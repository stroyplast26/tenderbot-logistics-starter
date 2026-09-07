# -*- coding: utf-8 -*-
"""
TenderBot — поиск завершённых тендеров с остеклением, ИИ-квалификация, письмо с лидами.

Режимы запуска:
  python tb_main.py            обычный ежедневный прогон (ищет НОВЫЕ, шлёт письмо)
  python tb_main.py --test     тестовый прогон: печать на экран, НИЧЕГО не отправляет,
                               состояние не меняет (для первой проверки)
  python tb_main.py --seed     "посев": помечает все текущие завершённые тендеры как
                               уже виденные, без ИИ и без письма (запустить 1 раз после
                               тестов, чтобы первый боевой прогон не выгрузил весь архив)
  доп. флаги: --days N (переопределить окно), --limit N (лимит для теста), --no-email
"""
import argparse
import json
import logging
import re
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

import tb_config
import tb_damia
import tb_ai
import tb_email
import tb_docs
import tb_smeta
import eis_client

log = logging.getLogger("tenderbot")


def setup_logging():
    tb_config.ensure_dirs()
    logfile = tb_config.LOGS_DIR / f"tenderbot_{date.today().isoformat()}.log"
    log.setLevel(logging.INFO)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(logfile, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    # консольный вывод — только если есть консоль (под pythonw.exe stdout = None)
    if sys.stdout is not None:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        log.addHandler(ch)


# ── состояние (дедупликация) ──────────────────────────────────────────────────
def load_state() -> dict:
    if tb_config.STATE_FILE.exists():
        try:
            # utf-8-sig — устойчиво к BOM (если файл кто-то пересохранил с BOM)
            return json.loads(tb_config.STATE_FILE.read_text(encoding="utf-8-sig"))
        except Exception as e:
            log.warning("Не удалось прочитать состояние (%s), начинаю с пустого", e)
    return {"processed": {}, "last_run": ""}


def save_state(state: dict):
    state["last_run"] = datetime.now().isoformat(timespec="seconds")
    tb_config.STATE_FILE.write_text(
        json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def alert(cfg, secrets, args, reason):
    """Письмо-тревога владельцу при сбое (только боевой режим, если включено)."""
    if getattr(args, "test", False) or getattr(args, "seed", False):
        return
    if not cfg.get("alert_on_failure", True):
        return
    tb_email.send_alert(
        secrets, "⚠️ TenderBot: проблема с прогоном",
        "Дневной прогон TenderBot столкнулся с проблемой:\n\n"
        f"{reason}\n\n"
        "Лиды за этот день могли не уйти. Загляните в папку logs (свежий файл) "
        "или запустите ТЕСТ_показать_лиды.bat вручную.")


# ── приоритет кандидата ───────────────────────────────────────────────────────
def candidate_priority(info, glazing_set):
    """Чем выше кортеж — тем раньше обрабатываем (важно при лимите запросов).

    1) ФЗ-44 — там победитель почти всегда РАСКРЫТ (есть контакты для письма),
       и именно там крупные стройки школ/ЖК/ФОК, где генподрядчику нужен субподряд.
       В ФЗ-223 победитель часто скрыт → лид без контактов = малополезен → ниже.
    2) совпадение с неводом ОСТЕКЛЕНИЯ (высокая релевантность профиля);
    3) свежесть по дате публикации.
    """
    kws = info.get("_keywords", []) or []
    is_glazing = 1 if any(k in glazing_set for k in kws) else 0
    is_44 = 1 if info.get("_fz") == "44" else 0
    return (is_44, is_glazing, info.get("ДатаПубл", ""))


# ── обработка одного тендера ──────────────────────────────────────────────────
def process_tender(client, secrets, cfg, regn, brief):
    """Возвращает (lead|None, processed_ok). lead=None если отфильтрован/нет данных."""
    body = client.zakupka(regn, actual=1)
    summary = tb_damia.extract_summary(body, regn)
    winners = tb_damia.extract_winners(body)

    # фильтр по минимальной цене
    min_price = cfg.get("min_price", 0) or 0
    try:
        sp = float(summary.get("start_price") or 0)
    except (ValueError, TypeError):
        sp = 0
    if min_price and sp and sp < min_price:
        log.info("  %s отброшен по цене (%.0f < %d)", regn, sp, min_price)
        return None, True

    # ИИ-квалификация
    ai = tb_ai.qualify(
        secrets["OPENROUTER_KEY"], cfg["model"], summary, winners,
        profile_anchors=cfg.get("profile_anchors"), stop_scope=cfg.get("stop_scope"),
        max_tokens=cfg.get("ai_max_tokens", 900), timeout=cfg.get("request_timeout", 60),
    )
    log.info("  %s | балл=%s est=%s рек=%s | %s",
             regn, ai["ball"], ai["est"], ai["rekomendaciya"],
             (summary.get("product_name") or "")[:60])

    # фильтр качества
    if ai["est"] == "нет" or ai["ball"] < cfg.get("min_ball", 2):
        return None, True

    # проверки надёжности победителя
    flags = []
    w = winners[0] if winners else {}
    inn = w.get("inn")
    if inn:
        if cfg.get("check_rnp", True):
            try:
                rnp = client.rnp(inn)
                if rnp.get("records", 0) > 0:
                    flags.append("риск: РНП")
                    ai["ball"] = max(1, ai["ball"] - 1)
            except tb_damia.QuotaError:
                raise
            except tb_damia.DamiaError as e:
                log.warning("  РНП для %s не проверен: %s", inn, e)
        if cfg.get("check_eruz", True):
            try:
                er = client.eruz(inn)
                smp = er.get("smp")
                if smp is False or (isinstance(smp, str) and smp.lower() in ("false", "нет", "0")):
                    flags.append("горячий / ч.5 ст.30 (не СМП)")
            except tb_damia.QuotaError:
                raise
            except tb_damia.DamiaError as e:
                log.warning("  ЕРУЗ для %s не проверен: %s", inn, e)
    if not winners:
        flags.append("победитель не раскрыт")

    lead = {
        "regn": regn,
        "summary": summary,
        "winner": w,
        "all_winners": winners,
        "ai": ai,
        "flags": flags,
        "link": tb_damia.eis_link(regn),
    }
    return lead, True


# ── ЕИС: реестр контрактов 44-ФЗ (свежие + победитель) ─────────────────────────
def _date_key(s):
    """'25.06.2026' -> '20260625' для сортировки по свежести."""
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", s or "")
    return (m.group(3) + m.group(2) + m.group(1)) if m else "0"


_STRONG_GLAZING = ("остекл", "витраж", "светопроз", "фасад", "оконн", "окон",
                   "входн", "зенитн", "стеклопак", "алюмини", "спк")


def eis_priority(item, glazing_set):
    """Сортировка кандидатов: сначала контракты, где остекление прямо в НАЗВАНИИ
    (самые релевантные), затем совпавшие со словом-неводом остекления, затем по свежести."""
    subj = (item.get("subject") or "").lower()
    strong = 1 if any(w in subj for w in _STRONG_GLAZING) else 0
    kws = item.get("_keywords", []) or []
    is_glazing = 1 if any(k in glazing_set for k in kws) else 0
    fresh = _date_key(item.get("update_date") or item.get("sign_date"))
    return (strong, is_glazing, fresh)


def _fetch_smeta_excerpt(damia, notice_regn, cfg):
    """Находит смету/ВОР в документах закупки, скачивает, отдаёт (выжимка_по_остеклению, все_документы)."""
    try:
        docs = tb_damia.extract_docs(damia.zakupka(notice_regn))
    except Exception as e:
        log.warning("    документы закупки %s не получены: %s", notice_regn, e)
        return "", []
    timeout = cfg.get("request_timeout", 60)
    max_chars = cfg.get("smeta_max_chars", 6000)
    read_cap = int(cfg.get("smeta_read_max_mb", 25)) * 1024 * 1024
    # для ЧТЕНИЯ берём только текстовые документы (смета/ТЗ/ООЗ); чертёжные разделы НЕ качаем.
    # Останавливаемся на ПЕРВОЙ смете, давшей позиции — лишнего не качаем.
    candidates = [d for d in tb_smeta.scope_docs(docs)
                  if not tb_smeta.is_drawing_section(d.get("name", ""))]
    for d in candidates[:5]:
        try:
            res = tb_docs._download_one(d["url"], d.get("name", "док"), read_cap, timeout)
        except Exception:
            res = None
        if not res:
            continue
        excerpt = tb_smeta.glazing_excerpt(tb_smeta.extract_text(res[0], res[1]), max_chars)
        if excerpt:
            return excerpt, docs   # нашли позиции — больше ничего не качаем
    return "", docs


def process_eis_contract(eis, damia, secrets, cfg, item):
    """Контракт ЕИС -> лид (та же структура, что и для DaMIA)."""
    sup = eis.contract_supplier(item["reestr"])
    summary = {
        "regn": item["reestr"],
        "region": item.get("region_code", ""),
        "product_name": item.get("subject", ""),
        "okpd": "",
        "start_price": item.get("price"),
        "objects": [],
        "customer": item.get("customer", ""),
        "customer_phone": "", "customer_email": "",
        "sposob": "контракт (реестр ЕИС, 44-ФЗ)",
        "completion_date": item.get("sign_date", ""),
        "docs": [],
    }
    winners = []
    if sup.get("name"):
        winners = [{
            "kind": "поставщик", "inn": sup.get("inn", ""), "name": sup.get("name", ""),
            "phone": sup.get("phone", ""), "email": sup.get("email", ""),
            "ogrn": "", "address": sup.get("address", ""),
            "ruk": "", "contract_price": item.get("price"),
            "contract_date": item.get("sign_date", ""),
        }]

    # фильтр по минимальной цене
    min_price = cfg.get("min_price", 0) or 0
    try:
        sp = float(summary.get("start_price") or 0)
    except (ValueError, TypeError):
        sp = 0
    if min_price and sp and sp < min_price:
        return None

    ai = tb_ai.qualify(
        secrets["OPENROUTER_KEY"], cfg["model"], summary, winners,
        profile_anchors=cfg.get("profile_anchors"), stop_scope=cfg.get("stop_scope"),
        max_tokens=cfg.get("ai_max_tokens", 900), timeout=cfg.get("request_timeout", 60),
    )
    log.info("  %s [%s] предв.балл=%s est=%s | %s",
             item["reestr"], item.get("region_code", ""), ai["ball"], ai["est"],
             (summary.get("product_name") or "")[:55])

    # явно не наш профиль по названию — не тратим чтение документов
    if ai["est"] == "нет":
        return None

    # V2: ОБЯЗАТЕЛЬНОЕ чтение сметы — балл 4-5 ставится только по доказательству из документа
    smeta_used = False
    if cfg.get("enrich_smeta", True) and damia is not None and sup.get("notice_regn"):
        excerpt, notice_docs = _fetch_smeta_excerpt(damia, sup["notice_regn"], cfg)
        if notice_docs:
            summary["docs"] = notice_docs  # ссылки + вложения чертежей/сметы
        if excerpt:
            try:
                ai = tb_ai.qualify(
                    secrets["OPENROUTER_KEY"], cfg["model"], summary, winners,
                    profile_anchors=cfg.get("profile_anchors"), stop_scope=cfg.get("stop_scope"),
                    smeta_text=excerpt, max_tokens=cfg.get("ai_max_tokens", 1300),
                    timeout=cfg.get("request_timeout", 60))
                smeta_used = True
                log.info("    смета прочитана: балл=%s доказательство: %s",
                         ai["ball"], (ai.get("dokazatelstvo", "") or "")[:70])
            except tb_ai.AIError as e:
                log.warning("    ИИ по смете не оценил: %s", e)
        else:
            log.info("    смета не прочитана (нет/скан) — балл остаётся предварительным (≤3)")

    # отсев по баллу ДО проверок победителя (экономим запросы на отбракованных).
    # review_min_ball (≤ min_ball) пропускает лиды балла 3 в секцию «на проверку».
    review_min = cfg.get("review_min_ball", cfg.get("min_ball", 4))
    if ai["est"] == "нет" or ai["ball"] < review_min:
        return None

    flags = []
    if smeta_used:
        flags.append("📋 оценка по смете")
    w = winners[0] if winners else {}
    inn = w.get("inn")
    if inn and damia is not None:
        if cfg.get("check_rnp", True):
            try:
                if damia.rnp(inn).get("records", 0) > 0:
                    flags.append("риск: РНП")
                    ai["ball"] = max(1, ai["ball"] - 1)
            except tb_damia.DamiaError as e:
                log.warning("  РНП для %s не проверен: %s", inn, e)
        if cfg.get("check_eruz", True):
            try:
                smp = damia.eruz(inn).get("smp")
                if smp is False or (isinstance(smp, str) and smp.lower() in ("false", "нет", "0")):
                    flags.append("горячий / ч.5 ст.30 (не СМП)")
            except tb_damia.DamiaError as e:
                log.warning("  ЕРУЗ для %s не проверен: %s", inn, e)
        if cfg.get("check_winner_activity", True):
            try:
                dos = damia.contracts(inn, fz="44")
                w["activity"] = dos
                if (dos["count"] >= cfg.get("winner_active_min_contracts", 5)
                        or dos["sum"] >= cfg.get("winner_active_min_sum", 50_000_000)):
                    flags.append(f"💪 активный подрядчик: {dos['count']} контр./{dos['sum']/1e6:.0f} млн")
            except tb_damia.DamiaError as e:
                log.warning("  Досье для %s не получено: %s", inn, e)
    if not winners:
        flags.append("победитель не раскрыт")

    # secondary = балл ниже основного порога (после возможного штрафа за РНП) → секция «на проверку»
    secondary = ai["ball"] < cfg.get("min_ball", 4)
    if secondary:
        flags.append("🔍 на проверку (профиль не подтверждён сметой)")

    return {
        "regn": item["reestr"], "summary": summary, "winner": w,
        "all_winners": winners, "ai": ai, "flags": flags,
        "link": item.get("link", ""), "secondary": secondary,
    }


def run_eis(args, cfg, secrets, window):
    eis = eis_client.EisClient(timeout=cfg.get("request_timeout", 60),
                               pause=cfg.get("eis_pause", 1.0))
    damia = None
    if secrets.get("DAMIA_KEY") and (cfg.get("check_rnp", True) or cfg.get("check_eruz", True)):
        damia = tb_damia.DamiaClient(secrets["DAMIA_KEY"],
                                     timeout=cfg.get("request_timeout", 60),
                                     pause=cfg.get("pause_seconds", 0.5))
    regions = tuple(r.strip() for r in str(cfg.get("regions", "77,50")).split(",") if r.strip())
    exclude = tuple(r.strip() for r in str(cfg.get("exclude_regions", "")).split(",") if r.strip())
    keywords = cfg["keywords"]
    glazing_set = set(cfg.get("q_glazing", []))

    # окно свежести: только контракты, заключённые за последние recency_days
    cutoff = date.today() - timedelta(days=cfg.get("recency_days", 90))
    recency_from = cutoff.strftime("%d.%m.%Y")
    log.info("Окно по дате ЗАКЛЮЧЕНИЯ контракта: с %s (≤ %d дней)", recency_from, cfg.get("recency_days", 90))

    # поиск по всем словам, объединение по номеру контракта
    found = {}
    per_kw = {}
    eis_down = False
    for kw in keywords:
        try:
            items = eis.search_contracts(kw, regions=regions, exclude=exclude,
                                         max_pages=cfg.get("eis_max_pages", 5),
                                         recency_from=recency_from, cutoff_date=cutoff)
        except eis_client.EisUnavailable as e:
            # сайт ЕИС недоступен (434) — не долбим все 47 слов, выходим сразу
            log.error("⛔ ЕИС недоступен: %s — прекращаю поиск.", e)
            eis_down = True
            break
        except eis_client.EisError as e:
            log.warning("ЕИС поиск '%s' не удался: %s", kw, e)
            per_kw[kw] = -1
            continue
        per_kw[kw] = len(items)
        for it in items:
            r = it["reestr"]
            if r not in found:
                it["_keywords"] = [kw]
                found[r] = it
            else:
                found[r]["_keywords"].append(kw)
    log.info("ЕИС найдено по словам: %s; уникальных контрактов (%s): %d; запросов: %d",
             per_kw, ",".join(regions), len(found), eis.request_count)

    # самоконтроль: различаем «ЕИС недоступен (434)» и «возможна смена структуры»
    if eis_down:
        log.error("⚠️ ЕИС недоступен (HTTP 434) — прогон пропущен, не поломка бота.")
        alert(cfg, secrets, args,
              "Сайт ЕИС (zakupki.gov.ru) сейчас НЕДОСТУПЕН (HTTP 434 — регламентные работы или "
              "временное ограничение доступа). Это НЕ поломка бота. Прогон пропущен; лиды придут "
              "автоматически, как только сайт снова заработает.")
    elif not found and keywords:
        log.error("⚠️ ЕИС вернул 0 контрактов при рабочих словах — возможна смена структуры сайта")
        alert(cfg, secrets, args,
              "ЕИС открылся, но вернул 0 контрактов по всем словам — возможно, сайт изменил структуру "
              "страницы (парсеру нужна правка). Загляните в логи.")

    # пред-фильтр по названию (клининг / ПВХ / проектирование-экспертиза-осмотр)
    skip_words = [w.lower() for w in cfg.get("skip_product_words", []) if w]
    if skip_words:
        before = len(found)
        found = {r: it for r, it in found.items()
                 if not any(sw in (it.get("subject", "").lower()) for sw in skip_words)}
        log.info("Пред-фильтр по словам отсеял %d (клининг/ПВХ/проектирование), осталось %d",
                 before - len(found), len(found))

    # пред-фильтр по цене (≥ min_price); цена-неизвестна оставляем для ИИ
    min_price = cfg.get("min_price", 0) or 0
    if min_price:
        before = len(found)
        found = {r: it for r, it in found.items()
                 if not it.get("price") or it["price"] >= min_price}
        log.info("Пред-фильтр по цене ≥ %.0f отсеял %d, осталось %d",
                 min_price, before - len(found), len(found))
    scanned = len(found)

    state = load_state()
    processed = state.setdefault("processed", {})

    if args.seed:
        n = 0
        for r in found:
            if r not in processed:
                processed[r] = {"date": datetime.now().isoformat(timespec="seconds"), "seeded": True}
                n += 1
        save_state(state)
        log.info("ПОСЕВ (ЕИС): помечено %d новых (всего %d).", n, len(processed))
        return

    if args.test:
        cands = sorted(found.values(), key=lambda it: eis_priority(it, glazing_set), reverse=True)
        cands = cands[:(args.limit if args.limit is not None else cfg.get("test_limit", 5))]
        log.info("ТЕСТ (ЕИС): прогоню %d из %d", len(cands), scanned)
    else:
        new = [it for r, it in found.items() if r not in processed]
        new.sort(key=lambda it: eis_priority(it, glazing_set), reverse=True)
        mx = cfg.get("max_per_run", 50)
        if len(new) > mx:
            log.info("Новых контрактов %d, беру первые %d (остальные — позже)", len(new), mx)
            new = new[:mx]
        cands = new
        log.info("Новых к обработке (ЕИС): %d", len(cands))

    leads = []
    for it in cands:
        try:
            lead = process_eis_contract(eis, damia, secrets, cfg, it)
            if lead:
                leads.append(lead)
            if not args.test:
                processed[it["reestr"]] = {
                    "date": datetime.now().isoformat(timespec="seconds"),
                    "ball": lead["ai"]["ball"] if lead else None, "is_lead": bool(lead)}
        except tb_ai.AIError as e:
            log.error("  ИИ не оценил %s: %s (пропуск)", it["reestr"], e)
        except Exception as e:
            log.exception("  Ошибка на контракте %s: %s", it["reestr"], e)
        time.sleep(cfg.get("pause_seconds", 0.5))

    log.info("Готово (ЕИС). Найдено лидов: %d. Запросов к ЕИС: %d", len(leads), eis.request_count)
    deliver_leads(leads, scanned, window, args, cfg, secrets, state)


# ── доставка результата (общая для источников) ─────────────────────────────────
def deliver_leads(leads, scanned, window, args, cfg, secrets, state, quota_hit=False):
    """Отчёт + (тест: печать | боевой: письмо с вложениями) + состояние."""
    # Коммерческий порядок: сначала подтверждённый объём и близкий срок, а поставка без монтажа
    # получает приоритет через priority_score от квалификатора. При равенстве — балл ИИ.
    leads.sort(key=lambda lead: (
        int((lead.get("ai") or {}).get("priority_score") or 0),
        int((lead.get("ai") or {}).get("ball") or 0),
    ), reverse=True)
    meta = {"date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "scanned": scanned, "window": window}
    if quota_hit:
        meta["window"] += " (прервано: лимит источника)"
    report_path = tb_config.REPORTS_DIR / f"report_{datetime.now().strftime('%Y-%m-%d_%H%M')}.html"

    # ── ТЕСТ: печать на экран, без скачивания/отправки, состояние не трогаем ──
    if args.test:
        html_report = tb_email.build_html_report(leads, meta)
        tb_email.save_report(html_report, report_path)
        primary = [l for l in leads if not l.get("secondary")]
        secondary = [l for l in leads if l.get("secondary")]
        print("\n" + "=" * 70)
        print(f"ТЕСТОВЫЙ ПРОГОН — лидов: {len(leads)} "
              f"(основных: {len(primary)}, на проверку: {len(secondary)}; письмо НЕ отправлялось)")
        print("=" * 70)

        def _print_group(group, title):
            if not group:
                return
            print(f"\n{'─' * 70}\n{title}: {len(group)}\n{'─' * 70}")
            for l in sorted(group, key=lambda x: x["ai"]["ball"], reverse=True):
                s, w, ai = l["summary"], l.get("winner") or {}, l["ai"]
                print(f"\n⭐ {ai['ball']}/5 [{ai['rekomendaciya']}] {ai.get('tip_obekta','')} "
                      f"(горячий: {ai.get('goryachiy','')})")
                print(f"   {s.get('product_name','')[:90]}")
                print(f"   Наш профиль: {ai.get('nash_profil','')[:90]}")
                if ai.get('chuzhoy_profil'):
                    print(f"   Чужой профиль: {ai.get('chuzhoy_profil','')[:80]}")
                if ai.get('ocenka_obema'):
                    print(f"   Объём по смете: {ai.get('ocenka_obema','')[:80]}")
                print(f"   Приоритет: {ai.get('priority_score', 0)}/100 | "
                      f"формат: {ai.get('format_raboty','неясно')} | "
                      f"монтаж: {ai.get('montazh','неясно')} | "
                      f"срок: {ai.get('srok_zakupa','не указан')[:60]}")
                if ai.get('dokazatelstvo'):
                    print(f"   📑 Доказательство: {ai.get('dokazatelstvo','')[:90]}")
                print(f"   Победитель: {w.get('name','(не раскрыт)')} ИНН {w.get('inn','—')} "
                      f"тел {w.get('phone','—')} {w.get('email','')}")
                print(f"   Цена: нач {s.get('start_price','—')} / контракт {w.get('contract_price','—')}")
                if l['flags']:
                    print(f"   Флаги: {', '.join(l['flags'])}")
                docs = s.get('docs') or []
                sm = [d['name'] for d in docs if any(k in (d.get('name', '').lower())
                      for k in cfg.get('attach_keywords', []))]
                print(f"   Документов: {len(docs)} (похоже на смету/ВОР: {len(sm)})")
                print(f"   Обоснование: {ai.get('obosnovanie','')}")
                print(f"   Ссылка: {l['link']}")

        _print_group(primary, "ОСНОВНЫЕ (балл 4-5)")
        _print_group(secondary, "НА ПРОВЕРКУ (балл 3 — профиль не подтверждён сметой)")
        print(f"\nHTML-отчёт сохранён: {report_path}")
        print("Состояние НЕ менялось (тест).")
        return

    # ── БОЕВОЙ режим ──
    # ВАЖНО: состояние (дедуп) сохраняем ТОЛЬКО после успешной отправки письма.
    # Иначе при сбое SMTP лиды пометятся "ушедшими", но владелец их не получит.
    if not leads:
        save_state(state)  # помечать нечего, просто обновим last_run
        html_report = tb_email.build_html_report(leads, meta)
        tb_email.save_report(html_report, report_path)
        log.info("Новых лидов нет — письмо не отправляю (отчёт сохранён).")
        return
    if args.no_email:
        html_report = tb_email.build_html_report(leads, meta)
        tb_email.save_report(html_report, report_path)
        log.info("Письмо не отправлялось (--no-email). Состояние НЕ сохранено. Отчёт: %s", report_path)
        return

    # Вложения: смета/ТЗ + вырезанные листы фасад/остекление (бюджет на всё письмо)
    email_attachments = []
    total_bytes = 0
    max_total = int(cfg.get("attach_max_total_mb", 25)) * 1024 * 1024
    for lead in leads:
        try:
            atts, oversized = tb_docs.build_doc_attachments(
                lead["summary"].get("docs"), cfg, budget_bytes=max_total - total_bytes)
        except Exception as e:
            log.warning("Сбор вложений для %s не удался: %s", lead.get("regn"), e)
            atts, oversized = [], False
        if oversized:
            lead["oversized_docs"] = True
        email_attachments.extend(atts)
        total_bytes += sum(len(c) for _, c, _ in atts)

    html_report = tb_email.build_html_report(leads, meta)
    tb_email.save_report(html_report, report_path)

    # Свежие лиды дневного поиска → в очередь отправки кампании (Лейна-1), приоритет свежему по ИНН
    # (иначе горячая свежая победа терялась: в очередь её никто не клал — только bulk-загрузчик пулов).
    try:
        import tb_outreach
        _new = _upg = 0
        for _lead in leads:
            _r = tb_outreach.enqueue_or_upgrade(_lead)
            if _r == "new":
                _new += 1
            elif _r == "upgraded":
                _upg += 1
        if _new or _upg:
            log.info("В очередь отправки добавлено: новых %d, обновлено свежим вместо старого %d", _new, _upg)
    except Exception as e:
        log.warning("Не удалось поставить свежие лиды в очередь отправки: %s", e)

    subject = f"🏗️ Тендеры-лиды: {len(leads)} новых ({datetime.now().strftime('%d.%m.%Y')})"
    try:
        tb_email.send_email(secrets, subject, html_report, attachments=email_attachments)
        save_state(state)   # дедуп фиксируем ТОЛЬКО после успешной отправки
        log.info("✅ Письмо с %d лидами отправлено (вложений: %d, %.1f МБ). Состояние сохранено.",
                 len(leads), len(email_attachments), total_bytes / 1024 / 1024)
    except Exception as e:
        log.error("Не удалось отправить письмо: %s. Состояние НЕ сохранено — "
                  "лиды повторятся в следующий прогон. Отчёт сохранён: %s", e, report_path)


# ── основной сценарий ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="TenderBot")
    parser.add_argument("--test", action="store_true", help="тестовый прогон без отправки")
    parser.add_argument("--seed", action="store_true", help="пометить текущие как виденные")
    parser.add_argument("--days", type=int, default=None, help="переопределить окно (дней)")
    parser.add_argument("--limit", type=int, default=None, help="лимит лидов (тест)")
    parser.add_argument("--no-email", action="store_true", help="не отправлять письмо")
    args = parser.parse_args()

    setup_logging()
    cfg = tb_config.load_config()
    secrets = tb_config.load_secrets()

    mode = "ТЕСТ" if args.test else ("ПОСЕВ" if args.seed else "БОЕВОЙ")
    log.info("=" * 60)
    log.info("Запуск TenderBot — режим: %s", mode)

    if not secrets["DAMIA_KEY"]:
        log.error("Не задан DAMIA_KEY в .env")
        sys.exit(1)
    if not args.seed and not secrets["OPENROUTER_KEY"]:
        log.error("Не задан OPENROUTER_KEY в .env (нужен для ИИ-квалификации)")
        sys.exit(1)

    lookback = args.days if args.days is not None else cfg.get("lookback_days", 120)
    to_d = date.today()
    from_d = to_d - timedelta(days=lookback)
    window = f"{from_d.isoformat()} … {to_d.isoformat()}"
    log.info("Окно публикаций: %s; регионы: %s; слова: %d",
             window, cfg.get("regions"), len(cfg.get("keywords", [])))

    # ── Источник ЕИС (реестр контрактов 44-ФЗ: свежие + победитель) ──
    if cfg.get("source", "eis") != "damia":
        log.info("Источник: ЕИС (реестр контрактов 44-ФЗ)")
        try:
            run_eis(args, cfg, secrets, window)
        except SystemExit:
            raise
        except Exception as e:
            log.exception("❌ Прогон ЕИС упал: %s", e)
            alert(cfg, secrets, args, f"Прогон упал с ошибкой: {e}")
            sys.exit(2)
        return
    log.info("Источник: DaMIA")

    client = tb_damia.DamiaClient(
        secrets["DAMIA_KEY"],
        timeout=cfg.get("request_timeout", 60),
        pause=cfg.get("pause_seconds", 0.5),
        max_requests=cfg.get("max_requests_per_run", 0),
    )

    # 1) Поиск — ДВА невода с разным okpd. Сначала невод ОСТЕКЛЕНИЯ (дёшево + ценнее),
    #    затем невод ТИПОВ ЗДАНИЙ (с okpd, чтобы резать мусор и расход квоты).
    glazing_kw = list(dict.fromkeys(cfg.get("q_glazing") or []))
    object_kw = list(dict.fromkeys((cfg.get("q_object") or []) + (cfg.get("q_object_broad") or [])))

    def _merge_into(found, src):
        for regn, info in src.items():
            if regn not in found:
                found[regn] = info
            else:
                found[regn].setdefault("_keywords", []).extend(info.get("_keywords", []))

    found = {}
    common = dict(regions=cfg.get("regions", ""), status=cfg.get("status", 3),
                  from_date=from_d.isoformat(), to_date=to_d.isoformat(),
                  max_pages=cfg.get("max_pages", 8))
    # невод остекления — без okpd по умолчанию
    try:
        _merge_into(found, client.search_all(glazing_kw, okpd=cfg.get("okpd_glazing", ""), **common))
    except tb_damia.QuotaError as e:
        log.error("❌ Квота DaMIA исчерпана уже на неводе остекления: %s", e)
        if not found:
            sys.exit(2)
    except tb_damia.DamiaError as e:
        log.error("❌ Ошибка поиска (невод остекления): %s", e)
    # невод типов зданий — с okpd_object (если квота/лимит позволит)
    if object_kw:
        try:
            _merge_into(found, client.search_all(object_kw, okpd=cfg.get("okpd_object", "43"), **common))
        except tb_damia.QuotaError as e:
            log.warning("Невод типов зданий прерван (квота/лимит): %s. Продолжаю с тем, что есть.", e)
        except tb_damia.DamiaError as e:
            log.warning("Невод типов зданий не выполнен: %s. Продолжаю с тем, что есть.", e)

    scanned = len(found)
    log.info("Всего завершённых закупок в окне: %d (запросов к DaMIA: %d)",
             scanned, client.request_count)

    # Пред-фильтр явного мусора по названию (до запроса деталей — экономит квоту и ИИ)
    skip_words = [w.lower() for w in cfg.get("skip_product_words", []) if w]
    if skip_words:
        skipped = 0
        for regn in list(found):
            name = str(found[regn].get("Продукт", "")).lower()
            if any(sw in name for sw in skip_words):
                del found[regn]
                skipped += 1
        if skipped:
            log.info("Пред-фильтр по названию отсеял %d закупок (мойка/клининг/уборка и т.п.), "
                     "осталось %d", skipped, len(found))
        scanned = len(found)

    state = load_state()
    processed = state.setdefault("processed", {})

    # ── режим ПОСЕВ ──
    if args.seed:
        n = 0
        for regn in found:
            if regn not in processed:
                processed[regn] = {"date": datetime.now().isoformat(timespec="seconds"),
                                   "seeded": True}
                n += 1
        save_state(state)
        log.info("ПОСЕВ завершён: помечено как виденные %d новых (всего в базе %d). "
                 "Теперь боевой прогон будет слать только НОВЫЕ завершения.",
                 n, len(processed))
        return

    # Определяем, что обрабатывать (с приоритетом: остекление + ФЗ-44 вперёд)
    glazing_set = set(cfg.get("q_glazing", []))
    if args.test:
        candidates = sorted(found.items(),
                            key=lambda kv: candidate_priority(kv[1], glazing_set), reverse=True)
        limit = args.limit if args.limit is not None else cfg.get("test_limit", 5)
        candidates = candidates[:limit]
        log.info("ТЕСТ: будет прогнано %d из %d (приоритет: остекление+ФЗ-44; без отправки)",
                 len(candidates), scanned)
    else:
        new_regns = [r for r in found if r not in processed]
        new_regns.sort(key=lambda r: candidate_priority(found[r], glazing_set), reverse=True)
        max_per_run = cfg.get("max_per_run", 50)
        if len(new_regns) > max_per_run:
            log.warning("Новых тендеров %d, обрабатываю первые %d (приоритет остекление+ФЗ-44; "
                        "остальные — в следующий прогон). Если это ПЕРВЫЙ запуск — "
                        "сначала лучше посев: python tb_main.py --seed",
                        len(new_regns), max_per_run)
            new_regns = new_regns[:max_per_run]
        candidates = [(r, found[r]) for r in new_regns]
        log.info("Новых к обработке: %d", len(candidates))

    # 2) Обработка
    leads = []
    quota_hit = False
    for regn, brief in candidates:
        try:
            lead, ok = process_tender(client, secrets, cfg, regn, brief)
            if lead:
                leads.append(lead)
            if ok and not args.test:
                processed[regn] = {
                    "date": datetime.now().isoformat(timespec="seconds"),
                    "ball": lead["ai"]["ball"] if lead else None,
                    "is_lead": bool(lead),
                }
        except tb_damia.QuotaError as e:
            log.error("❌ Квота DaMIA исчерпана при обработке %s: %s. Останавливаюсь.", regn, e)
            quota_hit = True
            break
        except tb_ai.AIError as e:
            log.error("  ИИ не оценил %s: %s (пропуск, повтор в след. раз)", regn, e)
        except Exception as e:
            log.exception("  Ошибка на тендере %s: %s (пропуск)", regn, e)
        time.sleep(cfg.get("pause_seconds", 0.5))

    log.info("Готово (DaMIA). Найдено лидов: %d. Запросов к DaMIA: %d",
             len(leads), client.request_count)
    deliver_leads(leads, scanned, window, args, cfg, secrets, state, quota_hit)


if __name__ == "__main__":
    main()
