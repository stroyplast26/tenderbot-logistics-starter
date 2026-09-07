# -*- coding: utf-8 -*-
"""ЛЕЙНА-2 — СБОРЩИК ПУЛА ПОБЕДИТЕЛЕЙ за период (по умолчанию год).

ЧЕМ ОТЛИЧАЕТСЯ ОТ ЛЕЙНЫ-1 (дневной бот tb_main.py — живые лиды за 90 дней):
  • цель не «свежий лид на просчёт сегодня», а БАЗА активных генподрядчиков,
    которые РЕГУЛЯРНО выигрывают работы с остеклением → для холодной кампании;
  • дедуп по ИНН: одна компания = одна запись (не N контрактов);
  • ранжирование по «повторности» — сколько раз ИНН выигрывал остекление за период;
  • сегментация в тиры:
        ТИР A — приоритетный ОБЗВОН (повторные победители с телефоном);
        ТИР B — EMAIL-рассылка (есть почта);
        ТИР C — контакта нет (только название+ИНН, смотреть карточку вручную).
  • свой вывод (папка pool/) и свой визуальный стиль — НЕ пересекается с лейной-1.

ЗАПУСК:
  python tb_pool.py                 полный сбор за pool_recency_days (год)
  python tb_pool.py --days N        переопределить окно (дней)
  python tb_pool.py --max-pages N   глубина пагинации ЕИС на слово
  python tb_pool.py --limit N       ограничить число открываемых карточек (быстрый тест)
  python tb_pool.py --no-cache      не использовать кэш карточек (перечитать всё заново)
"""
import argparse
import csv
import html
import json
import logging
import re
import sys
import time
from datetime import date, datetime, timedelta

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

import tb_config
import tb_ai
import eis_client

log = logging.getLogger("tenderbot.pool")

# Сильные признаки «нашего» профиля прямо в названии контракта (дешёвая квалификация).
STRONG_GLAZING = ("остекл", "витраж", "светопроз", "фасад", "оконн", "окон", "входн",
                  "зенитн", "стеклопак", "алюмини", "спк", "противопожарн")


def setup_logging():
    tb_config.ensure_dirs()
    logfile = tb_config.LOGS_DIR / f"pool_{date.today().isoformat()}.log"
    log.setLevel(logging.INFO)
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(logfile, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if sys.stdout is not None:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        log.addHandler(ch)


def _is_strong(subject: str) -> bool:
    s = (subject or "").lower()
    return any(w in s for w in STRONG_GLAZING)


def _dk(s):
    """'25.06.2026' -> '20260625' для сортировки по свежести."""
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", s or "")
    return (m.group(3) + m.group(2) + m.group(1)) if m else "0"


def _load_cache(use_cache: bool) -> dict:
    if use_cache and tb_config.POOL_CARDS_CACHE.exists():
        try:
            return json.loads(tb_config.POOL_CARDS_CACHE.read_text(encoding="utf-8-sig"))
        except Exception as e:
            log.warning("Кэш карточек не прочитан (%s), начну с пустого", e)
    return {}


def _save_cache(cache: dict):
    try:
        tb_config.POOL_CARDS_CACHE.write_text(
            json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.warning("Кэш карточек не сохранён: %s", e)


_AI_CACHE_FILE = tb_config.POOL_DIR / "ai_cache.json"


def _load_ai_cache(use_cache: bool) -> dict:
    if use_cache and _AI_CACHE_FILE.exists():
        try:
            return json.loads(_AI_CACHE_FILE.read_text(encoding="utf-8-sig"))
        except Exception:
            pass
    return {}


def _ai_qualify(cands, cfg, secrets, use_cache, no_ai):
    """ИИ-квалификация по НАЗВАНИЮ контракта (как preview-гейт лейны-1): отсекает
    явно не наш профиль (энергосбыт/телеком/услуги/поставка товара → est=нет) ДО
    открытия карточки. Возвращает только прошедшие (est != нет). Вердикты кэшируются.
    ПАРАЛЛЕЛЬНО: до ai_workers ИИ-запросов разом (узкое место — сетевая задержка)."""
    import concurrent.futures
    for it in cands:
        it["_strong"] = _is_strong(it.get("subject", ""))
    if no_ai or not secrets.get("OPENROUTER_KEY"):
        if not no_ai:
            log.warning("OPENROUTER_KEY не задан — ИИ-квалификация пропущена (пул будет с шумом)")
        for it in cands:
            it["_ai_est"] = "(без ИИ)"
        return cands

    cache = _load_ai_cache(use_cache)
    key, model = secrets["OPENROUTER_KEY"], cfg["model"]
    timeout = cfg.get("request_timeout", 60)
    workers = max(1, int(cfg.get("ai_workers", 12)))

    todo = [it for it in cands if it["reestr"] not in cache]   # без кэша → опросить ИИ
    log.info("ИИ-квалификация: всего %d, в кэше %d, опросить %d (параллельно ×%d)",
             len(cands), len(cands) - len(todo), len(todo), workers)

    def _classify(it):
        try:
            est = tb_ai.classify_profile(key, model, it.get("subject", ""),
                                         it.get("customer", ""), timeout=timeout)
            return it["reestr"], {"est": est}, None
        except Exception as e:                  # 402/429/таймаут — НЕ кэшируем (перечитается)
            return it["reestr"], None, str(e)[:120]

    fails = 0
    done = 0
    if todo:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for r, v, err in ex.map(_classify, todo):
                done += 1
                if v is not None:
                    cache[r] = v               # кэшируем ТОЛЬКО успешные
                else:
                    fails += 1
                    if fails <= 5:
                        log.warning("ИИ не оценил %s: %s", r, err)
                if done % 100 == 0:
                    log.info("  ИИ-квалификация: %d/%d (ошибок: %d)", done, len(todo), fails)
        try:
            _AI_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning("ИИ-кэш не сохранён: %s", e)

    # собрать результат В ИСХОДНОМ ПОРЯДКЕ; сбой ИИ → 'неясно' (НЕ отсеиваем)
    out, nyet = [], 0
    for it in cands:
        est = (cache.get(it["reestr"]) or {}).get("est", "неясно")
        it["_ai_est"] = est
        if est == "нет":
            nyet += 1
        else:
            out.append(it)
    tag = (" (ЧАСТЬ не оценена — ИИ-сбои/нет кредитов; оставлены как 'неясно')"
           if todo and fails >= max(15, len(todo) // 2) else "")
    log.info("ИИ-квалификация по названию: %d → %d (отсеяно не-профиль: %d; ошибок ИИ: %d)%s",
             len(cands), len(out), nyet, fails, tag)
    return out


# ── сбор пула ──────────────────────────────────────────────────────────────────
def build_pool(args, cfg, secrets):
    eis = eis_client.EisClient(timeout=cfg.get("request_timeout", 60),
                               pause=cfg.get("eis_pause", 1.0))
    regions = tuple(r.strip() for r in str(cfg.get("regions", "77,50")).split(",") if r.strip())
    exclude = tuple(r.strip() for r in str(cfg.get("exclude_regions", "")).split(",") if r.strip())
    keywords = list(cfg["keywords"])
    if getattr(args, "broad", False):
        broad = cfg.get("pool_broad_words", []) or []
        keywords = list(dict.fromkeys(keywords + broad))
        log.info("Режим --broad: +%d широких слов → всего слов: %d", len(broad), len(keywords))
    min_price = cfg.get("pool_min_price", cfg.get("min_price", 3000000)) or 0
    max_pages = args.max_pages if args.max_pages is not None else cfg.get("pool_max_pages", 20)
    days = args.days if args.days is not None else cfg.get("pool_recency_days", 365)

    cutoff = date.today() - timedelta(days=days)
    recency_from = cutoff.strftime("%d.%m.%Y")
    log.info("ЛЕЙНА-2: сбор пула победителей. Окно по дате ЗАКЛЮЧЕНИЯ: с %s (≤ %d дн); "
             "регионы: %s; слов: %d; глубина: %d стр.",
             recency_from, days, ",".join(regions), len(keywords), max_pages)

    # 1) поиск по всем словам, объединение по номеру контракта (как лейна-1, но окно=год)
    found = {}
    per_kw = {}
    truncated = []
    for kw in keywords:
        try:
            items = eis.search_contracts(kw, regions=regions, exclude=exclude, max_pages=max_pages,
                                         recency_from=recency_from, cutoff_date=cutoff)
        except eis_client.EisUnavailable as e:
            log.error("⛔ ЕИС недоступен: %s — прекращаю сбор.", e)
            return None
        except eis_client.EisError as e:
            log.warning("ЕИС поиск '%s' не удался: %s", kw, e)
            per_kw[kw] = -1
            continue
        per_kw[kw] = len(items)
        # honest coverage: если слово упёрлось в потолок страниц — могли недобрать
        if len(items) >= max_pages * 50 * 0.9:
            truncated.append(kw)
        for it in items:
            r = it["reestr"]
            if r not in found:
                it["_keywords"] = [kw]
                found[r] = it
            else:
                found[r]["_keywords"].append(kw)
    log.info("Найдено по словам: %s", per_kw)
    log.info("Уникальных контрактов (%s): %d; запросов к ЕИС: %d",
             ",".join(regions), len(found), eis.request_count)
    if truncated:
        log.warning("⚠️ НЕ ПОЛНОЕ покрытие по словам (упёрлись в %d стр.): %s — поднимите "
                    "pool_max_pages для полноты.", max_pages, ", ".join(truncated))

    # 2) пред-фильтры — ТЕ ЖЕ, что у лейны-1 (стоп-слова + цена). НЕ требуем остекление в
    #    названии: профиль подтверждается сметой/обзвоном, а не заголовком. «Остекление в
    #    названии» используется ниже только как признак УВЕРЕННОСТИ (доказанные vs вероятные).
    skip_words = [w.lower() for w in cfg.get("skip_product_words", []) if w]
    before = len(found)
    kept = {}
    for r, it in found.items():
        subj = (it.get("subject") or "").lower()
        if skip_words and any(sw in subj for sw in skip_words):
            continue
        price = it.get("price")
        if min_price and price and price < min_price:
            continue
        kept[r] = it
    log.info("Пред-фильтр (стоп-слова + цена≥%.0f, как у лейны-1): %d → %d",
             min_price, before, len(kept))

    # 3) ИИ-квалификация по названию (как лейна-1): отсекаем не-профиль ДО открытия карточек
    cands = list(kept.values())
    cands.sort(key=lambda it: it.get("sign_date", ""), reverse=True)
    cands = _ai_qualify(cands, cfg, secrets, use_cache=not args.no_cache, no_ai=args.no_ai)
    if args.limit is not None:
        cands = cands[:args.limit]
        log.info("ТЕСТ: ограничено %d карточками", len(cands))

    # 4) открыть карточку → победитель (основная стоимость по времени)

    cache = _load_cache(use_cache=not args.no_cache)
    suppliers = {}     # inn -> запись компании
    no_winner = 0
    for i, it in enumerate(cands, 1):
        reestr = it["reestr"]
        sup = cache.get(reestr)
        if sup is None:
            try:
                sup = eis.contract_supplier(reestr)
                cache[reestr] = sup   # кэшируем ТОЛЬКО успешные (в т.ч. валидное «нет победителя»)
            except eis_client.EisUnavailable as e:
                log.error("⛔ ЕИС стал недоступен на карточке %s: %s — останавливаюсь, "
                          "сохраню что собрал.", reestr, e)
                break
            except Exception as e:
                # ошибку (напр. HTTP 429) НЕ кэшируем — перечитается в следующий прогон
                log.warning("Карточка %s не открыта: %s", reestr, e)
                sup = {}
            time.sleep(cfg.get("pause_seconds", 0.5))
        if i % 25 == 0:
            log.info("  обработано карточек: %d/%d (компаний: %d)", i, len(cands), len(suppliers))

        inn = (sup or {}).get("inn")
        if not inn:
            no_winner += 1
            continue
        rec = suppliers.setdefault(inn, {
            "inn": inn, "name": sup.get("name", ""), "kpp": sup.get("kpp", ""),
            "phones": set(), "emails": set(), "address": sup.get("address", ""),
            "contracts": [],
        })
        if not rec["name"] and sup.get("name"):
            rec["name"] = sup["name"]
        if sup.get("phone"):
            rec["phones"].add(sup["phone"])
        if sup.get("email"):
            rec["emails"].add(sup["email"])
        if not rec["address"] and sup.get("address"):
            rec["address"] = sup["address"]
        rec["contracts"].append({
            "reestr": reestr,
            "subject": it.get("subject", ""),
            "price": it.get("price"),
            "customer": it.get("customer", ""),
            "region": it.get("region_code", ""),
            "sign_date": it.get("sign_date", ""),
            "strong": bool(it.get("_strong")),
            "ai_est": it.get("_ai_est", ""),
            "link": it.get("link", ""),
        })

    _save_cache(cache)
    log.info("Карточек открыто: %d; победитель раскрыт у %d; без победителя: %d; компаний (ИНН): %d",
             len(cands), len(cands) - no_winner, no_winner, len(suppliers))

    # 4) агрегаты + уверенность + ранжирование + тиры
    pool = []
    top_min = cfg.get("pool_top_min_contracts", 3)
    active_min = cfg.get("pool_active_min_contracts", 5)
    for rec in suppliers.values():
        glazing_count = sum(1 for c in rec["contracts"] if c["strong"])
        ai_da = sum(1 for c in rec["contracts"] if c.get("ai_est") == "да")
        contracts_count = len(rec["contracts"])
        total_sum = sum(c["price"] or 0 for c in rec["contracts"])
        phones = sorted(rec["phones"])
        emails = sorted(rec["emails"])
        regions_won = sorted({c["region"] for c in rec["contracts"] if c["region"]})
        last_date = max((c["sign_date"] for c in rec["contracts"]), default="")
        last_date_key = max((_dk(c["sign_date"]) for c in rec["contracts"]), default="0")
        # уверенность: остекление в названии ИЛИ ИИ подтвердил профиль (est=да) → «доказанные»,
        # иначе компания пришла из объектных контрактов (остекление вероятно в смете).
        confidence = "доказанные" if (glazing_count >= 1 or ai_da >= 1) else "вероятные"
        # тир A (обзвон) = ДОКАЗАННЫЕ с телефоном; активные-но-вероятные → email (тир B)
        if phones and confidence == "доказанные":
            tier = "A"
        elif emails:
            tier = "B"
        elif phones:
            tier = "A"
        else:
            tier = "C"
        pool.append({
            "inn": rec["inn"], "name": rec["name"], "kpp": rec["kpp"],
            "region_winner": (rec["inn"][:2] if rec.get("inn") else ""),
            "phones": phones, "emails": emails, "address": rec["address"],
            "glazing_count": glazing_count, "contracts_count": contracts_count,
            "total_sum": total_sum, "regions": regions_won,
            "last_date": last_date, "last_date_key": last_date_key,
            "confidence": confidence, "tier": tier, "contracts": rec["contracts"],
        })

    # сортировка: доказанные → повторность остекления → СВЕЖЕСТЬ → активность → сумма
    pool.sort(key=lambda r: (r["glazing_count"] > 0, r["glazing_count"],
                             r["last_date_key"], r["contracts_count"], r["total_sum"]), reverse=True)
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "window_days": days, "regions": ",".join(regions),
        "scanned_contracts": len(kept), "cards_opened": len(cands),
        "suppliers": pool,
    }


# ── выгрузка результата (JSON + CSV-листы + HTML-отчёт лейны-2) ──────────────────
def _esc(v):
    return html.escape(str(v)) if v is not None else ""


def _fmt_money(v):
    try:
        return f"{float(v):,.0f}".replace(",", " ") + " ₽"
    except (ValueError, TypeError):
        return "—"


def _load_inns(path):
    """ИНН-множество из существующего pool_*.json (для --exclude-from)."""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return {r.get("inn") for r in d.get("suppliers", []) if r.get("inn")}
    except Exception as e:
        log.warning("exclude-from %s не прочитан (%s) — ничего не исключаю", path, e)
        return set()


def write_outputs(data, tag=None):
    pool = data["suppliers"]
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    suffix = f"_{tag}" if tag else ""

    # 1) полный JSON (с тегом → отдельный файл pool_<tag>.json, без тега → основной pool.json)
    json_path = (tb_config.POOL_DIR / f"pool_{tag}.json") if tag else tb_config.POOL_FILE
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    # 2) CSV-листы: обзвон (A) и рассылка (B)
    call_rows = [r for r in pool if r["tier"] == "A"]
    mail_rows = [r for r in pool if r["tier"] == "B"]

    def _csv(path, rows, contact_key):
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Ранг", "Компания", "ИНН", "Регион_победителя", "Контакт", "Уверенность",
                        "Побед_остекление", "Контрактов_всего", "Сумма_руб",
                        "Регионы_объектов", "Последняя_дата"])
            for i, r in enumerate(rows, 1):
                contact = "; ".join(r[contact_key]) if r[contact_key] else ""
                w.writerow([i, r["name"], r["inn"], r.get("region_winner", ""), contact, r["confidence"],
                            r["glazing_count"], r["contracts_count"], int(r["total_sum"]),
                            ",".join(r["regions"]), r["last_date"]])

    call_path = tb_config.POOL_DIR / f"call_list{suffix}_{stamp}.csv"
    mail_path = tb_config.POOL_DIR / f"email_list{suffix}_{stamp}.csv"
    _csv(call_path, call_rows, "phones")
    _csv(mail_path, mail_rows, "emails")

    # 3) HTML-отчёт лейны-2 (ОТЛИЧНЫЙ дизайн от лейны-1: тёмно-бирюзовая тема)
    report_path = tb_config.POOL_DIR / f"pool_report{suffix}_{stamp}.html"
    report_path.write_text(_build_pool_html(data, len(call_rows), len(mail_rows)), encoding="utf-8")

    log.info("Сохранено:")
    log.info("  JSON пула:     %s (%d компаний)", json_path, len(pool))
    log.info("  Лист обзвона:  %s (%d тир A)", call_path, len(call_rows))
    log.info("  Лист рассылки: %s (%d тир B)", mail_path, len(mail_rows))
    log.info("  HTML-отчёт:    %s", report_path)
    return report_path


_TIER_LABEL = {"A": "📞 Обзвон (приоритет)", "B": "✉️ Email-рассылка", "C": "🔎 Без контакта"}
_TIER_COLOR = {"A": "#0d7a6f", "B": "#1f6feb", "C": "#888"}


def _supplier_card(r):
    tier = r["tier"]
    contracts = sorted(r["contracts"], key=lambda c: (c["strong"], c["sign_date"]), reverse=True)
    rows = "".join(
        f'<tr><td style="padding:2px 10px 2px 0;color:#9fb;white-space:nowrap;">{_esc(c["sign_date"])}'
        f'</td><td style="padding:2px 10px 2px 0;">{"🟢" if c["strong"] else "·"} '
        f'{_esc((c["subject"] or "")[:90])}</td>'
        f'<td style="padding:2px 0;white-space:nowrap;">{_fmt_money(c["price"])} '
        f'<a href="{_esc(c["link"])}" style="color:#7fd;">↗</a></td></tr>'
        for c in contracts[:8]
    )
    more = f'<div style="color:#789;font-size:12px;">…ещё {len(contracts)-8} контрактов</div>' \
           if len(contracts) > 8 else ""
    phones = ", ".join(r["phones"]) or "—"
    emails = ", ".join(f'<a href="mailto:{_esc(e)}" style="color:#7fd;">{_esc(e)}</a>'
                       for e in r["emails"]) or "—"
    return f"""
    <div style="border:1px solid #143b3a;border-radius:10px;padding:12px 14px;margin:10px 0;
                background:#0b1f1e;color:#dfeeec;font-family:Arial,Helvetica,sans-serif;">
      <div style="display:flex;justify-content:space-between;align-items:baseline;">
        <div style="font-size:17px;font-weight:bold;">{_esc(r["name"])}</div>
        <span style="background:{_TIER_COLOR[tier]};color:#fff;padding:2px 9px;border-radius:10px;
                     font-size:12px;">{_TIER_LABEL[tier]}</span>
      </div>
      <div style="font-size:13px;color:#9fb8b5;margin:3px 0 8px;">
        ИНН {_esc(r["inn"])} &nbsp;·&nbsp;
        <span style="color:{'#7ee0a0' if r['confidence']=='доказанные' else '#e0c97e'};">
          {'✅ доказанные' if r['confidence']=='доказанные' else '◻ вероятные'}</span>
        &nbsp;·&nbsp; 🟢 остекление в названии: <b>{r["glazing_count"]}</b>
        &nbsp;·&nbsp; всего контрактов: {r["contracts_count"]}
        &nbsp;·&nbsp; сумма: <b>{_fmt_money(r["total_sum"])}</b>
        &nbsp;·&nbsp; регионы: {_esc(",".join(r["regions"]))}
      </div>
      <div style="font-size:13px;margin-bottom:6px;">📞 {_esc(phones)} &nbsp;|&nbsp; ✉️ {emails}</div>
      <table style="font-size:13px;border-collapse:collapse;width:100%;">{rows}</table>
      {more}
    </div>
    """


def _build_pool_html(data, n_call, n_mail):
    pool = data["suppliers"]
    nA = sum(1 for r in pool if r["tier"] == "A")
    nB = sum(1 for r in pool if r["tier"] == "B")
    nC = sum(1 for r in pool if r["tier"] == "C")
    n_proven = sum(1 for r in pool if r["confidence"] == "доказанные")
    n_likely = len(pool) - n_proven
    cards = "".join(_supplier_card(r) for r in pool[:400])
    more = (f'<p style="color:#789;">…показаны первые 400 из {len(pool)} '
            f'(полный список — в pool.json и CSV).</p>') if len(pool) > 400 else ""
    return f"""<div style="background:#06100f;padding:18px;font-family:Arial,Helvetica,sans-serif;
                            max-width:900px;color:#dfeeec;">
      <div style="border-left:5px solid #0d7a6f;padding-left:12px;margin-bottom:10px;">
        <div style="font-size:12px;letter-spacing:2px;color:#0d7a6f;font-weight:bold;">
          ЛЕЙНА&nbsp;2 · ПУЛ ПОБЕДИТЕЛЕЙ (ХОЛОДНАЯ КАМПАНИЯ)</div>
        <h2 style="margin:4px 0;color:#eafffb;">🗂️ Пул генподрядчиков: {len(pool)} компаний</h2>
      </div>
      <div style="font-size:14px;margin-bottom:6px;color:#bfe;">
        📞 на обзвон (тир A): <b>{nA}</b> &nbsp;·&nbsp; ✉️ на рассылку (тир B): <b>{nB}</b>
        &nbsp;·&nbsp; 🔎 без контакта (тир C): <b>{nC}</b>
      </div>
      <div style="font-size:13px;margin-bottom:12px;color:#9fb8b5;">
        ✅ доказанные (остекление в названии): <b>{n_proven}</b> &nbsp;·&nbsp;
        ◻ вероятные (объектные, остекление в смете): <b>{n_likely}</b>
      </div>
      <div style="font-size:12px;color:#789;margin-bottom:14px;">
        Сформировано: {_esc(data["generated"])} &nbsp;|&nbsp; окно: {data["window_days"]} дн
        &nbsp;|&nbsp; регионы: {_esc(data["regions"])} &nbsp;|&nbsp;
        контрактов проанализировано: {data["scanned_contracts"]} &nbsp;|&nbsp;
        карточек открыто: {data["cards_opened"]}
      </div>
      {cards}
      {more}
    </div>"""


def main():
    p = argparse.ArgumentParser(description="TenderBot ЛЕЙНА-2 — сборщик пула победителей")
    p.add_argument("--days", type=int, default=None, help="окно сбора (дней), по умолч. год")
    p.add_argument("--max-pages", type=int, default=None, help="глубина пагинации на слово")
    p.add_argument("--limit", type=int, default=None, help="лимит открываемых карточек (тест)")
    p.add_argument("--no-cache", action="store_true", help="не использовать кэш карточек/ИИ")
    p.add_argument("--no-ai", action="store_true",
                   help="без ИИ-квалификации (быстрее, но в пуле будет шум — энергосбыт/телеком)")
    p.add_argument("--tag", default=None,
                   help="суффикс файлов вывода: pool_<tag>.json + *_<tag>_*.csv/html (раздельные списки)")
    p.add_argument("--exclude-from", default=None,
                   help="путь к pool_*.json — компании с этими ИНН ИСКЛЮЧИТЬ (анти-дубль между списками)")
    p.add_argument("--broad", action="store_true",
                   help="подмешать pool_broad_words (реконструкция/капремонт/...) — только для этого прогона")
    args = p.parse_args()

    setup_logging()
    cfg = tb_config.load_config()
    secrets = tb_config.load_secrets()
    log.info("=" * 60)
    log.info("Запуск TenderBot ЛЕЙНА-2 (пул победителей)")
    if not args.no_ai and not secrets.get("OPENROUTER_KEY"):
        log.warning("OPENROUTER_KEY не задан — пул будет собран БЕЗ ИИ-квалификации (с шумом).")

    data = build_pool(args, cfg, secrets)
    if data is None:
        log.error("Сбор пула не выполнен (ЕИС недоступен).")
        sys.exit(2)
    if args.exclude_from:
        excl = _load_inns(args.exclude_from)
        before = len(data["suppliers"])
        data["suppliers"] = [r for r in data["suppliers"] if r.get("inn") not in excl]
        log.info("Анти-дубль: исключено %d компаний из %s (было %d → стало %d)",
                 before - len(data["suppliers"]), args.exclude_from, before, len(data["suppliers"]))
    write_outputs(data, tag=args.tag)
    log.info("✅ Готово. Компаний в пуле: %d.", len(data["suppliers"]))


if __name__ == "__main__":
    main()
