# -*- coding: utf-8 -*-
"""ЛИДЫ ОТ FACADE.RU — 3-й канал, НЕЗАВИСИМО от лейн 1/2.
Facade.ru (info@facade.ru, сервис «Бастион») пересылает заявки реальных заказчиков на
alumkomplekt@mail.ru. Бот читает их → ИИ извлекает контакт заказчика → лид в Bitrix + 🔥 в Telegram.
Дедуп по Message-ID. ПЕРВЫЙ запуск НЕ бэкфилит историю (только помечает) — лиды лишь с новых писем."""
import email
import email.utils
import imaplib
import logging
import os
import re

import tb_ai
import tb_bitrix
import tb_config
import tb_leaddocs
import tb_mail
import tb_outreach
import tb_telegram as tg

from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import guarded_manual_egress_attempt

log = logging.getLogger("tenderbot.facade")

BASE = os.path.dirname(os.path.abspath(__file__))
PROCESSED = os.path.join(BASE, "pool", "facade_processed.json")
FACADE_FROM = "info@facade.ru"
_OPERATION = "legacy.imap.facade"


def _imap_call(method, source, transport, /, *args, **kwargs):
    return guarded_manual_egress_attempt(
        _OPERATION,
        method,
        source,
        transport,
        *args,
        **kwargs,
    )

# ── анти-дубль (owner 2026-07-14): не плодить лид, если тот же клиент+объект уже открыт ──
# стоп-слова: канцелярит + GENERIC-термины остекления (они есть на КАЖДОЙ заявке и НЕ отличают
# заказ) → идентичность объекта держится на адресе/названии (Байкальская, школа №N, ЖК …).
_OBJ_STOP = {"выполнение", "работ", "работы", "оказание", "услуг", "поставка", "монтаж",
             "изготовление", "объект", "адрес", "город", "запрос", "заявка",
             "витраж", "витражи", "витражные", "витражных", "остекление", "остекления",
             "окна", "окон", "оконные", "двери", "дверей", "дверные", "фасад", "фасады",
             "фасадные", "фасадных", "конструкции", "конструкций", "светопрозрачные",
             "светопрозрачных", "алюминиевые", "алюминиевых"}


def _obj_tokens(s):
    s = re.sub(r"[^а-яёa-z0-9 ]", " ", (s or "").lower())
    return {w for w in s.split() if len(w) > 3 and w not in _OBJ_STOP}


def _obj_similar(a, b):
    """Похож ли объект — чтобы отличить ПОВТОР заявки от НОВОГО заказа того же клиента.
    Метрика overlap (|A∩B|/min) ≥ 0.6 — устойчива к тому, что объект в заголовке лида обрезан."""
    A, B = _obj_tokens(a), _obj_tokens(b)
    return bool(A and B) and len(A & B) / min(len(A), len(B)) >= 0.6


def _find_open_dup(email_addr, obj):
    """Открытый facade-лид того же клиента (по email) с ПОХОЖИМ объектом → его id, иначе None.
    JUNK пропускаем (закрытые дубли); свежие сверху."""
    email_addr = (email_addr or "").strip().lower()
    if not email_addr or "@" not in email_addr:
        return None
    r = tb_bitrix._call("crm.lead.list", {"filter": {"EMAIL": email_addr},
                        "select": ["ID", "TITLE", "STATUS_ID"], "order": {"ID": "DESC"}})
    for L in (r.get("result") or []):
        if L.get("STATUS_ID") == "JUNK":
            continue
        title = L.get("TITLE") or ""
        if not title.startswith("Facade.ru"):
            continue
        tobj = title.split("—", 1)[1] if "—" in title else title
        if _obj_similar(obj, tobj):
            return L.get("ID")
    return None


def _imap():
    import tb_netguard
    sec = _imap_call(
        "credential.read",
        "config:legacy_secrets",
        tb_config.load_secrets,
    )
    try:
        M = _imap_call(
            "connect",
            "imap:manager_mailbox",
            imaplib.IMAP4_SSL,
            "imap.mail.ru",
            993,
            timeout=25,
        )
        try:
            _imap_call(
                "id.command",
                "imap:manager_mailbox",
                M._simple_command,
                "ID",
                '("name" "TenderBot" "version" "1.0")',
            )
            _imap_call(
                "id.response",
                "imap:manager_mailbox",
                M._untagged_response,
                "OK",
                [None],
                "ID",
            )
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        _imap_call(
            "login",
            "imap:manager_mailbox",
            M.login,
            sec["SMTP_USER"],
            sec["SMTP_PASSWORD"],
        )
    except Exception as e:
        tb_netguard.record_fail(e)
        raise
    tb_netguard.record_ok()
    return M


def _processed():
    return set(tb_outreach._load_json_safe(PROCESSED, {"ids": []}).get("ids", []))


def _save_processed(ids):
    tb_outreach._save_json_atomic(PROCESSED, {"ids": sorted(ids)})


def _make_lead(cfg, secrets, parsed, f, atts, msg, mid):
    """Заводит лид Bitrix + прикладывает тело письма и файлы + шлёт карточку в Telegram."""
    company = f.get("company") or "(заказчик не распознан)"
    obj = f.get("object") or parsed.get("subject", "")
    # анти-дубль: тот же клиент (email) + похожий объект уже открыт → приложить туда, лид НЕ плодим
    dup = _find_open_dup(f.get("email", ""), obj)
    if dup:
        try:
            attached = tb_leaddocs.attach_message_to_lead(
                dup, msg, frm=(f.get("email") or FACADE_FROM),
                subj=parsed.get("subject", ""), msgid=mid, force_body=True)
            tb_leaddocs.register_lead(dup, thread_msgids=[mid])
        except Exception as e:
            log.warning("facade dedup attach %s: %s", dup, e)
            attached = []
        tg.send_message(
            f"🔁 Повтор заявки Facade.ru — приложил к существующему лиду #{dup} ({company[:40]}), "
            f"новый НЕ создавал."
            + (("\n📎 " + ", ".join(a[:30] for a in attached)) if attached else "")
            + f"\n{tb_bitrix.lead_url(dup)}")
        return dup
    atts_line = ("\nВложения: " + ", ".join(atts)) if atts else ""
    title = f"Facade.ru: {company[:50]} — {obj[:50]}"
    comments = (
        "Источник: Facade.ru (Бастион) — пересланная заявка.\n"
        f"Компания: {company}\n"
        f"Контакт: {f.get('contact_name','')}\n"
        f"Телефон: {f.get('phone','')}\n"
        f"Email: {f.get('email','')}\n"
        f"Объект: {obj}\n"
        f"Запрос: {f.get('request','')}\n"
        f"Тема письма: {parsed.get('subject','')}{atts_line}\n"
        f"--- Текст заявки ---\n{(parsed.get('body','') or '')[:1500]}"
    )
    lid = tb_bitrix.create_lead(title=title, company=company,
                                name=f.get("contact_name", ""), phone=f.get("phone", ""),
                                email=f.get("email", ""), comments=comments, source_id="WEB")
    # приложить ТЕЛО письма (заявку целиком) + ВСЕ файлы-вложения к карточке Bitrix
    attached = []
    if lid:
        try:
            attached = tb_leaddocs.attach_message_to_lead(
                lid, msg, frm=(f.get("email") or FACADE_FROM), subj=parsed.get("subject", ""),
                msgid=mid, force_body=True)
            tb_leaddocs.register_lead(lid, company=company,
                                      emails=[f.get("email", "")], thread_msgids=[mid])
        except Exception as e:
            log.warning("facade attach %s: %s", lid, e)
    card = (
        "📥 Новая заявка Facade.ru\n"
        f"🏢 {company[:55]}\n"
        f"📍 {obj[:70]}\n"
        f"👤 {f.get('contact_name') or '—'}  ✉️ {f.get('email') or '—'}  📞 {f.get('phone') or '—'}\n"
        f"🔧 {f.get('request','')[:60]}"
        + (("\n📎 " + ", ".join(a[:30] for a in atts)) if atts else "")
    )
    if attached:
        card += "\n📎 в Bitrix приложено: " + ", ".join(a[:30] for a in attached)
    card += (f"\n✅ Лид Bitrix #{lid}\n{tb_bitrix.lead_url(lid)}" if lid
             else "\n⚠️ Bitrix сейчас не принял лид — сохранил в очередь, догружу после включения REST.")
    tg.send_message(card)
    return lid


def poll(cfg, secrets):
    """Обрабатывает НОВЫЕ заявки facade.ru. Возвращает число заведённых лидов."""
    from lead_factory.mdos_v7.authority import ExternalAuthorityError

    seen = _processed()
    first_run = not seen
    try:
        M = _imap()
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("facade imap login: %s", e)
        return 0
    n = 0
    try:
        _imap_call(
            "select.readonly",
            "imap:manager_mailbox",
            M.select,
            "INBOX",
            readonly=True,
        )
        typ, data = _imap_call(
            "search",
            "imap:manager_mailbox",
            M.search,
            None,
            "FROM",
            "facade",
        )
        ids = data[0].split() if data and data[0] else []
        for i in ids[-50:]:                       # последние 50 писем от facade
            typ, md = _imap_call(
                "fetch.message",
                "imap:manager_mailbox",
                M.fetch,
                i,
                "(RFC822)",
            )
            if not (md and md[0] and isinstance(md[0], tuple)):
                continue
            msg = email.message_from_bytes(md[0][1])
            mid = str(msg.get("Message-ID") or "").strip()
            frm = email.utils.parseaddr(str(msg.get("From", "")))[1].lower()
            if FACADE_FROM not in frm or not mid or mid in seen:
                continue
            if first_run:
                seen.add(mid)
                continue                          # первый запуск: только помечаем, БЕЗ лидов
            parsed = tb_mail._parse(msg)          # from/subject/body(html→текст)/attachments
            try:
                f = tb_ai.extract_facade_lead(secrets["OPENROUTER_KEY"], cfg["model"],
                                              parsed.get("subject", ""), parsed.get("body", ""))
            except Exception as e:
                log.warning("facade extract: %s", e)
                f = {"company": "", "contact_name": "", "email": "", "phone": "",
                     "object": parsed.get("subject", ""), "request": ""}
            lid = _make_lead(cfg, secrets, parsed, f, parsed.get("attachments") or [], msg, mid)
            if lid or tb_bitrix.last_error():
                # При недоступном Bitrix create_lead кладёт запись в локальную очередь.
                # Поэтому письмо можно считать учтённым, но не потерянным.
                seen.add(mid)
            n += 1
    except Exception as e:
        log.warning("facade poll: %s", e)
    finally:
        try:
            _imap_call(
                "logout",
                "imap:manager_mailbox",
                M.logout,
            )
        except Exception:
            pass
    _save_processed(seen)
    if first_run:
        log.info("facade: первый запуск — помечено %d исторических, лиды не создавались", len(seen))
    return n
