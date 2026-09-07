# -*- coding: utf-8 -*-
"""Почта КАМПАНИИ (ящик рассылки = MANAGER_IMAP_*): отправка письма №1/ответов с тред-заголовками
и чтение входящих ответов. SMTP smtp.mail.ru:465, IMAP imap.mail.ru:993.
CAMPAIGN_DRY_RUN=1 (по умолч.) — реально наружу НЕ шлём (для обкатки)."""
import email
import hashlib
import imaplib
import os
import re
import smtplib
import ssl
import time
import logging
from email.message import EmailMessage
from email.header import decode_header, make_header
from email.utils import make_msgid, parseaddr

import tb_control

log = logging.getLogger("tenderbot.mail")
_BASE = os.path.dirname(os.path.abspath(__file__))
_ENV_PATH = os.path.join(_BASE, ".env")

# Safe compatibility defaults.  Importing parsing helpers must never inspect
# mailbox credentials or campaign configuration.
USER = ""
PWD = ""
IMAP_HOST = "imap.mail.ru"
IMAP_STATE = os.path.join(_BASE, "pool", "imap_state.json")
SMTP_HOST = "smtp.mail.ru"
_ENV_DRY = True


def _load_runtime_config(operation):
    """Load mail credentials only after the immutable RC1 authority gate."""
    from lead_factory.mdos_v7.authority import assert_external_allowed

    assert_external_allowed(operation)
    from dotenv import load_dotenv

    load_dotenv(_ENV_PATH)
    try:
        daily_cap = int(os.getenv("CAMPAIGN_DAILY_CAP", "30"))
    except (TypeError, ValueError):
        daily_cap = 30
    return {
        "user": os.getenv("MANAGER_IMAP_USER", ""),
        "password": os.getenv("MANAGER_IMAP_PASSWORD", ""),
        "imap_host": os.getenv("MANAGER_IMAP_HOST", "imap.mail.ru"),
        "smtp_host": os.getenv("CAMPAIGN_SMTP_HOST", "smtp.mail.ru"),
        "dry_run": os.getenv("CAMPAIGN_DRY_RUN", "1").strip()
        not in ("0", "false", "no", "off"),
        "daily_cap": daily_cap,
        "sender_backend": os.getenv("CAMPAIGN_SENDER", "mailru").strip().lower(),
    }


def is_dry():
    """Эффективный DRY: рубильник (control.json) поверх дефолта из .env."""
    return not tb_control.is_live(env_default_dry=_ENV_DRY)


def is_paused():
    return tb_control.is_paused()


def is_blocked():
    """Реально НЕ уйдёт письмо (DRY-режим ИЛИ пауза)."""
    return is_dry() or is_paused()


def mode_label():
    """Человекочитаемый режим для статусов/панели."""
    if is_paused():
        return "⏸ ПАУЗА"
    return "🔴 DRY" if is_dry() else "🟢 БОЕВОЙ"


def blocked_word():
    return "ПАУЗА: не ушло" if is_paused() else "DRY: не ушло"


def _dh(s):
    s = "" if s is None else str(s)   # msg.get() иногда отдаёт email.header.Header, не str
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


SEND_COUNTER = os.path.join(_BASE, "pool", "send_counter.json")
REPLY_COUNTER = os.path.join(_BASE, "pool", "reply_counter.json")
DAILY_CAP = 30


def _daily_count():
    import tb_outreach
    from datetime import date
    c = tb_outreach._load_json_safe(SEND_COUNTER, {})
    return c.get(date.today().isoformat(), 0)


def _bump_daily():
    import tb_outreach
    from datetime import date
    today = date.today().isoformat()
    c = tb_outreach._load_json_safe(SEND_COUNTER, {})
    c = {today: c.get(today, 0) + 1}   # держим только сегодня
    tb_outreach._save_json_atomic(SEND_COUNTER, c)


def _counter_count(path):
    import tb_outreach
    from datetime import date
    return tb_outreach._load_json_safe(path, {}).get(date.today().isoformat(), 0)


def _bump_counter(path):
    import tb_outreach
    from datetime import date
    today = date.today().isoformat()
    data = tb_outreach._load_json_safe(path, {})
    tb_outreach._save_json_atomic(path, {today: data.get(today, 0) + 1})


def reply_daily_cap():
    try:
        import tb_config
        return max(1, int(tb_config.load_config().get("reply_daily_cap", 200) or 200))
    except Exception:
        return 200


def _send_reply_now(to_addr, subject, body, *, in_reply_to="", references="", force=False, message_id=None):
    """Отправляет живой ответ с почты АлюмКомплекта в существующем треде.

    Это не массовая рассылка: письмо уходит через SMTP ящика, чтобы клиент видел
    настоящую цепочку переписки. DRY/пауза и отдельный лимит защиты соблюдаются.
    """
    msgid = message_id or make_msgid(domain=(USER.split("@")[-1] or "mail.ru"))
    if is_blocked() and not force:
        reason = "PAUSE" if is_paused() else "DRY"
        log.info("[%s] ответ НЕ отправлен → %s | %s", reason, to_addr, subject)
        return msgid
    config = _load_runtime_config("smtp:thread_reply")
    if not force and _counter_count(REPLY_COUNTER) >= reply_daily_cap():
        raise RuntimeError("дневной лимит ответов исчерпан — нужна ручная проверка")
    clean_subject = (subject or "Ответ по заявке").replace("\r", "").replace("\n", " ").strip()
    if not clean_subject.lower().startswith("re:"):
        clean_subject = "Re: " + clean_subject
    msg = EmailMessage()
    msg["Message-ID"] = msgid
    msg["Subject"] = clean_subject
    msg["From"] = config["user"]
    msg["To"] = to_addr
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = ((references or "").strip() + " " + in_reply_to).strip()
    msg.set_content(body)
    last = None
    for attempt in range(3):
        try:
            from lead_factory.mdos_v7.authority import assert_external_allowed

            assert_external_allowed("smtp:thread_reply")
            with smtplib.SMTP_SSL(
                config["smtp_host"],
                465,
                context=ssl.create_default_context(),
                timeout=25,
            ) as s:
                s.login(config["user"], config["password"])
                s.send_message(msg)
            if not force:
                _bump_counter(REPLY_COUNTER)
            log.info("Ответ отправлен в тред → %s | %s", to_addr, clean_subject)
            return msgid
        except Exception as e:
            from lead_factory.mdos_v7.authority import ExternalAuthorityError

            if isinstance(e, ExternalAuthorityError):
                raise
            last = e
            log.warning("SMTP ответ попытка %d не удался: %s", attempt + 1, e)
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"SMTP не отправил ответ после 3 попыток: {last}")


def _queued_subject(subject):
    clean = (subject or "Reply").replace("\r", "").replace("\n", " ").strip()
    return clean if clean.lower().startswith("re:") else "Re: " + clean


def _queue_reply(msgid, to_addr, subject, body, in_reply_to, references, error):
    # Local import prevents a circular import: the queue calls deliver_queued_reply.
    import tb_reply_outbox
    tb_reply_outbox.enqueue(msgid=msgid, to_addr=to_addr, subject=subject, body=body,
                            in_reply_to=in_reply_to, references=references, error=error)
    log.warning("Automatic reply queued after SMTP failure -> %s", to_addr)
    return msgid


def send_reply(to_addr, subject, body, *, in_reply_to="", references="", force=False, queue_on_fail=True):
    """Send a thread reply, retaining it in a local queue if SMTP is unavailable."""
    msgid = make_msgid(domain=(USER.split("@")[-1] or "mail.ru"))
    if is_blocked() and not force:
        log.info("Automatic reply deferred by pause/dry mode -> %s", to_addr)
        return ""
    try:
        return _send_reply_now(to_addr, subject, body, in_reply_to=in_reply_to,
                               references=references, force=force, message_id=msgid)
    except Exception as e:
        from lead_factory.mdos_v7.authority import ExternalAuthorityError

        if isinstance(e, ExternalAuthorityError):
            raise
        if not queue_on_fail:
            raise
        return _queue_reply(msgid, to_addr, _queued_subject(subject), body,
                            in_reply_to, references, str(e))


def deliver_queued_reply(record):
    """Used by tb_reply_outbox; preserves the original Message-ID and thread."""
    if is_blocked():
        return "deferred", "mailing is paused or dry-run"
    if _counter_count(REPLY_COUNTER) >= reply_daily_cap():
        return "deferred", "reply daily cap reached"
    try:
        _send_reply_now(record.get("to", ""), record.get("subject", ""), record.get("body", ""),
                        in_reply_to=record.get("in_reply_to", ""),
                        references=record.get("references", ""),
                        message_id=record.get("msgid", ""))
        return "sent", ""
    except Exception as e:
        from lead_factory.mdos_v7.authority import ExternalAuthorityError

        if isinstance(e, ExternalAuthorityError):
            raise
        return "failed", str(e)


def send(to_addr, subject, body, attachments=None, in_reply_to=None, references=None, force=False):
    """Отправляет письмо. Возвращает Message-ID (свой, сохраняем для матчинга тредов).
    attachments — список (filename, bytes, mime). В DRY-режиме реально не шлёт (если не force)."""
    msgid = make_msgid(domain=(USER.split("@")[-1] or "mail.ru"))
    if is_blocked() and not force:
        reason = "PAUSE" if is_paused() else "DRY"
        log.info("[%s] письмо НЕ отправлено → %s | %s | msgid=%s", reason, to_addr, subject, msgid)
        return msgid
    config = _load_runtime_config("smtp:campaign_send")
    if not force and _daily_count() >= config["daily_cap"]:
        raise RuntimeError(
            f"дневной лимит отправки {config['daily_cap']} исчерпан — "
            "остальное завтра (анти-спам)"
        )
    # Бэкенд отправки (CAMPAIGN_SENDER): "unisender" | "mailru" | "auto".
    #  auto — умная маршрутизация по домену получателя (owner 2026-07-15): mail.ru-семья
    #  режет наш новый домен как спам → шлём ей со старого mail.ru; всё остальное (yandex/gmail/
    #  корп.) отлично доходит через Unisender GO. Гейты DRY/пауза/дневной кап уже проверены выше.
    _backend = config["sender_backend"]
    if _backend == "auto":
        _dom = (to_addr or "").rsplit("@", 1)[-1].lower()
        _MAILRU = {"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru", "mail.ua"}
        _backend = "mailru" if _dom in _MAILRU else "unisender"
    if _backend == "unisender":
        import tb_unisender
        mid = tb_unisender.send(to_addr, subject, body, attachments=attachments,
                                in_reply_to=in_reply_to, references=references, force=force)
        if not force:
            _bump_daily()
        log.info("Письмо отправлено через Unisender → %s | %s", to_addr, subject)
        return mid
    msg = EmailMessage()
    msg["Message-ID"] = msgid
    msg["Subject"] = subject
    msg["From"] = config["user"]
    msg["To"] = to_addr
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (references or "") + " " + in_reply_to
    # one-click отписка + текстовый opt-out (анти-спам/право)
    msg["List-Unsubscribe"] = f"<mailto:{config['user']}?subject=Unsubscribe>"
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    msg.set_content(body)
    for att in (attachments or []):
        fn, data, mime = att
        maintype, _, subtype = (mime or "application/octet-stream").partition("/")
        msg.add_attachment(data, maintype=maintype or "application",
                           subtype=subtype or "octet-stream", filename=fn)
    last = None
    for attempt in range(3):
        try:
            from lead_factory.mdos_v7.authority import assert_external_allowed

            assert_external_allowed("smtp:campaign_send")
            with smtplib.SMTP_SSL(
                config["smtp_host"],
                465,
                context=ssl.create_default_context(),
                timeout=25,
            ) as s:
                s.login(config["user"], config["password"])
                s.send_message(msg)
            if not force:
                _bump_daily()
            log.info("Письмо отправлено → %s | %s", to_addr, subject)
            return msgid
        except Exception as e:
            from lead_factory.mdos_v7.authority import ExternalAuthorityError

            if isinstance(e, ExternalAuthorityError):
                raise
            last = e
            log.warning("SMTP попытка %d не удалась: %s", attempt + 1, e)
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"SMTP не отправил после 3 попыток: {last}")


_BOUNCE_FROM = ("mailer-daemon", "postmaster", "mail-daemon")
_BOUNCE_SUBJ = ("undeliver", "delivery failed", "delivery status", "failure notice",
                "returned mail", "возврат", "не доставлено", "mail delivery")


def is_bounce(parsed):
    fr = (parsed.get("from") or "").lower()
    subj = (parsed.get("subject") or "").lower()
    return any(x in fr for x in _BOUNCE_FROM) or any(x in subj for x in _BOUNCE_SUBJ)


# ── IMAP ────────────────────────────────────────────────────────────────────────
def _imap():
    config = _load_runtime_config("imap:mailbox_read")
    from lead_factory.mdos_v7.authority import ExternalAuthorityError, assert_external_allowed

    import tb_netguard
    try:
        assert_external_allowed("imap:mailbox_read")
        M = imaplib.IMAP4_SSL(
            config["imap_host"],
            993,
            timeout=25,
        )  # таймаут — иначе зависший коннект морозит бот
        try:
            assert_external_allowed("imap:mailbox_read")
            M._simple_command("ID", '("name" "TenderBot" "version" "1.0")')
            M._untagged_response("OK", [None], "ID")
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        assert_external_allowed("imap:mailbox_read")
        M.login(config["user"], config["password"])
    except ExternalAuthorityError:
        raise
    except Exception as e:
        tb_netguard.record_fail(e)      # взвести предохранитель — не долбить IMAP весь цикл
        raise
    tb_netguard.record_ok()             # коннект удался — снять кулдаун
    return M


def _folder(M, flag, fallback="INBOX"):
    typ, folders = M.list()
    for f in folders or []:
        s = f.decode("utf-8", "replace") if isinstance(f, bytes) else str(f)
        if flag in s:
            m = re.search(r'"([^"]*)"\s*$', s)
            if m:
                return m.group(1)
    return fallback


def _strip_html(h):
    h = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", h)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    return re.sub(r"&[a-z#0-9]+;", " ", h)


def _parse(msg):
    plain = htmltxt = ""
    attachments = []
    for p in (msg.walk() if msg.is_multipart() else [msg]):
        if p.get_content_maintype() == "multipart":
            continue
        disp = str(p.get("Content-Disposition", ""))
        fn = p.get_filename()
        if fn or "attachment" in disp:
            attachments.append(_dh(fn or "вложение"))
            continue
        try:
            txt = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8", "replace")
        except Exception:
            continue
        if p.get_content_type() == "text/plain" and not plain:
            plain = txt
        elif p.get_content_type() == "text/html" and not htmltxt:
            htmltxt = _strip_html(txt)
    return {
        # str(...) — msg.get() может вернуть email.header.Header (кодированные не-ASCII заголовки),
        # тогда parseaddr/.strip падают ("object of type 'Header' has no len()") и зависает весь poll
        "msgid": str(msg.get("Message-ID") or "").strip(),
        "in_reply_to": str(msg.get("In-Reply-To") or "").strip(),
        "references": str(msg.get("References") or "").strip(),
        "from": parseaddr(str(msg.get("From", "")))[1].lower(),
        "to": parseaddr(str(msg.get("To", "")))[1].lower(),
        "subject": _dh(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "body": (plain or htmltxt).strip(),
        "attachments": attachments,
    }


def fetch_recent(flag="\\Inbox", limit=40):
    """Последние N писем из папки (по умолчанию входящие). Для триажа."""
    M = _imap()
    out = []
    try:
        M.select(f'"{_folder(M, flag)}"', readonly=True)
        typ, data = M.search(None, "ALL")
        ids = data[0].split()[-limit:]
        for i in reversed(ids):
            try:
                typ, md = M.fetch(i, "(RFC822)")
                out.append(_parse(email.message_from_bytes(md[0][1])))
            except Exception:
                continue
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return out


def fetch_uid_batch(flag="\\Inbox", after_uid=0, limit=200, uids=None):
    """Read a UID batch without mutating any cursor.

    The Lead Factory keeps its cursor in its own SQLite transaction and advances
    it only after durable event persistence. This helper deliberately does not
    touch the legacy ``pool/imap_state.json`` cursor.

    ``uids`` is an optional exact, ordered UID manifest.  It exists solely so a
    durable worker can resume its previously persisted SEARCH result after a
    restart without doing a new SEARCH.  Callers without a manifest retain the
    original ``after_uid`` behaviour.
    """
    after_uid = max(0, int(after_uid or 0))
    limit = max(1, min(int(limit or 200), 1000))
    exact_uids = None
    if uids is not None:
        exact_uids = [int(uid) for uid in uids]
        if not exact_uids or any(uid <= 0 for uid in exact_uids):
            raise ValueError("uids must contain positive UIDs")
        if exact_uids != sorted(set(exact_uids)):
            raise ValueError("uids must be unique and strictly increasing")
        if len(exact_uids) > limit:
            raise ValueError("uids exceed requested batch limit")
    M = _imap()
    out = []
    try:
        M.select(f'"{_folder(M, flag)}"', readonly=True)
        uv = M.untagged_responses.get("UIDVALIDITY")
        uidvalidity = (uv[0].decode() if uv and uv[0] else "")
        if exact_uids is None:
            typ, data = M.uid("search", None, f"UID {after_uid + 1}:*")
            available_uids = sorted(
                int(x) for x in (data[0].split() if typ == "OK" and data and data[0] else [])
                if int(x) > after_uid
            )
            selected = available_uids[:limit]
        else:
            # Do not replace a durable manifest with a fresh SEARCH on restart.
            available_uids = exact_uids
            selected = exact_uids
        for uid in selected:
            try:
                typ, md = M.uid("fetch", str(uid), "(RFC822)")
                if typ != "OK" or not md or not md[0] or not isinstance(md[0], tuple):
                    break
                raw = md[0][1]
                if not isinstance(raw, bytes) or not raw:
                    break
                try:
                    parsed = _parse(email.message_from_bytes(raw))
                except Exception as exc:
                    # Preserve malformed mail as raw UNROUTED evidence. The
                    # unified worker can route it to review later; a parser
                    # defect must not make this UID permanently invisible.
                    parsed = {
                        "msgid": "",
                        "in_reply_to": "",
                        "references": "",
                        "from": "",
                        "to": "",
                        "subject": "",
                        "date": "",
                        "body": "",
                        "attachments": [],
                        "parse_error_class": type(exc).__name__,
                    }
                parsed["uid"] = uid
                parsed["uidvalidity"] = uidvalidity
                # The stage unified inbox persists this immutable MIME evidence
                # before its local event/cursor transaction.  No legacy poller
                # consumes this field.
                parsed["rfc822_bytes"] = raw
                parsed["rfc822_sha256"] = hashlib.sha256(raw).hexdigest()
                parsed["rfc822_size"] = len(raw)
                out.append(parsed)
            except Exception:
                break
        return {
            "uidvalidity": uidvalidity,
            "selected_uids": selected,
            "messages": out,
            "last_available_uid": max(available_uids) if available_uids else after_uid,
        }
    finally:
        try:
            M.logout()
        except Exception:
            pass


def attachment_context(reply, max_file_mb=12, max_total_mb=20, max_chars=12000):
    """Извлекает текст пригодных для чтения вложений из конкретного входящего письма.

    Файлы не сохраняются на диск. Поддерживаются PDF с текстовым слоем, DOCX, XLSX/XLSM
    и TXT/CSV; сканы и старые форматы честно помечаются как непрочитанные.
    """
    preset = reply.get("_document_context")
    if isinstance(preset, dict):
        return preset
    result = {"text": "", "files": list(reply.get("attachments") or []),
              "readable_files": [], "unreadable_files": []}
    msgid = (reply.get("msgid") or "").strip()
    if not msgid:
        return result
    M = _imap()
    try:
        folder = _folder(M, "\\Inbox")
        M.select(f'"{folder}"', readonly=True)
        typ, data = M.search(None, "HEADER", "Message-ID", msgid)
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        if not ids:
            return result
        typ, md = M.fetch(ids[-1], "(RFC822)")
        if not md or not md[0] or not isinstance(md[0], tuple):
            return result
        message = email.message_from_bytes(md[0][1])
        import tb_smeta
        total = 0
        text_parts = []
        max_file = max_file_mb * 1024 * 1024
        max_total = max_total_mb * 1024 * 1024
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            filename = part.get_filename()
            disp = str(part.get("Content-Disposition", "")).lower()
            if not filename and "attachment" not in disp:
                continue
            filename = _dh(filename or "вложение")
            try:
                content = part.get_payload(decode=True) or b""
            except Exception:
                content = b""
            if not content or len(content) > max_file or total + len(content) > max_total:
                result["unreadable_files"].append(filename)
                continue
            total += len(content)
            low = filename.lower()
            if low.endswith((".txt", ".csv")):
                text = content.decode("utf-8", "replace")
            elif low.endswith((".pdf", ".docx", ".xlsx", ".xlsm", ".png", ".jpg", ".jpeg", ".tif", ".tiff")):
                text = tb_smeta.extract_text(filename, content)
            else:
                text = ""
            if text.strip():
                result["readable_files"].append(filename)
                text_parts.append(f"--- {filename} ---\n{text[:max_chars]}")
            else:
                result["unreadable_files"].append(filename)
            if sum(len(x) for x in text_parts) >= max_chars:
                break
        result["text"] = "\n\n".join(text_parts)[:max_chars]
        return result
    except Exception as e:
        log.warning("Не удалось прочитать вложения %s: %s", msgid, e)
        return result
    finally:
        try:
            M.logout()
        except Exception:
            pass


def fetch_sent(limit=60):
    return fetch_recent(flag="\\Sent", limit=limit)


def fetch_new_inbox(max_batch=200):
    """UID-инкрементальное чтение входящих: только НОВЫЕ письма с прошлого раза.
    Не зависит от \\Seen (общий ящик, человек читает почту), не теряет при >50/интервал.
    Первый запуск фиксирует текущий максимум UID и историю НЕ тянет."""
    import tb_outreach
    M = _imap()
    out = []
    try:
        folder = _folder(M, "\\Inbox")
        M.select(f'"{folder}"', readonly=True)
        uv = M.untagged_responses.get("UIDVALIDITY")
        uidval = (uv[0].decode() if uv and uv[0] else "")
        st = tb_outreach._load_json_safe(IMAP_STATE, {})
        cur = st.get("inbox", {})
        last = cur.get("uid", 0) if cur.get("uidvalidity") == uidval else 0
        typ, d = M.uid("search", None, f"UID {last + 1}:*")
        uids = sorted(int(x) for x in (d[0].split() if d and d[0] else []) if int(x) > last)
        if not uids:
            return []
        newmax = max(uids)
        if last == 0:
            st["inbox"] = {"uid": newmax, "uidvalidity": uidval}   # старт «отсюда», без истории
            tb_outreach._save_json_atomic(IMAP_STATE, st)
            return []
        # Process the oldest unread batch first. Advancing to the newest UID here
        # would silently skip replies after a temporary outage or a busy morning.
        selected = uids[:max(1, int(max_batch))]
        for u in selected:
            typ, md = M.uid("fetch", str(u), "(RFC822)")
            if md and md[0] and isinstance(md[0], tuple):
                p = _parse(email.message_from_bytes(md[0][1]))
                p["uid"] = u
                out.append(p)
        st["inbox"] = {"uid": selected[-1], "uidvalidity": uidval}
        tb_outreach._save_json_atomic(IMAP_STATE, st)
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return out
