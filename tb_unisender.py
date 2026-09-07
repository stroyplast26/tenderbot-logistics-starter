# -*- coding: utf-8 -*-
"""Отправка писем через Unisender GO (транзакционный API, регион go2).
Совместимая с tb_mail сигнатура send(), чтобы кампания могла переключиться сюда без переделок.
Ключ/хост/отправитель — из .env (UNISENDER_GO_API_KEY / UNISENDER_GO_HOST / CAMPAIGN_FROM_EMAIL /
CAMPAIGN_FROM_NAME). Домен отправителя должен быть ПОДТВЕРЖДЁН в Unisender (DKIM/SPF), иначе 401/ошибка.
"""
import base64
import json
import os
import time
import logging
import html as _html
from datetime import date

import requests

log = logging.getLogger("tenderbot.unisender")
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

# Safe compatibility defaults: importing the legacy adapter must not inspect
# credentials or sender/recipient configuration.
_KEY = ""
_HOST = "go2.unisender.ru"
_FROM_EMAIL = ""
_FROM_NAME = "АлюмКомплект"
_REPLY_TO = "alumkomplekt@mail.ru"
_API = f"https://{_HOST}/ru/transactional/api/v1"
_ACCOUNT_COUNTER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pool", "unisender_account_send_counter.json")


def _load_runtime_config(operation):
    """Load Unisender credentials only after the immutable RC1 authority gate."""
    from lead_factory.mdos_v7.authority import assert_external_allowed

    assert_external_allowed(operation)
    from dotenv import load_dotenv

    load_dotenv(_ENV_PATH)
    host = os.getenv("UNISENDER_GO_HOST", "go2.unisender.ru").strip()
    reply_to = (
        os.getenv("CAMPAIGN_REPLY_TO", "").strip()
        or os.getenv("MANAGER_IMAP_USER", "").strip()
        or "alumkomplekt@mail.ru"
    )
    return {
        "key": os.getenv("UNISENDER_GO_API_KEY", "").strip(),
        "host": host,
        "api": f"https://{host}/ru/transactional/api/v1",
        "from_email": os.getenv("CAMPAIGN_FROM_EMAIL", "").strip(),
        "from_name": os.getenv("CAMPAIGN_FROM_NAME", "АлюмКомплект").strip(),
        "reply_to": reply_to,
        "from_emails": os.getenv("CAMPAIGN_FROM_EMAILS", ""),
        "from_email_2": os.getenv("CAMPAIGN_FROM_EMAIL_2", ""),
    }


def _split_emails(raw):
    return [x.strip() for x in (raw or "").replace(";", ",").split(",") if x.strip()]


def _sender_emails_from_config(config):
    candidates = []
    primary = config.get("from_email", "")
    if primary:
        candidates.append(primary)
    candidates.extend(_split_emails(config.get("from_emails", "")))
    candidates.extend(_split_emails(config.get("from_email_2", "")))
    out, seen = [], set()
    for email in candidates:
        key = email.lower()
        if key not in seen:
            seen.add(key)
            out.append(email)
    return out


def sender_emails():
    """Safe import-time sender view; RC1 does not expose environment values."""
    return _sender_emails_from_config({"from_email": _FROM_EMAIL})


def account_daily_cap():
    """Configured account-wide cap; sender domains do not multiply it."""
    try:
        import tb_config
        return max(1, int(tb_config.load_config().get("campaign_daily_cap", 2000) or 2000))
    except Exception:
        return 2000


def account_daily_count(day=None):
    day = day or date.today().isoformat()
    try:
        with open(_ACCOUNT_COUNTER, encoding="utf-8") as f:
            data = json.load(f)
        return int(data.get(day, 0) or 0)
    except (OSError, ValueError, TypeError):
        return 0


def _bump_account_daily_count():
    today = date.today().isoformat()
    try:
        with open(_ACCOUNT_COUNTER, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError):
        data = {}
    data = {today: int(data.get(today, 0) or 0) + 1}
    os.makedirs(os.path.dirname(_ACCOUNT_COUNTER), exist_ok=True)
    tmp = _ACCOUNT_COUNTER + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, _ACCOUNT_COUNTER)


def _reserve_account_slot() -> bool:
    """Atomically reserve one account-wide Unisender slot before sending."""
    import tb_outreach
    today = date.today().isoformat()
    with tb_outreach._locked():
        data = tb_outreach._load_json_safe(_ACCOUNT_COUNTER, {})
        used = int(data.get(today, 0) or 0)
        if used >= account_daily_cap():
            return False
        tb_outreach._save_json_atomic(_ACCOUNT_COUNTER, {today: used + 1})
    return True


def _release_account_slot() -> None:
    """Release a reservation when Unisender rejected the message before accepting it."""
    import tb_outreach
    today = date.today().isoformat()
    with tb_outreach._locked():
        data = tb_outreach._load_json_safe(_ACCOUNT_COUNTER, {})
        used = max(0, int(data.get(today, 0) or 0) - 1)
        tb_outreach._save_json_atomic(_ACCOUNT_COUNTER, {today: used})


class UnisenderSendError(RuntimeError):
    def __init__(self, response):
        self.response = response or {}
        self.code = self.response.get("code")
        self.failed_emails = self.response.get("failed_emails") or {}
        msg = self.response.get("message") or self.response
        if self.failed_emails:
            msg = f"{msg}; failed_emails={self.failed_emails}"
        super().__init__(f"Unisender не принял: {msg}")


def is_configured():
    """Готов ли Unisender к боевой отправке (есть ключ И задан подтверждённый отправитель)."""
    return bool(_KEY and sender_emails())


def _call(method, payload, timeout=30):
    from lead_factory.mdos_v7.authority import external_block_reason
    return {
        "status": "error",
        "code": "MDOS_V7_DEFAULT_DENY",
        "message": external_block_reason(f"unisender:{method}"),
    }

    # Retained below for a future, separately ratified adapter release.  It is
    # unreachable under the immutable 7.1.0-rc.1 authority package.
    config = _load_runtime_config(f"unisender:{method}")
    body = {"api_key": config["key"], **payload}
    last = None
    for attempt in range(3):
        try:
            from lead_factory.mdos_v7.authority import assert_external_allowed

            assert_external_allowed(f"unisender:{method}")
            r = requests.post(
                f"{config['api']}/{method}",
                json=body,
                timeout=timeout,
                allow_redirects=False,
            )
            j = r.json()
            if j.get("status") == "success":
                return j
            # логическая ошибка (нет домена/лимит) — не ретраим бесконечно
            log.warning("Unisender %s error: %s", method, j)
            return j
        except Exception as e:
            last = e
            log.warning("Unisender %s попытка %d: %s", method, attempt + 1, e)
            time.sleep(2 * (attempt + 1))
    return {"status": "error", "message": f"network: {last}"}


def _plain_to_html(text):
    return "<html><body style='font-family:sans-serif;font-size:14px;color:#111'>" + \
           _html.escape(text).replace("\n", "<br>") + "</body></html>"


def send(to_addr, subject, body, attachments=None, in_reply_to=None, references=None,
         force=False, from_email=None, from_name=None):
    """Шлёт письмо через Unisender GO. Возвращает message_id (для матчинга) или бросает.
    attachments — список (filename, bytes, mime). Сигнатура совместима с tb_mail.send."""
    config = _load_runtime_config("unisender:email/send.json")
    reserved = False
    if not force:
        if not _reserve_account_slot():
            raise RuntimeError(f"Unisender account daily limit {account_daily_cap()} reached")
        reserved = True
    if not config["key"]:
        raise RuntimeError("UNISENDER_GO_API_KEY не задан")
    selected_from = (from_email or config["from_email"]).strip()
    selected_name = (from_name or config["from_name"]).strip()
    if not selected_from:
        raise RuntimeError("CAMPAIGN_FROM_EMAIL не задан (подтверди домен в Unisender и впиши адрес в .env)")
    msg = {
        "recipients": [{"email": to_addr}],
        "subject": subject,
        "from_email": selected_from,
        "from_name": selected_name,
        "reply_to": config["reply_to"],  # ответы → на читаемый ящик кампании
        "body": {"html": _plain_to_html(body), "plaintext": body},
        # Трекинг открытий/кликов ТРЕБУЕТ отдельного tracking-домена (CNAME). Пока его нет —
        # выключено (иначе API 229). Включить, когда добавим tracking-домен в Unisender.
        "track_read": 0,
        "track_links": 0,
        "skip_unsubscribe": 0,          # Unisender сам добавит ссылку отписки (анти-спам)
        "global_language": "ru",
    }
    atts = []
    for fn, data, mime in (attachments or []):
        atts.append({"type": mime or "application/octet-stream", "name": fn,
                     "content": base64.b64encode(data).decode("ascii")})
    if atts:
        msg["attachments"] = atts
    r = _call("email/send.json", {"message": msg})
    if r.get("status") != "success":
        if reserved:
            _release_account_slot()
        raise UnisenderSendError(r)
    emails = r.get("emails") or []
    mid = (emails[0].get("id") if emails and isinstance(emails[0], dict) else None) or r.get("job_id")
    log.info("Unisender отправлено → %s | %s | id=%s", to_addr, subject, mid)
    return f"<{mid}@unisender>" if mid else "<job@unisender>"


def check():
    """Диагностика: валиден ли ключ, подтверждён ли домен-отправитель. Ничего не шлёт."""
    key_ok = _call("template/list.json", {"limit": 1, "offset": 0}).get("status") == "success"
    dom = _call("domain/list.json", {"limit": 50, "offset": 0})
    domains = dom.get("domains", []) if dom.get("status") == "success" else []
    return {"key_ok": key_ok, "host": _HOST, "from_email": _FROM_EMAIL or "(не задан)",
            "sender_emails": sender_emails(), "domains": domains}


if __name__ == "__main__":
    import json
    print(json.dumps(check(), ensure_ascii=False, indent=2))
