# -*- coding: utf-8 -*-
"""Bitrix24 — создание ЛИДА при заинтересованном ответе победителя. Вебхук из .env."""
import os
import time
import logging
import json
import hashlib
from datetime import datetime
import requests

log = logging.getLogger("tenderbot.bitrix")
BASE = os.path.dirname(os.path.abspath(__file__))
_ENV_PATH = os.path.join(BASE, ".env")
PENDING_LEADS = os.path.join(BASE, "pool", "bitrix_pending_leads.json")
# Importing this frozen legacy module must not inspect credentials.  The empty
# value is also retained for callers/tests which historically patched ``_WH``.
_WH = ""
_LAST_ERROR = None

# Only inventoried read-only calls may use this legacy raw helper while the
# Factory canary owns the Bitrix lane.  Everything else (including ``batch``
# and future/unknown methods) fails closed before HTTP.
_LEGACY_READ_ONLY_BITRIX_METHODS = frozenset({
    "crm.company.list",
    "crm.contact.list",
    "crm.lead.list",
})


def _load_runtime_config(operation="bitrix24:credential.read"):
    """Load the legacy webhook only after the immutable RC1 authority gate."""
    from lead_factory.mdos_v7.authority import assert_external_allowed

    assert_external_allowed(operation)
    from dotenv import load_dotenv

    load_dotenv(_ENV_PATH)
    # Для задач и CRM используем новый вебхук с нужными правами. Старый
    # CRM-вебхук остаётся запасным для a future separately ratified release.
    return (
        os.getenv("BITRIX_TASKS_WEBHOOK")
        or os.getenv("BITRIX_WEBHOOK", "")
    ).rstrip("/")


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _load_pending():
    try:
        with open(PENDING_LEADS, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {"leads": {}}
    except FileNotFoundError:
        return {"leads": {}}
    except Exception as e:
        log.warning("Bitrix pending load: %s", e)
        return {"leads": {}}


def _save_pending(data):
    os.makedirs(os.path.dirname(PENDING_LEADS), exist_ok=True)
    tmp = PENDING_LEADS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, PENDING_LEADS)


def _lead_key(fields):
    raw = "|".join([
        fields.get("SOURCE_ID", ""),
        fields.get("TITLE", ""),
        fields.get("COMPANY_TITLE", ""),
        (fields.get("EMAIL") or [{}])[0].get("VALUE", "") if isinstance(fields.get("EMAIL"), list) else "",
        (fields.get("PHONE") or [{}])[0].get("VALUE", "") if isinstance(fields.get("PHONE"), list) else "",
    ]).lower()
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def _error_text(resp):
    if not resp:
        return ""
    err = str(resp.get("error") or "").strip()
    desc = str(resp.get("error_description") or "").strip()
    return (err + (f": {desc}" if desc else "")).strip()


def last_error():
    return _LAST_ERROR


def queue_pending_lead(fields, error="", context=None):
    """Сохраняет лид локально, если Bitrix REST временно недоступен."""
    key = _lead_key(fields)
    data = _load_pending()
    leads = data.setdefault("leads", {})
    rec = leads.get(key) or {
        "first_seen": _now(),
        "attempts": 0,
        "fields": fields,
        "context": context or {},
    }
    rec["last_seen"] = _now()
    rec["attempts"] = int(rec.get("attempts") or 0) + 1
    rec["last_error"] = error or "unknown"
    rec["fields"] = fields
    if context:
        rec["context"] = context
    leads[key] = rec
    _save_pending(data)
    return key


def pending_count():
    return len((_load_pending().get("leads") or {}))


def _call(method, payload):
    global _LAST_ERROR
    canonical_method = str(method or "").strip().casefold()
    from lead_factory.mdos_v7.authority import external_block_reason
    _LAST_ERROR = external_block_reason(f"bitrix24:{canonical_method or 'unknown'}")
    return {"error": "MDOS_V7_DEFAULT_DENY", "error_description": _LAST_ERROR}

    # Retained below for a future, separately ratified adapter release.  It is
    # unreachable under the immutable 7.1.0-rc.1 authority package.
    webhook = _load_runtime_config(f"bitrix24:{canonical_method or 'unknown'}")
    if not webhook:
        _LAST_ERROR = "BITRIX_TASKS_WEBHOOK / BITRIX_WEBHOOK не задан"
        return {"error": "BITRIX_TASKS_WEBHOOK / BITRIX_WEBHOOK не задан"}
    last = None
    for attempt in range(3):
        # Re-check at the last local point before *every* HTTP attempt.  A
        # request which failed before canary activation must not retry after
        # the durable HOLD has become active.
        if canonical_method not in _LEGACY_READ_ONLY_BITRIX_METHODS:
            from lead_factory.legacy_canary_guard import legacy_canary_holds_legacy_outboxes
            if legacy_canary_holds_legacy_outboxes():
                _LAST_ERROR = "factory_canary_hold"
                return {"error": "factory_canary_hold"}
        try:
            from lead_factory.mdos_v7.authority import assert_external_allowed

            assert_external_allowed(f"bitrix24:{canonical_method or 'unknown'}")
            r = requests.post(
                f"{webhook}/{method}.json",
                json=payload,
                timeout=30,
                allow_redirects=False,
            ).json()
            if "result" in r:
                _LAST_ERROR = None
                return r
            # логическая ошибка Bitrix (напр. insufficient_scope) — не ретраить
            if r.get("error"):
                _LAST_ERROR = _error_text(r)
                log.warning("Bitrix %s error: %s", method, _LAST_ERROR)
                return r
            return r
        except Exception as e:
            last = e
            log.warning("Bitrix %s попытка %d: %s", method, attempt + 1, e)
            time.sleep(2 * (attempt + 1))
    _LAST_ERROR = f"network: {last}"
    return {"error": _LAST_ERROR}


def create_lead(title, company="", name="", phone="", email="", comments="", source_id="WEB", queue_on_fail=True,
                context=None):
    """Создаёт лид. Возвращает id лида или None."""
    fields = {"TITLE": title, "OPENED": "Y", "SOURCE_ID": source_id}
    if company:
        fields["COMPANY_TITLE"] = company
    if name:
        fields["NAME"] = name
    if comments:
        fields["COMMENTS"] = comments
    if phone:
        fields["PHONE"] = [{"VALUE": phone, "VALUE_TYPE": "WORK"}]
    if email:
        fields["EMAIL"] = [{"VALUE": email, "VALUE_TYPE": "WORK"}]
    # Any old direct Bitrix create is outside the exact factory permit during
    # a live (or durably uncertain) canary.  Preserve the record locally but
    # never reach the REST boundary from this legacy path.
    from lead_factory.legacy_canary_guard import legacy_canary_holds_legacy_outboxes
    if legacy_canary_holds_legacy_outboxes():
        if queue_on_fail:
            queue_pending_lead(fields, "factory_canary_hold", context=context)
        return None
    r = _call("crm.lead.add", {"fields": fields, "params": {"REGISTER_SONET_EVENT": "Y"}})
    lid = r.get("result")
    if lid:
        return lid
    if queue_on_fail:
        queue_pending_lead(fields, _error_text(r) or last_error(), context=context)
    return None


def retry_pending(limit=50):
    """Пробует завести накопленные локально лиды. Возвращает краткую сводку."""
    data = _load_pending()
    leads = data.get("leads") or {}
    # Legacy records lack a factory canary binding.  Do not let this direct
    # writer compete with an approved scoped factory canary.
    from lead_factory.legacy_canary_guard import legacy_canary_holds_legacy_outboxes
    if legacy_canary_holds_legacy_outboxes():
        return {"created": [], "failed": [], "blocked": True, "remaining": len(leads)}
    done, failed = [], []
    for key, rec in list(leads.items())[:limit]:
        fields = rec.get("fields") or {}
        r = _call("crm.lead.add", {"fields": fields, "params": {"REGISTER_SONET_EVENT": "Y"}})
        lid = r.get("result")
        if lid:
            done.append({"key": key, "lead_id": lid, "title": fields.get("TITLE", "")})
            leads.pop(key, None)
        else:
            rec["last_retry"] = _now()
            rec["last_error"] = _error_text(r) or last_error()
            failed.append({"key": key, "error": rec["last_error"], "title": fields.get("TITLE", "")})
    _save_pending(data)
    return {"created": done, "failed": failed, "remaining": len(leads)}


def lead_url(lead_id):
    base = _WH.split("/rest/")[0] if "/rest/" in _WH else ""
    return f"{base}/crm/lead/details/{lead_id}/" if base and lead_id else ""


def lead_from_outreach(lead):
    """Собирает лид Bitrix из структуры лида лейны-1 (summary/winner/ai)."""
    import tb_outreach
    s = lead.get("summary", {}) or {}
    w = lead.get("winner", {}) or {}
    ai = lead.get("ai", {}) or {}
    obj = tb_outreach.short_object(s.get("product_name", ""))
    comments = (
        f"Объект: {s.get('product_name','')}\n"
        f"Заказчик: {s.get('customer','')}\n"
        f"Цена контракта: {s.get('start_price','—')}\n"
        f"Объём остекления (смета): {ai.get('ocenka_obema','—')}\n"
        f"Профиль: {ai.get('nash_profil','—')}\n"
        f"Балл ИИ: {ai.get('ball','—')}\n"
        f"Реестр ЕИС: {lead.get('regn','')}\n"
        f"Ссылка: {lead.get('link','')}\n"
        f"Источник: TenderBot (победитель тендера ответил «актуально»)."
    )
    lid = create_lead(title=f"Остекление: {obj}", company=w.get("name", ""),
                      phone=w.get("phone", ""), email=w.get("email", ""), comments=comments)
    return lid


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Bitrix24 helper")
    p.add_argument("--pending", action="store_true", help="показать число лидов в локальной очереди")
    p.add_argument("--retry-pending", action="store_true", help="попробовать догрузить очередь лидов в Bitrix")
    p.add_argument("--test-create", action="store_true", help="создать тестовый лид для ручной проверки")
    args = p.parse_args()

    if args.retry_pending:
        print(json.dumps(retry_pending(), ensure_ascii=False, indent=2))
    elif args.test_create:
        lid = create_lead(
            title="ТЕСТ TenderBot — можно удалить",
            company='ООО «Тестовый Подрядчик»',
            phone="+7 900 000-00-00", email="test@example.com",
            comments="Проверка интеграции TenderBot → Bitrix24. Этот лид можно удалить.",
            queue_on_fail=False)
        print("lead id:", lid, "| url:", lead_url(lid), "| error:", last_error())
    else:
        print("pending leads:", pending_count())
