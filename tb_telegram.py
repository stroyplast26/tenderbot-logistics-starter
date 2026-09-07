# -*- coding: utf-8 -*-
"""Telegram-бот контроля кампании: отправка сообщений и документов владельцу.
Токен/чат — из .env (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)."""
import os
import time
import logging
import requests

log = logging.getLogger("tenderbot.tg")
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

# Safe import-time compatibility values.  RC1 must not inspect the Telegram
# token or recipient identifiers merely because another legacy module imports
# this helper.
_TOKEN = ""
_CHAT_RAW = ""
_CHATS = []
_CHAT = _CHATS[0] if _CHATS else ""     # дефолтный (первый) — обратная совместимость
_API = f"https://api.telegram.org/bot{_TOKEN}"


def _load_runtime_config(operation):
    """Load token/recipients only after the immutable RC1 authority gate."""
    from lead_factory.mdos_v7.authority import assert_external_allowed

    assert_external_allowed(operation)
    from dotenv import load_dotenv

    load_dotenv(_ENV_PATH)
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_raw = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    chat_ids = [value.strip() for value in chat_raw.split(",") if value.strip()]
    return {
        "token": token,
        "chats": chat_ids,
        "api": f"https://api.telegram.org/bot{token}",
    }


def _safe_log_value(value, token=""):
    text = str(value)
    effective_token = token or _TOKEN
    return text.replace(effective_token, "<token>") if effective_token else text


def chats():
    """Список авторизованных chat_id (белый список)."""
    return list(_CHATS)


def is_authorized(chat_id):
    """Только эти чаты получают рассылку и могут управлять ботом."""
    return str(chat_id) in _CHATS


def _send_one(text, chat_id, reply_markup=None):
    from lead_factory.mdos_v7.authority import external_block_reason
    log.warning(external_block_reason("telegram:send_message"))
    return None

    # Unreachable until a future ratified adapter release binds an exact
    # PermitDecision at this boundary.
    config = _load_runtime_config("telegram:send_message")
    token = config["token"]
    if not token:
        log.warning("TELEGRAM_BOT_TOKEN не задан")
        return None
    data = {"chat_id": chat_id, "text": text[:4096], "disable_web_page_preview": True}
    if reply_markup:
        import json
        data["reply_markup"] = json.dumps(reply_markup)
    last = None
    for attempt in range(3):
        try:
            from lead_factory.mdos_v7.authority import assert_external_allowed

            assert_external_allowed("telegram:send_message")
            r = requests.post(
                f"{config['api']}/sendMessage",
                data=data,
                timeout=30,
                allow_redirects=False,
            ).json()
            if r.get("ok"):
                return r
            last = r
        except Exception as e:
            last = e
        time.sleep(1.5 * (attempt + 1))
    log.warning(
        "TG send_message не доставлено (%s): %s",
        chat_id,
        _safe_log_value(last, token),
    )
    return None


def send_message(text, chat_id=None, reply_markup=None):
    """chat_id задан → одному чату (возвращает dict-результат).
    chat_id None → РАССЫЛКА всем из белого списка (возвращает список результатов — по одному на чат)."""
    if chat_id is not None:
        return _send_one(text, chat_id, reply_markup)
    return [_send_one(text, c, reply_markup) for c in _CHATS]


def get_updates(offset=None, timeout=25):
    from lead_factory.mdos_v7.authority import external_block_reason
    log.warning(external_block_reason("telegram:get_updates"))
    return {"ok": False, "result": []}

    config = _load_runtime_config("telegram:get_updates")
    if not config["token"]:
        return {"ok": False, "result": []}
    params = {"timeout": timeout}
    if offset is not None:
        params["offset"] = offset
    try:
        from lead_factory.mdos_v7.authority import assert_external_allowed

        assert_external_allowed("telegram:get_updates")
        return requests.get(
            f"{config['api']}/getUpdates",
            params=params,
            timeout=timeout + 10,
            allow_redirects=False,
        ).json()
    except Exception as e:
        log.warning("TG get_updates: %s", _safe_log_value(e, config["token"]))
        return {"ok": False, "result": []}


def answer_callback(cb_id, text=""):
    from lead_factory.mdos_v7.authority import external_block_reason
    log.warning(external_block_reason("telegram:answer_callback"))
    return None

    config = _load_runtime_config("telegram:answer_callback")
    try:
        from lead_factory.mdos_v7.authority import assert_external_allowed

        assert_external_allowed("telegram:answer_callback")
        requests.post(
            f"{config['api']}/answerCallbackQuery",
            data={"callback_query_id": cb_id, "text": text[:200]},
            timeout=20,
            allow_redirects=False,
        )
    except Exception as e:
        log.warning("TG answer_callback: %s", _safe_log_value(e, config["token"]))


def edit_reply_markup(chat_id, message_id, reply_markup):
    from lead_factory.mdos_v7.authority import external_block_reason
    log.warning(external_block_reason("telegram:edit_reply_markup"))
    return None

    config = _load_runtime_config("telegram:edit_reply_markup")
    import json
    try:
        from lead_factory.mdos_v7.authority import assert_external_allowed

        assert_external_allowed("telegram:edit_reply_markup")
        requests.post(
            f"{config['api']}/editMessageReplyMarkup",
            data={"chat_id": chat_id, "message_id": message_id,
                  "reply_markup": json.dumps(reply_markup)},
            timeout=20,
            allow_redirects=False,
        )
    except Exception as e:
        log.warning("TG edit_reply_markup: %s", _safe_log_value(e, config["token"]))


def send_document(path, caption="", chat_id=None):
    from lead_factory.mdos_v7.authority import external_block_reason
    log.warning(external_block_reason("telegram:send_document"))
    return None

    config = _load_runtime_config("telegram:send_document")
    if not config["token"] or not os.path.exists(path):
        return None
    targets = [chat_id] if chat_id is not None else config["chats"]
    res = None
    for c in targets:
        try:
            from lead_factory.mdos_v7.authority import assert_external_allowed

            assert_external_allowed("telegram:send_document")
            with open(path, "rb") as f:
                res = requests.post(
                    f"{config['api']}/sendDocument",
                    data={"chat_id": c, "caption": caption[:1024]},
                    files={"document": f},
                    timeout=60,
                    allow_redirects=False,
                ).json()
        except Exception as e:
            log.warning(
                "TG send_document (%s): %s",
                c,
                _safe_log_value(e, config["token"]),
            )
    return res
