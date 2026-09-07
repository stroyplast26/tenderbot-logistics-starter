from __future__ import annotations

from typing import Any
from pathlib import Path

import requests

from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call


class TelegramError(RuntimeError):
    pass


class TelegramMethodRejected(TelegramError):
    """A raw Telegram method is absent from the exact reviewed inventory."""


_TELEGRAM_READ_METHODS = frozenset({"getFile", "getMe", "getUpdates"})
_TELEGRAM_CONTACT_METHODS = frozenset({
    "answerCallbackQuery",
    "editMessageText",
    "sendMessage",
})
_METHOD_REJECTED = "TASKBOT_TELEGRAM_METHOD_REJECTED"


def _classify_method(method: object) -> tuple[str, str]:
    canonical_method = str(method or "").strip()
    if canonical_method in _TELEGRAM_READ_METHODS:
        return canonical_method, "taskbot.telegram.read"
    if canonical_method in _TELEGRAM_CONTACT_METHODS:
        return canonical_method, "taskbot.telegram.contact"
    raise TelegramMethodRejected(_METHOD_REJECTED)


class Telegram:
    def __init__(self, token: str) -> None:
        self._api = f"https://api.telegram.org/bot{token}"
        self._http = requests.Session()

    def _call(self, method: str, payload: dict[str, Any] | None = None) -> Any:
        canonical_method, operation = _classify_method(method)
        try:
            response = guarded_manual_http_call(
                operation,
                f"POST /bot{{token}}/{canonical_method}",
                "host:api.telegram.org",
                f"{self._api}/{canonical_method}",
                self._http.post,
                json=payload or {},
                timeout=40,
                allow_redirects=False,
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            # Некоторые сетевые исключения включают полный URL с токеном бота.
            raise TelegramError(f"Telegram temporarily unavailable ({type(exc).__name__})") from exc
        if not body.get("ok"):
            raise TelegramError(body.get("description", "Telegram API error"))
        return body["result"]

    def get_me(self) -> dict[str, Any]:
        return self._call("getMe")

    def get_updates(self, offset: int | None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": 25, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            payload["offset"] = offset
        return self._call("getUpdates", payload)

    def send(
        self,
        chat_id: int,
        text: str,
        keyboard: list[list[dict[str, str]]] | None = None,
        reply_keyboard: list[list[str]] | None = None,
        *,
        force_reply: bool = False,
        input_placeholder: str | None = None,
        reply_to_message_id: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if reply_to_message_id is not None:
            payload["reply_parameters"] = {"message_id": reply_to_message_id}
        if force_reply:
            payload["reply_markup"] = {"force_reply": True, "input_field_placeholder": (input_placeholder or "Напишите ответ")[:64]}
        elif keyboard:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        elif reply_keyboard:
            payload["reply_markup"] = {
                "keyboard": [[{"text": button} for button in row] for row in reply_keyboard],
                "resize_keyboard": True,
                "is_persistent": True,
            }
        result = self._call("sendMessage", payload)
        return result if isinstance(result, dict) else {}

    def edit_message(self, chat_id: int, message_id: int, text: str, keyboard: list[list[dict[str, str]]] | None = None) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        self._call("editMessageText", payload)

    def answer_callback(self, callback_id: str, text: str = "") -> None:
        self._call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})

    def get_file_path(self, file_id: str) -> str:
        return str(self._call("getFile", {"file_id": file_id})["file_path"])

    def download_file(self, file_path: str, destination: Path) -> None:
        try:
            response = guarded_manual_http_call(
                "taskbot.telegram.read",
                "GET /file/bot{token}/{path...}",
                "host:api.telegram.org",
                f"{self._api.replace('/bot', '/file/bot')}/{file_path}",
                self._http.get,
                timeout=40,
                allow_redirects=False,
            )
            response.raise_for_status()
            destination.write_bytes(response.content)
        except requests.RequestException as exc:
            raise TelegramError(f"Telegram file download failed ({type(exc).__name__})") from exc
