"""Narrow Unisender GO transport adapter, disabled by default.

It deliberately has no campaign selection, recipient discovery, schedule or
retry loop.  A future worker may call it only after the Lead Factory Send Gate
has fenced one exact outbox command.  Timeouts are reported as ambiguous so
they cannot become blind retries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import html
import os
import re
from typing import Any, Callable, Mapping

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed


_CREDENTIAL_ENVIRONMENT_OPERATION = (
    "contact:unisender_go:credential_environment_read"
)
_SEND_OPERATION = "contact:unisender_go:transactional_email_send"


class UnisenderTransportError(RuntimeError):
    pass


class UnisenderTransportDisabled(UnisenderTransportError):
    pass


class UnisenderRejected(UnisenderTransportError):
    """Provider explicitly rejected the request before acceptance."""


class UnisenderAmbiguous(UnisenderTransportError):
    """Provider outcome cannot be proven; do not retry automatically."""


_EMAIL = re.compile(r"^[^\s@]{1,128}@[^\s@]{1,253}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_COMMAND_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


@dataclass(frozen=True, repr=False)
class UnisenderGoConfig:
    api_key: str = field(repr=False)
    from_email: str
    from_name: str
    reply_to: str
    host: str = "go2.unisender.ru"
    enabled: bool = False
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        key = str(self.api_key or "").strip()
        if len(key) < 12 or len(key) > 2048 or any(char in key for char in "\r\n\x00"):
            raise ValueError("Unisender key is invalid")
        if not _EMAIL.fullmatch(str(self.from_email or "").strip()):
            raise ValueError("Unisender sender email is invalid")
        if not _EMAIL.fullmatch(str(self.reply_to or "").strip()):
            raise ValueError("Unisender reply-to email is invalid")
        if not str(self.from_name or "").strip() or len(str(self.from_name)) > 200:
            raise ValueError("Unisender sender name is invalid")
        if not _HOST.fullmatch(str(self.host or "").strip()) or ".." in self.host:
            raise ValueError("Unisender host is invalid")
        if not isinstance(self.enabled, bool) or not isinstance(self.timeout_seconds, int) or not 1 <= self.timeout_seconds <= 120:
            raise ValueError("Unisender transport configuration is invalid")

    def __repr__(self) -> str:
        return "UnisenderGoConfig(<redacted>)"


def config_from_environ(environ: Mapping[str, str] | None = None) -> UnisenderGoConfig:
    """Bind credentials after authority, or from an explicit local mapping."""

    if environ is None:
        assert_external_allowed(_CREDENTIAL_ENVIRONMENT_OPERATION)
        values = os.environ
    else:
        # An injected mapping is local fixture/config data; no environment or
        # external credential source is touched by this branch.
        values = environ
    try:
        return UnisenderGoConfig(
            api_key=values.get("UNISENDER_GO_API_KEY", ""),
            from_email=values.get("CAMPAIGN_FROM_EMAIL", ""),
            from_name=values.get("CAMPAIGN_FROM_NAME", "АлюмКомплект"),
            reply_to=values.get("CAMPAIGN_REPLY_TO", values.get("MANAGER_IMAP_USER", "")),
            host=values.get("UNISENDER_GO_HOST", "go2.unisender.ru"),
            enabled=values.get("LEAD_FACTORY_UNISENDER_ENABLED", "0") == "1",
            timeout_seconds=int(values.get("LEAD_FACTORY_UNISENDER_TIMEOUT", "30")),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Unisender environment is invalid") from exc


@dataclass(frozen=True, repr=False)
class UnisenderMessage:
    command_id: str
    recipient: str
    subject: str
    text_body: str
    idempotency_key: str
    html_body: str = ""

    def __post_init__(self) -> None:
        if not _COMMAND_ID.fullmatch(str(self.command_id or "")):
            raise ValueError("Unisender command id is invalid")
        if not _EMAIL.fullmatch(str(self.recipient or "").strip()):
            raise ValueError("Unisender recipient is invalid")
        if not str(self.subject or "").strip() or len(str(self.subject)) > 500:
            raise ValueError("Unisender subject is invalid")
        if not str(self.text_body or "").strip() or len(str(self.text_body)) > 50_000:
            raise ValueError("Unisender text body is invalid")
        if not _COMMAND_ID.fullmatch(str(self.idempotency_key or "")):
            raise ValueError("Unisender idempotency key is invalid")
        if self.html_body and len(self.html_body) > 100_000:
            raise ValueError("Unisender HTML body is invalid")

    def __repr__(self) -> str:
        return "UnisenderMessage(<redacted>)"


@dataclass(frozen=True)
class UnisenderReceipt:
    provider_message_id: str


class UnisenderGoTransport:
    """One post-gate provider call; it does not schedule or retry messages."""

    def __init__(self, config: UnisenderGoConfig, *, post: Callable[..., Any]) -> None:
        if type(config) is not UnisenderGoConfig or not callable(post):
            raise TypeError("Unisender transport configuration is invalid")
        self.config = config
        self.post = post

    def send(self, message: UnisenderMessage) -> UnisenderReceipt:
        if not self.config.enabled:
            raise UnisenderTransportDisabled("Unisender transport is disabled")
        if type(message) is not UnisenderMessage:
            raise ValueError("Unisender message is invalid")
        body = {
            "api_key": self.config.api_key,
            "message": {
                "recipients": [{"email": message.recipient}],
                "subject": message.subject,
                "from_email": self.config.from_email,
                "from_name": self.config.from_name,
                "reply_to": self.config.reply_to,
                "body": {
                    "plaintext": message.text_body,
                    "html": message.html_body or "<html><body>" + html.escape(message.text_body).replace("\n", "<br>") + "</body></html>",
                },
                "track_read": 0,
                "track_links": 0,
                "skip_unsubscribe": 0,
                "global_language": "ru",
            },
        }
        try:
            assert_external_allowed(_SEND_OPERATION)
            response = self.post(
                f"https://{self.config.host}/ru/transactional/api/v1/email/send.json",
                json=body,
                timeout=self.config.timeout_seconds,
            )
            data = response.json() if hasattr(response, "json") else response
        except ExternalAuthorityError:
            raise
        except Exception:
            raise UnisenderAmbiguous("Unisender result is unknown") from None
        if not isinstance(data, dict) or data.get("status") != "success":
            raise UnisenderRejected("Unisender rejected the message")
        emails = data.get("emails") or []
        provider_id = ""
        if emails and isinstance(emails[0], dict):
            provider_id = str(emails[0].get("id") or "")
        provider_id = provider_id or str(data.get("job_id") or "")
        if not provider_id or len(provider_id) > 500:
            raise UnisenderAmbiguous("Unisender accepted status cannot be reconciled")
        return UnisenderReceipt(provider_message_id=provider_id)


__all__ = [
    "UnisenderAmbiguous", "UnisenderGoConfig", "UnisenderGoTransport",
    "UnisenderMessage", "UnisenderReceipt", "UnisenderRejected",
    "UnisenderTransportDisabled", "UnisenderTransportError", "config_from_environ",
]
