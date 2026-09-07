"""Explicit TLS IMAP client factory for an owner-approved read-only canary.

This module deliberately has no CLI, scheduler, ``.env`` loading, mailbox
registry mutation, or worker construction.  Possessing a configuration object
does not open a connection; only invoking the factory can contact IMAP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import imaplib
import os
import re
import ssl
from typing import Callable, Mapping

from .imap_readonly_boundary import ImapClient
from .mdos_v7.authority import ExternalAuthorityError
from .mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_egress_attempt,
)


class ImapCanaryConfigurationError(ValueError):
    """Canary configuration is absent or unsafe to use."""


class ImapCanaryConnectionError(RuntimeError):
    """A canary connection could not be established; no detail is exposed."""


_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


def _single_line(value: object, *, label: str, secret: bool = False) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 1024 or any(char in result for char in "\r\n\x00"):
        raise ImapCanaryConfigurationError(f"{label} is invalid")
    if not secret and any(char.isspace() for char in result):
        raise ImapCanaryConfigurationError(f"{label} is invalid")
    return result


@dataclass(frozen=True, repr=False)
class ImapCanaryConfig:
    """Credential material injected by the launcher, never persisted here."""

    host: str
    username: str
    password: str = field(repr=False)
    port: int = 993
    timeout_seconds: int = 25

    def __post_init__(self) -> None:
        host = _single_line(self.host, label="IMAP host").lower()
        if not _HOST.fullmatch(host) or ".." in host:
            raise ImapCanaryConfigurationError("IMAP host is invalid")
        _single_line(self.username, label="IMAP username")
        _single_line(self.password, label="IMAP password", secret=True)
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ImapCanaryConfigurationError("IMAP port is invalid")
        if not isinstance(self.timeout_seconds, int) or not 1 <= self.timeout_seconds <= 30:
            raise ImapCanaryConfigurationError("IMAP timeout is invalid")
        object.__setattr__(self, "host", host)

    def __repr__(self) -> str:
        return (
            "ImapCanaryConfig(host=<redacted>, username=<redacted>, "
            "password=<redacted>, port=<redacted>, timeout_seconds=<redacted>)"
        )


def config_from_environ(environ: Mapping[str, str] | None = None) -> ImapCanaryConfig:
    """Read only dedicated canary variables; legacy mailbox variables are ignored."""

    if environ is None:
        assert_manual_egress_allowed(
            "lead_factory.imap.canary",
            method="credential.read",
            source="imap:canary_mailbox",
        )
    values = os.environ if environ is None else environ
    try:
        return ImapCanaryConfig(
            host=values.get("LEAD_FACTORY_IMAP_CANARY_HOST", ""),
            username=values.get("LEAD_FACTORY_IMAP_CANARY_USER", ""),
            password=values.get("LEAD_FACTORY_IMAP_CANARY_PASSWORD", ""),
            port=int(values.get("LEAD_FACTORY_IMAP_CANARY_PORT", "993")),
            timeout_seconds=int(values.get("LEAD_FACTORY_IMAP_CANARY_TIMEOUT", "25")),
        )
    except (TypeError, ValueError) as exc:
        raise ImapCanaryConfigurationError("IMAP canary environment is invalid") from exc


ImapSslConstructor = Callable[..., ImapClient]


class ImapSslClientFactory:
    """Creates one authenticated TLS IMAP client only when explicitly called."""

    def __init__(
        self,
        config: ImapCanaryConfig,
        *,
        constructor: ImapSslConstructor = imaplib.IMAP4_SSL,
    ):
        if type(config) is not ImapCanaryConfig or not callable(constructor):
            raise ValueError("IMAP canary factory configuration is invalid")
        self._config = config
        self._constructor = constructor

    def __repr__(self) -> str:
        return "ImapSslClientFactory(<redacted>)"

    def __call__(self) -> ImapClient:
        client = None
        try:
            client = guarded_manual_egress_attempt(
                "lead_factory.imap.canary",
                "connect",
                "imap:canary_mailbox",
                self._constructor,
                self._config.host,
                self._config.port,
                ssl_context=ssl.create_default_context(),
                timeout=self._config.timeout_seconds,
            )
            status, _ = guarded_manual_egress_attempt(
                "lead_factory.imap.canary",
                "login",
                "imap:canary_mailbox",
                client.login,
                self._config.username,
                self._config.password,
            )
            if str(status or "").upper() != "OK":
                raise ImapCanaryConnectionError("IMAP authentication failed")
            return client
        except ImapCanaryConnectionError:
            raise
        except ExternalAuthorityError:
            raise
        except Exception as exc:
            raise ImapCanaryConnectionError("IMAP connection failed") from exc
        finally:
            # The successful client belongs to the read boundary, which will
            # close it after its bounded batch.  Failed connections do not
            # leave a logged-in session behind.
            if client is not None:
                try:
                    if getattr(client, "state", "AUTH") != "AUTH":
                        guarded_manual_egress_attempt(
                            "lead_factory.imap.canary",
                            "logout",
                            "imap:canary_mailbox",
                            client.logout,
                        )
                except Exception:
                    pass


__all__ = [
    "ImapCanaryConfig",
    "ImapCanaryConfigurationError",
    "ImapCanaryConnectionError",
    "ImapSslClientFactory",
    "config_from_environ",
]
