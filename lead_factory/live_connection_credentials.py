"""Windows Credential Manager storage for the live connection bundle.

The whole IMAP, SMTP, Bitrix and UniSender configuration is validated and
stored as one canonical UTF-8 JSON credential.  Production callers cannot
select a credential target: both import and runtime loading are permanently
bound to :data:`LIVE_CONNECTION_CREDENTIAL_TARGET`.

This module does not contact any provider and never falls back to process
environment variables.  The one-time importer is the only path that reads an
``.env`` file; runtime workers use :func:`load_live_connection_credentials`.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
from hashlib import sha256
import hmac
from io import StringIO
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Final, Mapping
from unicodedata import category
from urllib.parse import urlsplit

LIVE_CONNECTION_CREDENTIAL_TARGET: Final = "TenderBot/LeadFactory/LiveConnections/v1"
LIVE_CONNECTION_CREDENTIAL_VERSION: Final = "lead-factory-live-connections-v1"
LIVE_CONNECTION_BITRIX_SOURCE_NAME: Final = "BITRIX_GRAPH_CANARY_WEBHOOK"

_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168
_MAX_CREDENTIAL_BLOB_BYTES = 2_560
_MAX_ENV_FILE_BYTES = 64 * 1_024
_TARGET_SHA256 = sha256(LIVE_CONNECTION_CREDENTIAL_TARGET.encode("utf-8", "strict")).hexdigest()
_EMAIL = re.compile(r"^[^\s@]{1,128}@[^\s@]{1,253}$", re.ASCII)
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAILRU_IMAP_HOST = "imap.mail.ru"
_MAILRU_SMTP_HOST = "smtp.mail.ru"
_ALLOWED_UNISENDER_HOSTS = frozenset({"go1.unisender.ru", "go2.unisender.ru"})
_EXPECTED_PAYLOAD_KEYS = frozenset(
    {
        "version",
        "imap_host",
        "imap_port",
        "imap_user",
        "imap_password",
        "smtp_host",
        "smtp_port",
        "smtp_user",
        "smtp_password",
        "smtp_from",
        "bitrix_webhook",
        "unisender_host",
        "unisender_api_key",
        "unisender_from",
        "unisender_name",
        "unisender_reply_to",
    }
)


class LiveConnectionCredentialError(RuntimeError):
    """A deliberately sanitized credential failure."""

    code = "live_connection_credential_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


class LiveConnectionCredentialPlatformError(LiveConnectionCredentialError):
    code = "windows_credential_manager_unavailable"


class LiveConnectionCredentialSourceError(LiveConnectionCredentialError):
    code = "live_connection_env_invalid"


class LiveConnectionCredentialValidationError(LiveConnectionCredentialError):
    code = "live_connection_bundle_invalid"


class LiveConnectionCredentialNotFound(LiveConnectionCredentialError):
    code = "live_connection_credential_not_found"


class LiveConnectionCredentialReadError(LiveConnectionCredentialError):
    code = "live_connection_credential_read_failed"


class LiveConnectionCredentialWriteError(LiveConnectionCredentialError):
    code = "live_connection_credential_write_failed"


class LiveConnectionCredentialVerificationError(LiveConnectionCredentialError):
    code = "live_connection_credential_verification_failed"


@dataclass(frozen=True, slots=True)
class LiveConnectionCredentialBundle:
    """Validated live configuration; sensitive and identifying fields are hidden."""

    imap_host: str
    imap_port: int
    imap_user: str = field(repr=False)
    imap_password: str = field(repr=False)
    smtp_host: str
    smtp_port: int
    smtp_user: str = field(repr=False)
    smtp_password: str = field(repr=False)
    smtp_from: str = field(repr=False)
    bitrix_webhook: str = field(repr=False)
    unisender_host: str
    unisender_api_key: str = field(repr=False)
    unisender_from: str = field(repr=False)
    unisender_name: str = field(repr=False)
    unisender_reply_to: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_host(self.imap_host)
        if self.imap_host.casefold() != _MAILRU_IMAP_HOST:
            raise LiveConnectionCredentialValidationError
        _validate_port(self.imap_port, allowed=frozenset({993}))
        _validate_email(self.imap_user)
        _validate_secret(self.imap_password, maximum=1_024)
        _validate_host(self.smtp_host)
        if self.smtp_host.casefold() != _MAILRU_SMTP_HOST:
            raise LiveConnectionCredentialValidationError
        # The live runtime deliberately uses implicit TLS (SMTP_SSL).  Port
        # 587 would require a separately reviewed STARTTLS state machine, so
        # accepting it here would create a false-ready configuration.
        _validate_port(self.smtp_port, allowed=frozenset({465}))
        _validate_email(self.smtp_user)
        _validate_secret(self.smtp_password, maximum=1_024)
        _validate_email(self.smtp_from)
        _validate_bitrix_webhook(self.bitrix_webhook)
        _validate_host(self.unisender_host)
        if self.unisender_host not in _ALLOWED_UNISENDER_HOSTS:
            raise LiveConnectionCredentialValidationError
        _validate_secret(self.unisender_api_key, minimum=12, maximum=2_048)
        _validate_email(self.unisender_from)
        _validate_text(self.unisender_name, minimum=1, maximum=200, trimmed=True)
        _validate_email(self.unisender_reply_to)


@dataclass(frozen=True, slots=True)
class LiveConnectionCredentialReceipt:
    """Sanitized import/validation result containing no connection values."""

    target_sha256: str
    bundle_sha256: str
    source_binding_sha256: str
    bitrix_source_name: str
    credential_blob_bytes: int
    stored: bool
    replaced_existing: bool
    readback_verified: bool

    def __post_init__(self) -> None:
        for value in (
            self.target_sha256,
            self.bundle_sha256,
            self.source_binding_sha256,
        ):
            if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise LiveConnectionCredentialValidationError
        if self.bitrix_source_name != LIVE_CONNECTION_BITRIX_SOURCE_NAME:
            raise LiveConnectionCredentialValidationError
        if (
            type(self.credential_blob_bytes) is not int
            or not 1 <= self.credential_blob_bytes <= _MAX_CREDENTIAL_BLOB_BYTES
            or type(self.stored) is not bool
            or type(self.replaced_existing) is not bool
            or type(self.readback_verified) is not bool
        ):
            raise LiveConnectionCredentialValidationError


class _CredentialW(ctypes.Structure):
    pass


_CredentialW._fields_ = (  # type: ignore[attr-defined]
    ("Flags", wintypes.DWORD),
    ("Type", wintypes.DWORD),
    ("TargetName", wintypes.LPWSTR),
    ("Comment", wintypes.LPWSTR),
    ("LastWritten", wintypes.FILETIME),
    ("CredentialBlobSize", wintypes.DWORD),
    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
    ("Persist", wintypes.DWORD),
    ("AttributeCount", wintypes.DWORD),
    ("Attributes", wintypes.LPVOID),
    ("TargetAlias", wintypes.LPWSTR),
    ("UserName", wintypes.LPWSTR),
)


def _has_control(value: str) -> bool:
    return any(category(character).startswith("C") for character in value)


def _validate_text(
    value: object,
    *,
    minimum: int,
    maximum: int,
    trimmed: bool = False,
) -> str:
    if (
        type(value) is not str
        or not minimum <= len(value) <= maximum
        or _has_control(value)
        or (trimmed and value != value.strip())
    ):
        raise LiveConnectionCredentialValidationError
    return value


def _validate_secret(value: object, *, minimum: int = 1, maximum: int) -> str:
    return _validate_text(value, minimum=minimum, maximum=maximum)


def _validate_port(value: object, *, allowed: frozenset[int]) -> int:
    if type(value) is not int or value not in allowed:
        raise LiveConnectionCredentialValidationError
    return value


def _validate_host(value: object) -> str:
    host = _validate_text(value, minimum=1, maximum=253, trimmed=True)
    if any(character.isspace() for character in host) or host.endswith("."):
        raise LiveConnectionCredentialValidationError
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
            raise LiveConnectionCredentialValidationError from None
    return host


def _validate_email(value: object) -> str:
    email = _validate_text(value, minimum=3, maximum=320, trimmed=True)
    if _EMAIL.fullmatch(email) is None:
        raise LiveConnectionCredentialValidationError
    local, host = email.rsplit("@", 1)
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise LiveConnectionCredentialValidationError
    _validate_host(host)
    return email


def _validate_bitrix_webhook(value: object) -> str:
    webhook = _validate_text(value, minimum=20, maximum=2_048, trimmed=True)
    try:
        parsed = urlsplit(webhook)
        port = parsed.port
    except ValueError:
        raise LiveConnectionCredentialValidationError from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/rest/")
    ):
        raise LiveConnectionCredentialValidationError
    hostname = _validate_host(parsed.hostname).lower()
    # This credential is an isolated Bitrix24 Cloud webhook.  Keep the
    # destination pinned to that provider boundary so a modified dotenv file
    # cannot turn the live worker into an arbitrary HTTPS/loopback client.
    if hostname == "bitrix24.ru" or not hostname.endswith(".bitrix24.ru"):
        raise LiveConnectionCredentialValidationError
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) != 3 or path_parts[0] != "rest":
        raise LiveConnectionCredentialValidationError
    for part in path_parts[1:]:
        _validate_text(part, minimum=1, maximum=256)
        if any(character.isspace() for character in part):
            raise LiveConnectionCredentialValidationError
    return webhook


def _bundle_payload(bundle: LiveConnectionCredentialBundle) -> dict[str, object]:
    if type(bundle) is not LiveConnectionCredentialBundle:
        raise LiveConnectionCredentialValidationError
    return {
        "version": LIVE_CONNECTION_CREDENTIAL_VERSION,
        "imap_host": bundle.imap_host,
        "imap_port": bundle.imap_port,
        "imap_user": bundle.imap_user,
        "imap_password": bundle.imap_password,
        "smtp_host": bundle.smtp_host,
        "smtp_port": bundle.smtp_port,
        "smtp_user": bundle.smtp_user,
        "smtp_password": bundle.smtp_password,
        "smtp_from": bundle.smtp_from,
        "bitrix_webhook": bundle.bitrix_webhook,
        "unisender_host": bundle.unisender_host,
        "unisender_api_key": bundle.unisender_api_key,
        "unisender_from": bundle.unisender_from,
        "unisender_name": bundle.unisender_name,
        "unisender_reply_to": bundle.unisender_reply_to,
    }


def _encode_bundle(bundle: LiveConnectionCredentialBundle) -> bytes:
    try:
        blob = json.dumps(
            _bundle_payload(bundle),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, UnicodeError, ValueError):
        raise LiveConnectionCredentialValidationError from None
    if not blob or len(blob) > _MAX_CREDENTIAL_BLOB_BYTES:
        raise LiveConnectionCredentialValidationError
    return blob


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise LiveConnectionCredentialValidationError
        result[key] = value
    return result


def _decode_bundle(blob: bytes) -> LiveConnectionCredentialBundle:
    if type(blob) is not bytes or not blob or len(blob) > _MAX_CREDENTIAL_BLOB_BYTES:
        raise LiveConnectionCredentialValidationError
    try:
        payload = json.loads(
            blob.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                LiveConnectionCredentialValidationError()
            ),
        )
    except LiveConnectionCredentialError:
        raise
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        raise LiveConnectionCredentialValidationError from None
    if (
        type(payload) is not dict
        or frozenset(payload) != _EXPECTED_PAYLOAD_KEYS
        or payload.get("version") != LIVE_CONNECTION_CREDENTIAL_VERSION
    ):
        raise LiveConnectionCredentialValidationError
    try:
        bundle = LiveConnectionCredentialBundle(
            imap_host=payload["imap_host"],
            imap_port=payload["imap_port"],
            imap_user=payload["imap_user"],
            imap_password=payload["imap_password"],
            smtp_host=payload["smtp_host"],
            smtp_port=payload["smtp_port"],
            smtp_user=payload["smtp_user"],
            smtp_password=payload["smtp_password"],
            smtp_from=payload["smtp_from"],
            bitrix_webhook=payload["bitrix_webhook"],
            unisender_host=payload["unisender_host"],
            unisender_api_key=payload["unisender_api_key"],
            unisender_from=payload["unisender_from"],
            unisender_name=payload["unisender_name"],
            unisender_reply_to=payload["unisender_reply_to"],
        )
    except (KeyError, TypeError):
        raise LiveConnectionCredentialValidationError from None
    if not hmac.compare_digest(_encode_bundle(bundle), blob):
        raise LiveConnectionCredentialValidationError
    return bundle


def _required_env(values: Mapping[str, str | None], name: str) -> str:
    value = values.get(name)
    if type(value) is not str or not value:
        raise LiveConnectionCredentialSourceError
    return value


def _port_from_env(
    values: Mapping[str, str | None],
    name: str,
    *,
    default: int | None = None,
) -> int:
    value = values.get(name)
    if value in {None, ""} and default is not None:
        return default
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise LiveConnectionCredentialSourceError
    try:
        return int(value, 10)
    except ValueError:
        raise LiveConnectionCredentialSourceError from None


def _read_env_snapshot(env_file: str | os.PathLike[str]) -> Mapping[str, str | None]:
    try:
        path = Path(env_file)
    except TypeError:
        raise LiveConnectionCredentialSourceError from None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise LiveConnectionCredentialSourceError
        with path.open("rb") as source:
            raw = source.read(_MAX_ENV_FILE_BYTES + 1)
            opened = os.fstat(source.fileno())
        after = path.lstat()
    except LiveConnectionCredentialError:
        raise
    except OSError:
        raise LiveConnectionCredentialSourceError from None
    if (
        len(raw) > _MAX_ENV_FILE_BYTES
        or opened.st_size != len(raw)
        or opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise LiveConnectionCredentialSourceError
    try:
        from dotenv import dotenv_values  # noqa: PLC0415

        text = raw.decode("utf-8", "strict")
        values = dotenv_values(stream=StringIO(text), interpolate=False)
    except (ImportError, UnicodeError, ValueError):
        raise LiveConnectionCredentialSourceError from None
    if not isinstance(values, Mapping):
        raise LiveConnectionCredentialSourceError
    return values


def _bundle_from_env(env_file: str | os.PathLike[str]) -> LiveConnectionCredentialBundle:
    values = _read_env_snapshot(env_file)
    reply_to = values.get("CAMPAIGN_REPLY_TO") or values.get("MANAGER_IMAP_USER")
    if type(reply_to) is not str or not reply_to:
        raise LiveConnectionCredentialSourceError
    try:
        return LiveConnectionCredentialBundle(
            imap_host=_required_env(values, "MANAGER_IMAP_HOST"),
            imap_port=_port_from_env(values, "MANAGER_IMAP_PORT", default=993),
            imap_user=_required_env(values, "MANAGER_IMAP_USER"),
            imap_password=_required_env(values, "MANAGER_IMAP_PASSWORD"),
            smtp_host=_required_env(values, "SMTP_HOST"),
            smtp_port=_port_from_env(values, "SMTP_PORT"),
            smtp_user=_required_env(values, "SMTP_USER"),
            smtp_password=_required_env(values, "SMTP_PASSWORD"),
            smtp_from=_required_env(values, "SMTP_FROM"),
            bitrix_webhook=_required_env(values, LIVE_CONNECTION_BITRIX_SOURCE_NAME),
            unisender_host=_required_env(values, "UNISENDER_GO_HOST"),
            unisender_api_key=_required_env(values, "UNISENDER_GO_API_KEY"),
            unisender_from=_required_env(values, "CAMPAIGN_FROM_EMAIL"),
            unisender_name=_required_env(values, "CAMPAIGN_FROM_NAME"),
            unisender_reply_to=reply_to,
        )
    except LiveConnectionCredentialValidationError:
        raise LiveConnectionCredentialSourceError from None


def _source_binding_sha256() -> str:
    names = (
        "MANAGER_IMAP_HOST",
        "MANAGER_IMAP_PORT|default:993",
        "MANAGER_IMAP_USER",
        "MANAGER_IMAP_PASSWORD",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASSWORD",
        "SMTP_FROM",
        LIVE_CONNECTION_BITRIX_SOURCE_NAME,
        "UNISENDER_GO_HOST",
        "UNISENDER_GO_API_KEY",
        "CAMPAIGN_FROM_EMAIL",
        "CAMPAIGN_FROM_NAME",
        "CAMPAIGN_REPLY_TO|fallback:MANAGER_IMAP_USER",
    )
    return sha256("\n".join(names).encode("ascii", "strict")).hexdigest()


def _receipt(
    blob: bytes,
    *,
    stored: bool,
    replaced_existing: bool,
    readback_verified: bool,
) -> LiveConnectionCredentialReceipt:
    return LiveConnectionCredentialReceipt(
        target_sha256=_TARGET_SHA256,
        bundle_sha256=sha256(blob).hexdigest(),
        source_binding_sha256=_source_binding_sha256(),
        bitrix_source_name=LIVE_CONNECTION_BITRIX_SOURCE_NAME,
        credential_blob_bytes=len(blob),
        stored=stored,
        replaced_existing=replaced_existing,
        readback_verified=readback_verified,
    )


class _WindowsCredentialManager:
    """Minimal CredWriteW/CredReadW boundary bound to the fixed target."""

    __slots__ = ("_advapi",)

    def __init__(self) -> None:
        if os.name != "nt":
            raise LiveConnectionCredentialPlatformError
        try:
            advapi = ctypes.WinDLL("Advapi32", use_last_error=True)
        except (AttributeError, OSError):
            raise LiveConnectionCredentialPlatformError from None
        credential_pointer = ctypes.POINTER(_CredentialW)
        advapi.CredWriteW.argtypes = (ctypes.POINTER(_CredentialW), wintypes.DWORD)
        advapi.CredWriteW.restype = wintypes.BOOL
        advapi.CredReadW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(credential_pointer),
        )
        advapi.CredReadW.restype = wintypes.BOOL
        advapi.CredFree.argtypes = (wintypes.LPVOID,)
        advapi.CredFree.restype = None
        self._advapi = advapi

    def read(self) -> bytes | None:
        pointer = ctypes.POINTER(_CredentialW)()
        ctypes.set_last_error(0)
        if not self._advapi.CredReadW(
            LIVE_CONNECTION_CREDENTIAL_TARGET,
            _CRED_TYPE_GENERIC,
            0,
            ctypes.byref(pointer),
        ):
            if ctypes.get_last_error() == _ERROR_NOT_FOUND:
                return None
            raise LiveConnectionCredentialReadError
        try:
            if not pointer:
                raise LiveConnectionCredentialReadError
            size = int(pointer.contents.CredentialBlobSize)
            blob_pointer = pointer.contents.CredentialBlob
            if not 1 <= size <= _MAX_CREDENTIAL_BLOB_BYTES or not blob_pointer:
                raise LiveConnectionCredentialReadError
            return ctypes.string_at(blob_pointer, size)
        except LiveConnectionCredentialError:
            raise
        except Exception:
            raise LiveConnectionCredentialReadError from None
        finally:
            self._advapi.CredFree(pointer)

    def write(self, blob: bytes) -> None:
        if type(blob) is not bytes or not 1 <= len(blob) <= _MAX_CREDENTIAL_BLOB_BYTES:
            raise LiveConnectionCredentialWriteError
        buffer = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        credential = _CredentialW()
        credential.Flags = 0
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = LIVE_CONNECTION_CREDENTIAL_TARGET
        credential.Comment = "TenderBot Lead Factory live connections v1"
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.AttributeCount = 0
        credential.Attributes = None
        credential.TargetAlias = None
        credential.UserName = "LeadFactory"
        ctypes.set_last_error(0)
        try:
            written = bool(self._advapi.CredWriteW(ctypes.byref(credential), 0))
        except Exception:
            raise LiveConnectionCredentialWriteError from None
        finally:
            ctypes.memset(ctypes.addressof(buffer), 0, len(buffer))
        if not written:
            raise LiveConnectionCredentialWriteError


def _credential_manager() -> _WindowsCredentialManager:
    return _WindowsCredentialManager()


def verify_live_connection_credentials_from_env(
    env_file: str | os.PathLike[str],
) -> LiveConnectionCredentialReceipt:
    """Validate one stable ``.env`` snapshot without touching Credential Manager."""

    blob = _encode_bundle(_bundle_from_env(env_file))
    return _receipt(
        blob,
        stored=False,
        replaced_existing=False,
        readback_verified=False,
    )


def import_live_connection_credentials_from_env(
    env_file: str | os.PathLike[str],
) -> LiveConnectionCredentialReceipt:
    """Atomically write and verify one validated bundle at the fixed target."""

    blob = _encode_bundle(_bundle_from_env(env_file))
    manager = _credential_manager()
    existing = manager.read()
    if existing is not None and hmac.compare_digest(existing, blob):
        _decode_bundle(existing)
        return _receipt(
            blob,
            stored=False,
            replaced_existing=False,
            readback_verified=True,
        )
    manager.write(blob)
    readback = manager.read()
    if readback is None or not hmac.compare_digest(readback, blob):
        raise LiveConnectionCredentialVerificationError
    _decode_bundle(readback)
    return _receipt(
        blob,
        stored=True,
        replaced_existing=existing is not None,
        readback_verified=True,
    )


def load_live_connection_credentials() -> LiveConnectionCredentialBundle:
    """Load the validated fixed-target bundle for a live worker."""

    blob = _credential_manager().read()
    if blob is None:
        raise LiveConnectionCredentialNotFound
    try:
        return _decode_bundle(blob)
    except LiveConnectionCredentialError:
        raise LiveConnectionCredentialReadError from None


__all__ = [
    "LIVE_CONNECTION_BITRIX_SOURCE_NAME",
    "LIVE_CONNECTION_CREDENTIAL_TARGET",
    "LIVE_CONNECTION_CREDENTIAL_VERSION",
    "LiveConnectionCredentialBundle",
    "LiveConnectionCredentialError",
    "LiveConnectionCredentialNotFound",
    "LiveConnectionCredentialPlatformError",
    "LiveConnectionCredentialReadError",
    "LiveConnectionCredentialReceipt",
    "LiveConnectionCredentialSourceError",
    "LiveConnectionCredentialValidationError",
    "LiveConnectionCredentialVerificationError",
    "LiveConnectionCredentialWriteError",
    "import_live_connection_credentials_from_env",
    "load_live_connection_credentials",
    "verify_live_connection_credentials_from_env",
]
