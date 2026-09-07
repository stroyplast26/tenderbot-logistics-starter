"""Process-crash-safe, narrowly scoped Mail.ru -> Bitrix inbound worker.

This module deliberately has no scheduler and performs no network activity at
import time.  Runtime credentials are supplied by the Windows credential-store
boundary in :mod:`lead_factory.live_connection_credentials`.  The worker reads
one IMAP folder in read-only mode, persists the exact RFC822 bytes before it
advances a UID cursor, and creates Bitrix Leads through an idempotent outbox.

The public status objects contain counts and opaque provider ids only.  They
never contain mailbox addresses, message headers/bodies, webhook URLs, secret
values, or absolute evidence paths.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
import hashlib
import imaplib
import json
import os
from pathlib import Path
import re
import shutil
import smtplib
import sqlite3
import ssl
import stat
import tempfile
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid

from .facade_inquiry_parser import parse_facade_inquiry
from .live_connection_credentials import (
    LiveConnectionCredentialBundle,
    load_live_connection_credentials,
)
from .mail_threading import derive_thread_identity, extract_latest_visible_text


ORIGINATOR_ID = "TenderBot.MailInbound.v1"
FACADE_FROM = "info@facade.ru"
BITRIX_ASSIGNED_BY_ID = 13
BITRIX_CANARY_CONFIRMATION = "LF-CANARY-CAP-1-V4"
OWNER_AUTHORITY_CONFIRMATION = "MAIL-TO-BITRIX-INBOUND-V4"
AUTHORITY_REVOKE_CONFIRMATION = "MAIL-TO-BITRIX-INBOUND-REVOKE-V1"
LOCAL_PARSE_REVIEW_ACK_CONFIRMATION = "ACK-LOCAL-PARSE-REVIEW-V1"
LOCAL_REVIEW_ACK_CONFIRMATION = "ACK-LOCAL-REVIEW-NO-CRM-V1"
CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION = "SYNC-CAMPAIGN-SNAPSHOT-V1"
CANARY_TOMBSTONE_RECONCILE_CONFIRMATION = "RECONCILE-CANARY-TOMBSTONES-V1"
MAX_AUTHORITY_HOURS = 168
MAX_WRITE_BUDGET = 500
MIN_WRITE_BUDGET = 6
_MAILBOX = "INBOX"
_SCHEMA_VERSION = "4"
_MAX_MIME_BYTES = 50 * 1024 * 1024
_MAX_MIME_DEPTH = 64
_MAX_MIME_PARTS = 10_000
_MAX_EVIDENCE_BYTES = 5 * 1024 * 1024 * 1024
_MIN_EVIDENCE_FREE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_LEGACY_BYTES = 64 * 1024 * 1024
_MAX_RETRIES = 8
_MAX_RECONCILES = 8
_BITRIX_METHODS = frozenset(
    {
        "crm.activity.get",
        "crm.activity.list",
        "crm.activity.todo.add",
        "crm.lead.add",
        "crm.lead.fields",
        "crm.lead.get",
        "crm.lead.list",
        "crm.timeline.comment.add",
        "crm.timeline.comment.get",
        "crm.timeline.comment.list",
    }
)
_MSG_ID = re.compile(r"<[^<>\s]{1,998}>")
_EVIDENCE_TEMP_NAME = re.compile(r"\.([1-9]\d*)\.([a-z0-9_]{8})\.tmp")
_EMAIL = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])", re.I)
_PHONE = re.compile(r"(?<!\d)(\+?\d[\d\s().-]{7,22}\d)(?!\d)")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SPACE = re.compile(r"[ \t\f\v]+")
_BLANKS = re.compile(r"\n{3,}")
_SCHEMA_CONTRACT_OBJECTS = frozenset(
    {
        "meta",
        "cursor",
        "scoped_authority",
        "messages",
        "idx_messages_state",
        "idx_messages_mid",
        "message_deliveries",
        "legacy_message_state",
        "crm_outbox",
        "idx_crm_outbox_state",
        "crm_delivery_outbox",
        "idx_crm_delivery_outbox_state",
        "runs",
        "idx_runs_started",
    }
)
_LEGACY_V3_SCHEMA_CONTRACT_SHA256S = frozenset(
    {
        # The deployed state, upgraded in-place by the released V3 runtime.
        "95aba4076a659a7108c5bfb7f1299256c0fb371d5495c4f8d3a37fe96b156a5b",
        # A state created directly by the released V3 runtime.
        "3d394942d6ffcf7cf681b92a545b0e8238f9063587561104098347a765f914a3",
    }
)
_V4_SCHEMA_CONTRACT_SHA256S = frozenset(
    {
        # A database created directly by the V4 DDL.
        "532bb07f870d69d840b9b0c27fb5627b9987c6b4cd9dbb3837558868c8f93f23",
        # The deterministic result of migrating the exact released V3 DDL.
        "bcfa740fb1cef0e5b79ce3c8e3ac23fce61e12671a7a7e5261bbb0fbefb22583",
        # The deterministic result of migrating a fresh released V3 state.
        "69b355bfb7ee11f0cdd1ce38095707118e062cc878c5b35835d6a99be6374365",
    }
)
_AUTO_CALL_ROUTES = frozenset(
    {"FACADE_AUTO", "CAMPAIGN_HUMAN_AUTO", "DIRECT_INQUIRY_AUTO"}
)
_CRM_REVIEW_ROUTES = frozenset(
    {
        "FACADE_AUTH_REVIEW",
        "CAMPAIGN_IDENTITY_REVIEW",
        "CAMPAIGN_AUTH_REVIEW",
        "INQUIRY_REVIEW",
    }
)
_CRM_LEAD_ROUTES = _AUTO_CALL_ROUTES | _CRM_REVIEW_ROUTES


class LiveMailBitrixError(RuntimeError):
    """Base error whose message is safe for an operator log."""


class BootstrapRequired(LiveMailBitrixError):
    """The durable cursor must be set explicitly before the first read."""


class UidValidityMismatch(LiveMailBitrixError):
    """The mailbox UID namespace changed and requires manual reconciliation."""


class ConcurrentRun(LiveMailBitrixError):
    """Another local worker owns the single-process runtime lock."""


class CredentialContractError(LiveMailBitrixError):
    """A credential is missing or violates the narrow connection contract."""


class RemotePreflightError(LiveMailBitrixError):
    """A read-only provider preflight did not prove the required contract."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        code: str = "remote_preflight_failed",
    ):
        super().__init__(message)
        self.retryable = bool(retryable)
        self.code = str(code)


class BitrixWriteNotVerified(LiveMailBitrixError):
    """The cap-one Bitrix write/readback canary has not completed."""


class BitrixWriteBudgetExhausted(LiveMailBitrixError):
    """The active owner permit has no remaining Bitrix create attempts."""


class _ImapReadError(LiveMailBitrixError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        code: str = "imap_read_failed",
    ):
        super().__init__(message)
        self.retryable = bool(retryable)
        self.code = str(code)


class _MailParseError(LiveMailBitrixError):
    """A fetched MIME is locally unsafe to interpret but remains evidence."""


class _BitrixCallError(LiveMailBitrixError):
    def __init__(self, category: str, *, definite: bool, retryable: bool):
        super().__init__("Bitrix request did not complete safely")
        self.category = _safe_token(category, fallback="REMOTE_ERROR")
        self.definite = bool(definite)
        self.retryable = bool(retryable)


class _ImapClient(Protocol):
    untagged_responses: Mapping[object, object]

    def login(self, user: str, password: str) -> tuple[object, object]: ...

    def select(self, mailbox: str, readonly: bool = False) -> tuple[object, object]: ...

    def uid(self, command: str, *args: object) -> tuple[object, object]: ...

    def logout(self) -> tuple[object, object]: ...


ImapFactory = Callable[[LiveConnectionCredentialBundle], _ImapClient]
SmtpFactory = Callable[[LiveConnectionCredentialBundle], Any]
HttpCallable = Callable[..., Any]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class _ParsedMail:
    message_id: str
    message_id_hash: str
    thread_ids: tuple[str, ...]
    sender: str
    sender_name: str
    sender_hash: str
    subject: str
    text: str
    latest_text: str
    thread_key: str
    is_bounce: bool
    is_unsubscribe: bool
    is_system: bool
    sender_authenticated: bool
    facade_authenticated: bool


_PARSE_REVIEW_PLACEHOLDER = _ParsedMail(
    message_id="",
    message_id_hash="",
    thread_ids=(),
    sender="",
    sender_name="",
    sender_hash="",
    subject="",
    text="",
    latest_text="",
    thread_key="",
    is_bounce=False,
    is_unsubscribe=False,
    is_system=False,
    sender_authenticated=False,
    facade_authenticated=False,
)


@dataclass(frozen=True)
class _Route:
    name: str
    state: str
    payload: dict[str, Any] | None


@dataclass(frozen=True)
class _HttpResult:
    status_code: int
    payload: Any
    redirected: bool = False


@dataclass(frozen=True)
class _CampaignSnapshot:
    records: dict[str, dict[str, Any]]
    present: bool
    source_sha256: str


@dataclass(frozen=True)
class _StableJsonSnapshot:
    document: Any
    present: bool
    source_sha256: str


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class _TextExtractor(HTMLParser):
    _SKIP = frozenset({"script", "style", "head", "noscript", "svg"})
    _BREAK = frozenset(
        {"p", "div", "br", "li", "tr", "td", "th", "table", "section", "article", "h1", "h2", "h3"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        if lowered in self._SKIP:
            self.skip_depth += 1
        elif not self.skip_depth and lowered in self._BREAK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered in self._SKIP and self.skip_depth:
            self.skip_depth -= 1
        elif not self.skip_depth and lowered in self._BREAK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        return _clean_text("".join(self.parts), limit=200_000)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_token(value: object, *, fallback: str = "UNKNOWN") -> str:
    token = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").upper()).strip("_.-")
    return (token[:80] or fallback)


def _operator_action_for_route(route: object) -> str:
    return "CALL" if _safe_token(route, fallback="MAIL") in _AUTO_CALL_ROUTES else "REVIEW"


def _digest(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def _local_parse_review_ack_key(message_key: str) -> str:
    return f"local_parse_review_ack_{message_key}"


def _local_parse_review_ack_valid(
    value: object,
    *,
    message_key: str,
    rfc822_sha256: str,
) -> bool:
    try:
        record = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(record, dict) or set(record) != {
        "acknowledged_at_utc",
        "message_key_sha256",
        "rfc822_sha256",
    }:
        return False
    return bool(
        record.get("message_key_sha256") == _digest(message_key)
        and record.get("rfc822_sha256") == rfc822_sha256
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            str(record.get("acknowledged_at_utc", "")),
        )
    )


def _local_review_ack_key(message_key: str) -> str:
    return f"local_review_ack_{message_key}"


def _local_review_ack_valid(
    value: object,
    *,
    message_key: str,
    route: str,
    rfc822_sha256: str,
) -> bool:
    try:
        record = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(record, dict) or set(record) != {
        "acknowledged_at_utc",
        "confirmation_hash",
        "decision",
        "message_key_sha256",
        "rfc822_sha256",
        "route",
    }:
        return False
    return bool(
        record.get("confirmation_hash") == _digest(LOCAL_REVIEW_ACK_CONFIRMATION)
        and record.get("decision") == "ACKNOWLEDGED_NO_CRM"
        and record.get("message_key_sha256") == _digest(message_key)
        and record.get("rfc822_sha256") == rfc822_sha256
        and record.get("route") == route
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            str(record.get("acknowledged_at_utc", "")),
        )
    )


def _canary_tombstone_resolution_key(tombstone_key: str) -> str:
    return f"bitrix_canary_resolution_{_digest(tombstone_key)[:40]}"


def _canary_tombstone_resolution_valid(
    value: object,
    *,
    tombstone_key: str,
    tombstone_value: str,
) -> bool:
    try:
        record = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(record, dict) or set(record) != {
        "operator_todo_count",
        "parent_state",
        "reconciled_at_utc",
        "remote_lead_id",
        "timeline_mail_count",
        "tombstone_key_sha256",
        "tombstone_sha256",
    }:
        return False
    return bool(
        record.get("tombstone_key_sha256") == _digest(tombstone_key)
        and record.get("tombstone_sha256") == _digest(tombstone_value)
        and record.get("parent_state") in {"ABSENT", "VERIFIED"}
        and type(record.get("operator_todo_count")) is int
        and record.get("operator_todo_count") in {0, 1}
        and type(record.get("timeline_mail_count")) is int
        and record.get("timeline_mail_count") in {0, 1}
        and (
            record.get("remote_lead_id") == ""
            or re.fullmatch(r"\d{1,20}", str(record.get("remote_lead_id", "")))
        )
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            str(record.get("reconciled_at_utc", "")),
        )
    )


def _canonical_message_id(value: object) -> str:
    text = str(value or "").strip()
    found = _MSG_ID.findall(text)
    if len(found) != 1:
        return ""
    return found[0].casefold()


def _message_ids(value: object) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for token in _MSG_ID.findall(str(value or ""))[:128]:
        normalized = token.casefold()
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return tuple(result)


def _clean_text(value: object, *, limit: int) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)
    text = "\n".join(_SPACE.sub(" ", line).strip() for line in text.split("\n"))
    return _BLANKS.sub("\n\n", text).strip()[:limit]


def _header(value: object, *, limit: int = 500) -> str:
    return _clean_text(value, limit=limit).replace("\n", " ")


def _html_to_text(value: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(value[:2_000_000])
        parser.close()
    except MemoryError:
        raise
    except Exception:
        return ""
    return parser.text()


def _part_text(part: Message) -> str:
    try:
        content = part.get_content()
    except MemoryError:
        raise
    except Exception:
        raw = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            content = raw.decode(charset, errors="replace")
        except LookupError:
            content = raw.decode("utf-8", errors="replace")
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    return str(content or "")


def _visible_mime_parts(part: Message) -> Iterable[Message]:
    stack: list[tuple[Message, int]] = [(part, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        visited += 1
        if depth > _MAX_MIME_DEPTH or visited > _MAX_MIME_PARTS:
            raise _MailParseError("MIME structure exceeds the safe boundary")
        disposition = str(current.get_content_disposition() or "").casefold()
        content_type = current.get_content_type().casefold()
        if (
            disposition == "attachment"
            or bool(current.get_filename())
            or (
                content_type.startswith("message/")
                and content_type != "message/delivery-status"
            )
        ):
            continue
        yield current
        if current.is_multipart():
            payload = current.get_payload()
            if isinstance(payload, list):
                children = [child for child in payload if isinstance(child, Message)]
                stack.extend((child, depth + 1) for child in reversed(children))


def _body_text(message: Message) -> str:
    plain: list[str] = []
    html: list[str] = []
    for part in _visible_mime_parts(message):
        if part.is_multipart():
            continue
        kind = part.get_content_type().casefold()
        if kind == "text/plain":
            plain.append(_part_text(part))
        elif kind == "text/html":
            html.append(_html_to_text(_part_text(part)))
    selected = "\n\n".join(plain).strip() or "\n\n".join(html).strip()
    return _clean_text(selected, limit=200_000)


def _single_mailbox(message: Message, header_name: str) -> str:
    values = message.get_all(header_name, []) or []
    if len(values) != 1:
        return ""
    parsed = [
        address.strip().casefold()
        for _display, address in getaddresses([str(values[0])])
        if address.strip()
    ]
    if len(parsed) != 1 or len(parsed[0]) > 320 or not _EMAIL.fullmatch(parsed[0]):
        return ""
    return parsed[0]


def _mailru_authenticated_sender(
    message: Message,
    *,
    expected_recipient: str,
    sender: str,
) -> bool:
    """Accept only the receiver-added Mail.ru authentication trace shape.

    ``Authentication-Results`` has no integrity of its own.  Mail.ru's live
    INBOX currently seals its result above the first ``Received`` field in an
    exact delivery prefix.  Any duplicate, displacement, or shape drift is a
    fail-closed review condition; a sender-supplied lookalike can therefore
    never become an automatic CRM write.
    """

    if not expected_recipient or not sender:
        return False
    ordered = list(message.raw_items())
    header_names = tuple(name.casefold() for name, _value in ordered)
    direct_prefix = (
        "delivered-to",
        "return-path",
        "authentication-results",
        "received-spf",
        "received",
    )
    forwarded_prefix = (
        "delivered-to",
        "return-path",
        "received-spf",
        "received",
        "received",
    )
    forwarded_suffix = (
        "x-mailru-dmarc-auth",
        "x-mras",
        "x-spam",
        "authentication-results",
        "x-mailru-intl-transport",
    )
    direct_profile = header_names[: len(direct_prefix)] == direct_prefix
    forwarded_profile = bool(
        header_names[: len(forwarded_prefix)] == forwarded_prefix
        and header_names[-len(forwarded_suffix) :] == forwarded_suffix
    )
    if not direct_profile and not forwarded_profile:
        return False
    required_singletons = {
        "delivered-to",
        "return-path",
        "authentication-results",
        "received-spf",
    }
    if forwarded_profile:
        required_singletons.update(forwarded_suffix)
    if any(header_names.count(singleton) != 1 for singleton in required_singletons):
        return False

    delivered_to = _single_mailbox(message, "Delivered-To")
    return_path = _single_mailbox(message, "Return-Path")
    if delivered_to != expected_recipient.casefold() or not return_path:
        return False

    auth_index = 2 if direct_profile else len(ordered) - 2
    spf_index = 3 if direct_profile else 2
    raw_auth = " ".join(str(ordered[auth_index][1] or "").split())
    raw_received_spf = " ".join(str(ordered[spf_index][1] or "").split())
    if (
        len(raw_auth) > 8_192
        or len(raw_received_spf) > 8_192
        or _CONTROL.search(raw_auth)
        or _CONTROL.search(raw_received_spf)
        or not raw_auth.isascii()
        or not raw_received_spf.isascii()
    ):
        return False
    auth_parts = [part.strip().casefold() for part in raw_auth.split(";")]
    if len(auth_parts) != 3 or auth_parts[0] != "mxs.mail.ru":
        return False

    methods: dict[str, tuple[str, str]] = {}
    for clause in auth_parts[1:]:
        match = re.match(
            r"\A([a-z][a-z0-9_-]{0,31})(?:/[0-9]{1,3})?\s*=\s*"
            r"([a-z][a-z0-9_-]{0,31})(?:\s|$)",
            clause,
        )
        if not match or match.group(1) in methods:
            return False
        methods[match.group(1)] = (match.group(2), clause)
    if set(methods) != {"spf", "dkim"}:
        return False
    spf_result, spf_clause = methods["spf"]
    dkim_result, dkim_clause = methods["dkim"]
    if spf_result != "pass" or dkim_result != "pass":
        return False

    smtp_matches = re.findall(
        r"(?<![a-z0-9_.-])smtp\.mailfrom\s*=\s*"
        r"<?([a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+)>?(?=\s|$)",
        spf_clause,
    )
    dkim_matches = re.findall(
        r"(?<![a-z0-9_.-])header\.d\s*=\s*([a-z0-9.-]+)(?=\s|$)",
        dkim_clause,
    )
    if len(smtp_matches) != 1 or len(dkim_matches) != 1:
        return False
    smtp_mailfrom = smtp_matches[0].casefold()
    dkim_domain = dkim_matches[0].rstrip(".").casefold()
    sender_domain = sender.rpartition("@")[2].rstrip(".").casefold()
    smtp_domain = smtp_mailfrom.rpartition("@")[2].rstrip(".").casefold()
    if (
        not sender_domain
        or smtp_mailfrom != return_path
        or smtp_domain != sender_domain
        or dkim_domain != sender_domain
    ):
        return False

    received_spf = raw_received_spf.casefold()
    envelope_matches = re.findall(
        r"(?<![a-z0-9_.-])envelope-from\s*=\s*"
        r"<?([a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+)>?(?=;|\s|$)",
        received_spf,
    )
    if not received_spf.startswith("pass ") or envelope_matches != [smtp_mailfrom]:
        return False

    signature_domains: list[str] = []
    for signature in message.get_all("DKIM-Signature", []) or []:
        normalized = " ".join(str(signature or "").split()).casefold()
        signature_domains.extend(
            match.rstrip(".")
            for match in re.findall(r"(?:\A|;)\s*d\s*=\s*([a-z0-9.-]+)(?=\s*;|\s|$)", normalized)
        )
    return signature_domains.count(dkim_domain) == 1


def _parse_mail_unchecked(raw: bytes, *, expected_recipient: str) -> _ParsedMail:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except MemoryError:
        raise
    except Exception as exc:
        raise _MailParseError("MIME message could not be parsed safely") from exc
    sender_header = str(message.get("From", ""))
    sender = _single_mailbox(message, "From")
    sender_name = _header(parseaddr(sender_header)[0], limit=255)
    subject = _header(message.get("Subject", ""), limit=998)
    text = _body_text(message)
    latest_text = extract_latest_visible_text(text)
    message_id = _canonical_message_id(message.get("Message-ID", ""))
    thread_ids = _message_ids(message.get("In-Reply-To", "")) + _message_ids(
        message.get("References", "")
    )
    thread_ids = tuple(dict.fromkeys(thread_ids))
    thread_identity = derive_thread_identity(
        message_id=str(message.get("Message-ID", "") or ""),
        in_reply_to=str(message.get("In-Reply-To", "") or ""),
        references=str(message.get("References", "") or ""),
    )
    auto_submitted = str(message.get("Auto-Submitted", "")).strip().casefold()
    precedence = str(message.get("Precedence", "")).strip().casefold()
    sender_local = sender.partition("@")[0]
    subject_fold = subject.casefold()
    body_fold = latest_text[:20_000].casefold()
    content_types = {
        part.get_content_type().casefold() for part in _visible_mime_parts(message)
    }
    sender_authenticated = _mailru_authenticated_sender(
        message,
        expected_recipient=expected_recipient,
        sender=sender,
    )
    facade_authenticated = sender == FACADE_FROM and sender_authenticated
    is_bounce = bool(
        sender_local in {"mailer-daemon", "postmaster"}
        or "message/delivery-status" in content_types
        or str(message.get("Return-Path", "")).strip() == "<>"
        or any(
            marker in subject_fold
            for marker in (
                "delivery status notification",
                "undeliverable",
                "delivery failure",
                "mail delivery failed",
                "недостав",
                "ошибка доставки",
            )
        )
    )
    is_unsubscribe = any(
        marker in f"{subject_fold}\n{body_fold}"
        for marker in (
            "unsubscribe",
            "отписаться",
            "отпишите",
            "не пишите",
            "уберите из рассылки",
            "stop emailing",
        )
    )
    is_system = bool(
        (auto_submitted and auto_submitted != "no")
        or precedence in {"bulk", "junk", "list"}
        or message.get("X-Autoreply") is not None
        or message.get("X-Autorespond") is not None
        or any(
            marker in subject_fold
            for marker in (
                "automatic reply",
                "auto reply",
                "out of office",
                "автоматический ответ",
                "автоответ",
                "вне офиса",
            )
        )
    )
    return _ParsedMail(
        message_id=message_id,
        message_id_hash=_digest(message_id) if message_id else "",
        thread_ids=thread_ids,
        sender=sender,
        sender_name=sender_name,
        sender_hash=_digest(sender) if sender else "",
        subject=subject,
        text=text,
        latest_text=latest_text,
        thread_key=thread_identity.key if thread_identity is not None else "",
        is_bounce=is_bounce,
        is_unsubscribe=is_unsubscribe,
        is_system=is_system,
        sender_authenticated=sender_authenticated,
        facade_authenticated=facade_authenticated,
    )


def _parse_mail(raw: bytes, *, expected_recipient: str) -> _ParsedMail:
    try:
        return _parse_mail_unchecked(raw, expected_recipient=expected_recipient)
    except _MailParseError:
        raise
    except MemoryError:
        raise
    except Exception as exc:
        raise _MailParseError("MIME message could not be interpreted safely") from exc


def _label(text: str, labels: Iterable[str], *, limit: int) -> str:
    alternatives = "|".join(re.escape(label) for label in labels)
    pattern = re.compile(rf"(?im)^\s*(?:{alternatives})\s*[:\-]\s*(.+?)\s*$")
    match = pattern.search(text)
    return _header(match.group(1), limit=limit) if match else ""


def _first_email(text: str, *, excluded: Iterable[str] = ()) -> str:
    denied = {value.casefold() for value in excluded if value}
    for match in _EMAIL.finditer(text[:100_000]):
        candidate = match.group(1).casefold()
        if candidate not in denied:
            return candidate[:320]
    return ""


def _first_phone(text: str) -> str:
    labelled = _label(text, ("телефон", "тел.", "phone", "мобильный"), limit=64)
    candidates = (labelled, text[:100_000])
    for candidate_text in candidates:
        match = _PHONE.search(candidate_text)
        if match:
            phone = re.sub(r"[^\d+]", "", match.group(1))
            digits = re.sub(r"\D", "", phone)
            if 9 <= len(digits) <= 15:
                return phone[:32]
    return ""


def _read_json_snapshot(path: Path | None, *, default: Any) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        size = path.stat().st_size
        if size < 0 or size > _MAX_LEGACY_BYTES:
            return default
        with path.open("rb") as handle:
            raw = handle.read(_MAX_LEGACY_BYTES + 1)
        if len(raw) > _MAX_LEGACY_BYTES:
            return default
        return json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return default


def _stable_json_snapshot(path: Path) -> _StableJsonSnapshot:
    try:
        before = path.stat()
    except FileNotFoundError:
        return _StableJsonSnapshot(document={}, present=False, source_sha256=_digest(b""))
    except OSError as exc:
        raise LiveMailBitrixError("legacy source snapshot is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
        or not 1 <= int(before.st_size) <= _MAX_LEGACY_BYTES
    ):
        raise LiveMailBitrixError("legacy source snapshot is unsafe")
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(opened.st_nlink) != 1
            or (int(opened.st_dev), int(opened.st_ino))
            != (int(before.st_dev), int(before.st_ino))
            or int(opened.st_size) != int(before.st_size)
        ):
            raise LiveMailBitrixError("legacy source snapshot changed during read")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(_MAX_LEGACY_BYTES + 1)
        after = path.stat()
    except LiveMailBitrixError:
        raise
    except (OSError, ValueError) as exc:
        raise LiveMailBitrixError("legacy source snapshot is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(raw) != int(before.st_size)
        or len(raw) > _MAX_LEGACY_BYTES
        or (int(after.st_dev), int(after.st_ino))
        != (int(before.st_dev), int(before.st_ino))
        or int(after.st_size) != int(before.st_size)
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
    ):
        raise LiveMailBitrixError("legacy source snapshot changed during read")
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LiveMailBitrixError("legacy source snapshot is invalid") from exc
    return _StableJsonSnapshot(
        document=document,
        present=True,
        source_sha256=_digest(raw),
    )


def _campaign_snapshot(path: Path | None) -> _CampaignSnapshot:
    if path is None:
        return _CampaignSnapshot(records={}, present=False, source_sha256=_digest(b""))
    try:
        before = path.stat()
    except FileNotFoundError:
        return _CampaignSnapshot(records={}, present=False, source_sha256=_digest(b""))
    except OSError as exc:
        raise LiveMailBitrixError("campaign source snapshot is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
        or not 1 <= int(before.st_size) <= _MAX_LEGACY_BYTES
    ):
        raise LiveMailBitrixError("campaign source snapshot is unsafe")
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(opened.st_nlink) != 1
            or (int(opened.st_dev), int(opened.st_ino))
            != (int(before.st_dev), int(before.st_ino))
            or int(opened.st_size) != int(before.st_size)
        ):
            raise LiveMailBitrixError("campaign source snapshot changed during read")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(_MAX_LEGACY_BYTES + 1)
        after = path.stat()
    except LiveMailBitrixError:
        raise
    except (OSError, ValueError) as exc:
        raise LiveMailBitrixError("campaign source snapshot is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(raw) != int(before.st_size)
        or len(raw) > _MAX_LEGACY_BYTES
        or (int(after.st_dev), int(after.st_ino))
        != (int(before.st_dev), int(before.st_ino))
        or int(after.st_size) != int(before.st_size)
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
    ):
        raise LiveMailBitrixError("campaign source snapshot changed during read")
    try:
        source = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LiveMailBitrixError("campaign source snapshot is invalid") from exc
    if not isinstance(source, dict) or len(source) > 100_000:
        raise LiveMailBitrixError("campaign source snapshot is invalid")
    result: dict[str, dict[str, Any]] = {}
    identities: dict[str, str] = {}
    for raw_record in source.values():
        if not isinstance(raw_record, dict):
            raise LiveMailBitrixError("campaign source snapshot is invalid")
        record: dict[str, Any] = {}
        for key in ("subject", "object", "winner", "email", "phone"):
            raw_value = raw_record.get(key, "")
            if raw_value is None:
                raw_value = ""
            if type(raw_value) is not str:
                raise LiveMailBitrixError("campaign source snapshot is invalid")
            normalized = _header(raw_value, limit=2_000)
            record[key] = normalized.casefold() if key == "email" else normalized
        ids = raw_record.get("sent_msgids") or []
        if not isinstance(ids, list) or len(ids) > 100:
            raise LiveMailBitrixError("campaign source snapshot is invalid")
        record_identity = _digest(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        for raw_id in ids:
            if type(raw_id) is not str:
                raise LiveMailBitrixError("campaign source snapshot is invalid")
            message_id = _canonical_message_id(raw_id)
            if not message_id:
                raise LiveMailBitrixError("campaign source snapshot is invalid")
            prior_identity = identities.get(message_id)
            if prior_identity is not None and prior_identity != record_identity:
                raise LiveMailBitrixError(
                    "campaign source has a conflicting message identity"
                )
            identities[message_id] = record_identity
            result[message_id] = record
    return _CampaignSnapshot(
        records=result,
        present=True,
        source_sha256=_digest(raw),
    )


def _runtime_state_dir() -> Path:
    if os.name == "nt":
        profile = os.environ.get("USERPROFILE", "").strip()
        return (Path(profile) if profile else Path.home()) / ".tenderbot" / "live_inbound"
    state = os.environ.get("XDG_STATE_HOME", "").strip()
    if state:
        return Path(state) / "TenderBot" / "live_inbound"
    return Path.home() / ".local" / "state" / "TenderBot" / "live_inbound"


def _default_imap_factory(credentials: LiveConnectionCredentialBundle) -> _ImapClient:
    context = ssl.create_default_context()
    return imaplib.IMAP4_SSL(
        credentials.imap_host,
        int(credentials.imap_port),
        ssl_context=context,
        timeout=25,
    )


def _default_smtp_factory(credentials: LiveConnectionCredentialBundle) -> Any:
    context = ssl.create_default_context()
    port = int(credentials.smtp_port)
    if port == 465:
        return smtplib.SMTP_SSL(
            credentials.smtp_host,
            port,
            context=context,
            timeout=25,
        )
    if port == 587:
        client = smtplib.SMTP(credentials.smtp_host, port, timeout=25)
        client.ehlo()
        client.starttls(context=context)
        client.ehlo()
        return client
    raise CredentialContractError("SMTP port must be 465 or 587")


def _default_http_post(url: str, *, json: dict[str, Any], timeout: int, allow_redirects: bool) -> _HttpResult:
    if allow_redirects:
        raise ValueError("redirects must remain disabled")
    encoded = __import__("json").dumps(json, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=encoded,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(_MAX_JSON_BYTES + 1)
            if len(body) > _MAX_JSON_BYTES:
                raise _BitrixCallError("RESPONSE_TOO_LARGE", definite=False, retryable=False)
            try:
                payload = __import__("json").loads(body.decode("utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise _BitrixCallError("INVALID_JSON", definite=False, retryable=False) from exc
            return _HttpResult(int(response.status), payload, redirected=False)
    except HTTPError as exc:
        body = exc.read(_MAX_JSON_BYTES + 1)
        payload: Any = {}
        if len(body) <= _MAX_JSON_BYTES:
            try:
                payload = __import__("json").loads(body.decode("utf-8"))
            except (UnicodeError, ValueError):
                payload = {}
        return _HttpResult(int(exc.code), payload, redirected=300 <= int(exc.code) < 400)
    except _BitrixCallError:
        raise
    except (URLError, TimeoutError, OSError) as exc:
        raise _BitrixCallError("TRANSPORT", definite=False, retryable=False) from exc


def _response_result(response: Any) -> _HttpResult:
    if isinstance(response, _HttpResult):
        return response
    if isinstance(response, dict):
        return _HttpResult(200, response)
    status = getattr(response, "status_code", getattr(response, "status", None))
    if status is None:
        raise _BitrixCallError("INVALID_RESPONSE", definite=False, retryable=False)
    history = getattr(response, "history", ()) or ()
    redirected = bool(history) or bool(getattr(response, "is_redirect", False))
    try:
        payload = response.json()
    except Exception as exc:
        raise _BitrixCallError("INVALID_JSON", definite=False, retryable=False) from exc
    return _HttpResult(int(status), payload, redirected=redirected)


class _RuntimeLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle: Any = None

    def __enter__(self) -> "_RuntimeLock":
        _assert_plain_directory_chain(self.path.parent)
        _assert_plain_optional_file(self.path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(self.path, flags, 0o600)
            opened = os.fstat(descriptor)
            on_disk = _plain_path_stat(self.path, directory=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or int(opened.st_nlink) != 1
                or (int(opened.st_dev), int(opened.st_ino))
                != (int(on_disk.st_dev), int(on_disk.st_ino))
            ):
                raise LiveMailBitrixError("live inbound runtime lock is unsafe")
            self.handle = os.fdopen(descriptor, "r+b", buffering=0)
            descriptor = -1
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                if self.path.stat().st_size == 0:
                    self.handle.write(b"0")
                    self.handle.flush()
                    self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            if self.handle is not None:
                self.handle.close()
            self.handle = None
            raise ConcurrentRun("another inbound worker is already running") from exc
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            if self.handle is not None:
                self.handle.close()
            self.handle = None
            raise
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def _authority_generation_counter_tx(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT value FROM meta WHERE key='authority_generation_counter'"
    ).fetchone()
    if row is None:
        return 0
    try:
        return max(0, int(row[0]))
    except (TypeError, ValueError):
        return 0


def _record_authority_generation_tx(
    connection: sqlite3.Connection,
    generation: int,
) -> None:
    connection.execute(
        "INSERT INTO meta(key,value) VALUES('authority_generation_counter',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(max(0, int(generation))),),
    )


def _authority_revocation_fence_tx(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT value FROM meta WHERE key='authority_revocation_fence'"
    ).fetchone()
    try:
        return max(0, int(row[0])) if row is not None else 0
    except (TypeError, ValueError):
        return 0


def _advance_authority_revocation_fence_tx(connection: sqlite3.Connection) -> int:
    value = _authority_revocation_fence_tx(connection) + 1
    connection.execute(
        "INSERT INTO meta(key,value) VALUES('authority_revocation_fence',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(value),),
    )
    return value


def _mark_canary_review_tx(connection: sqlite3.Connection, *, state: str) -> None:
    connection.execute(
        "DELETE FROM meta WHERE key IN ("
        "'bitrix_write_verified','bitrix_canary_authority_generation',"
        "'bitrix_canary_runtime_sha256','bitrix_canary_release_sha256',"
        "'bitrix_canary_webhook_scope_hash','bitrix_canary_assigned_by_id')"
    )
    connection.execute(
        "INSERT INTO meta(key,value) VALUES('bitrix_canary_state',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (state,),
    )


def _invalidate_canary_tx(connection: sqlite3.Connection, *, state: str) -> None:
    delivery_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='crm_delivery_outbox'"
    ).fetchone()
    state_row = connection.execute(
        "SELECT value FROM meta WHERE key='bitrix_canary_state'"
    ).fetchone()
    prior_state = str(state_row[0]) if state_row is not None else ""
    identity_row = connection.execute(
        "SELECT value FROM meta WHERE key='bitrix_canary_origin_id'"
    ).fetchone()
    payload_row = connection.execute(
        "SELECT value FROM meta WHERE key='bitrix_canary_lead_payload_json'"
    ).fetchone()
    remote_row = connection.execute(
        "SELECT value FROM meta WHERE key='bitrix_canary_remote_id'"
    ).fetchone()
    origin_generation_row = connection.execute(
        "SELECT value FROM meta "
        "WHERE key='bitrix_canary_origin_authority_generation'"
    ).fetchone()
    origin_id = str(identity_row[0]) if identity_row is not None else ""
    try:
        origin_generation = max(
            0,
            int(origin_generation_row[0])
            if origin_generation_row is not None
            else 0,
        )
    except (TypeError, ValueError):
        origin_generation = 0
    unresolved_delivery = False
    if delivery_table is not None and origin_id and origin_generation > 0:
        parent_operation_id = (
            f"canary:{origin_generation}:{_digest(origin_id)[:32]}"
        )
        message_key = f"canary_{_digest(parent_operation_id)}"
        unresolved_delivery = bool(
            connection.execute(
                """SELECT 1 FROM crm_delivery_outbox
                   WHERE parent_operation_id=? AND message_key=?
                     AND state NOT IN ('CREATED','RECONCILED') LIMIT 1""",
                (parent_operation_id, message_key),
            ).fetchone()
        )
    # PREPARED/PRECREATE_QUERY prove that no Lead create crossed the durable
    # CREATE_DISPATCH fence.  Every later state may represent an acknowledged
    # or response-lost remote write, so its origin must survive reauthorization
    # and revocation as a durable reconciliation tombstone.
    preserve_identity = bool(
        identity_row is not None
        and (
            prior_state not in {"", "PREPARED", "PRECREATE_QUERY", "VERIFIED"}
            or unresolved_delivery
        )
    )
    if preserve_identity:
        tombstone_key = (
            f"bitrix_canary_tombstone_{origin_generation}_"
            f"{_digest(origin_id)[:16]}"
        )
        tombstone_value = json.dumps(
            {
                "authority_generation": origin_generation,
                "origin_id": origin_id,
                "payload_json": str(payload_row[0]) if payload_row is not None else "",
                "prior_state": prior_state,
                "remote_lead_id": str(remote_row[0]) if remote_row is not None else "",
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)",
            (tombstone_key, tombstone_value),
        )
        persisted_tombstone = connection.execute(
            "SELECT value FROM meta WHERE key=?",
            (tombstone_key,),
        ).fetchone()
        if (
            persisted_tombstone is None
            or str(persisted_tombstone[0]) != tombstone_value
        ):
            raise LiveMailBitrixError("canary reconciliation tombstone conflicts")
    _mark_canary_review_tx(connection, state=state)
    connection.execute(
        "DELETE FROM meta WHERE key IN ("
        "'bitrix_canary_remote_id','bitrix_canary_origin_id',"
        "'bitrix_canary_lead_payload_json',"
        "'bitrix_canary_origin_authority_generation')"
    )
    if delivery_table is not None:
        invalidated = "CANARY_INVALIDATED_REVIEW"
        connection.execute(
            """UPDATE crm_delivery_outbox SET state=?,next_attempt_at_utc='',
               error_class=?,error_digest=?
               WHERE message_key LIKE 'canary_%'
                 AND state NOT IN ('CREATED','RECONCILED')""",
            (invalidated, invalidated, _digest(invalidated)),
        )


def _schema_contract_sha256(
    connection: sqlite3.Connection,
    object_names: Iterable[str] = _SCHEMA_CONTRACT_OBJECTS,
) -> str:
    selected_objects = tuple(sorted(set(object_names)))
    placeholders = ",".join("?" for _ in selected_objects)
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        f"WHERE name IN ({placeholders}) ORDER BY type,name",
        selected_objects,
    ).fetchall()
    contract = [
        {
            "name": str(row["name"]),
            "sql": re.sub(r"\s+", " ", str(row["sql"] or "").strip()),
            "table": str(row["tbl_name"]),
            "type": str(row["type"]),
        }
        for row in rows
    ]
    return _digest(
        json.dumps(contract, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    )


def _user_schema_object_names(connection: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type IN ('table','index','trigger','view') "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    )


def _same_instant(left: object, right: object) -> bool:
    try:
        left_value = _as_utc(datetime.fromisoformat(str(left).replace("Z", "+00:00")))
        right_value = _as_utc(datetime.fromisoformat(str(right).replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return False
    return left_value.replace(microsecond=0) == right_value.replace(microsecond=0)


def _canary_lead_payload_valid(payload: object, *, assigned_by_id: int) -> bool:
    if not isinstance(payload, dict):
        return False
    title_prefix = "[LF-CANARY][NO CONTACT] Mail inbound "
    expected = {
        "ASSIGNED_BY_ID": assigned_by_id,
        "COMMENTS": (
            "Technical connection canary. No customer contact. "
            "Preserve this Lead as write/readback audit evidence."
        ),
        "COMPANY": "TenderBot Lead Factory",
        "EMAIL": "lf-canary@example.invalid",
        "NAME": "NO CONTACT",
        "SOURCE_DESCRIPTION": "TenderBot Mail inbound cap-one connection canary",
    }
    title = str(payload.get("TITLE", ""))
    title_timestamp = title.removeprefix(title_prefix)
    return bool(
        set(payload) == {*expected, "TITLE"}
        and title.startswith(title_prefix)
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            title_timestamp,
        )
        and all(payload.get(key) == value for key, value in expected.items())
    )


def _canary_delivery_payload_valid(
    delivery: Mapping[str, Any] | sqlite3.Row,
    *,
    assigned_by_id: int,
    origin_id: str,
) -> bool:
    operation_kind = str(delivery["operation_kind"])
    try:
        payload = json.loads(str(delivery["payload_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    if operation_kind == "OPERATOR_TODO":
        marker = f"[LF-CANARY-TODO:{origin_id}]"
        expected = {
            "description": (
                "[LF-CANARY][NO CONTACT] Technical CRM Todo canary. "
                f"Do not contact anyone. {marker}"
            ),
            "pingOffsets": [],
            "responsibleId": assigned_by_id,
            "title": "[LF-CANARY][NO CONTACT] Проверка задачи",
        }
        if set(payload) != {*expected, "deadline"} or any(
            payload.get(key) != value for key, value in expected.items()
        ):
            return False
        try:
            created_at = _as_utc(
                datetime.fromisoformat(
                    str(delivery["created_at_utc"]).replace("Z", "+00:00")
                )
            )
            deadline = _as_utc(
                datetime.fromisoformat(
                    str(payload["deadline"]).replace("Z", "+00:00")
                )
            )
        except (TypeError, ValueError):
            return False
        return 298 <= (deadline - created_at).total_seconds() <= 302
    if operation_kind == "TIMELINE_MAIL":
        marker = f"[LF-CANARY-MAIL:{origin_id}]"
        return payload == {
            "comment": (
                "[LF-CANARY][NO CONTACT] Technical timeline canary. "
                f"No customer contact. {marker}"
            ),
            "include_evidence_attachments": False,
        }
    return False


def _remote_attachment_names(value: object) -> tuple[str, ...] | None:
    if value in (None, "", [], {}):
        return ()
    entries: Iterable[object]
    if isinstance(value, dict):
        entries = value.values()
    elif isinstance(value, list):
        entries = value
    else:
        return None
    names: list[str] = []
    for entry in entries:
        raw_name: object = ""
        if isinstance(entry, dict):
            for key in ("name", "NAME", "originalName", "ORIGINAL_NAME", "FILE_NAME"):
                if entry.get(key):
                    raw_name = entry[key]
                    break
        elif isinstance(entry, (list, tuple)) and entry:
            raw_name = entry[0]
        name = Path(str(raw_name or "")).name
        if not name:
            return None
        names.append(name)
    return tuple(sorted(names, key=str.casefold))


def _bitrix_multifield_values(
    value: object,
    *,
    casefold: bool,
) -> tuple[tuple[str, str], ...] | None:
    if value in (None, ""):
        return ()
    if not isinstance(value, (list, tuple)):
        return None
    normalized: list[tuple[str, str]] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            return None
        item_value = _header(entry.get("VALUE", ""), limit=320)
        if casefold:
            item_value = item_value.casefold()
        value_type = _safe_token(entry.get("VALUE_TYPE", "WORK"), fallback="WORK")
        normalized.append((item_value, value_type))
    return tuple(sorted(normalized))


def _plain_path_stat(path: Path, *, directory: bool) -> os.stat_result:
    try:
        value = path.lstat()
    except OSError as exc:
        raise LiveMailBitrixError("live inbound storage path is unavailable") from exc
    if (
        stat.S_ISLNK(value.st_mode)
        or getattr(value, "st_file_attributes", 0) & 0x400
        or (directory and not stat.S_ISDIR(value.st_mode))
        or (not directory and not stat.S_ISREG(value.st_mode))
        or (not directory and int(value.st_nlink) != 1)
    ):
        raise LiveMailBitrixError("live inbound storage path is not a plain local path")
    return value


def _assert_plain_directory_chain(path: Path) -> tuple[tuple[int, int], ...]:
    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise LiveMailBitrixError("live inbound storage path is invalid")
    current = Path(parts[0])
    identities: list[tuple[int, int]] = []
    for part in parts[1:]:
        current /= part
        value = _plain_path_stat(current, directory=True)
        identities.append((int(value.st_dev), int(value.st_ino)))
    return tuple(identities)


def _ensure_plain_directory(path: Path) -> tuple[tuple[int, int], ...]:
    absolute = path.absolute()
    missing: list[Path] = []
    current = absolute
    while True:
        try:
            current.lstat()
        except FileNotFoundError:
            missing.append(current)
            parent = current.parent
            if parent == current:
                raise LiveMailBitrixError("live inbound storage root is unavailable")
            current = parent
            continue
        except OSError as exc:
            raise LiveMailBitrixError(
                "live inbound storage path is unavailable"
            ) from exc
        _plain_path_stat(current, directory=True)
        break
    _assert_plain_directory_chain(current)
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except OSError as exc:
            raise LiveMailBitrixError(
                "live inbound storage directory cannot be created"
            ) from exc
        _plain_path_stat(directory, directory=True)
    return _assert_plain_directory_chain(absolute)


def _assert_plain_optional_file(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LiveMailBitrixError("live inbound storage path is unavailable") from exc
    _plain_path_stat(path, directory=False)


def _assert_absent_storage_file(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LiveMailBitrixError("live inbound storage path is unavailable") from exc
    raise LiveMailBitrixError(
        "live inbound database is absent but a persisted storage file remains"
    )


def _assert_plain_existing_ancestor(path: Path) -> None:
    current = path.absolute()
    while True:
        try:
            current.lstat()
        except FileNotFoundError:
            parent = current.parent
            if parent == current:
                raise LiveMailBitrixError("live inbound storage root is unavailable")
            current = parent
            continue
        except OSError as exc:
            raise LiveMailBitrixError(
                "live inbound storage path is unavailable"
            ) from exc
        _plain_path_stat(current, directory=True)
        break
    _assert_plain_directory_chain(current)


def _durable_replace(source: Path, target: Path, *, directory: Path) -> None:
    if os.name == "nt":
        import ctypes

        move_file = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move_file.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        move_file.restype = ctypes.c_int
        movefile_replace_existing = 0x1
        movefile_write_through = 0x8
        if not move_file(
            str(source),
            str(target),
            movefile_replace_existing | movefile_write_through,
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "durable MIME evidence rename failed")
        return
    os.replace(source, target)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class LiveMailBitrixWorker:
    """One read-only mailbox consumer and one idempotent Bitrix Lead writer."""

    def __init__(
        self,
        credentials: LiveConnectionCredentialBundle,
        *,
        release_sha256: str,
        runtime_sha256: str,
        state_dir: str | os.PathLike[str] | None = None,
        imap_factory: ImapFactory | None = None,
        smtp_factory: SmtpFactory | None = None,
        http_post: HttpCallable | None = None,
        http_get: HttpCallable | None = None,
        clock: Clock | None = None,
        legacy_processed_path: str | os.PathLike[str] | None = None,
        legacy_registry_path: str | os.PathLike[str] | None = None,
        legacy_queue_path: str | os.PathLike[str] | None = None,
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(release_sha256)) or not any(
            character != "0" for character in str(release_sha256)
        ):
            raise CredentialContractError("a pinned live-inbound release is required")
        if not re.fullmatch(r"[0-9a-f]{64}", str(runtime_sha256)) or not any(
            character != "0" for character in str(runtime_sha256)
        ):
            raise CredentialContractError("a pinned live-inbound runtime is required")
        self._credentials = credentials
        self._release_sha256 = str(release_sha256)
        self._runtime_sha256 = str(runtime_sha256)
        self._state_dir = Path(state_dir) if state_dir is not None else _runtime_state_dir()
        self._db_path = self._state_dir / "live_mail_bitrix.sqlite3"
        self._evidence_dir = self._state_dir / "evidence"
        self._lock_path = self._state_dir / "worker.lock"
        self._imap_factory = imap_factory or _default_imap_factory
        self._smtp_factory = smtp_factory or _default_smtp_factory
        self._http_post = http_post or _default_http_post
        # Reserved for an injected diagnostics transport. Bitrix REST calls in
        # this worker are deliberately JSON POST only.
        self._http_get = http_get
        self._clock = clock or _utc_now
        repo_root = Path(__file__).resolve().parents[1]
        pool = repo_root / "pool"
        self._legacy_processed_path = (
            Path(legacy_processed_path) if legacy_processed_path is not None else pool / "facade_processed.json"
        )
        self._legacy_processed_path_explicit = legacy_processed_path is not None
        self._legacy_registry_path = (
            Path(legacy_registry_path) if legacy_registry_path is not None else pool / "leads_registry.json"
        )
        self._legacy_registry_path_explicit = legacy_registry_path is not None
        self._legacy_queue_path = (
            Path(legacy_queue_path) if legacy_queue_path is not None else pool / "outreach_queue.json"
        )
        self._legacy_queue_path_explicit = legacy_queue_path is not None
        self._webhook = self._validate_credentials(credentials)
        self._webhook_scope_hash = _digest(self._webhook)
        self._mailbox_scope_hash = _digest(
            "|".join(
                (
                    str(credentials.imap_host).strip().casefold(),
                    str(credentials.imap_port),
                    str(credentials.imap_user).strip().casefold(),
                    _MAILBOX,
                )
            )
        )
        self._authority_scope_hash = _digest(
            f"{self._mailbox_scope_hash}|{self._webhook_scope_hash}|"
            f"{self._release_sha256}|{self._runtime_sha256}"
        )

    def __repr__(self) -> str:
        return "<LiveMailBitrixWorker mailbox=INBOX state=local credentials=redacted>"

    @staticmethod
    def _validate_credentials(credentials: LiveConnectionCredentialBundle) -> str:
        required = {
            "imap_host": getattr(credentials, "imap_host", ""),
            "imap_user": getattr(credentials, "imap_user", ""),
            "imap_password": getattr(credentials, "imap_password", ""),
            "bitrix_webhook": getattr(credentials, "bitrix_webhook", ""),
            "smtp_host": getattr(credentials, "smtp_host", ""),
            "smtp_user": getattr(credentials, "smtp_user", ""),
            "smtp_password": getattr(credentials, "smtp_password", ""),
        }
        if any(not str(value or "").strip() for value in required.values()):
            raise CredentialContractError("required live connection credentials are unavailable")
        try:
            port = int(getattr(credentials, "imap_port", 0))
        except (TypeError, ValueError) as exc:
            raise CredentialContractError("IMAP connection settings are invalid") from exc
        if port != 993:
            raise CredentialContractError("IMAP connection settings are invalid")
        try:
            smtp_port = int(getattr(credentials, "smtp_port", 0))
        except (TypeError, ValueError) as exc:
            raise CredentialContractError("SMTP connection settings are invalid") from exc
        if smtp_port != 465:
            raise CredentialContractError("SMTP connection settings are invalid")
        host = getattr(credentials, "imap_host", "")
        if type(host) is not str or host.casefold() != "imap.mail.ru":
            raise CredentialContractError("IMAP connection settings are invalid")
        smtp_host = getattr(credentials, "smtp_host", "")
        if type(smtp_host) is not str or smtp_host.casefold() != "smtp.mail.ru":
            raise CredentialContractError("SMTP connection settings are invalid")
        raw = str(getattr(credentials, "bitrix_webhook", "")).strip()
        parsed = urlsplit(raw)
        bitrix_host = str(parsed.hostname or "").casefold()
        if (
            parsed.scheme.casefold() != "https"
            or not re.fullmatch(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+bitrix24\.ru",
                bitrix_host,
            )
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (parsed.port not in (None, 443))
            or not re.fullmatch(r"/rest/\d+/[^/\s]+/?", parsed.path)
        ):
            raise CredentialContractError("Bitrix webhook contract is invalid")
        return raw.rstrip("/") + "/"

    def _now(self) -> datetime:
        return _as_utc(self._clock())

    @staticmethod
    def _assigned_by_id_tx(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT value FROM meta WHERE key='bitrix_assigned_by_id'"
        ).fetchone()
        if row is None:
            authority = connection.execute(
                "SELECT 1 FROM scoped_authority WHERE singleton=1"
            ).fetchone()
            if authority is not None:
                raise LiveMailBitrixError("Bitrix operator assignment is unavailable")
            return BITRIX_ASSIGNED_BY_ID
        raw = str(row[0])
        if not re.fullmatch(r"[1-9]\d{0,18}", raw):
            raise LiveMailBitrixError("Bitrix operator assignment is invalid")
        return int(raw)

    def _assigned_by_id(self) -> int:
        with closing(self._connect()) as connection:
            return self._assigned_by_id_tx(connection)

    def _connect(self) -> sqlite3.Connection:
        _assert_plain_directory_chain(self._state_dir)
        for candidate in (
            self._db_path,
            Path(str(self._db_path) + "-journal"),
            Path(str(self._db_path) + "-shm"),
            Path(str(self._db_path) + "-wal"),
        ):
            _assert_plain_optional_file(candidate)
        connection = sqlite3.connect(self._db_path, timeout=5.0)
        _plain_path_stat(self._db_path, directory=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self, *, stage_delivery_outbox: bool = True) -> dict[str, Any]:
        if type(stage_delivery_outbox) is not bool:
            raise ValueError("stage_delivery_outbox must be a bool")
        _ensure_plain_directory(self._state_dir)
        _ensure_plain_directory(self._evidence_dir)
        connection = self._connect()
        try:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if not quick_check or str(quick_check[0]).casefold() != "ok":
                raise LiveMailBitrixError("live inbound database integrity check failed")
            existing_objects = _user_schema_object_names(connection)
            preexisting_schema = ""
            preexisting_contract = ""
            if existing_objects:
                if "meta" not in existing_objects:
                    raise LiveMailBitrixError(
                        "live inbound database schema metadata is unavailable"
                    )
                schema_row = connection.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()
                if schema_row is None:
                    raise LiveMailBitrixError(
                        "live inbound database schema label is unavailable"
                    )
                preexisting_schema = str(schema_row[0])
                if preexisting_schema == _SCHEMA_VERSION:
                    contract_row = connection.execute(
                        "SELECT value FROM meta WHERE key='schema_contract_sha256'"
                    ).fetchone()
                    preexisting_contract = str(contract_row[0]) if contract_row else ""
                    actual_preexisting_contract = _schema_contract_sha256(connection)
                    if (
                        existing_objects != _SCHEMA_CONTRACT_OBJECTS
                        or not re.fullmatch(r"[0-9a-f]{64}", preexisting_contract)
                        or preexisting_contract != actual_preexisting_contract
                        or actual_preexisting_contract not in _V4_SCHEMA_CONTRACT_SHA256S
                    ):
                        raise LiveMailBitrixError(
                            "live inbound database schema contract drifted"
                        )
                elif preexisting_schema == "3":
                    legacy_required = _SCHEMA_CONTRACT_OBJECTS - {
                        "crm_delivery_outbox",
                        "idx_crm_delivery_outbox_state",
                    }
                    if (
                        existing_objects != legacy_required
                        or _schema_contract_sha256(connection, legacy_required)
                        not in _LEGACY_V3_SCHEMA_CONTRACT_SHA256S
                    ):
                        raise LiveMailBitrixError(
                            "legacy live inbound database schema is incompatible"
                        )
                else:
                    raise LiveMailBitrixError(
                        "live inbound database schema is incompatible"
                    )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cursor(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    mailbox TEXT NOT NULL CHECK(mailbox='INBOX'),
                    uidvalidity TEXT NOT NULL,
                    last_uid INTEGER NOT NULL CHECK(last_uid>=0),
                    reconciliation_high_water_uid INTEGER NOT NULL DEFAULT 0
                        CHECK(reconciliation_high_water_uid>=0),
                    bootstrap_reason_hash TEXT NOT NULL,
                    bootstrapped_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scoped_authority(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    authority_version TEXT NOT NULL,
                    imap_inbox_read INTEGER NOT NULL CHECK(imap_inbox_read IN (0,1)),
                    bitrix_lead_list INTEGER NOT NULL CHECK(bitrix_lead_list IN (0,1)),
                    bitrix_lead_add INTEGER NOT NULL CHECK(bitrix_lead_add IN (0,1)),
                    bitrix_lead_get INTEGER NOT NULL CHECK(bitrix_lead_get IN (0,1)),
                    bitrix_activity_list INTEGER NOT NULL DEFAULT 0
                        CHECK(bitrix_activity_list IN (0,1)),
                    bitrix_activity_add INTEGER NOT NULL DEFAULT 0
                        CHECK(bitrix_activity_add IN (0,1)),
                    bitrix_activity_get INTEGER NOT NULL DEFAULT 0
                        CHECK(bitrix_activity_get IN (0,1)),
                    bitrix_timeline_comment_list INTEGER NOT NULL DEFAULT 0
                        CHECK(bitrix_timeline_comment_list IN (0,1)),
                    bitrix_timeline_comment_add INTEGER NOT NULL DEFAULT 0
                        CHECK(bitrix_timeline_comment_add IN (0,1)),
                    bitrix_timeline_comment_get INTEGER NOT NULL DEFAULT 0
                        CHECK(bitrix_timeline_comment_get IN (0,1)),
                    smtp_send INTEGER NOT NULL CHECK(smtp_send IN (0,1)),
                    unisender_send INTEGER NOT NULL CHECK(unisender_send IN (0,1)),
                    tenderplan_access INTEGER NOT NULL CHECK(tenderplan_access IN (0,1)),
                    confirmation_hash TEXT NOT NULL,
                    connection_scope_hash TEXT NOT NULL DEFAULT '',
                    mailbox_scope_hash TEXT NOT NULL DEFAULT '',
                    bitrix_scope_hash TEXT NOT NULL DEFAULT '',
                    release_sha256 TEXT NOT NULL DEFAULT '',
                    runtime_sha256 TEXT NOT NULL DEFAULT '',
                    authority_generation INTEGER NOT NULL DEFAULT 0
                        CHECK(authority_generation>=0),
                    authority_state TEXT NOT NULL DEFAULT 'REVOKED'
                        CHECK(authority_state IN ('ACTIVE','REVOKED')),
                    revoked_at_utc TEXT NOT NULL DEFAULT '',
                    revocation_reason_hash TEXT NOT NULL DEFAULT '',
                    revoked_by_release_sha256 TEXT NOT NULL DEFAULT '',
                    revoked_by_runtime_sha256 TEXT NOT NULL DEFAULT '',
                    authority_expires_at_utc TEXT NOT NULL DEFAULT '',
                    write_attempt_budget INTEGER NOT NULL DEFAULT 0
                        CHECK(write_attempt_budget>=0),
                    write_attempts_used INTEGER NOT NULL DEFAULT 0
                        CHECK(write_attempts_used>=0),
                    authorized_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages(
                    message_key TEXT PRIMARY KEY,
                    uidvalidity TEXT NOT NULL,
                    uid INTEGER NOT NULL CHECK(uid>0),
                    rfc822_sha256 TEXT NOT NULL,
                    rfc822_size INTEGER NOT NULL CHECK(rfc822_size>0),
                    evidence_ref TEXT NOT NULL,
                    message_id_hash TEXT NOT NULL DEFAULT '',
                    thread_key TEXT NOT NULL DEFAULT '',
                    sender_hash TEXT NOT NULL DEFAULT '',
                    route TEXT NOT NULL,
                    state TEXT NOT NULL,
                    lead_payload_json TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    UNIQUE(uidvalidity,uid),
                    UNIQUE(evidence_ref)
                );
                CREATE INDEX IF NOT EXISTS idx_messages_state ON messages(state,created_at_utc);
                CREATE INDEX IF NOT EXISTS idx_messages_mid ON messages(message_id_hash);
                CREATE TABLE IF NOT EXISTS message_deliveries(
                    uidvalidity TEXT NOT NULL,
                    uid INTEGER NOT NULL CHECK(uid>0),
                    message_key TEXT NOT NULL REFERENCES messages(message_key),
                    rfc822_sha256 TEXT NOT NULL,
                    evidence_ref TEXT NOT NULL UNIQUE,
                    observed_at_utc TEXT NOT NULL,
                    PRIMARY KEY(uidvalidity,uid)
                );
                CREATE TABLE IF NOT EXISTS legacy_message_state(
                    message_id_hash TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK(state IN ('ALREADY_HANDLED','LEGACY_UNKNOWN_REVIEW')),
                    remote_lead_id TEXT NOT NULL DEFAULT '',
                    imported_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS crm_outbox(
                    operation_id TEXT PRIMARY KEY,
                    message_key TEXT NOT NULL REFERENCES messages(message_key),
                    originator_id TEXT NOT NULL,
                    origin_id TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    phase TEXT NOT NULL DEFAULT '',
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    reconcile_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at_utc TEXT NOT NULL DEFAULT '',
                    remote_lead_id TEXT NOT NULL DEFAULT '',
                    error_class TEXT NOT NULL DEFAULT '',
                    error_digest TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    UNIQUE(message_key)
                );
                CREATE INDEX IF NOT EXISTS idx_crm_outbox_state
                    ON crm_outbox(state,next_attempt_at_utc,created_at_utc);
                CREATE TABLE IF NOT EXISTS crm_delivery_outbox(
                    delivery_id TEXT PRIMARY KEY,
                    parent_operation_id TEXT NOT NULL,
                    message_key TEXT NOT NULL,
                    operation_kind TEXT NOT NULL
                        CHECK(operation_kind IN ('OPERATOR_TODO','TIMELINE_MAIL')),
                    marker TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    phase TEXT NOT NULL DEFAULT '',
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    reconcile_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at_utc TEXT NOT NULL DEFAULT '',
                    remote_lead_id TEXT NOT NULL,
                    remote_id TEXT NOT NULL DEFAULT '',
                    error_class TEXT NOT NULL DEFAULT '',
                    error_digest TEXT NOT NULL DEFAULT '',
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    UNIQUE(parent_operation_id,operation_kind)
                );
                CREATE INDEX IF NOT EXISTS idx_crm_delivery_outbox_state
                    ON crm_delivery_outbox(state,next_attempt_at_utc,created_at_utc);
                CREATE TABLE IF NOT EXISTS runs(
                    run_id TEXT PRIMARY KEY,
                    run_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    started_at_utc TEXT NOT NULL,
                    finished_at_utc TEXT NOT NULL DEFAULT '',
                    counters_json TEXT NOT NULL DEFAULT '{}',
                    error_class TEXT NOT NULL DEFAULT '',
                    error_digest TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at_utc DESC);
                """
            )
            columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(cursor)").fetchall()
            }
            if "reconciliation_high_water_uid" not in columns:
                connection.execute(
                    "ALTER TABLE cursor ADD COLUMN reconciliation_high_water_uid INTEGER NOT NULL DEFAULT 0"
                )
            message_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(messages)").fetchall()
            }
            if "thread_key" not in message_columns:
                connection.execute(
                    "ALTER TABLE messages ADD COLUMN thread_key TEXT NOT NULL DEFAULT ''"
                )
            authority_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(scoped_authority)").fetchall()
            }
            if "connection_scope_hash" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN connection_scope_hash TEXT NOT NULL DEFAULT ''"
                )
            if "mailbox_scope_hash" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN mailbox_scope_hash TEXT NOT NULL DEFAULT ''"
                )
            if "bitrix_scope_hash" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN bitrix_scope_hash TEXT NOT NULL DEFAULT ''"
                )
            if "release_sha256" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN release_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "runtime_sha256" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN runtime_sha256 TEXT NOT NULL DEFAULT ''"
                )
            if "authority_generation" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN authority_generation "
                    "INTEGER NOT NULL DEFAULT 0 CHECK(authority_generation>=0)"
                )
            if "authority_state" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN authority_state TEXT NOT NULL "
                    "DEFAULT 'REVOKED' CHECK(authority_state IN ('ACTIVE','REVOKED'))"
                )
            if "revoked_at_utc" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN revoked_at_utc TEXT NOT NULL DEFAULT ''"
                )
            if "revocation_reason_hash" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN revocation_reason_hash "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "revoked_by_release_sha256" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN revoked_by_release_sha256 "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "revoked_by_runtime_sha256" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN revoked_by_runtime_sha256 "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "authority_expires_at_utc" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN authority_expires_at_utc "
                    "TEXT NOT NULL DEFAULT ''"
                )
            if "write_attempt_budget" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN write_attempt_budget "
                    "INTEGER NOT NULL DEFAULT 0 CHECK(write_attempt_budget>=0)"
                )
            if "write_attempts_used" not in authority_columns:
                connection.execute(
                    "ALTER TABLE scoped_authority ADD COLUMN write_attempts_used "
                    "INTEGER NOT NULL DEFAULT 0 CHECK(write_attempts_used>=0)"
                )
            projection_authority_columns = {
                "bitrix_activity_list",
                "bitrix_activity_add",
                "bitrix_activity_get",
                "bitrix_timeline_comment_list",
                "bitrix_timeline_comment_add",
                "bitrix_timeline_comment_get",
            }
            for column in sorted(projection_authority_columns - authority_columns):
                connection.execute(
                    f"ALTER TABLE scoped_authority ADD COLUMN {column} "
                    "INTEGER NOT NULL DEFAULT 0 CHECK("
                    f"{column} IN (0,1))"
                )
            connection.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)",
                (_SCHEMA_VERSION,),
            )
            actual = connection.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            if actual and str(actual[0]) == "3":
                migrated_at = _iso(self._now())
                connection.execute(
                    """UPDATE scoped_authority SET
                       authority_version='MailToBitrixInbound.v4',
                       authority_generation=CASE
                           WHEN authority_generation<1 THEN 1 ELSE authority_generation END,
                       authority_state='REVOKED',imap_inbox_read=0,bitrix_lead_list=0,
                       bitrix_lead_add=0,bitrix_lead_get=0,smtp_send=0,unisender_send=0,
                       bitrix_activity_list=0,bitrix_activity_add=0,bitrix_activity_get=0,
                       bitrix_timeline_comment_list=0,bitrix_timeline_comment_add=0,
                       bitrix_timeline_comment_get=0,
                       tenderplan_access=0,revoked_at_utc=?,revocation_reason_hash=?,
                       revoked_by_release_sha256='',revoked_by_runtime_sha256=''""",
                    (migrated_at, _digest("schema_v3_reauthorization_required")),
                )
                connection.execute(
                    "DELETE FROM meta WHERE key IN ("
                    "'bitrix_write_verified','bitrix_canary_authority_generation',"
                    "'bitrix_canary_runtime_sha256')"
                )
                if connection.execute(
                    "SELECT 1 FROM scoped_authority WHERE singleton=1"
                ).fetchone():
                    connection.execute(
                        """INSERT INTO meta(key,value) VALUES('bitrix_canary_state','REVOKED')
                           ON CONFLICT(key) DO UPDATE SET value='REVOKED'"""
                    )
                connection.execute(
                    "UPDATE meta SET value=? WHERE key='schema_version'",
                    (_SCHEMA_VERSION,),
                )
                actual = (_SCHEMA_VERSION,)
            if not actual or actual[0] != _SCHEMA_VERSION:
                raise LiveMailBitrixError("live inbound database schema is incompatible")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise LiveMailBitrixError(
                    "live inbound database relationships are inconsistent"
                )
            missing_parent = connection.execute(
                """SELECT m.message_key FROM messages AS m
                   LEFT JOIN crm_outbox AS o ON o.message_key=m.message_key
                   WHERE m.state IN (
                       'OUTBOX_PENDING','CRM_REVIEW_PENDING','CRM_CREATED','CRM_READY'
                   ) AND o.operation_id IS NULL
                   LIMIT 1"""
            ).fetchone()
            if missing_parent is not None:
                raise LiveMailBitrixError(
                    "persisted mailbox projection has no Lead parent"
                )
            orphan_delivery = connection.execute(
                """SELECT d.delivery_id FROM crm_delivery_outbox AS d
                   LEFT JOIN crm_outbox AS o
                     ON o.operation_id=d.parent_operation_id
                   LEFT JOIN messages AS m ON m.message_key=d.message_key
                   WHERE d.message_key LIKE 'mail_%' AND (
                       o.operation_id IS NULL OR m.message_key IS NULL
                       OR d.message_key<>o.message_key
                       OR d.remote_lead_id<>o.remote_lead_id
                   )
                   LIMIT 1"""
            ).fetchone()
            if orphan_delivery is not None:
                raise LiveMailBitrixError(
                    "persisted CRM delivery relationships are inconsistent"
                )
            persisted_leads = connection.execute(
                """SELECT o.*,m.route AS persisted_route,
                           m.state AS persisted_message_state,
                           m.lead_payload_json AS persisted_message_payload_json
                   FROM crm_outbox AS o
                   JOIN messages AS m ON m.message_key=o.message_key
                   ORDER BY o.created_at_utc,o.operation_id"""
            ).fetchall()
            assignment_row = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_assigned_by_id'"
            ).fetchone()
            try:
                completed_assignee = (
                    self._assigned_by_id_tx(connection)
                    if assignment_row is not None
                    else None
                )
            except LiveMailBitrixError:
                # Health must remain observable so an operator can repair a
                # corrupted assignment seal.  All write paths still fail
                # closed because the assignee and canary cannot validate.
                completed_assignee = None
            legacy_migration = preexisting_schema == "3"
            for persisted_lead in persisted_leads:
                parent = dict(persisted_lead)
                parent_state = str(parent.get("state", ""))
                parent_phase = str(parent.get("phase", ""))
                message_state = str(parent.get("persisted_message_state", ""))
                remote_lead_id = str(parent.get("remote_lead_id", ""))
                message_key = str(parent.get("message_key", ""))
                canonical_origin_id = (
                    "mail_" + _digest(message_key)[:56]
                    if re.fullmatch(r"mail_[0-9a-f]{64}", message_key)
                    else ""
                )
                if (
                    str(parent.get("originator_id", "")) != ORIGINATOR_ID
                    or str(parent.get("origin_id", "")) != canonical_origin_id
                ):
                    raise LiveMailBitrixError(
                        "persisted Lead origin identity requires manual review"
                    )
                terminal_parent = parent_state in {"CREATED", "RECONCILED"}
                valid_remote_lead_id = bool(
                    re.fullmatch(r"\d{1,20}", remote_lead_id)
                )
                if remote_lead_id and not valid_remote_lead_id:
                    raise LiveMailBitrixError(
                        "persisted Lead remote identity is invalid"
                    )
                if terminal_parent and not valid_remote_lead_id:
                    raise LiveMailBitrixError(
                        "persisted terminal Lead has no verified remote identity"
                    )
                if terminal_parent and parent_phase != "READBACK_VERIFIED":
                    raise LiveMailBitrixError(
                        "persisted terminal Lead has no durable readback proof"
                    )
                if parent_state in {"PENDING", "RETRYABLE"} and (
                    remote_lead_id or parent_phase == "CREATE_DISPATCH"
                ):
                    raise LiveMailBitrixError(
                        "persisted pending Lead has an ambiguous remote identity"
                    )
                if (
                    parent_state == "UNCERTAIN"
                    and remote_lead_id
                    and parent_phase != "CREATE_DISPATCH"
                ):
                    raise LiveMailBitrixError(
                        "persisted uncertain Lead identity has an invalid phase"
                    )
                terminal_message = message_state in {"CRM_CREATED", "CRM_READY"}
                if terminal_parent != terminal_message:
                    raise LiveMailBitrixError(
                        "persisted Lead and mailbox states are inconsistent"
                    )
                try:
                    lead_payload = json.loads(str(parent["payload_json"]))
                    message_payload = json.loads(
                        str(parent["persisted_message_payload_json"])
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise LiveMailBitrixError("persisted Lead payload is invalid") from exc
                if (
                    not isinstance(lead_payload, dict)
                    or not isinstance(message_payload, dict)
                    or str(parent["payload_json"])
                    != str(parent["persisted_message_payload_json"])
                    or lead_payload != message_payload
                ):
                    raise LiveMailBitrixError(
                        "persisted Lead payload copies are inconsistent"
                    )
                route = _safe_token(parent.get("persisted_route", ""), fallback="MAIL")
                if route not in _CRM_LEAD_ROUTES:
                    raise LiveMailBitrixError(
                        "persisted Lead mailbox route is unsupported"
                    )
                expected_action = _operator_action_for_route(route)
                payload_route = _safe_token(
                    lead_payload.get("LF_ROUTE", ""), fallback=""
                )
                payload_action = _safe_token(
                    lead_payload.get("OPERATOR_ACTION", ""), fallback=""
                )
                changed = False
                if legacy_migration:
                    if not payload_route and not payload_action:
                        lead_payload["LF_ROUTE"] = route
                        lead_payload["OPERATOR_ACTION"] = expected_action
                        changed = True
                    elif payload_route != route or payload_action != expected_action:
                        raise LiveMailBitrixError(
                            "legacy Lead route/action requires manual review"
                        )
                    if route == "FACADE_AUTO":
                        facade_projection = {
                            "SOURCE_DESCRIPTION": "Mail.ru inbound: Facade.ru",
                            "SOURCE_ID": "FASAD_RU",
                        }
                        if any(
                            lead_payload.get(key) != value
                            for key, value in facade_projection.items()
                        ):
                            lead_payload.update(facade_projection)
                            changed = True
                elif payload_route != route or payload_action != expected_action:
                    raise LiveMailBitrixError(
                        "persisted Lead route projection conflicts with mailbox routing"
                    )
                if not terminal_message:
                    expected_message_state = (
                        "OUTBOX_PENDING"
                        if expected_action == "CALL"
                        else "CRM_REVIEW_PENDING"
                    )
                    if message_state != expected_message_state:
                        raise LiveMailBitrixError(
                            "persisted Lead action conflicts with mailbox state"
                        )
                completed = terminal_parent and valid_remote_lead_id
                if (
                    completed
                    and completed_assignee is not None
                    and not re.fullmatch(
                        r"[1-9]\d{0,19}",
                        str(lead_payload.get("ASSIGNED_BY_ID", "")),
                    )
                ):
                    lead_payload["ASSIGNED_BY_ID"] = completed_assignee
                    changed = True
                if changed:
                    payload_json = json.dumps(
                        lead_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        "UPDATE crm_outbox SET payload_json=? WHERE operation_id=?",
                        (payload_json, parent["operation_id"]),
                    )
                    connection.execute(
                        "UPDATE messages SET lead_payload_json=? WHERE message_key=?",
                        (payload_json, parent["message_key"]),
                    )
                    parent["payload_json"] = payload_json
                if stage_delivery_outbox and completed and completed_assignee is not None:
                    self._stage_delivery_outbox_tx(connection, parent)
            invalid_delivery = connection.execute(
                """SELECT d.delivery_id FROM crm_delivery_outbox AS d
                   JOIN crm_outbox AS o ON o.operation_id=d.parent_operation_id
                   WHERE o.state NOT IN ('CREATED','RECONCILED')
                      OR d.remote_lead_id NOT GLOB '[0-9]*'
                      OR d.remote_lead_id GLOB '*[^0-9]*'
                      OR length(d.remote_lead_id)<1 OR length(d.remote_lead_id)>20
                      OR (d.remote_id<>'' AND (
                          d.remote_id NOT GLOB '[0-9]*'
                          OR d.remote_id GLOB '*[^0-9]*'
                          OR length(d.remote_id)>20
                      ))
                      OR (d.state IN ('CREATED','RECONCILED') AND (
                          d.remote_id='' OR d.phase<>'READBACK_VERIFIED'
                      ))
                      OR (d.state IN ('PENDING','RETRYABLE') AND (
                          d.remote_id<>'' OR d.phase='CREATE_DISPATCH'
                      ))
                      OR (d.state='UNCERTAIN' AND d.remote_id<>''
                          AND d.phase<>'CREATE_DISPATCH')
                   LIMIT 1"""
            ).fetchone()
            if invalid_delivery is not None:
                raise LiveMailBitrixError(
                    "persisted CRM delivery state is inconsistent"
                )
            invalid_canary_delivery = connection.execute(
                """SELECT delivery_id FROM crm_delivery_outbox
                   WHERE message_key NOT LIKE 'mail_%' AND (
                       message_key NOT LIKE 'canary_%'
                       OR parent_operation_id NOT LIKE 'canary:%'
                       OR remote_lead_id NOT GLOB '[0-9]*'
                       OR remote_lead_id GLOB '*[^0-9]*'
                       OR length(remote_lead_id)<1 OR length(remote_lead_id)>20
                       OR (remote_id<>'' AND (
                           remote_id NOT GLOB '[0-9]*'
                           OR remote_id GLOB '*[^0-9]*'
                           OR length(remote_id)>20
                       ))
                       OR (state IN ('CREATED','RECONCILED') AND (
                           remote_id='' OR phase<>'READBACK_VERIFIED'
                       ))
                       OR (state IN ('PENDING','RETRYABLE') AND (
                           remote_id<>'' OR phase='CREATE_DISPATCH'
                       ))
                       OR (state='UNCERTAIN' AND remote_id<>''
                           AND phase<>'CREATE_DISPATCH')
                   )
                   LIMIT 1"""
            ).fetchone()
            if invalid_canary_delivery is not None:
                raise LiveMailBitrixError(
                    "persisted canary delivery state is inconsistent"
                )
            invalid_ready_message = connection.execute(
                """SELECT m.message_key FROM messages AS m
                   JOIN crm_outbox AS o ON o.message_key=m.message_key
                   LEFT JOIN crm_delivery_outbox AS d
                     ON d.parent_operation_id=o.operation_id
                   WHERE m.state='CRM_READY'
                   GROUP BY m.message_key
                   HAVING COUNT(d.delivery_id)<>2 OR SUM(
                        CASE WHEN d.state IN ('CREATED','RECONCILED')
                                  AND d.phase='READBACK_VERIFIED'
                             THEN 1 ELSE 0 END
                   )<>2 OR COUNT(DISTINCT CASE
                       WHEN d.operation_kind IN ('OPERATOR_TODO','TIMELINE_MAIL')
                       THEN d.operation_kind END
                   )<>2
                   LIMIT 1"""
            ).fetchone()
            if invalid_ready_message is not None:
                raise LiveMailBitrixError(
                    "persisted ready mailbox projection is incomplete"
                )
            present_contract_objects = _user_schema_object_names(connection)
            if present_contract_objects != _SCHEMA_CONTRACT_OBJECTS:
                raise LiveMailBitrixError("live inbound database schema is incomplete")
            actual_contract = _schema_contract_sha256(connection)
            if actual_contract not in _V4_SCHEMA_CONTRACT_SHA256S:
                raise LiveMailBitrixError(
                    "live inbound database schema does not match an approved V4 contract"
                )
            if preexisting_schema == _SCHEMA_VERSION:
                if actual_contract != preexisting_contract:
                    raise LiveMailBitrixError(
                        "live inbound database schema changed during initialization"
                    )
            else:
                connection.execute(
                    "INSERT INTO meta(key,value) VALUES('schema_contract_sha256',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (actual_contract,),
                )
            connection.commit()
        finally:
            connection.close()
        if os.name != "nt":
            try:
                os.chmod(self._state_dir, 0o700)
                os.chmod(self._db_path, 0o600)
            except OSError:
                pass
        return {"ok": True, "status": "ready", "schema_version": int(_SCHEMA_VERSION)}

    def _authority_valid_tx(
        self,
        connection: sqlite3.Connection,
        *,
        expected_generation: int | None = None,
        observed_at: datetime | None = None,
    ) -> bool:
        row = connection.execute("SELECT * FROM scoped_authority WHERE singleton=1").fetchone()
        fence_row = connection.execute(
            "SELECT value FROM meta WHERE key='authority_time_fence'"
        ).fetchone()
        now = _as_utc(observed_at) if observed_at is not None else self._now()
        try:
            generation = int(row["authority_generation"])
            expires_at = _as_utc(datetime.fromisoformat(str(row["authority_expires_at_utc"])))
            fence = json.loads(str(fence_row[0]))
            max_observed = _as_utc(
                datetime.fromisoformat(
                    str(fence["max_observed_at_utc"]).replace("Z", "+00:00")
                )
            )
            valid_fence = bool(
                isinstance(fence, dict)
                and set(fence) == {"authority_generation", "max_observed_at_utc"}
                and type(fence.get("authority_generation")) is int
                and int(fence["authority_generation"]) == generation
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            generation = 0
            expires_at = now
            fence = {}
            max_observed = now
            valid_fence = False
        if row is not None and str(row["authority_state"]) == "ACTIVE":
            if not valid_fence or now < max_observed or now >= expires_at:
                observed = max(now, max_observed)
                connection.execute(
                    """UPDATE scoped_authority SET authority_state='REVOKED',
                       imap_inbox_read=0,bitrix_lead_list=0,bitrix_lead_add=0,
                       bitrix_lead_get=0,bitrix_activity_list=0,
                       bitrix_activity_add=0,bitrix_activity_get=0,
                       bitrix_timeline_comment_list=0,
                       bitrix_timeline_comment_add=0,
                       bitrix_timeline_comment_get=0,revoked_at_utc=?,
                       revocation_reason_hash=?,revoked_by_release_sha256=?,
                       revoked_by_runtime_sha256=? WHERE singleton=1""",
                    (
                        _iso(observed),
                        _digest("authority_time_fence"),
                        self._release_sha256,
                        self._runtime_sha256,
                    ),
                )
                _advance_authority_revocation_fence_tx(connection)
                _invalidate_canary_tx(connection, state="REVOKED")
                return False
            fence_value = json.dumps(
                {
                    "authority_generation": generation,
                    "max_observed_at_utc": _iso(max(now, max_observed)),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                "UPDATE meta SET value=? WHERE key='authority_time_fence'",
                (fence_value,),
            )
        return bool(
            row
            and valid_fence
            and now >= max_observed
            and str(row["authority_version"]) == "MailToBitrixInbound.v4"
            and str(row["authority_state"]) == "ACTIVE"
            and generation > 0
            and (
                expected_generation is None
                or generation == expected_generation
            )
            and str(row["revoked_at_utc"]) == ""
            and str(row["revocation_reason_hash"]) == ""
            and int(row["imap_inbox_read"]) == 1
            and int(row["bitrix_lead_list"]) == 1
            and int(row["bitrix_lead_add"]) == 1
            and int(row["bitrix_lead_get"]) == 1
            and int(row["bitrix_activity_list"]) == 1
            and int(row["bitrix_activity_add"]) == 1
            and int(row["bitrix_activity_get"]) == 1
            and int(row["bitrix_timeline_comment_list"]) == 1
            and int(row["bitrix_timeline_comment_add"]) == 1
            and int(row["bitrix_timeline_comment_get"]) == 1
            and int(row["smtp_send"]) == 0
            and int(row["unisender_send"]) == 0
            and int(row["tenderplan_access"]) == 0
            and str(row["connection_scope_hash"]) == self._authority_scope_hash
            and str(row["mailbox_scope_hash"]) == self._mailbox_scope_hash
            and str(row["bitrix_scope_hash"]) == self._webhook_scope_hash
            and str(row["release_sha256"]) == self._release_sha256
            and str(row["runtime_sha256"]) == self._runtime_sha256
            and str(row["confirmation_hash"]) == _digest(OWNER_AUTHORITY_CONFIRMATION)
            and expires_at > now
            and 0 <= int(row["write_attempts_used"]) <= int(row["write_attempt_budget"])
            and MIN_WRITE_BUDGET <= int(row["write_attempt_budget"]) <= MAX_WRITE_BUDGET
        )

    def _observe_authority_time(self) -> datetime:
        now = self._now()
        with self._transaction() as connection:
            self._authority_valid_tx(connection, observed_at=now)
        return now

    def _require_authority(self) -> int:
        now = self._now()
        with self._transaction() as connection:
            valid = self._authority_valid_tx(connection, observed_at=now)
            row = connection.execute(
                "SELECT authority_generation FROM scoped_authority WHERE singleton=1"
            ).fetchone()
        if not valid:
            raise LiveMailBitrixError("scoped Mail-to-Bitrix owner authority is unavailable")
        return int(row["authority_generation"])

    def _remaining_write_attempts_tx(self, connection: sqlite3.Connection) -> int:
        if not self._authority_valid_tx(connection):
            return 0
        row = connection.execute(
            "SELECT write_attempt_budget,write_attempts_used "
            "FROM scoped_authority WHERE singleton=1"
        ).fetchone()
        if not row:
            return 0
        return max(0, int(row["write_attempt_budget"]) - int(row["write_attempts_used"]))

    def _consume_write_attempt_tx(
        self,
        connection: sqlite3.Connection,
        *,
        expected_generation: int,
    ) -> None:
        """Consume one permit inside the caller's durable dispatch transaction."""

        if not self._authority_valid_tx(
            connection,
            expected_generation=expected_generation,
        ):
            # A clock-fence failure revokes authority inside the current
            # transaction.  Preserve that fail-closed transition before the
            # permit error unwinds the caller's transaction context.
            connection.commit()
            raise BitrixWriteBudgetExhausted("Bitrix write permit is unavailable")
        updated = connection.execute(
            """UPDATE scoped_authority
               SET write_attempts_used=write_attempts_used+1
               WHERE singleton=1 AND authority_state='ACTIVE'
                 AND authority_generation=?
                 AND write_attempts_used<write_attempt_budget""",
            (expected_generation,),
        )
        if updated.rowcount != 1:
            raise BitrixWriteBudgetExhausted("Bitrix write permit is exhausted")

    def _consume_write_attempt(self, *, expected_generation: int) -> None:
        with self._transaction() as connection:
            self._consume_write_attempt_tx(
                connection,
                expected_generation=expected_generation,
            )

    def _canary_seal_valid_tx(
        self,
        connection: sqlite3.Connection,
        *,
        authority_generation: int,
        assigned_by_id: int,
    ) -> bool:
        values = {
            str(row["key"]): str(row["value"])
            for row in connection.execute(
                """SELECT key,value FROM meta WHERE key IN (
                   'bitrix_write_verified','bitrix_canary_state',
                   'bitrix_canary_webhook_scope_hash','bitrix_canary_release_sha256',
                   'bitrix_canary_runtime_sha256','bitrix_canary_authority_generation',
                   'bitrix_canary_assigned_by_id','bitrix_canary_origin_id',
                   'bitrix_canary_remote_id','bitrix_canary_lead_payload_json',
                   'bitrix_canary_origin_authority_generation')"""
            ).fetchall()
        }
        origin_id = values.get("bitrix_canary_origin_id", "")
        remote_lead_id = values.get("bitrix_canary_remote_id", "")
        if (
            values.get("bitrix_write_verified") != "1"
            or values.get("bitrix_canary_state") != "VERIFIED"
            or values.get("bitrix_canary_webhook_scope_hash")
            != self._webhook_scope_hash
            or values.get("bitrix_canary_release_sha256") != self._release_sha256
            or values.get("bitrix_canary_runtime_sha256") != self._runtime_sha256
            or values.get("bitrix_canary_authority_generation")
            != str(authority_generation)
            or values.get("bitrix_canary_assigned_by_id") != str(assigned_by_id)
            or values.get("bitrix_canary_origin_authority_generation")
            != str(authority_generation)
            or not re.fullmatch(r"lf_canary_[0-9a-f]{48}", origin_id)
            or not re.fullmatch(r"\d{1,20}", remote_lead_id)
        ):
            return False
        try:
            lead_payload = json.loads(values.get("bitrix_canary_lead_payload_json", ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not _canary_lead_payload_valid(
            lead_payload,
            assigned_by_id=assigned_by_id,
        ):
            return False
        parent_operation_id = (
            f"canary:{authority_generation}:{_digest(origin_id)[:32]}"
        )
        message_key = f"canary_{_digest(parent_operation_id)}"
        rows = connection.execute(
            """SELECT * FROM crm_delivery_outbox
               WHERE parent_operation_id=? OR message_key=?
               ORDER BY operation_kind""",
            (parent_operation_id, message_key),
        ).fetchall()
        if (
            len(rows) != 2
            or {str(row["operation_kind"]) for row in rows}
            != {"OPERATOR_TODO", "TIMELINE_MAIL"}
        ):
            return False
        for row in rows:
            operation_kind = str(row["operation_kind"])
            expected_marker = (
                f"[LF-CANARY-TODO:{origin_id}]"
                if operation_kind == "OPERATOR_TODO"
                else f"[LF-CANARY-MAIL:{origin_id}]"
            )
            expected_delivery_id = (
                "delivery_"
                + _digest(f"{parent_operation_id}|{operation_kind}")[:55]
            )
            if (
                str(row["delivery_id"]) != expected_delivery_id
                or str(row["parent_operation_id"]) != parent_operation_id
                or str(row["message_key"]) != message_key
                or str(row["marker"]) != expected_marker
                or str(row["remote_lead_id"]) != remote_lead_id
                or str(row["state"]) not in {"CREATED", "RECONCILED"}
                or str(row["phase"]) != "READBACK_VERIFIED"
                or not re.fullmatch(r"\d{1,20}", str(row["remote_id"]))
                or not _canary_delivery_payload_valid(
                    row,
                    assigned_by_id=assigned_by_id,
                    origin_id=origin_id,
                )
            ):
                return False
        return True

    def _require_verified_canary(self, authority_generation: int) -> None:
        with closing(self._connect()) as connection:
            assigned_by_id = self._assigned_by_id_tx(connection)
            valid = self._canary_seal_valid_tx(
                connection,
                authority_generation=authority_generation,
                assigned_by_id=assigned_by_id,
            )
        if not valid:
            raise BitrixWriteNotVerified("Bitrix cap-one write/readback canary is required")

    def _start_run(self, run_type: str) -> str:
        run_id = "run_" + uuid.uuid4().hex
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO runs(run_id,run_type,state,started_at_utc) VALUES(?,?,?,?)",
                (run_id, _safe_token(run_type), "RUNNING", _iso(self._now())),
            )
        return run_id

    def _finish_run(
        self,
        run_id: str,
        *,
        state: str,
        counters: Mapping[str, Any] | None = None,
        error: BaseException | None = None,
    ) -> None:
        error_class = _safe_token(type(error).__name__, fallback="") if error else ""
        error_digest = _digest(error_class) if error_class else ""
        safe_counters = {
            _safe_token(key).casefold(): int(value)
            for key, value in (counters or {}).items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        with self._transaction() as connection:
            connection.execute(
                """UPDATE runs SET state=?,finished_at_utc=?,counters_json=?,
                   error_class=?,error_digest=? WHERE run_id=?""",
                (
                    _safe_token(state),
                    _iso(self._now()),
                    json.dumps(safe_counters, sort_keys=True, separators=(",", ":")),
                    error_class,
                    error_digest,
                    run_id,
                ),
            )

    def _import_legacy_state(
        self,
        connection: sqlite3.Connection,
        processed_snapshot: _StableJsonSnapshot,
        registry_snapshot: _StableJsonSnapshot,
        *,
        processed_path: Path,
        registry_path: Path,
    ) -> dict[str, int]:
        processed_doc = processed_snapshot.document
        registry_doc = registry_snapshot.document
        if processed_snapshot.present and (
            not isinstance(processed_doc, dict)
            or not isinstance(processed_doc.get("ids"), list)
            or len(processed_doc["ids"]) > 500_000
        ):
            raise LiveMailBitrixError("legacy processed snapshot is invalid")
        if registry_snapshot.present and (
            not isinstance(registry_doc, dict)
            or not isinstance(registry_doc.get("leads"), list)
            or len(registry_doc["leads"]) > 100_000
        ):
            raise LiveMailBitrixError("legacy registry snapshot is invalid")
        processed_values = processed_doc.get("ids", []) if processed_snapshot.present else []
        leads = registry_doc.get("leads", []) if registry_snapshot.present else []
        contract_row = connection.execute(
            "SELECT value FROM meta WHERE key='legacy_source_contract'"
        ).fetchone()
        processed_path_hash = _digest(
            str(processed_path.resolve(strict=False)).casefold()
        )
        registry_path_hash = _digest(
            str(registry_path.resolve(strict=False)).casefold()
        )
        if contract_row is not None:
            try:
                contract = json.loads(str(contract_row[0]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LiveMailBitrixError("legacy source contract is invalid") from exc
            if (
                not isinstance(contract, dict)
                or set(contract)
                != {
                    "format",
                    "mapping_sha256",
                    "processed_path_sha256",
                    "processed_presence_required",
                    "record_count",
                    "registry_path_sha256",
                    "registry_presence_required",
                }
                or contract.get("format") != "TenderBot.LegacySource.v1"
                or contract.get("processed_path_sha256") != processed_path_hash
                or contract.get("registry_path_sha256") != registry_path_hash
                or type(contract.get("processed_presence_required")) is not bool
                or type(contract.get("registry_presence_required")) is not bool
                or type(contract.get("record_count")) is not int
                or int(contract.get("record_count", -1)) < 0
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("mapping_sha256", "")),
                )
            ):
                raise LiveMailBitrixError("legacy source contract is invalid")
            self._verify_legacy_mapping_tx(connection, contract=contract)
            if contract["processed_presence_required"] and not processed_snapshot.present:
                raise LiveMailBitrixError("bound legacy processed snapshot is unavailable")
            if contract["registry_presence_required"] and not registry_snapshot.present:
                raise LiveMailBitrixError("bound legacy registry snapshot is unavailable")
        else:
            contract = {
                "format": "TenderBot.LegacySource.v1",
                "mapping_sha256": "",
                "processed_path_sha256": processed_path_hash,
                "processed_presence_required": processed_snapshot.present,
                "record_count": 0,
                "registry_path_sha256": registry_path_hash,
                "registry_presence_required": registry_snapshot.present,
            }
        if processed_snapshot.present:
            contract["processed_presence_required"] = True
        if registry_snapshot.present:
            contract["registry_presence_required"] = True
        mappings: dict[str, list[str]] = {}
        for lead in leads:
            if not isinstance(lead, dict):
                raise LiveMailBitrixError("legacy registry snapshot is invalid")
            remote_id = str(lead.get("lead_id", "") or "").strip()
            if not re.fullmatch(r"\d{1,20}", remote_id):
                raise LiveMailBitrixError("legacy registry snapshot is invalid")
            ids = lead.get("thread_msgids") or []
            if not isinstance(ids, list) or len(ids) > 1_000:
                raise LiveMailBitrixError("legacy registry snapshot is invalid")
            for raw_id in ids:
                if type(raw_id) is not str:
                    raise LiveMailBitrixError("legacy registry snapshot is invalid")
                message_id = _canonical_message_id(raw_id)
                if not message_id:
                    raise LiveMailBitrixError("legacy registry snapshot is invalid")
                mappings.setdefault(message_id, []).append(remote_id)
        now = _iso(self._now())
        counts = {"already_handled": 0, "legacy_unknown_review": 0}
        processed_ids: set[str] = set()
        for raw_id in processed_values:
            if type(raw_id) is not str:
                raise LiveMailBitrixError("legacy processed snapshot is invalid")
            message_id = _canonical_message_id(raw_id)
            if not message_id:
                raise LiveMailBitrixError("legacy processed snapshot is invalid")
            processed_ids.add(message_id)
        for message_id in sorted(processed_ids):
            candidates = sorted(set(mappings.get(message_id, [])))
            state = "ALREADY_HANDLED" if len(candidates) == 1 else "LEGACY_UNKNOWN_REVIEW"
            remote_id = candidates[0] if len(candidates) == 1 else ""
            existing = connection.execute(
                """SELECT state,remote_lead_id FROM legacy_message_state
                   WHERE message_id_hash=?""",
                (_digest(message_id),),
            ).fetchone()
            if existing is not None and (
                str(existing["state"]) != state
                or str(existing["remote_lead_id"]) != remote_id
            ):
                raise LiveMailBitrixError(
                    "legacy message identity conflicts with protected state"
                )
            connection.execute(
                """INSERT INTO legacy_message_state(
                       message_id_hash,state,remote_lead_id,imported_at_utc
                   ) VALUES(?,?,?,?) ON CONFLICT(message_id_hash) DO NOTHING""",
                (_digest(message_id), state, remote_id, now),
            )
            counts[state.casefold()] += 1
        rows = [
            {
                "message_id_hash": str(row["message_id_hash"]),
                "remote_lead_id": str(row["remote_lead_id"]),
                "state": str(row["state"]),
            }
            for row in connection.execute(
                """SELECT message_id_hash,state,remote_lead_id
                   FROM legacy_message_state ORDER BY message_id_hash"""
            ).fetchall()
        ]
        serialized = json.dumps(
            rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        contract["mapping_sha256"] = _digest(serialized)
        contract["record_count"] = len(rows)
        connection.execute(
            """INSERT INTO meta(key,value) VALUES('legacy_source_contract',?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (
                json.dumps(
                    contract,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        return counts

    @staticmethod
    def _verify_legacy_mapping_tx(
        connection: sqlite3.Connection,
        *,
        contract: Mapping[str, Any],
    ) -> None:
        rows = [
            {
                "message_id_hash": str(row["message_id_hash"]),
                "remote_lead_id": str(row["remote_lead_id"]),
                "state": str(row["state"]),
            }
            for row in connection.execute(
                """SELECT message_id_hash,state,remote_lead_id
                   FROM legacy_message_state ORDER BY message_id_hash"""
            ).fetchall()
        ]
        serialized = json.dumps(
            rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if (
            int(contract.get("record_count", -1)) != len(rows)
            or contract.get("mapping_sha256") != _digest(serialized)
        ):
            raise LiveMailBitrixError("protected legacy mapping seal is invalid")

    def _verify_protected_legacy_mapping(self) -> None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key='legacy_source_contract'"
            ).fetchone()
            if row is None:
                raise BootstrapRequired(
                    "legacy sources must be imported by an explicit bootstrap"
                )
            try:
                contract = json.loads(str(row[0]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LiveMailBitrixError("legacy source contract is invalid") from exc
            if (
                not isinstance(contract, dict)
                or set(contract)
                != {
                    "format",
                    "mapping_sha256",
                    "processed_path_sha256",
                    "processed_presence_required",
                    "record_count",
                    "registry_path_sha256",
                    "registry_presence_required",
                }
                or contract.get("format") != "TenderBot.LegacySource.v1"
                or type(contract.get("processed_presence_required")) is not bool
                or type(contract.get("registry_presence_required")) is not bool
                or type(contract.get("record_count")) is not int
                or int(contract.get("record_count", -1)) < 0
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("mapping_sha256", "")),
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("processed_path_sha256", "")),
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("registry_path_sha256", "")),
                )
            ):
                raise LiveMailBitrixError("legacy source contract is invalid")
            self._verify_legacy_mapping_tx(connection, contract=contract)

    def _rebind_safe_pending_assignee_tx(
        self,
        connection: sqlite3.Connection,
        assigned_by_id: int,
    ) -> int:
        try:
            current_assignee: int | None = self._assigned_by_id_tx(connection)
        except LiveMailBitrixError:
            current_assignee = None
        if current_assignee != assigned_by_id:
            ambiguous = connection.execute(
                """SELECT COUNT(*) FROM crm_outbox
                   WHERE state NOT IN ('CREATED','RECONCILED')
                     AND (state='UNCERTAIN' OR phase='CREATE_DISPATCH'
                          OR remote_lead_id<>'')"""
            ).fetchone()[0]
            if int(ambiguous):
                raise LiveMailBitrixError(
                    "Bitrix assignee cannot change while a Lead create is unresolved"
                )
            pending_todos = connection.execute(
                """SELECT COUNT(*) FROM crm_delivery_outbox
                   WHERE operation_kind='OPERATOR_TODO'
                     AND message_key LIKE 'mail_%'
                     AND state NOT IN ('CREATED','RECONCILED')"""
            ).fetchone()[0]
            if int(pending_todos):
                raise LiveMailBitrixError(
                    "Bitrix assignee cannot change while an operator Todo is unresolved"
                )
        rows = connection.execute(
            """SELECT o.operation_id,o.message_key,o.payload_json
               FROM crm_outbox AS o
               WHERE o.remote_lead_id=''
                 AND o.state IN ('PENDING','RETRYABLE')
                 AND o.phase<>'CREATE_DISPATCH'
               ORDER BY o.operation_id"""
        ).fetchall()
        rebound = 0
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LiveMailBitrixError(
                    "pending Lead payload cannot bind the Bitrix assignee"
                ) from exc
            if not isinstance(payload, dict):
                raise LiveMailBitrixError(
                    "pending Lead payload cannot bind the Bitrix assignee"
                )
            if str(payload.get("ASSIGNED_BY_ID", "")) == str(assigned_by_id):
                continue
            payload["ASSIGNED_BY_ID"] = assigned_by_id
            payload_json = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                "UPDATE crm_outbox SET payload_json=? WHERE operation_id=?",
                (payload_json, row["operation_id"]),
            )
            connection.execute(
                "UPDATE messages SET lead_payload_json=? WHERE message_key=?",
                (payload_json, row["message_key"]),
            )
            rebound += 1
        return rebound

    def _bind_campaign_snapshot_tx(
        self,
        connection: sqlite3.Connection,
        snapshot: _CampaignSnapshot,
        *,
        allow_create: bool,
        source_path: Path,
    ) -> None:
        key = "campaign_source_contract"
        path_scope_sha256 = _digest(
            str(source_path.resolve(strict=False)).casefold()
        )
        row = connection.execute(
            "SELECT value FROM meta WHERE key=?",
            (key,),
        ).fetchone()
        if row is None:
            if not allow_create:
                raise BootstrapRequired(
                    "campaign source must be bound by an explicit bootstrap"
                )
            contract = {
                "format": "TenderBot.CampaignSource.v1",
                "mapping_sha256": "",
                "path_scope_sha256": path_scope_sha256,
                "presence_required": snapshot.present,
                "record_count": 0,
            }
        else:
            try:
                contract = json.loads(str(row[0]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LiveMailBitrixError("campaign source contract is invalid") from exc
            if (
                not isinstance(contract, dict)
                or set(contract)
                != {
                    "format",
                    "mapping_sha256",
                    "path_scope_sha256",
                    "presence_required",
                    "record_count",
                }
                or contract.get("format") != "TenderBot.CampaignSource.v1"
                or contract.get("path_scope_sha256") != path_scope_sha256
                or type(contract.get("presence_required")) is not bool
                or type(contract.get("record_count")) is not int
                or int(contract.get("record_count", -1)) < 0
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("mapping_sha256", "")),
                )
            ):
                raise LiveMailBitrixError("campaign source contract is invalid")
            self._campaign_records_tx(connection, expected_contract=contract)
            if contract["presence_required"] and not snapshot.present:
                raise LiveMailBitrixError(
                    "a bound campaign source snapshot is unavailable"
                )
            if snapshot.present and not contract["presence_required"]:
                contract["presence_required"] = True
        for message_id, record in snapshot.records.items():
            message_id_hash = _digest(message_id)
            record_json = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            record_value = json.dumps(
                {
                    "message_id_hash": message_id_hash,
                    "record": record,
                    "record_sha256": _digest(record_json),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            record_key = f"campaign_message_{message_id_hash}"
            connection.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)",
                (record_key, record_value),
            )
            persisted = connection.execute(
                "SELECT value FROM meta WHERE key=?",
                (record_key,),
            ).fetchone()
            if persisted is None or str(persisted[0]) != record_value:
                raise LiveMailBitrixError(
                    "campaign message identity conflicts with protected state"
                )
        records = self._campaign_records_tx(connection, expected_contract=None)
        serialized_records = json.dumps(
            records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        contract["mapping_sha256"] = _digest(serialized_records)
        contract["record_count"] = len(records)
        value = json.dumps(
            contract,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    @staticmethod
    def _campaign_records_tx(
        connection: sqlite3.Connection,
        *,
        expected_contract: Mapping[str, Any] | None,
    ) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        rows = connection.execute(
            "SELECT key,value FROM meta WHERE key LIKE 'campaign_message_%' ORDER BY key"
        ).fetchall()
        for row in rows:
            key = str(row["key"])
            message_id_hash = key.removeprefix("campaign_message_")
            try:
                value = json.loads(str(row["value"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LiveMailBitrixError("protected campaign record is invalid") from exc
            if (
                not re.fullmatch(r"[0-9a-f]{64}", message_id_hash)
                or not isinstance(value, dict)
                or set(value) != {"message_id_hash", "record", "record_sha256"}
                or value.get("message_id_hash") != message_id_hash
                or not isinstance(value.get("record"), dict)
                or set(value["record"])
                != {"subject", "object", "winner", "email", "phone"}
            ):
                raise LiveMailBitrixError("protected campaign record is invalid")
            record = dict(value["record"])
            record_json = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if value.get("record_sha256") != _digest(record_json):
                raise LiveMailBitrixError("protected campaign record is invalid")
            records[message_id_hash] = record
        if expected_contract is not None:
            serialized_records = json.dumps(
                records,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if (
                int(expected_contract.get("record_count", -1)) != len(records)
                or expected_contract.get("mapping_sha256") != _digest(serialized_records)
            ):
                raise LiveMailBitrixError("protected campaign mapping seal is invalid")
        return records

    def _load_protected_campaign_records(self) -> dict[str, dict[str, Any]]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key='campaign_source_contract'"
            ).fetchone()
            if row is None:
                raise BootstrapRequired(
                    "campaign source must be imported by an explicit bootstrap"
                )
            try:
                contract = json.loads(str(row[0]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LiveMailBitrixError("campaign source contract is invalid") from exc
            if (
                not isinstance(contract, dict)
                or set(contract)
                != {
                    "format",
                    "mapping_sha256",
                    "path_scope_sha256",
                    "presence_required",
                    "record_count",
                }
                or contract.get("format") != "TenderBot.CampaignSource.v1"
                or type(contract.get("presence_required")) is not bool
                or type(contract.get("record_count")) is not int
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("mapping_sha256", "")),
                )
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(contract.get("path_scope_sha256", "")),
                )
            ):
                raise LiveMailBitrixError("campaign source contract is invalid")
            return self._campaign_records_tx(
                connection,
                expected_contract=contract,
            )

    def sync_campaign_snapshot(
        self,
        *,
        path: str | os.PathLike[str],
        confirmation: str,
    ) -> dict[str, Any]:
        """Append newly sent campaign identities to the protected state map."""

        if confirmation != CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION:
            raise ValueError("exact campaign snapshot sync confirmation is required")
        try:
            source_path = Path(path)
        except TypeError as exc:
            raise ValueError("campaign snapshot path is invalid") from exc
        if not source_path.is_absolute():
            raise ValueError("campaign snapshot path must be absolute")
        snapshot = _campaign_snapshot(source_path)
        if not snapshot.present:
            raise LiveMailBitrixError("campaign source snapshot is unavailable")
        self.initialize()
        with _RuntimeLock(self._lock_path):
            self._require_authority()
            with self._transaction() as connection:
                before = len(
                    self._campaign_records_tx(
                        connection,
                        expected_contract=None,
                    )
                )
                self._bind_campaign_snapshot_tx(
                    connection,
                    snapshot,
                    allow_create=False,
                    source_path=source_path,
                )
                after = len(
                    self._campaign_records_tx(
                        connection,
                        expected_contract=None,
                    )
                )
        return {
            "campaign_record_count": after,
            "imported_count": after - before,
            "ok": True,
            "status": "ready",
        }

    def bootstrap(
        self,
        *,
        after_uid: int,
        uidvalidity: str | int,
        reason: str,
        confirmation: str,
        authority_hours: int = MAX_AUTHORITY_HOURS,
        write_attempt_budget: int = 200,
        assigned_by_id: int = BITRIX_ASSIGNED_BY_ID,
        campaign_snapshot_path: str | os.PathLike[str] | None = None,
        legacy_processed_path: str | os.PathLike[str] | None = None,
        legacy_registry_path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Set the only accepted first cursor; never derives one from the inbox.

        Repeating the exact same bootstrap is idempotent.  Moving or replacing
        an existing cursor is deliberately unsupported and requires an audited
        database-level recovery procedure.
        """

        _ensure_plain_directory(self._state_dir)
        with _RuntimeLock(self._lock_path):
            self.initialize()
            with closing(self._connect()) as connection:
                epoch_row = connection.execute(
                    "SELECT authority_generation,authority_state,revoked_at_utc "
                    "FROM scoped_authority WHERE singleton=1"
                ).fetchone()
                generation_epoch = _authority_generation_counter_tx(connection)
                revocation_fence_epoch = _authority_revocation_fence_tx(connection)
            authority_epoch = (
                generation_epoch,
                revocation_fence_epoch,
                None
                if epoch_row is None
                else (
                    int(epoch_row["authority_generation"]),
                    str(epoch_row["authority_state"]),
                    str(epoch_row["revoked_at_utc"]),
                ),
            )
        if confirmation != OWNER_AUTHORITY_CONFIRMATION:
            raise ValueError("exact owner authority confirmation is required")
        if (
            type(authority_hours) is not int
            or not 1 <= authority_hours <= MAX_AUTHORITY_HOURS
            or type(write_attempt_budget) is not int
            or not MIN_WRITE_BUDGET <= write_attempt_budget <= MAX_WRITE_BUDGET
            or type(assigned_by_id) is not int
            or not 1 <= assigned_by_id <= 999_999_999
        ):
            raise ValueError("owner authority duration or write-attempt budget is invalid")
        try:
            uid = int(after_uid)
            validity = str(int(uidvalidity))
        except (TypeError, ValueError) as exc:
            raise ValueError("bootstrap cursor is invalid") from exc
        clean_reason = _clean_text(reason, limit=500)
        if uid < 0 or int(validity) <= 0 or not clean_reason:
            raise ValueError("bootstrap cursor is invalid")
        if campaign_snapshot_path is None and not self._legacy_queue_path_explicit:
            raise LiveMailBitrixError(
                "an explicit external campaign snapshot is required"
            )
        if legacy_processed_path is None and not self._legacy_processed_path_explicit:
            raise LiveMailBitrixError(
                "an explicit external legacy processed snapshot is required"
            )
        if legacy_registry_path is None and not self._legacy_registry_path_explicit:
            raise LiveMailBitrixError(
                "an explicit external legacy registry snapshot is required"
            )
        campaign_path = (
            Path(campaign_snapshot_path)
            if campaign_snapshot_path is not None
            else self._legacy_queue_path
        )
        campaign_snapshot = _campaign_snapshot(campaign_path)
        processed = Path(legacy_processed_path) if legacy_processed_path else self._legacy_processed_path
        registry = Path(legacy_registry_path) if legacy_registry_path else self._legacy_registry_path
        processed_snapshot = _stable_json_snapshot(processed)
        registry_snapshot = _stable_json_snapshot(registry)
        if not campaign_snapshot.present:
            raise LiveMailBitrixError(
                "the explicit campaign snapshot is unavailable"
            )
        if not processed_snapshot.present:
            raise LiveMailBitrixError(
                "the explicit legacy processed snapshot is unavailable"
            )
        if not registry_snapshot.present:
            raise LiveMailBitrixError(
                "the explicit legacy registry snapshot is unavailable"
            )
        # The reconciliation boundary is observed, not guessed.  This read is
        # bounded to UID metadata and never fetches message content.
        client: _ImapClient | None = None
        try:
            client = self._open_imap()
            observed_validity = self._select_imap(client)
            if observed_validity != validity:
                raise UidValidityMismatch("bootstrap UIDVALIDITY does not match the mailbox")
            current_uids = self._search(client, "ALL")
            high_water = max(current_uids, default=0)
            if uid > high_water:
                raise ValueError("bootstrap cursor is beyond the current mailbox high-water UID")
        finally:
            self._logout(client)
        now_value = self._now()
        now = _iso(now_value)
        expires_at = _iso(now_value + timedelta(hours=authority_hours))
        with _RuntimeLock(self._lock_path), self._transaction() as connection:
            existing = connection.execute("SELECT * FROM cursor WHERE singleton=1").fetchone()
            authority = connection.execute(
                "SELECT * FROM scoped_authority WHERE singleton=1"
            ).fetchone()
            current_epoch = (
                _authority_generation_counter_tx(connection),
                _authority_revocation_fence_tx(connection),
                None
                if authority is None
                else (
                    int(authority["authority_generation"]),
                    str(authority["authority_state"]),
                    str(authority["revoked_at_utc"]),
                ),
            )
            if current_epoch != authority_epoch:
                raise ConcurrentRun("authority changed while bootstrap inspected the mailbox")
            self._bind_campaign_snapshot_tx(
                connection,
                campaign_snapshot,
                allow_create=True,
                source_path=campaign_path,
            )
            generation_counter = _authority_generation_counter_tx(connection)
            authority_generation = (
                max(0, int(authority["authority_generation"]))
                if authority is not None
                else 0
            )
            new_generation = max(generation_counter, authority_generation) + 1
            if existing:
                if str(existing["uidvalidity"]) != validity or int(existing["last_uid"]) != uid:
                    raise LiveMailBitrixError("an existing cursor cannot be replaced by bootstrap")
                if int(existing["reconciliation_high_water_uid"]) != high_water:
                    # A repeated bootstrap must not silently widen the
                    # historical window while new mail is arriving.
                    high_water = int(existing["reconciliation_high_water_uid"])
                counts = self._import_legacy_state(
                    connection,
                    processed_snapshot,
                    registry_snapshot,
                    processed_path=processed,
                    registry_path=registry,
                )
                if not authority or str(authority["mailbox_scope_hash"]) != self._mailbox_scope_hash:
                    raise LiveMailBitrixError(
                        "mailbox scope changed; a new reconciled state store is required"
                    )
                if str(authority["bitrix_scope_hash"]) != self._webhook_scope_hash:
                    raise LiveMailBitrixError(
                        "Bitrix scope changed; a new reconciled state store is required"
                    )
                rebound_pending = self._rebind_safe_pending_assignee_tx(
                    connection,
                    assigned_by_id,
                )
                scope_changed = bool(
                    str(authority["connection_scope_hash"]) != self._authority_scope_hash
                    or str(authority["bitrix_scope_hash"]) != self._webhook_scope_hash
                    or str(authority["release_sha256"]) != self._release_sha256
                    or str(authority["runtime_sha256"]) != self._runtime_sha256
                )
                connection.execute(
                    """UPDATE scoped_authority SET authority_version='MailToBitrixInbound.v4',
                       imap_inbox_read=1,bitrix_lead_list=1,bitrix_lead_add=1,
                       bitrix_lead_get=1,bitrix_activity_list=1,bitrix_activity_add=1,
                       bitrix_activity_get=1,bitrix_timeline_comment_list=1,
                       bitrix_timeline_comment_add=1,bitrix_timeline_comment_get=1,
                       smtp_send=0,unisender_send=0,tenderplan_access=0,
                       confirmation_hash=?,connection_scope_hash=?,mailbox_scope_hash=?,
                       bitrix_scope_hash=?,release_sha256=?,runtime_sha256=?,
                       authority_generation=?,authority_state='ACTIVE',revoked_at_utc='',
                       revocation_reason_hash='',revoked_by_release_sha256='',
                       revoked_by_runtime_sha256='',authority_expires_at_utc=?,
                       write_attempt_budget=?,write_attempts_used=0,authorized_at_utc=?
                       WHERE singleton=1""",
                    (
                        _digest(confirmation),
                        self._authority_scope_hash,
                        self._mailbox_scope_hash,
                        self._webhook_scope_hash,
                        self._release_sha256,
                        self._runtime_sha256,
                        new_generation,
                        expires_at,
                        write_attempt_budget,
                        now,
                    ),
                )
                _record_authority_generation_tx(connection, new_generation)
                connection.execute(
                    "INSERT INTO meta(key,value) VALUES('authority_time_fence',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (
                        json.dumps(
                            {
                                "authority_generation": new_generation,
                                "max_observed_at_utc": now,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
                connection.execute(
                    """INSERT INTO meta(key,value) VALUES('bitrix_assigned_by_id',?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (str(assigned_by_id),),
                )
                _invalidate_canary_tx(connection, state="PREPARED")
                if scope_changed:
                    connection.execute(
                        "DELETE FROM meta WHERE key IN ("
                        "'bitrix_canary_webhook_scope_hash',"
                        "'bitrix_canary_remote_id','bitrix_canary_origin_id',"
                        "'bitrix_canary_release_sha256')"
                    )
                return {
                    "ok": True,
                    "status": "ready",
                    "created": False,
                    "reauthorized": True,
                    "canary_required": True,
                    "authority_generation": new_generation,
                    "authority_hours": authority_hours,
                    "write_attempt_budget": write_attempt_budget,
                    "bitrix_assigned_by_id": assigned_by_id,
                    "rebound_pending_assignee_count": rebound_pending,
                    "last_uid": uid,
                    "reconciliation_high_water_uid": high_water,
                    **counts,
                }
            counts = self._import_legacy_state(
                connection,
                processed_snapshot,
                registry_snapshot,
                processed_path=processed,
                registry_path=registry,
            )
            rebound_pending = self._rebind_safe_pending_assignee_tx(
                connection,
                assigned_by_id,
            )
            connection.execute(
                """INSERT INTO cursor(singleton,mailbox,uidvalidity,last_uid,
                   reconciliation_high_water_uid,bootstrap_reason_hash,
                   bootstrapped_at_utc,updated_at_utc)
                   VALUES(1,'INBOX',?,?,?,?,?,?)""",
                (validity, uid, high_water, _digest(clean_reason), now, now),
            )
            connection.execute(
                """INSERT INTO scoped_authority(
                   singleton,authority_version,imap_inbox_read,bitrix_lead_list,
                   bitrix_lead_add,bitrix_lead_get,bitrix_activity_list,
                   bitrix_activity_add,bitrix_activity_get,
                   bitrix_timeline_comment_list,bitrix_timeline_comment_add,
                   bitrix_timeline_comment_get,smtp_send,unisender_send,
                   tenderplan_access,confirmation_hash,connection_scope_hash,
                   authorized_at_utc,mailbox_scope_hash,bitrix_scope_hash,
                   release_sha256,runtime_sha256,authority_generation,authority_state,
                   revoked_at_utc,revocation_reason_hash,revoked_by_release_sha256,
                   revoked_by_runtime_sha256,authority_expires_at_utc,
                   write_attempt_budget,write_attempts_used
                   ) VALUES(1,'MailToBitrixInbound.v4',1,1,1,1,1,1,1,1,1,1,0,0,0,
                            ?,?,?,?,?,?,?,?,
                            'ACTIVE','','','','',?,?,0)""",
                (
                    _digest(confirmation),
                    self._authority_scope_hash,
                    now,
                    self._mailbox_scope_hash,
                    self._webhook_scope_hash,
                    self._release_sha256,
                    self._runtime_sha256,
                    new_generation,
                    expires_at,
                    write_attempt_budget,
                ),
            )
            _record_authority_generation_tx(connection, new_generation)
            connection.execute(
                "INSERT INTO meta(key,value) VALUES('authority_time_fence',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (
                    json.dumps(
                        {
                            "authority_generation": new_generation,
                            "max_observed_at_utc": now,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            connection.execute(
                """INSERT INTO meta(key,value) VALUES('bitrix_assigned_by_id',?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (str(assigned_by_id),),
            )
            _invalidate_canary_tx(connection, state="PREPARED")
        return {
            "ok": True,
            "status": "ready",
            "created": True,
            "reauthorized": False,
            "canary_required": True,
            "authority_generation": new_generation,
            "authority_hours": authority_hours,
            "write_attempt_budget": write_attempt_budget,
            "bitrix_assigned_by_id": assigned_by_id,
            "rebound_pending_assignee_count": rebound_pending,
            "last_uid": uid,
            "reconciliation_high_water_uid": high_water,
            **counts,
        }

    def set_bootstrap_cursor(
        self,
        uidvalidity: str | int,
        last_uid: int,
        *,
        reason: str,
        confirmation: str,
        authority_hours: int = MAX_AUTHORITY_HOURS,
        write_attempt_budget: int = 200,
        assigned_by_id: int = BITRIX_ASSIGNED_BY_ID,
        campaign_snapshot_path: str | os.PathLike[str] | None = None,
        legacy_processed_path: str | os.PathLike[str] | None = None,
        legacy_registry_path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Compatibility alias for operator scripts written before v1 final."""

        return self.bootstrap(
            after_uid=last_uid,
            uidvalidity=uidvalidity,
            reason=reason,
            confirmation=confirmation,
            authority_hours=authority_hours,
            write_attempt_budget=write_attempt_budget,
            assigned_by_id=assigned_by_id,
            campaign_snapshot_path=campaign_snapshot_path,
            legacy_processed_path=legacy_processed_path,
            legacy_registry_path=legacy_registry_path,
        )

    def _open_imap(self) -> _ImapClient:
        client: _ImapClient | None = None
        try:
            client = self._imap_factory(self._credentials)
        except (imaplib.IMAP4.abort, OSError) as exc:
            raise _ImapReadError(
                "IMAP connection failed",
                retryable=True,
                code="imap_transport_transient",
            ) from exc
        except Exception as exc:
            raise _ImapReadError(
                "IMAP client initialization failed",
                code="imap_client_contract_failed",
            ) from exc
        try:
            status, _ = client.login(
                str(self._credentials.imap_user), str(self._credentials.imap_password)
            )
            if str(status or "").upper() != "OK":
                raise _ImapReadError(
                    "IMAP authentication failed",
                    code="imap_authentication_failed",
                )
            return client
        except _ImapReadError:
            self._logout(client)
            raise
        except (imaplib.IMAP4.abort, OSError) as exc:
            self._logout(client)
            raise _ImapReadError(
                "IMAP connection failed",
                retryable=True,
                code="imap_transport_transient",
            ) from exc
        except imaplib.IMAP4.error as exc:
            self._logout(client)
            raise _ImapReadError(
                "IMAP authentication failed",
                code="imap_authentication_failed",
            ) from exc
        except Exception as exc:
            self._logout(client)
            raise _ImapReadError(
                "IMAP authentication contract failed",
                code="imap_authentication_failed",
            ) from exc

    @staticmethod
    def _select_imap(client: _ImapClient) -> str:
        try:
            status, _ = client.select(_MAILBOX, readonly=True)
            if str(status or "").upper() != "OK":
                raise _ImapReadError(
                    "IMAP read-only mailbox selection failed",
                    retryable=True,
                    code="imap_select_transient",
                )
            responses = getattr(client, "untagged_responses", {})
            values = responses.get("UIDVALIDITY") or responses.get(b"UIDVALIDITY") or []
            if not isinstance(values, (list, tuple)) or len(values) != 1:
                raise _ImapReadError("IMAP UIDVALIDITY is unavailable")
            value = values[0]
            if isinstance(value, bytes):
                value = value.decode("ascii", errors="strict")
            validity = str(int(value))
            if int(validity) <= 0:
                raise ValueError
            return validity
        except _ImapReadError:
            raise
        except (imaplib.IMAP4.abort, OSError) as exc:
            raise _ImapReadError(
                "IMAP read-only mailbox selection failed",
                retryable=True,
                code="imap_transport_transient",
            ) from exc
        except Exception as exc:
            raise _ImapReadError(
                "IMAP UIDVALIDITY is unavailable",
                code="imap_uidvalidity_contract_failed",
            ) from exc

    @staticmethod
    def _logout(client: _ImapClient | None) -> None:
        if client is None:
            return
        try:
            client.logout()
        except Exception:
            pass

    @staticmethod
    def _search(client: _ImapClient, criterion: str, *, after_uid: int = -1) -> list[int]:
        try:
            status, response = client.uid("search", None, criterion)
            if str(status or "").upper() != "OK" or not isinstance(response, (list, tuple)):
                raise _ImapReadError(
                    "IMAP UID search failed",
                    retryable=True,
                    code="imap_search_transient",
                )
            payload = response[0] if response else b""
            if isinstance(payload, bytes):
                payload = payload.decode("ascii", errors="strict")
            values: set[int] = set()
            for token in str(payload or "").split():
                value = int(token)
                if value > after_uid:
                    values.add(value)
            return sorted(values)
        except _ImapReadError:
            raise
        except (imaplib.IMAP4.abort, OSError) as exc:
            raise _ImapReadError(
                "IMAP UID search failed",
                retryable=True,
                code="imap_transport_transient",
            ) from exc
        except Exception as exc:
            raise _ImapReadError(
                "IMAP UID search response is invalid",
                code="imap_search_contract_failed",
            ) from exc

    @staticmethod
    def _fetch(client: _ImapClient, uid: int) -> bytes:
        try:
            status, response = client.uid("fetch", str(uid), "(UID BODY.PEEK[])")
            normalized_status = str(status or "").upper()
            if (
                normalized_status == "NO"
                and isinstance(response, (list, tuple))
                and all(
                    item is None or isinstance(item, (bytes, str))
                    for item in response
                )
            ):
                raise _ImapReadError(
                    "IMAP message disappeared before fetch",
                    retryable=True,
                    code="imap_fetch_expunge_race",
                )
            if normalized_status != "OK" or not isinstance(response, (list, tuple)):
                raise _ImapReadError(
                    "IMAP UID fetch response is invalid",
                    code="imap_fetch_contract_failed",
                )

            items = tuple(response)
            closing_tokens = (b")", ")")
            bodyless_expunge = (
                not items
                or items == (None,)
                or (
                    len(items) == 2
                    and items[0] is None
                    and items[1] in closing_tokens
                )
            )
            if bodyless_expunge:
                raise _ImapReadError(
                    "IMAP message disappeared before fetch",
                    retryable=True,
                    code="imap_fetch_expunge_race",
                )

            if len(items) == 1 and isinstance(items[0], (bytes, str)):
                nil_metadata = items[0]
                if isinstance(nil_metadata, bytes):
                    nil_metadata = nil_metadata.decode("ascii", errors="strict")
                nil_match = re.fullmatch(
                    r"[1-9]\d* \(UID ([1-9]\d*) BODY\[\] NIL\)",
                    nil_metadata,
                    flags=re.IGNORECASE,
                )
                if nil_match is not None and int(nil_match.group(1)) == uid:
                    raise _ImapReadError(
                        "IMAP message disappeared before fetch",
                        retryable=True,
                        code="imap_fetch_expunge_race",
                    )

            if (
                len(items) != 2
                or not isinstance(items[0], tuple)
                or len(items[0]) != 2
                or not isinstance(items[0][0], (bytes, str))
                or not isinstance(items[0][1], bytes)
                or items[1] not in closing_tokens
            ):
                raise _ImapReadError(
                    "IMAP UID fetch response is invalid",
                    code="imap_fetch_contract_failed",
                )

            metadata, body = items[0]
            if isinstance(metadata, bytes):
                metadata = metadata.decode("ascii", errors="strict")
            metadata_match = re.fullmatch(
                r"[1-9]\d* \(UID ([1-9]\d*) BODY\[\] \{(\d+)\}",
                metadata,
                flags=re.IGNORECASE,
            )
            if (
                metadata_match is None
                or int(metadata_match.group(1)) != uid
                or int(metadata_match.group(2)) != len(body)
                or not body
                or len(body) > _MAX_MIME_BYTES
            ):
                raise _ImapReadError(
                    "IMAP UID fetch response is invalid",
                    code="imap_fetch_contract_failed",
                )
            return body
        except _ImapReadError:
            raise
        except (imaplib.IMAP4.abort, OSError) as exc:
            raise _ImapReadError(
                "IMAP UID fetch failed",
                retryable=True,
                code="imap_transport_transient",
            ) from exc
        except Exception as exc:
            raise _ImapReadError(
                "IMAP UID fetch response is invalid",
                code="imap_fetch_contract_failed",
            ) from exc

    def _persist_evidence(self, *, uidvalidity: str, uid: int, raw: bytes) -> tuple[str, str]:
        if not re.fullmatch(r"[1-9]\d{0,30}", str(uidvalidity)) or not 1 <= int(uid):
            raise LiveMailBitrixError("MIME evidence identity is invalid")
        digest = _digest(raw)
        folder = self._evidence_dir / uidvalidity
        _assert_plain_directory_chain(self._state_dir)
        _assert_plain_directory_chain(self._evidence_dir)
        directory_identity = _ensure_plain_directory(folder)
        relative = Path("evidence") / uidvalidity / f"{uid}.eml"
        target = self._state_dir / relative
        try:
            target.lstat()
        except FileNotFoundError:
            target_exists = False
        except OSError as exc:
            raise LiveMailBitrixError("MIME evidence path is unavailable") from exc
        else:
            target_exists = True
        if target_exists:
            before = _plain_path_stat(target, directory=False)
            try:
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags)
                try:
                    opened = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or int(opened.st_nlink) != 1
                        or (int(opened.st_dev), int(opened.st_ino))
                        != (int(before.st_dev), int(before.st_ino))
                    ):
                        raise LiveMailBitrixError(
                            "existing MIME evidence identity is unsafe"
                        )
                    with os.fdopen(descriptor, "rb") as handle:
                        descriptor = -1
                        existing = handle.read(_MAX_MIME_BYTES + 1)
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            except OSError as exc:
                raise LiveMailBitrixError("existing MIME evidence is unreadable") from exc
            if _assert_plain_directory_chain(folder) != directory_identity:
                raise LiveMailBitrixError("MIME evidence directory identity changed")
            if _digest(existing) != digest:
                raise LiveMailBitrixError("existing MIME evidence conflicts with the mailbox UID")
            return relative.as_posix(), digest
        tracked_bytes = sum(item[3] for item in self._evidence_inventory())
        try:
            free_bytes = int(shutil.disk_usage(self._state_dir).free)
        except OSError as exc:
            raise LiveMailBitrixError("MIME evidence capacity is unavailable") from exc
        if (
            tracked_bytes + len(raw) > _MAX_EVIDENCE_BYTES
            or free_bytes - len(raw) < _MIN_EVIDENCE_FREE_BYTES
        ):
            raise LiveMailBitrixError("MIME evidence capacity boundary reached")
        descriptor, temp_name = tempfile.mkstemp(prefix=f".{uid}.", suffix=".tmp", dir=folder)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or int(opened.st_nlink) != 1:
                raise LiveMailBitrixError("temporary MIME evidence identity is unsafe")
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temp_name, 0o600)
            _plain_path_stat(Path(temp_name), directory=False)
            if _assert_plain_directory_chain(folder) != directory_identity:
                raise LiveMailBitrixError("MIME evidence directory identity changed")
            _durable_replace(Path(temp_name), target, directory=folder)
            _plain_path_stat(target, directory=False)
            if _assert_plain_directory_chain(folder) != directory_identity:
                raise LiveMailBitrixError("MIME evidence directory identity changed")
        except Exception:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
        return relative.as_posix(), digest

    def _message_evidence_intact(self, message_key: str) -> bool:
        if not re.fullmatch(r"mail_[0-9a-f]{64}", str(message_key or "")):
            return False
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """SELECT uidvalidity,uid,rfc822_sha256,rfc822_size,evidence_ref
                       FROM messages WHERE message_key=?""",
                    (message_key,),
                ).fetchone()
            if row is None:
                return False
            expected_relative = (
                Path("evidence") / str(row["uidvalidity"]) / f"{int(row['uid'])}.eml"
            )
            relative = Path(str(row["evidence_ref"]))
            if relative.is_absolute() or relative != expected_relative:
                return False
            folder = self._state_dir / expected_relative.parent
            target = self._state_dir / expected_relative
            directory_identity = _assert_plain_directory_chain(folder)
            before = _plain_path_stat(target, directory=False)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or int(opened.st_nlink) != 1
                    or (int(opened.st_dev), int(opened.st_ino))
                    != (int(before.st_dev), int(before.st_ino))
                ):
                    return False
                with os.fdopen(descriptor, "rb") as handle:
                    descriptor = -1
                    raw = handle.read(_MAX_MIME_BYTES + 1)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            return bool(
                _assert_plain_directory_chain(folder) == directory_identity
                and len(raw) == int(row["rfc822_size"])
                and len(raw) <= _MAX_MIME_BYTES
                and _digest(raw) == str(row["rfc822_sha256"])
            )
        except (LiveMailBitrixError, OSError, TypeError, ValueError):
            return False

    def _read_evidence_path(self, path: Path) -> bytes:
        before = _plain_path_stat(path, directory=False)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or int(opened.st_nlink) != 1
                or (int(opened.st_dev), int(opened.st_ino))
                != (int(before.st_dev), int(before.st_ino))
            ):
                raise LiveMailBitrixError("MIME evidence identity is unsafe")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                raw = handle.read(_MAX_MIME_BYTES + 1)
        except OSError as exc:
            raise LiveMailBitrixError("MIME evidence is unreadable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        after = _plain_path_stat(path, directory=False)
        if (
            not raw
            or len(raw) > _MAX_MIME_BYTES
            or len(raw) != int(before.st_size)
            or (int(after.st_dev), int(after.st_ino))
            != (int(before.st_dev), int(before.st_ino))
            or int(after.st_size) != int(before.st_size)
            or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        ):
            raise LiveMailBitrixError("MIME evidence changed during read")
        return raw

    def _evidence_inventory(self) -> list[tuple[str, int, Path, int]]:
        _assert_plain_directory_chain(self._evidence_dir)
        inventory: list[tuple[str, int, Path, int]] = []
        for folder in sorted(self._evidence_dir.iterdir(), key=lambda item: item.name):
            _plain_path_stat(folder, directory=True)
            if not re.fullmatch(r"[1-9]\d{0,30}", folder.name):
                raise LiveMailBitrixError("MIME evidence directory identity is invalid")
            for candidate in sorted(folder.iterdir(), key=lambda item: item.name):
                if _EVIDENCE_TEMP_NAME.fullmatch(candidate.name):
                    _plain_path_stat(candidate, directory=False)
                    continue
                file_stat = _plain_path_stat(candidate, directory=False)
                match = re.fullmatch(r"([1-9]\d*)\.eml", candidate.name)
                if match is None or int(file_stat.st_size) > _MAX_MIME_BYTES:
                    raise LiveMailBitrixError("MIME evidence file identity is invalid")
                inventory.append(
                    (folder.name, int(match.group(1)), candidate, int(file_stat.st_size))
                )
                if len(inventory) > 500_000:
                    raise LiveMailBitrixError("MIME evidence inventory is too large")
        return inventory

    def _cleanup_evidence_temps(self) -> int:
        evidence_identity = _assert_plain_directory_chain(self._evidence_dir)
        removed = 0
        for folder in sorted(self._evidence_dir.iterdir(), key=lambda item: item.name):
            folder_identity = _assert_plain_directory_chain(folder)
            if not re.fullmatch(r"[1-9]\d{0,30}", folder.name):
                raise LiveMailBitrixError("MIME evidence directory identity is invalid")
            for candidate in sorted(folder.iterdir(), key=lambda item: item.name):
                if _EVIDENCE_TEMP_NAME.fullmatch(candidate.name) is None:
                    continue
                before = _plain_path_stat(candidate, directory=False)
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = -1
                try:
                    descriptor = os.open(candidate, flags)
                    opened = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or int(opened.st_nlink) != 1
                        or (int(opened.st_dev), int(opened.st_ino))
                        != (int(before.st_dev), int(before.st_ino))
                    ):
                        raise LiveMailBitrixError(
                            "temporary MIME evidence identity is unsafe"
                        )
                except OSError as exc:
                    raise LiveMailBitrixError(
                        "temporary MIME evidence is unavailable"
                    ) from exc
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                current = _plain_path_stat(candidate, directory=False)
                if (
                    (int(current.st_dev), int(current.st_ino))
                    != (int(before.st_dev), int(before.st_ino))
                    or int(current.st_size) != int(before.st_size)
                    or int(current.st_mtime_ns) != int(before.st_mtime_ns)
                    or _assert_plain_directory_chain(folder) != folder_identity
                    or _assert_plain_directory_chain(self._evidence_dir)
                    != evidence_identity
                ):
                    raise LiveMailBitrixError(
                        "temporary MIME evidence changed before cleanup"
                    )
                try:
                    candidate.unlink()
                except OSError as exc:
                    raise LiveMailBitrixError(
                        "temporary MIME evidence cleanup failed"
                    ) from exc
                if _assert_plain_directory_chain(folder) != folder_identity:
                    raise LiveMailBitrixError(
                        "MIME evidence directory identity changed"
                    )
                removed += 1
        return removed

    def _untracked_evidence(
        self,
        *,
        uidvalidity: str,
        last_uid: int,
    ) -> dict[int, bytes]:
        inventory = self._evidence_inventory()
        with closing(self._connect()) as connection:
            tracked = {
                (str(row["uidvalidity"]), int(row["uid"]))
                for row in connection.execute(
                    "SELECT uidvalidity,uid FROM message_deliveries"
                ).fetchall()
            }
        result: dict[int, bytes] = {}
        for observed_validity, uid, path, _size in inventory:
            if (observed_validity, uid) in tracked:
                continue
            if observed_validity != uidvalidity or uid <= last_uid:
                raise LiveMailBitrixError(
                    "untracked MIME evidence conflicts with the durable cursor"
                )
            result[uid] = self._read_evidence_path(path)
        return result

    def _legacy_state(self, message_id_hash: str) -> sqlite3.Row | None:
        if not message_id_hash:
            return None
        connection = self._connect()
        try:
            return connection.execute(
                "SELECT state,remote_lead_id FROM legacy_message_state WHERE message_id_hash=?",
                (message_id_hash,),
            ).fetchone()
        finally:
            connection.close()

    def _lead_payload(
        self,
        parsed: _ParsedMail,
        *,
        route: str,
        campaign_record: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        review_required = route.endswith("_REVIEW")
        if route in {"FACADE_AUTO", "FACADE_AUTH_REVIEW"}:
            inquiry = parse_facade_inquiry(
                parsed.subject,
                parsed.text,
                excluded_emails=(FACADE_FROM, str(self._credentials.imap_user)),
            )
            email_match = inquiry.email
            company = inquiry.company
            name = inquiry.contact_name
            object_name = inquiry.object_name
            request = inquiry.request
            title_detail = object_name or company or parsed.subject or "новая заявка"
            title = (
                f"[Проверить] Facade.ru: {title_detail}"
                if review_required
                else f"Facade.ru: {title_detail}"
            )[:255]
            source_description = (
                "Mail.ru inbound: Facade.ru; authentication review required"
                if review_required
                else "Mail.ru inbound: Facade.ru"
            )
            source_id = "FASAD_RU"
            phone = inquiry.phone
        elif route in {"DIRECT_INQUIRY_AUTO", "INQUIRY_REVIEW"}:
            visible_text = parsed.latest_text or parsed.text
            company = _label(visible_text, ("компания", "организация", "заказчик"), limit=255)
            name = parsed.sender_name or _label(
                visible_text,
                ("контакт", "контактное лицо", "имя", "фио"),
                limit=255,
            )
            email_match = parsed.sender if "@" in parsed.sender else ""
            phone = _first_phone(visible_text)
            object_name = _label(
                visible_text,
                ("объект", "название объекта", "проект"),
                limit=255,
            )
            request = _label(visible_text, ("запрос", "потребность", "описание"), limit=1000)
            title_detail = company or object_name or parsed.subject or parsed.sender or "клиент"
            title = (
                f"[Проверить письмо] {title_detail}"
                if review_required
                else f"Входящий запрос: {title_detail}"
            )[:255]
            source_description = (
                "Mail.ru inbound: inquiry requiring identity review"
                if review_required
                else "Mail.ru inbound: authenticated direct inquiry"
            )
            source_id = "EMAIL"
        else:
            record = dict(campaign_record or {})
            company = _header(record.get("winner") or record.get("company") or "", limit=255)
            name = _header(parseaddr(parsed.sender)[0], limit=255)
            email_match = parsed.sender if "@" in parsed.sender else ""
            phone = _first_phone(parsed.text) or _header(record.get("phone", ""), limit=32)
            subject = parsed.subject or _header(record.get("subject", ""), limit=255)
            title_detail = company or subject or "клиент"
            title = (
                f"[Проверить ответ] {title_detail}"
                if review_required
                else f"Входящий ответ: {title_detail}"
            )[:255]
            source_description = (
                "Mail.ru inbound: campaign reply requiring identity review"
                if review_required
                else "Mail.ru inbound: reply to legacy campaign"
            )
            source_id = "EMAIL"
            object_name = _header(record.get("object", ""), limit=255)
            request = ""
        comments_parts = [
            f"Источник: {source_description}",
            f"Тема: {parsed.subject}" if parsed.subject else "",
            f"Объект: {object_name}" if object_name else "",
            f"Запрос: {request}" if request else "",
            (
                "ВАЖНО: личность отправителя не подтверждена; до проверки не звонить."
                if review_required
                else ""
            ),
            "--- Текст входящего письма ---",
            parsed.text[:12_000],
            "Полный MIME и вложения сохранены в локальном evidence-хранилище.",
        ]
        return {
            "TITLE": _header(title, limit=255),
            "SOURCE_ID": source_id,
            "SOURCE_DESCRIPTION": _header(source_description, limit=255),
            "ASSIGNED_BY_ID": self._assigned_by_id(),
            "LF_ROUTE": _safe_token(route),
            "OPERATOR_ACTION": "REVIEW" if review_required else "CALL",
            "THREAD_KEY": parsed.thread_key,
            "COMPANY": _header(company, limit=255),
            "NAME": _header(name, limit=255),
            "PHONE": phone[:32],
            "EMAIL": email_match[:320],
            "COMMENTS": _clean_text("\n".join(part for part in comments_parts if part), limit=16_000),
        }

    def _route(
        self,
        parsed: _ParsedMail,
        campaigns: Mapping[str, Mapping[str, Any]],
        *,
        uid: int,
        reconciliation_high_water_uid: int,
    ) -> _Route:
        legacy = self._legacy_state(parsed.message_id_hash)
        historical = uid <= reconciliation_high_water_uid
        if legacy is not None:
            if not historical:
                return _Route("MESSAGE_ID_CONFLICT_REVIEW", "REVIEW", None)
            state = str(legacy["state"])
            return _Route(state, state, None)
        if historical:
            return _Route("HISTORICAL_REVIEW", "REVIEW", None)
        campaign_candidates: dict[str, Mapping[str, Any]] = {}
        for thread_id in parsed.thread_ids:
            campaign_record = campaigns.get(_digest(thread_id))
            if campaign_record is None:
                continue
            identity = _digest(
                json.dumps(
                    dict(campaign_record),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            campaign_candidates[identity] = campaign_record
        has_campaign = bool(campaign_candidates)
        if parsed.is_bounce:
            return _Route(
                "CAMPAIGN_BOUNCE_REVIEW" if has_campaign else "BOUNCE_REVIEW",
                "REVIEW",
                None,
            )
        if parsed.is_unsubscribe:
            return _Route(
                "CAMPAIGN_SUPPRESSION_REVIEW" if has_campaign else "SUPPRESSION_REVIEW",
                "REVIEW",
                None,
            )
        if parsed.is_system:
            return _Route(
                "CAMPAIGN_SYSTEM_REVIEW" if has_campaign else "SYSTEM_REVIEW",
                "REVIEW",
                None,
            )
        if len(campaign_candidates) > 1:
            return _Route("CAMPAIGN_AMBIGUITY_REVIEW", "REVIEW", None)
        if parsed.sender == FACADE_FROM:
            if not parsed.facade_authenticated:
                return _Route(
                    "FACADE_AUTH_REVIEW",
                    "CRM_REVIEW_PENDING",
                    self._lead_payload(parsed, route="FACADE_AUTH_REVIEW"),
                )
            return _Route(
                "FACADE_AUTO",
                "OUTBOX_PENDING",
                self._lead_payload(parsed, route="FACADE_AUTO"),
            )
        if campaign_candidates:
            campaign_record = next(iter(campaign_candidates.values()))
            expected_sender = str(campaign_record.get("email", "") or "").strip().casefold()
            if not _EMAIL.fullmatch(expected_sender) or parsed.sender != expected_sender:
                return _Route(
                    "CAMPAIGN_IDENTITY_REVIEW",
                    "CRM_REVIEW_PENDING",
                    self._lead_payload(
                        parsed,
                        route="CAMPAIGN_IDENTITY_REVIEW",
                        campaign_record=campaign_record,
                    ),
                )
            if not parsed.sender_authenticated:
                return _Route(
                    "CAMPAIGN_AUTH_REVIEW",
                    "CRM_REVIEW_PENDING",
                    self._lead_payload(
                        parsed,
                        route="CAMPAIGN_AUTH_REVIEW",
                        campaign_record=campaign_record,
                    ),
                )
            return _Route(
                "CAMPAIGN_HUMAN_AUTO",
                "OUTBOX_PENDING",
                self._lead_payload(
                    parsed,
                    route="CAMPAIGN_HUMAN_AUTO",
                    campaign_record=campaign_record,
                ),
            )
        if parsed.thread_ids:
            # A reply to an outbound identity that has not yet crossed the
            # protected campaign-snapshot handshake must never be projected
            # as a generic direct inquiry with lost campaign attribution.
            return _Route("UNMAPPED_THREAD_REVIEW", "REVIEW", None)
        haystack = f"{parsed.subject}\n{parsed.latest_text[:20_000]}".casefold()
        inquiry = any(
            marker in haystack
            for marker in (
                "заявк",
                "запрос",
                "коммерческ",
                "расчёт",
                "расчет",
                "стоимост",
                "поставка",
                "фасад",
                "витраж",
                "окн",
                "request for quote",
                "quotation",
                "rfq",
            )
        )
        own_senders = {
            str(self._credentials.imap_user).strip().casefold(),
            str(self._credentials.smtp_user).strip().casefold(),
            str(self._credentials.smtp_from).strip().casefold(),
        }
        if inquiry and parsed.sender not in own_senders:
            if parsed.sender_authenticated:
                return _Route(
                    "DIRECT_INQUIRY_AUTO",
                    "OUTBOX_PENDING",
                    self._lead_payload(parsed, route="DIRECT_INQUIRY_AUTO"),
                )
            return _Route(
                "INQUIRY_REVIEW",
                "CRM_REVIEW_PENDING",
                self._lead_payload(parsed, route="INQUIRY_REVIEW"),
            )
        return _Route("INQUIRY_REVIEW" if inquiry else "UNKNOWN_REVIEW", "REVIEW", None)

    def _persist_message(
        self,
        *,
        uidvalidity: str,
        uid: int,
        raw: bytes,
        evidence_ref: str,
        evidence_sha256: str,
        parsed: _ParsedMail,
        route: _Route,
    ) -> bool:
        identity = (
            f"INBOX|MID|{parsed.message_id_hash}|RAW|{evidence_sha256}"
            if parsed.message_id_hash
            else f"INBOX|RAW|{evidence_sha256}"
        )
        message_key = "mail_" + _digest(identity)
        origin_id = "mail_" + _digest(message_key)[:56]
        now = _iso(self._now())
        payload_json = (
            json.dumps(route.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if route.payload
            else ""
        )
        with self._transaction() as connection:
            cursor = connection.execute("SELECT * FROM cursor WHERE singleton=1").fetchone()
            if not cursor:
                raise BootstrapRequired("explicit IMAP cursor bootstrap is required")
            if str(cursor["uidvalidity"]) != uidvalidity:
                raise UidValidityMismatch("IMAP UIDVALIDITY changed; cursor was not advanced")
            if uid <= int(cursor["last_uid"]):
                return False
            physical = connection.execute(
                """SELECT message_key,rfc822_sha256 FROM message_deliveries
                   WHERE uidvalidity=? AND uid=?""",
                (uidvalidity, uid),
            ).fetchone()
            if physical and str(physical["rfc822_sha256"]) != evidence_sha256:
                raise LiveMailBitrixError("mailbox UID maps to conflicting MIME evidence")
            raw_matches = connection.execute(
                """SELECT message_key,rfc822_sha256,rfc822_size
                   FROM messages WHERE rfc822_sha256=?
                   ORDER BY message_key LIMIT 2""",
                (evidence_sha256,),
            ).fetchall()
            if len(raw_matches) > 1:
                raise LiveMailBitrixError(
                    "identical MIME evidence has conflicting logical identities"
                )
            if raw_matches:
                if int(raw_matches[0]["rfc822_size"]) != len(raw):
                    raise LiveMailBitrixError(
                        "identical MIME digest has conflicting stored size"
                    )
                message_key = str(raw_matches[0]["message_key"])
                existing = raw_matches[0]
            else:
                existing = connection.execute(
                    "SELECT message_key,rfc822_sha256 FROM messages WHERE message_key=?",
                    (message_key,),
                ).fetchone()
            if existing and str(existing["rfc822_sha256"]) != evidence_sha256:
                raise LiveMailBitrixError(
                    "logical message identity conflicts with MIME evidence"
                )
            if physical and str(physical["message_key"]) != message_key:
                raise LiveMailBitrixError(
                    "mailbox UID maps to conflicting logical message identity"
                )
            created = existing is None
            if parsed.message_id_hash:
                collision = connection.execute(
                    """SELECT 1 FROM messages WHERE message_id_hash=?
                       AND rfc822_sha256<>? LIMIT 1""",
                    (parsed.message_id_hash, evidence_sha256),
                ).fetchone()
                if collision:
                    route = _Route("MESSAGE_ID_CONFLICT_REVIEW", "REVIEW", None)
                    payload_json = ""
            if created:
                connection.execute(
                    """INSERT INTO messages(
                       message_key,uidvalidity,uid,rfc822_sha256,rfc822_size,evidence_ref,
                       message_id_hash,thread_key,sender_hash,route,state,lead_payload_json,
                       created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        message_key,
                        uidvalidity,
                        uid,
                        evidence_sha256,
                        len(raw),
                        evidence_ref,
                        parsed.message_id_hash,
                        parsed.thread_key,
                        parsed.sender_hash,
                        route.name,
                        route.state,
                        payload_json,
                        now,
                        now,
                    ),
                    )
                connection.execute(
                    """INSERT INTO message_deliveries(
                       uidvalidity,uid,message_key,rfc822_sha256,evidence_ref,observed_at_utc
                   ) VALUES(?,?,?,?,?,?)""",
                    (uidvalidity, uid, message_key, evidence_sha256, evidence_ref, now),
                )
                if route.payload is not None and route.state in {
                    "OUTBOX_PENDING",
                    "CRM_REVIEW_PENDING",
                }:
                    connection.execute(
                        """INSERT INTO crm_outbox(
                           operation_id,message_key,originator_id,origin_id,payload_json,
                           state,created_at_utc,updated_at_utc
                       ) VALUES(?,?,?,?,?,'PENDING',?,?)""",
                        (
                            "op_" + uuid.uuid4().hex,
                            message_key,
                            ORIGINATOR_ID,
                            origin_id,
                            payload_json,
                            now,
                            now,
                        ),
                    )
            elif physical is None:
                connection.execute(
                    """INSERT INTO message_deliveries(
                       uidvalidity,uid,message_key,rfc822_sha256,evidence_ref,observed_at_utc
                   ) VALUES(?,?,?,?,?,?)""",
                    (uidvalidity, uid, message_key, evidence_sha256, evidence_ref, now),
                )
            changed = connection.execute(
                """UPDATE cursor SET last_uid=?,updated_at_utc=?
                   WHERE singleton=1 AND uidvalidity=? AND last_uid<?""",
                (uid, now, uidvalidity, uid),
            ).rowcount
            if changed != 1:
                raise LiveMailBitrixError("durable cursor did not advance atomically")
        return created

    def _bitrix_url(self, method: str) -> str:
        if method not in _BITRIX_METHODS:
            raise ValueError("Bitrix method is outside the live inbound allowlist")
        return f"{self._webhook}{method}.json"

    def _bitrix_call(self, method: str, payload: dict[str, Any], *, write: bool) -> Any:
        url = self._bitrix_url(method)
        try:
            raw_response = self._http_post(
                url,
                json=payload,
                timeout=25,
                allow_redirects=False,
            )
            response = _response_result(raw_response)
        except _BitrixCallError as error:
            if not write and not error.definite:
                raise _BitrixCallError(error.category, definite=True, retryable=True) from error
            raise
        except Exception as exc:
            raise _BitrixCallError("TRANSPORT", definite=not write, retryable=not write) from exc
        if response.redirected or 300 <= response.status_code < 400:
            raise _BitrixCallError("REDIRECT", definite=not write, retryable=False)
        body = response.payload
        if not isinstance(body, dict):
            raise _BitrixCallError("INVALID_JSON", definite=not write, retryable=not write)
        provider_error = _safe_token(body.get("error", ""), fallback="")
        if response.status_code == 429 or provider_error in {
            "QUERY_LIMIT_EXCEEDED",
            "TOO_MANY_REQUESTS",
            "OPERATION_TIME_LIMIT",
        }:
            raise _BitrixCallError("RATE_LIMIT", definite=True, retryable=True)
        if response.status_code >= 500:
            raise _BitrixCallError("SERVER_ERROR", definite=not write, retryable=not write)
        if response.status_code in {401, 403}:
            raise _BitrixCallError("AUTHORIZATION", definite=True, retryable=False)
        if response.status_code >= 400 or provider_error:
            raise _BitrixCallError(provider_error or "PROVIDER_REJECTION", definite=True, retryable=False)
        if "result" not in body:
            raise _BitrixCallError("MISSING_RESULT", definite=not write, retryable=not write)
        return body["result"]

    @staticmethod
    def _bitrix_fields(payload: Mapping[str, Any], *, origin_id: str) -> dict[str, Any]:
        source_id = _safe_token(payload.get("SOURCE_ID", "EMAIL"), fallback="EMAIL")
        if source_id not in {"CALL", "EMAIL", "FASAD_RU", "WEB"}:
            source_id = "EMAIL"
        responsible = str(payload.get("ASSIGNED_BY_ID", BITRIX_ASSIGNED_BY_ID)).strip()
        if not re.fullmatch(r"[1-9]\d{0,19}", responsible):
            responsible = str(BITRIX_ASSIGNED_BY_ID)
        fields: dict[str, Any] = {
            "TITLE": _header(payload.get("TITLE", ""), limit=255),
            "SOURCE_ID": source_id,
            "SOURCE_DESCRIPTION": _header(payload.get("SOURCE_DESCRIPTION", ""), limit=255),
            "ASSIGNED_BY_ID": int(responsible),
            "COMPANY_TITLE": _header(payload.get("COMPANY", ""), limit=255),
            "NAME": _header(payload.get("NAME", ""), limit=255),
            "COMMENTS": _clean_text(payload.get("COMMENTS", ""), limit=16_000),
            "ORIGINATOR_ID": ORIGINATOR_ID,
            "ORIGIN_ID": origin_id,
        }
        phone = _header(payload.get("PHONE", ""), limit=32)
        email_value = _header(payload.get("EMAIL", ""), limit=320).casefold()
        if phone:
            fields["PHONE"] = [{"VALUE": phone, "VALUE_TYPE": "WORK"}]
        if email_value and "@" in email_value:
            fields["EMAIL"] = [{"VALUE": email_value, "VALUE_TYPE": "WORK"}]
        return fields

    def _find_leads(self, origin_id: str) -> list[dict[str, Any]]:
        result = self._bitrix_call(
            "crm.lead.list",
            {
                "filter": {"ORIGINATOR_ID": ORIGINATOR_ID, "ORIGIN_ID": origin_id},
                "select": ["ID", "ORIGINATOR_ID", "ORIGIN_ID"],
                "order": {"ID": "ASC"},
            },
            write=False,
        )
        if not isinstance(result, list):
            raise _BitrixCallError("INVALID_LIST_RESULT", definite=True, retryable=False)
        return [item for item in result if isinstance(item, dict)]

    def _readback(
        self,
        remote_id: str,
        origin_id: str,
        expected_fields: Mapping[str, Any],
    ) -> bool:
        if not re.fullmatch(r"\d{1,20}", str(remote_id or "")):
            return False
        result = self._bitrix_call("crm.lead.get", {"id": str(remote_id)}, write=False)
        return bool(
            isinstance(result, dict)
            and str(result.get("ID", "")) == str(remote_id)
            and str(result.get("ORIGINATOR_ID", "")) == ORIGINATOR_ID
            and str(result.get("ORIGIN_ID", "")) == origin_id
            and _header(result.get("TITLE", ""), limit=255)
            == str(expected_fields.get("TITLE", ""))
            and str(result.get("SOURCE_ID", ""))
            == str(expected_fields.get("SOURCE_ID", ""))
            and str(result.get("ASSIGNED_BY_ID", ""))
            == str(expected_fields.get("ASSIGNED_BY_ID", ""))
            and _header(result.get("SOURCE_DESCRIPTION", ""), limit=255)
            == str(expected_fields.get("SOURCE_DESCRIPTION", ""))
            and _clean_text(result.get("COMMENTS", ""), limit=16_000)
            == str(expected_fields.get("COMMENTS", ""))
            and _header(result.get("COMPANY_TITLE", ""), limit=255)
            == str(expected_fields.get("COMPANY_TITLE", ""))
            and _header(result.get("NAME", ""), limit=255)
            == str(expected_fields.get("NAME", ""))
            and _bitrix_multifield_values(result.get("PHONE"), casefold=False)
            == _bitrix_multifield_values(expected_fields.get("PHONE"), casefold=False)
            and _bitrix_multifield_values(result.get("EMAIL"), casefold=True)
            == _bitrix_multifield_values(expected_fields.get("EMAIL"), casefold=True)
        )

    def preflight(self) -> dict[str, Any]:
        """Authenticate both providers with read-only operations only."""

        self.initialize()
        client: _ImapClient | None = None
        try:
            client = self._open_imap()
            validity = self._select_imap(client)
            uids = self._search(client, "ALL")
        finally:
            self._logout(client)
        smtp_client: Any = None
        try:
            smtp_client = self._smtp_factory(self._credentials)
            login_result = smtp_client.login(
                str(self._credentials.smtp_user), str(self._credentials.smtp_password)
            )
            if isinstance(login_result, tuple) and login_result:
                login_code = int(login_result[0])
                if not 200 <= login_code < 300:
                    raise RemotePreflightError(
                        "SMTP authentication failed",
                        retryable=400 <= login_code < 500,
                        code=(
                            "smtp_authentication_transient"
                            if 400 <= login_code < 500
                            else "smtp_authentication_failed"
                        ),
                    )
            noop_result = smtp_client.noop()
            noop_code = int(noop_result[0]) if isinstance(noop_result, tuple) else int(noop_result)
            if not 200 <= noop_code < 300:
                raise RemotePreflightError(
                    "SMTP NOOP failed",
                    retryable=400 <= noop_code < 500,
                    code=(
                        "smtp_noop_transient"
                        if 400 <= noop_code < 500
                        else "smtp_noop_failed"
                    ),
                )
        except RemotePreflightError:
            raise
        except smtplib.SMTPAuthenticationError as exc:
            smtp_code = int(getattr(exc, "smtp_code", 0) or 0)
            retryable = 400 <= smtp_code < 500
            raise RemotePreflightError(
                "SMTP authentication failed",
                retryable=retryable,
                code=(
                    "smtp_authentication_transient"
                    if retryable
                    else "smtp_authentication_failed"
                ),
            ) from exc
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, OSError) as exc:
            raise RemotePreflightError(
                "SMTP connection failed",
                retryable=True,
                code="smtp_transport_transient",
            ) from exc
        except smtplib.SMTPResponseException as exc:
            smtp_code = int(getattr(exc, "smtp_code", 0) or 0)
            retryable = 400 <= smtp_code < 500
            raise RemotePreflightError(
                "SMTP provider preflight failed",
                retryable=retryable,
                code="smtp_response_transient" if retryable else "smtp_response_failed",
            ) from exc
        except smtplib.SMTPException as exc:
            raise RemotePreflightError(
                "SMTP provider contract failed",
                code="smtp_contract_failed",
            ) from exc
        except Exception as exc:
            raise RemotePreflightError(
                "SMTP authentication preflight failed",
                code="smtp_contract_failed",
            ) from exc
        finally:
            if smtp_client is not None:
                try:
                    smtp_client.quit()
                except Exception:
                    try:
                        smtp_client.close()
                    except Exception:
                        pass
        fields = self._bitrix_call("crm.lead.fields", {}, write=False)
        required = {
            "TITLE",
            "SOURCE_ID",
            "SOURCE_DESCRIPTION",
            "ASSIGNED_BY_ID",
            "COMPANY_TITLE",
            "NAME",
            "PHONE",
            "EMAIL",
            "COMMENTS",
            "ORIGINATOR_ID",
            "ORIGIN_ID",
        }
        if not isinstance(fields, dict) or not required.issubset(fields):
            raise RemotePreflightError("Bitrix Lead field contract is incomplete")
        with closing(self._connect()) as connection:
            cursor = connection.execute("SELECT uidvalidity,last_uid FROM cursor WHERE singleton=1").fetchone()
        matches = cursor is None or str(cursor["uidvalidity"]) == validity
        if cursor is not None and not matches:
            raise UidValidityMismatch("IMAP UIDVALIDITY changed; cursor was not advanced")
        return {
            "ok": True,
            "status": "ready",
            "imap_readonly": True,
            "imap_uidvalidity": validity,
            "imap_message_count": len(uids),
            "imap_max_uid": max(uids, default=0),
            "cursor_bootstrapped": cursor is not None,
            "cursor_uidvalidity_matches": matches,
            "bitrix_readonly": True,
            "bitrix_required_fields": len(required),
            "smtp_authenticated": True,
            "smtp_noop": True,
            "smtp_send_enabled": False,
        }

    def poll_once(self, *, limit: int = 50, dispatch: bool = True) -> dict[str, Any]:
        """Persist one bounded, oldest-first UID batch and optionally dispatch it."""

        self.initialize()
        if not 1 <= int(limit) <= 200:
            raise ValueError("limit must be between 1 and 200")
        run_id = self._start_run("POLL")
        counters = {"selected": 0, "persisted": 0, "auto": 0, "review": 0, "handled": 0}
        try:
            with _RuntimeLock(self._lock_path):
                self._cleanup_evidence_temps()
                self._require_authority()
                with closing(self._connect()) as connection:
                    cursor = connection.execute(
                        """SELECT uidvalidity,last_uid,reconciliation_high_water_uid
                           FROM cursor WHERE singleton=1"""
                    ).fetchone()
                if cursor is None:
                    raise BootstrapRequired("explicit IMAP cursor bootstrap is required")
                expected_validity = str(cursor["uidvalidity"])
                after_uid = int(cursor["last_uid"])
                high_water = int(cursor["reconciliation_high_water_uid"])
                self._verify_protected_legacy_mapping()
                campaigns = self._load_protected_campaign_records()
                local_evidence = self._untracked_evidence(
                    uidvalidity=expected_validity,
                    last_uid=after_uid,
                )
                client: _ImapClient | None = None
                try:
                    client = self._open_imap()
                    observed_validity = self._select_imap(client)
                    if observed_validity != expected_validity:
                        raise UidValidityMismatch("IMAP UIDVALIDITY changed; cursor was not advanced")
                    mailbox_uids = self._search(
                        client, f"UID {after_uid + 1}:*", after_uid=after_uid
                    )
                    mailbox_uid_set = set(mailbox_uids)
                    selected = sorted(mailbox_uid_set | set(local_evidence))[
                        : int(limit)
                    ]
                    counters["selected"] = len(selected)
                    for uid in selected:
                        raw = local_evidence.get(uid)
                        if uid in mailbox_uid_set:
                            mailbox_raw = self._fetch(client, uid)
                            if raw is not None and _digest(raw) != _digest(mailbox_raw):
                                raise LiveMailBitrixError(
                                    "local MIME evidence conflicts with the mailbox UID"
                                )
                            raw = mailbox_raw
                        if raw is None:
                            raise LiveMailBitrixError(
                                "selected mailbox delivery has no MIME evidence"
                            )
                        evidence_ref, evidence_sha256 = self._persist_evidence(
                            uidvalidity=observed_validity, uid=uid, raw=raw
                        )
                        try:
                            parsed = _parse_mail(
                                raw,
                                expected_recipient=str(
                                    self._credentials.imap_user
                                ).strip().casefold(),
                            )
                        except _MailParseError:
                            parsed = _PARSE_REVIEW_PLACEHOLDER
                            route = _Route(
                                "LOCAL_PARSE_REVIEW",
                                "REVIEW",
                                None,
                            )
                        else:
                            route = self._route(
                                parsed,
                                campaigns,
                                uid=uid,
                                reconciliation_high_water_uid=high_water,
                            )
                        created = self._persist_message(
                            uidvalidity=observed_validity,
                            uid=uid,
                            raw=raw,
                            evidence_ref=evidence_ref,
                            evidence_sha256=evidence_sha256,
                            parsed=parsed,
                            route=route,
                        )
                        if created:
                            counters["persisted"] += 1
                            if route.state == "OUTBOX_PENDING":
                                counters["auto"] += 1
                            elif route.state == "ALREADY_HANDLED":
                                counters["handled"] += 1
                            else:
                                counters["review"] += 1
                finally:
                    self._logout(client)
            self._finish_run(run_id, state="SUCCESS", counters=counters)
        except Exception as exc:
            self._finish_run(run_id, state="FAILED", counters=counters, error=exc)
            raise
        dispatch_status: dict[str, Any] | None = None
        if dispatch:
            dispatch_status = self.dispatch_once(limit=min(int(limit), 50))
        result: dict[str, Any] = {"ok": True, "status": "success", **counters}
        if dispatch_status is not None:
            result["dispatch"] = {
                key: value
                for key, value in dispatch_status.items()
                if key
                in {
                    "ok",
                    "status",
                    "claimed",
                    "created",
                    "reconciled",
                    "retryable",
                    "uncertain",
                    "review",
                    "delivery_claimed",
                    "delivery_created",
                    "delivery_reconciled",
                    "delivery_retryable",
                    "delivery_uncertain",
                    "delivery_review",
                }
            }
        return result

    def _retry_time(self, attempt: int) -> str:
        seconds = min(3600, 15 * (2 ** max(0, min(int(attempt), 8) - 1)))
        return _iso(self._now() + timedelta(seconds=seconds))

    def _set_outbox_failure(
        self,
        operation_id: str,
        error: _BitrixCallError,
        *,
        create_may_have_run: bool,
    ) -> str:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT attempt_count,remote_lead_id,phase FROM crm_outbox "
                "WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            attempt = int(row["attempt_count"]) if row else 1
            acknowledged_create = bool(
                row
                and re.fullmatch(r"\d{1,20}", str(row["remote_lead_id"] or ""))
            )
            if create_may_have_run and (acknowledged_create or not error.definite):
                state = "UNCERTAIN"
                next_attempt = self._retry_time(attempt)
            elif error.retryable and attempt < _MAX_RETRIES:
                state = "RETRYABLE"
                next_attempt = self._retry_time(attempt)
            elif error.retryable:
                state = "RETRY_EXHAUSTED_REVIEW"
                next_attempt = ""
            else:
                state = "PERMANENT_REVIEW"
                next_attempt = ""
            phase = str(row["phase"]) if row else ""
            if create_may_have_run and error.definite and not acknowledged_create:
                phase = "DEFINITE_NO_CREATE"
            elif state == "UNCERTAIN":
                phase = "CREATE_DISPATCH"
            connection.execute(
                """UPDATE crm_outbox SET state=?,phase=?,next_attempt_at_utc=?,error_class=?,
                   error_digest=?,updated_at_utc=? WHERE operation_id=?""",
                (
                    state,
                    phase,
                    next_attempt,
                    error.category,
                    _digest(error.category),
                    _iso(self._now()),
                    operation_id,
                ),
            )
        return state

    def _set_outbox_review(self, operation_id: str, state: str) -> str:
        safe_state = _safe_token(state)
        with self._transaction() as connection:
            connection.execute(
                """UPDATE crm_outbox SET state=?,next_attempt_at_utc='',error_class=?,
                   error_digest=?,updated_at_utc=? WHERE operation_id=?""",
                (
                    safe_state,
                    safe_state,
                    _digest(safe_state),
                    _iso(self._now()),
                    operation_id,
                ),
            )
        return safe_state

    def _set_outbox_reconciliation_pending(self, operation_id: str) -> str:
        with self._transaction() as connection:
            current = connection.execute(
                "SELECT reconcile_count FROM crm_outbox WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            count = int(current["reconcile_count"]) + 1 if current else _MAX_RECONCILES
            state = (
                "MANUAL_RECONCILIATION_REVIEW"
                if count >= _MAX_RECONCILES
                else "UNCERTAIN"
            )
            connection.execute(
                """UPDATE crm_outbox SET state=?,reconcile_count=?,next_attempt_at_utc=?,
                   error_class='RECONCILIATION_PENDING',error_digest=?,updated_at_utc=?
                   WHERE operation_id=?""",
                (
                    state,
                    count,
                    "" if state != "UNCERTAIN" else self._retry_time(count),
                    _digest("RECONCILIATION_PENDING"),
                    _iso(self._now()),
                    operation_id,
                ),
            )
        return state

    def _complete_outbox(self, operation_id: str, remote_id: str, *, reconciled: bool) -> None:
        now = _iso(self._now())
        with self._transaction() as connection:
            row = connection.execute(
                """SELECT o.*,m.route AS persisted_route
                   FROM crm_outbox AS o
                   JOIN messages AS m ON m.message_key=o.message_key
                   WHERE o.operation_id=?""",
                (operation_id,),
            ).fetchone()
            if not row:
                raise LiveMailBitrixError("claimed CRM operation disappeared")
            connection.execute(
                """UPDATE crm_outbox SET state=?,phase='READBACK_VERIFIED',remote_lead_id=?,
                   next_attempt_at_utc='',error_class='',error_digest='',updated_at_utc=?
                   WHERE operation_id=?""",
                ("RECONCILED" if reconciled else "CREATED", str(remote_id), now, operation_id),
            )
            staged_row = dict(row)
            staged_row["remote_lead_id"] = str(remote_id)
            staged_row["updated_at_utc"] = now
            self._stage_delivery_outbox_tx(connection, staged_row)
            connection.execute(
                "UPDATE messages SET state='CRM_CREATED',updated_at_utc=? WHERE message_key=?",
                (now, row["message_key"]),
            )

    def _stage_delivery_outbox_tx(
        self,
        connection: sqlite3.Connection,
        parent: Mapping[str, Any],
    ) -> None:
        parent_operation_id = str(parent.get("operation_id", "") or "")
        message_key = str(parent.get("message_key", "") or "")
        origin_id = str(parent.get("origin_id", "") or "")
        remote_lead_id = str(parent.get("remote_lead_id", "") or "")
        if (
            not parent_operation_id
            or not message_key
            or not re.fullmatch(r"mail_[0-9a-f]{64}", message_key)
            or not re.fullmatch(r"mail_[0-9a-f]{56}", origin_id)
            or not re.fullmatch(r"\d{1,20}", remote_lead_id)
        ):
            raise LiveMailBitrixError("verified Lead cannot stage its CRM delivery")
        try:
            lead_payload = json.loads(str(parent.get("payload_json", "") or ""))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LiveMailBitrixError("verified Lead payload cannot stage CRM delivery") from exc
        if not isinstance(lead_payload, dict):
            raise LiveMailBitrixError("verified Lead payload cannot stage CRM delivery")
        try:
            anchor = _as_utc(
                datetime.fromisoformat(
                    str(parent.get("created_at_utc") or parent.get("updated_at_utc") or "")
                )
            )
        except (TypeError, ValueError):
            anchor = self._now()
        configured_assignee = self._assigned_by_id_tx(connection)
        responsible = str(
            lead_payload.get("ASSIGNED_BY_ID", configured_assignee)
        ).strip()
        if not re.fullmatch(r"[1-9]\d{0,19}", responsible):
            responsible = str(configured_assignee)
        route_row = connection.execute(
            "SELECT route FROM messages WHERE message_key=?",
            (message_key,),
        ).fetchone()
        if route_row is None:
            raise LiveMailBitrixError("verified Lead mailbox route is unavailable")
        route = _safe_token(route_row["route"], fallback="MAIL")
        action = _operator_action_for_route(route)
        if (
            _safe_token(lead_payload.get("LF_ROUTE", ""), fallback="") != route
            or _safe_token(lead_payload.get("OPERATOR_ACTION", ""), fallback="")
            != action
        ):
            raise LiveMailBitrixError(
                "verified Lead route projection conflicts with mailbox routing"
            )
        source = _header(lead_payload.get("SOURCE_DESCRIPTION", ""), limit=255)
        title = (
            "Проверить входящее письмо"
            if action == "REVIEW"
            else "Позвонить по входящему запросу"
        )
        deadline_minutes = 60 if action == "REVIEW" else 30
        timeline_marker = f"[LF-MAIL:{origin_id}]"
        todo_marker = f"[LF-TODO:{origin_id}]"
        timeline_body = _clean_text(
            lead_payload.get("COMMENTS", ""),
            limit=16_000 - len(timeline_marker) - 2,
        )
        timeline_comment = (
            f"{timeline_body}\n\n{timeline_marker}" if timeline_body else timeline_marker
        )
        records = (
            (
                "OPERATOR_TODO",
                todo_marker,
                {
                    "deadline": _iso(anchor + timedelta(minutes=deadline_minutes)),
                    "description": _clean_text(
                        f"Маршрут: {route}\nИсточник: {source}\n{todo_marker}",
                        limit=4_000,
                    ),
                    "pingOffsets": [0, 15],
                    "responsibleId": int(responsible),
                    "title": title,
                },
            ),
            (
                "TIMELINE_MAIL",
                timeline_marker,
                {
                    "attachment_policy": "LOCAL_QUARANTINE",
                    "comment": timeline_comment,
                    "include_evidence_attachments": False,
                },
            ),
        )
        created_at = str(parent.get("created_at_utc") or parent.get("updated_at_utc") or "")
        if not created_at:
            created_at = _iso(self._now())
        for operation_kind, marker, payload in records:
            delivery_id = "delivery_" + _digest(
                f"{parent_operation_id}|{operation_kind}"
            )[:55]
            payload_json = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                """INSERT OR IGNORE INTO crm_delivery_outbox(
                   delivery_id,parent_operation_id,message_key,operation_kind,
                   marker,payload_json,state,remote_lead_id,created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,'PENDING',?,?,?)""",
                (
                    delivery_id,
                    parent_operation_id,
                    message_key,
                    operation_kind,
                    marker,
                    payload_json,
                    remote_lead_id,
                    created_at,
                    created_at,
                ),
            )
            existing = connection.execute(
                "SELECT * FROM crm_delivery_outbox WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            if not existing or any(
                str(existing[key]) != expected
                for key, expected in {
                    "parent_operation_id": parent_operation_id,
                    "message_key": message_key,
                    "operation_kind": operation_kind,
                    "marker": marker,
                    "payload_json": payload_json,
                    "remote_lead_id": remote_lead_id,
                }.items()
            ):
                raise LiveMailBitrixError("CRM delivery identity conflicts with persisted state")

    def _stage_canary_delivery_tx(
        self,
        connection: sqlite3.Connection,
        *,
        authority_generation: int,
        remote_lead_id: str,
        origin_id: str,
    ) -> str:
        if (
            authority_generation < 1
            or not re.fullmatch(r"\d{1,20}", remote_lead_id)
            or not re.fullmatch(r"lf_canary_[0-9a-f]{48}", origin_id)
        ):
            raise LiveMailBitrixError("canary CRM delivery identity is invalid")
        parent_operation_id = (
            f"canary:{authority_generation}:{_digest(origin_id)[:32]}"
        )
        message_key = f"canary_{_digest(parent_operation_id)}"
        anchor = self._now()
        now = _iso(anchor)
        records = (
            (
                "OPERATOR_TODO",
                f"[LF-CANARY-TODO:{origin_id}]",
                {
                    "deadline": _iso(anchor + timedelta(minutes=5)),
                    "description": (
                        "[LF-CANARY][NO CONTACT] Technical CRM Todo canary. "
                        f"Do not contact anyone. [LF-CANARY-TODO:{origin_id}]"
                    ),
                    "pingOffsets": [],
                    "responsibleId": self._assigned_by_id_tx(connection),
                    "title": "[LF-CANARY][NO CONTACT] Проверка задачи",
                },
            ),
            (
                "TIMELINE_MAIL",
                f"[LF-CANARY-MAIL:{origin_id}]",
                {
                    "comment": (
                        "[LF-CANARY][NO CONTACT] Technical timeline canary. "
                        f"No customer contact. [LF-CANARY-MAIL:{origin_id}]"
                    ),
                    "include_evidence_attachments": False,
                },
            ),
        )
        for operation_kind, marker, payload in records:
            delivery_id = (
                "delivery_"
                + _digest(f"{parent_operation_id}|{operation_kind}")[:55]
            )
            payload_json = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute(
                """INSERT OR IGNORE INTO crm_delivery_outbox(
                   delivery_id,parent_operation_id,message_key,operation_kind,
                   marker,payload_json,state,remote_lead_id,created_at_utc,
                   updated_at_utc
               ) VALUES(?,?,?,?,?,?,'PENDING',?,?,?)""",
                (
                    delivery_id,
                    parent_operation_id,
                    message_key,
                    operation_kind,
                    marker,
                    payload_json,
                    remote_lead_id,
                    now,
                    now,
                ),
            )
            staged = connection.execute(
                "SELECT * FROM crm_delivery_outbox WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            if not staged or any(
                str(staged[key]) != str(expected)
                for key, expected in {
                    "parent_operation_id": parent_operation_id,
                    "message_key": message_key,
                    "operation_kind": operation_kind,
                    "marker": marker,
                    "remote_lead_id": remote_lead_id,
                }.items()
            ):
                raise LiveMailBitrixError("canary CRM delivery identity conflict")
            if not _canary_delivery_payload_valid(
                staged,
                assigned_by_id=self._assigned_by_id_tx(connection),
                origin_id=origin_id,
            ):
                raise LiveMailBitrixError("canary CRM delivery payload is invalid")
        return parent_operation_id

    def _verify_canary_deliveries(
        self,
        *,
        authority_generation: int,
        remote_lead_id: str,
        origin_id: str,
    ) -> dict[str, Any]:
        try:
            with self._transaction() as connection:
                parent_operation_id = self._stage_canary_delivery_tx(
                    connection,
                    authority_generation=authority_generation,
                    remote_lead_id=remote_lead_id,
                    origin_id=origin_id,
                )
        except LiveMailBitrixError:
            return {"ok": False, "reason": "canary_projection_payload_invalid"}
        with closing(self._connect()) as connection:
            before_rows = [
                dict(row)
                for row in connection.execute(
                    """SELECT * FROM crm_delivery_outbox
                       WHERE parent_operation_id=? ORDER BY operation_kind""",
                    (parent_operation_id,),
                ).fetchall()
            ]
        if (
            len(before_rows) != 2
            or {str(row["operation_kind"]) for row in before_rows}
            != {"OPERATOR_TODO", "TIMELINE_MAIL"}
        ):
            return {"ok": False, "reason": "canary_projection_shape_invalid"}
        missing_writes = 0
        for delivery in before_rows:
            try:
                found = self._find_delivery_remote(delivery)
            except _BitrixCallError:
                return {"ok": False, "reason": "canary_projection_query_failed"}
            if len(found) > 1:
                return {"ok": False, "reason": "canary_projection_duplicate"}
            if len(found) == 1:
                remote_id = str(found[0].get("ID", ""))
                stored_remote_id = str(delivery.get("remote_id", ""))
                if stored_remote_id and stored_remote_id != remote_id:
                    return {"ok": False, "reason": "canary_projection_identity_conflict"}
                try:
                    if not self._delivery_readback(delivery, remote_id):
                        return {"ok": False, "reason": "canary_projection_readback_mismatch"}
                except _BitrixCallError:
                    return {"ok": False, "reason": "canary_projection_readback_failed"}
                self._complete_delivery_outbox(
                    str(delivery["delivery_id"]),
                    remote_id,
                    reconciled=True,
                )
                continue
            state = str(delivery.get("state", ""))
            phase = str(delivery.get("phase", ""))
            stored_remote_id = str(delivery.get("remote_id", ""))
            if (
                stored_remote_id
                or state in {"CREATED", "RECONCILED"}
                or phase == "CREATE_DISPATCH"
                or not (
                    state in {"PENDING", "RETRYABLE"}
                    or (state == "UNCERTAIN" and phase == "PRECREATE_QUERY")
                )
            ):
                return {"ok": False, "reason": "canary_projection_missing_remote"}
            missing_writes += 1
        with self._transaction() as connection:
            if not self._authority_valid_tx(
                connection,
                expected_generation=authority_generation,
            ):
                return {"ok": False, "reason": "canary_authority_changed"}
            remaining = self._remaining_write_attempts_tx(connection)
        # Preserve one complete production Lead+Todo+Timeline bundle after the
        # connection canary, rather than proving the link while exhausting it.
        if remaining < missing_writes + 3:
            return {"ok": False, "reason": "insufficient_write_budget"}
        dispatched = self._dispatch_delivery_once(
            limit=2,
            authority_generation=authority_generation,
            parent_operation_id=parent_operation_id,
        )
        with closing(self._connect()) as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                """SELECT *
                   FROM crm_delivery_outbox WHERE parent_operation_id=?
                   ORDER BY operation_kind""",
                    (parent_operation_id,),
                ).fetchall()
            ]
        verified = len(rows) == 2
        for delivery in rows:
            if not verified:
                break
            remote_id = str(delivery.get("remote_id", ""))
            if (
                str(delivery.get("state", "")) not in {"CREATED", "RECONCILED"}
                or not re.fullmatch(r"\d{1,20}", remote_id)
            ):
                verified = False
                break
            try:
                found = self._find_delivery_remote(delivery)
                verified = bool(
                    len(found) == 1
                    and str(found[0].get("ID", "")) == remote_id
                    and self._delivery_readback(delivery, remote_id)
                )
            except _BitrixCallError:
                verified = False
        return {"ok": verified, **dispatched}

    def _find_delivery_remote(self, delivery: Mapping[str, Any]) -> list[dict[str, Any]]:
        operation_kind = str(delivery.get("operation_kind", ""))
        remote_lead_id = str(delivery.get("remote_lead_id", ""))
        marker = str(delivery.get("marker", ""))
        if not re.fullmatch(r"\d{1,20}", remote_lead_id) or not marker:
            raise _BitrixCallError("LOCAL_DELIVERY_IDENTITY", definite=True, retryable=False)
        matches: list[dict[str, Any]] = []
        for start in range(0, 250, 50):
            if operation_kind == "OPERATOR_TODO":
                result = self._bitrix_call(
                    "crm.activity.list",
                    {
                        "filter": {
                            "OWNER_TYPE_ID": 1,
                            "OWNER_ID": int(remote_lead_id),
                            "PROVIDER_ID": "CRM_TODO",
                        },
                        "select": [
                            "ID",
                            "OWNER_ID",
                            "OWNER_TYPE_ID",
                            "PROVIDER_ID",
                            "DESCRIPTION",
                        ],
                        "order": {"ID": "DESC"},
                        "start": start,
                    },
                    write=False,
                )
                text_field = "DESCRIPTION"
            elif operation_kind == "TIMELINE_MAIL":
                result = self._bitrix_call(
                    "crm.timeline.comment.list",
                    {
                        "filter": {
                            "ENTITY_ID": int(remote_lead_id),
                            "ENTITY_TYPE": "lead",
                        },
                        "select": ["ID", "ENTITY_ID", "ENTITY_TYPE", "COMMENT", "FILES"],
                        "order": {"ID": "DESC"},
                        "start": start,
                    },
                    write=False,
                )
                text_field = "COMMENT"
            else:
                raise _BitrixCallError("LOCAL_DELIVERY_KIND", definite=True, retryable=False)
            if not isinstance(result, list):
                raise _BitrixCallError("INVALID_LIST_RESULT", definite=True, retryable=False)
            for item in result:
                if isinstance(item, dict) and marker in str(item.get(text_field, "") or ""):
                    matches.append(item)
            if len(result) < 50:
                break
        return matches

    def _delivery_parent_identity_valid(
        self,
        delivery: Mapping[str, Any],
    ) -> bool | None:
        message_key = str(delivery.get("message_key", ""))
        parent_operation_id = str(delivery.get("parent_operation_id", ""))
        remote_lead_id = str(delivery.get("remote_lead_id", ""))
        if not re.fullmatch(r"\d{1,20}", remote_lead_id):
            return False
        with closing(self._connect()) as connection:
            if message_key.startswith("mail_"):
                parent = connection.execute(
                    """SELECT operation_id,message_key,originator_id,origin_id,
                              state,phase,remote_lead_id
                       FROM crm_outbox WHERE operation_id=? AND message_key=?""",
                    (parent_operation_id, message_key),
                ).fetchone()
                if parent is None:
                    return False
                origin_id = str(parent["origin_id"])
                if (
                    str(parent["originator_id"]) != ORIGINATOR_ID
                    or origin_id != "mail_" + _digest(message_key)[:56]
                    or str(parent["remote_lead_id"]) != remote_lead_id
                    or str(parent["state"]) not in {"CREATED", "RECONCILED"}
                    or str(parent["phase"]) != "READBACK_VERIFIED"
                ):
                    return False
            elif message_key.startswith("canary_"):
                values = {
                    str(row["key"]): str(row["value"])
                    for row in connection.execute(
                        """SELECT key,value FROM meta WHERE key IN (
                           'bitrix_canary_origin_id','bitrix_canary_remote_id',
                           'bitrix_canary_origin_authority_generation')"""
                    ).fetchall()
                }
                origin_id = values.get("bitrix_canary_origin_id", "")
                generation = values.get(
                    "bitrix_canary_origin_authority_generation", ""
                )
                expected_parent = (
                    f"canary:{generation}:{_digest(origin_id)[:32]}"
                )
                if (
                    not re.fullmatch(r"lf_canary_[0-9a-f]{48}", origin_id)
                    or not re.fullmatch(r"[1-9]\d*", generation)
                    or values.get("bitrix_canary_remote_id", "")
                    != remote_lead_id
                    or parent_operation_id != expected_parent
                    or message_key != f"canary_{_digest(expected_parent)}"
                ):
                    return False
            else:
                return False
        result = self._bitrix_call(
            "crm.lead.get",
            {"id": remote_lead_id},
            write=False,
        )
        if not isinstance(result, dict) or not str(result.get("ID", "")):
            return None
        if not (
            str(result.get("ID", "")) == remote_lead_id
            and str(result.get("ORIGINATOR_ID", "")) == ORIGINATOR_ID
            and str(result.get("ORIGIN_ID", "")) == origin_id
        ):
            return False
        matching_leads = self._find_leads(origin_id)
        for _attempt in range(2):
            if matching_leads:
                break
            matching_leads = self._find_leads(origin_id)
        if len(matching_leads) > 1:
            raise _BitrixCallError(
                "PARENT_LEAD_DUPLICATE",
                definite=True,
                retryable=False,
            )
        if not matching_leads:
            return None
        listed_parent = matching_leads[0]
        if (
            str(listed_parent.get("ID", "")) != remote_lead_id
            or str(listed_parent.get("ORIGINATOR_ID", "")) != ORIGINATOR_ID
            or str(listed_parent.get("ORIGIN_ID", "")) != origin_id
        ):
            return False
        return True

    def _delivery_readback(self, delivery: Mapping[str, Any], remote_id: str) -> bool:
        if not re.fullmatch(r"\d{1,20}", str(remote_id or "")):
            return False
        operation_kind = str(delivery.get("operation_kind", ""))
        remote_lead_id = str(delivery.get("remote_lead_id", ""))
        marker = str(delivery.get("marker", ""))
        try:
            payload = json.loads(str(delivery.get("payload_json", "")))
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(payload, dict):
            return False
        if operation_kind == "OPERATOR_TODO":
            result = self._bitrix_call(
                "crm.activity.get",
                {"id": str(remote_id)},
                write=False,
            )
            expected_title = _header(payload.get("title", ""), limit=255)
            expected_description = _clean_text(
                payload.get("description", ""), limit=4_000
            )
            expected_responsible = str(payload.get("responsibleId", ""))
            return bool(
                isinstance(result, dict)
                and str(result.get("ID", "")) == str(remote_id)
                and str(result.get("OWNER_ID", "")) == remote_lead_id
                and str(result.get("OWNER_TYPE_ID", "")) == "1"
                and str(result.get("PROVIDER_ID", "")) == "CRM_TODO"
                and _header(result.get("SUBJECT", ""), limit=255) == expected_title
                and _clean_text(result.get("DESCRIPTION", ""), limit=4_000)
                == expected_description
                and marker in expected_description
                and str(result.get("RESPONSIBLE_ID", "")) == expected_responsible
                and _same_instant(result.get("DEADLINE", ""), payload.get("deadline", ""))
            )
        if operation_kind == "TIMELINE_MAIL":
            result = self._bitrix_call(
                "crm.timeline.comment.get",
                {"id": str(remote_id)},
                write=False,
            )
            try:
                expected_fields = self._timeline_add_fields(delivery, payload)
            except (OSError, RuntimeError, TypeError, ValueError):
                return False
            expected_files = expected_fields.get("FILES", [])
            expected_names = tuple(
                sorted(
                    (Path(str(item[0])).name for item in expected_files),
                    key=str.casefold,
                )
            )
            return bool(
                isinstance(result, dict)
                and str(result.get("ID", "")) == str(remote_id)
                and str(result.get("ENTITY_ID", "")) == remote_lead_id
                and str(result.get("ENTITY_TYPE", "")).casefold() == "lead"
                and _clean_text(result.get("COMMENT", ""), limit=16_000)
                == str(expected_fields["COMMENT"])
                and marker in str(expected_fields["COMMENT"])
                and _remote_attachment_names(result.get("FILES")) == expected_names
            )
        return False

    def _timeline_add_fields(
        self,
        delivery: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        remote_lead_id = str(delivery.get("remote_lead_id", ""))
        comment = _clean_text(payload.get("comment", ""), limit=16_000)
        if not comment:
            raise ValueError("timeline comment is empty")
        if payload.get("include_evidence_attachments") is True:
            raise ValueError("automatic remote evidence attachments are disabled")
        fields: dict[str, Any] = {
            "ENTITY_TYPE": "lead",
            "ENTITY_ID": int(remote_lead_id),
            "COMMENT": comment,
        }
        return fields

    def _set_delivery_failure(
        self,
        delivery_id: str,
        error: _BitrixCallError,
        *,
        create_may_have_run: bool,
    ) -> str:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT attempt_count,remote_id,phase FROM crm_delivery_outbox "
                "WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            attempt = int(row["attempt_count"]) if row else 1
            acknowledged_create = bool(
                row and re.fullmatch(r"\d{1,20}", str(row["remote_id"] or ""))
            )
            if create_may_have_run and (acknowledged_create or not error.definite):
                state = "UNCERTAIN"
                next_attempt = self._retry_time(attempt)
            elif error.retryable and attempt < _MAX_RETRIES:
                state = "RETRYABLE"
                next_attempt = self._retry_time(attempt)
            elif error.retryable:
                state = "RETRY_EXHAUSTED_REVIEW"
                next_attempt = ""
            else:
                state = "PERMANENT_REVIEW"
                next_attempt = ""
            phase = str(row["phase"]) if row else ""
            if create_may_have_run and error.definite and not acknowledged_create:
                phase = "DEFINITE_NO_CREATE"
            elif state == "UNCERTAIN":
                phase = "CREATE_DISPATCH"
            connection.execute(
                """UPDATE crm_delivery_outbox SET state=?,phase=?,next_attempt_at_utc=?,
                   error_class=?,error_digest=?,updated_at_utc=? WHERE delivery_id=?""",
                (
                    state,
                    phase,
                    next_attempt,
                    error.category,
                    _digest(error.category),
                    _iso(self._now()),
                    delivery_id,
                ),
            )
        return state

    def _set_delivery_review(self, delivery_id: str, state: str) -> str:
        safe_state = _safe_token(state)
        with self._transaction() as connection:
            connection.execute(
                """UPDATE crm_delivery_outbox SET state=?,next_attempt_at_utc='',
                   error_class=?,error_digest=?,updated_at_utc=? WHERE delivery_id=?""",
                (
                    safe_state,
                    safe_state,
                    _digest(safe_state),
                    _iso(self._now()),
                    delivery_id,
                ),
            )
        return safe_state

    def _set_delivery_reconciliation_pending(self, delivery_id: str) -> str:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT reconcile_count FROM crm_delivery_outbox WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            count = int(row["reconcile_count"]) + 1 if row else _MAX_RECONCILES
            state = "MANUAL_RECONCILIATION_REVIEW" if count >= _MAX_RECONCILES else "UNCERTAIN"
            connection.execute(
                """UPDATE crm_delivery_outbox SET state=?,reconcile_count=?,
                   next_attempt_at_utc=?,error_class='RECONCILIATION_PENDING',
                   error_digest=?,updated_at_utc=? WHERE delivery_id=?""",
                (
                    state,
                    count,
                    "" if state != "UNCERTAIN" else self._retry_time(count),
                    _digest("RECONCILIATION_PENDING"),
                    _iso(self._now()),
                    delivery_id,
                ),
            )
        return state

    def _complete_delivery_outbox(
        self,
        delivery_id: str,
        remote_id: str,
        *,
        reconciled: bool,
    ) -> None:
        now = _iso(self._now())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT message_key FROM crm_delivery_outbox WHERE delivery_id=?",
                (delivery_id,),
            ).fetchone()
            if not row:
                raise LiveMailBitrixError("claimed CRM delivery disappeared")
            connection.execute(
                """UPDATE crm_delivery_outbox SET state=?,phase='READBACK_VERIFIED',
                   remote_id=?,next_attempt_at_utc='',error_class='',error_digest='',
                   updated_at_utc=? WHERE delivery_id=?""",
                (
                    "RECONCILED" if reconciled else "CREATED",
                    str(remote_id),
                    now,
                    delivery_id,
                ),
            )
            remaining = connection.execute(
                """SELECT COUNT(*) FROM crm_delivery_outbox
                   WHERE message_key=? AND state NOT IN ('CREATED','RECONCILED')""",
                (row["message_key"],),
            ).fetchone()[0]
            if int(remaining) == 0 and re.fullmatch(
                r"mail_[0-9a-f]{64}", str(row["message_key"])
            ):
                connection.execute(
                    "UPDATE messages SET state='CRM_READY',updated_at_utc=? WHERE message_key=?",
                    (now, row["message_key"]),
                )

    def _dispatch_delivery_operation(
        self,
        delivery: Mapping[str, Any],
        *,
        authority_generation: int,
    ) -> str:
        delivery_id = str(delivery["delivery_id"])
        message_key = str(delivery.get("message_key", ""))
        evidence_intact = bool(
            not message_key.startswith("mail_")
            or self._message_evidence_intact(message_key)
        )
        prior_phase = str(delivery.get("phase", ""))
        stored_remote_id = str(delivery.get("remote_id", ""))
        try:
            found = self._find_delivery_remote(delivery)
        except _BitrixCallError as error:
            if prior_phase == "CREATE_DISPATCH" or stored_remote_id:
                return self._set_delivery_reconciliation_pending(delivery_id)
            if not evidence_intact:
                return self._set_delivery_review(
                    delivery_id, "EVIDENCE_INTEGRITY_REVIEW"
                )
            return self._set_delivery_failure(
                delivery_id,
                error,
                create_may_have_run=False,
            )
        if len(found) > 1:
            return self._set_delivery_review(delivery_id, "DUPLICATE_MARKER_REVIEW")
        if len(found) == 1:
            remote_id = str(found[0].get("ID", ""))
            if not re.fullmatch(r"\d{1,20}", remote_id):
                return self._set_delivery_review(
                    delivery_id, "REMOTE_IDENTITY_REVIEW"
                )
            if stored_remote_id and stored_remote_id != remote_id:
                return self._set_delivery_review(
                    delivery_id, "IDENTITY_CONFLICT_REVIEW"
                )
            with self._transaction() as connection:
                connection.execute(
                    "UPDATE crm_delivery_outbox SET remote_id=?,phase='CREATE_DISPATCH',"
                    "updated_at_utc=? "
                    "WHERE delivery_id=?",
                    (remote_id, _iso(self._now()), delivery_id),
                )
            try:
                verified = self._delivery_readback(delivery, remote_id)
            except _BitrixCallError:
                return self._set_delivery_reconciliation_pending(delivery_id)
            if not verified:
                return self._set_delivery_reconciliation_pending(delivery_id)
            if not evidence_intact:
                return self._set_delivery_review(
                    delivery_id, "EVIDENCE_INTEGRITY_REVIEW"
                )
            self._complete_delivery_outbox(delivery_id, remote_id, reconciled=True)
            return "RECONCILED"
        if stored_remote_id:
            try:
                verified = self._delivery_readback(delivery, stored_remote_id)
            except _BitrixCallError:
                return self._set_delivery_reconciliation_pending(delivery_id)
            if not verified:
                return self._set_delivery_reconciliation_pending(delivery_id)
            if not evidence_intact:
                return self._set_delivery_review(
                    delivery_id, "EVIDENCE_INTEGRITY_REVIEW"
                )
            self._complete_delivery_outbox(
                delivery_id, stored_remote_id, reconciled=True
            )
            return "RECONCILED"
        if prior_phase == "CREATE_DISPATCH":
            return self._set_delivery_reconciliation_pending(delivery_id)
        if not evidence_intact:
            return self._set_delivery_review(
                delivery_id, "EVIDENCE_INTEGRITY_REVIEW"
            )
        try:
            payload = json.loads(str(delivery["payload_json"]))
            if not isinstance(payload, dict):
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError):
            return self._set_delivery_review(delivery_id, "LOCAL_PAYLOAD_REVIEW")
        try:
            parent_valid = self._delivery_parent_identity_valid(delivery)
        except _BitrixCallError as error:
            if error.category == "PARENT_LEAD_DUPLICATE":
                return self._set_delivery_review(
                    delivery_id,
                    "PARENT_LEAD_DUPLICATE_REVIEW",
                )
            return self._set_delivery_failure(
                delivery_id,
                error,
                create_may_have_run=False,
            )
        if parent_valid is None:
            not_visible = _BitrixCallError(
                "PARENT_LEAD_NOT_VISIBLE",
                definite=True,
                retryable=True,
            )
            return self._set_delivery_failure(
                delivery_id,
                not_visible,
                create_may_have_run=False,
            )
        if not parent_valid:
            return self._set_delivery_review(
                delivery_id, "PARENT_LEAD_IDENTITY_REVIEW"
            )
        try:
            with self._transaction() as connection:
                self._consume_write_attempt_tx(
                    connection,
                    expected_generation=authority_generation,
                )
                changed = connection.execute(
                    """UPDATE crm_delivery_outbox SET phase='CREATE_DISPATCH',
                       updated_at_utc=? WHERE delivery_id=? AND state='UNCERTAIN'
                         AND phase='PRECREATE_QUERY'""",
                    (_iso(self._now()), delivery_id),
                ).rowcount
                if changed != 1:
                    raise LiveMailBitrixError(
                        "CRM delivery changed before create dispatch"
                    )
        except BitrixWriteBudgetExhausted:
            permit_error = _BitrixCallError(
                "WRITE_PERMIT_UNAVAILABLE",
                definite=True,
                retryable=True,
            )
            return self._set_delivery_failure(
                delivery_id,
                permit_error,
                create_may_have_run=False,
            )
        try:
            if str(delivery["operation_kind"]) == "OPERATOR_TODO":
                result = self._bitrix_call(
                    "crm.activity.todo.add",
                    {
                        "ownerTypeId": 1,
                        "ownerId": int(str(delivery["remote_lead_id"])),
                        **payload,
                    },
                    write=True,
                )
            elif str(delivery["operation_kind"]) == "TIMELINE_MAIL":
                result = self._bitrix_call(
                    "crm.timeline.comment.add",
                    {"fields": self._timeline_add_fields(delivery, payload)},
                    write=True,
                )
            else:
                raise ValueError
        except _BitrixCallError as error:
            return self._set_delivery_failure(
                delivery_id,
                error,
                create_may_have_run=True,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return self._set_delivery_review(delivery_id, "LOCAL_DELIVERY_REVIEW")
        if isinstance(result, dict):
            remote_id = str(result.get("id", result.get("ID", "")))
        else:
            remote_id = str(result)
        if not re.fullmatch(r"\d{1,20}", remote_id):
            invalid = _BitrixCallError("INVALID_CREATE_RESULT", definite=False, retryable=False)
            return self._set_delivery_failure(
                delivery_id,
                invalid,
                create_may_have_run=True,
            )
        if stored_remote_id and stored_remote_id != remote_id:
            return self._set_delivery_review(delivery_id, "IDENTITY_CONFLICT_REVIEW")
        with self._transaction() as connection:
            connection.execute(
                "UPDATE crm_delivery_outbox SET remote_id=?,updated_at_utc=? WHERE delivery_id=?",
                (remote_id, _iso(self._now()), delivery_id),
            )
        try:
            verified = self._delivery_readback(delivery, remote_id)
        except _BitrixCallError:
            return self._set_delivery_reconciliation_pending(delivery_id)
        if not verified:
            return self._set_delivery_reconciliation_pending(delivery_id)
        self._complete_delivery_outbox(delivery_id, remote_id, reconciled=False)
        return "CREATED"

    def _dispatch_delivery_once(
        self,
        *,
        limit: int,
        authority_generation: int,
        parent_operation_id: str = "",
        reconciliation_only: bool = False,
    ) -> dict[str, int]:
        counters = {
            "claimed": 0,
            "created": 0,
            "reconciled": 0,
            "retryable": 0,
            "uncertain": 0,
            "review": 0,
        }
        for _ in range(max(0, int(limit))):
            now = _iso(self._now())
            with self._transaction() as connection:
                params: list[Any] = [now]
                parent_filter = ""
                if parent_operation_id:
                    parent_filter = " AND parent_operation_id=?"
                    params.append(parent_operation_id)
                else:
                    parent_filter = " AND message_key LIKE 'mail_%'"
                reconciliation_filter = ""
                if reconciliation_only:
                    reconciliation_filter = (
                        " AND (remote_id<>'' OR "
                        "(state='UNCERTAIN' AND phase='CREATE_DISPATCH'))"
                    )
                row = connection.execute(
                    """SELECT * FROM crm_delivery_outbox
                       WHERE state IN ('PENDING','RETRYABLE','UNCERTAIN')
                         AND (next_attempt_at_utc='' OR next_attempt_at_utc<=?)"""
                    + parent_filter
                    + reconciliation_filter
                    + " ORDER BY CASE operation_kind WHEN 'OPERATOR_TODO' THEN 0 ELSE 1 END,"
                    "created_at_utc,delivery_id LIMIT 1",
                    tuple(params),
                ).fetchone()
                if row is None:
                    break
                operation = dict(row)
                if str(row["state"]) in {"PENDING", "RETRYABLE"}:
                    changed = connection.execute(
                        """UPDATE crm_delivery_outbox SET state='UNCERTAIN',
                           phase='PRECREATE_QUERY',attempt_count=attempt_count+1,
                           updated_at_utc=? WHERE delivery_id=?
                             AND state IN ('PENDING','RETRYABLE')""",
                        (_iso(self._now()), row["delivery_id"]),
                    ).rowcount
                    if changed != 1:
                        continue
                    operation["state"] = "UNCERTAIN"
                    operation["phase"] = "PRECREATE_QUERY"
                    operation["attempt_count"] = int(row["attempt_count"]) + 1
            counters["claimed"] += 1
            state = self._dispatch_delivery_operation(
                operation,
                authority_generation=authority_generation,
            )
            if state == "CREATED":
                counters["created"] += 1
            elif state == "RECONCILED":
                counters["reconciled"] += 1
            elif state == "RETRYABLE":
                counters["retryable"] += 1
            elif state == "UNCERTAIN":
                counters["uncertain"] += 1
            else:
                counters["review"] += 1
        return counters

    def _dispatch_delivery_bundles(
        self,
        *,
        limit: int,
        authority_generation: int,
    ) -> dict[str, int]:
        counters = {
            "claimed": 0,
            "created": 0,
            "reconciled": 0,
            "retryable": 0,
            "uncertain": 0,
            "review": 0,
        }
        reconciliation = self._dispatch_delivery_once(
            limit=max(0, int(limit)),
            authority_generation=authority_generation,
            reconciliation_only=True,
        )
        for key, value in reconciliation.items():
            counters[key] += value
        remaining_limit = max(0, int(limit) - reconciliation["claimed"])
        for _ in range(remaining_limit):
            now = _iso(self._now())
            with self._transaction() as connection:
                parent = connection.execute(
                    """SELECT d.parent_operation_id,MIN(d.created_at_utc) AS oldest,
                              MIN(m.uid) AS oldest_uid,
                              COUNT(*) AS unresolved,
                              SUM(CASE
                                  WHEN d.remote_id<>'' OR (
                                      d.state='UNCERTAIN' AND d.phase='CREATE_DISPATCH'
                                  ) THEN 0
                                  ELSE 1 END) AS writes_required
                       FROM crm_delivery_outbox AS d
                       LEFT JOIN messages AS m ON m.message_key=d.message_key
                       WHERE d.state IN ('PENDING','RETRYABLE','UNCERTAIN')
                         AND d.message_key LIKE 'mail_%'
                          AND (d.next_attempt_at_utc='' OR d.next_attempt_at_utc<=?)
                       GROUP BY d.parent_operation_id
                       ORDER BY oldest,oldest_uid,d.parent_operation_id LIMIT 1""",
                    (now,),
                ).fetchone()
                remaining = self._remaining_write_attempts_tx(connection)
            if parent is None:
                break
            unresolved = int(parent["unresolved"])
            writes_required = int(parent["writes_required"] or 0)
            if unresolved < 1 or writes_required > remaining:
                break
            result = self._dispatch_delivery_once(
                limit=unresolved,
                authority_generation=authority_generation,
                parent_operation_id=str(parent["parent_operation_id"]),
            )
            for key, value in result.items():
                counters[key] += value
        return counters

    def _dispatch_operation(
        self,
        operation: Mapping[str, Any],
        *,
        authority_generation: int,
    ) -> str:
        operation_id = str(operation["operation_id"])
        origin_id = str(operation["origin_id"])
        prior_phase = str(operation.get("phase", ""))
        stored_remote_id = str(operation.get("remote_lead_id", ""))
        evidence_intact = self._message_evidence_intact(
            str(operation.get("message_key", ""))
        )
        try:
            local_payload = json.loads(str(operation["payload_json"]))
            if not isinstance(local_payload, dict):
                raise ValueError
            local_payload["ASSIGNED_BY_ID"] = self._assigned_by_id()
            fields = self._bitrix_fields(local_payload, origin_id=origin_id)
        except (ValueError, TypeError, json.JSONDecodeError):
            return self._set_outbox_review(operation_id, "LOCAL_PAYLOAD_REVIEW")
        try:
            found = self._find_leads(origin_id)
        except _BitrixCallError as error:
            if prior_phase == "CREATE_DISPATCH" or stored_remote_id:
                return self._set_outbox_reconciliation_pending(operation_id)
            if not evidence_intact:
                return self._set_outbox_review(
                    operation_id, "EVIDENCE_INTEGRITY_REVIEW"
                )
            return self._set_outbox_failure(
                operation_id, error, create_may_have_run=False
            )
        if len(found) > 1:
            conflict = _BitrixCallError("DUPLICATE_ORIGIN", definite=True, retryable=False)
            return self._set_outbox_failure(operation_id, conflict, create_may_have_run=False)
        if len(found) == 1:
            remote_id = str(found[0].get("ID", ""))
            if not re.fullmatch(r"\d{1,20}", remote_id):
                return self._set_outbox_review(
                    operation_id, "REMOTE_IDENTITY_REVIEW"
                )
            if stored_remote_id and stored_remote_id != remote_id:
                return self._set_outbox_review(
                    operation_id, "IDENTITY_CONFLICT_REVIEW"
                )
            with self._transaction() as connection:
                connection.execute(
                    "UPDATE crm_outbox SET remote_lead_id=?,phase='CREATE_DISPATCH',"
                    "updated_at_utc=? "
                    "WHERE operation_id=?",
                    (remote_id, _iso(self._now()), operation_id),
                )
            try:
                verified = self._readback(remote_id, origin_id, fields)
            except _BitrixCallError as error:
                return self._set_outbox_failure(
                    operation_id, error, create_may_have_run=True
                )
            if not verified:
                mismatch = _BitrixCallError("READBACK_MISMATCH", definite=False, retryable=False)
                return self._set_outbox_failure(
                    operation_id, mismatch, create_may_have_run=True
                )
            if not evidence_intact:
                return self._set_outbox_review(
                    operation_id, "EVIDENCE_INTEGRITY_REVIEW"
                )
            self._complete_outbox(operation_id, remote_id, reconciled=True)
            return "RECONCILED"
        if stored_remote_id:
            try:
                verified = self._readback(
                    stored_remote_id,
                    origin_id,
                    fields,
                )
            except _BitrixCallError:
                return self._set_outbox_reconciliation_pending(operation_id)
            if not verified:
                return self._set_outbox_reconciliation_pending(operation_id)
            if not evidence_intact:
                return self._set_outbox_review(
                    operation_id, "EVIDENCE_INTEGRITY_REVIEW"
                )
            self._complete_outbox(
                operation_id, stored_remote_id, reconciled=True
            )
            return "RECONCILED"
        if prior_phase == "CREATE_DISPATCH":
            return self._set_outbox_reconciliation_pending(operation_id)
        if not evidence_intact:
            return self._set_outbox_review(
                operation_id, "EVIDENCE_INTEGRITY_REVIEW"
            )
        # One authenticated Facade request is one commercial opportunity.
        # Customer e-mail is a contact attribute, not an idempotency key: the
        # same buyer can submit multiple distinct requests.  Replay safety is
        # provided by the deterministic message-derived ORIGIN_ID above.
        try:
            with self._transaction() as connection:
                self._consume_write_attempt_tx(
                    connection,
                    expected_generation=authority_generation,
                )
                changed = connection.execute(
                    """UPDATE crm_outbox SET phase='CREATE_DISPATCH',updated_at_utc=?
                       WHERE operation_id=? AND state='UNCERTAIN'
                         AND phase='PRECREATE_QUERY'""",
                    (_iso(self._now()), operation_id),
                ).rowcount
                if changed != 1:
                    raise LiveMailBitrixError(
                        "CRM operation changed before create dispatch"
                    )
        except BitrixWriteBudgetExhausted:
            permit_error = _BitrixCallError(
                "WRITE_PERMIT_UNAVAILABLE",
                definite=True,
                retryable=True,
            )
            return self._set_outbox_failure(
                operation_id,
                permit_error,
                create_may_have_run=False,
            )
        try:
            result = self._bitrix_call(
                "crm.lead.add",
                {"fields": fields, "params": {"REGISTER_SONET_EVENT": "Y"}},
                write=True,
            )
        except _BitrixCallError as error:
            return self._set_outbox_failure(operation_id, error, create_may_have_run=True)
        except (ValueError, TypeError, json.JSONDecodeError):
            malformed = _BitrixCallError("LOCAL_PAYLOAD", definite=True, retryable=False)
            return self._set_outbox_failure(operation_id, malformed, create_may_have_run=False)
        remote_id = ""
        if isinstance(result, (str, int)):
            remote_id = str(result)
        elif isinstance(result, dict):
            remote_id = str(result.get("ID", result.get("id", "")))
        if not re.fullmatch(r"\d{1,20}", remote_id):
            invalid = _BitrixCallError("INVALID_CREATE_RESULT", definite=False, retryable=False)
            return self._set_outbox_failure(operation_id, invalid, create_may_have_run=True)
        if stored_remote_id and stored_remote_id != remote_id:
            return self._set_outbox_review(operation_id, "IDENTITY_CONFLICT_REVIEW")
        with self._transaction() as connection:
            connection.execute(
                "UPDATE crm_outbox SET remote_lead_id=?,updated_at_utc=? WHERE operation_id=?",
                (remote_id, _iso(self._now()), operation_id),
            )
        try:
            verified = self._readback(remote_id, origin_id, fields)
        except _BitrixCallError as error:
            return self._set_outbox_failure(operation_id, error, create_may_have_run=True)
        if not verified:
            mismatch = _BitrixCallError("READBACK_MISMATCH", definite=False, retryable=False)
            return self._set_outbox_failure(operation_id, mismatch, create_may_have_run=True)
        self._complete_outbox(operation_id, remote_id, reconciled=False)
        return "CREATED"

    def _reconcile_uncertain(self, *, limit: int) -> dict[str, int]:
        counts = {"reconciled": 0, "uncertain": 0, "review": 0}
        now = _iso(self._now())
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT * FROM crm_outbox WHERE state='UNCERTAIN'
                   AND (next_attempt_at_utc='' OR next_attempt_at_utc<=?)
                   ORDER BY created_at_utc,operation_id LIMIT ?""",
                (now, int(limit)),
            ).fetchall()
        for row in rows:
            operation = dict(row)
            evidence_intact = self._message_evidence_intact(
                str(operation.get("message_key", ""))
            )
            if str(operation.get("phase", "")) == "PRECREATE_QUERY":
                if not evidence_intact:
                    self._set_outbox_review(
                        str(operation["operation_id"]),
                        "EVIDENCE_INTEGRITY_REVIEW",
                    )
                    counts["review"] += 1
                    continue
                # The process died before any create request could have been
                # dispatched.  Returning this row to the normal safe path is
                # not a blind retry of a write.
                with self._transaction() as connection:
                    connection.execute(
                        """UPDATE crm_outbox SET state='RETRYABLE',phase='CRASH_RECOVERED',
                           next_attempt_at_utc='',error_class='PRECREATE_CRASH_RECOVERED',
                           error_digest=?,updated_at_utc=?
                           WHERE operation_id=? AND state='UNCERTAIN'
                             AND phase='PRECREATE_QUERY'""",
                        (
                            _digest("PRECREATE_CRASH_RECOVERED"),
                            _iso(self._now()),
                            operation["operation_id"],
                        ),
                    )
                continue
            try:
                payload = json.loads(str(operation["payload_json"]))
                if not isinstance(payload, dict):
                    raise ValueError
                payload["ASSIGNED_BY_ID"] = self._assigned_by_id()
                expected_fields = self._bitrix_fields(
                    payload,
                    origin_id=str(operation["origin_id"]),
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                self._set_outbox_review(
                    str(operation["operation_id"]), "LOCAL_PAYLOAD_REVIEW"
                )
                counts["review"] += 1
                continue
            try:
                found = self._find_leads(str(operation["origin_id"]))
            except _BitrixCallError:
                state = self._set_outbox_reconciliation_pending(
                    str(operation["operation_id"])
                )
                counts["uncertain" if state == "UNCERTAIN" else "review"] += 1
                continue
            if len(found) > 1:
                self._set_outbox_review(
                    str(operation["operation_id"]),
                    "DUPLICATE_ORIGIN_REVIEW",
                )
                counts["review"] += 1
                continue
            if len(found) == 1:
                remote_id = str(found[0].get("ID", ""))
                if not re.fullmatch(r"\d{1,20}", remote_id):
                    self._set_outbox_review(
                        str(operation["operation_id"]),
                        "REMOTE_IDENTITY_REVIEW",
                    )
                    counts["review"] += 1
                    continue
                stored_remote_id = str(operation.get("remote_lead_id", ""))
                if stored_remote_id and stored_remote_id != remote_id:
                    self._set_outbox_review(
                        str(operation["operation_id"]),
                        "IDENTITY_CONFLICT_REVIEW",
                    )
                    counts["review"] += 1
                    continue
                with self._transaction() as connection:
                    connection.execute(
                        "UPDATE crm_outbox SET remote_lead_id=?,phase='CREATE_DISPATCH',"
                        "updated_at_utc=? "
                        "WHERE operation_id=?",
                        (
                            remote_id,
                            _iso(self._now()),
                            operation["operation_id"],
                        ),
                    )
                try:
                    verified = self._readback(
                        remote_id,
                        str(operation["origin_id"]),
                        expected_fields,
                    )
                except _BitrixCallError:
                    state = self._set_outbox_reconciliation_pending(
                        str(operation["operation_id"])
                    )
                    counts["uncertain" if state == "UNCERTAIN" else "review"] += 1
                    continue
                if verified:
                    if not evidence_intact:
                        self._set_outbox_review(
                            str(operation["operation_id"]),
                            "EVIDENCE_INTEGRITY_REVIEW",
                        )
                        counts["review"] += 1
                        continue
                    self._complete_outbox(
                        str(operation["operation_id"]), remote_id, reconciled=True
                    )
                    counts["reconciled"] += 1
                    continue
                state = self._set_outbox_reconciliation_pending(
                    str(operation["operation_id"])
                )
                counts["uncertain" if state == "UNCERTAIN" else "review"] += 1
                continue
            stored_remote_id = str(operation.get("remote_lead_id", ""))
            if stored_remote_id:
                try:
                    verified = self._readback(
                        stored_remote_id,
                        str(operation["origin_id"]),
                        expected_fields,
                    )
                except _BitrixCallError:
                    verified = False
                if verified:
                    if not evidence_intact:
                        self._set_outbox_review(
                            str(operation["operation_id"]),
                            "EVIDENCE_INTEGRITY_REVIEW",
                        )
                        counts["review"] += 1
                        continue
                    self._complete_outbox(
                        str(operation["operation_id"]),
                        stored_remote_id,
                        reconciled=True,
                    )
                    counts["reconciled"] += 1
                    continue
                state = self._set_outbox_reconciliation_pending(
                    str(operation["operation_id"])
                )
                counts["uncertain" if state == "UNCERTAIN" else "review"] += 1
                continue
            state = self._set_outbox_reconciliation_pending(
                str(operation["operation_id"])
            )
            if state == "UNCERTAIN":
                counts["uncertain"] += 1
            else:
                counts["review"] += 1
        return counts

    def dispatch_once(self, *, limit: int = 20) -> dict[str, Any]:
        """Reconcile uncertain creates, then dispatch safe pending operations."""

        self.initialize()
        if not 1 <= int(limit) <= 100:
            raise ValueError("limit must be between 1 and 100")
        run_id = self._start_run("DISPATCH")
        counters = {
            "claimed": 0,
            "created": 0,
            "reconciled": 0,
            "retryable": 0,
            "uncertain": 0,
            "review": 0,
            "delivery_claimed": 0,
            "delivery_created": 0,
            "delivery_reconciled": 0,
            "delivery_retryable": 0,
            "delivery_uncertain": 0,
            "delivery_review": 0,
        }
        try:
            with _RuntimeLock(self._lock_path):
                authority_generation = self._require_authority()
                self._require_verified_canary(authority_generation)
                reconciled = self._reconcile_uncertain(limit=int(limit))
                for key, value in reconciled.items():
                    counters[key] += value
                existing_delivery = self._dispatch_delivery_bundles(
                    limit=int(limit),
                    authority_generation=authority_generation,
                )
                for key, value in existing_delivery.items():
                    counters[f"delivery_{key}"] += value
                now = _iso(self._now())
                with self._transaction() as connection:
                    permit_remaining = self._remaining_write_attempts_tx(connection)
                parent_capacity = min(
                    max(0, int(limit) - sum(reconciled.values())),
                    permit_remaining // 3,
                )
                for _ in range(parent_capacity):
                    with self._transaction() as connection:
                        row = connection.execute(
                            """SELECT o.* FROM crm_outbox AS o
                               JOIN messages AS m ON m.message_key=o.message_key
                               WHERE o.state IN ('PENDING','RETRYABLE')
                                 AND (o.next_attempt_at_utc='' OR o.next_attempt_at_utc<=?)
                               ORDER BY o.created_at_utc,m.uid,o.operation_id LIMIT 1""",
                            (now,),
                        ).fetchone()
                        if row is None:
                            break
                        changed = connection.execute(
                            """UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',
                               attempt_count=attempt_count+1,updated_at_utc=?
                               WHERE operation_id=? AND state IN ('PENDING','RETRYABLE')""",
                            (_iso(self._now()), row["operation_id"]),
                        ).rowcount
                        if changed != 1:
                            continue
                        operation = dict(row)
                        operation["attempt_count"] = int(row["attempt_count"]) + 1
                    counters["claimed"] += 1
                    state = self._dispatch_operation(
                        operation,
                        authority_generation=authority_generation,
                    )
                    if state == "CREATED":
                        counters["created"] += 1
                    elif state == "RECONCILED":
                        counters["reconciled"] += 1
                    elif state == "RETRYABLE":
                        counters["retryable"] += 1
                    elif state == "UNCERTAIN":
                        counters["uncertain"] += 1
                    else:
                        counters["review"] += 1
                delivery = self._dispatch_delivery_bundles(
                    limit=int(limit),
                    authority_generation=authority_generation,
                )
                for key, value in delivery.items():
                    counters[f"delivery_{key}"] += value
            self._finish_run(run_id, state="SUCCESS", counters=counters)
        except Exception as exc:
            self._finish_run(run_id, state="FAILED", counters=counters, error=exc)
            raise
        return {"ok": True, "status": "success", **counters}

    def _reconcile_canary_tombstone(
        self,
        *,
        tombstone_key: str,
        tombstone_value: str,
    ) -> dict[str, Any] | None:
        try:
            tombstone = json.loads(tombstone_value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        expected_keys = {
            "authority_generation",
            "origin_id",
            "payload_json",
            "prior_state",
            "remote_lead_id",
        }
        if not isinstance(tombstone, dict) or set(tombstone) != expected_keys:
            return None
        generation = tombstone.get("authority_generation")
        origin_id = str(tombstone.get("origin_id", ""))
        remote_lead_id = str(tombstone.get("remote_lead_id", ""))
        if (
            type(generation) is not int
            or generation < 1
            or tombstone_key
            != f"bitrix_canary_tombstone_{generation}_{_digest(origin_id)[:16]}"
            or not re.fullmatch(r"lf_canary_[0-9a-f]{48}", origin_id)
            or (
                remote_lead_id
                and not re.fullmatch(r"\d{1,20}", remote_lead_id)
            )
            or not re.fullmatch(
                r"[A-Z][A-Z0-9_]{0,79}",
                str(tombstone.get("prior_state", "")),
            )
        ):
            return None
        try:
            payload = json.loads(str(tombstone.get("payload_json", "")))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        assigned_by_id = payload.get("ASSIGNED_BY_ID") if isinstance(payload, dict) else None
        if (
            type(assigned_by_id) is not int
            or not _canary_lead_payload_valid(payload, assigned_by_id=assigned_by_id)
        ):
            return None
        matching_leads = self._find_leads(origin_id)
        if len(matching_leads) > 1:
            return None
        # An empty provider lookup is never durable proof that an ambiguous
        # create did not happen.  Only a positively identified, exact-origin
        # Lead can resolve this tombstone automatically.
        if not matching_leads:
            return None
        observed_id = str(matching_leads[0].get("ID", ""))
        if (
            not re.fullmatch(r"\d{1,20}", observed_id)
            or (remote_lead_id and remote_lead_id != observed_id)
            or not self._readback(
                observed_id,
                origin_id,
                self._bitrix_fields(payload, origin_id=origin_id),
            )
        ):
            return None
        remote_lead_id = observed_id
        parent_state = "VERIFIED"

        parent_operation_id = f"canary:{generation}:{_digest(origin_id)[:32]}"
        message_key = f"canary_{_digest(parent_operation_id)}"
        with closing(self._connect()) as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                    """SELECT * FROM crm_delivery_outbox
                       WHERE parent_operation_id=? ORDER BY operation_kind""",
                    (parent_operation_id,),
                ).fetchall()
            ]
        if (
            len(rows) > 2
            or len({str(row.get("operation_kind", "")) for row in rows}) != len(rows)
            or any(
                str(row.get("operation_kind", ""))
                not in {"OPERATOR_TODO", "TIMELINE_MAIL"}
                or str(row.get("parent_operation_id", "")) != parent_operation_id
                or str(row.get("message_key", "")) != message_key
                or str(row.get("remote_lead_id", "")) != remote_lead_id
                or not _canary_delivery_payload_valid(
                    row,
                    assigned_by_id=assigned_by_id,
                    origin_id=origin_id,
                )
                for row in rows
            )
        ):
            return None
        by_kind = {str(row["operation_kind"]): row for row in rows}
        counts: dict[str, int] = {}
        for operation_kind, marker in (
            ("OPERATOR_TODO", f"[LF-CANARY-TODO:{origin_id}]"),
            ("TIMELINE_MAIL", f"[LF-CANARY-MAIL:{origin_id}]"),
        ):
            if not remote_lead_id:
                counts[operation_kind] = 0
                continue
            row = by_kind.get(operation_kind)
            lookup = row or {
                "marker": marker,
                "operation_kind": operation_kind,
                "remote_lead_id": remote_lead_id,
            }
            found = self._find_delivery_remote(lookup)
            for _attempt in range(2):
                if found:
                    break
                found = self._find_delivery_remote(lookup)
            if len(found) > 1 or (parent_state == "ABSENT" and found):
                return None
            if found:
                if row is None:
                    return None
                observed_id = str(found[0].get("ID", ""))
                stored_id = str(row.get("remote_id", ""))
                if (
                    not re.fullmatch(r"\d{1,20}", observed_id)
                    or (stored_id and stored_id != observed_id)
                    or not self._delivery_readback(row, observed_id)
                ):
                    return None
                counts[operation_kind] = 1
                continue
            if row is not None and (
                str(row.get("remote_id", ""))
                or str(row.get("phase", "")) == "CREATE_DISPATCH"
                or str(row.get("state", "")) in {"CREATED", "RECONCILED", "UNCERTAIN"}
            ):
                return None
            counts[operation_kind] = 0
        return {
            "operator_todo_count": counts.get("OPERATOR_TODO", 0),
            "parent_state": parent_state,
            "reconciled_at_utc": _iso(self._now()),
            "remote_lead_id": remote_lead_id,
            "timeline_mail_count": counts.get("TIMELINE_MAIL", 0),
            "tombstone_key_sha256": _digest(tombstone_key),
            "tombstone_sha256": _digest(tombstone_value),
        }

    def reconcile_canary_tombstones(self, *, confirmation: str) -> dict[str, Any]:
        """Read-reconcile old canary identities and preserve immutable audit records."""

        if confirmation != CANARY_TOMBSTONE_RECONCILE_CONFIRMATION:
            raise ValueError("exact canary tombstone reconciliation confirmation is required")
        self.initialize()
        with _RuntimeLock(self._lock_path):
            authority_generation = self._require_authority()
            with closing(self._connect()) as connection:
                assigned_by_id = self._assigned_by_id_tx(connection)
                if not self._canary_seal_valid_tx(
                    connection,
                    authority_generation=authority_generation,
                    assigned_by_id=assigned_by_id,
                ):
                    raise BitrixWriteNotVerified(
                        "a verified current canary is required before reconciliation"
                    )
                tombstones = [
                    (str(row["key"]), str(row["value"]))
                    for row in connection.execute(
                        "SELECT key,value FROM meta "
                        "WHERE key LIKE 'bitrix_canary_tombstone_%' ORDER BY key"
                    ).fetchall()
                    if re.fullmatch(
                        r"bitrix_canary_tombstone_[1-9]\d*_[0-9a-f]{16}",
                        str(row["key"]),
                    )
                ]
                resolutions = {
                    str(row["key"]): str(row["value"])
                    for row in connection.execute(
                        "SELECT key,value FROM meta "
                        "WHERE key LIKE 'bitrix_canary_resolution_%'"
                    ).fetchall()
                }
            reconciled = 0
            unresolved = 0
            for tombstone_key, tombstone_value in tombstones:
                resolution_key = _canary_tombstone_resolution_key(tombstone_key)
                prior = resolutions.get(resolution_key, "")
                if _canary_tombstone_resolution_valid(
                    prior,
                    tombstone_key=tombstone_key,
                    tombstone_value=tombstone_value,
                ):
                    reconciled += 1
                    continue
                resolution = self._reconcile_canary_tombstone(
                    tombstone_key=tombstone_key,
                    tombstone_value=tombstone_value,
                )
                if resolution is None:
                    unresolved += 1
                    continue
                resolution_value = json.dumps(
                    resolution,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                with self._transaction() as connection:
                    current = connection.execute(
                        "SELECT value FROM meta WHERE key=?",
                        (tombstone_key,),
                    ).fetchone()
                    if current is None or str(current[0]) != tombstone_value:
                        raise LiveMailBitrixError(
                            "canary tombstone changed during reconciliation"
                        )
                    connection.execute(
                        "INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)",
                        (resolution_key, resolution_value),
                    )
                    persisted = connection.execute(
                        "SELECT value FROM meta WHERE key=?",
                        (resolution_key,),
                    ).fetchone()
                    if persisted is None or str(persisted[0]) != resolution_value:
                        raise LiveMailBitrixError(
                            "canary tombstone resolution conflicts"
                        )
                reconciled += 1
        return {
            "ok": unresolved == 0,
            "reconciled_count": reconciled,
            "status": "ready" if unresolved == 0 else "needs_review",
            "tombstone_total_count": len(tombstones),
            "unresolved_count": unresolved,
        }

    def list_local_reviews(self) -> dict[str, Any]:
        """List unresolved local-review identities without exposing message content."""

        self.initialize()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT message_key,uid,route,rfc822_sha256,created_at_utc
                   FROM messages WHERE state='REVIEW'
                   ORDER BY created_at_utc,message_key LIMIT 1000"""
            ).fetchall()
            generic_acks = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM meta WHERE key LIKE 'local_review_ack_%'"
                ).fetchall()
            }
            parse_acks = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM meta "
                    "WHERE key LIKE 'local_parse_review_ack_%'"
                ).fetchall()
            }
        items: list[dict[str, Any]] = []
        for row in rows:
            message_key = str(row["message_key"])
            route = str(row["route"])
            rfc822_sha256 = str(row["rfc822_sha256"])
            acknowledged = _local_review_ack_valid(
                generic_acks.get(_local_review_ack_key(message_key), ""),
                message_key=message_key,
                route=route,
                rfc822_sha256=rfc822_sha256,
            ) or (
                route == "LOCAL_PARSE_REVIEW"
                and _local_parse_review_ack_valid(
                    parse_acks.get(_local_parse_review_ack_key(message_key), ""),
                    message_key=message_key,
                    rfc822_sha256=rfc822_sha256,
                )
            )
            if not acknowledged:
                items.append(
                    {
                        "created_at_utc": str(row["created_at_utc"]),
                        "message_key": message_key,
                        "route": route,
                        "uid": int(row["uid"]),
                    }
                )
        return {
            "items": items,
            "ok": not items,
            "status": "ready" if not items else "needs_review",
            "unresolved_count": len(items),
        }

    def acknowledge_local_review(
        self,
        *,
        message_key: str,
        confirmation: str,
    ) -> dict[str, Any]:
        """Acknowledge one evidence-bound REVIEW without creating CRM work."""

        if confirmation != LOCAL_REVIEW_ACK_CONFIRMATION:
            raise ValueError("exact local review confirmation is required")
        if not re.fullmatch(r"mail_[0-9a-f]{64}", str(message_key or "")):
            raise ValueError("local review message identity is invalid")
        self.initialize()
        with _RuntimeLock(self._lock_path):
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """SELECT message_key,rfc822_sha256,route,state FROM messages
                       WHERE message_key=?""",
                    (message_key,),
                ).fetchone()
                unexpected_crm = bool(
                    connection.execute(
                        "SELECT 1 FROM crm_outbox WHERE message_key=?",
                        (message_key,),
                    ).fetchone()
                    or connection.execute(
                        "SELECT 1 FROM crm_delivery_outbox WHERE message_key=?",
                        (message_key,),
                    ).fetchone()
                )
            if (
                row is None
                or str(row["state"]) != "REVIEW"
                or unexpected_crm
                or not self._message_evidence_intact(message_key)
            ):
                raise LiveMailBitrixError(
                    "local review is not an intact CRM-free quarantine"
                )
            route = str(row["route"])
            rfc822_sha256 = str(row["rfc822_sha256"])
            ack_key = _local_review_ack_key(message_key)
            value = json.dumps(
                {
                    "acknowledged_at_utc": _iso(self._now()),
                    "confirmation_hash": _digest(confirmation),
                    "decision": "ACKNOWLEDGED_NO_CRM",
                    "message_key_sha256": _digest(message_key),
                    "rfc822_sha256": rfc822_sha256,
                    "route": route,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            acknowledged = 0
            with self._transaction() as connection:
                current = connection.execute(
                    """SELECT rfc822_sha256,route,state FROM messages
                       WHERE message_key=?""",
                    (message_key,),
                ).fetchone()
                if (
                    current is None
                    or str(current["rfc822_sha256"]) != rfc822_sha256
                    or str(current["route"]) != route
                    or str(current["state"]) != "REVIEW"
                    or connection.execute(
                        "SELECT 1 FROM crm_outbox WHERE message_key=?",
                        (message_key,),
                    ).fetchone()
                    or connection.execute(
                        "SELECT 1 FROM crm_delivery_outbox WHERE message_key=?",
                        (message_key,),
                    ).fetchone()
                ):
                    raise LiveMailBitrixError(
                        "local review changed during acknowledgement"
                    )
                existing = connection.execute(
                    "SELECT value FROM meta WHERE key=?",
                    (ack_key,),
                ).fetchone()
                if existing is not None:
                    if not _local_review_ack_valid(
                        existing[0],
                        message_key=message_key,
                        route=route,
                        rfc822_sha256=rfc822_sha256,
                    ):
                        raise LiveMailBitrixError(
                            "local review acknowledgement conflicts"
                        )
                else:
                    connection.execute(
                        "INSERT INTO meta(key,value) VALUES(?,?)",
                        (ack_key, value),
                    )
                    acknowledged = 1
        return {
            "acknowledged_count": acknowledged,
            "message_key": message_key,
            "ok": True,
            "route": route,
            "status": "ready",
        }

    def acknowledge_local_parse_reviews(self, *, confirmation: str) -> dict[str, Any]:
        """Acknowledge parser quarantine without deleting evidence or creating CRM work."""

        if confirmation != LOCAL_PARSE_REVIEW_ACK_CONFIRMATION:
            raise ValueError("exact local parse review confirmation is required")
        self.initialize()
        with _RuntimeLock(self._lock_path):
            with closing(self._connect()) as connection:
                rows = [
                    dict(row)
                    for row in connection.execute(
                        """SELECT message_key,rfc822_sha256,route,state
                           FROM messages WHERE route='LOCAL_PARSE_REVIEW'
                           ORDER BY created_at_utc,message_key"""
                    ).fetchall()
                ]
                if any(
                    connection.execute(
                        "SELECT 1 FROM crm_outbox WHERE message_key=?",
                        (str(row["message_key"]),),
                    ).fetchone()
                    for row in rows
                ):
                    raise LiveMailBitrixError(
                        "local parse review unexpectedly has a CRM operation"
                    )
            for row in rows:
                if (
                    str(row["state"]) != "REVIEW"
                    or not self._message_evidence_intact(str(row["message_key"]))
                ):
                    raise LiveMailBitrixError(
                        "local parse review evidence is not intact"
                    )
            acknowledged = 0
            with self._transaction() as connection:
                for row in rows:
                    message_key = str(row["message_key"])
                    rfc822_sha256 = str(row["rfc822_sha256"])
                    current = connection.execute(
                        """SELECT rfc822_sha256,route,state FROM messages
                           WHERE message_key=?""",
                        (message_key,),
                    ).fetchone()
                    if (
                        current is None
                        or str(current["rfc822_sha256"]) != rfc822_sha256
                        or str(current["route"]) != "LOCAL_PARSE_REVIEW"
                        or str(current["state"]) != "REVIEW"
                        or connection.execute(
                            "SELECT 1 FROM crm_outbox WHERE message_key=?",
                            (message_key,),
                        ).fetchone()
                    ):
                        raise LiveMailBitrixError(
                            "local parse review changed during acknowledgement"
                        )
                    ack_key = _local_parse_review_ack_key(message_key)
                    existing = connection.execute(
                        "SELECT value FROM meta WHERE key=?",
                        (ack_key,),
                    ).fetchone()
                    if existing is not None:
                        if not _local_parse_review_ack_valid(
                            existing[0],
                            message_key=message_key,
                            rfc822_sha256=rfc822_sha256,
                        ):
                            raise LiveMailBitrixError(
                                "local parse review acknowledgement conflicts"
                            )
                        continue
                    value = json.dumps(
                        {
                            "acknowledged_at_utc": _iso(self._now()),
                            "message_key_sha256": _digest(message_key),
                            "rfc822_sha256": rfc822_sha256,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        "INSERT INTO meta(key,value) VALUES(?,?)",
                        (ack_key, value),
                    )
                    acknowledged += 1
        return {
            "acknowledged_count": acknowledged,
            "local_parse_review_total_count": len(rows),
            "local_parse_review_unacknowledged_count": 0,
            "ok": True,
            "status": "ready",
        }

    def _seal_canary_tx(
        self,
        connection: sqlite3.Connection,
        *,
        authority_generation: int,
        remote_id: str,
    ) -> None:
        if not self._authority_valid_tx(
            connection,
            expected_generation=authority_generation,
        ):
            # Authority validation can durably revoke a rolled-back or expired
            # grant.  Canary failure must not roll that revocation back.
            connection.commit()
            raise LiveMailBitrixError("authority changed before canary sealing")
        values = {
            "bitrix_canary_authority_generation": str(authority_generation),
            "bitrix_canary_assigned_by_id": str(
                self._assigned_by_id_tx(connection)
            ),
            "bitrix_canary_release_sha256": self._release_sha256,
            "bitrix_canary_remote_id": remote_id,
            "bitrix_canary_runtime_sha256": self._runtime_sha256,
            "bitrix_canary_state": "VERIFIED",
            "bitrix_canary_webhook_scope_hash": self._webhook_scope_hash,
            "bitrix_write_verified": "1",
        }
        for key, value in values.items():
            connection.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def bitrix_canary(self, *, confirmation: str) -> dict[str, Any]:
        """Create at most one tagged no-contact Lead and verify it by readback.

        The record is intentionally preserved as audit evidence.  A repeated
        invocation reuses the locally sealed ORIGIN_ID and queries before any
        possible create.  An ambiguous create can only be reconciled, never
        retried blindly.
        """

        if confirmation != BITRIX_CANARY_CONFIRMATION:
            raise ValueError("exact Bitrix canary confirmation is required")
        self.initialize()
        with _RuntimeLock(self._lock_path):
            authority_generation = self._require_authority()
            now = self._now()
            with self._transaction() as connection:
                origin_row = connection.execute(
                    "SELECT value FROM meta WHERE key='bitrix_canary_origin_id'"
                ).fetchone()
                payload_row = connection.execute(
                    "SELECT value FROM meta WHERE key='bitrix_canary_lead_payload_json'"
                ).fetchone()
                remote_row = connection.execute(
                    "SELECT value FROM meta WHERE key='bitrix_canary_remote_id'"
                ).fetchone()
                origin_generation_row = connection.execute(
                    "SELECT value FROM meta "
                    "WHERE key='bitrix_canary_origin_authority_generation'"
                ).fetchone()
                if origin_row:
                    origin_id = str(origin_row[0])
                    if (
                        payload_row is None
                        or origin_generation_row is None
                        or str(origin_generation_row[0]) != str(authority_generation)
                    ):
                        _mark_canary_review_tx(
                            connection, state="LEAD_PAYLOAD_REVIEW"
                        )
                        return {
                            "ok": False,
                            "status": "review",
                            "reason": "persisted_canary_payload_invalid",
                        }
                    try:
                        canary_payload = json.loads(str(payload_row[0]))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        _mark_canary_review_tx(
                            connection, state="LEAD_PAYLOAD_REVIEW"
                        )
                        return {
                            "ok": False,
                            "status": "review",
                            "reason": "persisted_canary_payload_invalid",
                        }
                    if not isinstance(canary_payload, dict):
                        _mark_canary_review_tx(
                            connection, state="LEAD_PAYLOAD_REVIEW"
                        )
                        return {
                            "ok": False,
                            "status": "review",
                            "reason": "persisted_canary_payload_invalid",
                        }
                else:
                    if (
                        payload_row is not None
                        or origin_generation_row is not None
                        or remote_row is not None
                    ):
                        _mark_canary_review_tx(
                            connection, state="LEAD_PAYLOAD_REVIEW"
                        )
                        return {
                            "ok": False,
                            "status": "review",
                            "reason": "persisted_canary_payload_invalid",
                        }
                    origin_id = "lf_canary_" + _digest(
                        f"{_iso(now)}|{uuid.uuid4().hex}"
                    )[:48]
                    canary_payload = {
                        "TITLE": f"[LF-CANARY][NO CONTACT] Mail inbound {_iso(now)}",
                        "SOURCE_DESCRIPTION": (
                            "TenderBot Mail inbound cap-one connection canary"
                        ),
                        "ASSIGNED_BY_ID": self._assigned_by_id_tx(connection),
                        "COMPANY": "TenderBot Lead Factory",
                        "NAME": "NO CONTACT",
                        "EMAIL": "lf-canary@example.invalid",
                        "COMMENTS": (
                            "Technical connection canary. No customer contact. "
                            "Preserve this Lead as write/readback audit evidence."
                        ),
                    }
                    payload_json = json.dumps(
                        canary_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    connection.execute(
                        "INSERT INTO meta(key,value) VALUES('bitrix_canary_origin_id',?)",
                        (origin_id,),
                    )
                    connection.execute(
                        "INSERT INTO meta(key,value) "
                        "VALUES('bitrix_canary_lead_payload_json',?)",
                        (payload_json,),
                    )
                    connection.execute(
                        "INSERT INTO meta(key,value) "
                        "VALUES('bitrix_canary_origin_authority_generation',?)",
                        (str(authority_generation),),
                    )
                    connection.execute(
                        """INSERT INTO meta(key,value) VALUES('bitrix_canary_state','PREPARED')
                           ON CONFLICT(key) DO UPDATE SET value='PREPARED'""",
                    )
                state_row = connection.execute(
                    "SELECT value FROM meta WHERE key='bitrix_canary_state'"
                ).fetchone()
                canary_state = str(state_row[0]) if state_row else "PREPARED"
                payload_valid = bool(
                    re.fullmatch(r"lf_canary_[0-9a-f]{48}", origin_id)
                    and _canary_lead_payload_valid(
                        canary_payload,
                        assigned_by_id=self._assigned_by_id_tx(connection),
                    )
                )
                if not payload_valid:
                    _mark_canary_review_tx(
                        connection, state="LEAD_PAYLOAD_REVIEW"
                    )
                    return {
                        "ok": False,
                        "status": "review",
                        "reason": "persisted_canary_payload_invalid",
                    }
                fields = self._bitrix_fields(canary_payload, origin_id=origin_id)
                if canary_state == "PREPARED":
                    connection.execute(
                        "UPDATE meta SET value='PRECREATE_QUERY' "
                        "WHERE key='bitrix_canary_state'"
                    )
                    canary_state = "PRECREATE_QUERY"
            try:
                found = self._find_leads(origin_id)
            except _BitrixCallError as exc:
                raise RemotePreflightError("Bitrix canary reconciliation query failed") from exc
            if len(found) > 1:
                with self._transaction() as connection:
                    _mark_canary_review_tx(
                        connection, state="CONFLICT_REVIEW"
                    )
                return {"ok": False, "status": "review", "reason": "duplicate_origin"}
            if len(found) == 1:
                remote_id = str(found[0].get("ID", ""))
                if (
                    not re.fullmatch(r"\d{1,20}", remote_id)
                    or (
                        remote_row is not None
                        and str(remote_row[0]) != remote_id
                    )
                ):
                    with self._transaction() as connection:
                        _mark_canary_review_tx(
                            connection, state="CONFLICT_REVIEW"
                        )
                    return {
                        "ok": False,
                        "status": "review",
                        "reason": "canary_remote_identity_conflict",
                    }
                with self._transaction() as connection:
                    connection.execute(
                        "INSERT INTO meta(key,value) VALUES('bitrix_canary_remote_id',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (remote_id,),
                    )
                    connection.execute(
                        "UPDATE meta SET value='CREATE_DISPATCH' "
                        "WHERE key='bitrix_canary_state'"
                    )
                try:
                    verified = self._readback(remote_id, origin_id, fields)
                except _BitrixCallError:
                    return {
                        "ok": False,
                        "status": "failed",
                        "reason": "canary_readback_failed",
                    }
                if not verified:
                    with self._transaction() as connection:
                        _mark_canary_review_tx(
                            connection, state="LEAD_REVIEW"
                        )
                    return {"ok": False, "status": "review", "reason": "readback_not_verified"}
                projection = self._verify_canary_deliveries(
                    authority_generation=authority_generation,
                    remote_lead_id=remote_id,
                    origin_id=origin_id,
                )
                if not projection["ok"]:
                    with self._transaction() as connection:
                        _mark_canary_review_tx(
                            connection, state="PROJECTION_REVIEW"
                        )
                    return {
                        "ok": False,
                        "status": "review",
                        "reason": "projection_canary_not_verified",
                        "projection_reason": str(projection.get("reason", "")),
                    }
                with self._transaction() as connection:
                    self._seal_canary_tx(
                        connection,
                        authority_generation=authority_generation,
                        remote_id=remote_id,
                    )
                return {
                    "ok": True,
                    "status": "success",
                    "created": False,
                    "reconciled": True,
                    "projection_verified": True,
                    "remote_lead_id": remote_id,
                }
            if canary_state == "VERIFIED":
                with self._transaction() as connection:
                    _mark_canary_review_tx(connection, state="LEAD_REVIEW")
                return {
                    "ok": False,
                    "status": "review",
                    "reason": "canary_lead_missing",
                }
            if remote_row is not None:
                return {
                    "ok": False,
                    "status": "review",
                    "reason": "acknowledged_canary_lead_missing",
                }
            if canary_state in {
                "CREATE_DISPATCH",
                "UNCERTAIN",
                "LEAD_REVIEW",
                "LEAD_PAYLOAD_REVIEW",
                "PROJECTION_REVIEW",
                "CONFLICT_REVIEW",
            }:
                return {
                    "ok": False,
                    "status": "review",
                    "reason": "ambiguous_create_not_retried",
                }
            if canary_state != "PRECREATE_QUERY":
                return {
                    "ok": False,
                    "status": "review",
                    "reason": "canary_state_not_retryable",
                }
            required = self._bitrix_call("crm.lead.fields", {}, write=False)
            if not isinstance(required, dict) or not {"ORIGINATOR_ID", "ORIGIN_ID"}.issubset(required):
                raise RemotePreflightError("Bitrix origin field contract is unavailable")
            with self._transaction() as connection:
                remaining = self._remaining_write_attempts_tx(connection)
            if remaining < 6:
                return {
                    "ok": False,
                    "status": "failed",
                    "reason": "insufficient_write_budget",
                }
            try:
                with self._transaction() as connection:
                    self._consume_write_attempt_tx(
                        connection,
                        expected_generation=authority_generation,
                    )
                    changed = connection.execute(
                        "UPDATE meta SET value='CREATE_DISPATCH' "
                        "WHERE key='bitrix_canary_state' AND value='PRECREATE_QUERY'"
                    ).rowcount
                    if changed != 1:
                        raise LiveMailBitrixError(
                            "Bitrix canary state changed before create dispatch"
                        )
            except BitrixWriteBudgetExhausted:
                return {
                    "ok": False,
                    "status": "failed",
                    "reason": "insufficient_write_budget",
                }
            try:
                result = self._bitrix_call(
                    "crm.lead.add",
                    {"fields": fields, "params": {"REGISTER_SONET_EVENT": "N"}},
                    write=True,
                )
            except _BitrixCallError as error:
                if error.definite:
                    with self._transaction() as connection:
                        connection.execute(
                            "UPDATE meta SET value='PREPARED' WHERE key='bitrix_canary_state'"
                        )
                return {
                    "ok": False,
                    "status": "review" if not error.definite else "failed",
                    "reason": "ambiguous_create" if not error.definite else "provider_rejection",
                }
            remote_id = str(result.get("ID", result.get("id", ""))) if isinstance(result, dict) else str(result)
            if not re.fullmatch(r"\d{1,20}", remote_id):
                return {"ok": False, "status": "review", "reason": "ambiguous_create"}
            with self._transaction() as connection:
                connection.execute(
                    "INSERT INTO meta(key,value) VALUES('bitrix_canary_remote_id',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (remote_id,),
                )
            try:
                verified = self._readback(remote_id, origin_id, fields)
            except _BitrixCallError:
                verified = False
            if not verified:
                with self._transaction() as connection:
                    _mark_canary_review_tx(connection, state="LEAD_REVIEW")
                return {
                    "ok": False,
                    "status": "review",
                    "reason": "readback_not_verified",
                    "remote_lead_id": remote_id,
                }
            projection = self._verify_canary_deliveries(
                authority_generation=authority_generation,
                remote_lead_id=remote_id,
                origin_id=origin_id,
            )
            if not projection["ok"]:
                with self._transaction() as connection:
                    _mark_canary_review_tx(
                        connection, state="PROJECTION_REVIEW"
                    )
                return {
                    "ok": False,
                    "status": "review",
                    "reason": "projection_canary_not_verified",
                    "projection_reason": str(projection.get("reason", "")),
                    "remote_lead_id": remote_id,
                }
            with self._transaction() as connection:
                self._seal_canary_tx(
                    connection,
                    authority_generation=authority_generation,
                    remote_id=remote_id,
                )
            return {
                "ok": True,
                "status": "success",
                "created": True,
                "reconciled": False,
                "projection_verified": True,
                "remote_lead_id": remote_id,
            }

    def health(self) -> dict[str, Any]:
        """Return only operational counts and cursor/outbox state."""

        self.initialize()
        authority_observed_at = self._observe_authority_time()
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT last_uid FROM cursor WHERE singleton=1"
            ).fetchone()
            message_rows = connection.execute(
                "SELECT state,COUNT(*) AS n FROM messages GROUP BY state ORDER BY state"
            ).fetchall()
            outbox_rows = connection.execute(
                "SELECT state,COUNT(*) AS n FROM crm_outbox GROUP BY state ORDER BY state"
            ).fetchall()
            delivery_rows = connection.execute(
                """SELECT state,COUNT(*) AS n FROM crm_delivery_outbox
                   GROUP BY state ORDER BY state"""
            ).fetchall()
            canary = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_canary_state'"
            ).fetchone()
            scope = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_canary_webhook_scope_hash'"
            ).fetchone()
            release = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_canary_release_sha256'"
            ).fetchone()
            runtime = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_canary_runtime_sha256'"
            ).fetchone()
            canary_generation = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_canary_authority_generation'"
            ).fetchone()
            canary_assignee = connection.execute(
                "SELECT value FROM meta WHERE key='bitrix_canary_assigned_by_id'"
            ).fetchone()
            permit = connection.execute(
                """SELECT authority_expires_at_utc,write_attempt_budget,write_attempts_used,
                          authority_generation,authority_state
                   FROM scoped_authority WHERE singleton=1"""
            ).fetchone()
            authority = self._authority_valid_tx(
                connection,
                observed_at=authority_observed_at,
            )
            try:
                assigned_by_id = self._assigned_by_id_tx(connection)
                assignment_valid = True
            except LiveMailBitrixError:
                assigned_by_id = 0
                assignment_valid = False
            permit_generation = int(permit["authority_generation"]) if permit else 0
            canary_projection_sealed = bool(
                assignment_valid
                and self._canary_seal_valid_tx(
                    connection,
                    authority_generation=permit_generation,
                    assigned_by_id=assigned_by_id,
                )
            )
            failed_runs = connection.execute(
                "SELECT COUNT(*) FROM runs WHERE state='FAILED'"
            ).fetchone()[0]
            local_review_rows = connection.execute(
                """SELECT message_key,route,rfc822_sha256 FROM messages
                   WHERE state='REVIEW'"""
            ).fetchall()
            local_parse_acks = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM meta "
                    "WHERE key LIKE 'local_parse_review_ack_%'"
                ).fetchall()
            }
            local_review_acks = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM meta WHERE key LIKE 'local_review_ack_%'"
                ).fetchall()
            }
            unresolved_local_reviews: list[sqlite3.Row] = []
            for row in local_review_rows:
                message_key = str(row["message_key"])
                route = str(row["route"])
                rfc822_sha256 = str(row["rfc822_sha256"])
                acknowledged = _local_review_ack_valid(
                    local_review_acks.get(_local_review_ack_key(message_key), ""),
                    message_key=message_key,
                    route=route,
                    rfc822_sha256=rfc822_sha256,
                ) or (
                    route == "LOCAL_PARSE_REVIEW"
                    and _local_parse_review_ack_valid(
                        local_parse_acks.get(
                            _local_parse_review_ack_key(message_key),
                            "",
                        ),
                        message_key=message_key,
                        rfc822_sha256=rfc822_sha256,
                    )
                )
                if not acknowledged:
                    unresolved_local_reviews.append(row)
            local_review_total_count = len(local_review_rows)
            local_review_count = len(unresolved_local_reviews)
            local_review_routes: dict[str, int] = {}
            for row in unresolved_local_reviews:
                route = str(row["route"])
                local_review_routes[route] = local_review_routes.get(route, 0) + 1
            local_parse_rows = [
                row
                for row in local_review_rows
                if str(row["route"]) == "LOCAL_PARSE_REVIEW"
            ]
            local_parse_review_total_count = len(local_parse_rows)
            local_parse_review_count = sum(
                1
                for row in unresolved_local_reviews
                if str(row["route"]) == "LOCAL_PARSE_REVIEW"
            )
            message_id_conflict_review_count = sum(
                1
                for row in unresolved_local_reviews
                if str(row["route"]) == "MESSAGE_ID_CONFLICT_REVIEW"
            )
            canary_tombstone_rows = [
                (str(row["key"]), str(row["value"]))
                for row in connection.execute(
                    "SELECT key,value FROM meta "
                    "WHERE key LIKE 'bitrix_canary_tombstone_%'"
                ).fetchall()
                if re.fullmatch(
                    r"bitrix_canary_tombstone_[1-9]\d*_[0-9a-f]{16}",
                    str(row["key"]),
                )
            ]
            canary_resolution_rows = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM meta "
                    "WHERE key LIKE 'bitrix_canary_resolution_%'"
                ).fetchall()
            }
            canary_tombstone_total_count = len(canary_tombstone_rows)
            canary_tombstones = sum(
                1
                for key, value in canary_tombstone_rows
                if not _canary_tombstone_resolution_valid(
                    canary_resolution_rows.get(
                        _canary_tombstone_resolution_key(key),
                        "",
                    ),
                    tombstone_key=key,
                    tombstone_value=value,
                )
            )
            evidence_inventory = self._evidence_inventory()
            tracked_evidence_rows = connection.execute(
                """SELECT d.uidvalidity,d.uid,d.rfc822_sha256 AS delivery_sha256,
                          d.evidence_ref AS delivery_evidence_ref,
                          m.rfc822_sha256 AS message_sha256,
                          m.rfc822_size AS message_size
                   FROM message_deliveries AS d
                   LEFT JOIN messages AS m ON m.message_key=d.message_key"""
            ).fetchall()
            tracked_evidence = {
                (str(row["uidvalidity"]), int(row["uid"]))
                for row in tracked_evidence_rows
            }
            evidence_by_identity = {
                (validity, uid): (path, size)
                for validity, uid, path, size in evidence_inventory
            }
            missing_evidence_count = 0
            for row in tracked_evidence_rows:
                try:
                    validity = str(row["uidvalidity"])
                    uid = int(row["uid"])
                    expected_relative = Path("evidence") / validity / f"{uid}.eml"
                    expected_path = self._state_dir / expected_relative
                    observed = evidence_by_identity.get((validity, uid))
                    message_size = int(row["message_size"])
                    delivery_sha256 = str(row["delivery_sha256"])
                    message_sha256 = str(row["message_sha256"])
                    if (
                        observed is None
                        or str(row["delivery_evidence_ref"])
                        != expected_relative.as_posix()
                        or observed[0] != expected_path
                        or observed[1] != message_size
                        or delivery_sha256 != message_sha256
                    ):
                        missing_evidence_count += 1
                        continue
                    raw = self._read_evidence_path(observed[0])
                    if len(raw) != message_size or _digest(raw) != delivery_sha256:
                        missing_evidence_count += 1
                except (LiveMailBitrixError, OSError, TypeError, ValueError):
                    missing_evidence_count += 1
            evidence_bytes = sum(item[3] for item in evidence_inventory)
            orphan_evidence_count = sum(
                1
                for validity, uid, _path, _size in evidence_inventory
                if (validity, uid) not in tracked_evidence
            )
        finally:
            connection.close()
        message_states = {str(row["state"]): int(row["n"]) for row in message_rows}
        outbox_states = {str(row["state"]): int(row["n"]) for row in outbox_rows}
        delivery_outbox_states = {
            str(row["state"]): int(row["n"]) for row in delivery_rows
        }
        scope_matches = bool(scope and str(scope[0]) == self._webhook_scope_hash)
        release_matches = bool(release and str(release[0]) == self._release_sha256)
        runtime_matches = bool(runtime and str(runtime[0]) == self._runtime_sha256)
        generation = permit_generation
        canary_generation_matches = bool(
            canary_generation and str(canary_generation[0]) == str(generation)
        )
        canary_assignee_matches = bool(
            assignment_valid
            and canary_assignee
            and str(canary_assignee[0]) == str(assigned_by_id)
        )
        budget = int(permit["write_attempt_budget"]) if permit else 0
        used = int(permit["write_attempts_used"]) if permit else 0
        remaining_write_attempts = max(0, budget - used)
        write_bundle_available = remaining_write_attempts >= 3
        try:
            evidence_free_bytes = int(shutil.disk_usage(self._state_dir).free)
        except OSError:
            evidence_free_bytes = 0
        evidence_storage_ready = bool(
            evidence_bytes < _MAX_EVIDENCE_BYTES
            and evidence_free_bytes >= _MIN_EVIDENCE_FREE_BYTES
        )
        try:
            expires_in_seconds = max(
                0,
                int(
                    (
                        _as_utc(datetime.fromisoformat(str(permit["authority_expires_at_utc"])))
                        - self._now()
                    ).total_seconds()
                ),
            )
        except (KeyError, TypeError, ValueError):
            expires_in_seconds = 0
        ready = bool(
            cursor is not None
            and authority
            and canary
            and canary[0] == "VERIFIED"
            and scope_matches
            and release_matches
            and runtime_matches
            and canary_generation_matches
            and canary_assignee_matches
            and canary_projection_sealed
            and write_bundle_available
            and evidence_storage_ready
            and missing_evidence_count == 0
        )
        needs_attention = bool(
            (
                canary
                and (
                    (canary[0] == "VERIFIED" and not canary_projection_sealed)
                    or canary[0] not in {"VERIFIED", "PREPARED"}
                )
            )
            or canary_tombstones > 0
            or local_review_count > 0
            or missing_evidence_count > 0
            or orphan_evidence_count > 0
            or any(
                count > 0
                for state, count in {
                    **outbox_states,
                    **delivery_outbox_states,
                }.items()
                if state not in {"CREATED", "RECONCILED", "PENDING", "RETRYABLE"}
            )
        )
        return {
            "ok": ready,
            "operational_ready": ready,
            "needs_attention": needs_attention,
            "status": "not_ready" if not ready else ("degraded" if needs_attention else "healthy"),
            "schema_version": int(_SCHEMA_VERSION),
            "mailbox": _MAILBOX,
            "cursor_bootstrapped": cursor is not None,
            "scoped_authority_present": authority,
            "imap_inbox_read_authorized": authority,
            "bitrix_mail_lead_write_authorized": authority,
            "smtp_send_enabled": False,
            "unisender_send_enabled": False,
            "tenderplan_access_enabled": False,
            "evidence_bytes": evidence_bytes,
            "evidence_quota_bytes": _MAX_EVIDENCE_BYTES,
            "evidence_free_bytes": evidence_free_bytes,
            "evidence_free_reserve_bytes": _MIN_EVIDENCE_FREE_BYTES,
            "evidence_storage_ready": evidence_storage_ready,
            "missing_evidence_count": missing_evidence_count,
            "orphan_evidence_count": orphan_evidence_count,
            "last_uid": int(cursor["last_uid"]) if cursor else 0,
            "message_states": message_states,
            "outbox_states": outbox_states,
            "delivery_outbox_states": delivery_outbox_states,
            "bitrix_canary_state": str(canary[0]) if canary else "NOT_RUN",
            "bitrix_canary_scope_matches": scope_matches,
            "bitrix_canary_release_matches": release_matches,
            "bitrix_canary_runtime_matches": runtime_matches,
            "bitrix_canary_generation_matches": canary_generation_matches,
            "bitrix_canary_assignee_matches": canary_assignee_matches,
            "bitrix_canary_projection_sealed": canary_projection_sealed,
            "bitrix_canary_tombstone_count": canary_tombstones,
            "bitrix_canary_tombstone_resolved_count": (
                canary_tombstone_total_count - canary_tombstones
            ),
            "bitrix_canary_tombstone_total_count": canary_tombstone_total_count,
            "local_parse_review_count": local_parse_review_count,
            "local_parse_review_total_count": local_parse_review_total_count,
            "local_review_count": local_review_count,
            "local_review_routes": dict(sorted(local_review_routes.items())),
            "local_review_total_count": local_review_total_count,
            "message_id_conflict_review_count": message_id_conflict_review_count,
            "release_pinned": True,
            "runtime_pinned": True,
            "authority_generation": generation,
            "authority_state": str(permit["authority_state"]) if permit else "ABSENT",
            "authority_expires_in_seconds": expires_in_seconds,
            "write_attempt_budget": budget,
            "write_attempts_used": used,
            "write_attempts_remaining": remaining_write_attempts,
            "bitrix_write_bundle_available": write_bundle_available,
            "bitrix_assigned_by_id": assigned_by_id,
            "bitrix_assignee_valid": assignment_valid,
            "failed_runs": int(failed_runs),
        }


def _materialize_empty_revocation_store(
    *,
    root: Path,
    release_sha256: str,
    runtime_sha256: str,
) -> None:
    """Create a schema-valid no-authority store without loading live secrets."""

    placeholder = LiveConnectionCredentialBundle(
        imap_host="imap.mail.ru",
        imap_port=993,
        imap_user="revocation-placeholder@example.invalid",
        imap_password="no-network-placeholder",
        smtp_host="smtp.mail.ru",
        smtp_port=465,
        smtp_user="revocation-placeholder@example.invalid",
        smtp_password="no-network-placeholder",
        smtp_from="revocation-placeholder@example.invalid",
        bitrix_webhook=(
            "https://revocation-placeholder.bitrix24.ru/rest/1/no-network-placeholder/"
        ),
        unisender_host="go1.unisender.ru",
        unisender_api_key="no-network-placeholder",
        unisender_from="revocation-placeholder@example.invalid",
        unisender_name="Revocation placeholder",
        unisender_reply_to="revocation-placeholder@example.invalid",
    )
    worker = LiveMailBitrixWorker(
        placeholder,
        release_sha256=release_sha256,
        runtime_sha256=runtime_sha256,
        state_dir=root,
        legacy_processed_path=root / "revocation-no-legacy-processed.json",
        legacy_registry_path=root / "revocation-no-legacy-registry.json",
        legacy_queue_path=root / "revocation-no-legacy-queue.json",
    )
    worker.initialize()


def revoke_persisted_authority(
    *,
    state_dir: str | os.PathLike[str],
    release_sha256: str,
    runtime_sha256: str,
    confirmation: str,
    reason: str,
) -> dict[str, Any]:
    """Durably revoke the local permit without credentials or network access.

    The confirmation is explicit operator friction, not an authentication
    secret.  Windows identity and the protected task/release boundary provide
    the local execution boundary.
    """

    if confirmation != AUTHORITY_REVOKE_CONFIRMATION:
        raise ValueError("exact authority revoke confirmation is required")
    if reason not in {"operator", "release_replacement", "scheduled_task_uninstall"}:
        raise ValueError("authority revoke reason is invalid")
    if any(
        not re.fullmatch(r"[0-9a-f]{64}", value)
        or not any(character != "0" for character in value)
        for value in (str(release_sha256), str(runtime_sha256))
    ):
        raise ValueError("pinned release identity is required for revoke")
    root = Path(state_dir).absolute()
    db_path = root / "live_mail_bitrix.sqlite3"
    lock_path = root / "worker.lock"
    sidecar_paths = (
        Path(str(db_path) + "-journal"),
        Path(str(db_path) + "-shm"),
        Path(str(db_path) + "-wal"),
    )
    try:
        root.lstat()
    except FileNotFoundError:
        _assert_plain_existing_ancestor(root)
        _ensure_plain_directory(root)
    except OSError as exc:
        raise LiveMailBitrixError("live inbound storage path is unavailable") from exc
    root_identities = _assert_plain_directory_chain(root)
    for candidate in (
        db_path,
        *sidecar_paths,
        lock_path,
    ):
        _assert_plain_optional_file(candidate)
    now = _iso(_utc_now())
    with _RuntimeLock(lock_path):
        try:
            db_path.lstat()
        except FileNotFoundError:
            for candidate in (db_path, *sidecar_paths):
                _assert_absent_storage_file(candidate)
            _materialize_empty_revocation_store(
                root=root,
                release_sha256=str(release_sha256),
                runtime_sha256=str(runtime_sha256),
            )
        except OSError as exc:
            raise LiveMailBitrixError(
                "live inbound storage path is unavailable"
            ) from exc
        before = _plain_path_stat(db_path, directory=False)
        connection = sqlite3.connect(db_path, timeout=30.0)
        after = _plain_path_stat(db_path, directory=False)
        if (int(before.st_dev), int(before.st_ino)) != (
            int(after.st_dev),
            int(after.st_ino),
        ):
            connection.close()
            raise LiveMailBitrixError("live inbound database identity changed")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        try:
            connection.execute("BEGIN IMMEDIATE")
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if not quick_check or str(quick_check[0]).casefold() != "ok":
                raise LiveMailBitrixError("live inbound database integrity check failed")
            objects = _user_schema_object_names(connection)
            schema_row = connection.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            schema_version = str(schema_row[0]) if schema_row else ""
            if schema_version == _SCHEMA_VERSION:
                contract_row = connection.execute(
                    "SELECT value FROM meta WHERE key='schema_contract_sha256'"
                ).fetchone()
                contract = _schema_contract_sha256(connection)
                if (
                    objects != _SCHEMA_CONTRACT_OBJECTS
                    or contract not in _V4_SCHEMA_CONTRACT_SHA256S
                    or contract_row is None
                    or str(contract_row[0]) != contract
                ):
                    raise LiveMailBitrixError(
                        "live inbound database schema contract drifted"
                    )
            elif schema_version == "3":
                legacy_objects = _SCHEMA_CONTRACT_OBJECTS - {
                    "crm_delivery_outbox",
                    "idx_crm_delivery_outbox_state",
                }
                if (
                    objects != legacy_objects
                    or _schema_contract_sha256(connection, legacy_objects)
                    not in _LEGACY_V3_SCHEMA_CONTRACT_SHA256S
                ):
                    raise LiveMailBitrixError(
                        "legacy live inbound database schema is incompatible"
                    )
            else:
                raise LiveMailBitrixError(
                    "live inbound database schema is incompatible"
                )
            row = connection.execute(
                "SELECT * FROM scoped_authority WHERE singleton=1"
            ).fetchone()
            _advance_authority_revocation_fence_tx(connection)
            if row is None:
                generation = max(
                    1,
                    _authority_generation_counter_tx(connection),
                )
                _record_authority_generation_tx(connection, generation)
                _invalidate_canary_tx(connection, state="REVOKED")
                already_revoked = True
            else:
                generation = max(
                    1,
                    int(row["authority_generation"]),
                    _authority_generation_counter_tx(connection),
                )
                already_revoked = bool(
                    str(row["authority_state"]) == "REVOKED"
                    and int(row["imap_inbox_read"]) == 0
                    and int(row["bitrix_lead_list"]) == 0
                    and int(row["bitrix_lead_add"]) == 0
                    and int(row["bitrix_lead_get"]) == 0
                    and (
                        schema_version == "3"
                        or (
                            int(row["bitrix_activity_list"]) == 0
                            and int(row["bitrix_activity_add"]) == 0
                            and int(row["bitrix_activity_get"]) == 0
                            and int(row["bitrix_timeline_comment_list"]) == 0
                            and int(row["bitrix_timeline_comment_add"]) == 0
                            and int(row["bitrix_timeline_comment_get"]) == 0
                        )
                    )
                    and int(row["smtp_send"]) == 0
                    and int(row["unisender_send"]) == 0
                    and int(row["tenderplan_access"]) == 0
                    and str(row["revoked_at_utc"])
                )
                projection_zeroes = (
                    ",bitrix_activity_list=0,bitrix_activity_add=0,"
                    "bitrix_activity_get=0,bitrix_timeline_comment_list=0,"
                    "bitrix_timeline_comment_add=0,bitrix_timeline_comment_get=0"
                    if schema_version == _SCHEMA_VERSION
                    else ""
                )
                if already_revoked:
                    # Legacy V3 allowed generation zero and an older writer could
                    # leave the version/counter pair out of sync.  A repeated
                    # revoke remains historically idempotent (timestamps and
                    # revoker pins are preserved) while normalizing the fields
                    # required by the read-only authority contract.
                    connection.execute(
                        "UPDATE scoped_authority SET authority_version=?,"
                        "authority_generation=?,authority_state='REVOKED',"
                        "imap_inbox_read=0,bitrix_lead_list=0,bitrix_lead_add=0,"
                        "bitrix_lead_get=0,smtp_send=0,unisender_send=0,"
                        "tenderplan_access=0"
                        + projection_zeroes
                        + " WHERE singleton=1",
                        (
                            f"MailToBitrixInbound.v{schema_version}",
                            generation,
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE scoped_authority SET authority_version=?,"
                        "authority_generation=?,authority_state='REVOKED',"
                        "imap_inbox_read=0,bitrix_lead_list=0,bitrix_lead_add=0,"
                        "bitrix_lead_get=0,smtp_send=0,unisender_send=0,"
                        "tenderplan_access=0,revoked_at_utc=?,revocation_reason_hash=?,"
                        "revoked_by_release_sha256=?,revoked_by_runtime_sha256=?"
                        + projection_zeroes
                        + " WHERE singleton=1",
                        (
                            f"MailToBitrixInbound.v{schema_version}",
                            generation,
                            now,
                            _digest(reason),
                            str(release_sha256),
                            str(runtime_sha256),
                        ),
                    )
                _record_authority_generation_tx(connection, generation)
                _invalidate_canary_tx(connection, state="REVOKED")
            for key, value in (
                ("authority_last_revoked_at_utc", now),
                ("authority_last_revoked_generation", str(generation)),
                (
                    "authority_last_revoked_by_release_sha256",
                    str(release_sha256),
                ),
                (
                    "authority_last_revoked_by_runtime_sha256",
                    str(runtime_sha256),
                ),
            ):
                connection.execute(
                    "INSERT INTO meta(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        final = _plain_path_stat(db_path, directory=False)
        if (int(final.st_dev), int(final.st_ino)) != (
            int(before.st_dev),
            int(before.st_ino),
        ):
            raise LiveMailBitrixError("live inbound database identity changed")
        if _assert_plain_directory_chain(root) != root_identities:
            raise LiveMailBitrixError("live inbound storage identity changed")
        for candidate in sidecar_paths:
            _assert_plain_optional_file(candidate)
    return {
        "already_revoked": already_revoked,
        "authority_generation": generation,
        "authority_state": "REVOKED",
        "canary_invalidated": True,
        "ok": True,
        "operational_ready": False,
        "status": "already_revoked" if already_revoked else "revoked",
    }


def build_runtime_from_credentials(
    credentials: LiveConnectionCredentialBundle | None = None,
    **kwargs: Any,
) -> LiveMailBitrixWorker:
    """Build a dormant runtime; callers explicitly invoke each network step."""

    bundle = credentials if credentials is not None else load_live_connection_credentials()
    return LiveMailBitrixWorker(bundle, **kwargs)


__all__ = [
    "AUTHORITY_REVOKE_CONFIRMATION",
    "BITRIX_CANARY_CONFIRMATION",
    "BootstrapRequired",
    "BitrixWriteNotVerified",
    "ConcurrentRun",
    "CredentialContractError",
    "LiveMailBitrixError",
    "LiveMailBitrixWorker",
    "OWNER_AUTHORITY_CONFIRMATION",
    "ORIGINATOR_ID",
    "RemotePreflightError",
    "UidValidityMismatch",
    "build_runtime_from_credentials",
    "revoke_persisted_authority",
]
