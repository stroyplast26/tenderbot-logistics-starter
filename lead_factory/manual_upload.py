"""Bytes-only MANUAL_IMPORT authorization seam for the future schema v17.

The persistent Radar permit ledger still deliberately accepts only
``OFFLINE_FIXTURE`` permits.  Additive schema 17 installs disabled manual-import
ledgers, but it has no durable vault/identity verifier and physically forbids a
final batch commit.  This module therefore stops at a cryptographically sealed,
in-memory ``PREPARED`` envelope.  It contains no file opener, URL client,
credential field, database call, or network transport.  Persistence remains an
explicit fail-closed boundary until a separately reviewed controller/vault
migration exists.

The in-process capability below is a composition and correctness seam, not a
Python security boundary.  Executable persistence must use a durable or
out-of-process authority verifier introduced with the future schema migration.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, NoReturn
from urllib.parse import urlsplit

from .ids import payload_hash


PERSISTENCE_BLOCKED_SCHEMA_17 = "PERSISTENCE_BLOCKED_SCHEMA_17_NO_DURABLE_CONTROLLER"
# Compatibility alias for callers of the original schema-16 scaffold.
PERSISTENCE_BLOCKED_SCHEMA_16 = PERSISTENCE_BLOCKED_SCHEMA_17
MANUAL_UPLOAD_REQUEST_VERSION = "manual-upload-request-v1"
MANUAL_UPLOAD_RECEIPT_VERSION = "manual-upload-receipt-v1"
MANUAL_UPLOAD_ENVELOPE_VERSION = "manual-upload-envelope-v1"


class ManualUploadError(RuntimeError):
    """Safe public base error; messages never include uploaded content."""


class ManualUploadValidationError(ManualUploadError):
    """The upload, grant, authority receipt, or capability is invalid."""


class ManualUploadPersistenceBlocked(ManualUploadError):
    """Schema 17 deliberately has no executable MANUAL_IMPORT controller."""


class ManualUploadFormat(str, Enum):
    CSV = "CSV"
    XLSX = "XLSX"
    JSON = "JSON"
    JSONL = "JSONL"


class ManualUploadState(str, Enum):
    PREPARED = "PREPARED"


@dataclass(frozen=True, slots=True, repr=False)
class ManualUploadAuthorityGrant:
    grant_version: str
    authority_id: str
    grant_id: str
    source_id: str
    passport_id: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    parser_version: str
    run_key: str
    batch_key: str
    manifest_hash: str
    data_class: str
    allowed_formats: tuple[ManualUploadFormat | str, ...]
    purpose_code: str
    legal_basis_ref: str
    operator_actor: str
    approver_actor: str
    valid_from_utc: str
    valid_until_utc: str
    retention_not_after_utc: str
    source_read_epoch: int
    max_bytes: int
    max_declared_records: int

    def __repr__(self) -> str:
        return "ManualUploadAuthorityGrant(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManualUploadRequest:
    blob: bytes
    declared_content_sha256: str
    declared_byte_count: int
    declared_record_count: int
    record_count_verification_state: str
    requires_trusted_parser_verification: bool
    source_id: str
    passport_id: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    parser_version: str
    run_key: str
    batch_key: str
    manifest_hash: str
    data_class: str
    source_format: ManualUploadFormat | str
    purpose_code: str
    legal_basis_ref: str
    retention_until_utc: str
    operator_actor: str
    approver_actor: str
    captured_at_utc: str
    source_read_epoch: int

    def __repr__(self) -> str:
        return "ManualUploadRequest(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManualUploadAuthorityReceipt:
    receipt_version: str
    receipt_id: str
    authority_id: str
    grant_id: str
    request_hash: str
    content_sha256: str
    byte_count: int
    declared_record_count: int
    record_count_verification_state: str
    requires_trusted_parser_verification: bool
    source_id: str
    passport_id: str
    policy_sha256: str
    parser_version: str
    run_key: str
    batch_key: str
    manifest_hash: str
    data_class: str
    source_format: str
    purpose_code: str
    legal_basis_ref: str
    retention_until_utc: str
    operator_actor: str
    approver_actor: str
    captured_at_utc: str
    source_read_epoch: int
    issued_at_utc: str
    valid_until_utc: str
    seal: str

    def __repr__(self) -> str:
        return "ManualUploadAuthorityReceipt(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PreparedManualUpload:
    envelope_version: str
    state: ManualUploadState
    acquisition_mode: str
    request_hash: str
    envelope_hash: str
    parser_version: str
    run_key: str
    batch_key: str
    manifest_hash: str
    declared_record_count: int
    record_count_verification_state: str
    requires_trusted_parser_verification: bool
    blob: bytes
    receipt: ManualUploadAuthorityReceipt

    def __repr__(self) -> str:
        return "PreparedManualUpload(state=PREPARED, content=<redacted>)"


@dataclass(frozen=True, slots=True)
class _ValidatedGrant:
    body: dict[str, object]
    formats: frozenset[ManualUploadFormat]
    valid_from: datetime
    valid_until: datetime
    retention_not_after: datetime


@dataclass(frozen=True, slots=True)
class _ValidatedRequest:
    body: dict[str, object]
    request_hash: str
    blob: bytes
    source_format: ManualUploadFormat
    captured_at: datetime
    retention_until: datetime


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_SAFE_CODE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_BYTES = 4 * 1024 * 1024
_MAX_RECORDS = 10_000
_CAPABILITY_SENTINEL = object()


def _required(value: object, message: str, *, maximum: int = 256) -> str:
    if type(value) is not str:
        raise ManualUploadValidationError(message)
    text = value.strip()
    try:
        encoded = text.encode("utf-8", "strict")
    except UnicodeError:
        raise ManualUploadValidationError(message) from None
    if not text or text != value or len(text) > maximum or len(encoded) > maximum * 4:
        raise ManualUploadValidationError(message)
    return text


def _safe_id(value: object, message: str) -> str:
    text = _required(value, message)
    if not _SAFE_ID.fullmatch(text):
        raise ManualUploadValidationError(message)
    return text


def _code(value: object, message: str) -> str:
    text = _required(value, message, maximum=128).upper()
    if not _SAFE_CODE.fullmatch(text):
        raise ManualUploadValidationError(message)
    return text


def _sha256(value: object, message: str) -> str:
    if type(value) is not str:
        raise ManualUploadValidationError(message)
    text = value.strip().lower()
    if not _HEX64.fullmatch(text):
        raise ManualUploadValidationError(message)
    return text


def _timestamp(value: object, message: str) -> tuple[str, datetime]:
    raw = _required(value, message, maximum=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ManualUploadValidationError(message) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ManualUploadValidationError(message)
    utc = parsed.astimezone(timezone.utc)
    rendered = utc.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), utc


def _clock_now(clock: Callable[[], datetime]) -> tuple[str, datetime]:
    try:
        value = clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("invalid clock value")
        utc = value.astimezone(timezone.utc)
        rendered = utc.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except Exception:
        raise ManualUploadValidationError(
            "manual upload authority clock is invalid"
        ) from None
    return rendered.replace(".000000Z", "Z"), utc


def _legal_ref(value: object) -> str:
    text = _required(value, "manual upload legal basis is invalid", maximum=2048)
    try:
        parsed = urlsplit(text)
    except ValueError:
        raise ManualUploadValidationError("manual upload legal basis is invalid") from None
    if (
        parsed.scheme not in {"evidence", "legal-evidence"}
        or not (parsed.netloc or parsed.path)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in text)
    ):
        raise ManualUploadValidationError("manual upload legal basis is invalid")
    return text


def _positive_int(value: object, message: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ManualUploadValidationError(message)
    return value


def _epoch(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 10**32:
        raise ManualUploadValidationError("manual upload source epoch is invalid")
    return value


def _validate_grant(grant: ManualUploadAuthorityGrant) -> _ValidatedGrant:
    if type(grant) is not ManualUploadAuthorityGrant:
        raise ManualUploadValidationError("manual upload authority grant is invalid")
    grant_version = _required(
        grant.grant_version, "manual upload authority grant version is invalid"
    )
    if grant_version != "manual-upload-authority-grant-v1":
        raise ManualUploadValidationError("manual upload authority grant version is invalid")
    authority_id = _safe_id(grant.authority_id, "manual upload authority is invalid")
    grant_id = _safe_id(grant.grant_id, "manual upload grant identity is invalid")
    source_id = _safe_id(grant.source_id, "manual upload source is invalid")
    passport_id = _safe_id(grant.passport_id, "manual upload passport is invalid")
    policy_id = _safe_id(grant.policy_id, "manual upload policy is invalid")
    policy_version = _safe_id(
        grant.policy_version, "manual upload policy version is invalid"
    )
    policy_sha256 = _sha256(grant.policy_sha256, "manual upload policy digest is invalid")
    parser_version = _safe_id(
        grant.parser_version, "manual upload parser version is invalid"
    )
    run_key = _safe_id(grant.run_key, "manual upload run key is invalid")
    batch_key = _safe_id(grant.batch_key, "manual upload batch key is invalid")
    manifest_hash = _sha256(
        grant.manifest_hash, "manual upload manifest digest is invalid"
    )
    data_class = _code(grant.data_class, "manual upload data class is invalid")
    if data_class != "BUSINESS_PUBLIC":
        raise ManualUploadValidationError("manual upload data class is not allowed")
    purpose_code = _code(grant.purpose_code, "manual upload purpose is invalid")
    legal_basis_ref = _legal_ref(grant.legal_basis_ref)
    operator_actor = _safe_id(grant.operator_actor, "manual upload operator is invalid")
    approver_actor = _safe_id(grant.approver_actor, "manual upload approver is invalid")
    if operator_actor == approver_actor:
        raise ManualUploadValidationError("manual upload requires independent approval")
    valid_from_text, valid_from = _timestamp(
        grant.valid_from_utc, "manual upload grant validity is invalid"
    )
    valid_until_text, valid_until = _timestamp(
        grant.valid_until_utc, "manual upload grant validity is invalid"
    )
    retention_text, retention_not_after = _timestamp(
        grant.retention_not_after_utc, "manual upload retention is invalid"
    )
    if valid_until < valid_from or retention_not_after < valid_from:
        raise ManualUploadValidationError("manual upload grant validity is invalid")
    if type(grant.allowed_formats) is not tuple or not grant.allowed_formats:
        raise ManualUploadValidationError("manual upload formats are invalid")
    try:
        normalized_formats: list[ManualUploadFormat] = []
        for item in grant.allowed_formats:
            if type(item) is ManualUploadFormat:
                normalized_formats.append(item)
            elif type(item) is str:
                normalized_formats.append(ManualUploadFormat(item.upper()))
            else:
                raise ValueError("invalid primitive type")
        formats = frozenset(normalized_formats)
    except (TypeError, ValueError, AttributeError):
        raise ManualUploadValidationError("manual upload formats are invalid") from None
    if len(formats) != len(grant.allowed_formats):
        raise ManualUploadValidationError("manual upload formats are invalid")
    max_bytes = _positive_int(
        grant.max_bytes, "manual upload byte budget is invalid", _MAX_BYTES
    )
    max_declared_records = _positive_int(
        grant.max_declared_records,
        "manual upload declared-record budget is invalid",
        _MAX_RECORDS,
    )
    source_read_epoch = _epoch(grant.source_read_epoch)
    body: dict[str, object] = {
        "grant_version": grant_version,
        "authority_id": authority_id,
        "grant_id": grant_id,
        "source_id": source_id,
        "passport_id": passport_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "parser_version": parser_version,
        "run_key": run_key,
        "batch_key": batch_key,
        "manifest_hash": manifest_hash,
        "data_class": data_class,
        "allowed_formats": sorted(item.value for item in formats),
        "purpose_code": purpose_code,
        "legal_basis_ref": legal_basis_ref,
        "operator_actor": operator_actor,
        "approver_actor": approver_actor,
        "valid_from_utc": valid_from_text,
        "valid_until_utc": valid_until_text,
        "retention_not_after_utc": retention_text,
        "source_read_epoch": source_read_epoch,
        "max_bytes": max_bytes,
        "max_declared_records": max_declared_records,
    }
    payload_hash(body)
    return _ValidatedGrant(body, formats, valid_from, valid_until, retention_not_after)


def _validate_request(
    request: ManualUploadRequest,
    grant: _ValidatedGrant,
    *,
    now: datetime,
) -> _ValidatedRequest:
    if type(request) is not ManualUploadRequest or type(request.blob) is not bytes:
        raise ManualUploadValidationError("manual upload requires an in-memory bytes value")
    blob = request.blob
    if not blob:
        raise ManualUploadValidationError("manual upload content is empty")
    byte_count = _positive_int(
        request.declared_byte_count, "manual upload byte count is invalid", _MAX_BYTES
    )
    declared_record_count = _positive_int(
        request.declared_record_count,
        "manual upload declared record count is invalid",
        _MAX_RECORDS,
    )
    if (
        type(request.record_count_verification_state) is not str
        or request.record_count_verification_state != "DECLARED_UNVERIFIED"
        or request.requires_trusted_parser_verification is not True
    ):
        raise ManualUploadValidationError(
            "manual upload record-count verification state is invalid"
        )
    digest = _sha256(
        request.declared_content_sha256, "manual upload content digest is invalid"
    )
    if len(blob) != byte_count or hashlib.sha256(blob).hexdigest() != digest:
        raise ManualUploadValidationError("manual upload content binding is invalid")
    try:
        if type(request.source_format) is ManualUploadFormat:
            source_format = request.source_format
        elif type(request.source_format) is str:
            source_format = ManualUploadFormat(request.source_format.upper())
        else:
            raise ValueError("invalid primitive type")
    except (TypeError, ValueError, AttributeError):
        raise ManualUploadValidationError("manual upload format is invalid") from None
    captured_text, captured = _timestamp(
        request.captured_at_utc, "manual upload capture timestamp is invalid"
    )
    retention_text, retention_until = _timestamp(
        request.retention_until_utc, "manual upload retention is invalid"
    )
    source_id = _safe_id(request.source_id, "manual upload source is invalid")
    passport_id = _safe_id(request.passport_id, "manual upload passport is invalid")
    policy_id = _safe_id(request.policy_id, "manual upload policy is invalid")
    policy_version = _safe_id(
        request.policy_version, "manual upload policy version is invalid"
    )
    policy_sha256 = _sha256(
        request.policy_sha256, "manual upload policy digest is invalid"
    )
    parser_version = _safe_id(
        request.parser_version, "manual upload parser version is invalid"
    )
    run_key = _safe_id(request.run_key, "manual upload run key is invalid")
    batch_key = _safe_id(request.batch_key, "manual upload batch key is invalid")
    manifest_hash = _sha256(
        request.manifest_hash, "manual upload manifest digest is invalid"
    )
    data_class = _code(request.data_class, "manual upload data class is invalid")
    if data_class != "BUSINESS_PUBLIC":
        raise ManualUploadValidationError("manual upload data class is not allowed")
    purpose_code = _code(request.purpose_code, "manual upload purpose is invalid")
    legal_basis_ref = _legal_ref(request.legal_basis_ref)
    operator_actor = _safe_id(request.operator_actor, "manual upload operator is invalid")
    approver_actor = _safe_id(request.approver_actor, "manual upload approver is invalid")
    source_read_epoch = _epoch(request.source_read_epoch)
    expected = grant.body
    if (
        source_id != expected["source_id"]
        or passport_id != expected["passport_id"]
        or policy_id != expected["policy_id"]
        or policy_version != expected["policy_version"]
        or policy_sha256 != expected["policy_sha256"]
        or parser_version != expected["parser_version"]
        or run_key != expected["run_key"]
        or batch_key != expected["batch_key"]
        or manifest_hash != expected["manifest_hash"]
        or data_class != expected["data_class"]
        or source_format not in grant.formats
        or purpose_code != expected["purpose_code"]
        or legal_basis_ref != expected["legal_basis_ref"]
        or operator_actor != expected["operator_actor"]
        or approver_actor != expected["approver_actor"]
        or source_read_epoch != expected["source_read_epoch"]
        or byte_count > int(expected["max_bytes"])
        or declared_record_count > int(expected["max_declared_records"])
    ):
        raise ManualUploadValidationError("manual upload is outside the authority grant")
    if operator_actor == approver_actor:
        raise ManualUploadValidationError("manual upload requires independent approval")
    if not (
        grant.valid_from <= now <= grant.valid_until
        and grant.valid_from <= captured <= min(now + timedelta(minutes=5), grant.valid_until)
        and max(captured, now) <= retention_until <= grant.retention_not_after
    ):
        raise ManualUploadValidationError("manual upload authorization is not currently valid")
    body: dict[str, object] = {
        "request_version": MANUAL_UPLOAD_REQUEST_VERSION,
        "acquisition_mode": "MANUAL_IMPORT",
        "content_sha256": digest,
        "byte_count": byte_count,
        "declared_record_count": declared_record_count,
        "record_count_verification_state": "DECLARED_UNVERIFIED",
        "requires_trusted_parser_verification": True,
        "source_id": source_id,
        "passport_id": passport_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "parser_version": parser_version,
        "run_key": run_key,
        "batch_key": batch_key,
        "manifest_hash": manifest_hash,
        "data_class": data_class,
        "source_format": source_format.value,
        "purpose_code": purpose_code,
        "legal_basis_ref": legal_basis_ref,
        "retention_until_utc": retention_text,
        "operator_actor": operator_actor,
        "approver_actor": approver_actor,
        "captured_at_utc": captured_text,
        "source_read_epoch": source_read_epoch,
    }
    return _ValidatedRequest(body, payload_hash(body), blob, source_format, captured, retention_until)


def _receipt_body(receipt: ManualUploadAuthorityReceipt) -> dict[str, object]:
    return {
        "receipt_version": receipt.receipt_version,
        "receipt_id": receipt.receipt_id,
        "authority_id": receipt.authority_id,
        "grant_id": receipt.grant_id,
        "request_hash": receipt.request_hash,
        "content_sha256": receipt.content_sha256,
        "byte_count": receipt.byte_count,
        "declared_record_count": receipt.declared_record_count,
        "record_count_verification_state": receipt.record_count_verification_state,
        "requires_trusted_parser_verification": (
            receipt.requires_trusted_parser_verification
        ),
        "source_id": receipt.source_id,
        "passport_id": receipt.passport_id,
        "policy_sha256": receipt.policy_sha256,
        "parser_version": receipt.parser_version,
        "run_key": receipt.run_key,
        "batch_key": receipt.batch_key,
        "manifest_hash": receipt.manifest_hash,
        "data_class": receipt.data_class,
        "source_format": receipt.source_format,
        "purpose_code": receipt.purpose_code,
        "legal_basis_ref": receipt.legal_basis_ref,
        "retention_until_utc": receipt.retention_until_utc,
        "operator_actor": receipt.operator_actor,
        "approver_actor": receipt.approver_actor,
        "captured_at_utc": receipt.captured_at_utc,
        "source_read_epoch": receipt.source_read_epoch,
        "issued_at_utc": receipt.issued_at_utc,
        "valid_until_utc": receipt.valid_until_utc,
    }


def _validate_receipt_shape(
    receipt: ManualUploadAuthorityReceipt,
) -> tuple[dict[str, object], datetime, datetime]:
    if type(receipt) is not ManualUploadAuthorityReceipt:
        raise ManualUploadValidationError("trusted manual upload receipt is required")
    version = _required(
        receipt.receipt_version, "manual upload receipt version is invalid"
    )
    if version != MANUAL_UPLOAD_RECEIPT_VERSION:
        raise ManualUploadValidationError("manual upload receipt version is invalid")
    for value, message in (
        (receipt.receipt_id, "manual upload receipt identity is invalid"),
        (receipt.authority_id, "manual upload receipt authority is invalid"),
        (receipt.grant_id, "manual upload receipt grant is invalid"),
        (receipt.source_id, "manual upload receipt source is invalid"),
        (receipt.passport_id, "manual upload receipt passport is invalid"),
        (receipt.parser_version, "manual upload receipt parser version is invalid"),
        (receipt.run_key, "manual upload receipt run key is invalid"),
        (receipt.batch_key, "manual upload receipt batch key is invalid"),
        (receipt.operator_actor, "manual upload receipt operator is invalid"),
        (receipt.approver_actor, "manual upload receipt approver is invalid"),
    ):
        _safe_id(value, message)
    for value, message in (
        (receipt.request_hash, "manual upload receipt binding is invalid"),
        (receipt.content_sha256, "manual upload receipt binding is invalid"),
        (receipt.policy_sha256, "manual upload receipt binding is invalid"),
        (receipt.manifest_hash, "manual upload receipt binding is invalid"),
        (receipt.seal, "manual upload receipt seal is invalid"),
    ):
        _sha256(value, message)
    data_class = _code(receipt.data_class, "manual upload receipt data class is invalid")
    if data_class != "BUSINESS_PUBLIC":
        raise ManualUploadValidationError("manual upload data class is not allowed")
    _code(receipt.purpose_code, "manual upload receipt purpose is invalid")
    _legal_ref(receipt.legal_basis_ref)
    source_format = _required(
        receipt.source_format, "manual upload receipt format is invalid", maximum=16
    )
    try:
        ManualUploadFormat(source_format)
    except ValueError:
        raise ManualUploadValidationError("manual upload receipt format is invalid") from None
    _positive_int(
        receipt.byte_count, "manual upload receipt byte count is invalid", _MAX_BYTES
    )
    _positive_int(
        receipt.declared_record_count,
        "manual upload receipt declared count is invalid",
        _MAX_RECORDS,
    )
    _epoch(receipt.source_read_epoch)
    if (
        type(receipt.record_count_verification_state) is not str
        or receipt.record_count_verification_state != "DECLARED_UNVERIFIED"
        or receipt.requires_trusted_parser_verification is not True
    ):
        raise ManualUploadValidationError(
            "manual upload receipt verification state is invalid"
        )
    _timestamp(receipt.captured_at_utc, "manual upload receipt timestamp is invalid")
    _timestamp(receipt.retention_until_utc, "manual upload receipt retention is invalid")
    _, issued_at = _timestamp(
        receipt.issued_at_utc, "manual upload receipt validity is invalid"
    )
    _, valid_until = _timestamp(
        receipt.valid_until_utc, "manual upload receipt validity is invalid"
    )
    return _receipt_body(receipt), issued_at, valid_until


class _AuthorityState:
    __slots__ = ("grant", "clock", "key", "issued", "prepared", "lock")

    def __init__(
        self,
        grant: _ValidatedGrant,
        clock: Callable[[], datetime],
    ) -> None:
        self.grant = grant
        self.clock = clock
        self.key = secrets.token_bytes(32)
        self.issued: dict[str, tuple[str, str]] = {}
        self.prepared: dict[str, str] = {}
        self.lock = threading.RLock()

    def seal(self, body: dict[str, object]) -> str:
        digest = payload_hash(body).encode("ascii", "strict")
        return hmac.new(self.key, digest, hashlib.sha256).hexdigest()


class ManualUploadAuthorityCapability:
    """In-process composition marker, not an isolation/security boundary."""

    __slots__ = ("__state",)

    def __init__(self, sentinel: object, state: _AuthorityState) -> None:
        if sentinel is not _CAPABILITY_SENTINEL or type(state) is not _AuthorityState:
            raise ManualUploadValidationError("trusted manual upload capability is required")
        self.__state = state

    def __repr__(self) -> str:
        return "ManualUploadAuthorityCapability(<opaque>)"

class TrustedManualUploadAuthority:
    """In-memory correctness authority for a non-executable schema-v17 seam."""

    __slots__ = ("_state", "_capability")

    def __init__(
        self,
        grant: ManualUploadAuthorityGrant,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        state = _AuthorityState(
            _validate_grant(grant),
            clock or (lambda: datetime.now(timezone.utc)),
        )
        self._state = state
        self._capability = ManualUploadAuthorityCapability(_CAPABILITY_SENTINEL, state)

    def __repr__(self) -> str:
        return "TrustedManualUploadAuthority(<redacted>)"

    @property
    def capability(self) -> ManualUploadAuthorityCapability:
        return self._capability

    def authorize(self, request: ManualUploadRequest) -> ManualUploadAuthorityReceipt:
        issued_at_text, now = _clock_now(self._state.clock)
        validated = _validate_request(request, self._state.grant, now=now)
        receipt_id = "manual-upload-receipt-" + secrets.token_hex(16)
        grant = self._state.grant.body
        valid_until = min(self._state.grant.valid_until, now + timedelta(minutes=10))
        valid_until_text = valid_until.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ).replace(".000000Z", "Z")
        body = {
            "receipt_version": MANUAL_UPLOAD_RECEIPT_VERSION,
            "receipt_id": receipt_id,
            "authority_id": grant["authority_id"],
            "grant_id": grant["grant_id"],
            "request_hash": validated.request_hash,
            "content_sha256": validated.body["content_sha256"],
            "byte_count": validated.body["byte_count"],
            "declared_record_count": validated.body["declared_record_count"],
            "record_count_verification_state": "DECLARED_UNVERIFIED",
            "requires_trusted_parser_verification": True,
            "source_id": validated.body["source_id"],
            "passport_id": validated.body["passport_id"],
            "policy_sha256": validated.body["policy_sha256"],
            "parser_version": validated.body["parser_version"],
            "run_key": validated.body["run_key"],
            "batch_key": validated.body["batch_key"],
            "manifest_hash": validated.body["manifest_hash"],
            "data_class": validated.body["data_class"],
            "source_format": validated.body["source_format"],
            "purpose_code": validated.body["purpose_code"],
            "legal_basis_ref": validated.body["legal_basis_ref"],
            "retention_until_utc": validated.body["retention_until_utc"],
            "operator_actor": validated.body["operator_actor"],
            "approver_actor": validated.body["approver_actor"],
            "captured_at_utc": validated.body["captured_at_utc"],
            "source_read_epoch": validated.body["source_read_epoch"],
            "issued_at_utc": issued_at_text,
            "valid_until_utc": valid_until_text,
        }
        seal = self._state.seal(body)
        receipt = ManualUploadAuthorityReceipt(**body, seal=seal)
        with self._state.lock:
            self._state.issued[receipt_id] = (validated.request_hash, seal)
        return receipt


class ManualUploadPreparer:
    """Verify a trusted receipt and produce a non-persistent typed envelope."""

    __slots__ = ("_state",)

    def __init__(self, capability: ManualUploadAuthorityCapability) -> None:
        if type(capability) is not ManualUploadAuthorityCapability:
            raise ManualUploadValidationError("trusted manual upload capability is required")
        state = object.__getattribute__(
            capability, "_ManualUploadAuthorityCapability__state"
        )
        if type(state) is not _AuthorityState:
            raise ManualUploadValidationError("trusted manual upload capability is required")
        self._state = state

    def prepare(
        self,
        request: ManualUploadRequest,
        *,
        receipt: ManualUploadAuthorityReceipt,
    ) -> PreparedManualUpload:
        _, now = _clock_now(self._state.clock)
        validated = _validate_request(request, self._state.grant, now=now)
        body, issued_at, receipt_valid_until = _validate_receipt_shape(receipt)
        expected = validated.body
        grant = self._state.grant.body
        if (
            receipt.receipt_version != MANUAL_UPLOAD_RECEIPT_VERSION
            or receipt.authority_id != grant["authority_id"]
            or receipt.grant_id != grant["grant_id"]
            or receipt.request_hash != validated.request_hash
            or receipt.content_sha256 != expected["content_sha256"]
            or receipt.byte_count != expected["byte_count"]
            or receipt.declared_record_count != expected["declared_record_count"]
            or receipt.record_count_verification_state != "DECLARED_UNVERIFIED"
            or receipt.requires_trusted_parser_verification is not True
            or receipt.source_id != expected["source_id"]
            or receipt.passport_id != expected["passport_id"]
            or receipt.policy_sha256 != expected["policy_sha256"]
            or receipt.parser_version != expected["parser_version"]
            or receipt.run_key != expected["run_key"]
            or receipt.batch_key != expected["batch_key"]
            or receipt.manifest_hash != expected["manifest_hash"]
            or receipt.data_class != expected["data_class"]
            or receipt.source_format != expected["source_format"]
            or receipt.purpose_code != expected["purpose_code"]
            or receipt.legal_basis_ref != expected["legal_basis_ref"]
            or receipt.retention_until_utc != expected["retention_until_utc"]
            or receipt.operator_actor != expected["operator_actor"]
            or receipt.approver_actor != expected["approver_actor"]
            or receipt.captured_at_utc != expected["captured_at_utc"]
            or receipt.source_read_epoch != expected["source_read_epoch"]
            or not (issued_at <= now <= receipt_valid_until <= self._state.grant.valid_until)
        ):
            raise ManualUploadValidationError("manual upload receipt binding is invalid")
        expected_seal = self._state.seal(body)
        with self._state.lock:
            issued = self._state.issued.get(receipt.receipt_id)
            if (
                issued != (validated.request_hash, receipt.seal)
                or not hmac.compare_digest(expected_seal, receipt.seal)
            ):
                raise ManualUploadValidationError("manual upload receipt is not trusted")
            envelope_body = {
                "envelope_version": MANUAL_UPLOAD_ENVELOPE_VERSION,
                "state": ManualUploadState.PREPARED.value,
                "acquisition_mode": "MANUAL_IMPORT",
                "request_hash": validated.request_hash,
                "receipt_hash": payload_hash({**body, "seal": receipt.seal}),
                "parser_version": validated.body["parser_version"],
                "run_key": validated.body["run_key"],
                "batch_key": validated.body["batch_key"],
                "manifest_hash": validated.body["manifest_hash"],
                "declared_record_count": validated.body["declared_record_count"],
                "record_count_verification_state": "DECLARED_UNVERIFIED",
                "requires_trusted_parser_verification": True,
            }
            envelope_hash = payload_hash(envelope_body)
            prior = self._state.prepared.get(receipt.receipt_id)
            if prior is not None and prior != envelope_hash:
                raise ManualUploadValidationError("manual upload receipt was already consumed")
            self._state.prepared[receipt.receipt_id] = envelope_hash
        return PreparedManualUpload(
            MANUAL_UPLOAD_ENVELOPE_VERSION,
            ManualUploadState.PREPARED,
            "MANUAL_IMPORT",
            validated.request_hash,
            envelope_hash,
            str(validated.body["parser_version"]),
            str(validated.body["run_key"]),
            str(validated.body["batch_key"]),
            str(validated.body["manifest_hash"]),
            int(validated.body["declared_record_count"]),
            "DECLARED_UNVERIFIED",
            True,
            validated.blob,
            receipt,
        )


def persist_prepared_manual_upload(
    prepared: PreparedManualUpload,
    *,
    target: object | None = None,
) -> NoReturn:
    """Fail before inspecting ``target`` or performing any persistent action."""

    del prepared, target
    raise ManualUploadPersistenceBlocked(PERSISTENCE_BLOCKED_SCHEMA_17)


__all__ = (
    "MANUAL_UPLOAD_ENVELOPE_VERSION",
    "MANUAL_UPLOAD_RECEIPT_VERSION",
    "MANUAL_UPLOAD_REQUEST_VERSION",
    "PERSISTENCE_BLOCKED_SCHEMA_16",
    "PERSISTENCE_BLOCKED_SCHEMA_17",
    "ManualUploadAuthorityCapability",
    "ManualUploadAuthorityGrant",
    "ManualUploadAuthorityReceipt",
    "ManualUploadError",
    "ManualUploadFormat",
    "ManualUploadPersistenceBlocked",
    "ManualUploadPreparer",
    "ManualUploadRequest",
    "ManualUploadState",
    "ManualUploadValidationError",
    "PreparedManualUpload",
    "TrustedManualUploadAuthority",
    "persist_prepared_manual_upload",
)
