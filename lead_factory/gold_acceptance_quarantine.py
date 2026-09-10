"""Fail-closed, non-executing Gold acceptance quarantine.

The quarantine is deliberately separate from :mod:`lead_factory.store`.  It
reads one Source Lab database through SQLite's read-only URI mode and writes a
digest-only acceptance fact into a different sidecar database.  It never opens
``crm_outbox`` and the only lawful action it can record is
``CREATE_CRM_TASK``.

SQLite cannot provide an atomic transaction across the independently owned
Source Lab and quarantine databases.  Admission is therefore a snapshot
quarantine: the exact source lineage is checked before and after the sidecar
insert, exact replay checks it again, and every future promotion must call
``revalidate_for_promotion``.  A durable quarantine row is not a promotion
permit.  ``prepare_approval`` initializes and binds a physical sidecar
instance; admission and revalidation never create or silently replace it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence

from .ids import canonical_json, payload_hash
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity


GOLD_QUARANTINE_SCHEMA_VERSION = 2
GOLD_QUARANTINE_APPLICATION_ID = 0x474F4C44  # ``GOLD``
GOLD_QUARANTINE_STATE = "GOLD_QUARANTINED"
GOLD_QUARANTINE_ACTION = "CREATE_CRM_TASK"
GOLD_APPROVAL_REQUEST_VERSION = "gold-quarantine-approval-request-v1"
GOLD_APPROVAL_RECEIPT_VERSION = "gold-quarantine-approval-receipt-v1"
GOLD_APPROVAL_ALGORITHM = "HMAC-SHA256"
GOLD_POLICY_PROFILE_STATUS = "GAP_VERSIONED_STAGE_PROFILE_NOT_BOUND"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_STAGE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SOURCE_READ_EPOCH = re.compile(r"^[0-9]{32}$")
_DECIMAL_ID = re.compile(r"^[1-9][0-9]{0,63}$")
_REQUIRED_SOURCE_TABLES = frozenset(
    {
        "schema_meta",
        "events",
        "source_lab_runs",
        "source_lab_batches",
        "source_lab_records",
        "source_lab_record_observations",
        "source_lab_identity_keys",
        "source_lab_record_identity_links",
        "source_lab_reviews",
        "source_lab_review_resolutions",
    }
)


class GoldQuarantineError(RuntimeError):
    """Base error whose messages are safe for operator reports."""


class GoldQuarantineValidationError(GoldQuarantineError):
    """The command, source lineage, or sidecar schema is malformed."""


class GoldQuarantineConflict(GoldQuarantineError):
    """An immutable idempotency key, receipt, or source scope conflicts."""


class GoldQuarantineSourceDrift(GoldQuarantineError):
    """The approved Source Lab snapshot is no longer current."""


class GoldApprovalReceiptError(GoldQuarantineError):
    """The injected approval receipt cannot authenticate the exact request."""


class GoldQuarantineIntegrityError(GoldQuarantineError):
    """The append-only sidecar ledger is incomplete or has been altered."""


@dataclass(frozen=True, slots=True, repr=False)
class GoldAcceptanceDraft:
    """PII-avoiding references and digests proposed for Gold quarantine."""

    source_record_id: str
    observation_id: str
    review_id: str
    latest_resolution_id: str
    reviewer_id: str
    demand_id: str
    product_key: str
    buyer_id: str
    stage: str
    purchase_deadline_utc: str
    capacity_snapshot_sha256: str
    economics_snapshot_sha256: str
    evidence_sha256: tuple[str, ...]
    idempotency_key: str
    allowed_action: str = GOLD_QUARANTINE_ACTION

    def __repr__(self) -> str:
        return "GoldAcceptanceDraft(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class GoldAcceptanceApprovalRequest:
    """Exact, non-secret material authenticated by an external authority."""

    source_database_identity_sha256: str
    quarantine_database_identity_sha256: str
    source_integrity_count: int
    source_integrity_ledger_sha256: str
    source_read_epoch: str
    source_snapshot_sha256: str
    record_snapshot_sha256: str
    observation_snapshot_sha256: str
    review_snapshot_sha256: str
    resolution_snapshot_sha256: str
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    resolution_event_id: str
    reviewer_id: str
    reviewer_kind: str
    demand_id: str
    product_key: str
    buyer_id: str
    stage: str
    purchase_deadline_utc: str
    capacity_snapshot_sha256: str
    economics_snapshot_sha256: str
    evidence_sha256: tuple[str, ...]
    allowed_action: str
    idempotency_key: str

    def __repr__(self) -> str:
        return "GoldAcceptanceApprovalRequest(<redacted>)"

    @property
    def request_hash(self) -> str:
        return payload_hash(_approval_request_payload(self))


@dataclass(frozen=True, slots=True)
class VerifiedGoldApprovalReceipt:
    authority_id: str
    receipt_id: str
    request_hash: str
    receipt_sha256: str
    issued_at_utc: str
    expires_at_utc: str


@dataclass(frozen=True, slots=True)
class GoldQuarantineResult:
    created: bool
    acceptance_id: str
    state: str
    allowed_action: str
    source_snapshot_sha256: str
    promotion_revalidation_required: bool

    def safe_report(self) -> dict[str, object]:
        return {
            "created": self.created,
            "acceptance_id": self.acceptance_id,
            "state": self.state,
            "allowed_action": self.allowed_action,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "promotion_revalidation_required": self.promotion_revalidation_required,
            "promotion_permit_issued": False,
            "gold_policy_profile_bound": False,
            "gold_policy_profile_status": GOLD_POLICY_PROFILE_STATUS,
            "external_effect": False,
            "contains_pii": False,
        }


@dataclass(frozen=True, slots=True)
class GoldPromotionRevalidation:
    acceptance_id: str
    source_snapshot_sha256: str
    allowed_action: str
    revalidated_at_utc: str
    source_current_at_check: bool
    promotion_permit_issued: bool

    def safe_report(self) -> dict[str, object]:
        return {
            "acceptance_id": self.acceptance_id,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "allowed_action": self.allowed_action,
            "revalidated_at_utc": self.revalidated_at_utc,
            "source_current_at_check": self.source_current_at_check,
            "promotion_permit_issued": self.promotion_permit_issued,
            "gold_policy_profile_bound": False,
            "gold_policy_profile_status": GOLD_POLICY_PROFILE_STATUS,
            "external_effect": False,
            "contains_pii": False,
        }


@dataclass(frozen=True, slots=True, repr=False)
class _SourceSnapshot:
    source_database_identity_sha256: str
    source_integrity_count: int
    source_integrity_ledger_sha256: str
    source_read_epoch: str
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    resolution_event_id: str
    reviewer_id: str
    record_snapshot_sha256: str
    observation_snapshot_sha256: str
    review_snapshot_sha256: str
    resolution_snapshot_sha256: str
    source_snapshot_sha256: str

    def __repr__(self) -> str:
        return "_SourceSnapshot(<redacted>)"


class GoldApprovalVerifier(Protocol):
    """Injected authority boundary; implementations must not persist secrets."""

    def verify(
        self,
        request: GoldAcceptanceApprovalRequest,
        sealed_receipt: bytes,
        *,
        at_utc: datetime,
    ) -> VerifiedGoldApprovalReceipt:
        """Authenticate one exact request or fail closed."""


def _required(value: object, message: str, *, maximum: int = 512) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum or "\x00" in result:
        raise GoldQuarantineValidationError(message)
    return result


def _safe_id(value: object, message: str, *, maximum: int = 256) -> str:
    result = _required(value, message, maximum=maximum)
    if not _SAFE_ID.fullmatch(result):
        raise GoldQuarantineValidationError(message)
    return result


def _principal(value: object, message: str) -> str:
    result = _required(value, message, maximum=128)
    if not _PRINCIPAL.fullmatch(result):
        raise GoldQuarantineValidationError(message)
    return result


def _sha256(value: object, message: str) -> str:
    result = str(value or "").strip().lower()
    if not _HEX64.fullmatch(result):
        raise GoldQuarantineValidationError(message)
    return result


def _utc_text(value: object, message: str) -> tuple[str, datetime]:
    result = str(value or "").strip()
    if not _UTC_SECONDS.fullmatch(result):
        raise GoldQuarantineValidationError(message)
    try:
        parsed = datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise GoldQuarantineValidationError(message) from None
    return result, parsed


def _clock_now(clock: Callable[[], datetime]) -> tuple[str, datetime]:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GoldQuarantineValidationError("Gold quarantine clock is invalid")
    current = value.astimezone(timezone.utc).replace(microsecond=0)
    return current.strftime("%Y-%m-%dT%H:%M:%SZ"), current


def _strict_json_object(value: object, message: str) -> dict[str, Any]:
    raw = str(value or "")

    def pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    def reject_constant(_token: str) -> None:
        raise ValueError("non-finite JSON")

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise GoldQuarantineValidationError(message) from None
    if not isinstance(parsed, dict) or canonical_json(parsed) != raw:
        raise GoldQuarantineValidationError(message)
    return parsed


def _strict_json_array(value: object, message: str) -> list[Any]:
    raw = str(value or "")

    def pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    def reject_constant(_token: str) -> None:
        raise ValueError("non-finite JSON")

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise GoldQuarantineIntegrityError(message) from None
    if not isinstance(parsed, list) or canonical_json(parsed) != raw:
        raise GoldQuarantineIntegrityError(message)
    return parsed


def _row_material(row: sqlite3.Row) -> dict[str, object]:
    return {str(key): row[key] for key in row.keys()}


def _row_snapshot(row: sqlite3.Row) -> str:
    return payload_hash(_row_material(row))


def _rows_snapshot(rows: Sequence[sqlite3.Row]) -> str:
    return payload_hash([_row_material(row) for row in rows])


def _normalise_schema_sql(value: object) -> str:
    result = " ".join(str(value or "").strip().rstrip(";").split()).casefold()
    return result.replace(" if not exists", "")


def _lexical_absolute_path(value: str | Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        raise GoldQuarantineValidationError(
            "Gold quarantine sidecar path is invalid"
        ) from None


def _file_identity(file_stat: os.stat_result) -> tuple[str, str]:
    device_id = str(int(file_stat.st_dev))
    file_id = str(int(file_stat.st_ino))
    if not _DECIMAL_ID.fullmatch(device_id) or not _DECIMAL_ID.fullmatch(file_id):
        raise GoldQuarantineIntegrityError(
            "Gold quarantine physical file identity is unavailable"
        )
    return device_id, file_id


def _database_instance_identity(
    *,
    logical_path_sha256: str,
    instance_nonce: str,
    device_id: str,
    file_id: str,
) -> str:
    return payload_hash(
        {
            "gold_quarantine_database_identity_version": 2,
            "logical_path_sha256": logical_path_sha256,
            "instance_nonce": instance_nonce,
            "device_id": device_id,
            "file_id": file_id,
        }
    )


def _instance_metadata_values(
    *,
    logical_path_sha256: str,
    instance_nonce: str,
    device_id: str,
    file_id: str,
    created_at_utc: str,
) -> dict[str, object]:
    database_identity_sha256 = _database_instance_identity(
        logical_path_sha256=logical_path_sha256,
        instance_nonce=instance_nonce,
        device_id=device_id,
        file_id=file_id,
    )
    material: dict[str, object] = {
        "singleton": 1,
        "instance_nonce": instance_nonce,
        "logical_path_sha256": logical_path_sha256,
        "device_id": device_id,
        "file_id": file_id,
        "database_identity_sha256": database_identity_sha256,
        "created_at_utc": created_at_utc,
    }
    return {
        **material,
        "metadata_sha256": payload_hash(material),
    }


def _approval_request_payload(
    request: GoldAcceptanceApprovalRequest,
) -> dict[str, object]:
    return {
        "request_version": GOLD_APPROVAL_REQUEST_VERSION,
        "source_database_identity_sha256": request.source_database_identity_sha256,
        "quarantine_database_identity_sha256": (
            request.quarantine_database_identity_sha256
        ),
        "source_integrity_count": request.source_integrity_count,
        "source_integrity_ledger_sha256": request.source_integrity_ledger_sha256,
        "source_read_epoch": request.source_read_epoch,
        "source_snapshot_sha256": request.source_snapshot_sha256,
        "record_snapshot_sha256": request.record_snapshot_sha256,
        "observation_snapshot_sha256": request.observation_snapshot_sha256,
        "review_snapshot_sha256": request.review_snapshot_sha256,
        "resolution_snapshot_sha256": request.resolution_snapshot_sha256,
        "source_record_id": request.source_record_id,
        "observation_id": request.observation_id,
        "review_id": request.review_id,
        "resolution_id": request.resolution_id,
        "resolution_event_id": request.resolution_event_id,
        "reviewer_id": request.reviewer_id,
        "reviewer_kind": request.reviewer_kind,
        "demand_id": request.demand_id,
        "product_key": request.product_key,
        "buyer_id": request.buyer_id,
        "stage": request.stage,
        "purchase_deadline_utc": request.purchase_deadline_utc,
        "capacity_snapshot_sha256": request.capacity_snapshot_sha256,
        "economics_snapshot_sha256": request.economics_snapshot_sha256,
        "evidence_sha256": list(request.evidence_sha256),
        "allowed_action": request.allowed_action,
        "idempotency_key": request.idempotency_key,
    }


def _secret_bytes(secret: object) -> bytes:
    if not isinstance(secret, (bytes, bytearray, memoryview)):
        raise GoldApprovalReceiptError("approval secret is unavailable")
    result = bytes(secret)
    if len(result) < 32:
        raise GoldApprovalReceiptError("approval secret is unavailable")
    return result


def _sealed_receipt_sha256(sealed_receipt: object) -> str:
    if not isinstance(sealed_receipt, bytes) or not (
        1 <= len(sealed_receipt) <= 16_384
    ):
        raise GoldApprovalReceiptError("approval receipt is invalid")
    return hashlib.sha256(sealed_receipt).hexdigest()


def _receipt_envelope(
    *,
    authority_id: str,
    receipt_id: str,
    request_hash: str,
    issued_at_utc: str,
    expires_at_utc: str,
) -> dict[str, str]:
    return {
        "receipt_version": GOLD_APPROVAL_RECEIPT_VERSION,
        "algorithm": GOLD_APPROVAL_ALGORITHM,
        "authority_id": authority_id,
        "receipt_id": receipt_id,
        "request_hash": request_hash,
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
    }


def seal_gold_approval(
    request: GoldAcceptanceApprovalRequest,
    *,
    secret: bytes,
    authority_id: str,
    receipt_id: str,
    issued_at_utc: str,
    expires_at_utc: str,
) -> bytes:
    """Create a canonical sealed receipt inside a trusted signing boundary.

    The returned bytes contain no secret.  Callers are responsible for keeping
    the injected ``secret`` outside files, logs, command lines, and reports.
    """

    if type(request) is not GoldAcceptanceApprovalRequest:
        raise GoldApprovalReceiptError("approval request is invalid")
    key = _secret_bytes(secret)
    try:
        authority = _principal(authority_id, "approval authority is invalid")
        receipt = _safe_id(receipt_id, "approval receipt identity is invalid")
        request_hash = _sha256(request.request_hash, "approval request is invalid")
        issued_text, issued = _utc_text(issued_at_utc, "approval receipt time is invalid")
        expires_text, expires = _utc_text(
            expires_at_utc, "approval receipt time is invalid"
        )
    except GoldQuarantineValidationError:
        raise GoldApprovalReceiptError("approval receipt is invalid") from None
    if expires <= issued:
        raise GoldApprovalReceiptError("approval receipt is invalid")
    envelope = _receipt_envelope(
        authority_id=authority,
        receipt_id=receipt,
        request_hash=request_hash,
        issued_at_utc=issued_text,
        expires_at_utc=expires_text,
    )
    body = canonical_json(envelope).encode("utf-8", "strict")
    signature = hmac.new(key, body, hashlib.sha256).hexdigest()
    return canonical_json({"envelope": envelope, "signature": signature}).encode(
        "utf-8", "strict"
    )


class HmacGoldApprovalVerifier:
    """Verify receipts with an injected key that is never persisted or printed."""

    def __init__(self, secret: bytes, *, expected_authority_id: str) -> None:
        self._secret = _secret_bytes(secret)
        try:
            self._authority_id = _principal(
                expected_authority_id, "approval authority is invalid"
            )
        except GoldQuarantineValidationError:
            raise GoldApprovalReceiptError("approval authority is invalid") from None

    def __repr__(self) -> str:
        return "HmacGoldApprovalVerifier(<secret redacted>)"

    def verify(
        self,
        request: GoldAcceptanceApprovalRequest,
        sealed_receipt: bytes,
        *,
        at_utc: datetime,
    ) -> VerifiedGoldApprovalReceipt:
        if type(request) is not GoldAcceptanceApprovalRequest:
            raise GoldApprovalReceiptError("approval request is invalid")
        receipt_sha256 = _sealed_receipt_sha256(sealed_receipt)
        try:
            raw = sealed_receipt.decode("utf-8", "strict")
            token = _strict_json_object(raw, "approval receipt is invalid")
            envelope = token.get("envelope")
            signature = token.get("signature")
            if not isinstance(envelope, dict) or canonical_json(token).encode(
                "utf-8", "strict"
            ) != sealed_receipt:
                raise ValueError("non-canonical receipt")
            if set(token) != {"envelope", "signature"} or set(envelope) != {
                "receipt_version",
                "algorithm",
                "authority_id",
                "receipt_id",
                "request_hash",
                "issued_at_utc",
                "expires_at_utc",
            }:
                raise ValueError("receipt shape")
            if (
                envelope["receipt_version"] != GOLD_APPROVAL_RECEIPT_VERSION
                or envelope["algorithm"] != GOLD_APPROVAL_ALGORITHM
                or envelope["authority_id"] != self._authority_id
                or envelope["request_hash"] != request.request_hash
                or not isinstance(signature, str)
                or not _HEX64.fullmatch(signature)
            ):
                raise ValueError("receipt binding")
            receipt_id = _safe_id(
                envelope["receipt_id"], "approval receipt identity is invalid"
            )
            issued_text, issued = _utc_text(
                envelope["issued_at_utc"], "approval receipt time is invalid"
            )
            expires_text, expires = _utc_text(
                envelope["expires_at_utc"], "approval receipt time is invalid"
            )
            if at_utc.tzinfo is None or at_utc.utcoffset() is None:
                raise ValueError("invalid verification clock")
            current = at_utc.astimezone(timezone.utc).replace(microsecond=0)
            if issued > current or expires <= current or expires <= issued:
                raise ValueError("expired receipt")
            expected = hmac.new(
                self._secret,
                canonical_json(envelope).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid receipt signature")
        except (KeyError, TypeError, ValueError, UnicodeError, GoldQuarantineError):
            raise GoldApprovalReceiptError("approval receipt verification failed") from None
        return VerifiedGoldApprovalReceipt(
            authority_id=self._authority_id,
            receipt_id=receipt_id,
            request_hash=request.request_hash,
            receipt_sha256=receipt_sha256,
            issued_at_utc=issued_text,
            expires_at_utc=expires_text,
        )


def decode_injected_secret(value: str) -> bytes:
    """Decode a base64 secret supplied by the runtime, without logging it."""

    try:
        secret = base64.b64decode(str(value or ""), validate=True)
    except (binascii.Error, ValueError):
        raise GoldApprovalReceiptError("approval secret is unavailable") from None
    return _secret_bytes(secret)


def _validate_draft(
    draft: GoldAcceptanceDraft,
    *,
    current: datetime,
) -> GoldAcceptanceDraft:
    if type(draft) is not GoldAcceptanceDraft:
        raise GoldQuarantineValidationError("Gold quarantine draft is invalid")
    for value, message in (
        (draft.source_record_id, "source record identity is invalid"),
        (draft.observation_id, "source observation identity is invalid"),
        (draft.review_id, "source review identity is invalid"),
        (draft.latest_resolution_id, "source resolution identity is invalid"),
        (draft.demand_id, "demand identity is invalid"),
        (draft.product_key, "product identity is invalid"),
        (draft.buyer_id, "buyer identity is invalid"),
        (draft.idempotency_key, "Gold idempotency key is invalid"),
    ):
        _safe_id(value, message)
    _principal(draft.reviewer_id, "human reviewer identity is invalid")
    if not _STAGE.fullmatch(str(draft.stage or "")):
        raise GoldQuarantineValidationError("purchase stage is invalid")
    deadline_text, deadline = _utc_text(
        draft.purchase_deadline_utc, "purchase deadline is invalid"
    )
    if deadline <= current or deadline > current + timedelta(days=30):
        raise GoldQuarantineValidationError(
            "purchase deadline is outside the 30-day Gold window"
        )
    _sha256(draft.capacity_snapshot_sha256, "capacity snapshot digest is invalid")
    _sha256(draft.economics_snapshot_sha256, "economics snapshot digest is invalid")
    if (
        type(draft.evidence_sha256) is not tuple
        or not draft.evidence_sha256
        or len(draft.evidence_sha256) > 64
        or tuple(sorted(set(draft.evidence_sha256))) != draft.evidence_sha256
        or any(not _HEX64.fullmatch(item) for item in draft.evidence_sha256)
    ):
        raise GoldQuarantineValidationError("evidence digests are invalid")
    if draft.allowed_action != GOLD_QUARANTINE_ACTION:
        raise GoldQuarantineValidationError("Gold action is not permitted")
    if deadline_text != draft.purchase_deadline_utc:
        raise GoldQuarantineValidationError("purchase deadline is invalid")
    return draft


_QUARANTINE_INSTANCE_TABLE_SQL = """CREATE TABLE gold_quarantine_instance (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    instance_nonce TEXT NOT NULL UNIQUE CHECK(length(instance_nonce)=64 AND instance_nonce NOT GLOB '*[^0-9a-f]*'),
    logical_path_sha256 TEXT NOT NULL CHECK(length(logical_path_sha256)=64),
    device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 64 AND device_id NOT GLOB '*[^0-9]*'),
    file_id TEXT NOT NULL CHECK(length(file_id) BETWEEN 1 AND 64 AND file_id NOT GLOB '*[^0-9]*'),
    database_identity_sha256 TEXT NOT NULL UNIQUE CHECK(length(database_identity_sha256)=64),
    metadata_sha256 TEXT NOT NULL UNIQUE CHECK(length(metadata_sha256)=64),
    created_at_utc TEXT NOT NULL
)"""

_QUARANTINE_TABLE_SQL = """CREATE TABLE gold_quarantine_entries (
    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
    acceptance_id TEXT NOT NULL UNIQUE,
    idempotency_key_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_key_sha256)=64),
    command_sha256 TEXT NOT NULL CHECK(length(command_sha256)=64),
    receipt_id TEXT NOT NULL UNIQUE,
    receipt_sha256 TEXT NOT NULL UNIQUE CHECK(length(receipt_sha256)=64),
    authority_id TEXT NOT NULL,
    source_database_identity_sha256 TEXT NOT NULL CHECK(length(source_database_identity_sha256)=64),
    quarantine_database_identity_sha256 TEXT NOT NULL CHECK(length(quarantine_database_identity_sha256)=64),
    source_integrity_count INTEGER NOT NULL CHECK(source_integrity_count>=1),
    source_integrity_ledger_sha256 TEXT NOT NULL CHECK(length(source_integrity_ledger_sha256)=64),
    source_read_epoch TEXT NOT NULL CHECK(length(source_read_epoch)=32 AND source_read_epoch NOT GLOB '*[^0-9]*'),
    source_record_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    resolution_id TEXT NOT NULL,
    resolution_event_id TEXT NOT NULL,
    source_snapshot_sha256 TEXT NOT NULL CHECK(length(source_snapshot_sha256)=64),
    record_snapshot_sha256 TEXT NOT NULL CHECK(length(record_snapshot_sha256)=64),
    observation_snapshot_sha256 TEXT NOT NULL CHECK(length(observation_snapshot_sha256)=64),
    review_snapshot_sha256 TEXT NOT NULL CHECK(length(review_snapshot_sha256)=64),
    resolution_snapshot_sha256 TEXT NOT NULL CHECK(length(resolution_snapshot_sha256)=64),
    reviewer_sha256 TEXT NOT NULL CHECK(length(reviewer_sha256)=64),
    demand_ref_sha256 TEXT NOT NULL CHECK(length(demand_ref_sha256)=64),
    product_ref_sha256 TEXT NOT NULL CHECK(length(product_ref_sha256)=64),
    buyer_ref_sha256 TEXT NOT NULL CHECK(length(buyer_ref_sha256)=64),
    stage TEXT NOT NULL,
    purchase_deadline_utc TEXT NOT NULL,
    capacity_snapshot_sha256 TEXT NOT NULL CHECK(length(capacity_snapshot_sha256)=64),
    economics_snapshot_sha256 TEXT NOT NULL CHECK(length(economics_snapshot_sha256)=64),
    evidence_digests_json TEXT NOT NULL,
    allowed_action TEXT NOT NULL CHECK(allowed_action='CREATE_CRM_TASK'),
    state TEXT NOT NULL CHECK(state='GOLD_QUARANTINED'),
    promotion_revalidation_required INTEGER NOT NULL CHECK(promotion_revalidation_required=1),
    previous_entry_sha256 TEXT NOT NULL CHECK(length(previous_entry_sha256) IN (0,64)),
    entry_sha256 TEXT NOT NULL UNIQUE CHECK(length(entry_sha256)=64),
    created_at_utc TEXT NOT NULL,
    UNIQUE(source_record_id,observation_id,review_id,resolution_id)
)"""

_QUARANTINE_UPDATE_TRIGGER_SQL = """CREATE TRIGGER gold_quarantine_entries_no_update
BEFORE UPDATE ON gold_quarantine_entries BEGIN
    SELECT RAISE(ABORT, 'Gold quarantine entries are immutable');
END"""

_QUARANTINE_DELETE_TRIGGER_SQL = """CREATE TRIGGER gold_quarantine_entries_no_delete
BEFORE DELETE ON gold_quarantine_entries BEGIN
    SELECT RAISE(ABORT, 'Gold quarantine entries are immutable');
END"""

_QUARANTINE_INSTANCE_UPDATE_TRIGGER_SQL = """CREATE TRIGGER gold_quarantine_instance_no_update
BEFORE UPDATE ON gold_quarantine_instance BEGIN
    SELECT RAISE(ABORT, 'Gold quarantine instance is immutable');
END"""

_QUARANTINE_INSTANCE_DELETE_TRIGGER_SQL = """CREATE TRIGGER gold_quarantine_instance_no_delete
BEFORE DELETE ON gold_quarantine_instance BEGIN
    SELECT RAISE(ABORT, 'Gold quarantine instance is immutable');
END"""

_INSTANCE_COLUMNS = (
    "singleton",
    "instance_nonce",
    "logical_path_sha256",
    "device_id",
    "file_id",
    "database_identity_sha256",
    "metadata_sha256",
    "created_at_utc",
)

_ENTRY_COLUMNS = (
    "acceptance_id",
    "idempotency_key_sha256",
    "command_sha256",
    "receipt_id",
    "receipt_sha256",
    "authority_id",
    "source_database_identity_sha256",
    "quarantine_database_identity_sha256",
    "source_integrity_count",
    "source_integrity_ledger_sha256",
    "source_read_epoch",
    "source_record_id",
    "observation_id",
    "review_id",
    "resolution_id",
    "resolution_event_id",
    "source_snapshot_sha256",
    "record_snapshot_sha256",
    "observation_snapshot_sha256",
    "review_snapshot_sha256",
    "resolution_snapshot_sha256",
    "reviewer_sha256",
    "demand_ref_sha256",
    "product_ref_sha256",
    "buyer_ref_sha256",
    "stage",
    "purchase_deadline_utc",
    "capacity_snapshot_sha256",
    "economics_snapshot_sha256",
    "evidence_digests_json",
    "allowed_action",
    "state",
    "promotion_revalidation_required",
    "previous_entry_sha256",
    "created_at_utc",
)


class GoldAcceptanceQuarantine:
    """Admit exact human-approved source facts into a digest-only sidecar."""

    def __init__(
        self,
        source_database: str | Path,
        quarantine_database: str | Path,
        *,
        approval_verifier: GoldApprovalVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        after_sidecar_write: Callable[[], None] | None = None,
    ) -> None:
        try:
            self.source_database = Path(source_database).resolve(strict=True)
        except (OSError, RuntimeError):
            raise GoldQuarantineValidationError(
                "Source Lab database is unavailable"
            ) from None
        self.quarantine_database = _lexical_absolute_path(quarantine_database)
        if self.source_database == self.quarantine_database:
            raise GoldQuarantineValidationError(
                "Gold quarantine must use a separate sidecar database"
            )
        self._assert_no_reparse_components(require_leaf=False)
        if self.quarantine_database.exists():
            try:
                if self.source_database.samefile(self.quarantine_database):
                    raise GoldQuarantineValidationError(
                        "Gold quarantine must use a separate sidecar database"
                    )
            except OSError:
                raise GoldQuarantineValidationError(
                    "Gold quarantine sidecar identity is unavailable"
                ) from None
        self.approval_verifier = approval_verifier
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.after_sidecar_write = after_sidecar_write
        self._source_database_identity_sha256 = payload_hash(
            {
                "gold_source_database_identity_version": 1,
                # Unicode case folding is not injective (for example, `ß`
                # and `ss`).  A security identity must prefer a fail-closed
                # case-alias mismatch over collapsing two distinct files.
                "resolved_path": str(self.source_database),
            }
        )
        self._quarantine_logical_path_sha256 = payload_hash(
            {
                "gold_quarantine_logical_path_version": 1,
                "lexical_absolute_path": str(self.quarantine_database),
            }
        )
        self._quarantine_database_identity_sha256: str | None = None

    def _assert_no_reparse_components(self, *, require_leaf: bool) -> None:
        path = self.quarantine_database
        components: list[Path] = []
        current = path
        while True:
            components.append(current)
            if current == current.parent:
                break
            current = current.parent
        missing_component = False
        for component in reversed(components):
            try:
                component_stat = os.lstat(component)
            except FileNotFoundError:
                missing_component = True
                continue
            except OSError:
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine path identity is unavailable"
                ) from None
            if missing_component:
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine path changed during validation"
                )
            attributes = int(getattr(component_stat, "st_file_attributes", 0))
            reparse_mask = int(
                getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
            if stat.S_ISLNK(component_stat.st_mode) or (
                reparse_mask and attributes & reparse_mask
            ):
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine path cannot contain a reparse point"
                )
            if component != path and not stat.S_ISDIR(component_stat.st_mode):
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine parent path is invalid"
                )
        if require_leaf and missing_component:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine must be prepared before use"
            )

    def _sidecar_file_identity(self) -> tuple[str, str]:
        self._assert_no_reparse_components(require_leaf=True)
        try:
            file_stat = os.stat(self.quarantine_database, follow_symlinks=False)
        except OSError:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine physical file identity is unavailable"
            ) from None
        attributes = int(getattr(file_stat, "st_file_attributes", 0))
        reparse_mask = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_ISLNK(file_stat.st_mode)
            or (reparse_mask and attributes & reparse_mask)
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine physical file identity is invalid"
            )
        return _file_identity(file_stat)

    def _create_sidecar_connection(
        self,
    ) -> tuple[sqlite3.Connection, tuple[str, str]]:
        self._assert_no_reparse_components(require_leaf=False)
        try:
            self.quarantine_database.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise GoldQuarantineValidationError(
                "Gold quarantine sidecar is unavailable"
            ) from None
        self._assert_no_reparse_components(require_leaf=False)
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOINHERIT", 0)
        )
        try:
            descriptor = os.open(self.quarantine_database, flags, 0o600)
        except OSError:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar creation conflict"
            ) from None
        con: sqlite3.Connection | None = None
        try:
            created_identity = _file_identity(os.fstat(descriptor))
            con = sqlite3.connect(
                self.quarantine_database.as_uri() + "?mode=rw",
                uri=True,
                timeout=30,
                isolation_level=None,
            )
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA foreign_keys=ON")
            if self._sidecar_file_identity() != created_identity:
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine path changed during creation"
                )
            return con, created_identity
        except sqlite3.Error:
            if con is not None:
                con.close()
            raise GoldQuarantineValidationError(
                "Gold quarantine sidecar is unavailable"
            ) from None
        except Exception:
            if con is not None:
                con.close()
            raise
        finally:
            os.close(descriptor)

    def _source_connection(self) -> sqlite3.Connection:
        try:
            con = sqlite3.connect(
                self.source_database.as_uri() + "?mode=ro",
                uri=True,
                timeout=30,
                isolation_level=None,
            )
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only=ON")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA busy_timeout=30000")
            return con
        except sqlite3.Error:
            raise GoldQuarantineValidationError(
                "Source Lab database is unavailable"
            ) from None

    def _sidecar_connection(self) -> sqlite3.Connection:
        identity_before = self._sidecar_file_identity()
        con: sqlite3.Connection | None = None
        try:
            con = sqlite3.connect(
                self.quarantine_database.as_uri() + "?mode=rw",
                uri=True,
                timeout=30,
                isolation_level=None,
            )
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA foreign_keys=ON")
            if self._sidecar_file_identity() != identity_before:
                con.close()
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine path changed while opening"
                )
            return con
        except sqlite3.Error:
            if con is not None:
                con.close()
            raise GoldQuarantineIntegrityError(
                "Gold quarantine must be prepared before use"
            ) from None
        except Exception:
            if con is not None:
                con.close()
            raise

    @staticmethod
    def _table_names(con: sqlite3.Connection) -> set[str]:
        return {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            if not str(row[0]).startswith("sqlite_")
        }

    def _assert_source_schema(self, con: sqlite3.Connection) -> None:
        if not _REQUIRED_SOURCE_TABLES.issubset(self._table_names(con)):
            raise GoldQuarantineValidationError("Source Lab schema is incomplete")
        version = int(con.execute("PRAGMA user_version").fetchone()[0])
        if version < 17:
            raise GoldQuarantineValidationError(
                "Source Lab review queue schema is required"
            )
        writer = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        if not writer or str(writer[0]) != "0":
            raise GoldQuarantineValidationError(
                "external writers must be disabled for Gold quarantine"
            )

    @staticmethod
    def _assert_payload_event(
        event: sqlite3.Row | None,
        *,
        event_type: str,
        producer: str,
        aggregate_id: str,
        actor: str | None = None,
    ) -> dict[str, Any]:
        if (
            event is None
            or str(event["event_type"]) != event_type
            or str(event["producer"]) != producer
            or str(event["aggregate_id"]) != aggregate_id
            or (actor is not None and str(event["actor"]) != actor)
        ):
            raise GoldQuarantineValidationError("Source Lab event binding is invalid")
        payload = _strict_json_object(
            event["payload_json"], "Source Lab event payload is invalid"
        )
        if str(event["payload_hash"]) != payload_hash(payload):
            raise GoldQuarantineValidationError("Source Lab event digest is invalid")
        return payload

    def _load_source_snapshot(self, draft: GoldAcceptanceDraft) -> _SourceSnapshot:
        con = self._source_connection()
        try:
            con.execute("BEGIN")
            self._assert_source_schema(con)
            try:
                integrity = validate_source_lab_integrity(con)
            except SourceLabIntegrityError:
                raise GoldQuarantineValidationError(
                    "Source Lab integrity validation failed"
                ) from None
            integrity_count = integrity.get("count")
            integrity_ledger_sha256 = str(
                integrity.get("ledger_sha256", "") or ""
            ).strip().lower()
            epoch_row = con.execute(
                "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
            ).fetchone()
            source_read_epoch = str(epoch_row[0] if epoch_row else "")
            if (
                type(integrity_count) is not int
                or integrity_count < 1
                or not _HEX64.fullmatch(integrity_ledger_sha256)
                or not _SOURCE_READ_EPOCH.fullmatch(source_read_epoch)
            ):
                raise GoldQuarantineValidationError(
                    "Source Lab integrity evidence is invalid"
                )
            record = con.execute(
                "SELECT * FROM source_lab_records WHERE source_record_id=?",
                (draft.source_record_id,),
            ).fetchone()
            if record is None:
                raise GoldQuarantineValidationError("source record does not exist")
            record_payload = _strict_json_object(
                record["payload_json"], "source record payload is invalid"
            )
            if str(record["payload_hash"]) != payload_hash(record_payload):
                raise GoldQuarantineValidationError("source record digest is invalid")
            external_key_hash = payload_hash(
                {
                    "source_lab_external_key_version": 1,
                    "source_id": str(record["source_id"]),
                    "external_key": str(record["external_key"]),
                }
            )
            record_identity_hash = payload_hash(
                {
                    "source_lab_record_version": 1,
                    "source_id": str(record["source_id"]),
                    "external_key_hash": external_key_hash,
                    "payload_hash": str(record["payload_hash"]),
                }
            )
            if (
                str(record["external_key_hash"]) != external_key_hash
                or str(record["record_identity_hash"]) != record_identity_hash
            ):
                raise GoldQuarantineValidationError("source record identity is invalid")

            observations = con.execute(
                """SELECT * FROM source_lab_record_observations
                   WHERE source_record_id=?
                   ORDER BY observed_at_utc DESC,created_at_utc DESC,observation_id DESC""",
                (draft.source_record_id,),
            ).fetchall()
            selected = [
                row for row in observations if str(row["observation_id"]) == draft.observation_id
            ]
            if len(selected) != 1:
                raise GoldQuarantineValidationError(
                    "source observation binding is invalid"
                )
            observation = selected[0]
            latest_observed_at = str(observations[0]["observed_at_utc"])
            if (
                sum(
                    str(row["observed_at_utc"]) == latest_observed_at
                    for row in observations
                )
                != 1
                or str(observations[0]["observation_id"]) != draft.observation_id
            ):
                raise GoldQuarantineSourceDrift(
                    "current source observation changed"
                )
            if str(observation["source_id"]) != str(record["source_id"]):
                raise GoldQuarantineValidationError(
                    "source observation binding is invalid"
                )
            run = con.execute(
                "SELECT * FROM source_lab_runs WHERE source_run_id=?",
                (observation["source_run_id"],),
            ).fetchone()
            batch = con.execute(
                "SELECT * FROM source_lab_batches WHERE source_batch_id=?",
                (observation["source_batch_id"],),
            ).fetchone()
            if (
                run is None
                or batch is None
                or str(run["source_id"]) != str(observation["source_id"])
                or str(run["acquisition_mode"]) != str(observation["acquisition_mode"])
                or str(run["run_key"]) != str(observation["run_key"])
                or str(batch["source_run_id"]) != str(observation["source_run_id"])
            ):
                raise GoldQuarantineValidationError(
                    "source observation provenance is invalid"
                )
            provenance_hash = payload_hash(
                {
                    "source_lab_run_version": 1,
                    "source_id": str(run["source_id"]),
                    "acquisition_mode": str(run["acquisition_mode"]),
                    "run_key": str(run["run_key"]),
                }
            )
            if str(run["provenance_hash"]) != provenance_hash:
                raise GoldQuarantineValidationError(
                    "source observation provenance is invalid"
                )
            identity_rows = con.execute(
                """SELECT l.identity_link_id,l.source_record_id,l.observation_id,
                          l.identity_key_id,l.evidence_ref AS link_evidence_ref,
                          l.created_at_utc AS link_created_at_utc,
                          k.key_namespace,k.canonical_key_hash,
                          k.created_at_utc AS key_created_at_utc
                   FROM source_lab_record_identity_links l
                   JOIN source_lab_identity_keys k
                     ON k.identity_key_id=l.identity_key_id
                   WHERE l.observation_id=?
                   ORDER BY k.canonical_key_hash,l.identity_link_id""",
                (draft.observation_id,),
            ).fetchall()
            identity_hashes = tuple(
                sorted(str(row["canonical_key_hash"]) for row in identity_rows)
            )
            if len(set(identity_hashes)) != len(identity_hashes) or any(
                not _HEX64.fullmatch(item) for item in identity_hashes
            ):
                raise GoldQuarantineValidationError(
                    "source observation identities are invalid"
                )
            command_v1: dict[str, object] = {
                "source_lab_ingest_version": 1,
                "source_id": str(observation["source_id"]),
                "acquisition_mode": str(observation["acquisition_mode"]),
                "run_key": str(observation["run_key"]),
                "external_key_hash": external_key_hash,
                "payload_hash": str(record["payload_hash"]),
                "evidence_ref": str(observation["evidence_ref"]),
                "canonical_key_hashes": identity_hashes,
            }
            command_v2 = {
                **command_v1,
                "source_lab_ingest_version": 2,
                "batch_key": str(batch["batch_key"]),
                "batch_manifest_hash": str(batch["manifest_hash"]),
            }
            if str(observation["command_hash"]) not in {
                payload_hash(command_v1),
                payload_hash(command_v2),
            }:
                raise GoldQuarantineValidationError(
                    "source observation command digest is invalid"
                )
            observation_event = con.execute(
                "SELECT * FROM events WHERE event_id=?", (observation["event_id"],)
            ).fetchone()
            observation_payload = self._assert_payload_event(
                observation_event,
                event_type="source_lab_record_ingested",
                producer="source_lab",
                aggregate_id=draft.source_record_id,
                actor="source_lab_sink",
            )
            if (
                observation_payload.get("observation_id") != draft.observation_id
                or observation_payload.get("record_identity_hash")
                != record_identity_hash
                or observation_payload.get("payload_hash") != str(record["payload_hash"])
            ):
                raise GoldQuarantineValidationError(
                    "source observation event binding is invalid"
                )

            reviews = con.execute(
                """SELECT * FROM source_lab_reviews
                   WHERE source_record_id=? AND review_kind='QUALIFICATION'
                   ORDER BY created_at_utc DESC,review_id DESC""",
                (draft.source_record_id,),
            ).fetchall()
            if not reviews:
                raise GoldQuarantineValidationError(
                    "latest qualification review is unavailable"
                )
            latest_time = str(reviews[0]["created_at_utc"])
            if (
                sum(str(row["created_at_utc"]) == latest_time for row in reviews) != 1
                or str(reviews[0]["review_id"]) != draft.review_id
            ):
                raise GoldQuarantineSourceDrift(
                    "latest qualification review changed"
                )
            review = reviews[0]
            review_command = {
                "source_lab_review_version": 1,
                "source_record_id": draft.source_record_id,
                "review_kind": "QUALIFICATION",
                "reason": str(review["reason"]),
                "requested_by": str(review["requested_by"]),
                "evidence_ref": str(review["evidence_ref"]),
            }
            if str(review["command_hash"]) != payload_hash(review_command):
                raise GoldQuarantineValidationError(
                    "qualification review digest is invalid"
                )
            review_event = con.execute(
                "SELECT * FROM events WHERE event_id=?", (review["event_id"],)
            ).fetchone()
            review_payload = self._assert_payload_event(
                review_event,
                event_type="source_lab_review_requested",
                producer="source_lab",
                aggregate_id=draft.review_id,
                actor=str(review["requested_by"]),
            )
            if (
                review_payload.get("source_record_id") != draft.source_record_id
                or review_payload.get("review_kind") != "QUALIFICATION"
                or review_payload.get("command_hash") != str(review["command_hash"])
            ):
                raise GoldQuarantineValidationError(
                    "qualification review event binding is invalid"
                )

            resolutions = con.execute(
                """SELECT * FROM source_lab_review_resolutions
                   WHERE review_id=? ORDER BY sequence_number""",
                (draft.review_id,),
            ).fetchall()
            if not resolutions:
                raise GoldQuarantineValidationError(
                    "qualification resolution is unavailable"
                )
            previous_resolution_id = ""
            for index, row in enumerate(resolutions, start=1):
                if (
                    int(row["sequence_number"]) != index
                    or str(row["supersedes_resolution_id"] or "")
                    != previous_resolution_id
                ):
                    raise GoldQuarantineValidationError(
                        "qualification resolution chain is invalid"
                    )
                previous_resolution_id = str(row["resolution_id"])
            resolution = resolutions[-1]
            if (
                str(resolution["resolution_id"]) != draft.latest_resolution_id
                or str(resolution["decision"]).upper() != "APPROVE"
                or str(resolution["resolved_by"]) != draft.reviewer_id
            ):
                raise GoldQuarantineSourceDrift(
                    "latest qualification resolution is not the approved human fact"
                )
            resolution_command = {
                "source_lab_resolution_version": 1,
                "review_id": draft.review_id,
                "decision": "APPROVE",
                "reason": str(resolution["reason"]),
                "resolved_by": draft.reviewer_id,
                "evidence_ref": str(resolution["evidence_ref"]),
                "supersedes_resolution_id": str(
                    resolution["supersedes_resolution_id"] or ""
                ),
            }
            if str(resolution["command_hash"]) != payload_hash(resolution_command):
                raise GoldQuarantineValidationError(
                    "qualification resolution digest is invalid"
                )
            resolution_event = con.execute(
                "SELECT * FROM events WHERE event_id=?", (resolution["event_id"],)
            ).fetchone()
            resolution_payload = self._assert_payload_event(
                resolution_event,
                event_type="source_lab_review_resolved",
                producer="source_lab",
                aggregate_id=draft.review_id,
                actor=draft.reviewer_id,
            )
            if (
                resolution_payload.get("resolution_id")
                != draft.latest_resolution_id
                or resolution_payload.get("decision") != "APPROVE"
                or resolution_payload.get("command_hash")
                != str(resolution["command_hash"])
            ):
                raise GoldQuarantineValidationError(
                    "qualification resolution event binding is invalid"
                )

            queue_events = con.execute(
                """SELECT * FROM events
                   WHERE aggregate_id=? AND producer='source_lab_review_queue'
                     AND event_type='source_lab_review_resolution_recorded'
                   ORDER BY recorded_at_utc,event_id""",
                (draft.review_id,),
            ).fetchall()
            parsed_queue_events: list[tuple[int, sqlite3.Row, dict[str, Any]]] = []
            for event in queue_events:
                payload = self._assert_payload_event(
                    event,
                    event_type="source_lab_review_resolution_recorded",
                    producer="source_lab_review_queue",
                    aggregate_id=draft.review_id,
                )
                revision = payload.get("revision")
                if type(revision) is not int or revision < 1:
                    raise GoldQuarantineValidationError(
                        "review queue resolution event is invalid"
                    )
                parsed_queue_events.append((revision, event, payload))
            if not parsed_queue_events:
                raise GoldQuarantineValidationError(
                    "human review queue resolution evidence is required"
                )
            parsed_queue_events.sort(key=lambda item: (item[0], str(item[1]["event_id"])))
            if len({item[0] for item in parsed_queue_events}) != len(parsed_queue_events):
                raise GoldQuarantineValidationError(
                    "review queue resolution history is ambiguous"
                )
            queue_payload = parsed_queue_events[-1][2]
            queue_event = parsed_queue_events[-1][1]
            if (
                queue_payload.get("resolution_id") != draft.latest_resolution_id
                or queue_payload.get("resolution_event_id")
                != str(resolution["event_id"])
                or queue_payload.get("decision") != "APPROVE"
                or queue_payload.get("resolved_by") != draft.reviewer_id
                or queue_payload.get("resolution_command_hash")
                != str(resolution["command_hash"])
                or str(queue_event["actor"]) != draft.reviewer_id
            ):
                raise GoldQuarantineSourceDrift(
                    "latest human review queue resolution changed"
                )

            record_snapshot = _row_snapshot(record)
            observation_snapshot = payload_hash(
                {
                    "selected_observation": _row_material(observation),
                    "all_record_observations_sha256": _rows_snapshot(observations),
                    "all_record_observations_count": len(observations),
                    "run_sha256": _row_snapshot(run),
                    "batch_sha256": _row_snapshot(batch),
                    "observation_event_sha256": _row_snapshot(observation_event),
                    "identity_hashes": list(identity_hashes),
                    "identity_lineage_sha256": _rows_snapshot(identity_rows),
                }
            )
            review_snapshot = payload_hash(
                {
                    "selected_review": _row_material(review),
                    "all_qualification_reviews_sha256": _rows_snapshot(reviews),
                    "all_qualification_reviews_count": len(reviews),
                    "review_event_sha256": _row_snapshot(review_event),
                }
            )
            resolution_snapshot = payload_hash(
                {
                    "latest_resolution": _row_material(resolution),
                    "all_resolutions_sha256": _rows_snapshot(resolutions),
                    "all_resolutions_count": len(resolutions),
                    "resolution_event_sha256": _row_snapshot(resolution_event),
                    "queue_events_sha256": _rows_snapshot(queue_events),
                    "queue_events_count": len(queue_events),
                }
            )
            source_snapshot = payload_hash(
                {
                    "gold_source_snapshot_version": 1,
                    "source_database_identity_sha256": (
                        self._source_database_identity_sha256
                    ),
                    "record_snapshot_sha256": record_snapshot,
                    "observation_snapshot_sha256": observation_snapshot,
                    "review_snapshot_sha256": review_snapshot,
                    "resolution_snapshot_sha256": resolution_snapshot,
                    "source_integrity_count": integrity_count,
                    "source_integrity_ledger_sha256": integrity_ledger_sha256,
                    "source_read_epoch": source_read_epoch,
                    "external_writers_enabled": False,
                }
            )
            con.rollback()
            return _SourceSnapshot(
                source_database_identity_sha256=(
                    self._source_database_identity_sha256
                ),
                source_integrity_count=integrity_count,
                source_integrity_ledger_sha256=integrity_ledger_sha256,
                source_read_epoch=source_read_epoch,
                source_record_id=draft.source_record_id,
                observation_id=draft.observation_id,
                review_id=draft.review_id,
                resolution_id=draft.latest_resolution_id,
                resolution_event_id=str(resolution["event_id"]),
                reviewer_id=draft.reviewer_id,
                record_snapshot_sha256=record_snapshot,
                observation_snapshot_sha256=observation_snapshot,
                review_snapshot_sha256=review_snapshot,
                resolution_snapshot_sha256=resolution_snapshot,
                source_snapshot_sha256=source_snapshot,
            )
        except sqlite3.Error:
            raise GoldQuarantineValidationError(
                "Source Lab snapshot is unavailable"
            ) from None
        finally:
            try:
                con.rollback()
            except sqlite3.Error:
                pass
            con.close()

    def _request_from_snapshot(
        self, draft: GoldAcceptanceDraft, snapshot: _SourceSnapshot
    ) -> GoldAcceptanceApprovalRequest:
        quarantine_identity = self._quarantine_database_identity_sha256
        if (
            not isinstance(quarantine_identity, str)
            or not _HEX64.fullmatch(quarantine_identity)
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine must be prepared before sealing"
            )
        return GoldAcceptanceApprovalRequest(
            source_database_identity_sha256=snapshot.source_database_identity_sha256,
            quarantine_database_identity_sha256=quarantine_identity,
            source_integrity_count=snapshot.source_integrity_count,
            source_integrity_ledger_sha256=(
                snapshot.source_integrity_ledger_sha256
            ),
            source_read_epoch=snapshot.source_read_epoch,
            source_snapshot_sha256=snapshot.source_snapshot_sha256,
            record_snapshot_sha256=snapshot.record_snapshot_sha256,
            observation_snapshot_sha256=snapshot.observation_snapshot_sha256,
            review_snapshot_sha256=snapshot.review_snapshot_sha256,
            resolution_snapshot_sha256=snapshot.resolution_snapshot_sha256,
            source_record_id=snapshot.source_record_id,
            observation_id=snapshot.observation_id,
            review_id=snapshot.review_id,
            resolution_id=snapshot.resolution_id,
            resolution_event_id=snapshot.resolution_event_id,
            reviewer_id=snapshot.reviewer_id,
            reviewer_kind="HUMAN",
            demand_id=draft.demand_id,
            product_key=draft.product_key,
            buyer_id=draft.buyer_id,
            stage=draft.stage,
            purchase_deadline_utc=draft.purchase_deadline_utc,
            capacity_snapshot_sha256=draft.capacity_snapshot_sha256,
            economics_snapshot_sha256=draft.economics_snapshot_sha256,
            evidence_sha256=draft.evidence_sha256,
            allowed_action=draft.allowed_action,
            idempotency_key=draft.idempotency_key,
        )

    def prepare_approval(
        self, draft: GoldAcceptanceDraft
    ) -> GoldAcceptanceApprovalRequest:
        """Build the exact current request for out-of-process human sealing."""

        now_text, current = _clock_now(self.clock)
        validated = _validate_draft(draft, current=current)
        snapshot_before = self._load_source_snapshot(validated)
        self._initialize_sidecar_for_sealing(now_text)
        snapshot_after = self._load_source_snapshot(validated)
        if snapshot_before != snapshot_after:
            raise GoldQuarantineSourceDrift(
                "Source Lab approval snapshot changed during preparation"
            )
        return self._request_from_snapshot(validated, snapshot_after)

    @staticmethod
    def _schema_columns(
        con: sqlite3.Connection, table_name: str
    ) -> tuple[str, ...]:
        return tuple(
            str(row[1])
            for row in con.execute(f"PRAGMA table_info({table_name})")
        )

    def _assert_sidecar_instance(
        self,
        con: sqlite3.Connection,
        *,
        expected_identity: str | None = None,
    ) -> str:
        physical_identity = self._sidecar_file_identity()
        application_id = int(con.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(con.execute("PRAGMA user_version").fetchone()[0])
        if application_id != GOLD_QUARANTINE_APPLICATION_ID:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar identity is invalid"
            )
        if user_version != GOLD_QUARANTINE_SCHEMA_VERSION:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar version is invalid"
            )
        if self._table_names(con) != {
            "gold_quarantine_instance",
            "gold_quarantine_entries",
        }:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar contains an unmanaged table"
            )
        schema_objects = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in con.execute(
                """SELECT type,name,tbl_name FROM sqlite_master
                   WHERE name NOT LIKE 'sqlite_%'"""
            ).fetchall()
        }
        expected_schema_objects = {
            ("table", "gold_quarantine_instance", "gold_quarantine_instance"),
            ("table", "gold_quarantine_entries", "gold_quarantine_entries"),
            (
                "trigger",
                "gold_quarantine_instance_no_update",
                "gold_quarantine_instance",
            ),
            (
                "trigger",
                "gold_quarantine_instance_no_delete",
                "gold_quarantine_instance",
            ),
            (
                "trigger",
                "gold_quarantine_entries_no_update",
                "gold_quarantine_entries",
            ),
            (
                "trigger",
                "gold_quarantine_entries_no_delete",
                "gold_quarantine_entries",
            ),
        }
        if schema_objects != expected_schema_objects:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar schema is invalid"
            )
        expected_entry_columns = (
            ("sequence_number",)
            + _ENTRY_COLUMNS[:-1]
            + ("entry_sha256", "created_at_utc")
        )
        if (
            self._schema_columns(con, "gold_quarantine_instance")
            != _INSTANCE_COLUMNS
            or self._schema_columns(con, "gold_quarantine_entries")
            != expected_entry_columns
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar schema is invalid"
            )
        table_sql = {
            str(row[0]): str(row[1] or "")
            for row in con.execute(
                """SELECT name,sql FROM sqlite_master
                   WHERE type='table' AND name IN (
                       'gold_quarantine_instance','gold_quarantine_entries'
                   )"""
            ).fetchall()
        }
        expected_table_sql = {
            "gold_quarantine_instance": _QUARANTINE_INSTANCE_TABLE_SQL,
            "gold_quarantine_entries": _QUARANTINE_TABLE_SQL,
        }
        if set(table_sql) != set(expected_table_sql) or any(
            _normalise_schema_sql(table_sql[name])
            != _normalise_schema_sql(expected_sql)
            for name, expected_sql in expected_table_sql.items()
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar schema is invalid"
            )
        trigger_rows = {
            str(row[0]): (str(row[1]), str(row[2] or ""))
            for row in con.execute(
                """SELECT name,tbl_name,sql FROM sqlite_master
                   WHERE type='trigger' AND tbl_name IN (
                       'gold_quarantine_instance','gold_quarantine_entries'
                   )"""
            ).fetchall()
        }
        expected_triggers = {
            "gold_quarantine_instance_no_update": (
                "gold_quarantine_instance",
                _QUARANTINE_INSTANCE_UPDATE_TRIGGER_SQL,
            ),
            "gold_quarantine_instance_no_delete": (
                "gold_quarantine_instance",
                _QUARANTINE_INSTANCE_DELETE_TRIGGER_SQL,
            ),
            "gold_quarantine_entries_no_update": (
                "gold_quarantine_entries",
                _QUARANTINE_UPDATE_TRIGGER_SQL,
            ),
            "gold_quarantine_entries_no_delete": (
                "gold_quarantine_entries",
                _QUARANTINE_DELETE_TRIGGER_SQL,
            ),
        }
        if set(trigger_rows) != set(expected_triggers) or any(
            actual_table != expected_table
            or _normalise_schema_sql(actual_sql)
            != _normalise_schema_sql(expected_sql)
            for name, (expected_table, expected_sql) in expected_triggers.items()
            for actual_table, actual_sql in (trigger_rows[name],)
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine append-only guards are invalid"
            )
        rows = con.execute(
            "SELECT * FROM gold_quarantine_instance ORDER BY singleton"
        ).fetchall()
        if len(rows) != 1:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine instance metadata is invalid"
            )
        row = rows[0]
        instance_nonce = str(row["instance_nonce"])
        logical_path_sha256 = str(row["logical_path_sha256"])
        device_id = str(row["device_id"])
        file_id = str(row["file_id"])
        created_at_utc = str(row["created_at_utc"])
        try:
            canonical_created_at_utc, _ = _utc_text(
                created_at_utc, "Gold quarantine creation time is invalid"
            )
        except GoldQuarantineValidationError:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine instance metadata is invalid"
            ) from None
        if (
            row["singleton"] != 1
            or not _HEX64.fullmatch(instance_nonce)
            or logical_path_sha256 != self._quarantine_logical_path_sha256
            or not _DECIMAL_ID.fullmatch(device_id)
            or not _DECIMAL_ID.fullmatch(file_id)
            or (device_id, file_id) != physical_identity
            or canonical_created_at_utc != created_at_utc
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine instance metadata is invalid"
            )
        expected_values = _instance_metadata_values(
            logical_path_sha256=logical_path_sha256,
            instance_nonce=instance_nonce,
            device_id=device_id,
            file_id=file_id,
            created_at_utc=created_at_utc,
        )
        if any(row[column] != expected_values[column] for column in _INSTANCE_COLUMNS):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine instance metadata is invalid"
            )
        identity = str(row["database_identity_sha256"])
        bound_identity = self._quarantine_database_identity_sha256
        if (
            (expected_identity is not None and identity != expected_identity)
            or (bound_identity is not None and identity != bound_identity)
            or self._sidecar_file_identity() != physical_identity
        ):
            raise GoldQuarantineIntegrityError(
                "Gold quarantine database instance changed"
            )
        self._quarantine_database_identity_sha256 = identity
        return identity

    def _load_sidecar_identity(self) -> str:
        con = self._sidecar_connection()
        try:
            con.execute("BEGIN")
            identity = self._assert_sidecar_instance(con)
            con.commit()
            return identity
        except sqlite3.Error:
            con.rollback()
            raise GoldQuarantineIntegrityError(
                "Gold quarantine instance validation failed"
            ) from None
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _initialize_sidecar_for_sealing(self, created_at_utc: str) -> str:
        self._assert_no_reparse_components(require_leaf=False)
        if os.path.lexists(self.quarantine_database):
            return self._load_sidecar_identity()
        con, physical_identity = self._create_sidecar_connection()
        prior_identity = self._quarantine_database_identity_sha256
        try:
            con.execute("BEGIN EXCLUSIVE")
            if (
                self._table_names(con)
                or int(con.execute("PRAGMA application_id").fetchone()[0]) != 0
                or int(con.execute("PRAGMA user_version").fetchone()[0]) != 0
            ):
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine sidecar creation conflict"
                )
            con.execute(_QUARANTINE_INSTANCE_TABLE_SQL)
            con.execute(_QUARANTINE_TABLE_SQL)
            con.execute(_QUARANTINE_INSTANCE_UPDATE_TRIGGER_SQL)
            con.execute(_QUARANTINE_INSTANCE_DELETE_TRIGGER_SQL)
            con.execute(_QUARANTINE_UPDATE_TRIGGER_SQL)
            con.execute(_QUARANTINE_DELETE_TRIGGER_SQL)
            values = _instance_metadata_values(
                logical_path_sha256=self._quarantine_logical_path_sha256,
                instance_nonce=secrets.token_hex(32),
                device_id=physical_identity[0],
                file_id=physical_identity[1],
                created_at_utc=created_at_utc,
            )
            con.execute(
                f"INSERT INTO gold_quarantine_instance({','.join(_INSTANCE_COLUMNS)}) "
                f"VALUES({','.join('?' for _ in _INSTANCE_COLUMNS)})",
                tuple(values[column] for column in _INSTANCE_COLUMNS),
            )
            con.execute(f"PRAGMA application_id={GOLD_QUARANTINE_APPLICATION_ID}")
            con.execute(f"PRAGMA user_version={GOLD_QUARANTINE_SCHEMA_VERSION}")
            identity = self._assert_sidecar_instance(
                con,
                expected_identity=str(values["database_identity_sha256"]),
            )
            con.commit()
        except sqlite3.Error:
            con.rollback()
            self._quarantine_database_identity_sha256 = prior_identity
            raise GoldQuarantineIntegrityError(
                "Gold quarantine sidecar initialization failed"
            ) from None
        except Exception:
            con.rollback()
            self._quarantine_database_identity_sha256 = prior_identity
            raise
        finally:
            con.close()
        if self._load_sidecar_identity() != identity:
            raise GoldQuarantineIntegrityError(
                "Gold quarantine database instance changed"
            )
        return identity

    @staticmethod
    def _entry_material_from_row(row: sqlite3.Row) -> dict[str, object]:
        return {column: row[column] for column in _ENTRY_COLUMNS}

    def _assert_ledger_integrity(self, con: sqlite3.Connection) -> tuple[int, str]:
        rows = con.execute(
            "SELECT * FROM gold_quarantine_entries ORDER BY sequence_number"
        ).fetchall()
        previous = ""
        expected_sequence = 1
        for row in rows:
            if (
                int(row["sequence_number"]) != expected_sequence
                or str(row["previous_entry_sha256"]) != previous
                or str(row["state"]) != GOLD_QUARANTINE_STATE
                or str(row["allowed_action"]) != GOLD_QUARANTINE_ACTION
                or int(row["promotion_revalidation_required"]) != 1
                or str(row["entry_sha256"])
                != payload_hash(self._entry_material_from_row(row))
            ):
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine ledger integrity check failed"
                )
            previous = str(row["entry_sha256"])
            expected_sequence += 1
        return len(rows), previous

    @staticmethod
    def _entry_values(
        request: GoldAcceptanceApprovalRequest,
        receipt: VerifiedGoldApprovalReceipt,
        *,
        acceptance_id: str,
        created_at_utc: str,
        previous_entry_sha256: str,
    ) -> dict[str, object]:
        return {
            "acceptance_id": acceptance_id,
            "idempotency_key_sha256": payload_hash(
                {"gold_idempotency_key_version": 1, "value": request.idempotency_key}
            ),
            "command_sha256": request.request_hash,
            "receipt_id": receipt.receipt_id,
            "receipt_sha256": receipt.receipt_sha256,
            "authority_id": receipt.authority_id,
            "source_database_identity_sha256": request.source_database_identity_sha256,
            "quarantine_database_identity_sha256": (
                request.quarantine_database_identity_sha256
            ),
            "source_integrity_count": request.source_integrity_count,
            "source_integrity_ledger_sha256": (
                request.source_integrity_ledger_sha256
            ),
            "source_read_epoch": request.source_read_epoch,
            "source_record_id": request.source_record_id,
            "observation_id": request.observation_id,
            "review_id": request.review_id,
            "resolution_id": request.resolution_id,
            "resolution_event_id": request.resolution_event_id,
            "source_snapshot_sha256": request.source_snapshot_sha256,
            "record_snapshot_sha256": request.record_snapshot_sha256,
            "observation_snapshot_sha256": request.observation_snapshot_sha256,
            "review_snapshot_sha256": request.review_snapshot_sha256,
            "resolution_snapshot_sha256": request.resolution_snapshot_sha256,
            "reviewer_sha256": payload_hash(
                {"gold_reviewer_ref_version": 1, "value": request.reviewer_id}
            ),
            "demand_ref_sha256": payload_hash(
                {"gold_demand_ref_version": 1, "value": request.demand_id}
            ),
            "product_ref_sha256": payload_hash(
                {"gold_product_ref_version": 1, "value": request.product_key}
            ),
            "buyer_ref_sha256": payload_hash(
                {"gold_buyer_ref_version": 1, "value": request.buyer_id}
            ),
            "stage": request.stage,
            "purchase_deadline_utc": request.purchase_deadline_utc,
            "capacity_snapshot_sha256": request.capacity_snapshot_sha256,
            "economics_snapshot_sha256": request.economics_snapshot_sha256,
            "evidence_digests_json": canonical_json(list(request.evidence_sha256)),
            "allowed_action": GOLD_QUARANTINE_ACTION,
            "state": GOLD_QUARANTINE_STATE,
            "promotion_revalidation_required": 1,
            "previous_entry_sha256": previous_entry_sha256,
            "created_at_utc": created_at_utc,
        }

    @staticmethod
    def _assert_current_request(
        request: GoldAcceptanceApprovalRequest,
        current: GoldAcceptanceApprovalRequest,
    ) -> None:
        if request != current or request.request_hash != current.request_hash:
            raise GoldQuarantineSourceDrift("Source Lab approval snapshot changed")

    def _verify_approval_receipt(
        self,
        request: GoldAcceptanceApprovalRequest,
        sealed_approval_receipt: bytes,
        *,
        at_utc: datetime,
    ) -> VerifiedGoldApprovalReceipt:
        receipt_sha256 = _sealed_receipt_sha256(sealed_approval_receipt)
        verifier = self.approval_verifier
        if verifier is None or not callable(getattr(verifier, "verify", None)):
            raise GoldApprovalReceiptError("approval verifier is unavailable")
        try:
            receipt = verifier.verify(
                request, sealed_approval_receipt, at_utc=at_utc
            )
        except GoldQuarantineError:
            raise
        except Exception:
            raise GoldApprovalReceiptError(
                "approval receipt verification failed"
            ) from None
        if type(receipt) is not VerifiedGoldApprovalReceipt:
            raise GoldApprovalReceiptError("approval receipt verification failed")
        try:
            authority_id = _principal(
                receipt.authority_id, "approval authority is invalid"
            )
            receipt_id = _safe_id(
                receipt.receipt_id, "approval receipt identity is invalid"
            )
            request_hash = _sha256(
                receipt.request_hash, "approval request is invalid"
            )
            verified_receipt_sha256 = _sha256(
                receipt.receipt_sha256, "approval receipt is invalid"
            )
            issued_at_utc, _ = _utc_text(
                receipt.issued_at_utc, "approval receipt time is invalid"
            )
            expires_at_utc, _ = _utc_text(
                receipt.expires_at_utc, "approval receipt time is invalid"
            )
        except GoldQuarantineValidationError:
            raise GoldApprovalReceiptError(
                "approval receipt verification failed"
            ) from None
        if (
            authority_id != receipt.authority_id
            or receipt_id != receipt.receipt_id
            or request_hash != receipt.request_hash
            or request_hash != request.request_hash
            or verified_receipt_sha256 != receipt.receipt_sha256
            or verified_receipt_sha256 != receipt_sha256
            or issued_at_utc != receipt.issued_at_utc
            or expires_at_utc != receipt.expires_at_utc
        ):
            raise GoldApprovalReceiptError("approval receipt verification failed")
        return receipt

    def _row_matches_exact_request(
        self,
        row: sqlite3.Row,
        request: GoldAcceptanceApprovalRequest,
        receipt: VerifiedGoldApprovalReceipt,
    ) -> bool:
        expected = self._entry_values(
            request,
            receipt,
            acceptance_id=str(row["acceptance_id"]),
            created_at_utc=str(row["created_at_utc"]),
            previous_entry_sha256=str(row["previous_entry_sha256"]),
        )
        return all(row[column] == expected[column] for column in _ENTRY_COLUMNS)

    @staticmethod
    def _result_from_existing(
        row: sqlite3.Row, request: GoldAcceptanceApprovalRequest
    ) -> GoldQuarantineResult:
        return GoldQuarantineResult(
            created=False,
            acceptance_id=str(row["acceptance_id"]),
            state=GOLD_QUARANTINE_STATE,
            allowed_action=GOLD_QUARANTINE_ACTION,
            source_snapshot_sha256=request.source_snapshot_sha256,
            promotion_revalidation_required=True,
        )

    def _recover_existing_replay(
        self,
        validated: GoldAcceptanceDraft,
        request: GoldAcceptanceApprovalRequest,
        sealed_approval_receipt: bytes,
        *,
        current: datetime,
    ) -> GoldQuarantineResult | None:
        """Authenticate and recover an already durable row, even after expiry."""

        _sealed_receipt_sha256(sealed_approval_receipt)
        verifier = self.approval_verifier
        if verifier is None or not callable(getattr(verifier, "verify", None)):
            raise GoldApprovalReceiptError("approval verifier is unavailable")
        con = self._sidecar_connection()
        try:
            con.execute("BEGIN IMMEDIATE")
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            self._assert_ledger_integrity(con)
            current_before = self._request_from_snapshot(
                validated, self._load_source_snapshot(validated)
            )
            self._assert_current_request(request, current_before)
            idempotency_digest = payload_hash(
                {
                    "gold_idempotency_key_version": 1,
                    "value": request.idempotency_key,
                }
            )
            existing = con.execute(
                """SELECT * FROM gold_quarantine_entries
                   WHERE idempotency_key_sha256=?""",
                (idempotency_digest,),
            ).fetchone()
            if existing is None:
                con.commit()
                return None
            try:
                created_at_utc, created_at = _utc_text(
                    existing["created_at_utc"],
                    "Gold quarantine creation time is invalid",
                )
            except GoldQuarantineValidationError:
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine creation time is invalid"
                ) from None
            if created_at_utc != existing["created_at_utc"] or created_at > current:
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine creation time is invalid"
                )
            receipt = self._verify_approval_receipt(
                request,
                sealed_approval_receipt,
                at_utc=created_at,
            )
            if not self._row_matches_exact_request(existing, request, receipt):
                raise GoldQuarantineConflict("Gold idempotency conflict")
            current_after = self._request_from_snapshot(
                validated, self._load_source_snapshot(validated)
            )
            self._assert_current_request(request, current_after)
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            con.commit()
            return self._result_from_existing(existing, request)
        except sqlite3.Error:
            con.rollback()
            raise GoldQuarantineIntegrityError(
                "Gold quarantine replay validation failed"
            ) from None
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def admit(
        self,
        draft: GoldAcceptanceDraft,
        *,
        sealed_approval_receipt: bytes,
    ) -> GoldQuarantineResult:
        """Append one quarantine fact; never stage or execute a CRM operation."""

        now_text, current = _clock_now(self.clock)
        self._load_sidecar_identity()
        validated = _validate_draft(draft, current=current)
        snapshot = self._load_source_snapshot(validated)
        request = self._request_from_snapshot(validated, snapshot)
        recovered = self._recover_existing_replay(
            validated,
            request,
            sealed_approval_receipt,
            current=current,
        )
        if recovered is not None:
            return recovered
        receipt = self._verify_approval_receipt(
            request, sealed_approval_receipt, at_utc=current
        )

        con = self._sidecar_connection()
        try:
            con.execute("BEGIN IMMEDIATE")
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            _, previous = self._assert_ledger_integrity(con)
            current_before = self._request_from_snapshot(
                validated, self._load_source_snapshot(validated)
            )
            self._assert_current_request(request, current_before)
            idempotency_digest = payload_hash(
                {"gold_idempotency_key_version": 1, "value": request.idempotency_key}
            )
            existing = con.execute(
                """SELECT * FROM gold_quarantine_entries
                   WHERE idempotency_key_sha256=?""",
                (idempotency_digest,),
            ).fetchone()
            if existing is not None:
                if not self._row_matches_exact_request(existing, request, receipt):
                    raise GoldQuarantineConflict("Gold idempotency conflict")
                current_after = self._request_from_snapshot(
                    validated, self._load_source_snapshot(validated)
                )
                self._assert_current_request(request, current_after)
                self._assert_sidecar_instance(
                    con,
                    expected_identity=request.quarantine_database_identity_sha256,
                )
                con.commit()
                return self._result_from_existing(existing, request)
            reused = con.execute(
                """SELECT 1 FROM gold_quarantine_entries
                   WHERE receipt_id=? OR receipt_sha256=? OR (
                       source_record_id=? AND observation_id=?
                       AND review_id=? AND resolution_id=?
                   ) LIMIT 1""",
                (
                    receipt.receipt_id,
                    receipt.receipt_sha256,
                    request.source_record_id,
                    request.observation_id,
                    request.review_id,
                    request.resolution_id,
                ),
            ).fetchone()
            if reused:
                raise GoldQuarantineConflict(
                    "approval receipt or source scope was already consumed"
                )
            acceptance_id = "lf_gold_quarantine_" + uuid.uuid4().hex
            values = self._entry_values(
                request,
                receipt,
                acceptance_id=acceptance_id,
                created_at_utc=now_text,
                previous_entry_sha256=previous,
            )
            entry_sha256 = payload_hash(values)
            columns = _ENTRY_COLUMNS + ("entry_sha256",)
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            con.execute(
                f"INSERT INTO gold_quarantine_entries({','.join(columns)}) "
                f"VALUES({','.join('?' for _ in columns)})",
                tuple(values[column] for column in _ENTRY_COLUMNS)
                + (entry_sha256,),
            )
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            if self.after_sidecar_write is not None:
                self.after_sidecar_write()
            current_after = self._request_from_snapshot(
                validated, self._load_source_snapshot(validated)
            )
            self._assert_current_request(request, current_after)
            self._assert_ledger_integrity(con)
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            con.commit()
        except sqlite3.IntegrityError:
            con.rollback()
            raise GoldQuarantineConflict(
                "concurrent Gold quarantine admission conflict"
            ) from None
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

        # This observation cannot make the cross-database write atomic.  It
        # catches immediate drift; revalidate_for_promotion remains mandatory.
        current_committed = self._request_from_snapshot(
            validated, self._load_source_snapshot(validated)
        )
        self._assert_current_request(request, current_committed)
        return GoldQuarantineResult(
            True,
            acceptance_id,
            GOLD_QUARANTINE_STATE,
            GOLD_QUARANTINE_ACTION,
            request.source_snapshot_sha256,
            True,
        )

    def revalidate_for_promotion(
        self,
        acceptance_id: str,
        draft: GoldAcceptanceDraft,
        *,
        sealed_approval_receipt: bytes,
    ) -> GoldPromotionRevalidation:
        """Check current source and authority; never issue a promotion permit."""

        acceptance = _safe_id(
            acceptance_id, "Gold quarantine acceptance identity is invalid"
        )
        now_text, current = _clock_now(self.clock)
        self._load_sidecar_identity()
        validated = _validate_draft(draft, current=current)
        snapshot = self._load_source_snapshot(validated)
        request = self._request_from_snapshot(validated, snapshot)
        receipt = self._verify_approval_receipt(
            request, sealed_approval_receipt, at_utc=current
        )
        con = self._sidecar_connection()
        try:
            con.execute("BEGIN")
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            self._assert_ledger_integrity(con)
            row = con.execute(
                "SELECT * FROM gold_quarantine_entries WHERE acceptance_id=?",
                (acceptance,),
            ).fetchone()
            if row is None:
                raise GoldQuarantineValidationError(
                    "Gold quarantine acceptance does not exist"
                )
            evidence = _strict_json_array(
                row["evidence_digests_json"],
                "Gold quarantine evidence digests are invalid",
            )
            if (
                not evidence
                or tuple(sorted(set(evidence))) != tuple(evidence)
                or any(
                    not isinstance(item, str) or not _HEX64.fullmatch(item)
                    for item in evidence
                )
            ):
                raise GoldQuarantineIntegrityError(
                    "Gold quarantine evidence digests are invalid"
                )
            current_snapshot = self._load_source_snapshot(validated)
            current_request = self._request_from_snapshot(
                validated, current_snapshot
            )
            self._assert_current_request(request, current_request)
            if (
                str(row["receipt_id"]) != receipt.receipt_id
                or str(row["receipt_sha256"]) != receipt.receipt_sha256
                or str(row["authority_id"]) != receipt.authority_id
            ):
                raise GoldApprovalReceiptError(
                    "sealed approval receipt does not match the quarantine entry"
                )
            if (
                tuple(evidence) != validated.evidence_sha256
                or not self._row_matches_exact_request(row, request, receipt)
            ):
                raise GoldQuarantineSourceDrift(
                    "Source Lab approval snapshot changed"
                )
            self._assert_sidecar_instance(
                con,
                expected_identity=request.quarantine_database_identity_sha256,
            )
            con.commit()
            return GoldPromotionRevalidation(
                acceptance_id=acceptance,
                source_snapshot_sha256=current_snapshot.source_snapshot_sha256,
                allowed_action=GOLD_QUARANTINE_ACTION,
                revalidated_at_utc=now_text,
                source_current_at_check=True,
                promotion_permit_issued=False,
            )
        except sqlite3.Error:
            con.rollback()
            raise GoldQuarantineIntegrityError(
                "Gold quarantine revalidation failed"
            ) from None
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def safe_report(self) -> dict[str, object]:
        """Return aggregate, digest-only evidence with no source payload or PII."""

        now_text, _ = _clock_now(self.clock)
        initialized_now = not os.path.lexists(self.quarantine_database)
        if initialized_now:
            expected_identity = self._initialize_sidecar_for_sealing(now_text)
        else:
            expected_identity = self._load_sidecar_identity()
        con = self._sidecar_connection()
        try:
            con.execute("BEGIN")
            self._assert_sidecar_instance(
                con, expected_identity=expected_identity
            )
            count, head = self._assert_ledger_integrity(con)
            self._assert_sidecar_instance(
                con, expected_identity=expected_identity
            )
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
        return {
            "schema_version": "gold-quarantine-report-v2",
            "quarantine_database_identity_sha256": expected_identity,
            "state_counts": {GOLD_QUARANTINE_STATE: count},
            "total": count,
            "ledger_head_sha256": head,
            "allowed_actions": [GOLD_QUARANTINE_ACTION],
            "promotion_revalidation_required": True,
            "promotion_permit_issued": False,
            "gold_policy_profile_bound": False,
            "gold_policy_profile_status": GOLD_POLICY_PROFILE_STATUS,
            "local_sidecar_initialized_now": initialized_now,
            "local_persistence_effect": "INITIALIZE_IF_MISSING",
            "external_effect": False,
            "contains_pii": False,
        }


__all__ = [
    "GOLD_APPROVAL_ALGORITHM",
    "GOLD_APPROVAL_RECEIPT_VERSION",
    "GOLD_APPROVAL_REQUEST_VERSION",
    "GOLD_POLICY_PROFILE_STATUS",
    "GOLD_QUARANTINE_ACTION",
    "GOLD_QUARANTINE_STATE",
    "GoldAcceptanceApprovalRequest",
    "GoldAcceptanceDraft",
    "GoldAcceptanceQuarantine",
    "GoldApprovalReceiptError",
    "GoldPromotionRevalidation",
    "GoldQuarantineConflict",
    "GoldQuarantineError",
    "GoldQuarantineIntegrityError",
    "GoldQuarantineResult",
    "GoldQuarantineSourceDrift",
    "GoldQuarantineValidationError",
    "HmacGoldApprovalVerifier",
    "VerifiedGoldApprovalReceipt",
    "decode_injected_secret",
    "seal_gold_approval",
]
