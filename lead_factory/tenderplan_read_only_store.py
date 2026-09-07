"""Local append-only store for manually invoked TenderPlan read-only intake.

The store is deliberately independent from the application database.  It has
no HTTP client, credential resolver, scheduler, Source Lab bridge, CRM bridge,
outbox, or provider-write capability.  A caller must first reserve a strictly
digest-bound intent.  The unresolved intent is then independently verified by
the worker before any credential or network boundary is entered.

Only encrypted review-card envelopes cross this boundary.  The SQLite file is
new-store schema v1: unknown, copied, moved, drifted, or older stores are
rejected and are never migrated in place.  All operational tables are
append-only and current state is derived from their immutable history.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Final

from lead_factory.tenderplan_read_only_crypto import (
    EncryptedTenderPlanCardV1,
    encrypted_card_material,
)


TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION: Final = 1
TENDERPLAN_READ_ONLY_STORE_APPLICATION_ID: Final = 0x54505231  # ``TPR1``
TENDERPLAN_READ_ONLY_STORE_CONTRACT_ID: Final = "tenderplan-read-only-store-v1"
TENDERPLAN_READ_ONLY_INTENT_VERSION: Final = "tenderplan-read-only-intent-v1"
TENDERPLAN_READ_ONLY_RECEIPT_VERSION: Final = "tenderplan-read-only-receipt-v1"
TENDERPLAN_READ_ONLY_RETENTION_DAYS: Final = 30
TENDERPLAN_READ_ONLY_MAXIMUM_CARDS: Final = 5
TENDERPLAN_READ_ONLY_MAXIMUM_RESPONSE_BYTES: Final = 1_048_576
TENDERPLAN_READ_ONLY_QUEUE_PATH: Final = (
    Path(__file__).resolve().parent.parent
    / "state"
    / "lead_factory"
    / "tenderplan_read_only_queue.sqlite3"
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_GENESIS_SHA256 = "0" * 64

_INTENT_KEYS: Final = frozenset(
    {
        "automatic_schedule_eligible",
        "auth_reference_id_sha256",
        "contact_count",
        "credential_target_sha256",
        "expires_at_utc",
        "intent_record_sha256",
        "live_release_eligible",
        "maximum_records",
        "maximum_response_bytes",
        "nonce_sha256",
        "protocol",
        "query_policy_sha256",
        "request_count",
        "request_sha256",
        "requested_at_utc",
        "run_id",
        "spend_minor",
        "write_count",
    }
)
_INTENT_HASH_KEYS: Final = (
    "auth_reference_id_sha256",
    "credential_target_sha256",
    "nonce_sha256",
    "query_policy_sha256",
    "request_sha256",
)
_RECEIPT_KEYS: Final = frozenset(
    {
        "automatic_schedule_eligible",
        "card_count",
        "cards_sha256",
        "captured_at_utc",
        "contact_count",
        "intent_record_sha256",
        "live_release_eligible",
        "provider_reported_count",
        "projection_sha256",
        "receipt_record_sha256",
        "receipt_version",
        "request_count",
        "request_sha256",
        "response_body_sha256",
        "response_byte_count",
        "returned_count",
        "run_id",
        "spend_minor",
        "write_count",
    }
)


class TenderPlanReadOnlyStoreError(RuntimeError):
    """Sanitized local-store failure."""

    code = "tenderplan_read_only_store_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


class TenderPlanReadOnlyStoreValidationError(TenderPlanReadOnlyStoreError):
    code = "tenderplan_read_only_store_input_invalid"


class TenderPlanReadOnlyStoreIntegrityError(TenderPlanReadOnlyStoreError):
    code = "tenderplan_read_only_store_integrity_failed"


class TenderPlanReadOnlyStoreConflict(TenderPlanReadOnlyStoreError):
    code = "tenderplan_read_only_store_conflict"


class TenderPlanReadOnlyStoreReconciliationRequired(TenderPlanReadOnlyStoreError):
    code = "tenderplan_read_only_store_reconciliation_required"


class TenderPlanReadOnlyRunState(str, Enum):
    INTENT = "INTENT"
    DISPATCH_CLAIMED = "DISPATCH_CLAIMED"
    FAILED_CLOSED = "FAILED_CLOSED"
    UNCERTAIN = "UNCERTAIN"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"


class TenderPlanReadOnlyDecision(str, Enum):
    KEEP = "KEEP"
    DISMISS = "DISMISS"
    HOLD = "HOLD"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyOperationReceipt:
    created: bool
    run_id: str
    state: TenderPlanReadOnlyRunState
    intent_record_sha256: str
    event_sha256: str
    card_count: int
    live_release_eligible: bool = False
    automatic_schedule_eligible: bool = False
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyOperationReceipt(content=<digest-only>, "
            f"state={self.state.value!r}, effects=zero, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyUncertainBinding:
    """Read-only, verified binding for non-authoritative diagnostics."""

    run_id: str
    store_identity_sha256: str
    main_uncertain_event_sha256: str
    intent_record_sha256: str
    request_sha256: str
    state: TenderPlanReadOnlyRunState = TenderPlanReadOnlyRunState.UNCERTAIN
    retry_eligible: bool = False
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyUncertainBinding(content=<digest-only>, "
            "state='UNCERTAIN', retry_eligible=False, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyReadyReceipt:
    run_id: str
    receipt_record_sha256: str
    event_sha256: str
    card_count: int
    item_ids: tuple[str, ...]
    live_release_eligible: bool = False
    automatic_schedule_eligible: bool = False
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyReadyReceipt(content=<encrypted-and-digest-only>, "
            "state='READY_FOR_REVIEW', effects=zero, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedTenderPlanWorkerIntent:
    run_id: str
    intent_record_sha256: str
    request_sha256: str
    maximum_response_bytes: int
    maximum_records: int

    def __repr__(self) -> str:
        return "VerifiedTenderPlanWorkerIntent(material=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyItem:
    item_id: str
    run_id: str
    state: str
    encrypted_card_sha256: str
    latest_decision_id: str
    latest_reason_code: str
    created_at_utc: str

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyItem(content=<encrypted>, "
            f"item_id={self.item_id!r}, state={self.state!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyDecisionReceipt:
    decision_id: str
    item_id: str
    decision: TenderPlanReadOnlyDecision
    reason_code: str
    sequence: int
    decision_sha256: str
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyDecisionReceipt(content=<local-only>, "
            f"decision={self.decision.value!r}, effects=zero)"
        )


_SCHEMA_SQL = """
CREATE TABLE tenderplan_read_only_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE tenderplan_read_only_operations(
    run_id TEXT PRIMARY KEY,
    intent_record_sha256 TEXT NOT NULL UNIQUE,
    intent_json TEXT NOT NULL,
    reserved_at_utc TEXT NOT NULL,
    operation_sha256 TEXT NOT NULL UNIQUE
) WITHOUT ROWID;

CREATE TABLE tenderplan_read_only_events(
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN (
        'INTENT_COMMITTED','DISPATCH_CLAIMED_COMMITTED','FAILED_CLOSED_COMMITTED',
        'UNCERTAIN_COMMITTED','READY_FOR_REVIEW_COMMITTED'
    )),
    state TEXT NOT NULL CHECK(state IN (
        'INTENT','DISPATCH_CLAIMED','FAILED_CLOSED','UNCERTAIN','READY_FOR_REVIEW'
    )),
    occurred_at_utc TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    payload_json TEXT,
    card_count INTEGER NOT NULL CHECK(card_count BETWEEN 0 AND 5),
    previous_event_sha256 TEXT NOT NULL,
    event_sha256 TEXT NOT NULL UNIQUE,
    FOREIGN KEY(run_id) REFERENCES tenderplan_read_only_operations(run_id)
);

CREATE TABLE tenderplan_read_only_cards(
    item_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 5),
    ciphertext TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL,
    encrypted_card_sha256 TEXT NOT NULL UNIQUE,
    created_at_utc TEXT NOT NULL,
    card_record_sha256 TEXT NOT NULL UNIQUE,
    UNIQUE(run_id,ordinal),
    FOREIGN KEY(run_id) REFERENCES tenderplan_read_only_operations(run_id)
);

CREATE TABLE tenderplan_read_only_decisions(
    decision_id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    decision TEXT NOT NULL CHECK(decision IN ('KEEP','DISMISS','HOLD')),
    reason_code TEXT NOT NULL,
    decided_at_utc TEXT NOT NULL,
    previous_decision_sha256 TEXT NOT NULL,
    decision_sha256 TEXT NOT NULL UNIQUE,
    UNIQUE(item_id,sequence),
    FOREIGN KEY(item_id) REFERENCES tenderplan_read_only_cards(item_id)
);

CREATE TRIGGER trg_tenderplan_read_only_meta_no_update
BEFORE UPDATE ON tenderplan_read_only_meta BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only metadata is immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_meta_no_delete
BEFORE DELETE ON tenderplan_read_only_meta BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only metadata is immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_operations_no_update
BEFORE UPDATE ON tenderplan_read_only_operations BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only operations are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_operations_no_delete
BEFORE DELETE ON tenderplan_read_only_operations BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only operations are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_events_no_update
BEFORE UPDATE ON tenderplan_read_only_events BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only events are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_events_no_delete
BEFORE DELETE ON tenderplan_read_only_events BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only events are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_cards_no_update
BEFORE UPDATE ON tenderplan_read_only_cards BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only cards are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_cards_no_delete
BEFORE DELETE ON tenderplan_read_only_cards BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only cards are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_decisions_no_update
BEFORE UPDATE ON tenderplan_read_only_decisions BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only decisions are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_decisions_no_delete
BEFORE DELETE ON tenderplan_read_only_decisions BEGIN
    SELECT RAISE(ABORT,'TenderPlan read-only decisions are immutable');
END;
"""

# Changed only for an explicitly reviewed new-store schema.  There is no
# v0-to-v1 or unknown-store migration path.
TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256: Final = (
    "a5b5b5fe09944a439dfe6d002f462808ef12bce16f04752b9feeb171350daf0d"
)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise TenderPlanReadOnlyStoreValidationError from None


def _strict_json_object(value: object) -> dict[str, object]:
    if type(value) is not str:
        raise TenderPlanReadOnlyStoreIntegrityError

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda _raw: (_ for _ in ()).throw(ValueError("number")),
        )
    except (TypeError, ValueError, RecursionError):
        raise TenderPlanReadOnlyStoreIntegrityError from None
    if type(parsed) is not dict or _canonical_json(parsed) != value:
        raise TenderPlanReadOnlyStoreIntegrityError
    return parsed


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8", "strict"))


def _hex64(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise TenderPlanReadOnlyStoreValidationError
    return value


def _safe_id(value: object) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise TenderPlanReadOnlyStoreValidationError
    return value


def _utc_z(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: object, *, integrity: bool = False) -> str:
    error = (
        TenderPlanReadOnlyStoreIntegrityError
        if integrity
        else TenderPlanReadOnlyStoreValidationError
    )
    if type(value) is not str or _UTC_Z.fullmatch(value) is None:
        raise error
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise error from None
    if parsed.tzinfo is None or _utc_z(parsed) != value:
        raise error
    return value


def _plain_resolved_path(path: str | Path, *, must_exist: bool = False) -> Path:
    if not isinstance(path, (str, Path)) or (
        isinstance(path, str) and not path.strip()
    ):
        raise TenderPlanReadOnlyStoreValidationError
    if str(path) == ":memory:":
        raise TenderPlanReadOnlyStoreValidationError
    candidate = Path(path)
    try:
        absolute = Path(os.path.abspath(candidate))
        resolved = candidate.resolve(strict=False)
        if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
            raise TenderPlanReadOnlyStoreValidationError
        if not resolved.parent.is_dir() or resolved.parent.is_symlink():
            raise TenderPlanReadOnlyStoreValidationError
        if resolved.exists():
            if resolved.is_symlink() or resolved.is_dir():
                raise TenderPlanReadOnlyStoreValidationError
        elif must_exist:
            raise TenderPlanReadOnlyStoreIntegrityError
    except TenderPlanReadOnlyStoreError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise TenderPlanReadOnlyStoreValidationError from None
    return resolved


def _path_sha256(path: Path) -> str:
    try:
        return _sha256_bytes(os.path.normcase(str(path)).encode("utf-8", "strict"))
    except UnicodeEncodeError:
        raise TenderPlanReadOnlyStoreValidationError from None


def _schema_statements() -> tuple[str, ...]:
    statements: list[str] = []
    buffer = ""
    for line in _SCHEMA_SQL.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise TenderPlanReadOnlyStoreIntegrityError
    return tuple(statements)


def _schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
    ).fetchall()
    return _sha256_json(
        [
            {
                "name": str(row[1]),
                "sql": " ".join(str(row[3] or "").split()),
                "table": str(row[2]),
                "type": str(row[0]),
            }
            for row in rows
        ]
    )


def _normalize_intent(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _INTENT_KEYS:
        raise TenderPlanReadOnlyStoreValidationError
    intent = dict(value)
    if (
        intent["protocol"] != TENDERPLAN_READ_ONLY_INTENT_VERSION
        or intent["live_release_eligible"] is not False
        or intent["automatic_schedule_eligible"] is not False
        or type(intent["request_count"]) is not int
        or intent["request_count"] != 1
        or type(intent["write_count"]) is not int
        or intent["write_count"] != 0
        or type(intent["contact_count"]) is not int
        or intent["contact_count"] != 0
        or type(intent["spend_minor"]) is not int
        or intent["spend_minor"] != 0
    ):
        raise TenderPlanReadOnlyStoreValidationError
    _safe_id(intent["run_id"])
    requested_text = _timestamp(intent["requested_at_utc"])
    expires_text = _timestamp(intent["expires_at_utc"])
    requested = datetime.fromisoformat(requested_text.replace("Z", "+00:00"))
    expires = datetime.fromisoformat(expires_text.replace("Z", "+00:00"))
    if (
        not requested
        < expires
        <= requested + timedelta(days=TENDERPLAN_READ_ONLY_RETENTION_DAYS)
    ):
        raise TenderPlanReadOnlyStoreValidationError
    for key in _INTENT_HASH_KEYS:
        _hex64(intent[key])
    maximum_bytes = intent["maximum_response_bytes"]
    maximum_records = intent["maximum_records"]
    if (
        type(maximum_bytes) is not int
        or not 1_024 <= maximum_bytes <= TENDERPLAN_READ_ONLY_MAXIMUM_RESPONSE_BYTES
        or type(maximum_records) is not int
        or not 1 <= maximum_records <= TENDERPLAN_READ_ONLY_MAXIMUM_CARDS
    ):
        raise TenderPlanReadOnlyStoreValidationError
    seal = _hex64(intent["intent_record_sha256"])
    unsigned = dict(intent)
    del unsigned["intent_record_sha256"]
    if seal != _sha256_json(unsigned):
        raise TenderPlanReadOnlyStoreValidationError
    return intent


def seal_tenderplan_read_only_intent(
    material: Mapping[str, object],
) -> dict[str, object]:
    """Seal exact safe intent material without granting live authority."""

    if type(material) is not dict or "intent_record_sha256" in material:
        raise TenderPlanReadOnlyStoreValidationError
    sealed = dict(material)
    sealed["intent_record_sha256"] = _sha256_json(sealed)
    return _normalize_intent(sealed)


def _card_materials(
    cards: object,
) -> tuple[tuple[EncryptedTenderPlanCardV1, dict[str, object]], ...]:
    if not isinstance(cards, Sequence) or isinstance(cards, (str, bytes)):
        raise TenderPlanReadOnlyStoreValidationError
    values = tuple(cards)
    if len(values) > TENDERPLAN_READ_ONLY_MAXIMUM_CARDS:
        raise TenderPlanReadOnlyStoreValidationError
    normalized: list[tuple[EncryptedTenderPlanCardV1, dict[str, object]]] = []
    seen: set[str] = set()
    for value in values:
        if type(value) is not EncryptedTenderPlanCardV1:
            raise TenderPlanReadOnlyStoreValidationError
        try:
            material = encrypted_card_material(value)
        except Exception:
            raise TenderPlanReadOnlyStoreValidationError from None
        if type(material) is not dict or material.get("envelope_sha256") != (
            value.envelope_sha256
        ):
            raise TenderPlanReadOnlyStoreValidationError
        if value.identity_sha256 in seen:
            raise TenderPlanReadOnlyStoreConflict
        seen.add(value.identity_sha256)
        normalized.append((value, material))
    return tuple(normalized)


def _cards_sha256(
    cards: Sequence[tuple[EncryptedTenderPlanCardV1, dict[str, object]]],
) -> str:
    return _sha256_json([material for _card, material in cards])


def _normalize_receipt(
    value: object,
    *,
    intent: Mapping[str, object],
    cards: Sequence[tuple[EncryptedTenderPlanCardV1, dict[str, object]]],
) -> dict[str, object]:
    if type(value) is not dict or set(value) != _RECEIPT_KEYS:
        raise TenderPlanReadOnlyStoreValidationError
    receipt = dict(value)
    if (
        receipt["receipt_version"] != TENDERPLAN_READ_ONLY_RECEIPT_VERSION
        or receipt["run_id"] != intent["run_id"]
        or receipt["intent_record_sha256"] != intent["intent_record_sha256"]
        or receipt["request_sha256"] != intent["request_sha256"]
        or receipt["cards_sha256"] != _cards_sha256(cards)
        or receipt["live_release_eligible"] is not False
        or receipt["automatic_schedule_eligible"] is not False
        or type(receipt["request_count"]) is not int
        or receipt["request_count"] != 1
        or type(receipt["write_count"]) is not int
        or receipt["write_count"] != 0
        or type(receipt["contact_count"]) is not int
        or receipt["contact_count"] != 0
        or type(receipt["spend_minor"]) is not int
        or receipt["spend_minor"] != 0
    ):
        raise TenderPlanReadOnlyStoreValidationError
    for key in (
        "intent_record_sha256",
        "projection_sha256",
        "request_sha256",
        "response_body_sha256",
        "cards_sha256",
    ):
        _hex64(receipt[key])
    _safe_id(receipt["run_id"])
    captured_text = _timestamp(receipt["captured_at_utc"])
    captured = datetime.fromisoformat(captured_text.replace("Z", "+00:00"))
    requested = datetime.fromisoformat(
        str(intent["requested_at_utc"]).replace("Z", "+00:00")
    )
    expires = datetime.fromisoformat(
        str(intent["expires_at_utc"]).replace("Z", "+00:00")
    )
    card_count = receipt["card_count"]
    returned_count = receipt["returned_count"]
    provider_count = receipt["provider_reported_count"]
    byte_count = receipt["response_byte_count"]
    if (
        type(card_count) is not int
        or card_count != len(cards)
        or type(returned_count) is not int
        or not 0 <= card_count <= returned_count
        or type(provider_count) is not int
        or not returned_count <= provider_count <= 1_000_000_000
        or type(byte_count) is not int
        or not 1 <= byte_count <= int(intent["maximum_response_bytes"])
        or card_count > int(intent["maximum_records"])
        or not requested <= captured <= expires
    ):
        raise TenderPlanReadOnlyStoreValidationError
    for card, _material in cards:
        if (
            card.run_id != intent["run_id"]
            or card.intent_record_sha256 != intent["intent_record_sha256"]
            or card.query_policy_sha256 != intent["query_policy_sha256"]
            or card.expires_at_utc != intent["expires_at_utc"]
        ):
            raise TenderPlanReadOnlyStoreValidationError
    seal = _hex64(receipt["receipt_record_sha256"])
    unsigned = dict(receipt)
    del unsigned["receipt_record_sha256"]
    if seal != _sha256_json(unsigned):
        raise TenderPlanReadOnlyStoreValidationError
    return receipt


def seal_tenderplan_read_only_receipt(
    material: Mapping[str, object],
    cards: Sequence[EncryptedTenderPlanCardV1],
) -> dict[str, object]:
    """Seal an exact zero-effect receipt for already encrypted cards."""

    if type(material) is not dict or "receipt_record_sha256" in material:
        raise TenderPlanReadOnlyStoreValidationError
    normalized_cards = _card_materials(cards)
    sealed = dict(material)
    sealed["receipt_record_sha256"] = _sha256_json(sealed)
    # Full run/intent validation is performed by commit_ready.  This helper
    # still proves that its card-set digest was supplied exactly.
    if sealed.get("cards_sha256") != _cards_sha256(normalized_cards):
        raise TenderPlanReadOnlyStoreValidationError
    return sealed


def _operation_material(
    *,
    run_id: str,
    intent_record_sha256: str,
    reserved_at_utc: str,
) -> dict[str, object]:
    return {
        "intent_record_sha256": intent_record_sha256,
        "reserved_at_utc": reserved_at_utc,
        "run_id": run_id,
    }


def _event_material(
    *,
    sequence: int,
    event_type: str,
    run_id: str,
    state: str,
    occurred_at_utc: str,
    payload_sha256: str,
    card_count: int,
    previous_event_sha256: str,
) -> dict[str, object]:
    return {
        "card_count": card_count,
        "event_type": event_type,
        "occurred_at_utc": occurred_at_utc,
        "payload_sha256": payload_sha256,
        "previous_event_sha256": previous_event_sha256,
        "run_id": run_id,
        "sequence": sequence,
        "state": state,
    }


def _terminal_payload_sha256(run_id: str, state: str) -> str:
    return _sha256_json(
        {
            "automatic_schedule_eligible": False,
            "contact_count": 0,
            "live_release_eligible": False,
            "run_id": run_id,
            "spend_minor": 0,
            "state": state,
            "write_count": 0,
        }
    )


def _dispatch_claim_payload_sha256(intent: Mapping[str, object]) -> str:
    return _sha256_json(
        {
            "automatic_schedule_eligible": False,
            "contact_count": 0,
            "intent_record_sha256": intent["intent_record_sha256"],
            "live_release_eligible": False,
            "request_sha256": intent["request_sha256"],
            "run_id": intent["run_id"],
            "spend_minor": 0,
            "state": TenderPlanReadOnlyRunState.DISPATCH_CLAIMED.value,
            "write_count": 0,
        }
    )


def _item_id(identity_sha256: str) -> str:
    _hex64(identity_sha256)
    return f"tpri-{identity_sha256}"


def _ciphertext_sha256(ciphertext_b64: str) -> str:
    try:
        raw = base64.b64decode(ciphertext_b64.encode("ascii", "strict"), validate=True)
    except Exception:
        raise TenderPlanReadOnlyStoreValidationError from None
    return _sha256_bytes(raw)


def _card_record_material(
    *,
    item_id: str,
    run_id: str,
    ordinal: int,
    ciphertext_sha256: str,
    envelope_sha256: str,
    encrypted_card_sha256: str,
    created_at_utc: str,
) -> dict[str, object]:
    return {
        "ciphertext_sha256": ciphertext_sha256,
        "created_at_utc": created_at_utc,
        "encrypted_card_sha256": encrypted_card_sha256,
        "envelope_sha256": envelope_sha256,
        "item_id": item_id,
        "ordinal": ordinal,
        "run_id": run_id,
    }


def _decision_material(
    *,
    item_id: str,
    sequence: int,
    decision: str,
    reason_code: str,
    decided_at_utc: str,
    previous_decision_sha256: str,
) -> dict[str, object]:
    return {
        "decided_at_utc": decided_at_utc,
        "decision": decision,
        "item_id": item_id,
        "previous_decision_sha256": previous_decision_sha256,
        "reason_code": reason_code,
        "sequence": sequence,
    }


class TenderPlanReadOnlyStore:
    """Path-bound encrypted-card ledger with no external side effects."""

    live_release_eligible = False
    automatic_schedule_eligible = False
    authorizes_live = False
    write_count = 0
    provider_write_count = 0
    contact_count = 0
    spend_minor = 0
    retention_days = TENDERPLAN_READ_ONLY_RETENTION_DAYS

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = _plain_resolved_path(path)
        if clock is not None and not callable(clock):
            raise TenderPlanReadOnlyStoreValidationError
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._path_sha256 = _path_sha256(self.path)
        self._store_identity_sha256 = _sha256_json(
            {
                "contract_id": TENDERPLAN_READ_ONLY_STORE_CONTRACT_ID,
                "path_sha256": self._path_sha256,
                "schema_version": TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION,
            }
        )
        self._bootstrap_or_validate()

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyStore(path=<bound>, content=<encrypted-only>, "
            "authorizes_live=False, automatic_schedule_eligible=False, "
            "live_release_eligible=False)"
        )

    @property
    def store_identity_sha256(self) -> str:
        return self._store_identity_sha256

    def _now(self) -> str:
        try:
            value = self._clock()
        except Exception:
            raise TenderPlanReadOnlyStoreValidationError from None
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise TenderPlanReadOnlyStoreValidationError
        try:
            return _utc_z(value)
        except (OverflowError, ValueError):
            raise TenderPlanReadOnlyStoreValidationError from None

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        try:
            if read_only:
                connection = sqlite3.connect(
                    self.path.as_uri() + "?mode=ro",
                    timeout=30,
                    isolation_level=None,
                    uri=True,
                )
            else:
                connection = sqlite3.connect(
                    str(self.path), timeout=30, isolation_level=None
                )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA trusted_schema=OFF")
            if read_only:
                connection.execute("PRAGMA query_only=ON")
            else:
                connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.DatabaseError:
            raise TenderPlanReadOnlyStoreIntegrityError from None

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = self._connect(read_only=not write)
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._verify_locked(connection)
            yield connection
            self._verify_locked(connection)
            connection.commit()
        except TenderPlanReadOnlyStoreError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError:
            connection.rollback()
            raise TenderPlanReadOnlyStoreIntegrityError from None
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _expected_metadata(self) -> dict[str, str]:
        return {
            "automatic_schedule_eligible": "0",
            "authorizes_live": "0",
            "contact_count": "0",
            "contract_id": TENDERPLAN_READ_ONLY_STORE_CONTRACT_ID,
            "encrypted_cards_only": "1",
            "live_release_eligible": "0",
            "maximum_cards_per_run": str(TENDERPLAN_READ_ONLY_MAXIMUM_CARDS),
            "path_sha256": self._path_sha256,
            "provider_write_count": "0",
            "retention_days": str(TENDERPLAN_READ_ONLY_RETENTION_DAYS),
            "schema_fingerprint_sha256": (
                TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256
            ),
            "schema_version": str(TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION),
            "spend_minor": "0",
            "store_identity_sha256": self._store_identity_sha256,
            "write_count": "0",
        }

    def _bootstrap_or_validate(self) -> None:
        try:
            existed = self.path.exists()
            original_size = self.path.stat().st_size if existed else 0
        except OSError:
            raise TenderPlanReadOnlyStoreIntegrityError from None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT name FROM sqlite_master
                   WHERE name NOT LIKE 'sqlite_%' LIMIT 1"""
            ).fetchone()
            if existing is None:
                if existed and original_size > 0:
                    raise TenderPlanReadOnlyStoreIntegrityError
                for statement in _schema_statements():
                    connection.execute(statement)
                if _schema_fingerprint(connection) != (
                    TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                connection.executemany(
                    "INSERT INTO tenderplan_read_only_meta(key,value) VALUES(?,?)",
                    sorted(self._expected_metadata().items()),
                )
                connection.execute(
                    f"PRAGMA application_id={TENDERPLAN_READ_ONLY_STORE_APPLICATION_ID}"
                )
                connection.execute(
                    f"PRAGMA user_version={TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION}"
                )
            self._verify_locked(connection)
            connection.commit()
        except TenderPlanReadOnlyStoreError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError:
            connection.rollback()
            raise TenderPlanReadOnlyStoreIntegrityError from None
        finally:
            connection.close()
        _plain_resolved_path(self.path, must_exist=True)

    def _verify_locked(self, connection: sqlite3.Connection) -> None:
        try:
            quick = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if (
                quick.casefold() != "ok"
                or application_id != TENDERPLAN_READ_ONLY_STORE_APPLICATION_ID
                or user_version != TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION
                or _schema_fingerprint(connection)
                != TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256
            ):
                raise TenderPlanReadOnlyStoreIntegrityError
            metadata = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key,value FROM tenderplan_read_only_meta ORDER BY key"
                ).fetchall()
            }
            if metadata != self._expected_metadata():
                raise TenderPlanReadOnlyStoreIntegrityError

            operations = connection.execute(
                "SELECT * FROM tenderplan_read_only_operations ORDER BY run_id"
            ).fetchall()
            operation_by_run: dict[str, tuple[sqlite3.Row, dict[str, object]]] = {}
            for row in operations:
                run_id = _safe_id(row["run_id"])
                intent = _normalize_intent(_strict_json_object(row["intent_json"]))
                reserved_at = _timestamp(row["reserved_at_utc"], integrity=True)
                if (
                    intent["run_id"] != run_id
                    or row["intent_record_sha256"] != intent["intent_record_sha256"]
                    or row["intent_json"] != _canonical_json(intent)
                    or row["operation_sha256"]
                    != _sha256_json(
                        _operation_material(
                            run_id=run_id,
                            intent_record_sha256=str(intent["intent_record_sha256"]),
                            reserved_at_utc=reserved_at,
                        )
                    )
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                operation_by_run[run_id] = (row, intent)
            if len(operation_by_run) != len(operations):
                raise TenderPlanReadOnlyStoreIntegrityError

            events = connection.execute(
                "SELECT * FROM tenderplan_read_only_events ORDER BY sequence"
            ).fetchall()
            events_by_run: dict[str, list[sqlite3.Row]] = {
                run_id: [] for run_id in operation_by_run
            }
            previous = _GENESIS_SHA256
            for expected_sequence, row in enumerate(events, start=1):
                sequence = row["sequence"]
                card_count = row["card_count"]
                if (
                    type(sequence) is not int
                    or sequence != expected_sequence
                    or type(card_count) is not int
                    or not 0 <= card_count <= TENDERPLAN_READ_ONLY_MAXIMUM_CARDS
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                run_id = str(row["run_id"])
                if run_id not in operation_by_run:
                    raise TenderPlanReadOnlyStoreIntegrityError
                occurred = _timestamp(row["occurred_at_utc"], integrity=True)
                payload_sha256 = _hex64(row["payload_sha256"])
                if row["payload_json"] is not None:
                    _strict_json_object(row["payload_json"])
                material = _event_material(
                    sequence=sequence,
                    event_type=str(row["event_type"]),
                    run_id=run_id,
                    state=str(row["state"]),
                    occurred_at_utc=occurred,
                    payload_sha256=payload_sha256,
                    card_count=card_count,
                    previous_event_sha256=previous,
                )
                digest = _sha256_json(material)
                if (
                    row["previous_event_sha256"] != previous
                    or row["event_sha256"] != digest
                    or row["event_id"] != f"tpre-{digest[:32]}"
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                previous = digest
                events_by_run[run_id].append(row)

            cards = connection.execute(
                "SELECT * FROM tenderplan_read_only_cards ORDER BY run_id,ordinal"
            ).fetchall()
            cards_by_run: dict[
                str,
                list[tuple[sqlite3.Row, EncryptedTenderPlanCardV1, dict[str, object]]],
            ] = {run_id: [] for run_id in operation_by_run}
            card_by_item: dict[str, sqlite3.Row] = {}
            for row in cards:
                run_id = str(row["run_id"])
                if run_id not in operation_by_run:
                    raise TenderPlanReadOnlyStoreIntegrityError
                envelope_mapping = _strict_json_object(row["envelope_json"])
                envelope = EncryptedTenderPlanCardV1.from_mapping(envelope_mapping)
                material = encrypted_card_material(envelope)
                encrypted_sha256 = _sha256_json(material)
                ciphertext_sha256 = _ciphertext_sha256(envelope.ciphertext_b64)
                item_id = _item_id(envelope.identity_sha256)
                ordinal = row["ordinal"]
                created_at = _timestamp(row["created_at_utc"], integrity=True)
                _operation_row, intent = operation_by_run[run_id]
                if (
                    type(ordinal) is not int
                    or row["item_id"] != item_id
                    or row["ciphertext"] != envelope.ciphertext_b64
                    or row["ciphertext_sha256"] != ciphertext_sha256
                    or row["envelope_json"] != _canonical_json(material)
                    or row["envelope_sha256"] != envelope.envelope_sha256
                    or row["encrypted_card_sha256"] != encrypted_sha256
                    or envelope.run_id != run_id
                    or envelope.intent_record_sha256 != intent["intent_record_sha256"]
                    or envelope.query_policy_sha256 != intent["query_policy_sha256"]
                    or envelope.expires_at_utc != intent["expires_at_utc"]
                    or row["card_record_sha256"]
                    != _sha256_json(
                        _card_record_material(
                            item_id=item_id,
                            run_id=run_id,
                            ordinal=ordinal,
                            ciphertext_sha256=ciphertext_sha256,
                            envelope_sha256=envelope.envelope_sha256,
                            encrypted_card_sha256=encrypted_sha256,
                            created_at_utc=created_at,
                        )
                    )
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                cards_by_run[run_id].append((row, envelope, material))
                if item_id in card_by_item:
                    raise TenderPlanReadOnlyStoreIntegrityError
                card_by_item[item_id] = row

            for run_id, (_operation, intent) in operation_by_run.items():
                history = events_by_run.get(run_id, [])
                run_cards = cards_by_run.get(run_id, [])
                if not 1 <= len(history) <= 3:
                    raise TenderPlanReadOnlyStoreIntegrityError
                first = history[0]
                if (
                    first["event_type"] != "INTENT_COMMITTED"
                    or first["state"] != TenderPlanReadOnlyRunState.INTENT.value
                    or first["occurred_at_utc"]
                    != operation_by_run[run_id][0]["reserved_at_utc"]
                    or first["payload_sha256"] != intent["intent_record_sha256"]
                    or first["payload_json"] is not None
                    or first["card_count"] != 0
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                if len(history) == 1:
                    if run_cards:
                        raise TenderPlanReadOnlyStoreIntegrityError
                    continue
                second = history[1]
                if datetime.fromisoformat(
                    str(second["occurred_at_utc"]).replace("Z", "+00:00")
                ) < datetime.fromisoformat(
                    str(first["occurred_at_utc"]).replace("Z", "+00:00")
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                if second["state"] == TenderPlanReadOnlyRunState.DISPATCH_CLAIMED.value:
                    if (
                        second["event_type"] != "DISPATCH_CLAIMED_COMMITTED"
                        or second["payload_sha256"]
                        != _dispatch_claim_payload_sha256(intent)
                        or second["payload_json"] is not None
                        or second["card_count"] != 0
                    ):
                        raise TenderPlanReadOnlyStoreIntegrityError
                    if len(history) == 2:
                        if run_cards:
                            raise TenderPlanReadOnlyStoreIntegrityError
                        continue
                    terminal = history[2]
                    if datetime.fromisoformat(
                        str(terminal["occurred_at_utc"]).replace("Z", "+00:00")
                    ) < datetime.fromisoformat(
                        str(second["occurred_at_utc"]).replace("Z", "+00:00")
                    ):
                        raise TenderPlanReadOnlyStoreIntegrityError
                elif len(history) == 2:
                    terminal = second
                else:
                    raise TenderPlanReadOnlyStoreIntegrityError
                state = str(terminal["state"])
                if state in {
                    TenderPlanReadOnlyRunState.FAILED_CLOSED.value,
                    TenderPlanReadOnlyRunState.UNCERTAIN.value,
                }:
                    if (
                        second["state"]
                        == TenderPlanReadOnlyRunState.DISPATCH_CLAIMED.value
                        and state != TenderPlanReadOnlyRunState.UNCERTAIN.value
                    ):
                        raise TenderPlanReadOnlyStoreIntegrityError
                    if (
                        terminal["event_type"] != f"{state}_COMMITTED"
                        or terminal["payload_sha256"]
                        != _terminal_payload_sha256(run_id, state)
                        or terminal["payload_json"] is not None
                        or terminal["card_count"] != 0
                        or run_cards
                    ):
                        raise TenderPlanReadOnlyStoreIntegrityError
                    continue
                if state != TenderPlanReadOnlyRunState.READY_FOR_REVIEW.value:
                    raise TenderPlanReadOnlyStoreIntegrityError
                if (
                    second["state"] != TenderPlanReadOnlyRunState.DISPATCH_CLAIMED.value
                    or terminal["event_type"] != "READY_FOR_REVIEW_COMMITTED"
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                if [int(row["ordinal"]) for row, _card, _material in run_cards] != list(
                    range(1, len(run_cards) + 1)
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError
                receipt = _normalize_receipt(
                    _strict_json_object(terminal["payload_json"]),
                    intent=intent,
                    cards=tuple((card, material) for _row, card, material in run_cards),
                )
                if (
                    terminal["payload_json"] != _canonical_json(receipt)
                    or terminal["payload_sha256"] != receipt["receipt_record_sha256"]
                    or terminal["card_count"] != len(run_cards)
                    or any(
                        row["created_at_utc"] != terminal["occurred_at_utc"]
                        for row, _card, _material in run_cards
                    )
                ):
                    raise TenderPlanReadOnlyStoreIntegrityError

            decisions = connection.execute(
                "SELECT * FROM tenderplan_read_only_decisions ORDER BY item_id,sequence"
            ).fetchall()
            decisions_by_item: dict[str, list[sqlite3.Row]] = {
                item_id: [] for item_id in card_by_item
            }
            for row in decisions:
                item_id = str(row["item_id"])
                if item_id not in card_by_item:
                    raise TenderPlanReadOnlyStoreIntegrityError
                decisions_by_item[item_id].append(row)
            for item_id, history in decisions_by_item.items():
                previous_decision = _GENESIS_SHA256
                card_created = str(card_by_item[item_id]["created_at_utc"])
                for expected_sequence, row in enumerate(history, start=1):
                    sequence = row["sequence"]
                    decision = str(row["decision"])
                    reason = str(row["reason_code"])
                    decided_at = _timestamp(row["decided_at_utc"], integrity=True)
                    if (
                        type(sequence) is not int
                        or sequence != expected_sequence
                        or decision
                        not in {item.value for item in TenderPlanReadOnlyDecision}
                        or _REASON_CODE.fullmatch(reason) is None
                        or datetime.fromisoformat(decided_at.replace("Z", "+00:00"))
                        < datetime.fromisoformat(card_created.replace("Z", "+00:00"))
                    ):
                        raise TenderPlanReadOnlyStoreIntegrityError
                    material = _decision_material(
                        item_id=item_id,
                        sequence=sequence,
                        decision=decision,
                        reason_code=reason,
                        decided_at_utc=decided_at,
                        previous_decision_sha256=previous_decision,
                    )
                    digest = _sha256_json(material)
                    if (
                        row["previous_decision_sha256"] != previous_decision
                        or row["decision_sha256"] != digest
                        or row["decision_id"] != f"tprd-{digest[:32]}"
                    ):
                        raise TenderPlanReadOnlyStoreIntegrityError
                    previous_decision = digest
        except TenderPlanReadOnlyStoreIntegrityError:
            raise
        except Exception:
            raise TenderPlanReadOnlyStoreIntegrityError from None

    def _before_intent_commit(self) -> None:
        """Fault-injection seam; receives no caller material."""

    def _before_terminal_commit(self) -> None:
        """Fault-injection seam; receives no caller material."""

    def _before_ready_commit(self) -> None:
        """Fault-injection seam; receives no caller material."""

    def _before_decision_commit(self) -> None:
        """Fault-injection seam; receives no caller material."""

    @staticmethod
    def _latest_event(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """SELECT * FROM tenderplan_read_only_events
               WHERE run_id=? ORDER BY sequence DESC LIMIT 1""",
            (run_id,),
        ).fetchone()

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        state: str,
        occurred_at_utc: str,
        payload_sha256: str,
        payload_json: str | None,
        card_count: int,
    ) -> tuple[str, str]:
        head = connection.execute(
            """SELECT sequence,event_sha256 FROM tenderplan_read_only_events
               ORDER BY sequence DESC LIMIT 1"""
        ).fetchone()
        sequence = int(head["sequence"]) + 1 if head else 1
        previous = str(head["event_sha256"]) if head else _GENESIS_SHA256
        material = _event_material(
            sequence=sequence,
            event_type=event_type,
            run_id=run_id,
            state=state,
            occurred_at_utc=occurred_at_utc,
            payload_sha256=payload_sha256,
            card_count=card_count,
            previous_event_sha256=previous,
        )
        digest = _sha256_json(material)
        event_id = f"tpre-{digest[:32]}"
        connection.execute(
            """INSERT INTO tenderplan_read_only_events(
                   sequence,event_id,run_id,event_type,state,occurred_at_utc,
                   payload_sha256,payload_json,card_count,
                   previous_event_sha256,event_sha256)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sequence,
                event_id,
                run_id,
                event_type,
                state,
                occurred_at_utc,
                payload_sha256,
                payload_json,
                card_count,
                previous,
                digest,
            ),
        )
        return event_id, digest

    @staticmethod
    def _state(row: sqlite3.Row) -> TenderPlanReadOnlyRunState:
        try:
            return TenderPlanReadOnlyRunState(str(row["state"]))
        except ValueError:
            raise TenderPlanReadOnlyStoreIntegrityError from None

    def _operation_receipt(
        self,
        connection: sqlite3.Connection,
        operation: sqlite3.Row,
        *,
        created: bool,
    ) -> TenderPlanReadOnlyOperationReceipt:
        event = self._latest_event(connection, str(operation["run_id"]))
        if event is None:
            raise TenderPlanReadOnlyStoreIntegrityError
        card_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_cards WHERE run_id=?",
                (str(operation["run_id"]),),
            ).fetchone()[0]
        )
        return TenderPlanReadOnlyOperationReceipt(
            created=created,
            run_id=str(operation["run_id"]),
            state=self._state(event),
            intent_record_sha256=str(operation["intent_record_sha256"]),
            event_sha256=str(event["event_sha256"]),
            card_count=card_count,
        )

    def reserve_intent(
        self,
        intent_mapping: Mapping[str, object],
    ) -> TenderPlanReadOnlyOperationReceipt:
        intent = _normalize_intent(intent_mapping)
        now = self._now()
        if not (
            datetime.fromisoformat(
                str(intent["requested_at_utc"]).replace("Z", "+00:00")
            )
            <= datetime.fromisoformat(now.replace("Z", "+00:00"))
            < datetime.fromisoformat(
                str(intent["expires_at_utc"]).replace("Z", "+00:00")
            )
        ):
            raise TenderPlanReadOnlyStoreValidationError
        intent_json = _canonical_json(intent)
        run_id = str(intent["run_id"])
        with self._transaction(write=True) as connection:
            unresolved = connection.execute(
                """SELECT e.state FROM tenderplan_read_only_events e
                   WHERE e.sequence=(
                       SELECT MAX(x.sequence) FROM tenderplan_read_only_events x
                       WHERE x.run_id=e.run_id
                   ) AND e.state IN (
                       'INTENT','DISPATCH_CLAIMED','UNCERTAIN'
                   ) LIMIT 1"""
            ).fetchone()
            existing = connection.execute(
                "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if unresolved:
                raise TenderPlanReadOnlyStoreReconciliationRequired
            if existing:
                if str(existing["intent_json"]) != intent_json:
                    raise TenderPlanReadOnlyStoreConflict
                return self._operation_receipt(connection, existing, created=False)
            reserved_at = now
            operation_sha256 = _sha256_json(
                _operation_material(
                    run_id=run_id,
                    intent_record_sha256=str(intent["intent_record_sha256"]),
                    reserved_at_utc=reserved_at,
                )
            )
            connection.execute(
                """INSERT INTO tenderplan_read_only_operations(
                       run_id,intent_record_sha256,intent_json,
                       reserved_at_utc,operation_sha256)
                   VALUES(?,?,?,?,?)""",
                (
                    run_id,
                    intent["intent_record_sha256"],
                    intent_json,
                    reserved_at,
                    operation_sha256,
                ),
            )
            self._append_event(
                connection,
                run_id=run_id,
                event_type="INTENT_COMMITTED",
                state=TenderPlanReadOnlyRunState.INTENT.value,
                occurred_at_utc=reserved_at,
                payload_sha256=str(intent["intent_record_sha256"]),
                payload_json=None,
                card_count=0,
            )
            self._before_intent_commit()
            operation = connection.execute(
                "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if operation is None:
                raise TenderPlanReadOnlyStoreIntegrityError
            return self._operation_receipt(connection, operation, created=True)

    def get_uncertain_binding(
        self,
        run_id: str,
    ) -> TenderPlanReadOnlyUncertainBinding:
        """Read a terminal UNCERTAIN binding without mutating main state."""

        run = _safe_id(run_id)
        with self._transaction(write=False) as connection:
            operation = connection.execute(
                "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?",
                (run,),
            ).fetchone()
            if operation is None:
                raise TenderPlanReadOnlyStoreConflict
            event = self._latest_event(connection, run)
            if (
                event is None
                or self._state(event) is not TenderPlanReadOnlyRunState.UNCERTAIN
            ):
                raise TenderPlanReadOnlyStoreConflict
            intent = _normalize_intent(_strict_json_object(operation["intent_json"]))
            if str(intent["run_id"]) != run or str(
                intent["intent_record_sha256"]
            ) != str(operation["intent_record_sha256"]):
                raise TenderPlanReadOnlyStoreIntegrityError
            return TenderPlanReadOnlyUncertainBinding(
                run_id=run,
                store_identity_sha256=self._store_identity_sha256,
                main_uncertain_event_sha256=str(event["event_sha256"]),
                intent_record_sha256=str(intent["intent_record_sha256"]),
                request_sha256=str(intent["request_sha256"]),
            )

    def record_terminal(
        self,
        run_id: str,
        state: str,
    ) -> TenderPlanReadOnlyOperationReceipt:
        run = _safe_id(run_id)
        if type(state) is not str or state not in {
            TenderPlanReadOnlyRunState.FAILED_CLOSED.value,
            TenderPlanReadOnlyRunState.UNCERTAIN.value,
        }:
            raise TenderPlanReadOnlyStoreValidationError
        now = self._now()
        with self._transaction(write=True) as connection:
            operation = connection.execute(
                "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?",
                (run,),
            ).fetchone()
            if operation is None:
                raise TenderPlanReadOnlyStoreConflict
            latest = self._latest_event(connection, run)
            if latest is None:
                raise TenderPlanReadOnlyStoreIntegrityError
            current = self._state(latest)
            if current.value == state:
                return self._operation_receipt(connection, operation, created=False)
            if current not in {
                TenderPlanReadOnlyRunState.INTENT,
                TenderPlanReadOnlyRunState.DISPATCH_CLAIMED,
            }:
                raise TenderPlanReadOnlyStoreConflict
            if (
                current is TenderPlanReadOnlyRunState.DISPATCH_CLAIMED
                and state != TenderPlanReadOnlyRunState.UNCERTAIN.value
            ):
                raise TenderPlanReadOnlyStoreConflict
            self._append_event(
                connection,
                run_id=run,
                event_type=f"{state}_COMMITTED",
                state=state,
                occurred_at_utc=now,
                payload_sha256=_terminal_payload_sha256(run, state),
                payload_json=None,
                card_count=0,
            )
            self._before_terminal_commit()
            return self._operation_receipt(connection, operation, created=True)

    def _ready_receipt(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> TenderPlanReadOnlyReadyReceipt:
        event = self._latest_event(connection, run_id)
        if event is None or self._state(event) is not (
            TenderPlanReadOnlyRunState.READY_FOR_REVIEW
        ):
            raise TenderPlanReadOnlyStoreIntegrityError
        receipt = _strict_json_object(event["payload_json"])
        cards = connection.execute(
            """SELECT item_id FROM tenderplan_read_only_cards
               WHERE run_id=? ORDER BY ordinal""",
            (run_id,),
        ).fetchall()
        return TenderPlanReadOnlyReadyReceipt(
            run_id=run_id,
            receipt_record_sha256=str(receipt["receipt_record_sha256"]),
            event_sha256=str(event["event_sha256"]),
            card_count=len(cards),
            item_ids=tuple(str(row["item_id"]) for row in cards),
        )

    @staticmethod
    def _stored_card_materials(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> tuple[dict[str, object], ...]:
        rows = connection.execute(
            """SELECT envelope_json FROM tenderplan_read_only_cards
               WHERE run_id=? ORDER BY ordinal""",
            (run_id,),
        ).fetchall()
        return tuple(_strict_json_object(row["envelope_json"]) for row in rows)

    def commit_ready(
        self,
        run_id: str,
        cards: Sequence[EncryptedTenderPlanCardV1],
        receipt_mapping: Mapping[str, object],
    ) -> TenderPlanReadOnlyReadyReceipt:
        run = _safe_id(run_id)
        normalized_cards = _card_materials(cards)
        now = self._now()
        with self._transaction(write=True) as connection:
            operation = connection.execute(
                "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?",
                (run,),
            ).fetchone()
            if operation is None:
                raise TenderPlanReadOnlyStoreConflict
            intent = _strict_json_object(operation["intent_json"])
            normalized_intent = _normalize_intent(intent)
            receipt = _normalize_receipt(
                receipt_mapping,
                intent=normalized_intent,
                cards=normalized_cards,
            )
            receipt_json = _canonical_json(receipt)
            latest = self._latest_event(connection, run)
            if latest is None:
                raise TenderPlanReadOnlyStoreIntegrityError
            current = self._state(latest)
            if current is TenderPlanReadOnlyRunState.READY_FOR_REVIEW:
                if str(
                    latest["payload_json"]
                ) != receipt_json or self._stored_card_materials(
                    connection, run
                ) != tuple(material for _card, material in normalized_cards):
                    raise TenderPlanReadOnlyStoreConflict
                return self._ready_receipt(connection, run)
            if current is not TenderPlanReadOnlyRunState.DISPATCH_CLAIMED:
                raise TenderPlanReadOnlyStoreConflict
            expires = datetime.fromisoformat(
                str(normalized_intent["expires_at_utc"]).replace("Z", "+00:00")
            )
            if datetime.fromisoformat(now.replace("Z", "+00:00")) > expires:
                raise TenderPlanReadOnlyStoreConflict
            for ordinal, (card, material) in enumerate(normalized_cards, start=1):
                item_id = _item_id(card.identity_sha256)
                envelope_json = _canonical_json(material)
                encrypted_sha256 = _sha256_json(material)
                ciphertext_sha256 = _ciphertext_sha256(card.ciphertext_b64)
                card_record_sha256 = _sha256_json(
                    _card_record_material(
                        item_id=item_id,
                        run_id=run,
                        ordinal=ordinal,
                        ciphertext_sha256=ciphertext_sha256,
                        envelope_sha256=card.envelope_sha256,
                        encrypted_card_sha256=encrypted_sha256,
                        created_at_utc=now,
                    )
                )
                try:
                    connection.execute(
                        """INSERT INTO tenderplan_read_only_cards(
                               item_id,run_id,ordinal,ciphertext,
                               ciphertext_sha256,envelope_json,envelope_sha256,
                               encrypted_card_sha256,created_at_utc,
                               card_record_sha256)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (
                            item_id,
                            run,
                            ordinal,
                            card.ciphertext_b64,
                            ciphertext_sha256,
                            envelope_json,
                            card.envelope_sha256,
                            encrypted_sha256,
                            now,
                            card_record_sha256,
                        ),
                    )
                except sqlite3.IntegrityError:
                    raise TenderPlanReadOnlyStoreConflict from None
            self._append_event(
                connection,
                run_id=run,
                event_type="READY_FOR_REVIEW_COMMITTED",
                state=TenderPlanReadOnlyRunState.READY_FOR_REVIEW.value,
                occurred_at_utc=now,
                payload_sha256=str(receipt["receipt_record_sha256"]),
                payload_json=receipt_json,
                card_count=len(normalized_cards),
            )
            self._before_ready_commit()
            return self._ready_receipt(connection, run)

    def list_items(self, *, limit: int = 50) -> tuple[TenderPlanReadOnlyItem, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise TenderPlanReadOnlyStoreValidationError
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                """SELECT c.*,
                          d.decision_id AS latest_decision_id,
                          d.decision AS latest_decision,
                          d.reason_code AS latest_reason_code
                   FROM tenderplan_read_only_cards c
                   LEFT JOIN tenderplan_read_only_decisions d
                     ON d.item_id=c.item_id
                    AND d.sequence=(
                        SELECT MAX(x.sequence)
                        FROM tenderplan_read_only_decisions x
                        WHERE x.item_id=c.item_id
                    )
                   ORDER BY c.created_at_utc,c.item_id LIMIT ?""",
                (limit,),
            ).fetchall()
            return tuple(
                TenderPlanReadOnlyItem(
                    item_id=str(row["item_id"]),
                    run_id=str(row["run_id"]),
                    state=(
                        str(row["latest_decision"])
                        if row["latest_decision"] is not None
                        else TenderPlanReadOnlyRunState.READY_FOR_REVIEW.value
                    ),
                    encrypted_card_sha256=str(row["encrypted_card_sha256"]),
                    latest_decision_id=(
                        ""
                        if row["latest_decision_id"] is None
                        else str(row["latest_decision_id"])
                    ),
                    latest_reason_code=(
                        ""
                        if row["latest_reason_code"] is None
                        else str(row["latest_reason_code"])
                    ),
                    created_at_utc=str(row["created_at_utc"]),
                )
                for row in rows
            )

    def get_encrypted_card(self, item_id: str) -> EncryptedTenderPlanCardV1:
        item = _safe_id(item_id)
        with self._transaction(write=False) as connection:
            row = connection.execute(
                """SELECT envelope_json FROM tenderplan_read_only_cards
                   WHERE item_id=?""",
                (item,),
            ).fetchone()
            if row is None:
                raise TenderPlanReadOnlyStoreConflict
            try:
                return EncryptedTenderPlanCardV1.from_mapping(
                    _strict_json_object(row["envelope_json"])
                )
            except Exception:
                raise TenderPlanReadOnlyStoreIntegrityError from None

    def append_decision(
        self,
        item_id: str,
        decision: TenderPlanReadOnlyDecision,
        reason_code: str,
    ) -> TenderPlanReadOnlyDecisionReceipt:
        item = _safe_id(item_id)
        if type(decision) is not TenderPlanReadOnlyDecision:
            raise TenderPlanReadOnlyStoreValidationError
        if type(reason_code) is not str or _REASON_CODE.fullmatch(reason_code) is None:
            raise TenderPlanReadOnlyStoreValidationError
        decided_at = self._now()
        with self._transaction(write=True) as connection:
            card = connection.execute(
                "SELECT item_id FROM tenderplan_read_only_cards WHERE item_id=?",
                (item,),
            ).fetchone()
            if card is None:
                raise TenderPlanReadOnlyStoreConflict
            previous = connection.execute(
                """SELECT sequence,decision_sha256
                   FROM tenderplan_read_only_decisions
                   WHERE item_id=? ORDER BY sequence DESC LIMIT 1""",
                (item,),
            ).fetchone()
            sequence = int(previous["sequence"]) + 1 if previous else 1
            previous_sha256 = (
                str(previous["decision_sha256"]) if previous else _GENESIS_SHA256
            )
            material = _decision_material(
                item_id=item,
                sequence=sequence,
                decision=decision.value,
                reason_code=reason_code,
                decided_at_utc=decided_at,
                previous_decision_sha256=previous_sha256,
            )
            digest = _sha256_json(material)
            decision_id = f"tprd-{digest[:32]}"
            connection.execute(
                """INSERT INTO tenderplan_read_only_decisions(
                       decision_id,item_id,sequence,decision,reason_code,
                       decided_at_utc,previous_decision_sha256,decision_sha256)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    decision_id,
                    item,
                    sequence,
                    decision.value,
                    reason_code,
                    decided_at,
                    previous_sha256,
                    digest,
                ),
            )
            self._before_decision_commit()
            return TenderPlanReadOnlyDecisionReceipt(
                decision_id=decision_id,
                item_id=item,
                decision=decision,
                reason_code=reason_code,
                sequence=sequence,
                decision_sha256=digest,
            )

    def decide(
        self,
        item_id: str,
        decision: TenderPlanReadOnlyDecision,
        reason_code: str,
    ) -> TenderPlanReadOnlyDecisionReceipt:
        """Compatibility spelling for the explicit local append operation."""

        return self.append_decision(item_id, decision, reason_code)


def _existing_store(
    path: str | Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> TenderPlanReadOnlyStore:
    resolved = _plain_resolved_path(path, must_exist=True)
    if clock is not None and not callable(clock):
        raise TenderPlanReadOnlyStoreValidationError
    store = object.__new__(TenderPlanReadOnlyStore)
    store.path = resolved
    store._clock = clock or (lambda: datetime.now(timezone.utc))  # noqa: SLF001
    store._path_sha256 = _path_sha256(resolved)  # noqa: SLF001
    store._store_identity_sha256 = _sha256_json(  # noqa: SLF001
        {
            "contract_id": TENDERPLAN_READ_ONLY_STORE_CONTRACT_ID,
            "path_sha256": store._path_sha256,  # noqa: SLF001
            "schema_version": TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION,
        }
    )
    return store


def verify_worker_intent(
    db_path: str | Path,
    *,
    run_id: str,
    intent_record_sha256: str,
    auth_reference_id_sha256: str,
    credential_target_sha256: str,
    nonce_sha256: str,
    query_policy_sha256: str,
    request_sha256: str,
    maximum_response_bytes: int,
    maximum_records: int,
    expires_at_utc: str,
    clock: Callable[[], datetime] | None = None,
) -> VerifiedTenderPlanWorkerIntent:
    """Atomically claim one exact INTENT before PAT or network access.

    The name is retained as the worker-facing protocol entry point.  This is
    intentionally a write transaction: exactly one concurrent worker can
    append ``DISPATCH_CLAIMED``.  Every later claimant fails reconciliation-
    only before credential resolution.
    """

    run = _safe_id(run_id)
    for value in (
        intent_record_sha256,
        auth_reference_id_sha256,
        credential_target_sha256,
        nonce_sha256,
        query_policy_sha256,
        request_sha256,
    ):
        _hex64(value)
    expires = _timestamp(expires_at_utc)
    if (
        type(maximum_response_bytes) is not int
        or not 1_024
        <= maximum_response_bytes
        <= TENDERPLAN_READ_ONLY_MAXIMUM_RESPONSE_BYTES
        or type(maximum_records) is not int
        or not 1 <= maximum_records <= TENDERPLAN_READ_ONLY_MAXIMUM_CARDS
    ):
        raise TenderPlanReadOnlyStoreValidationError
    store = _existing_store(db_path, clock=clock)
    with store._transaction(write=True) as connection:  # noqa: SLF001
        operation = connection.execute(
            "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?",
            (run,),
        ).fetchone()
        if operation is None:
            raise TenderPlanReadOnlyStoreReconciliationRequired
        intent = _normalize_intent(_strict_json_object(operation["intent_json"]))
        event = store._latest_event(connection, run)  # noqa: SLF001
        event_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_events WHERE run_id=?",
                (run,),
            ).fetchone()[0]
        )
        expected = {
            "auth_reference_id_sha256": auth_reference_id_sha256,
            "credential_target_sha256": credential_target_sha256,
            "expires_at_utc": expires,
            "intent_record_sha256": intent_record_sha256,
            "maximum_records": maximum_records,
            "maximum_response_bytes": maximum_response_bytes,
            "nonce_sha256": nonce_sha256,
            "query_policy_sha256": query_policy_sha256,
            "request_sha256": request_sha256,
            "run_id": run,
        }
        claimed_at = store._now()  # noqa: SLF001
        if (
            event is None
            or event_count != 1
            or event["state"] != TenderPlanReadOnlyRunState.INTENT.value
            or any(intent.get(key) != value for key, value in expected.items())
            or datetime.fromisoformat(claimed_at.replace("Z", "+00:00"))
            >= datetime.fromisoformat(expires.replace("Z", "+00:00"))
        ):
            raise TenderPlanReadOnlyStoreReconciliationRequired
        store._append_event(  # noqa: SLF001
            connection,
            run_id=run,
            event_type="DISPATCH_CLAIMED_COMMITTED",
            state=TenderPlanReadOnlyRunState.DISPATCH_CLAIMED.value,
            occurred_at_utc=claimed_at,
            payload_sha256=_dispatch_claim_payload_sha256(intent),
            payload_json=None,
            card_count=0,
        )
        return VerifiedTenderPlanWorkerIntent(
            run_id=run,
            intent_record_sha256=intent_record_sha256,
            request_sha256=request_sha256,
            maximum_response_bytes=maximum_response_bytes,
            maximum_records=maximum_records,
        )


def validate_tenderplan_read_only_store(path: str | Path) -> dict[str, object]:
    """Validate the complete store without writing or repairing it."""

    store = _existing_store(path)
    with store._transaction(write=False) as connection:  # noqa: SLF001
        return {
            "automatic_schedule_eligible": False,
            "card_count": int(
                connection.execute(
                    "SELECT COUNT(*) FROM tenderplan_read_only_cards"
                ).fetchone()[0]
            ),
            "contact_count": 0,
            "decision_count": int(
                connection.execute(
                    "SELECT COUNT(*) FROM tenderplan_read_only_decisions"
                ).fetchone()[0]
            ),
            "event_count": int(
                connection.execute(
                    "SELECT COUNT(*) FROM tenderplan_read_only_events"
                ).fetchone()[0]
            ),
            "live_release_eligible": False,
            "operation_count": int(
                connection.execute(
                    "SELECT COUNT(*) FROM tenderplan_read_only_operations"
                ).fetchone()[0]
            ),
            "retention_days": TENDERPLAN_READ_ONLY_RETENTION_DAYS,
            "schema_fingerprint_sha256": (
                TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256
            ),
            "spend_minor": 0,
            "store_identity_sha256": store.store_identity_sha256,
            "write_count": 0,
        }


__all__ = [
    "TENDERPLAN_READ_ONLY_INTENT_VERSION",
    "TENDERPLAN_READ_ONLY_MAXIMUM_CARDS",
    "TENDERPLAN_READ_ONLY_MAXIMUM_RESPONSE_BYTES",
    "TENDERPLAN_READ_ONLY_QUEUE_PATH",
    "TENDERPLAN_READ_ONLY_RECEIPT_VERSION",
    "TENDERPLAN_READ_ONLY_RETENTION_DAYS",
    "TENDERPLAN_READ_ONLY_STORE_APPLICATION_ID",
    "TENDERPLAN_READ_ONLY_STORE_CONTRACT_ID",
    "TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256",
    "TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION",
    "TenderPlanReadOnlyDecision",
    "TenderPlanReadOnlyDecisionReceipt",
    "TenderPlanReadOnlyItem",
    "TenderPlanReadOnlyOperationReceipt",
    "TenderPlanReadOnlyReadyReceipt",
    "TenderPlanReadOnlyRunState",
    "TenderPlanReadOnlyStore",
    "TenderPlanReadOnlyStoreConflict",
    "TenderPlanReadOnlyStoreError",
    "TenderPlanReadOnlyStoreIntegrityError",
    "TenderPlanReadOnlyStoreReconciliationRequired",
    "TenderPlanReadOnlyStoreValidationError",
    "TenderPlanReadOnlyUncertainBinding",
    "VerifiedTenderPlanWorkerIntent",
    "seal_tenderplan_read_only_intent",
    "seal_tenderplan_read_only_receipt",
    "validate_tenderplan_read_only_store",
    "verify_worker_intent",
]
