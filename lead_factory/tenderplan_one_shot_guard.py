"""Durable, default-off one-shot guard for a future TenderPlan canary.

The guard owns no HTTP client, credential resolver, query text, provider
response, live permit, or STOP authority.  It only makes one digest-bound
dispatch intent durable *before* a caller-supplied provider entry can run.

An existing ``DISPATCH_INTENT`` or ``UNCERTAIN`` record is reconciliation-only:
neither restart nor duplicate invocation may blindly call the provider again.
The externally supplied STOP assertion is deliberately a veto callback whose
only valid return is ``None``; it cannot be interpreted as positive live
authority.  A separate signed admission boundary remains required.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Final


TENDERPLAN_ONE_SHOT_OPERATION_ID: Final = "lead_factory.source.tenderplan.shadow_canary"
TENDERPLAN_ONE_SHOT_SCHEMA_VERSION: Final = 1
TENDERPLAN_ONE_SHOT_APPLICATION_ID: Final = 0x54504731  # ``TPG1``
TENDERPLAN_ONE_SHOT_CONTRACT_ID: Final = "tenderplan-one-shot-guard-v1"

_PROVIDER_CODE: Final = "TENDERPLAN"
_HTTP_METHOD: Final = "POST"
_HTTP_PATH: Final = "/api/search/v2/list"
_SEARCH_SET: Final = "actual"
_SEARCH_PAGE: Final = 0
# These are the durable digest-only projection limits, not the raw HTTP
# response limits.  They exactly match the signed one-shot authority slice.
_MAX_RESPONSE_BYTES: Final = 16_384
_MAX_RESPONSE_RECORDS: Final = 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_UTC_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z$")


class TenderPlanOneShotError(RuntimeError):
    """Base error with a message safe for an operational log."""


class TenderPlanOneShotValidationError(TenderPlanOneShotError):
    """A digest-only binding, callback, clock, or evidence is malformed."""


class TenderPlanOneShotIntegrityError(TenderPlanOneShotError):
    """The SQLite identity, schema, metadata, or evidence chain differs."""


class TenderPlanOneShotConflict(TenderPlanOneShotError):
    """The one available slot is already bound to different material."""


class TenderPlanOneShotReconciliationRequired(TenderPlanOneShotError):
    """A provider call must not be retried; external reconciliation is required."""


class TenderPlanOneShotStopped(TenderPlanOneShotError):
    """The external last-moment STOP assertion vetoed provider entry."""


class TenderPlanOneShotUncertain(TenderPlanOneShotError):
    """Provider entry may have occurred and local outcome is not safely known."""


class TenderPlanOneShotState(str, Enum):
    DISPATCH_INTENT = "DISPATCH_INTENT"
    SUCCESS = "SUCCESS"
    UNCERTAIN = "UNCERTAIN"


class TenderPlanOneShotUncertainReason(str, Enum):
    STOP_CHECK_REJECTED = "STOP_CHECK_REJECTED"
    PROVIDER_OUTCOME_UNKNOWN = "PROVIDER_OUTCOME_UNKNOWN"
    PROVIDER_EVIDENCE_INVALID = "PROVIDER_EVIDENCE_INVALID"
    LOCAL_COMMIT_UNKNOWN = "LOCAL_COMMIT_UNKNOWN"
    OPERATOR_RECONCILIATION = "OPERATOR_RECONCILIATION"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanOneShotBinding:
    """Exact digest-only identity produced by separate authority boundaries.

    ``external_admission_sha256`` is retained only as a binding.  This module
    does not verify, mint, refresh, or otherwise turn it into live authority.
    """

    operation_id: str
    command_sha256: str
    authorization_sha256: str
    authorization_receipt_sha256: str
    external_admission_sha256: str
    stop_policy_sha256: str
    source_read_epoch_sha256: str
    passport_sha256: str
    stream_sha256: str
    query_policy_sha256: str
    auth_reference_sha256: str

    def __repr__(self) -> str:
        return "TenderPlanOneShotBinding(material=<digest-only>)"

    @property
    def binding_sha256(self) -> str:
        return tenderplan_one_shot_binding_sha256(self)


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanOneShotSuccessEvidence:
    """Bounded digest-only evidence returned after one provider entry."""

    response_body_sha256: str
    projection_sha256: str
    upstream_receipt_sha256: str
    record_count: int
    byte_count: int
    http_status: int = 200
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "TenderPlanOneShotSuccessEvidence(content=<digest-only>, "
            "effects=zero, live_release_eligible=False)"
        )

    @property
    def evidence_sha256(self) -> str:
        normalized = _normalize_success_evidence(self)
        return _sha256_json(_success_evidence_material(normalized))


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanOneShotRecord:
    """Digest-safe view of the singleton durable record."""

    created: bool
    state: TenderPlanOneShotState
    binding_sha256: str
    store_identity_sha256: str
    intent_event_sha256: str
    reserved_at_utc: str
    terminal_at_utc: str | None
    provider_entered: bool
    success_evidence_sha256: str | None
    uncertain_reason: TenderPlanOneShotUncertainReason | None
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            f"TenderPlanOneShotRecord(created={self.created!r}, "
            f"state={self.state.value!r}, binding=<digest-only>, "
            "effects=zero, live_release_eligible=False)"
        )

    @property
    def reconcile_only(self) -> bool:
        return self.state in {
            TenderPlanOneShotState.DISPATCH_INTENT,
            TenderPlanOneShotState.UNCERTAIN,
        }


_SCHEMA_SQL = """
CREATE TABLE tenderplan_one_shot_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE tenderplan_one_shot_intent(
    slot INTEGER PRIMARY KEY CHECK(slot=1),
    store_identity_sha256 TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL UNIQUE,
    binding_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('DISPATCH_INTENT','SUCCESS','UNCERTAIN')),
    reserved_at_utc TEXT NOT NULL,
    terminal_at_utc TEXT,
    provider_entered INTEGER NOT NULL CHECK(provider_entered IN (0,1)),
    success_evidence_sha256 TEXT,
    success_evidence_json TEXT,
    uncertain_reason TEXT,
    record_sha256 TEXT NOT NULL,
    CHECK(
        (state='DISPATCH_INTENT' AND terminal_at_utc IS NULL
         AND provider_entered=0 AND success_evidence_sha256 IS NULL
         AND success_evidence_json IS NULL AND uncertain_reason IS NULL)
        OR
        (state='SUCCESS' AND terminal_at_utc IS NOT NULL
         AND provider_entered=1 AND success_evidence_sha256 IS NOT NULL
         AND success_evidence_json IS NOT NULL AND uncertain_reason IS NULL)
        OR
        (state='UNCERTAIN' AND terminal_at_utc IS NOT NULL
         AND success_evidence_sha256 IS NULL
         AND success_evidence_json IS NULL AND uncertain_reason IS NOT NULL)
    )
);

CREATE TABLE tenderplan_one_shot_events(
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 2),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL CHECK(
        event_type IN ('DISPATCH_INTENT_COMMITTED','SUCCESS_COMMITTED','UNCERTAIN_COMMITTED')
    ),
    binding_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('DISPATCH_INTENT','SUCCESS','UNCERTAIN')),
    occurred_at_utc TEXT NOT NULL,
    provider_entered INTEGER NOT NULL CHECK(provider_entered IN (0,1)),
    success_evidence_sha256 TEXT,
    uncertain_reason TEXT,
    previous_event_sha256 TEXT NOT NULL,
    event_sha256 TEXT NOT NULL UNIQUE
);

CREATE TRIGGER trg_tenderplan_one_shot_meta_no_update
BEFORE UPDATE ON tenderplan_one_shot_meta BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot metadata is immutable');
END;

CREATE TRIGGER trg_tenderplan_one_shot_meta_no_delete
BEFORE DELETE ON tenderplan_one_shot_meta BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot metadata is immutable');
END;

CREATE TRIGGER trg_tenderplan_one_shot_intent_no_delete
BEFORE DELETE ON tenderplan_one_shot_intent BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot intent is immutable');
END;

CREATE TRIGGER trg_tenderplan_one_shot_intent_binding_immutable
BEFORE UPDATE OF slot,store_identity_sha256,binding_sha256,binding_json,reserved_at_utc
ON tenderplan_one_shot_intent BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot binding is immutable');
END;

CREATE TRIGGER trg_tenderplan_one_shot_intent_terminal
BEFORE UPDATE OF state ON tenderplan_one_shot_intent
WHEN OLD.state<>'DISPATCH_INTENT' OR NEW.state NOT IN ('SUCCESS','UNCERTAIN') BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot state is terminal');
END;

CREATE TRIGGER trg_tenderplan_one_shot_events_no_update
BEFORE UPDATE ON tenderplan_one_shot_events BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot events are immutable');
END;

CREATE TRIGGER trg_tenderplan_one_shot_events_no_delete
BEFORE DELETE ON tenderplan_one_shot_events BEGIN
    SELECT RAISE(ABORT,'tenderplan one-shot events are immutable');
END;
"""

# Updated only through an explicit new-store schema review.  There is no
# migration path in this offline foundation.
TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256: Final = (
    "2e0844fb8a7a90c569daa180aaa3575ec61372b64afcea7b6fe691dec8e3f892"
)
_GENESIS_SHA256: Final = "0" * 64


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
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot digest material is invalid"
        ) from None


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8", "strict"))


def _hex64(value: object, field: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise TenderPlanOneShotValidationError(f"{field} must be a lowercase SHA-256")
    return value


def _normalize_binding(value: object) -> TenderPlanOneShotBinding:
    if type(value) is not TenderPlanOneShotBinding:
        raise TenderPlanOneShotValidationError("TenderPlan one-shot binding is invalid")
    if (
        type(value.operation_id) is not str
        or _SAFE_ID.fullmatch(value.operation_id) is None
        or value.operation_id != TENDERPLAN_ONE_SHOT_OPERATION_ID
    ):
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot operation identity is invalid"
        )
    for field in (
        "command_sha256",
        "authorization_sha256",
        "authorization_receipt_sha256",
        "external_admission_sha256",
        "stop_policy_sha256",
        "source_read_epoch_sha256",
        "passport_sha256",
        "stream_sha256",
        "query_policy_sha256",
        "auth_reference_sha256",
    ):
        _hex64(getattr(value, field), field)
    return value


def _binding_material(value: TenderPlanOneShotBinding) -> dict[str, object]:
    return {
        "auth_reference_sha256": value.auth_reference_sha256,
        "authorization_receipt_sha256": value.authorization_receipt_sha256,
        "authorization_sha256": value.authorization_sha256,
        "command_sha256": value.command_sha256,
        "contact_count": 0,
        "external_admission_sha256": value.external_admission_sha256,
        "http_method": _HTTP_METHOD,
        "http_path": _HTTP_PATH,
        "live_release_eligible": False,
        "max_provider_entries": 1,
        "max_response_bytes": _MAX_RESPONSE_BYTES,
        "max_response_records": _MAX_RESPONSE_RECORDS,
        "operation_id": value.operation_id,
        "page": _SEARCH_PAGE,
        "passport_sha256": value.passport_sha256,
        "provider_code": _PROVIDER_CODE,
        "query_policy_sha256": value.query_policy_sha256,
        "search_set": _SEARCH_SET,
        "source_read_epoch_sha256": value.source_read_epoch_sha256,
        "spend_minor": 0,
        "stop_policy_sha256": value.stop_policy_sha256,
        "stream_sha256": value.stream_sha256,
        "write_count": 0,
    }


def tenderplan_one_shot_binding_sha256(value: TenderPlanOneShotBinding) -> str:
    """Return the exact immutable digest without granting any authority."""

    normalized = _normalize_binding(value)
    return _sha256_json(_binding_material(normalized))


def _normalize_success_evidence(
    value: object,
) -> TenderPlanOneShotSuccessEvidence:
    if type(value) is not TenderPlanOneShotSuccessEvidence:
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot success evidence is invalid"
        )
    for field in (
        "response_body_sha256",
        "projection_sha256",
        "upstream_receipt_sha256",
    ):
        _hex64(getattr(value, field), field)
    if (
        type(value.record_count) is not int
        or not 0 <= value.record_count <= _MAX_RESPONSE_RECORDS
        or type(value.byte_count) is not int
        or not 1 <= value.byte_count <= _MAX_RESPONSE_BYTES
        or type(value.http_status) is not int
        or value.http_status != 200
        or type(value.write_count) is not int
        or value.write_count != 0
        or type(value.contact_count) is not int
        or value.contact_count != 0
        or type(value.spend_minor) is not int
        or value.spend_minor != 0
        or type(value.live_release_eligible) is not bool
        or value.live_release_eligible is not False
    ):
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot success evidence exceeds its offline boundary"
        )
    return value


def _success_evidence_material(
    value: TenderPlanOneShotSuccessEvidence,
) -> dict[str, object]:
    return {
        "byte_count": value.byte_count,
        "contact_count": 0,
        "http_status": value.http_status,
        "live_release_eligible": False,
        "projection_sha256": value.projection_sha256,
        "record_count": value.record_count,
        "response_body_sha256": value.response_body_sha256,
        "spend_minor": 0,
        "upstream_receipt_sha256": value.upstream_receipt_sha256,
        "write_count": 0,
    }


def _utc_z(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    timespec = "seconds" if normalized.microsecond == 0 else "microseconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _parse_utc_z(value: object, field: str) -> datetime:
    if type(value) is not str or _UTC_Z.fullmatch(value) is None:
        raise TenderPlanOneShotIntegrityError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise TenderPlanOneShotIntegrityError(f"{field} is invalid") from None
    if parsed.tzinfo is None or _utc_z(parsed) != value:
        raise TenderPlanOneShotIntegrityError(f"{field} is invalid")
    return parsed.astimezone(timezone.utc)


def _normalized_path(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)) or (
        isinstance(path, str) and not path.strip()
    ):
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot store path is invalid"
        )
    try:
        resolved = Path(path).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot store path is invalid"
        ) from None
    if not resolved.parent.is_dir() or resolved.is_dir():
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot store parent must already exist"
        )
    return resolved


def _path_sha256(path: Path) -> str:
    canonical = os.path.normcase(str(path))
    try:
        encoded = canonical.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise TenderPlanOneShotValidationError(
            "TenderPlan one-shot store path is invalid"
        ) from None
    return _sha256_bytes(encoded)


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
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot canonical schema is incomplete"
        )
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


def _record_material(
    *,
    store_identity_sha256: str,
    binding_sha256: str,
    state: str,
    reserved_at_utc: str,
    terminal_at_utc: str | None,
    provider_entered: bool,
    success_evidence_sha256: str | None,
    uncertain_reason: str | None,
) -> dict[str, object]:
    return {
        "binding_sha256": binding_sha256,
        "contact_count": 0,
        "live_release_eligible": False,
        "provider_entered": provider_entered,
        "reserved_at_utc": reserved_at_utc,
        "spend_minor": 0,
        "state": state,
        "store_identity_sha256": store_identity_sha256,
        "success_evidence_sha256": success_evidence_sha256,
        "terminal_at_utc": terminal_at_utc,
        "uncertain_reason": uncertain_reason,
        "write_count": 0,
    }


def _event_material(
    *,
    sequence: int,
    event_type: str,
    binding_sha256: str,
    state: str,
    occurred_at_utc: str,
    provider_entered: bool,
    success_evidence_sha256: str | None,
    uncertain_reason: str | None,
    previous_event_sha256: str,
) -> dict[str, object]:
    return {
        "binding_sha256": binding_sha256,
        "event_type": event_type,
        "occurred_at_utc": occurred_at_utc,
        "previous_event_sha256": previous_event_sha256,
        "provider_entered": provider_entered,
        "sequence": sequence,
        "state": state,
        "success_evidence_sha256": success_evidence_sha256,
        "uncertain_reason": uncertain_reason,
    }


class TenderPlanOneShotGuard:
    """SQLite singleton guard with no credential, transport, or live authority.

    The standalone guard deliberately cannot dispatch.  Its digest fields and
    caller callbacks are bindings only, not authority or STOP evidence.  A
    future sealed composition must replace the hard fence with exact signed,
    externally monotonic admission and an atomic durable STOP lease.
    """

    live_release_eligible = False
    authorizes_live = False
    maximum_provider_entries = 1
    write_count = 0
    contact_count = 0
    spend_minor = 0

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = _normalized_path(path)
        if clock is not None and not callable(clock):
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot clock is invalid"
            )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._path_sha256 = _path_sha256(self.path)
        self._store_identity_sha256 = _sha256_json(
            {
                "contract_id": TENDERPLAN_ONE_SHOT_CONTRACT_ID,
                "path_sha256": self._path_sha256,
                "schema_version": TENDERPLAN_ONE_SHOT_SCHEMA_VERSION,
            }
        )
        self._bootstrap_or_validate()

    def __repr__(self) -> str:
        return (
            "TenderPlanOneShotGuard(path=<bound>, transport=none, "
            "authorizes_live=False, live_release_eligible=False)"
        )

    @property
    def store_identity_sha256(self) -> str:
        return self._store_identity_sha256

    def _now(self) -> str:
        try:
            value = self._clock()
        except Exception:
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot clock is unavailable"
            ) from None
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot clock must be timezone-aware"
            )
        try:
            return _utc_z(value)
        except (OverflowError, ValueError):
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot clock is invalid"
            ) from None

    def _assert_live_admission(self, binding: TenderPlanOneShotBinding) -> None:
        del binding
        raise TenderPlanOneShotStopped(
            "TenderPlan one-shot live admission is not implemented"
        )

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                str(self.path), timeout=30, isolation_level=None
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            return connection
        except sqlite3.DatabaseError as error:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot store is unavailable"
            ) from error

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._verify_locked(connection)
            yield connection
            connection.commit()
        except TenderPlanOneShotError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as error:
            connection.rollback()
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot store operation failed closed"
            ) from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _expected_metadata(self) -> dict[str, str]:
        return {
            "auth_reference_material_allowed": "0",
            "authorizes_live": "0",
            "contact_count": "0",
            "contract_id": TENDERPLAN_ONE_SHOT_CONTRACT_ID,
            "live_release_eligible": "0",
            "max_provider_entries": "1",
            "path_sha256": self._path_sha256,
            "query_text_allowed": "0",
            "raw_response_allowed": "0",
            "schema_fingerprint_sha256": (
                TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256
            ),
            "schema_version": str(TENDERPLAN_ONE_SHOT_SCHEMA_VERSION),
            "spend_minor": "0",
            "store_identity_sha256": self._store_identity_sha256,
            "token_material_allowed": "0",
            "write_count": "0",
        }

    def _bootstrap_or_validate(self) -> None:
        try:
            existed = self.path.exists()
            original_size = self.path.stat().st_size if existed else 0
        except OSError:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot store identity is unavailable"
            ) from None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT name FROM sqlite_master
                   WHERE name NOT LIKE 'sqlite_%' LIMIT 1"""
            ).fetchone()
            if existing is None:
                if existed and original_size > 0:
                    raise TenderPlanOneShotIntegrityError(
                        "TenderPlan one-shot existing store is not canonical"
                    )
                for statement in _schema_statements():
                    connection.execute(statement)
                fingerprint = _schema_fingerprint(connection)
                if fingerprint != TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256:
                    raise TenderPlanOneShotIntegrityError(
                        "TenderPlan one-shot schema fingerprint constant differs"
                    )
                connection.executemany(
                    "INSERT INTO tenderplan_one_shot_meta(key,value) VALUES(?,?)",
                    sorted(self._expected_metadata().items()),
                )
                connection.execute(
                    f"PRAGMA application_id={TENDERPLAN_ONE_SHOT_APPLICATION_ID}"
                )
                connection.execute(
                    f"PRAGMA user_version={TENDERPLAN_ONE_SHOT_SCHEMA_VERSION}"
                )
            self._verify_locked(connection)
            connection.commit()
        except TenderPlanOneShotError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as error:
            connection.rollback()
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot store bootstrap failed closed"
            ) from error
        finally:
            connection.close()

    def _verify_locked(self, connection: sqlite3.Connection) -> None:
        try:
            quick = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if quick.casefold() != "ok":
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot SQLite quick_check failed"
                )
            if _schema_fingerprint(connection) != (
                TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256
            ):
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot schema inventory differs"
                )
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if (
                application_id != TENDERPLAN_ONE_SHOT_APPLICATION_ID
                or user_version != TENDERPLAN_ONE_SHOT_SCHEMA_VERSION
            ):
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot SQLite identity differs"
                )
            rows = connection.execute(
                "SELECT key,value FROM tenderplan_one_shot_meta ORDER BY key"
            ).fetchall()
            actual = {str(row["key"]): str(row["value"]) for row in rows}
            if actual != self._expected_metadata():
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot immutable metadata differs"
                )
            self._verify_record_locked(connection)
        except TenderPlanOneShotError:
            raise
        except (sqlite3.DatabaseError, KeyError, TypeError, ValueError) as error:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot durable evidence is invalid"
            ) from error

    def _verify_record_locked(self, connection: sqlite3.Connection) -> None:
        intents = connection.execute(
            "SELECT * FROM tenderplan_one_shot_intent ORDER BY slot"
        ).fetchall()
        events = connection.execute(
            "SELECT * FROM tenderplan_one_shot_events ORDER BY sequence"
        ).fetchall()
        if not intents:
            if events:
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot event exists without an intent"
                )
            return
        if len(intents) != 1 or len(events) not in {1, 2}:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot singleton cardinality differs"
            )
        row = intents[0]
        if int(row["slot"]) != 1:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot slot identity differs"
            )
        try:
            binding_material = json.loads(str(row["binding_json"]))
        except (TypeError, ValueError):
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot binding material is invalid"
            ) from None
        if (
            type(binding_material) is not dict
            or _canonical_json(binding_material) != str(row["binding_json"])
            or _sha256_json(binding_material) != str(row["binding_sha256"])
        ):
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot binding digest differs"
            )
        expected_keys = set(_binding_material(_binding_from_material(binding_material)))
        if set(binding_material) != expected_keys:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot binding fields differ"
            )
        if str(row["store_identity_sha256"]) != self._store_identity_sha256:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot store binding differs"
            )
        state = str(row["state"])
        reserved_at = str(row["reserved_at_utc"])
        reserved_time = _parse_utc_z(reserved_at, "reserved_at_utc")
        terminal_at = (
            None if row["terminal_at_utc"] is None else str(row["terminal_at_utc"])
        )
        terminal_time = (
            None
            if terminal_at is None
            else _parse_utc_z(terminal_at, "terminal_at_utc")
        )
        if terminal_time is not None and terminal_time < reserved_time:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot terminal time moved backwards"
            )
        provider_entered = bool(int(row["provider_entered"]))
        evidence_sha = (
            None
            if row["success_evidence_sha256"] is None
            else str(row["success_evidence_sha256"])
        )
        reason = (
            None if row["uncertain_reason"] is None else str(row["uncertain_reason"])
        )
        record_material = _record_material(
            store_identity_sha256=self._store_identity_sha256,
            binding_sha256=str(row["binding_sha256"]),
            state=state,
            reserved_at_utc=reserved_at,
            terminal_at_utc=terminal_at,
            provider_entered=provider_entered,
            success_evidence_sha256=evidence_sha,
            uncertain_reason=reason,
        )
        if _sha256_json(record_material) != str(row["record_sha256"]):
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot record digest differs"
            )
        if state == TenderPlanOneShotState.SUCCESS.value:
            if row["success_evidence_json"] is None or evidence_sha is None:
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot success evidence is absent"
                )
            try:
                evidence_material = json.loads(str(row["success_evidence_json"]))
            except (TypeError, ValueError):
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot success evidence is invalid"
                ) from None
            evidence = _success_evidence_from_material(evidence_material)
            if (
                _canonical_json(evidence_material) != str(row["success_evidence_json"])
                or _sha256_json(_success_evidence_material(evidence)) != evidence_sha
            ):
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot success evidence digest differs"
                )
        previous = _GENESIS_SHA256
        for index, event in enumerate(events, start=1):
            if int(event["sequence"]) != index:
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot event sequence differs"
                )
            event_material = _event_material(
                sequence=index,
                event_type=str(event["event_type"]),
                binding_sha256=str(event["binding_sha256"]),
                state=str(event["state"]),
                occurred_at_utc=str(event["occurred_at_utc"]),
                provider_entered=bool(int(event["provider_entered"])),
                success_evidence_sha256=(
                    None
                    if event["success_evidence_sha256"] is None
                    else str(event["success_evidence_sha256"])
                ),
                uncertain_reason=(
                    None
                    if event["uncertain_reason"] is None
                    else str(event["uncertain_reason"])
                ),
                previous_event_sha256=str(event["previous_event_sha256"]),
            )
            digest = _sha256_json(event_material)
            if (
                str(event["previous_event_sha256"]) != previous
                or str(event["event_sha256"]) != digest
                or str(event["event_id"]) != f"tpg-event-{digest[:32]}"
                or str(event["binding_sha256"]) != str(row["binding_sha256"])
            ):
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot event chain differs"
                )
            _parse_utc_z(str(event["occurred_at_utc"]), "event occurred_at_utc")
            previous = digest
        first = events[0]
        if (
            str(first["event_type"]) != "DISPATCH_INTENT_COMMITTED"
            or str(first["state"]) != TenderPlanOneShotState.DISPATCH_INTENT.value
            or str(first["occurred_at_utc"]) != reserved_at
            or int(first["provider_entered"]) != 0
            or first["success_evidence_sha256"] is not None
            or first["uncertain_reason"] is not None
        ):
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot intent event differs"
            )
        if state == TenderPlanOneShotState.DISPATCH_INTENT.value:
            if len(events) != 1:
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot pending history differs"
                )
        else:
            if len(events) != 2 or terminal_at is None:
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot terminal history differs"
                )
            last = events[-1]
            expected_type = (
                "SUCCESS_COMMITTED"
                if state == TenderPlanOneShotState.SUCCESS.value
                else "UNCERTAIN_COMMITTED"
            )
            if (
                str(last["event_type"]) != expected_type
                or str(last["state"]) != state
                or str(last["occurred_at_utc"]) != terminal_at
                or bool(int(last["provider_entered"])) != provider_entered
                or last["success_evidence_sha256"] != row["success_evidence_sha256"]
                or last["uncertain_reason"] != row["uncertain_reason"]
            ):
                raise TenderPlanOneShotIntegrityError(
                    "TenderPlan one-shot terminal event differs"
                )

    def reserve(self, binding: TenderPlanOneShotBinding) -> TenderPlanOneShotRecord:
        """Commit the singleton dispatch intent without entering a provider."""

        normalized = _normalize_binding(binding)
        material = _binding_material(normalized)
        binding_json = _canonical_json(material)
        binding_sha = _sha256_json(material)
        reserved_at = self._now()
        created = False
        with self._transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT * FROM tenderplan_one_shot_intent WHERE slot=1"
            ).fetchone()
            if existing is not None:
                if str(existing["binding_sha256"]) != binding_sha:
                    raise TenderPlanOneShotConflict(
                        "TenderPlan one-shot slot is already bound"
                    )
                return self._row_to_record(connection, existing, created=False)
            record_sha = _sha256_json(
                _record_material(
                    store_identity_sha256=self._store_identity_sha256,
                    binding_sha256=binding_sha,
                    state=TenderPlanOneShotState.DISPATCH_INTENT.value,
                    reserved_at_utc=reserved_at,
                    terminal_at_utc=None,
                    provider_entered=False,
                    success_evidence_sha256=None,
                    uncertain_reason=None,
                )
            )
            connection.execute(
                """INSERT INTO tenderplan_one_shot_intent(
                       slot,store_identity_sha256,binding_sha256,binding_json,state,
                       reserved_at_utc,terminal_at_utc,provider_entered,
                       success_evidence_sha256,success_evidence_json,
                       uncertain_reason,record_sha256)
                   VALUES(1,?,?,?,'DISPATCH_INTENT',?,NULL,0,NULL,NULL,NULL,?)""",
                (
                    self._store_identity_sha256,
                    binding_sha,
                    binding_json,
                    reserved_at,
                    record_sha,
                ),
            )
            self._insert_event_locked(
                connection,
                sequence=1,
                event_type="DISPATCH_INTENT_COMMITTED",
                binding_sha256=binding_sha,
                state=TenderPlanOneShotState.DISPATCH_INTENT.value,
                occurred_at_utc=reserved_at,
                provider_entered=False,
                success_evidence_sha256=None,
                uncertain_reason=None,
                previous_event_sha256=_GENESIS_SHA256,
            )
            created = True
        return self._inspect(normalized, created=created)

    def inspect(self, binding: TenderPlanOneShotBinding) -> TenderPlanOneShotRecord:
        """Read and verify the exact singleton without any external action."""

        return self._inspect(binding, created=False)

    def _inspect(
        self,
        binding: TenderPlanOneShotBinding,
        *,
        created: bool,
    ) -> TenderPlanOneShotRecord:
        normalized = _normalize_binding(binding)
        binding_sha = tenderplan_one_shot_binding_sha256(normalized)
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM tenderplan_one_shot_intent WHERE slot=1"
            ).fetchone()
            if row is None:
                raise TenderPlanOneShotConflict(
                    "TenderPlan one-shot intent does not exist"
                )
            if str(row["binding_sha256"]) != binding_sha:
                raise TenderPlanOneShotConflict(
                    "TenderPlan one-shot slot is bound differently"
                )
            return self._row_to_record(connection, row, created=created)

    def dispatch(
        self,
        binding: TenderPlanOneShotBinding,
        *,
        stop_check: Callable[[TenderPlanOneShotRecord], None],
        provider_entry: Callable[
            [TenderPlanOneShotRecord], TenderPlanOneShotSuccessEvidence
        ],
    ) -> TenderPlanOneShotRecord:
        """Run at most one caller-supplied provider entry after durable intent.

        The caller must already have established separate signed live
        admission.  ``stop_check`` is invoked once, after the intent commit and
        immediately before provider entry.  Its sole valid return is ``None``;
        it can veto but cannot confer authority.
        """

        if not callable(stop_check) or not callable(provider_entry):
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot dispatch callbacks are invalid"
            )
        normalized = _normalize_binding(binding)
        # A public digest or a caller-supplied STOP callback is not authority.
        # Keep the standalone state machine unreachable from provider entry
        # until a separately reviewed sealed composition exists.
        self._assert_live_admission(normalized)
        reserved = self.reserve(normalized)
        if not reserved.created:
            if reserved.state is TenderPlanOneShotState.SUCCESS:
                return reserved
            raise TenderPlanOneShotReconciliationRequired(
                "TenderPlan one-shot state is reconciliation-only"
            )
        try:
            stop_result = stop_check(reserved)
            if stop_result is not None:
                raise TenderPlanOneShotValidationError(
                    "TenderPlan one-shot STOP assertion is invalid"
                )
        except BaseException:
            self._best_effort_uncertain(
                normalized,
                TenderPlanOneShotUncertainReason.STOP_CHECK_REJECTED,
                provider_entered=False,
            )
            raise TenderPlanOneShotStopped(
                "TenderPlan one-shot provider entry was stopped"
            ) from None
        try:
            evidence = provider_entry(reserved)
            normalized_evidence = _normalize_success_evidence(evidence)
        except TenderPlanOneShotValidationError:
            self._best_effort_uncertain(
                normalized,
                TenderPlanOneShotUncertainReason.PROVIDER_EVIDENCE_INVALID,
                provider_entered=True,
            )
            raise TenderPlanOneShotUncertain(
                "TenderPlan one-shot outcome requires reconciliation"
            ) from None
        except BaseException:
            self._best_effort_uncertain(
                normalized,
                TenderPlanOneShotUncertainReason.PROVIDER_OUTCOME_UNKNOWN,
                provider_entered=True,
            )
            raise TenderPlanOneShotUncertain(
                "TenderPlan one-shot outcome requires reconciliation"
            ) from None
        try:
            return self.reconcile_success(normalized, normalized_evidence)
        except BaseException:
            self._best_effort_uncertain(
                normalized,
                TenderPlanOneShotUncertainReason.LOCAL_COMMIT_UNKNOWN,
                provider_entered=True,
            )
            raise TenderPlanOneShotUncertain(
                "TenderPlan one-shot outcome requires reconciliation"
            ) from None

    def reconcile_success(
        self,
        binding: TenderPlanOneShotBinding,
        evidence: TenderPlanOneShotSuccessEvidence,
    ) -> TenderPlanOneShotRecord:
        """Commit externally recovered digest evidence without provider entry."""

        normalized = _normalize_binding(binding)
        normalized_evidence = _normalize_success_evidence(evidence)
        binding_sha = tenderplan_one_shot_binding_sha256(normalized)
        evidence_material = _success_evidence_material(normalized_evidence)
        evidence_json = _canonical_json(evidence_material)
        evidence_sha = _sha256_json(evidence_material)
        terminal_at = self._now()
        with self._transaction(write=True) as connection:
            row = self._exact_row_locked(connection, binding_sha)
            state = TenderPlanOneShotState(str(row["state"]))
            if state is TenderPlanOneShotState.SUCCESS:
                if str(row["success_evidence_sha256"]) != evidence_sha:
                    raise TenderPlanOneShotConflict(
                        "TenderPlan one-shot success evidence differs"
                    )
                return self._row_to_record(connection, row, created=False)
            if state is not TenderPlanOneShotState.DISPATCH_INTENT:
                raise TenderPlanOneShotConflict(
                    "TenderPlan one-shot uncertain outcome is terminal"
                )
            self._assert_terminal_time(row, terminal_at)
            record_sha = _sha256_json(
                _record_material(
                    store_identity_sha256=self._store_identity_sha256,
                    binding_sha256=binding_sha,
                    state=TenderPlanOneShotState.SUCCESS.value,
                    reserved_at_utc=str(row["reserved_at_utc"]),
                    terminal_at_utc=terminal_at,
                    provider_entered=True,
                    success_evidence_sha256=evidence_sha,
                    uncertain_reason=None,
                )
            )
            changed = connection.execute(
                """UPDATE tenderplan_one_shot_intent
                   SET state='SUCCESS',terminal_at_utc=?,provider_entered=1,
                       success_evidence_sha256=?,success_evidence_json=?,
                       uncertain_reason=NULL,record_sha256=?
                   WHERE slot=1 AND state='DISPATCH_INTENT' AND binding_sha256=?""",
                (terminal_at, evidence_sha, evidence_json, record_sha, binding_sha),
            ).rowcount
            if changed != 1:
                raise TenderPlanOneShotConflict(
                    "TenderPlan one-shot success transition lost its winner"
                )
            previous = self._latest_event_sha_locked(connection)
            self._insert_event_locked(
                connection,
                sequence=2,
                event_type="SUCCESS_COMMITTED",
                binding_sha256=binding_sha,
                state=TenderPlanOneShotState.SUCCESS.value,
                occurred_at_utc=terminal_at,
                provider_entered=True,
                success_evidence_sha256=evidence_sha,
                uncertain_reason=None,
                previous_event_sha256=previous,
            )
        return self._inspect(normalized, created=False)

    def reconcile_uncertain(
        self,
        binding: TenderPlanOneShotBinding,
        reason: TenderPlanOneShotUncertainReason,
        *,
        provider_entered: bool,
    ) -> TenderPlanOneShotRecord:
        """Terminally fence an unresolved intent; never calls the provider."""

        normalized = _normalize_binding(binding)
        if type(reason) is not TenderPlanOneShotUncertainReason:
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot uncertainty reason is invalid"
            )
        if type(provider_entered) is not bool:
            raise TenderPlanOneShotValidationError(
                "TenderPlan one-shot provider-entry evidence is invalid"
            )
        binding_sha = tenderplan_one_shot_binding_sha256(normalized)
        terminal_at = self._now()
        with self._transaction(write=True) as connection:
            row = self._exact_row_locked(connection, binding_sha)
            state = TenderPlanOneShotState(str(row["state"]))
            if state is TenderPlanOneShotState.UNCERTAIN:
                if (
                    str(row["uncertain_reason"]) != reason.value
                    or bool(int(row["provider_entered"])) != provider_entered
                ):
                    raise TenderPlanOneShotConflict(
                        "TenderPlan one-shot uncertainty evidence differs"
                    )
                return self._row_to_record(connection, row, created=False)
            if state is not TenderPlanOneShotState.DISPATCH_INTENT:
                raise TenderPlanOneShotConflict(
                    "TenderPlan one-shot successful outcome is terminal"
                )
            self._assert_terminal_time(row, terminal_at)
            record_sha = _sha256_json(
                _record_material(
                    store_identity_sha256=self._store_identity_sha256,
                    binding_sha256=binding_sha,
                    state=TenderPlanOneShotState.UNCERTAIN.value,
                    reserved_at_utc=str(row["reserved_at_utc"]),
                    terminal_at_utc=terminal_at,
                    provider_entered=provider_entered,
                    success_evidence_sha256=None,
                    uncertain_reason=reason.value,
                )
            )
            changed = connection.execute(
                """UPDATE tenderplan_one_shot_intent
                   SET state='UNCERTAIN',terminal_at_utc=?,provider_entered=?,
                       success_evidence_sha256=NULL,success_evidence_json=NULL,
                       uncertain_reason=?,record_sha256=?
                   WHERE slot=1 AND state='DISPATCH_INTENT' AND binding_sha256=?""",
                (
                    terminal_at,
                    int(provider_entered),
                    reason.value,
                    record_sha,
                    binding_sha,
                ),
            ).rowcount
            if changed != 1:
                raise TenderPlanOneShotConflict(
                    "TenderPlan one-shot uncertain transition lost its winner"
                )
            previous = self._latest_event_sha_locked(connection)
            self._insert_event_locked(
                connection,
                sequence=2,
                event_type="UNCERTAIN_COMMITTED",
                binding_sha256=binding_sha,
                state=TenderPlanOneShotState.UNCERTAIN.value,
                occurred_at_utc=terminal_at,
                provider_entered=provider_entered,
                success_evidence_sha256=None,
                uncertain_reason=reason.value,
                previous_event_sha256=previous,
            )
        return self._inspect(normalized, created=False)

    def _best_effort_uncertain(
        self,
        binding: TenderPlanOneShotBinding,
        reason: TenderPlanOneShotUncertainReason,
        *,
        provider_entered: bool,
    ) -> None:
        try:
            self.reconcile_uncertain(binding, reason, provider_entered=provider_entered)
        except BaseException:
            # A committed DISPATCH_INTENT is itself a durable no-retry fence.
            # Never risk another provider call to repair local evidence.
            return

    @staticmethod
    def _assert_terminal_time(row: sqlite3.Row, terminal_at: str) -> None:
        reserved = _parse_utc_z(str(row["reserved_at_utc"]), "reserved_at_utc")
        terminal = _parse_utc_z(terminal_at, "terminal_at_utc")
        if terminal < reserved:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot clock moved backwards"
            )

    @staticmethod
    def _exact_row_locked(
        connection: sqlite3.Connection, binding_sha256: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM tenderplan_one_shot_intent WHERE slot=1"
        ).fetchone()
        if row is None:
            raise TenderPlanOneShotConflict("TenderPlan one-shot intent does not exist")
        if str(row["binding_sha256"]) != binding_sha256:
            raise TenderPlanOneShotConflict(
                "TenderPlan one-shot slot is bound differently"
            )
        return row

    @staticmethod
    def _latest_event_sha_locked(connection: sqlite3.Connection) -> str:
        row = connection.execute(
            """SELECT event_sha256 FROM tenderplan_one_shot_events
               ORDER BY sequence DESC LIMIT 1"""
        ).fetchone()
        if row is None:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot intent event is absent"
            )
        return str(row["event_sha256"])

    @staticmethod
    def _insert_event_locked(
        connection: sqlite3.Connection,
        *,
        sequence: int,
        event_type: str,
        binding_sha256: str,
        state: str,
        occurred_at_utc: str,
        provider_entered: bool,
        success_evidence_sha256: str | None,
        uncertain_reason: str | None,
        previous_event_sha256: str,
    ) -> None:
        material = _event_material(
            sequence=sequence,
            event_type=event_type,
            binding_sha256=binding_sha256,
            state=state,
            occurred_at_utc=occurred_at_utc,
            provider_entered=provider_entered,
            success_evidence_sha256=success_evidence_sha256,
            uncertain_reason=uncertain_reason,
            previous_event_sha256=previous_event_sha256,
        )
        digest = _sha256_json(material)
        connection.execute(
            """INSERT INTO tenderplan_one_shot_events(
                   sequence,event_id,event_type,binding_sha256,state,
                   occurred_at_utc,provider_entered,success_evidence_sha256,
                   uncertain_reason,previous_event_sha256,event_sha256)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sequence,
                f"tpg-event-{digest[:32]}",
                event_type,
                binding_sha256,
                state,
                occurred_at_utc,
                int(provider_entered),
                success_evidence_sha256,
                uncertain_reason,
                previous_event_sha256,
                digest,
            ),
        )

    def _row_to_record(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        created: bool,
    ) -> TenderPlanOneShotRecord:
        intent_event = connection.execute(
            """SELECT event_sha256 FROM tenderplan_one_shot_events
               WHERE sequence=1"""
        ).fetchone()
        if intent_event is None:
            raise TenderPlanOneShotIntegrityError(
                "TenderPlan one-shot intent event is absent"
            )
        reason = (
            None
            if row["uncertain_reason"] is None
            else TenderPlanOneShotUncertainReason(str(row["uncertain_reason"]))
        )
        return TenderPlanOneShotRecord(
            created=created,
            state=TenderPlanOneShotState(str(row["state"])),
            binding_sha256=str(row["binding_sha256"]),
            store_identity_sha256=self._store_identity_sha256,
            intent_event_sha256=str(intent_event["event_sha256"]),
            reserved_at_utc=str(row["reserved_at_utc"]),
            terminal_at_utc=(
                None if row["terminal_at_utc"] is None else str(row["terminal_at_utc"])
            ),
            provider_entered=bool(int(row["provider_entered"])),
            success_evidence_sha256=(
                None
                if row["success_evidence_sha256"] is None
                else str(row["success_evidence_sha256"])
            ),
            uncertain_reason=reason,
        )


def _binding_from_material(material: Mapping[str, object]) -> TenderPlanOneShotBinding:
    expected_constants = {
        "contact_count": 0,
        "http_method": _HTTP_METHOD,
        "http_path": _HTTP_PATH,
        "live_release_eligible": False,
        "max_provider_entries": 1,
        "max_response_bytes": _MAX_RESPONSE_BYTES,
        "max_response_records": _MAX_RESPONSE_RECORDS,
        "page": _SEARCH_PAGE,
        "provider_code": _PROVIDER_CODE,
        "search_set": _SEARCH_SET,
        "spend_minor": 0,
        "write_count": 0,
    }
    if any(material.get(key) != value for key, value in expected_constants.items()):
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot binding constants differ"
        )
    try:
        binding = TenderPlanOneShotBinding(
            operation_id=material["operation_id"],  # type: ignore[arg-type]
            command_sha256=material["command_sha256"],  # type: ignore[arg-type]
            authorization_sha256=material["authorization_sha256"],  # type: ignore[arg-type]
            authorization_receipt_sha256=material["authorization_receipt_sha256"],  # type: ignore[arg-type]
            external_admission_sha256=material["external_admission_sha256"],  # type: ignore[arg-type]
            stop_policy_sha256=material["stop_policy_sha256"],  # type: ignore[arg-type]
            source_read_epoch_sha256=material["source_read_epoch_sha256"],  # type: ignore[arg-type]
            passport_sha256=material["passport_sha256"],  # type: ignore[arg-type]
            stream_sha256=material["stream_sha256"],  # type: ignore[arg-type]
            query_policy_sha256=material["query_policy_sha256"],  # type: ignore[arg-type]
            auth_reference_sha256=material["auth_reference_sha256"],  # type: ignore[arg-type]
        )
    except (KeyError, TypeError):
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot binding material is incomplete"
        ) from None
    try:
        return _normalize_binding(binding)
    except TenderPlanOneShotValidationError as error:
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot binding material is invalid"
        ) from error


def _success_evidence_from_material(
    material: object,
) -> TenderPlanOneShotSuccessEvidence:
    if type(material) is not dict:
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot success evidence is invalid"
        )
    try:
        evidence = TenderPlanOneShotSuccessEvidence(
            response_body_sha256=material["response_body_sha256"],
            projection_sha256=material["projection_sha256"],
            upstream_receipt_sha256=material["upstream_receipt_sha256"],
            record_count=material["record_count"],
            byte_count=material["byte_count"],
            http_status=material["http_status"],
            write_count=material["write_count"],
            contact_count=material["contact_count"],
            spend_minor=material["spend_minor"],
            live_release_eligible=material["live_release_eligible"],
        )
    except (KeyError, TypeError):
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot success evidence is incomplete"
        ) from None
    try:
        normalized = _normalize_success_evidence(evidence)
    except TenderPlanOneShotValidationError as error:
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot success evidence is invalid"
        ) from error
    if set(material) != set(_success_evidence_material(normalized)):
        raise TenderPlanOneShotIntegrityError(
            "TenderPlan one-shot success evidence fields differ"
        )
    return normalized


__all__ = [
    "TENDERPLAN_ONE_SHOT_APPLICATION_ID",
    "TENDERPLAN_ONE_SHOT_CONTRACT_ID",
    "TENDERPLAN_ONE_SHOT_OPERATION_ID",
    "TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256",
    "TENDERPLAN_ONE_SHOT_SCHEMA_VERSION",
    "TenderPlanOneShotBinding",
    "TenderPlanOneShotConflict",
    "TenderPlanOneShotError",
    "TenderPlanOneShotGuard",
    "TenderPlanOneShotIntegrityError",
    "TenderPlanOneShotRecord",
    "TenderPlanOneShotReconciliationRequired",
    "TenderPlanOneShotState",
    "TenderPlanOneShotStopped",
    "TenderPlanOneShotSuccessEvidence",
    "TenderPlanOneShotUncertain",
    "TenderPlanOneShotUncertainReason",
    "TenderPlanOneShotValidationError",
    "tenderplan_one_shot_binding_sha256",
]
