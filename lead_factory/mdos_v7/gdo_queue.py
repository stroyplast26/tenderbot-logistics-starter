"""Bounded offline-shadow queue for accepted hot-demand work.

This module is deliberately isolated from the MDOS evidence stores and every
transport boundary.  The caller must provide the SQLite path; there is no
workspace default, credential input, HTTP client, or live mode.  The database
is an operational projection only and can never be canonical KPI evidence.

The immutable admission binding contains hashes only.  Raw demand, personal
data, commercial documents, and credentials do not belong in this store.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sqlite3
from typing import Callable, Iterator, Mapping

from .contracts import (
    CONTRACT_ID,
    PACKAGE_ROOT_SHA256,
    PACKAGE_VERSION,
    value_sha256,
)


SCHEMA_VERSION = 1
APPLICATION_ID = 0x47445131  # "GDQ1"
ENVIRONMENT = "OFFLINE_SHADOW"
MODE = "OFFLINE_SHADOW"
GENESIS_SHA256 = "0" * 64
DEFAULT_MAX_QUEUE_DEPTH = 1_000
MAX_SAFE_QUEUE_DEPTH = 100_000
DEFAULT_BUSINESS_UTC_OFFSET_MINUTES = 180
# Filled from the canonical sqlite_master inventory after every intentional
# schema change.  Existing stores fail closed if their inventory differs.
CANONICAL_SCHEMA_FINGERPRINT_SHA256 = (
    "682daa33a7e09c9fccab3b0b7049bac22e969b266d136b3e94ec7232b80e82fe"
)

READY = "READY"
IN_PROGRESS = "IN_PROGRESS"
HOLD = "HOLD"
DONE = "DONE"
QUEUE_STATES = frozenset({READY, IN_PROGRESS, HOLD, DONE})
_ADMISSION_HOLD_REASONS = frozenset(
    {
        "CAPACITY_ZERO",
        "CAPACITY_NOT_YET_OBSERVED",
        "CAPACITY_STALE",
        "CAPACITY_SNAPSHOT_ROLLBACK",
        "MAX_WIP_REACHED",
        "CAPACITY_SLOTS_EXHAUSTED",
        "DAILY_INTAKE_REACHED",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/\-]{0,254}$")
_SENSITIVE_TOKEN_PREFIX_RE = re.compile(
    r"^(?:e-?mail|mailto|tel|phone|mobile|whatsapp)[_.:/\-]", re.IGNORECASE
)
_REQUIRED_ADMISSION_KEYS = frozenset(
    {
        "queue_item_id",
        "demand_unit_id",
        "gold_acceptance_id",
        "demand_unit_sha256",
        "gold_acceptance_sha256",
        "scope_sha256",
        "hot_gate_sha256",
        "permit_decision_sha256",
        "capacity_snapshot_sha256",
        "economics_snapshot_sha256",
        "hot_gate_passed",
        "permit_allows_offline_queue",
        "capacity_pool_id",
        "capacity_slots",
        "capacity_observed_at_utc",
        "capacity_valid_until_utc",
        "owner_id",
        "deadline_at_utc",
        "idempotency_key",
    }
)


class GdoQueueError(RuntimeError):
    """Base error for the isolated GDO queue."""


class GdoQueueValidationError(GdoQueueError):
    """An input is not an exact safe offline-queue value."""


class GdoQueueIntegrityError(GdoQueueError):
    """Persisted schema, event history, or projection integrity failed."""


class GdoQueueMetadataTamper(GdoQueueIntegrityError):
    """Immutable contract or operating metadata differs from the store."""


class GdoQueueIdempotencyConflict(GdoQueueError):
    """An idempotency key was reused for different exact input."""


class GdoQueueDuplicateItem(GdoQueueError):
    """The same queue identity was submitted under another command."""


class GdoQueueTransitionError(GdoQueueError):
    """A state transition is not permitted."""


class GdoQueueBackpressure(GdoQueueError):
    """A HOLD item cannot reserve a slot under the current bound limits."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class GdoQueueCapacityConflict(GdoQueueError):
    """One capacity snapshot identity conflicts with stored pool evidence."""


@dataclass(frozen=True, slots=True)
class GdoQueueAdmission:
    """Privacy-minimised exact binding for one accepted hot-demand item."""

    queue_item_id: str
    demand_unit_id: str
    gold_acceptance_id: str
    demand_unit_sha256: str
    gold_acceptance_sha256: str
    scope_sha256: str
    hot_gate_sha256: str
    permit_decision_sha256: str
    capacity_snapshot_sha256: str
    economics_snapshot_sha256: str
    hot_gate_passed: bool
    permit_allows_offline_queue: bool
    capacity_pool_id: str
    capacity_slots: int
    capacity_observed_at_utc: str
    capacity_valid_until_utc: str
    owner_id: str
    deadline_at_utc: str
    idempotency_key: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "GdoQueueAdmission":
        if not isinstance(value, Mapping):
            raise GdoQueueValidationError("admission payload must be a mapping")
        keys = frozenset(str(key) for key in value)
        if keys != _REQUIRED_ADMISSION_KEYS:
            missing = sorted(_REQUIRED_ADMISSION_KEYS - keys)
            extra = sorted(keys - _REQUIRED_ADMISSION_KEYS)
            raise GdoQueueValidationError(
                f"admission keys differ: missing={missing}, extra={extra}"
            )
        return cls(**{key: value[key] for key in _REQUIRED_ADMISSION_KEYS})  # type: ignore[arg-type]

    def material(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GdoQueueItem:
    queue_item_id: str
    demand_unit_id: str
    gold_acceptance_id: str
    demand_unit_sha256: str
    gold_acceptance_sha256: str
    scope_sha256: str
    hot_gate_sha256: str
    permit_decision_sha256: str
    capacity_snapshot_sha256: str
    economics_snapshot_sha256: str
    capacity_pool_id: str
    capacity_slots: int
    capacity_observed_at_utc: str
    capacity_valid_until_utc: str
    owner_id: str
    deadline_at_utc: str
    state: str
    hold_reason: str
    slot_reserved: bool
    admitted_at_utc: str
    started_at_utc: str
    completed_at_utc: str
    slot_released_at_utc: str
    last_event_id: str
    last_event_sha256: str
    version: int
    mode: str = MODE
    canonical_kpi_eligible: bool = False
    external_effect: bool = False
    transport_call_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class QueueMutation:
    disposition: str
    event_id: str
    event_sha256: str
    slot_delta: int
    item: GdoQueueItem


@dataclass(frozen=True, slots=True)
class QueueSnapshot:
    as_of_utc: str
    depth: int
    ready: int
    in_progress: int
    hold: int
    done: int
    active_wip: int
    available_wip_slots: int
    max_wip: int
    available_queue_depth: int
    max_queue_depth: int
    daily_intake_used: int
    daily_intake_limit: int
    business_utc_offset_minutes: int
    active_by_capacity_pool: tuple[tuple[str, int], ...]
    oldest_open_age_seconds: int
    sla_breaches: int
    sla_breach_item_ids: tuple[str, ...]
    backpressure: bool
    backpressure_reasons: tuple[str, ...]
    mode: str = MODE
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0
    transport_call_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_SCHEMA_SQL = """
CREATE TABLE gdo_queue_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE gdo_queue_items(
    queue_item_id TEXT PRIMARY KEY,
    admission_idempotency_key TEXT NOT NULL UNIQUE,
    admission_command_sha256 TEXT NOT NULL,
    demand_unit_id TEXT NOT NULL UNIQUE,
    gold_acceptance_id TEXT NOT NULL UNIQUE,
    demand_unit_sha256 TEXT NOT NULL UNIQUE,
    gold_acceptance_sha256 TEXT NOT NULL UNIQUE,
    scope_sha256 TEXT NOT NULL,
    hot_gate_sha256 TEXT NOT NULL,
    permit_decision_sha256 TEXT NOT NULL,
    capacity_snapshot_sha256 TEXT NOT NULL,
    economics_snapshot_sha256 TEXT NOT NULL,
    capacity_pool_id TEXT NOT NULL,
    capacity_slots INTEGER NOT NULL CHECK(capacity_slots >= 0),
    capacity_observed_at_utc TEXT NOT NULL,
    capacity_valid_until_utc TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    deadline_at_utc TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('READY','IN_PROGRESS','HOLD','DONE')),
    hold_reason TEXT NOT NULL,
    slot_reserved INTEGER NOT NULL CHECK(slot_reserved IN (0,1)),
    admitted_at_utc TEXT NOT NULL,
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT NOT NULL,
    slot_released_at_utc TEXT NOT NULL,
    last_event_id TEXT NOT NULL,
    last_event_sha256 TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    mode TEXT NOT NULL CHECK(mode = 'OFFLINE_SHADOW'),
    canonical_kpi_eligible INTEGER NOT NULL CHECK(canonical_kpi_eligible = 0),
    external_effect INTEGER NOT NULL CHECK(external_effect = 0),
    transport_call_count INTEGER NOT NULL CHECK(transport_call_count = 0),
    UNIQUE(demand_unit_sha256, gold_acceptance_sha256, scope_sha256)
);

CREATE TABLE gdo_queue_events(
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    queue_item_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL CHECK(to_state IN ('READY','IN_PROGRESS','HOLD','DONE')),
    reason_code TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    occurred_at_utc TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    command_sha256 TEXT NOT NULL,
    slot_delta INTEGER NOT NULL CHECK(slot_delta IN (-1,0,1)),
    previous_event_sha256 TEXT NOT NULL,
    event_sha256 TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK(mode = 'OFFLINE_SHADOW'),
    canonical_kpi_eligible INTEGER NOT NULL CHECK(canonical_kpi_eligible = 0),
    external_effect INTEGER NOT NULL CHECK(external_effect = 0),
    transport_call_count INTEGER NOT NULL CHECK(transport_call_count = 0),
    FOREIGN KEY(queue_item_id) REFERENCES gdo_queue_items(queue_item_id)
);

CREATE INDEX idx_gdo_queue_state ON gdo_queue_items(state, admitted_at_utc);
CREATE INDEX idx_gdo_queue_deadline ON gdo_queue_items(state, deadline_at_utc);
CREATE INDEX idx_gdo_queue_capacity_pool
    ON gdo_queue_items(capacity_pool_id, state, admitted_at_utc);
CREATE INDEX idx_gdo_queue_events_item ON gdo_queue_events(queue_item_id, sequence);
CREATE INDEX idx_gdo_queue_events_time ON gdo_queue_events(occurred_at_utc, sequence);

CREATE TRIGGER trg_gdo_queue_meta_no_update
BEFORE UPDATE ON gdo_queue_meta BEGIN
    SELECT RAISE(ABORT, 'gdo queue metadata is immutable');
END;
CREATE TRIGGER trg_gdo_queue_meta_no_delete
BEFORE DELETE ON gdo_queue_meta BEGIN
    SELECT RAISE(ABORT, 'gdo queue metadata is immutable');
END;
CREATE TRIGGER trg_gdo_queue_events_no_update
BEFORE UPDATE ON gdo_queue_events BEGIN
    SELECT RAISE(ABORT, 'gdo queue events are append-only');
END;
CREATE TRIGGER trg_gdo_queue_events_no_delete
BEFORE DELETE ON gdo_queue_events BEGIN
    SELECT RAISE(ABORT, 'gdo queue events are append-only');
END;

CREATE TRIGGER trg_gdo_queue_items_no_delete
BEFORE DELETE ON gdo_queue_items BEGIN
    SELECT RAISE(ABORT, 'gdo queue items cannot be deleted');
END;
CREATE TRIGGER trg_gdo_queue_items_immutable_binding
BEFORE UPDATE ON gdo_queue_items
WHEN OLD.queue_item_id != NEW.queue_item_id
  OR OLD.admission_idempotency_key != NEW.admission_idempotency_key
  OR OLD.admission_command_sha256 != NEW.admission_command_sha256
  OR OLD.demand_unit_id != NEW.demand_unit_id
  OR OLD.gold_acceptance_id != NEW.gold_acceptance_id
  OR OLD.demand_unit_sha256 != NEW.demand_unit_sha256
  OR OLD.gold_acceptance_sha256 != NEW.gold_acceptance_sha256
  OR OLD.scope_sha256 != NEW.scope_sha256
  OR OLD.hot_gate_sha256 != NEW.hot_gate_sha256
  OR OLD.permit_decision_sha256 != NEW.permit_decision_sha256
  OR OLD.capacity_snapshot_sha256 != NEW.capacity_snapshot_sha256
  OR OLD.economics_snapshot_sha256 != NEW.economics_snapshot_sha256
  OR OLD.capacity_pool_id != NEW.capacity_pool_id
  OR OLD.capacity_slots != NEW.capacity_slots
  OR OLD.capacity_observed_at_utc != NEW.capacity_observed_at_utc
  OR OLD.capacity_valid_until_utc != NEW.capacity_valid_until_utc
  OR OLD.owner_id != NEW.owner_id
  OR OLD.deadline_at_utc != NEW.deadline_at_utc
  OR OLD.admitted_at_utc != NEW.admitted_at_utc
  OR OLD.mode != NEW.mode
  OR OLD.canonical_kpi_eligible != NEW.canonical_kpi_eligible
  OR OLD.external_effect != NEW.external_effect
  OR OLD.transport_call_count != NEW.transport_call_count
BEGIN
    SELECT RAISE(ABORT, 'gdo queue admission binding is immutable');
END;
"""


def _parse_utc_z(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GdoQueueValidationError(f"{field} must be an RFC3339 UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise GdoQueueValidationError(f"{field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GdoQueueValidationError(f"{field} must be UTC")
    return parsed.astimezone(timezone.utc)


def _utc_z(value: datetime) -> str:
    if value.tzinfo is None:
        raise GdoQueueValidationError("queue clock must be timezone-aware")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _safe_token(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or _SAFE_TOKEN_RE.fullmatch(value) is None
        or not any(
            "A" <= character <= "Z" or "a" <= character <= "z" for character in value
        )
        or _SENSITIVE_TOKEN_PREFIX_RE.match(value) is not None
    ):
        raise GdoQueueValidationError(f"{field} must be a non-empty safe token")
    return value


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GdoQueueValidationError(f"{field} must be a lowercase SHA-256")
    return value


class GdoQueueStore:
    """SQLite-backed bounded queue with no transport or live authority surface."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_wip: int,
        daily_intake: int,
        max_queue_depth: int = DEFAULT_MAX_QUEUE_DEPTH,
        business_utc_offset_minutes: int = DEFAULT_BUSINESS_UTC_OFFSET_MINUTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(max_wip) is not int or max_wip < 1:
            raise GdoQueueValidationError("max_wip must be a positive integer")
        if type(daily_intake) is not int or daily_intake < 1:
            raise GdoQueueValidationError("daily_intake must be a positive integer")
        if (
            type(max_queue_depth) is not int
            or not 1 <= max_queue_depth <= MAX_SAFE_QUEUE_DEPTH
        ):
            raise GdoQueueValidationError("max_queue_depth is outside its safe limit")
        if (
            type(business_utc_offset_minutes) is not int
            or not -720 <= business_utc_offset_minutes <= 840
        ):
            raise GdoQueueValidationError(
                "business_utc_offset_minutes is outside a fixed UTC offset"
            )
        self.path = Path(path).resolve()
        if not self.path.parent.is_dir():
            raise GdoQueueValidationError("queue database parent must already exist")
        self.max_wip = max_wip
        self.daily_intake = daily_intake
        self.max_queue_depth = max_queue_depth
        self.business_utc_offset_minutes = business_utc_offset_minutes
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._bootstrap_or_validate()

    def _now(self) -> tuple[datetime, str]:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise GdoQueueValidationError("queue clock must be timezone-aware")
        return value.astimezone(timezone.utc), _utc_z(value)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_locked(connection)
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _schema_fingerprint(connection: sqlite3.Connection) -> str:
        rows = connection.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%'
               ORDER BY type,name"""
        ).fetchall()
        return value_sha256(
            [
                {
                    "type": str(row[0]),
                    "name": str(row[1]),
                    "table": str(row[2]),
                    "sql": " ".join(str(row[3] or "").split()),
                }
                for row in rows
            ]
        )

    def _expected_metadata(self) -> dict[str, str]:
        return {
            "schema_version": str(SCHEMA_VERSION),
            "contract_id": CONTRACT_ID,
            "package_version": PACKAGE_VERSION,
            "package_root_sha256": PACKAGE_ROOT_SHA256,
            "contract_root_sha256": PACKAGE_ROOT_SHA256,
            "environment": ENVIRONMENT,
            "mode": MODE,
            "canonical_kpi_eligible": "0",
            "external_reads_enabled": "0",
            "external_writers_enabled": "0",
            "external_effects_enabled": "0",
            "live_bitrix_enabled": "0",
            "transport_enabled": "0",
            "transport_call_count": "0",
            "credentials_allowed": "0",
            "max_wip": str(self.max_wip),
            "daily_intake": str(self.daily_intake),
            "max_queue_depth": str(self.max_queue_depth),
            "business_utc_offset_minutes": str(self.business_utc_offset_minutes),
            "schema_fingerprint_sha256": CANONICAL_SCHEMA_FINGERPRINT_SHA256,
        }

    @staticmethod
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
            raise GdoQueueIntegrityError("canonical queue schema is incomplete")
        return tuple(statements)

    def _bootstrap_or_validate(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT name FROM sqlite_master
                   WHERE name NOT LIKE 'sqlite_%' LIMIT 1"""
            ).fetchone()
            if existing is None:
                for statement in self._schema_statements():
                    connection.execute(statement)
                fingerprint = self._schema_fingerprint(connection)
                if fingerprint != CANONICAL_SCHEMA_FINGERPRINT_SHA256:
                    raise GdoQueueIntegrityError(
                        "canonical queue schema fingerprint constant differs"
                    )
                connection.executemany(
                    "INSERT INTO gdo_queue_meta(key,value) VALUES(?,?)",
                    sorted(self._expected_metadata().items()),
                )
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._verify_locked(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _validate_existing(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._verify_locked(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _verify_metadata_locked(self, connection: sqlite3.Connection) -> None:
        try:
            rows = connection.execute(
                "SELECT key,value FROM gdo_queue_meta ORDER BY key"
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise GdoQueueMetadataTamper(
                "queue metadata table is unavailable"
            ) from error
        actual = {str(row["key"]): str(row["value"]) for row in rows}
        fingerprint = self._schema_fingerprint(connection)
        if fingerprint != CANONICAL_SCHEMA_FINGERPRINT_SHA256:
            raise GdoQueueMetadataTamper("canonical queue schema inventory differs")
        if actual != self._expected_metadata():
            raise GdoQueueMetadataTamper("immutable queue metadata differs")
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if application_id != APPLICATION_ID or user_version != SCHEMA_VERSION:
            raise GdoQueueMetadataTamper("queue SQLite identity differs")

    @staticmethod
    def _event_material(row: Mapping[str, object]) -> dict[str, object]:
        return {
            "event_id": row["event_id"],
            "queue_item_id": row["queue_item_id"],
            "event_type": row["event_type"],
            "from_state": row["from_state"],
            "to_state": row["to_state"],
            "reason_code": row["reason_code"],
            "actor_id": row["actor_id"],
            "occurred_at_utc": row["occurred_at_utc"],
            "idempotency_key": row["idempotency_key"],
            "command_sha256": row["command_sha256"],
            "slot_delta": int(row["slot_delta"]),
            "previous_event_sha256": row["previous_event_sha256"],
            "mode": row["mode"],
            "canonical_kpi_eligible": bool(row["canonical_kpi_eligible"]),
            "external_effect": bool(row["external_effect"]),
            "transport_call_count": int(row["transport_call_count"]),
        }

    def _verify_events_locked(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT * FROM gdo_queue_events ORDER BY sequence"
        ).fetchall()
        previous = GENESIS_SHA256
        previous_time: datetime | None = None
        per_item: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            if str(row["previous_event_sha256"]) != previous:
                raise GdoQueueIntegrityError("queue event chain predecessor differs")
            material = self._event_material(row)
            digest = value_sha256(material)
            if str(row["event_sha256"]) != digest:
                raise GdoQueueIntegrityError("queue event digest differs")
            identity = {
                "queue_item_id": row["queue_item_id"],
                "event_type": row["event_type"],
                "idempotency_key": row["idempotency_key"],
                "command_sha256": row["command_sha256"],
            }
            if str(row["event_id"]) != f"gdoq-event-{value_sha256(identity)[:32]}":
                raise GdoQueueIntegrityError("queue event identity differs")
            if (
                str(row["mode"]) != MODE
                or int(row["canonical_kpi_eligible"]) != 0
                or int(row["external_effect"]) != 0
                or int(row["transport_call_count"]) != 0
            ):
                raise GdoQueueIntegrityError("queue event exceeds offline authority")
            occurred = _parse_utc_z(row["occurred_at_utc"], "occurred_at_utc")
            if previous_time is not None and occurred < previous_time:
                raise GdoQueueIntegrityError("queue event time moved backwards")
            previous_time = occurred
            previous = digest
            per_item.setdefault(str(row["queue_item_id"]), []).append(row)

        items = connection.execute(
            "SELECT * FROM gdo_queue_items ORDER BY queue_item_id"
        ).fetchall()
        if len(items) != len(per_item):
            raise GdoQueueIntegrityError("queue item/event cardinality differs")
        for item in items:
            item_id = str(item["queue_item_id"])
            history = per_item.get(item_id, [])
            if not history:
                raise GdoQueueIntegrityError("queue item has no event history")
            if (
                str(item["mode"]) != MODE
                or int(item["canonical_kpi_eligible"]) != 0
                or int(item["external_effect"]) != 0
                or int(item["transport_call_count"]) != 0
            ):
                raise GdoQueueIntegrityError("queue item exceeds offline authority")
            admission = GdoQueueAdmission(
                queue_item_id=item_id,
                demand_unit_id=str(item["demand_unit_id"]),
                gold_acceptance_id=str(item["gold_acceptance_id"]),
                demand_unit_sha256=str(item["demand_unit_sha256"]),
                gold_acceptance_sha256=str(item["gold_acceptance_sha256"]),
                scope_sha256=str(item["scope_sha256"]),
                hot_gate_sha256=str(item["hot_gate_sha256"]),
                permit_decision_sha256=str(item["permit_decision_sha256"]),
                capacity_snapshot_sha256=str(item["capacity_snapshot_sha256"]),
                economics_snapshot_sha256=str(item["economics_snapshot_sha256"]),
                hot_gate_passed=True,
                permit_allows_offline_queue=True,
                capacity_pool_id=str(item["capacity_pool_id"]),
                capacity_slots=int(item["capacity_slots"]),
                capacity_observed_at_utc=str(item["capacity_observed_at_utc"]),
                capacity_valid_until_utc=str(item["capacity_valid_until_utc"]),
                owner_id=str(item["owner_id"]),
                deadline_at_utc=str(item["deadline_at_utc"]),
                idempotency_key=str(item["admission_idempotency_key"]),
            )
            admission_sha = self._command_sha(admission.material())
            first = history[0]
            if (
                str(item["admission_command_sha256"]) != admission_sha
                or str(first["event_type"]) != "ADMITTED"
                or str(first["command_sha256"]) != admission_sha
                or str(first["from_state"]) != ""
                or str(first["actor_id"]) != str(item["owner_id"])
                or str(first["occurred_at_utc"]) != str(item["admitted_at_utc"])
                or str(first["idempotency_key"])
                != str(item["admission_idempotency_key"])
            ):
                raise GdoQueueIntegrityError("queue admission binding differs")
            state = str(first["to_state"])
            if state not in {READY, HOLD}:
                raise GdoQueueIntegrityError("queue admission state differs")
            reason = str(first["reason_code"])
            expected_delta = 1 if state == READY else 0
            if (
                int(first["slot_delta"]) != expected_delta
                or (state == READY and reason != "CAPACITY_RESERVED")
                or (state == HOLD and reason not in _ADMISSION_HOLD_REASONS)
            ):
                raise GdoQueueIntegrityError("queue admission capacity event differs")

            slot_balance = expected_delta
            hold_reason = reason if state == HOLD else ""
            admitted_at = str(first["occurred_at_utc"])
            started_at = ""
            completed_at = ""
            released_at = ""
            item_time = _parse_utc_z(first["occurred_at_utc"], "occurred_at_utc")
            for event in history[1:]:
                target = str(event["to_state"])
                event_time = _parse_utc_z(event["occurred_at_utc"], "occurred_at_utc")
                if event_time < item_time:
                    raise GdoQueueIntegrityError(
                        "queue item event time moved backwards"
                    )
                if str(event["from_state"]) != state or str(event["actor_id"]) != str(
                    item["owner_id"]
                ):
                    raise GdoQueueIntegrityError("queue transition authority differs")
                allowed = {
                    READY: {IN_PROGRESS, HOLD},
                    IN_PROGRESS: {HOLD, DONE},
                    HOLD: {READY},
                    DONE: set(),
                }
                if target not in allowed[state]:
                    raise GdoQueueIntegrityError("queue transition chain is illegal")
                acknowledgement = state == READY and target == IN_PROGRESS
                expected_type = (
                    "OWNER_ACKNOWLEDGED" if acknowledgement else "TRANSITION"
                )
                event_reason = str(event["reason_code"])
                if str(event["event_type"]) != expected_type or (
                    acknowledgement and event_reason != "OWNER_ACKNOWLEDGED"
                ):
                    raise GdoQueueIntegrityError("queue transition event type differs")
                transition_command = {
                    "queue_item_id": item_id,
                    "target_state": target,
                    "owner_id": str(item["owner_id"]),
                    "idempotency_key": str(event["idempotency_key"]),
                    "reason_code": event_reason,
                }
                if str(event["command_sha256"]) != self._command_sha(
                    transition_command
                ):
                    raise GdoQueueIntegrityError("queue transition command differs")
                expected_slot_delta = {
                    (READY, IN_PROGRESS): 0,
                    (READY, HOLD): -1,
                    (IN_PROGRESS, HOLD): -1,
                    (IN_PROGRESS, DONE): -1,
                    (HOLD, READY): 1,
                }[(state, target)]
                if int(event["slot_delta"]) != expected_slot_delta:
                    raise GdoQueueIntegrityError("queue transition slot delta differs")
                slot_balance += expected_slot_delta
                if slot_balance not in (0, 1):
                    raise GdoQueueIntegrityError("queue slot balance differs")
                if target == IN_PROGRESS and not started_at:
                    started_at = str(event["occurred_at_utc"])
                if target == HOLD:
                    hold_reason = event_reason
                    released_at = str(event["occurred_at_utc"])
                elif target == READY:
                    hold_reason = ""
                    released_at = ""
                elif target == DONE:
                    hold_reason = ""
                    completed_at = str(event["occurred_at_utc"])
                    released_at = str(event["occurred_at_utc"])
                else:
                    hold_reason = ""
                state = target
                item_time = event_time

            last = history[-1]
            expected_reserved = 1 if state in {READY, IN_PROGRESS} else 0
            if (
                str(item["state"]) != state
                or int(item["slot_reserved"]) != expected_reserved
                or slot_balance != expected_reserved
                or str(item["hold_reason"]) != hold_reason
                or str(item["admitted_at_utc"]) != admitted_at
                or str(item["started_at_utc"]) != started_at
                or str(item["completed_at_utc"]) != completed_at
                or str(item["slot_released_at_utc"]) != released_at
                or str(item["last_event_id"]) != str(last["event_id"])
                or str(item["last_event_sha256"]) != str(last["event_sha256"])
                or int(item["version"]) != len(history)
            ):
                raise GdoQueueIntegrityError(
                    "queue projection differs from event replay"
                )

    def _verify_locked(self, connection: sqlite3.Connection) -> None:
        self._verify_metadata_locked(connection)
        self._verify_events_locked(connection)

    @staticmethod
    def _validate_admission(value: GdoQueueAdmission) -> None:
        for field in (
            "queue_item_id",
            "demand_unit_id",
            "gold_acceptance_id",
            "capacity_pool_id",
            "owner_id",
            "idempotency_key",
        ):
            _safe_token(getattr(value, field), field)
        for field in (
            "demand_unit_sha256",
            "gold_acceptance_sha256",
            "scope_sha256",
            "hot_gate_sha256",
            "permit_decision_sha256",
            "capacity_snapshot_sha256",
            "economics_snapshot_sha256",
        ):
            _sha256(getattr(value, field), field)
        if type(value.hot_gate_passed) is not bool or not value.hot_gate_passed:
            raise GdoQueueValidationError("hot gate must be explicitly passed")
        if (
            type(value.permit_allows_offline_queue) is not bool
            or not value.permit_allows_offline_queue
        ):
            raise GdoQueueValidationError(
                "permit must explicitly allow the offline queue only"
            )
        if type(value.capacity_slots) is not int or value.capacity_slots < 0:
            raise GdoQueueValidationError(
                "capacity_slots must be a non-negative integer"
            )
        observed = _parse_utc_z(
            value.capacity_observed_at_utc, "capacity_observed_at_utc"
        )
        valid_until = _parse_utc_z(
            value.capacity_valid_until_utc, "capacity_valid_until_utc"
        )
        _parse_utc_z(value.deadline_at_utc, "deadline_at_utc")
        if valid_until <= observed:
            raise GdoQueueValidationError(
                "capacity validity must end after its observation"
            )

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> GdoQueueItem:
        return GdoQueueItem(
            queue_item_id=str(row["queue_item_id"]),
            demand_unit_id=str(row["demand_unit_id"]),
            gold_acceptance_id=str(row["gold_acceptance_id"]),
            demand_unit_sha256=str(row["demand_unit_sha256"]),
            gold_acceptance_sha256=str(row["gold_acceptance_sha256"]),
            scope_sha256=str(row["scope_sha256"]),
            hot_gate_sha256=str(row["hot_gate_sha256"]),
            permit_decision_sha256=str(row["permit_decision_sha256"]),
            capacity_snapshot_sha256=str(row["capacity_snapshot_sha256"]),
            economics_snapshot_sha256=str(row["economics_snapshot_sha256"]),
            capacity_pool_id=str(row["capacity_pool_id"]),
            capacity_slots=int(row["capacity_slots"]),
            capacity_observed_at_utc=str(row["capacity_observed_at_utc"]),
            capacity_valid_until_utc=str(row["capacity_valid_until_utc"]),
            owner_id=str(row["owner_id"]),
            deadline_at_utc=str(row["deadline_at_utc"]),
            state=str(row["state"]),
            hold_reason=str(row["hold_reason"]),
            slot_reserved=bool(row["slot_reserved"]),
            admitted_at_utc=str(row["admitted_at_utc"]),
            started_at_utc=str(row["started_at_utc"]),
            completed_at_utc=str(row["completed_at_utc"]),
            slot_released_at_utc=str(row["slot_released_at_utc"]),
            last_event_id=str(row["last_event_id"]),
            last_event_sha256=str(row["last_event_sha256"]),
            version=int(row["version"]),
        )

    @staticmethod
    def _active_wip_locked(connection: sqlite3.Connection) -> int:
        return int(
            connection.execute(
                """SELECT COUNT(*) FROM gdo_queue_items
                   WHERE state IN ('READY','IN_PROGRESS') AND slot_reserved=1"""
            ).fetchone()[0]
        )

    @staticmethod
    def _active_capacity_pool_locked(
        connection: sqlite3.Connection, capacity_pool_id: str
    ) -> int:
        return int(
            connection.execute(
                """SELECT COUNT(*) FROM gdo_queue_items
                   WHERE capacity_pool_id=?
                     AND state IN ('READY','IN_PROGRESS') AND slot_reserved=1""",
                (capacity_pool_id,),
            ).fetchone()[0]
        )

    @staticmethod
    def _queue_depth_locked(connection: sqlite3.Connection) -> int:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM gdo_queue_items WHERE state!='DONE'"
            ).fetchone()[0]
        )

    def _business_day_bounds(self, now: datetime) -> tuple[str, str]:
        offset = timedelta(minutes=self.business_utc_offset_minutes)
        local = now.astimezone(timezone.utc) + offset
        local_start = datetime(local.year, local.month, local.day, tzinfo=timezone.utc)
        start = local_start - offset
        return _utc_z(start), _utc_z(start + timedelta(days=1))

    def _daily_intake_locked(
        self, connection: sqlite3.Connection, now: datetime
    ) -> int:
        start, end = self._business_day_bounds(now)
        return int(
            connection.execute(
                """SELECT COUNT(DISTINCT queue_item_id) FROM gdo_queue_events
                   WHERE slot_delta=1 AND occurred_at_utc>=? AND occurred_at_utc<?""",
                (start, end),
            ).fetchone()[0]
        )

    @staticmethod
    def _capacity_snapshot_blocker_locked(
        connection: sqlite3.Connection, admission: GdoQueueAdmission
    ) -> str:
        rows = connection.execute(
            """SELECT capacity_pool_id,capacity_snapshot_sha256,capacity_slots,
                      capacity_observed_at_utc,capacity_valid_until_utc
               FROM gdo_queue_items
               WHERE capacity_pool_id=? OR capacity_snapshot_sha256=?""",
            (admission.capacity_pool_id, admission.capacity_snapshot_sha256),
        ).fetchall()
        incoming_observed = _parse_utc_z(
            admission.capacity_observed_at_utc, "capacity_observed_at_utc"
        )
        incoming_evidence = (
            admission.capacity_pool_id,
            admission.capacity_snapshot_sha256,
            admission.capacity_slots,
            admission.capacity_observed_at_utc,
            admission.capacity_valid_until_utc,
        )
        latest_pool_observed: datetime | None = None
        for row in rows:
            stored_evidence = (
                str(row["capacity_pool_id"]),
                str(row["capacity_snapshot_sha256"]),
                int(row["capacity_slots"]),
                str(row["capacity_observed_at_utc"]),
                str(row["capacity_valid_until_utc"]),
            )
            if (
                str(row["capacity_snapshot_sha256"])
                == admission.capacity_snapshot_sha256
                and stored_evidence != incoming_evidence
            ):
                raise GdoQueueCapacityConflict(
                    "capacity snapshot digest was reused for different exact evidence"
                )
            if str(row["capacity_pool_id"]) != admission.capacity_pool_id:
                continue
            stored_observed = _parse_utc_z(
                row["capacity_observed_at_utc"], "capacity_observed_at_utc"
            )
            if latest_pool_observed is None or stored_observed > latest_pool_observed:
                latest_pool_observed = stored_observed
            if (
                stored_observed == incoming_observed
                and stored_evidence != incoming_evidence
            ):
                raise GdoQueueCapacityConflict(
                    "capacity pool has conflicting evidence at the same observation time"
                )
        if (
            latest_pool_observed is not None
            and incoming_observed < latest_pool_observed
        ):
            return "CAPACITY_SNAPSHOT_ROLLBACK"
        return ""

    def _slot_blocker_locked(
        self,
        connection: sqlite3.Connection,
        admission: GdoQueueAdmission,
        now: datetime,
        _now_text: str,
    ) -> str:
        observed = _parse_utc_z(
            admission.capacity_observed_at_utc, "capacity_observed_at_utc"
        )
        valid_until = _parse_utc_z(
            admission.capacity_valid_until_utc, "capacity_valid_until_utc"
        )
        if admission.capacity_slots == 0:
            return "CAPACITY_ZERO"
        if observed > now:
            return "CAPACITY_NOT_YET_OBSERVED"
        if valid_until <= now:
            return "CAPACITY_STALE"
        active_global = self._active_wip_locked(connection)
        if active_global >= self.max_wip:
            return "MAX_WIP_REACHED"
        active_pool = self._active_capacity_pool_locked(
            connection, admission.capacity_pool_id
        )
        if active_pool >= admission.capacity_slots:
            return "CAPACITY_SLOTS_EXHAUSTED"
        if self._daily_intake_locked(connection, now) >= self.daily_intake:
            return "DAILY_INTAKE_REACHED"
        return ""

    @staticmethod
    def _command_sha(value: Mapping[str, object]) -> str:
        return value_sha256(dict(value))

    def _idempotent_event_locked(
        self,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        queue_item_id: str,
        event_type: str,
        command_sha256: str,
    ) -> sqlite3.Row | None:
        row = connection.execute(
            "SELECT * FROM gdo_queue_events WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        if (
            str(row["queue_item_id"]) != queue_item_id
            or str(row["event_type"]) != event_type
            or str(row["command_sha256"]) != command_sha256
        ):
            raise GdoQueueIdempotencyConflict(
                "idempotency key was reused for different exact input"
            )
        return row

    def _append_event_locked(
        self,
        connection: sqlite3.Connection,
        *,
        queue_item_id: str,
        event_type: str,
        from_state: str,
        to_state: str,
        reason_code: str,
        actor_id: str,
        occurred_at_utc: str,
        idempotency_key: str,
        command_sha256: str,
        slot_delta: int,
    ) -> tuple[str, str]:
        previous_row = connection.execute(
            """SELECT event_sha256,occurred_at_utc FROM gdo_queue_events
               ORDER BY sequence DESC LIMIT 1"""
        ).fetchone()
        previous = (
            str(previous_row["event_sha256"])
            if previous_row is not None
            else GENESIS_SHA256
        )
        occurred = _parse_utc_z(occurred_at_utc, "occurred_at_utc")
        if previous_row is not None and occurred < _parse_utc_z(
            previous_row["occurred_at_utc"], "occurred_at_utc"
        ):
            raise GdoQueueValidationError("queue event time cannot move backwards")
        event_identity = {
            "queue_item_id": queue_item_id,
            "event_type": event_type,
            "idempotency_key": idempotency_key,
            "command_sha256": command_sha256,
        }
        event_id = f"gdoq-event-{value_sha256(event_identity)[:32]}"
        material: dict[str, object] = {
            "event_id": event_id,
            "queue_item_id": queue_item_id,
            "event_type": event_type,
            "from_state": from_state,
            "to_state": to_state,
            "reason_code": reason_code,
            "actor_id": actor_id,
            "occurred_at_utc": occurred_at_utc,
            "idempotency_key": idempotency_key,
            "command_sha256": command_sha256,
            "slot_delta": slot_delta,
            "previous_event_sha256": previous,
            "mode": MODE,
            "canonical_kpi_eligible": False,
            "external_effect": False,
            "transport_call_count": 0,
        }
        event_sha = value_sha256(material)
        connection.execute(
            """INSERT INTO gdo_queue_events(
                   event_id,queue_item_id,event_type,from_state,to_state,reason_code,
                   actor_id,occurred_at_utc,idempotency_key,command_sha256,slot_delta,
                   previous_event_sha256,event_sha256,mode,canonical_kpi_eligible,
                   external_effect,transport_call_count
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id,
                queue_item_id,
                event_type,
                from_state,
                to_state,
                reason_code,
                actor_id,
                occurred_at_utc,
                idempotency_key,
                command_sha256,
                slot_delta,
                previous,
                event_sha,
                MODE,
                0,
                0,
                0,
            ),
        )
        return event_id, event_sha

    def enqueue(
        self, payload: GdoQueueAdmission | Mapping[str, object]
    ) -> QueueMutation:
        """Atomically admit one exact hot-demand binding or place it on HOLD."""

        admission = (
            payload
            if isinstance(payload, GdoQueueAdmission)
            else GdoQueueAdmission.from_mapping(payload)
        )
        self._validate_admission(admission)
        command_material = admission.material()
        command_sha = self._command_sha(command_material)

        with self._write_transaction() as connection:
            replay = self._idempotent_event_locked(
                connection,
                idempotency_key=admission.idempotency_key,
                queue_item_id=admission.queue_item_id,
                event_type="ADMITTED",
                command_sha256=command_sha,
            )
            if replay is not None:
                row = connection.execute(
                    "SELECT * FROM gdo_queue_items WHERE queue_item_id=?",
                    (admission.queue_item_id,),
                ).fetchone()
                if row is None:
                    raise GdoQueueIntegrityError("replayed admission has no queue item")
                return QueueMutation(
                    "REPLAY",
                    str(replay["event_id"]),
                    str(replay["event_sha256"]),
                    int(replay["slot_delta"]),
                    self._row_to_item(row),
                )

            now, now_text = self._now()
            if _parse_utc_z(admission.deadline_at_utc, "deadline_at_utc") <= now:
                raise GdoQueueValidationError("queue deadline must be in the future")

            duplicate = connection.execute(
                """SELECT queue_item_id,admission_command_sha256
                   FROM gdo_queue_items
                   WHERE queue_item_id=? OR demand_unit_id=? OR gold_acceptance_id=? OR
                         demand_unit_sha256=? OR gold_acceptance_sha256=?""",
                (
                    admission.queue_item_id,
                    admission.demand_unit_id,
                    admission.gold_acceptance_id,
                    admission.demand_unit_sha256,
                    admission.gold_acceptance_sha256,
                ),
            ).fetchone()
            if duplicate is not None:
                raise GdoQueueDuplicateItem(
                    f"queue identity already exists as {duplicate['queue_item_id']}"
                )
            if self._queue_depth_locked(connection) >= self.max_queue_depth:
                raise GdoQueueBackpressure("MAX_QUEUE_DEPTH_REACHED")

            snapshot_blocker = self._capacity_snapshot_blocker_locked(
                connection, admission
            )
            blocker = snapshot_blocker or self._slot_blocker_locked(
                connection, admission, now, now_text
            )
            state = HOLD if blocker else READY
            slot_reserved = 0 if blocker else 1
            reason = blocker or "CAPACITY_RESERVED"
            connection.execute(
                """INSERT INTO gdo_queue_items(
                       queue_item_id,admission_idempotency_key,
                       admission_command_sha256,demand_unit_id,gold_acceptance_id,
                       demand_unit_sha256,gold_acceptance_sha256,scope_sha256,
                       hot_gate_sha256,permit_decision_sha256,
                       capacity_snapshot_sha256,economics_snapshot_sha256,
                       capacity_pool_id,capacity_slots,capacity_observed_at_utc,
                       capacity_valid_until_utc,owner_id,deadline_at_utc,state,
                       hold_reason,slot_reserved,admitted_at_utc,started_at_utc,
                       completed_at_utc,slot_released_at_utc,last_event_id,
                       last_event_sha256,version,mode,canonical_kpi_eligible,
                       external_effect,transport_call_count
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    admission.queue_item_id,
                    admission.idempotency_key,
                    command_sha,
                    admission.demand_unit_id,
                    admission.gold_acceptance_id,
                    admission.demand_unit_sha256,
                    admission.gold_acceptance_sha256,
                    admission.scope_sha256,
                    admission.hot_gate_sha256,
                    admission.permit_decision_sha256,
                    admission.capacity_snapshot_sha256,
                    admission.economics_snapshot_sha256,
                    admission.capacity_pool_id,
                    admission.capacity_slots,
                    admission.capacity_observed_at_utc,
                    admission.capacity_valid_until_utc,
                    admission.owner_id,
                    admission.deadline_at_utc,
                    state,
                    blocker,
                    slot_reserved,
                    now_text,
                    "",
                    "",
                    "",
                    "",
                    "",
                    1,
                    MODE,
                    0,
                    0,
                    0,
                ),
            )
            event_id, event_sha = self._append_event_locked(
                connection,
                queue_item_id=admission.queue_item_id,
                event_type="ADMITTED",
                from_state="",
                to_state=state,
                reason_code=reason,
                actor_id=admission.owner_id,
                occurred_at_utc=now_text,
                idempotency_key=admission.idempotency_key,
                command_sha256=command_sha,
                slot_delta=slot_reserved,
            )
            connection.execute(
                """UPDATE gdo_queue_items
                   SET last_event_id=?,last_event_sha256=?
                   WHERE queue_item_id=?""",
                (event_id, event_sha, admission.queue_item_id),
            )
            row = connection.execute(
                "SELECT * FROM gdo_queue_items WHERE queue_item_id=?",
                (admission.queue_item_id,),
            ).fetchone()
            if row is None:
                raise GdoQueueIntegrityError("admitted queue item disappeared")
            return QueueMutation(
                "APPLIED",
                event_id,
                event_sha,
                slot_reserved,
                self._row_to_item(row),
            )

    def ack(
        self,
        queue_item_id: str,
        *,
        owner_id: str,
        idempotency_key: str,
    ) -> QueueMutation:
        """Acknowledge READY work and move it to IN_PROGRESS."""

        return self.transition(
            queue_item_id,
            target_state=IN_PROGRESS,
            owner_id=owner_id,
            idempotency_key=idempotency_key,
            reason_code="OWNER_ACKNOWLEDGED",
        )

    def transition(
        self,
        queue_item_id: str,
        *,
        target_state: str,
        owner_id: str,
        idempotency_key: str,
        reason_code: str,
    ) -> QueueMutation:
        """Apply one owner transition and release/reserve capacity exactly once."""

        item_id = _safe_token(queue_item_id, "queue_item_id")
        actor = _safe_token(owner_id, "owner_id")
        key = _safe_token(idempotency_key, "idempotency_key")
        reason = _safe_token(reason_code, "reason_code")
        if target_state not in QUEUE_STATES:
            raise GdoQueueValidationError("target_state is invalid")
        if target_state == IN_PROGRESS and reason != "OWNER_ACKNOWLEDGED":
            raise GdoQueueValidationError(
                "IN_PROGRESS requires exact OWNER_ACKNOWLEDGED reason"
            )
        command_material: dict[str, object] = {
            "queue_item_id": item_id,
            "target_state": target_state,
            "owner_id": actor,
            "idempotency_key": key,
            "reason_code": reason,
        }
        command_sha = self._command_sha(command_material)
        event_type = (
            "OWNER_ACKNOWLEDGED" if target_state == IN_PROGRESS else "TRANSITION"
        )

        with self._write_transaction() as connection:
            replay = self._idempotent_event_locked(
                connection,
                idempotency_key=key,
                queue_item_id=item_id,
                event_type=event_type,
                command_sha256=command_sha,
            )
            if replay is not None:
                row = connection.execute(
                    "SELECT * FROM gdo_queue_items WHERE queue_item_id=?", (item_id,)
                ).fetchone()
                if row is None:
                    raise GdoQueueIntegrityError(
                        "replayed transition has no queue item"
                    )
                return QueueMutation(
                    "REPLAY",
                    str(replay["event_id"]),
                    str(replay["event_sha256"]),
                    int(replay["slot_delta"]),
                    self._row_to_item(row),
                )

            now, now_text = self._now()
            row = connection.execute(
                "SELECT * FROM gdo_queue_items WHERE queue_item_id=?", (item_id,)
            ).fetchone()
            if row is None:
                raise GdoQueueTransitionError("queue item does not exist")
            if str(row["owner_id"]) != actor:
                raise GdoQueueTransitionError(
                    "only the exact queue owner may transition"
                )
            current = str(row["state"])
            allowed = {
                READY: {IN_PROGRESS, HOLD},
                IN_PROGRESS: {HOLD, DONE},
                HOLD: {READY},
                DONE: set(),
            }
            if target_state not in allowed[current]:
                raise GdoQueueTransitionError(
                    f"transition {current}->{target_state} is not allowed"
                )

            reserved = bool(row["slot_reserved"])
            slot_delta = 0
            hold_reason = ""
            released_at = str(row["slot_released_at_utc"])
            started_at = str(row["started_at_utc"])
            completed_at = str(row["completed_at_utc"])
            if target_state == READY:
                rebound = GdoQueueAdmission(
                    queue_item_id=item_id,
                    demand_unit_id=str(row["demand_unit_id"]),
                    gold_acceptance_id=str(row["gold_acceptance_id"]),
                    demand_unit_sha256=str(row["demand_unit_sha256"]),
                    gold_acceptance_sha256=str(row["gold_acceptance_sha256"]),
                    scope_sha256=str(row["scope_sha256"]),
                    hot_gate_sha256=str(row["hot_gate_sha256"]),
                    permit_decision_sha256=str(row["permit_decision_sha256"]),
                    capacity_snapshot_sha256=str(row["capacity_snapshot_sha256"]),
                    economics_snapshot_sha256=str(row["economics_snapshot_sha256"]),
                    hot_gate_passed=True,
                    permit_allows_offline_queue=True,
                    capacity_pool_id=str(row["capacity_pool_id"]),
                    capacity_slots=int(row["capacity_slots"]),
                    capacity_observed_at_utc=str(row["capacity_observed_at_utc"]),
                    capacity_valid_until_utc=str(row["capacity_valid_until_utc"]),
                    owner_id=actor,
                    deadline_at_utc=str(row["deadline_at_utc"]),
                    idempotency_key=str(row["admission_idempotency_key"]),
                )
                snapshot_blocker = self._capacity_snapshot_blocker_locked(
                    connection, rebound
                )
                blocker = snapshot_blocker or self._slot_blocker_locked(
                    connection, rebound, now, now_text
                )
                if blocker:
                    raise GdoQueueBackpressure(blocker)
                slot_delta = 1
                reserved = True
                released_at = ""
            elif target_state in {HOLD, DONE} and reserved:
                slot_delta = -1
                reserved = False
                released_at = now_text
            if target_state == HOLD:
                hold_reason = reason
            if target_state == IN_PROGRESS and not started_at:
                started_at = now_text
            if target_state == DONE:
                completed_at = now_text

            event_id, event_sha = self._append_event_locked(
                connection,
                queue_item_id=item_id,
                event_type=event_type,
                from_state=current,
                to_state=target_state,
                reason_code=reason,
                actor_id=actor,
                occurred_at_utc=now_text,
                idempotency_key=key,
                command_sha256=command_sha,
                slot_delta=slot_delta,
            )
            connection.execute(
                """UPDATE gdo_queue_items SET
                       state=?,hold_reason=?,slot_reserved=?,started_at_utc=?,
                       completed_at_utc=?,slot_released_at_utc=?,last_event_id=?,
                       last_event_sha256=?,version=version+1
                   WHERE queue_item_id=?""",
                (
                    target_state,
                    hold_reason,
                    int(reserved),
                    started_at,
                    completed_at,
                    released_at,
                    event_id,
                    event_sha,
                    item_id,
                ),
            )
            current_row = connection.execute(
                "SELECT * FROM gdo_queue_items WHERE queue_item_id=?", (item_id,)
            ).fetchone()
            if current_row is None:
                raise GdoQueueIntegrityError("transitioned queue item disappeared")
            return QueueMutation(
                "APPLIED",
                event_id,
                event_sha,
                slot_delta,
                self._row_to_item(current_row),
            )

    def get(self, queue_item_id: str) -> GdoQueueItem | None:
        item_id = _safe_token(queue_item_id, "queue_item_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._verify_locked(connection)
            row = connection.execute(
                "SELECT * FROM gdo_queue_items WHERE queue_item_id=?", (item_id,)
            ).fetchone()
            connection.commit()
            return None if row is None else self._row_to_item(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def events(self, queue_item_id: str | None = None) -> tuple[dict[str, object], ...]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._verify_locked(connection)
            if queue_item_id is None:
                rows = connection.execute(
                    "SELECT * FROM gdo_queue_events ORDER BY sequence"
                ).fetchall()
            else:
                item_id = _safe_token(queue_item_id, "queue_item_id")
                rows = connection.execute(
                    """SELECT * FROM gdo_queue_events
                       WHERE queue_item_id=? ORDER BY sequence""",
                    (item_id,),
                ).fetchall()
            connection.commit()
            return tuple({key: row[key] for key in row.keys()} for row in rows)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def snapshot(self) -> QueueSnapshot:
        """Return a consistent non-KPI operational queue view."""

        now, now_text = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._verify_locked(connection)
            state_counts = {
                str(row["state"]): int(row["count"])
                for row in connection.execute(
                    "SELECT state,COUNT(*) AS count FROM gdo_queue_items GROUP BY state"
                ).fetchall()
            }
            open_rows = connection.execute(
                """SELECT queue_item_id,admitted_at_utc,deadline_at_utc,hold_reason
                   FROM gdo_queue_items WHERE state!='DONE'
                   ORDER BY admitted_at_utc,queue_item_id"""
            ).fetchall()
            active = self._active_wip_locked(connection)
            daily = self._daily_intake_locked(connection, now)
            active_by_pool = tuple(
                (str(row["capacity_pool_id"]), int(row["count"]))
                for row in connection.execute(
                    """SELECT capacity_pool_id,COUNT(*) AS count
                       FROM gdo_queue_items
                       WHERE state IN ('READY','IN_PROGRESS') AND slot_reserved=1
                       GROUP BY capacity_pool_id ORDER BY capacity_pool_id"""
                ).fetchall()
            )
            ages = [
                max(
                    0,
                    int(
                        (
                            now
                            - _parse_utc_z(row["admitted_at_utc"], "admitted_at_utc")
                        ).total_seconds()
                    ),
                )
                for row in open_rows
            ]
            breach_ids = tuple(
                str(row["queue_item_id"])
                for row in open_rows
                if _parse_utc_z(row["deadline_at_utc"], "deadline_at_utc") <= now
            )
            reasons = {
                str(row["hold_reason"]) for row in open_rows if str(row["hold_reason"])
            }
            if active >= self.max_wip:
                reasons.add("MAX_WIP_REACHED")
            if daily >= self.daily_intake:
                reasons.add("DAILY_INTAKE_REACHED")
            ready = state_counts.get(READY, 0)
            in_progress = state_counts.get(IN_PROGRESS, 0)
            hold = state_counts.get(HOLD, 0)
            done = state_counts.get(DONE, 0)
            depth = ready + in_progress + hold
            if depth >= self.max_queue_depth:
                reasons.add("MAX_QUEUE_DEPTH_REACHED")
            connection.commit()
            return QueueSnapshot(
                as_of_utc=now_text,
                depth=depth,
                ready=ready,
                in_progress=in_progress,
                hold=hold,
                done=done,
                active_wip=active,
                available_wip_slots=max(0, self.max_wip - active),
                max_wip=self.max_wip,
                available_queue_depth=max(0, self.max_queue_depth - depth),
                max_queue_depth=self.max_queue_depth,
                daily_intake_used=daily,
                daily_intake_limit=self.daily_intake,
                business_utc_offset_minutes=self.business_utc_offset_minutes,
                active_by_capacity_pool=active_by_pool,
                oldest_open_age_seconds=max(ages, default=0),
                sla_breaches=len(breach_ids),
                sla_breach_item_ids=breach_ids,
                backpressure=bool(reasons),
                backpressure_reasons=tuple(sorted(reasons)),
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


__all__ = [
    "DONE",
    "ENVIRONMENT",
    "GdoQueueAdmission",
    "GdoQueueBackpressure",
    "GdoQueueCapacityConflict",
    "GdoQueueDuplicateItem",
    "GdoQueueError",
    "GdoQueueIdempotencyConflict",
    "GdoQueueIntegrityError",
    "GdoQueueItem",
    "GdoQueueMetadataTamper",
    "GdoQueueStore",
    "GdoQueueTransitionError",
    "GdoQueueValidationError",
    "HOLD",
    "IN_PROGRESS",
    "MODE",
    "QueueMutation",
    "QueueSnapshot",
    "READY",
    "CANONICAL_SCHEMA_FINGERPRINT_SHA256",
    "DEFAULT_BUSINESS_UTC_OFFSET_MINUTES",
    "DEFAULT_MAX_QUEUE_DEPTH",
]
