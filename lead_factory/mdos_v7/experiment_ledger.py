"""Immutable offline evidence ledger for hypotheses and bounded experiments.

The ledger is deliberately *not* an execution engine.  It has no default
database path, clock, network transport, environment lookup, credential
handling, or authority grant.  Every stored record is permanently classified
as ``OFFLINE_SHADOW`` and ``NON_KPI`` and carries an exact zero-effect
attestation.

This is a small, generic substrate: domain layers may add stricter transition,
budget, capacity, privacy, or causal-analysis policy before calling it.  The
recursive payload-key denylist below is only a fail-closed guard against common
accidental PII/private/raw material; it is not a substitute for data
classification or privacy review.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
import json
import math
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any

from .contracts import canonical_json_bytes, value_sha256


SCHEMA_VERSION = 1
APPLICATION_ID = 0x45585031  # ``EXP1`` -- not an authority or release marker.
EXECUTION_MODE = "OFFLINE_SHADOW"
EVIDENCE_CLASS = "NON_KPI"
ZERO_EFFECTS = MappingProxyType(
    {
        "external_read_count": 0,
        "external_write_count": 0,
        "contact_count": 0,
        "message_count": 0,
        "publication_count": 0,
        "spend_minor": 0,
        "live_bitrix_write_count": 0,
        "transport_call_count": 0,
    }
)

MAX_PAYLOAD_BYTES = 256 * 1024
MAX_STRING_LENGTH = 32 * 1024
MAX_CONTAINER_ITEMS = 10_000
MAX_NESTING_DEPTH = 32

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDEMPOTENCY_RE = re.compile(
    r"^(?=.{1,255}$)(?=.*[A-Za-z])[A-Za-z0-9][A-Za-z0-9_.:/\-]*$"
)
_KEY_PART_RE = re.compile(r"[^a-z0-9]+")


class ExperimentLedgerError(RuntimeError):
    """Base class for fail-closed experiment-ledger errors."""


class LedgerValidationError(ExperimentLedgerError, ValueError):
    """A proposed record is unsafe or not canonical JSON data."""


class LedgerIntegrityError(ExperimentLedgerError):
    """Stored bytes, dependencies, event chain, or schema do not verify."""


class IdempotencyConflict(ExperimentLedgerError):
    """An idempotency key was reused for different canonical content."""


class SemanticDuplicate(ExperimentLedgerError):
    """Canonical content already exists under another idempotency identity."""

    def __init__(self, existing_record_id: str) -> None:
        self.existing_record_id = existing_record_id
        super().__init__(
            "semantic content already exists under a different idempotency key: "
            f"{existing_record_id}"
        )


class MissingDependency(LedgerValidationError):
    """A dependency is absent or its exact digest does not match."""


class LedgerRecordType(str, Enum):
    CAPABILITY = "CAPABILITY"
    MANDATE = "MANDATE"
    HYPOTHESIS = "HYPOTHESIS"
    TREATMENT = "TREATMENT"
    PLAN = "PLAN"
    ASSIGNMENT = "ASSIGNMENT"
    OUTCOME = "OUTCOME"
    ANALYSIS = "ANALYSIS"
    DECISION = "DECISION"


# Direct typed edges required by the generic experiment grammar.  These are
# deliberately capability/vendor neutral.  Domain layers remain free to add
# cardinality and scope rules, but may not weaken these minimum predecessors.
DEPENDENCY_POLICY: Mapping[LedgerRecordType, frozenset[LedgerRecordType]] = (
    MappingProxyType(
        {
            LedgerRecordType.TREATMENT: frozenset({LedgerRecordType.HYPOTHESIS}),
            LedgerRecordType.PLAN: frozenset(
                {
                    LedgerRecordType.CAPABILITY,
                    LedgerRecordType.MANDATE,
                    LedgerRecordType.HYPOTHESIS,
                    LedgerRecordType.TREATMENT,
                }
            ),
            LedgerRecordType.ASSIGNMENT: frozenset(
                {LedgerRecordType.PLAN, LedgerRecordType.TREATMENT}
            ),
            LedgerRecordType.OUTCOME: frozenset({LedgerRecordType.ASSIGNMENT}),
            LedgerRecordType.ANALYSIS: frozenset(
                {LedgerRecordType.PLAN, LedgerRecordType.OUTCOME}
            ),
            LedgerRecordType.DECISION: frozenset({LedgerRecordType.ANALYSIS}),
        }
    )
)


@dataclass(frozen=True)
class DependencyRef:
    record_id: str
    record_sha256: str

    @property
    def content_sha256(self) -> str:
        """Compatibility alias for callers that call the record hash content."""

        return self.record_sha256


@dataclass(frozen=True)
class LedgerRecord:
    sequence: int
    record_id: str
    record_type: LedgerRecordType
    record_sha256: str
    idempotency_key: str
    payload: Mapping[str, Any]
    dependencies: tuple[DependencyRef, ...]
    execution_mode: str = EXECUTION_MODE
    evidence_class: str = EVIDENCE_CLASS
    external_effects: Mapping[str, int] = field(default_factory=lambda: ZERO_EFFECTS)
    inserted: bool = True

    @property
    def content_sha256(self) -> str:
        return self.record_sha256


@dataclass(frozen=True)
class LedgerEvent:
    sequence: int
    event_id: str
    event_type: str
    record_id: str
    record_sha256: str
    previous_event_sha256: str
    event_sha256: str


@dataclass(frozen=True)
class LedgerVerification:
    schema_inventory_sha256: str
    record_count: int
    dependency_count: int
    event_count: int
    head_event_sha256: str
    semantic_sha256: str


@dataclass(frozen=True)
class LedgerSnapshot:
    execution_mode: str
    evidence_class: str
    external_effects: Mapping[str, int]
    records: tuple[LedgerRecord, ...]
    events: tuple[LedgerEvent, ...]
    snapshot_sha256: str


def _normalize_sql(sql: str) -> str:
    return " ".join(sql.strip().rstrip(";").split())


_TABLE_STATEMENTS: tuple[tuple[str, str, str], ...] = (
    (
        "table",
        "experiment_ledger_meta",
        """CREATE TABLE experiment_ledger_meta (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               schema_version INTEGER NOT NULL CHECK (schema_version = 1),
               schema_inventory_sha256 TEXT NOT NULL CHECK (length(schema_inventory_sha256) = 64),
               execution_mode TEXT NOT NULL CHECK (execution_mode = 'OFFLINE_SHADOW'),
               evidence_class TEXT NOT NULL CHECK (evidence_class = 'NON_KPI'),
               external_effects_json TEXT NOT NULL
           )""",
    ),
    (
        "table",
        "experiment_records",
        """CREATE TABLE experiment_records (
               sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
               record_id TEXT NOT NULL UNIQUE,
               record_type TEXT NOT NULL CHECK (record_type IN (
                   'CAPABILITY','MANDATE','HYPOTHESIS','TREATMENT','PLAN',
                   'ASSIGNMENT','OUTCOME','ANALYSIS','DECISION'
               )),
               record_sha256 TEXT NOT NULL UNIQUE CHECK (length(record_sha256) = 64),
               idempotency_key TEXT NOT NULL UNIQUE,
               request_sha256 TEXT NOT NULL UNIQUE CHECK (length(request_sha256) = 64),
               idempotency_binding_sha256 TEXT NOT NULL CHECK (length(idempotency_binding_sha256) = 64),
               payload_json TEXT NOT NULL,
               dependency_manifest_json TEXT NOT NULL,
               execution_mode TEXT NOT NULL CHECK (execution_mode = 'OFFLINE_SHADOW'),
               evidence_class TEXT NOT NULL CHECK (evidence_class = 'NON_KPI'),
               external_effects_json TEXT NOT NULL
           )""",
    ),
    (
        "table",
        "experiment_dependencies",
        """CREATE TABLE experiment_dependencies (
               child_record_id TEXT NOT NULL,
               ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
               parent_record_id TEXT NOT NULL,
               parent_record_sha256 TEXT NOT NULL CHECK (length(parent_record_sha256) = 64),
               PRIMARY KEY (child_record_id, ordinal),
               UNIQUE (child_record_id, parent_record_id),
               FOREIGN KEY (child_record_id) REFERENCES experiment_records(record_id),
               FOREIGN KEY (parent_record_id) REFERENCES experiment_records(record_id)
           )""",
    ),
    (
        "table",
        "experiment_events",
        """CREATE TABLE experiment_events (
               sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
               event_id TEXT NOT NULL UNIQUE,
               event_type TEXT NOT NULL CHECK (event_type = 'RECORD_APPENDED'),
               record_id TEXT NOT NULL UNIQUE,
               record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
               previous_event_sha256 TEXT NOT NULL CHECK (length(previous_event_sha256) = 64),
               event_sha256 TEXT NOT NULL UNIQUE CHECK (length(event_sha256) = 64),
               FOREIGN KEY (record_id) REFERENCES experiment_records(record_id)
           )""",
    ),
)


def _immutable_triggers() -> tuple[tuple[str, str, str], ...]:
    objects: list[tuple[str, str, str]] = []
    for table in (
        "experiment_ledger_meta",
        "experiment_records",
        "experiment_dependencies",
        "experiment_events",
    ):
        for action in ("UPDATE", "DELETE"):
            name = f"{table}_no_{action.lower()}"
            sql = f"""CREATE TRIGGER {name}
                      BEFORE {action} ON {table}
                      BEGIN
                          SELECT RAISE(ABORT, '{table} is append-only');
                      END"""
            objects.append(("trigger", name, sql))
    return tuple(objects)


_GUARD_TRIGGERS: tuple[tuple[str, str, str], ...] = (
    (
        "trigger",
        "experiment_records_contiguous_insert",
        """CREATE TRIGGER experiment_records_contiguous_insert
           BEFORE INSERT ON experiment_records
           BEGIN
               SELECT CASE WHEN NEW.sequence !=
                   COALESCE((SELECT MAX(sequence) + 1 FROM experiment_records), 1)
               THEN RAISE(ABORT, 'experiment_records sequence is not contiguous') END;
           END""",
    ),
    (
        "trigger",
        "experiment_events_chain_insert",
        """CREATE TRIGGER experiment_events_chain_insert
           BEFORE INSERT ON experiment_events
           BEGIN
               SELECT CASE WHEN NEW.sequence !=
                   COALESCE((SELECT MAX(sequence) + 1 FROM experiment_events), 1)
               THEN RAISE(ABORT, 'experiment_events sequence is not contiguous') END;
               SELECT CASE WHEN NEW.previous_event_sha256 !=
                   COALESCE((SELECT event_sha256 FROM experiment_events
                             ORDER BY sequence DESC LIMIT 1),
                            '0000000000000000000000000000000000000000000000000000000000000000')
               THEN RAISE(ABORT, 'experiment_events previous digest mismatch') END;
               SELECT CASE WHEN NOT EXISTS (
                   SELECT 1 FROM experiment_records r
                   WHERE r.sequence = NEW.sequence
                     AND r.record_id = NEW.record_id
                     AND r.record_sha256 = NEW.record_sha256
               ) THEN RAISE(ABORT, 'experiment_events record binding mismatch') END;
           END""",
    ),
)

_SCHEMA_OBJECTS = _TABLE_STATEMENTS + _immutable_triggers() + _GUARD_TRIGGERS


def _expected_inventory() -> list[dict[str, str]]:
    table_by_object = {
        name: name for kind, name, _sql in _TABLE_STATEMENTS if kind == "table"
    }
    values: list[dict[str, str]] = []
    for kind, name, sql in _SCHEMA_OBJECTS:
        if kind == "trigger":
            match = re.search(r"\bON\s+([A-Za-z0-9_]+)", sql, re.IGNORECASE)
            if match is None:
                raise RuntimeError(f"cannot resolve trigger table for {name}")
            table_name = match.group(1)
        else:
            table_name = table_by_object[name]
        values.append(
            {
                "type": kind,
                "name": name,
                "table": table_name,
                "sql": _normalize_sql(sql),
            }
        )
    return sorted(values, key=lambda item: (item["type"], item["name"]))


EXPECTED_SCHEMA_INVENTORY = tuple(
    MappingProxyType(item) for item in _expected_inventory()
)
SCHEMA_INVENTORY_SHA256 = value_sha256(
    [dict(item) for item in EXPECTED_SCHEMA_INVENTORY]
)
_ZERO_EFFECTS_JSON = canonical_json_bytes(dict(ZERO_EFFECTS)).decode("utf-8")
_ZERO_SHA256 = "0" * 64


_FORBIDDEN_EXACT_KEYS = {
    "address",
    "api_key",
    "authorization",
    "bank_account",
    "body",
    "chat_text",
    "contact_name",
    "credential",
    "credentials",
    "customer_name",
    "email",
    "first_name",
    "full_name",
    "inn",
    "last_name",
    "message_body",
    "middle_name",
    "name",
    "passport",
    "password",
    "personal_data",
    "person_name",
    "phone",
    "private_data",
    "raw",
    "raw_body",
    "raw_data",
    "raw_payload",
    "secret",
    "session_cookie",
    "snils",
    "surname",
    "tax_id",
    "token",
    "username",
}
_FORBIDDEN_KEY_PARTS = {
    "apikey",
    "credential",
    "email",
    "passport",
    "password",
    "phone",
    "pii",
    "private",
    "raw",
    "secret",
    "token",
}
_AUTHORITY_CLAIM_PARTS = {
    "authority",
    "authorized",
    "enable",
    "enabled",
    "executable",
    "grant",
    "granted",
    "live",
}
_EXACT_OFFLINE_CEILING_KEYS = {
    "auto_live",
    "auto_scale",
    "authority_granted",
    "external_authority_granted",
    "live_enabled",
    "permit_granted",
    "release_eligible",
}
_EFFECT_KEY_PARTS = {
    "contact",
    "effect",
    "externalread",
    "externalwrite",
    "message",
    "publication",
    "spend",
    "transportcall",
    "write",
}
_PLANNING_PARTS = {
    "budget",
    "cap",
    "limit",
    "max",
    "maximum",
    "planned",
    "proposed",
    "requested",
    "target",
}


def _key_parts(key: str) -> tuple[str, ...]:
    return tuple(part for part in _KEY_PART_RE.split(key.casefold()) if part)


def _truthy_authority_claim(value: object) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    if type(value) in (int, float):
        return value != 0
    if isinstance(value, str):
        return value.strip().casefold() not in {
            "",
            "0",
            "false",
            "no",
            "none",
            "null",
            "deny",
            "denied",
            "disabled",
            "offline",
            "offline_shadow",
            "shadow",
        }
    return value != [] and value != {}


def _validate_payload_tree(value: object, *, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise LedgerValidationError("payload nesting exceeds the offline ledger limit")
    if value is None or isinstance(value, bool) or type(value) is int:
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LedgerValidationError(f"{path} contains a non-finite number")
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise LedgerValidationError(
                f"{path} string exceeds the offline ledger limit"
            )
        if value.casefold().startswith("private:"):
            raise LedgerValidationError(f"{path} contains a private reference")
        encoded_candidate: object = value.strip()
        for decode_depth in range(MAX_NESTING_DEPTH + 1):
            if not isinstance(encoded_candidate, str):
                break
            stripped = encoded_candidate.strip()
            try:
                decoded = json.loads(stripped)
            except (json.JSONDecodeError, RecursionError):
                break
            if isinstance(decoded, (dict, list)):
                raise LedgerValidationError(
                    f"{path} contains an encoded JSON container; "
                    "store structured data so the recursive guard can inspect it"
                )
            if not isinstance(decoded, str) or decoded == encoded_candidate:
                break
            if decode_depth == MAX_NESTING_DEPTH:
                raise LedgerValidationError(
                    f"{path} exceeds the encoded JSON inspection depth"
                )
            encoded_candidate = decoded
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise LedgerValidationError(f"{path} has too many members")
        for raw_key, item in value.items():
            if not isinstance(raw_key, str) or not raw_key:
                raise LedgerValidationError(f"{path} keys must be non-empty strings")
            key = raw_key.casefold()
            parts = _key_parts(raw_key)
            collapsed = "".join(parts)
            if (
                key in _FORBIDDEN_EXACT_KEYS
                or key.startswith(("raw_", "private_", "pii_"))
                or key.endswith(("_email", "_phone", "_password", "_secret", "_token"))
                or any(part in _FORBIDDEN_KEY_PARTS for part in parts)
            ):
                raise LedgerValidationError(
                    f"{path}.{raw_key} is a forbidden private/raw key"
                )
            if key in {"external_effects", "effect_attestation", "evidence_class"}:
                raise LedgerValidationError(
                    f"{path}.{raw_key} is reserved for the ledger assurance envelope"
                )
            # Approval provenance and declarative fields such as
            # ``approved_by`` or ``allowed_effect_classes`` are legitimate
            # offline evidence.  Only an actual authority/live/release claim
            # is forbidden here; effect-specific booleans/counters are guarded
            # independently below.
            authority_claim = key in _EXACT_OFFLINE_CEILING_KEYS or bool(
                set(parts) & _AUTHORITY_CLAIM_PARTS
            )
            if authority_claim and _truthy_authority_claim(item):
                raise LedgerValidationError(
                    f"{path}.{raw_key} cannot grant or claim external authority"
                )
            if (
                any(part in collapsed for part in _EFFECT_KEY_PARTS)
                and not bool(set(parts) & _PLANNING_PARTS)
                and (isinstance(item, bool) or type(item) in (int, float))
            ):
                if (
                    isinstance(item, bool)
                    or type(item) not in (int, float)
                    or item != 0
                ):
                    raise LedgerValidationError(
                        f"{path}.{raw_key} must be the numeric zero in offline shadow"
                    )
            if key in {"mode", "execution_mode", "run_mode"} and (
                not isinstance(item, str)
                or item.casefold() not in {"offline", "shadow", "offline_shadow"}
            ):
                raise LedgerValidationError(
                    f"{path}.{raw_key} must remain offline shadow"
                )
            if "kpi" in parts and "eligible" in parts and _truthy_authority_claim(item):
                raise LedgerValidationError(
                    f"{path}.{raw_key} cannot claim KPI eligibility"
                )
            _validate_payload_tree(item, path=f"{path}.{raw_key}", depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise LedgerValidationError(f"{path} has too many items")
        for index, item in enumerate(value):
            _validate_payload_tree(item, path=f"{path}[{index}]", depth=depth + 1)
        return
    raise LedgerValidationError(f"{path} contains unsupported non-JSON data")


def _canonical_payload(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    if not isinstance(payload, Mapping):
        raise LedgerValidationError("payload must be a mapping")
    # A JSON round trip both detaches caller-owned mutable objects and rejects
    # custom mappings/scalars that the canonical contract cannot represent.
    _validate_payload_tree(payload)
    try:
        encoded = canonical_json_bytes(payload)
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise LedgerValidationError("payload exceeds the offline ledger byte limit")
        decoded = json.loads(encoded.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise LedgerValidationError("payload is not canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise LedgerValidationError("payload must canonicalize to an object")
    return decoded, encoded.decode("utf-8")


def _record_type(value: LedgerRecordType | str) -> LedgerRecordType:
    try:
        return value if isinstance(value, LedgerRecordType) else LedgerRecordType(value)
    except (TypeError, ValueError) as exc:
        raise LedgerValidationError(
            f"unsupported ledger record type: {value!r}"
        ) from exc


def _dependency_ref(value: object) -> DependencyRef:
    if isinstance(value, LedgerRecord):
        return DependencyRef(value.record_id, value.record_sha256)
    if isinstance(value, DependencyRef):
        return value
    if isinstance(value, Mapping):
        digest = value.get("record_sha256", value.get("content_sha256"))
        return DependencyRef(str(value.get("record_id", "")), str(digest or ""))
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return DependencyRef(str(value[0]), str(value[1]))
    raise LedgerValidationError(
        "dependency must contain exact record_id and record_sha256"
    )


def _normalize_dependencies(values: Iterable[object]) -> tuple[DependencyRef, ...]:
    dependencies = sorted(
        (_dependency_ref(value) for value in values),
        key=lambda value: (value.record_id, value.record_sha256),
    )
    seen: set[str] = set()
    for dependency in dependencies:
        if not dependency.record_id or not _SHA256_RE.fullmatch(
            dependency.record_sha256
        ):
            raise LedgerValidationError("dependency contains an invalid id or digest")
        if dependency.record_id in seen:
            raise LedgerValidationError("duplicate dependency record_id")
        seen.add(dependency.record_id)
    return tuple(dependencies)


def _record_material(
    record_type: LedgerRecordType,
    payload: Mapping[str, Any],
    dependencies: tuple[DependencyRef, ...],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": record_type.value,
        "payload": dict(payload),
        "dependencies": [
            {
                "record_id": dependency.record_id,
                "record_sha256": dependency.record_sha256,
            }
            for dependency in dependencies
        ],
        "execution_mode": EXECUTION_MODE,
        "evidence_class": EVIDENCE_CLASS,
        "external_effects": dict(ZERO_EFFECTS),
    }


def _request_sha256(
    record_type: LedgerRecordType,
    payload: Mapping[str, Any],
    dependencies: tuple[DependencyRef, ...],
) -> str:
    """Hash semantic input without the operation's idempotency key."""

    return value_sha256(_record_material(record_type, payload, dependencies))


def _idempotency_binding_sha256(
    idempotency_key: str, record_id: str, record_sha256: str
) -> str:
    return value_sha256(
        {
            "idempotency_key": idempotency_key,
            "record_id": record_id,
            "record_sha256": record_sha256,
        }
    )


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _missing_dependency_types(
    record_type: LedgerRecordType,
    parent_types: set[LedgerRecordType],
) -> tuple[LedgerRecordType, ...]:
    required = DEPENDENCY_POLICY.get(record_type, frozenset())
    return tuple(sorted(required - parent_types, key=lambda item: item.value))


def _actual_inventory(connection: sqlite3.Connection) -> list[dict[str, str]]:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','trigger','index','view')
           ORDER BY type,name"""
    ).fetchall()
    return [
        {
            "type": str(row[0]),
            "name": str(row[1]),
            "table": str(row[2]),
            "sql": _normalize_sql(str(row[3] or "")),
        }
        for row in rows
    ]


class ExperimentLedger:
    """Caller-scoped SQLite ledger with verified reads and atomic appends."""

    def __init__(self, path: str | Path) -> None:
        if path is None:
            raise LedgerValidationError(
                "an explicit caller-supplied database path is required"
            )
        raw_path = Path(path)
        if str(raw_path) in {"", "."} or raw_path.name in {"", ".", ".."}:
            raise LedgerValidationError("database path must name an explicit file")
        self.path = raw_path.resolve()
        if not self.path.parent.is_dir():
            raise LedgerValidationError("database parent directory must already exist")
        self._bootstrap()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path), timeout=30, isolation_level=None, check_same_thread=False
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _verify_schema_tx(connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
            raise LedgerIntegrityError("experiment ledger application_id drift")
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise LedgerIntegrityError("experiment ledger schema version drift")
        actual = _actual_inventory(connection)
        expected = [dict(item) for item in EXPECTED_SCHEMA_INVENTORY]
        if actual != expected or value_sha256(actual) != SCHEMA_INVENTORY_SHA256:
            raise LedgerIntegrityError("experiment ledger schema inventory drift")

    @staticmethod
    def _verify_meta_tx(connection: sqlite3.Connection) -> None:
        rows = connection.execute("SELECT * FROM experiment_ledger_meta").fetchall()
        if len(rows) != 1:
            raise LedgerIntegrityError(
                "experiment ledger must have one pinned meta row"
            )
        row = rows[0]
        if (
            row["singleton"] != 1
            or row["schema_version"] != SCHEMA_VERSION
            or row["schema_inventory_sha256"] != SCHEMA_INVENTORY_SHA256
            or row["execution_mode"] != EXECUTION_MODE
            or row["evidence_class"] != EVIDENCE_CLASS
            or row["external_effects_json"] != _ZERO_EFFECTS_JSON
        ):
            raise LedgerIntegrityError("experiment ledger pinned metadata drift")

    def _bootstrap(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            inventory = _actual_inventory(connection)
            if not inventory:
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                for _kind, _name, sql in _SCHEMA_OBJECTS:
                    connection.execute(sql)
                connection.execute(
                    """INSERT INTO experiment_ledger_meta(
                           singleton,schema_version,schema_inventory_sha256,
                           execution_mode,evidence_class,external_effects_json
                       ) VALUES(1,?,?,?,?,?)""",
                    (
                        SCHEMA_VERSION,
                        SCHEMA_INVENTORY_SHA256,
                        EXECUTION_MODE,
                        EVIDENCE_CLASS,
                        _ZERO_EFFECTS_JSON,
                    ),
                )
            self._verify_schema_tx(connection)
            self._verify_meta_tx(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _row_to_record(
        row: sqlite3.Row,
        dependencies: tuple[DependencyRef, ...],
        *,
        inserted: bool,
    ) -> LedgerRecord:
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise LedgerIntegrityError("stored record payload is invalid JSON") from exc
        return LedgerRecord(
            sequence=int(row["sequence"]),
            record_id=str(row["record_id"]),
            record_type=LedgerRecordType(str(row["record_type"])),
            record_sha256=str(row["record_sha256"]),
            idempotency_key=str(row["idempotency_key"]),
            payload=_deep_freeze(payload),
            dependencies=dependencies,
            inserted=inserted,
        )

    @staticmethod
    def _dependencies_for_tx(
        connection: sqlite3.Connection, record_id: str
    ) -> tuple[DependencyRef, ...]:
        rows = connection.execute(
            """SELECT parent_record_id,parent_record_sha256
               FROM experiment_dependencies
               WHERE child_record_id=? ORDER BY ordinal""",
            (record_id,),
        ).fetchall()
        return tuple(DependencyRef(str(row[0]), str(row[1])) for row in rows)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> LedgerEvent:
        return LedgerEvent(
            sequence=int(row["sequence"]),
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            record_id=str(row["record_id"]),
            record_sha256=str(row["record_sha256"]),
            previous_event_sha256=str(row["previous_event_sha256"]),
            event_sha256=str(row["event_sha256"]),
        )

    @staticmethod
    def _verify_all_tx(connection: sqlite3.Connection) -> LedgerVerification:
        ExperimentLedger._verify_schema_tx(connection)
        ExperimentLedger._verify_meta_tx(connection)
        check = connection.execute("PRAGMA integrity_check").fetchall()
        if len(check) != 1 or str(check[0][0]).casefold() != "ok":
            raise LedgerIntegrityError("SQLite integrity_check failed")

        record_rows = connection.execute(
            "SELECT * FROM experiment_records ORDER BY sequence"
        ).fetchall()
        dependency_rows = connection.execute(
            """SELECT child_record_id,ordinal,parent_record_id,parent_record_sha256
               FROM experiment_dependencies ORDER BY child_record_id,ordinal"""
        ).fetchall()
        event_rows = connection.execute(
            "SELECT * FROM experiment_events ORDER BY sequence"
        ).fetchall()
        if len(record_rows) != len(event_rows):
            raise LedgerIntegrityError(
                "each experiment record must have exactly one event"
            )

        record_by_id = {str(row["record_id"]): row for row in record_rows}
        deps_by_child: dict[str, list[sqlite3.Row]] = {}
        for row in dependency_rows:
            deps_by_child.setdefault(str(row["child_record_id"]), []).append(row)

        semantic_records: list[dict[str, Any]] = []
        for expected_sequence, row in enumerate(record_rows, 1):
            if int(row["sequence"]) != expected_sequence:
                raise LedgerIntegrityError(
                    "experiment record sequence is not contiguous"
                )
            try:
                record_type = LedgerRecordType(str(row["record_type"]))
                payload = json.loads(str(row["payload_json"]))
                manifest = json.loads(str(row["dependency_manifest_json"]))
                effects = json.loads(str(row["external_effects_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LedgerIntegrityError(
                    "stored experiment record is not canonical JSON"
                ) from exc
            if (
                canonical_json_bytes(payload).decode("utf-8") != row["payload_json"]
                or canonical_json_bytes(manifest).decode("utf-8")
                != row["dependency_manifest_json"]
                or canonical_json_bytes(effects).decode("utf-8")
                != row["external_effects_json"]
                or effects != dict(ZERO_EFFECTS)
                or row["execution_mode"] != EXECUTION_MODE
                or row["evidence_class"] != EVIDENCE_CLASS
            ):
                raise LedgerIntegrityError(
                    "stored record classification or canonical bytes drift"
                )
            try:
                _canonical_payload(payload)
            except LedgerValidationError as exc:
                raise LedgerIntegrityError(
                    "stored record violates payload safety guard"
                ) from exc

            dependency_rows_for_record = deps_by_child.get(str(row["record_id"]), [])
            actual_manifest = [
                {
                    "record_id": str(dep["parent_record_id"]),
                    "record_sha256": str(dep["parent_record_sha256"]),
                }
                for dep in dependency_rows_for_record
            ]
            if (
                [int(dep["ordinal"]) for dep in dependency_rows_for_record]
                != list(range(len(dependency_rows_for_record)))
                or actual_manifest != manifest
                or actual_manifest
                != sorted(
                    actual_manifest,
                    key=lambda item: (item["record_id"], item["record_sha256"]),
                )
            ):
                raise LedgerIntegrityError("dependency manifest and rows differ")
            dependencies = tuple(
                DependencyRef(item["record_id"], item["record_sha256"])
                for item in actual_manifest
            )
            for dependency in dependencies:
                parent = record_by_id.get(dependency.record_id)
                if (
                    parent is None
                    or str(parent["record_sha256"]) != dependency.record_sha256
                    or int(parent["sequence"]) >= expected_sequence
                ):
                    raise LedgerIntegrityError(
                        "dependency is absent, changed, or not prior"
                    )
            parent_types = {
                LedgerRecordType(str(record_by_id[dependency.record_id]["record_type"]))
                for dependency in dependencies
            }
            missing_types = _missing_dependency_types(record_type, parent_types)
            if missing_types:
                raise LedgerIntegrityError(
                    f"stored {record_type.value} lacks required direct dependency types: "
                    + ",".join(item.value for item in missing_types)
                )

            idempotency_key = str(row["idempotency_key"])
            expected_sha = _request_sha256(record_type, payload, dependencies)
            expected_id = f"experiment-{record_type.value.casefold()}-{expected_sha}"
            expected_request_sha = expected_sha
            expected_binding_sha = _idempotency_binding_sha256(
                idempotency_key, expected_id, expected_sha
            )
            if (
                row["record_sha256"] != expected_sha
                or row["record_id"] != expected_id
                or row["request_sha256"] != expected_request_sha
                or row["idempotency_binding_sha256"] != expected_binding_sha
            ):
                raise LedgerIntegrityError("experiment record content address mismatch")
            semantic_records.append(
                {
                    "sequence": expected_sequence,
                    "record_id": expected_id,
                    "record_sha256": expected_sha,
                }
            )

        previous_sha = _ZERO_SHA256
        semantic_events: list[dict[str, Any]] = []
        for expected_sequence, row in enumerate(event_rows, 1):
            record = record_rows[expected_sequence - 1]
            base = {
                "sequence": expected_sequence,
                "event_type": "RECORD_APPENDED",
                "record_id": str(record["record_id"]),
                "record_sha256": str(record["record_sha256"]),
                "previous_event_sha256": previous_sha,
            }
            expected_event_id = f"experiment-event-{value_sha256(base)}"
            expected_event_sha = value_sha256({"event_id": expected_event_id, **base})
            if (
                int(row["sequence"]) != expected_sequence
                or row["event_type"] != "RECORD_APPENDED"
                or row["record_id"] != record["record_id"]
                or row["record_sha256"] != record["record_sha256"]
                or row["previous_event_sha256"] != previous_sha
                or row["event_id"] != expected_event_id
                or row["event_sha256"] != expected_event_sha
            ):
                raise LedgerIntegrityError("experiment event chain mismatch")
            semantic_events.append(
                {
                    "sequence": expected_sequence,
                    **base,
                    "event_id": expected_event_id,
                    "event_sha256": expected_event_sha,
                }
            )
            previous_sha = expected_event_sha

        semantic_sha = value_sha256(
            {
                "schema_inventory_sha256": SCHEMA_INVENTORY_SHA256,
                "records": semantic_records,
                "events": semantic_events,
            }
        )
        return LedgerVerification(
            schema_inventory_sha256=SCHEMA_INVENTORY_SHA256,
            record_count=len(record_rows),
            dependency_count=len(dependency_rows),
            event_count=len(event_rows),
            head_event_sha256=previous_sha,
            semantic_sha256=semantic_sha,
        )

    def append(
        self,
        record_type: LedgerRecordType | str,
        payload: Mapping[str, Any],
        *,
        dependencies: Iterable[object] = (),
        idempotency_key: str,
    ) -> LedgerRecord:
        """Atomically append one content-addressed offline evidence record."""

        kind = _record_type(record_type)
        if (
            not isinstance(idempotency_key, str)
            or _SAFE_IDEMPOTENCY_RE.fullmatch(idempotency_key) is None
        ):
            raise LedgerValidationError(
                "idempotency_key must be an explicit safe opaque token"
            )
        safe_payload, payload_json = _canonical_payload(payload)
        refs = _normalize_dependencies(dependencies)
        dependency_manifest = [
            {"record_id": ref.record_id, "record_sha256": ref.record_sha256}
            for ref in refs
        ]
        dependency_json = canonical_json_bytes(dependency_manifest).decode("utf-8")
        request_sha = _request_sha256(kind, safe_payload, refs)
        record_sha = request_sha
        record_id = f"experiment-{kind.value.casefold()}-{record_sha}"
        binding_sha = _idempotency_binding_sha256(
            idempotency_key, record_id, record_sha
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_all_tx(connection)
            existing = connection.execute(
                "SELECT * FROM experiment_records WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["request_sha256"]) != request_sha
                    or str(existing["record_sha256"]) != record_sha
                    or str(existing["record_id"]) != record_id
                ):
                    raise IdempotencyConflict(
                        "idempotency key was already bound to different canonical content"
                    )
                existing_refs = self._dependencies_for_tx(connection, record_id)
                result = self._row_to_record(existing, existing_refs, inserted=False)
                connection.commit()
                return result

            semantic_existing = connection.execute(
                "SELECT * FROM experiment_records WHERE request_sha256=?",
                (request_sha,),
            ).fetchone()
            if semantic_existing is not None:
                existing_record_id = str(semantic_existing["record_id"])
                raise SemanticDuplicate(existing_record_id)

            parent_types: set[LedgerRecordType] = set()
            for ref in refs:
                dependency = connection.execute(
                    """SELECT sequence,record_sha256,record_type
                       FROM experiment_records WHERE record_id=?""",
                    (ref.record_id,),
                ).fetchone()
                if dependency is None:
                    raise MissingDependency(f"missing dependency {ref.record_id}")
                if str(dependency["record_sha256"]) != ref.record_sha256:
                    raise MissingDependency(
                        f"dependency digest mismatch for {ref.record_id}"
                    )
                parent_types.add(LedgerRecordType(str(dependency["record_type"])))
            missing_types = _missing_dependency_types(kind, parent_types)
            if missing_types:
                raise MissingDependency(
                    f"{kind.value} requires exact direct dependency types: "
                    + ",".join(item.value for item in missing_types)
                )

            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM experiment_records"
                ).fetchone()[0]
            )
            connection.execute(
                """INSERT INTO experiment_records(
                       sequence,record_id,record_type,record_sha256,idempotency_key,
                       request_sha256,idempotency_binding_sha256,payload_json,
                       dependency_manifest_json,
                       execution_mode,evidence_class,external_effects_json
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sequence,
                    record_id,
                    kind.value,
                    record_sha,
                    idempotency_key,
                    request_sha,
                    binding_sha,
                    payload_json,
                    dependency_json,
                    EXECUTION_MODE,
                    EVIDENCE_CLASS,
                    _ZERO_EFFECTS_JSON,
                ),
            )
            for ordinal, ref in enumerate(refs):
                connection.execute(
                    """INSERT INTO experiment_dependencies(
                           child_record_id,ordinal,parent_record_id,parent_record_sha256
                       ) VALUES(?,?,?,?)""",
                    (record_id, ordinal, ref.record_id, ref.record_sha256),
                )
            previous_sha = str(
                connection.execute(
                    """SELECT COALESCE(
                           (SELECT event_sha256 FROM experiment_events
                            ORDER BY sequence DESC LIMIT 1), ?
                       )""",
                    (_ZERO_SHA256,),
                ).fetchone()[0]
            )
            event_base = {
                "sequence": sequence,
                "event_type": "RECORD_APPENDED",
                "record_id": record_id,
                "record_sha256": record_sha,
                "previous_event_sha256": previous_sha,
            }
            event_id = f"experiment-event-{value_sha256(event_base)}"
            event_sha = value_sha256({"event_id": event_id, **event_base})
            connection.execute(
                """INSERT INTO experiment_events(
                       sequence,event_id,event_type,record_id,record_sha256,
                       previous_event_sha256,event_sha256
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    sequence,
                    event_id,
                    "RECORD_APPENDED",
                    record_id,
                    record_sha,
                    previous_sha,
                    event_sha,
                ),
            )
            self._verify_all_tx(connection)
            row = connection.execute(
                "SELECT * FROM experiment_records WHERE record_id=?", (record_id,)
            ).fetchone()
            if row is None:  # pragma: no cover - guarded by the same transaction.
                raise LedgerIntegrityError("new record vanished before commit")
            result = self._row_to_record(row, refs, inserted=True)
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _verified_read(self) -> tuple[sqlite3.Connection, LedgerVerification]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            verification = self._verify_all_tx(connection)
            return connection, verification
        except Exception:
            connection.rollback()
            connection.close()
            raise

    def get(self, record_id: str) -> LedgerRecord | None:
        connection, _verification = self._verified_read()
        try:
            row = connection.execute(
                "SELECT * FROM experiment_records WHERE record_id=?", (record_id,)
            ).fetchone()
            if row is None:
                return None
            refs = self._dependencies_for_tx(connection, str(row["record_id"]))
            return self._row_to_record(row, refs, inserted=False)
        finally:
            connection.rollback()
            connection.close()

    def list(
        self, record_type: LedgerRecordType | str | None = None
    ) -> tuple[LedgerRecord, ...]:
        kind = _record_type(record_type) if record_type is not None else None
        connection, _verification = self._verified_read()
        try:
            if kind is None:
                rows = connection.execute(
                    "SELECT * FROM experiment_records ORDER BY sequence"
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT * FROM experiment_records
                       WHERE record_type=? ORDER BY sequence""",
                    (kind.value,),
                ).fetchall()
            return tuple(
                self._row_to_record(
                    row,
                    self._dependencies_for_tx(connection, str(row["record_id"])),
                    inserted=False,
                )
                for row in rows
            )
        finally:
            connection.rollback()
            connection.close()

    def events(self) -> tuple[LedgerEvent, ...]:
        connection, _verification = self._verified_read()
        try:
            rows = connection.execute(
                "SELECT * FROM experiment_events ORDER BY sequence"
            ).fetchall()
            return tuple(self._row_to_event(row) for row in rows)
        finally:
            connection.rollback()
            connection.close()

    def snapshot(self) -> LedgerSnapshot:
        connection, verification = self._verified_read()
        try:
            rows = connection.execute(
                "SELECT * FROM experiment_records ORDER BY sequence"
            ).fetchall()
            records = tuple(
                self._row_to_record(
                    row,
                    self._dependencies_for_tx(connection, str(row["record_id"])),
                    inserted=False,
                )
                for row in rows
            )
            event_rows = connection.execute(
                "SELECT * FROM experiment_events ORDER BY sequence"
            ).fetchall()
            events = tuple(self._row_to_event(row) for row in event_rows)
            material = {
                "execution_mode": EXECUTION_MODE,
                "evidence_class": EVIDENCE_CLASS,
                "external_effects": dict(ZERO_EFFECTS),
                "semantic_sha256": verification.semantic_sha256,
                "record_ids": [record.record_id for record in records],
                "event_sha256s": [event.event_sha256 for event in events],
            }
            return LedgerSnapshot(
                execution_mode=EXECUTION_MODE,
                evidence_class=EVIDENCE_CLASS,
                external_effects=ZERO_EFFECTS,
                records=records,
                events=events,
                snapshot_sha256=value_sha256(material),
            )
        finally:
            connection.rollback()
            connection.close()

    def verify(self) -> LedgerVerification:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            return self._verify_all_tx(connection)
        finally:
            connection.rollback()
            connection.close()


__all__ = [
    "APPLICATION_ID",
    "DEPENDENCY_POLICY",
    "EVIDENCE_CLASS",
    "EXECUTION_MODE",
    "EXPECTED_SCHEMA_INVENTORY",
    "ExperimentLedger",
    "ExperimentLedgerError",
    "IdempotencyConflict",
    "LedgerEvent",
    "LedgerIntegrityError",
    "LedgerRecord",
    "LedgerRecordType",
    "LedgerSnapshot",
    "LedgerValidationError",
    "LedgerVerification",
    "MissingDependency",
    "SCHEMA_INVENTORY_SHA256",
    "SCHEMA_VERSION",
    "SemanticDuplicate",
    "ZERO_EFFECTS",
    "DependencyRef",
]
