"""Append-only SQLite substrate for the MDOS v7.1 G0/G1 shadow slice."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .authority import CONTRACT_ID, PACKAGE_ROOT_SHA256, PACKAGE_VERSION, authority_snapshot
from .contracts import ContractRegistry
from .internal_contracts import INTERNAL_SCHEMAS, InternalContractRegistry


SCHEMA_VERSION = 1
APPLICATION_ID = 0x4D444F53  # "MDOS"
MIGRATION_NAME = "001_g0_g1.sql"
MIGRATION_SHA256 = "35528aa18a554889de76fa90e042a670c52ceec611258b6d76bcad5e3a8007cb"
ZERO_SHA256 = "0" * 64
KERNEL_ACTOR_ID = "mdos-assurance-kernel"

HUMAN_ONLY_ROLES = frozenset(
    {
        "GOLD_REVIEWER",
        "POLICY_AUTHORITY",
        "ORDER_APPROVER",
        "PAYMENT_VERIFIER",
        "FULFILMENT_WRITER",
        "CONSENT_AUTHORITY",
        "PROMISE_AUTHORITY",
        "INDEPENDENT_EVIDENCE_VERIFIER",
        "CONFLICT_ARBITRATOR",
    }
)

ROLE_ACTOR_TYPES: Mapping[str, frozenset[str]] = {
    "ASSURANCE_KERNEL": frozenset({"SYSTEM"}),
    "SOURCE_ADAPTER": frozenset({"SYSTEM"}),
    "CLAIM_PRODUCER": frozenset({"SYSTEM", "AI"}),
    "CLAIM_REVIEWER": frozenset({"HUMAN"}),
    "IDENTITY_STEWARD": frozenset({"HUMAN"}),
    "DATA_STEWARD": frozenset({"HUMAN", "SYSTEM"}),
    "DEMAND_STEWARD": frozenset({"HUMAN", "SYSTEM"}),
    "GOLD_REVIEWER": frozenset({"HUMAN"}),
    "POLICY_AUTHORITY": frozenset({"HUMAN"}),
    "SALES_OPERATOR": frozenset({"HUMAN"}),
    "ORDER_APPROVER": frozenset({"HUMAN"}),
    "BANK_ADAPTER": frozenset({"SYSTEM"}),
    "PAYMENT_VERIFIER": frozenset({"HUMAN"}),
    "FULFILMENT_WRITER": frozenset({"HUMAN"}),
    "RECONCILER": frozenset({"SYSTEM"}),
    "BITRIX_PROJECTION_WRITER": frozenset({"SYSTEM"}),
    "CONFLICT_ARBITRATOR": frozenset({"HUMAN"}),
    "CONSENT_AUTHORITY": frozenset({"HUMAN"}),
    "CONTACT_POLICY_GATE": frozenset({"SYSTEM"}),
}

# The caller may select among the explicitly allowed transition roles, but may
# never weaken a canonical record type to a generic writer role.
RECORD_WRITE_ROLES: Mapping[str, frozenset[str]] = {
    "FixtureObservation": frozenset({"SOURCE_ADAPTER"}),
    "SIGNAL_OBSERVATION": frozenset({"SOURCE_ADAPTER"}),
    "CLAIM": frozenset({"CLAIM_PRODUCER", "CLAIM_REVIEWER"}),
    "ENTITY_RESOLUTION_DECISION": frozenset({"IDENTITY_STEWARD"}),
    "CAPACITY_SNAPSHOT": frozenset({"DATA_STEWARD"}),
    "ECONOMICS_SNAPSHOT": frozenset({"DATA_STEWARD"}),
    "DENOMINATOR_SNAPSHOT": frozenset({"DATA_STEWARD"}),
    "EVIDENCE_BUNDLE": frozenset({"DATA_STEWARD"}),
    "HUMAN_GOLD_REVIEW": frozenset({"GOLD_REVIEWER"}),
    "DEMAND_UNIT": frozenset({"DEMAND_STEWARD", "GOLD_REVIEWER"}),
    "PERMIT_DECISION": frozenset({"POLICY_AUTHORITY"}),
    "GOLD_ACCEPTANCE": frozenset({"GOLD_REVIEWER"}),
    "ACTION_ASSIGNMENT": frozenset({"SALES_OPERATOR"}),
    "COMMERCIAL_TERMS": frozenset({"ORDER_APPROVER"}),
    "ORDER_RECORD": frozenset(
        {"ORDER_APPROVER", "PAYMENT_VERIFIER", "FULFILMENT_WRITER"}
    ),
    "RAW_PAYMENT_OBSERVATION": frozenset({"BANK_ADAPTER"}),
    "RAW_FULFILMENT_DOCUMENT": frozenset({"FULFILMENT_WRITER"}),
    "PAYMENT_PROOF": frozenset({"PAYMENT_VERIFIER"}),
    "FULFILMENT_RECORD": frozenset({"FULFILMENT_WRITER"}),
    "OUTCOME_EVENT": frozenset({"RECONCILER"}),
    "CRM_OUTCOME_CLAIM": frozenset({"RECONCILER"}),
    "RECONCILIATION_RESULT": frozenset({"RECONCILER"}),
    "CONFLICT_RESOLUTION": frozenset({"CONFLICT_ARBITRATOR"}),
    "LEGAL_POLICY_SNAPSHOT": frozenset({"CONSENT_AUTHORITY"}),
    "CONSENT_RECORD": frozenset({"CONSENT_AUTHORITY"}),
    "SUPPRESSION_TOMBSTONE": frozenset({"CONSENT_AUTHORITY"}),
    "CONTACT_AUTHORIZATION_DECISION": frozenset({"CONTACT_POLICY_GATE"}),
    "BITRIX_PROJECTION_COMMAND": frozenset({"BITRIX_PROJECTION_WRITER"}),
    "BITRIX_PROJECTION_CLAIM": frozenset({"BITRIX_PROJECTION_WRITER"}),
    "BITRIX_PROJECTION_ATTEMPT": frozenset({"BITRIX_PROJECTION_WRITER"}),
    "BITRIX_PROJECTION_RECEIPT": frozenset({"BITRIX_PROJECTION_WRITER"}),
    "BITRIX_PROJECTION_DLQ": frozenset({"BITRIX_PROJECTION_WRITER"}),
}

RECORD_SCHEMAS: Mapping[str, str] = {
    "SIGNAL_OBSERVATION": "signal-observation.schema.json",
    "CLAIM": "claim.schema.json",
    "ENTITY_RESOLUTION_DECISION": "entity-resolution-decision.schema.json",
    "DEMAND_UNIT": "demand-unit.schema.json",
    "PERMIT_DECISION": "permit-decision.schema.json",
    "GOLD_ACCEPTANCE": "gold-acceptance.schema.json",
    "ACTION_ASSIGNMENT": "action-assignment.schema.json",
    "ORDER_RECORD": "order-record.schema.json",
    "PAYMENT_PROOF": "payment-proof.schema.json",
    "FULFILMENT_RECORD": "fulfilment-record.schema.json",
    "OUTCOME_EVENT": "outcome-event.schema.json",
}

INTERNAL_RECORD_TYPES = frozenset(RECORD_WRITE_ROLES).difference(RECORD_SCHEMAS).difference(
    {"FixtureObservation"}
)
PROTECTED_RECORD_TYPES = frozenset(RECORD_WRITE_ROLES).difference({"FixtureObservation"})
EVIDENCE_WRITE_ROLES = frozenset({"SOURCE_ADAPTER", "BANK_ADAPTER", "FULFILMENT_WRITER"})

CRM_SHADOW_SOURCE_SYSTEM = "BITRIX24_SHADOW_FIXTURE"
CRM_SHADOW_READ_MODEL_STATUS = "CONTRACT_SIGNED_AWAITING_PAYMENT"
CRM_SHADOW_MAPPING_ID = "fixture:bitrix24-contract-signed:v1"
CRM_SHADOW_PORTAL_FINGERPRINT_SHA256 = (
    "e5fb7f6c132453c6b3c7a6a7295c9e0e2c858db71222bd058b85cfa0d1eaae64"
)
CRM_SHADOW_REMOTE_CATEGORY_ID = "bx-category-6e8348147dfdc323"
CRM_SHADOW_REMOTE_PIPELINE_ID = "bx-pipeline-523cefc27a4cc922"
CRM_SHADOW_REMOTE_STAGE_ID = "bx-stage-d1c1c4b39e436acd"
CRM_SHADOW_STAGE_MAPPING_VERSION = "delivery-local-fixture-v1"
CRM_SHADOW_STAGE_MAPPING_SHA256 = (
    "a89475c5baa2261ff8fc813db4ee8f9434f86b6d0b7172882086bf8010dc56f8"
)
CRM_SHADOW_MAPPING_REGISTRY_SHA256 = (
    "a9e7f9e051d46602ef67a3bd061cdd10260e426fde485795d8d46c77abb9d8f3"
)
CRM_REAL_MAPPING_STATE = "UNKNOWN_BLOCKED"
CRM_SHADOW_ARTIFACT_FIELDS = (
    "source_system",
    "portal_fingerprint_sha256",
    "remote_entity_type",
    "remote_entity_id",
    "remote_version",
    "remote_category_id",
    "remote_pipeline_id",
    "remote_stage_id",
    "stage_mapping_id",
    "stage_mapping_version",
    "stage_mapping_sha256",
    "stage_mapping_registry_sha256",
    "real_mapping_state",
    "semantic_milestone",
    "demand_unit_id",
    "account_id",
    "distinct_order_id",
    "authoritative_class",
    "observed_at",
    "reconciliation_state",
    "payment_proof_ref",
)


class MdosStoreError(RuntimeError):
    """Base error for the isolated v7 store."""


class SchemaIntegrityError(MdosStoreError):
    """The database or migration does not match the supported schema."""


class UnknownWriterError(MdosStoreError):
    """A writer is absent from the immutable registry."""


class WriterRoleError(MdosStoreError):
    """A registered actor lacks the required role or actor type."""


class IdempotencyConflict(MdosStoreError):
    """One idempotency key was reused for a different business effect."""


class AppendOnlyViolation(MdosStoreError):
    """An aggregate revision skipped or rewrote immutable history."""


class BackupIntegrityError(MdosStoreError):
    """A backup or restored candidate failed verification."""


class _ClosingConnection(sqlite3.Connection):
    """Make ``with store._connect()`` close Windows file handles on exit."""

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, tb))
        finally:
            self.close()


@dataclass(frozen=True)
class ActorSpec:
    actor_type: str
    roles: tuple[str, ...]
    registered_at_utc: str = "2026-08-25T00:00:00Z"


@dataclass(frozen=True)
class AppendResult:
    entry_id: str
    entry_sha256: str
    sequence: int
    inserted: bool
    disposition: str


@dataclass(frozen=True)
class EvidenceResult:
    content_sha256: str
    inserted: bool


@dataclass(frozen=True)
class PaymentTransitionCommit:
    """Atomic results for one authoritative synthetic payment installment."""

    payment: AppendResult
    order: AppendResult
    outcome: AppendResult | None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _require_utc_z(value: str, label: str) -> str:
    text = str(value or "")
    if not text.endswith("Z"):
        raise ValueError(f"{label} must be RFC3339 UTC with Z")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be RFC3339 UTC with Z") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be UTC")
    return text


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def value_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8", "strict")).hexdigest()


def crm_shadow_stage_mapping_sha256(value: Mapping[str, Any]) -> str:
    """Digest the exact local mapping that turns one CRM stage into a milestone."""

    return value_sha256(
        {
            "schema_version": "1.0.0",
            "source_system": value.get("source_system"),
            "portal_fingerprint_sha256": value.get("portal_fingerprint_sha256"),
            "remote_category_id": value.get("remote_category_id"),
            "remote_pipeline_id": value.get("remote_pipeline_id"),
            "remote_stage_id": value.get("remote_stage_id"),
            "mapping_id": value.get("stage_mapping_id"),
            "stage_mapping_version": value.get("stage_mapping_version"),
            "semantic_milestone": value.get("semantic_milestone"),
        }
    )


def crm_shadow_source_artifact(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the strict evidence envelope bound to a persisted CRM claim."""

    return {field: value.get(field) for field in CRM_SHADOW_ARTIFACT_FIELDS}


def crm_shadow_claim_aggregate_id(value: Mapping[str, Any]) -> str:
    """Stable local identity for one remote deal inside an exact Bitrix lane."""

    identity = {
        "source_system": value.get("source_system"),
        "portal_fingerprint_sha256": value.get("portal_fingerprint_sha256"),
        "remote_entity_type": value.get("remote_entity_type"),
        "remote_entity_id": value.get("remote_entity_id"),
        "remote_category_id": value.get("remote_category_id"),
        "remote_pipeline_id": value.get("remote_pipeline_id"),
    }
    return f"crm-outcome-claim-{value_sha256(identity)[:32]}"


def crm_shadow_claim_idempotency_key(value: Mapping[str, Any]) -> str:
    aggregate_id = crm_shadow_claim_aggregate_id(value)
    return f"crm-outcome-claim:{aggregate_id}:{int(value.get('remote_version', 0))}"


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_actor_registry(
    actor_registry: Mapping[str, ActorSpec | Mapping[str, Any]],
) -> list[dict[str, Any]]:
    values: dict[str, ActorSpec | Mapping[str, Any]] = dict(actor_registry)
    values.setdefault(
        KERNEL_ACTOR_ID,
        ActorSpec(
            actor_type="SYSTEM",
            roles=("ASSURANCE_KERNEL", "LEDGER_WRITER", "MIGRATOR", "RECONCILER"),
        ),
    )
    normalized: list[dict[str, Any]] = []
    for actor_id in sorted(values):
        if not actor_id or actor_id.strip() != actor_id:
            raise ValueError("actor_id must be a non-empty canonical string")
        raw = values[actor_id]
        if isinstance(raw, ActorSpec):
            actor_type = raw.actor_type
            roles = raw.roles
            registered_at = raw.registered_at_utc
        else:
            actor_type = str(raw.get("actor_type", ""))
            roles = tuple(str(role) for role in raw.get("roles", ()))
            registered_at = str(raw.get("registered_at_utc", "2026-08-25T00:00:00Z"))
        actor_type = actor_type.upper()
        if actor_type not in {"HUMAN", "SYSTEM", "AI"}:
            raise ValueError(f"unsupported actor type for {actor_id}")
        canonical_roles = tuple(sorted({role.strip().upper() for role in roles if role.strip()}))
        if not canonical_roles:
            raise ValueError(f"actor {actor_id} has no roles")
        if actor_type != "HUMAN" and HUMAN_ONLY_ROLES.intersection(canonical_roles):
            raise ValueError(f"actor {actor_id} cannot hold human-only roles")
        for role in canonical_roles:
            allowed_actor_types = ROLE_ACTOR_TYPES.get(role)
            if allowed_actor_types is not None and actor_type not in allowed_actor_types:
                raise ValueError(f"actor {actor_id} type is not allowed for role {role}")
        registered_at = _require_utc_z(registered_at, f"{actor_id}.registered_at_utc")
        material = {
            "actor_id": actor_id,
            "actor_type": actor_type,
            "roles": list(canonical_roles),
            "registered_at_utc": registered_at,
        }
        normalized.append({**material, "registry_entry_sha256": value_sha256(material)})
    return normalized


class MdosStore:
    """A fresh bounded-context database; it never migrates the legacy v6 DB."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        actor_registry: Mapping[str, ActorSpec | Mapping[str, Any]] | None = None,
    ) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.__domain_write_capability = object()
        self.__payment_transition_capability = object()
        self.__crm_claim_transition_capability = object()
        self.contracts = ContractRegistry(Path(__file__).resolve().parents[2])
        self.internal_contracts = InternalContractRegistry()
        new_database = not self.path.exists() or self.path.stat().st_size == 0
        if new_database and actor_registry is None:
            raise SchemaIntegrityError("a fresh MDOS store requires an explicit actor registry")
        if new_database:
            self._bootstrap(actor_registry or {})
        else:
            self._validate_existing(actor_registry)

    @property
    def _migration_path(self) -> Path:
        return Path(__file__).with_name("migrations") / MIGRATION_NAME

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=30,
            isolation_level=None,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
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

    @staticmethod
    def _schema_fingerprint(connection: sqlite3.Connection) -> str:
        rows = connection.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%'
               ORDER BY type,name"""
        ).fetchall()
        values = [
            {
                "type": str(row[0]),
                "name": str(row[1]),
                "table": str(row[2]),
                "sql": " ".join(str(row[3] or "").split()),
            }
            for row in rows
        ]
        return value_sha256(values)

    def _bootstrap(self, actor_registry: Mapping[str, ActorSpec | Mapping[str, Any]]) -> None:
        sql_bytes = self._migration_path.read_bytes()
        if bytes_sha256(sql_bytes) != MIGRATION_SHA256:
            raise SchemaIntegrityError("MDOS migration checksum drift")
        actors = _normalize_actor_registry(actor_registry)
        registry_digest = value_sha256(actors)
        connection = self._connect()
        try:
            existing = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1"
            ).fetchone()
            if existing:
                raise SchemaIntegrityError("refusing to bootstrap a non-empty unmanaged database")
            connection.executescript(sql_bytes.decode("utf-8", "strict"))
            connection.execute("BEGIN IMMEDIATE")
            for actor in actors:
                connection.execute(
                    """INSERT INTO mdos_actor_registry(
                           actor_id,actor_type,roles_json,registered_at_utc,registry_entry_sha256
                       ) VALUES(?,?,?,?,?)""",
                    (
                        actor["actor_id"],
                        actor["actor_type"],
                        canonical_json(actor["roles"]),
                        actor["registered_at_utc"],
                        actor["registry_entry_sha256"],
                    ),
                )
            schema_fingerprint = self._schema_fingerprint(connection)
            metadata = {
                "schema_version": str(SCHEMA_VERSION),
                "contract_id": CONTRACT_ID,
                "package_version": PACKAGE_VERSION,
                "package_root_sha256": PACKAGE_ROOT_SHA256,
                "environment": "FIXTURE_SHADOW",
                "canonical_kpi_eligible": "0",
                "external_effects_enabled": "0",
                "active_beachhead_profile": "",
                "actor_registry_sha256": registry_digest,
                "schema_fingerprint_sha256": schema_fingerprint,
            }
            connection.executemany(
                "INSERT INTO mdos_meta(key,value) VALUES(?,?)", sorted(metadata.items())
            )
            connection.execute(
                """INSERT INTO mdos_schema_migrations(
                       version,name,sql_sha256,applied_at_utc,applied_by
                   ) VALUES(?,?,?,?,?)""",
                (SCHEMA_VERSION, MIGRATION_NAME, MIGRATION_SHA256, _utc_now(), KERNEL_ACTOR_ID),
            )
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.commit()
        except Exception:
            connection.rollback()
            connection.close()
            try:
                if self.path.exists():
                    self.path.unlink()
            except OSError:
                pass
            raise
        finally:
            try:
                connection.close()
            except Exception:
                pass
        self.verify_integrity()

    def _validate_existing(
        self,
        actor_registry: Mapping[str, ActorSpec | Mapping[str, Any]] | None,
    ) -> None:
        summary = self.verify_integrity()
        if actor_registry is not None:
            expected = value_sha256(_normalize_actor_registry(actor_registry))
            if summary["actor_registry_sha256"] != expected:
                raise SchemaIntegrityError("actor registry differs from the immutable store registry")

    @staticmethod
    def _actor_row(connection: sqlite3.Connection, actor_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT actor_id,actor_type,roles_json FROM mdos_actor_registry WHERE actor_id=?",
            (actor_id,),
        ).fetchone()

    def _require_actor_tx(
        self,
        connection: sqlite3.Connection,
        actor_id: str,
        required_role: str,
    ) -> sqlite3.Row:
        row = self._actor_row(connection, actor_id)
        if row is None:
            raise UnknownWriterError(f"unknown writer: {actor_id}")
        roles = set(json.loads(str(row["roles_json"])))
        canonical_role = str(required_role or "LEDGER_WRITER").upper()
        if canonical_role not in roles:
            raise WriterRoleError(f"writer {actor_id} lacks role {canonical_role}")
        actor_type = str(row["actor_type"])
        allowed_actor_types = ROLE_ACTOR_TYPES.get(canonical_role)
        if allowed_actor_types is not None and actor_type not in allowed_actor_types:
            raise WriterRoleError(
                f"writer {actor_id} type cannot exercise role {canonical_role}"
            )
        return row

    def require_actor(self, actor_id: str, required_role: str) -> dict[str, Any]:
        """Return a checked immutable actor grant for a domain boundary."""

        with self._connect() as connection:
            row = self._require_actor_tx(connection, actor_id, required_role)
            return {
                "actor_id": str(row["actor_id"]),
                "actor_type": str(row["actor_type"]),
                "roles": tuple(json.loads(str(row["roles_json"]))),
            }

    @staticmethod
    def _payload_tx(
        connection: sqlite3.Connection,
        record_type: str,
        aggregate_id: str,
        version: int | None = None,
    ) -> dict[str, Any] | None:
        if version is None:
            row = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type=? AND aggregate_id=?
                   ORDER BY aggregate_version DESC LIMIT 1""",
                (record_type, aggregate_id),
            ).fetchone()
        else:
            row = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type=? AND aggregate_id=? AND aggregate_version=?""",
                (record_type, aggregate_id, int(version)),
            ).fetchone()
        return json.loads(str(row[0])) if row is not None else None

    @staticmethod
    def _payload_as_of_tx(
        connection: sqlite3.Connection,
        record_type: str,
        aggregate_id: str,
        as_of_sequence: int,
        version: int | None = None,
    ) -> dict[str, Any] | None:
        if version is None:
            row = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type=? AND aggregate_id=? AND sequence<=?
                   ORDER BY aggregate_version DESC LIMIT 1""",
                (record_type, aggregate_id, int(as_of_sequence)),
            ).fetchone()
        else:
            row = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type=? AND aggregate_id=? AND aggregate_version=?
                     AND sequence<=?""",
                (record_type, aggregate_id, int(version), int(as_of_sequence)),
            ).fetchone()
        return json.loads(str(row[0])) if row is not None else None

    @staticmethod
    def _amount(value: object, label: str) -> Decimal:
        try:
            amount = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise SchemaIntegrityError(f"{label} is not an exact decimal amount") from exc
        if not amount.is_finite():
            raise SchemaIntegrityError(f"{label} is not a finite amount")
        return amount

    @staticmethod
    def _utc_instant(value: object, label: str) -> datetime:
        text = str(value or "")
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SchemaIntegrityError(f"{label} is not a valid UTC instant") from exc
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise SchemaIntegrityError(f"{label} is not UTC")
        return parsed

    @staticmethod
    def _payment_rows_tx(
        connection: sqlite3.Connection,
        distinct_order_id: str,
        as_of_sequence: int,
    ) -> list[tuple[int, dict[str, Any]]]:
        rows = connection.execute(
            """SELECT sequence,payload_json FROM mdos_ledger
               WHERE record_type='PAYMENT_PROOF'
                 AND json_extract(payload_json,'$.distinct_order_id')=?
                 AND sequence<=?
               ORDER BY sequence""",
            (distinct_order_id, int(as_of_sequence)),
        ).fetchall()
        return [(int(row[0]), json.loads(str(row[1]))) for row in rows]

    def _payment_terms_tx(
        self,
        connection: sqlite3.Connection,
        distinct_order_id: str,
        as_of_sequence: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        order = self._payload_as_of_tx(
            connection,
            "ORDER_RECORD",
            distinct_order_id,
            as_of_sequence,
            1,
        )
        if order is None or order.get("state") != "APPROVED":
            raise SchemaIntegrityError("payment transition has no approved OrderRecord")
        terms = self._payload_as_of_tx(
            connection,
            "COMMERCIAL_TERMS",
            str(order.get("commercial_terms_ref", "")),
            as_of_sequence,
            1,
        )
        if terms is None:
            raise SchemaIntegrityError("payment transition has no commercial terms")
        return order, terms

    def _settled_amount_tx(
        self,
        connection: sqlite3.Connection,
        distinct_order_id: str,
        as_of_sequence: int,
    ) -> tuple[Decimal, list[tuple[int, dict[str, Any]]], dict[str, Any], dict[str, Any]]:
        order, terms = self._payment_terms_tx(
            connection, distinct_order_id, as_of_sequence
        )
        rows = self._payment_rows_tx(connection, distinct_order_id, as_of_sequence)
        currency = str(terms.get("currency", ""))
        account_id = str(order.get("account_id", ""))
        total = Decimal("0")
        provider_events: set[tuple[str, str]] = set()
        for _, proof in rows:
            event_key = (
                str(proof.get("provider", "")),
                str(proof.get("provider_event_id", "")),
            )
            if event_key in provider_events:
                raise SchemaIntegrityError("duplicate reconciled PaymentProof provider event")
            provider_events.add(event_key)
            if (
                proof.get("currency") != currency
                or proof.get("canonical_account_id") != account_id
                or proof.get("reconciliation_state") != "RECONCILED"
            ):
                raise SchemaIntegrityError("PaymentProof set differs from order terms")
            total += self._amount(proof.get("amount"), "PaymentProof amount")
        return total, rows, order, terms

    def _accepted_demand_sources_tx(
        self,
        connection: sqlite3.Connection,
        demand_unit_id: str,
        as_of_sequence: int,
    ) -> tuple[dict[str, Any], set[str]]:
        demand = self._payload_as_of_tx(
            connection,
            "DEMAND_UNIT",
            demand_unit_id,
            as_of_sequence,
            2,
        )
        if demand is None or demand.get("state") != "ACCEPTED_GDO":
            raise SchemaIntegrityError("commercial outcome has no accepted DemandUnit")
        source_event_ids: set[str] = set()
        claim_ids = tuple(str(item) for item in demand.get("evidence_claim_ids", []))
        for claim_id in claim_ids:
            claim = self._payload_as_of_tx(
                connection,
                "CLAIM",
                claim_id,
                as_of_sequence,
            )
            source_event_id = str(claim.get("source_event_id", "")) if claim else ""
            signal = self._payload_as_of_tx(
                connection,
                "SIGNAL_OBSERVATION",
                source_event_id,
                as_of_sequence,
            )
            if claim is None or claim.get("status") != "ACCEPTED" or signal is None:
                raise SchemaIntegrityError(
                    "commercial outcome demand provenance is not accepted and sequence-bounded"
                )
            source_event_ids.add(source_event_id)
        if not source_event_ids:
            raise SchemaIntegrityError("commercial outcome demand has no accepted source signal")
        return demand, source_event_ids

    @staticmethod
    def _payment_transition_sequences_tx(connection: sqlite3.Connection) -> set[int]:
        """Reconstruct atomic payment batches from immutable ledger order."""

        rows = connection.execute(
            """SELECT sequence,record_type,trace_id,payload_json
               FROM mdos_ledger ORDER BY sequence"""
        ).fetchall()
        contexts: set[int] = set()
        for index, row in enumerate(rows):
            if str(row["record_type"]) != "PAYMENT_PROOF":
                continue
            payment = json.loads(str(row["payload_json"]))
            if index + 1 >= len(rows):
                raise SchemaIntegrityError("orphan PaymentProof outside an atomic transition")
            order_row = rows[index + 1]
            order = json.loads(str(order_row["payload_json"]))
            if (
                str(order_row["record_type"]) != "ORDER_RECORD"
                or str(order_row["trace_id"]) != str(row["trace_id"])
                or order.get("distinct_order_id") != payment.get("distinct_order_id")
                or order.get("state") not in {"PAID_PARTIAL", "PAID"}
            ):
                raise SchemaIntegrityError("PaymentProof is not followed by its order transition")
            contexts.update({int(row["sequence"]), int(order_row["sequence"])})
            if order.get("state") == "PAID":
                if index + 2 >= len(rows):
                    raise SchemaIntegrityError("terminal payment lacks CLEARED_PAYMENT")
                outcome_row = rows[index + 2]
                outcome = json.loads(str(outcome_row["payload_json"]))
                if (
                    str(outcome_row["record_type"]) != "OUTCOME_EVENT"
                    or str(outcome_row["trace_id"]) != str(row["trace_id"])
                    or outcome.get("outcome_type") != "CLEARED_PAYMENT"
                    or outcome.get("distinct_order_id") != payment.get("distinct_order_id")
                    or outcome.get("payment_proof_ref") != payment.get("payment_proof_id")
                ):
                    raise SchemaIntegrityError("terminal payment outcome is not atomically bound")
                contexts.add(int(outcome_row["sequence"]))

        for row in rows:
            payload = json.loads(str(row["payload_json"]))
            requires_context = (
                str(row["record_type"]) == "PAYMENT_PROOF"
                or (
                    str(row["record_type"]) == "ORDER_RECORD"
                    and payload.get("state") in {"PAID_PARTIAL", "PAID"}
                )
                or (
                    str(row["record_type"]) == "OUTCOME_EVENT"
                    and payload.get("outcome_type") == "CLEARED_PAYMENT"
                )
            )
            if requires_context and int(row["sequence"]) not in contexts:
                raise SchemaIntegrityError("payment truth exists outside an atomic transition")
        return contexts

    @staticmethod
    def _crm_claim_transition_sequences_tx(connection: sqlite3.Connection) -> set[int]:
        """Reconstruct claims emitted only by the typed local CRM intake."""

        rows = connection.execute(
            """SELECT sequence,entry_id,record_type,idempotency_key,payload_sha256,
                      writer_id,trace_id,recorded_at_utc
               FROM mdos_ledger WHERE record_type='CRM_OUTCOME_CLAIM'
               ORDER BY sequence"""
        ).fetchall()
        contexts: set[int] = set()
        for row in rows:
            receipts = connection.execute(
                """SELECT * FROM mdos_delivery_receipts
                   WHERE business_entry_id=? AND disposition='APPLIED'""",
                (str(row["entry_id"]),),
            ).fetchall()
            exact = [
                receipt
                for receipt in receipts
                if str(receipt["idempotency_key"]) == str(row["idempotency_key"])
                and str(receipt["record_type"]) == "CRM_OUTCOME_CLAIM"
                and str(receipt["proposed_payload_sha256"])
                == str(row["payload_sha256"])
                and str(receipt["attempted_actor_id"]) == str(row["writer_id"])
                and str(receipt["trace_id"]) == str(row["trace_id"])
                and str(receipt["recorded_at_utc"]) == str(row["recorded_at_utc"])
            ]
            if len(exact) != 1:
                raise SchemaIntegrityError(
                    "CRM_OUTCOME_CLAIM lacks its typed APPLIED receipt"
                )
            contexts.add(int(row["sequence"]))
        return contexts

    @staticmethod
    def _self_digest(payload: Mapping[str, Any]) -> str:
        return value_sha256(
            {key: item for key, item in payload.items() if key != "payload_sha256"}
        )

    def _validate_domain_dependencies_tx(
        self,
        connection: sqlite3.Connection,
        *,
        record_type: str,
        aggregate_id: str | None = None,
        aggregate_version: int,
        idempotency_key: str | None = None,
        payload: Mapping[str, Any],
        writer_id: str,
        as_of_sequence: int,
        payment_transition: bool = False,
        crm_claim_transition: bool = False,
        recorded_at_utc: str | None = None,
    ) -> None:
        """Enforce commercial dependencies beneath every guarded writer."""

        value = dict(payload)
        semantic_writer_field = {
            "LEGAL_POLICY_SNAPSHOT": "approved_by",
            "CONSENT_RECORD": "decided_by",
            "SUPPRESSION_TOMBSTONE": "created_by",
            "CONTACT_AUTHORIZATION_DECISION": "evaluated_by",
            "CONFLICT_RESOLUTION": "arbitrator_id",
            "CRM_OUTCOME_CLAIM": "recorded_by",
            "PAYMENT_PROOF": "verified_by",
            "FULFILMENT_RECORD": "actor_id",
            "BITRIX_PROJECTION_COMMAND": "enqueued_by",
            "BITRIX_PROJECTION_CLAIM": "worker_id",
            "BITRIX_PROJECTION_ATTEMPT": "worker_id",
            "BITRIX_PROJECTION_RECEIPT": "worker_id",
            "BITRIX_PROJECTION_DLQ": "worker_id",
        }.get(record_type)
        if semantic_writer_field is not None and value.get(semantic_writer_field) != writer_id:
            raise SchemaIntegrityError(
                f"{record_type} semantic actor does not match ledger writer"
            )
        if (
            record_type == "ORDER_RECORD"
            and aggregate_version == 1
            and value.get("approved_by") != writer_id
        ):
            raise SchemaIntegrityError(
                "initial ORDER_RECORD approver does not match ledger writer"
            )
        if record_type == "COMMERCIAL_TERMS" and aggregate_version != 1:
            raise SchemaIntegrityError(
                "COMMERCIAL_TERMS is immutable v1; corrections require a new record_id"
            )
        if record_type in {"PERMIT_DECISION", "ORDER_RECORD", "OUTCOME_EVENT"} and (
            value.get("payload_sha256") != self._self_digest(value)
        ):
            raise SchemaIntegrityError(f"{record_type} self digest mismatch")
        if record_type in INTERNAL_SCHEMAS and record_type not in {
            "CONTACT_ACTION_PROPOSAL",
            "CONFLICT_RESOLUTION",
        }:
            if value.get("payload_sha256") != self._self_digest(value):
                raise SchemaIntegrityError(f"{record_type} self digest mismatch")

        if record_type == "SIGNAL_OBSERVATION":
            evidence = connection.execute(
                "SELECT 1 FROM mdos_evidence WHERE content_sha256=?",
                (str(value.get("payload_sha256", "")),),
            ).fetchone()
            if evidence is None or value.get("source_id") != "fixture:known-account-history":
                raise SchemaIntegrityError("SignalObservation source/evidence binding failed")

        elif record_type == "CLAIM":
            source = self._payload_tx(
                connection, "SIGNAL_OBSERVATION", str(value.get("source_event_id", ""))
            )
            if source is None or source.get("payload_sha256") != value.get("payload_sha256"):
                raise SchemaIntegrityError("Claim source binding failed")
            if aggregate_version > 1:
                previous = self._payload_tx(
                    connection, "CLAIM", str(value.get("claim_id", "")), aggregate_version - 1
                )
                if previous is None:
                    raise SchemaIntegrityError("Claim adjudication predecessor is missing")

        elif record_type == "ENTITY_RESOLUTION_DECISION":
            for claim_id in value.get("evidence_claim_ids", []):
                claim = self._payload_tx(connection, "CLAIM", str(claim_id))
                if claim is None or claim.get("status") != "ACCEPTED":
                    raise SchemaIntegrityError("identity decision has no accepted claim")

        elif record_type == "DEMAND_UNIT":
            for claim_id in value.get("evidence_claim_ids", []):
                claim = self._payload_tx(connection, "CLAIM", str(claim_id))
                if claim is None or claim.get("status") != "ACCEPTED":
                    raise SchemaIntegrityError("DemandUnit has no accepted claim")
            if aggregate_version == 2:
                previous = self._payload_tx(
                    connection, "DEMAND_UNIT", str(value.get("demand_unit_id", "")), 1
                )
                gold = self._payload_tx(
                    connection,
                    "GOLD_ACCEPTANCE",
                    str(value.get("gold_acceptance_ref", "")),
                )
                if (
                    previous is None
                    or gold is None
                    or value.get("state") != "ACCEPTED_GDO"
                    or gold.get("decision") != "ACCEPTED"
                    or gold.get("demand_unit_id") != value.get("demand_unit_id")
                    or gold.get("permit_decision_ref") != value.get("lawful_next_action_ref")
                ):
                    raise SchemaIntegrityError("accepted DemandUnit Gold binding failed")

        elif record_type == "PERMIT_DECISION" and value.get("decision") == "ALLOW":
            subject_refs = value.get("subject_refs", [])
            demand = self._payload_tx(
                connection,
                "DEMAND_UNIT",
                str(subject_refs[0]) if len(subject_refs) == 1 else "",
            )
            capacity = self._payload_tx(
                connection,
                "CAPACITY_SNAPSHOT",
                str(value.get("capacity_snapshot_ref", "")),
            )
            evidence_refs = set(value.get("evidence_refs", []))
            known_evidence = {
                ref
                for ref in evidence_refs
                if self._payload_tx(connection, "EVIDENCE_BUNDLE", str(ref)) is not None
                or self._payload_tx(connection, "HUMAN_GOLD_REVIEW", str(ref)) is not None
            }
            expected_scope = None
            if demand is not None and capacity is not None:
                expected_scope = {
                    "beachhead_profile_ref": None,
                    "region": capacity.get("region"),
                    "product_scope": demand.get("product_scope"),
                }
            if (
                demand is None
                or capacity is None
                or capacity.get("demand_unit_id") != demand.get("demand_unit_id")
                or capacity.get("product_scope") != demand.get("product_scope")
                or value.get("scope") != expected_scope
                or known_evidence != evidence_refs
            ):
                raise SchemaIntegrityError("ALLOW PermitDecision trusted scope binding failed")

        elif record_type == "GOLD_ACCEPTANCE":
            demand = self._payload_tx(
                connection, "DEMAND_UNIT", str(value.get("demand_unit_id", "")), 1
            )
            review_rows = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type='HUMAN_GOLD_REVIEW'"""
            ).fetchall()
            reviews = [json.loads(str(row[0])) for row in review_rows]
            review = next(
                (
                    item
                    for item in reviews
                    if item.get("demand_unit_id") == value.get("demand_unit_id")
                    and item.get("reviewer_id") == value.get("reviewer_id")
                    and item.get("decision") == "ACCEPTED"
                ),
                None,
            )
            permit = self._payload_tx(
                connection,
                "PERMIT_DECISION",
                str(value.get("permit_decision_ref", "")),
            )
            refs = (
                ("CAPACITY_SNAPSHOT", value.get("capacity_snapshot_ref")),
                ("ECONOMICS_SNAPSHOT", value.get("economics_snapshot_ref")),
                ("DENOMINATOR_SNAPSHOT", value.get("denominator_snapshot_ref")),
                ("EVIDENCE_BUNDLE", value.get("evidence_bundle_ref")),
            )
            if (
                demand is None
                or review is None
                or permit is None
                or value.get("decision") != "ACCEPTED"
                or value.get("scope_fingerprint") != demand.get("scope_fingerprint")
                or value.get("motion") != demand.get("motion")
                or any(
                    self._payload_tx(connection, kind, str(reference or "")) is None
                    for kind, reference in refs
                )
            ):
                raise SchemaIntegrityError("GoldAcceptance authority binding failed")
            duplicate_gold_rows = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type='GOLD_ACCEPTANCE'
                     AND json_extract(payload_json,'$.scope_fingerprint')=?
                     AND json_extract(payload_json,'$.cohort_id')=?
                     AND json_extract(payload_json,'$.cutoff_at')=?""",
                (
                    str(value.get("scope_fingerprint", "")),
                    str(value.get("cohort_id", "")),
                    str(value.get("cutoff_at", "")),
                ),
            ).fetchall()
            if any(json.loads(str(row[0])) != value for row in duplicate_gold_rows):
                raise SchemaIntegrityError("duplicate Gold scope in sealed cohort")

        elif record_type == "ACTION_ASSIGNMENT":
            demand = self._payload_tx(
                connection, "DEMAND_UNIT", str(value.get("demand_unit_id", "")), 2
            )
            permit = self._payload_tx(
                connection,
                "PERMIT_DECISION",
                str(value.get("permit_decision_ref", "")),
            )
            if (
                demand is None
                or permit is None
                or value.get("status") != "APPROVED"
                or demand.get("lawful_next_action_ref") != value.get("permit_decision_ref")
                or value_sha256(permit) != value.get("permit_decision_sha256")
            ):
                raise SchemaIntegrityError("ActionAssignment permit binding failed")

        elif record_type == "CRM_OUTCOME_CLAIM":
            if not crm_claim_transition:
                raise SchemaIntegrityError(
                    "CRM_OUTCOME_CLAIM requires typed shadow CRM transition"
                )
            expected_aggregate_id = crm_shadow_claim_aggregate_id(value)
            expected_idempotency_key = crm_shadow_claim_idempotency_key(value)
            mapping_sha = crm_shadow_stage_mapping_sha256(value)
            artifact_sha = str(value.get("source_artifact_sha256", ""))
            evidence = connection.execute(
                """SELECT content,media_type,source_ref,synthetic,writer_id,recorded_at_utc
                   FROM mdos_evidence WHERE content_sha256=?""",
                (artifact_sha,),
            ).fetchone()
            try:
                artifact = (
                    json.loads(
                        bytes(evidence["content"]).decode("utf-8", "strict"),
                        parse_constant=lambda item: (_ for _ in ()).throw(
                            ValueError(item)
                        ),
                    )
                    if evidence is not None
                    else None
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise SchemaIntegrityError("CRM claim evidence is not strict JSON") from exc
            evidence_actor = (
                self._actor_row(connection, str(evidence["writer_id"]))
                if evidence is not None
                else None
            )
            evidence_roles = (
                set(json.loads(str(evidence_actor["roles_json"])))
                if evidence_actor is not None
                else set()
            )
            expected_artifact = crm_shadow_source_artifact(value)
            observed_at = self._utc_instant(
                value.get("observed_at"), "CRM claim observed_at"
            )
            claim_recorded_at = self._utc_instant(
                value.get("recorded_at"), "CRM claim recorded_at"
            )
            ledger_recorded_at = self._utc_instant(
                recorded_at_utc or value.get("recorded_at"),
                "CRM claim ledger time",
            )
            evidence_recorded_at = (
                self._utc_instant(
                    evidence["recorded_at_utc"], "CRM claim evidence time"
                )
                if evidence is not None
                else None
            )
            expected_source_ref = (
                "fixture:bitrix24-shadow:"
                f"{str(value.get('portal_fingerprint_sha256', ''))[:16]}"
            )
            dependency_sequence = int(as_of_sequence) - 1
            previous_row = connection.execute(
                """SELECT aggregate_version,payload_json FROM mdos_ledger
                   WHERE record_type='CRM_OUTCOME_CLAIM' AND aggregate_id=?
                     AND sequence<=?
                   ORDER BY sequence DESC LIMIT 1""",
                (expected_aggregate_id, dependency_sequence),
            ).fetchone()
            previous = (
                json.loads(str(previous_row["payload_json"]))
                if previous_row is not None
                else None
            )
            demand = self._payload_as_of_tx(
                connection,
                "DEMAND_UNIT",
                str(value.get("demand_unit_id", "")),
                dependency_sequence,
                2,
            )
            order_id = value.get("distinct_order_id")
            order = (
                self._payload_as_of_tx(
                    connection,
                    "ORDER_RECORD",
                    str(order_id),
                    dependency_sequence,
                )
                if order_id is not None
                else None
            )
            demand_recorded_at = (
                self._utc_instant(
                    demand.get("recorded_at"), "accepted DemandUnit recorded_at"
                )
                if demand is not None
                else None
            )
            order_relevant_at = (
                self._utc_instant(order.get("approved_at"), "OrderRecord approved_at")
                if order is not None
                else None
            )
            if (
                aggregate_id != expected_aggregate_id
                or value.get("record_id") != expected_aggregate_id
                or idempotency_key != expected_idempotency_key
                or aggregate_version
                != (1 if previous_row is None else int(previous_row["aggregate_version"]) + 1)
                or value.get("source_system") != CRM_SHADOW_SOURCE_SYSTEM
                or value.get("portal_fingerprint_sha256")
                != CRM_SHADOW_PORTAL_FINGERPRINT_SHA256
                or value.get("remote_category_id") != CRM_SHADOW_REMOTE_CATEGORY_ID
                or value.get("remote_pipeline_id") != CRM_SHADOW_REMOTE_PIPELINE_ID
                or value.get("remote_stage_id") != CRM_SHADOW_REMOTE_STAGE_ID
                or value.get("stage_mapping_id") != CRM_SHADOW_MAPPING_ID
                or value.get("stage_mapping_version")
                != CRM_SHADOW_STAGE_MAPPING_VERSION
                or value.get("stage_mapping_sha256") != mapping_sha
                or mapping_sha != CRM_SHADOW_STAGE_MAPPING_SHA256
                or value.get("stage_mapping_registry_sha256")
                != CRM_SHADOW_MAPPING_REGISTRY_SHA256
                or value.get("real_mapping_state") != CRM_REAL_MAPPING_STATE
                or value.get("read_model_status") != CRM_SHADOW_READ_MODEL_STATUS
                or evidence is None
                or not isinstance(artifact, dict)
                or artifact != expected_artifact
                or bytes(evidence["content"])
                != canonical_json(expected_artifact).encode("utf-8", "strict")
                or str(evidence["media_type"]) != "application/json"
                or str(evidence["source_ref"]) != expected_source_ref
                or int(evidence["synthetic"]) != 1
                or "SOURCE_ADAPTER" not in evidence_roles
                or evidence_recorded_at != claim_recorded_at
                or not observed_at <= claim_recorded_at <= ledger_recorded_at
                or demand is None
                or demand.get("state") != "ACCEPTED_GDO"
                or demand.get("account_ref") != value.get("account_id")
                or demand_recorded_at is None
                or observed_at < demand_recorded_at
                or (
                    order_id is not None
                    and (
                        order is None
                        or order.get("distinct_order_id") != order_id
                        or order.get("demand_unit_id") != value.get("demand_unit_id")
                        or order.get("account_id") != value.get("account_id")
                        or order_relevant_at is None
                        or observed_at < order_relevant_at
                    )
                )
                or (
                    previous is not None
                    and (
                        int(value.get("remote_version", 0))
                        <= int(previous.get("remote_version", 0))
                        or self._utc_instant(
                            value.get("observed_at"), "CRM claim observed_at"
                        )
                        < self._utc_instant(
                            previous.get("observed_at"),
                            "previous CRM claim observed_at",
                        )
                    )
                )
            ):
                raise SchemaIntegrityError(
                    "CRM_OUTCOME_CLAIM source/version/order binding failed"
                )

        elif record_type == "RAW_PAYMENT_OBSERVATION":
            provider_key = f"{value.get('provider')}:{value.get('provider_event_id')}"
            evidence = connection.execute(
                """SELECT content,media_type,source_ref,synthetic,writer_id,recorded_at_utc
                   FROM mdos_evidence WHERE content_sha256=?""",
                (str(value.get("source_artifact_sha256", "")),),
            ).fetchone()
            try:
                artifact = (
                    json.loads(
                        bytes(evidence["content"]).decode("utf-8", "strict"),
                        parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
                    )
                    if evidence is not None
                    else None
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise SchemaIntegrityError(
                    "raw payment evidence is not strict JSON"
                ) from exc
            raw_artifact = {
                key: item
                for key, item in value.items()
                if key
                not in {
                    "schema_version",
                    "record_id",
                    "synthetic",
                    "canonical_kpi_eligible",
                    "source_artifact_sha256",
                    "authoritative_class",
                }
            }
            if (
                aggregate_version != 1
                or evidence is None
                or not isinstance(artifact, dict)
                or artifact != raw_artifact
                or artifact.get("fixture") is not True
                or artifact.get("signed") is not True
                or artifact.get("provider") != "fixture-signed-bank-statement"
                or value.get("record_id") != provider_key
                or value.get("authoritative_class") != "SIGNED_BANK_STATEMENT"
                or str(evidence["media_type"]) != "application/json"
                or str(evidence["source_ref"]) != value.get("provider")
                or int(evidence["synthetic"]) != 1
                or str(evidence["writer_id"]) != writer_id
                or self._utc_instant(
                    evidence["recorded_at_utc"], "raw payment evidence time"
                )
                != self._utc_instant(
                    recorded_at_utc or evidence["recorded_at_utc"],
                    "raw payment ledger time",
                )
            ):
                raise SchemaIntegrityError(
                    "RAW_PAYMENT_OBSERVATION must be immutable signed fixture evidence"
                )

        elif record_type == "PAYMENT_PROOF":
            dependency_sequence = int(as_of_sequence) - 1
            order = self._payload_as_of_tx(
                connection,
                "ORDER_RECORD",
                str(value.get("distinct_order_id", "")),
                dependency_sequence,
                1,
            )
            raw_key = f"{value.get('provider')}:{value.get('provider_event_id')}"
            raw_row = connection.execute(
                """SELECT payload_json,recorded_at_utc FROM mdos_ledger
                   WHERE record_type='RAW_PAYMENT_OBSERVATION' AND aggregate_id=?
                     AND aggregate_version=1 AND sequence<=?""",
                (raw_key, dependency_sequence),
            ).fetchone()
            raw = json.loads(str(raw_row["payload_json"])) if raw_row is not None else None
            evidence = connection.execute(
                "SELECT recorded_at_utc FROM mdos_evidence WHERE content_sha256=?",
                (str(value.get("source_artifact_sha256", "")),),
            ).fetchone()
            fields = (
                "provider",
                "provider_event_id",
                "distinct_order_id",
                "canonical_account_id",
                "payer_identity_ref",
                "recipient_identity_ref",
                "amount",
                "currency",
                "value_at",
                "source_artifact_sha256",
                "authoritative_class",
            )
            duplicate_rows = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type='PAYMENT_PROOF'
                     AND json_extract(payload_json,'$.provider')=?
                     AND json_extract(payload_json,'$.provider_event_id')=?
                     AND sequence<=?""",
                (
                    str(value.get("provider", "")),
                    str(value.get("provider_event_id", "")),
                    int(as_of_sequence),
                ),
            ).fetchall()
            if any(json.loads(str(row[0])) != value for row in duplicate_rows):
                raise SchemaIntegrityError("duplicate reconciled PaymentProof")
            evidence_time = (
                self._utc_instant(evidence["recorded_at_utc"], "payment evidence time")
                if evidence is not None
                else None
            )
            raw_time = (
                self._utc_instant(raw_row["recorded_at_utc"], "raw payment ledger time")
                if raw_row is not None
                else None
            )
            verified_time = self._utc_instant(
                value.get("verified_at"), "PaymentProof verified_at"
            )
            value_time = self._utc_instant(value.get("value_at"), "PaymentProof value_at")
            ledger_time = self._utc_instant(
                recorded_at_utc or value.get("verified_at"),
                "PaymentProof ledger time",
            )
            if (
                order is None
                or raw is None
                or evidence is None
                or value_time > evidence_time
                or evidence_time != raw_time
                or raw_time > verified_time
                or ledger_time != verified_time
                or order.get("state") != "APPROVED"
                or any(raw.get(field) != value.get(field) for field in fields)
            ):
                raise SchemaIntegrityError("PaymentProof order/raw/evidence binding failed")
            if not payment_transition:
                raise SchemaIntegrityError("PaymentProof requires typed atomic payment transition")
            total, rows, bound_order, terms = self._settled_amount_tx(
                connection,
                str(value.get("distinct_order_id", "")),
                as_of_sequence,
            )
            if not any(proof == value for _, proof in rows):
                total += self._amount(value.get("amount"), "PaymentProof amount")
            if (
                value.get("canonical_account_id") != bound_order.get("account_id")
                or value.get("currency") != terms.get("currency")
                or total > self._amount(terms.get("amount"), "commercial terms amount")
            ):
                raise SchemaIntegrityError("PaymentProof settlement exceeds or differs from terms")

        elif record_type == "ORDER_RECORD":
            dependency_sequence = int(as_of_sequence) - 1
            demand = self._payload_as_of_tx(
                connection,
                "DEMAND_UNIT",
                str(value.get("demand_unit_id", "")),
                dependency_sequence,
                2,
            )
            terms = self._payload_as_of_tx(
                connection,
                "COMMERCIAL_TERMS",
                str(value.get("commercial_terms_ref", "")),
                dependency_sequence,
                1,
            )
            if demand is None or terms is None:
                raise SchemaIntegrityError("OrderRecord demand/terms binding failed")
            if aggregate_version > 1:
                previous = self._payload_as_of_tx(
                    connection,
                    "ORDER_RECORD",
                    str(value.get("distinct_order_id", "")),
                    dependency_sequence,
                    aggregate_version - 1,
                )
                immutable = (
                    "distinct_order_id",
                    "demand_unit_id",
                    "account_id",
                    "scope_fingerprint",
                    "commercial_terms_ref",
                    "approved_by",
                    "approved_at",
                )
                if previous is None or any(
                    previous.get(field) != value.get(field) for field in immutable
                ):
                    raise SchemaIntegrityError("OrderRecord immutable revision binding failed")
                state = str(value.get("state", ""))
                previous_state = str(previous.get("state", ""))
                if state in {"PAID_PARTIAL", "PAID"}:
                    if not payment_transition:
                        raise SchemaIntegrityError(
                            "payment OrderRecord requires typed atomic payment transition"
                        )
                    if previous_state not in {"APPROVED", "PAID_PARTIAL"}:
                        raise SchemaIntegrityError("invalid payment OrderRecord progression")
                    total, proofs, _, payment_terms = self._settled_amount_tx(
                        connection,
                        str(value.get("distinct_order_id", "")),
                        as_of_sequence,
                    )
                    due = self._amount(payment_terms.get("amount"), "commercial terms amount")
                    if not proofs or total > due:
                        raise SchemaIntegrityError("paid OrderRecord has invalid PaymentProof sum")
                    if state == "PAID_PARTIAL" and not total < due:
                        raise SchemaIntegrityError("PAID_PARTIAL requires a positive remaining balance")
                    if state == "PAID" and total != due:
                        raise SchemaIntegrityError("PAID requires exact settled commercial terms")
                elif state == "FULFILLED":
                    if previous_state != "PAID":
                        raise SchemaIntegrityError("FULFILLED requires the prior PAID state")
                    fulfilment = connection.execute(
                        """SELECT 1 FROM mdos_ledger WHERE record_type='FULFILMENT_RECORD'
                           AND json_extract(payload_json,'$.distinct_order_id')=?
                           AND sequence<=?""",
                        (
                            str(value.get("distinct_order_id", "")),
                            dependency_sequence,
                        ),
                    ).fetchone()
                    if fulfilment is None:
                        raise SchemaIntegrityError("fulfilled OrderRecord has no fulfilment")

        elif record_type == "RAW_FULFILMENT_DOCUMENT":
            evidence = connection.execute(
                """SELECT content,media_type,source_ref,synthetic,writer_id,recorded_at_utc
                   FROM mdos_evidence WHERE content_sha256=?""",
                (str(value.get("evidence_sha256", "")),),
            ).fetchone()
            try:
                artifact = (
                    json.loads(
                        bytes(evidence["content"]).decode("utf-8", "strict"),
                        parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
                    )
                    if evidence is not None
                    else None
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise SchemaIntegrityError(
                    "raw fulfilment evidence is not strict JSON"
                ) from exc
            raw_artifact = {
                key: item
                for key, item in value.items()
                if key
                not in {
                    "schema_version",
                    "record_id",
                    "synthetic",
                    "canonical_kpi_eligible",
                    "evidence_sha256",
                }
            }
            if (
                aggregate_version != 1
                or evidence is None
                or not isinstance(artifact, dict)
                or artifact != raw_artifact
                or artifact.get("fixture") is not True
                or artifact.get("document_type") != "SIGNED_UPD"
                or artifact.get("accepted_by_customer") is not True
                or value.get("record_id") != value.get("document_ref")
                or str(evidence["media_type"]) != "application/json"
                or str(evidence["source_ref"]) != value.get("document_ref")
                or int(evidence["synthetic"]) != 1
                or str(evidence["writer_id"]) != writer_id
                or self._utc_instant(
                    evidence["recorded_at_utc"], "raw fulfilment evidence time"
                )
                != self._utc_instant(
                    recorded_at_utc or evidence["recorded_at_utc"],
                    "raw fulfilment ledger time",
                )
            ):
                raise SchemaIntegrityError(
                    "RAW_FULFILMENT_DOCUMENT must be immutable signed fixture evidence"
                )

        elif record_type == "FULFILMENT_RECORD":
            order = self._payload_as_of_tx(
                connection,
                "ORDER_RECORD",
                str(value.get("distinct_order_id", "")),
                int(as_of_sequence) - 1,
            )
            raw_row = connection.execute(
                """SELECT payload_json,recorded_at_utc FROM mdos_ledger
                   WHERE record_type='RAW_FULFILMENT_DOCUMENT' AND aggregate_id=?
                     AND aggregate_version=1 AND sequence<?""",
                (str(value.get("primary_document_ref", "")), int(as_of_sequence)),
            ).fetchone()
            raw = json.loads(str(raw_row["payload_json"])) if raw_row is not None else None
            evidence = connection.execute(
                "SELECT recorded_at_utc FROM mdos_evidence WHERE content_sha256=?",
                (str(value.get("evidence_sha256", "")),),
            ).fetchone()
            evidence_time = (
                self._utc_instant(evidence["recorded_at_utc"], "fulfilment evidence time")
                if evidence is not None
                else None
            )
            raw_time = (
                self._utc_instant(raw_row["recorded_at_utc"], "raw fulfilment ledger time")
                if raw_row is not None
                else None
            )
            event_time = self._utc_instant(
                value.get("event_at"), "FulfilmentRecord event_at"
            )
            ledger_time = self._utc_instant(
                recorded_at_utc or value.get("event_at"),
                "FulfilmentRecord ledger time",
            )
            if (
                order is None
                or raw is None
                or evidence is None
                or event_time > evidence_time
                or evidence_time != raw_time
                or raw_time > ledger_time
                or order.get("state") != "PAID"
                or raw.get("distinct_order_id") != value.get("distinct_order_id")
                or raw.get("evidence_sha256") != value.get("evidence_sha256")
                or raw.get("event_at") != value.get("event_at")
            ):
                raise SchemaIntegrityError("FulfilmentRecord signed-document binding failed")
            total, proofs, _, payment_terms = self._settled_amount_tx(
                connection,
                str(value.get("distinct_order_id", "")),
                int(as_of_sequence) - 1,
            )
            terminal_payment_rows = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type='OUTCOME_EVENT'
                     AND json_extract(payload_json,'$.distinct_order_id')=?
                     AND json_extract(payload_json,'$.outcome_type')='CLEARED_PAYMENT'
                     AND sequence<? ORDER BY sequence""",
                (str(value.get("distinct_order_id", "")), int(as_of_sequence)),
            ).fetchall()
            terminal_payments = [
                json.loads(str(row[0])) for row in terminal_payment_rows
            ]
            if (
                not proofs
                or total != self._amount(payment_terms.get("amount"), "commercial terms amount")
                or len(terminal_payments) != 1
                or terminal_payments[0].get("payment_proof_ref")
                != proofs[-1][1].get("payment_proof_id")
            ):
                raise SchemaIntegrityError("FulfilmentRecord lacks an exactly settled proof set")
            duplicate_rows = connection.execute(
                """SELECT payload_json FROM mdos_ledger
                   WHERE record_type='FULFILMENT_RECORD'
                     AND json_extract(payload_json,'$.distinct_order_id')=?
                     AND json_extract(payload_json,'$.event_type')='ACCEPTED_BY_CUSTOMER'
                     AND sequence<=?""",
                (str(value.get("distinct_order_id", "")), int(as_of_sequence)),
            ).fetchall()
            if any(json.loads(str(row[0])) != value for row in duplicate_rows):
                raise SchemaIntegrityError("duplicate terminal fulfilment")

        elif record_type == "RECONCILIATION_RESULT":
            dependency_sequence = int(as_of_sequence) - 1
            distinct_order_id = str(value.get("distinct_order_id", ""))
            order_row = connection.execute(
                """SELECT * FROM mdos_ledger
                   WHERE record_type='ORDER_RECORD' AND aggregate_id=? AND sequence<=?
                   ORDER BY aggregate_version DESC LIMIT 1""",
                (distinct_order_id, dependency_sequence),
            ).fetchone()
            proof_rows = connection.execute(
                """SELECT * FROM mdos_ledger
                   WHERE record_type='PAYMENT_PROOF'
                     AND json_extract(payload_json,'$.distinct_order_id')=?
                     AND sequence<=? ORDER BY sequence""",
                (distinct_order_id, dependency_sequence),
            ).fetchall()
            fulfilment_rows = connection.execute(
                """SELECT * FROM mdos_ledger
                   WHERE record_type='FULFILMENT_RECORD'
                     AND json_extract(payload_json,'$.distinct_order_id')=?
                     AND sequence<=? ORDER BY sequence""",
                (distinct_order_id, dependency_sequence),
            ).fetchall()
            payment_outcome_rows = connection.execute(
                """SELECT * FROM mdos_ledger
                   WHERE record_type='OUTCOME_EVENT'
                     AND json_extract(payload_json,'$.distinct_order_id')=?
                     AND json_extract(payload_json,'$.outcome_type')='CLEARED_PAYMENT'
                     AND sequence<=? ORDER BY sequence""",
                (distinct_order_id, dependency_sequence),
            ).fetchall()
            fulfilment_outcome_rows = connection.execute(
                """SELECT * FROM mdos_ledger
                   WHERE record_type='OUTCOME_EVENT'
                     AND json_extract(payload_json,'$.distinct_order_id')=?
                     AND json_extract(payload_json,'$.outcome_type')='FULFILLED'
                     AND sequence<=? ORDER BY sequence""",
                (distinct_order_id, dependency_sequence),
            ).fetchall()
            order_payload = (
                json.loads(str(order_row["payload_json"]))
                if order_row is not None
                else None
            )
            proofs = [json.loads(str(row["payload_json"])) for row in proof_rows]
            fulfilments = [
                json.loads(str(row["payload_json"])) for row in fulfilment_rows
            ]
            payment_outcomes = [
                json.loads(str(row["payload_json"])) for row in payment_outcome_rows
            ]
            fulfilment_outcomes = [
                json.loads(str(row["payload_json"]))
                for row in fulfilment_outcome_rows
            ]
            expected_proof_entry_ids = [str(row["entry_id"]) for row in proof_rows]
            expected_proof_refs = [
                str(proof.get("payment_proof_id", "")) for proof in proofs
            ]
            expected_fulfilment_entry_ids = [
                str(row["entry_id"]) for row in fulfilment_rows
            ]
            legacy_keys = {
                "schema_version",
                "record_id",
                "synthetic",
                "canonical_kpi_eligible",
                "status",
                "distinct_order_id",
                "demand_unit_id",
                "order_record_entry_id",
                "payment_proof_entry_id",
                "fulfilment_record_entry_ids",
                "payment_outcome_entry_id",
                "fulfilment_outcome_entry_id",
                "reconciled_at",
            }
            plural_keys = {"payment_proof_entry_ids", "payment_proof_refs"}
            actual_keys = set(value)
            plural_present = plural_keys.issubset(actual_keys)
            exact_shape = actual_keys == legacy_keys or actual_keys == legacy_keys | plural_keys
            bindings_valid = (
                exact_shape
                and order_row is not None
                and order_payload is not None
                and order_payload.get("state") == "FULFILLED"
                and order_payload.get("demand_unit_id") == value.get("demand_unit_id")
                and value.get("status") == "RECONCILED_FIXTURE_NON_KPI"
                and value.get("order_record_entry_id") == str(order_row["entry_id"])
                and bool(proof_rows)
                and value.get("payment_proof_entry_id")
                == expected_proof_entry_ids[-1]
                and value.get("fulfilment_record_entry_ids")
                == expected_fulfilment_entry_ids
                and len(fulfilment_rows) == 1
                and len(payment_outcome_rows) == 1
                and len(fulfilment_outcome_rows) == 1
                and value.get("payment_outcome_entry_id")
                == str(payment_outcome_rows[0]["entry_id"])
                and value.get("fulfilment_outcome_entry_id")
                == str(fulfilment_outcome_rows[0]["entry_id"])
                and payment_outcomes[0].get("payment_proof_ref")
                == expected_proof_refs[-1]
                and fulfilment_outcomes[0].get("payment_proof_ref")
                == expected_proof_refs[-1]
                and (
                    (len(proof_rows) == 1 and not plural_keys.intersection(actual_keys))
                    or (
                        plural_present
                        and value.get("payment_proof_entry_ids")
                        == expected_proof_entry_ids
                        and value.get("payment_proof_refs") == expected_proof_refs
                    )
                )
                and (len(proof_rows) == 1 or plural_present)
            )
            if not bindings_valid:
                raise SchemaIntegrityError(
                    "RECONCILIATION_RESULT exact terminal truth binding failed"
                )

            reconciled_at = self._utc_instant(
                value.get("reconciled_at"), "reconciliation time"
            )
            ledger_time = self._utc_instant(
                recorded_at_utc or value.get("reconciled_at"),
                "reconciliation ledger time",
            )
            terminal_proof = proofs[-1]
            bound_times = [
                self._utc_instant(terminal_proof.get("value_at"), "terminal payment time"),
                self._utc_instant(
                    terminal_proof.get("verified_at"), "terminal verification time"
                ),
                self._utc_instant(
                    proof_rows[-1]["recorded_at_utc"], "terminal proof ledger time"
                ),
                self._utc_instant(
                    fulfilments[0].get("event_at"), "terminal fulfilment time"
                ),
                self._utc_instant(
                    fulfilment_rows[0]["recorded_at_utc"],
                    "terminal fulfilment ledger time",
                ),
            ]
            for row, outcome in (
                (payment_outcome_rows[0], payment_outcomes[0]),
                (fulfilment_outcome_rows[0], fulfilment_outcomes[0]),
            ):
                bound_times.extend(
                    (
                        self._utc_instant(
                            outcome.get("event_time"), "terminal outcome event time"
                        ),
                        self._utc_instant(
                            outcome.get("recorded_at"), "terminal outcome recorded time"
                        ),
                        self._utc_instant(
                            row["recorded_at_utc"], "terminal outcome ledger time"
                        ),
                    )
                )
            if reconciled_at != ledger_time or any(
                bound_time > reconciled_at for bound_time in bound_times
            ):
                raise SchemaIntegrityError(
                    "RECONCILIATION_RESULT time precedes bound terminal truth"
                )

        elif record_type == "CONFLICT_RESOLUTION":
            conflict = connection.execute(
                "SELECT writer_id FROM mdos_conflicts WHERE conflict_id=?",
                (str(value.get("conflict_id", "")),),
            ).fetchone()
            if (
                conflict is None
                or value.get("decision") != "RESOLVED"
                or value.get("arbitrator_id") == str(conflict[0])
                or value.get("attestation_sha256")
                != value_sha256(
                    {
                        key: item
                        for key, item in value.items()
                        if key != "attestation_sha256"
                    }
                )
            ):
                raise SchemaIntegrityError("conflict resolution authority binding failed")

        elif record_type == "LEGAL_POLICY_SNAPSHOT":
            actor = self._actor_row(connection, str(value.get("approved_by", "")))
            roles = set(json.loads(str(actor["roles_json"]))) if actor is not None else set()
            evidence_refs = tuple(str(ref) for ref in value.get("evidence_refs", []))
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_evidence WHERE content_sha256 IN "
                f"({','.join('?' for _ in evidence_refs)})",
                evidence_refs,
            ).fetchone()[0]
            effective = datetime.fromisoformat(
                str(value.get("effective_at", "")).replace("Z", "+00:00")
            )
            expires = datetime.fromisoformat(
                str(value.get("expires_at", "")).replace("Z", "+00:00")
            )
            if (
                actor is None
                or str(actor["actor_type"]) != "HUMAN"
                or "CONSENT_AUTHORITY" not in roles
                or int(evidence_count) != len(evidence_refs)
                or expires <= effective
                or value.get("contact_enabled") is not False
            ):
                raise SchemaIntegrityError("legal policy authority/evidence binding failed")

        elif record_type == "CONSENT_RECORD":
            actor = self._actor_row(connection, str(value.get("decided_by", "")))
            roles = set(json.loads(str(actor["roles_json"]))) if actor is not None else set()
            effective = datetime.fromisoformat(
                str(value.get("effective_at", "")).replace("Z", "+00:00")
            )
            expires_raw = value.get("expires_at")
            expires = (
                datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
                if expires_raw is not None
                else None
            )
            policy = self._payload_tx(
                connection, "LEGAL_POLICY_SNAPSHOT", str(value.get("legal_basis_ref", ""))
            )
            policy_effective = (
                datetime.fromisoformat(
                    str(policy.get("effective_at", "")).replace("Z", "+00:00")
                )
                if policy is not None
                else None
            )
            policy_expires = (
                datetime.fromisoformat(
                    str(policy.get("expires_at", "")).replace("Z", "+00:00")
                )
                if policy is not None
                else None
            )
            evidence_refs = tuple(str(ref) for ref in value.get("evidence_refs", []))
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_evidence WHERE content_sha256 IN "
                f"({','.join('?' for _ in evidence_refs)})",
                evidence_refs,
            ).fetchone()[0]
            if (
                actor is None
                or str(actor["actor_type"]) != "HUMAN"
                or "CONSENT_AUTHORITY" not in roles
                or policy is None
                or policy_effective is None
                or policy_expires is None
                or not (policy_effective <= effective < policy_expires)
                or value.get("purpose") not in policy.get("purposes", [])
                or any(channel not in policy.get("channels", []) for channel in value.get("channels", []))
                or int(evidence_count) != len(evidence_refs)
                or (expires is not None and expires <= effective)
                or (
                    value.get("status") == "GRANTED"
                    and (expires is None or expires > policy_expires)
                )
            ):
                raise SchemaIntegrityError("ConsentRecord human authority binding failed")
            if aggregate_version > 1:
                previous = self._payload_tx(
                    connection,
                    "CONSENT_RECORD",
                    str(value.get("record_id", "")),
                    aggregate_version - 1,
                )
                immutable = ("record_id", "subject_token", "purpose", "channels")
                if previous is None or any(
                    previous.get(field) != value.get(field) for field in immutable
                ):
                    raise SchemaIntegrityError("ConsentRecord immutable revision binding failed")
                previous_effective = datetime.fromisoformat(
                    str(previous.get("effective_at", "")).replace("Z", "+00:00")
                )
                if effective <= previous_effective:
                    raise SchemaIntegrityError(
                        "ConsentRecord revision effective_at must advance"
                    )

        elif record_type == "SUPPRESSION_TOMBSTONE":
            actor = self._actor_row(connection, str(value.get("created_by", "")))
            roles = set(json.loads(str(actor["roles_json"]))) if actor is not None else set()
            effective = datetime.fromisoformat(
                str(value.get("effective_at", "")).replace("Z", "+00:00")
            )
            expires_raw = value.get("expires_at")
            expires = (
                datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
                if expires_raw is not None
                else None
            )
            policy = self._payload_tx(
                connection, "LEGAL_POLICY_SNAPSHOT", str(value.get("legal_basis_ref", ""))
            )
            policy_effective = (
                datetime.fromisoformat(
                    str(policy.get("effective_at", "")).replace("Z", "+00:00")
                )
                if policy is not None
                else None
            )
            policy_expires = (
                datetime.fromisoformat(
                    str(policy.get("expires_at", "")).replace("Z", "+00:00")
                )
                if policy is not None
                else None
            )
            evidence_refs = tuple(str(ref) for ref in value.get("evidence_refs", []))
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_evidence WHERE content_sha256 IN "
                f"({','.join('?' for _ in evidence_refs)})",
                evidence_refs,
            ).fetchone()[0]
            if (
                actor is None
                or str(actor["actor_type"]) != "HUMAN"
                or "CONSENT_AUTHORITY" not in roles
                or policy is None
                or policy_effective is None
                or policy_expires is None
                or not (policy_effective <= effective < policy_expires)
                or int(evidence_count) != len(evidence_refs)
                or (expires is not None and expires <= effective)
            ):
                raise SchemaIntegrityError("suppression human authority binding failed")

        elif record_type == "CONTACT_AUTHORIZATION_DECISION":
            proposal = value.get("proposal")
            if not isinstance(proposal, dict):
                raise SchemaIntegrityError("contact decision proposal is missing")
            self.internal_contracts.validate("CONTACT_ACTION_PROPOSAL", proposal)
            evaluated = datetime.fromisoformat(
                str(value.get("evaluated_at", "")).replace("Z", "+00:00")
            )
            gate = self._actor_row(connection, str(value.get("evaluated_by", "")))
            gate_roles = (
                set(json.loads(str(gate["roles_json"]))) if gate is not None else set()
            )
            if (
                gate is None
                or str(gate["actor_type"]) != "SYSTEM"
                or "CONTACT_POLICY_GATE" not in gate_roles
                or value.get("proposal_sha256") != value_sha256(proposal)
                or value.get("decision") != "DENY"
                or "CONTACT_AUTHORITY_DISABLED" not in value.get("reason_codes", [])
            ):
                raise SchemaIntegrityError("contact decision gate binding failed")
            subject_token = str(proposal.get("subject_token", ""))
            purpose = str(proposal.get("purpose", ""))
            channel = str(proposal.get("channel", ""))
            source_profile = str(proposal.get("source_profile", ""))
            latest_policies: dict[str, tuple[int, sqlite3.Row, dict[str, Any]]] = {}
            for row in connection.execute(
                "SELECT * FROM mdos_ledger WHERE record_type='LEGAL_POLICY_SNAPSHOT' "
                "AND sequence < ? ORDER BY sequence",
                (int(as_of_sequence),),
            ):
                policy_value = json.loads(str(row["payload_json"]))
                effective = datetime.fromisoformat(
                    str(policy_value.get("effective_at", "")).replace("Z", "+00:00")
                )
                if effective > evaluated:
                    continue
                policy_id = str(policy_value.get("policy_id", ""))
                version = int(row["aggregate_version"])
                previous = latest_policies.get(policy_id)
                if previous is None or version > previous[0]:
                    latest_policies[policy_id] = (version, row, policy_value)
            matching_policies = [
                (version, row, policy_value)
                for version, row, policy_value in latest_policies.values()
                if policy_value.get("status") == "ACTIVE"
                and datetime.fromisoformat(
                    str(policy_value.get("effective_at", "")).replace("Z", "+00:00")
                )
                <= evaluated
                < datetime.fromisoformat(
                    str(policy_value.get("expires_at", "")).replace("Z", "+00:00")
                )
                and purpose in policy_value.get("purposes", [])
                and channel in policy_value.get("channels", [])
                and source_profile in policy_value.get("source_profiles", [])
            ]
            policy_binding = (
                value.get("legal_policy_ref"),
                value.get("legal_policy_version"),
                value.get("legal_policy_entry_id"),
                value.get("legal_policy_sha256"),
            )
            policy_reason_codes = {"LEGAL_POLICY_MISSING", "LEGAL_POLICY_CONFLICT"}
            actual_policy_reasons = policy_reason_codes.intersection(
                value.get("reason_codes", [])
            )
            if len(matching_policies) == 1:
                expected_version, expected_row, expected_policy = matching_policies[0]
                expected_binding = (
                    expected_policy["policy_id"],
                    expected_version,
                    str(expected_row["entry_id"]),
                    str(expected_row["payload_sha256"]),
                )
                if policy_binding != expected_binding or actual_policy_reasons:
                    raise SchemaIntegrityError("contact legal policy binding failed")
            else:
                expected_reason = (
                    "LEGAL_POLICY_MISSING"
                    if not matching_policies
                    else "LEGAL_POLICY_CONFLICT"
                )
                if policy_binding != (None, None, None, None) or actual_policy_reasons != {
                    expected_reason
                }:
                    raise SchemaIntegrityError("contact legal policy denial is not exact")
            active_suppressions: list[dict[str, Any]] = []
            for row in connection.execute(
                "SELECT payload_json FROM mdos_ledger "
                "WHERE record_type='SUPPRESSION_TOMBSTONE' AND sequence < ? "
                "ORDER BY sequence",
                (int(as_of_sequence),),
            ):
                tombstone = json.loads(str(row[0]))
                expires_raw = tombstone.get("expires_at")
                expires = (
                    datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
                    if expires_raw is not None
                    else None
                )
                effective = datetime.fromisoformat(
                    str(tombstone.get("effective_at", "")).replace("Z", "+00:00")
                )
                if (
                    tombstone.get("subject_token") == subject_token
                    and effective <= evaluated
                    and (expires is None or evaluated < expires)
                    and (
                        "ANY_CONTACT" in tombstone.get("purposes", [])
                        or purpose in tombstone.get("purposes", [])
                    )
                    and (
                        "ANY_CONTACT" in tombstone.get("channels", [])
                        or channel in tombstone.get("channels", [])
                    )
                ):
                    active_suppressions.append(tombstone)
            expected_refs = sorted(
                str(item["tombstone_id"]) for item in active_suppressions
            )
            actual_refs = sorted(str(item) for item in value.get("suppression_tombstone_refs", []))
            if expected_refs != actual_refs or bool(expected_refs) != (
                "SUPPRESSION_ACTIVE" in value.get("reason_codes", [])
            ):
                raise SchemaIntegrityError("contact suppression binding failed")
            consent_ref = value.get("consent_record_ref")
            conflicting_refs = sorted(
                str(item) for item in value.get("conflicting_consent_refs", [])
            )
            consent_conflict_ref = value.get("consent_conflict_ref")
            consent_version = value.get("consent_record_version")
            consent_sha256 = value.get("consent_record_sha256")
            all_subject_consents: list[dict[str, Any]] = []
            latest_consent_as_of: dict[str, tuple[int, dict[str, Any]]] = {}
            for row in connection.execute(
                "SELECT aggregate_version,payload_json FROM mdos_ledger "
                "WHERE record_type='CONSENT_RECORD' AND sequence < ? ORDER BY sequence",
                (int(as_of_sequence),),
            ):
                consent_value = json.loads(str(row["payload_json"]))
                if consent_value.get("subject_token") != subject_token:
                    continue
                all_subject_consents.append(consent_value)
                consent_effective = datetime.fromisoformat(
                    str(consent_value.get("effective_at", "")).replace("Z", "+00:00")
                )
                if consent_effective > evaluated:
                    continue
                record_id = str(consent_value.get("record_id", ""))
                version = int(row["aggregate_version"])
                previous = latest_consent_as_of.get(record_id)
                if previous is None or version > previous[0]:
                    latest_consent_as_of[record_id] = (version, consent_value)
            active_scoped_consents: list[tuple[int, dict[str, Any]]] = []
            for version, consent_value in latest_consent_as_of.values():
                consent_expires_raw = consent_value.get("expires_at")
                consent_expires = (
                    datetime.fromisoformat(
                        str(consent_expires_raw).replace("Z", "+00:00")
                    )
                    if consent_expires_raw is not None
                    else None
                )
                if (
                    consent_value.get("purpose") == purpose
                    and channel in consent_value.get("channels", [])
                    and (consent_expires is None or evaluated < consent_expires)
                ):
                    active_scoped_consents.append((version, consent_value))
            if consent_ref is not None:
                if not isinstance(consent_version, int):
                    raise SchemaIntegrityError("contact consent version binding failed")
                consent = self._payload_tx(
                    connection,
                    "CONSENT_RECORD",
                    str(consent_ref),
                    consent_version,
                )
                consent_expires_raw = consent.get("expires_at") if consent is not None else None
                consent_expires = (
                    datetime.fromisoformat(str(consent_expires_raw).replace("Z", "+00:00"))
                    if consent_expires_raw is not None
                    else None
                )
                if (
                    consent is None
                    or value_sha256(consent) != consent_sha256
                    or latest_consent_as_of.get(str(consent_ref))
                    != (consent_version, consent)
                    or consent.get("subject_token") != subject_token
                    or consent.get("status") != "GRANTED"
                    or consent.get("purpose") != purpose
                    or channel not in consent.get("channels", [])
                    or datetime.fromisoformat(
                        str(consent.get("effective_at", "")).replace("Z", "+00:00")
                    )
                    > evaluated
                    or (consent_expires is not None and evaluated >= consent_expires)
                ):
                    raise SchemaIntegrityError("contact consent binding failed")
                if conflicting_refs:
                    raise SchemaIntegrityError("contact decision mixes consent and conflict")
            elif "CONSENT_CONFLICT" in value.get("reason_codes", []):
                if consent_version is not None or consent_sha256 is not None:
                    raise SchemaIntegrityError("contact conflict has unexpected consent binding")
                scoped_active_refs = [
                    str(consent["record_id"])
                    for _, consent in active_scoped_consents
                ]
                if len(scoped_active_refs) < 2 or sorted(scoped_active_refs) != conflicting_refs:
                    raise SchemaIntegrityError("contact consent conflict binding failed")
                conflict_row = connection.execute(
                    "SELECT conflict_type,business_key,existing_sha256,proposed_sha256,"
                    "details_json FROM mdos_conflicts WHERE conflict_id=?",
                    (str(consent_conflict_ref or ""),),
                ).fetchone()
                expected_business_key = f"{subject_token}:{purpose}:{channel}"
                consent_by_id = {
                    str(consent["record_id"]): consent
                    for _, consent in active_scoped_consents
                }
                first_ref = conflicting_refs[0]
                expected_details = {
                    "conflicting_consent_refs": conflicting_refs,
                }
                if (
                    conflict_row is None
                    or str(conflict_row["conflict_type"]) != "CONSENT_CONFLICT"
                    or str(conflict_row["business_key"]) != expected_business_key
                    or str(conflict_row["existing_sha256"])
                    != value_sha256(consent_by_id[first_ref])
                    or str(conflict_row["proposed_sha256"])
                    != value_sha256(
                        {
                            record_id: consent_by_id[record_id]
                            for record_id in conflicting_refs[1:]
                        }
                    )
                    or json.loads(str(conflict_row["details_json"])) != expected_details
                ):
                    raise SchemaIntegrityError("contact consent conflict audit binding failed")
                resolved_as_of = connection.execute(
                    "SELECT 1 FROM mdos_ledger "
                    "WHERE record_type='CONFLICT_RESOLUTION' AND sequence < ? "
                    "AND json_extract(payload_json,'$.conflict_id')=? "
                    "AND json_extract(payload_json,'$.decision')='RESOLVED' LIMIT 1",
                    (int(as_of_sequence), str(consent_conflict_ref)),
                ).fetchone() is not None
                if resolved_as_of != (
                    "CONSENT_CONFLICT_RESOLVED_DENY" in value.get("reason_codes", [])
                ):
                    raise SchemaIntegrityError(
                        "contact consent arbitration status binding failed"
                    )
            else:
                consent_reason_codes = {
                    "CONSENT_MISSING",
                    "CONSENT_EXPIRED",
                    "CONSENT_REVOKED",
                    "CONSENT_NOT_GRANTED",
                    "CONSENT_SCOPE_MISMATCH",
                }
                if not all_subject_consents:
                    expected_consent_reason = "CONSENT_MISSING"
                elif not any(
                    consent.get("purpose") == purpose
                    and channel in consent.get("channels", [])
                    for consent in all_subject_consents
                ):
                    expected_consent_reason = "CONSENT_SCOPE_MISMATCH"
                elif not active_scoped_consents:
                    expected_consent_reason = "CONSENT_EXPIRED"
                elif len(active_scoped_consents) > 1:
                    raise SchemaIntegrityError("contact decision omitted consent conflict")
                else:
                    status = active_scoped_consents[0][1].get("status")
                    if status == "REVOKED":
                        expected_consent_reason = "CONSENT_REVOKED"
                    elif status == "NOT_GRANTED":
                        expected_consent_reason = "CONSENT_NOT_GRANTED"
                    else:
                        raise SchemaIntegrityError("contact decision omitted exact consent")
                actual_consent_reasons = consent_reason_codes.intersection(
                    value.get("reason_codes", [])
                )
                if (
                    consent_version is not None
                    or consent_sha256 is not None
                    or conflicting_refs
                    or actual_consent_reasons != {expected_consent_reason}
                ):
                    raise SchemaIntegrityError("contact consent denial reason is not exact")
            if "CONSENT_CONFLICT" not in value.get("reason_codes", []) and consent_conflict_ref is not None:
                raise SchemaIntegrityError("contact decision has unexpected consent conflict")
            if (
                "CONSENT_CONFLICT_RESOLVED_DENY" in value.get("reason_codes", [])
                and "CONSENT_CONFLICT" not in value.get("reason_codes", [])
            ):
                raise SchemaIntegrityError("contact decision has orphan arbitration reason")

        elif record_type == "BITRIX_PROJECTION_COMMAND":
            entry_bindings = (
                (
                    "DEMAND_UNIT",
                    "demand_unit_id",
                    "demand_unit_version",
                    "demand_unit_entry_id",
                    "demand_unit_sha256",
                ),
                (
                    "GOLD_ACCEPTANCE",
                    "gold_acceptance_id",
                    "gold_acceptance_version",
                    "gold_acceptance_entry_id",
                    "gold_acceptance_sha256",
                ),
                (
                    "ACTION_ASSIGNMENT",
                    "assignment_id",
                    None,
                    "assignment_entry_id",
                    "assignment_sha256",
                ),
                (
                    "PERMIT_DECISION",
                    "permit_decision_id",
                    None,
                    "permit_decision_entry_id",
                    "permit_decision_sha256",
                ),
                (
                    "CAPACITY_SNAPSHOT",
                    "capacity_snapshot_ref",
                    None,
                    "capacity_snapshot_entry_id",
                    "capacity_snapshot_sha256",
                ),
            )
            bound: dict[str, dict[str, Any]] = {}
            for (
                expected_type,
                aggregate_field,
                version_field,
                entry_field,
                sha_field,
            ) in entry_bindings:
                row = connection.execute(
                    "SELECT * FROM mdos_ledger WHERE entry_id=?",
                    (str(value.get(entry_field, "")),),
                ).fetchone()
                if (
                    row is None
                    or str(row["record_type"]) != expected_type
                    or str(row["aggregate_id"]) != str(value.get(aggregate_field, ""))
                    or (version_field is not None and int(row["aggregate_version"]) != int(value.get(version_field, 0)))
                    or str(row["payload_sha256"]) != str(value.get(sha_field, ""))
                ):
                    raise SchemaIntegrityError("projection command exact input binding failed")
                bound[expected_type] = json.loads(str(row["payload_json"]))
            demand = bound["DEMAND_UNIT"]
            gold = bound["GOLD_ACCEPTANCE"]
            assignment = bound["ACTION_ASSIGNMENT"]
            permit = bound["PERMIT_DECISION"]
            capacity = bound["CAPACITY_SNAPSHOT"]
            projection = value.get("projection")
            projection_deal = projection.get("deal") if isinstance(projection, dict) else None
            projection_task = projection.get("task") if isinstance(projection, dict) else None
            projection_authority = (
                projection.get("authority") if isinstance(projection, dict) else None
            )
            actor = self._actor_row(connection, str(value.get("enqueued_by", "")))
            actor_roles = (
                set(json.loads(str(actor["roles_json"]))) if actor is not None else set()
            )
            command_material = {
                "command_key": value.get("command_key"),
                "demand_unit_entry_id": value.get("demand_unit_entry_id"),
                "gold_acceptance_entry_id": value.get("gold_acceptance_entry_id"),
                "assignment_entry_id": value.get("assignment_entry_id"),
                "permit_decision_entry_id": value.get("permit_decision_entry_id"),
                "capacity_snapshot_entry_id": value.get("capacity_snapshot_entry_id"),
                "projection_sha256": value.get("projection_sha256"),
            }
            if (
                actor is None
                or str(actor["actor_type"]) != "SYSTEM"
                or "BITRIX_PROJECTION_WRITER" not in actor_roles
                or not isinstance(projection, dict)
                or value_sha256(projection) != value.get("projection_sha256")
                or value.get("projection_id")
                != f"bitrix-shadow-{str(value.get('projection_sha256', ''))[:32]}"
                or value.get("projection_key")
                != f"BITRIX_DEAL:{value.get('demand_unit_id')}"
                or value.get("command_key") != f"BITRIX_SHADOW:{value.get('projection_key')}"
                or value.get("command_id")
                != f"bitrix-command-{value_sha256(command_material)[:32]}"
                or demand.get("state") != "ACCEPTED_GDO"
                or demand.get("gold_acceptance_ref") != gold.get("gold_acceptance_id")
                or gold.get("decision") != "ACCEPTED"
                or assignment.get("status") != "APPROVED"
                or assignment.get("demand_unit_id") != demand.get("demand_unit_id")
                or assignment.get("permit_decision_ref") != permit.get("permit_decision_id")
                or assignment.get("permit_decision_sha256") != value_sha256(permit)
                or permit.get("decision") != "ALLOW"
                or value_sha256(permit) != value.get("permit_decision_sha256")
                or capacity.get("demand_unit_id") != demand.get("demand_unit_id")
                or value.get("scope")
                != {
                    "beachhead_profile_ref": None,
                    "region": capacity.get("region"),
                    "product_scope": demand.get("product_scope"),
                }
                or projection.get("mode") != "SHADOW"
                or projection.get("external_effect") is not False
                or not all(
                    isinstance(item, dict)
                    for item in (projection_deal, projection_task, projection_authority)
                )
                or projection_deal.get("external_key") != value.get("projection_key")
                or projection_deal.get("demand_unit_id") != demand.get("demand_unit_id")
                or projection_deal.get("gold_acceptance_ref")
                != gold.get("gold_acceptance_id")
                or projection_deal.get("scope_fingerprint")
                != demand.get("scope_fingerprint")
                or projection_task.get("assignment_id") != assignment.get("assignment_id")
                or projection_task.get("action_type") != assignment.get("action_type")
                or projection_authority.get("permit_decision_id")
                != permit.get("permit_decision_id")
                or projection_authority.get("permit_decision_sha256")
                != value_sha256(permit)
                or projection_authority.get("policy_version")
                != assignment.get("policy_version")
            ):
                raise SchemaIntegrityError("projection command accepted-work binding failed")
            enqueued_at = datetime.fromisoformat(
                str(value.get("enqueued_at", "")).replace("Z", "+00:00")
            )
            if not (
                datetime.fromisoformat(str(permit["issued_at"]).replace("Z", "+00:00"))
                <= enqueued_at
                < datetime.fromisoformat(str(permit["expires_at"]).replace("Z", "+00:00"))
            ):
                raise SchemaIntegrityError("projection command permit was not current at enqueue")

        elif record_type == "BITRIX_PROJECTION_CLAIM":
            command = self._payload_tx(
                connection, "BITRIX_PROJECTION_COMMAND", str(value.get("command_id", ""))
            )
            terminal_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_ledger WHERE sequence < ? AND "
                "record_type IN ('BITRIX_PROJECTION_RECEIPT','BITRIX_PROJECTION_DLQ') "
                "AND json_extract(payload_json,'$.command_id')=?",
                (int(as_of_sequence), str(value.get("command_id", ""))),
            ).fetchone()[0]
            actor = self._actor_row(connection, str(value.get("worker_id", "")))
            actor_roles = (
                set(json.loads(str(actor["roles_json"]))) if actor is not None else set()
            )
            claimed = datetime.fromisoformat(
                str(value.get("claimed_at", "")).replace("Z", "+00:00")
            )
            expires = datetime.fromisoformat(
                str(value.get("lease_expires_at", "")).replace("Z", "+00:00")
            )
            claim_material = {
                "command_id": value.get("command_id"),
                "attempt_no": value.get("attempt_no"),
                "worker_id": value.get("worker_id"),
                "claimed_at": value.get("claimed_at"),
                "lease_expires_at": value.get("lease_expires_at"),
            }
            expected_claim_id = f"bitrix-claim-{value_sha256(claim_material)[:32]}"
            expected_fence = value_sha256(
                {
                    "claim_id": expected_claim_id,
                    "command_id": value.get("command_id"),
                    "attempt_no": value.get("attempt_no"),
                    "worker_id": value.get("worker_id"),
                }
            )
            if (
                command is None
                or int(terminal_count) != 0
                or actor is None
                or str(actor["actor_type"]) != "SYSTEM"
                or "BITRIX_PROJECTION_WRITER" not in actor_roles
                or value.get("claim_id") != expected_claim_id
                or value.get("fencing_token") != expected_fence
                or expires <= claimed
                or (expires - claimed).total_seconds() != 30
            ):
                raise SchemaIntegrityError("projection claim authority/lease binding failed")
            for row in connection.execute(
                "SELECT payload_json FROM mdos_ledger "
                "WHERE record_type='BITRIX_PROJECTION_CLAIM'"
            ):
                other = json.loads(str(row[0]))
                if (
                    other.get("claim_id") != value.get("claim_id")
                    and other.get("command_id") == value.get("command_id")
                    and str(other.get("claimed_at")) <= str(value.get("claimed_at"))
                    and claimed < datetime.fromisoformat(
                        str(other.get("lease_expires_at", "")).replace("Z", "+00:00")
                    )
                ):
                    other_attempt = connection.execute(
                        "SELECT aggregate_id FROM mdos_ledger "
                        "WHERE record_type='BITRIX_PROJECTION_ATTEMPT' "
                        "AND json_extract(payload_json,'$.claim_id')=?",
                        (str(other.get("claim_id")),),
                    ).fetchone()
                    terminal = False
                    if other_attempt is not None:
                        terminal = connection.execute(
                            "SELECT 1 FROM mdos_ledger WHERE "
                            "(record_type='BITRIX_PROJECTION_RECEIPT' "
                            "AND json_extract(payload_json,'$.attempt_id')=?) OR "
                            "(record_type='BITRIX_PROJECTION_DLQ' "
                            "AND json_extract(payload_json,'$.claim_id')=?) LIMIT 1",
                            (str(other_attempt[0]), str(other.get("claim_id"))),
                        ).fetchone() is not None
                    if not terminal:
                        raise SchemaIntegrityError("projection claim overlaps active lease")

        elif record_type == "BITRIX_PROJECTION_ATTEMPT":
            command = self._payload_tx(
                connection, "BITRIX_PROJECTION_COMMAND", str(value.get("command_id", ""))
            )
            claim = self._payload_tx(
                connection, "BITRIX_PROJECTION_CLAIM", str(value.get("claim_id", ""))
            )
            attempt_material = {
                "claim_id": value.get("claim_id"),
                "command_id": value.get("command_id"),
                "attempt_no": value.get("attempt_no"),
            }
            started = datetime.fromisoformat(
                str(value.get("started_at", "")).replace("Z", "+00:00")
            )
            claimed = datetime.fromisoformat(
                str(claim.get("claimed_at", "")).replace("Z", "+00:00")
            ) if claim is not None else None
            lease_expires = datetime.fromisoformat(
                str(claim.get("lease_expires_at", "")).replace("Z", "+00:00")
            ) if claim is not None else None
            if (
                command is None
                or claim is None
                or claim.get("command_id") != value.get("command_id")
                or value.get("attempt_id")
                != f"bitrix-attempt-{value_sha256(attempt_material)[:32]}"
                or value.get("worker_id") != claim.get("worker_id")
                or value.get("attempt_no") != claim.get("attempt_no")
                or value.get("status") != "STARTED"
                or claimed is None
                or lease_expires is None
                or not (claimed <= started < lease_expires)
            ):
                raise SchemaIntegrityError("projection attempt claim binding failed")

        elif record_type == "BITRIX_PROJECTION_RECEIPT":
            command = self._payload_tx(
                connection, "BITRIX_PROJECTION_COMMAND", str(value.get("command_id", ""))
            )
            attempt = self._payload_tx(
                connection, "BITRIX_PROJECTION_ATTEMPT", str(value.get("attempt_id", ""))
            )
            claim = (
                self._payload_tx(
                    connection,
                    "BITRIX_PROJECTION_CLAIM",
                    str(attempt.get("claim_id", "")),
                )
                if attempt is not None
                else None
            )
            permit = (
                self._payload_tx(
                    connection,
                    "PERMIT_DECISION",
                    str(command.get("permit_decision_id", "")),
                )
                if command is not None
                else None
            )
            projection_row = connection.execute(
                "SELECT * FROM mdos_bitrix_shadow_projection WHERE projection_id=?",
                (str(value.get("projection_id", "")),),
            ).fetchone()
            completed = datetime.fromisoformat(
                str(value.get("completed_at", "")).replace("Z", "+00:00")
            )
            receipt_material = {
                "command_id": value.get("command_id"),
                "attempt_id": value.get("attempt_id"),
                "projection_sha256": value.get("projection_sha256"),
                "outcome": value.get("outcome"),
            }
            receipt_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_ledger "
                "WHERE record_type='BITRIX_PROJECTION_RECEIPT' "
                "AND json_extract(payload_json,'$.command_id')=? AND sequence < ?",
                (str(value.get("command_id", "")), int(as_of_sequence)),
            ).fetchone()[0]
            dlq_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_ledger "
                "WHERE record_type='BITRIX_PROJECTION_DLQ' "
                "AND json_extract(payload_json,'$.command_id')=? AND sequence < ?",
                (str(value.get("command_id", "")), int(as_of_sequence)),
            ).fetchone()[0]
            if (
                command is None
                or attempt is None
                or claim is None
                or permit is None
                or projection_row is None
                or int(receipt_count) != 0
                or int(dlq_count) != 0
                or value.get("receipt_id")
                != f"bitrix-receipt-{value_sha256(receipt_material)[:32]}"
                or value.get("worker_id") != attempt.get("worker_id")
                or value.get("projection_id") != command.get("projection_id")
                or value.get("projection_key") != command.get("projection_key")
                or value.get("projection_sha256") != command.get("projection_sha256")
                or value.get("readback_sha256") != command.get("projection_sha256")
                or str(projection_row["projection_sha256"])
                != str(command.get("projection_sha256"))
                or permit.get("decision") != "ALLOW"
                or value_sha256(permit) != command.get("permit_decision_sha256")
                or not (
                    datetime.fromisoformat(
                        str(permit.get("issued_at", "")).replace("Z", "+00:00")
                    )
                    <= completed
                    < datetime.fromisoformat(
                        str(permit.get("expires_at", "")).replace("Z", "+00:00")
                    )
                )
                or completed
                < datetime.fromisoformat(
                    str(attempt.get("started_at", "")).replace("Z", "+00:00")
                )
                or completed
                >= datetime.fromisoformat(
                    str(claim.get("lease_expires_at", "")).replace("Z", "+00:00")
                )
            ):
                raise SchemaIntegrityError("projection receipt readback binding failed")

        elif record_type == "BITRIX_PROJECTION_DLQ":
            command = self._payload_tx(
                connection, "BITRIX_PROJECTION_COMMAND", str(value.get("command_id", ""))
            )
            claim = self._payload_tx(
                connection, "BITRIX_PROJECTION_CLAIM", str(value.get("claim_id", ""))
            )
            dlq_material = {
                "command_id": value.get("command_id"),
                "claim_id": value.get("claim_id"),
                "reason_code": value.get("reason_code"),
            }
            attempt = connection.execute(
                "SELECT 1 FROM mdos_ledger "
                "WHERE record_type='BITRIX_PROJECTION_ATTEMPT' "
                "AND json_extract(payload_json,'$.claim_id')=? LIMIT 1",
                (str(value.get("claim_id", "")),),
            ).fetchone()
            receipt_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_ledger "
                "WHERE record_type='BITRIX_PROJECTION_RECEIPT' "
                "AND json_extract(payload_json,'$.command_id')=? AND sequence < ?",
                (str(value.get("command_id", "")), int(as_of_sequence)),
            ).fetchone()[0]
            dlq_count = connection.execute(
                "SELECT COUNT(*) FROM mdos_ledger "
                "WHERE record_type='BITRIX_PROJECTION_DLQ' "
                "AND json_extract(payload_json,'$.command_id')=? AND sequence < ?",
                (str(value.get("command_id", "")), int(as_of_sequence)),
            ).fetchone()[0]
            if (
                command is None
                or claim is None
                or attempt is None
                or claim.get("command_id") != value.get("command_id")
                or int(receipt_count) != 0
                or int(dlq_count) != 0
                or value.get("dlq_id")
                != f"bitrix-dlq-{value_sha256(dlq_material)[:32]}"
                or value.get("worker_id") != claim.get("worker_id")
            ):
                raise SchemaIntegrityError("projection DLQ claim binding failed")

        elif record_type == "OUTCOME_EVENT":
            outcome_type = value.get("outcome_type")
            if outcome_type == "CLEARED_PAYMENT":
                if not payment_transition:
                    raise SchemaIntegrityError(
                        "CLEARED_PAYMENT requires typed atomic payment transition"
                    )
                payment = self._payload_as_of_tx(
                    connection,
                    "PAYMENT_PROOF",
                    str(value.get("payment_proof_ref", "")),
                    int(as_of_sequence) - 1,
                )
                total, proofs, base_order, terms = self._settled_amount_tx(
                    connection,
                    str(value.get("distinct_order_id", "")),
                    int(as_of_sequence) - 1,
                )
                demand, source_event_ids = self._accepted_demand_sources_tx(
                    connection,
                    str(base_order.get("demand_unit_id", "")),
                    int(as_of_sequence) - 1,
                )
                outcome_recorded_time = self._utc_instant(
                    value.get("recorded_at"), "payment OutcomeEvent recorded_at"
                )
                outcome_ledger_time = self._utc_instant(
                    recorded_at_utc or value.get("recorded_at"),
                    "payment OutcomeEvent ledger time",
                )
                if (
                    payment is None
                    or payment.get("distinct_order_id") != value.get("distinct_order_id")
                    or not proofs
                    or proofs[-1][1].get("payment_proof_id")
                    != value.get("payment_proof_ref")
                    or total != self._amount(terms.get("amount"), "commercial terms amount")
                    or value.get("amount") != terms.get("amount")
                    or value.get("currency") != terms.get("currency")
                    or value.get("authoritative_class") != payment.get("authoritative_class")
                    or value.get("source_system") != payment.get("provider")
                    or value.get("event_time") != payment.get("value_at")
                    or value.get("demand_unit_id") != base_order.get("demand_unit_id")
                    or value.get("account_id") != base_order.get("account_id")
                    or value.get("motion") != demand.get("motion")
                    or value.get("original_source_ref") not in source_event_ids
                    or value.get("latest_source_ref") != payment.get("provider_event_id")
                    or self._utc_instant(
                        payment.get("verified_at"), "PaymentProof verified_at"
                    )
                    > outcome_recorded_time
                    or outcome_ledger_time != outcome_recorded_time
                ):
                    raise SchemaIntegrityError("payment OutcomeEvent truth binding failed")
            elif outcome_type == "FULFILLED":
                order_id = str(value.get("distinct_order_id", ""))
                fulfilment = self._payload_as_of_tx(
                    connection,
                    "FULFILMENT_RECORD",
                    str(value.get("latest_source_ref", "")),
                    int(as_of_sequence) - 1,
                )
                order = self._payload_as_of_tx(
                    connection,
                    "ORDER_RECORD",
                    order_id,
                    int(as_of_sequence) - 1,
                )
                total, proofs, base_order, terms = self._settled_amount_tx(
                    connection,
                    order_id,
                    int(as_of_sequence) - 1,
                )
                demand, source_event_ids = self._accepted_demand_sources_tx(
                    connection,
                    str(base_order.get("demand_unit_id", "")),
                    int(as_of_sequence) - 1,
                )
                terminal_payment_rows = connection.execute(
                    """SELECT payload_json FROM mdos_ledger
                       WHERE record_type='OUTCOME_EVENT'
                         AND json_extract(payload_json,'$.distinct_order_id')=?
                         AND json_extract(payload_json,'$.outcome_type')='CLEARED_PAYMENT'
                         AND sequence<? ORDER BY sequence""",
                    (order_id, int(as_of_sequence)),
                ).fetchall()
                terminal_payments = [
                    json.loads(str(row[0])) for row in terminal_payment_rows
                ]
                outcome_recorded_time = self._utc_instant(
                    value.get("recorded_at"), "fulfilment OutcomeEvent recorded_at"
                )
                outcome_ledger_time = self._utc_instant(
                    recorded_at_utc or value.get("recorded_at"),
                    "fulfilment OutcomeEvent ledger time",
                )
                if (
                    fulfilment is None
                    or order is None
                    or order.get("state") != "FULFILLED"
                    or fulfilment.get("distinct_order_id") != order_id
                    or len(terminal_payments) != 1
                    or not proofs
                    or total != self._amount(terms.get("amount"), "commercial terms amount")
                    or terminal_payments[0].get("payment_proof_ref")
                    != proofs[-1][1].get("payment_proof_id")
                    or value.get("payment_proof_ref")
                    != proofs[-1][1].get("payment_proof_id")
                    or value.get("demand_unit_id") != base_order.get("demand_unit_id")
                    or value.get("account_id") != base_order.get("account_id")
                    or value.get("amount") != terms.get("amount")
                    or value.get("currency") != terms.get("currency")
                    or value.get("event_time") != fulfilment.get("event_at")
                    or value.get("authoritative_class") != "FULFILMENT_LEDGER"
                    or value.get("source_system") != "LOCAL_FULFILMENT_LEDGER"
                    or value.get("reconciliation_state") != "RECONCILED"
                    or value.get("motion") != demand.get("motion")
                    or value.get("original_source_ref") not in source_event_ids
                    or self._utc_instant(
                        fulfilment.get("event_at"), "FulfilmentRecord event_at"
                    )
                    > outcome_recorded_time
                    or outcome_ledger_time != outcome_recorded_time
                ):
                    raise SchemaIntegrityError("fulfilment OutcomeEvent truth binding failed")
            if outcome_type in {"CLEARED_PAYMENT", "FULFILLED"}:
                duplicate_rows = connection.execute(
                    """SELECT payload_json FROM mdos_ledger
                       WHERE record_type='OUTCOME_EVENT'
                         AND json_extract(payload_json,'$.distinct_order_id')=?
                         AND json_extract(payload_json,'$.outcome_type')=?
                         AND sequence<=?""",
                    (
                        str(value.get("distinct_order_id", "")),
                        str(outcome_type),
                        int(as_of_sequence),
                    ),
                ).fetchall()
                if any(json.loads(str(row[0])) != value for row in duplicate_rows):
                    raise SchemaIntegrityError("duplicate terminal OutcomeEvent")

    @staticmethod
    def _delivery_id(
        *,
        idempotency_key: str,
        record_type: str,
        proposed_sha256: str,
        attempted_actor_id: str,
        trace_id: str,
        disposition: str,
    ) -> str:
        digest = value_sha256(
            {
                "idempotency_key": idempotency_key,
                "record_type": record_type,
                "proposed_sha256": proposed_sha256,
                "attempted_actor_id": attempted_actor_id,
                "trace_id": trace_id,
                "disposition": disposition,
            }
        )
        return f"delivery-{digest[:32]}"

    def _insert_delivery_tx(
        self,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        record_type: str,
        proposed_sha256: str,
        business_entry_id: str | None,
        disposition: str,
        attempted_actor_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> None:
        connection.execute(
            """INSERT OR IGNORE INTO mdos_delivery_receipts(
                   delivery_id,idempotency_key,record_type,proposed_payload_sha256,
                   business_entry_id,disposition,attempted_actor_id,trace_id,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                self._delivery_id(
                    idempotency_key=idempotency_key,
                    record_type=record_type,
                    proposed_sha256=proposed_sha256,
                    attempted_actor_id=attempted_actor_id,
                    trace_id=trace_id,
                    disposition=disposition,
                ),
                idempotency_key,
                record_type,
                proposed_sha256,
                business_entry_id,
                disposition,
                attempted_actor_id,
                trace_id,
                recorded_at_utc,
            ),
        )

    def _insert_denial_tx(
        self,
        connection: sqlite3.Connection,
        *,
        operation: str,
        actor_id: str,
        reason_code: str,
        payload_sha256: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> None:
        material = {
            "operation": operation,
            "attempted_actor_id": actor_id,
            "reason_code": reason_code,
            "payload_sha256": payload_sha256,
            "trace_id": trace_id,
        }
        denial_id = f"denial-{value_sha256(material)[:32]}"
        connection.execute(
            """INSERT OR IGNORE INTO mdos_denials(
                   denial_id,operation,attempted_actor_id,reason_code,payload_sha256,
                   trace_id,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                denial_id,
                operation,
                actor_id,
                reason_code,
                payload_sha256,
                trace_id,
                recorded_at_utc,
            ),
        )

    def append_record(self, **kwargs: Any) -> AppendResult:
        """Append an unprotected fixture transport record.

        Canonical MDOS records are accepted only through the guarded domain
        services, which call the private capability-bound entry point below.
        """

        return self._append_record(_domain_capability=None, **kwargs)

    def _append_domain_record(self, **kwargs: Any) -> AppendResult:
        return self._append_record(
            _domain_capability=self.__domain_write_capability,
            **kwargs,
        )

    def _append_domain_batch(
        self, records: Sequence[Mapping[str, Any]]
    ) -> tuple[AppendResult, ...]:
        """Append a non-payment guarded batch.

        Payment truth deliberately has no caller-supplied capability flag.  It
        can enter only through :meth:`commit_payment_transition`.
        """

        return self.__append_domain_batch(records)

    def commit_crm_outcome_claim(
        self,
        *,
        claim: Mapping[str, Any],
        reconciler_id: str,
        trace_id: str,
        delivery_attempt_recorded_at_utc: str,
    ) -> AppendResult:
        """Persist one evidence-bound, non-authoritative shadow CRM milestone.

        Callers cannot choose the aggregate identity, local version, idempotency
        key, role, or typed capability.  In particular, this method has no path
        to PaymentProof, paid OrderRecord revisions, or OutcomeEvent.
        """

        value = dict(claim)
        self.internal_contracts.validate("CRM_OUTCOME_CLAIM", value)
        delivery_attempt_recorded_at = _require_utc_z(
            delivery_attempt_recorded_at_utc,
            "delivery_attempt_recorded_at_utc",
        )
        if self._utc_instant(
            delivery_attempt_recorded_at, "CRM delivery attempt time"
        ) < self._utc_instant(value.get("recorded_at"), "CRM claim recorded_at"):
            raise SchemaIntegrityError(
                "CRM delivery attempt cannot predate the immutable business record"
            )
        aggregate_id = crm_shadow_claim_aggregate_id(value)
        idempotency_key = crm_shadow_claim_idempotency_key(value)
        proposed_sha = value_sha256(value)
        latest = self.latest_record("CRM_OUTCOME_CLAIM", aggregate_id)
        if latest is None:
            aggregate_version = 1
        else:
            latest_remote_version = int(latest["payload"].get("remote_version", 0))
            proposed_remote_version = int(value.get("remote_version", 0))
            if proposed_remote_version < latest_remote_version:
                raise AppendOnlyViolation("stale Bitrix remote version")
            if proposed_remote_version == latest_remote_version:
                if (
                    str(latest["idempotency_key"]) != idempotency_key
                    or str(latest["payload_sha256"]) != proposed_sha
                    or str(latest["writer_id"]) != reconciler_id
                ):
                    raise IdempotencyConflict(
                        "Bitrix remote version is already bound to another CRM claim"
                    )
                aggregate_version = int(latest["aggregate_version"])
            else:
                aggregate_version = int(latest["aggregate_version"]) + 1
        return self._append_record(
            record_type="CRM_OUTCOME_CLAIM",
            aggregate_id=aggregate_id,
            aggregate_version=aggregate_version,
            idempotency_key=idempotency_key,
            payload=value,
            writer_id=reconciler_id,
            required_role="RECONCILER",
            trace_id=trace_id,
            recorded_at_utc=delivery_attempt_recorded_at,
            _domain_capability=self.__domain_write_capability,
            _crm_claim_capability=self.__crm_claim_transition_capability,
        )

    def commit_payment_transition(
        self,
        *,
        payment_proof: Mapping[str, Any],
        order_update: Mapping[str, Any],
        outcome: Mapping[str, Any] | None,
        verifier_id: str,
        reconciler_id: str,
        trace_id: str,
    ) -> PaymentTransitionCommit:
        """Atomically persist one partial or terminal payment installment."""

        payment = dict(payment_proof)
        order = dict(order_update)
        outcome_value = dict(outcome) if outcome is not None else None
        payment_order_id = str(payment.get("distinct_order_id", ""))
        order_id = str(order.get("distinct_order_id", ""))
        if payment_order_id != order_id:
            raise SchemaIntegrityError(
                "payment proof and order update must reference the same order"
            )
        if payment.get("canonical_account_id") != order.get("account_id"):
            raise SchemaIntegrityError(
                "payment proof account must match the payment order"
            )
        state = str(order.get("state", ""))
        if state == "PAID_PARTIAL":
            if outcome_value is not None:
                raise SchemaIntegrityError("partial payment cannot emit CLEARED_PAYMENT")
        elif state == "PAID":
            if outcome_value is None or outcome_value.get("outcome_type") != "CLEARED_PAYMENT":
                raise SchemaIntegrityError("terminal payment requires CLEARED_PAYMENT")
            terminal_bindings = {
                "payment_proof_ref": payment.get("payment_proof_id"),
                "distinct_order_id": payment_order_id,
                "demand_unit_id": order.get("demand_unit_id"),
                "account_id": order.get("account_id"),
                "currency": payment.get("currency"),
                "authoritative_class": payment.get("authoritative_class"),
                "source_system": payment.get("provider"),
                "event_time": payment.get("value_at"),
                "latest_source_ref": payment.get("provider_event_id"),
            }
            if any(
                outcome_value.get(field) != expected
                for field, expected in terminal_bindings.items()
                ):
                raise SchemaIntegrityError(
                    "terminal outcome must exactly bind the current payment proof and order"
                )
        else:
            raise SchemaIntegrityError("typed payment transition requires PAID_PARTIAL or PAID")

        records: list[Mapping[str, Any]] = [
            {
                "record_type": "PAYMENT_PROOF",
                "aggregate_id": str(payment.get("payment_proof_id", "")),
                "aggregate_version": 1,
                "idempotency_key": (
                    f"payment-provider:{payment.get('provider')}:{payment.get('provider_event_id')}"
                ),
                "payload": payment,
                "writer_id": verifier_id,
                "required_role": "PAYMENT_VERIFIER",
                "trace_id": trace_id,
                "recorded_at_utc": str(payment.get("verified_at", "")),
            },
            {
                "record_type": "ORDER_RECORD",
                "aggregate_id": str(order.get("distinct_order_id", "")),
                "aggregate_version": int(order.get("version", 0)),
                "idempotency_key": f"order:{order.get('distinct_order_id')}:{order.get('version')}",
                "payload": order,
                "writer_id": verifier_id,
                "required_role": "PAYMENT_VERIFIER",
                "trace_id": trace_id,
                "recorded_at_utc": str(payment.get("verified_at", "")),
            },
        ]
        if outcome_value is not None:
            records.append(
                {
                    "record_type": "OUTCOME_EVENT",
                    "aggregate_id": str(outcome_value.get("outcome_event_id", "")),
                    "aggregate_version": 1,
                    "idempotency_key": f"outcome:{outcome_value.get('outcome_event_id')}",
                    "payload": outcome_value,
                    "writer_id": reconciler_id,
                    "required_role": "RECONCILER",
                    "trace_id": trace_id,
                    "recorded_at_utc": str(outcome_value.get("recorded_at", "")),
                }
            )
        results = self.__append_domain_batch(
            records,
            _payment_capability=self.__payment_transition_capability,
        )
        return PaymentTransitionCommit(
            payment=results[0],
            order=results[1],
            outcome=results[2] if len(results) == 3 else None,
        )

    def __append_domain_batch(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        _payment_capability: object | None = None,
    ) -> tuple[AppendResult, ...]:
        """Atomically append a prevalidated ordered commercial transition."""

        payment_transition = (
            _payment_capability is self.__payment_transition_capability
        )
        prepared: list[dict[str, Any]] = []
        for raw in records:
            item = dict(raw)
            for label in (
                "record_type",
                "aggregate_id",
                "idempotency_key",
                "writer_id",
                "required_role",
                "trace_id",
                "recorded_at_utc",
            ):
                if not str(item.get(label, "")).strip():
                    raise ValueError(f"{label} is required")
            item["aggregate_version"] = int(item["aggregate_version"])
            if item["aggregate_version"] < 1:
                raise ValueError("aggregate_version must be positive")
            item["recorded_at_utc"] = _require_utc_z(
                str(item["recorded_at_utc"]), "recorded_at_utc"
            )
            item["payload"] = dict(item["payload"])
            schema_name = RECORD_SCHEMAS.get(str(item["record_type"]))
            if schema_name is not None:
                self.contracts.validate(schema_name, item["payload"])
            elif str(item["record_type"]) in INTERNAL_SCHEMAS:
                self.internal_contracts.validate(str(item["record_type"]), item["payload"])
            elif str(item["record_type"]) in INTERNAL_RECORD_TYPES and (
                item["payload"].get("schema_version") != "1.0.0"
                or item["payload"].get("synthetic") is not True
                or item["payload"].get("canonical_kpi_eligible") is not False
            ):
                raise ValueError("internal fixture records must be synthetic and non-KPI")
            item["payload_json"] = canonical_json(item["payload"])
            item["payload_sha256"] = hashlib.sha256(
                item["payload_json"].encode("utf-8", "strict")
            ).hexdigest()
            prepared.append(item)

        results: list[AppendResult] = []
        with self.transaction() as connection:
            for item in prepared:
                record_type = str(item["record_type"])
                writer_id = str(item["writer_id"])
                role = str(item["required_role"]).strip().upper()
                allowed_roles = RECORD_WRITE_ROLES.get(record_type)
                if allowed_roles is None or role not in allowed_roles:
                    raise WriterRoleError(f"record type {record_type} cannot be written as {role}")
                self._require_actor_tx(connection, writer_id, role)
                existing = connection.execute(
                    "SELECT * FROM mdos_ledger WHERE idempotency_key=?",
                    (str(item["idempotency_key"]),),
                ).fetchone()
                existing_is_exact = existing is not None and (
                    str(existing["record_type"]) == record_type
                    and str(existing["aggregate_id"]) == str(item["aggregate_id"])
                    and int(existing["aggregate_version"])
                    == int(item["aggregate_version"])
                    and str(existing["payload_sha256"]) == item["payload_sha256"]
                    and str(existing["writer_id"]) == writer_id
                )
                next_sequence = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence),0)+1 FROM mdos_ledger"
                    ).fetchone()[0]
                )
                self._validate_domain_dependencies_tx(
                    connection,
                    record_type=record_type,
                    aggregate_id=str(item["aggregate_id"]),
                    aggregate_version=int(item["aggregate_version"]),
                    idempotency_key=str(item["idempotency_key"]),
                    payload=item["payload"],
                    writer_id=writer_id,
                    as_of_sequence=(
                        int(existing["sequence"])
                        if existing_is_exact
                        else next_sequence
                    ),
                    payment_transition=payment_transition,
                    recorded_at_utc=(
                        str(existing["recorded_at_utc"])
                        if existing_is_exact
                        else str(item["recorded_at_utc"])
                    ),
                )
                if existing is not None:
                    exact = (
                        str(existing["record_type"]) == record_type
                        and str(existing["aggregate_id"]) == str(item["aggregate_id"])
                        and int(existing["aggregate_version"])
                        == int(item["aggregate_version"])
                        and str(existing["payload_sha256"]) == item["payload_sha256"]
                        and str(existing["writer_id"]) == writer_id
                    )
                    if not exact:
                        raise IdempotencyConflict(
                            f"idempotency key {item['idempotency_key']} has a different effect"
                        )
                    self._insert_delivery_tx(
                        connection,
                        idempotency_key=str(item["idempotency_key"]),
                        record_type=record_type,
                        proposed_sha256=str(item["payload_sha256"]),
                        business_entry_id=str(existing["entry_id"]),
                        disposition="REPLAY",
                        attempted_actor_id=writer_id,
                        trace_id=str(item["trace_id"]),
                        recorded_at_utc=str(item["recorded_at_utc"]),
                    )
                    results.append(
                        AppendResult(
                            str(existing["entry_id"]),
                            str(existing["entry_sha256"]),
                            int(existing["sequence"]),
                            False,
                            "REPLAY",
                        )
                    )
                    continue
                latest = connection.execute(
                    """SELECT MAX(aggregate_version) FROM mdos_ledger
                       WHERE record_type=? AND aggregate_id=?""",
                    (record_type, str(item["aggregate_id"])),
                ).fetchone()[0]
                expected_version = 1 if latest is None else int(latest) + 1
                if int(item["aggregate_version"]) != expected_version:
                    raise AppendOnlyViolation(
                        f"{record_type}/{item['aggregate_id']} expected version "
                        f"{expected_version}, got {item['aggregate_version']}"
                    )
                previous_row = connection.execute(
                    "SELECT entry_sha256 FROM mdos_ledger ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous_sha = str(previous_row[0]) if previous_row else ZERO_SHA256
                base = {
                    "record_type": record_type,
                    "aggregate_id": str(item["aggregate_id"]),
                    "aggregate_version": int(item["aggregate_version"]),
                    "idempotency_key": str(item["idempotency_key"]),
                    "payload_sha256": str(item["payload_sha256"]),
                    "previous_entry_sha256": previous_sha,
                    "writer_id": writer_id,
                    "trace_id": str(item["trace_id"]),
                    "recorded_at_utc": str(item["recorded_at_utc"]),
                }
                entry_id = f"mdos-entry-{value_sha256(base)[:32]}"
                entry_sha = value_sha256({"entry_id": entry_id, **base})
                cursor = connection.execute(
                    """INSERT INTO mdos_ledger(
                           entry_id,record_type,aggregate_id,aggregate_version,
                           idempotency_key,payload_json,payload_sha256,
                           previous_entry_sha256,entry_sha256,writer_id,trace_id,recorded_at_utc
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        entry_id,
                        record_type,
                        str(item["aggregate_id"]),
                        int(item["aggregate_version"]),
                        str(item["idempotency_key"]),
                        str(item["payload_json"]),
                        str(item["payload_sha256"]),
                        previous_sha,
                        entry_sha,
                        writer_id,
                        str(item["trace_id"]),
                        str(item["recorded_at_utc"]),
                    ),
                )
                self._insert_delivery_tx(
                    connection,
                    idempotency_key=str(item["idempotency_key"]),
                    record_type=record_type,
                    proposed_sha256=str(item["payload_sha256"]),
                    business_entry_id=entry_id,
                    disposition="APPLIED",
                    attempted_actor_id=writer_id,
                    trace_id=str(item["trace_id"]),
                    recorded_at_utc=str(item["recorded_at_utc"]),
                )
                results.append(
                    AppendResult(
                        entry_id,
                        entry_sha,
                        int(cursor.lastrowid),
                        True,
                        "APPLIED",
                    )
                )
            if payment_transition and len({result.disposition for result in results}) != 1:
                raise IdempotencyConflict(
                    "payment transition cannot mix replay and applied effects"
                )
        return tuple(results)

    def _append_record(
        self,
        *,
        record_type: str,
        aggregate_id: str,
        aggregate_version: int,
        idempotency_key: str,
        payload: Mapping[str, Any],
        writer_id: str,
        required_role: str,
        trace_id: str,
        recorded_at_utc: str,
        _domain_capability: object | None,
        _crm_claim_capability: object | None = None,
    ) -> AppendResult:
        for label, value in (
            ("record_type", record_type),
            ("aggregate_id", aggregate_id),
            ("idempotency_key", idempotency_key),
            ("writer_id", writer_id),
            ("trace_id", trace_id),
        ):
            if not str(value or "").strip():
                raise ValueError(f"{label} is required")
        version = int(aggregate_version)
        if version < 1:
            raise ValueError("aggregate_version must be positive")
        recorded = _require_utc_z(recorded_at_utc, "recorded_at_utc")
        payload_value = dict(payload)
        payload_json = canonical_json(payload_value)
        proposed_sha = hashlib.sha256(payload_json.encode("utf-8", "strict")).hexdigest()
        schema_name = RECORD_SCHEMAS.get(record_type)
        try:
            if schema_name is not None:
                self.contracts.validate(schema_name, payload_value)
            elif record_type in INTERNAL_SCHEMAS:
                self.internal_contracts.validate(record_type, payload_value)
            elif record_type in INTERNAL_RECORD_TYPES and (
                payload_value.get("schema_version") != "1.0.0"
                or payload_value.get("synthetic") is not True
                or payload_value.get("canonical_kpi_eligible") is not False
            ):
                raise ValueError("internal fixture records must be synthetic and non-KPI")
        except Exception:
            self._record_preflight_denial(
                operation=f"append:{record_type}",
                record_type=record_type,
                idempotency_key=idempotency_key,
                attempted_actor_id=writer_id,
                reason_code="SCHEMA_VALIDATION_DENIED",
                payload_sha256=proposed_sha,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )
            raise
        conflict_error: Exception | None = None
        result: AppendResult | None = None
        crm_claim_transition = (
            _crm_claim_capability is self.__crm_claim_transition_capability
        )

        with self.transaction() as connection:
            allowed_roles = RECORD_WRITE_ROLES.get(record_type)
            existing = connection.execute(
                "SELECT * FROM mdos_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            existing_is_exact = existing is not None and (
                str(existing["record_type"]) == record_type
                and str(existing["aggregate_id"]) == aggregate_id
                and int(existing["aggregate_version"]) == version
                and str(existing["payload_sha256"]) == proposed_sha
                and str(existing["writer_id"]) == writer_id
            )
            next_sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM mdos_ledger"
                ).fetchone()[0]
            )
            try:
                if allowed_roles is None:
                    raise WriterRoleError(f"record type is not registered: {record_type}")
                if (
                    record_type in PROTECTED_RECORD_TYPES
                    and _domain_capability is not self.__domain_write_capability
                ):
                    raise WriterRoleError(
                        f"record type {record_type} requires a guarded domain service"
                    )
                canonical_role = str(required_role).strip().upper()
                if canonical_role not in allowed_roles:
                    raise WriterRoleError(
                        f"record type {record_type} cannot be written as {canonical_role}"
                    )
                self._require_actor_tx(connection, writer_id, canonical_role)
                if record_type in PROTECTED_RECORD_TYPES:
                    self._validate_domain_dependencies_tx(
                        connection,
                        record_type=record_type,
                        aggregate_id=aggregate_id,
                        aggregate_version=version,
                        idempotency_key=idempotency_key,
                        payload=payload_value,
                        writer_id=writer_id,
                        as_of_sequence=(
                            int(existing["sequence"])
                            if existing_is_exact
                            else next_sequence
                        ),
                        crm_claim_transition=crm_claim_transition,
                        recorded_at_utc=(
                            str(existing["recorded_at_utc"])
                            if existing_is_exact
                            else recorded
                        ),
                    )
            except (UnknownWriterError, WriterRoleError, SchemaIntegrityError) as exc:
                if isinstance(exc, UnknownWriterError):
                    reason = "UNKNOWN_WRITER"
                elif isinstance(exc, WriterRoleError):
                    reason = "WRITER_ROLE_DENIED"
                else:
                    reason = "DOMAIN_INVARIANT_DENIED"
                self._insert_denial_tx(
                    connection,
                    operation=f"append:{record_type}",
                    actor_id=writer_id,
                    reason_code=reason,
                    payload_sha256=proposed_sha,
                    trace_id=trace_id,
                    recorded_at_utc=recorded,
                )
                self._insert_delivery_tx(
                    connection,
                    idempotency_key=idempotency_key,
                    record_type=record_type,
                    proposed_sha256=proposed_sha,
                    business_entry_id=None,
                    disposition="DENIED",
                    attempted_actor_id=writer_id,
                    trace_id=trace_id,
                    recorded_at_utc=recorded,
                )
                conflict_error = exc
            if conflict_error is None:
                if existing is not None:
                    exact = (
                        str(existing["record_type"]) == record_type
                        and str(existing["aggregate_id"]) == aggregate_id
                        and int(existing["aggregate_version"]) == version
                        and str(existing["payload_sha256"]) == proposed_sha
                        and str(existing["writer_id"]) == writer_id
                    )
                    if exact:
                        self._insert_delivery_tx(
                            connection,
                            idempotency_key=idempotency_key,
                            record_type=record_type,
                            proposed_sha256=proposed_sha,
                            business_entry_id=str(existing["entry_id"]),
                            disposition="REPLAY",
                            attempted_actor_id=writer_id,
                            trace_id=trace_id,
                            recorded_at_utc=recorded,
                        )
                        result = AppendResult(
                            entry_id=str(existing["entry_id"]),
                            entry_sha256=str(existing["entry_sha256"]),
                            sequence=int(existing["sequence"]),
                            inserted=False,
                            disposition="REPLAY",
                        )
                    else:
                        details = {
                            "idempotency_key": idempotency_key,
                            "existing_entry_id": str(existing["entry_id"]),
                            "existing_record_type": str(existing["record_type"]),
                            "proposed_record_type": record_type,
                        }
                        self._insert_conflict_tx(
                            connection,
                            conflict_type="IDEMPOTENCY_KEY_REUSE",
                            business_key=idempotency_key,
                            existing_sha256=str(existing["payload_sha256"]),
                            proposed_sha256=proposed_sha,
                            details=details,
                            blocked_action=f"append:{record_type}",
                            writer_id=writer_id,
                            trace_id=trace_id,
                            recorded_at_utc=recorded,
                        )
                        self._insert_delivery_tx(
                            connection,
                            idempotency_key=idempotency_key,
                            record_type=record_type,
                            proposed_sha256=proposed_sha,
                            business_entry_id=str(existing["entry_id"]),
                            disposition="CONFLICT",
                            attempted_actor_id=writer_id,
                            trace_id=trace_id,
                            recorded_at_utc=recorded,
                        )
                        conflict_error = IdempotencyConflict(
                            f"idempotency key {idempotency_key} has a different effect"
                        )
                if existing is None:
                    latest = connection.execute(
                        """SELECT MAX(aggregate_version) FROM mdos_ledger
                           WHERE record_type=? AND aggregate_id=?""",
                        (record_type, aggregate_id),
                    ).fetchone()[0]
                    expected_version = 1 if latest is None else int(latest) + 1
                    if version != expected_version:
                        self._insert_denial_tx(
                            connection,
                            operation=f"append:{record_type}",
                            actor_id=writer_id,
                            reason_code="NON_SEQUENTIAL_AGGREGATE_VERSION",
                            payload_sha256=proposed_sha,
                            trace_id=trace_id,
                            recorded_at_utc=recorded,
                        )
                        self._insert_delivery_tx(
                            connection,
                            idempotency_key=idempotency_key,
                            record_type=record_type,
                            proposed_sha256=proposed_sha,
                            business_entry_id=None,
                            disposition="DENIED",
                            attempted_actor_id=writer_id,
                            trace_id=trace_id,
                            recorded_at_utc=recorded,
                        )
                        conflict_error = AppendOnlyViolation(
                            f"{record_type}/{aggregate_id} expected version {expected_version}, got {version}"
                        )
                    else:
                        previous = connection.execute(
                            "SELECT entry_sha256 FROM mdos_ledger ORDER BY sequence DESC LIMIT 1"
                        ).fetchone()
                        previous_sha = str(previous[0]) if previous else ZERO_SHA256
                        base = {
                            "record_type": record_type,
                            "aggregate_id": aggregate_id,
                            "aggregate_version": version,
                            "idempotency_key": idempotency_key,
                            "payload_sha256": proposed_sha,
                            "previous_entry_sha256": previous_sha,
                            "writer_id": writer_id,
                            "trace_id": trace_id,
                            "recorded_at_utc": recorded,
                        }
                        entry_id = f"mdos-entry-{value_sha256(base)[:32]}"
                        entry_sha = value_sha256({"entry_id": entry_id, **base})
                        cursor = connection.execute(
                            """INSERT INTO mdos_ledger(
                                   entry_id,record_type,aggregate_id,aggregate_version,
                                   idempotency_key,payload_json,payload_sha256,
                                   previous_entry_sha256,entry_sha256,writer_id,trace_id,recorded_at_utc
                               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (
                                entry_id,
                                record_type,
                                aggregate_id,
                                version,
                                idempotency_key,
                                payload_json,
                                proposed_sha,
                                previous_sha,
                                entry_sha,
                                writer_id,
                                trace_id,
                                recorded,
                            ),
                        )
                        sequence = int(cursor.lastrowid)
                        self._insert_delivery_tx(
                            connection,
                            idempotency_key=idempotency_key,
                            record_type=record_type,
                            proposed_sha256=proposed_sha,
                            business_entry_id=entry_id,
                            disposition="APPLIED",
                            attempted_actor_id=writer_id,
                            trace_id=trace_id,
                            recorded_at_utc=recorded,
                        )
                        result = AppendResult(entry_id, entry_sha, sequence, True, "APPLIED")

        if conflict_error is not None:
            raise conflict_error
        if result is None:
            raise MdosStoreError("append completed without a result")
        return result

    def _insert_conflict_tx(
        self,
        connection: sqlite3.Connection,
        *,
        conflict_type: str,
        business_key: str,
        existing_sha256: str,
        proposed_sha256: str,
        details: Mapping[str, Any],
        blocked_action: str,
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> str:
        material = {
            "conflict_type": conflict_type,
            "business_key": business_key,
            "existing_sha256": existing_sha256,
            "proposed_sha256": proposed_sha256,
            "details": dict(details),
            "blocked_action": blocked_action,
        }
        conflict_id = f"conflict-{value_sha256(material)[:32]}"
        connection.execute(
            """INSERT OR IGNORE INTO mdos_conflicts(
                   conflict_id,conflict_type,business_key,existing_sha256,proposed_sha256,
                   details_json,blocked_action,writer_id,trace_id,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                conflict_id,
                conflict_type,
                business_key,
                existing_sha256,
                proposed_sha256,
                canonical_json(dict(details)),
                blocked_action,
                writer_id,
                trace_id,
                recorded_at_utc,
            ),
        )
        return conflict_id

    def record_conflict(
        self,
        *,
        conflict_type: str,
        business_key: str,
        existing_sha256: str,
        proposed_sha256: str,
        details: Mapping[str, Any],
        blocked_action: str,
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> str:
        recorded = _require_utc_z(recorded_at_utc, "recorded_at_utc")
        with self.transaction() as connection:
            self._require_actor_tx(connection, writer_id, "RECONCILER")
            return self._insert_conflict_tx(
                connection,
                conflict_type=conflict_type,
                business_key=business_key,
                existing_sha256=existing_sha256,
                proposed_sha256=proposed_sha256,
                details=details,
                blocked_action=blocked_action,
                writer_id=writer_id,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )

    def record_denial(
        self,
        *,
        operation: str,
        attempted_actor_id: str,
        reason_code: str,
        payload_sha256: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> None:
        """Append an assurance-kernel denial even when no business row is written."""

        recorded = _require_utc_z(recorded_at_utc, "recorded_at_utc")
        with self.transaction() as connection:
            self._require_actor_tx(connection, KERNEL_ACTOR_ID, "ASSURANCE_KERNEL")
            self._insert_denial_tx(
                connection,
                operation=operation,
                actor_id=attempted_actor_id,
                reason_code=reason_code,
                payload_sha256=payload_sha256,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )

    def _record_preflight_denial(
        self,
        *,
        operation: str,
        record_type: str,
        idempotency_key: str,
        attempted_actor_id: str,
        reason_code: str,
        payload_sha256: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> None:
        with self.transaction() as connection:
            self._require_actor_tx(connection, KERNEL_ACTOR_ID, "ASSURANCE_KERNEL")
            self._insert_denial_tx(
                connection,
                operation=operation,
                actor_id=attempted_actor_id,
                reason_code=reason_code,
                payload_sha256=payload_sha256,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
            )
            self._insert_delivery_tx(
                connection,
                idempotency_key=idempotency_key,
                record_type=record_type,
                proposed_sha256=payload_sha256,
                business_entry_id=None,
                disposition="DENIED",
                attempted_actor_id=attempted_actor_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
            )

    def append_evidence(
        self,
        *,
        content: bytes,
        media_type: str,
        source_ref: str,
        synthetic: bool,
        writer_id: str,
        required_role: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> EvidenceResult:
        if not isinstance(content, bytes) or not content:
            raise ValueError("evidence content must be non-empty bytes")
        recorded = _require_utc_z(recorded_at_utc, "recorded_at_utc")
        digest = bytes_sha256(content)
        with self.transaction() as connection:
            canonical_role = str(required_role).strip().upper()
            if canonical_role not in EVIDENCE_WRITE_ROLES:
                raise WriterRoleError("evidence writer role is not allowed")
            self._require_actor_tx(connection, writer_id, canonical_role)
            existing = connection.execute(
                "SELECT content FROM mdos_evidence WHERE content_sha256=?", (digest,)
            ).fetchone()
            if existing is not None:
                if bytes(existing[0]) != content:
                    raise SchemaIntegrityError("content-addressed evidence collision")
                return EvidenceResult(digest, False)
            connection.execute(
                """INSERT INTO mdos_evidence(
                       content_sha256,content,media_type,source_ref,synthetic,
                       writer_id,trace_id,recorded_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    digest,
                    sqlite3.Binary(content),
                    str(media_type),
                    str(source_ref),
                    1 if synthetic else 0,
                    writer_id,
                    trace_id,
                    recorded,
                ),
            )
        return EvidenceResult(digest, True)

    def evidence(self, content_sha256: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT content_sha256,media_type,source_ref,synthetic,writer_id,
                          trace_id,recorded_at_utc,length(content) AS byte_length
                   FROM mdos_evidence WHERE content_sha256=?""",
                (content_sha256,),
            ).fetchone()
        return dict(row) if row else None

    def _write_bitrix_shadow_projection_tx(
        self,
        connection: sqlite3.Connection,
        *,
        projection_id: str,
        projection_key: str,
        demand_unit_id: str,
        projection: Mapping[str, Any],
        permit_decision_id: str,
        permit_decision_sha256: str,
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> tuple[bool, bool]:
        projection_json = canonical_json(dict(projection))
        projection_sha = hashlib.sha256(projection_json.encode("utf-8", "strict")).hexdigest()
        self._require_actor_tx(connection, writer_id, "BITRIX_PROJECTION_WRITER")
        projection_value = dict(projection)
        if (
            projection_value.get("schema_version") != "1.0.0"
            or projection_value.get("mode") != "SHADOW"
            or projection_value.get("external_effect") is not False
            or projection_id != f"bitrix-shadow-{projection_sha[:32]}"
        ):
            raise WriterRoleError("Bitrix projection is not a local shadow effect")
        deal = projection_value.get("deal")
        task = projection_value.get("task")
        authority = projection_value.get("authority")
        if not all(isinstance(item, dict) for item in (deal, task, authority)):
            raise SchemaIntegrityError("Bitrix projection shape is invalid")
        if (
            deal.get("demand_unit_id") != demand_unit_id
            or authority.get("permit_decision_id") != permit_decision_id
            or authority.get("permit_decision_sha256") != permit_decision_sha256
        ):
            raise SchemaIntegrityError("Bitrix projection column binding mismatch")
        demand_row = connection.execute(
            """SELECT payload_json FROM mdos_ledger
               WHERE record_type='DEMAND_UNIT' AND aggregate_id=?
               ORDER BY aggregate_version DESC LIMIT 1""",
            (demand_unit_id,),
        ).fetchone()
        permit_row = connection.execute(
            """SELECT payload_json FROM mdos_ledger
               WHERE record_type='PERMIT_DECISION' AND aggregate_id=?
               ORDER BY aggregate_version DESC LIMIT 1""",
            (permit_decision_id,),
        ).fetchone()
        if demand_row is None or permit_row is None:
            raise SchemaIntegrityError("Bitrix projection authority inputs are missing")
        demand_payload = json.loads(str(demand_row[0]))
        permit_payload = json.loads(str(permit_row[0]))
        if (
            demand_payload.get("state") != "ACCEPTED_GDO"
            or demand_payload.get("gold_acceptance_ref") != deal.get("gold_acceptance_ref")
            or demand_payload.get("scope_fingerprint") != deal.get("scope_fingerprint")
            or value_sha256(permit_payload) != permit_decision_sha256
            or demand_payload.get("lawful_next_action_ref") != permit_decision_id
        ):
            raise SchemaIntegrityError("Bitrix projection is not exact accepted work")
        gold_row = connection.execute(
            """SELECT payload_json FROM mdos_ledger
               WHERE record_type='GOLD_ACCEPTANCE' AND aggregate_id=?
               ORDER BY aggregate_version DESC LIMIT 1""",
            (str(deal.get("gold_acceptance_ref", "")),),
        ).fetchone()
        assignment_row = connection.execute(
            """SELECT payload_json FROM mdos_ledger
               WHERE record_type='ACTION_ASSIGNMENT' AND aggregate_id=?
               ORDER BY aggregate_version DESC LIMIT 1""",
            (str(task.get("assignment_id", "")),),
        ).fetchone()
        if gold_row is None or assignment_row is None:
            raise SchemaIntegrityError("Bitrix projection Gold/assignment inputs are missing")
        gold_payload = json.loads(str(gold_row[0]))
        assignment_payload = json.loads(str(assignment_row[0]))
        if (
            gold_payload.get("decision") != "ACCEPTED"
            or gold_payload.get("permit_decision_ref") != permit_decision_id
            or assignment_payload.get("status") != "APPROVED"
            or assignment_payload.get("permit_decision_sha256") != permit_decision_sha256
            or assignment_payload.get("demand_unit_id") != demand_unit_id
        ):
            raise SchemaIntegrityError("Bitrix projection input binding mismatch")
        existing = connection.execute(
            "SELECT * FROM mdos_bitrix_shadow_projection WHERE projection_key=?",
            (projection_key,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["projection_sha256"]) == projection_sha
                and str(existing["permit_decision_id"]) == permit_decision_id
                and str(existing["permit_decision_sha256"]) == permit_decision_sha256
            ):
                return False, False
            self._insert_conflict_tx(
                connection,
                conflict_type="BITRIX_PROJECTION_KEY_REUSE",
                business_key=projection_key,
                existing_sha256=str(existing["projection_sha256"]),
                proposed_sha256=projection_sha,
                details={"projection_id": projection_id, "demand_unit_id": demand_unit_id},
                blocked_action="BITRIX_SHADOW_PROJECTION",
                writer_id=writer_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
            )
            return False, True
        connection.execute(
            """INSERT INTO mdos_bitrix_shadow_projection(
                   projection_id,projection_key,demand_unit_id,projection_json,
                   projection_sha256,permit_decision_id,permit_decision_sha256,
                   mode,external_effect,writer_id,trace_id,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                projection_id,
                projection_key,
                demand_unit_id,
                projection_json,
                projection_sha,
                permit_decision_id,
                permit_decision_sha256,
                "SHADOW",
                0,
                writer_id,
                trace_id,
                recorded_at_utc,
            ),
        )
        return True, False

    def write_bitrix_shadow_projection(
        self,
        *,
        projection: Mapping[str, Any],
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
        **_: Any,
    ) -> bool:
        """Reject the obsolete direct sink; durable outbox completion is mandatory."""

        self.record_denial(
            operation="direct_bitrix_shadow_projection",
            attempted_actor_id=writer_id,
            reason_code="DURABLE_OUTBOX_REQUIRED",
            payload_sha256=value_sha256(dict(projection)),
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        raise WriterRoleError("direct Bitrix projection writes require the durable outbox")

    def complete_bitrix_shadow_outbox(
        self,
        *,
        projection_id: str,
        projection_key: str,
        demand_unit_id: str,
        projection: Mapping[str, Any],
        permit_decision_id: str,
        permit_decision_sha256: str,
        receipt: Mapping[str, Any],
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> tuple[bool, AppendResult]:
        """Atomically materialize one local projection and its terminal receipt."""

        recorded = _require_utc_z(recorded_at_utc, "recorded_at_utc")
        receipt_value = dict(receipt)
        receipt_sha = value_sha256(receipt_value)
        try:
            self.internal_contracts.validate("BITRIX_PROJECTION_RECEIPT", receipt_value)
        except Exception:
            self.record_denial(
                operation="bitrix_outbox_store_completion",
                attempted_actor_id=writer_id,
                reason_code="RECEIPT_SCHEMA_VALIDATION_DENIED",
                payload_sha256=receipt_sha,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )
            raise
        if receipt_value.get("completed_at") != recorded:
            self.record_denial(
                operation="bitrix_outbox_store_completion",
                attempted_actor_id=writer_id,
                reason_code="RECEIPT_TIME_MISMATCH",
                payload_sha256=receipt_sha,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )
            raise SchemaIntegrityError("projection receipt time must equal commit time")
        receipt_json = canonical_json(receipt_value)
        if hashlib.sha256(receipt_json.encode("utf-8", "strict")).hexdigest() != receipt_sha:
            raise SchemaIntegrityError("projection receipt canonical digest mismatch")
        receipt_id = str(receipt_value["receipt_id"])
        idempotency_key = f"bitrix-receipt:{receipt_id}"
        result: AppendResult | None = None
        inserted = False
        conflict_error: Exception | None = None
        try:
            authority_snapshot()
        except Exception as exc:
            self.record_denial(
                operation="bitrix_outbox_store_completion",
                attempted_actor_id=writer_id,
                reason_code="AUTHORITY_SNAPSHOT_INVALID",
                payload_sha256=receipt_sha,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )
            raise WriterRoleError("Bitrix outbox authority snapshot invalid") from exc
        command_row = self.latest_record(
            "BITRIX_PROJECTION_COMMAND", str(receipt_value.get("command_id", ""))
        )
        attempt_row = self.latest_record(
            "BITRIX_PROJECTION_ATTEMPT", str(receipt_value.get("attempt_id", ""))
        )
        command = command_row["payload"] if command_row is not None else None
        attempt = attempt_row["payload"] if attempt_row is not None else None
        claim_row = (
            self.latest_record(
                "BITRIX_PROJECTION_CLAIM", str(attempt.get("claim_id", ""))
            )
            if attempt is not None
            else None
        )
        claim = claim_row["payload"] if claim_row is not None else None
        permit_row = (
            self.latest_record(
                "PERMIT_DECISION", str(command.get("permit_decision_id", ""))
            )
            if command is not None
            else None
        )
        permit = permit_row["payload"] if permit_row is not None else None
        completed = datetime.fromisoformat(recorded.replace("Z", "+00:00"))
        exact_jit_binding = (
            command is not None
            and attempt is not None
            and claim is not None
            and permit is not None
            and receipt_value.get("worker_id") == writer_id
            and receipt_value.get("projection_id") == projection_id
            and receipt_value.get("projection_key") == projection_key
            and receipt_value.get("projection_sha256") == value_sha256(dict(projection))
            and command.get("projection_id") == projection_id
            and command.get("projection_key") == projection_key
            and command.get("demand_unit_id") == demand_unit_id
            and command.get("projection") == dict(projection)
            and command.get("permit_decision_id") == permit_decision_id
            and command.get("permit_decision_sha256") == permit_decision_sha256
            and permit.get("decision") == "ALLOW"
            and value_sha256(permit) == permit_decision_sha256
            and attempt.get("worker_id") == writer_id
            and claim.get("worker_id") == writer_id
            and datetime.fromisoformat(
                str(attempt.get("started_at", "")).replace("Z", "+00:00")
            )
            <= completed
            < datetime.fromisoformat(
                str(claim.get("lease_expires_at", "")).replace("Z", "+00:00")
            )
            and datetime.fromisoformat(
                str(permit.get("issued_at", "")).replace("Z", "+00:00")
            )
            <= completed
            < datetime.fromisoformat(
                str(permit.get("expires_at", "")).replace("Z", "+00:00")
            )
        )
        if not exact_jit_binding:
            self.record_denial(
                operation="bitrix_outbox_store_completion",
                attempted_actor_id=writer_id,
                reason_code="JIT_BINDING_DENIED",
                payload_sha256=receipt_sha,
                trace_id=trace_id,
                recorded_at_utc=recorded,
            )
            raise SchemaIntegrityError("projection receipt JIT binding failed")
        with self.transaction() as connection:
            self._require_actor_tx(connection, writer_id, "BITRIX_PROJECTION_WRITER")
            existing_receipt = connection.execute(
                "SELECT * FROM mdos_ledger WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing_receipt is not None:
                if (
                    str(existing_receipt["record_type"]) == "BITRIX_PROJECTION_RECEIPT"
                    and str(existing_receipt["aggregate_id"]) == receipt_id
                    and str(existing_receipt["payload_sha256"]) == receipt_sha
                    and str(existing_receipt["writer_id"]) == writer_id
                ):
                    result = AppendResult(
                        str(existing_receipt["entry_id"]),
                        str(existing_receipt["entry_sha256"]),
                        int(existing_receipt["sequence"]),
                        False,
                        "REPLAY",
                    )
                else:
                    self._insert_conflict_tx(
                        connection,
                        conflict_type="IDEMPOTENCY_KEY_REUSE",
                        business_key=idempotency_key,
                        existing_sha256=str(existing_receipt["payload_sha256"]),
                        proposed_sha256=receipt_sha,
                        details={"receipt_id": receipt_id},
                        blocked_action="BITRIX_SHADOW_PROJECTION",
                        writer_id=writer_id,
                        trace_id=trace_id,
                        recorded_at_utc=recorded,
                    )
                    conflict_error = IdempotencyConflict("Bitrix receipt key conflict")
            if existing_receipt is None:
                inserted, projection_conflict = self._write_bitrix_shadow_projection_tx(
                    connection,
                    projection_id=projection_id,
                    projection_key=projection_key,
                    demand_unit_id=demand_unit_id,
                    projection=projection,
                    permit_decision_id=permit_decision_id,
                    permit_decision_sha256=permit_decision_sha256,
                    writer_id=writer_id,
                    trace_id=trace_id,
                    recorded_at_utc=recorded,
                )
                if projection_conflict:
                    conflict_error = IdempotencyConflict(
                        "Bitrix shadow projection key conflict"
                    )
                else:
                    self._validate_domain_dependencies_tx(
                        connection,
                        record_type="BITRIX_PROJECTION_RECEIPT",
                        aggregate_version=1,
                        payload=receipt_value,
                        writer_id=writer_id,
                        as_of_sequence=int(
                            connection.execute(
                                "SELECT COALESCE(MAX(sequence),0)+1 FROM mdos_ledger"
                            ).fetchone()[0]
                        ),
                        recorded_at_utc=recorded,
                    )
                    previous = connection.execute(
                        "SELECT entry_sha256 FROM mdos_ledger ORDER BY sequence DESC LIMIT 1"
                    ).fetchone()
                    previous_sha = str(previous[0]) if previous else ZERO_SHA256
                    base = {
                        "record_type": "BITRIX_PROJECTION_RECEIPT",
                        "aggregate_id": receipt_id,
                        "aggregate_version": 1,
                        "idempotency_key": idempotency_key,
                        "payload_sha256": receipt_sha,
                        "previous_entry_sha256": previous_sha,
                        "writer_id": writer_id,
                        "trace_id": trace_id,
                        "recorded_at_utc": recorded,
                    }
                    entry_id = f"mdos-entry-{value_sha256(base)[:32]}"
                    entry_sha = value_sha256({"entry_id": entry_id, **base})
                    cursor = connection.execute(
                        """INSERT INTO mdos_ledger(
                               entry_id,record_type,aggregate_id,aggregate_version,
                               idempotency_key,payload_json,payload_sha256,
                               previous_entry_sha256,entry_sha256,writer_id,trace_id,
                               recorded_at_utc
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            entry_id,
                            "BITRIX_PROJECTION_RECEIPT",
                            receipt_id,
                            1,
                            idempotency_key,
                            receipt_json,
                            receipt_sha,
                            previous_sha,
                            entry_sha,
                            writer_id,
                            trace_id,
                            recorded,
                        ),
                    )
                    self._insert_delivery_tx(
                        connection,
                        idempotency_key=idempotency_key,
                        record_type="BITRIX_PROJECTION_RECEIPT",
                        proposed_sha256=receipt_sha,
                        business_entry_id=entry_id,
                        disposition="APPLIED",
                        attempted_actor_id=writer_id,
                        trace_id=trace_id,
                        recorded_at_utc=recorded,
                    )
                    result = AppendResult(
                        entry_id, entry_sha, int(cursor.lastrowid), True, "APPLIED"
                    )
        if conflict_error is not None:
            raise conflict_error
        if result is None:
            raise MdosStoreError("projection completion produced no receipt")
        return inserted, result

    def latest_record(self, record_type: str, aggregate_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT * FROM mdos_ledger WHERE record_type=? AND aggregate_id=?
                   ORDER BY aggregate_version DESC LIMIT 1""",
                (record_type, aggregate_id),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def record_version(
        self, record_type: str, aggregate_id: str, aggregate_version: int
    ) -> dict[str, Any] | None:
        """Return one immutable aggregate revision instead of resolving by latest time."""

        with self._connect() as connection:
            row = connection.execute(
                """SELECT * FROM mdos_ledger
                   WHERE record_type=? AND aggregate_id=? AND aggregate_version=?""",
                (record_type, aggregate_id, int(aggregate_version)),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def record_by_id(self, entry_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM mdos_ledger WHERE entry_id=?", (entry_id,)
            ).fetchone()
        return self._row_to_record(row) if row else None

    def find_payload(self, record_type: str, field: str, value: str) -> list[dict[str, Any]]:
        if not field.replace("_", "").isalnum():
            raise ValueError("invalid JSON field")
        with self._connect() as connection:
            rows = connection.execute(
                f"""SELECT * FROM mdos_ledger
                    WHERE record_type=? AND json_extract(payload_json, '$.{field}')=?
                    ORDER BY sequence""",
                (record_type, value),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def payment_proofs_for_order(
        self,
        distinct_order_id: str,
        *,
        through_sequence: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return the immutable proof set in ledger order, optionally as-of a sequence."""

        with self._connect() as connection:
            if through_sequence is None:
                rows = connection.execute(
                    """SELECT * FROM mdos_ledger
                       WHERE record_type='PAYMENT_PROOF'
                         AND json_extract(payload_json,'$.distinct_order_id')=?
                       ORDER BY sequence""",
                    (distinct_order_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT * FROM mdos_ledger
                       WHERE record_type='PAYMENT_PROOF'
                         AND json_extract(payload_json,'$.distinct_order_id')=?
                         AND sequence<=?
                       ORDER BY sequence""",
                    (distinct_order_id, int(through_sequence)),
                ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def records(self, record_type: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if record_type is None:
                rows = connection.execute("SELECT * FROM mdos_ledger ORDER BY sequence").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM mdos_ledger WHERE record_type=? ORDER BY sequence",
                    (record_type,),
                ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def delivery_receipts(self, idempotency_key: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT * FROM mdos_delivery_receipts WHERE idempotency_key=?
                   ORDER BY delivery_sequence""",
                (idempotency_key,),
            ).fetchall()
        return [dict(row) for row in rows]

    def conflicts(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mdos_conflicts ORDER BY conflict_sequence"
            ).fetchall()
        values = [dict(row) for row in rows]
        for value in values:
            value["details"] = json.loads(str(value.pop("details_json")))
        return values

    def denials(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM mdos_denials ORDER BY denial_sequence"
                ).fetchall()
            ]

    def shadow_projections(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM mdos_bitrix_shadow_projection ORDER BY projection_sequence"
            ).fetchall()
        values = [dict(row) for row in rows]
        for value in values:
            value["projection"] = json.loads(str(value.pop("projection_json")))
        return values

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["payload"] = json.loads(str(value.pop("payload_json")))
        return value

    def count(self, table: str) -> int:
        allowed = {
            "mdos_actor_registry",
            "mdos_evidence",
            "mdos_ledger",
            "mdos_delivery_receipts",
            "mdos_denials",
            "mdos_conflicts",
            "mdos_bitrix_shadow_projection",
            "mdos_schema_migrations",
        }
        if table not in allowed:
            raise ValueError("unknown MDOS table")
        with self._connect() as connection:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    @staticmethod
    def _actor_registry_from_db(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT * FROM mdos_actor_registry ORDER BY actor_id"
        ).fetchall()
        return [
            {
                "actor_id": str(row["actor_id"]),
                "actor_type": str(row["actor_type"]),
                "roles": json.loads(str(row["roles_json"])),
                "registered_at_utc": str(row["registered_at_utc"]),
                "registry_entry_sha256": str(row["registry_entry_sha256"]),
            }
            for row in rows
        ]

    @staticmethod
    def _semantic_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
        tables = (
            ("mdos_meta", "key"),
            ("mdos_schema_migrations", "version"),
            ("mdos_actor_registry", "actor_id"),
            ("mdos_evidence", "content_sha256"),
            ("mdos_ledger", "sequence"),
            ("mdos_delivery_receipts", "delivery_sequence"),
            ("mdos_denials", "denial_sequence"),
            ("mdos_conflicts", "conflict_sequence"),
            ("mdos_bitrix_shadow_projection", "projection_sequence"),
        )
        result: dict[str, Any] = {}
        for table, order_column in tables:
            rows = connection.execute(f"SELECT * FROM {table} ORDER BY {order_column}").fetchall()
            normalized: list[dict[str, Any]] = []
            for row in rows:
                value: dict[str, Any] = {}
                for key in row.keys():
                    cell = row[key]
                    value[key] = (
                        {"blob_sha256": bytes_sha256(bytes(cell)), "size": len(bytes(cell))}
                        if isinstance(cell, bytes)
                        else cell
                    )
                normalized.append(value)
            result[table] = normalized
        return result

    def verify_integrity(self) -> dict[str, Any]:
        migration_bytes = self._migration_path.read_bytes()
        if bytes_sha256(migration_bytes) != MIGRATION_SHA256:
            raise SchemaIntegrityError("MDOS migration artifact checksum drift")
        connection = self._connect()
        try:
            if int(connection.execute("PRAGMA application_id").fetchone()[0]) != APPLICATION_ID:
                raise SchemaIntegrityError("MDOS application_id mismatch")
            if int(connection.execute("PRAGMA user_version").fetchone()[0]) != SCHEMA_VERSION:
                raise SchemaIntegrityError("unsupported MDOS schema version")
            if str(connection.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
                raise SchemaIntegrityError("SQLite integrity_check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise SchemaIntegrityError("SQLite foreign key check failed")
            meta = {
                str(row[0]): str(row[1])
                for row in connection.execute("SELECT key,value FROM mdos_meta").fetchall()
            }
            expected_meta = {
                "schema_version": str(SCHEMA_VERSION),
                "contract_id": CONTRACT_ID,
                "package_version": PACKAGE_VERSION,
                "package_root_sha256": PACKAGE_ROOT_SHA256,
                "environment": "FIXTURE_SHADOW",
                "canonical_kpi_eligible": "0",
                "external_effects_enabled": "0",
                "active_beachhead_profile": "",
            }
            for key, expected in expected_meta.items():
                if meta.get(key) != expected:
                    raise SchemaIntegrityError(f"MDOS metadata mismatch: {key}")
            if meta.get("schema_fingerprint_sha256") != self._schema_fingerprint(connection):
                raise SchemaIntegrityError("MDOS schema object fingerprint drift")
            migration = connection.execute(
                "SELECT version,name,sql_sha256 FROM mdos_schema_migrations"
            ).fetchall()
            if [tuple(row) for row in migration] != [
                (SCHEMA_VERSION, MIGRATION_NAME, MIGRATION_SHA256)
            ]:
                raise SchemaIntegrityError("MDOS migration ledger drift")
            actors = self._actor_registry_from_db(connection)
            for actor in actors:
                material = {key: actor[key] for key in (
                    "actor_id", "actor_type", "roles", "registered_at_utc"
                )}
                if actor["registry_entry_sha256"] != value_sha256(material):
                    raise SchemaIntegrityError("actor registry entry digest mismatch")
                if actor["actor_type"] != "HUMAN" and HUMAN_ONLY_ROLES.intersection(actor["roles"]):
                    raise SchemaIntegrityError("non-human actor holds a human-only role")
                for role in actor["roles"]:
                    allowed_actor_types = ROLE_ACTOR_TYPES.get(role)
                    if (
                        allowed_actor_types is not None
                        and actor["actor_type"] not in allowed_actor_types
                    ):
                        raise SchemaIntegrityError("actor registry role/type policy failed")
            actor_registry_sha = value_sha256(actors)
            if meta.get("actor_registry_sha256") != actor_registry_sha:
                raise SchemaIntegrityError("actor registry root mismatch")
            actor_by_id = {actor["actor_id"]: actor for actor in actors}

            previous = ZERO_SHA256
            aggregate_versions: dict[tuple[str, str], int] = {}
            ledger_rows = connection.execute("SELECT * FROM mdos_ledger ORDER BY sequence").fetchall()
            payment_transition_sequences = self._payment_transition_sequences_tx(connection)
            crm_claim_transition_sequences = self._crm_claim_transition_sequences_tx(
                connection
            )
            for row in ledger_rows:
                payload = json.loads(str(row["payload_json"]), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
                record_type = str(row["record_type"])
                allowed_roles = RECORD_WRITE_ROLES.get(record_type)
                actor = actor_by_id.get(str(row["writer_id"]))
                if allowed_roles is None or actor is None:
                    raise SchemaIntegrityError("ledger record type/writer is not registered")
                exercised_roles = allowed_roles.intersection(actor["roles"])
                if not exercised_roles or not any(
                    actor["actor_type"] in ROLE_ACTOR_TYPES.get(role, {actor["actor_type"]})
                    for role in exercised_roles
                ):
                    raise SchemaIntegrityError("ledger writer role/type policy failed")
                schema_name = RECORD_SCHEMAS.get(record_type)
                if schema_name is not None:
                    self.contracts.validate(schema_name, payload)
                elif record_type in INTERNAL_SCHEMAS:
                    self.internal_contracts.validate(record_type, payload)
                elif record_type in INTERNAL_RECORD_TYPES and (
                    payload.get("schema_version") != "1.0.0"
                    or payload.get("synthetic") is not True
                    or payload.get("canonical_kpi_eligible") is not False
                ):
                    raise SchemaIntegrityError("internal ledger record is not fixture/non-KPI")
                if record_type in PROTECTED_RECORD_TYPES:
                    self._validate_domain_dependencies_tx(
                        connection,
                        record_type=record_type,
                        aggregate_id=str(row["aggregate_id"]),
                        aggregate_version=int(row["aggregate_version"]),
                        idempotency_key=str(row["idempotency_key"]),
                        payload=payload,
                        writer_id=str(row["writer_id"]),
                        as_of_sequence=int(row["sequence"]),
                        payment_transition=(
                            int(row["sequence"]) in payment_transition_sequences
                        ),
                        crm_claim_transition=(
                            int(row["sequence"]) in crm_claim_transition_sequences
                        ),
                        recorded_at_utc=str(row["recorded_at_utc"]),
                    )
                if canonical_json(payload) != str(row["payload_json"]):
                    raise SchemaIntegrityError("ledger payload is not canonical JSON")
                if value_sha256(payload) != str(row["payload_sha256"]):
                    raise SchemaIntegrityError("ledger payload digest mismatch")
                if str(row["previous_entry_sha256"]) != previous:
                    raise SchemaIntegrityError("ledger hash chain is broken")
                base = {
                    "record_type": str(row["record_type"]),
                    "aggregate_id": str(row["aggregate_id"]),
                    "aggregate_version": int(row["aggregate_version"]),
                    "idempotency_key": str(row["idempotency_key"]),
                    "payload_sha256": str(row["payload_sha256"]),
                    "previous_entry_sha256": previous,
                    "writer_id": str(row["writer_id"]),
                    "trace_id": str(row["trace_id"]),
                    "recorded_at_utc": str(row["recorded_at_utc"]),
                }
                expected_entry_id = f"mdos-entry-{value_sha256(base)[:32]}"
                expected_entry_sha = value_sha256({"entry_id": expected_entry_id, **base})
                if str(row["entry_id"]) != expected_entry_id or str(row["entry_sha256"]) != expected_entry_sha:
                    raise SchemaIntegrityError("ledger entry digest mismatch")
                aggregate_key = (str(row["record_type"]), str(row["aggregate_id"]))
                expected_version = aggregate_versions.get(aggregate_key, 0) + 1
                if int(row["aggregate_version"]) != expected_version:
                    raise SchemaIntegrityError("ledger aggregate version gap")
                aggregate_versions[aggregate_key] = expected_version
                previous = expected_entry_sha

            for row in connection.execute("SELECT * FROM mdos_evidence"):
                if bytes_sha256(bytes(row[1])) != str(row[0]):
                    raise SchemaIntegrityError("evidence content digest mismatch")
                evidence_actor = actor_by_id.get(str(row["writer_id"]))
                if evidence_actor is None or not EVIDENCE_WRITE_ROLES.intersection(
                    evidence_actor["roles"]
                ):
                    raise SchemaIntegrityError("evidence writer policy failed")

            for row in connection.execute("SELECT * FROM mdos_conflicts"):
                conflict_actor = actor_by_id.get(str(row["writer_id"]))
                if conflict_actor is None:
                    raise SchemaIntegrityError("conflict writer policy failed")
                details = json.loads(str(row["details_json"]))
                if canonical_json(details) != str(row["details_json"]):
                    raise SchemaIntegrityError("conflict details are not canonical JSON")
                conflict_material = {
                    "conflict_type": str(row["conflict_type"]),
                    "business_key": str(row["business_key"]),
                    "existing_sha256": str(row["existing_sha256"]),
                    "proposed_sha256": str(row["proposed_sha256"]),
                    "details": details,
                    "blocked_action": str(row["blocked_action"]),
                }
                if str(row["conflict_id"]) != (
                    f"conflict-{value_sha256(conflict_material)[:32]}"
                ):
                    raise SchemaIntegrityError("conflict identity digest mismatch")

            for row in connection.execute("SELECT * FROM mdos_denials"):
                denial_material = {
                    "operation": str(row["operation"]),
                    "attempted_actor_id": str(row["attempted_actor_id"]),
                    "reason_code": str(row["reason_code"]),
                    "payload_sha256": str(row["payload_sha256"]),
                    "trace_id": str(row["trace_id"]),
                }
                if str(row["denial_id"]) != f"denial-{value_sha256(denial_material)[:32]}":
                    raise SchemaIntegrityError("denial identity digest mismatch")

            for row in connection.execute("SELECT * FROM mdos_delivery_receipts"):
                expected_delivery_id = self._delivery_id(
                    idempotency_key=str(row["idempotency_key"]),
                    record_type=str(row["record_type"]),
                    proposed_sha256=str(row["proposed_payload_sha256"]),
                    attempted_actor_id=str(row["attempted_actor_id"]),
                    trace_id=str(row["trace_id"]),
                    disposition=str(row["disposition"]),
                )
                if str(row["delivery_id"]) != expected_delivery_id:
                    raise SchemaIntegrityError("delivery receipt identity digest mismatch")
                business_entry_id = row["business_entry_id"]
                if str(row["disposition"]) == "DENIED":
                    if business_entry_id is not None:
                        raise SchemaIntegrityError("denied delivery references a business effect")
                elif business_entry_id is None:
                    raise SchemaIntegrityError("non-denied delivery lacks a business effect")
                else:
                    business_row = connection.execute(
                        "SELECT * FROM mdos_ledger WHERE entry_id=?",
                        (str(business_entry_id),),
                    ).fetchone()
                    if (
                        business_row is None
                        or str(business_row["idempotency_key"])
                        != str(row["idempotency_key"])
                        or str(business_row["record_type"]) != str(row["record_type"])
                    ):
                        raise SchemaIntegrityError("delivery receipt business binding failed")
                    if str(row["disposition"]) in {"APPLIED", "REPLAY"} and (
                        str(business_row["payload_sha256"])
                        != str(row["proposed_payload_sha256"])
                    ):
                        raise SchemaIntegrityError("delivery receipt payload binding failed")

            for row in connection.execute("SELECT * FROM mdos_bitrix_shadow_projection"):
                projection = json.loads(str(row["projection_json"]))
                projection_actor = actor_by_id.get(str(row["writer_id"]))
                if (
                    str(row["mode"]) != "SHADOW"
                    or int(row["external_effect"]) != 0
                    or projection.get("mode") != "SHADOW"
                    or projection.get("external_effect") is not False
                    or value_sha256(projection) != str(row["projection_sha256"])
                    or projection_actor is None
                    or "BITRIX_PROJECTION_WRITER" not in projection_actor["roles"]
                    or projection_actor["actor_type"] != "SYSTEM"
                ):
                    raise SchemaIntegrityError("Bitrix shadow projection integrity failed")
                if str(row["projection_id"]) != (
                    f"bitrix-shadow-{str(row['projection_sha256'])[:32]}"
                ):
                    raise SchemaIntegrityError("Bitrix projection identity digest mismatch")
                deal = projection.get("deal")
                authority = projection.get("authority")
                if not isinstance(deal, dict) or not isinstance(authority, dict):
                    raise SchemaIntegrityError("Bitrix projection shape is invalid")
                demand = self._payload_tx(
                    connection, "DEMAND_UNIT", str(row["demand_unit_id"])
                )
                permit = self._payload_tx(
                    connection, "PERMIT_DECISION", str(row["permit_decision_id"])
                )
                if (
                    demand is None
                    or permit is None
                    or demand.get("state") != "ACCEPTED_GDO"
                    or deal.get("demand_unit_id") != row["demand_unit_id"]
                    or authority.get("permit_decision_id") != row["permit_decision_id"]
                    or value_sha256(permit) != row["permit_decision_sha256"]
                    or authority.get("permit_decision_sha256")
                    != row["permit_decision_sha256"]
                ):
                    raise SchemaIntegrityError("Bitrix projection authority binding failed")
                command_row = connection.execute(
                    "SELECT aggregate_id FROM mdos_ledger "
                    "WHERE record_type='BITRIX_PROJECTION_COMMAND' "
                    "AND json_extract(payload_json,'$.projection_id')=? "
                    "AND json_extract(payload_json,'$.projection_sha256')=?",
                    (str(row["projection_id"]), str(row["projection_sha256"])),
                ).fetchone()
                receipt_row = connection.execute(
                    "SELECT 1 FROM mdos_ledger "
                    "WHERE record_type='BITRIX_PROJECTION_RECEIPT' "
                    "AND json_extract(payload_json,'$.command_id')=? "
                    "AND json_extract(payload_json,'$.projection_id')=?",
                    (
                        str(command_row[0]) if command_row is not None else "",
                        str(row["projection_id"]),
                    ),
                ).fetchone()
                if command_row is None or receipt_row is None:
                    raise SchemaIntegrityError(
                        "Bitrix projection lacks durable command/terminal receipt"
                    )
            snapshot = self._semantic_snapshot(connection)
            semantic_sha = value_sha256(snapshot)
            counts = {table: len(rows) for table, rows in snapshot.items()}
            return {
                "schema_version": SCHEMA_VERSION,
                "package_root_sha256": PACKAGE_ROOT_SHA256,
                "actor_registry_sha256": actor_registry_sha,
                "schema_fingerprint_sha256": meta["schema_fingerprint_sha256"],
                "ledger_root_sha256": previous,
                "semantic_sha256": semantic_sha,
                "counts": counts,
            }
        except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, SchemaIntegrityError):
                raise
            raise SchemaIntegrityError("MDOS database verification failed") from exc
        finally:
            connection.close()

    def create_backup(
        self,
        destination: str | os.PathLike[str],
        *,
        created_at_utc: str,
    ) -> tuple[Path, Path]:
        created = _require_utc_z(created_at_utc, "created_at_utc")
        target = Path(destination).resolve()
        manifest_path = Path(str(target) + ".manifest.json")
        if target.exists() or manifest_path.exists():
            raise BackupIntegrityError("backup target already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        before = self.verify_integrity()
        partial = target.with_name(f".{target.name}.{uuid.uuid4().hex}.partial")
        source = self._connect()
        destination_connection = sqlite3.connect(str(partial), timeout=30)
        try:
            source.backup(destination_connection)
            destination_connection.commit()
        finally:
            destination_connection.close()
            source.close()
        candidate = MdosStore(partial)
        after = candidate.verify_integrity()
        if before != after:
            partial.unlink(missing_ok=True)
            raise BackupIntegrityError("backup semantic snapshot differs from source")
        os.replace(partial, target)
        manifest = {
            "schema_version": "1.0.0",
            "contract_id": CONTRACT_ID,
            "package_version": PACKAGE_VERSION,
            "package_root_sha256": PACKAGE_ROOT_SHA256,
            "created_at_utc": created,
            "database_sha256": file_sha256(target),
            "snapshot": after,
        }
        manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8", errors="strict")
        return target, manifest_path

    @classmethod
    def restore_verified(
        cls,
        backup: str | os.PathLike[str],
        destination: str | os.PathLike[str],
    ) -> "MdosStore":
        source_path = Path(backup).resolve()
        manifest_path = Path(str(source_path) + ".manifest.json")
        target = Path(destination).resolve()
        if target.exists():
            raise BackupIntegrityError("restore target already exists")
        if not source_path.is_file() or not manifest_path.is_file():
            raise BackupIntegrityError("complete backup set is missing")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackupIntegrityError("backup manifest is invalid") from exc
        if (
            manifest.get("contract_id") != CONTRACT_ID
            or manifest.get("package_version") != PACKAGE_VERSION
            or manifest.get("package_root_sha256") != PACKAGE_ROOT_SHA256
            or manifest.get("database_sha256") != file_sha256(source_path)
        ):
            raise BackupIntegrityError("backup authority or file digest mismatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(f".{target.name}.{uuid.uuid4().hex}.partial")
        source_connection = sqlite3.connect(str(source_path), timeout=30)
        destination_connection = sqlite3.connect(str(partial), timeout=30)
        try:
            source_connection.backup(destination_connection)
            destination_connection.commit()
        finally:
            destination_connection.close()
            source_connection.close()
        candidate = cls(partial)
        restored_snapshot = candidate.verify_integrity()
        if restored_snapshot != manifest.get("snapshot"):
            partial.unlink(missing_ok=True)
            raise BackupIntegrityError("restored semantic snapshot differs from backup manifest")
        os.replace(partial, target)
        return cls(target)


__all__ = [
    "ActorSpec",
    "AppendOnlyViolation",
    "AppendResult",
    "BackupIntegrityError",
    "EvidenceResult",
    "IdempotencyConflict",
    "MdosStore",
    "MdosStoreError",
    "PaymentTransitionCommit",
    "SchemaIntegrityError",
    "UnknownWriterError",
    "WriterRoleError",
    "canonical_json",
    "value_sha256",
]
