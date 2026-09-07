"""Immutable phase-2 reconciliation for the first commercial queue.

The phase-1 inspector proves that the pinned Wave 1 and AT-SITE intake facts
arrived intact.  This module proves their bounded offline evolution in one
schema-17 snapshot: one reviewed Site graph reaches an offline SCREENED
outcome, one independent AT-SRC-PAR graph keeps three evidence slices, and the
same semantic snapshot survives backup/restore.  It never grants a live
transport, writer, source-read, or FAST readiness capability.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping
import zipfile

from .commercial_spine import CommercialSpineError
from .crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphOutbox,
    GraphInvariantError,
)
from .cross_source_reconciliation import (
    CrossSourceApprovalBinding,
    CrossSourceExpectation,
    CrossSourceReconciliationError,
    CrossSourceReconciliationReport,
    reconcile_cross_source_object,
)
from .first_queue_snapshot import (
    FIRST_QUEUE_CONTRACT_VERSION,
    FIRST_QUEUE_EVIDENCE_MODE,
    FirstQueueQueueSnapshot,
    FirstQueueSiteSnapshot,
    FirstQueueSnapshotManifest,
    FirstQueueWave1Snapshot,
    _event_ledger,
    _read_connection,
    _schema_inventory,
    _site_snapshot,
    _snapshot,
    _wave1_snapshot,
    _queue_snapshot,
    validate_first_queue_manifest,
)
from .ids import address_hash, canonical_json, normalize_phone_ru, payload_hash
from .manual_import_v17_schema import MANUAL_IMPORT_V17_TABLES
from .recovery import RecoveryError, _validate_radar_evidence_records
from .reviewed_opportunity_bridge import (
    ReviewedOpportunityBridge,
    ReviewedOpportunityBridgeError,
)
from .site_commercial_bridge import (
    ApprovedSiteCommand,
    SiteCommercialBridge,
    SiteCommercialBridgeError,
    SiteCommercialPolicy,
    SiteOpportunityProjection,
    TrustedSiteApprovalReceipt,
)
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity
from .source_review_queue import (
    SourceReviewQueueIntegrityError,
    validate_source_review_queue_integrity,
)
from .store import CURRENT_SCHEMA_VERSION, FactoryStore


FIRST_QUEUE_RECONCILIATION_MANIFEST_VERSION = (
    "first-queue-reconciliation-manifest-v1"
)
FIRST_QUEUE_RECONCILIATION_REPORT_VERSION = (
    "first-queue-reconciliation-report-v1"
)
FIRST_QUEUE_RECOVERY_REPORT_VERSION = "first-queue-recovery-report-v1"
OFFLINE_CRM_ATTESTATION_VERSION = "offline-crm-graph-attestation-v1"
FIRST_QUEUE_RECONCILIATION_STATUS = "PASSED"
FIRST_QUEUE_REMAINING_FAST_COMPONENTS = (
    "BITRIX_GRAPH_BRIDGE_BINDINGS",
    "BITRIX_GRAPH_CANARY_1_TO_5",
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_REMOTE_ID = re.compile(r"[1-9][0-9]{0,31}")
_EPOCH_VALUE = re.compile(r"[0-9]{32}")
_CRM_ORDER = (COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE)
_REMOTE_TYPE = {
    COMPANY_CREATE: "company",
    CONTACT_CREATE: "contact",
    DEAL_CREATE: "deal",
    ACTIVITY_CREATE: "activity",
}
_EPOCH_KEYS = frozenset({"source_read_epoch", "manual_import_epoch"})
_CORE_TABLE_COUNTS = {
    "schema_meta": 7,
    "schema_migrations": 4,
    "source_records": 2,
    "source_lab_runs": 8,
    "source_lab_batches": 8,
    "source_lab_records": 23,
    "source_lab_record_observations": 23,
    "source_lab_identity_keys": 59,
    "source_lab_record_identity_links": 65,
    "source_lab_reviews": 23,
    "source_lab_review_resolutions": 4,
    "source_lab_opportunity_evidence_links": 4,
    "companies": 2,
    "contacts": 2,
    "projects": 2,
    "opportunities": 2,
    "opportunity_transitions": 3,
    "crm_outbox": 8,
    "crm_mappings": 3,
    "crm_inbox_events": 1,
    "crm_sync_state": 1,
    "interactions": 12,
    "human_tasks": 12,
    "radar_source_passports": 7,
    "radar_source_permissions": 7,
    "radar_source_access_permits": 7,
    "radar_source_access_usage": 7,
    "radar_source_evidence_receipts": 7,
    "radar_evidence_records": 17,
}
_PHASE2_EVENT_SUFFIX_COUNTS = {
    ("commercial_spine", "crm_outcome_processed"): 1,
    ("commercial_spine", "normalized_opportunity_created"): 2,
    ("commercial_spine", "opportunity_transitioned"): 1,
    ("construction_radar", "radar_source_passport_registered"): 3,
    ("construction_radar_access", "radar_source_access_permit_issued"): 3,
    ("construction_radar_access", "radar_source_evidence_recorded"): 3,
    ("construction_radar_evidence", "construction_radar_evidence_stored"): 5,
    ("crm_graph_outbox", "crm_graph_operation_sent"): 4,
    ("crm_graph_outbox", "crm_graph_operation_staged"): 8,
    (
        "first_queue_offline_crm_fixture",
        "offline_crm_graph_operation_attested",
    ): 4,
    ("human_task_controller", "human_task_acknowledged"): 1,
    ("human_task_controller", "human_task_completed"): 1,
    ("human_task_controller", "human_task_first_action"): 1,
    ("reviewed_opportunity_bridge", "reviewed_opportunity_staged"): 1,
    (
        "source_commercial_bridge",
        "source_commercial_approved_link_anchored",
    ): 3,
    ("source_lab", "source_lab_opportunity_evidence_linked"): 4,
    ("source_lab", "source_lab_record_ingested"): 3,
    ("source_lab", "source_lab_review_requested"): 3,
    ("source_lab", "source_lab_review_resolved"): 4,
    ("source_lab_review_queue", "source_lab_review_claimed"): 4,
    (
        "source_lab_review_queue",
        "source_lab_review_resolution_recorded",
    ): 4,
}
_BACKUP_MANIFEST_KEYS = frozenset(
    {
        "backup",
        "counts",
        "created_at_utc",
        "duration_ms",
        "environment",
        "evidence",
        "evidence_archive",
        "evidence_sha256",
        "external_source_reads_enabled",
        "external_writers_enabled",
        "manual_import_commits_enabled",
        "manual_import_epoch_hash",
        "manual_import_ledger",
        "ok",
        "pragma_user_version",
        "radar_evidence_ledger",
        "schema_meta_version",
        "schema_migrations",
        "schema_version",
        "sha256",
        "source_lab_ledger",
        "source_read_epoch_hash",
    }
)
_RESTORE_REPORT_KEYS = frozenset(
    {
        "backup",
        "counts",
        "duration_ms",
        "evidence",
        "external_source_reads_enabled",
        "external_writers_enabled",
        "mail_restore_fence",
        "manual_import_commits_enabled",
        "manual_import_epoch_hash",
        "manual_import_epoch_rotated",
        "manual_import_ledger",
        "ok",
        "pragma_user_version",
        "radar_evidence_ledger",
        "restored",
        "restored_evidence",
        "schema_meta_version",
        "schema_migrations",
        "schema_version",
        "source_lab_ledger",
        "source_read_epoch_hash",
        "source_read_epoch_rotated",
    }
)


class FirstQueueReconciliationError(RuntimeError):
    """Base error with deliberately non-sensitive messages."""


class FirstQueueReconciliationManifestError(FirstQueueReconciliationError, ValueError):
    """The externally pinned reconciliation manifest is malformed."""


class FirstQueueReconciliationConflict(FirstQueueReconciliationError):
    """The immutable snapshot does not match the declared reconciliation."""


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueDatabaseFingerprint:
    schema_object_count: int
    schema_inventory_hash: str
    event_count: int
    event_ledger_hash: str
    event_head_rowid: int
    event_head_id: str
    event_head_payload_hash: str
    semantic_row_count: int
    semantic_ledger_hash: str
    table_counts: tuple[tuple[str, int], ...]

    def __repr__(self) -> str:
        return "FirstQueueDatabaseFingerprint(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueOfflineOperationAttestation:
    attestation_version: str
    transport_mode: str
    fixture_id: str
    transport_version: str
    execution_id: str
    operation_id: str
    operation_type: str
    request_hash: str
    readback_hash: str
    remote_entity_type: str
    remote_entity_id: str
    sent_event_id: str
    sent_event_payload_hash: str
    occurred_at_utc: str
    actor: str
    evidence_ref: str
    fixture_transport_invoked: bool
    live_provider_called: bool
    network_calls: int
    external_writes_performed: int
    declared_attestation_hash: str
    event_id: str
    event_payload_hash: str

    def __repr__(self) -> str:
        return "FirstQueueOfflineOperationAttestation(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueSiteCommercialExpectation:
    policy: SiteCommercialPolicy
    approval_receipt: TrustedSiteApprovalReceipt
    bridge_actor: str
    bridge_idempotency_key: str
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    evidence_link_id: str
    anchor_event_id: str
    lf_company_id: str
    lf_contact_id: str
    lf_project_id: str
    lf_opportunity_id: str
    attestations: tuple[FirstQueueOfflineOperationAttestation, ...]

    def __repr__(self) -> str:
        return "FirstQueueSiteCommercialExpectation(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueOutcomeExpectation:
    inbox_event_id: str
    remote_entity_type: str
    remote_entity_id: str
    remote_version: int
    event_type: str
    raw_payload_hash: str
    dedupe_key: str
    envelope_hash: str
    evidence_ref: str
    received_at_utc: str
    actor: str
    lf_opportunity_id: str
    transition_id: str

    def __repr__(self) -> str:
        return "FirstQueueOutcomeExpectation(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueReconciliationManifest:
    manifest_version: str
    contract_version: str
    evidence_mode: str
    schema_version: int
    baseline_manifest: FirstQueueSnapshotManifest
    baseline_report_hash: str
    baseline_semantic_hash: str
    baseline_event_head_rowid: int
    baseline_event_head_id: str
    baseline_event_head_payload_hash: str
    final_fingerprint: FirstQueueDatabaseFingerprint
    site_commercial: FirstQueueSiteCommercialExpectation
    cross_source: CrossSourceExpectation
    outcome: FirstQueueOutcomeExpectation
    declared_manifest_hash: str

    def __repr__(self) -> str:
        return "FirstQueueReconciliationManifest(<redacted>)"


@dataclass(frozen=True, slots=True)
class FirstQueueSiteCommercialSnapshot:
    source_record_id: str
    review_id: str
    resolution_id: str
    evidence_link_id: str
    anchor_event_id: str
    lf_company_id: str
    lf_contact_id: str
    lf_project_id: str
    lf_opportunity_id: str
    crm_operation_ids: tuple[str, ...]
    crm_remote_bindings: tuple[tuple[str, str], ...]
    attestation_event_ids: tuple[str, ...]
    graph_hash: str


@dataclass(frozen=True, slots=True)
class FirstQueueOutcomeSnapshot:
    inbox_event_id: str
    transition_id: str
    lf_opportunity_id: str
    remote_entity_type: str
    remote_entity_id: str
    state: str
    opportunity_state: str
    outcome_hash: str


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueReconciliationReport:
    report_version: str
    report_hash: str
    manifest_hash: str
    status: str
    criterion_42_3_6_passed: bool
    fast_commercial_slice_ready: bool
    remaining_fast_components: tuple[str, ...]
    baseline_manifest_hash: str
    baseline_report_hash: str
    baseline_semantic_hash: str
    baseline_event_prefix_verified: bool
    schema_version: int
    database_sha256: str
    database_size_bytes: int
    database_mtime_ns: int
    final_fingerprint: FirstQueueDatabaseFingerprint
    site: FirstQueueSiteSnapshot
    wave1: tuple[FirstQueueWave1Snapshot, ...]
    queue: FirstQueueQueueSnapshot
    site_commercial: FirstQueueSiteCommercialSnapshot
    cross_source: CrossSourceReconciliationReport
    outcome: FirstQueueOutcomeSnapshot
    external_writers_enabled: bool
    external_source_reads_enabled: bool
    manual_import_commits_enabled: bool
    source_read_epoch_hash: str
    next_source_read_epoch_hash: str
    manual_import_epoch_hash: str
    next_manual_import_epoch_hash: str
    radar_evidence_ledger_hash: str
    source_lab_ledger_hash: str
    manual_import_ledger_hash: str
    query_only: bool
    sidecars_absent: bool
    source_unchanged: bool
    inspection_live_calls: int
    inspection_external_writes: int
    historical_offline_fixture_operations: int
    semantic_hash: str

    def __repr__(self) -> str:
        return (
            "FirstQueueReconciliationReport("
            f"status={self.status!r}, schema_version={self.schema_version!r}, "
            "content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueRecoveryReport:
    report_version: str
    report_hash: str
    manifest_hash: str
    status: str
    criterion_42_3_6_passed: bool
    fast_commercial_slice_ready: bool
    semantic_hash: str
    source_report_hash: str
    backup_report_hash: str
    restored_report_hash: str
    source_database_sha256: str
    backup_database_sha256: str
    restored_database_sha256: str
    source_read_epoch_rotated: bool
    manual_import_epoch_rotated: bool
    external_writers_enabled: bool
    external_source_reads_enabled: bool
    manual_import_commits_enabled: bool

    def __repr__(self) -> str:
        return "FirstQueueRecoveryReport(status='PASSED', content=<redacted>)"


def _safe_id(value: object, message: str) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise FirstQueueReconciliationManifestError(message)
    return value


def _digest(value: object, message: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise FirstQueueReconciliationManifestError(message)
    return value


def _utc_seconds(value: object, message: str) -> str:
    if type(value) is not str or not _UTC_SECONDS.fullmatch(value):
        raise FirstQueueReconciliationManifestError(message)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise FirstQueueReconciliationManifestError(message) from None
    return value


def _evidence_ref(value: object, message: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 512
        or "://" not in value
        or "?" in value
        or "@" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise FirstQueueReconciliationManifestError(message)
    return value


def _positive_int(value: object, message: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise FirstQueueReconciliationManifestError(message)
    return value


def _plain(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    if type(value) is list:
        return [_plain(item) for item in value]
    if type(value) is dict:
        return {str(key): _plain(item) for key, item in value.items()}
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise FirstQueueReconciliationManifestError(
        "first queue reconciliation value is not canonical"
    )


def _attestation_body(
    value: FirstQueueOfflineOperationAttestation,
) -> dict[str, object]:
    if type(value) is not FirstQueueOfflineOperationAttestation:
        raise FirstQueueReconciliationManifestError(
            "offline CRM attestation type is invalid"
        )
    if (
        value.attestation_version != OFFLINE_CRM_ATTESTATION_VERSION
        or value.transport_mode != FIRST_QUEUE_EVIDENCE_MODE
        or type(value.fixture_transport_invoked) is not bool
        or value.fixture_transport_invoked is not True
        or type(value.live_provider_called) is not bool
        or value.live_provider_called is not False
        or type(value.network_calls) is not int
        or value.network_calls != 0
        or type(value.external_writes_performed) is not int
        or value.external_writes_performed != 0
    ):
        raise FirstQueueReconciliationManifestError(
            "offline CRM attestation boundary is invalid"
        )
    for item in (
        value.fixture_id,
        value.transport_version,
        value.execution_id,
        value.operation_id,
        value.sent_event_id,
        value.actor,
        value.event_id,
    ):
        _safe_id(item, "offline CRM attestation identity is invalid")
    _evidence_ref(value.evidence_ref, "offline CRM attestation evidence is invalid")
    _utc_seconds(value.occurred_at_utc, "offline CRM attestation time is invalid")
    for item in (
        value.request_hash,
        value.readback_hash,
        value.sent_event_payload_hash,
        value.event_payload_hash,
    ):
        _digest(item, "offline CRM attestation hash is invalid")
    if (
        value.operation_type not in _CRM_ORDER
        or value.remote_entity_type != _REMOTE_TYPE[value.operation_type]
        or type(value.remote_entity_id) is not str
        or not _REMOTE_ID.fullmatch(value.remote_entity_id)
    ):
        raise FirstQueueReconciliationManifestError(
            "offline CRM attestation operation is invalid"
        )
    return {
        "attestation_version": value.attestation_version,
        "transport_mode": value.transport_mode,
        "fixture_id": value.fixture_id,
        "transport_version": value.transport_version,
        "execution_id": value.execution_id,
        "operation_id": value.operation_id,
        "operation_type": value.operation_type,
        "request_hash": value.request_hash,
        "readback_hash": value.readback_hash,
        "remote_entity_type": value.remote_entity_type,
        "remote_entity_id": value.remote_entity_id,
        "sent_event_id": value.sent_event_id,
        "sent_event_payload_hash": value.sent_event_payload_hash,
        "occurred_at_utc": value.occurred_at_utc,
        "actor": value.actor,
        "evidence_ref": value.evidence_ref,
        "fixture_transport_invoked": True,
        "live_provider_called": False,
        "network_calls": 0,
        "external_writes_performed": 0,
    }


def offline_operation_attestation_payload(
    value: FirstQueueOfflineOperationAttestation,
) -> dict[str, object]:
    body = _attestation_body(value)
    declared = payload_hash(body)
    if value.declared_attestation_hash != declared:
        raise FirstQueueReconciliationManifestError(
            "offline CRM attestation declared hash is invalid"
        )
    return {**body, "declared_attestation_hash": declared}


def _normalize_db_value(table: str, column: str, value: object) -> object:
    if table == "schema_meta" and column == "value":
        return value
    if value is None or type(value) in (str, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise FirstQueueReconciliationConflict(
                "first queue database contains a non-finite value"
            )
        return value
    if type(value) is bytes:
        return {
            "blob_size": len(value),
            "blob_sha256": hashlib.sha256(value).hexdigest(),
        }
    raise FirstQueueReconciliationConflict(
        "first queue database contains an unsupported value"
    )


def _semantic_ledger_tx(
    con: sqlite3.Connection,
) -> tuple[int, str, tuple[tuple[str, int], ...]]:
    table_rows = con.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    ledger: list[dict[str, object]] = []
    table_counts: list[tuple[str, int]] = []
    total = 0
    for table_row in table_rows:
        table = str(table_row["name"])
        if not _IDENTIFIER.fullmatch(table):
            raise FirstQueueReconciliationConflict(
                "first queue table inventory is invalid"
            )
        columns = [
            str(row["name"])
            for row in con.execute(f'PRAGMA table_info("{table}")').fetchall()
        ]
        if not columns:
            raise FirstQueueReconciliationConflict(
                "first queue table inventory is invalid"
            )
        rows = con.execute(f'SELECT * FROM "{table}"').fetchall()
        row_hashes: list[str] = []
        for row in rows:
            body: dict[str, object] = {}
            for column in columns:
                value = row[column]
                if (
                    table == "schema_meta"
                    and column == "value"
                    and str(row["key"]) in _EPOCH_KEYS
                ):
                    value = "<ROTATED_EPOCH>"
                body[column] = _normalize_db_value(table, column, value)
            row_hashes.append(payload_hash(body))
        row_hashes.sort()
        count = len(row_hashes)
        total += count
        table_counts.append((table, count))
        ledger.append(
            {
                "table": table,
                "row_count": count,
                "row_hashes_hash": payload_hash(row_hashes),
            }
        )
    if not ledger:
        raise FirstQueueReconciliationConflict(
            "first queue semantic ledger is empty"
        )
    return total, payload_hash(ledger), tuple(table_counts)


def _fingerprint_tx(con: sqlite3.Connection) -> FirstQueueDatabaseFingerprint:
    schema_count, schema_hash = _schema_inventory(con)
    event_count, event_hash, head_rowid, head_id, head_payload_hash = _event_ledger(con)
    semantic_count, semantic_hash, table_counts = _semantic_ledger_tx(con)
    return FirstQueueDatabaseFingerprint(
        schema_object_count=schema_count,
        schema_inventory_hash=schema_hash,
        event_count=event_count,
        event_ledger_hash=event_hash,
        event_head_rowid=head_rowid,
        event_head_id=head_id,
        event_head_payload_hash=head_payload_hash,
        semantic_row_count=semantic_count,
        semantic_ledger_hash=semantic_hash,
        table_counts=table_counts,
    )


def capture_first_queue_database_fingerprint(
    db_path: str | Path | FactoryStore,
) -> FirstQueueDatabaseFingerprint:
    raw_path = db_path.path if isinstance(db_path, FactoryStore) else db_path
    path = Path(raw_path).expanduser().resolve()
    before = _snapshot(path)
    con = _read_connection(path)
    try:
        con.execute("BEGIN")
        if FactoryStore(path)._probe_schema(con) != CURRENT_SCHEMA_VERSION:
            raise FirstQueueReconciliationConflict(
                "first queue reconciliation requires schema 17"
            )
        return _fingerprint_tx(con)
    finally:
        if con.in_transaction:
            con.rollback()
        con.close()
        if _snapshot(path) != before:
            raise FirstQueueReconciliationConflict(
                "first queue database changed during fingerprinting"
            )


def _epoch_hashes(value: str) -> tuple[str, str]:
    if not _EPOCH_VALUE.fullmatch(value):
        raise FirstQueueReconciliationConflict(
            "first queue recovery epoch is invalid"
        )
    current = int(value, 10)
    if current >= 2**63 - 1:
        raise FirstQueueReconciliationConflict(
            "first queue recovery epoch is exhausted"
        )
    return (
        hashlib.sha256(value.encode("ascii")).hexdigest(),
        hashlib.sha256(f"{current + 1:032d}".encode("ascii")).hexdigest(),
    )


def _reconciliation_ledger_hashes_tx(
    con: sqlite3.Connection,
    source_lab_ledger: Mapping[str, object],
) -> tuple[str, str, str]:
    """Bind the recovery-owned ledgers to this exact immutable snapshot."""

    tables = {
        str(row["name"])
        for row in con.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    if "radar_evidence_records" not in tables or any(
        table not in tables for table in MANUAL_IMPORT_V17_TABLES
    ):
        raise FirstQueueReconciliationConflict(
            "first queue recovery ledger inventory is incomplete"
        )
    try:
        radar_ledger = _validate_radar_evidence_records(con, tables)
    except RecoveryError:
        raise FirstQueueReconciliationConflict(
            "first queue radar evidence ledger is invalid"
        ) from None

    manual_inventory = tuple(
        (
            table,
            int(con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]),
        )
        for table in MANUAL_IMPORT_V17_TABLES
    )
    if any(count for _, count in manual_inventory):
        raise FirstQueueReconciliationConflict(
            "first queue manual import ledger is not empty"
        )
    manual_encoded = json.dumps(
        manual_inventory,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    try:
        radar_hash = str(radar_ledger["ledger_sha256"])
        source_lab_hash = str(source_lab_ledger["ledger_sha256"])
    except (KeyError, TypeError, ValueError):
        raise FirstQueueReconciliationConflict(
            "first queue recovery ledger hash is invalid"
        ) from None
    if not _HEX64.fullmatch(radar_hash) or not _HEX64.fullmatch(source_lab_hash):
        raise FirstQueueReconciliationConflict(
            "first queue recovery ledger hash is invalid"
        )
    return radar_hash, source_lab_hash, hashlib.sha256(manual_encoded).hexdigest()


def _file_digest(path: Path) -> str:
    if not path.is_file():
        raise FirstQueueReconciliationConflict(
            "first queue recovery artifact is missing"
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_snapshot(path: Path) -> tuple[int, int, str]:
    if not path.is_file() or path.is_symlink():
        raise FirstQueueReconciliationConflict(
            "first queue recovery artifact is invalid"
        )
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, _file_digest(path)


def _directory_snapshot(path: Path) -> tuple[int, str]:
    if not path.is_dir() or path.is_symlink():
        raise FirstQueueReconciliationConflict(
            "first queue restored evidence is invalid"
        )
    ledger: list[dict[str, object]] = []
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise FirstQueueReconciliationConflict(
                "first queue restored evidence is invalid"
            )
        relative = item.relative_to(path).as_posix()
        if item.is_dir():
            ledger.append({"path": relative, "kind": "directory"})
        elif item.is_file():
            stat = item.stat()
            ledger.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size": stat.st_size,
                    "sha256": _file_digest(item),
                }
            )
        else:
            raise FirstQueueReconciliationConflict(
                "first queue restored evidence is invalid"
            )
    return len(ledger), payload_hash(ledger)


def _fingerprint_body(value: FirstQueueDatabaseFingerprint) -> dict[str, object]:
    if type(value) is not FirstQueueDatabaseFingerprint:
        raise FirstQueueReconciliationManifestError(
            "first queue database fingerprint type is invalid"
        )
    _positive_int(value.schema_object_count, "schema fingerprint is invalid", maximum=4096)
    _positive_int(value.event_count, "event fingerprint is invalid", maximum=1_000_000)
    _positive_int(value.event_head_rowid, "event fingerprint is invalid", maximum=2**63 - 1)
    _positive_int(value.semantic_row_count, "semantic fingerprint is invalid", maximum=10_000_000)
    for item in (
        value.schema_inventory_hash,
        value.event_ledger_hash,
        value.event_head_payload_hash,
        value.semantic_ledger_hash,
    ):
        _digest(item, "first queue database fingerprint hash is invalid")
    _safe_id(value.event_head_id, "first queue event head is invalid")
    if (
        type(value.table_counts) is not tuple
        or not value.table_counts
        or tuple(sorted(value.table_counts)) != value.table_counts
        or len({item[0] for item in value.table_counts}) != len(value.table_counts)
    ):
        raise FirstQueueReconciliationManifestError(
            "first queue table count inventory is invalid"
        )
    table_counts: list[list[object]] = []
    for table, count in value.table_counts:
        _safe_id(table, "first queue table count identity is invalid")
        if type(count) is not int or count < 0 or count > 10_000_000:
            raise FirstQueueReconciliationManifestError(
                "first queue table count is invalid"
            )
        table_counts.append([table, count])
    return {
        "schema_object_count": value.schema_object_count,
        "schema_inventory_hash": value.schema_inventory_hash,
        "event_count": value.event_count,
        "event_ledger_hash": value.event_ledger_hash,
        "event_head_rowid": value.event_head_rowid,
        "event_head_id": value.event_head_id,
        "event_head_payload_hash": value.event_head_payload_hash,
        "semantic_row_count": value.semantic_row_count,
        "semantic_ledger_hash": value.semantic_ledger_hash,
        "table_counts": table_counts,
    }


def _site_expectation_body(
    value: FirstQueueSiteCommercialExpectation,
) -> dict[str, object]:
    if type(value) is not FirstQueueSiteCommercialExpectation:
        raise FirstQueueReconciliationManifestError(
            "site commercial expectation type is invalid"
        )
    if type(value.policy) is not SiteCommercialPolicy:
        raise FirstQueueReconciliationManifestError(
            "site commercial policy type is invalid"
        )
    if type(value.approval_receipt) is not TrustedSiteApprovalReceipt:
        raise FirstQueueReconciliationManifestError(
            "site commercial approval receipt type is invalid"
        )
    request = value.approval_receipt.request
    for item in (
        value.bridge_actor,
        value.bridge_idempotency_key,
        value.source_record_id,
        value.observation_id,
        value.review_id,
        value.resolution_id,
        value.evidence_link_id,
        value.anchor_event_id,
        value.lf_company_id,
        value.lf_contact_id,
        value.lf_project_id,
        value.lf_opportunity_id,
    ):
        _safe_id(item, "site commercial expectation identity is invalid")
    if (
        request.source_record_id != value.source_record_id
        or request.observation_id != value.observation_id
        or request.review_id != value.review_id
        or request.resolution_id != value.resolution_id
        or request.projection.source_record_id != value.source_record_id
        or request.projection.observation_id != value.observation_id
        or request.projection.review_id != value.review_id
        or request.projection.resolution_id != value.resolution_id
        or value.policy.source_id != request.source_id
        or type(value.attestations) is not tuple
        or len(value.attestations) != 4
        or tuple(item.operation_type for item in value.attestations) != _CRM_ORDER
        or len({item.event_id for item in value.attestations}) != 4
        or len({item.operation_id for item in value.attestations}) != 4
        or len({item.execution_id for item in value.attestations}) != 1
        or value.approval_receipt.authority_id != "offline-site-authority"
        or value.approval_receipt.receipt_id
        != f"site-receipt-{value.approval_receipt.request_hash[:32]}"
    ):
        raise FirstQueueReconciliationManifestError(
            "site commercial expectation binding is invalid"
        )
    attestations: list[dict[str, object]] = []
    for item in value.attestations:
        payload = offline_operation_attestation_payload(item)
        attestations.append(
            {
                "event_id": item.event_id,
                "event_payload_hash": item.event_payload_hash,
                "payload": payload,
            }
        )
    return {
        "policy_hash": payload_hash(_plain(value.policy)),
        "approval_request_hash": value.approval_receipt.request_hash,
        "approval_receipt_hash": value.approval_receipt.receipt_hash,
        "approval_authority_id": value.approval_receipt.authority_id,
        "approval_receipt_id": value.approval_receipt.receipt_id,
        "bridge_actor": value.bridge_actor,
        "bridge_idempotency_key": value.bridge_idempotency_key,
        "source_record_id": value.source_record_id,
        "observation_id": value.observation_id,
        "review_id": value.review_id,
        "resolution_id": value.resolution_id,
        "evidence_link_id": value.evidence_link_id,
        "anchor_event_id": value.anchor_event_id,
        "lf_company_id": value.lf_company_id,
        "lf_contact_id": value.lf_contact_id,
        "lf_project_id": value.lf_project_id,
        "lf_opportunity_id": value.lf_opportunity_id,
        "attestations": attestations,
    }


def _outcome_body(value: FirstQueueOutcomeExpectation) -> dict[str, object]:
    if type(value) is not FirstQueueOutcomeExpectation:
        raise FirstQueueReconciliationManifestError(
            "offline outcome expectation type is invalid"
        )
    for item in (
        value.inbox_event_id,
        value.remote_entity_type,
        value.remote_entity_id,
        value.event_type,
        value.dedupe_key,
        value.actor,
        value.lf_opportunity_id,
        value.transition_id,
    ):
        _safe_id(item, "offline outcome identity is invalid")
    if (
        value.remote_entity_type != "deal"
        or not _REMOTE_ID.fullmatch(value.remote_entity_id)
        or type(value.remote_version) is not int
        or value.remote_version != 1
        or value.event_type != "SCREENED"
    ):
        raise FirstQueueReconciliationManifestError(
            "offline outcome scope is invalid"
        )
    _digest(value.raw_payload_hash, "offline outcome hash is invalid")
    _digest(value.envelope_hash, "offline outcome hash is invalid")
    expected_envelope_hash = payload_hash(
        {
            "event_type": value.event_type,
            "payload_hash": value.raw_payload_hash,
            "reason": "",
        }
    )
    if value.envelope_hash != expected_envelope_hash:
        raise FirstQueueReconciliationManifestError(
            "offline outcome envelope binding is invalid"
        )
    _evidence_ref(value.evidence_ref, "offline outcome evidence is invalid")
    _utc_seconds(value.received_at_utc, "offline outcome time is invalid")
    return {
        "inbox_event_id": value.inbox_event_id,
        "remote_entity_type": value.remote_entity_type,
        "remote_entity_id": value.remote_entity_id,
        "remote_version": value.remote_version,
        "event_type": value.event_type,
        "raw_payload_hash": value.raw_payload_hash,
        "dedupe_key": value.dedupe_key,
        "envelope_hash": value.envelope_hash,
        "evidence_ref": value.evidence_ref,
        "received_at_utc": value.received_at_utc,
        "actor": value.actor,
        "lf_opportunity_id": value.lf_opportunity_id,
        "transition_id": value.transition_id,
    }


def _manifest_body(
    manifest: FirstQueueReconciliationManifest,
) -> dict[str, object]:
    if type(manifest) is not FirstQueueReconciliationManifest:
        raise FirstQueueReconciliationManifestError(
            "first queue reconciliation manifest type is invalid"
        )
    if (
        manifest.manifest_version
        != FIRST_QUEUE_RECONCILIATION_MANIFEST_VERSION
        or manifest.contract_version != FIRST_QUEUE_CONTRACT_VERSION
        or manifest.evidence_mode != FIRST_QUEUE_EVIDENCE_MODE
        or type(manifest.schema_version) is not int
        or manifest.schema_version != CURRENT_SCHEMA_VERSION
    ):
        raise FirstQueueReconciliationManifestError(
            "first queue reconciliation manifest header is invalid"
        )
    baseline_hash = validate_first_queue_manifest(manifest.baseline_manifest)
    for item in (
        manifest.baseline_report_hash,
        manifest.baseline_semantic_hash,
        manifest.baseline_event_head_payload_hash,
    ):
        _digest(item, "first queue baseline hash is invalid")
    _positive_int(
        manifest.baseline_event_head_rowid,
        "first queue baseline event head is invalid",
        maximum=2**63 - 1,
    )
    _safe_id(
        manifest.baseline_event_head_id,
        "first queue baseline event head is invalid",
    )
    fingerprint = _fingerprint_body(manifest.final_fingerprint)
    baseline = manifest.baseline_manifest
    if (
        manifest.final_fingerprint.schema_object_count
        != baseline.expected_schema_object_count
        or manifest.final_fingerprint.schema_inventory_hash
        != baseline.expected_schema_inventory_hash
        or manifest.final_fingerprint.event_count
        != baseline.expected_event_count + 63
    ):
        raise FirstQueueReconciliationManifestError(
            "first queue reconciliation evolution is invalid"
        )
    counts = dict(manifest.final_fingerprint.table_counts)
    for table, expected in _CORE_TABLE_COUNTS.items():
        if counts.get(table) != expected:
            raise FirstQueueReconciliationManifestError(
                "first queue reconciliation table counts are invalid"
            )
    if counts.get("events") != baseline.expected_event_count + 63:
        raise FirstQueueReconciliationManifestError(
            "first queue reconciliation event count is invalid"
        )
    if any(
        count != 0
        for table, count in counts.items()
        if table not in _CORE_TABLE_COUNTS and table != "events"
    ):
        raise FirstQueueReconciliationManifestError(
            "first queue reconciliation unexpected table is not empty"
        )
    for table in (
        "manual_import_authority_grants",
        "manual_import_grant_revocations",
        "manual_import_vault_receipts",
        "manual_import_parser_receipts",
        "manual_import_batch_authorizations",
        "manual_import_vault_disposals",
        "manual_import_batch_bindings",
    ):
        if counts.get(table) != 0:
            raise FirstQueueReconciliationManifestError(
                "first queue manual import ledger is not empty"
            )
    site = _site_expectation_body(manifest.site_commercial)
    outcome = _outcome_body(manifest.outcome)
    if manifest.outcome.lf_opportunity_id != manifest.site_commercial.lf_opportunity_id:
        raise FirstQueueReconciliationManifestError(
            "offline outcome is not bound to the Site graph"
        )
    if type(manifest.cross_source) is not CrossSourceExpectation:
        raise FirstQueueReconciliationManifestError(
            "cross-source expectation type is invalid"
        )
    if (
        type(manifest.cross_source.approval_bindings) is not tuple
        or len(manifest.cross_source.approval_bindings) != 3
    ):
        raise FirstQueueReconciliationManifestError(
            "cross-source offline approval fixture is invalid"
        )
    for binding in manifest.cross_source.approval_bindings:
        if (
            type(binding) is not CrossSourceApprovalBinding
            or binding.receipt.authority_id
            != "offline-cross-source-approval-authority"
            or binding.receipt.receipt_id
            != f"cross-source-receipt-{binding.receipt.request_hash[:40]}"
        ):
            raise FirstQueueReconciliationManifestError(
                "cross-source offline approval fixture is invalid"
            )
    cross_hash = payload_hash(_plain(manifest.cross_source))
    return {
        "manifest_version": manifest.manifest_version,
        "contract_version": manifest.contract_version,
        "evidence_mode": manifest.evidence_mode,
        "schema_version": manifest.schema_version,
        "baseline_manifest_hash": baseline_hash,
        "baseline_report_hash": manifest.baseline_report_hash,
        "baseline_semantic_hash": manifest.baseline_semantic_hash,
        "baseline_event_count": baseline.expected_event_count,
        "baseline_event_ledger_hash": baseline.expected_event_ledger_hash,
        "baseline_event_head_rowid": manifest.baseline_event_head_rowid,
        "baseline_event_head_id": manifest.baseline_event_head_id,
        "baseline_event_head_payload_hash": (
            manifest.baseline_event_head_payload_hash
        ),
        "final_fingerprint": fingerprint,
        "site_commercial": site,
        "cross_source_expectation_hash": cross_hash,
        "outcome": outcome,
    }


def first_queue_reconciliation_manifest_hash(
    manifest: FirstQueueReconciliationManifest,
) -> str:
    return payload_hash(_manifest_body(manifest))


def validate_first_queue_reconciliation_manifest(
    manifest: FirstQueueReconciliationManifest,
) -> str:
    digest = first_queue_reconciliation_manifest_hash(manifest)
    if manifest.declared_manifest_hash != digest:
        raise FirstQueueReconciliationManifestError(
            "first queue reconciliation declared manifest hash is invalid"
        )
    return digest


def _event_prefix(
    con: sqlite3.Connection,
    count: int,
) -> tuple[int, str, int, str, str]:
    rows = con.execute(
        "SELECT rowid AS _event_rowid,* FROM events ORDER BY rowid LIMIT ?",
        (count,),
    ).fetchall()
    if len(rows) != count:
        raise FirstQueueReconciliationConflict(
            "first queue baseline event prefix is incomplete"
        )
    ledger: list[dict[str, object]] = []
    previous = 0
    for row in rows:
        rowid = row["_event_rowid"]
        if type(rowid) is not int or rowid <= previous:
            raise FirstQueueReconciliationConflict(
                "first queue baseline event order is invalid"
            )
        previous = rowid
        body = {key: row[key] for key in row.keys() if key != "_event_rowid"}
        ledger.append(
            {
                "rowid": rowid,
                "event_id": str(row["event_id"]),
                "row_hash": payload_hash(body),
            }
        )
    head = rows[-1]
    return (
        len(rows),
        payload_hash(ledger),
        int(head["_event_rowid"]),
        str(head["event_id"]),
        str(head["payload_hash"]),
    )


def offline_operation_proof_hashes(
    operation: Mapping[str, object],
    dependency_remote_ids: Mapping[str, str],
) -> tuple[str, str]:
    """Return redacted request/readback proofs for an already SENT fixture op."""

    required = {
        "operation_id",
        "operation_type",
        "lf_entity_type",
        "lf_entity_id",
        "external_event_id",
        "payload_hash",
        "correlation_token",
        "remote_entity_type",
        "remote_entity_id",
    }
    if not isinstance(operation, Mapping) or not required.issubset(operation):
        raise FirstQueueReconciliationConflict(
            "offline CRM operation proof is incomplete"
        )
    operation_type = str(operation["operation_type"])
    if operation_type not in _CRM_ORDER:
        raise FirstQueueReconciliationConflict(
            "offline CRM operation proof is invalid"
        )
    operation_id = str(operation["operation_id"])
    lf_type = str(operation["lf_entity_type"])
    lf_id = str(operation["lf_entity_id"])
    external_event_id = str(operation["external_event_id"])
    command_hash = str(operation["payload_hash"])
    correlation = str(operation["correlation_token"])
    remote_type = str(operation["remote_entity_type"])
    remote_id = str(operation["remote_entity_id"])
    if (
        not _IDENTIFIER.fullmatch(operation_id)
        or not _IDENTIFIER.fullmatch(lf_type)
        or not _IDENTIFIER.fullmatch(lf_id)
        or not _IDENTIFIER.fullmatch(external_event_id)
        or not _HEX64.fullmatch(command_hash)
        or not correlation
        or remote_type != _REMOTE_TYPE[operation_type]
        or not _REMOTE_ID.fullmatch(remote_id)
        or not isinstance(dependency_remote_ids, Mapping)
    ):
        raise FirstQueueReconciliationConflict(
            "offline CRM operation proof is invalid"
        )
    dependencies: list[list[str]] = []
    for key in sorted(dependency_remote_ids):
        value = dependency_remote_ids[key]
        if (
            type(key) is not str
            or key not in {"company", "contact", "deal"}
            or type(value) is not str
            or not _REMOTE_ID.fullmatch(value)
        ):
            raise FirstQueueReconciliationConflict(
                "offline CRM dependency proof is invalid"
            )
        dependencies.append([key, value])
    request = {
        "operation_id": operation_id,
        "operation_type": operation_type,
        "lf_entity_type": lf_type,
        "lf_entity_id": lf_id,
        "external_event_id": external_event_id,
        "command_payload_hash": command_hash,
        "correlation_token_hash": hashlib.sha256(
            correlation.encode("utf-8")
        ).hexdigest(),
        "dependency_remote_ids": dependencies,
    }
    request_hash = payload_hash(request)
    readback_hash = payload_hash(
        {
            "request_hash": request_hash,
            "remote_entity_type": remote_type,
            "remote_entity_id": remote_id,
            "dependency_remote_ids": dependencies,
        }
    )
    return request_hash, readback_hash


def _strict_event_payload(row: sqlite3.Row, message: str) -> dict[str, Any]:
    try:
        decoded = json.loads(str(row["payload_json"] or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise FirstQueueReconciliationConflict(message) from None
    if (
        type(decoded) is not dict
        or canonical_json(decoded) != str(row["payload_json"] or "")
        or payload_hash(decoded) != str(row["payload_hash"] or "")
    ):
        raise FirstQueueReconciliationConflict(message)
    return decoded


def _validate_normalized_creation_events_tx(
    con: sqlite3.Connection,
    *,
    baseline_event_head_rowid: int,
    expected_source_payload_hashes: Mapping[str, str],
) -> None:
    graphs = con.execute(
        "SELECT sr.source_record_id,sr.producer AS source_producer,"
        "sr.external_key AS source_external_key,sr.evidence_ref AS source_evidence_ref,"
        "sr.observed_at_utc AS source_observed_at_utc,"
        "sr.created_at_utc AS source_created_at_utc,sr.idempotency_key,"
        "o.lf_opportunity_id,o.lf_company_id,o.lf_contact_id,o.lf_project_id,"
        "o.source AS opportunity_source,o.external_key AS opportunity_external_key,"
        "o.source_event_id AS opportunity_source_event_id,"
        "o.created_at_utc AS opportunity_created_at_utc,"
        "c.identity_state,c.source_event_id AS company_source_event_id,"
        "c.created_at_utc AS company_created_at_utc,"
        "ct.lf_company_id AS contact_company_id,"
        "ct.source_event_id AS contact_source_event_id,"
        "ct.created_at_utc AS contact_created_at_utc,"
        "p.lf_company_id AS project_company_id,p.source AS project_source,"
        "p.external_key AS project_external_key,p.evidence_ref AS project_evidence_ref,"
        "p.source_event_id AS project_source_event_id,"
        "p.created_at_utc AS project_created_at_utc "
        "FROM source_records sr "
        "JOIN opportunities o ON o.source_event_id=sr.source_record_id "
        "JOIN companies c ON c.lf_company_id=o.lf_company_id "
        "JOIN contacts ct ON ct.lf_contact_id=o.lf_contact_id "
        "JOIN projects p ON p.lf_project_id=o.lf_project_id "
        "ORDER BY sr.source_record_id"
    ).fetchall()
    events = con.execute(
        "SELECT rowid AS _event_rowid,* FROM events WHERE rowid>? "
        "AND producer='commercial_spine' "
        "AND event_type='normalized_opportunity_created' ORDER BY rowid",
        (baseline_event_head_rowid,),
    ).fetchall()
    if len(graphs) != 2 or len(events) != 2:
        raise FirstQueueReconciliationConflict(
            "first queue normalized graph event inventory is invalid"
        )
    if set(expected_source_payload_hashes) != {
        str(graph["source_record_id"]) for graph in graphs
    } or any(
        not _HEX64.fullmatch(str(value))
        for value in expected_source_payload_hashes.values()
    ):
        raise FirstQueueReconciliationConflict(
            "first queue normalized graph source proof is invalid"
        )
    by_source: dict[str, tuple[sqlite3.Row, dict[str, Any]]] = {}
    for event in events:
        payload = _strict_event_payload(
            event, "first queue normalized graph event is invalid"
        )
        source_record_id = str(payload.get("source_record_id", ""))
        if source_record_id in by_source:
            raise FirstQueueReconciliationConflict(
                "first queue normalized graph event is duplicated"
            )
        by_source[source_record_id] = (event, payload)
    for graph in graphs:
        source_record_id = str(graph["source_record_id"])
        pair = by_source.get(source_record_id)
        if pair is None:
            raise FirstQueueReconciliationConflict(
                "first queue normalized graph event is missing"
            )
        event, payload = pair
        opportunity_id = str(graph["lf_opportunity_id"])
        source_created = str(graph["source_created_at_utc"] or "")
        expected_payload = {
            "source_record_id": source_record_id,
            "lf_company_id": str(graph["lf_company_id"]),
            "lf_contact_id": str(graph["lf_contact_id"]),
            "lf_project_id": str(graph["lf_project_id"]),
            "lf_opportunity_id": opportunity_id,
            "company_identity_state": str(graph["identity_state"]),
            "source_payload_hash": expected_source_payload_hashes[source_record_id],
        }
        occurred = str(event["occurred_at_utc"] or "")
        recorded = str(event["recorded_at_utc"] or "")
        try:
            recorded_time = datetime.strptime(recorded, "%Y-%m-%dT%H:%M:%SZ")
            source_created_time = datetime.strptime(
                source_created, "%Y-%m-%dT%H:%M:%SZ"
            )
        except ValueError:
            raise FirstQueueReconciliationConflict(
                "first queue normalized graph time is invalid"
            ) from None
        if (
            payload != expected_payload
            or not _HEX64.fullmatch(expected_payload["source_payload_hash"])
            or str(event["aggregate_type"]) != "opportunity"
            or str(event["aggregate_id"]) != opportunity_id
            or type(event["schema_version"]) is not int
            or int(event["schema_version"]) != 14
            or str(event["actor"]) != "commercial_spine"
            or str(event["correlation_id"]) != str(event["event_id"])
            or str(event["causation_id"] or "")
            or str(event["idempotency_key"]) != f"normalized:{source_record_id}"
            or str(event["evidence_ref"])
            != str(graph["source_evidence_ref"])
            or occurred != str(graph["source_observed_at_utc"])
            or not _UTC_SECONDS.fullmatch(occurred)
            or not _UTC_SECONDS.fullmatch(recorded)
            or recorded < occurred
            or recorded_time < source_created_time
            or (recorded_time - source_created_time).total_seconds() > 300
            or str(graph["company_source_event_id"] or "") != source_record_id
            or str(graph["contact_source_event_id"] or "") != source_record_id
            or str(graph["project_source_event_id"] or "") != source_record_id
            or str(graph["opportunity_source_event_id"] or "") != source_record_id
            or any(
                str(graph[column] or "") != source_created
                for column in (
                    "company_created_at_utc",
                    "contact_created_at_utc",
                    "project_created_at_utc",
                    "opportunity_created_at_utc",
                )
            )
            or str(graph["contact_company_id"] or "")
            != str(graph["lf_company_id"])
            or str(graph["project_company_id"] or "")
            != str(graph["lf_company_id"])
            or str(graph["project_source"] or "")
            != str(graph["source_producer"])
            or str(graph["project_external_key"] or "")
            != str(graph["source_external_key"])
            or str(graph["project_evidence_ref"] or "")
            != str(graph["source_evidence_ref"])
            or str(graph["opportunity_source"] or "")
            != str(graph["source_producer"])
            or str(graph["opportunity_external_key"] or "")
            != str(graph["source_external_key"])
        ):
            raise FirstQueueReconciliationConflict(
                "first queue normalized graph event is invalid"
            )
        transitions = con.execute(
            "SELECT * FROM opportunity_transitions WHERE idempotency_key=?",
            (f"source:{source_record_id}:discovered",),
        ).fetchall()
        expected_transition_hash = payload_hash(
            {
                "lf_opportunity_id": opportunity_id,
                "to_state": "DISCOVERED",
                "reason": "SOURCE_NORMALIZED",
                "evidence_ref": str(graph["source_evidence_ref"]),
                "actor": "source_intake",
            }
        )
        if len(transitions) != 1:
            raise FirstQueueReconciliationConflict(
                "first queue normalized transition is missing"
            )
        transition = transitions[0]
        if (
            str(transition["lf_opportunity_id"]) != opportunity_id
            or str(transition["from_state"]) != "__INITIAL__"
            or str(transition["to_state"]) != "DISCOVERED"
            or str(transition["reason"]) != "SOURCE_NORMALIZED"
            or str(transition["evidence_ref"])
            != str(graph["source_evidence_ref"])
            or str(transition["actor"]) != "source_intake"
            or str(transition["payload_hash"]) != expected_transition_hash
            or str(transition["occurred_at_utc"])
            != str(graph["source_observed_at_utc"])
            or str(transition["created_at_utc"]) != source_created
        ):
            raise FirstQueueReconciliationConflict(
                "first queue normalized transition is invalid"
            )


def _site_commercial_snapshot_tx(
    con: sqlite3.Connection,
    store: FactoryStore,
    expected: FirstQueueSiteCommercialExpectation,
) -> tuple[FirstQueueSiteCommercialSnapshot, str]:
    try:
        bridge = SiteCommercialBridge(
            store,
            policy=expected.policy,
            approval_authority=None,
        )
        receipt_request = expected.approval_receipt.request
        command = ApprovedSiteCommand(
            source_record_id=expected.source_record_id,
            observation_id=expected.observation_id,
            review_id=expected.review_id,
            latest_resolution_id=expected.resolution_id,
            expected_payload_hash=receipt_request.source_payload_hash,
            projection=SiteOpportunityProjection(
                company_inn=receipt_request.projection.company_inn,
                contact_email=receipt_request.projection.contact_email,
                identity_evidence_ref=receipt_request.identity_evidence_ref,
            ),
            actor=expected.bridge_actor,
            idempotency_key=expected.bridge_idempotency_key,
        )
        approved = bridge._load_approved(con, command)
        bridge._validate_receipt(expected.approval_receipt, approved.request)
        if approved.request != receipt_request:
            raise FirstQueueReconciliationConflict(
                "Site approval proof changed"
            )
    except (SiteCommercialBridgeError, ValueError, TypeError):
        raise FirstQueueReconciliationConflict(
            "Site commercial approval proof is invalid"
        ) from None

    projection = approved.projection
    normalized_rows = con.execute(
        "SELECT * FROM source_records WHERE idempotency_key=?",
        (f"reviewed-opportunity:{projection.source_record_id}",),
    ).fetchall()
    if len(normalized_rows) != 1:
        raise FirstQueueReconciliationConflict(
            "Site normalized source record is incomplete"
        )
    normalized_intake_payload = {
        "reviewed_opportunity_intake_version": 1,
        "source_record_id": projection.source_record_id,
        "observation_id": projection.observation_id,
        "resolution_event_id": projection.resolution_event_id,
        "source_payload_hash": projection.source_payload_hash,
        "projection_hash": projection.projection_hash,
    }
    normalized_intake_payload_hash = payload_hash(normalized_intake_payload)
    try:
        normalized_graph = bridge.reviewed_bridge.intake.ingest(
            producer=projection.producer,
            external_key=projection.external_key,
            idempotency_key=f"reviewed-opportunity:{projection.source_record_id}",
            payload=normalized_intake_payload,
            evidence_ref=projection.evidence_ref,
            observed_at_utc=projection.observed_at_utc,
            company_name=projection.company_name,
            company_inn=projection.company_inn,
            contact_name=projection.contact_name,
            contact_email=projection.contact_email,
            contact_phone=projection.contact_phone,
            contact_role=projection.contact_role,
            project_title=projection.project_title,
            project_region=projection.project_region,
            product_key=projection.product_key,
            _transaction=con,
        )
    except CommercialSpineError:
        raise FirstQueueReconciliationConflict(
            "Site normalized source record is invalid"
        ) from None
    if (
        normalized_graph.created
        or normalized_graph.source_record_id
        != str(normalized_rows[0]["source_record_id"])
        or normalized_graph.lf_company_id != expected.lf_company_id
        or normalized_graph.lf_contact_id != expected.lf_contact_id
        or normalized_graph.lf_project_id != expected.lf_project_id
        or normalized_graph.lf_opportunity_id != expected.lf_opportunity_id
    ):
        raise FirstQueueReconciliationConflict(
            "Site normalized graph binding is invalid"
        )
    graph_rows = {
        "company": con.execute(
            "SELECT * FROM companies WHERE lf_company_id=?",
            (expected.lf_company_id,),
        ).fetchone(),
        "contact": con.execute(
            "SELECT * FROM contacts WHERE lf_contact_id=?",
            (expected.lf_contact_id,),
        ).fetchone(),
        "project": con.execute(
            "SELECT * FROM projects WHERE lf_project_id=?",
            (expected.lf_project_id,),
        ).fetchone(),
        "opportunity": con.execute(
            "SELECT * FROM opportunities WHERE lf_opportunity_id=?",
            (expected.lf_opportunity_id,),
        ).fetchone(),
    }
    if any(row is None for row in graph_rows.values()):
        raise FirstQueueReconciliationConflict("Site commercial graph is incomplete")
    company = graph_rows["company"]
    contact = graph_rows["contact"]
    project = graph_rows["project"]
    opportunity = graph_rows["opportunity"]
    normalized_source = normalized_rows[0]
    normalized_created = str(normalized_source["created_at_utc"] or "")
    phone_digits = normalize_phone_ru(projection.contact_phone).removeprefix("+")
    expected_phone_hash = (
        payload_hash({"phone": phone_digits}) if phone_digits else ""
    )
    if (
        str(normalized_source["producer"]) != projection.producer
        or str(normalized_source["external_key"]) != projection.external_key
        or str(normalized_source["idempotency_key"])
        != f"reviewed-opportunity:{projection.source_record_id}"
        or str(normalized_source["evidence_ref"]) != projection.evidence_ref
        or str(normalized_source["observed_at_utc"])
        != projection.observed_at_utc
        or not _UTC_SECONDS.fullmatch(normalized_created)
        or str(company["inn"] or "") != projection.company_inn
        or str(company["name"] or "") != projection.company_name
        or str(company["domain"] or "")
        or str(company["identity_state"] or "") != "EXACT"
        or str(company["source_event_id"])
        != normalized_graph.source_record_id
        or str(company["created_at_utc"]) != normalized_created
        or str(contact["lf_company_id"] or "") != expected.lf_company_id
        or str(contact["name"] or "") != projection.contact_name
        or str(contact["email"] or "") != projection.contact_email
        or str(contact["email_hash"] or "")
        != address_hash(projection.contact_email)
        or str(contact["phone_hash"] or "") != expected_phone_hash
        or str(contact["role"] or "") != projection.contact_role
        or str(contact["source_event_id"])
        != normalized_graph.source_record_id
        or str(contact["created_at_utc"]) != normalized_created
        or str(project["lf_company_id"] or "") != expected.lf_company_id
        or str(project["source"]) != projection.producer
        or str(project["external_key"]) != projection.external_key
        or str(project["title"] or "") != projection.project_title
        or str(project["region"] or "") != projection.project_region
        or str(project["evidence_ref"]) != projection.evidence_ref
        or str(project["source_event_id"])
        != normalized_graph.source_record_id
        or str(project["created_at_utc"]) != normalized_created
        or str(opportunity["lf_company_id"] or "") != expected.lf_company_id
        or str(opportunity["lf_contact_id"] or "") != expected.lf_contact_id
        or str(opportunity["lf_project_id"] or "") != expected.lf_project_id
        or str(opportunity["source"]) != projection.producer
        or str(opportunity["external_key"]) != projection.external_key
        or str(opportunity["product_key"] or "") != projection.product_key
        or str(opportunity["source_event_id"])
        != normalized_graph.source_record_id
        or str(opportunity["created_at_utc"]) != normalized_created
        or str(opportunity["status"] or "") != "SCREENED"
    ):
        raise FirstQueueReconciliationConflict(
            "Site commercial graph binding is invalid"
        )

    link = con.execute(
        "SELECT * FROM source_lab_opportunity_evidence_links "
        "WHERE evidence_link_id=?",
        (expected.evidence_link_id,),
    ).fetchone()
    if (
        not link
        or str(link["lf_opportunity_id"]) != expected.lf_opportunity_id
        or str(link["source_record_id"]) != expected.source_record_id
        or str(link["evidence_ref"]) != projection.evidence_ref
        or str(link["link_reason"]) != "APPROVED_SITE_SUBMISSION"
        or str(link["actor"]) != expected.bridge_actor
    ):
        raise FirstQueueReconciliationConflict(
            "Site commercial evidence link is invalid"
        )

    anchor_payload = {
        "reviewed_opportunity_bridge_version": 1,
        "source_record_id": projection.source_record_id,
        "observation_id": projection.observation_id,
        "review_id": projection.review_id,
        "resolution_id": projection.resolution_id,
        "resolution_event_id": projection.resolution_event_id,
        "source_payload_hash": projection.source_payload_hash,
        "projection_hash": projection.projection_hash,
        "commercial_policy_hash": bridge._policy_hash,
        "approval_request_hash": approved.request.request_hash,
        "approval_receipt_hash": expected.approval_receipt.receipt_hash,
        "mapping_manifest_hash": approved.request.mapping_manifest_hash,
        "lf_source_id": approved.request.lf_source_id,
        "activity_deadline_utc": approved.request.activity_deadline_utc,
        "anchor_timestamp_utc": projection.approval_event_occurred_at_utc,
        "evidence_link_id": expected.evidence_link_id,
        "lf_source_record_id": normalized_graph.source_record_id,
        "lf_company_id": expected.lf_company_id,
        "lf_contact_id": expected.lf_contact_id,
        "lf_project_id": expected.lf_project_id,
        "lf_opportunity_id": expected.lf_opportunity_id,
    }
    try:
        anchor = ReviewedOpportunityBridge._assert_anchor_event_tx(
            con,
            expected_payload=anchor_payload,
            expected_actor=expected.bridge_actor,
            expected_evidence_ref=projection.evidence_ref,
        )
    except ReviewedOpportunityBridgeError:
        raise FirstQueueReconciliationConflict(
            "Site commercial anchor is invalid"
        ) from None
    if str(anchor["event_id"]) != expected.anchor_event_id:
        raise FirstQueueReconciliationConflict("Site commercial anchor changed")

    graph = normalized_graph
    expected_payloads = ReviewedOpportunityBridge._crm_payloads(
        projection,
        graph,
        dict(projection.crm_context),
        expected.policy.bitrix_graph_binding,
    )
    operations = con.execute(
        "SELECT * FROM crm_outbox WHERE "
        "(lf_entity_type='company' AND lf_entity_id=?) OR "
        "(lf_entity_type='contact' AND lf_entity_id=?) OR "
        "(lf_entity_type='opportunity' AND lf_entity_id=?) "
        "ORDER BY operation_type",
        (
            expected.lf_company_id,
            expected.lf_contact_id,
            expected.lf_opportunity_id,
        ),
    ).fetchall()
    by_type = {str(row["operation_type"]): row for row in operations}
    if len(operations) != 4 or set(by_type) != set(_CRM_ORDER):
        raise FirstQueueReconciliationConflict("Site CRM graph is not exact")

    attestations = {item.operation_type: item for item in expected.attestations}
    operation_ids: list[str] = []
    remote_bindings: list[tuple[str, str]] = []
    attestation_event_ids: list[str] = []
    outbox = CrmGraphOutbox(store)
    for operation_type in _CRM_ORDER:
        row = by_type[operation_type]
        try:
            body = CrmGraphOutbox._assert_operation_envelope(row)
            CrmGraphOutbox._assert_stage_anchor_tx(con, row)
            dependencies = outbox._validate_operation_tx(con, row, require_sent=True)
        except GraphInvariantError:
            raise FirstQueueReconciliationConflict(
                "Site CRM operation proof is invalid"
            ) from None
        metadata = CrmGraphOutbox._metadata(
            operation_type,
            company_id=expected.lf_company_id,
            contact_id=expected.lf_contact_id,
            project_id=expected.lf_project_id,
            opportunity_id=expected.lf_opportunity_id,
            mapping_manifest_hash=approved.request.mapping_manifest_hash,
            lf_source_id=approved.request.lf_source_id,
        )
        public_body = {
            key: value for key, value in body.items() if not str(key).startswith("_lf_")
        }
        if (
            body.get("_lf_graph_v1") != metadata
            or public_body
            != expected_payloads[
                {
                    COMPANY_CREATE: "company",
                    CONTACT_CREATE: "contact",
                    DEAL_CREATE: "deal",
                    ACTIVITY_CREATE: "activity",
                }[operation_type]
            ]
            or str(row["external_event_id"])
            != projection.resolution_event_id
            or str(row["state"]) != "SENT"
            or int(row["attempt_count"]) != 1
            or int(row["reconcile_count"]) != 0
            or str(row["remote_entity_type"]) != _REMOTE_TYPE[operation_type]
            or not _REMOTE_ID.fullmatch(str(row["remote_entity_id"] or ""))
            or any(
                str(row[key] or "")
                for key in (
                    "next_attempt_at_utc",
                    "lease_until_utc",
                    "leased_by",
                    "lease_token",
                    "last_error_class",
                    "last_error_hash",
                    "suspect_remote_entity_type",
                    "suspect_remote_entity_id",
                )
            )
        ):
            raise FirstQueueReconciliationConflict(
                "Site CRM operation state is invalid"
            )

        attestation = attestations[operation_type]
        request_hash, readback_hash = offline_operation_proof_hashes(
            dict(row), dependencies
        )
        sent_rows = con.execute(
            "SELECT * FROM events WHERE producer='crm_graph_outbox' "
            "AND event_type='crm_graph_operation_sent' "
            "AND payload_json LIKE ? ORDER BY rowid",
            (f'%"operation_id":"{row["operation_id"]}"%',),
        ).fetchall()
        if len(sent_rows) != 1:
            raise FirstQueueReconciliationConflict(
                "Site CRM sent event is not exact"
            )
        sent_event = sent_rows[0]
        sent_payload = _strict_event_payload(
            sent_event, "Site CRM sent event is invalid"
        )
        expected_sent_payload = {
            "operation_id": str(row["operation_id"]),
            "remote_entity_type": str(row["remote_entity_type"]),
            "remote_entity_id": str(row["remote_entity_id"]),
            "dependency_operation_id": str(row["dependency_operation_id"] or ""),
        }
        sent_occurred = str(sent_event["occurred_at_utc"] or "")
        sent_recorded = str(sent_event["recorded_at_utc"] or "")
        if (
            sent_payload != expected_sent_payload
            or str(sent_event["event_type"]) != "crm_graph_operation_sent"
            or str(sent_event["aggregate_type"]) != str(row["lf_entity_type"])
            or str(sent_event["aggregate_id"]) != str(row["lf_entity_id"])
            or str(sent_event["producer"]) != "crm_graph_outbox"
            or type(sent_event["schema_version"]) is not int
            or int(sent_event["schema_version"]) != 1
            or str(sent_event["actor"]) != "integration_worker"
            or str(sent_event["correlation_id"]) != str(sent_event["event_id"])
            or str(sent_event["causation_id"] or "")
            or str(sent_event["evidence_ref"] or "")
            or str(sent_event["idempotency_key"])
            != (
                f"crm-graph-sent:{row['operation_id']}:"
                f"{row['remote_entity_type']}:{row['remote_entity_id']}"
            )
            or sent_occurred != sent_recorded
            or not _UTC_SECONDS.fullmatch(sent_occurred)
        ):
            raise FirstQueueReconciliationConflict("Site CRM sent event is invalid")
        if (
            attestation.operation_id != str(row["operation_id"])
            or attestation.request_hash != request_hash
            or attestation.readback_hash != readback_hash
            or attestation.remote_entity_type != str(row["remote_entity_type"])
            or attestation.remote_entity_id != str(row["remote_entity_id"])
            or attestation.sent_event_id != str(sent_event["event_id"])
            or attestation.sent_event_payload_hash
            != str(sent_event["payload_hash"])
        ):
            raise FirstQueueReconciliationConflict(
                "offline CRM attestation binding is invalid"
            )
        attestation_event = con.execute(
            "SELECT * FROM events WHERE event_id=?", (attestation.event_id,)
        ).fetchone()
        if not attestation_event:
            raise FirstQueueReconciliationConflict(
                "offline CRM attestation event is missing"
            )
        attestation_payload = _strict_event_payload(
            attestation_event, "offline CRM attestation event is invalid"
        )
        expected_attestation_payload = offline_operation_attestation_payload(
            attestation
        )
        if (
            attestation_payload != expected_attestation_payload
            or str(attestation_event["payload_hash"])
            != attestation.event_payload_hash
            or str(attestation_event["event_type"])
            != "offline_crm_graph_operation_attested"
            or str(attestation_event["aggregate_type"]) != "crm_operation"
            or str(attestation_event["aggregate_id"]) != attestation.operation_id
            or str(attestation_event["producer"])
            != "first_queue_offline_crm_fixture"
            or str(attestation_event["actor"]) != attestation.actor
            or str(attestation_event["evidence_ref"]) != attestation.evidence_ref
            or str(attestation_event["occurred_at_utc"])
            != attestation.occurred_at_utc
            or str(attestation_event["correlation_id"])
            != attestation.execution_id
            or str(attestation_event["causation_id"])
            != attestation.sent_event_id
            or int(attestation_event["schema_version"]) != CURRENT_SCHEMA_VERSION
            or str(attestation_event["idempotency_key"])
            != f"offline-crm-fixture:{attestation.execution_id}:{attestation.operation_id}"
        ):
            raise FirstQueueReconciliationConflict(
                "offline CRM attestation event is invalid"
            )
        operation_ids.append(str(row["operation_id"]))
        remote_bindings.append((str(row["remote_entity_type"]), str(row["remote_entity_id"])))
        attestation_event_ids.append(attestation.event_id)

    mapping_count = int(
        con.execute(
            "SELECT COUNT(*) FROM crm_mappings WHERE "
            "(lf_entity_type='company' AND lf_entity_id=?) OR "
            "(lf_entity_type='contact' AND lf_entity_id=?) OR "
            "(lf_entity_type='opportunity' AND lf_entity_id=?)",
            (
                expected.lf_company_id,
                expected.lf_contact_id,
                expected.lf_opportunity_id,
            ),
        ).fetchone()[0]
    )
    if mapping_count != 3:
        raise FirstQueueReconciliationConflict("Site CRM mappings are incomplete")

    graph_hash = payload_hash(
        {
            "anchor": anchor_payload,
            "graph_rows": [payload_hash(dict(graph_rows[key])) for key in sorted(graph_rows)],
            "operation_ids": operation_ids,
            "remote_bindings": [list(item) for item in remote_bindings],
            "attestation_event_ids": attestation_event_ids,
        }
    )
    return FirstQueueSiteCommercialSnapshot(
        source_record_id=expected.source_record_id,
        review_id=expected.review_id,
        resolution_id=expected.resolution_id,
        evidence_link_id=expected.evidence_link_id,
        anchor_event_id=expected.anchor_event_id,
        lf_company_id=expected.lf_company_id,
        lf_contact_id=expected.lf_contact_id,
        lf_project_id=expected.lf_project_id,
        lf_opportunity_id=expected.lf_opportunity_id,
        crm_operation_ids=tuple(operation_ids),
        crm_remote_bindings=tuple(remote_bindings),
        attestation_event_ids=tuple(attestation_event_ids),
        graph_hash=graph_hash,
    ), normalized_intake_payload_hash


def _outcome_snapshot_tx(
    con: sqlite3.Connection,
    expected: FirstQueueOutcomeExpectation,
    site: FirstQueueSiteCommercialSnapshot,
) -> FirstQueueOutcomeSnapshot:
    inbox = con.execute(
        "SELECT * FROM crm_inbox_events WHERE inbox_event_id=?",
        (expected.inbox_event_id,),
    ).fetchone()
    sync = con.execute(
        "SELECT * FROM crm_sync_state WHERE remote_entity_type=? AND remote_entity_id=?",
        (expected.remote_entity_type, expected.remote_entity_id),
    ).fetchone()
    transition = con.execute(
        "SELECT * FROM opportunity_transitions WHERE transition_id=?",
        (expected.transition_id,),
    ).fetchone()
    opportunity = con.execute(
        "SELECT * FROM opportunities WHERE lf_opportunity_id=?",
        (expected.lf_opportunity_id,),
    ).fetchone()
    mapping = con.execute(
        "SELECT * FROM crm_mappings WHERE remote_entity_type=? AND remote_entity_id=?",
        (expected.remote_entity_type, expected.remote_entity_id),
    ).fetchone()
    if not all((inbox, sync, transition, opportunity, mapping)):
        raise FirstQueueReconciliationConflict(
            "offline CRM outcome lineage is incomplete"
        )
    transition_hash = payload_hash(
        {
            "lf_opportunity_id": expected.lf_opportunity_id,
            "to_state": "SCREENED",
            "reason": "",
            "evidence_ref": expected.evidence_ref,
            "actor": expected.actor,
        }
    )
    if (
        expected.lf_opportunity_id != site.lf_opportunity_id
        or str(inbox["remote_entity_type"]) != expected.remote_entity_type
        or str(inbox["remote_entity_id"]) != expected.remote_entity_id
        or int(inbox["remote_version"]) != expected.remote_version
        or str(inbox["dedupe_key"]) != expected.dedupe_key
        or str(inbox["payload_hash"]) != expected.envelope_hash
        or str(inbox["event_type"]) != expected.event_type
        or str(inbox["state"]) != "PROCESSED"
        or str(inbox["evidence_ref"]) != expected.evidence_ref
        or str(inbox["received_at_utc"]) != expected.received_at_utc
        or str(inbox["lf_opportunity_id"]) != expected.lf_opportunity_id
        or str(inbox["error_code"] or "")
        or str(sync["lf_opportunity_id"]) != expected.lf_opportunity_id
        or int(sync["last_remote_version"]) != expected.remote_version
        or str(sync["last_payload_hash"]) != expected.envelope_hash
        or str(sync["last_event_id"]) != expected.inbox_event_id
        or str(mapping["lf_entity_type"]) != "opportunity"
        or str(mapping["lf_entity_id"]) != expected.lf_opportunity_id
        or str(mapping["state"]) != "ACTIVE"
        or str(transition["lf_opportunity_id"]) != expected.lf_opportunity_id
        or str(transition["from_state"]) != "DISCOVERED"
        or str(transition["to_state"]) != "SCREENED"
        or str(transition["reason"] or "")
        or str(transition["actor"]) != expected.actor
        or str(transition["evidence_ref"]) != expected.evidence_ref
        or str(transition["idempotency_key"])
        != f"crm-inbox:{expected.inbox_event_id}"
        or str(transition["payload_hash"]) != transition_hash
        or str(transition["occurred_at_utc"]) != expected.received_at_utc
        or str(opportunity["status"]) != "SCREENED"
    ):
        raise FirstQueueReconciliationConflict(
            "offline CRM outcome binding is invalid"
        )
    events = con.execute(
        "SELECT * FROM events WHERE producer='commercial_spine' "
        "AND idempotency_key IN (?,?) ORDER BY event_id",
        (
            f"transition:{expected.transition_id}",
            f"crm-outcome:{expected.inbox_event_id}",
        ),
    ).fetchall()
    if len(events) != 2:
        raise FirstQueueReconciliationConflict(
            "offline CRM outcome events are incomplete"
        )
    by_idempotency = {str(event["idempotency_key"]): event for event in events}
    if len(by_idempotency) != 2:
        raise FirstQueueReconciliationConflict(
            "offline CRM outcome events are incomplete"
        )
    expected_events = {
        f"transition:{expected.transition_id}": (
            "opportunity_transitioned",
            {
                "transition_id": expected.transition_id,
                "lf_opportunity_id": expected.lf_opportunity_id,
                "from_state": "DISCOVERED",
                "to_state": "SCREENED",
                "reason_hash": payload_hash({"reason": ""}),
                "actor_hash": payload_hash({"actor": expected.actor}),
            },
        ),
        f"crm-outcome:{expected.inbox_event_id}": (
            "crm_outcome_processed",
            {
                "inbox_event_id": expected.inbox_event_id,
                "lf_opportunity_id": expected.lf_opportunity_id,
                "state": "PROCESSED",
                "error_code": "",
            },
        ),
    }
    for idempotency_key, (event_type, expected_payload) in expected_events.items():
        event = by_idempotency.get(idempotency_key)
        if event is None:
            raise FirstQueueReconciliationConflict(
                "offline CRM outcome event is missing"
            )
        event_payload = _strict_event_payload(
            event, "offline CRM outcome event is invalid"
        )
        occurred = str(event["occurred_at_utc"] or "")
        recorded = str(event["recorded_at_utc"] or "")
        if (
            event_payload != expected_payload
            or str(event["event_type"]) != event_type
            or str(event["aggregate_type"]) != "opportunity"
            or str(event["aggregate_id"]) != expected.lf_opportunity_id
            or str(event["producer"]) != "commercial_spine"
            or type(event["schema_version"]) is not int
            or int(event["schema_version"]) != 14
            or str(event["actor"]) != "commercial_spine"
            or str(event["correlation_id"]) != str(event["event_id"])
            or str(event["causation_id"] or "")
            or str(event["evidence_ref"]) != expected.evidence_ref
            or occurred != expected.received_at_utc
            or not _UTC_SECONDS.fullmatch(recorded)
            or recorded < occurred
        ):
            raise FirstQueueReconciliationConflict(
                "offline CRM outcome event is invalid"
            )
    outcome_hash = payload_hash(
        {
            "inbox_row_hash": payload_hash(dict(inbox)),
            "sync_row_hash": payload_hash(dict(sync)),
            "transition_row_hash": payload_hash(dict(transition)),
            "opportunity_row_hash": payload_hash(dict(opportunity)),
            "event_row_hashes": sorted(payload_hash(dict(row)) for row in events),
        }
    )
    return FirstQueueOutcomeSnapshot(
        inbox_event_id=expected.inbox_event_id,
        transition_id=expected.transition_id,
        lf_opportunity_id=expected.lf_opportunity_id,
        remote_entity_type=expected.remote_entity_type,
        remote_entity_id=expected.remote_entity_id,
        state="PROCESSED",
        opportunity_state="SCREENED",
        outcome_hash=outcome_hash,
    )


def _report_payload(values: Mapping[str, object]) -> dict[str, object]:
    return {
        key: _plain(value)
        for key, value in values.items()
        if key != "report_hash"
    }


def inspect_first_queue_reconciliation_snapshot(
    db_path: str | Path | FactoryStore,
    manifest: FirstQueueReconciliationManifest,
) -> FirstQueueReconciliationReport:
    """Inspect one exact evolved first-queue snapshot without modifying it."""

    manifest_hash = validate_first_queue_reconciliation_manifest(manifest)
    raw_path = db_path.path if isinstance(db_path, FactoryStore) else db_path
    path = Path(raw_path).expanduser().resolve()
    before = _snapshot(path)
    store = FactoryStore(path)
    con = _read_connection(path)
    try:
        query_only = int(con.execute("PRAGMA query_only").fetchone()[0]) == 1
        if not query_only:
            raise FirstQueueReconciliationConflict(
                "first queue reconciliation connection is not read-only"
            )
        con.execute("BEGIN")
        if store._probe_schema(con) != CURRENT_SCHEMA_VERSION:
            raise FirstQueueReconciliationConflict(
                "first queue reconciliation requires schema 17"
            )
        quick = str(con.execute("PRAGMA quick_check").fetchone()[0]).lower()
        foreign_keys = con.execute("PRAGMA foreign_key_check").fetchall()
        if quick != "ok" or foreign_keys:
            raise FirstQueueReconciliationConflict(
                "first queue reconciliation database integrity failed"
            )
        meta = dict(
            con.execute(
                "SELECT key,value FROM schema_meta WHERE key IN (?,?,?,?,?,?,?)",
                (
                    "schema_version",
                    "environment",
                    "external_writers_enabled",
                    "external_source_reads_enabled",
                    "manual_import_commits_enabled",
                    "source_read_epoch",
                    "manual_import_epoch",
                ),
            ).fetchall()
        )
        if (
            meta.get("schema_version") != str(CURRENT_SCHEMA_VERSION)
            or meta.get("environment") != "stage"
            or meta.get("external_writers_enabled") != "0"
            or meta.get("external_source_reads_enabled") != "0"
            or meta.get("manual_import_commits_enabled") != "0"
            or not _EPOCH_VALUE.fullmatch(
                str(meta.get("source_read_epoch", ""))
            )
            or not _EPOCH_VALUE.fullmatch(
                str(meta.get("manual_import_epoch", ""))
            )
        ):
            raise FirstQueueReconciliationConflict(
                "first queue reconciliation switches are invalid"
            )

        actual_fingerprint = _fingerprint_tx(con)
        if actual_fingerprint != manifest.final_fingerprint:
            raise FirstQueueReconciliationConflict(
                "first queue final fingerprint changed"
            )
        baseline = manifest.baseline_manifest
        prefix = _event_prefix(con, baseline.expected_event_count)
        expected_prefix = (
            baseline.expected_event_count,
            baseline.expected_event_ledger_hash,
            manifest.baseline_event_head_rowid,
            manifest.baseline_event_head_id,
            manifest.baseline_event_head_payload_hash,
        )
        if prefix != expected_prefix:
            raise FirstQueueReconciliationConflict(
                "first queue baseline event prefix changed"
            )
        suffix_counts = {
            (str(row["producer"]), str(row["event_type"])): int(row["fact_count"])
            for row in con.execute(
                "SELECT producer,event_type,COUNT(*) AS fact_count FROM events "
                "WHERE rowid>? GROUP BY producer,event_type",
                (manifest.baseline_event_head_rowid,),
            ).fetchall()
        }
        if suffix_counts != _PHASE2_EVENT_SUFFIX_COUNTS:
            raise FirstQueueReconciliationConflict(
                "first queue phase-2 event inventory is invalid"
            )

        try:
            source_lab_ledger = validate_source_lab_integrity(con)
            queue_ledger = validate_source_review_queue_integrity(con)
        except (SourceLabIntegrityError, SourceReviewQueueIntegrityError):
            raise FirstQueueReconciliationConflict(
                "first queue semantic integrity failed"
            ) from None
        if (
            int(queue_ledger["event_count"]) != 8
            or int(queue_ledger["count"]) != 22
            or int(source_lab_ledger["event_count"]) <= 0
            or int(source_lab_ledger["count"]) <= 0
        ):
            raise FirstQueueReconciliationConflict(
                "first queue semantic ledger counts are invalid"
            )
        (
            radar_evidence_ledger_hash,
            source_lab_ledger_hash,
            manual_import_ledger_hash,
        ) = _reconciliation_ledger_hashes_tx(con, source_lab_ledger)

        site = _site_snapshot(
            con,
            store,
            baseline.site,
            expected_resolution_count=1,
        )
        wave1 = tuple(
            _wave1_snapshot(con, item) for item in baseline.wave1
        )
        selected_record_ids = tuple(
            sorted(
                (*site.source_record_ids, *(item for part in wave1 for item in part.source_record_ids))
            )
        )
        selected_review_ids = tuple(
            sorted(
                (*site.review_ids, *(item for part in wave1 for item in part.review_ids))
            )
        )
        if len(selected_record_ids) != 20 or len(selected_review_ids) != 20:
            raise FirstQueueReconciliationConflict(
                "first queue baseline cohort is incomplete"
            )
        queue = _queue_snapshot(
            con,
            selected_review_ids,
            queue_ledger,
            expected_resolution_count=1,
            expected_queue_event_count=2,
        )
        if queue.selected_open_review_count != 19:
            raise FirstQueueReconciliationConflict(
                "first queue Site evolution is invalid"
            )

        site_commercial, site_normalized_payload_hash = _site_commercial_snapshot_tx(
            con, store, manifest.site_commercial
        )
        try:
            cross_source = reconcile_cross_source_object(
                store,
                manifest.cross_source,
                _connection=con,
            )
        except CrossSourceReconciliationError:
            raise FirstQueueReconciliationConflict(
                "first queue cross-source reconciliation failed"
            ) from None
        if cross_source.status != "PASSED" or cross_source.crm_mapping_count != 0:
            raise FirstQueueReconciliationConflict(
                "first queue cross-source graph is invalid"
            )
        if {
            site_commercial.lf_company_id,
            site_commercial.lf_contact_id,
            site_commercial.lf_project_id,
            site_commercial.lf_opportunity_id,
        } & {
            cross_source.lf_company_id,
            cross_source.lf_contact_id,
            cross_source.lf_project_id,
            cross_source.lf_opportunity_id,
        }:
            raise FirstQueueReconciliationConflict(
                "first queue commercial graphs crossed identity boundaries"
            )

        cross_creator_slices = [
            item for item in cross_source.source_slices if item.graph_created
        ]
        cross_normalized = con.execute(
            "SELECT source_event_id FROM opportunities WHERE lf_opportunity_id=?",
            (cross_source.lf_opportunity_id,),
        ).fetchone()
        if len(cross_creator_slices) != 1 or not cross_normalized:
            raise FirstQueueReconciliationConflict(
                "first queue cross-source creator lineage is invalid"
            )
        site_normalized = con.execute(
            "SELECT source_event_id FROM opportunities WHERE lf_opportunity_id=?",
            (site_commercial.lf_opportunity_id,),
        ).fetchone()
        if not site_normalized:
            raise FirstQueueReconciliationConflict(
                "first queue Site normalized lineage is invalid"
            )
        expected_normalized_source_payload_hashes = {
            str(site_normalized["source_event_id"]): site_normalized_payload_hash,
            str(cross_normalized["source_event_id"]): (
                cross_creator_slices[0].source_payload_hash
            ),
        }

        _validate_normalized_creation_events_tx(
            con,
            baseline_event_head_rowid=manifest.baseline_event_head_rowid,
            expected_source_payload_hashes=expected_normalized_source_payload_hashes,
        )

        outcome = _outcome_snapshot_tx(
            con, manifest.outcome, site_commercial
        )
        open_reviews = int(
            con.execute(
                "SELECT COUNT(*) FROM source_lab_reviews r WHERE NOT EXISTS ("
                "SELECT 1 FROM source_lab_review_resolutions x "
                "WHERE x.review_id=r.review_id)"
            ).fetchone()[0]
        )
        state_counts = dict(
            con.execute(
                "SELECT state,COUNT(*) FROM crm_outbox GROUP BY state"
            ).fetchall()
        )
        attestation_count = int(
            con.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE producer='first_queue_offline_crm_fixture' "
                "AND event_type='offline_crm_graph_operation_attested'"
            ).fetchone()[0]
        )
        operation_type_counts = dict(
            con.execute(
                "SELECT operation_type,COUNT(*) FROM crm_outbox GROUP BY operation_type"
            ).fetchall()
        )
        if (
            open_reviews != 19
            or state_counts != {"PENDING": 4, "SENT": 4}
            or attestation_count != 4
            or operation_type_counts != {item: 2 for item in _CRM_ORDER}
            or str(
                con.execute(
                    "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                    (cross_source.lf_opportunity_id,),
                ).fetchone()[0]
            )
            != "DISCOVERED"
        ):
            raise FirstQueueReconciliationConflict(
                "first queue final commercial state is invalid"
            )

        source_epoch_hash, next_source_epoch_hash = _epoch_hashes(
            str(meta["source_read_epoch"])
        )
        manual_epoch_hash, next_manual_epoch_hash = _epoch_hashes(
            str(meta["manual_import_epoch"])
        )
        semantic_values = {
            "baseline_manifest_hash": baseline.declared_manifest_hash,
            "baseline_report_hash": manifest.baseline_report_hash,
            "baseline_semantic_hash": manifest.baseline_semantic_hash,
            "final_semantic_ledger_hash": actual_fingerprint.semantic_ledger_hash,
            "site": site,
            "wave1": wave1,
            "queue": queue,
            "site_commercial": site_commercial,
            "cross_source_report_hash": cross_source.report_hash,
            "outcome": outcome,
        }
        semantic_hash = payload_hash(_plain(semantic_values))
        values: dict[str, object] = {
            "report_version": FIRST_QUEUE_RECONCILIATION_REPORT_VERSION,
            "report_hash": "",
            "manifest_hash": manifest_hash,
            "status": FIRST_QUEUE_RECONCILIATION_STATUS,
            "criterion_42_3_6_passed": True,
            "fast_commercial_slice_ready": False,
            "remaining_fast_components": FIRST_QUEUE_REMAINING_FAST_COMPONENTS,
            "baseline_manifest_hash": baseline.declared_manifest_hash,
            "baseline_report_hash": manifest.baseline_report_hash,
            "baseline_semantic_hash": manifest.baseline_semantic_hash,
            "baseline_event_prefix_verified": True,
            "schema_version": CURRENT_SCHEMA_VERSION,
            "database_sha256": before[2],
            "database_size_bytes": before[0],
            "database_mtime_ns": before[1],
            "final_fingerprint": actual_fingerprint,
            "site": site,
            "wave1": wave1,
            "queue": queue,
            "site_commercial": site_commercial,
            "cross_source": cross_source,
            "outcome": outcome,
            "external_writers_enabled": False,
            "external_source_reads_enabled": False,
            "manual_import_commits_enabled": False,
            "source_read_epoch_hash": source_epoch_hash,
            "next_source_read_epoch_hash": next_source_epoch_hash,
            "manual_import_epoch_hash": manual_epoch_hash,
            "next_manual_import_epoch_hash": next_manual_epoch_hash,
            "radar_evidence_ledger_hash": radar_evidence_ledger_hash,
            "source_lab_ledger_hash": source_lab_ledger_hash,
            "manual_import_ledger_hash": manual_import_ledger_hash,
            "query_only": True,
            "sidecars_absent": True,
            "source_unchanged": True,
            "inspection_live_calls": 0,
            "inspection_external_writes": 0,
            "historical_offline_fixture_operations": 4,
            "semantic_hash": semantic_hash,
        }
        values["report_hash"] = payload_hash(_report_payload(values))
        return FirstQueueReconciliationReport(**values)
    except FirstQueueReconciliationError:
        raise
    except (KeyError, TypeError, ValueError, sqlite3.DatabaseError):
        raise FirstQueueReconciliationConflict(
            "first queue reconciliation inspection failed"
        ) from None
    finally:
        if con.in_transaction:
            con.rollback()
        con.close()
        if _snapshot(path) != before:
            raise FirstQueueReconciliationConflict(
                "first queue database changed during immutable reconciliation"
            )


def verify_first_queue_reconciliation_recovery(
    source_path: str | Path | FactoryStore,
    backup_path: str | Path | FactoryStore,
    restored_path: str | Path | FactoryStore,
    manifest: FirstQueueReconciliationManifest,
    restore_report: Mapping[str, object],
) -> FirstQueueRecoveryReport:
    """Compose source, backup, and restored semantic proofs fail closed."""

    if (
        not isinstance(restore_report, Mapping)
        or frozenset(restore_report.keys()) != _RESTORE_REPORT_KEYS
        or any(type(key) is not str for key in restore_report)
    ):
        raise FirstQueueReconciliationConflict(
            "first queue restore report is invalid"
        )
    source_resolved = Path(
        source_path.path if isinstance(source_path, FactoryStore) else source_path
    ).expanduser().resolve()
    backup_resolved = Path(
        backup_path.path if isinstance(backup_path, FactoryStore) else backup_path
    ).expanduser().resolve()
    restored_resolved = Path(
        restored_path.path if isinstance(restored_path, FactoryStore) else restored_path
    ).expanduser().resolve()
    if len({source_resolved, backup_resolved, restored_resolved}) != 3:
        raise FirstQueueReconciliationConflict(
            "first queue recovery paths are not distinct"
        )
    manifest_path = Path(f"{backup_resolved}.manifest.json")
    evidence_path = Path(f"{backup_resolved}.evidence.zip")
    restored_evidence_value = restore_report.get("restored_evidence")
    if type(restored_evidence_value) is not str or not restored_evidence_value:
        raise FirstQueueReconciliationConflict(
            "first queue restored evidence path is invalid"
        )
    restored_evidence_path = Path(restored_evidence_value).expanduser().resolve()
    expected_restored_evidence_path = Path(
        f"{restored_resolved}.evidence"
    ).resolve()
    if restored_evidence_path in {
        source_resolved,
        backup_resolved,
        restored_resolved,
        manifest_path,
        evidence_path,
    } or restored_evidence_path != expected_restored_evidence_path:
        raise FirstQueueReconciliationConflict(
            "first queue restored evidence path is invalid"
        )
    physical_before = {
        source_resolved: _snapshot(source_resolved),
        backup_resolved: _snapshot(backup_resolved),
        restored_resolved: _snapshot(restored_resolved),
    }
    artifact_before = {
        manifest_path: _artifact_snapshot(manifest_path),
        evidence_path: _artifact_snapshot(evidence_path),
    }
    restored_evidence_before = _directory_snapshot(restored_evidence_path)
    source = inspect_first_queue_reconciliation_snapshot(source_path, manifest)
    backup = inspect_first_queue_reconciliation_snapshot(backup_path, manifest)
    restored = inspect_first_queue_reconciliation_snapshot(restored_path, manifest)
    try:
        backup_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise FirstQueueReconciliationConflict(
            "first queue backup manifest is invalid"
        ) from None
    if (
        type(backup_manifest) is not dict
        or frozenset(backup_manifest) != _BACKUP_MANIFEST_KEYS
    ):
        raise FirstQueueReconciliationConflict(
            "first queue backup manifest is invalid"
        )
    expected_backup_counts = {
        table: count
        for table, count in backup.final_fingerprint.table_counts
        if table != "schema_meta"
    }
    empty_evidence_summary = {
        "file_count": 0,
        "metadata_count": 0,
        "raw_mime_count": 0,
        "referenced_count": 0,
        "uncompressed_bytes": 0,
    }
    expected_manual_ledger = {
        "candidate_state": "EMPTY_FAIL_CLOSED",
        "table_count": len(MANUAL_IMPORT_V17_TABLES),
        "row_count": 0,
        "ledger_sha256": source.manual_import_ledger_hash,
    }
    backup_source_lab_ledger = backup_manifest.get("source_lab_ledger")
    try:
        with zipfile.ZipFile(evidence_path, "r") as archive:
            evidence_archive_is_empty = not archive.infolist()
    except (OSError, zipfile.BadZipFile):
        evidence_archive_is_empty = False
    snapshot_fields = (
        "counts",
        "evidence",
        "pragma_user_version",
        "radar_evidence_ledger",
        "schema_meta_version",
        "schema_migrations",
        "schema_version",
        "manual_import_ledger",
        "source_lab_ledger",
    )
    if (
        restore_report.get("ok") is not True
        or source.semantic_hash != backup.semantic_hash
        or source.semantic_hash != restored.semantic_hash
        or source.manifest_hash != backup.manifest_hash
        or source.manifest_hash != restored.manifest_hash
        or source.final_fingerprint != backup.final_fingerprint
        or source.final_fingerprint != restored.final_fingerprint
        or source.radar_evidence_ledger_hash
        != backup.radar_evidence_ledger_hash
        or source.radar_evidence_ledger_hash
        != restored.radar_evidence_ledger_hash
        or source.source_lab_ledger_hash != backup.source_lab_ledger_hash
        or source.source_lab_ledger_hash != restored.source_lab_ledger_hash
        or source.manual_import_ledger_hash != backup.manual_import_ledger_hash
        or source.manual_import_ledger_hash != restored.manual_import_ledger_hash
        or source.database_sha256 == restored.database_sha256
        or source.source_read_epoch_hash != backup.source_read_epoch_hash
        or source.manual_import_epoch_hash != backup.manual_import_epoch_hash
        or restored.source_read_epoch_hash
        != source.next_source_read_epoch_hash
        or restored.manual_import_epoch_hash
        != source.next_manual_import_epoch_hash
        or str(backup_manifest.get("backup", "")) != str(backup_resolved)
        or str(backup_manifest.get("evidence_archive", ""))
        != str(evidence_path)
        or backup_manifest.get("ok") is not True
        or str(backup_manifest.get("environment", "")) != "stage"
        or backup_manifest.get("counts") != expected_backup_counts
        or backup_manifest.get("evidence") != empty_evidence_summary
        or backup_manifest.get("radar_evidence_ledger")
        != {"count": 17, "ledger_sha256": source.radar_evidence_ledger_hash}
        or type(backup_source_lab_ledger) is not dict
        or backup_source_lab_ledger.get("ledger_sha256")
        != source.source_lab_ledger_hash
        or backup_manifest.get("manual_import_ledger") != expected_manual_ledger
        or backup_manifest.get("pragma_user_version") != CURRENT_SCHEMA_VERSION
        or backup_manifest.get("schema_meta_version") != str(CURRENT_SCHEMA_VERSION)
        or not evidence_archive_is_empty
        or type(backup_manifest.get("duration_ms")) is not int
        or int(backup_manifest.get("duration_ms", -1)) < 0
        or not _UTC_SECONDS.fullmatch(
            str(backup_manifest.get("created_at_utc", ""))
        )
        or str(backup_manifest.get("sha256", "")) != backup.database_sha256
        or str(backup_manifest.get("evidence_sha256", ""))
        != _file_digest(evidence_path)
        or str(backup_manifest.get("schema_version", ""))
        != str(CURRENT_SCHEMA_VERSION)
        or str(backup_manifest.get("external_writers_enabled", "")) != "0"
        or str(backup_manifest.get("external_source_reads_enabled", "")) != "0"
        or str(backup_manifest.get("manual_import_commits_enabled", "")) != "0"
        or str(backup_manifest.get("source_read_epoch_hash", ""))
        != source.source_read_epoch_hash
        or str(backup_manifest.get("manual_import_epoch_hash", ""))
        != source.manual_import_epoch_hash
        or type(restore_report.get("duration_ms")) is not int
        or int(restore_report.get("duration_ms", -1)) < 0
        or any(
            restore_report.get(key) != backup_manifest.get(key)
            for key in snapshot_fields
        )
        or restore_report.get("mail_restore_fence")
        != {"revoked_unsent_permits": 0, "ambiguous_commands": 0}
        or Path(str(restore_report.get("backup", ""))).resolve()
        != backup_resolved
        or Path(str(restore_report.get("restored", ""))).resolve()
        != restored_resolved
        or str(restore_report.get("schema_version", ""))
        != str(CURRENT_SCHEMA_VERSION)
        or str(restore_report.get("external_writers_enabled", "")) != "0"
        or str(restore_report.get("external_source_reads_enabled", "")) != "0"
        or str(restore_report.get("manual_import_commits_enabled", "")) != "0"
        or restore_report.get("source_read_epoch_rotated") is not True
        or restore_report.get("manual_import_epoch_rotated") is not True
        or str(restore_report.get("source_read_epoch_hash", ""))
        != restored.source_read_epoch_hash
        or str(restore_report.get("manual_import_epoch_hash", ""))
        != restored.manual_import_epoch_hash
        or restore_report.get("counts") != expected_backup_counts
        or restore_report.get("evidence") != empty_evidence_summary
        or restore_report.get("pragma_user_version") != CURRENT_SCHEMA_VERSION
        or restore_report.get("schema_meta_version") != str(CURRENT_SCHEMA_VERSION)
        or restore_report.get("radar_evidence_ledger")
        != {"count": 17, "ledger_sha256": restored.radar_evidence_ledger_hash}
        or restore_report.get("manual_import_ledger")
        != {
            **expected_manual_ledger,
            "ledger_sha256": restored.manual_import_ledger_hash,
        }
        or any(_snapshot(path) != stamp for path, stamp in physical_before.items())
        or any(
            _artifact_snapshot(path) != stamp
            for path, stamp in artifact_before.items()
        )
        or restored_evidence_before != (0, payload_hash([]))
        or _directory_snapshot(restored_evidence_path) != restored_evidence_before
    ):
        raise FirstQueueReconciliationConflict(
            "first queue backup/restore composition is invalid"
        )
    values: dict[str, object] = {
        "report_version": FIRST_QUEUE_RECOVERY_REPORT_VERSION,
        "report_hash": "",
        "manifest_hash": source.manifest_hash,
        "status": FIRST_QUEUE_RECONCILIATION_STATUS,
        "criterion_42_3_6_passed": True,
        "fast_commercial_slice_ready": False,
        "semantic_hash": source.semantic_hash,
        "source_report_hash": source.report_hash,
        "backup_report_hash": backup.report_hash,
        "restored_report_hash": restored.report_hash,
        "source_database_sha256": source.database_sha256,
        "backup_database_sha256": backup.database_sha256,
        "restored_database_sha256": restored.database_sha256,
        "source_read_epoch_rotated": True,
        "manual_import_epoch_rotated": True,
        "external_writers_enabled": False,
        "external_source_reads_enabled": False,
        "manual_import_commits_enabled": False,
    }
    values["report_hash"] = payload_hash(_report_payload(values))
    return FirstQueueRecoveryReport(**values)


__all__ = [
    "FIRST_QUEUE_RECONCILIATION_MANIFEST_VERSION",
    "FIRST_QUEUE_RECONCILIATION_REPORT_VERSION",
    "FIRST_QUEUE_RECOVERY_REPORT_VERSION",
    "FIRST_QUEUE_RECONCILIATION_STATUS",
    "FIRST_QUEUE_REMAINING_FAST_COMPONENTS",
    "OFFLINE_CRM_ATTESTATION_VERSION",
    "FirstQueueDatabaseFingerprint",
    "FirstQueueOfflineOperationAttestation",
    "FirstQueueOutcomeExpectation",
    "FirstQueueOutcomeSnapshot",
    "FirstQueueReconciliationConflict",
    "FirstQueueReconciliationError",
    "FirstQueueReconciliationManifest",
    "FirstQueueReconciliationManifestError",
    "FirstQueueReconciliationReport",
    "FirstQueueRecoveryReport",
    "FirstQueueSiteCommercialExpectation",
    "FirstQueueSiteCommercialSnapshot",
    "capture_first_queue_database_fingerprint",
    "first_queue_reconciliation_manifest_hash",
    "inspect_first_queue_reconciliation_snapshot",
    "offline_operation_attestation_payload",
    "offline_operation_proof_hashes",
    "validate_first_queue_reconciliation_manifest",
    "verify_first_queue_reconciliation_recovery",
]
