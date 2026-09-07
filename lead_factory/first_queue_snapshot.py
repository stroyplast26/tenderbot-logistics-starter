"""Immutable phase-1 reconciliation for the Lead Factory first queue.

The inspector deliberately proves only the intake half of the first queue:
the four pinned Wave 1 offline batches, the AT-SITE-01 delivery matrix and
their Source Lab review requests.  It opens one quiescent SQLite file through
one immutable read-only connection and never calls a transport or writer.

Commercial projection, cross-source commercial reconciliation, outcomes and
the composed backup/restore proof are separate phase-2 requirements.  The
public report therefore cannot claim FAST readiness.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping

from .ids import canonical_json, payload_hash
from .manual_import_v17_schema import MANUAL_IMPORT_V17_TABLES
from .recovery import RecoveryError, _validate_application_schema_object_inventory
from .site_delivery_intake import (
    SITE_DELIVERY_MAX_BYTES,
    SiteDeliveryCoordinator,
    SiteDeliveryIntegrityError,
    audit_site_deliveries,
)
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity
from .source_review_queue import (
    SourceReviewQueueIntegrityError,
    validate_source_review_queue_integrity,
)
from .source_wave1_contracts import (
    Wave1Provider,
    wave1_contract,
    wave1_fixture_page_specs,
)
from .store import CURRENT_SCHEMA_VERSION, FactoryStore, SchemaVersionError


FIRST_QUEUE_SNAPSHOT_MANIFEST_VERSION = "first-queue-snapshot-manifest-v1"
FIRST_QUEUE_SNAPSHOT_REPORT_VERSION = "first-queue-snapshot-report-v1"
FIRST_QUEUE_CONTRACT_VERSION = "5.2"
FIRST_QUEUE_EVIDENCE_MODE = "OFFLINE_FIXTURE"
FIRST_QUEUE_STATUS = "PARTIAL_EVIDENCE"
FIRST_QUEUE_MISSING_COMPONENTS = (
    "BACKUP_RESTORE_COMPOSER",
    "COMMERCIAL_GRAPH",
    "CROSS_SOURCE_RECONCILIATION",
    "OUTCOME_RECONCILIATION",
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SITE_STATE_COUNTS = (
    ("ACCEPTED", 12),
    ("DUPLICATE", 4),
    ("FORM_REJECTED", 2),
    ("SPAM", 2),
)
_PHASE1_SOURCE_LAB_COUNTS = {
    "source_lab_runs": 5,
    "source_lab_batches": 5,
    "source_lab_records": 20,
    "source_lab_record_observations": 20,
    "source_lab_identity_keys": 56,
    "source_lab_record_identity_links": 56,
    "source_lab_reviews": 20,
    "source_lab_review_resolutions": 0,
    "source_lab_opportunity_evidence_links": 0,
}
_PHASE1_COMMERCIAL_TABLES = (
    "companies",
    "contacts",
    "projects",
    "opportunities",
    "opportunity_transitions",
    "source_records",
    "source_lab_opportunity_evidence_links",
    "crm_outbox",
    "crm_mappings",
    "crm_inbox_events",
    "outbox",
)
_START_CURSOR_SHA256 = hashlib.sha256(
    b'{"opaque_value":"","position":0}'
).hexdigest()
_NULL_CURSOR_SHA256 = hashlib.sha256(b"null").hexdigest()


class FirstQueueSnapshotError(RuntimeError):
    """A sanitized immutable-snapshot failure."""


class FirstQueueManifestError(FirstQueueSnapshotError, ValueError):
    """The caller supplied reconciliation manifest is not exact."""


class FirstQueueIntegrityError(FirstQueueSnapshotError):
    """The immutable database or its selected lineage is not exact."""


class FirstQueueSnapshotConflict(FirstQueueIntegrityError):
    """The selected durable intake facts do not match their manifest."""


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueSiteDeliveryExpectation:
    delivery_id: str
    received_at_utc: str
    body_sha256: str
    byte_count: int
    evidence_ref: str
    actor: str
    terminal_state: str
    canonical_hash: str

    def __repr__(self) -> str:
        return "FirstQueueSiteDeliveryExpectation(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueSiteExpectation:
    source_id: str
    trusted_policy_id: str
    trusted_policy_version: str
    trusted_policy_evidence_ref: str
    trusted_policy_hash: str
    deliveries: tuple[FirstQueueSiteDeliveryExpectation, ...]
    expected_canonical_submissions: int = 12
    expected_reviews: int = 12
    expected_interactions: int = 12
    expected_tasks: int = 12

    def __repr__(self) -> str:
        return "FirstQueueSiteExpectation(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueWave1Expectation:
    provider: Wave1Provider
    source_id: str
    run_key: str
    batch_key: str
    content_sha256: str
    import_manifest_hash: str
    fixture_manifest_sha256: str
    contract_manifest_sha256: str
    mapping_sha256: str
    adapter_authorization_sha256: str
    adapter_authorization_receipt_sha256: str
    expected_page_count: int = 2
    expected_records: int = 2
    expected_reviews: int = 2

    @property
    def expected_record_count(self) -> int:
        return self.expected_records

    @property
    def expected_review_count(self) -> int:
        return self.expected_reviews

    def __repr__(self) -> str:
        provider = (
            self.provider.value
            if isinstance(self.provider, Wave1Provider)
            else "<unvalidated>"
        )
        return f"FirstQueueWave1Expectation(provider={provider!r}, <redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueSnapshotManifest:
    manifest_version: str
    contract_version: str
    evidence_mode: str
    schema_version: int
    expected_schema_object_count: int
    expected_schema_inventory_hash: str
    expected_event_count: int
    expected_event_ledger_hash: str
    site: FirstQueueSiteExpectation
    wave1: tuple[FirstQueueWave1Expectation, ...]
    declared_manifest_hash: str

    def __repr__(self) -> str:
        return "FirstQueueSnapshotManifest(<redacted>)"


@dataclass(frozen=True, slots=True)
class FirstQueueSiteSnapshot:
    source_id: str
    trusted_policy_id: str
    trusted_policy_version: str
    trusted_policy_evidence_ref: str
    trusted_policy_hash: str
    delivery_manifest_hash: str
    raw_deliveries: int
    processed_deliveries: int
    state_counts: tuple[tuple[str, int], ...]
    canonical_submissions: int
    reviews: int
    interactions: int
    tasks: int
    pending_deliveries: int
    delivery_ids: tuple[str, ...]
    source_record_ids: tuple[str, ...]
    review_ids: tuple[str, ...]
    interaction_ids: tuple[str, ...]
    task_ids: tuple[str, ...]
    lineage_hash: str


@dataclass(frozen=True, slots=True)
class FirstQueueWave1Snapshot:
    provider: str
    source_id: str
    run_key: str
    batch_key: str
    content_sha256: str
    fixture_manifest_sha256: str
    contract_manifest_sha256: str
    mapping_sha256: str
    adapter_authorization_sha256: str
    adapter_authorization_receipt_sha256: str
    import_manifest_hash: str
    page_count: int
    record_count: int
    observation_count: int
    review_count: int
    resolution_count: int
    source_run_id: str
    source_batch_id: str
    source_record_ids: tuple[str, ...]
    review_ids: tuple[str, ...]
    record_ledger_hash: str


@dataclass(frozen=True, slots=True)
class FirstQueueQueueSnapshot:
    selected_review_count: int
    selected_resolution_count: int
    selected_open_review_count: int
    selected_queue_event_count: int
    selected_review_binding_hash: str
    global_ledger_count: int
    global_event_count: int
    global_ledger_hash: str


@dataclass(frozen=True, slots=True, repr=False)
class FirstQueueSnapshotReport:
    report_version: str
    report_hash: str
    manifest_hash: str
    status: str
    intake_reconciliation_status: str
    criterion_42_3_6_passed: bool
    fast_commercial_slice_ready: bool
    schema_version: int
    schema_object_count: int
    schema_inventory_hash: str
    event_count: int
    event_ledger_hash: str
    event_head_rowid: int
    event_head_id: str
    event_head_payload_hash: str
    database_sha256: str
    database_size_bytes: int
    database_mtime_ns: int
    source_lab_ledger_count: int
    source_lab_event_count: int
    source_lab_ledger_hash: str
    site: FirstQueueSiteSnapshot
    wave1: tuple[FirstQueueWave1Snapshot, ...]
    queue: FirstQueueQueueSnapshot
    selected_record_count: int
    selected_review_count: int
    external_writers_enabled: bool
    external_source_reads_enabled: bool
    manual_import_commits_enabled: bool
    query_only: bool
    sidecars_absent: bool
    source_unchanged: bool
    live_calls_performed: int
    external_writes_performed: int
    missing_components: tuple[str, ...]
    semantic_hash: str

    def __repr__(self) -> str:
        return (
            "FirstQueueSnapshotReport("
            f"status={self.status!r}, schema_version={self.schema_version!r}, "
            "content=<redacted>)"
        )


# Short aliases retained for callers that use the phase-1 design names.
Wave1SnapshotExpectation = FirstQueueWave1Expectation
SiteSnapshotExpectation = FirstQueueSiteExpectation


def _identifier(value: object, message: str) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise FirstQueueManifestError(message)
    return value


def _sha256(value: object, message: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise FirstQueueManifestError(message)
    return value


def _positive_int(value: object, message: str, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise FirstQueueManifestError(message)
    return value


def _evidence_ref(value: object, message: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 512
        or any(ord(character) < 32 for character in value)
        or "?" in value
        or "@" in value
    ):
        raise FirstQueueManifestError(message)
    return value


def _provider_text(value: object) -> str:
    if not isinstance(value, Wave1Provider):
        raise FirstQueueManifestError("first queue Wave 1 provider is invalid")
    return value.value


def _delivery_body(item: FirstQueueSiteDeliveryExpectation) -> dict[str, object]:
    if not isinstance(item, FirstQueueSiteDeliveryExpectation):
        raise FirstQueueManifestError("first queue site delivery is invalid")
    delivery_id = _identifier(item.delivery_id, "first queue delivery id is invalid")
    if type(item.received_at_utc) is not str or not _UTC_SECONDS.fullmatch(
        item.received_at_utc
    ):
        raise FirstQueueManifestError("first queue delivery timestamp is invalid")
    body_sha256 = _sha256(item.body_sha256, "first queue delivery hash is invalid")
    byte_count = _positive_int(
        item.byte_count,
        "first queue delivery byte count is invalid",
        maximum=SITE_DELIVERY_MAX_BYTES,
    )
    evidence_ref = _evidence_ref(
        item.evidence_ref, "first queue delivery evidence is invalid"
    )
    actor = _identifier(item.actor, "first queue delivery actor is invalid")
    if item.terminal_state not in {name for name, _ in _SITE_STATE_COUNTS}:
        raise FirstQueueManifestError("first queue delivery state is invalid")
    canonical_hash = item.canonical_hash
    if item.terminal_state in {"ACCEPTED", "DUPLICATE"}:
        _sha256(canonical_hash, "first queue delivery canonical hash is invalid")
    elif canonical_hash != "":
        raise FirstQueueManifestError("first queue delivery canonical hash is invalid")
    return {
        "delivery_id": delivery_id,
        "received_at_utc": item.received_at_utc,
        "body_sha256": body_sha256,
        "byte_count": byte_count,
        "evidence_ref": evidence_ref,
        "actor": actor,
        "terminal_state": item.terminal_state,
        "canonical_hash": canonical_hash,
    }


def _site_body(site: FirstQueueSiteExpectation) -> dict[str, object]:
    if not isinstance(site, FirstQueueSiteExpectation):
        raise FirstQueueManifestError("first queue site expectation is invalid")
    source_id = _identifier(site.source_id, "first queue site source is invalid")
    trusted_policy_id = _identifier(
        site.trusted_policy_id, "first queue site policy id is invalid"
    )
    trusted_policy_version = _identifier(
        site.trusted_policy_version, "first queue site policy version is invalid"
    )
    trusted_policy_evidence_ref = _evidence_ref(
        site.trusted_policy_evidence_ref,
        "first queue site policy evidence is invalid",
    )
    trusted_policy_hash = _sha256(
        site.trusted_policy_hash, "first queue site policy hash is invalid"
    )
    if type(site.deliveries) is not tuple or len(site.deliveries) != 20:
        raise FirstQueueManifestError("first queue site delivery manifest is incomplete")
    deliveries = tuple(_delivery_body(item) for item in site.deliveries)
    if tuple(item["delivery_id"] for item in deliveries) != tuple(
        sorted(str(item["delivery_id"]) for item in deliveries)
    ) or len({str(item["delivery_id"]) for item in deliveries}) != len(deliveries):
        raise FirstQueueManifestError(
            "first queue site deliveries must be unique and sorted"
        )
    state_counts = tuple(
        sorted(
            (
                state,
                sum(item["terminal_state"] == state for item in deliveries),
            )
            for state, _ in _SITE_STATE_COUNTS
        )
    )
    if state_counts != _SITE_STATE_COUNTS:
        raise FirstQueueManifestError("first queue site state matrix is invalid")
    expected = (
        site.expected_canonical_submissions,
        site.expected_reviews,
        site.expected_interactions,
        site.expected_tasks,
    )
    if any(type(value) is not int for value in expected) or expected != (12, 12, 12, 12):
        raise FirstQueueManifestError("first queue site expected counts are invalid")
    return {
        "source_id": source_id,
        "trusted_policy_id": trusted_policy_id,
        "trusted_policy_version": trusted_policy_version,
        "trusted_policy_evidence_ref": trusted_policy_evidence_ref,
        "trusted_policy_hash": trusted_policy_hash,
        "deliveries": list(deliveries),
        "expected_canonical_submissions": site.expected_canonical_submissions,
        "expected_reviews": site.expected_reviews,
        "expected_interactions": site.expected_interactions,
        "expected_tasks": site.expected_tasks,
    }


def _wave1_body(item: FirstQueueWave1Expectation) -> dict[str, object]:
    if not isinstance(item, FirstQueueWave1Expectation):
        raise FirstQueueManifestError("first queue Wave 1 expectation is invalid")
    provider = _provider_text(item.provider)
    contract = wave1_contract(item.provider)
    source_id = _identifier(item.source_id, "first queue Wave 1 source is invalid")
    if source_id != contract.source_id:
        raise FirstQueueManifestError("first queue Wave 1 source binding is invalid")
    run_key = _identifier(item.run_key, "first queue Wave 1 run key is invalid")
    batch_key = _identifier(item.batch_key, "first queue Wave 1 batch key is invalid")
    content_sha256 = _sha256(
        item.content_sha256, "first queue Wave 1 content hash is invalid"
    )
    import_manifest_hash = _sha256(
        item.import_manifest_hash,
        "first queue Wave 1 import manifest hash is invalid",
    )
    fixture_hash = _sha256(
        item.fixture_manifest_sha256,
        "first queue Wave 1 fixture manifest hash is invalid",
    )
    contract_hash = _sha256(
        item.contract_manifest_sha256,
        "first queue Wave 1 contract manifest hash is invalid",
    )
    mapping_hash = _sha256(
        item.mapping_sha256, "first queue Wave 1 mapping hash is invalid"
    )
    if (
        fixture_hash != contract.fixture_manifest_sha256
        or contract_hash != contract.contract_manifest_sha256
        or mapping_hash != contract.mapping_sha256
    ):
        raise FirstQueueManifestError("first queue Wave 1 registry binding is invalid")
    adapter_authorization_hash = _sha256(
        item.adapter_authorization_sha256,
        "first queue Wave 1 adapter authorization hash is invalid",
    )
    adapter_receipt_hash = _sha256(
        item.adapter_authorization_receipt_sha256,
        "first queue Wave 1 adapter receipt hash is invalid",
    )
    counts = (
        item.expected_page_count,
        item.expected_records,
        item.expected_reviews,
    )
    if any(type(value) is not int for value in counts) or counts != (2, 2, 2):
        raise FirstQueueManifestError("first queue Wave 1 expected counts are invalid")
    return {
        "provider": provider,
        "source_id": source_id,
        "run_key": run_key,
        "batch_key": batch_key,
        "content_sha256": content_sha256,
        "import_manifest_hash": import_manifest_hash,
        "fixture_manifest_sha256": fixture_hash,
        "contract_manifest_sha256": contract_hash,
        "mapping_sha256": mapping_hash,
        "adapter_authorization_sha256": adapter_authorization_hash,
        "adapter_authorization_receipt_sha256": adapter_receipt_hash,
        "expected_page_count": item.expected_page_count,
        "expected_records": item.expected_records,
        "expected_reviews": item.expected_reviews,
    }


def _manifest_body(manifest: FirstQueueSnapshotManifest) -> dict[str, object]:
    if not isinstance(manifest, FirstQueueSnapshotManifest):
        raise FirstQueueManifestError("a typed first queue manifest is required")
    if (
        manifest.manifest_version != FIRST_QUEUE_SNAPSHOT_MANIFEST_VERSION
        or manifest.contract_version != FIRST_QUEUE_CONTRACT_VERSION
        or manifest.evidence_mode != FIRST_QUEUE_EVIDENCE_MODE
        or type(manifest.schema_version) is not int
        or manifest.schema_version != CURRENT_SCHEMA_VERSION
    ):
        raise FirstQueueManifestError("first queue manifest version is invalid")
    expected_event_count = _positive_int(
        manifest.expected_event_count,
        "first queue event count is invalid",
        maximum=10_000_000,
    )
    expected_event_ledger_hash = _sha256(
        manifest.expected_event_ledger_hash,
        "first queue event ledger hash is invalid",
    )
    expected_schema_object_count = _positive_int(
        manifest.expected_schema_object_count,
        "first queue schema object count is invalid",
        maximum=100_000,
    )
    expected_schema_inventory_hash = _sha256(
        manifest.expected_schema_inventory_hash,
        "first queue schema inventory hash is invalid",
    )
    if type(manifest.wave1) is not tuple or len(manifest.wave1) != len(Wave1Provider):
        raise FirstQueueManifestError("first queue Wave 1 manifest is incomplete")
    wave1 = tuple(_wave1_body(item) for item in manifest.wave1)
    providers = tuple(str(item["provider"]) for item in wave1)
    expected_providers = tuple(sorted(provider.value for provider in Wave1Provider))
    if providers != expected_providers or len(set(providers)) != len(providers):
        raise FirstQueueManifestError(
            "first queue Wave 1 entries must be complete and sorted"
        )
    if len({str(item["source_id"]) for item in wave1}) != len(wave1):
        raise FirstQueueManifestError("first queue Wave 1 sources are duplicated")
    return {
        "manifest_version": manifest.manifest_version,
        "contract_version": manifest.contract_version,
        "evidence_mode": manifest.evidence_mode,
        "schema_version": manifest.schema_version,
        "expected_schema_object_count": expected_schema_object_count,
        "expected_schema_inventory_hash": expected_schema_inventory_hash,
        "expected_event_count": expected_event_count,
        "expected_event_ledger_hash": expected_event_ledger_hash,
        "site": _site_body(manifest.site),
        "wave1": list(wave1),
    }


def first_queue_manifest_hash(manifest: FirstQueueSnapshotManifest) -> str:
    """Return the exact manifest hash, excluding its declaration field."""

    return payload_hash(_manifest_body(manifest))


def validate_first_queue_manifest(manifest: FirstQueueSnapshotManifest) -> str:
    """Validate and return the exact declared phase-1 manifest hash."""

    exact = first_queue_manifest_hash(manifest)
    if (
        type(manifest.declared_manifest_hash) is not str
        or manifest.declared_manifest_hash != exact
        or not _HEX64.fullmatch(manifest.declared_manifest_hash)
    ):
        raise FirstQueueManifestError("first queue manifest hash is invalid")
    return exact


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(path: Path) -> tuple[int, int, str]:
    if not path.is_file():
        raise FirstQueueIntegrityError("first queue database is missing")
    if any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")):
        raise FirstQueueIntegrityError(
            "first queue database is not a quiescent immutable snapshot"
        )
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, _file_sha256(path)


def _read_connection(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(
        path.as_uri() + "?mode=ro&immutable=1",
        uri=True,
        timeout=30,
        isolation_level=None,
    )
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA busy_timeout=30000")
    return con


def _json_object(value: object, message: str) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise FirstQueueSnapshotConflict(message) from None
    if type(decoded) is not dict or canonical_json(decoded) != str(value or ""):
        raise FirstQueueSnapshotConflict(message)
    return decoded


def _event_ledger(
    con: sqlite3.Connection,
) -> tuple[int, str, int, str, str]:
    rows = con.execute(
        "SELECT rowid AS _event_rowid,* FROM events ORDER BY rowid"
    ).fetchall()
    if not rows:
        raise FirstQueueSnapshotConflict("first queue event ledger is empty")
    ledger: list[dict[str, object]] = []
    previous_rowid = 0
    for row in rows:
        rowid = row["_event_rowid"]
        if type(rowid) is not int or rowid <= previous_rowid:
            raise FirstQueueSnapshotConflict("first queue event order is invalid")
        previous_rowid = rowid
        event_body = {
            key: row[key]
            for key in row.keys()
            if key != "_event_rowid"
        }
        ledger.append(
            {
                "rowid": rowid,
                "event_id": str(row["event_id"]),
                "row_hash": payload_hash(event_body),
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


def _schema_inventory(con: sqlite3.Connection) -> tuple[int, str]:
    rows = con.execute(
        """SELECT type,name,tbl_name,COALESCE(sql,'') AS sql
           FROM sqlite_master
           WHERE type IN ('table','index','trigger','view')
             AND name NOT LIKE 'sqlite_%'
           ORDER BY type,name"""
    ).fetchall()
    inventory = [
        {
            "type": str(row["type"]),
            "name": str(row["name"]),
            "table_name": str(row["tbl_name"]),
            "sql": str(row["sql"]),
        }
        for row in rows
    ]
    if not inventory:
        raise FirstQueueSnapshotConflict("first queue schema inventory is empty")
    return len(inventory), payload_hash(inventory)


def _site_snapshot(
    con: sqlite3.Connection,
    store: FactoryStore,
    expected: FirstQueueSiteExpectation,
    *,
    expected_resolution_count: int = 0,
) -> FirstQueueSiteSnapshot:
    expected_body = _site_body(expected)
    audit = audit_site_deliveries(store, expected.source_id, _connection=con)
    if audit.lineage_errors:
        raise FirstQueueSnapshotConflict("first queue site lineage is invalid")
    if (
        audit.raw_deliveries != len(expected.deliveries)
        or audit.processed_deliveries != len(expected.deliveries)
        or audit.canonical_submissions != expected.expected_canonical_submissions
        or audit.reviews != expected.expected_reviews
        or audit.interactions != expected.expected_interactions
        or audit.tasks != expected.expected_tasks
        or audit.pending_deliveries != 0
    ):
        raise FirstQueueSnapshotConflict("first queue site counts are invalid")

    all_site_events = con.execute(
        "SELECT event_type FROM events WHERE producer='site_delivery_intake'"
    ).fetchall()
    if (
        len(all_site_events) != 40
        or {str(row["event_type"]) for row in all_site_events}
        != {"site_raw_delivery_captured", "site_delivery_processed"}
    ):
        raise FirstQueueSnapshotConflict("first queue site event cohort is not exact")

    raw_rows = con.execute(
        """SELECT * FROM events
           WHERE producer='site_delivery_intake'
             AND event_type='site_raw_delivery_captured'
           ORDER BY event_id"""
    ).fetchall()
    raw: dict[str, tuple[sqlite3.Row, dict[str, Any]]] = {}
    for row in raw_rows:
        try:
            payload = SiteDeliveryCoordinator._raw_event_payload(row)
        except SiteDeliveryIntegrityError:
            raise FirstQueueSnapshotConflict(
                "first queue site raw delivery is invalid"
            ) from None
        if str(payload.get("source_id", "")) != expected.source_id:
            raise FirstQueueSnapshotConflict(
                "first queue site event source is not exact"
            )
        raw[str(payload["delivery_id"])] = (row, payload)

    processed_rows = con.execute(
        """SELECT * FROM events
           WHERE producer='site_delivery_intake'
             AND event_type='site_delivery_processed'
           ORDER BY event_id"""
    ).fetchall()
    processed: dict[str, tuple[sqlite3.Row, dict[str, Any]]] = {}
    for row in processed_rows:
        try:
            payload = SiteDeliveryCoordinator._processed_payload(row)
        except SiteDeliveryIntegrityError:
            raise FirstQueueSnapshotConflict(
                "first queue site processed delivery is invalid"
            ) from None
        if str(payload.get("source_id", "")) != expected.source_id:
            raise FirstQueueSnapshotConflict(
                "first queue site event source is not exact"
            )
        processed[str(payload["delivery_id"])] = (row, payload)

    expected_deliveries = {
        item.delivery_id: body
        for item, body in zip(expected.deliveries, expected_body["deliveries"])
    }
    if set(raw) != set(expected_deliveries) or set(processed) != set(expected_deliveries):
        raise FirstQueueSnapshotConflict("first queue site delivery set is invalid")
    state_counts: dict[str, int] = {state: 0 for state, _ in _SITE_STATE_COUNTS}
    lineage_items: list[dict[str, object]] = []
    for delivery_id in sorted(expected_deliveries):
        declaration = expected_deliveries[delivery_id]
        raw_row, raw_payload = raw[delivery_id]
        processed_row, processed_payload = processed[delivery_id]
        for key in (
            "delivery_id",
            "received_at_utc",
            "body_sha256",
            "byte_count",
            "evidence_ref",
            "actor",
        ):
            if raw_payload.get(key) != declaration[key]:
                raise FirstQueueSnapshotConflict(
                    "first queue site delivery binding is invalid"
                )
        if processed_payload.get("state") != declaration["terminal_state"]:
            raise FirstQueueSnapshotConflict("first queue site terminal state is invalid")
        if processed_payload.get("canonical_hash") != declaration["canonical_hash"]:
            raise FirstQueueSnapshotConflict(
                "first queue site canonical output binding is invalid"
            )
        state_counts[str(processed_payload["state"])] += 1
        lineage_items.append(
            {
                "delivery_id": delivery_id,
                "raw_event_id": str(raw_row["event_id"]),
                "raw_payload_hash": str(raw_row["payload_hash"]),
                "processed_event_id": str(processed_row["event_id"]),
                "processed_payload_hash": str(processed_row["payload_hash"]),
            }
        )
    state_count_tuple = tuple(sorted(state_counts.items()))
    if state_count_tuple != _SITE_STATE_COUNTS:
        raise FirstQueueSnapshotConflict("first queue site state counts are invalid")

    policy_hashes: set[str] = set()
    for record_id in audit.source_record_ids:
        row = con.execute(
            "SELECT payload_json,payload_hash FROM source_lab_records WHERE source_record_id=?",
            (record_id,),
        ).fetchone()
        if not row:
            raise FirstQueueSnapshotConflict("first queue site record is missing")
        envelope = _json_object(row["payload_json"], "first queue site record is invalid")
        if payload_hash(envelope) != str(row["payload_hash"]):
            raise FirstQueueSnapshotConflict("first queue site record is invalid")
        record = envelope.get("record")
        trusted_policy = (
            record.get("trusted_policy") if type(record) is dict else None
        )
        if (
            type(trusted_policy) is not dict
            or frozenset(trusted_policy)
            != frozenset(
                {"policy_id", "policy_version", "policy_hash", "evidence_ref"}
            )
            or not _IDENTIFIER.fullmatch(str(trusted_policy.get("policy_id", "")))
            or not _IDENTIFIER.fullmatch(
                str(trusted_policy.get("policy_version", ""))
            )
            or not str(trusted_policy.get("evidence_ref", ""))
        ):
            raise FirstQueueSnapshotConflict(
                "first queue site trusted policy is invalid"
            )
        policy_hashes.add(
            str(trusted_policy.get("policy_hash", ""))
        )
        if (
            trusted_policy.get("policy_id") != expected.trusted_policy_id
            or trusted_policy.get("policy_version")
            != expected.trusted_policy_version
            or trusted_policy.get("evidence_ref")
            != expected.trusted_policy_evidence_ref
        ):
            raise FirstQueueSnapshotConflict(
                "first queue site trusted policy binding is invalid"
            )
    if policy_hashes != {expected.trusted_policy_hash}:
        raise FirstQueueSnapshotConflict("first queue site policy binding is invalid")

    placeholders = ",".join("?" for _ in audit.review_ids)
    resolution_rows = con.execute(
        "SELECT * FROM source_lab_review_resolutions "
        f"WHERE review_id IN ({placeholders}) ORDER BY review_id,sequence_number",
        tuple(audit.review_ids),
    ).fetchall()
    if len(resolution_rows) != expected_resolution_count:
        raise FirstQueueSnapshotConflict(
            "first queue site review resolution count is invalid"
        )
    delivery_manifest_hash = payload_hash(list(expected_body["deliveries"]))
    lineage_hash = payload_hash(
        {
            "delivery_manifest_hash": delivery_manifest_hash,
            "events": lineage_items,
            "source_record_ids": list(audit.source_record_ids),
            "review_ids": list(audit.review_ids),
            "review_resolutions": [
                {
                    "resolution_id": str(row["resolution_id"]),
                    "review_id": str(row["review_id"]),
                    "sequence_number": int(row["sequence_number"]),
                    "row_hash": payload_hash(dict(row)),
                }
                for row in resolution_rows
            ],
            "interaction_ids": list(audit.interaction_ids),
            "task_ids": list(audit.task_ids),
        }
    )
    return FirstQueueSiteSnapshot(
        source_id=expected.source_id,
        trusted_policy_id=expected.trusted_policy_id,
        trusted_policy_version=expected.trusted_policy_version,
        trusted_policy_evidence_ref=expected.trusted_policy_evidence_ref,
        trusted_policy_hash=expected.trusted_policy_hash,
        delivery_manifest_hash=delivery_manifest_hash,
        raw_deliveries=audit.raw_deliveries,
        processed_deliveries=audit.processed_deliveries,
        state_counts=state_count_tuple,
        canonical_submissions=audit.canonical_submissions,
        reviews=audit.reviews,
        interactions=audit.interactions,
        tasks=audit.tasks,
        pending_deliveries=audit.pending_deliveries,
        delivery_ids=audit.delivery_ids,
        source_record_ids=audit.source_record_ids,
        review_ids=audit.review_ids,
        interaction_ids=audit.interaction_ids,
        task_ids=audit.task_ids,
        lineage_hash=lineage_hash,
    )


def _wave1_snapshot(
    con: sqlite3.Connection,
    expected: FirstQueueWave1Expectation,
) -> FirstQueueWave1Snapshot:
    _wave1_body(expected)
    contract = wave1_contract(expected.provider)
    page_specs = wave1_fixture_page_specs(expected.provider)
    run_rows = con.execute(
        """SELECT * FROM source_lab_runs
           WHERE source_id=? AND acquisition_mode='OFFLINE_FIXTURE' AND run_key=?""",
        (expected.source_id, expected.run_key),
    ).fetchall()
    if len(run_rows) != 1:
        raise FirstQueueSnapshotConflict("first queue Wave 1 run is not exact")
    run = run_rows[0]
    batch_rows = con.execute(
        """SELECT * FROM source_lab_batches
           WHERE source_run_id=? AND batch_key=?""",
        (str(run["source_run_id"]), expected.batch_key),
    ).fetchall()
    if len(batch_rows) != 1:
        raise FirstQueueSnapshotConflict("first queue Wave 1 batch is not exact")
    batch = batch_rows[0]
    if str(batch["manifest_hash"]) != expected.import_manifest_hash:
        raise FirstQueueSnapshotConflict(
            "first queue Wave 1 import manifest binding is invalid"
        )
    observations = con.execute(
        """SELECT * FROM source_lab_record_observations
           WHERE source_run_id=? AND source_batch_id=?
           ORDER BY observation_id""",
        (str(run["source_run_id"]), str(batch["source_batch_id"])),
    ).fetchall()
    if len(observations) != expected.expected_record_count:
        raise FirstQueueSnapshotConflict("first queue Wave 1 observations are incomplete")
    record_ids = tuple(sorted(str(row["source_record_id"]) for row in observations))
    if len(set(record_ids)) != expected.expected_record_count:
        raise FirstQueueSnapshotConflict("first queue Wave 1 record set is invalid")

    page_sequences: set[int] = set()
    cursor_bindings: dict[int, tuple[str, str]] = {}
    anchors: list[dict[str, Any]] = []
    record_rows: list[sqlite3.Row] = []
    review_rows: list[sqlite3.Row] = []
    for record_id in record_ids:
        row = con.execute(
            "SELECT * FROM source_lab_records WHERE source_record_id=?",
            (record_id,),
        ).fetchone()
        if not row or str(row["source_id"]) != expected.source_id:
            raise FirstQueueSnapshotConflict("first queue Wave 1 record is invalid")
        envelope = _json_object(row["payload_json"], "first queue Wave 1 record is invalid")
        if payload_hash(envelope) != str(row["payload_hash"]):
            raise FirstQueueSnapshotConflict("first queue Wave 1 record is invalid")
        record = envelope.get("record")
        if type(record) is not dict:
            raise FirstQueueSnapshotConflict("first queue Wave 1 record is invalid")
        sequence = record.get("page_sequence")
        if type(sequence) is not int:
            raise FirstQueueSnapshotConflict("first queue Wave 1 page proof is invalid")
        page_sequences.add(sequence)
        expected_fields = {
            "provider": expected.provider.value,
            "product_code": contract.product_code,
            "source_id": expected.source_id,
            "record_kind": contract.record_kind.value,
            "data_class": contract.data_class,
            "fixture_manifest_sha256": expected.fixture_manifest_sha256,
            "contract_manifest_sha256": expected.contract_manifest_sha256,
            "mapping_artifact_id": contract.mapping_artifact_id,
            "mapping_version": contract.mapping_version,
            "mapping_sha256": expected.mapping_sha256,
            "adapter_authorization_sha256": expected.adapter_authorization_sha256,
            "adapter_authorization_receipt_sha256": (
                expected.adapter_authorization_receipt_sha256
            ),
        }
        if (
            envelope.get("schema_version") != "source-import-record-v2"
            or envelope.get("content_sha256") != expected.content_sha256
            or envelope.get("data_contract_version") != contract.contract_version
            or any(record.get(key) != value for key, value in expected_fields.items())
        ):
            raise FirstQueueSnapshotConflict("first queue Wave 1 binding is invalid")
        if not 1 <= sequence <= len(page_specs):
            raise FirstQueueSnapshotConflict("first queue Wave 1 page proof is invalid")
        page_spec = page_specs[sequence - 1]
        expected_has_more = sequence < len(page_specs)
        if (
            record.get("raw_page_sha256") != page_spec.content_sha256
            or record.get("adapter_page_receipt_key_sha256")
            != hashlib.sha256(page_spec.receipt_key.encode("utf-8")).hexdigest()
            or type(record.get("page_has_more")) is not bool
            or record.get("page_has_more") is not expected_has_more
            or type(record.get("page_record_count")) is not int
            or record.get("page_record_count") != 1
            or type(record.get("page_record_ordinal")) is not int
            or record.get("page_record_ordinal") != 1
            or not _HEX64.fullmatch(str(record.get("cursor_before_sha256", "")))
            or not _HEX64.fullmatch(str(record.get("next_cursor_sha256", "")))
        ):
            raise FirstQueueSnapshotConflict("first queue Wave 1 page proof is invalid")
        cursor_bindings[sequence] = (
            str(record["cursor_before_sha256"]),
            str(record["next_cursor_sha256"]),
        )
        if "batch_anchor" in envelope:
            if type(envelope["batch_anchor"]) is not dict:
                raise FirstQueueSnapshotConflict("first queue Wave 1 batch anchor is invalid")
            anchors.append(envelope["batch_anchor"])
        reviews = con.execute(
            """SELECT * FROM source_lab_reviews
               WHERE source_record_id=? AND review_kind='QUALIFICATION'
                 AND requested_by='wave1_offline_ingest'
               ORDER BY review_id""",
            (record_id,),
        ).fetchall()
        if len(reviews) != 1:
            raise FirstQueueSnapshotConflict("first queue Wave 1 review is not exact")
        record_rows.append(row)
        review_rows.extend(reviews)

    if page_sequences != set(range(1, expected.expected_page_count + 1)):
        raise FirstQueueSnapshotConflict("first queue Wave 1 page sequence is invalid")
    if (
        cursor_bindings[1][0] != _START_CURSOR_SHA256
        or cursor_bindings[1][1] != cursor_bindings[2][0]
        or cursor_bindings[2][1] != _NULL_CURSOR_SHA256
    ):
        raise FirstQueueSnapshotConflict("first queue Wave 1 cursor chain is invalid")
    if len(anchors) != 1:
        raise FirstQueueSnapshotConflict("first queue Wave 1 batch anchor is not exact")
    anchor = anchors[0]
    import_manifest = anchor.get("import_manifest")
    authorization = anchor.get("authorization_snapshot")
    if type(import_manifest) is not dict or type(authorization) is not dict:
        raise FirstQueueSnapshotConflict("first queue Wave 1 batch anchor is invalid")
    if (
        payload_hash(import_manifest) != expected.import_manifest_hash
        or import_manifest.get("source_id") != expected.source_id
        or import_manifest.get("run_key") != expected.run_key
        or import_manifest.get("batch_key") != expected.batch_key
        or import_manifest.get("content_sha256") != expected.content_sha256
        or import_manifest.get("record_count") != expected.expected_record_count
        or import_manifest.get("data_contract_version") != contract.contract_version
        or import_manifest.get("acquisition_mode") != FIRST_QUEUE_EVIDENCE_MODE
        or authorization.get("source_id") != expected.source_id
        or authorization.get("content_sha256") != expected.content_sha256
        or authorization.get("record_count") != expected.expected_record_count
        or authorization.get("acquisition_mode") != FIRST_QUEUE_EVIDENCE_MODE
    ):
        raise FirstQueueSnapshotConflict("first queue Wave 1 import anchor is invalid")

    review_ids = tuple(sorted(str(row["review_id"]) for row in review_rows))
    placeholders = ",".join("?" for _ in review_ids)
    resolution_count = int(
        con.execute(
            "SELECT COUNT(*) FROM source_lab_review_resolutions "
            f"WHERE review_id IN ({placeholders})",
            review_ids,
        ).fetchone()[0]
    )
    if len(review_ids) != expected.expected_review_count or resolution_count:
        raise FirstQueueSnapshotConflict("first queue Wave 1 review state is invalid")
    ledger = [
        {
            "kind": "run",
            "id": str(run["source_run_id"]),
            "hash": payload_hash(dict(run)),
        },
        {
            "kind": "batch",
            "id": str(batch["source_batch_id"]),
            "hash": payload_hash(dict(batch)),
        },
        *(
            {
                "kind": "observation",
                "id": str(row["observation_id"]),
                "hash": payload_hash(dict(row)),
            }
            for row in observations
        ),
        *(
            {
                "kind": "record",
                "id": str(row["source_record_id"]),
                "hash": payload_hash(dict(row)),
            }
            for row in record_rows
        ),
        *(
            {
                "kind": "review",
                "id": str(row["review_id"]),
                "hash": payload_hash(dict(row)),
            }
            for row in review_rows
        ),
    ]
    ledger.sort(key=lambda item: (str(item["kind"]), str(item["id"])))
    return FirstQueueWave1Snapshot(
        provider=expected.provider.value,
        source_id=expected.source_id,
        run_key=expected.run_key,
        batch_key=expected.batch_key,
        content_sha256=expected.content_sha256,
        fixture_manifest_sha256=expected.fixture_manifest_sha256,
        contract_manifest_sha256=expected.contract_manifest_sha256,
        mapping_sha256=expected.mapping_sha256,
        adapter_authorization_sha256=expected.adapter_authorization_sha256,
        adapter_authorization_receipt_sha256=(
            expected.adapter_authorization_receipt_sha256
        ),
        import_manifest_hash=expected.import_manifest_hash,
        page_count=len(page_sequences),
        record_count=len(record_rows),
        observation_count=len(observations),
        review_count=len(review_rows),
        resolution_count=resolution_count,
        source_run_id=str(run["source_run_id"]),
        source_batch_id=str(batch["source_batch_id"]),
        source_record_ids=record_ids,
        review_ids=review_ids,
        record_ledger_hash=payload_hash(ledger),
    )


def _queue_snapshot(
    con: sqlite3.Connection,
    selected_review_ids: tuple[str, ...],
    queue_ledger: Mapping[str, object],
    *,
    expected_resolution_count: int = 0,
    expected_queue_event_count: int = 0,
) -> FirstQueueQueueSnapshot:
    if not selected_review_ids:
        raise FirstQueueSnapshotConflict("first queue selected reviews are missing")
    placeholders = ",".join("?" for _ in selected_review_ids)
    reviews = con.execute(
        "SELECT * FROM source_lab_reviews "
        f"WHERE review_id IN ({placeholders}) ORDER BY review_id",
        selected_review_ids,
    ).fetchall()
    if len(reviews) != len(selected_review_ids):
        raise FirstQueueSnapshotConflict("first queue selected review set is invalid")
    resolution_rows = con.execute(
        "SELECT review_id FROM source_lab_review_resolutions "
        f"WHERE review_id IN ({placeholders}) ORDER BY review_id,sequence_number",
        selected_review_ids,
    ).fetchall()
    resolution_count = len(resolution_rows)
    resolved_review_count = len({str(row["review_id"]) for row in resolution_rows})
    queue_event_count = int(
        con.execute(
            "SELECT COUNT(*) FROM events WHERE producer='source_lab_review_queue' "
            f"AND aggregate_id IN ({placeholders})",
            selected_review_ids,
        ).fetchone()[0]
    )
    if (
        resolution_count != expected_resolution_count
        or queue_event_count != expected_queue_event_count
    ):
        raise FirstQueueSnapshotConflict(
            "first queue selected review state is invalid"
        )
    binding = [
        {
            "review_id": str(row["review_id"]),
            "source_record_id": str(row["source_record_id"]),
            "review_kind": str(row["review_kind"]),
            "requested_by": str(row["requested_by"]),
            "command_hash": str(row["command_hash"]),
            "event_id": str(row["event_id"]),
            "row_hash": payload_hash(dict(row)),
        }
        for row in reviews
    ]
    return FirstQueueQueueSnapshot(
        selected_review_count=len(reviews),
        selected_resolution_count=resolution_count,
        selected_open_review_count=len(reviews) - resolved_review_count,
        selected_queue_event_count=queue_event_count,
        selected_review_binding_hash=payload_hash(binding),
        global_ledger_count=int(queue_ledger["count"]),
        global_event_count=int(queue_ledger["event_count"]),
        global_ledger_hash=str(queue_ledger["ledger_sha256"]),
    )


def _report_body(values: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in values.items() if key != "report_hash"}


def inspect_first_queue_snapshot(
    db_path: str | Path | FactoryStore,
    manifest: FirstQueueSnapshotManifest,
) -> FirstQueueSnapshotReport:
    """Inspect one exact schema-17 intake snapshot without modifying it."""

    manifest_hash = validate_first_queue_manifest(manifest)
    raw_path = db_path.path if isinstance(db_path, FactoryStore) else db_path
    path = Path(raw_path).expanduser().resolve()
    before = _snapshot(path)
    store = FactoryStore(path)
    con = _read_connection(path)
    total_changes = 0
    try:
        query_only = int(con.execute("PRAGMA query_only").fetchone()[0]) == 1
        if not query_only:
            raise FirstQueueIntegrityError("first queue connection is not read-only")
        con.execute("BEGIN")
        try:
            if store._probe_schema(con) != CURRENT_SCHEMA_VERSION:
                raise FirstQueueIntegrityError("first queue schema is not version 17")
            _validate_application_schema_object_inventory(
                con,
                version=CURRENT_SCHEMA_VERSION,
            )
            schema_inventory = _schema_inventory(con)
            if (
                schema_inventory[0] != manifest.expected_schema_object_count
                or schema_inventory[1] != manifest.expected_schema_inventory_hash
            ):
                raise FirstQueueSnapshotConflict(
                    "first queue schema inventory is not exact"
                )
            if str(con.execute("PRAGMA quick_check").fetchone()[0]).lower() != "ok":
                raise FirstQueueIntegrityError("first queue SQLite integrity check failed")
            if con.execute("PRAGMA foreign_key_check").fetchall():
                raise FirstQueueIntegrityError("first queue foreign key check failed")
            meta = {
                str(row[0]): str(row[1])
                for row in con.execute(
                    """SELECT key,value FROM schema_meta WHERE key IN (
                           'schema_version','external_writers_enabled',
                           'external_source_reads_enabled',
                           'manual_import_commits_enabled','source_read_epoch',
                           'manual_import_epoch')"""
                ).fetchall()
            }
            if (
                meta.get("schema_version") != str(CURRENT_SCHEMA_VERSION)
                or meta.get("external_writers_enabled") != "0"
                or meta.get("external_source_reads_enabled") != "0"
                or meta.get("manual_import_commits_enabled") != "0"
                or not re.fullmatch(r"[0-9]{32}", meta.get("source_read_epoch", ""))
                or not re.fullmatch(r"[0-9]{32}", meta.get("manual_import_epoch", ""))
            ):
                raise FirstQueueSnapshotConflict(
                    "first queue safety switches or epochs are invalid"
                )
            if any(
                int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in MANUAL_IMPORT_V17_TABLES
            ):
                raise FirstQueueSnapshotConflict(
                    "first queue manual import ledger must remain empty"
                )
            source_lab_ledger = validate_source_lab_integrity(con)
            queue_ledger = validate_source_review_queue_integrity(con)
            event_ledger = _event_ledger(con)
            if (
                event_ledger[0] != manifest.expected_event_count
                or event_ledger[1] != manifest.expected_event_ledger_hash
            ):
                raise FirstQueueSnapshotConflict(
                    "first queue global event ledger is not exact"
                )
            if source_lab_ledger.get("table_counts") != _PHASE1_SOURCE_LAB_COUNTS:
                raise FirstQueueSnapshotConflict(
                    "first queue Source Lab cohort is not exact"
                )
            if any(
                int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in _PHASE1_COMMERCIAL_TABLES
            ):
                raise FirstQueueSnapshotConflict(
                    "first queue phase-1 snapshot contains a commercial projection"
                )
            site = _site_snapshot(con, store, manifest.site)
            wave1 = tuple(
                _wave1_snapshot(con, item)
                for item in manifest.wave1
            )
            selected_record_ids = tuple(
                sorted(
                    (
                        *site.source_record_ids,
                        *(record_id for item in wave1 for record_id in item.source_record_ids),
                    )
                )
            )
            selected_review_ids = tuple(
                sorted(
                    (
                        *site.review_ids,
                        *(review_id for item in wave1 for review_id in item.review_ids),
                    )
                )
            )
            if len(selected_record_ids) != 20 or len(set(selected_record_ids)) != 20:
                raise FirstQueueSnapshotConflict(
                    "first queue selected record set is not exact"
                )
            if len(selected_review_ids) != 20 or len(set(selected_review_ids)) != 20:
                raise FirstQueueSnapshotConflict(
                    "first queue selected review set is not exact"
                )
            queue = _queue_snapshot(con, selected_review_ids, queue_ledger)
            total_changes = con.total_changes
        finally:
            if con.in_transaction:
                con.execute("ROLLBACK")
    except (
        SchemaVersionError,
        SourceLabIntegrityError,
        SourceReviewQueueIntegrityError,
        RecoveryError,
        sqlite3.Error,
    ) as exc:
        raise FirstQueueIntegrityError("first queue immutable snapshot is invalid") from exc
    finally:
        con.close()
    after = _snapshot(path)
    if before != after or total_changes != 0:
        raise FirstQueueIntegrityError("first queue snapshot changed during inspection")

    semantic_body = {
        "manifest_hash": manifest_hash,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "schema_object_count": schema_inventory[0],
        "schema_inventory_hash": schema_inventory[1],
        "event_count": event_ledger[0],
        "event_ledger_hash": event_ledger[1],
        "event_head_rowid": event_ledger[2],
        "event_head_id": event_ledger[3],
        "event_head_payload_hash": event_ledger[4],
        "source_lab_ledger": source_lab_ledger,
        "site": asdict(site),
        "wave1": [asdict(item) for item in wave1],
        "queue": asdict(queue),
        "selected_record_count": len(selected_record_ids),
        "selected_review_count": len(selected_review_ids),
        "safety_switches": {
            "external_writers_enabled": False,
            "external_source_reads_enabled": False,
            "manual_import_commits_enabled": False,
        },
    }
    semantic_hash = payload_hash(semantic_body)
    values: dict[str, object] = {
        "report_version": FIRST_QUEUE_SNAPSHOT_REPORT_VERSION,
        "report_hash": "",
        "manifest_hash": manifest_hash,
        "status": FIRST_QUEUE_STATUS,
        "intake_reconciliation_status": "PASSED",
        "criterion_42_3_6_passed": False,
        "fast_commercial_slice_ready": False,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "schema_object_count": schema_inventory[0],
        "schema_inventory_hash": schema_inventory[1],
        "event_count": event_ledger[0],
        "event_ledger_hash": event_ledger[1],
        "event_head_rowid": event_ledger[2],
        "event_head_id": event_ledger[3],
        "event_head_payload_hash": event_ledger[4],
        "database_sha256": before[2],
        "database_size_bytes": before[0],
        "database_mtime_ns": before[1],
        "source_lab_ledger_count": int(source_lab_ledger["count"]),
        "source_lab_event_count": int(source_lab_ledger["event_count"]),
        "source_lab_ledger_hash": str(source_lab_ledger["ledger_sha256"]),
        "site": site,
        "wave1": wave1,
        "queue": queue,
        "selected_record_count": len(selected_record_ids),
        "selected_review_count": len(selected_review_ids),
        "external_writers_enabled": False,
        "external_source_reads_enabled": False,
        "manual_import_commits_enabled": False,
        "query_only": True,
        "sidecars_absent": True,
        "source_unchanged": True,
        "live_calls_performed": 0,
        "external_writes_performed": 0,
        "missing_components": FIRST_QUEUE_MISSING_COMPONENTS,
        "semantic_hash": semantic_hash,
    }
    report_hash = payload_hash(
        {
            key: asdict(value) if hasattr(value, "__dataclass_fields__") else (
                [asdict(item) for item in value]
                if key == "wave1"
                else value
            )
            for key, value in _report_body(values).items()
        }
    )
    values["report_hash"] = report_hash
    return FirstQueueSnapshotReport(**values)


__all__ = [
    "FIRST_QUEUE_CONTRACT_VERSION",
    "FIRST_QUEUE_EVIDENCE_MODE",
    "FIRST_QUEUE_MISSING_COMPONENTS",
    "FIRST_QUEUE_SNAPSHOT_MANIFEST_VERSION",
    "FIRST_QUEUE_SNAPSHOT_REPORT_VERSION",
    "FIRST_QUEUE_STATUS",
    "FirstQueueManifestError",
    "FirstQueueIntegrityError",
    "FirstQueueQueueSnapshot",
    "FirstQueueSiteDeliveryExpectation",
    "FirstQueueSiteExpectation",
    "FirstQueueSiteSnapshot",
    "FirstQueueSnapshotConflict",
    "FirstQueueSnapshotError",
    "FirstQueueSnapshotManifest",
    "FirstQueueSnapshotReport",
    "FirstQueueWave1Expectation",
    "FirstQueueWave1Snapshot",
    "SiteSnapshotExpectation",
    "Wave1SnapshotExpectation",
    "first_queue_manifest_hash",
    "inspect_first_queue_snapshot",
    "validate_first_queue_manifest",
]
