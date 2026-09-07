"""Read-only reconciliation for the offline ``AT-SRC-PAR-01`` fixture.

The commercial bridges are responsible for creating and reusing the local
Company/Project/Opportunity graph.  This module does not create, repair, or
dispatch anything.  It proves that three independently approved Source Lab
records with one exact project identity retained three immutable evidence
chains while producing a single local graph and a single four-operation CRM
stage.

The report deliberately opens SQLite in ``mode=ro`` with ``query_only``.  A
failed or incomplete proof raises instead of returning a partially trusted
report.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    CrmGraphOutbox,
    DEAL_CREATE,
    GraphInvariantError,
)
from .bitrix_graph_mapping import (
    BitrixGraphMappingError,
    validate_graph_bridge_binding,
)
from .ids import canonical_json, payload_hash
from .source_lab import canonical_identity_fingerprints
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity
from .source_commercial_bridge import (
    ApprovedSourceCommand,
    SourceCommercialBridge,
    SourceCommercialBridgeError,
    SourceCommercialPolicy,
    TrustedApprovalReceipt,
    _validate_approval_receipt,
)
from .store import CURRENT_SCHEMA_VERSION, FactoryStore


AT_SRC_PAR_01 = "AT-SRC-PAR-01"
_ANCHOR_VERSION = "source-commercial-approved-link-anchor-v1"
_ANCHOR_EVENT = "source_commercial_approved_link_anchored"
_BRIDGE_PRODUCER = "source_commercial_bridge"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_NON_PROJECT_NAMESPACES = frozenset(
    {"inn", "ogrn", "domain", "email", "phone", "contact-email", "contact-phone"}
)
_ANCHOR_KEYS = frozenset(
    {
        "anchor_version",
        "evidence_link_id",
        "link_event_id",
        "link_command_hash",
        "lf_company_id",
        "lf_contact_id",
        "lf_project_id",
        "lf_opportunity_id",
        "source_record_id",
        "observation_id",
        "review_id",
        "resolution_id",
        "resolution_event_id",
        "resolution_command_hash",
        "resolution_event_hash",
        "source_payload_hash",
        "strong_identity_hashes",
        "approval_request_hash",
        "approval_receipt_hash",
        "approval_authority_id",
        "approval_receipt_id",
        "policy_id",
        "policy_version",
        "policy_hash",
        "source_id",
        "data_contract_version",
        "mapping_policy_hash",
        "mapping_manifest_hash",
        "lf_source_id",
        "activity_deadline_utc",
        "graph_created",
        "creator_resolution_event_id",
    }
)
_ANCHOR_DIGEST_KEYS = frozenset(
    {
        "link_command_hash",
        "resolution_command_hash",
        "resolution_event_hash",
        "source_payload_hash",
        "approval_request_hash",
        "approval_receipt_hash",
        "policy_hash",
        "mapping_policy_hash",
        "mapping_manifest_hash",
    }
)
_CRM_TYPES = (COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE)


class CrossSourceReconciliationError(RuntimeError):
    """The stored AT-SRC-PAR-01 proof is absent, ambiguous, or inconsistent."""


class CrossSourceExpectationError(CrossSourceReconciliationError):
    """The caller supplied an invalid acceptance manifest."""


@dataclass(frozen=True, slots=True, repr=False)
class CrossSourceApprovalBinding:
    """Expected local policy and typed authority receipt for one source."""

    source_id: str
    policy: SourceCommercialPolicy
    receipt: TrustedApprovalReceipt

    def __repr__(self) -> str:
        return "CrossSourceApprovalBinding(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class CrossSourceExpectation:
    """Privacy-safe exact manifest for one three-source acceptance object."""

    source_ids: tuple[str, str, str]
    project_identity_namespace: str
    project_identity_hash: str
    approval_bindings: tuple[CrossSourceApprovalBinding, ...] = ()

    def __repr__(self) -> str:
        return "CrossSourceExpectation(<redacted>)"


@dataclass(frozen=True, slots=True)
class CrossSourceEvidenceSlice:
    """One source's immutable proof, kept separate for source metrics."""

    source_id: str
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    resolution_event_id: str
    evidence_link_id: str
    anchor_event_id: str
    graph_created: bool
    source_payload_hash: str
    policy_hash: str
    mapping_policy_hash: str
    mapping_manifest_hash: str
    lf_source_id: str
    activity_deadline_utc: str
    data_contract_version: str
    approval_request_hash: str
    approval_receipt_hash: str
    approval_authority_id: str
    approval_receipt_id: str


@dataclass(frozen=True, slots=True)
class CrossSourceReconciliationReport:
    acceptance_id: str
    status: str
    schema_version: int
    source_ids: tuple[str, str, str]
    source_slices: tuple[CrossSourceEvidenceSlice, ...]
    project_identity_namespace: str
    project_identity_hash: str
    company_inn_hash: str
    lf_company_id: str
    lf_contact_id: str
    lf_project_id: str
    lf_opportunity_id: str
    creator_resolution_event_id: str
    resolution_event_ids: tuple[str, str, str]
    source_record_count: int
    company_count: int
    contact_count: int
    project_count: int
    opportunity_count: int
    evidence_link_count: int
    graph_creator_count: int
    graph_reuse_count: int
    crm_operation_counts: tuple[tuple[str, int], ...]
    crm_outbox_operation_count: int
    crm_mapping_count: int
    external_writers_enabled: bool
    external_source_reads_enabled: bool
    manual_import_commits_enabled: bool
    live_calls_performed: int
    report_hash: str


def _expectation(value: object) -> CrossSourceExpectation:
    if type(value) is not CrossSourceExpectation:
        raise CrossSourceExpectationError("cross-source expectation is invalid")
    if type(value.source_ids) is not tuple or len(value.source_ids) != 3:
        raise CrossSourceExpectationError("exactly three source identities are required")
    sources: list[str] = []
    for source_id in value.source_ids:
        if type(source_id) is not str or not _SAFE_ID.fullmatch(source_id):
            raise CrossSourceExpectationError("cross-source identity is invalid")
        sources.append(source_id)
    if len(set(sources)) != 3 or tuple(sorted(sources)) != value.source_ids:
        raise CrossSourceExpectationError(
            "cross-source identities must be distinct and sorted"
        )
    namespace = value.project_identity_namespace
    if (
        type(namespace) is not str
        or not _NAMESPACE.fullmatch(namespace)
        or namespace in _NON_PROJECT_NAMESPACES
    ):
        raise CrossSourceExpectationError("strong project namespace is invalid")
    digest = value.project_identity_hash
    if type(digest) is not str or not _HEX64.fullmatch(digest):
        raise CrossSourceExpectationError("strong project identity hash is invalid")
    if type(value.approval_bindings) is not tuple or len(value.approval_bindings) != 3:
        raise CrossSourceExpectationError(
            "three typed cross-source approval bindings are required"
        )
    binding_sources: list[str] = []
    receipt_ids: set[str] = set()
    receipt_hashes: set[str] = set()
    for binding in value.approval_bindings:
        if type(binding) is not CrossSourceApprovalBinding:
            raise CrossSourceExpectationError(
                "cross-source approval binding is invalid"
            )
        if binding.source_id not in sources or binding.source_id in binding_sources:
            raise CrossSourceExpectationError(
                "cross-source approval binding is invalid"
            )
        if (
            type(binding.policy) is not SourceCommercialPolicy
            or binding.policy.source_id != binding.source_id
            or _expectation_namespace_missing(binding.policy, namespace)
            or type(binding.receipt) is not TrustedApprovalReceipt
        ):
            raise CrossSourceExpectationError(
                "cross-source approval binding is invalid"
            )
        receipt_id = binding.receipt.receipt_id
        receipt_hash = binding.receipt.receipt_hash
        if (
            type(receipt_id) is not str
            or not _SAFE_ID.fullmatch(receipt_id)
            or not _HEX64.fullmatch(receipt_hash)
            or receipt_id in receipt_ids
            or receipt_hash in receipt_hashes
        ):
            raise CrossSourceExpectationError(
                "cross-source approval binding is invalid"
            )
        binding_sources.append(binding.source_id)
        receipt_ids.add(receipt_id)
        receipt_hashes.add(receipt_hash)
    if tuple(binding_sources) != value.source_ids:
        raise CrossSourceExpectationError(
            "cross-source approval bindings must follow source order"
        )
    return value


def _expectation_namespace_missing(
    policy: SourceCommercialPolicy, namespace: str
) -> bool:
    namespaces = policy.strong_project_namespaces
    return type(namespaces) is not tuple or namespaces != (namespace,)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _database_snapshot(path: Path) -> tuple[int, int, str]:
    if not path.is_file():
        raise CrossSourceReconciliationError("cross-source database is missing")
    if any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")):
        raise CrossSourceReconciliationError(
            "cross-source database is not a quiescent immutable snapshot"
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


def _meta(con: sqlite3.Connection) -> dict[str, str]:
    return {
        str(row[0]): str(row[1])
        for row in con.execute(
            """SELECT key,value FROM schema_meta WHERE key IN
               ('schema_version','external_writers_enabled',
                'external_source_reads_enabled','manual_import_commits_enabled')"""
        ).fetchall()
    }


def _strict_anchor_event(
    con: sqlite3.Connection,
    link: sqlite3.Row,
    *,
    expected_source_id: str,
) -> tuple[sqlite3.Row, dict[str, Any]]:
    link_id = str(link["evidence_link_id"] or "")
    rows = con.execute(
        """SELECT * FROM events
           WHERE aggregate_type='source_lab_evidence_link' AND aggregate_id=?
           ORDER BY event_id""",
        (link_id,),
    ).fetchall()
    if len(rows) != 1:
        raise CrossSourceReconciliationError(
            "exactly one commercial evidence anchor is required"
        )
    event = rows[0]
    try:
        raw = str(event["payload_json"] or "")
        anchor = json.loads(raw)
        rendered = canonical_json(anchor)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise CrossSourceReconciliationError("commercial evidence anchor is invalid") from None
    if type(anchor) is not dict or frozenset(anchor) != _ANCHOR_KEYS:
        raise CrossSourceReconciliationError("commercial evidence anchor is invalid")
    for key in _ANCHOR_KEYS - {"strong_identity_hashes", "graph_created"}:
        if type(anchor[key]) is not str or not anchor[key]:
            raise CrossSourceReconciliationError("commercial evidence anchor is invalid")
    for key in _ANCHOR_DIGEST_KEYS:
        if not _HEX64.fullmatch(anchor[key]):
            raise CrossSourceReconciliationError("commercial evidence anchor is invalid")
    strong = anchor["strong_identity_hashes"]
    if (
        type(strong) is not list
        or not strong
        or any(type(item) is not str or not _HEX64.fullmatch(item) for item in strong)
        or strong != sorted(set(strong))
        or type(anchor["graph_created"]) is not bool
        or not _UTC_SECONDS.fullmatch(anchor["activity_deadline_utc"])
    ):
        raise CrossSourceReconciliationError("commercial evidence anchor is invalid")
    occurred = str(event["occurred_at_utc"] or "")
    recorded = str(event["recorded_at_utc"] or "")
    try:
        schema_version = int(event["schema_version"])
    except (TypeError, ValueError):
        raise CrossSourceReconciliationError("commercial evidence anchor is invalid") from None
    if (
        rendered != raw
        or payload_hash(anchor) != str(event["payload_hash"] or "")
        or str(event["event_type"] or "") != _ANCHOR_EVENT
        or str(event["producer"] or "") != _BRIDGE_PRODUCER
        or str(event["actor"] or "") != _BRIDGE_PRODUCER
        or str(event["idempotency_key"] or "") != f"approved-link-anchor:{link_id}"
        or str(event["correlation_id"] or "") != str(event["event_id"] or "")
        or str(event["causation_id"] or "") != anchor["resolution_event_id"]
        or str(event["evidence_ref"] or "")
        or occurred != recorded
        or not _UTC_SECONDS.fullmatch(occurred)
        or schema_version != 16
        or anchor["anchor_version"] != _ANCHOR_VERSION
        or anchor["evidence_link_id"] != link_id
        or anchor["link_event_id"] != str(link["event_id"] or "")
        or anchor["link_command_hash"] != str(link["command_hash"] or "")
        or anchor["lf_opportunity_id"] != str(link["lf_opportunity_id"] or "")
        or anchor["source_record_id"] != str(link["source_record_id"] or "")
        or anchor["source_id"] != expected_source_id
    ):
        raise CrossSourceReconciliationError("commercial evidence anchor is invalid")
    return event, anchor


def _source_slice(
    con: sqlite3.Connection,
    source_id: str,
    expectation: CrossSourceExpectation,
    bridge: SourceCommercialBridge,
    approval_binding: CrossSourceApprovalBinding,
) -> tuple[CrossSourceEvidenceSlice, dict[str, Any], sqlite3.Row]:
    rows = con.execute(
        """SELECT DISTINCT s.source_record_id,o.observation_id
           FROM source_lab_records s
           JOIN source_lab_record_observations o
             ON o.source_record_id=s.source_record_id
           JOIN source_lab_record_identity_links l
             ON l.source_record_id=s.source_record_id
            AND l.observation_id=o.observation_id
           JOIN source_lab_identity_keys k ON k.identity_key_id=l.identity_key_id
           WHERE s.source_id=? AND k.key_namespace=? AND k.canonical_key_hash=?
           ORDER BY s.source_record_id,o.observation_id""",
        (
            source_id,
            expectation.project_identity_namespace,
            expectation.project_identity_hash,
        ),
    ).fetchall()
    if len(rows) != 1:
        raise CrossSourceReconciliationError(
            "each source must have one exact project observation"
        )
    record_id = str(rows[0]["source_record_id"])
    observation_id = str(rows[0]["observation_id"])
    links = con.execute(
        """SELECT * FROM source_lab_opportunity_evidence_links
           WHERE source_record_id=? ORDER BY evidence_link_id""",
        (record_id,),
    ).fetchall()
    if len(links) != 1:
        raise CrossSourceReconciliationError(
            "each source record must have one opportunity evidence link"
        )
    link = links[0]
    event, anchor = _strict_anchor_event(
        con, link, expected_source_id=source_id
    )
    if (
        anchor["observation_id"] != observation_id
        or expectation.project_identity_hash not in anchor["strong_identity_hashes"]
    ):
        raise CrossSourceReconciliationError("strong project proof is detached")
    record = con.execute(
        "SELECT * FROM source_lab_records WHERE source_record_id=?",
        (record_id,),
    ).fetchone()
    if not record:
        raise CrossSourceReconciliationError("approved source record is missing")
    command = ApprovedSourceCommand(
        source_record_id=record_id,
        observation_id=observation_id,
        review_id=anchor["review_id"],
        latest_resolution_id=anchor["resolution_id"],
        expected_payload_hash=str(record["payload_hash"] or ""),
        actor="cross-source-reconciliation",
        idempotency_key=f"cross-source-reconcile:{link['evidence_link_id']}",
    )
    try:
        approved = bridge._load_approved_import(con, command)
        request = bridge._current_approval_request(approved)
        receipt = _validate_approval_receipt(approval_binding.receipt, request)
        proof = bridge._current_approval_proof(con, approved, request, receipt)
        verified = bridge._validate_anchored_link(
            con,
            link,
            required=True,
            expected_proof=proof,
        )
    except SourceCommercialBridgeError:
        raise CrossSourceReconciliationError(
            "typed commercial approval proof is invalid"
        ) from None
    if (
        verified is None
        or verified.evidence_link_id != str(link["evidence_link_id"])
        or verified.opportunity_id != str(link["lf_opportunity_id"])
        or anchor["mapping_manifest_hash"] != request.mapping_manifest_hash
        or anchor["lf_source_id"] != request.lf_source_id
        or anchor["activity_deadline_utc"] != request.activity_deadline_utc
    ):
        raise CrossSourceReconciliationError(
            "typed commercial approval proof is invalid"
        )
    review = con.execute(
        "SELECT * FROM source_lab_reviews WHERE review_id=?",
        (anchor["review_id"],),
    ).fetchone()
    resolution = con.execute(
        "SELECT * FROM source_lab_review_resolutions WHERE resolution_id=?",
        (anchor["resolution_id"],),
    ).fetchone()
    if (
        not review
        or not resolution
        or str(review["source_record_id"] or "") != record_id
        or str(resolution["review_id"] or "") != str(review["review_id"] or "")
        or str(resolution["event_id"] or "") != anchor["resolution_event_id"]
        or str(resolution["command_hash"] or "") != anchor["resolution_command_hash"]
        or str(resolution["decision"] or "") != "APPROVE"
        or str(link["link_reason"] or "") != "APPROVED_SOURCE_IMPORT"
        or str(link["actor"] or "") != _BRIDGE_PRODUCER
    ):
        raise CrossSourceReconciliationError("approved source lineage is invalid")
    resolution_event = con.execute(
        "SELECT * FROM events WHERE event_id=?",
        (anchor["resolution_event_id"],),
    ).fetchone()
    if (
        not resolution_event
        or str(resolution_event["payload_hash"] or "") != anchor["resolution_event_hash"]
    ):
        raise CrossSourceReconciliationError("approved source lineage is invalid")
    return (
        CrossSourceEvidenceSlice(
            source_id=source_id,
            source_record_id=record_id,
            observation_id=observation_id,
            review_id=str(review["review_id"]),
            resolution_id=str(resolution["resolution_id"]),
            resolution_event_id=str(resolution["event_id"]),
            evidence_link_id=str(link["evidence_link_id"]),
            anchor_event_id=str(event["event_id"]),
            graph_created=bool(anchor["graph_created"]),
            source_payload_hash=proof.source_payload_hash,
            policy_hash=request.policy_hash,
            mapping_policy_hash=request.mapping_policy_hash,
            mapping_manifest_hash=request.mapping_manifest_hash,
            lf_source_id=request.lf_source_id,
            activity_deadline_utc=request.activity_deadline_utc,
            data_contract_version=request.data_contract_version,
            approval_request_hash=request.request_hash,
            approval_receipt_hash=receipt.receipt_hash,
            approval_authority_id=receipt.authority_id,
            approval_receipt_id=receipt.receipt_id,
        ),
        anchor,
        link,
    )


def _report_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {
        **report,
        "source_slices": [
            {
                "source_id": item.source_id,
                "source_record_id": item.source_record_id,
                "observation_id": item.observation_id,
                "review_id": item.review_id,
                "resolution_id": item.resolution_id,
                "resolution_event_id": item.resolution_event_id,
                "evidence_link_id": item.evidence_link_id,
                "anchor_event_id": item.anchor_event_id,
                "graph_created": item.graph_created,
                "source_payload_hash": item.source_payload_hash,
                "policy_hash": item.policy_hash,
                "mapping_policy_hash": item.mapping_policy_hash,
                "mapping_manifest_hash": item.mapping_manifest_hash,
                "lf_source_id": item.lf_source_id,
                "activity_deadline_utc": item.activity_deadline_utc,
                "data_contract_version": item.data_contract_version,
                "approval_request_hash": item.approval_request_hash,
                "approval_receipt_hash": item.approval_receipt_hash,
                "approval_authority_id": item.approval_authority_id,
                "approval_receipt_id": item.approval_receipt_id,
            }
            for item in report["source_slices"]
        ],
        "crm_operation_counts": [list(item) for item in report["crm_operation_counts"]],
        "source_ids": list(report["source_ids"]),
        "resolution_event_ids": list(report["resolution_event_ids"]),
    }


def reconcile_cross_source_object(
    store: FactoryStore,
    expectation: CrossSourceExpectation,
    *,
    _connection: sqlite3.Connection | None = None,
) -> CrossSourceReconciliationReport:
    """Return a deterministic proof or fail closed without changing the DB."""

    if type(store) is not FactoryStore:
        raise CrossSourceExpectationError("cross-source store is invalid")
    expected = _expectation(expectation)
    path = Path(store.path).resolve()
    owns_connection = _connection is None
    before_snapshot = _database_snapshot(path) if owns_connection else None
    con = _read_connection(path) if owns_connection else _connection
    if con is None:
        raise CrossSourceExpectationError("cross-source connection is invalid")
    started_transaction = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            started_transaction = True
        if store._probe_schema(con) != CURRENT_SCHEMA_VERSION:
            raise CrossSourceReconciliationError(
                "cross-source acceptance requires the current exact schema"
            )
        try:
            validate_source_lab_integrity(con)
        except SourceLabIntegrityError:
            raise CrossSourceReconciliationError(
                "Source Lab integrity validation failed"
            ) from None
        meta = _meta(con)
        if (
            meta.get("schema_version") != str(CURRENT_SCHEMA_VERSION)
            or meta.get("external_writers_enabled") != "0"
            or meta.get("external_source_reads_enabled") != "0"
            or meta.get("manual_import_commits_enabled") != "0"
        ):
            raise CrossSourceReconciliationError(
                "cross-source acceptance safety switches are invalid"
            )

        slices: list[CrossSourceEvidenceSlice] = []
        anchors: list[dict[str, Any]] = []
        links: list[sqlite3.Row] = []
        for source_id, approval_binding in zip(
            expected.source_ids, expected.approval_bindings, strict=True
        ):
            try:
                bridge = SourceCommercialBridge(
                    store,
                    policy=approval_binding.policy,
                    approval_authority=None,
                )
            except SourceCommercialBridgeError:
                raise CrossSourceExpectationError(
                    "cross-source commercial policy is invalid"
                ) from None
            source_slice, anchor, link = _source_slice(
                con,
                source_id,
                expected,
                bridge,
                approval_binding,
            )
            slices.append(source_slice)
            anchors.append(anchor)
            links.append(link)

        graph_ids = {
            key: {str(anchor[key]) for anchor in anchors}
            for key in (
                "lf_company_id",
                "lf_contact_id",
                "lf_project_id",
                "lf_opportunity_id",
            )
        }
        if any(len(values) != 1 for values in graph_ids.values()):
            raise CrossSourceReconciliationError(
                "cross-source evidence did not resolve to one normalized graph"
            )
        company_id = next(iter(graph_ids["lf_company_id"]))
        contact_id = next(iter(graph_ids["lf_contact_id"]))
        project_id = next(iter(graph_ids["lf_project_id"]))
        opportunity_id = next(iter(graph_ids["lf_opportunity_id"]))
        company = con.execute(
            "SELECT * FROM companies WHERE lf_company_id=?", (company_id,)
        ).fetchone()
        contact = con.execute(
            "SELECT * FROM contacts WHERE lf_contact_id=?", (contact_id,)
        ).fetchone()
        project = con.execute(
            "SELECT * FROM projects WHERE lf_project_id=?", (project_id,)
        ).fetchone()
        opportunity = con.execute(
            "SELECT * FROM opportunities WHERE lf_opportunity_id=?", (opportunity_id,)
        ).fetchone()
        if not all((company, contact, project, opportunity)):
            raise CrossSourceReconciliationError("normalized graph is incomplete")
        inn = str(company["inn"] or "")
        if not re.fullmatch(r"[0-9]{10}|[0-9]{12}", inn):
            raise CrossSourceReconciliationError("normalized company INN is not exact")
        inn_fingerprints = canonical_identity_fingerprints((("inn", inn),))
        if len(inn_fingerprints) != 1:
            raise CrossSourceReconciliationError("normalized company INN is not exact")
        company_inn_hash = inn_fingerprints[0][1]
        if (
            str(contact["lf_company_id"] or "") != company_id
            or str(project["lf_company_id"] or "") != company_id
            or str(opportunity["lf_company_id"] or "") != company_id
            or str(opportunity["lf_contact_id"] or "") != contact_id
            or str(opportunity["lf_project_id"] or "") != project_id
            or str(company["identity_state"] or "") != "EXACT"
        ):
            raise CrossSourceReconciliationError("normalized graph crossed identity boundaries")
        for source_slice in slices:
            identity = con.execute(
                """SELECT COUNT(*) FROM source_lab_record_identity_links l
                   JOIN source_lab_identity_keys k
                     ON k.identity_key_id=l.identity_key_id
                   WHERE l.source_record_id=? AND l.observation_id=?
                     AND k.key_namespace='inn' AND k.canonical_key_hash=?""",
                (
                    source_slice.source_record_id,
                    source_slice.observation_id,
                    company_inn_hash,
                ),
            ).fetchone()
            if not identity or int(identity[0]) != 1:
                raise CrossSourceReconciliationError(
                    "cross-source company identity is not exact"
                )

        creator_anchors = [anchor for anchor in anchors if anchor["graph_created"]]
        if len(creator_anchors) != 1:
            raise CrossSourceReconciliationError(
                "cross-source graph must have exactly one creator"
            )
        creator_event = str(creator_anchors[0]["creator_resolution_event_id"])
        if any(
            anchor["creator_resolution_event_id"] != creator_event
            for anchor in anchors
        ):
            raise CrossSourceReconciliationError(
                "cross-source graph creator lineage is inconsistent"
            )
        if any(
            bool(anchor["graph_created"])
            != (anchor["resolution_event_id"] == creator_event)
            for anchor in anchors
        ):
            raise CrossSourceReconciliationError(
                "cross-source graph creator flag is inconsistent"
            )
        strong_sets = {tuple(anchor["strong_identity_hashes"]) for anchor in anchors}
        if len(strong_sets) != 1:
            raise CrossSourceReconciliationError(
                "cross-source strong project proofs do not match exactly"
            )
        creator_source_id = str(creator_anchors[0]["source_id"])
        creator_policy = next(
            (
                item.policy
                for item in expected.approval_bindings
                if item.source_id == creator_source_id
            ),
            None,
        )
        if creator_policy is None:
            raise CrossSourceReconciliationError("graph creator policy is absent")
        creator_binding = replace(
            creator_policy.bitrix_graph_binding,
            lf_source_id=str(creator_anchors[0]["lf_source_id"]),
            activity_deadline_utc=str(creator_anchors[0]["activity_deadline_utc"]),
        )
        try:
            if (
                validate_graph_bridge_binding(creator_binding)
                != str(creator_anchors[0]["mapping_manifest_hash"])
            ):
                raise CrossSourceReconciliationError("graph creator binding is invalid")
        except BitrixGraphMappingError:
            raise CrossSourceReconciliationError("graph creator binding is invalid") from None

        operations = con.execute(
            """SELECT * FROM crm_outbox
               WHERE (lf_entity_type='company' AND lf_entity_id=?)
                  OR (lf_entity_type='contact' AND lf_entity_id=?)
                  OR (lf_entity_type='opportunity' AND lf_entity_id=?)
               ORDER BY operation_type""",
            (company_id, contact_id, opportunity_id),
        ).fetchall()
        operation_counts = tuple(
            (operation_type, sum(row["operation_type"] == operation_type for row in operations))
            for operation_type in sorted(_CRM_TYPES)
        )
        operation_by_type = {str(row["operation_type"]): row for row in operations}
        graph = SourceCommercialBridge._load_graph(con, opportunity_id)
        graph_payloads = SourceCommercialBridge._crm_payloads(
            con, graph, creator_binding, creator_event
        )
        expected_public_payloads = {
            COMPANY_CREATE: graph_payloads["company"],
            CONTACT_CREATE: graph_payloads["contact"],
            DEAL_CREATE: graph_payloads["deal"],
            ACTIVITY_CREATE: graph_payloads["activity"],
        }
        try:
            for row in operations:
                body = CrmGraphOutbox._assert_operation_envelope(row)
                CrmGraphOutbox._assert_stage_anchor_tx(con, row)
                operation_type = str(row["operation_type"])
                expected_metadata = CrmGraphOutbox._metadata(
                    operation_type,
                    company_id=company_id,
                    contact_id=contact_id,
                    project_id=project_id,
                    opportunity_id=opportunity_id,
                    mapping_manifest_hash=validate_graph_bridge_binding(
                        creator_binding
                    ),
                    lf_source_id=creator_binding.lf_source_id,
                )
                public_body = {
                    key: value
                    for key, value in body.items()
                    if not str(key).startswith("_lf_")
                }
                if (
                    body.get("_lf_graph_v1") != expected_metadata
                    or public_body != expected_public_payloads[operation_type]
                ):
                    raise GraphInvariantError("CRM graph metadata changed")
        except GraphInvariantError:
            raise CrossSourceReconciliationError(
                "cross-source CRM graph proof is invalid"
            ) from None
        if (
            len(operations) != 4
            or set(operation_by_type) != set(_CRM_TYPES)
            or any(count != 1 for _, count in operation_counts)
            or any(str(row["external_event_id"] or "") != creator_event for row in operations)
            or any(str(row["state"] or "") != "PENDING" for row in operations)
            or any(int(row["attempt_count"]) != 0 for row in operations)
            or any(int(row["reconcile_count"]) != 0 for row in operations)
            or any(
                str(row[key] or "")
                for row in operations
                for key in (
                    "next_attempt_at_utc",
                    "lease_until_utc",
                    "leased_by",
                    "lease_token",
                    "last_error_class",
                    "last_error_hash",
                    "remote_entity_type",
                    "remote_entity_id",
                    "suspect_remote_entity_type",
                    "suspect_remote_entity_id",
                )
            )
            or any(
                str(row["updated_at_utc"] or "")
                != str(row["created_at_utc"] or "")
                for row in operations
            )
        ):
            raise CrossSourceReconciliationError(
                "cross-source CRM stage is not one untouched creator graph"
            )
        company_op = operation_by_type[COMPANY_CREATE]
        contact_op = operation_by_type[CONTACT_CREATE]
        deal_op = operation_by_type[DEAL_CREATE]
        activity_op = operation_by_type[ACTIVITY_CREATE]
        if (
            str(company_op["dependency_operation_id"] or "")
            or str(contact_op["dependency_operation_id"] or "")
            != str(company_op["operation_id"])
            or str(deal_op["dependency_operation_id"] or "")
            != str(contact_op["operation_id"])
            or str(activity_op["dependency_operation_id"] or "")
            != str(deal_op["operation_id"])
        ):
            raise CrossSourceReconciliationError("CRM graph dependency chain is invalid")
        mapping_count = int(
            con.execute(
                """SELECT COUNT(*) FROM crm_mappings
                   WHERE (lf_entity_type='company' AND lf_entity_id=?)
                      OR (lf_entity_type='contact' AND lf_entity_id=?)
                      OR (lf_entity_type='opportunity' AND lf_entity_id=?)""",
                (company_id, contact_id, opportunity_id),
            ).fetchone()[0]
        )
        if mapping_count:
            raise CrossSourceReconciliationError(
                "cross-source acceptance performed an external CRM mapping"
            )

        base: dict[str, Any] = {
            "acceptance_id": AT_SRC_PAR_01,
            "status": "PASSED",
            "schema_version": CURRENT_SCHEMA_VERSION,
            "source_ids": expected.source_ids,
            "source_slices": tuple(slices),
            "project_identity_namespace": expected.project_identity_namespace,
            "project_identity_hash": expected.project_identity_hash,
            "company_inn_hash": company_inn_hash,
            "lf_company_id": company_id,
            "lf_contact_id": contact_id,
            "lf_project_id": project_id,
            "lf_opportunity_id": opportunity_id,
            "creator_resolution_event_id": creator_event,
            "resolution_event_ids": tuple(
                sorted(item.resolution_event_id for item in slices)
            ),
            "source_record_count": len(slices),
            "company_count": 1,
            "contact_count": 1,
            "project_count": 1,
            "opportunity_count": 1,
            "evidence_link_count": len(links),
            "graph_creator_count": len(creator_anchors),
            "graph_reuse_count": len(anchors) - len(creator_anchors),
            "crm_operation_counts": operation_counts,
            "crm_outbox_operation_count": len(operations),
            "crm_mapping_count": mapping_count,
            "external_writers_enabled": False,
            "external_source_reads_enabled": False,
            "manual_import_commits_enabled": False,
            "live_calls_performed": 0,
        }
        digest = payload_hash(_report_payload(base))
        return CrossSourceReconciliationReport(**base, report_hash=digest)
    except (CrossSourceReconciliationError, CrossSourceExpectationError):
        raise
    except (KeyError, TypeError, ValueError, sqlite3.DatabaseError):
        raise CrossSourceReconciliationError(
            "cross-source acceptance reconciliation failed"
        ) from None
    finally:
        if started_transaction and con.in_transaction:
            con.rollback()
        if owns_connection:
            con.close()
            if _database_snapshot(path) != before_snapshot:
                raise CrossSourceReconciliationError(
                    "cross-source database changed during immutable reconciliation"
                )


__all__ = [
    "AT_SRC_PAR_01",
    "CrossSourceApprovalBinding",
    "CrossSourceEvidenceSlice",
    "CrossSourceExpectation",
    "CrossSourceExpectationError",
    "CrossSourceReconciliationError",
    "CrossSourceReconciliationReport",
    "reconcile_cross_source_object",
]
