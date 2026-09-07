from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import tempfile
from types import MethodType
import unittest
from unittest.mock import patch

from lead_factory.commercial_spine import OfflineCrmOutcomeIntake, OpportunityState
from lead_factory.construction_radar import (
    CapabilityState,
    LicenceState,
    PassportState,
    RadarContour,
    SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.crm_graph_outbox import CrmGraphOutbox
from lead_factory.first_queue_reconciliation import (
    FIRST_QUEUE_RECONCILIATION_MANIFEST_VERSION,
    OFFLINE_CRM_ATTESTATION_VERSION,
    FirstQueueOfflineOperationAttestation,
    FirstQueueOutcomeExpectation,
    FirstQueueReconciliationConflict,
    FirstQueueReconciliationManifest,
    FirstQueueReconciliationManifestError,
    FirstQueueSiteCommercialExpectation,
    capture_first_queue_database_fingerprint,
    first_queue_reconciliation_manifest_hash,
    inspect_first_queue_reconciliation_snapshot,
    offline_operation_proof_hashes,
    offline_operation_attestation_payload,
    validate_first_queue_reconciliation_manifest,
    verify_first_queue_reconciliation_recovery,
)
from lead_factory.ids import new_lf_id, payload_hash
from lead_factory.radar_review_access import (
    RadarEvidenceVault,
    SourceAccessPermitLedger,
    SourceEvidenceBoundary,
)
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.site_commercial_bridge import (
    ApprovedSiteCommand,
    SiteCommercialBridge,
    SiteCommercialPolicy,
    SiteOpportunityProjection,
)
from lead_factory.source_lab import SourceLabSink, canonical_identity_fingerprints
from lead_factory.source_review_queue import SourceReviewQueue
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore
from tests import test_lead_factory_at_site_01 as site_fixture
from tests import test_lead_factory_cross_source_reconciliation as cross_fixture
from tests import test_lead_factory_first_queue_snapshot as phase1_fixture
from tests.test_lead_factory_commercial_path_e2e import FixtureGraphTransport
from tests.test_lead_factory_site_commercial_bridge import (
    ExactSiteAuthority,
    graph_binding,
)


_AUTHORITY_PATCHER = patch(
    "lead_factory.crm_graph_outbox.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


_SITE_COMPANY_INN = "7812345675"
_SITE_REMOTE_DEAL_ID = "301"
_FIXTURE_ID = "first-queue-offline-crm"
_FIXTURE_TRANSPORT_VERSION = "fixture-graph-transport-v1"
_FIXTURE_EXECUTION_ID = "first-queue-site-execution"
_ATTESTATION_ACTOR = "first-queue-offline-crm-fixture"
_EXPECTED_CORE_COUNTS = {
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
    "source_records": 2,
    "interactions": 12,
    "human_tasks": 12,
    "radar_source_passports": 7,
    "radar_source_permissions": 7,
    "radar_source_access_permits": 7,
    "radar_source_access_usage": 7,
    "radar_source_evidence_receipts": 7,
    "radar_evidence_records": 17,
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _physical_snapshot(path: Path) -> tuple[object, ...]:
    stat = path.stat()
    return (
        stat.st_size,
        stat.st_mtime_ns,
        _sha256_file(path),
        tuple(
            (suffix, Path(f"{path}{suffix}").exists())
            for suffix in ("-wal", "-shm", "-journal")
        ),
    )


def _attestation_body(
    *,
    execution_id: str,
    operation_id: str,
    operation_type: str,
    request_hash: str,
    readback_hash: str,
    remote_entity_type: str,
    remote_entity_id: str,
    sent_event_id: str,
    sent_event_payload_hash: str,
    occurred_at_utc: str,
    evidence_ref: str,
) -> dict[str, object]:
    return {
        "attestation_version": OFFLINE_CRM_ATTESTATION_VERSION,
        "transport_mode": "OFFLINE_FIXTURE",
        "fixture_id": _FIXTURE_ID,
        "transport_version": _FIXTURE_TRANSPORT_VERSION,
        "execution_id": execution_id,
        "operation_id": operation_id,
        "operation_type": operation_type,
        "request_hash": request_hash,
        "readback_hash": readback_hash,
        "remote_entity_type": remote_entity_type,
        "remote_entity_id": remote_entity_id,
        "sent_event_id": sent_event_id,
        "sent_event_payload_hash": sent_event_payload_hash,
        "occurred_at_utc": occurred_at_utc,
        "actor": _ATTESTATION_ACTOR,
        "evidence_ref": evidence_ref,
        "fixture_transport_invoked": True,
        "live_provider_called": False,
        "network_calls": 0,
        "external_writes_performed": 0,
    }


class _RecordingSiteAuthority(ExactSiteAuthority):
    def __init__(self) -> None:
        super().__init__()
        self.receipts = []

    def verify_approval(self, request):
        receipt = super().verify_approval(request)
        self.receipts.append(receipt)
        return receipt


def _phase_two_passport(builder, source_id: str):
    cached = builder.passport_cache.get(source_id)
    if cached is not None:
        return cached
    passport = builder.passports.register(
        SourcePassport(
            source_key=source_id,
            passport_version=2,
            contour=RadarContour.CAPITAL_PROJECT,
            acquisition_mode="OFFLINE_FIXTURE",
            allowed_data_classes=("B2B_LEAD_CANDIDATE",),
            max_age_days=30,
            state=PassportState.APPROVED,
            capability_state=CapabilityState.PASS,
            licence_state=LicenceState.ALLOWED,
            terms_ref=f"evidence://passport/{source_id}/terms-v2",
            licence_ref=f"evidence://passport/{source_id}/licence-v2",
            capability_evidence_ref=(
                f"evidence://passport/{source_id}/capability-v2"
            ),
            valid_from_utc="2026-08-01T00:00:00Z",
            valid_until_utc="2026-09-01T00:00:00Z",
            data_contract_version="aluminium-lead-v1",
        ),
        idempotency_key=f"phase2-cross-source-passport:{source_id}:v2",
        actor="offline-test",
    )
    builder.passport_cache[source_id] = passport
    return passport


class FirstQueueReconciliationAcceptanceTests(unittest.TestCase):
    """One schema-17 fixture proves the exact composed offline phase-2 path."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._template_temp = tempfile.TemporaryDirectory()
        cls.template_root = Path(cls._template_temp.name)
        cls.template_path = cls.template_root / "first-queue-phase2.sqlite3"

        phase1 = phase1_fixture.FirstQueueSnapshotAcceptanceTests
        phase1.setUpClass()
        try:
            shutil.copy2(phase1.template_path, cls.template_path)
            cls.baseline_manifest = phase1.manifest
        finally:
            phase1.tearDownClass()

        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in first queue phase 2"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in first queue phase 2"),
            ),
        ):
            cls._build_template()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._template_temp.cleanup()

    @classmethod
    def _build_template(cls) -> None:
        from lead_factory.first_queue_snapshot import inspect_first_queue_snapshot

        baseline = inspect_first_queue_snapshot(
            cls.template_path,
            cls.baseline_manifest,
        )
        cls.baseline_report = baseline
        store = FactoryStore(cls.template_path)
        site = cls._stage_site_commercial(store)
        attestations = cls._send_site_graph_with_attestations(store, site)
        outcome = cls._record_site_outcome(store, site)
        cross_expectation, cross_report = cls._stage_cross_source_graph(store)

        with store.transaction() as connection:
            switches = dict(
                connection.execute(
                    "SELECT key,value FROM schema_meta WHERE key IN (?,?,?)",
                    (
                        "external_writers_enabled",
                        "external_source_reads_enabled",
                        "manual_import_commits_enabled",
                    ),
                ).fetchall()
            )
            counts = {
                table: int(
                    connection.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0]
                )
                for table in _EXPECTED_CORE_COUNTS
            }
            open_reviews = int(
                connection.execute(
                    "SELECT COUNT(*) FROM source_lab_reviews r "
                    "WHERE NOT EXISTS (SELECT 1 FROM source_lab_review_resolutions x "
                    "WHERE x.review_id=r.review_id)"
                ).fetchone()[0]
            )
            task_states = dict(
                connection.execute(
                    "SELECT status,COUNT(*) FROM human_tasks GROUP BY status"
                ).fetchall()
            )
        if switches != {
            "external_writers_enabled": "0",
            "external_source_reads_enabled": "0",
            "manual_import_commits_enabled": "0",
        }:
            raise AssertionError("phase-2 fixture switches must end fail-closed")
        if counts != _EXPECTED_CORE_COUNTS:
            raise AssertionError(f"phase-2 core counts changed: {counts!r}")
        if open_reviews != 19 or task_states != {"COMPLETED": 1, "OPEN": 11}:
            raise AssertionError("phase-2 review/task distribution changed")
        if cross_report.status != "PASSED":
            raise AssertionError("cross-source phase-2 fixture did not reconcile")

        fingerprint = capture_first_queue_database_fingerprint(cls.template_path)
        if fingerprint.event_count != 167:
            raise AssertionError(
                f"phase-2 event inventory changed: {fingerprint.event_count}"
            )
        site_expectation = FirstQueueSiteCommercialExpectation(
            policy=site["policy"],
            approval_receipt=site["approval_receipt"],
            bridge_actor=site["command"].actor,
            bridge_idempotency_key=site["command"].idempotency_key,
            source_record_id=site["command"].source_record_id,
            observation_id=site["command"].observation_id,
            review_id=site["command"].review_id,
            resolution_id=site["resolution"].resolution_id,
            evidence_link_id=site["result"].staged.evidence_link.evidence_link_id,
            anchor_event_id=site["result"].staged.anchor_event_id,
            lf_company_id=site["result"].lf_company_id,
            lf_contact_id=site["result"].lf_contact_id,
            lf_project_id=site["result"].lf_project_id,
            lf_opportunity_id=site["result"].lf_opportunity_id,
            attestations=tuple(attestations),
        )
        outcome_expectation = FirstQueueOutcomeExpectation(
            inbox_event_id=outcome["result"].inbox_event_id,
            remote_entity_type="deal",
            remote_entity_id=_SITE_REMOTE_DEAL_ID,
            remote_version=1,
            event_type="SCREENED",
            raw_payload_hash=outcome["raw_payload_hash"],
            dedupe_key=outcome["dedupe_key"],
            envelope_hash=outcome["envelope_hash"],
            evidence_ref=outcome["evidence_ref"],
            received_at_utc=outcome["received_at_utc"],
            actor=outcome["actor"],
            lf_opportunity_id=site["result"].lf_opportunity_id,
            transition_id=outcome["result"].transition_id,
        )
        candidate = FirstQueueReconciliationManifest(
            manifest_version=FIRST_QUEUE_RECONCILIATION_MANIFEST_VERSION,
            contract_version="5.2",
            evidence_mode="OFFLINE_FIXTURE",
            schema_version=CURRENT_SCHEMA_VERSION,
            baseline_manifest=cls.baseline_manifest,
            baseline_report_hash=baseline.report_hash,
            baseline_semantic_hash=baseline.semantic_hash,
            baseline_event_head_rowid=baseline.event_head_rowid,
            baseline_event_head_id=baseline.event_head_id,
            baseline_event_head_payload_hash=baseline.event_head_payload_hash,
            final_fingerprint=fingerprint,
            site_commercial=site_expectation,
            cross_source=cross_expectation,
            outcome=outcome_expectation,
            declared_manifest_hash="",
        )
        cls.manifest = replace(
            candidate,
            declared_manifest_hash=first_queue_reconciliation_manifest_hash(candidate),
        )
        validate_first_queue_reconciliation_manifest(cls.manifest)

    @classmethod
    def _stage_site_commercial(cls, store: FactoryStore) -> dict[str, object]:
        connection = store.connect()
        try:
            rows = connection.execute(
                "SELECT r.*,o.observation_id,v.review_id "
                "FROM source_lab_records r "
                "JOIN source_lab_record_observations o "
                "ON o.source_record_id=r.source_record_id "
                "JOIN source_lab_reviews v ON v.source_record_id=r.source_record_id "
                "WHERE r.source_id=? ORDER BY r.source_record_id",
                (site_fixture.SOURCE_ID,),
            ).fetchall()
            selected = next(
                row
                for row in rows
                if json.loads(str(row["payload_json"]))["record"]["submission_id"]
                == "valid-001"
            )
            record = json.loads(str(selected["payload_json"]))["record"]
        finally:
            connection.close()

        queue = SourceReviewQueue(
            store,
            clock=lambda: datetime.now(timezone.utc).replace(microsecond=0),
        )
        item = next(
            candidate
            for candidate in queue.list_open(limit=100).items
            if candidate.review_id == str(selected["review_id"])
        )
        claim = queue.claim(
            review_id=item.review_id,
            claimant=item.task_assigned_to,
            evidence_ref="evidence://first-queue/site/claim/valid-001",
            idempotency_key="first-queue-site-claim-valid-001",
            expected_state_digest=item.state_digest,
        )
        resolution = queue.resolve_claimed(
            claim,
            decision="APPROVE",
            reason="first queue offline commercial fixture",
            evidence_ref="evidence://first-queue/site/resolution/valid-001",
            idempotency_key="first-queue-site-resolution-valid-001",
        )
        trusted_policy = site_fixture.trusted_policy()
        policy = SiteCommercialPolicy(
            policy_id="first-queue-site-commercial",
            policy_version="1",
            source_id=site_fixture.SOURCE_ID,
            identity_policy_version="inn-email-v1",
            trusted_site_policy=trusted_policy,
            bitrix_graph_binding=graph_binding(site_fixture.SOURCE_ID),
        )
        command = ApprovedSiteCommand(
            source_record_id=str(selected["source_record_id"]),
            observation_id=str(selected["observation_id"]),
            review_id=str(selected["review_id"]),
            latest_resolution_id=resolution.resolution_id,
            expected_payload_hash=str(selected["payload_hash"]),
            projection=SiteOpportunityProjection(
                company_inn=_SITE_COMPANY_INN,
                contact_email=str(record["contact"]["email"]),
                identity_evidence_ref=(
                    "evidence://first-queue/site/identity/valid-001"
                ),
            ),
            actor="first-queue-site-commercial",
            idempotency_key="first-queue-site-commercial-valid-001",
        )
        authority = _RecordingSiteAuthority()
        result = SiteCommercialBridge(
            store,
            policy=policy,
            approval_authority=authority,
        ).execute(command)
        if result.state != "STAGED" or len(authority.receipts) != 1:
            raise AssertionError("Site phase-2 graph was not staged exactly once")
        return {
            "policy": policy,
            "command": command,
            "resolution": resolution,
            "approval_receipt": authority.receipts[0],
            "result": result,
        }

    @classmethod
    def _send_site_graph_with_attestations(
        cls,
        store: FactoryStore,
        site: dict[str, object],
    ) -> tuple[FirstQueueOfflineOperationAttestation, ...]:
        del site
        with store.transaction() as connection:
            changed = connection.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_writers_enabled' AND value='0'"
            )
            if changed.rowcount != 1:
                raise AssertionError("fixture writer gate could not be isolated")
        transport = FixtureGraphTransport()
        outbox = CrmGraphOutbox(store)
        attestations: list[FirstQueueOfflineOperationAttestation] = []
        try:
            for _ in range(4):
                before_calls = len(transport.create_calls)
                result = outbox.process_next(
                    transport,
                    worker_id="first-queue-offline-worker",
                )
                if (
                    result is None
                    or result.state != "SENT"
                    or len(transport.create_calls) != before_calls + 1
                ):
                    raise AssertionError("fixture graph operation was not sent exactly once")
                request = transport.create_calls[-1]
                connection = store.connect()
                try:
                    operation = connection.execute(
                        "SELECT * FROM crm_outbox WHERE operation_id=?",
                        (request.operation_id,),
                    ).fetchone()
                    if operation is None:
                        raise AssertionError("fixture graph operation is missing")
                    dependencies = outbox._validate_operation_tx(
                        connection,
                        operation,
                        require_sent=True,
                    )
                    request_hash, readback_hash = offline_operation_proof_hashes(
                        dict(operation),
                        dependencies,
                    )
                    sent_rows = connection.execute(
                        "SELECT * FROM events "
                        "WHERE producer='crm_graph_outbox' "
                        "AND event_type='crm_graph_operation_sent' "
                        "ORDER BY rowid"
                    ).fetchall()
                    sent = next(
                        row
                        for row in sent_rows
                        if json.loads(str(row["payload_json"]))["operation_id"]
                        == request.operation_id
                    )
                finally:
                    connection.close()
                evidence_ref = (
                    f"evidence://first-queue/offline-crm/{request.operation_id}"
                )
                body = _attestation_body(
                    execution_id=_FIXTURE_EXECUTION_ID,
                    operation_id=request.operation_id,
                    operation_type=request.operation_type,
                    request_hash=request_hash,
                    readback_hash=readback_hash,
                    remote_entity_type=str(operation["remote_entity_type"]),
                    remote_entity_id=str(operation["remote_entity_id"]),
                    sent_event_id=str(sent["event_id"]),
                    sent_event_payload_hash=str(sent["payload_hash"]),
                    occurred_at_utc=str(sent["occurred_at_utc"]),
                    evidence_ref=evidence_ref,
                )
                event_id = new_lf_id("event")
                declared_hash = payload_hash(body)
                draft = FirstQueueOfflineOperationAttestation(
                    **body,
                    declared_attestation_hash=declared_hash,
                    event_id=event_id,
                    event_payload_hash="0" * 64,
                )
                event_payload = offline_operation_attestation_payload(draft)
                event_payload_hash = payload_hash(event_payload)
                attestation = replace(
                    draft,
                    event_payload_hash=event_payload_hash,
                )
                event, created = store.append_event(
                    event_type="offline_crm_graph_operation_attested",
                    aggregate_type="crm_operation",
                    aggregate_id=request.operation_id,
                    producer="first_queue_offline_crm_fixture",
                    idempotency_key=(
                        "offline-crm-fixture:"
                        f"{attestation.execution_id}:{request.operation_id}"
                    ),
                    payload=offline_operation_attestation_payload(attestation),
                    evidence_ref=evidence_ref,
                    actor=_ATTESTATION_ACTOR,
                    correlation_id=attestation.execution_id,
                    causation_id=str(sent["event_id"]),
                    occurred_at_utc=str(sent["occurred_at_utc"]),
                    schema_version=CURRENT_SCHEMA_VERSION,
                    event_id=event_id,
                )
                if (
                    not created
                    or str(event["payload_hash"]) != event_payload_hash
                    or str(event["event_id"]) != event_id
                ):
                    raise AssertionError("offline graph attestation was not exact")
                attestations.append(attestation)
        finally:
            with store.transaction() as connection:
                connection.execute(
                    "UPDATE schema_meta SET value='0' "
                    "WHERE key='external_writers_enabled'"
                )
        return tuple(attestations)

    @classmethod
    def _record_site_outcome(
        cls,
        store: FactoryStore,
        site: dict[str, object],
    ) -> dict[str, object]:
        payload = {"stage": "screened", "transport": "offline-fixture"}
        evidence_ref = "evidence://first-queue/offline-crm/screened"
        received_at_utc = "2026-08-21T10:30:00Z"
        actor = "first-queue-offline-crm-sync"
        dedupe_key = "first-queue-offline-screened-v1"
        intake = OfflineCrmOutcomeIntake(store)
        result = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id=_SITE_REMOTE_DEAL_ID,
            remote_version=1,
            event_type="SCREENED",
            payload=payload,
            evidence_ref=evidence_ref,
            received_at_utc=received_at_utc,
            actor=actor,
            dedupe_key=dedupe_key,
        )
        replay = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id=_SITE_REMOTE_DEAL_ID,
            remote_version=1,
            event_type="SCREENED",
            payload=payload,
            evidence_ref=evidence_ref,
            received_at_utc=received_at_utc,
            actor=actor,
            dedupe_key=dedupe_key,
        )
        if (
            result.state != "PROCESSED"
            or result.lf_opportunity_id != site["result"].lf_opportunity_id
            or replay.created
        ):
            raise AssertionError("offline SCREENED outcome was not exact")
        raw_hash = payload_hash(payload)
        envelope_hash = payload_hash(
            {
                "event_type": "SCREENED",
                "payload_hash": raw_hash,
                "reason": "",
            }
        )
        return {
            "result": result,
            "dedupe_key": dedupe_key,
            "raw_payload_hash": raw_hash,
            "envelope_hash": envelope_hash,
            "evidence_ref": evidence_ref,
            "received_at_utc": received_at_utc,
            "actor": actor,
        }

    @classmethod
    def _stage_cross_source_graph(cls, store: FactoryStore):
        builder = cross_fixture.CrossSourceReconciliationAcceptanceTests()
        builder.root = cls.template_root
        builder.store = store
        builder.sink = SourceLabSink(store, clock=lambda: cross_fixture.NOW)
        builder.queue = SourceReviewQueue(
            store,
            clock=lambda: datetime.now(timezone.utc).replace(microsecond=0),
        )
        builder.passports = SourcePassportRegistry(store, clock=lambda: cross_fixture.NOW)
        builder.vault = RadarEvidenceVault(store, clock=lambda: cross_fixture.NOW)
        builder.access = SourceAccessPermitLedger(store, clock=lambda: cross_fixture.NOW)
        builder.evidence = SourceEvidenceBoundary(store, clock=lambda: cross_fixture.NOW)
        builder.authority = cross_fixture._ExactApprovalAuthority()
        builder.sequence = 0
        builder.passport_cache = {}
        builder.approval = builder._put_evidence(
            b'{"approved":true}',
            data_class="RADAR_SOURCE_ACCESS_APPROVAL",
            suffix="shared-approval",
        )
        builder.budget = builder._put_evidence(
            b'{"budget":true}',
            data_class="RADAR_SOURCE_ACCESS_BUDGET",
            suffix="shared-budget",
        )
        builder.project_hash = canonical_identity_fingerprints(
            ((cross_fixture.PROJECT_NAMESPACE, cross_fixture.PROJECT_REF),)
        )[0][1]
        builder._passport = MethodType(_phase_two_passport, builder)

        original_snapshot = cross_fixture.SourceAuthorizationSnapshot

        def phase_two_snapshot(*args, **kwargs):
            kwargs["passport_version"] = "2"
            kwargs["passport_evidence_ref"] = str(
                kwargs["passport_evidence_ref"]
            ).replace("/capability", "/capability-v2")
            return original_snapshot(*args, **kwargs)

        with patch.object(
            cross_fixture,
            "SourceAuthorizationSnapshot",
            side_effect=phase_two_snapshot,
        ):
            items = [
                builder._import_review(source_id, project_ref=cross_fixture.PROJECT_REF)
                for source_id in cross_fixture.SOURCE_IDS
            ]
        for item in items:
            builder._bridge(item)
        expectation = builder._expectation(items)
        report = cross_fixture.reconcile_cross_source_object(store, expectation)
        return expectation, report

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db_path = self.root / "first-queue-phase2.sqlite3"
        shutil.copy2(self.template_path, self.db_path)

    def _inspect_without_network(self, path: Path | None = None, manifest=None):
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in phase-2 inspection"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in phase-2 inspection"),
            ),
        ):
            return inspect_first_queue_reconciliation_snapshot(
                path or self.db_path,
                manifest or self.manifest,
            )

    def _resealed_manifest_for(self, path: Path):
        candidate = replace(
            self.manifest,
            final_fingerprint=capture_first_queue_database_fingerprint(path),
            declared_manifest_hash="",
        )
        return replace(
            candidate,
            declared_manifest_hash=first_queue_reconciliation_manifest_hash(candidate),
        )

    def _rewrite_event(
        self,
        path: Path,
        *,
        event_id: str,
        updates: dict[str, object],
    ) -> None:
        self.assertTrue(updates)
        self.assertLessEqual(
            set(updates),
            {"actor", "event_type", "producer"},
        )
        connection = sqlite3.connect(path)
        try:
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_events_no_update'"
            ).fetchone()
            self.assertIsNotNone(trigger)
            trigger_sql = str(trigger[0])
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP TRIGGER trg_lf_events_no_update")
            columns = tuple(sorted(updates))
            assignments = ",".join(f'"{column}"=?' for column in columns)
            changed = connection.execute(
                f"UPDATE events SET {assignments} WHERE event_id=?",
                (*[updates[column] for column in columns], event_id),
            )
            self.assertEqual(changed.rowcount, 1)
            connection.execute(trigger_sql)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        verify = sqlite3.connect(path)
        try:
            restored = verify.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_events_no_update'"
            ).fetchone()
            self.assertIsNotNone(restored)
            self.assertEqual(str(restored[0]), trigger_sql)
        finally:
            verify.close()

    def _rewrite_normalized_event_source_payload_hash(
        self,
        path: Path,
        *,
        source_record_id: str,
    ) -> None:
        connection = sqlite3.connect(path)
        try:
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_events_no_update'"
            ).fetchone()
            self.assertIsNotNone(trigger)
            trigger_sql = str(trigger[0])
            row = connection.execute(
                "SELECT event_id,payload_json FROM events WHERE "
                "producer='commercial_spine' AND event_type="
                "'normalized_opportunity_created' AND idempotency_key=?",
                (f"normalized:{source_record_id}",),
            ).fetchone()
            self.assertIsNotNone(row)
            payload = json.loads(str(row[1]))
            payload["source_payload_hash"] = "0" * 64
            rendered = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DROP TRIGGER trg_lf_events_no_update")
            changed = connection.execute(
                "UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                (rendered, payload_hash(payload), str(row[0])),
            )
            self.assertEqual(changed.rowcount, 1)
            connection.execute(trigger_sql)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _verify_recovery_without_network(
        self,
        source_path: Path,
        backup_path: Path,
        restored_path: Path,
        restore_report: dict[str, object],
    ):
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in recovery proof"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in recovery proof"),
            ),
        ):
            return verify_first_queue_reconciliation_recovery(
                source_path,
                backup_path,
                restored_path,
                self.manifest,
                restore_report,
            )

    def test_composed_report_is_exact_deterministic_and_physically_read_only(self) -> None:
        before = _physical_snapshot(self.db_path)
        first = self._inspect_without_network()
        second = self._inspect_without_network()

        self.assertEqual(first, second)
        self.assertEqual(_physical_snapshot(self.db_path), before)
        self.assertEqual(first.status, "PASSED")
        self.assertTrue(first.criterion_42_3_6_passed)
        self.assertFalse(first.fast_commercial_slice_ready)
        self.assertTrue(first.baseline_event_prefix_verified)
        self.assertEqual(first.final_fingerprint.event_count, 167)
        self.assertEqual(first.queue.selected_review_count, 20)
        self.assertEqual(first.queue.selected_resolution_count, 1)
        self.assertEqual(first.queue.selected_open_review_count, 19)
        self.assertEqual(first.historical_offline_fixture_operations, 4)
        self.assertEqual(len(first.site_commercial.crm_operation_ids), 4)
        self.assertEqual(
            dict(first.site_commercial.crm_remote_bindings),
            {"activity": "401", "company": "101", "contact": "201", "deal": "301"},
        )
        self.assertEqual(first.outcome.state, "PROCESSED")
        self.assertEqual(first.outcome.opportunity_state, OpportunityState.SCREENED.value)
        self.assertEqual(first.cross_source.status, "PASSED")
        self.assertFalse(first.external_writers_enabled)
        self.assertFalse(first.external_source_reads_enabled)
        self.assertFalse(first.manual_import_commits_enabled)
        self.assertEqual(first.inspection_live_calls, 0)
        self.assertEqual(first.inspection_external_writes, 0)

    def test_backup_and_restored_copy_have_one_semantic_report(self) -> None:
        backup = create_backup(
            FactoryStore(self.db_path),
            destination_dir=self.root / "backups",
            evidence_root=self.root / "evidence",
        )
        restored_path = self.root / "restored-first-queue-phase2.sqlite3"
        restore_report = verify_restore(
            backup["backup"],
            restore_path=restored_path,
        )
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in recovery proof"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in recovery proof"),
            ),
        ):
            report = verify_first_queue_reconciliation_recovery(
                self.db_path,
                Path(str(backup["backup"])),
                restored_path,
                self.manifest,
                restore_report,
            )

        self.assertEqual(report.status, "PASSED")
        self.assertTrue(report.criterion_42_3_6_passed)
        self.assertFalse(report.fast_commercial_slice_ready)
        self.assertTrue(report.source_read_epoch_rotated)
        self.assertTrue(report.manual_import_epoch_rotated)
        self.assertFalse(report.external_writers_enabled)
        self.assertFalse(report.external_source_reads_enabled)
        self.assertFalse(report.manual_import_commits_enabled)
        self.assertRegex(report.semantic_hash, r"^[0-9a-f]{64}$")

    def test_plain_backup_copy_with_forged_restore_report_fails_closed(self) -> None:
        backup = create_backup(
            FactoryStore(self.db_path),
            destination_dir=self.root / "forged-backups",
            evidence_root=self.root / "forged-evidence",
        )
        backup_path = Path(str(backup["backup"]))
        restored_path = self.root / "plain-backup-copy.sqlite3"
        shutil.copy2(backup_path, restored_path)
        forged_restore_report = {
            "backup": str(backup_path),
            "restored": str(restored_path),
            "schema_version": CURRENT_SCHEMA_VERSION,
            "external_writers_enabled": "0",
            "external_source_reads_enabled": "0",
            "manual_import_commits_enabled": "0",
            "source_read_epoch_rotated": True,
            "manual_import_epoch_rotated": True,
            "source_read_epoch_hash": "1" * 64,
            "manual_import_epoch_hash": "2" * 64,
        }
        before = {
            "source": _physical_snapshot(self.db_path),
            "backup": _physical_snapshot(backup_path),
            "restored": _physical_snapshot(restored_path),
        }

        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in recovery proof"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in recovery proof"),
            ),
            self.assertRaises(FirstQueueReconciliationConflict),
        ):
            verify_first_queue_reconciliation_recovery(
                self.db_path,
                backup_path,
                restored_path,
                self.manifest,
                forged_restore_report,
            )

        self.assertEqual(_physical_snapshot(self.db_path), before["source"])
        self.assertEqual(_physical_snapshot(backup_path), before["backup"])
        self.assertEqual(_physical_snapshot(restored_path), before["restored"])

    def test_unexpected_rows_cannot_be_hidden_by_fingerprint_reseal(self) -> None:
        attacks = (
            (
                "source-record",
                "INSERT INTO source_records("
                "source_record_id,producer,external_key,idempotency_key,"
                "payload_hash,evidence_ref,observed_at_utc,created_at_utc"
                ") VALUES(?,?,?,?,?,?,?,?)",
                (
                    "lf_source_record_forged_phase2_extra",
                    "forged_phase2",
                    "forged-extra",
                    "forged-phase2-source-record",
                    "3" * 64,
                    "evidence://first-queue/forged/source-record",
                    "2026-08-21T13:00:00Z",
                    "2026-08-21T13:00:00Z",
                ),
            ),
            (
                "pause",
                "INSERT INTO pauses("
                "pause_id,scope,scope_id,reason,author,evidence_ref,"
                "review_at_utc,expires_at_utc,state,created_at_utc,released_at_utc"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "lf_pause_forged_phase2_extra",
                    "GLOBAL",
                    "",
                    "forged phase2 pause",
                    "forged-phase2",
                    "evidence://first-queue/forged/pause",
                    "",
                    "",
                    "ACTIVE",
                    "2026-08-21T13:00:00Z",
                    "",
                ),
            ),
        )
        for suffix, statement, parameters in attacks:
            with self.subTest(table=suffix):
                path = self.root / f"unexpected-{suffix}.sqlite3"
                shutil.copy2(self.template_path, path)
                connection = sqlite3.connect(path)
                try:
                    connection.execute(statement, parameters)
                    connection.commit()
                finally:
                    connection.close()
                candidate = replace(
                    self.manifest,
                    final_fingerprint=capture_first_queue_database_fingerprint(path),
                    declared_manifest_hash="",
                )
                before = _physical_snapshot(path)
                with self.assertRaises(FirstQueueReconciliationManifestError):
                    first_queue_reconciliation_manifest_hash(candidate)
                self.assertEqual(_physical_snapshot(path), before)

    def test_phase2_suffix_event_rewrite_survives_reseal_but_is_rejected(self) -> None:
        path = self.root / "rewritten-phase2-suffix.sqlite3"
        shutil.copy2(self.template_path, path)
        connection = sqlite3.connect(path)
        try:
            row = connection.execute(
                "SELECT event_id FROM events WHERE rowid=?",
                (self.manifest.baseline_event_head_rowid + 1,),
            ).fetchone()
            self.assertIsNotNone(row)
            event_id = str(row[0])
        finally:
            connection.close()
        self._rewrite_event(
            path,
            event_id=event_id,
            updates={
                "producer": "forged_phase2",
                "event_type": "forged_phase2_suffix",
            },
        )
        resealed = self._resealed_manifest_for(path)
        before = _physical_snapshot(path)
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._inspect_without_network(path, resealed)
        self.assertEqual(_physical_snapshot(path), before)

    def test_outcome_event_metadata_rewrite_survives_reseal_but_is_rejected(self) -> None:
        path = self.root / "rewritten-outcome-event.sqlite3"
        shutil.copy2(self.template_path, path)
        connection = sqlite3.connect(path)
        try:
            row = connection.execute(
                "SELECT event_id FROM events WHERE producer='commercial_spine' "
                "AND idempotency_key=?",
                (f"crm-outcome:{self.manifest.outcome.inbox_event_id}",),
            ).fetchone()
            self.assertIsNotNone(row)
            event_id = str(row[0])
        finally:
            connection.close()
        self._rewrite_event(
            path,
            event_id=event_id,
            updates={"actor": "forged-outcome-actor"},
        )
        resealed = self._resealed_manifest_for(path)
        before = _physical_snapshot(path)
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._inspect_without_network(path, resealed)
        self.assertEqual(_physical_snapshot(path), before)

    def test_site_company_lineage_rewrite_survives_reseal_but_is_rejected(self) -> None:
        attacks = {
            "domain": "forged.example",
            "source_event_id": "lf_source_record_forged_phase2",
            "created_at_utc": "2026-08-01T00:00:00Z",
        }
        for column, value in attacks.items():
            with self.subTest(column=column):
                path = self.root / f"rewritten-site-company-{column}.sqlite3"
                shutil.copy2(self.template_path, path)
                connection = sqlite3.connect(path)
                try:
                    changed = connection.execute(
                        f'UPDATE companies SET "{column}"=? WHERE lf_company_id=?',
                        (value, self.manifest.site_commercial.lf_company_id),
                    )
                    self.assertEqual(changed.rowcount, 1)
                    connection.commit()
                finally:
                    connection.close()
                resealed = self._resealed_manifest_for(path)
                before = _physical_snapshot(path)
                with self.assertRaises(FirstQueueReconciliationConflict):
                    self._inspect_without_network(path, resealed)
                self.assertEqual(_physical_snapshot(path), before)

    def test_cross_creator_graph_lineage_rewrite_survives_reseal_but_is_rejected(
        self,
    ) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            row = connection.execute(
                "SELECT o.lf_company_id,o.lf_contact_id,o.lf_project_id,"
                "o.lf_opportunity_id,o.source_event_id FROM opportunities o "
                "WHERE o.lf_opportunity_id<>?",
                (self.manifest.site_commercial.lf_opportunity_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            company_id, contact_id, project_id, opportunity_id, source_id = map(
                str, row
            )
        finally:
            connection.close()
        attacks = (
            ("companies", "lf_company_id", company_id, "source_event_id", "forged"),
            ("companies", "lf_company_id", company_id, "created_at_utc", "time"),
            ("contacts", "lf_contact_id", contact_id, "source_event_id", "forged"),
            ("contacts", "lf_contact_id", contact_id, "created_at_utc", "time"),
            ("projects", "lf_project_id", project_id, "source_event_id", "forged"),
            ("projects", "lf_project_id", project_id, "created_at_utc", "time"),
            ("opportunities", "lf_opportunity_id", opportunity_id, "created_at_utc", "time"),
        )
        for table, id_column, entity_id, column, kind in attacks:
            with self.subTest(table=table, column=column):
                path = self.root / f"rewritten-cross-{table}-{column}.sqlite3"
                shutil.copy2(self.template_path, path)
                value = (
                    "lf_source_record_forged_phase2"
                    if kind == "forged"
                    else "2026-08-01T00:00:00Z"
                )
                connection = sqlite3.connect(path)
                try:
                    changed = connection.execute(
                        f'UPDATE "{table}" SET "{column}"=? '
                        f'WHERE "{id_column}"=?',
                        (value, entity_id),
                    )
                    self.assertEqual(changed.rowcount, 1)
                    connection.commit()
                finally:
                    connection.close()
                resealed = self._resealed_manifest_for(path)
                before = _physical_snapshot(path)
                with self.assertRaises(FirstQueueReconciliationConflict):
                    self._inspect_without_network(path, resealed)
                self.assertEqual(_physical_snapshot(path), before)

    def test_normalized_event_source_payload_hash_is_exact_after_reseal(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            source_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT source_event_id FROM opportunities ORDER BY lf_opportunity_id"
                ).fetchall()
            )
        finally:
            connection.close()
        self.assertEqual(len(source_ids), 2)
        for source_id in source_ids:
            with self.subTest(source_record_id=source_id):
                path = self.root / f"rewritten-normalized-{source_id}.sqlite3"
                shutil.copy2(self.template_path, path)
                self._rewrite_normalized_event_source_payload_hash(
                    path,
                    source_record_id=source_id,
                )
                resealed = self._resealed_manifest_for(path)
                before = _physical_snapshot(path)
                with self.assertRaises(FirstQueueReconciliationConflict):
                    self._inspect_without_network(path, resealed)
                self.assertEqual(_physical_snapshot(path), before)

    def test_truncated_restore_report_or_backup_manifest_is_rejected(self) -> None:
        backup = create_backup(
            FactoryStore(self.db_path),
            destination_dir=self.root / "truncated-backups",
            evidence_root=self.root / "truncated-evidence",
        )
        backup_path = Path(str(backup["backup"]))
        restored_path = self.root / "truncated-restored.sqlite3"
        genuine_report = verify_restore(
            backup_path,
            restore_path=restored_path,
        )
        truncated_report = dict(genuine_report)
        truncated_report.pop("duration_ms")
        database_before = {
            path: _physical_snapshot(path)
            for path in (self.db_path, backup_path, restored_path)
        }
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._verify_recovery_without_network(
                self.db_path,
                backup_path,
                restored_path,
                truncated_report,
            )
        for path, snapshot in database_before.items():
            self.assertEqual(_physical_snapshot(path), snapshot)

        manifest_path = Path(f"{backup_path}.manifest.json")
        backup_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        backup_manifest.pop("counts")
        manifest_path.write_text(
            json.dumps(
                backup_manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        database_before = {
            path: _physical_snapshot(path)
            for path in (self.db_path, backup_path, restored_path)
        }
        manifest_before = _physical_snapshot(manifest_path)
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._verify_recovery_without_network(
                self.db_path,
                backup_path,
                restored_path,
                dict(genuine_report),
            )
        for path, snapshot in database_before.items():
            self.assertEqual(_physical_snapshot(path), snapshot)
        self.assertEqual(_physical_snapshot(manifest_path), manifest_before)

    def test_recovery_requires_exact_fixture_ledgers_and_zero_evidence(self) -> None:
        backup = create_backup(
            FactoryStore(self.db_path),
            destination_dir=self.root / "exact-recovery-backups",
            evidence_root=self.root / "exact-recovery-evidence",
        )
        backup_path = Path(str(backup["backup"]))
        restored_path = self.root / "exact-recovery-restored.sqlite3"
        genuine_report = verify_restore(backup_path, restore_path=restored_path)
        manifest_path = Path(f"{backup_path}.manifest.json")
        original_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        cases: list[tuple[str, dict[str, object], dict[str, object]]] = []

        changed_counts = dict(original_manifest)
        changed_counts["counts"] = {
            **dict(original_manifest["counts"]),
            "events": 166,
        }
        cases.append(("counts", changed_counts, dict(genuine_report)))

        changed_evidence = dict(original_manifest)
        changed_evidence["evidence"] = {
            "file_count": 1,
            "metadata_count": 0,
            "raw_mime_count": 0,
            "referenced_count": 0,
            "uncompressed_bytes": 0,
        }
        cases.append(("evidence", changed_evidence, dict(genuine_report)))

        changed_pragma = dict(original_manifest)
        changed_pragma["pragma_user_version"] = 16
        cases.append(("pragma", changed_pragma, dict(genuine_report)))

        changed_report = dict(genuine_report)
        changed_report["source_lab_ledger"] = {
            **dict(genuine_report["source_lab_ledger"]),
            "ledger_sha256": "0" * 64,
        }
        cases.append(("source-lab-ledger", dict(original_manifest), changed_report))

        for name, changed_manifest, changed_restore_report in cases:
            with self.subTest(case=name):
                manifest_path.write_text(
                    json.dumps(
                        changed_manifest,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
                database_before = {
                    path: _physical_snapshot(path)
                    for path in (self.db_path, backup_path, restored_path)
                }
                manifest_before = _physical_snapshot(manifest_path)
                with self.assertRaises(FirstQueueReconciliationConflict):
                    self._verify_recovery_without_network(
                        self.db_path,
                        backup_path,
                        restored_path,
                        changed_restore_report,
                    )
                for path, snapshot in database_before.items():
                    self.assertEqual(_physical_snapshot(path), snapshot)
                self.assertEqual(_physical_snapshot(manifest_path), manifest_before)

    def test_source_swap_after_first_inspection_is_rejected(self) -> None:
        backup = create_backup(
            FactoryStore(self.db_path),
            destination_dir=self.root / "swap-backups",
            evidence_root=self.root / "swap-evidence",
        )
        backup_path = Path(str(backup["backup"]))
        restored_path = self.root / "swap-restored.sqlite3"
        restore_report = verify_restore(
            backup_path,
            restore_path=restored_path,
        )
        original_inspector = inspect_first_queue_reconciliation_snapshot
        calls = 0

        def inspect_then_swap(path, manifest):
            nonlocal calls
            report = original_inspector(path, manifest)
            calls += 1
            if calls == 1:
                shutil.copy2(restored_path, self.db_path)
            return report

        source_before = _physical_snapshot(self.db_path)
        stable_before = {
            backup_path: _physical_snapshot(backup_path),
            restored_path: _physical_snapshot(restored_path),
        }
        with (
            patch(
                "lead_factory.first_queue_reconciliation."
                "inspect_first_queue_reconciliation_snapshot",
                side_effect=inspect_then_swap,
            ),
            self.assertRaises(FirstQueueReconciliationConflict),
        ):
            self._verify_recovery_without_network(
                self.db_path,
                backup_path,
                restored_path,
                dict(restore_report),
            )
        self.assertGreaterEqual(calls, 1)
        self.assertNotEqual(_physical_snapshot(self.db_path), source_before)
        for path, snapshot in stable_before.items():
            self.assertEqual(_physical_snapshot(path), snapshot)

    def test_manifest_outcome_or_attestation_tamper_fails_closed(self) -> None:
        changed_outcome = replace(
            self.manifest.outcome,
            remote_entity_id="302",
        )
        candidate = replace(
            self.manifest,
            outcome=changed_outcome,
            declared_manifest_hash="",
        )
        changed_manifest = replace(
            candidate,
            declared_manifest_hash=first_queue_reconciliation_manifest_hash(candidate),
        )
        before = _physical_snapshot(self.db_path)
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._inspect_without_network(manifest=changed_manifest)
        self.assertEqual(_physical_snapshot(self.db_path), before)

        first_attestation = self.manifest.site_commercial.attestations[0]
        invalid = replace(first_attestation, live_provider_called=True)
        changed_site = replace(
            self.manifest.site_commercial,
            attestations=(
                invalid,
                *self.manifest.site_commercial.attestations[1:],
            ),
        )
        invalid_manifest = replace(
            self.manifest,
            site_commercial=changed_site,
            declared_manifest_hash="",
        )
        with self.assertRaises(FirstQueueReconciliationManifestError):
            first_queue_reconciliation_manifest_hash(invalid_manifest)

    def test_database_outcome_or_missing_attestation_fails_without_inspector_writes(self) -> None:
        tampered = self.root / "tampered-outcome.sqlite3"
        shutil.copy2(self.template_path, tampered)
        with FactoryStore(tampered).transaction() as connection:
            connection.execute(
                "UPDATE crm_inbox_events SET payload_hash=?",
                ("0" * 64,),
            )
        before = _physical_snapshot(tampered)
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._inspect_without_network(tampered)
        self.assertEqual(_physical_snapshot(tampered), before)

        missing = self.root / "missing-attestation.sqlite3"
        shutil.copy2(self.template_path, missing)
        connection = sqlite3.connect(missing)
        try:
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_events_no_delete'"
            ).fetchone()
            self.assertIsNotNone(trigger)
            connection.execute("DROP TRIGGER trg_lf_events_no_delete")
            deleted = connection.execute(
                "DELETE FROM events WHERE event_id=?",
                (self.manifest.site_commercial.attestations[0].event_id,),
            )
            self.assertEqual(deleted.rowcount, 1)
            connection.execute(str(trigger[0]))
            connection.commit()
        finally:
            connection.close()
        before = _physical_snapshot(missing)
        with self.assertRaises(FirstQueueReconciliationConflict):
            self._inspect_without_network(missing)
        self.assertEqual(_physical_snapshot(missing), before)


if __name__ == "__main__":
    unittest.main()
