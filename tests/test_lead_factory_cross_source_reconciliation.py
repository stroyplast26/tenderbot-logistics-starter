from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from lead_factory.construction_radar import (
    CapabilityState,
    LicenceState,
    PassportState,
    RadarContour,
    SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    CrmGraphOutbox,
    DEAL_CREATE,
)
from lead_factory.cross_source_reconciliation import (
    CrossSourceApprovalBinding,
    CrossSourceExpectation,
    CrossSourceExpectationError,
    CrossSourceReconciliationError,
    reconcile_cross_source_object,
)
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.radar_review_access import (
    RadarEvidenceCommand,
    RadarEvidenceVault,
    SourceAccessMode,
    SourceAccessPermit,
    SourceAccessPermitLedger,
    SourceEvidenceBoundary,
    SourceEvidenceCommand,
)
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.source_commercial_bridge import (
    ApprovedSourceCommand,
    SourceCommercialBridge,
    SourceCommercialPolicy,
    TRUSTED_APPROVAL_CAPABILITY_VERSION,
    TRUSTED_APPROVAL_RECEIPT_VERSION,
    TrustedApprovalReceipt,
    TrustedApprovalRequest,
)
from lead_factory.source_import import (
    FieldMapping,
    IdentityMapping,
    SourceAuthorizationSnapshot,
    SourceBatchImporter,
    SourceImportFormat,
    SourceImportPolicy,
)
from lead_factory.source_lab import (
    SourceLabSink,
    canonical_identity_fingerprints,
)
from lead_factory.source_lab_integrity import validate_source_lab_integrity
from lead_factory.source_review_queue import (
    SourceReviewQueue,
    validate_source_review_queue_integrity,
)
from lead_factory.store import FactoryStore
from tests.test_lead_factory_source_commercial_bridge import graph_binding


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
SOURCE_IDS = (
    "wave1:domrf_public_projects",
    "wave1:saby_trade",
    "wave1:tenderplan",
)
PROJECT_NAMESPACE = "project-ref"
PROJECT_REF = "aluminium-facade-project-42"
COMPANY_INN = "7707083893"
CONTACT_EMAIL = "procurement@example.test"
HEADERS = (
    "id",
    "company_name",
    "inn",
    "domain",
    "contact_name",
    "email",
    "phone",
    "role",
    "project_title",
    "region",
    "product_key",
    "project_code",
)
GRAPH_OPERATION_TYPES = frozenset(
    {COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE}
)


def _csv_bytes(values: dict[str, str]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=HEADERS, lineterminator="\n")
    writer.writeheader()
    writer.writerow({header: values.get(header, "") for header in HEADERS})
    return stream.getvalue().encode("utf-8")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _ExactApprovalAuthority:
    capability_version = TRUSTED_APPROVAL_CAPABILITY_VERSION

    def __init__(self) -> None:
        self.calls: list[TrustedApprovalRequest] = []
        self.receipts: dict[tuple[str, str], TrustedApprovalReceipt] = {}
        self.receipts_by_source: dict[str, TrustedApprovalReceipt] = {}

    def verify_approval(
        self, request: TrustedApprovalRequest
    ) -> TrustedApprovalReceipt:
        self.calls.append(request)
        key = (request.source_id, request.request_hash)
        receipt = self.receipts.get(key)
        if receipt is None:
            receipt = TrustedApprovalReceipt(
                capability_version=TRUSTED_APPROVAL_CAPABILITY_VERSION,
                receipt_version=TRUSTED_APPROVAL_RECEIPT_VERSION,
                authority_id="offline-cross-source-approval-authority",
                receipt_id=f"cross-source-receipt-{request.request_hash[:40]}",
                request=request,
                request_hash=request.request_hash,
            )
            self.receipts[key] = receipt
        self.receipts_by_source[request.source_id] = receipt
        return receipt


@dataclass(frozen=True, slots=True)
class _PipelineItem:
    source_id: str
    importer: SourceBatchImporter
    import_policy: SourceImportPolicy
    data: bytes
    run_key: str
    batch_key: str
    source_record_id: str
    resolution_event_id: str
    command: ApprovedSourceCommand
    commercial_policy: SourceCommercialPolicy


class CrossSourceReconciliationAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = FactoryStore(self.root / "cross-source.sqlite3")
        self.store.init()
        self.sink = SourceLabSink(self.store, clock=lambda: NOW)
        self.queue = SourceReviewQueue(
            self.store,
            clock=lambda: datetime.now(timezone.utc).replace(microsecond=0),
        )
        self.passports = SourcePassportRegistry(self.store, clock=lambda: NOW)
        self.vault = RadarEvidenceVault(self.store, clock=lambda: NOW)
        self.access = SourceAccessPermitLedger(self.store, clock=lambda: NOW)
        self.evidence = SourceEvidenceBoundary(self.store, clock=lambda: NOW)
        self.authority = _ExactApprovalAuthority()
        self.sequence = 0
        self.passport_cache: dict[str, object] = {}
        self.approval = self._put_evidence(
            b'{"approved":true}',
            data_class="RADAR_SOURCE_ACCESS_APPROVAL",
            suffix="shared-approval",
        )
        self.budget = self._put_evidence(
            b'{"budget":true}',
            data_class="RADAR_SOURCE_ACCESS_BUDGET",
            suffix="shared-budget",
        )
        self.project_hash = canonical_identity_fingerprints(
            ((PROJECT_NAMESPACE, PROJECT_REF),)
        )[0][1]

    def _put_evidence(
        self,
        blob: bytes,
        *,
        data_class: str,
        suffix: str,
        passport_id: str = "",
    ):
        return self.vault.put(
            RadarEvidenceCommand(
                blob=blob,
                media_type=(
                    "text/csv"
                    if data_class == "B2B_LEAD_CANDIDATE"
                    else "application/json"
                ),
                source_label=f"cross-source-{suffix}",
                captured_at_utc="2026-08-20T10:00:00Z",
                actor="offline-curator",
                declared_sha256=hashlib.sha256(blob).hexdigest(),
                data_class=data_class,
                classification="INTERNAL",
                passport_id=passport_id,
            ),
            idempotency_key=(
                f"cross-source-evidence:{suffix}:{hashlib.sha256(blob).hexdigest()}"
            ),
        )

    def _passport(self, source_id: str):
        cached = self.passport_cache.get(source_id)
        if cached is not None:
            return cached
        passport = self.passports.register(
            SourcePassport(
                source_key=source_id,
                passport_version=1,
                contour=RadarContour.CAPITAL_PROJECT,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=("B2B_LEAD_CANDIDATE",),
                max_age_days=30,
                state=PassportState.APPROVED,
                capability_state=CapabilityState.PASS,
                licence_state=LicenceState.ALLOWED,
                terms_ref=f"evidence://passport/{source_id}/terms",
                licence_ref=f"evidence://passport/{source_id}/licence",
                capability_evidence_ref=(
                    f"evidence://passport/{source_id}/capability"
                ),
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-09-01T00:00:00Z",
                data_contract_version="aluminium-lead-v1",
            ),
            idempotency_key=f"cross-source-passport:{source_id}:v1",
            actor="offline-test",
        )
        self.passport_cache[source_id] = passport
        return passport

    def _import_review(self, source_id: str, *, project_ref: str) -> _PipelineItem:
        self.sequence += 1
        suffix = f"source-{self.sequence}"
        values = {
            "id": f"upstream-{self.sequence}",
            "company_name": "Aluminium Buyer",
            "inn": COMPANY_INN,
            "domain": "buyer.example",
            "contact_name": "Procurement Manager",
            "email": CONTACT_EMAIL,
            "phone": "+7 999 123-45-67",
            "role": "procurement",
            "project_title": "Facade reconstruction",
            "region": "Moscow",
            "product_key": "ALUMINIUM_PROFILE",
            "project_code": project_ref,
        }
        data = _csv_bytes(values)
        digest = hashlib.sha256(data).hexdigest()
        passport = self._passport(source_id)
        blob_evidence = self._put_evidence(
            data,
            data_class="B2B_LEAD_CANDIDATE",
            suffix=f"blob-{suffix}",
            passport_id=passport.passport_id,
        )
        permit = self.access.issue(
            SourceAccessPermit(
                passport_id=passport.passport_id,
                data_class="B2B_LEAD_CANDIDATE",
                mode=SourceAccessMode.OFFLINE_FIXTURE,
                purpose_code="ALUMKOMPLEKT_SOURCE_IMPORT",
                max_records=1,
                max_bytes=len(data),
                max_cost_minor=0,
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-09-01T00:00:00Z",
                approval_evidence_id=self.approval.evidence_id,
                budget_evidence_id=self.budget.evidence_id,
                approver="offline-owner",
                max_operations=1,
            ),
            idempotency_key=f"cross-source-permit:{suffix}",
            actor="offline-access-controller",
        )
        receipt = self.evidence.capture(
            SourceEvidenceCommand(
                permit_id=permit.permit_id,
                operation_key=f"cross-source-import-{suffix}",
                record_count=1,
                byte_count=len(data),
                cost_minor=0,
                content_sha256=digest,
                evidence_id=blob_evidence.evidence_id,
                observed_at_utc="2026-08-20T10:00:00Z",
                actor="offline-normalizer",
            ),
            idempotency_key=f"cross-source-receipt:{suffix}",
        )
        authorization = SourceAuthorizationSnapshot(
            snapshot_version="source-authorization-v1",
            source_id=source_id,
            data_class="B2B_LEAD_CANDIDATE",
            acquisition_mode="OFFLINE_FIXTURE",
            passport_id=passport.passport_id,
            passport_version="1",
            passport_evidence_ref=(
                f"evidence://passport/{source_id}/capability"
            ),
            access_permit_id=permit.permit_id,
            access_policy_version="source-access-permit-v1",
            access_evidence_ref=f"radar-evidence://{self.approval.evidence_id}",
            evidence_receipt_id=receipt.receipt_id,
            source_blob_evidence_ref=f"radar-evidence://{blob_evidence.evidence_id}",
            content_sha256=digest,
            byte_count=len(data),
            record_count=1,
            captured_at_utc="2026-08-20T10:00:00Z",
            valid_from_utc="2026-08-01T00:00:00Z",
            valid_until_utc="2026-09-01T00:00:00Z",
            source_read_epoch=0,
        )
        import_policy = SourceImportPolicy(
            policy_id=f"cross-source-import-{source_id}",
            policy_version="mapping-v1",
            evidence_ref=f"evidence://mapping/{source_id}",
            source_id=source_id,
            acquisition_mode="OFFLINE_FIXTURE",
            data_class="B2B_LEAD_CANDIDATE",
            data_contract_version="aluminium-lead-v1",
            allowed_formats=(SourceImportFormat.CSV,),
            allowed_source_headers=HEADERS,
            required_source_headers=(
                "id",
                "company_name",
                "email",
                "project_title",
                "product_key",
            ),
            external_key_header="id",
            field_mappings=tuple(
                FieldMapping(header, header) for header in HEADERS
            ),
            identity_mappings=(
                IdentityMapping("project_code", PROJECT_NAMESPACE),
                IdentityMapping("inn", "inn"),
                IdentityMapping("email", "email"),
            ),
            authorization=authorization,
        )
        importer = SourceBatchImporter(
            self.sink,
            policy=import_policy,
            clock=lambda: NOW,
            current_source_read_epoch=0,
        )
        run_key = f"cross-source-run-{self.sequence}"
        batch_key = f"cross-source-batch-{self.sequence}"
        imported = importer.import_bytes(
            data,
            source_format=SourceImportFormat.CSV,
            run_key=run_key,
            batch_key=batch_key,
        )
        ingest = imported.record_results[0]
        review = self.sink.request_review(
            source_record_id=ingest.source_record_id,
            reason="cross-source commercial qualification",
            requested_by="qualification-requester",
            evidence_ref=f"evidence://review/{suffix}",
            idempotency_key=f"cross-source-review:{suffix}",
        )
        item = next(
            candidate
            for candidate in self.queue.list_open(limit=100).items
            if candidate.review_id == review.review_id
        )
        claim = self.queue.claim(
            review_id=review.review_id,
            claimant="commercial-approver",
            evidence_ref=f"evidence://review-claim/{suffix}",
            idempotency_key=f"cross-source-claim:{suffix}",
            expected_state_digest=item.state_digest,
        )
        resolution = self.queue.resolve_claimed(
            claim,
            decision="APPROVE",
            reason="exact offline fixture accepted",
            evidence_ref=f"evidence://resolution/{suffix}",
            idempotency_key=f"cross-source-resolution:{suffix}",
        )
        command = ApprovedSourceCommand(
            source_record_id=ingest.source_record_id,
            observation_id=ingest.observation_id,
            review_id=review.review_id,
            latest_resolution_id=resolution.resolution_id,
            expected_payload_hash=ingest.payload_hash,
            actor="commercial-bridge",
            idempotency_key=f"cross-source-bridge:{suffix}",
        )
        commercial_policy = SourceCommercialPolicy(
            policy_id=f"cross-source-commercial-{source_id}",
            policy_version="1",
            source_id=source_id,
            data_contract_version="aluminium-lead-v1",
            mapping_policy_hash=imported.mapping_policy_hash,
            bitrix_graph_binding=graph_binding(source_id),
            strong_project_namespaces=(PROJECT_NAMESPACE,),
        )
        return _PipelineItem(
            source_id=source_id,
            importer=importer,
            import_policy=import_policy,
            data=data,
            run_key=run_key,
            batch_key=batch_key,
            source_record_id=ingest.source_record_id,
            resolution_event_id=resolution.event_id,
            command=command,
            commercial_policy=commercial_policy,
        )

    def _bridge(self, item: _PipelineItem):
        return SourceCommercialBridge(
            self.store,
            policy=item.commercial_policy,
            approval_authority=self.authority,
        ).execute(item.command)

    def _expectation(
        self, items: list[_PipelineItem] | tuple[_PipelineItem, ...]
    ) -> CrossSourceExpectation:
        by_source = {item.source_id: item for item in items}
        return CrossSourceExpectation(
            source_ids=SOURCE_IDS,
            project_identity_namespace=PROJECT_NAMESPACE,
            project_identity_hash=self.project_hash,
            approval_bindings=tuple(
                CrossSourceApprovalBinding(
                    source_id=source_id,
                    policy=by_source[source_id].commercial_policy,
                    receipt=self.authority.receipts_by_source[source_id],
                )
                for source_id in SOURCE_IDS
            ),
        )

    def _counts(self, store: FactoryStore | None = None) -> dict[str, int]:
        target = store or self.store
        return {
            table: target.table_count(table)
            for table in (
                "source_lab_runs",
                "source_lab_batches",
                "source_lab_records",
                "source_lab_record_observations",
                "source_lab_reviews",
                "source_lab_review_resolutions",
                "source_lab_opportunity_evidence_links",
                "companies",
                "contacts",
                "projects",
                "opportunities",
                "crm_outbox",
                "crm_mappings",
            )
        }

    def _assert_switches_off(self, store: FactoryStore | None = None) -> None:
        target = store or self.store
        con = target.connect()
        try:
            meta = dict(
                con.execute(
                    "SELECT key,value FROM schema_meta WHERE key IN (?,?,?)",
                    (
                        "external_writers_enabled",
                        "external_source_reads_enabled",
                        "manual_import_commits_enabled",
                    ),
                ).fetchall()
            )
        finally:
            con.close()
        self.assertEqual(
            meta,
            {
                "external_writers_enabled": "0",
                "external_source_reads_enabled": "0",
                "manual_import_commits_enabled": "0",
            },
        )

    def _build_shared_object(self):
        items = [
            self._import_review(source_id, project_ref=PROJECT_REF)
            for source_id in SOURCE_IDS
        ]
        bridge_results = [self._bridge(item) for item in items]
        return items, bridge_results

    def _event_update_trigger_sql(self) -> str:
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT sql FROM sqlite_master
                   WHERE type='trigger' AND name='trg_lf_events_no_update'"""
            ).fetchone()
            self.assertIsNotNone(row)
            return str(row[0])
        finally:
            con.close()

    def _rewrite_event_payload(
        self,
        *,
        event_id: str,
        payload_json: str,
        stored_payload_hash: str,
        expected_trigger_sql: str,
    ) -> None:
        con = self.store.connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            current = con.execute(
                """SELECT sql FROM sqlite_master
                   WHERE type='trigger' AND name='trg_lf_events_no_update'"""
            ).fetchone()
            self.assertIsNotNone(current)
            self.assertEqual(str(current[0]), expected_trigger_sql)
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            updated = con.execute(
                """UPDATE events SET payload_json=?,payload_hash=?
                   WHERE event_id=?""",
                (payload_json, stored_payload_hash, event_id),
            )
            self.assertEqual(updated.rowcount, 1)
            con.execute(expected_trigger_sql)
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
        self.assertEqual(self._event_update_trigger_sql(), expected_trigger_sql)

    def _record_later_qualification(
        self, item: _PipelineItem, *, decision: str
    ):
        # Advance from the runtime-backed review-queue clock instead of pinning a
        # calendar instant that eventually becomes earlier than its own fixture.
        later = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
        later_text = later.isoformat().replace("+00:00", "Z")
        suffix = f"post-graph-{decision.lower()}"
        with patch("lead_factory.source_lab.utc_now", return_value=later_text):
            review = self.sink.request_review(
                source_record_id=item.source_record_id,
                reason="post-graph qualification evidence",
                requested_by="post-graph-requester",
                evidence_ref=f"evidence://review/{suffix}",
                idempotency_key=f"cross-source-review:{suffix}",
            )
            queue = SourceReviewQueue(self.store, clock=lambda: later)
            queued = next(
                candidate
                for candidate in queue.list_open(limit=100).items
                if candidate.review_id == review.review_id
            )
            claim = queue.claim(
                review_id=review.review_id,
                claimant="post-graph-approver",
                evidence_ref=f"evidence://review-claim/{suffix}",
                idempotency_key=f"cross-source-claim:{suffix}",
                expected_state_digest=queued.state_digest,
            )
            return queue.resolve_claimed(
                claim,
                decision=decision,
                reason="new evidence supersedes the commercial qualification",
                evidence_ref=f"evidence://resolution/{suffix}",
                idempotency_key=f"cross-source-resolution:{suffix}",
            )

    def test_at_src_par_01_reconciles_three_sources_into_one_exact_graph(self) -> None:
        items, bridge_results = self._build_shared_object()
        report = reconcile_cross_source_object(self.store, self._expectation(items))

        self.assertEqual(report.acceptance_id, "AT-SRC-PAR-01")
        self.assertEqual(report.status, "PASSED")
        self.assertEqual(report.schema_version, 17)
        self.assertEqual(report.source_ids, SOURCE_IDS)
        self.assertEqual(
            tuple(source_slice.source_id for source_slice in report.source_slices),
            SOURCE_IDS,
        )
        self.assertEqual(
            tuple(
                source_slice.source_record_id
                for source_slice in report.source_slices
            ),
            tuple(item.source_record_id for item in items),
        )
        self.assertEqual(
            len(
                {
                    source_slice.evidence_link_id
                    for source_slice in report.source_slices
                }
            ),
            3,
        )
        self.assertEqual(
            tuple(
                source_slice.resolution_event_id
                for source_slice in report.source_slices
            ),
            tuple(item.resolution_event_id for item in items),
        )
        self.assertEqual(
            report.company_inn_hash,
            canonical_identity_fingerprints((("inn", COMPANY_INN),))[0][1],
        )
        self.assertEqual(report.project_identity_namespace, PROJECT_NAMESPACE)
        self.assertEqual(report.project_identity_hash, self.project_hash)
        self.assertEqual(report.source_record_count, 3)
        self.assertEqual(report.company_count, 1)
        self.assertEqual(report.contact_count, 1)
        self.assertEqual(report.project_count, 1)
        self.assertEqual(report.opportunity_count, 1)
        self.assertEqual(report.evidence_link_count, 3)
        self.assertEqual(report.crm_outbox_operation_count, 4)
        self.assertEqual(report.graph_creator_count, 1)
        self.assertEqual(report.graph_reuse_count, 2)
        self.assertEqual(
            sum(source_slice.graph_created for source_slice in report.source_slices),
            1,
        )
        self.assertEqual(
            dict(report.crm_operation_counts),
            {operation_type: 1 for operation_type in GRAPH_OPERATION_TYPES},
        )
        self.assertEqual(report.crm_mapping_count, 0)
        self.assertEqual(
            {
                result.lf_company_id for result in bridge_results
            },
            {report.lf_company_id},
        )
        self.assertEqual(
            {result.lf_contact_id for result in bridge_results},
            {report.lf_contact_id},
        )
        self.assertEqual(
            {result.lf_project_id for result in bridge_results},
            {report.lf_project_id},
        )
        self.assertEqual(
            {result.lf_opportunity_id for result in bridge_results},
            {report.lf_opportunity_id},
        )
        creator_event_id = items[0].resolution_event_id
        self.assertEqual(report.creator_resolution_event_id, creator_event_id)
        self.assertFalse(report.external_writers_enabled)
        self.assertFalse(report.external_source_reads_enabled)
        self.assertFalse(report.manual_import_commits_enabled)
        self.assertEqual(report.live_calls_performed, 0)
        self.assertRegex(report.report_hash, re.compile(r"^[0-9a-f]{64}$"))

        expected_counts = {
            "source_lab_runs": 3,
            "source_lab_batches": 3,
            "source_lab_records": 3,
            "source_lab_record_observations": 3,
            "source_lab_reviews": 3,
            "source_lab_review_resolutions": 3,
            "source_lab_opportunity_evidence_links": 3,
            "companies": 1,
            "contacts": 1,
            "projects": 1,
            "opportunities": 1,
            "crm_outbox": 4,
            "crm_mappings": 0,
        }
        self.assertEqual(self._counts(), expected_counts)
        con = self.store.connect()
        try:
            operations = con.execute(
                "SELECT operation_type,external_event_id,state FROM crm_outbox"
            ).fetchall()
            self.assertEqual({str(row[0]) for row in operations}, GRAPH_OPERATION_TYPES)
            self.assertEqual({str(row[1]) for row in operations}, {creator_event_id})
            self.assertEqual({str(row[2]) for row in operations}, {"PENDING"})
            anchor_rows = con.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='source_commercial_approved_link_anchored'"""
            ).fetchall()
            queue_event_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type IN (
                       'source_lab_review_claimed',
                       'source_lab_review_resolution_recorded'
                   )"""
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(len(anchor_rows), 3)
        self.assertEqual(queue_event_count, 6)
        self._assert_switches_off()
        con = self.store.connect()
        try:
            validate_source_lab_integrity(con)
            validate_source_review_queue_integrity(con)
        finally:
            con.close()

    def test_exact_replay_changes_no_fact_or_reconciliation_hash(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        before = reconcile_cross_source_object(self.store, expectation)
        counts = self._counts()

        for item in items:
            replay_import = item.importer.import_bytes(
                item.data,
                source_format=SourceImportFormat.CSV,
                run_key=item.run_key,
                batch_key=item.batch_key,
            )
            self.assertEqual(replay_import.created_rows, 0)
            self.assertEqual(replay_import.replayed_rows, 1)
            replay_bridge = self._bridge(item)
            self.assertFalse(replay_bridge.graph_created)
            self.assertTrue(replay_bridge.opportunity_reused)
            self.assertFalse(replay_bridge.evidence_link_created)
            self.assertFalse(replay_bridge.crm_stage.created)

        after = reconcile_cross_source_object(self.store, expectation)
        self.assertEqual(after, before)
        self.assertEqual(after.report_hash, before.report_hash)
        self.assertEqual(self._counts(), counts)
        self._assert_switches_off()

    def test_backup_restore_preserves_the_exact_reconciliation_report(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        expected = reconcile_cross_source_object(self.store, expectation)
        backup = create_backup(
            self.store,
            destination_dir=self.root / "backups",
            evidence_root=self.root / "evidence",
        )
        restored_path = self.root / "restored-cross-source.sqlite3"
        restore = verify_restore(backup["backup"], restore_path=restored_path)
        restored_store = FactoryStore(restored_path)

        actual = reconcile_cross_source_object(restored_store, expectation)
        self.assertEqual(actual, expected)
        self.assertEqual(actual.report_hash, expected.report_hash)
        self.assertEqual(restore["schema_version"], "17")
        self.assertEqual(restore["external_writers_enabled"], "0")
        self.assertEqual(restore["external_source_reads_enabled"], "0")
        self.assertEqual(restore["manual_import_commits_enabled"], "0")
        self.assertEqual(self._counts(restored_store), self._counts())
        self._assert_switches_off(restored_store)

    def test_same_inn_without_strong_project_ref_stays_two_projects(self) -> None:
        first = self._import_review(SOURCE_IDS[0], project_ref="")
        second = self._import_review(SOURCE_IDS[1], project_ref="")
        first_result = self._bridge(first)
        second_result = self._bridge(second)

        self.assertNotEqual(first_result.lf_project_id, second_result.lf_project_id)
        self.assertNotEqual(
            first_result.lf_opportunity_id, second_result.lf_opportunity_id
        )
        self.assertEqual(self.store.table_count("companies"), 1)
        self.assertEqual(self.store.table_count("projects"), 2)
        self.assertEqual(self.store.table_count("opportunities"), 2)
        self.assertEqual(
            self.store.table_count("source_lab_opportunity_evidence_links"), 2
        )
        self._assert_switches_off()

    def test_invalid_expectations_and_wrong_project_hash_fail_closed(self) -> None:
        invalid_expectations = (
            CrossSourceExpectation(
                source_ids=("wave1 bad", SOURCE_IDS[1], SOURCE_IDS[2]),
                project_identity_namespace=PROJECT_NAMESPACE,
                project_identity_hash=self.project_hash,
            ),
            CrossSourceExpectation(
                source_ids=tuple(reversed(SOURCE_IDS)),
                project_identity_namespace=PROJECT_NAMESPACE,
                project_identity_hash=self.project_hash,
            ),
            CrossSourceExpectation(
                source_ids=(SOURCE_IDS[0], SOURCE_IDS[0], SOURCE_IDS[2]),
                project_identity_namespace=PROJECT_NAMESPACE,
                project_identity_hash=self.project_hash,
            ),
            CrossSourceExpectation(
                source_ids=SOURCE_IDS,
                project_identity_namespace=PROJECT_NAMESPACE,
                project_identity_hash=self.project_hash,
                approval_bindings=(),
            ),
        )
        for expectation in invalid_expectations:
            with self.subTest(source_ids=expectation.source_ids):
                with self.assertRaises(CrossSourceExpectationError):
                    reconcile_cross_source_object(self.store, expectation)

        items, _ = self._build_shared_object()
        counts = self._counts()
        valid = self._expectation(items)
        wrong_hash = CrossSourceExpectation(
            source_ids=SOURCE_IDS,
            project_identity_namespace=PROJECT_NAMESPACE,
            project_identity_hash="0" * 64,
            approval_bindings=valid.approval_bindings,
        )
        with self.assertRaises(CrossSourceReconciliationError):
            reconcile_cross_source_object(self.store, wrong_hash)
        self.assertEqual(self._counts(), counts)
        self._assert_switches_off()

    def test_rehashed_commercial_anchor_tamper_is_rejected_and_restored(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        expected = reconcile_cross_source_object(self.store, expectation)
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT event_id,payload_json,payload_hash FROM events
                   WHERE event_type='source_commercial_approved_link_anchored'
                     AND causation_id=?""",
                (items[1].resolution_event_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            event_id = str(row["event_id"])
            original_json = str(row["payload_json"])
            original_hash = str(row["payload_hash"])
        finally:
            con.close()
        trigger_sql = self._event_update_trigger_sql()
        tampered = json.loads(original_json)
        tampered["creator_resolution_event_id"] = items[1].resolution_event_id
        tampered_json = canonical_json(tampered)
        tampered_hash = payload_hash(tampered)
        self.assertNotEqual(tampered_json, original_json)
        self.assertNotEqual(tampered_hash, original_hash)

        self._rewrite_event_payload(
            event_id=event_id,
            payload_json=tampered_json,
            stored_payload_hash=tampered_hash,
            expected_trigger_sql=trigger_sql,
        )
        try:
            with self.assertRaises(CrossSourceReconciliationError):
                reconcile_cross_source_object(self.store, expectation)
        finally:
            self._rewrite_event_payload(
                event_id=event_id,
                payload_json=original_json,
                stored_payload_hash=original_hash,
                expected_trigger_sql=trigger_sql,
            )

        self.assertEqual(
            reconcile_cross_source_object(self.store, expectation),
            expected,
        )
        self.assertEqual(self._event_update_trigger_sql(), trigger_sql)

    def test_later_rejected_qualification_revokes_the_acceptance_report(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        self.assertEqual(
            reconcile_cross_source_object(self.store, expectation).status,
            "PASSED",
        )

        rejection = self._record_later_qualification(items[1], decision="REJECT")

        self.assertEqual(rejection.decision, "REJECT")
        with self.assertRaises(CrossSourceReconciliationError):
            reconcile_cross_source_object(self.store, expectation)
        self._assert_switches_off()

    def test_shadow_anchor_with_a_foreign_aggregate_is_rejected(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        self.assertEqual(
            reconcile_cross_source_object(self.store, expectation).status,
            "PASSED",
        )
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='source_commercial_approved_link_anchored'
                     AND causation_id=?""",
                (items[0].resolution_event_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            copied_payload = json.loads(str(row["payload_json"]))
        finally:
            con.close()

        shadow, created = self.store.append_event(
            event_type="source_commercial_approved_link_anchored",
            aggregate_type="source_lab_evidence_link",
            aggregate_id="lf_source_lab_evidence_link_foreign_shadow",
            producer="source_commercial_bridge",
            idempotency_key="cross-source-foreign-shadow-anchor",
            payload=copied_payload,
            actor="source_commercial_bridge",
            causation_id=str(copied_payload["resolution_event_id"]),
            schema_version=16,
        )
        self.assertTrue(created)
        self.assertNotEqual(
            shadow["aggregate_id"], copied_payload["evidence_link_id"]
        )
        with self.assertRaises(CrossSourceReconciliationError):
            reconcile_cross_source_object(self.store, expectation)

    def test_swapped_graph_creator_flags_with_repaired_hashes_are_rejected(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        expected = reconcile_cross_source_object(self.store, expectation)
        con = self.store.connect()
        try:
            rows = con.execute(
                """SELECT event_id,payload_json,payload_hash FROM events
                   WHERE event_type='source_commercial_approved_link_anchored'
                   ORDER BY event_id"""
            ).fetchall()
            originals = [
                (str(row["event_id"]), str(row["payload_json"]), str(row["payload_hash"]))
                for row in rows
            ]
        finally:
            con.close()
        self.assertEqual(len(originals), 3)
        creator = next(
            original
            for original in originals
            if json.loads(original[1])["graph_created"]
        )
        reuse = next(
            original
            for original in originals
            if not json.loads(original[1])["graph_created"]
        )
        trigger_sql = self._event_update_trigger_sql()
        applied: list[tuple[str, str, str]] = []
        try:
            for original in (creator, reuse):
                event_id, original_json, original_hash = original
                tampered = json.loads(original_json)
                tampered["graph_created"] = not tampered["graph_created"]
                self._rewrite_event_payload(
                    event_id=event_id,
                    payload_json=canonical_json(tampered),
                    stored_payload_hash=payload_hash(tampered),
                    expected_trigger_sql=trigger_sql,
                )
                applied.append((event_id, original_json, original_hash))
            with self.assertRaises(CrossSourceReconciliationError):
                reconcile_cross_source_object(self.store, expectation)
        finally:
            for event_id, original_json, original_hash in reversed(applied):
                self._rewrite_event_payload(
                    event_id=event_id,
                    payload_json=original_json,
                    stored_payload_hash=original_hash,
                    expected_trigger_sql=trigger_sql,
                )

        self.assertEqual(
            reconcile_cross_source_object(self.store, expectation), expected
        )

    def test_bound_anchor_hash_tampers_are_rejected_after_payload_rehash(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        expected = reconcile_cross_source_object(self.store, expectation)
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT event_id,payload_json,payload_hash FROM events
                   WHERE event_type='source_commercial_approved_link_anchored'
                     AND causation_id=?""",
                (items[0].resolution_event_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            event_id = str(row["event_id"])
            original_json = str(row["payload_json"])
            original_hash = str(row["payload_hash"])
        finally:
            con.close()
        trigger_sql = self._event_update_trigger_sql()
        replacements = {
            "source_payload_hash": "0" * 64,
            "policy_hash": "1" * 64,
            "approval_receipt_hash": "2" * 64,
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                tampered = json.loads(original_json)
                self.assertNotEqual(tampered[field], replacement)
                tampered[field] = replacement
                self._rewrite_event_payload(
                    event_id=event_id,
                    payload_json=canonical_json(tampered),
                    stored_payload_hash=payload_hash(tampered),
                    expected_trigger_sql=trigger_sql,
                )
                try:
                    with self.assertRaises(CrossSourceReconciliationError):
                        reconcile_cross_source_object(self.store, expectation)
                finally:
                    self._rewrite_event_payload(
                        event_id=event_id,
                        payload_json=original_json,
                        stored_payload_hash=original_hash,
                        expected_trigger_sql=trigger_sql,
                    )
                self.assertEqual(
                    reconcile_cross_source_object(self.store, expectation),
                    expected,
                )

    def test_coordinated_company_payload_and_stage_anchor_tamper_is_rejected(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        expected = reconcile_cross_source_object(self.store, expectation)
        con = self.store.connect()
        try:
            operation = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_type=?",
                (COMPANY_CREATE,),
            ).fetchone()
            self.assertIsNotNone(operation)
            original_operation = dict(operation)
            stage_event = con.execute(
                """SELECT event_id,payload_json,payload_hash FROM events
                   WHERE producer='crm_graph_outbox' AND idempotency_key=?""",
                (f"crm-graph-stage:{operation['operation_id']}",),
            ).fetchone()
            self.assertIsNotNone(stage_event)
            stage_event_id = str(stage_event["event_id"])
            original_anchor_json = str(stage_event["payload_json"])
            original_anchor_hash = str(stage_event["payload_hash"])
        finally:
            con.close()
        public_tamper = json.loads(str(original_operation["payload_json"]))
        public_tamper["TITLE"] = "COORDINATED COMPANY PAYLOAD TAMPER"
        tampered_json = canonical_json(public_tamper)
        tampered_hash = payload_hash(public_tamper)
        trigger_sql = self._event_update_trigger_sql()
        outbox_changed = False
        anchor_changed = False
        try:
            with self.store.transaction() as con:
                changed = con.execute(
                    """UPDATE crm_outbox SET payload_json=?,payload_hash=?
                       WHERE operation_id=?""",
                    (
                        tampered_json,
                        tampered_hash,
                        original_operation["operation_id"],
                    ),
                )
                self.assertEqual(changed.rowcount, 1)
            outbox_changed = True
            con = self.store.connect()
            try:
                changed_operation = con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?",
                    (original_operation["operation_id"],),
                ).fetchone()
                self.assertIsNotNone(changed_operation)
                coordinated_anchor = CrmGraphOutbox._stage_anchor_payload(
                    changed_operation
                )
            finally:
                con.close()
            self._rewrite_event_payload(
                event_id=stage_event_id,
                payload_json=canonical_json(coordinated_anchor),
                stored_payload_hash=payload_hash(coordinated_anchor),
                expected_trigger_sql=trigger_sql,
            )
            anchor_changed = True

            with self.assertRaises(CrossSourceReconciliationError):
                reconcile_cross_source_object(self.store, expectation)
        finally:
            if anchor_changed:
                self._rewrite_event_payload(
                    event_id=stage_event_id,
                    payload_json=original_anchor_json,
                    stored_payload_hash=original_anchor_hash,
                    expected_trigger_sql=trigger_sql,
                )
            if outbox_changed:
                with self.store.transaction() as con:
                    restored = con.execute(
                        """UPDATE crm_outbox SET payload_json=?,payload_hash=?
                           WHERE operation_id=?""",
                        (
                            original_operation["payload_json"],
                            original_operation["payload_hash"],
                            original_operation["operation_id"],
                        ),
                    )
                    self.assertEqual(restored.rowcount, 1)

        con = self.store.connect()
        try:
            restored_operation = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (original_operation["operation_id"],),
            ).fetchone()
            self.assertIsNotNone(restored_operation)
            self.assertEqual(dict(restored_operation), original_operation)
        finally:
            con.close()
        self.assertEqual(self._event_update_trigger_sql(), trigger_sql)
        self.assertEqual(
            reconcile_cross_source_object(self.store, expectation), expected
        )

    def test_each_nonzero_crm_operational_field_revokes_acceptance(self) -> None:
        items, _ = self._build_shared_object()
        expectation = self._expectation(items)
        expected = reconcile_cross_source_object(self.store, expectation)
        con = self.store.connect()
        try:
            operation = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_type=?",
                (COMPANY_CREATE,),
            ).fetchone()
            self.assertIsNotNone(operation)
            original = dict(operation)
        finally:
            con.close()
        trigger_sql = self._event_update_trigger_sql()
        mutations: tuple[tuple[str, object], ...] = (
            ("next_attempt_at_utc", "2026-08-25T12:00:00Z"),
            ("lease_until_utc", "2026-08-25T12:05:00Z"),
            ("leased_by", "offline-worker"),
            ("lease_token", "lf_lease_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("last_error_class", "RetryableRemoteError"),
            ("last_error_hash", "a" * 64),
            ("remote_entity_type", "company"),
            ("remote_entity_id", "101"),
            ("suspect_remote_entity_type", "company"),
            ("suspect_remote_entity_id", "202"),
            ("updated_at_utc", "2026-08-25T12:10:00Z"),
        )
        allowed_columns = frozenset(field for field, _ in mutations)
        for field, value in mutations:
            with self.subTest(field=field):
                self.assertIn(field, allowed_columns)
                self.assertNotEqual(value, original[field])
                try:
                    with self.store.transaction() as con:
                        changed = con.execute(
                            f"UPDATE crm_outbox SET {field}=? WHERE operation_id=?",
                            (value, original["operation_id"]),
                        )
                        self.assertEqual(changed.rowcount, 1)
                    with self.assertRaises(CrossSourceReconciliationError):
                        reconcile_cross_source_object(self.store, expectation)
                finally:
                    with self.store.transaction() as con:
                        restored = con.execute(
                            f"UPDATE crm_outbox SET {field}=? WHERE operation_id=?",
                            (original[field], original["operation_id"]),
                        )
                        self.assertEqual(restored.rowcount, 1)
                con = self.store.connect()
                try:
                    restored_row = con.execute(
                        "SELECT * FROM crm_outbox WHERE operation_id=?",
                        (original["operation_id"],),
                    ).fetchone()
                    self.assertIsNotNone(restored_row)
                    self.assertEqual(dict(restored_row), original)
                finally:
                    con.close()
                self.assertEqual(self._event_update_trigger_sql(), trigger_sql)
                self.assertEqual(
                    reconcile_cross_source_object(self.store, expectation),
                    expected,
                )

    def test_reconciliation_is_physically_read_only_and_leaves_no_sidecars(self) -> None:
        items, _ = self._build_shared_object()
        database = Path(self.store.path).resolve()
        wal = Path(f"{database}-wal")
        shm = Path(f"{database}-shm")
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        before = (
            database.stat().st_size,
            database.stat().st_mtime_ns,
            _file_sha256(database),
        )

        report = reconcile_cross_source_object(self.store, self._expectation(items))

        after = (
            database.stat().st_size,
            database.stat().st_mtime_ns,
            _file_sha256(database),
        )
        self.assertEqual(report.status, "PASSED")
        self.assertEqual(after, before)
        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())


if __name__ == "__main__":
    unittest.main()
