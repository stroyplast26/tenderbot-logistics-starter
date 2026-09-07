from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lead_factory.commercial_spine import NormalizedOpportunityIntake
from lead_factory.construction_radar import (
    CapabilityState,
    LicenceState,
    PassportState,
    RadarContour,
    SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.crm_graph_outbox import ACTIVITY_CREATE, DEAL_CREATE
from lead_factory.bitrix_graph_mapping import (
    GRAPH_ACTIVITY_MARKER_VERSION,
    GRAPH_CONTRACT_VERSION,
    GRAPH_INPUT_CONTRACT_VERSION,
    GRAPH_MAPPING_EVIDENCE_MODE,
    GRAPH_MAPPING_LIFECYCLE,
    GRAPH_MAPPING_MANIFEST_VERSION,
    BitrixGraphBridgeBinding,
    BitrixGraphCorrelationField,
    BitrixGraphFieldBinding,
    BitrixGraphMappingManifest,
    BitrixGraphRoute,
    BitrixGraphSourceBinding,
    graph_mapping_manifest_hash,
)
from lead_factory.radar_review_access import (
    RadarEvidenceCommand,
    RadarEvidenceVault,
    SourceAccessMode,
    SourceAccessPermit,
    SourceAccessPermitLedger,
    SourceEvidenceBoundary,
    SourceEvidenceCommand,
)
from lead_factory.source_commercial_bridge import (
    ApprovedSourceCommand,
    SourceCommercialBridge,
    SourceCommercialConflict,
    SourceCommercialPolicy,
    SourceCommercialValidationError,
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
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_lab_integrity import (
    SourceLabIntegrityError,
    validate_source_lab_integrity,
)
from lead_factory.source_review_queue import SourceReviewQueue
from lead_factory.store import FactoryStore


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
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


def graph_binding(source_id: str) -> BitrixGraphBridgeBinding:
    fixed = {
        ("activity", "DEADLINE"): "deadline",
        ("activity", "DESCRIPTION"): "description",
        ("activity", "SUBJECT"): "title",
        ("company", "TITLE"): "TITLE",
        ("contact", "EMAIL"): "EMAIL",
        ("contact", "NAME"): "NAME",
        ("contact", "PHONE"): "PHONE",
        ("contact", "POST"): "POST",
        ("deal", "TITLE"): "TITLE",
    }
    keys = {
        ("activity", "DEADLINE"), ("activity", "DESCRIPTION"), ("activity", "SUBJECT"),
        ("company", "TITLE"), ("company", "UF_CRM_LF_COMPANY_ID"),
        ("company", "UF_CRM_LF_INN"), ("contact", "EMAIL"), ("contact", "NAME"),
        ("contact", "PHONE"), ("contact", "POST"), ("contact", "UF_CRM_LF_CONTACT_ID"),
        ("deal", "TITLE"), ("deal", "UF_CRM_LF_OPPORTUNITY_ID"),
        ("deal", "UF_CRM_LF_PROJECT_ID"), ("deal", "UF_CRM_LF_PRODUCT_KEY"),
        ("deal", "UF_CRM_LF_SOURCE_EVENT_ID"), ("deal", "UF_CRM_LF_SOURCE_ID"),
    }
    raw = BitrixGraphMappingManifest(
        GRAPH_MAPPING_MANIFEST_VERSION, "fixture:source-graph", "1", GRAPH_CONTRACT_VERSION,
        GRAPH_INPUT_CONTRACT_VERSION, GRAPH_MAPPING_LIFECYCLE, GRAPH_MAPPING_EVIDENCE_MODE,
        "bitrix-host-v1:" + "b" * 64,
        tuple(BitrixGraphFieldBinding(entity, key, fixed.get((entity, key), key)) for entity, key in sorted(keys)),
        (BitrixGraphCorrelationField("company", "UF_CRM_LF_CORRELATION_COMPANY"),
         BitrixGraphCorrelationField("contact", "UF_CRM_LF_CORRELATION_CONTACT"),
         BitrixGraphCorrelationField("deal", "UF_CRM_LF_CORRELATION_DEAL")),
        (
            BitrixGraphSourceBinding("manual", "LF_MANUAL"),
            BitrixGraphSourceBinding("saby", "LF_SABY"),
            BitrixGraphSourceBinding("tenderplan", "LF_TENDERPLAN"),
            BitrixGraphSourceBinding("wave1:domrf_public_projects", "LF_DOMRF"),
            BitrixGraphSourceBinding("wave1:saby_trade", "LF_SABY_TRADE"),
            BitrixGraphSourceBinding("wave1:tenderplan", "LF_TENDERPLAN_W1"),
        ),
        BitrixGraphRoute("7", "C7:NEW", "10", "11"), GRAPH_ACTIVITY_MARKER_VERSION,
    )
    manifest = replace(raw, declared_manifest_hash=graph_mapping_manifest_hash(raw))
    return BitrixGraphBridgeBinding(manifest, source_id, "2026-08-21T10:00:00Z")


def _csv_bytes(values: dict[str, str]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=HEADERS, lineterminator="\n")
    writer.writeheader()
    writer.writerow({header: values.get(header, "") for header in HEADERS})
    return stream.getvalue().encode("utf-8")


class ExactApprovalAuthority:
    capability_version = TRUSTED_APPROVAL_CAPABILITY_VERSION

    def __init__(self, mode: str = "exact", *, fixed_receipt_id: str = ""):
        self.mode = mode
        self.fixed_receipt_id = fixed_receipt_id
        self.calls: list[TrustedApprovalRequest] = []

    def verify_approval(self, request: TrustedApprovalRequest):
        self.calls.append(request)
        if self.mode == "error":
            raise RuntimeError("PRIVATE-AUTHORITY-TOKEN")
        bound = request
        bound_hash = request.request_hash
        if self.mode == "skip":
            return None
        if self.mode == "mismatch":
            bound = replace(request, observation_id="substituted-observation")
            bound_hash = bound.request_hash
        elif self.mode == "substitute":
            bound_hash = "0" * 64
        return TrustedApprovalReceipt(
            capability_version=TRUSTED_APPROVAL_CAPABILITY_VERSION,
            receipt_version=TRUSTED_APPROVAL_RECEIPT_VERSION,
            authority_id="offline-approval-authority",
            receipt_id=(
                self.fixed_receipt_id
                or f"approval-receipt-{bound_hash[:40]}"
            ),
            request=bound,
            request_hash=bound_hash,
        )


class SourceCommercialBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "source-commercial.sqlite3")
        self.store.init()
        self.sink = SourceLabSink(self.store, clock=lambda: NOW)
        self.review_queue = SourceReviewQueue(
            self.store,
            clock=lambda: datetime.now(timezone.utc).replace(microsecond=0),
        )
        self.sequence = 0
        self.passports = SourcePassportRegistry(self.store, clock=lambda: NOW)
        self.vault = RadarEvidenceVault(self.store, clock=lambda: NOW)
        self.access = SourceAccessPermitLedger(self.store, clock=lambda: NOW)
        self.evidence_boundary = SourceEvidenceBoundary(self.store, clock=lambda: NOW)
        self._passport_cache = {}
        self.authority = ExactApprovalAuthority()
        self.approval = self._put_evidence(
            b'{"approved":true}',
            "RADAR_SOURCE_ACCESS_APPROVAL",
            "shared-approval",
        )
        self.budget = self._put_evidence(
            b'{"budget":true}',
            "RADAR_SOURCE_ACCESS_BUDGET",
            "shared-budget",
        )

    def tearDown(self):
        self.temp.cleanup()

    def _put_evidence(
        self,
        blob: bytes,
        data_class: str,
        suffix: str,
        *,
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
                source_label=f"bridge-{suffix}",
                captured_at_utc="2026-08-20T10:00:00Z",
                actor="offline-curator",
                declared_sha256=hashlib.sha256(blob).hexdigest(),
                data_class=data_class,
                classification="INTERNAL",
                passport_id=passport_id,
            ),
            idempotency_key=(
                f"bridge-evidence:{suffix}:{hashlib.sha256(blob).hexdigest()}"
            ),
        )

    def _passport(self, source: str):
        existing = self._passport_cache.get(source)
        if existing is not None:
            return existing
        passport = self.passports.register(
            SourcePassport(
                source_key=source,
                passport_version=1,
                contour=RadarContour.CAPITAL_PROJECT,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=("B2B_LEAD_CANDIDATE",),
                max_age_days=30,
                state=PassportState.APPROVED,
                capability_state=CapabilityState.PASS,
                licence_state=LicenceState.ALLOWED,
                terms_ref=f"evidence://passport/{source}/terms",
                licence_ref=f"evidence://passport/{source}/licence",
                capability_evidence_ref=f"evidence://passport/{source}/capability",
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-09-01T00:00:00Z",
                data_contract_version="aluminium-lead-v1",
            ),
            idempotency_key=f"bridge-passport:{source}:v1",
            actor="offline-test",
        )
        self._passport_cache[source] = passport
        return passport

    def _import(
        self,
        *,
        source="tenderplan",
        external_key="tender-1",
        inn="7707083893",
        domain="buyer.example",
        email="buyer@example.test",
        phone="+7 999 123-45-67",
        project_code="project-42",
        project_title="Facade reconstruction",
        product_key="ALUMINIUM_PROFILE",
    ):
        self.sequence += 1
        values = {
            "id": external_key,
            "company_name": "Aluminium Buyer",
            "inn": inn,
            "domain": domain,
            "contact_name": "Procurement Manager",
            "email": email,
            "phone": phone,
            "role": "procurement",
            "project_title": project_title,
            "region": "Moscow",
            "product_key": product_key,
            "project_code": project_code,
        }
        data = _csv_bytes(values)
        digest = hashlib.sha256(data).hexdigest()
        passport = self._passport(source)
        blob_evidence = self._put_evidence(
            data,
            "B2B_LEAD_CANDIDATE",
            f"blob-{source}-{self.sequence}",
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
            idempotency_key=f"bridge-permit:{source}:{self.sequence}",
            actor="offline-access-controller",
        )
        receipt = self.evidence_boundary.capture(
            SourceEvidenceCommand(
                permit_id=permit.permit_id,
                operation_key=f"bridge-import-{source}-{self.sequence}",
                record_count=1,
                byte_count=len(data),
                cost_minor=0,
                content_sha256=digest,
                evidence_id=blob_evidence.evidence_id,
                observed_at_utc="2026-08-20T10:00:00Z",
                actor="offline-normalizer",
            ),
            idempotency_key=f"bridge-receipt:{source}:{self.sequence}",
        )
        auth = SourceAuthorizationSnapshot(
            snapshot_version="source-authorization-v1",
            source_id=source,
            data_class="B2B_LEAD_CANDIDATE",
            acquisition_mode="OFFLINE_FIXTURE",
            passport_id=passport.passport_id,
            passport_version="1",
            passport_evidence_ref=f"evidence://passport/{source}/capability",
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
            policy_id=f"import-{source}",
            policy_version="mapping-v1",
            evidence_ref=f"evidence://mapping/{source}",
            source_id=source,
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
            field_mappings=tuple(FieldMapping(header, header) for header in HEADERS),
            identity_mappings=(
                IdentityMapping("project_code", "project-ref"),
                IdentityMapping("inn", "inn"),
                IdentityMapping("email", "email"),
            ),
            authorization=auth,
        )
        imported = SourceBatchImporter(
            self.sink,
            policy=import_policy,
            clock=lambda: NOW,
            current_source_read_epoch=0,
        ).import_bytes(
            data,
            source_format="CSV",
            run_key=f"run-{source}-{self.sequence}",
            batch_key=f"batch-{source}-{self.sequence}",
        )
        result = imported.record_results[0]
        commercial_policy = SourceCommercialPolicy(
            policy_id=f"commercial-{source}",
            policy_version="1",
            source_id=source,
            data_contract_version="aluminium-lead-v1",
            mapping_policy_hash=imported.mapping_policy_hash,
            bitrix_graph_binding=graph_binding(source),
            strong_project_namespaces=("project-ref",),
        )
        return {
            "source": source,
            "import": imported,
            "ingest": result,
            "policy": commercial_policy,
            "values": values,
        }

    def _review(
        self,
        imported,
        *,
        decision="APPROVE",
        resolve=True,
        key="",
        resolved_by="approver",
    ):
        suffix = key or str(self.sequence)
        review = self.sink.request_review(
            source_record_id=imported["ingest"].source_record_id,
            reason="commercial qualification",
            requested_by="reviewer",
            evidence_ref=f"evidence://review/{suffix}",
            idempotency_key=f"review-{suffix}",
        )
        resolution = None
        if resolve:
            resolution = self._resolve_review(
                review,
                decision=decision,
                reason="reviewed",
                resolved_by=resolved_by,
                evidence_ref=f"evidence://resolution/{suffix}",
                idempotency_key=f"resolution-{suffix}",
            )
        payload_hash = imported["ingest"].payload_hash
        command = ApprovedSourceCommand(
            source_record_id=imported["ingest"].source_record_id,
            observation_id=imported["ingest"].observation_id,
            review_id=review.review_id,
            latest_resolution_id=(
                resolution.resolution_id
                if resolution
                else "lf_source_lab_resolution_missing"
            ),
            expected_payload_hash=payload_hash,
            actor="commercial-bridge",
            idempotency_key=f"bridge-{suffix}",
        )
        return review, resolution, command

    def _resolve_review(
        self,
        review,
        *,
        decision,
        reason,
        resolved_by,
        evidence_ref,
        idempotency_key,
    ):
        page = self.review_queue.list_open(limit=100)
        item = next(
            (candidate for candidate in page.items if candidate.review_id == review.review_id),
            None,
        )
        self.assertIsNotNone(item)
        permit = self.review_queue.claim(
            review_id=review.review_id,
            claimant=resolved_by,
            evidence_ref=f"evidence://review-claim/{idempotency_key}",
            idempotency_key=f"claim-{idempotency_key}",
            expected_state_digest=item.state_digest,
        )
        return self.review_queue.resolve_claimed(
            permit,
            decision=decision,
            reason=reason,
            evidence_ref=evidence_ref,
            idempotency_key=idempotency_key,
        )

    def _replacement_hold(self, imported, *, suffix, resolved_by):
        review = self.sink.request_review(
            source_record_id=imported["ingest"].source_record_id,
            reason="approval reassessment",
            requested_by="reviewer",
            evidence_ref=f"evidence://review/{suffix}",
            idempotency_key=f"review-{suffix}",
        )
        return self._resolve_review(
            review,
            decision="HOLD",
            reason="approval withdrawn after new evidence",
            resolved_by=resolved_by,
            evidence_ref=f"evidence://resolution/{suffix}",
            idempotency_key=f"resolution-{suffix}",
        )

    def _count(self, table):
        return self.store.table_count(table)

    def _bridge(self, policy, *, authority=None, **kwargs):
        return SourceCommercialBridge(
            self.store,
            policy=policy,
            approval_authority=self.authority if authority is None else authority,
            **kwargs,
        )

    def _assert_integrity(self):
        con = self.store.connect()
        try:
            validate_source_lab_integrity(con)
        finally:
            con.close()

    def test_happy_pipeline_stages_exact_graph_with_writers_off_and_safe_repr(self):
        imported = self._import()
        _, _, command = self._review(imported)
        result = self._bridge(imported["policy"]).execute(command)

        self.assertTrue(result.graph_created)
        self.assertFalse(result.opportunity_reused)
        self.assertTrue(result.evidence_link_created)
        self.assertEqual(len(result.crm_stage.created_operation_ids), 4)
        self.assertEqual(self._count("companies"), 1)
        self.assertEqual(self._count("contacts"), 1)
        self.assertEqual(self._count("projects"), 1)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 1)
        self.assertEqual(self._count("crm_outbox"), 4)
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                ).fetchone()[0],
                "0",
            )
            rows = con.execute(
                "SELECT operation_type,state,dependency_operation_id,payload_json FROM crm_outbox"
            ).fetchall()
            self.assertEqual({row[1] for row in rows}, {"PENDING"})
            payloads = {row[0]: json.loads(row[3]) for row in rows}
            self.assertEqual(
                payloads[DEAL_CREATE]["_lf_graph_v1"]["mapping_manifest_hash"],
                self._bridge(imported["policy"])._mapping_manifest_hash,
            )
            self.assertEqual(
                payloads[DEAL_CREATE]["_lf_graph_v1"]["lf_source_id"],
                imported["source"],
            )
            self.assertEqual(
                payloads[ACTIVITY_CREATE]["DEADLINE"], "2026-08-21T10:00:00Z"
            )
        finally:
            con.close()
        secret = replace(command, actor="PRIVATE-CONTACT", idempotency_key="secret-token")
        self.assertNotIn("PRIVATE", repr(secret))
        self.assertNotIn("secret-token", repr(secret))
        self.assertNotIn(imported["source"], repr(imported["policy"]))
        self.assertNotIn(command.source_record_id, repr(self.authority.calls[0]))
        con = self.store.connect()
        try:
            anchor = con.execute(
                """SELECT payload_json,evidence_ref FROM events
                   WHERE event_type='source_commercial_approved_link_anchored'"""
            ).fetchall()
            self.assertEqual(len(anchor), 1)
            self.assertEqual(anchor[0]["evidence_ref"], "")
            payload = json.loads(anchor[0]["payload_json"])
            self.assertNotIn("evidence_ref", payload)
            self.assertNotIn("resolved_by", payload)
            self.assertEqual(payload["observation_id"], command.observation_id)
            self.assertEqual(payload["lf_opportunity_id"], result.lf_opportunity_id)
        finally:
            con.close()
        self._assert_integrity()

    def test_untrusted_actor_or_missing_legacy_authority_writes_no_graph(self):
        imported = self._import(external_key="attacker-approval")
        _, _, command = self._review(
            imported, key="attacker-approval", resolved_by="arbitrary-attacker"
        )
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "authority is unavailable"
        ):
            SourceCommercialBridge(
                self.store, policy=imported["policy"]
            ).execute(command)

        class LegacyAuthority:
            def verify_approval(self, request):
                return ExactApprovalAuthority().verify_approval(request)

        with self.assertRaisesRegex(
            SourceCommercialValidationError, "authority is unavailable"
        ):
            SourceCommercialBridge(
                self.store,
                policy=imported["policy"],
                approval_authority=LegacyAuthority(),
            ).execute(command)
        self.assertEqual(self._count("opportunities"), 0)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 0)
        self.assertEqual(self._count("crm_outbox"), 0)

    def test_mismatched_skipped_substituted_and_error_receipts_fail_closed(self):
        for mode in ("skip", "mismatch", "substitute", "error"):
            with self.subTest(mode=mode):
                imported = self._import(external_key=f"bad-receipt-{mode}")
                _, _, command = self._review(
                    imported, key=f"bad-receipt-{mode}"
                )
                authority = ExactApprovalAuthority(mode)
                with self.assertRaises(SourceCommercialValidationError) as caught:
                    self._bridge(
                        imported["policy"], authority=authority
                    ).execute(command)
                self.assertNotIn("PRIVATE-AUTHORITY-TOKEN", str(caught.exception))
        self.assertEqual(self._count("opportunities"), 0)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 0)
        self.assertEqual(self._count("crm_outbox"), 0)

    def test_one_receipt_id_cannot_authorize_two_bridge_anchors(self):
        authority = ExactApprovalAuthority(fixed_receipt_id="single-use-receipt")
        first_import = self._import(
            external_key="receipt-first", project_code="receipt-project-a"
        )
        _, _, first_command = self._review(first_import, key="receipt-first")
        self._bridge(
            first_import["policy"], authority=authority
        ).execute(first_command)
        second_import = self._import(
            external_key="receipt-second",
            project_code="receipt-project-b",
            email="receipt-second@example.test",
        )
        _, _, second_command = self._review(second_import, key="receipt-second")
        with self.assertRaisesRegex(SourceCommercialConflict, "already anchored"):
            self._bridge(
                second_import["policy"], authority=authority
            ).execute(second_command)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 1)
        self.assertEqual(self._count("crm_outbox"), 4)

    def test_authority_callback_runs_before_writer_lock_and_is_rechecked(self):
        imported = self._import(external_key="authority-lock-probe")
        _, _, command = self._review(imported, key="authority-lock-probe")
        store = self.store

        class WriteProbeAuthority(ExactApprovalAuthority):
            def verify_approval(self, request):
                store.append_event(
                    event_type="trusted_approval_probe",
                    aggregate_type="approval_probe",
                    aggregate_id="offline-probe",
                    producer="trusted_approval_probe",
                    idempotency_key=f"probe:{request.request_hash}",
                    payload={"request_hash": request.request_hash},
                    actor="offline-probe",
                )
                return super().verify_approval(request)

        result = self._bridge(
            imported["policy"], authority=WriteProbeAuthority()
        ).execute(command)
        self.assertTrue(result.graph_created)
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='trusted_approval_probe'"
                ).fetchone()[0],
                1,
            )
        finally:
            con.close()

    def test_open_hold_and_superseded_approval_are_rejected_without_graph(self):
        open_import = self._import(external_key="open")
        _, _, open_command = self._review(open_import, resolve=False, key="open")
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "resolution is not APPROVE"
        ):
            self._bridge(open_import["policy"]).execute(open_command)

        hold_import = self._import(external_key="hold")
        _, _, hold_command = self._review(
            hold_import, decision="HOLD", key="hold"
        )
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "resolution is not APPROVE"
        ):
            self._bridge(hold_import["policy"]).execute(hold_command)

        old_import = self._import(external_key="superseded")
        with patch(
            "lead_factory.source_lab.utc_now",
            return_value="2026-08-20T11:00:00Z",
        ):
            _, _, old_command = self._review(old_import, key="superseded")
        with patch(
            "lead_factory.source_lab.utc_now",
            return_value="2026-08-20T11:01:00Z",
        ):
            self._replacement_hold(
                old_import,
                suffix="superseding",
                resolved_by="approver",
            )
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "latest qualification review"
        ):
            self._bridge(old_import["policy"]).execute(old_command)
        self.assertEqual(self._count("opportunities"), 0)
        self.assertEqual(self._count("crm_outbox"), 0)

    def test_exact_replay_does_not_duplicate_any_fact(self):
        imported = self._import(external_key="replay")
        _, _, command = self._review(imported, key="replay")
        bridge = self._bridge(imported["policy"])
        first = bridge.execute(command)
        counts = {
            table: self._count(table)
            for table in (
                "companies",
                "contacts",
                "projects",
                "opportunities",
                "source_lab_opportunity_evidence_links",
                "crm_outbox",
            )
        }
        replay = bridge.execute(command)
        self.assertFalse(replay.graph_created)
        self.assertTrue(replay.opportunity_reused)
        self.assertFalse(replay.evidence_link_created)
        self.assertFalse(replay.crm_stage.created)
        self.assertEqual(replay.lf_opportunity_id, first.lf_opportunity_id)
        self.assertEqual(
            counts, {table: self._count(table) for table in counts}
        )

    def test_two_sources_same_strong_project_and_exact_inn_reuse_one_opportunity(self):
        first_import = self._import(source="tenderplan", external_key="tp-42")
        _, first_resolution, first_command = self._review(first_import, key="tp-42")
        first = self._bridge(first_import["policy"]).execute(first_command)

        second_import = self._import(
            source="saby", external_key="saby-42", email="other@example.test"
        )
        _, second_resolution, second_command = self._review(second_import, key="saby-42")
        second = self._bridge(second_import["policy"]).execute(second_command)

        self.assertTrue(second.opportunity_reused)
        self.assertFalse(second.crm_stage.created)
        self.assertEqual(second.crm_stage.created_operation_ids, ())
        self.assertEqual(second.lf_opportunity_id, first.lf_opportunity_id)
        self.assertEqual(self._count("companies"), 1)
        self.assertEqual(self._count("projects"), 1)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 2)
        self.assertEqual(self._count("crm_outbox"), 4)
        con = self.store.connect()
        try:
            causation = {
                row[0]
                for row in con.execute(
                    """SELECT external_event_id FROM crm_outbox
                       WHERE operation_type IN (?,?)""",
                    (DEAL_CREATE, ACTIVITY_CREATE),
                ).fetchall()
            }
        finally:
            con.close()
        self.assertEqual(causation, {first_resolution.event_id})
        self.assertNotIn(second_resolution.event_id, causation)
        self._assert_integrity()

    def test_same_inn_without_strong_project_key_creates_two_projects(self):
        first_import = self._import(
            source="tenderplan", external_key="tp-a", project_code=""
        )
        _, _, first_command = self._review(first_import, key="tp-a")
        self._bridge(first_import["policy"]).execute(first_command)
        second_import = self._import(
            source="saby",
            external_key="saby-b",
            project_code="",
            project_title="Second independent project",
            email="second@example.test",
        )
        _, _, second_command = self._review(second_import, key="saby-b")
        self._bridge(second_import["policy"]).execute(second_command)
        self.assertEqual(self._count("companies"), 1)
        self.assertEqual(self._count("projects"), 2)
        self.assertEqual(self._count("opportunities"), 2)
        self.assertEqual(self._count("crm_outbox"), 7)

    def test_strong_project_company_mismatch_is_fail_closed(self):
        first_import = self._import(source="tenderplan", external_key="tp-match")
        _, _, first_command = self._review(first_import, key="tp-match")
        self._bridge(first_import["policy"]).execute(first_command)
        second_import = self._import(
            source="saby", external_key="saby-mismatch", inn="7701234567"
        )
        _, _, second_command = self._review(second_import, key="saby-mismatch")
        before = (self._count("opportunities"), self._count("crm_outbox"))
        with self.assertRaisesRegex(SourceCommercialConflict, "exact INN"):
            self._bridge(second_import["policy"]).execute(second_command)
        self.assertEqual(
            before, (self._count("opportunities"), self._count("crm_outbox"))
        )
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 1)

    def test_unicode_phone_lookalike_is_rejected_before_graph_creation(self):
        imported = self._import(
            external_key="unicode-phone", phone="+７ 999 123-45-67"
        )
        _, _, command = self._review(imported, key="unicode-phone")
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "contact phone is invalid"
        ):
            self._bridge(imported["policy"]).execute(command)
        self.assertEqual(self._count("opportunities"), 0)
        self.assertEqual(self._count("crm_outbox"), 0)

    def test_unanchored_generic_link_cannot_create_false_strong_dedupe(self):
        first_import = self._import(source="tenderplan", external_key="collision-a")
        _, _, first_command = self._review(first_import, key="collision-a")
        first = self._bridge(first_import["policy"]).execute(first_command)
        second_import = self._import(source="manual", external_key="collision-b")
        legacy = NormalizedOpportunityIntake(self.store).ingest(
            producer="legacy-fixture",
            external_key="legacy-collision",
            idempotency_key="legacy-collision",
            payload={"fixture": True},
            evidence_ref="evidence://legacy/collision",
            observed_at_utc="2026-08-20T10:00:00Z",
            company_name="Aluminium Buyer",
            company_inn="7707083893",
            contact_name="Other",
            contact_email="legacy@example.test",
            project_title="Legacy duplicate project",
            product_key="ALUMINIUM_PROFILE",
        )
        self.sink.link_opportunity_evidence(
            lf_opportunity_id=legacy.lf_opportunity_id,
            source_record_id=second_import["ingest"].source_record_id,
            evidence_ref="evidence://legacy/link",
            actor="legacy-migration",
            idempotency_key="legacy-collision-link",
        )
        third_import = self._import(source="saby", external_key="collision-c")
        _, _, third_command = self._review(third_import, key="collision-c")
        before = self._count("opportunities")
        result = self._bridge(third_import["policy"]).execute(third_command)
        self.assertTrue(result.opportunity_reused)
        self.assertEqual(result.lf_opportunity_id, first.lf_opportunity_id)
        self.assertNotEqual(result.lf_opportunity_id, legacy.lf_opportunity_id)
        self.assertEqual(self._count("opportunities"), before)

    def test_unapproved_observation_identity_cannot_piggyback_valid_anchor(self):
        first_import = self._import(
            source="tenderplan",
            external_key="piggyback-record",
            project_code="approved-project-a",
        )
        _, _, first_command = self._review(first_import, key="piggyback-a")
        first = self._bridge(first_import["policy"]).execute(first_command)
        con = self.store.connect()
        try:
            record = con.execute(
                "SELECT * FROM source_lab_records WHERE source_record_id=?",
                (first_import["ingest"].source_record_id,),
            ).fetchone()
            stored_payload = json.loads(record["payload_json"])
        finally:
            con.close()

        incoming = self._import(
            source="saby",
            external_key="piggyback-incoming",
            project_code="unapproved-project-b",
            email="piggyback-incoming@example.test",
            project_title="Independent incoming project",
        )
        _, _, incoming_command = self._review(incoming, key="piggyback-incoming")
        with self.store.transaction(min_schema_version=16) as con:
            second_observation = self.sink._ingest_record_tx(
                source_id="tenderplan",
                acquisition_mode="OFFLINE_FIXTURE",
                run_key="piggyback-unapproved-observation",
                external_key=record["external_key"],
                payload=stored_payload,
                observed_at_utc="2026-08-20T10:00:00Z",
                evidence_ref="evidence://piggyback/unapproved-observation",
                idempotency_key="piggyback-unapproved-observation",
                canonical_keys=(("project-ref", "unapproved-project-b"),),
                _transaction=con,
            )
        self.assertEqual(
            second_observation.source_record_id,
            first_import["ingest"].source_record_id,
        )
        # Deliberately bypass the independent whole-ledger auditor here so the
        # bridge's own observation-bound dedupe guard is exercised in isolation.
        with patch(
            "lead_factory.source_commercial_bridge.validate_source_lab_integrity",
            return_value=None,
        ):
            result = self._bridge(incoming["policy"]).execute(incoming_command)
        self.assertFalse(result.opportunity_reused)
        self.assertNotEqual(result.lf_opportunity_id, first.lf_opportunity_id)
        self.assertEqual(self._count("opportunities"), 2)

    def test_forged_approved_link_without_anchor_is_fail_closed(self):
        imported = self._import(external_key="forged-approved")
        _, _, command = self._review(imported, key="forged-approved")
        legacy = NormalizedOpportunityIntake(self.store).ingest(
            producer="legacy-fixture",
            external_key="forged-approved-target",
            idempotency_key="forged-approved-target",
            payload={"fixture": True},
            evidence_ref="evidence://legacy/forged-approved",
            observed_at_utc="2026-08-20T10:00:00Z",
            company_name="Aluminium Buyer",
            company_inn="7707083893",
            contact_name="Other",
            contact_email="forged@example.test",
            project_title="Forged target",
            product_key="ALUMINIUM_PROFILE",
        )
        self.sink.link_opportunity_evidence(
            lf_opportunity_id=legacy.lf_opportunity_id,
            source_record_id=imported["ingest"].source_record_id,
            evidence_ref="evidence://legacy/forged-approved-link",
            actor="source_commercial_bridge",
            idempotency_key=f"source-commercial-link-v1:{command.idempotency_key}",
            link_reason="APPROVED_SOURCE_IMPORT",
        )
        with self.assertRaisesRegex(SourceCommercialConflict, "no trusted approval anchor"):
            self._bridge(imported["policy"]).execute(command)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("crm_outbox"), 0)

    def test_missing_direct_anchor_is_fail_closed(self):
        imported = self._import(external_key="missing-anchor")
        _, _, command = self._review(imported, key="missing-anchor")
        bridge = self._bridge(imported["policy"])
        bridge.execute(command)
        con = self.store.connect()
        try:
            con.execute("DROP TRIGGER trg_lf_events_no_delete")
            con.execute(
                "DELETE FROM events WHERE event_type=?",
                ("source_commercial_approved_link_anchored",),
            )
            con.execute(
                """CREATE TRIGGER trg_lf_events_no_delete
                   BEFORE DELETE ON events BEGIN
                       SELECT RAISE(ABORT, 'lead factory events are append-only');
                   END"""
            )
            con.commit()
        finally:
            con.close()
        before = self._count("crm_outbox")
        with self.assertRaisesRegex(SourceCommercialConflict, "no trusted approval anchor"):
            bridge.execute(command)
        self.assertEqual(self._count("crm_outbox"), before)

    def test_tampered_anchor_is_fail_closed(self):
        imported = self._import(external_key="tampered-anchor")
        _, _, command = self._review(imported, key="tampered-anchor")
        bridge = self._bridge(imported["policy"])
        bridge.execute(command)
        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT * FROM events WHERE event_type=?",
                ("source_commercial_approved_link_anchored",),
            ).fetchone()
            payload = json.loads(row["payload_json"])
            payload["policy_hash"] = "0" * 64
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            con.execute(
                "UPDATE events SET payload_json=? WHERE event_id=?",
                (
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    row["event_id"],
                ),
            )
            con.execute(
                """CREATE TRIGGER trg_lf_events_no_update
                   BEFORE UPDATE ON events BEGIN
                       SELECT RAISE(ABORT, 'lead factory events are append-only');
                   END"""
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaises(SourceCommercialConflict):
            bridge.execute(command)

    def test_tampered_anchor_event_correlation_is_fail_closed(self):
        imported = self._import(external_key="tampered-anchor-correlation")
        _, _, command = self._review(
            imported, key="tampered-anchor-correlation"
        )
        bridge = self._bridge(imported["policy"])
        bridge.execute(command)
        con = self.store.connect()
        try:
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            con.execute(
                """UPDATE events SET correlation_id='lf_event_wrong_correlation'
                   WHERE event_type='source_commercial_approved_link_anchored'"""
            )
            con.execute(
                """CREATE TRIGGER trg_lf_events_no_update
                   BEFORE UPDATE ON events BEGIN
                       SELECT RAISE(ABORT, 'lead factory events are append-only');
                   END"""
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaisesRegex(SourceCommercialConflict, "anchor is invalid"):
            bridge.execute(command)

    def test_ambiguous_anchor_is_fail_closed(self):
        imported = self._import(external_key="ambiguous-anchor")
        _, _, command = self._review(imported, key="ambiguous-anchor")
        bridge = self._bridge(imported["policy"])
        bridge.execute(command)
        with self.store.transaction(min_schema_version=16) as con:
            row = con.execute(
                """SELECT * FROM events
                   WHERE event_type=? AND aggregate_id=(
                       SELECT evidence_link_id
                       FROM source_lab_opportunity_evidence_links
                       WHERE source_record_id=?
                   )""",
                (
                    "source_commercial_approved_link_anchored",
                    imported["ingest"].source_record_id,
                ),
            ).fetchone()
            self.store._append_event_tx(
                con,
                event_type="source_commercial_approved_link_anchored",
                aggregate_type="source_lab_evidence_link",
                aggregate_id=row["aggregate_id"],
                producer="attacker-fixture",
                idempotency_key="ambiguous-approved-anchor",
                payload=json.loads(row["payload_json"]),
                actor="source_commercial_bridge",
                causation_id=row["causation_id"],
                schema_version=16,
            )
        with self.assertRaisesRegex(SourceCommercialConflict, "exactly one"):
            bridge.execute(command)

    def test_injected_transaction_failure_rolls_back_graph_and_evidence(self):
        imported = self._import(external_key="tx-crash")
        _, _, command = self._review(imported, key="tx-crash")

        def crash(_graph, _link):
            raise RuntimeError("injected graph transaction crash")

        with self.assertRaisesRegex(RuntimeError, "injected"):
            self._bridge(
                imported["policy"], before_graph_commit=crash
            ).execute(command)
        self.assertEqual(self._count("opportunities"), 0)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 0)
        self.assertEqual(self._count("crm_outbox"), 0)
        recovered = self._bridge(imported["policy"]).execute(command)
        self.assertTrue(recovered.graph_created)

    def test_crash_after_graph_commit_replays_into_crm_without_duplicates(self):
        imported = self._import(external_key="crm-crash")
        _, _, command = self._review(imported, key="crm-crash")

        def crash():
            raise RuntimeError("injected pre-stage crash")

        with self.assertRaisesRegex(RuntimeError, "pre-stage"):
            self._bridge(
                imported["policy"], before_crm_stage=crash
            ).execute(command)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 1)
        self.assertEqual(self._count("crm_outbox"), 0)
        recovered = self._bridge(imported["policy"]).execute(command)
        self.assertEqual(len(recovered.crm_stage.created_operation_ids), 4)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 1)

    def test_hold_between_graph_commit_and_crm_stage_writes_zero_crm(self):
        imported = self._import(external_key="hold-before-crm")
        with patch(
            "lead_factory.source_lab.utc_now",
            return_value="2026-08-20T11:00:00Z",
        ):
            _, _, command = self._review(imported, key="hold-before-crm")

        def append_hold():
            with patch(
                "lead_factory.source_lab.utc_now",
                return_value="2026-08-20T11:01:00Z",
            ):
                self._replacement_hold(
                    imported,
                    suffix="withdrawn-before-crm-stage",
                    resolved_by="trusted-approver",
                )

        with self.assertRaisesRegex(
            SourceCommercialValidationError, "latest qualification review"
        ):
            self._bridge(
                imported["policy"], before_crm_stage=append_hold
            ).execute(command)
        self.assertEqual(self._count("opportunities"), 1)
        self.assertEqual(self._count("source_lab_opportunity_evidence_links"), 1)
        self.assertEqual(self._count("crm_outbox"), 0)

    def test_existing_exact_crm_graph_with_substituted_causation_is_rejected(self):
        imported = self._import(external_key="substituted-crm-causation")
        _, approval, command = self._review(
            imported, key="substituted-crm-causation"
        )
        bridge = self._bridge(imported["policy"])
        substituted_event_id = "lf_event_substituted_causation"

        def preseed_wrong_causation():
            con = self.store.connect()
            try:
                link = con.execute(
                    """SELECT lf_opportunity_id
                       FROM source_lab_opportunity_evidence_links
                       WHERE source_record_id=?""",
                    (imported["ingest"].source_record_id,),
                ).fetchone()
                graph = bridge._load_graph(con, str(link["lf_opportunity_id"]))
                payloads = bridge._crm_payloads(
                    con,
                    graph,
                    bridge.policy.bitrix_graph_binding,
                    "fixture:existing-crm",
                )
            finally:
                con.close()
            bridge.crm_outbox.stage_graph(
                company_id=graph.lf_company_id,
                contact_id=graph.lf_contact_id,
                project_id=graph.lf_project_id,
                opportunity_id=graph.lf_opportunity_id,
                external_event_id=substituted_event_id,
                company_payload=payloads["company"],
                contact_payload=payloads["contact"],
                deal_payload=payloads["deal"],
                activity_payload=payloads["activity"],
            )

        with self.assertRaisesRegex(SourceCommercialConflict, "not exact"):
            self._bridge(
                imported["policy"], before_crm_stage=preseed_wrong_causation
            ).execute(command)
        self.assertNotEqual(substituted_event_id, approval.resolution_event_id)
        self.assertEqual(self._count("crm_outbox"), 4)
        con = self.store.connect()
        try:
            self.assertEqual(
                {
                    row[0]
                    for row in con.execute(
                        """SELECT external_event_id FROM crm_outbox
                           WHERE operation_type IN (?,?)""",
                        (DEAL_CREATE, ACTIVITY_CREATE),
                    ).fetchall()
                },
                {substituted_event_id},
            )
        finally:
            con.close()

    def test_mapping_policy_mismatch_and_stored_tamper_write_no_graph(self):
        mismatch = self._import(external_key="policy-mismatch")
        _, _, mismatch_command = self._review(mismatch, key="policy-mismatch")
        wrong = replace(mismatch["policy"], mapping_policy_hash="0" * 64)
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "contract is not approved"
        ):
            self._bridge(wrong).execute(mismatch_command)
        self.assertEqual(self._count("opportunities"), 0)

        tampered = self._import(external_key="tampered")
        _, _, tampered_command = self._review(tampered, key="tampered")
        con = self.store.connect()
        try:
            con.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            row = con.execute(
                "SELECT payload_json FROM source_lab_records WHERE source_record_id=?",
                (tampered["ingest"].source_record_id,),
            ).fetchone()
            payload = json.loads(row[0])
            payload["record"]["project_title"] = "tampered title"
            con.execute(
                "UPDATE source_lab_records SET payload_json=? WHERE source_record_id=?",
                (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")), tampered["ingest"].source_record_id),
            )
            con.execute(
                """CREATE TRIGGER trg_lf_source_lab_records_no_update
                   BEFORE UPDATE ON source_lab_records BEGIN
                       SELECT RAISE(ABORT, 'Source Lab records are immutable');
                   END"""
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaises(SourceLabIntegrityError):
            self._bridge(tampered["policy"]).execute(tampered_command)
        self.assertEqual(self._count("opportunities"), 0)

    def test_ambiguous_latest_qualification_review_is_fail_closed(self):
        imported = self._import(external_key="ambiguous-review")
        fixed = "2026-08-20T11:00:00Z"
        with patch("lead_factory.source_lab.utc_now", return_value=fixed):
            first = self.sink.request_review(
                source_record_id=imported["ingest"].source_record_id,
                reason="first",
                requested_by="reviewer",
                evidence_ref="evidence://review/ambiguous-1",
                idempotency_key="ambiguous-review-1",
            )
            second = self.sink.request_review(
                source_record_id=imported["ingest"].source_record_id,
                reason="second",
                requested_by="reviewer",
                evidence_ref="evidence://review/ambiguous-2",
                idempotency_key="ambiguous-review-2",
            )
            resolution = self._resolve_review(
                second,
                decision="APPROVE",
                reason="approved",
                resolved_by="approver",
                evidence_ref="evidence://resolution/ambiguous",
                idempotency_key="ambiguous-resolution",
            )
        command = ApprovedSourceCommand(
            imported["ingest"].source_record_id,
            imported["ingest"].observation_id,
            second.review_id,
            resolution.resolution_id,
            imported["ingest"].payload_hash,
            "commercial-bridge",
            "ambiguous-command",
        )
        with self.assertRaisesRegex(
            SourceCommercialValidationError, "latest qualification review"
        ):
            self._bridge(imported["policy"]).execute(command)
        self.assertNotEqual(first.review_id, second.review_id)
        self.assertEqual(self._count("opportunities"), 0)

    def test_partial_crm_opportunity_graph_is_not_silently_repaired(self):
        imported = self._import(external_key="partial-crm")
        _, _, command = self._review(imported, key="partial-crm")
        bridge = self._bridge(imported["policy"])
        bridge.execute(command)
        con = self.store.connect()
        try:
            con.execute(
                "DELETE FROM crm_outbox WHERE operation_type=?", (ACTIVITY_CREATE,)
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaisesRegex(SourceCommercialConflict, "partially staged"):
            bridge.execute(command)
        con = self.store.connect()
        try:
            present = {
                row[0]
                for row in con.execute(
                    "SELECT operation_type FROM crm_outbox WHERE lf_entity_type='opportunity'"
                ).fetchall()
            }
        finally:
            con.close()
        self.assertIn(DEAL_CREATE, present)
        self.assertNotIn(ACTIVITY_CREATE, present)


if __name__ == "__main__":
    unittest.main()
