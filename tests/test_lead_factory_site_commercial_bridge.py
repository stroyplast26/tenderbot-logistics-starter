from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from lead_factory.site_commercial_bridge import (
    ApprovedSiteCommand,
    SITE_APPROVAL_CAPABILITY_VERSION,
    SITE_APPROVAL_RECEIPT_VERSION,
    SiteCommercialBridge,
    SiteCommercialConflict,
    SiteCommercialPolicy,
    SiteCommercialValidationError,
    SiteOpportunityProjection,
    TrustedSiteApprovalReceipt,
    TrustedSiteApprovalRequest,
)
from lead_factory.crm_graph_outbox import CrmGraphOutbox, GraphInvariantError
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
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.reviewed_opportunity_bridge import ReviewedOpportunityBridge
from lead_factory.site_ingress import (
    ConsentEvidence,
    ConsentPurpose,
    FormSubmission,
    SiteAttribution,
    SiteIngress,
    TrustedConsentRule,
    TrustedSitePolicy,
    UtmSet,
)
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_review_queue import SourceReviewQueue
from lead_factory.store import FactoryStore


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
CONSENT_TEXT = "Согласен на обработку переданных персональных данных."


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
        ("activity", "DEADLINE"), ("activity", "DESCRIPTION"),
        ("activity", "SUBJECT"), ("company", "TITLE"),
        ("company", "UF_CRM_LF_COMPANY_ID"), ("company", "UF_CRM_LF_INN"),
        ("contact", "EMAIL"), ("contact", "NAME"), ("contact", "PHONE"),
        ("contact", "POST"), ("contact", "UF_CRM_LF_CONTACT_ID"),
        ("deal", "TITLE"), ("deal", "UF_CRM_LF_OPPORTUNITY_ID"),
        ("deal", "UF_CRM_LF_PROJECT_ID"), ("deal", "UF_CRM_LF_PRODUCT_KEY"),
        ("deal", "UF_CRM_LF_SOURCE_EVENT_ID"), ("deal", "UF_CRM_LF_SOURCE_ID"),
        ("deal", "UF_CRM_LF_SOURCE_RECORD_ID"), ("deal", "UF_CRM_LF_SUBMISSION_ID"),
        ("deal", "UF_CRM_LF_CORRELATION_ID"), ("deal", "UF_CRM_LF_ATTRIBUTION"),
        ("deal", "UF_CRM_LF_SITE_POLICY_ID"), ("deal", "UF_CRM_LF_SITE_POLICY_VERSION"),
        ("deal", "UF_CRM_LF_SITE_POLICY_HASH"), ("deal", "UF_CRM_LF_LANDING_URL"),
        ("deal", "UF_CRM_LF_LANDING_VERSION"), ("deal", "UF_CRM_LF_OFFER_VERSION"),
        ("deal", "UF_CRM_LF_FORM_ID"), ("deal", "UF_CRM_LF_FORM_VERSION"),
        ("deal", "UF_CRM_LF_ORIGINAL_UTM_SOURCE"), ("deal", "UF_CRM_LF_ORIGINAL_UTM_MEDIUM"),
        ("deal", "UF_CRM_LF_ORIGINAL_UTM_CAMPAIGN"), ("deal", "UF_CRM_LF_ORIGINAL_UTM_CONTENT"),
        ("deal", "UF_CRM_LF_ORIGINAL_UTM_TERM"), ("deal", "UF_CRM_LF_LATEST_UTM_SOURCE"),
        ("deal", "UF_CRM_LF_LATEST_UTM_MEDIUM"), ("deal", "UF_CRM_LF_LATEST_UTM_CAMPAIGN"),
        ("deal", "UF_CRM_LF_LATEST_UTM_CONTENT"), ("deal", "UF_CRM_LF_LATEST_UTM_TERM"),
        ("deal", "UF_CRM_LF_YCLID"), ("deal", "UF_CRM_LF_AD_CLICK_ID"),
        ("deal", "UF_CRM_LF_CONSENT_VERSION"), ("deal", "UF_CRM_LF_CONSENT_HASH"),
        ("deal", "UF_CRM_LF_IDENTITY_POLICY_VERSION"),
    }
    raw = BitrixGraphMappingManifest(
        GRAPH_MAPPING_MANIFEST_VERSION, "fixture:union-graph", "1", GRAPH_CONTRACT_VERSION,
        GRAPH_INPUT_CONTRACT_VERSION, GRAPH_MAPPING_LIFECYCLE, GRAPH_MAPPING_EVIDENCE_MODE,
        "bitrix-host-v1:" + "a" * 64,
        tuple(BitrixGraphFieldBinding(entity, key, fixed.get((entity, key), key)) for entity, key in sorted(keys)),
        (BitrixGraphCorrelationField("company", "UF_CRM_LF_CORRELATION_COMPANY"),
         BitrixGraphCorrelationField("contact", "UF_CRM_LF_CORRELATION_CONTACT"),
         BitrixGraphCorrelationField("deal", "UF_CRM_LF_CORRELATION_DEAL")),
        (BitrixGraphSourceBinding(source_id, "LF_SITE"),),
        BitrixGraphRoute("7", "C7:NEW", "10", "11"),
        GRAPH_ACTIVITY_MARKER_VERSION,
    )
    manifest = replace(raw, declared_manifest_hash=graph_mapping_manifest_hash(raw))
    return BitrixGraphBridgeBinding(manifest, source_id, "2026-08-21T10:00:00Z")


def site_policy(**changes) -> TrustedSitePolicy:
    policy = TrustedSitePolicy(
        policy_id="alumkomplekt-site-policy",
        policy_version="2026-08-20-v1",
        source_id="alumkomplekt-site",
        evidence_ref="evidence://site-policy/alumkomplekt/v1",
        allowed_origins=("https://alum.example",),
        allowed_landing_paths=("/b2b",),
        allowed_form_versions=(("b2b-demand", "form-v1"),),
        allowed_landing_versions=("landing-v1",),
        allowed_offer_versions=("offer-v1",),
        allowed_consent_sources=("site-checkbox",),
        consent_rules=(
            TrustedConsentRule(
                purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
                source="site-checkbox",
                text_version="privacy-v1",
                text_sha256=hashlib.sha256(CONSENT_TEXT.encode("utf-8")).hexdigest(),
            ),
        ),
    )
    return replace(policy, **changes)


def submission(**changes) -> FormSubmission:
    landing = "https://alum.example/b2b"
    form = FormSubmission(
        submission_id="site-submission-001",
        submitted_at_utc="2026-08-20T10:00:00Z",
        company_name="ООО Фасад",
        applicant_role="закупщик",
        city_or_region="Москва",
        object_or_recurring_need="Фасад строящегося объекта",
        product_or_system="ALUMINIUM_PROFILE",
        estimated_volume="1200 пог. м",
        purchase_stage="собираем предложения",
        supplier_selection_open=True,
        required_delivery_or_quote_date="2026-09-05",
        specification_status="спецификация готова",
        landing_url=landing,
        landing_version="landing-v1",
        offer_version="offer-v1",
        form_id="b2b-demand",
        form_version="form-v1",
        attribution=SiteAttribution.SITE_PAID,
        personal_data_consent=ConsentEvidence(
            purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
            granted=True,
            text=CONSENT_TEXT,
            text_version="privacy-v1",
            occurred_at_utc="2026-08-20T09:59:59Z",
            source="site-checkbox",
            page_url=landing,
            evidence_ref="evidence://site/consent/submission-001",
        ),
        evidence_ref="evidence://site/form/submission-001",
        phone="+7 (999) 123-45-67",
        email="BUYER@EXAMPLE.COM",
        original_utm=UtmSet("yandex", "cpc", "facades", "ad-1", "profile"),
        latest_utm=UtmSet("yandex", "cpc", "facades", "ad-2", "buy"),
        yclid="1234567890",
    )
    return replace(form, **changes)


class ExactSiteAuthority:
    capability_version = SITE_APPROVAL_CAPABILITY_VERSION

    def __init__(self, mode: str = "exact") -> None:
        self.mode = mode
        self.calls: list[TrustedSiteApprovalRequest] = []

    def verify_approval(self, request: TrustedSiteApprovalRequest):
        self.calls.append(request)
        if self.mode == "error":
            raise RuntimeError("PRIVATE-AUTHORITY-DATA")
        bound = request
        if self.mode == "mismatch":
            bound = replace(request, observation_id="different-observation")
        return TrustedSiteApprovalReceipt(
            capability_version=SITE_APPROVAL_CAPABILITY_VERSION,
            receipt_version=SITE_APPROVAL_RECEIPT_VERSION,
            authority_id="offline-site-authority",
            receipt_id=f"site-receipt-{bound.request_hash[:32]}",
            request=bound,
            request_hash=bound.request_hash,
        )


class FailAfterGraphOutbox(CrmGraphOutbox):
    def stage_graph(self, **kwargs):
        super().stage_graph(**kwargs)
        raise GraphInvariantError("fixture failure after all four commands")


class SiteCommercialBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "site-commercial.sqlite3")
        self.store.init()
        self.sink = SourceLabSink(self.store, clock=lambda: NOW)
        self.trusted_policy = site_policy()
        self.ingress = SiteIngress(
            self.sink,
            source_id="alumkomplekt-site",
            policy=self.trusted_policy,
            clock=lambda: NOW,
        )
        self.authority = ExactSiteAuthority()
        self.policy = SiteCommercialPolicy(
            policy_id="site-commercial-alumkomplekt",
            policy_version="1",
            source_id="alumkomplekt-site",
            identity_policy_version="inn-email-v1",
            trusted_site_policy=self.trusted_policy,
            bitrix_graph_binding=graph_binding("alumkomplekt-site"),
        )
        self.sequence = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _resolve_review(
        self,
        review_id: str,
        *,
        decision: str,
        key: str,
        resolved_by: str = "approver",
    ):
        queue = SourceReviewQueue(
            self.store,
            clock=lambda: datetime.now(timezone.utc),
        )
        item = next(
            item for item in queue.list_open(limit=100).items
            if item.review_id == review_id
        )
        permit = queue.claim(
            review_id=review_id,
            claimant=resolved_by,
            evidence_ref=f"evidence://site/claim/{key}",
            idempotency_key=f"site-claim-{key}",
            expected_state_digest=item.state_digest,
        )
        return queue.resolve_claimed(
            permit,
            decision=decision,
            reason="reviewed",
            evidence_ref=f"evidence://site/resolution/{key}",
            idempotency_key=f"site-resolution-{key}",
        )

    def _approved_command(
        self,
        *,
        form: FormSubmission | None = None,
        decision: str = "APPROVE",
        company_inn: str = "7707083893",
        contact_email: str | None = None,
        suffix: str = "",
    ):
        self.sequence += 1
        key = suffix or str(self.sequence)
        actual_form = form or submission(
            submission_id=f"site-submission-{self.sequence:03d}",
            evidence_ref=f"evidence://site/form/submission-{self.sequence:03d}",
            personal_data_consent=replace(
                submission().personal_data_consent,
                evidence_ref=f"evidence://site/consent/submission-{self.sequence:03d}",
            ),
        )
        ingested = self.ingress.ingest(actual_form)
        review = self.sink.request_review(
            source_record_id=ingested.sink_result.source_record_id,
            reason="commercial qualification",
            requested_by="reviewer",
            evidence_ref=f"evidence://site/review/{key}",
            idempotency_key=f"site-review-{key}",
        )
        resolution = self._resolve_review(
            review.review_id,
            decision=decision,
            key=key,
        )
        command = ApprovedSiteCommand(
            source_record_id=ingested.sink_result.source_record_id,
            observation_id=ingested.sink_result.observation_id,
            review_id=review.review_id,
            latest_resolution_id=resolution.resolution_id,
            expected_payload_hash=ingested.sink_result.payload_hash,
            projection=SiteOpportunityProjection(
                company_inn=company_inn,
                contact_email=(
                    actual_form.email if contact_email is None else contact_email
                ),
                identity_evidence_ref=f"evidence://identity/{key}",
            ),
            actor="site-commercial-bridge",
            idempotency_key=f"site-commercial-{key}",
        )
        return ingested, review, resolution, command

    def _bridge(self, **kwargs) -> SiteCommercialBridge:
        return SiteCommercialBridge(
            self.store,
            policy=kwargs.pop("policy", self.policy),
            approval_authority=kwargs.pop("authority", self.authority),
            **kwargs,
        )

    def _commercial_counts(self):
        return {
            table: self.store.table_count(table)
            for table in (
                "source_records",
                "companies",
                "contacts",
                "projects",
                "opportunities",
                "source_lab_opportunity_evidence_links",
                "crm_outbox",
            )
        }

    def _rewrite_anchor(self, assignments: str, parameters: tuple) -> None:
        with self.store.transaction() as con:
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            con.execute(
                f"""UPDATE events SET {assignments}
                    WHERE producer='reviewed_opportunity_bridge'
                      AND event_type='reviewed_opportunity_staged'""",
                parameters,
            )
            con.execute(
                """CREATE TRIGGER trg_lf_events_no_update
                   BEFORE UPDATE ON events BEGIN
                       SELECT RAISE(ABORT, 'lead factory events are append-only');
                   END"""
            )

    def test_approved_site_stages_atomic_graph_and_exact_replay_writes_zero(self) -> None:
        _ingested, _review, resolution, command = self._approved_command()
        bridge = self._bridge()

        first = bridge.execute(command)
        replay = bridge.execute(command)

        self.assertEqual(first.state, "STAGED")
        self.assertTrue(first.staged.graph.created)
        self.assertTrue(first.staged.evidence_link.created)
        self.assertTrue(first.staged.anchor_created)
        self.assertEqual(len(first.crm_stage.created_operation_ids), 4)
        self.assertEqual(replay.state, "STAGED")
        self.assertFalse(replay.staged.graph.created)
        self.assertFalse(replay.staged.evidence_link.created)
        self.assertFalse(replay.staged.anchor_created)
        self.assertEqual(replay.crm_stage.created_operation_ids, ())
        self.assertEqual(self._commercial_counts(), {
            "source_records": 1,
            "companies": 1,
            "contacts": 1,
            "projects": 1,
            "opportunities": 1,
            "source_lab_opportunity_evidence_links": 1,
            "crm_outbox": 4,
        })
        status = self.store.status()
        self.assertFalse(status["external_writers_enabled"])
        with self.store.transaction() as con:
            anchors = con.execute(
                """SELECT * FROM events
                   WHERE producer='reviewed_opportunity_bridge'"""
            ).fetchall()
            self.assertEqual(len(anchors), 1)
            self.assertEqual(str(anchors[0]["causation_id"]), resolution.event_id)
            approval_event = con.execute(
                "SELECT occurred_at_utc FROM events WHERE event_id=?",
                (resolution.event_id,),
            ).fetchone()
            self.assertEqual(
                (
                    str(anchors[0]["occurred_at_utc"]),
                    str(anchors[0]["recorded_at_utc"]),
                ),
                (str(approval_event[0]), str(approval_event[0])),
            )
            deal = con.execute(
                "SELECT payload_json FROM crm_outbox WHERE operation_type='BITRIX_DEAL_CREATE'"
            ).fetchone()
            activity = con.execute(
                "SELECT payload_json FROM crm_outbox WHERE operation_type='BITRIX_DEAL_ACTIVITY_CREATE'"
            ).fetchone()
        payload = json.loads(deal[0])
        self.assertEqual(payload["UF_CRM_LF_ATTRIBUTION"], "SITE_PAID")
        self.assertEqual(payload["UF_CRM_LF_ORIGINAL_UTM_SOURCE"], "yandex")
        self.assertEqual(payload["UF_CRM_LF_SUBMISSION_ID"], "site-submission-001")
        self.assertEqual(
            payload["_lf_graph_v1"]["mapping_manifest_hash"],
            bridge._mapping_manifest_hash,
        )
        self.assertEqual(payload["_lf_graph_v1"]["lf_source_id"], "alumkomplekt-site")
        self.assertEqual(
            json.loads(activity[0])["DEADLINE"], "2026-08-21T10:00:00Z"
        )

    def test_missing_inn_and_phone_only_remain_review_with_zero_writes(self) -> None:
        _a, _b, _c, no_inn = self._approved_command(company_inn="", suffix="no-inn")
        result = self._bridge().execute(no_inn)
        self.assertEqual((result.state, result.reason), ("REVIEW", "EXACT_COMPANY_IDENTITY_REQUIRED"))
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

        phone_form = submission(
            submission_id="site-phone-only",
            email="",
            evidence_ref="evidence://site/form/phone-only",
            personal_data_consent=replace(
                submission().personal_data_consent,
                evidence_ref="evidence://site/consent/phone-only",
            ),
        )
        _a, _b, _c, phone_only = self._approved_command(
            form=phone_form,
            company_inn="7707083893",
            contact_email="",
            suffix="phone-only",
        )
        result = self._bridge().execute(phone_only)
        self.assertEqual((result.state, result.reason), ("REVIEW", "CONTACT_EMAIL_REQUIRED"))
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

    def test_text_wrapped_inn_never_becomes_an_exact_company_match(self) -> None:
        _a, _b, _c, wrapped = self._approved_command(
            company_inn="ATTACK-7707083893-WRAPPER",
            suffix="wrapped-inn",
        )

        result = self._bridge().execute(wrapped)

        self.assertEqual(
            (result.state, result.reason),
            ("REVIEW", "EXACT_COMPANY_IDENTITY_REQUIRED"),
        )
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

    def test_hold_payload_policy_and_identity_mismatch_write_nothing(self) -> None:
        _a, _b, _c, hold = self._approved_command(decision="HOLD", suffix="hold")
        with self.assertRaisesRegex(
            SiteCommercialValidationError, "not APPROVE"
        ):
            self._bridge().execute(hold)
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

        _a, _b, _c, command = self._approved_command(suffix="payload")
        with self.assertRaisesRegex(SiteCommercialValidationError, "policy binding"):
            self._bridge().execute(replace(command, expected_payload_hash="0" * 64))
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

        wrong_policy = replace(
            self.policy,
            trusted_site_policy=site_policy(policy_version="2026-08-20-v2"),
        )
        with self.assertRaisesRegex(SiteCommercialValidationError, "site policy binding"):
            self._bridge(policy=wrong_policy).execute(command)
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

        with self.assertRaisesRegex(SiteCommercialConflict, "contact identity"):
            self._bridge().execute(
                replace(
                    command,
                    projection=replace(
                        command.projection, contact_email="other@example.com"
                    ),
                )
            )
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

    def test_superseded_after_authority_and_mismatched_receipt_write_nothing(self) -> None:
        _a, review, approval, command = self._approved_command(suffix="supersede")

        def supersede() -> None:
            newer = self.sink.request_review(
                source_record_id=command.source_record_id,
                reason="withdrawn approval requires a new qualification",
                requested_by="reviewer",
                evidence_ref="evidence://site/review/superseding",
                idempotency_key="site-review-superseding",
            )
            self._resolve_review(
                newer.review_id,
                decision="HOLD",
                key="superseding",
            )

        with self.assertRaisesRegex(
            SiteCommercialValidationError, "latest site qualification review|not APPROVE"
        ):
            self._bridge(before_transaction=supersede).execute(command)
        self.assertEqual(len(self.authority.calls), 1)
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))

    def test_crm_stage_failure_rolls_back_graph_link_anchor_and_all_commands(self) -> None:
        _a, _b, _c, command = self._approved_command(suffix="rollback")
        reviewed = ReviewedOpportunityBridge(
            self.store,
            crm_outbox=FailAfterGraphOutbox(self.store),
        )

        with self.assertRaisesRegex(SiteCommercialConflict, "transaction was rejected"):
            self._bridge(reviewed_bridge=reviewed).execute(command)

        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))
        with self.store.transaction() as con:
            anchors = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE producer='reviewed_opportunity_bridge'"""
            ).fetchone()[0]
        self.assertEqual(anchors, 0)

    def test_coordinated_anchor_payload_and_hash_rewrite_is_never_accepted(self) -> None:
        _a, _b, _c, command = self._approved_command(suffix="anchor-payload")
        bridge = self._bridge()
        bridge.execute(command)
        before = self._commercial_counts()
        with self.store.transaction() as con:
            row = con.execute(
                """SELECT payload_json FROM events
                   WHERE producer='reviewed_opportunity_bridge'
                     AND event_type='reviewed_opportunity_staged'"""
            ).fetchone()
        payload = json.loads(row[0])
        payload["commercial_policy_hash"] = "0" * 64
        self._rewrite_anchor(
            "payload_json=?,payload_hash=?",
            (canonical_json(payload), payload_hash(payload)),
        )

        for _ in range(2):
            with self.assertRaisesRegex(
                SiteCommercialConflict, "transaction was rejected"
            ):
                bridge.execute(command)
            self.assertEqual(self._commercial_counts(), before)
        with self.store.transaction() as con:
            persisted = con.execute(
                """SELECT payload_json FROM events
                   WHERE producer='reviewed_opportunity_bridge'"""
            ).fetchone()
        self.assertEqual(
            json.loads(persisted[0])["commercial_policy_hash"], "0" * 64
        )

    def test_coordinated_anchor_metadata_rewrite_cannot_hide_old_anchor(self) -> None:
        _a, _b, _c, command = self._approved_command(suffix="anchor-metadata")
        bridge = self._bridge()
        bridge.execute(command)
        before_counts = self._commercial_counts()
        before_events = self.store.table_count("events")
        self._rewrite_anchor(
            """event_type=?,aggregate_type=?,aggregate_id=?,producer=?,
               schema_version=?,actor=?,correlation_id=?,causation_id=?,
               idempotency_key=?,evidence_ref=?,occurred_at_utc=?,recorded_at_utc=?""",
            (
                "attacker_event",
                "attacker_aggregate",
                "attacker-id",
                "attacker-fixture",
                1,
                "attacker",
                "attacker-correlation",
                "attacker-causation",
                "attacker-anchor-key",
                "evidence://attacker/anchor",
                "2026-08-20T09:00:00Z",
                "2026-08-20T09:00:01Z",
            ),
        )

        for _ in range(2):
            with self.assertRaisesRegex(
                SiteCommercialConflict, "transaction was rejected"
            ):
                bridge.execute(command)
            self.assertEqual(self._commercial_counts(), before_counts)
            self.assertEqual(self.store.table_count("events"), before_events)
        with self.store.transaction() as con:
            expected = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE producer='reviewed_opportunity_bridge'
                     AND event_type='reviewed_opportunity_staged'"""
            ).fetchone()[0]
            persisted = con.execute(
                "SELECT COUNT(*) FROM events WHERE producer='attacker-fixture'"
            ).fetchone()[0]
        self.assertEqual(expected, 0)
        self.assertEqual(persisted, 1)

    def test_anchor_metadata_envelope_is_revalidated_before_crm_replay(self) -> None:
        _a, _b, _c, command = self._approved_command(suffix="anchor-envelope")
        bridge = self._bridge()
        bridge.execute(command)
        before_counts = self._commercial_counts()
        before_events = self.store.table_count("events")
        self._rewrite_anchor(
            """schema_version=?,actor=?,correlation_id=?,causation_id=?,
               evidence_ref=?,occurred_at_utc=?,recorded_at_utc=?""",
            (
                16,
                "different-actor",
                "different-correlation",
                "different-causation",
                "evidence://different/anchor",
                "2026-08-20T09:00:00Z",
                "2026-08-20T09:00:01Z",
            ),
        )

        with self.assertRaisesRegex(
            SiteCommercialConflict, "transaction was rejected"
        ):
            bridge.execute(command)
        self.assertEqual(self._commercial_counts(), before_counts)
        self.assertEqual(self.store.table_count("events"), before_events)

    def test_equal_timestamp_only_rewrite_is_rejected_by_independent_binding(self) -> None:
        _a, _b, _c, command = self._approved_command(suffix="anchor-timestamp")
        bridge = self._bridge()
        bridge.execute(command)
        before_counts = self._commercial_counts()
        before_events = self.store.table_count("events")
        rewritten = "2026-08-20T08:00:00Z"
        self._rewrite_anchor(
            "occurred_at_utc=?,recorded_at_utc=?",
            (rewritten, rewritten),
        )

        for _ in range(2):
            with self.assertRaisesRegex(
                SiteCommercialConflict, "transaction was rejected"
            ):
                bridge.execute(command)
            self.assertEqual(self._commercial_counts(), before_counts)
            self.assertEqual(self.store.table_count("events"), before_events)
        with self.store.transaction() as con:
            persisted = con.execute(
                """SELECT occurred_at_utc,recorded_at_utc FROM events
                   WHERE producer='reviewed_opportunity_bridge'"""
            ).fetchone()
        self.assertEqual((persisted[0], persisted[1]), (rewritten, rewritten))

    def test_second_persisted_anchor_is_rejected_before_crm_replay(self) -> None:
        _a, _b, _c, command = self._approved_command(suffix="anchor-duplicate")
        bridge = self._bridge()
        result = bridge.execute(command)
        before_counts = self._commercial_counts()
        with self.store.transaction() as con:
            row = con.execute(
                """SELECT * FROM events
                   WHERE producer='reviewed_opportunity_bridge'
                     AND event_type='reviewed_opportunity_staged'"""
            ).fetchone()
            self.store._append_event_tx(
                con,
                event_type="reviewed_opportunity_staged",
                aggregate_type="opportunity",
                aggregate_id=result.lf_opportunity_id,
                producer="attacker-fixture",
                idempotency_key="attacker-duplicate-reviewed-anchor",
                payload=json.loads(row["payload_json"]),
                evidence_ref=str(row["evidence_ref"]),
                actor=str(row["actor"]),
                causation_id=str(row["causation_id"]),
                schema_version=int(row["schema_version"]),
            )
        before_events = self.store.table_count("events")

        with self.assertRaisesRegex(SiteCommercialConflict, "transaction was rejected"):
            bridge.execute(command)
        self.assertEqual(self._commercial_counts(), before_counts)
        self.assertEqual(self.store.table_count("events"), before_events)

    def test_mismatched_typed_receipt_writes_nothing(self) -> None:
        _a, _b, _c, fresh = self._approved_command(suffix="receipt")
        with self.assertRaisesRegex(
            SiteCommercialValidationError, "receipt is invalid"
        ):
            self._bridge(authority=ExactSiteAuthority("mismatch")).execute(fresh)
        self.assertTrue(all(value == 0 for value in self._commercial_counts().values()))


if __name__ == "__main__":
    unittest.main()
