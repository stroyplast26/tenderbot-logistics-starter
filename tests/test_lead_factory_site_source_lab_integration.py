import tempfile
import unittest
from dataclasses import replace
import hashlib
from pathlib import Path

from lead_factory.site_ingress import (
    ConsentEvidence,
    ConsentPurpose,
    FormSubmission,
    SiteAttribution,
    SiteIngress,
    SiteIngressConflict,
    TrustedConsentRule,
    TrustedSitePolicy,
    UtmSet,
)
from lead_factory.source_lab import SourceLabSink
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore


class SiteSourceLabIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "site-source-lab.sqlite3")
        self.sink = SourceLabSink(self.store)
        consent_text = "Согласен на обработку переданных персональных данных."
        policy = TrustedSitePolicy(
            policy_id="alumkomplekt-site-policy",
            policy_version="2026-08-20-v1",
            source_id="alumkomplekt-site",
            evidence_ref="evidence://site-policy/alumkomplekt/2026-08-20-v1",
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
                    text_sha256=hashlib.sha256(
                        consent_text.encode("utf-8")
                    ).hexdigest(),
                ),
            ),
        )
        self.ingress = SiteIngress(
            self.sink,
            source_id="alumkomplekt-site",
            policy=policy,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def submission() -> FormSubmission:
        landing = "https://alum.example/b2b"
        return FormSubmission(
            submission_id="site-submission-001",
            submitted_at_utc="2026-08-19T08:59:00Z",
            company_name="ООО Фасад",
            applicant_role="закупщик",
            city_or_region="Москва",
            object_or_recurring_need="фасад строящегося объекта",
            product_or_system="алюминиевый профиль",
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
                text="Согласен на обработку переданных персональных данных.",
                text_version="privacy-v1",
                occurred_at_utc="2026-08-19T08:58:59Z",
                source="site-checkbox",
                page_url=landing,
                evidence_ref="evidence://site/consent/site-submission-001",
            ),
            evidence_ref="evidence://site/form/site-submission-001",
            phone="+7 (999) 123-45-67",
            email="BUYER@EXAMPLE.COM",
            original_utm=UtmSet("yandex", "cpc", "facades", "ad-1", "profile"),
            latest_utm=UtmSet("yandex", "cpc", "facades", "ad-2", "profile-buy"),
            yclid="1234567890",
        )

    def test_site_replay_and_contact_identity_are_exact_in_source_lab(self) -> None:
        submission = self.submission()

        first = self.ingress.ingest(submission)
        replay = self.ingress.ingest(
            submission, observed_at_utc="2026-08-19T09:01:00Z"
        )

        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.sink_result.source_record_id, replay.sink_result.source_record_id)
        self.assertEqual(self.store.schema_version(), CURRENT_SCHEMA_VERSION)
        records = self.sink.records_for_canonical_key("email:buyer@example.com")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source_id"], "alumkomplekt-site")
        self.assertEqual(
            {row["source_record_id"] for row in self.sink.records_for_canonical_key(
                "phone:+79991234567"
            )},
            {first.sink_result.source_record_id},
        )
        status = self.store.status()
        self.assertFalse(status["external_writers_enabled"])
        self.assertFalse(status["external_source_reads_enabled"])
        self.assertEqual(status["crm_outbox"], 0)

    def test_same_submission_identity_with_changed_facts_fails_closed(self) -> None:
        submission = self.submission()
        self.ingress.ingest(submission)

        with self.assertRaises(SiteIngressConflict):
            self.ingress.ingest(replace(submission, estimated_volume="2400 пог. м"))

        self.assertEqual(self.store.table_count("source_lab_record_observations"), 1)
        self.assertEqual(self.store.table_count("source_lab_records"), 1)


if __name__ == "__main__":
    unittest.main()
