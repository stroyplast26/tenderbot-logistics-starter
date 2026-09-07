from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac
import tempfile
import unittest

from lead_factory.site_delivery_intake import encode_site_delivery_submission
from lead_factory.site_delivery_runtime import (
    ALUMKOMPLEKT_SITE_SOURCE_ID,
    SiteDeliveryEndpoint,
    SiteDeliveryRuntimeConfig,
    alumkomplekt_rfq_policy,
    config_from_environ,
    signature_payload,
)
from lead_factory.site_ingress import ConsentEvidence, FormSubmission, SiteAttribution, UtmSet
from lead_factory.store import FactoryStore


SECRET = "s" * 32


def _submission() -> FormSubmission:
    landing_url = "https://alumkomplekt-rf.ru/rfq/"
    consent = ConsentEvidence(
        purpose="PERSONAL_DATA_PROCESSING",
        granted=True,
        text=(
            "Я согласен(-на) на обработку персональных данных и принимаю условия "
            "Политики обработки персональных данных."
        ),
        text_version="rfq-privacy-2026-08-24-v1",
        occurred_at_utc="2026-08-24T09:59:00Z",
        source="rfq-personal-data-checkbox",
        page_url=landing_url,
        evidence_ref="evidence://site/consent/site-001",
    )
    return FormSubmission(
        submission_id="site-001",
        submitted_at_utc="2026-08-24T10:00:00Z",
        company_name="ООО Тест",
        applicant_role="Закупки",
        city_or_region="Ставрополь",
        object_or_recurring_need="Запрос предварительного расчёта",
        product_or_system="Фасады и витражи",
        estimated_volume="Не указан",
        purchase_stage="Новый запрос",
        supplier_selection_open=True,
        required_delivery_or_quote_date="2026-08-25",
        specification_status="Не приложено",
        landing_url=landing_url,
        landing_version="rfq-2026-08-24-v1",
        offer_version="rfq-estimate-1bd-v1",
        form_id="rfq-form",
        form_version="rfq-form-2026-08-24-v1",
        attribution=SiteAttribution.SITE_DIRECT,
        personal_data_consent=consent,
        evidence_ref="evidence://site/raw/site-001",
        email="buyer@example.test",
        original_utm=UtmSet(),
        latest_utm=UtmSet(),
        attachment_summary="0 attachments",
    )


class SiteDeliveryRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(f"{self.temp.name}/stage.sqlite3")
        self.store.init()
        self.config = SiteDeliveryRuntimeConfig(shared_secret=SECRET, enabled=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _headers(self, body: bytes, *, delivery_id: str = "delivery-001") -> dict[str, str]:
        received_at = "2026-08-24T10:00:00Z"
        digest = hashlib.sha256(body).hexdigest()
        evidence_ref = f"evidence://site/delivery/{delivery_id}"
        signature = hmac.new(
            SECRET.encode(),
            signature_payload(
                delivery_id=delivery_id,
                source_id=ALUMKOMPLEKT_SITE_SOURCE_ID,
                received_at_utc=received_at,
                body_sha256=digest,
                evidence_ref=evidence_ref,
            ),
            hashlib.sha256,
        ).hexdigest()
        return {
            "x-lf-delivery-id": delivery_id,
            "x-lf-source-id": ALUMKOMPLEKT_SITE_SOURCE_ID,
            "x-lf-received-at": received_at,
            "x-lf-body-sha256": digest,
            "x-lf-evidence-ref": evidence_ref,
            "x-lf-signature": "sha256=" + signature,
        }

    def test_signed_delivery_creates_local_review_chain(self) -> None:
        body = encode_site_delivery_submission(_submission())
        result = SiteDeliveryEndpoint(self.store, self.config).handle(
            self._headers(body), body
        )
        self.assertEqual(result.status_code, 202)
        self.assertEqual(result.payload["state"], "ACCEPTED")
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute("SELECT COUNT(*) FROM source_lab_records").fetchone()[0], 1
            )
            self.assertEqual(
                con.execute("SELECT COUNT(*) FROM human_tasks").fetchone()[0], 1
            )
        finally:
            con.close()

    def test_invalid_signature_never_creates_event(self) -> None:
        body = encode_site_delivery_submission(_submission())
        headers = self._headers(body)
        headers["x-lf-signature"] = "sha256=" + "0" * 64
        result = SiteDeliveryEndpoint(self.store, self.config).handle(headers, body)
        self.assertEqual(result.status_code, 401)
        con = self.store.connect()
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        finally:
            con.close()

    def test_http_header_case_is_not_part_of_the_protocol(self) -> None:
        body = encode_site_delivery_submission(_submission())
        headers = {key.title(): value for key, value in self._headers(body).items()}
        result = SiteDeliveryEndpoint(self.store, self.config).handle(headers, body)
        self.assertEqual(result.status_code, 202)

    def test_switch_is_fail_closed(self) -> None:
        body = encode_site_delivery_submission(_submission())
        result = SiteDeliveryEndpoint(
            self.store, replace(self.config, enabled=False)
        ).handle(self._headers(body), body)
        self.assertEqual(result.status_code, 503)

    def test_policy_is_bound_to_deployed_form(self) -> None:
        policy = alumkomplekt_rfq_policy()
        self.assertEqual(policy.source_id, ALUMKOMPLEKT_SITE_SOURCE_ID)
        self.assertIn(
            ("rfq-form", "rfq-form-2026-08-24-v1"), policy.allowed_form_versions
        )

    def test_environment_never_reuses_legacy_keys(self) -> None:
        config = config_from_environ(
            {
                "LEAD_FACTORY_SITE_INGRESS_SECRET": SECRET,
                "LEAD_FACTORY_SITE_INGRESS_ENABLED": "1",
                "UNISENDER_GO_API_KEY": "legacy-value-must-be-ignored",
                "OPENROUTER_KEY": "legacy-value-must-be-ignored",
            }
        )
        self.assertTrue(config.enabled)
        self.assertEqual(config.source_id, ALUMKOMPLEKT_SITE_SOURCE_ID)
