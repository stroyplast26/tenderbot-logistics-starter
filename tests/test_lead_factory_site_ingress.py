import logging
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import unittest

from lead_factory.ids import payload_hash
from lead_factory.site_ingress import (
    ConsentEvidence,
    ConsentPurpose,
    FormSubmission,
    SiteAttribution,
    SiteIngress,
    SiteIngressConflict,
    SiteIngressError,
    SiteValidationError,
    TrustedConsentRule,
    TrustedSitePolicy,
    UtmSet,
    ingest_site_submission,
)


SUBMITTED_AT = "2026-08-19T09:00:00Z"
OBSERVED_AT = "2026-08-19T09:00:03Z"
LANDING_URL = "https://alum.example/b2b?product=facade"
PERSONAL_CONSENT_TEXT = (
    "Согласен на обработку персональных данных для ответа на заявку."
)
MARKETING_CONSENT_TEXT = "Согласен получать маркетинговые сообщения компании."


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def trusted_policy(**changes):
    base = TrustedSitePolicy(
        policy_id="alumkomplekt-site-policy",
        policy_version="2026-08-20-v1",
        source_id="alumkomplekt-site",
        evidence_ref="evidence://site-policy/alumkomplekt/2026-08-20-v1",
        allowed_origins=("https://alum.example",),
        allowed_landing_paths=("/b2b",),
        allowed_form_versions=(("hot-b2b-order", "form-v5"),),
        allowed_landing_versions=("landing-v4",),
        allowed_offer_versions=("offer-v2",),
        allowed_consent_sources=("b2b-form-checkbox",),
        consent_rules=(
            TrustedConsentRule(
                purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
                source="b2b-form-checkbox",
                text_version="privacy-v3",
                text_sha256=sha256_text(PERSONAL_CONSENT_TEXT),
            ),
            TrustedConsentRule(
                purpose=ConsentPurpose.MARKETING_COMMUNICATION,
                source="b2b-form-checkbox",
                text_version="marketing-v2",
                text_sha256=sha256_text(MARKETING_CONSENT_TEXT),
            ),
        ),
        allowed_landing_query_keys=(
            "product",
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_content",
            "utm_term",
            "yclid",
            "ad_click_id",
        ),
        allowed_referrer_origins=(
            "https://yandex.ru",
            "https://partner.example",
        ),
        allowed_referrer_paths=("/search/", "/catalog"),
        allowed_referrer_query_keys=("text",),
    )
    return replace(base, **changes)


class ImmutableSinkConflict(RuntimeError):
    pass


class RecordingSink:
    """Small contract fixture with sink-owned idempotency semantics."""

    def __init__(self):
        self.calls = []
        self._records = {}

    def ingest_record(self, **kwargs):
        self.calls.append(kwargs)
        key = kwargs["idempotency_key"]
        fingerprint = payload_hash(
            {
                "source_id": kwargs["source_id"],
                "acquisition_mode": kwargs["acquisition_mode"],
                "external_key": kwargs["external_key"],
                "payload": kwargs["payload"],
                "evidence_ref": kwargs["evidence_ref"],
            }
        )
        previous = self._records.get(key)
        if previous is not None:
            if previous != fingerprint:
                raise ImmutableSinkConflict("fixture secret must not escape")
            return {"created": False, "source_record_id": "source-record-1"}
        self._records[key] = fingerprint
        return {"created": True, "source_record_id": "source-record-1"}


def consent(
    *,
    purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
    granted=True,
    occurred_at="2026-08-19T08:59:00Z",
    valid_until="2027-08-19T08:59:00Z",
    page_url=LANDING_URL,
    text=None,
    text_version=None,
    source="b2b-form-checkbox",
):
    is_marketing = purpose == ConsentPurpose.MARKETING_COMMUNICATION
    return ConsentEvidence(
        purpose=purpose,
        granted=granted,
        text=(
            text
            if text is not None
            else (MARKETING_CONSENT_TEXT if is_marketing else PERSONAL_CONSENT_TEXT)
        ),
        text_version=(
            text_version
            if text_version is not None
            else ("marketing-v2" if is_marketing else "privacy-v3")
        ),
        occurred_at_utc=occurred_at,
        source=source,
        page_url=page_url,
        evidence_ref="evidence://site/consent/submission-001",
        valid_until_utc=valid_until,
    )


def submission(**changes):
    base = FormSubmission(
        submission_id="submission-001",
        submitted_at_utc=SUBMITTED_AT,
        company_name="ООО Фасад Проект",
        applicant_role="Руководитель отдела закупок",
        city_or_region="Москва",
        object_or_recurring_need="Бизнес-центр, подтверждённый контракт",
        product_or_system="Алюминиевые фасадные системы",
        estimated_volume="1 200 м2",
        purchase_stage="Идёт выбор поставщика",
        supplier_selection_open=True,
        required_delivery_or_quote_date="2026-09-15",
        specification_status="ТЗ и чертежи готовы",
        landing_url=LANDING_URL,
        landing_version="landing-v4",
        offer_version="offer-v2",
        form_id="hot-b2b-order",
        form_version="form-v5",
        attribution=SiteAttribution.SITE_PAID,
        personal_data_consent=consent(),
        evidence_ref="evidence://site/raw/submission-001",
        phone="+7 (999) 123-45-67",
        email="BUYER@EXAMPLE.COM",
        original_utm=UtmSet(
            utm_source="yandex",
            utm_medium="cpc",
            utm_campaign="facades_moscow",
            utm_content="ad_17",
            utm_term="алюминиевые фасады",
        ),
        latest_utm=UtmSet(
            utm_source="yandex",
            utm_medium="cpc",
            utm_campaign="facades_moscow",
            utm_content="ad_21",
            utm_term="алюминиевые фасады купить",
        ),
        yclid="1234567890.abcdef",
        ad_click_id="yandex:1234567890.abcdef",
    )
    return replace(base, **changes)


class SiteIngressTests(unittest.TestCase):
    def setUp(self):
        self.sink = RecordingSink()
        self.policy = trusted_policy()
        self.ingress = SiteIngress(
            self.sink,
            source_id="alumkomplekt-site",
            policy=self.policy,
        )

    def ingest(self, form=None):
        return self.ingress.ingest(
            form or submission(), observed_at_utc=OBSERVED_AT
        )

    def test_paid_submission_preserves_first_and_latest_touch(self):
        result = self.ingest()

        self.assertTrue(result.created)
        self.assertEqual(result.attribution, SiteAttribution.SITE_PAID)
        self.assertTrue(result.correlation_id.startswith("lf_site_corr_"))
        call = self.sink.calls[0]
        self.assertEqual(call["acquisition_mode"], "SITE_PAID")
        self.assertEqual(call["external_key"], "submission-001")
        self.assertEqual(call["observed_at_utc"], OBSERVED_AT)
        self.assertEqual(call["run_key"], "site:alumkomplekt-site:2026-08-19")
        record = call["payload"]["record"]
        self.assertEqual(record["attribution"]["original_utm"]["utm_content"], "ad_17")
        self.assertEqual(record["attribution"]["latest_utm"]["utm_content"], "ad_21")
        self.assertEqual(record["attribution"]["yclid"], "1234567890.abcdef")
        self.assertEqual(record["contact"]["phone"], "+79991234567")
        self.assertEqual(record["contact"]["email"], "buyer@example.com")
        self.assertEqual(record["consents"]["personal_data_processing"]["text_version"], "privacy-v3")
        self.assertEqual(call["payload"]["canonical_hash"], payload_hash(record))
        self.assertEqual(result.canonical_hash, payload_hash(record))
        self.assertTrue(all("buyer@example.com" not in key for key in call["canonical_keys"]))

    def test_paid_requires_all_original_and_latest_utm_fields(self):
        incomplete = replace(submission().original_utm, utm_campaign="")
        with self.assertRaisesRegex(SiteValidationError, "complete original and latest UTM"):
            self.ingest(submission(original_utm=incomplete))
        self.assertEqual(self.sink.calls, [])

    def test_organic_is_explicit_and_keeps_empty_utm(self):
        form = submission(
            attribution=SiteAttribution.SITE_ORGANIC,
            original_utm=UtmSet(),
            latest_utm=UtmSet(),
            yclid="",
            ad_click_id="",
            referrer_url="https://yandex.ru/search/?text=facade",
        )
        result = self.ingest(form)
        record = self.sink.calls[-1]["payload"]["record"]
        self.assertEqual(result.attribution.value, "SITE_ORGANIC")
        self.assertEqual(record["attribution_state"], "SITE_ORGANIC")
        self.assertFalse(any(record["attribution"]["original_utm"].values()))

    def test_direct_is_explicit_without_fabricated_attribution(self):
        form = submission(
            attribution=SiteAttribution.SITE_DIRECT,
            original_utm=UtmSet(),
            latest_utm=UtmSet(),
            yclid="",
            ad_click_id="",
            referrer_url="",
        )
        self.ingest(form)
        record = self.sink.calls[-1]["payload"]["record"]
        self.assertEqual(record["attribution_state"], "SITE_DIRECT")
        self.assertEqual(record["landing"]["referrer_url"], "")
        self.assertFalse(any(record["attribution"]["latest_utm"].values()))

    def test_referral_requires_and_preserves_referrer(self):
        form = submission(
            attribution=SiteAttribution.SITE_REFERRAL,
            original_utm=UtmSet(),
            latest_utm=UtmSet(),
            yclid="",
            ad_click_id="",
            referrer_url="https://partner.example/catalog#facades",
        )
        self.ingest(form)
        record = self.sink.calls[-1]["payload"]["record"]
        self.assertEqual(record["attribution_state"], "SITE_REFERRAL")
        self.assertEqual(record["landing"]["referrer_url"], "https://partner.example/catalog")

        with self.assertRaises(SiteValidationError):
            self.ingest(replace(form, referrer_url="", submission_id="submission-002"))

    def test_required_b2b_fields_and_contact_are_fail_closed(self):
        for field in (
            "company_name",
            "applicant_role",
            "city_or_region",
            "object_or_recurring_need",
            "product_or_system",
            "estimated_volume",
            "purchase_stage",
            "specification_status",
            "landing_version",
            "offer_version",
            "form_id",
            "form_version",
        ):
            with self.subTest(field=field):
                with self.assertRaises(SiteValidationError):
                    self.ingest(submission(**{field: ""}))
        with self.assertRaisesRegex(SiteValidationError, "phone or email"):
            self.ingest(submission(phone="", email=""))

    def test_russian_domestic_phone_is_canonicalized_to_country_code_7(self):
        self.ingest(submission(phone="8 (999) 123-45-67", email=""))

        record = self.sink.calls[0]["payload"]["record"]
        self.assertEqual(record["contact"]["phone"], "+79991234567")
        with self.assertRaisesRegex(SiteValidationError, "boolean"):
            self.ingest(submission(supplier_selection_open="yes"))

    def test_unicode_digit_phone_is_rejected_before_site_sink(self):
        unicode_phones = (
            "８（９９９）１２３－４５－６７",
            "٨٩٩٩١٢٣٤٥٦٧",
            "8 (999) 123-45-6７",
        )
        for index, phone in enumerate(unicode_phones, start=1):
            with self.subTest(index=index):
                with self.assertRaisesRegex(SiteValidationError, "phone"):
                    self.ingest(
                        submission(
                            submission_id=f"unicode-phone-{index}",
                            phone=phone,
                            email="",
                        )
                    )
        self.assertEqual(self.sink.calls, [])

    def test_consent_is_purpose_bound_versioned_and_temporal(self):
        good = self.ingest().canonical_json
        self.assertIn('"text_version":"privacy-v3"', good)
        self.assertIn('"text":"Согласен на обработку персональных данных', good)
        self.assertIn('"source":"b2b-form-checkbox"', good)
        self.assertIn('"evidence_ref":"evidence://site/consent/submission-001"', good)

        bad_cases = (
            consent(granted=False),
            consent(purpose=ConsentPurpose.MARKETING_COMMUNICATION),
            consent(occurred_at="2026-08-19T09:01:00Z"),
            consent(valid_until="2026-08-19T08:58:59Z"),
            consent(occurred_at="2026-08-19 08:59:00"),
        )
        for index, bad in enumerate(bad_cases, start=2):
            with self.subTest(index=index):
                with self.assertRaises(SiteValidationError):
                    self.ingest(
                        submission(
                            submission_id=f"submission-{index:03d}",
                            personal_data_consent=bad,
                        )
                    )

    def test_marketing_consent_is_not_inferred_from_processing_consent(self):
        self.ingest(submission(marketing_consent=None))
        record = self.sink.calls[-1]["payload"]["record"]
        self.assertIsNone(record["consents"]["marketing_communication"])

        marketing = replace(
            consent(purpose=ConsentPurpose.MARKETING_COMMUNICATION),
            text_version="marketing-v2",
        )
        self.ingest(submission(submission_id="submission-002", marketing_consent=marketing))
        record = self.sink.calls[-1]["payload"]["record"]
        self.assertEqual(
            record["consents"]["marketing_communication"]["purpose"],
            "MARKETING_COMMUNICATION",
        )

    def test_replay_is_idempotent_at_sink_and_conflict_fails_closed(self):
        first = self.ingest()
        replay = self.ingest()
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.idempotency_key, replay.idempotency_key)
        self.assertEqual(first.canonical_hash, replay.canonical_hash)

        changed = submission(estimated_volume="9 999 м2")
        with self.assertRaisesRegex(SiteIngressConflict, "conflicting content") as raised:
            self.ingest(changed)
        self.assertNotIn("fixture secret", str(raised.exception))

    def test_invalid_observation_timestamp_never_reaches_sink(self):
        with self.assertRaises(SiteValidationError):
            self.ingress.ingest(submission(), observed_at_utc="2026-08-19 09:00:03")
        with self.assertRaisesRegex(SiteValidationError, "cannot precede"):
            self.ingress.ingest(
                submission(), observed_at_utc="2026-08-19T08:59:59Z"
            )
        self.assertEqual(self.sink.calls, [])

    def test_future_capture_is_rejected_against_an_injectable_clock(self):
        ingress = SiteIngress(
            self.sink,
            source_id="alumkomplekt-site",
            policy=self.policy,
            clock=lambda: datetime(2026, 8, 19, 9, tzinfo=timezone.utc),
        )
        future = replace(
            submission(),
            submitted_at_utc="2099-01-01T09:00:00Z",
            personal_data_consent=consent(
                occurred_at="2099-01-01T08:59:00Z",
                valid_until="2100-01-01T08:59:00Z",
            ),
        )

        with self.assertRaisesRegex(SiteValidationError, "future"):
            ingress.ingest(future, observed_at_utc="2099-01-01T09:00:01Z")

        self.assertEqual(self.sink.calls, [])

    def test_repr_and_safe_errors_do_not_expose_contact_or_tokens(self):
        token = "super-secret-access-token-value"
        form = submission(
            landing_url=f"https://alum.example/b2b?access_token={token}",
            personal_data_consent=consent(
                page_url=f"https://alum.example/b2b?access_token={token}"
            ),
        )
        self.assertNotIn("buyer@example.com", repr(form).lower())
        self.assertNotIn("999", repr(form))
        self.assertNotIn(token, repr(form))
        with self.assertRaises(SiteValidationError) as raised:
            self.ingest(form)
        self.assertNotIn(token, str(raised.exception))

        safe_result = self.ingest()
        self.assertNotIn("buyer@example.com", repr(safe_result).lower())
        self.assertNotIn("999", repr(safe_result))

        logger = logging.getLogger("site-ingress-redaction-test")
        with self.assertLogs(logger, level="INFO") as captured:
            logger.info("%r", form)
            logger.info("%r", safe_result)
            logger.info("%s", raised.exception)
        rendered = "\n".join(captured.output)
        self.assertNotIn(token, rendered)
        self.assertNotIn("buyer@example.com", rendered.lower())
        self.assertNotIn("999", rendered)

    def test_sink_errors_are_sanitised_and_no_side_effect_capability_is_required(self):
        class ExplodingSink:
            def ingest_record(self, **unused):
                raise RuntimeError("Bearer production-token phone +79991234567")

        ingress = SiteIngress(
            ExplodingSink(),
            source_id="alumkomplekt-site",
            policy=self.policy,
        )
        with self.assertRaisesRegex(SiteIngressError, "site ingress sink failed") as raised:
            ingress.ingest(submission(), observed_at_utc=OBSERVED_AT)
        self.assertNotIn("production-token", str(raised.exception))
        self.assertNotIn("7999", str(raised.exception))

    def test_repr_redacts_unvalidated_enum_like_fields(self):
        secret = "Bearer-super-secret-token"
        form = replace(submission(), attribution=secret)
        consent_value = consent(purpose="buyer@example.com")

        self.assertNotIn(secret, repr(form))
        self.assertNotIn("buyer@example.com", repr(consent_value))

    def test_oversized_url_query_is_a_safe_validation_error(self):
        query = "&".join(f"field{i}=value" for i in range(101))
        form = replace(submission(), landing_url=f"https://alum.example/b2b?{query}")

        with self.assertRaises(SiteValidationError) as raised:
            self.ingest(form)

        self.assertNotIn("field100", str(raised.exception))

    def test_trusted_policy_provenance_is_bound_into_canonical_record(self):
        result = self.ingest()
        record = self.sink.calls[0]["payload"]["record"]
        provenance = record["trusted_policy"]

        self.assertEqual(provenance["policy_id"], "alumkomplekt-site-policy")
        self.assertEqual(provenance["policy_version"], "2026-08-20-v1")
        self.assertRegex(provenance["policy_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            provenance["evidence_ref"],
            "evidence://site-policy/alumkomplekt/2026-08-20-v1",
        )
        self.assertIn(provenance["policy_hash"], result.canonical_json)

    def test_typed_policy_is_mandatory_and_bound_to_exact_source(self):
        with self.assertRaises(TypeError):
            SiteIngress(self.sink, source_id="alumkomplekt-site")
        with self.assertRaisesRegex(SiteValidationError, "typed trusted"):
            SiteIngress(
                self.sink,
                source_id="alumkomplekt-site",
                policy={"allowed_origins": ("https://alum.example",)},
            )
        with self.assertRaisesRegex(SiteValidationError, "another source"):
            SiteIngress(
                self.sink,
                source_id="attacker-site",
                policy=self.policy,
            )
        self.assertEqual(self.sink.calls, [])

    def test_attack_landing_hosts_and_userinfo_are_rejected_before_sink(self):
        attack_urls = (
            "https://alum.example.evil.test/b2b?product=facade",
            "https://alum.example@evil.test/b2b?product=facade",
            "https://evil.test/b2b?product=facade",
        )
        for index, attack_url in enumerate(attack_urls, start=1):
            with self.subTest(url_index=index):
                with self.assertRaises(SiteValidationError):
                    self.ingest(
                        submission(
                            submission_id=f"attack-host-{index}",
                            landing_url=attack_url,
                            personal_data_consent=consent(page_url=attack_url),
                        )
                    )
        self.assertEqual(self.sink.calls, [])

    def test_unregistered_landing_path_cannot_persist_a_path_token(self):
        secret = "prod-secret-reset-token-xyz"
        attack_url = f"https://alum.example/reset/{secret}"
        with self.assertRaisesRegex(SiteValidationError, "path") as raised:
            self.ingest(
                submission(
                    submission_id="attack-path-1",
                    landing_url=attack_url,
                    personal_data_consent=consent(page_url=attack_url),
                )
            )
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(self.sink.calls, [])

    def test_unregistered_deployment_versions_are_rejected_before_sink(self):
        changes = (
            {"form_id": "lookalike-form"},
            {"form_version": "form-v999"},
            {"landing_version": "landing-v999"},
            {"offer_version": "offer-v999"},
        )
        for index, change in enumerate(changes, start=1):
            with self.subTest(change=change):
                with self.assertRaisesRegex(SiteValidationError, "not trusted"):
                    self.ingest(
                        submission(
                            submission_id=f"fake-deployment-{index}", **change
                        )
                    )
        self.assertEqual(self.sink.calls, [])

    def test_consent_source_version_and_exact_text_hash_are_trusted_facts(self):
        attacks = (
            consent(source="lookalike-checkbox"),
            consent(text_version="privacy-v999"),
            consent(
                text=(
                    PERSONAL_CONSENT_TEXT
                    + " Подменённый текст Bearer-super-secret-token."
                )
            ),
        )
        for index, forged in enumerate(attacks, start=1):
            with self.subTest(attack=index):
                with self.assertRaises(SiteValidationError) as raised:
                    self.ingest(
                        submission(
                            submission_id=f"fake-consent-{index}",
                            personal_data_consent=forged,
                        )
                    )
                self.assertNotIn("super-secret-token", str(raised.exception))
        self.assertEqual(self.sink.calls, [])

    def test_secret_and_unknown_query_keys_are_rejected_and_never_persisted(self):
        forbidden_keys = (
            "token",
            "access_token",
            "session",
            "jwt",
            "code",
            "sig",
            "signature",
            "totally_unknown",
        )
        secret = "query-secret-must-not-escape"
        for index, key in enumerate(forbidden_keys, start=1):
            url = f"https://alum.example/b2b?product=facade&{key}={secret}"
            with self.subTest(key=key):
                with self.assertRaises(SiteValidationError) as raised:
                    self.ingest(
                        submission(
                            submission_id=f"query-attack-{index}",
                            landing_url=url,
                            personal_data_consent=consent(page_url=url),
                        )
                    )
                self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(self.sink.calls, [])

    def test_policy_cannot_allow_secret_or_duplicate_query_keys(self):
        unsafe_policies = (
            trusted_policy(allowed_landing_query_keys=("product", "token")),
            trusted_policy(allowed_landing_query_keys=("product", "product")),
        )
        for unsafe in unsafe_policies:
            with self.subTest(policy=repr(unsafe)):
                with self.assertRaises(SiteValidationError):
                    SiteIngress(
                        self.sink,
                        source_id="alumkomplekt-site",
                        policy=unsafe,
                    )
        self.assertEqual(self.sink.calls, [])

    def test_referrer_has_its_own_origin_and_query_registry(self):
        attack_referrers = (
            "https://evil.test/catalog",
            "https://partner.example/catalog?token=secret",
            "https://partner.example/catalog?unknown=value",
            "https://partner.example/invite/prod-secret-invite-token",
        )
        for index, referrer in enumerate(attack_referrers, start=1):
            with self.subTest(referrer=index):
                with self.assertRaises(SiteValidationError):
                    self.ingest(
                        submission(
                            submission_id=f"referrer-attack-{index}",
                            attribution=SiteAttribution.SITE_REFERRAL,
                            original_utm=UtmSet(),
                            latest_utm=UtmSet(),
                            yclid="",
                            ad_click_id="",
                            referrer_url=referrer,
                        )
                    )
        self.assertEqual(self.sink.calls, [])

    def test_convenience_api_requires_and_applies_the_same_policy(self):
        result = ingest_site_submission(
            self.sink,
            source_id="alumkomplekt-site",
            policy=self.policy,
            submission=submission(),
            observed_at_utc=OBSERVED_AT,
        )
        self.assertTrue(result.created)
        self.assertEqual(
            self.sink.calls[0]["payload"]["record"]["trusted_policy"]["policy_id"],
            "alumkomplekt-site-policy",
        )


if __name__ == "__main__":
    unittest.main()
