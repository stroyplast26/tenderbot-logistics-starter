from __future__ import annotations

import json

import pytest

import lead_factory.mdos_v7.inbound_attribution as inbound_module
from lead_factory.mdos_v7.inbound_attribution import (
    InboundAttributionError,
    UNKNOWN,
    UTM_FIELDS,
    WebsiteInboundAttributionContract,
    assert_pii_free,
    reconcile_attribution,
    serialized_public_bundle,
)


PRIVATE_VALUES = (
    "Иван Тестовый",
    "private-person@example.invalid",
    "+7 999 111-22-33",
    "Нужен расчёт частного объекта с контактными деталями",
    "visit-private-123",
    "client-private-456",
)


def _public() -> dict[str, object]:
    return {
        "submission_id": "fixture-submission-website-001",
        "captured_at": "2026-08-25T12:00:00Z",
        "origin_channel": "WEBSITE_FORM",
        "landing_path": "/rfq",
        "prior_path": "/catalog/facades",
        "referrer_classification": "SEARCH",
        "utm": {
            "utm_source": "yandex",
            "utm_medium": "cpc",
            "utm_campaign": "facade_b2b",
            "utm_content": "calculator_cta",
            "utm_term": "aluminium_facade",
        },
        "synthetic": True,
        "canonical_kpi_eligible": False,
    }


def _private(*, lawful: bool = True) -> dict[str, object]:
    return {
        "pii": {
            "full_name": PRIVATE_VALUES[0],
            "email": PRIVATE_VALUES[1],
            "phone": PRIVATE_VALUES[2],
        },
        "request_text": PRIVATE_VALUES[3],
        "metrika_visit_id": PRIVATE_VALUES[4],
        "metrika_client_id": PRIVATE_VALUES[5],
        "metrika_ids_lawfully_supplied": lawful,
    }


def test_website_attribution_is_deterministic_pii_free_and_shadow_only() -> None:
    contract = WebsiteInboundAttributionContract()
    first = contract.capture(_public(), _private())
    second = contract.capture(_public(), _private())

    assert first == second
    assert first.correlation_id.startswith("lf_web_v1_")
    assert first.analytics["attribution_status"] == "ATTRIBUTED"
    assert first.analytics["source_basis"] == "ALLOWLISTED_UTM"
    assert first.analytics["source_class"] == "UTM"
    assert first.analytics["metrika_visit_id_present"] is True
    assert first.analytics["metrika_client_id_present"] is True
    assert first.bitrix_projection["mode"] == "SHADOW"
    assert first.bitrix_projection["external_effect"] is False
    assert first.bitrix_projection["fields"]["opaque_correlation_id"] == (
        first.correlation_id
    )
    assert first.reconciliation["status"] == "RECONCILED_ATTRIBUTED"
    assert first.reconciliation["exact_projection_match"] is True
    assert first.external_effect_count == 0
    assert first.canonical_kpi_eligible is False

    public_json = serialized_public_bundle(first)
    for private_value in PRIVATE_VALUES:
        assert private_value not in public_json
    assert "metrika_visit_id\"" not in public_json
    assert "metrika_client_id\"" not in public_json
    assert first.evidence_summary["raw_private_values_included"] is False
    assert first.evidence_summary["private_payload_separated"] is True


def test_missing_attribution_is_explicit_unknown_and_never_invented() -> None:
    public = {
        "submission_id": "fixture-submission-website-unknown",
        "captured_at": "2026-08-25T12:01:00Z",
        "synthetic": True,
        "canonical_kpi_eligible": False,
    }
    private = {
        "pii": {},
        "request_text": "",
        "metrika_visit_id": "",
        "metrika_client_id": "",
        "metrika_ids_lawfully_supplied": False,
    }
    result = WebsiteInboundAttributionContract().capture(public, private)

    assert result.analytics["origin_channel"] == UNKNOWN
    assert result.analytics["landing_path"] == UNKNOWN
    assert result.analytics["prior_path"] == UNKNOWN
    assert result.analytics["referrer_classification"] == UNKNOWN
    assert result.analytics["utm"] == {field: UNKNOWN for field in UTM_FIELDS}
    assert result.analytics["attribution_status"] == UNKNOWN
    assert result.analytics["source_basis"] == "NO_TRUSTED_SOURCE_EVIDENCE"
    assert result.analytics["source_class"] == UNKNOWN
    assert result.reconciliation["status"] == "RECONCILED_UNKNOWN"
    assert result.bitrix_projection["fields"]["source_class"] == UNKNOWN


def test_source_hierarchy_is_utm_then_external_referrer_then_direct_then_unknown() -> None:
    contract = WebsiteInboundAttributionContract()
    private = _private()

    search = _public()
    search["utm"] = {}
    search_result = contract.capture(search, private)
    assert search_result.analytics["source_basis"] == "CLASSIFIED_EXTERNAL_REFERRER"
    assert search_result.analytics["source_class"] == "ORGANIC_SEARCH"

    direct = _public()
    direct["utm"] = {}
    direct["referrer_classification"] = "DIRECT"
    direct_result = contract.capture(direct, private)
    assert direct_result.analytics["source_basis"] == "EXPLICIT_DIRECT"
    assert direct_result.analytics["source_class"] == "DIRECT_WEBSITE"

    partial = _public()
    partial["utm"] = {"utm_campaign": "campaign_without_source"}
    partial["referrer_classification"] = "SEARCH"
    partial_result = contract.capture(partial, private)
    assert partial_result.analytics["attribution_status"] == UNKNOWN
    assert partial_result.analytics["source_basis"] == "PARTIAL_UTM_UNKNOWN_SOURCE"
    assert partial_result.analytics["source_class"] == UNKNOWN


def test_public_allowlist_paths_pii_and_lawful_metrika_fail_closed() -> None:
    contract = WebsiteInboundAttributionContract()

    public_pii = _public()
    public_pii["email"] = PRIVATE_VALUES[1]
    with pytest.raises(InboundAttributionError, match="forbidden fields"):
        contract.capture(public_pii, _private())

    unknown_utm = _public()
    unknown_utm["utm"] = {"utm_source": "yandex", "email": PRIVATE_VALUES[1]}
    with pytest.raises(InboundAttributionError, match="forbidden fields"):
        contract.capture(unknown_utm, _private())

    query_path = _public()
    query_path["landing_path"] = "/rfq?email=private-person@example.invalid"
    with pytest.raises(InboundAttributionError, match="without query"):
        contract.capture(query_path, _private())

    pii_utm = _public()
    pii_utm["utm"] = {"utm_source": PRIVATE_VALUES[1]}
    with pytest.raises(InboundAttributionError, match="PII or a URL"):
        contract.capture(pii_utm, _private())

    with pytest.raises(InboundAttributionError, match="lawful supplied evidence"):
        contract.capture(_public(), _private(lawful=False))

    short_timestamp = _public()
    short_timestamp["captured_at"] = "2026-08-25T12:00Z"
    with pytest.raises(InboundAttributionError, match="RFC3339 UTC Z"):
        contract.capture(short_timestamp, _private())


def test_projection_reconciliation_detects_correlation_or_attribution_drift() -> None:
    result = WebsiteInboundAttributionContract().capture(_public(), _private())
    changed = json.loads(json.dumps(result.bitrix_projection))
    changed["fields"]["source_class"] = "DIRECT_WEBSITE"
    with pytest.raises(InboundAttributionError, match="does not match analytics"):
        reconcile_attribution(result.analytics, changed)

    with pytest.raises(InboundAttributionError, match="private field leaked"):
        assert_pii_free({"safe": {"request_text": PRIVATE_VALUES[3]}})


def test_authority_drift_blocks_contract_before_any_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        inbound_module,
        "authority_snapshot",
        lambda: {
            "manifest": {
                "active_beachhead_profile": None,
                "defaults_pending_ratification": {
                    "external_reads_enabled": False,
                    "external_writers_enabled": False,
                    "contact_enabled": False,
                    "spend_enabled": False,
                },
            },
            "freeze": {
                "external_reads_enabled": False,
                "external_writers_enabled": True,
                "contact_enabled": False,
                "spend_enabled": False,
                "live_bitrix_writes_enabled": False,
            },
        },
    )
    with pytest.raises(InboundAttributionError, match="not shadow-only"):
        WebsiteInboundAttributionContract()
