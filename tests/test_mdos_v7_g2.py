from __future__ import annotations

import json
from pathlib import Path

import pytest

from lead_factory.mdos_v7.g2 import (
    G2MotionRegistry,
    G2ProfileError,
    REQUIRED_CANDIDATE_FIELDS,
)


def _candidate(profile_id: str) -> dict[str, object]:
    value: dict[str, object] = {
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "external_read": False,
        "external_write": False,
        "contact": False,
        "spend": False,
        "live_bitrix_write": False,
    }
    for field in REQUIRED_CANDIDATE_FIELDS[profile_id]:
        value[field] = (
            ["fixture-product"] if field == "product_scope" else f"fixture:{field}"
        )
    if profile_id == "G2-MOTION-HIGH-INTENT-INBOUND":
        value["private_inbound_payload_ref"] = "private:fixture-inbound-001"
        value["website_attribution_status"] = "ATTRIBUTED"
        value["opaque_form_correlation_id"] = "lf_web_v1_" + "a" * 40
    return value


def test_three_g2_motions_are_executable_shadow_readiness_contracts() -> None:
    registry = G2MotionRegistry()
    assert registry.profile_ids == (
        "G2-MOTION-EXISTING-WINBACK",
        "G2-MOTION-HIGH-INTENT-INBOUND",
        "G2-MOTION-DEALER-BENCHMARK-RFQ",
    )
    for profile_id in registry.profile_ids:
        result = registry.evaluate_shadow_candidate(profile_id, _candidate(profile_id))
        assert result.ready_for_human_gold_review is True
        assert result.missing_fields == ()
        assert result.next_action == "HUMAN_GOLD_REVIEW"
        assert result.canonical_kpi_eligible is False
        assert result.external_effect_count == 0


def test_g2_missing_proof_routes_to_human_verify_and_external_effect_is_denied() -> (
    None
):
    registry = G2MotionRegistry()
    profile_id = "G2-MOTION-DEALER-BENCHMARK-RFQ"
    incomplete = _candidate(profile_id)
    incomplete["rfq_artifact_ref"] = ""
    result = registry.evaluate_shadow_candidate(profile_id, incomplete)
    assert result.ready_for_human_gold_review is False
    assert result.missing_fields == ("rfq_artifact_ref",)
    assert result.next_action == "HUMAN_VERIFY"

    live = _candidate(profile_id)
    live["contact"] = True
    with pytest.raises(G2ProfileError, match="prohibited external effect"):
        registry.evaluate_shadow_candidate(profile_id, live)


def test_g2_authority_drift_fails_closed(tmp_path: Path) -> None:
    source = json.loads(
        Path("docs/market_demand_os_v7_delivery/g2-motion-profiles.json").read_text(
            encoding="utf-8"
        )
    )
    source["authority"]["external_reads_enabled"] = True
    drifted = tmp_path / "g2-drift.json"
    drifted.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(G2ProfileError, match="must remain false"):
        G2MotionRegistry(drifted)


def test_g2_inbound_profile_binds_private_plane_and_opaque_correlation() -> None:
    registry = G2MotionRegistry()
    profile = registry.profile("G2-MOTION-HIGH-INTENT-INBOUND")
    attribution = profile["inbound_attribution_contract"]
    assert attribution["owner_requirement_id"] == "DLV-REQ-INBOUND-ATTR-001"
    assert attribution["source_hierarchy"] == [
        "ALLOWLISTED_UTM",
        "CLASSIFIED_EXTERNAL_REFERRER",
        "DIRECT_WEBSITE",
        "UNKNOWN",
    ]
    assert attribution["private_plane"]["analytics_export_allowed"] is False
    assert attribution["public_plane"]["raw_metrika_ids_allowed"] is False

    raw_private = _candidate("G2-MOTION-HIGH-INTENT-INBOUND")
    raw_private["request_text"] = "private request"
    with pytest.raises(G2ProfileError, match="exposes private inbound fields"):
        registry.evaluate_shadow_candidate("G2-MOTION-HIGH-INTENT-INBOUND", raw_private)

    bad_correlation = _candidate("G2-MOTION-HIGH-INTENT-INBOUND")
    bad_correlation["opaque_form_correlation_id"] = "contact@example.invalid"
    with pytest.raises(G2ProfileError, match="correlation is not opaque"):
        registry.evaluate_shadow_candidate(
            "G2-MOTION-HIGH-INTENT-INBOUND", bad_correlation
        )

    bad_private_ref = _candidate("G2-MOTION-HIGH-INTENT-INBOUND")
    bad_private_ref["private_inbound_payload_ref"] = "private:contact@example.invalid"
    with pytest.raises(
        G2ProfileError, match="private payload reference is not separated"
    ):
        registry.evaluate_shadow_candidate(
            "G2-MOTION-HIGH-INTENT-INBOUND", bad_private_ref
        )
