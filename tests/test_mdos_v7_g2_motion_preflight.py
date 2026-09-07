from __future__ import annotations

from copy import deepcopy
from datetime import date, timedelta
import json
from pathlib import Path
from typing import Any

import pytest

from lead_factory.mdos_v7.contracts import record_digest_excluding, value_sha256
from lead_factory.mdos_v7.g2_preflight import (
    CLASSIFICATION,
    G2PreflightConflict,
    G2PreflightError,
    G2ShadowPreflightService,
    PREFLIGHT_LIMITATIONS,
    build_preflight_bundle,
    load_preflight_fixture,
    write_content_addressed_bundle,
)
from lead_factory.mdos_v7.store import MdosStore


FIXTURE_ROOT = Path("tests/fixtures/market_demand_os_v7")
EXISTING_FIXTURE = FIXTURE_ROOT / "g2_existing_winback_preflight" / "fixture.json"
DEALER_FIXTURE = FIXTURE_ROOT / "g2_dealer_benchmark_preflight" / "fixture.json"
INBOUND_FIXTURE = FIXTURE_ROOT / "g2_high_intent_inbound_preflight" / "fixture.json"


def _fixtures() -> list[dict[str, object]]:
    return [
        load_preflight_fixture(EXISTING_FIXTURE),
        load_preflight_fixture(INBOUND_FIXTURE),
        load_preflight_fixture(DEALER_FIXTURE),
    ]


def _reseal_result(result: dict[str, Any]) -> None:
    unsigned = dict(result)
    unsigned.pop("bundle_sha256", None)
    result["bundle_sha256"] = value_sha256(unsigned)


def _reseal_bundle(bundle: dict[str, Any]) -> None:
    unsigned = dict(bundle)
    unsigned.pop("bundle_sha256", None)
    bundle["bundle_sha256"] = value_sha256(unsigned)


def _synthetic_permit(fixture: dict[str, Any]) -> dict[str, Any]:
    binding = fixture["profile_binding"]
    candidate = fixture["candidate"]
    candidate_sha = value_sha256(candidate)
    permit = {
        "schema_version": "1.0.0",
        "permit_decision_id": "permit-fixture-g2-forged-001",
        "decision": "ALLOW",
        "purpose": "G2_SHADOW_PREFLIGHT_PROJECTION",
        "action_type": "CREATE_CRM_TASK",
        "channel": "BITRIX24_SHADOW",
        "scope": {
            "beachhead_profile_ref": None,
            "region": candidate["region"],
            "product_scope": candidate["product_scope"],
        },
        "subject_refs": [
            candidate.get("canonical_account_ref")
            or candidate["opaque_form_correlation_id"]
        ],
        "legal_basis_ref": "FIXTURE_ONLY_NO_EXTERNAL_EFFECT",
        "source_passport_ref": fixture["source"]["source_passport_ref"],
        "issued_by": "fixture-human-policy-authority",
        "issued_at": "2026-08-25T19:59:00Z",
        "expires_at": "2026-08-25T20:59:00Z",
        "policy_version": "mdos-v7.1-rc1-g2-shadow-preflight-1",
        "capacity_snapshot_ref": candidate["capacity_snapshot_ref"],
        "max_cost": 0,
        "currency": "RUB",
        "evidence_refs": [
            f"g2-profile-file-sha256:{binding['profile_file_sha256']}",
            f"g2-profile-set-sha256:{binding['profile_set_sha256']}",
            f"g2-profile-sha256:{binding['profile_sha256']}",
            f"g2-candidate-sha256:{candidate_sha}",
        ],
        "payload_sha256": "",
    }
    permit["payload_sha256"] = record_digest_excluding(permit, "payload_sha256")
    return permit


def test_all_three_preflights_are_ready_proposals_but_effects_stay_denied() -> None:
    service = G2ShadowPreflightService()
    results = [service.evaluate(fixture) for fixture in _fixtures()]

    assert {result["profile_binding"]["profile_id"] for result in results} == {
        "G2-MOTION-EXISTING-WINBACK",
        "G2-MOTION-HIGH-INTENT-INBOUND",
        "G2-MOTION-DEALER-BENCHMARK-RFQ",
    }
    for result in results:
        assert result["status"] == "READY_PROPOSAL_EFFECT_DENIED"
        assert result["candidate"]["readiness_status"] == "READY_FOR_HUMAN_GOLD_REVIEW"
        assert result["candidate"]["next_action"] == "HUMAN_GOLD_REVIEW"
        assert result["permit"] == {
            "supplied": False,
            "permit_decision_sha256": None,
            "exact_persisted": False,
            "local_denial_audit_recorded": False,
            "effect_decision": "DENY",
            "reason_codes": [
                "PERMIT_NOT_SUPPLIED",
                "UNRATIFIED_SHADOW_DESIGN_ONLY",
            ],
        }
        assert result["canonical_kpi_eligible"] is False
        assert result["limitations"] == list(PREFLIGHT_LIMITATIONS)
        assert result["external_effect_count"] == 0
        assert result["live_bitrix_write_count"] == 0
        assert set(result["created_truth"].values()) == {0}
        assert result["privacy"] == {
            "raw_candidate_included": False,
            "raw_pii_included": False,
            "request_text_included": False,
        }
        sealed = dict(result)
        observed_sha = sealed.pop("bundle_sha256")
        assert observed_sha == value_sha256(sealed)


def test_inbound_private_reference_is_validated_but_never_echoed() -> None:
    fixture = deepcopy(load_preflight_fixture(INBOUND_FIXTURE))
    private_ref = fixture["candidate"]["private_inbound_payload_ref"]

    result = G2ShadowPreflightService().evaluate(fixture)

    assert result["status"] == "READY_PROPOSAL_EFFECT_DENIED"
    assert private_ref not in json.dumps(result, ensure_ascii=False, sort_keys=True)

    for unsafe_ref in (
        "fixture:not-private",
        "private:",
        "private:buyer@example.invalid",
        "private:raw request text",
    ):
        invalid = deepcopy(fixture)
        invalid["candidate"]["private_inbound_payload_ref"] = unsafe_ref
        denied = G2ShadowPreflightService().evaluate(invalid)
        assert denied["status"] == "DENIED"
        assert unsafe_ref not in json.dumps(denied, ensure_ascii=False, sort_keys=True)


def test_inbound_permit_subject_is_exact_opaque_form_correlation() -> None:
    fixture = deepcopy(load_preflight_fixture(INBOUND_FIXTURE))
    permit = _synthetic_permit(fixture)
    assert permit["subject_refs"] == [
        fixture["candidate"]["opaque_form_correlation_id"]
    ]
    fixture["permit_decision"] = permit

    result = G2ShadowPreflightService().evaluate(fixture)
    assert "PERMIT_EFFECT_SCOPE_MISMATCH" not in result["permit"]["reason_codes"]

    changed = deepcopy(fixture)
    changed["permit_decision"]["subject_refs"] = [
        changed["candidate"]["identity_decision_ref"]
    ]
    changed["permit_decision"]["payload_sha256"] = record_digest_excluding(
        changed["permit_decision"], "payload_sha256"
    )
    denied = G2ShadowPreflightService().evaluate(changed)
    assert "PERMIT_EFFECT_SCOPE_MISMATCH" in denied["permit"]["reason_codes"]


def test_preflight_replay_and_content_addressed_output_are_deterministic(
    tmp_path: Path,
) -> None:
    service = G2ShadowPreflightService()
    first = [service.evaluate(fixture) for fixture in _fixtures()]
    second = [service.evaluate(fixture) for fixture in _fixtures()]
    assert first == second

    bundle = build_preflight_bundle(first)
    output = tmp_path / "g2-preflight.json"
    assert write_content_addressed_bundle(output, bundle) == "APPLIED"
    assert write_content_addressed_bundle(output, bundle) == "REPLAY"
    assert json.loads(output.read_text(encoding="utf-8")) == bundle

    output.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
    with pytest.raises(G2PreflightConflict, match="different bytes"):
        write_content_addressed_bundle(output, bundle)


@pytest.mark.parametrize(
    "failure", ["profile", "source", "privacy", "timestamp", "authority"]
)
def test_profile_source_privacy_and_authority_mismatch_fail_closed(
    failure: str,
) -> None:
    fixture = deepcopy(load_preflight_fixture(EXISTING_FIXTURE))
    authority_provider = None
    private_value = "raw-person@example.invalid asks for a private quote"
    if failure == "profile":
        fixture["profile_binding"]["profile_sha256"] = "0" * 64
    elif failure == "source":
        fixture["source"]["source_passport_ref"] = "fixture:unknown-source"
    elif failure == "privacy":
        fixture["candidate"]["request_text"] = private_value
    elif failure == "timestamp":
        fixture["evaluated_at"] = private_value
    else:

        def invalid_authority() -> dict[str, object]:
            raise RuntimeError("drift")

        authority_provider = invalid_authority

    service = (
        G2ShadowPreflightService(authority_provider=authority_provider)
        if authority_provider is not None
        else G2ShadowPreflightService()
    )
    result = service.evaluate(fixture)
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert result["status"] == "DENIED"
    assert result["candidate"]["readiness_status"] == "DENIED"
    assert result["candidate"]["next_action"] == "STOP"
    assert result["permit"]["effect_decision"] == "DENY"
    assert result["external_effect_count"] == 0
    assert result["live_bitrix_write_count"] == 0
    assert private_value not in serialized
    assert "raw-person@example.invalid" not in serialized


def test_missing_dealer_rfq_routes_only_to_human_verification() -> None:
    fixture = deepcopy(load_preflight_fixture(DEALER_FIXTURE))
    fixture["candidate"]["rfq_artifact_ref"] = ""
    result = G2ShadowPreflightService().evaluate(fixture)
    assert result["status"] == "NEEDS_HUMAN_VERIFICATION_EFFECT_DENIED"
    assert result["candidate"] == {
        "candidate_sha256": value_sha256(fixture["candidate"]),
        "readiness_status": "NEEDS_HUMAN_VERIFICATION",
        "missing_fields": ["rfq_artifact_ref"],
        "next_action": "HUMAN_VERIFY",
    }
    assert result["permit"]["effect_decision"] == "DENY"


def test_profile_mismatch_records_hash_only_local_denial_when_store_is_available(
    tmp_path: Path,
) -> None:
    fixture = deepcopy(load_preflight_fixture(EXISTING_FIXTURE))
    fixture["profile_binding"]["profile_sha256"] = "0" * 64
    store = MdosStore(tmp_path / "denial-ledger.sqlite3", actor_registry={})
    service = G2ShadowPreflightService(permit_store=store)

    result = service.evaluate(fixture)
    replay = service.evaluate(fixture)
    denials = store.denials()
    assert result == replay
    assert result["status"] == "DENIED"
    assert result["local_denial_audit_recorded"] is True
    assert result["permit"]["effect_decision"] == "DENY"
    assert len(denials) == 1
    assert denials[0]["operation"] == "g2_shadow_preflight_contract"
    assert denials[0]["reason_code"] == "PREFLIGHT_CONTRACT_DENIED"
    assert denials[0]["payload_sha256"] == value_sha256(fixture)
    store.verify_integrity()


def test_unknown_forged_permit_is_hashed_not_trusted_or_echoed(tmp_path: Path) -> None:
    fixture = deepcopy(load_preflight_fixture(DEALER_FIXTURE))
    permit = _synthetic_permit(fixture)
    fixture["permit_decision"] = permit

    permit_store = MdosStore(tmp_path / "permit-ledger.sqlite3", actor_registry={})
    service = G2ShadowPreflightService(permit_store=permit_store)
    result = service.evaluate(fixture)
    replay = service.evaluate(fixture)
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert result["status"] == "READY_PROPOSAL_EFFECT_DENIED"
    assert result["permit"]["supplied"] is True
    assert result["permit"]["exact_persisted"] is False
    assert result["permit"]["local_denial_audit_recorded"] is True
    assert result["permit"]["effect_decision"] == "DENY"
    assert "PERMIT_NOT_EXACT_PERSISTED" in result["permit"]["reason_codes"]
    assert "PERMIT_EFFECT_SCOPE_MISMATCH" not in result["permit"]["reason_codes"]
    assert "PERMIT_PROFILE_BINDING_MISMATCH" not in result["permit"]["reason_codes"]
    assert "UNRATIFIED_SHADOW_DESIGN_ONLY" in result["permit"]["reason_codes"]
    assert result["permit"]["permit_decision_sha256"] == value_sha256(permit)
    assert permit["permit_decision_id"] not in serialized
    assert result["created_truth"]["permit_decision"] == 0
    assert replay == result
    assert permit_store.records("PERMIT_DECISION") == []
    assert len(permit_store.denials()) == 1
    assert permit_store.denials()[0]["reason_code"] == "G2_PREFLIGHT_PERMIT_DENIED"
    permit_store.verify_integrity()


@pytest.mark.parametrize("permit_value", [[], {}])
def test_nonmapping_or_schema_invalid_permit_is_never_exact_persisted(
    permit_value: object,
) -> None:
    fixture = deepcopy(load_preflight_fixture(DEALER_FIXTURE))
    fixture["permit_decision"] = permit_value
    result = G2ShadowPreflightService().evaluate(fixture)
    assert result["status"] == "READY_PROPOSAL_EFFECT_DENIED"
    assert result["permit"]["exact_persisted"] is False
    assert result["permit"]["effect_decision"] == "DENY"
    assert "PERMIT_CONTRACT_INVALID" in result["permit"]["reason_codes"]


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("purpose", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("policy", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("currency", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("product", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("region", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("beachhead", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("capacity", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("legal_basis", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("subject", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("issuer", "PERMIT_EFFECT_SCOPE_MISMATCH"),
        ("evidence", "PERMIT_PROFILE_BINDING_MISMATCH"),
    ],
)
def test_each_exact_permit_boundary_mismatch_remains_denied(
    mutation: str, expected_reason: str
) -> None:
    fixture = deepcopy(load_preflight_fixture(DEALER_FIXTURE))
    permit = _synthetic_permit(fixture)
    if mutation == "purpose":
        permit["purpose"] = "WRONG_PURPOSE"
    elif mutation == "policy":
        permit["policy_version"] = "wrong-policy"
    elif mutation == "currency":
        permit["currency"] = "USD"
    elif mutation == "product":
        permit["scope"]["product_scope"] = ["OTHER_PRODUCT"]
    elif mutation == "region":
        permit["scope"]["region"] = "FIXTURE_REGION_OTHER"
    elif mutation == "beachhead":
        permit["scope"]["beachhead_profile_ref"] = "forged-beachhead"
    elif mutation == "capacity":
        permit["capacity_snapshot_ref"] = "fixture:capacity-other"
    elif mutation == "legal_basis":
        permit["legal_basis_ref"] = "OTHER_BASIS"
    elif mutation == "subject":
        permit["subject_refs"] = ["fixture:account-other"]
    elif mutation == "issuer":
        permit["issued_by"] = "fixture-human-other-policy"
    else:
        permit["evidence_refs"].append("g2-extra-sha256:" + "f" * 64)
    permit["payload_sha256"] = record_digest_excluding(permit, "payload_sha256")
    fixture["permit_decision"] = permit

    result = G2ShadowPreflightService().evaluate(fixture)
    assert result["status"] == "READY_PROPOSAL_EFFECT_DENIED"
    assert result["permit"]["exact_persisted"] is False
    assert result["permit"]["effect_decision"] == "DENY"
    assert expected_reason in result["permit"]["reason_codes"]


def test_existing_region_is_required_before_human_gold_review() -> None:
    fixture = deepcopy(load_preflight_fixture(EXISTING_FIXTURE))
    del fixture["candidate"]["region"]
    result = G2ShadowPreflightService().evaluate(fixture)
    assert result["status"] == "NEEDS_HUMAN_VERIFICATION_EFFECT_DENIED"
    assert result["candidate"]["missing_fields"] == ["region"]
    assert result["candidate"]["next_action"] == "HUMAN_VERIFY"
    assert result["permit"]["effect_decision"] == "DENY"


@pytest.mark.parametrize(
    ("day_offset", "expected_status"),
    [
        (-1, "DENIED"),
        (0, "READY_PROPOSAL_EFFECT_DENIED"),
        (366, "READY_PROPOSAL_EFFECT_DENIED"),
        (367, "DENIED"),
    ],
)
def test_dealer_requested_date_is_bounded_to_evaluation_plus_366_days(
    day_offset: int, expected_status: str
) -> None:
    fixture = deepcopy(load_preflight_fixture(DEALER_FIXTURE))
    requested = date(2026, 8, 25) + timedelta(days=day_offset)
    fixture["candidate"]["requested_date"] = requested.isoformat()
    result = G2ShadowPreflightService().evaluate(fixture)
    assert result["status"] == expected_status
    assert result["permit"]["effect_decision"] == "DENY"


@pytest.mark.parametrize(
    ("raw_fixture_id", "expected_status"),
    [
        ("fixture:person-name-possibly-sensitive", "READY_PROPOSAL_EFFECT_DENIED"),
        ("person@example.invalid", "DENIED"),
    ],
)
def test_fixture_id_is_validated_then_hashed_before_any_local_audit(
    tmp_path: Path, raw_fixture_id: str, expected_status: str
) -> None:
    fixture = deepcopy(load_preflight_fixture(EXISTING_FIXTURE))
    fixture["fixture_id"] = raw_fixture_id
    store = MdosStore(
        tmp_path / (value_sha256(raw_fixture_id) + ".sqlite3"), actor_registry={}
    )
    result = G2ShadowPreflightService(permit_store=store).evaluate(fixture)
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    denials = store.denials()
    assert result["status"] == expected_status
    assert result["fixture_id"].startswith("fixture:g2-preflight-")
    assert raw_fixture_id not in serialized
    assert len(denials) == 1
    assert denials[0]["trace_id"] == result["fixture_id"]
    assert raw_fixture_id not in json.dumps(denials, ensure_ascii=False, sort_keys=True)
    store.verify_integrity()


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_raw",
        "effect_count",
        "privacy",
        "created_truth",
        "permit_allow",
        "permit_reason_raw",
        "package",
        "profile",
        "status",
        "candidate_raw",
    ],
)
def test_bundle_rejects_resealed_fabricated_or_raw_result_fields(mutation: str) -> None:
    results = [G2ShadowPreflightService().evaluate(fixture) for fixture in _fixtures()]
    forged = deepcopy(results)
    result = forged[0]
    if mutation == "extra_raw":
        result["raw_pii"] = "private"
    elif mutation == "effect_count":
        result["external_effect_count"] = 1
    elif mutation == "privacy":
        result["privacy"]["raw_pii_included"] = True
    elif mutation == "created_truth":
        result["created_truth"]["gold_acceptance"] = 1
    elif mutation == "permit_allow":
        result["permit"]["effect_decision"] = "ALLOW"
    elif mutation == "permit_reason_raw":
        result["permit"]["reason_codes"].append("person@example.invalid")
    elif mutation == "package":
        result["package_version"] = "forged"
    elif mutation == "profile":
        result["profile_binding"]["profile_sha256"] = "0" * 64
    elif mutation == "status":
        result["status"] = "EXECUTED"
    else:
        result["candidate"]["raw_request_text"] = "private"
    _reseal_result(result)
    with pytest.raises(G2PreflightError):
        build_preflight_bundle(forged)


def test_bundle_rejects_unsealed_duplicate_or_noncanonical_results(
    tmp_path: Path,
) -> None:
    results = [G2ShadowPreflightService().evaluate(fixture) for fixture in _fixtures()]
    unsealed = deepcopy(results)
    unsealed[0]["external_effect_count"] = 1
    with pytest.raises(G2PreflightError, match="seal mismatch"):
        build_preflight_bundle(unsealed)

    duplicate = deepcopy(results)
    duplicate[1]["fixture_id"] = duplicate[0]["fixture_id"]
    _reseal_result(duplicate[1])
    with pytest.raises(G2PreflightError, match="unique exact three-profile"):
        build_preflight_bundle(duplicate)

    with pytest.raises(G2PreflightError, match="unique exact three-profile"):
        build_preflight_bundle(results[:2])

    bundle = build_preflight_bundle(list(reversed(results)))
    assert bundle["results"] == sorted(results, key=lambda item: item["fixture_id"])
    bundle["results"].reverse()
    _reseal_bundle(bundle)
    with pytest.raises(G2PreflightError, match="canonically sorted"):
        write_content_addressed_bundle(tmp_path / "unsorted.json", bundle)

    extra = build_preflight_bundle(results)
    extra["raw_candidate"] = "private"
    _reseal_bundle(extra)
    with pytest.raises(G2PreflightError, match="fields are not exact"):
        write_content_addressed_bundle(tmp_path / "raw.json", extra)


def test_fixture_loader_and_bundle_keep_exact_non_kpi_classification() -> None:
    fixtures = _fixtures()
    results = [G2ShadowPreflightService().evaluate(fixture) for fixture in fixtures]
    bundle = build_preflight_bundle(results)
    assert bundle["classification"] == CLASSIFICATION
    assert bundle["canonical_kpi_eligible"] is False
    assert bundle["independent_verification"] is False
    assert bundle["limitations"] == list(PREFLIGHT_LIMITATIONS)
    assert bundle["external_effect_count"] == 0
    assert bundle["bundle_sha256"] == value_sha256(
        {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    )
