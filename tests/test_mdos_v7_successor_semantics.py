from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from lead_factory.mdos_v7.successor_semantics import (
    MANDATORY_TELEPHONY_STOP_CONDITIONS,
    RATIFICATION_NORMATIVE_ARTIFACTS,
    SuccessorSemanticError,
    compute_ratification_binding_sha256,
    validate_ratification_record_semantics,
    validate_telephony_pilot_semantics,
)


PACKAGE_ROOT = "a" * 64
CANDIDATE_MANIFEST = "b" * 64
BEACHHEAD = "PROPOSED-BEACHHEAD-AL-WINDOWS-RU-MOS-DELIVERY"


def _sealed_ref(name: str) -> dict[str, str]:
    return {
        "uri": f"evidence://ratification/{name}",
        "sha256": hashlib.sha256(name.encode()).hexdigest(),
    }


def _pilot() -> dict[str, object]:
    return {
        "status": "DRAFT_NOT_RATIFIED",
        "max_duration_hours": 24,
        "operator_actor": "actor-operator",
        "controller_actor": "actor-controller",
        "stop_conditions": list(MANDATORY_TELEPHONY_STOP_CONDITIONS),
        "starts_at_utc": "2026-09-01T08:00:00Z",
        "expires_at_utc": "2026-09-02T08:00:00Z",
    }


def _ratification() -> dict[str, object]:
    roles = (
        "BusinessOwner",
        "ContractAuthority",
        "PrivacyLegalOwner",
        "IndependentEvidenceVerifier",
    )
    record: dict[str, object] = {
        "contract_id": "AK-MDOS-V7",
        "package_version": "7.2.0-rc.1",
        "package_root_sha256": PACKAGE_ROOT,
        "ratified_candidate_manifest_sha256": CANDIDATE_MANIFEST,
        "active_beachhead_profile_id": BEACHHEAD,
        "normative_artifacts": {
            name: _sealed_ref(name) for name in RATIFICATION_NORMATIVE_ARTIFACTS
        },
        "independent_verification_ref": _sealed_ref("independent-verification"),
        "ratified_at_utc": "2026-09-01T20:00:00Z",
    }
    binding = compute_ratification_binding_sha256(record)
    record["ratification_binding_sha256"] = binding
    record["independent_verification_binding_sha256"] = binding
    record["approvals"] = {
        role: {
            "role": role,
            "actor_ref": f"actor-{index}",
            "key_id": f"key-{index}",
            "signed_binding_sha256": binding,
            "signature_ref": _sealed_ref(f"signature-{index}"),
            "approved_at_utc": f"2026-09-01T1{index}:00:00Z",
        }
        for index, role in enumerate(roles, 1)
    }
    return record


def _validate_ratification(record: dict[str, object]) -> None:
    validate_ratification_record_semantics(
        record,
        expected_package_root_sha256=PACKAGE_ROOT,
        expected_candidate_manifest_sha256=CANDIDATE_MANIFEST,
        expected_beachhead_profile_id=BEACHHEAD,
    )


def test_telephony_pilot_semantics_accept_exact_24_hour_draft() -> None:
    validate_telephony_pilot_semantics(_pilot())


def test_telephony_pilot_semantics_reject_one_year_hidden_behind_24_hour_field() -> None:
    pilot = _pilot()
    pilot["expires_at_utc"] = "2027-09-01T08:00:00Z"
    with pytest.raises(SuccessorSemanticError, match="exceeds the 24-hour limit"):
        validate_telephony_pilot_semantics(pilot)


def test_telephony_pilot_requires_distinct_operator_and_controller() -> None:
    pilot = _pilot()
    pilot["controller_actor"] = pilot["operator_actor"]
    with pytest.raises(SuccessorSemanticError, match="must be distinct"):
        validate_telephony_pilot_semantics(pilot)


def test_telephony_pilot_requires_exact_stop_condition_set() -> None:
    pilot = _pilot()
    pilot["stop_conditions"] = [f"unrelated-{index}" for index in range(12)]
    with pytest.raises(SuccessorSemanticError, match="exact mandatory stop condition set"):
        validate_telephony_pilot_semantics(pilot)


def test_ratification_semantics_require_distinct_actors_keys_and_signatures() -> None:
    valid = _ratification()
    _validate_ratification(valid)

    duplicate_actor = deepcopy(valid)
    duplicate_actor["approvals"]["ContractAuthority"]["actor_ref"] = "actor-1"
    with pytest.raises(SuccessorSemanticError, match="actors must be distinct"):
        _validate_ratification(duplicate_actor)

    duplicate_key = deepcopy(valid)
    duplicate_key["approvals"]["PrivacyLegalOwner"]["key_id"] = "key-1"
    with pytest.raises(SuccessorSemanticError, match="keys must be distinct"):
        _validate_ratification(duplicate_key)

    duplicate_signature = deepcopy(valid)
    duplicate_signature["approvals"]["PrivacyLegalOwner"]["signature_ref"] = deepcopy(
        duplicate_signature["approvals"]["BusinessOwner"]["signature_ref"]
    )
    with pytest.raises(SuccessorSemanticError, match="signature refs must be distinct"):
        _validate_ratification(duplicate_signature)


@pytest.mark.parametrize(
    ("field", "error"),
    [
        ("package_root_sha256", "package root binding drift"),
        ("ratified_candidate_manifest_sha256", "candidate manifest binding drift"),
        ("active_beachhead_profile_id", "beachhead binding drift"),
    ],
)
def test_ratification_semantics_reject_exact_candidate_binding_drift(
    field: str,
    error: str,
) -> None:
    record = _ratification()
    record[field] = "c" * 64 if field != "active_beachhead_profile_id" else "other"
    with pytest.raises(SuccessorSemanticError, match=error):
        _validate_ratification(record)


def test_ratification_semantics_bind_mandatory_artifacts_and_approval_time() -> None:
    wrong_verification_binding = _ratification()
    wrong_verification_binding["independent_verification_binding_sha256"] = "c" * 64
    with pytest.raises(SuccessorSemanticError, match="independent verification binding drift"):
        _validate_ratification(wrong_verification_binding)

    missing_artifact = _ratification()
    missing_artifact["normative_artifacts"].pop("economics")
    with pytest.raises(SuccessorSemanticError, match="mandatory normative artifact set"):
        _validate_ratification(missing_artifact)

    late_approval = _ratification()
    late_approval["approvals"]["BusinessOwner"]["approved_at_utc"] = (
        "2026-09-01T21:00:00Z"
    )
    with pytest.raises(SuccessorSemanticError, match="cannot precede an approval"):
        _validate_ratification(late_approval)

    mutable_evidence = _ratification()
    mutable_evidence["independent_verification_ref"] = {
        "uri": "https://evidence.invalid/latest"
    }
    with pytest.raises(SuccessorSemanticError, match=r"immutable uri\+sha256"):
        _validate_ratification(mutable_evidence)
