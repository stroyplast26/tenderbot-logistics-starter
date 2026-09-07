from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.run_mdos_v7_owner_preflight import ROOT, _write_atomic, build_report


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_unsigned_owner_preflight_evidence_is_privacy_safe_and_non_authoritative(
    tmp_path: Path,
) -> None:
    report = build_report()

    assert report["status"] == "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
    assert report["classification"] == "LOCAL_UNSIGNED_PREFLIGHT_NON_AUTHORITY"
    assert report["assessment"]["state"] == "NOT_RATIFIED"
    assert report["assessment"]["ready_for_independent_review"] is False
    assert report["assessment"]["verified_roles"] == []
    assert report["assessment"]["artifact_resolution_present"] is False
    assert report["assessment"]["artifact_bytes_verified"] is False
    assert report["assessment"]["raw_owner_packet_included"] is False
    assert report["assessment"]["pii_or_credentials_included"] is False
    assert report["authority"] == {
        "external_reads_enabled": False,
        "external_writers_enabled": False,
        "contact_enabled": False,
        "spend_enabled": False,
        "live_bitrix_writes_enabled": False,
        "authority_mutation_allowed": False,
        "activation_allowed": False,
        "live_activation_probe_denial": "OWNER_PREFLIGHT_NEVER_AUTHORIZES_LIVE",
    }
    assert report["independent_evidence_verifier"] is None
    assert report["assessment"]["issue_code_counts"][
        "ARTIFACT_BYTES_NOT_VERIFIED"
    ] == 1
    assert report["assessment"]["issue_code_counts"]["OWNER_INPUT_PENDING"] > 0
    assert report["assessment"]["issue_code_counts"][
        "TRUSTED_ROLE_KEYS_REQUIRED_OUT_OF_BAND"
    ] == 1
    intent = report["owner_intent_capture"]
    assert intent["state"] == "CAPTURED_NOT_RATIFIED"
    assert intent["authority_capability"] == "NONE"
    assert intent["ratified"] is False
    assert intent["activation_allowed"] is False
    assert intent["strategic_motion_ids"] == [
        "EXISTING_ACCOUNT_EXPANSION",
        "DEALER_AND_INSTALLER_ACTIVATION",
        "HIGH_INTENT_INBOUND",
    ]
    assert intent["proposed_first_cell"]["profile_state"] == (
        "OWNER_PROPOSED_NOT_ACTIVE"
    )
    assert intent["proposed_first_cell"]["region_code"] == "RU-MOS"
    assert intent["proposed_first_cell"]["region_semantics"] == (
        "MOSCOW_OBLAST_ONLY"
    )
    assert intent["proposed_first_cell"]["active"] is False
    assert intent["shadow_review_queue_limits"]["limit_class"] == (
        "SHADOW_REVIEW_QUEUE_LIMITS"
    )
    assert intent["shadow_review_queue_limits"]["production_capacity_claimed"] is False
    assert intent["human_actor"]["actor_ref"] == "ACTOR_CLIENT_PARTNER_01"
    assert intent["human_actor"]["raw_identity_retained"] is False
    assert intent["human_actor"]["independent_verifier"] is False
    assert intent["preferred_future_payment_source"] == "BANK_API"
    assert intent["payment_format_state"] == "PENDING_OWNER_INPUT"
    assert intent["bitrix_contract_milestone"]["source_event"] == "CONTRACT_SIGNED"
    assert intent["bitrix_contract_milestone"]["application_status"] == (
        "CONTRACT_SIGNED_AWAITING_PAYMENT"
    )
    assert intent["bitrix_contract_milestone"]["exact_stage_code"] == "UNKNOWN"
    assert intent["bitrix_contract_milestone"]["payment_truth_effect"] == "NONE"
    assert set(intent["authority_effect"].values()) == {False}
    assert intent["raw_owner_chat_included"] is False
    assert intent["pii_or_credentials_included"] is False
    assert intent["live_activation_probe_denial"] == (
        "OWNER_INTENT_DRAFT_NEVER_AUTHORIZES_LIVE"
    )
    assert "payload" not in report
    assert "attestations" not in report
    expected_owner_artifacts = {
        "owner_artifact_module": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "owner_artifacts.py",
        "owner_artifact_manifest_schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-artifact-bundle-manifest.schema.json",
        "owner_artifact_envelope_schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-artifact-envelope.schema.json",
        "owner_artifact_tests": ROOT
        / "tests"
        / "test_mdos_v7_owner_artifacts.py",
        "owner_intent_module": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "owner_intent.py",
        "owner_intent_schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-intent-draft.schema.json",
        "owner_intent_template": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "templates"
        / "owner-intent-draft.captured-not-ratified.json",
        "owner_intent_tests": ROOT
        / "tests"
        / "test_mdos_v7_owner_intent.py",
    }
    for name, path in expected_owner_artifacts.items():
        assert report["artifact_digests"][name] == _sha256(path)

    output = tmp_path / "owner-preflight-evidence.json"
    _write_atomic(output, report)
    first = output.read_bytes()
    _write_atomic(output, report)
    assert output.read_bytes() == first
    assert json.loads(first) == report
