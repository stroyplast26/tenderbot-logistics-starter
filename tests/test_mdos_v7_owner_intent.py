from __future__ import annotations

import copy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

import lead_factory.mdos_v7.owner_intent as owner_intent_module
from lead_factory.mdos_v7.g2 import G2MotionRegistry
from lead_factory.mdos_v7.owner_intent import (
    CAPTURED_NOT_RATIFIED,
    INVALID_NOT_AUTHORITY,
    OwnerIntentAuthorityDenied,
    OwnerIntentDraftError,
    assert_owner_intent_live_activation_allowed,
    assess_owner_intent_draft,
    load_captured_owner_intent_draft,
    require_captured_owner_intent,
    seal_owner_intent_draft,
    serialized_owner_intent_draft,
)


PRIVATE_VALUES = (
    "Дима",
    "owner-private@example.invalid",
    "+7 999 111-22-33",
    "Свяжитесь с клиентом по частному запросу",
)


def _sealed_copy(record: dict[str, object]) -> dict[str, object]:
    return seal_owner_intent_draft(record)


def test_checked_in_owner_intent_is_exact_sealed_and_never_authority() -> None:
    first = load_captured_owner_intent_draft()
    second = load_captured_owner_intent_draft()
    assessment = require_captured_owner_intent(first)

    assert first == second
    assert seal_owner_intent_draft(first) == first
    assert assessment.state == CAPTURED_NOT_RATIFIED
    assert assessment.content_sha256 == first["seal"]["content_sha256"]
    assert assessment.authority_capability == "NONE"
    assert assessment.ratified is False
    assert assessment.activation_allowed is False
    assert assessment.external_reads_allowed is False
    assert assessment.external_writes_allowed is False
    assert assessment.contact_allowed is False
    assert assessment.spend_allowed is False
    assert assessment.live_bitrix_reads_allowed is False
    assert assessment.live_bitrix_writes_allowed is False
    assert set(first["authority_effect"].values()) == {False}


def test_owner_semantics_and_delivery_defaults_are_unambiguous() -> None:
    draft = load_captured_owner_intent_draft()

    assert draft["commercial_intent"]["intent_class"] == "STRATEGIC_INTENT_ONLY"
    assert draft["commercial_intent"]["motion_ids"] == [
        "EXISTING_ACCOUNT_EXPANSION",
        "DEALER_AND_INSTALLER_ACTIVATION",
        "HIGH_INTENT_INBOUND",
    ]
    assert draft["commercial_intent"]["geography_intent"] == (
        "GLOBAL_WHERE_LAWFUL_AND_FULFILLABLE"
    )
    assert draft["commercial_intent"]["active_all_region_beachhead"] is False
    assert draft["proposed_first_cell"] == {
        "profile_state": "OWNER_PROPOSED_NOT_ACTIVE",
        "motion_id": "EXISTING_ACCOUNT_EXPANSION",
        "product_scope_id": "ALUMINIUM_WINDOWS",
        "region_code": "RU-MOS",
        "region_semantics": "MOSCOW_OBLAST_ONLY",
        "fulfilment_model_id": "FACTORY_DELIVERY_NO_INSTALLATION",
        "fulfilment_assumption_state": "PROPOSED_PENDING_OWNER_CONFIRMATION",
        "installation_scope": "EXCLUDED",
        "installation_required_cases_disposition": "OUT_OF_SCOPE",
        "allowed_channel_ids": ["FIXTURE_SHADOW"],
        "proposal_origin": "CONSERVATIVE_DELIVERY_DEFAULT",
        "owner_confirmation_state": "PENDING_EXACT_RATIFICATION",
        "active": False,
        "live_eligible": False,
    }
    assert draft["shadow_capacity"] == {
        "limit_class": "SHADOW_REVIEW_QUEUE_LIMITS",
        "scope": "FIXTURE_SHADOW_ONLY",
        "cohort_total_cap": 5,
        "daily_review_cap": 1,
        "max_wip": 1,
        "human_review_required": True,
        "send_mode": "NO_SEND",
        "production_capacity_claimed": False,
        "capacity_evidence_state": "PENDING_OWNER_INPUT",
    }

    actor = draft["human_actor_assignments"][0]
    assert actor["actor_ref"] == "ACTOR_CLIENT_PARTNER_01"
    assert actor["owner_asserted_role_ids"] == ["GOLD_REVIEWER"]
    assert actor["candidate_role_ids"] == ["SALES_OPERATOR"]
    assert actor["raw_identity_retained"] is False
    for forbidden_authority in (
        "arbitrator",
        "may_review_own_originated_case",
        "policy_authority",
        "payment_truth_authority",
        "independent_verifier",
        "release_authority",
    ):
        assert actor[forbidden_authority] is False


def test_bank_api_is_pending_and_bitrix_contract_is_not_payment() -> None:
    draft = load_captured_owner_intent_draft()
    payment = draft["payment_intent"]
    milestone = draft["bitrix_contract_milestone"]

    assert payment["preferred_future_source_type"] == "BANK_API"
    assert payment["format_state"] == "PENDING_OWNER_INPUT"
    assert payment["provider_state"] == "UNKNOWN"
    assert payment["accepted_payment_truth_source_types"] == [
        "BANK_API",
        "PAYMENT_PROVIDER",
        "SIGNED_BANK_STATEMENT",
    ]
    assert payment["one_c_dependency"] == "NONE"
    assert payment["bitrix_is_payment_truth"] is False
    assert payment["credentials_present"] is False
    assert milestone["source_system_role"] == "PROJECTION_ONLY"
    assert milestone["source_event"] == "CONTRACT_SIGNED"
    assert milestone["application_status"] == "CONTRACT_SIGNED_AWAITING_PAYMENT"
    assert milestone["exact_stage_code"] == "UNKNOWN"
    assert milestone["payment_status"] == "NOT_PROVEN"
    assert milestone["payment_truth_effect"] == "NONE"
    assert milestone["creates_payment_proof"] is False
    assert milestone["changes_order_paid_state"] is False
    assert milestone["canonical_kpi_eligible"] is False
    assert milestone["live_read_performed"] is False
    assert milestone["live_write_performed"] is False


def test_existing_winback_binding_matches_current_g2_registry_exactly() -> None:
    draft = load_captured_owner_intent_draft()
    expected = asdict(
        G2MotionRegistry().binding("G2-MOTION-EXISTING-WINBACK")
    )
    expected["profile_file_ref"] = (
        "docs/market_demand_os_v7_delivery/g2-motion-profiles.json"
    )

    assert draft["g2_profile_binding"] == expected
    assert draft["g2_profile_binding"]["normative_motion"] == (
        draft["proposed_first_cell"]["motion_id"]
    )


def test_serialization_is_deterministic_and_contains_no_raw_identity() -> None:
    draft = load_captured_owner_intent_draft()
    reversed_draft = dict(reversed(list(draft.items())))

    assert seal_owner_intent_draft(reversed_draft)["seal"] == draft["seal"]
    serialized = serialized_owner_intent_draft(draft)
    assert serialized == json.dumps(
        draft,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    for private_value in PRIVATE_VALUES:
        assert private_value not in serialized
    assert draft["privacy_boundary"] == {
        "data_class": "NON_PII_OWNER_INTENT",
        "opaque_human_references_only": True,
        "raw_person_names_present": False,
        "raw_contact_data_present": False,
        "raw_request_text_present": False,
        "raw_chat_content_present": False,
        "analytics_contains_pii": False,
        "evidence_contains_pii": False,
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda draft: draft["shadow_capacity"].update({"cohort_total_cap": 6}),
        lambda draft: draft["commercial_intent"].update(
            {"active_all_region_beachhead": True}
        ),
        lambda draft: draft["authority_effect"].update(
            {"external_writers_enabled": True}
        ),
        lambda draft: draft["bitrix_contract_milestone"].update(
            {"payment_truth_effect": "PAID"}
        ),
        lambda draft: draft["human_actor_assignments"][0].update(
            {"independent_verifier": True}
        ),
    ],
)
def test_tamper_is_rejected_before_and_after_adversarial_reseal(mutate: object) -> None:
    draft = load_captured_owner_intent_draft()
    mutate(draft)

    before_reseal = assess_owner_intent_draft(draft)
    assert before_reseal.state == INVALID_NOT_AUTHORITY
    assert "CONTENT_SHA256_MISMATCH" in before_reseal.issues

    after_reseal = assess_owner_intent_draft(_sealed_copy(draft))
    assert after_reseal.state == INVALID_NOT_AUTHORITY
    assert any(issue.startswith("SCHEMA_INVALID:") for issue in after_reseal.issues)
    assert after_reseal.activation_allowed is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_message", PRIVATE_VALUES[3]),
        ("email", PRIVATE_VALUES[1]),
        ("phone", PRIVATE_VALUES[2]),
    ],
)
def test_raw_pii_fields_fail_closed_even_when_adversary_reseals(
    field: str,
    value: str,
) -> None:
    draft = load_captured_owner_intent_draft()
    draft[field] = value
    assessment = assess_owner_intent_draft(_sealed_copy(draft))

    assert assessment.state == INVALID_NOT_AUTHORITY
    assert any(issue.startswith("SCHEMA_INVALID:") for issue in assessment.issues)
    assert any(
        issue.startswith(("RAW_IDENTITY_FIELD_FORBIDDEN:", "PII_OR_SECRET_VALUE_FORBIDDEN:"))
        for issue in assessment.issues
    )
    with pytest.raises(OwnerIntentDraftError):
        serialized_owner_intent_draft(_sealed_copy(draft))


def test_opaque_actor_cannot_be_replaced_with_a_person_label() -> None:
    draft = load_captured_owner_intent_draft()
    draft["human_actor_assignments"][0]["actor_ref"] = "DIMA"
    assessment = assess_owner_intent_draft(_sealed_copy(draft))

    assert assessment.state == INVALID_NOT_AUTHORITY
    assert any(issue.startswith("SCHEMA_INVALID:") for issue in assessment.issues)


def test_manifest_or_authority_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_manifest = load_captured_owner_intent_draft()
    wrong_manifest["contract_binding"]["manifest_sha256"] = "f" * 64
    wrong_manifest_assessment = assess_owner_intent_draft(
        _sealed_copy(wrong_manifest)
    )
    assert "MANIFEST_SHA256_MISMATCH" in wrong_manifest_assessment.issues

    captured = load_captured_owner_intent_draft()
    monkeypatch.setattr(
        owner_intent_module,
        "authority_snapshot",
        lambda: (_ for _ in ()).throw(ValueError("authority drift")),
    )
    authority_assessment = assess_owner_intent_draft(captured)
    assert "UNRATIFIED_AUTHORITY_BASELINE_INVALID" in authority_assessment.issues
    assert authority_assessment.state == INVALID_NOT_AUTHORITY


def test_schema_drift_and_live_activation_are_unconditionally_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = load_captured_owner_intent_draft()
    monkeypatch.setattr(owner_intent_module, "_SCHEMA_SHA256", "0" * 64)
    assessment = assess_owner_intent_draft(captured)
    assert "LOCAL_SCHEMA_DIGEST_DRIFT" in assessment.issues
    assert assessment.state == INVALID_NOT_AUTHORITY

    with pytest.raises(
        OwnerIntentAuthorityDenied,
        match="OWNER_INTENT_DRAFT_NEVER_AUTHORIZES_LIVE",
    ):
        assert_owner_intent_live_activation_allowed(captured)


def test_assessment_does_not_mutate_callers_and_non_objects_fail_closed() -> None:
    draft = load_captured_owner_intent_draft()
    before = copy.deepcopy(draft)
    assess_owner_intent_draft(draft)
    assert draft == before

    assessment = assess_owner_intent_draft([])
    assert assessment.state == INVALID_NOT_AUTHORITY
    assert "OWNER_INTENT_RECORD_NOT_OBJECT" in assessment.issues
    with pytest.raises(TypeError, match="record must be a mapping"):
        seal_owner_intent_draft([])  # type: ignore[arg-type]


def test_cyclic_mapping_is_invalid_not_authority_without_recursion_error() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    assessment = assess_owner_intent_draft(cyclic)

    assert assessment.state == INVALID_NOT_AUTHORITY
    assert assessment.content_sha256 is None
    assert assessment.issues == ("CYCLIC_STRUCTURE_FORBIDDEN",)
    assert assessment.activation_allowed is False
    with pytest.raises(OwnerIntentDraftError, match="CYCLIC_STRUCTURE_FORBIDDEN"):
        seal_owner_intent_draft(cyclic)


def test_loader_rejects_nested_duplicate_keys_before_dict_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate = tmp_path / "duplicate-owner-intent.json"
    duplicate.write_text(
        '{"outer":{"source_kind":"FIRST","source_kind":"SECOND"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(owner_intent_module, "_TEMPLATE_PATH", duplicate)

    with pytest.raises(
        OwnerIntentDraftError,
        match="CAPTURED_TEMPLATE_DUPLICATE_JSON_KEY",
    ):
        load_captured_owner_intent_draft()


def test_loader_calls_full_validation_and_rejects_resealed_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tampered = load_captured_owner_intent_draft()
    tampered["authority_effect"]["contact_enabled"] = True
    tampered = seal_owner_intent_draft(tampered)
    path = tmp_path / "tampered-owner-intent.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    monkeypatch.setattr(owner_intent_module, "_TEMPLATE_PATH", path)

    with pytest.raises(OwnerIntentDraftError, match="SCHEMA_INVALID"):
        load_captured_owner_intent_draft()


def test_schema_and_profile_nested_duplicates_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = load_captured_owner_intent_draft()
    duplicate_schema = tmp_path / "duplicate-schema.json"
    schema_bytes = b'{"type":"object","nested":{"type":"object","type":"array"}}'
    duplicate_schema.write_bytes(schema_bytes)
    monkeypatch.setattr(owner_intent_module, "_SCHEMA_PATH", duplicate_schema)
    monkeypatch.setattr(
        owner_intent_module,
        "_SCHEMA_SHA256",
        hashlib.sha256(schema_bytes).hexdigest(),
    )
    schema_assessment = assess_owner_intent_draft(captured)
    assert "LOCAL_SCHEMA_DUPLICATE_JSON_KEY" in schema_assessment.issues

    monkeypatch.undo()
    duplicate_profile = tmp_path / "duplicate-profile.json"
    duplicate_profile.write_text(
        '{"outer":{"profile_id":"FIRST","profile_id":"SECOND"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(owner_intent_module, "PROFILE_PATH", duplicate_profile)
    profile_assessment = assess_owner_intent_draft(captured)
    assert "G2_PROFILE_SET_DUPLICATE_JSON_KEY" in profile_assessment.issues

    monkeypatch.undo()
    duplicate_manifest = tmp_path / "duplicate-manifest.json"
    duplicate_manifest.write_text(
        '{"binding":{"contract_id":"FIRST","contract_id":"SECOND"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        owner_intent_module,
        "_MANIFEST_PATH",
        duplicate_manifest,
    )
    manifest_assessment = assess_owner_intent_draft(captured)
    assert "MANIFEST_DUPLICATE_JSON_KEY" in manifest_assessment.issues


def test_single_read_guard_detects_symlink_and_toctou(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template_path = Path(owner_intent_module._TEMPLATE_PATH)
    read_calls = 0
    real_read = os.read

    def counted_read(descriptor: int, count: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return real_read(descriptor, count)

    monkeypatch.setattr(owner_intent_module.os, "read", counted_read)
    assert owner_intent_module._read_regular_file_once(
        template_path,
        "TEST_TEMPLATE",
    )
    assert read_calls == 1
    monkeypatch.undo()

    symlink = tmp_path / "owner-intent-link.json"
    try:
        symlink.symlink_to(template_path)
    except OSError:
        symlink = None
    if symlink is not None:
        with pytest.raises(OwnerIntentDraftError, match="NON_REGULAR_OR_REPARSE"):
            owner_intent_module._read_regular_file_once(symlink, "TEST_TEMPLATE")

    real_fstat = os.fstat
    fstat_calls = 0

    def drifting_fstat(descriptor: int) -> object:
        nonlocal fstat_calls
        fstat_calls += 1
        metadata = real_fstat(descriptor)
        if fstat_calls == 2:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_mode=metadata.st_mode,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns + 1,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )
        return metadata

    monkeypatch.setattr(owner_intent_module.os, "fstat", drifting_fstat)
    with pytest.raises(OwnerIntentDraftError, match="TOCTOU_DETECTED"):
        owner_intent_module._read_regular_file_once(template_path, "TEST_TEMPLATE")


def test_all_owner_intent_dependency_files_use_bounded_single_read_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = (
        Path(owner_intent_module._SCHEMA_PATH),
        Path(owner_intent_module._TEMPLATE_PATH),
        Path(owner_intent_module._MANIFEST_PATH),
        Path(owner_intent_module.PROFILE_PATH),
    )
    real_read = os.read
    read_calls = 0

    def counted_read(descriptor: int, count: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return real_read(descriptor, count)

    monkeypatch.setattr(owner_intent_module.os, "read", counted_read)
    for index, path in enumerate(paths):
        assert owner_intent_module._read_regular_file_once(
            path,
            f"DEPENDENCY_{index}",
        )
    assert read_calls == len(paths)


def test_reparse_guard_is_fail_closed_for_every_dependency_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = (
        Path(owner_intent_module._SCHEMA_PATH),
        Path(owner_intent_module._TEMPLATE_PATH),
        Path(owner_intent_module._MANIFEST_PATH),
        Path(owner_intent_module.PROFILE_PATH),
    )
    monkeypatch.setattr(owner_intent_module, "_is_reparse_point", lambda _: True)

    for index, path in enumerate(paths):
        with pytest.raises(OwnerIntentDraftError, match="REPARSE"):
            owner_intent_module._read_regular_file_once(
                path,
                f"DEPENDENCY_{index}",
            )


def _copied_contract_package(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    repository_root = tmp_path / "repository"
    source = Path(__file__).resolve().parents[1] / "docs" / "market_demand_os_v7"
    destination = repository_root / "docs" / "market_demand_os_v7"
    destination.parent.mkdir(parents=True)
    shutil.copytree(source, destination)
    manifest = json.loads(
        (destination / "contract-manifest.json").read_text(encoding="utf-8")
    )
    assert isinstance(manifest, dict)
    return repository_root, manifest


def test_safe_package_bytes_match_contract_registry_exactly(tmp_path: Path) -> None:
    repository_root, manifest = _copied_contract_package(tmp_path)

    assert owner_intent_module._exact_package_issues(
        manifest,
        repository_root,
    ) == ()


def test_tampered_package_artifact_is_rejected_even_with_claimed_root(
    tmp_path: Path,
) -> None:
    repository_root, manifest = _copied_contract_package(tmp_path)
    artifact = (
        repository_root
        / "docs"
        / "market_demand_os_v7"
        / "CONTRACT.md"
    )
    artifact.write_bytes(artifact.read_bytes() + b"\nTAMPERED\n")

    content_tamper = owner_intent_module._exact_package_issues(
        manifest,
        repository_root,
    )
    assert any(
        issue.startswith("PACKAGE_ARTIFACT_DIGEST_MISMATCH:")
        for issue in content_tamper
    )
    assert "CONTRACT_REGISTRY_PACKAGE_VERIFICATION_FAILED" in content_tamper

    tampered_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
    contract_entry = next(
        item
        for item in manifest["normative_documents"]
        if item["path"] == "docs/market_demand_os_v7/CONTRACT.md"
    )
    contract_entry["sha256"] = tampered_sha256
    manifest_path = (
        repository_root
        / "docs"
        / "market_demand_os_v7"
        / "contract-manifest.json"
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    rebound_digest_but_claimed_root = owner_intent_module._exact_package_issues(
        manifest,
        repository_root,
    )
    assert "PACKAGE_ROOT_SHA256_MISMATCH" in rebound_digest_but_claimed_root
    assert (
        "CONTRACT_REGISTRY_PACKAGE_VERIFICATION_FAILED"
        in rebound_digest_but_claimed_root
    )


def test_parent_directory_symlink_is_rejected_before_file_open(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    (real_parent / "record.json").write_text("{}", encoding="utf-8")
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(OwnerIntentDraftError, match="PARENT_REPARSE_FORBIDDEN"):
        owner_intent_module._read_regular_file_once(
            linked_parent / "record.json",
            "PARENT_LINK_TEST",
        )
