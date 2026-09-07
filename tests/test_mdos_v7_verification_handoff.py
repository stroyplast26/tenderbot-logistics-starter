from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from lead_factory.mdos_v7.contracts import canonical_json_bytes, record_digest_excluding
import lead_factory.mdos_v7.verification_handoff as handoff


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT
    / "lead_factory"
    / "mdos_v7"
    / "local_schemas"
    / "verification-handoff.schema.json"
)
TEMPLATE_PATH = (
    ROOT
    / "lead_factory"
    / "mdos_v7"
    / "templates"
    / "verification-handoff.unsigned.json"
)
RUNNER_PATH = ROOT / "scripts" / "run_mdos_v7_verification_handoff.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reseal(bundle: dict[str, object]) -> dict[str, object]:
    bundle["bundle_sha256"] = record_digest_excluding(bundle, "bundle_sha256")
    return bundle


def _copy_workspace(destination: Path) -> Path:
    shutil.copytree(
        ROOT / "docs" / "market_demand_os_v7",
        destination / "docs" / "market_demand_os_v7",
    )
    delivery = destination / "docs" / "market_demand_os_v7_delivery"
    delivery.mkdir(parents=True)
    for name in ("g2-motion-profiles.json", "implementation-trace-overlay.json"):
        shutil.copy2(ROOT / "docs" / "market_demand_os_v7_delivery" / name, delivery / name)
    shutil.copytree(
        ROOT / "reports" / "market_demand_os_v7",
        destination / "reports" / "market_demand_os_v7",
    )
    state = destination / "state"
    state.mkdir()
    shutil.copy2(
        ROOT / "state" / "mdos_v7_external_freeze.json",
        state / "mdos_v7_external_freeze.json",
    )
    return destination


def _rewrite_json(path: Path, mutate) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _copy_coherent_workspace(destination: Path) -> Path:
    copied = _copy_workspace(destination)
    summary_path = copied / handoff._REPORT_PATHS["TEST_SUMMARY"]

    def bind_summary(value: dict[str, object]) -> None:
        evidence = value["evidence"]
        assert isinstance(evidence, dict)
        for key, relative_path in handoff._SUMMARY_EVIDENCE_KEYS.items():
            evidence[key] = {
                "path": relative_path,
                "sha256": _sha256(copied / relative_path),
            }

    _rewrite_json(summary_path, bind_summary)
    report_hashes = {
        relative_path: _sha256(copied / relative_path)
        for relative_path in handoff._REPORT_PATHS.values()
    }
    overlay_path = copied / handoff._OVERLAY_PATH

    def bind_overlay(value: dict[str, object]) -> None:
        observation = value["verification_observation"]
        assert isinstance(observation, dict)
        observation["evidence_catalog"] = [
            {
                "ref": f"EVIDENCE:{relative_path}",
                "sha256": digest,
            }
            for relative_path, digest in sorted(report_hashes.items())
        ]

    _rewrite_json(overlay_path, bind_overlay)
    return copied


def _replace_with_same_root_symlink(path: Path) -> None:
    target = path.with_name(f"{path.name}.real")
    path.rename(target)
    try:
        path.symlink_to(target.name, target_is_directory=False)
    except OSError as exc:
        target.rename(path)
        pytest.skip(f"local symlink creation is unavailable: {type(exc).__name__}")


@pytest.mark.skipif(os.name != "nt", reason="Windows timestamp regression")
def test_read_bytes_tolerates_windows_handle_ctime_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "stable-input.bin"
    expected = b"stable payload"
    path.write_bytes(expected)
    real_fstat = os.fstat
    calls = 0

    def drifting_fstat(fd: int) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = real_fstat(fd)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns,
            st_ctime_ns=metadata.st_ctime_ns + calls,
            st_birthtime_ns=getattr(
                metadata,
                "st_birthtime_ns",
                metadata.st_ctime_ns,
            ),
        )

    monkeypatch.setattr(handoff.os, "fstat", drifting_fstat)
    payload, digest, _ = handoff._read_bytes(
        path,
        "WINDOWS_CTIME_REGRESSION",
        boundary=tmp_path,
    )

    assert calls == 4
    assert payload == expected
    assert digest == hashlib.sha256(expected).hexdigest()


@pytest.mark.skipif(os.name != "nt", reason="Windows timestamp regression")
def test_read_bytes_second_read_rejects_same_metadata_payload_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "mutable-input.bin"
    path.write_bytes(b"first-payload")
    original_metadata = path.stat()
    real_assert_no_indirection = handoff._assert_no_indirection
    checks = 0

    def mutate_before_recheck(candidate: Path, boundary: Path) -> None:
        nonlocal checks
        real_assert_no_indirection(candidate, boundary)
        checks += 1
        if checks == 2:
            candidate.write_bytes(b"other-payload")
            os.utime(
                candidate,
                ns=(
                    original_metadata.st_atime_ns,
                    original_metadata.st_mtime_ns,
                ),
            )

    monkeypatch.setattr(
        handoff,
        "_assert_no_indirection",
        mutate_before_recheck,
    )
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="WINDOWS_PAYLOAD_REGRESSION:CHANGED_AFTER_READ",
    ):
        handoff._read_bytes(
            path,
            "WINDOWS_PAYLOAD_REGRESSION",
            boundary=tmp_path,
        )
    assert path.stat().st_size == original_metadata.st_size
    assert path.stat().st_mtime_ns == original_metadata.st_mtime_ns


def test_schema_is_strict_draft_2020_12_and_draft_is_not_ready() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == handoff.SCHEMA_ID
    assert schema["additionalProperties"] is False
    report_scope = schema["$defs"]["scope"]["properties"]["report_artifacts"]
    assert report_scope["minItems"] == report_scope["maxItems"] == 9
    assert "G1_SPLIT_PAYMENT" in schema["$defs"]["reportArtifact"][
        "properties"
    ]["artifact_id"]["enum"]

    draft = handoff.load_unsigned_template()
    assert draft["status"] == handoff.DRAFT_BINDING_PENDING
    assert draft["snapshot_at_utc"] is None
    assert draft["bundle_sha256"] == handoff.ZERO_SHA256
    with pytest.raises(handoff.VerificationHandoffError, match="HANDOFF_NOT_READY"):
        handoff.validate_ready_handoff(draft)


def test_builder_is_deterministic_exact_and_never_claims_verification() -> None:
    before = {
        path: _sha256(ROOT / path)
        for path in (
            "docs/market_demand_os_v7_delivery/implementation-trace-overlay.json",
            "reports/market_demand_os_v7/test-summary.json",
            "state/mdos_v7_external_freeze.json",
        )
    }
    first = handoff.build_verification_handoff()
    second = handoff.build_verification_handoff()
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert first["status"] == handoff.READY_FOR_INDEPENDENT_REVIEW
    assert first["classification"] == handoff.CLASSIFICATION
    assert first["owner_preflight_state"] == "NOT_RATIFIED"
    assert first["open_p0_nonclaim_count"] == 36
    assert first["prerequisites_satisfied"] is False
    assert first["production_release_eligible"] is False
    assert first["bundle_sha256"] == record_digest_excluding(
        first, "bundle_sha256"
    )
    assert first["package_binding"] == {
        "contract_id": "AK-MDOS-V7",
        "package_version": "7.1.0-rc.1",
        "package_root_sha256": (
            "d4da97bd47ed1bf76a52826a852e3a158611d18adf32a901b814a864e862d97e"
        ),
        "active_beachhead_profile": None,
        "ratification": None,
    }
    assert set(first["authority"].values()) == {False}
    assert set(first["claims"].values()) == {False}
    assert set(first["effects"].values()) == {0}
    assert first["p0_nonclaims"]["normative_p0_count"] == 36
    assert len(first["p0_nonclaims"]["requirement_ids"]) == 36
    assert all(
        first["p0_nonclaims"][field] is False
        for field in (
            "all_p0_implemented",
            "all_p0_tested",
            "all_p0_evidenced",
            "all_p0_independently_verified",
            "normative_completion_claimed",
        )
    )
    verifier = first["separation_of_duties"]["future_independent_verifier"]
    assert verifier == {
        "required_role": "IndependentEvidenceVerifier",
        "must_be_distinct_from_implementer": True,
        "identity_ref": None,
        "public_key_fingerprint_sha256": None,
        "signature_algorithm": None,
        "signature_b64": None,
        "signed_bundle_sha256": None,
        "verification_status": "NOT_PRESENT",
    }
    assert len(first["scope"]["report_artifacts"]) == 9
    split_payment = next(
        artifact
        for artifact in first["scope"]["report_artifacts"]
        if artifact["artifact_id"] == "G1_SPLIT_PAYMENT"
    )
    assert split_payment["path"] == (
        "reports/market_demand_os_v7/g1-split-payment-shadow-evidence.json"
    )
    for artifact in first["scope"]["report_artifacts"]:
        assert artifact["sha256"] == _sha256(ROOT / artifact["path"])
    assert first["scope"]["profile_artifact"]["file_sha256"] == _sha256(
        ROOT / first["scope"]["profile_artifact"]["path"]
    )
    assert first["scope"]["overlay_artifact"]["sha256"] == _sha256(
        ROOT / first["scope"]["overlay_artifact"]["path"]
    )
    assert before == {path: _sha256(ROOT / path) for path in before}


def test_content_addressed_persist_is_apply_replay_and_conflict(tmp_path: Path) -> None:
    copied = _copy_coherent_workspace(tmp_path / "repository")
    bundle = handoff.build_verification_handoff(copied)
    output = tmp_path / "handoffs"
    applied = handoff.persist_content_addressed_handoff(bundle, output, copied)
    replay = handoff.persist_content_addressed_handoff(bundle, output, copied)
    assert applied.disposition == "APPLIED"
    assert replay.disposition == "REPLAY"
    assert applied.path == replay.path
    assert applied.path.name == f"verification-handoff-{bundle['bundle_sha256']}.json"
    assert applied.path.read_bytes() == canonical_json_bytes(bundle) + b"\n"

    collision_dir = tmp_path / "collision"
    collision_dir.mkdir()
    collision = collision_dir / applied.path.name
    collision.write_bytes(b"not the canonical bundle\n")
    with pytest.raises(
        handoff.VerificationHandoffConflictError,
        match="CONTENT_ADDRESS_COLLISION",
    ):
        handoff.persist_content_addressed_handoff(bundle, collision_dir, copied)


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda value: value.update({"status": "VERIFIED"}),
            "SCHEMA_INVALID",
        ),
        (
            lambda value: value["claims"].update({"verified": True}),
            "SCHEMA_INVALID",
        ),
        (
            lambda value: value["separation_of_duties"][
                "future_independent_verifier"
            ].update(
                {
                    "identity_ref": "self-verifier",
                    "public_key_fingerprint_sha256": "1" * 64,
                    "signature_algorithm": "Ed25519",
                    "signature_b64": "ZmFrZQ==",
                    "signed_bundle_sha256": "2" * 64,
                    "verification_status": "VERIFIED",
                }
            ),
            "SCHEMA_INVALID",
        ),
        (
            lambda value: value.update({"raw_payload": "buyer@example.test"}),
            "SCHEMA_INVALID",
        ),
        (
            lambda value: value["p0_nonclaims"]["requirement_ids"].pop(),
            "SCHEMA_INVALID",
        ),
    ],
)
def test_status_signature_raw_payload_and_p0_promotions_fail_closed(
    mutate, expected: str
) -> None:
    bundle = copy.deepcopy(handoff.build_verification_handoff())
    mutate(bundle)
    _reseal(bundle)
    with pytest.raises(handoff.VerificationHandoffError, match=expected):
        handoff.validate_ready_handoff(bundle)


def test_self_digest_and_exact_artifact_hash_tamper_fail_closed() -> None:
    bundle = handoff.build_verification_handoff()
    unsealed = copy.deepcopy(bundle)
    unsealed["scope"]["overlay_artifact"]["sha256"] = "f" * 64
    with pytest.raises(
        handoff.VerificationHandoffError, match="BUNDLE_SELF_DIGEST_MISMATCH"
    ):
        handoff.validate_ready_handoff(unsealed)

    resealed = _reseal(unsealed)
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="WORKSPACE_ARTIFACT_BINDING_MISMATCH",
    ):
        handoff.validate_ready_handoff(resealed)


def test_missing_or_changed_report_invalidates_existing_handoff(tmp_path: Path) -> None:
    bundle = handoff.build_verification_handoff()
    copied = _copy_workspace(tmp_path / "repository")
    handoff.validate_ready_handoff(bundle, copied)

    report = copied / "reports" / "market_demand_os_v7" / "g2-outbox-evidence.json"
    report.unlink()
    with pytest.raises(
        handoff.VerificationHandoffError, match="REPORT_MISSING_OR_INVALID:G2_OUTBOX"
    ):
        handoff.validate_ready_handoff(bundle, copied)


def test_missing_split_payment_report_fails_closed(tmp_path: Path) -> None:
    copied = _copy_workspace(tmp_path / "repository")
    split_report = (
        copied
        / "reports"
        / "market_demand_os_v7"
        / "g1-split-payment-shadow-evidence.json"
    )
    split_report.unlink()
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="REPORT_MISSING_OR_INVALID:G1_SPLIT_PAYMENT",
    ):
        handoff.build_verification_handoff(copied)


@pytest.mark.parametrize(
    "relative_path",
    [
        "docs/market_demand_os_v7/CONTRACT.md",
        "docs/market_demand_os_v7_delivery/g2-motion-profiles.json",
        "docs/market_demand_os_v7_delivery/implementation-trace-overlay.json",
        "reports/market_demand_os_v7/g1-shadow-evidence.json",
    ],
)
def test_required_input_same_root_symlink_or_reparse_is_rejected(
    tmp_path: Path,
    relative_path: str,
) -> None:
    copied = _copy_workspace(tmp_path / "repository")
    _replace_with_same_root_symlink(copied / relative_path)
    with pytest.raises(
        handoff.VerificationHandoffError, match="ARTIFACT_INDIRECTION_FORBIDDEN"
    ):
        handoff.build_verification_handoff(copied)


def test_report_mutated_after_its_semantic_read_is_denied(
    tmp_path: Path,
    monkeypatch,
) -> None:
    copied = _copy_coherent_workspace(tmp_path / "repository")
    original = handoff._load_object_with_sha256
    mutated = False

    def mutate_after_read(path: Path, code: str, *, boundary: Path):
        nonlocal mutated
        result = original(path, code, boundary=boundary)
        if path.name == "g1-shadow-evidence.json" and not mutated:
            path.write_bytes(path.read_bytes() + b" ")
            mutated = True
        return result

    monkeypatch.setattr(handoff, "_load_object_with_sha256", mutate_after_read)
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="WORKSPACE_INPUT_CHANGED_DURING_VALIDATION",
    ):
        handoff.build_verification_handoff(copied)
    assert mutated is True


def test_workspace_mutation_after_prevalidation_removes_applied_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    copied = _copy_coherent_workspace(tmp_path / "repository")
    bundle = handoff.build_verification_handoff(copied)
    report = (
        copied
        / "reports"
        / "market_demand_os_v7"
        / "g0-suppression-evidence.json"
    )
    output = tmp_path / "handoffs"
    original = handoff._open_exclusive

    def mutate_before_open(path: Path):
        report.write_bytes(report.read_bytes() + b" ")
        return original(path)

    monkeypatch.setattr(handoff, "_open_exclusive", mutate_before_open)
    with pytest.raises(handoff.VerificationHandoffError):
        handoff.persist_content_addressed_handoff(bundle, output, copied)
    assert list(output.glob("verification-handoff-*.json")) == []


def test_output_directory_indirection_is_denied(
    tmp_path: Path,
) -> None:
    copied = _copy_coherent_workspace(tmp_path / "repository")
    bundle = handoff.build_verification_handoff(copied)
    real = tmp_path / "real-output"
    real.mkdir()
    indirect = tmp_path / "indirect-output"
    try:
        indirect.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"local directory symlink is unavailable: {type(exc).__name__}")

    with pytest.raises(
        handoff.VerificationHandoffError,
        match="OUTPUT_DIRECTORY_INDIRECTION_FORBIDDEN",
    ):
        handoff.persist_content_addressed_handoff(
            bundle,
            indirect / "nested",
            copied,
        )
    assert list(real.rglob("verification-handoff-*.json")) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_output_directory_junction_is_denied(tmp_path: Path) -> None:
    copied = _copy_coherent_workspace(tmp_path / "repository")
    bundle = handoff.build_verification_handoff(copied)
    real = tmp_path / "real-junction-output"
    real.mkdir()
    junction = tmp_path / "junction-output"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(real)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("local junction creation is unavailable")
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="OUTPUT_DIRECTORY_INDIRECTION_FORBIDDEN",
    ):
        handoff.persist_content_addressed_handoff(
            bundle,
            junction / "nested",
            copied,
        )
    assert list(real.rglob("verification-handoff-*.json")) == []


def test_replay_path_replaced_during_read_never_returns_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    copied = _copy_coherent_workspace(tmp_path / "repository")
    bundle = handoff.build_verification_handoff(copied)
    output = tmp_path / "handoffs"
    handoff.persist_content_addressed_handoff(bundle, output, copied)
    original = handoff._read_bytes
    replaced = False

    def replace_after_read(path: Path, code: str, *, boundary: Path):
        nonlocal replaced
        result = original(path, code, boundary=boundary)
        if code == "CONTENT_ADDRESS_REPLAY_READ" and not replaced:
            replacement = path.with_name(f"{path.name}.replacement")
            replacement.write_bytes(result[0])
            os.replace(replacement, path)
            replaced = True
        return result

    monkeypatch.setattr(handoff, "_read_bytes", replace_after_read)
    with pytest.raises(
        handoff.VerificationHandoffConflictError,
        match="CONTENT_ADDRESS_REPLAY_CHANGED",
    ):
        handoff.persist_content_addressed_handoff(bundle, output, copied)
    assert replaced is True


def test_report_status_overlay_authority_and_p0_drift_fail_closed(
    tmp_path: Path,
) -> None:
    bundle = handoff.build_verification_handoff()

    report_root = _copy_workspace(tmp_path / "report-status")
    report = report_root / "reports" / "market_demand_os_v7" / "g0-suppression-evidence.json"
    _rewrite_json(report, lambda value: value.update({"status": "VERIFIED"}))
    with pytest.raises(
        handoff.VerificationHandoffError, match="REPORT_STATUS_PROMOTION"
    ):
        handoff.validate_ready_handoff(bundle, report_root)

    classification_root = _copy_workspace(tmp_path / "report-classification")
    classification_report = (
        classification_root
        / "reports"
        / "market_demand_os_v7"
        / "g0-suppression-evidence.json"
    )
    _rewrite_json(
        classification_report,
        lambda value: value.update({"classification": "CANONICAL_KPI"}),
    )
    with pytest.raises(
        handoff.VerificationHandoffError, match="REPORT_CLASSIFICATION_DRIFT"
    ):
        handoff.validate_ready_handoff(bundle, classification_root)

    split_root = _copy_workspace(tmp_path / "split-payment-authority")
    split_report = (
        split_root
        / "reports"
        / "market_demand_os_v7"
        / "g1-split-payment-shadow-evidence.json"
    )
    _rewrite_json(
        split_report,
        lambda value: value["authority"].update(
            {"canonical_kpi_eligible": True}
        ),
    )
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="SPLIT_PAYMENT_AUTHORITY_OR_EFFECT_PROMOTION",
    ):
        handoff.validate_ready_handoff(bundle, split_root)

    split_nonclaim_root = _copy_workspace(tmp_path / "split-payment-nonclaim")
    split_nonclaim_report = (
        split_nonclaim_root
        / "reports"
        / "market_demand_os_v7"
        / "g1-split-payment-shadow-evidence.json"
    )
    _rewrite_json(
        split_nonclaim_report,
        lambda value: value["nonclaims"].remove(
            "It performs no external reads, writes, contact, or spend."
        ),
    )
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="SPLIT_PAYMENT_ZERO_EFFECT_NONCLAIM_MISSING",
    ):
        handoff.validate_ready_handoff(bundle, split_nonclaim_root)

    overlay_root = _copy_workspace(tmp_path / "overlay-authority")
    overlay = (
        overlay_root
        / "docs"
        / "market_demand_os_v7_delivery"
        / "implementation-trace-overlay.json"
    )
    _rewrite_json(
        overlay,
        lambda value: value["authority"].update(
            {"production_release_eligible": True}
        ),
    )
    with pytest.raises(
        handoff.VerificationHandoffError, match="OVERLAY_STATUS_PROMOTION"
    ):
        handoff.validate_ready_handoff(bundle, overlay_root)

    p0_root = _copy_workspace(tmp_path / "p0-drift")
    p0_overlay = (
        p0_root
        / "docs"
        / "market_demand_os_v7_delivery"
        / "implementation-trace-overlay.json"
    )
    _rewrite_json(
        p0_overlay,
        lambda value: value["p0_completion_statement"][
            "p0_requirements_not_claimed_complete"
        ].pop(),
    )
    with pytest.raises(
        handoff.VerificationHandoffError, match="OVERLAY_P0_NONCLAIM_SET_DRIFT"
    ):
        handoff.validate_ready_handoff(bundle, p0_root)


@pytest.mark.parametrize(
    ("case", "expected_issue"),
    (
        ("missing", "OWNER_INTENT_CAPTURE_MISSING_OR_PROMOTED"),
        ("active_cell", "OWNER_INTENT_CELL_DRIFT"),
        ("actor_authority", "OWNER_INTENT_ACTOR_SOD_DRIFT"),
        ("bitrix_payment", "OWNER_INTENT_BITRIX_MILESTONE_DRIFT"),
        ("payment_source", "OWNER_INTENT_PAYMENT_SOURCE_DRIFT"),
    ),
)
def test_owner_intent_report_is_bound_as_non_authority(
    tmp_path: Path,
    case: str,
    expected_issue: str,
) -> None:
    copied = _copy_coherent_workspace(tmp_path / case)
    bundle = handoff.build_verification_handoff(copied)
    report = copied / handoff._REPORT_PATHS["G2_OWNER_PREFLIGHT"]

    def mutate(value: dict[str, object]) -> None:
        if case == "missing":
            value.pop("owner_intent_capture")
            return
        intent = value["owner_intent_capture"]
        assert isinstance(intent, dict)
        if case == "active_cell":
            cell = intent["proposed_first_cell"]
            assert isinstance(cell, dict)
            cell["active"] = True
        elif case == "actor_authority":
            actor = intent["human_actor"]
            assert isinstance(actor, dict)
            actor["independent_verifier"] = True
        elif case == "bitrix_payment":
            milestone = intent["bitrix_contract_milestone"]
            assert isinstance(milestone, dict)
            milestone["creates_payment_proof"] = True
        elif case == "payment_source":
            intent["preferred_future_payment_source"] = "PAYMENT_PROVIDER_API"
        else:  # pragma: no cover - parametrization is closed above
            raise AssertionError(case)

    _rewrite_json(report, mutate)
    with pytest.raises(handoff.VerificationHandoffError, match=expected_issue):
        handoff.validate_ready_handoff(bundle, copied)


@pytest.mark.parametrize(
    "case",
    (
        "missing",
        "status_regression",
        "payment_forgery",
        "real_stage_claim",
        "truth_mutation",
    ),
)
def test_crm_contract_milestone_proof_preserves_payment_source_hierarchy(
    tmp_path: Path,
    case: str,
) -> None:
    copied = _copy_coherent_workspace(tmp_path / f"crm-{case}")
    bundle = handoff.build_verification_handoff(copied)
    report = copied / handoff._REPORT_PATHS["G1_SHADOW"]

    def mutate(value: dict[str, object]) -> None:
        if case == "missing":
            value.pop("crm_contract_milestone_proof")
            return
        proof = value["crm_contract_milestone_proof"]
        assert isinstance(proof, dict)
        if case == "status_regression":
            proof["effective_application_status"] = (
                "CONTRACT_SIGNED_AWAITING_PAYMENT"
            )
        elif case == "payment_forgery":
            proof["payment_proof_ref"] = "payment-forged-from-crm"
        elif case == "real_stage_claim":
            proof["real_stage_code_present"] = True
        elif case == "truth_mutation":
            proof["commercial_truth_unchanged"] = False
        else:  # pragma: no cover - parametrization is closed above
            raise AssertionError(case)

    _rewrite_json(report, mutate)
    with pytest.raises(
        handoff.VerificationHandoffError,
        match="CRM_CONTRACT_MILESTONE_PROOF_MISSING_OR_DRIFTED",
    ):
        handoff.validate_ready_handoff(bundle, copied)


def test_local_schema_and_template_digest_drift_are_denied(monkeypatch) -> None:
    monkeypatch.setattr(handoff, "_SCHEMA_SHA256", "f" * 64)
    with pytest.raises(
        handoff.VerificationHandoffError, match="LOCAL_SCHEMA_DIGEST_DRIFT"
    ):
        handoff.load_unsigned_template()

    monkeypatch.setattr(handoff, "_SCHEMA_SHA256", _sha256(SCHEMA_PATH))
    monkeypatch.setattr(handoff, "_TEMPLATE_SHA256", "f" * 64)
    with pytest.raises(
        handoff.VerificationHandoffError, match="UNSIGNED_TEMPLATE_DIGEST_DRIFT"
    ):
        handoff.load_unsigned_template()


def test_runner_applies_replays_and_validates_local_bundle(tmp_path: Path) -> None:
    command = [
        sys.executable,
        str(RUNNER_PATH),
        "--output-directory",
        str(tmp_path),
    ]
    first = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    first_result = json.loads(first.stdout)
    assert first_result["disposition"] == "APPLIED"
    assert first_result["bundle_status"] == "READY_FOR_INDEPENDENT_REVIEW"
    assert first_result["owner_preflight_state"] == "NOT_RATIFIED"
    assert first_result["open_p0_nonclaim_count"] == 36
    assert first_result["independent_verification"] is False
    assert first_result["production_release_eligible"] is False
    assert first_result["authority_mutation_allowed"] is False
    assert first_result["external_effect_count"] == 0

    replay = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(replay.stdout)["disposition"] == "REPLAY"

    validate = subprocess.run(
        [sys.executable, str(RUNNER_PATH), "--validate", first_result["path"]],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(validate.stdout)["disposition"] == "VALID"


def test_owned_artifact_references_and_template_are_exact() -> None:
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    assert template == handoff.load_unsigned_template()
    assert template["traceability"]["code_refs"] == [
        "CODE:lead_factory/mdos_v7/verification_handoff.py",
        "CODE:lead_factory/mdos_v7/local_schemas/verification-handoff.schema.json",
        "CODE:lead_factory/mdos_v7/templates/verification-handoff.unsigned.json",
        "CODE:scripts/run_mdos_v7_verification_handoff.py",
    ]
    assert template["traceability"]["test_refs"] == [
        "TEST:tests/test_mdos_v7_verification_handoff.py"
    ]
