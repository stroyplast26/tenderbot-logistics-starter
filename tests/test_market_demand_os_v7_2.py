from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lead_factory.mdos_v7.successor_semantics import (
    MANDATORY_TELEPHONY_STOP_CONDITIONS,
    RATIFICATION_NORMATIVE_ARTIFACTS,
    SuccessorSemanticError,
    compute_ratification_binding_sha256,
    validate_ratification_record_semantics,
    validate_telephony_pilot_semantics,
)


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "market_demand_os_v7_2"
MANIFEST = PACKAGE / "contract-manifest.json"
RELEASE_PIN = PACKAGE / "release-pin.json"
ARTIFACT_COLLECTIONS = (
    "normative_documents",
    "schemas",
    "registries",
    "evidence_artifacts",
    "advisory_documents",
)
LIVE_GATES = {
    "bitrix": False,
    "mango": False,
    "mail": False,
    "unisender": False,
    "tenderplan": False,
}
PROPOSED_BEACHHEAD = {
    "id": "PROPOSED-BEACHHEAD-AL-WINDOWS-RU-MOS-DELIVERY",
    "status": "PROPOSED_NOT_ACTIVE",
    "motion_id": "EXISTING_ACCOUNT_EXPANSION",
    "product_scope_id": "ALUMINIUM_WINDOWS",
    "region_code": "RU-MOS",
    "fulfilment_model_id": "FACTORY_DELIVERY_NO_INSTALLATION",
    "installation_scope": "EXCLUDED",
    "source_ref": "docs/market_demand_os_v7_2/evidence/ratification-readiness.json",
}


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def sealed_ref(name: str) -> dict[str, str]:
    return {
        "uri": f"evidence://ratification/{name}",
        "sha256": hashlib.sha256(name.encode()).hexdigest(),
    }


def load_package_builder() -> object:
    path = ROOT / "scripts" / "build_market_demand_os_v7_2_package.py"
    spec = importlib.util.spec_from_file_location("mdos_v72_builder_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schema_validator(schema_name: str) -> Draft202012Validator:
    schema = load(PACKAGE / "schemas" / schema_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validation_errors(instance: dict[str, object], schema_name: str) -> list[object]:
    return list(schema_validator(schema_name).iter_errors(instance))


def validate(instance: dict[str, object], schema_name: str) -> None:
    errors = sorted(validation_errors(instance, schema_name), key=lambda error: list(error.path))
    assert not errors, "\n".join(error.message for error in errors)


def manifest_artifacts(manifest: dict[str, object]) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for collection in ARTIFACT_COLLECTIONS:
        entries = manifest[collection]
        assert isinstance(entries, list) and entries
        assert all(isinstance(item, dict) for item in entries)
        artifacts.extend(entries)
    return artifacts


def assert_test_binding_exists(binding: str) -> None:
    assert binding.startswith("TEST:"), binding
    relative_path, separator, symbol = binding.removeprefix("TEST:").partition("#")
    target = ROOT / relative_path
    assert target.exists(), binding
    if not separator:
        return
    assert target.is_file() and target.suffix == ".py", binding
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
    if "." not in symbol:
        assert any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol
            for node in tree.body
        ), binding
        return
    class_name, method_name = symbol.rsplit(".", 1)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    assert len(classes) == 1, binding
    assert any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name
        for node in classes[0].body
    ), binding


def assert_evidence_binding_exists(binding: str) -> None:
    assert binding.startswith("EVIDENCE:"), binding
    relative_path = binding.removeprefix("EVIDENCE:").partition("#")[0]
    assert (ROOT / relative_path).is_file(), binding


def assert_code_binding_exists(binding: str) -> None:
    assert binding.startswith("CODE:"), binding
    relative_path, separator, symbol = binding.removeprefix("CODE:").partition("#")
    target = ROOT / relative_path
    assert target.is_file(), binding
    if not separator:
        return
    assert target.suffix == ".py" and symbol, binding
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
    if "." not in symbol:
        declared = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        }
        declared.update(
            target.id
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
            )
            if isinstance(target, ast.Name)
        )
        assert symbol in declared, binding
        return
    class_name, method_name = symbol.rsplit(".", 1)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    assert len(classes) == 1, binding
    assert any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name
        for node in classes[0].body
    ), binding


def test_mdos_v72_all_json_schemas_are_meta_valid_and_manifest_is_valid() -> None:
    schema_paths = sorted((PACKAGE / "schemas").glob("*.schema.json"))
    assert len(schema_paths) == 29
    for path in schema_paths:
        schema = load(path)
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema.get("additionalProperties") is False

    manifest = load(MANIFEST)
    validate(manifest, "contract-manifest.schema.json")
    assert manifest["contract_id"] == "AK-MDOS-V7"
    assert manifest["package_version"] == "7.2.0-rc.2"
    assert manifest["status"] == "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION"


def test_mdos_v72_exact_artifact_digests_and_canonical_package_root() -> None:
    manifest = load(MANIFEST)
    artifacts = manifest_artifacts(manifest)
    assert len(artifacts) == 45
    assert len({str(item["id"]) for item in artifacts}) == 45
    assert len({str(item["path"]) for item in artifacts}) == 45

    digest_items: list[dict[str, str]] = []
    for item in artifacts:
        relative_path = str(item["path"])
        target = ROOT / relative_path
        assert target.is_file(), relative_path
        assert sha(target) == item["sha256"], relative_path
        digest_items.append({"path": relative_path, "sha256": str(item["sha256"])})

    canonical = json.dumps(
        {"artifacts": sorted(digest_items, key=lambda item: item["path"])},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == manifest["package_root_sha256"]


def test_mdos_v72_builder_emits_platform_independent_lf_bytes(tmp_path: Path) -> None:
    builder = load_package_builder()
    pretty_path = tmp_path / "pretty.json"
    compact_path = tmp_path / "compact.json"
    builder.write_json_atomic(pretty_path, {"z": 1, "a": 2})
    builder.write_json_atomic(compact_path, {"z": 1, "a": 2}, compact=True)
    assert pretty_path.read_bytes() == b'{\n  "a": 2,\n  "z": 1\n}\n'
    assert compact_path.read_bytes() == b'{"a":2,"z":1}\n'


def test_mdos_v72_release_pin_is_exact_and_default_deny() -> None:
    manifest = load(MANIFEST)
    pin = load(RELEASE_PIN)
    validate(pin, "release-pin.schema.json")
    assert pin == {
        "schema_version": "1.0.0",
        "record_type": "EXACT_RELEASE_PIN",
        "contract_id": "AK-MDOS-V7",
        "package_version": "7.2.0-rc.2",
        "package_dir": "docs/market_demand_os_v7_2",
        "manifest_path": "docs/market_demand_os_v7_2/contract-manifest.json",
        "manifest_sha256": sha(MANIFEST),
        "package_root_sha256": manifest["package_root_sha256"],
        "artifact_count": 45,
        "authority_status": "DEFAULT_DENY_NOT_RATIFIED",
        "live_gates": LIVE_GATES,
    }


def test_mdos_v72_registry_coverage_statuses_and_bindings_are_honest() -> None:
    manifest = load(MANIFEST)
    requirements = load(PACKAGE / "registries" / "requirements-registry.json")
    acceptance = load(PACKAGE / "registries" / "acceptance-manifest.json")
    traceability = load(PACKAGE / "registries" / "traceability-registry.json")
    validate(requirements, "requirement-registry.schema.json")
    validate(acceptance, "acceptance-manifest.schema.json")
    validate(traceability, "traceability-registry.schema.json")

    requirement_re = re.compile(r"\*\*(MDOS-[A-Z0-9-]+-[0-9]{3})\.\*\*")
    acceptance_re = re.compile(r"^\| `(AT-[A-Z0-9-]+-[0-9]{2})` \|", re.MULTILINE)
    declared_requirements: set[str] = set()
    declared_acceptance: set[str] = set()
    for item in manifest["normative_documents"]:
        text = (ROOT / str(item["path"])).read_text(encoding="utf-8")
        found_requirements = set(requirement_re.findall(text))
        found_acceptance = set(acceptance_re.findall(text))
        assert not declared_requirements.intersection(found_requirements)
        assert not declared_acceptance.intersection(found_acceptance)
        declared_requirements.update(found_requirements)
        declared_acceptance.update(found_acceptance)

    requirement_rows = requirements["requirements"]
    acceptance_rows = acceptance["acceptance_cases"]
    assert isinstance(requirement_rows, list)
    assert isinstance(acceptance_rows, list)
    assert len(requirement_rows) == len(declared_requirements) == 244
    assert len(acceptance_rows) == len(declared_acceptance) == 113
    assert {str(item["id"]) for item in requirement_rows} == declared_requirements
    assert {str(item["id"]) for item in acceptance_rows} == declared_acceptance

    for requirement in requirement_rows:
        assert requirement["status"] not in {"VERIFIED", "PRODUCTION_PROVEN"}
        if requirement["status"] == "IMPLEMENTED":
            assert requirement["code_bindings"], requirement["id"]
            assert requirement["test_bindings"], requirement["id"]
            assert requirement["evidence_refs"], requirement["id"]
        for binding in requirement["test_bindings"]:
            assert_test_binding_exists(str(binding))
    assert all(item["execution_status"] != "VERIFIED" for item in acceptance_rows)
    for acceptance_case in acceptance_rows:
        for binding in acceptance_case["test_bindings"]:
            assert_test_binding_exists(str(binding))


def test_mdos_v72_all_operator_acceptance_is_bound_but_not_verified() -> None:
    acceptance = load(PACKAGE / "registries" / "acceptance-manifest.json")
    operator_cases = {
        str(item["id"]): item
        for item in acceptance["acceptance_cases"]
        if str(item["id"]).startswith("AT-OPT-")
    }
    implemented_cases = {f"AT-OPT-{number:02d}" for number in range(1, 15)}
    assert set(operator_cases) == implemented_cases | {"AT-OPT-15"}
    for case_id in implemented_cases:
        case = operator_cases[case_id]
        assert case["execution_status"] == "IMPLEMENTED_NOT_VERIFIED", case_id
        assert case["test_bindings"], case_id
        assert case["evidence_refs"], case_id
        for binding in case["test_bindings"]:
            assert_test_binding_exists(str(binding))
        for binding in case["evidence_refs"]:
            assert_evidence_binding_exists(str(binding))
    deferred_case = operator_cases["AT-OPT-15"]
    assert deferred_case["execution_status"] == "SPECIFIED_NOT_IMPLEMENTED"
    assert deferred_case["coverage"] == "NONE"
    assert deferred_case["test_bindings"] == []
    assert deferred_case["evidence_refs"] == []


def test_mdos_v72_operator_evidence_source_digests_are_current() -> None:
    evidence = load(PACKAGE / "evidence" / "operator-telephony-offline-evidence.json")
    validate(evidence, "release-evidence.schema.json")
    assert evidence["result"] == "PASSED"
    assert evidence["failed"] == 0
    assert evidence["external_effect_count"] == 0
    assert evidence["independent_verification"] is False
    source_digests = evidence["source_digests"]
    assert isinstance(source_digests, list) and source_digests
    for source in source_digests:
        target = ROOT / str(source["path"])
        assert target.is_file(), source["path"]
        assert sha(target) == source["sha256"], source["path"]

    inconsistent_pass = deepcopy(evidence)
    inconsistent_pass["failed"] = 1
    assert validation_errors(inconsistent_pass, "release-evidence.schema.json")

    inconsistent_failure = deepcopy(evidence)
    inconsistent_failure["result"] = "FAILED"
    assert validation_errors(inconsistent_failure, "release-evidence.schema.json")


def test_mdos_v72_beachhead_ratification_and_live_gates_fail_closed() -> None:
    manifest = load(MANIFEST)
    assert manifest["proposed_beachhead_profile"] == PROPOSED_BEACHHEAD
    assert manifest["active_beachhead_profile"] is None
    assert manifest["ratification"] is None
    assert manifest["live_gates"] == LIVE_GATES
    assert manifest["defaults_pending_ratification"] == {
        "external_reads_enabled": False,
        "external_writers_enabled": False,
        "contact_enabled": False,
        "spend_enabled": False,
        "pc10_enabled": False,
    }

    arbitrary_ratification = deepcopy(manifest)
    arbitrary_ratification["status"] = "RATIFIED"
    arbitrary_ratification["active_beachhead_profile"] = PROPOSED_BEACHHEAD["id"]
    arbitrary_ratification["ratification"] = {"approved": True}
    assert validation_errors(arbitrary_ratification, "contract-manifest.schema.json")

    for gate_name in LIVE_GATES:
        live_manifest = deepcopy(manifest)
        live_manifest["live_gates"][gate_name] = True
        assert validation_errors(live_manifest, "contract-manifest.schema.json"), gate_name

        live_pin = load(RELEASE_PIN)
        live_pin["live_gates"][gate_name] = True
        assert validation_errors(live_pin, "release-pin.schema.json"), gate_name


def test_mdos_v72_ratification_digest_names_candidate_without_self_hash_cycle() -> None:
    schema = load(PACKAGE / "schemas" / "ratification-record.schema.json")
    properties = schema["properties"]
    required = schema["required"]
    assert "ratified_candidate_manifest_sha256" in properties
    assert "ratified_candidate_manifest_sha256" in required
    assert "manifest_sha256" not in properties
    assert "manifest_sha256" not in required

    approval_time = "2026-08-31T20:00:00Z"
    approval_roles = (
        "BusinessOwner",
        "ContractAuthority",
        "PrivacyLegalOwner",
        "IndependentEvidenceVerifier",
    )
    manifest = load(MANIFEST)
    record: dict[str, object] = {
        "schema_version": "1.0.0",
        "record_type": "RATIFICATION_RECORD",
        "contract_id": "AK-MDOS-V7",
        "package_version": "7.2.0-rc.2",
        "package_root_sha256": manifest["package_root_sha256"],
        "ratified_candidate_manifest_sha256": sha(MANIFEST),
        "active_beachhead_profile_id": PROPOSED_BEACHHEAD["id"],
        "normative_artifacts": {
            name: sealed_ref(name) for name in RATIFICATION_NORMATIVE_ARTIFACTS
        },
        "independent_verification_ref": sealed_ref("independent-verification"),
        "ratified_at_utc": approval_time,
    }
    binding = compute_ratification_binding_sha256(record)
    record["ratification_binding_sha256"] = binding
    record["independent_verification_binding_sha256"] = binding
    record["approvals"] = {
        role: {
            "role": role,
            "actor_ref": f"actor:{role}",
            "key_id": f"key:{role}",
            "signed_binding_sha256": binding,
            "signature_ref": sealed_ref(f"signature-{role}"),
            "approved_at_utc": approval_time,
        }
        for role in approval_roles
    }
    validate(record, "ratification-record.schema.json")
    with pytest.raises(SuccessorSemanticError, match="package version drift"):
        validate_ratification_record_semantics(
            record,
            expected_package_root_sha256=str(manifest["package_root_sha256"]),
            expected_candidate_manifest_sha256=sha(MANIFEST),
            expected_beachhead_profile_id=str(PROPOSED_BEACHHEAD["id"]),
        )
    ratified_manifest = deepcopy(manifest)
    ratified_manifest["status"] = "RATIFIED"
    ratified_manifest["active_beachhead_profile"] = PROPOSED_BEACHHEAD["id"]
    ratified_manifest["ratification"] = record
    validate(ratified_manifest, "contract-manifest.schema.json")

    old_self_hash_field = deepcopy(record)
    old_self_hash_field["manifest_sha256"] = old_self_hash_field.pop(
        "ratified_candidate_manifest_sha256"
    )
    assert validation_errors(old_self_hash_field, "ratification-record.schema.json")

    approvals_as_unkeyed_list = deepcopy(record)
    approvals_as_unkeyed_list["approvals"] = list(record["approvals"].values())
    assert validation_errors(approvals_as_unkeyed_list, "ratification-record.schema.json")

    missing_required_role = deepcopy(record)
    missing_required_role["approvals"].pop("PrivacyLegalOwner")
    assert validation_errors(missing_required_role, "ratification-record.schema.json")

    mismatched_role = deepcopy(record)
    mismatched_role["approvals"]["BusinessOwner"]["role"] = "ContractAuthority"
    assert validation_errors(mismatched_role, "ratification-record.schema.json")

    mutable_signature = deepcopy(record)
    mutable_signature["approvals"]["BusinessOwner"]["signature_ref"] = {
        "uri": "https://evidence.invalid/signatures/latest"
    }
    assert validation_errors(mutable_signature, "ratification-record.schema.json")


def test_mdos_v72_telephony_pilot_cannot_be_live_or_exceed_one_day() -> None:
    pilot = {
        "schema_version": "1.0.0",
        "record_type": "TELEPHONY_PILOT",
        "pilot_id": "pilot:internal:1",
        "status": "DRAFT_NOT_RATIFIED",
        "contract_id": "AK-MDOS-V7",
        "package_version": "7.2.0-rc.2",
        "package_root_sha256": "a" * 64,
        "permit_ref": "https://evidence.invalid/permits/1",
        "portal_scope_id": "portal:test",
        "operator_actor": "actor:operator",
        "controller_actor": "actor:controller",
        "starts_at_utc": "2026-08-31T20:00:00Z",
        "expires_at_utc": "2026-09-01T20:00:00Z",
        "contact_scope": "INTERNAL_TEST_ONLY",
        "participant_allowlist_refs": ["https://evidence.invalid/participants/1"],
        "max_calls": 1,
        "max_wip": 1,
        "manual_checkpoint_after_calls": 1,
        "raw_download_to_lead_factory_enabled": False,
        "external_ai_enabled": False,
        "auto_dial_enabled": False,
        "tenderplan_enabled": False,
        "stop_conditions": list(MANDATORY_TELEPHONY_STOP_CONDITIONS),
        "max_duration_hours": 24,
        "stop_evidence_ref": "evidence://telephony/pilot/stop/1",
    }
    validate(pilot, "telephony-pilot.schema.json")
    validate_telephony_pilot_semantics(pilot)

    active_pilot = deepcopy(pilot)
    active_pilot["status"] = "ACTIVE"
    assert validation_errors(active_pilot, "telephony-pilot.schema.json")

    overlong_pilot = deepcopy(pilot)
    overlong_pilot["max_duration_hours"] = 25
    assert validation_errors(overlong_pilot, "telephony-pilot.schema.json")

    for flag in (
        "raw_download_to_lead_factory_enabled",
        "external_ai_enabled",
        "auto_dial_enabled",
        "tenderplan_enabled",
    ):
        live_pilot = deepcopy(pilot)
        live_pilot[flag] = True
        assert validation_errors(live_pilot, "telephony-pilot.schema.json"), flag

    wrong_stop_set = deepcopy(pilot)
    wrong_stop_set["stop_conditions"] = [f"unrelated-{index}" for index in range(12)]
    assert validation_errors(wrong_stop_set, "telephony-pilot.schema.json")

    same_actor = deepcopy(pilot)
    same_actor["controller_actor"] = same_actor["operator_actor"]
    with pytest.raises(SuccessorSemanticError, match="must be distinct"):
        validate_telephony_pilot_semantics(same_actor)


def test_mdos_v72_requirement_digests_cover_the_complete_normative_block() -> None:
    requirements = load(PACKAGE / "registries" / "requirements-registry.json")
    rows = requirements["requirements"]
    assert isinstance(rows, list)
    by_id = {row["id"]: row for row in rows}
    for row in rows:
        lines = (ROOT / row["document"]).read_text(encoding="utf-8").splitlines()
        start = row["line_start"]
        end = row["line_end"]
        assert 1 <= start <= end <= len(lines), row["id"]
        normative_block = "\n".join(lines[start - 1 : end]).strip()
        assert hashlib.sha256(normative_block.encode("utf-8")).hexdigest() == row["text_sha256"]

    multi_line = by_id["MDOS-TEL-002"]
    assert multi_line["line_end"] > multi_line["line_start"]
    lines = (ROOT / multi_line["document"]).read_text(encoding="utf-8").splitlines()
    original = "\n".join(
        lines[multi_line["line_start"] - 1 : multi_line["line_end"]]
    ).strip()
    changed = original.replace("новый receipt", "изменённый receipt")
    assert changed != original
    assert hashlib.sha256(changed.encode("utf-8")).hexdigest() != multi_line["text_sha256"]


def test_mdos_v72_baseline_overlay_cannot_promote_normative_status() -> None:
    overlay = load(PACKAGE / "evidence" / "baseline-implementation-trace-overlay.v7.1.json")
    authority = overlay["authority"]
    assert authority["normative"] is False
    assert authority["modifies_normative_registries"] is False
    assert authority["may_promote_normative_status"] is False

    requirements = load(PACKAGE / "registries" / "requirements-registry.json")["requirements"]
    acceptance = load(PACKAGE / "registries" / "acceptance-manifest.json")["acceptance_cases"]
    requirement_by_id = {row["id"]: row for row in requirements}
    acceptance_by_id = {row["id"]: row for row in acceptance}
    inherited_requirement_ids = {
        requirement_id
        for trace in overlay["trace_sets"]
        for requirement_id in trace.get("requirement_refs", [])
    }
    locally_tested_acceptance = {
        row["id"]
        for row in overlay["acceptance_overlay"]
        if row["status"] == "LOCALLY_TESTED_NOT_INDEPENDENTLY_VERIFIED"
    }
    assert all(
        requirement_by_id[requirement_id]["status"] == "DESIGNED"
        for requirement_id in inherited_requirement_ids
    )
    assert all(
        acceptance_by_id[case_id]["execution_status"] == "SPECIFIED_NOT_IMPLEMENTED"
        for case_id in locally_tested_acceptance
    )


def test_mdos_v72_operator_mapping_is_exact_and_all_code_symbols_exist() -> None:
    requirements = load(PACKAGE / "registries" / "requirements-registry.json")["requirements"]
    operator_rows = {
        row["id"]: row
        for row in requirements
        if row["id"].split("-")[1] in {"OPT", "TEL", "OPR", "PIL"}
    }
    assert len(operator_rows) == 21
    assert operator_rows["MDOS-TEL-003"]["acceptance_ids"] == ["AT-OPT-05"]
    assert operator_rows["MDOS-PIL-001"]["acceptance_ids"] == []
    assert all(len(row["acceptance_ids"]) < 14 for row in operator_rows.values())
    assert {
        row["id"] for row in operator_rows.values() if row["status"] == "IMPLEMENTED"
    } == {"MDOS-TEL-003", "MDOS-OPR-002"}
    assert operator_rows["MDOS-OPT-005"]["acceptance_ids"] == [
        "AT-OPT-15",
        "AT-MBO-06",
    ]
    non_operator_rows = [row for row in requirements if row["id"] not in operator_rows]
    linked_non_operator_rows = [row for row in non_operator_rows if row["acceptance_ids"]]
    assert linked_non_operator_rows
    assert all(
        all(str(case_id).startswith("AT-MBO-") for case_id in row["acceptance_ids"])
        for row in linked_non_operator_rows
    )
    assert {f"MDOS-MBO-{number:03d}" for number in range(1, 18)} <= {
        str(row["id"]) for row in linked_non_operator_rows
    }
    for row in requirements:
        for binding in row["code_bindings"]:
            assert_code_binding_exists(binding)


def test_mdos_v72_trace_digests_are_artifact_bytes_and_cover_acceptance() -> None:
    trace = load(PACKAGE / "registries" / "traceability-registry.json")["edges"]
    requirements = load(PACKAGE / "registries" / "requirements-registry.json")["requirements"]
    acceptance = load(PACKAGE / "registries" / "acceptance-manifest.json")["acceptance_cases"]
    acceptance_by_id = {row["id"]: row for row in acceptance}
    acceptance_sources = {edge["from_id"] for edge in trace if edge["from_kind"] == "ACCEPTANCE"}
    assert {f"AT-OPT-{number:02d}" for number in range(1, 15)} <= acceptance_sources
    assert all(edge["verification_level"] != "INDEPENDENT" for edge in trace)
    expected_requirement_acceptance = {
        (row["id"], acceptance_id)
        for row in requirements
        for acceptance_id in row["acceptance_ids"]
    }
    actual_requirement_acceptance = {
        (edge["from_id"], edge["to_id"])
        for edge in trace
        if edge["from_kind"] == "REQUIREMENT" and edge["to_kind"] == "ACCEPTANCE"
    }
    assert actual_requirement_acceptance == expected_requirement_acceptance
    linked_families = {from_id.split("-")[1] for from_id, _ in actual_requirement_acceptance}
    assert linked_families <= {
        "OPT",
        "TEL",
        "OPR",
        "PIL",
        "GOV",
        "ARC",
        "EVT",
        "STO",
        "OPS",
        "SRC",
        "PORT",
        "PRG",
        "BAS",
        "REL",
        "MBO",
    }
    assert "MBO" in linked_families

    for edge in trace:
        if edge["to_kind"] == "ACCEPTANCE":
            assert edge["to_digest"] == acceptance_by_id[edge["to_id"]]["case_sha256"]
            continue
        locator = edge["to_id"].split(":", 1)[1]
        relative_path = locator.split("#", 1)[0]
        target = ROOT / relative_path
        assert target.is_file(), edge["edge_id"]
        assert edge["to_digest"] == sha(target), edge["edge_id"]


def test_mdos_v72_mail_bitrix_observer_is_normative_design_only() -> None:
    manifest = load(MANIFEST)
    normative = {str(item["id"]): item for item in manifest["normative_documents"]}
    observer_artifact = normative["APP-MDOS-MAIL-BITRIX-OBSERVER"]
    assert observer_artifact["path"] == (
        "docs/market_demand_os_v7_2/APP-MDOS-MAIL-BITRIX-OBSERVER.md"
    )
    assert observer_artifact["version"] == "1.0.0"
    assert manifest["package_version"] == "7.2.0-rc.2"
    assert manifest["ratification"] is None
    assert manifest["live_gates"] == LIVE_GATES

    requirements = load(PACKAGE / "registries" / "requirements-registry.json")["requirements"]
    acceptance = load(PACKAGE / "registries" / "acceptance-manifest.json")["acceptance_cases"]
    requirement_by_id = {str(row["id"]): row for row in requirements}
    acceptance_by_id = {str(row["id"]): row for row in acceptance}
    observer_requirement_ids = {f"MDOS-MBO-{number:03d}" for number in range(1, 18)}
    observer_acceptance_ids = {f"AT-MBO-{number:02d}" for number in range(1, 17)}
    assert observer_requirement_ids <= set(requirement_by_id)
    assert observer_acceptance_ids <= set(acceptance_by_id)
    for requirement_id in observer_requirement_ids:
        row = requirement_by_id[requirement_id]
        assert row["owner_role"] == "InboundMailObserverOwner"
        assert row["criticality"] == "P0"
        assert row["status"] == "DESIGNED"
        assert row["implementation_coverage"] == "NONE"
        assert row["acceptance_ids"]
        assert row["code_bindings"] == []
        assert row["test_bindings"] == []
        assert row["evidence_refs"] == []
    for acceptance_id in observer_acceptance_ids:
        row = acceptance_by_id[acceptance_id]
        assert row["execution_status"] == "SPECIFIED_NOT_IMPLEMENTED"
        assert row["coverage"] == "NONE"
        assert row["test_bindings"] == []
        assert row["evidence_refs"] == []

    assert requirement_by_id["MDOS-MBO-005"]["acceptance_ids"] == [
        "AT-MBO-02",
        "AT-MBO-03",
    ]
    assert requirement_by_id["MDOS-MBO-006"]["acceptance_ids"] == [
        "AT-MBO-03",
        "AT-MBO-04",
        "AT-MBO-14",
    ]
    assert requirement_by_id["MDOS-MBO-013"]["acceptance_ids"] == ["AT-MBO-11"]
    assert requirement_by_id["MDOS-MBO-014"]["acceptance_ids"] == ["AT-MBO-12"]
    assert requirement_by_id["MDOS-MBO-015"]["acceptance_ids"] == ["AT-MBO-13"]
    assert requirement_by_id["MDOS-MBO-016"]["acceptance_ids"] == ["AT-MBO-15"]
    assert requirement_by_id["MDOS-MBO-017"]["acceptance_ids"] == ["AT-MBO-16"]
    assert requirement_by_id["MDOS-BAS-004"]["acceptance_ids"] == [
        "AT-MBO-07",
        "AT-MBO-15",
    ]
    assert requirement_by_id["MDOS-REL-003"]["acceptance_ids"] == [
        "AT-MBO-09",
        "AT-MBO-10",
    ]

    observer_text = (PACKAGE / "APP-MDOS-MAIL-BITRIX-OBSERVER.md").read_text(
        encoding="utf-8"
    )
    for phrase in (
        "единственным writer-ом",
        "IMAP READ-ONLY",
        "crm.activity.list",
        "crm.activity.get",
        "Lead`, `Todo`, `Timeline",
        "не менее пяти минут",
        "до 90 минут",
        "пять `OPERATOR_TODO` и пять",
        "MANGO, TenderPlan, UniSender, SMTP",
        "whitespace collapse/normalization",
        "OWNER_ID`/`OWNER_TYPE_ID`",
        "строго возрастающему",
        "immutable cutover receipt",
        "до и после каждого remote IMAP или",
        "DESIGN_ONLY",
    ):
        assert phrase in observer_text

    readiness = load(PACKAGE / "evidence" / "ratification-readiness.json")
    assert readiness["package_version"] == "7.2.0-rc.2"
    blockers = "\n".join(str(value) for value in readiness["blockers"])
    assert "assignment is intentionally deferred for observation" in blockers
    assert "five OPERATOR_TODO and five TIMELINE_MAIL" in blockers
    assert "MANGO, TenderPlan, UniSender/SMTP and outbound" in blockers
