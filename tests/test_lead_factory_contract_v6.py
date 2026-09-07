from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "lead_factory_contract_v6"
MANIFEST_PATH = PACKAGE / "contract-manifest.json"

ARTIFACT_COLLECTIONS = (
    "normative_documents",
    "schemas",
    "policies",
    "registries",
    "advisory_documents",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _manifest() -> dict[str, object]:
    return _json(MANIFEST_PATH)


def _validate(instance: dict[str, object], schema_name: str) -> None:
    schema = _json(PACKAGE / "schemas" / schema_name)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    assert not errors, "\n".join(error.message for error in errors)


def _artifact_entries(manifest: dict[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for collection in ARTIFACT_COLLECTIONS:
        entries = manifest[collection]
        assert isinstance(entries, list) and entries, collection
        for entry in entries:
            assert isinstance(entry, dict)
            result.append(entry)
    return result


def test_contract_v6_manifest_and_locked_artifacts_are_valid() -> None:
    manifest = _manifest()
    _validate(manifest, "contract-manifest.schema.json")

    assert manifest["contract_id"] == "LF-OUTCOME-V6"
    assert manifest["package_version"] == "6.1.0-rc.1"
    assert manifest["status"] in {
        "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION",
        "RATIFIED",
        "SUPERSEDED",
        "REVOKED",
    }

    target = manifest["target_profile"]
    assert isinstance(target, dict)
    assert target["id"] == "GCO10"
    assert target["unit"] == "AcceptedGoldenClientOpportunity"
    assert target["target_per_workday"] == 10
    assert target["evaluation_workdays"] == 30
    assert target["minimum_total"] == 300
    assert target["new_paying_clients_profile"] == "SEPARATE_NOT_ACTIVE"

    base = manifest["base_contract"]
    assert isinstance(base, dict)
    base_path = ROOT / str(base["path"])
    assert base_path.is_file()
    assert _sha256(base_path) == base["sha256"]
    assert (ROOT / str(base["import_map"])).is_file()

    artifact_ids: set[str] = set()
    artifact_paths: set[str] = set()
    digest_items: list[dict[str, str]] = []
    for artifact in _artifact_entries(manifest):
        artifact_id = str(artifact["id"])
        artifact_path = str(artifact["path"])
        assert artifact_id not in artifact_ids, artifact_id
        assert artifact_path not in artifact_paths, artifact_path
        artifact_ids.add(artifact_id)
        artifact_paths.add(artifact_path)
        path = ROOT / artifact_path
        assert path.is_file(), path
        assert _sha256(path) == artifact["sha256"], path
        digest_items.append({"path": artifact_path, "sha256": str(artifact["sha256"])})

    digest_input = {"artifacts": sorted(digest_items, key=lambda item: item["path"])}
    canonical = json.dumps(
        digest_input,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == manifest["package_root_sha256"]


def test_contract_v6_registries_match_every_declared_id() -> None:
    manifest = _manifest()
    normative = manifest["normative_documents"]
    assert isinstance(normative, list)

    requirement_declaration = re.compile(r"\*\*(LF-[A-Z0-9-]+-\d{3})\.\*\*")
    acceptance_declaration = re.compile(r"^\| `(AT-[A-Z0-9-]+-\d{2})` \|", re.MULTILINE)

    declared_requirements: dict[str, Path] = {}
    declared_acceptance: dict[str, Path] = {}
    for document in normative:
        assert isinstance(document, dict)
        path = ROOT / str(document["path"])
        document_text = path.read_text(encoding="utf-8")
        for requirement_id in requirement_declaration.findall(document_text):
            assert requirement_id not in declared_requirements, requirement_id
            declared_requirements[requirement_id] = path
        for acceptance_id in acceptance_declaration.findall(document_text):
            assert acceptance_id not in declared_acceptance, acceptance_id
            declared_acceptance[acceptance_id] = path

    requirement_registry = _json(PACKAGE / "registries" / "requirements-registry.json")
    acceptance_manifest = _json(PACKAGE / "registries" / "acceptance-manifest.json")
    _validate(requirement_registry, "requirement-registry.schema.json")
    _validate(acceptance_manifest, "acceptance-manifest.schema.json")

    requirements = requirement_registry["requirements"]
    acceptance_cases = acceptance_manifest["acceptance_cases"]
    assert isinstance(requirements, list)
    assert isinstance(acceptance_cases, list)
    registered_requirements = {str(item["id"]) for item in requirements}
    registered_acceptance = {str(item["id"]) for item in acceptance_cases}

    assert registered_requirements == set(declared_requirements)
    assert registered_acceptance == set(declared_acceptance)
    assert len(registered_requirements) >= 300
    assert len(registered_acceptance) >= 100

    for requirement in requirements:
        assert isinstance(requirement, dict)
        acceptance_ids = requirement["acceptance_ids"]
        assert isinstance(acceptance_ids, list)
        assert set(map(str, acceptance_ids)) <= registered_acceptance
        if requirement["criticality"] in {"P0", "P1"}:
            assert acceptance_ids, requirement["id"]


def test_contract_v6_control_plane_schemas_and_policy_are_valid() -> None:
    for path in (PACKAGE / "schemas").glob("*.schema.json"):
        schema = _json(path)
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema.get("additionalProperties") is False

    policy = _json(PACKAGE / "policies" / "rbac-sod-policy.json")
    _validate(policy, "rbac-sod-policy.schema.json")
    assert policy["default_decision"] == "DENY"
    break_glass = policy["break_glass"]
    assert isinstance(break_glass, dict)
    assert break_glass["incident_required"] is True
    actions = policy["actions"]
    assert isinstance(actions, list)
    action_ids = [str(item["action"]) for item in actions]
    assert len(action_ids) == len(set(action_ids))


def test_contract_v6_release_candidate_cannot_claim_live_authority() -> None:
    manifest = _manifest()
    if manifest["status"] != "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION":
        return

    defaults = manifest["defaults_pending_ratification"]
    assert isinstance(defaults, dict)
    assert defaults["external_reads_enabled"] is False
    assert defaults["external_writers_enabled"] is False
    assert defaults["b2c_routing_only"] == "DISABLED"
    assert manifest["ratification"] is None
