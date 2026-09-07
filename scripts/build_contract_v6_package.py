from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "lead_factory_contract_v6"
PACKAGE_VERSION = "6.1.0-rc.1"
BASE_PATH = ROOT / "docs" / "LEAD_FACTORY_CONTRACT.md"
BASE_SHA256 = "84b61a956bae970d0d7baf61985256ae15d1775474512d71f5c2d74d64974afb"

NORMATIVE_DOCUMENTS = [
    ("LF-V6-ROOT", "CONTRACT.md", "1.1.0"),
    ("APP-LF-FUNNELS", "APP-LF-FUNNELS.md", "1.0.0"),
    ("APP-LF-G10-EVIDENCE", "APP-LF-G10-EVIDENCE.md", "1.0.0"),
    ("APP-LF-METHOD-LAB", "APP-LF-METHOD-LAB.md", "1.0.0"),
    ("APP-LF-SOURCE-CRM", "APP-LF-SOURCE-CRM.md", "1.0.0"),
    ("APP-LF-DEVELOPMENT-PROGRAM", "APP-LF-DEVELOPMENT-PROGRAM.md", "1.1.0"),
    ("APP-LF-DEMAND-INTELLIGENCE", "APP-LF-DEMAND-INTELLIGENCE.md", "1.0.0"),
    ("APP-LF-PLATFORM-ARCHITECTURE", "APP-LF-PLATFORM-ARCHITECTURE.md", "1.0.0"),
    ("APP-LF-DEALER-NETWORK-ECONOMICS", "APP-LF-DEALER-NETWORK-ECONOMICS.md", "1.0.0"),
    ("APP-LF-DECISION-SCIENCE", "APP-LF-DECISION-SCIENCE.md", "1.0.0"),
    ("APP-LF-GOVERNANCE-RELEASE", "APP-LF-GOVERNANCE-RELEASE.md", "1.0.0"),
    ("APP-LF-SAFETY-KERNEL-IMPORT", "APP-LF-SAFETY-KERNEL-IMPORT.md", "1.0.0"),
    ("APP-LF-QUALITY-ARBITRATION", "APP-LF-QUALITY-ARBITRATION.md", "1.0.0"),
]

ADVISORY_DOCUMENTS = [
    ("LF-V6-README", "README.md", "1.1.0"),
    ("ADR-LF-V6", "ADR-LF-V6.md", "1.0.0"),
]

REQUIREMENT_RE = re.compile(r"\*\*(LF-[A-Z0-9-]+-\d{3})\.\*\*")
ACCEPTANCE_ROW_RE = re.compile(
    r"^\| `(AT-[A-Z0-9-]+-\d{2})` \| (.*?) \| (.*?) \|\s*$"
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def owner_for(identifier: str) -> str:
    family = identifier.split("-")[1]
    return {
        "V6": "ContractAuthority",
        "GOV": "ContractAuthority",
        "IMP": "ContractAuthority",
        "PLT": "ReleaseManager",
        "DI": "ModelRiskOwner",
        "DS": "ModelRiskOwner",
        "MTH": "MethodOwner",
        "SRC": "SourceAuthority",
        "CRM": "ReleaseManager",
        "QA": "QualityArbiter",
        "G10": "BusinessOwner",
        "ECO": "BusinessOwner",
        "NET": "BusinessOwner",
        "OFR": "BusinessOwner",
        "PRG": "BusinessOwner",
    }.get(family, "BusinessOwner")


def criticality_for(identifier: str) -> str:
    if identifier.startswith(("LF-GOV", "LF-IMP", "LF-QA", "LF-PLT-POL", "LF-PLT-CMD", "LF-PLT-EVT")):
        return "P0"
    if identifier.startswith(("LF-GOLD", "LF-G10", "LF-DI", "LF-DS", "LF-SRC", "LF-CRM", "LF-RTE", "LF-SPINE")):
        return "P1"
    return "P2"


def acceptance_family_for_requirement(identifier: str) -> str:
    family = identifier.split("-")[1]
    return {
        "ICP": "FNL", "GOLD": "FNL", "FNL": "FNL", "DLR": "FNL",
        "RTE": "FNL", "PRJ": "FNL", "SPINE": "FNL", "ARC": "PLT",
        "OFR": "NET", "ECO": "ECO", "V6": "GOV",
    }.get(family, family)


def artifact(identifier: str, relative_path: str, version: str) -> dict[str, str]:
    path = PACKAGE / relative_path
    if not path.is_file():
        raise SystemExit(f"missing contract artifact: {path}")
    return {
        "id": identifier,
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "version": version,
        "sha256": sha256_path(path),
    }


def build_registries() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    requirements: list[dict[str, object]] = []
    acceptance: list[dict[str, object]] = []
    seen_requirements: set[str] = set()
    seen_acceptance: set[str] = set()

    for _, relative_path, _ in NORMATIVE_DOCUMENTS:
        path = PACKAGE / relative_path
        lines = path.read_text(encoding="utf-8").splitlines()
        document = str(path.relative_to(ROOT)).replace("\\", "/")
        for line_number, line in enumerate(lines, start=1):
            for match in REQUIREMENT_RE.finditer(line):
                requirement_id = match.group(1)
                if requirement_id in seen_requirements:
                    raise SystemExit(f"duplicate requirement id: {requirement_id}")
                seen_requirements.add(requirement_id)
                requirements.append(
                    {
                        "id": requirement_id,
                        "document": document,
                        "line": line_number,
                        "text_sha256": sha256_bytes(line.strip().encode("utf-8")),
                        "owner_role": owner_for(requirement_id),
                        "criticality": criticality_for(requirement_id),
                        "status": "DEFINED",
                        "applicable_tiers": ["T0_OFFLINE", "T1_SHADOW", "T2_BOUNDED_CANARY", "T3_CONTROLLED_PRODUCTION", "T4_MULTI_METHOD_GCO10", "T5_RESILIENT_OPERATION"],
                        "acceptance_ids": [],
                    }
                )
            match = ACCEPTANCE_ROW_RE.match(line)
            if match:
                acceptance_id, scenario, expected = match.groups()
                if acceptance_id in seen_acceptance:
                    raise SystemExit(f"duplicate acceptance id: {acceptance_id}")
                seen_acceptance.add(acceptance_id)
                acceptance.append(
                    {
                        "id": acceptance_id,
                        "document": document,
                        "line": line_number,
                        "scenario": scenario.strip(),
                        "expected_result": expected.strip(),
                        "owner_role": owner_for(acceptance_id.replace("AT-", "LF-", 1)),
                        "execution_status": "SPECIFIED_NOT_IMPLEMENTED",
                        "test_bindings": [],
                        "evidence_refs": [],
                    }
                )

    acceptance_by_family: dict[str, list[str]] = {}
    for item in acceptance:
        family = str(item["id"]).split("-")[1]
        acceptance_by_family.setdefault(family, []).append(str(item["id"]))
    for item in requirements:
        family = acceptance_family_for_requirement(str(item["id"]))
        item["acceptance_ids"] = sorted(acceptance_by_family.get(family, []))

    requirements.sort(key=lambda item: str(item["id"]))
    acceptance.sort(key=lambda item: str(item["id"]))
    return requirements, acceptance


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    if sha256_path(BASE_PATH) != BASE_SHA256:
        raise SystemExit("v5.2 safety-kernel hash changed; update import map explicitly")

    requirements, acceptance = build_registries()
    registries_dir = PACKAGE / "registries"
    registries_dir.mkdir(parents=True, exist_ok=True)

    requirement_registry = {
        "registry_id": "LF-V6-REQUIREMENTS",
        "registry_version": "1.0.0",
        "contract_id": "LF-OUTCOME-V6",
        "package_version": PACKAGE_VERSION,
        "requirements": requirements,
    }
    acceptance_manifest = {
        "manifest_id": "LF-V6-ACCEPTANCE",
        "manifest_version": "1.0.0",
        "contract_id": "LF-OUTCOME-V6",
        "package_version": PACKAGE_VERSION,
        "acceptance_cases": acceptance,
    }
    write_json(registries_dir / "requirements-registry.json", requirement_registry)
    write_json(registries_dir / "acceptance-manifest.json", acceptance_manifest)

    normative = [artifact(*item) for item in NORMATIVE_DOCUMENTS]
    schemas = [
        artifact(
            f"SCHEMA-{path.stem.upper()}",
            str(path.relative_to(PACKAGE)).replace("\\", "/"),
            "1.0.0",
        )
        for path in sorted((PACKAGE / "schemas").glob("*.schema.json"))
    ]
    policies = [artifact("POLICY-LF-RBAC-SOD", "policies/rbac-sod-policy.json", "1.0.0")]
    registries = [
        artifact("LF-V6-REQUIREMENTS", "registries/requirements-registry.json", "1.0.0"),
        artifact("LF-V6-ACCEPTANCE", "registries/acceptance-manifest.json", "1.0.0"),
    ]
    advisory = [artifact(*item) for item in ADVISORY_DOCUMENTS]
    digest_input = {
        "artifacts": sorted(
            [
                {"path": item["path"], "sha256": item["sha256"]}
                for group in (normative, schemas, policies, registries, advisory)
                for item in group
            ],
            key=lambda item: item["path"],
        )
    }
    package_root_sha256 = sha256_bytes(canonical_json_bytes(digest_input))

    manifest = {
        "$schema": "schemas/contract-manifest.schema.json",
        "schema_version": "1.1.0",
        "contract_id": "LF-OUTCOME-V6",
        "package_version": PACKAGE_VERSION,
        "status": "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION",
        "fixed_at": "2026-08-25",
        "package_root_sha256": package_root_sha256,
        "package_digest_algorithm": "sha256(canonical-json(sorted(path,sha256)))",
        "supersedes": {"package_version": "6.0.0", "status": "SUPERSEDED_DRAFT"},
        "target_profile": {
            "id": "GCO10",
            "unit": "AcceptedGoldenClientOpportunity",
            "target_per_workday": 10,
            "evaluation_workdays": 30,
            "minimum_total": 300,
            "lower_confidence_bound": 0.95,
            "new_paying_clients_profile": "SEPARATE_NOT_ACTIVE",
        },
        "defaults_pending_ratification": {
            "commercial_priority": "DEALER_FIRST",
            "b2c_routing_only": "DISABLED",
            "gold_decision_window_days": 30,
            "dealer_active_window_days": 30,
            "external_reads_enabled": False,
            "external_writers_enabled": False,
        },
        "base_contract": {
            "path": "docs/LEAD_FACTORY_CONTRACT.md",
            "revision": "5.2",
            "role": "HASH_LOCKED_IMPORTED_SAFETY_KERNEL",
            "sha256": BASE_SHA256,
            "import_map": "docs/lead_factory_contract_v6/APP-LF-SAFETY-KERNEL-IMPORT.md",
        },
        "normative_documents": normative,
        "schemas": schemas,
        "policies": policies,
        "registries": registries,
        "advisory_documents": advisory,
        "required_approver_roles": ["BusinessOwner", "ContractAuthority", "IndependentAuditor"],
        "ratification": None,
    }
    write_json(PACKAGE / "contract-manifest.json", manifest)

    print(
        json.dumps(
            {
                "package_version": PACKAGE_VERSION,
                "package_root_sha256": package_root_sha256,
                "requirements": len(requirements),
                "acceptance_cases": len(acceptance),
                "schemas": len(schemas),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()

