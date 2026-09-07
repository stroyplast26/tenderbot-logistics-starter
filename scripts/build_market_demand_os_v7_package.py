from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "market_demand_os_v7"
PACKAGE_VERSION = "7.1.0-rc.1"
PREVIOUS_RC_MANIFEST_SHA256 = "e052b1bcda696df913aa6d1386d7cfdf3c9435c89fc2d2882a2055d01dd998d0"

NORMATIVE_DOCUMENTS = [
    ("MDOS-V7-ROOT", "CONTRACT.md", "1.1.0"),
    ("APP-MDOS-COMMERCIAL-MODEL", "APP-MDOS-COMMERCIAL-MODEL.md", "1.1.0"),
    ("APP-MDOS-REFERENCE-ARCHITECTURE", "APP-MDOS-REFERENCE-ARCHITECTURE.md", "1.1.0"),
    ("APP-MDOS-DEMAND-INTELLIGENCE", "APP-MDOS-DEMAND-INTELLIGENCE.md", "1.0.0"),
    ("APP-MDOS-SOURCE-PORTFOLIO", "APP-MDOS-SOURCE-PORTFOLIO.md", "1.1.0"),
    ("APP-MDOS-DECISION-OUTCOMES", "APP-MDOS-DECISION-OUTCOMES.md", "1.1.0"),
    ("APP-MDOS-DELIVERY-ASSURANCE", "APP-MDOS-DELIVERY-ASSURANCE.md", "1.1.0"),
]
ADVISORY_DOCUMENTS = [("MDOS-V7-README", "README.md", "1.1.0")]

REQUIREMENT_RE = re.compile(r"\*\*(MDOS-[A-Z0-9-]+-[0-9]{3})\.\*\*")
ACCEPTANCE_RE = re.compile(r"^\| `(AT-[A-Z0-9-]+-[0-9]{2})` \| (.*?) \| (.*?) \|\s*$")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def artifact(identifier: str, relative_path: str, version: str) -> dict[str, str]:
    path = PACKAGE / relative_path
    if not path.is_file():
        raise SystemExit(f"missing artifact: {path}")
    return {
        "id": identifier,
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "version": version,
        "sha256": sha256_path(path),
    }


def family(identifier: str) -> str:
    return identifier.split("-")[1]


def acceptance_family(identifier: str) -> str:
    return {
        "MIS": "DEC", "SCP": "COM", "TRU": "ARC", "AST": "ARC",
        "OUT": "DEC", "AUT": "ASR", "SUC": "DEC", "GOV": "ASR",
        "COM": "COM", "GOLD": "COM", "MOT": "COM", "DTP": "COM",
        "GEO": "COM", "OFR": "COM", "BCH": "COM", "ARC": "ARC", "EVT": "ARC",
        "KG": "ARC", "CAP": "ARC", "JRN": "ARC", "STO": "ARC",
        "OPS": "ARC", "DI": "DI7", "DOC": "DI7", "ER": "DI7",
        "RES": "DI7", "RSH": "DI7", "CAL": "DI7", "SEC": "DI7",
        "LRN": "DI7", "SRC": "SRC7", "PORT": "SRC7", "ADP": "SRC7",
        "LGL": "SRC7", "SLA": "SRC7", "DEC": "DEC", "OUTC": "DEC",
        "EXP": "DEC", "ECO": "DEC", "G10": "DEC", "PC10": "DEC",
        "MET": "DEC", "ASR": "ASR", "TRC": "ASR", "PRG": "ASR",
        "BAS": "ASR", "REV": "ASR", "REL": "ASR",
    }[family(identifier)]


def owner(identifier: str) -> str:
    return {
        "MIS": "BusinessOwner", "SCP": "BusinessOwner", "SUC": "BusinessOwner",
        "OUT": "BusinessOwner", "COM": "RevenueArchitect", "GOLD": "SalesOwner",
        "MOT": "MotionOwner", "DTP": "PartnerOwner", "GEO": "CommercialFinanceOwner",
        "OFR": "ProductAndPromiseOwner", "BCH": "BusinessOwner", "ARC": "PlatformOwner", "EVT": "DataPlatformOwner",
        "KG": "DataSteward", "CAP": "OperationsOwner", "JRN": "JourneyOwner",
        "STO": "DataPlatformOwner", "OPS": "SREOwner", "DI": "ModelRiskOwner",
        "DOC": "DocumentIntelligenceOwner", "ER": "IdentitySteward", "RES": "ModelRiskOwner",
        "RSH": "ResearchOwner", "CAL": "IndependentModelValidator", "SEC": "SecurityOwner",
        "LRN": "DecisionScienceOwner", "SRC": "SourceAuthority", "PORT": "SourcePortfolioOwner",
        "ADP": "SourceAuthority", "LGL": "PrivacyLegalOwner", "SLA": "SourcePortfolioOwner",
        "DEC": "DecisionScienceOwner", "OUTC": "FinanceDataOwner", "EXP": "ExperimentOwner",
        "ECO": "CommercialFinanceOwner", "G10": "IndependentEvidenceVerifier",
        "PC10": "IndependentEvidenceVerifier", "MET": "AnalyticsOwner", "ASR": "AssuranceOwner",
        "TRC": "ContractCustodian", "PRG": "ProgramOwner", "BAS": "DataSteward",
        "REV": "ProgramOwner", "REL": "ReleaseManager", "TRU": "QualityArbiter",
        "AST": "RevenueArchitect", "AUT": "PolicyAuthority", "GOV": "ContractAuthority",
    }.get(family(identifier), "ContractAuthority")


def criticality(identifier: str) -> str:
    p0 = ("MDOS-GOV", "MDOS-AUT", "MDOS-TRU", "MDOS-LGL", "MDOS-ASR", "MDOS-TRC", "MDOS-REL", "MDOS-SEC", "MDOS-BCH")
    p1 = ("MDOS-MIS", "MDOS-SUC", "MDOS-GOLD", "MDOS-EVT", "MDOS-KG", "MDOS-STO", "MDOS-DI", "MDOS-ER", "MDOS-RES", "MDOS-CAL", "MDOS-LRN", "MDOS-DEC", "MDOS-OUTC", "MDOS-EXP", "MDOS-ECO", "MDOS-G10", "MDOS-PC10")
    if identifier.startswith(p0):
        return "P0"
    if identifier.startswith(p1):
        return "P1"
    return "P2"


def applicable_tiers(identifier: str) -> list[str]:
    level = criticality(identifier)
    if level == "P0":
        return ["G0", "G1", "G2", "PRODUCTION"]
    if level == "P1":
        return ["G1", "G2", "PRODUCTION"]
    return ["G2", "PRODUCTION"]


def build_registries() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    requirements: list[dict[str, object]] = []
    acceptance: list[dict[str, object]] = []
    requirement_ids: set[str] = set()
    acceptance_ids: set[str] = set()

    for _, relative_path, _ in NORMATIVE_DOCUMENTS:
        path = PACKAGE / relative_path
        document = str(path.relative_to(ROOT)).replace("\\", "/")
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in REQUIREMENT_RE.finditer(line):
                requirement_id = match.group(1)
                if requirement_id in requirement_ids:
                    raise SystemExit(f"duplicate requirement: {requirement_id}")
                requirement_ids.add(requirement_id)
                requirements.append({
                    "id": requirement_id,
                    "document": document,
                    "line": line_number,
                    "text_sha256": sha256_bytes(line.strip().encode("utf-8")),
                    "owner_role": owner(requirement_id),
                    "criticality": criticality(requirement_id),
                    "applicable_tiers": applicable_tiers(requirement_id),
                    "status": "DESIGNED",
                    "acceptance_ids": [],
                    "design_bindings": [f"DESIGN:{document}#L{line_number}"],
                    "code_bindings": [],
                    "test_bindings": [],
                    "evidence_refs": [],
                })
            match = ACCEPTANCE_RE.match(line)
            if match:
                acceptance_id, scenario, expected = match.groups()
                if acceptance_id in acceptance_ids:
                    raise SystemExit(f"duplicate acceptance: {acceptance_id}")
                acceptance_ids.add(acceptance_id)
                acceptance.append({
                    "id": acceptance_id,
                    "document": document,
                    "line": line_number,
                    "scenario": scenario.strip(),
                    "expected_result": expected.strip(),
                    "owner_role": owner(acceptance_id.replace("AT-", "MDOS-", 1)),
                    "execution_status": "SPECIFIED_NOT_IMPLEMENTED",
                    "test_bindings": [],
                    "evidence_refs": [],
                })

    by_family: dict[str, list[str]] = {}
    for case in acceptance:
        by_family.setdefault(family(str(case["id"])), []).append(str(case["id"]))
    for requirement in requirements:
        requirement["acceptance_ids"] = sorted(by_family.get(acceptance_family(str(requirement["id"])), []))

    requirements.sort(key=lambda item: str(item["id"]))
    acceptance.sort(key=lambda item: str(item["id"]))
    return requirements, acceptance


def main() -> None:
    requirements, acceptance = build_registries()
    registries = PACKAGE / "registries"
    registries.mkdir(parents=True, exist_ok=True)
    write_json(registries / "requirements-registry.json", {
        "registry_id": "MDOS-V7-REQUIREMENTS",
        "registry_version": "1.0.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "requirements": requirements,
    })
    write_json(registries / "acceptance-manifest.json", {
        "manifest_id": "MDOS-V7-ACCEPTANCE",
        "manifest_version": "1.0.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "acceptance_cases": acceptance,
    })
    acceptance_by_id = {str(case["id"]): case for case in acceptance}
    trace_edges: list[dict[str, object]] = []
    for requirement in requirements:
        requirement_id = str(requirement["id"])
        requirement_digest = str(requirement["text_sha256"])
        design_id = str(requirement["design_bindings"][0])
        trace_edges.append({
            "edge_id": f"TRACE-{requirement_id}-DESIGN",
            "from_id": requirement_id,
            "from_digest": requirement_digest,
            "edge_type": "SATISFIED_BY",
            "to_id": design_id,
            "to_digest": requirement_digest,
            "status": "ACTIVE",
            "created_at": "2026-08-25T00:00:00Z",
        })
        for acceptance_id in requirement["acceptance_ids"]:
            case = acceptance_by_id[str(acceptance_id)]
            case_digest = sha256_bytes(f'{case["scenario"]}\n{case["expected_result"]}'.encode("utf-8"))
            trace_edges.append({
                "edge_id": f"TRACE-{requirement_id}-{acceptance_id}",
                "from_id": requirement_id,
                "from_digest": requirement_digest,
                "edge_type": "VERIFIED_BY",
                "to_id": str(acceptance_id),
                "to_digest": case_digest,
                "status": "SPECIFIED",
                "created_at": "2026-08-25T00:00:00Z",
            })
    write_json(registries / "traceability-registry.json", {
        "registry_id": "MDOS-V7-TRACEABILITY",
        "registry_version": "1.0.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "edges": sorted(trace_edges, key=lambda edge: str(edge["edge_id"])),
    })

    normative = [artifact(*item) for item in NORMATIVE_DOCUMENTS]
    schemas = [artifact(f"SCHEMA-{path.stem.upper()}", str(path.relative_to(PACKAGE)).replace("\\", "/"), "1.1.0") for path in sorted((PACKAGE / "schemas").glob("*.schema.json"))]
    registry_artifacts = [
        artifact("MDOS-V7-REQUIREMENTS", "registries/requirements-registry.json", "1.0.0"),
        artifact("MDOS-V7-ACCEPTANCE", "registries/acceptance-manifest.json", "1.0.0"),
        artifact("MDOS-V7-TRACEABILITY", "registries/traceability-registry.json", "1.0.0"),
    ]
    advisory = [artifact(*item) for item in ADVISORY_DOCUMENTS]
    digest_input = {"artifacts": sorted(
        [{"path": item["path"], "sha256": item["sha256"]} for group in (normative, schemas, registry_artifacts, advisory) for item in group],
        key=lambda item: item["path"],
    )}
    manifest = {
        "$schema": "schemas/contract-manifest.schema.json",
        "schema_version": "1.1.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "status": "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION",
        "fixed_at": "2026-08-25",
        "package_root_sha256": sha256_bytes(canonical_json_bytes(digest_input)),
        "package_digest_algorithm": "sha256(canonical-json(sorted(path,sha256)))",
        "supersedes": {"id": "AK-MDOS-V7", "version": "7.0.0-rc.1", "role": "SUPERSEDED_RELEASE_CANDIDATE", "manifest_sha256": PREVIOUS_RC_MANIFEST_SHA256},
        "target_profiles": [
            {"id": "GDO10", "unit": "AcceptedGoldenDemandOpportunity", "status": "ACTIVE_EVALUATION_TARGET", "target_per_workday": 10, "evaluation_workdays": 30, "minimum_total": 300},
            {"id": "PC10", "unit": "NewPayingClient", "status": "SEPARATE_NOT_ACTIVE", "target_per_workday": 10, "evaluation_workdays": 30, "minimum_total": 300},
        ],
        "active_beachhead_profile": None,
        "defaults_pending_ratification": {"external_reads_enabled": False, "external_writers_enabled": False, "contact_enabled": False, "spend_enabled": False, "pc10_enabled": False},
        "normative_documents": normative,
        "schemas": schemas,
        "registries": registry_artifacts,
        "advisory_documents": advisory,
        "required_approver_roles": ["BusinessOwner", "ContractAuthority", "PrivacyLegalOwner", "IndependentEvidenceVerifier"],
        "ratification": None,
    }
    write_json(PACKAGE / "contract-manifest.json", manifest)
    print(json.dumps({"package_version": PACKAGE_VERSION, "package_root_sha256": manifest["package_root_sha256"], "requirements": len(requirements), "acceptance_cases": len(acceptance), "schemas": len(schemas)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
