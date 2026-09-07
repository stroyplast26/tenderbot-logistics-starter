from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "market_demand_os_v7_2"
PACKAGE_VERSION = "7.2.0-rc.2"
PREDECESSOR_MANIFEST = ROOT / "docs" / "market_demand_os_v7" / "contract-manifest.json"
PREDECESSOR_MANIFEST_SHA256 = "83b984df37ad8d8b1903cd07934de0d3ee9117b9c659538afb9b919dc0cccbf9"
FIXED_AT = "2026-09-02"
CREATED_AT = "2026-09-02T00:00:00Z"

NORMATIVE_DOCUMENTS = [
    ("MDOS-V7-ROOT", "CONTRACT.md", "1.3.0"),
    ("APP-MDOS-COMMERCIAL-MODEL", "APP-MDOS-COMMERCIAL-MODEL.md", "1.1.0"),
    ("APP-MDOS-REFERENCE-ARCHITECTURE", "APP-MDOS-REFERENCE-ARCHITECTURE.md", "1.2.0"),
    ("APP-MDOS-DEMAND-INTELLIGENCE", "APP-MDOS-DEMAND-INTELLIGENCE.md", "1.0.0"),
    ("APP-MDOS-SOURCE-PORTFOLIO", "APP-MDOS-SOURCE-PORTFOLIO.md", "1.2.0"),
    ("APP-MDOS-DECISION-OUTCOMES", "APP-MDOS-DECISION-OUTCOMES.md", "1.1.0"),
    ("APP-MDOS-DELIVERY-ASSURANCE", "APP-MDOS-DELIVERY-ASSURANCE.md", "1.2.0"),
    ("APP-MDOS-OPERATOR-TELEPHONY", "APP-MDOS-OPERATOR-TELEPHONY.md", "1.1.0"),
    ("APP-MDOS-MAIL-BITRIX-OBSERVER", "APP-MDOS-MAIL-BITRIX-OBSERVER.md", "1.0.0"),
]
ADVISORY_DOCUMENTS = [("MDOS-V7-README", "README.md", "1.3.0")]
EVIDENCE_ARTIFACTS = [
    (
        "MDOS-V7.1-BASELINE-IMPLEMENTATION-TRACE",
        "evidence/baseline-implementation-trace-overlay.v7.1.json",
        "1.0.0",
    ),
    (
        "MDOS-V7.2-OPERATOR-TELEPHONY-OFFLINE-EVIDENCE",
        "evidence/operator-telephony-offline-evidence.json",
        "1.0.0",
    ),
    (
        "MDOS-V7.2-RATIFICATION-READINESS",
        "evidence/ratification-readiness.json",
        "1.1.0",
    ),
]

REQUIREMENT_RE = re.compile(r"\*\*(MDOS-[A-Z0-9-]+-[0-9]{3})\.\*\*")
ACCEPTANCE_RE = re.compile(r"^\| `(AT-[A-Z0-9-]+-[0-9]{2})` \| (.*?) \| (.*?) \|\s*$")
BASELINE_EVIDENCE_REF = (
    "EVIDENCE:docs/market_demand_os_v7_2/evidence/"
    "baseline-implementation-trace-overlay.v7.1.json"
)
OPERATOR_EVIDENCE_REF = (
    "EVIDENCE:docs/market_demand_os_v7_2/evidence/"
    "operator-telephony-offline-evidence.json"
)

OPERATOR_ACCEPTANCE_TESTS = {
    "AT-OPT-01": "test_provider_call_exact_replay_has_one_business_effect",
    "AT-OPT-02": "test_out_of_order_evidence_and_multiple_recordings_converge_after_binding",
    "AT-OPT-03": "test_transfer_legs_share_one_session_and_one_activity_binding",
    "AT-OPT-04": "test_bitrix_identity_is_one_to_one_and_binding_replay_is_terminal_safe",
    "AT-OPT-05": "test_ambiguous_crm_candidates_require_review_before_exact_binding",
    "AT-OPT-06": "test_manual_confirmation_succeeds_without_ai_draft",
    "AT-OPT-07": "test_transcript_revision_makes_prior_analysis_draft_stale",
    "AT-OPT-08": "test_callback_keeps_task_active_and_projects_owner_due_and_binding_ids",
    "AT-OPT-09": "test_analysis_and_gold_confirmation_are_idempotent_and_review_only",
    "AT-OPT-10": "test_manual_dnc_creates_suppression_review_without_canonical_suppression",
    "AT-OPT-11": "test_reconciliation_repairs_crash_after_confirmation_event",
    "AT-OPT-12": "test_bitrix_identity_is_one_to_one_and_binding_replay_is_terminal_safe",
    "AT-OPT-13": "test_canonical_events_contain_no_raw_audio_transcript_or_temporary_url",
    "AT-OPT-14": "test_task_reassignment_invalidates_operator_binding",
}
OPERATOR_ACCEPTANCE_ADDITIONAL_TESTS = {
    "AT-OPT-03": (
        "test_out_of_order_evidence_and_multiple_recordings_converge_after_binding",
    ),
    "AT-OPT-04": ("test_crm_activity_identity_cannot_bind_two_call_sessions",),
    "AT-OPT-06": (
        "test_ai_denied_or_unavailable_does_not_block_manual_confirmation",
    ),
    "AT-OPT-14": (
        "test_wrong_actor_rejection_leaves_events_task_and_state_unchanged",
    ),
}
OPERATOR_ACCEPTANCE_COVERAGE = {
    acceptance_id: "FULL" for acceptance_id in OPERATOR_ACCEPTANCE_TESTS
}


def operator_test_binding(method: str) -> str:
    return (
        "TEST:tests/test_lead_factory_operator_call_workflow.py#"
        f"OperatorCallWorkflowTests.{method}"
    )


OPERATOR_REQUIREMENT_BINDINGS = {
    "MDOS-OPT-001": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow"],
        [operator_test_binding("test_analysis_and_gold_confirmation_are_idempotent_and_review_only")],
    ),
    "MDOS-OPT-002": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.confirm_disposition"],
        [operator_test_binding("test_manual_confirmation_succeeds_without_ai_draft")],
    ),
    "MDOS-TEL-002": (
        [
            "CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.record_call_completed",
            "CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.bind_bitrix_activity",
        ],
        [
            operator_test_binding("test_provider_call_exact_replay_has_one_business_effect"),
            operator_test_binding("test_transfer_legs_share_one_session_and_one_activity_binding"),
        ],
    ),
    "MDOS-TEL-003": (
        [
            "CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.record_crm_candidate_review",
            "CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.bind_bitrix_activity",
        ],
        [operator_test_binding("test_ambiguous_crm_candidates_require_review_before_exact_binding")],
    ),
    "MDOS-TEL-004": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.record_call_completed"],
        [operator_test_binding("test_transfer_legs_share_one_session_and_one_activity_binding")],
    ),
    "MDOS-TEL-005": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow"],
        [operator_test_binding("test_canonical_events_contain_no_raw_audio_transcript_or_temporary_url")],
    ),
    "MDOS-OPR-001": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.confirm_disposition"],
        [operator_test_binding("test_callback_keeps_task_active_and_projects_owner_due_and_binding_ids")],
    ),
    "MDOS-OPR-002": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.confirm_disposition"],
        [operator_test_binding("test_changed_replays_and_cross_call_draft_reuse_conflict")],
    ),
    "MDOS-OPR-003": (
        [
            "CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.confirm_disposition",
            "CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.reconcile_human_task",
        ],
        [
            operator_test_binding("test_callback_keeps_task_active_and_projects_owner_due_and_binding_ids"),
            operator_test_binding("test_reconciliation_repairs_crash_after_confirmation_event"),
        ],
    ),
    "MDOS-OPR-004": (
        ["CODE:lead_factory/operator_call_workflow.py#OperatorCallWorkflow.confirm_disposition"],
        [operator_test_binding("test_analysis_and_gold_confirmation_are_idempotent_and_review_only")],
    ),
}
OPERATOR_REQUIREMENT_COVERAGE = {
    requirement_id: (
        "FULL" if requirement_id in {"MDOS-TEL-003", "MDOS-OPR-002"} else "PARTIAL"
    )
    for requirement_id in OPERATOR_REQUIREMENT_BINDINGS
}

OPERATOR_REQUIREMENT_ACCEPTANCE = {
    "MDOS-OPT-001": ["AT-OPT-06", "AT-OPT-08", "AT-OPT-09", "AT-OPT-10", "AT-OPT-14"],
    "MDOS-OPT-002": ["AT-OPT-06", "AT-OPT-07", "AT-OPT-09", "AT-OPT-10", "AT-OPT-14"],
    "MDOS-OPT-003": ["AT-OPT-08", "AT-OPT-14", "AT-OPT-15", "AT-MBO-06"],
    "MDOS-OPT-004": ["AT-OPT-03", "AT-OPT-04", "AT-OPT-05", "AT-OPT-11", "AT-OPT-12"],
    "MDOS-OPT-005": ["AT-OPT-15", "AT-MBO-06"],
    "MDOS-TEL-001": ["AT-OPT-03", "AT-OPT-04"],
    "MDOS-TEL-002": ["AT-OPT-01", "AT-OPT-03", "AT-OPT-04", "AT-OPT-12"],
    "MDOS-TEL-003": ["AT-OPT-05"],
    "MDOS-TEL-004": ["AT-OPT-02", "AT-OPT-03"],
    "MDOS-TEL-005": ["AT-OPT-13"],
    "MDOS-TEL-006": [],
    "MDOS-TEL-007": ["AT-OPT-06", "AT-OPT-07"],
    "MDOS-TEL-008": [],
    "MDOS-OPR-001": ["AT-OPT-08", "AT-OPT-09", "AT-OPT-10", "AT-OPT-14"],
    "MDOS-OPR-002": ["AT-OPT-14"],
    "MDOS-OPR-003": ["AT-OPT-08", "AT-OPT-09", "AT-OPT-10", "AT-OPT-11", "AT-OPT-12"],
    "MDOS-OPR-004": ["AT-OPT-09"],
    "MDOS-OPR-005": [],
    "MDOS-PIL-001": [],
    "MDOS-PIL-002": ["AT-OPT-06", "AT-OPT-13"],
    "MDOS-PIL-003": [],
}

MAIL_OBSERVER_REQUIREMENT_ACCEPTANCE = {
    "MDOS-GOV-006": ["AT-MBO-10"],
    "MDOS-ARC-003": ["AT-MBO-01", "AT-MBO-05"],
    "MDOS-EVT-005": ["AT-MBO-02", "AT-MBO-03", "AT-MBO-04", "AT-MBO-14"],
    "MDOS-STO-006": ["AT-MBO-01", "AT-MBO-05"],
    "MDOS-OPS-005": ["AT-MBO-07", "AT-MBO-08", "AT-MBO-13", "AT-MBO-16"],
    "MDOS-SRC-005": [
        "AT-MBO-01",
        "AT-MBO-05",
        "AT-MBO-11",
        "AT-MBO-12",
        "AT-MBO-13",
        "AT-MBO-16",
    ],
    "MDOS-PORT-008": ["AT-MBO-01", "AT-MBO-04"],
    "MDOS-PRG-010": ["AT-MBO-02", "AT-MBO-04", "AT-MBO-07", "AT-MBO-15", "AT-MBO-16"],
    "MDOS-BAS-004": ["AT-MBO-07", "AT-MBO-15"],
    "MDOS-REL-003": ["AT-MBO-09", "AT-MBO-10"],
    "MDOS-MBO-001": ["AT-MBO-01"],
    "MDOS-MBO-002": ["AT-MBO-05", "AT-MBO-16"],
    "MDOS-MBO-003": ["AT-MBO-01", "AT-MBO-04", "AT-MBO-05"],
    "MDOS-MBO-004": ["AT-MBO-01", "AT-MBO-02", "AT-MBO-11", "AT-MBO-12"],
    "MDOS-MBO-005": ["AT-MBO-02", "AT-MBO-03"],
    "MDOS-MBO-006": ["AT-MBO-03", "AT-MBO-04", "AT-MBO-14"],
    "MDOS-MBO-007": ["AT-MBO-06"],
    "MDOS-MBO-008": ["AT-MBO-08"],
    "MDOS-MBO-009": ["AT-MBO-07", "AT-MBO-15"],
    "MDOS-MBO-010": ["AT-MBO-09"],
    "MDOS-MBO-011": [
        "AT-MBO-01",
        "AT-MBO-02",
        "AT-MBO-04",
        "AT-MBO-08",
        "AT-MBO-13",
        "AT-MBO-16",
    ],
    "MDOS-MBO-012": ["AT-MBO-10"],
    "MDOS-MBO-013": ["AT-MBO-11"],
    "MDOS-MBO-014": ["AT-MBO-12"],
    "MDOS-MBO-015": ["AT-MBO-13"],
    "MDOS-MBO-016": ["AT-MBO-15"],
    "MDOS-MBO-017": ["AT-MBO-16"],
}

REQUIREMENT_ACCEPTANCE = {
    **OPERATOR_REQUIREMENT_ACCEPTANCE,
    **MAIL_OBSERVER_REQUIREMENT_ACCEPTANCE,
}

SUCCESSOR_SCHEMA_NAMES = {
    "analysis-draft.schema.json",
    "call-evidence.schema.json",
    "call-interaction.schema.json",
    "operator-adjudication.schema.json",
    "operator-work-item.schema.json",
    "ratification-readiness.schema.json",
    "ratification-record.schema.json",
    "release-evidence.schema.json",
    "release-pin.schema.json",
    "telephony-data-policy.schema.json",
    "telephony-pilot.schema.json",
}
SUCCESSOR_REGISTRY_SCHEMA_NAMES = {
    "acceptance-manifest.schema.json",
    "requirement-registry.schema.json",
    "traceability-registry.schema.json",
}


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


def write_json_atomic(path: Path, value: object, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    formatting = {"separators": (",", ":")} if compact else {"indent": 2}
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, **formatting) + "\n"
    temporary.write_bytes(serialized.encode("utf-8"))
    os.replace(temporary, path)


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


def owner(identifier: str) -> str:
    return {
        "MIS": "BusinessOwner",
        "SCP": "BusinessOwner",
        "SUC": "BusinessOwner",
        "OUT": "BusinessOwner",
        "COM": "RevenueArchitect",
        "GOLD": "SalesOwner",
        "MOT": "MotionOwner",
        "DTP": "PartnerOwner",
        "GEO": "CommercialFinanceOwner",
        "OFR": "ProductAndPromiseOwner",
        "BCH": "BusinessOwner",
        "ARC": "PlatformOwner",
        "EVT": "DataPlatformOwner",
        "KG": "DataSteward",
        "CAP": "OperationsOwner",
        "JRN": "JourneyOwner",
        "STO": "DataPlatformOwner",
        "OPS": "SREOwner",
        "DI": "ModelRiskOwner",
        "DOC": "DocumentIntelligenceOwner",
        "ER": "IdentitySteward",
        "RES": "ModelRiskOwner",
        "RSH": "ResearchOwner",
        "CAL": "IndependentModelValidator",
        "SEC": "SecurityOwner",
        "LRN": "DecisionScienceOwner",
        "SRC": "SourceAuthority",
        "PORT": "SourcePortfolioOwner",
        "ADP": "SourceAuthority",
        "LGL": "PrivacyLegalOwner",
        "SLA": "SourcePortfolioOwner",
        "DEC": "DecisionScienceOwner",
        "OUTC": "FinanceDataOwner",
        "EXP": "ExperimentOwner",
        "ECO": "CommercialFinanceOwner",
        "G10": "IndependentEvidenceVerifier",
        "PC10": "IndependentEvidenceVerifier",
        "MET": "AnalyticsOwner",
        "ASR": "AssuranceOwner",
        "TRC": "ContractCustodian",
        "PRG": "ProgramOwner",
        "BAS": "DataSteward",
        "REV": "ProgramOwner",
        "REL": "ReleaseManager",
        "TRU": "QualityArbiter",
        "AST": "RevenueArchitect",
        "AUT": "PolicyAuthority",
        "GOV": "ContractAuthority",
        "OPT": "SalesOperationsOwner",
        "TEL": "TelephonyIntegrationOwner",
        "OPR": "SalesOperationsOwner",
        "PIL": "ReleaseManager",
        "MBO": "InboundMailObserverOwner",
    }.get(family(identifier), "ContractAuthority")


def criticality(identifier: str) -> str:
    p0 = (
        "MDOS-GOV",
        "MDOS-AUT",
        "MDOS-TRU",
        "MDOS-LGL",
        "MDOS-ASR",
        "MDOS-TRC",
        "MDOS-REL",
        "MDOS-SEC",
        "MDOS-BCH",
        "MDOS-TEL",
        "MDOS-PIL",
        "MDOS-MBO",
    )
    p1 = (
        "MDOS-MIS",
        "MDOS-SUC",
        "MDOS-GOLD",
        "MDOS-EVT",
        "MDOS-KG",
        "MDOS-STO",
        "MDOS-DI",
        "MDOS-ER",
        "MDOS-RES",
        "MDOS-CAL",
        "MDOS-LRN",
        "MDOS-DEC",
        "MDOS-OUTC",
        "MDOS-EXP",
        "MDOS-ECO",
        "MDOS-G10",
        "MDOS-PC10",
        "MDOS-OPT",
        "MDOS-OPR",
    )
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


def schema_artifact_version(path: Path) -> str:
    if path.name == "contract-manifest.schema.json":
        return "1.2.0"
    if path.name in SUCCESSOR_REGISTRY_SCHEMA_NAMES:
        return "1.2.0"
    if path.name in SUCCESSOR_SCHEMA_NAMES:
        return "1.0.0"
    return "1.1.0"


def binding_path(binding: str) -> Path | None:
    if ":" not in binding:
        return None
    _kind, locator = binding.split(":", 1)
    relative_path = locator.split("#", 1)[0]
    path = (ROOT / relative_path).resolve()
    if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
        return None
    return path


def existing_file_bindings(values: list[str]) -> list[str]:
    return sorted({value for value in values if binding_path(value) is not None})


def binding_digest(binding: str) -> str:
    path = binding_path(binding)
    if path is None:
        raise SystemExit(f"binding does not resolve to a file: {binding}")
    return sha256_path(path)


def requirement_blocks(lines: list[str]) -> list[tuple[str, int, int, str]]:
    starts: list[tuple[str, int]] = []
    for line_number, line in enumerate(lines, 1):
        match = REQUIREMENT_RE.search(line)
        if match:
            starts.append((match.group(1), line_number))
    result: list[tuple[str, int, int, str]] = []
    for index, (requirement_id, line_start) in enumerate(starts):
        next_start = starts[index + 1][1] if index + 1 < len(starts) else len(lines) + 1
        line_end = next_start - 1
        for candidate in range(line_start + 1, next_start):
            value = lines[candidate - 1]
            if value.startswith("#") or ACCEPTANCE_RE.match(value):
                line_end = candidate - 1
                break
        while line_end > line_start and not lines[line_end - 1].strip():
            line_end -= 1
        text = "\n".join(lines[line_start - 1 : line_end]).strip()
        result.append((requirement_id, line_start, line_end, text))
    return result


def load_baseline_overlay() -> dict[str, object]:
    path = PACKAGE / "evidence" / "baseline-implementation-trace-overlay.v7.1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def baseline_requirement_bindings(
    overlay: dict[str, object],
) -> dict[str, dict[str, list[str]]]:
    result: dict[str, dict[str, list[str]]] = {}
    for trace in overlay["trace_sets"]:  # type: ignore[index]
        if trace.get("status") != "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED":
            continue
        for requirement_id in trace.get("requirement_refs", []):
            entry = result.setdefault(
                str(requirement_id),
                {"code": [], "test": [], "evidence": [BASELINE_EVIDENCE_REF]},
            )
            entry["code"].extend(str(value) for value in trace.get("code_bindings", []))
            entry["test"].extend(str(value) for value in trace.get("test_bindings", []))
            entry["evidence"].extend(str(value) for value in trace.get("evidence_refs", []))
    for entry in result.values():
        for key in entry:
            entry[key] = existing_file_bindings(entry[key])
    return result


def baseline_acceptance_bindings(
    overlay: dict[str, object],
) -> dict[str, dict[str, list[str]]]:
    locally_tested = {
        str(item["id"])
        for item in overlay["acceptance_overlay"]  # type: ignore[index]
        if item.get("status") == "LOCALLY_TESTED_NOT_INDEPENDENTLY_VERIFIED"
    }
    result: dict[str, dict[str, list[str]]] = {}
    for trace in overlay["trace_sets"]:  # type: ignore[index]
        for acceptance_id in trace.get("acceptance_refs", []):
            acceptance_id = str(acceptance_id)
            if acceptance_id not in locally_tested:
                continue
            entry = result.setdefault(
                acceptance_id,
                {"test": [], "evidence": [BASELINE_EVIDENCE_REF]},
            )
            entry["test"].extend(str(value) for value in trace.get("test_bindings", []))
            entry["evidence"].extend(str(value) for value in trace.get("evidence_refs", []))
    for entry in result.values():
        for key in entry:
            entry[key] = existing_file_bindings(entry[key])
    return result


def build_registries() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    overlay = load_baseline_overlay()
    baseline_requirements = baseline_requirement_bindings(overlay)
    baseline_acceptance = baseline_acceptance_bindings(overlay)
    requirements: list[dict[str, object]] = []
    acceptance: list[dict[str, object]] = []
    requirement_ids: set[str] = set()
    acceptance_ids: set[str] = set()

    for _, relative_path, _ in NORMATIVE_DOCUMENTS:
        path = PACKAGE / relative_path
        document = str(path.relative_to(ROOT)).replace("\\", "/")
        lines = path.read_text(encoding="utf-8").splitlines()
        for requirement_id, line_start, line_end, requirement_text in requirement_blocks(lines):
            if requirement_id in requirement_ids:
                raise SystemExit(f"duplicate requirement: {requirement_id}")
            requirement_ids.add(requirement_id)
            baseline = baseline_requirements.get(requirement_id, {})
            code_bindings = list(baseline.get("code", []))
            test_bindings = list(baseline.get("test", []))
            evidence_refs = list(baseline.get("evidence", []))
            operator_bindings = OPERATOR_REQUIREMENT_BINDINGS.get(requirement_id)
            if operator_bindings is not None:
                code_bindings.extend(operator_bindings[0])
                test_bindings.extend(operator_bindings[1])
                evidence_refs.append(OPERATOR_EVIDENCE_REF)
            code_bindings = existing_file_bindings(code_bindings)
            test_bindings = existing_file_bindings(test_bindings)
            evidence_refs = existing_file_bindings(evidence_refs)
            if operator_bindings is not None:
                implementation_coverage = OPERATOR_REQUIREMENT_COVERAGE[requirement_id]
            elif code_bindings or test_bindings or evidence_refs:
                implementation_coverage = "PARTIAL"
            else:
                implementation_coverage = "NONE"
            implemented = bool(
                implementation_coverage == "FULL"
                and code_bindings
                and test_bindings
                and evidence_refs
            )
            requirements.append(
                {
                    "id": requirement_id,
                    "document": document,
                    "line_start": line_start,
                    "line_end": line_end,
                    "text_sha256": sha256_bytes(requirement_text.encode("utf-8")),
                    "owner_role": owner(requirement_id),
                    "criticality": criticality(requirement_id),
                    "applicable_tiers": applicable_tiers(requirement_id),
                    "status": "IMPLEMENTED" if implemented else "DESIGNED",
                    "implementation_coverage": implementation_coverage,
                    "acceptance_ids": [],
                    "design_bindings": [f"DESIGN:{document}#L{line_start}-L{line_end}"],
                    "code_bindings": code_bindings,
                    "test_bindings": test_bindings,
                    "evidence_refs": evidence_refs,
                }
            )
        for line_number, line in enumerate(lines, 1):
            acceptance_match = ACCEPTANCE_RE.match(line)
            if acceptance_match:
                acceptance_id, scenario, expected = acceptance_match.groups()
                if acceptance_id in acceptance_ids:
                    raise SystemExit(f"duplicate acceptance: {acceptance_id}")
                acceptance_ids.add(acceptance_id)
                bindings = baseline_acceptance.get(acceptance_id, {})
                test_bindings = list(bindings.get("test", []))
                evidence_refs = list(bindings.get("evidence", []))
                operator_test = OPERATOR_ACCEPTANCE_TESTS.get(acceptance_id)
                if operator_test is not None:
                    test_bindings.append(operator_test_binding(operator_test))
                    test_bindings.extend(
                        operator_test_binding(method)
                        for method in OPERATOR_ACCEPTANCE_ADDITIONAL_TESTS.get(
                            acceptance_id, ()
                        )
                    )
                    evidence_refs.append(OPERATOR_EVIDENCE_REF)
                test_bindings = existing_file_bindings(test_bindings)
                evidence_refs = existing_file_bindings(evidence_refs)
                if operator_test is not None:
                    coverage = OPERATOR_ACCEPTANCE_COVERAGE[acceptance_id]
                elif test_bindings or evidence_refs:
                    coverage = "PARTIAL"
                else:
                    coverage = "NONE"
                implemented = bool(
                    coverage == "FULL" and test_bindings and evidence_refs
                )
                case_sha256 = sha256_bytes(
                    f"{scenario.strip()}\n{expected.strip()}".encode("utf-8")
                )
                acceptance.append(
                    {
                        "id": acceptance_id,
                        "document": document,
                        "line": line_number,
                        "scenario": scenario.strip(),
                        "expected_result": expected.strip(),
                        "case_sha256": case_sha256,
                        "owner_role": owner(acceptance_id.replace("AT-", "MDOS-", 1)),
                        "execution_status": (
                            "IMPLEMENTED_NOT_VERIFIED"
                            if implemented
                            else "SPECIFIED_NOT_IMPLEMENTED"
                        ),
                        "coverage": coverage,
                        "test_bindings": test_bindings,
                        "evidence_refs": evidence_refs,
                    }
                )

    declared_acceptance_ids = {str(case["id"]) for case in acceptance}
    for requirement in requirements:
        requirement_id = str(requirement["id"])
        explicit_acceptance_ids = list(
            REQUIREMENT_ACCEPTANCE.get(requirement_id, ())
        )
        unknown_acceptance_ids = set(explicit_acceptance_ids) - declared_acceptance_ids
        if unknown_acceptance_ids:
            raise SystemExit(
                f"unknown explicit acceptance mapping for {requirement_id}: "
                f"{sorted(unknown_acceptance_ids)}"
            )
        requirement["acceptance_ids"] = explicit_acceptance_ids

    requirements.sort(key=lambda item: str(item["id"]))
    acceptance.sort(key=lambda item: str(item["id"]))
    return requirements, acceptance


def build_traceability(
    requirements: list[dict[str, object]],
    acceptance: list[dict[str, object]],
) -> list[dict[str, object]]:
    acceptance_by_id = {str(case["id"]): case for case in acceptance}
    edges: list[dict[str, object]] = []
    for requirement in requirements:
        requirement_id = str(requirement["id"])
        requirement_digest = str(requirement["text_sha256"])
        for index, binding in enumerate(requirement["design_bindings"], 1):
            edges.append(
                trace_edge(
                    requirement_id,
                    "REQUIREMENT",
                    requirement_digest,
                    "SATISFIED_BY",
                    str(binding),
                    "DESIGN",
                    binding_digest(str(binding)),
                    "ACTIVE",
                    "FULL",
                    "SPECIFIED",
                    f"DESIGN-{index:02d}",
                )
            )
        for acceptance_id in requirement["acceptance_ids"]:
            case = acceptance_by_id[str(acceptance_id)]
            edges.append(
                trace_edge(
                    requirement_id,
                    "REQUIREMENT",
                    requirement_digest,
                    "VERIFIED_BY",
                    str(acceptance_id),
                    "ACCEPTANCE",
                    str(case["case_sha256"]),
                    "SPECIFIED",
                    "PLANNED",
                    "SPECIFIED",
                    str(acceptance_id),
                )
            )
        for edge_type, key, target_kind in (
            ("IMPLEMENTED_BY", "code_bindings", "CODE"),
            ("VERIFIED_BY", "test_bindings", "TEST"),
            ("PRODUCED_EVIDENCE", "evidence_refs", "EVIDENCE"),
        ):
            for index, binding in enumerate(requirement[key], 1):
                edges.append(
                    trace_edge(
                        requirement_id,
                        "REQUIREMENT",
                        requirement_digest,
                        edge_type,
                        str(binding),
                        target_kind,
                        binding_digest(str(binding)),
                        "ACTIVE",
                        str(requirement["implementation_coverage"]),
                        "LOCAL_NOT_INDEPENDENT",
                        f"{target_kind}-{index:02d}",
                    )
                )
    for case in acceptance:
        acceptance_id = str(case["id"])
        case_digest = str(case["case_sha256"])
        for edge_type, key, target_kind in (
            ("VERIFIED_BY", "test_bindings", "TEST"),
            ("PRODUCED_EVIDENCE", "evidence_refs", "EVIDENCE"),
        ):
            for index, binding in enumerate(case[key], 1):
                edges.append(
                    trace_edge(
                        acceptance_id,
                        "ACCEPTANCE",
                        case_digest,
                        edge_type,
                        str(binding),
                        target_kind,
                        binding_digest(str(binding)),
                        "ACTIVE",
                        str(case["coverage"]),
                        "LOCAL_NOT_INDEPENDENT",
                        f"{target_kind}-{index:02d}",
                    )
                )
    return sorted(edges, key=lambda edge: str(edge["edge_id"]))


def trace_edge(
    from_id: str,
    from_kind: str,
    from_digest: str,
    edge_type: str,
    to_id: str,
    to_kind: str,
    to_digest: str,
    status: str,
    coverage: str,
    verification_level: str,
    suffix: str,
) -> dict[str, object]:
    return {
        "edge_id": f"TRACE-{from_id}-{suffix}",
        "from_id": from_id,
        "from_kind": from_kind,
        "from_digest": from_digest,
        "edge_type": edge_type,
        "to_id": to_id,
        "to_kind": to_kind,
        "to_digest": to_digest,
        "status": status,
        "coverage": coverage,
        "verification_level": verification_level,
    }


def validate(schema_path: Path, value: object) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def verify_local_evidence_sources() -> None:
    evidence_path = PACKAGE / "evidence" / "operator-telephony-offline-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    validate(PACKAGE / "schemas" / "release-evidence.schema.json", evidence)
    for source in evidence["source_digests"]:
        source_path = ROOT / str(source["path"])
        if sha256_path(source_path) != source["sha256"]:
            raise SystemExit(f"stale operator evidence source digest: {source_path}")
    readiness = json.loads(
        (PACKAGE / "evidence" / "ratification-readiness.json").read_text(encoding="utf-8")
    )
    validate(PACKAGE / "schemas" / "ratification-readiness.schema.json", readiness)


def verify_operator_code_bindings() -> None:
    source_path = ROOT / "lead_factory" / "operator_call_workflow.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    classes = {
        node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
    }
    for code_bindings, _test_bindings in OPERATOR_REQUIREMENT_BINDINGS.values():
        for binding in code_bindings:
            path = binding_path(binding)
            if path != source_path:
                raise SystemExit(f"unexpected operator code binding path: {binding}")
            _prefix, locator = binding.split(":", 1)
            _relative_path, separator, symbol = locator.partition("#")
            if not separator or not symbol:
                raise SystemExit(f"operator code binding lacks a symbol: {binding}")
            class_name, dot, method_name = symbol.partition(".")
            class_node = classes.get(class_name)
            if class_node is None:
                raise SystemExit(f"operator code binding class is missing: {binding}")
            if dot and not any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == method_name
                for node in class_node.body
            ):
                raise SystemExit(f"operator code binding method is missing: {binding}")


def main() -> None:
    if sha256_path(PREDECESSOR_MANIFEST) != PREDECESSOR_MANIFEST_SHA256:
        raise SystemExit("v7.1 predecessor manifest changed; successor lineage is no longer exact")
    verify_local_evidence_sources()
    verify_operator_code_bindings()
    requirements, acceptance = build_registries()
    if len(requirements) != 244 or len(acceptance) != 113:
        raise SystemExit(
            f"unexpected normative surface: {len(requirements)} requirements, "
            f"{len(acceptance)} acceptance cases"
        )

    requirements_registry = {
        "registry_id": "MDOS-V7-REQUIREMENTS",
        "registry_version": "1.2.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "requirements": requirements,
    }
    acceptance_manifest = {
        "manifest_id": "MDOS-V7-ACCEPTANCE",
        "manifest_version": "1.2.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "acceptance_cases": acceptance,
    }
    traceability_registry = {
        "registry_id": "MDOS-V7-TRACEABILITY",
        "registry_version": "1.2.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "created_at": CREATED_AT,
        "edges": build_traceability(requirements, acceptance),
    }
    generated_registries = {
        PACKAGE / "registries" / "requirements-registry.json": requirements_registry,
        PACKAGE / "registries" / "acceptance-manifest.json": acceptance_manifest,
        PACKAGE / "registries" / "traceability-registry.json": traceability_registry,
    }
    for path, value in generated_registries.items():
        write_json_atomic(
            path,
            value,
            compact=path.name == "traceability-registry.json",
        )

    validate(PACKAGE / "schemas" / "requirement-registry.schema.json", requirements_registry)
    validate(PACKAGE / "schemas" / "acceptance-manifest.schema.json", acceptance_manifest)
    validate(PACKAGE / "schemas" / "traceability-registry.schema.json", traceability_registry)

    normative = [artifact(*item) for item in NORMATIVE_DOCUMENTS]
    schemas = [
        artifact(
            f"SCHEMA-{path.name.removesuffix('.schema.json').upper().replace('_', '-')}",
            str(path.relative_to(PACKAGE)).replace("\\", "/"),
            schema_artifact_version(path),
        )
        for path in sorted((PACKAGE / "schemas").glob("*.schema.json"))
    ]
    registry_artifacts = [
        artifact("MDOS-V7-REQUIREMENTS", "registries/requirements-registry.json", "1.2.0"),
        artifact("MDOS-V7-ACCEPTANCE", "registries/acceptance-manifest.json", "1.2.0"),
        artifact("MDOS-V7-TRACEABILITY", "registries/traceability-registry.json", "1.2.0"),
    ]
    evidence_artifacts = [artifact(*item) for item in EVIDENCE_ARTIFACTS]
    advisory = [artifact(*item) for item in ADVISORY_DOCUMENTS]
    artifact_groups = (normative, schemas, registry_artifacts, evidence_artifacts, advisory)
    digest_input = {
        "artifacts": sorted(
            [
                {"path": item["path"], "sha256": item["sha256"]}
                for group in artifact_groups
                for item in group
            ],
            key=lambda item: item["path"],
        )
    }
    live_gates = {
        "bitrix": False,
        "mango": False,
        "mail": False,
        "unisender": False,
        "tenderplan": False,
    }
    manifest = {
        "$schema": "schemas/contract-manifest.schema.json",
        "schema_version": "1.2.0",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "status": "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION",
        "fixed_at": FIXED_AT,
        "package_root_sha256": sha256_bytes(canonical_json_bytes(digest_input)),
        "package_digest_algorithm": "sha256(canonical-json(sorted(path,sha256)))",
        "supersedes": {
            "id": "AK-MDOS-V7",
            "version": "7.1.0-rc.1",
            "role": "SUPERSEDED_RELEASE_CANDIDATE",
            "manifest_sha256": PREDECESSOR_MANIFEST_SHA256,
        },
        "target_profiles": [
            {
                "id": "GDO10",
                "unit": "AcceptedGoldenDemandOpportunity",
                "status": "ACTIVE_EVALUATION_TARGET",
                "target_per_workday": 10,
                "evaluation_workdays": 30,
                "minimum_total": 300,
            },
            {
                "id": "PC10",
                "unit": "NewPayingClient",
                "status": "SEPARATE_NOT_ACTIVE",
                "target_per_workday": 10,
                "evaluation_workdays": 30,
                "minimum_total": 300,
            },
        ],
        "proposed_beachhead_profile": {
            "id": "PROPOSED-BEACHHEAD-AL-WINDOWS-RU-MOS-DELIVERY",
            "status": "PROPOSED_NOT_ACTIVE",
            "motion_id": "EXISTING_ACCOUNT_EXPANSION",
            "product_scope_id": "ALUMINIUM_WINDOWS",
            "region_code": "RU-MOS",
            "fulfilment_model_id": "FACTORY_DELIVERY_NO_INSTALLATION",
            "installation_scope": "EXCLUDED",
            "source_ref": (
                "docs/market_demand_os_v7_2/evidence/ratification-readiness.json"
            ),
        },
        "active_beachhead_profile": None,
        "defaults_pending_ratification": {
            "external_reads_enabled": False,
            "external_writers_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
            "pc10_enabled": False,
        },
        "live_gates": live_gates,
        "normative_documents": normative,
        "schemas": schemas,
        "registries": registry_artifacts,
        "evidence_artifacts": evidence_artifacts,
        "advisory_documents": advisory,
        "required_approver_roles": [
            "BusinessOwner",
            "ContractAuthority",
            "PrivacyLegalOwner",
            "IndependentEvidenceVerifier",
        ],
        "ratification": None,
    }
    validate(PACKAGE / "schemas" / "contract-manifest.schema.json", manifest)
    manifest_path = PACKAGE / "contract-manifest.json"
    write_json_atomic(manifest_path, manifest)
    manifest_sha256 = sha256_path(manifest_path)
    artifact_count = sum(len(group) for group in artifact_groups)
    release_pin = {
        "schema_version": "1.0.0",
        "record_type": "EXACT_RELEASE_PIN",
        "contract_id": "AK-MDOS-V7",
        "package_version": PACKAGE_VERSION,
        "package_dir": "docs/market_demand_os_v7_2",
        "manifest_path": "docs/market_demand_os_v7_2/contract-manifest.json",
        "manifest_sha256": manifest_sha256,
        "package_root_sha256": manifest["package_root_sha256"],
        "artifact_count": artifact_count,
        "authority_status": "DEFAULT_DENY_NOT_RATIFIED",
        "live_gates": live_gates,
    }
    validate(PACKAGE / "schemas" / "release-pin.schema.json", release_pin)
    write_json_atomic(PACKAGE / "release-pin.json", release_pin)
    print(
        json.dumps(
            {
                "package_version": PACKAGE_VERSION,
                "package_root_sha256": manifest["package_root_sha256"],
                "manifest_sha256": manifest_sha256,
                "artifact_count": artifact_count,
                "requirements": len(requirements),
                "implemented_requirements": sum(
                    item["status"] == "IMPLEMENTED" for item in requirements
                ),
                "acceptance_cases": len(acceptance),
                "implemented_not_verified_acceptance": sum(
                    item["execution_status"] == "IMPLEMENTED_NOT_VERIFIED"
                    for item in acceptance
                ),
                "schemas": len(schemas),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
