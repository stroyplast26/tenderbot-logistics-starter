"""Deterministic sealed inputs for graph-canary expansion slots two through five.

This module is pure preparation.  It performs no database, environment, host,
or network access and grants no writer authority.  The resulting cohort seal is
an input to the durable graph controller; it cannot activate a run by itself.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import json
from pathlib import Path
import re

from .bitrix_graph_canary_stage import GraphCanaryCandidate
from .ids import canonical_json, payload_hash


GRAPH_CANARY_EXPANSION_COHORT_VERSION = "bitrix-graph-canary-cohort-v1"
GRAPH_CANARY_EXPANSION_ORDINALS = (2, 3, 4, 5)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PORTAL = re.compile(r"^bitrix-host-v1:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,511}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_COHORT_INPUT_KEYS = {
    "candidate_hashes",
    "declared_cohort_hash",
    "declared_spec_hash",
    "spec",
}


@dataclass(frozen=True, slots=True)
class GraphCanaryExpansionCohortSpec:
    cohort_version: str
    cohort_id: str
    approved_at_utc: str
    activity_deadline_utc: str
    owner_approval_evidence_ref: str
    reviewer_ref: str
    lf_source_id: str
    portal_identity: str
    deployment_input_hash: str
    mapping_manifest_hash: str
    cap_one_evidence_hash: str
    cap_one_control_snapshot_hash: str

    def seal_hash(self) -> str:
        validate_graph_canary_expansion_cohort_spec(self)
        return payload_hash(asdict(self))


@dataclass(frozen=True, slots=True)
class SealedGraphCanaryExpansionCohort:
    spec: GraphCanaryExpansionCohortSpec
    candidates: tuple[GraphCanaryCandidate, ...]
    candidate_hashes: tuple[str, ...]
    cohort_hash: str

    def named_input_hashes(self) -> tuple[tuple[str, str], ...]:
        validate_sealed_graph_canary_expansion_cohort(self)
        return (
            ("cap_one_evidence", self.spec.cap_one_evidence_hash),
            ("cap_one_control_snapshot", self.spec.cap_one_control_snapshot_hash),
            ("deployment_input", self.spec.deployment_input_hash),
            ("mapping_manifest", self.spec.mapping_manifest_hash),
            ("expansion_cohort", self.cohort_hash),
            *tuple(
                (f"expansion_candidate_{ordinal}", digest)
                for ordinal, digest in zip(
                    GRAPH_CANARY_EXPANSION_ORDINALS,
                    self.candidate_hashes,
                    strict=True,
                )
            ),
        )


def _utc(value: object, label: str) -> datetime:
    if type(value) is not str or not _UTC_SECONDS.fullmatch(value):
        raise ValueError(f"{label} must be exact UTC seconds")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{label} must be exact UTC seconds") from None


def validate_graph_canary_expansion_cohort_spec(
    value: GraphCanaryExpansionCohortSpec,
) -> str:
    if type(value) is not GraphCanaryExpansionCohortSpec:
        raise TypeError("exact graph canary expansion cohort spec is required")
    if (
        value.cohort_version != GRAPH_CANARY_EXPANSION_COHORT_VERSION
        or not _SAFE_ID.fullmatch(value.cohort_id)
        or not _SAFE_ID.fullmatch(value.owner_approval_evidence_ref)
        or not _SAFE_ID.fullmatch(value.reviewer_ref)
        or not _SAFE_ID.fullmatch(value.lf_source_id)
        or not _PORTAL.fullmatch(value.portal_identity)
        or any(
            not _HEX64.fullmatch(item)
            for item in (
                value.deployment_input_hash,
                value.mapping_manifest_hash,
                value.cap_one_evidence_hash,
                value.cap_one_control_snapshot_hash,
            )
        )
    ):
        raise ValueError("graph canary expansion cohort spec is invalid")
    approved = _utc(value.approved_at_utc, "approved_at_utc")
    deadline = _utc(value.activity_deadline_utc, "activity_deadline_utc")
    if deadline <= approved:
        raise ValueError("graph canary Activity deadline must follow approval")
    return payload_hash(asdict(value))


def _inn10(seed: str) -> str:
    digest = payload_hash({"kind": "synthetic_canary_inn", "seed": seed})
    digits = [int(character, 16) % 10 for character in digest[:9]]
    if digits[0] == 0:
        digits[0] = 7
    checksum = sum(
        digit * weight
        for digit, weight in zip(digits, (2, 4, 10, 3, 5, 9, 4, 6, 8), strict=True)
    )
    checksum = checksum % 11 % 10
    return "".join(str(item) for item in (*digits, checksum))


def build_graph_canary_expansion_cohort(
    spec: GraphCanaryExpansionCohortSpec,
) -> SealedGraphCanaryExpansionCohort:
    spec_hash = validate_graph_canary_expansion_cohort_spec(spec)
    candidates: list[GraphCanaryCandidate] = []
    for ordinal in GRAPH_CANARY_EXPANSION_ORDINALS:
        identity = payload_hash(
            {
                "cohort_hash": spec_hash,
                "ordinal": ordinal,
                "purpose": "bitrix_graph_canary_expansion",
            }
        )
        short = identity[:20]
        candidate = GraphCanaryCandidate(
            candidate_id=f"cap5:{spec.cohort_id}:{ordinal}:{short}",
            mailbox="INBOX",
            campaign_id=f"bitrix-graph-cap5-{spec.cohort_id}",
            canonical_thread=(
                f"<bitrix-graph-cap5-{ordinal}-{short}@tenderbot.example>"
            ),
            contact_address=(
                f"bitrix-graph-cap5-{ordinal}-{short}@tenderbot.example"
            ),
            company_title=(
                f"TenderBot graph canary {ordinal}/5 - do not contact"
            ),
            company_inn=_inn10(identity),
            contact_name=f"TenderBot canary {ordinal}/5",
            contact_post="System canary - do not contact",
            project_title=f"TenderBot graph canary project {ordinal}/5",
            deal_title=f"TenderBot graph canary {ordinal}/5 - no commercial action",
            product_key="system_canary",
            activity_subject=(
                f"TenderBot graph canary {ordinal}/5 - no action required"
            ),
            activity_description=(
                "Automated bounded integration canary. Do not contact or process."
            ),
            activity_deadline_utc=spec.activity_deadline_utc,
            lf_source_id=spec.lf_source_id,
            reviewer_ref=spec.reviewer_ref,
        )
        candidate.seal_hash()
        candidates.append(candidate)
    candidate_tuple = tuple(candidates)
    candidate_hashes = tuple(item.seal_hash() for item in candidate_tuple)
    cohort_hash = payload_hash(
        {
            "cohort_spec_hash": spec_hash,
            "ordinals": list(GRAPH_CANARY_EXPANSION_ORDINALS),
            "candidate_hashes": list(candidate_hashes),
        }
    )
    result = SealedGraphCanaryExpansionCohort(
        spec=spec,
        candidates=candidate_tuple,
        candidate_hashes=candidate_hashes,
        cohort_hash=cohort_hash,
    )
    validate_sealed_graph_canary_expansion_cohort(result)
    return result


def validate_sealed_graph_canary_expansion_cohort(
    value: SealedGraphCanaryExpansionCohort,
) -> str:
    if type(value) is not SealedGraphCanaryExpansionCohort:
        raise TypeError("sealed graph canary expansion cohort is required")
    spec_hash = validate_graph_canary_expansion_cohort_spec(value.spec)
    if (
        type(value.candidates) is not tuple
        or type(value.candidate_hashes) is not tuple
        or len(value.candidates) != len(GRAPH_CANARY_EXPANSION_ORDINALS)
        or len(value.candidate_hashes) != len(GRAPH_CANARY_EXPANSION_ORDINALS)
        or tuple(item.seal_hash() for item in value.candidates)
        != value.candidate_hashes
        or len(set(value.candidate_hashes)) != len(value.candidate_hashes)
    ):
        raise ValueError("graph canary expansion cohort members are invalid")
    expected = payload_hash(
        {
            "cohort_spec_hash": spec_hash,
            "ordinals": list(GRAPH_CANARY_EXPANSION_ORDINALS),
            "candidate_hashes": list(value.candidate_hashes),
        }
    )
    if not _HEX64.fullmatch(value.cohort_hash) or value.cohort_hash != expected:
        raise ValueError("graph canary expansion cohort seal is invalid")
    return expected


def load_graph_canary_expansion_cohort(
    path: str | Path,
) -> SealedGraphCanaryExpansionCohort:
    target = Path(path).expanduser().resolve(strict=True)
    raw_bytes = target.read_bytes()
    if not raw_bytes or len(raw_bytes) > 128 * 1024:
        raise ValueError("graph canary expansion cohort file is invalid")
    try:
        raw = raw_bytes.decode("utf-8")
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("graph canary expansion cohort file is invalid") from None
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _COHORT_INPUT_KEYS
        or raw
        not in {
            canonical_json(parsed),
            canonical_json(parsed) + "\n",
            canonical_json(parsed) + "\r\n",
        }
        or not isinstance(parsed.get("spec"), dict)
        or set(parsed["spec"]) != set(GraphCanaryExpansionCohortSpec.__annotations__)
        or type(parsed.get("candidate_hashes")) is not list
        or len(parsed["candidate_hashes"]) != len(GRAPH_CANARY_EXPANSION_ORDINALS)
    ):
        raise ValueError("graph canary expansion cohort file is not canonical")
    try:
        spec = GraphCanaryExpansionCohortSpec(**parsed["spec"])
    except (TypeError, ValueError):
        raise ValueError("graph canary expansion cohort file is invalid") from None
    cohort = build_graph_canary_expansion_cohort(spec)
    if (
        parsed.get("declared_spec_hash") != spec.seal_hash()
        or parsed.get("declared_cohort_hash") != cohort.cohort_hash
        or tuple(parsed["candidate_hashes"]) != cohort.candidate_hashes
    ):
        raise ValueError("graph canary expansion cohort declared seal is invalid")
    return cohort


__all__ = [
    "GRAPH_CANARY_EXPANSION_COHORT_VERSION",
    "GRAPH_CANARY_EXPANSION_ORDINALS",
    "GraphCanaryExpansionCohortSpec",
    "SealedGraphCanaryExpansionCohort",
    "build_graph_canary_expansion_cohort",
    "load_graph_canary_expansion_cohort",
    "validate_graph_canary_expansion_cohort_spec",
    "validate_sealed_graph_canary_expansion_cohort",
]
