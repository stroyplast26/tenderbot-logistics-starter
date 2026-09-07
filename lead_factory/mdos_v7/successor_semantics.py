"""Cross-field semantic guards for MDOS v7.2 successor records.

JSON Schema validates record shape.  Duration arithmetic and separation of
duties require comparisons across fields and therefore live in this explicit,
default-deny validator.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


RATIFICATION_ROLES = (
    "BusinessOwner",
    "ContractAuthority",
    "PrivacyLegalOwner",
    "IndependentEvidenceVerifier",
)
RATIFICATION_NORMATIVE_ARTIFACTS = (
    "target_profile",
    "motions",
    "economics",
    "owner_capacity",
    "payment_truth",
    "consent_policy",
    "source_permits",
    "promises",
    "initial_release_evidence",
)
MANDATORY_TELEPHONY_STOP_CONDITIONS = (
    "notice_missing",
    "consent_missing",
    "scope_mismatch",
    "unexpected_participant",
    "recording_failure",
    "crm_binding_conflict",
    "duplicate_effect",
    "ambiguous_or_unknown_outcome",
    "raw_or_secret_leak",
    "cap_or_wip_exceeded",
    "stop_unavailable",
    "controller_stop",
)


class SuccessorSemanticError(ValueError):
    """A shaped successor record violates a cross-field safety invariant."""


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SuccessorSemanticError(f"{field} must be a UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SuccessorSemanticError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SuccessorSemanticError(f"{field} must be UTC")
    return parsed.astimezone(timezone.utc)


def _digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SuccessorSemanticError(f"{field} must be a lowercase SHA256 digest")
    return value


def _immutable_ref(value: object, field: str) -> tuple[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"uri", "sha256"}:
        raise SuccessorSemanticError(f"{field} must be an immutable uri+sha256 reference")
    uri = value.get("uri")
    if not isinstance(uri, str) or "://" not in uri or any(character.isspace() for character in uri):
        raise SuccessorSemanticError(f"{field}.uri must be an absolute reference")
    return uri, _digest(value.get("sha256"), f"{field}.sha256")


def compute_ratification_binding_sha256(record: Mapping[str, Any]) -> str:
    """Bind the exact candidate, beachhead and all mandatory normative artifacts."""

    artifacts = record.get("normative_artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(
        RATIFICATION_NORMATIVE_ARTIFACTS
    ):
        raise SuccessorSemanticError(
            "ratification must bind the exact mandatory normative artifact set"
        )
    artifact_identities = [
        _immutable_ref(artifacts[name], f"normative_artifacts.{name}")
        for name in RATIFICATION_NORMATIVE_ARTIFACTS
    ]
    if len(set(artifact_identities)) != len(RATIFICATION_NORMATIVE_ARTIFACTS):
        raise SuccessorSemanticError("ratification normative artifact refs must be distinct")
    payload = {
        "contract_id": record.get("contract_id"),
        "package_version": record.get("package_version"),
        "package_root_sha256": _digest(
            record.get("package_root_sha256"), "package_root_sha256"
        ),
        "ratified_candidate_manifest_sha256": _digest(
            record.get("ratified_candidate_manifest_sha256"),
            "ratified_candidate_manifest_sha256",
        ),
        "active_beachhead_profile_id": record.get("active_beachhead_profile_id"),
        "normative_artifacts": artifacts,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def validate_telephony_pilot_semantics(record: Mapping[str, Any]) -> None:
    """Reject an overlong or active pilot under the unratified RC contract."""

    if record.get("status") != "DRAFT_NOT_RATIFIED":
        raise SuccessorSemanticError("the v7.2 RC cannot activate a telephony pilot")
    if record.get("max_duration_hours") != 24:
        raise SuccessorSemanticError("telephony pilot duration limit must be 24 hours")
    operator_actor = record.get("operator_actor")
    controller_actor = record.get("controller_actor")
    if (
        not isinstance(operator_actor, str)
        or not operator_actor
        or not isinstance(controller_actor, str)
        or not controller_actor
    ):
        raise SuccessorSemanticError("telephony pilot operator and controller are required")
    if operator_actor == controller_actor:
        raise SuccessorSemanticError("telephony pilot operator and controller must be distinct")
    stop_conditions = record.get("stop_conditions")
    if (
        not isinstance(stop_conditions, list)
        or len(stop_conditions) != len(MANDATORY_TELEPHONY_STOP_CONDITIONS)
        or set(stop_conditions) != set(MANDATORY_TELEPHONY_STOP_CONDITIONS)
    ):
        raise SuccessorSemanticError(
            "telephony pilot must contain the exact mandatory stop condition set"
        )
    starts_at = _utc(record.get("starts_at_utc"), "starts_at_utc")
    expires_at = _utc(record.get("expires_at_utc"), "expires_at_utc")
    duration = expires_at - starts_at
    if duration <= timedelta(0):
        raise SuccessorSemanticError("telephony pilot expiry must follow its start")
    if duration > timedelta(hours=24):
        raise SuccessorSemanticError("telephony pilot exceeds the 24-hour limit")


def validate_ratification_record_semantics(
    record: Mapping[str, Any],
    *,
    expected_package_root_sha256: str,
    expected_candidate_manifest_sha256: str,
    expected_beachhead_profile_id: str,
) -> None:
    """Validate an exact, immutable and separated ratification candidate binding."""

    if record.get("contract_id") != "AK-MDOS-V7":
        raise SuccessorSemanticError("ratification contract binding drift")
    if record.get("package_version") != "7.2.0-rc.1":
        raise SuccessorSemanticError("ratification package version drift")
    expected_root = _digest(expected_package_root_sha256, "expected_package_root_sha256")
    expected_manifest = _digest(
        expected_candidate_manifest_sha256,
        "expected_candidate_manifest_sha256",
    )
    if record.get("package_root_sha256") != expected_root:
        raise SuccessorSemanticError("ratification package root binding drift")
    if record.get("ratified_candidate_manifest_sha256") != expected_manifest:
        raise SuccessorSemanticError("ratification candidate manifest binding drift")
    if (
        not isinstance(expected_beachhead_profile_id, str)
        or not expected_beachhead_profile_id
        or record.get("active_beachhead_profile_id") != expected_beachhead_profile_id
    ):
        raise SuccessorSemanticError("ratification beachhead binding drift")
    binding_digest = compute_ratification_binding_sha256(record)
    if record.get("ratification_binding_sha256") != binding_digest:
        raise SuccessorSemanticError("ratification binding digest drift")
    if record.get("independent_verification_binding_sha256") != binding_digest:
        raise SuccessorSemanticError("independent verification binding drift")
    independent_ref = _immutable_ref(
        record.get("independent_verification_ref"),
        "independent_verification_ref",
    )
    normative_artifacts = record["normative_artifacts"]
    normative_refs = {
        _immutable_ref(
            normative_artifacts[name],
            f"normative_artifacts.{name}",
        )
        for name in RATIFICATION_NORMATIVE_ARTIFACTS
    }
    if independent_ref in normative_refs:
        raise SuccessorSemanticError(
            "independent verification evidence must be distinct from normative artifacts"
        )
    ratified_at = _utc(record.get("ratified_at_utc"), "ratified_at_utc")

    approvals = record.get("approvals")
    if not isinstance(approvals, Mapping) or set(approvals) != set(RATIFICATION_ROLES):
        raise SuccessorSemanticError("ratification must contain exactly four role approvals")
    actors: list[str] = []
    keys: list[str] = []
    signature_refs: list[tuple[str, str]] = []
    approval_times: list[datetime] = []
    for role in RATIFICATION_ROLES:
        approval = approvals.get(role)
        if not isinstance(approval, Mapping) or approval.get("role") != role:
            raise SuccessorSemanticError(f"ratification role binding drift: {role}")
        actor = approval.get("actor_ref")
        key = approval.get("key_id")
        if not isinstance(actor, str) or not actor or not isinstance(key, str) or not key:
            raise SuccessorSemanticError(f"ratification identity is missing: {role}")
        if approval.get("signed_binding_sha256") != binding_digest:
            raise SuccessorSemanticError(f"ratification signed binding drift: {role}")
        signature_refs.append(
            _immutable_ref(approval.get("signature_ref"), f"approvals.{role}.signature_ref")
        )
        approval_times.append(
            _utc(approval.get("approved_at_utc"), f"approvals.{role}.approved_at_utc")
        )
        actors.append(actor)
        keys.append(key)
    if len(set(actors)) != len(RATIFICATION_ROLES):
        raise SuccessorSemanticError("ratification actors must be distinct across roles")
    if len(set(keys)) != len(RATIFICATION_ROLES):
        raise SuccessorSemanticError("ratification signing keys must be distinct across roles")
    if len(set(signature_refs)) != len(RATIFICATION_ROLES):
        raise SuccessorSemanticError("ratification signature refs must be distinct across roles")
    if independent_ref in signature_refs or any(
        signature_ref in normative_refs for signature_ref in signature_refs
    ):
        raise SuccessorSemanticError(
            "approval signatures must be distinct from verification and normative artifacts"
        )
    if any(approved_at > ratified_at for approved_at in approval_times):
        raise SuccessorSemanticError("ratification time cannot precede an approval")
