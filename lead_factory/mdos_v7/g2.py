"""Executable shadow-only readiness contracts for the three G2 motions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping

from .authority import PACKAGE_ROOT_SHA256, PACKAGE_VERSION, authority_snapshot
from .contracts import value_sha256


PROFILE_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "market_demand_os_v7_delivery"
    / "g2-motion-profiles.json"
)

EXPECTED_PROFILES = {
    "G2-MOTION-EXISTING-WINBACK": "EXISTING_ACCOUNT_EXPANSION",
    "G2-MOTION-DEALER-BENCHMARK-RFQ": "DEALER_AND_INSTALLER_ACTIVATION",
    "G2-MOTION-HIGH-INTENT-INBOUND": "HIGH_INTENT_INBOUND",
}

REQUIRED_CANDIDATE_FIELDS = {
    "G2-MOTION-EXISTING-WINBACK": (
        "canonical_account_ref",
        "relationship_evidence_ref",
        "current_need_evidence_ref",
        "object_or_site_ref",
        "product_scope",
        "region",
        "decision_horizon",
        "capacity_snapshot_ref",
        "economics_snapshot_ref",
        "responsible_human_id",
    ),
    "G2-MOTION-DEALER-BENCHMARK-RFQ": (
        "canonical_account_ref",
        "dealer_role_decision_ref",
        "rfq_artifact_ref",
        "object_or_site_ref",
        "product_scope",
        "quantity_scope",
        "region",
        "requested_date",
        "protected_opportunity_owner_ref",
        "capacity_snapshot_ref",
        "economics_snapshot_ref",
        "responsible_human_id",
    ),
    "G2-MOTION-HIGH-INTENT-INBOUND": (
        "inbound_source_artifact_ref",
        "private_inbound_payload_ref",
        "website_attribution_evidence_ref",
        "website_attribution_status",
        "opaque_form_correlation_id",
        "identity_decision_ref",
        "current_need_evidence_ref",
        "object_or_site_ref",
        "product_scope",
        "region",
        "dimensions_or_specification_ref",
        "decision_horizon",
        "capacity_snapshot_ref",
        "responsible_human_id",
    ),
}

_INBOUND_PROFILE_ID = "G2-MOTION-HIGH-INTENT-INBOUND"
_CORRELATION_RE = re.compile(r"^lf_web_v1_[0-9a-f]{40}$")
_PRIVATE_REF_RE = re.compile(r"^private:[a-z0-9][a-z0-9._:-]{0,127}$")
_FORBIDDEN_PUBLIC_CANDIDATE_FIELDS = {
    "pii",
    "raw_pii",
    "request_text",
    "metrika_visit_id",
    "metrika_client_id",
    "raw_metrika_visit_id",
    "raw_metrika_client_id",
}


class G2ProfileError(RuntimeError):
    """The local G2 overlay attempted to exceed its shadow-only authority."""


@dataclass(frozen=True)
class ShadowReadiness:
    profile_id: str
    ready_for_human_gold_review: bool
    missing_fields: tuple[str, ...]
    next_action: str
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0


@dataclass(frozen=True)
class G2ProfileBinding:
    """Exact delivery-local profile material used by a shadow proposal."""

    profile_set_id: str
    profile_id: str
    normative_motion: str
    profile_file_sha256: str
    profile_set_sha256: str
    profile_sha256: str


class G2MotionRegistry:
    def __init__(self, path: str | Path = PROFILE_PATH) -> None:
        authority_snapshot()
        self.path = Path(path).resolve()
        raw_bytes = self.path.read_bytes()
        value = json.loads(raw_bytes.decode("utf-8", "strict"))
        if not isinstance(value, dict):
            raise G2ProfileError("G2 profile set must be a JSON object")
        binding = value.get("package_binding")
        if not isinstance(binding, dict) or (
            binding.get("contract_id") != "AK-MDOS-V7"
            or binding.get("package_version") != PACKAGE_VERSION
            or binding.get("package_root_sha256") != PACKAGE_ROOT_SHA256
            or binding.get("active_beachhead_profile") is not None
            or binding.get("ratification") is not None
        ):
            raise G2ProfileError("G2 profile package binding drift")
        profile_set_id = value.get("profile_set_id")
        if not isinstance(profile_set_id, str) or not profile_set_id:
            raise G2ProfileError("G2 profile_set_id is missing")
        self.profile_set_id = profile_set_id
        self.profile_file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.profile_set_sha256 = value_sha256(value)
        authority = value.get("authority")
        if not isinstance(authority, dict):
            raise G2ProfileError("G2 authority is missing")
        for field in (
            "canonical_kpi_eligible",
            "external_reads_enabled",
            "external_writers_enabled",
            "contact_enabled",
            "spend_enabled",
            "live_bitrix_writes_enabled",
        ):
            if authority.get(field) is not False:
                raise G2ProfileError(f"G2 authority must remain false: {field}")
        if authority.get("status") != "SHADOW_DESIGN_ONLY":
            raise G2ProfileError("G2 authority status drift")

        profiles = value.get("profiles")
        if not isinstance(profiles, list):
            raise G2ProfileError("G2 profiles are missing")
        self._profiles: dict[str, dict[str, Any]] = {}
        for raw in profiles:
            if not isinstance(raw, dict):
                raise G2ProfileError("G2 profile must be an object")
            profile = dict(raw)
            profile_id = str(profile.get("profile_id", ""))
            if profile_id in self._profiles:
                raise G2ProfileError("duplicate G2 profile")
            self._profiles[profile_id] = profile
        if set(self._profiles) != set(EXPECTED_PROFILES):
            raise G2ProfileError("G2 profile set is not exact")
        if {profile.get("priority_rank") for profile in self._profiles.values()} != {
            1,
            2,
            3,
        }:
            raise G2ProfileError("G2 priority order is not a total order")
        if value.get("evaluation_order") != [
            profile_id
            for profile_id, _ in sorted(
                self._profiles.items(), key=lambda item: int(item[1]["priority_rank"])
            )
        ]:
            raise G2ProfileError("G2 evaluation order drift")
        self._profile_sha256 = {
            profile_id: value_sha256(profile)
            for profile_id, profile in self._profiles.items()
        }
        for profile_id, expected_motion in EXPECTED_PROFILES.items():
            profile = self._profiles[profile_id]
            action = profile.get("shadow_action")
            if (
                profile.get("normative_motion") != expected_motion
                or profile.get("status") != "SHADOW_DESIGN_ONLY"
                or not isinstance(action, dict)
                or action.get("action_type") != "CREATE_CRM_TASK"
                or action.get("channel") != "BITRIX24_SHADOW"
                or action.get("cost") != 0
                or action.get("external_effect") is not False
            ):
                raise G2ProfileError(f"G2 shadow action drift: {profile_id}")
            if not profile.get("live_prerequisites") or not profile.get(
                "profile_specific_blockers"
            ):
                raise G2ProfileError(f"G2 live blockers are missing: {profile_id}")
        inbound = self._profiles[_INBOUND_PROFILE_ID]
        attribution = inbound.get("inbound_attribution_contract")
        if not isinstance(attribution, dict):
            raise G2ProfileError("website inbound attribution contract is missing")
        private_plane = attribution.get("private_plane")
        public_plane = attribution.get("public_plane")
        if (
            attribution.get("owner_requirement_id") != "DLV-REQ-INBOUND-ATTR-001"
            or attribution.get("priority") != "P0_OWNER_OVERLAY"
            or attribution.get("authority") != "SYNTHETIC_SHADOW_ONLY"
            or attribution.get("external_effect_count") != 0
            or attribution.get("canonical_kpi_eligible") is not False
            or attribution.get("source_hierarchy")
            != [
                "ALLOWLISTED_UTM",
                "CLASSIFIED_EXTERNAL_REFERRER",
                "DIRECT_WEBSITE",
                "UNKNOWN",
            ]
            or not isinstance(private_plane, dict)
            or private_plane.get("analytics_export_allowed") is not False
            or private_plane.get("bitrix_projection_export_allowed") is not False
            or private_plane.get("evidence_export_allowed") is not False
            or not isinstance(public_plane, dict)
            or public_plane.get("pii_allowed") is not False
            or public_plane.get("request_text_allowed") is not False
            or public_plane.get("raw_metrika_ids_allowed") is not False
            or public_plane.get("metrika_presence_flags_allowed") is not True
        ):
            raise G2ProfileError("website inbound attribution contract drift")
        if "BLOCK-INBOUND-ATTRIBUTION-LIVE" not in inbound.get(
            "live_prerequisites", []
        ):
            raise G2ProfileError("website inbound live blocker is missing")

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(
            profile_id
            for profile_id, _ in sorted(
                self._profiles.items(), key=lambda item: int(item[1]["priority_rank"])
            )
        )

    def profile(self, profile_id: str) -> dict[str, Any]:
        try:
            return json.loads(json.dumps(self._profiles[profile_id]))
        except KeyError as exc:
            raise G2ProfileError(f"unknown G2 profile: {profile_id}") from exc

    def binding(self, profile_id: str) -> G2ProfileBinding:
        profile = self.profile(profile_id)
        return G2ProfileBinding(
            profile_set_id=self.profile_set_id,
            profile_id=profile_id,
            normative_motion=str(profile["normative_motion"]),
            profile_file_sha256=self.profile_file_sha256,
            profile_set_sha256=self.profile_set_sha256,
            profile_sha256=self._profile_sha256[profile_id],
        )

    def evaluate_shadow_candidate(
        self, profile_id: str, candidate: Mapping[str, Any]
    ) -> ShadowReadiness:
        self.profile(profile_id)
        values = dict(candidate)
        forbidden = _FORBIDDEN_PUBLIC_CANDIDATE_FIELDS.intersection(values)
        if forbidden:
            raise G2ProfileError(
                f"G2 candidate exposes private inbound fields: {sorted(forbidden)}"
            )
        if (
            values.get("synthetic") is not True
            or values.get("canonical_kpi_eligible") is not False
        ):
            raise G2ProfileError("G2 candidate must be synthetic/shadow and non-KPI")
        if any(
            values.get(flag) is not False
            for flag in (
                "external_read",
                "external_write",
                "contact",
                "spend",
                "live_bitrix_write",
            )
        ):
            raise G2ProfileError("G2 candidate requests a prohibited external effect")
        missing = tuple(
            field
            for field in REQUIRED_CANDIDATE_FIELDS[profile_id]
            if values.get(field) in (None, "", [], {})
        )
        if profile_id == _INBOUND_PROFILE_ID and not missing:
            if values.get("website_attribution_status") not in {
                "ATTRIBUTED",
                "UNKNOWN",
            }:
                raise G2ProfileError("website attribution status is not deterministic")
            correlation = values.get("opaque_form_correlation_id")
            if (
                not isinstance(correlation, str)
                or _CORRELATION_RE.fullmatch(correlation) is None
            ):
                raise G2ProfileError("website form correlation is not opaque and exact")
            private_ref = values.get("private_inbound_payload_ref")
            if (
                not isinstance(private_ref, str)
                or _PRIVATE_REF_RE.fullmatch(private_ref) is None
            ):
                raise G2ProfileError(
                    "website private payload reference is not separated"
                )
        return ShadowReadiness(
            profile_id=profile_id,
            ready_for_human_gold_review=not missing,
            missing_fields=missing,
            next_action="HUMAN_GOLD_REVIEW" if not missing else "HUMAN_VERIFY",
        )


__all__ = [
    "EXPECTED_PROFILES",
    "G2MotionRegistry",
    "G2ProfileBinding",
    "G2ProfileError",
    "PROFILE_PATH",
    "REQUIRED_CANDIDATE_FIELDS",
    "ShadowReadiness",
]
