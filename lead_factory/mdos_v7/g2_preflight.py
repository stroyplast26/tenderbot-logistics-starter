"""Fail-closed G2 motion preflight over synthetic, privacy-safe proposals.

This module never creates GoldAcceptance, PermitDecision, Consent, PaymentProof,
OrderRecord, a promise, or a CRM effect.  It evaluates only whether a sealed
synthetic proposal has enough evidence to enter human review.  Any supplied
PermitDecision is read and checked as an existing immutable fact; it is never
issued or amended here, and the fixed unratified RC1 still denies every effect.
Synthetic evidence references are checked only as privacy-safe lexical tokens;
their existence and substance remain unverified until human review.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
import re
from typing import Any, Callable, Mapping

from .authority import (
    CONTRACT_ID,
    PACKAGE_ROOT_SHA256,
    PACKAGE_VERSION,
    authority_snapshot,
)
from .contracts import ContractRegistry, record_digest_excluding, value_sha256
from .g2 import G2MotionRegistry, G2ProfileBinding, REQUIRED_CANDIDATE_FIELDS
from .store import MdosStore


_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = _ROOT / "docs" / "market_demand_os_v7" / "contract-manifest.json"
_FREEZE_PATH = _ROOT / "state" / "mdos_v7_external_freeze.json"

CLASSIFICATION = "SYNTHETIC_FIXTURE_NON_CANONICAL_NON_KPI"
PREFLIGHT_PERMIT_PURPOSE = "G2_SHADOW_PREFLIGHT_PROJECTION"
PREFLIGHT_POLICY_VERSION = "mdos-v7.1-rc1-g2-shadow-preflight-1"
PREFLIGHT_POLICY_ISSUER = "fixture-human-policy-authority"
PREFLIGHT_LIMITATIONS = (
    "SYNTHETIC_EVIDENCE_REFS_LEXICAL_ONLY_UNVERIFIED",
    "READINESS_REQUIRES_HUMAN_REVIEW",
)
SUPPORTED_PREFLIGHT_PROFILES: Mapping[str, Mapping[str, str]] = {
    "G2-MOTION-EXISTING-WINBACK": {
        "source_passport_ref": "fixture:g2-existing-winback",
        "allowed_source_label": "Synthetic known-account history fixture",
    },
    "G2-MOTION-DEALER-BENCHMARK-RFQ": {
        "source_passport_ref": "fixture:g2-dealer-benchmark-rfq",
        "allowed_source_label": "Synthetic dealer/account and RFQ fixtures",
    },
    "G2-MOTION-HIGH-INTENT-INBOUND": {
        "source_passport_ref": "fixture:g2-high-intent-inbound",
        "allowed_source_label": "Synthetic website form/email/call-transcript fixture",
    },
}

_INBOUND_PROFILE_ID = "G2-MOTION-HIGH-INTENT-INBOUND"

_FIXTURE_KEYS = {
    "schema_version",
    "fixture_id",
    "classification",
    "contract_id",
    "package_version",
    "package_root_sha256",
    "evaluated_at",
    "profile_binding",
    "source",
    "candidate",
    "permit_decision",
}
_PROFILE_BINDING_KEYS = {
    "profile_set_id",
    "profile_id",
    "normative_motion",
    "profile_file_sha256",
    "profile_set_sha256",
    "profile_sha256",
}
_SOURCE_KEYS = {
    "kind",
    "source_passport_ref",
    "lawful_purpose",
    "contains_raw_pii",
    "contains_request_text",
}
_BOUNDARY_FIELDS = {
    "synthetic",
    "canonical_kpi_eligible",
    "external_read",
    "external_write",
    "contact",
    "spend",
    "live_bitrix_write",
}
_REF_RE = re.compile(r"^fixture:[a-z0-9][a-z0-9._:-]{0,127}$")
_PRIVATE_REF_RE = re.compile(r"^private:[a-z0-9][a-z0-9._:-]{0,127}$")
_HUMAN_ID_RE = re.compile(r"^fixture-human-[a-z0-9][a-z0-9-]{0,63}$")
_PRODUCT_RE = re.compile(r"^[A-Z0-9][A-Z0-9_:-]{0,63}$")
_REGION_RE = re.compile(r"^FIXTURE_REGION_[A-Z0-9_]{1,48}$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_FIXTURE_ID_RE = re.compile(r"^fixture:g2-preflight-[0-9a-f]{32}$")
_CORRELATION_RE = re.compile(r"^lf_web_v1_[0-9a-f]{40}$")
_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
_FORBIDDEN_KEY_PARTS = {
    "email",
    "phone",
    "name",
    "address",
    "inn",
    "request_text",
    "message",
    "pii",
    "metrika",
}
_RESULT_KEYS = {
    "schema_version",
    "fixture_id",
    "fixture_sha256",
    "classification",
    "contract_id",
    "package_version",
    "package_root_sha256",
    "canonical_kpi_eligible",
    "independent_verification",
    "proposal_only",
    "limitations",
    "local_denial_audit_recorded",
    "external_effect_count",
    "external_read_count",
    "external_write_count",
    "contact_count",
    "spend_count",
    "live_bitrix_write_count",
    "created_truth",
    "privacy",
    "evaluated_at",
    "status",
    "reason_codes",
    "authority",
    "profile_binding",
    "source",
    "candidate",
    "permit",
    "bundle_sha256",
}
_CREATED_TRUTH_KEYS = {
    "gold_acceptance",
    "permit_decision",
    "consent",
    "payment_proof",
    "order_record",
    "promise",
}
_PRIVACY_KEYS = {
    "raw_candidate_included",
    "raw_pii_included",
    "request_text_included",
}
_AUTHORITY_RESULT_KEYS = {
    "manifest_sha256",
    "freeze_sha256",
    "active_beachhead_profile",
    "ratification",
    "external_reads_enabled",
    "external_writers_enabled",
    "contact_enabled",
    "spend_enabled",
    "live_bitrix_writes_enabled",
}
_CANDIDATE_RESULT_KEYS = {
    "candidate_sha256",
    "readiness_status",
    "missing_fields",
    "next_action",
}
_PERMIT_RESULT_KEYS = {
    "supplied",
    "permit_decision_sha256",
    "exact_persisted",
    "local_denial_audit_recorded",
    "effect_decision",
    "reason_codes",
}
_PERMIT_REASON_CODES = {
    "PERMIT_NOT_SUPPLIED",
    "PERMIT_CONTRACT_INVALID",
    "PERMIT_PAYLOAD_DIGEST_MISMATCH",
    "PERMIT_NOT_EXACT_PERSISTED",
    "PERMIT_DECISION_NOT_ALLOW",
    "PERMIT_EFFECT_SCOPE_MISMATCH",
    "PERMIT_PROFILE_BINDING_MISMATCH",
    "PERMIT_ISSUER_MISMATCH",
    "PERMIT_EXPIRED",
    "PERMIT_TIME_INVALID",
    "UNRATIFIED_SHADOW_DESIGN_ONLY",
}
_BUNDLE_KEYS = {
    "schema_version",
    "classification",
    "contract_id",
    "package_version",
    "package_root_sha256",
    "canonical_kpi_eligible",
    "independent_verification",
    "limitations",
    "external_effect_count",
    "results",
    "bundle_sha256",
}


class G2PreflightError(RuntimeError):
    """A fixture or output cannot be processed without weakening fail-closed rules."""


class G2PreflightConflict(G2PreflightError):
    """One output path was reused for a different content-addressed result."""


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or _UTC_Z_RE.fullmatch(value) is None:
        raise G2PreflightError("timestamp must be UTC Z")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise G2PreflightError("timestamp must be UTC Z") from exc


def _has_forbidden_key(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).casefold()
            if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
                return True
            if _has_forbidden_key(item):
                return True
    elif isinstance(value, list):
        return any(_has_forbidden_key(item) for item in value)
    return False


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise G2PreflightError(f"{label} fields are not exact")


def _profile_binding_value(binding: G2ProfileBinding) -> dict[str, str]:
    return {key: str(value) for key, value in asdict(binding).items()}


def _safe_fixture_id(value: object) -> str:
    """Return a content-addressed identifier that cannot expose a caller label."""

    return f"fixture:g2-preflight-{value_sha256(str(value))[:32]}"


def _permit_subject_ref(profile_id: str, candidate: Mapping[str, Any]) -> object:
    """Select the one privacy-safe subject token bound by a preflight permit."""

    if profile_id == _INBOUND_PROFILE_ID:
        return candidate.get("opaque_form_correlation_id")
    return candidate.get("canonical_account_ref")


def load_preflight_fixture(path: str | Path) -> dict[str, Any]:
    """Load an exact synthetic fixture without accepting alternate authority."""

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise G2PreflightError("cannot load G2 preflight fixture") from exc
    if not isinstance(value, dict):
        raise G2PreflightError("G2 preflight fixture must be an object")
    _exact_keys(value, _FIXTURE_KEYS, "fixture")
    for field, expected in (
        ("schema_version", "1.0.0"),
        ("classification", CLASSIFICATION),
        ("contract_id", CONTRACT_ID),
        ("package_version", PACKAGE_VERSION),
        ("package_root_sha256", PACKAGE_ROOT_SHA256),
    ):
        if value.get(field) != expected:
            raise G2PreflightError(f"fixture {field} mismatch")
    if (
        not isinstance(value.get("fixture_id"), str)
        or _REF_RE.fullmatch(str(value["fixture_id"])) is None
    ):
        raise G2PreflightError("fixture_id must be an opaque fixture reference")
    _utc(value.get("evaluated_at"))
    return value


class G2ShadowPreflightService:
    """Evaluate noncanonical G2 proposals and deny every external effect."""

    def __init__(
        self,
        *,
        registry: G2MotionRegistry | None = None,
        permit_store: MdosStore | None = None,
        authority_provider: Callable[[], dict[str, Any]] = authority_snapshot,
    ) -> None:
        self.registry = registry or G2MotionRegistry()
        self.permit_store = permit_store
        self.authority_provider = authority_provider
        self.contracts = ContractRegistry(_ROOT)

    def _authority_evidence(self) -> dict[str, Any]:
        snapshot = self.authority_provider()
        manifest = snapshot.get("manifest")
        freeze = snapshot.get("freeze")
        if not isinstance(manifest, dict) or not isinstance(freeze, dict):
            raise G2PreflightError("authority snapshot is incomplete")
        return {
            "manifest_sha256": _file_sha256(_MANIFEST_PATH),
            "freeze_sha256": _file_sha256(_FREEZE_PATH),
            "active_beachhead_profile": manifest.get("active_beachhead_profile"),
            "ratification": manifest.get("ratification"),
            "external_reads_enabled": freeze.get("external_reads_enabled"),
            "external_writers_enabled": freeze.get("external_writers_enabled"),
            "contact_enabled": freeze.get("contact_enabled"),
            "spend_enabled": freeze.get("spend_enabled"),
            "live_bitrix_writes_enabled": freeze.get("live_bitrix_writes_enabled"),
        }

    def _validate_candidate(
        self,
        *,
        profile_id: str,
        candidate: Mapping[str, Any],
        evaluated_at: datetime,
    ) -> tuple[bool, tuple[str, ...], str]:
        allowed = _BOUNDARY_FIELDS.union(REQUIRED_CANDIDATE_FIELDS[profile_id])
        if not set(candidate).issubset(allowed) or _has_forbidden_key(candidate):
            raise G2PreflightError("candidate is not privacy-safe and allowlisted")
        if (
            candidate.get("synthetic") is not True
            or candidate.get("canonical_kpi_eligible") is not False
        ):
            raise G2PreflightError("candidate is not explicitly synthetic/non-KPI")
        if any(
            candidate.get(field) is not False
            for field in _BOUNDARY_FIELDS.difference(
                {"synthetic", "canonical_kpi_eligible"}
            )
        ):
            raise G2PreflightError("candidate crosses a prohibited effect boundary")

        special = {
            "product_scope",
            "responsible_human_id",
            "region",
            "requested_date",
            "private_inbound_payload_ref",
            "website_attribution_status",
            "opaque_form_correlation_id",
        }
        for field in REQUIRED_CANDIDATE_FIELDS[profile_id]:
            item = candidate.get(field)
            if item in (None, "", [], {}):
                continue
            if field == "product_scope":
                if (
                    not isinstance(item, list)
                    or not item
                    or len(set(item)) != len(item)
                    or any(
                        not isinstance(part, str) or _PRODUCT_RE.fullmatch(part) is None
                        for part in item
                    )
                ):
                    raise G2PreflightError(
                        "product_scope is not a safe fixture code set"
                    )
            elif field == "responsible_human_id":
                if not isinstance(item, str) or _HUMAN_ID_RE.fullmatch(item) is None:
                    raise G2PreflightError("responsible_human_id is not opaque")
            elif field == "region":
                if not isinstance(item, str) or _REGION_RE.fullmatch(item) is None:
                    raise G2PreflightError("region is not a synthetic region code")
            elif field == "requested_date":
                if not isinstance(item, str) or _DATE_RE.fullmatch(item) is None:
                    raise G2PreflightError("requested_date is not an exact date")
                try:
                    requested = datetime.fromisoformat(item).date()
                except ValueError as exc:
                    raise G2PreflightError(
                        "requested_date is not an exact date"
                    ) from exc
                if profile_id == "G2-MOTION-DEALER-BENCHMARK-RFQ":
                    days_until_requested = (requested - evaluated_at.date()).days
                    if not 0 <= days_until_requested <= 366:
                        raise G2PreflightError(
                            "dealer requested_date is outside the 0..366 day fixture window"
                        )
            elif field == "private_inbound_payload_ref":
                if not isinstance(item, str) or _PRIVATE_REF_RE.fullmatch(item) is None:
                    raise G2PreflightError(
                        "private_inbound_payload_ref is not an opaque private reference"
                    )
            elif field == "website_attribution_status":
                if item not in {"ATTRIBUTED", "UNKNOWN"}:
                    raise G2PreflightError(
                        "website_attribution_status is not deterministic"
                    )
            elif field == "opaque_form_correlation_id":
                if not isinstance(item, str) or _CORRELATION_RE.fullmatch(item) is None:
                    raise G2PreflightError(
                        "opaque_form_correlation_id is not an opaque correlation token"
                    )
            elif field not in special and (
                not isinstance(item, str) or _REF_RE.fullmatch(item) is None
            ):
                raise G2PreflightError(f"{field} is not an opaque fixture reference")

        readiness = self.registry.evaluate_shadow_candidate(profile_id, candidate)
        return (
            readiness.ready_for_human_gold_review,
            readiness.missing_fields,
            readiness.next_action,
        )

    def _permit_evidence(
        self,
        *,
        permit: object,
        binding: G2ProfileBinding,
        candidate: Mapping[str, Any],
        candidate_sha256: str,
        source_passport_ref: str,
        evaluated_at: str,
        fixture_id: str,
    ) -> dict[str, Any]:
        if permit is None:
            audit_recorded = False
            if self.permit_store is not None:
                self.permit_store.record_denial(
                    operation="g2_shadow_preflight_permit",
                    attempted_actor_id="g2-shadow-preflight",
                    reason_code="PERMIT_NOT_SUPPLIED",
                    payload_sha256=value_sha256(
                        {
                            "profile_id": binding.profile_id,
                            "candidate_sha256": candidate_sha256,
                            "permit": None,
                        }
                    ),
                    trace_id=fixture_id,
                    recorded_at_utc=evaluated_at,
                )
                audit_recorded = True
            return {
                "supplied": False,
                "permit_decision_sha256": None,
                "exact_persisted": False,
                "local_denial_audit_recorded": audit_recorded,
                "effect_decision": "DENY",
                "reason_codes": [
                    "PERMIT_NOT_SUPPLIED",
                    "UNRATIFIED_SHADOW_DESIGN_ONLY",
                ],
            }
        raw_sha = value_sha256(permit)
        reasons: list[str] = []
        exact_persisted = False
        if not isinstance(permit, Mapping):
            reasons.append("PERMIT_CONTRACT_INVALID")
        else:
            value = dict(permit)
            try:
                self.contracts.validate("permit-decision.schema.json", value)
            except Exception:
                reasons.append("PERMIT_CONTRACT_INVALID")
            else:
                digest_valid = value.get("payload_sha256") == record_digest_excluding(
                    value, "payload_sha256"
                )
                if not digest_valid:
                    reasons.append("PERMIT_PAYLOAD_DIGEST_MISMATCH")
                persisted = None
                if self.permit_store is not None:
                    persisted = self.permit_store.latest_record(
                        "PERMIT_DECISION", str(value.get("permit_decision_id", ""))
                    )
                exact_persisted = bool(
                    digest_valid
                    and persisted is not None
                    and persisted.get("payload") == value
                )
                if not exact_persisted:
                    reasons.append("PERMIT_NOT_EXACT_PERSISTED")
                if value.get("decision") != "ALLOW":
                    reasons.append("PERMIT_DECISION_NOT_ALLOW")
                expected_scope = {
                    "beachhead_profile_ref": None,
                    "region": candidate.get("region"),
                    "product_scope": candidate.get("product_scope"),
                }
                expected_subject_refs = [
                    _permit_subject_ref(binding.profile_id, candidate)
                ]
                if (
                    value.get("purpose") != PREFLIGHT_PERMIT_PURPOSE
                    or value.get("action_type") != "CREATE_CRM_TASK"
                    or value.get("channel") != "BITRIX24_SHADOW"
                    or value.get("max_cost") != 0
                    or value.get("currency") != "RUB"
                    or value.get("policy_version") != PREFLIGHT_POLICY_VERSION
                    or value.get("legal_basis_ref") != "FIXTURE_ONLY_NO_EXTERNAL_EFFECT"
                    or value.get("source_passport_ref") != source_passport_ref
                    or value.get("capacity_snapshot_ref")
                    != candidate.get("capacity_snapshot_ref")
                    or value.get("scope") != expected_scope
                    or value.get("subject_refs") != expected_subject_refs
                    or value.get("issued_by") != PREFLIGHT_POLICY_ISSUER
                ):
                    reasons.append("PERMIT_EFFECT_SCOPE_MISMATCH")
                expected_refs = {
                    f"g2-profile-file-sha256:{binding.profile_file_sha256}",
                    f"g2-profile-set-sha256:{binding.profile_set_sha256}",
                    f"g2-profile-sha256:{binding.profile_sha256}",
                    f"g2-candidate-sha256:{candidate_sha256}",
                }
                if set(value.get("evidence_refs", [])) != expected_refs or len(
                    value.get("evidence_refs", [])
                ) != len(expected_refs):
                    reasons.append("PERMIT_PROFILE_BINDING_MISMATCH")
                if exact_persisted and self.permit_store is not None:
                    try:
                        issuer = self.permit_store.require_actor(
                            PREFLIGHT_POLICY_ISSUER, "POLICY_AUTHORITY"
                        )
                    except Exception:
                        reasons.append("PERMIT_ISSUER_MISMATCH")
                    else:
                        if (
                            issuer.get("actor_type") != "HUMAN"
                            or persisted.get("writer_id") != PREFLIGHT_POLICY_ISSUER
                        ):
                            reasons.append("PERMIT_ISSUER_MISMATCH")
                try:
                    now = _utc(evaluated_at)
                    if not (
                        _utc(value.get("issued_at"))
                        <= now
                        < _utc(value.get("expires_at"))
                    ):
                        reasons.append("PERMIT_EXPIRED")
                except G2PreflightError:
                    reasons.append("PERMIT_TIME_INVALID")
        reasons.append("UNRATIFIED_SHADOW_DESIGN_ONLY")
        audit_recorded = False
        if self.permit_store is not None:
            self.permit_store.record_denial(
                operation="g2_shadow_preflight_permit",
                attempted_actor_id="g2-shadow-preflight",
                reason_code="G2_PREFLIGHT_PERMIT_DENIED",
                payload_sha256=raw_sha,
                trace_id=fixture_id,
                recorded_at_utc=evaluated_at,
            )
            audit_recorded = True
        return {
            "supplied": True,
            "permit_decision_sha256": raw_sha,
            "exact_persisted": exact_persisted,
            "local_denial_audit_recorded": audit_recorded,
            "effect_decision": "DENY",
            "reason_codes": sorted(set(reasons)),
        }

    @staticmethod
    def _seal(bundle: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(bundle)
        value["bundle_sha256"] = value_sha256(value)
        return value

    def evaluate(self, fixture: Mapping[str, Any]) -> dict[str, Any]:
        """Return a privacy-minimised, content-addressed fail-closed result."""

        raw = dict(fixture)
        fixture_sha256 = value_sha256(raw)
        candidate_raw = raw.get("candidate")
        candidate_sha256 = value_sha256(candidate_raw)
        fixture_id_raw = raw.get("fixture_id")
        fixture_id = _safe_fixture_id(fixture_id_raw)
        evaluated_at_raw = raw.get("evaluated_at")
        try:
            _utc(evaluated_at_raw)
            safe_evaluated_at = str(evaluated_at_raw)
        except G2PreflightError:
            safe_evaluated_at = "UNKNOWN"
        base = {
            "schema_version": "1.0.0",
            "fixture_id": fixture_id,
            "fixture_sha256": fixture_sha256,
            "classification": CLASSIFICATION,
            "contract_id": CONTRACT_ID,
            "package_version": PACKAGE_VERSION,
            "package_root_sha256": PACKAGE_ROOT_SHA256,
            "canonical_kpi_eligible": False,
            "independent_verification": False,
            "proposal_only": True,
            "limitations": list(PREFLIGHT_LIMITATIONS),
            "local_denial_audit_recorded": False,
            "external_effect_count": 0,
            "external_read_count": 0,
            "external_write_count": 0,
            "contact_count": 0,
            "spend_count": 0,
            "live_bitrix_write_count": 0,
            "created_truth": {
                "gold_acceptance": 0,
                "permit_decision": 0,
                "consent": 0,
                "payment_proof": 0,
                "order_record": 0,
                "promise": 0,
            },
            "privacy": {
                "raw_candidate_included": False,
                "raw_pii_included": False,
                "request_text_included": False,
            },
        }

        try:
            _exact_keys(raw, _FIXTURE_KEYS, "fixture")
            if (
                not isinstance(fixture_id_raw, str)
                or _REF_RE.fullmatch(fixture_id_raw) is None
            ):
                raise G2PreflightError("fixture_id is not a safe fixture reference")
            for field, expected in (
                ("schema_version", "1.0.0"),
                ("classification", CLASSIFICATION),
                ("contract_id", CONTRACT_ID),
                ("package_version", PACKAGE_VERSION),
                ("package_root_sha256", PACKAGE_ROOT_SHA256),
            ):
                if raw.get(field) != expected:
                    raise G2PreflightError("fixture authority binding mismatch")
            evaluated_at = str(raw.get("evaluated_at", ""))
            evaluated_at_value = _utc(evaluated_at)
            authority = self._authority_evidence()
            if (
                any(
                    authority.get(field) is not False
                    for field in (
                        "external_reads_enabled",
                        "external_writers_enabled",
                        "contact_enabled",
                        "spend_enabled",
                        "live_bitrix_writes_enabled",
                    )
                )
                or authority.get("active_beachhead_profile") is not None
                or authority.get("ratification") is not None
            ):
                raise G2PreflightError("authority snapshot exceeds shadow baseline")

            profile_binding = raw.get("profile_binding")
            if not isinstance(profile_binding, Mapping):
                raise G2PreflightError("profile binding is missing")
            _exact_keys(profile_binding, _PROFILE_BINDING_KEYS, "profile binding")
            profile_id = str(profile_binding.get("profile_id", ""))
            if profile_id not in SUPPORTED_PREFLIGHT_PROFILES:
                raise G2PreflightError("profile is not supported by this preflight")
            exact_binding = self.registry.binding(profile_id)
            if dict(profile_binding) != _profile_binding_value(exact_binding):
                raise G2PreflightError("profile binding mismatch")

            source = raw.get("source")
            if not isinstance(source, Mapping):
                raise G2PreflightError("source boundary is missing")
            _exact_keys(source, _SOURCE_KEYS, "source")
            expected_source = SUPPORTED_PREFLIGHT_PROFILES[profile_id]
            profile = self.registry.profile(profile_id)
            if (
                source.get("kind") != "SYNTHETIC_FIXTURE"
                or source.get("source_passport_ref")
                != expected_source["source_passport_ref"]
                or source.get("lawful_purpose") != "FIXTURE_SHADOW_PREFLIGHT_ONLY"
                or source.get("contains_raw_pii") is not False
                or source.get("contains_request_text") is not False
                or expected_source["allowed_source_label"]
                not in profile.get("allowed_input_sources", [])
            ):
                raise G2PreflightError(
                    "source is not an exact allowed synthetic source"
                )

            if not isinstance(candidate_raw, Mapping):
                raise G2PreflightError("candidate is missing")
            ready, missing, next_action = self._validate_candidate(
                profile_id=profile_id,
                candidate=candidate_raw,
                evaluated_at=evaluated_at_value,
            )
            permit = self._permit_evidence(
                permit=raw.get("permit_decision"),
                binding=exact_binding,
                candidate=candidate_raw,
                candidate_sha256=candidate_sha256,
                source_passport_ref=str(source["source_passport_ref"]),
                evaluated_at=evaluated_at,
                fixture_id=fixture_id,
            )
            status = (
                "READY_PROPOSAL_EFFECT_DENIED"
                if ready
                else "NEEDS_HUMAN_VERIFICATION_EFFECT_DENIED"
            )
            return self._seal(
                {
                    **base,
                    "evaluated_at": evaluated_at,
                    "status": status,
                    "reason_codes": [],
                    "authority": authority,
                    "profile_binding": _profile_binding_value(exact_binding),
                    "source": {
                        "kind": source["kind"],
                        "source_passport_ref": source["source_passport_ref"],
                    },
                    "candidate": {
                        "candidate_sha256": candidate_sha256,
                        "readiness_status": (
                            "READY_FOR_HUMAN_GOLD_REVIEW"
                            if ready
                            else "NEEDS_HUMAN_VERIFICATION"
                        ),
                        "missing_fields": list(missing),
                        "next_action": next_action,
                    },
                    "local_denial_audit_recorded": permit[
                        "local_denial_audit_recorded"
                    ],
                    "permit": permit,
                }
            )
        except Exception as exc:
            if isinstance(exc, G2PreflightError):
                reason = "PREFLIGHT_CONTRACT_DENIED"
            else:
                reason = "AUTHORITY_OR_CONTRACT_INVALID"
            audit_recorded = False
            if self.permit_store is not None and safe_evaluated_at != "UNKNOWN":
                try:
                    self.permit_store.record_denial(
                        operation="g2_shadow_preflight_contract",
                        attempted_actor_id="g2-shadow-preflight",
                        reason_code=reason,
                        payload_sha256=fixture_sha256,
                        trace_id=fixture_id,
                        recorded_at_utc=safe_evaluated_at,
                    )
                except Exception:
                    audit_recorded = False
                else:
                    audit_recorded = True
            return self._seal(
                {
                    **base,
                    "evaluated_at": safe_evaluated_at,
                    "status": "DENIED",
                    "reason_codes": [reason],
                    "authority": None,
                    "profile_binding": None,
                    "source": None,
                    "candidate": {
                        "candidate_sha256": candidate_sha256,
                        "readiness_status": "DENIED",
                        "missing_fields": [],
                        "next_action": "STOP",
                    },
                    "local_denial_audit_recorded": audit_recorded,
                    "permit": {
                        "supplied": raw.get("permit_decision") is not None,
                        "permit_decision_sha256": (
                            value_sha256(raw.get("permit_decision"))
                            if raw.get("permit_decision") is not None
                            else None
                        ),
                        "exact_persisted": False,
                        "local_denial_audit_recorded": audit_recorded,
                        "effect_decision": "DENY",
                        "reason_codes": [reason],
                    },
                }
            )


def _zero_int(value: object) -> bool:
    return type(value) is int and value == 0


def _validate_sealed_result(
    raw: Mapping[str, Any], registry: G2MotionRegistry
) -> dict[str, Any]:
    item = dict(raw)
    _exact_keys(item, _RESULT_KEYS, "preflight result")
    seal = item.get("bundle_sha256")
    unsigned = dict(item)
    unsigned.pop("bundle_sha256")
    if (
        not isinstance(seal, str)
        or _SHA_RE.fullmatch(seal) is None
        or seal != value_sha256(unsigned)
    ):
        raise G2PreflightError("preflight result seal mismatch")
    for field, expected in (
        ("schema_version", "1.0.0"),
        ("classification", CLASSIFICATION),
        ("contract_id", CONTRACT_ID),
        ("package_version", PACKAGE_VERSION),
        ("package_root_sha256", PACKAGE_ROOT_SHA256),
        ("canonical_kpi_eligible", False),
        ("independent_verification", False),
        ("proposal_only", True),
    ):
        matches = (
            item.get(field) is expected
            if isinstance(expected, bool)
            else item.get(field) == expected
        )
        if not matches:
            raise G2PreflightError(f"preflight result {field} mismatch")
    if item.get("limitations") != list(PREFLIGHT_LIMITATIONS):
        raise G2PreflightError("preflight limitations are not exact")
    if (
        not isinstance(item.get("fixture_id"), str)
        or _SAFE_FIXTURE_ID_RE.fullmatch(item["fixture_id"]) is None
    ):
        raise G2PreflightError("preflight fixture_id is not sanitised")
    if (
        not isinstance(item.get("fixture_sha256"), str)
        or _SHA_RE.fullmatch(item["fixture_sha256"]) is None
    ):
        raise G2PreflightError("preflight fixture digest is invalid")
    _utc(item.get("evaluated_at"))
    if (
        item.get("status")
        not in {
            "READY_PROPOSAL_EFFECT_DENIED",
            "NEEDS_HUMAN_VERIFICATION_EFFECT_DENIED",
        }
        or item.get("reason_codes") != []
    ):
        raise G2PreflightError("preflight result status is not bundle-eligible")
    for field in (
        "external_effect_count",
        "external_read_count",
        "external_write_count",
        "contact_count",
        "spend_count",
        "live_bitrix_write_count",
    ):
        if not _zero_int(item.get(field)):
            raise G2PreflightError(f"preflight result fabricated effect: {field}")
    if not isinstance(item.get("local_denial_audit_recorded"), bool):
        raise G2PreflightError("preflight audit marker is invalid")

    created = item.get("created_truth")
    if not isinstance(created, Mapping):
        raise G2PreflightError("preflight created_truth is missing")
    _exact_keys(created, _CREATED_TRUTH_KEYS, "created_truth")
    if any(not _zero_int(value) for value in created.values()):
        raise G2PreflightError("preflight fabricated canonical truth")
    privacy = item.get("privacy")
    if not isinstance(privacy, Mapping):
        raise G2PreflightError("preflight privacy boundary is missing")
    _exact_keys(privacy, _PRIVACY_KEYS, "privacy")
    if any(value is not False for value in privacy.values()):
        raise G2PreflightError("preflight contains raw/private material")

    authority = item.get("authority")
    if not isinstance(authority, Mapping):
        raise G2PreflightError("preflight authority evidence is missing")
    _exact_keys(authority, _AUTHORITY_RESULT_KEYS, "authority")
    for field in ("manifest_sha256", "freeze_sha256"):
        if (
            not isinstance(authority.get(field), str)
            or _SHA_RE.fullmatch(authority[field]) is None
        ):
            raise G2PreflightError("preflight authority digest is invalid")
    if authority.get("manifest_sha256") != _file_sha256(
        _MANIFEST_PATH
    ) or authority.get("freeze_sha256") != _file_sha256(_FREEZE_PATH):
        raise G2PreflightError("preflight authority digest is not current")
    if (
        authority.get("active_beachhead_profile") is not None
        or authority.get("ratification") is not None
        or any(
            authority.get(field) is not False
            for field in (
                "external_reads_enabled",
                "external_writers_enabled",
                "contact_enabled",
                "spend_enabled",
                "live_bitrix_writes_enabled",
            )
        )
    ):
        raise G2PreflightError("preflight authority exceeds the fixed freeze")

    profile_binding = item.get("profile_binding")
    if not isinstance(profile_binding, Mapping):
        raise G2PreflightError("preflight profile binding is missing")
    _exact_keys(profile_binding, _PROFILE_BINDING_KEYS, "profile binding")
    profile_id = str(profile_binding.get("profile_id", ""))
    if profile_id not in SUPPORTED_PREFLIGHT_PROFILES or dict(
        profile_binding
    ) != _profile_binding_value(registry.binding(profile_id)):
        raise G2PreflightError("preflight exact profile binding mismatch")

    source = item.get("source")
    if not isinstance(source, Mapping):
        raise G2PreflightError("preflight source result is missing")
    _exact_keys(source, {"kind", "source_passport_ref"}, "source result")
    if (
        source.get("kind") != "SYNTHETIC_FIXTURE"
        or source.get("source_passport_ref")
        != SUPPORTED_PREFLIGHT_PROFILES[profile_id]["source_passport_ref"]
    ):
        raise G2PreflightError("preflight source result mismatch")

    candidate = item.get("candidate")
    if not isinstance(candidate, Mapping):
        raise G2PreflightError("preflight candidate result is missing")
    _exact_keys(candidate, _CANDIDATE_RESULT_KEYS, "candidate result")
    if (
        not isinstance(candidate.get("candidate_sha256"), str)
        or _SHA_RE.fullmatch(candidate["candidate_sha256"]) is None
    ):
        raise G2PreflightError("preflight candidate digest is invalid")
    missing = candidate.get("missing_fields")
    if (
        not isinstance(missing, list)
        or any(not isinstance(field, str) for field in missing)
        or len(set(missing)) != len(missing)
        or any(field not in REQUIRED_CANDIDATE_FIELDS[profile_id] for field in missing)
        or missing
        != [
            field
            for field in REQUIRED_CANDIDATE_FIELDS[profile_id]
            if field in set(missing)
        ]
    ):
        raise G2PreflightError("preflight missing_fields are invalid")
    ready = item["status"] == "READY_PROPOSAL_EFFECT_DENIED"
    if ready:
        if (
            candidate.get("readiness_status") != "READY_FOR_HUMAN_GOLD_REVIEW"
            or candidate.get("next_action") != "HUMAN_GOLD_REVIEW"
            or missing != []
        ):
            raise G2PreflightError("preflight ready state is inconsistent")
    elif (
        candidate.get("readiness_status") != "NEEDS_HUMAN_VERIFICATION"
        or candidate.get("next_action") != "HUMAN_VERIFY"
        or not missing
    ):
        raise G2PreflightError("preflight verification state is inconsistent")

    permit = item.get("permit")
    if not isinstance(permit, Mapping):
        raise G2PreflightError("preflight permit result is missing")
    _exact_keys(permit, _PERMIT_RESULT_KEYS, "permit result")
    if (
        not isinstance(permit.get("supplied"), bool)
        or not isinstance(permit.get("exact_persisted"), bool)
        or not isinstance(permit.get("local_denial_audit_recorded"), bool)
        or permit.get("effect_decision") != "DENY"
        or permit.get("local_denial_audit_recorded")
        is not item.get("local_denial_audit_recorded")
    ):
        raise G2PreflightError("preflight permit denial boundary mismatch")
    permit_reasons = permit.get("reason_codes")
    if (
        not isinstance(permit_reasons, list)
        or not permit_reasons
        or any(not isinstance(reason, str) or not reason for reason in permit_reasons)
        or len(set(permit_reasons)) != len(permit_reasons)
        or any(reason not in _PERMIT_REASON_CODES for reason in permit_reasons)
        or permit_reasons != sorted(permit_reasons)
        or "UNRATIFIED_SHADOW_DESIGN_ONLY" not in permit_reasons
    ):
        raise G2PreflightError("preflight permit denial reasons are invalid")
    if permit["supplied"]:
        if (
            not isinstance(permit.get("permit_decision_sha256"), str)
            or _SHA_RE.fullmatch(permit["permit_decision_sha256"]) is None
        ):
            raise G2PreflightError("preflight supplied permit digest is invalid")
    elif (
        permit.get("permit_decision_sha256") is not None
        or permit.get("exact_persisted") is not False
        or "PERMIT_NOT_SUPPLIED" not in permit_reasons
    ):
        raise G2PreflightError("preflight missing permit state is inconsistent")
    return item


def _validated_sorted_results(results: object) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        raise G2PreflightError("bundle results must be a list")
    registry = G2MotionRegistry()
    validated = [
        _validate_sealed_result(item, registry)
        for item in results
        if isinstance(item, Mapping)
    ]
    if len(validated) != len(results):
        raise G2PreflightError("bundle result must be an object")
    profile_ids = [item["profile_binding"]["profile_id"] for item in validated]
    fixture_ids = [item["fixture_id"] for item in validated]
    if (
        len(validated) != len(SUPPORTED_PREFLIGHT_PROFILES)
        or set(profile_ids) != set(SUPPORTED_PREFLIGHT_PROFILES)
        or len(set(profile_ids)) != len(profile_ids)
        or len(set(fixture_ids)) != len(fixture_ids)
    ):
        raise G2PreflightError("bundle requires unique exact three-profile results")
    return sorted(validated, key=lambda item: item["fixture_id"])


def _validate_preflight_bundle(value: Mapping[str, Any]) -> dict[str, Any]:
    bundle = dict(value)
    _exact_keys(bundle, _BUNDLE_KEYS, "preflight bundle")
    expected_sha = bundle.get("bundle_sha256")
    unsigned = dict(bundle)
    unsigned.pop("bundle_sha256")
    if (
        not isinstance(expected_sha, str)
        or _SHA_RE.fullmatch(expected_sha) is None
        or expected_sha != value_sha256(unsigned)
    ):
        raise G2PreflightError("bundle digest mismatch")
    for field, expected in (
        ("schema_version", "1.0.0"),
        ("classification", CLASSIFICATION),
        ("contract_id", CONTRACT_ID),
        ("package_version", PACKAGE_VERSION),
        ("package_root_sha256", PACKAGE_ROOT_SHA256),
    ):
        if bundle.get(field) != expected:
            raise G2PreflightError(f"bundle {field} mismatch")
    if (
        bundle.get("canonical_kpi_eligible") is not False
        or bundle.get("independent_verification") is not False
        or not _zero_int(bundle.get("external_effect_count"))
        or bundle.get("limitations") != list(PREFLIGHT_LIMITATIONS)
    ):
        raise G2PreflightError("bundle authority/classification mismatch")
    ordered = _validated_sorted_results(bundle.get("results"))
    if bundle.get("results") != ordered:
        raise G2PreflightError("bundle results are not canonically sorted")
    return bundle


def build_preflight_bundle(results: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate and seal the exact three-motion result without raw fixture material."""

    ordered = _validated_sorted_results(results)
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "classification": CLASSIFICATION,
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "canonical_kpi_eligible": False,
        "independent_verification": False,
        "limitations": list(PREFLIGHT_LIMITATIONS),
        "external_effect_count": 0,
        "results": ordered,
    }
    value["bundle_sha256"] = value_sha256(value)
    return _validate_preflight_bundle(value)


def write_content_addressed_bundle(path: str | Path, bundle: Mapping[str, Any]) -> str:
    """Create one local bundle, replay exact bytes, and reject path reuse conflicts."""

    value = _validate_preflight_bundle(bundle)
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    serialized_bytes = serialized.encode("utf-8", "strict")
    try:
        with output.open("xb") as stream:
            stream.write(serialized_bytes)
    except FileExistsError:
        try:
            existing = output.read_bytes()
        except OSError as exc:
            raise G2PreflightConflict(
                "existing preflight bundle is unreadable"
            ) from exc
        if existing != serialized_bytes:
            raise G2PreflightConflict("preflight output path has different bytes")
        return "REPLAY"
    return "APPLIED"


__all__ = [
    "CLASSIFICATION",
    "G2PreflightConflict",
    "G2PreflightError",
    "G2ShadowPreflightService",
    "PREFLIGHT_LIMITATIONS",
    "PREFLIGHT_PERMIT_PURPOSE",
    "PREFLIGHT_POLICY_ISSUER",
    "PREFLIGHT_POLICY_VERSION",
    "SUPPORTED_PREFLIGHT_PROFILES",
    "build_preflight_bundle",
    "load_preflight_fixture",
    "write_content_addressed_bundle",
]
