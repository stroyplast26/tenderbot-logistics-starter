"""PII-separated website inbound attribution for the MDOS v7 G2 shadow lane.

The contract deliberately accepts the non-PII capture and private form body as
two arguments.  Private values are validated but are never retained in the
analytics, Bitrix projection or evidence result.  This module performs no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any, Mapping

from .authority import authority_snapshot
from .contracts import value_sha256


SCHEMA_VERSION = "1.0.0"
SOURCE_HIERARCHY_VERSION = "website-attribution-v1"
UNKNOWN = "UNKNOWN"
UTM_FIELDS = (
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
)
REFERRER_CLASSIFICATIONS = frozenset(
    {"SEARCH", "SOCIAL", "REFERRAL", "CAMPAIGN", "DIRECT", "INTERNAL", UNKNOWN}
)

_PUBLIC_FIELDS = frozenset(
    {
        "submission_id",
        "captured_at",
        "origin_channel",
        "landing_path",
        "prior_path",
        "referrer_classification",
        "utm",
        "synthetic",
        "canonical_kpi_eligible",
    }
)
_PRIVATE_FIELDS = frozenset(
    {
        "pii",
        "request_text",
        "metrika_visit_id",
        "metrika_client_id",
        "metrika_ids_lawfully_supplied",
    }
)
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "pii",
        "raw_pii",
        "request_text",
        "full_name",
        "name",
        "email",
        "phone",
        "company_name",
        "metrika_visit_id",
        "metrika_client_id",
    }
)
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_METRIKA_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
_EMAIL_LIKE_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_PHONE_LIKE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s().-]*){7,}(?!\d)")
_URL_LIKE_RE = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class InboundAttributionError(ValueError):
    """A website attribution record cannot be represented without ambiguity or PII risk."""


@dataclass(frozen=True)
class AttributionBundle:
    correlation_id: str
    analytics: dict[str, Any]
    bitrix_projection: dict[str, Any]
    reconciliation: dict[str, Any]
    evidence_summary: dict[str, Any]
    external_effect_count: int = 0
    canonical_kpi_eligible: bool = False


def _exact_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    extras = set(value) - allowed
    if extras:
        raise InboundAttributionError(f"{label} contains forbidden fields: {sorted(extras)}")


def _utc_z(value: object) -> str:
    if not isinstance(value, str) or _UTC_Z_RE.fullmatch(value) is None:
        raise InboundAttributionError("captured_at must be RFC3339 UTC Z")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as exc:
        raise InboundAttributionError("captured_at must be RFC3339 UTC Z") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise InboundAttributionError("captured_at must be RFC3339 UTC Z")
    return value


def _unknownable_text(value: object, label: str, *, maximum: int = 256) -> str:
    if value in (None, ""):
        return UNKNOWN
    if not isinstance(value, str):
        raise InboundAttributionError(f"{label} must be text or UNKNOWN")
    result = value.strip()
    if not result:
        return UNKNOWN
    if len(result) > maximum or _CONTROL_RE.search(result):
        raise InboundAttributionError(f"{label} has an unsafe shape")
    return result


def _path(value: object, label: str) -> str:
    result = _unknownable_text(value, label, maximum=512)
    if result == UNKNOWN:
        return result
    if not result.startswith("/") or "?" in result or "#" in result or "://" in result:
        raise InboundAttributionError(f"{label} must be a path without query or fragment")
    return result


def _safe_utm(value: object, label: str) -> str:
    result = _unknownable_text(value, label, maximum=300)
    if result == UNKNOWN:
        return result
    if (
        _EMAIL_LIKE_RE.search(result)
        or _PHONE_LIKE_RE.search(result)
        or _URL_LIKE_RE.search(result)
        or "?" in result
        or "#" in result
    ):
        raise InboundAttributionError(f"{label} may contain PII or a URL")
    return result


def _private_presence(value: Mapping[str, Any]) -> dict[str, bool]:
    _exact_keys(value, _PRIVATE_FIELDS, "private inbound payload")
    pii = value.get("pii", {})
    if not isinstance(pii, Mapping):
        raise InboundAttributionError("private pii must be an object")
    for key, item in pii.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise InboundAttributionError("private pii keys and values must be text")
    request_text = value.get("request_text", "")
    if not isinstance(request_text, str):
        raise InboundAttributionError("private request_text must be text")
    visit_id = value.get("metrika_visit_id", "")
    client_id = value.get("metrika_client_id", "")
    if not isinstance(visit_id, str) or not isinstance(client_id, str):
        raise InboundAttributionError("Metrika identifiers must be text")
    for label, item in (("metrika_visit_id", visit_id), ("metrika_client_id", client_id)):
        if item and _METRIKA_ID_RE.fullmatch(item) is None:
            raise InboundAttributionError(f"{label} has an invalid format")
    lawful = value.get("metrika_ids_lawfully_supplied", False)
    if not isinstance(lawful, bool):
        raise InboundAttributionError("metrika_ids_lawfully_supplied must be boolean")
    if (visit_id or client_id) and not lawful:
        raise InboundAttributionError("Metrika identifiers require lawful supplied evidence")
    return {
        "private_pii_present": bool(pii),
        "private_request_text_present": bool(request_text),
        "metrika_visit_id_present": bool(visit_id),
        "metrika_client_id_present": bool(client_id),
        "metrika_ids_lawfully_supplied": bool((visit_id or client_id) and lawful),
    }


def _source_resolution(
    *, utm: Mapping[str, str], referrer_classification: str
) -> tuple[str, str, str]:
    if utm["utm_source"] != UNKNOWN:
        return "ATTRIBUTED", "ALLOWLISTED_UTM", "UTM"
    if any(value != UNKNOWN for key, value in utm.items() if key != "utm_source"):
        return UNKNOWN, "PARTIAL_UTM_UNKNOWN_SOURCE", UNKNOWN
    referrer_sources = {
        "SEARCH": "ORGANIC_SEARCH",
        "SOCIAL": "SOCIAL_REFERRER",
        "REFERRAL": "EXTERNAL_REFERRAL",
        "CAMPAIGN": "CLASSIFIED_CAMPAIGN_REFERRER",
    }
    if referrer_classification in referrer_sources:
        return "ATTRIBUTED", "CLASSIFIED_EXTERNAL_REFERRER", referrer_sources[
            referrer_classification
        ]
    if referrer_classification == "DIRECT":
        return "ATTRIBUTED", "EXPLICIT_DIRECT", "DIRECT_WEBSITE"
    return UNKNOWN, "NO_TRUSTED_SOURCE_EVIDENCE", UNKNOWN


def assert_pii_free(value: Mapping[str, Any]) -> None:
    """Reject private field names anywhere in an analytics/evidence payload."""

    def visit(item: object) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if str(key).lower() in _FORBIDDEN_PUBLIC_KEYS:
                    raise InboundAttributionError("private field leaked into public output")
                visit(nested)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested)

    visit(value)


def reconcile_attribution(
    analytics: Mapping[str, Any], bitrix_projection: Mapping[str, Any]
) -> dict[str, Any]:
    safe_analytics = dict(analytics)
    projection = dict(bitrix_projection)
    assert_pii_free(safe_analytics)
    assert_pii_free(projection)
    fields = projection.get("fields")
    if not isinstance(fields, Mapping):
        raise InboundAttributionError("Bitrix attribution projection fields are missing")
    correlation_id = safe_analytics.get("opaque_correlation_id")
    expected_fields = {
        "opaque_correlation_id": correlation_id,
        "captured_at": safe_analytics.get("captured_at"),
        "origin_channel": safe_analytics.get("origin_channel"),
        "landing_path": safe_analytics.get("landing_path"),
        "prior_path": safe_analytics.get("prior_path"),
        "referrer_classification": safe_analytics.get("referrer_classification"),
        "utm": safe_analytics.get("utm"),
        "attribution_status": safe_analytics.get("attribution_status"),
        "source_basis": safe_analytics.get("source_basis"),
        "source_class": safe_analytics.get("source_class"),
        "metrika_visit_id_present": safe_analytics.get("metrika_visit_id_present"),
        "metrika_client_id_present": safe_analytics.get("metrika_client_id_present"),
    }
    if (
        projection.get("schema_version") != SCHEMA_VERSION
        or projection.get("mode") != "SHADOW"
        or projection.get("external_effect") is not False
        or dict(fields) != expected_fields
    ):
        raise InboundAttributionError("Bitrix attribution projection does not match analytics")
    status = (
        "RECONCILED_ATTRIBUTED"
        if safe_analytics.get("attribution_status") == "ATTRIBUTED"
        else "RECONCILED_UNKNOWN"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "opaque_correlation_id": correlation_id,
        "status": status,
        "source_hierarchy_version": SOURCE_HIERARCHY_VERSION,
        "analytics_sha256": value_sha256(safe_analytics),
        "bitrix_projection_sha256": value_sha256(projection),
        "exact_projection_match": True,
        "canonical_kpi_eligible": False,
        "external_effect": False,
    }


class WebsiteInboundAttributionContract:
    """Build one deterministic, PII-free attribution and shadow projection bundle."""

    def __init__(self) -> None:
        snapshot = authority_snapshot()
        freeze = snapshot.get("freeze")
        manifest = snapshot.get("manifest")
        defaults = manifest.get("defaults_pending_ratification") if isinstance(manifest, dict) else None
        false_flags = (
            "external_reads_enabled",
            "external_writers_enabled",
            "contact_enabled",
            "spend_enabled",
        )
        if (
            not isinstance(freeze, dict)
            or not isinstance(defaults, dict)
            or any(freeze.get(flag) is not False for flag in false_flags)
            or any(defaults.get(flag) is not False for flag in false_flags)
            or freeze.get("live_bitrix_writes_enabled") is not False
            or manifest.get("active_beachhead_profile") is not None
        ):
            raise InboundAttributionError("website attribution authority is not shadow-only")

    def capture(
        self,
        public_claim: Mapping[str, Any],
        private_payload: Mapping[str, Any],
    ) -> AttributionBundle:
        if not isinstance(public_claim, Mapping) or not isinstance(private_payload, Mapping):
            raise InboundAttributionError("website inbound capture must use two objects")
        _exact_keys(public_claim, _PUBLIC_FIELDS, "public attribution claim")
        if public_claim.get("synthetic") is not True:
            raise InboundAttributionError("website attribution is fixture/shadow only")
        if public_claim.get("canonical_kpi_eligible") is not False:
            raise InboundAttributionError("website attribution cannot be KPI eligible")
        submission_id = public_claim.get("submission_id")
        if not isinstance(submission_id, str) or _OPAQUE_ID_RE.fullmatch(submission_id) is None:
            raise InboundAttributionError("submission_id must be opaque and bounded")
        captured_at = _utc_z(public_claim.get("captured_at"))
        origin_channel = _unknownable_text(
            public_claim.get("origin_channel"), "origin_channel", maximum=64
        ).upper()
        if origin_channel not in {"WEBSITE_FORM", UNKNOWN}:
            raise InboundAttributionError("origin_channel is not a website form")
        landing_path = _path(public_claim.get("landing_path"), "landing_path")
        prior_path = _path(public_claim.get("prior_path"), "prior_path")
        referrer = _unknownable_text(
            public_claim.get("referrer_classification"),
            "referrer_classification",
            maximum=64,
        ).upper()
        if referrer not in REFERRER_CLASSIFICATIONS:
            raise InboundAttributionError("referrer_classification is not allowlisted")
        raw_utm = public_claim.get("utm", {})
        if not isinstance(raw_utm, Mapping):
            raise InboundAttributionError("utm must be an object")
        _exact_keys(raw_utm, frozenset(UTM_FIELDS), "utm")
        utm = {field: _safe_utm(raw_utm.get(field), field) for field in UTM_FIELDS}
        private_presence = _private_presence(private_payload)
        attribution_status, source_basis, source_class = _source_resolution(
            utm=utm, referrer_classification=referrer
        )
        correlation_material = {
            "schema_version": SCHEMA_VERSION,
            "source": "WEBSITE_FORM_SHADOW",
            "submission_id": submission_id,
            "captured_at": captured_at,
        }
        correlation_id = f"lf_web_v1_{value_sha256(correlation_material)[:40]}"
        analytics: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "WEBSITE_INBOUND_ATTRIBUTION",
            "opaque_correlation_id": correlation_id,
            "captured_at": captured_at,
            "origin_channel": origin_channel,
            "landing_path": landing_path,
            "prior_path": prior_path,
            "referrer_classification": referrer,
            "utm": utm,
            "attribution_status": attribution_status,
            "source_basis": source_basis,
            "source_class": source_class,
            "source_hierarchy_version": SOURCE_HIERARCHY_VERSION,
            "metrika_visit_id_present": private_presence["metrika_visit_id_present"],
            "metrika_client_id_present": private_presence["metrika_client_id_present"],
            "canonical_kpi_eligible": False,
            "external_effect": False,
        }
        projection_fields = {
            key: analytics[key]
            for key in (
                "opaque_correlation_id",
                "captured_at",
                "origin_channel",
                "landing_path",
                "prior_path",
                "referrer_classification",
                "utm",
                "attribution_status",
                "source_basis",
                "source_class",
                "metrika_visit_id_present",
                "metrika_client_id_present",
            )
        }
        bitrix_projection = {
            "schema_version": SCHEMA_VERSION,
            "projection_type": "WEBSITE_ATTRIBUTION",
            "mode": "SHADOW",
            "external_effect": False,
            "fields": projection_fields,
        }
        assert_pii_free(analytics)
        assert_pii_free(bitrix_projection)
        reconciliation = reconcile_attribution(analytics, bitrix_projection)
        evidence_summary = {
            "schema_version": SCHEMA_VERSION,
            "classification": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
            "opaque_correlation_id": correlation_id,
            "attribution_status": attribution_status,
            "source_basis": source_basis,
            "source_class": source_class,
            "reconciliation_status": reconciliation["status"],
            "analytics_sha256": reconciliation["analytics_sha256"],
            "bitrix_projection_sha256": reconciliation["bitrix_projection_sha256"],
            "private_payload_separated": True,
            "private_pii_present": private_presence["private_pii_present"],
            "private_request_text_present": private_presence[
                "private_request_text_present"
            ],
            "metrika_visit_id_present": private_presence["metrika_visit_id_present"],
            "metrika_client_id_present": private_presence["metrika_client_id_present"],
            "raw_private_values_included": False,
            "canonical_kpi_eligible": False,
            "external_effect_count": 0,
        }
        assert_pii_free(evidence_summary)
        return AttributionBundle(
            correlation_id=correlation_id,
            analytics=analytics,
            bitrix_projection=bitrix_projection,
            reconciliation=reconciliation,
            evidence_summary=evidence_summary,
        )


def serialized_public_bundle(bundle: AttributionBundle) -> str:
    """Return the deterministic public artifact; the object has no private payload field."""

    value = {
        "analytics": bundle.analytics,
        "bitrix_projection": bundle.bitrix_projection,
        "reconciliation": bundle.reconciliation,
        "evidence_summary": bundle.evidence_summary,
    }
    assert_pii_free(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


__all__ = [
    "AttributionBundle",
    "InboundAttributionError",
    "REFERRER_CLASSIFICATIONS",
    "SCHEMA_VERSION",
    "SOURCE_HIERARCHY_VERSION",
    "UNKNOWN",
    "UTM_FIELDS",
    "WebsiteInboundAttributionContract",
    "assert_pii_free",
    "reconcile_attribution",
    "serialized_public_bundle",
]
