"""Fail-closed bridge from an approved site submission to the commercial graph.

Only the exact ``site-form-submission-v1`` envelope emitted by
:mod:`lead_factory.site_ingress` is accepted.  Human review actor strings are
not authority: an injected typed authority must return a receipt bound to the
latest APPROVE fact and the complete normalized projection.  No transport or
credential code lives here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import json
import re
from typing import Any, Callable, Protocol

from .bitrix_graph_mapping import (
    BitrixGraphBridgeBinding,
    BitrixGraphMappingError,
    validate_graph_bridge_binding,
)
from .ids import canonical_json, normalize_email, normalize_inn, payload_hash
from .reviewed_opportunity_bridge import (
    ReviewedOpportunityBridge,
    ReviewedOpportunityBridgeError,
    ReviewedOpportunityBridgeResult,
    ReviewedOpportunityProjection,
    ReviewedOpportunityProof,
)
from .site_ingress import (
    ConsentPurpose,
    SITE_FORM_SCHEMA_VERSION,
    SiteAttribution,
    SiteValidationError,
    TrustedSitePolicy,
    _PAID_MEDIUM_RE,
    _compile_policy,
    _email,
    _evidence_ref,
    _phone,
    _url,
    _utc,
)
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity
from .store import CURRENT_SCHEMA_VERSION, FactoryStore


SITE_APPROVAL_CAPABILITY_VERSION = "site-commercial-approval-authority-v1"
SITE_APPROVAL_RECEIPT_VERSION = "site-commercial-approval-receipt-v1"
SITE_COMMERCIAL_DATA_CONTRACT_VERSION = SITE_FORM_SCHEMA_VERSION


class SiteCommercialBridgeError(RuntimeError):
    """Safe base error for the approved-site boundary."""


class SiteCommercialValidationError(SiteCommercialBridgeError):
    """The command, source contract, policy, or authority proof is invalid."""


class SiteCommercialConflict(SiteCommercialBridgeError):
    """Append-only facts changed or conflict with an existing commercial graph."""


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_INN_TEXT = re.compile(r"^[0-9 \t-]+$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CLICK_ID = re.compile(r"^[A-Za-z0-9._:~-]+$")
_YCLID = re.compile(r"^[A-Za-z0-9._~-]+$")
_RECORD_KEYS = {
    "schema_version",
    "source_id",
    "trusted_policy",
    "submission_id",
    "correlation_id",
    "attribution_state",
    "submitted_at_utc",
    "company_name",
    "applicant_role",
    "city_or_region",
    "object_or_recurring_need",
    "product_or_system",
    "estimated_volume",
    "purchase_stage",
    "supplier_selection_open",
    "required_delivery_or_quote_date",
    "specification_status",
    "contact",
    "landing",
    "attribution",
    "consents",
    "attachment_summary",
}
_UTM_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
}
_CONSENT_KEYS = {
    "purpose",
    "granted",
    "text",
    "text_version",
    "text_sha256",
    "occurred_at_utc",
    "source",
    "page_url",
    "evidence_ref",
    "valid_until_utc",
}


def _required(value: object, message: str, *, maximum: int = 2048) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum or _CONTROL.search(result):
        raise SiteCommercialValidationError(message)
    return result


def _optional(value: object, message: str, *, maximum: int = 2048) -> str:
    if not isinstance(value, str):
        raise SiteCommercialValidationError(message)
    result = value.strip()
    if result != value or len(result) > maximum or _CONTROL.search(result):
        raise SiteCommercialValidationError(message)
    return result


def _safe_id(value: object, message: str) -> str:
    result = _required(value, message, maximum=512)
    if not _SAFE_ID.fullmatch(result):
        raise SiteCommercialValidationError(message)
    return result


def _digest(value: object, message: str) -> str:
    result = str(value or "").strip()
    if not _HEX64.fullmatch(result):
        raise SiteCommercialValidationError(message)
    return result


def _exact_keys(value: object, keys: set[str], message: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SiteCommercialValidationError(message)
    return value


def _strict_json_object(raw: object, message: str) -> dict[str, Any]:
    def reject_constant(_token: str) -> None:
        raise ValueError("non-finite JSON")

    try:
        result = json.loads(str(raw or ""), parse_constant=reject_constant)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise SiteCommercialValidationError(message) from None
    if not isinstance(result, dict):
        raise SiteCommercialValidationError(message)
    return result


@dataclass(frozen=True, slots=True, repr=False)
class SiteOpportunityProjection:
    """Reviewer-supplied exact company/contact identity for one site record."""

    company_inn: str
    contact_email: str
    identity_evidence_ref: str

    def __repr__(self) -> str:
        return "SiteOpportunityProjection(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SiteCommercialPolicy:
    """Exact site registry and identity policy allowed into the commercial graph."""

    policy_id: str
    policy_version: str
    source_id: str
    identity_policy_version: str
    trusted_site_policy: TrustedSitePolicy
    bitrix_graph_binding: BitrixGraphBridgeBinding

    def __repr__(self) -> str:
        return "SiteCommercialPolicy(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ApprovedSiteCommand:
    """Stale-safe pointer plus the manually verified exact identity projection."""

    source_record_id: str
    observation_id: str
    review_id: str
    latest_resolution_id: str
    expected_payload_hash: str
    projection: SiteOpportunityProjection
    actor: str
    idempotency_key: str

    def __repr__(self) -> str:
        return "ApprovedSiteCommand(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TrustedSiteApprovalRequest:
    """All lineage and normalized facts an injected authority must authenticate."""

    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    resolution_event_id: str
    decision: str
    resolved_by: str
    evidence_ref: str
    resolution_command_hash: str
    resolution_event_hash: str
    source_id: str
    source_payload_hash: str
    data_contract_version: str
    site_policy_id: str
    site_policy_version: str
    site_policy_hash: str
    commercial_policy_id: str
    commercial_policy_version: str
    commercial_policy_hash: str
    identity_policy_version: str
    identity_evidence_ref: str
    mapping_manifest_hash: str
    lf_source_id: str
    activity_deadline_utc: str
    projection: ReviewedOpportunityProjection

    def __repr__(self) -> str:
        return "TrustedSiteApprovalRequest(<redacted>)"

    @property
    def request_hash(self) -> str:
        return payload_hash(_approval_request_payload(self))


@dataclass(frozen=True, slots=True, repr=False)
class TrustedSiteApprovalReceipt:
    """Opaque, typed receipt bound to one exact site approval request."""

    capability_version: str
    receipt_version: str
    authority_id: str
    receipt_id: str
    request: TrustedSiteApprovalRequest
    request_hash: str

    def __repr__(self) -> str:
        return "TrustedSiteApprovalReceipt(<redacted>)"

    @property
    def receipt_hash(self) -> str:
        return payload_hash(
            {
                "capability_version": self.capability_version,
                "receipt_version": self.receipt_version,
                "authority_id": self.authority_id,
                "receipt_id": self.receipt_id,
                "request_hash": self.request_hash,
                "request": _approval_request_payload(self.request),
            }
        )


class TrustedSiteApprovalAuthority(Protocol):
    capability_version: str

    def verify_approval(
        self, request: TrustedSiteApprovalRequest
    ) -> TrustedSiteApprovalReceipt: ...


@dataclass(frozen=True, slots=True)
class SiteCommercialBridgeResult:
    state: str
    reason: str
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    staged: ReviewedOpportunityBridgeResult | None = None

    @property
    def lf_company_id(self) -> str:
        return self.staged.graph.lf_company_id if self.staged else ""

    @property
    def lf_contact_id(self) -> str:
        return self.staged.graph.lf_contact_id if self.staged else ""

    @property
    def lf_project_id(self) -> str:
        return self.staged.graph.lf_project_id if self.staged else ""

    @property
    def lf_opportunity_id(self) -> str:
        return self.staged.graph.lf_opportunity_id if self.staged else ""

    @property
    def crm_stage(self) -> Any | None:
        return self.staged.crm_stage if self.staged else None


@dataclass(frozen=True, slots=True)
class _ApprovedSite:
    request: TrustedSiteApprovalRequest
    projection: ReviewedOpportunityProjection


def _exact_company_inn(value: str) -> str:
    """Normalize only an explicitly numeric INN representation.

    ``normalize_inn`` intentionally extracts ASCII digits for shared identity
    helpers.  The reviewed commercial boundary is stricter: arbitrary text
    wrapped around those digits must never become an exact company match.
    """

    raw = value.strip()
    normalized = normalize_inn(raw)
    if not raw or not _INN_TEXT.fullmatch(raw) or len(normalized) not in {10, 12}:
        return ""
    return normalized


def _commercial_policy_payload(
    policy: SiteCommercialPolicy, compiled_site_policy: Any
) -> dict[str, Any]:
    return {
        "site_commercial_policy_version": 1,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "source_id": policy.source_id,
        "data_contract_version": SITE_COMMERCIAL_DATA_CONTRACT_VERSION,
        "identity_policy_version": policy.identity_policy_version,
        "mapping_manifest_hash": validate_graph_bridge_binding(
            policy.bitrix_graph_binding
        ),
        "lf_source_id": policy.bitrix_graph_binding.lf_source_id,
        "activity_deadline_utc": policy.bitrix_graph_binding.activity_deadline_utc,
        "trusted_site_policy_id": compiled_site_policy.policy_id,
        "trusted_site_policy_version": compiled_site_policy.policy_version,
        "trusted_site_policy_hash": compiled_site_policy.canonical_hash,
    }


def _approval_request_payload(request: TrustedSiteApprovalRequest) -> dict[str, Any]:
    return {
        "site_approval_request_version": 1,
        "source_record_id": request.source_record_id,
        "observation_id": request.observation_id,
        "review_id": request.review_id,
        "resolution_id": request.resolution_id,
        "resolution_event_id": request.resolution_event_id,
        "decision": request.decision,
        "resolved_by": request.resolved_by,
        "evidence_ref": request.evidence_ref,
        "resolution_command_hash": request.resolution_command_hash,
        "resolution_event_hash": request.resolution_event_hash,
        "source_id": request.source_id,
        "source_payload_hash": request.source_payload_hash,
        "data_contract_version": request.data_contract_version,
        "site_policy_id": request.site_policy_id,
        "site_policy_version": request.site_policy_version,
        "site_policy_hash": request.site_policy_hash,
        "commercial_policy_id": request.commercial_policy_id,
        "commercial_policy_version": request.commercial_policy_version,
        "commercial_policy_hash": request.commercial_policy_hash,
        "identity_policy_version": request.identity_policy_version,
        "identity_evidence_ref": request.identity_evidence_ref,
        "mapping_manifest_hash": request.mapping_manifest_hash,
        "lf_source_id": request.lf_source_id,
        "activity_deadline_utc": request.activity_deadline_utc,
        "projection_hash": request.projection.projection_hash,
    }


def _validate_command(command: ApprovedSiteCommand) -> None:
    if type(command) is not ApprovedSiteCommand:
        raise SiteCommercialValidationError("approved site command is invalid")
    for value, message in (
        (command.source_record_id, "site source record identity is invalid"),
        (command.observation_id, "site observation identity is invalid"),
        (command.review_id, "site review identity is invalid"),
        (command.latest_resolution_id, "site resolution identity is invalid"),
    ):
        _safe_id(value, message)
    _digest(command.expected_payload_hash, "expected site payload hash is invalid")
    if type(command.projection) is not SiteOpportunityProjection:
        raise SiteCommercialValidationError("site opportunity projection is invalid")
    if not isinstance(command.projection.company_inn, str) or not isinstance(
        command.projection.contact_email, str
    ):
        raise SiteCommercialValidationError("site opportunity projection is invalid")
    _required(command.actor, "site commercial actor is required", maximum=128)
    _safe_id(command.idempotency_key, "site commercial idempotency key is invalid")


def _validate_utm(value: object, message: str) -> dict[str, str]:
    result = _exact_keys(value, _UTM_KEYS, message)
    for key in _UTM_KEYS:
        _optional(result[key], message, maximum=300)
    return result  # type: ignore[return-value]


def _validate_consent(
    value: object,
    *,
    expected_purpose: ConsentPurpose,
    submitted_at: datetime,
    landing_url: str,
    compiled_policy: Any,
    required: bool,
) -> dict[str, Any] | None:
    if value is None and not required:
        return None
    consent = _exact_keys(value, _CONSENT_KEYS, "site consent contract is invalid")
    rule = compiled_policy.consent_rule(expected_purpose)
    if rule is None:
        raise SiteCommercialValidationError("site consent policy is invalid")
    _purpose, expected_source, expected_version, expected_sha = rule
    if (
        consent["purpose"] != expected_purpose.value
        or consent["granted"] is not True
        or not isinstance(consent["text"], str)
        or consent["text"] != consent["text"].strip()
        or len(consent["text"]) < 10
        or len(consent["text"]) > 4000
        or _CONTROL.search(consent["text"])
        or hashlib.sha256(consent["text"].encode("utf-8")).hexdigest()
        != consent["text_sha256"]
        or consent["source"] != expected_source
        or consent["text_version"] != expected_version
        or consent["text_sha256"] != expected_sha
        or consent["page_url"] != landing_url
    ):
        raise SiteCommercialValidationError("site consent contract is invalid")
    try:
        occurred, occurred_dt = _utc(consent["occurred_at_utc"], "consent occurred")
        if occurred != consent["occurred_at_utc"] or occurred_dt > submitted_at:
            raise SiteCommercialValidationError("site consent contract is invalid")
        valid_until = consent["valid_until_utc"]
        if not isinstance(valid_until, str):
            raise SiteCommercialValidationError("site consent contract is invalid")
        if valid_until:
            canonical_until, valid_until_dt = _utc(valid_until, "consent validity")
            if (
                canonical_until != valid_until
                or valid_until_dt <= occurred_dt
                or valid_until_dt < submitted_at
            ):
                raise SiteCommercialValidationError("site consent contract is invalid")
        _evidence_ref(consent["evidence_ref"], "consent evidence")
    except SiteValidationError:
        raise SiteCommercialValidationError("site consent contract is invalid") from None
    return consent


def _validate_site_record(
    envelope: dict[str, Any],
    *,
    record_row: Any,
    observation_row: Any,
    compiled_policy: Any,
) -> tuple[dict[str, Any], dict[str, str]]:
    if (
        set(envelope) != {"schema_version", "canonical_hash", "record"}
        or envelope.get("schema_version") != SITE_FORM_SCHEMA_VERSION
    ):
        raise SiteCommercialValidationError("site submission contract is invalid")
    record = _exact_keys(
        envelope.get("record"), _RECORD_KEYS, "site submission contract is invalid"
    )
    if (
        canonical_json(envelope) != str(record_row["payload_json"])
        or payload_hash(envelope) != str(record_row["payload_hash"])
        or envelope.get("canonical_hash") != payload_hash(record)
        or record.get("schema_version") != SITE_FORM_SCHEMA_VERSION
        or record.get("source_id") != compiled_policy.source_id
        or record.get("submission_id") != str(record_row["external_key"])
    ):
        raise SiteCommercialValidationError("site submission contract is invalid")

    trusted = _exact_keys(
        record.get("trusted_policy"),
        {"policy_id", "policy_version", "policy_hash", "evidence_ref"},
        "site policy binding is invalid",
    )
    if trusted != {
        "policy_id": compiled_policy.policy_id,
        "policy_version": compiled_policy.policy_version,
        "policy_hash": compiled_policy.canonical_hash,
        "evidence_ref": compiled_policy.evidence_ref,
    }:
        raise SiteCommercialValidationError("site policy binding is invalid")

    contact = _exact_keys(
        record.get("contact"), {"phone", "email"}, "site contact contract is invalid"
    )
    try:
        phone = _phone(contact["phone"])
        email = _email(contact["email"])
    except SiteValidationError:
        raise SiteCommercialValidationError("site contact contract is invalid") from None
    if phone != contact["phone"] or email != contact["email"] or not (phone or email):
        raise SiteCommercialValidationError("site contact contract is invalid")

    landing = _exact_keys(
        record.get("landing"),
        {"url", "landing_version", "offer_version", "form_id", "form_version", "referrer_url"},
        "site landing contract is invalid",
    )
    try:
        landing_url = _url(
            landing["url"],
            "landing url",
            required=True,
            allowed_origins=compiled_policy.allowed_origins,
            allowed_paths=compiled_policy.allowed_landing_paths,
            allowed_query_keys=compiled_policy.allowed_landing_query_keys,
        )
        referrer_url = _url(
            landing["referrer_url"],
            "referrer url",
            required=False,
            allowed_origins=compiled_policy.allowed_referrer_origins,
            allowed_paths=compiled_policy.allowed_referrer_paths,
            allowed_query_keys=compiled_policy.allowed_referrer_query_keys,
        )
    except SiteValidationError:
        raise SiteCommercialValidationError("site landing contract is invalid") from None
    if (
        landing_url != landing["url"]
        or referrer_url != landing["referrer_url"]
        or (landing["form_id"], landing["form_version"])
        not in compiled_policy.allowed_form_versions
        or landing["landing_version"] not in compiled_policy.allowed_landing_versions
        or landing["offer_version"] not in compiled_policy.allowed_offer_versions
    ):
        raise SiteCommercialValidationError("site landing contract is invalid")

    attribution = _exact_keys(
        record.get("attribution"),
        {"original_utm", "latest_utm", "yclid", "ad_click_id"},
        "site attribution contract is invalid",
    )
    original = _validate_utm(
        attribution["original_utm"], "site attribution contract is invalid"
    )
    latest = _validate_utm(
        attribution["latest_utm"], "site attribution contract is invalid"
    )
    try:
        attribution_state = SiteAttribution(str(record["attribution_state"]))
    except (TypeError, ValueError):
        raise SiteCommercialValidationError("site attribution contract is invalid") from None
    if str(observation_row["acquisition_mode"]) != attribution_state.value:
        raise SiteCommercialValidationError("site attribution contract is invalid")
    yclid = _optional(attribution["yclid"], "site attribution contract is invalid", maximum=256)
    ad_click_id = _optional(
        attribution["ad_click_id"], "site attribution contract is invalid", maximum=256
    )
    if (yclid and not _YCLID.fullmatch(yclid)) or (
        ad_click_id and not _CLICK_ID.fullmatch(ad_click_id)
    ):
        raise SiteCommercialValidationError("site attribution contract is invalid")
    if attribution_state is SiteAttribution.SITE_PAID:
        if not all(original.values()) or not all(latest.values()):
            raise SiteCommercialValidationError("site attribution contract is invalid")
    elif (
        yclid
        or ad_click_id
        or _PAID_MEDIUM_RE.search(original["utm_medium"])
        or _PAID_MEDIUM_RE.search(latest["utm_medium"])
    ):
        raise SiteCommercialValidationError("site attribution contract is invalid")
    if attribution_state is SiteAttribution.SITE_DIRECT and referrer_url:
        raise SiteCommercialValidationError("site attribution contract is invalid")
    if attribution_state is SiteAttribution.SITE_REFERRAL and not referrer_url:
        raise SiteCommercialValidationError("site attribution contract is invalid")

    try:
        submitted, submitted_dt = _utc(record["submitted_at_utc"], "submitted at")
    except SiteValidationError:
        raise SiteCommercialValidationError("site submission timestamp is invalid") from None
    if submitted != record["submitted_at_utc"]:
        raise SiteCommercialValidationError("site submission timestamp is invalid")
    consents = _exact_keys(
        record.get("consents"),
        {"personal_data_processing", "marketing_communication"},
        "site consent contract is invalid",
    )
    personal = _validate_consent(
        consents["personal_data_processing"],
        expected_purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
        submitted_at=submitted_dt,
        landing_url=landing_url,
        compiled_policy=compiled_policy,
        required=True,
    )
    _validate_consent(
        consents["marketing_communication"],
        expected_purpose=ConsentPurpose.MARKETING_COMMUNICATION,
        submitted_at=submitted_dt,
        landing_url=landing_url,
        compiled_policy=compiled_policy,
        required=False,
    )

    required_string_limits = {
        "company_name": 200,
        "applicant_role": 160,
        "city_or_region": 200,
        "object_or_recurring_need": 2000,
        "product_or_system": 500,
        "estimated_volume": 300,
        "purchase_stage": 300,
        "required_delivery_or_quote_date": 10,
        "specification_status": 1000,
    }
    for key, maximum in required_string_limits.items():
        if not _optional(
            record[key], "site submission fields are invalid", maximum=maximum
        ):
            raise SiteCommercialValidationError("site submission fields are invalid")
    _optional(
        record["attachment_summary"],
        "site submission fields are invalid",
        maximum=1000,
    )
    try:
        if date.fromisoformat(str(record["required_delivery_or_quote_date"])).isoformat() != record[
            "required_delivery_or_quote_date"
        ]:
            raise ValueError
    except (TypeError, ValueError):
        raise SiteCommercialValidationError("site submission fields are invalid") from None
    if type(record["supplier_selection_open"]) is not bool:
        raise SiteCommercialValidationError("site submission fields are invalid")
    _safe_id(record["submission_id"], "site submission identity is invalid")
    _safe_id(record["correlation_id"], "site correlation identity is invalid")

    crm_context = {
        "source_id": compiled_policy.source_id,
        "submission_id": str(record["submission_id"]),
        "correlation_id": str(record["correlation_id"]),
        "attribution_state": attribution_state.value,
        "site_policy_id": compiled_policy.policy_id,
        "site_policy_version": compiled_policy.policy_version,
        "site_policy_hash": compiled_policy.canonical_hash,
        "landing_url": str(landing["url"]),
        "landing_version": str(landing["landing_version"]),
        "offer_version": str(landing["offer_version"]),
        "form_id": str(landing["form_id"]),
        "form_version": str(landing["form_version"]),
        **{f"original_{key}": value for key, value in original.items()},
        **{f"latest_{key}": value for key, value in latest.items()},
        "yclid": yclid,
        "ad_click_id": ad_click_id,
        "personal_consent_version": str(personal["text_version"]),
        "personal_consent_hash": str(personal["text_sha256"]),
    }
    return record, crm_context


class SiteCommercialBridge:
    """Authenticate and stage one latest-approved site submission."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        policy: SiteCommercialPolicy,
        approval_authority: TrustedSiteApprovalAuthority | None = None,
        reviewed_bridge: ReviewedOpportunityBridge | None = None,
        before_transaction: Callable[[], None] | None = None,
    ) -> None:
        if type(policy) is not SiteCommercialPolicy:
            raise SiteCommercialValidationError("site commercial policy is invalid")
        for value, message in (
            (policy.policy_id, "site commercial policy identity is invalid"),
            (policy.policy_version, "site commercial policy version is invalid"),
            (policy.source_id, "site commercial source identity is invalid"),
            (policy.identity_policy_version, "site identity policy version is invalid"),
        ):
            _safe_id(value, message)
        try:
            compiled = _compile_policy(policy.trusted_site_policy, source_id=policy.source_id)
            manifest_hash = validate_graph_bridge_binding(policy.bitrix_graph_binding)
        except SiteValidationError:
            raise SiteCommercialValidationError("trusted site policy is invalid") from None
        except BitrixGraphMappingError:
            raise SiteCommercialValidationError("site graph binding is invalid") from None
        if policy.bitrix_graph_binding.lf_source_id != policy.source_id:
            raise SiteCommercialValidationError("site graph source binding is invalid")
        self.store = store
        self.policy = policy
        self._compiled_site_policy = compiled
        self._mapping_manifest_hash = manifest_hash
        self._policy_hash = payload_hash(_commercial_policy_payload(policy, compiled))
        self.approval_authority = approval_authority
        self.reviewed_bridge = reviewed_bridge or ReviewedOpportunityBridge(store)
        self.before_transaction = before_transaction

    @staticmethod
    def _review(command: ApprovedSiteCommand, reason: str) -> SiteCommercialBridgeResult:
        return SiteCommercialBridgeResult(
            state="REVIEW",
            reason=reason,
            source_record_id=command.source_record_id,
            observation_id=command.observation_id,
            review_id=command.review_id,
            resolution_id=command.latest_resolution_id,
        )

    def _verify_approval(
        self, request: TrustedSiteApprovalRequest
    ) -> TrustedSiteApprovalReceipt:
        authority = self.approval_authority
        try:
            capability = getattr(authority, "capability_version", None)
            callback = getattr(authority, "verify_approval", None)
        except Exception:
            raise SiteCommercialValidationError(
                "trusted site approval authority is unavailable"
            ) from None
        if capability != SITE_APPROVAL_CAPABILITY_VERSION or not callable(callback):
            raise SiteCommercialValidationError(
                "trusted site approval authority is unavailable"
            )
        try:
            receipt = callback(request)
        except Exception:
            raise SiteCommercialValidationError(
                "trusted site approval verification failed"
            ) from None
        return self._validate_receipt(receipt, request)

    @staticmethod
    def _validate_receipt(
        receipt: object, request: TrustedSiteApprovalRequest
    ) -> TrustedSiteApprovalReceipt:
        if (
            type(receipt) is not TrustedSiteApprovalReceipt
            or receipt.capability_version != SITE_APPROVAL_CAPABILITY_VERSION
            or receipt.receipt_version != SITE_APPROVAL_RECEIPT_VERSION
            or receipt.request != request
            or receipt.request_hash != request.request_hash
        ):
            raise SiteCommercialValidationError("trusted site approval receipt is invalid")
        _safe_id(receipt.authority_id, "trusted site approval receipt is invalid")
        _safe_id(receipt.receipt_id, "trusted site approval receipt is invalid")
        _digest(receipt.receipt_hash, "trusted site approval receipt is invalid")
        return receipt

    def _load_approved(self, con: Any, command: ApprovedSiteCommand) -> _ApprovedSite:
        record_row = con.execute(
            "SELECT * FROM source_lab_records WHERE source_record_id=?",
            (command.source_record_id,),
        ).fetchone()
        if not record_row:
            raise SiteCommercialValidationError("site source record does not exist")
        if (
            str(record_row["source_id"]) != self.policy.source_id
            or str(record_row["payload_hash"]) != command.expected_payload_hash
        ):
            raise SiteCommercialValidationError("site source policy binding changed")
        observation = con.execute(
            """SELECT * FROM source_lab_record_observations
               WHERE observation_id=? AND source_record_id=?""",
            (command.observation_id, command.source_record_id),
        ).fetchone()
        if not observation or str(observation["source_id"]) != self.policy.source_id:
            raise SiteCommercialValidationError("site observation binding is invalid")
        reviews = con.execute(
            """SELECT * FROM source_lab_reviews
               WHERE source_record_id=? AND review_kind='QUALIFICATION'
               ORDER BY created_at_utc DESC,review_id DESC""",
            (command.source_record_id,),
        ).fetchall()
        latest_time = str(reviews[0]["created_at_utc"]) if reviews else ""
        if (
            not reviews
            or sum(str(row["created_at_utc"]) == latest_time for row in reviews) != 1
            or str(reviews[0]["review_id"]) != command.review_id
        ):
            raise SiteCommercialValidationError(
                "latest site qualification review changed"
            )
        resolution = con.execute(
            """SELECT * FROM source_lab_review_resolutions
               WHERE review_id=? ORDER BY sequence_number DESC LIMIT 1""",
            (command.review_id,),
        ).fetchone()
        if (
            not resolution
            or str(resolution["resolution_id"]) != command.latest_resolution_id
            or str(resolution["decision"]).upper() != "APPROVE"
        ):
            raise SiteCommercialValidationError(
                "latest site qualification resolution is not APPROVE"
            )
        resolution_event = con.execute(
            "SELECT * FROM events WHERE event_id=?", (str(resolution["event_id"]),)
        ).fetchone()
        if not resolution_event:
            raise SiteCommercialConflict("site approval event is missing")
        approval_timestamp = str(resolution_event["occurred_at_utc"] or "")
        recorded_timestamp = str(resolution_event["recorded_at_utc"] or "")
        queue_timestamp_bound = False
        if recorded_timestamp != approval_timestamp:
            queue_rows = con.execute(
                """SELECT * FROM events
                   WHERE producer='source_lab_review_queue'
                     AND event_type='source_lab_review_resolution_recorded'
                     AND aggregate_type='source_lab_review'
                     AND aggregate_id=? ORDER BY rowid,event_id""",
                (command.review_id,),
            ).fetchall()
            matches = []
            for queue_row in queue_rows:
                queue_payload = _strict_json_object(
                    queue_row["payload_json"],
                    "site approval queue binding is invalid",
                )
                if (
                    str(queue_payload.get("resolution_id", ""))
                    == str(resolution["resolution_id"])
                    and str(queue_payload.get("resolution_event_id", ""))
                    == str(resolution["event_id"])
                    and str(queue_payload.get("review_id", "")) == command.review_id
                    and str(queue_payload.get("decision", "")).upper() == "APPROVE"
                    and str(queue_payload.get("recorded_at_utc", ""))
                    == approval_timestamp
                    and str(queue_row["occurred_at_utc"] or "")
                    == approval_timestamp
                ):
                    matches.append(queue_row)
            queue_timestamp_bound = len(matches) == 1
        if not _UTC_SECONDS.fullmatch(approval_timestamp) or (
            recorded_timestamp != approval_timestamp and not queue_timestamp_bound
        ):
            raise SiteCommercialConflict("site approval timestamp is invalid")
        try:
            datetime.strptime(approval_timestamp, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise SiteCommercialConflict("site approval timestamp is invalid") from None

        envelope = _strict_json_object(
            record_row["payload_json"], "site submission payload is invalid"
        )
        record, crm_context = _validate_site_record(
            envelope,
            record_row=record_row,
            observation_row=observation,
            compiled_policy=self._compiled_site_policy,
        )
        raw_inn = command.projection.company_inn.strip()
        normalized_inn = _exact_company_inn(raw_inn)
        raw_email = command.projection.contact_email.strip().lower()
        normalized_email = normalize_email(raw_email)
        record_email = str(record["contact"]["email"])
        if (
            not normalized_inn
            or normalized_inn != _exact_company_inn(command.projection.company_inn)
        ):
            raise SiteCommercialValidationError("EXACT_COMPANY_IDENTITY_REQUIRED")
        if not record_email or not normalized_email or "@" not in normalized_email:
            raise SiteCommercialValidationError("CONTACT_EMAIL_REQUIRED")
        if normalized_email != record_email:
            raise SiteCommercialConflict("site contact identity changed")
        try:
            identity_evidence = _evidence_ref(
                command.projection.identity_evidence_ref, "identity evidence"
            )
        except SiteValidationError:
            raise SiteCommercialValidationError("site identity evidence is invalid") from None

        project_title = (
            str(record["object_or_recurring_need"])
            or str(record["product_or_system"])
            or f"Site submission {record['submission_id']}"
        )
        crm_context["identity_policy_version"] = self.policy.identity_policy_version
        projection = ReviewedOpportunityProjection(
            producer=self.policy.source_id,
            external_key=str(record["submission_id"]),
            source_record_id=command.source_record_id,
            observation_id=command.observation_id,
            review_id=command.review_id,
            resolution_id=str(resolution["resolution_id"]),
            resolution_event_id=str(resolution["event_id"]),
            source_payload_hash=str(record_row["payload_hash"]),
            evidence_ref=str(resolution["evidence_ref"]),
            observed_at_utc=str(observation["observed_at_utc"]),
            approval_event_occurred_at_utc=approval_timestamp,
            company_name=str(record["company_name"]),
            company_inn=normalized_inn,
            contact_name="",
            contact_email=normalized_email,
            contact_phone=str(record["contact"]["phone"]),
            contact_role=str(record["applicant_role"]),
            project_title=project_title,
            project_region=str(record["city_or_region"]),
            product_key=str(record["product_or_system"]),
            crm_context=tuple(sorted(crm_context.items())),
        )
        request = TrustedSiteApprovalRequest(
            source_record_id=command.source_record_id,
            observation_id=command.observation_id,
            review_id=command.review_id,
            resolution_id=str(resolution["resolution_id"]),
            resolution_event_id=str(resolution["event_id"]),
            decision="APPROVE",
            resolved_by=str(resolution["resolved_by"]),
            evidence_ref=str(resolution["evidence_ref"]),
            resolution_command_hash=_digest(
                resolution["command_hash"], "site approval proof is invalid"
            ),
            resolution_event_hash=_digest(
                resolution_event["payload_hash"], "site approval proof is invalid"
            ),
            source_id=self.policy.source_id,
            source_payload_hash=str(record_row["payload_hash"]),
            data_contract_version=SITE_COMMERCIAL_DATA_CONTRACT_VERSION,
            site_policy_id=self._compiled_site_policy.policy_id,
            site_policy_version=self._compiled_site_policy.policy_version,
            site_policy_hash=self._compiled_site_policy.canonical_hash,
            commercial_policy_id=self.policy.policy_id,
            commercial_policy_version=self.policy.policy_version,
            commercial_policy_hash=self._policy_hash,
            identity_policy_version=self.policy.identity_policy_version,
            identity_evidence_ref=identity_evidence,
            mapping_manifest_hash=self._mapping_manifest_hash,
            lf_source_id=self.policy.bitrix_graph_binding.lf_source_id,
            activity_deadline_utc=self.policy.bitrix_graph_binding.activity_deadline_utc,
            projection=projection,
        )
        _digest(request.request_hash, "site approval request is invalid")
        return _ApprovedSite(request=request, projection=projection)

    def execute(self, command: ApprovedSiteCommand) -> SiteCommercialBridgeResult:
        _validate_command(command)
        self.store.init()

        # Missing production-grade identity is a qualification state, not an
        # invitation to create a probable graph.
        normalized_inn = _exact_company_inn(command.projection.company_inn)
        if not normalized_inn:
            return self._review(command, "EXACT_COMPANY_IDENTITY_REQUIRED")
        if not normalize_email(command.projection.contact_email):
            return self._review(command, "CONTACT_EMAIL_REQUIRED")

        con = self.store.connect()
        try:
            con.execute("BEGIN")
            if self.store._probe_schema(con) < CURRENT_SCHEMA_VERSION:
                raise SiteCommercialValidationError(
                    "site commercial bridge requires the current schema"
                )
            validate_source_lab_integrity(con)
            approved = self._load_approved(con, command)
        except SourceLabIntegrityError:
            raise SiteCommercialConflict("Source Lab integrity validation failed") from None
        finally:
            if con.in_transaction:
                con.rollback()
            con.close()

        receipt = self._verify_approval(approved.request)
        if self.before_transaction:
            try:
                self.before_transaction()
            except Exception:
                raise SiteCommercialValidationError(
                    "site commercial pre-transaction hook failed"
                ) from None

        try:
            with self.store.transaction(min_schema_version=CURRENT_SCHEMA_VERSION) as tx:
                validate_source_lab_integrity(tx)
                current = self._load_approved(tx, command)
                if current.request != approved.request or current.projection != approved.projection:
                    raise SiteCommercialConflict("site approval lineage changed")
                self._validate_receipt(receipt, current.request)
                staged = self.reviewed_bridge.stage(
                    projection=current.projection,
                    proof=ReviewedOpportunityProof(
                        approval_request_hash=current.request.request_hash,
                        approval_receipt_hash=receipt.receipt_hash,
                        commercial_policy_hash=self._policy_hash,
                        mapping_manifest_hash=current.request.mapping_manifest_hash,
                        lf_source_id=current.request.lf_source_id,
                        activity_deadline_utc=current.request.activity_deadline_utc,
                    ),
                    binding=self.policy.bitrix_graph_binding,
                    actor=command.actor,
                    _transaction=tx,
                )
        except SiteCommercialBridgeError:
            raise
        except SourceLabIntegrityError:
            raise SiteCommercialConflict("Source Lab integrity validation failed") from None
        except ReviewedOpportunityBridgeError:
            raise SiteCommercialConflict("site commercial transaction was rejected") from None
        return SiteCommercialBridgeResult(
            state="STAGED",
            reason="APPROVED_SITE_SUBMISSION",
            source_record_id=command.source_record_id,
            observation_id=command.observation_id,
            review_id=command.review_id,
            resolution_id=command.latest_resolution_id,
            staged=staged,
        )


__all__ = [
    "ApprovedSiteCommand",
    "SITE_APPROVAL_CAPABILITY_VERSION",
    "SITE_APPROVAL_RECEIPT_VERSION",
    "SITE_COMMERCIAL_DATA_CONTRACT_VERSION",
    "SiteCommercialBridge",
    "SiteCommercialBridgeError",
    "SiteCommercialBridgeResult",
    "SiteCommercialConflict",
    "SiteCommercialPolicy",
    "SiteCommercialValidationError",
    "SiteOpportunityProjection",
    "TrustedSiteApprovalAuthority",
    "TrustedSiteApprovalReceipt",
    "TrustedSiteApprovalRequest",
]
