"""Offline bridge from an approved Source Lab import to the commercial graph.

The bridge has deliberately narrow authority.  It accepts only a complete,
immutable ``source-import-record-v2`` batch whose latest QUALIFICATION review
fact is APPROVE.  Company/Contact/Project/Opportunity creation and the Source
Lab evidence link share one SQLite transaction.  The Bitrix graph is only
*staged* afterwards; this module has no transport, URL, credential, or writer
enablement path.

Cross-source project reuse is fail-closed.  Only identity namespaces named by
the commercial policy may participate, and generic company/contact identities
(INN, domain, email, phone, OGRN) can never be promoted to project identities.
An existing project may be reused only for an exact INN match.  A domain-only
match is not sufficient with the current commercial schema.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol

from .bitrix_graph_mapping import (
    BitrixGraphBridgeBinding,
    BitrixGraphMappingError,
    validate_graph_bridge_binding,
)
from .commercial_spine import (
    CommercialSpineError,
    NormalizedOpportunityIntake,
    NormalizedOpportunityResult,
)
from .crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphOutbox,
    CrmGraphStageResult,
    GraphInvariantError,
)
from .ids import (
    canonical_json,
    normalize_domain,
    normalize_email,
    normalize_inn,
    normalize_phone_ru,
    payload_hash,
)
from .source_lab import (
    SourceLabError,
    SourceLabEvidenceLinkResult,
    SourceLabSink,
    canonical_identity_fingerprints,
)
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity
from .store import FactoryStore, IdempotencyConflict


class SourceCommercialBridgeError(RuntimeError):
    """Base error for a local, fail-closed bridge decision."""


class SourceCommercialValidationError(SourceCommercialBridgeError):
    """The command, policy, imported record, or approval is not admissible."""


class SourceCommercialConflict(SourceCommercialBridgeError):
    """Stored facts cannot be reconciled to exactly one commercial graph."""


class SourceCommercialStageError(SourceCommercialBridgeError):
    """The local CRM graph could not be staged after the graph commit."""


TRUSTED_APPROVAL_CAPABILITY_VERSION = "source-commercial-approval-authority-v1"
_TRUSTED_APPROVAL_REQUEST_VERSION = "source-commercial-approval-request-v1"
TRUSTED_APPROVAL_RECEIPT_VERSION = "source-commercial-approval-receipt-v1"
_BRIDGE_LINK_ANCHOR_VERSION = "source-commercial-approved-link-anchor-v1"
_BRIDGE_LINK_ANCHOR_EVENT = "source_commercial_approved_link_anchored"
_BRIDGE_PRODUCER = "source_commercial_bridge"
_BRIDGE_ACTOR = "source_commercial_bridge"


@dataclass(frozen=True, slots=True, repr=False)
class TrustedApprovalRequest:
    """Exact non-secret facts a trusted authority must authenticate."""

    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    resolution_event_id: str
    decision: str
    resolved_by: str
    evidence_ref: str
    policy_id: str
    policy_version: str
    policy_hash: str
    source_id: str
    data_contract_version: str
    mapping_policy_hash: str
    mapping_manifest_hash: str
    lf_source_id: str
    activity_deadline_utc: str

    def __repr__(self) -> str:
        return "TrustedApprovalRequest(<redacted>)"

    @property
    def request_hash(self) -> str:
        return payload_hash(_approval_request_payload(self))


@dataclass(frozen=True, slots=True, repr=False)
class TrustedApprovalReceipt:
    """Opaque authority receipt that binds one exact approval request."""

    capability_version: str
    receipt_version: str
    authority_id: str
    receipt_id: str
    request: TrustedApprovalRequest
    request_hash: str

    def __repr__(self) -> str:
        return "TrustedApprovalReceipt(<redacted>)"

    @property
    def receipt_hash(self) -> str:
        return payload_hash(_approval_receipt_payload(self))


class TrustedApprovalAuthority(Protocol):
    """Injected trust boundary; Source Lab actor strings are not credentials."""

    capability_version: str

    def verify_approval(
        self, request: TrustedApprovalRequest
    ) -> TrustedApprovalReceipt:
        """Authenticate exactly ``request`` or fail without returning a receipt."""


def _approval_request_payload(request: TrustedApprovalRequest) -> dict[str, str]:
    return {
        "request_version": _TRUSTED_APPROVAL_REQUEST_VERSION,
        "source_record_id": request.source_record_id,
        "observation_id": request.observation_id,
        "review_id": request.review_id,
        "resolution_id": request.resolution_id,
        "resolution_event_id": request.resolution_event_id,
        "decision": request.decision,
        "resolved_by": request.resolved_by,
        "evidence_ref": request.evidence_ref,
        "policy_id": request.policy_id,
        "policy_version": request.policy_version,
        "policy_hash": request.policy_hash,
        "source_id": request.source_id,
        "data_contract_version": request.data_contract_version,
        "mapping_policy_hash": request.mapping_policy_hash,
        "mapping_manifest_hash": request.mapping_manifest_hash,
        "lf_source_id": request.lf_source_id,
        "activity_deadline_utc": request.activity_deadline_utc,
    }


def _approval_receipt_payload(receipt: TrustedApprovalReceipt) -> dict[str, Any]:
    return {
        "receipt_version": receipt.receipt_version,
        "capability_version": receipt.capability_version,
        "authority_id": receipt.authority_id,
        "receipt_id": receipt.receipt_id,
        "request_hash": receipt.request_hash,
        "request": _approval_request_payload(receipt.request),
    }


@dataclass(frozen=True, slots=True)
class CommercialFieldBindings:
    """Canonical imported-record fields used by the v1 commercial contract."""

    company_name: str = "company_name"
    company_inn: str = "inn"
    company_domain: str = "domain"
    contact_name: str = "contact_name"
    contact_email: str = "email"
    contact_phone: str = "phone"
    contact_role: str = "role"
    project_title: str = "project_title"
    project_region: str = "region"
    product_key: str = "product_key"


@dataclass(frozen=True, slots=True, repr=False)
class SourceCommercialPolicy:
    """Exact source-import/mapping contract allowed into the commercial graph."""

    policy_id: str
    policy_version: str
    source_id: str
    data_contract_version: str
    mapping_policy_hash: str
    bitrix_graph_binding: BitrixGraphBridgeBinding
    field_bindings: CommercialFieldBindings = CommercialFieldBindings()
    strong_project_namespaces: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "SourceCommercialPolicy(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ApprovedSourceCommand:
    """A stale-safe pointer to one reviewed immutable Source Lab observation."""

    source_record_id: str
    observation_id: str
    review_id: str
    latest_resolution_id: str
    expected_payload_hash: str
    actor: str
    idempotency_key: str

    def __repr__(self) -> str:
        return "ApprovedSourceCommand(<redacted>)"


@dataclass(frozen=True, slots=True)
class SourceCommercialBridgeResult:
    graph_created: bool
    opportunity_reused: bool
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    lf_company_id: str
    lf_contact_id: str
    lf_project_id: str
    lf_opportunity_id: str
    evidence_link_id: str
    evidence_link_created: bool
    crm_stage: CrmGraphStageResult


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_INN_TEXT = re.compile(r"^[0-9 \t-]+$")
_PHONE_TEXT = re.compile(r"^[+0-9 ()\t.\-]+$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_NON_PROJECT_NAMESPACES = frozenset(
    {
        "inn",
        "ogrn",
        "domain",
        "email",
        "contact-email",
        "phone",
        "contact-phone",
    }
)


@dataclass(frozen=True, slots=True)
class _ApprovedImport:
    record_row: Any
    observation_row: Any
    resolution_row: Any
    envelope: dict[str, Any]
    mapped_record: dict[str, Any]
    mapping_policy: dict[str, Any]
    values: dict[str, str]
    strong_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ApprovalProof:
    request: TrustedApprovalRequest
    receipt: TrustedApprovalReceipt
    source_payload_hash: str
    resolution_command_hash: str
    resolution_event_hash: str
    strong_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedAnchor:
    evidence_link_id: str
    opportunity_id: str
    company_id: str
    contact_id: str
    project_id: str
    graph_created: bool
    creator_resolution_event_id: str
    proof: _ApprovalProof


def _required(value: object, message: str, *, maximum: int = 512) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum or "\x00" in result:
        raise SourceCommercialValidationError(message)
    return result


def _safe_id(value: object, message: str) -> str:
    result = _required(value, message)
    if not _SAFE_ID.fullmatch(result):
        raise SourceCommercialValidationError(message)
    return result


def _json_object(value: object, message: str) -> dict[str, Any]:
    def reject_constant(_token: str) -> None:
        raise ValueError("non-finite JSON")

    try:
        parsed = json.loads(str(value or ""), parse_constant=reject_constant)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise SourceCommercialValidationError(message) from None
    if not isinstance(parsed, dict):
        raise SourceCommercialValidationError(message)
    return parsed


def _validate_policy(policy: SourceCommercialPolicy) -> tuple[str, ...]:
    if not isinstance(policy, SourceCommercialPolicy):
        raise SourceCommercialValidationError("commercial source policy is invalid")
    _safe_id(policy.policy_id, "commercial source policy identity is invalid")
    _safe_id(policy.policy_version, "commercial source policy version is invalid")
    _safe_id(policy.source_id, "commercial source identity is invalid")
    _safe_id(
        policy.data_contract_version,
        "commercial source data contract is invalid",
    )
    mapping_hash = str(policy.mapping_policy_hash or "").strip().lower()
    if mapping_hash != policy.mapping_policy_hash or not _HEX64.fullmatch(mapping_hash):
        raise SourceCommercialValidationError(
            "commercial source mapping policy hash is invalid"
        )
    try:
        validate_graph_bridge_binding(policy.bitrix_graph_binding)
    except BitrixGraphMappingError:
        raise SourceCommercialValidationError("commercial graph binding is invalid") from None
    if policy.bitrix_graph_binding.lf_source_id != policy.source_id:
        raise SourceCommercialValidationError("commercial graph source binding is invalid")
    bindings = policy.field_bindings
    if not isinstance(bindings, CommercialFieldBindings):
        raise SourceCommercialValidationError("commercial field bindings are invalid")
    fields = tuple(getattr(bindings, name) for name in bindings.__dataclass_fields__)
    if (
        any(not isinstance(item, str) or not _FIELD.fullmatch(item) for item in fields)
        or len(set(fields)) != len(fields)
    ):
        raise SourceCommercialValidationError("commercial field bindings are invalid")
    if not isinstance(policy.strong_project_namespaces, tuple):
        raise SourceCommercialValidationError("strong project namespaces are invalid")
    namespaces = tuple(str(item or "").strip().lower() for item in policy.strong_project_namespaces)
    if (
        len(set(namespaces)) != len(namespaces)
        or any(not _NAMESPACE.fullmatch(item) for item in namespaces)
        or any(item in _NON_PROJECT_NAMESPACES for item in namespaces)
    ):
        raise SourceCommercialValidationError("strong project namespaces are invalid")
    return namespaces


def _commercial_policy_payload(policy: SourceCommercialPolicy) -> dict[str, Any]:
    bindings = policy.field_bindings
    return {
        "commercial_policy_version": 1,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "source_id": policy.source_id,
        "data_contract_version": policy.data_contract_version,
        "mapping_policy_hash": policy.mapping_policy_hash,
        "mapping_manifest_hash": validate_graph_bridge_binding(
            policy.bitrix_graph_binding
        ),
        "lf_source_id": policy.bitrix_graph_binding.lf_source_id,
        "activity_deadline_utc": policy.bitrix_graph_binding.activity_deadline_utc,
        "field_bindings": {
            name: getattr(bindings, name) for name in bindings.__dataclass_fields__
        },
        "strong_project_namespaces": list(policy.strong_project_namespaces),
    }


def _commercial_policy_hash(policy: SourceCommercialPolicy) -> str:
    return payload_hash(_commercial_policy_payload(policy))


def _validate_approval_request(request: TrustedApprovalRequest) -> None:
    if type(request) is not TrustedApprovalRequest:
        raise SourceCommercialValidationError("trusted approval request is invalid")
    for value in (
        request.source_record_id,
        request.observation_id,
        request.review_id,
        request.resolution_id,
        request.resolution_event_id,
        request.policy_id,
        request.policy_version,
        request.source_id,
        request.data_contract_version,
    ):
        _safe_id(value, "trusted approval request is invalid")
    if request.decision != "APPROVE":
        raise SourceCommercialValidationError("trusted approval request is invalid")
    _required(request.resolved_by, "trusted approval request is invalid", maximum=128)
    _required(request.evidence_ref, "trusted approval request is invalid", maximum=2048)
    for digest in (
        request.policy_hash,
        request.mapping_policy_hash,
        request.mapping_manifest_hash,
        request.request_hash,
    ):
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise SourceCommercialValidationError("trusted approval request is invalid")
    _safe_id(request.lf_source_id, "trusted approval request is invalid")
    if request.lf_source_id != request.source_id:
        raise SourceCommercialValidationError("trusted approval request is invalid")
    if not _UTC_SECONDS.fullmatch(request.activity_deadline_utc):
        raise SourceCommercialValidationError("trusted approval request is invalid")
    try:
        datetime.strptime(request.activity_deadline_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SourceCommercialValidationError("trusted approval request is invalid") from None


def _validate_approval_receipt(
    receipt: object, request: TrustedApprovalRequest
) -> TrustedApprovalReceipt:
    if type(receipt) is not TrustedApprovalReceipt:
        raise SourceCommercialValidationError("trusted approval receipt is invalid")
    if (
        receipt.capability_version != TRUSTED_APPROVAL_CAPABILITY_VERSION
        or receipt.receipt_version != TRUSTED_APPROVAL_RECEIPT_VERSION
        or receipt.request != request
        or receipt.request_hash != request.request_hash
    ):
        raise SourceCommercialValidationError("trusted approval receipt is invalid")
    try:
        _safe_id(receipt.authority_id, "trusted approval receipt is invalid")
        _safe_id(receipt.receipt_id, "trusted approval receipt is invalid")
    except SourceCommercialValidationError:
        raise SourceCommercialValidationError("trusted approval receipt is invalid") from None
    if not _HEX64.fullmatch(receipt.receipt_hash):
        raise SourceCommercialValidationError("trusted approval receipt is invalid")
    return receipt


def _validate_command(command: ApprovedSourceCommand) -> None:
    if not isinstance(command, ApprovedSourceCommand):
        raise SourceCommercialValidationError("approved source command is invalid")
    for value, message in (
        (command.source_record_id, "source record identity is invalid"),
        (command.observation_id, "source observation identity is invalid"),
        (command.review_id, "source review identity is invalid"),
        (command.latest_resolution_id, "source resolution identity is invalid"),
    ):
        _safe_id(value, message)
    expected_hash = str(command.expected_payload_hash or "").strip().lower()
    if expected_hash != command.expected_payload_hash or not _HEX64.fullmatch(expected_hash):
        raise SourceCommercialValidationError("expected source payload hash is invalid")
    _required(command.actor, "commercial bridge actor is required", maximum=128)
    idem = _safe_id(
        command.idempotency_key, "commercial bridge idempotency key is invalid"
    )
    if len(idem) > 400:
        raise SourceCommercialValidationError(
            "commercial bridge idempotency key is invalid"
        )


def _mapped_text(
    record: Mapping[str, Any], field: str, *, required: bool, message: str
) -> str:
    if field not in record:
        if required:
            raise SourceCommercialValidationError(message)
        return ""
    value = record[field]
    if not isinstance(value, str):
        raise SourceCommercialValidationError(message)
    result = value.strip()
    if required and not result:
        raise SourceCommercialValidationError(message)
    if len(result) > 4096 or "\x00" in result:
        raise SourceCommercialValidationError(message)
    return result


def _normalised_values(
    record: Mapping[str, Any], bindings: CommercialFieldBindings
) -> dict[str, str]:
    values = {
        "company_name": _mapped_text(
            record, bindings.company_name, required=False, message="company name is invalid"
        ),
        "company_inn_raw": _mapped_text(
            record, bindings.company_inn, required=False, message="company INN is invalid"
        ),
        "company_domain_raw": _mapped_text(
            record,
            bindings.company_domain,
            required=False,
            message="company domain is invalid",
        ),
        "contact_name": _mapped_text(
            record, bindings.contact_name, required=False, message="contact name is invalid"
        ),
        "contact_email_raw": _mapped_text(
            record,
            bindings.contact_email,
            required=True,
            message="contact email is required",
        ),
        "contact_phone_raw": _mapped_text(
            record,
            bindings.contact_phone,
            required=False,
            message="contact phone is invalid",
        ),
        "contact_role": _mapped_text(
            record, bindings.contact_role, required=False, message="contact role is invalid"
        ),
        "project_title": _mapped_text(
            record,
            bindings.project_title,
            required=True,
            message="project title is required",
        ),
        "project_region": _mapped_text(
            record,
            bindings.project_region,
            required=False,
            message="project region is invalid",
        ),
        "product_key": _mapped_text(
            record,
            bindings.product_key,
            required=True,
            message="product key is required",
        ),
    }
    raw_inn = values.pop("company_inn_raw")
    raw_domain = values.pop("company_domain_raw")
    inn = normalize_inn(raw_inn)
    domain = normalize_domain(raw_domain)
    if raw_inn and (
        not _INN_TEXT.fullmatch(raw_inn) or len(inn) not in {10, 12}
    ):
        raise SourceCommercialValidationError("company INN is invalid")
    if raw_domain and not domain:
        raise SourceCommercialValidationError("company domain is invalid")
    if not inn and not domain:
        raise SourceCommercialValidationError("company identity is required")
    email = normalize_email(values.pop("contact_email_raw"))
    if not email or "@" not in email:
        raise SourceCommercialValidationError("contact email is required")
    raw_phone = values.pop("contact_phone_raw")
    phone = normalize_phone_ru(raw_phone)
    if raw_phone and (not _PHONE_TEXT.fullmatch(raw_phone) or not phone):
        raise SourceCommercialValidationError("contact phone is invalid")
    values.update(
        {
            "company_inn": inn,
            "company_domain": domain,
            "contact_email": email,
            "contact_phone": phone,
        }
    )
    return values


class SourceCommercialBridge:
    """Create/reuse one local graph from one approved Source Lab import fact."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        policy: SourceCommercialPolicy,
        approval_authority: TrustedApprovalAuthority | None = None,
        crm_outbox: CrmGraphOutbox | None = None,
        before_graph_commit: Callable[
            [NormalizedOpportunityResult, SourceLabEvidenceLinkResult], None
        ]
        | None = None,
        before_crm_stage: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self._strong_namespaces = _validate_policy(policy)
        self._mapping_manifest_hash = validate_graph_bridge_binding(
            policy.bitrix_graph_binding
        )
        self._policy_hash = _commercial_policy_hash(policy)
        self.approval_authority = approval_authority
        self.intake = NormalizedOpportunityIntake(store)
        self.source_lab = SourceLabSink(store)
        self.crm_outbox = crm_outbox or CrmGraphOutbox(store)
        self.before_graph_commit = before_graph_commit
        self.before_crm_stage = before_crm_stage

    @staticmethod
    def _writers_are_off(con: Any) -> bool:
        row = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        return bool(row) and str(row[0]) == "0"

    def _verify_approval(
        self, request: TrustedApprovalRequest
    ) -> TrustedApprovalReceipt:
        """Cross the injected authority boundary without leaking callback details."""

        _validate_approval_request(request)
        authority = self.approval_authority
        try:
            capability = getattr(authority, "capability_version", None)
            callback = getattr(authority, "verify_approval", None)
        except Exception:
            raise SourceCommercialValidationError(
                "trusted approval authority is unavailable"
            ) from None
        if (
            capability != TRUSTED_APPROVAL_CAPABILITY_VERSION
            or not callable(callback)
        ):
            raise SourceCommercialValidationError(
                "trusted approval authority is unavailable"
            )
        try:
            receipt = callback(request)
        except Exception:
            raise SourceCommercialValidationError(
                "trusted approval verification failed"
            ) from None
        return _validate_approval_receipt(receipt, request)

    def _current_approval_request(
        self, approved: _ApprovedImport
    ) -> TrustedApprovalRequest:
        resolution = approved.resolution_row
        request = TrustedApprovalRequest(
            source_record_id=str(approved.record_row["source_record_id"]),
            observation_id=str(approved.observation_row["observation_id"]),
            review_id=str(resolution["review_id"]),
            resolution_id=str(resolution["resolution_id"]),
            resolution_event_id=str(resolution["event_id"]),
            decision=str(resolution["decision"]).upper(),
            resolved_by=str(resolution["resolved_by"]),
            evidence_ref=str(resolution["evidence_ref"]),
            policy_id=self.policy.policy_id,
            policy_version=self.policy.policy_version,
            policy_hash=self._policy_hash,
            source_id=self.policy.source_id,
            data_contract_version=self.policy.data_contract_version,
            mapping_policy_hash=self.policy.mapping_policy_hash,
            mapping_manifest_hash=self._mapping_manifest_hash,
            lf_source_id=self.policy.bitrix_graph_binding.lf_source_id,
            activity_deadline_utc=self.policy.bitrix_graph_binding.activity_deadline_utc,
        )
        _validate_approval_request(request)
        return request

    def _binding_for_anchored_request(
        self, request: TrustedApprovalRequest
    ) -> BitrixGraphBridgeBinding:
        """Rebuild a creator's binding from its immutable authority request.

        Cross-source reuse must preserve the original Deal/Activity provenance;
        it may not restage that graph using the later source's deadline or ID.
        The only mutable input here is the locally held sealed union manifest,
        whose digest must exactly match the creator's receipt-bound hash.
        """

        if request.mapping_manifest_hash != self._mapping_manifest_hash:
            raise SourceCommercialConflict("creator graph mapping manifest changed")
        binding = replace(
            self.policy.bitrix_graph_binding,
            lf_source_id=request.lf_source_id,
            activity_deadline_utc=request.activity_deadline_utc,
        )
        try:
            if validate_graph_bridge_binding(binding) != request.mapping_manifest_hash:
                raise SourceCommercialConflict("creator graph binding is invalid")
        except BitrixGraphMappingError:
            raise SourceCommercialConflict("creator graph binding is invalid") from None
        return binding

    @staticmethod
    def _current_approval_proof(
        con: Any,
        approved: _ApprovedImport,
        request: TrustedApprovalRequest,
        receipt: TrustedApprovalReceipt,
    ) -> _ApprovalProof:
        event = con.execute(
            "SELECT * FROM events WHERE event_id=?",
            (request.resolution_event_id,),
        ).fetchone()
        if not event:
            raise SourceCommercialConflict("approval resolution event is missing")
        source_payload_hash = str(approved.record_row["payload_hash"] or "")
        resolution_command_hash = str(
            approved.resolution_row["command_hash"] or ""
        )
        resolution_event_hash = str(event["payload_hash"] or "")
        strong_hashes = tuple(sorted(approved.strong_hashes))
        if (
            not _HEX64.fullmatch(source_payload_hash)
            or not _HEX64.fullmatch(resolution_command_hash)
            or not _HEX64.fullmatch(resolution_event_hash)
            or len(set(strong_hashes)) != len(strong_hashes)
            or any(not _HEX64.fullmatch(item) for item in strong_hashes)
        ):
            raise SourceCommercialConflict("approval proof hashes are invalid")
        return _ApprovalProof(
            request,
            receipt,
            source_payload_hash,
            resolution_command_hash,
            resolution_event_hash,
            strong_hashes,
        )

    @staticmethod
    def _anchor_for_batch(con: Any, batch_id: str) -> dict[str, Any]:
        anchors: list[dict[str, Any]] = []
        rows = con.execute(
            """SELECT r.payload_json
               FROM source_lab_record_observations o
               JOIN source_lab_records r ON r.source_record_id=o.source_record_id
               WHERE o.source_batch_id=?""",
            (batch_id,),
        ).fetchall()
        for row in rows:
            envelope = _json_object(row[0], "source import batch payload is invalid")
            if envelope.get("row_number") == 1 and "batch_anchor" in envelope:
                anchors.append(envelope)
        if len(anchors) != 1:
            raise SourceCommercialValidationError("source import batch anchor is invalid")
        anchor = anchors[0].get("batch_anchor")
        if not isinstance(anchor, dict):
            raise SourceCommercialValidationError("source import batch anchor is invalid")
        return anchor

    def _load_approved_import(
        self, con: Any, command: ApprovedSourceCommand
    ) -> _ApprovedImport:
        record = con.execute(
            "SELECT * FROM source_lab_records WHERE source_record_id=?",
            (command.source_record_id,),
        ).fetchone()
        if not record:
            raise SourceCommercialValidationError("source record does not exist")
        if (
            str(record["source_id"]) != self.policy.source_id
            or str(record["payload_hash"]) != command.expected_payload_hash
        ):
            raise SourceCommercialValidationError("source record policy binding changed")
        observation = con.execute(
            """SELECT * FROM source_lab_record_observations
               WHERE observation_id=? AND source_record_id=?""",
            (command.observation_id, command.source_record_id),
        ).fetchone()
        if not observation or str(observation["source_id"]) != self.policy.source_id:
            raise SourceCommercialValidationError("source observation binding is invalid")

        qualification_reviews = con.execute(
            """SELECT * FROM source_lab_reviews
               WHERE source_record_id=? AND review_kind='QUALIFICATION'
               ORDER BY created_at_utc DESC,review_id DESC""",
            (command.source_record_id,),
        ).fetchall()
        if not qualification_reviews:
            raise SourceCommercialValidationError(
                "latest qualification review is not the approved command review"
            )
        latest_review_time = str(qualification_reviews[0]["created_at_utc"])
        if (
            sum(
                str(row["created_at_utc"]) == latest_review_time
                for row in qualification_reviews
            )
            != 1
            or str(qualification_reviews[0]["review_id"]) != command.review_id
        ):
            raise SourceCommercialValidationError(
                "latest qualification review is not the approved command review"
            )
        latest = con.execute(
            """SELECT * FROM source_lab_review_resolutions
               WHERE review_id=? ORDER BY sequence_number DESC LIMIT 1""",
            (command.review_id,),
        ).fetchone()
        if (
            not latest
            or str(latest["resolution_id"]) != command.latest_resolution_id
            or str(latest["decision"]).upper() != "APPROVE"
        ):
            raise SourceCommercialValidationError(
                "latest qualification resolution is not APPROVE"
            )

        envelope = _json_object(record["payload_json"], "source import payload is invalid")
        if (
            envelope.get("schema_version") != "source-import-record-v2"
            or envelope.get("data_contract_version") != self.policy.data_contract_version
            or envelope.get("mapping_policy_hash") != self.policy.mapping_policy_hash
            or not isinstance(envelope.get("record"), dict)
        ):
            raise SourceCommercialValidationError("source import contract is not approved")
        anchor = self._anchor_for_batch(con, str(observation["source_batch_id"]))
        mapping_policy = anchor.get("mapping_policy")
        if (
            not isinstance(mapping_policy, dict)
            or mapping_policy.get("source_id") != self.policy.source_id
            or mapping_policy.get("data_contract_version")
            != self.policy.data_contract_version
        ):
            raise SourceCommercialValidationError("source import mapping policy is invalid")

        raw_field_mappings = mapping_policy.get("field_mappings")
        raw_identity_mappings = mapping_policy.get("identity_mappings")
        if not isinstance(raw_field_mappings, list) or not isinstance(
            raw_identity_mappings, list
        ):
            raise SourceCommercialValidationError("source import mapping policy is invalid")
        source_to_target: dict[str, str] = {}
        for item in raw_field_mappings:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not all(isinstance(part, str) for part in item)
                or not _FIELD.fullmatch(item[1])
                or item[0] in source_to_target
            ):
                raise SourceCommercialValidationError("source import field mapping is invalid")
            source_to_target[item[0]] = item[1]
        bound_fields = {
            getattr(self.policy.field_bindings, name)
            for name in self.policy.field_bindings.__dataclass_fields__
        }
        if not bound_fields.issubset(set(source_to_target.values())):
            raise SourceCommercialValidationError(
                "commercial fields are not bound by the source mapping policy"
            )

        mapped_record = dict(envelope["record"])
        values = _normalised_values(mapped_record, self.policy.field_bindings)
        observation_identities = {
            (str(row["key_namespace"]), str(row["canonical_key_hash"]))
            for row in con.execute(
                """SELECT k.key_namespace,k.canonical_key_hash
                   FROM source_lab_record_identity_links l
                   JOIN source_lab_identity_keys k
                     ON k.identity_key_id=l.identity_key_id
                   WHERE l.observation_id=?""",
                (command.observation_id,),
            ).fetchall()
        }
        strong_hashes: set[str] = set()
        declared_strong: set[str] = set()
        for item in raw_identity_mappings:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
                or not isinstance(item[2], bool)
                or item[0] not in source_to_target
            ):
                raise SourceCommercialValidationError("source identity mapping is invalid")
            namespace = item[1].strip().lower()
            if namespace not in self._strong_namespaces:
                continue
            declared_strong.add(namespace)
            target = source_to_target[item[0]]
            raw_value = mapped_record.get(target)
            if raw_value in (None, ""):
                continue
            if not isinstance(raw_value, str):
                raise SourceCommercialValidationError("strong project identity is invalid")
            try:
                fingerprints = canonical_identity_fingerprints(((namespace, raw_value),))
            except SourceLabError:
                raise SourceCommercialValidationError(
                    "strong project identity is invalid"
                ) from None
            if len(fingerprints) != 1 or fingerprints[0] not in observation_identities:
                raise SourceCommercialConflict(
                    "strong project identity is detached from source provenance"
                )
            strong_hashes.add(fingerprints[0][1])
        if set(self._strong_namespaces) - declared_strong:
            raise SourceCommercialValidationError(
                "strong project namespace is absent from the source mapping policy"
            )
        return _ApprovedImport(
            record,
            observation,
            latest,
            envelope,
            mapped_record,
            mapping_policy,
            values,
            tuple(sorted(strong_hashes)),
        )

    @staticmethod
    def _load_graph(con: Any, opportunity_id: str) -> NormalizedOpportunityResult:
        row = con.execute(
            """SELECT lf_opportunity_id,lf_company_id,lf_contact_id,lf_project_id,
                      source_event_id
               FROM opportunities WHERE lf_opportunity_id=?""",
            (opportunity_id,),
        ).fetchone()
        if not row or not row["lf_contact_id"] or not row["lf_project_id"]:
            raise SourceCommercialConflict("commercial opportunity graph is incomplete")
        if not con.execute(
            """SELECT 1 FROM contacts c JOIN projects p ON p.lf_company_id=c.lf_company_id
               WHERE c.lf_contact_id=? AND p.lf_project_id=?
                 AND c.lf_company_id=?""",
            (row["lf_contact_id"], row["lf_project_id"], row["lf_company_id"]),
        ).fetchone():
            raise SourceCommercialConflict("commercial opportunity graph crossed companies")
        return NormalizedOpportunityResult(
            False,
            str(row["source_event_id"] or ""),
            str(row["lf_company_id"]),
            str(row["lf_contact_id"]),
            str(row["lf_project_id"]),
            str(row["lf_opportunity_id"]),
        )

    @staticmethod
    def _direct_link(con: Any, source_record_id: str) -> Any | None:
        rows = con.execute(
            """SELECT * FROM source_lab_opportunity_evidence_links
               WHERE source_record_id=? ORDER BY evidence_link_id""",
            (source_record_id,),
        ).fetchall()
        if len(rows) > 1:
            raise SourceCommercialConflict(
                "source record is linked to multiple commercial opportunities"
            )
        return rows[0] if rows else None

    @staticmethod
    def _link_row(con: Any, evidence_link_id: str) -> Any:
        row = con.execute(
            """SELECT * FROM source_lab_opportunity_evidence_links
               WHERE evidence_link_id=?""",
            (evidence_link_id,),
        ).fetchone()
        if not row:
            raise SourceCommercialConflict("source evidence link disappeared")
        return row

    @staticmethod
    def _bridge_anchor_payload(
        link: Any,
        graph: NormalizedOpportunityResult,
        proof: _ApprovalProof,
        *,
        graph_created: bool,
        creator_resolution_event_id: str,
    ) -> dict[str, Any]:
        """Return the non-secret immutable binding stored in the Event Store."""

        request = proof.request
        receipt = proof.receipt
        if str(link["lf_opportunity_id"]) != graph.lf_opportunity_id:
            raise SourceCommercialConflict("approved evidence link crossed opportunities")
        return {
            "anchor_version": _BRIDGE_LINK_ANCHOR_VERSION,
            "evidence_link_id": str(link["evidence_link_id"]),
            "link_event_id": str(link["event_id"]),
            "link_command_hash": str(link["command_hash"]),
            "lf_company_id": graph.lf_company_id,
            "lf_contact_id": graph.lf_contact_id,
            "lf_project_id": graph.lf_project_id,
            "lf_opportunity_id": graph.lf_opportunity_id,
            "source_record_id": request.source_record_id,
            "observation_id": request.observation_id,
            "review_id": request.review_id,
            "resolution_id": request.resolution_id,
            "resolution_event_id": request.resolution_event_id,
            "resolution_command_hash": proof.resolution_command_hash,
            "resolution_event_hash": proof.resolution_event_hash,
            "source_payload_hash": proof.source_payload_hash,
            "strong_identity_hashes": list(proof.strong_hashes),
            "approval_request_hash": request.request_hash,
            "approval_receipt_hash": receipt.receipt_hash,
            "approval_authority_id": receipt.authority_id,
            "approval_receipt_id": receipt.receipt_id,
            "policy_id": request.policy_id,
            "policy_version": request.policy_version,
            "policy_hash": request.policy_hash,
            "source_id": request.source_id,
            "data_contract_version": request.data_contract_version,
            "mapping_policy_hash": request.mapping_policy_hash,
            "mapping_manifest_hash": request.mapping_manifest_hash,
            "lf_source_id": request.lf_source_id,
            "activity_deadline_utc": request.activity_deadline_utc,
            "graph_created": bool(graph_created),
            "creator_resolution_event_id": creator_resolution_event_id,
        }

    @staticmethod
    def _anchor_events_for_link(con: Any, link_id: str) -> list[tuple[Any, dict[str, Any]]]:
        matches: list[tuple[Any, dict[str, Any]]] = []
        for event in con.execute(
            "SELECT * FROM events WHERE event_type=? ORDER BY event_id",
            (_BRIDGE_LINK_ANCHOR_EVENT,),
        ).fetchall():
            aggregate_match = (
                str(event["aggregate_type"]) == "source_lab_evidence_link"
                and str(event["aggregate_id"]) == link_id
            )
            try:
                anchored = _json_object(
                    event["payload_json"], "approved evidence anchor is invalid"
                )
                canonical_json(anchored)
            except (SourceCommercialValidationError, TypeError, ValueError):
                if aggregate_match:
                    raise SourceCommercialConflict(
                        "approved evidence anchor is invalid"
                    ) from None
                continue
            payload_match = str(anchored.get("evidence_link_id") or "") == link_id
            if aggregate_match or payload_match:
                matches.append((event, anchored))
        return matches

    @staticmethod
    def _assert_anchor_event(
        event: Any, anchored: dict[str, Any], expected: dict[str, Any]
    ) -> None:
        raw = str(event["payload_json"] or "")
        event_id = str(event["event_id"] or "")
        occurred_at = str(event["occurred_at_utc"] or "")
        recorded_at = str(event["recorded_at_utc"] or "")
        try:
            _safe_id(event_id, "approved evidence anchor is invalid")
            if (
                not _UTC_SECONDS.fullmatch(occurred_at)
                or not _UTC_SECONDS.fullmatch(recorded_at)
            ):
                raise ValueError("non-canonical timestamp")
            datetime.strptime(occurred_at, "%Y-%m-%dT%H:%M:%SZ")
            datetime.strptime(recorded_at, "%Y-%m-%dT%H:%M:%SZ")
            schema_version = int(event["schema_version"])
            canonical = canonical_json(anchored)
            digest = payload_hash(anchored)
        except (SourceCommercialValidationError, TypeError, ValueError):
            raise SourceCommercialConflict("approved evidence anchor is invalid") from None
        if (
            anchored != expected
            or canonical != raw
            or digest != str(event["payload_hash"] or "")
            or str(event["event_type"]) != _BRIDGE_LINK_ANCHOR_EVENT
            or str(event["aggregate_type"]) != "source_lab_evidence_link"
            or str(event["aggregate_id"]) != expected["evidence_link_id"]
            or str(event["producer"]) != _BRIDGE_PRODUCER
            or str(event["idempotency_key"])
            != f"approved-link-anchor:{expected['evidence_link_id']}"
            or str(event["actor"]) != _BRIDGE_ACTOR
            or str(event["correlation_id"] or "") != event_id
            or str(event["causation_id"] or "") != expected["resolution_event_id"]
            or str(event["evidence_ref"] or "")
            or occurred_at != recorded_at
            or schema_version != 16
        ):
            raise SourceCommercialConflict("approved evidence anchor is invalid")

    def _append_bridge_anchor(
        self,
        con: Any,
        link: Any,
        graph: NormalizedOpportunityResult,
        proof: _ApprovalProof,
        *,
        graph_created: bool,
        creator_resolution_event_id: str,
    ) -> None:
        expected = self._bridge_anchor_payload(
            link,
            graph,
            proof,
            graph_created=graph_created,
            creator_resolution_event_id=creator_resolution_event_id,
        )
        self._assert_receipt_anchor_unique(con, expected)
        self.store._append_event_tx(
            con,
            event_type=_BRIDGE_LINK_ANCHOR_EVENT,
            aggregate_type="source_lab_evidence_link",
            aggregate_id=str(link["evidence_link_id"]),
            producer=_BRIDGE_PRODUCER,
            idempotency_key=f"approved-link-anchor:{link['evidence_link_id']}",
            payload=expected,
            actor=_BRIDGE_ACTOR,
            causation_id=proof.request.resolution_event_id,
            schema_version=16,
        )
        rows = self._anchor_events_for_link(con, str(link["evidence_link_id"]))
        if len(rows) != 1:
            raise SourceCommercialConflict(
                "exactly one approved evidence anchor is required"
            )
        self._assert_anchor_event(rows[0][0], rows[0][1], expected)

    @staticmethod
    def _assert_receipt_anchor_unique(
        con: Any, expected: Mapping[str, Any]
    ) -> None:
        receipt_id = str(expected["approval_receipt_id"])
        receipt_hash = str(expected["approval_receipt_hash"])
        link_id = str(expected["evidence_link_id"])
        for event in con.execute(
            "SELECT aggregate_id,payload_json FROM events WHERE event_type=?",
            (_BRIDGE_LINK_ANCHOR_EVENT,),
        ).fetchall():
            try:
                other = _json_object(
                    event["payload_json"], "approved evidence anchor is invalid"
                )
            except SourceCommercialValidationError:
                if str(event["aggregate_id"]) == link_id:
                    raise SourceCommercialConflict(
                        "approved evidence anchor is invalid"
                    ) from None
                continue
            if (
                str(other.get("approval_receipt_id") or "") == receipt_id
                or str(other.get("approval_receipt_hash") or "") == receipt_hash
            ) and str(other.get("evidence_link_id") or "") != link_id:
                raise SourceCommercialConflict(
                    "approval receipt is already anchored to another link"
                )

    @staticmethod
    def _anchor_text(anchor: Mapping[str, Any], key: str, *, digest: bool = False) -> str:
        value = str(anchor.get(key) or "").strip()
        if digest:
            if not _HEX64.fullmatch(value):
                raise SourceCommercialConflict("approved evidence anchor is invalid")
        else:
            try:
                _safe_id(value, "approved evidence anchor is invalid")
            except SourceCommercialValidationError:
                raise SourceCommercialConflict(
                    "approved evidence anchor is invalid"
                ) from None
        return value

    @staticmethod
    def _anchor_deadline(anchor: Mapping[str, Any]) -> str:
        value = str(anchor.get("activity_deadline_utc") or "")
        if not _UTC_SECONDS.fullmatch(value):
            raise SourceCommercialConflict("approved evidence anchor is invalid")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise SourceCommercialConflict("approved evidence anchor is invalid") from None
        return value

    def _request_from_anchor(
        self, con: Any, link: Any, anchor: Mapping[str, Any]
    ) -> TrustedApprovalRequest:
        source_record_id = self._anchor_text(anchor, "source_record_id")
        observation_id = self._anchor_text(anchor, "observation_id")
        review_id = self._anchor_text(anchor, "review_id")
        resolution_id = self._anchor_text(anchor, "resolution_id")
        resolution_event_id = self._anchor_text(anchor, "resolution_event_id")
        if source_record_id != str(link["source_record_id"]):
            raise SourceCommercialConflict("approved evidence lineage is invalid")

        record = con.execute(
            "SELECT * FROM source_lab_records WHERE source_record_id=?",
            (source_record_id,),
        ).fetchone()
        observation = con.execute(
            """SELECT * FROM source_lab_record_observations
               WHERE observation_id=? AND source_record_id=?""",
            (observation_id, source_record_id),
        ).fetchone()
        review = con.execute(
            """SELECT * FROM source_lab_reviews
               WHERE review_id=? AND source_record_id=? AND review_kind='QUALIFICATION'""",
            (review_id, source_record_id),
        ).fetchone()
        if not record or not observation or not review:
            raise SourceCommercialConflict("approved evidence lineage is invalid")

        reviews = con.execute(
            """SELECT review_id,created_at_utc FROM source_lab_reviews
               WHERE source_record_id=? AND review_kind='QUALIFICATION'
               ORDER BY created_at_utc DESC,review_id DESC""",
            (source_record_id,),
        ).fetchall()
        latest_review_time = str(reviews[0]["created_at_utc"]) if reviews else ""
        if (
            not reviews
            or sum(str(row["created_at_utc"]) == latest_review_time for row in reviews)
            != 1
            or str(reviews[0]["review_id"]) != review_id
        ):
            raise SourceCommercialConflict("approved evidence lineage is not latest")

        resolution = con.execute(
            """SELECT * FROM source_lab_review_resolutions
               WHERE review_id=? ORDER BY sequence_number DESC LIMIT 1""",
            (review_id,),
        ).fetchone()
        if (
            not resolution
            or str(resolution["resolution_id"]) != resolution_id
            or str(resolution["event_id"]) != resolution_event_id
            or str(resolution["decision"]).upper() != "APPROVE"
        ):
            raise SourceCommercialConflict("approved evidence lineage is invalid")

        source_id = self._anchor_text(anchor, "source_id")
        data_contract_version = self._anchor_text(anchor, "data_contract_version")
        mapping_policy_hash = self._anchor_text(
            anchor, "mapping_policy_hash", digest=True
        )
        envelope = _json_object(record["payload_json"], "source import payload is invalid")
        if (
            str(record["source_id"]) != source_id
            or str(observation["source_id"]) != source_id
            or envelope.get("schema_version") != "source-import-record-v2"
            or envelope.get("data_contract_version") != data_contract_version
            or envelope.get("mapping_policy_hash") != mapping_policy_hash
        ):
            raise SourceCommercialConflict("approved evidence lineage is invalid")

        request = TrustedApprovalRequest(
            source_record_id=source_record_id,
            observation_id=observation_id,
            review_id=review_id,
            resolution_id=resolution_id,
            resolution_event_id=resolution_event_id,
            decision="APPROVE",
            resolved_by=str(resolution["resolved_by"]),
            evidence_ref=str(resolution["evidence_ref"]),
            policy_id=self._anchor_text(anchor, "policy_id"),
            policy_version=self._anchor_text(anchor, "policy_version"),
            policy_hash=self._anchor_text(anchor, "policy_hash", digest=True),
            source_id=source_id,
            data_contract_version=data_contract_version,
            mapping_policy_hash=mapping_policy_hash,
            mapping_manifest_hash=self._anchor_text(
                anchor, "mapping_manifest_hash", digest=True
            ),
            lf_source_id=self._anchor_text(anchor, "lf_source_id"),
            activity_deadline_utc=self._anchor_deadline(anchor),
        )
        try:
            _validate_approval_request(request)
        except SourceCommercialValidationError:
            raise SourceCommercialConflict("approved evidence lineage is invalid") from None
        return request

    def _proof_from_anchor(
        self,
        con: Any,
        link: Any,
        anchor: Mapping[str, Any],
        *,
        expected_proof: _ApprovalProof | None = None,
    ) -> _ApprovalProof:
        request = self._request_from_anchor(con, link, anchor)
        if expected_proof is None:
            try:
                receipt = self._verify_approval(request)
            except SourceCommercialValidationError:
                raise SourceCommercialConflict(
                    "trusted approval lineage could not be verified"
                ) from None
        else:
            if request != expected_proof.request:
                raise SourceCommercialConflict("trusted approval lineage changed")
            try:
                receipt = _validate_approval_receipt(
                    expected_proof.receipt, request
                )
            except SourceCommercialValidationError:
                raise SourceCommercialConflict(
                    "trusted approval lineage changed"
                ) from None

        raw_strong = anchor.get("strong_identity_hashes")
        if (
            not isinstance(raw_strong, list)
            or any(type(item) is not str for item in raw_strong)
        ):
            raise SourceCommercialConflict("approved strong identity anchor is invalid")
        strong_hashes = tuple(raw_strong)
        if (
            tuple(sorted(strong_hashes)) != strong_hashes
            or len(set(strong_hashes)) != len(strong_hashes)
            or any(not _HEX64.fullmatch(item) for item in strong_hashes)
        ):
            raise SourceCommercialConflict("approved strong identity anchor is invalid")
        observed_hashes = {
            str(row[0])
            for row in con.execute(
                """SELECT k.canonical_key_hash
                   FROM source_lab_record_identity_links l
                   JOIN source_lab_identity_keys k
                     ON k.identity_key_id=l.identity_key_id
                   WHERE l.observation_id=?""",
                (request.observation_id,),
            ).fetchall()
        }
        if not set(strong_hashes).issubset(observed_hashes):
            raise SourceCommercialConflict(
                "approved strong identity is detached from its observation"
            )

        record = con.execute(
            "SELECT payload_hash FROM source_lab_records WHERE source_record_id=?",
            (request.source_record_id,),
        ).fetchone()
        resolution = con.execute(
            """SELECT command_hash FROM source_lab_review_resolutions
               WHERE resolution_id=? AND review_id=?""",
            (request.resolution_id, request.review_id),
        ).fetchone()
        resolution_event = con.execute(
            "SELECT payload_hash FROM events WHERE event_id=?",
            (request.resolution_event_id,),
        ).fetchone()
        if not record or not resolution or not resolution_event:
            raise SourceCommercialConflict("approved evidence lineage is invalid")
        proof = _ApprovalProof(
            request,
            receipt,
            str(record["payload_hash"] or ""),
            str(resolution["command_hash"] or ""),
            str(resolution_event["payload_hash"] or ""),
            strong_hashes,
        )
        if (
            any(
                not _HEX64.fullmatch(item)
                for item in (
                    proof.source_payload_hash,
                    proof.resolution_command_hash,
                    proof.resolution_event_hash,
                )
            )
            or (expected_proof is not None and proof != expected_proof)
        ):
            raise SourceCommercialConflict("trusted approval lineage changed")
        return proof

    def _validate_anchored_link(
        self,
        con: Any,
        link: Any,
        *,
        required: bool,
        expected_proof: _ApprovalProof | None = None,
    ) -> _VerifiedAnchor | None:
        events = self._anchor_events_for_link(con, str(link["evidence_link_id"]))
        if not events:
            if required or str(link["link_reason"]) == "APPROVED_SOURCE_IMPORT":
                raise SourceCommercialConflict(
                    "direct evidence link has no trusted approval anchor"
                )
            return None
        if len(events) != 1:
            raise SourceCommercialConflict(
                "exactly one approved evidence anchor is required"
            )
        if (
            str(link["link_reason"]) != "APPROVED_SOURCE_IMPORT"
            or str(link["actor"]) != _BRIDGE_ACTOR
        ):
            raise SourceCommercialConflict("approved evidence link is invalid")

        anchored = events[0][1]
        proof = self._proof_from_anchor(
            con, link, anchored, expected_proof=expected_proof
        )
        opportunity_id = self._anchor_text(anchored, "lf_opportunity_id")
        company_id = self._anchor_text(anchored, "lf_company_id")
        contact_id = self._anchor_text(anchored, "lf_contact_id")
        project_id = self._anchor_text(anchored, "lf_project_id")
        creator_event_id = self._anchor_text(
            anchored, "creator_resolution_event_id"
        )
        graph_created = anchored.get("graph_created")
        if type(graph_created) is not bool or opportunity_id != str(
            link["lf_opportunity_id"]
        ):
            raise SourceCommercialConflict("approved evidence graph anchor is invalid")
        graph = self._load_graph(con, opportunity_id)
        if (
            graph.lf_company_id != company_id
            or graph.lf_contact_id != contact_id
            or graph.lf_project_id != project_id
            or (graph_created and creator_event_id != proof.request.resolution_event_id)
        ):
            raise SourceCommercialConflict("approved evidence graph anchor is invalid")
        expected = self._bridge_anchor_payload(
            link,
            graph,
            proof,
            graph_created=graph_created,
            creator_resolution_event_id=creator_event_id,
        )
        self._assert_receipt_anchor_unique(con, expected)
        self._assert_anchor_event(events[0][0], events[0][1], expected)
        return _VerifiedAnchor(
            str(link["evidence_link_id"]),
            opportunity_id,
            company_id,
            contact_id,
            project_id,
            graph_created,
            creator_event_id,
            proof,
        )

    def _strong_linked_anchors(
        self,
        con: Any,
        hashes: tuple[str, ...],
        *,
        exclude_link_id: str = "",
        expected_anchors: Mapping[str, _VerifiedAnchor] | None = None,
        include_unmatched: bool = False,
    ) -> tuple[_VerifiedAnchor, ...]:
        if not hashes:
            return ()
        placeholders = ",".join("?" for _ in hashes)
        rows = con.execute(
            f"""SELECT DISTINCT e.*
                FROM source_lab_identity_keys k
                JOIN source_lab_record_identity_links l
                  ON l.identity_key_id=k.identity_key_id
                JOIN source_lab_opportunity_evidence_links e
                  ON e.source_record_id=l.source_record_id
                WHERE k.canonical_key_hash IN ({placeholders})
                ORDER BY e.evidence_link_id""",
            hashes,
        ).fetchall()
        trusted: list[_VerifiedAnchor] = []
        seen: set[str] = set()
        for link in rows:
            link_id = str(link["evidence_link_id"])
            if link_id == exclude_link_id:
                continue
            cached = expected_anchors.get(link_id) if expected_anchors is not None else None
            if expected_anchors is not None and cached is None:
                events = self._anchor_events_for_link(con, link_id)
                if events or str(link["link_reason"]) == "APPROVED_SOURCE_IMPORT":
                    raise SourceCommercialConflict(
                        "strong approval candidate set changed"
                    )
                continue
            verified = self._validate_anchored_link(
                con,
                link,
                required=False,
                expected_proof=(cached.proof if cached is not None else None),
            )
            if verified is None:
                continue
            if cached is not None and verified != cached:
                raise SourceCommercialConflict("strong approval candidate changed")
            if not set(hashes).intersection(verified.proof.strong_hashes):
                if include_unmatched:
                    trusted.append(verified)
                    seen.add(link_id)
                continue
            trusted.append(verified)
            seen.add(link_id)
        if expected_anchors is not None and seen != set(expected_anchors):
            raise SourceCommercialConflict("strong approval candidate set changed")
        return tuple(sorted(trusted, key=lambda item: item.evidence_link_id))

    @staticmethod
    def _assert_company_match(
        con: Any,
        graph: NormalizedOpportunityResult,
        values: Mapping[str, str],
        *,
        cross_record_reuse: bool,
    ) -> None:
        row = con.execute(
            "SELECT inn,domain FROM companies WHERE lf_company_id=?",
            (graph.lf_company_id,),
        ).fetchone()
        if not row:
            raise SourceCommercialConflict("commercial company is missing")
        expected_inn = str(values["company_inn"])
        expected_domain = str(values["company_domain"])
        if cross_record_reuse:
            if not expected_inn or str(row["inn"]) != expected_inn:
                raise SourceCommercialConflict(
                    "strong project identity has no exact INN company match"
                )
            return
        if expected_inn:
            matched = str(row["inn"]) == expected_inn
        else:
            matched = bool(expected_domain) and str(row["domain"]) == expected_domain
        if not matched:
            raise SourceCommercialConflict("commercial company identity changed")

    @staticmethod
    def _crm_payloads(
        con: Any,
        graph: NormalizedOpportunityResult,
        binding: BitrixGraphBridgeBinding,
        source_event_id: str,
    ) -> dict[str, dict[str, Any]]:
        company = con.execute(
            "SELECT * FROM companies WHERE lf_company_id=?", (graph.lf_company_id,)
        ).fetchone()
        contact = con.execute(
            "SELECT * FROM contacts WHERE lf_contact_id=?", (graph.lf_contact_id,)
        ).fetchone()
        project = con.execute(
            "SELECT * FROM projects WHERE lf_project_id=?", (graph.lf_project_id,)
        ).fetchone()
        opportunity = con.execute(
            "SELECT * FROM opportunities WHERE lf_opportunity_id=?",
            (graph.lf_opportunity_id,),
        ).fetchone()
        if not all((company, contact, project, opportunity)):
            raise SourceCommercialConflict("commercial graph payload is incomplete")
        company_title = str(company["name"] or company["inn"] or company["domain"] or "").strip()
        contact_title = str(contact["name"] or contact["email"] or "").strip()
        project_title = str(project["title"] or "").strip()
        if not company_title or not contact_title or not project_title:
            raise SourceCommercialConflict("commercial graph payload is incomplete")
        return {
            "company": {
                "TITLE": company_title,
                "UF_CRM_LF_COMPANY_ID": graph.lf_company_id,
            },
            "contact": {
                "NAME": contact_title,
                "EMAIL": str(contact["email"]),
                "UF_CRM_LF_CONTACT_ID": graph.lf_contact_id,
            },
            "deal": {
                "TITLE": project_title,
                "UF_CRM_LF_OPPORTUNITY_ID": graph.lf_opportunity_id,
                "UF_CRM_LF_PROJECT_ID": graph.lf_project_id,
                "UF_CRM_LF_PRODUCT_KEY": str(opportunity["product_key"]),
                "UF_CRM_LF_SOURCE_EVENT_ID": source_event_id,
                "UF_CRM_LF_SOURCE_ID": binding.lf_source_id,
            },
            "activity": {
                "SUBJECT": f"Review: {project_title}",
                "DEADLINE": binding.activity_deadline_utc,
                "UF_CRM_LF_OPPORTUNITY_ID": graph.lf_opportunity_id,
            },
        }

    @staticmethod
    def _existing_crm_stage(
        con: Any,
        graph: NormalizedOpportunityResult,
        payloads: Mapping[str, Mapping[str, Any]],
        *,
        expected_external_event_id: str,
        binding: BitrixGraphBridgeBinding,
    ) -> CrmGraphStageResult | None:
        """Read and verify a complete prior four-operation graph, if present."""

        expected_causation = str(expected_external_event_id or "").strip()
        if not expected_causation:
            raise SourceCommercialConflict("expected CRM causation is missing")
        specs = (
            (COMPANY_CREATE, "company", graph.lf_company_id, payloads["company"]),
            (CONTACT_CREATE, "contact", graph.lf_contact_id, payloads["contact"]),
            (DEAL_CREATE, "opportunity", graph.lf_opportunity_id, payloads["deal"]),
            (ACTIVITY_CREATE, "opportunity", graph.lf_opportunity_id, payloads["activity"]),
        )
        rows: dict[str, Any] = {}
        for operation_type, entity_type, entity_id, _payload in specs:
            found = con.execute(
                """SELECT * FROM crm_outbox
                   WHERE operation_type=? AND lf_entity_type=? AND lf_entity_id=?
                   ORDER BY operation_id""",
                (operation_type, entity_type, entity_id),
            ).fetchall()
            if len(found) > 1:
                raise SourceCommercialConflict("CRM graph operation is ambiguous")
            if found:
                rows[operation_type] = found[0]
        opportunity_operations = {
            item for item in (DEAL_CREATE, ACTIVITY_CREATE) if item in rows
        }
        if not opportunity_operations:
            return None
        if opportunity_operations != {DEAL_CREATE, ACTIVITY_CREATE} or set(rows) != {
            COMPANY_CREATE,
            CONTACT_CREATE,
            DEAL_CREATE,
            ACTIVITY_CREATE,
        }:
            raise SourceCommercialConflict("CRM opportunity graph is only partially staged")

        company = rows[COMPANY_CREATE]
        contact = rows[CONTACT_CREATE]
        deal = rows[DEAL_CREATE]
        activity = rows[ACTIVITY_CREATE]
        dependencies = {
            COMPANY_CREATE: "",
            CONTACT_CREATE: str(company["operation_id"]),
            DEAL_CREATE: str(contact["operation_id"]),
            ACTIVITY_CREATE: str(deal["operation_id"]),
        }
        expected_metadata = {
            operation_type: CrmGraphOutbox._metadata(
                operation_type,
                company_id=graph.lf_company_id,
                contact_id=graph.lf_contact_id,
                project_id=graph.lf_project_id,
                opportunity_id=graph.lf_opportunity_id,
                mapping_manifest_hash=validate_graph_bridge_binding(binding),
                lf_source_id=binding.lf_source_id,
            )
            for operation_type in rows
        }
        payload_by_type = {
            COMPANY_CREATE: dict(payloads["company"]),
            CONTACT_CREATE: dict(payloads["contact"]),
            DEAL_CREATE: dict(payloads["deal"]),
            ACTIVITY_CREATE: dict(payloads["activity"]),
        }
        try:
            CrmGraphOutbox._assert_exact_graph_tx(
                con,
                company_id=graph.lf_company_id,
                contact_id=graph.lf_contact_id,
                project_id=graph.lf_project_id,
                opportunity_id=graph.lf_opportunity_id,
            )
            CrmGraphOutbox._assert_no_lead_path_tx(con, graph.lf_opportunity_id)
            for operation_type, operation in rows.items():
                body = CrmGraphOutbox._assert_operation_envelope(operation)
                CrmGraphOutbox._assert_stage_anchor_tx(con, operation)
                public = {
                    key: value
                    for key, value in body.items()
                    if not str(key).startswith("_lf_")
                }
                if (
                    str(operation["dependency_operation_id"] or "")
                    != dependencies[operation_type]
                    or body.get("_lf_graph_v1") != expected_metadata[operation_type]
                    or public != payload_by_type[operation_type]
                ):
                    raise GraphInvariantError("CRM graph command chain changed")
            deal_causation = str(deal["external_event_id"] or "")
            activity_causation = str(activity["external_event_id"] or "")
            if (
                deal_causation != activity_causation
                or deal_causation != expected_causation
            ):
                raise GraphInvariantError("CRM opportunity causation chain changed")
        except (GraphInvariantError, IdempotencyConflict, KeyError, TypeError, ValueError):
            raise SourceCommercialConflict("existing CRM graph is not exact") from None
        return CrmGraphStageResult(
            str(company["operation_id"]),
            str(contact["operation_id"]),
            str(deal["operation_id"]),
            str(activity["operation_id"]),
            (),
        )

    def execute(self, command: ApprovedSourceCommand) -> SourceCommercialBridgeResult:
        """Apply one approved command without performing external I/O."""

        _validate_command(command)
        link_idempotency = f"source-commercial-link-v1:{command.idempotency_key}"
        intake_idempotency = f"source-commercial-intake-v1:{command.idempotency_key}"

        try:
            # Authority callbacks run before BEGIN IMMEDIATE.  The writer
            # transaction below reloads every bound fact and accepts only the
            # exact preflight proof, closing the check/use gap without holding
            # a database write lock across injected code.
            self.store.init()
            preflight_con = self.store.connect()
            try:
                if not self._writers_are_off(preflight_con):
                    raise SourceCommercialValidationError(
                        "external writers must remain disabled for the offline bridge"
                    )
                validate_source_lab_integrity(preflight_con)
                preflight_approved = self._load_approved_import(
                    preflight_con, command
                )
                preflight_request = self._current_approval_request(
                    preflight_approved
                )
                preflight_receipt = self._verify_approval(preflight_request)
                preflight_proof = self._current_approval_proof(
                    preflight_con,
                    preflight_approved,
                    preflight_request,
                    preflight_receipt,
                )
                preflight_direct = self._direct_link(
                    preflight_con, command.source_record_id
                )
                preflight_direct_anchor = (
                    self._validate_anchored_link(
                        preflight_con,
                        preflight_direct,
                        required=True,
                        expected_proof=preflight_proof,
                    )
                    if preflight_direct
                    else None
                )
                preflight_candidates = self._strong_linked_anchors(
                    preflight_con,
                    preflight_approved.strong_hashes,
                    exclude_link_id=(
                        str(preflight_direct["evidence_link_id"])
                        if preflight_direct
                        else ""
                    ),
                    include_unmatched=True,
                )
            finally:
                preflight_con.close()

            cached_candidates = {
                item.evidence_link_id: item for item in preflight_candidates
            }
            with self.store.transaction(min_schema_version=16) as con:
                if not self._writers_are_off(con):
                    raise SourceCommercialValidationError(
                        "external writers must remain disabled for the offline bridge"
                    )
                validate_source_lab_integrity(con)
                approved = self._load_approved_import(con, command)
                approval_request = self._current_approval_request(approved)
                if approval_request != preflight_request:
                    raise SourceCommercialConflict("approved command changed after verification")
                approval_receipt = _validate_approval_receipt(
                    preflight_receipt, approval_request
                )
                approval_proof = self._current_approval_proof(
                    con, approved, approval_request, approval_receipt
                )
                if approval_proof != preflight_proof:
                    raise SourceCommercialConflict("approved command changed after verification")
                direct = self._direct_link(con, command.source_record_id)
                if bool(direct) != bool(preflight_direct) or (
                    direct
                    and str(direct["evidence_link_id"])
                    != str(preflight_direct["evidence_link_id"])
                ):
                    raise SourceCommercialConflict("direct evidence link changed")
                direct_anchor = (
                    self._validate_anchored_link(
                        con,
                        direct,
                        required=True,
                        expected_proof=approval_proof,
                    )
                    if direct
                    else None
                )
                if direct_anchor != preflight_direct_anchor:
                    raise SourceCommercialConflict("direct evidence anchor changed")
                candidates = self._strong_linked_anchors(
                    con,
                    approved.strong_hashes,
                    exclude_link_id=(
                        str(direct["evidence_link_id"]) if direct else ""
                    ),
                    expected_anchors=cached_candidates,
                    include_unmatched=True,
                )
                linked_anchors = tuple(
                    item
                    for item in candidates
                    if set(approved.strong_hashes).intersection(
                        item.proof.strong_hashes
                    )
                )
                linked = tuple(
                    sorted({item.opportunity_id for item in linked_anchors})
                )
                cross_source_reuse = False
                crm_binding = self.policy.bitrix_graph_binding
                if direct:
                    target_id = str(direct["lf_opportunity_id"])
                    if linked and set(linked) != {target_id}:
                        raise SourceCommercialConflict(
                            "strong project identity resolves to multiple opportunities"
                        )
                    if str(direct["idempotency_key"]) != link_idempotency:
                        raise SourceCommercialConflict(
                            "source record was linked by another bridge command"
                        )
                    graph = self._load_graph(con, target_id)
                    self._assert_company_match(
                        con, graph, approved.values, cross_record_reuse=False
                    )
                    opportunity_reused = True
                    anchor_lineage = (direct_anchor,) + tuple(linked_anchors)
                    creators = tuple(
                        item
                        for item in anchor_lineage
                        if item is not None
                        and item.opportunity_id == target_id
                        and item.graph_created
                    )
                    if len(creators) != 1 or any(
                        item.creator_resolution_event_id
                        != creators[0].creator_resolution_event_id
                        for item in anchor_lineage
                        if item is not None and item.opportunity_id == target_id
                    ):
                        raise SourceCommercialConflict(
                            "commercial graph creator anchor is not unique"
                        )
                    creator_resolution_event_id = (
                        creators[0].creator_resolution_event_id
                    )
                    current_link_graph_created = bool(direct_anchor.graph_created)
                elif linked:
                    if len(linked) != 1:
                        raise SourceCommercialConflict(
                            "strong project identity resolves to multiple opportunities"
                        )
                    graph = self._load_graph(con, linked[0])
                    self._assert_company_match(
                        con, graph, approved.values, cross_record_reuse=True
                    )
                    creators = tuple(
                        item
                        for item in linked_anchors
                        if item.opportunity_id == graph.lf_opportunity_id
                        and item.graph_created
                    )
                    if len(creators) != 1 or any(
                        item.creator_resolution_event_id
                        != creators[0].creator_resolution_event_id
                        for item in linked_anchors
                        if item.opportunity_id == graph.lf_opportunity_id
                    ):
                        raise SourceCommercialConflict(
                            "commercial graph creator anchor is not unique"
                        )
                    creator_resolution_event_id = (
                        creators[0].creator_resolution_event_id
                    )
                    opportunity_reused = True
                    cross_source_reuse = True
                    current_link_graph_created = False
                else:
                    graph = self.intake.ingest(
                        producer=f"source-lab:{self.policy.source_id}",
                        external_key=str(approved.record_row["external_key"]),
                        idempotency_key=intake_idempotency,
                        payload=approved.envelope,
                        evidence_ref=str(approved.observation_row["evidence_ref"]),
                        observed_at_utc=str(approved.observation_row["observed_at_utc"]),
                        company_name=approved.values["company_name"],
                        company_inn=approved.values["company_inn"],
                        company_domain=approved.values["company_domain"],
                        contact_name=approved.values["contact_name"],
                        contact_email=approved.values["contact_email"],
                        contact_phone=approved.values["contact_phone"],
                        contact_role=approved.values["contact_role"],
                        project_title=approved.values["project_title"],
                        project_region=approved.values["project_region"],
                        product_key=approved.values["product_key"],
                        _transaction=con,
                    )
                    opportunity_reused = not graph.created
                    if not graph.created:
                        raise SourceCommercialConflict(
                            "commercial graph has no trusted creator anchor"
                        )
                    current_link_graph_created = True
                    creator_resolution_event_id = approval_request.resolution_event_id

                if opportunity_reused:
                    crm_binding = self._binding_for_anchored_request(
                        creators[0].proof.request
                    )
                if cross_source_reuse:
                    prior_payloads = self._crm_payloads(
                        con,
                        graph,
                        crm_binding,
                        creator_resolution_event_id,
                    )
                    if self._existing_crm_stage(
                        con,
                        graph,
                        prior_payloads,
                        expected_external_event_id=creator_resolution_event_id,
                        binding=crm_binding,
                    ) is None:
                        raise SourceCommercialConflict(
                            "reused opportunity has no complete original CRM graph"
                        )

                link = self.source_lab.link_opportunity_evidence(
                    lf_opportunity_id=graph.lf_opportunity_id,
                    source_record_id=command.source_record_id,
                    evidence_ref=str(approved.resolution_row["evidence_ref"]),
                    actor=_BRIDGE_ACTOR,
                    idempotency_key=link_idempotency,
                    link_reason="APPROVED_SOURCE_IMPORT",
                    _transaction=con,
                )
                if direct and str(direct["evidence_link_id"]) != link.evidence_link_id:
                    raise SourceCommercialConflict("source evidence link identity changed")
                link_row = self._link_row(con, link.evidence_link_id)
                if link.created:
                    self._append_bridge_anchor(
                        con,
                        link_row,
                        graph,
                        approval_proof,
                        graph_created=current_link_graph_created,
                        creator_resolution_event_id=creator_resolution_event_id,
                    )
                verified_current = self._validate_anchored_link(
                    con,
                    link_row,
                    required=True,
                    expected_proof=approval_proof,
                )
                if not link.created and verified_current != direct_anchor:
                    raise SourceCommercialConflict(
                        "direct evidence anchor changed"
                    )
                if self.before_graph_commit:
                    self.before_graph_commit(graph, link)
                validate_source_lab_integrity(con)
                resolution_event_id = creator_resolution_event_id
        except (SourceCommercialBridgeError, SourceLabIntegrityError):
            raise
        except (CommercialSpineError, SourceLabError, IdempotencyConflict):
            raise SourceCommercialConflict("commercial graph transaction was rejected") from None

        # The graph/link commit is deliberately recoverable, but approval must
        # still be current at the exact CRM staging boundary.  Test/runtime
        # hooks run before the final lock.  One BEGIN IMMEDIATE then reloads the
        # approval and anchor and either reads an existing exact CRM graph or
        # appends all four commands through the caller-owned transaction seam.
        if self.before_crm_stage:
            self.before_crm_stage()
        try:
            with self.store.transaction(min_schema_version=16) as con:
                if not self._writers_are_off(con):
                    raise SourceCommercialStageError(
                        "external writers must remain disabled for CRM staging"
                    )
                validate_source_lab_integrity(con)
                final_approved = self._load_approved_import(con, command)
                final_request = self._current_approval_request(final_approved)
                if final_request != preflight_request:
                    raise SourceCommercialConflict(
                        "approved command changed before CRM staging"
                    )
                final_receipt = _validate_approval_receipt(
                    preflight_receipt, final_request
                )
                final_proof = self._current_approval_proof(
                    con, final_approved, final_request, final_receipt
                )
                if final_proof != preflight_proof:
                    raise SourceCommercialConflict(
                        "approved command changed before CRM staging"
                    )

                final_direct = self._direct_link(con, command.source_record_id)
                if (
                    not final_direct
                    or str(final_direct["evidence_link_id"])
                    != link.evidence_link_id
                ):
                    raise SourceCommercialConflict(
                        "approved evidence link changed before CRM staging"
                    )
                final_anchor = self._validate_anchored_link(
                    con,
                    final_direct,
                    required=True,
                    expected_proof=final_proof,
                )
                if final_anchor != verified_current:
                    raise SourceCommercialConflict(
                        "approved evidence anchor changed before CRM staging"
                    )
                final_graph = self._load_graph(
                    con, str(final_direct["lf_opportunity_id"])
                )
                if (
                    final_graph.lf_company_id != graph.lf_company_id
                    or final_graph.lf_contact_id != graph.lf_contact_id
                    or final_graph.lf_project_id != graph.lf_project_id
                    or final_graph.lf_opportunity_id != graph.lf_opportunity_id
                ):
                    raise SourceCommercialConflict(
                        "commercial graph changed before CRM staging"
                    )
                self._assert_company_match(
                    con,
                    final_graph,
                    final_approved.values,
                    cross_record_reuse=False,
                )
                payloads = self._crm_payloads(
                    con,
                    final_graph,
                    crm_binding,
                    resolution_event_id,
                )
                existing_crm_stage = self._existing_crm_stage(
                    con,
                    final_graph,
                    payloads,
                    expected_external_event_id=resolution_event_id,
                    binding=crm_binding,
                )
                if existing_crm_stage is not None:
                    crm_stage = existing_crm_stage
                elif cross_source_reuse or not current_link_graph_created:
                    raise SourceCommercialStageError(
                        "reused opportunity has no complete original CRM graph"
                    )
                else:
                    crm_stage = self.crm_outbox.stage_graph(
                        company_id=final_graph.lf_company_id,
                        contact_id=final_graph.lf_contact_id,
                        project_id=final_graph.lf_project_id,
                        opportunity_id=final_graph.lf_opportunity_id,
                        external_event_id=resolution_event_id,
                        company_payload=payloads["company"],
                        contact_payload=payloads["contact"],
                        deal_payload=payloads["deal"],
                        activity_payload=payloads["activity"],
                        mapping_manifest_hash=self._mapping_manifest_hash,
                        lf_source_id=self.policy.bitrix_graph_binding.lf_source_id,
                        _transaction=con,
                    )
        except (SourceCommercialBridgeError, SourceLabIntegrityError):
            raise
        except (
            GraphInvariantError,
            IdempotencyConflict,
            ValueError,
            KeyError,
            TypeError,
        ):
            raise SourceCommercialStageError("CRM graph staging was rejected") from None
        return SourceCommercialBridgeResult(
            graph.created,
            opportunity_reused,
            command.source_record_id,
            command.observation_id,
            command.review_id,
            command.latest_resolution_id,
            graph.lf_company_id,
            graph.lf_contact_id,
            graph.lf_project_id,
            graph.lf_opportunity_id,
            link.evidence_link_id,
            link.created,
            crm_stage,
        )


__all__ = [
    "ApprovedSourceCommand",
    "CommercialFieldBindings",
    "SourceCommercialBridge",
    "SourceCommercialBridgeError",
    "SourceCommercialBridgeResult",
    "SourceCommercialConflict",
    "SourceCommercialPolicy",
    "SourceCommercialStageError",
    "SourceCommercialValidationError",
    "TRUSTED_APPROVAL_CAPABILITY_VERSION",
    "TRUSTED_APPROVAL_RECEIPT_VERSION",
    "TrustedApprovalAuthority",
    "TrustedApprovalReceipt",
    "TrustedApprovalRequest",
]
