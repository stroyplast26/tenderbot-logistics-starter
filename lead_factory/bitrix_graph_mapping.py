"""Pure, fail-closed Bitrix mapping for the four-operation CRM graph.

This module compiles an already sealed :class:`CrmGraphCreateRequest` into a
provider-shaped command.  It has no database, HTTP, environment, credential,
worker, or CLI integration.  The mapping remains ``DRAFT_OFFLINE`` until a
separate live preflight and graph canary are approved.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
import json
import math
import re
import unicodedata
from typing import Any

from .crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphCreateRequest,
    CrmGraphOutbox,
    CrmGraphReadback,
    SafeReconciliationUnsupported,
)
from .crm_outbox import MappingConflict
from .ids import canonical_json, payload_hash


GRAPH_MAPPING_MANIFEST_VERSION = "bitrix-graph-mapping-manifest-v1"
GRAPH_INPUT_CONTRACT_VERSION = "crm-graph-bridge-v1"
GRAPH_ACTIVITY_MARKER_VERSION = "deal-todo-marker-v1"
GRAPH_CONTRACT_VERSION = "5.2"
GRAPH_MAPPING_LIFECYCLE = "DRAFT_OFFLINE"
GRAPH_MAPPING_EVIDENCE_MODE = "OFFLINE_FIXTURE"

_OPERATION_ORDER = (COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE)
_REMOTE_TYPE = {
    COMPANY_CREATE: "company",
    CONTACT_CREATE: "contact",
    DEAL_CREATE: "deal",
    ACTIVITY_CREATE: "activity",
}
_LOCAL_TYPE = {
    COMPANY_CREATE: "company",
    CONTACT_CREATE: "contact",
    DEAL_CREATE: "opportunity",
    ACTIVITY_CREATE: "opportunity",
}
_CREATE_METHOD = {
    COMPANY_CREATE: "crm.company.add",
    CONTACT_CREATE: "crm.contact.add",
    DEAL_CREATE: "crm.deal.add",
    ACTIVITY_CREATE: "crm.activity.todo.add",
}
_GET_METHOD = {
    COMPANY_CREATE: "crm.company.get",
    CONTACT_CREATE: "crm.contact.get",
    DEAL_CREATE: "crm.deal.get",
    ACTIVITY_CREATE: "crm.activity.get",
}
_LIST_METHOD = {
    "company": "crm.company.list",
    "contact": "crm.contact.list",
    "deal": "crm.deal.list",
}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PORTAL = re.compile(r"^bitrix-host-v1:[0-9a-f]{64}$")
_CORRELATION = re.compile(r"^lf_graph_v1_[0-9a-f]{40}$")
_REMOTE_ID = re.compile(r"^[1-9][0-9]*$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PAYLOAD_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")
_REMOTE_FIELD = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")
_CUSTOM_FIELD = re.compile(r"^UF_CRM_[A-Z0-9_]{1,88}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ACTIVITY_MARKER_PREFIX = "LF_GRAPH_V1|"
_MAX_COMMAND_BYTES = 128 * 1024

_ALLOWED_INPUT = {
    "company": frozenset({"TITLE", "UF_CRM_LF_COMPANY_ID", "UF_CRM_LF_INN"}),
    "contact": frozenset(
        {"NAME", "EMAIL", "PHONE", "POST", "UF_CRM_LF_CONTACT_ID"}
    ),
    "deal": frozenset(
        {
            "TITLE",
            "UF_CRM_LF_OPPORTUNITY_ID",
            "UF_CRM_LF_PROJECT_ID",
            "UF_CRM_LF_PRODUCT_KEY",
            "UF_CRM_LF_SOURCE_EVENT_ID",
            "UF_CRM_LF_SOURCE_ID",
            "UF_CRM_LF_SOURCE_RECORD_ID",
            "UF_CRM_LF_SUBMISSION_ID",
            "UF_CRM_LF_CORRELATION_ID",
            "UF_CRM_LF_ATTRIBUTION",
            "UF_CRM_LF_SITE_POLICY_ID",
            "UF_CRM_LF_SITE_POLICY_VERSION",
            "UF_CRM_LF_SITE_POLICY_HASH",
            "UF_CRM_LF_LANDING_URL",
            "UF_CRM_LF_LANDING_VERSION",
            "UF_CRM_LF_OFFER_VERSION",
            "UF_CRM_LF_FORM_ID",
            "UF_CRM_LF_FORM_VERSION",
            "UF_CRM_LF_ORIGINAL_UTM_SOURCE",
            "UF_CRM_LF_ORIGINAL_UTM_MEDIUM",
            "UF_CRM_LF_ORIGINAL_UTM_CAMPAIGN",
            "UF_CRM_LF_ORIGINAL_UTM_CONTENT",
            "UF_CRM_LF_ORIGINAL_UTM_TERM",
            "UF_CRM_LF_LATEST_UTM_SOURCE",
            "UF_CRM_LF_LATEST_UTM_MEDIUM",
            "UF_CRM_LF_LATEST_UTM_CAMPAIGN",
            "UF_CRM_LF_LATEST_UTM_CONTENT",
            "UF_CRM_LF_LATEST_UTM_TERM",
            "UF_CRM_LF_YCLID",
            "UF_CRM_LF_AD_CLICK_ID",
            "UF_CRM_LF_CONSENT_VERSION",
            "UF_CRM_LF_CONSENT_HASH",
            "UF_CRM_LF_IDENTITY_POLICY_VERSION",
        }
    ),
    "activity": frozenset(
        {"SUBJECT", "DESCRIPTION", "DEADLINE", "UF_CRM_LF_OPPORTUNITY_ID"}
    ),
}
_REQUIRED_BINDINGS = frozenset(
    {
        ("company", "TITLE"),
        ("company", "UF_CRM_LF_COMPANY_ID"),
        ("contact", "NAME"),
        ("contact", "EMAIL"),
        ("contact", "PHONE"),
        ("contact", "UF_CRM_LF_CONTACT_ID"),
        ("deal", "TITLE"),
        ("deal", "UF_CRM_LF_OPPORTUNITY_ID"),
        ("deal", "UF_CRM_LF_PROJECT_ID"),
        ("deal", "UF_CRM_LF_PRODUCT_KEY"),
        ("deal", "UF_CRM_LF_SOURCE_EVENT_ID"),
        ("deal", "UF_CRM_LF_SOURCE_ID"),
        ("activity", "SUBJECT"),
        ("activity", "DEADLINE"),
    }
)
_FIXED_STANDARD_BINDINGS = {
    ("company", "TITLE"): "TITLE",
    ("contact", "NAME"): "NAME",
    ("contact", "EMAIL"): "EMAIL",
    ("contact", "PHONE"): "PHONE",
    ("contact", "POST"): "POST",
    ("deal", "TITLE"): "TITLE",
    ("activity", "SUBJECT"): "title",
    ("activity", "DESCRIPTION"): "description",
    ("activity", "DEADLINE"): "deadline",
}
_RELATIONSHIP_KEYS = frozenset(
    {
        "COMPANY_ID",
        "COMPANY_IDS",
        "CONTACT_ID",
        "CONTACT_IDS",
        "CONTACTS",
        "OWNER",
        "OWNER_ID",
        "OWNER_TYPE",
        "OWNER_TYPE_ID",
        "DEAL_ID",
        "BINDINGS",
        "ownerId",
        "ownerTypeId",
    }
)


class BitrixGraphMappingError(ValueError):
    """A local manifest or command is not exact enough to compile."""


class BitrixGraphManifestMismatch(BitrixGraphMappingError):
    """The sealed command and selected mapping manifest differ."""


class BitrixGraphProviderConflict(MappingConflict):
    """Remote readback does not prove the exact command identity."""


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphFieldBinding:
    entity_type: str
    payload_key: str
    remote_field: str

    def __repr__(self) -> str:
        return "<BitrixGraphFieldBinding redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphCorrelationField:
    entity_type: str
    remote_field: str

    def __repr__(self) -> str:
        return "<BitrixGraphCorrelationField redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphSourceBinding:
    lf_source_id: str
    bitrix_source_id: str

    def __repr__(self) -> str:
        return "<BitrixGraphSourceBinding redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphRoute:
    deal_category_id: str
    deal_stage_id: str
    deal_assigned_by_id: str
    activity_responsible_id: str
    activity_ping_offsets: tuple[int, ...] = ()
    activity_color_id: str = ""

    def __repr__(self) -> str:
        return "<BitrixGraphRoute redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphMappingManifest:
    manifest_version: str
    mapping_id: str
    mapping_version: str
    contract_version: str
    input_contract_version: str
    lifecycle: str
    evidence_mode: str
    portal_identity: str
    field_bindings: tuple[BitrixGraphFieldBinding, ...]
    correlation_fields: tuple[BitrixGraphCorrelationField, ...]
    source_bindings: tuple[BitrixGraphSourceBinding, ...]
    route: BitrixGraphRoute
    activity_marker_version: str
    declared_manifest_hash: str = ""

    def __repr__(self) -> str:
        return "<BitrixGraphMappingManifest redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphBridgeBinding:
    """Sealed graph facts required before a commercial bridge may stage.

    The full manifest, rather than a caller-supplied digest alone, is retained
    here so the source binding is checked against the exact approved mapping.
    ``activity_deadline_utc`` is an already-approved immutable fact: retries
    must replay it, never derive a new deadline from wall-clock time.
    """

    manifest: BitrixGraphMappingManifest
    lf_source_id: str
    activity_deadline_utc: str

    def __repr__(self) -> str:
        return "<BitrixGraphBridgeBinding redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphReadbackExpectation:
    remote_entity_type: str
    get_method: str
    correlation_field: str
    correlation_token: str
    company_remote_id: str = ""
    contact_remote_id: str = ""
    deal_remote_id: str = ""
    activity_marker: str = ""
    owned_fields_json: str = ""
    owned_fields_hash: str = ""

    def __repr__(self) -> str:
        return "<BitrixGraphReadbackExpectation redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphMappedCreate:
    operation_id: str
    operation_type: str
    remote_entity_type: str
    create_method: str
    payload_json: str
    payload_hash: str
    mapping_manifest_hash: str
    expectation: BitrixGraphReadbackExpectation
    plan_hash: str

    def __repr__(self) -> str:
        return "<BitrixGraphMappedCreate redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphMappedLookup:
    operation_id: str
    operation_type: str
    lf_identity_id: str
    remote_entity_type: str
    list_method: str
    get_method: str
    payload_json: str
    payload_hash: str
    mapping_manifest_hash: str
    expectation: BitrixGraphReadbackExpectation
    source_create_plan: BitrixGraphMappedCreate
    source_create_plan_hash: str
    plan_hash: str

    def __repr__(self) -> str:
        return "<BitrixGraphMappedLookup redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphLookupCandidate:
    remote_entity_type: str
    remote_id: str
    get_method: str
    get_payload_json: str
    mapping_manifest_hash: str

    def __repr__(self) -> str:
        return "<BitrixGraphLookupCandidate redacted>"


def _required_text(value: object, message: str, *, maximum: int = 512) -> str:
    if type(value) is not str or value != value.strip() or not value:
        raise BitrixGraphMappingError(message)
    if len(value) > maximum or _CONTROL.search(value):
        raise BitrixGraphMappingError(message)
    return value


def _safe_id(value: object, message: str) -> str:
    result = _required_text(value, message)
    if not result.isascii() or not _SAFE_ID.fullmatch(result):
        raise BitrixGraphMappingError(message)
    return result


def _safe_token(value: object, message: str) -> str:
    result = _required_text(value, message, maximum=128)
    if not result.isascii() or not _SAFE_TOKEN.fullmatch(result):
        raise BitrixGraphMappingError(message)
    return result


def _positive_ascii_id(value: object, message: str) -> str:
    if type(value) is not str or not _REMOTE_ID.fullmatch(value):
        raise BitrixGraphMappingError(message)
    return value


def _strict_json(value: object) -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float:
        if math.isfinite(value):
            return
        raise BitrixGraphMappingError("graph mapping command is invalid")
    if type(value) is list:
        for child in value:
            _strict_json(child)
        return
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise BitrixGraphMappingError("graph mapping command is invalid")
            _strict_json(child)
        return
    raise BitrixGraphMappingError("graph mapping command is invalid")


def _load_canonical_object(raw: object, message: str) -> dict[str, Any]:
    if type(raw) is not str or not raw or len(raw.encode("utf-8")) > _MAX_COMMAND_BYTES:
        raise BitrixGraphMappingError(message)

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON")

    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            raw,
            parse_constant=reject_constant,
            object_pairs_hook=exact_object,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise BitrixGraphMappingError(message) from None
    if type(parsed) is not dict:
        raise BitrixGraphMappingError(message)
    _strict_json(parsed)
    if canonical_json(parsed) != raw:
        raise BitrixGraphMappingError(message)
    return parsed


def _expectation_body(expectation: BitrixGraphReadbackExpectation) -> dict[str, str]:
    if type(expectation) is not BitrixGraphReadbackExpectation:
        raise BitrixGraphMappingError("graph mapped plan is invalid")
    values = {
        "remote_entity_type": expectation.remote_entity_type,
        "get_method": expectation.get_method,
        "correlation_field": expectation.correlation_field,
        "correlation_token": expectation.correlation_token,
        "company_remote_id": expectation.company_remote_id,
        "contact_remote_id": expectation.contact_remote_id,
        "deal_remote_id": expectation.deal_remote_id,
        "activity_marker": expectation.activity_marker,
        "owned_fields_json": expectation.owned_fields_json,
        "owned_fields_hash": expectation.owned_fields_hash,
    }
    if any(type(value) is not str for value in values.values()):
        raise BitrixGraphMappingError("graph mapped plan is invalid")
    return values


def _create_plan_body(plan: BitrixGraphMappedCreate) -> dict[str, Any]:
    return {
        "operation_id": plan.operation_id,
        "operation_type": plan.operation_type,
        "remote_entity_type": plan.remote_entity_type,
        "create_method": plan.create_method,
        "payload_json": plan.payload_json,
        "payload_hash": plan.payload_hash,
        "mapping_manifest_hash": plan.mapping_manifest_hash,
        "expectation": _expectation_body(plan.expectation),
    }


def _lookup_plan_body(plan: BitrixGraphMappedLookup) -> dict[str, Any]:
    return {
        "operation_id": plan.operation_id,
        "operation_type": plan.operation_type,
        "lf_identity_id": plan.lf_identity_id,
        "remote_entity_type": plan.remote_entity_type,
        "list_method": plan.list_method,
        "get_method": plan.get_method,
        "payload_json": plan.payload_json,
        "payload_hash": plan.payload_hash,
        "mapping_manifest_hash": plan.mapping_manifest_hash,
        "expectation": _expectation_body(plan.expectation),
        "source_create_plan_hash": plan.source_create_plan_hash,
    }


def _manifest_body(manifest: BitrixGraphMappingManifest) -> dict[str, Any]:
    if type(manifest) is not BitrixGraphMappingManifest:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    if (
        type(manifest.manifest_version) is not str
        or type(manifest.contract_version) is not str
        or type(manifest.input_contract_version) is not str
        or type(manifest.lifecycle) is not str
        or type(manifest.evidence_mode) is not str
        or type(manifest.activity_marker_version) is not str
        or manifest.manifest_version != GRAPH_MAPPING_MANIFEST_VERSION
        or manifest.contract_version != GRAPH_CONTRACT_VERSION
        or manifest.input_contract_version != GRAPH_INPUT_CONTRACT_VERSION
        or manifest.lifecycle != GRAPH_MAPPING_LIFECYCLE
        or manifest.evidence_mode != GRAPH_MAPPING_EVIDENCE_MODE
        or manifest.activity_marker_version != GRAPH_ACTIVITY_MARKER_VERSION
    ):
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    mapping_id = _safe_id(manifest.mapping_id, "graph mapping manifest is invalid")
    mapping_version = _safe_token(
        manifest.mapping_version, "graph mapping manifest is invalid"
    )
    portal = _required_text(
        manifest.portal_identity, "graph mapping manifest is invalid", maximum=96
    )
    if not _PORTAL.fullmatch(portal):
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    if type(manifest.field_bindings) is not tuple:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    bindings: list[dict[str, str]] = []
    binding_keys: list[tuple[str, str]] = []
    remote_keys: set[tuple[str, str]] = set()
    for binding in manifest.field_bindings:
        if type(binding) is not BitrixGraphFieldBinding:
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        entity = binding.entity_type
        key = binding.payload_key
        remote = binding.remote_field
        if (
            type(entity) is not str
            or entity not in _ALLOWED_INPUT
            or type(key) is not str
            or not key.isascii()
            or not _PAYLOAD_KEY.fullmatch(key)
            or key not in _ALLOWED_INPUT[entity]
            or type(remote) is not str
            or not remote
            or remote != remote.strip()
            or not remote.isascii()
            or (
                entity == "activity"
                and key == "UF_CRM_LF_OPPORTUNITY_ID"
            )
        ):
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        fixed = _FIXED_STANDARD_BINDINGS.get((entity, key))
        if fixed is not None:
            if remote != fixed:
                raise BitrixGraphMappingError("graph mapping manifest is invalid")
        elif not _CUSTOM_FIELD.fullmatch(remote):
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        if remote in _RELATIONSHIP_KEYS:
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        binding_key = (entity, key)
        remote_key = (entity, remote.casefold())
        if binding_key in binding_keys or remote_key in remote_keys:
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        binding_keys.append(binding_key)
        remote_keys.add(remote_key)
        bindings.append(
            {"entity_type": entity, "payload_key": key, "remote_field": remote}
        )
    if binding_keys != sorted(binding_keys) or not _REQUIRED_BINDINGS.issubset(
        binding_keys
    ):
        raise BitrixGraphMappingError("graph mapping manifest is invalid")

    if type(manifest.correlation_fields) is not tuple:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    correlations: list[dict[str, str]] = []
    correlation_entities: list[str] = []
    for field in manifest.correlation_fields:
        if type(field) is not BitrixGraphCorrelationField:
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        if (
            type(field.entity_type) is not str
            or field.entity_type not in {"company", "contact", "deal"}
            or type(field.remote_field) is not str
            or not field.remote_field.isascii()
            or not _CUSTOM_FIELD.fullmatch(field.remote_field)
            or (field.entity_type, field.remote_field.casefold()) in remote_keys
        ):
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        correlation_entities.append(field.entity_type)
        correlations.append(
            {
                "entity_type": field.entity_type,
                "remote_field": field.remote_field,
            }
        )
    if correlation_entities != ["company", "contact", "deal"]:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")

    if type(manifest.source_bindings) is not tuple or not manifest.source_bindings:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    sources: list[dict[str, str]] = []
    source_ids: list[str] = []
    for binding in manifest.source_bindings:
        if type(binding) is not BitrixGraphSourceBinding:
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        lf_source = _safe_id(
            binding.lf_source_id, "graph mapping manifest is invalid"
        )
        bitrix_source = _safe_token(
            binding.bitrix_source_id, "graph mapping manifest is invalid"
        )
        if lf_source in source_ids:
            raise BitrixGraphMappingError("graph mapping manifest is invalid")
        source_ids.append(lf_source)
        sources.append(
            {"lf_source_id": lf_source, "bitrix_source_id": bitrix_source}
        )
    if source_ids != sorted(source_ids):
        raise BitrixGraphMappingError("graph mapping manifest is invalid")

    route = manifest.route
    if type(route) is not BitrixGraphRoute:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    category = _positive_ascii_id(
        route.deal_category_id, "graph mapping manifest is invalid"
    )
    stage = _safe_token(route.deal_stage_id, "graph mapping manifest is invalid")
    assigned = _positive_ascii_id(
        route.deal_assigned_by_id, "graph mapping manifest is invalid"
    )
    responsible = _positive_ascii_id(
        route.activity_responsible_id, "graph mapping manifest is invalid"
    )
    offsets = route.activity_ping_offsets
    if (
        type(offsets) is not tuple
        or any(type(item) is not int or item < 0 or item > 525600 for item in offsets)
        or tuple(sorted(set(offsets))) != offsets
    ):
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    color = route.activity_color_id
    if type(color) is not str or color not in {"", "1", "2", "3", "4", "5", "6", "7"}:
        raise BitrixGraphMappingError("graph mapping manifest is invalid")
    return {
        "manifest_version": manifest.manifest_version,
        "mapping_id": mapping_id,
        "mapping_version": mapping_version,
        "contract_version": manifest.contract_version,
        "input_contract_version": manifest.input_contract_version,
        "lifecycle": manifest.lifecycle,
        "evidence_mode": manifest.evidence_mode,
        "portal_identity": portal,
        "field_bindings": bindings,
        "correlation_fields": correlations,
        "source_bindings": sources,
        "route": {
            "deal_category_id": category,
            "deal_stage_id": stage,
            "deal_assigned_by_id": assigned,
            "activity_responsible_id": responsible,
            "activity_ping_offsets": list(offsets),
            "activity_color_id": color,
        },
        "activity_marker_version": manifest.activity_marker_version,
    }


def graph_mapping_manifest_hash(manifest: BitrixGraphMappingManifest) -> str:
    """Return the exact hash excluding only ``declared_manifest_hash``."""

    return payload_hash(_manifest_body(manifest))


def graph_manifest_custom_fields(
    manifest: BitrixGraphMappingManifest,
) -> tuple[tuple[str, str, bool], ...]:
    """Derive the exact provider UF schema from one sealed mapping manifest.

    The remote code may intentionally differ from the local payload key, so a
    live schema plan must never infer identity mapping.  Activity's local
    opportunity marker is encoded in the immutable description payload and is
    therefore not a remotely provisioned Activity user field.
    """

    validate_graph_mapping_manifest(manifest)
    fields: dict[tuple[str, str], bool] = {}
    for binding in manifest.field_bindings:
        if (
            binding.entity_type in {"company", "contact", "deal"}
            and binding.remote_field.startswith("UF_CRM_")
        ):
            fields[(binding.entity_type, binding.remote_field)] = False
    for field in manifest.correlation_fields:
        fields[(field.entity_type, field.remote_field)] = True
    return tuple(
        (entity, remote_field, searchable)
        for (entity, remote_field), searchable in sorted(fields.items())
    )


def canonical_identity_graph_field_bindings() -> tuple[BitrixGraphFieldBinding, ...]:
    """Compile the explicit ``CANONICAL_IDENTITY_V1`` deployment mode."""

    bindings: list[BitrixGraphFieldBinding] = []
    for entity, keys in _ALLOWED_INPUT.items():
        for key in keys:
            if entity == "activity" and key == "UF_CRM_LF_OPPORTUNITY_ID":
                continue
            bindings.append(
                BitrixGraphFieldBinding(
                    entity_type=entity,
                    payload_key=key,
                    remote_field=_FIXED_STANDARD_BINDINGS.get((entity, key), key),
                )
            )
    return tuple(sorted(bindings, key=lambda item: (item.entity_type, item.payload_key)))


def validate_graph_mapping_manifest(manifest: BitrixGraphMappingManifest) -> str:
    digest = graph_mapping_manifest_hash(manifest)
    if (
        type(manifest.declared_manifest_hash) is not str
        or not _HEX64.fullmatch(manifest.declared_manifest_hash)
        or manifest.declared_manifest_hash != digest
    ):
        raise BitrixGraphManifestMismatch("graph mapping manifest hash is invalid")
    return digest


def validate_graph_bridge_binding(binding: BitrixGraphBridgeBinding) -> str:
    """Return the manifest hash only for an exact source/deadline binding."""

    if type(binding) is not BitrixGraphBridgeBinding:
        raise BitrixGraphMappingError("graph bridge binding is invalid")
    manifest_hash = validate_graph_mapping_manifest(binding.manifest)
    source_id = _safe_id(binding.lf_source_id, "graph bridge binding is invalid")
    if source_id not in {item.lf_source_id for item in binding.manifest.source_bindings}:
        raise BitrixGraphMappingError("graph bridge source is not mapped")
    deadline = binding.activity_deadline_utc
    if type(deadline) is not str or not _UTC_SECONDS.fullmatch(deadline):
        raise BitrixGraphMappingError("graph Activity deadline is invalid")
    try:
        datetime.fromisoformat(deadline.replace("Z", "+00:00"))
    except ValueError:
        raise BitrixGraphMappingError("graph Activity deadline is invalid") from None
    return manifest_hash


class BitrixGraphMapper:
    """Compile sealed graph commands without performing provider calls."""

    def __init__(self, manifest: BitrixGraphMappingManifest):
        self.manifest = manifest
        self.manifest_hash = validate_graph_mapping_manifest(manifest)
        self._bindings = {
            (item.entity_type, item.payload_key): item.remote_field
            for item in manifest.field_bindings
        }
        self._correlations = {
            item.entity_type: item.remote_field for item in manifest.correlation_fields
        }
        self._sources = {
            item.lf_source_id: item.bitrix_source_id
            for item in manifest.source_bindings
        }

    def __repr__(self) -> str:
        return "<BitrixGraphMapper redacted>"

    def validate_create_plan(self, plan: BitrixGraphMappedCreate) -> str:
        """Validate one sealed mapped create without performing provider I/O."""

        self._validate_create_plan(plan)
        return plan.plan_hash

    def _validate_create_plan(
        self, plan: BitrixGraphMappedCreate
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        if type(plan) is not BitrixGraphMappedCreate:
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        scalar_values = (
            plan.operation_id,
            plan.operation_type,
            plan.remote_entity_type,
            plan.create_method,
            plan.payload_json,
            plan.payload_hash,
            plan.mapping_manifest_hash,
            plan.plan_hash,
        )
        if any(type(value) is not str for value in scalar_values):
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        if (
            plan.operation_type not in _OPERATION_ORDER
            or not _SAFE_ID.fullmatch(plan.operation_id)
            or plan.remote_entity_type != _REMOTE_TYPE[plan.operation_type]
            or plan.create_method != _CREATE_METHOD[plan.operation_type]
            or plan.mapping_manifest_hash != self.manifest_hash
            or not _HEX64.fullmatch(plan.payload_hash)
            or not _HEX64.fullmatch(plan.plan_hash)
            or payload_hash(_create_plan_body(plan)) != plan.plan_hash
        ):
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        provider = _load_canonical_object(
            plan.payload_json, "graph mapped plan is invalid"
        )
        if payload_hash(provider) != plan.payload_hash:
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        expectation = plan.expectation
        body = _expectation_body(expectation)
        entity = plan.remote_entity_type
        if (
            expectation.remote_entity_type != entity
            or expectation.get_method != _GET_METHOD[plan.operation_type]
            or not _CORRELATION.fullmatch(expectation.correlation_token)
            or type(expectation.owned_fields_json) is not str
            or type(expectation.owned_fields_hash) is not str
            or not _HEX64.fullmatch(expectation.owned_fields_hash)
        ):
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        owned = _load_canonical_object(
            expectation.owned_fields_json, "graph mapped plan is invalid"
        )
        if payload_hash(owned) != expectation.owned_fields_hash:
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        actual_parents = {
            "company": (),
            "contact": (expectation.company_remote_id,),
            "deal": (
                expectation.company_remote_id,
                expectation.contact_remote_id,
            ),
            "activity": (
                expectation.company_remote_id,
                expectation.contact_remote_id,
                expectation.deal_remote_id,
            ),
        }[entity]
        unused_parents = {
            "company": (
                expectation.company_remote_id,
                expectation.contact_remote_id,
                expectation.deal_remote_id,
            ),
            "contact": (
                expectation.contact_remote_id,
                expectation.deal_remote_id,
            ),
            "deal": (expectation.deal_remote_id,),
            "activity": (),
        }[entity]
        if any(not _REMOTE_ID.fullmatch(value) for value in actual_parents) or any(
            unused_parents
        ):
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        if entity == "activity":
            marker_match = re.fullmatch(
                r"LF_GRAPH_V1\|opportunity=([A-Za-z0-9][A-Za-z0-9_.:/-]{0,511})"
                r"\|correlation=(lf_graph_v1_[0-9a-f]{40})",
                expectation.activity_marker,
            )
            route = self.manifest.route
            expected_provider = {
                "title": owned.get("SUBJECT"),
                "description": owned.get("DESCRIPTION"),
                "deadline": owned.get("DEADLINE"),
                "ownerTypeId": 2,
                "ownerId": int(expectation.deal_remote_id),
                "responsibleId": int(route.activity_responsible_id),
            }
            expected_owned_keys = {
                "SUBJECT",
                "DESCRIPTION",
                "DEADLINE",
                "RESPONSIBLE_ID",
            }
            if route.activity_ping_offsets:
                expected_provider["pingOffsets"] = list(route.activity_ping_offsets)
                expected_owned_keys.add("PING_OFFSETS")
            if route.activity_color_id:
                expected_provider["colorId"] = route.activity_color_id
                expected_owned_keys.add("COLOR_ID")
            if (
                expectation.correlation_field
                or marker_match is None
                or marker_match.group(2) != expectation.correlation_token
                or provider != expected_provider
                or set(owned) != expected_owned_keys
                or owned.get("DESCRIPTION") != provider.get("description")
                or not str(owned.get("DESCRIPTION", "")).endswith(
                    expectation.activity_marker
                )
                or owned.get("RESPONSIBLE_ID") != route.activity_responsible_id
                or (
                    "PING_OFFSETS" in owned
                    and owned["PING_OFFSETS"] != list(route.activity_ping_offsets)
                )
                or (
                    "COLOR_ID" in owned
                    and owned["COLOR_ID"] != route.activity_color_id
                )
            ):
                raise BitrixGraphMappingError("graph mapped plan is invalid")
            identity_value = marker_match.group(1)
        else:
            expected_correlation = self._correlations.get(entity, "")
            fields = provider.get("fields")
            if (
                expectation.correlation_field != expected_correlation
                or expectation.activity_marker
                or type(fields) is not dict
                or provider.get("params") != {"REGISTER_SONET_EVENT": "N"}
                or set(provider) != {"fields", "params"}
                or fields.get(expected_correlation) != expectation.correlation_token
                or owned != fields
            ):
                raise BitrixGraphMappingError("graph mapped plan is invalid")
            identity_key = {
                "company": "UF_CRM_LF_COMPANY_ID",
                "contact": "UF_CRM_LF_CONTACT_ID",
                "deal": "UF_CRM_LF_OPPORTUNITY_ID",
            }[entity]
            identity_remote_field = self._bindings[(entity, identity_key)]
            identity_value = owned.get(identity_remote_field)
            if type(identity_value) is not str or not _SAFE_ID.fullmatch(
                identity_value
            ):
                raise BitrixGraphMappingError("graph mapped plan is invalid")
        _expected_key, expected_token = CrmGraphOutbox._derived_identity(
            plan.operation_type,
            _LOCAL_TYPE[plan.operation_type],
            identity_value,
        )
        if expected_token != expectation.correlation_token:
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        if body != _expectation_body(expectation):
            raise BitrixGraphMappingError("graph mapped plan is invalid")
        return provider, owned, identity_value

    def _validate_lookup_plan(self, plan: BitrixGraphMappedLookup) -> None:
        if type(plan) is not BitrixGraphMappedLookup:
            raise BitrixGraphMappingError("graph lookup plan is invalid")
        scalar_values = (
            plan.operation_id,
            plan.operation_type,
            plan.lf_identity_id,
            plan.remote_entity_type,
            plan.list_method,
            plan.get_method,
            plan.payload_json,
            plan.payload_hash,
            plan.mapping_manifest_hash,
            plan.source_create_plan_hash,
            plan.plan_hash,
        )
        if any(type(value) is not str for value in scalar_values):
            raise BitrixGraphMappingError("graph lookup plan is invalid")
        if type(plan.source_create_plan) is not BitrixGraphMappedCreate:
            raise BitrixGraphMappingError("graph lookup plan is invalid")
        _source_provider, _source_owned, source_identity = (
            self._validate_create_plan(plan.source_create_plan)
        )
        entity = plan.remote_entity_type
        expectation = plan.expectation
        if (
            plan.operation_type not in _OPERATION_ORDER
            or not _SAFE_ID.fullmatch(plan.operation_id)
            or entity not in _LIST_METHOD
            or entity != _REMOTE_TYPE[plan.operation_type]
            or type(plan.lf_identity_id) is not str
            or not _SAFE_ID.fullmatch(plan.lf_identity_id)
            or plan.list_method != _LIST_METHOD[entity]
            or plan.get_method != _GET_METHOD[plan.operation_type]
            or expectation.get_method != _GET_METHOD[plan.operation_type]
            or plan.mapping_manifest_hash != self.manifest_hash
            or not _HEX64.fullmatch(plan.source_create_plan_hash)
            or not _HEX64.fullmatch(plan.payload_hash)
            or not _HEX64.fullmatch(plan.plan_hash)
            or payload_hash(_lookup_plan_body(plan)) != plan.plan_hash
            or expectation.remote_entity_type != entity
            or expectation.correlation_field != self._correlations.get(entity, "")
            or not _CORRELATION.fullmatch(expectation.correlation_token)
            or plan.source_create_plan_hash != plan.source_create_plan.plan_hash
            or plan.source_create_plan.operation_id != plan.operation_id
            or plan.source_create_plan.operation_type != plan.operation_type
            or plan.source_create_plan.remote_entity_type != entity
            or plan.source_create_plan.expectation != expectation
            or source_identity != plan.lf_identity_id
        ):
            raise BitrixGraphMappingError("graph lookup plan is invalid")
        _expected_key, expected_token = CrmGraphOutbox._derived_identity(
            plan.operation_type,
            _LOCAL_TYPE[plan.operation_type],
            plan.lf_identity_id,
        )
        if expectation.correlation_token != expected_token:
            raise BitrixGraphMappingError("graph lookup plan is invalid")
        payload = _load_canonical_object(
            plan.payload_json, "graph lookup plan is invalid"
        )
        select = ["ID", expectation.correlation_field]
        if entity == "contact":
            select.append("COMPANY_ID")
        elif entity == "deal":
            select.extend(("COMPANY_ID", "CONTACT_ID", "CONTACT_IDS"))
        expected = {
            "filter": {
                f"={expectation.correlation_field}": expectation.correlation_token
            },
            "select": select,
            "start": 0,
        }
        if payload != expected or payload_hash(payload) != plan.payload_hash:
            raise BitrixGraphMappingError("graph lookup plan is invalid")

    @staticmethod
    def _request_body(request: CrmGraphCreateRequest) -> tuple[str, dict[str, str]]:
        if type(request) is not CrmGraphCreateRequest:
            raise BitrixGraphMappingError("graph create request is invalid")
        operation = request.operation_type
        if operation not in _OPERATION_ORDER:
            raise BitrixGraphMappingError("graph create request is invalid")
        entity = _REMOTE_TYPE[operation]
        local_type = _LOCAL_TYPE[operation]
        if (
            type(request.operation_id) is not str
            or type(request.operation_type) is not str
            or type(request.remote_entity_type) is not str
            or type(request.correlation_token) is not str
            or type(request.lf_entity_type) is not str
            or type(request.lf_entity_id) is not str
            or type(request.source_event_id) is not str
            or type(request.idempotency_key) is not str
            or type(request.command_payload_hash) is not str
            or type(request.mapping_manifest_hash) is not str
            or type(request.lf_source_id) is not str
            or request.remote_entity_type != entity
            or request.lf_entity_type != local_type
            or not _SAFE_ID.fullmatch(request.operation_id)
            or not _SAFE_ID.fullmatch(request.lf_entity_id)
            or not _SAFE_ID.fullmatch(request.source_event_id)
            or not _HEX64.fullmatch(request.command_payload_hash)
        ):
            raise BitrixGraphMappingError("graph create request is invalid")
        expected_key, expected_token = CrmGraphOutbox._derived_identity(
            operation, local_type, request.lf_entity_id
        )
        if (
            request.idempotency_key != expected_key
            or request.correlation_token != expected_token
            or not _CORRELATION.fullmatch(request.correlation_token)
        ):
            raise BitrixGraphMappingError("graph create request proof is invalid")
        if type(request.graph_identity_ids) is not tuple:
            raise BitrixGraphMappingError("graph create request proof is invalid")
        identities: dict[str, str] = {}
        for item in request.graph_identity_ids:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                or item[0] in identities
                or item[0] not in {"company", "contact", "project", "opportunity"}
                or not _SAFE_ID.fullmatch(item[1])
            ):
                raise BitrixGraphMappingError("graph create request proof is invalid")
            identities[item[0]] = item[1]
        expected_identity_keys = {
            COMPANY_CREATE: {"company"},
            CONTACT_CREATE: {"company", "contact"},
            DEAL_CREATE: {"company", "contact", "project", "opportunity"},
            ACTIVITY_CREATE: {"company", "contact", "project", "opportunity"},
        }[operation]
        if (
            set(identities) != expected_identity_keys
            or request.graph_identity_ids != tuple(sorted(identities.items()))
            or identities[local_type] != request.lf_entity_id
        ):
            raise BitrixGraphMappingError("graph create request proof is invalid")
        if entity in {"deal", "activity"}:
            lf_source_id = _safe_id(
                request.lf_source_id, "graph create request proof is invalid"
            )
        else:
            if request.lf_source_id:
                raise BitrixGraphMappingError("graph create request proof is invalid")
            lf_source_id = ""
        if type(request.payload) is not dict or not request.payload:
            raise BitrixGraphMappingError("graph create request payload is invalid")
        values: dict[str, str] = {}
        allowed = _ALLOWED_INPUT[entity]
        for key, value in request.payload.items():
            if (
                type(key) is not str
                or not key.isascii()
                or unicodedata.normalize("NFKC", key) != key
                or key not in allowed
                or type(value) is not str
                or value != value.strip()
                or not value
                or len(value) > 8192
                or _CONTROL.search(value)
            ):
                raise BitrixGraphMappingError("graph create request payload is invalid")
            values[key] = value
        _strict_json(request.payload)
        if len(canonical_json(request.payload).encode("utf-8")) > _MAX_COMMAND_BYTES:
            raise BitrixGraphMappingError("graph create request payload is invalid")
        if entity == "company":
            required = {"TITLE", "UF_CRM_LF_COMPANY_ID"}
            identity_key = "UF_CRM_LF_COMPANY_ID"
        elif entity == "contact":
            required = {"NAME", "UF_CRM_LF_CONTACT_ID"}
            if not ({"EMAIL", "PHONE"} & set(values)):
                raise BitrixGraphMappingError("graph contact channel is missing")
            identity_key = "UF_CRM_LF_CONTACT_ID"
        elif entity == "deal":
            required = {"TITLE", "UF_CRM_LF_PROJECT_ID", "UF_CRM_LF_PRODUCT_KEY"}
            identity_key = "UF_CRM_LF_OPPORTUNITY_ID"
            derived = {
                "UF_CRM_LF_OPPORTUNITY_ID": identities["opportunity"],
                "UF_CRM_LF_SOURCE_EVENT_ID": request.source_event_id,
                "UF_CRM_LF_SOURCE_ID": lf_source_id,
            }
            for key, value in derived.items():
                if key in values and values[key] != value:
                    raise BitrixGraphMappingError("graph create request proof is invalid")
                values[key] = value
            if values.get("UF_CRM_LF_PROJECT_ID") != identities["project"]:
                raise BitrixGraphMappingError("graph create request proof is invalid")
        else:
            required = {"SUBJECT", "DEADLINE", "UF_CRM_LF_OPPORTUNITY_ID"}
            identity_key = "UF_CRM_LF_OPPORTUNITY_ID"
            if values.get(identity_key) != identities["opportunity"]:
                raise BitrixGraphMappingError("graph create request proof is invalid")
            deadline = values["DEADLINE"]
            if not _UTC_SECONDS.fullmatch(deadline):
                raise BitrixGraphMappingError("graph Activity deadline is invalid")
            try:
                datetime.fromisoformat(deadline.replace("Z", "+00:00"))
            except ValueError:
                raise BitrixGraphMappingError(
                    "graph Activity deadline is invalid"
                ) from None
        if not required.issubset(values) or values[identity_key] != request.lf_entity_id:
            raise BitrixGraphMappingError("graph create request proof is invalid")
        sealed_metadata = {
            f"{identity_type}_id": identity_id
            for identity_type, identity_id in identities.items()
        }
        sealed_metadata["mapping_manifest_hash"] = request.mapping_manifest_hash
        if lf_source_id:
            sealed_metadata["lf_source_id"] = lf_source_id
        sealed_body: dict[str, Any] = dict(request.payload)
        sealed_body["_lf_correlation_token"] = request.correlation_token
        sealed_body["_lf_graph_v1"] = sealed_metadata
        if payload_hash(sealed_body) != request.command_payload_hash:
            raise BitrixGraphMappingError("graph create request seal is invalid")
        return entity, values

    def _dependencies(
        self, request: CrmGraphCreateRequest
    ) -> dict[str, str]:
        expected = {
            COMPANY_CREATE: (),
            CONTACT_CREATE: ("company",),
            DEAL_CREATE: ("company", "contact"),
            ACTIVITY_CREATE: ("company", "contact", "deal"),
        }[request.operation_type]
        if type(request.dependency_remote_ids) is not tuple:
            raise BitrixGraphMappingError("graph dependency proof is invalid")
        dependencies: dict[str, str] = {}
        for item in request.dependency_remote_ids:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or item[0] in dependencies
            ):
                raise BitrixGraphMappingError("graph dependency proof is invalid")
            dependencies[item[0]] = _positive_ascii_id(
                item[1], "graph dependency proof is invalid"
            )
        if tuple(dependencies) != expected:
            raise BitrixGraphMappingError("graph dependency proof is invalid")
        return dependencies

    def compile_create(self, request: CrmGraphCreateRequest) -> BitrixGraphMappedCreate:
        if request.mapping_manifest_hash != self.manifest_hash:
            raise BitrixGraphManifestMismatch("graph command mapping hash is invalid")
        entity, values = self._request_body(request)
        if entity == "activity" and request.lf_source_id not in self._sources:
            raise BitrixGraphMappingError("graph source mapping is missing")
        dependencies = self._dependencies(request)
        remote: dict[str, Any] = {}
        for key, value in values.items():
            if entity == "activity" and key == "UF_CRM_LF_OPPORTUNITY_ID":
                continue
            if (entity, key) not in self._bindings:
                raise BitrixGraphMappingError("graph payload field is not mapped")
            target = self._bindings[(entity, key)]
            if target in remote:
                raise BitrixGraphMappingError("graph payload mapping is ambiguous")
            if key in {"EMAIL", "PHONE"}:
                remote[target] = [{"VALUE": value, "VALUE_TYPE": "WORK"}]
            else:
                remote[target] = value
        route = self.manifest.route
        correlation_field = ""
        marker = ""
        if entity in {"company", "contact", "deal"}:
            correlation_field = self._correlations[entity]
            if correlation_field in remote:
                raise BitrixGraphMappingError("graph correlation mapping is ambiguous")
            remote[correlation_field] = request.correlation_token
        if entity == "contact":
            remote["COMPANY_ID"] = dependencies["company"]
        elif entity == "deal":
            source_id = self._sources.get(request.lf_source_id)
            if not source_id:
                raise BitrixGraphMappingError("graph source mapping is missing")
            remote.update(
                {
                    "COMPANY_ID": dependencies["company"],
                    "CONTACT_ID": dependencies["contact"],
                    "CATEGORY_ID": route.deal_category_id,
                    "STAGE_ID": route.deal_stage_id,
                    "ASSIGNED_BY_ID": route.deal_assigned_by_id,
                    "SOURCE_ID": source_id,
                }
            )
        elif entity == "activity":
            description = str(remote.get("description", ""))
            if _ACTIVITY_MARKER_PREFIX in description:
                raise BitrixGraphMappingError("graph Activity description is invalid")
            marker = (
                f"{_ACTIVITY_MARKER_PREFIX}opportunity={request.lf_entity_id}"
                f"|correlation={request.correlation_token}"
            )
            remote["description"] = f"{description}\n{marker}" if description else marker
            remote["ownerTypeId"] = 2
            remote["ownerId"] = int(dependencies["deal"])
            remote["responsibleId"] = int(route.activity_responsible_id)
            if route.activity_ping_offsets:
                remote["pingOffsets"] = list(route.activity_ping_offsets)
            if route.activity_color_id:
                remote["colorId"] = route.activity_color_id
        _strict_json(remote)
        if entity == "activity":
            provider_payload = remote
            owned_fields: dict[str, Any] = {
                "SUBJECT": remote["title"],
                "DESCRIPTION": remote["description"],
                "DEADLINE": remote["deadline"],
                "RESPONSIBLE_ID": str(remote["responsibleId"]),
            }
            if "pingOffsets" in remote:
                owned_fields["PING_OFFSETS"] = remote["pingOffsets"]
            if "colorId" in remote:
                owned_fields["COLOR_ID"] = remote["colorId"]
        else:
            provider_payload = {
                "fields": remote,
                "params": {"REGISTER_SONET_EVENT": "N"},
            }
            owned_fields = dict(remote)
        rendered = canonical_json(provider_payload)
        if len(rendered.encode("utf-8")) > _MAX_COMMAND_BYTES:
            raise BitrixGraphMappingError("graph mapped command is too large")
        owned_fields_json = canonical_json(owned_fields)
        expectation = BitrixGraphReadbackExpectation(
            remote_entity_type=entity,
            get_method=_GET_METHOD[request.operation_type],
            correlation_field=correlation_field,
            correlation_token=request.correlation_token,
            company_remote_id=dependencies.get("company", ""),
            contact_remote_id=dependencies.get("contact", ""),
            deal_remote_id=dependencies.get("deal", ""),
            activity_marker=marker,
            owned_fields_json=owned_fields_json,
            owned_fields_hash=payload_hash(owned_fields),
        )
        plan = BitrixGraphMappedCreate(
            operation_id=request.operation_id,
            operation_type=request.operation_type,
            remote_entity_type=entity,
            create_method=_CREATE_METHOD[request.operation_type],
            payload_json=rendered,
            payload_hash=payload_hash(provider_payload),
            mapping_manifest_hash=self.manifest_hash,
            expectation=expectation,
            plan_hash="",
        )
        return replace(plan, plan_hash=payload_hash(_create_plan_body(plan)))

    def compile_lookup(self, plan: BitrixGraphMappedCreate) -> BitrixGraphMappedLookup:
        _provider, _owned, identity_value = self._validate_create_plan(plan)
        expectation = plan.expectation
        entity = plan.remote_entity_type
        if entity == "activity":
            raise SafeReconciliationUnsupported(
                "Activity correlation lookup is not safely supported"
            )
        if entity not in _LIST_METHOD or not expectation.correlation_field:
            raise BitrixGraphMappingError("graph lookup plan is invalid")
        select = ["ID", expectation.correlation_field]
        if entity == "contact":
            select.append("COMPANY_ID")
        elif entity == "deal":
            select.extend(("COMPANY_ID", "CONTACT_ID", "CONTACT_IDS"))
        payload = {
            "filter": {f"={expectation.correlation_field}": expectation.correlation_token},
            "select": select,
            "start": 0,
        }
        rendered = canonical_json(payload)
        lookup = BitrixGraphMappedLookup(
            operation_id=plan.operation_id,
            operation_type=plan.operation_type,
            lf_identity_id=identity_value,
            remote_entity_type=entity,
            list_method=_LIST_METHOD[entity],
            get_method=expectation.get_method,
            payload_json=rendered,
            payload_hash=payload_hash(payload),
            mapping_manifest_hash=self.manifest_hash,
            expectation=expectation,
            source_create_plan=plan,
            source_create_plan_hash=plan.plan_hash,
            plan_hash="",
        )
        return replace(lookup, plan_hash=payload_hash(_lookup_plan_body(lookup)))

    def verify_lookup_page(
        self, plan: BitrixGraphMappedLookup, envelope: Mapping[str, Any]
    ) -> BitrixGraphLookupCandidate | None:
        self._validate_lookup_plan(plan)
        if type(envelope) is not dict:
            raise BitrixGraphProviderConflict("graph lookup result is invalid")
        rows = envelope.get("result")
        total = envelope.get("total")
        if (
            type(rows) is not list
            or type(total) is not int
            or total < 0
            or envelope.get("next") is not None
            or total != len(rows)
            or len(rows) > 1
        ):
            raise BitrixGraphProviderConflict("graph lookup result is incomplete")
        if not rows:
            return None
        row = rows[0]
        if type(row) is not dict:
            raise BitrixGraphProviderConflict("graph lookup result is invalid")
        expectation = plan.expectation
        if row.get(expectation.correlation_field) != expectation.correlation_token:
            raise BitrixGraphProviderConflict("graph lookup identity is invalid")
        remote_id = _provider_remote_id(row.get("ID"))
        _assert_parent_readback(expectation, row)
        get_payload = canonical_json({"id": remote_id})
        return BitrixGraphLookupCandidate(
            remote_entity_type=plan.remote_entity_type,
            remote_id=remote_id,
            get_method=plan.get_method,
            get_payload_json=get_payload,
            mapping_manifest_hash=self.manifest_hash,
        )

    def verify_readback(
        self, plan: BitrixGraphMappedCreate, result: Mapping[str, Any]
    ) -> CrmGraphReadback:
        _provider, owned, _identity_value = self._validate_create_plan(plan)
        if type(result) is not dict:
            raise BitrixGraphProviderConflict("graph readback is invalid")
        expectation = plan.expectation
        remote_id = _provider_remote_id(result.get("ID"))
        if expectation.remote_entity_type == "activity":
            if result.get("DESCRIPTION") != expectation.activity_marker and not str(
                result.get("DESCRIPTION", "")
            ).endswith("\n" + expectation.activity_marker):
                raise BitrixGraphProviderConflict("graph readback identity is invalid")
        elif result.get(expectation.correlation_field) != expectation.correlation_token:
            raise BitrixGraphProviderConflict("graph readback identity is invalid")
        _assert_parent_readback(expectation, result)
        _assert_owned_readback(owned, result)
        return CrmGraphReadback(
            remote_entity_type=expectation.remote_entity_type,
            remote_id=remote_id,
            correlation_token=expectation.correlation_token,
            readback_verified=True,
            company_remote_id=expectation.company_remote_id,
            contact_remote_id=expectation.contact_remote_id,
            deal_remote_id=expectation.deal_remote_id,
        )


def _provider_remote_id(value: object) -> str:
    if type(value) is int:
        rendered = str(value)
    elif type(value) is str:
        rendered = value
    else:
        raise BitrixGraphProviderConflict("graph provider id is invalid")
    if not _REMOTE_ID.fullmatch(rendered):
        raise BitrixGraphProviderConflict("graph provider id is invalid")
    return rendered


def _assert_parent_readback(
    expectation: BitrixGraphReadbackExpectation, result: Mapping[str, Any]
) -> None:
    entity = expectation.remote_entity_type
    if entity == "contact":
        if _provider_remote_id(result.get("COMPANY_ID")) != expectation.company_remote_id:
            raise BitrixGraphProviderConflict("graph readback parent is invalid")
    elif entity == "deal":
        if (
            _provider_remote_id(result.get("COMPANY_ID"))
            != expectation.company_remote_id
            or _provider_remote_id(result.get("CONTACT_ID"))
            != expectation.contact_remote_id
        ):
            raise BitrixGraphProviderConflict("graph readback parent is invalid")
        if "CONTACT_IDS" in result:
            contacts = result.get("CONTACT_IDS")
            if type(contacts) is not list or contacts != [expectation.contact_remote_id]:
                raise BitrixGraphProviderConflict("graph readback parent is invalid")
    elif entity == "activity":
        if (
            _provider_remote_id(result.get("OWNER_TYPE_ID")) != "2"
            or _provider_remote_id(result.get("OWNER_ID")) != expectation.deal_remote_id
        ):
            raise BitrixGraphProviderConflict("graph readback parent is invalid")


def _assert_owned_readback(
    expected: Mapping[str, Any], result: Mapping[str, Any]
) -> None:
    integer_fields = {
        "COMPANY_ID",
        "CONTACT_ID",
        "CATEGORY_ID",
        "ASSIGNED_BY_ID",
        "RESPONSIBLE_ID",
    }
    for field, expected_value in expected.items():
        if field not in result:
            raise BitrixGraphProviderConflict("graph readback field is missing")
        actual = result[field]
        if field in {"EMAIL", "PHONE"}:
            if type(expected_value) is not list or type(actual) is not list:
                raise BitrixGraphProviderConflict("graph readback field is invalid")
            normalized = []
            for item in actual:
                if (
                    type(item) is not dict
                    or not {"VALUE", "VALUE_TYPE"}.issubset(item)
                    or not set(item).issubset(
                        {"ID", "TYPE_ID", "VALUE", "VALUE_TYPE"}
                    )
                    or ("ID" in item and not _REMOTE_ID.fullmatch(str(item["ID"])))
                    or ("TYPE_ID" in item and str(item["TYPE_ID"]) != field)
                ):
                    raise BitrixGraphProviderConflict(
                        "graph readback field is invalid"
                    )
                normalized.append(
                    {"VALUE": item["VALUE"], "VALUE_TYPE": item["VALUE_TYPE"]}
                )
            if normalized != expected_value:
                raise BitrixGraphProviderConflict("graph readback field is invalid")
        elif field in integer_fields:
            if _provider_remote_id(actual) != str(expected_value):
                raise BitrixGraphProviderConflict("graph readback field is invalid")
        elif field == "DEADLINE":
            try:
                expected_deadline = datetime.fromisoformat(
                    str(expected_value).replace("Z", "+00:00")
                )
                actual_deadline = datetime.fromisoformat(
                    str(actual).replace("Z", "+00:00")
                )
            except ValueError:
                raise BitrixGraphProviderConflict(
                    "graph readback field is invalid"
                ) from None
            if (
                expected_deadline.tzinfo is None
                or actual_deadline.tzinfo is None
                or expected_deadline.timestamp() != actual_deadline.timestamp()
            ):
                raise BitrixGraphProviderConflict("graph readback field is invalid")
        elif actual != expected_value:
            raise BitrixGraphProviderConflict("graph readback field is invalid")


__all__ = [
    "GRAPH_ACTIVITY_MARKER_VERSION",
    "GRAPH_CONTRACT_VERSION",
    "GRAPH_INPUT_CONTRACT_VERSION",
    "GRAPH_MAPPING_EVIDENCE_MODE",
    "GRAPH_MAPPING_LIFECYCLE",
    "GRAPH_MAPPING_MANIFEST_VERSION",
    "BitrixGraphCorrelationField",
    "BitrixGraphBridgeBinding",
    "BitrixGraphFieldBinding",
    "BitrixGraphLookupCandidate",
    "BitrixGraphMappedCreate",
    "BitrixGraphMappedLookup",
    "BitrixGraphManifestMismatch",
    "BitrixGraphMapper",
    "BitrixGraphMappingError",
    "BitrixGraphMappingManifest",
    "BitrixGraphProviderConflict",
    "BitrixGraphReadbackExpectation",
    "BitrixGraphRoute",
    "BitrixGraphSourceBinding",
    "graph_mapping_manifest_hash",
    "graph_manifest_custom_fields",
    "canonical_identity_graph_field_bindings",
    "validate_graph_mapping_manifest",
    "validate_graph_bridge_binding",
]
