"""Offline-only schema preflight for the four-entity Bitrix graph mapping.

The caller supplies an immutable, hashed fixture snapshot.  This module never
opens SQLite, reads configuration or secrets, creates an HTTP session, or calls
Bitrix.  A passing report proves only that the draft mapping and the fixture
snapshot are internally compatible; live preflight and canary stay false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any

from .bitrix_graph_mapping import (
    GRAPH_MAPPING_EVIDENCE_MODE,
    BitrixGraphMappingError,
    BitrixGraphMappingManifest,
    validate_graph_mapping_manifest,
)
from .crm_graph_outbox import (
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphOutbox,
)
from .ids import payload_hash


GRAPH_SCHEMA_SNAPSHOT_VERSION = "bitrix-graph-schema-snapshot-v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PORTAL = re.compile(r"^bitrix-host-v1:[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,95}$")
_REMOTE_ID = re.compile(r"^[1-9][0-9]*$")
_CORRELATION = re.compile(r"^lf_graph_v1_[0-9a-f]{40}$")

_CAPABILITIES = (
    "activity.deal_owner_readback",
    "activity.description_marker_readback",
    "activity.get",
    "activity.mapped_fields_readback",
    "activity.route_fields_readback",
    "company.correlation_lookup",
    "company.get",
    "company.mapped_fields_readback",
    "contact.company_readback",
    "contact.correlation_lookup",
    "contact.get",
    "contact.mapped_fields_readback",
    "deal.company_contact_readback",
    "deal.correlation_lookup",
    "deal.get",
    "deal.mapped_fields_readback",
)


class BitrixGraphPreflightError(ValueError):
    """The offline schema snapshot is malformed or untrusted."""


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphFieldFact:
    entity_type: str
    field_code: str
    value_type: str
    multiple: bool
    mandatory: bool
    read_only: bool
    searchable: bool

    def __repr__(self) -> str:
        return "<BitrixGraphFieldFact redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphRouteFact:
    deal_category_id: str
    deal_stage_id: str
    stage_category_id: str
    deal_assigned_by_id: str
    deal_assignee_active: bool
    activity_responsible_id: str
    activity_responsible_active: bool
    available_source_ids: tuple[str, ...]

    def __repr__(self) -> str:
        return "<BitrixGraphRouteFact redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphCapabilityFact:
    capability_id: str
    proven: bool

    def __repr__(self) -> str:
        return "<BitrixGraphCapabilityFact redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphCorrelationProbe:
    entity_type: str
    operation_type: str
    lf_identity_id: str
    correlation_token: str
    total: int
    returned_remote_ids: tuple[str, ...]
    has_next: bool

    def __repr__(self) -> str:
        return "<BitrixGraphCorrelationProbe redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class BitrixGraphSchemaSnapshot:
    snapshot_version: str
    evidence_mode: str
    portal_identity: str
    captured_at_utc: str
    mapping_manifest_hash: str
    inventory_complete: bool
    fields: tuple[BitrixGraphFieldFact, ...]
    route: BitrixGraphRouteFact
    capabilities: tuple[BitrixGraphCapabilityFact, ...]
    probes: tuple[BitrixGraphCorrelationProbe, ...]
    evidence_ref: str
    declared_snapshot_hash: str = ""

    def __repr__(self) -> str:
        return "<BitrixGraphSchemaSnapshot redacted>"


@dataclass(frozen=True, slots=True)
class BitrixGraphPreflightReport:
    offline_contract_ok: bool
    checks: tuple[str, ...]
    error_code: str
    manifest_hash: str
    snapshot_hash: str
    live_calls_performed: int
    external_writes_performed: int
    live_preflight_ok: bool
    canary_ready: bool
    report_hash: str


def _positive_ascii_id(value: object) -> str:
    if type(value) is not str or not _REMOTE_ID.fullmatch(value):
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    return value


def _snapshot_body(snapshot: BitrixGraphSchemaSnapshot) -> dict[str, Any]:
    if type(snapshot) is not BitrixGraphSchemaSnapshot:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    if (
        type(snapshot.snapshot_version) is not str
        or type(snapshot.evidence_mode) is not str
        or snapshot.snapshot_version != GRAPH_SCHEMA_SNAPSHOT_VERSION
        or snapshot.evidence_mode != GRAPH_MAPPING_EVIDENCE_MODE
        or type(snapshot.portal_identity) is not str
        or not _PORTAL.fullmatch(snapshot.portal_identity)
        or type(snapshot.mapping_manifest_hash) is not str
        or not _HEX64.fullmatch(snapshot.mapping_manifest_hash)
        or snapshot.inventory_complete is not True
        or type(snapshot.captured_at_utc) is not str
        or not _UTC_SECONDS.fullmatch(snapshot.captured_at_utc)
        or type(snapshot.evidence_ref) is not str
        or not _SAFE.fullmatch(snapshot.evidence_ref)
    ):
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    try:
        datetime.fromisoformat(snapshot.captured_at_utc.replace("Z", "+00:00"))
    except ValueError:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid") from None

    if type(snapshot.fields) is not tuple:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    fields: list[dict[str, Any]] = []
    keys: list[tuple[str, str]] = []
    casefolded: set[tuple[str, str]] = set()
    for fact in snapshot.fields:
        if type(fact) is not BitrixGraphFieldFact:
            raise BitrixGraphPreflightError("offline graph snapshot is invalid")
        if (
            fact.entity_type not in {"company", "contact", "deal", "activity"}
            or type(fact.entity_type) is not str
            or type(fact.field_code) is not str
            or not fact.field_code.isascii()
            or not _FIELD.fullmatch(fact.field_code)
            or type(fact.value_type) is not str
            or fact.value_type
            not in {"string", "integer", "datetime", "crm_multifield"}
            or type(fact.multiple) is not bool
            or type(fact.mandatory) is not bool
            or type(fact.read_only) is not bool
            or type(fact.searchable) is not bool
        ):
            raise BitrixGraphPreflightError("offline graph snapshot is invalid")
        key = (fact.entity_type, fact.field_code)
        folded = (fact.entity_type, fact.field_code.casefold())
        if key in keys or folded in casefolded:
            raise BitrixGraphPreflightError("offline graph snapshot is invalid")
        keys.append(key)
        casefolded.add(folded)
        fields.append(
            {
                "entity_type": fact.entity_type,
                "field_code": fact.field_code,
                "value_type": fact.value_type,
                "multiple": fact.multiple,
                "mandatory": fact.mandatory,
                "read_only": fact.read_only,
                "searchable": fact.searchable,
            }
        )
    if keys != sorted(keys):
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")

    route = snapshot.route
    if type(route) is not BitrixGraphRouteFact:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    category = _positive_ascii_id(route.deal_category_id)
    stage_category = _positive_ascii_id(route.stage_category_id)
    assigned = _positive_ascii_id(route.deal_assigned_by_id)
    responsible = _positive_ascii_id(route.activity_responsible_id)
    if (
        type(route.deal_stage_id) is not str
        or not _SAFE.fullmatch(route.deal_stage_id)
        or type(route.deal_assignee_active) is not bool
        or type(route.activity_responsible_active) is not bool
        or type(route.available_source_ids) is not tuple
        or any(
            type(value) is not str or not _SAFE.fullmatch(value)
            for value in route.available_source_ids
        )
        or route.available_source_ids != tuple(sorted(set(route.available_source_ids)))
    ):
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")

    if type(snapshot.capabilities) is not tuple:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    capabilities: list[dict[str, Any]] = []
    capability_ids: list[str] = []
    for fact in snapshot.capabilities:
        if (
            type(fact) is not BitrixGraphCapabilityFact
            or type(fact.capability_id) is not str
            or not _SAFE.fullmatch(fact.capability_id)
            or type(fact.proven) is not bool
            or fact.capability_id in capability_ids
        ):
            raise BitrixGraphPreflightError("offline graph snapshot is invalid")
        capability_ids.append(fact.capability_id)
        capabilities.append(
            {"capability_id": fact.capability_id, "proven": fact.proven}
        )
    if capability_ids != sorted(capability_ids):
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")

    if type(snapshot.probes) is not tuple:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    probes: list[dict[str, Any]] = []
    probe_entities: list[str] = []
    probe_contract = {
        "company": (COMPANY_CREATE, "company"),
        "contact": (CONTACT_CREATE, "contact"),
        "deal": (DEAL_CREATE, "opportunity"),
    }
    for probe in snapshot.probes:
        if (
            type(probe) is not BitrixGraphCorrelationProbe
            or type(probe.entity_type) is not str
            or probe.entity_type not in {"company", "contact", "deal"}
            or type(probe.operation_type) is not str
            or type(probe.lf_identity_id) is not str
            or not probe.lf_identity_id.isascii()
            or not _SAFE.fullmatch(probe.lf_identity_id)
            or type(probe.correlation_token) is not str
            or not _CORRELATION.fullmatch(probe.correlation_token)
            or type(probe.total) is not int
            or probe.total < 0
            or type(probe.returned_remote_ids) is not tuple
            or any(
                type(value) is not str or not _REMOTE_ID.fullmatch(value)
                for value in probe.returned_remote_ids
            )
            or type(probe.has_next) is not bool
            or probe.entity_type in probe_entities
        ):
            raise BitrixGraphPreflightError("offline graph snapshot is invalid")
        expected_operation, expected_local_type = probe_contract[probe.entity_type]
        _expected_key, expected_token = CrmGraphOutbox._derived_identity(
            expected_operation,
            expected_local_type,
            probe.lf_identity_id,
        )
        if (
            probe.operation_type != expected_operation
            or probe.correlation_token != expected_token
        ):
            raise BitrixGraphPreflightError("offline graph snapshot is invalid")
        probe_entities.append(probe.entity_type)
        probes.append(
            {
                "entity_type": probe.entity_type,
                "operation_type": probe.operation_type,
                "lf_identity_id": probe.lf_identity_id,
                "correlation_token": probe.correlation_token,
                "total": probe.total,
                "returned_remote_ids": list(probe.returned_remote_ids),
                "has_next": probe.has_next,
            }
        )
    if probe_entities != ["company", "contact", "deal"]:
        raise BitrixGraphPreflightError("offline graph snapshot is invalid")
    return {
        "snapshot_version": snapshot.snapshot_version,
        "evidence_mode": snapshot.evidence_mode,
        "portal_identity": snapshot.portal_identity,
        "captured_at_utc": snapshot.captured_at_utc,
        "mapping_manifest_hash": snapshot.mapping_manifest_hash,
        "inventory_complete": snapshot.inventory_complete,
        "fields": fields,
        "route": {
            "deal_category_id": category,
            "deal_stage_id": route.deal_stage_id,
            "stage_category_id": stage_category,
            "deal_assigned_by_id": assigned,
            "deal_assignee_active": route.deal_assignee_active,
            "activity_responsible_id": responsible,
            "activity_responsible_active": route.activity_responsible_active,
            "available_source_ids": list(route.available_source_ids),
        },
        "capabilities": capabilities,
        "probes": probes,
        "evidence_ref": snapshot.evidence_ref,
    }


def graph_schema_snapshot_hash(snapshot: BitrixGraphSchemaSnapshot) -> str:
    return payload_hash(_snapshot_body(snapshot))


def validate_graph_schema_snapshot(snapshot: BitrixGraphSchemaSnapshot) -> str:
    digest = graph_schema_snapshot_hash(snapshot)
    if (
        type(snapshot.declared_snapshot_hash) is not str
        or not _HEX64.fullmatch(snapshot.declared_snapshot_hash)
        or snapshot.declared_snapshot_hash != digest
    ):
        raise BitrixGraphPreflightError("offline graph snapshot hash is invalid")
    return digest


def _required_field_shapes(
    manifest: BitrixGraphMappingManifest,
) -> dict[tuple[str, str], tuple[str, bool, bool, bool]]:
    result: dict[tuple[str, str], tuple[str, bool, bool, bool]] = {}
    for binding in manifest.field_bindings:
        if (
            binding.entity_type == "activity"
            and binding.payload_key == "UF_CRM_LF_OPPORTUNITY_ID"
        ):
            continue
        value_type = (
            "crm_multifield"
            if binding.payload_key in {"EMAIL", "PHONE"}
            else "datetime"
            if binding.payload_key == "DEADLINE"
            else "string"
        )
        result[(binding.entity_type, binding.remote_field)] = (
            value_type,
            value_type == "crm_multifield",
            (binding.entity_type, binding.payload_key)
            in {
                ("company", "TITLE"),
                ("contact", "NAME"),
                ("activity", "SUBJECT"),
            },
            False,
        )
    for field in manifest.correlation_fields:
        result[(field.entity_type, field.remote_field)] = (
            "string",
            False,
            False,
            True,
        )
    result.update(
        {
            ("contact", "COMPANY_ID"): ("integer", False, False, False),
            ("deal", "COMPANY_ID"): ("integer", False, False, False),
            ("deal", "CONTACT_ID"): ("integer", False, False, False),
            ("deal", "CATEGORY_ID"): ("integer", False, False, False),
            ("deal", "STAGE_ID"): ("string", False, False, False),
            ("deal", "ASSIGNED_BY_ID"): ("integer", False, False, False),
            ("deal", "SOURCE_ID"): ("string", False, False, False),
            ("activity", "ownerTypeId"): ("integer", False, False, False),
            ("activity", "ownerId"): ("integer", False, False, False),
            ("activity", "responsibleId"): ("integer", False, True, False),
        }
    )
    return result


def graph_required_field_shapes(
    manifest: BitrixGraphMappingManifest,
) -> dict[tuple[str, str], tuple[str, bool, bool, bool]]:
    """Return the validated normalized field contract for live inventory."""

    validate_graph_mapping_manifest(manifest)
    return dict(_required_field_shapes(manifest))


def _report(
    *,
    ok: bool,
    checks: list[str],
    error_code: str,
    manifest_hash: str,
    snapshot_hash: str,
) -> BitrixGraphPreflightReport:
    body = {
        "offline_contract_ok": ok,
        "checks": list(checks),
        "error_code": error_code,
        "manifest_hash": manifest_hash,
        "snapshot_hash": snapshot_hash,
        "live_calls_performed": 0,
        "external_writes_performed": 0,
        "live_preflight_ok": False,
        "canary_ready": False,
    }
    return BitrixGraphPreflightReport(
        offline_contract_ok=ok,
        checks=tuple(checks),
        error_code=error_code,
        manifest_hash=manifest_hash,
        snapshot_hash=snapshot_hash,
        live_calls_performed=0,
        external_writes_performed=0,
        live_preflight_ok=False,
        canary_ready=False,
        report_hash=payload_hash(body),
    )


def run_bitrix_graph_offline_preflight(
    manifest: BitrixGraphMappingManifest,
    snapshot: BitrixGraphSchemaSnapshot,
) -> BitrixGraphPreflightReport:
    """Validate an exact offline fixture; never claim live or canary readiness."""

    checks: list[str] = []
    try:
        manifest_hash = validate_graph_mapping_manifest(manifest)
    except (BitrixGraphMappingError, TypeError, ValueError):
        return _report(
            ok=False,
            checks=checks,
            error_code="MANIFEST_INVALID",
            manifest_hash="",
            snapshot_hash="",
        )
    checks.append("MANIFEST_VALID")
    try:
        snapshot_hash = validate_graph_schema_snapshot(snapshot)
    except (BitrixGraphPreflightError, TypeError, ValueError):
        return _report(
            ok=False,
            checks=checks,
            error_code="SNAPSHOT_INVALID",
            manifest_hash=manifest_hash,
            snapshot_hash="",
        )
    checks.append("SNAPSHOT_VALID")
    if snapshot.portal_identity != manifest.portal_identity:
        return _report(
            ok=False,
            checks=checks,
            error_code="PORTAL_MISMATCH",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    if snapshot.mapping_manifest_hash != manifest_hash:
        return _report(
            ok=False,
            checks=checks,
            error_code="SNAPSHOT_MAPPING_MISMATCH",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    checks.append("SNAPSHOT_BOUND")

    actual_fields = {
        (item.entity_type, item.field_code): item for item in snapshot.fields
    }
    for key, expected in _required_field_shapes(manifest).items():
        fact = actual_fields.get(key)
        if fact is None:
            return _report(
                ok=False,
                checks=checks,
                error_code="FIELD_MISSING",
                manifest_hash=manifest_hash,
                snapshot_hash=snapshot_hash,
            )
        value_type, multiple, mandatory, searchable = expected
        if (
            fact.value_type != value_type
            or fact.multiple is not multiple
            or fact.mandatory is not mandatory
            or fact.searchable is not searchable
        ):
            return _report(
                ok=False,
                checks=checks,
                error_code="FIELD_SHAPE",
                manifest_hash=manifest_hash,
                snapshot_hash=snapshot_hash,
            )
        if fact.read_only:
            return _report(
                ok=False,
                checks=checks,
                error_code="FIELD_READ_ONLY",
                manifest_hash=manifest_hash,
                snapshot_hash=snapshot_hash,
            )
    checks.append("FIELDS_COMPATIBLE")

    route = snapshot.route
    expected_route = manifest.route
    if (
        route.deal_category_id != expected_route.deal_category_id
        or route.deal_stage_id != expected_route.deal_stage_id
        or route.stage_category_id != expected_route.deal_category_id
    ):
        return _report(
            ok=False,
            checks=checks,
            error_code="ROUTE_STAGE_MISMATCH",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    if (
        route.deal_assigned_by_id != expected_route.deal_assigned_by_id
        or route.deal_assignee_active is not True
        or route.activity_responsible_id != expected_route.activity_responsible_id
        or route.activity_responsible_active is not True
    ):
        return _report(
            ok=False,
            checks=checks,
            error_code="ROUTE_OWNER_INVALID",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    expected_sources = {
        item.bitrix_source_id for item in manifest.source_bindings
    }
    if not expected_sources.issubset(route.available_source_ids):
        return _report(
            ok=False,
            checks=checks,
            error_code="SOURCE_ID_MISSING",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    checks.append("ROUTE_COMPATIBLE")

    capabilities = {item.capability_id: item.proven for item in snapshot.capabilities}
    if set(capabilities) != set(_CAPABILITIES) or not all(capabilities.values()):
        return _report(
            ok=False,
            checks=checks,
            error_code="RELATION_READBACK_UNPROVEN",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    checks.append("READBACK_CAPABILITIES_PROVEN")
    if any(
        probe.total != 0
        or probe.returned_remote_ids
        or probe.has_next
        for probe in snapshot.probes
    ):
        return _report(
            ok=False,
            checks=checks,
            error_code="CORRELATION_TOKEN_NOT_UNUSED",
            manifest_hash=manifest_hash,
            snapshot_hash=snapshot_hash,
        )
    checks.append("CORRELATION_TOKENS_UNUSED")
    return _report(
        ok=True,
        checks=checks,
        error_code="",
        manifest_hash=manifest_hash,
        snapshot_hash=snapshot_hash,
    )


__all__ = [
    "GRAPH_SCHEMA_SNAPSHOT_VERSION",
    "BitrixGraphCapabilityFact",
    "BitrixGraphCorrelationProbe",
    "BitrixGraphFieldFact",
    "BitrixGraphPreflightError",
    "BitrixGraphPreflightReport",
    "BitrixGraphRouteFact",
    "BitrixGraphSchemaSnapshot",
    "graph_schema_snapshot_hash",
    "graph_required_field_shapes",
    "run_bitrix_graph_offline_preflight",
    "validate_graph_schema_snapshot",
]
