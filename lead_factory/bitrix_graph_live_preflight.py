"""Read-only live Bitrix graph inventory bound to one sealed manifest."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .bitrix_graph_mapping import (
    BitrixGraphMappingManifest,
    validate_graph_mapping_manifest,
)
from .bitrix_graph_preflight import graph_required_field_shapes
from .bitrix_rest import BitrixRestBoundary, BitrixRestBoundaryError
from .crm_graph_outbox import COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE
from .crm_outbox import AmbiguousRemoteError, PermanentRemoteError, RetryableRemoteError
from .ids import payload_hash


class BitrixGraphLivePreflightError(ValueError):
    """Live inventory was incomplete, ambiguous, or incompatible."""


@dataclass(frozen=True)
class BitrixGraphLivePreflightReport:
    live_preflight_ok: bool
    checks: tuple[str, ...]
    error_code: str
    manifest_hash: str
    portal_identity: str
    read_calls_performed: int
    external_writes_performed: int
    required_field_count: int
    correlation_probe_totals: tuple[tuple[str, int], ...]
    credential_owner_bound: bool
    credential_isolation_limited: bool
    owner_approval_required: bool
    canary_ready: bool
    report_hash: str


class BitrixGraphLiveReadBoundary:
    """Closed facade: graph inventory/readback only, never a provider write."""

    __slots__ = ("_transport", "_read_calls")

    def __init__(self, transport: BitrixRestBoundary) -> None:
        if type(transport) is not BitrixRestBoundary:
            raise BitrixGraphLivePreflightError("live graph transport is invalid")
        self._transport = transport
        self._read_calls = 0

    def __repr__(self) -> str:
        return "BitrixGraphLiveReadBoundary(<redacted>)"

    __str__ = __repr__

    @property
    def portal_identity(self) -> str:
        return self._transport.portal_fingerprint

    @property
    def credential_user_id(self) -> str:
        return self._transport.credential_user_id

    @property
    def read_calls(self) -> int:
        return self._read_calls

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._read_calls += 1
        return self._transport._call_allowlisted(method, payload)

    def field_catalog(self, entity: str) -> dict[str, Any]:
        if entity not in {"company", "contact", "deal", "activity"}:
            raise BitrixGraphLivePreflightError("live graph entity is invalid")
        result = self._call(f"crm.{entity}.fields", {}).get("result")
        if not isinstance(result, dict):
            raise BitrixGraphLivePreflightError("live graph field catalog is invalid")
        return result

    def userfield_exact(self, entity: str, field: str) -> dict[str, Any]:
        if entity not in {"company", "contact", "deal"} or not field.startswith(
            "UF_CRM_"
        ):
            raise BitrixGraphLivePreflightError("live graph userfield probe is invalid")
        return self._call(
            f"crm.{entity}.userfield.list", {"filter": {"FIELD_NAME": field}}
        )

    def categories(self) -> list[dict[str, Any]]:
        result = self._call("crm.category.list", {"entityTypeId": 2}).get("result")
        rows = result.get("categories") if isinstance(result, dict) else None
        if type(rows) is not list:
            raise BitrixGraphLivePreflightError("live graph categories are invalid")
        return rows

    def statuses(self, entity_id: str) -> list[dict[str, Any]]:
        result = self._call(
            "crm.status.list",
            {"order": {"SORT": "ASC"}, "filter": {"ENTITY_ID": entity_id}},
        ).get("result")
        if type(result) is not list:
            raise BitrixGraphLivePreflightError("live graph directory is invalid")
        return result

    def first_get(self, entity: str) -> dict[str, Any]:
        if entity not in {"company", "contact", "deal", "activity"}:
            raise BitrixGraphLivePreflightError("live graph entity is invalid")
        listed = self._call(
            f"crm.{entity}.list",
            {"order": {"ID": "ASC"}, "filter": {}, "select": ["ID"], "start": 0},
        )
        rows = listed.get("result")
        if type(rows) is not list or not rows or not isinstance(rows[0], dict):
            raise BitrixGraphLivePreflightError("live graph readback probe is unavailable")
        remote_id = str(rows[0].get("ID", "") or "")
        if not remote_id.isascii() or not remote_id.isdigit() or int(remote_id) < 1:
            raise BitrixGraphLivePreflightError("live graph readback id is invalid")
        result = self._call(f"crm.{entity}.get", {"id": remote_id}).get("result")
        if not isinstance(result, dict) or str(result.get("ID", "") or "") != remote_id:
            raise BitrixGraphLivePreflightError("live graph readback is invalid")
        return result

    def correlation_probe(
        self, entity: str, field: str, correlation_token: str
    ) -> tuple[int, bool]:
        if entity not in {"company", "contact", "deal"}:
            raise BitrixGraphLivePreflightError("live graph correlation entity is invalid")
        result = self._call(
            f"crm.{entity}.list",
            {
                "order": {"ID": "ASC"},
                "filter": {f"={field}": correlation_token},
                "select": ["ID", field],
                "start": 0,
            },
        )
        rows = result.get("result")
        total_value = result.get("total")
        if isinstance(total_value, bool) or type(rows) is not list:
            raise BitrixGraphLivePreflightError("live graph correlation result is invalid")
        try:
            total = int(total_value)
        except (TypeError, ValueError):
            raise BitrixGraphLivePreflightError(
                "live graph correlation total is invalid"
            ) from None
        if total != len(rows):
            raise BitrixGraphLivePreflightError("live graph correlation page is incomplete")
        return total, "next" in result


def _report(
    *,
    ok: bool,
    checks: list[str],
    error_code: str,
    manifest_hash: str,
    boundary: BitrixGraphLiveReadBoundary,
    required_field_count: int,
    probe_totals: list[tuple[str, int]],
    credential_owner_bound: bool,
) -> BitrixGraphLivePreflightReport:
    body = {
        "live_preflight_ok": ok,
        "checks": list(checks),
        "error_code": error_code,
        "manifest_hash": manifest_hash,
        "portal_identity": boundary.portal_identity,
        "read_calls_performed": boundary.read_calls,
        "external_writes_performed": 0,
        "required_field_count": required_field_count,
        "correlation_probe_totals": [list(item) for item in probe_totals],
        "credential_owner_bound": credential_owner_bound,
        "credential_isolation_limited": True,
        "owner_approval_required": True,
        "canary_ready": False,
    }
    return BitrixGraphLivePreflightReport(
        live_preflight_ok=ok,
        checks=tuple(checks),
        error_code=error_code,
        manifest_hash=manifest_hash,
        portal_identity=boundary.portal_identity,
        read_calls_performed=boundary.read_calls,
        external_writes_performed=0,
        required_field_count=required_field_count,
        correlation_probe_totals=tuple(probe_totals),
        credential_owner_bound=credential_owner_bound,
        credential_isolation_limited=True,
        owner_approval_required=True,
        canary_ready=False,
        report_hash=payload_hash(body),
    )


def _normalized_provider_type(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw in {
        "integer",
        "crm_company",
        "crm_contact",
        "crm_category",
        "crm_enum_ownertype",
        "user",
    }:
        return "integer"
    if raw == "crm_status":
        return "string"
    return raw


def _derived_probe_token(operation: str, entity: str, manifest_hash: str) -> str:
    local_type = "company" if entity == "company" else "contact" if entity == "contact" else "opportunity"
    local_id = f"preflight:{manifest_hash[:24]}:{entity}"
    return "lf_graph_v1_" + payload_hash(
        {
            "operation_type": operation,
            "lf_entity_type": local_type,
            "lf_entity_id": local_id,
        }
    )[:40]


def run_bitrix_graph_live_preflight(
    manifest: BitrixGraphMappingManifest,
    boundary: BitrixGraphLiveReadBoundary,
) -> BitrixGraphLivePreflightReport:
    if type(boundary) is not BitrixGraphLiveReadBoundary:
        raise BitrixGraphLivePreflightError("live graph boundary is invalid")
    checks: list[str] = []
    probes: list[tuple[str, int]] = []
    credential_bound = False
    try:
        manifest_hash = validate_graph_mapping_manifest(manifest)
        required = graph_required_field_shapes(manifest)
        if boundary.portal_identity != manifest.portal_identity:
            raise BitrixGraphLivePreflightError("portal mismatch")
        checks.append("MANIFEST_AND_PORTAL_BOUND")

        catalogs = {
            entity: boundary.field_catalog(entity)
            for entity in ("company", "contact", "deal", "activity")
        }
        for (entity, field), expected in required.items():
            provider_field = field
            if entity == "activity":
                provider_field = {
                    "title": "SUBJECT",
                    "description": "DESCRIPTION",
                    "deadline": "DEADLINE",
                    "ownerTypeId": "OWNER_TYPE_ID",
                    "ownerId": "OWNER_ID",
                    "responsibleId": "RESPONSIBLE_ID",
                }.get(field, field)
            descriptor = catalogs[entity].get(provider_field)
            if not isinstance(descriptor, dict):
                raise BitrixGraphLivePreflightError("required field is missing")
            value_type, multiple, mandatory, searchable = expected
            if (
                _normalized_provider_type(descriptor.get("type")) != value_type
                or bool(descriptor.get("isMultiple", False)) is not multiple
                or bool(descriptor.get("isRequired", False)) is not mandatory
                or bool(descriptor.get("isReadOnly", False))
            ):
                raise BitrixGraphLivePreflightError("required field shape changed")
            if field.startswith("UF_CRM_"):
                envelope = boundary.userfield_exact(entity, field)
                rows = envelope.get("result")
                total = envelope.get("total")
                if (
                    type(rows) is not list
                    or str(total) != "1"
                    or len(rows) != 1
                    or not isinstance(rows[0], dict)
                    or str(rows[0].get("FIELD_NAME", "") or "").upper() != field
                    or (str(rows[0].get("IS_SEARCHABLE", "N") or "N").upper() == "Y")
                    is not searchable
                    or str(rows[0].get("EDIT_IN_LIST", "Y") or "Y").upper() != "Y"
                ):
                    raise BitrixGraphLivePreflightError("required userfield shape changed")
        checks.append("FIELD_SCHEMA_EXACT")

        category_ids = {str(item.get("id", "") or "") for item in boundary.categories() if isinstance(item, dict)}
        if manifest.route.deal_category_id not in category_ids:
            raise BitrixGraphLivePreflightError("deal category is unavailable")
        stage_entity = (
            "DEAL_STAGE"
            if manifest.route.deal_category_id == "0"
            else f"DEAL_STAGE_{manifest.route.deal_category_id}"
        )
        stages = boundary.statuses(stage_entity)
        if manifest.route.deal_stage_id not in {
            str(item.get("STATUS_ID", "") or "") for item in stages if isinstance(item, dict)
        }:
            raise BitrixGraphLivePreflightError("deal stage is unavailable")
        sources = boundary.statuses("SOURCE")
        available_sources = {
            str(item.get("STATUS_ID", "") or "") for item in sources if isinstance(item, dict)
        }
        if not {item.bitrix_source_id for item in manifest.source_bindings}.issubset(
            available_sources
        ):
            raise BitrixGraphLivePreflightError("deal source is unavailable")
        credential_bound = bool(boundary.credential_user_id) and (
            boundary.credential_user_id == manifest.route.deal_assigned_by_id
            == manifest.route.activity_responsible_id
        )
        if not credential_bound:
            raise BitrixGraphLivePreflightError("route owner is not credential-bound")
        checks.append("ROUTE_SOURCE_AND_OWNER_BOUND")

        readbacks = {
            entity: boundary.first_get(entity)
            for entity in ("company", "contact", "deal", "activity")
        }
        if "COMPANY_ID" not in readbacks["contact"]:
            raise BitrixGraphLivePreflightError("contact parent readback is unavailable")
        if not {"COMPANY_ID", "CONTACT_ID"}.issubset(readbacks["deal"]):
            raise BitrixGraphLivePreflightError("deal parent readback is unavailable")
        if not {
            "OWNER_TYPE_ID",
            "OWNER_ID",
            "RESPONSIBLE_ID",
            "DESCRIPTION",
            "DEADLINE",
        }.issubset(readbacks["activity"]):
            raise BitrixGraphLivePreflightError("activity readback is unavailable")
        checks.append("READBACK_CAPABILITIES_PROVEN")

        operations = {
            "company": COMPANY_CREATE,
            "contact": CONTACT_CREATE,
            "deal": DEAL_CREATE,
        }
        correlations = {
            item.entity_type: item.remote_field for item in manifest.correlation_fields
        }
        for entity in ("company", "contact", "deal"):
            total, has_next = boundary.correlation_probe(
                entity,
                correlations[entity],
                _derived_probe_token(operations[entity], entity, manifest_hash),
            )
            probes.append((entity, total))
            if total != 0 or has_next:
                raise BitrixGraphLivePreflightError("correlation token is not unused")
        checks.append("CORRELATION_TOKENS_UNUSED")
    except (
        AmbiguousRemoteError,
        BitrixGraphLivePreflightError,
        BitrixRestBoundaryError,
        PermanentRemoteError,
        RetryableRemoteError,
        TypeError,
        ValueError,
    ):
        return _report(
            ok=False,
            checks=checks,
            error_code="LIVE_GRAPH_PREFLIGHT_FAILED",
            manifest_hash=locals().get("manifest_hash", ""),
            boundary=boundary,
            required_field_count=len(locals().get("required", {})),
            probe_totals=probes,
            credential_owner_bound=credential_bound,
        )
    return _report(
        ok=True,
        checks=checks,
        error_code="",
        manifest_hash=manifest_hash,
        boundary=boundary,
        required_field_count=len(required),
        probe_totals=probes,
        credential_owner_bound=credential_bound,
    )


__all__ = [
    "BitrixGraphLivePreflightError",
    "BitrixGraphLivePreflightReport",
    "BitrixGraphLiveReadBoundary",
    "run_bitrix_graph_live_preflight",
]
