"""Sealed, idempotent Bitrix graph user-field provisioning.

This module is intentionally separate from CRM graph writes.  Its boundary can
only list or add the exact Company/Contact/Deal string fields derived from the
production graph contract.  It has no update/delete method and cannot create a
CRM entity or Activity.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any
from uuid import uuid4

from .bitrix_graph_mapping import (
    BitrixGraphMappingManifest,
    graph_manifest_custom_fields,
    validate_graph_mapping_manifest,
)
from .bitrix_rest import BitrixRestBoundary, HttpSession
from .crm_outbox import AmbiguousRemoteError
from .ids import payload_hash


BITRIX_GRAPH_UF_PLAN_VERSION = "bitrix-graph-uf-plan-v1"

_ENTITY_METHOD_PREFIX = {
    "company": "crm.company.userfield",
    "contact": "crm.contact.userfield",
    "deal": "crm.deal.userfield",
}
_FIELD_NAME = re.compile(r"^UF_CRM_[A-Z0-9_]{1,43}$")
_PORTAL = re.compile(r"^bitrix-host-v1:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class BitrixGraphUfSchemaError(ValueError):
    """The sealed plan, provider shape, or boundary composition is invalid."""


class BitrixGraphUfOutcomeUncertain(RuntimeError):
    """A field add may have reached Bitrix but exact readback did not prove it."""


@dataclass(frozen=True)
class BitrixGraphUfField:
    entity_type: str
    field_name: str
    user_type_id: str = "string"
    multiple: str = "N"
    mandatory: str = "N"
    searchable: str = "N"
    editable: str = "Y"


@dataclass(frozen=True)
class BitrixGraphUfPlan:
    plan_version: str
    portal_identity: str
    mapping_manifest: BitrixGraphMappingManifest
    fields: tuple[BitrixGraphUfField, ...]
    declared_plan_hash: str = ""


@dataclass(frozen=True)
class BitrixGraphUfProvisioningReport:
    plan_hash: str
    portal_identity: str
    created: tuple[tuple[str, str], ...]
    existing: tuple[tuple[str, str], ...]


class _BitrixGraphUfAddCapability:
    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        self._token = token

    def __repr__(self) -> str:
        return "BitrixGraphUfAddCapability(<redacted>)"

    __str__ = __repr__


def _field_body(field: BitrixGraphUfField) -> dict[str, str]:
    return {
        "entity_type": field.entity_type,
        "field_name": field.field_name,
        "user_type_id": field.user_type_id,
        "multiple": field.multiple,
        "mandatory": field.mandatory,
        "searchable": field.searchable,
        "editable": field.editable,
    }


def _plan_body(plan: BitrixGraphUfPlan) -> dict[str, Any]:
    return {
        "plan_version": plan.plan_version,
        "portal_identity": plan.portal_identity,
        "mapping_manifest_hash": validate_graph_mapping_manifest(
            plan.mapping_manifest
        ),
        "fields": [_field_body(field) for field in plan.fields],
    }


def bitrix_graph_uf_plan_hash(plan: BitrixGraphUfPlan) -> str:
    return payload_hash(_plan_body(plan))


def validate_bitrix_graph_uf_plan(plan: BitrixGraphUfPlan) -> str:
    if type(plan) is not BitrixGraphUfPlan:
        raise BitrixGraphUfSchemaError("Bitrix graph UF plan is invalid")
    if (
        plan.plan_version != BITRIX_GRAPH_UF_PLAN_VERSION
        or type(plan.portal_identity) is not str
        or not _PORTAL.fullmatch(plan.portal_identity)
        or type(plan.fields) is not tuple
        or not plan.fields
    ):
        raise BitrixGraphUfSchemaError("Bitrix graph UF plan is invalid")

    try:
        validate_graph_mapping_manifest(plan.mapping_manifest)
    except (TypeError, ValueError) as exc:
        raise BitrixGraphUfSchemaError("Bitrix graph UF manifest is invalid") from exc
    if plan.mapping_manifest.portal_identity != plan.portal_identity:
        raise BitrixGraphUfSchemaError("Bitrix graph UF manifest portal changed")
    expected_contract = graph_manifest_custom_fields(plan.mapping_manifest)
    actual_contract: list[tuple[str, str, bool]] = []
    for field in plan.fields:
        if (
            type(field) is not BitrixGraphUfField
            or field.entity_type not in _ENTITY_METHOD_PREFIX
            or type(field.field_name) is not str
            or not _FIELD_NAME.fullmatch(field.field_name)
            or field.user_type_id != "string"
            or field.multiple != "N"
            or field.mandatory != "N"
            or field.searchable not in {"N", "Y"}
            or field.editable != "Y"
        ):
            raise BitrixGraphUfSchemaError("Bitrix graph UF plan is invalid")
        actual_contract.append(
            (field.entity_type, field.field_name, field.searchable == "Y")
        )
    if tuple(actual_contract) != expected_contract:
        raise BitrixGraphUfSchemaError("Bitrix graph UF plan contract is not exact")

    digest = bitrix_graph_uf_plan_hash(plan)
    if (
        type(plan.declared_plan_hash) is not str
        or not _HEX64.fullmatch(plan.declared_plan_hash)
        or plan.declared_plan_hash != digest
    ):
        raise BitrixGraphUfSchemaError("Bitrix graph UF plan hash is invalid")
    return digest


def build_bitrix_graph_uf_plan(
    mapping_manifest: BitrixGraphMappingManifest,
) -> BitrixGraphUfPlan:
    validate_graph_mapping_manifest(mapping_manifest)
    raw = BitrixGraphUfPlan(
        plan_version=BITRIX_GRAPH_UF_PLAN_VERSION,
        portal_identity=mapping_manifest.portal_identity,
        mapping_manifest=mapping_manifest,
        fields=tuple(
            BitrixGraphUfField(
                entity_type=entity,
                field_name=field,
                searchable="Y" if searchable else "N",
            )
            for entity, field, searchable in graph_manifest_custom_fields(
                mapping_manifest
            )
        ),
    )
    sealed = replace(raw, declared_plan_hash=bitrix_graph_uf_plan_hash(raw))
    validate_bitrix_graph_uf_plan(sealed)
    return sealed


class BitrixGraphUfAdminBoundary:
    """Exact list/add-only REST boundary for the sealed graph UF contract."""

    __slots__ = ("_transport", "_issued")

    def __init__(
        self,
        *,
        webhook_url: str,
        session: HttpSession,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._transport = BitrixRestBoundary(
            webhook_url=webhook_url,
            session=session,
            timeout_seconds=timeout_seconds,
        )
        self._issued: dict[str, tuple[str, str, str]] = {}

    def __repr__(self) -> str:
        return (
            "BitrixGraphUfAdminBoundary(webhook_url=<redacted>, "
            f"portal_identity={self.portal_identity})"
        )

    __str__ = __repr__

    @property
    def portal_identity(self) -> str:
        return self._transport.portal_fingerprint

    @staticmethod
    def _validate_field(field: BitrixGraphUfField) -> None:
        if (
            type(field) is not BitrixGraphUfField
            or field.entity_type not in _ENTITY_METHOD_PREFIX
            or not _FIELD_NAME.fullmatch(field.field_name)
            or field.user_type_id != "string"
            or field.multiple != "N"
            or field.mandatory != "N"
            or field.searchable not in {"N", "Y"}
            or field.editable != "Y"
        ):
            raise BitrixGraphUfSchemaError("Bitrix graph UF field is invalid")

    def list_exact(self, field: BitrixGraphUfField) -> dict[str, Any]:
        self._validate_field(field)
        method = f"{_ENTITY_METHOD_PREFIX[field.entity_type]}.list"
        return self._transport._call_allowlisted(
            method, {"filter": {"FIELD_NAME": field.field_name}}
        )

    def _mint_add_capability(
        self, *, plan_hash: str, field: BitrixGraphUfField
    ) -> _BitrixGraphUfAddCapability:
        self._validate_field(field)
        if type(plan_hash) is not str or not _HEX64.fullmatch(plan_hash):
            raise BitrixGraphUfSchemaError("Bitrix graph UF plan hash is invalid")
        token = uuid4().hex
        self._issued[token] = (plan_hash, field.entity_type, field.field_name)
        return _BitrixGraphUfAddCapability(token)

    def _add_exact(
        self,
        field: BitrixGraphUfField,
        *,
        plan_hash: str,
        capability: _BitrixGraphUfAddCapability,
    ) -> dict[str, Any]:
        self._validate_field(field)
        if type(capability) is not _BitrixGraphUfAddCapability:
            raise BitrixGraphUfSchemaError("Bitrix graph UF add requires a capability")
        record = self._issued.pop(capability._token, None)
        if record != (plan_hash, field.entity_type, field.field_name):
            raise BitrixGraphUfSchemaError("Bitrix graph UF add capability is invalid")
        method = f"{_ENTITY_METHOD_PREFIX[field.entity_type]}.add"
        label = f"Lead Factory — {field.field_name.removeprefix('UF_CRM_LF_')}"
        return self._transport._call_allowlisted(
            method,
            {
                "fields": {
                    "FIELD_NAME": field.field_name,
                    "USER_TYPE_ID": field.user_type_id,
                    "MULTIPLE": field.multiple,
                    "MANDATORY": field.mandatory,
                    "SHOW_FILTER": "Y",
                    "EDIT_IN_LIST": field.editable,
                    "IS_SEARCHABLE": field.searchable,
                    "LABEL": label,
                }
            },
        )


class BitrixGraphUfProvisioner:
    """Provision only missing exact fields, then prove every remote shape."""

    __slots__ = ("_boundary", "_plan", "_plan_hash")

    def __init__(
        self, boundary: BitrixGraphUfAdminBoundary, plan: BitrixGraphUfPlan
    ) -> None:
        if type(boundary) is not BitrixGraphUfAdminBoundary:
            raise BitrixGraphUfSchemaError("Bitrix graph UF boundary is invalid")
        plan_hash = validate_bitrix_graph_uf_plan(plan)
        if boundary.portal_identity != plan.portal_identity:
            raise BitrixGraphUfSchemaError("Bitrix graph UF portal binding changed")
        self._boundary = boundary
        self._plan = plan
        self._plan_hash = plan_hash

    @staticmethod
    def _read_shape(
        field: BitrixGraphUfField, envelope: dict[str, Any]
    ) -> bool:
        if not isinstance(envelope, dict) or "total" not in envelope:
            raise BitrixGraphUfSchemaError("Bitrix graph UF list total is invalid")
        total_value = envelope.get("total")
        if isinstance(total_value, bool):
            raise BitrixGraphUfSchemaError("Bitrix graph UF list total is invalid")
        try:
            total = int(total_value)
        except (TypeError, ValueError):
            raise BitrixGraphUfSchemaError(
                "Bitrix graph UF list total is invalid"
            ) from None
        rows = envelope.get("result")
        if (
            type(rows) is not list
            or total not in {0, 1}
            or len(rows) != total
        ):
            raise BitrixGraphUfSchemaError("Bitrix graph UF list is not exact")
        if not rows:
            return False
        row = rows[0]
        if not isinstance(row, dict):
            raise BitrixGraphUfSchemaError("Bitrix graph UF provider shape is invalid")
        if (
            str(row.get("FIELD_NAME", "") or "").upper() != field.field_name
            or str(row.get("USER_TYPE_ID", "") or "").lower()
            != field.user_type_id
            or str(row.get("MULTIPLE", "N") or "N").upper() != field.multiple
            or str(row.get("MANDATORY", "N") or "N").upper()
            != field.mandatory
            or str(row.get("IS_SEARCHABLE", "N") or "N").upper()
            != field.searchable
            or str(row.get("EDIT_IN_LIST", "Y") or "Y").upper()
            != field.editable
        ):
            raise BitrixGraphUfSchemaError("Bitrix graph UF provider shape is invalid")
        return True

    def _exists_exact(self, field: BitrixGraphUfField) -> bool:
        return self._read_shape(field, self._boundary.list_exact(field))

    def provision(self) -> BitrixGraphUfProvisioningReport:
        if validate_bitrix_graph_uf_plan(self._plan) != self._plan_hash:
            raise BitrixGraphUfSchemaError("Bitrix graph UF plan binding changed")
        if self._boundary.portal_identity != self._plan.portal_identity:
            raise BitrixGraphUfSchemaError("Bitrix graph UF portal binding changed")

        created: list[tuple[str, str]] = []
        existing: list[tuple[str, str]] = []
        for field in self._plan.fields:
            identity = (field.entity_type, field.field_name)
            if self._exists_exact(field):
                existing.append(identity)
                continue
            capability = self._boundary._mint_add_capability(
                plan_hash=self._plan_hash, field=field
            )
            try:
                result = self._boundary._add_exact(
                    field,
                    plan_hash=self._plan_hash,
                    capability=capability,
                )
            except AmbiguousRemoteError:
                try:
                    reconciled = self._exists_exact(field)
                except Exception:
                    raise BitrixGraphUfOutcomeUncertain(
                        "Bitrix graph UF add requires read-only review"
                    ) from None
                if not reconciled:
                    raise BitrixGraphUfOutcomeUncertain(
                        "Bitrix graph UF add requires read-only review"
                    ) from None
            else:
                remote_id = result.get("result") if isinstance(result, dict) else None
                if isinstance(remote_id, bool) or not str(remote_id or "").isdigit():
                    raise BitrixGraphUfOutcomeUncertain(
                        "Bitrix graph UF add result is invalid"
                    )
                if int(str(remote_id)) < 1:
                    raise BitrixGraphUfOutcomeUncertain(
                        "Bitrix graph UF add result is invalid"
                    )
                if not self._exists_exact(field):
                    raise BitrixGraphUfOutcomeUncertain(
                        "Bitrix graph UF add readback is missing"
                    )
            created.append(identity)

        return BitrixGraphUfProvisioningReport(
            plan_hash=self._plan_hash,
            portal_identity=self._plan.portal_identity,
            created=tuple(created),
            existing=tuple(existing),
        )


__all__ = [
    "BITRIX_GRAPH_UF_PLAN_VERSION",
    "BitrixGraphUfAdminBoundary",
    "BitrixGraphUfField",
    "BitrixGraphUfOutcomeUncertain",
    "BitrixGraphUfPlan",
    "BitrixGraphUfProvisioner",
    "BitrixGraphUfProvisioningReport",
    "BitrixGraphUfSchemaError",
    "bitrix_graph_uf_plan_hash",
    "build_bitrix_graph_uf_plan",
    "validate_bitrix_graph_uf_plan",
]
