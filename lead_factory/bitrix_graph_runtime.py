"""Default-off sealed runtime for future owner-approved Bitrix graph writes."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any
from uuid import uuid4

from .bitrix_graph_live_preflight import BitrixGraphLivePreflightReport
from .bitrix_graph_mapping import (
    BitrixGraphMappedCreate,
    BitrixGraphMapper,
)
from .bitrix_rest import BitrixRestBoundary
from .crm_graph_outbox import CrmGraphReadback
from .crm_outbox import ActivityOutcomeUncertain, AmbiguousRemoteError
from .ids import payload_hash


_CREATE_METHODS = frozenset(
    {
        "crm.company.add",
        "crm.contact.add",
        "crm.deal.add",
        "crm.activity.todo.add",
    }
)
_GET_METHODS = frozenset(
    {
        "crm.company.get",
        "crm.contact.get",
        "crm.deal.get",
        "crm.activity.get",
    }
)
_LIST_METHODS = frozenset(
    {"crm.company.list", "crm.contact.list", "crm.deal.list"}
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")


class BitrixGraphRuntimeError(ValueError):
    """The graph write composition, plan, or permit is invalid."""


class BitrixGraphWriterDisabled(RuntimeError):
    """The graph writer kill-switch is closed."""


class BitrixGraphWriteOutcomeUncertain(AmbiguousRemoteError):
    """A create may have succeeded but exact reconciliation is unavailable."""

    def __init__(self, remote_id: str = "") -> None:
        super().__init__("Bitrix graph write requires manual review")
        self.remote_id = str(remote_id or "")


@dataclass(frozen=True)
class BitrixGraphWritePermit:
    manifest_hash: str
    live_preflight_report_hash: str
    operation_id: str
    mapped_plan_hash: str
    canary_step: int
    owner_approval_ref: str
    declared_permit_hash: str


class _BitrixGraphWriteCapability:
    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        self._token = token

    def __repr__(self) -> str:
        return "BitrixGraphWriteCapability(<redacted>)"

    __str__ = __repr__


def _permit_body(permit: BitrixGraphWritePermit) -> dict[str, Any]:
    if type(permit) is not BitrixGraphWritePermit:
        raise BitrixGraphRuntimeError("Bitrix graph write permit is invalid")
    return {
        "manifest_hash": permit.manifest_hash,
        "live_preflight_report_hash": permit.live_preflight_report_hash,
        "operation_id": permit.operation_id,
        "mapped_plan_hash": permit.mapped_plan_hash,
        "canary_step": permit.canary_step,
        "owner_approval_ref": permit.owner_approval_ref,
    }


def bitrix_graph_write_permit_hash(permit: BitrixGraphWritePermit) -> str:
    return payload_hash(_permit_body(permit))


class BitrixGraphWriteBoundary:
    """Exact graph create/get/list facade with one-time create capabilities."""

    __slots__ = ("_transport", "_issued")

    def __init__(self, transport: BitrixRestBoundary) -> None:
        if type(transport) is not BitrixRestBoundary:
            raise BitrixGraphRuntimeError("Bitrix graph transport is invalid")
        self._transport = transport
        self._issued: dict[str, tuple[str, str]] = {}

    def __repr__(self) -> str:
        return "BitrixGraphWriteBoundary(<redacted>)"

    __str__ = __repr__

    @property
    def portal_identity(self) -> str:
        return self._transport.portal_fingerprint

    def _mint(self, method: str, permit_hash: str) -> _BitrixGraphWriteCapability:
        if method not in _CREATE_METHODS or not _HEX64.fullmatch(permit_hash):
            raise BitrixGraphRuntimeError("Bitrix graph write capability is invalid")
        token = uuid4().hex
        self._issued[token] = (method, permit_hash)
        return _BitrixGraphWriteCapability(token)

    def create(
        self,
        method: str,
        payload: dict[str, Any],
        *,
        permit_hash: str,
        capability: _BitrixGraphWriteCapability,
    ) -> dict[str, Any]:
        if method not in _CREATE_METHODS or not isinstance(payload, dict):
            raise BitrixGraphRuntimeError("Bitrix graph create is invalid")
        if type(capability) is not _BitrixGraphWriteCapability:
            raise BitrixGraphRuntimeError("Bitrix graph create requires a capability")
        record = self._issued.pop(capability._token, None)
        if record != (method, permit_hash):
            raise BitrixGraphRuntimeError("Bitrix graph write capability is stale")
        return self._transport._call_allowlisted(method, payload)

    def get(self, method: str, remote_id: str) -> dict[str, Any]:
        if method not in _GET_METHODS or not remote_id.isdigit() or int(remote_id) < 1:
            raise BitrixGraphRuntimeError("Bitrix graph get is invalid")
        return self._transport._call_allowlisted(method, {"id": remote_id})

    def lookup(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        if method not in _LIST_METHODS or not isinstance(payload, dict):
            raise BitrixGraphRuntimeError("Bitrix graph lookup is invalid")
        return self._transport._call_allowlisted(method, payload)


class BitrixGraphWriterController:
    """One-plan controller; disabled unless explicitly composed as enabled."""

    __slots__ = (
        "_boundary",
        "_mapper",
        "_preflight",
        "_writer_enabled",
        "_consumed_permits",
    )

    def __init__(
        self,
        boundary: BitrixGraphWriteBoundary,
        mapper: BitrixGraphMapper,
        live_preflight: BitrixGraphLivePreflightReport,
        *,
        writer_enabled: bool = False,
    ) -> None:
        if (
            type(boundary) is not BitrixGraphWriteBoundary
            or type(mapper) is not BitrixGraphMapper
            or type(live_preflight) is not BitrixGraphLivePreflightReport
            or type(writer_enabled) is not bool
            or boundary.portal_identity != mapper.manifest.portal_identity
            or live_preflight.portal_identity != mapper.manifest.portal_identity
            or live_preflight.manifest_hash != mapper.manifest_hash
            or live_preflight.live_preflight_ok is not True
            or live_preflight.external_writes_performed != 0
            or live_preflight.credential_owner_bound is not True
            or live_preflight.owner_approval_required is not True
            or live_preflight.canary_ready is not False
            or not _HEX64.fullmatch(live_preflight.report_hash)
        ):
            raise BitrixGraphRuntimeError("Bitrix graph writer composition is invalid")
        self._boundary = boundary
        self._mapper = mapper
        self._preflight = live_preflight
        self._writer_enabled = writer_enabled
        self._consumed_permits: set[str] = set()

    @staticmethod
    def _remote_id(envelope: dict[str, Any]) -> str:
        value = envelope.get("result") if isinstance(envelope, dict) else None
        if isinstance(value, bool):
            raise BitrixGraphWriteOutcomeUncertain()
        rendered = str(value or "")
        if not rendered.isascii() or not rendered.isdigit() or int(rendered) < 1:
            raise BitrixGraphWriteOutcomeUncertain()
        return rendered

    def _validate_permit(
        self, permit: BitrixGraphWritePermit, plan: BitrixGraphMappedCreate
    ) -> str:
        if (
            type(permit) is not BitrixGraphWritePermit
            or permit.manifest_hash != self._mapper.manifest_hash
            or permit.live_preflight_report_hash != self._preflight.report_hash
            or permit.operation_id != plan.operation_id
            or permit.mapped_plan_hash != plan.plan_hash
            or type(permit.canary_step) is not int
            or permit.canary_step not in {1, 2, 3, 4, 5}
            or type(permit.owner_approval_ref) is not str
            or not _SAFE_REF.fullmatch(permit.owner_approval_ref)
        ):
            raise BitrixGraphRuntimeError("Bitrix graph write permit is invalid")
        digest = bitrix_graph_write_permit_hash(permit)
        if permit.declared_permit_hash != digest or not _HEX64.fullmatch(digest):
            raise BitrixGraphRuntimeError("Bitrix graph write permit hash is invalid")
        if digest in self._consumed_permits:
            raise BitrixGraphRuntimeError("Bitrix graph write permit is already consumed")
        return digest

    def execute(
        self, plan: BitrixGraphMappedCreate, permit: BitrixGraphWritePermit
    ) -> CrmGraphReadback:
        if not self._writer_enabled:
            raise BitrixGraphWriterDisabled("Bitrix graph writer is disabled")
        self._mapper.validate_create_plan(plan)
        permit_hash = self._validate_permit(permit, plan)
        self._consumed_permits.add(permit_hash)
        try:
            payload = json.loads(plan.payload_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BitrixGraphRuntimeError("Bitrix graph payload is invalid") from None
        if not isinstance(payload, dict):
            raise BitrixGraphRuntimeError("Bitrix graph payload is invalid")
        capability = self._boundary._mint(plan.create_method, permit_hash)
        try:
            created = self._boundary.create(
                plan.create_method,
                payload,
                permit_hash=permit_hash,
                capability=capability,
            )
        except AmbiguousRemoteError:
            if plan.remote_entity_type == "activity":
                raise ActivityOutcomeUncertain() from None
            lookup = self._mapper.compile_lookup(plan)
            lookup_payload = json.loads(lookup.payload_json)
            page = self._boundary.lookup(lookup.list_method, lookup_payload)
            candidate = self._mapper.verify_lookup_page(lookup, page)
            if candidate is None:
                raise BitrixGraphWriteOutcomeUncertain() from None
            remote_id = candidate.remote_id
        else:
            remote_id = self._remote_id(created)
        try:
            readback = self._boundary.get(plan.expectation.get_method, remote_id)
            result = readback.get("result")
            if not isinstance(result, dict):
                raise BitrixGraphWriteOutcomeUncertain(remote_id)
            return self._mapper.verify_readback(plan, result)
        except AmbiguousRemoteError:
            if plan.remote_entity_type == "activity":
                raise ActivityOutcomeUncertain(remote_id) from None
            raise BitrixGraphWriteOutcomeUncertain(remote_id) from None


__all__ = [
    "BitrixGraphRuntimeError",
    "BitrixGraphWriteBoundary",
    "BitrixGraphWriteOutcomeUncertain",
    "BitrixGraphWritePermit",
    "BitrixGraphWriterController",
    "BitrixGraphWriterDisabled",
    "bitrix_graph_write_permit_hash",
]
