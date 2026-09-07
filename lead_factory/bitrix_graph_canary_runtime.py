"""Rate-gated, fail-closed transport for a future graph canary.

This module owns no configuration loader, worker, or activation switch.  A
caller must supply one exact graph request plus a durable validator which is
executed inside the same ``BEGIN IMMEDIATE`` barrier that spans the remote
create.  Every create, lookup, and readback consumes its own portal rate slot.
"""

from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .bitrix_graph_mapping import BitrixGraphMapper, BitrixGraphMappedCreate
from .bitrix_rate_gate import (
    BitrixPortalRateGate,
    BitrixRateGateClosed,
    BitrixRateReservation,
)
from .bitrix_rest import BitrixRestBoundary
from .crm_graph_outbox import CrmGraphCreateRequest, CrmGraphReadback
from .crm_outbox import ActivityOutcomeUncertain, AmbiguousRemoteError
from .store import CURRENT_SCHEMA_VERSION, DEFAULT_DB_PATH, FactoryStore


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_ID = re.compile(r"^lf_crm_operation_[0-9a-f]{32}$")


class BitrixGraphCanaryRuntimeError(RuntimeError):
    """The sealed graph dispatch could not be proven safe."""


class BitrixGraphCanaryCorrelationExists(BitrixGraphCanaryRuntimeError):
    """The exact create correlation is already present remotely."""


class BitrixGraphCanaryOutcomeUncertain(AmbiguousRemoteError):
    """A graph create may exist remotely and must not be repeated."""

    def __init__(self, remote_id: str = "") -> None:
        super().__init__("Bitrix graph canary outcome requires reconciliation")
        self.remote_id = str(remote_id or "")


CreateValidator = Callable[[BitrixRateReservation, sqlite3.Connection], None]


class SealedBitrixGraphCanaryTransport:
    """Exact mapper/REST/rate-gate composition for one bound graph operation."""

    __slots__ = (
        "_store",
        "_gate",
        "_boundary",
        "_mapper",
        "_store_path",
        "_portal_identity",
    )

    def __init__(
        self,
        store: FactoryStore,
        *,
        rate_gate: BitrixPortalRateGate,
        rest_boundary: BitrixRestBoundary,
        mapper: BitrixGraphMapper,
    ) -> None:
        if (
            type(store) is not FactoryStore
            or type(rate_gate) is not BitrixPortalRateGate
            or type(rate_gate.store) is not FactoryStore
            or type(rest_boundary) is not BitrixRestBoundary
            or type(mapper) is not BitrixGraphMapper
        ):
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary composition is invalid"
            )
        store_path = Path(str(store.path)).expanduser().resolve(strict=False)
        gate_path = Path(str(rate_gate.store.path)).expanduser().resolve(strict=False)
        canonical_path = Path(str(DEFAULT_DB_PATH)).expanduser().resolve(strict=False)
        if store_path != gate_path or store_path == canonical_path:
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary requires a separate schema17 control store"
            )
        store.init()
        if store.schema_version() != CURRENT_SCHEMA_VERSION:
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary control schema is invalid"
            )
        if (
            rate_gate.portal_identity != rest_boundary.portal_fingerprint
            or mapper.manifest.portal_identity != rest_boundary.portal_fingerprint
        ):
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary portal binding is invalid"
            )
        self._store = store
        self._gate = rate_gate
        self._boundary = rest_boundary
        self._mapper = mapper
        self._store_path = store_path
        self._portal_identity = rest_boundary.portal_fingerprint

    def __repr__(self) -> str:
        return "SealedBitrixGraphCanaryTransport(<redacted>)"

    __str__ = __repr__

    def _assert_composition(self) -> None:
        if (
            type(self._store) is not FactoryStore
            or type(self._gate) is not BitrixPortalRateGate
            or type(self._gate.store) is not FactoryStore
            or type(self._boundary) is not BitrixRestBoundary
            or type(self._mapper) is not BitrixGraphMapper
            or Path(str(self._store.path)).expanduser().resolve(strict=False)
            != self._store_path
            or Path(str(self._gate.store.path)).expanduser().resolve(strict=False)
            != self._store_path
            or self._gate.portal_identity != self._portal_identity
            or self._boundary.portal_fingerprint != self._portal_identity
            or self._mapper.manifest.portal_identity != self._portal_identity
            or self._store.schema_version() != CURRENT_SCHEMA_VERSION
        ):
            raise BitrixRateGateClosed("Bitrix graph canary composition changed")

    def _audit_tx(
        self,
        con: sqlite3.Connection,
        reservation: BitrixRateReservation,
        *,
        operation_id: str,
        method: str,
        action: str,
    ) -> None:
        self._store._append_event_tx(
            con,
            event_type="bitrix_graph_canary_rate_reservation_consumed",
            aggregate_type="bitrix_rate_reservation",
            aggregate_id=reservation.reservation_id,
            producer="bitrix_graph_canary_runtime",
            idempotency_key=(
                f"bitrix-graph-canary-rate:{reservation.reservation_id}"
            ),
            payload={
                "portal_identity": reservation.portal_identity,
                "fence_token": reservation.fence_token,
                "sequence_number": reservation.sequence_number,
                "operation_id": operation_id,
                "method": method,
                "action": action,
            },
            actor="bitrix_graph_canary_runtime",
        )

    def _call(
        self,
        method: str,
        payload: dict[str, Any],
        *,
        operation_id: str,
        action: str,
        create_validator: CreateValidator | None = None,
    ) -> dict[str, Any]:
        self._assert_composition()

        def validator(reservation: BitrixRateReservation, con: sqlite3.Connection) -> None:
            if type(reservation) is not BitrixRateReservation:
                raise BitrixRateGateClosed("Bitrix graph rate evidence is invalid")
            if create_validator is not None:
                create_validator(reservation, con)
            self._audit_tx(
                con,
                reservation,
                operation_id=operation_id,
                method=method,
                action=action,
            )

        def callback(_reservation: BitrixRateReservation, _con: sqlite3.Connection):
            return self._boundary._call_allowlisted(method, payload)

        return self._gate.dispatch(callback, validator=validator)

    @staticmethod
    def _remote_id(envelope: dict[str, Any]) -> str:
        value = envelope.get("result") if isinstance(envelope, dict) else None
        if isinstance(value, dict) and set(value) == {"id"}:
            value = value["id"]
        if isinstance(value, bool):
            raise BitrixGraphCanaryOutcomeUncertain()
        rendered = str(value or "")
        if not rendered.isascii() or not rendered.isdigit() or int(rendered) < 1:
            raise BitrixGraphCanaryOutcomeUncertain()
        return rendered

    def execute(
        self,
        request: CrmGraphCreateRequest,
        *,
        permit_hash: str,
        create_validator: CreateValidator,
    ) -> CrmGraphReadback:
        """Create once, then prove exact readback through separately gated calls."""
        if (
            type(request) is not CrmGraphCreateRequest
            or not _OPERATION_ID.fullmatch(request.operation_id)
            or not _HEX64.fullmatch(str(permit_hash or ""))
            or not callable(create_validator)
        ):
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary dispatch permit is invalid"
            )
        plan = self._mapper.compile_create(request)
        self._mapper.validate_create_plan(plan)
        try:
            payload = json.loads(plan.payload_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary payload is invalid"
            ) from None
        if not isinstance(payload, dict):
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary payload is invalid"
            )
        try:
            created = self._call(
                plan.create_method,
                payload,
                operation_id=plan.operation_id,
                action="CREATE",
                create_validator=create_validator,
            )
        except AmbiguousRemoteError:
            if plan.remote_entity_type == "activity":
                raise ActivityOutcomeUncertain() from None
            lookup = self._mapper.compile_lookup(plan)
            lookup_payload = json.loads(lookup.payload_json)
            page = self._call(
                lookup.list_method,
                lookup_payload,
                operation_id=plan.operation_id,
                action="RECONCILE",
            )
            candidate = self._mapper.verify_lookup_page(lookup, page)
            if candidate is None:
                raise BitrixGraphCanaryOutcomeUncertain() from None
            remote_id = candidate.remote_id
        else:
            remote_id = self._remote_id(created)
        return self._readback(plan, remote_id)

    def assert_correlation_unused(self, request: CrmGraphCreateRequest) -> None:
        """Prove the exact non-Activity correlation is absent before create."""
        if type(request) is not CrmGraphCreateRequest:
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary correlation request is invalid"
            )
        plan = self._mapper.compile_create(request)
        self._mapper.validate_create_plan(plan)
        if plan.remote_entity_type == "activity":
            return
        lookup = self._mapper.compile_lookup(plan)
        try:
            payload = json.loads(lookup.payload_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BitrixGraphCanaryRuntimeError(
                "Bitrix graph canary lookup payload is invalid"
            ) from None
        page = self._call(
            lookup.list_method,
            payload,
            operation_id=plan.operation_id,
            action="PRECREATE_LOOKUP",
        )
        candidate = self._mapper.verify_lookup_page(lookup, page)
        if candidate is not None:
            raise BitrixGraphCanaryCorrelationExists()

    def _readback(
        self, plan: BitrixGraphMappedCreate, remote_id: str
    ) -> CrmGraphReadback:
        try:
            envelope = self._call(
                plan.expectation.get_method,
                {"id": remote_id},
                operation_id=plan.operation_id,
                action="READBACK",
            )
            result = envelope.get("result")
            if not isinstance(result, dict):
                raise BitrixGraphCanaryOutcomeUncertain(remote_id)
            return self._mapper.verify_readback(plan, result)
        except AmbiguousRemoteError:
            if plan.remote_entity_type == "activity":
                raise ActivityOutcomeUncertain(remote_id) from None
            raise BitrixGraphCanaryOutcomeUncertain(remote_id) from None


__all__ = [
    "BitrixGraphCanaryCorrelationExists",
    "BitrixGraphCanaryOutcomeUncertain",
    "BitrixGraphCanaryRuntimeError",
    "CreateValidator",
    "SealedBitrixGraphCanaryTransport",
]
