"""Sealed offline composition for the one-record Bitrix canary.

This module is intentionally not a worker, CLI, scheduler, configuration
loader, or HTTP client.  It composes the already-approved injected REST
boundary with the single durable portal rate gate and the two allowlisted
adapters.  It never enables external writers; the durable canary controller
must already have granted the exact permit and writer lease before a caller
can invoke a dispatch method.

The generic :mod:`canary_executor` remains transport-agnostic for offline
tests.  A future live caller must use ``SealedBitrixCanaryRuntime`` instead:
its public dispatch methods do not accept arbitrary transport objects.

This composition reduces accidental bypasses but is not a Python security
sandbox.  The live write credential must be isolated by the OS in the single
approved worker process and must not be available to other local code.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
import re

from .bitrix_activity import BitrixActivityAdapter
from .bitrix_canary import BitrixCanaryConfig, BitrixLeadCanaryAdapter
from .bitrix_rate_gate import (
    BitrixPortalRateGate,
    BitrixRateGateClosed,
    BitrixRateReservation,
)
from .bitrix_rest import (
    ALLOWED_METHODS,
    BitrixRestBoundary,
    BitrixRestBoundaryError,
    WRITE_METHODS,
)
from .canary_control import (
    BITRIX_CANARY_CONNECTOR,
    CanaryControl,
    CanaryDispatchPermit,
    ConnectorWriterLease,
)
from .canary_executor import CanaryExecutionResult, CanaryExecutor
from .store import DEFAULT_DB_PATH, FactoryStore


class CanaryRuntimeCompositionError(ValueError):
    """The supplied objects cannot form the one approved Bitrix path."""


def _store_path(store: FactoryStore) -> Path:
    return Path(str(store.path)).expanduser().resolve(strict=False)


def _default_stage_path() -> Path:
    """Return the one database watched by legacy HOLD guards.

    Tests may patch this module-level imported constant to a temporary stage
    file.  Production construction receives no override and therefore cannot
    compose a canary against an isolated SQLite database.
    """
    return Path(str(DEFAULT_DB_PATH)).expanduser().resolve(strict=False)


class _AuditedPortalGate:
    """One approved gate that defers an adapter's rate request to REST edge.

    Adapters have a deliberately narrow ``reserve(); rest.call(...)`` protocol.
    In the sealed runtime ``reserve`` only records that the next in-scope call
    must take a rate slot.  The exact method is known only at ``rest.call``:
    read calls use a normal reservation, while writes use the gate's dispatch
    barrier.  That barrier spans final permit validation through the actual
    session request, so ``stop_run`` cannot commit in between.
    """

    __slots__ = (
        "_store",
        "_gate",
        "_boundary",
        "_scope_var",
        "_expected_store_path",
        "_expected_portal_identity",
    )

    def __init__(
        self,
        store: FactoryStore,
        gate: BitrixPortalRateGate,
        boundary: BitrixRestBoundary,
        scope_var: ContextVar["_DispatchScope | None"],
    ) -> None:
        self._store = store
        self._gate = gate
        self._boundary = boundary
        self._scope_var = scope_var
        self._expected_store_path = _store_path(store)
        self._expected_portal_identity = boundary.portal_fingerprint

    def _assert_composition_intact(self) -> None:
        """Recheck mutable injected objects immediately before rate dispatch."""
        if (
            type(self._store) is not FactoryStore
            or type(self._gate) is not BitrixPortalRateGate
            or type(self._gate.store) is not FactoryStore
            or type(self._boundary) is not BitrixRestBoundary
            or _store_path(self._store) != self._expected_store_path
            or _store_path(self._gate.store) != self._expected_store_path
            or self._expected_store_path != _default_stage_path()
        ):
            raise BitrixRateGateClosed("sealed Bitrix database binding changed")
        if (
            self._gate.portal_identity != self._expected_portal_identity
            or self._boundary.portal_fingerprint != self._expected_portal_identity
        ):
            raise BitrixRateGateClosed("sealed Bitrix portal binding changed")

    def reserve(self) -> None:
        scope = self._scope_var.get()
        if scope is None:
            raise BitrixRateGateClosed("sealed Bitrix dispatch has no active scope")
        scope.note_rate_request()

    def dispatch(
        self,
        callback,
        *,
        operation_id: str,
        method: str,
        action: str,
        validator=None,
    ):
        """Run one write callback inside the raw gate's SQLite barrier.

        ``callback(reservation, con)`` receives the same transaction holding
        the dispatch admission.  It must not open a second store transaction
        for a safety check which is meant to be linear with this write.
        """
        audit_operation_id = str(operation_id or "").strip()
        audit_method = str(method or "").strip()
        audit_action = str(action or "").strip().upper()
        if not re.fullmatch(r"lf_crm_operation_[0-9a-f]{32}", audit_operation_id):
            raise BitrixRateGateClosed("canary rate audit requires an opaque operation id")
        if audit_method not in ALLOWED_METHODS:
            raise BitrixRateGateClosed("canary rate audit method is not allowlisted")
        if audit_action not in {"CREATE", "RECONCILE", "ACTIVITY_REVIEW"}:
            raise BitrixRateGateClosed("canary rate audit action is invalid")

        def _validator(reservation: BitrixRateReservation, con):
            if type(reservation) is not BitrixRateReservation:
                raise BitrixRateGateClosed("Bitrix gate returned an invalid reservation")
            if validator is not None:
                validator(reservation, con)
            self._append_reservation_audit_tx(
                con,
                reservation,
                operation_id=audit_operation_id,
                method=audit_method,
                action=audit_action,
            )

        def _audited_callback(reservation: BitrixRateReservation, con):
            if type(reservation) is not BitrixRateReservation:
                raise BitrixRateGateClosed("Bitrix gate returned an invalid reservation")
            return callback(reservation, con)

        self._assert_composition_intact()
        return self._gate.dispatch(_audited_callback, validator=_validator)

    def _append_reservation_audit_tx(
        self,
        con,
        reservation: BitrixRateReservation,
        *,
        operation_id: str,
        method: str,
        action: str,
    ) -> None:
        self._store._append_event_tx(
            con,
            event_type="bitrix_canary_rate_reservation_consumed",
            aggregate_type="bitrix_rate_reservation",
            aggregate_id=reservation.reservation_id,
            producer="bitrix_canary_runtime",
            idempotency_key=(
                f"bitrix-canary-rate-reservation:{reservation.reservation_id}"
            ),
            payload={
                "portal_identity": reservation.portal_identity,
                "fence_token": reservation.fence_token,
                "reservation_id": reservation.reservation_id,
                "sequence_number": reservation.sequence_number,
                "operation_id": operation_id,
                "method": method,
                "action": action,
            },
            actor="canary_runtime",
        )


@dataclass
class _DispatchScope:
    """Per-dispatch context; it never contains payload, address, or webhook."""

    permit: CanaryDispatchPermit
    lease: ConnectorWriterLease
    rate_request_pending: bool = False

    def note_rate_request(self) -> None:
        if self.rate_request_pending:
            raise BitrixRateGateClosed("previous Bitrix rate request was not consumed")
        self.rate_request_pending = True

    def take_rate_request(self) -> bool:
        pending = self.rate_request_pending
        self.rate_request_pending = False
        return pending


class _CapabilityBoundRest:
    """Adapter-facing REST facade that can mint a write token only in scope."""

    __slots__ = ("_boundary", "_control", "_gate", "_scope_var")

    def __init__(
        self,
        boundary: BitrixRestBoundary,
        control: CanaryControl,
        gate: _AuditedPortalGate,
        scope_var: ContextVar[_DispatchScope | None],
    ) -> None:
        self._boundary = boundary
        self._control = control
        self._gate = gate
        self._scope_var = scope_var

    def call(self, method: str, payload: dict) -> dict:
        safe_method = str(method or "").strip()
        if safe_method not in ALLOWED_METHODS:
            raise BitrixRestBoundaryError("sealed Bitrix method is not allowlisted")
        scope = self._scope_var.get()
        has_rate_request = scope.take_rate_request() if scope is not None else False
        if scope is None or not has_rate_request:
            # Runtime adapters may not bypass the shared portal gate even for
            # a read.  Boundary/preflight read APIs stay independently usable;
            # a sealed dispatch read must retain its durable audit trail.
            raise BitrixRestBoundaryError(
                "sealed Bitrix dispatch requires an audited rate reservation"
            )
        if safe_method in WRITE_METHODS:
            # ``dispatch`` holds the raw gate's BEGIN IMMEDIATE transaction
            # from final permit verification through ``session.request``. A
            # stop that committed first is seen by assert_dispatch_permit_tx;
            # a stop that starts later must wait until this exact request has
            # crossed (or failed before) the boundary.
            def _verify_inside_barrier(reservation: BitrixRateReservation, con):
                self._control.assert_dispatch_permit_tx(
                    con, scope.permit, scope.lease,
                    operation_id=scope.permit.operation_id,
                )

            def _write_inside_barrier(reservation: BitrixRateReservation, con):
                capability = self._boundary._mint_write_capability(
                    method=safe_method,
                    operation_id=scope.permit.operation_id,
                    action=scope.permit.action,
                    fence_token=scope.lease.fence_token,
                    reservation_id=reservation.reservation_id,
                    reservation_sequence=reservation.sequence_number,
                )
                return self._boundary.call(
                    safe_method, payload, write_capability=capability
                )

            return self._gate.dispatch(
                _write_inside_barrier,
                operation_id=scope.permit.operation_id,
                method=safe_method,
                action=scope.permit.action,
                validator=_verify_inside_barrier,
            )
        # Reads use the *same* dispatch barrier, although they deliberately
        # receive no writer validator or capability.  A readback/reconcile
        # remains allowed after a stopped write, but it cannot start beside a
        # different worker's in-flight write and violate Bitrix's shared
        # portal spacing.
        def _read_inside_barrier(_reservation: BitrixRateReservation, _con):
            return self._boundary.call(safe_method, payload)

        return self._gate.dispatch(
            _read_inside_barrier,
            operation_id=scope.permit.operation_id,
            method=safe_method,
            action=scope.permit.action,
        )


class SealedBitrixCanaryRuntime:
    """The only composed path from a canary permit to Bitrix adapters.

    It accepts exact concrete implementations rather than structural
    ``Protocol`` lookalikes.  This prevents a caller from supplying a fake rate
    gate, an arbitrary REST-shaped object, a second portal bucket, or another
    SQLite store to a production-shaped runner.
    """

    __slots__ = (
        "_store",
        "_control",
        "_executor",
        "_lead_adapter",
        "_activity_adapter",
        "_scope_var",
    )

    def __init__(
        self,
        store: FactoryStore,
        control: CanaryControl,
        *,
        rate_gate: BitrixPortalRateGate,
        rest_boundary: BitrixRestBoundary,
        lead_config: BitrixCanaryConfig,
    ) -> None:
        if type(store) is not FactoryStore:
            raise CanaryRuntimeCompositionError("runtime requires the FactoryStore")
        if type(control) is not CanaryControl:
            raise CanaryRuntimeCompositionError("runtime requires the CanaryControl")
        if type(rate_gate) is not BitrixPortalRateGate:
            raise CanaryRuntimeCompositionError("runtime requires BitrixPortalRateGate")
        if type(rest_boundary) is not BitrixRestBoundary:
            raise CanaryRuntimeCompositionError("runtime requires BitrixRestBoundary")
        if type(lead_config) is not BitrixCanaryConfig:
            raise CanaryRuntimeCompositionError("runtime requires BitrixCanaryConfig")
        expected_path = _store_path(store)
        if expected_path != _default_stage_path():
            raise CanaryRuntimeCompositionError(
                "runtime must use the single default stage database"
            )
        if _store_path(control.store) != expected_path:
            raise CanaryRuntimeCompositionError("controller must use the runtime stage database")
        if _store_path(rate_gate.store) != expected_path:
            raise CanaryRuntimeCompositionError("rate gate must use the runtime stage database")
        if control.connector != BITRIX_CANARY_CONNECTOR:
            raise CanaryRuntimeCompositionError("runtime requires the Bitrix canary connector")
        if rate_gate.portal_identity != rest_boundary.portal_fingerprint:
            raise CanaryRuntimeCompositionError("rate gate belongs to another portal identity")

        # Safe local initialisation only.  This does not touch the writer gate;
        # it remains default-off until an independent approval path changes it.
        store.init()
        self._store = store
        self._control = control
        self._scope_var: ContextVar[_DispatchScope | None] = ContextVar(
            "sealed_bitrix_canary_dispatch_scope", default=None
        )
        audited_gate = _AuditedPortalGate(
            store, rate_gate, rest_boundary, self._scope_var
        )
        sealed_rest = _CapabilityBoundRest(
            rest_boundary, control, audited_gate, self._scope_var
        )
        self._lead_adapter = BitrixLeadCanaryAdapter(
            sealed_rest, audited_gate, lead_config
        )
        self._activity_adapter = BitrixActivityAdapter(sealed_rest, audited_gate)
        self._executor = CanaryExecutor(store, control)

    def __repr__(self) -> str:
        return "SealedBitrixCanaryRuntime(adapters=approved)"

    __str__ = __repr__

    def dispatch_lead(
        self, permit: CanaryDispatchPermit, lease: ConnectorWriterLease
    ) -> CanaryExecutionResult:
        """Dispatch one already-claimed CREATE Lead through the sealed path."""
        return self._within_scope(
            permit, lease, self._executor.execute_lead, self._lead_adapter
        )

    def reconcile_lead(
        self, permit: CanaryDispatchPermit, lease: ConnectorWriterLease
    ) -> CanaryExecutionResult:
        """Correlation-only Lead reconcile through the sealed approved adapter."""
        return self._within_scope(
            permit, lease, self._executor.reconcile_lead, self._lead_adapter
        )

    def dispatch_activity(
        self, permit: CanaryDispatchPermit, lease: ConnectorWriterLease
    ) -> CanaryExecutionResult:
        """Dispatch one exact dependent Activity through the sealed path."""
        return self._within_scope(
            permit, lease, self._executor.execute_activity, self._activity_adapter
        )

    def finalize_expired_activity(
        self, permit: CanaryDispatchPermit, lease: ConnectorWriterLease
    ) -> CanaryExecutionResult:
        """Locally terminal-review an expired Activity; this never calls REST."""
        return self._executor.finalize_expired_activity(permit, lease)

    def _within_scope(self, permit, lease, executor_call, adapter) -> CanaryExecutionResult:
        token: Token[_DispatchScope | None] = self._scope_var.set(
            _DispatchScope(permit, lease)
        )
        try:
            return executor_call(permit, lease, adapter)
        finally:
            self._scope_var.reset(token)


__all__ = [
    "CanaryRuntimeCompositionError",
    "SealedBitrixCanaryRuntime",
]
