"""One-shot executor for the durable Bitrix graph canary.

The controller owns admission, ordering, leases, and durable outcomes.  The
transport owns the exact mapper/REST/rate boundary.  This adapter deliberately
has no retry loop: after a claimed create, every unproved outcome remains
``UNCERTAIN`` and cannot become eligible for another create.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .bitrix_graph_canary_control import (
    BitrixGraphCanaryControl,
    GraphCanaryDispatchPermit,
    GraphCanaryWriterLease,
)
from .bitrix_graph_canary_runtime import (
    BitrixGraphCanaryOutcomeUncertain,
    BitrixGraphCanaryRuntimeError,
    SealedBitrixGraphCanaryTransport,
)
from .bitrix_graph_mapping import BitrixGraphMappingError
from .canary_control import CanaryStaleLease
from .crm_graph_outbox import GraphReadbackMismatch
from .crm_outbox import ActivityOutcomeUncertain, MappingConflict, PermanentRemoteError
from .ids import payload_hash


@dataclass(frozen=True, slots=True)
class GraphCanaryExecutionResult:
    operation_id: str
    operation_type: str
    state: str
    error_class: str = ""


class BitrixGraphCanaryExecutor:
    """Execute at most one already-admitted graph operation per call."""

    def __init__(
        self,
        control: BitrixGraphCanaryControl,
        transport: SealedBitrixGraphCanaryTransport,
    ) -> None:
        if (
            type(control) is not BitrixGraphCanaryControl
            or type(transport) is not SealedBitrixGraphCanaryTransport
        ):
            raise TypeError("sealed graph canary control and transport are required")
        if control.store is not transport._store:
            raise ValueError("graph canary control and transport store changed")
        self._control = control
        self._transport = transport

    @staticmethod
    def _permit_hash(permit: GraphCanaryDispatchPermit) -> str:
        return payload_hash(
            {
                "connector": permit.connector,
                "run_id": permit.run_id,
                "member_id": permit.member_id,
                "approval_id": permit.approval_id,
                "operation_id": permit.operation_id,
                "operation_type": permit.operation_type,
                "action": permit.action,
                "payload_hash": permit.payload_hash,
                "correlation_token": permit.correlation_token,
                "fence_token": permit.fence_token,
                "operation_lease_token": permit.operation_lease_token,
                "dependency_remote_ids": [
                    list(item) for item in permit.dependency_remote_ids
                ],
            }
        )

    def _operation(self, permit: GraphCanaryDispatchPermit) -> dict[str, Any]:
        con = self._control.store.connect()
        try:
            row = con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?",
                (permit.operation_id,),
            ).fetchone()
            if not row:
                raise CanaryStaleLease("bound graph operation disappeared")
            operation = dict(row)
        finally:
            con.close()
        if (
            str(operation["state"]) != "UNCERTAIN"
            or str(operation["operation_type"]) != permit.operation_type
            or str(operation["payload_hash"]) != permit.payload_hash
            or str(operation["correlation_token"]) != permit.correlation_token
            or str(operation["lease_token"]) != permit.operation_lease_token
        ):
            raise CanaryStaleLease("bound graph operation changed after claim")
        operation["_dependency_remote_ids"] = dict(permit.dependency_remote_ids)
        return operation

    def execute_next(
        self,
        lease: GraphCanaryWriterLease,
        *,
        actor: str,
        operation_lease_seconds: int = 120,
    ) -> GraphCanaryExecutionResult | None:
        permit = self._control.claim_next_graph_operation(
            lease, operation_lease_seconds=operation_lease_seconds
        )
        if permit is None:
            return None
        try:
            operation = self._operation(permit)
            request = self._control.graph_outbox._request(operation)

            def validator(_reservation: object, con: Any) -> None:
                self._control.assert_dispatch_permit_tx(
                    con, permit, lease, operation_id=permit.operation_id
                )

            self._transport.assert_correlation_unused(request)
            readback = self._transport.execute(
                request,
                permit_hash=self._permit_hash(permit),
                create_validator=validator,
            )
            self._control.mark_sent(permit, lease, readback, actor=actor)
            return GraphCanaryExecutionResult(
                permit.operation_id, permit.operation_type, "SENT"
            )
        except (ActivityOutcomeUncertain, BitrixGraphCanaryOutcomeUncertain) as exc:
            self._mark_uncertain_best_effort(permit, lease, exc, actor=actor)
            return GraphCanaryExecutionResult(
                permit.operation_id,
                permit.operation_type,
                "UNCERTAIN",
                type(exc).__name__,
            )
        except (
            BitrixGraphCanaryRuntimeError,
            BitrixGraphMappingError,
            GraphReadbackMismatch,
            MappingConflict,
            PermanentRemoteError,
        ) as exc:
            try:
                self._control.mark_review(
                    permit, lease, error_class=type(exc).__name__, actor=actor
                )
            except CanaryStaleLease:
                return GraphCanaryExecutionResult(
                    permit.operation_id,
                    permit.operation_type,
                    "UNCERTAIN",
                    type(exc).__name__,
                )
            return GraphCanaryExecutionResult(
                permit.operation_id,
                permit.operation_type,
                "REVIEW",
                type(exc).__name__,
            )
        except Exception as exc:
            # The transport may already have crossed the remote boundary.
            # Never infer absence and never retry a create from this state.
            self._mark_uncertain_best_effort(permit, lease, exc, actor=actor)
            return GraphCanaryExecutionResult(
                permit.operation_id,
                permit.operation_type,
                "UNCERTAIN",
                type(exc).__name__,
            )

    def _mark_uncertain_best_effort(
        self,
        permit: GraphCanaryDispatchPermit,
        lease: GraphCanaryWriterLease,
        error: Exception,
        *,
        actor: str,
    ) -> None:
        try:
            self._control.mark_uncertain(
                permit, lease, error_class=type(error).__name__, actor=actor
            )
        except CanaryStaleLease:
            # The claimed row was already UNCERTAIN.  A lost fence must not
            # turn it back into work or conceal the possible remote effect.
            pass


__all__ = ["BitrixGraphCanaryExecutor", "GraphCanaryExecutionResult"]
