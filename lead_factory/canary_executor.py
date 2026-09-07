"""Offline executor for one already-claimed, explicitly permitted canary operation.

The executor has no HTTP, environment, scheduler, or generic-queue claim path.
It can only process a :class:`CanaryDispatchPermit` that was atomically issued
for an exact canary binding.  A future Bitrix adapter is injected by the caller
and is reached only after the permit, writer fence, immutable payload and (for
Activities) exact Lead dependency have been rechecked.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .canary_control import (
    ACTIVITY_CREATE,
    LEAD_CREATE,
    CanaryControl,
    CanaryDispatchPermit,
    CanaryStaleLease,
    ConnectorWriterLease,
)
from .crm_outbox import (
    AmbiguousRemoteError,
    ActivityOutcomeUncertain,
    CrmActivityOutbox,
    CrmActivityReceipt,
    CrmOutbox,
    MappingConflict,
    PermanentRemoteError,
    RetryableRemoteError,
)
from .ids import payload_hash
from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .store import FactoryStore


class CanaryLeadTransport(Protocol):
    def create_lead(self, payload: dict[str, Any], correlation_token: str) -> str: ...


class CanaryLeadReconcileTransport(Protocol):
    def find_lead_by_correlation_token(self, correlation_token: str) -> str | None: ...


class CanaryActivityTransport(Protocol):
    def create_activity(self, lead_remote_id: str, payload: dict[str, Any]) -> CrmActivityReceipt: ...


@dataclass(frozen=True)
class CanaryExecutionResult:
    operation_id: str
    state: str
    remote_entity_id: str = ""
    error_class: str = ""
    transport_called: bool = False


class CanaryExecutor:
    """Execute exactly one durable permit; never claim or scan generic work."""

    def __init__(self, store: FactoryStore, control: CanaryControl):
        if control.store is not store and str(control.store.path) != str(store.path):
            raise ValueError("canary executor and control must use the same FactoryStore")
        self.store = store
        self.control = control
        # These existing local state-transition primitives are used only after
        # the scoped permit checks below.  They do not claim or dispatch work.
        self.leads = CrmOutbox(store)
        self.activities = CrmActivityOutbox(store)

    def execute_lead(
        self,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        transport: CanaryLeadTransport,
        *,
        before_transport_hook: Callable[[], None] | None = None,
        after_remote_hook: Callable[[], None] | None = None,
    ) -> CanaryExecutionResult:
        """Dispatch one already-claimed Lead, preserving lead ambiguity semantics."""
        self._require_type(permit, LEAD_CREATE, "CREATE")
        called = False
        try:
            operation, payload = self._load_exact_operation(permit, lease)
            self._audit("started", permit)
            mapping = self._existing_lead_mapping(operation)
            if mapping:
                # No remote request: an earlier exact local mapping is stronger
                # proof than a second create attempt.
                self.control.assert_dispatch_permit(permit, lease, operation_id=permit.operation_id)
                result = self.leads._mark_sent(operation, mapping)
                self._safe_audit("outcome", permit, state=result.state)
                return self._result(result, called)
            if before_transport_hook:
                before_transport_hook()
            # This is deliberately the last step before the injected boundary.
            operation, payload = self._load_exact_operation(permit, lease)
            assert_external_allowed("bitrix.canary.lead.create")
            called = True
            remote_id = transport.create_lead(payload, permit.correlation_token)
            if after_remote_hook:
                after_remote_hook()
            # A stop/fence mutation after a remote call must not make another
            # create possible.  The handler below leaves a Lead UNCERTAIN so it
            # can only be reconciled by correlation, never blindly re-added.
            self.control.assert_dispatch_permit(permit, lease, operation_id=permit.operation_id)
            result = self.leads._mark_sent(operation, remote_id)
            self._safe_audit("outcome", permit, state=result.state)
            return self._result(result, called)
        except CanaryStaleLease as exc:
            if called:
                result = self.leads._set_failure(
                    self._operation_for_failure(permit), state="UNCERTAIN", error=exc,
                    producer="canary_executor",
                )
                self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
                return self._result(result, called)
            self._safe_audit("blocked", permit, state="BLOCKED", error_class=type(exc).__name__)
            return CanaryExecutionResult(permit.operation_id, "BLOCKED", error_class=type(exc).__name__, transport_called=False)
        except ExternalAuthorityError as exc:
            released = self.leads._set_failure(
                self._operation_for_failure(permit), state="PENDING", error=exc,
                producer="canary_executor",
            )
            if released.state == "STALE":
                return self._result(released, called)
            self._safe_audit(
                "blocked", permit, state="BLOCKED", error_class=type(exc).__name__
            )
            return CanaryExecutionResult(
                permit.operation_id,
                "BLOCKED",
                error_class=type(exc).__name__,
                transport_called=False,
            )
        except RetryableRemoteError as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit),
                state="PENDING",
                error=exc,
                retry_after_seconds=30,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except MappingConflict as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="CONFLICT_REVIEW", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except PermanentRemoteError as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="DEAD", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except Exception as exc:
            # A lost response, an adapter failure, or a crash simulated after a
            # remote success remains ambiguous.  Do not issue another add.
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="UNCERTAIN", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)

    def execute_activity(
        self,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        transport: CanaryActivityTransport,
        *,
        before_transport_hook: Callable[[], None] | None = None,
        after_remote_hook: Callable[[], None] | None = None,
    ) -> CanaryExecutionResult:
        """Dispatch one Activity only against its exact sent and mapped Lead."""
        self._require_type(permit, ACTIVITY_CREATE, "CREATE")
        called = False
        activity_remote_id = ""
        try:
            operation, payload, lead_remote_id = self._load_exact_activity(permit, lease)
            self._audit("started", permit)
            if before_transport_hook:
                before_transport_hook()
            # Rebuild all proof after the hook; this is the last local action
            # before the injected Activity transport.
            operation, payload, lead_remote_id = self._load_exact_activity(permit, lease)
            assert_external_allowed("bitrix.canary.activity.create")
            called = True
            receipt = transport.create_activity(lead_remote_id, payload)
            remote_id = self._verified_activity_receipt(receipt, expected_owner_lead_id=lead_remote_id)
            activity_remote_id = remote_id
            if after_remote_hook:
                after_remote_hook()
            self._load_exact_activity(permit, lease)
            result = self.activities._mark_sent(operation, remote_id)
            self._safe_audit("outcome", permit, state=result.state)
            return self._result(result, called)
        except CanaryStaleLease as exc:
            # Before a call this is a clean block; after a call it is ambiguous
            # because Bitrix Activities have no immutable correlation lookup.
            state = "REVIEW" if called else "BLOCKED"
            if called:
                result = self.leads._set_failure(
                    self._operation_for_failure(permit), state="REVIEW",
                    error=ActivityOutcomeUncertain(activity_remote_id),
                    producer="canary_executor",
                )
                state = result.state
            self._safe_audit("blocked" if not called else "outcome", permit, state=state, error_class=type(exc).__name__)
            return CanaryExecutionResult(permit.operation_id, state, error_class=type(exc).__name__, transport_called=called)
        except ExternalAuthorityError as exc:
            released = self.leads._set_failure(
                self._operation_for_failure(permit), state="PENDING", error=exc,
                producer="canary_executor",
            )
            if released.state == "STALE":
                return self._result(released, called)
            self._safe_audit(
                "blocked", permit, state="BLOCKED", error_class=type(exc).__name__
            )
            return CanaryExecutionResult(
                permit.operation_id,
                "BLOCKED",
                error_class=type(exc).__name__,
                transport_called=False,
            )
        except RetryableRemoteError as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="PENDING", error=exc,
                retry_after_seconds=30, producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except MappingConflict as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="CONFLICT_REVIEW", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except PermanentRemoteError as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="DEAD", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except Exception as exc:
            # An Activity's remote success cannot be safely reconciled by a
            # correlation token.  Any ambiguous result is terminal REVIEW.
            error = ActivityOutcomeUncertain(
                activity_remote_id or str(getattr(exc, "remote_id", "") or "")
            )
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="REVIEW", error=error,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)

    def reconcile_lead(
        self,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        transport: CanaryLeadReconcileTransport,
        *,
        before_lookup_hook: Callable[[], None] | None = None,
        after_lookup_hook: Callable[[], None] | None = None,
    ) -> CanaryExecutionResult:
        """Correlation-only reconcile for an exact already-uncertain Lead.

        A ``RECONCILE`` permit is distinct from a CREATE permit, so no caller
        can accidentally turn a lost response into another add request.
        """
        self._require_type(permit, LEAD_CREATE, "RECONCILE")
        called = False
        try:
            operation, _ = self._load_exact_operation(permit, lease)
            self._audit("started", permit)
            if before_lookup_hook:
                before_lookup_hook()
            operation, _ = self._load_exact_operation(permit, lease)
            assert_external_allowed("bitrix.canary.lead.reconcile")
            called = True
            remote_id = transport.find_lead_by_correlation_token(permit.correlation_token)
            if after_lookup_hook:
                after_lookup_hook()
            self.control.assert_dispatch_permit(permit, lease, operation_id=permit.operation_id)
            if remote_id:
                result = self.leads._mark_sent(operation, remote_id)
            else:
                reconcile_count = self._reconcile_count(permit.operation_id)
                if reconcile_count >= self.leads.max_reconcile_attempts:
                    result = self.leads._set_failure(
                        self._operation_for_failure(permit), state="REVIEW",
                        error=AmbiguousRemoteError("correlation token not found after bounded reconcile"),
                        producer="canary_executor",
                    )
                else:
                    delay = min(3600, 60 * (2 ** min(reconcile_count - 1, 5)))
                    result = self.leads._set_failure(
                        self._operation_for_failure(permit), state="UNCERTAIN",
                        error=AmbiguousRemoteError("correlation token not found yet"),
                        retry_after_seconds=delay,
                        producer="canary_executor",
                    )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except CanaryStaleLease as exc:
            self._safe_audit("blocked", permit, state="BLOCKED", error_class=type(exc).__name__)
            return CanaryExecutionResult(permit.operation_id, "BLOCKED", error_class=type(exc).__name__, transport_called=called)
        except ExternalAuthorityError as exc:
            released = self.leads._set_failure(
                self._operation_for_failure(permit),
                state="UNCERTAIN",
                error=exc,
                retry_after_seconds=120,
                producer="canary_executor",
            )
            if released.state == "STALE":
                return self._result(released, called)
            self._safe_audit(
                "blocked", permit, state="BLOCKED", error_class=type(exc).__name__
            )
            return CanaryExecutionResult(
                permit.operation_id,
                "BLOCKED",
                error_class=type(exc).__name__,
                transport_called=False,
            )
        except MappingConflict as exc:
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="CONFLICT_REVIEW", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except PermanentRemoteError as exc:
            # A permanent lookup failure cannot prove that the earlier create
            # did not succeed.  Keep the existing ambiguity for a human rather
            # than retrying lookups indefinitely or issuing a new create.
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="REVIEW", error=exc,
                producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)
        except Exception as exc:
            result = self._bounded_reconcile_failure(permit, exc)
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, called)

    def finalize_expired_activity(
        self,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
    ) -> CanaryExecutionResult:
        """Move an expired ambiguous Activity to REVIEW without any transport."""
        self._require_type(permit, ACTIVITY_CREATE, "ACTIVITY_REVIEW")
        try:
            self._load_exact_operation(permit, lease)
            self._audit("started", permit)
            # The permit recheck is immediately before the only state change;
            # no network boundary exists in this terminal path.
            self.control.assert_dispatch_permit(permit, lease, operation_id=permit.operation_id)
            result = self.leads._set_failure(
                self._operation_for_failure(permit), state="REVIEW",
                error=ActivityOutcomeUncertain(), producer="canary_executor",
            )
            self._safe_audit("outcome", permit, state=result.state, error_class=result.error_class)
            return self._result(result, False)
        except CanaryStaleLease as exc:
            self._safe_audit("blocked", permit, state="BLOCKED", error_class=type(exc).__name__)
            return CanaryExecutionResult(permit.operation_id, "BLOCKED", error_class=type(exc).__name__)
        except Exception as exc:
            # A local failure cannot justify a remote retry.  If the operation
            # is still owned, the next explicit expired-review permit can retry
            # only this terminal local transition.
            self._safe_audit("outcome", permit, state="REVIEW", error_class=type(exc).__name__)
            return CanaryExecutionResult(permit.operation_id, "REVIEW", error_class=type(exc).__name__)

    def _load_exact_operation(
        self, permit: CanaryDispatchPermit, lease: ConnectorWriterLease
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self.control.assert_dispatch_permit(permit, lease, operation_id=permit.operation_id)
        self.store.init()
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT o.*,b.operation_type AS binding_operation_type
                   FROM crm_outbox o JOIN canary_operation_bindings b ON b.operation_id=o.operation_id
                   WHERE o.operation_id=?""",
                (permit.operation_id,),
            ).fetchone()
        finally:
            con.close()
        if not row:
            raise CanaryStaleLease("claimed canary operation no longer exists")
        operation = dict(row)
        if (
            operation["operation_type"] != permit.operation_type
            or operation["binding_operation_type"] != permit.operation_type
            or operation["payload_hash"] != permit.payload_hash
            or operation["correlation_token"] != permit.correlation_token
            or operation["leased_by"] != lease.owner_id
            or operation["lease_token"] != permit.operation_lease_token
        ):
            raise CanaryStaleLease("claimed canary operation identity changed")
        try:
            payload = json.loads(str(operation["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CanaryStaleLease("claimed canary payload is not valid immutable JSON") from exc
        if not isinstance(payload, dict) or payload_hash(payload) != permit.payload_hash:
            raise CanaryStaleLease("claimed canary payload hash changed")
        return operation, payload

    def _load_exact_activity(
        self, permit: CanaryDispatchPermit, lease: ConnectorWriterLease) -> tuple[dict[str, Any], dict[str, Any], str]:
        operation, payload = self._load_exact_operation(permit, lease)
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT l.operation_id,l.operation_type,l.state,l.remote_entity_type,l.remote_entity_id,
                           lb.run_id AS bound_run_id,lb.member_id AS bound_member_id,
                           m.lf_entity_id AS exact_mapping_id
                   FROM crm_outbox l
                   JOIN canary_operation_bindings lb ON lb.operation_id=l.operation_id
                   LEFT JOIN crm_mappings m
                     ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                    AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id AND m.state='ACTIVE'
                   WHERE l.operation_id=?""",
                (operation["dependency_operation_id"],),
            ).fetchone()
        finally:
            con.close()
        if (
            not row or row["operation_type"] != LEAD_CREATE or row["state"] != "SENT"
            or row["remote_entity_type"] != "lead" or not row["remote_entity_id"]
            or not row["exact_mapping_id"] or row["bound_run_id"] != permit.run_id
            or row["bound_member_id"] != permit.member_id
        ):
            raise CanaryStaleLease("Activity no longer has its exact sent Lead dependency")
        # CrmActivityOutbox._mark_sent repeats this equality in its transaction
        # as a final race check.  Generic selectors populate this derived value
        # on their claimed row; the canary never uses that selector, so provide
        # the same already-proven value explicitly.
        operation = dict(operation)
        operation["dependency_remote_entity_id"] = str(row["remote_entity_id"])
        return operation, payload, str(row["remote_entity_id"])

    def _existing_lead_mapping(self, operation: dict[str, Any]) -> str:
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT remote_entity_id FROM crm_mappings
                   WHERE lf_entity_type=? AND lf_entity_id=? AND remote_entity_type='lead' AND state='ACTIVE'""",
                (operation["lf_entity_type"], operation["lf_entity_id"]),
            ).fetchone()
        finally:
            con.close()
        return str(row["remote_entity_id"]) if row else ""

    @staticmethod
    def _verified_activity_receipt(value: Any, *, expected_owner_lead_id: str) -> str:
        if not isinstance(value, CrmActivityReceipt):
            raise ActivityOutcomeUncertain()
        remote_id = str(value.remote_id or "").strip()
        owner = str(value.owner_lead_id or "").strip()
        if (
            not remote_id.isdigit() or int(remote_id) <= 0
            or not value.readback_verified or owner != str(expected_owner_lead_id)
        ):
            raise ActivityOutcomeUncertain(remote_id)
        return remote_id

    @staticmethod
    def _require_type(
        permit: CanaryDispatchPermit, operation_type: str, action: str
    ) -> None:
        if (
            not isinstance(permit, CanaryDispatchPermit)
            or permit.operation_type != operation_type
            or permit.action != action
        ):
            raise CanaryStaleLease("canary permit has the wrong operation type")

    def _operation_for_failure(self, permit: CanaryDispatchPermit) -> dict[str, Any]:
        """Get only the lease identity needed by proven local transition code."""
        return {
            "operation_id": permit.operation_id,
            "lease_token": permit.operation_lease_token,
        }

    def _audit(
        self,
        phase: str,
        permit: CanaryDispatchPermit,
        *,
        state: str = "",
        error_class: str = "",
    ) -> None:
        """Append audit metadata only; never copy payload, address, or PII."""
        self.store.append_event(
            event_type=f"canary_executor_{phase}",
            aggregate_type="crm_operation",
            aggregate_id=permit.operation_id,
            producer="canary_executor",
            idempotency_key=(
                f"canary-executor:{phase}:{permit.operation_id}:"
                f"{permit.operation_lease_token}:{state}:{error_class}"
            ),
            payload={
                "operation_id": permit.operation_id,
                "operation_type": permit.operation_type,
                "action": permit.action,
                "run_id": permit.run_id,
                "member_id": permit.member_id,
                "approval_id": permit.approval_id,
                "fence_token": permit.fence_token,
                "state": state,
                "error_class": error_class,
            },
            actor="canary_executor",
        )

    def _safe_audit(self, *args: Any, **kwargs: Any) -> None:
        """Never let a post-transition audit failure alter a committed result."""
        try:
            self._audit(*args, **kwargs)
        except Exception:
            # The result has already been committed by the outbox primitive.
            # A later audit repair can identify the operation from that durable
            # state; retrying or changing it here would be unsafe.
            return

    def _reconcile_count(self, operation_id: str) -> int:
        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT reconcile_count FROM crm_outbox WHERE operation_id=?", (operation_id,)
            ).fetchone()
        finally:
            con.close()
        if not row:
            raise CanaryStaleLease("reconcile operation no longer exists")
        return int(row["reconcile_count"])

    def _bounded_reconcile_failure(
        self, permit: CanaryDispatchPermit, error: Exception
    ) -> Any:
        """Retry only a bounded number of ambiguous correlation lookups."""
        reconcile_count = self._reconcile_count(permit.operation_id)
        if reconcile_count >= self.leads.max_reconcile_attempts:
            return self.leads._set_failure(
                self._operation_for_failure(permit), state="REVIEW", error=error,
                producer="canary_executor",
            )
        delay = min(3600, 60 * (2 ** min(reconcile_count - 1, 5)))
        return self.leads._set_failure(
            self._operation_for_failure(permit), state="UNCERTAIN", error=error,
            retry_after_seconds=delay, producer="canary_executor",
        )

    @staticmethod
    def _result(result: Any, called: bool) -> CanaryExecutionResult:
        return CanaryExecutionResult(
            str(result.operation_id),
            str(result.state),
            str(getattr(result, "remote_entity_id", "") or ""),
            str(getattr(result, "error_class", "") or ""),
            called,
        )


__all__ = [
    "CanaryActivityTransport",
    "CanaryExecutionResult",
    "CanaryExecutor",
    "CanaryLeadTransport",
    "CanaryLeadReconcileTransport",
]
