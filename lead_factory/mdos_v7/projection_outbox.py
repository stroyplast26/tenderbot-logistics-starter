"""Durable, ledger-backed Bitrix shadow projection outbox."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .authority import authority_snapshot
from .consent_suppression import seal_internal_record
from .contracts import value_sha256
from .internal_contracts import InternalContractRegistry
from .policy import PermitError, PermitService
from .store import (
    AppendResult,
    MdosStore,
    SchemaIntegrityError,
    UnknownWriterError,
    WriterRoleError,
)


LEASE_SECONDS = 30


class ProjectionOutboxError(RuntimeError):
    """Base durable projection lifecycle error."""


class ProjectionLeaseError(ProjectionOutboxError):
    """Another worker owns an unexpired append-only claim."""


class ProjectionDispatchBlocked(ProjectionOutboxError):
    """The command reached a terminal fail-closed DLQ state."""


@dataclass(frozen=True)
class OutboxEnqueueResult:
    command_id: str
    entry_id: str
    disposition: str


@dataclass(frozen=True)
class OutboxDispatchResult:
    command_id: str
    projection_id: str
    projection_key: str
    inserted: bool
    outcome: str
    attempt_no: int
    external_effect_count: int = 0
    transport_call_count: int = 0
    mode: str = "SHADOW"


def system_utc_clock() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _utc_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ProjectionOutbox:
    """Append commands/claims/attempts and atomically commit shadow receipts."""

    def __init__(
        self,
        store: MdosStore,
        permits: PermitService,
        *,
        clock: Callable[[], str] = system_utc_clock,
    ) -> None:
        self.store = store
        self.permits = permits
        self.clock = clock
        self.contracts = InternalContractRegistry()

    def _now(self) -> str:
        value = str(self.clock())
        _parse_utc(value)
        if not value.endswith("Z"):
            raise ProjectionOutboxError("trusted outbox clock must return UTC Z")
        return value

    def _assert_authority(
        self,
        *,
        operation: str,
        actor_id: str,
        trace_id: str,
        at_utc: str,
        payload: Mapping[str, Any],
    ) -> None:
        try:
            authority_snapshot()
        except Exception as exc:
            self.store.record_denial(
                operation=operation,
                attempted_actor_id=actor_id,
                reason_code="AUTHORITY_SNAPSHOT_INVALID",
                payload_sha256=value_sha256(dict(payload)),
                trace_id=trace_id,
                recorded_at_utc=at_utc,
            )
            raise ProjectionDispatchBlocked("AUTHORITY_SNAPSHOT_INVALID") from exc

    def _deny(
        self,
        *,
        operation: str,
        actor_id: str,
        reason_code: str,
        trace_id: str,
        at_utc: str,
        payload: Mapping[str, Any],
    ) -> None:
        self.store.record_denial(
            operation=operation,
            attempted_actor_id=actor_id,
            reason_code=reason_code,
            payload_sha256=value_sha256(dict(payload)),
            trace_id=trace_id,
            recorded_at_utc=at_utc,
        )

    def _require_projector(
        self,
        *,
        actor_id: str,
        operation: str,
        trace_id: str,
        at_utc: str,
        payload: Mapping[str, Any],
    ) -> None:
        try:
            self.store.require_actor(actor_id, "BITRIX_PROJECTION_WRITER")
        except (UnknownWriterError, WriterRoleError) as exc:
            self._deny(
                operation=operation,
                actor_id=actor_id,
                reason_code=(
                    "UNKNOWN_WRITER"
                    if isinstance(exc, UnknownWriterError)
                    else "WRITER_ROLE_DENIED"
                ),
                trace_id=trace_id,
                at_utc=at_utc,
                payload=payload,
            )
            raise

    def _payloads(self, record_type: str, command_id: str) -> list[dict[str, Any]]:
        return [
            dict(row["payload"])
            for row in self.store.records(record_type)
            if row["payload"].get("command_id") == command_id
        ]

    def command(self, command_id: str) -> dict[str, Any] | None:
        row = self.store.latest_record("BITRIX_PROJECTION_COMMAND", command_id)
        return dict(row["payload"]) if row is not None else None

    def status(self, command_id: str) -> dict[str, Any]:
        command = self.command(command_id)
        if command is None:
            return {"command_id": command_id, "status": "MISSING"}
        receipts = self._payloads("BITRIX_PROJECTION_RECEIPT", command_id)
        dlq = self._payloads("BITRIX_PROJECTION_DLQ", command_id)
        claims = self._payloads("BITRIX_PROJECTION_CLAIM", command_id)
        attempts = self._payloads("BITRIX_PROJECTION_ATTEMPT", command_id)
        if receipts:
            state = "COMPLETED"
        elif dlq:
            state = "DLQ"
        elif attempts:
            state = "AMBIGUOUS"
        elif claims:
            state = "CLAIMED"
        else:
            state = "PENDING"
        return {
            "command_id": command_id,
            "status": state,
            "claim_count": len(claims),
            "attempt_count": len(attempts),
            "receipt_count": len(receipts),
            "dlq_count": len(dlq),
        }

    def enqueue(
        self,
        *,
        demand_unit: Mapping[str, Any],
        gold_acceptance: Mapping[str, Any],
        assignment: Mapping[str, Any],
        permit: Mapping[str, Any],
        projection: Mapping[str, Any],
        projection_id: str,
        projection_key: str,
        scope: Mapping[str, Any],
        writer_id: str,
        trace_id: str,
    ) -> OutboxEnqueueResult:
        now = self._now()
        self._assert_authority(
            operation="bitrix_outbox_enqueue",
            actor_id=writer_id,
            trace_id=trace_id,
            at_utc=now,
            payload=dict(projection),
        )
        self._require_projector(
            actor_id=writer_id,
            operation="bitrix_outbox_enqueue",
            trace_id=trace_id,
            at_utc=now,
            payload=projection,
        )
        demand = dict(demand_unit)
        gold = dict(gold_acceptance)
        action = dict(assignment)
        decision = dict(permit)
        projection_value = dict(projection)
        demand_row = self.store.record_version(
            "DEMAND_UNIT", str(demand["demand_unit_id"]), int(demand["version"])
        )
        gold_row = self.store.record_version(
            "GOLD_ACCEPTANCE", str(gold["gold_acceptance_id"]), int(gold["version"])
        )
        action_row = self.store.record_version(
            "ACTION_ASSIGNMENT", str(action["assignment_id"]), 1
        )
        permit_row = self.store.record_version(
            "PERMIT_DECISION", str(decision["permit_decision_id"]), 1
        )
        capacity_row = self.store.latest_record(
            "CAPACITY_SNAPSHOT", str(demand["capacity_snapshot_ref"])
        )
        exact = (
            (demand_row, demand),
            (gold_row, gold),
            (action_row, action),
            (permit_row, decision),
        )
        if any(row is None or row["payload"] != payload for row, payload in exact):
            raise ProjectionOutboxError("outbox command input is not exact persisted work")
        if capacity_row is None:
            raise ProjectionOutboxError("outbox command capacity snapshot is missing")
        projection_sha = value_sha256(projection_value)
        command_key = f"BITRIX_SHADOW:{projection_key}"
        command_material = {
            "command_key": command_key,
            "demand_unit_entry_id": demand_row["entry_id"],
            "gold_acceptance_entry_id": gold_row["entry_id"],
            "assignment_entry_id": action_row["entry_id"],
            "permit_decision_entry_id": permit_row["entry_id"],
            "capacity_snapshot_entry_id": capacity_row["entry_id"],
            "projection_sha256": projection_sha,
        }
        command_id = f"bitrix-command-{value_sha256(command_material)[:32]}"
        command = seal_internal_record(
            {
                "schema_version": "1.0.0",
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "command_id": command_id,
                "command_key": command_key,
                "demand_unit_id": demand["demand_unit_id"],
                "demand_unit_version": demand["version"],
                "demand_unit_entry_id": demand_row["entry_id"],
                "demand_unit_sha256": demand_row["payload_sha256"],
                "gold_acceptance_id": gold["gold_acceptance_id"],
                "gold_acceptance_version": gold["version"],
                "gold_acceptance_entry_id": gold_row["entry_id"],
                "gold_acceptance_sha256": gold_row["payload_sha256"],
                "assignment_id": action["assignment_id"],
                "assignment_entry_id": action_row["entry_id"],
                "assignment_sha256": action_row["payload_sha256"],
                "permit_decision_id": decision["permit_decision_id"],
                "permit_decision_entry_id": permit_row["entry_id"],
                "permit_decision_sha256": permit_row["payload_sha256"],
                "purpose": decision["purpose"],
                "action_type": action["action_type"],
                "channel": decision["channel"],
                "scope": dict(scope),
                "capacity_snapshot_ref": demand["capacity_snapshot_ref"],
                "capacity_snapshot_entry_id": capacity_row["entry_id"],
                "capacity_snapshot_sha256": capacity_row["payload_sha256"],
                "policy_version": action["policy_version"],
                "cost": action["cost"],
                "currency": action["currency"],
                "projection_id": projection_id,
                "projection_key": projection_key,
                "projection": projection_value,
                "projection_sha256": projection_sha,
                "enqueued_by": writer_id,
                "enqueued_at": now,
                "mode": "SHADOW",
                "external_effect": False,
            }
        )
        self.contracts.validate("BITRIX_PROJECTION_COMMAND", command)
        result = self.store._append_domain_record(
            record_type="BITRIX_PROJECTION_COMMAND",
            aggregate_id=command_id,
            aggregate_version=1,
            idempotency_key=f"bitrix-outbox:{command_key}",
            payload=command,
            writer_id=writer_id,
            required_role="BITRIX_PROJECTION_WRITER",
            trace_id=trace_id,
            recorded_at_utc=now,
        )
        return OutboxEnqueueResult(command_id, result.entry_id, result.disposition)

    def claim(self, command_id: str, *, worker_id: str, trace_id: str) -> dict[str, Any]:
        now = self._now()
        self._assert_authority(
            operation="bitrix_outbox_claim",
            actor_id=worker_id,
            trace_id=trace_id,
            at_utc=now,
            payload={"command_id": command_id},
        )
        command_ref = {"command_id": command_id}
        self._require_projector(
            actor_id=worker_id,
            operation="bitrix_outbox_claim",
            trace_id=trace_id,
            at_utc=now,
            payload=command_ref,
        )
        if self.command(command_id) is None:
            self._deny(
                operation="bitrix_outbox_claim",
                actor_id=worker_id,
                reason_code="COMMAND_MISSING",
                trace_id=trace_id,
                at_utc=now,
                payload=command_ref,
            )
            raise ProjectionOutboxError("cannot claim a missing command")
        state = self.status(command_id)
        if state["status"] == "COMPLETED":
            self._deny(
                operation="bitrix_outbox_claim",
                actor_id=worker_id,
                reason_code="COMMAND_ALREADY_COMPLETED",
                trace_id=trace_id,
                at_utc=now,
                payload=command_ref,
            )
            raise ProjectionOutboxError("completed command does not need a claim")
        if state["status"] == "DLQ":
            self._deny(
                operation="bitrix_outbox_claim",
                actor_id=worker_id,
                reason_code="COMMAND_DLQ",
                trace_id=trace_id,
                at_utc=now,
                payload=command_ref,
            )
            raise ProjectionDispatchBlocked("DLQ command cannot be reclaimed")
        claims = self._payloads("BITRIX_PROJECTION_CLAIM", command_id)
        terminal_attempts = {
            value["attempt_id"]
            for record_type in ("BITRIX_PROJECTION_RECEIPT",)
            for value in self._payloads(record_type, command_id)
        }
        now_dt = _parse_utc(now)
        for claim in claims:
            attempt_id = f"bitrix-attempt-{value_sha256({'claim_id': claim['claim_id'], 'command_id': command_id, 'attempt_no': claim['attempt_no']})[:32]}"
            if attempt_id not in terminal_attempts and now_dt < _parse_utc(
                str(claim["lease_expires_at"])
            ):
                self._deny(
                    operation="bitrix_outbox_claim",
                    actor_id=worker_id,
                    reason_code="LEASE_HELD",
                    trace_id=trace_id,
                    at_utc=now,
                    payload=command_ref,
                )
                raise ProjectionLeaseError("projection command has an unexpired claim")
        attempt_no = max((int(value["attempt_no"]) for value in claims), default=0) + 1
        lease_expires = _utc_z(now_dt + timedelta(seconds=LEASE_SECONDS))
        claim_material = {
            "command_id": command_id,
            "attempt_no": attempt_no,
            "worker_id": worker_id,
            "claimed_at": now,
            "lease_expires_at": lease_expires,
        }
        claim_id = f"bitrix-claim-{value_sha256(claim_material)[:32]}"
        claim = seal_internal_record(
            {
                "schema_version": "1.0.0",
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "claim_id": claim_id,
                **claim_material,
                "fencing_token": value_sha256(
                    {
                        "claim_id": claim_id,
                        "command_id": command_id,
                        "attempt_no": attempt_no,
                        "worker_id": worker_id,
                    }
                ),
                "mode": "SHADOW",
                "external_effect": False,
            }
        )
        try:
            self.store._append_domain_record(
                record_type="BITRIX_PROJECTION_CLAIM",
                aggregate_id=claim_id,
                aggregate_version=1,
                idempotency_key=f"bitrix-claim:{claim_id}",
                payload=claim,
                writer_id=worker_id,
                required_role="BITRIX_PROJECTION_WRITER",
                trace_id=trace_id,
                recorded_at_utc=now,
            )
        except SchemaIntegrityError as exc:
            self._deny(
                operation="bitrix_outbox_claim",
                actor_id=worker_id,
                reason_code="LEASE_CONFLICT",
                trace_id=trace_id,
                at_utc=now,
                payload=command_ref,
            )
            raise ProjectionLeaseError("projection claim lost lease arbitration") from exc
        return claim

    def begin_attempt(
        self, claim: Mapping[str, Any], *, worker_id: str, trace_id: str
    ) -> dict[str, Any]:
        now = self._now()
        claim_value = dict(claim)
        self._assert_authority(
            operation="bitrix_outbox_begin_attempt",
            actor_id=worker_id,
            trace_id=trace_id,
            at_utc=now,
            payload=claim_value,
        )
        self._require_projector(
            actor_id=worker_id,
            operation="bitrix_outbox_begin_attempt",
            trace_id=trace_id,
            at_utc=now,
            payload=claim_value,
        )
        if claim_value.get("worker_id") != worker_id:
            self._deny(
                operation="bitrix_outbox_begin_attempt",
                actor_id=worker_id,
                reason_code="CLAIM_OWNER_MISMATCH",
                trace_id=trace_id,
                at_utc=now,
                payload=claim_value,
            )
            raise ProjectionLeaseError("claim belongs to another worker")
        if _parse_utc(now) >= _parse_utc(str(claim_value["lease_expires_at"])):
            self._deny(
                operation="bitrix_outbox_begin_attempt",
                actor_id=worker_id,
                reason_code="LEASE_EXPIRED",
                trace_id=trace_id,
                at_utc=now,
                payload=claim_value,
            )
            raise ProjectionLeaseError("claim lease expired before attempt")
        claim_row = self.store.latest_record(
            "BITRIX_PROJECTION_CLAIM", str(claim_value["claim_id"])
        )
        if claim_row is None or claim_row["payload"] != claim_value:
            self._deny(
                operation="bitrix_outbox_begin_attempt",
                actor_id=worker_id,
                reason_code="CLAIM_NOT_EXACT",
                trace_id=trace_id,
                at_utc=now,
                payload=claim_value,
            )
            raise ProjectionLeaseError("claim is not the exact persisted claim")
        attempt_material = {
            "claim_id": claim_value["claim_id"],
            "command_id": claim_value["command_id"],
            "attempt_no": claim_value["attempt_no"],
        }
        attempt_id = f"bitrix-attempt-{value_sha256(attempt_material)[:32]}"
        attempt = seal_internal_record(
            {
                "schema_version": "1.0.0",
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "attempt_id": attempt_id,
                **attempt_material,
                "worker_id": worker_id,
                "status": "STARTED",
                "started_at": now,
                "transport_call_count": 0,
                "mode": "SHADOW",
                "external_effect": False,
            }
        )
        self.store._append_domain_record(
            record_type="BITRIX_PROJECTION_ATTEMPT",
            aggregate_id=attempt_id,
            aggregate_version=1,
            idempotency_key=f"bitrix-attempt:{attempt_id}",
            payload=attempt,
            writer_id=worker_id,
            required_role="BITRIX_PROJECTION_WRITER",
            trace_id=trace_id,
            recorded_at_utc=now,
        )
        return attempt

    def _append_dlq(
        self,
        *,
        command: Mapping[str, Any],
        claim: Mapping[str, Any],
        worker_id: str,
        reason_code: str,
        trace_id: str,
        failed_at: str,
    ) -> AppendResult:
        material = {
            "command_id": command["command_id"],
            "claim_id": claim["claim_id"],
            "reason_code": reason_code,
        }
        dlq_id = f"bitrix-dlq-{value_sha256(material)[:32]}"
        dlq = seal_internal_record(
            {
                "schema_version": "1.0.0",
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "dlq_id": dlq_id,
                **material,
                "worker_id": worker_id,
                "blocked_action": "BITRIX_PROJECTION",
                "failed_at": failed_at,
                "transport_call_count": 0,
                "mode": "SHADOW",
                "external_effect": False,
            }
        )
        return self.store._append_domain_record(
            record_type="BITRIX_PROJECTION_DLQ",
            aggregate_id=dlq_id,
            aggregate_version=1,
            idempotency_key=f"bitrix-dlq:{dlq_id}",
            payload=dlq,
            writer_id=worker_id,
            required_role="BITRIX_PROJECTION_WRITER",
            trace_id=trace_id,
            recorded_at_utc=failed_at,
        )

    def complete(
        self,
        attempt: Mapping[str, Any],
        *,
        worker_id: str,
        trace_id: str,
    ) -> OutboxDispatchResult:
        now = self._now()
        attempt_value = dict(attempt)
        self._assert_authority(
            operation="bitrix_outbox_complete",
            actor_id=worker_id,
            trace_id=trace_id,
            at_utc=now,
            payload=attempt_value,
        )
        self._require_projector(
            actor_id=worker_id,
            operation="bitrix_outbox_complete",
            trace_id=trace_id,
            at_utc=now,
            payload=attempt_value,
        )
        if attempt_value.get("worker_id") != worker_id:
            self._deny(
                operation="bitrix_outbox_complete",
                actor_id=worker_id,
                reason_code="ATTEMPT_OWNER_MISMATCH",
                trace_id=trace_id,
                at_utc=now,
                payload=attempt_value,
            )
            raise ProjectionLeaseError("attempt belongs to another worker")
        attempt_row = self.store.latest_record(
            "BITRIX_PROJECTION_ATTEMPT", str(attempt_value["attempt_id"])
        )
        claim_row = self.store.latest_record(
            "BITRIX_PROJECTION_CLAIM", str(attempt_value["claim_id"])
        )
        if (
            attempt_row is None
            or attempt_row["payload"] != attempt_value
            or claim_row is None
            or claim_row["payload"].get("worker_id") != worker_id
            or _parse_utc(now) >= _parse_utc(str(claim_row["payload"]["lease_expires_at"]))
        ):
            self._deny(
                operation="bitrix_outbox_complete",
                actor_id=worker_id,
                reason_code="ATTEMPT_HAS_NO_ACTIVE_CLAIM",
                trace_id=trace_id,
                at_utc=now,
                payload=attempt_value,
            )
            raise ProjectionLeaseError("attempt has no exact active claim")
        command = self.command(str(attempt_value["command_id"]))
        if command is None:
            raise ProjectionOutboxError("attempt command is missing")
        permit_row = self.store.latest_record(
            "PERMIT_DECISION", str(command["permit_decision_id"])
        )
        if permit_row is None:
            raise ProjectionOutboxError("command permit is missing")
        try:
            checked = self.permits.assert_exact(
                permit_row["payload"],
                at_utc=now,
                action_type=str(command["action_type"]),
                channel=str(command["channel"]),
                purpose=str(command["purpose"]),
                subject_refs=(str(command["demand_unit_id"]),),
                scope=dict(command["scope"]),
                capacity_snapshot_ref=str(command["capacity_snapshot_ref"]),
                cost=float(command["cost"]),
                currency=str(command["currency"]),
                policy_version=str(command["policy_version"]),
                mode="SHADOW",
                attempted_actor_id=worker_id,
                trace_id=trace_id,
            )
            if checked != command["permit_decision_sha256"]:
                raise ProjectionOutboxError("JIT permit digest differs from command")
        except PermitError as exc:
            reason = type(exc).__name__.replace("Permit", "").replace("Error", "").upper()
            reason_code = {
                "DENIED": "PERMIT_DENIED",
                "EXPIRED": "PERMIT_EXPIRED",
                "MISMATCH": "PERMIT_MISMATCH",
            }.get(reason, "PERMIT_MISMATCH")
            self._append_dlq(
                command=command,
                claim=claim_row["payload"],
                worker_id=worker_id,
                reason_code=reason_code,
                trace_id=trace_id,
                failed_at=now,
            )
            raise ProjectionDispatchBlocked(reason_code) from exc

        existing = next(
            (
                row
                for row in self.store.shadow_projections()
                if row["projection_key"] == command["projection_key"]
            ),
            None,
        )
        outcome = "CONFIRMED_AFTER_READBACK" if existing is not None else "SHADOW_COMMITTED"
        receipt_material = {
            "command_id": command["command_id"],
            "attempt_id": attempt_value["attempt_id"],
            "projection_sha256": command["projection_sha256"],
            "outcome": outcome,
        }
        receipt_id = f"bitrix-receipt-{value_sha256(receipt_material)[:32]}"
        receipt = seal_internal_record(
            {
                "schema_version": "1.0.0",
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "receipt_id": receipt_id,
                "command_id": command["command_id"],
                "attempt_id": attempt_value["attempt_id"],
                "worker_id": worker_id,
                "outcome": outcome,
                "projection_id": command["projection_id"],
                "projection_key": command["projection_key"],
                "projection_sha256": command["projection_sha256"],
                "readback_sha256": command["projection_sha256"],
                "completed_at": now,
                "transport_call_count": 0,
                "mode": "SHADOW",
                "external_effect": False,
            }
        )
        inserted, append_result = self.store.complete_bitrix_shadow_outbox(
            projection_id=str(command["projection_id"]),
            projection_key=str(command["projection_key"]),
            demand_unit_id=str(command["demand_unit_id"]),
            projection=dict(command["projection"]),
            permit_decision_id=str(command["permit_decision_id"]),
            permit_decision_sha256=str(command["permit_decision_sha256"]),
            receipt=receipt,
            writer_id=worker_id,
            trace_id=trace_id,
            recorded_at_utc=now,
        )
        return OutboxDispatchResult(
            command_id=str(command["command_id"]),
            projection_id=str(command["projection_id"]),
            projection_key=str(command["projection_key"]),
            inserted=inserted,
            outcome=outcome,
            attempt_no=int(attempt_value["attempt_no"]),
        )

    def dispatch(
        self, command_id: str, *, worker_id: str, trace_id: str
    ) -> OutboxDispatchResult:
        state = self.status(command_id)
        if state["status"] == "COMPLETED":
            receipt = self._payloads("BITRIX_PROJECTION_RECEIPT", command_id)[-1]
            return OutboxDispatchResult(
                command_id=command_id,
                projection_id=str(receipt["projection_id"]),
                projection_key=str(receipt["projection_key"]),
                inserted=False,
                outcome=str(receipt["outcome"]),
                attempt_no=int(
                    self.store.latest_record(
                        "BITRIX_PROJECTION_ATTEMPT", str(receipt["attempt_id"])
                    )["payload"]["attempt_no"]
                ),
            )
        claim = self.claim(command_id, worker_id=worker_id, trace_id=trace_id)
        attempt = self.begin_attempt(claim, worker_id=worker_id, trace_id=trace_id)
        return self.complete(attempt, worker_id=worker_id, trace_id=trace_id)


__all__ = [
    "LEASE_SECONDS",
    "OutboxDispatchResult",
    "OutboxEnqueueResult",
    "ProjectionDispatchBlocked",
    "ProjectionLeaseError",
    "ProjectionOutbox",
    "ProjectionOutboxError",
    "system_utc_clock",
]
