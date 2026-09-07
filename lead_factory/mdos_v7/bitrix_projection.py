"""Bitrix24 work projection boundary; G1 implements a local shadow sink only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .authority import assert_external_allowed
from .contracts import ContractRegistry, value_sha256
from .policy import SHADOW_POLICY_VERSION, PermitService, permit_record_sha256
from .projection_outbox import ProjectionOutbox, system_utc_clock
from .store import MdosStore


class ProjectionError(RuntimeError):
    """An accepted DemandUnit could not be projected safely."""


@dataclass(frozen=True)
class ProjectionResult:
    projection_id: str
    projection_key: str
    inserted: bool
    external_effect_count: int
    mode: str
    command_id: str | None = None
    outbox_outcome: str | None = None


class BitrixTransport(Protocol):
    def create_or_update_work(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ShadowBitrixProjectionAdapter:
    """Create Company/Deal/Task-shaped local data without credentials or network."""

    def __init__(
        self,
        store: MdosStore,
        contracts: ContractRegistry,
        permits: PermitService,
        *,
        clock: Callable[[], str] = system_utc_clock,
    ) -> None:
        self.store = store
        self.contracts = contracts
        self.permits = permits
        self.outbox = ProjectionOutbox(store, permits, clock=clock)

    def project(
        self,
        *,
        demand_unit: Mapping[str, Any],
        gold_acceptance: Mapping[str, Any],
        assignment: Mapping[str, Any],
        permit: Mapping[str, Any],
        writer_id: str,
        trace_id: str,
    ) -> ProjectionResult:
        demand = dict(demand_unit)
        gold = dict(gold_acceptance)
        action = dict(assignment)
        decision = dict(permit)
        self.contracts.validate("demand-unit.schema.json", demand)
        self.contracts.validate("gold-acceptance.schema.json", gold)
        self.contracts.validate("action-assignment.schema.json", action)
        self.contracts.validate("permit-decision.schema.json", decision)
        persisted_inputs = (
            ("DEMAND_UNIT", str(demand.get("demand_unit_id", "")), int(demand.get("version", 0)), demand),
            (
                "GOLD_ACCEPTANCE",
                str(gold.get("gold_acceptance_id", "")),
                int(gold.get("version", 0)),
                gold,
            ),
            ("ACTION_ASSIGNMENT", str(action.get("assignment_id", "")), 1, action),
        )
        for record_type, aggregate_id, version, payload in persisted_inputs:
            persisted = self.store.record_version(record_type, aggregate_id, version)
            if persisted is None or persisted["payload"] != payload:
                raise ProjectionError(f"{record_type} is not the exact persisted input")
        if demand.get("state") != "ACCEPTED_GDO":
            raise ProjectionError("Bitrix receives only ACCEPTED_GDO work")
        if gold.get("decision") != "ACCEPTED":
            raise ProjectionError("GoldAcceptance is not accepted")
        if demand.get("gold_acceptance_ref") != gold.get("gold_acceptance_id"):
            raise ProjectionError("DemandUnit does not bind the exact GoldAcceptance")
        if gold.get("demand_unit_id") != demand.get("demand_unit_id"):
            raise ProjectionError("GoldAcceptance belongs to another DemandUnit")
        if action.get("demand_unit_id") != demand.get("demand_unit_id"):
            raise ProjectionError("ActionAssignment belongs to another DemandUnit")
        if action.get("action_type") != "CREATE_CRM_TASK" or action.get("status") != "APPROVED":
            raise ProjectionError("only an approved CREATE_CRM_TASK assignment is projectable")
        if (
            action.get("policy_version") != SHADOW_POLICY_VERSION
            or action.get("capacity_snapshot_ref") != demand.get("capacity_snapshot_ref")
            or action.get("cost") != 0
            or action.get("currency") != "RUB"
        ):
            raise ProjectionError("assignment policy/capacity/cost boundary mismatch")
        if action.get("permit_decision_ref") != decision.get("permit_decision_id"):
            raise ProjectionError("assignment permit reference mismatch")
        if (
            demand.get("lawful_next_action_ref") != decision.get("permit_decision_id")
            or gold.get("permit_decision_ref") != decision.get("permit_decision_id")
        ):
            raise ProjectionError("accepted work does not bind the exact permit")
        exact_permit_sha = permit_record_sha256(decision)
        if action.get("permit_decision_sha256") != exact_permit_sha:
            raise ProjectionError("assignment permit digest mismatch")
        scope = self.permits.trusted_shadow_scope(
            demand_unit_id=str(demand["demand_unit_id"]),
            capacity_snapshot_ref=str(demand["capacity_snapshot_ref"]),
        )
        projection_key = f"BITRIX_DEAL:{demand['demand_unit_id']}"
        projection: dict[str, Any] = {
            "schema_version": "1.0.0",
            "mode": "SHADOW",
            "external_effect": False,
            "company": {
                "canonical_account_id": demand["account_ref"],
            },
            "deal": {
                "external_key": projection_key,
                "demand_unit_id": demand["demand_unit_id"],
                "motion": demand["motion"],
                "need": demand["need"],
                "product_scope": demand["product_scope"],
                "object_or_site_ref": demand["object_or_site_ref"],
                "scope_fingerprint": demand["scope_fingerprint"],
                "gold_acceptance_ref": gold["gold_acceptance_id"],
            },
            "task": {
                "action_type": action["action_type"],
                "assignment_id": action["assignment_id"],
                "actor_id": action["actor_id"],
                "outcome_window_end": action["outcome_window_end"],
            },
            "authority": {
                "permit_decision_id": decision["permit_decision_id"],
                "permit_decision_sha256": exact_permit_sha,
                "policy_version": decision["policy_version"],
            },
        }
        projection_id = f"bitrix-shadow-{value_sha256(projection)[:32]}"
        enqueued = self.outbox.enqueue(
            demand_unit=demand,
            gold_acceptance=gold,
            assignment=action,
            permit=decision,
            projection=projection,
            projection_id=projection_id,
            projection_key=projection_key,
            scope=scope,
            writer_id=writer_id,
            trace_id=trace_id,
        )
        dispatched = self.outbox.dispatch(
            enqueued.command_id,
            worker_id=writer_id,
            trace_id=trace_id,
        )
        return ProjectionResult(
            projection_id,
            projection_key,
            dispatched.inserted,
            0,
            "SHADOW",
            command_id=enqueued.command_id,
            outbox_outcome=dispatched.outcome,
        )


class LiveBitrixProjectionAdapter:
    """A deliberately fenced boundary proving no transport call under RC1."""

    def __init__(self, permits: PermitService, transport: BitrixTransport) -> None:
        if type(permits) is not PermitService:
            raise TypeError("live Bitrix projection requires the exact PermitService")
        self.permits = permits
        self.transport = transport

    def project(
        self,
        *,
        permit: Mapping[str, Any],
        demand_unit_id: str,
        scope: Mapping[str, Any],
        capacity_snapshot_ref: str,
        policy_version: str,
        at_utc: str,
        payload: Mapping[str, Any],
        writer_id: str,
        trace_id: str,
    ) -> Mapping[str, Any]:
        # This call always fails before transport for the fixed unratified RC1.
        self.permits.assert_exact(
            permit,
            at_utc=at_utc,
            action_type="CREATE_CRM_TASK",
            channel="BITRIX24_LIVE",
            purpose=str(permit.get("purpose", "")),
            subject_refs=(demand_unit_id,),
            scope=scope,
            capacity_snapshot_ref=capacity_snapshot_ref,
            cost=0,
            currency="RUB",
            policy_version=policy_version,
            mode="LIVE",
            attempted_actor_id=writer_id,
            trace_id=trace_id,
        )
        # This independent RC1 fence remains immediately adjacent to the
        # transport even if PermitService internals are replaced at runtime.
        assert_external_allowed(
            "bitrix_projection.create_or_update_work:external_write"
        )
        return self.transport.create_or_update_work(payload)


__all__ = [
    "BitrixTransport",
    "LiveBitrixProjectionAdapter",
    "ProjectionError",
    "ProjectionResult",
    "ShadowBitrixProjectionAdapter",
]
