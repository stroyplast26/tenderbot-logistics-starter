"""Executable G0/G1 domain path for synthetic fixture and shadow data only."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from .contracts import ContractRegistry, record_digest_excluding, value_sha256
from .policy import SHADOW_POLICY_VERSION, SHADOW_PURPOSE, PermitService, permit_record_sha256
from .store import AppendResult, MdosStore, ZERO_SHA256


class DomainInvariantError(RuntimeError):
    """A cross-record invariant failed even though individual schemas may pass."""


class HumanAuthorityError(DomainInvariantError):
    """A human-only commercial fact lacked an eligible human actor."""


class ReconciliationBlocked(DomainInvariantError):
    """Commercial truth cannot be reconciled and no KPI may be emitted."""


@dataclass(frozen=True)
class PaymentIntakeResult:
    status: str
    observation_id: str
    conflict_id: str | None


@dataclass(frozen=True)
class PaymentInstallmentResult:
    payment: AppendResult
    order: AppendResult
    outcome: AppendResult | None
    settlement_state: str


@dataclass(frozen=True)
class ReconciliationResult:
    reconciliation_id: str
    status: str
    canonical_kpi_eligible: bool
    ledger_entry_id: str


_INTERNAL_RECORD_TYPES = frozenset(
    {
        "CAPACITY_SNAPSHOT",
        "ECONOMICS_SNAPSHOT",
        "DENOMINATOR_SNAPSHOT",
        "EVIDENCE_BUNDLE",
        "HUMAN_GOLD_REVIEW",
        "COMMERCIAL_TERMS",
        "RAW_PAYMENT_OBSERVATION",
        "RAW_FULFILMENT_DOCUMENT",
        "CRM_OUTCOME_CLAIM",
        "RECONCILIATION_RESULT",
        "CONFLICT_RESOLUTION",
    }
)


def scope_fingerprint(demand_unit: Mapping[str, Any]) -> str:
    """Stable G1 identity for one independently decidable synthetic scope."""

    return value_sha256(
        {
            "account_ref": str(demand_unit.get("account_ref", "")),
            "object_or_site_ref": str(demand_unit.get("object_or_site_ref", "")),
            "product_scope": sorted(str(item) for item in demand_unit.get("product_scope", [])),
            "purchase_decision": " ".join(
                str(demand_unit.get("need", "")).casefold().split()
            ),
        }
    )


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _decimal_amount(value: object, label: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise DomainInvariantError(f"{label} is not an exact decimal amount") from exc
    if not amount.is_finite():
        raise DomainInvariantError(f"{label} is not finite")
    return amount


class G1Pipeline:
    def __init__(
        self,
        store: MdosStore,
        contracts: ContractRegistry,
        permits: PermitService,
    ) -> None:
        self.store = store
        self.contracts = contracts
        self.permits = permits

    def _validated_append(
        self,
        *,
        schema_name: str,
        record_type: str,
        aggregate_id: str,
        aggregate_version: int,
        idempotency_key: str,
        record: Mapping[str, Any],
        writer_id: str,
        required_role: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> AppendResult:
        value = dict(record)
        self.contracts.validate(schema_name, value)
        return self.store._append_domain_record(
            record_type=record_type,
            aggregate_id=aggregate_id,
            aggregate_version=aggregate_version,
            idempotency_key=idempotency_key,
            payload=value,
            writer_id=writer_id,
            required_role=required_role,
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )

    def capture_signal(
        self,
        observation: Mapping[str, Any],
        *,
        raw_content: bytes,
        writer_id: str,
        delivery_trace_id: str | None = None,
    ) -> AppendResult:
        value = dict(observation)
        if value.get("producer") != writer_id or writer_id != "fixture-source-adapter":
            raise DomainInvariantError("signal producer must be the registered source adapter")
        if (
            value.get("source_id") != "fixture:known-account-history"
            or value.get("source_revision") != "fixture-v1"
            or value.get("event_type") != "KNOWN_ACCOUNT_CURRENT_NEED"
        ):
            raise DomainInvariantError("unratified G1 accepts only the fixed fixture source passport")
        if not str(value.get("data_class", "")).startswith("SYNTHETIC"):
            raise DomainInvariantError("fixture signal must be explicitly synthetic")
        evidence = self.store.append_evidence(
            content=raw_content,
            media_type="application/json",
            source_ref=str(value.get("source_id", "")),
            synthetic=True,
            writer_id=writer_id,
            required_role="SOURCE_ADAPTER",
            trace_id=delivery_trace_id or str(value.get("trace_id", "")),
            recorded_at_utc=str(value.get("observed_time", "")),
        )
        expected_uri = f"mdos-evidence:{evidence.content_sha256}"
        if value.get("payload_sha256") != evidence.content_sha256:
            raise DomainInvariantError("signal payload hash differs from immutable raw evidence")
        if value.get("evidence_uri") != expected_uri:
            raise DomainInvariantError("signal evidence_uri does not address the raw content")
        return self._validated_append(
            schema_name="signal-observation.schema.json",
            record_type="SIGNAL_OBSERVATION",
            aggregate_id=str(value["event_id"]),
            aggregate_version=1,
            idempotency_key=str(value["idempotency_key"]),
            record=value,
            writer_id=writer_id,
            required_role="SOURCE_ADAPTER",
            trace_id=delivery_trace_id or str(value["trace_id"]),
            recorded_at_utc=str(value["observed_time"]),
        )

    def propose_claim(
        self,
        claim: Mapping[str, Any],
        *,
        writer_id: str,
        trace_id: str,
    ) -> AppendResult:
        value = dict(claim)
        if value.get("producer") != writer_id or value.get("status") != "PROPOSED":
            raise DomainInvariantError("claim producer/status boundary failed")
        if value.get("model_prompt_digest") is not None:
            raise DomainInvariantError("unknown model/prompt digests are denied in G1")
        source = self.store.latest_record(
            "SIGNAL_OBSERVATION", str(value.get("source_event_id", ""))
        )
        if source is None:
            raise DomainInvariantError("claim references an unknown source event")
        if value.get("payload_sha256") != source["payload"].get("payload_sha256"):
            raise DomainInvariantError("claim does not bind the exact source payload")
        if value.get("evidence_uri") != source["payload"].get("evidence_uri"):
            raise DomainInvariantError("claim evidence URI differs from its source event")
        return self._validated_append(
            schema_name="claim.schema.json",
            record_type="CLAIM",
            aggregate_id=str(value["claim_id"]),
            aggregate_version=1,
            idempotency_key=f"claim:{value['claim_id']}:1",
            record=value,
            writer_id=writer_id,
            required_role="CLAIM_PRODUCER",
            trace_id=trace_id,
            recorded_at_utc=str(value["recorded_at"]),
        )

    def accept_claim(
        self,
        accepted_claim: Mapping[str, Any],
        *,
        reviewer_id: str,
        trace_id: str,
    ) -> AppendResult:
        actor = self.store.require_actor(reviewer_id, "CLAIM_REVIEWER")
        if actor["actor_type"] != "HUMAN":
            raise HumanAuthorityError("claim reviewer must be human")
        value = dict(accepted_claim)
        previous = self.store.record_version("CLAIM", str(value.get("claim_id", "")), 1)
        if previous is None or previous["payload"].get("status") != "PROPOSED":
            raise DomainInvariantError("accepted claim has no proposed predecessor")
        if reviewer_id == previous["payload"].get("producer"):
            raise HumanAuthorityError("claim producer cannot review its own claim")
        for field in (
            "claim_id",
            "claim_type",
            "subject_ref",
            "value",
            "valid_from",
            "source_event_id",
            "evidence_uri",
            "evidence_span",
            "payload_sha256",
            "producer",
            "producer_version",
            "purpose",
        ):
            if value.get(field) != previous["payload"].get(field):
                raise DomainInvariantError(f"claim adjudication rewrote {field}")
        if value.get("status") != "ACCEPTED" or value.get("authoritative_class") != "HUMAN_ADJUDICATED":
            raise DomainInvariantError("claim adjudication must be HUMAN_ADJUDICATED/ACCEPTED")
        return self._validated_append(
            schema_name="claim.schema.json",
            record_type="CLAIM",
            aggregate_id=str(value["claim_id"]),
            aggregate_version=int(previous["aggregate_version"]) + 1,
            idempotency_key=f"claim:{value['claim_id']}:2",
            record=value,
            writer_id=reviewer_id,
            required_role="CLAIM_REVIEWER",
            trace_id=trace_id,
            recorded_at_utc=str(value["recorded_at"]),
        )

    def record_identity_decision(
        self,
        decision: Mapping[str, Any],
        *,
        writer_id: str,
        trace_id: str,
    ) -> AppendResult:
        actor = self.store.require_actor(writer_id, "IDENTITY_STEWARD")
        if actor["actor_type"] != "HUMAN":
            raise HumanAuthorityError("identity steward must be human for fixture linkage")
        value = dict(decision)
        if value.get("decided_by") != writer_id:
            raise DomainInvariantError("identity decision actor mismatch")
        lower = float(value.get("lower_threshold", -1))
        upper = float(value.get("upper_threshold", -1))
        probability = float(value.get("match_probability", -1))
        if not 0 <= lower < upper <= 1:
            raise DomainInvariantError("identity thresholds must satisfy 0 <= lower < upper <= 1")
        expected_zone = "AUTO_LINK" if probability >= upper else (
            "REJECT" if probability <= lower else "REVIEW"
        )
        if value.get("zone") != expected_zone:
            raise DomainInvariantError("identity probability does not match its decision zone")
        features = dict(value.get("comparison_vector") or {})
        material_features = [item for item in features.values() if item not in (None, "", False, 0)]
        if expected_zone == "AUTO_LINK" and len(material_features) < 2:
            raise DomainInvariantError("AUTO_LINK requires multi-feature evidence")
        for claim_id in value.get("evidence_claim_ids", []):
            claim = self.store.latest_record("CLAIM", str(claim_id))
            if claim is None or claim["payload"].get("status") != "ACCEPTED":
                raise DomainInvariantError("identity decision references a non-accepted claim")
        return self._validated_append(
            schema_name="entity-resolution-decision.schema.json",
            record_type="ENTITY_RESOLUTION_DECISION",
            aggregate_id=str(value["decision_id"]),
            aggregate_version=1,
            idempotency_key=f"identity:{value['decision_id']}",
            record=value,
            writer_id=writer_id,
            required_role="IDENTITY_STEWARD",
            trace_id=trace_id,
            recorded_at_utc=str(value["recorded_at"]),
        )

    def append_internal_record(
        self,
        *,
        record_type: str,
        record_id: str,
        payload: Mapping[str, Any],
        writer_id: str,
        required_role: str,
        trace_id: str,
        recorded_at_utc: str,
        version: int = 1,
    ) -> AppendResult:
        if record_type not in _INTERNAL_RECORD_TYPES:
            raise DomainInvariantError(f"unknown internal record type: {record_type}")
        value = dict(payload)
        if value.get("schema_version") != "1.0.0":
            raise DomainInvariantError("internal record schema_version must be 1.0.0")
        if value.get("synthetic") is not True or value.get("canonical_kpi_eligible") is not False:
            raise DomainInvariantError("G1 internal records must be synthetic and non-KPI")
        if value.get("record_id") != record_id:
            raise DomainInvariantError("internal record_id mismatch")
        return self.store._append_domain_record(
            record_type=record_type,
            aggregate_id=record_id,
            aggregate_version=version,
            idempotency_key=f"{record_type.casefold()}:{record_id}:{version}",
            payload=value,
            writer_id=writer_id,
            required_role=required_role,
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )

    def record_demand_unit(
        self,
        demand_unit: Mapping[str, Any],
        *,
        writer_id: str,
        trace_id: str,
    ) -> AppendResult:
        value = dict(demand_unit)
        if value.get("state") != "ELIGIBLE_FOR_GOLD_REVIEW" or value.get("version") != 1:
            raise DomainInvariantError("initial DemandUnit must enter human Gold review")
        if value.get("scope_fingerprint") != scope_fingerprint(value):
            raise DomainInvariantError("DemandUnit scope fingerprint mismatch")
        probabilities = dict((value.get("decision_horizon") or {}).get("probabilities") or {})
        if abs(sum(float(item) for item in probabilities.values()) - 1.0) > 1e-9:
            raise DomainInvariantError("DemandUnit decision probabilities must sum to one")
        for claim_id in value.get("evidence_claim_ids", []):
            claim = self.store.latest_record("CLAIM", str(claim_id))
            if claim is None or claim["payload"].get("status") != "ACCEPTED":
                raise DomainInvariantError("DemandUnit references a non-accepted claim")
        identity = self.store.find_payload(
            "ENTITY_RESOLUTION_DECISION", "right_ref", str(value.get("account_ref", ""))
        )
        if not identity or identity[-1]["payload"].get("zone") != "AUTO_LINK":
            raise DomainInvariantError("DemandUnit account identity is not adjudicated")
        return self._validated_append(
            schema_name="demand-unit.schema.json",
            record_type="DEMAND_UNIT",
            aggregate_id=str(value["demand_unit_id"]),
            aggregate_version=1,
            idempotency_key=f"demand-unit:{value['demand_unit_id']}:1",
            record=value,
            writer_id=writer_id,
            required_role="DEMAND_STEWARD",
            trace_id=trace_id,
            recorded_at_utc=str(value["recorded_at"]),
        )

    def record_human_gold_review(
        self,
        review: Mapping[str, Any],
        *,
        reviewer_id: str,
        trace_id: str,
    ) -> AppendResult:
        actor = self.store.require_actor(reviewer_id, "GOLD_REVIEWER")
        if actor["actor_type"] != "HUMAN":
            raise HumanAuthorityError("Gold review requires a human actor")
        value = dict(review)
        if value.get("reviewer_id") != reviewer_id or value.get("origin") != "HUMAN_FIXTURE_INPUT":
            raise HumanAuthorityError("Gold review did not enter through the human fixture boundary")
        if value.get("decision") not in {"ACCEPTED", "REJECTED"}:
            raise DomainInvariantError("human Gold review decision is invalid")
        demand = self.store.record_version(
            "DEMAND_UNIT", str(value.get("demand_unit_id", "")), 1
        )
        if demand is None or demand["payload"].get("state") != "ELIGIBLE_FOR_GOLD_REVIEW":
            raise DomainInvariantError("Gold review has no eligible DemandUnit")
        if value.get("scope_fingerprint") != demand["payload"].get("scope_fingerprint"):
            raise DomainInvariantError("Gold review scope fingerprint mismatch")
        if not isinstance(value.get("attestation_sha256"), str) or len(value["attestation_sha256"]) != 64:
            raise DomainInvariantError("Gold review requires a sealed attestation digest")
        producers = {
            record["payload"].get("producer")
            for record in self.store.records("CLAIM")
            if record["payload"].get("claim_id") in demand["payload"].get("evidence_claim_ids", [])
        }
        if reviewer_id in producers:
            raise HumanAuthorityError("AI/claim producer cannot accept its own Gold case")
        return self.append_internal_record(
            record_type="HUMAN_GOLD_REVIEW",
            record_id=str(value["record_id"]),
            payload=value,
            writer_id=reviewer_id,
            required_role="GOLD_REVIEWER",
            trace_id=trace_id,
            recorded_at_utc=str(value["reviewed_at"]),
        )

    def commit_gold_acceptance(
        self,
        *,
        gold_acceptance: Mapping[str, Any],
        accepted_demand_unit: Mapping[str, Any],
        human_review_ref: str,
        permit: Mapping[str, Any],
        reviewer_id: str,
        trace_id: str,
    ) -> tuple[AppendResult, AppendResult]:
        actor = self.store.require_actor(reviewer_id, "GOLD_REVIEWER")
        if actor["actor_type"] != "HUMAN":
            raise HumanAuthorityError("GoldAcceptance requires a human reviewer")
        gold = dict(gold_acceptance)
        demand = dict(accepted_demand_unit)
        decision = dict(permit)
        review = self.store.latest_record("HUMAN_GOLD_REVIEW", human_review_ref)
        previous = self.store.record_version(
            "DEMAND_UNIT", str(demand.get("demand_unit_id", "")), 1
        )
        if review is None or review["payload"].get("decision") != "ACCEPTED":
            raise HumanAuthorityError("no accepted human review attestation")
        if previous is None or previous["payload"].get("state") != "ELIGIBLE_FOR_GOLD_REVIEW":
            raise DomainInvariantError("DemandUnit is not eligible for Gold")
        if gold.get("reviewer_id") != reviewer_id:
            raise HumanAuthorityError("GoldAcceptance reviewer mismatch")
        if gold.get("decision") != "ACCEPTED":
            raise DomainInvariantError("Gold transition requires an ACCEPTED human decision")
        if (
            review["payload"].get("reviewer_id") != reviewer_id
            or review["payload"].get("demand_unit_id") != demand.get("demand_unit_id")
        ):
            raise HumanAuthorityError("Gold review authority does not bind this DemandUnit")
        if decision.get("issued_by") == reviewer_id:
            raise HumanAuthorityError("Gold reviewer cannot issue the PermitDecision")
        if gold.get("demand_unit_id") != demand.get("demand_unit_id"):
            raise DomainInvariantError("GoldAcceptance DemandUnit mismatch")
        if gold.get("scope_fingerprint") != demand.get("scope_fingerprint"):
            raise DomainInvariantError("GoldAcceptance scope mismatch")
        if gold.get("motion") != demand.get("motion"):
            raise DomainInvariantError("GoldAcceptance motion mismatch")
        if review["payload"].get("scope_fingerprint") != gold.get("scope_fingerprint"):
            raise DomainInvariantError("human review does not cover the Gold scope")
        if gold.get("permit_decision_ref") != decision.get("permit_decision_id"):
            raise DomainInvariantError("GoldAcceptance permit reference mismatch")
        for record_type, reference in (
            ("CAPACITY_SNAPSHOT", gold.get("capacity_snapshot_ref")),
            ("ECONOMICS_SNAPSHOT", gold.get("economics_snapshot_ref")),
            ("DENOMINATOR_SNAPSHOT", gold.get("denominator_snapshot_ref")),
            ("EVIDENCE_BUNDLE", gold.get("evidence_bundle_ref")),
        ):
            if self.store.latest_record(record_type, str(reference or "")) is None:
                raise DomainInvariantError(f"GoldAcceptance missing {record_type}")
        self.permits.assert_exact(
            decision,
            at_utc=str(demand["recorded_at"]),
            action_type=str(gold["permitted_next_action"]),
            channel="BITRIX24_SHADOW",
            purpose=SHADOW_PURPOSE,
            subject_refs=(str(demand["demand_unit_id"]),),
            scope=self.permits.trusted_shadow_scope(
                demand_unit_id=str(demand["demand_unit_id"]),
                capacity_snapshot_ref=str(gold["capacity_snapshot_ref"]),
            ),
            capacity_snapshot_ref=str(gold["capacity_snapshot_ref"]),
            cost=0,
            currency=str(decision["currency"]),
            policy_version=SHADOW_POLICY_VERSION,
            mode="SHADOW",
            attempted_actor_id=reviewer_id,
            trace_id=trace_id,
        )
        self.contracts.validate("gold-acceptance.schema.json", gold)
        self.contracts.validate("demand-unit.schema.json", demand)
        immutable_fields = (
            "demand_unit_id",
            "account_ref",
            "motion",
            "need",
            "product_scope",
            "object_or_site_ref",
            "buying_group",
            "decision_horizon",
            "supplier_state",
            "evidence_claim_ids",
            "scope_fingerprint",
        )
        for field in immutable_fields:
            if demand.get(field) != previous["payload"].get(field):
                raise DomainInvariantError(f"Gold transition rewrote DemandUnit {field}")
        if (
            demand.get("version") != 2
            or demand.get("state") != "ACCEPTED_GDO"
            or demand.get("gold_acceptance_ref") != gold.get("gold_acceptance_id")
            or demand.get("lawful_next_action_ref") != decision.get("permit_decision_id")
            or demand.get("capacity_snapshot_ref") != gold.get("capacity_snapshot_ref")
            or demand.get("economics_snapshot_ref") != gold.get("economics_snapshot_ref")
        ):
            raise DomainInvariantError("DemandUnit Gold transition lacks exact bindings")
        existing_gold = self.store.find_payload(
            "GOLD_ACCEPTANCE", "scope_fingerprint", str(gold["scope_fingerprint"])
        )
        for record in existing_gold:
            payload = record["payload"]
            if (
                payload.get("cohort_id") == gold.get("cohort_id")
                and payload.get("cutoff_at") == gold.get("cutoff_at")
                and payload.get("gold_acceptance_id") != gold.get("gold_acceptance_id")
            ):
                raise DomainInvariantError("duplicate Gold scope inside sealed cohort/cut-off")
        gold_result, demand_result = self.store._append_domain_batch(
            (
                {
                    "record_type": "GOLD_ACCEPTANCE",
                    "aggregate_id": str(gold["gold_acceptance_id"]),
                    "aggregate_version": int(gold["version"]),
                    "idempotency_key": f"gold:{gold['gold_acceptance_id']}:{gold['version']}",
                    "payload": gold,
                    "writer_id": reviewer_id,
                    "required_role": "GOLD_REVIEWER",
                    "trace_id": trace_id,
                    "recorded_at_utc": str(gold["reviewed_at"]),
                },
                {
                    "record_type": "DEMAND_UNIT",
                    "aggregate_id": str(demand["demand_unit_id"]),
                    "aggregate_version": 2,
                    "idempotency_key": f"demand-unit:{demand['demand_unit_id']}:2",
                    "payload": demand,
                    "writer_id": reviewer_id,
                    "required_role": "GOLD_REVIEWER",
                    "trace_id": trace_id,
                    "recorded_at_utc": str(demand["recorded_at"]),
                },
            )
        )
        return gold_result, demand_result

    def record_action_assignment(
        self,
        assignment: Mapping[str, Any],
        *,
        permit: Mapping[str, Any],
        writer_id: str,
        trace_id: str,
    ) -> AppendResult:
        value = dict(assignment)
        decision = dict(permit)
        if value.get("actor_id") != writer_id:
            raise DomainInvariantError("ActionAssignment actor mismatch")
        demand = self.store.record_version(
            "DEMAND_UNIT", str(value.get("demand_unit_id", "")), 2
        )
        if demand is None or demand["payload"].get("state") != "ACCEPTED_GDO":
            raise DomainInvariantError("ActionAssignment requires accepted work")
        if value.get("permit_decision_ref") != decision.get("permit_decision_id"):
            raise DomainInvariantError("ActionAssignment permit reference mismatch")
        if value.get("permit_decision_sha256") != permit_record_sha256(decision):
            raise DomainInvariantError("ActionAssignment exact permit digest mismatch")
        if (
            value.get("policy_version") != decision.get("policy_version")
            or value.get("capacity_snapshot_ref")
            != demand["payload"].get("capacity_snapshot_ref")
        ):
            raise DomainInvariantError("ActionAssignment policy/capacity binding mismatch")
        if (
            demand["payload"].get("lawful_next_action_ref")
            != decision.get("permit_decision_id")
        ):
            raise DomainInvariantError("DemandUnit lawful action does not bind this permit")
        gold = self.store.latest_record(
            "GOLD_ACCEPTANCE", str(demand["payload"].get("gold_acceptance_ref", ""))
        )
        if gold is None or gold["payload"].get("permit_decision_ref") != decision.get(
            "permit_decision_id"
        ):
            raise DomainInvariantError("GoldAcceptance does not bind this permit")
        self.permits.assert_exact(
            decision,
            at_utc=str(value["assigned_at"]),
            action_type=str(value["action_type"]),
            channel="BITRIX24_SHADOW",
            purpose=SHADOW_PURPOSE,
            subject_refs=(str(value["demand_unit_id"]),),
            scope=self.permits.trusted_shadow_scope(
                demand_unit_id=str(value["demand_unit_id"]),
                capacity_snapshot_ref=str(value["capacity_snapshot_ref"]),
            ),
            capacity_snapshot_ref=str(value["capacity_snapshot_ref"]),
            cost=float(value["cost"]),
            currency=str(value["currency"]),
            policy_version=SHADOW_POLICY_VERSION,
            mode="SHADOW",
            attempted_actor_id=writer_id,
            trace_id=trace_id,
        )
        return self._validated_append(
            schema_name="action-assignment.schema.json",
            record_type="ACTION_ASSIGNMENT",
            aggregate_id=str(value["assignment_id"]),
            aggregate_version=1,
            idempotency_key=f"assignment:{value['assignment_id']}",
            record=value,
            writer_id=writer_id,
            required_role="SALES_OPERATOR",
            trace_id=trace_id,
            recorded_at_utc=str(value["assigned_at"]),
        )

    def record_order(
        self,
        order: Mapping[str, Any],
        *,
        writer_id: str,
        trace_id: str,
    ) -> AppendResult:
        actor = self.store.require_actor(writer_id, "ORDER_APPROVER")
        if actor["actor_type"] != "HUMAN" or order.get("approved_by") != writer_id:
            raise HumanAuthorityError("OrderRecord requires its human approver")
        value = dict(order)
        if value.get("version") != 1 or value.get("state") != "APPROVED":
            raise DomainInvariantError("initial OrderRecord must be version 1 / APPROVED")
        if value.get("payload_sha256") != record_digest_excluding(value, "payload_sha256"):
            raise DomainInvariantError("OrderRecord payload digest mismatch")
        demand = self.store.record_version(
            "DEMAND_UNIT", str(value.get("demand_unit_id", "")), 2
        )
        if demand is None or demand["payload"].get("state") != "ACCEPTED_GDO":
            raise DomainInvariantError("OrderRecord requires an accepted DemandUnit")
        if (
            value.get("account_id") != demand["payload"].get("account_ref")
            or value.get("scope_fingerprint") != demand["payload"].get("scope_fingerprint")
        ):
            raise DomainInvariantError("OrderRecord identity/scope mismatch")
        if self.store.record_version(
            "COMMERCIAL_TERMS",
            str(value.get("commercial_terms_ref", "")),
            1,
        ) is None:
            raise DomainInvariantError("OrderRecord references unknown commercial terms")
        return self._validated_append(
            schema_name="order-record.schema.json",
            record_type="ORDER_RECORD",
            aggregate_id=str(value["distinct_order_id"]),
            aggregate_version=int(value["version"]),
            idempotency_key=f"order:{value['distinct_order_id']}:{value['version']}",
            record=value,
            writer_id=writer_id,
            required_role="ORDER_APPROVER",
            trace_id=trace_id,
            recorded_at_utc=str(value["approved_at"]),
        )

    def ingest_payment_observation(
        self,
        observation: Mapping[str, Any],
        *,
        source_content: bytes,
        writer_id: str,
        reconciler_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> PaymentIntakeResult:
        value = dict(observation)
        evidence = self.store.append_evidence(
            content=source_content,
            media_type="application/json",
            source_ref=str(value.get("provider", "fixture-bank")),
            synthetic=True,
            writer_id=writer_id,
            required_role="BANK_ADAPTER",
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        if value.get("source_artifact_sha256") != evidence.content_sha256:
            raise DomainInvariantError("raw payment observation artifact digest mismatch")
        try:
            artifact = json.loads(source_content.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainInvariantError("raw payment artifact is not strict UTF-8 JSON") from exc
        if not isinstance(artifact, dict):
            raise DomainInvariantError("raw payment artifact must be a JSON object")
        if (
            artifact.get("fixture") is not True
            or artifact.get("signed") is not True
            or artifact.get("provider") != "fixture-signed-bank-statement"
        ):
            raise DomainInvariantError("G1 accepts only the signed fixture bank statement adapter")
        if {key: item for key, item in value.items() if key != "source_artifact_sha256"} != artifact:
            raise DomainInvariantError("raw payment observation contains unsealed semantic overrides")
        for field in (
            "provider",
            "provider_event_id",
            "distinct_order_id",
            "canonical_account_id",
            "payer_identity_ref",
            "recipient_identity_ref",
            "amount",
            "currency",
            "value_at",
        ):
            if value.get(field) != artifact.get(field):
                raise DomainInvariantError(f"raw payment observation differs from artifact: {field}")
        provider_key = f"{value.get('provider')}:{value.get('provider_event_id')}"
        value.update(
            {
                "schema_version": "1.0.0",
                "record_id": provider_key,
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "authoritative_class": "SIGNED_BANK_STATEMENT",
            }
        )
        self.append_internal_record(
            record_type="RAW_PAYMENT_OBSERVATION",
            record_id=provider_key,
            payload=value,
            writer_id=writer_id,
            required_role="BANK_ADAPTER",
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        order = self.store.latest_record("ORDER_RECORD", str(value.get("distinct_order_id", "")))
        if order is not None:
            return PaymentIntakeResult("READY_FOR_RECONCILIATION", provider_key, None)
        conflict_id = self.store.record_conflict(
            conflict_type="PAYMENT_WITH_UNKNOWN_ORDER",
            business_key=provider_key,
            existing_sha256=ZERO_SHA256,
            proposed_sha256=value_sha256(value),
            details={
                "distinct_order_id": value.get("distinct_order_id"),
                "payment_observation_id": provider_key,
            },
            blocked_action="CREATE_PAYMENT_PROOF_AND_KPI",
            writer_id=reconciler_id,
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        return PaymentIntakeResult("QUARANTINED", provider_key, conflict_id)

    def _raise_payment_conflict(
        self,
        *,
        payment: Mapping[str, Any],
        reason: str,
        reconciler_id: str,
        trace_id: str,
        existing_payload: Mapping[str, Any] | None = None,
        conflict_type: str = "PAYMENT_RECONCILIATION_MISMATCH",
        legacy_duplicate_message: bool = False,
    ) -> None:
        conflict_id = self.store.record_conflict(
            conflict_type=conflict_type,
            business_key=str(payment.get("distinct_order_id", "")),
            existing_sha256=(
                value_sha256(dict(existing_payload))
                if existing_payload is not None
                else ZERO_SHA256
            ),
            proposed_sha256=value_sha256(dict(payment)),
            details={
                "reason": reason,
                "provider": payment.get("provider"),
                "provider_event_id": payment.get("provider_event_id"),
                "distinct_order_id": payment.get("distinct_order_id"),
            },
            blocked_action="CREATE_PAYMENT_PROOF_AND_KPI",
            writer_id=reconciler_id,
            trace_id=trace_id,
            recorded_at_utc=str(payment.get("verified_at", "")),
        )
        if legacy_duplicate_message:
            raise DomainInvariantError(f"duplicate payment blocked by {conflict_id}")
        raise DomainInvariantError(f"payment transition blocked by {conflict_id}: {reason}")

    def record_payment_installment(
        self,
        *,
        payment_proof: Mapping[str, Any],
        order_update: Mapping[str, Any],
        outcome: Mapping[str, Any] | None,
        verifier_id: str,
        reconciler_id: str,
        trace_id: str,
    ) -> PaymentInstallmentResult:
        actor = self.store.require_actor(verifier_id, "PAYMENT_VERIFIER")
        if actor["actor_type"] != "HUMAN" or payment_proof.get("verified_by") != verifier_id:
            raise HumanAuthorityError("PaymentProof requires its human verifier")
        payment = dict(payment_proof)
        order_value = dict(order_update)
        outcome_value = dict(outcome) if outcome is not None else None
        self.contracts.validate("payment-proof.schema.json", payment)
        self.contracts.validate("order-record.schema.json", order_value)
        if outcome_value is not None:
            self.contracts.validate("outcome-event.schema.json", outcome_value)
        if order_value.get("payload_sha256") != record_digest_excluding(
            order_value, "payload_sha256"
        ):
            raise DomainInvariantError("payment OrderRecord payload digest mismatch")
        if outcome_value is not None and outcome_value.get(
            "payload_sha256"
        ) != record_digest_excluding(outcome_value, "payload_sha256"):
            raise DomainInvariantError("payment OutcomeEvent payload digest mismatch")

        order_id = str(payment.get("distinct_order_id", ""))
        target_version = int(order_value.get("version", 0))
        existing_payment = self.store.latest_record(
            "PAYMENT_PROOF", str(payment.get("payment_proof_id", ""))
        )
        existing_order = self.store.record_version("ORDER_RECORD", order_id, target_version)
        existing_outcome = (
            self.store.latest_record(
                "OUTCOME_EVENT", str(outcome_value.get("outcome_event_id", ""))
            )
            if outcome_value is not None
            else None
        )
        exact_historical_batch = (
            existing_payment is not None
            and existing_payment["payload"] == payment
            and existing_order is not None
            and existing_order["payload"] == order_value
            and (
                (outcome_value is None and order_value.get("state") == "PAID_PARTIAL")
                or (
                    outcome_value is not None
                    and existing_outcome is not None
                    and existing_outcome["payload"] == outcome_value
                )
            )
        )
        if exact_historical_batch:
            committed = self.store.commit_payment_transition(
                payment_proof=payment,
                order_update=order_value,
                outcome=outcome_value,
                verifier_id=verifier_id,
                reconciler_id=reconciler_id,
                trace_id=trace_id,
            )
            return PaymentInstallmentResult(
                committed.payment,
                committed.order,
                committed.outcome,
                str(order_value["state"]),
            )

        if existing_payment is not None:
            self._raise_payment_conflict(
                payment=payment,
                reason="PAYMENT_PROOF_ID_REUSE",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=existing_payment["payload"],
                conflict_type="PAYMENT_PROOF_ID_REUSE",
            )
        provider_matches = [
            row
            for row in self.store.records("PAYMENT_PROOF")
            if row["payload"].get("provider") == payment.get("provider")
            and row["payload"].get("provider_event_id") == payment.get("provider_event_id")
        ]
        if provider_matches:
            self._raise_payment_conflict(
                payment=payment,
                reason="PROVIDER_EVENT_CHANGED",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=provider_matches[0]["payload"],
                conflict_type="DUPLICATE_RECONCILED_PAYMENT",
                legacy_duplicate_message=True,
            )

        if existing_order is not None:
            self._raise_payment_conflict(
                payment=payment,
                reason="ORDER_VERSION_REUSE",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=existing_order["payload"],
                conflict_type="ORDER_VERSION_REUSE",
                legacy_duplicate_message=True,
            )

        terminal_outcomes = [
            row
            for row in self.store.find_payload("OUTCOME_EVENT", "distinct_order_id", order_id)
            if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        ]
        if terminal_outcomes:
            self._raise_payment_conflict(
                payment=payment,
                reason="ORDER_ALREADY_PAID",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=terminal_outcomes[0]["payload"],
                conflict_type="DUPLICATE_RECONCILED_PAYMENT",
                legacy_duplicate_message=True,
            )

        base_order = self.store.record_version("ORDER_RECORD", order_id, 1)
        previous_order = self.store.record_version("ORDER_RECORD", order_id, target_version - 1)
        if (
            base_order is None
            or base_order["payload"].get("state") != "APPROVED"
            or previous_order is None
            or previous_order["payload"].get("state") not in {"APPROVED", "PAID_PARTIAL"}
        ):
            self._raise_payment_conflict(
                payment=payment,
                reason="ORDER_PROGRESSION_INVALID",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=previous_order["payload"] if previous_order else None,
            )
        if order_value.get("distinct_order_id") != order_id:
            self._raise_payment_conflict(
                payment=payment,
                reason="ORDER_ID_MISMATCH",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=base_order["payload"],
            )
        raw_key = f"{payment['provider']}:{payment['provider_event_id']}"
        raw = self.store.record_version("RAW_PAYMENT_OBSERVATION", raw_key, 1)
        evidence = self.store.evidence(str(payment["source_artifact_sha256"]))
        if raw is None or evidence is None:
            self._raise_payment_conflict(
                payment=payment,
                reason="RAW_OR_EVIDENCE_MISSING",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=base_order["payload"],
            )
        value_time = _parse_utc(str(payment["value_at"]))
        evidence_time = _parse_utc(str(evidence["recorded_at_utc"]))
        raw_time = _parse_utc(str(raw["recorded_at_utc"]))
        verified_time = _parse_utc(str(payment["verified_at"]))
        if not value_time <= evidence_time == raw_time <= verified_time:
            self._raise_payment_conflict(
                payment=payment,
                reason="PAYMENT_EVIDENCE_CHRONOLOGY_INVALID",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=raw["payload"],
            )
        terms = self.store.record_version(
            "COMMERCIAL_TERMS",
            str(base_order["payload"]["commercial_terms_ref"]),
            1,
        )
        if terms is None:
            self._raise_payment_conflict(
                payment=payment,
                reason="COMMERCIAL_TERMS_MISSING",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=base_order["payload"],
            )
        demand = self.store.record_version(
            "DEMAND_UNIT", str(base_order["payload"].get("demand_unit_id", "")), 2
        )
        accepted_source_refs: set[str] = set()
        if demand is not None and demand["payload"].get("state") == "ACCEPTED_GDO":
            for claim_id in demand["payload"].get("evidence_claim_ids", []):
                claim = self.store.latest_record("CLAIM", str(claim_id))
                source_ref = (
                    str(claim["payload"].get("source_event_id", "")) if claim else ""
                )
                signal = self.store.latest_record("SIGNAL_OBSERVATION", source_ref)
                if (
                    claim is None
                    or claim["payload"].get("status") != "ACCEPTED"
                    or signal is None
                ):
                    accepted_source_refs.clear()
                    break
                accepted_source_refs.add(source_ref)
        if demand is None or not accepted_source_refs:
            self._raise_payment_conflict(
                payment=payment,
                reason="ACCEPTED_DEMAND_PROVENANCE_MISSING",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=base_order["payload"],
            )
        for field in (
            "provider",
            "provider_event_id",
            "distinct_order_id",
            "canonical_account_id",
            "payer_identity_ref",
            "recipient_identity_ref",
            "amount",
            "currency",
            "value_at",
            "source_artifact_sha256",
            "authoritative_class",
        ):
            if raw["payload"].get(field) != payment.get(field):
                self._raise_payment_conflict(
                    payment=payment,
                    reason=f"RAW_FIELD_MISMATCH:{field}",
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    existing_payload=raw["payload"],
                )
        for field, expected in (
            ("canonical_account_id", base_order["payload"].get("account_id")),
            ("currency", terms["payload"].get("currency")),
        ):
            if payment.get(field) != expected:
                self._raise_payment_conflict(
                    payment=payment,
                    reason=f"TERMS_FIELD_MISMATCH:{field}",
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    existing_payload=terms["payload"],
                )
        if target_version != int(previous_order["aggregate_version"]) + 1:
            self._raise_payment_conflict(
                payment=payment,
                reason="ORDER_VERSION_INVALID",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=previous_order["payload"],
            )
        for field in (
            "distinct_order_id",
            "demand_unit_id",
            "account_id",
            "scope_fingerprint",
            "commercial_terms_ref",
            "approved_by",
            "approved_at",
        ):
            if order_value.get(field) != previous_order["payload"].get(field):
                self._raise_payment_conflict(
                    payment=payment,
                    reason=f"ORDER_IMMUTABLE_FIELD_REWRITE:{field}",
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    existing_payload=previous_order["payload"],
                )

        prior_proofs = self.store.payment_proofs_for_order(order_id)
        settled = sum(
            (_decimal_amount(row["payload"].get("amount"), "PaymentProof amount") for row in prior_proofs),
            Decimal("0"),
        ) + _decimal_amount(payment.get("amount"), "PaymentProof amount")
        due = _decimal_amount(terms["payload"].get("amount"), "commercial terms amount")
        if settled > due:
            self._raise_payment_conflict(
                payment=payment,
                reason="OVERPAYMENT",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=terms["payload"],
            )
        expected_state = "PAID" if settled == due else "PAID_PARTIAL"
        if order_value.get("state") != expected_state:
            self._raise_payment_conflict(
                payment=payment,
                reason=f"ORDER_STATE_MUST_BE_{expected_state}",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=previous_order["payload"],
            )
        if expected_state == "PAID_PARTIAL" and outcome_value is not None:
            self._raise_payment_conflict(
                payment=payment,
                reason="PARTIAL_PAYMENT_CANNOT_EMIT_CLEARED_PAYMENT",
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                existing_payload=order_value,
            )
        if expected_state == "PAID":
            if outcome_value is None or (
                outcome_value.get("payment_proof_ref") != payment.get("payment_proof_id")
                or outcome_value.get("distinct_order_id") != order_id
                or outcome_value.get("authoritative_class") != payment.get("authoritative_class")
                or outcome_value.get("source_system") != payment.get("provider")
                or outcome_value.get("event_time") != payment.get("value_at")
                or outcome_value.get("reconciliation_state") != "RECONCILED"
                or outcome_value.get("outcome_type") != "CLEARED_PAYMENT"
                or outcome_value.get("demand_unit_id")
                != base_order["payload"].get("demand_unit_id")
                or outcome_value.get("account_id") != payment.get("canonical_account_id")
                or outcome_value.get("amount") != terms["payload"].get("amount")
                or outcome_value.get("currency") != payment.get("currency")
                or outcome_value.get("motion") != demand["payload"].get("motion")
                or outcome_value.get("original_source_ref") not in accepted_source_refs
                or outcome_value.get("latest_source_ref")
                != payment.get("provider_event_id")
            ):
                self._raise_payment_conflict(
                    payment=payment,
                    reason="TERMINAL_OUTCOME_TRUTH_BINDING_MISMATCH",
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    existing_payload=order_value,
                )

        committed = self.store.commit_payment_transition(
            payment_proof=payment,
            order_update=order_value,
            outcome=outcome_value,
            verifier_id=verifier_id,
            reconciler_id=reconciler_id,
            trace_id=trace_id,
        )
        return PaymentInstallmentResult(
            committed.payment,
            committed.order,
            committed.outcome,
            expected_state,
        )

    def record_payment_and_outcome(
        self,
        *,
        payment_proof: Mapping[str, Any],
        paid_order: Mapping[str, Any],
        outcome: Mapping[str, Any],
        verifier_id: str,
        reconciler_id: str,
        trace_id: str,
    ) -> tuple[AppendResult, AppendResult, AppendResult]:
        result = self.record_payment_installment(
            payment_proof=payment_proof,
            order_update=paid_order,
            outcome=outcome,
            verifier_id=verifier_id,
            reconciler_id=reconciler_id,
            trace_id=trace_id,
        )
        if result.outcome is None:
            raise DomainInvariantError("full payment compatibility path requires an outcome")
        return result.payment, result.order, result.outcome

    def ingest_fulfilment_document(
        self,
        document: Mapping[str, Any],
        *,
        source_content: bytes,
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> AppendResult:
        """Bind one signed fixture UPD to immutable bytes before fulfilment truth."""

        value = dict(document)
        try:
            artifact = json.loads(source_content.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainInvariantError("fulfilment artifact is not strict UTF-8 JSON") from exc
        if not isinstance(artifact, dict) or artifact != value:
            raise DomainInvariantError("fulfilment document differs from its source artifact")
        if (
            artifact.get("fixture") is not True
            or artifact.get("document_type") != "SIGNED_UPD"
            or artifact.get("accepted_by_customer") is not True
            or not artifact.get("document_ref")
            or not artifact.get("distinct_order_id")
            or not artifact.get("event_at")
        ):
            raise DomainInvariantError("G1 requires an accepted signed fixture UPD")
        evidence = self.store.append_evidence(
            content=source_content,
            media_type="application/json",
            source_ref=str(artifact["document_ref"]),
            synthetic=True,
            writer_id=writer_id,
            required_role="FULFILMENT_WRITER",
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        record_id = str(artifact["document_ref"])
        payload = {
            "schema_version": "1.0.0",
            "record_id": record_id,
            "synthetic": True,
            "canonical_kpi_eligible": False,
            **artifact,
            "evidence_sha256": evidence.content_sha256,
        }
        return self.append_internal_record(
            record_type="RAW_FULFILMENT_DOCUMENT",
            record_id=record_id,
            payload=payload,
            writer_id=writer_id,
            required_role="FULFILMENT_WRITER",
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )

    def record_fulfilment_and_outcome(
        self,
        *,
        fulfilment: Mapping[str, Any],
        fulfilled_order: Mapping[str, Any],
        outcome: Mapping[str, Any],
        writer_id: str,
        reconciler_id: str,
        trace_id: str,
    ) -> tuple[AppendResult, AppendResult, AppendResult]:
        actor = self.store.require_actor(writer_id, "FULFILMENT_WRITER")
        if actor["actor_type"] != "HUMAN" or fulfilment.get("actor_id") != writer_id:
            raise HumanAuthorityError("FulfilmentRecord requires its human ledger actor")
        value = dict(fulfilment)
        order_update = dict(fulfilled_order)
        outcome_value = dict(outcome)
        self.contracts.validate("fulfilment-record.schema.json", value)
        raw_document = self.store.record_version(
            "RAW_FULFILMENT_DOCUMENT",
            str(value.get("primary_document_ref", "")),
            1,
        )
        if raw_document is None:
            raise DomainInvariantError("FulfilmentRecord has no typed signed document intake")
        fulfilment_evidence = self.store.evidence(str(value.get("evidence_sha256", "")))
        if fulfilment_evidence is None or not (
            _parse_utc(str(value.get("event_at", "")))
            <= _parse_utc(str(fulfilment_evidence["recorded_at_utc"]))
            == _parse_utc(str(raw_document["recorded_at_utc"]))
            <= _parse_utc(str(outcome_value.get("recorded_at", "")))
        ):
            raise DomainInvariantError(
                "FulfilmentRecord evidence was not recorded by its claimed event time"
            )
        for field in ("distinct_order_id", "evidence_sha256", "event_at"):
            if raw_document["payload"].get(field) != value.get(field):
                raise DomainInvariantError(f"FulfilmentRecord differs from signed document: {field}")
        if (
            raw_document["payload"].get("document_ref") != value.get("primary_document_ref")
            or raw_document["payload"].get("accepted_by_customer") is not True
            or value.get("event_type") != "ACCEPTED_BY_CUSTOMER"
        ):
            raise DomainInvariantError("FulfilmentRecord is not customer-accepted signed evidence")
        order_id = str(value.get("distinct_order_id", ""))
        target_version = int(order_update.get("version", 0))
        previous_order = self.store.record_version(
            "ORDER_RECORD", order_id, target_version - 1
        )
        if previous_order is None or previous_order["payload"].get("state") != "PAID":
            raise DomainInvariantError("FulfilmentRecord requires a paid OrderRecord")
        latest_order = self.store.latest_record("ORDER_RECORD", order_id)
        existing_target_order = self.store.record_version(
            "ORDER_RECORD", order_id, target_version
        )
        exact_order_replay = (
            existing_target_order is not None
            and existing_target_order["payload"] == order_update
        )
        if existing_target_order is not None and not exact_order_replay:
            raise DomainInvariantError("fulfilled OrderRecord version is already bound")
        if not exact_order_replay and (
            latest_order is None
            or target_version != int(latest_order["aggregate_version"]) + 1
        ):
            raise DomainInvariantError("fulfilled OrderRecord must be latest version plus one")
        if (
            order_update.get("version") != int(previous_order["aggregate_version"]) + 1
            or order_update.get("state") != "FULFILLED"
            or order_update.get("distinct_order_id") != value.get("distinct_order_id")
            or order_update.get("payload_sha256")
            != record_digest_excluding(order_update, "payload_sha256")
        ):
            raise DomainInvariantError("fulfilled OrderRecord revision is invalid")
        for field in (
            "distinct_order_id",
            "demand_unit_id",
            "account_id",
            "scope_fingerprint",
            "commercial_terms_ref",
            "approved_by",
            "approved_at",
        ):
            if order_update.get(field) != previous_order["payload"].get(field):
                raise DomainInvariantError(f"fulfilled OrderRecord rewrote {field}")
        self.contracts.validate("order-record.schema.json", order_update)
        if outcome_value.get("payload_sha256") != record_digest_excluding(
            outcome_value, "payload_sha256"
        ):
            raise DomainInvariantError("fulfilment OutcomeEvent payload digest mismatch")
        payments = self.store.payment_proofs_for_order(order_id)
        terms = self.store.record_version(
            "COMMERCIAL_TERMS",
            str(previous_order["payload"]["commercial_terms_ref"]),
            1,
        )
        demand = self.store.record_version(
            "DEMAND_UNIT",
            str(previous_order["payload"]["demand_unit_id"]),
            2,
        )
        terminal_payment_outcomes = [
            row
            for row in self.store.find_payload("OUTCOME_EVENT", "distinct_order_id", order_id)
            if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        ]
        if not payments or terms is None or demand is None:
            raise DomainInvariantError("FulfilmentRecord lacks reconciled payment/terms/demand")
        due = _decimal_amount(terms["payload"].get("amount"), "commercial terms amount")
        settled = sum(
            (
                _decimal_amount(row["payload"].get("amount"), "PaymentProof amount")
                for row in payments
            ),
            Decimal("0"),
        )
        terminal_proof = payments[-1]["payload"]
        if (
            settled != due
            or any(
                row["payload"].get("currency") != terms["payload"].get("currency")
                or row["payload"].get("canonical_account_id")
                != previous_order["payload"].get("account_id")
                or row["payload"].get("reconciliation_state") != "RECONCILED"
                for row in payments
            )
            or len(terminal_payment_outcomes) != 1
            or terminal_payment_outcomes[0]["payload"].get("payment_proof_ref")
            != terminal_proof.get("payment_proof_id")
        ):
            raise DomainInvariantError(
                "FulfilmentRecord requires an exact ordered proof set and one terminal payment truth"
            )
        accepted_source_refs: set[str] = set()
        for claim_id in demand["payload"].get("evidence_claim_ids", []):
            claim = self.store.latest_record("CLAIM", str(claim_id))
            source_ref = str(claim["payload"].get("source_event_id", "")) if claim else ""
            signal = self.store.latest_record("SIGNAL_OBSERVATION", source_ref)
            if (
                claim is None
                or claim["payload"].get("status") != "ACCEPTED"
                or signal is None
            ):
                accepted_source_refs.clear()
                break
            accepted_source_refs.add(source_ref)
        if not accepted_source_refs:
            raise DomainInvariantError("FulfilmentRecord has no accepted demand provenance")
        if (
            outcome_value.get("distinct_order_id") != value.get("distinct_order_id")
            or outcome_value.get("authoritative_class") != "FULFILMENT_LEDGER"
            or outcome_value.get("outcome_type") != "FULFILLED"
            or outcome_value.get("demand_unit_id") != previous_order["payload"].get("demand_unit_id")
            or outcome_value.get("account_id") != previous_order["payload"].get("account_id")
            or outcome_value.get("reconciliation_state") != "RECONCILED"
            or outcome_value.get("payment_proof_ref")
            != terminal_proof.get("payment_proof_id")
            or outcome_value.get("amount") != terms["payload"].get("amount")
            or outcome_value.get("currency") != terms["payload"].get("currency")
            or outcome_value.get("motion") != demand["payload"].get("motion")
            or outcome_value.get("event_time") != value.get("event_at")
            or outcome_value.get("latest_source_ref") != value.get("fulfilment_record_id")
            or outcome_value.get("original_source_ref") not in accepted_source_refs
        ):
            raise DomainInvariantError("fulfilment OutcomeEvent truth binding mismatch")
        self.contracts.validate("outcome-event.schema.json", outcome_value)

        existing_fulfilments = self.store.find_payload(
            "FULFILMENT_RECORD", "distinct_order_id", str(value["distinct_order_id"])
        )
        existing_outcomes = [
            row
            for row in self.store.find_payload(
                "OUTCOME_EVENT", "distinct_order_id", str(value["distinct_order_id"])
            )
            if row["payload"].get("outcome_type") == "FULFILLED"
        ]
        non_exact_fulfilments = [
            row for row in existing_fulfilments if row["payload"] != value
        ]
        non_exact_outcomes = [
            row for row in existing_outcomes if row["payload"] != outcome_value
        ]
        if non_exact_fulfilments or non_exact_outcomes:
            existing_payload = (
                non_exact_fulfilments[0]["payload"]
                if non_exact_fulfilments
                else non_exact_outcomes[0]["payload"]
            )
            conflict_id = self.store.record_conflict(
                conflict_type="DUPLICATE_TERMINAL_FULFILMENT",
                business_key=str(value["distinct_order_id"]),
                existing_sha256=value_sha256(existing_payload),
                proposed_sha256=value_sha256(value),
                details={"fulfilment_record_id": value["fulfilment_record_id"]},
                blocked_action="CREATE_FULFILMENT_OUTCOME_AND_KPI",
                writer_id=reconciler_id,
                trace_id=trace_id,
                recorded_at_utc=str(value["event_at"]),
            )
            raise DomainInvariantError(f"duplicate fulfilment blocked by {conflict_id}")

        fulfilment_result, order_result, outcome_result = self.store._append_domain_batch(
            (
                {
                    "record_type": "FULFILMENT_RECORD",
                    "aggregate_id": str(value["fulfilment_record_id"]),
                    "aggregate_version": int(value["version"]),
                    "idempotency_key": (
                        f"fulfilment:{value['fulfilment_record_id']}:{value['version']}"
                    ),
                    "payload": value,
                    "writer_id": writer_id,
                    "required_role": "FULFILMENT_WRITER",
                    "trace_id": trace_id,
                    "recorded_at_utc": str(outcome_value["recorded_at"]),
                },
                {
                    "record_type": "ORDER_RECORD",
                    "aggregate_id": str(order_update["distinct_order_id"]),
                    "aggregate_version": int(order_update["version"]),
                    "idempotency_key": (
                        f"order:{order_update['distinct_order_id']}:{order_update['version']}"
                    ),
                    "payload": order_update,
                    "writer_id": writer_id,
                    "required_role": "FULFILMENT_WRITER",
                    "trace_id": trace_id,
                    "recorded_at_utc": str(outcome_value["recorded_at"]),
                },
                {
                    "record_type": "OUTCOME_EVENT",
                    "aggregate_id": str(outcome_value["outcome_event_id"]),
                    "aggregate_version": 1,
                    "idempotency_key": f"outcome:{outcome_value['outcome_event_id']}",
                    "payload": outcome_value,
                    "writer_id": reconciler_id,
                    "required_role": "RECONCILER",
                    "trace_id": trace_id,
                    "recorded_at_utc": str(outcome_value["recorded_at"]),
                },
            )
        )
        return fulfilment_result, order_result, outcome_result

    def record_conflict_resolution(
        self,
        resolution: Mapping[str, Any],
        *,
        arbitrator_id: str,
        trace_id: str,
    ) -> AppendResult:
        actor = self.store.require_actor(arbitrator_id, "CONFLICT_ARBITRATOR")
        if actor["actor_type"] != "HUMAN":
            raise HumanAuthorityError("conflict arbitration requires a human actor")
        value = dict(resolution)
        if (
            value.get("arbitrator_id") != arbitrator_id
            or value.get("decision") != "RESOLVED"
        ):
            raise HumanAuthorityError("conflict resolution authority mismatch")
        conflicts = {
            item["conflict_id"]: item for item in self.store.conflicts()
        }
        conflict = conflicts.get(str(value.get("conflict_id", "")))
        if conflict is None:
            raise DomainInvariantError("conflict resolution references an unknown conflict")
        if conflict.get("writer_id") == arbitrator_id:
            raise HumanAuthorityError("conflict writer cannot arbitrate its own conflict")
        if value.get("attestation_sha256") != record_digest_excluding(
            value, "attestation_sha256"
        ):
            raise DomainInvariantError("conflict resolution attestation digest mismatch")
        return self.append_internal_record(
            record_type="CONFLICT_RESOLUTION",
            record_id=str(value["record_id"]),
            payload=value,
            writer_id=arbitrator_id,
            required_role="CONFLICT_ARBITRATOR",
            trace_id=trace_id,
            recorded_at_utc=str(value["reviewed_at"]),
        )

    def reconcile(
        self,
        *,
        reconciliation_id: str,
        distinct_order_id: str,
        demand_unit_id: str,
        writer_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> ReconciliationResult:
        self.store.verify_integrity()
        resolved_conflicts = {
            row["payload"].get("conflict_id")
            for row in self.store.records("CONFLICT_RESOLUTION")
            if row["payload"].get("decision") == "RESOLVED"
        }
        relevant_conflicts = []
        for conflict in self.store.conflicts():
            details = dict(conflict.get("details") or {})
            relevant = conflict.get("business_key") in {
                distinct_order_id,
                demand_unit_id,
            } or details.get("distinct_order_id") == distinct_order_id
            if relevant and conflict["conflict_id"] not in resolved_conflicts:
                relevant_conflicts.append(conflict)
        if relevant_conflicts:
            conflict_ids = ",".join(item["conflict_id"] for item in relevant_conflicts)
            raise ReconciliationBlocked(
                f"reconciliation blocked by unresolved conflicts: {conflict_ids}"
            )
        order = self.store.latest_record("ORDER_RECORD", distinct_order_id)
        payments = self.store.payment_proofs_for_order(distinct_order_id)
        fulfilments = self.store.find_payload(
            "FULFILMENT_RECORD", "distinct_order_id", distinct_order_id
        )
        payment_outcomes = [
            row
            for row in self.store.find_payload("OUTCOME_EVENT", "distinct_order_id", distinct_order_id)
            if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        ]
        fulfilment_outcomes = [
            row
            for row in self.store.find_payload("OUTCOME_EVENT", "distinct_order_id", distinct_order_id)
            if row["payload"].get("outcome_type") == "FULFILLED"
        ]
        reasons: list[str] = []
        if order is None or order["payload"].get("state") != "FULFILLED":
            reasons.append("ORDER_NOT_FULFILLED")
        if not payments:
            reasons.append("PAYMENT_PROOF_SET_MISSING")
        if len(fulfilments) != 1:
            reasons.append("FULFILMENT_CARDINALITY")
        if len(payment_outcomes) != 1 or len(fulfilment_outcomes) != 1:
            reasons.append("OUTCOME_RECONCILIATION_MISSING")
        base_order = self.store.record_version("ORDER_RECORD", distinct_order_id, 1)
        terms = (
            self.store.record_version(
                "COMMERCIAL_TERMS",
                str(base_order["payload"].get("commercial_terms_ref", "")),
                1,
            )
            if base_order is not None
            else None
        )
        terminal_proof = payments[-1] if payments else None
        if base_order is None or terms is None:
            reasons.append("COMMERCIAL_TERMS_MISSING")
        elif payments:
            settled = sum(
                (
                    _decimal_amount(item["payload"].get("amount"), "PaymentProof amount")
                    for item in payments
                ),
                Decimal("0"),
            )
            due = _decimal_amount(terms["payload"].get("amount"), "commercial terms amount")
            if (
                settled != due
                or any(
                    item["payload"].get("currency") != terms["payload"].get("currency")
                    or item["payload"].get("canonical_account_id")
                    != base_order["payload"].get("account_id")
                    or item["payload"].get("reconciliation_state") != "RECONCILED"
                    for item in payments
                )
            ):
                reasons.append("PAYMENT_PROOF_SET_NOT_EXACTLY_SETTLED")
        if (
            terminal_proof is not None
            and len(payment_outcomes) == 1
            and payment_outcomes[0]["payload"].get("payment_proof_ref")
            != terminal_proof["payload"].get("payment_proof_id")
        ):
            reasons.append("PAYMENT_TERMINAL_PROOF_MISMATCH")
        if (
            terminal_proof is not None
            and len(fulfilment_outcomes) == 1
            and fulfilment_outcomes[0]["payload"].get("payment_proof_ref")
            != terminal_proof["payload"].get("payment_proof_id")
        ):
            reasons.append("FULFILMENT_TERMINAL_PROOF_MISMATCH")
        demand = self.store.record_version("DEMAND_UNIT", demand_unit_id, 2)
        if demand is None or demand["payload"].get("state") != "ACCEPTED_GDO":
            reasons.append("DEMAND_UNIT_NOT_ACCEPTED")
        if order is not None and order["payload"].get("demand_unit_id") != demand_unit_id:
            reasons.append("ORDER_DEMAND_MISMATCH")
        reconciled_at = _parse_utc(recorded_at_utc)
        bound_terminal_times: list[datetime] = []
        if terminal_proof is not None:
            bound_terminal_times.extend(
                (
                    _parse_utc(str(terminal_proof["payload"].get("value_at", ""))),
                    _parse_utc(str(terminal_proof["payload"].get("verified_at", ""))),
                    _parse_utc(str(terminal_proof["recorded_at_utc"])),
                )
            )
        for item in payment_outcomes:
            bound_terminal_times.extend(
                (
                    _parse_utc(str(item["payload"].get("event_time", ""))),
                    _parse_utc(str(item["payload"].get("recorded_at", ""))),
                    _parse_utc(str(item["recorded_at_utc"])),
                )
            )
        for item in fulfilments:
            bound_terminal_times.extend(
                (
                    _parse_utc(str(item["payload"].get("event_at", ""))),
                    _parse_utc(str(item["recorded_at_utc"])),
                )
            )
        for item in fulfilment_outcomes:
            bound_terminal_times.extend(
                (
                    _parse_utc(str(item["payload"].get("event_time", ""))),
                    _parse_utc(str(item["payload"].get("recorded_at", ""))),
                    _parse_utc(str(item["recorded_at_utc"])),
                )
            )
        if any(bound_time > reconciled_at for bound_time in bound_terminal_times):
            reasons.append("RECONCILIATION_BACKDATED")
        if reasons:
            conflict_id = self.store.record_conflict(
                conflict_type="COMMERCIAL_TRUTH_RECONCILIATION",
                business_key=distinct_order_id,
                existing_sha256=value_sha256(order["payload"]) if order else ZERO_SHA256,
                proposed_sha256=value_sha256({"reasons": reasons}),
                details={"reasons": reasons, "demand_unit_id": demand_unit_id},
                blocked_action="EMIT_COMMERCIAL_KPI",
                writer_id=writer_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
            )
            raise ReconciliationBlocked(f"reconciliation blocked by {conflict_id}: {reasons}")
        payload = {
            "schema_version": "1.0.0",
            "record_id": reconciliation_id,
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "status": "RECONCILED_FIXTURE_NON_KPI",
            "distinct_order_id": distinct_order_id,
            "demand_unit_id": demand_unit_id,
            "order_record_entry_id": order["entry_id"],
            "payment_proof_entry_id": terminal_proof["entry_id"],
            "fulfilment_record_entry_ids": [item["entry_id"] for item in fulfilments],
            "payment_outcome_entry_id": payment_outcomes[0]["entry_id"],
            "fulfilment_outcome_entry_id": fulfilment_outcomes[0]["entry_id"],
            "reconciled_at": recorded_at_utc,
        }
        if len(payments) > 1:
            payload["payment_proof_entry_ids"] = [
                item["entry_id"] for item in payments
            ]
            payload["payment_proof_refs"] = [
                item["payload"]["payment_proof_id"] for item in payments
            ]
        appended = self.append_internal_record(
            record_type="RECONCILIATION_RESULT",
            record_id=reconciliation_id,
            payload=payload,
            writer_id=writer_id,
            required_role="RECONCILER",
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        return ReconciliationResult(
            reconciliation_id,
            "RECONCILED_FIXTURE_NON_KPI",
            False,
            appended.entry_id,
        )


__all__ = [
    "DomainInvariantError",
    "G1Pipeline",
    "HumanAuthorityError",
    "PaymentIntakeResult",
    "PaymentInstallmentResult",
    "ReconciliationBlocked",
    "ReconciliationResult",
    "scope_fingerprint",
]
