"""Deterministic two-installment payment slice over synthetic local evidence only.

The slice extends the proven G1 fixture with a second, isolated order.  It does
not authorize live reads, writes, contact, spend, KPI emission, or owner
ratification.  Every human-looking decision is a sealed synthetic test input.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Mapping

from .authority import CONTRACT_ID, PACKAGE_ROOT_SHA256, PACKAGE_VERSION
from .contracts import (
    ContractRegistry,
    canonical_json_bytes,
    record_digest_excluding,
    value_sha256,
)
from .fixture_slice import DEFAULT_FIXTURE, load_fixture, run_g1_fixture_slice
from .pipeline import G1Pipeline, PaymentInstallmentResult
from .policy import PermitService
from .store import AppendResult, MdosStore


DEFAULT_SPLIT_PAYMENT_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "market_demand_os_v7"
    / "g1_split_payment"
    / "fixture.json"
)


class SplitPaymentFixtureError(RuntimeError):
    """A local split-payment fixture is not exact or not sealed."""


@dataclass(frozen=True)
class SplitPaymentContext:
    fixture: Mapping[str, Any]
    base_fixture: Mapping[str, Any]
    store: MdosStore
    pipeline: G1Pipeline
    trace_id: str
    order_v1: Mapping[str, Any]
    demand: Mapping[str, Any]


def _amount(value: object, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except Exception as exc:  # pragma: no cover - fixture validation normalizes the error
        raise SplitPaymentFixtureError(f"{label} is not an exact decimal") from exc
    if not result.is_finite() or result <= 0:
        raise SplitPaymentFixtureError(f"{label} must be positive and finite")
    return result


def _with_digest(record: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(record)
    value["payload_sha256"] = record_digest_excluding(value, "payload_sha256")
    return value


def load_split_payment_fixture(
    path: str | Path = DEFAULT_SPLIT_PAYMENT_FIXTURE,
) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SplitPaymentFixtureError("split-payment fixture root must be an object")
    expected = {
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "classification": "SYNTHETIC_FIXTURE_NON_CANONICAL_NON_KPI",
        "base_fixture_id": "g1-existing-account-shadow-001",
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise SplitPaymentFixtureError(f"split-payment fixture authority mismatch: {field}")

    terms = value.get("commercial_terms")
    artifacts = value.get("signed_bank_statement_payloads")
    fulfilment = value.get("fulfilment_document_payload")
    human = value.get("human_inputs")
    if not isinstance(terms, dict) or not isinstance(human, dict):
        raise SplitPaymentFixtureError("split-payment terms or human inputs are missing")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise SplitPaymentFixtureError("split-payment fixture requires exactly two installments")
    if not isinstance(fulfilment, dict):
        raise SplitPaymentFixtureError("split-payment fulfilment document is missing")

    order_id = str(terms.get("distinct_order_id", ""))
    due = _amount(terms.get("amount"), "commercial terms amount")
    provider_events: set[tuple[str, str]] = set()
    settled = Decimal("0")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise SplitPaymentFixtureError("payment artifact must be an object")
        event = (str(artifact.get("provider", "")), str(artifact.get("provider_event_id", "")))
        if event in provider_events:
            raise SplitPaymentFixtureError("payment provider events must be distinct")
        provider_events.add(event)
        if (
            artifact.get("fixture") is not True
            or artifact.get("signed") is not True
            or artifact.get("distinct_order_id") != order_id
            or artifact.get("currency") != terms.get("currency")
        ):
            raise SplitPaymentFixtureError("payment artifact differs from sealed commercial terms")
        settled += _amount(artifact.get("amount"), "installment amount")
    if settled != due:
        raise SplitPaymentFixtureError("two installments do not exactly settle commercial terms")
    if (
        fulfilment.get("fixture") is not True
        or fulfilment.get("document_type") != "SIGNED_UPD"
        or fulfilment.get("accepted_by_customer") is not True
        or fulfilment.get("distinct_order_id") != order_id
    ):
        raise SplitPaymentFixtureError("fulfilment document is not exact signed fixture evidence")

    for name in ("order_approval", "payment_verification", "fulfilment_attestation"):
        sealed = human.get(name)
        if not isinstance(sealed, dict):
            raise SplitPaymentFixtureError(f"sealed human input is missing: {name}")
        digest = str(sealed.get("sealed_input_sha256", ""))
        expected_digest = value_sha256(
            {key: item for key, item in sealed.items() if key != "sealed_input_sha256"}
        )
        if digest != expected_digest:
            raise SplitPaymentFixtureError(f"sealed human input mismatch: {name}")

    order_approval = human["order_approval"]
    payment_verification = human["payment_verification"]
    fulfilment_attestation = human["fulfilment_attestation"]
    ordered_provider_event_ids = [
        str(artifact.get("provider_event_id", "")) for artifact in artifacts
    ]
    if (
        order_approval.get("decision") != "APPROVED"
        or order_approval.get("distinct_order_id") != order_id
        or _amount(order_approval.get("amount"), "sealed order approval amount") != due
        or order_approval.get("currency") != terms.get("currency")
    ):
        raise SplitPaymentFixtureError(
            "sealed order approval does not match commercial terms"
        )
    if (
        payment_verification.get("decision") != "RECONCILED"
        or payment_verification.get("distinct_order_id") != order_id
        or payment_verification.get("provider_event_ids")
        != ordered_provider_event_ids
    ):
        raise SplitPaymentFixtureError(
            "sealed payment verification does not match ordered provider events"
        )
    if (
        fulfilment_attestation.get("decision") != "ACCEPTED_BY_CUSTOMER"
        or fulfilment_attestation.get("distinct_order_id") != order_id
        or fulfilment_attestation.get("document_ref")
        != fulfilment.get("document_ref")
    ):
        raise SplitPaymentFixtureError(
            "sealed fulfilment attestation does not match signed document"
        )
    return value


def prepare_split_payment_fixture(
    database_path: str | Path,
    *,
    fixture_path: str | Path = DEFAULT_SPLIT_PAYMENT_FIXTURE,
    delivery_run_id: str = "split-payment-default",
) -> SplitPaymentContext:
    """Prepare the accepted demand plus one isolated APPROVED split-payment order."""

    if not delivery_run_id or delivery_run_id.strip() != delivery_run_id:
        raise SplitPaymentFixtureError("delivery_run_id must be a canonical non-empty string")
    fixture = load_split_payment_fixture(fixture_path)
    base_fixture = load_fixture(DEFAULT_FIXTURE)
    run_g1_fixture_slice(
        database_path,
        fixture_path=DEFAULT_FIXTURE,
        delivery_run_id=f"{delivery_run_id}-base",
    )
    store = MdosStore(database_path, actor_registry=dict(base_fixture["actors"]))
    contracts = ContractRegistry(Path(__file__).resolve().parents[2])
    pipeline = G1Pipeline(store, contracts, PermitService(store, contracts))
    trace_id = f"trace:{fixture['fixture_id']}:{delivery_run_id}"
    terms = dict(fixture["commercial_terms"])
    human = dict(fixture["human_inputs"])
    business = dict(base_fixture["business"])
    demand_row = store.record_version("DEMAND_UNIT", str(business["demand_unit_id"]), 2)
    if demand_row is None or demand_row["payload"].get("state") != "ACCEPTED_GDO":
        raise SplitPaymentFixtureError("base fixture has no accepted demand")
    demand = dict(demand_row["payload"])

    terms_id = "commercial-terms-fixture-split-001"
    terms_payload = {
        "schema_version": "1.0.0",
        "record_id": terms_id,
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "approved_fixture_input_ref": human["order_approval"]["sealed_input_sha256"],
        "amount": terms["amount"],
        "currency": terms["currency"],
        "captured_at": "2026-08-25T10:10:00Z",
    }
    pipeline.append_internal_record(
        record_type="COMMERCIAL_TERMS",
        record_id=terms_id,
        payload=terms_payload,
        writer_id=str(human["order_approval"]["approver_id"]),
        required_role="ORDER_APPROVER",
        trace_id=trace_id,
        recorded_at_utc="2026-08-25T10:10:00Z",
    )
    order_v1 = _with_digest(
        {
            "schema_version": "1.0.0",
            "distinct_order_id": terms["distinct_order_id"],
            "demand_unit_id": business["demand_unit_id"],
            "account_id": business["account_id"],
            "scope_fingerprint": demand["scope_fingerprint"],
            "commercial_terms_ref": terms_id,
            "state": human["order_approval"]["decision"],
            "approved_by": human["order_approval"]["approver_id"],
            "approved_at": "2026-08-25T10:11:00Z",
            "version": 1,
            "payload_sha256": "",
        }
    )
    pipeline.record_order(
        order_v1,
        writer_id=str(human["order_approval"]["approver_id"]),
        trace_id=trace_id,
    )
    return SplitPaymentContext(
        fixture=fixture,
        base_fixture=base_fixture,
        store=store,
        pipeline=pipeline,
        trace_id=trace_id,
        order_v1=order_v1,
        demand=demand,
    )


def ingest_fixture_installment(
    context: SplitPaymentContext,
    installment_index: int,
) -> Mapping[str, Any]:
    artifact = dict(context.fixture["signed_bank_statement_payloads"][installment_index])
    content = canonical_json_bytes(artifact)
    observation = {**artifact, "source_artifact_sha256": value_sha256(artifact)}
    result = context.pipeline.ingest_payment_observation(
        observation,
        source_content=content,
        writer_id="fixture-bank-adapter",
        reconciler_id="fixture-reconciler",
        trace_id=context.trace_id,
        recorded_at_utc=(
            "2026-08-25T10:12:01Z"
            if installment_index == 0
            else "2026-08-25T10:14:01Z"
        ),
    )
    if result.status != "READY_FOR_RECONCILIATION":
        raise SplitPaymentFixtureError("installment did not resolve to the approved order")
    return observation


def fixture_payment_transition(
    context: SplitPaymentContext,
    installment_index: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    """Build the exact transition payloads; intake must be recorded separately."""

    artifact = dict(context.fixture["signed_bank_statement_payloads"][installment_index])
    terms = dict(context.fixture["commercial_terms"])
    human = dict(context.fixture["human_inputs"])
    version = installment_index + 2
    terminal = installment_index == 1
    verified_at = "2026-08-25T10:13:00Z" if installment_index == 0 else "2026-08-25T10:15:00Z"
    payment = {
        "schema_version": "1.0.0",
        "payment_proof_id": f"payment-proof-fixture-split-{installment_index + 1:03d}",
        "authoritative_class": "SIGNED_BANK_STATEMENT",
        "provider": artifact["provider"],
        "provider_event_id": artifact["provider_event_id"],
        "canonical_account_id": artifact["canonical_account_id"],
        "distinct_order_id": artifact["distinct_order_id"],
        "payer_identity_ref": artifact["payer_identity_ref"],
        "recipient_identity_ref": artifact["recipient_identity_ref"],
        "amount": artifact["amount"],
        "currency": artifact["currency"],
        "value_at": artifact["value_at"],
        "source_artifact_sha256": value_sha256(artifact),
        "reconciliation_state": human["payment_verification"]["decision"],
        "verified_by": human["payment_verification"]["verifier_id"],
        "verified_at": verified_at,
    }
    order = _with_digest(
        {
            **dict(context.order_v1),
            "state": "PAID" if terminal else "PAID_PARTIAL",
            "version": version,
            "payload_sha256": "",
        }
    )
    outcome = None
    if terminal:
        outcome = _with_digest(
            {
                "schema_version": "1.1.0",
                "outcome_event_id": "outcome-fixture-split-cleared-payment-001",
                "outcome_type": "CLEARED_PAYMENT",
                "demand_unit_id": context.order_v1["demand_unit_id"],
                "account_id": context.order_v1["account_id"],
                "motion": context.demand["motion"],
                "event_time": artifact["value_at"],
                "recorded_at": "2026-08-25T10:15:01Z",
                "source_system": artifact["provider"],
                "authoritative_class": "SIGNED_BANK_STATEMENT",
                "distinct_order_id": artifact["distinct_order_id"],
                "payment_proof_ref": payment["payment_proof_id"],
                "amount": terms["amount"],
                "cost": None,
                "contribution_margin": None,
                "currency": terms["currency"],
                "original_source_ref": "signal-fixture-existing-001",
                "latest_source_ref": artifact["provider_event_id"],
                "influence_refs": [],
                "action_assignment_refs": [],
                "routing_ref": None,
                "reconciliation_state": "RECONCILED",
                "payload_sha256": "",
            }
        )
    return payment, order, outcome


def record_fixture_installment(
    context: SplitPaymentContext,
    installment_index: int,
) -> PaymentInstallmentResult:
    ingest_fixture_installment(context, installment_index)
    payment, order, outcome = fixture_payment_transition(context, installment_index)
    human = dict(context.fixture["human_inputs"])
    return context.pipeline.record_payment_installment(
        payment_proof=payment,
        order_update=order,
        outcome=outcome,
        verifier_id=str(human["payment_verification"]["verifier_id"]),
        reconciler_id="fixture-reconciler",
        trace_id=context.trace_id,
    )


def fixture_fulfilment_transition(
    context: SplitPaymentContext,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build the exact fulfilment transition after both proofs are present."""

    fixture = context.fixture
    terms = dict(fixture["commercial_terms"])
    human = dict(fixture["human_inputs"])
    artifact = dict(fixture["fulfilment_document_payload"])
    fulfilment = {
        "schema_version": "1.0.0",
        "fulfilment_record_id": "fulfilment-fixture-split-001",
        "distinct_order_id": terms["distinct_order_id"],
        "event_type": human["fulfilment_attestation"]["decision"],
        "event_at": artifact["event_at"],
        "actor_id": human["fulfilment_attestation"]["actor_id"],
        "primary_document_ref": artifact["document_ref"],
        "evidence_sha256": value_sha256(artifact),
        "version": 1,
    }
    fulfilled_order = _with_digest(
        {
            **dict(context.order_v1),
            "state": "FULFILLED",
            "version": 4,
            "payload_sha256": "",
        }
    )
    terminal_proof = context.store.payment_proofs_for_order(terms["distinct_order_id"])[-1]
    outcome = _with_digest(
        {
            "schema_version": "1.1.0",
            "outcome_event_id": "outcome-fixture-split-fulfilled-001",
            "outcome_type": "FULFILLED",
            "demand_unit_id": context.order_v1["demand_unit_id"],
            "account_id": context.order_v1["account_id"],
            "motion": context.demand["motion"],
            "event_time": fulfilment["event_at"],
            "recorded_at": "2026-08-25T10:20:01Z",
            "source_system": "LOCAL_FULFILMENT_LEDGER",
            "authoritative_class": "FULFILMENT_LEDGER",
            "distinct_order_id": terms["distinct_order_id"],
            "payment_proof_ref": terminal_proof["payload"]["payment_proof_id"],
            "amount": terms["amount"],
            "cost": None,
            "contribution_margin": None,
            "currency": terms["currency"],
            "original_source_ref": "signal-fixture-existing-001",
            "latest_source_ref": fulfilment["fulfilment_record_id"],
            "influence_refs": [],
            "action_assignment_refs": [],
            "routing_ref": None,
            "reconciliation_state": "RECONCILED",
            "payload_sha256": "",
        }
    )
    return fulfilment, fulfilled_order, outcome


def record_fixture_fulfilment(
    context: SplitPaymentContext,
) -> tuple[AppendResult, AppendResult, AppendResult]:
    fixture = context.fixture
    human = dict(fixture["human_inputs"])
    artifact = dict(fixture["fulfilment_document_payload"])
    context.pipeline.ingest_fulfilment_document(
        artifact,
        source_content=canonical_json_bytes(artifact),
        writer_id=str(human["fulfilment_attestation"]["actor_id"]),
        trace_id=context.trace_id,
        recorded_at_utc=str(artifact["event_at"]),
    )
    fulfilment, fulfilled_order, outcome = fixture_fulfilment_transition(context)
    return context.pipeline.record_fulfilment_and_outcome(
        fulfilment=fulfilment,
        fulfilled_order=fulfilled_order,
        outcome=outcome,
        writer_id=str(human["fulfilment_attestation"]["actor_id"]),
        reconciler_id="fixture-reconciler",
        trace_id=context.trace_id,
    )


def run_split_payment_fixture_slice(
    database_path: str | Path,
    *,
    fixture_path: str | Path = DEFAULT_SPLIT_PAYMENT_FIXTURE,
    delivery_run_id: str = "split-payment-default",
) -> dict[str, Any]:
    """Run or exactly replay the complete local two-installment slice."""

    context = prepare_split_payment_fixture(
        database_path,
        fixture_path=fixture_path,
        delivery_run_id=delivery_run_id,
    )
    order_id = str(context.fixture["commercial_terms"]["distinct_order_id"])
    outcomes_before = len(
        [
            row
            for row in context.store.find_payload("OUTCOME_EVENT", "distinct_order_id", order_id)
            if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        ]
    )
    first = record_fixture_installment(context, 0)
    outcomes_after_first = len(
        [
            row
            for row in context.store.find_payload("OUTCOME_EVENT", "distinct_order_id", order_id)
            if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        ]
    )
    if first.payment.inserted and outcomes_after_first != 0:
        raise SplitPaymentFixtureError("first installment emitted terminal payment truth")
    if outcomes_after_first != outcomes_before:
        raise SplitPaymentFixtureError("first installment changed terminal outcome cardinality")
    second = record_fixture_installment(context, 1)
    fulfilment, fulfilled_order, fulfilment_outcome = record_fixture_fulfilment(context)
    reconciliation = context.pipeline.reconcile(
        reconciliation_id="reconciliation-fixture-split-001",
        distinct_order_id=order_id,
        demand_unit_id=str(context.order_v1["demand_unit_id"]),
        writer_id="fixture-reconciler",
        trace_id=context.trace_id,
        recorded_at_utc="2026-08-25T10:21:00Z",
    )

    proofs = context.store.payment_proofs_for_order(order_id)
    payment_outcomes = [
        row
        for row in context.store.find_payload("OUTCOME_EVENT", "distinct_order_id", order_id)
        if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
    ]
    fulfilment_outcomes = [
        row
        for row in context.store.find_payload("OUTCOME_EVENT", "distinct_order_id", order_id)
        if row["payload"].get("outcome_type") == "FULFILLED"
    ]
    due = _amount(context.fixture["commercial_terms"]["amount"], "commercial terms amount")
    settled = sum(
        (_amount(row["payload"]["amount"], "PaymentProof amount") for row in proofs),
        Decimal("0"),
    )
    if (
        len(proofs) != 2
        or settled != due
        or len(payment_outcomes) != 1
        or len(fulfilment_outcomes) != 1
        or payment_outcomes[0]["payload"].get("payment_proof_ref")
        != proofs[-1]["payload"].get("payment_proof_id")
        or fulfilment_outcomes[0]["payload"].get("payment_proof_ref")
        != proofs[-1]["payload"].get("payment_proof_id")
    ):
        raise SplitPaymentFixtureError("split-payment terminal proof set is not exact")

    integrity = context.store.verify_integrity()
    counts = Counter(row["record_type"] for row in context.store.records())
    return {
        "schema_version": "1.0.0",
        "fixture_id": context.fixture["fixture_id"],
        "classification": context.fixture["classification"],
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "canonical_kpi_eligible": False,
        "independent_verification": False,
        "external_effect_count": 0,
        "distinct_order_id": order_id,
        "payment_proof_refs": [row["payload"]["payment_proof_id"] for row in proofs],
        "payment_proof_entry_ids": [row["entry_id"] for row in proofs],
        "payment_proof_sequences": [row["sequence"] for row in proofs],
        "settled_amount": float(settled),
        "terminal_payment_outcome_entry_id": payment_outcomes[0]["entry_id"],
        "terminal_fulfilment_outcome_entry_id": fulfilment_outcomes[0]["entry_id"],
        "first_installment_dispositions": {
            "payment": first.payment.disposition,
            "order": first.order.disposition,
        },
        "second_installment_dispositions": {
            "payment": second.payment.disposition,
            "order": second.order.disposition,
            "outcome": second.outcome.disposition if second.outcome else None,
        },
        "fulfilment_entry_id": fulfilment.entry_id,
        "fulfilled_order_entry_id": fulfilled_order.entry_id,
        "fulfilment_outcome_entry_id": fulfilment_outcome.entry_id,
        "reconciliation_entry_id": reconciliation.ledger_entry_id,
        "record_type_counts": dict(sorted(counts.items())),
        "integrity": integrity,
    }


__all__ = [
    "DEFAULT_SPLIT_PAYMENT_FIXTURE",
    "SplitPaymentContext",
    "SplitPaymentFixtureError",
    "fixture_fulfilment_transition",
    "fixture_payment_transition",
    "ingest_fixture_installment",
    "load_split_payment_fixture",
    "prepare_split_payment_fixture",
    "record_fixture_fulfilment",
    "record_fixture_installment",
    "run_split_payment_fixture_slice",
]
