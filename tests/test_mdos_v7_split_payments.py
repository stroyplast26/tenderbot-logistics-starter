from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

import pytest

from lead_factory.mdos_v7.contracts import (
    canonical_json_bytes,
    record_digest_excluding,
    value_sha256,
)
from lead_factory.mdos_v7.fixture_slice import run_g1_fixture_slice
from lead_factory.mdos_v7.pipeline import DomainInvariantError, ReconciliationBlocked
from lead_factory.mdos_v7.split_payment_fixture import (
    DEFAULT_SPLIT_PAYMENT_FIXTURE,
    SplitPaymentFixtureError,
    fixture_fulfilment_transition,
    fixture_payment_transition,
    ingest_fixture_installment,
    load_split_payment_fixture,
    prepare_split_payment_fixture,
    record_fixture_fulfilment,
    record_fixture_installment,
    run_split_payment_fixture_slice,
)
from lead_factory.mdos_v7.store import (
    IdempotencyConflict,
    MdosStore,
    SchemaIntegrityError,
    UnknownWriterError,
)


ROOT = Path(__file__).resolve().parents[1]
ORDER_ID = "order-fixture-split-001"


def _with_digest(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["payload_sha256"] = record_digest_excluding(result, "payload_sha256")
    return result


def _cleared(store: MdosStore) -> list[dict[str, Any]]:
    return [
        row
        for row in store.find_payload("OUTCOME_EVENT", "distinct_order_id", ORDER_ID)
        if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
    ]


def _custom_intake(
    context: Any,
    artifact: Mapping[str, Any],
    *,
    recorded_at_utc: str,
) -> str:
    content = canonical_json_bytes(artifact)
    digest = value_sha256(artifact)
    result = context.pipeline.ingest_payment_observation(
        {**dict(artifact), "source_artifact_sha256": digest},
        source_content=content,
        writer_id="fixture-bank-adapter",
        reconciler_id="fixture-reconciler",
        trace_id=context.trace_id,
        recorded_at_utc=recorded_at_utc,
    )
    assert result.status == "READY_FOR_RECONCILIATION"
    return digest


def _payment_records(
    payment: Mapping[str, Any],
    order: Mapping[str, Any],
    outcome: Mapping[str, Any] | None,
    *,
    trace_id: str,
) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = [
        {
            "record_type": "PAYMENT_PROOF",
            "aggregate_id": payment["payment_proof_id"],
            "aggregate_version": 1,
            "idempotency_key": (
                f"payment-provider:{payment['provider']}:{payment['provider_event_id']}"
            ),
            "payload": dict(payment),
            "writer_id": "fixture-bank-verifier",
            "required_role": "PAYMENT_VERIFIER",
            "trace_id": trace_id,
            "recorded_at_utc": payment["verified_at"],
        },
        {
            "record_type": "ORDER_RECORD",
            "aggregate_id": order["distinct_order_id"],
            "aggregate_version": order["version"],
            "idempotency_key": f"order:{order['distinct_order_id']}:{order['version']}",
            "payload": dict(order),
            "writer_id": "fixture-bank-verifier",
            "required_role": "PAYMENT_VERIFIER",
            "trace_id": trace_id,
            "recorded_at_utc": payment["verified_at"],
        },
    ]
    if outcome is not None:
        records.append(
            {
                "record_type": "OUTCOME_EVENT",
                "aggregate_id": outcome["outcome_event_id"],
                "aggregate_version": 1,
                "idempotency_key": f"outcome:{outcome['outcome_event_id']}",
                "payload": dict(outcome),
                "writer_id": "fixture-reconciler",
                "required_role": "RECONCILER",
                "trace_id": trace_id,
                "recorded_at_utc": outcome["recorded_at"],
            }
        )
    return tuple(records)


def _fulfilment_records(
    fulfilment: Mapping[str, Any],
    order: Mapping[str, Any],
    outcome: Mapping[str, Any],
    *,
    trace_id: str,
) -> tuple[dict[str, Any], ...]:
    return (
        {
            "record_type": "FULFILMENT_RECORD",
            "aggregate_id": fulfilment["fulfilment_record_id"],
            "aggregate_version": fulfilment["version"],
            "idempotency_key": (
                f"fulfilment:{fulfilment['fulfilment_record_id']}:{fulfilment['version']}"
            ),
            "payload": dict(fulfilment),
            "writer_id": "fixture-fulfilment-writer",
            "required_role": "FULFILMENT_WRITER",
            "trace_id": trace_id,
            "recorded_at_utc": outcome["recorded_at"],
        },
        {
            "record_type": "ORDER_RECORD",
            "aggregate_id": order["distinct_order_id"],
            "aggregate_version": order["version"],
            "idempotency_key": f"order:{order['distinct_order_id']}:{order['version']}",
            "payload": dict(order),
            "writer_id": "fixture-fulfilment-writer",
            "required_role": "FULFILMENT_WRITER",
            "trace_id": trace_id,
            "recorded_at_utc": outcome["recorded_at"],
        },
        {
            "record_type": "OUTCOME_EVENT",
            "aggregate_id": outcome["outcome_event_id"],
            "aggregate_version": 1,
            "idempotency_key": f"outcome:{outcome['outcome_event_id']}",
            "payload": dict(outcome),
            "writer_id": "fixture-reconciler",
            "required_role": "RECONCILER",
            "trace_id": trace_id,
            "recorded_at_utc": outcome["recorded_at"],
        },
    )


@pytest.mark.parametrize(
    ("section", "field", "changed_value"),
    [
        ("order_approval", "distinct_order_id", "order-resealed-wrong"),
        ("order_approval", "amount", 125001.0),
        ("order_approval", "currency", "USD"),
        ("order_approval", "decision", "REJECTED"),
        ("payment_verification", "distinct_order_id", "order-resealed-wrong"),
        (
            "payment_verification",
            "provider_event_ids",
            ["bank-fixture-split-event-002", "bank-fixture-split-event-001"],
        ),
        ("payment_verification", "decision", "REJECTED"),
        ("fulfilment_attestation", "distinct_order_id", "order-resealed-wrong"),
        ("fulfilment_attestation", "document_ref", "upd-resealed-wrong"),
        ("fulfilment_attestation", "decision", "REJECTED"),
    ],
)
def test_resealed_human_input_must_still_match_exact_fixture_facts(
    tmp_path: Path,
    section: str,
    field: str,
    changed_value: Any,
) -> None:
    fixture = json.loads(DEFAULT_SPLIT_PAYMENT_FIXTURE.read_text(encoding="utf-8"))
    sealed = fixture["human_inputs"][section]
    sealed[field] = changed_value
    sealed["sealed_input_sha256"] = value_sha256(
        {key: item for key, item in sealed.items() if key != "sealed_input_sha256"}
    )
    changed_fixture = tmp_path / f"{section}-{field}.json"
    changed_fixture.write_text(json.dumps(fixture), encoding="utf-8")

    with pytest.raises(SplitPaymentFixtureError, match="sealed"):
        load_split_payment_fixture(changed_fixture)


def test_two_installments_have_one_terminal_truth_and_exact_reconciliation(
    tmp_path: Path,
) -> None:
    context = prepare_split_payment_fixture(tmp_path / "split.sqlite3", delivery_run_id="happy")
    first = record_fixture_installment(context, 0)
    assert first.settlement_state == "PAID_PARTIAL"
    assert first.outcome is None
    assert context.store.latest_record("ORDER_RECORD", ORDER_ID)["payload"]["state"] == (
        "PAID_PARTIAL"
    )
    assert len(context.store.payment_proofs_for_order(ORDER_ID)) == 1
    assert _cleared(context.store) == []

    second = record_fixture_installment(context, 1)
    assert second.settlement_state == "PAID"
    proofs = context.store.payment_proofs_for_order(ORDER_ID)
    assert [row["payload"]["amount"] for row in proofs] == [50000.0, 75000.0]
    assert [row["sequence"] for row in proofs] == sorted(row["sequence"] for row in proofs)
    assert len(_cleared(context.store)) == 1
    assert _cleared(context.store)[0]["payload"]["payment_proof_ref"] == (
        proofs[-1]["payload"]["payment_proof_id"]
    )
    assert _cleared(context.store)[0]["payload"]["amount"] == 125000.0

    record_fixture_fulfilment(context)
    reconciliation = context.pipeline.reconcile(
        reconciliation_id="reconciliation-split-happy",
        distinct_order_id=ORDER_ID,
        demand_unit_id=str(context.order_v1["demand_unit_id"]),
        writer_id="fixture-reconciler",
        trace_id=context.trace_id,
        recorded_at_utc="2026-08-25T10:21:30Z",
    )
    payload = context.store.latest_record(
        "RECONCILIATION_RESULT", reconciliation.reconciliation_id
    )["payload"]
    assert payload["payment_proof_refs"] == [
        "payment-proof-fixture-split-001",
        "payment-proof-fixture-split-002",
    ]
    assert payload["payment_proof_entry_id"] == proofs[-1]["entry_id"]
    assert context.store.verify_integrity()["counts"]["mdos_ledger"] > 0


def test_backdated_reconciliation_is_blocked_by_service_and_store_boundary(
    tmp_path: Path,
) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "backdated-service.sqlite3", delivery_run_id="backdated-service"
    )
    record_fixture_installment(context, 0)
    record_fixture_installment(context, 1)
    record_fixture_fulfilment(context)
    before = context.store.verify_integrity()
    with pytest.raises(ReconciliationBlocked, match="RECONCILIATION_BACKDATED"):
        context.pipeline.reconcile(
            reconciliation_id="reconciliation-split-backdated-service",
            distinct_order_id=ORDER_ID,
            demand_unit_id=str(context.order_v1["demand_unit_id"]),
            writer_id="fixture-reconciler",
            trace_id=context.trace_id,
            recorded_at_utc="2026-08-25T10:19:59Z",
        )
    assert context.store.latest_record(
        "RECONCILIATION_RESULT", "reconciliation-split-backdated-service"
    ) is None
    assert context.store.verify_integrity()["ledger_root_sha256"] == before[
        "ledger_root_sha256"
    ]
    assert "RECONCILIATION_BACKDATED" in context.store.conflicts()[-1]["details"][
        "reasons"
    ]

    direct = prepare_split_payment_fixture(
        tmp_path / "backdated-store.sqlite3", delivery_run_id="backdated-store"
    )
    record_fixture_installment(direct, 0)
    record_fixture_installment(direct, 1)
    record_fixture_fulfilment(direct)
    accepted = direct.pipeline.reconcile(
        reconciliation_id="reconciliation-split-causal-source",
        distinct_order_id=ORDER_ID,
        demand_unit_id=str(direct.order_v1["demand_unit_id"]),
        writer_id="fixture-reconciler",
        trace_id=direct.trace_id,
        recorded_at_utc="2026-08-25T10:21:00Z",
    )
    forged = dict(
        direct.store.latest_record("RECONCILIATION_RESULT", accepted.reconciliation_id)[
            "payload"
        ]
    )
    forged["record_id"] = "reconciliation-split-backdated-direct"
    forged["reconciled_at"] = "2026-08-25T10:19:59Z"
    direct_before = direct.store.verify_integrity()
    with pytest.raises(SchemaIntegrityError, match="time precedes bound terminal truth"):
        direct.pipeline.append_internal_record(
            record_type="RECONCILIATION_RESULT",
            record_id=str(forged["record_id"]),
            payload=forged,
            writer_id="fixture-reconciler",
            required_role="RECONCILER",
            trace_id=direct.trace_id,
            recorded_at_utc=str(forged["reconciled_at"]),
        )
    assert direct.store.latest_record(
        "RECONCILIATION_RESULT", str(forged["record_id"])
    ) is None
    assert direct.store.verify_integrity()["ledger_root_sha256"] == direct_before[
        "ledger_root_sha256"
    ]


def test_single_payment_reconciliation_keeps_legacy_shape_and_exactly_replays(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-single-payment.sqlite3"
    first = run_g1_fixture_slice(database, delivery_run_id="legacy-shape-first")
    store = MdosStore(database)
    reconciliation = store.latest_record(
        "RECONCILIATION_RESULT", "reconciliation-fixture-001"
    )
    assert reconciliation is not None
    assert "payment_proof_entry_ids" not in reconciliation["payload"]
    assert "payment_proof_refs" not in reconciliation["payload"]

    second = run_g1_fixture_slice(database, delivery_run_id="legacy-shape-replay")
    assert second["integrity"]["ledger_root_sha256"] == first["integrity"][
        "ledger_root_sha256"
    ]
    receipts = store.delivery_receipts(
        "reconciliation_result:reconciliation-fixture-001:1"
    )
    assert [receipt["disposition"] for receipt in receipts] == ["APPLIED", "REPLAY"]


def test_first_installment_exact_replay_after_terminal_payment_is_historical(
    tmp_path: Path,
) -> None:
    context = prepare_split_payment_fixture(tmp_path / "replay.sqlite3", delivery_run_id="replay")
    record_fixture_installment(context, 0)
    record_fixture_installment(context, 1)
    before = context.store.verify_integrity()
    replay = record_fixture_installment(context, 0)
    after = context.store.verify_integrity()
    assert replay.payment.disposition == replay.order.disposition == "REPLAY"
    assert replay.outcome is None
    assert after["ledger_root_sha256"] == before["ledger_root_sha256"]
    assert after["counts"]["mdos_ledger"] == before["counts"]["mdos_ledger"]
    assert len(_cleared(context.store)) == 1


def test_changed_provider_event_is_audited_without_partial_transition(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(tmp_path / "changed.sqlite3", delivery_run_id="changed")
    record_fixture_installment(context, 0)
    payment, order, _ = fixture_payment_transition(context, 0)
    payment = {
        **payment,
        "payment_proof_id": "payment-proof-fixture-split-changed",
        "amount": 49000.0,
    }
    before = context.store.verify_integrity()
    with pytest.raises(DomainInvariantError, match="duplicate payment blocked"):
        context.pipeline.record_payment_installment(
            payment_proof=payment,
            order_update=order,
            outcome=None,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.verify_integrity()["ledger_root_sha256"] == before["ledger_root_sha256"]
    assert context.store.conflicts()[-1]["conflict_type"] == "DUPLICATE_RECONCILED_PAYMENT"
    assert len(context.store.payment_proofs_for_order(ORDER_ID)) == 1


@pytest.mark.parametrize(
    "case",
    ["OVERPAY", "CURRENCY", "ACCOUNT", "ORDER", "SOURCE", "EVIDENCE"],
)
def test_invalid_installment_is_audited_and_never_partially_transitions(
    tmp_path: Path,
    case: str,
) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / f"{case.casefold()}.sqlite3", delivery_run_id=case.casefold()
    )
    index = 1 if case == "OVERPAY" else 0
    if index == 1:
        record_fixture_installment(context, 0)
    artifact = dict(context.fixture["signed_bank_statement_payloads"][index])
    if case == "OVERPAY":
        artifact["amount"] = 80000.0
    elif case == "CURRENCY":
        artifact["currency"] = "USD"
    elif case == "ACCOUNT":
        artifact["canonical_account_id"] = "acct-fixture-wrong"
    digest = _custom_intake(
        context,
        artifact,
        recorded_at_utc=(
            "2026-08-25T10:14:01Z" if index == 1 else "2026-08-25T10:12:01Z"
        ),
    )
    payment, order, outcome = fixture_payment_transition(context, index)
    if case in {"OVERPAY", "CURRENCY", "ACCOUNT"}:
        payment = {
            **payment,
            "amount": artifact["amount"],
            "currency": artifact["currency"],
            "canonical_account_id": artifact["canonical_account_id"],
            "source_artifact_sha256": digest,
        }
    elif case == "ORDER":
        order = _with_digest({**order, "distinct_order_id": "order-fixture-wrong"})
    elif case == "SOURCE":
        payment = {**payment, "provider": "fixture-other-source"}
    elif case == "EVIDENCE":
        payment = {**payment, "source_artifact_sha256": "f" * 64}

    proof_count = len(context.store.payment_proofs_for_order(ORDER_ID))
    order_count = len(context.store.find_payload("ORDER_RECORD", "distinct_order_id", ORDER_ID))
    conflict_count = len(context.store.conflicts())
    with pytest.raises(DomainInvariantError, match="payment transition blocked"):
        context.pipeline.record_payment_installment(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert len(context.store.payment_proofs_for_order(ORDER_ID)) == proof_count
    assert len(context.store.find_payload("ORDER_RECORD", "distinct_order_id", ORDER_ID)) == (
        order_count
    )
    assert len(_cleared(context.store)) == 0
    assert len(context.store.conflicts()) == conflict_count + 1
    context.store.verify_integrity()


@pytest.mark.parametrize("reuse", ["PAYMENT_PROOF_ID_REUSE", "ORDER_VERSION_REUSE"])
def test_reused_proof_id_and_order_version_have_immutable_audit(
    tmp_path: Path,
    reuse: str,
) -> None:
    context = prepare_split_payment_fixture(tmp_path / f"{reuse}.sqlite3", delivery_run_id=reuse)
    record_fixture_installment(context, 0)
    ingest_fixture_installment(context, 1)
    payment, order, outcome = fixture_payment_transition(context, 1)
    if reuse == "PAYMENT_PROOF_ID_REUSE":
        payment = {**payment, "payment_proof_id": "payment-proof-fixture-split-001"}
    else:
        order = dict(context.store.record_version("ORDER_RECORD", ORDER_ID, 2)["payload"])
    before = context.store.verify_integrity()
    with pytest.raises(DomainInvariantError):
        context.pipeline.record_payment_installment(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.conflicts()[-1]["conflict_type"] == reuse
    assert context.store.verify_integrity()["ledger_root_sha256"] == before["ledger_root_sha256"]


def test_payment_batch_fault_rolls_back_exactly(tmp_path: Path, monkeypatch: Any) -> None:
    context = prepare_split_payment_fixture(tmp_path / "crash.sqlite3", delivery_run_id="crash")
    ingest_fixture_installment(context, 0)
    payment, order, outcome = fixture_payment_transition(context, 0)
    before = context.store.verify_integrity()
    original = MdosStore._insert_delivery_tx

    def crash_on_order(
        self: MdosStore, connection: sqlite3.Connection, **kwargs: Any
    ) -> None:
        if kwargs.get("record_type") == "ORDER_RECORD" and kwargs.get("disposition") == "APPLIED":
            raise RuntimeError("injected split payment batch crash")
        original(self, connection, **kwargs)

    monkeypatch.setattr(MdosStore, "_insert_delivery_tx", crash_on_order)
    with pytest.raises(RuntimeError, match="injected split payment batch crash"):
        context.pipeline.record_payment_installment(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.payment_proofs_for_order(ORDER_ID) == []
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 2) is None
    assert _cleared(context.store) == []
    after = context.store.verify_integrity()
    assert after["ledger_root_sha256"] == before["ledger_root_sha256"]
    assert after["counts"] == before["counts"]


def test_direct_guarded_writes_and_unknown_writer_cannot_mint_payment_truth(
    tmp_path: Path,
) -> None:
    context = prepare_split_payment_fixture(tmp_path / "bypass.sqlite3", delivery_run_id="bypass")
    ingest_fixture_installment(context, 0)
    payment, order, outcome = fixture_payment_transition(context, 0)
    kwargs = _payment_records(payment, order, outcome, trace_id=context.trace_id)[0]
    with pytest.raises(SchemaIntegrityError, match="typed atomic payment transition"):
        context.store._append_domain_record(**kwargs)
    with pytest.raises(SchemaIntegrityError, match="typed atomic payment transition"):
        context.store._append_domain_batch(
            _payment_records(payment, order, outcome, trace_id=context.trace_id)
        )
    private_batch = getattr(context.store, "_MdosStore__append_domain_batch")
    with pytest.raises(SchemaIntegrityError, match="typed atomic payment transition"):
        private_batch(
            _payment_records(payment, order, outcome, trace_id=context.trace_id),
            _payment_capability=object(),
        )
    with pytest.raises(UnknownWriterError, match="unknown writer"):
        context.store.commit_payment_transition(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="caller-minted-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.payment_proofs_for_order(ORDER_ID) == []
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 2) is None


def test_typed_commit_binds_verifier_and_preserves_original_order_approver(
    tmp_path: Path,
) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "semantic-actors.sqlite3",
        delivery_run_id="semantic-actors",
    )
    ingest_fixture_installment(context, 0)
    payment, order, outcome = fixture_payment_transition(context, 0)
    before = context.store.verify_integrity()

    forged_initial_order = _with_digest(
        {
            **dict(context.order_v1),
            "distinct_order_id": "order-fixture-forged-approver",
            "approved_by": "unregistered-other-person",
            "payload_sha256": "",
        }
    )
    with pytest.raises(SchemaIntegrityError, match="initial ORDER_RECORD approver"):
        context.store._append_domain_record(
            record_type="ORDER_RECORD",
            aggregate_id=forged_initial_order["distinct_order_id"],
            aggregate_version=1,
            idempotency_key="order:order-fixture-forged-approver:1",
            payload=forged_initial_order,
            writer_id="fixture-order-approver",
            required_role="ORDER_APPROVER",
            trace_id=context.trace_id,
            recorded_at_utc="2026-08-25T10:11:30Z",
        )
    assert context.store.latest_record(
        "ORDER_RECORD", "order-fixture-forged-approver"
    ) is None
    after_initial_denial = context.store.verify_integrity()
    assert after_initial_denial["ledger_root_sha256"] == before["ledger_root_sha256"]
    assert after_initial_denial["counts"]["mdos_ledger"] == before["counts"]["mdos_ledger"]
    before = after_initial_denial

    forged_payment = {**payment, "verified_by": "unregistered-other-person"}
    with pytest.raises(SchemaIntegrityError, match="PAYMENT_PROOF semantic actor"):
        context.store.commit_payment_transition(
            payment_proof=forged_payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.payment_proofs_for_order(ORDER_ID) == []
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 2) is None
    assert context.store.verify_integrity() == before

    forged_order = _with_digest(
        {**order, "approved_by": "unregistered-other-person"}
    )
    with pytest.raises(SchemaIntegrityError, match="immutable revision binding"):
        context.store.commit_payment_transition(
            payment_proof=payment,
            order_update=forged_order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.payment_proofs_for_order(ORDER_ID) == []
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 2) is None
    assert context.store.verify_integrity() == before

    recovered = record_fixture_installment(context, 0)
    assert recovered.payment.disposition == recovered.order.disposition == "APPLIED"
    context.store.verify_integrity()


def test_typed_commit_rejects_cross_order_batch_before_any_write(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "cross-order.sqlite3",
        delivery_run_id="cross-order",
    )
    ingest_fixture_installment(context, 0)
    payment, order, outcome = fixture_payment_transition(context, 0)
    cross_order = _with_digest(
        {**order, "distinct_order_id": "order-fixture-001"}
    )
    before = context.store.verify_integrity()
    with pytest.raises(SchemaIntegrityError, match="same order"):
        context.store.commit_payment_transition(
            payment_proof=payment,
            order_update=cross_order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.payment_proofs_for_order(ORDER_ID) == []
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 2) is None
    assert context.store.verify_integrity() == before


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("motion", "FORGED_MOTION"),
        ("original_source_ref", "signal-forged"),
        ("latest_source_ref", "provider-event-forged"),
    ],
)
def test_terminal_outcome_motion_and_provenance_are_store_bound(
    tmp_path: Path,
    field: str,
    forged_value: str,
) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / f"terminal-{field}.sqlite3",
        delivery_run_id=f"terminal-{field}",
    )
    record_fixture_installment(context, 0)
    ingest_fixture_installment(context, 1)
    payment, order, outcome = fixture_payment_transition(context, 1)
    assert outcome is not None
    forged_outcome = _with_digest({**outcome, field: forged_value})
    before = context.store.verify_integrity()
    with pytest.raises(SchemaIntegrityError, match="terminal outcome|truth binding"):
        context.store.commit_payment_transition(
            payment_proof=payment,
            order_update=order,
            outcome=forged_outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert len(context.store.payment_proofs_for_order(ORDER_ID)) == 1
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 3) is None
    assert context.store.verify_integrity() == before

    if field == "motion":
        with pytest.raises(
            DomainInvariantError,
            match="TERMINAL_OUTCOME_TRUTH_BINDING_MISMATCH",
        ):
            context.pipeline.record_payment_installment(
                payment_proof=payment,
                order_update=order,
                outcome=forged_outcome,
                verifier_id="fixture-bank-verifier",
                reconciler_id="fixture-reconciler",
                trace_id=context.trace_id,
            )
        assert context.store.conflicts()[-1]["details"]["reason"] == (
            "TERMINAL_OUTCOME_TRUTH_BINDING_MISMATCH"
        )
        assert len(context.store.payment_proofs_for_order(ORDER_ID)) == 1


def test_fulfilment_actor_is_bound_at_store_boundary(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "fulfilment-actor.sqlite3",
        delivery_run_id="fulfilment-actor",
    )
    record_fixture_installment(context, 0)
    record_fixture_installment(context, 1)
    artifact = dict(context.fixture["fulfilment_document_payload"])
    context.pipeline.ingest_fulfilment_document(
        artifact,
        source_content=canonical_json_bytes(artifact),
        writer_id="fixture-fulfilment-writer",
        trace_id=context.trace_id,
        recorded_at_utc=str(artifact["event_at"]),
    )
    fulfilment, order, outcome = fixture_fulfilment_transition(context)
    forged_fulfilment = {**fulfilment, "actor_id": "unregistered-other-person"}
    before = context.store.verify_integrity()
    with pytest.raises(SchemaIntegrityError, match="FULFILMENT_RECORD semantic actor"):
        context.store._append_domain_batch(
            _fulfilment_records(
                forged_fulfilment,
                order,
                outcome,
                trace_id=context.trace_id,
            )
        )
    assert not any(
        row["payload"].get("distinct_order_id") == ORDER_ID
        for row in context.store.records("FULFILMENT_RECORD")
    )
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 4) is None
    assert context.store.verify_integrity() == before


def test_raw_fulfilment_evidence_is_store_bound_immutable_v1(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "raw-fulfilment.sqlite3",
        delivery_run_id="raw-fulfilment",
    )
    record_fixture_installment(context, 0)
    record_fixture_installment(context, 1)
    artifact = dict(context.fixture["fulfilment_document_payload"])
    arbitrary_evidence = context.store.append_evidence(
        content=b'{"arbitrary":true}',
        media_type="application/json",
        source_ref=str(artifact["document_ref"]),
        synthetic=True,
        writer_id="fixture-fulfilment-writer",
        required_role="FULFILMENT_WRITER",
        trace_id=context.trace_id,
        recorded_at_utc=str(artifact["event_at"]),
    )
    forged_raw = {
        "schema_version": "1.0.0",
        "record_id": artifact["document_ref"],
        "synthetic": True,
        "canonical_kpi_eligible": False,
        **artifact,
        "evidence_sha256": arbitrary_evidence.content_sha256,
    }
    with pytest.raises(SchemaIntegrityError, match="immutable signed fixture evidence"):
        context.store._append_domain_record(
            record_type="RAW_FULFILMENT_DOCUMENT",
            aggregate_id=artifact["document_ref"],
            aggregate_version=1,
            idempotency_key=f"raw_fulfilment_document:{artifact['document_ref']}:1",
            payload=forged_raw,
            writer_id="fixture-fulfilment-writer",
            required_role="FULFILMENT_WRITER",
            trace_id=context.trace_id,
            recorded_at_utc=str(artifact["event_at"]),
        )
    assert context.store.latest_record(
        "RAW_FULFILMENT_DOCUMENT", str(artifact["document_ref"])
    ) is None

    context.pipeline.ingest_fulfilment_document(
        artifact,
        source_content=canonical_json_bytes(artifact),
        writer_id="fixture-fulfilment-writer",
        trace_id=context.trace_id,
        recorded_at_utc=str(artifact["event_at"]),
    )
    changed_artifact = {**artifact, "event_at": "2026-08-25T10:20:30Z"}
    changed_evidence = context.store.append_evidence(
        content=canonical_json_bytes(changed_artifact),
        media_type="application/json",
        source_ref=str(artifact["document_ref"]),
        synthetic=True,
        writer_id="fixture-fulfilment-writer",
        required_role="FULFILMENT_WRITER",
        trace_id=context.trace_id,
        recorded_at_utc="2026-08-25T10:20:30Z",
    )
    changed_raw = {
        **forged_raw,
        **changed_artifact,
        "evidence_sha256": changed_evidence.content_sha256,
    }
    with pytest.raises(SchemaIntegrityError, match="immutable signed fixture evidence"):
        context.store._append_domain_record(
            record_type="RAW_FULFILMENT_DOCUMENT",
            aggregate_id=artifact["document_ref"],
            aggregate_version=2,
            idempotency_key=f"raw_fulfilment_document:{artifact['document_ref']}:2",
            payload=changed_raw,
            writer_id="fixture-fulfilment-writer",
            required_role="FULFILMENT_WRITER",
            trace_id=context.trace_id,
            recorded_at_utc="2026-08-25T10:20:30Z",
        )
    assert context.store.latest_record(
        "RAW_FULFILMENT_DOCUMENT", str(artifact["document_ref"])
    )["aggregate_version"] == 1
    context.store.verify_integrity()


def test_old_proof_cannot_apply_phantom_revision_and_mixed_batch_rolls_back(
    tmp_path: Path,
) -> None:
    context = prepare_split_payment_fixture(tmp_path / "mixed.sqlite3", delivery_run_id="mixed")
    record_fixture_installment(context, 0)
    payment = dict(context.store.payment_proofs_for_order(ORDER_ID)[0]["payload"])
    phantom_order = _with_digest(
        {
            **dict(context.order_v1),
            "state": "PAID_PARTIAL",
            "version": 3,
            "payload_sha256": "",
        }
    )
    before = context.store.verify_integrity()
    with pytest.raises(IdempotencyConflict, match="mix replay and applied"):
        context.store.commit_payment_transition(
            payment_proof=payment,
            order_update=phantom_order,
            outcome=None,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id="trace:old-proof-phantom-revision",
        )
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 3) is None
    assert context.store.verify_integrity()["ledger_root_sha256"] == before["ledger_root_sha256"]


def test_terminal_outcome_cannot_reference_first_installment(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(tmp_path / "terminal.sqlite3", delivery_run_id="terminal")
    record_fixture_installment(context, 0)
    ingest_fixture_installment(context, 1)
    payment, order, outcome = fixture_payment_transition(context, 1)
    assert outcome is not None
    outcome = _with_digest(
        {**outcome, "payment_proof_ref": "payment-proof-fixture-split-001"}
    )
    before = context.store.verify_integrity()
    with pytest.raises(SchemaIntegrityError, match="current payment proof"):
        context.store.commit_payment_transition(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert len(context.store.payment_proofs_for_order(ORDER_ID)) == 1
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 3) is None
    assert context.store.verify_integrity()["ledger_root_sha256"] == before["ledger_root_sha256"]


def test_commercial_terms_are_immutable_v1_and_cannot_expand_settlement(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "terms.sqlite3",
        delivery_run_id="terms-v1",
    )
    record_fixture_installment(context, 0)
    terms_id = str(context.order_v1["commercial_terms_ref"])
    terms_v1 = dict(context.store.record_version("COMMERCIAL_TERMS", terms_id, 1)["payload"])
    terms_v2 = {**terms_v1, "amount": 130000.0, "captured_at": "2026-08-25T10:13:30Z"}
    with pytest.raises(SchemaIntegrityError, match="immutable v1"):
        context.pipeline.append_internal_record(
            record_type="COMMERCIAL_TERMS",
            record_id=terms_id,
            payload=terms_v2,
            writer_id="fixture-order-approver",
            required_role="ORDER_APPROVER",
            trace_id=context.trace_id,
            recorded_at_utc="2026-08-25T10:13:30Z",
            version=2,
        )
    assert context.store.record_version("COMMERCIAL_TERMS", terms_id, 2) is None

    artifact = dict(context.fixture["signed_bank_statement_payloads"][1])
    artifact["amount"] = 80000.0
    digest = _custom_intake(
        context,
        artifact,
        recorded_at_utc="2026-08-25T10:14:01Z",
    )
    payment, order, outcome = fixture_payment_transition(context, 1)
    payment = {**payment, "amount": 80000.0, "source_artifact_sha256": digest}
    with pytest.raises(DomainInvariantError, match="OVERPAYMENT"):
        context.pipeline.record_payment_installment(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert len(context.store.payment_proofs_for_order(ORDER_ID)) == 1
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 3) is None
    context.store.verify_integrity()

    injected = prepare_split_payment_fixture(
        tmp_path / "terms-injected.sqlite3",
        delivery_run_id="terms-injected",
    )
    injected_terms_id = str(injected.order_v1["commercial_terms_ref"])
    injected_v1 = dict(
        injected.store.record_version("COMMERCIAL_TERMS", injected_terms_id, 1)["payload"]
    )
    original_validator = MdosStore._validate_domain_dependencies_tx

    def bypass_terms_v2(self: MdosStore, connection: sqlite3.Connection, **kwargs: Any) -> None:
        if kwargs.get("record_type") == "COMMERCIAL_TERMS" and kwargs.get(
            "aggregate_version"
        ) == 2:
            return
        original_validator(self, connection, **kwargs)

    monkeypatch.setattr(MdosStore, "_validate_domain_dependencies_tx", bypass_terms_v2)
    injected.pipeline.append_internal_record(
        record_type="COMMERCIAL_TERMS",
        record_id=injected_terms_id,
        payload={**injected_v1, "amount": 130000.0},
        writer_id="fixture-order-approver",
        required_role="ORDER_APPROVER",
        trace_id=injected.trace_id,
        recorded_at_utc="2026-08-25T10:13:30Z",
        version=2,
    )
    monkeypatch.setattr(MdosStore, "_validate_domain_dependencies_tx", original_validator)
    with pytest.raises(SchemaIntegrityError, match="immutable v1"):
        injected.store.verify_integrity()


def test_raw_payment_evidence_is_store_bound_immutable_v1(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "raw-payment.sqlite3",
        delivery_run_id="raw-payment",
    )
    artifact = dict(context.fixture["signed_bank_statement_payloads"][0])
    arbitrary = b'{"arbitrary":true}'
    arbitrary_evidence = context.store.append_evidence(
        content=arbitrary,
        media_type="application/json",
        source_ref=str(artifact["provider"]),
        synthetic=True,
        writer_id="fixture-bank-adapter",
        required_role="BANK_ADAPTER",
        trace_id=context.trace_id,
        recorded_at_utc="2026-08-25T10:12:01Z",
    )
    raw_id = f"{artifact['provider']}:{artifact['provider_event_id']}"
    forged_raw = {
        "schema_version": "1.0.0",
        "record_id": raw_id,
        "synthetic": True,
        "canonical_kpi_eligible": False,
        **artifact,
        "source_artifact_sha256": arbitrary_evidence.content_sha256,
        "authoritative_class": "SIGNED_BANK_STATEMENT",
    }
    with pytest.raises(SchemaIntegrityError, match="immutable signed fixture evidence"):
        context.store._append_domain_record(
            record_type="RAW_PAYMENT_OBSERVATION",
            aggregate_id=raw_id,
            aggregate_version=1,
            idempotency_key=f"raw_payment_observation:{raw_id}:1",
            payload=forged_raw,
            writer_id="fixture-bank-adapter",
            required_role="BANK_ADAPTER",
            trace_id=context.trace_id,
            recorded_at_utc="2026-08-25T10:12:01Z",
        )
    assert context.store.latest_record("RAW_PAYMENT_OBSERVATION", raw_id) is None

    ingest_fixture_installment(context, 0)
    changed_artifact = {**artifact, "amount": 60000.0}
    changed_evidence = context.store.append_evidence(
        content=canonical_json_bytes(changed_artifact),
        media_type="application/json",
        source_ref=str(artifact["provider"]),
        synthetic=True,
        writer_id="fixture-bank-adapter",
        required_role="BANK_ADAPTER",
        trace_id=context.trace_id,
        recorded_at_utc="2026-08-25T10:12:02Z",
    )
    changed_raw = {
        **forged_raw,
        **changed_artifact,
        "source_artifact_sha256": changed_evidence.content_sha256,
    }
    with pytest.raises(SchemaIntegrityError, match="immutable signed fixture evidence"):
        context.store._append_domain_record(
            record_type="RAW_PAYMENT_OBSERVATION",
            aggregate_id=raw_id,
            aggregate_version=2,
            idempotency_key=f"raw_payment_observation:{raw_id}:2",
            payload=changed_raw,
            writer_id="fixture-bank-adapter",
            required_role="BANK_ADAPTER",
            trace_id=context.trace_id,
            recorded_at_utc="2026-08-25T10:12:02Z",
        )
    assert context.store.latest_record("RAW_PAYMENT_OBSERVATION", raw_id)[
        "aggregate_version"
    ] == 1
    context.store.verify_integrity()


def test_payment_event_cannot_postdate_its_raw_evidence(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "future-event.sqlite3",
        delivery_run_id="future-event",
    )
    artifact = dict(context.fixture["signed_bank_statement_payloads"][0])
    artifact["value_at"] = "2026-08-25T10:20:00Z"
    digest = _custom_intake(
        context,
        artifact,
        recorded_at_utc="2026-08-25T10:12:01Z",
    )
    payment, order, outcome = fixture_payment_transition(context, 0)
    payment = {
        **payment,
        "value_at": artifact["value_at"],
        "verified_at": "2026-08-25T10:21:00Z",
        "source_artifact_sha256": digest,
    }
    with pytest.raises(DomainInvariantError, match="PAYMENT_EVIDENCE_CHRONOLOGY_INVALID"):
        context.pipeline.record_payment_installment(
            payment_proof=payment,
            order_update=order,
            outcome=outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.payment_proofs_for_order(ORDER_ID) == []
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 2) is None
    context.store.verify_integrity()


def test_as_of_dependencies_reject_later_raw_and_future_dated_evidence(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(tmp_path / "as-of.sqlite3", delivery_run_id="as-of")
    ingest_fixture_installment(context, 0)
    payment, order, _ = fixture_payment_transition(context, 0)
    raw = context.store.latest_record(
        "RAW_PAYMENT_OBSERVATION",
        f"{payment['provider']}:{payment['provider_event_id']}",
    )
    assert raw is not None
    with context.store.transaction() as connection:
        with pytest.raises(SchemaIntegrityError, match="order/raw/evidence binding"):
            context.store._validate_domain_dependencies_tx(
                connection,
                record_type="PAYMENT_PROOF",
                aggregate_version=1,
                payload=payment,
                writer_id="fixture-bank-verifier",
                as_of_sequence=int(raw["sequence"]),
                payment_transition=True,
            )

    future = prepare_split_payment_fixture(
        tmp_path / "future.sqlite3", delivery_run_id="future-evidence"
    )
    artifact = dict(future.fixture["signed_bank_statement_payloads"][0])
    _custom_intake(future, artifact, recorded_at_utc="2026-08-25T10:30:00Z")
    future_payment, future_order, _ = fixture_payment_transition(future, 0)
    with pytest.raises(DomainInvariantError, match="PAYMENT_EVIDENCE_CHRONOLOGY_INVALID"):
        future.pipeline.record_payment_installment(
            payment_proof=future_payment,
            order_update=future_order,
            outcome=None,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id=future.trace_id,
        )
    assert future.store.payment_proofs_for_order(ORDER_ID) == []
    assert future.store.conflicts()[-1]["details"]["reason"] == (
        "PAYMENT_EVIDENCE_CHRONOLOGY_INVALID"
    )


def test_fulfilment_rejects_future_dated_signed_evidence(tmp_path: Path) -> None:
    context = prepare_split_payment_fixture(
        tmp_path / "fulfilment-as-of.sqlite3", delivery_run_id="fulfilment-as-of"
    )
    record_fixture_installment(context, 0)
    record_fixture_installment(context, 1)
    artifact = dict(context.fixture["fulfilment_document_payload"])
    context.pipeline.ingest_fulfilment_document(
        artifact,
        source_content=canonical_json_bytes(artifact),
        writer_id="fixture-fulfilment-writer",
        trace_id=context.trace_id,
        recorded_at_utc="2026-08-25T10:30:00Z",
    )
    fulfilment, order, outcome = fixture_fulfilment_transition(context)
    with pytest.raises(DomainInvariantError, match="claimed event time"):
        context.pipeline.record_fulfilment_and_outcome(
            fulfilment=fulfilment,
            fulfilled_order=order,
            outcome=outcome,
            writer_id="fixture-fulfilment-writer",
            reconciler_id="fixture-reconciler",
            trace_id=context.trace_id,
        )
    assert context.store.records("FULFILMENT_RECORD")[-1]["payload"].get(
        "distinct_order_id"
    ) != ORDER_ID
    assert context.store.record_version("ORDER_RECORD", ORDER_ID, 4) is None


def test_full_slice_replay_backup_restore_and_runner_evidence(tmp_path: Path) -> None:
    database = tmp_path / "full.sqlite3"
    first = run_split_payment_fixture_slice(database, delivery_run_id="full-1")
    second = run_split_payment_fixture_slice(database, delivery_run_id="full-2")
    assert first["integrity"]["ledger_root_sha256"] == second["integrity"][
        "ledger_root_sha256"
    ]
    assert first["record_type_counts"] == second["record_type_counts"]
    store = MdosStore(database)
    backup, _ = store.create_backup(
        tmp_path / "backups" / "split.sqlite3",
        created_at_utc="2026-08-25T10:40:00Z",
    )
    restored = MdosStore.restore_verified(backup, tmp_path / "restore" / "split.sqlite3")
    assert restored.verify_integrity() == store.verify_integrity()

    runner_database = tmp_path / "runner" / "split.sqlite3"
    report = tmp_path / "runner" / "evidence.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_mdos_v7_split_payment_shadow.py"),
            "--database",
            str(runner_database),
            "--fixture",
            str(DEFAULT_SPLIT_PAYMENT_FIXTURE),
            "--report",
            str(report),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    evidence = json.loads(report.read_text(encoding="utf-8"))
    assert evidence["status"] == "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
    assert evidence["authority"]["canonical_kpi_eligible"] is False
    assert evidence["authority"]["external_reads_enabled"] is False
    assert evidence["assertions"]["exact_replay_stable"] is True
    assert evidence["assertions"]["backup_restore_verified"] is True
