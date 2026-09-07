from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from lead_factory.mdos_v7.contracts import (
    ContractRegistry,
    ContractValidationError,
    canonical_json_bytes,
    record_digest_excluding,
    value_sha256,
)
from lead_factory.mdos_v7.fixture_slice import load_fixture, run_g1_fixture_slice
from lead_factory.mdos_v7.pipeline import (
    DomainInvariantError,
    G1Pipeline,
    ReconciliationBlocked,
)
from lead_factory.mdos_v7.policy import PermitRequest, PermitService
from lead_factory.mdos_v7.store import (
    MdosStore,
    SchemaIntegrityError,
    WriterRoleError,
)


def _runtime(database: Path) -> tuple[MdosStore, PermitService, G1Pipeline]:
    fixture = load_fixture()
    store = MdosStore(database, actor_registry=fixture["actors"])
    contracts = ContractRegistry()
    permits = PermitService(store, contracts)
    return store, permits, G1Pipeline(store, contracts, permits)


def test_unknown_source_and_wrong_scope_permit_are_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "scope.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id="scope-base")
    store, permits, pipeline = _runtime(database)
    signal = dict(store.records("SIGNAL_OBSERVATION")[0]["payload"])
    signal.update(
        {
            "event_id": "signal-unregistered-source",
            "idempotency_key": "fixture:signal:unregistered",
            "source_id": "fixture:UNREGISTERED_SOURCE",
        }
    )
    raw = canonical_json_bytes(load_fixture()["raw_trigger_payload"])
    before_signals = len(store.records("SIGNAL_OBSERVATION"))
    with pytest.raises(DomainInvariantError, match="fixed fixture source passport"):
        pipeline.capture_signal(
            signal,
            raw_content=raw,
            writer_id="fixture-source-adapter",
            delivery_trace_id="trace:unregistered-source",
        )
    assert len(store.records("SIGNAL_OBSERVATION")) == before_signals

    demand = store.record_version("DEMAND_UNIT", "du-fixture-existing-001", 2)["payload"]
    wrong = permits.decide(
        PermitRequest(
            permit_decision_id="permit-wrong-scope-fixture",
            purpose="G1_ACCEPTED_WORK_SHADOW_PROJECTION",
            action_type="CREATE_CRM_TASK",
            channel="BITRIX24_SHADOW",
            scope={
                "beachhead_profile_ref": None,
                "region": "WRONG REGION",
                "product_scope": ["WRONG_PRODUCT"],
            },
            subject_refs=(demand["demand_unit_id"],),
            legal_basis_ref="FIXTURE_ONLY_NO_EXTERNAL_EFFECT",
            source_passport_ref="fixture:known-account-history",
            issued_at="2026-08-25T09:30:00Z",
            expires_at="2026-08-25T10:30:00Z",
            policy_version="unknown-policy",
            capacity_snapshot_ref=demand["capacity_snapshot_ref"],
            max_cost=0,
            currency="USD",
            evidence_refs=("missing-evidence",),
            mode="SHADOW",
        ),
        issued_by="fixture-policy-authority",
        trace_id="trace:wrong-scope",
    )
    assert wrong["decision"] == "DENY"
    assert len(store.records("ACTION_ASSIGNMENT")) == 1


def test_unsigned_and_duplicate_payment_never_create_canonical_truth(tmp_path: Path) -> None:
    database = tmp_path / "payment.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id="payment-base")
    store, _, pipeline = _runtime(database)
    payment_count = len(store.records("PAYMENT_PROOF"))
    outcome_count = len(
        [
            row
            for row in store.records("OUTCOME_EVENT")
            if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        ]
    )
    unsigned = {
        **load_fixture()["signed_bank_statement_payload"],
        "signed": False,
        "provider_event_id": "unsigned-event-fixture",
    }
    with pytest.raises(DomainInvariantError, match="signed fixture bank"):
        pipeline.ingest_payment_observation(
            {**unsigned, "source_artifact_sha256": value_sha256(unsigned)},
            source_content=canonical_json_bytes(unsigned),
            writer_id="fixture-bank-adapter",
            reconciler_id="fixture-reconciler",
            trace_id="trace:unsigned-bank",
            recorded_at_utc="2026-08-25T09:40:00Z",
        )
    assert len(store.records("PAYMENT_PROOF")) == payment_count

    duplicate_artifact = {
        **load_fixture()["signed_bank_statement_payload"],
        "provider_event_id": "duplicate-payment-event-fixture",
        "value_at": "2026-08-25T09:41:00Z",
    }
    duplicate_sha = value_sha256(duplicate_artifact)
    intake = pipeline.ingest_payment_observation(
        {**duplicate_artifact, "source_artifact_sha256": duplicate_sha},
        source_content=canonical_json_bytes(duplicate_artifact),
        writer_id="fixture-bank-adapter",
        reconciler_id="fixture-reconciler",
        trace_id="trace:duplicate-bank",
        recorded_at_utc="2026-08-25T09:41:01Z",
    )
    assert intake.status == "READY_FOR_RECONCILIATION"
    original_payment = dict(store.records("PAYMENT_PROOF")[0]["payload"])
    duplicate_payment = {
        **original_payment,
        "payment_proof_id": "payment-proof-duplicate-fixture",
        "provider_event_id": duplicate_artifact["provider_event_id"],
        "value_at": duplicate_artifact["value_at"],
        "source_artifact_sha256": duplicate_sha,
        "verified_at": "2026-08-25T09:42:00Z",
    }
    paid_order = dict(store.record_version("ORDER_RECORD", "order-fixture-001", 2)["payload"])
    original_outcome = next(
        row["payload"]
        for row in store.records("OUTCOME_EVENT")
        if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
    )
    duplicate_outcome: dict[str, Any] = {
        **original_outcome,
        "outcome_event_id": "outcome-duplicate-payment-fixture",
        "event_time": duplicate_artifact["value_at"],
        "recorded_at": "2026-08-25T09:42:01Z",
        "payment_proof_ref": duplicate_payment["payment_proof_id"],
        "latest_source_ref": duplicate_artifact["provider_event_id"],
        "payload_sha256": "",
    }
    duplicate_outcome["payload_sha256"] = record_digest_excluding(
        duplicate_outcome, "payload_sha256"
    )
    with pytest.raises(DomainInvariantError, match="duplicate payment blocked"):
        pipeline.record_payment_and_outcome(
            payment_proof=duplicate_payment,
            paid_order=paid_order,
            outcome=duplicate_outcome,
            verifier_id="fixture-bank-verifier",
            reconciler_id="fixture-reconciler",
            trace_id="trace:duplicate-payment",
        )
    assert len(store.records("PAYMENT_PROOF")) == payment_count
    assert (
        len(
            [
                row
                for row in store.records("OUTCOME_EVENT")
                if row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
            ]
        )
        == outcome_count
    )


def test_unresolved_conflict_blocks_until_independent_human_resolution(
    tmp_path: Path,
) -> None:
    database = tmp_path / "conflict.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id="conflict-base")
    store, _, pipeline = _runtime(database)
    conflict_id = store.record_conflict(
        conflict_type="DUPLICATE_RECONCILED_PAYMENT",
        business_key="order-fixture-001",
        existing_sha256="1" * 64,
        proposed_sha256="2" * 64,
        details={"distinct_order_id": "order-fixture-001"},
        blocked_action="EMIT_COMMERCIAL_KPI",
        writer_id="fixture-reconciler",
        trace_id="trace:unresolved-conflict",
        recorded_at_utc="2026-08-25T09:50:00Z",
    )
    with pytest.raises(ReconciliationBlocked, match="unresolved conflicts"):
        pipeline.reconcile(
            reconciliation_id="reconciliation-blocked-fixture",
            distinct_order_id="order-fixture-001",
            demand_unit_id="du-fixture-existing-001",
            writer_id="fixture-reconciler",
            trace_id="trace:blocked-reconciliation",
            recorded_at_utc="2026-08-25T09:51:00Z",
        )

    resolution: dict[str, Any] = {
        "schema_version": "1.0.0",
        "record_id": "conflict-resolution-fixture-001",
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "conflict_id": conflict_id,
        "decision": "RESOLVED",
        "justification": "Independent synthetic fixture arbitration",
        "arbitrator_id": "fixture-conflict-arbitrator",
        "reviewed_at": "2026-08-25T09:52:00Z",
        "attestation_sha256": "",
    }
    resolution["attestation_sha256"] = record_digest_excluding(
        resolution, "attestation_sha256"
    )
    pipeline.record_conflict_resolution(
        resolution,
        arbitrator_id="fixture-conflict-arbitrator",
        trace_id="trace:conflict-resolution",
    )
    reconciled = pipeline.reconcile(
        reconciliation_id="reconciliation-after-arbitration-fixture",
        distinct_order_id="order-fixture-001",
        demand_unit_id="du-fixture-existing-001",
        writer_id="fixture-reconciler",
        trace_id="trace:reconciled-after-resolution",
        recorded_at_utc="2026-08-25T09:53:00Z",
    )
    assert reconciled.status == "RECONCILED_FIXTURE_NON_KPI"
    assert any(row["conflict_id"] == conflict_id for row in store.conflicts())


def test_payment_batch_rolls_back_and_full_replay_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "atomic.sqlite3"
    original = MdosStore._insert_delivery_tx

    def fail_on_payment(
        self: MdosStore, connection: sqlite3.Connection, **kwargs: Any
    ) -> None:
        if kwargs.get("record_type") == "PAYMENT_PROOF" and kwargs.get(
            "disposition"
        ) == "APPLIED":
            raise RuntimeError("injected payment batch crash")
        original(self, connection, **kwargs)

    monkeypatch.setattr(MdosStore, "_insert_delivery_tx", fail_on_payment)
    with pytest.raises(RuntimeError, match="injected payment batch crash"):
        run_g1_fixture_slice(database, delivery_run_id="atomic-crash")
    store, _, _ = _runtime(database)
    assert store.records("PAYMENT_PROOF") == []
    assert store.record_version("ORDER_RECORD", "order-fixture-001", 2) is None
    assert not any(
        row["payload"].get("outcome_type") == "CLEARED_PAYMENT"
        for row in store.records("OUTCOME_EVENT")
    )

    monkeypatch.setattr(MdosStore, "_insert_delivery_tx", original)
    recovered = run_g1_fixture_slice(database, delivery_run_id="atomic-recovery")
    assert recovered["reconciliation"]["status"] == "RECONCILED_FIXTURE_NON_KPI"
    assert recovered["integrity"]["counts"]["mdos_ledger"] == 29


def test_direct_bypasses_and_fabricated_audit_rows_fail_integrity(tmp_path: Path) -> None:
    database = tmp_path / "direct.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id="direct-base")
    store, _, _ = _runtime(database)
    payment = dict(store.records("PAYMENT_PROOF")[0]["payload"])
    payment["payment_proof_id"] = "payment-proof-direct-duplicate"
    with pytest.raises(SchemaIntegrityError, match="duplicate reconciled PaymentProof"):
        store._append_domain_record(
            record_type="PAYMENT_PROOF",
            aggregate_id=payment["payment_proof_id"],
            aggregate_version=1,
            idempotency_key="direct-private-payment-duplicate",
            payload=payment,
            writer_id="fixture-bank-verifier",
            required_role="PAYMENT_VERIFIER",
            trace_id="trace:direct-private-payment",
            recorded_at_utc="2026-08-25T10:00:00Z",
        )

    denials_before = store.count("mdos_denials")
    with pytest.raises(ContractValidationError):
        store.append_record(
            record_type="PAYMENT_PROOF",
            aggregate_id="invalid-payment",
            aggregate_version=1,
            idempotency_key="invalid-payment-schema",
            payload={},
            writer_id="fixture-bank-verifier",
            required_role="PAYMENT_VERIFIER",
            trace_id="trace:invalid-payment-schema",
            recorded_at_utc="2026-08-25T10:01:00Z",
        )
    assert store.count("mdos_denials") == denials_before + 1
    assert store.delivery_receipts("invalid-payment-schema")[0]["disposition"] == "DENIED"
    store.verify_integrity()

    with sqlite3.connect(database) as connection:
        connection.execute(
            """INSERT INTO mdos_denials(
                   denial_id,operation,attempted_actor_id,reason_code,payload_sha256,
                   trace_id,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                "denial-fabricated",
                "fake",
                "fixture-reconciler",
                "FAKE",
                "0" * 64,
                "trace:fake",
                "2026-08-25T10:02:00Z",
            ),
        )
        connection.commit()
    with pytest.raises(SchemaIntegrityError, match="denial identity digest mismatch"):
        store.verify_integrity()


def test_projection_conflict_is_auditable_and_backup_tamper_is_rejected(
    tmp_path: Path,
) -> None:
    database = tmp_path / "projection.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id="projection-base")
    store, _, _ = _runtime(database)
    original = store.shadow_projections()[0]
    changed = json.loads(json.dumps(original["projection"]))
    changed["company"]["shadow_note"] = "changed payload"
    changed_sha = value_sha256(changed)
    denials_before = len(store.denials())
    with pytest.raises(WriterRoleError, match="durable outbox"):
        store.write_bitrix_shadow_projection(
            projection_id=f"bitrix-shadow-{changed_sha[:32]}",
            projection_key=original["projection_key"],
            demand_unit_id=original["demand_unit_id"],
            projection=changed,
            permit_decision_id=original["permit_decision_id"],
            permit_decision_sha256=original["permit_decision_sha256"],
            writer_id="fixture-bitrix-projector",
            trace_id="trace:projection-conflict",
            recorded_at_utc="2026-08-25T10:10:00Z",
        )
    assert len(store.shadow_projections()) == 1
    assert len(store.denials()) == denials_before + 1
    assert store.denials()[-1]["reason_code"] == "DURABLE_OUTBOX_REQUIRED"
    store.verify_integrity()

    backup, manifest = store.create_backup(
        tmp_path / "backups" / "projection.sqlite3",
        created_at_utc="2026-08-25T10:11:00Z",
    )
    with backup.open("r+b") as stream:
        stream.seek(100)
        original_byte = stream.read(1)
        stream.seek(100)
        stream.write(bytes([original_byte[0] ^ 0xFF]))
    with pytest.raises(Exception, match="backup authority or file digest mismatch"):
        MdosStore.restore_verified(backup, tmp_path / "restore" / "candidate.sqlite3")
    assert not (tmp_path / "restore" / "candidate.sqlite3").exists()
    assert manifest.exists()
