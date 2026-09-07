from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from lead_factory.mdos_v7 import projection_outbox as outbox_module
from lead_factory.mdos_v7.consent_suppression import seal_internal_record
from lead_factory.mdos_v7.contracts import ContractRegistry, value_sha256
from lead_factory.mdos_v7.fixture_slice import load_fixture, run_g1_fixture_slice
from lead_factory.mdos_v7.policy import PermitService
from lead_factory.mdos_v7.projection_outbox import (
    ProjectionDispatchBlocked,
    ProjectionLeaseError,
    ProjectionOutbox,
)
from lead_factory.mdos_v7.store import (
    IdempotencyConflict,
    MdosStore,
    SchemaIntegrityError,
    UnknownWriterError,
)


class MutableClock:
    def __init__(self, value: str) -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value


def _runtime(database: Path, clock: MutableClock) -> tuple[MdosStore, ProjectionOutbox]:
    store = MdosStore(database, actor_registry=load_fixture()["actors"])
    contracts = ContractRegistry()
    return store, ProjectionOutbox(
        store,
        PermitService(store, contracts),
        clock=clock,
    )


def _pending_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, MdosStore, ProjectionOutbox, MutableClock, str]:
    database = tmp_path / "pending.sqlite3"
    original = ProjectionOutbox.dispatch

    def stop_after_enqueue(self: ProjectionOutbox, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("injected stop after durable enqueue")

    monkeypatch.setattr(ProjectionOutbox, "dispatch", stop_after_enqueue)
    with pytest.raises(RuntimeError, match="stop after durable enqueue"):
        run_g1_fixture_slice(database, delivery_run_id="pending-command")
    monkeypatch.setattr(ProjectionOutbox, "dispatch", original)
    clock = MutableClock("2026-08-25T09:09:02Z")
    store, outbox = _runtime(database, clock)
    command_id = str(store.records("BITRIX_PROJECTION_COMMAND")[0]["aggregate_id"])
    assert outbox.status(command_id)["status"] == "PENDING"
    assert store.shadow_projections() == []
    store.verify_integrity()
    return database, store, outbox, clock, command_id


def test_complete_lifecycle_is_durable_replay_safe_and_transport_free(
    tmp_path: Path,
) -> None:
    database = tmp_path / "complete.sqlite3"
    first = run_g1_fixture_slice(database, delivery_run_id="outbox-first")
    second = run_g1_fixture_slice(database, delivery_run_id="outbox-second")
    store, outbox = _runtime(database, MutableClock("2026-08-25T09:09:01Z"))
    command = store.records("BITRIX_PROJECTION_COMMAND")[0]["payload"]

    assert first["projection"]["command_id"] == command["command_id"]
    assert first["projection"]["outbox_outcome"] == "SHADOW_COMMITTED"
    assert second["projection"]["inserted_on_this_delivery"] is False
    assert outbox.status(command["command_id"]) == {
        "command_id": command["command_id"],
        "status": "COMPLETED",
        "claim_count": 1,
        "attempt_count": 1,
        "receipt_count": 1,
        "dlq_count": 0,
    }
    assert len(store.shadow_projections()) == 1
    assert store.records("BITRIX_PROJECTION_RECEIPT")[0]["payload"][
        "transport_call_count"
    ] == 0
    assert first["external_effect_count"] == second["external_effect_count"] == 0
    store.verify_integrity()


def test_exact_enqueue_replays_and_changed_payload_is_immutable_conflict(
    tmp_path: Path,
) -> None:
    database = tmp_path / "enqueue.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id="enqueue-base")
    store, outbox = _runtime(database, MutableClock("2026-08-25T09:09:01Z"))
    command = store.records("BITRIX_PROJECTION_COMMAND")[0]["payload"]
    demand = store.record_version(
        "DEMAND_UNIT", command["demand_unit_id"], command["demand_unit_version"]
    )["payload"]
    gold = store.record_version(
        "GOLD_ACCEPTANCE",
        command["gold_acceptance_id"],
        command["gold_acceptance_version"],
    )["payload"]
    assignment = store.latest_record("ACTION_ASSIGNMENT", command["assignment_id"])[
        "payload"
    ]
    permit = store.latest_record("PERMIT_DECISION", command["permit_decision_id"])[
        "payload"
    ]
    replay = outbox.enqueue(
        demand_unit=demand,
        gold_acceptance=gold,
        assignment=assignment,
        permit=permit,
        projection=command["projection"],
        projection_id=command["projection_id"],
        projection_key=command["projection_key"],
        scope=command["scope"],
        writer_id="fixture-bitrix-projector",
        trace_id="trace:enqueue-replay",
    )
    assert replay.disposition == "REPLAY"

    changed = {**command["projection"], "company": {**command["projection"]["company"], "shadow_note": "changed"}}
    changed_sha = value_sha256(changed)
    with pytest.raises(IdempotencyConflict, match="different effect"):
        outbox.enqueue(
            demand_unit=demand,
            gold_acceptance=gold,
            assignment=assignment,
            permit=permit,
            projection=changed,
            projection_id=f"bitrix-shadow-{changed_sha[:32]}",
            projection_key=command["projection_key"],
            scope=command["scope"],
            writer_id="fixture-bitrix-projector",
            trace_id="trace:enqueue-conflict",
        )
    assert len(store.records("BITRIX_PROJECTION_COMMAND")) == 1
    assert any(
        value["conflict_type"] == "IDEMPOTENCY_KEY_REUSE"
        for value in store.conflicts()
    )
    store.verify_integrity()


def test_one_active_lease_then_expiry_reclaims_and_converges_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, clock, command_id = _pending_database(tmp_path, monkeypatch)
    first_claim = outbox.claim(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:first-claim",
    )
    first_attempt = outbox.begin_attempt(
        first_claim,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:first-attempt",
    )
    with pytest.raises(ProjectionLeaseError, match="unexpired claim"):
        outbox.claim(
            command_id,
            worker_id="fixture-bitrix-projector",
            trace_id="trace:competing-claim",
        )
    assert any(
        item["operation"] == "bitrix_outbox_claim"
        and item["reason_code"] == "LEASE_HELD"
        for item in store.denials()
    )
    assert outbox.status(command_id)["status"] == "AMBIGUOUS"
    assert first_attempt["transport_call_count"] == 0

    clock.value = "2026-08-25T09:09:33Z"
    second_claim = outbox.claim(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:reclaimed",
    )
    second_attempt = outbox.begin_attempt(
        second_claim,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:reclaimed-attempt",
    )
    completed = outbox.complete(
        second_attempt,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:reclaimed-complete",
    )
    assert completed.inserted is True
    assert completed.attempt_no == 2
    assert len(store.shadow_projections()) == 1
    assert outbox.status(command_id)["status"] == "COMPLETED"
    store.verify_integrity()


def test_projection_and_terminal_receipt_are_one_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, clock, command_id = _pending_database(tmp_path, monkeypatch)
    claim = outbox.claim(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:atomic-claim",
    )
    attempt = outbox.begin_attempt(
        claim,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:atomic-attempt",
    )
    original = MdosStore._insert_delivery_tx

    def fail_receipt(
        self: MdosStore, connection: Any, **kwargs: Any
    ) -> None:
        if kwargs.get("record_type") == "BITRIX_PROJECTION_RECEIPT":
            raise RuntimeError("injected terminal receipt crash")
        original(self, connection, **kwargs)

    monkeypatch.setattr(MdosStore, "_insert_delivery_tx", fail_receipt)
    with pytest.raises(RuntimeError, match="terminal receipt crash"):
        outbox.complete(
            attempt,
            worker_id="fixture-bitrix-projector",
            trace_id="trace:atomic-crash",
        )
    assert store.shadow_projections() == []
    assert store.records("BITRIX_PROJECTION_RECEIPT") == []
    store.verify_integrity()

    monkeypatch.setattr(MdosStore, "_insert_delivery_tx", original)
    clock.value = "2026-08-25T09:09:33Z"
    recovered = outbox.dispatch(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:atomic-recovery",
    )
    assert recovered.inserted is True
    assert len(store.shadow_projections()) == 1
    assert len(store.records("BITRIX_PROJECTION_RECEIPT")) == 1
    store.verify_integrity()


def test_expired_permit_goes_to_dlq_with_no_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, clock, command_id = _pending_database(tmp_path, monkeypatch)
    clock.value = "2026-08-25T10:07:00Z"
    with pytest.raises(ProjectionDispatchBlocked, match="PERMIT_EXPIRED"):
        outbox.dispatch(
            command_id,
            worker_id="fixture-bitrix-projector",
            trace_id="trace:expired-outbox",
        )
    assert store.shadow_projections() == []
    assert outbox.status(command_id)["status"] == "DLQ"
    assert store.records("BITRIX_PROJECTION_DLQ")[0]["payload"][
        "transport_call_count"
    ] == 0
    assert any(item["reason_code"] == "PERMITEXPIREDERROR" for item in store.denials())
    store.verify_integrity()


def test_unknown_worker_and_verified_restore_preserve_pending_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, _, command_id = _pending_database(tmp_path, monkeypatch)
    with pytest.raises(UnknownWriterError, match="unknown writer"):
        outbox.claim(
            command_id,
            worker_id="unregistered-projector",
            trace_id="trace:unknown-worker",
        )
    assert any(
        item["attempted_actor_id"] == "unregistered-projector"
        and item["reason_code"] == "UNKNOWN_WRITER"
        for item in store.denials()
    )
    backup, _ = store.create_backup(
        tmp_path / "backups" / "pending.sqlite3",
        created_at_utc="2026-08-25T09:09:03Z",
    )
    restored = MdosStore.restore_verified(
        backup, tmp_path / "restored" / "pending.sqlite3"
    )
    restored_outbox = ProjectionOutbox(
        restored,
        PermitService(restored, ContractRegistry()),
        clock=MutableClock("2026-08-25T09:09:04Z"),
    )
    assert restored_outbox.status(command_id)["status"] == "PENDING"
    assert restored.shadow_projections() == []
    restored.verify_integrity()


def test_store_completion_rechecks_permit_time_and_rolls_back_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, clock, command_id = _pending_database(tmp_path, monkeypatch)
    clock.value = "2026-08-25T10:06:50Z"
    claim = outbox.claim(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:store-jit-claim",
    )
    attempt = outbox.begin_attempt(
        claim,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:store-jit-attempt",
    )
    command = outbox.command(command_id)
    assert command is not None
    completed_at = "2026-08-25T10:07:00Z"
    outcome = "SHADOW_COMMITTED"
    receipt_id = (
        "bitrix-receipt-"
        + value_sha256(
            {
                "command_id": command_id,
                "attempt_id": attempt["attempt_id"],
                "projection_sha256": command["projection_sha256"],
                "outcome": outcome,
            }
        )[:32]
    )
    receipt = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "receipt_id": receipt_id,
            "command_id": command_id,
            "attempt_id": attempt["attempt_id"],
            "worker_id": "fixture-bitrix-projector",
            "outcome": outcome,
            "projection_id": command["projection_id"],
            "projection_key": command["projection_key"],
            "projection_sha256": command["projection_sha256"],
            "readback_sha256": command["projection_sha256"],
            "completed_at": completed_at,
            "transport_call_count": 0,
            "mode": "SHADOW",
            "external_effect": False,
        }
    )
    with pytest.raises(SchemaIntegrityError, match="JIT binding"):
        store.complete_bitrix_shadow_outbox(
            projection_id=str(command["projection_id"]),
            projection_key=str(command["projection_key"]),
            demand_unit_id=str(command["demand_unit_id"]),
            projection=dict(command["projection"]),
            permit_decision_id=str(command["permit_decision_id"]),
            permit_decision_sha256=str(command["permit_decision_sha256"]),
            receipt=receipt,
            writer_id="fixture-bitrix-projector",
            trace_id="trace:store-jit-expired",
            recorded_at_utc=completed_at,
        )
    assert store.shadow_projections() == []
    assert store.records("BITRIX_PROJECTION_RECEIPT") == []
    assert any(
        item["operation"] == "bitrix_outbox_store_completion"
        and item["reason_code"] == "JIT_BINDING_DENIED"
        for item in store.denials()
    )
    store.verify_integrity()


def test_attempt_must_use_its_claim_command_and_terminal_states_are_exclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, _, command_id = _pending_database(tmp_path, monkeypatch)
    original = outbox.command(command_id)
    assert original is not None
    changed_projection = {
        **original["projection"],
        "company": {
            **original["projection"]["company"],
            "shadow_note": "second durable command fixture",
        },
    }
    changed_projection_sha = value_sha256(changed_projection)
    changed_command_material = {
        "command_key": original["command_key"],
        "demand_unit_entry_id": original["demand_unit_entry_id"],
        "gold_acceptance_entry_id": original["gold_acceptance_entry_id"],
        "assignment_entry_id": original["assignment_entry_id"],
        "permit_decision_entry_id": original["permit_decision_entry_id"],
        "capacity_snapshot_entry_id": original["capacity_snapshot_entry_id"],
        "projection_sha256": changed_projection_sha,
    }
    changed_command_id = (
        "bitrix-command-" + value_sha256(changed_command_material)[:32]
    )
    changed_command = seal_internal_record(
        {
            **original,
            "command_id": changed_command_id,
            "projection_id": f"bitrix-shadow-{changed_projection_sha[:32]}",
            "projection": changed_projection,
            "projection_sha256": changed_projection_sha,
            "payload_sha256": "",
        }
    )
    store._append_domain_record(
        record_type="BITRIX_PROJECTION_COMMAND",
        aggregate_id=changed_command_id,
        aggregate_version=1,
        idempotency_key="fixture:second-outbox-command",
        payload=changed_command,
        writer_id="fixture-bitrix-projector",
        required_role="BITRIX_PROJECTION_WRITER",
        trace_id="trace:second-command",
        recorded_at_utc="2026-08-25T09:09:01Z",
    )
    claim = outbox.claim(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:cross-command-claim",
    )
    mismatched_attempt_material = {
        "claim_id": claim["claim_id"],
        "command_id": changed_command_id,
        "attempt_no": claim["attempt_no"],
    }
    mismatched_attempt = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "attempt_id": (
                "bitrix-attempt-"
                + value_sha256(mismatched_attempt_material)[:32]
            ),
            **mismatched_attempt_material,
            "worker_id": "fixture-bitrix-projector",
            "status": "STARTED",
            "started_at": "2026-08-25T09:09:02Z",
            "transport_call_count": 0,
            "mode": "SHADOW",
            "external_effect": False,
        }
    )
    with pytest.raises(SchemaIntegrityError, match="attempt claim binding"):
        store._append_domain_record(
            record_type="BITRIX_PROJECTION_ATTEMPT",
            aggregate_id=str(mismatched_attempt["attempt_id"]),
            aggregate_version=1,
            idempotency_key=f"bitrix-attempt:{mismatched_attempt['attempt_id']}",
            payload=mismatched_attempt,
            writer_id="fixture-bitrix-projector",
            required_role="BITRIX_PROJECTION_WRITER",
            trace_id="trace:cross-command-attempt",
            recorded_at_utc="2026-08-25T09:09:02Z",
        )
    assert store.records("BITRIX_PROJECTION_ATTEMPT") == []

    completed_db = tmp_path / "completed-terminal.sqlite3"
    run_g1_fixture_slice(completed_db, delivery_run_id="terminal-exclusive")
    completed_store, completed_outbox = _runtime(
        completed_db, MutableClock("2026-08-25T09:09:03Z")
    )
    completed_command = completed_store.records("BITRIX_PROJECTION_COMMAND")[0][
        "payload"
    ]
    completed_claim = completed_store.records("BITRIX_PROJECTION_CLAIM")[0]["payload"]
    completed_attempt = completed_store.records("BITRIX_PROJECTION_ATTEMPT")[0][
        "payload"
    ]
    second_claim_material = {
        "command_id": completed_command["command_id"],
        "attempt_no": 2,
        "worker_id": "fixture-bitrix-projector",
        "claimed_at": "2026-08-25T09:09:03Z",
        "lease_expires_at": "2026-08-25T09:09:33Z",
    }
    second_claim_id = "bitrix-claim-" + value_sha256(second_claim_material)[:32]
    second_claim = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "claim_id": second_claim_id,
            **second_claim_material,
            "fencing_token": value_sha256(
                {
                    "claim_id": second_claim_id,
                    "command_id": completed_command["command_id"],
                    "attempt_no": 2,
                    "worker_id": "fixture-bitrix-projector",
                }
            ),
            "mode": "SHADOW",
            "external_effect": False,
        }
    )
    with pytest.raises(SchemaIntegrityError, match="claim authority/lease binding"):
        completed_store._append_domain_record(
            record_type="BITRIX_PROJECTION_CLAIM",
            aggregate_id=second_claim_id,
            aggregate_version=1,
            idempotency_key=f"bitrix-claim:{second_claim_id}",
            payload=second_claim,
            writer_id="fixture-bitrix-projector",
            required_role="BITRIX_PROJECTION_WRITER",
            trace_id="trace:second-terminal-claim",
            recorded_at_utc="2026-08-25T09:09:03Z",
        )
    assert len(completed_store.records("BITRIX_PROJECTION_CLAIM")) == 1
    second_outcome = "CONFIRMED_AFTER_READBACK"
    second_receipt_id = "bitrix-receipt-" + value_sha256(
        {
            "command_id": completed_command["command_id"],
            "attempt_id": completed_attempt["attempt_id"],
            "projection_sha256": completed_command["projection_sha256"],
            "outcome": second_outcome,
        }
    )[:32]
    second_receipt = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "receipt_id": second_receipt_id,
            "command_id": completed_command["command_id"],
            "attempt_id": completed_attempt["attempt_id"],
            "worker_id": "fixture-bitrix-projector",
            "outcome": second_outcome,
            "projection_id": completed_command["projection_id"],
            "projection_key": completed_command["projection_key"],
            "projection_sha256": completed_command["projection_sha256"],
            "readback_sha256": completed_command["projection_sha256"],
            "completed_at": "2026-08-25T09:09:04Z",
            "transport_call_count": 0,
            "mode": "SHADOW",
            "external_effect": False,
        }
    )
    with pytest.raises(SchemaIntegrityError, match="receipt readback binding"):
        completed_store.complete_bitrix_shadow_outbox(
            projection_id=str(completed_command["projection_id"]),
            projection_key=str(completed_command["projection_key"]),
            demand_unit_id=str(completed_command["demand_unit_id"]),
            projection=dict(completed_command["projection"]),
            permit_decision_id=str(completed_command["permit_decision_id"]),
            permit_decision_sha256=str(
                completed_command["permit_decision_sha256"]
            ),
            receipt=second_receipt,
            writer_id="fixture-bitrix-projector",
            trace_id="trace:second-terminal-receipt",
            recorded_at_utc="2026-08-25T09:09:04Z",
        )
    assert len(completed_store.records("BITRIX_PROJECTION_RECEIPT")) == 1
    with pytest.raises(SchemaIntegrityError, match="DLQ claim binding"):
        completed_outbox._append_dlq(
            command=completed_command,
            claim=completed_claim,
            worker_id="fixture-bitrix-projector",
            reason_code="PERMIT_MISMATCH",
            trace_id="trace:dlq-after-receipt",
            failed_at="2026-08-25T09:09:03Z",
        )
    assert completed_store.records("BITRIX_PROJECTION_DLQ") == []
    completed_store.verify_integrity()


def test_authority_drift_denies_enqueue_claim_and_completion_immutably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, store, outbox, _, command_id = _pending_database(tmp_path, monkeypatch)
    command = outbox.command(command_id)
    assert command is not None
    demand = store.record_version(
        "DEMAND_UNIT", command["demand_unit_id"], command["demand_unit_version"]
    )["payload"]
    gold = store.record_version(
        "GOLD_ACCEPTANCE",
        command["gold_acceptance_id"],
        command["gold_acceptance_version"],
    )["payload"]
    assignment = store.latest_record("ACTION_ASSIGNMENT", command["assignment_id"])[
        "payload"
    ]
    permit = store.latest_record("PERMIT_DECISION", command["permit_decision_id"])[
        "payload"
    ]
    original_authority = outbox_module.authority_snapshot

    def invalid_authority() -> Any:
        raise ValueError("injected freeze digest drift")

    monkeypatch.setattr(outbox_module, "authority_snapshot", invalid_authority)
    with pytest.raises(ProjectionDispatchBlocked, match="AUTHORITY_SNAPSHOT_INVALID"):
        outbox.enqueue(
            demand_unit=demand,
            gold_acceptance=gold,
            assignment=assignment,
            permit=permit,
            projection=command["projection"],
            projection_id=command["projection_id"],
            projection_key=command["projection_key"],
            scope=command["scope"],
            writer_id="fixture-bitrix-projector",
            trace_id="trace:drift-enqueue",
        )
    with pytest.raises(ProjectionDispatchBlocked, match="AUTHORITY_SNAPSHOT_INVALID"):
        outbox.claim(
            command_id,
            worker_id="fixture-bitrix-projector",
            trace_id="trace:drift-claim",
        )
    assert store.records("BITRIX_PROJECTION_CLAIM") == []

    monkeypatch.setattr(outbox_module, "authority_snapshot", original_authority)
    claim = outbox.claim(
        command_id,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:valid-claim",
    )
    attempt = outbox.begin_attempt(
        claim,
        worker_id="fixture-bitrix-projector",
        trace_id="trace:valid-attempt",
    )
    monkeypatch.setattr(outbox_module, "authority_snapshot", invalid_authority)
    with pytest.raises(ProjectionDispatchBlocked, match="AUTHORITY_SNAPSHOT_INVALID"):
        outbox.complete(
            attempt,
            worker_id="fixture-bitrix-projector",
            trace_id="trace:drift-complete",
        )
    assert store.shadow_projections() == []
    assert store.records("BITRIX_PROJECTION_RECEIPT") == []
    drift_denials = [
        value
        for value in store.denials()
        if value["reason_code"] == "AUTHORITY_SNAPSHOT_INVALID"
    ]
    assert len(drift_denials) == 3
    store.verify_integrity()
