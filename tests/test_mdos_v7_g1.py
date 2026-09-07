from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Mapping

import pytest

from lead_factory.mdos_v7.bitrix_projection import (
    LiveBitrixProjectionAdapter,
    ProjectionError,
    ShadowBitrixProjectionAdapter,
)
from lead_factory.mdos_v7.contracts import ContractRegistry, canonical_json_bytes, value_sha256
from lead_factory.mdos_v7.fixture_slice import load_fixture, run_g1_fixture_slice
from lead_factory.mdos_v7.pipeline import G1Pipeline
from lead_factory.mdos_v7.policy import (
    PermitDeniedError,
    PermitExpiredError,
    PermitMismatchError,
    PermitRequest,
    PermitService,
)
from lead_factory.mdos_v7.store import MdosStore, WriterRoleError


def _open(database: Path) -> tuple[MdosStore, ContractRegistry, PermitService, G1Pipeline]:
    fixture = load_fixture()
    store = MdosStore(database, actor_registry=fixture["actors"])
    contracts = ContractRegistry()
    permits = PermitService(store, contracts)
    return store, contracts, permits, G1Pipeline(store, contracts, permits)


def test_complete_g1_slice_is_schema_valid_non_kpi_and_replay_safe(tmp_path: Path) -> None:
    database = tmp_path / "g1-shadow.sqlite3"
    first = run_g1_fixture_slice(database, delivery_run_id="test-delivery-001")
    first_root = first["integrity"]["ledger_root_sha256"]
    first_counts = first["record_type_counts"]

    assert first["status"] == "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
    assert first["canonical_kpi_eligible"] is False
    assert first["independent_verification"] is False
    assert first["external_effect_count"] == 0
    assert first["live_bitrix_write_count"] == 0
    assert first["bitrix_shadow_projection_count"] == 1
    assert first["reconciliation"] == {
        "reconciliation_id": "reconciliation-fixture-001",
        "status": "RECONCILED_FIXTURE_NON_KPI",
        "canonical_kpi_eligible": False,
    }
    assert first_counts["SIGNAL_OBSERVATION"] == 1
    assert first_counts["CLAIM"] == 2
    assert first_counts["DEMAND_UNIT"] == 2
    assert first_counts["GOLD_ACCEPTANCE"] == 1
    assert first_counts["PERMIT_DECISION"] == 1
    assert first_counts["ACTION_ASSIGNMENT"] == 1
    assert first_counts["PAYMENT_PROOF"] == 1
    assert first_counts["ORDER_RECORD"] == 3
    assert first_counts["FULFILMENT_RECORD"] == 1
    assert first_counts["OUTCOME_EVENT"] == 2

    store, contracts, _, _ = _open(database)
    schema_for_type = {
        "SIGNAL_OBSERVATION": "signal-observation.schema.json",
        "CLAIM": "claim.schema.json",
        "ENTITY_RESOLUTION_DECISION": "entity-resolution-decision.schema.json",
        "DEMAND_UNIT": "demand-unit.schema.json",
        "GOLD_ACCEPTANCE": "gold-acceptance.schema.json",
        "PERMIT_DECISION": "permit-decision.schema.json",
        "ACTION_ASSIGNMENT": "action-assignment.schema.json",
        "PAYMENT_PROOF": "payment-proof.schema.json",
        "ORDER_RECORD": "order-record.schema.json",
        "FULFILMENT_RECORD": "fulfilment-record.schema.json",
        "OUTCOME_EVENT": "outcome-event.schema.json",
    }
    for record in store.records():
        schema = schema_for_type.get(record["record_type"])
        if schema:
            contracts.validate(schema, record["payload"])
    payment = store.records("PAYMENT_PROOF")[0]["payload"]
    assert payment["authoritative_class"] == "SIGNED_BANK_STATEMENT"
    assert payment["reconciliation_state"] == "RECONCILED"
    assert store.latest_record("ORDER_RECORD", payment["distinct_order_id"])["payload"][
        "state"
    ] == "FULFILLED"
    assert all(projection["external_effect"] == 0 for projection in store.shadow_projections())

    second = run_g1_fixture_slice(database, delivery_run_id="test-delivery-002")
    assert second["integrity"]["ledger_root_sha256"] == first_root
    assert second["record_type_counts"] == first_counts
    assert second["projection"]["inserted_on_this_delivery"] is False
    assert second["bitrix_shadow_projection_count"] == 1
    third = run_g1_fixture_slice(database, delivery_run_id="test-delivery-003")
    assert third["integrity"]["ledger_root_sha256"] == first_root
    signal_receipts = store.delivery_receipts("fixture:signal:existing-001")
    assert [row["disposition"] for row in signal_receipts] == [
        "APPLIED",
        "REPLAY",
        "REPLAY",
    ]


def test_unknown_order_payment_stays_raw_quarantined_and_non_kpi(tmp_path: Path) -> None:
    fixture = load_fixture()
    database = tmp_path / "unknown-order.sqlite3"
    store = MdosStore(database, actor_registry=fixture["actors"])
    contracts = ContractRegistry()
    pipeline = G1Pipeline(store, contracts, PermitService(store, contracts))
    artifact = {
        "fixture": True,
        "signed": True,
        "provider": "fixture-signed-bank-statement",
        "provider_event_id": "unknown-order-event-001",
        "distinct_order_id": "order-does-not-exist",
        "canonical_account_id": "acct-fixture-alum-001",
        "payer_identity_ref": "payer-fixture-001",
        "recipient_identity_ref": "alumkomplekt-fixture-legal-entity",
        "amount": 1000.0,
        "currency": "RUB",
        "value_at": "2026-08-25T10:00:00Z",
    }
    content = canonical_json_bytes(artifact)
    observation = {
        **artifact,
        "source_artifact_sha256": value_sha256(artifact),
    }

    result = pipeline.ingest_payment_observation(
        observation,
        source_content=content,
        writer_id="fixture-bank-adapter",
        reconciler_id="fixture-reconciler",
        trace_id="trace:unknown-order",
        recorded_at_utc="2026-08-25T10:00:01Z",
    )

    assert result.status == "QUARANTINED"
    assert result.conflict_id
    assert store.count("mdos_conflicts") == 1
    assert store.records("RAW_PAYMENT_OBSERVATION")[0]["payload"][
        "canonical_kpi_eligible"
    ] is False
    assert store.records("PAYMENT_PROOF") == []
    assert store.records("OUTCOME_EVENT") == []
    assert store.conflicts()[0]["blocked_action"] == "CREATE_PAYMENT_PROOF_AND_KPI"


def test_direct_ai_or_generic_writer_cannot_bypass_gold_store_policy(tmp_path: Path) -> None:
    fixture = load_fixture()
    source_database = tmp_path / "source.sqlite3"
    run_g1_fixture_slice(source_database)
    source_store, _, _, _ = _open(source_database)
    gold = source_store.records("GOLD_ACCEPTANCE")[0]["payload"]

    actors = dict(fixture["actors"])
    actors["rogue-ai"] = {
        "actor_type": "AI",
        "roles": ["LEDGER_WRITER"],
        "registered_at_utc": "2026-08-25T08:00:00Z",
    }
    target = MdosStore(tmp_path / "target.sqlite3", actor_registry=actors)
    with pytest.raises(WriterRoleError, match="guarded domain service"):
        target.append_record(
            record_type="GOLD_ACCEPTANCE",
            aggregate_id=str(gold["gold_acceptance_id"]),
            aggregate_version=1,
            idempotency_key="rogue-gold-attempt",
            payload=gold,
            writer_id="rogue-ai",
            required_role="LEDGER_WRITER",
            trace_id="trace:rogue-ai",
            recorded_at_utc="2026-08-25T10:10:00Z",
        )
    assert target.records("GOLD_ACCEPTANCE") == []
    assert target.denials()[0]["reason_code"] == "WRITER_ROLE_DENIED"


class _SpyTransport:
    def __init__(self) -> None:
        self.calls = 0

    def create_or_update_work(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        return dict(payload)


def test_expired_mismatched_and_denied_permits_call_no_bitrix_transport(
    tmp_path: Path,
) -> None:
    database = tmp_path / "permit.sqlite3"
    run_g1_fixture_slice(database)
    store, contracts, permits, _ = _open(database)
    permit = store.records("PERMIT_DECISION")[0]["payload"]
    demand = store.record_version("DEMAND_UNIT", "du-fixture-existing-001", 2)["payload"]
    gold = store.records("GOLD_ACCEPTANCE")[0]["payload"]
    assignment = store.records("ACTION_ASSIGNMENT")[0]["payload"]
    spy = _SpyTransport()
    live = LiveBitrixProjectionAdapter(permits, spy)

    with pytest.raises(PermitExpiredError):
        permits.assert_exact(
            permit,
            at_utc=permit["expires_at"],
            action_type="CREATE_CRM_TASK",
            channel="BITRIX24_SHADOW",
            purpose=permit["purpose"],
            subject_refs=(demand["demand_unit_id"],),
            scope=permit["scope"],
            capacity_snapshot_ref=demand["capacity_snapshot_ref"],
            cost=0,
            currency="RUB",
            policy_version=permit["policy_version"],
            mode="SHADOW",
            attempted_actor_id="fixture-bitrix-projector",
            trace_id="trace:expired-permit",
        )

    tampered = {**permit, "max_cost": 1}
    with pytest.raises(PermitMismatchError):
        permits.assert_exact(
            tampered,
            at_utc="2026-08-25T09:09:01Z",
            action_type="CREATE_CRM_TASK",
            channel="BITRIX24_SHADOW",
            purpose=permit["purpose"],
            subject_refs=(demand["demand_unit_id"],),
            scope=permit["scope"],
            capacity_snapshot_ref=demand["capacity_snapshot_ref"],
            cost=0,
            currency="RUB",
            policy_version=permit["policy_version"],
            mode="SHADOW",
            attempted_actor_id="fixture-bitrix-projector",
            trace_id="trace:tampered-permit",
        )

    denied = permits.decide(
        PermitRequest(
            permit_decision_id="permit-live-denied-fixture",
            purpose="LIVE_WRITE",
            action_type="CREATE_CRM_TASK",
            channel="BITRIX24_LIVE",
            scope=permit["scope"],
            subject_refs=(demand["demand_unit_id"],),
            legal_basis_ref="FIXTURE_ONLY_NO_EXTERNAL_EFFECT",
            source_passport_ref="fixture:known-account-history",
            issued_at="2026-08-25T09:30:00Z",
            expires_at="2026-08-25T10:30:00Z",
            policy_version=permit["policy_version"],
            capacity_snapshot_ref=demand["capacity_snapshot_ref"],
            max_cost=0,
            currency="RUB",
            evidence_refs=("evidence-bundle-fixture-existing-001",),
            mode="LIVE",
        ),
        issued_by="fixture-policy-authority",
        trace_id="trace:live-denied",
    )
    with pytest.raises(PermitDeniedError):
        live.project(
            permit=denied,
            demand_unit_id=demand["demand_unit_id"],
            scope=denied["scope"],
            capacity_snapshot_ref=demand["capacity_snapshot_ref"],
            policy_version=denied["policy_version"],
            at_utc="2026-08-25T09:31:00Z",
            payload={"fixture": True},
            writer_id="fixture-bitrix-projector",
            trace_id="trace:live-denied",
        )
    assert spy.calls == 0
    assert len(store.denials()) >= 3

    altered_demand = {**demand, "need": "tampered unpersisted need"}
    with pytest.raises(ProjectionError, match="exact persisted input"):
        ShadowBitrixProjectionAdapter(
            store,
            contracts,
            permits,
            clock=lambda: "2026-08-25T09:09:01Z",
        ).project(
            demand_unit=altered_demand,
            gold_acceptance=gold,
            assignment=assignment,
            permit=permit,
            writer_id="fixture-bitrix-projector",
            trace_id="trace:tampered-projection",
        )
    assert len(store.shadow_projections()) == 1

    payment_before = store.records("PAYMENT_PROOF")[0]["payload"]
    projection_id = store.shadow_projections()[0]["projection_id"]
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE mdos_bitrix_shadow_projection SET external_effect=1 WHERE projection_id=?",
                (projection_id,),
            )
    assert store.records("PAYMENT_PROOF")[0]["payload"] == payment_before
