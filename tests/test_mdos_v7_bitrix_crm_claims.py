from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from lead_factory.mdos_v7.bitrix_crm_claims import (
    BitrixContractSignedMapping,
    BitrixCrmEnvelopeError,
    BitrixCrmMappingBlockedError,
    ShadowBitrixCrmClaimIntake,
    sealed_fixture_mapping_registry,
)
from lead_factory.mdos_v7.contracts import (
    ContractRegistry,
    record_digest_excluding,
    value_sha256,
)
from lead_factory.mdos_v7.fixture_slice import load_fixture, run_g1_fixture_slice
from lead_factory.mdos_v7.pipeline import G1Pipeline
from lead_factory.mdos_v7.policy import PermitService
from lead_factory.mdos_v7.store import (
    CRM_REAL_MAPPING_STATE,
    CRM_SHADOW_MAPPING_REGISTRY_SHA256,
    CRM_SHADOW_PORTAL_FINGERPRINT_SHA256,
    CRM_SHADOW_REMOTE_CATEGORY_ID,
    CRM_SHADOW_REMOTE_PIPELINE_ID,
    CRM_SHADOW_REMOTE_STAGE_ID,
    CRM_SHADOW_STAGE_MAPPING_VERSION,
    MdosStore,
    SchemaIntegrityError,
    canonical_json,
    crm_shadow_claim_aggregate_id,
    crm_shadow_claim_idempotency_key,
)


PORTAL_FINGERPRINT = CRM_SHADOW_PORTAL_FINGERPRINT_SHA256
SOURCE_ADAPTER = "fixture-source-adapter"
RECONCILER = "fixture-reconciler"
DEFAULT_DEAL_ID = "bx-deal-0123456789abcdef"


def _runtime(
    tmp_path: Path, name: str
) -> tuple[MdosStore, ShadowBitrixCrmClaimIntake, BitrixContractSignedMapping]:
    database = tmp_path / f"{name}.sqlite3"
    run_g1_fixture_slice(database, delivery_run_id=f"crm-{name}")
    store = MdosStore(database, actor_registry=load_fixture()["actors"])
    mapping = BitrixContractSignedMapping.from_sealed_fixture_registry(
        sealed_fixture_mapping_registry(),
        store=store,
        reconciler_id=RECONCILER,
        trace_id=f"trace:crm:{name}:mapping-resolution",
        recorded_at_utc="2026-08-25T10:59:00Z",
    )
    return store, ShadowBitrixCrmClaimIntake(store, mapping), mapping


def _envelope(
    mapping: BitrixContractSignedMapping,
    *,
    entity_id: str = DEFAULT_DEAL_ID,
    remote_version: int = 7,
    observed_at: str = "2026-08-25T11:00:00Z",
    distinct_order_id: str | None = None,
    **changes: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        **mapping.as_claim_fields(),
        "remote_entity_type": "DEAL",
        "remote_entity_id": entity_id,
        "remote_version": remote_version,
        "demand_unit_id": "du-fixture-existing-001",
        "account_id": "acct-fixture-alum-001",
        "distinct_order_id": distinct_order_id,
        "authoritative_class": "CRM_PROJECTION",
        "observed_at": observed_at,
        "reconciliation_state": "UNRECONCILED",
        "payment_proof_ref": None,
    }
    value.update(changes)
    return value


def _raw(value: dict[str, Any]) -> bytes:
    return canonical_json(value).encode("utf-8", "strict")


def _canonical_truth(store: MdosStore) -> dict[str, list[dict[str, Any]]]:
    return {
        record_type: store.records(record_type)
        for record_type in ("PAYMENT_PROOF", "ORDER_RECORD", "OUTCOME_EVENT")
    }


def _ingest(
    intake: ShadowBitrixCrmClaimIntake,
    value: dict[str, Any],
    *,
    trace_id: str = "trace:crm-contract-signed",
    recorded_at_utc: str = "2026-08-25T11:01:00Z",
):
    return intake.ingest(
        value,
        source_content=_raw(value),
        source_adapter_id=SOURCE_ADAPTER,
        reconciler_id=RECONCILER,
        trace_id=trace_id,
        recorded_at_utc=recorded_at_utc,
    )


def test_contract_claim_is_non_kpi_but_fulfilled_truth_outranks_its_read_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, intake, mapping = _runtime(tmp_path, "accepted")
    before = _canonical_truth(store)

    def payment_path_must_not_run(*_: Any, **__: Any) -> None:
        raise AssertionError("CRM intake reached authoritative payment transition")

    monkeypatch.setattr(store, "commit_payment_transition", payment_path_must_not_run)
    result = _ingest(intake, _envelope(mapping))

    assert result.disposition == "APPLIED"
    assert result.read_model_status == "FULFILLED"
    assert result.external_effect is False
    assert result.transport_call_count == 0
    assert intake.read_model_status(DEFAULT_DEAL_ID) == "FULFILLED"
    claims = store.records("CRM_OUTCOME_CLAIM")
    assert len(claims) == 1
    claim = claims[0]["payload"]
    assert claim["source_system"] == "BITRIX24_SHADOW_FIXTURE"
    assert claim["portal_fingerprint_sha256"] == PORTAL_FINGERPRINT
    assert claim["remote_category_id"] == CRM_SHADOW_REMOTE_CATEGORY_ID
    assert claim["remote_pipeline_id"] == CRM_SHADOW_REMOTE_PIPELINE_ID
    assert claim["remote_stage_id"] == CRM_SHADOW_REMOTE_STAGE_ID
    assert claim["stage_mapping_version"] == CRM_SHADOW_STAGE_MAPPING_VERSION
    assert claim["stage_mapping_sha256"] == mapping.stage_mapping_sha256
    assert (
        claim["stage_mapping_registry_sha256"]
        == CRM_SHADOW_MAPPING_REGISTRY_SHA256
    )
    assert claim["real_mapping_state"] == CRM_REAL_MAPPING_STATE
    assert claim["semantic_milestone"] == "CONTRACT_SIGNED"
    assert claim["read_model_status"] == "CONTRACT_SIGNED_AWAITING_PAYMENT"
    assert claim["canonical_kpi_eligible"] is False
    assert claim["authoritative_class"] == "CRM_PROJECTION"
    assert claim["reconciliation_state"] == "UNRECONCILED"
    assert claim["payment_proof_ref"] is None
    assert claim["recorded_by"] == RECONCILER
    assert before["PAYMENT_PROOF"]
    assert before["ORDER_RECORD"][-1]["payload"]["state"] == "FULFILLED"
    paid_snapshot = store.record_version("ORDER_RECORD", "order-fixture-001", 2)
    assert paid_snapshot is not None
    assert paid_snapshot["payload"]["state"] == "PAID"
    monkeypatch.setattr(intake, "_bound_order", lambda _: paid_snapshot)
    assert intake._effective_read_model_status(claim) == "PAID"
    assert _canonical_truth(store) == before
    store.verify_integrity()


def test_contract_claim_moves_an_approved_order_to_awaiting_payment_read_model(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "approved-awaiting-payment")
    approved = dict(
        store.record_version("ORDER_RECORD", "order-fixture-001", 1)["payload"]
    )
    approved.update(
        {
            "distinct_order_id": "order-fixture-awaiting-002",
            "approved_at": "2026-08-25T11:00:00Z",
        }
    )
    approved["payload_sha256"] = record_digest_excluding(
        approved, "payload_sha256"
    )
    pipeline = G1Pipeline(store, ContractRegistry(), PermitService(store, ContractRegistry()))
    order_result = pipeline.record_order(
        approved,
        writer_id="fixture-order-approver",
        trace_id="trace:crm:approved-awaiting-payment:order",
    )
    assert order_result.disposition == "APPLIED"
    before_truth = _canonical_truth(store)

    result = _ingest(
        intake,
        _envelope(
            mapping,
            distinct_order_id="order-fixture-awaiting-002",
            observed_at="2026-08-25T11:00:30Z",
        ),
        recorded_at_utc="2026-08-25T11:01:00Z",
    )

    assert result.disposition == "APPLIED"
    assert result.read_model_status == "CONTRACT_SIGNED_AWAITING_PAYMENT"
    assert intake.read_model_status(DEFAULT_DEAL_ID) == (
        "CONTRACT_SIGNED_AWAITING_PAYMENT"
    )
    assert _canonical_truth(store) == before_truth
    store.verify_integrity()


def test_claim_and_delivery_audit_survive_verified_backup_restore(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "backup-restore")
    result = _ingest(intake, _envelope(mapping))
    assert result.disposition == "APPLIED"
    before = store.verify_integrity()
    claim = store.records("CRM_OUTCOME_CLAIM")[0]
    receipts = store.delivery_receipts(claim["idempotency_key"])
    assert [row["disposition"] for row in receipts] == ["APPLIED"]

    backup, _ = store.create_backup(
        tmp_path / "backups" / "crm-claim.sqlite3",
        created_at_utc="2026-08-25T12:00:00Z",
    )
    restored = MdosStore.restore_verified(
        backup, tmp_path / "restored" / "crm-claim.sqlite3"
    )

    assert restored.verify_integrity() == before
    assert restored.records("CRM_OUTCOME_CLAIM") == store.records("CRM_OUTCOME_CLAIM")
    assert restored.delivery_receipts(claim["idempotency_key"]) == receipts


def test_only_sealed_fixture_mapping_registry_can_authorize_intake(
    tmp_path: Path,
) -> None:
    store, _, _ = _runtime(tmp_path, "sealed-registry")
    with pytest.raises(BitrixCrmMappingBlockedError, match="sealed fixture registry"):
        BitrixContractSignedMapping()

    candidates: list[dict[str, Any]] = []
    changed_stage = sealed_fixture_mapping_registry()
    changed_stage["mappings"][0]["remote_stage_id"] = "bx-stage-aaaaaaaaaaaaaaaa"
    candidates.append(changed_stage)
    changed_version = sealed_fixture_mapping_registry()
    changed_version["mappings"][0]["stage_mapping_version"] = "unratified-v2"
    candidates.append(changed_version)
    claimed_real = sealed_fixture_mapping_registry()
    claimed_real["real_mapping_state"] = "RATIFIED"
    candidates.append(claimed_real)

    for index, candidate in enumerate(candidates):
        with pytest.raises(BitrixCrmMappingBlockedError, match="UNKNOWN and blocked"):
            BitrixContractSignedMapping.from_sealed_fixture_registry(
                candidate,
                store=store,
                reconciler_id=RECONCILER,
                trace_id=f"trace:crm:unsealed-mapping:{index}",
                recorded_at_utc=f"2026-08-25T11:0{index}:00Z",
            )

    conflicts = store.conflicts()[-3:]
    assert len(conflicts) == 3
    assert {row["conflict_type"] for row in conflicts} == {
        "CRM_MAPPING_REGISTRY_UNRATIFIED"
    }
    assert {row["blocked_action"] for row in conflicts} == {
        "ACTIVATE_CRM_STAGE_MAPPING"
    }
    assert all(
        row["details"]["real_mapping_state"] == "UNKNOWN_BLOCKED"
        for row in conflicts
    )
    assert store.records("CRM_OUTCOME_CLAIM") == []
    store.verify_integrity()


def test_exact_replay_and_changed_same_remote_version_are_distinct(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "replay-conflict")
    original = _envelope(mapping)
    first = _ingest(intake, original, trace_id="trace:crm:first")
    replay = _ingest(
        intake,
        original,
        trace_id="trace:crm:replay",
        recorded_at_utc="2026-08-25T11:02:00Z",
    )
    changed = {**original, "account_id": "acct-forged-other"}
    conflict = _ingest(
        intake,
        changed,
        trace_id="trace:crm:version-conflict",
        recorded_at_utc="2026-08-25T11:03:00Z",
    )

    assert replay.disposition == "REPLAY"
    assert replay.ledger_entry_id == first.ledger_entry_id
    assert conflict.disposition == "QUARANTINED"
    assert conflict.conflict_id is not None
    assert len(store.records("CRM_OUTCOME_CLAIM")) == 1
    receipts = store.delivery_receipts(
        store.records("CRM_OUTCOME_CLAIM")[0]["idempotency_key"]
    )
    assert [row["disposition"] for row in receipts] == ["APPLIED", "REPLAY"]
    assert [row["recorded_at_utc"] for row in receipts] == [
        "2026-08-25T11:01:00Z",
        "2026-08-25T11:02:00Z",
    ]
    assert store.conflicts()[-1]["conflict_type"] == "CRM_REMOTE_VERSION_CONFLICT"
    store.verify_integrity()


def test_stale_version_and_observed_time_regression_do_not_change_read_model(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "stale")
    _ingest(intake, _envelope(mapping, remote_version=7))
    stale = _ingest(
        intake,
        _envelope(mapping, remote_version=6),
        trace_id="trace:crm:stale",
        recorded_at_utc="2026-08-25T11:02:00Z",
    )
    chronology = _ingest(
        intake,
        _envelope(
            mapping,
            remote_version=8,
            observed_at="2026-08-25T10:59:59Z",
        ),
        trace_id="trace:crm:chronology",
        recorded_at_utc="2026-08-25T11:03:00Z",
    )

    assert stale.disposition == chronology.disposition == "QUARANTINED"
    assert stale.remote_version == chronology.remote_version == 7
    assert intake.read_model_status(DEFAULT_DEAL_ID) == "FULFILLED"
    assert len(store.records("CRM_OUTCOME_CLAIM")) == 1
    assert [row["conflict_type"] for row in store.conflicts()[-2:]] == [
        "CRM_REMOTE_VERSION_STALE",
        "CRM_REMOTE_CHRONOLOGY_REGRESSION",
    ]
    store.verify_integrity()


@pytest.mark.parametrize(
    "semantic_milestone",
    ["PAID", "CLEARED_PAYMENT", "REPEAT_PAYMENT"],
)
def test_forged_paid_semantics_never_reach_payment_truth(
    tmp_path: Path, semantic_milestone: str
) -> None:
    store, intake, mapping = _runtime(tmp_path, f"forged-{semantic_milestone}")
    before = _canonical_truth(store)
    result = _ingest(
        intake,
        _envelope(mapping, semantic_milestone=semantic_milestone),
    )

    assert result.disposition == "QUARANTINED"
    assert store.conflicts()[-1]["conflict_type"] == "CRM_PAYMENT_TRUTH_FORGERY"
    assert store.records("CRM_OUTCOME_CLAIM") == []
    assert _canonical_truth(store) == before
    store.verify_integrity()


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("source_system", "BANK_API"),
        ("authoritative_class", "BANK_API"),
        ("reconciliation_state", "RECONCILED"),
        ("payment_proof_ref", "payment-proof-forged"),
    ],
)
def test_authority_reconciliation_and_proof_forgery_are_quarantined(
    tmp_path: Path, field: str, forged_value: str
) -> None:
    store, intake, mapping = _runtime(tmp_path, f"authority-{field}")
    before = _canonical_truth(store)
    result = _ingest(intake, _envelope(mapping, **{field: forged_value}))

    assert result.disposition == "QUARANTINED"
    assert store.conflicts()[-1]["conflict_type"] == "CRM_AUTHORITY_FORGERY"
    assert store.records("CRM_OUTCOME_CLAIM") == []
    assert _canonical_truth(store) == before
    store.verify_integrity()


def test_order_reference_is_bound_without_mutating_the_order(tmp_path: Path) -> None:
    store, intake, mapping = _runtime(tmp_path, "order-binding")
    before = _canonical_truth(store)
    result = _ingest(
        intake,
        _envelope(mapping, distinct_order_id="order-fixture-001"),
    )

    assert result.disposition == "APPLIED"
    assert store.records("CRM_OUTCOME_CLAIM")[0]["payload"]["distinct_order_id"] == (
        "order-fixture-001"
    )
    assert _canonical_truth(store) == before
    store.verify_integrity()


def test_missing_or_mismatched_order_binding_is_denied_at_store_boundary(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "bad-order-binding")
    before = _canonical_truth(store)
    value = _envelope(mapping, distinct_order_id="order-does-not-exist")

    with pytest.raises(SchemaIntegrityError, match="source/version/order binding"):
        _ingest(intake, value)

    assert store.records("CRM_OUTCOME_CLAIM") == []
    assert _canonical_truth(store) == before
    assert store.denials()[-1]["reason_code"] == "DOMAIN_INVARIANT_DENIED"
    store.verify_integrity()


def test_strict_envelope_and_chronology_fail_before_claim_effects(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "strict")
    valid = _envelope(mapping)
    cases = [
        ({**valid, "unexpected": "field"}, None, "unexpected"),
        ({**valid, "remote_version": True}, None, "remote_version"),
        (
            valid,
            json.dumps(valid, ensure_ascii=False, indent=2).encode("utf-8"),
            "canonical JSON",
        ),
    ]
    for index, (value, raw_content, message) in enumerate(cases):
        with pytest.raises(BitrixCrmEnvelopeError, match=message):
            intake.ingest(
                value,
                source_content=raw_content if raw_content is not None else _raw(value),
                source_adapter_id=SOURCE_ADAPTER,
                reconciler_id=RECONCILER,
                trace_id=f"trace:crm:strict:{index}",
                recorded_at_utc="2026-08-25T11:01:00Z",
            )
    with pytest.raises(BitrixCrmEnvelopeError, match="later than recorded"):
        _ingest(
            intake,
            _envelope(mapping, observed_at="2026-08-25T11:02:00Z"),
        )

    assert store.records("CRM_OUTCOME_CLAIM") == []
    assert store.evidence(value_sha256(valid)) is None
    store.verify_integrity()


def test_phone_like_remote_id_is_denied_and_immutably_audited(tmp_path: Path) -> None:
    store, intake, mapping = _runtime(tmp_path, "phone-id")
    value = _envelope(mapping, entity_id="79001234567")
    denials_before = len(store.denials())

    with pytest.raises(BitrixCrmEnvelopeError, match="remote_entity_id"):
        _ingest(intake, value, trace_id="trace:crm:phone-like-id")

    assert store.records("CRM_OUTCOME_CLAIM") == []
    assert len(store.denials()) == denials_before + 1
    assert store.denials()[-1]["reason_code"] == "CRM_ENVELOPE_SCHEMA_DENIED"
    assert store.evidence(value_sha256(value)) is None
    store.verify_integrity()


def test_observation_before_accepted_demand_is_quarantined_without_evidence(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "ancient-observation")
    value = _envelope(mapping, observed_at="2026-08-25T09:07:59Z")
    result = _ingest(
        intake,
        value,
        trace_id="trace:crm:ancient-observation",
        recorded_at_utc="2026-08-25T11:01:00Z",
    )

    assert result.disposition == "QUARANTINED"
    assert store.conflicts()[-1]["conflict_type"] == (
        "CRM_LOCAL_CHRONOLOGY_VIOLATION"
    )
    assert store.records("CRM_OUTCOME_CLAIM") == []
    assert store.evidence(value_sha256(value)) is None
    store.verify_integrity()


def test_generic_pipeline_and_direct_store_cannot_mint_a_valid_crm_claim(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "generic-bypass")
    accepted = _ingest(intake, _envelope(mapping))
    persisted = store.record_by_id(str(accepted.ledger_entry_id))
    assert persisted is not None
    payload = persisted["payload"]

    with pytest.raises(SchemaIntegrityError, match="typed shadow CRM transition"):
        store._append_domain_record(
            record_type="CRM_OUTCOME_CLAIM",
            aggregate_id=str(persisted["aggregate_id"]),
            aggregate_version=int(persisted["aggregate_version"]),
            idempotency_key=str(persisted["idempotency_key"]),
            payload=payload,
            writer_id=RECONCILER,
            required_role="RECONCILER",
            trace_id="trace:crm:direct-store-bypass",
            recorded_at_utc="2026-08-25T11:02:00Z",
        )

    contracts = ContractRegistry()
    pipeline = G1Pipeline(store, contracts, PermitService(store, contracts))
    with pytest.raises(SchemaIntegrityError, match="typed shadow CRM transition"):
        pipeline.append_internal_record(
            record_type="CRM_OUTCOME_CLAIM",
            record_id=str(payload["record_id"]),
            payload=payload,
            writer_id=RECONCILER,
            required_role="RECONCILER",
            trace_id="trace:crm:pipeline-bypass",
            recorded_at_utc="2026-08-25T11:03:00Z",
        )

    assert len(store.records("CRM_OUTCOME_CLAIM")) == 1
    store.verify_integrity()


def test_integrity_rejects_schema_valid_direct_sql_claim_without_typed_receipt(
    tmp_path: Path,
) -> None:
    store, intake, mapping = _runtime(tmp_path, "sql-bypass")
    accepted = _ingest(intake, _envelope(mapping))
    persisted = store.record_by_id(str(accepted.ledger_entry_id))
    assert persisted is not None
    direct_envelope = _envelope(
        mapping,
        entity_id="bx-deal-fedcba9876543210",
        remote_version=8,
        observed_at="2026-08-25T11:02:00Z",
    )
    direct_recorded_at = "2026-08-25T11:03:00Z"
    direct_trace_id = "trace:crm:direct-sql"
    direct_artifact_sha = value_sha256(direct_envelope)
    store.append_evidence(
        content=_raw(direct_envelope),
        media_type="application/json",
        source_ref=mapping.source_ref,
        synthetic=True,
        writer_id=SOURCE_ADAPTER,
        required_role="SOURCE_ADAPTER",
        trace_id=direct_trace_id,
        recorded_at_utc=direct_recorded_at,
    )
    aggregate_id = crm_shadow_claim_aggregate_id(direct_envelope)
    direct_claim = {
        "schema_version": "1.0.0",
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "record_id": aggregate_id,
        **direct_envelope,
        "source_artifact_sha256": direct_artifact_sha,
        "recorded_at": direct_recorded_at,
        "read_model_status": "CONTRACT_SIGNED_AWAITING_PAYMENT",
        "recorded_by": RECONCILER,
        "mode": "SHADOW",
        "external_effect": False,
        "transport_call_count": 0,
    }
    direct_claim["payload_sha256"] = record_digest_excluding(
        direct_claim, "payload_sha256"
    )
    idempotency_key = crm_shadow_claim_idempotency_key(direct_claim)
    ledger_payload_sha = value_sha256(direct_claim)
    base = {
        "record_type": "CRM_OUTCOME_CLAIM",
        "aggregate_id": aggregate_id,
        "aggregate_version": 1,
        "idempotency_key": idempotency_key,
        "payload_sha256": ledger_payload_sha,
        "previous_entry_sha256": str(persisted["entry_sha256"]),
        "writer_id": RECONCILER,
        "trace_id": direct_trace_id,
        "recorded_at_utc": direct_recorded_at,
    }
    direct_entry_id = f"mdos-entry-{value_sha256(base)[:32]}"
    direct_entry_sha = value_sha256({"entry_id": direct_entry_id, **base})
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """INSERT INTO mdos_ledger(
                   entry_id,record_type,aggregate_id,aggregate_version,
                   idempotency_key,payload_json,payload_sha256,
                   previous_entry_sha256,entry_sha256,writer_id,trace_id,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                direct_entry_id,
                "CRM_OUTCOME_CLAIM",
                aggregate_id,
                1,
                idempotency_key,
                canonical_json(direct_claim),
                ledger_payload_sha,
                str(persisted["entry_sha256"]),
                direct_entry_sha,
                RECONCILER,
                direct_trace_id,
                direct_recorded_at,
            ),
        )
        connection.commit()

    with pytest.raises(SchemaIntegrityError, match="typed APPLIED receipt"):
        store.verify_integrity()
