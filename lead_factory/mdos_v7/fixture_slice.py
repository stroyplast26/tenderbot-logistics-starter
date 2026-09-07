"""Deterministic G1 vertical slice over sealed synthetic fixture inputs.

Nothing in this module is live or KPI-eligible.  Human-only decisions are read
from the fixture file as pre-sealed test inputs; the runtime only validates and
records them.  It never turns model output into Gold, payment, order or
fulfilment truth.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .authority import CONTRACT_ID, PACKAGE_ROOT_SHA256, PACKAGE_VERSION
from .bitrix_projection import ShadowBitrixProjectionAdapter
from .contracts import (
    ContractRegistry,
    canonical_json_bytes,
    record_digest_excluding,
    value_sha256,
)
from .pipeline import G1Pipeline, scope_fingerprint
from .policy import PermitRequest, PermitService, permit_record_sha256
from .store import MdosStore


DEFAULT_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "market_demand_os_v7"
    / "g1_existing_account"
    / "fixture.json"
)


class FixtureSliceError(RuntimeError):
    """A synthetic input is missing an explicit sealed authority boundary."""


def load_fixture(path: str | Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FixtureSliceError("fixture root must be an object")
    expected = {
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "classification": "SYNTHETIC_FIXTURE_NON_CANONICAL_NON_KPI",
    }
    for field, expected_value in expected.items():
        if value.get(field) != expected_value:
            raise FixtureSliceError(f"fixture authority mismatch: {field}")
    if not isinstance(value.get("actors"), dict) or not value["actors"]:
        raise FixtureSliceError("fixture actor registry is missing")
    human_inputs = value.get("human_inputs")
    if not isinstance(human_inputs, dict):
        raise FixtureSliceError("sealed human fixture inputs are missing")
    for name in (
        "claim_adjudication",
        "identity_adjudication",
        "gold_review",
        "permit_authorization",
        "order_approval",
        "payment_verification",
        "fulfilment_attestation",
    ):
        item = human_inputs.get(name)
        if not isinstance(item, dict):
            raise FixtureSliceError(f"sealed human input is missing: {name}")
        seal_field = "attestation_sha256" if name == "gold_review" else "sealed_input_sha256"
        digest = str(item.get(seal_field, ""))
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise FixtureSliceError(f"human input is not sealed: {name}")
        expected_digest = value_sha256(
            {key: value for key, value in item.items() if key != seal_field}
        )
        if digest != expected_digest:
            raise FixtureSliceError(f"human input seal mismatch: {name}")
    return value


def _internal(
    pipeline: G1Pipeline,
    *,
    record_type: str,
    record_id: str,
    body: Mapping[str, Any],
    writer_id: str,
    required_role: str,
    trace_id: str,
    recorded_at: str,
) -> str:
    payload = {
        "schema_version": "1.0.0",
        "record_id": record_id,
        "synthetic": True,
        "canonical_kpi_eligible": False,
        **dict(body),
    }
    return pipeline.append_internal_record(
        record_type=record_type,
        record_id=record_id,
        payload=payload,
        writer_id=writer_id,
        required_role=required_role,
        trace_id=trace_id,
        recorded_at_utc=recorded_at,
    ).entry_id


def _with_digest(record: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(record)
    value["payload_sha256"] = record_digest_excluding(value, "payload_sha256")
    return value


def run_g1_fixture_slice(
    database_path: str | Path,
    *,
    fixture_path: str | Path = DEFAULT_FIXTURE,
    delivery_run_id: str = "delivery-default",
) -> dict[str, Any]:
    """Run or replay the complete fixture slice without any external effect."""

    fixture = load_fixture(fixture_path)
    business = dict(fixture["business"])
    human = dict(fixture["human_inputs"])
    if not delivery_run_id or delivery_run_id.strip() != delivery_run_id:
        raise FixtureSliceError("delivery_run_id must be a non-empty canonical string")
    trace_id = f"trace:{fixture['fixture_id']}:{delivery_run_id}"
    store = MdosStore(database_path, actor_registry=dict(fixture["actors"]))
    contracts = ContractRegistry(Path(__file__).resolve().parents[2])
    permits = PermitService(store, contracts)
    pipeline = G1Pipeline(store, contracts, permits)

    raw_payload = dict(fixture["raw_trigger_payload"])
    raw_content = canonical_json_bytes(raw_payload)
    raw_sha = value_sha256(raw_payload)
    signal = {
        "schema_version": "1.0.0",
        "event_id": "signal-fixture-existing-001",
        "event_type": "KNOWN_ACCOUNT_CURRENT_NEED",
        "producer": "fixture-source-adapter",
        "source_id": "fixture:known-account-history",
        "source_role": ["TRIGGER", "INTENT", "EVIDENCE_SUPPORT"],
        "subject_refs": [business["raw_account_ref"], business["object_or_site_ref"]],
        "event_time": "2026-08-25T09:00:00Z",
        "observed_time": "2026-08-25T09:00:01Z",
        "source_revision": "fixture-v1",
        "payload_sha256": raw_sha,
        "data_class": "SYNTHETIC_FIXTURE_NON_CANONICAL",
        "purpose": "G1_SHADOW_VERTICAL_SLICE",
        "idempotency_key": "fixture:signal:existing-001",
        "trace_id": f"trace:{fixture['fixture_id']}:business-event",
        "evidence_uri": f"mdos-evidence:{raw_sha}",
        "retention_until": "2027-08-25T00:00:00Z",
    }
    signal_result = pipeline.capture_signal(
        signal,
        raw_content=raw_content,
        writer_id="fixture-source-adapter",
        delivery_trace_id=trace_id,
    )

    claim_v1 = {
        "schema_version": "1.0.0",
        "claim_id": "claim-fixture-current-need-001",
        "claim_type": "CURRENT_PURCHASE_NEED",
        "subject_ref": business["raw_account_ref"],
        "value": {
            "need": business["need"],
            "product_scope": business["product_scope"],
            "object_or_site_ref": business["object_or_site_ref"],
        },
        "valid_from": "2026-08-25T09:00:00Z",
        "valid_to": None,
        "recorded_at": "2026-08-25T09:01:00Z",
        "source_event_id": signal["event_id"],
        "evidence_uri": signal["evidence_uri"],
        "evidence_span": "$.message",
        "payload_sha256": raw_sha,
        "producer": "fixture-source-adapter",
        "producer_version": "fixture-extractor-1",
        "model_prompt_digest": None,
        "confidence": 0.93,
        "uncertainty": 0.07,
        "authoritative_class": "INFERRED_CLAIM",
        "purpose": "G1_SHADOW_VERTICAL_SLICE",
        "ttl_until": "2026-09-24T09:01:00Z",
        "contradicts": [],
        "status": "PROPOSED",
    }
    claim_proposed = pipeline.propose_claim(
        claim_v1, writer_id="fixture-source-adapter", trace_id=trace_id
    )
    claim_v2 = {
        **claim_v1,
        "recorded_at": "2026-08-25T09:02:00Z",
        "confidence": 1.0,
        "uncertainty": 0.0,
        "authoritative_class": "HUMAN_ADJUDICATED",
        "status": str(human["claim_adjudication"]["decision"]),
    }
    claim_accepted = pipeline.accept_claim(
        claim_v2,
        reviewer_id=str(human["claim_adjudication"]["reviewer_id"]),
        trace_id=trace_id,
    )

    identity = {
        "schema_version": "1.0.0",
        "decision_id": "identity-fixture-account-001",
        "entity_type": "ACCOUNT",
        "left_ref": business["raw_account_ref"],
        "right_ref": business["account_id"],
        "comparison_vector": {"inn_exact": True, "email_domain_exact": True, "phone_exact": True},
        "prior": 0.6,
        "match_probability": 0.99,
        "lower_threshold": 0.2,
        "upper_threshold": 0.95,
        "zone": str(human["identity_adjudication"]["decision"]),
        "ruleset_version": "fixture-er-1",
        "model_digest": None,
        "evidence_claim_ids": [claim_v1["claim_id"]],
        "recorded_at": "2026-08-25T09:03:00Z",
        "decided_by": str(human["identity_adjudication"]["reviewer_id"]),
        "reversible": True,
        "supersedes_decision_id": None,
    }
    identity_result = pipeline.record_identity_decision(
        identity,
        writer_id=str(human["identity_adjudication"]["reviewer_id"]),
        trace_id=trace_id,
    )

    capacity_id = "capacity-fixture-20260825-0904"
    economics_id = "economics-fixture-existing-001"
    denominator_id = "denominator-fixture-existing-20260825"
    evidence_bundle_id = "evidence-bundle-fixture-existing-001"
    _internal(
        pipeline,
        record_type="CAPACITY_SNAPSHOT",
        record_id=capacity_id,
        body={
            "captured_at": "2026-08-25T09:04:00Z",
            "available_shadow_tasks": 1,
            "demand_unit_id": business["demand_unit_id"],
            "region": business["region"],
            "product_scope": list(business["product_scope"]),
        },
        writer_id="fixture-demand-steward",
        required_role="DATA_STEWARD",
        trace_id=trace_id,
        recorded_at="2026-08-25T09:04:00Z",
    )
    _internal(
        pipeline,
        record_type="ECONOMICS_SNAPSHOT",
        record_id=economics_id,
        body={"captured_at": "2026-08-25T09:04:01Z", "currency": "RUB", "shadow_cost": 0},
        writer_id="fixture-demand-steward",
        required_role="DATA_STEWARD",
        trace_id=trace_id,
        recorded_at="2026-08-25T09:04:01Z",
    )
    _internal(
        pipeline,
        record_type="DENOMINATOR_SNAPSHOT",
        record_id=denominator_id,
        body={"captured_at": "2026-08-25T09:04:02Z", "sealed_population": [business["demand_unit_id"]]},
        writer_id="fixture-demand-steward",
        required_role="DATA_STEWARD",
        trace_id=trace_id,
        recorded_at="2026-08-25T09:04:02Z",
    )
    _internal(
        pipeline,
        record_type="EVIDENCE_BUNDLE",
        record_id=evidence_bundle_id,
        body={
            "sealed_at": "2026-08-25T09:04:03Z",
            "evidence_refs": [signal["evidence_uri"], claim_v1["claim_id"], identity["decision_id"]],
        },
        writer_id="fixture-demand-steward",
        required_role="DATA_STEWARD",
        trace_id=trace_id,
        recorded_at="2026-08-25T09:04:03Z",
    )

    demand_v1: dict[str, Any] = {
        "schema_version": "1.1.0",
        "demand_unit_id": business["demand_unit_id"],
        "account_ref": business["account_id"],
        "motion": "EXISTING_ACCOUNT_EXPANSION",
        "need": business["need"],
        "product_scope": list(business["product_scope"]),
        "object_or_site_ref": business["object_or_site_ref"],
        "installed_asset_refs": [],
        "buying_group": [
            {
                "actor_ref": business["payer_identity_ref"],
                "role": "ECONOMIC_BUYER",
                "confidence": 1.0,
                "claim_ids": [claim_v1["claim_id"]],
            }
        ],
        "decision_horizon": {
            "as_of": "2026-08-25T09:05:00Z",
            "maturity": "MATURE",
            "probabilities": {
                "D0_7": 0.7,
                "D8_30": 0.2,
                "D31_60": 0.05,
                "D61_90": 0.02,
                "GT90": 0.01,
                "UNKNOWN": 0.02,
            },
        },
        "supplier_state": "OPEN",
        "artifact_refs": [signal["evidence_uri"]],
        "evidence_claim_ids": [claim_v1["claim_id"]],
        "negative_claim_ids": [],
        "scope_fingerprint": None,
        "gold_acceptance_ref": None,
        "state": "ELIGIBLE_FOR_GOLD_REVIEW",
        "lawful_next_action_ref": None,
        "capacity_snapshot_ref": None,
        "economics_snapshot_ref": None,
        "version": 1,
        "recorded_at": "2026-08-25T09:05:00Z",
    }
    demand_v1["scope_fingerprint"] = scope_fingerprint(demand_v1)
    demand_initial = pipeline.record_demand_unit(
        demand_v1, writer_id="fixture-demand-steward", trace_id=trace_id
    )

    gold_review_id = "human-gold-review-fixture-001"
    gold_review = {
        "schema_version": "1.0.0",
        "record_id": gold_review_id,
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "origin": "HUMAN_FIXTURE_INPUT",
        "reviewer_id": human["gold_review"]["reviewer_id"],
        "demand_unit_id": business["demand_unit_id"],
        "scope_fingerprint": demand_v1["scope_fingerprint"],
        "decision": human["gold_review"]["decision"],
        "reason_codes": human["gold_review"]["reason_codes"],
        "attestation_sha256": human["gold_review"]["attestation_sha256"],
        "reviewed_at": "2026-08-25T09:06:00Z",
    }
    gold_review_result = pipeline.record_human_gold_review(
        gold_review,
        reviewer_id=str(human["gold_review"]["reviewer_id"]),
        trace_id=trace_id,
    )

    permit_request = PermitRequest(
        permit_decision_id="permit-fixture-bitrix-shadow-001",
        purpose="G1_ACCEPTED_WORK_SHADOW_PROJECTION",
        action_type="CREATE_CRM_TASK",
        channel="BITRIX24_SHADOW",
        scope={
            "beachhead_profile_ref": None,
            "region": business["region"],
            "product_scope": list(business["product_scope"]),
        },
        subject_refs=(business["demand_unit_id"],),
        legal_basis_ref="FIXTURE_ONLY_NO_EXTERNAL_EFFECT",
        source_passport_ref="fixture:known-account-history",
        issued_at="2026-08-25T09:07:00Z",
        expires_at="2026-08-25T10:07:00Z",
        policy_version="mdos-v7.1-rc1-shadow-1",
        capacity_snapshot_ref=capacity_id,
        max_cost=0,
        currency="RUB",
        evidence_refs=(evidence_bundle_id, gold_review_id),
        mode="SHADOW",
    )
    permit = permits.decide(
        permit_request,
        issued_by=str(human["permit_authorization"]["issuer_id"]),
        trace_id=trace_id,
    )

    gold_id = "gold-fixture-existing-001"
    gold = {
        "schema_version": "1.0.0",
        "gold_acceptance_id": gold_id,
        "demand_unit_id": business["demand_unit_id"],
        "scope_fingerprint": demand_v1["scope_fingerprint"],
        "cohort_id": "cohort-fixture-existing-20260825",
        "denominator_snapshot_ref": denominator_id,
        "motion": demand_v1["motion"],
        "reviewer_id": human["gold_review"]["reviewer_id"],
        "reviewed_at": "2026-08-25T09:08:00Z",
        "cutoff_at": "2026-08-25T09:08:00Z",
        "evidence_bundle_ref": evidence_bundle_id,
        "capacity_snapshot_ref": capacity_id,
        "economics_snapshot_ref": economics_id,
        "permit_decision_ref": permit["permit_decision_id"],
        "permitted_next_action": "CREATE_CRM_TASK",
        "decision": "ACCEPTED",
        "reason_codes": list(human["gold_review"]["reason_codes"]),
        "version": 1,
    }
    demand_v2 = {
        **demand_v1,
        "gold_acceptance_ref": gold_id,
        "state": "ACCEPTED_GDO",
        "lawful_next_action_ref": permit["permit_decision_id"],
        "capacity_snapshot_ref": capacity_id,
        "economics_snapshot_ref": economics_id,
        "version": 2,
        "recorded_at": "2026-08-25T09:08:00Z",
    }
    gold_result, demand_accepted = pipeline.commit_gold_acceptance(
        gold_acceptance=gold,
        accepted_demand_unit=demand_v2,
        human_review_ref=gold_review_result.entry_id and gold_review_id,
        permit=permit,
        reviewer_id=str(human["gold_review"]["reviewer_id"]),
        trace_id=trace_id,
    )

    assignment = {
        "schema_version": "1.1.0",
        "assignment_id": "assignment-fixture-bitrix-shadow-001",
        "demand_unit_id": business["demand_unit_id"],
        "action_type": "CREATE_CRM_TASK",
        "eligibility_cohort_id": gold["cohort_id"],
        "treatment_id": "LOCAL_SHADOW_NO_CONTACT",
        "assignment_probability": 1.0,
        "policy_version": permit["policy_version"],
        "offer_content_version": None,
        "permit_decision_ref": permit["permit_decision_id"],
        "permit_decision_sha256": permit_record_sha256(permit),
        "actor_id": "fixture-sales-operator",
        "assigned_at": "2026-08-25T09:09:00Z",
        "capacity_snapshot_ref": capacity_id,
        "cost": 0,
        "currency": "RUB",
        "outcome_window_end": "2026-09-24T09:09:00Z",
        "interference_cluster_id": "fixture-account-cluster-001",
        "status": "APPROVED",
    }
    assignment_result = pipeline.record_action_assignment(
        assignment,
        permit=permit,
        writer_id="fixture-sales-operator",
        trace_id=trace_id,
    )
    projection = ShadowBitrixProjectionAdapter(
        store,
        contracts,
        permits,
        clock=lambda: "2026-08-25T09:09:01Z",
    ).project(
        demand_unit=demand_v2,
        gold_acceptance=gold,
        assignment=assignment,
        permit=permit,
        writer_id="fixture-bitrix-projector",
        trace_id=trace_id,
    )

    terms_id = "commercial-terms-fixture-order-001"
    _internal(
        pipeline,
        record_type="COMMERCIAL_TERMS",
        record_id=terms_id,
        body={
            "approved_fixture_input_ref": human["order_approval"]["sealed_input_sha256"],
            "amount": business["amount"],
            "currency": business["currency"],
            "captured_at": "2026-08-25T09:10:00Z",
        },
        writer_id=str(human["order_approval"]["approver_id"]),
        required_role="ORDER_APPROVER",
        trace_id=trace_id,
        recorded_at="2026-08-25T09:10:00Z",
    )
    order_v1 = _with_digest(
        {
            "schema_version": "1.0.0",
            "distinct_order_id": business["distinct_order_id"],
            "demand_unit_id": business["demand_unit_id"],
            "account_id": business["account_id"],
            "scope_fingerprint": demand_v1["scope_fingerprint"],
            "commercial_terms_ref": terms_id,
            "state": str(human["order_approval"]["decision"]),
            "approved_by": human["order_approval"]["approver_id"],
            "approved_at": "2026-08-25T09:11:00Z",
            "version": 1,
            "payload_sha256": "",
        }
    )
    order_initial = pipeline.record_order(
        order_v1,
        writer_id=str(human["order_approval"]["approver_id"]),
        trace_id=trace_id,
    )

    bank_artifact = dict(fixture["signed_bank_statement_payload"])
    bank_content = canonical_json_bytes(bank_artifact)
    bank_sha = value_sha256(bank_artifact)
    payment_observation = {
        **bank_artifact,
        "source_artifact_sha256": bank_sha,
    }
    payment_intake = pipeline.ingest_payment_observation(
        payment_observation,
        source_content=bank_content,
        writer_id="fixture-bank-adapter",
        reconciler_id="fixture-reconciler",
        trace_id=trace_id,
        recorded_at_utc="2026-08-25T09:12:01Z",
    )
    if payment_intake.status != "READY_FOR_RECONCILIATION":
        raise FixtureSliceError("fixture payment did not resolve to the approved local order")
    payment = {
        "schema_version": "1.0.0",
        "payment_proof_id": "payment-proof-fixture-001",
        "authoritative_class": "SIGNED_BANK_STATEMENT",
        "provider": bank_artifact["provider"],
        "provider_event_id": bank_artifact["provider_event_id"],
        "canonical_account_id": business["account_id"],
        "distinct_order_id": business["distinct_order_id"],
        "payer_identity_ref": business["payer_identity_ref"],
        "recipient_identity_ref": business["recipient_identity_ref"],
        "amount": business["amount"],
        "currency": business["currency"],
        "value_at": bank_artifact["value_at"],
        "source_artifact_sha256": bank_sha,
        "reconciliation_state": human["payment_verification"]["decision"],
        "verified_by": human["payment_verification"]["verifier_id"],
        "verified_at": "2026-08-25T09:13:00Z",
    }
    order_v2 = _with_digest({**order_v1, "state": "PAID", "version": 2, "payload_sha256": ""})
    payment_outcome = _with_digest(
        {
            "schema_version": "1.1.0",
            "outcome_event_id": "outcome-fixture-cleared-payment-001",
            "outcome_type": "CLEARED_PAYMENT",
            "demand_unit_id": business["demand_unit_id"],
            "account_id": business["account_id"],
            "motion": demand_v1["motion"],
            "event_time": bank_artifact["value_at"],
            "recorded_at": "2026-08-25T09:13:01Z",
            "source_system": bank_artifact["provider"],
            "authoritative_class": "SIGNED_BANK_STATEMENT",
            "distinct_order_id": business["distinct_order_id"],
            "payment_proof_ref": payment["payment_proof_id"],
            "amount": business["amount"],
            "cost": None,
            "contribution_margin": None,
            "currency": business["currency"],
            "original_source_ref": signal["event_id"],
            "latest_source_ref": bank_artifact["provider_event_id"],
            "influence_refs": [gold_id],
            "action_assignment_refs": [assignment["assignment_id"]],
            "routing_ref": None,
            "reconciliation_state": "RECONCILED",
            "payload_sha256": "",
        }
    )
    payment_result, order_paid, payment_outcome_result = pipeline.record_payment_and_outcome(
        payment_proof=payment,
        paid_order=order_v2,
        outcome=payment_outcome,
        verifier_id=str(human["payment_verification"]["verifier_id"]),
        reconciler_id="fixture-reconciler",
        trace_id=trace_id,
    )

    fulfilment_artifact = dict(fixture["fulfilment_document_payload"])
    fulfilment_content = canonical_json_bytes(fulfilment_artifact)
    pipeline.ingest_fulfilment_document(
        fulfilment_artifact,
        source_content=fulfilment_content,
        writer_id=str(human["fulfilment_attestation"]["actor_id"]),
        trace_id=trace_id,
        recorded_at_utc="2026-08-25T09:20:00Z",
    )
    fulfilment = {
        "schema_version": "1.0.0",
        "fulfilment_record_id": "fulfilment-fixture-001",
        "distinct_order_id": business["distinct_order_id"],
        "event_type": human["fulfilment_attestation"]["decision"],
        "event_at": "2026-08-25T09:20:00Z",
        "actor_id": human["fulfilment_attestation"]["actor_id"],
        "primary_document_ref": fulfilment_artifact["document_ref"],
        "evidence_sha256": value_sha256(fulfilment_artifact),
        "version": 1,
    }
    order_v3 = _with_digest({**order_v1, "state": "FULFILLED", "version": 3, "payload_sha256": ""})
    fulfilment_outcome = _with_digest(
        {
            "schema_version": "1.1.0",
            "outcome_event_id": "outcome-fixture-fulfilled-001",
            "outcome_type": "FULFILLED",
            "demand_unit_id": business["demand_unit_id"],
            "account_id": business["account_id"],
            "motion": demand_v1["motion"],
            "event_time": fulfilment["event_at"],
            "recorded_at": "2026-08-25T09:20:01Z",
            "source_system": "LOCAL_FULFILMENT_LEDGER",
            "authoritative_class": "FULFILMENT_LEDGER",
            "distinct_order_id": business["distinct_order_id"],
            "payment_proof_ref": payment["payment_proof_id"],
            "amount": business["amount"],
            "cost": None,
            "contribution_margin": None,
            "currency": business["currency"],
            "original_source_ref": signal["event_id"],
            "latest_source_ref": fulfilment["fulfilment_record_id"],
            "influence_refs": [gold_id],
            "action_assignment_refs": [assignment["assignment_id"]],
            "routing_ref": None,
            "reconciliation_state": "RECONCILED",
            "payload_sha256": "",
        }
    )
    fulfilment_result, order_fulfilled, fulfilment_outcome_result = (
        pipeline.record_fulfilment_and_outcome(
            fulfilment=fulfilment,
            fulfilled_order=order_v3,
            outcome=fulfilment_outcome,
            writer_id=str(human["fulfilment_attestation"]["actor_id"]),
            reconciler_id="fixture-reconciler",
            trace_id=trace_id,
        )
    )
    reconciliation = pipeline.reconcile(
        reconciliation_id="reconciliation-fixture-001",
        distinct_order_id=business["distinct_order_id"],
        demand_unit_id=business["demand_unit_id"],
        writer_id="fixture-reconciler",
        trace_id=trace_id,
        recorded_at_utc="2026-08-25T09:21:00Z",
    )

    integrity = store.verify_integrity()
    records = store.records()
    type_counts = Counter(str(record["record_type"]) for record in records)
    return {
        "schema_version": "1.0.0",
        "fixture_id": fixture["fixture_id"],
        "classification": fixture["classification"],
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "canonical_kpi_eligible": False,
        "independent_verification": False,
        "external_effect_count": 0,
        "live_bitrix_write_count": 0,
        "bitrix_shadow_projection_count": len(store.shadow_projections()),
        "projection": {
            "projection_id": projection.projection_id,
            "inserted_on_this_delivery": projection.inserted,
            "mode": projection.mode,
            "command_id": projection.command_id,
            "outbox_outcome": projection.outbox_outcome,
        },
        "reconciliation": {
            "reconciliation_id": reconciliation.reconciliation_id,
            "status": reconciliation.status,
            "canonical_kpi_eligible": reconciliation.canonical_kpi_eligible,
        },
        "record_type_counts": dict(sorted(type_counts.items())),
        "entry_refs": {
            "signal": signal_result.entry_id,
            "claim_proposed": claim_proposed.entry_id,
            "claim_accepted": claim_accepted.entry_id,
            "identity": identity_result.entry_id,
            "demand_initial": demand_initial.entry_id,
            "gold_review": gold_review_result.entry_id,
            "gold": gold_result.entry_id,
            "demand_accepted": demand_accepted.entry_id,
            "assignment": assignment_result.entry_id,
            "order_initial": order_initial.entry_id,
            "payment": payment_result.entry_id,
            "order_paid": order_paid.entry_id,
            "payment_outcome": payment_outcome_result.entry_id,
            "fulfilment": fulfilment_result.entry_id,
            "order_fulfilled": order_fulfilled.entry_id,
            "fulfilment_outcome": fulfilment_outcome_result.entry_id,
            "reconciliation": reconciliation.ledger_entry_id,
        },
        "permit": {
            "permit_decision_id": permit["permit_decision_id"],
            "decision": permit["decision"],
            "record_sha256": permit_record_sha256(permit),
        },
        "integrity": integrity,
    }


__all__ = ["DEFAULT_FIXTURE", "FixtureSliceError", "load_fixture", "run_g1_fixture_slice"]
