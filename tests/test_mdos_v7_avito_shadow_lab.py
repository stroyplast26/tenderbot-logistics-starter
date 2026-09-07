from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import inspect
from pathlib import Path

import pytest

from lead_factory.mdos_v7 import avito_shadow_lab as avito_module
from lead_factory.mdos_v7.avito_shadow_lab import (
    FIXED_COHORT_SIZE,
    AvitoOperation,
    AvitoShadowLabError,
    AvitoShadowTimeline,
    EntitlementStatus,
    TechnicalSupportStatus,
    build_avito_capability_catalog,
    domain_material_sha256,
    run_avito_shadow_lab,
    validate_synthetic_capability_bundle,
    verify_avito_domain_ledger,
)
from lead_factory.mdos_v7.contracts import value_sha256
from lead_factory.mdos_v7.experiment_ledger import (
    EVIDENCE_CLASS,
    EXECUTION_MODE,
    ZERO_EFFECTS,
    ExperimentLedger,
    LedgerRecordType,
)
from lead_factory.mdos_v7.hypothesis_engine import (
    CapabilityStatus,
    EffectClass,
    ExecutionMode,
    LearningStatus,
)


UTC = timezone.utc
T0 = datetime(2026, 2, 1, tzinfo=UTC)


def _sha(label: str) -> str:
    return value_sha256({"avito-shadow-fixture": label})


def _timeline() -> AvitoShadowTimeline:
    return AvitoShadowTimeline(
        observed_at=T0,
        capability_valid_from=T0 + timedelta(hours=1),
        proposed_at=T0 + timedelta(hours=2),
        seed_committed_at=T0 + timedelta(hours=3),
        preregistered_at=T0 + timedelta(hours=4),
        approved_at=T0 + timedelta(hours=5),
        starts_at=T0 + timedelta(hours=6),
        ends_at=T0 + timedelta(hours=7),
        outcome_window_ends_at=T0 + timedelta(hours=8),
        analyzed_at=T0 + timedelta(hours=9),
        decided_at=T0 + timedelta(hours=10),
        capability_valid_until=T0 + timedelta(hours=11),
    )


def _catalog():
    return build_avito_capability_catalog(
        timeline=_timeline(), evidence_root_sha256=_sha("root")
    )


def _ledger(tmp_path: Path) -> ExperimentLedger:
    return ExperimentLedger(tmp_path / "avito-shadow.sqlite3")


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def test_catalog_separates_live_references_synthetic_twins_and_effect_atoms() -> None:
    catalog = _catalog()

    assert len(catalog.pairs) == len(AvitoOperation)
    assert catalog.authority_granted is False
    assert catalog.transport_call_count == 0
    assert catalog.content_sha256
    for pair in catalog.pairs:
        assert pair.rights_transfer is False
        assert pair.live_reference.mode is ExecutionMode.SHADOW
        assert pair.live_reference.capability_status in {
            CapabilityStatus.UNPROVEN,
            CapabilityStatus.UNSUPPORTED,
        }
        assert pair.live_entitlement_status is EntitlementStatus.UNPROVEN
        assert pair.synthetic_offline.mode is ExecutionMode.OFFLINE
        assert pair.synthetic_offline.capability_status is CapabilityStatus.VERIFIED
        assert pair.synthetic_offline.authority_granted is False
        assert (
            pair.synthetic_offline.required_effect_classes
            == pair.live_reference.required_effect_classes
        )

    promotion = catalog.pair(AvitoOperation.PROMOTE_OWN_LISTING)
    ads_create = catalog.pair(AvitoOperation.ADS_CREATE_OR_EDIT)
    ads_budget = catalog.pair(AvitoOperation.ADS_BUDGET_OR_BID_MUTATION)
    ads_activate = catalog.pair(AvitoOperation.ADS_ACTIVATE)
    ads_stats = catalog.pair(AvitoOperation.READ_ADS_STATS)
    assert promotion.live_reference.required_effect_classes == frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    )
    assert ads_create.live_reference.required_effect_classes == frozenset(
        {EffectClass.WRITE}
    )
    assert ads_budget.live_reference.required_effect_classes == frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    )
    assert ads_activate.live_reference.required_effect_classes == frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    )
    assert ads_stats.live_reference.required_effect_classes == frozenset(
        {EffectClass.READ}
    )


def test_new_contact_is_unsupported_and_observation_does_not_transfer_rights() -> None:
    catalog = _catalog()
    start_chat = catalog.pair(AvitoOperation.START_OUTBOUND_CHAT)
    initiate = catalog.pair(AvitoOperation.INITIATE_COLLABORATION_CONTACT)
    reply = catalog.pair(AvitoOperation.REPLY_EXISTING_CHAT)
    observe = catalog.pair(AvitoOperation.OBSERVE_THIRD_PARTY_LISTING)

    assert start_chat.live_reference.capability_status is CapabilityStatus.UNSUPPORTED
    assert initiate.live_reference.capability_status is CapabilityStatus.UNSUPPORTED
    assert (
        initiate.live_technical_status is TechnicalSupportStatus.UNSUPPORTED_UNCONFIRMED
    )
    assert (
        reply.live_technical_status
        is TechnicalSupportStatus.EXISTING_CHAT_REFERENCE_ONLY
    )
    with pytest.raises(AvitoShadowLabError, match="exact synthetic operation set"):
        validate_synthetic_capability_bundle(
            catalog,
            (
                AvitoOperation.OBSERVE_THIRD_PARTY_LISTING,
                AvitoOperation.INITIATE_COLLABORATION_CONTACT,
            ),
            (observe.synthetic_offline,),
        )
    with pytest.raises(AvitoShadowLabError, match="exact synthetic operation set"):
        validate_synthetic_capability_bundle(
            catalog,
            (AvitoOperation.INITIATE_COLLABORATION_CONTACT,),
            (initiate.live_reference,),
        )


def test_three_fixed_cohort_experiments_persist_full_zero_effect_dag(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    timeline = _timeline()
    catalog = _catalog()
    result = run_avito_shadow_lab(
        ledger,
        catalog=catalog,
        timeline=timeline,
        evidence_root_sha256=_sha("root"),
        owner_id="owner-avito-shadow",
    )

    assert result.execution_mode == EXECUTION_MODE
    assert result.evidence_class == EVIDENCE_CLASS
    assert result.canonical_kpi_eligible is False
    assert dict(result.external_effects) == dict(ZERO_EFFECTS)
    assert result.transport_call_count == 0
    assert result.ledger_record_count == len(AvitoOperation) * 2 + 33
    assert {record.record_type for record in ledger.list()} == set(LedgerRecordType)
    assert ledger.verify().record_count == result.ledger_record_count
    assert ledger.snapshot().snapshot_sha256 == result.ledger_snapshot_sha256
    assert all(
        record.execution_mode == EXECUTION_MODE
        and record.evidence_class == EVIDENCE_CLASS
        and dict(record.external_effects) == dict(ZERO_EFFECTS)
        for record in ledger.list()
    )

    inbound = result.inbound_own_listing
    partner = result.partner_collaboration
    ads = result.offline_ads
    assert len(inbound.assignments) == FIXED_COHORT_SIZE
    assert len(partner.assignments) == FIXED_COHORT_SIZE
    assert len(ads.assignments) == FIXED_COHORT_SIZE
    assert {item.cluster_id for item in inbound.assignments} == set(
        inbound.plan.cohort_snapshot.cluster_ids
    )
    assert {item.cluster_id for item in partner.assignments} == set(
        partner.plan.cohort_snapshot.cluster_ids
    )
    assert inbound.decision.status is LearningStatus.KEEP_TESTING
    assert partner.decision.status is LearningStatus.KEEP_TESTING
    assert ads.decision.status is LearningStatus.KEEP_TESTING
    assert inbound.decision.release_eligible is False
    assert partner.decision.auto_scale is False
    assert inbound.analysis.commercial_candidate_variant_ids == ()
    assert partner.analysis.signal_candidate_variant_ids == ()
    assert ads.analysis.signal_candidate_variant_ids == ()
    assert result.observed_learning_eligible is False
    assert result.commercial_proof_eligible is False
    assert result.portfolio_allocation_eligible is False
    assert all(
        experiment.data_origin == "SYNTHETIC_FIXTURE"
        and experiment.proof_scope == "FIXTURE_EXPECTATION_ONLY"
        and experiment.observed_learning_eligible is False
        and experiment.commercial_proof_eligible is False
        and experiment.portfolio_allocation_eligible is False
        for experiment in (inbound, partner, ads)
    )
    assert all(item.external_effect_count == 0 for item in inbound.outcomes)
    assert all(item.observed_contact_count == 0 for item in partner.outcomes)
    assert all(
        cluster_id.startswith("cluster-hmac-v1:")
        for cluster_id in inbound.plan.cohort_snapshot.cluster_ids
    )

    plan_record = next(
        record
        for record in ledger.list(LedgerRecordType.PLAN)
        if any(
            ref["domain_content_sha256"] == inbound.plan.content_sha256
            for ref in record.payload["domain_record_refs"]
        )
    )
    assert plan_record.payload["domain_record_refs"] == (
        {
            "domain_record_kind": "experiment-plan",
            "domain_content_sha256": inbound.plan.content_sha256,
        },
    )
    assert domain_material_sha256(plan_record.payload["domain_records"][0]) == (
        inbound.plan.content_sha256
    )
    assert plan_record.payload["data_origin"] == "SYNTHETIC_FIXTURE"
    assert plan_record.payload["observed_learning_eligible"] is False


def test_exact_replay_is_deterministic_and_does_not_append(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    timeline = _timeline()
    catalog = _catalog()
    first = run_avito_shadow_lab(
        ledger,
        catalog=catalog,
        timeline=timeline,
        evidence_root_sha256=_sha("root"),
        owner_id="owner-avito-shadow",
    )
    first_verification = ledger.verify()
    second = run_avito_shadow_lab(
        ledger,
        catalog=catalog,
        timeline=timeline,
        evidence_root_sha256=_sha("root"),
        owner_id="owner-avito-shadow",
    )

    assert ledger.verify() == first_verification
    assert second.ledger_snapshot_sha256 == first.ledger_snapshot_sha256
    assert second.ledger_semantic_sha256 == first.ledger_semantic_sha256
    assert second.ledger_record_count == first.ledger_record_count
    assert (
        second.inbound_own_listing.ledger_record_ids
        == first.inbound_own_listing.ledger_record_ids
    )
    assert [
        (item.cluster_id, item.bucket_bps, item.variant_id)
        for item in second.partner_collaboration.assignments
    ] == [
        (item.cluster_id, item.bucket_bps, item.variant_id)
        for item in first.partner_collaboration.assignments
    ]
    reopened = ExperimentLedger(ledger.path)
    verification = verify_avito_domain_ledger(reopened)
    assert verification.ledger_record_count == first.ledger_record_count
    assert verification.domain_material_count >= verification.ledger_record_count


def test_reopen_verifier_recomputes_assignment_bucket_and_downstream_dag(
    tmp_path: Path,
) -> None:
    source = ExperimentLedger(tmp_path / "source-avito-shadow.sqlite3")
    run_avito_shadow_lab(
        source,
        catalog=_catalog(),
        timeline=_timeline(),
        evidence_root_sha256=_sha("root"),
        owner_id="owner-avito-shadow",
    )
    resealed = ExperimentLedger(tmp_path / "resealed-avito-shadow.sqlite3")
    cloned_by_id = {}
    old_assignment_sha256: str | None = None
    new_assignment_sha256: str | None = None
    for record in source.list():
        payload = _thaw(record.payload)
        assert isinstance(payload, dict)
        domain_kind = payload.get("domain_kind")
        if domain_kind == "INBOUND_OWN_LISTING:assignments:active":
            materials = payload["domain_records"]
            refs = payload["domain_record_refs"]
            assert isinstance(materials, list) and isinstance(refs, list)
            material = materials[0]
            ref = refs[0]
            assert isinstance(material, dict) and isinstance(ref, dict)
            assignment = material["payload"]
            assert isinstance(assignment, dict)
            old_assignment_sha256 = ref["domain_content_sha256"]
            bucket = assignment["bucket_bps"]
            assert isinstance(bucket, int)
            assignment["bucket_bps"] = (bucket + 1) % 10_000
            new_assignment_sha256 = value_sha256(material)
            ref["domain_content_sha256"] = new_assignment_sha256
        elif domain_kind == "INBOUND_OWN_LISTING:outcomes:active":
            assert old_assignment_sha256 is not None
            assert new_assignment_sha256 is not None
            materials = payload["domain_records"]
            refs = payload["domain_record_refs"]
            assert isinstance(materials, list) and isinstance(refs, list)
            for material, ref in zip(materials, refs, strict=True):
                assert isinstance(material, dict) and isinstance(ref, dict)
                outcome = material["payload"]
                assert isinstance(outcome, dict)
                if outcome["assignment_sha256"] == old_assignment_sha256:
                    outcome["assignment_sha256"] = new_assignment_sha256
                    ref["domain_content_sha256"] = value_sha256(material)
        dependencies = tuple(
            cloned_by_id[item.record_id] for item in record.dependencies
        )
        cloned_by_id[record.record_id] = resealed.append(
            record.record_type,
            payload,
            dependencies=dependencies,
            idempotency_key=record.idempotency_key,
        )

    assert old_assignment_sha256 is not None
    assert new_assignment_sha256 is not None
    assert resealed.verify().record_count == source.verify().record_count
    with pytest.raises(AvitoShadowLabError, match="deterministic plan result"):
        verify_avito_domain_ledger(ExperimentLedger(resealed.path))


def test_reopen_verifier_rejects_domain_ref_material_mismatch(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "bad-avito-domain.sqlite3")
    capability = _catalog().pairs[0].synthetic_offline
    material = capability.material()
    tampered = {
        **material,
        "payload": {**material["payload"], "action": "TAMPERED_SYNTHETIC_ACTION"},
    }
    ledger.append(
        LedgerRecordType.CAPABILITY,
        {
            "avito_shadow_schema_version": "1.0.0",
            "domain_kind": "tampered-fixture",
            "domain_record_count": 1,
            "domain_record_refs": [
                {
                    "domain_record_kind": capability.record_kind,
                    "domain_content_sha256": capability.content_sha256,
                }
            ],
            "domain_records": [tampered],
            "data_origin": "SYNTHETIC_FIXTURE",
            "observed_learning_eligible": False,
            "commercial_proof_eligible": False,
            "portfolio_allocation_eligible": False,
            "mode": EXECUTION_MODE,
            "canonical_kpi_eligible": False,
            "external_effect_count": 0,
            "transport_call_count": 0,
        },
        idempotency_key="avito-shadow/tampered/capability/v1",
    )
    assert ledger.verify().record_count == 1
    reopened = ExperimentLedger(ledger.path)
    with pytest.raises(AvitoShadowLabError, match="digest or type mismatch"):
        verify_avito_domain_ledger(reopened)

    wrong_type_ledger = ExperimentLedger(tmp_path / "wrong-domain-type.sqlite3")
    wrong_type_ledger.append(
        LedgerRecordType.HYPOTHESIS,
        {
            "avito_shadow_schema_version": "1.0.0",
            "domain_kind": "wrong-type-fixture",
            "domain_record_count": 1,
            "domain_record_refs": [
                {
                    "domain_record_kind": capability.record_kind,
                    "domain_content_sha256": capability.content_sha256,
                }
            ],
            "domain_records": [material],
            "data_origin": "SYNTHETIC_FIXTURE",
            "observed_learning_eligible": False,
            "commercial_proof_eligible": False,
            "portfolio_allocation_eligible": False,
            "mode": EXECUTION_MODE,
            "canonical_kpi_eligible": False,
            "external_effect_count": 0,
            "transport_call_count": 0,
        },
        idempotency_key="avito-shadow/wrong-type/hypothesis/v1",
    )
    with pytest.raises(AvitoShadowLabError, match="digest or type mismatch"):
        verify_avito_domain_ledger(ExperimentLedger(wrong_type_ledger.path))

    partial_ledger = ExperimentLedger(tmp_path / "partial-avito-domain.sqlite3")
    partial_ledger.append(
        LedgerRecordType.CAPABILITY,
        {
            "avito_shadow_schema_version": "1.0.0",
            "domain_kind": (
                "avito-capability:synthetic-offline:"
                f"{AvitoOperation.OBSERVE_THIRD_PARTY_LISTING.value}"
            ),
            "domain_record_count": 1,
            "domain_record_refs": [
                {
                    "domain_record_kind": capability.record_kind,
                    "domain_content_sha256": capability.content_sha256,
                }
            ],
            "domain_records": [material],
            "data_origin": "SYNTHETIC_FIXTURE",
            "observed_learning_eligible": False,
            "commercial_proof_eligible": False,
            "portfolio_allocation_eligible": False,
            "mode": EXECUTION_MODE,
            "canonical_kpi_eligible": False,
            "external_effect_count": 0,
            "transport_call_count": 0,
        },
        idempotency_key="avito-shadow/partial/capability/v1",
    )
    with pytest.raises(AvitoShadowLabError, match="complete exact"):
        verify_avito_domain_ledger(ExperimentLedger(partial_ledger.path))


def test_lab_rejects_pii_shaped_actor_and_has_no_transport_surface(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    catalog = _catalog()
    with pytest.raises(AvitoShadowLabError, match="non-PII opaque"):
        run_avito_shadow_lab(
            ledger,
            catalog=catalog,
            timeline=_timeline(),
            evidence_root_sha256=_sha("root"),
            owner_id="79990001122",
        )
    assert ledger.verify().record_count == 0

    parameters = inspect.signature(run_avito_shadow_lab).parameters
    assert not {
        "transport",
        "credentials",
        "api_key",
        "access_token",
        "live",
        "network",
    }.intersection(parameters)
    assert not {
        "requests",
        "socket",
        "urllib",
        "httpx",
    }.intersection(avito_module.__dict__)


def test_timeline_requires_explicit_utc_and_strict_order() -> None:
    timeline = _timeline()
    with pytest.raises(AvitoShadowLabError, match="explicit UTC"):
        AvitoShadowTimeline(
            **{
                **{
                    name: getattr(timeline, name)
                    for name in timeline.__dataclass_fields__
                },
                "observed_at": datetime(2026, 2, 1),
            }
        )
    with pytest.raises(AvitoShadowLabError, match="strictly increasing"):
        AvitoShadowTimeline(
            **{
                name: (
                    timeline.starts_at
                    if name == "approved_at"
                    else getattr(timeline, name)
                )
                for name in timeline.__dataclass_fields__
            }
        )
