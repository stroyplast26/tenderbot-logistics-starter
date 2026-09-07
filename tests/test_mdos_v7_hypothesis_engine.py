from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from lead_factory.mdos_v7.contracts import value_sha256
from lead_factory.mdos_v7.hypothesis_engine import (
    ASSIGNMENT_DENOMINATOR_BPS,
    CapabilityStatus,
    ClusterAssignment,
    CohortSnapshot,
    EffectClass,
    ExecutionMode,
    ExperimentOutcome,
    ExperimentPlan,
    ExperimentVariant,
    ExplorationMandate,
    HypothesisEngineError,
    HypothesisVersion,
    LearningStatus,
    PlatformCapabilityVersion,
    ProposerKind,
    TreatmentVersion,
    analyze_experiment,
    assign_all_clusters,
    assign_cluster,
    eligibility_cohort_sha256,
    make_learning_decision,
    method_fingerprint_sha256,
)


UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _sha(label: str) -> str:
    return value_sha256({"fixture": label})


def _capability(
    capability_id: str,
    action: str,
    effect_class: EffectClass,
) -> PlatformCapabilityVersion:
    return PlatformCapabilityVersion(
        platform_id="avito",
        capability_id=capability_id,
        version=1,
        action=action,
        object_type="listing",
        source_role="DISCOVERY" if effect_class is EffectClass.READ else "ACTION",
        required_effect_classes=frozenset({effect_class}),
        capability_status=CapabilityStatus.VERIFIED,
        terms_evidence_sha256=_sha(f"terms-{capability_id}"),
        operation_contract_sha256=_sha(f"operation-contract-{capability_id}"),
        status_evidence_sha256=_sha(f"status-{capability_id}"),
        observed_at=T0,
        valid_from=T0 + timedelta(days=1),
        valid_until=T0 + timedelta(days=10),
        mode=ExecutionMode.SHADOW,
    )


def _plan(*, minimum_clusters: int = 10) -> ExperimentPlan:
    read_listing = _capability("read-listing", "READ_LISTING", EffectClass.READ)
    contact_seller = _capability(
        "contact-seller",
        "CONTACT_SELLER",
        EffectClass.CONTACT,
    )
    capability_shas = (read_listing.content_sha256, contact_seller.content_sha256)
    mandate = ExplorationMandate(
        mandate_id="mandate-avito-shadow",
        version=1,
        scope_id="scope-aluminium-moscow",
        capability_sha256s=capability_shas,
        allowed_effect_classes=frozenset({EffectClass.READ, EffectClass.CONTACT}),
        currency="RUB",
        budget_cap_minor=20_000,
        contact_cap=100,
        capacity_cap=200,
        minimum_holdout_bps=2_000,
        approved_by="owner-001",
        approved_at=T0,
        approval_evidence_sha256=_sha("mandate-approval"),
        valid_from=T0 + timedelta(days=1),
        valid_until=T0 + timedelta(days=10),
        mode=ExecutionMode.SHADOW,
    )
    hypothesis = HypothesisVersion(
        hypothesis_id="hypothesis-avito-partners",
        version=1,
        statement="Seller listings identify partners with incremental accepted GDO.",
        falsification_rule="Reject if accepted-GDO rate does not exceed holdout.",
        causal_mechanism="A bounded partner treatment changes accepted-GDO incidence.",
        causal_mechanism_sha256=_sha("partner-treatment-causal-mechanism-v1"),
        assumption_sha256s=(_sha("stable-partner-demand-assumption"),),
        unit_of_randomization="seller-account",
        scope_id=mandate.scope_id,
        scope_definition_sha256=_sha("aluminium-moscow-scope-v1"),
        audience_definition_sha256=_sha("avito-seller-audience-v1"),
        capability_sha256s=capability_shas,
        proposed_by="ai-planner-001",
        proposer_kind=ProposerKind.AI,
        proposed_at=T0 + timedelta(hours=1),
    )
    control = TreatmentVersion(
        treatment_id="no-treatment",
        version=1,
        treatment_label="No treatment holdout",
        description="Observe the assigned cluster without contact or spend.",
        mechanism_sha256=_sha("no-treatment-mechanism-v1"),
        capability_sha256s=(),
        effect_classes=frozenset(),
        proposed_by="analyst-001",
        proposer_kind=ProposerKind.HUMAN,
        proposed_at=T0 + timedelta(hours=1),
        is_no_treatment_control=True,
    )
    treatment = TreatmentVersion(
        treatment_id="partner-offer",
        version=1,
        treatment_label="Bounded partner offer",
        description="Shadow-plan a collaboration offer after listing discovery.",
        mechanism_sha256=_sha("partner-offer-mechanism-v1"),
        capability_sha256s=capability_shas,
        effect_classes=frozenset({EffectClass.READ, EffectClass.CONTACT}),
        proposed_by="ai-planner-001",
        proposer_kind=ProposerKind.AI,
        proposed_at=T0 + timedelta(hours=1),
    )
    cluster_ids = tuple(
        sorted(f"cluster-hmac-v1:{_sha(f'seller-{index:04d}')}" for index in range(100))
    )
    cohort = CohortSnapshot(
        cohort_id="cohort-avito-sellers",
        unit_of_randomization=hypothesis.unit_of_randomization,
        cluster_ids=cluster_ids,
        eligibility_policy_sha256=_sha("eligibility-policy"),
        source_snapshot_sha256=_sha("eligible-source-snapshot"),
        sealed_by="analyst-002",
        sealed_at=T0 + timedelta(hours=1),
        membership_sha256=eligibility_cohort_sha256(
            unit_of_randomization=hypothesis.unit_of_randomization,
            cluster_ids=cluster_ids,
        ),
        pseudonymization_key_version="fixture-key-v1",
        pseudonymization_evidence_sha256=_sha("pseudonymization-attestation"),
    )
    variants = (
        ExperimentVariant(
            variant_id="control",
            treatment_sha256=control.content_sha256,
            allocation_bps=3_000,
            budget_cap_minor=0,
            contact_cap=0,
            capacity_cap=100,
            is_control=True,
        ),
        ExperimentVariant(
            variant_id="partner-offer",
            treatment_sha256=treatment.content_sha256,
            allocation_bps=7_000,
            budget_cap_minor=10_000,
            contact_cap=100,
            capacity_cap=100,
        ),
    )
    return ExperimentPlan(
        plan_id="experiment-avito-partners",
        version=1,
        mandate=mandate,
        hypothesis=hypothesis,
        capabilities=(read_listing, contact_seller),
        treatments=(control, treatment),
        variants=variants,
        cohort_snapshot=cohort,
        analysis_plan_sha256=_sha("preregistered-analysis-plan"),
        outcome_identity_policy_sha256=_sha("outcome-identity-policy-v1"),
        outcome_pseudonymization_key_version="outcome-fixture-key-v1",
        outcome_pseudonymization_evidence_sha256=_sha(
            "outcome-pseudonymization-policy-v1"
        ),
        guardrail_ids=("complaint", "capacity-overload"),
        stop_rule_ids=("stop-on-complaint", "stop-on-cap"),
        assignment_seed_sha256=_sha("assignment-seed"),
        assignment_seed_source="independent-fixture-custodian",
        assignment_seed_evidence_sha256=_sha("assignment-seed-evidence"),
        seed_committed_by="seed-custodian-001",
        seed_committed_at=T0 + timedelta(hours=1),
        preregistered_at=T0 + timedelta(hours=2),
        approved_at=T0 + timedelta(hours=3),
        starts_at=T0 + timedelta(days=1, hours=1),
        ends_at=T0 + timedelta(days=3),
        outcome_window_ends_at=T0 + timedelta(days=5),
        minimum_clusters_per_variant=minimum_clusters,
        confidence_z_milli=1_645,
        minimum_signal_lift_bps=1,
        minimum_paid_lift_bps=1,
        minimum_net_contribution_lift_minor_per_cluster=1,
        budget_cap_minor=10_000,
        contact_cap=100,
        capacity_cap=200,
        approved_by="owner-001",
        approval_evidence_sha256=_sha("plan-approval"),
        mode=ExecutionMode.SHADOW,
    )


def _balanced_assignments(plan: ExperimentPlan) -> tuple[ClusterAssignment, ...]:
    assignments = assign_all_clusters(plan, assigned_at=plan.starts_at)
    assert {item.cluster_id for item in assignments} == set(
        plan.cohort_snapshot.cluster_ids
    )
    return assignments


def _outcome(
    plan: ExperimentPlan,
    assignment: ClusterAssignment,
    *,
    ordinal: int,
    complete: bool = True,
) -> ExperimentOutcome:
    is_treatment = assignment.variant_id == "partner-offer"
    return ExperimentOutcome(
        plan_sha256=plan.content_sha256,
        assignment_sha256=assignment.content_sha256,
        cluster_id=assignment.cluster_id,
        variant_id=assignment.variant_id,
        measured_at=plan.outcome_window_ends_at,
        outcome_window_ends_at=plan.outcome_window_ends_at,
        data_cutoff_at=plan.outcome_window_ends_at,
        outcome_source_snapshot_sha256=_sha(f"outcome-source-{ordinal}"),
        outcome_identity_policy_sha256=plan.outcome_identity_policy_sha256,
        pseudonymization_key_version=plan.outcome_pseudonymization_key_version,
        pseudonymization_evidence_sha256=(
            plan.outcome_pseudonymization_evidence_sha256
        ),
        window_complete=complete,
        accepted_gdo_ids=(f"gdo-hmac-v1:{_sha(f'gdo-{ordinal}')}",)
        if is_treatment
        else (),
        paid_order_ids=(f"order-hmac-v1:{_sha(f'order-{ordinal}')}",)
        if is_treatment
        else (),
        contribution_minor=1_000 if is_treatment else 0,
        observed_spend_minor=100 if is_treatment else 0,
        observed_contact_count=1 if is_treatment else 0,
        observed_capacity_units=1 if is_treatment else 0,
        evidence_sha256s=(_sha(f"outcome-{ordinal}"),),
        payment_evidence_sha256s=(_sha(f"payment-{ordinal}"),) if is_treatment else (),
        contribution_evidence_sha256s=(_sha(f"contribution-{ordinal}"),)
        if is_treatment
        else (),
        guardrail_breach_codes=(),
    )


def test_capabilities_are_atomic_content_addressed_and_never_authority() -> None:
    read_listing = _capability("read-listing", "READ_LISTING", EffectClass.READ)
    contact_seller = _capability(
        "contact-seller", "CONTACT_SELLER", EffectClass.CONTACT
    )

    assert read_listing.content_sha256 == value_sha256(read_listing.material())
    assert read_listing.material()["schema_version"] == "1.3.0"
    assert read_listing.material()["record_kind"] == "platform-capability"
    assert read_listing.content_sha256 != contact_seller.content_sha256
    assert read_listing.required_effect_classes == frozenset({EffectClass.READ})
    assert contact_seller.required_effect_classes == frozenset({EffectClass.CONTACT})
    assert read_listing.authority_granted is False
    assert read_listing.external_effect_count == 0
    with pytest.raises(FrozenInstanceError):
        read_listing.action = "CONTACT_SELLER"  # type: ignore[misc]
    with pytest.raises(TypeError):
        PlatformCapabilityVersion(
            platform_id="avito",
            capability_id="unsafe",
            version=1,
            action="CONTACT_SELLER",
            object_type="listing",
            source_role="ACTION",
            required_effect_classes=frozenset({EffectClass.CONTACT}),
            capability_status=CapabilityStatus.VERIFIED,
            terms_evidence_sha256=_sha("terms"),
            operation_contract_sha256=_sha("unsafe-operation-contract"),
            status_evidence_sha256=_sha("status"),
            valid_from=T0 + timedelta(days=1),
            valid_until=T0 + timedelta(days=2),
            observed_at=T0,
            authority_granted=True,  # type: ignore[call-arg]
        )


def test_plan_is_exact_human_bounded_and_has_one_holdout() -> None:
    plan = _plan()

    assert plan.hypothesis.proposer_kind is ProposerKind.AI
    assert plan.hypothesis.proposal_only is True
    assert plan.approver_kind == "HUMAN"
    assert plan.external_authority_granted is False
    assert plan.auto_live is False
    assert sum(variant.allocation_bps for variant in plan.variants) == 10_000
    assert [variant.variant_id for variant in plan.variants if variant.is_control] == [
        "control"
    ]

    with pytest.raises(HypothesisEngineError, match="sum exactly"):
        replace(
            plan,
            variants=(
                replace(plan.variants[0], allocation_bps=2_999),
                plan.variants[1],
            ),
        )
    with pytest.raises(HypothesisEngineError, match="exactly one control"):
        replace(
            plan,
            variants=(
                replace(plan.variants[0], is_control=False),
                plan.variants[1],
            ),
        )
    with pytest.raises(HypothesisEngineError, match="integer"):
        replace(plan, contact_cap=True)  # type: ignore[arg-type]


def test_assignment_is_stable_order_independent_and_logs_propensity() -> None:
    plan = _plan()
    timestamp = plan.starts_at + timedelta(minutes=1)
    stable_cluster = plan.cohort_snapshot.cluster_ids[0]
    first = assign_cluster(plan, cluster_id=stable_cluster, assigned_at=timestamp)
    second = assign_cluster(plan, cluster_id=stable_cluster, assigned_at=timestamp)
    assignments = {
        cluster_id: assign_cluster(plan, cluster_id=cluster_id, assigned_at=timestamp)
        for cluster_id in plan.cohort_snapshot.cluster_ids[:3]
    }
    reverse = {
        cluster_id: assign_cluster(plan, cluster_id=cluster_id, assigned_at=timestamp)
        for cluster_id in reversed(plan.cohort_snapshot.cluster_ids[:3])
    }

    assert first == second
    assert assignments == reverse
    variant = next(
        item for item in plan.variants if item.variant_id == first.variant_id
    )
    assert first.propensity_numerator == variant.allocation_bps
    assert first.propensity_denominator == ASSIGNMENT_DENOMINATOR_BPS
    assert 0 <= first.bucket_bps < ASSIGNMENT_DENOMINATOR_BPS
    with pytest.raises(HypothesisEngineError, match="follow preregistration"):
        assign_cluster(
            plan,
            cluster_id=stable_cluster,
            assigned_at=plan.preregistered_at,
        )
    with pytest.raises(HypothesisEngineError, match="sealed eligibility cohort"):
        assign_cluster(
            plan,
            cluster_id=f"cluster-hmac-v1:{_sha('seller-not-eligible')}",
            assigned_at=timestamp,
        )


def test_randomization_design_ignores_approval_metadata_but_not_seed() -> None:
    plan = _plan()
    changed_approval = replace(
        plan,
        approved_at=plan.approved_at + timedelta(minutes=1),
        approval_evidence_sha256=_sha("changed-plan-approval-evidence"),
    )
    assert changed_approval.content_sha256 != plan.content_sha256
    assert changed_approval.assignment_design_sha256 == plan.assignment_design_sha256
    original = assign_all_clusters(plan, assigned_at=plan.starts_at)
    replay = assign_all_clusters(
        changed_approval, assigned_at=changed_approval.starts_at
    )
    assert [
        (item.cluster_id, item.bucket_bps, item.variant_id) for item in original
    ] == [(item.cluster_id, item.bucket_bps, item.variant_id) for item in replay]

    changed_seed = replace(
        plan,
        assignment_seed_sha256=_sha("different-independent-seed"),
        assignment_seed_evidence_sha256=_sha("different-seed-evidence"),
    )
    assert changed_seed.assignment_design_sha256 != plan.assignment_design_sha256
    changed_assignments = assign_all_clusters(
        changed_seed, assigned_at=changed_seed.starts_at
    )
    assert any(
        left.bucket_bps != right.bucket_bps
        for left, right in zip(original, changed_assignments, strict=True)
    )

    cosmetic_hypothesis = replace(
        plan.hypothesis,
        hypothesis_id="cosmetic-hypothesis-id",
        version=99,
        statement="Cosmetic punctuation changed!",
        falsification_rule="Cosmetic prose changed; machine semantics did not.",
        causal_mechanism="Cosmetic explanation changed.",
        proposed_by="different-ai-label",
    )
    cosmetic_control = replace(
        plan.treatments[0],
        treatment_id="cosmetic-control-id",
        version=99,
        treatment_label="Cosmetic control label",
        description="Cosmetic control prose.",
    )
    cosmetic_active = replace(
        plan.treatments[1],
        treatment_id="cosmetic-active-id",
        version=99,
        treatment_label="Cosmetic active label",
        description="Cosmetic active prose.",
    )
    cosmetic_variants = (
        replace(
            plan.variants[0],
            variant_id="cosmetic-holdout-label",
            treatment_sha256=cosmetic_control.content_sha256,
        ),
        replace(
            plan.variants[1],
            variant_id="cosmetic-active-label",
            treatment_sha256=cosmetic_active.content_sha256,
        ),
    )
    cosmetic_plan = replace(
        plan,
        hypothesis=cosmetic_hypothesis,
        treatments=(cosmetic_control, cosmetic_active),
        variants=cosmetic_variants,
    )
    assert cosmetic_plan.assignment_design_sha256 == plan.assignment_design_sha256
    cosmetic_assignments = assign_all_clusters(
        cosmetic_plan, assigned_at=cosmetic_plan.starts_at
    )
    assert [item.bucket_bps for item in cosmetic_assignments] == [
        item.bucket_bps for item in original
    ]


def test_randomization_design_binds_ordered_arm_capability_semantics() -> None:
    plan = _plan()
    control = plan.treatments[0]
    base_active = plan.treatments[1]
    read_capability, contact_capability = plan.capabilities
    shared_mechanism = _sha("shared-arm-mechanism")
    read_treatment = replace(
        base_active,
        treatment_id="read-arm",
        treatment_label="Read arm",
        description="Cosmetic read-arm description.",
        mechanism_sha256=shared_mechanism,
        capability_sha256s=(read_capability.content_sha256,),
        effect_classes=frozenset({EffectClass.READ}),
    )
    contact_treatment = replace(
        base_active,
        treatment_id="contact-arm",
        treatment_label="Contact arm",
        description="Cosmetic contact-arm description.",
        mechanism_sha256=shared_mechanism,
        capability_sha256s=(contact_capability.content_sha256,),
        effect_classes=frozenset({EffectClass.CONTACT}),
    )
    control_variant = replace(
        plan.variants[0],
        allocation_bps=3_000,
        capacity_cap=100,
    )
    read_variant = ExperimentVariant(
        variant_id="read-arm",
        treatment_sha256=read_treatment.content_sha256,
        allocation_bps=3_500,
        budget_cap_minor=5_000,
        contact_cap=50,
        capacity_cap=50,
    )
    contact_variant = ExperimentVariant(
        variant_id="contact-arm",
        treatment_sha256=contact_treatment.content_sha256,
        allocation_bps=3_500,
        budget_cap_minor=5_000,
        contact_cap=50,
        capacity_cap=50,
    )
    ordered = replace(
        plan,
        treatments=(control, read_treatment, contact_treatment),
        variants=(control_variant, read_variant, contact_variant),
    )
    swapped = replace(
        ordered,
        variants=(control_variant, contact_variant, read_variant),
    )

    assert ordered.assignment_design_sha256 != swapped.assignment_design_sha256
    ordered_assignments = assign_all_clusters(ordered, assigned_at=ordered.starts_at)
    swapped_assignments = assign_all_clusters(swapped, assigned_at=swapped.starts_at)
    assert any(
        left.bucket_bps != right.bucket_bps
        for left, right in zip(ordered_assignments, swapped_assignments, strict=True)
    )


def test_method_fingerprint_ignores_cosmetics_but_binds_machine_assumptions() -> None:
    plan = _plan()
    original = method_fingerprint_sha256(
        plan.hypothesis, plan.treatments, plan.capabilities
    )
    cosmetic_hypothesis = replace(
        plan.hypothesis,
        hypothesis_id="renamed-hypothesis",
        version=77,
        statement="Same machine method; different display sentence.",
        falsification_rule="Cosmetic punctuation only!",
        causal_mechanism="Different explanatory prose.",
        proposed_by="different-author-label",
        proposed_at=plan.hypothesis.proposed_at + timedelta(seconds=1),
    )
    cosmetic_treatments = tuple(
        replace(
            item,
            treatment_id=f"renamed-{index}",
            version=88,
            treatment_label=f"Display label {index}",
            description=f"Display prose {index}.",
        )
        for index, item in enumerate(plan.treatments)
    )
    assert (
        method_fingerprint_sha256(
            cosmetic_hypothesis,
            cosmetic_treatments,
            plan.capabilities,
        )
        == original
    )
    changed_assumption = replace(
        plan.hypothesis,
        assumption_sha256s=(_sha("materially-different-assumption"),),
    )
    assert (
        method_fingerprint_sha256(
            changed_assumption,
            plan.treatments,
            plan.capabilities,
        )
        != original
    )
    changed_treatment = replace(
        plan.treatments[1],
        mechanism_sha256=_sha("materially-different-treatment-mechanism"),
    )
    assert (
        method_fingerprint_sha256(
            plan.hypothesis,
            (plan.treatments[0], changed_treatment),
            plan.capabilities,
        )
        != original
    )


def test_analysis_uses_unique_gdo_and_paid_contribution_for_commercial_proof() -> None:
    plan = _plan()
    assignments = _balanced_assignments(plan)
    outcomes = tuple(
        _outcome(plan, assignment, ordinal=index)
        for index, assignment in enumerate(assignments)
    )

    analysis = analyze_experiment(
        plan,
        assignments,
        outcomes,
        analyzed_at=plan.outcome_window_ends_at + timedelta(seconds=1),
    )

    treatment = next(
        metric for metric in analysis.metrics if metric.variant_id == "partner-offer"
    )
    assert treatment.unique_accepted_gdo == treatment.assigned_clusters
    assert treatment.paid_orders == treatment.assigned_clusters
    assert analysis.signal_candidate_variant_ids == ("partner-offer",)
    assert analysis.commercial_candidate_variant_ids == ("partner-offer",)
    assert analysis.causal_estimate_eligible is True
    assert analysis.attribution_is_causal_proof is False
    decision = make_learning_decision(
        analysis=analysis,
        plan=plan,
        assignments=assignments,
        outcomes=outcomes,
        status=LearningStatus.COMMERCIAL_CANDIDATE,
        selected_variant_ids=("partner-offer",),
        rationale="Verified paid and net-contribution lift over the holdout.",
        decided_by="owner-001",
        decided_at=analysis.analyzed_at,
        decision_evidence_sha256=_sha("commercial-decision"),
    )
    assert decision.status is LearningStatus.COMMERCIAL_CANDIDATE
    assert decision.proof_scope == "OFFLINE_SHADOW_LEARNING_ONLY"
    assert decision.release_eligible is False
    assert decision.auto_scale is False
    assert decision.external_authority_granted is False


def test_missing_outcome_remains_in_itt_and_cannot_be_promoted() -> None:
    plan = _plan()
    assignments = _balanced_assignments(plan)
    outcomes = tuple(
        _outcome(plan, assignment, ordinal=index)
        for index, assignment in enumerate(assignments[:-1])
    )

    analysis = analyze_experiment(
        plan,
        assignments,
        outcomes,
        analyzed_at=plan.outcome_window_ends_at + timedelta(days=1),
    )

    assert sum(metric.assigned_clusters for metric in analysis.metrics) == len(
        assignments
    )
    assert sum(metric.completed_clusters for metric in analysis.metrics) == len(
        outcomes
    )
    assert analysis.outcome_window_complete is False
    assert analysis.causal_estimate_eligible is False
    assert analysis.signal_candidate_variant_ids == ()
    assert analysis.commercial_candidate_variant_ids == ()
    with pytest.raises(HypothesisEngineError, match="unique-GDO lift"):
        make_learning_decision(
            analysis=analysis,
            plan=plan,
            assignments=assignments,
            outcomes=outcomes,
            status=LearningStatus.SIGNAL_CANDIDATE,
            selected_variant_ids=("partner-offer",),
            rationale="Unsafe premature promotion.",
            decided_by="ai-planner-001",
            decided_at=analysis.analyzed_at,
            decision_evidence_sha256=_sha("unsafe-decision"),
        )
    keep_testing = make_learning_decision(
        analysis=analysis,
        plan=plan,
        assignments=assignments,
        outcomes=outcomes,
        status=LearningStatus.KEEP_TESTING,
        selected_variant_ids=(),
        rationale="Outcome window is incomplete; retain the preregistered holdout.",
        decided_by="owner-001",
        decided_at=analysis.analyzed_at,
        decision_evidence_sha256=_sha("keep-testing"),
    )
    assert keep_testing.status is LearningStatus.KEEP_TESTING


def test_analysis_rejects_cluster_reassignment_and_cap_overrun() -> None:
    plan = _plan()
    assignments = _balanced_assignments(plan)
    assignment = assignments[0]
    with pytest.raises(HypothesisEngineError, match="assigned only once"):
        analyze_experiment(
            plan,
            (assignment, assignment),
            (),
            analyzed_at=plan.outcome_window_ends_at,
        )

    treatment_assignment = next(
        item for item in assignments if item.variant_id == "partner-offer"
    )
    outcome = replace(
        _outcome(plan, treatment_assignment, ordinal=1),
        observed_contact_count=plan.variants[1].contact_cap + 1,
    )
    with pytest.raises(HypothesisEngineError, match="exceeds"):
        analyze_experiment(
            plan,
            assignments,
            (outcome,),
            analyzed_at=plan.outcome_window_ends_at,
        )


def test_timestamps_and_nested_collections_are_strict() -> None:
    capability = _capability("read-listing", "READ_LISTING", EffectClass.READ)
    with pytest.raises(HypothesisEngineError, match="explicit UTC"):
        replace(capability, observed_at=datetime(2026, 1, 1))
    with pytest.raises(HypothesisEngineError, match="must be a tuple"):
        ExplorationMandate(
            mandate_id="bad-mandate",
            version=1,
            scope_id="scope",
            capability_sha256s=[capability.content_sha256],  # type: ignore[arg-type]
            allowed_effect_classes=frozenset({EffectClass.READ}),
            currency="RUB",
            budget_cap_minor=0,
            contact_cap=0,
            capacity_cap=1,
            minimum_holdout_bps=1_000,
            valid_from=T0 + timedelta(days=1),
            valid_until=T0 + timedelta(days=2),
            approved_by="owner",
            approved_at=T0,
            approval_evidence_sha256=_sha("approval"),
        )
    plan = _plan()
    with pytest.raises(HypothesisEngineError, match="cluster-hmac-v1"):
        replace(
            plan.cohort_snapshot,
            cluster_ids=("cluster-hmac-v1:79990001122",),
            membership_sha256=_sha("unsafe-membership"),
        )
    with pytest.raises(HypothesisEngineError, match="sealed before assignment seed"):
        replace(
            plan,
            cohort_snapshot=replace(
                plan.cohort_snapshot,
                sealed_at=plan.seed_committed_at + timedelta(seconds=1),
            ),
        )

    treatment_assignment = next(
        item
        for item in _balanced_assignments(plan)
        if item.variant_id == "partner-offer"
    )
    with pytest.raises(HypothesisEngineError, match="cluster-hmac-v1"):
        replace(treatment_assignment, cluster_id="79991234567")
    outcome = _outcome(plan, treatment_assignment, ordinal=1)
    with pytest.raises(HypothesisEngineError, match="cluster-hmac-v1"):
        replace(outcome, cluster_id="79991234567")
    with pytest.raises(HypothesisEngineError, match="gdo-hmac-v1"):
        replace(outcome, accepted_gdo_ids=("79991234567",))
    with pytest.raises(HypothesisEngineError, match="order-hmac-v1"):
        replace(outcome, paid_order_ids=("79991234567",))
    with pytest.raises(HypothesisEngineError, match="cluster-hmac-v1"):
        replace(treatment_assignment, cluster_id="79991234567")
    with pytest.raises(HypothesisEngineError, match="cluster-hmac-v1"):
        replace(outcome, cluster_id="79991234567")


def test_analysis_rejects_mixed_outcome_pseudonymization_versions() -> None:
    plan = _plan()
    assignments = _balanced_assignments(plan)
    outcomes = tuple(
        _outcome(plan, assignment, ordinal=index)
        for index, assignment in enumerate(assignments)
    )
    changed_index = next(
        index
        for index, outcome in enumerate(outcomes)
        if outcome.variant_id == "partner-offer"
    )
    mixed = (
        *outcomes[:changed_index],
        replace(
            outcomes[changed_index],
            pseudonymization_key_version="outcome-fixture-key-v2",
            pseudonymization_evidence_sha256=_sha("outcome-pseudonymization-policy-v2"),
        ),
        *outcomes[changed_index + 1 :],
    )

    with pytest.raises(HypothesisEngineError, match="exact valid assignment"):
        analyze_experiment(
            plan,
            assignments,
            mixed,
            analyzed_at=plan.outcome_window_ends_at + timedelta(seconds=1),
        )


def test_compound_capability_is_descriptive_and_unproven_is_not_plannable() -> None:
    promote = PlatformCapabilityVersion(
        platform_id="avito",
        capability_id="promote-listing",
        version=1,
        action="PROMOTE_LISTING",
        object_type="listing",
        source_role="ACTION",
        required_effect_classes=frozenset({EffectClass.WRITE, EffectClass.SPEND}),
        capability_status=CapabilityStatus.UNPROVEN,
        terms_evidence_sha256=_sha("promote-terms"),
        operation_contract_sha256=_sha("promote-operation-contract"),
        status_evidence_sha256=_sha("promote-unproven"),
        observed_at=T0,
        valid_from=T0 + timedelta(days=1),
        valid_until=T0 + timedelta(days=10),
    )
    assert promote.required_effect_classes == frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    )
    assert promote.authority_granted is False

    plan = _plan()
    unproven = replace(
        plan.capabilities[0],
        capability_status=CapabilityStatus.UNPROVEN,
        status_evidence_sha256=_sha("read-unproven"),
    )
    capabilities = (unproven, plan.capabilities[1])
    capability_shas = tuple(item.content_sha256 for item in capabilities)
    mandate = replace(plan.mandate, capability_sha256s=capability_shas)
    hypothesis = replace(plan.hypothesis, capability_sha256s=capability_shas)
    treatment = replace(
        plan.treatments[1],
        capability_sha256s=capability_shas,
    )
    variants = (
        plan.variants[0],
        replace(plan.variants[1], treatment_sha256=treatment.content_sha256),
    )
    with pytest.raises(HypothesisEngineError, match="only independently VERIFIED"):
        replace(
            plan,
            mandate=mandate,
            hypothesis=hypothesis,
            capabilities=capabilities,
            treatments=(plan.treatments[0], treatment),
            variants=variants,
        )


def test_guardrail_breach_and_forged_analysis_cannot_become_candidates() -> None:
    plan = _plan()
    assignments = _balanced_assignments(plan)
    outcomes = list(
        _outcome(plan, assignment, ordinal=index)
        for index, assignment in enumerate(assignments)
    )
    treatment_index = next(
        index
        for index, assignment in enumerate(assignments)
        if assignment.variant_id == "partner-offer"
    )
    outcomes[treatment_index] = replace(
        outcomes[treatment_index], guardrail_breach_codes=("complaint",)
    )
    analysis = analyze_experiment(
        plan,
        assignments,
        tuple(outcomes),
        analyzed_at=plan.outcome_window_ends_at,
    )
    assert analysis.guardrail_breach_codes == ("complaint",)
    assert analysis.signal_candidate_variant_ids == ()
    assert analysis.commercial_candidate_variant_ids == ()
    with pytest.raises(HypothesisEngineError, match="recomputed by"):
        replace(analysis, signal_candidate_variant_ids=("partner-offer",))


def test_decision_recomputes_evidence_and_outcome_window_is_not_self_declared() -> None:
    plan = _plan()
    assignments = _balanced_assignments(plan)
    outcomes = tuple(
        _outcome(plan, assignment, ordinal=index)
        for index, assignment in enumerate(assignments)
    )
    analysis = analyze_experiment(
        plan,
        assignments,
        outcomes,
        analyzed_at=plan.outcome_window_ends_at,
    )
    with pytest.raises(HypothesisEngineError, match="exact sealed eligibility cohort"):
        analyze_experiment(
            plan,
            assignments[:-1],
            outcomes[:-1],
            analyzed_at=plan.outcome_window_ends_at,
        )
    with pytest.raises(HypothesisEngineError, match="does not match exact recomputed"):
        make_learning_decision(
            analysis=analysis,
            plan=plan,
            assignments=assignments,
            outcomes=outcomes[:-1],
            status=LearningStatus.KEEP_TESTING,
            selected_variant_ids=(),
            rationale="Do not accept an analysis over different evidence.",
            decided_by="owner-001",
            decided_at=analysis.analyzed_at,
            decision_evidence_sha256=_sha("mismatch-decision"),
        )
    assignment = assignments[0]
    with pytest.raises(HypothesisEngineError, match="outcome cutoff"):
        replace(
            _outcome(plan, assignment, ordinal=999),
            measured_at=plan.outcome_window_ends_at - timedelta(seconds=1),
        )
