from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import inspect

import pytest

from lead_factory.mdos_v7.contracts import value_sha256
from lead_factory.mdos_v7.hypothesis_engine import (
    CapabilityStatus,
    CohortSnapshot,
    EffectClass,
    ExecutionMode,
    ExperimentPlan,
    ExperimentVariant,
    ExplorationMandate,
    HypothesisVersion,
    PlatformCapabilityVersion,
    ProposerKind,
    TreatmentVersion,
    eligibility_cohort_sha256,
)
from lead_factory.mdos_v7.source_portfolio_control import (
    PORTFOLIO_SCHEMA_VERSION,
    AllocationReason,
    AllocationStatus,
    ExperimentRequest,
    LearningEvidenceClass,
    LearningGate,
    LearningMemoryEntry,
    LearningMemorySnapshot,
    MethodFingerprintEvidence,
    PortfolioMode,
    PortfolioPolicy,
    SourcePortfolioControlError,
    TrialEntitlement,
    allocate_portfolio,
    build_negative_learning_memory_entry,
    build_method_fingerprint_evidence,
    verify_portfolio_allocation,
)


UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)
AT = T0 + timedelta(days=2)


def _sha(label: str) -> str:
    return value_sha256({"offline_fixture": label})


def _opaque(namespace: str, label: str) -> str:
    return f"opaque:{namespace}:{_sha(label)[:32]}"


def _capability(
    method_label: str,
    capability_label: str,
    effect: EffectClass,
) -> PlatformCapabilityVersion:
    return PlatformCapabilityVersion(
        platform_id=f"platform-{method_label}",
        capability_id=f"{capability_label}-{method_label}",
        version=1,
        action=f"{effect.value}_{capability_label}".upper(),
        object_type="listing",
        source_role="DISCOVERY" if effect is EffectClass.READ else "ACTION",
        required_effect_classes=frozenset({effect}),
        capability_status=CapabilityStatus.VERIFIED,
        operation_contract_sha256=_sha(
            f"operation-contract-{method_label}-{capability_label}"
        ),
        terms_evidence_sha256=_sha(f"terms-{method_label}-{capability_label}"),
        status_evidence_sha256=_sha(f"status-{method_label}-{capability_label}"),
        observed_at=T0,
        valid_from=T0 + timedelta(hours=1),
        valid_until=T0 + timedelta(days=10),
        mode=ExecutionMode.SHADOW,
    )


def _plan(
    method_label: str,
    *,
    plan_label: str | None = None,
    assumption_label: str | None = None,
) -> ExperimentPlan:
    plan_label = plan_label or method_label
    assumption_label = assumption_label or method_label
    read = _capability(method_label, "read", EffectClass.READ)
    contact = _capability(method_label, "contact", EffectClass.CONTACT)
    capability_shas = (read.content_sha256, contact.content_sha256)
    mandate = ExplorationMandate(
        mandate_id=f"mandate-{plan_label}",
        version=1,
        scope_id=f"scope-{method_label}",
        capability_sha256s=capability_shas,
        allowed_effect_classes=frozenset({EffectClass.READ, EffectClass.CONTACT}),
        currency="RUB",
        budget_cap_minor=50_000,
        contact_cap=100,
        capacity_cap=100,
        minimum_holdout_bps=2_000,
        approved_by="owner-001",
        approved_at=T0,
        approval_evidence_sha256=_sha(f"mandate-approval-{plan_label}"),
        valid_from=T0 + timedelta(hours=1),
        valid_until=T0 + timedelta(days=10),
        mode=ExecutionMode.SHADOW,
    )
    hypothesis = HypothesisVersion(
        hypothesis_id=f"hypothesis-{plan_label}",
        version=1,
        statement=f"Method {method_label} creates incremental accepted GDO.",
        falsification_rule="Reject when accepted-GDO lift does not exceed holdout.",
        causal_mechanism=f"Treatment mechanism for {method_label} changes GDO incidence.",
        causal_mechanism_sha256=_sha(f"causal-mechanism-{method_label}"),
        assumption_sha256s=(_sha(f"assumption-{assumption_label}"),),
        unit_of_randomization="opaque-account-cluster",
        scope_id=mandate.scope_id,
        scope_definition_sha256=_sha(f"scope-definition-{method_label}"),
        audience_definition_sha256=_sha(f"audience-definition-{method_label}"),
        capability_sha256s=capability_shas,
        proposed_by="ai-planner-001",
        proposer_kind=ProposerKind.AI,
        proposed_at=T0 + timedelta(minutes=10),
    )
    control = TreatmentVersion(
        treatment_id=f"control-{method_label}",
        version=1,
        treatment_label="No treatment holdout",
        description="Observe without contact, write, or spend.",
        mechanism_sha256=_sha(f"control-mechanism-{method_label}"),
        capability_sha256s=(),
        effect_classes=frozenset(),
        proposed_by="analyst-001",
        proposer_kind=ProposerKind.HUMAN,
        proposed_at=T0 + timedelta(minutes=15),
        is_no_treatment_control=True,
    )
    treatment = TreatmentVersion(
        treatment_id=f"treatment-{method_label}",
        version=1,
        treatment_label=f"Bounded treatment {method_label}",
        description="Shadow-plan one bounded collaboration treatment.",
        mechanism_sha256=_sha(f"treatment-mechanism-{method_label}"),
        capability_sha256s=capability_shas,
        effect_classes=frozenset({EffectClass.READ, EffectClass.CONTACT}),
        proposed_by="ai-planner-001",
        proposer_kind=ProposerKind.AI,
        proposed_at=T0 + timedelta(minutes=15),
    )
    cluster_ids = tuple(
        sorted(
            f"cluster-hmac-v1:{_sha(f'{method_label}-{index:03d}')}"
            for index in range(100)
        )
    )
    cohort = CohortSnapshot(
        cohort_id=f"cohort-{method_label}",
        unit_of_randomization=hypothesis.unit_of_randomization,
        cluster_ids=cluster_ids,
        eligibility_policy_sha256=_sha(f"eligibility-{method_label}"),
        source_snapshot_sha256=_sha(f"source-snapshot-{method_label}"),
        sealed_by="analyst-002",
        sealed_at=T0 + timedelta(minutes=20),
        membership_sha256=eligibility_cohort_sha256(
            unit_of_randomization=hypothesis.unit_of_randomization,
            cluster_ids=cluster_ids,
        ),
        pseudonymization_key_version="fixture-key-v1",
        pseudonymization_evidence_sha256=_sha(f"pseudonymization-{method_label}"),
    )
    variants = (
        ExperimentVariant(
            variant_id="control",
            treatment_sha256=control.content_sha256,
            allocation_bps=3_000,
            budget_cap_minor=0,
            contact_cap=0,
            capacity_cap=50,
            is_control=True,
        ),
        ExperimentVariant(
            variant_id="treatment",
            treatment_sha256=treatment.content_sha256,
            allocation_bps=7_000,
            budget_cap_minor=20_000,
            contact_cap=50,
            capacity_cap=50,
        ),
    )
    return ExperimentPlan(
        plan_id=f"experiment-{plan_label}",
        version=1,
        mandate=mandate,
        hypothesis=hypothesis,
        capabilities=(read, contact),
        treatments=(control, treatment),
        variants=variants,
        cohort_snapshot=cohort,
        analysis_plan_sha256=_sha(f"analysis-plan-{method_label}"),
        outcome_identity_policy_sha256=_sha(f"outcome-identity-policy-{method_label}"),
        outcome_pseudonymization_key_version="portfolio-fixture-hmac-v1",
        outcome_pseudonymization_evidence_sha256=_sha(
            f"outcome-pseudonymization-{method_label}"
        ),
        guardrail_ids=("complaint", "capacity-overload"),
        stop_rule_ids=("stop-on-complaint", "stop-on-cap"),
        assignment_seed_sha256=_sha(f"assignment-seed-{plan_label}"),
        assignment_seed_source="independent-fixture-custodian",
        assignment_seed_evidence_sha256=_sha(f"seed-evidence-{plan_label}"),
        seed_committed_by="seed-custodian-001",
        seed_committed_at=T0 + timedelta(minutes=25),
        preregistered_at=T0 + timedelta(minutes=30),
        approved_at=T0 + timedelta(minutes=40),
        starts_at=T0 + timedelta(days=1),
        ends_at=T0 + timedelta(days=4),
        outcome_window_ends_at=T0 + timedelta(days=6),
        minimum_clusters_per_variant=10,
        confidence_z_milli=1_645,
        minimum_signal_lift_bps=1,
        minimum_paid_lift_bps=1,
        minimum_net_contribution_lift_minor_per_cluster=1,
        budget_cap_minor=20_000,
        contact_cap=50,
        capacity_cap=100,
        approved_by="owner-001",
        approval_evidence_sha256=_sha(f"plan-approval-{plan_label}"),
        mode=ExecutionMode.SHADOW,
    )


def _method(
    method_label: str,
    *,
    plan_label: str | None = None,
    assumption_label: str | None = None,
    supersedes: str | None = None,
) -> MethodFingerprintEvidence:
    plan = _plan(
        method_label,
        plan_label=plan_label,
        assumption_label=assumption_label,
    )
    return build_method_fingerprint_evidence(
        plan,
        approved_by=_opaque("owner", "method-approver"),
        approved_at=T0 + timedelta(hours=1),
        approval_evidence_sha256=_sha(f"method-approval-{plan_label or method_label}"),
        supersedes_method_fingerprint_sha256=supersedes,
        material_change_evidence_sha256=(
            _sha(f"material-change-{plan_label or method_label}")
            if supersedes is not None
            else None
        ),
        change_rationale_sha256=(
            _sha(f"change-rationale-{plan_label or method_label}")
            if supersedes is not None
            else None
        ),
    )


def _policy(**changes: object) -> PortfolioPolicy:
    values: dict[str, object] = {
        "policy_id": "portfolio-policy-001",
        "version": 1,
        "currency": "RUB",
        "global_budget_cap_minor": 10_000,
        "global_contact_cap": 20,
        "global_review_capacity_units": 20,
        "max_parallel_experiments": 4,
        "dependency_family_concentration_bps": 5_000,
        "exploration_reserve_bps": 2_500,
        "valid_from": T0,
        "valid_until": T0 + timedelta(days=10),
        "approved_by": _opaque("owner", "portfolio-approver"),
        "approved_at": T0 - timedelta(hours=1),
        "approval_evidence_sha256": _sha("portfolio-approval"),
    }
    values.update(changes)
    return PortfolioPolicy(**values)  # type: ignore[arg-type]


def _trial(label: str = "a", **changes: object) -> TrialEntitlement:
    values: dict[str, object] = {
        "provider_id": f"provider-{label}",
        "account_id": _opaque("account", label),
        "starts_at": T0 + timedelta(days=1),
        "ends_at": T0 + timedelta(days=9),
        "cancellation_deadline_at": T0 + timedelta(days=8),
        "tariff_id": f"trial-tariff-{label}",
        "currency": "RUB",
        "max_commitment_minor": 1_000,
        "auto_renew": False,
        "owner_id": _opaque("owner", "trial-owner"),
        "evidence_sha256": _sha(f"trial-evidence-{label}"),
    }
    values.update(changes)
    return TrialEntitlement(**values)  # type: ignore[arg-type]


def _request(
    trial: TrialEntitlement,
    method: MethodFingerprintEvidence,
    *,
    family: str,
    **changes: object,
) -> ExperimentRequest:
    values: dict[str, object] = {
        "plan_sha256": method.plan_sha256,
        "method_fingerprint_sha256": method.method_fingerprint_sha256,
        "trial_sha256": trial.content_sha256,
        "dependency_family": family,
        "requested_budget_minor": 500,
        "requested_contact_count": 1,
        "requested_review_capacity_units": 1,
        "priority": 100,
        "is_exploration": True,
        "learning_gate": LearningGate.ELIGIBLE,
        "learning_evidence_sha256": _sha("new-method-eligibility"),
    }
    values.update(changes)
    return ExperimentRequest(**values)  # type: ignore[arg-type]


def _memory(
    entries: tuple[LearningMemoryEntry, ...] = (),
    *,
    complete_through: datetime = AT,
    sealed_at: datetime | None = None,
) -> LearningMemorySnapshot:
    ordered = tuple(sorted(entries, key=lambda item: item.content_sha256))
    return LearningMemorySnapshot(
        entries=ordered,
        complete_through=complete_through,
        sealed_at=sealed_at or complete_through,
        sealed_by=_opaque("owner", "memory-custodian"),
        snapshot_evidence_sha256=_sha(
            f"memory-snapshot-{complete_through.isoformat()}-{len(entries)}"
        ),
    )


def _allocate(
    *,
    policy: PortfolioPolicy,
    trials: tuple[TrialEntitlement, ...],
    methods: tuple[MethodFingerprintEvidence, ...],
    requests: tuple[ExperimentRequest, ...],
    memory: LearningMemorySnapshot | None = None,
    evaluated_at: datetime = AT,
):
    return allocate_portfolio(
        policy=policy,
        trials=trials,
        methods=methods,
        requests=requests,
        learning_memory=memory or _memory(complete_through=evaluated_at),
        evaluated_at=evaluated_at,
    )


def _memory_entry(
    method: MethodFingerprintEvidence,
    status: LearningGate,
) -> LearningMemoryEntry:
    return build_negative_learning_memory_entry(
        method,
        status=status,
        decision_sha256=_sha(f"decision-{status.value}-{method.plan_sha256}"),
        evidence_sha256=_sha(f"evidence-{status.value}-{method.plan_sha256}"),
        recorded_at=AT - timedelta(hours=1),
        recorded_by=_opaque("owner", "negative-memory-recorder"),
    )


def test_records_are_strict_domain_separated_frozen_and_zero_authority() -> None:
    policy = _policy()
    trial = _trial()
    method = _method("strict")
    request = _request(trial, method, family="family-strict")

    for record in (policy, trial, method, request, _memory()):
        material = record.material()
        assert material["schema_version"] == PORTFOLIO_SCHEMA_VERSION
        assert material["record_kind"] == record.record_kind
        assert material["payload"]
        assert record.content_sha256 == value_sha256(material)
        assert record.external_authority_granted is False
        assert record.external_effect_count == 0
    assert policy.mode is PortfolioMode.OFFLINE_SHADOW
    assert policy.permit_granted is False
    assert trial.access_granted is False
    assert method.permit_granted is False
    assert request.permit_granted is False
    with pytest.raises(FrozenInstanceError):
        trial.currency = "USD"  # type: ignore[misc]
    with pytest.raises(SourcePortfolioControlError, match="explicitly false"):
        replace(trial, auto_renew=True)
    with pytest.raises(SourcePortfolioControlError, match="integer"):
        replace(trial, max_commitment_minor=True)  # type: ignore[arg-type]
    with pytest.raises(SourcePortfolioControlError, match="opaque:"):
        replace(trial, account_id="79991234567")
    with pytest.raises(SourcePortfolioControlError, match="opaque:"):
        replace(policy, approved_by="owner-001")
    with pytest.raises(SourcePortfolioControlError, match="exact ExperimentPlan"):
        replace(method, approved_at=AT)
    with pytest.raises(SourcePortfolioControlError, match="cannot predate"):
        build_method_fingerprint_evidence(
            _plan("too-early"),
            approved_by=_opaque("owner", "too-early-approver"),
            approved_at=T0,
            approval_evidence_sha256=_sha("too-early-method-approval"),
        )

    over_plan = replace(request, requested_budget_minor=20_001)
    over_plan_result = _allocate(
        policy=policy,
        trials=(trial,),
        methods=(method,),
        requests=(over_plan,),
    )
    assert AllocationReason.REQUEST_EXCEEDS_PLAN_BUDGET_CAP in (
        over_plan_result.decisions[0].reason_codes
    )


def test_allocation_is_order_independent_atomic_and_charges_trial_once() -> None:
    policy = _policy()
    trial_a, trial_b = _trial("a"), _trial("b")
    high_method, middle_method, low_method = (
        _method("high"),
        _method("middle"),
        _method("low"),
    )
    high = _request(
        trial_a,
        high_method,
        family="family-a",
        requested_budget_minor=1_000,
        requested_contact_count=2,
        requested_review_capacity_units=2,
        priority=300,
    )
    middle = _request(
        trial_b,
        middle_method,
        family="family-b",
        requested_budget_minor=700,
        priority=200,
    )
    low = _request(
        trial_a,
        low_method,
        family="family-a",
        requested_budget_minor=500,
        priority=100,
    )

    forward = _allocate(
        policy=policy,
        trials=(trial_a, trial_b),
        methods=(low_method, high_method, middle_method),
        requests=(low, high, middle),
    )
    reverse = _allocate(
        policy=policy,
        trials=(trial_b, trial_a),
        methods=(middle_method, high_method, low_method),
        requests=(middle, high, low),
    )

    assert forward == reverse
    assert [item.status for item in forward.decisions] == [
        AllocationStatus.ALLOCATED,
        AllocationStatus.ALLOCATED,
        AllocationStatus.ALLOCATED,
    ]
    assert [item.allocated_trial_commitment_minor for item in forward.decisions] == [
        1_000,
        1_000,
        0,
    ]
    assert forward.remaining_caps.remaining_budget_minor == 5_800
    for decision in forward.decisions:
        assert decision.full_request_allocated is True
        assert decision.durable_reservation_created is False
        assert decision.permit_granted is False
        assert decision.allocation_scope == "OFFLINE_SHADOW_PROPOSAL_ONLY"


def test_trial_policy_and_cancellation_boundaries_fail_closed() -> None:
    method = _method("boundaries")
    cases = (
        (
            _trial("expired", ends_at=AT, cancellation_deadline_at=AT),
            AT,
            AllocationReason.TRIAL_EXPIRED,
        ),
        (
            _trial("cancel", cancellation_deadline_at=AT),
            AT,
            AllocationReason.CANCELLATION_DEADLINE_REACHED,
        ),
        (
            _trial(
                "future",
                starts_at=AT + timedelta(days=1),
                cancellation_deadline_at=AT + timedelta(days=2),
            ),
            AT,
            AllocationReason.TRIAL_NOT_STARTED,
        ),
        (
            _trial("currency", currency="USD"),
            AT,
            AllocationReason.CURRENCY_MISMATCH,
        ),
    )
    for trial, evaluated_at, expected in cases:
        request = _request(trial, method, family="family-boundaries")
        result = _allocate(
            policy=_policy(),
            trials=(trial,),
            methods=(method,),
            requests=(request,),
            evaluated_at=evaluated_at,
        )
        assert result.decisions[0].status is AllocationStatus.DENIED
        assert expected in result.decisions[0].reason_codes

    trial = _trial("policy-time")
    request = _request(trial, method, family="family-boundaries")
    for evaluated_at, expected in (
        (T0 - timedelta(seconds=1), AllocationReason.POLICY_NOT_STARTED),
        (T0 + timedelta(days=10), AllocationReason.POLICY_EXPIRED),
    ):
        result = _allocate(
            policy=_policy(),
            trials=(trial,),
            methods=(method,),
            requests=(request,),
            evaluated_at=evaluated_at,
        )
        assert result.decisions[0].status is AllocationStatus.DENIED
        assert expected in result.decisions[0].reason_codes


def test_stop_memory_cannot_be_evaded_by_new_plan_or_random_fingerprint() -> None:
    trial = _trial("memory")
    stopped_method = _method("stopped", plan_label="original-plan")
    stop = _memory_entry(
        stopped_method,
        LearningGate.STOPPED,
    )
    memory = _memory((stop,))
    original = _request(trial, stopped_method, family="family-memory")
    original_result = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(stopped_method,),
        requests=(original,),
        memory=memory,
    )
    assert AllocationReason.NEGATIVE_LEARNING_MEMORY in (
        original_result.decisions[0].reason_codes
    )

    renamed_plan_method = _method("stopped", plan_label="renamed-plan")
    assert (
        renamed_plan_method.method_fingerprint_sha256
        == stopped_method.method_fingerprint_sha256
    )
    renamed = _request(trial, renamed_plan_method, family="family-memory")
    renamed_result = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(renamed_plan_method,),
        requests=(renamed,),
        memory=memory,
    )
    assert renamed_result.decisions[0].status is AllocationStatus.DENIED
    assert AllocationReason.NEGATIVE_LEARNING_MEMORY in (
        renamed_result.decisions[0].reason_codes
    )

    random_fingerprint = replace(
        original,
        method_fingerprint_sha256=_sha("random-fingerprint-bypass"),
    )
    random_result = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(stopped_method,),
        requests=(random_fingerprint,),
        memory=memory,
    )
    assert random_result.decisions[0].status is AllocationStatus.DENIED
    assert AllocationReason.METHOD_FINGERPRINT_NOT_FOUND in (
        random_result.decisions[0].reason_codes
    )

    unlineaged_method = _method(
        "stopped",
        plan_label="unlineaged-retest",
        assumption_label="changed-without-lineage",
    )
    unlineaged = _request(trial, unlineaged_method, family="family-memory")
    unlineaged_result = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(unlineaged_method,),
        requests=(unlineaged,),
        memory=memory,
    )
    assert unlineaged_result.decisions[0].status is AllocationStatus.DENIED
    assert AllocationReason.STOPPED_METHOD_LINEAGE_UNRESOLVED in (
        unlineaged_result.decisions[0].reason_codes
    )

    revised_method = _method(
        "stopped",
        plan_label="material-retest",
        assumption_label="changed-assumption",
        supersedes=stopped_method.method_fingerprint_sha256,
    )
    assert revised_method.method_fingerprint_sha256 != (
        stopped_method.method_fingerprint_sha256
    )
    revised = _request(trial, revised_method, family="family-memory")
    revised_result = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(revised_method,),
        requests=(revised,),
        memory=memory,
    )
    assert revised_result.decisions[0].status is AllocationStatus.ALLOCATED


def test_synthetic_or_unevidenced_learning_cannot_unlock_allocation() -> None:
    trial = _trial("synthetic")
    method = _method("synthetic")
    negative = _memory_entry(method, LearningGate.STOPPED)
    with pytest.raises(SourcePortfolioControlError, match="typed evidence bridge"):
        replace(
            negative,
            status=LearningGate.COMMERCIAL_CANDIDATE,
            evidence_class=LearningEvidenceClass.SHADOW_OBSERVED,
            learning_eligible=True,
        )
    with pytest.raises(SourcePortfolioControlError, match="typed evidence bridge"):
        LearningMemoryEntry(
            method_fingerprint_sha256=method.method_fingerprint_sha256,
            method_family_sha256=method.method_family_sha256,
            plan_sha256=method.plan_sha256,
            status=LearningGate.COMMERCIAL_CANDIDATE,
            evidence_class=LearningEvidenceClass.SHADOW_OBSERVED,
            learning_eligible=True,
            decision_sha256=_sha("synthetic-decision-relabel"),
            evidence_sha256=_sha("synthetic-evidence-relabel"),
            recorded_at=AT - timedelta(hours=1),
            recorded_by=_opaque("owner", "synthetic-relabeler"),
        )
    request = _request(
        trial,
        method,
        family="family-synthetic",
        learning_gate=LearningGate.COMMERCIAL_CANDIDATE,
        learning_evidence_sha256=_sha("synthetic-evidence-relabel"),
    )
    no_memory = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(method,),
        requests=(request,),
    )
    assert no_memory.decisions[0].status is AllocationStatus.DENIED
    assert AllocationReason.LEARNING_CLAIM_NOT_EVIDENCED in (
        no_memory.decisions[0].reason_codes
    )


def test_duplicates_and_family_evasion_fail_closed() -> None:
    policy = _policy()
    trial = _trial("duplicates")
    method = _method("duplicates")
    request = _request(trial, method, family="family-one")
    duplicates = _allocate(
        policy=policy,
        trials=(trial,),
        methods=(method,),
        requests=(request, request),
    )
    assert all(item.status is AllocationStatus.DENIED for item in duplicates.decisions)
    assert all(
        AllocationReason.DUPLICATE_REQUEST in item.reason_codes
        and AllocationReason.DUPLICATE_PLAN in item.reason_codes
        and AllocationReason.DUPLICATE_ACTIVE_METHOD_FINGERPRINT in item.reason_codes
        for item in duplicates.decisions
    )

    duplicate_trial = _allocate(
        policy=policy,
        trials=(trial, trial),
        methods=(method,),
        requests=(request,),
    )
    assert AllocationReason.DUPLICATE_TRIAL_ENTITLEMENT in (
        duplicate_trial.decisions[0].reason_codes
    )
    duplicate_method = _allocate(
        policy=policy,
        trials=(trial,),
        methods=(method, method),
        requests=(request,),
    )
    assert AllocationReason.DUPLICATE_METHOD_FINGERPRINT in (
        duplicate_method.decisions[0].reason_codes
    )

    other_method = _method("family-evasion")
    other = _request(trial, other_method, family="family-two")
    family_split = _allocate(
        policy=policy,
        trials=(trial,),
        methods=(method, other_method),
        requests=(request, other),
    )
    assert all(
        item.status is AllocationStatus.DENIED for item in family_split.decisions
    )
    assert all(
        AllocationReason.TRIAL_DEPENDENCY_FAMILY_CONFLICT in item.reason_codes
        for item in family_split.decisions
    )

    sibling_trial = _trial(
        "sibling-account",
        provider_id=trial.provider_id,
    )
    sibling_method = _method("sibling-account")
    sibling_request = _request(
        sibling_trial,
        sibling_method,
        family="family-two",
    )
    provider_split = _allocate(
        policy=policy,
        trials=(trial, sibling_trial),
        methods=(method, sibling_method),
        requests=(request, sibling_request),
    )
    assert all(
        item.status is AllocationStatus.DENIED for item in provider_split.decisions
    )
    assert all(
        AllocationReason.PROVIDER_DEPENDENCY_FAMILY_CONFLICT in item.reason_codes
        for item in provider_split.decisions
    )


def test_shortage_concentration_and_reserve_waitlist_without_partial_grant() -> None:
    policy = _policy(
        global_budget_cap_minor=3_000,
        global_contact_cap=3,
        global_review_capacity_units=3,
        max_parallel_experiments=3,
        dependency_family_concentration_bps=10_000,
        exploration_reserve_bps=0,
    )
    first_trial = _trial("capacity-1", max_commitment_minor=500)
    second_trial = _trial("capacity-2", max_commitment_minor=500)
    first_method, second_method = _method("capacity-1"), _method("capacity-2")
    first = _request(
        first_trial,
        first_method,
        family="shared-capacity-family",
        requested_budget_minor=1_500,
        requested_contact_count=2,
        requested_review_capacity_units=2,
        priority=200,
    )
    second = _request(
        second_trial,
        second_method,
        family="shared-capacity-family",
        requested_budget_minor=1_001,
        requested_contact_count=2,
        requested_review_capacity_units=2,
        priority=100,
    )
    constrained = _allocate(
        policy=policy,
        trials=(first_trial, second_trial),
        methods=(first_method, second_method),
        requests=(second, first),
    )
    assert constrained.decisions[0].status is AllocationStatus.ALLOCATED
    waiting = constrained.decisions[1]
    assert waiting.status is AllocationStatus.WAITLISTED
    assert set(waiting.reason_codes) >= {
        AllocationReason.GLOBAL_BUDGET_EXHAUSTED,
        AllocationReason.GLOBAL_CONTACT_CAP_EXHAUSTED,
        AllocationReason.GLOBAL_REVIEW_CAPACITY_EXHAUSTED,
    }
    assert waiting.full_request_allocated is False
    assert waiting.allocated_budget_minor == 0
    assert waiting.allocated_contact_count == 0
    assert waiting.allocated_review_capacity_units == 0

    reserve_policy = _policy(dependency_family_concentration_bps=10_000)
    shared_trial = _trial("reserve")
    exploit_method, explore_method = _method("exploit"), _method("explore")
    exploit = _request(
        shared_trial,
        exploit_method,
        family="mixed-lane-family",
        requested_budget_minor=7_000,
        priority=200,
        is_exploration=False,
    )
    explore = _request(
        shared_trial,
        explore_method,
        family="mixed-lane-family",
        requested_budget_minor=500,
        priority=100,
        is_exploration=True,
    )
    reserved = _allocate(
        policy=reserve_policy,
        trials=(shared_trial,),
        methods=(exploit_method, explore_method),
        requests=(explore, exploit),
    )
    assert reserved.decisions[0].status is AllocationStatus.WAITLISTED
    assert AllocationReason.EXPLORATION_BUDGET_RESERVE_PROTECTED in (
        reserved.decisions[0].reason_codes
    )
    assert reserved.decisions[1].status is AllocationStatus.ALLOCATED
    assert reserved.decisions[1].allocated_trial_commitment_minor == 1_000
    assert reserved.remaining_caps.non_exploration_budget_headroom_minor == 6_500


def test_derived_records_cannot_be_forged_and_exact_recomputation_verifies() -> None:
    policy = _policy(dependency_family_concentration_bps=10_000)
    trial = _trial("verify")
    method = _method("verify")
    request = _request(trial, method, family="family-verify")
    memory = _memory()
    result = _allocate(
        policy=policy,
        trials=(trial,),
        methods=(method,),
        requests=(request,),
        memory=memory,
    )
    assert verify_portfolio_allocation(
        result,
        policy=policy,
        trials=(trial,),
        methods=(method,),
        requests=(request,),
        learning_memory=memory,
        evaluated_at=AT,
    )
    with pytest.raises(SourcePortfolioControlError, match="allocate_portfolio"):
        replace(
            result.decisions[0],
            allocated_experiment_budget_minor=9_999,
        )
    with pytest.raises(SourcePortfolioControlError, match="allocate_portfolio"):
        replace(result, policy_sha256=_sha("forged-policy"))
    with pytest.raises(SourcePortfolioControlError, match="exact recomputation"):
        verify_portfolio_allocation(
            result,
            policy=replace(policy, global_budget_cap_minor=9_999),
            trials=(trial,),
            methods=(method,),
            requests=(request,),
            learning_memory=memory,
            evaluated_at=AT,
        )


def test_stale_memory_and_implicit_clock_io_network_or_environment_are_denied() -> None:
    trial = _trial("pure")
    method = _method("pure")
    request = _request(trial, method, family="family-pure")
    stale = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(method,),
        requests=(request,),
        memory=_memory(complete_through=AT - timedelta(seconds=1)),
    )
    assert stale.decisions[0].status is AllocationStatus.DENIED
    assert AllocationReason.LEARNING_MEMORY_SNAPSHOT_STALE in (
        stale.decisions[0].reason_codes
    )
    future_sealed = _allocate(
        policy=_policy(),
        trials=(trial,),
        methods=(method,),
        requests=(request,),
        memory=_memory(sealed_at=AT + timedelta(seconds=1)),
    )
    assert future_sealed.decisions[0].status is AllocationStatus.DENIED
    assert AllocationReason.LEARNING_MEMORY_SNAPSHOT_TIME_TRAVEL in (
        future_sealed.decisions[0].reason_codes
    )

    source = inspect.getsource(
        __import__(
            "lead_factory.mdos_v7.source_portfolio_control",
            fromlist=["source_portfolio_control"],
        )
    )
    forbidden = (
        "datetime.now",
        "datetime.utcnow",
        "import os",
        "import pathlib",
        "import sqlite3",
        "import requests",
        "import httpx",
        "import socket",
        "open(",
    )
    assert not any(token in source for token in forbidden)
    with pytest.raises(TypeError, match="evaluated_at"):
        allocate_portfolio(  # type: ignore[call-arg]
            policy=_policy(),
            trials=(trial,),
            methods=(method,),
            requests=(request,),
            learning_memory=_memory(),
        )
    with pytest.raises(SourcePortfolioControlError, match="immutable tuple"):
        allocate_portfolio(
            policy=_policy(),
            trials=[trial],  # type: ignore[arg-type]
            methods=(method,),
            requests=(request,),
            learning_memory=_memory(),
            evaluated_at=AT,
        )
