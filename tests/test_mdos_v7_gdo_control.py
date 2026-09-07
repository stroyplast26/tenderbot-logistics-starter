from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal

import pytest

from lead_factory.mdos_v7.gdo_control import (
    SHADOW_NOT_PROVEN,
    BitrixShadowAck,
    BitrixShadowExpectation,
    BitrixShadowPolicy,
    BusinessDayPolicy,
    Gdo10Policy,
    GoldAcceptanceEvent,
    HotGateCandidate,
    HotGatePolicy,
    build_daily_gdo_snapshots,
    evaluate_bitrix_shadow,
    evaluate_gdo10,
    evaluate_hot_gate,
)


UTC = timezone.utc
MOTIONS = (
    "EXISTING_ACCOUNT_EXPANSION",
    "DEALER_AND_INSTALLER_ACTIVATION",
    "HIGH_INTENT_INBOUND",
)


def _hot(**changes: object) -> HotGateCandidate:
    base = HotGateCandidate(
        demand_unit_id="du-1",
        motion=MOTIONS[0],
        scope_fingerprint="a" * 64,
        cohort_id="cohort-1",
        evaluated_at=datetime(2026, 8, 25, 12, tzinfo=UTC),
        cutoff_at=datetime(2026, 8, 25, 18, tzinfo=UTC),
        current_need_proven=True,
        product_scope_supported=True,
        object_or_site_resolved=True,
        buyer_or_payer_resolved=True,
        supplier_state="OPEN",
        buyer_transition_complete=True,
        decision_horizon_passed=True,
        required_artifacts_present=True,
        evidence_bundle_ref="evidence-1",
        lawful_next_action=True,
        permit_decision="ALLOW",
        permit_ref="permit-1",
        permit_sha256="b" * 64,
        permit_expires_at=datetime(2026, 8, 26, tzinfo=UTC),
        capacity_snapshot_ref="capacity-1",
        capacity_snapshot_at=datetime(2026, 8, 25, 11, tzinfo=UTC),
        capacity_available_units=1,
        economics_snapshot_ref="economics-1",
        economics_snapshot_at=datetime(2026, 8, 25, 10, tzinfo=UTC),
        expected_contribution=Decimal("1"),
        reviewer_id="reviewer-1",
        reviewer_is_human=True,
        claim_author_ids=("model-1",),
        case_originator_id="originator-1",
    )
    return replace(base, **changes)


def _event(
    number: int,
    accepted_at: datetime,
    *,
    motion: str | None = None,
    demand_unit_id: str | None = None,
    fingerprint: str | None = None,
) -> GoldAcceptanceEvent:
    return GoldAcceptanceEvent(
        gold_acceptance_id=f"gold-{number:04d}",
        demand_unit_id=demand_unit_id or f"du-{number:04d}",
        scope_fingerprint=fingerprint or f"{number:064x}",
        cohort_id="cohort-1",
        motion=motion or MOTIONS[number % len(MOTIONS)],
        accepted_at=accepted_at,
    )


def _business_days(start: date, count: int) -> tuple[date, ...]:
    rows: list[date] = []
    current = start
    while len(rows) < count:
        if current.weekday() < 5:
            rows.append(current)
        current += timedelta(days=1)
    return tuple(rows)


def _window(day_counts: tuple[int, ...]) -> tuple:
    days = _business_days(date(2026, 8, 3), len(day_counts))
    events: list[GoldAcceptanceEvent] = []
    number = 1
    for day, count in zip(days, day_counts):
        for _ in range(count):
            events.append(_event(number, datetime.combine(day, time(12), tzinfo=UTC)))
            number += 1
    return build_daily_gdo_snapshots(
        events,
        days,
        cohort_id="cohort-1",
        policy=BusinessDayPolicy(),
    )


def _expectation(number: int, entity_kind: str = "DEAL") -> BitrixShadowExpectation:
    return BitrixShadowExpectation(
        projection_id=f"projection-{number}-{entity_kind.lower()}",
        gold_acceptance_id=f"gold-{number}",
        entity_kind=entity_kind,
        payload_sha256=f"{number * (1 if entity_kind == 'DEAL' else 2):064x}",
        enqueued_at=datetime(2026, 8, 25, 12, tzinfo=UTC),
    )


def _ack(
    expected: BitrixShadowExpectation,
    *,
    seconds: int = 5,
    payload_sha256: str | None = None,
) -> BitrixShadowAck:
    return BitrixShadowAck(
        ack_id=f"ack-{expected.projection_id}",
        projection_id=expected.projection_id,
        entity_kind=expected.entity_kind,
        payload_sha256=payload_sha256 or expected.payload_sha256,
        acked_at=expected.enqueued_at + timedelta(seconds=seconds),
    )


def _pair(number: int) -> tuple[BitrixShadowExpectation, BitrixShadowExpectation]:
    return _expectation(number, "DEAL"), _expectation(number, "TASK")


def test_policy_is_frozen_and_positive_hot_candidate_passes() -> None:
    policy = HotGatePolicy()
    with pytest.raises(FrozenInstanceError):
        policy.capacity_ttl = timedelta(days=1)  # type: ignore[misc]

    result = evaluate_hot_gate(_hot(), policy)

    assert result.accepted is True
    assert result.reason_codes == ("HOT_GATE_PASSED",)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"current_need_proven": False}, "NEED_NOT_PROVEN"),
        ({"product_scope_supported": False}, "PRODUCT_SCOPE_UNSUPPORTED"),
        ({"object_or_site_resolved": False}, "OBJECT_OR_SITE_UNRESOLVED"),
        ({"buyer_or_payer_resolved": False}, "BUYER_OR_PAYER_UNRESOLVED"),
        ({"supplier_state": "UNKNOWN"}, "SUPPLIER_NOT_OPEN"),
        ({"decision_horizon_passed": False}, "DECISION_HORIZON_FAILED"),
        ({"required_artifacts_present": False}, "REQUIRED_ARTIFACTS_MISSING"),
        ({"lawful_next_action": False}, "NEXT_ACTION_NOT_LAWFUL"),
        ({"permit_decision": "DENY"}, "PERMIT_NOT_ALLOWED"),
        ({"permit_sha256": "not-a-digest"}, "PERMIT_DIGEST_INVALID"),
        ({"capacity_available_units": 0}, "CAPACITY_UNAVAILABLE"),
        ({"expected_contribution": Decimal("-0.01")}, "ECONOMICS_BELOW_MINIMUM"),
        ({"conflicts": ("buyer",)}, "CONFLICT_PRESENT"),
        ({"suppressed": True}, "SUPPRESSED"),
        ({"reviewer_is_human": False}, "REVIEWER_NOT_HUMAN"),
        ({"reviewer_id": "model-1"}, "REVIEWER_NOT_INDEPENDENT"),
        ({"duplicate_scope": True}, "DUPLICATE_SCOPE"),
    ],
)
def test_hot_gate_fails_closed_with_stable_reason_codes(
    change: dict[str, object], reason: str
) -> None:
    result = evaluate_hot_gate(_hot(**change), HotGatePolicy())

    assert result.accepted is False
    assert reason in result.reason_codes


def test_hot_gate_blocks_transition_only_motion_and_stale_snapshots() -> None:
    policy = HotGatePolicy(
        allowed_motions=frozenset({"PROJECT_SPECIFICATION_INFLUENCE"})
    )
    candidate = _hot(
        motion="PROJECT_SPECIFICATION_INFLUENCE",
        buyer_transition_complete=False,
        permit_expires_at=datetime(2026, 8, 25, 11, tzinfo=UTC),
        capacity_snapshot_at=datetime(2026, 8, 25, 1, tzinfo=UTC),
        economics_snapshot_at=datetime(2026, 8, 23, tzinfo=UTC),
    )

    result = evaluate_hot_gate(candidate, policy)

    assert result.reason_codes == (
        "BUYER_TRANSITION_REQUIRED",
        "PERMIT_EXPIRED",
        "CAPACITY_SNAPSHOT_STALE",
        "ECONOMICS_SNAPSHOT_STALE",
    )


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity")])
def test_nonfinite_policy_contribution_is_rejected_cleanly(value: Decimal) -> None:
    with pytest.raises(ValueError, match="must be finite"):
        HotGatePolicy(minimum_expected_contribution=value)


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity")])
def test_nonfinite_candidate_contribution_returns_reason_code(value: Decimal) -> None:
    result = evaluate_hot_gate(
        _hot(expected_contribution=value),
        HotGatePolicy(),
    )

    assert result.accepted is False
    assert "ECONOMICS_VALUE_INVALID" in result.reason_codes


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"current_need_proven": 1}, "NEED_NOT_PROVEN"),
        ({"reviewer_is_human": "yes"}, "REVIEWER_NOT_HUMAN"),
        ({"suppressed": 0}, "SUPPRESSED"),
        ({"duplicate_scope": "no"}, "DUPLICATE_SCOPE"),
        ({"capacity_available_units": "1"}, "CAPACITY_VALUE_INVALID"),
        ({"permit_sha256": 7}, "PERMIT_DIGEST_INVALID"),
        ({"scope_fingerprint": 7}, "SCOPE_FINGERPRINT_INVALID"),
        ({"evaluated_at": "2026-08-25T12:00:00Z"}, "TIME_INVALID"),
        ({"motion": []}, "MOTION_NOT_ALLOWED"),
        ({"supplier_state": []}, "SUPPLIER_NOT_OPEN"),
        ({"evidence_bundle_ref": 7}, "EVIDENCE_BUNDLE_MISSING"),
    ],
)
def test_malformed_hot_facts_fail_closed_without_type_errors(
    change: dict[str, object], reason: str
) -> None:
    result = evaluate_hot_gate(_hot(**change), HotGatePolicy())

    assert result.accepted is False
    assert reason in result.reason_codes


@pytest.mark.parametrize(
    "factory",
    [
        lambda: GoldAcceptanceEvent(
            gold_acceptance_id=7,  # type: ignore[arg-type]
            demand_unit_id="du-1",
            scope_fingerprint="a" * 64,
            cohort_id="cohort-1",
            motion=MOTIONS[0],
            accepted_at=datetime(2026, 8, 25, 12, tzinfo=UTC),
        ),
        lambda: BitrixShadowExpectation(
            projection_id=7,  # type: ignore[arg-type]
            gold_acceptance_id="gold-1",
            entity_kind="DEAL",
            payload_sha256="a" * 64,
            enqueued_at=datetime(2026, 8, 25, 12, tzinfo=UTC),
        ),
        lambda: BitrixShadowAck(
            ack_id=7,  # type: ignore[arg-type]
            projection_id="projection-1",
            entity_kind="DEAL",
            payload_sha256="a" * 64,
            acked_at=datetime(2026, 8, 25, 12, tzinfo=UTC),
        ),
    ],
)
def test_counter_and_bitrix_identities_require_text(factory: object) -> None:
    with pytest.raises(ValueError):
        factory()  # type: ignore[operator]


def test_daily_snapshot_dedupes_scope_and_keeps_late_acceptance_out() -> None:
    day = date(2026, 8, 25)
    events = [
        _event(number, datetime(2026, 8, 25, 12, tzinfo=UTC)) for number in range(1, 10)
    ]
    events.extend(
        [
            _event(10, datetime(2026, 8, 25, 18, 0, 1, tzinfo=UTC)),
            _event(
                11,
                datetime(2026, 8, 25, 13, tzinfo=UTC),
                demand_unit_id="du-0001",
                fingerprint=f"{1:064x}",
            ),
        ]
    )

    snapshot = build_daily_gdo_snapshots(
        events,
        (day,),
        cohort_id="cohort-1",
        policy=BusinessDayPolicy(),
    )[0]

    assert snapshot.accepted_count == 9
    assert snapshot.successful is False
    assert snapshot.late_ids == ("gold-0010",)
    assert snapshot.duplicate_ids == ("gold-0011",)


def test_revocation_after_evaluation_cutoff_is_visible_but_not_applied() -> None:
    day = date(2026, 8, 25)
    event = replace(
        _event(1, datetime(2026, 8, 25, 12, tzinfo=UTC)),
        revoked_at=datetime(2026, 8, 26, 12, tzinfo=UTC),
    )

    snapshot = build_daily_gdo_snapshots(
        (event,),
        (day,),
        cohort_id="cohort-1",
        policy=BusinessDayPolicy(),
    )[0]

    assert snapshot.accepted_ids == (event.gold_acceptance_id,)
    assert snapshot.revoked_ids == ()
    assert snapshot.future_revocation_ids == (event.gold_acceptance_id,)


def test_effective_revocation_removes_acceptance_as_of_last_cutoff() -> None:
    days = (date(2026, 8, 25), date(2026, 8, 26))
    event = replace(
        _event(1, datetime(2026, 8, 25, 12, tzinfo=UTC)),
        revoked_at=datetime(2026, 8, 26, 12, tzinfo=UTC),
    )

    snapshots = build_daily_gdo_snapshots(
        (event,),
        days,
        cohort_id="cohort-1",
        policy=BusinessDayPolicy(),
    )

    assert snapshots[0].accepted_count == 0
    assert snapshots[0].revoked_ids == (event.gold_acceptance_id,)


def test_revoked_at_must_be_aware_and_not_precede_acceptance() -> None:
    accepted = datetime(2026, 8, 25, 12, tzinfo=UTC)
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(_event(1, accepted), revoked_at=datetime(2026, 8, 26, 12))
    with pytest.raises(ValueError, match="cannot precede"):
        replace(
            _event(1, accepted),
            revoked_at=datetime(2026, 8, 25, 11, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"gold_acceptance_id": ""},
        {"demand_unit_id": ""},
        {"cohort_id": ""},
        {"motion": ""},
        {"scope_fingerprint": "not-a-hash"},
        {"accepted_at": datetime(2026, 8, 25, 12)},
    ],
)
def test_gold_event_rejects_empty_or_invalid_identity_fields(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(
            _event(1, datetime(2026, 8, 25, 12, tzinfo=UTC)),
            **changes,
        )


def test_gdo10_300_total_but_only_18_successful_days_fails() -> None:
    snapshots = _window((15,) * 18 + (3,) * 6 + (2,) * 6)

    result = evaluate_gdo10(snapshots)

    assert result.total_unique_accepted == 300
    assert result.successful_days == 18
    assert result.arithmetic_passed is False
    assert "GDO10_SUCCESSFUL_DAYS_BELOW_MINIMUM" in result.reason_codes
    assert result.status == SHADOW_NOT_PROVEN


def test_gdo10_300_total_and_24_successful_days_is_arithmetic_only() -> None:
    snapshots = _window((11,) * 12 + (10,) * 12 + (8,) * 6)

    result = evaluate_gdo10(snapshots, Gdo10Policy())

    assert result.total_unique_accepted == 300
    assert result.successful_days == 24
    assert result.independent_motions == 3
    assert result.arithmetic_passed is True
    assert result.status == SHADOW_NOT_PROVEN
    assert result.reason_codes == ("GDO10_ARITHMETIC_PASSED", SHADOW_NOT_PROVEN)


@pytest.mark.parametrize(
    "changes",
    [
        {"evaluation_workdays": 0},
        {"minimum_total": 0},
        {"target_per_day": 0},
        {"minimum_successful_days": 0},
        {"minimum_independent_motions": 0},
        {"working_weekdays": frozenset()},
        {"working_weekdays": frozenset({0, 7})},
        {"evaluation_workdays": 5, "minimum_successful_days": 6},
    ],
)
def test_gdo10_policy_rejects_invalid_thresholds(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        Gdo10Policy(**changes)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda row: replace(
                row, accepted_ids=(row.accepted_ids[0], row.accepted_ids[0])
            ),
            "GDO10_SNAPSHOT_DUPLICATE_ACCEPTANCE",
        ),
        (
            lambda row: replace(
                row,
                motion_counts=((MOTIONS[0], 5), (MOTIONS[0], 5)),
            ),
            "GDO10_MOTION_COUNTS_DUPLICATE_MOTION",
        ),
        (
            lambda row: replace(row, motion_counts=((MOTIONS[0], 0),)),
            "GDO10_MOTION_COUNTS_NONPOSITIVE",
        ),
        (
            lambda row: replace(row, motion_counts=((MOTIONS[0], 1),)),
            "GDO10_MOTION_COUNTS_MISMATCH",
        ),
        (
            lambda row: replace(row, cutoff_at=row.cutoff_at.replace(tzinfo=None)),
            "GDO10_CUTOFF_UNAWARE",
        ),
        (
            lambda row: replace(row, cutoff_at=row.cutoff_at + timedelta(days=1)),
            "GDO10_CUTOFF_BUSINESS_DATE_MISMATCH",
        ),
    ],
)
def test_gdo10_evaluator_rejects_malformed_snapshots(
    mutation: object,
    reason: str,
) -> None:
    snapshots = list(_window((11,) * 12 + (10,) * 12 + (8,) * 6))
    snapshots[0] = mutation(snapshots[0])  # type: ignore[operator]

    result = evaluate_gdo10(snapshots)

    assert result.arithmetic_passed is False
    assert reason in result.reason_codes
    assert result.status == SHADOW_NOT_PROVEN


def test_bitrix_shadow_complete_matching_acks_pass_with_nearest_rank_p90() -> None:
    expected = tuple(item for number in range(1, 11) for item in _pair(number))
    acks = tuple(
        _ack(row, seconds=seconds)
        for row, seconds in zip(
            expected, (1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10)
        )
    )

    result = evaluate_bitrix_shadow(
        expected, acks, BitrixShadowPolicy(ack_sla=timedelta(seconds=9))
    )

    assert result.passed is True
    assert result.completeness == Decimal(1)
    assert result.p90_latency_ms == 9000


def test_bitrix_shadow_missing_ack_fails_completeness() -> None:
    first, second = _pair(1)

    result = evaluate_bitrix_shadow(
        (first, second),
        (_ack(first),),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert result.completeness == Decimal("0.5")
    assert result.missing_projection_ids == (second.projection_id,)
    assert "BITRIX_ACK_MISSING" in result.reason_codes


def test_bitrix_shadow_late_ack_fails_p90_sla() -> None:
    expected = _pair(1)

    result = evaluate_bitrix_shadow(
        expected,
        tuple(_ack(row, seconds=11) for row in expected),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert result.p90_latency_ms == 11000
    assert result.late_projection_ids == tuple(
        sorted(row.projection_id for row in expected)
    )
    assert "BITRIX_P90_SLA_FAILED" in result.reason_codes
    assert "BITRIX_ACK_LATE" in result.reason_codes


def test_bitrix_shadow_payload_mismatch_is_not_a_valid_ack() -> None:
    deal, task = _pair(1)

    result = evaluate_bitrix_shadow(
        (deal, task),
        (_ack(deal, payload_sha256="f" * 64), _ack(task)),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert result.valid_ack_count == 1
    assert result.completeness == Decimal("0.5")
    assert result.mismatched_projection_ids == (deal.projection_id,)
    assert "BITRIX_ACK_MISMATCHED" in result.reason_codes


def test_bitrix_shadow_missing_task_expectation_fails_pair_contract() -> None:
    deal = _expectation(1, "DEAL")

    result = evaluate_bitrix_shadow(
        (deal,),
        (_ack(deal),),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert result.incomplete_gold_acceptance_ids == (deal.gold_acceptance_id,)
    assert "BITRIX_EXPECTATION_PAIR_INCOMPLETE" in result.reason_codes


def test_bitrix_shadow_duplicate_entity_kind_fails() -> None:
    deal, task = _pair(1)
    duplicate_deal = replace(deal, projection_id="projection-1-deal-duplicate")

    result = evaluate_bitrix_shadow(
        (deal, duplicate_deal, task),
        (_ack(deal), _ack(duplicate_deal), _ack(task)),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert "BITRIX_EXPECTATION_DUPLICATE_KIND" in result.reason_codes


def test_bitrix_shadow_ack_entity_kind_mismatch_fails() -> None:
    deal, task = _pair(1)
    wrong_kind_ack = replace(_ack(deal), entity_kind="TASK")

    result = evaluate_bitrix_shadow(
        (deal, task),
        (wrong_kind_ack, _ack(task)),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert deal.projection_id in result.mismatched_projection_ids
    assert "BITRIX_ACK_KIND_MISMATCH" in result.reason_codes


def test_bitrix_shadow_allows_exact_ack_replay() -> None:
    deal, task = _pair(1)
    deal_ack, task_ack = _ack(deal), _ack(task)

    result = evaluate_bitrix_shadow(
        (deal, task),
        (deal_ack, deal_ack, task_ack, task_ack),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is True
    assert result.valid_ack_count == 2
    assert result.conflicting_ack_ids == ()


def test_bitrix_shadow_rejects_conflicting_ack_id_reuse() -> None:
    deal, task = _pair(1)
    deal_ack = _ack(deal)
    conflicting = replace(deal_ack, payload_sha256="f" * 64)

    result = evaluate_bitrix_shadow(
        (deal, task),
        (deal_ack, conflicting, _ack(task)),
        BitrixShadowPolicy(ack_sla=timedelta(seconds=10)),
    )

    assert result.passed is False
    assert result.conflicting_ack_ids == (deal_ack.ack_id,)
    assert "BITRIX_ACK_ID_CONFLICT" in result.reason_codes


@pytest.mark.parametrize(
    "changes",
    [
        {"projection_id": ""},
        {"gold_acceptance_id": ""},
        {"payload_sha256": "not-a-hash"},
        {"enqueued_at": datetime(2026, 8, 25, 12)},
    ],
)
def test_bitrix_expectation_rejects_invalid_identity_fields(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(_expectation(1), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"ack_id": ""},
        {"projection_id": ""},
        {"payload_sha256": "not-a-hash"},
        {"acked_at": datetime(2026, 8, 25, 12)},
    ],
)
def test_bitrix_ack_rejects_invalid_identity_fields(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(_ack(_expectation(1)), **changes)
