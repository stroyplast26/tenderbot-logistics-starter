from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path

import pytest

from lead_factory.mdos_v7.contracts import value_sha256
from lead_factory.mdos_v7.g2_preflight import (
    G2ShadowPreflightService,
    load_preflight_fixture,
)
from lead_factory.mdos_v7.gdo_control import (
    SHADOW_NOT_PROVEN,
    BitrixShadowPolicy,
    BusinessDayPolicy,
    HotGateCandidate,
    HotGatePolicy,
    build_daily_gdo_snapshots,
    evaluate_bitrix_shadow,
    evaluate_gdo10,
)
from lead_factory.mdos_v7.gdo_queue import HOLD, IN_PROGRESS, READY, GdoQueueStore
from lead_factory.mdos_v7.offline_hot_factory import (
    HumanGoldApproval,
    InMemoryBitrixShadow,
    OfflineBitrixShadowConflict,
    OfflineHotFactory,
    OfflineHotFactoryDenied,
    OfflineHotFactoryError,
    bind_high_intent_demand,
    build_offline_shadow_permit,
)


UTC = timezone.utc
NOW = datetime(2026, 8, 27, 9, 6, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 8, 27, 9, 0, tzinfo=UTC)
APPROVED_AT = datetime(2026, 8, 27, 9, 5, tzinfo=UTC)
FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "market_demand_os_v7"
    / "g2_high_intent_inbound_preflight"
    / "fixture.json"
)


class FixedClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _sealed_preflight() -> dict[str, object]:
    fixture = load_preflight_fixture(FIXTURE)
    return G2ShadowPreflightService().evaluate(fixture)


def _scenario(
    tmp_path: Path,
    *,
    label: str = "one",
    max_wip: int = 3,
    queue: GdoQueueStore | None = None,
    shadow: InMemoryBitrixShadow | None = None,
    capacity_units: int = 3,
) -> dict[str, object]:
    preflight = _sealed_preflight()
    scope_sha = value_sha256({"offline_scope": label})
    demand = bind_high_intent_demand(
        preflight,
        scope_sha256=scope_sha,
        cohort_id="offline-cohort-2026-08-27",
    )
    capacity_ref = "offline:capacity:pool-a"
    economics_ref = f"offline:economics:scope-a:{label}"
    permit = build_offline_shadow_permit(
        demand,
        capacity_snapshot_ref=capacity_ref,
        economics_snapshot_ref=economics_ref,
        owner_id="fixture-owner-1",
        issued_by="fixture-policy-authority",
        issued_at=EVALUATED_AT - timedelta(hours=1),
        expires_at=EVALUATED_AT + timedelta(hours=8),
    )
    candidate = HotGateCandidate(
        demand_unit_id=demand.demand_unit_id,
        motion=demand.motion,
        scope_fingerprint=demand.scope_sha256,
        cohort_id=demand.cohort_id,
        evaluated_at=EVALUATED_AT,
        cutoff_at=datetime(2026, 8, 27, 18, 0, tzinfo=UTC),
        current_need_proven=True,
        product_scope_supported=True,
        object_or_site_resolved=True,
        buyer_or_payer_resolved=True,
        supplier_state="OPEN",
        buyer_transition_complete=True,
        decision_horizon_passed=True,
        required_artifacts_present=True,
        evidence_bundle_ref=demand.preflight_evidence_ref,
        lawful_next_action=True,
        permit_decision="ALLOW",
        permit_ref=permit.permit_id,
        permit_sha256=permit.permit_sha256,
        permit_expires_at=permit.expires_at,
        capacity_snapshot_ref=capacity_ref,
        capacity_snapshot_at=EVALUATED_AT - timedelta(minutes=15),
        capacity_available_units=capacity_units,
        economics_snapshot_ref=economics_ref,
        economics_snapshot_at=EVALUATED_AT - timedelta(minutes=30),
        expected_contribution=Decimal("1.00"),
        reviewer_id="fixture-human-hot-reviewer",
        reviewer_is_human=True,
        claim_author_ids=("fixture-model-originator",),
        case_originator_id="fixture-case-originator",
    )
    approval = HumanGoldApproval(
        approval_id=f"offline:approval:{label}",
        decision="ACCEPTED",
        reviewer_id=candidate.reviewer_id,
        reviewer_is_human=True,
        demand_unit_id=demand.demand_unit_id,
        scope_sha256=demand.scope_sha256,
        preflight_sha256=demand.preflight_sha256,
        approved_at=APPROVED_AT,
    )
    queue_store = queue or GdoQueueStore(
        tmp_path / f"queue-{label}.sqlite3",
        max_wip=max_wip,
        daily_intake=10,
        clock=FixedClock(),
    )
    bitrix = shadow or InMemoryBitrixShadow()
    factory = OfflineHotFactory(queue=queue_store, bitrix_shadow=bitrix)
    return {
        "preflight": preflight,
        "demand": demand,
        "permit": permit,
        "candidate": candidate,
        "approval": approval,
        "queue": queue_store,
        "shadow": bitrix,
        "factory": factory,
        "policy": HotGatePolicy(),
        "deadline": APPROVED_AT + timedelta(hours=4),
    }


def _admit(case: dict[str, object]):
    return case["factory"].admit(  # type: ignore[union-attr]
        sealed_preflight=case["preflight"],
        demand=case["demand"],
        hot_candidate=case["candidate"],
        hot_policy=case["policy"],
        offline_permit=case["permit"],
        human_approval=case["approval"],
        deadline_at=case["deadline"],
    )


def test_true_offline_high_intent_flow_reaches_queue_pair_acks_and_daily_count(
    tmp_path: Path,
) -> None:
    case = _scenario(tmp_path)

    result = _admit(case)

    assert result.disposition == "APPLIED"
    assert result.queue_item.state == READY
    assert result.projection_disposition == "APPLIED"
    assert [row.entity_kind for row in result.projections] == ["DEAL", "TASK"]
    assert len({row.projection_id for row in result.projections}) == 2
    assert all(
        row.payload_sha256 == value_sha256(dict(row.payload))
        for row in result.projections
    )
    assert all(
        row.payload["owner_id"] == "fixture-owner-1" for row in result.projections
    )
    assert all(
        row.payload["deadline_at_utc"].endswith("Z") for row in result.projections
    )
    with pytest.raises(TypeError):
        result.projections[0].payload["owner_id"] = "forged"  # type: ignore[index]

    queue = case["queue"]
    owner_ack = queue.ack(  # type: ignore[union-attr]
        result.queue_item.queue_item_id,
        owner_id="fixture-owner-1",
        idempotency_key="offline:owner-ack:one",
    )
    assert owner_ack.item.state == IN_PROGRESS

    shadow = case["shadow"]
    for row in result.projections:
        shadow.acknowledge(  # type: ignore[union-attr]
            row.projection_id,
            acked_at=APPROVED_AT + timedelta(seconds=2),
        )
    bitrix = evaluate_bitrix_shadow(
        shadow.expectations(),  # type: ignore[union-attr]
        shadow.acks(),  # type: ignore[union-attr]
        BitrixShadowPolicy(ack_sla=timedelta(seconds=5)),
    )
    assert bitrix.passed is True
    assert bitrix.expected_count == bitrix.valid_ack_count == 2
    assert bitrix.completeness == Decimal("1")

    snapshots = build_daily_gdo_snapshots(
        [result.daily_counter_event],
        [date(2026, 8, 27)],
        cohort_id=result.demand.cohort_id,
        policy=BusinessDayPolicy(
            timezone=UTC,
            cutoff_local_time=time(18, 0),
            daily_target=1,
        ),
    )
    assert snapshots[0].accepted_count == 1
    assert snapshots[0].accepted_ids == (result.gold_acceptance_id,)
    assert result.gdo10_status == SHADOW_NOT_PROVEN
    assert evaluate_gdo10(snapshots).status == SHADOW_NOT_PROVEN

    public_json = json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True)
    assert "private:" not in public_json.casefold()
    assert "fixture-inbound-payload-001" not in public_json
    assert "current_need_evidence_ref" not in public_json
    assert result.external_effect_count == 0
    assert result.transport_call_count == 0
    assert result.live_bitrix_write_count == 0
    assert shadow.transport_call_count == 0  # type: ignore[union-attr]
    assert shadow.external_effect_count == 0  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("approval_change", "message"),
    [
        ({"reviewer_is_human": False}, "human Gold approval"),
        ({"reviewer_id": "fixture-human-other"}, "human Gold approval"),
        ({"demand_unit_id": "offline:demand:wrong"}, "human Gold approval"),
        ({"scope_sha256": "f" * 64}, "human Gold approval"),
        ({"preflight_sha256": "e" * 64}, "human Gold approval"),
    ],
)
def test_missing_human_or_mismatched_approval_never_mutates_queue(
    tmp_path: Path,
    approval_change: dict[str, object],
    message: str,
) -> None:
    case = _scenario(tmp_path, label=value_sha256(approval_change)[:8])
    case["approval"] = replace(case["approval"], **approval_change)  # type: ignore[arg-type]

    with pytest.raises(OfflineHotFactoryError, match=message):
        _admit(case)

    assert case["queue"].events() == ()  # type: ignore[union-attr]
    assert case["shadow"].envelopes() == ()  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("candidate_change", "reason"),
    [
        ({"capacity_available_units": 0}, "CAPACITY_UNAVAILABLE"),
        (
            {"capacity_snapshot_at": EVALUATED_AT - timedelta(hours=5)},
            "CAPACITY_SNAPSHOT_STALE",
        ),
    ],
)
def test_stale_or_zero_capacity_is_denied_before_queue_mutation(
    tmp_path: Path,
    candidate_change: dict[str, object],
    reason: str,
) -> None:
    case = _scenario(tmp_path, label=reason.casefold())
    case["candidate"] = replace(case["candidate"], **candidate_change)  # type: ignore[arg-type]

    with pytest.raises(OfflineHotFactoryDenied) as denied:
        _admit(case)

    assert reason in denied.value.reason_codes
    assert case["queue"].events() == ()  # type: ignore[union-attr]
    assert case["shadow"].envelopes() == ()  # type: ignore[union-attr]


def test_tampered_preflight_is_rejected_before_queue_mutation(tmp_path: Path) -> None:
    case = _scenario(tmp_path)
    case["preflight"] = {**case["preflight"], "status": "DENIED"}  # type: ignore[dict-item]

    with pytest.raises(OfflineHotFactoryError, match="sealed preflight"):
        _admit(case)

    assert case["queue"].events() == ()  # type: ignore[union-attr]
    assert case["shadow"].envelopes() == ()  # type: ignore[union-attr]


def test_resealed_nonzero_effect_preflight_is_still_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    case = _scenario(tmp_path, label="effect-boundary")
    tampered = {**case["preflight"], "external_effect_count": 1}  # type: ignore[dict-item]
    tampered.pop("bundle_sha256")
    tampered["bundle_sha256"] = value_sha256(tampered)
    case["preflight"] = tampered

    with pytest.raises(OfflineHotFactoryError, match="sealed preflight"):
        _admit(case)

    assert case["queue"].events() == ()  # type: ignore[union-attr]
    assert case["shadow"].envelopes() == ()  # type: ignore[union-attr]


def test_max_wip_admits_hold_but_emits_no_bitrix_projection(tmp_path: Path) -> None:
    queue = GdoQueueStore(
        tmp_path / "bounded.sqlite3",
        max_wip=1,
        daily_intake=10,
        clock=FixedClock(),
    )
    shadow = InMemoryBitrixShadow()
    first_case = _scenario(tmp_path, label="first", queue=queue, shadow=shadow)
    second_case = _scenario(tmp_path, label="second", queue=queue, shadow=shadow)

    first = _admit(first_case)
    second = _admit(second_case)

    assert first.queue_item.state == READY
    assert second.queue_item.state == HOLD
    assert second.queue_item.hold_reason == "MAX_WIP_REACHED"
    assert second.projections == ()
    assert second.projection_disposition == "NOT_READY"
    assert len(shadow.envelopes()) == 2
    assert len(queue.events()) == 2


def test_exact_replay_is_idempotent_for_queue_and_bitrix_pair(tmp_path: Path) -> None:
    case = _scenario(tmp_path)

    first = _admit(case)
    replay = _admit(case)

    assert first.disposition == "APPLIED"
    assert replay.disposition == "REPLAY"
    assert replay.projection_disposition == "REPLAY"
    assert replay.gold_acceptance_sha256 == first.gold_acceptance_sha256
    assert replay.projections == first.projections
    assert len(case["queue"].events()) == 1  # type: ignore[union-attr]
    assert len(case["shadow"].envelopes()) == 2  # type: ignore[union-attr]


def test_bitrix_conflict_is_detected_before_queue_mutation(tmp_path: Path) -> None:
    seed = _scenario(tmp_path, label="projection-conflict")
    seeded_result = _admit(seed)
    conflicting_shadow = InMemoryBitrixShadow()
    conflicting_shadow.publish(
        replace(row, enqueued_at=row.enqueued_at + timedelta(seconds=1))
        for row in seeded_result.projections
    )
    empty_queue = GdoQueueStore(
        tmp_path / "conflict-empty.sqlite3",
        max_wip=3,
        daily_intake=10,
        clock=FixedClock(),
    )
    case = _scenario(
        tmp_path,
        label="projection-conflict",
        queue=empty_queue,
        shadow=conflicting_shadow,
    )

    with pytest.raises(OfflineBitrixShadowConflict, match="projection idempotency"):
        _admit(case)

    assert empty_queue.events() == ()


def test_first_local_ack_is_immutable_and_exact_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    case = _scenario(tmp_path)
    result = _admit(case)
    shadow = case["shadow"]
    first_at = APPROVED_AT + timedelta(seconds=2)

    first = shadow.acknowledge(  # type: ignore[union-attr]
        result.projections[0].projection_id,
        acked_at=first_at,
    )
    replay = shadow.acknowledge(  # type: ignore[union-attr]
        result.projections[0].projection_id,
        acked_at=first_at,
    )
    assert replay == first
    with pytest.raises(OfflineBitrixShadowConflict, match="first ACK"):
        shadow.acknowledge(  # type: ignore[union-attr]
            result.projections[0].projection_id,
            acked_at=first_at + timedelta(seconds=10),
        )
    assert shadow.acks() == (first,)  # type: ignore[union-attr]


def test_non_offline_or_mismatched_permit_never_mutates_queue(tmp_path: Path) -> None:
    case = _scenario(tmp_path)
    bad_permit = replace(case["permit"], permit_id="live:permit:forbidden")  # type: ignore[arg-type]
    case["permit"] = bad_permit
    case["candidate"] = replace(  # type: ignore[arg-type]
        case["candidate"],
        permit_ref=bad_permit.permit_id,
        permit_sha256=bad_permit.permit_sha256,
    )

    with pytest.raises(OfflineHotFactoryError, match="local offline authority"):
        _admit(case)

    assert case["queue"].events() == ()  # type: ignore[union-attr]
    assert case["shadow"].envelopes() == ()  # type: ignore[union-attr]
