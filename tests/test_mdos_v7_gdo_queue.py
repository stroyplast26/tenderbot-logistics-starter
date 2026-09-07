from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path
from threading import Barrier

import pytest

from lead_factory.mdos_v7.contracts import (
    CONTRACT_ID,
    PACKAGE_ROOT_SHA256,
    PACKAGE_VERSION,
    value_sha256,
)
from lead_factory.mdos_v7.gdo_queue import (
    CANONICAL_SCHEMA_FINGERPRINT_SHA256,
    DONE,
    HOLD,
    IN_PROGRESS,
    READY,
    GdoQueueAdmission,
    GdoQueueBackpressure,
    GdoQueueCapacityConflict,
    GdoQueueDuplicateItem,
    GdoQueueIdempotencyConflict,
    GdoQueueIntegrityError,
    GdoQueueMetadataTamper,
    GdoQueueStore,
    GdoQueueTransitionError,
    GdoQueueValidationError,
)


NOW = datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **delta: int) -> None:
        self.value += timedelta(**delta)

    def set(self, value: datetime) -> None:
        self.value = value


def _utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _digest(label: str) -> str:
    return value_sha256({"offline_fixture": label})


def _admission(
    index: int,
    *,
    capacity_slots: int = 10,
    capacity_pool_id: str = "capacity-pool-main",
    observed_at: datetime | None = None,
    valid_until: datetime | None = None,
    deadline: datetime | None = None,
    idempotency_key: str | None = None,
    **changes: object,
) -> GdoQueueAdmission:
    observed = observed_at or NOW - timedelta(minutes=5)
    expires = valid_until or NOW + timedelta(days=3)
    values: dict[str, object] = {
        "queue_item_id": f"gdoq-fixture-{index}",
        "demand_unit_id": f"demand-fixture-{index}",
        "gold_acceptance_id": f"gold-fixture-{index}",
        "demand_unit_sha256": _digest(f"demand-{index}"),
        "gold_acceptance_sha256": _digest(f"gold-{index}"),
        "scope_sha256": _digest("scope-aluminium-moscow"),
        "hot_gate_sha256": _digest(f"hot-gate-{index}"),
        "permit_decision_sha256": _digest(f"permit-{index}"),
        "capacity_snapshot_sha256": _digest(
            f"capacity:{capacity_pool_id}:{capacity_slots}:{_utc(observed)}:{_utc(expires)}"
        ),
        "economics_snapshot_sha256": _digest(f"economics-{index}"),
        "hot_gate_passed": True,
        "permit_allows_offline_queue": True,
        "capacity_pool_id": capacity_pool_id,
        "capacity_slots": capacity_slots,
        "capacity_observed_at_utc": _utc(observed),
        "capacity_valid_until_utc": _utc(expires),
        "owner_id": "dima",
        "deadline_at_utc": _utc(deadline or NOW + timedelta(hours=4)),
        "idempotency_key": idempotency_key or f"enqueue-fixture-{index}",
    }
    values.update(changes)
    return GdoQueueAdmission.from_mapping(values)


def _store(
    tmp_path: Path,
    *,
    max_wip: int = 5,
    daily_intake: int = 10,
    max_queue_depth: int = 1_000,
    business_utc_offset_minutes: int = 180,
    clock: MutableClock | None = None,
    name: str = "gdo-queue.sqlite3",
) -> GdoQueueStore:
    return GdoQueueStore(
        tmp_path / name,
        max_wip=max_wip,
        daily_intake=daily_intake,
        max_queue_depth=max_queue_depth,
        business_utc_offset_minutes=business_utc_offset_minutes,
        clock=clock or MutableClock(),
    )


def test_store_is_exact_offline_shadow_non_kpi_and_has_no_transport(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, max_wip=3, daily_intake=7)
    snapshot = store.snapshot()
    assert snapshot.to_dict() == {
        "as_of_utc": "2026-08-27T09:00:00Z",
        "depth": 0,
        "ready": 0,
        "in_progress": 0,
        "hold": 0,
        "done": 0,
        "active_wip": 0,
        "available_wip_slots": 3,
        "max_wip": 3,
        "available_queue_depth": 1000,
        "max_queue_depth": 1000,
        "daily_intake_used": 0,
        "daily_intake_limit": 7,
        "business_utc_offset_minutes": 180,
        "active_by_capacity_pool": (),
        "oldest_open_age_seconds": 0,
        "sla_breaches": 0,
        "sla_breach_item_ids": (),
        "backpressure": False,
        "backpressure_reasons": (),
        "mode": "OFFLINE_SHADOW",
        "canonical_kpi_eligible": False,
        "external_effect_count": 0,
        "transport_call_count": 0,
    }
    with sqlite3.connect(store.path) as connection:
        metadata = dict(connection.execute("SELECT key,value FROM gdo_queue_meta"))
    assert metadata["contract_id"] == CONTRACT_ID
    assert metadata["package_version"] == PACKAGE_VERSION
    assert metadata["contract_root_sha256"] == PACKAGE_ROOT_SHA256
    assert metadata["package_root_sha256"] == PACKAGE_ROOT_SHA256
    assert metadata["environment"] == "OFFLINE_SHADOW"
    assert metadata["canonical_kpi_eligible"] == "0"
    assert metadata["transport_enabled"] == "0"
    assert metadata["credentials_allowed"] == "0"
    assert metadata["max_queue_depth"] == "1000"
    assert metadata["business_utc_offset_minutes"] == "180"
    assert metadata["schema_fingerprint_sha256"] == CANONICAL_SCHEMA_FINGERPRINT_SHA256


def test_concurrent_clean_bootstrap_builds_one_canonical_store(tmp_path: Path) -> None:
    path = tmp_path / "bootstrap-race.sqlite3"
    barrier = Barrier(2)

    def construct() -> tuple[int, str]:
        barrier.wait()
        store = GdoQueueStore(path, max_wip=3, daily_intake=7)
        return store.snapshot().depth, str(store.path)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: construct(), range(2)))

    assert results == [(0, str(path.resolve())), (0, str(path.resolve()))]
    reopened = GdoQueueStore(path, max_wip=3, daily_intake=7)
    assert reopened.snapshot().depth == 0


def test_begin_immediate_makes_concurrent_n_plus_one_exactly_one_ready(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, max_wip=1, daily_intake=10)

    def admit(index: int) -> str:
        return store.enqueue(_admission(index, capacity_slots=5)).item.state

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = list(executor.map(admit, (1, 2)))

    assert sorted(states) == [HOLD, READY]
    snapshot = store.snapshot()
    assert snapshot.active_wip == 1
    assert snapshot.depth == 2
    assert snapshot.hold == 1
    assert snapshot.backpressure is True
    assert "MAX_WIP_REACHED" in snapshot.backpressure_reasons


def test_capacity_slot_n_plus_one_and_daily_intake_create_bounded_hold(
    tmp_path: Path,
) -> None:
    capacity_store = _store(
        tmp_path, max_wip=5, daily_intake=10, name="capacity.sqlite3"
    )
    assert (
        capacity_store.enqueue(
            _admission(1, capacity_slots=1, capacity_pool_id="capacity-pool-a")
        ).item.state
        == READY
    )
    assert (
        capacity_store.enqueue(
            _admission(2, capacity_slots=1, capacity_pool_id="capacity-pool-b")
        ).item.state
        == READY
    )
    held = capacity_store.enqueue(
        _admission(3, capacity_slots=1, capacity_pool_id="capacity-pool-a")
    ).item
    assert (held.state, held.hold_reason, held.slot_reserved) == (
        HOLD,
        "CAPACITY_SLOTS_EXHAUSTED",
        False,
    )
    assert capacity_store.snapshot().active_by_capacity_pool == (
        ("capacity-pool-a", 1),
        ("capacity-pool-b", 1),
    )

    clock = MutableClock()
    daily_store = _store(
        tmp_path,
        max_wip=5,
        daily_intake=1,
        clock=clock,
        name="daily.sqlite3",
    )
    assert daily_store.enqueue(_admission(11)).item.state == READY
    daily_held = daily_store.enqueue(_admission(12)).item
    assert daily_held.hold_reason == "DAILY_INTAKE_REACHED"
    clock.advance(days=1)
    promoted = daily_store.transition(
        daily_held.queue_item_id,
        target_state=READY,
        owner_id="dima",
        idempotency_key="promote-next-day",
        reason_code="NEXT_DAY_CAPACITY",
    )
    assert promoted.item.state == READY
    assert promoted.slot_delta == 1


def test_capacity_snapshots_are_monotonic_per_pool_and_conflicts_fail_closed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, max_wip=10, daily_intake=10)
    newest = _admission(
        1,
        capacity_pool_id="capacity-pool-a",
        capacity_slots=5,
        observed_at=NOW - timedelta(minutes=2),
        valid_until=NOW + timedelta(days=1),
    )
    pool_b_older = _admission(
        2,
        capacity_pool_id="capacity-pool-b",
        capacity_slots=5,
        observed_at=NOW - timedelta(minutes=20),
        valid_until=NOW + timedelta(days=1),
    )
    assert store.enqueue(newest).item.state == READY
    assert store.enqueue(pool_b_older).item.state == READY

    rollback = store.enqueue(
        _admission(
            3,
            capacity_pool_id="capacity-pool-a",
            capacity_slots=5,
            observed_at=NOW - timedelta(minutes=10),
            valid_until=NOW + timedelta(days=1),
        )
    ).item
    assert (rollback.state, rollback.hold_reason, rollback.slot_reserved) == (
        HOLD,
        "CAPACITY_SNAPSHOT_ROLLBACK",
        False,
    )
    with pytest.raises(GdoQueueBackpressure) as rollback_promotion:
        store.transition(
            rollback.queue_item_id,
            target_state=READY,
            owner_id="dima",
            idempotency_key="promote-rollback",
            reason_code="CAPACITY_RECHECKED",
        )
    assert rollback_promotion.value.reason_code == "CAPACITY_SNAPSHOT_ROLLBACK"

    with pytest.raises(GdoQueueCapacityConflict):
        store.enqueue(
            _admission(
                4,
                capacity_pool_id="capacity-pool-a",
                capacity_slots=5,
                observed_at=NOW - timedelta(minutes=2),
                valid_until=NOW + timedelta(days=1),
                capacity_snapshot_sha256=_digest("conflicting-same-time-snapshot"),
            )
        )
    with pytest.raises(GdoQueueCapacityConflict):
        store.enqueue(
            _admission(
                5,
                capacity_pool_id="capacity-pool-b",
                capacity_slots=9,
                observed_at=NOW - timedelta(minutes=1),
                valid_until=NOW + timedelta(days=2),
                capacity_snapshot_sha256=newest.capacity_snapshot_sha256,
            )
        )
    assert store.snapshot().active_by_capacity_pool == (
        ("capacity-pool-a", 1),
        ("capacity-pool-b", 1),
    )


def test_queue_depth_is_a_hard_bounded_backpressure_gate(tmp_path: Path) -> None:
    store = _store(tmp_path, max_wip=1, max_queue_depth=2)
    assert store.enqueue(_admission(1)).item.state == READY
    assert store.enqueue(_admission(2)).item.state == HOLD
    with pytest.raises(GdoQueueBackpressure) as full:
        store.enqueue(_admission(3))
    assert full.value.reason_code == "MAX_QUEUE_DEPTH_REACHED"
    snapshot = store.snapshot()
    assert (snapshot.depth, snapshot.available_queue_depth) == (2, 0)
    assert "MAX_QUEUE_DEPTH_REACHED" in snapshot.backpressure_reasons


def test_daily_window_uses_the_pinned_business_utc_offset(tmp_path: Path) -> None:
    clock = MutableClock(datetime(2026, 8, 27, 20, 59, tzinfo=timezone.utc))
    store = _store(tmp_path, daily_intake=1, clock=clock)

    def at_clock(index: int) -> GdoQueueAdmission:
        return _admission(
            index,
            observed_at=clock.value - timedelta(minutes=5),
            valid_until=clock.value + timedelta(days=1),
            deadline=clock.value + timedelta(hours=4),
        )

    assert store.enqueue(at_clock(1)).item.state == READY
    held = store.enqueue(at_clock(2)).item
    assert held.hold_reason == "DAILY_INTAKE_REACHED"
    clock.advance(minutes=2)
    promoted = store.transition(
        held.queue_item_id,
        target_state=READY,
        owner_id="dima",
        idempotency_key="business-midnight-promotion",
        reason_code="NEW_BUSINESS_DAY",
    )
    assert promoted.item.state == READY
    assert store.snapshot().daily_intake_used == 1


def test_zero_and_stale_capacity_never_reserve_a_slot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    zero = store.enqueue(_admission(1, capacity_slots=0)).item
    stale = store.enqueue(
        _admission(
            2,
            capacity_pool_id="capacity-pool-stale",
            capacity_slots=4,
            observed_at=NOW - timedelta(hours=2),
            valid_until=NOW - timedelta(seconds=1),
        )
    ).item
    assert (zero.state, zero.hold_reason, zero.slot_reserved) == (
        HOLD,
        "CAPACITY_ZERO",
        False,
    )
    assert (stale.state, stale.hold_reason, stale.slot_reserved) == (
        HOLD,
        "CAPACITY_STALE",
        False,
    )
    snapshot = store.snapshot()
    assert snapshot.active_wip == 0
    assert snapshot.backpressure_reasons == ("CAPACITY_STALE", "CAPACITY_ZERO")


def test_exact_duplicate_replays_and_changed_or_rekeyed_duplicate_fails(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    payload = _admission(1)
    first = store.enqueue(payload)
    replay = store.enqueue(payload)
    assert first.disposition == "APPLIED"
    assert replay.disposition == "REPLAY"
    assert replay.event_id == first.event_id
    assert len(store.events(payload.queue_item_id)) == 1

    changed = _admission(
        1,
        demand_unit_sha256=_digest("changed-demand"),
    )
    with pytest.raises(GdoQueueIdempotencyConflict):
        store.enqueue(changed)

    rekeyed = _admission(
        99,
        demand_unit_sha256=payload.demand_unit_sha256,
        gold_acceptance_sha256=payload.gold_acceptance_sha256,
        scope_sha256=payload.scope_sha256,
        idempotency_key="rekeyed-duplicate",
    )
    with pytest.raises(GdoQueueDuplicateItem):
        store.enqueue(rekeyed)

    same_demand_new_scope = _admission(
        100,
        demand_unit_id=payload.demand_unit_id,
        demand_unit_sha256=_digest("resealed-demand-with-new-scope"),
        scope_sha256=_digest("changed-scope"),
        idempotency_key="same-demand-new-scope",
    )
    with pytest.raises(GdoQueueDuplicateItem):
        store.enqueue(same_demand_new_scope)

    same_gold_new_scope = _admission(
        101,
        gold_acceptance_id=payload.gold_acceptance_id,
        gold_acceptance_sha256=_digest("resealed-gold-with-new-scope"),
        scope_sha256=_digest("another-changed-scope"),
        idempotency_key="same-gold-new-scope",
    )
    with pytest.raises(GdoQueueDuplicateItem):
        store.enqueue(same_gold_new_scope)

    same_demand_digest_new_ids_and_scope = _admission(
        102,
        demand_unit_sha256=payload.demand_unit_sha256,
        scope_sha256=_digest("digest-attack-scope-a"),
        idempotency_key="same-demand-digest-new-ids",
    )
    with pytest.raises(GdoQueueDuplicateItem):
        store.enqueue(same_demand_digest_new_ids_and_scope)

    same_gold_digest_new_ids_and_scope = _admission(
        103,
        gold_acceptance_sha256=payload.gold_acceptance_sha256,
        scope_sha256=_digest("digest-attack-scope-b"),
        idempotency_key="same-gold-digest-new-ids",
    )
    with pytest.raises(GdoQueueDuplicateItem):
        store.enqueue(same_gold_digest_new_ids_and_scope)
    assert store.snapshot().depth == 1


def test_transitions_release_once_and_a_held_item_can_take_the_slot(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    store = _store(tmp_path, max_wip=1, daily_intake=10, clock=clock)
    first = store.enqueue(_admission(1)).item
    second = store.enqueue(_admission(2)).item
    assert (first.state, second.state) == (READY, HOLD)

    clock.advance(minutes=1)
    acknowledged = store.ack(
        first.queue_item_id,
        owner_id="dima",
        idempotency_key="ack-first",
    )
    assert acknowledged.item.state == IN_PROGRESS
    assert acknowledged.slot_delta == 0

    clock.advance(minutes=1)
    completed = store.transition(
        first.queue_item_id,
        target_state=DONE,
        owner_id="dima",
        idempotency_key="done-first",
        reason_code="QUALIFIED_HANDOFF_COMPLETE",
    )
    replay = store.transition(
        first.queue_item_id,
        target_state=DONE,
        owner_id="dima",
        idempotency_key="done-first",
        reason_code="QUALIFIED_HANDOFF_COMPLETE",
    )
    assert completed.slot_delta == -1
    assert completed.item.slot_reserved is False
    assert completed.item.slot_released_at_utc == "2026-08-27T09:02:00Z"
    assert replay.disposition == "REPLAY"
    assert replay.event_id == completed.event_id
    assert [event["slot_delta"] for event in store.events(first.queue_item_id)] == [
        1,
        0,
        -1,
    ]

    promoted = store.transition(
        second.queue_item_id,
        target_state=READY,
        owner_id="dima",
        idempotency_key="promote-second",
        reason_code="CAPACITY_RELEASED",
    )
    assert promoted.item.state == READY
    assert promoted.slot_delta == 1
    snapshot = store.snapshot()
    assert (snapshot.done, snapshot.ready, snapshot.active_wip) == (1, 1, 1)


def test_only_in_progress_can_complete_and_event_time_cannot_move_backwards(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    store = _store(tmp_path, max_wip=1, clock=clock)
    ready = store.enqueue(_admission(1)).item
    held = store.enqueue(_admission(2)).item
    with pytest.raises(GdoQueueTransitionError):
        store.transition(
            ready.queue_item_id,
            target_state=DONE,
            owner_id="dima",
            idempotency_key="invalid-ready-done",
            reason_code="INVALID_COMPLETION",
        )
    with pytest.raises(GdoQueueValidationError, match="OWNER_ACKNOWLEDGED"):
        store.transition(
            ready.queue_item_id,
            target_state=IN_PROGRESS,
            owner_id="dima",
            idempotency_key="invalid-ack-reason",
            reason_code="SOMETHING_ELSE",
        )
    with pytest.raises(GdoQueueTransitionError):
        store.transition(
            held.queue_item_id,
            target_state=DONE,
            owner_id="dima",
            idempotency_key="invalid-hold-done",
            reason_code="INVALID_COMPLETION",
        )

    clock.set(NOW - timedelta(seconds=1))
    with pytest.raises(GdoQueueValidationError, match="cannot move backwards"):
        store.ack(
            ready.queue_item_id,
            owner_id="dima",
            idempotency_key="clock-rollback-ack",
        )
    assert len(store.events(ready.queue_item_id)) == 1


def test_deadline_and_privacy_minimised_tokens_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(GdoQueueValidationError, match="future"):
        store.enqueue(_admission(1, deadline=NOW))
    with pytest.raises(GdoQueueValidationError, match="future"):
        store.enqueue(_admission(2, deadline=NOW - timedelta(seconds=1)))
    with pytest.raises(GdoQueueValidationError, match="safe token"):
        store.enqueue(_admission(3, owner_id="dima@example.com"))
    with pytest.raises(GdoQueueValidationError, match="safe token"):
        store.enqueue(_admission(4, owner_id="+79991234567"))
    with pytest.raises(GdoQueueValidationError, match="safe token"):
        store.enqueue(_admission(5, owner_id="79991234567"))
    with pytest.raises(GdoQueueValidationError, match="safe token"):
        store.enqueue(_admission(6, owner_id="tel:79991234567"))


def test_malformed_clock_is_a_validation_error(tmp_path: Path) -> None:
    store = GdoQueueStore(
        tmp_path / "bad-clock.sqlite3",
        max_wip=1,
        daily_intake=1,
        clock=lambda: "not-a-datetime",  # type: ignore[return-value]
    )
    with pytest.raises(GdoQueueValidationError, match="timezone-aware"):
        store.snapshot()


def test_snapshot_makes_oldest_age_and_sla_breach_visible(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path, clock=clock)
    store.enqueue(_admission(1, deadline=NOW + timedelta(minutes=5)))
    clock.advance(minutes=5)
    snapshot = store.snapshot()
    assert snapshot.oldest_open_age_seconds == 300
    assert snapshot.sla_breaches == 1
    assert snapshot.sla_breach_item_ids == ("gdoq-fixture-1",)


def test_metadata_and_append_only_event_tamper_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.enqueue(_admission(1))

    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="metadata is immutable"):
            connection.execute(
                "UPDATE gdo_queue_meta SET value='0' WHERE key='contract_root_sha256'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="events are append-only"):
            connection.execute("UPDATE gdo_queue_events SET reason_code='FORGED'")
        with pytest.raises(sqlite3.IntegrityError, match="events are append-only"):
            connection.execute("DELETE FROM gdo_queue_events")

    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER trg_gdo_queue_meta_no_update")
        connection.execute(
            "UPDATE gdo_queue_meta SET value=? WHERE key='contract_root_sha256'",
            ("f" * 64,),
        )
        connection.commit()
    with pytest.raises(GdoQueueMetadataTamper):
        store.snapshot()


@pytest.mark.parametrize(
    ("column", "forged"),
    [
        ("state", HOLD),
        ("hold_reason", "FORGED"),
        ("slot_reserved", 0),
        ("started_at_utc", "2026-08-27T09:01:00Z"),
        ("completed_at_utc", "2026-08-27T09:02:00Z"),
        ("slot_released_at_utc", "2026-08-27T09:03:00Z"),
        ("last_event_id", "gdoq-event-forged"),
        ("last_event_sha256", "f" * 64),
        ("version", 99),
    ],
)
def test_each_mutable_projection_field_is_rebuilt_from_events(
    tmp_path: Path, column: str, forged: object
) -> None:
    store = _store(tmp_path, name=f"projection-{column}.sqlite3")
    store.enqueue(_admission(1))
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            f"UPDATE gdo_queue_items SET {column}=? WHERE queue_item_id=?",
            (forged, "gdoq-fixture-1"),
        )
        connection.commit()
    with pytest.raises(GdoQueueIntegrityError, match="projection differs"):
        store.snapshot()


def test_schema_fingerprint_is_pinned_not_self_attested(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER trg_gdo_queue_events_no_update")
        connection.execute("DROP TRIGGER trg_gdo_queue_meta_no_update")
        forged_fingerprint = store._schema_fingerprint(connection)
        assert forged_fingerprint != CANONICAL_SCHEMA_FINGERPRINT_SHA256
        connection.execute(
            """UPDATE gdo_queue_meta SET value=?
               WHERE key='schema_fingerprint_sha256'""",
            (forged_fingerprint,),
        )
        connection.commit()
    with pytest.raises(GdoQueueMetadataTamper, match="schema inventory"):
        store.snapshot()
