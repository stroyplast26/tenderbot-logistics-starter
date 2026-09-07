from __future__ import annotations

from datetime import datetime, timedelta, timezone
import multiprocessing
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.bitrix_rate_gate import (
    BitrixPortalRateGate,
    BitrixRateGateClosed,
    BitrixRateReservation,
)
from lead_factory.legacy_canary_guard import (
    DurableLegacyCanarySelector,
    legacy_canary_holds_legacy_outboxes,
)
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore
from taskbot.bitrix import BitrixTasks


def _reserve_in_other_process(path: str, start, output) -> None:
    """Top-level target so the Windows ``spawn`` context can import it."""
    start.wait(10)
    gate = BitrixPortalRateGate(FactoryStore(path))
    try:
        reservation = gate.reserve()
        gate.check(reservation)
        output.put((
            reservation.reserved_at_utc,
            reservation.fence_token,
            reservation.sequence_number,
        ))
    except Exception as exc:  # pragma: no cover - reported to parent process
        output.put(("ERROR", type(exc).__name__))


def _dispatch_in_other_process(path: str, start, output) -> None:
    """Record the instant the gate permits a callback to start."""
    start.wait(10)
    gate = BitrixPortalRateGate(
        FactoryStore(path), portal_identity="shared-portal", max_dispatch_seconds=1.0
    )
    try:
        def callback(reservation, con):
            output.put(("START", time.monotonic(), reservation.sequence_number))
            return reservation.sequence_number

        gate.dispatch(callback)
    except Exception as exc:  # pragma: no cover - reported to parent process
        output.put(("ERROR", type(exc).__name__))


class _MutableClock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class BitrixPortalRateGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "stage.sqlite3"
        self.store = FactoryStore(self.path)
        self.store.init()
        self.clock = _MutableClock(datetime(2026, 8, 18, 9, 0, tzinfo=timezone.utc))
        self.sleeps: list[float] = []

    def tearDown(self):
        self.temp.cleanup()

    def gate(self, *, store: FactoryStore | None = None) -> BitrixPortalRateGate:
        def sleep(seconds: float) -> None:
            self.sleeps.append(seconds)
            self.clock.now += timedelta(seconds=seconds)

        return BitrixPortalRateGate(
            store or self.store,
            clock=self.clock,
            sleeper=sleep,
        )

    def test_two_processes_reserve_distinct_slots_in_one_portal_bucket(self):
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        workers = [
            context.Process(target=_reserve_in_other_process, args=(str(self.path), start, output))
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        start.set()
        results = [output.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(20)
            self.assertEqual(worker.exitcode, 0)
        self.assertFalse(any(item[0] == "ERROR" for item in results), results)
        slots = sorted(item[0] for item in results)
        first = datetime.fromisoformat(slots[0].replace("Z", "+00:00"))
        second = datetime.fromisoformat(slots[1].replace("Z", "+00:00"))
        self.assertEqual(second - first, timedelta(seconds=1))
        self.assertEqual({item[1] for item in results}, {1})
        self.assertEqual(sorted(item[2] for item in results), [1, 2])

    def test_clock_rollback_never_releases_a_slot_early(self):
        gate = self.gate()
        first = gate.reserve()
        self.clock.now -= timedelta(seconds=1)
        second = gate.reserve()
        self.assertEqual(first.wait_seconds, 0.0)
        self.assertEqual(second.wait_seconds, 2.0)
        self.assertEqual(self.sleeps, [2.0])
        self.assertEqual(
            datetime.fromisoformat(second.reserved_at_utc.replace("Z", "+00:00")),
            datetime(2026, 8, 18, 9, 0, 1, tzinfo=timezone.utc),
        )

    def test_restore_invalidates_an_already_issued_reservation(self):
        pending_id = "pending-before-restore"
        pending_at = "2026-08-18T09:00:00.000000Z"
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO bitrix_rate_gates(
                       portal_identity,next_allowed_at_utc,fence_token,last_sequence,updated_at_utc
                   ) VALUES(?,?,?,?,?)""",
                ("bitrix_portal", pending_at, 1, 1, pending_at),
            )
            con.execute(
                """INSERT INTO bitrix_rate_reservations(
                       reservation_id,portal_identity,fence_token,sequence_number,
                       reserved_at_utc,state,created_at_utc
                   ) VALUES(?,?,?,?,?,'RESERVED',?)""",
                (pending_id, "bitrix_portal", 1, 1, pending_at, pending_at),
            )
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        restored_path = self.root / "restored.sqlite3"
        verify_restore(backup["backup"], restore_path=restored_path)
        restored_gate = self.gate(store=FactoryStore(restored_path))
        reservation = BitrixRateReservation(
            reservation_id=pending_id,
            portal_identity="bitrix_portal",
            fence_token=1,
            sequence_number=1,
            reserved_at_utc=pending_at,
            next_allowed_at_utc=pending_at,
            wait_seconds=0.0,
        )
        with self.assertRaises(BitrixRateGateClosed):
            restored_gate.check(reservation)
        con = sqlite3.connect(restored_path)
        try:
            self.assertEqual(
                con.execute(
                    "SELECT state FROM bitrix_rate_reservations WHERE reservation_id=?",
                    (pending_id,),
                ).fetchone()[0],
                "INVALIDATED",
            )
        finally:
            con.close()

    def test_restore_invalidates_a_precommitted_live_dispatch_hold(self):
        hold_id = "prepared-before-restore"
        now = "2026-08-18T09:00:00.000000Z"
        hold = "2026-08-18T09:02:01.000000Z"
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO bitrix_rate_gates(
                       portal_identity,next_allowed_at_utc,last_actual_start_at_utc,
                       last_dispatch_finished_at_utc,fence_token,last_sequence,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?)""",
                ("live-portal", hold, "", "", 1, 1, now),
            )
            con.execute(
                """INSERT INTO bitrix_rate_reservations(
                       reservation_id,portal_identity,fence_token,sequence_number,
                       reserved_at_utc,state,created_at_utc,hold_until_utc
                   ) VALUES(?,?,?,?,?,'PREPARED',?,?)""",
                (hold_id, "live-portal", 1, 1, now, now, hold),
            )
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        restored_path = self.root / "prepared-restored.sqlite3"
        verify_restore(backup["backup"], restore_path=restored_path)
        con = sqlite3.connect(restored_path)
        try:
            self.assertEqual(
                con.execute(
                    "SELECT state FROM bitrix_rate_reservations WHERE reservation_id=?",
                    (hold_id,),
                ).fetchone()[0],
                "INVALIDATED",
            )
            self.assertEqual(
                con.execute(
                    """SELECT next_allowed_at_utc,last_actual_start_at_utc,
                              last_dispatch_finished_at_utc
                       FROM bitrix_rate_gates WHERE portal_identity='live-portal'"""
                ).fetchone(),
                ("", "", ""),
            )
        finally:
            con.close()

    def test_each_reservation_is_consumed_once_before_return(self):
        reservation = self.gate().reserve()
        self.gate().check(reservation)
        with self.assertRaises(BitrixRateGateClosed):
            self.gate()._consume(reservation)

    def test_later_reservation_does_not_invalidate_an_earlier_consumed_slot(self):
        first = self.gate().reserve()
        second = self.gate().reserve()
        self.gate().check(first)
        self.gate().check(second)
        self.assertEqual((first.fence_token, first.sequence_number), (1, 1))
        self.assertEqual((second.fence_token, second.sequence_number), (1, 2))

    def test_live_dispatch_marks_actual_start_and_serializes_callback_starts(self):
        gate = self.gate()
        starts = []

        def callback(reservation, con):
            self.assertTrue(con.in_transaction)
            starts.append((self.clock.now, reservation.sequence_number))
            return reservation.sequence_number

        self.assertEqual(gate.dispatch(callback), 1)
        self.assertEqual(gate.dispatch(callback), 2)
        self.assertEqual(starts[1][0] - starts[0][0], timedelta(seconds=1))
        self.assertEqual(self.sleeps, [1.0])
        con = self.store.connect()
        try:
            rows = con.execute(
                """SELECT state,dispatch_started_at_utc,dispatched_at_utc
                   FROM bitrix_rate_reservations ORDER BY sequence_number"""
            ).fetchall()
            events = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE producer='bitrix_rate_gate'
                     AND event_type='bitrix_rate_dispatch_prepared'"""
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual([row["state"] for row in rows], ["DISPATCHED", "DISPATCHED"])
        self.assertTrue(all(row["dispatch_started_at_utc"] and row["dispatched_at_utc"] for row in rows))
        self.assertEqual(events, 2)

    def test_live_dispatch_commits_terminal_record_before_reraising_callback_error(self):
        def callback(reservation, con):
            raise TimeoutError("fixture")

        with self.assertRaises(TimeoutError):
            self.gate().dispatch(callback)
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT state,dispatch_started_at_utc,dispatched_at_utc,dispatch_error_class
                   FROM bitrix_rate_reservations"""
            ).fetchone()
        finally:
            con.close()
        self.assertEqual(
            (row["state"], row["dispatch_error_class"]),
            ("DISPATCHED", "TimeoutError"),
        )
        self.assertTrue(row["dispatch_started_at_utc"] and row["dispatched_at_utc"])

    def test_validator_blocks_before_callback_and_releases_unused_hold(self):
        called = []

        def validator(reservation, con):
            raise RuntimeError("stopped")

        def callback(reservation, con):
            called.append(reservation.reservation_id)

        with self.assertRaises(RuntimeError):
            self.gate().dispatch(callback, validator=validator)
        self.assertEqual(called, [])
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT state,hold_until_utc,dispatch_started_at_utc,dispatch_error_class
                   FROM bitrix_rate_reservations"""
            ).fetchone()
        finally:
            con.close()
        self.assertEqual((row["state"], row["dispatch_error_class"]), ("BLOCKED", "RuntimeError"))
        self.assertTrue(row["hold_until_utc"])
        self.assertEqual(row["dispatch_started_at_utc"], "")
        # A denied validator proves that no callback/HTTP was entered. Its
        # conservative crash hold may therefore be released when no later
        # reservation exists; the next safe dispatch need not wait 121s.
        starts = []
        self.assertEqual(
            self.gate().dispatch(lambda reservation, _con: starts.append(reservation.sequence_number)),
            None,
        )
        self.assertEqual(starts, [2])
        self.assertEqual(self.sleeps, [])

    def test_expired_prepared_is_audited_before_later_dispatch_and_paused_callback(self):
        """A caller paused after phase 1 never reaches a later callback."""
        gate_a = self.gate()
        gate_b = self.gate()
        original_prepare = gate_a._prepare_dispatch
        prepared = threading.Event()
        resume_a = threading.Event()
        prepared_records = []
        callback_a = []
        errors_a = []

        def _pause_after_prepare():
            reservation = original_prepare()
            prepared_records.append(reservation)
            prepared.set()
            if not resume_a.wait(5):
                raise TimeoutError("test did not resume paused dispatch")
            return reservation

        gate_a._prepare_dispatch = _pause_after_prepare

        def _run_a():
            try:
                gate_a.dispatch(lambda reservation, _con: callback_a.append(reservation.sequence_number))
            except BaseException as exc:  # asserted from owner thread
                errors_a.append(exc)

        thread_a = threading.Thread(target=_run_a, daemon=True)
        thread_a.start()
        self.assertTrue(prepared.wait(3), "phase-1 reservation was not prepared")
        # Cross A's conservative PREPARED TTL before B attempts its own
        # admission. B's phase 1 must expire and audit A atomically.
        self.clock.now += timedelta(
            seconds=gate_a.max_dispatch_seconds + gate_a.min_gap_seconds
        )
        callback_b = []
        gate_b.dispatch(lambda reservation, _con: callback_b.append(reservation.sequence_number))
        resume_a.set()
        thread_a.join(5)
        self.assertFalse(thread_a.is_alive())
        self.assertEqual(callback_a, [])
        self.assertEqual(callback_b, [2])
        self.assertEqual(len(errors_a), 1)
        self.assertIsInstance(errors_a[0], BitrixRateGateClosed)
        reservation_a = prepared_records[0]
        con = self.store.connect()
        try:
            state = con.execute(
                "SELECT state FROM bitrix_rate_reservations WHERE reservation_id=?",
                (reservation_a.reservation_id,),
            ).fetchone()[0]
            audit = con.execute(
                """SELECT payload_json FROM events
                   WHERE producer='bitrix_rate_gate' AND event_type='bitrix_rate_dispatch_expired'
                     AND aggregate_id=?""",
                (reservation_a.reservation_id,),
            ).fetchone()
        finally:
            con.close()
        self.assertEqual(state, "EXPIRED")
        self.assertIsNotNone(audit)

    def test_late_phase_two_is_expired_before_callback_so_crash_hold_keeps_gap(self):
        """A phase-2 pause cannot start a request in the final crash gap.

        If A were allowed to start at ``hold_until - epsilon`` and then died
        before committing its actual start, B could expire A at the hold and
        start too soon after A's possible provider request.  The safe policy
        is to expire A before its callback and let B be the first actual
        callback at the durable hold boundary.
        """
        gate_a = self.gate()
        gate_b = self.gate()
        original_prepare = gate_a._prepare_dispatch
        prepared = threading.Event()
        resume_a = threading.Event()
        records = []
        callback_a = []
        errors_a = []

        def _pause_after_prepare():
            reservation = original_prepare()
            records.append(reservation)
            prepared.set()
            if not resume_a.wait(5):
                raise TimeoutError("test did not resume late phase-2 caller")
            return reservation

        gate_a._prepare_dispatch = _pause_after_prepare

        def _run_a():
            try:
                gate_a.dispatch(lambda reservation, _con: callback_a.append(reservation.sequence_number))
            except BaseException as exc:  # asserted from owner thread
                errors_a.append(exc)

        thread_a = threading.Thread(target=_run_a, daemon=True)
        thread_a.start()
        self.assertTrue(prepared.wait(3), "phase-1 reservation was not prepared")
        # Resume A less than one full portal gap before its conservative hold
        # expires.  It must be terminally expired without an HTTP callback.
        self.clock.now += timedelta(
            seconds=gate_a.max_dispatch_seconds + gate_a.min_gap_seconds - 0.25
        )
        resume_a.set()
        thread_a.join(5)
        self.assertFalse(thread_a.is_alive())
        self.assertEqual(callback_a, [])
        self.assertEqual(len(errors_a), 1)
        self.assertIsInstance(errors_a[0], BitrixRateGateClosed)

        started_b = []
        gate_b.dispatch(lambda reservation, _con: started_b.append(self.clock.now))
        self.assertEqual(len(started_b), 1)
        reservation_a = records[0]
        hold_until = datetime.fromisoformat(
            reservation_a.next_allowed_at_utc.replace("Z", "+00:00")
        )
        # B is the next possible actual callback and begins at/after A's
        # crash hold. Since A was not permitted to start inside the final
        # min_gap, every possible A start remains at least one gap before B.
        self.assertGreaterEqual(started_b[0], hold_until)
        con = self.store.connect()
        try:
            state = con.execute(
                "SELECT state FROM bitrix_rate_reservations WHERE reservation_id=?",
                (reservation_a.reservation_id,),
            ).fetchone()[0]
            actual_starts = con.execute(
                """SELECT COUNT(*) FROM bitrix_rate_reservations
                   WHERE dispatch_started_at_utc<>''"""
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(state, "EXPIRED")
        self.assertEqual(actual_starts, 1)

    def test_two_processes_cannot_start_live_callbacks_inside_one_gap(self):
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        output = context.Queue()
        workers = [
            context.Process(target=_dispatch_in_other_process, args=(str(self.path), start, output))
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        start.set()
        results = [output.get(timeout=25) for _ in workers]
        for worker in workers:
            worker.join(25)
            self.assertEqual(worker.exitcode, 0)
        self.assertFalse(any(row[0] == "ERROR" for row in results), results)
        starts = sorted(row[1] for row in results if row[0] == "START")
        self.assertEqual(len(starts), 2)
        self.assertGreaterEqual(starts[1] - starts[0], 0.95)

    def test_database_error_is_fail_closed(self):
        with patch.object(self.store, "transaction", side_effect=sqlite3.OperationalError("locked")):
            with self.assertRaises(BitrixRateGateClosed):
                self.gate().reserve()

    def test_writers_disabled_preserves_legacy_taskbot_path(self):
        selector = DurableLegacyCanarySelector(self.store)
        self.assertFalse(legacy_canary_holds_legacy_outboxes(selector=selector))
        client = BitrixTasks("https://example.test/rest/1/token")
        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=False),
            patch.object(client, "_call", return_value={"task": {"id": "5"}}) as rest,
        ):
            self.assertEqual(
                client.create_task(
                    title="fixture", responsible_id=1, deadline=None,
                    priority="low", creator_tg_id=1,
                ),
                5,
            )
        self.assertEqual(rest.call_count, 1)
        self.assertEqual(
            self.store.status()["schema_version"], str(CURRENT_SCHEMA_VERSION)
        )
        self.assertEqual(self.store.status()["bitrix_rate_gates"], 0)


if __name__ == "__main__":
    unittest.main()
