from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lead_factory import store as store_module
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.recovery import RecoveryError, create_backup, verify_restore
from lead_factory.source_lab import SourceLabConflict, SourceLabSink
from lead_factory.source_lab_integrity import (
    SourceLabIntegrityError,
    validate_source_lab_integrity,
)
from lead_factory.source_review_queue import (
    QUEUE_PRODUCER,
    ReviewClaimPermit,
    SourceReviewQueue,
    SourceReviewQueueConflict,
    SourceReviewQueueError,
    SourceReviewQueueIntegrityError,
    SourceReviewQueueStaleClaim,
    validate_source_review_queue_integrity,
)


class _MutableClock:
    def __init__(self, value: datetime) -> None:
        self._value = value
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._value

    def set(self, value: datetime) -> None:
        with self._lock:
            self._value = value

    def advance(self, *, seconds: int) -> None:
        with self._lock:
            self._value += timedelta(seconds=seconds)


class _CrashAfterSourceLabResolution(SourceReviewQueue):
    def _after_resolution_before_queue_event(self, result) -> None:
        raise RuntimeError("injected crash after Source Lab resolution")


class _UnsafeV16QueueStore(store_module.FactoryStore):
    """Test seam that proves recovery rejects a queue fact below schema 17."""

    @contextmanager
    def transaction(self, *, min_schema_version: int = 13):
        with super().transaction(min_schema_version=16) as con:
            yield con


class SourceReviewQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "source-review-queue.sqlite3"
        self.store = store_module.FactoryStore(self.database)
        self.store.init()
        self.clock = _MutableClock(
            datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        )
        self.sink = SourceLabSink(self.store, clock=self.clock)
        self.queue = SourceReviewQueue(self.store, clock=self.clock)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _create_review(self, suffix: str = "one") -> str:
        record = self.sink.ingest_record(
            source_id="tenderplan",
            acquisition_mode="manual_export",
            run_key=f"queue-run-{suffix}",
            external_key=f"queue-record-{suffix}",
            payload={"title": f"Queue fixture {suffix}"},
            observed_at_utc="2026-08-21T10:00:00Z",
            evidence_ref=f"evidence://queue/record/{suffix}",
            idempotency_key=f"queue-record-{suffix}",
            canonical_keys=(f"external:tenderplan:{suffix}",),
        )
        review = self.sink.request_review(
            source_record_id=record.source_record_id,
            reason="Check commercial relevance",
            requested_by="source-review-tests",
            evidence_ref=f"evidence://queue/review/{suffix}",
            idempotency_key=f"queue-review-{suffix}",
        )
        return review.review_id

    def _item(self, review_id: str):
        matches = [
            item
            for item in self.queue.list_open(limit=100).items
            if item.review_id == review_id
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _claim(
        self,
        review_id: str,
        *,
        claimant: str = "reviewer-a",
        idempotency_key: str = "claim-one",
        expected_state_digest: str = "",
        lease_seconds: int = 30,
    ) -> ReviewClaimPermit:
        digest = expected_state_digest or self._item(review_id).state_digest
        return self.queue.claim(
            review_id=review_id,
            claimant=claimant,
            evidence_ref=f"evidence://queue/claim/{idempotency_key}",
            idempotency_key=idempotency_key,
            expected_state_digest=digest,
            lease_seconds=lease_seconds,
        )

    def _count(self, table: str) -> int:
        return self.store.table_count(table)

    def _queue_event_count(self) -> int:
        con = self.store.connect()
        try:
            return int(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE producer=?",
                    (QUEUE_PRODUCER,),
                ).fetchone()[0]
            )
        finally:
            con.close()

    def test_two_concurrent_claimers_create_exactly_one_active_claim(self) -> None:
        review_id = self._create_review("race")
        expected = self._item(review_id).state_digest
        barrier = threading.Barrier(2)

        def attempt(index: int):
            queue = SourceReviewQueue(
                store_module.FactoryStore(self.database), clock=self.clock
            )
            claimant = f"reviewer-{index}"
            barrier.wait(timeout=5)
            try:
                return queue.claim(
                    review_id=review_id,
                    claimant=claimant,
                    evidence_ref=f"evidence://queue/race/{index}",
                    idempotency_key=f"race-{index}",
                    expected_state_digest=expected,
                    lease_seconds=30,
                )
            except Exception as exc:  # the losing concurrent command is evidence
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(attempt, (1, 2)))

        permits = [item for item in outcomes if isinstance(item, ReviewClaimPermit)]
        failures = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(permits), 1)
        self.assertTrue(permits[0].created)
        self.assertTrue(permits[0].active)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], SourceReviewQueueError)
        self.assertEqual(self._queue_event_count(), 1)
        claimed = self._item(review_id)
        self.assertEqual(claimed.state, "CLAIMED")
        self.assertEqual(claimed.assignee, permits[0].assignee)

    def test_claim_exact_replay_is_stable_and_changed_command_conflicts(self) -> None:
        review_id = self._create_review("replay")
        expected = self._item(review_id).state_digest
        first = self._claim(
            review_id,
            idempotency_key="claim-replay",
            expected_state_digest=expected,
        )
        replay = self._claim(
            review_id,
            idempotency_key="claim-replay",
            expected_state_digest=expected,
        )

        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertTrue(replay.active)
        self.assertEqual(replay.claim_event_id, first.claim_event_id)
        self.assertEqual(replay.lease_token, first.lease_token)
        self.assertEqual(replay.fence, first.fence)
        with self.assertRaises(SourceReviewQueueConflict):
            self._claim(
                review_id,
                claimant="reviewer-b",
                idempotency_key="claim-replay",
                expected_state_digest=expected,
            )
        self.assertEqual(self._queue_event_count(), 1)

    def test_resolution_rejects_non_exact_claim_permit_before_write(self) -> None:
        review_id = self._create_review("strict-permit")
        permit = self._claim(review_id, idempotency_key="strict-permit-claim")
        before_events = self._count("events")
        before_resolutions = self._count("source_lab_review_resolutions")

        with self.assertRaises(SourceReviewQueueError):
            self.queue.resolve_claimed(
                replace(permit, fence=True),
                decision="APPROVE",
                reason="A boolean fence is not an integer claim fence",
                evidence_ref="evidence://queue/resolution/strict-permit",
                idempotency_key="strict-permit-resolution",
            )

        self.assertEqual(self._count("events"), before_events)
        self.assertEqual(
            self._count("source_lab_review_resolutions"), before_resolutions
        )
        self.assertEqual(self._item(review_id).state, "CLAIMED")

    def test_expired_claim_is_reclaimed_and_old_permit_is_fenced(self) -> None:
        review_id = self._create_review("reclaim")
        initial_digest = self._item(review_id).state_digest
        old = self._claim(
            review_id,
            idempotency_key="old-claim",
            expected_state_digest=initial_digest,
            lease_seconds=30,
        )
        self.clock.advance(seconds=31)

        expired_replay = self._claim(
            review_id,
            idempotency_key="old-claim",
            expected_state_digest=initial_digest,
            lease_seconds=30,
        )
        self.assertFalse(expired_replay.created)
        self.assertFalse(expired_replay.active)
        reclaimable = self._item(review_id)
        self.assertEqual(reclaimable.state, "RECLAIMABLE")
        current = self.queue.reclaim(
            review_id=review_id,
            assignee="reviewer-b",
            actor="reviewer-b",
            reason_code="LEASE_EXPIRED",
            previous_claim_event_id=old.claim_event_id,
            evidence_ref="evidence://queue/reclaim/current",
            idempotency_key="reclaim-current",
            expected_state_digest=reclaimable.state_digest,
            lease_seconds=30,
        )
        self.assertEqual(current.fence, old.fence + 1)
        with self.assertRaises(SourceReviewQueueConflict):
            self.queue.reclaim(
                review_id=review_id,
                assignee="reviewer-b",
                actor="reviewer-b",
                reason_code="LEASE_EXPIRED",
                previous_claim_event_id="forged-previous-claim",
                evidence_ref="evidence://queue/reclaim/current",
                idempotency_key="reclaim-current",
                expected_state_digest=reclaimable.state_digest,
                lease_seconds=30,
            )

        with self.assertRaises(SourceReviewQueueStaleClaim):
            self.queue.resolve_claimed(
                old,
                decision="APPROVE",
                reason="Stale reviewer must not win",
                evidence_ref="evidence://queue/resolution/stale",
                idempotency_key="resolve-stale",
            )
        resolved = self.queue.resolve_claimed(
            current,
            decision="APPROVE",
            reason="Current reviewer confirmed the signal",
            evidence_ref="evidence://queue/resolution/current",
            idempotency_key="resolve-current",
        )
        self.assertTrue(resolved.created)
        self.assertEqual(resolved.sequence_number, 1)
        self.assertEqual(self._count("source_lab_review_resolutions"), 1)

    def test_clock_rollback_fails_closed_without_resolution(self) -> None:
        review_id = self._create_review("clock-rollback")
        permit = self._claim(review_id, idempotency_key="clock-claim")
        self.clock.set(datetime(2026, 8, 21, 11, 59, 59, tzinfo=timezone.utc))

        with self.assertRaisesRegex(
            SourceReviewQueueIntegrityError, "clock moved backwards"
        ):
            self.queue.list_open(limit=100)
        with self.assertRaisesRegex(
            SourceReviewQueueIntegrityError, "clock moved backwards"
        ):
            self.queue.resolve_claimed(
                permit,
                decision="APPROVE",
                reason="A backdated decision is invalid",
                evidence_ref="evidence://queue/resolution/backdated",
                idempotency_key="resolve-backdated",
            )
        self.assertEqual(self._count("source_lab_review_resolutions"), 0)
        self.assertEqual(self._queue_event_count(), 1)

    def test_first_claim_cannot_predate_its_review_request(self) -> None:
        review_id = self._create_review("first-claim-clock")
        expected = self._item(review_id).state_digest
        self.clock.set(datetime(2020, 1, 1, tzinfo=timezone.utc))

        with self.assertRaisesRegex(
            SourceReviewQueueIntegrityError, "clock precedes its review"
        ):
            self._claim(
                review_id,
                idempotency_key="backdated-first-claim",
                expected_state_digest=expected,
            )
        self.assertEqual(self._queue_event_count(), 0)

    def test_crash_after_source_lab_resolution_rolls_back_both_ledgers(self) -> None:
        review_id = self._create_review("resolution-crash")
        permit = self._claim(review_id, idempotency_key="crash-claim")
        crashing = _CrashAfterSourceLabResolution(self.store, clock=self.clock)

        with self.assertRaisesRegex(RuntimeError, "injected crash"):
            crashing.resolve_claimed(
                permit,
                decision="APPROVE",
                reason="Resolution must be atomic with its queue fact",
                evidence_ref="evidence://queue/resolution/crash",
                idempotency_key="resolve-after-crash",
            )
        self.assertEqual(self._count("source_lab_review_resolutions"), 0)
        self.assertEqual(self._queue_event_count(), 1)
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='source_lab_review_resolved'"
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

        recovered = self.queue.resolve_claimed(
            permit,
            decision="APPROVE",
            reason="Resolution must be atomic with its queue fact",
            evidence_ref="evidence://queue/resolution/crash",
            idempotency_key="resolve-after-crash",
        )
        self.assertTrue(recovered.created)
        self.assertEqual(recovered.sequence_number, 1)
        self.assertEqual(self._queue_event_count(), 2)

    def test_needs_research_can_be_reclaimed_then_resolved_as_sequence_two(self) -> None:
        review_id = self._create_review("needs-research")
        first_claim = self._claim(review_id, idempotency_key="research-claim-one")
        first = self.queue.resolve_claimed(
            first_claim,
            decision="NEEDS_RESEARCH",
            reason="Confirm the buyer before approval",
            evidence_ref="evidence://queue/resolution/research",
            idempotency_key="research-resolution-one",
        )
        self.assertEqual(first.sequence_number, 1)

        research = self._item(review_id)
        self.assertEqual(research.state, "NEEDS_RESEARCH")
        self.assertEqual(research.latest_decision, "NEEDS_RESEARCH")
        second_claim = self._claim(
            review_id,
            claimant="reviewer-b",
            idempotency_key="research-claim-two",
            expected_state_digest=research.state_digest,
        )
        second = self.queue.resolve_claimed(
            second_claim,
            decision="APPROVE",
            reason="Buyer and demand are now confirmed",
            evidence_ref="evidence://queue/resolution/approved",
            idempotency_key="research-resolution-two",
        )
        self.assertEqual(second.sequence_number, 2)
        self.assertEqual(tuple(self.queue.list_open(limit=100).items), ())

        con = self.store.connect()
        try:
            rows = con.execute(
                """SELECT sequence_number,decision,supersedes_resolution_id,resolution_id
                   FROM source_lab_review_resolutions WHERE review_id=?
                   ORDER BY sequence_number""",
                (review_id,),
            ).fetchall()
        finally:
            con.close()
        self.assertEqual([row[0] for row in rows], [1, 2])
        self.assertEqual([row[1] for row in rows], ["NEEDS_RESEARCH", "APPROVE"])
        self.assertEqual(rows[1][2], rows[0][3])

    def test_direct_source_lab_resolution_cannot_bypass_started_queue(self) -> None:
        review_id = self._create_review("direct-bypass")
        permit = self._claim(review_id, idempotency_key="managed-claim")

        with self.assertRaisesRegex(SourceLabConflict, "managed by the review queue"):
            self.sink.append_review_resolution(
                review_id=review_id,
                decision="APPROVE",
                reason="Direct bypass must be rejected",
                resolved_by=permit.assignee,
                evidence_ref="evidence://queue/resolution/direct-bypass",
                idempotency_key="direct-bypass-resolution",
            )
        self.assertEqual(self._count("source_lab_review_resolutions"), 0)
        self.assertEqual(self._item(review_id).state, "CLAIMED")

    def test_schema17_direct_resolution_is_blocked_before_first_claim(self) -> None:
        review_id = self._create_review("direct-before-claim")

        with self.assertRaisesRegex(SourceLabConflict, "managed by the review queue"):
            self.sink.append_review_resolution(
                review_id=review_id,
                decision="APPROVE",
                reason="Schema 17 decisions require an owned queue claim",
                resolved_by="reviewer-b",
                evidence_ref="evidence://queue/resolution/before-claim",
                idempotency_key="direct-before-claim-resolution",
            )

        self.assertEqual(self._count("source_lab_review_resolutions"), 0)
        self.assertEqual(self._item(review_id).state, "OPEN_UNASSIGNED")

    def test_restore_rejects_tampered_queue_payload_or_event_metadata(self) -> None:
        review_id = self._create_review("backup-tamper")
        self._claim(review_id, idempotency_key="backup-claim")
        con = self.store.connect()
        try:
            self.assertEqual(validate_source_review_queue_integrity(con)["event_count"], 1)
        finally:
            con.close()

        for mode in ("payload", "metadata"):
            with self.subTest(mode=mode):
                backup = create_backup(
                    self.store,
                    destination_dir=self.root / f"backup-{mode}",
                )
                backup_path = Path(str(backup["backup"]))
                con = sqlite3.connect(backup_path)
                try:
                    row = con.execute(
                        """SELECT event_id,payload_json FROM events
                           WHERE producer=? ORDER BY rowid LIMIT 1""",
                        (QUEUE_PRODUCER,),
                    ).fetchone()
                    self.assertIsNotNone(row)
                    con.execute("DROP TRIGGER trg_lf_events_no_update")
                    if mode == "payload":
                        forged = json.loads(str(row[1]))
                        forged["fence"] = int(forged["fence"]) + 100
                        con.execute(
                            "UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                            (canonical_json(forged), payload_hash(forged), row[0]),
                        )
                    else:
                        con.execute(
                            "UPDATE events SET actor='forged-reviewer' WHERE event_id=?",
                            (row[0],),
                        )
                    con.execute(
                        """CREATE TRIGGER trg_lf_events_no_update
                           BEFORE UPDATE ON events BEGIN
                               SELECT RAISE(ABORT, 'lead factory events are append-only');
                           END"""
                    )
                    con.commit()
                finally:
                    con.close()

                manifest_path = Path(str(backup["manifest"]))
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
                manifest_path.write_text(
                    json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2),
                    encoding="utf-8",
                )
                target = self.root / f"must-not-restore-{mode}.sqlite3"
                with self.assertRaisesRegex(
                    RecoveryError, "Source Lab semantic integrity"
                ):
                    verify_restore(backup_path, restore_path=target)
                self.assertFalse(target.exists())
                self.assertFalse(Path(str(target) + ".evidence").exists())

    def test_integrity_rejects_disguised_queue_event_and_direct_bypass(self) -> None:
        review_id = self._create_review("disguised-event")
        self._claim(review_id, idempotency_key="disguised-claim")
        con = self.store.connect()
        try:
            trigger_sql = str(
                con.execute(
                    "SELECT sql FROM sqlite_master WHERE name='trg_lf_events_no_update'"
                ).fetchone()[0]
            )
            row = con.execute(
                "SELECT event_id FROM events WHERE producer=?", (QUEUE_PRODUCER,)
            ).fetchone()
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            disguised = {"disguised": True}
            con.execute(
                """UPDATE events SET producer='disguised',event_type='disguised',
                          payload_json=?,payload_hash=? WHERE event_id=?""",
                (canonical_json(disguised), payload_hash(disguised), row[0]),
            )
            con.execute(trigger_sql)
            con.commit()
            with self.assertRaises(SourceLabIntegrityError):
                validate_source_lab_integrity(con)
        finally:
            con.close()

        with self.assertRaisesRegex(SourceLabConflict, "managed by the review queue"):
            self.sink.append_review_resolution(
                review_id=review_id,
                decision="APPROVE",
                reason="A disguised queue event must still fence direct writes",
                resolved_by="reviewer-b",
                evidence_ref="evidence://queue/disguised/bypass",
                idempotency_key="disguised-bypass",
            )

    def test_integrity_rejects_non_exact_numbers_and_forged_reason_policy(self) -> None:
        for mode in (
            "boolean-numbers",
            "forged-reason",
            "forged-requester",
            "renamed-idempotency",
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                store = store_module.FactoryStore(Path(directory) / "strict.sqlite3")
                store.init()
                clock = _MutableClock(
                    datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
                )
                sink = SourceLabSink(store, clock=clock)
                record = sink.ingest_record(
                    "strict-source",
                    "OFFLINE_FIXTURE",
                    "strict-run",
                    "strict-row",
                    {"subject": "strict queue"},
                    "2026-08-21T11:00:00Z",
                    "evidence://queue/strict/record",
                    "strict-record",
                )
                review = sink.request_review(
                    source_record_id=record.source_record_id,
                    reason="Strict queue proof",
                    requested_by="source-review-tests",
                    evidence_ref="evidence://queue/strict/review",
                    idempotency_key="strict-review",
                )
                queue = SourceReviewQueue(store, clock=clock)
                item = queue.list_open().items[0]
                queue.claim(
                    review_id=review.review_id,
                    claimant="reviewer-a",
                    evidence_ref="evidence://queue/strict/claim",
                    idempotency_key="strict-claim",
                    expected_state_digest=item.state_digest,
                    lease_seconds=30,
                )
                con = store.connect()
                try:
                    trigger_sql = str(
                        con.execute(
                            "SELECT sql FROM sqlite_master "
                            "WHERE name='trg_lf_events_no_update'"
                        ).fetchone()[0]
                    )
                    row = con.execute(
                        "SELECT event_id,payload_json,evidence_ref FROM events "
                        "WHERE producer=?",
                        (QUEUE_PRODUCER,),
                    ).fetchone()
                    forged = json.loads(str(row[1]))
                    if mode == "boolean-numbers":
                        forged["queue_event_version"] = True
                        forged["revision"] = True
                        forged["fence"] = True
                    elif mode in {"forged-reason", "forged-requester"}:
                        if mode == "forged-reason":
                            forged["reason_code"] = "FORGED_REASON"
                        else:
                            forged["actor"] = "source-review-tests"
                            forged["assignee"] = "source-review-tests"
                        forged["command_hash"] = payload_hash(
                            {
                                "source_review_queue_claim_command_version": 1,
                                "requested_operation": forged["requested_operation"],
                                "review_id": forged["review_id"],
                                "assignee": forged["assignee"],
                                "actor": forged["actor"],
                                "reason_code": forged["reason_code"],
                                "lease_seconds": forged["lease_seconds"],
                                "evidence_ref": row[2],
                                "expected_state_digest": forged[
                                    "expected_state_digest"
                                ],
                                "previous_claim_event_id": forged[
                                    "previous_claim_event_id"
                                ],
                                "idempotency_key_hash": forged[
                                    "idempotency_key_hash"
                                ],
                            }
                        )
                    con.execute("DROP TRIGGER trg_lf_events_no_update")
                    if mode == "renamed-idempotency":
                        con.execute(
                            "UPDATE events SET idempotency_key='claim:renamed' "
                            "WHERE event_id=?",
                            (row[0],),
                        )
                    else:
                        con.execute(
                            "UPDATE events SET payload_json=?,payload_hash=? "
                            "WHERE event_id=?",
                            (canonical_json(forged), payload_hash(forged), row[0]),
                        )
                    con.execute(trigger_sql)
                    con.commit()
                    with self.assertRaises(SourceReviewQueueIntegrityError):
                        validate_source_review_queue_integrity(con)
                    with self.assertRaises(SourceLabIntegrityError):
                        validate_source_lab_integrity(con)
                finally:
                    con.close()

    def test_schema16_queue_fact_is_rejected_by_backup_and_restore(self) -> None:
        from tests.test_lead_factory_recovery_v17 import _create_exact_v16

        database = self.root / "hostile-queue-v16.sqlite3"
        v16_store = _create_exact_v16(database)
        clock = _MutableClock(datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc))
        sink = SourceLabSink(v16_store, clock=clock)
        record = sink.ingest_record(
            "legacy-source",
            "OFFLINE_FIXTURE",
            "hostile-v16-run",
            "hostile-v16-row",
            {"subject": "schema 16 cannot own queue events"},
            "2026-08-21T11:00:00Z",
            "evidence://queue/v16/record",
            "hostile-v16-record",
        )
        sink.request_review(
            source_record_id=record.source_record_id,
            reason="Hostile schema 16 queue proof",
            requested_by="legacy-intake",
            evidence_ref="evidence://queue/v16/review",
            idempotency_key="hostile-v16-review",
        )
        clean_backup = create_backup(
            v16_store,
            destination_dir=self.root / "clean-v16-backups",
        )

        def inject_hostile_claim(path: Path) -> None:
            unsafe_queue = SourceReviewQueue(_UnsafeV16QueueStore(path), clock=clock)
            item = unsafe_queue.list_open().items[0]
            unsafe_queue.claim(
                review_id=item.review_id,
                claimant="reviewer-v16",
                evidence_ref="evidence://queue/v16/claim",
                idempotency_key="hostile-v16-claim",
                expected_state_digest=item.state_digest,
                lease_seconds=30,
            )

        backup_path = Path(str(clean_backup["backup"]))
        inject_hostile_claim(backup_path)
        manifest_path = Path(str(clean_backup["manifest"]))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        restored = self.root / "must-not-restore-hostile-v16.sqlite3"
        with self.assertRaisesRegex(RecoveryError, "Source Lab semantic integrity"):
            verify_restore(backup_path, restore_path=restored)
        self.assertFalse(restored.exists())
        self.assertFalse(Path(str(restored) + ".evidence").exists())

        inject_hostile_claim(database)
        con = v16_store.connect()
        try:
            with self.assertRaisesRegex(
                SourceReviewQueueIntegrityError,
                "authoritative schema 17",
            ):
                validate_source_review_queue_integrity(con)
            with self.assertRaises(SourceLabIntegrityError):
                validate_source_lab_integrity(con)
        finally:
            con.close()
        rejected_dir = self.root / "rejected-hostile-v16-backups"
        with self.assertRaisesRegex(RecoveryError, "Source Lab semantic integrity"):
            create_backup(v16_store, destination_dir=rejected_dir)
        self.assertEqual(tuple(rejected_dir.glob("*.sqlite3")), ())
        self.assertEqual(tuple(rejected_dir.glob("*.partial")), ())

    def test_integrity_rejects_first_queue_row_before_review_request(self) -> None:
        review_id = self._create_review("rowid-before-review")
        self._claim(review_id, idempotency_key="rowid-before-review-claim")
        con = self.store.connect()
        try:
            trigger_sql = str(
                con.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE name='trg_lf_events_no_update'"
                ).fetchone()[0]
            )
            row = con.execute(
                "SELECT event_id FROM events WHERE producer=?",
                (QUEUE_PRODUCER,),
            ).fetchone()
            request_rowid = int(
                con.execute(
                    """SELECT e.rowid FROM source_lab_reviews r
                       JOIN events e ON e.event_id=r.event_id
                       WHERE r.review_id=?""",
                    (review_id,),
                ).fetchone()[0]
            )
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            con.execute("UPDATE events SET rowid=-1 WHERE event_id=?", (row[0],))
            con.execute(trigger_sql)
            con.commit()
            queue_rowid = int(
                con.execute(
                    "SELECT rowid FROM events WHERE event_id=?", (row[0],)
                ).fetchone()[0]
            )
            self.assertLessEqual(queue_rowid, request_rowid)
            with self.assertRaisesRegex(
                SourceReviewQueueIntegrityError,
                "event chain is invalid",
            ):
                validate_source_review_queue_integrity(con)
            with self.assertRaises(SourceLabIntegrityError):
                validate_source_lab_integrity(con)
        finally:
            con.close()

        rejected_dir = self.root / "rejected-rowid-backups"
        with self.assertRaisesRegex(RecoveryError, "Source Lab semantic integrity"):
            create_backup(self.store, destination_dir=rejected_dir)
        self.assertEqual(tuple(rejected_dir.glob("*.sqlite3")), ())

    def test_restore_rejects_companion_task_event_envelope_or_full_row_tamper(
        self,
    ) -> None:
        from tests.test_lead_factory_source_review_queue_integration import (
            SourceReviewQueueIntegrationTests,
        )

        fixture = SourceReviewQueueIntegrationTests(
            methodName="test_unified_keyset_queue_lists_exact_wave1_and_site_reviews"
        )
        fixture.setUp()
        try:
            item = next(
                candidate
                for candidate in fixture._all_pages(limit=20)
                if candidate.review_id in fixture.site_review_ids
            )
            fixture.queue.claim(
                review_id=item.review_id,
                claimant="dima",
                evidence_ref="evidence://queue/task-proof/claim",
                idempotency_key="task-proof-claim",
                expected_state_digest=item.state_digest,
                lease_seconds=900,
            )
            for mode in ("envelope", "full-row"):
                with self.subTest(mode=mode):
                    backup = create_backup(
                        fixture.store,
                        destination_dir=fixture.root / f"task-proof-backup-{mode}",
                    )
                    backup_path = Path(str(backup["backup"]))
                    con = sqlite3.connect(backup_path)
                    try:
                        trigger_sql = str(
                            con.execute(
                                "SELECT sql FROM sqlite_master "
                                "WHERE name='trg_lf_events_no_update'"
                            ).fetchone()[0]
                        )
                        task_event_id = str(
                            con.execute(
                                """SELECT event_id FROM events
                                   WHERE producer='human_task_controller'
                                     AND idempotency_key=?""",
                                (
                                    f"task-state:{item.task_id}:ACKNOWLEDGED",
                                ),
                            ).fetchone()[0]
                        )
                        con.execute("DROP TRIGGER trg_lf_events_no_update")
                        if mode == "envelope":
                            con.execute(
                                """UPDATE events SET schema_version=16,
                                          correlation_id='forged-correlation'
                                   WHERE event_id=?""",
                                (task_event_id,),
                            )
                        else:
                            con.execute(
                                """UPDATE events
                                   SET recorded_at_utc='2099-01-01T00:00:00Z'
                                   WHERE event_id=?""",
                                (task_event_id,),
                            )
                        con.execute(trigger_sql)
                        con.commit()
                    finally:
                        con.close()

                    manifest_path = Path(str(backup["manifest"]))
                    manifest = json.loads(
                        manifest_path.read_text(encoding="utf-8")
                    )
                    manifest["sha256"] = hashlib.sha256(
                        backup_path.read_bytes()
                    ).hexdigest()
                    manifest_path.write_text(
                        json.dumps(
                            manifest,
                            ensure_ascii=False,
                            sort_keys=True,
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    restored = fixture.root / f"must-not-restore-task-{mode}.sqlite3"
                    with self.assertRaises(RecoveryError):
                        verify_restore(backup_path, restore_path=restored)
                    self.assertFalse(restored.exists())
                    self.assertFalse(Path(str(restored) + ".evidence").exists())
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
