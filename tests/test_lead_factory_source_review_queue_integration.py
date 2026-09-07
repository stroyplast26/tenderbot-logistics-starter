from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from lead_factory.recovery import create_backup, verify_restore
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_review_queue import (
    ReviewQueueItem,
    SourceReviewQueue,
    SourceReviewQueueConflict,
    SourceReviewQueueIntegrityError,
    SourceReviewQueueStaleClaim,
    validate_source_review_queue_integrity,
)
from lead_factory.source_wave1_contracts import Wave1Provider, wave1_contract
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore
from lead_factory.tasks import HumanTaskController, TaskStateError
from tests import test_lead_factory_at_site_01 as site_fixture
from tests import test_lead_factory_source_wave1_ingest as wave1_fixture


QUEUE_NOW = datetime(2026, 8, 22, 9, 0, tzinfo=timezone.utc)


class _MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, *, seconds: int = 0) -> None:
        self.value += timedelta(seconds=seconds)


class SourceReviewQueueIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = FactoryStore(self.root / "source-review-queue.sqlite3")
        self.store.init()
        self.assertEqual(self.store.schema_version(), CURRENT_SCHEMA_VERSION)
        self.source_lab = SourceLabSink(self.store, clock=lambda: wave1_fixture.NOW)
        self.clock = _MutableClock(QUEUE_NOW)
        self.queue = SourceReviewQueue(self.store, clock=self.clock)
        self.wave_review_ids: set[str] = set()
        self.wave_review_ids_by_source: dict[str, set[str]] = {}
        self.site_review_ids: set[str] = set()
        self._ingest_real_wave1_and_site_fixtures()

    def _ingest_real_wave1_and_site_fixtures(self) -> None:
        wave = wave1_fixture.Wave1OfflineIngestTests()
        wave.root = self.root
        wave.store = self.store
        wave.source_lab = self.source_lab
        for provider in Wave1Provider:
            contract, _manifest, _pages, prepared = wave._collect(provider)
            authorization = wave._persistent_authorization(contract, prepared)
            committed = wave._commit(contract, prepared, authorization)
            review_ids = {item.review_id for item in committed.review_results}
            self.assertEqual(len(review_ids), 2)
            self.wave_review_ids_by_source[contract.source_id] = review_ids
            self.wave_review_ids.update(review_ids)

        site = site_fixture.AtSite01AcceptanceTests()
        site.store = self.store
        site.policy = site_fixture.trusted_policy()
        coordinator = site._coordinator()
        site_results = tuple(
            site._ingest_without_network(coordinator, command)
            for command in site._matrix()
        )
        self.site_review_ids = {
            str(result.review_id) for result in site_results if result.review_id
        }

        self.assertEqual(len(self.wave_review_ids), 8)
        self.assertEqual(len(self.site_review_ids), site_fixture.VALID_COUNT)
        self.assertTrue(self.wave_review_ids.isdisjoint(self.site_review_ids))
        self.assertEqual(self.store.table_count("source_lab_reviews"), 20)

    def _all_pages(
        self,
        queue: SourceReviewQueue | None = None,
        *,
        limit: int,
        source_id: str = "",
        review_kind: str = "",
    ) -> tuple[ReviewQueueItem, ...]:
        selected = queue or self.queue
        cursor = ""
        items: list[ReviewQueueItem] = []
        snapshot: tuple[str, int, str] | None = None
        while True:
            page = selected.list_open(
                limit=limit,
                cursor=cursor,
                source_id=source_id,
                review_kind=review_kind,
            )
            current = (
                page.snapshot_event_id,
                page.snapshot_event_rowid,
                page.as_of_utc,
            )
            if snapshot is None:
                snapshot = current
            else:
                self.assertEqual(current, snapshot)
            items.extend(page.items)
            if not page.next_cursor:
                break
            self.assertNotEqual(page.next_cursor, cursor)
            cursor = page.next_cursor
        return tuple(items)

    def _item(self, review_id: str, *, queue: SourceReviewQueue | None = None) -> ReviewQueueItem:
        matches = [
            item
            for item in self._all_pages(queue, limit=17)
            if item.review_id == review_id
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _assert_external_switches_off(self, store: FactoryStore | None = None) -> None:
        status = (store or self.store).status()
        self.assertFalse(status["external_writers_enabled"])
        self.assertFalse(status["external_source_reads_enabled"])
        self.assertFalse(status["manual_import_commits_enabled"])

    @staticmethod
    def _queue_integrity(store: FactoryStore) -> dict[str, object]:
        con = store.connect()
        try:
            return validate_source_review_queue_integrity(con)
        finally:
            con.close()

    def test_unified_keyset_queue_lists_exact_wave1_and_site_reviews(self) -> None:
        first = self.queue.list_open(limit=4, review_kind="QUALIFICATION")
        self.assertEqual(len(first.items), 4)
        self.assertTrue(first.next_cursor)

        claimed_candidate = next(
            item for item in first.items if item.review_id in self.wave_review_ids
        )
        permit = self.queue.claim(
            review_id=claimed_candidate.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/snapshot-claim",
            idempotency_key="snapshot-claim",
            expected_state_digest=claimed_candidate.state_digest,
            lease_seconds=900,
        )
        self.assertTrue(permit.created)

        snapshot_items = list(first.items)
        cursor = first.next_cursor
        while cursor:
            page = self.queue.list_open(
                limit=4,
                cursor=cursor,
                review_kind="QUALIFICATION",
            )
            self.assertEqual(page.snapshot_event_id, first.snapshot_event_id)
            self.assertEqual(page.snapshot_event_rowid, first.snapshot_event_rowid)
            self.assertEqual(page.as_of_utc, first.as_of_utc)
            snapshot_items.extend(page.items)
            cursor = page.next_cursor
        snapshot_ids = [item.review_id for item in snapshot_items]
        self.assertEqual(len(snapshot_ids), 20)
        self.assertEqual(len(set(snapshot_ids)), 20)
        self.assertEqual(set(snapshot_ids), self.wave_review_ids | self.site_review_ids)

        current = self._item(claimed_candidate.review_id)
        self.assertEqual(current.state, "CLAIMED")
        self.assertEqual(current.assignee, "dima")

        site_items = self._all_pages(
            limit=5,
            source_id=site_fixture.SOURCE_ID,
            review_kind="QUALIFICATION",
        )
        self.assertEqual({item.review_id for item in site_items}, self.site_review_ids)
        self.assertEqual(len(site_items), site_fixture.VALID_COUNT)
        for item in site_items:
            self.assertEqual(item.task_kind, "SITE_QUALIFICATION")
            self.assertFalse(hasattr(item, "task_status"))
            self.assertEqual(item.task_assigned_to, "dima")
            self.assertTrue(item.task_id)
            self.assertTrue(item.task_due_at_utc)
            con = self.store.connect()
            try:
                task_status = str(
                    con.execute(
                        "SELECT status FROM human_tasks WHERE lf_task_id=?",
                        (item.task_id,),
                    ).fetchone()[0]
                )
            finally:
                con.close()
            self.assertEqual(
                task_status,
                "ACKNOWLEDGED"
                if item.review_id == claimed_candidate.review_id
                else "OPEN",
            )

        for provider in Wave1Provider:
            source_id = wave1_contract(provider).source_id
            source_items = self._all_pages(limit=1, source_id=source_id)
            self.assertEqual(
                {item.review_id for item in source_items},
                self.wave_review_ids_by_source[source_id],
            )
            self.assertTrue(all(not item.task_id for item in source_items))

        with self.assertRaises(SourceReviewQueueConflict):
            self.queue.list_open(
                limit=4,
                cursor=first.next_cursor,
                source_id=site_fixture.SOURCE_ID,
                review_kind="QUALIFICATION",
            )
        self._assert_external_switches_off()

    def test_site_owner_is_dima_and_wave1_needs_research_has_no_commercial_writes(self) -> None:
        graph_tables = (
            "companies",
            "contacts",
            "projects",
            "opportunities",
            "source_lab_opportunity_evidence_links",
            "crm_mappings",
            "crm_outbox",
            "outbox",
        )
        before = {table: self.store.table_count(table) for table in graph_tables}
        self.assertEqual(before, {table: 0 for table in graph_tables})

        site_item = next(
            item
            for item in self._all_pages(limit=20, source_id=site_fixture.SOURCE_ID)
        )
        with self.assertRaises(SourceReviewQueueConflict):
            self.queue.assign(
                review_id=site_item.review_id,
                assignee="other-reviewer",
                assigned_by="queue-controller",
                reason_code="SLA_TASK_ASSIGNMENT",
                evidence_ref="evidence://review-queue/site-wrong-owner",
                idempotency_key="site-wrong-owner",
                expected_state_digest=site_item.state_digest,
                lease_seconds=900,
            )
        site_permit = self.queue.claim(
            review_id=site_item.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/site-dima",
            idempotency_key="site-dima",
            expected_state_digest=site_item.state_digest,
            lease_seconds=900,
        )
        self.assertEqual(site_permit.assignee, "dima")
        site_resolution = self.queue.resolve_claimed(
            site_permit,
            decision="APPROVE",
            reason="Site demand is qualified for commercial review",
            evidence_ref="evidence://review-queue/site-resolution",
            idempotency_key="site-resolution",
        )
        self.assertTrue(site_resolution.created)
        con = self.store.connect()
        try:
            site_task = con.execute(
                "SELECT * FROM human_tasks WHERE lf_task_id=?",
                (site_item.task_id,),
            ).fetchone()
        finally:
            con.close()
        self.assertEqual(str(site_task["status"]), "COMPLETED")
        self.assertEqual(
            str(site_task["resolution"]),
            f"SOURCE_LAB_REVIEW:APPROVE:{site_resolution.resolution_id}",
        )
        self.assertTrue(str(site_task["closed_at_utc"]))

        for index, review_id in enumerate(sorted(self.wave_review_ids), start=1):
            item = self._item(review_id)
            permit = self.queue.assign(
                review_id=review_id,
                assignee="dima",
                assigned_by="queue-controller",
                reason_code="REVIEW_ASSIGNMENT",
                evidence_ref=f"evidence://review-queue/wave1-assign/{index}",
                idempotency_key=f"wave1-assign-{index}",
                expected_state_digest=item.state_digest,
                lease_seconds=900,
            )
            resolved = self.queue.resolve_claimed(
                permit,
                decision="NEEDS_RESEARCH",
                reason="CONTACT_ENRICHMENT_REQUIRED",
                evidence_ref=f"evidence://review-queue/wave1-resolution/{index}",
                idempotency_key=f"wave1-resolution-{index}",
            )
            self.assertTrue(resolved.created)
            self.assertEqual(resolved.decision, "NEEDS_RESEARCH")

        wave_items = {
            item.review_id: item
            for provider in Wave1Provider
            for item in self._all_pages(
                limit=2,
                source_id=wave1_contract(provider).source_id,
            )
        }
        self.assertEqual(set(wave_items), self.wave_review_ids)
        for item in wave_items.values():
            self.assertEqual(item.state, "NEEDS_RESEARCH")
            self.assertEqual(item.latest_decision, "NEEDS_RESEARCH")
            self.assertEqual(
                item.latest_resolution_reason,
                "CONTACT_ENRICHMENT_REQUIRED",
            )
            self.assertEqual(item.latest_resolved_by, "dima")

        after = {table: self.store.table_count(table) for table in graph_tables}
        self.assertEqual(after, before)
        self.assertEqual(self._queue_integrity(self.store)["event_count"], 18)
        self._assert_external_switches_off()

    def test_site_task_rejects_direct_controller_transitions_before_and_after_claim(
        self,
    ) -> None:
        site_item = next(
            item
            for item in self._all_pages(limit=20, source_id=site_fixture.SOURCE_ID)
        )
        controller = HumanTaskController(self.store)

        def snapshot() -> tuple[dict[str, object], int]:
            con = self.store.connect()
            try:
                task = dict(
                    con.execute(
                        "SELECT * FROM human_tasks WHERE lf_task_id=?",
                        (site_item.task_id,),
                    ).fetchone()
                )
                task_events = int(
                    con.execute(
                        "SELECT COUNT(*) FROM events "
                        "WHERE aggregate_type='task' AND aggregate_id=?",
                        (site_item.task_id,),
                    ).fetchone()[0]
                )
                return task, task_events
            finally:
                con.close()

        def assert_direct_transitions_rejected(phase: str) -> None:
            expected = snapshot()
            commands = (
                (
                    "acknowledge",
                    lambda: controller.acknowledge(
                        site_item.task_id,
                        actor="dima",
                        evidence_ref=f"evidence://review-queue/direct/{phase}/ack",
                        at_utc="2026-08-22T09:00:01Z",
                    ),
                ),
                (
                    "first-action",
                    lambda: controller.record_first_action(
                        site_item.task_id,
                        actor="dima",
                        evidence_ref=f"evidence://review-queue/direct/{phase}/first",
                        at_utc="2026-08-22T09:00:01Z",
                    ),
                ),
                (
                    "complete",
                    lambda: controller.complete(
                        site_item.task_id,
                        actor="dima",
                        evidence_ref=f"evidence://review-queue/direct/{phase}/complete",
                        resolution="COMPLETED_OUTSIDE_REVIEW_QUEUE",
                        at_utc="2026-08-22T09:00:01Z",
                    ),
                ),
            )
            for name, command in commands:
                with self.subTest(phase=phase, command=name):
                    with self.assertRaises(TaskStateError):
                        command()
                    self.assertEqual(snapshot(), expected)

        assert_direct_transitions_rejected("before-claim")
        permit = self.queue.claim(
            review_id=site_item.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/direct/queue-claim",
            idempotency_key="direct-controller-guard-claim",
            expected_state_digest=site_item.state_digest,
            lease_seconds=900,
        )
        self.assertTrue(permit.created)
        self.assertEqual(snapshot()[0]["status"], "ACKNOWLEDGED")

        assert_direct_transitions_rejected("after-claim")
        self.assertEqual(self._item(site_item.review_id).state, "CLAIMED")
        self.assertEqual(self._queue_integrity(self.store)["event_count"], 1)
        self._assert_external_switches_off()

    def test_site_needs_research_records_first_action_then_terminal_review_completes_task(
        self,
    ) -> None:
        site_item = next(
            item
            for item in self._all_pages(limit=20, source_id=site_fixture.SOURCE_ID)
        )
        first_permit = self.queue.claim(
            review_id=site_item.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/site-research/claim-1",
            idempotency_key="site-research-claim-1",
            expected_state_digest=site_item.state_digest,
            lease_seconds=900,
        )
        research = self.queue.resolve_claimed(
            first_permit,
            decision="NEEDS_RESEARCH",
            reason="CONTACT_ENRICHMENT_REQUIRED",
            evidence_ref="evidence://review-queue/site-research/resolution-1",
            idempotency_key="site-research-resolution-1",
        )
        self.assertTrue(research.created)

        con = self.store.connect()
        try:
            task_after_research = dict(
                con.execute(
                    "SELECT * FROM human_tasks WHERE lf_task_id=?",
                    (site_item.task_id,),
                ).fetchone()
            )
            review_event_id = str(
                con.execute(
                    "SELECT event_id FROM source_lab_reviews WHERE review_id=?",
                    (site_item.review_id,),
                ).fetchone()[0]
            )
            first_action = dict(
                con.execute(
                    "SELECT * FROM events WHERE producer='human_task_controller' "
                    "AND aggregate_id=? AND event_type='human_task_first_action'",
                    (site_item.task_id,),
                ).fetchone()
            )
            completion_count = int(
                con.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE producer='human_task_controller' AND aggregate_id=? "
                    "AND event_type='human_task_completed'",
                    (site_item.task_id,),
                ).fetchone()[0]
            )
        finally:
            con.close()

        self.assertEqual(task_after_research["status"], "IN_PROGRESS")
        self.assertTrue(task_after_research["acknowledged_at_utc"])
        self.assertEqual(
            task_after_research["first_human_action_at_utc"],
            first_action["occurred_at_utc"],
        )
        self.assertEqual(task_after_research["closed_at_utc"], "")
        self.assertEqual(task_after_research["resolution"], "")
        self.assertEqual(completion_count, 0)
        self.assertEqual(first_action["schema_version"], CURRENT_SCHEMA_VERSION)
        self.assertEqual(first_action["correlation_id"], review_event_id)
        self.assertEqual(first_action["causation_id"], research.resolution_event_id)
        self.assertEqual(
            first_action["evidence_ref"],
            "evidence://review-queue/site-research/resolution-1",
        )

        research_item = self._item(site_item.review_id)
        self.assertEqual(research_item.state, "NEEDS_RESEARCH")
        second_permit = self.queue.claim(
            review_id=site_item.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/site-research/claim-2",
            idempotency_key="site-research-claim-2",
            expected_state_digest=research_item.state_digest,
            lease_seconds=900,
        )
        approved = self.queue.resolve_claimed(
            second_permit,
            decision="APPROVE",
            reason="Site demand is now fully qualified",
            evidence_ref="evidence://review-queue/site-research/resolution-2",
            idempotency_key="site-research-resolution-2",
        )
        self.assertTrue(approved.created)

        con = self.store.connect()
        try:
            final_task = dict(
                con.execute(
                    "SELECT * FROM human_tasks WHERE lf_task_id=?",
                    (site_item.task_id,),
                ).fetchone()
            )
            task_events = [
                dict(row)
                for row in con.execute(
                    "SELECT * FROM events WHERE producer='human_task_controller' "
                    "AND aggregate_id=? ORDER BY rowid",
                    (site_item.task_id,),
                ).fetchall()
            ]
        finally:
            con.close()

        self.assertEqual(
            [event["event_type"] for event in task_events],
            [
                "human_task_acknowledged",
                "human_task_first_action",
                "human_task_completed",
            ],
        )
        self.assertEqual(final_task["status"], "COMPLETED")
        self.assertEqual(
            final_task["first_human_action_at_utc"],
            task_after_research["first_human_action_at_utc"],
        )
        self.assertEqual(
            final_task["resolution"],
            f"SOURCE_LAB_REVIEW:APPROVE:{approved.resolution_id}",
        )
        completion = task_events[-1]
        self.assertEqual(final_task["closed_at_utc"], completion["occurred_at_utc"])
        self.assertEqual(completion["schema_version"], CURRENT_SCHEMA_VERSION)
        self.assertEqual(completion["correlation_id"], review_event_id)
        self.assertEqual(completion["causation_id"], approved.resolution_event_id)
        self.assertEqual(
            completion["evidence_ref"],
            "evidence://review-queue/site-research/resolution-2",
        )
        self.assertEqual(self._queue_integrity(self.store)["event_count"], 4)
        self.assertFalse(
            any(
                item.review_id == site_item.review_id
                for item in self._all_pages(
                    limit=20,
                    source_id=site_fixture.SOURCE_ID,
                )
            )
        )
        self._assert_external_switches_off()

    def test_restore_fences_old_cursor_and_permit_then_exact_reclaim_resumes(self) -> None:
        first_page = self.queue.list_open(limit=3)
        self.assertTrue(first_page.next_cursor)
        wave_item = next(
            item for item in self._all_pages(limit=20) if item.review_id in self.wave_review_ids
        )
        old_permit = self.queue.claim(
            review_id=wave_item.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/pre-restore-claim",
            idempotency_key="pre-restore-claim",
            expected_state_digest=wave_item.state_digest,
            lease_seconds=900,
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "backups",
        )
        restored_path = self.root / "restored-source-review-queue.sqlite3"
        report = verify_restore(backup["backup"], restore_path=restored_path)
        restored_store = FactoryStore(restored_path)
        self.assertEqual(report["schema_version"], str(CURRENT_SCHEMA_VERSION))
        self.assertEqual(report["external_writers_enabled"], "0")
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertEqual(report["manual_import_commits_enabled"], "0")
        self._assert_external_switches_off(restored_store)

        self.clock.advance(seconds=1)
        restored_queue = SourceReviewQueue(restored_store, clock=self.clock)
        with self.assertRaises(SourceReviewQueueConflict):
            restored_queue.list_open(limit=3, cursor=first_page.next_cursor)
        with self.assertRaises(SourceReviewQueueStaleClaim):
            restored_queue.resolve_claimed(
                old_permit,
                decision="NEEDS_RESEARCH",
                reason="CONTACT_ENRICHMENT_REQUIRED",
                evidence_ref="evidence://review-queue/stale-resolution",
                idempotency_key="stale-resolution",
            )

        restored_item = self._item(wave_item.review_id, queue=restored_queue)
        self.assertEqual(restored_item.state, "RECLAIMABLE")
        self.assertEqual(restored_item.claim_event_id, old_permit.claim_event_id)
        reclaimed = restored_queue.reclaim(
            review_id=wave_item.review_id,
            assignee="dima",
            actor="dima",
            reason_code="RESTORE_EPOCH_FENCED",
            previous_claim_event_id=old_permit.claim_event_id,
            evidence_ref="evidence://review-queue/post-restore-reclaim",
            idempotency_key="post-restore-reclaim",
            expected_state_digest=restored_item.state_digest,
            lease_seconds=900,
        )
        self.assertTrue(reclaimed.created)
        self.assertEqual(reclaimed.action, "RECLAIM")
        self.assertGreater(reclaimed.fence, old_permit.fence)
        self.assertNotEqual(
            reclaimed.source_read_epoch_hash,
            old_permit.source_read_epoch_hash,
        )
        resolved = restored_queue.resolve_claimed(
            reclaimed,
            decision="NEEDS_RESEARCH",
            reason="CONTACT_ENRICHMENT_REQUIRED",
            evidence_ref="evidence://review-queue/post-restore-resolution",
            idempotency_key="post-restore-resolution",
        )
        self.assertTrue(resolved.created)
        final_item = self._item(wave_item.review_id, queue=restored_queue)
        self.assertEqual(final_item.state, "NEEDS_RESEARCH")
        self.assertEqual(final_item.latest_decision, "NEEDS_RESEARCH")
        self.assertGreaterEqual(
            self._queue_integrity(restored_store)["event_count"],
            3,
        )

    def test_semantic_integrity_binds_site_claim_to_its_sla_owner(self) -> None:
        site_item = next(
            item
            for item in self._all_pages(limit=20, source_id=site_fixture.SOURCE_ID)
        )
        self.queue.claim(
            review_id=site_item.review_id,
            claimant="dima",
            evidence_ref="evidence://review-queue/site-owner-proof",
            idempotency_key="site-owner-proof",
            expected_state_digest=site_item.state_digest,
            lease_seconds=900,
        )
        con = self.store.connect()
        try:
            trigger_sql = str(
                con.execute(
                    "SELECT sql FROM sqlite_master WHERE name='trg_lf_events_no_update'"
                ).fetchone()[0]
            )
            row = con.execute(
                "SELECT event_id,payload_json,evidence_ref FROM events "
                "WHERE producer='source_lab_review_queue'"
            ).fetchone()
            forged = json.loads(str(row[1]))
            forged["actor"] = "other-reviewer"
            forged["assignee"] = "other-reviewer"
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
                    "expected_state_digest": forged["expected_state_digest"],
                    "previous_claim_event_id": forged["previous_claim_event_id"],
                    "idempotency_key_hash": forged["idempotency_key_hash"],
                }
            )
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            con.execute(
                "UPDATE events SET actor=?,payload_json=?,payload_hash=? "
                "WHERE event_id=?",
                (
                    forged["actor"],
                    canonical_json(forged),
                    payload_hash(forged),
                    row[0],
                ),
            )
            con.execute(trigger_sql)
            con.commit()
            with self.assertRaises(SourceReviewQueueIntegrityError):
                validate_source_review_queue_integrity(con)
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
