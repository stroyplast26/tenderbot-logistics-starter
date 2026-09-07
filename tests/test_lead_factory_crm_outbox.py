from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from lead_factory.crm_outbox import (
    CrmOutbox,
    PermanentRemoteError,
    RetryableRemoteError,
    StaleLease,
)
from lead_factory.bitrix_canary import CorrelationReadbackMismatch, ReadbackUncertain
from lead_factory.store import FactoryStore, IdempotencyConflict


_AUTHORITY_PATCHER = patch(
    "lead_factory.crm_outbox.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class FakeTransport:
    def __init__(self, create_result="501", create_error=None, found=None):
        self.create_result = create_result
        self.create_error = create_error
        self.found = found
        self.create_calls = 0
        self.find_calls = 0

    def create_lead(self, payload, external_event_id):
        self.create_calls += 1
        if self.create_error:
            raise self.create_error
        return self.create_result

    def find_lead_by_correlation_token(self, correlation_token):
        self.find_calls += 1
        return self.found


class CrmOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "crm.sqlite3")
        self.store.init()
        self.outbox = CrmOutbox(self.store)
        self.entity_seq = 0
        self.opp_id = self.create_opportunity("fixture")
        self.set_writers(True)

    def tearDown(self):
        self.temp.cleanup()

    def set_writers(self, enabled):
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='external_writers_enabled'",
                ("1" if enabled else "0",),
            )

    def create_opportunity(self, suffix):
        self.entity_seq += 1
        company, _ = self.store.create_company(
            name=f"Company {suffix}", inn=f"770100{self.entity_seq:04d}"
        )
        project, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"], source="fixture", external_key=f"project-{suffix}"
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            lf_project_id=project["lf_project_id"],
            source="fixture",
            external_key=f"opportunity-{suffix}",
        )
        return opportunity["lf_opportunity_id"]

    def enqueue(self, payload=None):
        return self.outbox.enqueue_lead_create(
            lf_entity_id=self.opp_id,
            external_event_id="inbound:fixture:message-1",
            payload=payload or {"title": "Fixture lead"},
        )

    def state(self):
        con = self.store.connect()
        try:
            return dict(con.execute("SELECT * FROM crm_outbox").fetchone())
        finally:
            con.close()

    def test_enqueue_is_idempotent_and_payload_conflict_is_rejected(self):
        first, created = self.enqueue()
        same, created_again = self.enqueue()
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first, same)
        with self.assertRaises(IdempotencyConflict):
            self.enqueue({"title": "Changed payload"})

    def test_remote_success_is_linked_once(self):
        self.enqueue()
        transport = FakeTransport(create_result="901")
        result = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(result.state, "SENT")
        self.assertEqual(transport.create_calls, 1)
        self.assertIsNone(self.outbox.process_next(transport, worker_id="worker-a"))
        self.assertEqual(self.store.table_count("crm_mappings"), 1)

    def test_lost_response_is_not_blindly_retried_and_reconciles(self):
        self.enqueue()
        transport = FakeTransport(create_error=TimeoutError("response lost"))
        result = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(transport.create_calls, 1)
        self.assertIsNone(self.outbox.process_next(transport, worker_id="worker-b"))
        transport.create_error = None
        transport.found = "902"
        reconciled = self.outbox.reconcile_one(transport, worker_id="reconcile-a")
        self.assertEqual(reconciled.state, "SENT")
        self.assertEqual(reconciled.remote_entity_id, "902")
        self.assertEqual(transport.create_calls, 1)

    def test_crash_after_remote_success_remains_uncertain(self):
        self.enqueue()
        transport = FakeTransport(create_result="903")

        def crash():
            raise RuntimeError("local power loss")

        result = self.outbox.process_next(
            transport, worker_id="worker-a", after_remote_hook=crash
        )
        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(transport.create_calls, 1)
        self.assertIsNone(self.outbox.process_next(transport, worker_id="worker-b"))

    def test_two_workers_cannot_claim_the_same_operation(self):
        self.enqueue()
        first = self.outbox.claim_next("worker-a")
        second = self.outbox.claim_next("worker-b")
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_crash_after_claim_is_reconciled_not_left_leased(self):
        self.enqueue()
        claimed = self.outbox.claim_next("worker-a", lease_seconds=1)
        self.assertEqual(claimed["state"], "UNCERTAIN")
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET lease_until_utc='2000-01-01T00:00:00Z' WHERE operation_id=?",
                (claimed["operation_id"],),
            )
        transport = FakeTransport(found="904")
        reconciled = self.outbox.reconcile_one(transport, worker_id="reconcile-a")
        self.assertEqual(reconciled.state, "SENT")
        self.assertEqual(transport.create_calls, 0)

    def test_stale_worker_cannot_overwrite_new_lease(self):
        self.enqueue()
        old = self.outbox.claim_next("worker-old")
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET leased_by='worker-new',lease_token='lease-new',
                   lease_until_utc='2099-01-01T00:00:00Z' WHERE operation_id=?""",
                (old["operation_id"],),
            )
            current = dict(
                con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?", (old["operation_id"],)
                ).fetchone()
            )
        stale_failure = self.outbox._set_failure(
            old, state="PENDING", error=RetryableRemoteError("late 429")
        )
        self.assertEqual(stale_failure.state, "STALE")
        with self.assertRaises(StaleLease):
            self.outbox._mark_sent(old, "906")
        sent = self.outbox._mark_sent(current, "906")
        self.assertEqual(sent.state, "SENT")

    def test_writer_kill_switch_blocks_transport(self):
        self.enqueue()
        self.set_writers(False)
        transport = FakeTransport(create_result="905")
        result = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(transport.create_calls, 0)
        self.assertEqual(self.state()["state"], "PENDING")

    def test_same_opportunity_cannot_enqueue_second_create_event(self):
        self.enqueue()
        with self.assertRaises(IdempotencyConflict):
            self.outbox.enqueue_lead_create(
                lf_entity_id=self.opp_id,
                external_event_id="inbound:fixture:message-2",
                payload={"title": "Same opportunity, later reply"},
            )

    def test_remote_mapping_conflict_is_not_marked_sent(self):
        other_opp = self.create_opportunity("other")
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO crm_mappings(
                    lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,
                    state,last_readback_at_utc,created_at_utc
                ) VALUES('opportunity',?,'lead','999','ACTIVE','','2026-08-18T00:00:00Z')""",
                (other_opp,),
            )
        self.enqueue()
        result = self.outbox.process_next(
            FakeTransport(create_result="999"), worker_id="worker-a"
        )
        self.assertEqual(result.state, "CONFLICT_REVIEW")
        state = self.state()
        self.assertNotEqual(state["state"], "SENT")
        self.assertEqual(state["suspect_remote_entity_type"], "lead")
        self.assertEqual(state["suspect_remote_entity_id"], "999")

    def test_suspect_remote_id_is_preserved_for_manual_conflict_review(self):
        self.enqueue()
        result = self.outbox.process_next(
            FakeTransport(create_error=CorrelationReadbackMismatch("777")),
            worker_id="worker-a",
        )
        self.assertEqual(result.state, "CONFLICT_REVIEW")
        state = self.state()
        self.assertEqual(state["suspect_remote_entity_type"], "lead")
        self.assertEqual(state["suspect_remote_entity_id"], "777")

    def test_readback_uncertainty_preserves_suspect_id_without_dead_letter(self):
        self.enqueue()
        result = self.outbox.process_next(
            FakeTransport(create_error=ReadbackUncertain("778")), worker_id="worker-a"
        )
        self.assertEqual(result.state, "UNCERTAIN")
        state = self.state()
        self.assertEqual(state["state"], "UNCERTAIN")
        self.assertEqual(state["suspect_remote_entity_type"], "lead")
        self.assertEqual(state["suspect_remote_entity_id"], "778")

    def test_reconcile_keeps_existing_suspect_id_until_resolved(self):
        self.enqueue()
        self.outbox.process_next(
            FakeTransport(create_error=ReadbackUncertain("779")), worker_id="worker-a"
        )
        reconciled = self.outbox.reconcile_one(FakeTransport(found=None), worker_id="reconcile-a")
        self.assertEqual(reconciled.state, "UNCERTAIN")
        state = self.state()
        self.assertEqual(state["suspect_remote_entity_type"], "lead")
        self.assertEqual(state["suspect_remote_entity_id"], "779")

    def test_writer_switch_is_rechecked_after_claim_before_create(self):
        self.enqueue()
        original = self.outbox._writers_enabled
        checks = 0

        def close_switch_after_claim():
            nonlocal checks
            checks += 1
            if checks == 3:
                self.set_writers(False)
            return original()

        transport = FakeTransport(create_result="907")
        with patch.object(self.outbox, "_writers_enabled", side_effect=close_switch_after_claim):
            result = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(transport.create_calls, 0)
        state = self.state()
        self.assertEqual(state["state"], "PENDING")
        self.assertEqual(state["lease_token"], "")

    def test_explicit_retryable_and_permanent_failures_are_separate(self):
        self.enqueue()
        retry = FakeTransport(create_error=RetryableRemoteError("429 rejected"))
        result = self.outbox.process_next(retry, worker_id="worker-a")
        self.assertEqual(result.state, "PENDING")
        self.assertTrue(self.state()["next_attempt_at_utc"])

        second = CrmOutbox(self.store)
        second_opp = self.create_opportunity("second")
        second.enqueue_lead_create(
            lf_entity_id=second_opp,
            external_event_id="inbound:fixture:message-2",
            payload={"title": "Second fixture"},
        )
        permanent = FakeTransport(create_error=PermanentRemoteError("invalid field"))
        dead = second.process_next(permanent, worker_id="worker-b")
        self.assertEqual(dead.state, "DEAD")


if __name__ == "__main__":
    unittest.main()
