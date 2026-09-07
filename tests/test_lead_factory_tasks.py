from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lead_factory.inbound import HUMAN_REPLY, InboundIntake, InboundMessage
from lead_factory.store import FactoryStore
from lead_factory.tasks import HumanTaskController, TaskStateError


class HumanTaskControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "tasks.sqlite3")
        self.store.init()
        result = InboundIntake(self.store).ingest(
            InboundMessage(
                producer="task-test",
                mailbox="INBOX",
                external_message_id="<task@example.test>",
                uid="1",
                uid_validity="100",
                from_address="buyer@example.test",
                contact_address="buyer@example.test",
                received_at_utc="2026-08-18T09:00:00Z",
                classification=HUMAN_REPLY,
                campaign_id="fixture",
                evidence_ref="stage://task/fixture",
            )
        )
        self.task_id = result.task_id
        self.tasks = HumanTaskController(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_acknowledge_first_action_complete_are_monotonic_and_idempotent(self):
        acknowledged = self.tasks.acknowledge(
            self.task_id,
            actor="dima",
            evidence_ref="stage://action/ack",
            at_utc="2026-08-18T09:01:00Z",
        )
        self.assertTrue(acknowledged.changed)
        self.assertFalse(
            self.tasks.acknowledge(
                self.task_id,
                actor="dima",
                evidence_ref="stage://action/ack",
                at_utc="2026-08-18T09:02:00Z",
            ).changed
        )
        action = self.tasks.record_first_action(
            self.task_id,
            actor="dima",
            evidence_ref="stage://action/first",
            at_utc="2026-08-18T09:03:00Z",
        )
        self.assertEqual(action.state, "IN_PROGRESS")
        completed = self.tasks.complete(
            self.task_id,
            actor="dima",
            evidence_ref="stage://action/complete",
            resolution="QUALIFIED_FOR_REVIEW",
            at_utc="2026-08-18T09:05:00Z",
        )
        self.assertEqual(completed.state, "COMPLETED")
        self.assertFalse(
            self.tasks.complete(
                self.task_id,
                actor="dima",
                evidence_ref="stage://action/complete",
                resolution="QUALIFIED_FOR_REVIEW",
            ).changed
        )
        with self.assertRaises(TaskStateError):
            self.tasks.record_first_action(
                self.task_id,
                actor="dima",
                evidence_ref="stage://action/late",
            )

    def test_slo_report_and_escalation_are_deduplicated(self):
        report = self.tasks.slo_report(now_utc="2026-08-18T10:00:00Z")
        self.assertEqual(report["active"], 1)
        self.assertEqual(report["overdue"], 1)
        self.assertEqual(report["unacknowledged"], 1)
        first = self.tasks.record_overdue_escalations(
            now_utc="2026-08-18T10:00:00Z",
            actor="slo-monitor",
            escalation_owner="dima-backup",
        )
        second = self.tasks.record_overdue_escalations(
            now_utc="2026-08-18T10:05:00Z",
            actor="slo-monitor",
            escalation_owner="dima-backup",
        )
        self.assertEqual(first, [self.task_id])
        self.assertEqual(second, [])


if __name__ == "__main__":
    unittest.main()
