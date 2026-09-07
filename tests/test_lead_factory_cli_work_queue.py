from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from lead_factory.cli import main
from lead_factory.inbound import HUMAN_REPLY, InboundIntake, InboundMessage
from lead_factory.store import FactoryStore


class WorkQueueCliTests(unittest.TestCase):
    def test_work_queue_is_pii_free_and_reports_local_stop_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "queue.sqlite3"
            store = FactoryStore(database)
            store.init()
            InboundIntake(store).ingest(
                InboundMessage(
                    producer="fixture",
                    mailbox="fixture-mailbox",
                    external_message_id="<queue@example.test>",
                    uid="1",
                    uid_validity="1",
                    from_address="private.person@example.test",
                    contact_address="private.person@example.test",
                    received_at_utc="2026-08-22T10:00:00Z",
                    classification=HUMAN_REPLY,
                    evidence_ref="fixture://queue",
                    subject_hash="subject-hash",
                    content_hash="content-hash",
                    create_human_task=True,
                )
            )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--db", str(database), "work-queue"]), 0)
            report = json.loads(output.getvalue())
            self.assertFalse(report["external_writers_enabled"])
            self.assertFalse(report["external_source_reads_enabled"])
            self.assertEqual(report["outbox"], 0)
            self.assertEqual(report["crm_outbox"], 0)
            self.assertEqual(report["task_slo"]["active"], 1)
            self.assertNotIn("private.person@example.test", output.getvalue())


if __name__ == "__main__":
    unittest.main()
