from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lead_factory.legacy_shadow import capture_campaign_reply
from lead_factory.store import FactoryStore


class LegacyShadowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "shadow.sqlite3")
        self.store.init()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def reply(**changes):
        value = {
            "msgid": "",
            "uid": "",
            "from": "employee@example.test",
            "to": "sales@example.test",
            "date": "Tue, 18 Aug 2026 10:00:00 +0300",
            "subject": "Re: proposal",
            "body": "Please call me about the project.",
            "in_reply_to": "<offer@example.test>",
        }
        value.update(changes)
        return value

    def capture(self, reply, **flags):
        return capture_campaign_reply(
            campaign_id="dealer_outreach",
            producer="legacy_dealer_poll",
            reply=reply,
            contact_address="buyer@example.test",
            store=self.store,
            **flags,
        )

    def test_message_without_message_id_has_stable_dedupe(self):
        first = self.capture(self.reply())
        duplicate = self.capture(self.reply())
        self.assertTrue(first.created)
        self.assertFalse(duplicate.created)
        self.assertEqual(self.store.table_count("events"), 1)
        self.assertEqual(self.store.table_count("interactions"), 1)
        self.assertEqual(self.store.table_count("human_tasks"), 1)

    def test_unknown_bounce_is_soft_and_not_suppressed(self):
        self.capture(
            self.reply(subject="Delivery Status Notification", body="Delivery temporarily delayed"),
            bounce=True,
        )
        con = self.store.connect()
        try:
            classification = con.execute("SELECT classification FROM interactions").fetchone()[0]
        finally:
            con.close()
        self.assertEqual(classification, "SOFT_BOUNCE")
        self.assertEqual(self.store.table_count("suppression_entries"), 0)

    def test_permanent_bounce_is_address_scoped(self):
        self.capture(
            self.reply(subject="Delivery failed", body="550 5.1.1 User unknown"),
            bounce=True,
        )
        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT classification FROM interactions"
            ).fetchone()
            suppression = con.execute(
                "SELECT address,scope FROM suppression_entries"
            ).fetchone()
        finally:
            con.close()
        self.assertEqual(row[0], "HARD_BOUNCE")
        self.assertEqual(tuple(suppression), ("buyer@example.test", "EMAIL_ADDRESS"))

    def test_delegated_unsubscribe_stops_cadence_but_needs_review(self):
        self.capture(self.reply(body="Please unsubscribe this address"), unsubscribe=True)
        con = self.store.connect()
        try:
            classification = con.execute("SELECT classification FROM interactions").fetchone()[0]
            task = con.execute("SELECT kind FROM human_tasks").fetchone()[0]
        finally:
            con.close()
        self.assertEqual(classification, "UNSUBSCRIBE_REVIEW")
        self.assertEqual(task, "SUPPRESSION_REVIEW")
        self.assertEqual(self.store.table_count("cadence_blocks"), 1)
        self.assertEqual(self.store.table_count("suppression_entries"), 0)


if __name__ == "__main__":
    unittest.main()
