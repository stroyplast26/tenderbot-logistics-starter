from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lead_factory.inbound import AUTO_REPLY, HUMAN_REPLY, InboundIntake, InboundMessage
from lead_factory.mailbox_cursor import MailboxCursor, UidValidityChanged
from lead_factory.store import FactoryStore


class MailboxCursorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "mailbox.sqlite3")
        self.store.init()
        self.cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )

    def tearDown(self):
        self.temp.cleanup()

    def persist(self, uid, uid_validity="100", classification=AUTO_REPLY):
        return InboundIntake(self.store).ingest(
            InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                external_message_id=f"<uid-{uid}-{uid_validity}@example.test>",
                uid=str(uid),
                uid_validity=str(uid_validity),
                from_address="buyer@example.test",
                contact_address="buyer@example.test",
                classification=classification,
                campaign_id="fixture",
                evidence_ref=f"imap://INBOX/{uid_validity}/{uid}",
                content_hash=f"fixture-content-{uid}-{uid_validity}",
            )
        )

    def manifest(self, uids, uid_validity="100"):
        return self.cursor.register_manifest(
            uid_validity=uid_validity,
            uids=list(uids),
            snapshot_ref=f"stage://imap-search/{uid_validity}/{'-'.join(map(str, uids))}",
        )

    def test_cursor_cannot_advance_before_event_is_durable(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=0)
        manifest_id = self.manifest([1])
        with self.assertRaises(ValueError):
            self.cursor.advance_after_persist(
                uid_validity="100", uid=1, event_id="missing-event", manifest_id=manifest_id
            )
        self.assertEqual(self.cursor.get().last_persisted_uid, 0)

    def test_crash_after_persist_replays_idempotently_then_advances(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=0)
        manifest_id = self.manifest([1])
        intake = InboundIntake(self.store)
        message = InboundMessage(
            producer="factory-unified-inbox",
            mailbox="INBOX",
            uid="1",
            uid_validity="100",
            from_address="buyer@example.test",
            contact_address="buyer@example.test",
            classification=HUMAN_REPLY,
            campaign_id="fixture",
            evidence_ref="imap://INBOX/100/1",
            content_hash="fixture-content",
        )
        intake.ingest(message)
        # Simulated process death here: the durable event exists but the cursor
        # still points to zero. The next run reads UID 1 again.
        self.assertEqual(self.cursor.get().last_persisted_uid, 0)
        replayed = intake.ingest(message)
        self.assertFalse(replayed.created)
        state = self.cursor.advance_after_persist(
            uid_validity="100", uid=1, event_id=replayed.event_id, manifest_id=manifest_id
        )
        self.assertEqual(state.last_persisted_uid, 1)
        self.assertEqual(self.store.table_count("interactions"), 1)
        self.assertEqual(self.store.table_count("human_tasks"), 1)

    def test_cursor_never_regresses(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=0)
        manifest_id = self.manifest([1, 2])
        first = self.persist(1)
        self.cursor.advance_after_persist(
            uid_validity="100", uid=1, event_id=first.event_id, manifest_id=manifest_id
        )
        second = self.persist(2)
        state = self.cursor.advance_after_persist(
            uid_validity="100", uid=2, event_id=second.event_id, manifest_id=manifest_id
        )
        self.assertEqual(state.last_persisted_uid, 2)
        with self.assertRaises(ValueError):
            self.cursor.advance_after_persist(
                uid_validity="100", uid=1, event_id=first.event_id, manifest_id=manifest_id
            )
        self.assertEqual(self.cursor.get().last_persisted_uid, 2)

    def test_wrong_event_or_uid_gap_cannot_advance_cursor(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=0)
        manifest_id = self.manifest([2, 3])
        event_two = self.persist(2)
        with self.assertRaises(ValueError):
            self.cursor.advance_after_persist(
                uid_validity="100", uid=1, event_id=event_two.event_id, manifest_id=manifest_id
            )
        event_three = self.persist(3)
        with self.assertRaises(ValueError):
            self.cursor.advance_after_persist(
                uid_validity="100", uid=3, event_id=event_three.event_id, manifest_id=manifest_id
            )
        self.assertEqual(self.cursor.get().last_persisted_uid, 0)

    def test_uidvalidity_change_is_persisted_as_reset_required(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=5)
        manifest_id = self.manifest([6])
        event, _ = self.store.append_event(
            event_type="fixture",
            aggregate_type="mail",
            aggregate_id="6",
            producer="tests",
            idempotency_key="mail-6",
            payload={},
        )
        with self.assertRaises(UidValidityChanged):
            self.cursor.advance_after_persist(
                uid_validity="200", uid=6, event_id=event["event_id"], manifest_id=manifest_id
            )
        state = self.cursor.get()
        self.assertEqual(state.state, "RESET_REQUIRED")
        self.assertEqual(state.last_persisted_uid, 5)
        matching_old_event = self.persist(6, uid_validity="100")
        with self.assertRaises(RuntimeError):
            self.cursor.advance_after_persist(
                uid_validity="100", uid=6, event_id=matching_old_event.event_id, manifest_id=manifest_id
            )
        self.assertEqual(self.cursor.get().state, "RESET_REQUIRED")

    def test_reset_requires_explicit_rescan_evidence(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=5)
        with self.assertRaises(UidValidityChanged):
            self.cursor.register_manifest(
                uid_validity="200",
                uids=[6],
                snapshot_ref="stage://rescan/detected-new-validity",
            )
        reset = self.cursor.reset_after_rescan(
            uid_validity="200",
            last_persisted_uid=5,
            evidence_ref="stage://rescan/fixture",
            actor="test-operator",
        )
        self.assertEqual(reset.state, "ACTIVE")
        manifest_id = self.manifest([6], uid_validity="200")
        event = self.persist(6, uid_validity="200")
        advanced = self.cursor.advance_after_persist(
            uid_validity="200", uid=6, event_id=event.event_id, manifest_id=manifest_id
        )
        self.assertEqual(advanced.last_persisted_uid, 6)

    def test_sparse_real_imap_uids_advance_in_manifest_order(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=0)
        first_manifest = self.manifest([5, 7])
        event_five = self.persist(5)
        event_seven = self.persist(7)
        event_nine = self.persist(9)
        state = self.cursor.advance_after_persist(
            uid_validity="100", uid=5, event_id=event_five.event_id,
            manifest_id=first_manifest,
        )
        self.assertEqual(state.last_persisted_uid, 5)
        restarted = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        active = restarted.get_active_manifest()
        self.assertEqual(active["manifest_id"], first_manifest)
        self.assertEqual(active["next_uid"], 7)
        self.assertEqual(
            restarted.register_manifest(
                uid_validity="100",
                uids=[5, 7],
                snapshot_ref="stage://imap-search/replayed-snapshot",
            ),
            first_manifest,
        )
        with self.assertRaises(ValueError):
            self.cursor.advance_after_persist(
                uid_validity="100", uid=9, event_id=event_nine.event_id,
                manifest_id=first_manifest,
            )
        state = self.cursor.advance_after_persist(
            uid_validity="100", uid=7, event_id=event_seven.event_id,
            manifest_id=first_manifest,
        )
        self.assertEqual(state.last_persisted_uid, 7)
        second_manifest = self.manifest([9])
        state = self.cursor.advance_after_persist(
            uid_validity="100", uid=9, event_id=event_nine.event_id,
            manifest_id=second_manifest,
        )
        self.assertEqual(state.last_persisted_uid, 9)

    def test_restart_resumes_active_manifest_after_partial_batch(self):
        self.cursor.initialize(uid_validity="100", last_persisted_uid=0)
        manifest_id = self.manifest([5, 7])
        event_five = self.persist(5)
        self.cursor.advance_after_persist(
            uid_validity="100",
            uid=5,
            event_id=event_five.event_id,
            manifest_id=manifest_id,
        )

        # Simulate a process death before UID 7 was fetched and persisted.
        restarted = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        active = restarted.get_active_manifest()
        self.assertIsNotNone(active)
        self.assertEqual(active["manifest_id"], manifest_id)
        self.assertEqual(active["next_uid"], 7)

        event_seven = self.persist(7)
        state = restarted.advance_after_persist(
            uid_validity="100",
            uid=7,
            event_id=event_seven.event_id,
            manifest_id=active["manifest_id"],
        )
        self.assertEqual(state.last_persisted_uid, 7)
        self.assertIsNone(restarted.get_active_manifest())


if __name__ == "__main__":
    unittest.main()
