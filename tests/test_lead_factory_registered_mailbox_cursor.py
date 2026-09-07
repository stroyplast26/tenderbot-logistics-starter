import concurrent.futures
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from lead_factory.mail_registry import MailRegistry
from lead_factory.mailbox_cursor import RegisteredMailboxCursor
from lead_factory.store import FactoryStore, V16_SCHEMA_VERSION


EVIDENCE = "offline-test:registered-mailbox-cursor"
ACTOR = "offline_test"


class RegisteredMailboxCursorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = FactoryStore(Path(self.temp.name) / "factory.sqlite3")
        self.store.init()
        self.registry = MailRegistry(self.store)
        provider = self.registry.register_provider_account(
            provider_type="IMAP",
            label="offline-fixture",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
            daily_send_cap=10,
        )
        self.provider_id = provider.entity_id
        self.registry.activate_provider_account(
            self.provider_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        domain = self.registry.register_sending_domain(
            provider_account_id=self.provider_id,
            domain="cursor.example.invalid",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
            daily_send_cap=10,
            reputation_state="VERIFIED",
        )
        self.domain_id = domain.entity_id
        self.registry.activate_sending_domain(
            self.domain_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.mailbox_ids = (
            self._mailbox("one"),
            self._mailbox("two"),
        )

    def _mailbox(self, local_part):
        mailbox = self.registry.register_mailbox_account(
            provider_account_id=self.provider_id,
            sending_domain_id=self.domain_id,
            address=f"{local_part}@cursor.example.invalid",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
            daily_send_cap=10,
        )
        self.registry.activate_mailbox_account(
            mailbox.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        return mailbox.entity_id

    def _cursor(self, mailbox_id, folder="INBOX"):
        return RegisteredMailboxCursor(
            self.store,
            consumer_id="unified_inbound_v14",
            mailbox_account_id=mailbox_id,
            folder=folder,
        )

    def _event(self, cursor, uid, uid_validity):
        event, _ = self.store.append_event(
            event_type="registered_mailbox_message_persisted",
            aggregate_type="mailbox_cursor",
            aggregate_id=cursor.mailbox,
            producer=cursor.consumer_id,
            idempotency_key=f"registered:{cursor.mailbox}:{uid_validity}:{uid}",
            payload={
                "mailbox": cursor.mailbox,
                "uid": str(uid),
                "uid_validity": str(uid_validity),
            },
            evidence_ref=EVIDENCE,
            actor=ACTOR,
            schema_version=14,
        )
        return event["event_id"]

    def test_accounts_and_folders_have_independent_durable_cursors(self):
        account_one = self._cursor(self.mailbox_ids[0])
        account_two = self._cursor(self.mailbox_ids[1])
        archive = self._cursor(self.mailbox_ids[0], "Archive/2026")
        self.assertEqual(account_one._minimum_schema_version(), V16_SCHEMA_VERSION)

        account_one.initialize(uid_validity="101", last_persisted_uid=7)
        account_two.initialize(uid_validity="202", last_persisted_uid=11)
        archive.initialize(uid_validity="303", last_persisted_uid=19)

        self.assertEqual(account_one.get().last_persisted_uid, 7)
        self.assertEqual(account_two.get().last_persisted_uid, 11)
        self.assertEqual(archive.get().last_persisted_uid, 19)
        self.assertEqual(account_one.get().mailbox_account_id, self.mailbox_ids[0])
        self.assertEqual(archive.get().folder, "Archive/2026")
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM registered_inbox_cursor_bindings"
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                {
                    int(row[0])
                    for row in con.execute(
                        "SELECT schema_version FROM events "
                        "WHERE event_type='registered_inbox_cursor_bound'"
                    ).fetchall()
                },
                {V16_SCHEMA_VERSION},
            )
        finally:
            con.close()

    def test_restart_resumes_exact_manifest_and_duplicate_uid_cannot_advance(self):
        cursor = self._cursor(self.mailbox_ids[0])
        cursor.initialize(uid_validity="100")
        manifest_id = cursor.register_manifest(
            uid_validity="100", uids=[5, 7], snapshot_ref=EVIDENCE
        )
        cursor.advance_after_persist(
            uid_validity="100",
            uid=5,
            event_id=self._event(cursor, 5, "100"),
            manifest_id=manifest_id,
        )

        restarted = self._cursor(self.mailbox_ids[0])
        self.assertEqual(restarted.get().last_persisted_uid, 5)
        self.assertEqual(restarted.get_active_manifest()["next_uid"], 7)
        with self.assertRaises(ValueError):
            restarted.advance_after_persist(
                uid_validity="100",
                uid=5,
                event_id=self._event(cursor, 5, "100"),
                manifest_id=manifest_id,
            )
        restarted.advance_after_persist(
            uid_validity="100",
            uid=7,
            event_id=self._event(cursor, 7, "100"),
            manifest_id=manifest_id,
        )
        self.assertIsNone(restarted.get_active_manifest())

    def test_binding_and_cursor_initialization_roll_back_together_on_failure(self):
        cursor = self._cursor(self.mailbox_ids[0])
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """CREATE TRIGGER offline_cursor_init_fault
                   BEFORE INSERT ON inbox_cursors
                   WHEN NEW.mailbox=?
                   BEGIN SELECT RAISE(ABORT, 'offline fault'); END""".replace(
                    "?", "'" + cursor.mailbox + "'"
                )
            )
        with self.assertRaises(sqlite3.DatabaseError):
            cursor.initialize(uid_validity="100")
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM registered_inbox_cursor_bindings
                       WHERE consumer_id=? AND cursor_mailbox_key=?""",
                    (cursor.consumer_id, cursor.mailbox),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                    (cursor.consumer_id, cursor.mailbox),
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

    def test_concurrent_initialization_creates_one_binding_and_one_cursor(self):
        barrier = threading.Barrier(2)

        def initialize(_index):
            local = self._cursor(self.mailbox_ids[0])
            barrier.wait(timeout=5)
            return local.initialize(uid_validity="100")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            states = list(executor.map(initialize, range(2)))
        self.assertEqual({state.last_persisted_uid for state in states}, {0})
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute("SELECT COUNT(*) FROM registered_inbox_cursor_bindings").fetchone()[0],
                1,
            )
            self.assertEqual(con.execute("SELECT COUNT(*) FROM inbox_cursors").fetchone()[0], 1)
        finally:
            con.close()

    def test_inactive_mailbox_and_binding_mutation_fail_closed(self):
        cursor = self._cursor(self.mailbox_ids[0])
        cursor.initialize(uid_validity="100")
        con = self.store.connect()
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    """UPDATE registered_inbox_cursor_bindings SET folder='Other'
                       WHERE consumer_id=? AND cursor_mailbox_key=?""",
                    (cursor.consumer_id, cursor.mailbox),
                )
            con.execute(
                "UPDATE mailbox_accounts SET state='DISABLED' WHERE mailbox_account_id=?",
                (self.mailbox_ids[0],),
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaises(RuntimeError):
            cursor.get()


if __name__ == "__main__":
    unittest.main()
