from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.inbound import InboundIntake
from lead_factory.mail_registry import MailRegistry
from lead_factory.mailbox_cursor import RegisteredMailboxCursor
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import UnifiedInboundWorker


ACTOR = "offline-registered-worker-test"
EVIDENCE = "stage://registered-mailbox-worker/test"
CONSUMER = "registered_unified_inbound_v14"


def fetched_message(
    uid: int,
    *,
    message_id: str = "<shared-message@buyer.example.test>",
    sender: str = "buyer@buyer.example.test",
) -> dict:
    raw = (
        f"From: {sender}\r\n"
        "To: reply@example.test\r\n"
        f"Message-ID: {message_id}\r\n"
        "Date: Tue, 18 Aug 2026 12:00:00 +0300\r\n"
        "Subject: Offline reply\r\n\r\n"
        "Offline fixture body"
    ).encode("utf-8")
    return {
        "uid": uid,
        "rfc822_bytes": raw,
        "rfc822_sha256": hashlib.sha256(raw).hexdigest(),
    }


class OfflineFetcher:
    """Deterministic injected reader; it has no transport or network dependency."""

    def __init__(self, *, uid_validity: str, selected_uids, messages):
        self.uid_validity = str(uid_validity)
        self.selected_uids = list(selected_uids)
        self.messages = list(messages)
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(dict(kwargs))
        requested = kwargs.get("uids")
        selected = list(requested) if requested is not None else list(self.selected_uids)
        by_uid = {int(item["uid"]): item for item in self.messages}
        return {
            "uidvalidity": self.uid_validity,
            "selected_uids": selected,
            "messages": [by_uid[uid] for uid in selected if uid in by_uid],
        }


class FailingFetcher:
    def __init__(self):
        self.calls = 0

    def __call__(self, **_kwargs):
        self.calls += 1
        raise AssertionError("inactive mailbox reached the injected fetch boundary")


class RegisteredMailboxWorkerTests(unittest.TestCase):
    def setUp(self):
        authority = patch(
            "lead_factory.unified_inbound_worker.assert_external_allowed",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = FactoryStore(Path(self.temp.name) / "registered-worker.sqlite3")
        self.store.init()
        self.registry = MailRegistry(self.store)

        provider = self.registry.register_provider_account(
            provider_type="IMAP",
            label="offline registered worker",
            daily_send_cap=10,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.provider_id = provider.entity_id
        self.registry.activate_provider_account(
            self.provider_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        domain = self.registry.register_sending_domain(
            provider_account_id=self.provider_id,
            domain="registered-worker.example.test",
            daily_send_cap=10,
            reputation_state="VERIFIED",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.domain_id = domain.entity_id
        self.registry.activate_sending_domain(
            self.domain_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.mailbox_ids = (self._mailbox("one"), self._mailbox("two"))

    def _mailbox(self, local_part: str) -> str:
        mailbox = self.registry.register_mailbox_account(
            provider_account_id=self.provider_id,
            sending_domain_id=self.domain_id,
            address=f"{local_part}@registered-worker.example.test",
            daily_send_cap=10,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_mailbox_account(
            mailbox.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        return mailbox.entity_id

    def _cursor(self, mailbox_account_id: str) -> RegisteredMailboxCursor:
        return RegisteredMailboxCursor(
            self.store,
            consumer_id=CONSUMER,
            mailbox_account_id=mailbox_account_id,
            folder="INBOX",
        )

    def _worker(self, mailbox_account_id: str, fetcher) -> UnifiedInboundWorker:
        return UnifiedInboundWorker(
            cursor=self._cursor(mailbox_account_id),
            intake=InboundIntake(self.store),
            fetch_uid_batch=fetcher,
            batch_limit=20,
        )

    def _assert_no_external_handoff(self):
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM human_tasks").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM crm_outbox").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM delivery_events").fetchone()[0], 0)

    def test_two_active_accounts_have_independent_uid_cursors_and_scoped_claims(self):
        # The same physical MIME/Message-ID in two registered accounts is two
        # receive deliveries and two scoped claims, never one global collision.
        first_fetcher = OfflineFetcher(
            uid_validity="101",
            selected_uids=[5],
            messages=[fetched_message(5)],
        )
        second_fetcher = OfflineFetcher(
            uid_validity="202",
            selected_uids=[900],
            messages=[fetched_message(900)],
        )

        first = self._worker(self.mailbox_ids[0], first_fetcher).run_once()
        second = self._worker(self.mailbox_ids[1], second_fetcher).run_once()

        self.assertEqual(first.persisted_uids, (5,))
        self.assertEqual(second.persisted_uids, (900,))
        self.assertEqual(first_fetcher.calls[0]["after_uid"], 0)
        self.assertEqual(second_fetcher.calls[0]["after_uid"], 0)
        with self.store.transaction(min_schema_version=14) as con:
            cursor_rows = con.execute(
                """SELECT b.mailbox_account_id,c.uid_validity,c.last_persisted_uid,c.state
                   FROM registered_inbox_cursor_bindings b
                   JOIN inbox_cursors c
                     ON c.consumer_id=b.consumer_id
                    AND c.mailbox=b.cursor_mailbox_key
                   WHERE b.consumer_id=? ORDER BY b.mailbox_account_id""",
                (CONSUMER,),
            ).fetchall()
            claims = con.execute(
                """SELECT mailbox_account_id,message_id_key,interaction_id
                   FROM email_message_claims ORDER BY mailbox_account_id"""
            ).fetchall()
            interactions = con.execute(
                """SELECT mailbox_account_id,external_message_id,classification
                   FROM interactions ORDER BY mailbox_account_id"""
            ).fetchall()
            inbound_events = con.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='inbound_received'"
            ).fetchone()[0]

        self.assertEqual(
            {
                row["mailbox_account_id"]: (
                    row["uid_validity"], int(row["last_persisted_uid"]), row["state"]
                )
                for row in cursor_rows
            },
            {
                self.mailbox_ids[0]: ("101", 5, "ACTIVE"),
                self.mailbox_ids[1]: ("202", 900, "ACTIVE"),
            },
        )
        self.assertEqual({row["mailbox_account_id"] for row in claims}, set(self.mailbox_ids))
        self.assertEqual(len({row["interaction_id"] for row in claims}), 2)
        self.assertEqual(len({row["message_id_key"] for row in claims}), 1)
        self.assertEqual({row["mailbox_account_id"] for row in interactions}, set(self.mailbox_ids))
        self.assertEqual({row["classification"] for row in interactions}, {"UNROUTED"})
        self.assertEqual(inbound_events, 2)
        self._assert_no_external_handoff()

    def test_restart_after_persist_before_advance_replays_duplicate_safely(self):
        mailbox_id = self.mailbox_ids[0]
        raw = fetched_message(7, message_id="<restart@buyer.example.test>")
        fetcher = OfflineFetcher(
            uid_validity="303", selected_uids=[7], messages=[raw]
        )
        cursor = self._cursor(mailbox_id)
        worker = UnifiedInboundWorker(
            cursor=cursor,
            intake=InboundIntake(self.store),
            fetch_uid_batch=fetcher,
        )

        def crash_before_advance(**_kwargs):
            raise RuntimeError("offline crash after durable inbound persistence")

        cursor.advance_after_persist = crash_before_advance
        with self.assertRaisesRegex(RuntimeError, "offline crash"):
            worker.run_once()

        # Event/interaction/claim are durable, while the manifest still points
        # to UID 7. A new process must fetch that exact UID, not SEARCH again.
        restarted_cursor = self._cursor(mailbox_id)
        self.assertEqual(restarted_cursor.get().last_persisted_uid, 0)
        self.assertEqual(restarted_cursor.get_active_manifest()["next_uid"], 7)
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='inbound_received'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(con.execute("SELECT COUNT(*) FROM interactions").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM email_message_claims").fetchone()[0], 1)

        resume_fetcher = OfflineFetcher(
            uid_validity="303", selected_uids=[7], messages=[raw]
        )
        resumed = self._worker(mailbox_id, resume_fetcher).run_once()
        self.assertTrue(resumed.resumed_manifest)
        self.assertEqual(resumed.persisted_uids, (7,))
        self.assertEqual(resume_fetcher.calls, [{
            "flag": "\\Inbox", "after_uid": 0, "limit": 1, "uids": [7]
        }])
        self.assertEqual(self._cursor(mailbox_id).get().last_persisted_uid, 7)

        # A later UID carrying the same Message-ID/raw content has its own
        # receive event but reuses the account-scoped interaction claim.
        duplicate = dict(raw)
        duplicate["uid"] = 8
        duplicate_fetcher = OfflineFetcher(
            uid_validity="303", selected_uids=[8], messages=[duplicate]
        )
        duplicate_run = self._worker(mailbox_id, duplicate_fetcher).run_once()
        self.assertEqual(duplicate_run.persisted_uids, (8,))
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='inbound_received'"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(con.execute("SELECT COUNT(*) FROM interactions").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM email_message_claims").fetchone()[0], 1)
        self.assertEqual(self._cursor(mailbox_id).get().last_persisted_uid, 8)
        self._assert_no_external_handoff()

    def test_inactive_registered_mailbox_fails_before_fetch_and_other_account_remains_independent(self):
        inactive_id, active_id = self.mailbox_ids
        inactive_cursor = self._cursor(inactive_id)
        inactive_cursor.initialize(uid_validity="404")
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                "UPDATE mailbox_accounts SET state='DISABLED' WHERE mailbox_account_id=?",
                (inactive_id,),
            )

        forbidden_fetcher = FailingFetcher()
        inactive_worker = UnifiedInboundWorker(
            cursor=self._cursor(inactive_id),
            intake=InboundIntake(self.store),
            fetch_uid_batch=forbidden_fetcher,
        )
        with self.assertRaisesRegex(RuntimeError, "not ACTIVE"):
            inactive_worker.run_once()
        self.assertEqual(forbidden_fetcher.calls, 0)

        active_fetcher = OfflineFetcher(
            uid_validity="505",
            selected_uids=[11],
            messages=[
                fetched_message(
                    11,
                    message_id="<active-second@buyer.example.test>",
                    sender="second@buyer.example.test",
                )
            ],
        )
        run = self._worker(active_id, active_fetcher).run_once()
        self.assertEqual(run.persisted_uids, (11,))
        self.assertEqual(self._cursor(active_id).get().last_persisted_uid, 11)
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM interactions WHERE mailbox_account_id=?",
                    (inactive_id,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM interactions WHERE mailbox_account_id=?",
                    (active_id,),
                ).fetchone()[0],
                1,
            )
        self._assert_no_external_handoff()


if __name__ == "__main__":
    unittest.main()
