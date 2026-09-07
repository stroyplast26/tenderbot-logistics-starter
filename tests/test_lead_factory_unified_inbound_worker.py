from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.mailbox_cursor import MailboxCursor
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import (
    EvidenceReceipt,
    InboundWorkerError,
    LocalEvidenceVault,
    UNROUTED,
    UnifiedInboundWorker,
)


def message(uid: int, *, body: str = "reply") -> dict:
    raw_mime = (
        f"From: buyer{uid}@example.test\r\n"
        "To: sales@example.test\r\n"
        f"Message-ID: <stage-{uid}@example.test>\r\n"
        f"Subject: Stage {uid}\r\n\r\n{body}"
    ).encode("utf-8")
    return {
        "uid": uid,
        "msgid": f"<stage-{uid}@example.test>",
        "from": f"buyer{uid}@example.test",
        "subject": f"Stage {uid}",
        "body": body,
        "date": "Fri, 01 Jan 2021 12:00:00 +0000",
        "rfc822_bytes": raw_mime,
        "rfc822_sha256": hashlib.sha256(raw_mime).hexdigest(),
    }


class FakeFetcher:
    def __init__(self, *, fresh: dict | None = None, resumes: dict[tuple[int, ...], dict] | None = None):
        self.fresh = fresh or {"uidvalidity": "100", "selected_uids": [], "messages": []}
        self.resumes = resumes or {}
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(dict(kwargs))
        requested = kwargs.get("uids")
        if requested is None:
            return self.fresh
        return self.resumes[tuple(requested)]


class UnifiedInboundWorkerTests(unittest.TestCase):
    def setUp(self):
        self._authority_patch = patch(
            "lead_factory.unified_inbound_worker.assert_external_allowed",
            return_value=None,
        )
        self._authority_patch.start()
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "stage.sqlite3")
        self.store.init()

    def tearDown(self):
        self.temp.cleanup()
        self._authority_patch.stop()

    def make_worker(self, fetcher, **kwargs):
        cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        return UnifiedInboundWorker(
            cursor=cursor, intake=InboundIntake(self.store), fetch_uid_batch=fetcher, **kwargs
        )

    def test_new_batch_persists_raw_evidence_before_unrouted_interactions(self):
        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5, 7],
                "messages": [message(5), message(7)],
            }
        )
        run = self.make_worker(fetcher).run_once()

        self.assertEqual(run.status, "NEW_MANIFEST")
        self.assertEqual(run.persisted_uids, (5, 7))
        self.assertEqual(self.store.table_count("interactions"), 2)
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("outbox"), 0)
        self.assertEqual(self.store.table_count("crm_outbox"), 0)
        con = self.store.connect()
        try:
            unrouted = con.execute(
                "SELECT COUNT(*) FROM interactions WHERE classification=?", (UNROUTED,)
            ).fetchone()[0]
            event_payload = json.loads(
                con.execute(
                    "SELECT payload_json FROM events WHERE event_type='inbound_received' "
                    "ORDER BY recorded_at_utc,event_id LIMIT 1"
                ).fetchone()[0]
            )
        finally:
            con.close()
        self.assertEqual(unrouted, 2)
        self.assertEqual(len(event_payload["evidence_sha256"]), 64)
        self.assertGreater(event_payload["evidence_size"], 0)
        self.assertEqual(event_payload["parser_version"], "tb_mail._parse/v1")
        evidence_root = Path(self.temp.name) / "evidence"
        self.assertEqual(len(list(evidence_root.rglob("*.eml"))), 2)
        self.assertEqual(len(list(evidence_root.rglob("*.json"))), 2)

    def test_sender_and_message_identity_are_derived_from_raw_mime(self):
        altered = message(5)
        altered.update({
            "from": "attacker@example.test",
            "msgid": "<forged@example.test>",
            "in_reply_to": "<forged-thread@example.test>",
            "subject": "Forged subject",
            "body": "Forged body",
        })
        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5],
                "messages": [altered],
            }
        )
        self.make_worker(fetcher).run_once()
        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT address,external_message_id,thread_id,classification "
                "FROM interactions"
            ).fetchone()
        finally:
            con.close()
        self.assertEqual(row["address"], "buyer5@example.test")
        self.assertEqual(row["external_message_id"], "<stage-5@example.test>")
        self.assertEqual(row["thread_id"], "")
        self.assertEqual(row["classification"], UNROUTED)

    def test_reader_cannot_create_a_human_task_without_separate_routing(self):
        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5],
                "messages": [message(5)],
            }
        )

        def unsafe_builder(raw, *, uid, uid_validity):
            return InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                uid=str(uid),
                uid_validity=uid_validity,
                from_address="other@example.test",
                contact_address="other@example.test",
                classification="HUMAN_REPLY",
                create_human_task=True,
            )

        worker = self.make_worker(fetcher, message_builder=unsafe_builder)
        with self.assertRaisesRegex(InboundWorkerError, "must remain UNROUTED"):
            worker.run_once()
        self.assertEqual(worker.cursor.get().last_persisted_uid, 0)
        self.assertEqual(self.store.table_count("interactions"), 0)
        self.assertEqual(self.store.table_count("human_tasks"), 0)

    def test_worker_requires_explicit_fetcher_and_cannot_read_live_mail_by_default(self):
        cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        with self.assertRaisesRegex(ValueError, "explicitly injected"):
            UnifiedInboundWorker(cursor=cursor, intake=InboundIntake(self.store))

    def test_uidvalidity_change_is_audited_and_enables_explicit_reset(self):
        cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        cursor.initialize(uid_validity="100")
        fetcher = FakeFetcher(
            fresh={"uidvalidity": "200", "selected_uids": [], "messages": []}
        )
        worker = UnifiedInboundWorker(
            cursor=cursor, intake=InboundIntake(self.store), fetch_uid_batch=fetcher
        )
        with self.assertRaisesRegex(InboundWorkerError, "UIDVALIDITY changed"):
            worker.run_once()
        self.assertEqual(cursor.get().state, "RESET_REQUIRED")
        con = self.store.connect()
        try:
            change_event = con.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='inbox_cursor_uidvalidity_changed'"""
            ).fetchone()
        finally:
            con.close()
        self.assertIsNotNone(change_event)
        payload = json.loads(change_event[0])
        self.assertEqual(payload["previous_uid_validity"], "100")
        self.assertEqual(payload["observed_uid_validity"], "200")
        reset = cursor.reset_after_rescan(
            uid_validity="200",
            last_persisted_uid=0,
            evidence_ref="stage://rescan/fixture",
            actor="test-operator",
        )
        self.assertEqual(reset.state, "ACTIVE")
        self.assertEqual(reset.uid_validity, "200")

    def test_active_manifest_uidvalidity_change_requires_rescan_before_resume(self):
        cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        cursor.initialize(uid_validity="100")
        cursor.register_manifest(
            uid_validity="100", uids=[5], snapshot_ref="stage://manifest/100/5"
        )
        fetcher = FakeFetcher(
            resumes={(5,): {"uidvalidity": "200", "selected_uids": [5], "messages": []}}
        )
        worker = UnifiedInboundWorker(
            cursor=cursor,
            intake=InboundIntake(self.store),
            fetch_uid_batch=fetcher,
        )

        with self.assertRaisesRegex(InboundWorkerError, "UIDVALIDITY changed while resuming"):
            worker.run_once()

        self.assertEqual(cursor.get().state, "RESET_REQUIRED")
        self.assertIsNone(cursor.get_active_manifest())
        reset = cursor.reset_after_rescan(
            uid_validity="200",
            last_persisted_uid=0,
            evidence_ref="stage://rescan/active-manifest",
            actor="test",
        )
        self.assertEqual(reset.state, "ACTIVE")
        self.assertEqual(reset.uid_validity, "200")

    def test_evidence_vault_is_called_before_any_inbound_event(self):
        fetcher = FakeFetcher(
            fresh={"uidvalidity": "100", "selected_uids": [5], "messages": [message(5)]}
        )
        evidence_root = Path(self.temp.name) / "ordered-evidence"
        evidence_counts: list[tuple[int, int]] = []

        def after_event():
            evidence_counts.append((
                len(list(evidence_root.rglob("*.eml"))),
                len(list(evidence_root.rglob("*.json"))),
            ))

        cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        worker = UnifiedInboundWorker(
            cursor=cursor,
            intake=InboundIntake(self.store, after_event_hook=after_event),
            fetch_uid_batch=fetcher,
            evidence_vault=LocalEvidenceVault(evidence_root),
        )
        worker.run_once()

        self.assertEqual(evidence_counts, [(1, 1)])

    def test_arbitrary_or_noop_evidence_vault_is_rejected(self):
        raw = message(5)["rfc822_bytes"]
        receipt = LocalEvidenceVault(Path(self.temp.name) / "source-vault").put(
            raw,
            mailbox="INBOX",
            uid_validity="100",
            uid=5,
            parser_version="tb_mail._parse/v1",
        )

        class NoOpVerifyVault:
            def put(self, raw_mime, **kwargs):
                return receipt

            def verify(self, candidate, **kwargs):
                return None

        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5],
                "messages": [message(5)],
            }
        )
        with self.assertRaisesRegex(ValueError, "only the audited LocalEvidenceVault"):
            self.make_worker(fetcher, evidence_vault=NoOpVerifyVault())

    def test_evidence_reference_must_exist_in_the_selected_vault(self):
        raw = message(5)["rfc822_bytes"]
        receipt = LocalEvidenceVault(Path(self.temp.name) / "source-vault").put(
            raw,
            mailbox="INBOX",
            uid_validity="100",
            uid=5,
            parser_version="tb_mail._parse/v1",
        )
        empty_delegate = LocalEvidenceVault(Path(self.temp.name) / "empty-vault")

        with self.assertRaisesRegex(InboundWorkerError, "does not resolve"):
            empty_delegate.verify(
                receipt,
                raw_mime=raw,
                mailbox="INBOX",
                uid_validity="100",
                uid=5,
                parser_version="tb_mail._parse/v1",
            )

    def test_evidence_metadata_is_bound_to_exact_mailbox_uid_and_uidvalidity(self):
        raw = message(5)["rfc822_bytes"]
        wrong_receipt = LocalEvidenceVault(Path(self.temp.name) / "wrong-envelope").put(
            raw,
            mailbox="OTHER",
            uid_validity="999",
            uid=7,
            parser_version="tb_mail._parse/v1",
        )

        wrong_vault = LocalEvidenceVault(Path(self.temp.name) / "wrong-envelope")
        with self.assertRaisesRegex(InboundWorkerError, "not bound"):
            wrong_vault.verify(
                wrong_receipt,
                raw_mime=raw,
                mailbox="INBOX",
                uid_validity="100",
                uid=5,
                parser_version="tb_mail._parse/v1",
            )

    def test_evidence_pointer_cannot_be_substituted_for_another_raw_message(self):
        raw_b = message(7)["rfc822_bytes"]
        receipt_b = LocalEvidenceVault(Path(self.temp.name) / "other-evidence").put(
            raw_b,
            mailbox="INBOX",
            uid_validity="100",
            uid=7,
            parser_version="tb_mail._parse/v1",
        )

        substituted = EvidenceReceipt(
            evidence_ref=receipt_b.evidence_ref,
            sha256=hashlib.sha256(message(5)["rfc822_bytes"]).hexdigest(),
            size=len(message(5)["rfc822_bytes"]),
            parser_version="tb_mail._parse/v1",
        )
        vault = LocalEvidenceVault(Path(self.temp.name) / "other-evidence")
        with self.assertRaisesRegex(InboundWorkerError, "not bound"):
            vault.verify(
                substituted,
                raw_mime=message(5)["rfc822_bytes"],
                mailbox="INBOX",
                uid_validity="100",
                uid=5,
                parser_version="tb_mail._parse/v1",
            )

    def test_restart_resumes_exact_manifest_without_a_new_search(self):
        first_fetch = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5, 7],
                "messages": [message(5), message(7)],
            }
        )

        def fail_on_seven(raw, *, uid, uid_validity):
            if uid == 7:
                raise RuntimeError("simulated parser failure")
            return InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                uid=str(uid),
                uid_validity=uid_validity,
                classification=UNROUTED,
                create_human_task=False,
            )

        with self.assertRaisesRegex(RuntimeError, "simulated parser failure"):
            self.make_worker(first_fetch, message_builder=fail_on_seven).run_once()
        cursor = MailboxCursor(
            self.store, consumer_id="factory-unified-inbox", mailbox="INBOX"
        )
        self.assertEqual(cursor.get().last_persisted_uid, 5)
        active = cursor.get_active_manifest()
        self.assertEqual(active["next_uid"], 7)

        resumed_fetch = FakeFetcher(resumes={(7,): {
            "uidvalidity": "100", "selected_uids": [7], "messages": [message(7)]
        }})
        resumed = self.make_worker(resumed_fetch).run_once()

        self.assertEqual(resumed.status, "RESUMED")
        self.assertEqual(resumed.persisted_uids, (7,))
        self.assertEqual(resumed_fetch.calls[0]["uids"], [7])
        self.assertEqual(cursor.get().last_persisted_uid, 7)
        self.assertIsNone(cursor.get_active_manifest())

    def test_missing_raw_mime_leaves_uid_unadvanced_in_durable_manifest(self):
        raw = message(5)
        raw.pop("rfc822_bytes")
        fetcher = FakeFetcher(
            fresh={"uidvalidity": "100", "selected_uids": [5], "messages": [raw]}
        )
        worker = self.make_worker(fetcher)

        with self.assertRaisesRegex(InboundWorkerError, "raw MIME evidence"):
            worker.run_once()
        self.assertEqual(worker.cursor.get().last_persisted_uid, 0)
        self.assertEqual(worker.cursor.get_active_manifest()["next_uid"], 5)
        self.assertEqual(self.store.table_count("interactions"), 0)

    def test_malformed_uid_sequence_cannot_create_a_manifest_or_advance_cursor(self):
        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5, 7],
                "messages": [message(7), message(5)],
            }
        )
        worker = self.make_worker(fetcher)

        with self.assertRaises(InboundWorkerError):
            worker.run_once()
        self.assertEqual(worker.cursor.get().last_persisted_uid, 0)
        self.assertIsNone(worker.cursor.get_active_manifest())
        self.assertEqual(self.store.table_count("interactions"), 0)

    def test_fetch_gap_is_reported_and_the_next_uid_remains_retryable(self):
        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5, 7],
                "messages": [message(5)],
            }
        )
        worker = self.make_worker(fetcher)
        run = worker.run_once()

        self.assertEqual(run.status, "PARTIAL_FETCH")
        self.assertEqual(run.persisted_uids, (5,))
        self.assertEqual(run.next_uid, 7)
        self.assertEqual(worker.cursor.get().last_persisted_uid, 5)
        self.assertEqual(worker.cursor.get_active_manifest()["next_uid"], 7)

    def test_same_message_id_under_two_uids_advances_both_without_second_task(self):
        copy = message(5)
        copy["uid"] = 7
        fetcher = FakeFetcher(
            fresh={
                "uidvalidity": "100",
                "selected_uids": [5, 7],
                "messages": [message(5), copy],
            }
        )
        worker = self.make_worker(fetcher)
        run = worker.run_once()

        self.assertEqual(run.persisted_uids, (5, 7))
        self.assertEqual(worker.cursor.get().last_persisted_uid, 7)
        self.assertEqual(self.store.table_count("events"), 4)  # cursor, manifest, two receive events
        self.assertEqual(self.store.table_count("interactions"), 1)
        self.assertEqual(self.store.table_count("human_tasks"), 0)


if __name__ == "__main__":
    unittest.main()
