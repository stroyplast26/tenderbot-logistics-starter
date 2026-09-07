from __future__ import annotations

import hashlib
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from lead_factory.inbound import InboundIntake
from lead_factory.mailbox_cursor import MailboxCursor
from lead_factory.policy import SendGate, SendIntent
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore
from lead_factory.tasks import HumanTaskController
from lead_factory.unified_inbound_worker import LocalEvidenceVault, UnifiedInboundWorker


class StageTwoAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self._authority_patch = patch(
            "lead_factory.unified_inbound_worker.assert_external_allowed",
            return_value=None,
        )
        self._authority_patch.start()

    def tearDown(self):
        self._authority_patch.stop()

    def test_ten_raw_replies_create_exactly_ten_tasks_after_routing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = FactoryStore(root / "stage.sqlite3")
            store.init()
            messages = []
            for uid in range(1, 11):
                address = f"buyer{uid}@example.test"
                raw_mime = (
                    f"From: {address}\r\n"
                    "To: sales@example.test\r\n"
                    f"Message-ID: <acceptance-{uid}@example.test>\r\n"
                    "Subject: Project request\r\n\r\nPlease review"
                ).encode("ascii")
                messages.append({
                    "uid": uid,
                    "msgid": f"<acceptance-{uid}@example.test>",
                    "from": address,
                    "subject": "Project request",
                    "body": "Please review",
                    "date": "Tue, 18 Aug 2026 12:00:00 +0000",
                    "rfc822_bytes": raw_mime,
                    "rfc822_sha256": hashlib.sha256(raw_mime).hexdigest(),
                })

            calls = 0

            def fetcher(**kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return {
                        "uidvalidity": "100",
                        "selected_uids": list(range(1, 11)),
                        "messages": messages,
                    }
                return {"uidvalidity": "100", "selected_uids": [], "messages": []}

            cursor = MailboxCursor(
                store, consumer_id="factory-unified-inbox", mailbox="INBOX"
            )
            worker = UnifiedInboundWorker(
                cursor=cursor,
                intake=InboundIntake(store),
                fetch_uid_batch=fetcher,
                evidence_vault=LocalEvidenceVault(root / "evidence"),
            )
            self.assertEqual(worker.run_once().persisted_uids, tuple(range(1, 11)))

            con = store.connect()
            try:
                interactions = con.execute(
                    "SELECT lf_interaction_id,address FROM interactions ORDER BY address"
                ).fetchall()
            finally:
                con.close()
            self.assertEqual(len(interactions), 10)

            router = InboundRouter(store)
            for interaction in interactions:
                decision = InboundRouteDecision(
                    interaction_id=interaction["lf_interaction_id"],
                    decision_id=f"fixture-route-{interaction['lf_interaction_id']}",
                    classification="HUMAN_REPLY",
                    contact_address=interaction["address"],
                    campaign_id="dealer-canary",
                    rule_version="acceptance/v1",
                    evidence_ref="stage://acceptance/manual-route",
                )
                first = router.route(decision)
                repeated = router.route(decision)
                self.assertEqual(first.task_id, repeated.task_id)
                self.assertEqual(first.cadence_block_id, repeated.cadence_block_id)

            restarted = UnifiedInboundWorker(
                cursor=MailboxCursor(
                    store, consumer_id="factory-unified-inbox", mailbox="INBOX"
                ),
                intake=InboundIntake(store),
                fetch_uid_batch=fetcher,
                evidence_vault=LocalEvidenceVault(root / "evidence"),
            )
            self.assertEqual(restarted.run_once().status, "EMPTY")
            self.assertEqual(store.table_count("interactions"), 10)
            self.assertEqual(store.table_count("human_tasks"), 10)
            self.assertEqual(store.table_count("cadence_blocks"), 10)

    def test_raw_reply_to_human_task_block_and_restore_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = FactoryStore(root / "stage.sqlite3")
            store.init()
            raw_mime = (
                b"From: buyer@example.test\r\n"
                b"To: sales@example.test\r\n"
                b"Message-ID: <acceptance@example.test>\r\n"
                b"Subject: Project request\r\n\r\nPlease review"
            )

            def fetcher(**kwargs):
                self.assertNotIn("uids", kwargs)
                return {
                    "uidvalidity": "100",
                    "selected_uids": [5],
                    "messages": [{
                        "uid": 5,
                        "msgid": "<acceptance@example.test>",
                        "from": "buyer@example.test",
                        "subject": "Project request",
                        "body": "Please review",
                        "date": "Tue, 18 Aug 2026 12:00:00 +0000",
                        "rfc822_bytes": raw_mime,
                        "rfc822_sha256": hashlib.sha256(raw_mime).hexdigest(),
                    }],
                }

            cursor = MailboxCursor(
                store, consumer_id="factory-unified-inbox", mailbox="INBOX"
            )
            worker = UnifiedInboundWorker(
                cursor=cursor,
                intake=InboundIntake(store),
                fetch_uid_batch=fetcher,
                evidence_vault=LocalEvidenceVault(root / "evidence"),
            )
            run = worker.run_once()
            self.assertEqual(run.persisted_uids, (5,))
            self.assertEqual(store.table_count("human_tasks"), 0)

            con = store.connect()
            try:
                interaction_id = con.execute(
                    "SELECT lf_interaction_id FROM interactions"
                ).fetchone()[0]
            finally:
                con.close()
            routed = InboundRouter(store).route(
                InboundRouteDecision(
                    interaction_id=interaction_id,
                    decision_id="fixture-human-route",
                    classification="HUMAN_REPLY",
                    contact_address="buyer@example.test",
                    campaign_id="dealer-canary",
                    rule_version="acceptance/v1",
                    evidence_ref="stage://acceptance/manual-route",
                )
            )
            self.assertTrue(routed.task_id)
            self.assertTrue(routed.cadence_block_id)

            gate = SendGate(store)
            authorization = gate.create_authorization(
                channel="email",
                segment_id="dealer",
                cohort_id="other-series",
                content_version="v1",
                sender_identity="sender@example.test",
                first_touch_cap=1,
                followup_cap=1,
                valid_from_utc="2020-01-01T00:00:00Z",
                valid_until_utc="2099-01-01T00:00:00Z",
                legal_status="APPROVED",
                legal_evidence_ref="stage://legal/acceptance",
                suppression_snapshot_id="acceptance",
                approver="test-owner",
            )
            denied = gate.issue_permit(
                SendIntent(
                    message_id="must-not-send",
                    authorization_id=authorization,
                    channel="email",
                    address="buyer@example.test",
                    segment_id="dealer",
                    cohort_id="other-series",
                    content_version="v1",
                    sender_identity="sender@example.test",
                )
            )
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.rule_id, "LF-POL-CADENCE-BLOCK")

            HumanTaskController(store).acknowledge(
                routed.task_id,
                actor="dima",
                evidence_ref="stage://acceptance/ack",
            )
            backup = create_backup(
                store,
                destination_dir=root / "backups",
                evidence_root=root / "evidence",
            )
            restored = verify_restore(
                backup["backup"], restore_path=root / "restored.sqlite3"
            )
            self.assertEqual(restored["external_writers_enabled"], "0")
            self.assertEqual(restored["counts"]["interactions"], 1)
            self.assertEqual(restored["counts"]["human_tasks"], 1)
            self.assertEqual(restored["evidence"]["raw_mime_count"], 1)


if __name__ == "__main__":
    unittest.main()
