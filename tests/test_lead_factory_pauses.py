from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lead_factory.pauses import PauseController
from lead_factory.policy import SendGate, SendIntent
from lead_factory.store import FactoryStore


class PauseControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "pause.sqlite3")
        self.store.init()
        self.gate = SendGate(self.store)
        self.controller = PauseController(self.store)
        self.authorization_id = self.gate.create_authorization(
            channel="email",
            segment_id="dealers",
            cohort_id="fixture",
            content_version="v1",
            sender_identity="sender@example.test",
            first_touch_cap=10,
            followup_cap=10,
            valid_from_utc="2020-01-01T00:00:00Z",
            valid_until_utc="2099-01-01T00:00:00Z",
            legal_status="APPROVED",
            legal_evidence_ref="stage://legal/fixture",
            suppression_snapshot_id="fixture",
            approver="test-owner",
        )

    def tearDown(self):
        self.temp.cleanup()

    def intent(self, message_id: str) -> SendIntent:
        return SendIntent(
            message_id=message_id,
            authorization_id=self.authorization_id,
            channel="email",
            address="buyer@example.test",
            segment_id="dealers",
            cohort_id="fixture",
            content_version="v1",
            sender_identity="sender@example.test",
        )

    def test_pause_requires_reason_review_and_evidence(self):
        with self.assertRaises(ValueError):
            self.controller.open(
                scope="GLOBAL",
                reason="",
                author="owner",
                evidence_ref="stage://incident/1",
                review_at_utc="2090-01-01T00:00:00Z",
            )
        with self.assertRaises(ValueError):
            self.controller.open(
                scope="CHANNEL",
                scope_id="email",
                reason="delivery incident",
                author="owner",
                evidence_ref="stage://incident/1",
                review_at_utc="",
            )

    def test_expiry_never_silently_resumes_sending(self):
        pause_id = self.controller.open(
            scope="CHANNEL",
            scope_id="email",
            reason="delivery incident",
            author="owner",
            evidence_ref="stage://incident/1",
            review_at_utc="2025-01-01T00:00:00Z",
            expires_at_utc="2025-01-02T00:00:00Z",
        )
        denied = self.gate.issue_permit(self.intent("paused-message"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.rule_id, "LF-POL-SAFETY-PAUSE")

        released = self.controller.expire_due(now_utc="2025-01-03T00:00:00Z")
        self.assertEqual(released, [pause_id])
        allowed = self.gate.issue_permit(self.intent("after-audited-expiry"))
        self.assertTrue(allowed.allowed)
        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT state,released_at_utc FROM pauses WHERE pause_id=?", (pause_id,)
            ).fetchone()
            self.assertEqual(row["state"], "EXPIRED")
            self.assertTrue(row["released_at_utc"])
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE event_type='safety_pause_released'"
                ).fetchone()[0],
                1,
            )
        finally:
            con.close()

    def test_release_is_idempotent_and_needs_evidence(self):
        pause_id = self.controller.open(
            scope="GLOBAL",
            reason="operator stop",
            author="owner",
            evidence_ref="stage://incident/2",
            review_at_utc="2090-01-01T00:00:00Z",
        )
        with self.assertRaises(ValueError):
            self.controller.release(
                pause_id, author="owner", evidence_ref="", resolution="resolved"
            )
        self.assertTrue(
            self.controller.release(
                pause_id,
                author="owner",
                evidence_ref="stage://incident/2/resolved",
                resolution="manual verification passed",
            )
        )
        self.assertFalse(
            self.controller.release(
                pause_id,
                author="owner",
                evidence_ref="stage://incident/2/resolved",
                resolution="manual verification passed",
            )
        )


if __name__ == "__main__":
    unittest.main()
