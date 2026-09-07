from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lead_factory.inbound import (
    HARD_BOUNCE,
    HUMAN_REPLY,
    UNSUBSCRIBE,
    UNSUBSCRIBE_REVIEW,
    InboundIntake,
    InboundMessage,
)
from lead_factory.pauses import PauseController
from lead_factory.policy import SendGate, SendIntent
from lead_factory.store import FactoryStore, IdempotencyConflict


def utc(delta_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_minutes)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


class FactoryCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "factory.sqlite3"
        self.store = FactoryStore(self.db)
        self.store.init()

    def tearDown(self):
        self.temp.cleanup()

    def inbound(self, **changes):
        values = {
            "producer": "imap_test",
            "mailbox": "inbox",
            "external_message_id": "<reply-1@example.test>",
            "uid": "10",
            "from_address": "buyer@example.test",
            "received_at_utc": utc(),
            "classification": HUMAN_REPLY,
            "campaign_id": "dealer-canary",
            "evidence_ref": "imap://inbox/10",
            "content_hash": "content-1",
        }
        values.update(changes)
        return InboundMessage(**values)

    def authorization(self, gate: SendGate, **changes) -> str:
        values = {
            "channel": "email",
            "segment_id": "seg-1",
            "cohort_id": "cohort-1",
            "content_version": "content-v1",
            "sender_identity": "sender-1",
            "first_touch_cap": 2,
            "followup_cap": 2,
            "valid_from_utc": utc(-5),
            "valid_until_utc": utc(60),
            "legal_status": "APPROVED",
            "legal_evidence_ref": "legal://approval/1",
            "suppression_snapshot_id": "suppression-snapshot-1",
            "approver": "owner",
        }
        values.update(changes)
        return gate.create_authorization(**values)

    @staticmethod
    def intent(authorization_id: str, **changes) -> SendIntent:
        values = {
            "message_id": "message-1",
            "authorization_id": authorization_id,
            "channel": "email",
            "address": "buyer@example.test",
            "segment_id": "seg-1",
            "cohort_id": "cohort-1",
            "content_version": "content-v1",
            "sender_identity": "sender-1",
            "touch_type": "FIRST_TOUCH",
            "domain": "example.test",
        }
        values.update(changes)
        return SendIntent(**values)


class EventStoreTests(FactoryCase):
    def test_event_is_idempotent_and_append_only(self):
        first, created = self.store.append_event(
            event_type="test",
            aggregate_type="fixture",
            aggregate_id="one",
            producer="tests",
            idempotency_key="fixture-1",
            payload={"value": 1},
        )
        again, created_again = self.store.append_event(
            event_type="test",
            aggregate_type="fixture",
            aggregate_id="one",
            producer="tests",
            idempotency_key="fixture-1",
            payload={"value": 1},
        )
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first["event_id"], again["event_id"])
        with self.assertRaises(IdempotencyConflict):
            self.store.append_event(
                event_type="test",
                aggregate_type="fixture",
                aggregate_id="one",
                producer="tests",
                idempotency_key="fixture-1",
                payload={"value": 2},
            )
        con = self.store.connect()
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute("UPDATE events SET actor='changed' WHERE event_id=?", (first["event_id"],))
        finally:
            con.close()

    def test_two_projects_same_company_and_contact_are_two_opportunities(self):
        company, _ = self.store.create_company(name="Builder", inn="7701000000")
        contact, _ = self.store.create_contact(
            lf_company_id=company["lf_company_id"], email="procurement@example.test"
        )
        project_a, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"], source="fixture", external_key="object-a"
        )
        project_b, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"], source="fixture", external_key="object-b"
        )
        opp_a, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"], lf_contact_id=contact["lf_contact_id"],
            lf_project_id=project_a["lf_project_id"], source="fixture", external_key="opp-a"
        )
        opp_b, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"], lf_contact_id=contact["lf_contact_id"],
            lf_project_id=project_b["lf_project_id"], source="fixture", external_key="opp-b"
        )
        self.assertNotEqual(opp_a["lf_opportunity_id"], opp_b["lf_opportunity_id"])
        self.assertEqual(self.store.table_count("companies"), 1)
        self.assertEqual(self.store.table_count("contacts"), 1)
        self.assertEqual(self.store.table_count("projects"), 2)
        self.assertEqual(self.store.table_count("opportunities"), 2)


class InboundSafetyTests(FactoryCase):
    def test_duplicate_message_creates_one_interaction_task_and_block(self):
        intake = InboundIntake(self.store)
        first = intake.ingest(self.inbound())
        duplicate = intake.ingest(self.inbound())
        self.assertTrue(first.created)
        self.assertFalse(duplicate.created)
        self.assertEqual(first.interaction_id, duplicate.interaction_id)
        self.assertEqual(first.task_id, duplicate.task_id)
        self.assertEqual(self.store.table_count("events"), 1)
        self.assertEqual(self.store.table_count("interactions"), 1)
        self.assertEqual(self.store.table_count("human_tasks"), 1)
        self.assertEqual(self.store.table_count("cadence_blocks"), 1)

    def test_legacy_message_without_uidvalidity_keeps_message_id_event_dedupe(self):
        intake = InboundIntake(self.store)
        message = self.inbound(uid="legacy-one", uid_validity="")
        self.assertEqual(
            message.event_dedupe_key(), "message-id:<reply-1@example.test>"
        )
        first = intake.ingest(message)
        second = intake.ingest(message)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.event_id, second.event_id)
        self.assertEqual(self.store.table_count("events"), 1)
        self.assertEqual(self.store.table_count("interactions"), 1)

    def test_crash_rolls_back_and_replay_is_safe(self):
        def crash():
            raise RuntimeError("simulated power loss")

        with self.assertRaises(RuntimeError):
            InboundIntake(self.store, after_event_hook=crash).ingest(self.inbound())
        self.assertEqual(self.store.table_count("events"), 0)
        self.assertEqual(self.store.table_count("interactions"), 0)
        recovered = InboundIntake(self.store).ingest(self.inbound())
        self.assertTrue(recovered.created)
        self.assertEqual(self.store.table_count("human_tasks"), 1)

    def test_unsubscribe_and_hard_bounce_suppress_only_address(self):
        intake = InboundIntake(self.store)
        unsub = intake.ingest(
            self.inbound(
                external_message_id="<unsub@example.test>", uid="11", classification=UNSUBSCRIBE,
                evidence_ref="imap://inbox/11"
            )
        )
        bounce = intake.ingest(
            self.inbound(
                external_message_id="<bounce@example.test>", uid="12", from_address="bad@example.test",
                classification=HARD_BOUNCE, evidence_ref="imap://inbox/12"
            )
        )
        self.assertTrue(unsub.suppression_id)
        self.assertTrue(bounce.suppression_id)
        con = self.store.connect()
        try:
            rows = con.execute("SELECT scope,subject_type FROM suppression_entries").fetchall()
            self.assertEqual({(r[0], r[1]) for r in rows}, {("EMAIL_ADDRESS", "EMAIL_ADDRESS")})
        finally:
            con.close()
        self.assertEqual(self.store.table_count("human_tasks"), 0)

    def test_repeated_unsubscribe_keeps_one_active_suppression(self):
        intake = InboundIntake(self.store)
        first = intake.ingest(
            self.inbound(
                external_message_id="<unsub-1@example.test>",
                uid="21",
                classification=UNSUBSCRIBE,
                evidence_ref="imap://inbox/21",
            )
        )
        second = intake.ingest(
            self.inbound(
                external_message_id="<unsub-2@example.test>",
                uid="22",
                classification=UNSUBSCRIBE,
                evidence_ref="imap://inbox/22",
            )
        )
        self.assertEqual(first.suppression_id, second.suppression_id)
        con = self.store.connect()
        try:
            count = con.execute(
                "SELECT COUNT(*) FROM suppression_entries WHERE state='ACTIVE'"
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(count, 1)

    def test_delegated_unsubscribe_requires_review_before_suppression(self):
        intake = InboundIntake(self.store)
        intake.ingest(
            self.inbound(
                external_message_id="<forwarded-unsub@example.test>",
                uid="13",
                from_address="colleague@example.test",
                contact_address="buyer@example.test",
                classification=UNSUBSCRIBE_REVIEW,
                evidence_ref="imap://inbox/13",
            )
        )
        con = self.store.connect()
        try:
            interaction = con.execute("SELECT address FROM interactions").fetchone()
            task = con.execute("SELECT kind FROM human_tasks").fetchone()
            self.assertEqual(interaction[0], "colleague@example.test")
            self.assertEqual(task[0], "SUPPRESSION_REVIEW")
            self.assertEqual(
                con.execute("SELECT COUNT(*) FROM suppression_entries").fetchone()[0], 0
            )
        finally:
            con.close()


class SendGateTests(FactoryCase):
    def test_default_deny_without_authorization(self):
        gate = SendGate(self.store)
        decision = gate.issue_permit(self.intent("missing-auth"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-AUTH-MISSING")
        self.assertEqual(self.store.table_count("send_permits"), 0)
        self.assertEqual(self.store.table_count("outbox"), 0)

    def test_one_message_gets_one_permit_and_one_staged_command(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        intent = self.intent(aid)
        first = gate.issue_permit(intent)
        again = gate.issue_permit(intent)
        self.assertTrue(first.allowed)
        self.assertTrue(again.allowed)
        self.assertEqual(first.permit_id, again.permit_id)
        self.assertEqual(self.store.table_count("send_permits"), 1)
        payload = {"subject": "Fixture", "body": "Test"}
        staged = gate.stage_command(
            intent, first.permit_id, payload_ref="stage://payload/message-1", payload=payload
        )
        repeated = gate.stage_command(
            intent, first.permit_id, payload_ref="stage://payload/message-1", payload=payload
        )
        self.assertTrue(staged.allowed)
        self.assertTrue(repeated.allowed)
        self.assertEqual(self.store.table_count("outbox"), 1)

    def test_new_suppression_between_permit_and_stage_revokes_send(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        intent = self.intent(aid)
        permit = gate.issue_permit(intent)
        self.assertTrue(permit.allowed)
        gate.add_suppression(
            address=intent.address,
            reason="unsubscribe",
            scope="EMAIL_ADDRESS",
            channel="email",
            evidence_ref="inbound://unsubscribe/1",
            source="inbound",
            author="system",
        )
        staged = gate.stage_command(
            intent,
            permit.permit_id,
            payload_ref="stage://payload/message-1",
            payload={"subject": "Fixture", "body": "Test"},
        )
        self.assertFalse(staged.allowed)
        self.assertEqual(staged.rule_id, "LF-POL-LEGAL-SUPPRESSION")
        self.assertEqual(self.store.table_count("outbox"), 0)

    def test_human_reply_blocks_every_later_cold_series_for_that_address(self):
        InboundIntake(self.store).ingest(
            self.inbound(campaign_id="dealer-series")
        )
        gate = SendGate(self.store)
        aid = self.authorization(
            gate,
            cohort_id="builder-cohort",
        )
        decision = gate.issue_permit(
            self.intent(
                aid,
                message_id="other-series-message",
                cohort_id="builder-cohort",
            )
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-POL-CADENCE-BLOCK")
        self.assertEqual(self.store.table_count("send_permits"), 0)

    def test_domain_suppression_is_derived_from_the_recipient_address(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        gate.add_suppression(
            reason="provider_complaint",
            scope="DOMAIN",
            channel="email",
            subject_id="blocked.example",
            evidence_ref="stage://suppression/domain",
            source="test",
            author="owner",
        )
        decision = gate.issue_permit(
            self.intent(aid, address="buyer@blocked.example", domain="")
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-POL-LEGAL-SUPPRESSION")

    def test_declared_domain_cannot_differ_from_the_recipient_address(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        decision = gate.issue_permit(
            self.intent(aid, address="buyer@actual.example", domain="other.example")
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-INTENT-DOMAIN")

    def test_unmappable_active_pause_scope_fails_closed(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        PauseController(self.store).open(
            scope="CAMPAIGN",
            scope_id="campaign-a",
            reason="incident",
            author="owner",
            evidence_ref="stage://pause/campaign-a",
            review_at_utc=utc(30),
        )
        decision = gate.issue_permit(self.intent(aid))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-POL-SAFETY-PAUSE")

    def test_invalid_legal_status_is_denied(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate, legal_status="NOT_APPROVED")
        decision = gate.issue_permit(self.intent(aid))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-AUTH-LEGAL")

    def test_permit_cannot_be_reused_for_another_recipient(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        original = self.intent(aid, address="first@example.test")
        permit = gate.issue_permit(original)
        substituted = self.intent(aid, address="other@example.test")
        staged = gate.stage_command(
            substituted,
            permit.permit_id,
            payload_ref="stage://payload/message-1",
            payload={"subject": "Fixture", "body": "Test"},
        )
        self.assertFalse(staged.allowed)
        self.assertEqual(staged.rule_id, "LF-PERMIT-SCOPE")
        self.assertEqual(self.store.table_count("outbox"), 0)

    def test_empty_recipient_is_denied(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        decision = gate.issue_permit(self.intent(aid, address=""))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule_id, "LF-INTENT-ADDRESS")

    def test_dispatch_is_blocked_while_external_writers_are_disabled(self):
        gate = SendGate(self.store)
        aid = self.authorization(gate)
        intent = self.intent(aid)
        permit = gate.issue_permit(intent)
        payload = {"subject": "Fixture", "body": "Test"}
        gate.stage_command(
            intent,
            permit.permit_id,
            payload_ref="stage://payload/message-1",
            payload=payload,
        )
        con = self.store.connect()
        try:
            command_id = con.execute("SELECT command_id FROM outbox").fetchone()[0]
        finally:
            con.close()
        dispatch = gate.authorize_dispatch(
            intent,
            command_id,
            payload_ref="stage://payload/message-1",
            payload=payload,
        )
        self.assertFalse(dispatch.allowed)
        self.assertEqual(dispatch.rule_id, "LF-WRITER-DISABLED")


if __name__ == "__main__":
    unittest.main()
