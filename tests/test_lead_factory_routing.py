from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore, IdempotencyConflict
from lead_factory.unified_inbound_worker import UNROUTED


class InboundRouterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "routing.sqlite3")
        self.store.init()
        result = InboundIntake(self.store).ingest(
            InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                external_message_id="<route@example.test>",
                uid="5",
                uid_validity="100",
                from_address="buyer@example.test",
                contact_address="buyer@example.test",
                received_at_utc="2026-08-18T09:00:00Z",
                classification=UNROUTED,
                evidence_ref="stage-evidence:fixture",
                create_human_task=False,
            )
        )
        self.interaction_id = result.interaction_id
        self.router = InboundRouter(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def decision(self, **changes):
        values = {
            "interaction_id": self.interaction_id,
            "decision_id": "decision-1",
            "classification": "HUMAN_REPLY",
            "contact_address": "buyer@example.test",
            "campaign_id": "dealer-series",
            "rule_version": "fixture/v1",
            "evidence_ref": "stage://route/decision-1",
        }
        values.update(changes)
        return InboundRouteDecision(**values)

    def test_human_route_creates_one_task_and_global_address_block(self):
        first = self.router.route(self.decision())
        repeated = self.router.route(self.decision())
        self.assertTrue(first.changed)
        self.assertFalse(repeated.changed)
        self.assertEqual(first.task_id, repeated.task_id)
        self.assertEqual(self.store.table_count("human_tasks"), 1)
        self.assertEqual(self.store.table_count("cadence_blocks"), 1)
        self.assertEqual(self.store.table_count("outbox"), 0)
        self.assertEqual(self.store.table_count("crm_outbox"), 0)
        with self.assertRaises(IdempotencyConflict):
            self.router.route(
                self.decision(decision_id="decision-2", classification="AUTO_REPLY")
            )
        with self.assertRaises(ValueError):
            self.router.route(
                self.decision(contact_address="substituted@example.test")
            )

    def test_human_reply_cannot_substitute_a_contact_address(self):
        with self.assertRaisesRegex(ValueError, "must match the inbound sender"):
            self.router.route(
                self.decision(contact_address="substituted@example.test")
            )
        con = self.store.connect()
        try:
            classification = con.execute(
                "SELECT classification FROM interactions WHERE lf_interaction_id=?",
                (self.interaction_id,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(classification, UNROUTED)
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("cadence_blocks"), 0)

    def test_auto_reply_route_creates_no_task_or_block(self):
        result = self.router.route(
            self.decision(classification="AUTO_REPLY", contact_address="")
        )
        self.assertTrue(result.changed)
        self.assertFalse(result.task_id)
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("cadence_blocks"), 0)

    def test_delegated_unsubscribe_requires_review_and_no_suppression(self):
        with self.assertRaises(ValueError):
            self.router.route(
                self.decision(
                    classification="UNSUBSCRIBE",
                    contact_address="other@example.test",
                )
            )
        reviewed = self.router.route(
            self.decision(
                decision_id="decision-review",
                classification="UNSUBSCRIBE_REVIEW",
                contact_address="other@example.test",
            )
        )
        self.assertTrue(reviewed.task_id)
        self.assertFalse(reviewed.suppression_id)
        self.assertEqual(self.store.table_count("suppression_entries"), 0)

    def test_exact_unsubscribe_creates_address_only_suppression(self):
        result = self.router.route(self.decision(classification="UNSUBSCRIBE"))
        self.assertTrue(result.suppression_id)
        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT scope,subject_type,address FROM suppression_entries"
            ).fetchone()
            self.assertEqual(row["scope"], "EMAIL_ADDRESS")
            self.assertEqual(row["subject_type"], "EMAIL_ADDRESS")
            self.assertEqual(row["address"], "buyer@example.test")
        finally:
            con.close()

    def test_contact_opportunity_company_invariant_and_five_minute_slo(self):
        buyer_company, _ = self.store.create_company(
            name="Buyer", inn="7701000101"
        )
        buyer_contact, _ = self.store.create_contact(
            lf_company_id=buyer_company["lf_company_id"],
            email="buyer@example.test",
        )
        other_company, _ = self.store.create_company(
            name="Other", inn="7701000102"
        )
        other_project, _ = self.store.create_project(
            lf_company_id=other_company["lf_company_id"],
            source="fixture",
            external_key="other-project",
        )
        other_opportunity, _ = self.store.create_opportunity(
            lf_company_id=other_company["lf_company_id"],
            lf_project_id=other_project["lf_project_id"],
            source="fixture",
            external_key="other-opportunity",
        )
        with self.assertRaisesRegex(ValueError, "different companies"):
            self.router.route(
                self.decision(
                    lf_contact_id=buyer_contact["lf_contact_id"],
                    lf_opportunity_id=other_opportunity["lf_opportunity_id"],
                )
            )

        buyer_project, _ = self.store.create_project(
            lf_company_id=buyer_company["lf_company_id"],
            source="fixture",
            external_key="buyer-project",
        )
        buyer_opportunity, _ = self.store.create_opportunity(
            lf_company_id=buyer_company["lf_company_id"],
            lf_project_id=buyer_project["lf_project_id"],
            source="fixture",
            external_key="buyer-opportunity",
        )
        result = self.router.route(
            self.decision(
                lf_contact_id=buyer_contact["lf_contact_id"],
                lf_opportunity_id=buyer_opportunity["lf_opportunity_id"],
            )
        )
        self.assertTrue(result.task_id)
        con = self.store.connect()
        try:
            task = con.execute(
                "SELECT assigned_to,due_at_utc FROM human_tasks WHERE lf_task_id=?",
                (result.task_id,),
            ).fetchone()
        finally:
            con.close()
        self.assertEqual(task["assigned_to"], "dima")
        self.assertEqual(task["due_at_utc"], "2026-08-18T09:05:00Z")

    def test_route_contact_id_must_match_inbound_sender(self):
        company, _ = self.store.create_company(name="Buyer", inn="7701000103")
        wrong_contact, _ = self.store.create_contact(
            lf_company_id=company["lf_company_id"],
            email="someone-else@example.test",
        )
        with self.assertRaisesRegex(ValueError, "email does not match"):
            self.router.route(
                self.decision(lf_contact_id=wrong_contact["lf_contact_id"])
            )


if __name__ == "__main__":
    unittest.main()
