from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.crm_handoff import HumanReplyCrmHandoff
from lead_factory.crm_outbox import CrmActivityOutbox, CrmActivityReceipt, CrmOutbox
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import UNROUTED


_AUTHORITY_PATCHER = patch(
    "lead_factory.crm_outbox.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class FakeCrmTransport:
    def __init__(
        self,
        *,
        lead_result="901",
        lead_error=None,
        activity_result="801",
        return_activity_value_raw=False,
    ):
        self.lead_result = lead_result
        self.lead_error = lead_error
        self.activity_result = activity_result
        self.return_activity_value_raw = return_activity_value_raw
        self.lead_calls = 0
        self.activity_calls = 0
        self.activity_lead_ids: list[str] = []

    def create_lead(self, payload, correlation_token):
        self.lead_calls += 1
        if self.lead_error:
            raise self.lead_error
        return self.lead_result

    def find_lead_by_correlation_token(self, correlation_token):
        return None

    def create_activity(self, lead_remote_id, payload):
        self.activity_calls += 1
        self.activity_lead_ids.append(str(lead_remote_id))
        if self.return_activity_value_raw:
            return self.activity_result
        if isinstance(self.activity_result, CrmActivityReceipt):
            return self.activity_result
        return CrmActivityReceipt(
            remote_id=str(self.activity_result),
            owner_lead_id=str(lead_remote_id),
            readback_verified=True,
        )


class HumanReplyCrmHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "handoff.sqlite3")
        self.store.init()
        company, _ = self.store.create_company(name="Fixture", inn="7701000001")
        project, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"], source="fixture", external_key="project-1"
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            lf_project_id=project["lf_project_id"],
            source="fixture",
            external_key="opportunity-1",
        )
        self.opportunity_id = opportunity["lf_opportunity_id"]
        self.interaction_id = self._ingest_unrouted("<handoff-1@example.test>")

    def tearDown(self):
        self.temp.cleanup()

    def _ingest_unrouted(self, message_id):
        return InboundIntake(self.store).ingest(
            InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                external_message_id=message_id,
                # The mailbox UID is part of the immutable intake idempotency key.
                # Different fixture messages must therefore use different UIDs.
                uid=message_id,
                uid_validity="100",
                from_address="buyer@example.test",
                contact_address="buyer@example.test",
                received_at_utc="2026-08-18T09:00:00Z",
                classification=UNROUTED,
                evidence_ref="stage-evidence:handoff",
                create_human_task=False,
            )
        ).interaction_id

    def _handoff(self, **changes):
        values = {
            "lead_payload": {"title": "Inbound reply — fixture"},
            "activity_payload": {
                "title": "Follow up inbound reply",
                "description": "Open the local human-review task before replying.",
                "responsible_id": "7",
            },
        }
        values.update(changes)
        return HumanReplyCrmHandoff(self.store, **values)

    def _decision(self, **changes):
        values = {
            "interaction_id": self.interaction_id,
            "decision_id": "decision-1",
            "classification": "HUMAN_REPLY",
            "contact_address": "buyer@example.test",
            "campaign_id": "dealer-series",
            "lf_opportunity_id": self.opportunity_id,
            "rule_version": "fixture/v1",
            "evidence_ref": "stage://route/handoff-1",
        }
        values.update(changes)
        return InboundRouteDecision(**values)

    def _set_writers(self, enabled):
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='external_writers_enabled'",
                ("1" if enabled else "0",),
            )

    def _operations(self):
        con = self.store.connect()
        try:
            return [
                dict(row)
                for row in con.execute(
                    "SELECT * FROM crm_outbox ORDER BY operation_type,operation_id"
                ).fetchall()
            ]
        finally:
            con.close()

    def test_one_routed_reply_atomically_stages_one_task_lead_and_activity(self):
        router = InboundRouter(self.store, human_reply_handoff=self._handoff())
        first = router.route(self._decision())
        replay = router.route(self._decision())

        self.assertTrue(first.changed)
        self.assertFalse(replay.changed)
        self.assertEqual(first.crm_handoff_state, "STAGED")
        self.assertEqual(first.lead_operation_id, replay.lead_operation_id)
        self.assertEqual(first.activity_operation_id, replay.activity_operation_id)
        self.assertEqual(self.store.table_count("human_tasks"), 1)
        operations = self._operations()
        self.assertEqual(len(operations), 2)
        lead = next(row for row in operations if row["operation_type"] == "BITRIX_LEAD_CREATE")
        activity = next(row for row in operations if row["operation_type"] == "BITRIX_ACTIVITY_CREATE")
        self.assertEqual(lead["lf_entity_id"], self.opportunity_id)
        self.assertEqual(activity["lf_entity_id"], self.interaction_id)
        self.assertEqual(activity["dependency_operation_id"], lead["operation_id"])

    def test_crash_after_staging_rolls_back_route_task_and_both_operations(self):
        def crash():
            raise RuntimeError("simulated process loss")

        crashing_router = InboundRouter(
            self.store, human_reply_handoff=self._handoff(after_stage_hook=crash)
        )
        with self.assertRaisesRegex(RuntimeError, "simulated process loss"):
            crashing_router.route(self._decision())
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("crm_outbox"), 0)
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT classification FROM interactions WHERE lf_interaction_id=?",
                    (self.interaction_id,),
                ).fetchone()[0],
                UNROUTED,
            )
        finally:
            con.close()

        replay = InboundRouter(self.store, human_reply_handoff=self._handoff()).route(
            self._decision()
        )
        self.assertEqual(replay.crm_handoff_state, "STAGED")
        self.assertEqual(self.store.table_count("human_tasks"), 1)
        self.assertEqual(self.store.table_count("crm_outbox"), 2)

    def test_uncertain_lead_blocks_activity_without_activity_call(self):
        staged = InboundRouter(self.store, human_reply_handoff=self._handoff()).route(
            self._decision()
        )
        self._set_writers(True)
        transport = FakeCrmTransport(lead_error=TimeoutError("lost lead response"))
        lead_result = CrmOutbox(self.store).process_next(transport, worker_id="lead-worker")
        activity_result = CrmActivityOutbox(self.store).process_next(
            transport, worker_id="activity-worker"
        )
        self.assertEqual(lead_result.state, "UNCERTAIN")
        self.assertEqual(activity_result.operation_id, staged.activity_operation_id)
        self.assertEqual(activity_result.state, "BLOCKED_DEPENDENCY")
        self.assertEqual(transport.lead_calls, 1)
        self.assertEqual(transport.activity_calls, 0)

    def test_exact_sent_lead_mapping_allows_exactly_one_activity(self):
        staged = InboundRouter(self.store, human_reply_handoff=self._handoff()).route(
            self._decision()
        )
        self._set_writers(True)
        transport = FakeCrmTransport(lead_result="901", activity_result="801")
        lead_result = CrmOutbox(self.store).process_next(transport, worker_id="lead-worker")
        activity_result = CrmActivityOutbox(self.store).process_next(
            transport, worker_id="activity-worker"
        )
        self.assertEqual(lead_result.state, "SENT")
        self.assertEqual(activity_result.state, "SENT")
        self.assertEqual(activity_result.operation_id, staged.activity_operation_id)
        self.assertEqual(transport.activity_lead_ids, ["901"])
        self.assertIsNone(CrmOutbox(self.store).process_next(transport, worker_id="lead-worker"))
        self.assertIsNone(
            CrmActivityOutbox(self.store).process_next(transport, worker_id="activity-worker")
        )
        self.assertEqual(transport.lead_calls, 1)
        self.assertEqual(transport.activity_calls, 1)

    def test_missing_exact_lead_mapping_blocks_activity(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        self._set_writers(True)
        transport = FakeCrmTransport()
        self.assertEqual(
            CrmOutbox(self.store).process_next(transport, worker_id="lead-worker").state,
            "SENT",
        )
        with self.store.transaction() as con:
            con.execute("DELETE FROM crm_mappings")
        blocked = CrmActivityOutbox(self.store).process_next(
            transport, worker_id="activity-worker"
        )
        self.assertEqual(blocked.state, "BLOCKED_DEPENDENCY")
        self.assertEqual(blocked.error_class, "LeadMAPPING_MISSING")
        self.assertEqual(transport.activity_calls, 0)

    def test_ambiguous_activity_is_terminal_review_without_retry(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        self._set_writers(True)
        transport = FakeCrmTransport(lead_result="902", activity_result="802")
        self.assertEqual(
            CrmOutbox(self.store).process_next(transport, worker_id="lead-worker").state,
            "SENT",
        )

        def crash_after_remote_activity():
            raise RuntimeError("local loss after activity response")

        review = CrmActivityOutbox(self.store).process_next(
            transport,
            worker_id="activity-worker",
            after_remote_hook=crash_after_remote_activity,
        )
        self.assertEqual(review.state, "REVIEW")
        activity = next(
            row for row in self._operations() if row["operation_type"] == "BITRIX_ACTIVITY_CREATE"
        )
        self.assertEqual(activity["suspect_remote_entity_type"], "activity")
        self.assertEqual(activity["suspect_remote_entity_id"], "802")
        self.assertIsNone(
            CrmActivityOutbox(self.store).process_next(transport, worker_id="activity-worker")
        )
        self.assertEqual(transport.activity_calls, 1)

    def test_mapping_removed_after_activity_receipt_is_review_not_false_sent(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        self._set_writers(True)
        transport = FakeCrmTransport(lead_result="908", activity_result="808")
        self.assertEqual(
            CrmOutbox(self.store).process_next(transport, worker_id="lead-worker").state,
            "SENT",
        )

        def remove_mapping_after_activity_receipt():
            with self.store.transaction() as con:
                con.execute("DELETE FROM crm_mappings")

        result = CrmActivityOutbox(self.store).process_next(
            transport,
            worker_id="activity-worker",
            after_remote_hook=remove_mapping_after_activity_receipt,
        )
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "ActivityDependencyChanged")
        self.assertEqual(transport.activity_calls, 1)
        activity = next(
            row for row in self._operations() if row["operation_type"] == "BITRIX_ACTIVITY_CREATE"
        )
        self.assertEqual(activity["state"], "REVIEW")
        self.assertEqual(activity["remote_entity_id"], "")
        self.assertEqual(activity["suspect_remote_entity_type"], "activity")
        self.assertEqual(activity["suspect_remote_entity_id"], "808")

    def test_dependency_mapping_removed_after_claim_blocks_before_activity_call(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        self._set_writers(True)
        transport = FakeCrmTransport()
        self.assertEqual(
            CrmOutbox(self.store).process_next(transport, worker_id="lead-worker").state,
            "SENT",
        )

        def remove_mapping_after_claim():
            with self.store.transaction() as con:
                con.execute("DELETE FROM crm_mappings")

        result = CrmActivityOutbox(self.store).process_next(
            transport,
            worker_id="activity-worker",
            before_create_hook=remove_mapping_after_claim,
        )
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "ActivityDependencyChanged")
        self.assertEqual(transport.activity_calls, 0)

    def test_dependency_lead_state_changed_after_claim_blocks_before_activity_call(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        self._set_writers(True)
        transport = FakeCrmTransport()
        self.assertEqual(
            CrmOutbox(self.store).process_next(transport, worker_id="lead-worker").state,
            "SENT",
        )

        def change_lead_after_claim():
            with self.store.transaction() as con:
                con.execute(
                    "UPDATE crm_outbox SET state='UNCERTAIN' "
                    "WHERE operation_type='BITRIX_LEAD_CREATE'"
                )

        result = CrmActivityOutbox(self.store).process_next(
            transport,
            worker_id="activity-worker",
            before_create_hook=change_lead_after_claim,
        )
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "ActivityDependencyChanged")
        self.assertEqual(transport.activity_calls, 0)

    def test_writer_disabled_after_activity_claim_blocks_before_activity_call(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        self._set_writers(True)
        transport = FakeCrmTransport()
        self.assertEqual(
            CrmOutbox(self.store).process_next(transport, worker_id="lead-worker").state,
            "SENT",
        )
        result = CrmActivityOutbox(self.store).process_next(
            transport,
            worker_id="activity-worker",
            before_create_hook=lambda: self._set_writers(False),
        )
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(result.error_class, "ExternalWritersDisabled")
        self.assertEqual(transport.activity_calls, 0)

    def test_unverified_wrong_owner_or_bare_activity_id_is_review_not_sent(self):
        for receipt, suspect_id in (
            (CrmActivityReceipt("803", "903", True), "803"),
            (CrmActivityReceipt("804", "904", False), "804"),
            ("805", "805"),
        ):
            with self.subTest(receipt=receipt):
                temp = tempfile.TemporaryDirectory()
                try:
                    store = FactoryStore(Path(temp.name) / "receipt.sqlite3")
                    store.init()
                    company, _ = store.create_company(name="Receipt", inn="7701000002")
                    project, _ = store.create_project(
                        lf_company_id=company["lf_company_id"],
                        source="fixture",
                        external_key="receipt-project",
                    )
                    opportunity, _ = store.create_opportunity(
                        lf_company_id=company["lf_company_id"],
                        lf_project_id=project["lf_project_id"],
                        source="fixture",
                        external_key="receipt-opportunity",
                    )
                    interaction = InboundIntake(store).ingest(
                        InboundMessage(
                            producer="factory-unified-inbox",
                            mailbox="INBOX",
                            external_message_id=f"<receipt-{suspect_id}@example.test>",
                            uid=f"receipt-{suspect_id}",
                            uid_validity="100",
                            from_address="buyer@example.test",
                            contact_address="buyer@example.test",
                            received_at_utc="2026-08-18T09:00:00Z",
                            classification=UNROUTED,
                            evidence_ref="stage-evidence:receipt",
                            create_human_task=False,
                        )
                    ).interaction_id
                    handoff = HumanReplyCrmHandoff(
                        store,
                        lead_payload={"title": "Receipt fixture"},
                        activity_payload={"title": "Follow up"},
                    )
                    InboundRouter(store, human_reply_handoff=handoff).route(
                        InboundRouteDecision(
                            interaction_id=interaction,
                            decision_id="receipt-decision",
                            classification="HUMAN_REPLY",
                            contact_address="buyer@example.test",
                            campaign_id="dealer-series",
                            lf_opportunity_id=opportunity["lf_opportunity_id"],
                            rule_version="fixture/v1",
                            evidence_ref="stage://route/receipt",
                        )
                    )
                    with store.transaction() as con:
                        con.execute(
                            "UPDATE schema_meta SET value='1' "
                            "WHERE key='external_writers_enabled'"
                        )
                    transport = FakeCrmTransport(
                        lead_result="904",
                        activity_result=receipt,
                        return_activity_value_raw=isinstance(receipt, str),
                    )
                    self.assertEqual(
                        CrmOutbox(store).process_next(transport, worker_id="lead-worker").state,
                        "SENT",
                    )
                    result = CrmActivityOutbox(store).process_next(
                        transport, worker_id="activity-worker"
                    )
                    self.assertEqual(result.state, "REVIEW")
                    self.assertEqual(transport.activity_calls, 1)
                    con = store.connect()
                    try:
                        row = con.execute(
                            "SELECT suspect_remote_entity_type,suspect_remote_entity_id "
                            "FROM crm_outbox WHERE operation_type='BITRIX_ACTIVITY_CREATE'"
                        ).fetchone()
                    finally:
                        con.close()
                    self.assertEqual(row["suspect_remote_entity_type"], "activity")
                    self.assertEqual(row["suspect_remote_entity_id"], suspect_id)
                finally:
                    temp.cleanup()

    def test_writer_flag_off_makes_zero_lead_and_activity_calls(self):
        InboundRouter(self.store, human_reply_handoff=self._handoff()).route(self._decision())
        transport = FakeCrmTransport()
        lead = CrmOutbox(self.store).process_next(transport, worker_id="lead-worker")
        activity = CrmActivityOutbox(self.store).process_next(
            transport, worker_id="activity-worker"
        )
        self.assertEqual(lead.state, "BLOCKED")
        self.assertEqual(activity.state, "BLOCKED")
        self.assertEqual(transport.lead_calls, 0)
        self.assertEqual(transport.activity_calls, 0)

    def test_unrouted_or_missing_opportunity_stages_only_review_not_crm_ops(self):
        handoff = self._handoff()
        with self.store.transaction() as con:
            review = handoff.stage_tx(
                con,
                interaction_id=self.interaction_id,
                decision_id="unrouted-review",
                evidence_ref="stage://handoff/unrouted",
            )
        self.assertEqual(review.state, "REVIEW")
        self.assertEqual(review.review_code, "ROUTE_NOT_HUMAN_REPLY")
        self.assertEqual(self.store.table_count("crm_outbox"), 0)

        missing_opportunity_interaction = self._ingest_unrouted("<handoff-2@example.test>")
        missing = InboundRouter(self.store, human_reply_handoff=handoff).route(
            self._decision(
                interaction_id=missing_opportunity_interaction,
                decision_id="decision-no-opportunity",
                lf_opportunity_id="",
                evidence_ref="stage://route/no-opportunity",
            )
        )
        self.assertEqual(missing.crm_handoff_state, "REVIEW")
        self.assertEqual(self.store.table_count("crm_outbox"), 0)


if __name__ == "__main__":
    unittest.main()
