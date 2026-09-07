from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory.canary_control import (
    CanaryApprovalRequired,
    CanaryCapacityExceeded,
    CanaryControl,
    CanaryControlError,
    CanaryLeaseUnavailable,
    CanaryScopeMismatch,
    CanaryStaleLease,
)
from lead_factory.crm_handoff import HumanReplyCrmHandoff
from lead_factory.crm_outbox import CrmActivityOutbox, CrmActivityReceipt, CrmOutbox
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.ids import utc_now
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.store import FactoryStore, IdempotencyConflict
from lead_factory.unified_inbound_worker import UNROUTED


class CanaryControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "canary.sqlite3")
        self.store.init()
        self.control = CanaryControl(self.store)
        company, _ = self.store.create_company(name="Canary Fixture", inn="7701000011")
        self.company_id = company["lf_company_id"]
        self.run_id = self.control.create_run(created_by="owner")
        self.control.activate_run(self.run_id, actor="owner", evidence_ref="stage://run/activate")

    def tearDown(self):
        self.temp.cleanup()

    def _fixture(self, n: int, *, thread: str = "") -> dict:
        email = f"buyer{n}@example.test"
        outbound_thread = thread or f"<outbound-{n}@example.test>"
        project, _ = self.store.create_project(
            lf_company_id=self.company_id,
            source="canary-fixture",
            external_key=f"project-{n}",
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=self.company_id,
            lf_project_id=project["lf_project_id"],
            source="canary-fixture",
            external_key=f"opportunity-{n}",
        )
        interaction = InboundIntake(self.store).ingest(
            InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                external_message_id=f"<inbound-{n}@example.test>",
                uid=f"uid-{n}",
                uid_validity="100",
                from_address=email,
                contact_address=email,
                received_at_utc="2026-08-18T09:00:00Z",
                classification=UNROUTED,
                thread_id=outbound_thread,
                evidence_ref=f"stage-evidence:canary-{n}",
                create_human_task=False,
            )
        )
        return {
            "n": n,
            "email": email,
            "thread": outbound_thread,
            "opportunity_id": opportunity["lf_opportunity_id"],
            "interaction_id": interaction.interaction_id,
        }

    def _arm(self, fixture: dict, *, thread: str = "") -> str:
        return self.control.arm_scope(
            self.run_id,
            mailbox="INBOX",
            campaign_id="dealer-series",
            contact_address=fixture["email"],
            canonical_thread=thread or fixture["thread"],
            lf_opportunity_id=fixture["opportunity_id"],
            armed_by="owner",
            evidence_ref=f"stage://scope/{fixture['n']}",
        )

    def _route(self, fixture: dict, member_id: str, *, after_stage_hook=None, thread: str = ""):
        handoff = HumanReplyCrmHandoff(
            self.store,
            lead_payload={"title": f"Canary {fixture['n']}"},
            activity_payload={"title": "Review reply", "responsible_id": "7"},
            after_stage_hook=after_stage_hook,
            canary_control=self.control,
            canary_run_id=self.run_id,
            canary_member_id=member_id,
        )
        return InboundRouter(self.store, human_reply_handoff=handoff).route(
            InboundRouteDecision(
                interaction_id=fixture["interaction_id"],
                decision_id=f"route-{fixture['n']}",
                classification="HUMAN_REPLY",
                contact_address=fixture["email"],
                campaign_id="dealer-series",
                mailbox="INBOX",
                lf_opportunity_id=fixture["opportunity_id"],
                rule_version="canary-test/v1",
                evidence_ref=f"stage://route/{fixture['n']}",
            )
        )

    def _approve_one(self):
        return self.control.create_approval(
            self.run_id,
            cumulative_cap=1,
            approver="owner",
            evidence_ref="stage://approval/one",
        )

    def _prove_sent_pair(self, routed) -> None:
        """Create only the durable local outcome a real adapter would leave."""
        now = utc_now()
        with self.store.transaction() as con:
            lead = con.execute(
                "SELECT lf_entity_type,lf_entity_id FROM crm_outbox WHERE operation_id=?",
                (routed.lead_operation_id,),
            ).fetchone()
            self.assertIsNotNone(lead)
            con.execute(
                """UPDATE crm_outbox
                   SET state='SENT',remote_entity_type='lead',remote_entity_id='901',
                       lease_until_utc='',leased_by='',lease_token='',updated_at_utc=?
                   WHERE operation_id=?""",
                (now, routed.lead_operation_id),
            )
            con.execute(
                """INSERT INTO crm_mappings(
                       lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,state,created_at_utc
                   ) VALUES(?,?, 'lead','901','ACTIVE',?)""",
                (lead["lf_entity_type"], lead["lf_entity_id"], now),
            )
            con.execute(
                """UPDATE crm_outbox
                   SET state='SENT',remote_entity_type='activity',remote_entity_id='801',
                       lease_until_utc='',leased_by='',lease_token='',updated_at_utc=?
                   WHERE operation_id=?""",
                (now, routed.activity_operation_id),
            )

    def _expand_to_five(self, routed):
        self._prove_sent_pair(routed)
        checkpoint = self.control.record_manual_checkpoint(
            self.run_id,
            actor="owner",
            evidence_ref="stage://checkpoint/one",
            outcome="owner reviewed the first admitted member",
        )
        return self.control.create_approval(
            self.run_id,
            cumulative_cap=5,
            approver="owner",
            evidence_ref="stage://approval/five",
            checkpoint_event_id=checkpoint,
        )

    def _binding_count(self):
        return self.store.table_count("canary_operation_bindings")

    def test_no_approval_rolls_back_route_task_and_both_operations(self):
        fixture = self._fixture(1)
        member = self._arm(fixture)
        with self.assertRaises(CanaryApprovalRequired):
            self._route(fixture, member)
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("crm_outbox"), 0)
        self.assertEqual(self._binding_count(), 0)

    def test_cap_one_then_checkpointed_cumulative_five_and_sixth_is_rejected(self):
        members = [(self._fixture(n), None) for n in range(1, 7)]
        members = [(fixture, self._arm(fixture)) for fixture, _ in members]
        self._approve_one()
        first_routed = self._route(*members[0])
        with self.assertRaises(CanaryCapacityExceeded):
            self._route(*members[1])

        self._expand_to_five(first_routed)
        for fixture, member in members[1:5]:
            self._route(fixture, member)
        with self.assertRaises(CanaryCapacityExceeded):
            self._route(*members[5])
        self.assertEqual(self._binding_count(), 10)
        self.assertEqual(self.store.table_count("crm_outbox"), 10)

    def test_pending_or_review_bound_member_remains_a_consumed_slot(self):
        first, second = self._fixture(1), self._fixture(2)
        first_member, second_member = self._arm(first), self._arm(second)
        self._approve_one()
        routed = self._route(first, first_member)
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET state='REVIEW' WHERE operation_id=?",
                (routed.lead_operation_id,),
            )
        with self.assertRaises(CanaryCapacityExceeded):
            self._route(second, second_member)
        self.assertEqual(self._binding_count(), 2)

    def test_cap_five_requires_a_later_checkpoint_and_approvals_cannot_update(self):
        approval = self._approve_one()
        with self.assertRaises(CanaryApprovalRequired):
            self.control.create_approval(
                self.run_id,
                cumulative_cap=5,
                approver="owner",
                evidence_ref="stage://approval/illegal-five",
            )
        with self.store.transaction() as con:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE canary_approvals SET cumulative_cap=5 WHERE approval_id=?", (approval,)
                )
        fixture = self._fixture(1)
        routed = self._route(fixture, self._arm(fixture))
        expanded = self._expand_to_five(routed)
        self.assertTrue(expanded)
        with self.assertRaises(CanaryApprovalRequired):
            self.control.create_approval(
                self.run_id,
                cumulative_cap=5,
                approver="owner",
                evidence_ref="stage://approval/second-five",
                checkpoint_event_id=self.control.record_manual_checkpoint(
                    self.run_id,
                    actor="owner",
                    evidence_ref="stage://checkpoint/two",
                    outcome="owner reviewed the first admitted member again",
                ),
            )

    def test_checkpoint_rejects_pending_or_unmapped_pair_and_accepts_exact_sent_pair(self):
        fixture = self._fixture(1)
        self._approve_one()
        routed = self._route(fixture, self._arm(fixture))
        with self.assertRaises(CanaryApprovalRequired):
            self.control.record_manual_checkpoint(
                self.run_id,
                actor="owner",
                evidence_ref="stage://checkpoint/pending",
                outcome="pending is not proof",
            )
        now = utc_now()
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='lead',remote_entity_id='902',
                   updated_at_utc=? WHERE operation_id=?""",
                (now, routed.lead_operation_id),
            )
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='activity',remote_entity_id='802',
                   updated_at_utc=? WHERE operation_id=?""",
                (now, routed.activity_operation_id),
            )
        with self.assertRaises(CanaryApprovalRequired):
            self.control.record_manual_checkpoint(
                self.run_id,
                actor="owner",
                evidence_ref="stage://checkpoint/unmapped",
                outcome="sent without active mapping is not proof",
            )
        self._prove_sent_pair(routed)
        checkpoint = self.control.record_manual_checkpoint(
            self.run_id,
            actor="owner",
            evidence_ref="stage://checkpoint/proved",
            outcome="owner verified local sent receipts",
        )
        self.assertTrue(checkpoint)

    def test_checkpoint_rejects_sent_state_without_positive_remote_receipts(self):
        fixture = self._fixture(1)
        self._approve_one()
        routed = self._route(fixture, self._arm(fixture))
        self._prove_sent_pair(routed)
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET remote_entity_type='',remote_entity_id=''
                   WHERE operation_id=?""",
                (routed.activity_operation_id,),
            )
        with self.assertRaises(CanaryApprovalRequired):
            self.control.record_manual_checkpoint(
                self.run_id,
                actor="owner",
                evidence_ref="stage://checkpoint/activity-without-receipt",
                outcome="a state label is not an activity receipt",
            )
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET remote_entity_type='activity',remote_entity_id='801'
                   WHERE operation_id=?""",
                (routed.activity_operation_id,),
            )
            con.execute(
                "UPDATE crm_outbox SET remote_entity_id='0' WHERE operation_id=?",
                (routed.lead_operation_id,),
            )
            con.execute("UPDATE crm_mappings SET remote_entity_id='0'")
        with self.assertRaises(CanaryApprovalRequired):
            self.control.record_manual_checkpoint(
                self.run_id,
                actor="owner",
                evidence_ref="stage://checkpoint/lead-zero-receipt",
                outcome="zero is not a lead receipt",
            )

    def test_expansion_rechecks_active_mapping_after_checkpoint(self):
        fixture = self._fixture(1)
        self._approve_one()
        routed = self._route(fixture, self._arm(fixture))
        self._prove_sent_pair(routed)
        checkpoint = self.control.record_manual_checkpoint(
            self.run_id,
            actor="owner",
            evidence_ref="stage://checkpoint/proved",
            outcome="owner verified local sent receipts",
        )
        with self.store.transaction() as con:
            con.execute("UPDATE crm_mappings SET state='INACTIVE'")
        with self.assertRaises(CanaryApprovalRequired):
            self.control.create_approval(
                self.run_id,
                cumulative_cap=5,
                approver="owner",
                evidence_ref="stage://approval/five",
                checkpoint_event_id=checkpoint,
            )

    def test_unrelated_pending_crm_operation_never_consumes_canary_capacity(self):
        unrelated = self._fixture(99)
        CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=unrelated["opportunity_id"],
            external_event_id="unrelated-pending",
            payload={"title": "Not canary"},
        )
        fixture = self._fixture(1)
        member = self._arm(fixture)
        self._approve_one()
        self._route(fixture, member)
        self.assertEqual(self._binding_count(), 2)
        self.assertEqual(self.store.table_count("crm_outbox"), 3)

    def test_exact_scope_mismatch_rolls_back_everything(self):
        fixture = self._fixture(1)
        member = self._arm(fixture, thread="<other-outbound@example.test>")
        self._approve_one()
        with self.assertRaises(CanaryScopeMismatch):
            self._route(fixture, member)
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("crm_outbox"), 0)
        self.assertEqual(self._binding_count(), 0)

    def test_crash_after_bind_rolls_back_bindings_and_handoff_pair(self):
        fixture = self._fixture(1)
        member = self._arm(fixture)
        self._approve_one()
        with self.assertRaisesRegex(RuntimeError, "simulated loss"):
            self._route(fixture, member, after_stage_hook=lambda: (_ for _ in ()).throw(RuntimeError("simulated loss")))
        self.assertEqual(self.store.table_count("human_tasks"), 0)
        self.assertEqual(self.store.table_count("crm_outbox"), 0)
        self.assertEqual(self._binding_count(), 0)

    def test_two_workers_are_fenced_and_stop_revokes_lease_and_writer_gate(self):
        first = self.control.acquire_writer_lease(self.run_id, owner_id="worker-1", lease_seconds=300)
        with self.assertRaises(CanaryLeaseUnavailable):
            self.control.acquire_writer_lease(self.run_id, owner_id="worker-2", lease_seconds=300)
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")
        self.control.assert_writer_lease(first)
        self.assertTrue(self.control.release_writer_lease(first))
        second = self.control.acquire_writer_lease(self.run_id, owner_id="worker-2", lease_seconds=300)
        self.assertGreater(second.fence_token, first.fence_token)
        with self.assertRaises(CanaryStaleLease):
            self.control.assert_writer_lease(first)

        self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="acceptance stop",
            evidence_ref="stage://stop/one",
        )
        self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="acceptance stop",
            evidence_ref="stage://stop/one",
        )
        with self.assertRaises(IdempotencyConflict):
            self.control.stop_run(
                self.run_id,
                actor="owner",
                reason="different stop reason",
                evidence_ref="stage://stop/one",
            )
        with self.assertRaises(CanaryStaleLease):
            self.control.assert_writer_lease(second)
        con = self.store.connect()
        try:
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]
            lease = con.execute("SELECT owner_id,run_id FROM connector_writer_leases").fetchone()
        finally:
            con.close()
        self.assertEqual(writer, "0")
        self.assertEqual((lease["owner_id"], lease["run_id"]), ("", ""))

    def test_checkpoint_before_first_admission_is_rejected_and_approval_replay_is_idempotent(self):
        first = self._approve_one()
        replay = self.control.create_approval(
            self.run_id,
            cumulative_cap=1,
            approver="owner",
            evidence_ref="stage://approval/one",
            approval_id=first,
        )
        self.assertEqual(replay, first)
        with self.assertRaises(CanaryApprovalRequired):
            self.control.record_manual_checkpoint(
                self.run_id,
                actor="owner",
                evidence_ref="stage://checkpoint/too-early",
                outcome="no admitted member yet",
            )

    def test_only_one_active_run_exists_for_connector(self):
        second = self.control.create_run(created_by="owner")
        with self.assertRaises(CanaryControlError):
            self.control.activate_run(second, actor="owner", evidence_ref="stage://run/second")

    def test_same_owner_renewal_fences_the_old_lease(self):
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")
        first = self.control.acquire_writer_lease(self.run_id, owner_id="worker-1", lease_seconds=300)
        renewed = self.control.acquire_writer_lease(self.run_id, owner_id="worker-1", lease_seconds=300)
        self.assertGreater(renewed.fence_token, first.fence_token)
        with self.assertRaises(CanaryStaleLease):
            self.control.assert_writer_lease(first)
        self.control.assert_writer_lease(renewed)

    def test_canary_dispatch_ignores_older_unrelated_pending_and_permit_is_exact(self):
        unrelated = self._fixture(99)
        unrelated_operation, _ = CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=unrelated["opportunity_id"],
            external_event_id="older-unrelated-pending",
            payload={"title": "Not a canary operation"},
        )
        fixture = self._fixture(1)
        member = self._arm(fixture)
        self._approve_one()
        routed = self._route(fixture, member)
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")
        lease = self.control.acquire_writer_lease(self.run_id, owner_id="canary-worker", lease_seconds=300)
        lead_permit = self.control.claim_next_dispatch(lease)
        self.assertIsNotNone(lead_permit)
        self.assertEqual(lead_permit.operation_id, routed.lead_operation_id)
        with self.assertRaises(CanaryStaleLease):
            self.control.assert_dispatch_permit(
                lead_permit, lease, operation_id=unrelated_operation
            )
        self.control.assert_dispatch_permit(
            lead_permit, lease, operation_id=routed.lead_operation_id
        )
        # The same check is usable inside an already-acquired writer barrier;
        # the sealed runtime relies on this form to make a later stop linear
        # with the actual provider request.
        with self.store.transaction() as con:
            self.control.assert_dispatch_permit_tx(
                con, lead_permit, lease, operation_id=routed.lead_operation_id
            )
        # The permit commits to the exact payload/correlation and the claimed
        # operation owner; any drift makes it unusable before a future adapter
        # call.  Restore each field only to keep exercising the same local
        # permit without creating another canary member.
        for column, changed, expected in (
            ("payload_hash", "tampered-payload", lead_permit.payload_hash),
            ("correlation_token", "tampered-correlation", lead_permit.correlation_token),
            ("leased_by", "other-worker", lease.owner_id),
        ):
            with self.subTest(column=column):
                with self.store.transaction() as con:
                    con.execute(
                        f"UPDATE crm_outbox SET {column}=? WHERE operation_id=?",
                        (changed, routed.lead_operation_id),
                    )
                with self.assertRaises(CanaryStaleLease):
                    self.control.assert_dispatch_permit(
                        lead_permit, lease, operation_id=routed.lead_operation_id
                    )
                with self.store.transaction() as con:
                    con.execute(
                        f"UPDATE crm_outbox SET {column}=? WHERE operation_id=?",
                        (expected, routed.lead_operation_id),
                    )
                self.control.assert_dispatch_permit(
                    lead_permit, lease, operation_id=routed.lead_operation_id
                )
        # A dependent Activity remains unclaimable until its *same bound* Lead
        # is sent and has the exact active mapping.
        self.assertIsNone(self.control.claim_next_dispatch(lease, operation_type="BITRIX_ACTIVITY_CREATE"))
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='lead',remote_entity_id='901',
                   lease_until_utc='',leased_by='',lease_token='' WHERE operation_id=?""",
                (routed.lead_operation_id,),
            )
            con.execute(
                """INSERT INTO crm_mappings(
                    lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,state,last_readback_at_utc,created_at_utc
                ) VALUES(?,?,?,?,?,?,?)""",
                ("opportunity", fixture["opportunity_id"], "lead", "901", "ACTIVE", "", "2026-08-18T10:00:00Z"),
            )
        activity_permit = self.control.claim_next_dispatch(
            lease, operation_type="BITRIX_ACTIVITY_CREATE"
        )
        self.assertIsNotNone(activity_permit)
        self.assertEqual(activity_permit.operation_id, routed.activity_operation_id)
        self.control.assert_dispatch_permit(
            activity_permit, lease, operation_id=routed.activity_operation_id
        )
        with self.assertRaises(CanaryStaleLease):
            self.control.assert_dispatch_permit(
                activity_permit, lease, operation_id=routed.lead_operation_id
            )

    def test_generic_crm_workers_never_claim_or_transport_a_bound_canary_pair(self):
        fixture = self._fixture(1)
        member = self._arm(fixture)
        self._approve_one()
        routed = self._route(fixture, member)
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")

        class Transport:
            def __init__(self):
                self.lead_calls = 0
                self.lookup_calls = 0
                self.activity_calls = 0

            def create_lead(self, payload, correlation_token):
                self.lead_calls += 1
                return "901"

            def find_lead_by_correlation_token(self, correlation_token):
                self.lookup_calls += 1
                return None

            def create_activity(self, lead_id, payload):
                self.activity_calls += 1
                return CrmActivityReceipt("801", lead_id, True)

        transport = Transport()
        leads = CrmOutbox(self.store)
        activities = CrmActivityOutbox(self.store)

        self.assertIsNone(leads.claim_next("generic-lead"))
        self.assertIsNone(leads.process_next(transport, worker_id="generic-lead"))
        self.assertEqual(transport.lead_calls, 0)

        # Generic reconciliation is also not an escape route for an uncertain
        # operation belonging to the dedicated canary executor.
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN' WHERE operation_id=?",
                (routed.lead_operation_id,),
            )
        self.assertIsNone(leads.reconcile_one(transport, worker_id="generic-reconcile"))
        self.assertEqual(transport.lookup_calls, 0)

        # Make the bound Activity otherwise eligible.  The generic activity
        # worker must still neither claim nor invoke its transport.
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='lead',
                   remote_entity_id='901',lease_until_utc='',leased_by='',lease_token=''
                   WHERE operation_id=?""",
                (routed.lead_operation_id,),
            )
            con.execute(
                """INSERT INTO crm_mappings(
                    lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,
                    state,last_readback_at_utc,created_at_utc
                ) VALUES(?,?,?,?,?,?,?)""",
                ("opportunity", fixture["opportunity_id"], "lead", "901", "ACTIVE", "", "2026-08-18T10:00:00Z"),
            )
        self.assertIsNone(activities.claim_next("generic-activity"))
        self.assertIsNone(activities.process_next(transport, worker_id="generic-activity"))
        self.assertEqual(transport.activity_calls, 0)

    def test_active_approved_canary_holds_unbound_generic_lead_and_activity_workers(self):
        """The canary writer flag must not open the generic CRM queues."""
        canary = self._fixture(1)
        self._approve_one()
        self._route(canary, self._arm(canary))

        # Route a different conversation without the canary handoff.  Its
        # Lead/Activity pair has no canary binding and would historically be
        # selected by the generic oldest-PENDING queries.
        unbound = self._fixture(99)
        generic_handoff = HumanReplyCrmHandoff(
            self.store,
            lead_payload={"title": "Unbound generic lead"},
            activity_payload={"title": "Unbound generic activity", "responsible_id": "7"},
        )
        routed = InboundRouter(self.store, human_reply_handoff=generic_handoff).route(
            InboundRouteDecision(
                interaction_id=unbound["interaction_id"],
                decision_id="route-unbound-99",
                classification="HUMAN_REPLY",
                contact_address=unbound["email"],
                campaign_id="dealer-series",
                mailbox="INBOX",
                lf_opportunity_id=unbound["opportunity_id"],
                rule_version="generic-test/v1",
                evidence_ref="stage://route/unbound-99",
            )
        )
        con = self.store.connect()
        try:
            binding = con.execute(
                "SELECT 1 FROM canary_operation_bindings WHERE operation_id=?",
                (routed.lead_operation_id,),
            ).fetchone()
        finally:
            con.close()
        self.assertFalse(binding)
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")

        class Transport:
            def __init__(self):
                self.lead_calls = 0
                self.lookup_calls = 0
                self.activity_calls = 0

            def create_lead(self, payload, correlation_token):
                self.lead_calls += 1
                return "901"

            def find_lead_by_correlation_token(self, correlation_token):
                self.lookup_calls += 1
                return None

            def create_activity(self, lead_id, payload):
                self.activity_calls += 1
                return CrmActivityReceipt("801", lead_id, True)

        transport = Transport()
        leads = CrmOutbox(self.store)
        activities = CrmActivityOutbox(self.store)
        self.assertIsNone(leads.claim_next("generic-lead"))
        blocked_lead = leads.process_next(transport, worker_id="generic-lead")
        self.assertIsNotNone(blocked_lead)
        self.assertEqual(blocked_lead.state, "BLOCKED")
        self.assertEqual(transport.lead_calls, 0)

        # Also prove that generic reconcile cannot use a read call as a
        # transport escape route while the approved canary owns the global
        # writer flag.
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN' WHERE operation_id=?",
                (routed.lead_operation_id,),
            )
        self.assertIsNone(leads.reconcile_one(transport, worker_id="generic-reconcile"))
        self.assertEqual(transport.lookup_calls, 0)

        # Make the unbound Activity otherwise eligible.  The generic worker
        # must still fail before claim and before its create transport.
        now = utc_now()
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='lead',
                   remote_entity_id='901',lease_until_utc='',leased_by='',lease_token=''
                   WHERE operation_id=?""",
                (routed.lead_operation_id,),
            )
            con.execute(
                """INSERT INTO crm_mappings(
                    lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,
                    state,last_readback_at_utc,created_at_utc
                ) VALUES(?,?,?,?,?,?,?)""",
                ("opportunity", unbound["opportunity_id"], "lead", "901", "ACTIVE", "", now),
            )
        self.assertIsNone(activities.claim_next("generic-activity"))
        blocked_activity = activities.process_next(transport, worker_id="generic-activity")
        self.assertIsNotNone(blocked_activity)
        self.assertEqual(blocked_activity.state, "BLOCKED")
        self.assertEqual(transport.activity_calls, 0)

    def test_generic_workers_are_available_again_after_canary_stop_and_new_enable(self):
        """Stopping a canary does not leave ordinary queues permanently held."""
        self._approve_one()
        self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="fixture complete",
            evidence_ref="stage://run/stop",
        )
        fixture = self._fixture(77)
        operation_id, _ = CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=fixture["opportunity_id"],
            external_event_id="ordinary-after-stop",
            payload={"title": "Ordinary operation"},
        )
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")
        claimed = CrmOutbox(self.store).claim_next("ordinary-worker")
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["operation_id"], operation_id)

    def test_restore_stops_active_run_and_old_approval_cannot_reacquire_lease(self):
        self._approve_one()
        evidence = Path(self.temp.name) / "empty-evidence"
        backup_dir = Path(self.temp.name) / "backups"
        report = create_backup(self.store, destination_dir=backup_dir, evidence_root=evidence)
        restored_path = Path(self.temp.name) / "restored.sqlite3"
        verify_restore(report["backup"], restore_path=restored_path)
        restored = FactoryStore(restored_path)
        restored_control = CanaryControl(restored)
        with self.assertRaises(CanaryControlError):
            restored_control.acquire_writer_lease(
                self.run_id, owner_id="restored-worker", lease_seconds=60
            )
        self.assertFalse(restored.status()["external_writers_enabled"])


if __name__ == "__main__":
    unittest.main()
