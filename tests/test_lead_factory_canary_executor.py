from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lead_factory.canary_control import (
    ACTIVITY_CREATE,
    CanaryControl,
    CanaryStaleLease,
)
from lead_factory.canary_executor import CanaryExecutor
from lead_factory.crm_handoff import HumanReplyCrmHandoff
from lead_factory.crm_outbox import CrmActivityReceipt, CrmOutbox, PermanentRemoteError
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import UNROUTED


_AUTHORITY_PATCHER = patch(
    "lead_factory.canary_executor.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class LeadAdapter:
    def __init__(self, *, remote_id: str = "701", failure: Exception | None = None):
        self.remote_id = remote_id
        self.failure = failure
        self.creates = 0
        self.lookups = 0
        self.seen_tokens: list[str] = []

    def create_lead(self, payload, correlation_token):
        self.creates += 1
        self.seen_tokens.append(correlation_token)
        if self.failure:
            raise self.failure
        return self.remote_id

    def find_lead_by_correlation_token(self, correlation_token):
        self.lookups += 1
        self.seen_tokens.append(correlation_token)
        if self.failure:
            raise self.failure
        return self.remote_id


class ActivityAdapter:
    def __init__(self, receipt: CrmActivityReceipt | None = None):
        self.receipt = receipt or CrmActivityReceipt("811", "701", True)
        self.calls = 0
        self.owners: list[str] = []

    def create_activity(self, lead_remote_id, payload):
        self.calls += 1
        self.owners.append(lead_remote_id)
        return self.receipt


class CanaryExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "canary-executor.sqlite3")
        self.store.init()
        self.control = CanaryControl(self.store)
        self.executor = CanaryExecutor(self.store, self.control)
        company, _ = self.store.create_company(name="Canary executor", inn="7701000011")
        self.company_id = company["lf_company_id"]
        self.run_id = self.control.create_run(created_by="owner")
        self.control.activate_run(
            self.run_id, actor="owner", evidence_ref="stage://run/activate"
        )

    def tearDown(self):
        self.temp.cleanup()

    def _fixture(self, n: int = 1):
        email = f"buyer{n}@example.test"
        thread = f"<outbound-{n}@example.test>"
        project, _ = self.store.create_project(
            lf_company_id=self.company_id,
            source="canary-executor-test",
            external_key=f"project-{n}",
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=self.company_id,
            lf_project_id=project["lf_project_id"],
            source="canary-executor-test",
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
                thread_id=thread,
                evidence_ref=f"stage-evidence:executor-{n}",
                create_human_task=False,
            )
        )
        return {
            "n": n,
            "email": email,
            "thread": thread,
            "opportunity_id": opportunity["lf_opportunity_id"],
            "interaction_id": interaction.interaction_id,
        }

    def _route_one(self, n: int = 1):
        fixture = self._fixture(n)
        member_id = self.control.arm_scope(
            self.run_id,
            mailbox="INBOX",
            campaign_id="dealer-series",
            contact_address=fixture["email"],
            canonical_thread=fixture["thread"],
            lf_opportunity_id=fixture["opportunity_id"],
            armed_by="owner",
            evidence_ref=f"stage://scope/{n}",
        )
        self.control.create_approval(
            self.run_id,
            cumulative_cap=1,
            approver="owner",
            evidence_ref="stage://approval/one",
        )
        handoff = HumanReplyCrmHandoff(
            self.store,
            lead_payload={"title": f"Canary private title {n}"},
            activity_payload={"title": "Review reply", "responsible_id": "7"},
            canary_control=self.control,
            canary_run_id=self.run_id,
            canary_member_id=member_id,
        )
        routed = InboundRouter(self.store, human_reply_handoff=handoff).route(
            InboundRouteDecision(
                interaction_id=fixture["interaction_id"],
                decision_id=f"route-{n}",
                classification="HUMAN_REPLY",
                contact_address=fixture["email"],
                campaign_id="dealer-series",
                mailbox="INBOX",
                lf_opportunity_id=fixture["opportunity_id"],
                rule_version="canary-executor/v1",
                evidence_ref=f"stage://route/{n}",
            )
        )
        return fixture, routed

    def _lease(self):
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )
        return self.control.acquire_writer_lease(
            self.run_id, owner_id="canary-executor", lease_seconds=300
        )

    def _row(self, operation_id: str):
        con = self.store.connect()
        try:
            row = con.execute("SELECT * FROM crm_outbox WHERE operation_id=?", (operation_id,)).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def test_success_is_exact_audited_and_activity_uses_the_sent_lead(self):
        fixture, routed = self._route_one()
        lease = self._lease()
        lead_permit = self.control.claim_next_dispatch(lease)
        lead = LeadAdapter(remote_id="701")
        result = self.executor.execute_lead(lead_permit, lease, lead)
        self.assertEqual((result.state, lead.creates), ("SENT", 1))
        self.assertEqual(self._row(routed.lead_operation_id)["remote_entity_id"], "701")

        activity_permit = self.control.claim_next_dispatch(lease, operation_type=ACTIVITY_CREATE)
        self.assertIsNotNone(activity_permit)
        activity = ActivityAdapter(CrmActivityReceipt("811", "701", True))
        activity_result = self.executor.execute_activity(activity_permit, lease, activity)
        self.assertEqual((activity_result.state, activity.calls, activity.owners), ("SENT", 1, ["701"]))
        self.assertEqual(self._row(routed.activity_operation_id)["remote_entity_id"], "811")

        con = self.store.connect()
        try:
            rows = con.execute(
                "SELECT payload_json FROM events WHERE producer='canary_executor' ORDER BY event_id"
            ).fetchall()
        finally:
            con.close()
        self.assertGreaterEqual(len(rows), 4)
        audit = "\n".join(str(row["payload_json"]) for row in rows)
        self.assertNotIn(fixture["email"], audit)
        self.assertNotIn("Canary private title", audit)

    def test_generic_older_pending_is_never_dispatched_and_permit_substitution_fails(self):
        unrelated = self._fixture(99)
        unrelated_id, _ = CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=unrelated["opportunity_id"],
            external_event_id="older-unrelated",
            payload={"title": "unrelated"},
        )
        _, routed = self._route_one()
        lease = self._lease()
        permit = self.control.claim_next_dispatch(lease)
        self.assertEqual(permit.operation_id, routed.lead_operation_id)
        self.assertNotEqual(permit.operation_id, unrelated_id)

        with self.assertRaises(CanaryStaleLease):
            self.executor.execute_activity(permit, lease, ActivityAdapter())
        self.assertEqual(self._row(unrelated_id)["state"], "PENDING")

    def test_payload_drift_blocks_before_any_transport(self):
        # A direct payload drift cannot pass immutable hash verification, even
        # though its original permit is well formed.
        _, routed = self._route_one()
        lease = self._lease()
        permit = self.control.claim_next_dispatch(lease)
        with self.store.transaction() as con:
            con.execute("UPDATE crm_outbox SET payload_json=? WHERE operation_id=?", (json.dumps({"title": "tampered"}), routed.lead_operation_id))
        adapter = LeadAdapter()
        result = self.executor.execute_lead(permit, lease, adapter)
        self.assertEqual((result.state, adapter.creates), ("BLOCKED", 0))

    def test_kill_switch_blocks_pre_call(self):
        _, _ = self._route_one()
        lease = self._lease()
        permit = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter()
        result = self.executor.execute_lead(
            permit,
            lease,
            adapter,
            before_transport_hook=lambda: self._disable_writers(),
        )
        self.assertEqual((result.state, adapter.creates), ("BLOCKED", 0))

    def test_stop_fence_blocks_pre_call(self):
        _, _ = self._route_one()
        lease = self._lease()
        permit = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter()
        result = self.executor.execute_lead(
            permit,
            lease,
            adapter,
            before_transport_hook=lambda: self.control.stop_run(
                self.run_id, actor="owner", reason="test stop", evidence_ref="stage://stop"
            ),
        )
        self.assertEqual((result.state, adapter.creates), ("BLOCKED", 0))

    def test_crash_after_remote_lead_can_only_reconcile_by_correlation_without_second_add(self):
        _, routed = self._route_one()
        lease = self._lease()
        create_permit = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter(remote_id="702")
        first = self.executor.execute_lead(
            create_permit,
            lease,
            adapter,
            after_remote_hook=lambda: (_ for _ in ()).throw(RuntimeError("crash after remote")),
        )
        self.assertEqual((first.state, adapter.creates), ("UNCERTAIN", 1))
        self.assertEqual(self._row(routed.lead_operation_id)["state"], "UNCERTAIN")

        reconcile = self.control.claim_next_reconcile(lease)
        self.assertIsNotNone(reconcile)
        with self.assertRaises(CanaryStaleLease):
            self.executor.execute_lead(reconcile, lease, adapter)
        self.assertEqual(adapter.creates, 1)
        result = self.executor.reconcile_lead(reconcile, lease, adapter)
        self.assertEqual((result.state, adapter.creates, adapter.lookups), ("SENT", 1, 1))
        self.assertEqual(self._row(routed.lead_operation_id)["remote_entity_id"], "702")

    def test_bounded_lead_reconcile_never_recreates_and_escalates_to_review(self):
        _, routed = self._route_one()
        lease = self._lease()
        create = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter(remote_id="703")
        self.executor.execute_lead(
            create,
            lease,
            adapter,
            after_remote_hook=lambda: (_ for _ in ()).throw(RuntimeError("crash after remote")),
        )
        self.executor.leads.max_reconcile_attempts = 1
        reconcile = self.control.claim_next_reconcile(lease)
        adapter.remote_id = ""
        result = self.executor.reconcile_lead(reconcile, lease, adapter)
        row = self._row(routed.lead_operation_id)
        self.assertEqual((result.state, adapter.creates, adapter.lookups), ("REVIEW", 1, 1))
        self.assertEqual((row["state"], row["reconcile_count"]), ("REVIEW", 1))

    def test_repeated_reconcile_timeouts_are_bounded_then_no_longer_selectable(self):
        _, routed = self._route_one()
        lease = self._lease()
        create = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter(remote_id="704")
        self.executor.execute_lead(
            create,
            lease,
            adapter,
            after_remote_hook=lambda: (_ for _ in ()).throw(RuntimeError("crash after remote")),
        )
        self.executor.leads.max_reconcile_attempts = 2
        adapter.failure = TimeoutError("lookup timeout")
        first = self.control.claim_next_reconcile(lease)
        self.assertEqual(self.executor.reconcile_lead(first, lease, adapter).state, "UNCERTAIN")
        with self.store.transaction() as con:
            con.execute("UPDATE crm_outbox SET next_attempt_at_utc='' WHERE operation_id=?", (routed.lead_operation_id,))
        second = self.control.claim_next_reconcile(lease)
        self.assertEqual(self.executor.reconcile_lead(second, lease, adapter).state, "REVIEW")
        self.assertEqual((adapter.creates, adapter.lookups), (1, 2))
        self.assertIsNone(self.control.claim_next_reconcile(lease))

    def test_permanent_reconcile_failure_is_terminal_review_not_another_create(self):
        _, routed = self._route_one()
        lease = self._lease()
        create = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter(remote_id="705")
        self.executor.execute_lead(
            create,
            lease,
            adapter,
            after_remote_hook=lambda: (_ for _ in ()).throw(RuntimeError("crash after remote")),
        )
        reconcile = self.control.claim_next_reconcile(lease)
        adapter.failure = PermanentRemoteError("lookup configuration invalid")
        result = self.executor.reconcile_lead(reconcile, lease, adapter)
        self.assertEqual((result.state, adapter.creates, adapter.lookups), ("REVIEW", 1, 1))
        self.assertEqual(self._row(routed.lead_operation_id)["state"], "REVIEW")

    def test_durable_lease_action_rejects_create_reconcile_substitution(self):
        _, _ = self._route_one()
        lease = self._lease()
        create = self.control.claim_next_dispatch(lease)
        adapter = LeadAdapter(remote_id="706")
        self.assertEqual(
            self.executor.reconcile_lead(
                replace(create, action="RECONCILE"), lease, adapter
            ).state,
            "BLOCKED",
        )
        self.assertEqual((adapter.creates, adapter.lookups), (0, 0))

        self.executor.execute_lead(
            create,
            lease,
            adapter,
            after_remote_hook=lambda: (_ for _ in ()).throw(RuntimeError("crash after remote")),
        )
        reconcile = self.control.claim_next_reconcile(lease)
        self.assertEqual(
            self.executor.execute_lead(
                replace(reconcile, action="CREATE"), lease, adapter
            ).state,
            "BLOCKED",
        )
        self.assertEqual((adapter.creates, adapter.lookups), (1, 0))

    def test_unverified_activity_receipt_preserves_candidate_for_review(self):
        _, routed = self._route_one()
        lease = self._lease()
        self.executor.execute_lead(
            self.control.claim_next_dispatch(lease), lease, LeadAdapter(remote_id="701")
        )
        permit = self.control.claim_next_dispatch(lease, operation_type=ACTIVITY_CREATE)
        adapter = ActivityAdapter(CrmActivityReceipt("812", "wrong-owner", False))
        result = self.executor.execute_activity(permit, lease, adapter)
        row = self._row(routed.activity_operation_id)
        self.assertEqual((result.state, adapter.calls), ("REVIEW", 1))
        self.assertEqual(
            (row["suspect_remote_entity_type"], row["suspect_remote_entity_id"]),
            ("activity", "812"),
        )

    def test_post_remote_activity_stop_preserves_suspect_id_and_does_not_retry(self):
        _, routed = self._route_one()
        lease = self._lease()
        lead_permit = self.control.claim_next_dispatch(lease)
        self.executor.execute_lead(lead_permit, lease, LeadAdapter(remote_id="701"))
        activity_permit = self.control.claim_next_dispatch(lease, operation_type=ACTIVITY_CREATE)
        adapter = ActivityAdapter(CrmActivityReceipt("811", "701", True))
        result = self.executor.execute_activity(
            activity_permit,
            lease,
            adapter,
            after_remote_hook=lambda: self.control.stop_run(
                self.run_id, actor="owner", reason="post remote stop", evidence_ref="stage://stop"
            ),
        )
        row = self._row(routed.activity_operation_id)
        self.assertEqual((result.state, adapter.calls), ("REVIEW", 1))
        self.assertEqual((row["state"], row["suspect_remote_entity_type"], row["suspect_remote_entity_id"]), ("REVIEW", "activity", "811"))

    def test_expired_ambiguous_activity_is_reviewed_locally_with_zero_transport_calls(self):
        _, routed = self._route_one()
        lease = self._lease()
        self.executor.execute_lead(self.control.claim_next_dispatch(lease), lease, LeadAdapter(remote_id="701"))
        activity_permit = self.control.claim_next_dispatch(lease, operation_type=ACTIVITY_CREATE)
        # Simulate a process crash after durable claim and before the adapter.
        with self.store.transaction() as con:
            con.execute("UPDATE crm_outbox SET lease_until_utc='' WHERE operation_id=?", (activity_permit.operation_id,))
        review_permit = self.control.claim_next_expired_activity_review(lease)
        adapter = ActivityAdapter()
        result = self.executor.finalize_expired_activity(review_permit, lease)
        self.assertEqual((result.state, adapter.calls), ("REVIEW", 0))
        self.assertEqual(self._row(routed.activity_operation_id)["state"], "REVIEW")

    def test_outcome_audit_failure_after_sent_does_not_roll_back_sent_state(self):
        _, routed = self._route_one()
        lease = self._lease()
        permit = self.control.claim_next_dispatch(lease)
        original_audit = self.executor._audit

        def fail_outcome(phase, *args, **kwargs):
            if phase == "outcome":
                raise RuntimeError("audit sink unavailable")
            return original_audit(phase, *args, **kwargs)

        self.executor._audit = fail_outcome
        result = self.executor.execute_lead(permit, lease, LeadAdapter(remote_id="701"))
        self.assertEqual(result.state, "SENT")
        self.assertEqual(self._row(routed.lead_operation_id)["state"], "SENT")

    def _disable_writers(self):
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='0' WHERE key='external_writers_enabled'")


if __name__ == "__main__":
    unittest.main()
