from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.canary_control import BITRIX_CANARY_CONNECTOR
from lead_factory.crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphCreateRequest,
    CrmGraphOutbox,
    CrmGraphReadback,
    GraphInvariantError,
    GraphReadbackMismatch,
    SafeReconciliationUnsupported,
)
from lead_factory.crm_outbox import (
    CrmOutbox,
    PermanentRemoteError,
    RetryableRemoteError,
)
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.store import FactoryStore, IdempotencyConflict


_AUTHORITY_PATCHER = patch(
    "lead_factory.crm_graph_outbox.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class FakeGraphTransport:
    def __init__(self):
        self.create_calls = []
        self.find_calls = []
        self.next_ids = {
            "company": "101",
            "contact": "201",
            "deal": "301",
            "activity": "401",
        }
        self.create_error = None
        self.find_error = None
        self.receipts = {}
        self.receipt_override = None

    @staticmethod
    def receipt_for(request, remote_id):
        dependencies = dict(request.dependency_remote_ids)
        return CrmGraphReadback(
            remote_entity_type=request.remote_entity_type,
            remote_id=remote_id,
            correlation_token=request.correlation_token,
            readback_verified=True,
            company_remote_id=dependencies.get("company", ""),
            contact_remote_id=dependencies.get("contact", ""),
            deal_remote_id=dependencies.get("deal", ""),
        )

    def create_entity(self, request):
        self.create_calls.append(request)
        if self.create_error:
            error = self.create_error
            self.create_error = None
            raise error
        receipt = self.receipt_override or self.receipt_for(
            request, self.next_ids[request.remote_entity_type]
        )
        self.receipt_override = None
        self.receipts[(request.remote_entity_type, request.correlation_token)] = receipt
        return receipt

    def find_by_correlation(self, remote_entity_type, correlation_token):
        self.find_calls.append((remote_entity_type, correlation_token))
        if self.find_error:
            raise self.find_error
        return self.receipts.get((remote_entity_type, correlation_token))


class CrmGraphOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "graph.sqlite3")
        self.store.init()
        self.outbox = CrmGraphOutbox(self.store, max_reconcile_attempts=2)
        self.company, _ = self.store.create_company(
            name="Aluminium buyer", inn="7701000001"
        )
        self.contact, _ = self.store.create_contact(
            lf_company_id=self.company["lf_company_id"],
            email="buyer@example.test",
            name="Buyer",
        )
        self.project, _ = self.store.create_project(
            lf_company_id=self.company["lf_company_id"],
            source="fixture",
            external_key="project-1",
            title="Facade",
        )
        self.opportunity, _ = self.store.create_opportunity(
            lf_company_id=self.company["lf_company_id"],
            lf_contact_id=self.contact["lf_contact_id"],
            lf_project_id=self.project["lf_project_id"],
            source="fixture",
            external_key="opportunity-1",
        )

    def tearDown(self):
        self.temp.cleanup()

    def set_writers(self, enabled):
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='external_writers_enabled'",
                ("1" if enabled else "0",),
            )

    def stage(self, **overrides):
        values = {
            "company_id": self.company["lf_company_id"],
            "contact_id": self.contact["lf_contact_id"],
            "project_id": self.project["lf_project_id"],
            "opportunity_id": self.opportunity["lf_opportunity_id"],
            "external_event_id": "source:fixture:1",
            "company_payload": {"TITLE": "Aluminium buyer"},
            "contact_payload": {"NAME": "Buyer"},
            "deal_payload": {"TITLE": "Facade opportunity"},
            "activity_payload": {"SUBJECT": "Review opportunity"},
        }
        values.update(overrides)
        return self.outbox.stage_graph(**values)

    def rows(self):
        con = self.store.connect()
        try:
            return [
                dict(row)
                for row in con.execute(
                    "SELECT * FROM crm_outbox ORDER BY created_at_utc,operation_id"
                ).fetchall()
            ]
        finally:
            con.close()

    def row(self, operation_id):
        con = self.store.connect()
        try:
            return dict(
                con.execute(
                    "SELECT * FROM crm_outbox WHERE operation_id=?", (operation_id,)
                ).fetchone()
            )
        finally:
            con.close()

    def run_graph(self, transport):
        results = []
        for _ in range(4):
            results.append(
                self.outbox.process_next(transport, worker_id="graph-worker")
            )
        return results

    def make_company_uncertain(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        transport.create_error = TimeoutError("response lost")
        result = self.outbox.process_next(transport, worker_id="create-worker")
        self.assertEqual(result.state, "UNCERTAIN")
        return plan, transport

    def install_canary(self, *, state="ACTIVE", suffix="sealed"):
        run_id = f"run-{suffix}"
        approval_id = f"approval-{suffix}"
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO canary_runs(
                       run_id,connector,state,created_by,created_at_utc
                   ) VALUES(?,?,?,?,?)""",
                (
                    run_id,
                    BITRIX_CANARY_CONNECTOR,
                    state,
                    "tester",
                    "2026-08-20T00:00:00Z",
                ),
            )
            con.execute(
                """INSERT INTO canary_approvals(
                       approval_id,run_id,approval_sequence,cumulative_cap,
                       approver,evidence_ref,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    approval_id,
                    run_id,
                    1,
                    1,
                    "tester",
                    "evidence://approval",
                    "2026-08-20T00:00:00Z",
                ),
            )
        return run_id, approval_id

    def bind_operation_to_draft_canary(self, operation_id):
        run_id, approval_id = self.install_canary(state="DRAFT", suffix="bound")
        event, _ = self.store.append_event(
            event_type="fixture_interaction",
            aggregate_type="opportunity",
            aggregate_id=self.opportunity["lf_opportunity_id"],
            producer="crm_graph_test",
            idempotency_key="fixture-interaction:bound",
            payload={"fixture": True},
        )
        interaction_id = "lf_interaction_graph_bound"
        member_id = "member-graph-bound"
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO interactions(
                       lf_interaction_id,lf_opportunity_id,source_event_id,dedupe_key,
                       channel,direction,classification,received_at_utc,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    interaction_id,
                    self.opportunity["lf_opportunity_id"],
                    event["event_id"],
                    "fixture-bound-operation",
                    "email",
                    "INBOUND",
                    "HUMAN_REPLY",
                    "2026-08-20T00:00:00Z",
                    "2026-08-20T00:00:00Z",
                ),
            )
            con.execute(
                """INSERT INTO canary_scope_members(
                       member_id,run_id,mailbox,campaign_id,contact_address,
                       canonical_outbound_thread,lf_opportunity_id,armed_by,
                       evidence_ref,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    member_id,
                    run_id,
                    "fixture@example.test",
                    "fixture-campaign",
                    "buyer@example.test",
                    "fixture-thread",
                    self.opportunity["lf_opportunity_id"],
                    "tester",
                    "evidence://scope",
                    "2026-08-20T00:00:00Z",
                ),
            )
            con.execute(
                """INSERT INTO canary_operation_bindings(
                       operation_id,run_id,member_id,approval_id,operation_type,
                       interaction_id,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    operation_id,
                    run_id,
                    member_id,
                    approval_id,
                    COMPANY_CREATE,
                    interaction_id,
                    "2026-08-20T00:00:00Z",
                ),
            )

    def test_stage_is_atomic_idempotent_and_has_exact_dependency_chain(self):
        first = self.stage()
        second = self.stage()
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(
            (
                first.company_operation_id,
                first.contact_operation_id,
                first.deal_operation_id,
                first.activity_operation_id,
            ),
            (
                second.company_operation_id,
                second.contact_operation_id,
                second.deal_operation_id,
                second.activity_operation_id,
            ),
        )
        self.assertEqual(len(self.rows()), 4)
        by_id = {row["operation_id"]: row for row in self.rows()}
        self.assertEqual(by_id[first.company_operation_id]["operation_type"], COMPANY_CREATE)
        self.assertEqual(by_id[first.company_operation_id]["dependency_operation_id"], "")
        self.assertEqual(
            by_id[first.contact_operation_id]["dependency_operation_id"],
            first.company_operation_id,
        )
        self.assertEqual(
            by_id[first.deal_operation_id]["dependency_operation_id"],
            first.contact_operation_id,
        )
        self.assertEqual(
            by_id[first.activity_operation_id]["dependency_operation_id"],
            first.deal_operation_id,
        )
        with self.assertRaises(IdempotencyConflict):
            self.stage(company_payload={"TITLE": "changed"})
        self.assertEqual(len(self.rows()), 4)

    def test_caller_owned_transaction_rollback_removes_graph_and_anchors(self):
        with self.assertRaisesRegex(RuntimeError, "rollback fixture"):
            with self.store.transaction() as con:
                plan = self.stage(_transaction=con)
                self.assertEqual(len(plan.created_operation_ids), 4)
                self.assertEqual(
                    con.execute("SELECT COUNT(*) FROM crm_outbox").fetchone()[0], 4
                )
                self.assertEqual(
                    con.execute(
                        "SELECT COUNT(*) FROM events WHERE producer='crm_graph_outbox'"
                    ).fetchone()[0],
                    4,
                )
                raise RuntimeError("rollback fixture")

        self.assertEqual(self.rows(), [])
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE producer='crm_graph_outbox'"
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

    def test_caller_owned_transaction_commits_one_exact_graph(self):
        with self.store.transaction() as con:
            plan = self.stage(_transaction=con)
            operation_ids = {
                str(row[0])
                for row in con.execute("SELECT operation_id FROM crm_outbox").fetchall()
            }
            anchor_ids = {
                str(row[0]).removeprefix("crm-graph-stage:")
                for row in con.execute(
                    """SELECT idempotency_key FROM events
                       WHERE producer='crm_graph_outbox'"""
                ).fetchall()
            }
            self.assertEqual(operation_ids, set(plan.created_operation_ids))
            self.assertEqual(anchor_ids, operation_ids)

        self.assertEqual(len(self.rows()), 4)
        self.assertEqual(self.store.table_count("events"), 4)

    def test_create_request_repr_is_fully_redacted(self):
        request = CrmGraphCreateRequest(
            operation_id="pii-operation@example.test",
            operation_type=DEAL_CREATE,
            remote_entity_type="deal",
            correlation_token="secret-correlation-token",
            payload={"EMAIL": "buyer@example.test", "PHONE": "+79990000000"},
            dependency_remote_ids=(("contact", "secret-remote-id"),),
        )

        self.assertEqual(repr(request), "<CrmGraphCreateRequest redacted>")

    def test_deal_and_activity_replay_require_same_causation_event(self):
        metadata = self.outbox._metadata(
            DEAL_CREATE,
            company_id=self.company["lf_company_id"],
            contact_id=self.contact["lf_contact_id"],
            project_id=self.project["lf_project_id"],
            opportunity_id=self.opportunity["lf_opportunity_id"],
        )
        cases = (
            (DEAL_CREATE, "dependency-contact", {"TITLE": "Facade opportunity"}),
            (ACTIVITY_CREATE, "dependency-deal", {"SUBJECT": "Review opportunity"}),
        )
        staged = {}
        for operation_type, dependency_id, payload in cases:
            with self.store.transaction() as con:
                operation_id, created = self.outbox._stage_operation_tx(
                    con,
                    operation_type=operation_type,
                    lf_entity_id=self.opportunity["lf_opportunity_id"],
                    dependency_operation_id=dependency_id,
                    external_event_id="source:fixture:original",
                    payload=payload,
                    metadata=metadata,
                )
            staged[operation_type] = operation_id
            self.assertTrue(created)

            with self.store.transaction() as con:
                replay_id, replay_created = self.outbox._stage_operation_tx(
                    con,
                    operation_type=operation_type,
                    lf_entity_id=self.opportunity["lf_opportunity_id"],
                    dependency_operation_id=dependency_id,
                    external_event_id="source:fixture:original",
                    payload=payload,
                    metadata=metadata,
                )
            self.assertEqual(replay_id, operation_id)
            self.assertFalse(replay_created)

            before = self.rows()
            before_events = self.store.table_count("events")
            with self.assertRaises(IdempotencyConflict):
                with self.store.transaction() as con:
                    self.outbox._stage_operation_tx(
                        con,
                        operation_type=operation_type,
                        lf_entity_id=self.opportunity["lf_opportunity_id"],
                        dependency_operation_id=dependency_id,
                        external_event_id="source:fixture:different",
                        payload=payload,
                        metadata=metadata,
                    )
            self.assertEqual(self.rows(), before)
            self.assertEqual(self.store.table_count("events"), before_events)

        self.assertEqual(set(staged), {DEAL_CREATE, ACTIVITY_CREATE})

    def test_company_and_contact_can_be_reused_by_new_graph_event(self):
        first = self.stage()
        second_project, _ = self.store.create_project(
            lf_company_id=self.company["lf_company_id"],
            source="fixture",
            external_key="project-2",
            title="Second facade",
        )
        second_opportunity, _ = self.store.create_opportunity(
            lf_company_id=self.company["lf_company_id"],
            lf_contact_id=self.contact["lf_contact_id"],
            lf_project_id=second_project["lf_project_id"],
            source="fixture",
            external_key="opportunity-2",
        )

        second = self.stage(
            project_id=second_project["lf_project_id"],
            opportunity_id=second_opportunity["lf_opportunity_id"],
            external_event_id="source:fixture:2",
            deal_payload={"TITLE": "Second facade opportunity"},
            activity_payload={"SUBJECT": "Review second opportunity"},
        )

        self.assertEqual(second.company_operation_id, first.company_operation_id)
        self.assertEqual(second.contact_operation_id, first.contact_operation_id)
        self.assertNotEqual(second.deal_operation_id, first.deal_operation_id)
        self.assertNotEqual(second.activity_operation_id, first.activity_operation_id)
        self.assertEqual(
            second.created_operation_ids,
            (second.deal_operation_id, second.activity_operation_id),
        )
        self.assertEqual(len(self.rows()), 6)

    def test_reserved_provider_relationship_fields_are_rejected_before_staging(self):
        cases = (
            {"contact_payload": {"company_id": "999"}},
            {"deal_payload": {"fields": {"CONTACT_ID": "999"}}},
            {"activity_payload": {"owner_id": "999"}},
            {"activity_payload": {"BINDINGS": [{"OWNER_ID": "999"}]}},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    self.stage(**overrides)
                self.assertEqual(self.rows(), [])

    def test_non_finite_json_numbers_are_rejected_at_stage_and_runtime(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.stage(deal_payload={"AMOUNT": {"value": value}})
                self.assertEqual(self.rows(), [])

        plan = self.stage()
        row = self.row(plan.company_operation_id)
        body = json.loads(row["payload_json"])
        body["TITLE"] = float("nan")
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET payload_json=?,payload_hash=?
                   WHERE operation_id=?""",
                (
                    canonical_json(body),
                    payload_hash(body),
                    plan.company_operation_id,
                ),
            )
        self.set_writers(True)
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="nonfinite-worker")
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(transport.create_calls, [])

    def test_payload_json_tamper_breaks_restage_and_is_quarantined_before_create(self):
        plan = self.stage()
        row = self.row(plan.company_operation_id)
        body = json.loads(row["payload_json"])
        body["TITLE"] = "ATTACKER CHANGED"
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET payload_json=? WHERE operation_id=?",
                (canonical_json(body), plan.company_operation_id),
            )
        with self.assertRaises(GraphInvariantError):
            self.stage()

        self.set_writers(True)
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="tamper-worker")
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "GraphInvariantError")
        self.assertEqual(transport.create_calls, [])
        self.assertEqual(self.row(plan.company_operation_id)["state"], "REVIEW")

    def test_coordinated_payload_and_hash_tamper_fails_immutable_stage_anchor(self):
        plan = self.stage()
        row = self.row(plan.company_operation_id)
        body = json.loads(row["payload_json"])
        body["TITLE"] = "ATTACKER CHANGED WITH NEW HASH"
        with self.store.transaction() as con:
            con.execute(
                """UPDATE crm_outbox SET payload_json=?,payload_hash=?
                   WHERE operation_id=?""",
                (
                    canonical_json(body),
                    payload_hash(body),
                    plan.company_operation_id,
                ),
            )
        with self.assertRaises(GraphInvariantError):
            self.stage()

        self.set_writers(True)
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="anchor-worker")
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "GraphInvariantError")
        self.assertEqual(transport.create_calls, [])
        self.assertEqual(self.row(plan.company_operation_id)["state"], "REVIEW")

    def test_append_only_stage_anchor_rejects_event_tamper(self):
        plan = self.stage()
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.transaction() as con:
                con.execute(
                    """UPDATE events SET payload_json='{}'
                       WHERE producer='crm_graph_outbox' AND idempotency_key=?""",
                    (f"crm-graph-stage:{plan.company_operation_id}",),
                )
        replay = self.stage()
        self.assertFalse(replay.created)

    def test_correlation_tamper_is_quarantined_before_create(self):
        plan = self.stage()
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET correlation_token='attacker-token' WHERE operation_id=?",
                (plan.company_operation_id,),
            )
        self.set_writers(True)
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="tamper-worker")
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(transport.create_calls, [])

    def test_dependency_tamper_is_quarantined_before_create(self):
        plan = self.stage()
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET dependency_operation_id=? WHERE operation_id=?",
                (plan.contact_operation_id, plan.company_operation_id),
            )
        self.set_writers(True)
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="tamper-worker")
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "GraphInvariantError")
        self.assertEqual(transport.create_calls, [])

    def test_cross_company_contact_project_graph_is_forbidden(self):
        other, _ = self.store.create_company(name="Other", inn="7701000002")
        other_contact, _ = self.store.create_contact(
            lf_company_id=other["lf_company_id"], email="other@example.test"
        )
        with self.assertRaises(GraphInvariantError):
            self.stage(contact_id=other_contact["lf_contact_id"])
        with self.store.transaction() as con:
            con.execute(
                "UPDATE projects SET lf_company_id=? WHERE lf_project_id=?",
                (other["lf_company_id"], self.project["lf_project_id"]),
            )
        with self.assertRaises(GraphInvariantError):
            self.stage()
        self.assertEqual(len(self.rows()), 0)

    def test_direct_lead_path_blocks_graph_staging(self):
        CrmOutbox(self.store).enqueue_lead_create(
            lf_entity_id=self.opportunity["lf_opportunity_id"],
            external_event_id="legacy-lead:1",
            payload={"TITLE": "Legacy lead"},
        )
        with self.assertRaises(IdempotencyConflict):
            self.stage()
        operations = self.rows()
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["operation_type"], "BITRIX_LEAD_CREATE")

    def test_writers_are_default_off_and_transport_is_not_called(self):
        plan = self.stage()
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(result.operation_id, plan.company_operation_id)
        self.assertEqual(transport.create_calls, [])
        self.assertEqual(self.row(plan.company_operation_id)["state"], "PENDING")

    def test_full_graph_executes_in_order_with_exact_readback_and_three_mappings(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        results = self.run_graph(transport)
        self.assertEqual([result.state for result in results], ["SENT"] * 4)
        self.assertEqual(
            [request.operation_type for request in transport.create_calls],
            [COMPANY_CREATE, CONTACT_CREATE, DEAL_CREATE, ACTIVITY_CREATE],
        )
        self.assertEqual(transport.create_calls[1].dependency_id("company"), "101")
        self.assertEqual(transport.create_calls[2].dependency_id("company"), "101")
        self.assertEqual(transport.create_calls[2].dependency_id("contact"), "201")
        self.assertEqual(transport.create_calls[3].dependency_id("deal"), "301")
        self.assertEqual(self.store.table_count("crm_mappings"), 3)
        activity = self.row(plan.activity_operation_id)
        self.assertEqual(activity["state"], "SENT")
        self.assertEqual(activity["remote_entity_type"], "activity")
        self.assertEqual(activity["remote_entity_id"], "401")

    def test_missing_exact_dependency_mapping_prevents_child_create(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        self.assertEqual(
            self.outbox.process_next(transport, worker_id="worker-a").state, "SENT"
        )
        with self.store.transaction() as con:
            con.execute(
                "DELETE FROM crm_mappings WHERE lf_entity_type='company' AND lf_entity_id=?",
                (self.company["lf_company_id"],),
            )
        result = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(result.state, "WAITING_DEPENDENCY")
        self.assertEqual(len(transport.create_calls), 1)
        self.assertEqual(self.row(plan.contact_operation_id)["state"], "PENDING")

    def test_stop_and_writer_gate_are_rechecked_immediately_before_create(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        stopped = self.outbox.process_next(
            transport,
            worker_id="worker-a",
            before_create_hook=lambda: None,
            stop_requested=lambda: True,
        )
        self.assertEqual(stopped.state, "STOPPED")
        self.assertEqual(transport.create_calls, [])
        self.assertEqual(self.row(plan.company_operation_id)["state"], "PENDING")

        def close_writer():
            self.set_writers(False)

        blocked = self.outbox.process_next(
            transport, worker_id="worker-b", before_create_hook=close_writer
        )
        self.assertEqual(blocked.state, "BLOCKED")
        self.assertEqual(transport.create_calls, [])
        self.assertEqual(self.row(plan.company_operation_id)["state"], "PENDING")

    def test_two_workers_cannot_claim_same_create(self):
        self.stage()
        self.set_writers(True)
        first = self.outbox.claim_next("worker-a")
        second = self.outbox.claim_next("worker-b")
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_explicit_retryable_and_permanent_failures_are_distinct(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        transport.create_error = RetryableRemoteError("429 rejected before create")
        retry = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(retry.state, "PENDING")
        self.assertTrue(self.row(plan.company_operation_id)["next_attempt_at_utc"])
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET next_attempt_at_utc='' WHERE operation_id=?",
                (plan.company_operation_id,),
            )
        transport.create_error = PermanentRemoteError("invalid required field")
        dead = self.outbox.process_next(transport, worker_id="worker-b")
        self.assertEqual(dead.state, "DEAD")

    def test_ambiguous_create_is_not_repeated_and_reconciles_by_exact_token(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        transport.create_error = TimeoutError("response lost")
        uncertain = self.outbox.process_next(transport, worker_id="worker-a")
        self.assertEqual(uncertain.state, "UNCERTAIN")
        self.assertEqual(len(transport.create_calls), 1)
        waiting = self.outbox.process_next(transport, worker_id="worker-b")
        self.assertEqual(waiting.state, "WAITING_DEPENDENCY")
        self.assertEqual(len(transport.create_calls), 1)

        company_row = self.row(plan.company_operation_id)
        request = transport.create_calls[0]
        transport.receipts[("company", company_row["correlation_token"])] = (
            transport.receipt_for(request, "109")
        )
        reconciled = self.outbox.reconcile_next(transport, worker_id="reconcile-a")
        self.assertEqual(reconciled.state, "SENT")
        self.assertEqual(reconciled.remote_entity_id, "109")
        self.assertEqual(len(transport.create_calls), 1)

    def test_reconcile_writer_off_after_uncertain_makes_no_external_lookup(self):
        plan, transport = self.make_company_uncertain()
        self.set_writers(False)
        result = self.outbox.reconcile_next(transport, worker_id="reconcile-off")
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(result.error_class, "ExternalWritersDisabled")
        self.assertEqual(transport.find_calls, [])
        persisted = self.row(plan.company_operation_id)
        self.assertEqual(persisted["state"], "UNCERTAIN")
        self.assertEqual(persisted["lease_token"], "")
        self.assertEqual(persisted["reconcile_count"], 0)

    def test_reconcile_approved_active_canary_blocks_generic_lookup(self):
        plan, transport = self.make_company_uncertain()
        self.install_canary(state="ACTIVE", suffix="reconcile-sealed")
        result = self.outbox.reconcile_next(transport, worker_id="generic-reconcile")
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(result.error_class, "ExternalWritersDisabled")
        self.assertEqual(transport.find_calls, [])
        persisted = self.row(plan.company_operation_id)
        self.assertEqual(persisted["state"], "UNCERTAIN")
        self.assertEqual(persisted["reconcile_count"], 0)

    def test_generic_reconciler_never_claims_or_mutates_bound_operation(self):
        plan, transport = self.make_company_uncertain()
        self.bind_operation_to_draft_canary(plan.company_operation_id)
        before = self.row(plan.company_operation_id)
        result = self.outbox.reconcile_next(transport, worker_id="generic-reconcile")
        self.assertIsNone(result)
        self.assertEqual(transport.find_calls, [])
        self.assertEqual(self.row(plan.company_operation_id), before)

    def test_reconcile_gate_closing_between_claim_and_find_blocks_lookup(self):
        plan, transport = self.make_company_uncertain()

        def close_gate():
            self.set_writers(False)

        result = self.outbox.reconcile_next(
            transport,
            worker_id="reconcile-race",
            before_find_hook=close_gate,
        )
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(result.error_class, "ExternalWritersDisabled")
        self.assertEqual(transport.find_calls, [])
        persisted = self.row(plan.company_operation_id)
        self.assertEqual(persisted["state"], "UNCERTAIN")
        self.assertEqual(persisted["lease_token"], "")
        self.assertEqual(persisted["reconcile_count"], 0)

    def test_repeated_reconcile_timeouts_hit_review_at_attempt_cap(self):
        plan, transport = self.make_company_uncertain()
        transport.find_error = TimeoutError("correlation lookup timed out")

        first = self.outbox.reconcile_next(transport, worker_id="reconcile-one")
        self.assertEqual(first.state, "UNCERTAIN")
        self.assertEqual(self.row(plan.company_operation_id)["reconcile_count"], 1)
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET next_attempt_at_utc='' WHERE operation_id=?",
                (plan.company_operation_id,),
            )

        second = self.outbox.reconcile_next(transport, worker_id="reconcile-two")
        self.assertEqual(second.state, "REVIEW")
        self.assertEqual(second.error_class, "TimeoutError")
        persisted = self.row(plan.company_operation_id)
        self.assertEqual(persisted["state"], "REVIEW")
        self.assertEqual(persisted["reconcile_count"], 2)
        self.assertEqual(len(transport.find_calls), 2)

    def test_uncertain_child_with_lost_parent_mapping_goes_to_review_without_lookup(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        self.assertEqual(
            self.outbox.process_next(transport, worker_id="create-company").state,
            "SENT",
        )
        transport.create_error = TimeoutError("contact response lost")
        self.assertEqual(
            self.outbox.process_next(transport, worker_id="create-contact").state,
            "UNCERTAIN",
        )
        with self.store.transaction() as con:
            con.execute(
                """DELETE FROM crm_mappings
                   WHERE lf_entity_type='company' AND lf_entity_id=?""",
                (self.company["lf_company_id"],),
            )

        result = self.outbox.reconcile_next(transport, worker_id="reconcile-contact")
        self.assertEqual(result.state, "REVIEW")
        self.assertEqual(result.error_class, "GraphInvariantError")
        self.assertEqual(transport.find_calls, [])
        persisted = self.row(plan.contact_operation_id)
        self.assertEqual(persisted["state"], "REVIEW")
        self.assertEqual(persisted["reconcile_count"], 0)

    def test_wrong_parent_readback_goes_to_conflict_review(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        self.assertEqual(
            self.outbox.process_next(transport, worker_id="worker-a").state, "SENT"
        )
        contact_row = self.row(plan.contact_operation_id)
        transport.receipt_override = CrmGraphReadback(
            remote_entity_type="contact",
            remote_id="299",
            correlation_token=contact_row["correlation_token"],
            readback_verified=True,
            company_remote_id="999",
        )
        conflict = self.outbox.process_next(transport, worker_id="worker-b")
        self.assertEqual(conflict.state, "CONFLICT_REVIEW")
        persisted = self.row(plan.contact_operation_id)
        self.assertEqual(persisted["suspect_remote_entity_type"], "contact")
        self.assertEqual(persisted["suspect_remote_entity_id"], "299")

    def test_readback_type_and_every_parent_slot_are_exact(self):
        plan = self.stage()
        operation = self.row(plan.company_operation_id)
        operation["_dependency_remote_ids"] = {}
        common = {
            "remote_id": "101",
            "correlation_token": operation["correlation_token"],
            "readback_verified": True,
        }
        receipts = {
            "normalized_type": CrmGraphReadback(
                remote_entity_type=" Company ",
                **common,
            ),
            "unused_parent": CrmGraphReadback(
                remote_entity_type="company",
                company_remote_id="999",
                **common,
            ),
        }

        for label, receipt in receipts.items():
            with self.subTest(label=label):
                with self.assertRaises(GraphReadbackMismatch):
                    self.outbox._verify_readback(operation, receipt)

    def test_active_approved_canary_blocks_unbound_generic_graph_worker(self):
        plan = self.stage()
        self.set_writers(True)
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO canary_runs(
                       run_id,connector,state,created_by,created_at_utc
                   ) VALUES(?,?,?,?,?)""",
                (
                    "run-sealed",
                    BITRIX_CANARY_CONNECTOR,
                    "ACTIVE",
                    "tester",
                    "2026-08-19T00:00:00Z",
                ),
            )
            con.execute(
                """INSERT INTO canary_approvals(
                       approval_id,run_id,approval_sequence,cumulative_cap,
                       approver,evidence_ref,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    "approval-sealed",
                    "run-sealed",
                    1,
                    1,
                    "tester",
                    "evidence://approval",
                    "2026-08-19T00:00:00Z",
                ),
            )
        transport = FakeGraphTransport()
        result = self.outbox.process_next(transport, worker_id="generic-worker")
        self.assertEqual(result.state, "BLOCKED")
        self.assertEqual(transport.create_calls, [])
        self.assertEqual(self.row(plan.company_operation_id)["state"], "PENDING")

    def test_activity_without_safe_correlation_lookup_goes_to_review(self):
        plan = self.stage()
        self.set_writers(True)
        transport = FakeGraphTransport()
        for _ in range(3):
            self.assertEqual(
                self.outbox.process_next(transport, worker_id="worker-a").state,
                "SENT",
            )
        transport.create_error = TimeoutError("activity response lost")
        self.assertEqual(
            self.outbox.process_next(transport, worker_id="worker-a").state,
            "UNCERTAIN",
        )
        transport.find_error = SafeReconciliationUnsupported(
            "provider has no immutable Activity correlation field"
        )
        review = self.outbox.reconcile_next(transport, worker_id="reconcile-a")
        self.assertEqual(review.state, "REVIEW")
        self.assertEqual(self.row(plan.activity_operation_id)["state"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
