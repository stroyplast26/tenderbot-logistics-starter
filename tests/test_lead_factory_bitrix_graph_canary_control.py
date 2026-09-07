from __future__ import annotations

from dataclasses import replace
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory.bitrix_graph_canary_control import (
    BITRIX_GRAPH_CANARY_CONNECTOR,
    GRAPH_OPERATION_ORDER,
    BitrixGraphCanaryControl,
    GraphCanaryCredentialEvidence,
    GraphCanaryCutoverEvidence,
    GraphCanaryDispatchPermit,
    GraphCanaryEvidenceError,
    GraphCanaryExpansionCutoverEvidence,
    GraphCanaryMemberCutoverEvidence,
)
from lead_factory.canary_control import (
    CanaryCapacityExceeded,
    CanaryScopeMismatch,
    CanaryStaleLease,
)
from lead_factory.crm_graph_outbox import (
    ACTIVITY_CREATE,
    COMPANY_CREATE,
    CONTACT_CREATE,
    DEAL_CREATE,
    CrmGraphOutbox,
    CrmGraphReadback,
    GraphInvariantError,
)
from lead_factory.ids import payload_hash, utc_now
from lead_factory.store import FactoryStore


class BitrixGraphCanaryControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "schema17.sqlite3"
        self.store = FactoryStore(self.path)
        self.store.init()
        self.assertEqual(self.store.schema_version(), 17)
        self.control = BitrixGraphCanaryControl(self.store)
        self.company, _ = self.store.create_company(
            name="Fixture buyer", inn="7701000099"
        )
        self.contact, _ = self.store.create_contact(
            lf_company_id=self.company["lf_company_id"],
            email="buyer@example.test",
            name="Buyer",
        )
        self.project, _ = self.store.create_project(
            lf_company_id=self.company["lf_company_id"],
            source="fixture",
            external_key="graph-canary-project",
            title="Facade",
        )
        self.opportunity, _ = self.store.create_opportunity(
            lf_company_id=self.company["lf_company_id"],
            lf_contact_id=self.contact["lf_contact_id"],
            lf_project_id=self.project["lf_project_id"],
            source="fixture",
            external_key="graph-canary-opportunity",
        )
        self.plan = CrmGraphOutbox(self.store).stage_graph(
            company_id=self.company["lf_company_id"],
            contact_id=self.contact["lf_contact_id"],
            project_id=self.project["lf_project_id"],
            opportunity_id=self.opportunity["lf_opportunity_id"],
            external_event_id="fixture:graph-canary:1",
            company_payload={"TITLE": "Fixture buyer"},
            contact_payload={"NAME": "Buyer"},
            deal_payload={"TITLE": "Facade"},
            activity_payload={"SUBJECT": "Review", "DEADLINE": "2030-01-01T00:00:00Z"},
            mapping_manifest_hash="1" * 64,
            lf_source_id="fixture-source",
        )
        event, _ = self.store.append_event(
            event_type="graph_canary_fixture_interaction",
            aggregate_type="opportunity",
            aggregate_id=self.opportunity["lf_opportunity_id"],
            producer="graph_canary_test",
            idempotency_key="graph-canary-fixture-interaction",
            payload={"fixture": True},
        )
        self.interaction_id = "lf_interaction_graph_canary"
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                """INSERT INTO interactions(
                       lf_interaction_id,lf_opportunity_id,lf_contact_id,
                       source_event_id,dedupe_key,channel,direction,classification,
                       thread_id,address,received_at_utc,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    self.interaction_id,
                    self.opportunity["lf_opportunity_id"],
                    self.contact["lf_contact_id"],
                    event["event_id"],
                    "graph-canary-interaction",
                    "email",
                    "INBOUND",
                    "HUMAN_REPLY",
                    "<graph-canary@example.test>",
                    "buyer@example.test",
                    utc_now(),
                    utc_now(),
                ),
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @property
    def operation_ids(self) -> tuple[str, ...]:
        return (
            self.plan.company_operation_id,
            self.plan.contact_operation_id,
            self.plan.deal_operation_id,
            self.plan.activity_operation_id,
        )

    def writer_flag(self) -> str:
        con = self.store.connect()
        try:
            return str(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                ).fetchone()[0]
            )
        finally:
            con.close()

    def operation_states(self) -> tuple[str, ...]:
        con = self.store.connect()
        try:
            return tuple(
                str(
                    con.execute(
                        "SELECT state FROM crm_outbox WHERE operation_id=?", (item,)
                    ).fetchone()[0]
                )
                for item in self.operation_ids
            )
        finally:
            con.close()

    def prepare_bound(self) -> tuple[str, str, str]:
        run_id = self.control.create_run(created_by="owner", run_id="graph-run-1")
        approval_id = self.control.create_cap_one_approval(
            run_id,
            approver="owner",
            evidence_ref="evidence://owner/cap-1",
            approval_id="graph-approval-1",
        )
        member_id = self.control.arm_scope_member(
            run_id,
            mailbox="INBOX",
            campaign_id="wave-1",
            contact_address="buyer@example.test",
            canonical_thread="<graph-canary@example.test>",
            lf_opportunity_id=self.opportunity["lf_opportunity_id"],
            armed_by="owner",
            evidence_ref="evidence://owner/scope-1",
            member_id="graph-member-1",
        )
        self.assertTrue(
            self.control.bind_graph(
                run_id,
                member_id=member_id,
                interaction_id=self.interaction_id,
                operation_ids=self.operation_ids,
                actor="router",
            )
        )
        self.assertFalse(
            self.control.bind_graph(
                run_id,
                member_id=member_id,
                interaction_id=self.interaction_id,
                operation_ids=self.operation_ids,
                actor="router",
            )
        )
        return run_id, approval_id, member_id

    def payload_hashes(self) -> tuple[str, ...]:
        con = self.store.connect()
        try:
            return tuple(
                str(
                    con.execute(
                        "SELECT payload_hash FROM crm_outbox WHERE operation_id=?",
                        (item,),
                    ).fetchone()[0]
                )
                for item in self.operation_ids
            )
        finally:
            con.close()

    def evidence(
        self, run_id: str, approval_id: str, member_id: str
    ) -> GraphCanaryCutoverEvidence:
        credential = GraphCanaryCredentialEvidence.exact_crm_only(
            credential_fingerprint="bitrix-credential-v1:fixture",
            evidence_ref="evidence://credential/crm-only",
        )
        return GraphCanaryCutoverEvidence.seal(
            run_id=run_id,
            member_id=member_id,
            approval_id=approval_id,
            interaction_id=self.interaction_id,
            operation_ids=self.operation_ids,
            operation_payload_hashes=self.payload_hashes(),
            sealed_input_hashes=(
                ("mapping_manifest", "2" * 64),
                ("live_preflight", "3" * 64),
                ("deployment_input", "4" * 64),
            ),
            owner_approval_evidence_ref="evidence://owner/cap-1",
            cutover_evidence_ref="evidence://cutover/cap-1",
            credential=credential,
        )

    def activate(self):
        run_id, approval_id, member_id = self.prepare_bound()
        evidence = self.evidence(run_id, approval_id, member_id)
        self.assertTrue(self.control.activate_cutover(evidence, actor="owner"))
        return run_id, evidence

    @staticmethod
    def readback(permit, remote_id: str) -> CrmGraphReadback:
        dependencies = dict(permit.dependency_remote_ids)
        remote_type = {
            COMPANY_CREATE: "company",
            CONTACT_CREATE: "contact",
            DEAL_CREATE: "deal",
            ACTIVITY_CREATE: "activity",
        }[permit.operation_type]
        return CrmGraphReadback(
            remote_entity_type=remote_type,
            remote_id=remote_id,
            correlation_token=permit.correlation_token,
            readback_verified=True,
            company_remote_id=dependencies.get("company", ""),
            contact_remote_id=dependencies.get("contact", ""),
            deal_remote_id=dependencies.get("deal", ""),
        )

    def test_default_off_atomic_binding_cap_and_redacted_repr(self) -> None:
        self.assertEqual(self.writer_flag(), "0")
        run_id, approval_id, member_id = self.prepare_bound()
        self.assertEqual(self.writer_flag(), "0")
        con = self.store.connect()
        try:
            bindings = con.execute(
                """SELECT operation_type,interaction_id FROM canary_operation_bindings
                   WHERE run_id=? ORDER BY CASE operation_type
                       WHEN ? THEN 1 WHEN ? THEN 2 WHEN ? THEN 3 ELSE 4 END""",
                (run_id, *GRAPH_OPERATION_ORDER[:3]),
            ).fetchall()
            self.assertEqual(
                tuple(str(row["operation_type"]) for row in bindings),
                GRAPH_OPERATION_ORDER,
            )
            self.assertEqual(
                {str(row["interaction_id"]) for row in bindings},
                {self.interaction_id},
            )
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM events
                           WHERE producer='bitrix_graph_canary_control'
                             AND event_type='bitrix_graph_canary_graph_bound'"""
                    ).fetchone()[0]
                ),
                1,
            )
        finally:
            con.close()
        evidence = self.evidence(run_id, approval_id, member_id)
        self.assertEqual(repr(evidence), "<GraphCanaryCutoverEvidence redacted>")
        self.assertNotIn("buyer", repr(evidence))
        with self.assertRaises(CanaryCapacityExceeded):
            self.control.arm_scope_member(
                run_id,
                mailbox="other",
                campaign_id="other",
                contact_address="other@example.test",
                canonical_thread="<other@example.test>",
                lf_opportunity_id=self.opportunity["lf_opportunity_id"],
                armed_by="owner",
                evidence_ref="evidence://other",
            )

    def test_cutover_requires_sealed_exact_crm_only_evidence_and_replays(self) -> None:
        run_id, approval_id, member_id = self.prepare_bound()
        evidence = self.evidence(run_id, approval_id, member_id)
        tampered = replace(evidence, cutover_evidence_ref="evidence://tampered")
        with self.assertRaises(GraphCanaryEvidenceError):
            self.control.activate_cutover(tampered, actor="owner")
        broad = replace(
            evidence.credential,
            granted_scopes=("crm", "user"),
        )
        with self.assertRaises(GraphCanaryEvidenceError):
            self.control.activate_cutover(
                replace(evidence, credential=broad), actor="owner"
            )
        self.assertEqual(self.writer_flag(), "0")
        self.assertTrue(self.control.activate_cutover(evidence, actor="owner"))
        self.assertFalse(self.control.activate_cutover(evidence, actor="owner"))
        self.assertEqual(self.writer_flag(), "1")

    def test_restart_claims_exact_four_in_order_and_commits_readback(self) -> None:
        run_id, _ = self.activate()
        restarted = BitrixGraphCanaryControl(FactoryStore(self.path))
        lease = restarted.acquire_writer_lease(
            run_id, owner_id="graph-worker", lease_seconds=60
        )
        expected_dependencies = (
            (),
            (("company", "101"),),
            (("company", "101"), ("contact", "201")),
            (("company", "101"), ("contact", "201"), ("deal", "301")),
        )
        for index, (operation_type, remote_id) in enumerate(
            zip(GRAPH_OPERATION_ORDER, ("101", "201", "301", "401"), strict=True)
        ):
            permit = restarted.claim_next_graph_operation(lease)
            self.assertIsInstance(permit, GraphCanaryDispatchPermit)
            self.assertEqual(permit.operation_type, operation_type)
            self.assertEqual(permit.operation_id, self.operation_ids[index])
            self.assertEqual(permit.dependency_remote_ids, expected_dependencies[index])
            self.assertEqual(repr(permit), "<GraphCanaryDispatchPermit redacted>")
            with restarted.store.transaction(min_schema_version=17) as con:
                restarted.assert_dispatch_permit_tx(
                    con, permit, lease, operation_id=permit.operation_id
                )
            restarted.mark_sent(
                permit,
                lease,
                self.readback(permit, remote_id),
                actor="graph-worker",
            )
        self.assertEqual(self.operation_states(), ("SENT",) * 4)
        self.assertIsNone(restarted.claim_next_graph_operation(lease))

    def test_wrong_dependency_and_payload_tamper_fail_before_cutover(self) -> None:
        run_id = self.control.create_run(created_by="owner")
        self.control.create_cap_one_approval(
            run_id, approver="owner", evidence_ref="evidence://approval"
        )
        member_id = self.control.arm_scope_member(
            run_id,
            mailbox="INBOX",
            campaign_id="wave-1",
            contact_address="buyer@example.test",
            canonical_thread="<graph-canary@example.test>",
            lf_opportunity_id=self.opportunity["lf_opportunity_id"],
            armed_by="owner",
            evidence_ref="evidence://scope",
        )
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                """UPDATE crm_outbox SET dependency_operation_id=?
                   WHERE operation_id=?""",
                (self.plan.deal_operation_id, self.plan.contact_operation_id),
            )
        with self.assertRaises(GraphInvariantError):
            self.control.bind_graph(
                run_id,
                member_id=member_id,
                interaction_id=self.interaction_id,
                operation_ids=self.operation_ids,
                actor="router",
            )
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                """UPDATE crm_outbox SET dependency_operation_id=?
                   WHERE operation_id=?""",
                (self.plan.company_operation_id, self.plan.contact_operation_id),
            )
            con.execute(
                "UPDATE crm_outbox SET payload_json='{}' WHERE operation_id=?",
                (self.plan.company_operation_id,),
            )
        with self.assertRaises(GraphInvariantError):
            self.control.bind_graph(
                run_id,
                member_id=member_id,
                interaction_id=self.interaction_id,
                operation_ids=self.operation_ids,
                actor="router",
            )

    def test_second_scope_insert_fails_closed(self) -> None:
        run_id, approval_id, member_id = self.prepare_bound()
        evidence = self.evidence(run_id, approval_id, member_id)
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                """INSERT INTO canary_scope_members(
                       member_id,run_id,mailbox,campaign_id,contact_address,
                       canonical_outbound_thread,lf_opportunity_id,armed_by,
                       evidence_ref,state,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "attacker-member",
                    run_id,
                    "other",
                    "other",
                    "other@example.test",
                    "<other@example.test>",
                    self.opportunity["lf_opportunity_id"],
                    "attacker",
                    "evidence://attacker",
                    "ARMED",
                    utc_now(),
                ),
            )
        with self.assertRaises(CanaryScopeMismatch):
            self.control.activate_cutover(evidence, actor="owner")

    def test_sealed_payload_hash_tamper_and_unrelated_work_fail_closed(self) -> None:
        run_id, approval_id, member_id = self.prepare_bound()
        evidence = self.evidence(run_id, approval_id, member_id)
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                "UPDATE crm_outbox SET payload_hash=? WHERE operation_id=?",
                ("f" * 64, self.plan.company_operation_id),
            )
        with self.assertRaises(GraphInvariantError):
            self.control.activate_cutover(evidence, actor="owner")

        self.tearDown()
        self.setUp()
        run_id, approval_id, member_id = self.prepare_bound()
        evidence = self.evidence(run_id, approval_id, member_id)
        now = utc_now()
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                """INSERT INTO crm_outbox(
                       operation_id,operation_type,lf_entity_type,lf_entity_id,
                       external_event_id,correlation_token,idempotency_key,
                       payload_json,payload_hash,state,created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "unrelated-operation",
                    "UNRELATED_CRM_WRITE",
                    "opportunity",
                    self.opportunity["lf_opportunity_id"],
                    "unrelated-event",
                    "unrelated-correlation",
                    "unrelated-idempotency",
                    "{}",
                    "0" * 64,
                    "PENDING",
                    now,
                    now,
                ),
            )
        with self.assertRaises(CanaryCapacityExceeded):
            self.control.activate_cutover(evidence, actor="owner")

    def test_stale_lease_and_stop_leave_ambiguous_binding_durable(self) -> None:
        run_id, _ = self.activate()
        old = self.control.acquire_writer_lease(
            run_id, owner_id="worker", lease_seconds=60
        )
        current = self.control.acquire_writer_lease(
            run_id, owner_id="worker", lease_seconds=60
        )
        with self.assertRaises(CanaryStaleLease):
            self.control.claim_next_graph_operation(old)
        permit = self.control.claim_next_graph_operation(current)
        self.assertIsNotNone(permit)
        self.assertTrue(
            self.control.stop_run(
                run_id,
                actor="owner",
                reason="operator stop",
                evidence_ref="evidence://stop",
            )
        )
        self.assertEqual(self.writer_flag(), "0")
        self.assertEqual(self.operation_states()[0], "UNCERTAIN")
        con = self.store.connect()
        try:
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM canary_operation_bindings
                           WHERE run_id=?""",
                        (run_id,),
                    ).fetchone()[0]
                ),
                4,
            )
            with self.assertRaises(CanaryStaleLease):
                self.control.assert_dispatch_permit_tx(
                    con, permit, current, operation_id=permit.operation_id
                )
        finally:
            con.close()

    def test_uncertain_and_review_are_durable_and_never_recreated(self) -> None:
        run_id, _ = self.activate()
        lease = self.control.acquire_writer_lease(
            run_id, owner_id="worker", lease_seconds=60
        )
        permit = self.control.claim_next_graph_operation(lease)
        self.control.mark_uncertain(
            permit, lease, error_class="AmbiguousRemoteError", actor="worker"
        )
        self.assertEqual(self.operation_states()[0], "UNCERTAIN")
        self.assertIsNone(self.control.claim_next_graph_operation(lease))

        # A fresh fixture proves the separate REVIEW terminal transition.
        self.tearDown()
        self.setUp()
        run_id, _ = self.activate()
        lease = self.control.acquire_writer_lease(
            run_id, owner_id="worker", lease_seconds=60
        )
        permit = self.control.claim_next_graph_operation(lease)
        self.control.mark_review(
            permit, lease, error_class="GraphReadbackMismatch", actor="worker"
        )
        self.assertEqual(self.operation_states()[0], "REVIEW")
        self.assertIsNone(self.control.claim_next_graph_operation(lease))

    def test_connector_isolated_from_legacy_canary_lane(self) -> None:
        run_id, _ = self.activate()
        con = self.store.connect()
        try:
            connector = con.execute(
                "SELECT connector FROM canary_runs WHERE run_id=?", (run_id,)
            ).fetchone()[0]
            self.assertEqual(connector, BITRIX_GRAPH_CANARY_CONNECTOR)
        finally:
            con.close()


class BitrixGraphCanaryExpansionTests(BitrixGraphCanaryControlTests):
    def add_graph(self, suffix: int) -> dict[str, object]:
        company, _ = self.store.create_company(
            name=f"Expansion buyer {suffix}", inn=f"77020000{suffix:02d}"
        )
        contact, _ = self.store.create_contact(
            lf_company_id=company["lf_company_id"],
            email=f"buyer{suffix}@example.test",
            name=f"Buyer {suffix}",
        )
        project, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"],
            source="fixture",
            external_key=f"expansion-project-{suffix}",
            title=f"Expansion {suffix}",
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            lf_contact_id=contact["lf_contact_id"],
            lf_project_id=project["lf_project_id"],
            source="fixture",
            external_key=f"expansion-opportunity-{suffix}",
        )
        plan = CrmGraphOutbox(self.store).stage_graph(
            company_id=company["lf_company_id"],
            contact_id=contact["lf_contact_id"],
            project_id=project["lf_project_id"],
            opportunity_id=opportunity["lf_opportunity_id"],
            external_event_id=f"fixture:expansion:{suffix}",
            company_payload={"TITLE": f"Expansion buyer {suffix}"},
            contact_payload={"NAME": f"Buyer {suffix}"},
            deal_payload={"TITLE": f"Expansion {suffix}"},
            activity_payload={
                "SUBJECT": f"Review {suffix}",
                "DEADLINE": "2030-01-01T00:00:00Z",
            },
            mapping_manifest_hash="1" * 64,
            lf_source_id="fixture-source",
        )
        event, _ = self.store.append_event(
            event_type="graph_canary_expansion_interaction",
            aggregate_type="opportunity",
            aggregate_id=opportunity["lf_opportunity_id"],
            producer="graph_canary_expansion_test",
            idempotency_key=f"graph-canary-expansion-interaction:{suffix}",
            payload={"suffix": suffix},
        )
        interaction_id = f"lf_interaction_graph_expansion_{suffix}"
        thread = f"<graph-expansion-{suffix}@example.test>"
        address = f"buyer{suffix}@example.test"
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                """INSERT INTO interactions(
                       lf_interaction_id,lf_opportunity_id,lf_contact_id,
                       source_event_id,dedupe_key,channel,direction,classification,
                       thread_id,address,received_at_utc,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    interaction_id,
                    opportunity["lf_opportunity_id"],
                    contact["lf_contact_id"],
                    event["event_id"],
                    f"graph-canary-expansion:{suffix}",
                    "email",
                    "INBOUND",
                    "HUMAN_REPLY",
                    thread,
                    address,
                    utc_now(),
                    utc_now(),
                ),
            )
        ids = (
            plan.company_operation_id,
            plan.contact_operation_id,
            plan.deal_operation_id,
            plan.activity_operation_id,
        )
        con = self.store.connect()
        try:
            hashes = tuple(
                str(
                    con.execute(
                        "SELECT payload_hash FROM crm_outbox WHERE operation_id=?",
                        (operation_id,),
                    ).fetchone()[0]
                )
                for operation_id in ids
            )
        finally:
            con.close()
        return {
            "opportunity_id": opportunity["lf_opportunity_id"],
            "interaction_id": interaction_id,
            "thread": thread,
            "address": address,
            "operation_ids": ids,
            "payload_hashes": hashes,
        }

    def completed_cap_one(self) -> tuple[str, str]:
        run_id, _ = self.activate()
        lease = self.control.acquire_writer_lease(
            run_id, owner_id="cap-one-worker", lease_seconds=60
        )
        for remote_id in ("101", "201", "301", "401"):
            permit = self.control.claim_next_graph_operation(lease)
            self.control.mark_sent(
                permit,
                lease,
                self.readback(permit, remote_id),
                actor="cap-one-worker",
            )
        self.control.stop_run(
            run_id,
            actor="owner",
            reason="cap-one completed",
            evidence_ref="evidence://stop/cap-one-completed",
        )
        checkpoint = self.control.record_cap_one_completion_checkpoint(
            run_id,
            actor="owner",
            evidence_ref="evidence://checkpoint/cap-one-completed",
        )
        return run_id, checkpoint

    def prepare_expansion(
        self, member_count: int = 4, *, member_ids: tuple[str, ...] = ()
    ):
        original_run, checkpoint = self.completed_cap_one()
        expansion_run, approval_id = self.control.create_cap_five_expansion(
            run_id=original_run,
            checkpoint_event_id=checkpoint,
            approver="owner",
            approval_evidence_ref="evidence://owner/cap-5",
            approval_id="graph-expansion-approval",
        )
        graphs = []
        members = []
        for suffix in range(2, 2 + member_count):
            graph = self.add_graph(suffix)
            member_id = self.control.arm_scope_member(
                expansion_run,
                mailbox="INBOX",
                campaign_id="wave-1",
                contact_address=graph["address"],
                canonical_thread=graph["thread"],
                lf_opportunity_id=graph["opportunity_id"],
                armed_by="owner",
                evidence_ref=f"evidence://scope/{suffix}",
                member_id=(
                    member_ids[suffix - 2]
                    if member_ids
                    else f"graph-expansion-member-{suffix}"
                ),
            )
            self.control.bind_graph(
                expansion_run,
                member_id=member_id,
                interaction_id=graph["interaction_id"],
                operation_ids=graph["operation_ids"],
                actor="router",
            )
            graphs.append(graph)
            members.append(member_id)
        return original_run, checkpoint, expansion_run, approval_id, graphs, members

    def expansion_evidence(
        self,
        checkpoint: str,
        expansion_run: str,
        approval_id: str,
        graphs: list[dict[str, object]],
        members: list[str],
    ) -> GraphCanaryExpansionCutoverEvidence:
        inputs = (
            ("mapping_manifest", "2" * 64),
            ("live_preflight", "3" * 64),
            ("deployment_input", "4" * 64),
        )
        member_evidence = tuple(
            GraphCanaryMemberCutoverEvidence.seal(
                member_id=member_id,
                interaction_id=graph["interaction_id"],
                operation_ids=graph["operation_ids"],
                operation_payload_hashes=graph["payload_hashes"],
                dependency_operation_ids=(
                    "",
                    graph["operation_ids"][0],
                    graph["operation_ids"][1],
                    graph["operation_ids"][2],
                ),
                sealed_input_hashes=(
                    *inputs,
                    ("expansion_cohort", "5" * 64),
                    (
                        f"expansion_candidate_{ordinal}",
                        f"{ordinal + 4:x}" * 64,
                    ),
                ),
            )
            for ordinal, (graph, member_id) in enumerate(
                zip(graphs, members, strict=True), start=2
            )
        )
        return GraphCanaryExpansionCutoverEvidence.seal(
            run_id=expansion_run,
            approval_id=approval_id,
            checkpoint_event_id=checkpoint,
            members=member_evidence,
            cutover_evidence_ref="evidence://cutover/cap-5",
            credential_isolation_evidence_ref="evidence://credential/isolation/cap-5",
            credential=GraphCanaryCredentialEvidence.exact_crm_only(
                credential_fingerprint="bitrix-credential-v2:isolated-expansion",
                evidence_ref="evidence://credential/isolated-crm-only",
                owner_accepted_existing_credential=False,
            ),
        )

    def test_cap_one_to_five_expansion_claims_four_exact_graphs(self) -> None:
        (
            _,
            checkpoint,
            expansion_run,
            approval_id,
            graphs,
            members,
        ) = self.prepare_expansion()
        evidence = self.expansion_evidence(
            checkpoint, expansion_run, approval_id, graphs, members
        )
        self.assertTrue(
            self.control.activate_expansion_cutover(evidence, actor="owner")
        )
        con = self.store.connect()
        try:
            event = con.execute(
                """SELECT payload_json FROM events
                   WHERE producer='bitrix_graph_canary_control'
                     AND idempotency_key=?""",
                (f"graph-canary-expansion-cutover:{expansion_run}",),
            ).fetchone()
            payload = json.loads(str(event[0]))
            self.assertEqual(payload["expansion_cohort_hash"], "5" * 64)
            predecessor_hash = payload_hash(
                {
                    "credential_fingerprint": "bitrix-credential-v1:fixture",
                    "granted_scopes": ["crm"],
                    "owner_accepted_existing_credential": True,
                    "evidence_ref": "evidence://credential/crm-only",
                }
            )
            expansion_hash = payload_hash(
                {
                    "credential_fingerprint": (
                        "bitrix-credential-v2:isolated-expansion"
                    ),
                    "granted_scopes": ["crm"],
                    "owner_accepted_existing_credential": False,
                    "evidence_ref": "evidence://credential/isolated-crm-only",
                }
            )
            self.assertEqual(
                payload["predecessor_credential_evidence_hash"], predecessor_hash
            )
            self.assertEqual(
                payload["expansion_credential_evidence_hash"], expansion_hash
            )
            self.assertNotEqual(predecessor_hash, expansion_hash)
            self.assertEqual(
                [item["candidate_name"] for item in payload["expansion_candidates"]],
                [f"expansion_candidate_{ordinal}" for ordinal in range(2, 6)],
            )
            self.assertEqual(
                [item["member_id"] for item in payload["expansion_candidates"]],
                members,
            )
        finally:
            con.close()
        restarted = BitrixGraphCanaryControl(FactoryStore(self.path))
        lease = restarted.acquire_writer_lease(
            expansion_run, owner_id="expansion-worker", lease_seconds=60
        )
        claimed = []
        next_remote = 1000
        for _ in range(16):
            permit = restarted.claim_next_graph_operation(lease)
            self.assertIsNotNone(permit)
            claimed.append((permit.member_id, permit.operation_type))
            next_remote += 1
            restarted.mark_sent(
                permit,
                lease,
                self.readback(permit, str(next_remote)),
                actor="expansion-worker",
            )
        self.assertIsNone(restarted.claim_next_graph_operation(lease))
        self.assertEqual(
            claimed,
            [
                (member, operation_type)
                for member in members
                for operation_type in GRAPH_OPERATION_ORDER
            ],
        )

    def test_expansion_order_is_sealed_not_timestamp_or_member_id_order(self) -> None:
        custom_member_ids = (
            "graph-expansion-member-z",
            "graph-expansion-member-a",
            "graph-expansion-member-y",
            "graph-expansion-member-b",
        )
        (
            _,
            checkpoint,
            expansion_run,
            approval_id,
            graphs,
            members,
        ) = self.prepare_expansion(member_ids=custom_member_ids)
        self.assertEqual(tuple(members), custom_member_ids)
        evidence = self.expansion_evidence(
            checkpoint, expansion_run, approval_id, graphs, members
        )
        self.assertTrue(
            self.control.activate_expansion_cutover(evidence, actor="owner")
        )
        lease = self.control.acquire_writer_lease(
            expansion_run, owner_id="ordered-worker", lease_seconds=60
        )
        claimed_members = []
        for index in range(16):
            permit = self.control.claim_next_graph_operation(lease)
            self.assertIsNotNone(permit)
            claimed_members.append(permit.member_id)
            self.control.mark_sent(
                permit,
                lease,
                self.readback(permit, str(5000 + index)),
                actor="ordered-worker",
            )
        self.assertEqual(
            claimed_members,
            [member for member in custom_member_ids for _ in GRAPH_OPERATION_ORDER],
        )

    def test_expansion_requires_completed_stopped_cap_one(self) -> None:
        run_id, _ = self.activate()
        with self.assertRaises(CanaryScopeMismatch):
            self.control.record_cap_one_completion_checkpoint(
                run_id,
                actor="owner",
                evidence_ref="evidence://checkpoint/too-early",
            )

    def test_expansion_cap_replay_tamper_and_stop_fail_closed(self) -> None:
        (
            _,
            checkpoint,
            expansion_run,
            approval_id,
            graphs,
            members,
        ) = self.prepare_expansion(member_count=1)
        evidence = self.expansion_evidence(
            checkpoint, expansion_run, approval_id, graphs, members
        )
        original_member = evidence.members[0]
        tampered_member = GraphCanaryMemberCutoverEvidence.seal(
            member_id=original_member.member_id,
            interaction_id=original_member.interaction_id,
            operation_ids=original_member.operation_ids,
            operation_payload_hashes=original_member.operation_payload_hashes,
            dependency_operation_ids=original_member.dependency_operation_ids,
            sealed_input_hashes=(("mapping_manifest", "9" * 64),),
        )
        tampered = GraphCanaryExpansionCutoverEvidence.seal(
            run_id=evidence.run_id,
            approval_id=evidence.approval_id,
            checkpoint_event_id=evidence.checkpoint_event_id,
            members=(tampered_member,),
            cutover_evidence_ref=evidence.cutover_evidence_ref,
            credential_isolation_evidence_ref=(
                evidence.credential_isolation_evidence_ref
            ),
            credential=evidence.credential,
        )
        with self.assertRaises(GraphCanaryEvidenceError):
            self.control.activate_expansion_cutover(tampered, actor="owner")
        self.assertTrue(
            self.control.activate_expansion_cutover(evidence, actor="owner")
        )
        self.assertFalse(
            self.control.activate_expansion_cutover(evidence, actor="owner")
        )
        lease = self.control.acquire_writer_lease(
            expansion_run, owner_id="worker", lease_seconds=60
        )
        permit = self.control.claim_next_graph_operation(lease)
        self.control.stop_run(
            expansion_run,
            actor="owner",
            reason="expansion stop",
            evidence_ref="evidence://stop/expansion",
        )
        self.assertFalse(
            self.control.stop_run(
                expansion_run,
                actor="owner",
                reason="expansion stop",
                evidence_ref="evidence://stop/expansion",
            )
        )
        with self.store.transaction(min_schema_version=17) as con:
            with self.assertRaises(CanaryStaleLease):
                self.control.assert_dispatch_permit_tx(
                    con, permit, lease, operation_id=permit.operation_id
                )
        self.assertEqual(self.writer_flag(), "0")

    def test_expansion_is_same_run_with_separate_immutable_approval(self) -> None:
        (
            original_run,
            checkpoint,
            expansion_run,
            approval_id,
            _,
            _,
        ) = self.prepare_expansion(member_count=1)
        self.assertEqual(expansion_run, original_run)
        con = self.store.connect()
        try:
            approvals = con.execute(
                """SELECT approval_id,approval_sequence,cumulative_cap,
                          checkpoint_event_id FROM canary_approvals
                   WHERE run_id=? ORDER BY approval_sequence""",
                (original_run,),
            ).fetchall()
            self.assertEqual(
                [
                    (
                        str(row["approval_id"]),
                        int(row["approval_sequence"]),
                        int(row["cumulative_cap"]),
                        str(row["checkpoint_event_id"]),
                    )
                    for row in approvals
                ],
                [
                    ("graph-approval-1", 1, 1, ""),
                    (approval_id, 2, 5, checkpoint),
                ],
            )
        finally:
            con.close()
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.transaction(min_schema_version=17) as con:
                con.execute(
                    "UPDATE canary_approvals SET cumulative_cap=6 WHERE approval_id=?",
                    (approval_id,),
                )

    def test_checkpoint_rejects_nonpositive_completed_receipt(self) -> None:
        run_id, _ = self.activate()
        lease = self.control.acquire_writer_lease(
            run_id, owner_id="checkpoint-worker", lease_seconds=60
        )
        for remote_id in ("101", "201", "301", "401"):
            permit = self.control.claim_next_graph_operation(lease)
            self.control.mark_sent(
                permit,
                lease,
                self.readback(permit, remote_id),
                actor="checkpoint-worker",
            )
        self.control.stop_run(
            run_id,
            actor="owner",
            reason="cap-one completed",
            evidence_ref="evidence://stop/cap-one-completed",
        )
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                "UPDATE crm_outbox SET remote_entity_id='0' WHERE operation_id=?",
                (self.plan.activity_operation_id,),
            )
        with self.assertRaises(CanaryScopeMismatch):
            self.control.record_cap_one_completion_checkpoint(
                run_id,
                actor="owner",
                evidence_ref="evidence://checkpoint/nonpositive",
            )

    def test_expansion_cannot_arm_more_than_four_additional_members(self) -> None:
        _, _, expansion_run, _, _, _ = self.prepare_expansion(member_count=4)
        fifth = self.add_graph(9)
        with self.assertRaises(CanaryCapacityExceeded):
            self.control.arm_scope_member(
                expansion_run,
                mailbox="INBOX",
                campaign_id="wave-1",
                contact_address=fifth["address"],
                canonical_thread=fifth["thread"],
                lf_opportunity_id=fifth["opportunity_id"],
                armed_by="owner",
                evidence_ref="evidence://scope/fifth",
            )

    def test_expansion_input_contract_rejects_all_composition_tamper(self) -> None:
        (
            _,
            checkpoint,
            expansion_run,
            approval_id,
            graphs,
            members,
        ) = self.prepare_expansion(member_count=2)
        valid = self.expansion_evidence(
            checkpoint, expansion_run, approval_id, graphs, members
        )

        def reseal_member(index: int, inputs):
            member = valid.members[index]
            return GraphCanaryMemberCutoverEvidence.seal(
                member_id=member.member_id,
                interaction_id=member.interaction_id,
                operation_ids=member.operation_ids,
                operation_payload_hashes=member.operation_payload_hashes,
                dependency_operation_ids=member.dependency_operation_ids,
                sealed_input_hashes=inputs,
            )

        def reseal_expansion(member_values):
            return GraphCanaryExpansionCutoverEvidence.seal(
                run_id=valid.run_id,
                approval_id=valid.approval_id,
                checkpoint_event_id=valid.checkpoint_event_id,
                members=member_values,
                cutover_evidence_ref=valid.cutover_evidence_ref,
                credential_isolation_evidence_ref=(
                    valid.credential_isolation_evidence_ref
                ),
                credential=valid.credential,
            )

        first = dict(valid.members[0].sealed_input_hashes)
        second = dict(valid.members[1].sealed_input_hashes)
        cases = {}

        changed_baseline = dict(first)
        changed_baseline["mapping_manifest"] = "9" * 64
        cases["changed baseline"] = reseal_expansion(
            (reseal_member(0, changed_baseline.items()), valid.members[1])
        )

        missing_cohort = dict(first)
        missing_cohort.pop("expansion_cohort")
        cases["missing cohort"] = reseal_expansion(
            (reseal_member(0, missing_cohort.items()), valid.members[1])
        )

        extra_input = dict(first)
        extra_input["expansion_unrecognized"] = "a" * 64
        cases["unrecognized expansion input"] = reseal_expansion(
            (reseal_member(0, extra_input.items()), valid.members[1])
        )

        changed_cohort = dict(second)
        changed_cohort["expansion_cohort"] = "b" * 64
        cases["mismatched cohort"] = reseal_expansion(
            (valid.members[0], reseal_member(1, changed_cohort.items()))
        )

        swapped_first = dict(first)
        swapped_second = dict(second)
        first_hash = swapped_first.pop("expansion_candidate_2")
        second_hash = swapped_second.pop("expansion_candidate_3")
        swapped_first["expansion_candidate_3"] = first_hash
        swapped_second["expansion_candidate_2"] = second_hash
        cases["swapped candidates"] = reseal_expansion(
            (
                reseal_member(0, swapped_first.items()),
                reseal_member(1, swapped_second.items()),
            )
        )

        duplicate_first = dict(first)
        duplicate_second = dict(second)
        duplicate_second["expansion_candidate_3"] = duplicate_first[
            "expansion_candidate_2"
        ]
        cases["duplicate candidate hash"] = reseal_expansion(
            (
                reseal_member(0, duplicate_first.items()),
                reseal_member(1, duplicate_second.items()),
            )
        )

        forged_member = replace(valid.members[0], seal_hash="0" * 64)
        cases["member seal tamper"] = reseal_expansion(
            (forged_member, valid.members[1])
        )

        for label, evidence in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(GraphCanaryEvidenceError):
                    self.control.activate_expansion_cutover(evidence, actor="owner")

    def test_expansion_rejects_old_shared_credential_exception(self) -> None:
        (
            _,
            checkpoint,
            expansion_run,
            approval_id,
            graphs,
            members,
        ) = self.prepare_expansion(member_count=1)
        valid = self.expansion_evidence(
            checkpoint, expansion_run, approval_id, graphs, members
        )
        old_shared = GraphCanaryCredentialEvidence.exact_crm_only(
            credential_fingerprint="bitrix-credential-v1:fixture",
            evidence_ref="evidence://credential/crm-only",
            owner_accepted_existing_credential=True,
        )
        old_evidence = GraphCanaryExpansionCutoverEvidence.seal(
            run_id=valid.run_id,
            approval_id=valid.approval_id,
            checkpoint_event_id=valid.checkpoint_event_id,
            members=valid.members,
            cutover_evidence_ref=valid.cutover_evidence_ref,
            credential_isolation_evidence_ref=(
                valid.credential_isolation_evidence_ref
            ),
            credential=old_shared,
        )
        with self.assertRaises(GraphCanaryEvidenceError):
            self.control.activate_expansion_cutover(old_evidence, actor="owner")

    def test_expansion_rejects_predecessor_credential_evidence_hash(self) -> None:
        (
            _,
            checkpoint,
            expansion_run,
            approval_id,
            graphs,
            members,
        ) = self.prepare_expansion(member_count=1)
        valid = self.expansion_evidence(
            checkpoint, expansion_run, approval_id, graphs, members
        )
        predecessor = GraphCanaryCredentialEvidence.exact_crm_only(
            credential_fingerprint="bitrix-credential-v1:fixture",
            evidence_ref="evidence://credential/crm-only",
        )
        predecessor_hash = payload_hash(
            {
                "credential_fingerprint": predecessor.credential_fingerprint,
                "granted_scopes": list(predecessor.granted_scopes),
                "owner_accepted_existing_credential": True,
                "evidence_ref": predecessor.evidence_ref,
            }
        )
        con = self.store.connect()
        try:
            checkpoint_payload = json.loads(
                str(
                    con.execute(
                        "SELECT payload_json FROM events WHERE event_id=?",
                        (checkpoint,),
                    ).fetchone()[0]
                )
            )
        finally:
            con.close()
        self.assertEqual(
            checkpoint_payload["credential_evidence_hash"], predecessor_hash
        )
        same_hash_evidence = GraphCanaryExpansionCutoverEvidence.seal(
            run_id=valid.run_id,
            approval_id=valid.approval_id,
            checkpoint_event_id=valid.checkpoint_event_id,
            members=valid.members,
            cutover_evidence_ref=valid.cutover_evidence_ref,
            credential_isolation_evidence_ref=(
                valid.credential_isolation_evidence_ref
            ),
            credential=predecessor,
        )
        with self.assertRaisesRegex(
            GraphCanaryEvidenceError,
            "isolated exact crm-only|must differ",
        ):
            self.control.activate_expansion_cutover(
                same_hash_evidence, actor="owner"
            )

    def test_stopped_exact_readback_reconciliation_can_resume_same_graph(self) -> None:
        run_id, evidence = self.activate()
        lease = self.control.acquire_writer_lease(
            run_id, owner_id="recovery-worker", lease_seconds=300
        )
        company = self.control.claim_next_graph_operation(lease)
        self.control.mark_sent(
            company, lease, self.readback(company, "101"), actor="recovery-worker"
        )
        contact = self.control.claim_next_graph_operation(lease)
        self.control.mark_review(
            contact,
            lease,
            error_class="BitrixGraphProviderConflict",
            actor="recovery-worker",
        )
        self.control.stop_run(
            run_id,
            actor="owner",
            reason="provider_shape_review",
            evidence_ref="evidence://stop/provider-shape",
        )
        self.control.reconcile_stopped_operation(
            run_id,
            operation_id=contact.operation_id,
            readback=self.readback(contact, "202"),
            actor="reviewer",
            evidence_ref="evidence://read-only/contact-202",
        )
        self.assertEqual(
            self.operation_states(), ("SENT", "SENT", "PENDING", "PENDING")
        )
        self.control.resume_stopped_run(
            evidence,
            actor="owner",
            recovery_approval_ref="evidence://owner/recover-same-cap1",
        )
        self.assertEqual(self.writer_flag(), "1")
        renewed = self.control.acquire_writer_lease(
            run_id, owner_id="recovery-worker", lease_seconds=300
        )
        deal = self.control.claim_next_graph_operation(renewed)
        self.assertEqual(deal.operation_type, DEAL_CREATE)


if __name__ == "__main__":
    unittest.main()
