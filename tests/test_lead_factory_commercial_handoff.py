import inspect
import json
import socket
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lead_factory.commercial_handoff import (
    CommercialHandoffInvariantError,
    CommercialOpportunityHandoff,
)
from lead_factory.commercial_spine import (
    CrmOutcomeType,
    NormalizedOpportunityIntake,
    OfflineCrmOutcomeIntake,
    OpportunityLifecycle,
    OpportunityState,
)
from lead_factory.crm_identity import CrmActorBindingRegistry
from lead_factory.ids import address_hash, utc_now
from lead_factory.store import FactoryStore


OBSERVED = "2026-08-17T09:00:00Z"
CLOCK = datetime(2026, 8, 18, 9, 1, tzinfo=timezone.utc)


class CommercialOpportunityHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "commercial-handoff.sqlite3"
        self.store = FactoryStore(self.db_path)
        self.store.init()
        self.responsible = CrmActorBindingRegistry(self.store).register_verified(
            connector="bitrix",
            local_actor="sales_operator",
            remote_actor_id="7001",
            evidence_ref="offline-fixture:bitrix-user-readback",
            verified_by="offline_test",
        )

    def tearDown(self):
        self.temp.cleanup()

    def ingest(
        self,
        suffix="one",
        *,
        inn="7700000001",
        domain="fixture.example",
        email="buyer@fixture.example",
        company_name="Fixture Company",
        contact_name="Fixture Buyer",
        route_human_reply=True,
    ):
        normalized = NormalizedOpportunityIntake(self.store).ingest(
            producer="fixture_source",
            external_key=f"project-{suffix}",
            idempotency_key=f"source-{suffix}",
            payload={"fixture_version": 1, "suffix": suffix},
            evidence_ref=f"evidence://source/{suffix}",
            observed_at_utc=OBSERVED,
            company_name=company_name,
            company_inn=inn,
            company_domain=domain,
            contact_name=contact_name,
            contact_email=email,
            contact_role="buyer",
            project_title=f"Fixture Project {suffix}",
            project_region="moscow",
            product_key="aluminium",
        )
        if route_human_reply:
            lifecycle = OpportunityLifecycle(self.store)
            for index, state in enumerate(
                (
                    OpportunityState.SCREENED,
                    OpportunityState.TARGET_ACCOUNT,
                    OpportunityState.SIGNAL_CONFIRMED,
                    OpportunityState.CONTACT_ALLOWED,
                    OpportunityState.HUMAN_REPLY,
                ),
                start=1,
            ):
                lifecycle.transition(
                    lf_opportunity_id=normalized.lf_opportunity_id,
                    to_state=state,
                    actor="offline_fixture",
                    evidence_ref=f"evidence://route/{suffix}/{state.value}",
                    idempotency_key=f"route:{suffix}:{state.value}",
                    occurred_at_utc=f"2026-08-18T09:00:{index:02d}Z",
                )
        return normalized

    def handoff(self, store=None, **kwargs):
        return CommercialOpportunityHandoff(
            store or self.store,
            assignee="sales_operator",
            clock=lambda: CLOCK,
            **kwargs,
        )

    def counts(self):
        with self.store.transaction(min_schema_version=14) as con:
            return {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("events", "interactions", "human_tasks", "crm_outbox")
            }

    def load_handoff(self, opportunity_id):
        with self.store.transaction(min_schema_version=14) as con:
            interaction = con.execute(
                "SELECT * FROM interactions WHERE lf_opportunity_id=?",
                (opportunity_id,),
            ).fetchone()
            task = con.execute(
                "SELECT * FROM human_tasks WHERE lf_opportunity_id=?",
                (opportunity_id,),
            ).fetchone()
            operations = con.execute(
                "SELECT * FROM crm_outbox ORDER BY operation_type",
            ).fetchall()
            writer_flag = str(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                ).fetchone()[0]
            )
            audit_payloads = [
                str(row[0])
                for row in con.execute(
                    """SELECT payload_json FROM events
                       WHERE producer='commercial_opportunity_handoff'
                       ORDER BY recorded_at_utc,event_id"""
                ).fetchall()
            ]
            return (
                dict(interaction) if interaction else None,
                dict(task) if task else None,
                [dict(row) for row in operations],
                writer_flag,
                audit_payloads,
            )

    def test_atomic_handoff_uses_only_canonical_graph_and_stages_two_operations(self):
        normalized = self.ingest()
        signature = inspect.signature(CommercialOpportunityHandoff.stage)
        self.assertEqual(tuple(signature.parameters), ("self", "lf_opportunity_id"))

        with patch.object(
            socket,
            "create_connection",
            side_effect=AssertionError("network boundary must remain unused"),
        ):
            result = self.handoff().stage(
                lf_opportunity_id=normalized.lf_opportunity_id
            )

        self.assertTrue(result.created)
        self.assertEqual(result.state, "STAGED")
        self.assertEqual(result.due_at_utc, "2026-08-18T09:30:05Z")
        interaction, task, operations, writer_flag, audits = self.load_handoff(
            normalized.lf_opportunity_id
        )
        self.assertIsNotNone(interaction)
        self.assertEqual(interaction["lf_interaction_id"], result.interaction_id)
        self.assertEqual(interaction["lf_contact_id"], normalized.lf_contact_id)
        self.assertEqual(interaction["classification"], "COMMERCIAL_HANDOFF")
        self.assertEqual(interaction["channel"], "SOURCE")
        self.assertEqual(interaction["direction"], "INBOUND")
        self.assertEqual(interaction["received_at_utc"], "2026-08-18T09:00:05Z")
        self.assertEqual(
            interaction["evidence_ref"], "evidence://route/one/HUMAN_REPLY"
        )
        with self.store.transaction(min_schema_version=14) as con:
            reply = con.execute(
                """SELECT tr.transition_id,ev.event_id
                   FROM opportunity_transitions tr
                   JOIN events ev
                     ON ev.producer='commercial_spine'
                    AND ev.idempotency_key='transition:' || tr.transition_id
                   WHERE tr.lf_opportunity_id=? AND tr.to_state='HUMAN_REPLY'""",
                (normalized.lf_opportunity_id,),
            ).fetchone()
        self.assertEqual(interaction["source_event_id"], reply["event_id"])
        self.assertEqual(interaction["thread_id"], f"transition:{reply['transition_id']}")

        self.assertIsNotNone(task)
        self.assertEqual(task["lf_task_id"], result.task_id)
        self.assertEqual(task["lf_interaction_id"], result.interaction_id)
        self.assertEqual(task["kind"], "COMMERCIAL_QUALIFICATION")
        self.assertEqual(task["status"], "OPEN")
        self.assertEqual(task["priority"], "A1")
        self.assertEqual(task["assigned_to"], "sales_operator")
        self.assertEqual(task["due_at_utc"], "2026-08-18T09:30:05Z")

        self.assertEqual(len(operations), 2)
        lead = next(
            row for row in operations if row["operation_type"] == "BITRIX_LEAD_CREATE"
        )
        activity = next(
            row
            for row in operations
            if row["operation_type"] == "BITRIX_ACTIVITY_CREATE"
        )
        self.assertEqual(lead["operation_id"], result.lead_operation_id)
        self.assertEqual(lead["lf_entity_id"], normalized.lf_opportunity_id)
        self.assertEqual(activity["operation_id"], result.activity_operation_id)
        self.assertEqual(activity["lf_entity_id"], result.interaction_id)
        self.assertEqual(activity["dependency_operation_id"], lead["operation_id"])
        self.assertEqual(activity["external_event_id"], lead["external_event_id"])
        self.assertEqual(lead["state"], "PENDING")
        self.assertEqual(activity["state"], "PENDING")

        lead_payload = json.loads(lead["payload_json"])
        activity_payload = json.loads(activity["payload_json"])
        self.assertEqual(lead_payload["title"], "Fixture Project one")
        self.assertEqual(lead_payload["company_title"], "Fixture Company")
        self.assertEqual(lead_payload["name"], "Fixture Buyer")
        self.assertEqual(
            lead_payload["email"],
            [{"VALUE": "buyer@fixture.example", "VALUE_TYPE": "WORK"}],
        )
        self.assertIn(normalized.lf_opportunity_id, lead_payload["comments"])
        self.assertIn(normalized.lf_project_id, lead_payload["comments"])
        self.assertIn(lead["external_event_id"], lead_payload["comments"])
        self.assertEqual(lead_payload["utm_source"], "fixture_source")
        self.assertTrue(lead_payload["_lf_correlation_token"].startswith("lf_evt_v1_"))
        self.assertEqual(activity_payload["deadline"], result.due_at_utc)
        self.assertEqual(activity_payload["responsible_id"], "7001")
        self.assertEqual(activity_payload["_lf_task_id"], result.task_id)
        self.assertIn(normalized.lf_opportunity_id, activity_payload["description"])
        self.assertEqual(writer_flag, "0")

        audit_text = "".join(audits)
        self.assertNotIn("buyer@fixture.example", audit_text)
        self.assertNotIn("Fixture Company", audit_text)
        audit_payloads = [json.loads(item) for item in audits]
        request = next(
            item for item in audit_payloads if "task_creation_slo_minutes" in item
        )
        self.assertEqual(request["task_creation_elapsed_seconds"], 55)
        self.assertTrue(request["task_creation_slo_met"])

    def test_duplicate_and_restart_return_the_same_objects(self):
        normalized = self.ingest()
        first = self.handoff().stage(
            lf_opportunity_id=normalized.lf_opportunity_id
        )
        before = self.counts()
        duplicate = self.handoff().stage(
            lf_opportunity_id=normalized.lf_opportunity_id
        )
        restarted = self.handoff(FactoryStore(self.db_path)).stage(
            lf_opportunity_id=normalized.lf_opportunity_id
        )

        self.assertTrue(first.created)
        self.assertFalse(duplicate.created)
        self.assertFalse(restarted.created)
        for replay in (duplicate, restarted):
            self.assertEqual(replay.interaction_id, first.interaction_id)
            self.assertEqual(replay.task_id, first.task_id)
            self.assertEqual(replay.lead_operation_id, first.lead_operation_id)
            self.assertEqual(replay.activity_operation_id, first.activity_operation_id)
            self.assertEqual(replay.due_at_utc, first.due_at_utc)
        self.assertEqual(self.counts(), before)

    def test_two_concurrent_stagers_commit_exactly_once(self):
        normalized = self.ingest()
        barrier = threading.Barrier(2)

        def stage_once():
            barrier.wait(timeout=5)
            return self.handoff(FactoryStore(self.db_path)).stage(
                lf_opportunity_id=normalized.lf_opportunity_id
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: stage_once(), range(2)))

        self.assertEqual(sorted(result.created for result in results), [False, True])
        self.assertEqual({result.interaction_id for result in results}, {results[0].interaction_id})
        self.assertEqual({result.task_id for result in results}, {results[0].task_id})
        self.assertEqual({result.lead_operation_id for result in results}, {results[0].lead_operation_id})
        self.assertEqual(
            {result.activity_operation_id for result in results},
            {results[0].activity_operation_id},
        )
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM interactions").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM human_tasks").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM crm_outbox").fetchone()[0], 2)

    def test_crash_rolls_back_every_handoff_write_and_restart_recovers(self):
        normalized = self.ingest()
        before = self.counts()

        def crash():
            raise RuntimeError("injected crash")

        with self.assertRaises(RuntimeError):
            self.handoff(after_stage_hook=crash).stage(
                lf_opportunity_id=normalized.lf_opportunity_id
            )
        self.assertEqual(self.counts(), before)

        recovered = self.handoff(FactoryStore(self.db_path)).stage(
            lf_opportunity_id=normalized.lf_opportunity_id
        )
        self.assertTrue(recovered.created)
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM interactions").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM human_tasks").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM crm_outbox").fetchone()[0], 2)

    def test_cross_company_contact_is_rejected_without_partial_writes(self):
        first = self.ingest("company-a")
        second = self.ingest(
            "company-b",
            inn="7700000002",
            domain="other.example",
            email="buyer@other.example",
            company_name="Other Company",
            contact_name="Other Buyer",
        )
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                "UPDATE opportunities SET lf_contact_id=? WHERE lf_opportunity_id=?",
                (second.lf_contact_id, first.lf_opportunity_id),
            )
        before = self.counts()

        with self.assertRaises(CommercialHandoffInvariantError) as caught:
            self.handoff().stage(
                lf_opportunity_id=first.lf_opportunity_id
            )
        self.assertNotIn("buyer@", str(caught.exception))
        self.assertNotIn("Other Company", str(caught.exception))
        self.assertEqual(self.counts(), before)

    def test_address_hash_drift_is_rejected_without_partial_writes(self):
        normalized = self.ingest()
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                "UPDATE contacts SET email=? WHERE lf_contact_id=?",
                ("changed@fixture.example", normalized.lf_contact_id),
            )
        before = self.counts()

        with self.assertRaises(CommercialHandoffInvariantError) as caught:
            self.handoff().stage(
                lf_opportunity_id=normalized.lf_opportunity_id
            )
        self.assertNotIn("changed@", str(caught.exception))
        self.assertEqual(self.counts(), before)

    def test_domain_only_probable_company_is_not_auto_handed_off(self):
        normalized = self.ingest(inn="", domain="probable.example")
        before = self.counts()
        with self.assertRaises(CommercialHandoffInvariantError):
            self.handoff().stage(
                lf_opportunity_id=normalized.lf_opportunity_id
            )
        self.assertEqual(self.counts(), before)

    def test_discovered_source_is_not_mislabeled_as_a1_or_sent_to_crm(self):
        normalized = self.ingest("unrouted", route_human_reply=False)
        before = self.counts()
        with self.assertRaisesRegex(
            CommercialHandoffInvariantError, "persisted human reply"
        ):
            self.handoff().stage(lf_opportunity_id=normalized.lf_opportunity_id)
        self.assertEqual(self.counts(), before)

    def test_control_character_email_and_revoked_responsible_fail_closed(self):
        malformed = self.ingest("malformed")
        injected = "buyer@fixture.example\r\nBcc:other@example.test"
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                "UPDATE contacts SET email=?,email_hash=? WHERE lf_contact_id=?",
                (injected, address_hash(injected), malformed.lf_contact_id),
            )
        with self.assertRaises(CommercialHandoffInvariantError):
            self.handoff().stage(lf_opportunity_id=malformed.lf_opportunity_id)

        safe = self.ingest("revoked")
        CrmActorBindingRegistry(self.store).revoke(
            self.responsible.binding_id,
            evidence_ref="offline-fixture:binding-revoked",
            actor="offline_test",
        )
        with self.assertRaisesRegex(
            CommercialHandoffInvariantError, "responsible binding"
        ):
            self.handoff().stage(lf_opportunity_id=safe.lf_opportunity_id)

    def test_synthetic_sent_lead_outcomes_prove_only_local_measured_funnel(self):
        normalized = self.ingest()
        handoff = self.handoff().stage(
            lf_opportunity_id=normalized.lf_opportunity_id
        )
        synthetic_lead_id = "900001"
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_id=?,updated_at_utc=?
                   WHERE operation_id=? AND operation_type='BITRIX_LEAD_CREATE'""",
                (synthetic_lead_id, OBSERVED, handoff.lead_operation_id),
            )
            con.execute(
                """INSERT INTO crm_mappings(
                       lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,
                       state,last_readback_at_utc,created_at_utc
                   ) VALUES('opportunity',?,'lead',?,'ACTIVE',?,?)""",
                (
                    normalized.lf_opportunity_id,
                    synthetic_lead_id,
                    OBSERVED,
                    utc_now(),
                ),
            )

        intake = OfflineCrmOutcomeIntake(self.store)
        outcomes = (
            CrmOutcomeType.QUALIFIED,
            CrmOutcomeType.READY_PACKAGE,
            CrmOutcomeType.ESTIMATE_ACCEPTED,
            CrmOutcomeType.ESTIMATE_DONE,
            CrmOutcomeType.PROPOSAL_SENT,
            CrmOutcomeType.WON,
        )
        for version, outcome in enumerate(outcomes, start=1):
            result = intake.ingest(
                remote_entity_type="lead",
                remote_entity_id=synthetic_lead_id,
                remote_version=version,
                event_type=outcome,
                payload={"synthetic": True, "version": version},
                evidence_ref=f"evidence://crm/{version}",
                received_at_utc=f"2026-08-18T09:{version + 9:02d}:00Z",
                actor="offline_fixture",
            )
            self.assertEqual(result.state, "PROCESSED")

        with self.store.transaction(min_schema_version=14) as con:
            opportunity = con.execute(
                "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                (normalized.lf_opportunity_id,),
            ).fetchone()
            sync = con.execute(
                """SELECT last_remote_version,lf_opportunity_id FROM crm_sync_state
                   WHERE remote_entity_type='lead' AND remote_entity_id=?""",
                (synthetic_lead_id,),
            ).fetchone()
            task = con.execute(
                "SELECT assigned_to,due_at_utc FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
            writer_flag = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]

        self.assertEqual(opportunity["status"], "WON")
        self.assertEqual(sync["last_remote_version"], 6)
        self.assertEqual(sync["lf_opportunity_id"], normalized.lf_opportunity_id)
        self.assertEqual(task["assigned_to"], "sales_operator")
        self.assertEqual(task["due_at_utc"], "2026-08-18T09:30:05Z")
        self.assertEqual(str(writer_flag), "0")


if __name__ == "__main__":
    unittest.main()
