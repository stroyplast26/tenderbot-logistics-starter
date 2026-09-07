import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory.commercial_spine import (
    CommercialSpineConflict,
    CommercialSpineValidationError,
    NormalizedOpportunityIntake,
    OfflineCrmOutcomeIntake,
    OpportunityLifecycle,
    OpportunityState,
    funnel_metrics,
)
from lead_factory.store import FactoryStore


OBSERVED = "2026-08-18T09:00:00Z"


class CommercialSpineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "commercial-spine.sqlite3")
        self.store.init()

    def tearDown(self):
        self.temp.cleanup()

    def count(self, table):
        with self.store.transaction(min_schema_version=14) as con:
            return int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def ingest(
        self,
        suffix,
        *,
        intake=None,
        inn="7700000001",
        domain="example.test",
        email="buyer@example.test",
        payload=None,
        transaction=None,
    ):
        return (intake or NormalizedOpportunityIntake(self.store)).ingest(
            producer="fixture_source",
            external_key=f"project-{suffix}",
            idempotency_key=f"source-{suffix}",
            payload=payload or {"source_version": 1, "suffix": suffix},
            evidence_ref=f"evidence://source/{suffix}",
            observed_at_utc=OBSERVED,
            company_name="Fixture Company",
            company_inn=inn,
            company_domain=domain,
            contact_name="Fixture Buyer",
            contact_email=email,
            contact_role="buyer",
            project_title=f"Fixture Project {suffix}",
            project_region="fixture-region",
            product_key="aluminium",
            _transaction=transaction,
        )

    def transition(
        self,
        lifecycle,
        opportunity_id,
        target,
        index,
        *,
        reason="",
        evidence="",
    ):
        return lifecycle.transition(
            lf_opportunity_id=opportunity_id,
            to_state=target,
            reason=reason,
            evidence_ref=evidence,
            actor="fixture-operator",
            idempotency_key=f"transition-{opportunity_id}-{index}",
            occurred_at_utc=f"2026-08-18T09:{index:02d}:00Z",
        )

    def map_crm(self, opportunity_id, *, remote_id="501", state="ACTIVE"):
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO crm_mappings(
                    lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,
                    state,last_readback_at_utc,created_at_utc
                ) VALUES('opportunity',?,'deal',?,?,?,?)""",
                (opportunity_id, remote_id, state, OBSERVED, OBSERVED),
            )

    def test_normalized_intake_is_idempotent_and_payload_conflict_is_safe(self):
        first = self.ingest("one")
        duplicate = self.ingest("one")

        self.assertTrue(first.created)
        self.assertFalse(duplicate.created)
        self.assertEqual(first.source_record_id, duplicate.source_record_id)
        self.assertEqual(first.lf_opportunity_id, duplicate.lf_opportunity_id)
        self.assertEqual(self.count("source_records"), 1)
        self.assertEqual(self.count("companies"), 1)
        self.assertEqual(self.count("contacts"), 1)
        self.assertEqual(self.count("projects"), 1)
        self.assertEqual(self.count("opportunities"), 1)
        self.assertEqual(self.count("opportunity_transitions"), 1)

        with self.assertRaises(CommercialSpineConflict) as caught:
            self.ingest("one", payload={"source_version": 2})
        self.assertNotIn("project-one", str(caught.exception))
        self.assertNotIn("buyer@", str(caught.exception))
        self.assertEqual(self.count("source_records"), 1)

        with self.assertRaises(CommercialSpineConflict):
            self.ingest("one", email="other@example.test")

        with self.store.transaction(min_schema_version=14) as con:
            payloads = [
                str(row[0])
                for row in con.execute(
                    "SELECT payload_json FROM events WHERE producer='commercial_spine'"
                ).fetchall()
            ]
        self.assertTrue(payloads)
        self.assertNotIn("buyer@example.test", "".join(payloads))
        self.assertNotIn("Fixture Company", "".join(payloads))

    def test_non_finite_payload_and_unicode_phone_fail_before_any_write(self):
        for index, payload in enumerate(
            ({"score": float("nan")}, {"score": float("inf")}, {"text": "\ud800"}),
            start=1,
        ):
            with self.subTest(payload_index=index):
                with self.assertRaisesRegex(
                    CommercialSpineValidationError, "canonical JSON"
                ):
                    self.ingest(f"invalid-payload-{index}", payload=payload)

        with self.assertRaisesRegex(
            CommercialSpineValidationError, "contact phone is invalid"
        ):
            NormalizedOpportunityIntake(self.store).ingest(
                producer="fixture_source",
                external_key="unicode-phone",
                idempotency_key="unicode-phone",
                payload={"source_version": 1},
                evidence_ref="evidence://source/unicode-phone",
                observed_at_utc=OBSERVED,
                company_name="Fixture Company",
                company_inn="7700000001",
                contact_email="buyer@example.test",
                contact_phone="８９９９１２３４５６７",
                project_title="Unicode phone fixture",
            )

        for table in (
            "source_records",
            "companies",
            "contacts",
            "projects",
            "opportunities",
            "opportunity_transitions",
        ):
            self.assertEqual(self.count(table), 0, table)

    def test_crash_after_source_record_rolls_back_the_whole_graph(self):
        def crash():
            raise RuntimeError("fixture crash")

        crashing = NormalizedOpportunityIntake(self.store, after_source_hook=crash)
        with self.assertRaises(RuntimeError):
            self.ingest("crash", intake=crashing)

        for table in (
            "source_records",
            "companies",
            "contacts",
            "projects",
            "opportunities",
            "opportunity_transitions",
        ):
            self.assertEqual(self.count(table), 0, table)

        retry = self.ingest("crash")
        self.assertTrue(retry.created)
        self.assertEqual(self.count("opportunities"), 1)

    def test_caller_owned_transaction_can_bind_review_and_graph_atomically(self):
        with self.assertRaisesRegex(RuntimeError, "bridge crash"):
            with self.store.transaction(min_schema_version=16) as con:
                created = self.ingest("outer-transaction", transaction=con)
                self.assertTrue(created.created)
                raise RuntimeError("bridge crash")

        for table in (
            "source_records",
            "companies",
            "contacts",
            "projects",
            "opportunities",
            "opportunity_transitions",
        ):
            self.assertEqual(self.count(table), 0, table)

        with self.store.transaction(min_schema_version=16) as con:
            retried = self.ingest("outer-transaction", transaction=con)
        self.assertTrue(retried.created)
        self.assertEqual(self.count("opportunities"), 1)

    def test_company_contact_project_links_never_cross_company_boundaries(self):
        first = self.ingest("company-a", inn="7700000001", email="shared@example.test")
        second = self.ingest("company-b", inn="7700000002", email="shared@example.test")

        self.assertNotEqual(first.lf_company_id, second.lf_company_id)
        self.assertNotEqual(first.lf_contact_id, second.lf_contact_id)
        with self.store.transaction(min_schema_version=14) as con:
            invalid = con.execute(
                """SELECT COUNT(*) FROM opportunities o
                   JOIN contacts c ON c.lf_contact_id=o.lf_contact_id
                   JOIN projects p ON p.lf_project_id=o.lf_project_id
                   WHERE o.lf_company_id<>c.lf_company_id
                      OR o.lf_company_id<>p.lf_company_id"""
            ).fetchone()[0]
        self.assertEqual(invalid, 0)

    def test_domain_only_companies_are_probable_and_never_auto_merged(self):
        first = self.ingest("domain-a", inn="", domain="same.example.test")
        second = self.ingest("domain-b", inn="", domain="same.example.test")

        self.assertNotEqual(first.lf_company_id, second.lf_company_id)
        with self.store.transaction(min_schema_version=14) as con:
            states = {
                str(row[0])
                for row in con.execute(
                    "SELECT identity_state FROM companies ORDER BY lf_company_id"
                ).fetchall()
            }
        self.assertEqual(states, {"PROBABLE"})

    def test_two_projects_of_one_company_are_two_opportunities(self):
        first = self.ingest("object-a")
        second = self.ingest("object-b")

        self.assertEqual(first.lf_company_id, second.lf_company_id)
        self.assertEqual(first.lf_contact_id, second.lf_contact_id)
        self.assertNotEqual(first.lf_project_id, second.lf_project_id)
        self.assertNotEqual(first.lf_opportunity_id, second.lf_opportunity_id)
        self.assertEqual(self.count("companies"), 1)
        self.assertEqual(self.count("projects"), 2)
        self.assertEqual(self.count("opportunities"), 2)

    def test_lifecycle_is_typed_idempotent_and_transition_log_is_append_only(self):
        opportunity = self.ingest("lifecycle")
        lifecycle = OpportunityLifecycle(self.store)
        screened = self.transition(
            lifecycle, opportunity.lf_opportunity_id, OpportunityState.SCREENED, 1
        )
        replay = self.transition(
            lifecycle, opportunity.lf_opportunity_id, OpportunityState.SCREENED, 1
        )
        self.assertTrue(screened.created)
        self.assertFalse(replay.created)
        self.assertEqual(screened.transition_id, replay.transition_id)

        self.transition(lifecycle, opportunity.lf_opportunity_id, OpportunityState.TARGET_ACCOUNT, 2)
        self.transition(
            lifecycle,
            opportunity.lf_opportunity_id,
            OpportunityState.SIGNAL_CONFIRMED,
            3,
            evidence="evidence://signal/3",
        )
        self.transition(
            lifecycle,
            opportunity.lf_opportunity_id,
            OpportunityState.DIMA_QUALIFICATION,
            4,
        )
        with self.assertRaises(CommercialSpineValidationError):
            self.transition(
                lifecycle, opportunity.lf_opportunity_id, OpportunityState.LOST, 5
            )

        lost = self.transition(
            lifecycle,
            opportunity.lf_opportunity_id,
            OpportunityState.LOST,
            6,
            reason="NO_CURRENT_NEED",
        )
        self.assertTrue(lost.created)
        with self.assertRaises(sqlite3.DatabaseError):
            with self.store.transaction(min_schema_version=14) as con:
                con.execute(
                    "UPDATE opportunity_transitions SET reason='changed' WHERE transition_id=?",
                    (lost.transition_id,),
                )

    def test_crm_outcome_duplicate_stale_and_same_version_conflict_are_safe(self):
        opportunity = self.ingest("crm")
        self.map_crm(opportunity.lf_opportunity_id)
        intake = OfflineCrmOutcomeIntake(self.store)

        first = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="501",
            remote_version=1,
            event_type="SCREENED",
            payload={"stage": "screened"},
            evidence_ref="evidence://crm/1",
            received_at_utc="2026-08-18T10:01:00Z",
            dedupe_key="crm-event-1",
        )
        exact_replay = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="501",
            remote_version=1,
            event_type="SCREENED",
            payload={"stage": "screened"},
            evidence_ref="evidence://crm/1",
            received_at_utc="2026-08-18T10:01:00Z",
            dedupe_key="crm-event-1",
        )
        duplicate = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="501",
            remote_version=1,
            event_type="SCREENED",
            payload={"stage": "screened"},
            evidence_ref="evidence://crm/1-copy",
            received_at_utc="2026-08-18T10:02:00Z",
            dedupe_key="crm-event-1-copy",
        )
        second = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="501",
            remote_version=2,
            event_type="TARGET_ACCOUNT",
            payload={"stage": "target"},
            evidence_ref="evidence://crm/2",
            received_at_utc="2026-08-18T10:03:00Z",
            dedupe_key="crm-event-2",
        )
        stale = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="501",
            remote_version=1,
            event_type="SCREENED",
            payload={"stage": "late-copy"},
            evidence_ref="evidence://crm/stale",
            received_at_utc="2026-08-18T10:04:00Z",
            dedupe_key="crm-event-stale",
        )
        conflict = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="501",
            remote_version=2,
            event_type="TARGET_ACCOUNT",
            payload={"stage": "different-payload"},
            evidence_ref="evidence://crm/conflict",
            received_at_utc="2026-08-18T10:05:00Z",
            dedupe_key="crm-event-conflict",
        )

        self.assertEqual(first.state, "PROCESSED")
        self.assertFalse(exact_replay.created)
        self.assertEqual(duplicate.state, "DUPLICATE")
        self.assertEqual(second.state, "PROCESSED")
        self.assertEqual(stale.state, "STALE")
        self.assertEqual(conflict.state, "REVIEW")
        self.assertEqual(conflict.error_code, "REMOTE_VERSION_PAYLOAD_CONFLICT")
        with self.store.transaction(min_schema_version=14) as con:
            current = con.execute(
                "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                (opportunity.lf_opportunity_id,),
            ).fetchone()[0]
            sync_version = con.execute(
                "SELECT last_remote_version FROM crm_sync_state WHERE remote_entity_id='501'"
            ).fetchone()[0]
        self.assertEqual(current, OpportunityState.TARGET_ACCOUNT.value)
        self.assertEqual(sync_version, 2)
        self.assertEqual(self.count("opportunity_transitions"), 3)

    def test_crm_outcome_requires_an_active_exact_opportunity_mapping(self):
        opportunity = self.ingest("crm-review")
        intake = OfflineCrmOutcomeIntake(self.store)
        review = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="missing",
            remote_version=1,
            event_type="SCREENED",
            payload={"stage": "screened"},
            evidence_ref="evidence://crm/unmapped",
            received_at_utc="2026-08-18T10:10:00Z",
        )
        self.assertEqual(review.state, "REVIEW")
        self.assertEqual(review.error_code, "ACTIVE_OPPORTUNITY_MAPPING_REQUIRED")
        with self.store.transaction(min_schema_version=14) as con:
            status = con.execute(
                "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                (opportunity.lf_opportunity_id,),
            ).fetchone()[0]
        self.assertEqual(status, OpportunityState.DISCOVERED.value)

    def test_reviewed_newer_crm_version_fences_older_outcome(self):
        opportunity = self.ingest("crm-watermark")
        self.map_crm(opportunity.lf_opportunity_id, remote_id="watermark")
        intake = OfflineCrmOutcomeIntake(self.store)

        reviewed = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="watermark",
            remote_version=4,
            event_type="WON",
            payload={"stage": "won-too-early"},
            evidence_ref="evidence://crm/watermark/4",
            received_at_utc="2026-08-18T10:11:00Z",
        )
        stale = intake.ingest(
            remote_entity_type="deal",
            remote_entity_id="watermark",
            remote_version=3,
            event_type="SCREENED",
            payload={"stage": "late-screened"},
            evidence_ref="evidence://crm/watermark/3",
            received_at_utc="2026-08-18T10:12:00Z",
        )

        self.assertEqual(reviewed.state, "REVIEW")
        self.assertEqual(reviewed.error_code, "CRM_OUTCOME_TRANSITION_REVIEW")
        self.assertEqual(stale.state, "STALE")
        with self.store.transaction(min_schema_version=14) as con:
            sync = con.execute(
                """SELECT last_remote_version FROM crm_sync_state
                   WHERE remote_entity_type='deal' AND remote_entity_id='watermark'"""
            ).fetchone()
            status = con.execute(
                "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                (opportunity.lf_opportunity_id,),
            ).fetchone()[0]
        self.assertEqual(int(sync[0]), 4)
        self.assertEqual(status, OpportunityState.DISCOVERED.value)

    def test_crm_crash_after_durable_inbox_insert_rolls_back_everything(self):
        opportunity = self.ingest("crm-crash")
        self.map_crm(opportunity.lf_opportunity_id, remote_id="777")

        def crash():
            raise RuntimeError("fixture crash")

        intake = OfflineCrmOutcomeIntake(self.store, after_inbox_hook=crash)
        with self.assertRaises(RuntimeError):
            intake.ingest(
                remote_entity_type="deal",
                remote_entity_id="777",
                remote_version=1,
                event_type="SCREENED",
                payload={"stage": "screened"},
                evidence_ref="evidence://crm/crash",
                received_at_utc="2026-08-18T10:20:00Z",
            )

        self.assertEqual(self.count("crm_inbox_events"), 0)
        self.assertEqual(self.count("crm_sync_state"), 0)
        self.assertEqual(self.count("opportunity_transitions"), 1)

    def test_funnel_metrics_count_distinct_opportunity_transitions(self):
        first = self.ingest("funnel-a")
        second = self.ingest("funnel-b")
        lifecycle = OpportunityLifecycle(self.store)
        for offset, opportunity in enumerate((first, second), start=1):
            oid = opportunity.lf_opportunity_id
            self.transition(lifecycle, oid, OpportunityState.SCREENED, offset * 10 + 1)
            self.transition(lifecycle, oid, OpportunityState.TARGET_ACCOUNT, offset * 10 + 2)
            self.transition(
                lifecycle,
                oid,
                OpportunityState.SIGNAL_CONFIRMED,
                offset * 10 + 3,
                evidence=f"evidence://signal/{offset}",
            )
            qualified = self.transition(
                lifecycle, oid, OpportunityState.DIMA_QUALIFICATION, offset * 10 + 4
            )
            replay = self.transition(
                lifecycle, oid, OpportunityState.DIMA_QUALIFICATION, offset * 10 + 4
            )
            self.assertEqual(qualified.transition_id, replay.transition_id)

        oid = first.lf_opportunity_id
        self.transition(
            lifecycle,
            oid,
            OpportunityState.READY_PACKAGE,
            31,
            evidence="evidence://package/1",
        )
        self.transition(lifecycle, oid, OpportunityState.ESTIMATE_ACCEPTED, 32)
        self.transition(lifecycle, oid, OpportunityState.ESTIMATE_DONE, 33)
        self.transition(
            lifecycle,
            oid,
            OpportunityState.PROPOSAL_SENT,
            34,
            evidence="evidence://proposal/1",
        )
        self.transition(
            lifecycle,
            oid,
            OpportunityState.WON,
            35,
            evidence="evidence://won/1",
        )

        metrics = funnel_metrics(self.store)
        self.assertEqual(metrics[OpportunityState.DISCOVERED.value], 2)
        self.assertEqual(metrics[OpportunityState.DIMA_QUALIFICATION.value], 2)
        self.assertEqual(metrics[OpportunityState.READY_PACKAGE.value], 1)
        self.assertEqual(metrics[OpportunityState.ESTIMATE_ACCEPTED.value], 1)
        self.assertEqual(metrics[OpportunityState.PROPOSAL_SENT.value], 1)
        self.assertEqual(metrics[OpportunityState.WON.value], 1)
        self.assertEqual(metrics[OpportunityState.LOST.value], 0)


if __name__ == "__main__":
    unittest.main()
