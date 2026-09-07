from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from lead_factory.commercial_spine import (
    NormalizedOpportunityIntake,
    OpportunityLifecycle,
    OpportunityState,
)
from lead_factory.conversation_routing import ConversationRouter
from lead_factory.delivery_metrics import (
    DeliveryEventError,
    DeliveryEventTracker,
    delivery_metrics,
)
from lead_factory.mail_registry import MailRegistry
from lead_factory.multimail_policy import (
    MultiMailSendGate,
    MultiMailSendIntent,
)
from lead_factory.store import FactoryStore, IdempotencyConflict


CLOCK = "2026-08-18T09:00:00Z"
OCCURRED = "2020-01-01T00:00:00Z"
ACTOR = "offline-delivery-test"
EVIDENCE = "evidence://offline/delivery-test"


class DeliveryMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = FactoryStore(Path(self.temp.name) / "delivery-metrics.sqlite3")
        self.store.init()
        self.registry = MailRegistry(self.store)
        self.router = ConversationRouter(self.store)
        self.gate = MultiMailSendGate(self.store, clock=lambda: CLOCK)

        normalized = NormalizedOpportunityIntake(self.store).ingest(
            producer="delivery_fixture",
            external_key="project-one",
            idempotency_key="source-one",
            payload={"source_version": 1},
            evidence_ref="evidence://offline/source-one",
            observed_at_utc="2026-08-18T08:00:00Z",
            company_name="Delivery Fixture",
            company_inn="7700000001",
            company_domain="buyer.example.test",
            contact_name="Fixture Buyer",
            contact_email="buyer@buyer.example.test",
            contact_role="buyer",
            project_title="Fixture Project",
            product_key="aluminium",
        )
        self.opportunity_id = normalized.lf_opportunity_id
        self.contact_id = normalized.lf_contact_id
        self.company_id = normalized.lf_company_id
        self.contact_address = "buyer@buyer.example.test"
        self.base_graph = {
            "opportunity_id": self.opportunity_id,
            "contact_id": self.contact_id,
            "company_id": self.company_id,
            "contact_address": self.contact_address,
        }
        self.graph_serial = 1
        lifecycle = OpportunityLifecycle(self.store)
        for index, (state, evidence) in enumerate(
            (
                (OpportunityState.SCREENED, ""),
                (OpportunityState.TARGET_ACCOUNT, ""),
                (OpportunityState.SIGNAL_CONFIRMED, "evidence://offline/signal"),
                (OpportunityState.CONTACT_ALLOWED, "evidence://offline/contact-allowed"),
            ),
            start=1,
        ):
            lifecycle.transition(
                lf_opportunity_id=self.opportunity_id,
                to_state=state,
                evidence_ref=evidence,
                actor=ACTOR,
                idempotency_key=f"lifecycle-{index}",
                occurred_at_utc=f"2026-08-18T08:{index:02d}:00Z",
            )

        provider = self.registry.register_provider_account(
            provider_type="OFFLINE",
            label="offline delivery fixture",
            daily_send_cap=50,
            provider_account_id="provider_primary",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.provider_id = provider.entity_id
        self.registry.activate_provider_account(
            self.provider_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        domain = self.registry.register_sending_domain(
            provider_account_id=self.provider_id,
            domain="send.example.test",
            daily_send_cap=50,
            reputation_state="VERIFIED",
            sending_domain_id="domain_primary",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.domain_id = domain.entity_id
        self.registry.activate_sending_domain(
            self.domain_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        mailbox = self.registry.register_mailbox_account(
            provider_account_id=self.provider_id,
            sending_domain_id=self.domain_id,
            address="sales@send.example.test",
            daily_send_cap=50,
            mailbox_account_id="mailbox_primary",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.mailbox_id = mailbox.entity_id
        self.registry.activate_mailbox_account(
            self.mailbox_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        sender = self.registry.register_sender_identity(
            provider_account_id=self.provider_id,
            sending_domain_id=self.domain_id,
            mailbox_account_id=self.mailbox_id,
            from_address="sales@send.example.test",
            reply_to_address="sales@send.example.test",
            daily_send_cap=50,
            reputation_state="VERIFIED",
            sender_identity_id="sender_primary",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.sender_id = sender.entity_id
        self.registry.activate_sender_identity(
            self.sender_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.primary = self._create_scope("campaign_primary", graph=self.base_graph)

    def _create_scope(
        self,
        campaign_id,
        *,
        graph,
        register_campaign=True,
        scope_suffix="",
    ):
        if register_campaign:
            self.registry.register_campaign(
                campaign_id=campaign_id,
                daily_send_cap=50,
                lifetime_send_cap=50,
                actor=ACTOR,
                evidence_ref=EVIDENCE,
            )
            self.registry.activate_campaign(
                campaign_id, actor=ACTOR, evidence_ref=EVIDENCE
            )
        suffix = scope_suffix or campaign_id
        conversation_id = self.router.pin_conversation(
            lf_opportunity_id=graph["opportunity_id"],
            lf_contact_id=graph["contact_id"],
            sender_identity_id=self.sender_id,
            mailbox_account_id=self.mailbox_id,
            campaign_id=campaign_id,
            peer_address=graph["contact_address"],
            actor=ACTOR,
            evidence_ref=EVIDENCE,
            conversation_id=f"conversation_{suffix}",
        ).conversation_id
        authorization_id = self.gate.create_authorization(
            conversation_id=conversation_id,
            segment_id="segment_fixture",
            cohort_id="cohort_fixture",
            content_version="content_v1",
            first_touch_cap=40,
            followup_cap=40,
            lifetime_first_touch_cap=40,
            lifetime_followup_cap=40,
            valid_from_utc="2026-08-17T00:00:00Z",
            valid_until_utc="2026-08-19T23:59:59Z",
            legal_status="APPROVED",
            legal_evidence_ref="evidence://offline/legal",
            suppression_snapshot_id="suppression_snapshot_fixture",
            approver=ACTOR,
            authorization_id=f"authorization_{suffix}",
        )
        return {
            "campaign_id": campaign_id,
            "conversation_id": conversation_id,
            "authorization_id": authorization_id,
            "provider_account_id": self.provider_id,
            "sending_domain_id": self.domain_id,
            "mailbox_account_id": self.mailbox_id,
            "sender_identity_id": self.sender_id,
            "opportunity_id": graph["opportunity_id"],
            "contact_id": graph["contact_id"],
            "company_id": graph["company_id"],
            "contact_address": graph["contact_address"],
        }

    def _additional_scope(self, suffix, *, campaign_id="campaign_primary"):
        self.graph_serial += 1
        serial = self.graph_serial
        address = f"buyer-{serial}@buyer.example.test"
        normalized = NormalizedOpportunityIntake(self.store).ingest(
            producer="delivery_fixture",
            external_key=f"project-{suffix}",
            idempotency_key=f"source-{suffix}",
            payload={"source_version": 1, "suffix": suffix},
            evidence_ref=f"evidence://offline/source-{suffix}",
            observed_at_utc="2026-08-18T08:10:00Z",
            company_name=f"Delivery Fixture {serial}",
            company_inn=str(7700000000 + serial),
            company_domain=f"buyer-{serial}.example.test",
            contact_name=f"Fixture Buyer {serial}",
            contact_email=address,
            contact_role="buyer",
            project_title=f"Fixture Project {serial}",
            product_key="aluminium",
        )
        lifecycle = OpportunityLifecycle(self.store)
        for index, (state, evidence) in enumerate(
            (
                (OpportunityState.SCREENED, ""),
                (OpportunityState.TARGET_ACCOUNT, ""),
                (OpportunityState.SIGNAL_CONFIRMED, f"evidence://offline/signal-{suffix}"),
                (OpportunityState.CONTACT_ALLOWED, f"evidence://offline/contact-{suffix}"),
            ),
            start=1,
        ):
            lifecycle.transition(
                lf_opportunity_id=normalized.lf_opportunity_id,
                to_state=state,
                evidence_ref=evidence,
                actor=ACTOR,
                idempotency_key=f"lifecycle-{suffix}-{index}",
                occurred_at_utc=f"2026-08-18T08:{10 + index:02d}:00Z",
            )
        graph = {
            "opportunity_id": normalized.lf_opportunity_id,
            "contact_id": normalized.lf_contact_id,
            "company_id": normalized.lf_company_id,
            "contact_address": address,
        }
        return self._create_scope(
            campaign_id,
            graph=graph,
            register_campaign=campaign_id != "campaign_primary",
            scope_suffix=suffix,
        )

    def _intent(self, scope, message_id):
        return MultiMailSendIntent(
            message_id=message_id,
            authorization_id=scope["authorization_id"],
            conversation_id=scope["conversation_id"],
            address=scope["contact_address"],
            segment_id="segment_fixture",
            cohort_id="cohort_fixture",
            content_version="content_v1",
            touch_type="FIRST_TOUCH",
        )

    def _payload(self, scope):
        return {
            "to_address": scope["contact_address"],
            "sender_identity_id": scope["sender_identity_id"],
            "mailbox_account_id": scope["mailbox_account_id"],
            "conversation_id": scope["conversation_id"],
            "provider_account_id": scope["provider_account_id"],
            "sending_domain_id": scope["sending_domain_id"],
            "campaign_id": scope["campaign_id"],
            "authorization_id": scope["authorization_id"],
            "content_version": "content_v1",
            "template_id": "offline_fixture",
        }

    def _stage(self, message_id, scope=None):
        scope = scope or self.primary
        intent = self._intent(scope, message_id)
        payload = self._payload(scope)
        permit = self.gate.issue_permit(intent)
        self.assertTrue(permit.allowed)
        self.assertTrue(permit.created)
        staged = self.gate.stage_command(
            intent,
            permit.permit_id,
            payload_ref=f"payload://{message_id}",
            payload=payload,
        )
        self.assertTrue(staged.allowed)
        self.assertTrue(staged.created)
        with self.store.transaction(min_schema_version=14) as con:
            command_id = str(
                con.execute(
                    "SELECT command_id FROM outbox WHERE message_id=?",
                    (message_id,),
                ).fetchone()[0]
            )
        return {
            "scope": scope,
            "intent": intent,
            "payload": payload,
            "payload_ref": f"payload://{message_id}",
            "permit_id": permit.permit_id,
            "command_id": command_id,
            "message_id": message_id,
        }

    @contextmanager
    def _writers_enabled(self):
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_writers_enabled'"
            )
        try:
            yield
        finally:
            with self.store.transaction(min_schema_version=14) as con:
                con.execute(
                    "UPDATE schema_meta SET value='0' "
                    "WHERE key='external_writers_enabled'"
                )

    def _authorize_dispatch(self, staged):
        decision = self.gate.authorize_dispatch(
            staged["intent"],
            staged["command_id"],
            payload_ref=staged["payload_ref"],
            payload=staged["payload"],
        )
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.created)

    def _send(self, staged, *, provider_message_id=None, rfc_message_id=None):
        provider_message_id = provider_message_id or f"provider-{staged['message_id']}"
        rfc_message_id = rfc_message_id or f"<{staged['message_id']}@send.example.test>"
        with self._writers_enabled():
            self._authorize_dispatch(staged)
            created = self.gate.record_sent(
                staged["command_id"],
                provider_message_id=provider_message_id,
                rfc_message_id=rfc_message_id,
                actor=ACTOR,
                evidence_ref=EVIDENCE,
            )
        self.assertTrue(created)
        staged["provider_message_id"] = provider_message_id
        staged["rfc_message_id"] = rfc_message_id
        return staged

    def _record(self, sent, event_key, event_type, *, payload=None, tracker=None):
        return (tracker or DeliveryEventTracker(self.store)).record_event(
            provider_account_id=sent["scope"]["provider_account_id"],
            provider_message_id=sent["provider_message_id"],
            provider_event_key=event_key,
            event_type=event_type,
            payload=payload or {"kind": event_type, "fixture": True},
            evidence_ref=f"evidence://offline/provider/{event_key}",
            occurred_at_utc=OCCURRED,
            actor=ACTOR,
        )

    def _count(self, table, where="", values=()):
        with self.store.transaction(min_schema_version=14) as con:
            return int(
                con.execute(
                    f"SELECT COUNT(*) FROM {table} {where}",
                    values,
                ).fetchone()[0]
            )

    def test_delivery_event_requires_exact_sent_command_and_provider_scope(self):
        unsent = self._stage("message-unsent")
        tracker = DeliveryEventTracker(self.store)
        with self.assertRaises(DeliveryEventError):
            tracker.record_event(
                provider_account_id=self.provider_id,
                provider_message_id="provider-message-unsent",
                provider_event_key="event-unsent",
                event_type="DELIVERED",
                payload={"kind": "DELIVERED"},
                evidence_ref=EVIDENCE,
                occurred_at_utc=OCCURRED,
            )

        sent = self._send(unsent, provider_message_id="provider-message-unsent")
        result = self._record(sent, "event-exact", "DELIVERED")

        self.assertTrue(result.created)
        self.assertEqual(result.command_id, sent["command_id"])
        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                """SELECT command_id,provider_account_id,sending_domain_id,
                          sender_identity_id,campaign_id,message_id,
                          recipient_address_hash
                   FROM delivery_events WHERE delivery_event_id=?""",
                (result.delivery_event_id,),
            ).fetchone()
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?",
                (sent["permit_id"],),
            ).fetchone()
        self.assertEqual(str(row["command_id"]), sent["command_id"])
        self.assertEqual(str(row["provider_account_id"]), str(permit["provider_account_id"]))
        self.assertEqual(str(row["sending_domain_id"]), str(permit["sending_domain_id"]))
        self.assertEqual(str(row["sender_identity_id"]), str(permit["sender_identity"]))
        self.assertEqual(str(row["campaign_id"]), str(permit["campaign_id"]))
        self.assertEqual(str(row["message_id"]), sent["message_id"])
        self.assertEqual(str(row["recipient_address_hash"]), str(permit["address_hash"]))

    def test_fake_provider_or_provider_message_is_denied(self):
        sent = self._send(self._stage("message-provider-scope"))
        tracker = DeliveryEventTracker(self.store)
        common = {
            "event_type": "DELIVERED",
            "payload": {"kind": "DELIVERED"},
            "evidence_ref": EVIDENCE,
            "occurred_at_utc": OCCURRED,
        }
        with self.assertRaises(DeliveryEventError):
            tracker.record_event(
                provider_account_id="provider_different",
                provider_message_id=sent["provider_message_id"],
                provider_event_key="event-wrong-provider",
                **common,
            )
        with self.assertRaises(DeliveryEventError):
            tracker.record_event(
                provider_account_id=self.provider_id,
                provider_message_id="provider-message-different",
                provider_event_key="event-wrong-message",
                **common,
            )
        self.assertEqual(self._count("delivery_events"), 0)

    def test_delivery_event_duplicate_conflict_and_race_are_safe(self):
        sent = self._send(self._stage("message-duplicate"))
        first = self._record(sent, "event-duplicate", "OPEN")
        replay = self._record(sent, "event-duplicate", "OPEN")
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.delivery_event_id, replay.delivery_event_id)
        with self.assertRaises(IdempotencyConflict):
            self._record(
                sent,
                "event-duplicate",
                "OPEN",
                payload={"kind": "OPEN", "changed": True},
            )

        barrier = threading.Barrier(2)

        def record_once(_):
            barrier.wait(timeout=5)
            return self._record(sent, "event-race", "CLICK")

        with ThreadPoolExecutor(max_workers=2) as pool:
            raced = list(pool.map(record_once, range(2)))

        self.assertEqual(sorted(result.created for result in raced), [False, True])
        self.assertEqual(len({result.delivery_event_id for result in raced}), 1)
        self.assertEqual(
            self._count(
                "delivery_events",
                "WHERE provider_account_id=? AND provider_event_key=?",
                (self.provider_id, "event-race"),
            ),
            1,
        )

    def test_bounce_and_complaint_suppressions_are_atomic_across_crash(self):
        sent = self._send(self._stage("message-suppression"))

        for key, kind in (
            ("event-bounce", "HARD_BOUNCE"),
            ("event-complaint", "COMPLAINT"),
        ):
            before = (
                self._count("delivery_events"),
                self._count("suppression_entries"),
                self._count(
                    "events",
                    "WHERE producer='delivery_event_tracker'",
                ),
            )

            def crash():
                raise RuntimeError("offline crash injection")

            with self.assertRaises(RuntimeError):
                self._record(
                    sent,
                    key,
                    kind,
                    tracker=DeliveryEventTracker(self.store, after_event_hook=crash),
                )
            after = (
                self._count("delivery_events"),
                self._count("suppression_entries"),
                self._count(
                    "events",
                    "WHERE producer='delivery_event_tracker'",
                ),
            )
            self.assertEqual(after, before)
            self.assertTrue(self._record(sent, key, kind).created)

        with self.store.transaction(min_schema_version=14) as con:
            suppressions = {
                (str(row["scope"]), str(row["reason"]))
                for row in con.execute(
                    """SELECT scope,reason FROM suppression_entries
                       WHERE source='delivery_event' AND state='ACTIVE'"""
                ).fetchall()
            }
        self.assertEqual(
            suppressions,
            {
                ("EMAIL_ADDRESS", "HARD_BOUNCE"),
                ("EMAIL_ADDRESS", "COMPLAINT"),
                ("CAMPAIGN", "PROVIDER_COMPLAINT"),
            },
        )

    def test_delivery_and_suppression_ledgers_are_append_only(self):
        sent = self._send(self._stage("message-append-only"))
        result = self._record(sent, "event-append-only", "HARD_BOUNCE")
        with self.store.transaction(min_schema_version=14) as con:
            suppression_id = str(
                con.execute(
                    """SELECT suppression_id FROM suppression_entries
                       WHERE source='delivery_event' LIMIT 1"""
                ).fetchone()[0]
            )
        for statement, values in (
            (
                "UPDATE delivery_events SET event_type='OPEN' WHERE delivery_event_id=?",
                (result.delivery_event_id,),
            ),
            (
                "DELETE FROM delivery_events WHERE delivery_event_id=?",
                (result.delivery_event_id,),
            ),
            (
                "UPDATE suppression_entries SET state='SUPERSEDED' WHERE suppression_id=?",
                (suppression_id,),
            ),
            (
                "DELETE FROM suppression_entries WHERE suppression_id=?",
                (suppression_id,),
            ),
        ):
            with self.subTest(statement=statement.split()[0]):
                with self.assertRaises(sqlite3.DatabaseError):
                    with self.store.transaction(min_schema_version=14) as con:
                        con.execute(statement, values)

    def test_metrics_count_unique_first_touch_per_identity_scope(self):
        first = self._send(self._stage("message-metric-one"))
        second_primary = self._additional_scope("metric-primary-two")
        self._send(self._stage("message-metric-two", second_primary))
        self._record(first, "metric-delivered-one", "DELIVERED")
        self._record(first, "metric-delivered-two", "DELIVERED")
        self._record(first, "metric-open-one", "OPEN")
        self._record(first, "metric-open-two", "OPEN")

        second_scope = self._additional_scope(
            "metric-secondary",
            campaign_id="campaign_secondary",
        )
        self._send(self._stage("message-metric-secondary", second_scope))
        metrics = {
            (
                row["sending_domain_id"],
                row["sender_identity_id"],
                row["campaign_id"],
            ): row
            for row in delivery_metrics(self.store)
        }

        primary_key = (self.domain_id, self.sender_id, "campaign_primary")
        secondary_key = (self.domain_id, self.sender_id, "campaign_secondary")
        self.assertEqual(set(metrics), {primary_key, secondary_key})
        self.assertEqual(metrics[primary_key]["first_touch_sent"], 2)
        self.assertEqual(metrics[primary_key]["delivered"], 1)
        self.assertEqual(metrics[primary_key]["open"], 1)
        self.assertEqual(metrics[secondary_key]["first_touch_sent"], 1)
        self.assertEqual(metrics[secondary_key]["delivered"], 0)

    def test_counter_drift_blocks_delivery_intake(self):
        sent = self._send(self._stage("message-counter-drift"))
        with self.store.transaction(min_schema_version=14) as con:
            reservation = con.execute(
                """SELECT scope_type,scope_id,bucket_date
                   FROM mail_limit_reservations
                   WHERE permit_id=? AND scope_type='PROVIDER_DAILY'""",
                (sent["permit_id"],),
            ).fetchone()
            con.execute(
                """UPDATE mail_limit_counters SET reserved_count=reserved_count+1
                   WHERE scope_type=? AND scope_id=? AND bucket_date=?""",
                tuple(reservation),
            )

        with self.assertRaises(DeliveryEventError):
            self._record(sent, "event-counter-drift", "DELIVERED")
        self.assertEqual(self._count("delivery_events"), 0)

    def test_record_sent_rejects_duplicate_provider_id_and_rfc_mismatch(self):
        first = self._stage("message-sent-one")
        second_scope = self._additional_scope("sent-two")
        second = self._stage("message-sent-two", second_scope)
        with self._writers_enabled():
            self._authorize_dispatch(first)
            self._authorize_dispatch(second)
            self.assertTrue(
                self.gate.record_sent(
                    first["command_id"],
                    provider_message_id="provider-shared",
                    rfc_message_id="<sent-one@send.example.test>",
                    actor=ACTOR,
                    evidence_ref=EVIDENCE,
                )
            )
            self.assertFalse(
                self.gate.record_sent(
                    first["command_id"],
                    provider_message_id="provider-shared",
                    rfc_message_id="<sent-one@send.example.test>",
                    actor=ACTOR,
                    evidence_ref=EVIDENCE,
                )
            )
            with self.assertRaises(IdempotencyConflict):
                self.gate.record_sent(
                    first["command_id"],
                    provider_message_id="provider-shared",
                    rfc_message_id="<changed@send.example.test>",
                    actor=ACTOR,
                    evidence_ref=EVIDENCE,
                )
            with self.assertRaises(IdempotencyConflict):
                self.gate.record_sent(
                    second["command_id"],
                    provider_message_id="provider-shared",
                    rfc_message_id="<sent-two@send.example.test>",
                    actor=ACTOR,
                    evidence_ref=EVIDENCE,
                )
        with self.store.transaction(min_schema_version=14) as con:
            second_state = con.execute(
                "SELECT state FROM outbox WHERE command_id=?",
                (second["command_id"],),
            ).fetchone()[0]
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]
        self.assertEqual(second_state, "DISPATCHING")
        self.assertEqual(writer, "0")

    def test_complete_path_makes_no_network_call(self):
        staged = self._stage("message-no-network")
        with patch.object(
            socket,
            "create_connection",
            side_effect=AssertionError("network call attempted"),
        ):
            sent = self._send(staged)
            recorded = self._record(sent, "event-no-network", "DELIVERED")
        self.assertTrue(recorded.created)
        with self.store.transaction(min_schema_version=14) as con:
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]
        self.assertEqual(writer, "0")


if __name__ == "__main__":
    unittest.main()
