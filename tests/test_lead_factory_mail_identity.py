import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from lead_factory.conversation_routing import (
    EXACT,
    REVIEW,
    ConversationPinConflict,
    ConversationRouter,
)
from lead_factory.ids import canonical_json, message_id_key, new_lf_id, utc_now
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.mail_registry import DISABLED, MailRegistry
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import UNROUTED


ACTOR = "offline-test"
EVIDENCE = "stage://mail-identity/test"


class MailIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "mail-identity.sqlite3")
        self.store.init()
        self.registry = MailRegistry(self.store)
        self.router = ConversationRouter(self.store)
        self.serial = 0

        self.out_provider, self.out_domain, _ = self._active_mailbox_chain(
            provider_type="TRANSPORT",
            label="offline outbound",
            domain="send.example.test",
            mailbox_address="transport@send.example.test",
        )
        self.in_provider, self.in_domain, self.mailbox = self._active_mailbox_chain(
            provider_type="IMAP",
            label="offline inbound",
            domain="inbox.example.test",
            mailbox_address="reply@inbox.example.test",
        )
        sender = self.registry.register_sender_identity(
            provider_account_id=self.out_provider,
            sending_domain_id=self.out_domain,
            mailbox_account_id=self.mailbox,
            from_address="sales@send.example.test",
            reply_to_address="reply@inbox.example.test",
            daily_send_cap=0,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.sender = sender.entity_id
        self.registry.activate_sender_identity(
            self.sender, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self._activate_campaign("campaign-one")

        self.company = self.store.create_company(
            name="Fixture", inn="7700000001", domain="buyer.example.test"
        )[0]
        self.contact = self.store.create_contact(
            lf_company_id=self.company["lf_company_id"],
            email="buyer@buyer.example.test",
            name="Fixture Buyer",
        )[0]
        self.project = self.store.create_project(
            lf_company_id=self.company["lf_company_id"],
            source="offline-fixture",
            external_key="project-1",
            title="Fixture project",
            evidence_ref=EVIDENCE,
        )[0]
        self.opportunity = self.store.create_opportunity(
            lf_company_id=self.company["lf_company_id"],
            lf_contact_id=self.contact["lf_contact_id"],
            lf_project_id=self.project["lf_project_id"],
            source="offline-fixture",
            external_key="opportunity-1",
        )[0]
        self.conversation = self._pin(
            campaign_id="campaign-one", sender_identity_id=self.sender
        )

    def tearDown(self):
        self.temp.cleanup()

    def _active_mailbox_chain(
        self, *, provider_type: str, label: str, domain: str, mailbox_address: str
    ):
        provider = self.registry.register_provider_account(
            provider_type=provider_type,
            label=label,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_provider_account(
            provider.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        sending_domain = self.registry.register_sending_domain(
            provider_account_id=provider.entity_id,
            domain=domain,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_sending_domain(
            sending_domain.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        mailbox = self.registry.register_mailbox_account(
            provider_account_id=provider.entity_id,
            sending_domain_id=sending_domain.entity_id,
            address=mailbox_address,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_mailbox_account(
            mailbox.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        return provider.entity_id, sending_domain.entity_id, mailbox.entity_id

    def _activate_campaign(self, campaign_id: str):
        self.registry.register_campaign(
            campaign_id=campaign_id,
            daily_send_cap=0,
            lifetime_send_cap=0,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_campaign(
            campaign_id, actor=ACTOR, evidence_ref=EVIDENCE
        )

    def _pin(
        self, *, campaign_id: str, sender_identity_id: str,
        mailbox_account_id: str | None = None,
    ):
        return self.router.pin_conversation(
            lf_opportunity_id=self.opportunity["lf_opportunity_id"],
            lf_contact_id=self.contact["lf_contact_id"],
            sender_identity_id=sender_identity_id,
            mailbox_account_id=mailbox_account_id or self.mailbox,
            campaign_id=campaign_id,
            peer_address=self.contact["email"],
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).conversation_id

    def _outbound(self, conversation_id: str, message_id: str):
        self.serial += 1
        with self.store.transaction(min_schema_version=14) as con:
            scope = con.execute(
                """SELECT c.*,o.lf_company_id,s.provider_account_id,
                          s.sending_domain_id,s.sender_identity_id
                   FROM conversations c
                   JOIN opportunities o ON o.lf_opportunity_id=c.lf_opportunity_id
                   JOIN sender_identities s ON s.sender_identity_id=c.sender_identity_id
                   WHERE c.conversation_id=?""",
                (conversation_id,),
            ).fetchone()
            authorization_id = new_lf_id("authorization")
            permit_id = new_lf_id("permit")
            command_id = new_lf_id("command")
            internal_message_id = f"fixture-message-{self.serial}"
            now = utc_now()
            con.execute(
                """INSERT INTO outbound_authorizations(
                       authorization_id,state,channel,segment_id,cohort_id,content_version,
                       sender_identity,first_touch_cap,followup_cap,lifetime_first_touch_cap,
                       lifetime_followup_cap,valid_from_utc,valid_until_utc,legal_status,
                       legal_evidence_ref,suppression_snapshot_id,approver,approved_at_utc,
                       stop_rules_json,created_at_utc,campaign_id,provider_account_id,
                       sending_domain_id,mailbox_account_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    authorization_id, "ACTIVE", "email", "fixture", "fixture", "v1",
                    scope["sender_identity_id"], 1, 1, 1, 1,
                    "2026-08-18T00:00:00Z", "2026-08-19T00:00:00Z", "APPROVED",
                    EVIDENCE, "fixture", ACTOR, now, "{}", now, scope["campaign_id"],
                    scope["provider_account_id"], scope["sending_domain_id"],
                    scope["mailbox_account_id"],
                ),
            )
            con.execute(
                """INSERT INTO send_permits(
                       permit_id,authorization_id,message_id,lf_opportunity_id,lf_contact_id,
                       company_id,address_hash,domain,channel,touch_type,segment_id,cohort_id,
                       content_version,sender_identity,state,issued_at_utc,expires_at_utc,
                       consumed_at_utc,denial_rule_id,campaign_id,provider_account_id,
                       sending_domain_id,mailbox_account_id,conversation_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    permit_id, authorization_id, internal_message_id,
                    scope["lf_opportunity_id"], scope["lf_contact_id"], scope["lf_company_id"],
                    scope["peer_address_hash"], "buyer.example.test", "email", "FOLLOWUP",
                    "fixture", "fixture", "v1", scope["sender_identity_id"], "SENT", now,
                    "2026-08-19T00:00:00Z", now, "", scope["campaign_id"],
                    scope["provider_account_id"], scope["sending_domain_id"],
                    scope["mailbox_account_id"], conversation_id,
                ),
            )
            con.execute(
                """INSERT INTO outbox(
                       command_id,message_id,permit_id,command_type,channel,payload_ref,
                       payload_hash,state,attempt_count,next_retry_at_utc,last_error_class,
                       provider_message_id,correlation_id,created_at_utc,updated_at_utc,
                       conversation_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    command_id, internal_message_id, permit_id, "SEND_MESSAGE", "email",
                    "fixture://payload", f"fixture-hash-{self.serial}", "SENT", 1, "", "",
                    f"provider-message-{self.serial}", internal_message_id, now, now,
                    conversation_id,
                ),
            )
        return self.router.register_message_reference(
            conversation_id=conversation_id,
            direction="OUTBOUND",
            external_message_id=message_id,
            send_command_id=command_id,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )

    def _interaction(
        self,
        *,
        mailbox_account_id: str | None = None,
        peer: str = "buyer@buyer.example.test",
        in_reply_to: str = "",
        references=(),
        external_message_id: str = "",
    ) -> str:
        self.serial += 1
        message_id = external_message_id or f"<in-{self.serial}@buyer.example.test>"
        mailbox_id = mailbox_account_id or self.mailbox
        reference_values = (
            (references,) if isinstance(references, str) else tuple(references)
        )
        result = InboundIntake(self.store).ingest(
            InboundMessage(
                producer=f"mailbox:{mailbox_id}",
                mailbox="INBOX",
                mailbox_account_id=mailbox_id,
                external_message_id=message_id,
                uid=str(self.serial),
                uid_validity="100",
                from_address=peer,
                contact_address=peer,
                in_reply_to=in_reply_to,
                references=reference_values,
                classification=UNROUTED,
                evidence_ref=f"stage-evidence:fixture:{self.serial}",
                evidence_sha256=f"evidence-hash-{self.serial}",
                content_hash=f"content-hash-{self.serial}",
                create_human_task=False,
            )
        )
        return result.interaction_id

    def _assert_no_external_handoff(self):
        con = self.store.connect()
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM human_tasks").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM crm_outbox").fetchone()[0], 0)
        finally:
            con.close()

    def test_registry_defaults_disabled_and_activation_requires_evidence(self):
        pending = self.registry.register_provider_account(
            provider_type="OFFLINE",
            label="disabled fixture",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.assertEqual(pending.state, DISABLED)
        with self.assertRaises(ValueError):
            self.registry.activate_provider_account(
                pending.entity_id, actor=ACTOR, evidence_ref=""
            )
        con = self.store.connect()
        try:
            state = con.execute(
                "SELECT state FROM provider_accounts WHERE provider_account_id=?",
                (pending.entity_id,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(state, DISABLED)

    def test_active_conversation_is_pinned_to_one_sender_identity(self):
        repeated = self._pin(campaign_id="campaign-one", sender_identity_id=self.sender)
        self.assertEqual(repeated, self.conversation)
        second = self.registry.register_sender_identity(
            provider_account_id=self.out_provider,
            sending_domain_id=self.out_domain,
            mailbox_account_id=self.mailbox,
            from_address="alternate@send.example.test",
            reply_to_address="reply@inbox.example.test",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_sender_identity(
            second.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        with self.assertRaises(ConversationPinConflict):
            self._pin(campaign_id="campaign-one", sender_identity_id=second.entity_id)

    def test_references_header_routes_exactly_without_task_or_crm(self):
        self._outbound(self.conversation, "<root-1@send.example.test>")
        interaction = self._interaction(references=["<root-1@send.example.test>"])
        routed = self.router.route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual(routed.state, EXACT)
        self.assertEqual(routed.conversation_id, self.conversation)
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT conversation_id,lf_opportunity_id,lf_contact_id,thread_route_state
                   FROM interactions WHERE lf_interaction_id=?""",
                (interaction,),
            ).fetchone()
            inbound_messages = con.execute(
                """SELECT COUNT(*) FROM conversation_messages
                   WHERE conversation_id=? AND direction='INBOUND'""",
                (self.conversation,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(tuple(row), (
            self.conversation,
            self.opportunity["lf_opportunity_id"],
            self.contact["lf_contact_id"],
            EXACT,
        ))
        self.assertEqual(inbound_messages, 1)
        self._assert_no_external_handoff()

    def test_exact_route_is_restart_and_duplicate_safe(self):
        parent = "<restart-safe@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(in_reply_to=parent)
        first = self.router.route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        replay = ConversationRouter(self.store).route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertTrue(first.changed)
        self.assertFalse(replay.changed)
        self.assertEqual(replay.state, EXACT)
        con = self.store.connect()
        try:
            message_count = con.execute(
                """SELECT COUNT(*) FROM conversation_messages
                   WHERE interaction_id=? AND direction='INBOUND'""",
                (interaction,),
            ).fetchone()[0]
            event_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='conversation_route_exact' AND aggregate_id=?""",
                (interaction,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual((message_count, event_count), (1, 1))

    def test_route_rolls_back_after_crash_and_recovers(self):
        parent = "<crash-safe@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(in_reply_to=parent)
        original_event_tx = self.router._event_tx

        def crash_before_commit(con, **kwargs):
            if kwargs.get("event_type") == "conversation_route_exact":
                raise RuntimeError("simulated offline crash")
            return original_event_tx(con, **kwargs)

        self.router._event_tx = crash_before_commit
        with self.assertRaises(RuntimeError):
            self.router.route_interaction(
                interaction, actor=ACTOR, evidence_ref=EVIDENCE
            )
        con = self.store.connect()
        try:
            route_state = con.execute(
                """SELECT thread_route_state FROM interactions
                   WHERE lf_interaction_id=?""",
                (interaction,),
            ).fetchone()[0]
            message_count = con.execute(
                """SELECT COUNT(*) FROM conversation_messages
                   WHERE interaction_id=?""",
                (interaction,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual((route_state, message_count), ("UNRESOLVED", 0))
        recovered = ConversationRouter(self.store).route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual(recovered.state, EXACT)

    def test_concurrent_duplicate_route_has_one_commit(self):
        parent = "<race-safe@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(in_reply_to=parent)
        barrier = threading.Barrier(2)

        def route_once():
            barrier.wait(timeout=5)
            return ConversationRouter(self.store).route_interaction(
                interaction, actor=ACTOR, evidence_ref=EVIDENCE
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: route_once(), range(2)))
        self.assertEqual([result.state for result in results], [EXACT, EXACT])
        self.assertEqual(sorted(result.changed for result in results), [False, True])
        con = self.store.connect()
        try:
            message_count = con.execute(
                """SELECT COUNT(*) FROM conversation_messages
                   WHERE interaction_id=?""",
                (interaction,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(message_count, 1)

    def test_same_inbound_message_id_is_independent_across_mailboxes(self):
        _, _, other_mailbox = self._active_mailbox_chain(
            provider_type="IMAP",
            label="second offline inbound",
            domain="second-inbox.example.test",
            mailbox_address="reply@second-inbox.example.test",
        )
        second_sender = self.registry.register_sender_identity(
            provider_account_id=self.out_provider,
            sending_domain_id=self.out_domain,
            mailbox_account_id=other_mailbox,
            from_address="second@send.example.test",
            reply_to_address="reply@second-inbox.example.test",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_sender_identity(
            second_sender.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self._activate_campaign("campaign-second-mailbox")
        second_conversation = self._pin(
            campaign_id="campaign-second-mailbox",
            sender_identity_id=second_sender.entity_id,
            mailbox_account_id=other_mailbox,
        )
        parent = "<scoped-parent@send.example.test>"
        inbound_id = "<scoped-inbound@buyer.example.test>"
        self._outbound(self.conversation, parent)
        self._outbound(second_conversation, parent)
        first = self._interaction(
            in_reply_to=parent, external_message_id=inbound_id
        )
        second = self._interaction(
            mailbox_account_id=other_mailbox,
            in_reply_to=parent,
            external_message_id=inbound_id,
        )
        first_result = self.router.route_interaction(
            first, actor=ACTOR, evidence_ref=EVIDENCE
        )
        second_result = self.router.route_interaction(
            second, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual(
            (first_result.state, second_result.state), (EXACT, EXACT)
        )
        self.assertNotEqual(
            first_result.conversation_id, second_result.conversation_id
        )
        con = self.store.connect()
        try:
            claim_count = con.execute(
                """SELECT COUNT(*) FROM email_message_claims
                   WHERE message_id_key=?""",
                (message_id_key(inbound_id),),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(claim_count, 2)

    def test_same_reference_in_two_conversations_is_ambiguous_review(self):
        self._activate_campaign("campaign-two")
        second = self._pin(campaign_id="campaign-two", sender_identity_id=self.sender)
        first_reference = "<shared-a@send.example.test>"
        second_reference = "<shared-b@send.example.test>"
        self._outbound(self.conversation, first_reference)
        self._outbound(second, second_reference)
        interaction = self._interaction(
            in_reply_to=first_reference, references=(second_reference,)
        )
        routed = self.router.route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual(routed.state, REVIEW)
        self.assertEqual(routed.reason, "AMBIGUOUS_CONVERSATION_MATCH")
        self.assertEqual(routed.candidate_count, 2)
        self._assert_no_external_handoff()

    def test_spoofed_sender_is_review_not_exact(self):
        parent = "<peer-check@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(peer="spoof@buyer.example.test", in_reply_to=parent)
        routed = self.router.route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual((routed.state, routed.reason), (REVIEW, "PEER_MISMATCH"))
        self._assert_no_external_handoff()

    def test_wrong_mailbox_is_review_not_exact(self):
        other = self.registry.register_mailbox_account(
            provider_account_id=self.in_provider,
            sending_domain_id=self.in_domain,
            address="other@inbox.example.test",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_mailbox_account(
            other.entity_id, actor=ACTOR, evidence_ref=EVIDENCE
        )
        parent = "<mailbox-check@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(
            mailbox_account_id=other.entity_id, in_reply_to=parent
        )
        routed = self.router.route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual((routed.state, routed.reason), (REVIEW, "MAILBOX_MISMATCH"))
        self._assert_no_external_handoff()

    def test_duplicate_references_collapse_to_one_exact_candidate(self):
        parent = "<duplicate-ref@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(
            in_reply_to=parent,
            references=[parent, parent, parent.upper()],
        )
        routed = self.router.route_interaction(
            interaction, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual(routed.state, EXACT)
        self.assertEqual(routed.candidate_count, 1)
        self._assert_no_external_handoff()

    def test_missing_and_malformed_references_create_review(self):
        missing = self._interaction()
        missing_result = self.router.route_interaction(
            missing, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual((missing_result.state, missing_result.reason), (
            REVIEW, "MISSING_THREAD_REFERENCE",
        ))

        malformed = self._interaction(references="not-a-message-id")
        malformed_result = self.router.route_interaction(
            malformed, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual((malformed_result.state, malformed_result.reason), (
            REVIEW, "MALFORMED_THREAD_HEADERS",
        ))
        self._assert_no_external_handoff()

    def test_inbound_message_id_collision_is_review(self):
        parent = "<collision-parent@send.example.test>"
        self._outbound(self.conversation, parent)
        first = self._interaction(
            in_reply_to=parent, external_message_id="<collision@buyer.example.test>"
        )
        self.assertEqual(
            self.router.route_interaction(first, actor=ACTOR, evidence_ref=EVIDENCE).state,
            EXACT,
        )
        second = self._interaction(in_reply_to=parent)
        with self.store.transaction() as con:
            con.execute(
                "UPDATE interactions SET external_message_id=? WHERE lf_interaction_id=?",
                ("<collision@buyer.example.test>", second),
            )
        result = self.router.route_interaction(
            second, actor=ACTOR, evidence_ref=EVIDENCE
        )
        self.assertEqual((result.state, result.reason), (
            REVIEW, "INBOUND_MESSAGE_ID_CONFLICT",
        ))
        self._assert_no_external_handoff()

    def test_conversation_events_do_not_contain_raw_addresses_or_message_ids(self):
        parent = "<pii-safe@send.example.test>"
        self._outbound(self.conversation, parent)
        interaction = self._interaction(in_reply_to=parent)
        self.router.route_interaction(interaction, actor=ACTOR, evidence_ref=EVIDENCE)
        con = self.store.connect()
        try:
            payloads = [
                json.loads(row[0])
                for row in con.execute(
                    """SELECT payload_json FROM events
                       WHERE producer IN ('mail_registry','conversation_router')"""
                ).fetchall()
            ]
        finally:
            con.close()
        serialized = canonical_json(payloads)
        self.assertNotIn("buyer@buyer.example.test", serialized)
        self.assertNotIn("sales@send.example.test", serialized)
        self.assertNotIn(parent.casefold(), serialized.casefold())


if __name__ == "__main__":
    unittest.main()
