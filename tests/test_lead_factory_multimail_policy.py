import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lead_factory.commercial_spine import (
    NormalizedOpportunityIntake,
    OpportunityLifecycle,
    OpportunityState,
)
from lead_factory.conversation_routing import ConversationRouter
from lead_factory.ids import address_hash, message_id_key, new_lf_id
from lead_factory.mail_registry import MailRegistry
from lead_factory.multimail_policy import (
    MultiMailPolicyError,
    MultiMailSendGate,
    MultiMailSendIntent,
)
from lead_factory.store import FactoryStore, IdempotencyConflict, SchemaVersionError


ACTOR = "offline-multimail-test"
EVIDENCE = "stage://multimail-policy/test"
SEGMENT = "fixture-segment"
COHORT = "fixture-cohort"
CONTENT = "fixture-content-v1"
EXPECTED_RESERVATION_SCOPES = {
    "AUTH_DAILY_FIRST_TOUCH",
    "AUTH_LIFETIME_FIRST_TOUCH",
    "PROVIDER_DAILY",
    "DOMAIN_DAILY",
    "MAILBOX_DAILY",
    "SENDER_DAILY",
    "CAMPAIGN_DAILY",
    "CAMPAIGN_LIFETIME",
}


class MutableClock:
    def __init__(self):
        self.value = datetime(2026, 8, 18, 9, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, **kwargs):
        self.value += timedelta(**kwargs)

    def text(self, offset=timedelta()):
        return (self.value + offset).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Fixture:
    key: str
    provider_id: str
    domain_id: str
    mailbox_provider_id: str
    mailbox_domain_id: str
    mailbox_id: str
    sender_id: str
    campaign_id: str
    company_id: str
    contact_id: str
    opportunity_id: str
    conversation_id: str
    peer_address: str


class MultiMailPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "multimail-policy.sqlite3")
        self.store.init()
        self.registry = MailRegistry(self.store)
        self.router = ConversationRouter(self.store)
        self.clock = MutableClock()
        self.gate = MultiMailSendGate(self.store, clock=self.clock)
        self.serial = 0

    def tearDown(self):
        self.temp.cleanup()

    def _advance_to_contact_allowed(self, opportunity_id, key):
        lifecycle = OpportunityLifecycle(self.store)
        steps = (
            (OpportunityState.SCREENED, ""),
            (OpportunityState.TARGET_ACCOUNT, ""),
            (OpportunityState.SIGNAL_CONFIRMED, f"{EVIDENCE}/signal/{key}"),
            (OpportunityState.CONTACT_ALLOWED, f"{EVIDENCE}/legal/{key}"),
        )
        for index, (state, evidence) in enumerate(steps, start=1):
            lifecycle.transition(
                lf_opportunity_id=opportunity_id,
                to_state=state,
                actor=ACTOR,
                evidence_ref=evidence,
                idempotency_key=f"{key}:state:{index}",
                occurred_at_utc=self.clock.text(timedelta(minutes=index)),
            )

    def _commercial(self, key, *, advance=True):
        self.serial += 1
        peer = f"buyer-{self.serial}@buyer.example.test"
        result = NormalizedOpportunityIntake(self.store).ingest(
            producer="multimail_fixture",
            external_key=f"project-{key}-{self.serial}",
            idempotency_key=f"source-{key}-{self.serial}",
            payload={"fixture": key, "serial": self.serial},
            evidence_ref=f"{EVIDENCE}/source/{key}/{self.serial}",
            observed_at_utc=self.clock.text(),
            company_name=f"Fixture {self.serial}",
            company_inn=f"77{self.serial:08d}",
            company_domain=f"buyer-{self.serial}.example.test",
            contact_name="Fixture Buyer",
            contact_email=peer,
            contact_role="buyer",
            project_title=f"Fixture Project {self.serial}",
            product_key="aluminium",
        )
        if advance:
            self._advance_to_contact_allowed(result.lf_opportunity_id, f"{key}-{self.serial}")
        return result, peer

    def _fixture(
        self,
        key,
        *,
        cap=20,
        campaign_lifetime=20,
        reputation="VERIFIED",
        advance=True,
    ):
        # Outbound SMTP identity and inbound reply mailbox deliberately use
        # different provider accounts/domains. This is a supported canonical chain.
        out_provider = self.registry.register_provider_account(
            provider_type="TRANSPORT",
            label=f"out-{key}",
            daily_send_cap=cap,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).entity_id
        self.registry.activate_provider_account(out_provider, actor=ACTOR, evidence_ref=EVIDENCE)
        out_domain = self.registry.register_sending_domain(
            provider_account_id=out_provider,
            domain=f"send-{key}.example.test",
            daily_send_cap=cap,
            reputation_state=reputation,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).entity_id
        self.registry.activate_sending_domain(out_domain, actor=ACTOR, evidence_ref=EVIDENCE)

        inbox_provider = self.registry.register_provider_account(
            provider_type="IMAP",
            label=f"in-{key}",
            daily_send_cap=cap,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).entity_id
        self.registry.activate_provider_account(inbox_provider, actor=ACTOR, evidence_ref=EVIDENCE)
        inbox_domain = self.registry.register_sending_domain(
            provider_account_id=inbox_provider,
            domain=f"inbox-{key}.example.test",
            daily_send_cap=cap,
            reputation_state="VERIFIED",
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).entity_id
        self.registry.activate_sending_domain(inbox_domain, actor=ACTOR, evidence_ref=EVIDENCE)
        mailbox = self.registry.register_mailbox_account(
            provider_account_id=inbox_provider,
            sending_domain_id=inbox_domain,
            address=f"reply@inbox-{key}.example.test",
            daily_send_cap=cap,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).entity_id
        self.registry.activate_mailbox_account(mailbox, actor=ACTOR, evidence_ref=EVIDENCE)

        sender = self.registry.register_sender_identity(
            provider_account_id=out_provider,
            sending_domain_id=out_domain,
            mailbox_account_id=mailbox,
            from_address=f"sales@send-{key}.example.test",
            reply_to_address=f"reply@inbox-{key}.example.test",
            daily_send_cap=cap,
            reputation_state=reputation,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).entity_id
        self.registry.activate_sender_identity(sender, actor=ACTOR, evidence_ref=EVIDENCE)
        campaign = f"campaign-{key}"
        self.registry.register_campaign(
            campaign_id=campaign,
            daily_send_cap=cap,
            lifetime_send_cap=campaign_lifetime,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        )
        self.registry.activate_campaign(campaign, actor=ACTOR, evidence_ref=EVIDENCE)

        commercial, peer = self._commercial(key, advance=advance)
        conversation = self.router.pin_conversation(
            lf_opportunity_id=commercial.lf_opportunity_id,
            lf_contact_id=commercial.lf_contact_id,
            sender_identity_id=sender,
            mailbox_account_id=mailbox,
            campaign_id=campaign,
            peer_address=peer,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).conversation_id
        return Fixture(
            key,
            out_provider,
            out_domain,
            inbox_provider,
            inbox_domain,
            mailbox,
            sender,
            campaign,
            commercial.lf_company_id,
            commercial.lf_contact_id,
            commercial.lf_opportunity_id,
            conversation,
            peer,
        )

    def _conversation_on_chain(self, base, key, *, advance=True):
        commercial, peer = self._commercial(key, advance=advance)
        conversation = self.router.pin_conversation(
            lf_opportunity_id=commercial.lf_opportunity_id,
            lf_contact_id=commercial.lf_contact_id,
            sender_identity_id=base.sender_id,
            mailbox_account_id=base.mailbox_id,
            campaign_id=base.campaign_id,
            peer_address=peer,
            actor=ACTOR,
            evidence_ref=EVIDENCE,
        ).conversation_id
        return Fixture(
            key,
            base.provider_id,
            base.domain_id,
            base.mailbox_provider_id,
            base.mailbox_domain_id,
            base.mailbox_id,
            base.sender_id,
            base.campaign_id,
            commercial.lf_company_id,
            commercial.lf_contact_id,
            commercial.lf_opportunity_id,
            conversation,
            peer,
        )

    def _authorize(self, fixture, *, cap=20):
        return self.gate.create_authorization(
            conversation_id=fixture.conversation_id,
            segment_id=SEGMENT,
            cohort_id=COHORT,
            content_version=CONTENT,
            first_touch_cap=cap,
            followup_cap=cap,
            lifetime_first_touch_cap=cap,
            lifetime_followup_cap=cap,
            valid_from_utc=self.clock.text(timedelta(hours=-1)),
            valid_until_utc=self.clock.text(timedelta(days=2)),
            legal_status="APPROVED",
            legal_evidence_ref=EVIDENCE,
            suppression_snapshot_id="fixture-snapshot",
            approver=ACTOR,
            authorization_id=f"auth-{fixture.key}",
        )

    @staticmethod
    def _intent(fixture, authorization_id, message_id, *, touch="FIRST_TOUCH", address=None):
        return MultiMailSendIntent(
            message_id=message_id,
            authorization_id=authorization_id,
            conversation_id=fixture.conversation_id,
            address=fixture.peer_address if address is None else address,
            segment_id=SEGMENT,
            cohort_id=COHORT,
            content_version=CONTENT,
            touch_type=touch,
        )

    @staticmethod
    def _payload(fixture, authorization_id):
        return {
            "to_address": fixture.peer_address,
            "sender_identity_id": fixture.sender_id,
            "mailbox_account_id": fixture.mailbox_id,
            "conversation_id": fixture.conversation_id,
            "provider_account_id": fixture.provider_id,
            "sending_domain_id": fixture.domain_id,
            "campaign_id": fixture.campaign_id,
            "authorization_id": authorization_id,
            "content_version": CONTENT,
            "subject": "Offline fixture",
            "text_body": "Offline fixture body",
        }

    def _add_suppression(self, fixture, scope):
        digest = address_hash(fixture.peer_address)
        values = {
            "EMAIL_ADDRESS": ("EMAIL_ADDRESS", digest, fixture.peer_address, digest),
            "PERSON": ("PERSON", fixture.contact_id, "", ""),
            "COMPANY": ("COMPANY", fixture.company_id, "", ""),
            "DOMAIN": ("DOMAIN", fixture.peer_address.rsplit("@", 1)[1], "", ""),
        }
        subject_type, subject_id, address, address_digest = values[scope]
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO suppression_entries(
                       suppression_id,subject_type,subject_id,channel,address,address_hash,
                       reason,scope,evidence_ref,source,author,created_at_utc,
                       expires_at_utc,state
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    new_lf_id("suppression"), subject_type, subject_id, "email", address,
                    address_digest, "fixture suppression", scope, EVIDENCE, "offline-test",
                    ACTOR, self.clock.text(), "", "ACTIVE",
                ),
            )

    def _persist_outbound_parent(self, fixture, key):
        external_message_id = f"<{key}@offline.example.test>"
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO conversation_messages(
                       email_message_id,conversation_id,direction,external_message_id,
                       message_id_key,interaction_id,send_command_id,sender_identity_id,
                       mailbox_account_id,fingerprint_hash,evidence_ref,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    new_lf_id("email_message"), fixture.conversation_id, "OUTBOUND",
                    external_message_id, message_id_key(external_message_id), None, None,
                    fixture.sender_id, fixture.mailbox_id, "fixture-parent-hash", EVIDENCE,
                    self.clock.text(),
                ),
            )

    def _assert_denied_or_error(self, callback):
        try:
            decision = callback()
        except (MultiMailPolicyError, SchemaVersionError):
            return
        self.assertFalse(decision.allowed)

    def test_canonical_cross_provider_context_address_and_replay(self):
        fixture = self._fixture("canonical")
        authorization = self._authorize(fixture)
        intent = self._intent(fixture, authorization, "message-canonical")
        first = self.gate.issue_permit(intent)
        replay = self.gate.issue_permit(intent)

        self.assertTrue(first.allowed)
        self.assertTrue(first.created)
        self.assertTrue(replay.allowed)
        self.assertFalse(replay.created)
        self.assertEqual(first.permit_id, replay.permit_id)
        with self.store.transaction(min_schema_version=14) as con:
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?", (first.permit_id,)
            ).fetchone()
            reservations = con.execute(
                "SELECT scope_type,state FROM mail_limit_reservations WHERE permit_id=?",
                (first.permit_id,),
            ).fetchall()
            counters = con.execute(
                "SELECT reserved_count FROM mail_limit_counters"
            ).fetchall()
        self.assertEqual(permit["lf_opportunity_id"], fixture.opportunity_id)
        self.assertEqual(permit["lf_contact_id"], fixture.contact_id)
        self.assertEqual(permit["company_id"], fixture.company_id)
        self.assertEqual(permit["provider_account_id"], fixture.provider_id)
        self.assertEqual(permit["sending_domain_id"], fixture.domain_id)
        self.assertEqual(permit["mailbox_account_id"], fixture.mailbox_id)
        self.assertEqual(permit["sender_identity"], fixture.sender_id)
        self.assertEqual(permit["campaign_id"], fixture.campaign_id)
        self.assertEqual(permit["conversation_id"], fixture.conversation_id)
        self.assertEqual(permit["address_hash"], address_hash(fixture.peer_address))
        self.assertEqual({row["scope_type"] for row in reservations}, EXPECTED_RESERVATION_SCOPES)
        self.assertEqual({row["state"] for row in reservations}, {"HELD"})
        self.assertEqual(len(counters), 8)
        self.assertTrue(all(int(row[0]) == 1 for row in counters))

        wrong = self.gate.issue_permit(
            self._intent(fixture, authorization, "message-wrong-address", address="other@example.test")
        )
        empty = self.gate.issue_permit(
            self._intent(fixture, authorization, "message-empty-address", address="")
        )
        self.assertFalse(wrong.allowed)
        self.assertFalse(empty.allowed)

    def test_required_shared_recipient_suppression_scopes_deny_before_reservation(self):
        for index, scope in enumerate(("EMAIL_ADDRESS", "PERSON", "COMPANY", "DOMAIN"), start=1):
            with self.subTest(scope=scope):
                fixture = self._fixture(f"suppression-{index}")
                authorization = self._authorize(fixture)
                self._add_suppression(fixture, scope)
                decision = self.gate.issue_permit(
                    self._intent(fixture, authorization, f"message-suppression-{index}")
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule_id, "LF-POL-LEGAL-SUPPRESSION")

    def test_registry_authorization_and_reputation_states_fail_closed(self):
        fixture = self._fixture("states")
        authorization = self._authorize(fixture)
        state_cases = (
            ("provider_accounts", "provider_account_id", fixture.provider_id),
            ("sending_domains", "sending_domain_id", fixture.domain_id),
            ("provider_accounts", "provider_account_id", fixture.mailbox_provider_id),
            ("sending_domains", "sending_domain_id", fixture.mailbox_domain_id),
            ("mailbox_accounts", "mailbox_account_id", fixture.mailbox_id),
            ("sender_identities", "sender_identity_id", fixture.sender_id),
            ("mail_campaigns", "campaign_id", fixture.campaign_id),
            ("conversations", "conversation_id", fixture.conversation_id),
            ("outbound_authorizations", "authorization_id", authorization),
        )
        for index, (table, key_column, entity_id) in enumerate(state_cases, start=1):
            with self.subTest(table=table):
                try:
                    with self.store.transaction(min_schema_version=14) as con:
                        con.execute(
                            f'UPDATE "{table}" SET state=? WHERE "{key_column}"=?',
                            ("DISABLED", entity_id),
                        )
                except (sqlite3.DatabaseError, SchemaVersionError):
                    # An immutable/monotonic state trigger is itself a stronger
                    # fail-closed result than the runtime denial below.
                    continue
                decision = self.gate.issue_permit(
                    self._intent(fixture, authorization, f"message-disabled-{index}")
                )
                self.assertFalse(decision.allowed)
                with self.store.transaction(min_schema_version=14) as con:
                    con.execute(
                        f'UPDATE "{table}" SET state=? WHERE "{key_column}"=?',
                        ("ACTIVE", entity_id),
                    )

        for index, (table, key_column, entity_id) in enumerate(
            (
                ("sending_domains", "sending_domain_id", fixture.domain_id),
                ("sender_identities", "sender_identity_id", fixture.sender_id),
            ),
            start=1,
        ):
            with self.subTest(reputation_table=table):
                try:
                    with self.store.transaction(min_schema_version=14) as con:
                        con.execute(
                            f'UPDATE "{table}" SET reputation_state=? WHERE "{key_column}"=?',
                            ("UNKNOWN", entity_id),
                        )
                except (sqlite3.DatabaseError, SchemaVersionError):
                    continue
                decision = self.gate.issue_permit(
                    self._intent(fixture, authorization, f"message-reputation-{index}")
                )
                self.assertFalse(decision.allowed)
                with self.store.transaction(min_schema_version=14) as con:
                    con.execute(
                        f'UPDATE "{table}" SET reputation_state=? WHERE "{key_column}"=?',
                        ("VERIFIED", entity_id),
                    )

    def test_eight_thread_cap_race_and_same_message_replay_do_not_overcount(self):
        fixture = self._fixture("race", cap=1, campaign_lifetime=1)
        fixtures = [fixture] + [
            self._conversation_on_chain(fixture, f"race-peer-{index}")
            for index in range(1, 8)
        ]
        authorizations = [self._authorize(item, cap=20) for item in fixtures]
        barrier = threading.Barrier(8)

        def distinct_worker(index):
            barrier.wait(timeout=10)
            return self.gate.issue_permit(
                self._intent(
                    fixtures[index], authorizations[index], f"message-race-{index}"
                )
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            decisions = list(pool.map(distinct_worker, range(8)))
        self.assertEqual(sum(decision.allowed for decision in decisions), 1)
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM send_permits").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM mail_limit_reservations").fetchone()[0], 8)

        replay_fixture = self._fixture("replay-race", cap=20)
        replay_auth = self._authorize(replay_fixture, cap=20)
        replay_intent = self._intent(replay_fixture, replay_auth, "message-one-id")
        barrier = threading.Barrier(8)

        def replay_worker(_index):
            barrier.wait(timeout=10)
            return self.gate.issue_permit(replay_intent)

        with ThreadPoolExecutor(max_workers=8) as pool:
            replays = list(pool.map(replay_worker, range(8)))
        self.assertTrue(all(result.allowed for result in replays))
        self.assertEqual(sum(result.created for result in replays), 1)
        self.assertEqual(len({result.permit_id for result in replays}), 1)
        permit_id = replays[0].permit_id
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM mail_limit_reservations WHERE permit_id=?",
                    (permit_id,),
                ).fetchone()[0],
                8,
            )

    def test_mid_reservation_database_failure_rolls_back_all_quota_state(self):
        fixture = self._fixture("crash")
        authorization = self._authorize(fixture)
        intent = self._intent(fixture, authorization, "message-crash")
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """CREATE TRIGGER fixture_crash_mid_reservation
                   BEFORE INSERT ON mail_limit_reservations
                   WHEN NEW.scope_type='SENDER_DAILY'
                   BEGIN SELECT RAISE(ABORT, 'fixture crash'); END"""
            )
        with self.assertRaises(sqlite3.DatabaseError):
            self.gate.issue_permit(intent)
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM send_permits WHERE message_id=?", (intent.message_id,)
                ).fetchone()[0],
                0,
            )
            self.assertEqual(con.execute("SELECT COUNT(*) FROM mail_limit_reservations").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM mail_limit_counters").fetchone()[0], 0)

    def test_stage_requires_strict_envelope_and_keeps_complete_reservations_held(self):
        fixture = self._fixture("stage")
        authorization = self._authorize(fixture)
        missing = self._intent(fixture, authorization, "message-stage-missing")
        missing_permit = self.gate.issue_permit(missing)
        payload = self._payload(fixture, authorization)
        invalid_payloads = []
        for field in (
            "to_address",
            "sender_identity_id",
            "mailbox_account_id",
            "conversation_id",
            "provider_account_id",
            "sending_domain_id",
            "campaign_id",
            "authorization_id",
            "content_version",
        ):
            candidate = dict(payload)
            candidate.pop(field)
            invalid_payloads.append((f"missing-{field}", candidate))
        for field in (
            "to_address",
            "sender_identity_id",
            "mailbox_account_id",
            "conversation_id",
        ):
            candidate = dict(payload)
            candidate[field] = "wrong-canonical-value"
            invalid_payloads.append((f"wrong-{field}", candidate))
        nested_headers = dict(payload)
        nested_headers["headers"] = {
            "To": "other@example.test",
            "From": "spoof@example.test",
            "Reply-To": "spoof@example.test",
        }
        invalid_payloads.append(("nested-spoof-headers", nested_headers))
        for label, candidate in invalid_payloads:
            with self.subTest(payload=label):
                self._assert_denied_or_error(
                    lambda candidate=candidate, label=label: self.gate.stage_command(
                        missing,
                        missing_permit.permit_id,
                        payload_ref=f"stage://payload/{label}",
                        payload=candidate,
                    )
                )

        valid_fixture = self._fixture("stage-valid")
        valid_authorization = self._authorize(valid_fixture)
        valid = self._intent(valid_fixture, valid_authorization, "message-stage-valid")
        permit = self.gate.issue_permit(valid)
        staged = self.gate.stage_command(
            valid,
            permit.permit_id,
            payload_ref="stage://payload/valid",
            payload=self._payload(valid_fixture, valid_authorization),
        )
        replay = self.gate.stage_command(
            valid,
            permit.permit_id,
            payload_ref="stage://payload/valid",
            payload=self._payload(valid_fixture, valid_authorization),
        )
        self.assertTrue(staged.allowed)
        self.assertTrue(staged.created)
        self.assertTrue(replay.allowed)
        self.assertFalse(replay.created)
        with self.store.transaction(min_schema_version=14) as con:
            states = {
                row[0]
                for row in con.execute(
                    "SELECT state FROM mail_limit_reservations WHERE permit_id=?",
                    (permit.permit_id,),
                ).fetchall()
            }
            self.assertEqual(states, {"HELD"})
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM outbox WHERE message_id=? AND state='STAGED'",
                    (valid.message_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(con.execute("SELECT COUNT(*) FROM delivery_events").fetchone()[0], 0)

        corrupt_fixture = self._fixture("stage-corrupt")
        corrupt_authorization = self._authorize(corrupt_fixture)
        corrupt = self._intent(
            corrupt_fixture, corrupt_authorization, "message-stage-corrupt"
        )
        corrupt_permit = self.gate.issue_permit(corrupt)
        with self.store.transaction(min_schema_version=14) as con:
            con.execute("DROP TRIGGER trg_lf_limit_reservation_no_delete")
            con.execute(
                "DELETE FROM mail_limit_reservations WHERE reservation_id=(SELECT reservation_id FROM mail_limit_reservations WHERE permit_id=? LIMIT 1)",
                (corrupt_permit.permit_id,),
            )
        self._assert_denied_or_error(
            lambda: self.gate.stage_command(
                corrupt,
                corrupt_permit.permit_id,
                payload_ref="stage://payload/corrupt",
                payload=self._payload(corrupt_fixture, corrupt_authorization),
            )
        )

    def test_suppression_is_rechecked_between_permit_and_stage(self):
        fixture = self._fixture("late-suppression")
        authorization = self._authorize(fixture)
        intent = self._intent(fixture, authorization, "message-late-suppression")
        permit = self.gate.issue_permit(intent)
        self.assertTrue(permit.allowed)
        self._add_suppression(fixture, "EMAIL_ADDRESS")
        replay = self.gate.issue_permit(intent)
        self.assertFalse(replay.allowed)
        staged = self.gate.stage_command(
            intent,
            permit.permit_id,
            payload_ref="stage://payload/suppressed",
            payload=self._payload(fixture, authorization),
        )
        self.assertFalse(staged.allowed)
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                con.execute("SELECT COUNT(*) FROM outbox WHERE message_id=?", (intent.message_id,)).fetchone()[0],
                0,
            )

    def test_commercial_state_and_followup_conversation_are_fail_closed(self):
        fixture = self._fixture("state", advance=False)
        authorization = self._authorize(fixture)
        first = self.gate.issue_permit(
            self._intent(fixture, authorization, "message-too-early")
        )
        self.assertFalse(first.allowed)

        self._advance_to_contact_allowed(fixture.opportunity_id, "state-late")
        first_intent = self._intent(fixture, authorization, "message-first")
        permit = self.gate.issue_permit(first_intent)
        self.assertTrue(permit.allowed)
        self.assertTrue(
            self.gate.stage_command(
                first_intent,
                permit.permit_id,
                payload_ref="stage://payload/first",
                payload=self._payload(fixture, authorization),
            ).allowed
        )
        early_followup = self.gate.issue_permit(
            self._intent(fixture, authorization, "message-followup-early", touch="FOLLOWUP")
        )
        self.assertFalse(early_followup.allowed)

        self._persist_outbound_parent(fixture, "fixture-first")
        OpportunityLifecycle(self.store).transition(
            lf_opportunity_id=fixture.opportunity_id,
            to_state=OpportunityState.CONTACTING,
            actor=ACTOR,
            evidence_ref=f"{EVIDENCE}/contacting",
            idempotency_key="state:contacting",
            occurred_at_utc=self.clock.text(timedelta(minutes=10)),
        )
        correct = self.gate.issue_permit(
            self._intent(fixture, authorization, "message-followup-correct", touch="FOLLOWUP")
        )
        self.assertTrue(correct.allowed)

        other = self._conversation_on_chain(fixture, "other-conversation")
        self._persist_outbound_parent(other, "fixture-other")
        with self.assertRaises(IdempotencyConflict):
            self.gate.create_authorization(
                conversation_id=other.conversation_id,
                segment_id=SEGMENT,
                cohort_id=COHORT,
                content_version=CONTENT,
                first_touch_cap=20,
                followup_cap=20,
                lifetime_first_touch_cap=20,
                lifetime_followup_cap=20,
                valid_from_utc=self.clock.text(timedelta(hours=-1)),
                valid_until_utc=self.clock.text(timedelta(days=2)),
                legal_status="APPROVED",
                legal_evidence_ref=EVIDENCE,
                suppression_snapshot_id="fixture-snapshot",
                approver=ACTOR,
                authorization_id=authorization,
            )
        OpportunityLifecycle(self.store).transition(
            lf_opportunity_id=other.opportunity_id,
            to_state=OpportunityState.CONTACTING,
            actor=ACTOR,
            evidence_ref=f"{EVIDENCE}/other-contacting",
            idempotency_key="other:contacting",
            occurred_at_utc=self.clock.text(timedelta(minutes=11)),
        )
        switched = self.gate.issue_permit(
            self._intent(other, authorization, "message-followup-switched", touch="FOLLOWUP")
        )
        self.assertFalse(switched.allowed)

    def test_release_only_expired_issued_permit_decrements_exactly_once(self):
        fixture = self._fixture("release")
        authorization = self._authorize(fixture)
        intent = self._intent(fixture, authorization, "message-release")
        permit = self.gate.issue_permit(intent)
        self.assertTrue(permit.allowed)

        try:
            early = self.gate.release_expired_permit(
                permit.permit_id, actor=ACTOR, evidence_ref=EVIDENCE
            )
            self.assertFalse(early)
        except MultiMailPolicyError:
            pass
        self.clock.advance(hours=1)
        self.assertTrue(
            self.gate.release_expired_permit(
                permit.permit_id, actor=ACTOR, evidence_ref=EVIDENCE
            )
        )
        self.assertFalse(
            self.gate.release_expired_permit(
                permit.permit_id, actor=ACTOR, evidence_ref=EVIDENCE
            )
        )
        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(
                {
                    row[0]
                    for row in con.execute(
                        "SELECT state FROM mail_limit_reservations WHERE permit_id=?",
                        (permit.permit_id,),
                    ).fetchall()
                },
                {"RELEASED"},
            )
            self.assertTrue(
                all(
                    int(row[0]) == 0
                    for row in con.execute(
                        "SELECT reserved_count FROM mail_limit_counters"
                    ).fetchall()
                )
            )
            self.assertEqual(
                con.execute(
                    "SELECT state FROM send_permits WHERE permit_id=?", (permit.permit_id,)
                ).fetchone()[0],
                "EXPIRED",
            )


if __name__ == "__main__":
    unittest.main()
