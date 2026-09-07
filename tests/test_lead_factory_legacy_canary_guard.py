from __future__ import annotations

import datetime as dt
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import tb_builder_campaign as builder
import tb_dealer_campaign as dealer
from lead_factory import legacy_canary_guard
from lead_factory.canary_control import CanaryControl
from lead_factory.crm_handoff import HumanReplyCrmHandoff
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.legacy_canary_guard import (
    DurableLegacyCanarySelector,
    LegacyCanaryGuard,
    LegacyCanaryScope,
    assess_legacy_canary,
    resolve_canary_operation_quarantine,
)
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore, IdempotencyConflict
from lead_factory.unified_inbound_worker import UNROUTED


def _reply(email: str, *, message_id: str = "<inbound@example.test>") -> dict:
    return {
        "from": email,
        "msgid": message_id,
        "in_reply_to": "<outbound@example.test>",
        "references": "<outbound@example.test>",
        "subject": "Нужен расчёт",
        "body": "Просим подготовить расчёт.",
        "date": "Mon, 18 Aug 2026 10:00:00 +0000",
    }


def _record(email: str, *, qualification_sent: bool = False) -> dict:
    return {
        "email": email,
        "name": "Canary Test",
        "status": "active",
        "touch": 1,
        "t1_date": "2026-08-01",
        "t2_date": "",
        "t3_date": "",
        "sent_msgids": ["<outbound@example.test>"],
        "processed_reply_ids": [],
        "got_reply": False,
        "qualification_request_msgid": "<qualification@example.test>" if qualification_sent else "",
        "inn": "",
    }


class LegacyCanaryGuardTests(unittest.TestCase):
    def test_scope_is_exact_and_arming_is_observe_only_by_default(self):
        guard = LegacyCanaryGuard()
        scope = LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="dealer_outreach",
            contact_address="canary@example.test",
            thread_id="<outbound@example.test>",
        )
        guard.arm(scope)
        same = LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="dealer_outreach",
            contact_address="canary@example.test",
            thread_id="<outbound@example.test>",
            interaction_id="<inbound@example.test>",
        )
        different_thread = LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="dealer_outreach",
            contact_address="canary@example.test",
            thread_id="<another-thread@example.test>",
        )

        decision = guard.assess(same)
        self.assertTrue(decision.observed)
        self.assertFalse(decision.block_legacy_writers)
        ambiguous = guard.assess(different_thread)
        self.assertTrue(ambiguous.observed)
        self.assertFalse(ambiguous.block_legacy_writers)
        self.assertEqual(ambiguous.reason, "AMBIGUOUS_CANARY")

        with self.assertRaisesRegex(ValueError, "mailbox, campaign, contact, and outbound thread"):
            guard.arm(LegacyCanaryScope(
                mailbox="\\Inbox", campaign_id="dealer_outreach", contact_address="canary@example.test"
            ))

    def test_guard_error_fails_closed_only_for_an_explicit_armed_scope(self):
        guard = LegacyCanaryGuard(writers_enabled=True)
        scope = LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="dealer_outreach",
            contact_address="canary@example.test",
            thread_id="<outbound@example.test>",
        )
        guard.arm(scope)
        matching = LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="dealer_outreach",
            contact_address="canary@example.test",
            thread_id="<outbound@example.test>",
        )
        non_canary = LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="dealer_outreach",
            contact_address="other@example.test",
        )

        with (
            patch.object(guard, "_matching_scopes", side_effect=RuntimeError("registry unavailable")),
            patch.object(guard, "_fallback_matching_scopes", side_effect=RuntimeError("fallback unavailable")),
        ):
            guarded = guard.assess(matching)
            pass_through = guard.assess(non_canary)

        self.assertTrue(guarded.block_legacy_writers)
        self.assertEqual(guarded.reason, "guard_error_scoped_contact")
        self.assertFalse(pass_through.block_legacy_writers)
        self.assertEqual(pass_through.reason, "guard_error_non_canary_or_observe_only")

    def test_double_guard_failure_cannot_reopen_armed_contact_to_legacy_writers(self):
        email = "canary@example.test"
        rec = _record(email, qualification_sent=True)
        state = {"_meta": {"enabled": True, "send_days": []}, "builders": {email: rec}}
        incoming = _reply(email)
        guard = LegacyCanaryGuard(writers_enabled=True)
        guard.arm(LegacyCanaryScope(
            mailbox="\\Inbox", campaign_id="builder_outreach",
            contact_address=email, thread_id=incoming["in_reply_to"],
        ))
        with (
            patch.object(guard, "_matching_scopes", side_effect=RuntimeError("registry unavailable")),
            patch.object(guard, "_fallback_matching_scopes", side_effect=RuntimeError("fallback unavailable")),
            patch.object(legacy_canary_guard, "DEFAULT_LEGACY_CANARY_GUARD", guard),
        ):
            _, smtp_reply, unisender_send, bitrix_create, qualify, _ = self._run_poll(
                builder, state, incoming
            )

        self.assertEqual(rec["status"], "canary_guarded")
        self.assertEqual(rec["legacy_canary_reason"], "guard_error_scoped_contact")
        self.assertEqual(smtp_reply.call_count, 0)
        self.assertEqual(unisender_send.call_count, 0)
        self.assertEqual(bitrix_create.call_count, 0)
        self.assertEqual(qualify.call_count, 0)

    def _run_poll(self, module, state, reply_data, *, bounce=False):
        with (
            patch.object(module, "_load_state", return_value=state),
            patch.object(module, "_save_state") as save_state,
            patch.object(module, "_tg"),
            patch.object(module, "_hub_inbound", return_value=None),
            patch.object(module, "_hub_qualification", return_value=None),
            patch("lead_factory.legacy_shadow.capture_campaign_reply"),
            patch("tb_mail.fetch_recent", return_value=[reply_data]),
            patch("tb_mail.is_bounce", return_value=bounce),
            patch("tb_mail.send_reply", return_value="<followup@example.test>") as smtp_reply,
            patch("tb_unisender.send") as unisender_send,
            patch("tb_bitrix.create_lead", return_value=999) as bitrix_create,
            patch("tb_outreach.suppress") as suppress,
            patch.object(module.reply_qualification, "qualify", return_value={
                "decision": "quote", "priority": "A", "summary": "test", "facts": [], "score": 100,
            }) as qualify,
        ):
            module.cmd_poll.__wrapped__(object())
        return save_state, smtp_reply, unisender_send, bitrix_create, qualify, suppress

    def test_guarded_human_replies_never_reach_legacy_writers_or_cadence(self):
        # Dealer exercises the automatic follow-up branch; builder has already
        # sent a qualifier so it would otherwise enter the direct Bitrix branch.
        cases = (
            (dealer, "dealers", "dealer_outreach", False),
            (builder, "builders", "builder_outreach", True),
        )
        for module, bucket, campaign_id, qualification_sent in cases:
            with self.subTest(campaign_id=campaign_id):
                email = "canary@example.test"
                rec = _record(email, qualification_sent=qualification_sent)
                state = {"_meta": {"enabled": True, "send_days": []}, bucket: {email: rec}}
                incoming = _reply(email)
                guard = LegacyCanaryGuard(writers_enabled=True)
                guard.arm(LegacyCanaryScope(
                    mailbox="\\Inbox",
                    campaign_id=campaign_id,
                    contact_address=email,
                    thread_id=incoming["in_reply_to"],
                ))
                with patch.object(legacy_canary_guard, "DEFAULT_LEGACY_CANARY_GUARD", guard):
                    _, smtp_reply, unisender_send, bitrix_create, qualify, _ = self._run_poll(module, state, incoming)

                self.assertEqual(smtp_reply.call_count, 0)
                self.assertEqual(unisender_send.call_count, 0)
                self.assertEqual(bitrix_create.call_count, 0)
                self.assertEqual(qualify.call_count, 0)
                self.assertTrue(rec["got_reply"])
                self.assertEqual(rec["status"], "canary_guarded")
                if module is dealer:
                    with patch.object(module, "_suppressed_emails", return_value=set()):
                        self.assertEqual(module._due_followups(state, dt.date(2026, 8, 18)), [])
                else:
                    with patch("tb_outreach.is_suppressed", return_value=False):
                        self.assertEqual(module._due_followups(state, dt.date(2026, 8, 18)), [])

    def test_non_canary_reply_keeps_legacy_followup_behaviour(self):
        email = "ordinary@example.test"
        rec = _record(email)
        state = {"_meta": {"enabled": True, "send_days": []}, "dealers": {email: rec}}
        incoming = _reply(email)
        with (
            patch.object(legacy_canary_guard, "DEFAULT_LEGACY_CANARY_GUARD", LegacyCanaryGuard()),
            patch.object(dealer.reply_qualification, "inspect_first_reply", return_value=({}, "", {
                "readable_files": [], "unreadable_files": [],
            })),
        ):
            _, smtp_reply, unisender_send, bitrix_create, qualify, _ = self._run_poll(dealer, state, incoming)

        self.assertEqual(smtp_reply.call_count, 1)
        self.assertEqual(unisender_send.call_count, 0)
        self.assertEqual(bitrix_create.call_count, 0)
        self.assertEqual(qualify.call_count, 0)
        self.assertTrue(rec["got_reply"])
        self.assertEqual(rec["status"], "awaiting_qualification")

    def test_message_id_format_and_wrong_or_missing_thread_are_closed_for_armed_contact(self):
        email = "canary@example.test"
        variants = (
            (" <OUTBOUND@EXAMPLE.TEST> ", "explicit_canary"),
            ("<unrelated@example.test>", "AMBIGUOUS_CANARY"),
            ("", "AMBIGUOUS_CANARY"),
        )
        for thread, expected_reason in variants:
            with self.subTest(thread=thread or "missing"):
                rec = _record(email)
                state = {"_meta": {"enabled": True, "send_days": []}, "dealers": {email: rec}}
                incoming = _reply(email)
                incoming["in_reply_to"] = thread
                incoming["references"] = ""
                guard = LegacyCanaryGuard(writers_enabled=True)
                guard.arm(LegacyCanaryScope(
                    mailbox="\\Inbox",
                    campaign_id="dealer_outreach",
                    contact_address=email,
                    thread_id=" <outbound@example.test> ",
                ))
                with patch.object(legacy_canary_guard, "DEFAULT_LEGACY_CANARY_GUARD", guard):
                    _, smtp_reply, unisender_send, bitrix_create, qualify, _ = self._run_poll(
                        dealer, state, incoming
                    )

                self.assertEqual(rec["status"], "canary_guarded")
                self.assertEqual(rec["legacy_canary_reason"], expected_reason)
                self.assertEqual(smtp_reply.call_count, 0)
                self.assertEqual(unisender_send.call_count, 0)
                self.assertEqual(bitrix_create.call_count, 0)
                self.assertEqual(qualify.call_count, 0)

    def test_armed_auto_reply_is_terminal_and_bounce_unsubscribe_keep_suppression(self):
        for module, bucket, campaign_id in (
            (dealer, "dealers", "dealer_outreach"),
            (builder, "builders", "builder_outreach"),
        ):
            with self.subTest(campaign_id=campaign_id, kind="auto"):
                email = "canary@example.test"
                rec = _record(email)
                state = {"_meta": {"enabled": True, "send_days": []}, bucket: {email: rec}}
                incoming = _reply(email)
                incoming["subject"] = "Automatic reply"
                guard = LegacyCanaryGuard(writers_enabled=True)
                guard.arm(LegacyCanaryScope(
                    mailbox="\\Inbox", campaign_id=campaign_id,
                    contact_address=email, thread_id=incoming["in_reply_to"],
                ))
                with patch.object(legacy_canary_guard, "DEFAULT_LEGACY_CANARY_GUARD", guard):
                    _, smtp_reply, unisender_send, bitrix_create, _, suppress = self._run_poll(
                        module, state, incoming
                    )
                self.assertEqual(rec["status"], "canary_guarded")
                self.assertTrue(rec["got_reply"])
                self.assertEqual(smtp_reply.call_count, 0)
                self.assertEqual(unisender_send.call_count, 0)
                self.assertEqual(bitrix_create.call_count, 0)
                self.assertEqual(suppress.call_count, 0)

            for kind, bounce, body, expected_status in (
                ("bounce", True, "Delivery failed", "bounce"),
                ("unsubscribe", False, "Пожалуйста, не пишите", "unsub"),
            ):
                with self.subTest(campaign_id=campaign_id, kind=kind):
                    email = "canary@example.test"
                    rec = _record(email)
                    state = {"_meta": {"enabled": True, "send_days": []}, bucket: {email: rec}}
                    incoming = _reply(email)
                    incoming["body"] = body
                    guard = LegacyCanaryGuard(writers_enabled=True)
                    guard.arm(LegacyCanaryScope(
                        mailbox="\\Inbox", campaign_id=campaign_id,
                        contact_address=email, thread_id=incoming["in_reply_to"],
                    ))
                    with patch.object(legacy_canary_guard, "DEFAULT_LEGACY_CANARY_GUARD", guard):
                        _, smtp_reply, unisender_send, bitrix_create, _, suppress = self._run_poll(
                            module, state, incoming, bounce=bounce
                        )
                    self.assertEqual(rec["status"], expected_status)
                    self.assertEqual(suppress.call_count, 1)
                    self.assertEqual(smtp_reply.call_count, 0)
                    self.assertEqual(unisender_send.call_count, 0)
                    self.assertEqual(bitrix_create.call_count, 0)

    def test_canary_guarded_status_never_returns_to_due_followups_after_reply_flag_reset(self):
        email = "canary@example.test"
        dealer_state = {"_meta": {"enabled": True, "send_days": []}, "dealers": {
            email: {**_record(email), "status": "canary_guarded", "got_reply": False},
        }}
        builder_state = {"_meta": {"enabled": True, "send_days": []}, "builders": {
            email: {**_record(email), "status": "canary_guarded", "got_reply": False},
        }}
        with patch.object(dealer, "_suppressed_emails", return_value=set()):
            self.assertEqual(dealer._due_followups(dealer_state, dt.date(2026, 8, 18)), [])
        with patch("tb_outreach.is_suppressed", return_value=False):
            self.assertEqual(builder._due_followups(builder_state, dt.date(2026, 8, 18)), [])


class DurableLegacyCanaryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "durable-canary.sqlite3")
        self.store.init()
        company, _ = self.store.create_company(name="Fixture", inn="7701000033")
        project, _ = self.store.create_project(
            lf_company_id=company["lf_company_id"], source="fixture", external_key="project"
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            lf_project_id=project["lf_project_id"],
            source="fixture",
            external_key="opportunity",
        )
        self.opportunity_id = opportunity["lf_opportunity_id"]
        self.control = CanaryControl(self.store)
        self.run_id = self.control.create_run(created_by="owner")
        self.control.activate_run(self.run_id, actor="owner", evidence_ref="stage://activate")
        self.member_id = self.control.arm_scope(
            self.run_id,
            mailbox="INBOX",
            campaign_id="dealer_outreach",
            contact_address="canary@example.test",
            canonical_thread="<outbound@example.test>",
            lf_opportunity_id=opportunity["lf_opportunity_id"],
            armed_by="owner",
            evidence_ref="stage://arm",
        )
        self.control.create_approval(
            self.run_id, cumulative_cap=1, approver="owner", evidence_ref="stage://approval"
        )
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
            )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _context(thread="<outbound@example.test>"):
        return LegacyCanaryScope(
            mailbox="\\Inbox",
            campaign_id="DEALER_OUTREACH",
            contact_address="CANARY@example.test",
            thread_id=thread,
        )

    def _stage_bound_pair(self):
        interaction = InboundIntake(self.store).ingest(
            InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                external_message_id="<quarantine-inbound@example.test>",
                uid="quarantine-uid",
                uid_validity="100",
                from_address="canary@example.test",
                contact_address="canary@example.test",
                received_at_utc="2026-08-18T09:00:00Z",
                classification=UNROUTED,
                thread_id="<outbound@example.test>",
                evidence_ref="stage://quarantine/inbound",
                create_human_task=False,
            )
        )
        handoff = HumanReplyCrmHandoff(
            self.store,
            lead_payload={"title": "Quarantine fixture"},
            activity_payload={"title": "Review reply", "responsible_id": "7"},
            canary_control=self.control,
            canary_run_id=self.run_id,
            canary_member_id=self.member_id,
        )
        return InboundRouter(self.store, human_reply_handoff=handoff).route(
            InboundRouteDecision(
                interaction_id=interaction.interaction_id,
                decision_id="quarantine-route",
                classification="HUMAN_REPLY",
                contact_address="canary@example.test",
                campaign_id="dealer_outreach",
                mailbox="INBOX",
                lf_opportunity_id=self.opportunity_id,
                rule_version="quarantine-test/v1",
                evidence_ref="stage://quarantine/route",
            )
        )

    def test_restart_reads_active_scope_from_store_and_closes_wrong_thread(self):
        # A new selector simulates the fresh Python process used by scheduled
        # dealer/builder polls; no in-memory arming is involved.
        restarted = DurableLegacyCanarySelector(FactoryStore(self.store.path))
        exact = assess_legacy_canary(self._context(), selector=restarted)
        wrong = assess_legacy_canary(
            self._context("<other@example.test>"), selector=restarted
        )
        self.assertTrue(exact.block_legacy_writers)
        self.assertEqual(exact.reason, "durable_explicit_canary")
        self.assertEqual((exact.run_id, exact.member_id), (self.run_id, self.member_id))
        self.assertTrue(wrong.block_legacy_writers)
        self.assertEqual(wrong.reason, "AMBIGUOUS_CANARY")

    def test_marker_fails_closed_if_durable_scope_becomes_unreadable(self):
        broken = Mock()
        broken.assess.side_effect = legacy_canary_guard.DurableCanaryStoreError("offline")
        rec = {
            "legacy_canary_run_id": self.run_id,
            "legacy_canary_member_id": self.member_id,
        }
        decision = assess_legacy_canary(self._context(), selector=broken, record=rec)
        self.assertTrue(decision.block_legacy_writers)
        self.assertEqual(decision.reason, "durable_guard_error_marked_scope")

    def test_unmarked_reply_fails_closed_when_existing_stage_db_is_unreadable(self):
        selector = DurableLegacyCanarySelector(FactoryStore(self.store.path))
        with patch.object(selector.store, "connect", side_effect=sqlite3.OperationalError("locked")):
            decision = assess_legacy_canary(self._context(), selector=selector, record={})
            self.assertTrue(selector.has_active_approved_canary())
        self.assertTrue(decision.block_legacy_writers)
        self.assertEqual(decision.reason, "durable_guard_error_stage_db")

    def test_campaign_hook_persists_durable_run_and_member_marker(self):
        email = "canary@example.test"
        rec = _record(email)
        state = {"_meta": {"enabled": True, "send_days": []}, "dealers": {email: rec}}
        incoming = _reply(email)
        selector = DurableLegacyCanarySelector(FactoryStore(self.store.path))
        with patch.object(legacy_canary_guard, "DEFAULT_DURABLE_LEGACY_CANARY_SELECTOR", selector):
            _, smtp_reply, unisender_send, bitrix_create, _, _ = LegacyCanaryGuardTests()._run_poll(
                dealer, state, incoming
            )
        self.assertEqual((rec["legacy_canary_run_id"], rec["legacy_canary_member_id"]),
                         (self.run_id, self.member_id))
        self.assertEqual(smtp_reply.call_count, 0)
        self.assertEqual(unisender_send.call_count, 0)
        self.assertEqual(bitrix_create.call_count, 0)

    def test_plain_stop_without_bound_operations_releases_hold(self):
        self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="plain stop",
            evidence_ref="stage://stop/plain",
        )
        restarted = DurableLegacyCanarySelector(FactoryStore(self.store.path))
        self.assertFalse(restarted.has_active_approved_canary())
        self.assertFalse(
            assess_legacy_canary(self._context(), selector=restarted).block_legacy_writers
        )

    def test_stopped_ambiguous_operation_stays_quarantined_until_audited_resolution(self):
        routed = self._stage_bound_pair()
        with self.store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN' WHERE operation_id=?",
                (routed.lead_operation_id,),
            )
        self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="ambiguous result",
            evidence_ref="stage://stop/ambiguous",
        )
        restarted = DurableLegacyCanarySelector(FactoryStore(self.store.path))
        self.assertTrue(restarted.has_active_approved_canary())
        decision = assess_legacy_canary(self._context(), selector=restarted)
        self.assertTrue(decision.block_legacy_writers)
        self.assertEqual(decision.reason, "durable_canary_quarantine")
        wrong_thread = assess_legacy_canary(
            self._context("<wrong-thread@example.test>"), selector=restarted
        )
        self.assertTrue(wrong_thread.block_legacy_writers)
        self.assertEqual(wrong_thread.reason, "AMBIGUOUS_CANARY")
        other_contact = LegacyCanaryScope(
            mailbox="INBOX",
            campaign_id="dealer_outreach",
            contact_address="other@example.test",
            thread_id="<outbound@example.test>",
        )
        self.assertFalse(
            assess_legacy_canary(other_contact, selector=restarted).block_legacy_writers
        )

        event_id, created = resolve_canary_operation_quarantine(
            routed.lead_operation_id,
            actor="owner",
            evidence_ref="stage://resolution/lead-absent",
            outcome="REMOTE_ABSENCE_PROVEN",
            store=self.store,
        )
        self.assertTrue(created)
        self.assertTrue(event_id.startswith("lf_event_"))
        self.assertFalse(restarted.has_active_approved_canary())

        same_event_id, created = resolve_canary_operation_quarantine(
            routed.lead_operation_id,
            actor="owner",
            evidence_ref="stage://resolution/lead-absent",
            outcome="REMOTE_ABSENCE_PROVEN",
            store=self.store,
        )
        self.assertEqual((same_event_id, created), (event_id, False))
        with self.assertRaises(IdempotencyConflict):
            resolve_canary_operation_quarantine(
                routed.lead_operation_id,
                actor="owner",
                evidence_ref="stage://resolution/conflicting",
                outcome="REMOTE_PRESENT_RECONCILED",
                store=self.store,
            )

        # A later ambiguous state is not covered by the old state-bound audit.
        for state in ("REVIEW", "CONFLICT_REVIEW", "future_ambiguous"):
            with self.subTest(state=state):
                with self.store.transaction() as con:
                    con.execute(
                        "UPDATE crm_outbox SET state=? WHERE operation_id=?",
                        (state, routed.lead_operation_id),
                    )
                self.assertTrue(restarted.has_active_approved_canary())
                resolve_canary_operation_quarantine(
                    routed.lead_operation_id,
                    actor="owner",
                    evidence_ref=f"stage://resolution/{state.lower()}",
                    outcome="REMOTE_ABSENCE_PROVEN",
                    store=self.store,
                )
                self.assertFalse(restarted.has_active_approved_canary())


class LegacyCanaryOutboxHoldTests(unittest.TestCase):
    def test_reply_outbox_is_held_without_smtp_or_mutation(self):
        import tb_reply_outbox

        data = {"messages": {"<queued@example.test>": {"msgid": "<queued@example.test>"}}}
        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(tb_reply_outbox, "_load", return_value=data),
            patch("tb_mail.deliver_queued_reply") as deliver,
        ):
            result = tb_reply_outbox.retry_pending()
        self.assertTrue(result["blocked"])
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(deliver.call_count, 0)

    def test_bitrix_retry_queue_is_held_without_rest_call(self):
        import tb_bitrix

        data = {"leads": {"queued": {"fields": {"TITLE": "fixture"}}}}
        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(tb_bitrix, "_load_pending", return_value=data),
            patch.object(tb_bitrix, "_call") as rest_call,
        ):
            result = tb_bitrix.retry_pending()
        self.assertTrue(result["blocked"])
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(rest_call.call_count, 0)

    def test_direct_legacy_bitrix_create_is_held_before_rest(self):
        import tb_bitrix

        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(tb_bitrix, "_call") as rest_call,
            patch.object(tb_bitrix, "queue_pending_lead") as queue,
        ):
            result = tb_bitrix.create_lead("fixture", email="buyer@example.test")
            no_queue = tb_bitrix.create_lead("fixture", queue_on_fail=False)
        self.assertIsNone(result)
        self.assertIsNone(no_queue)
        self.assertEqual(rest_call.call_count, 0)
        self.assertEqual(queue.call_count, 1)
        self.assertEqual(queue.call_args.args[1], "factory_canary_hold")

    def test_raw_bitrix_is_default_denied_even_for_inventoried_reads(self):
        import tb_bitrix

        class Response:
            def json(self):
                return {"result": []}

        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(tb_bitrix, "_WH", "https://fixture.invalid/rest/1/token"),
            patch.object(tb_bitrix.requests, "post", return_value=Response()) as rest,
        ):
            read = tb_bitrix._call("crm.lead.list", {"filter": {}})
            held = [
                tb_bitrix._call("batch", {"cmd": {"write": "crm.lead.add?fields[TITLE]=fixture"}}),
                tb_bitrix._call("crm.future.inspect", {}),
                tb_bitrix._call("CrM.LeAd.AdD", {"fields": {"TITLE": "fixture"}}),
            ]
        for result in [read, *held]:
            self.assertEqual(result["error"], "MDOS_V7_DEFAULT_DENY")
        self.assertEqual(rest.call_count, 0)

    def test_raw_bitrix_unknown_method_is_default_denied_without_canary(self):
        import tb_bitrix

        class Response:
            def json(self):
                return {"result": "normal"}

        with (
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=False),
            patch.object(tb_bitrix, "_WH", "https://fixture.invalid/rest/1/token"),
            patch.object(tb_bitrix.requests, "post", return_value=Response()) as rest,
        ):
            result = tb_bitrix._call("future.method", {})
        self.assertEqual(result["error"], "MDOS_V7_DEFAULT_DENY")
        self.assertEqual(rest.call_count, 0)

    def test_raw_bitrix_retry_is_denied_before_hold_or_transport(self):
        import tb_bitrix

        class Response:
            def json(self):
                return {"result": "must-not-run"}

        with (
            patch(
                "lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes",
                side_effect=[False, True],
            ) as hold,
            patch.object(tb_bitrix, "_WH", "https://fixture.invalid/rest/1/token"),
            patch.object(
                tb_bitrix.requests,
                "post",
                side_effect=[OSError("first attempt failed"), Response()],
            ) as rest,
            patch.object(tb_bitrix.time, "sleep"),
        ):
            result = tb_bitrix._call("crm.lead.add", {"fields": {"TITLE": "fixture"}})

        self.assertEqual(result["error"], "MDOS_V7_DEFAULT_DENY")
        self.assertEqual(hold.call_count, 0)
        self.assertEqual(rest.call_count, 0)

    def test_legacy_document_attach_is_held_before_rest(self):
        import tb_leaddocs

        with (
            patch(
                "lead_factory.mdos_v7.manual_egress.assert_external_allowed",
                return_value=None,
            ),
            patch("lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes", return_value=True),
            patch.object(tb_leaddocs.requests, "post") as rest,
        ):
            attached = tb_leaddocs._bitrix_attach(
                1, "fixture.pdf", b"fixture", "sender@example.test", "fixture"
            )
        self.assertFalse(attached)
        self.assertEqual(rest.call_count, 0)

    def test_legacy_document_retry_cannot_cross_hold_activation(self):
        import tb_bitrix
        import tb_leaddocs

        class Response:
            def json(self):
                return {"result": "must-not-run"}

        with (
            patch(
                "lead_factory.mdos_v7.manual_egress.assert_external_allowed",
                return_value=None,
            ),
            patch(
                "lead_factory.legacy_canary_guard.legacy_canary_holds_legacy_outboxes",
                side_effect=[False, True],
            ) as hold,
            patch.object(tb_bitrix, "_WH", "https://fixture.invalid/rest/1/token"),
            patch.object(
                tb_leaddocs.requests,
                "post",
                side_effect=[OSError("first attempt failed"), Response()],
            ) as rest,
        ):
            attached = tb_leaddocs._bitrix_attach(
                1, "fixture.pdf", b"fixture", "sender@example.test", "fixture"
            )

        self.assertFalse(attached)
        self.assertEqual(hold.call_count, 2)
        self.assertEqual(rest.call_count, 1)


if __name__ == "__main__":
    unittest.main()
