from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lead_factory.commercial_handoff import CommercialOpportunityHandoff
from lead_factory.commercial_spine import (
    NormalizedOpportunityIntake,
    OpportunityLifecycle,
    OpportunityState,
)
from lead_factory.crm_identity import CrmActorBindingRegistry
from lead_factory.ids import payload_hash
from lead_factory.operator_call_workflow import (
    CallAnalysisProposal,
    CallWorkflowState,
    CommercialDisposition,
    NextActionCode,
    OperatorCallBindingRequired,
    OperatorCallConfirmation,
    OperatorCallWorkflow,
    OperatorCallWorkflowConflict,
    OperatorCallWorkflowError,
    RecordingNoticeStatus,
    TechnicalDisposition,
)
from lead_factory.store import FactoryStore


OBSERVED = "2026-08-30T09:00:00Z"
CLOCK = datetime(2026, 8, 30, 9, 1, tzinfo=timezone.utc)
TRANSCRIPT_SHA = "a" * 64
ANALYSIS_SHA = "b" * 64
SPANS_SHA = "c" * 64


class OperatorCallWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "operator-call.sqlite3")
        self.store.init()
        CrmActorBindingRegistry(self.store).register_verified(
            connector="bitrix",
            local_actor="sales_operator",
            remote_actor_id="7001",
            evidence_ref="offline-fixture:bitrix-user-readback",
            verified_by="offline_test",
        )
        self.workflow = OperatorCallWorkflow(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def _handoff(self, suffix: str = "one"):
        normalized = NormalizedOpportunityIntake(self.store).ingest(
            producer="fixture_source",
            external_key=f"project-{suffix}",
            idempotency_key=f"source-{suffix}",
            payload={"fixture_version": 1, "suffix": suffix},
            evidence_ref=f"evidence://source/{suffix}",
            observed_at_utc=OBSERVED,
            company_name=f"Fixture Company {suffix}",
            company_inn=f"7700000{len(suffix):03d}",
            company_domain=f"{suffix}.fixture.example",
            contact_name="Fixture Buyer",
            contact_email=f"buyer-{suffix}@fixture.example",
            contact_role="buyer",
            project_title=f"Fixture Project {suffix}",
            project_region="moscow",
            product_key="aluminium",
        )
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
                occurred_at_utc=f"2026-08-30T09:00:{index:02d}Z",
            )
        handoff = CommercialOpportunityHandoff(
            self.store,
            assignee="sales_operator",
            clock=lambda: CLOCK,
        ).stage(lf_opportunity_id=normalized.lf_opportunity_id)
        return normalized, handoff

    def _completed_call(self, entry_id: str, call_id: str):
        return self.workflow.record_call_completed(
            mango_entry_id=entry_id,
            mango_call_id=call_id,
            seq=1,
            direction="OUTBOUND",
            started_at_utc="2026-08-30T10:00:00Z",
            completed_at_utc="2026-08-30T10:04:00Z",
            duration_seconds=240,
            evidence_ref=f"evidence://mango/call/{call_id}",
        )

    def _bound_call(self, suffix: str = "one"):
        normalized, handoff = self._handoff(suffix)
        entry_id = f"entry-{suffix}"
        self._completed_call(entry_id, f"call-{suffix}")
        result = self.workflow.bind_bitrix_activity(
            mango_entry_id=entry_id,
            bitrix_call_id=f"bitrix-call-{suffix}",
            crm_activity_id=f"activity-{suffix}",
            lf_opportunity_id=normalized.lf_opportunity_id,
            lf_task_id=handoff.task_id,
            operator_actor="sales_operator",
            evidence_ref=f"evidence://bitrix/call/{suffix}",
        )
        return normalized, handoff, entry_id, result

    def _transcript(self, entry_id: str, suffix: str = "one"):
        self.workflow.record_recording_ready(
            mango_entry_id=entry_id,
            mango_call_id=f"call-{suffix}",
            mango_recording_id=f"recording-{suffix}",
            seq=1,
            duration_seconds=230,
            evidence_ref=f"evidence://mango/recording/{suffix}",
        )
        return self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id=f"recording-{suffix}",
            transcript_revision=1,
            transcript_sha256=TRANSCRIPT_SHA,
            segment_count=12,
            speaker_count=2,
            language="ru-RU",
            evidence_ref=f"evidence://transcript/{suffix}",
        )

    def _proposal(self, session_id: str, *, draft_id: str = "draft-one"):
        return CallAnalysisProposal(
            call_session_id=session_id,
            draft_id=draft_id,
            transcript_set_sha256=(
                self.workflow.current_transcript_set_sha256(session_id)
            ),
            analysis_sha256=ANALYSIS_SHA,
            prompt_version="call-v1",
            model_id="local-fixture",
            confidence_bps=8200,
            proposed_commercial_disposition=CommercialDisposition.CALLBACK_REQUESTED,
            proposed_next_action=NextActionCode.CALL_BACK,
            proposed_next_action_at_utc="2026-08-31T09:00:00Z",
            flags=(),
            evidence_spans_sha256=SPANS_SHA,
            evidence_ref="evidence://analysis/draft-one",
        )

    @staticmethod
    def _gold_confirmation(session_id: str, *, draft_id: str = "draft-one"):
        return OperatorCallConfirmation(
            call_session_id=session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.CONNECTED,
            commercial_disposition=(
                CommercialDisposition.QUALIFIED_FOR_GOLD_REVIEW
            ),
            next_action=NextActionCode.GOLD_REVIEW,
            next_action_at_utc="2026-08-30T11:00:00Z",
            next_action_owner="sales_operator",
            reason_code="QUALIFIED",
            request_gold_review=True,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.CONFIRMED,
            evidence_ref="evidence://operator/confirmation-one",
            draft_id=draft_id,
        )

    def test_out_of_order_evidence_and_multiple_recordings_converge_after_binding(self):
        entry_id = "entry-transfer"
        session_id = self.workflow.call_session_id(entry_id)
        self.workflow.record_recording_ready(
            mango_entry_id=entry_id,
            mango_call_id="call-leg-two",
            mango_recording_id="recording-two",
            seq=2,
            duration_seconds=90,
            evidence_ref="evidence://mango/recording/two",
        )
        self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id="recording-two",
            transcript_revision=1,
            transcript_sha256=TRANSCRIPT_SHA,
            segment_count=5,
            speaker_count=2,
            language="ru",
            evidence_ref="evidence://transcript/two",
        )
        self.assertEqual(
            self.workflow.snapshot(session_id).state,
            CallWorkflowState.UNBOUND_EVIDENCE,
        )

        normalized, handoff = self._handoff("transfer")
        self._completed_call(entry_id, "call-leg-one")
        self.workflow.record_call_completed(
            mango_entry_id=entry_id,
            mango_call_id="call-leg-two",
            seq=2,
            direction="OUTBOUND",
            started_at_utc="2026-08-30T10:04:00Z",
            completed_at_utc="2026-08-30T10:06:00Z",
            duration_seconds=120,
            evidence_ref="evidence://mango/call/leg-two",
        )
        self.workflow.record_recording_ready(
            mango_entry_id=entry_id,
            mango_call_id="call-leg-one",
            mango_recording_id="recording-one",
            seq=1,
            duration_seconds=230,
            evidence_ref="evidence://mango/recording/one",
        )
        self.assertEqual(
            self.workflow.snapshot(session_id).state,
            CallWorkflowState.UNBOUND_CALL,
        )
        self.workflow.bind_bitrix_activity(
            mango_entry_id=entry_id,
            bitrix_call_id="bitrix-call-transfer",
            crm_activity_id="activity-transfer",
            lf_opportunity_id=normalized.lf_opportunity_id,
            lf_task_id=handoff.task_id,
            operator_actor="sales_operator",
            evidence_ref="evidence://bitrix/call/transfer",
        )

        snapshot = self.workflow.snapshot(session_id)
        self.assertEqual(snapshot.state, CallWorkflowState.RECORDING_READY)
        self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id="recording-one",
            transcript_revision=1,
            transcript_sha256="d" * 64,
            segment_count=8,
            speaker_count=2,
            language="ru",
            evidence_ref="evidence://transcript/one",
        )
        snapshot = self.workflow.snapshot(session_id)
        self.assertEqual(snapshot.state, CallWorkflowState.TRANSCRIPT_READY)
        self.assertEqual(snapshot.call_count, 2)
        self.assertEqual(snapshot.recording_count, 2)
        self.assertEqual(snapshot.transcript_count, 2)
        self.assertEqual(len(snapshot.transcript_set_sha256), 64)
        self.assertEqual(snapshot.lf_opportunity_id, normalized.lf_opportunity_id)

    def test_analysis_and_gold_confirmation_are_idempotent_and_review_only(self):
        normalized, handoff, entry_id, bound = self._bound_call()
        self._transcript(entry_id)
        proposal = self._proposal(bound.call_session_id)
        first_draft = self.workflow.record_analysis_draft(proposal)
        replay_draft = self.workflow.record_analysis_draft(proposal)
        self.assertTrue(first_draft.created)
        self.assertFalse(replay_draft.created)

        confirmation = self._gold_confirmation(bound.call_session_id)
        first = self.workflow.confirm_disposition(confirmation)
        replay = self.workflow.confirm_disposition(confirmation)
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.state, CallWorkflowState.REVIEW_REQUIRED)

        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(snapshot.review_reasons, ("GOLD_REVIEW",))
        with self.store.transaction() as con:
            opportunity = con.execute(
                "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                (normalized.lf_opportunity_id,),
            ).fetchone()
            task = con.execute(
                "SELECT status,resolution FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
        self.assertEqual(opportunity["status"], OpportunityState.HUMAN_REPLY.value)
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["resolution"], "")

    def test_manual_dnc_creates_suppression_review_without_canonical_suppression(self):
        _normalized, handoff, _entry_id, bound = self._bound_call("dnc")
        confirmation = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.CONNECTED,
            commercial_disposition=CommercialDisposition.DO_NOT_CONTACT,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="CUSTOMER_DNC",
            request_gold_review=False,
            request_suppression_review=True,
            recording_notice_status=RecordingNoticeStatus.UNKNOWN,
            evidence_ref="evidence://operator/dnc",
        )
        result = self.workflow.confirm_disposition(confirmation)
        self.assertEqual(result.state, CallWorkflowState.REVIEW_REQUIRED)
        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(
            snapshot.review_reasons,
            ("RECORDING_NOTICE_REVIEW", "SUPPRESSION_REVIEW"),
        )
        with self.store.transaction() as con:
            suppressions = con.execute(
                "SELECT COUNT(*) FROM suppression_entries"
            ).fetchone()[0]
            task = con.execute(
                "SELECT status FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
        self.assertEqual(suppressions, 0)
        self.assertEqual(task["status"], "IN_PROGRESS")

    def test_binding_and_confirmation_fail_closed_on_wrong_scope(self):
        normalized, handoff = self._handoff("scope")
        completed = self._completed_call("entry-scope", "call-scope")
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.bind_bitrix_activity(
                mango_entry_id="entry-scope",
                bitrix_call_id="bitrix-call-scope",
                crm_activity_id="activity-scope",
                lf_opportunity_id=normalized.lf_opportunity_id,
                lf_task_id=handoff.task_id,
                operator_actor="another_operator",
                evidence_ref="evidence://bitrix/call/scope",
            )
        with self.assertRaises(OperatorCallBindingRequired):
            self.workflow.confirm_disposition(
                OperatorCallConfirmation(
                    call_session_id=completed.call_session_id,
                    confirmation_version=1,
                    operator_actor="sales_operator",
                    technical_disposition=TechnicalDisposition.NO_ANSWER,
                    commercial_disposition=CommercialDisposition.NOT_ASSESSED,
                    next_action=NextActionCode.CALL_BACK,
                    next_action_at_utc="2026-08-31T09:00:00Z",
                    next_action_owner="sales_operator",
                    reason_code="NO_ANSWER",
                    request_gold_review=False,
                    request_suppression_review=False,
                    recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                    evidence_ref="evidence://operator/unbound",
                )
            )

    def test_changed_replays_and_cross_call_draft_reuse_conflict(self):
        _normalized, _handoff, entry_id, first = self._bound_call("first")
        self._transcript(entry_id, "first")
        self.workflow.record_analysis_draft(
            self._proposal(first.call_session_id, draft_id="shared-draft")
        )

        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.record_call_completed(
                mango_entry_id=entry_id,
                mango_call_id="call-first",
                seq=1,
                direction="OUTBOUND",
                started_at_utc="2026-08-30T10:00:00Z",
                completed_at_utc="2026-08-30T10:04:00Z",
                duration_seconds=239,
                evidence_ref="evidence://mango/call/first",
            )

        _normalized2, _handoff2, entry_id2, second = self._bound_call("second")
        self._transcript(entry_id2, "second")
        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.record_analysis_draft(
                self._proposal(second.call_session_id, draft_id="shared-draft")
            )

    def test_bitrix_identity_is_one_to_one_and_binding_replay_is_terminal_safe(self):
        _normalized, _handoff, _entry_id, first = self._bound_call("binding-one")
        terminal = OperatorCallConfirmation(
            call_session_id=first.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.WRONG_NUMBER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="WRONG_NUMBER",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/binding-terminal",
        )
        self.workflow.confirm_disposition(terminal)
        replay = self.workflow.bind_bitrix_activity(
            mango_entry_id="entry-binding-one",
            bitrix_call_id="bitrix-call-binding-one",
            crm_activity_id="activity-binding-one",
            lf_opportunity_id=self.workflow.snapshot(first.call_session_id).lf_opportunity_id,
            lf_task_id=self.workflow.snapshot(first.call_session_id).lf_task_id,
            operator_actor="sales_operator",
            evidence_ref="evidence://bitrix/call/binding-one",
        )
        self.assertFalse(replay.created)

        normalized2, handoff2 = self._handoff("binding-two")
        self._completed_call("entry-binding-two", "call-binding-two")
        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.bind_bitrix_activity(
                mango_entry_id="entry-binding-two",
                bitrix_call_id="bitrix-call-binding-one",
                crm_activity_id="activity-binding-two",
                lf_opportunity_id=normalized2.lf_opportunity_id,
                lf_task_id=handoff2.task_id,
                operator_actor="sales_operator",
                evidence_ref="evidence://bitrix/call/binding-two",
            )

        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.confirm_disposition(
                OperatorCallConfirmation(
                    call_session_id=first.call_session_id,
                    confirmation_version=2,
                    operator_actor="sales_operator",
                    technical_disposition=TechnicalDisposition.CONNECTED,
                    commercial_disposition=CommercialDisposition.NO_CURRENT_NEED,
                    next_action=NextActionCode.NONE,
                    next_action_at_utc="",
                    next_action_owner="",
                    reason_code="NO_CURRENT_NEED",
                    request_gold_review=False,
                    request_suppression_review=False,
                    recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                    evidence_ref="evidence://operator/terminal-revision",
                )
            )

    def test_orphan_and_late_transcripts_block_stale_analysis(self):
        _normalized, _handoff, entry_id, bound = self._bound_call("stale")
        self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id="recording-stale",
            transcript_revision=1,
            transcript_sha256=TRANSCRIPT_SHA,
            segment_count=4,
            speaker_count=2,
            language="ru",
            evidence_ref="evidence://transcript/stale",
        )
        orphan = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(orphan.state, CallWorkflowState.REVIEW_REQUIRED)
        self.assertIn("ORPHAN_TRANSCRIPT", orphan.review_reasons)
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.current_transcript_set_sha256(bound.call_session_id)

        self.workflow.record_recording_ready(
            mango_entry_id=entry_id,
            mango_call_id="call-stale",
            mango_recording_id="recording-stale",
            seq=1,
            duration_seconds=100,
            evidence_ref="evidence://mango/recording/stale",
        )
        proposal = self._proposal(bound.call_session_id, draft_id="draft-stale")
        self.workflow.record_analysis_draft(proposal)
        self.workflow.record_recording_ready(
            mango_entry_id=entry_id,
            mango_call_id="call-stale",
            mango_recording_id="recording-late",
            seq=2,
            duration_seconds=30,
            evidence_ref="evidence://mango/recording/late",
        )
        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(snapshot.state, CallWorkflowState.REVIEW_REQUIRED)
        self.assertIn("STALE_ANALYSIS_DRAFT", snapshot.review_reasons)
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.confirm_disposition(
                self._gold_confirmation(
                    bound.call_session_id, draft_id="draft-stale"
                )
            )

    def test_recording_requires_notice_and_evidence_identity_is_immutable(self):
        _normalized, _handoff, entry_id, bound = self._bound_call("notice")
        self._transcript(entry_id, "notice")
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.confirm_disposition(
                OperatorCallConfirmation(
                    call_session_id=bound.call_session_id,
                    confirmation_version=1,
                    operator_actor="sales_operator",
                    technical_disposition=TechnicalDisposition.NO_ANSWER,
                    commercial_disposition=CommercialDisposition.NOT_ASSESSED,
                    next_action=NextActionCode.CALL_BACK,
                    next_action_at_utc="2026-08-31T09:00:00Z",
                    next_action_owner="sales_operator",
                    reason_code="NO_ANSWER",
                    request_gold_review=False,
                    request_suppression_review=False,
                    recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                    evidence_ref="evidence://operator/notice",
                )
            )
        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.record_recording_ready(
                mango_entry_id=entry_id,
                mango_call_id="call-notice",
                mango_recording_id="recording-notice",
                seq=1,
                duration_seconds=230,
                evidence_ref="evidence://mango/recording/different-proof",
            )

    def test_open_review_survives_corrected_terminal_disposition(self):
        _normalized, handoff, _entry_id, bound = self._bound_call("review-correction")
        first = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.CONNECTED,
            commercial_disposition=CommercialDisposition.DO_NOT_CONTACT,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="CUSTOMER_DNC",
            request_gold_review=False,
            request_suppression_review=True,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/review-correction-one",
        )
        self.workflow.confirm_disposition(first)
        corrected = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=2,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.CONNECTED,
            commercial_disposition=CommercialDisposition.NO_CURRENT_NEED,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="NO_CURRENT_NEED",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/review-correction-two",
        )
        self.workflow.confirm_disposition(corrected)

        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(snapshot.confirmation_version, 2)
        self.assertEqual(snapshot.state, CallWorkflowState.REVIEW_REQUIRED)
        self.assertIn("SUPPRESSION_REVIEW", snapshot.review_reasons)
        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,resolution FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["resolution"], "")

    def test_task_reassignment_invalidates_operator_binding(self):
        _normalized, handoff, _entry_id, bound = self._bound_call("reassigned")
        with self.store.transaction() as con:
            con.execute(
                "UPDATE human_tasks SET assigned_to='replacement_operator' "
                "WHERE lf_task_id=?",
                (handoff.task_id,),
            )
        confirmation = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.NO_ANSWER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.CALL_BACK,
            next_action_at_utc="2026-08-31T09:00:00Z",
            next_action_owner="sales_operator",
            reason_code="NO_ANSWER",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/reassigned",
        )
        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.confirm_disposition(confirmation)
        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.reconcile_human_task(bound.call_session_id)

    def test_orphan_recording_blocks_analysis_until_call_leg_arrives(self):
        _normalized, _handoff, entry_id, bound = self._bound_call("orphan-leg")
        self.workflow.record_recording_ready(
            mango_entry_id=entry_id,
            mango_call_id="late-call-leg",
            mango_recording_id="late-leg-recording",
            seq=2,
            duration_seconds=40,
            evidence_ref="evidence://mango/recording/late-leg",
        )
        self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id="late-leg-recording",
            transcript_revision=1,
            transcript_sha256=TRANSCRIPT_SHA,
            segment_count=3,
            speaker_count=2,
            language="ru",
            evidence_ref="evidence://transcript/late-leg",
        )
        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(snapshot.state, CallWorkflowState.REVIEW_REQUIRED)
        self.assertIn("ORPHAN_RECORDING", snapshot.review_reasons)
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.current_transcript_set_sha256(bound.call_session_id)

        self.workflow.record_call_completed(
            mango_entry_id=entry_id,
            mango_call_id="late-call-leg",
            seq=2,
            direction="OUTBOUND",
            started_at_utc="2026-08-30T10:04:00Z",
            completed_at_utc="2026-08-30T10:05:00Z",
            duration_seconds=60,
            evidence_ref="evidence://mango/call/late-leg",
        )
        converged = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(converged.state, CallWorkflowState.TRANSCRIPT_READY)
        self.assertEqual(len(converged.transcript_set_sha256), 64)

    def test_reconciliation_repairs_crash_after_confirmation_event(self):
        _normalized, handoff, _entry_id, bound = self._bound_call("repair")
        confirmation = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.WRONG_NUMBER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="WRONG_NUMBER",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/repair",
        )
        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.store.append_event(
            event_type="operator_call_disposition_confirmed",
            aggregate_type="call_session",
            aggregate_id=bound.call_session_id,
            producer="operator_call_workflow",
            idempotency_key=f"operator-confirmed:{bound.call_session_id}:1",
            payload={
                "call_session_id": bound.call_session_id,
                "bitrix_call_id": snapshot.bitrix_call_id,
                "crm_activity_id": snapshot.crm_activity_id,
                "lf_opportunity_id": snapshot.lf_opportunity_id,
                "lf_task_id": snapshot.lf_task_id,
                "confirmation_version": 1,
                "operator_actor": "sales_operator",
                "technical_disposition": TechnicalDisposition.WRONG_NUMBER.value,
                "commercial_disposition": CommercialDisposition.NOT_ASSESSED.value,
                "next_action": NextActionCode.NONE.value,
                "next_action_at_utc": "",
                "next_action_owner": "",
                "reason_code": "WRONG_NUMBER",
                "request_gold_review": False,
                "request_suppression_review": False,
                "recording_notice_status": RecordingNoticeStatus.NOT_APPLICABLE.value,
                "draft_id": "",
                "review_reasons": [],
                "_evidence_ref_sha256": payload_hash(
                    {"evidence_ref": confirmation.evidence_ref}
                ),
            },
            evidence_ref=confirmation.evidence_ref,
            actor=confirmation.operator_actor,
        )

        first_action, completed = self.workflow.reconcile_human_task(
            bound.call_session_id
        )
        self.assertFalse(first_action.changed)
        self.assertIsNotNone(completed)
        self.assertTrue(completed.changed)
        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,resolution FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
        self.assertEqual(task["status"], "COMPLETED")
        self.assertEqual(task["resolution"], "CALL:NOT_ASSESSED")

        replay_first, replay_completed = self.workflow.reconcile_human_task(
            bound.call_session_id
        )
        self.assertFalse(replay_first.changed)
        self.assertIsNotNone(replay_completed)
        self.assertFalse(replay_completed.changed)

    def test_provider_call_exact_replay_has_one_business_effect(self):
        first = self._completed_call("entry-provider-replay", "call-provider-replay")
        replay = self._completed_call("entry-provider-replay", "call-provider-replay")
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        with self.store.transaction() as con:
            count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE producer='operator_call_workflow'
                     AND event_type='call_completed'
                     AND aggregate_id=?""",
                (first.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_transfer_legs_share_one_session_and_one_activity_binding(self):
        normalized, handoff = self._handoff("single-activity")
        entry_id = "entry-single-activity"
        self._completed_call(entry_id, "call-single-activity-one")
        self.workflow.record_call_completed(
            mango_entry_id=entry_id,
            mango_call_id="call-single-activity-two",
            seq=2,
            direction="OUTBOUND",
            started_at_utc="2026-08-30T10:04:00Z",
            completed_at_utc="2026-08-30T10:06:00Z",
            duration_seconds=120,
            evidence_ref="evidence://mango/call/single-activity-two",
        )
        first = self.workflow.bind_bitrix_activity(
            mango_entry_id=entry_id,
            bitrix_call_id="bitrix-call-single-activity",
            crm_activity_id="activity-single-activity",
            lf_opportunity_id=normalized.lf_opportunity_id,
            lf_task_id=handoff.task_id,
            operator_actor="sales_operator",
            evidence_ref="evidence://bitrix/call/single-activity",
        )
        replay = self.workflow.bind_bitrix_activity(
            mango_entry_id=entry_id,
            bitrix_call_id="bitrix-call-single-activity",
            crm_activity_id="activity-single-activity",
            lf_opportunity_id=normalized.lf_opportunity_id,
            lf_task_id=handoff.task_id,
            operator_actor="sales_operator",
            evidence_ref="evidence://bitrix/call/single-activity",
        )
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        snapshot = self.workflow.snapshot(first.call_session_id)
        self.assertEqual(snapshot.call_count, 2)
        with self.store.transaction() as con:
            binding_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE producer='operator_call_workflow'
                     AND event_type='call_bitrix_activity_bound'
                     AND aggregate_id=?""",
                (first.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(binding_count, 1)

    def test_ambiguous_crm_candidates_require_review_before_exact_binding(self):
        normalized, handoff = self._handoff("ambiguous")
        entry_id = "entry-ambiguous"
        completed = self._completed_call(entry_id, "call-ambiguous")
        candidates = ("activity-ambiguous-a", "activity-ambiguous-b")
        candidate_digest = payload_hash(
            {"crm_activity_ids": sorted(candidates)}
        )
        first = self.workflow.record_crm_candidate_review(
            mango_entry_id=entry_id,
            crm_activity_ids=candidates,
            candidate_snapshot_sha256=candidate_digest,
            evidence_ref="evidence://bitrix/candidates/ambiguous",
        )
        replay = self.workflow.record_crm_candidate_review(
            mango_entry_id=entry_id,
            crm_activity_ids=candidates,
            candidate_snapshot_sha256=candidate_digest,
            evidence_ref="evidence://bitrix/candidates/ambiguous",
        )
        self.assertEqual(first.state, CallWorkflowState.REVIEW_REQUIRED)
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        with self.store.transaction() as con:
            binding_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='call_bitrix_activity_bound'
                     AND aggregate_id=?""",
                (completed.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(binding_count, 0)

        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.bind_bitrix_activity(
                mango_entry_id=entry_id,
                bitrix_call_id="bitrix-call-ambiguous",
                crm_activity_id="activity-not-in-snapshot",
                lf_opportunity_id=normalized.lf_opportunity_id,
                lf_task_id=handoff.task_id,
                operator_actor="sales_operator",
                evidence_ref="evidence://bitrix/call/ambiguous-rejected",
            )
        bound = self.workflow.bind_bitrix_activity(
            mango_entry_id=entry_id,
            bitrix_call_id="bitrix-call-ambiguous",
            crm_activity_id="activity-ambiguous-a",
            lf_opportunity_id=normalized.lf_opportunity_id,
            lf_task_id=handoff.task_id,
            operator_actor="sales_operator",
            evidence_ref="evidence://bitrix/call/ambiguous-selected",
        )
        self.assertTrue(bound.created)
        with self.store.transaction() as con:
            resolved_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='call_crm_binding_review_resolved'
                     AND aggregate_id=?""",
                (completed.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(resolved_count, 1)

    def test_manual_confirmation_succeeds_without_ai_draft(self):
        _normalized, handoff, _entry_id, bound = self._bound_call("manual-no-ai")
        result = self.workflow.confirm_disposition(
            OperatorCallConfirmation(
                call_session_id=bound.call_session_id,
                confirmation_version=1,
                operator_actor="sales_operator",
                technical_disposition=TechnicalDisposition.CONNECTED,
                commercial_disposition=CommercialDisposition.NO_CURRENT_NEED,
                next_action=NextActionCode.NONE,
                next_action_at_utc="",
                next_action_owner="",
                reason_code="NO_CURRENT_NEED",
                request_gold_review=False,
                request_suppression_review=False,
                recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                evidence_ref="evidence://operator/manual-no-ai",
            )
        )
        self.assertEqual(result.state, CallWorkflowState.OPERATOR_CONFIRMED)
        with self.store.transaction() as con:
            draft_count = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='call_analysis_draft_recorded'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()[0]
            task = con.execute(
                "SELECT status FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
        self.assertEqual(draft_count, 0)
        self.assertEqual(task["status"], "COMPLETED")

    def test_ai_denied_or_unavailable_does_not_block_manual_confirmation(self):
        _normalized, _handoff, _entry_id, bound = self._bound_call("ai-denied")
        with self.store.transaction() as con:
            before = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='call_analysis_draft_recorded'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(before, 0)

        result = self.workflow.confirm_disposition(
            OperatorCallConfirmation(
                call_session_id=bound.call_session_id,
                confirmation_version=1,
                operator_actor="sales_operator",
                technical_disposition=TechnicalDisposition.CONNECTED,
                commercial_disposition=CommercialDisposition.NO_CURRENT_NEED,
                next_action=NextActionCode.NONE,
                next_action_at_utc="",
                next_action_owner="",
                reason_code="AI_DENIED_MANUAL_CONFIRMATION",
                request_gold_review=False,
                request_suppression_review=False,
                recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                evidence_ref="evidence://operator/ai-denied-manual",
            )
        )
        self.assertEqual(result.state, CallWorkflowState.OPERATOR_CONFIRMED)
        with self.store.transaction() as con:
            after = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='call_analysis_draft_recorded'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(after, 0)

    def test_crm_activity_identity_cannot_bind_two_call_sessions(self):
        _normalized, _handoff, _entry_id, first = self._bound_call("activity-owner")
        normalized2, handoff2 = self._handoff("activity-contender")
        self._completed_call("entry-activity-contender", "call-activity-contender")

        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.bind_bitrix_activity(
                mango_entry_id="entry-activity-contender",
                bitrix_call_id="bitrix-call-activity-contender",
                crm_activity_id="activity-activity-owner",
                lf_opportunity_id=normalized2.lf_opportunity_id,
                lf_task_id=handoff2.task_id,
                operator_actor="sales_operator",
                evidence_ref="evidence://bitrix/call/activity-conflict",
            )
        self.assertEqual(
            self.workflow.snapshot(first.call_session_id).crm_activity_id,
            "activity-activity-owner",
        )

    def test_wrong_actor_rejection_leaves_events_task_and_state_unchanged(self):
        _normalized, handoff, _entry_id, bound = self._bound_call("wrong-actor-stable")
        before_snapshot = self.workflow.snapshot(bound.call_session_id)
        with self.store.transaction() as con:
            before_event_count = con.execute(
                "SELECT COUNT(*) FROM events WHERE aggregate_id=?",
                (bound.call_session_id,),
            ).fetchone()[0]
            before_task = dict(
                con.execute(
                    """SELECT status,assigned_to,due_at_utc,resolution
                       FROM human_tasks WHERE lf_task_id=?""",
                    (handoff.task_id,),
                ).fetchone()
            )

        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.confirm_disposition(
                OperatorCallConfirmation(
                    call_session_id=bound.call_session_id,
                    confirmation_version=1,
                    operator_actor="unassigned_operator",
                    technical_disposition=TechnicalDisposition.NO_ANSWER,
                    commercial_disposition=CommercialDisposition.NOT_ASSESSED,
                    next_action=NextActionCode.CALL_BACK,
                    next_action_at_utc="2026-09-01T09:00:00Z",
                    next_action_owner="unassigned_operator",
                    reason_code="NO_ANSWER",
                    request_gold_review=False,
                    request_suppression_review=False,
                    recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                    evidence_ref="evidence://operator/wrong-actor-stable",
                )
            )

        self.assertEqual(self.workflow.snapshot(bound.call_session_id), before_snapshot)
        with self.store.transaction() as con:
            after_event_count = con.execute(
                "SELECT COUNT(*) FROM events WHERE aggregate_id=?",
                (bound.call_session_id,),
            ).fetchone()[0]
            after_task = dict(
                con.execute(
                    """SELECT status,assigned_to,due_at_utc,resolution
                       FROM human_tasks WHERE lf_task_id=?""",
                    (handoff.task_id,),
                ).fetchone()
            )
        self.assertEqual(after_event_count, before_event_count)
        self.assertEqual(after_task, before_task)

    def test_transcript_revision_makes_prior_analysis_draft_stale(self):
        _normalized, _handoff, entry_id, bound = self._bound_call("revision")
        self._transcript(entry_id, "revision")
        proposal = self._proposal(bound.call_session_id, draft_id="draft-revision")
        self.workflow.record_analysis_draft(proposal)
        self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id="recording-revision",
            transcript_revision=2,
            transcript_sha256="e" * 64,
            segment_count=13,
            speaker_count=2,
            language="ru-RU",
            evidence_ref="evidence://transcript/revision-two",
        )
        confirmation = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.CONNECTED,
            commercial_disposition=CommercialDisposition.CALLBACK_REQUESTED,
            next_action=NextActionCode.CALL_BACK,
            next_action_at_utc="2026-08-31T09:00:00Z",
            next_action_owner="sales_operator",
            reason_code="CALLBACK_REQUESTED",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.CONFIRMED,
            evidence_ref="evidence://operator/revision",
            draft_id="draft-revision",
        )
        with self.assertRaises(OperatorCallWorkflowConflict):
            self.workflow.confirm_disposition(confirmation)

    def test_callback_keeps_task_active_and_projects_owner_due_and_binding_ids(self):
        normalized, handoff, _entry_id, bound = self._bound_call("callback")
        result = self.workflow.confirm_disposition(
            OperatorCallConfirmation(
                call_session_id=bound.call_session_id,
                confirmation_version=1,
                operator_actor="sales_operator",
                technical_disposition=TechnicalDisposition.CONNECTED,
                commercial_disposition=CommercialDisposition.CALLBACK_REQUESTED,
                next_action=NextActionCode.CALL_BACK,
                next_action_at_utc="2026-09-01T08:30:00Z",
                next_action_owner="sales_operator",
                reason_code="CALLBACK_REQUESTED",
                request_gold_review=False,
                request_suppression_review=False,
                recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                evidence_ref="evidence://operator/callback",
            )
        )
        self.assertEqual(result.state, CallWorkflowState.OPERATOR_CONFIRMED)
        with self.store.transaction() as con:
            task = con.execute(
                """SELECT status,assigned_to,due_at_utc,resolution
                   FROM human_tasks WHERE lf_task_id=?""",
                (handoff.task_id,),
            ).fetchone()
            event_row = con.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='operator_call_disposition_confirmed'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["assigned_to"], "sales_operator")
        self.assertEqual(task["due_at_utc"], "2026-09-01T08:30:00Z")
        self.assertEqual(task["resolution"], "")
        payload = json.loads(event_row["payload_json"])
        self.assertEqual(payload["lf_opportunity_id"], normalized.lf_opportunity_id)
        self.assertEqual(payload["lf_task_id"], handoff.task_id)
        self.assertEqual(payload["crm_activity_id"], "activity-callback")
        self.assertEqual(payload["bitrix_call_id"], "bitrix-call-callback")
        self.assertEqual(payload["next_action_owner"], "sales_operator")
        self.assertEqual(payload["next_action_at_utc"], "2026-09-01T08:30:00Z")

    def test_callback_rebinds_to_verified_operator_and_next_confirmation_converges(self):
        CrmActorBindingRegistry(self.store).register_verified(
            connector="bitrix",
            local_actor="callback_operator",
            remote_actor_id="7002",
            evidence_ref="offline-fixture:bitrix-callback-user-readback",
            verified_by="offline_test",
        )
        _normalized, handoff, _entry_id, bound = self._bound_call("callback-rebind")
        callback = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.NO_ANSWER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.CALL_BACK,
            next_action_at_utc="2026-09-01T08:30:00Z",
            next_action_owner="callback_operator",
            reason_code="NO_ANSWER",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/callback-rebind-v1",
        )
        first = self.workflow.confirm_disposition(callback)
        replay = self.workflow.confirm_disposition(callback)
        self.assertTrue(first.created)
        self.assertFalse(replay.created)

        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,assigned_to,due_at_utc FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
            reassignment = con.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='call_operator_reassigned' AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["assigned_to"], "callback_operator")
        self.assertEqual(task["due_at_utc"], "2026-09-01T08:30:00Z")
        reassignment_payload = json.loads(reassignment["payload_json"])
        self.assertEqual(reassignment_payload["from_operator_actor"], "sales_operator")
        self.assertEqual(reassignment_payload["to_operator_actor"], "callback_operator")
        self.assertTrue(reassignment_payload["crm_actor_binding_id"])

        terminal = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=2,
            operator_actor="callback_operator",
            technical_disposition=TechnicalDisposition.NO_ANSWER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="NO_CURRENT_NEED",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/callback-rebind-v2",
        )
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.confirm_disposition(
                OperatorCallConfirmation(
                    **{
                        **terminal.__dict__,
                        "operator_actor": "sales_operator",
                        "evidence_ref": "evidence://operator/callback-old-actor-v2",
                    }
                )
            )
        completed = self.workflow.confirm_disposition(terminal)
        self.assertEqual(completed.state, CallWorkflowState.OPERATOR_CONFIRMED)
        with self.store.transaction() as con:
            final_task = con.execute(
                "SELECT status,assigned_to,resolution FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
        self.assertEqual(final_task["status"], "COMPLETED")
        self.assertEqual(final_task["assigned_to"], "callback_operator")
        self.assertEqual(final_task["resolution"], "CALL:NOT_ASSESSED")
        first_action, reconciled = self.workflow.reconcile_human_task(
            bound.call_session_id
        )
        self.assertFalse(first_action.changed)
        self.assertIsNotNone(reconciled)
        self.assertFalse(reconciled.changed)

    def test_callback_rebinding_rejects_unverified_operator_atomically(self):
        _normalized, handoff, _entry_id, bound = self._bound_call(
            "callback-unverified"
        )
        before = self.workflow.snapshot(bound.call_session_id)
        with self.assertRaises(OperatorCallWorkflowError):
            self.workflow.confirm_disposition(
                OperatorCallConfirmation(
                    call_session_id=bound.call_session_id,
                    confirmation_version=1,
                    operator_actor="sales_operator",
                    technical_disposition=TechnicalDisposition.NO_ANSWER,
                    commercial_disposition=CommercialDisposition.NOT_ASSESSED,
                    next_action=NextActionCode.CALL_BACK,
                    next_action_at_utc="2026-09-01T08:30:00Z",
                    next_action_owner="unverified_operator",
                    reason_code="NO_ANSWER",
                    request_gold_review=False,
                    request_suppression_review=False,
                    recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
                    evidence_ref="evidence://operator/callback-unverified",
                )
            )
        self.assertEqual(self.workflow.snapshot(bound.call_session_id), before)
        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,assigned_to FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
            confirmations = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='operator_call_disposition_confirmed'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["assigned_to"], "sales_operator")
        self.assertEqual(confirmations, 0)

    def test_confirmation_and_task_completion_rollback_in_one_transaction(self):
        _normalized, handoff, _entry_id, bound = self._bound_call(
            "atomic-completion"
        )
        confirmation = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.WRONG_NUMBER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="WRONG_NUMBER",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.NOT_APPLICABLE,
            evidence_ref="evidence://operator/atomic-completion",
        )
        with patch.object(
            self.workflow,
            "_complete_task_tx",
            side_effect=RuntimeError("simulated transaction failure"),
        ):
            with self.assertRaises(RuntimeError):
                self.workflow.confirm_disposition(confirmation)
        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,resolution FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
            confirmations = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='operator_call_disposition_confirmed'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()[0]
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["resolution"], "")
        self.assertEqual(confirmations, 0)
        retried = self.workflow.confirm_disposition(confirmation)
        self.assertTrue(retried.created)

    def test_transcript_revision_at_confirmation_transaction_boundary_is_rejected(self):
        _normalized, handoff, entry_id, bound = self._bound_call(
            "transaction-revision"
        )
        self._transcript(entry_id, "transaction-revision")
        proposal = self._proposal(
            bound.call_session_id, draft_id="draft-transaction-revision"
        )
        self.workflow.record_analysis_draft(proposal)
        original_transaction = self.store.transaction
        injected = False

        @contextmanager
        def transaction_with_revision(*args, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                self.workflow.record_transcript_ready(
                    mango_entry_id=entry_id,
                    mango_recording_id="recording-transaction-revision",
                    transcript_revision=2,
                    transcript_sha256="e" * 64,
                    segment_count=13,
                    speaker_count=2,
                    language="ru-RU",
                    evidence_ref="evidence://transcript/transaction-revision-two",
                )
            with original_transaction(*args, **kwargs) as con:
                yield con

        confirmation = OperatorCallConfirmation(
            call_session_id=bound.call_session_id,
            confirmation_version=1,
            operator_actor="sales_operator",
            technical_disposition=TechnicalDisposition.WRONG_NUMBER,
            commercial_disposition=CommercialDisposition.NOT_ASSESSED,
            next_action=NextActionCode.NONE,
            next_action_at_utc="",
            next_action_owner="",
            reason_code="WRONG_NUMBER",
            request_gold_review=False,
            request_suppression_review=False,
            recording_notice_status=RecordingNoticeStatus.CONFIRMED,
            evidence_ref="evidence://operator/transaction-revision",
            draft_id="draft-transaction-revision",
        )
        with patch.object(self.store, "transaction", transaction_with_revision):
            with self.assertRaises(OperatorCallWorkflowConflict):
                self.workflow.confirm_disposition(confirmation)
        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,resolution FROM human_tasks WHERE lf_task_id=?",
                (handoff.task_id,),
            ).fetchone()
            confirmations = con.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='operator_call_disposition_confirmed'
                     AND aggregate_id=?""",
                (bound.call_session_id,),
            ).fetchone()[0]
        self.assertTrue(injected)
        self.assertEqual(task["status"], "IN_PROGRESS")
        self.assertEqual(task["resolution"], "")
        self.assertEqual(confirmations, 0)

    def test_pending_crm_binding_review_survives_snapshot_reconstruction(self):
        completed = self._completed_call("entry-review-state", "call-review-state")
        candidates = ("activity-review-a", "activity-review-b")
        review = self.workflow.record_crm_candidate_review(
            mango_entry_id="entry-review-state",
            crm_activity_ids=candidates,
            candidate_snapshot_sha256=payload_hash(
                {"crm_activity_ids": sorted(candidates)}
            ),
            evidence_ref="evidence://bitrix/candidates/review-state",
        )
        self.assertEqual(review.state, CallWorkflowState.REVIEW_REQUIRED)
        snapshot = self.workflow.snapshot(completed.call_session_id)
        self.assertEqual(snapshot.state, CallWorkflowState.REVIEW_REQUIRED)
        self.assertEqual(snapshot.review_reasons, ("CRM_BINDING_REVIEW",))

    def test_latest_analysis_draft_uses_insertion_order_not_random_event_id(self):
        _normalized, _handoff, entry_id, bound = self._bound_call("draft-order")
        self._transcript(entry_id, "draft-order")
        old = self._proposal(bound.call_session_id, draft_id="draft-order-old")
        with patch(
            "lead_factory.store.utc_now", return_value="2030-01-01T00:00:00Z"
        ), patch(
            "lead_factory.store.new_lf_id",
            return_value="lf_event_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ):
            self.workflow.record_analysis_draft(old)
        self.workflow.record_transcript_ready(
            mango_entry_id=entry_id,
            mango_recording_id="recording-draft-order",
            transcript_revision=2,
            transcript_sha256="e" * 64,
            segment_count=13,
            speaker_count=2,
            language="ru-RU",
            evidence_ref="evidence://transcript/draft-order-two",
        )
        current = self._proposal(bound.call_session_id, draft_id="draft-order-current")
        with patch(
            "lead_factory.store.utc_now", return_value="2030-01-01T00:00:00Z"
        ), patch(
            "lead_factory.store.new_lf_id",
            return_value="lf_event_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ):
            result = self.workflow.record_analysis_draft(current)
        self.assertEqual(result.state, CallWorkflowState.ANALYSIS_DRAFT)
        snapshot = self.workflow.snapshot(bound.call_session_id)
        self.assertEqual(snapshot.state, CallWorkflowState.ANALYSIS_DRAFT)
        self.assertNotIn("STALE_ANALYSIS_DRAFT", snapshot.review_reasons)

    def test_canonical_events_contain_no_raw_audio_transcript_or_temporary_url(self):
        with self.assertRaises(ValueError):
            self.workflow.record_recording_ready(
                mango_entry_id="entry-unsafe",
                mango_call_id="call-unsafe",
                mango_recording_id="recording-unsafe",
                seq=1,
                duration_seconds=10,
                evidence_ref="evidence://https://provider.example/file?token=secret",
            )
        with self.assertRaises(ValueError):
            self.workflow.record_recording_ready(
                mango_entry_id="entry-unsafe",
                mango_call_id="call-unsafe",
                mango_recording_id="recording-unsafe",
                seq=1,
                duration_seconds=10,
                evidence_ref="evidence://https://provider.example/download/secret",
            )
        _normalized, _handoff, entry_id, bound = self._bound_call("privacy")
        self._transcript(entry_id, "privacy")
        self.workflow.record_analysis_draft(self._proposal(bound.call_session_id))
        with self.store.transaction() as con:
            rows = con.execute(
                """SELECT payload_json,evidence_ref FROM events
                   WHERE producer='operator_call_workflow'"""
            ).fetchall()
        serialized = json.dumps(
            [dict(row) for row in rows], ensure_ascii=False, sort_keys=True
        )
        self.assertNotIn("raw transcript", serialized.lower())
        self.assertNotIn("audio bytes", serialized.lower())
        self.assertNotIn("https://", serialized.lower())
        self.assertNotIn("?token=", serialized.lower())
        for row in rows:
            self.assertIsInstance(json.loads(row["payload_json"]), dict)


if __name__ == "__main__":
    unittest.main()
