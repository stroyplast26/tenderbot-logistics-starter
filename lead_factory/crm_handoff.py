"""Atomic local handoff from a routed human reply to two CRM operations.

This module deliberately has no HTTP client, webhook, or environment lookup.
It stages a Lead create and a dependent follow-up Activity create in the same
SQLite transaction that already holds the routed HUMAN_REPLY and assigned operator task.

Bitrix documentation used for the future Activity adapter:
* crm.activity.todo.add (current): ownerTypeId, ownerId, deadline, title,
  description, responsibleId —
  https://apidocs.bitrix24.ru/api-reference/crm/timeline/activities/todo/crm-activity-todo-add.html
* crm.activity.add is deprecated and only documents a returned numeric id, not
  an immutable external idempotency/correlation field —
  https://apidocs.bitrix24.ru/api-reference/crm/timeline/activities/activity-base/crm-activity-add.html

Consequently, an Activity's local correlation token is provenance only.  An
ambiguous remote Activity create must go to manual REVIEW, never to a blind
retry or a lookup by an unproven marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .crm_outbox import CrmActivityOutbox, CrmOutbox
from .ids import canonical_json, payload_hash
from .inbound import HUMAN_REPLY
from .store import FactoryStore


@dataclass(frozen=True)
class HumanReplyCrmHandoffResult:
    state: str
    lead_operation_id: str = ""
    activity_operation_id: str = ""
    review_code: str = ""


class HumanReplyCrmHandoff:
    """Stage exactly one lead and one dependent Activity for a routed reply."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        lead_payload: dict[str, Any],
        activity_payload: dict[str, Any],
        after_stage_hook: Callable[[], None] | None = None,
        canary_control: Any | None = None,
        canary_run_id: str = "",
        canary_member_id: str = "",
    ):
        self.store = store
        self.leads = CrmOutbox(store)
        self.activities = CrmActivityOutbox(store)
        self.lead_payload = dict(lead_payload or {})
        self.activity_payload = dict(activity_payload or {})
        self.after_stage_hook = after_stage_hook
        if bool(canary_run_id) != bool(canary_member_id):
            raise ValueError("canary_run_id and canary_member_id must be supplied together")
        self.canary_control = canary_control
        self.canary_run_id = str(canary_run_id or "").strip()
        self.canary_member_id = str(canary_member_id or "").strip()
        if self.canary_control is None and (self.canary_run_id or self.canary_member_id):
            raise ValueError("a canary controller is required for a canary handoff")
        if self.canary_control is not None and not self.canary_run_id:
            raise ValueError("a canary controller requires run and member identities")

    def _review_tx(
        self,
        con: Any,
        *,
        interaction_id: str,
        decision_id: str,
        code: str,
        evidence_ref: str,
    ) -> HumanReplyCrmHandoffResult:
        self.store._append_event_tx(
            con,
            event_type="crm_handoff_review_required",
            aggregate_type="interaction",
            aggregate_id=interaction_id,
            producer="human_reply_crm_handoff",
            idempotency_key=f"crm-handoff-review:{interaction_id}:{decision_id}:{code}",
            payload={"state": "REVIEW", "review_code": code},
            evidence_ref=evidence_ref,
            actor="inbound_router",
        )
        return HumanReplyCrmHandoffResult("REVIEW", review_code=code)

    def stage_tx(
        self,
        con: Any,
        *,
        interaction_id: str,
        decision_id: str,
        evidence_ref: str,
        mailbox: str = "",
        campaign_id: str = "",
    ) -> HumanReplyCrmHandoffResult:
        """Stage the handoff using the router's still-open SQLite transaction.

        The preconditions intentionally examine persisted state rather than
        trusting the caller: the interaction must already be HUMAN_REPLY, it
        must have an opportunity, and exactly one OPEN human-review task must
        exist.  Invalid/early invocations create only an auditable local REVIEW
        event and never stage CRM operations.
        """
        interaction = con.execute(
            """SELECT lf_interaction_id,classification,lf_opportunity_id,source_event_id,address,thread_id
               FROM interactions WHERE lf_interaction_id=?""",
            (interaction_id,),
        ).fetchone()
        if not interaction:
            return self._review_tx(
                con,
                interaction_id=interaction_id,
                decision_id=decision_id,
                code="INTERACTION_MISSING",
                evidence_ref=evidence_ref,
            )
        if interaction["classification"] != HUMAN_REPLY:
            return self._review_tx(
                con,
                interaction_id=interaction_id,
                decision_id=decision_id,
                code="ROUTE_NOT_HUMAN_REPLY",
                evidence_ref=evidence_ref,
            )
        opportunity_id = str(interaction["lf_opportunity_id"] or "")
        if not opportunity_id:
            return self._review_tx(
                con,
                interaction_id=interaction_id,
                decision_id=decision_id,
                code="OPPORTUNITY_REQUIRED",
                evidence_ref=evidence_ref,
            )
        tasks = con.execute(
            """SELECT lf_task_id,lf_opportunity_id FROM human_tasks
               WHERE lf_interaction_id=? AND kind='HUMAN_REPLY_REVIEW' AND status='OPEN'
               ORDER BY lf_task_id""",
            (interaction_id,),
        ).fetchall()
        if len(tasks) != 1:
            return self._review_tx(
                con,
                interaction_id=interaction_id,
                decision_id=decision_id,
                code="ONE_OPEN_HUMAN_TASK_REQUIRED",
                evidence_ref=evidence_ref,
            )
        task = tasks[0]
        if str(task["lf_opportunity_id"] or "") != opportunity_id:
            return self._review_tx(
                con,
                interaction_id=interaction_id,
                decision_id=decision_id,
                code="TASK_OPPORTUNITY_MISMATCH",
                evidence_ref=evidence_ref,
            )
        if not self.lead_payload or not self.activity_payload:
            return self._review_tx(
                con,
                interaction_id=interaction_id,
                decision_id=decision_id,
                code="CRM_PAYLOAD_REQUIRED",
                evidence_ref=evidence_ref,
            )

        external_event_id = f"inbound-route:{interaction_id}:{decision_id}"
        lead_operation_id, _ = self.leads.stage_lead_create_tx(
            con,
            lf_entity_id=opportunity_id,
            external_event_id=external_event_id,
            payload=self.lead_payload,
        )
        activity_operation_id, _ = self.activities.stage_activity_create_tx(
            con,
            interaction_id=interaction_id,
            task_id=str(task["lf_task_id"]),
            lead_operation_id=lead_operation_id,
            external_event_id=f"{external_event_id}:activity",
            payload=self.activity_payload,
        )
        if self.canary_control is not None:
            # The controller runs inside the router transaction: either the
            # task, route, Lead, Activity and both canary bindings commit
            # together, or none of them do.
            self.canary_control.admit_handoff_tx(
                con,
                run_id=self.canary_run_id,
                member_id=self.canary_member_id,
                mailbox=mailbox,
                campaign_id=campaign_id,
                contact_address=interaction["address"],
                canonical_thread=interaction["thread_id"],
                lf_opportunity_id=opportunity_id,
                interaction_id=interaction_id,
                lead_operation_id=lead_operation_id,
                activity_operation_id=activity_operation_id,
            )
        handoff_key = f"crm-handoff:{interaction_id}:{decision_id}"
        handoff_payload = {
            "state": "STAGED",
            "lead_operation_id": lead_operation_id,
            "activity_operation_id": activity_operation_id,
            "payload_digest": payload_hash(
                {
                    "lead": canonical_json(self.lead_payload),
                    "activity": canonical_json(self.activity_payload),
                }
            ),
        }
        self.store._append_event_tx(
            con,
            event_type="human_reply_crm_handoff_staged",
            aggregate_type="interaction",
            aggregate_id=interaction_id,
            producer="human_reply_crm_handoff",
            idempotency_key=handoff_key,
            payload=handoff_payload,
            evidence_ref=evidence_ref,
            actor="inbound_router",
            causation_id=interaction["source_event_id"],
        )
        if self.after_stage_hook:
            self.after_stage_hook()
        return HumanReplyCrmHandoffResult(
            "STAGED", lead_operation_id, activity_operation_id
        )


__all__ = [
    "HumanReplyCrmHandoff",
    "HumanReplyCrmHandoffResult",
]
