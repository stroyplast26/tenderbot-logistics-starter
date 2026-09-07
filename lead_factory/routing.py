"""Idempotent stage routing from UNROUTED evidence to human work."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .ids import address_hash, new_lf_id, normalize_email, utc_now
from .inbound import (
    AUTO_REPLY,
    HARD_BOUNCE,
    HUMAN_REPLY,
    SOFT_BOUNCE,
    UNSUBSCRIBE,
    UNSUBSCRIBE_REVIEW,
)
from .store import FactoryStore, IdempotencyConflict


ROUTABLE_CLASSIFICATIONS = {
    HUMAN_REPLY,
    AUTO_REPLY,
    UNSUBSCRIBE,
    UNSUBSCRIBE_REVIEW,
    HARD_BOUNCE,
    SOFT_BOUNCE,
}


@dataclass(frozen=True)
class InboundRouteDecision:
    interaction_id: str
    decision_id: str
    classification: str
    contact_address: str
    campaign_id: str = ""
    mailbox: str = ""
    lf_contact_id: str = ""
    lf_opportunity_id: str = ""
    rule_version: str = "manual-stage/v1"
    evidence_ref: str = ""
    create_human_task: bool = True


@dataclass(frozen=True)
class InboundRouteResult:
    interaction_id: str
    classification: str
    changed: bool
    task_id: str = ""
    cadence_block_id: str = ""
    suppression_id: str = ""
    lead_operation_id: str = ""
    activity_operation_id: str = ""
    crm_handoff_state: str = ""


class InboundRouter:
    def __init__(
        self,
        store: FactoryStore,
        *,
        assigned_to: str = "dima",
        reply_slo_minutes: int = 5,
        human_reply_handoff: Any | None = None,
    ):
        self.store = store
        self.assigned_to = assigned_to
        self.reply_slo_minutes = max(1, int(reply_slo_minutes))
        self.human_reply_handoff = human_reply_handoff

    def _stage_handoff_tx(
        self,
        con: Any,
        *,
        decision: InboundRouteDecision,
        classification: str,
    ) -> tuple[str, str, str]:
        if classification != HUMAN_REPLY or self.human_reply_handoff is None:
            return "", "", ""
        staged = self.human_reply_handoff.stage_tx(
            con,
            interaction_id=decision.interaction_id,
            decision_id=decision.decision_id,
            evidence_ref=decision.evidence_ref,
            mailbox=decision.mailbox,
            campaign_id=decision.campaign_id,
        )
        return (
            str(getattr(staged, "lead_operation_id", "") or ""),
            str(getattr(staged, "activity_operation_id", "") or ""),
            str(getattr(staged, "state", "") or ""),
        )

    @staticmethod
    def _due_at(received_at: str, minutes: int) -> str:
        try:
            base = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            base = datetime.now(timezone.utc)
        return (base + timedelta(minutes=minutes)).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")

    def route(self, decision: InboundRouteDecision) -> InboundRouteResult:
        classification = str(decision.classification or "").strip().upper()
        if classification not in ROUTABLE_CLASSIFICATIONS:
            raise ValueError("unsupported inbound route classification")
        if not str(decision.interaction_id or "").strip() or not str(
            decision.decision_id or ""
        ).strip():
            raise ValueError("interaction_id and decision_id are required")
        if not str(decision.rule_version or "").strip() or not str(
            decision.evidence_ref or ""
        ).strip():
            raise ValueError("rule_version and evidence_ref are required")
        contact = normalize_email(decision.contact_address)
        if classification in {
            HUMAN_REPLY,
            UNSUBSCRIBE,
            UNSUBSCRIBE_REVIEW,
            HARD_BOUNCE,
        } and not contact:
            raise ValueError("actionable inbound route requires a contact address")

        event_key = f"route:{decision.interaction_id}:{decision.decision_id}"
        with self.store.transaction() as con:
            interaction = con.execute(
                "SELECT * FROM interactions WHERE lf_interaction_id=?",
                (decision.interaction_id,),
            ).fetchone()
            if not interaction:
                raise KeyError("interaction does not exist")
            sender = normalize_email(interaction["address"])
            if classification in {HUMAN_REPLY, UNSUBSCRIBE} and sender != contact:
                raise ValueError(
                    "human reply or unsubscribe contact must match the inbound sender"
                )
            resolved_contact_id = str(decision.lf_contact_id or "").strip()
            resolved_opportunity_id = str(decision.lf_opportunity_id or "").strip()
            exact_conversation_id = str(interaction["conversation_id"] or "") if (
                "conversation_id" in interaction.keys()
            ) else ""
            exact_route = (
                str(interaction["thread_route_state"] or "") == "EXACT"
                if "thread_route_state" in interaction.keys()
                else False
            )
            if exact_route:
                conversation = con.execute(
                    """SELECT c.*,ct.lf_company_id AS contact_company_id,
                              ct.email AS contact_email,
                              o.lf_company_id AS opportunity_company_id,
                              p.lf_company_id AS project_company_id
                       FROM conversations c
                       JOIN contacts ct ON ct.lf_contact_id=c.lf_contact_id
                       JOIN opportunities o ON o.lf_opportunity_id=c.lf_opportunity_id
                       JOIN projects p ON p.lf_project_id=o.lf_project_id
                       WHERE c.conversation_id=?""",
                    (exact_conversation_id,),
                ).fetchone()
                if not conversation:
                    raise ValueError("exact inbound route has no canonical conversation")
                if (
                    str(conversation["contact_company_id"])
                    != str(conversation["opportunity_company_id"])
                    or str(conversation["project_company_id"])
                    != str(conversation["opportunity_company_id"])
                    or address_hash(conversation["contact_email"])
                    != str(conversation["peer_address_hash"])
                    or address_hash(contact) != str(conversation["peer_address_hash"])
                    or str(interaction["lf_contact_id"] or "")
                    != str(conversation["lf_contact_id"])
                    or str(interaction["lf_opportunity_id"] or "")
                    != str(conversation["lf_opportunity_id"])
                ):
                    raise ValueError("exact inbound route canonical graph is inconsistent")
                if resolved_contact_id and resolved_contact_id != str(
                    conversation["lf_contact_id"]
                ):
                    raise ValueError("caller contact conflicts with exact conversation")
                if resolved_opportunity_id and resolved_opportunity_id != str(
                    conversation["lf_opportunity_id"]
                ):
                    raise ValueError("caller opportunity conflicts with exact conversation")
                resolved_contact_id = str(conversation["lf_contact_id"])
                resolved_opportunity_id = str(conversation["lf_opportunity_id"])
            else:
                contact_row = None
                if resolved_contact_id:
                    contact_row = con.execute(
                        "SELECT lf_company_id,email FROM contacts WHERE lf_contact_id=?",
                        (resolved_contact_id,),
                    ).fetchone()
                    if not contact_row:
                        raise KeyError("route contact does not exist")
                    if contact and address_hash(contact_row["email"]) != address_hash(contact):
                        raise ValueError("route contact email does not match inbound sender")
                opportunity_row = None
                if resolved_opportunity_id:
                    opportunity_row = con.execute(
                        """SELECT o.lf_company_id,p.lf_company_id AS project_company_id
                           FROM opportunities o
                           JOIN projects p ON p.lf_project_id=o.lf_project_id
                           WHERE o.lf_opportunity_id=?""",
                        (resolved_opportunity_id,),
                    ).fetchone()
                    if not opportunity_row:
                        raise KeyError("route opportunity does not exist")
                    if str(opportunity_row["lf_company_id"]) != str(
                        opportunity_row["project_company_id"]
                    ):
                        raise ValueError("route opportunity project belongs to another company")
                if (
                    contact_row
                    and opportunity_row
                    and str(contact_row["lf_company_id"])
                    != str(opportunity_row["lf_company_id"])
                ):
                    raise ValueError("route contact and opportunity belong to different companies")

            route_event, event_created = self.store._append_event_tx(
                con,
                event_type="inbound_routed",
                aggregate_type="interaction",
                aggregate_id=decision.interaction_id,
                producer="inbound_router",
                idempotency_key=event_key,
                payload={
                    "classification": classification,
                    "campaign_id": decision.campaign_id,
                    "mailbox": decision.mailbox,
                    "lf_contact_id": resolved_contact_id,
                    "lf_opportunity_id": resolved_opportunity_id,
                    "contact_address_hash": address_hash(contact) if contact else "",
                    "rule_version": decision.rule_version,
                    "create_human_task": bool(decision.create_human_task),
                },
                evidence_ref=decision.evidence_ref,
                actor="inbound_router",
                causation_id=interaction["source_event_id"],
            )
            if interaction["classification"] != "UNROUTED":
                if not event_created and interaction["classification"] == classification:
                    task = con.execute(
                        "SELECT lf_task_id FROM human_tasks WHERE lf_interaction_id=?",
                        (decision.interaction_id,),
                    ).fetchone()
                    block = con.execute(
                        """SELECT block_id FROM cadence_blocks
                           WHERE channel='email' AND address_hash=? AND state='ACTIVE'
                           ORDER BY created_at_utc LIMIT 1""",
                        (address_hash(contact),),
                    ).fetchone() if contact else None
                    suppression = con.execute(
                        """SELECT suppression_id FROM suppression_entries
                           WHERE channel='email' AND address_hash=? AND state='ACTIVE'
                           ORDER BY created_at_utc LIMIT 1""",
                        (address_hash(contact),),
                    ).fetchone() if contact else None
                    lead_operation_id, activity_operation_id, handoff_state = (
                        self._stage_handoff_tx(
                            con, decision=decision, classification=classification
                        )
                    )
                    return InboundRouteResult(
                        decision.interaction_id,
                        classification,
                        False,
                        task[0] if task else "",
                        block[0] if block else "",
                        suppression[0] if suppression else "",
                        lead_operation_id,
                        activity_operation_id,
                        handoff_state,
                    )
                raise IdempotencyConflict("interaction already has another route decision")
            con.execute(
                """UPDATE interactions SET classification=?,lf_contact_id=?,
                   lf_opportunity_id=? WHERE lf_interaction_id=?
                   AND classification='UNROUTED'""",
                (
                    classification,
                    resolved_contact_id or None,
                    resolved_opportunity_id or None,
                    decision.interaction_id,
                ),
            )

            block_id = ""
            if classification in {
                HUMAN_REPLY,
                UNSUBSCRIBE,
                UNSUBSCRIBE_REVIEW,
                HARD_BOUNCE,
            }:
                existing_block = con.execute(
                    """SELECT block_id FROM cadence_blocks
                       WHERE channel='email' AND address_hash=? AND state='ACTIVE'
                       ORDER BY created_at_utc LIMIT 1""",
                    (address_hash(contact),),
                ).fetchone()
                if existing_block:
                    block_id = str(existing_block[0])
                else:
                    block_id = new_lf_id("pause")
                    con.execute(
                        """INSERT INTO cadence_blocks(
                            block_id,lf_contact_id,address_hash,channel,campaign_id,reason,
                            source_event_id,state,created_at_utc,released_at_utc
                        ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (
                            block_id,
                            resolved_contact_id or None,
                            address_hash(contact),
                            "email",
                            decision.campaign_id,
                            classification,
                            route_event["event_id"],
                            "ACTIVE",
                            utc_now(),
                            "",
                        ),
                    )

            task_id = ""
            if decision.create_human_task and classification in {
                HUMAN_REPLY,
                UNSUBSCRIBE_REVIEW,
            }:
                task_kind = (
                    "SUPPRESSION_REVIEW"
                    if classification == UNSUBSCRIBE_REVIEW
                    else "HUMAN_REPLY_REVIEW"
                )
                existing_task = con.execute(
                    """SELECT lf_task_id FROM human_tasks
                       WHERE lf_interaction_id=? AND kind=?""",
                    (decision.interaction_id, task_kind),
                ).fetchone()
                if existing_task:
                    task_id = str(existing_task[0])
                else:
                    task_id = new_lf_id("task")
                    con.execute(
                        """INSERT INTO human_tasks(
                            lf_task_id,lf_opportunity_id,lf_interaction_id,kind,status,
                            priority,assigned_to,due_at_utc,acknowledged_at_utc,
                            first_human_action_at_utc,closed_at_utc,resolution,created_at_utc
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            task_id,
                            resolved_opportunity_id or None,
                            decision.interaction_id,
                            task_kind,
                            "OPEN",
                            "A",
                            self.assigned_to,
                            self._due_at(
                                interaction["received_at_utc"], self.reply_slo_minutes
                            ),
                            "",
                            "",
                            "",
                            "",
                            utc_now(),
                        ),
                    )

            suppression_id = ""
            if classification in {UNSUBSCRIBE, HARD_BOUNCE}:
                reason = "unsubscribe" if classification == UNSUBSCRIBE else "hard_bounce"
                existing_suppression = con.execute(
                    """SELECT suppression_id FROM suppression_entries
                       WHERE channel='email' AND scope='EMAIL_ADDRESS'
                         AND subject_id=? AND reason=? AND state='ACTIVE'""",
                    (address_hash(contact), reason),
                ).fetchone()
                if existing_suppression:
                    suppression_id = str(existing_suppression[0])
                else:
                    suppression_id = new_lf_id("suppression")
                    con.execute(
                        """INSERT INTO suppression_entries(
                            suppression_id,subject_type,subject_id,channel,address,address_hash,
                            reason,scope,evidence_ref,source,author,created_at_utc,
                            expires_at_utc,state
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            suppression_id,
                            "EMAIL_ADDRESS",
                            address_hash(contact),
                            "email",
                            contact,
                            address_hash(contact),
                            reason,
                            "EMAIL_ADDRESS",
                            decision.evidence_ref,
                            "inbound_router",
                            "inbound_router",
                            utc_now(),
                            "",
                            "ACTIVE",
                        ),
                    )

            lead_operation_id, activity_operation_id, handoff_state = self._stage_handoff_tx(
                con, decision=decision, classification=classification
            )
            return InboundRouteResult(
                decision.interaction_id,
                classification,
                True,
                task_id,
                block_id,
                suppression_id,
                lead_operation_id,
                activity_operation_id,
                handoff_state,
            )


__all__ = [
    "InboundRouteDecision",
    "InboundRouteResult",
    "InboundRouter",
    "ROUTABLE_CLASSIFICATIONS",
]
