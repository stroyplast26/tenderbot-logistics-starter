"""Durable, idempotent intake for replies and delivery events.

The intake performs no external side effects.  A human reply is persisted in a
single SQLite transaction together with a cadence block and a local review
task.  A later integration worker may mirror that task to Bitrix after its own
acceptance tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from .ids import (
    address_hash,
    canonical_json,
    message_id_key,
    new_lf_id,
    normalize_email,
    normalize_message_id,
    payload_hash,
    utc_now,
)
from .store import FactoryStore


HUMAN_REPLY = "HUMAN_REPLY"
AUTO_REPLY = "AUTO_REPLY"
UNSUBSCRIBE = "UNSUBSCRIBE"
UNSUBSCRIBE_REVIEW = "UNSUBSCRIBE_REVIEW"
HARD_BOUNCE = "HARD_BOUNCE"
SOFT_BOUNCE = "SOFT_BOUNCE"


@dataclass(frozen=True)
class InboundMessage:
    producer: str
    mailbox: str
    mailbox_account_id: str = ""
    external_message_id: str = ""
    uid: str = ""
    uid_validity: str = ""
    from_address: str = ""
    contact_address: str = ""
    received_at_utc: str = ""
    channel: str = "email"
    thread_id: str = ""
    in_reply_to: str = ""
    references: tuple[str, ...] = ()
    reference_parse_state: str = "OK"
    classification: str = HUMAN_REPLY
    lf_opportunity_id: str = ""
    lf_contact_id: str = ""
    campaign_id: str = ""
    evidence_ref: str = ""
    evidence_sha256: str = ""
    evidence_size: int = 0
    parser_version: str = ""
    subject_hash: str = ""
    content_hash: str = ""
    create_human_task: bool = True

    def dedupe_key(self) -> str:
        mid_key = message_id_key(self.external_message_id)
        mailbox_account_id = str(self.mailbox_account_id or "").strip()
        if mid_key:
            if mailbox_account_id:
                return f"mailbox-message-id:{mailbox_account_id}:{mid_key}"
            return f"message-id:{str(self.external_message_id or '').strip().lower()}"
        if self.uid and self.mailbox:
            scope = mailbox_account_id or self.mailbox.strip().lower()
            return f"uid:{scope}:{self.uid}"
        raw = "|".join(
            [
                self.producer,
                self.mailbox,
                normalize_email(self.from_address),
                self.received_at_utc,
                self.subject_hash,
                self.content_hash,
            ]
        )
        return "surrogate:" + hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()

    def event_dedupe_key(self) -> str:
        """Use mailbox UID for the immutable receive event when available.

        A copy of the same RFC Message-ID can legitimately appear under another
        IMAP UID.  It must have its own durable receive event so that a strict
        UID cursor can advance, while ``dedupe_key`` above still prevents a
        duplicate interaction or human task.
        """
        validity = str(self.uid_validity or "").strip()
        if self.uid and self.mailbox and validity:
            return f"uid:{self.mailbox.strip().lower()}:{validity}:{self.uid}"
        return self.dedupe_key()


@dataclass(frozen=True)
class InboundResult:
    created: bool
    event_id: str
    interaction_id: str
    task_id: str = ""
    cadence_block_id: str = ""
    suppression_id: str = ""
    review_id: str = ""


class InboundIntake:
    def __init__(
        self,
        store: FactoryStore,
        *,
        assigned_to: str = "dima",
        reply_slo_minutes: int = 15,
        after_event_hook: Callable[[], None] | None = None,
    ):
        self.store = store
        self.assigned_to = assigned_to
        self.reply_slo_minutes = max(1, int(reply_slo_minutes))
        self.after_event_hook = after_event_hook

    @staticmethod
    def _due_at(received_at: str, minutes: int) -> str:
        try:
            base = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            base = datetime.now(timezone.utc)
        return (base + timedelta(minutes=minutes)).isoformat(timespec="seconds").replace("+00:00", "Z")

    def ingest(self, message: InboundMessage) -> InboundResult:
        dedupe_key = message.dedupe_key()
        event_dedupe_key = message.event_dedupe_key()
        mailbox_account_id = str(message.mailbox_account_id or "").strip()
        sender_address = normalize_email(message.from_address)
        sender_hash = address_hash(sender_address) if sender_address else ""
        contact_address = normalize_email(message.contact_address) or sender_address
        contact_hash = address_hash(contact_address) if contact_address else ""
        received = message.received_at_utc or utc_now()
        external_message_id = normalize_message_id(message.external_message_id)
        in_reply_to = normalize_message_id(message.in_reply_to or message.thread_id)
        references: list[str] = []
        reference_parse_state = str(message.reference_parse_state or "OK").strip().upper()
        for raw_reference in tuple(message.references or ()):
            normalized_reference = normalize_message_id(raw_reference)
            if not normalized_reference:
                reference_parse_state = "MALFORMED"
                continue
            if normalized_reference not in references:
                references.append(normalized_reference)
        if str(message.external_message_id or "").strip() and not external_message_id:
            reference_parse_state = "MALFORMED"
        if str(message.in_reply_to or message.thread_id or "").strip() and not in_reply_to:
            reference_parse_state = "MALFORMED"
        if reference_parse_state not in {"OK", "MALFORMED", "OVERSIZED"}:
            reference_parse_state = "MALFORMED"
        fingerprint = payload_hash(
            {
                "sender_address_hash": sender_hash,
                "content_hash": str(message.content_hash or ""),
                "evidence_sha256": str(message.evidence_sha256 or ""),
            }
        )
        payload = {
            "mailbox": message.mailbox,
            "mailbox_account_id": mailbox_account_id,
            "external_message_id_key": message_id_key(external_message_id),
            "uid": message.uid,
            "uid_validity": message.uid_validity,
            "channel": message.channel,
            "in_reply_to_key": message_id_key(in_reply_to),
            "reference_keys": [message_id_key(value) for value in references],
            "reference_parse_state": reference_parse_state,
            "classification": message.classification,
            "lf_opportunity_id": message.lf_opportunity_id,
            "lf_contact_id": message.lf_contact_id,
            "campaign_id": message.campaign_id,
            "evidence_sha256": message.evidence_sha256,
            "evidence_size": max(0, int(message.evidence_size or 0)),
            "parser_version": message.parser_version,
            "sender_address_hash": sender_hash,
            "contact_address_hash": contact_hash,
            "subject_hash": message.subject_hash,
            "content_hash": message.content_hash,
            "create_human_task": bool(message.create_human_task),
        }

        min_schema_version = 14 if mailbox_account_id else 13
        with self.store.transaction(min_schema_version=min_schema_version) as con:
            if mailbox_account_id:
                mailbox = con.execute(
                    "SELECT state FROM mailbox_accounts WHERE mailbox_account_id=?",
                    (mailbox_account_id,),
                ).fetchone()
                if not mailbox:
                    raise ValueError("registered mailbox account is required")
                if str(mailbox["state"]) not in {"ACTIVE", "READ_ONLY"}:
                    raise ValueError("mailbox account is not enabled for inbound intake")
            event, event_created = self.store._append_event_tx(
                con,
                event_type="inbound_received",
                aggregate_type="opportunity" if message.lf_opportunity_id else "interaction",
                aggregate_id=message.lf_opportunity_id or event_dedupe_key,
                producer=message.producer,
                idempotency_key=event_dedupe_key,
                payload=payload,
                evidence_ref=message.evidence_ref,
                actor="inbound_worker",
                occurred_at_utc=received,
            )
            if self.after_event_hook:
                self.after_event_hook()

            claim = None
            if mailbox_account_id:
                canonical_key = message_id_key(external_message_id) or payload_hash(
                    {
                        "mailbox_account_id": mailbox_account_id,
                        "dedupe_key": dedupe_key,
                    }
                )
                claim = con.execute(
                    """SELECT c.*,i.* FROM email_message_claims c
                       JOIN interactions i ON i.lf_interaction_id=c.interaction_id
                       WHERE c.mailbox_account_id=? AND c.message_id_key=?""",
                    (mailbox_account_id, canonical_key),
                ).fetchone()
                if claim and (
                    str(claim["sender_address_hash"] or "") != sender_hash
                    or str(claim["content_hash"] or "") != str(message.content_hash or "")
                    or (
                        str(claim["evidence_hash"] or "")
                        and str(message.evidence_sha256 or "")
                        and str(claim["evidence_hash"] or "")
                        != str(message.evidence_sha256 or "")
                    )
                ):
                    conflict_interaction_id = new_lf_id("interaction")
                    conflict_key = f"message-id-conflict:{mailbox_account_id}:{event['event_id']}"
                    con.execute(
                        """INSERT INTO interactions(
                            lf_interaction_id,lf_opportunity_id,lf_contact_id,source_event_id,
                            dedupe_key,channel,direction,classification,external_message_id,
                            thread_id,address,address_hash,received_at_utc,evidence_ref,created_at_utc,
                            mailbox_account_id,in_reply_to,references_json,conversation_id,
                            thread_route_state,reference_parse_state,message_fingerprint_hash,
                            legacy_dedupe_key
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            conflict_interaction_id, None, None, event["event_id"],
                            conflict_key, message.channel, "INBOUND", "UNROUTED",
                            external_message_id, in_reply_to, sender_address, sender_hash,
                            received, message.evidence_ref, utc_now(), mailbox_account_id,
                            in_reply_to, canonical_json(references), "", "REVIEW",
                            reference_parse_state, fingerprint, "",
                        ),
                    )
                    review_id = new_lf_id("route_review")
                    con.execute(
                        """INSERT INTO conversation_route_reviews(
                            review_id,interaction_id,reason,candidate_count,state,
                            evidence_ref,created_at_utc,resolved_at_utc
                        ) VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            review_id, conflict_interaction_id, "MESSAGE_ID_CONFLICT", 0,
                            "OPEN", message.evidence_ref or event["event_id"], utc_now(), "",
                        ),
                    )
                    self.store._append_event_tx(
                        con,
                        event_type="message_id_conflict_review_required",
                        aggregate_type="interaction",
                        aggregate_id=conflict_interaction_id,
                        producer="inbound_intake",
                        idempotency_key=f"message-id-conflict:{event['event_id']}",
                        payload={
                            "mailbox_account_id": mailbox_account_id,
                            "message_id_key": canonical_key,
                            "reason": "MESSAGE_ID_CONFLICT",
                        },
                        evidence_ref=message.evidence_ref,
                        actor="inbound_worker",
                        causation_id=event["event_id"],
                    )
                    return InboundResult(
                        event_created,
                        event["event_id"],
                        conflict_interaction_id,
                        review_id=review_id,
                    )
            existing = claim or con.execute(
                "SELECT * FROM interactions WHERE dedupe_key=?", (dedupe_key,)
            ).fetchone()
            if existing:
                task = con.execute(
                    "SELECT lf_task_id FROM human_tasks WHERE lf_interaction_id=?",
                    (existing["lf_interaction_id"],),
                ).fetchone()
                block = con.execute(
                    """SELECT block_id FROM cadence_blocks
                       WHERE channel=? AND address_hash=? AND campaign_id=? AND state='ACTIVE'""",
                    (message.channel, contact_hash, message.campaign_id),
                ).fetchone()
                suppression = con.execute(
                    """SELECT suppression_id FROM suppression_entries
                       WHERE channel=? AND address_hash=? AND state='ACTIVE'
                       ORDER BY created_at_utc DESC LIMIT 1""",
                    (message.channel, contact_hash),
                ).fetchone() if contact_hash else None
                return InboundResult(
                    False,
                    event["event_id"],
                    existing["lf_interaction_id"],
                    task[0] if task else "",
                    block[0] if block else "",
                    suppression[0] if suppression else "",
                )

            interaction_id = new_lf_id("interaction")
            if mailbox_account_id:
                con.execute(
                    """INSERT INTO interactions(
                        lf_interaction_id,lf_opportunity_id,lf_contact_id,source_event_id,
                        dedupe_key,channel,direction,classification,external_message_id,
                        thread_id,address,address_hash,received_at_utc,evidence_ref,created_at_utc,
                        mailbox_account_id,in_reply_to,references_json,conversation_id,
                        thread_route_state,reference_parse_state,message_fingerprint_hash,
                        legacy_dedupe_key
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        interaction_id, message.lf_opportunity_id or None,
                        message.lf_contact_id or None, event["event_id"], dedupe_key,
                        message.channel, "INBOUND", message.classification,
                        external_message_id, in_reply_to, sender_address, sender_hash,
                        received, message.evidence_ref, utc_now(), mailbox_account_id,
                        in_reply_to, canonical_json(references), "", "UNRESOLVED",
                        reference_parse_state, fingerprint, "",
                    ),
                )
                con.execute(
                    """INSERT INTO email_message_claims(
                        claim_id,mailbox_account_id,message_id_key,interaction_id,
                        sender_address_hash,content_hash,evidence_hash,state,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        new_lf_id("message_claim"), mailbox_account_id, canonical_key,
                        interaction_id, sender_hash, str(message.content_hash or ""),
                        str(message.evidence_sha256 or ""), "ACTIVE", utc_now(),
                    ),
                )
            else:
                con.execute(
                    """INSERT INTO interactions(
                        lf_interaction_id,lf_opportunity_id,lf_contact_id,source_event_id,
                        dedupe_key,channel,direction,classification,external_message_id,
                        thread_id,address,address_hash,received_at_utc,evidence_ref,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        interaction_id,
                        message.lf_opportunity_id or None,
                        message.lf_contact_id or None,
                        event["event_id"],
                        dedupe_key,
                        message.channel,
                        "INBOUND",
                        message.classification,
                        message.external_message_id,
                        message.thread_id,
                        sender_address,
                        sender_hash,
                        received,
                        message.evidence_ref,
                        utc_now(),
                    ),
                )

            task_id = ""
            block_id = ""
            suppression_id = ""
            if message.classification in {
                HUMAN_REPLY,
                UNSUBSCRIBE,
                UNSUBSCRIBE_REVIEW,
                HARD_BOUNCE,
            }:
                block_id = new_lf_id("pause")
                con.execute(
                    """INSERT OR IGNORE INTO cadence_blocks(
                        block_id,lf_contact_id,address_hash,channel,campaign_id,reason,
                        source_event_id,state,created_at_utc,released_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        block_id,
                        message.lf_contact_id or None,
                        contact_hash,
                        message.channel,
                        message.campaign_id,
                        message.classification,
                        event["event_id"],
                        "ACTIVE",
                        utc_now(),
                        "",
                    ),
                )
                row = con.execute(
                    """SELECT block_id FROM cadence_blocks
                       WHERE channel=? AND address_hash=? AND campaign_id=? AND state='ACTIVE'""",
                    (message.channel, contact_hash, message.campaign_id),
                ).fetchone()
                block_id = row[0] if row else block_id

            if message.create_human_task and message.classification in {
                HUMAN_REPLY,
                UNSUBSCRIBE_REVIEW,
            }:
                task_id = new_lf_id("task")
                task_kind = (
                    "SUPPRESSION_REVIEW"
                    if message.classification == UNSUBSCRIBE_REVIEW
                    else "HUMAN_REPLY_REVIEW"
                )
                con.execute(
                    """INSERT INTO human_tasks(
                        lf_task_id,lf_opportunity_id,lf_interaction_id,kind,status,priority,
                        assigned_to,due_at_utc,acknowledged_at_utc,
                        first_human_action_at_utc,closed_at_utc,resolution,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        task_id,
                        message.lf_opportunity_id or None,
                        interaction_id,
                        task_kind,
                        "OPEN",
                        "A",
                        self.assigned_to,
                        self._due_at(received, self.reply_slo_minutes),
                        "",
                        "",
                        "",
                        "",
                        utc_now(),
                    ),
                )

            if message.classification in {UNSUBSCRIBE, HARD_BOUNCE} and contact_hash:
                reason = "unsubscribe" if message.classification == UNSUBSCRIBE else "hard_bounce"
                existing_suppression = con.execute(
                    """SELECT suppression_id FROM suppression_entries
                       WHERE channel='email' AND scope='EMAIL_ADDRESS'
                         AND subject_id=? AND reason=? AND state='ACTIVE'""",
                    (contact_hash, reason),
                ).fetchone()
                if existing_suppression:
                    suppression_id = existing_suppression[0]
                else:
                    suppression_id = new_lf_id("suppression")
                    con.execute(
                        """INSERT INTO suppression_entries(
                            suppression_id,subject_type,subject_id,channel,address,address_hash,
                            reason,scope,evidence_ref,source,author,created_at_utc,expires_at_utc,state
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            suppression_id,
                            "EMAIL_ADDRESS",
                            contact_hash,
                            "email",
                            contact_address,
                            contact_hash,
                            reason,
                            "EMAIL_ADDRESS",
                            message.evidence_ref or event["event_id"],
                            message.producer,
                            "inbound_worker",
                            utc_now(),
                            "",
                            "ACTIVE",
                        ),
                    )

            return InboundResult(
                event_created,
                event["event_id"],
                interaction_id,
                task_id,
                block_id,
                suppression_id,
            )


def hashed_message_content(subject: str, body: str) -> tuple[str, str]:
    """Return hashes for dedupe/evidence without duplicating message text."""
    return payload_hash({"subject": subject or ""}), payload_hash({"body": body or ""})


__all__ = [
    "AUTO_REPLY",
    "HARD_BOUNCE",
    "HUMAN_REPLY",
    "SOFT_BOUNCE",
    "UNSUBSCRIBE",
    "UNSUBSCRIBE_REVIEW",
    "InboundIntake",
    "InboundMessage",
    "InboundResult",
    "hashed_message_content",
]
