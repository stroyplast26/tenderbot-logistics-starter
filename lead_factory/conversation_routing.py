"""Identity-pinned email conversations and fail-closed inbound routing.

This module has no SMTP/IMAP/CRM boundary.  It records immutable RFC
Message-ID references and can attach an already-durable inbound interaction to
one conversation only when all matching references resolve to exactly one
active conversation with the same mailbox and peer.  Every other outcome is a
local review record; it never creates human work or CRM operations.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .ids import (
    address_hash,
    canonical_json,
    message_id_key,
    new_lf_id,
    normalize_email,
    payload_hash,
    utc_now,
)
from .mail_registry import ACTIVE, MailRegistry, MailRegistryError
from .store import FactoryStore, IdempotencyConflict


EXACT = "EXACT"
REVIEW = "REVIEW"
OPEN = "OPEN"

_MESSAGE_ID = re.compile(r"<([^<>\s@]+@[^<>\s@]+)>")
_MAX_REFERENCE_TOKENS = 64
_MAX_REFERENCE_HEADER_CHARS = 65_536


class ConversationRoutingError(RuntimeError):
    """Conversation state or evidence cannot support the requested operation."""


class ConversationPinConflict(ConversationRoutingError):
    """An active commercial thread is already pinned to another identity."""


@dataclass(frozen=True)
class ConversationPinResult:
    conversation_id: str
    created: bool


@dataclass(frozen=True)
class MessageReferenceResult:
    email_message_id: str
    created: bool


@dataclass(frozen=True)
class ConversationRouteResult:
    interaction_id: str
    state: str
    changed: bool
    conversation_id: str = ""
    review_id: str = ""
    reason: str = ""
    candidate_count: int = 0


def _required(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    return text


def canonical_message_id(value: object) -> str:
    """Return one strict, bracketed, case-folded RFC Message-ID token."""
    raw = str(value or "").strip()
    match = _MESSAGE_ID.fullmatch(raw)
    if not match:
        raise ValueError("message id must be one bracketed addr-spec token")
    return f"<{match.group(1).casefold()}>"


def _dedupe(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _parse_header(value: object, *, single: bool) -> tuple[list[str], bool]:
    if value is None:
        return [], False
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_REFERENCE_TOKENS:
            return [], True
        tokens: list[str] = []
        try:
            for item in value:
                tokens.append(canonical_message_id(item))
        except ValueError:
            return [], True
        normalized = _dedupe(tokens)
        return normalized, bool(single and len(normalized) > 1)

    raw = str(value or "").strip()
    if not raw:
        return [], False
    if len(raw) > _MAX_REFERENCE_HEADER_CHARS:
        return [], True
    matches = list(_MESSAGE_ID.finditer(raw))
    if not matches:
        return [], True
    residual = _MESSAGE_ID.sub("", raw)
    if residual.strip():
        return [], True
    normalized = _dedupe(f"<{match.group(1).casefold()}>" for match in matches)
    return normalized, bool(
        (single and len(normalized) > 1)
        or len(normalized) > _MAX_REFERENCE_TOKENS
    )


def _parse_references_json(value: object) -> tuple[list[str], bool]:
    raw = str(value or "").strip()
    if not raw:
        return [], False
    if raw.startswith("["):
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            return [], True
        if not isinstance(decoded, list):
            return [], True
        return _parse_header(decoded, single=False)
    return _parse_header(raw, single=False)


class ConversationRouter:
    def __init__(self, store: FactoryStore):
        self.store = store
        self.registry = MailRegistry(store)

    @staticmethod
    def _evidence(actor: str, evidence_ref: str) -> tuple[str, str]:
        return _required(actor, "actor"), _required(evidence_ref, "evidence_ref")

    def _event_tx(
        self,
        con: Any,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        idempotency_key: str,
        payload: dict[str, Any],
        actor: str,
        evidence_ref: str,
        causation_id: str = "",
    ) -> None:
        self.store._append_event_tx(
            con,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            producer="conversation_router",
            idempotency_key=idempotency_key,
            payload=payload,
            evidence_ref=evidence_ref,
            actor=actor,
            causation_id=causation_id,
        )

    def pin_conversation(
        self,
        *,
        lf_opportunity_id: str,
        lf_contact_id: str,
        sender_identity_id: str,
        mailbox_account_id: str,
        campaign_id: str,
        peer_address: str,
        actor: str,
        evidence_ref: str,
        conversation_id: str = "",
    ) -> ConversationPinResult:
        """Create one active thread whose sender/mailbox relationship cannot change."""
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        opportunity_id = _required(lf_opportunity_id, "lf_opportunity_id")
        contact_id = _required(lf_contact_id, "lf_contact_id")
        sender_id = _required(sender_identity_id, "sender_identity_id")
        mailbox_id = _required(mailbox_account_id, "mailbox_account_id")
        campaign_id = _required(campaign_id, "campaign_id")
        peer = normalize_email(_required(peer_address, "peer_address"))
        if "@" not in peer:
            raise ValueError("peer_address must be a valid email address")
        peer_digest = address_hash(peer)
        entity_id = str(conversation_id or new_lf_id("conversation")).strip()
        now = utc_now()

        with self.store.transaction(min_schema_version=14) as con:
            opportunity = con.execute(
                "SELECT * FROM opportunities WHERE lf_opportunity_id=?",
                (opportunity_id,),
            ).fetchone()
            contact = con.execute(
                "SELECT * FROM contacts WHERE lf_contact_id=?", (contact_id,)
            ).fetchone()
            if not opportunity or not contact:
                raise KeyError("opportunity and contact must exist before a conversation")
            if str(opportunity["lf_contact_id"] or "") != contact_id:
                raise ConversationPinConflict("opportunity is not assigned to this contact")
            if str(opportunity["lf_company_id"]) != str(contact["lf_company_id"]):
                raise ConversationPinConflict("opportunity and contact belong to different companies")
            if opportunity["lf_project_id"]:
                project = con.execute(
                    "SELECT lf_company_id FROM projects WHERE lf_project_id=?",
                    (opportunity["lf_project_id"],),
                ).fetchone()
                if not project or str(project["lf_company_id"]) != str(opportunity["lf_company_id"]):
                    raise ConversationPinConflict("opportunity and project belong to different companies")
            if not contact["email_hash"] or str(contact["email_hash"]) != peer_digest:
                raise ConversationPinConflict("peer address is not the opportunity contact")

            identity = self.registry.assert_sender_identity_chain_tx(
                con, sender_id, require_active=True
            )
            if str(identity["mailbox_account_id"]) != mailbox_id:
                raise ConversationPinConflict("sender identity is pinned to another reply mailbox")
            campaign = con.execute(
                "SELECT state FROM mail_campaigns WHERE campaign_id=?", (campaign_id,)
            ).fetchone()
            if not campaign or str(campaign["state"]) != ACTIVE:
                raise ConversationRoutingError("campaign must be ACTIVE before conversation pinning")

            by_id = con.execute(
                "SELECT * FROM conversations WHERE conversation_id=?", (entity_id,)
            ).fetchone()
            if by_id:
                exact = (
                    str(by_id["lf_opportunity_id"]) == opportunity_id
                    and str(by_id["lf_contact_id"]) == contact_id
                    and str(by_id["sender_identity_id"]) == sender_id
                    and str(by_id["mailbox_account_id"]) == mailbox_id
                    and str(by_id["campaign_id"]) == campaign_id
                    and str(by_id["peer_address_hash"]) == peer_digest
                )
                if not exact:
                    raise IdempotencyConflict("conversation id was reused with another identity chain")
                return ConversationPinResult(entity_id, False)

            active = con.execute(
                """SELECT * FROM conversations
                   WHERE lf_opportunity_id=? AND lf_contact_id=? AND campaign_id=?
                     AND peer_address_hash=? AND state='ACTIVE'
                   ORDER BY conversation_id""",
                (opportunity_id, contact_id, campaign_id, peer_digest),
            ).fetchall()
            if active:
                exact = [
                    row for row in active
                    if str(row["sender_identity_id"]) == sender_id
                    and str(row["mailbox_account_id"]) == mailbox_id
                ]
                if len(active) == 1 and len(exact) == 1:
                    return ConversationPinResult(str(exact[0]["conversation_id"]), False)
                raise ConversationPinConflict(
                    "active conversation is already pinned to another sender identity"
                )
            try:
                con.execute(
                    """INSERT INTO conversations(
                           conversation_id,lf_opportunity_id,lf_contact_id,
                           sender_identity_id,mailbox_account_id,campaign_id,
                           peer_address_hash,state,created_at_utc,updated_at_utc
                       ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        entity_id, opportunity_id, contact_id, sender_id, mailbox_id,
                        campaign_id, peer_digest, ACTIVE, now, now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConversationPinConflict("conversation identity conflicts with persisted state") from exc
            self._event_tx(
                con,
                event_type="conversation_pinned",
                aggregate_type="conversation",
                aggregate_id=entity_id,
                idempotency_key=f"conversation-pin:{entity_id}",
                payload={
                    "lf_opportunity_id": opportunity_id,
                    "lf_contact_id": contact_id,
                    "sender_identity_id": sender_id,
                    "mailbox_account_id": mailbox_id,
                    "campaign_id": campaign_id,
                    "peer_address_hash": peer_digest,
                    "state": ACTIVE,
                },
                actor=actor,
                evidence_ref=evidence_ref,
            )
            return ConversationPinResult(entity_id, True)

    def _register_message_tx(
        self,
        con: Any,
        *,
        conversation_id: str,
        direction: str,
        external_message_id: str,
        interaction_id: str,
        send_command_id: str,
        actor: str,
        evidence_ref: str,
        email_message_id: str = "",
        fingerprint_hash: str = "",
        require_active_conversation: bool = True,
    ) -> MessageReferenceResult:
        conversation = con.execute(
            "SELECT * FROM conversations WHERE conversation_id=?", (conversation_id,)
        ).fetchone()
        if not conversation or (
            require_active_conversation and str(conversation["state"]) != ACTIVE
        ):
            raise ConversationRoutingError("message reference requires an ACTIVE conversation")
        direction = _required(direction, "direction").upper()
        if direction not in {"INBOUND", "OUTBOUND"}:
            raise ValueError("direction must be INBOUND or OUTBOUND")
        external_key = canonical_message_id(external_message_id)
        key = message_id_key(external_key)
        if not key:
            raise ValueError("message id could not be canonicalized")
        if direction == "INBOUND":
            interaction_id = _required(interaction_id, "interaction_id")
            interaction = con.execute(
                """SELECT conversation_id,thread_route_state FROM interactions
                   WHERE lf_interaction_id=?""",
                (interaction_id,),
            ).fetchone()
            if (
                not interaction
                or str(interaction["conversation_id"] or "") != conversation_id
                or str(interaction["thread_route_state"] or "") != EXACT
            ):
                raise ConversationRoutingError("inbound message is not exactly routed")
        else:
            send_command_id = _required(send_command_id, "send_command_id")
            command = con.execute(
                """SELECT o.state AS command_state,o.provider_message_id,o.conversation_id,
                          p.state AS permit_state,p.sender_identity,p.mailbox_account_id
                   FROM outbox o JOIN send_permits p ON p.permit_id=o.permit_id
                   WHERE o.command_id=?""",
                (send_command_id,),
            ).fetchone()
            if (
                not command
                or str(command["command_state"]) != "SENT"
                or str(command["permit_state"]) != "SENT"
                or not str(command["provider_message_id"] or "")
                or str(command["conversation_id"]) != conversation_id
                or str(command["sender_identity"]) != str(conversation["sender_identity_id"])
                or str(command["mailbox_account_id"]) != str(conversation["mailbox_account_id"])
            ):
                raise ConversationRoutingError(
                    "outbound reference requires one reconciled SENT command"
                )
            collision = con.execute(
                """SELECT conversation_id,send_command_id FROM conversation_messages
                   WHERE direction='OUTBOUND' AND mailbox_account_id=? AND message_id_key=?
                   ORDER BY email_message_id LIMIT 1""",
                (conversation["mailbox_account_id"], key),
            ).fetchone()
            if collision and (
                str(collision["conversation_id"]) != conversation_id
                or str(collision["send_command_id"] or "") != send_command_id
            ):
                raise IdempotencyConflict(
                    "outbound RFC Message-ID is already bound in this mailbox"
                )
        existing = con.execute(
            """SELECT * FROM conversation_messages
               WHERE conversation_id=? AND direction=? AND message_id_key=?
               ORDER BY email_message_id LIMIT 1""",
            (conversation_id, direction, key),
        ).fetchone()
        if existing:
            if (
                str(existing["interaction_id"] or "") != str(interaction_id or "")
                or str(existing["send_command_id"] or "") != str(send_command_id or "")
            ):
                raise IdempotencyConflict("message reference was reused with another linkage")
            return MessageReferenceResult(str(existing["email_message_id"]), False)
        entity_id = str(email_message_id or new_lf_id("email_message")).strip()
        fingerprint = str(fingerprint_hash or "").strip() or payload_hash(
            {
                "conversation_id": conversation_id,
                "direction": direction,
                "message_id_key": key,
            }
        )
        try:
            con.execute(
                """INSERT INTO conversation_messages(
                       email_message_id,conversation_id,direction,external_message_id,
                       message_id_key,interaction_id,send_command_id,sender_identity_id,
                       mailbox_account_id,fingerprint_hash,evidence_ref,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entity_id, conversation_id, direction, external_key, key,
                    interaction_id or None, send_command_id or None,
                    conversation["sender_identity_id"], conversation["mailbox_account_id"],
                    fingerprint, evidence_ref, utc_now(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdempotencyConflict("email message identity conflicts with persisted state") from exc
        self._event_tx(
            con,
            event_type="conversation_message_registered",
            aggregate_type="conversation",
            aggregate_id=conversation_id,
            idempotency_key=f"conversation-message:{entity_id}",
            payload={
                "email_message_id": entity_id,
                "direction": direction,
                "message_id_hash": key,
                "interaction_id": interaction_id,
                "send_command_id": send_command_id,
            },
            actor=actor,
            evidence_ref=evidence_ref,
        )
        return MessageReferenceResult(entity_id, True)

    def register_message_reference(
        self,
        *,
        conversation_id: str,
        direction: str,
        external_message_id: str,
        actor: str,
        evidence_ref: str,
        interaction_id: str = "",
        send_command_id: str = "",
        email_message_id: str = "",
    ) -> MessageReferenceResult:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        conversation_id = _required(conversation_id, "conversation_id")
        with self.store.transaction(min_schema_version=14) as con:
            return self._register_message_tx(
                con,
                conversation_id=conversation_id,
                direction=direction,
                external_message_id=external_message_id,
                interaction_id=interaction_id,
                send_command_id=send_command_id,
                actor=actor,
                evidence_ref=evidence_ref,
                email_message_id=email_message_id,
            )

    def _review_tx(
        self,
        con: Any,
        *,
        interaction: Any,
        reason: str,
        candidate_count: int,
        actor: str,
        evidence_ref: str,
        in_reply_to: str,
        references: Sequence[str],
    ) -> ConversationRouteResult:
        interaction_id = str(interaction["lf_interaction_id"])
        existing = con.execute(
            """SELECT * FROM conversation_route_reviews
               WHERE interaction_id=? AND state='OPEN'""",
            (interaction_id,),
        ).fetchone()
        con.execute(
            """UPDATE interactions SET mailbox_account_id=?,in_reply_to=?,
                      references_json=?,conversation_id='',thread_route_state='REVIEW'
               WHERE lf_interaction_id=? AND COALESCE(thread_route_state,'')<>'EXACT'""",
            (
                str(interaction["mailbox_account_id"] or ""),
                in_reply_to,
                canonical_json(list(references)),
                interaction_id,
            ),
        )
        if existing:
            return ConversationRouteResult(
                interaction_id, REVIEW, False, review_id=str(existing["review_id"]),
                reason=str(existing["reason"]), candidate_count=int(existing["candidate_count"]),
            )
        review_id = new_lf_id("conversation_review")
        now = utc_now()
        try:
            con.execute(
                """INSERT INTO conversation_route_reviews(
                       review_id,interaction_id,reason,candidate_count,state,
                       evidence_ref,created_at_utc,resolved_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (review_id, interaction_id, reason, int(candidate_count), OPEN, evidence_ref, now, ""),
            )
        except sqlite3.IntegrityError as exc:
            raise ConversationRoutingError("conversation review uniqueness conflict") from exc
        self._event_tx(
            con,
            event_type="conversation_route_review_required",
            aggregate_type="interaction",
            aggregate_id=interaction_id,
            idempotency_key=f"conversation-route-review:{review_id}",
            payload={
                "review_id": review_id,
                "reason": reason,
                "candidate_count": int(candidate_count),
                "mailbox_account_id": str(interaction["mailbox_account_id"] or ""),
                "peer_address_hash": str(interaction["address_hash"] or ""),
            },
            actor=actor,
            evidence_ref=evidence_ref,
            causation_id=str(interaction["source_event_id"] or ""),
        )
        return ConversationRouteResult(
            interaction_id, REVIEW, True, review_id=review_id,
            reason=reason, candidate_count=int(candidate_count),
        )

    def route_interaction(
        self, interaction_id: str, *, actor: str, evidence_ref: str
    ) -> ConversationRouteResult:
        """Resolve persisted headers without accepting identity fields from the caller."""
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        interaction_id = _required(interaction_id, "interaction_id")
        with self.store.transaction(min_schema_version=14) as con:
            interaction = con.execute(
                "SELECT * FROM interactions WHERE lf_interaction_id=?", (interaction_id,)
            ).fetchone()
            if not interaction:
                raise KeyError("interaction does not exist")
            if str(interaction["direction"]) != "INBOUND":
                raise ConversationRoutingError("only an inbound interaction can be routed")
            current_state = str(interaction["thread_route_state"] or "")
            if current_state == EXACT:
                conversation_id = str(interaction["conversation_id"] or "")
                if not conversation_id:
                    raise ConversationRoutingError("EXACT route has no conversation")
                return ConversationRouteResult(
                    interaction_id, EXACT, False, conversation_id=conversation_id,
                    candidate_count=1,
                )
            existing_review = con.execute(
                """SELECT * FROM conversation_route_reviews
                   WHERE interaction_id=? AND state='OPEN'""",
                (interaction_id,),
            ).fetchone()
            if existing_review:
                return ConversationRouteResult(
                    interaction_id, REVIEW, False,
                    review_id=str(existing_review["review_id"]),
                    reason=str(existing_review["reason"]),
                    candidate_count=int(existing_review["candidate_count"]),
                )

            reference_parse_state = str(
                interaction["reference_parse_state"] or "OK"
            ).strip().upper()
            if reference_parse_state != "OK":
                return self._review_tx(
                    con, interaction=interaction, reason="MALFORMED_THREAD_HEADERS",
                    candidate_count=0, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to="", references=(),
                )
            in_reply_tokens, bad_in_reply = _parse_header(
                interaction["in_reply_to"], single=True
            )
            reference_tokens, bad_references = _parse_references_json(
                interaction["references_json"]
            )
            stored_in_reply = in_reply_tokens[0] if len(in_reply_tokens) == 1 else ""
            all_tokens = _dedupe([*in_reply_tokens, *reference_tokens])
            if bad_in_reply or bad_references:
                return self._review_tx(
                    con, interaction=interaction, reason="MALFORMED_THREAD_HEADERS",
                    candidate_count=0, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if not all_tokens:
                return self._review_tx(
                    con, interaction=interaction, reason="MISSING_THREAD_REFERENCE",
                    candidate_count=0, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )

            mailbox_id = str(interaction["mailbox_account_id"] or "")
            if not mailbox_id:
                return self._review_tx(
                    con, interaction=interaction, reason="MAILBOX_MISMATCH",
                    candidate_count=0, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            reference_keys = [message_id_key(token) for token in all_tokens]
            placeholders = ",".join("?" for _ in reference_keys)
            candidates = con.execute(
                f"""SELECT DISTINCT c.*,
                            s.mailbox_account_id AS identity_mailbox_account_id
                     FROM conversation_messages m
                     JOIN conversations c ON c.conversation_id=m.conversation_id
                     JOIN sender_identities s ON s.sender_identity_id=c.sender_identity_id
                     WHERE m.direction='OUTBOUND' AND m.message_id_key IN ({placeholders})
                       AND m.mailbox_account_id=? AND c.mailbox_account_id=?
                       AND c.state='ACTIVE'
                     ORDER BY c.conversation_id""",
                (*reference_keys, mailbox_id, mailbox_id),
            ).fetchall()
            candidate_count = len(candidates)
            if candidate_count == 0:
                unscoped_count = con.execute(
                    f"""SELECT COUNT(DISTINCT c.conversation_id)
                         FROM conversation_messages m
                         JOIN conversations c ON c.conversation_id=m.conversation_id
                         WHERE m.direction='OUTBOUND'
                           AND m.message_id_key IN ({placeholders})
                           AND c.state='ACTIVE'""",
                    tuple(reference_keys),
                ).fetchone()[0]
                return self._review_tx(
                    con, interaction=interaction,
                    reason=("MAILBOX_MISMATCH" if unscoped_count else "NO_CONVERSATION_MATCH"),
                    candidate_count=int(unscoped_count), actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if candidate_count != 1:
                return self._review_tx(
                    con, interaction=interaction, reason="AMBIGUOUS_CONVERSATION_MATCH",
                    candidate_count=candidate_count, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            conversation = candidates[0]
            if not mailbox_id or mailbox_id != str(conversation["mailbox_account_id"]):
                return self._review_tx(
                    con, interaction=interaction, reason="MAILBOX_MISMATCH",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            try:
                identity = self.registry.assert_sender_identity_chain_tx(
                    con, str(conversation["sender_identity_id"]), require_active=True
                )
            except (KeyError, MailRegistryError):
                return self._review_tx(
                    con, interaction=interaction, reason="CONVERSATION_CHAIN_CONFLICT",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if str(identity["mailbox_account_id"]) != mailbox_id:
                return self._review_tx(
                    con, interaction=interaction, reason="CONVERSATION_CHAIN_CONFLICT",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if mailbox_id != str(conversation["identity_mailbox_account_id"]):
                return self._review_tx(
                    con, interaction=interaction, reason="CONVERSATION_CHAIN_CONFLICT",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if str(interaction["address_hash"] or "") != str(conversation["peer_address_hash"]):
                return self._review_tx(
                    con, interaction=interaction, reason="PEER_MISMATCH",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if (
                interaction["lf_opportunity_id"]
                and str(interaction["lf_opportunity_id"]) != str(conversation["lf_opportunity_id"])
            ) or (
                interaction["lf_contact_id"]
                and str(interaction["lf_contact_id"]) != str(conversation["lf_contact_id"])
            ):
                return self._review_tx(
                    con, interaction=interaction, reason="INTERACTION_IDENTITY_CONFLICT",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )

            try:
                inbound_external_key = canonical_message_id(
                    interaction["external_message_id"]
                )
            except ValueError:
                return self._review_tx(
                    con, interaction=interaction, reason="MALFORMED_INBOUND_MESSAGE_ID",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            inbound_message_key = message_id_key(inbound_external_key)
            claim = con.execute(
                """SELECT * FROM email_message_claims
                   WHERE mailbox_account_id=? AND message_id_key=?""",
                (mailbox_id, inbound_message_key),
            ).fetchone()
            if claim and (
                str(claim["interaction_id"]) != interaction_id
                or str(claim["sender_address_hash"] or "")
                != str(interaction["address_hash"] or "")
            ):
                return self._review_tx(
                    con, interaction=interaction, reason="INBOUND_MESSAGE_ID_CONFLICT",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )
            if not claim:
                try:
                    con.execute(
                        """INSERT INTO email_message_claims(
                               claim_id,mailbox_account_id,message_id_key,interaction_id,
                               sender_address_hash,content_hash,evidence_hash,state,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?,?,?)""",
                        (
                            new_lf_id("message_claim"), mailbox_id, inbound_message_key,
                            interaction_id, str(interaction["address_hash"] or ""),
                            "", "", ACTIVE, utc_now(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    return self._review_tx(
                        con, interaction=interaction,
                        reason="INBOUND_MESSAGE_ID_CONFLICT",
                        candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                        in_reply_to=stored_in_reply, references=reference_tokens,
                    )
            collisions = con.execute(
                """SELECT * FROM conversation_messages
                   WHERE mailbox_account_id=? AND message_id_key=?
                   ORDER BY email_message_id""",
                (mailbox_id, inbound_message_key),
            ).fetchall()
            allowed_existing = [
                row for row in collisions
                if str(row["direction"]) == "INBOUND"
                and str(row["interaction_id"] or "") == interaction_id
                and str(row["conversation_id"]) == str(conversation["conversation_id"])
            ]
            if collisions and len(allowed_existing) != len(collisions):
                return self._review_tx(
                    con, interaction=interaction, reason="INBOUND_MESSAGE_ID_CONFLICT",
                    candidate_count=1, actor=actor, evidence_ref=evidence_ref,
                    in_reply_to=stored_in_reply, references=reference_tokens,
                )

            con.execute(
                """UPDATE interactions SET lf_opportunity_id=?,lf_contact_id=?,
                          mailbox_account_id=?,in_reply_to=?,references_json=?,
                          conversation_id=?,thread_route_state='EXACT'
                   WHERE lf_interaction_id=? AND COALESCE(thread_route_state,'')<>'EXACT'""",
                (
                    conversation["lf_opportunity_id"], conversation["lf_contact_id"],
                    mailbox_id, stored_in_reply, canonical_json(reference_tokens),
                    conversation["conversation_id"], interaction_id,
                ),
            )
            if not allowed_existing:
                self._register_message_tx(
                    con,
                    conversation_id=str(conversation["conversation_id"]),
                    direction="INBOUND",
                    external_message_id=inbound_external_key,
                    interaction_id=interaction_id,
                    send_command_id="",
                    actor=actor,
                    evidence_ref=evidence_ref,
                    fingerprint_hash=str(
                        interaction["message_fingerprint_hash"] or ""
                    ),
                )
            self._event_tx(
                con,
                event_type="conversation_route_exact",
                aggregate_type="interaction",
                aggregate_id=interaction_id,
                idempotency_key=f"conversation-route-exact:{interaction_id}",
                payload={
                    "conversation_id": str(conversation["conversation_id"]),
                    "mailbox_account_id": mailbox_id,
                    "peer_address_hash": str(interaction["address_hash"] or ""),
                    "matched_reference_count": len(all_tokens),
                    "state": EXACT,
                },
                actor=actor,
                evidence_ref=evidence_ref,
                causation_id=str(interaction["source_event_id"] or ""),
            )
            return ConversationRouteResult(
                interaction_id, EXACT, True,
                conversation_id=str(conversation["conversation_id"]),
                candidate_count=1,
            )


__all__ = [
    "EXACT",
    "OPEN",
    "REVIEW",
    "ConversationPinConflict",
    "ConversationPinResult",
    "ConversationRouteResult",
    "ConversationRouter",
    "ConversationRoutingError",
    "MessageReferenceResult",
    "canonical_message_id",
]
