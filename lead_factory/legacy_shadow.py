"""Read-only bridge from legacy mailbox polls into the stage event store.

The bridge has no Unisender, SMTP, Telegram, or Bitrix dependency.  It mirrors
matched inbound messages into the isolated factory database so the new intake
can be verified before any production cutover.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Mapping, Any

from .ids import payload_hash, utc_now
from .inbound import (
    AUTO_REPLY,
    HARD_BOUNCE,
    HUMAN_REPLY,
    SOFT_BOUNCE,
    UNSUBSCRIBE,
    UNSUBSCRIBE_REVIEW,
    InboundIntake,
    InboundMessage,
)
from .store import FactoryStore


_HARD_BOUNCE_MARKERS = (
    "5.1.1",
    "5.1.0",
    "5.4.1",
    "user unknown",
    "unknown user",
    "no such user",
    "mailbox not found",
    "recipient address rejected",
    "address does not exist",
    "пользователь не найден",
    "адрес не существует",
    "ящик не существует",
)


def _received_at(raw_date: str) -> str:
    try:
        value = parsedate_to_datetime(str(raw_date or ""))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return utc_now()


def _fallback_uid(reply: Mapping[str, Any]) -> str:
    raw = "|".join(
        str(reply.get(key, "") or "")
        for key in ("from", "to", "date", "subject", "body")
    )
    return "legacy-" + hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()


def _classification(
    reply: Mapping[str, Any],
    *,
    contact_address: str,
    bounce: bool,
    unsubscribe: bool,
    auto_reply: bool,
) -> str:
    if bounce:
        evidence = "\n".join(
            str(reply.get(key, "") or "").lower()
            for key in ("subject", "body")
        )
        return HARD_BOUNCE if any(marker in evidence for marker in _HARD_BOUNCE_MARKERS) else SOFT_BOUNCE
    if unsubscribe:
        sender = str(reply.get("from", "") or "").strip().lower()
        target = str(contact_address or "").strip().lower()
        return UNSUBSCRIBE if sender and sender == target else UNSUBSCRIBE_REVIEW
    if auto_reply:
        return AUTO_REPLY
    return HUMAN_REPLY


def capture_campaign_reply(
    *,
    campaign_id: str,
    producer: str,
    reply: Mapping[str, Any],
    contact_address: str,
    bounce: bool = False,
    unsubscribe: bool = False,
    auto_reply: bool = False,
    create_human_task: bool = True,
    store: FactoryStore | None = None,
):
    """Persist one matched reply in stage and return the idempotent result."""
    subject = str(reply.get("subject", "") or "")
    body = str(reply.get("body", "") or "")
    raw_date = str(reply.get("date", "") or "")
    message_id = str(reply.get("msgid", "") or "").strip()
    uid = str(reply.get("uid", "") or "").strip() or _fallback_uid(reply)
    evidence_key = message_id or uid
    evidence_ref = "imap-stage:" + payload_hash(
        {"campaign_id": campaign_id, "message_key": evidence_key}
    )
    intake = InboundIntake(store or FactoryStore())
    return intake.ingest(
        InboundMessage(
            producer=producer,
            mailbox="alumcomplete-inbox",
            external_message_id=message_id,
            uid=uid,
            uid_validity=str(reply.get("uidvalidity", "") or ""),
            from_address=str(reply.get("from", "") or ""),
            contact_address=contact_address,
            received_at_utc=_received_at(raw_date),
            channel="email",
            thread_id=str(reply.get("in_reply_to", "") or ""),
            classification=_classification(
                reply,
                contact_address=contact_address,
                bounce=bounce,
                unsubscribe=unsubscribe,
                auto_reply=auto_reply,
            ),
            campaign_id=campaign_id,
            evidence_ref=evidence_ref,
            subject_hash=payload_hash({"subject": subject}),
            content_hash=payload_hash({"body": body, "raw_date": raw_date}),
            create_human_task=create_human_task,
        )
    )


def close_dealer_shadow_tasks_already_handled(
    *,
    state_path: str | Path,
    store: FactoryStore | None = None,
) -> int:
    """Close historical shadow tasks already handled by the legacy campaign.

    This touches only local stage tasks and records an immutable reconciliation
    event. It does not call email, Telegram, or Bitrix.
    """
    state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    dealers = state.get("dealers", {}) if isinstance(state, dict) else {}
    factory = store or FactoryStore()
    closed = 0
    terminal = {
        "lead", "unsub", "bounce", "bitrix_pending", "warm", "question",
        "refusal", "review", "done",
    }
    with factory.transaction() as con:
        rows = con.execute(
            """SELECT t.lf_task_id,i.address,i.external_message_id
               FROM human_tasks t JOIN interactions i
                 ON i.lf_interaction_id=t.lf_interaction_id
               JOIN events e ON e.event_id=i.source_event_id
               WHERE t.status='OPEN' AND e.producer='legacy_dealer_poll'"""
        ).fetchall()
        now = utc_now()
        for row in rows:
            record = dealers.get(str(row["address"] or "").lower())
            if not isinstance(record, dict):
                continue
            was_seen = bool(
                row["external_message_id"]
                and row["external_message_id"] in (record.get("processed_reply_ids") or [])
            )
            legacy_status = str(record.get("status", ""))
            if not was_seen and legacy_status not in terminal:
                continue
            con.execute(
                """UPDATE human_tasks SET status='CLOSED_LEGACY_HANDLED',
                   closed_at_utc=CASE WHEN closed_at_utc='' THEN ? ELSE closed_at_utc END,
                   resolution='LEGACY_ALREADY_HANDLED'
                   WHERE lf_task_id=? AND status='OPEN'""",
                (now, row["lf_task_id"]),
            )
            self_event_key = f"shadow-task-reconciled:{row['lf_task_id']}"
            factory._append_event_tx(
                con,
                event_type="shadow_task_reconciled",
                aggregate_type="task",
                aggregate_id=row["lf_task_id"],
                producer="legacy_shadow_reconcile",
                idempotency_key=self_event_key,
                payload={"status": "CLOSED_LEGACY_HANDLED", "legacy_status": legacy_status},
                actor="shadow_reconcile",
            )
            closed += 1
    return closed


__all__ = ["capture_campaign_reply", "close_dealer_shadow_tasks_already_handled"]
