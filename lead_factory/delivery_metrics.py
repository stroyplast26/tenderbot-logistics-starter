"""Offline delivery-event ledger and identity-scoped funnel metrics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .ids import new_lf_id, payload_hash, utc_now
from .multimail_policy import MultiMailSendGate
from .store import FactoryStore, IdempotencyConflict


DELIVERY_EVENT_TYPES = frozenset(
    {
        "DELIVERED",
        "HARD_BOUNCE",
        "SOFT_BOUNCE",
        "COMPLAINT",
        "UNSUBSCRIBE",
        "OPEN",
        "CLICK",
    }
)


class DeliveryEventError(RuntimeError):
    """A provider event cannot be bound to one canonical sent command."""


@dataclass(frozen=True)
class DeliveryEventResult:
    delivery_event_id: str
    command_id: str
    created: bool


def _required(value: object, label: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValueError(f"{label} is required")
    return result


def _timestamp(value: object, label: str) -> str:
    raw = _required(value, label)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError(f"{label} is invalid") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{label} is invalid")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


class DeliveryEventTracker:
    """Persist a provider event only after exact SENT-command reconciliation."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_event_hook: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.after_event_hook = after_event_hook

    def _sent_command_tx(
        self, con: Any, provider_account_id: str, provider_message_id: str
    ) -> Any:
        rows = con.execute(
            """SELECT o.command_id,o.message_id AS command_message_id,o.state AS command_state,
                      o.provider_message_id,o.conversation_id AS command_conversation_id,
                      p.permit_id,p.message_id AS permit_message_id,
                      p.conversation_id AS permit_conversation_id,
                      p.state AS permit_state,p.provider_account_id,
                      p.sending_domain_id,p.sender_identity,p.campaign_id,
                      p.mailbox_account_id,p.address_hash,p.lf_opportunity_id,
                      p.lf_contact_id,p.company_id,
                      c.sender_identity_id AS conversation_sender_identity_id,
                      c.mailbox_account_id AS conversation_mailbox_account_id,
                      c.campaign_id AS conversation_campaign_id,
                      c.peer_address_hash,c.lf_opportunity_id AS conversation_opportunity_id,
                      c.lf_contact_id AS conversation_contact_id
               FROM outbox o
               JOIN send_permits p ON p.permit_id=o.permit_id
               JOIN conversations c ON c.conversation_id=o.conversation_id
               WHERE p.provider_account_id=? AND o.provider_message_id=?
                 AND o.provider_message_id<>'' AND o.state='SENT'""",
            (provider_account_id, provider_message_id),
        ).fetchall()
        if len(rows) != 1:
            raise DeliveryEventError("provider message does not resolve to one SENT command")
        row = rows[0]
        if str(row["permit_state"]) != "SENT":
            raise DeliveryEventError("sent command permit is not reconciled")
        exact = (
            str(row["command_message_id"]) == str(row["permit_message_id"])
            and str(row["command_conversation_id"]) == str(row["permit_conversation_id"])
            and str(row["sender_identity"]) == str(row["conversation_sender_identity_id"])
            and str(row["mailbox_account_id"]) == str(row["conversation_mailbox_account_id"])
            and str(row["campaign_id"]) == str(row["conversation_campaign_id"])
            and str(row["address_hash"]) == str(row["peer_address_hash"])
            and str(row["lf_opportunity_id"]) == str(row["conversation_opportunity_id"])
            and str(row["lf_contact_id"]) == str(row["conversation_contact_id"])
        )
        if not exact:
            raise DeliveryEventError("sent command canonical conversation scope changed")
        permit = con.execute(
            "SELECT * FROM send_permits WHERE permit_id=?", (row["permit_id"],)
        ).fetchone()
        reservation_problem = MultiMailSendGate(self.store)._permit_reservation_problem_tx(
            con, permit
        )
        if reservation_problem:
            raise DeliveryEventError(reservation_problem[1])
        return row

    @staticmethod
    def _add_suppression_tx(
        con: Any,
        *,
        scope: str,
        subject_id: str,
        address_hash: str,
        reason: str,
        evidence_ref: str,
        now: str,
    ) -> tuple[str, bool]:
        existing_rows = con.execute(
            """SELECT suppression_id,address_hash FROM suppression_entries
               WHERE state='ACTIVE' AND channel='email' AND scope=?
                 AND subject_id=? AND reason=?""",
            (scope, subject_id, reason),
        ).fetchall()
        if existing_rows:
            if scope == "EMAIL_ADDRESS" and any(
                str(row["address_hash"] or "") != address_hash for row in existing_rows
            ):
                raise DeliveryEventError("existing address suppression is malformed")
            existing = existing_rows[0]
            return str(existing["suppression_id"]), False
        suppression_id = new_lf_id("suppression")
        con.execute(
            """INSERT INTO suppression_entries(
                   suppression_id,subject_type,subject_id,channel,address,address_hash,
                   reason,scope,evidence_ref,source,author,created_at_utc,
                   expires_at_utc,state
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                suppression_id,
                "EMAIL_ADDRESS" if scope == "EMAIL_ADDRESS" else scope,
                subject_id,
                "email",
                "",
                address_hash if scope == "EMAIL_ADDRESS" else "",
                reason,
                scope,
                evidence_ref,
                "delivery_event",
                "delivery_event_tracker",
                now,
                "",
                "ACTIVE",
            ),
        )
        return suppression_id, True

    @staticmethod
    def _required_suppressions_present_tx(con: Any, command: Any, kind: str) -> bool:
        if kind not in {"HARD_BOUNCE", "COMPLAINT", "UNSUBSCRIBE"}:
            return True
        address = con.execute(
            """SELECT 1 FROM suppression_entries
               WHERE state='ACTIVE' AND channel='email' AND scope='EMAIL_ADDRESS'
                 AND subject_id=? AND address_hash=? AND reason=? LIMIT 1""",
            (command["address_hash"], command["address_hash"], kind),
        ).fetchone()
        if not address:
            return False
        if kind == "COMPLAINT":
            campaign = con.execute(
                """SELECT 1 FROM suppression_entries
                   WHERE state='ACTIVE' AND channel='email' AND scope='CAMPAIGN'
                     AND subject_id=? AND reason='PROVIDER_COMPLAINT' LIMIT 1""",
                (command["campaign_id"],),
            ).fetchone()
            return bool(campaign)
        return True

    def record_event(
        self,
        *,
        provider_account_id: str,
        provider_message_id: str,
        provider_event_key: str,
        event_type: str,
        payload: Mapping[str, Any],
        evidence_ref: str,
        occurred_at_utc: str,
        actor: str = "delivery_sync",
    ) -> DeliveryEventResult:
        provider_id = _required(provider_account_id, "provider_account_id")
        provider_message = _required(provider_message_id, "provider_message_id")
        event_key = _required(provider_event_key, "provider_event_key")
        kind = _required(event_type, "event_type").upper()
        if kind not in DELIVERY_EVENT_TYPES:
            raise ValueError("event_type is not allowed")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")
        try:
            digest = payload_hash(dict(payload))
        except (TypeError, ValueError):
            raise ValueError("payload is not canonical JSON") from None
        evidence = _required(evidence_ref, "evidence_ref")
        actor_id = _required(actor, "actor")
        occurred = _timestamp(occurred_at_utc, "occurred_at_utc")
        occurred_dt = datetime.fromisoformat(occurred.replace("Z", "+00:00"))
        if occurred_dt > datetime.now(timezone.utc) + timedelta(minutes=15):
            raise ValueError("occurred_at_utc is implausibly in the future")

        with self.store.transaction(min_schema_version=14) as con:
            command = self._sent_command_tx(con, provider_id, provider_message)
            existing = con.execute(
                """SELECT * FROM delivery_events
                   WHERE provider_account_id=? AND provider_event_key=?""",
                (provider_id, event_key),
            ).fetchone()
            if existing:
                exact = (
                    str(existing["command_id"]) == str(command["command_id"])
                    and str(existing["message_id"]) == str(command["command_message_id"])
                    and str(existing["event_type"]) == kind
                    and str(existing["payload_hash"]) == digest
                    and str(existing["evidence_ref"]) == evidence
                    and str(existing["occurred_at_utc"]) == occurred
                )
                if not exact:
                    raise IdempotencyConflict("provider event key was reused with different facts")
                if not self._required_suppressions_present_tx(con, command, kind):
                    raise DeliveryEventError("required delivery suppression is missing")
                return DeliveryEventResult(
                    str(existing["delivery_event_id"]), str(command["command_id"]), False
                )

            event_id = new_lf_id("delivery_event")
            now = utc_now()
            con.execute(
                """INSERT INTO delivery_events(
                       delivery_event_id,command_id,provider_account_id,sending_domain_id,
                       sender_identity_id,campaign_id,message_id,provider_event_key,
                       event_type,recipient_address_hash,payload_hash,evidence_ref,
                       occurred_at_utc,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id,
                    command["command_id"],
                    provider_id,
                    command["sending_domain_id"],
                    command["sender_identity"],
                    command["campaign_id"],
                    command["command_message_id"],
                    event_key,
                    kind,
                    command["address_hash"],
                    digest,
                    evidence,
                    occurred,
                    now,
                ),
            )
            if self.after_event_hook:
                self.after_event_hook()

            suppression_changes: list[dict[str, Any]] = []
            if kind in {"HARD_BOUNCE", "COMPLAINT", "UNSUBSCRIBE"}:
                suppression_id, created = self._add_suppression_tx(
                    con,
                    scope="EMAIL_ADDRESS",
                    subject_id=str(command["address_hash"]),
                    address_hash=str(command["address_hash"]),
                    reason=kind,
                    evidence_ref=evidence,
                    now=now,
                )
                suppression_changes.append(
                    {"suppression_id": suppression_id, "scope": "EMAIL_ADDRESS", "created": created}
                )
            if kind == "COMPLAINT":
                suppression_id, created = self._add_suppression_tx(
                    con,
                    scope="CAMPAIGN",
                    subject_id=str(command["campaign_id"]),
                    address_hash="",
                    reason="PROVIDER_COMPLAINT",
                    evidence_ref=evidence,
                    now=now,
                )
                suppression_changes.append(
                    {"suppression_id": suppression_id, "scope": "CAMPAIGN", "created": created}
                )

            self.store._append_event_tx(
                con,
                event_type="delivery_event_recorded",
                aggregate_type="message",
                aggregate_id=payload_hash({"internal_message_id": str(command["command_message_id"])}),
                producer="delivery_event_tracker",
                idempotency_key=f"delivery:{provider_id}:{payload_hash({'event_key': event_key})}",
                payload={
                    "delivery_event_id": event_id,
                    "command_id": str(command["command_id"]),
                    "event_type": kind,
                    "sending_domain_id": str(command["sending_domain_id"]),
                    "sender_identity_id": str(command["sender_identity"]),
                    "campaign_id": str(command["campaign_id"]),
                    "provider_event_key_hash": payload_hash({"provider_event_key": event_key}),
                    "suppression_changes": suppression_changes,
                },
                evidence_ref=evidence,
                actor=actor_id,
                occurred_at_utc=occurred,
                schema_version=14,
            )
            return DeliveryEventResult(event_id, str(command["command_id"]), True)


def delivery_metrics(store: FactoryStore) -> list[dict[str, Any]]:
    """Return unique-first-attempt metrics per domain/identity/campaign tuple."""
    with store.transaction(min_schema_version=14) as con:
        sent = con.execute(
            """SELECT p.sending_domain_id,p.sender_identity AS sender_identity_id,
                      p.campaign_id,COUNT(DISTINCT o.command_id) AS sent_count
               FROM outbox o JOIN send_permits p ON p.permit_id=o.permit_id
               WHERE o.state='SENT' AND p.state='SENT' AND p.touch_type='FIRST_TOUCH'
               GROUP BY p.sending_domain_id,p.sender_identity,p.campaign_id"""
        ).fetchall()
        events = con.execute(
            """SELECT d.sending_domain_id,d.sender_identity_id,d.campaign_id,d.event_type,
                      COUNT(DISTINCT d.command_id) AS event_count
               FROM delivery_events d
               JOIN outbox o ON o.command_id=d.command_id
               JOIN send_permits p ON p.permit_id=o.permit_id
               WHERE p.touch_type='FIRST_TOUCH'
               GROUP BY d.sending_domain_id,d.sender_identity_id,d.campaign_id,d.event_type"""
        ).fetchall()
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in sent:
        key = (
            str(row["sending_domain_id"]),
            str(row["sender_identity_id"]),
            str(row["campaign_id"]),
        )
        grouped[key] = {
            "sending_domain_id": key[0],
            "sender_identity_id": key[1],
            "campaign_id": key[2],
            "first_touch_sent": int(row["sent_count"]),
            **{event.lower(): 0 for event in sorted(DELIVERY_EVENT_TYPES)},
        }
    for row in events:
        key = (
            str(row["sending_domain_id"]),
            str(row["sender_identity_id"]),
            str(row["campaign_id"]),
        )
        metric = grouped.setdefault(
            key,
            {
                "sending_domain_id": key[0],
                "sender_identity_id": key[1],
                "campaign_id": key[2],
                "first_touch_sent": 0,
                **{event.lower(): 0 for event in sorted(DELIVERY_EVENT_TYPES)},
            },
        )
        metric[str(row["event_type"]).lower()] = int(row["event_count"])
    return [grouped[key] for key in sorted(grouped)]


__all__ = [
    "DELIVERY_EVENT_TYPES",
    "DeliveryEventError",
    "DeliveryEventResult",
    "DeliveryEventTracker",
    "delivery_metrics",
]
