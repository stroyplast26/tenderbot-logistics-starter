"""Strict offline Send Gate for identity-pinned multi-mail conversations.

This module has no transport boundary.  It derives every commercial and mail
identity from persisted v14 relations, applies the shared suppression ledger,
and reserves all quota layers in one ``BEGIN IMMEDIATE`` transaction.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .conversation_routing import ConversationRouter, canonical_message_id
from .ids import address_hash, new_lf_id, normalize_domain, normalize_email, payload_hash, utc_now
from .mail_registry import ACTIVE, MailRegistry, MailRegistryError
from .policy import PolicyDecision
from .store import FactoryStore, IdempotencyConflict


MOSCOW = timezone(timedelta(hours=3))
HELD = "HELD"
CONSUMED = "CONSUMED"
RELEASED = "RELEASED"
_INTERNAL_MESSAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}")


class MultiMailPolicyError(RuntimeError):
    """A fail-closed canonical identity or quota invariant was violated."""


@dataclass(frozen=True)
class MultiMailSendIntent:
    message_id: str
    authorization_id: str
    conversation_id: str
    address: str
    segment_id: str
    cohort_id: str
    content_version: str
    touch_type: str = "FIRST_TOUCH"


class MultiMailSendGate:
    """Issue durable permits and stage commands without calling a provider."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        permit_ttl_minutes: int = 15,
        clock: Callable[[], str | datetime] | None = None,
        after_reservations_hook: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.registry = MailRegistry(store)
        self.permit_ttl_minutes = max(1, int(permit_ttl_minutes))
        self.clock = clock
        self.after_reservations_hook = after_reservations_hook

    @staticmethod
    def _required(value: object, label: str) -> str:
        result = str(value or "").strip()
        if not result:
            raise ValueError(f"{label} is required")
        return result

    @staticmethod
    def _parse_utc(value: object, label: str) -> datetime:
        raw = str(value or "").strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise ValueError(f"{label} is invalid") from None
        if parsed.tzinfo is None:
            raise ValueError(f"{label} is invalid")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_utc(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )

    def _now_dt(self) -> datetime:
        value = self.clock() if self.clock else utc_now()
        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError("clock must return an aware timestamp")
            return value.astimezone(timezone.utc)
        return self._parse_utc(value, "clock timestamp")

    @staticmethod
    def _recipient_domain(address: str) -> str:
        normalized = normalize_email(address)
        return normalize_domain(normalized.rsplit("@", 1)[1]) if "@" in normalized else ""

    @staticmethod
    def _cap(value: object, label: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{label} must be a non-negative integer")
        try:
            result = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{label} must be a non-negative integer") from None
        if result < 0:
            raise ValueError(f"{label} must be a non-negative integer")
        return result

    @staticmethod
    def payload_digest(intent: MultiMailSendIntent, payload: dict[str, Any]) -> str:
        return payload_hash(
            {
                "message_id": str(intent.message_id or "").strip(),
                "authorization_id": str(intent.authorization_id or "").strip(),
                "conversation_id": str(intent.conversation_id or "").strip(),
                "address_hash": address_hash(intent.address),
                "segment_id": str(intent.segment_id or "").strip(),
                "cohort_id": str(intent.cohort_id or "").strip(),
                "content_version": str(intent.content_version or "").strip(),
                "touch_type": str(intent.touch_type or "").strip().upper(),
                "payload": payload or {},
            }
        )

    def _context_tx(
        self, con: Any, conversation_id: str, *, recipient_address: str | None = None
    ) -> dict[str, Any]:
        conversation_id = self._required(conversation_id, "conversation_id")
        row = con.execute(
            """SELECT c.*,
                      o.lf_company_id AS company_id,
                      o.status AS opportunity_status,
                      o.lf_contact_id AS opportunity_contact_id,
                      o.lf_project_id AS opportunity_project_id,
                      ct.lf_company_id AS contact_company_id,
                      ct.email AS contact_email,
                      ct.email_hash AS contact_email_hash,
                      p.lf_company_id AS project_company_id
               FROM conversations c
               JOIN opportunities o ON o.lf_opportunity_id=c.lf_opportunity_id
               JOIN contacts ct ON ct.lf_contact_id=c.lf_contact_id
               LEFT JOIN projects p ON p.lf_project_id=o.lf_project_id
               WHERE c.conversation_id=?""",
            (conversation_id,),
        ).fetchone()
        if not row or str(row["state"]) != ACTIVE:
            raise MultiMailPolicyError("an ACTIVE canonical conversation is required")
        if str(row["opportunity_contact_id"] or "") != str(row["lf_contact_id"]):
            raise MultiMailPolicyError("conversation contact is not the opportunity contact")
        if str(row["company_id"]) != str(row["contact_company_id"]):
            raise MultiMailPolicyError("contact and opportunity companies differ")
        if row["opportunity_project_id"] and str(row["company_id"]) != str(
            row["project_company_id"] or ""
        ):
            raise MultiMailPolicyError("project and opportunity companies differ")

        contact_email = normalize_email(str(row["contact_email"] or ""))
        if not contact_email or "@" not in contact_email:
            raise MultiMailPolicyError("canonical contact email is missing")
        contact_hash = address_hash(contact_email)
        if contact_hash != str(row["contact_email_hash"] or ""):
            raise MultiMailPolicyError("canonical contact email hash changed")
        if contact_hash != str(row["peer_address_hash"] or ""):
            raise MultiMailPolicyError("conversation peer is not the canonical contact")
        if recipient_address is not None:
            candidate = normalize_email(recipient_address)
            if not candidate or "@" not in candidate or address_hash(candidate) != contact_hash:
                raise MultiMailPolicyError("recipient does not match the canonical conversation peer")

        try:
            identity = self.registry.assert_sender_identity_chain_tx(
                con, str(row["sender_identity_id"]), require_active=True
            )
        except (KeyError, MailRegistryError) as exc:
            raise MultiMailPolicyError("sender identity chain is not active and consistent") from exc
        if str(identity["mailbox_account_id"]) != str(row["mailbox_account_id"]):
            raise MultiMailPolicyError("conversation mailbox is not pinned to its sender identity")

        provider = con.execute(
            "SELECT state,daily_send_cap FROM provider_accounts WHERE provider_account_id=?",
            (identity["provider_account_id"],),
        ).fetchone()
        domain = con.execute(
            """SELECT state,daily_send_cap,provider_account_id,reputation_state
               FROM sending_domains WHERE sending_domain_id=?""",
            (identity["sending_domain_id"],),
        ).fetchone()
        mailbox = con.execute(
            """SELECT state,daily_send_cap,provider_account_id,sending_domain_id
               FROM mailbox_accounts WHERE mailbox_account_id=?""",
            (identity["mailbox_account_id"],),
        ).fetchone()
        campaign = con.execute(
            "SELECT state,daily_send_cap,lifetime_send_cap FROM mail_campaigns WHERE campaign_id=?",
            (row["campaign_id"],),
        ).fetchone()
        if not all((provider, domain, mailbox, campaign)):
            raise MultiMailPolicyError("canonical mail chain is incomplete")
        if any(str(parent["state"]) != ACTIVE for parent in (provider, domain, mailbox, campaign)):
            raise MultiMailPolicyError("canonical mail chain is not ACTIVE")
        healthy_reputation = {"VERIFIED", "HEALTHY", "GOOD"}
        if str(domain["reputation_state"] or "").upper() not in healthy_reputation:
            raise MultiMailPolicyError("sending domain reputation is not verified")
        if str(identity["reputation_state"] or "").upper() not in healthy_reputation:
            raise MultiMailPolicyError("sender identity reputation is not verified")
        if str(domain["provider_account_id"]) != str(identity["provider_account_id"]):
            raise MultiMailPolicyError("sending domain provider relationship changed")

        return {
            "conversation_id": conversation_id,
            "lf_opportunity_id": str(row["lf_opportunity_id"]),
            "opportunity_status": str(row["opportunity_status"]),
            "lf_contact_id": str(row["lf_contact_id"]),
            "company_id": str(row["company_id"]),
            "recipient_address_hash": contact_hash,
            "recipient_domain": self._recipient_domain(contact_email),
            "provider_account_id": str(identity["provider_account_id"]),
            "sending_domain_id": str(identity["sending_domain_id"]),
            "mailbox_account_id": str(identity["mailbox_account_id"]),
            "sender_identity_id": str(row["sender_identity_id"]),
            "campaign_id": str(row["campaign_id"]),
            "provider_daily_cap": int(provider["daily_send_cap"]),
            "domain_daily_cap": int(domain["daily_send_cap"]),
            "mailbox_daily_cap": int(mailbox["daily_send_cap"]),
            "sender_daily_cap": int(identity["daily_send_cap"]),
            "campaign_daily_cap": int(campaign["daily_send_cap"]),
            "campaign_lifetime_cap": int(campaign["lifetime_send_cap"]),
        }

    def create_authorization(
        self,
        *,
        conversation_id: str,
        segment_id: str,
        cohort_id: str,
        content_version: str,
        first_touch_cap: int,
        followup_cap: int,
        valid_from_utc: str,
        valid_until_utc: str,
        legal_status: str,
        legal_evidence_ref: str,
        suppression_snapshot_id: str,
        approver: str,
        lifetime_first_touch_cap: int | None = None,
        lifetime_followup_cap: int | None = None,
        stop_rules: dict[str, Any] | None = None,
        state: str = ACTIVE,
        authorization_id: str = "",
    ) -> str:
        segment = self._required(segment_id, "segment_id")
        cohort = self._required(cohort_id, "cohort_id")
        content = self._required(content_version, "content_version")
        evidence = self._required(legal_evidence_ref, "legal_evidence_ref")
        approver_id = self._required(approver, "approver")
        snapshot_id = self._required(suppression_snapshot_id, "suppression_snapshot_id")
        legal = self._required(legal_status, "legal_status").upper()
        auth_state = self._required(state, "state").upper()
        if legal != "APPROVED" or auth_state != ACTIVE:
            raise MultiMailPolicyError("authorization must be ACTIVE with approved legal evidence")
        if stop_rules:
            raise MultiMailPolicyError(
                "typed automatic stop rules are not enabled in the offline v14 gate"
            )
        valid_from = self._parse_utc(valid_from_utc, "valid_from_utc")
        valid_until = self._parse_utc(valid_until_utc, "valid_until_utc")
        if valid_until <= valid_from:
            raise ValueError("authorization validity window is invalid")
        first_daily = self._cap(first_touch_cap, "first_touch_cap")
        follow_daily = self._cap(followup_cap, "followup_cap")
        first_life = self._cap(
            lifetime_first_touch_cap if lifetime_first_touch_cap is not None else first_daily,
            "lifetime_first_touch_cap",
        )
        follow_life = self._cap(
            lifetime_followup_cap if lifetime_followup_cap is not None else follow_daily,
            "lifetime_followup_cap",
        )
        aid = str(authorization_id or new_lf_id("authorization")).strip()
        now = self._format_utc(self._now_dt())
        stop_rules_json = json.dumps(stop_rules or {}, ensure_ascii=False, sort_keys=True)
        with self.store.transaction(min_schema_version=14) as con:
            context = self._context_tx(con, conversation_id)
            expected = {
                "state": auth_state,
                "channel": "email",
                "segment_id": segment,
                "cohort_id": cohort,
                "content_version": content,
                "sender_identity": context["sender_identity_id"],
                "campaign_id": context["campaign_id"],
                "provider_account_id": context["provider_account_id"],
                "sending_domain_id": context["sending_domain_id"],
                "mailbox_account_id": context["mailbox_account_id"],
            }
            existing = con.execute(
                "SELECT * FROM outbound_authorizations WHERE authorization_id=?", (aid,)
            ).fetchone()
            if existing:
                numeric = {
                    "first_touch_cap": first_daily,
                    "followup_cap": follow_daily,
                    "lifetime_first_touch_cap": first_life,
                    "lifetime_followup_cap": follow_life,
                }
                provenance = {
                    "valid_from_utc": self._format_utc(valid_from),
                    "valid_until_utc": self._format_utc(valid_until),
                    "legal_status": legal,
                    "legal_evidence_ref": evidence,
                    "suppression_snapshot_id": snapshot_id,
                    "approver": approver_id,
                    "stop_rules_json": stop_rules_json,
                }
                if (
                    any(str(existing[key] or "") != str(value) for key, value in expected.items())
                    or any(int(existing[key]) != value for key, value in numeric.items())
                    or any(str(existing[key] or "") != value for key, value in provenance.items())
                ):
                    raise IdempotencyConflict("authorization id was reused with another canonical scope")
                creation_rows = con.execute(
                    """SELECT payload_json FROM events
                       WHERE event_type='multimail_authorization_created'
                         AND aggregate_type='authorization' AND aggregate_id=?
                         AND producer='multimail_policy'""",
                    (aid,),
                ).fetchall()
                try:
                    creation = (
                        json.loads(str(creation_rows[0]["payload_json"] or "{}"))
                        if len(creation_rows) == 1
                        else {}
                    )
                except (TypeError, ValueError):
                    creation = {}
                if (
                    str(creation.get("conversation_id", ""))
                    != context["conversation_id"]
                    or str(creation.get("campaign_id", "")) != context["campaign_id"]
                    or str(creation.get("sender_identity_id", ""))
                    != context["sender_identity_id"]
                ):
                    raise IdempotencyConflict(
                        "authorization id was reused for another conversation"
                    )
                return aid
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
                    aid, auth_state, "email", segment, cohort, content,
                    context["sender_identity_id"], first_daily, follow_daily, first_life,
                    follow_life, self._format_utc(valid_from), self._format_utc(valid_until),
                    legal, evidence, snapshot_id, approver_id, now,
                    stop_rules_json, now,
                    context["campaign_id"], context["provider_account_id"],
                    context["sending_domain_id"], context["mailbox_account_id"],
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="multimail_authorization_created",
                aggregate_type="authorization",
                aggregate_id=aid,
                producer="multimail_policy",
                idempotency_key=f"authorization:{aid}",
                payload={
                    "conversation_id": context["conversation_id"],
                    "campaign_id": context["campaign_id"],
                    "sender_identity_id": context["sender_identity_id"],
                    "state": ACTIVE,
                },
                evidence_ref=evidence,
                actor=approver_id,
                schema_version=14,
            )
        return aid

    def _deny_tx(
        self, con: Any, intent: MultiMailSendIntent, rule_id: str, reason: str
    ) -> PolicyDecision:
        message_id = str(intent.message_id or "").strip()
        fingerprint = payload_hash(
            {
                "message_id": message_id,
                "authorization_id": str(intent.authorization_id or "").strip(),
                "conversation_id": str(intent.conversation_id or "").strip(),
                "address_hash": address_hash(intent.address),
                "rule_id": rule_id,
                "reason": reason,
            }
        )[:24]
        self.store._append_event_tx(
            con,
            event_type="send_denied",
            aggregate_type="message",
            aggregate_id=payload_hash({"internal_message_id": message_id}) if message_id else fingerprint,
            producer="multimail_policy",
            idempotency_key=f"deny:{fingerprint}",
            payload={"rule_id": rule_id, "reason": reason, "channel": "email"},
            actor="multimail_send_gate",
            schema_version=14,
        )
        return PolicyDecision(False, rule_id, reason)

    def _suppression_problem_tx(
        self, con: Any, context: dict[str, Any], now: str
    ) -> tuple[str, str] | None:
        rows = con.execute(
            """SELECT * FROM suppression_entries
               WHERE state='ACTIVE'
                 AND (channel='email' OR channel='ALL' OR scope='ALL_CHANNELS')""",
        ).fetchall()
        now_dt = self._parse_utc(now, "policy timestamp")
        known_scopes = {
            "EMAIL_ADDRESS", "PERSON", "COMPANY", "DOMAIN",
            "CAMPAIGN", "SENDER_IDENTITY", "SENDING_DOMAIN", "PROVIDER_ACCOUNT",
            "CHANNEL", "ALL_CHANNELS",
        }
        for row in rows:
            scope = str(row["scope"])
            if scope not in known_scopes or not str(row["evidence_ref"] or "").strip():
                return "LF-POL-SUPPRESSION-INVALID", "active suppression record is invalid"
            expiry = str(row["expires_at_utc"] or "").strip()
            if expiry:
                try:
                    if self._parse_utc(expiry, "suppression expiry") <= now_dt:
                        continue
                except ValueError:
                    return "LF-POL-SUPPRESSION-INVALID", "active suppression record is invalid"
            if scope == "EMAIL_ADDRESS" and not str(row["address_hash"] or ""):
                return "LF-POL-SUPPRESSION-INVALID", "active suppression record is invalid"
            if scope in {
                "PERSON", "COMPANY", "DOMAIN", "CAMPAIGN",
                "SENDER_IDENTITY", "SENDING_DOMAIN", "PROVIDER_ACCOUNT",
            } and not str(
                row["subject_id"] or ""
            ).strip():
                return "LF-POL-SUPPRESSION-INVALID", "active suppression record is invalid"
            matches = (
                (scope == "EMAIL_ADDRESS" and str(row["address_hash"]) == context["recipient_address_hash"])
                or (scope == "PERSON" and str(row["subject_id"]) == context["lf_contact_id"])
                or (scope == "COMPANY" and str(row["subject_id"]) == context["company_id"])
                or (scope == "DOMAIN" and normalize_domain(str(row["subject_id"])) == context["recipient_domain"])
                or (scope == "CAMPAIGN" and str(row["subject_id"]) == context["campaign_id"])
                or (scope == "SENDER_IDENTITY" and str(row["subject_id"]) == context["sender_identity_id"])
                or (scope == "SENDING_DOMAIN" and str(row["subject_id"]) == context["sending_domain_id"])
                or (scope == "PROVIDER_ACCOUNT" and str(row["subject_id"]) == context["provider_account_id"])
                or scope in {"CHANNEL", "ALL_CHANNELS"}
            )
            if matches:
                return "LF-POL-LEGAL-SUPPRESSION", "canonical recipient is suppressed"
        return None

    def _pause_problem_tx(
        self, con: Any, context: dict[str, Any], intent: MultiMailSendIntent
    ) -> tuple[str, str] | None:
        for row in con.execute("SELECT * FROM pauses WHERE state='ACTIVE'").fetchall():
            scope = str(row["scope"])
            scope_id = str(row["scope_id"] or "")
            matches = (
                scope == "GLOBAL"
                or (scope == "CHANNEL" and scope_id == "email")
                or (scope == "SEGMENT" and scope_id == intent.segment_id)
                or (scope == "COHORT" and scope_id == intent.cohort_id)
                or (scope == "CAMPAIGN" and scope_id == context["campaign_id"])
                or (scope == "CONNECTOR" and scope_id == context["provider_account_id"])
                or (scope == "INBOX" and scope_id == context["mailbox_account_id"])
                or (scope == "SENDING_DOMAIN" and scope_id == context["sending_domain_id"])
            )
            if matches or scope not in {
                "GLOBAL", "CHANNEL", "SEGMENT", "COHORT", "CAMPAIGN", "CONNECTOR",
                "INBOX", "SENDING_DOMAIN"
            }:
                return "LF-POL-SAFETY-PAUSE", "an applicable safety pause is active"
        return None

    def _safety_problem_tx(
        self,
        con: Any,
        context: dict[str, Any],
        intent: MultiMailSendIntent,
        now: str,
    ) -> tuple[str, str] | None:
        suppression = self._suppression_problem_tx(con, context, now)
        if suppression:
            return suppression
        touch = str(intent.touch_type or "").strip().upper()
        allowed_state = "CONTACT_ALLOWED" if touch == "FIRST_TOUCH" else "CONTACTING"
        if context["opportunity_status"] != allowed_state:
            return "LF-POL-OPPORTUNITY-STATE", "opportunity is not eligible for this touch"
        cadence = con.execute(
            """SELECT 1 FROM cadence_blocks
               WHERE state='ACTIVE' AND channel='email' AND address_hash=? LIMIT 1""",
            (context["recipient_address_hash"],),
        ).fetchone()
        if cadence:
            return "LF-POL-CADENCE-BLOCK", "canonical contact cadence is blocked"
        return self._pause_problem_tx(con, context, intent)

    def _authorization_problem_tx(
        self,
        con: Any,
        context: dict[str, Any],
        intent: MultiMailSendIntent,
        now_dt: datetime,
    ) -> tuple[Any | None, tuple[str, str] | None]:
        auth = con.execute(
            "SELECT * FROM outbound_authorizations WHERE authorization_id=?",
            (str(intent.authorization_id or "").strip(),),
        ).fetchone()
        if not auth:
            return None, ("LF-AUTH-MISSING", "canonical authorization is required")
        if str(auth["state"]) != ACTIVE:
            return auth, ("LF-AUTH-STATE", "authorization is not ACTIVE")
        if str(auth["legal_status"]) != "APPROVED" or not str(auth["legal_evidence_ref"] or ""):
            return auth, ("LF-AUTH-LEGAL", "legal approval evidence is required")
        if now_dt < self._parse_utc(auth["valid_from_utc"], "authorization window") or now_dt > self._parse_utc(
            auth["valid_until_utc"], "authorization window"
        ):
            return auth, ("LF-AUTH-WINDOW", "authorization is outside its validity window")
        exact = {
            "channel": "email",
            "segment_id": str(intent.segment_id or "").strip(),
            "cohort_id": str(intent.cohort_id or "").strip(),
            "content_version": str(intent.content_version or "").strip(),
            "sender_identity": context["sender_identity_id"],
            "campaign_id": context["campaign_id"],
            "provider_account_id": context["provider_account_id"],
            "sending_domain_id": context["sending_domain_id"],
            "mailbox_account_id": context["mailbox_account_id"],
        }
        if any(str(auth[field] or "") != value for field, value in exact.items()):
            return auth, ("LF-AUTH-SCOPE", "authorization does not match canonical identity")
        provenance_rows = con.execute(
            """SELECT payload_json FROM events
               WHERE event_type='multimail_authorization_created'
                 AND aggregate_type='authorization' AND aggregate_id=?
                 AND producer='multimail_policy'""",
            (str(auth["authorization_id"]),),
        ).fetchall()
        if len(provenance_rows) != 1:
            return auth, ("LF-AUTH-PROVENANCE", "authorization creation evidence is incomplete")
        try:
            provenance = json.loads(str(provenance_rows[0]["payload_json"] or "{}"))
        except (TypeError, ValueError):
            return auth, ("LF-AUTH-PROVENANCE", "authorization creation evidence is invalid")
        if (
            str(provenance.get("conversation_id", "")) != context["conversation_id"]
            or str(provenance.get("campaign_id", "")) != context["campaign_id"]
            or str(provenance.get("sender_identity_id", ""))
            != context["sender_identity_id"]
        ):
            return auth, ("LF-AUTH-SCOPE", "authorization is not bound to this conversation")
        touch = str(intent.touch_type or "").strip().upper()
        if touch not in {"FIRST_TOUCH", "FOLLOWUP"}:
            return auth, ("LF-AUTH-TOUCH", "touch type is invalid")
        return auth, None

    @staticmethod
    def _reservation_specs(
        context: dict[str, Any], auth: Any, touch: str, day: str
    ) -> list[tuple[str, str, str, int]]:
        daily_field = "first_touch_cap" if touch == "FIRST_TOUCH" else "followup_cap"
        lifetime_field = (
            "lifetime_first_touch_cap" if touch == "FIRST_TOUCH" else "lifetime_followup_cap"
        )
        suffix = touch
        return [
            (f"AUTH_DAILY_{suffix}", str(auth["authorization_id"]), day, int(auth[daily_field])),
            (f"AUTH_LIFETIME_{suffix}", str(auth["authorization_id"]), "__LIFETIME__", int(auth[lifetime_field])),
            ("PROVIDER_DAILY", context["provider_account_id"], day, context["provider_daily_cap"]),
            ("DOMAIN_DAILY", context["sending_domain_id"], day, context["domain_daily_cap"]),
            ("MAILBOX_DAILY", context["mailbox_account_id"], day, context["mailbox_daily_cap"]),
            ("SENDER_DAILY", context["sender_identity_id"], day, context["sender_daily_cap"]),
            ("CAMPAIGN_DAILY", context["campaign_id"], day, context["campaign_daily_cap"]),
            ("CAMPAIGN_LIFETIME", context["campaign_id"], "__LIFETIME__", context["campaign_lifetime_cap"]),
        ]

    @staticmethod
    def _scope_problem(permit: Any, intent: MultiMailSendIntent, context: dict[str, Any]):
        expected = {
            "authorization_id": str(intent.authorization_id or "").strip(),
            "message_id": str(intent.message_id or "").strip(),
            "lf_opportunity_id": context["lf_opportunity_id"],
            "lf_contact_id": context["lf_contact_id"],
            "company_id": context["company_id"],
            "address_hash": context["recipient_address_hash"],
            "domain": context["recipient_domain"],
            "channel": "email",
            "touch_type": str(intent.touch_type or "").strip().upper(),
            "segment_id": str(intent.segment_id or "").strip(),
            "cohort_id": str(intent.cohort_id or "").strip(),
            "content_version": str(intent.content_version or "").strip(),
            "sender_identity": context["sender_identity_id"],
            "campaign_id": context["campaign_id"],
            "provider_account_id": context["provider_account_id"],
            "sending_domain_id": context["sending_domain_id"],
            "mailbox_account_id": context["mailbox_account_id"],
            "conversation_id": context["conversation_id"],
        }
        for field, value in expected.items():
            if str(permit[field] or "") != value:
                return "LF-PERMIT-SCOPE", f"permit does not match canonical {field}"
        return None

    @staticmethod
    def _counter_integrity_problem_tx(
        con: Any, scope_type: str, scope_id: str, bucket: str
    ) -> tuple[str, str] | None:
        counter = con.execute(
            """SELECT reserved_count FROM mail_limit_counters
               WHERE scope_type=? AND scope_id=? AND bucket_date=?""",
            (scope_type, scope_id, bucket),
        ).fetchone()
        actual = int(
            con.execute(
                """SELECT COALESCE(SUM(amount),0) FROM mail_limit_reservations
                   WHERE scope_type=? AND scope_id=? AND bucket_date=?
                     AND state IN ('HELD','CONSUMED')""",
                (scope_type, scope_id, bucket),
            ).fetchone()[0]
        )
        persisted = int(counter[0]) if counter else 0
        if persisted != actual:
            return "LF-MAIL-LIMIT-DRIFT", "quota counter and reservations differ"
        return None

    def _permit_reservation_problem_tx(
        self, con: Any, permit: Any
    ) -> tuple[str, str] | None:
        rows = con.execute(
            """SELECT * FROM mail_limit_reservations
               WHERE permit_id=? ORDER BY scope_type""",
            (permit["permit_id"],),
        ).fetchall()
        touch = str(permit["touch_type"])
        expected_ids = {
            f"AUTH_DAILY_{touch}": str(permit["authorization_id"]),
            f"AUTH_LIFETIME_{touch}": str(permit["authorization_id"]),
            "PROVIDER_DAILY": str(permit["provider_account_id"]),
            "DOMAIN_DAILY": str(permit["sending_domain_id"]),
            "MAILBOX_DAILY": str(permit["mailbox_account_id"]),
            "SENDER_DAILY": str(permit["sender_identity"]),
            "CAMPAIGN_DAILY": str(permit["campaign_id"]),
            "CAMPAIGN_LIFETIME": str(permit["campaign_id"]),
        }
        if len(rows) != len(expected_ids) or {str(row["scope_type"]) for row in rows} != set(
            expected_ids
        ):
            return "LF-MAIL-LIMIT-DRIFT", "permit quota reservation set is incomplete"
        expected_state = {
            "ISSUED": HELD,
            # A staged command is still definitely unsent.  Quota remains HELD
            # until a provider success is durably reconciled as SENT.
            "CONSUMED": HELD,
            "SENT": CONSUMED,
            "EXPIRED": RELEASED,
            "REVOKED": RELEASED,
        }.get(str(permit["state"]))
        if not expected_state:
            return "LF-MAIL-LIMIT-DRIFT", "permit state has no quota semantics"
        daily_buckets: set[str] = set()
        for row in rows:
            scope_type = str(row["scope_type"])
            if str(row["scope_id"]) != expected_ids[scope_type] or int(row["amount"]) != 1:
                return "LF-MAIL-LIMIT-DRIFT", "permit quota scope changed"
            if str(row["state"]) != expected_state:
                return "LF-MAIL-LIMIT-DRIFT", "permit and reservation states differ"
            bucket = str(row["bucket_date"])
            if scope_type.endswith("LIFETIME") or "_LIFETIME_" in scope_type:
                if bucket != "__LIFETIME__":
                    return "LF-MAIL-LIMIT-DRIFT", "lifetime quota bucket is invalid"
            else:
                daily_buckets.add(bucket)
            drift = self._counter_integrity_problem_tx(
                con, scope_type, str(row["scope_id"]), bucket
            )
            if drift:
                return drift
        if len(daily_buckets) != 1:
            return "LF-MAIL-LIMIT-DRIFT", "permit daily quota buckets differ"
        commands = con.execute(
            "SELECT * FROM outbox WHERE permit_id=? ORDER BY command_id", (permit["permit_id"],)
        ).fetchall()
        permit_state = str(permit["state"])
        if permit_state == "ISSUED" and commands:
            return "LF-MAIL-LIMIT-DRIFT", "issued permit already has a command"
        if permit_state == CONSUMED:
            if len(commands) != 1 or str(commands[0]["state"]) not in {
                "STAGED", "DISPATCHING", "AMBIGUOUS"
            }:
                return "LF-MAIL-LIMIT-DRIFT", "staged permit command is inconsistent"
            command_state = str(commands[0]["state"])
            attempt_count = int(commands[0]["attempt_count"])
            if (
                (command_state == "STAGED" and attempt_count != 0)
                or (command_state in {"DISPATCHING", "AMBIGUOUS"} and attempt_count < 1)
            ):
                return "LF-MAIL-LIMIT-DRIFT", "staged permit attempt state is inconsistent"
            if str(commands[0]["conversation_id"]) != str(permit["conversation_id"]):
                return "LF-MAIL-LIMIT-DRIFT", "staged command conversation changed"
            parent_id = str(commands[0]["parent_email_message_id"] or "")
            if touch == "FIRST_TOUCH" and parent_id:
                return "LF-MAIL-LIMIT-DRIFT", "first touch unexpectedly has a parent"
            if touch == "FOLLOWUP" and not con.execute(
                """SELECT 1 FROM conversation_messages
                   WHERE email_message_id=? AND conversation_id=? AND direction='OUTBOUND'""",
                (parent_id, permit["conversation_id"]),
            ).fetchone():
                return "LF-MAIL-LIMIT-DRIFT", "follow-up parent is not canonical"
        if permit_state == "SENT":
            if (
                len(commands) != 1
                or str(commands[0]["state"]) != "SENT"
                or not str(commands[0]["provider_message_id"] or "")
            ):
                return "LF-MAIL-LIMIT-DRIFT", "sent permit command is inconsistent"
            parent_id = str(commands[0]["parent_email_message_id"] or "")
            if touch == "FIRST_TOUCH" and parent_id:
                return "LF-MAIL-LIMIT-DRIFT", "first touch unexpectedly has a parent"
            if touch == "FOLLOWUP" and not con.execute(
                """SELECT 1 FROM conversation_messages
                   WHERE email_message_id=? AND conversation_id=? AND direction='OUTBOUND'""",
                (parent_id, permit["conversation_id"]),
            ).fetchone():
                return "LF-MAIL-LIMIT-DRIFT", "follow-up parent is not canonical"
        return None

    def _current_cap_problem_tx(
        self,
        con: Any,
        context: dict[str, Any],
        auth: Any,
        permit: Any,
        now_dt: datetime,
    ) -> tuple[str, str] | None:
        touch = str(permit["touch_type"])
        day = now_dt.astimezone(MOSCOW).date().isoformat()
        specs = self._reservation_specs(context, auth, touch, day)
        for scope_type, scope_id, bucket, cap in specs:
            if cap <= 0:
                return "LF-MAIL-LIMIT", f"{scope_type.lower()} cap is disabled"
            reservation = con.execute(
                """SELECT 1 FROM mail_limit_reservations
                   WHERE permit_id=? AND scope_type=? AND scope_id=? AND bucket_date=?
                     AND state IN ('HELD','CONSUMED')""",
                (permit["permit_id"], scope_type, scope_id, bucket),
            ).fetchone()
            if not reservation:
                return "LF-MAIL-LIMIT-DAY", "permit quota bucket is not current"
            counter = con.execute(
                """SELECT reserved_count FROM mail_limit_counters
                   WHERE scope_type=? AND scope_id=? AND bucket_date=?""",
                (scope_type, scope_id, bucket),
            ).fetchone()
            if not counter or int(counter[0]) > cap:
                return "LF-MAIL-LIMIT", f"{scope_type.lower()} cap is exceeded"
        return None

    @staticmethod
    def _payload_problem(
        payload: dict[str, Any], context: dict[str, Any], intent: MultiMailSendIntent
    ) -> tuple[str, str] | None:
        if not isinstance(payload, dict):
            return "LF-PAYLOAD-SCOPE", "canonical envelope payload must be an object"
        to_address = normalize_email(str(payload.get("to_address", "") or ""))
        if not to_address or "@" not in to_address or address_hash(to_address) != context[
            "recipient_address_hash"
        ]:
            return "LF-PAYLOAD-SCOPE", "payload recipient is not canonical"
        expected = {
            "sender_identity_id": context["sender_identity_id"],
            "mailbox_account_id": context["mailbox_account_id"],
            "conversation_id": context["conversation_id"],
            "provider_account_id": context["provider_account_id"],
            "sending_domain_id": context["sending_domain_id"],
            "campaign_id": context["campaign_id"],
            "authorization_id": str(intent.authorization_id or "").strip(),
            "content_version": str(intent.content_version or "").strip(),
        }
        if any(str(payload.get(field, "") or "") != value for field, value in expected.items()):
            return "LF-PAYLOAD-SCOPE", "payload mail identity is not canonical"
        allowed_keys = {
            "to_address",
            *expected.keys(),
            "subject",
            "text_body",
            "html_body",
            "template_id",
            "template_variables",
            "attachments_manifest_ref",
        }
        if any(str(key) not in allowed_keys for key in payload):
            return "LF-PAYLOAD-SCOPE", "payload is not a typed content envelope"
        for key in ("subject", "text_body", "html_body", "template_id", "attachments_manifest_ref"):
            if key in payload and not isinstance(payload[key], str):
                return "LF-PAYLOAD-SCOPE", "payload content field has an invalid type"
        if "template_variables" in payload and not isinstance(payload["template_variables"], dict):
            return "LF-PAYLOAD-SCOPE", "payload template variables have an invalid type"
        return None

    @staticmethod
    def _parent_message_tx(
        con: Any, context: dict[str, Any], touch: str
    ) -> str:
        if touch == "FIRST_TOUCH":
            return ""
        parent = con.execute(
            """SELECT email_message_id FROM conversation_messages
               WHERE conversation_id=? AND direction='OUTBOUND'
               ORDER BY created_at_utc DESC,email_message_id DESC LIMIT 1""",
            (context["conversation_id"],),
        ).fetchone()
        if not parent:
            raise MultiMailPolicyError(
                "follow-up requires a persisted outbound parent in the same conversation"
            )
        return str(parent["email_message_id"])

    @classmethod
    def _command_parent_tx(
        cls,
        con: Any,
        context: dict[str, Any],
        touch: str,
        command: Any | None,
    ) -> str:
        if command is None:
            return cls._parent_message_tx(con, context, touch)
        parent_id = str(command["parent_email_message_id"] or "")
        if touch == "FIRST_TOUCH":
            if parent_id:
                raise MultiMailPolicyError("first touch command has an unexpected parent")
            return ""
        if not parent_id or not con.execute(
            """SELECT 1 FROM conversation_messages
               WHERE email_message_id=? AND conversation_id=? AND direction='OUTBOUND'""",
            (parent_id, context["conversation_id"]),
        ).fetchone():
            raise MultiMailPolicyError("follow-up command parent is not canonical")
        return parent_id

    def issue_permit(self, intent: MultiMailSendIntent) -> PolicyDecision:
        message_id = str(intent.message_id or "").strip()
        if not _INTERNAL_MESSAGE_ID.fullmatch(message_id):
            raise ValueError("message_id must be an opaque internal identifier")
        now_dt = self._now_dt()
        now = self._format_utc(now_dt)
        with self.store.transaction(min_schema_version=14) as con:
            try:
                context = self._context_tx(
                    con, str(intent.conversation_id or "").strip(), recipient_address=intent.address
                )
            except MultiMailPolicyError:
                return self._deny_tx(con, intent, "LF-CONVERSATION-IDENTITY", "canonical identity check failed")
            existing = con.execute(
                "SELECT * FROM send_permits WHERE message_id=?", (message_id,)
            ).fetchone()
            if existing:
                problem = self._scope_problem(existing, intent, context)
                if problem:
                    raise IdempotencyConflict("message id was reused with another canonical scope")
                if str(existing["state"]) not in {"ISSUED", CONSUMED, "SENT"}:
                    return self._deny_tx(con, intent, "LF-PERMIT-STATE", "existing permit is not active")
                if str(existing["state"]) == "ISSUED" and self._parse_utc(
                    existing["expires_at_utc"], "permit expiry"
                ) <= now_dt:
                    return self._deny_tx(con, intent, "LF-PERMIT-STATE", "existing permit expired")
                reservation_problem = self._permit_reservation_problem_tx(con, existing)
                if reservation_problem:
                    return self._deny_tx(con, intent, *reservation_problem)
                safety = self._safety_problem_tx(con, context, intent, now)
                if safety:
                    return self._deny_tx(con, intent, *safety)
                replay_auth, auth_problem = self._authorization_problem_tx(
                    con, context, intent, now_dt
                )
                if auth_problem:
                    return self._deny_tx(con, intent, *auth_problem)
                assert replay_auth is not None
                cap_problem = self._current_cap_problem_tx(
                    con, context, replay_auth, existing, now_dt
                )
                if cap_problem:
                    return self._deny_tx(con, intent, *cap_problem)
                return PolicyDecision(
                    True, "LF-AUTH-IDEMPOTENT", "permit already exists",
                    str(existing["permit_id"]), False,
                )

            safety = self._safety_problem_tx(con, context, intent, now)
            if safety:
                return self._deny_tx(con, intent, *safety)
            auth, auth_problem = self._authorization_problem_tx(con, context, intent, now_dt)
            if auth_problem:
                return self._deny_tx(con, intent, *auth_problem)
            assert auth is not None
            touch = str(intent.touch_type or "").strip().upper()
            if touch == "FIRST_TOUCH":
                prior_first_touch = con.execute(
                    """SELECT 1 FROM send_permits
                       WHERE channel='email' AND touch_type='FIRST_TOUCH'
                         AND address_hash=? AND state IN ('ISSUED','CONSUMED','SENT')
                       LIMIT 1""",
                    (context["recipient_address_hash"],),
                ).fetchone()
                if prior_first_touch:
                    return self._deny_tx(
                        con,
                        intent,
                        "LF-CADENCE-FIRST-TOUCH",
                        "canonical recipient already has a first touch",
                    )
            day = now_dt.astimezone(MOSCOW).date().isoformat()
            specs = self._reservation_specs(context, auth, touch, day)
            quota_snapshot: list[dict[str, Any]] = []
            for scope_type, scope_id, bucket, cap in specs:
                drift = self._counter_integrity_problem_tx(con, scope_type, scope_id, bucket)
                if drift:
                    return self._deny_tx(con, intent, *drift)
                current = con.execute(
                    """SELECT reserved_count FROM mail_limit_counters
                       WHERE scope_type=? AND scope_id=? AND bucket_date=?""",
                    (scope_type, scope_id, bucket),
                ).fetchone()
                count = int(current[0]) if current else 0
                if cap <= 0 or count >= cap:
                    return self._deny_tx(
                        con, intent, "LF-MAIL-LIMIT", f"{scope_type.lower()} cap reached"
                    )
                quota_snapshot.append(
                    {
                        "scope_type": scope_type,
                        "scope_id": scope_id,
                        "bucket": bucket,
                        "cap": cap,
                        "count_before": count,
                    }
                )

            permit_id = new_lf_id("permit")
            local_now = now_dt.astimezone(MOSCOW)
            next_local_day = datetime.combine(
                local_now.date() + timedelta(days=1), datetime.min.time(), tzinfo=MOSCOW
            ).astimezone(timezone.utc)
            expires = self._format_utc(
                min(now_dt + timedelta(minutes=self.permit_ttl_minutes), next_local_day)
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
                    permit_id, intent.authorization_id, message_id,
                    context["lf_opportunity_id"], context["lf_contact_id"], context["company_id"],
                    context["recipient_address_hash"], context["recipient_domain"], "email", touch,
                    intent.segment_id, intent.cohort_id, intent.content_version,
                    context["sender_identity_id"], "ISSUED", now, expires, "", "",
                    context["campaign_id"], context["provider_account_id"],
                    context["sending_domain_id"], context["mailbox_account_id"],
                    context["conversation_id"],
                ),
            )
            for scope_type, scope_id, bucket, _cap in specs:
                con.execute(
                    """INSERT INTO mail_limit_counters(
                           scope_type,scope_id,bucket_date,reserved_count,updated_at_utc
                       ) VALUES(?,?,?,?,?)
                       ON CONFLICT(scope_type,scope_id,bucket_date) DO UPDATE SET
                           reserved_count=mail_limit_counters.reserved_count+1,
                           updated_at_utc=excluded.updated_at_utc""",
                    (scope_type, scope_id, bucket, 1, now),
                )
                con.execute(
                    """INSERT INTO mail_limit_reservations(
                           reservation_id,permit_id,scope_type,scope_id,bucket_date,
                           amount,state,created_at_utc,released_at_utc
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (new_lf_id("limit_reservation"), permit_id, scope_type, scope_id,
                     bucket, 1, HELD, now, ""),
                )
            if self.after_reservations_hook:
                self.after_reservations_hook()
            self.store._append_event_tx(
                con,
                event_type="multimail_send_permit_issued",
                aggregate_type="message",
                aggregate_id=payload_hash({"internal_message_id": message_id}),
                producer="multimail_policy",
                idempotency_key=f"permit:{message_id}",
                payload={
                    "permit_id": permit_id,
                    "conversation_id": context["conversation_id"],
                    "campaign_id": context["campaign_id"],
                    "sender_identity_id": context["sender_identity_id"],
                    "quota_scope_count": len(specs),
                    "quota_timezone": "Europe/Moscow",
                    "quota_snapshot": quota_snapshot,
                },
                actor="multimail_send_gate",
                schema_version=14,
            )
            return PolicyDecision(True, "LF-AUTH-ALLOW", "permit issued", permit_id, True)

    def _release_reservations_tx(
        self,
        con: Any,
        permit_id: str,
        *,
        now: str,
        target_permit_state: str,
        allowed_permit_states: tuple[str, ...] = ("ISSUED",),
    ) -> int:
        rows = con.execute(
            """SELECT * FROM mail_limit_reservations
               WHERE permit_id=? AND state='HELD' ORDER BY scope_type""",
            (permit_id,),
        ).fetchall()
        placeholders = ",".join("?" for _ in allowed_permit_states)
        changed = con.execute(
            f"""UPDATE send_permits SET state=?,denial_rule_id=?
                 WHERE permit_id=? AND state IN ({placeholders})""",
            (target_permit_state, target_permit_state, permit_id, *allowed_permit_states),
        )
        if changed.rowcount != 1:
            raise MultiMailPolicyError("permit state cannot release quota reservations")
        for row in rows:
            changed = con.execute(
                """UPDATE mail_limit_counters
                   SET reserved_count=reserved_count-1,updated_at_utc=?
                   WHERE scope_type=? AND scope_id=? AND bucket_date=? AND reserved_count>=1""",
                (now, row["scope_type"], row["scope_id"], row["bucket_date"]),
            )
            if changed.rowcount != 1:
                raise MultiMailPolicyError("quota counter cannot release its reservation")
            con.execute(
                """UPDATE mail_limit_reservations SET state='RELEASED',released_at_utc=?
                   WHERE reservation_id=? AND state='HELD'""",
                (now, row["reservation_id"]),
            )
        return len(rows)

    def release_expired_permit(
        self, permit_id: str, *, actor: str, evidence_ref: str
    ) -> bool:
        permit_id = self._required(permit_id, "permit_id")
        actor_id = self._required(actor, "actor")
        evidence = self._required(evidence_ref, "evidence_ref")
        now_dt = self._now_dt()
        now = self._format_utc(now_dt)
        with self.store.transaction(min_schema_version=14) as con:
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if not permit:
                raise KeyError("permit does not exist")
            if str(permit["state"]) == "EXPIRED":
                return False
            if str(permit["state"]) != "ISSUED":
                raise MultiMailPolicyError("only an unconsumed permit can expire")
            if self._parse_utc(permit["expires_at_utc"], "permit expiry") > now_dt:
                raise MultiMailPolicyError("permit has not expired")
            reservation_problem = self._permit_reservation_problem_tx(con, permit)
            if reservation_problem:
                raise MultiMailPolicyError(reservation_problem[1])
            released = self._release_reservations_tx(
                con, permit_id, now=now, target_permit_state="EXPIRED"
            )
            if released != 8:
                raise MultiMailPolicyError("expired permit reservation set is incomplete")
            self.store._append_event_tx(
                con,
                event_type="multimail_permit_expired",
                aggregate_type="permit",
                aggregate_id=permit_id,
                producer="multimail_policy",
                idempotency_key=f"permit-expired:{permit_id}",
                payload={"permit_id": permit_id, "released_scope_count": released},
                evidence_ref=evidence,
                actor=actor_id,
                schema_version=14,
            )
            return True

    def stage_command(
        self,
        intent: MultiMailSendIntent,
        permit_id: str,
        *,
        payload_ref: str,
        payload: dict[str, Any],
    ) -> PolicyDecision:
        permit_id = self._required(permit_id, "permit_id")
        payload_reference = self._required(payload_ref, "payload_ref")
        content_digest = self.payload_digest(intent, payload)
        now_dt = self._now_dt()
        now = self._format_utc(now_dt)
        with self.store.transaction(min_schema_version=14) as con:
            try:
                context = self._context_tx(con, intent.conversation_id, recipient_address=intent.address)
            except MultiMailPolicyError:
                return self._deny_tx(con, intent, "LF-CONVERSATION-IDENTITY", "canonical identity check failed")
            payload_problem = self._payload_problem(payload, context, intent)
            if payload_problem:
                return self._deny_tx(con, intent, *payload_problem)
            command = con.execute(
                "SELECT * FROM outbox WHERE message_id=?", (intent.message_id,)
            ).fetchone()
            try:
                parent_message_id = self._command_parent_tx(
                    con,
                    context,
                    str(intent.touch_type or "").strip().upper(),
                    command,
                )
            except MultiMailPolicyError:
                return self._deny_tx(
                    con, intent, "LF-FOLLOWUP-PARENT", "canonical follow-up parent is missing"
                )
            digest = payload_hash(
                {
                    "typed_payload_hash": content_digest,
                    "parent_email_message_id": parent_message_id,
                }
            )
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if not permit or str(permit["message_id"]) != str(intent.message_id):
                return self._deny_tx(con, intent, "LF-PERMIT-MISSING", "matching permit is required")
            scope_problem = self._scope_problem(permit, intent, context)
            if scope_problem:
                return self._deny_tx(con, intent, *scope_problem)
            reservation_problem = self._permit_reservation_problem_tx(con, permit)
            if reservation_problem:
                return self._deny_tx(con, intent, *reservation_problem)
            if command:
                if (
                    str(command["permit_id"]) != permit_id
                    or str(command["payload_ref"]) != payload_reference
                    or str(command["payload_hash"]) != digest
                    or str(command["conversation_id"]) != context["conversation_id"]
                    or str(command["parent_email_message_id"] or "") != parent_message_id
                    or str(command["state"]) not in {"STAGED", "DISPATCHING", "SENT"}
                ):
                    raise IdempotencyConflict("message was staged with different immutable data")
            expiry_problem = None
            if self._parse_utc(permit["expires_at_utc"], "permit expiry") <= now_dt:
                expiry_problem = ("LF-PERMIT-STATE", "permit expired before dispatch")
            safety = self._safety_problem_tx(con, context, intent, now)
            current_auth, auth_problem = self._authorization_problem_tx(
                con, context, intent, now_dt
            )
            cap_problem = (
                self._current_cap_problem_tx(con, context, current_auth, permit, now_dt)
                if current_auth is not None and not auth_problem
                else None
            )
            problem = expiry_problem or safety or auth_problem or cap_problem
            if problem:
                if command and str(command["state"]) == "STAGED" and int(
                    command["attempt_count"]
                ) == 0:
                    con.execute(
                        "UPDATE outbox SET state='CANCELLED',updated_at_utc=? WHERE command_id=?",
                        (now, command["command_id"]),
                    )
                    released = self._release_reservations_tx(
                        con,
                        permit_id,
                        now=now,
                        target_permit_state="REVOKED",
                        allowed_permit_states=("CONSUMED",),
                    )
                    if released != 8:
                        raise MultiMailPolicyError("revoked permit reservation set is incomplete")
                elif not command and str(permit["state"]) == "ISSUED":
                    released = self._release_reservations_tx(
                        con, permit_id, now=now, target_permit_state="REVOKED"
                    )
                    if released != 8:
                        raise MultiMailPolicyError("revoked permit reservation set is incomplete")
                return self._deny_tx(con, intent, *problem)
            if command:
                return PolicyDecision(
                    True, "LF-OUTBOX-IDEMPOTENT", "command already staged", permit_id, False
                )
            if str(permit["state"]) != "ISSUED" or self._parse_utc(
                permit["expires_at_utc"], "permit expiry"
            ) <= now_dt:
                return self._deny_tx(con, intent, "LF-PERMIT-STATE", "permit is not active")
            if parent_message_id and con.execute(
                """SELECT 1 FROM outbox
                   WHERE parent_email_message_id=?
                     AND state IN ('STAGED','DISPATCHING','SENT') LIMIT 1""",
                (parent_message_id,),
            ).fetchone():
                released = self._release_reservations_tx(
                    con, permit_id, now=now, target_permit_state="REVOKED"
                )
                if released != 8:
                    raise MultiMailPolicyError("duplicate follow-up reservation set is incomplete")
                return self._deny_tx(
                    con,
                    intent,
                    "LF-FOLLOWUP-SEQUENCE",
                    "canonical parent already has a follow-up command",
                )
            command_id = new_lf_id("command")
            con.execute(
                """INSERT INTO outbox(
                       command_id,message_id,permit_id,command_type,channel,payload_ref,
                       payload_hash,state,attempt_count,next_retry_at_utc,last_error_class,
                       provider_message_id,correlation_id,created_at_utc,updated_at_utc,
                       conversation_id,parent_email_message_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    command_id, intent.message_id, permit_id, "SEND_MESSAGE", "email",
                    payload_reference, digest, "STAGED", 0, "", "", "", intent.message_id,
                    now, now, context["conversation_id"], parent_message_id,
                ),
            )
            con.execute(
                """UPDATE send_permits SET state='CONSUMED',consumed_at_utc=?
                   WHERE permit_id=? AND state='ISSUED'""",
                (now, permit_id),
            )
            self.store._append_event_tx(
                con,
                event_type="multimail_send_command_staged",
                aggregate_type="message",
                aggregate_id=payload_hash({"internal_message_id": str(intent.message_id)}),
                producer="multimail_policy",
                idempotency_key=f"outbox:{intent.message_id}",
                payload={
                    "command_id": command_id,
                    "permit_id": permit_id,
                    "conversation_id": context["conversation_id"],
                },
                actor="multimail_send_gate",
                schema_version=14,
            )
            return PolicyDecision(
                True, "LF-OUTBOX-STAGED", "command staged; no transport called",
                permit_id, True,
            )

    def authorize_dispatch(
        self,
        intent: MultiMailSendIntent,
        command_id: str,
        *,
        payload_ref: str,
        payload: dict[str, Any],
    ) -> PolicyDecision:
        """Perform the final local gate and fence one transport attempt.

        The method never calls a provider.  A worker that receives an
        ambiguous provider result must leave the command in ``DISPATCHING``;
        this API will not authorize a blind retry.
        """
        command_id = self._required(command_id, "command_id")
        payload_reference = self._required(payload_ref, "payload_ref")
        content_digest = self.payload_digest(intent, payload)
        now_dt = self._now_dt()
        now = self._format_utc(now_dt)
        with self.store.transaction(min_schema_version=14) as con:
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            if not writer or str(writer[0]) != "1":
                return self._deny_tx(
                    con, intent, "LF-WRITER-DISABLED", "external writers are disabled"
                )
            try:
                context = self._context_tx(
                    con, intent.conversation_id, recipient_address=intent.address
                )
            except MultiMailPolicyError:
                return self._deny_tx(
                    con, intent, "LF-CONVERSATION-IDENTITY", "canonical identity check failed"
                )
            payload_problem = self._payload_problem(payload, context, intent)
            if payload_problem:
                return self._deny_tx(con, intent, *payload_problem)
            command = con.execute(
                "SELECT * FROM outbox WHERE command_id=?", (command_id,)
            ).fetchone()
            if not command or str(command["message_id"]) != str(intent.message_id):
                return self._deny_tx(con, intent, "LF-OUTBOX-MISSING", "staged command is required")
            try:
                parent_message_id = self._command_parent_tx(
                    con,
                    context,
                    str(intent.touch_type or "").strip().upper(),
                    command,
                )
            except MultiMailPolicyError:
                return self._deny_tx(
                    con, intent, "LF-FOLLOWUP-PARENT", "canonical follow-up parent is missing"
                )
            digest = payload_hash(
                {
                    "typed_payload_hash": content_digest,
                    "parent_email_message_id": parent_message_id,
                }
            )
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?", (command["permit_id"],)
            ).fetchone()
            if not permit:
                return self._deny_tx(con, intent, "LF-PERMIT-MISSING", "matching permit is required")
            scope_problem = self._scope_problem(permit, intent, context)
            if scope_problem:
                return self._deny_tx(con, intent, *scope_problem)
            reservation_problem = self._permit_reservation_problem_tx(con, permit)
            if reservation_problem:
                return self._deny_tx(con, intent, *reservation_problem)
            if (
                str(command["payload_ref"]) != payload_reference
                or str(command["payload_hash"]) != digest
                or str(command["conversation_id"]) != context["conversation_id"]
                or str(command["parent_email_message_id"] or "") != parent_message_id
            ):
                return self._deny_tx(con, intent, "LF-OUTBOX-SCOPE", "command payload is not canonical")
            if str(command["state"]) != "STAGED" or int(command["attempt_count"]) != 0:
                return self._deny_tx(
                    con, intent, "LF-DISPATCH-AMBIGUOUS", "transport attempt is already fenced"
                )
            if str(permit["state"]) != CONSUMED:
                return self._deny_tx(con, intent, "LF-PERMIT-STATE", "staged permit is not active")
            expiry_problem = None
            if self._parse_utc(permit["expires_at_utc"], "permit expiry") <= now_dt:
                expiry_problem = ("LF-PERMIT-STATE", "permit expired before dispatch")
            safety = self._safety_problem_tx(con, context, intent, now)
            current_auth, auth_problem = self._authorization_problem_tx(
                con, context, intent, now_dt
            )
            cap_problem = (
                self._current_cap_problem_tx(con, context, current_auth, permit, now_dt)
                if current_auth is not None and not auth_problem
                else None
            )
            problem = expiry_problem or safety or auth_problem or cap_problem
            if problem:
                con.execute(
                    "UPDATE outbox SET state='CANCELLED',updated_at_utc=? WHERE command_id=?",
                    (now, command_id),
                )
                released = self._release_reservations_tx(
                    con,
                    str(permit["permit_id"]),
                    now=now,
                    target_permit_state="REVOKED",
                    allowed_permit_states=(CONSUMED,),
                )
                if released != 8:
                    raise MultiMailPolicyError("cancelled command reservation set is incomplete")
                return self._deny_tx(con, intent, *problem)
            changed = con.execute(
                """UPDATE outbox SET state='DISPATCHING',attempt_count=1,updated_at_utc=?
                   WHERE command_id=? AND state='STAGED' AND attempt_count=0""",
                (now, command_id),
            )
            if changed.rowcount != 1:
                raise MultiMailPolicyError("transport dispatch fence was lost")
            self.store._append_event_tx(
                con,
                event_type="multimail_transport_dispatch_authorized",
                aggregate_type="message",
                aggregate_id=payload_hash({"internal_message_id": str(intent.message_id)}),
                producer="multimail_policy",
                idempotency_key=f"dispatch:{intent.message_id}",
                payload={
                    "command_id": command_id,
                    "conversation_id": context["conversation_id"],
                    "attempt_count": 1,
                },
                actor="multimail_send_gate",
                schema_version=14,
            )
            return PolicyDecision(
                True, "LF-DISPATCH-AUTHORIZED", "one transport attempt fenced",
                str(permit["permit_id"]), True,
            )

    def record_sent(
        self,
        command_id: str,
        *,
        provider_message_id: str,
        rfc_message_id: str,
        actor: str,
        evidence_ref: str,
    ) -> bool:
        """Reconcile an already-successful provider result; no transport call."""
        command_id = self._required(command_id, "command_id")
        provider_id = self._required(provider_message_id, "provider_message_id")
        rfc_id = canonical_message_id(rfc_message_id)
        actor_id = self._required(actor, "actor")
        evidence = self._required(evidence_ref, "evidence_ref")
        now = self._format_utc(self._now_dt())
        with self.store.transaction(min_schema_version=14) as con:
            command = con.execute(
                "SELECT * FROM outbox WHERE command_id=?", (command_id,)
            ).fetchone()
            if not command:
                raise KeyError("command does not exist")
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?", (command["permit_id"],)
            ).fetchone()
            if not permit:
                raise MultiMailPolicyError("sent command has no permit")
            duplicate_provider_id = con.execute(
                """SELECT o.command_id FROM outbox o
                   JOIN send_permits p ON p.permit_id=o.permit_id
                   WHERE p.provider_account_id=? AND o.provider_message_id=?
                     AND o.provider_message_id<>'' AND o.command_id<>?
                   LIMIT 1""",
                (permit["provider_account_id"], provider_id, command_id),
            ).fetchone()
            if duplicate_provider_id:
                raise IdempotencyConflict("provider message identity is already reconciled")
            if str(command["state"]) == "SENT":
                if str(command["provider_message_id"]) != provider_id or str(permit["state"]) != "SENT":
                    raise IdempotencyConflict("sent provider identity changed")
                problem = self._permit_reservation_problem_tx(con, permit)
                if problem:
                    raise MultiMailPolicyError(problem[1])
                ConversationRouter(self.store)._register_message_tx(
                    con,
                    conversation_id=str(command["conversation_id"]),
                    direction="OUTBOUND",
                    external_message_id=rfc_id,
                    interaction_id="",
                    send_command_id=command_id,
                    actor=actor_id,
                    evidence_ref=evidence,
                    require_active_conversation=False,
                )
                return False
            if str(command["state"]) != "DISPATCHING" or int(command["attempt_count"]) != 1:
                raise MultiMailPolicyError("only the fenced transport attempt can become SENT")
            if str(permit["state"]) != CONSUMED:
                raise MultiMailPolicyError("dispatching command permit is inconsistent")
            problem = self._permit_reservation_problem_tx(con, permit)
            if problem:
                raise MultiMailPolicyError(problem[1])
            changed = con.execute(
                """UPDATE outbox SET state='SENT',provider_message_id=?,updated_at_utc=?
                   WHERE command_id=? AND state='DISPATCHING' AND attempt_count=1""",
                (provider_id, now, command_id),
            )
            if changed.rowcount != 1:
                raise MultiMailPolicyError("sent reconciliation race was lost")
            con.execute(
                "UPDATE send_permits SET state='SENT' WHERE permit_id=? AND state='CONSUMED'",
                (permit["permit_id"],),
            )
            reservations = con.execute(
                """UPDATE mail_limit_reservations SET state='CONSUMED'
                   WHERE permit_id=? AND state='HELD'""",
                (permit["permit_id"],),
            )
            if reservations.rowcount != 8:
                raise MultiMailPolicyError("sent command reservation set is incomplete")
            ConversationRouter(self.store)._register_message_tx(
                con,
                conversation_id=str(command["conversation_id"]),
                direction="OUTBOUND",
                external_message_id=rfc_id,
                interaction_id="",
                send_command_id=command_id,
                actor=actor_id,
                evidence_ref=evidence,
                require_active_conversation=False,
            )
            self.store._append_event_tx(
                con,
                event_type="multimail_message_sent_reconciled",
                aggregate_type="message",
                aggregate_id=payload_hash({"internal_message_id": str(command["message_id"])}),
                producer="multimail_policy",
                idempotency_key=f"sent:{command_id}",
                payload={
                    "command_id": command_id,
                    "provider_message_id_hash": payload_hash({"provider_message_id": provider_id}),
                    "conversation_id": str(command["conversation_id"]),
                },
                evidence_ref=evidence,
                actor=actor_id,
                schema_version=14,
            )
            return True


__all__ = [
    "MultiMailPolicyError",
    "MultiMailSendGate",
    "MultiMailSendIntent",
]
