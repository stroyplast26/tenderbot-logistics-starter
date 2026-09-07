"""Default-deny policy and one-time permit gate for staged outbound work."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .ids import address_hash, new_lf_id, normalize_domain, normalize_email, payload_hash, utc_now
from .store import FactoryStore, IdempotencyConflict


@dataclass(frozen=True)
class SendIntent:
    message_id: str
    authorization_id: str
    channel: str
    address: str
    segment_id: str
    cohort_id: str
    content_version: str
    sender_identity: str
    touch_type: str = "FIRST_TOUCH"
    lf_opportunity_id: str = ""
    lf_contact_id: str = ""
    company_id: str = ""
    domain: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str
    permit_id: str = ""
    created: bool = False


class SendGate:
    """Issues permits and stages commands; it never calls a transport."""

    def __init__(self, store: FactoryStore, *, permit_ttl_minutes: int = 15):
        self.store = store
        self.permit_ttl_minutes = max(1, int(permit_ttl_minutes))

    @staticmethod
    def _parse_utc(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _date_prefix(value: str) -> str:
        return value[:10]

    @staticmethod
    def _recipient_domain(address: str) -> str:
        """Return the canonical domain from the actual recipient address."""
        normalized = normalize_email(address)
        if "@" not in normalized:
            return ""
        return normalize_domain(normalized.rsplit("@", 1)[1])

    @staticmethod
    def payload_digest(intent: SendIntent, payload: dict) -> str:
        """Bind the final payload to the immutable recipient and authorization scope."""
        return payload_hash(
            {
                "message_id": intent.message_id,
                "authorization_id": intent.authorization_id,
                "address_hash": address_hash(intent.address),
                "channel": intent.channel,
                "touch_type": intent.touch_type.upper(),
                "segment_id": intent.segment_id,
                "cohort_id": intent.cohort_id,
                "content_version": intent.content_version,
                "sender_identity": intent.sender_identity,
                "payload": payload or {},
            }
        )

    @staticmethod
    def _permit_scope_problem(permit, intent: SendIntent):
        expected = {
            "authorization_id": intent.authorization_id,
            "message_id": intent.message_id,
            "lf_opportunity_id": intent.lf_opportunity_id,
            "lf_contact_id": intent.lf_contact_id,
            "company_id": intent.company_id,
            "address_hash": address_hash(intent.address),
            "domain": SendGate._recipient_domain(intent.address),
            "channel": intent.channel,
            "touch_type": intent.touch_type.upper(),
            "segment_id": intent.segment_id,
            "cohort_id": intent.cohort_id,
            "content_version": intent.content_version,
            "sender_identity": intent.sender_identity,
        }
        for field, value in expected.items():
            if (permit[field] or "") != (value or ""):
                return "LF-PERMIT-SCOPE", f"permit does not match {field}"
        return None

    def create_authorization(
        self,
        *,
        channel: str,
        segment_id: str,
        cohort_id: str,
        content_version: str,
        sender_identity: str,
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
        stop_rules: dict | None = None,
        state: str = "ACTIVE",
        authorization_id: str = "",
    ) -> str:
        aid = authorization_id or new_lf_id("authorization")
        with self.store.transaction() as con:
            con.execute(
                """INSERT INTO outbound_authorizations(
                    authorization_id,state,channel,segment_id,cohort_id,content_version,
                    sender_identity,first_touch_cap,followup_cap,lifetime_first_touch_cap,
                    lifetime_followup_cap,valid_from_utc,valid_until_utc,legal_status,
                    legal_evidence_ref,suppression_snapshot_id,approver,approved_at_utc,
                    stop_rules_json,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    aid,
                    state,
                    channel,
                    segment_id,
                    cohort_id,
                    content_version,
                    sender_identity,
                    int(first_touch_cap),
                    int(followup_cap),
                    int(lifetime_first_touch_cap if lifetime_first_touch_cap is not None else first_touch_cap),
                    int(lifetime_followup_cap if lifetime_followup_cap is not None else followup_cap),
                    valid_from_utc,
                    valid_until_utc,
                    legal_status,
                    legal_evidence_ref,
                    suppression_snapshot_id,
                    approver,
                    utc_now(),
                    json.dumps(stop_rules or {}, ensure_ascii=False, sort_keys=True),
                    utc_now(),
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="outbound_authorization_created",
                aggregate_type="authorization",
                aggregate_id=aid,
                producer="policy_engine",
                idempotency_key=f"authorization:{aid}",
                payload={
                    "state": state,
                    "channel": channel,
                    "segment_id": segment_id,
                    "cohort_id": cohort_id,
                    "content_version": content_version,
                    "legal_status": legal_status,
                },
                evidence_ref=legal_evidence_ref,
                actor=approver,
            )
        return aid

    def add_suppression(
        self,
        *,
        reason: str,
        scope: str,
        channel: str = "email",
        address: str = "",
        subject_type: str = "EMAIL_ADDRESS",
        subject_id: str = "",
        evidence_ref: str,
        source: str,
        author: str,
        expires_at_utc: str = "",
    ) -> str:
        sid = new_lf_id("suppression")
        normalized = normalize_email(address)
        ahash = address_hash(normalized) if normalized else ""
        with self.store.transaction() as con:
            normalized_subject_id = subject_id or ahash
            if scope == "DOMAIN":
                normalized_subject_id = normalize_domain(normalized_subject_id)
            existing = con.execute(
                """SELECT suppression_id FROM suppression_entries
                   WHERE channel=? AND scope=? AND subject_id=? AND reason=? AND state='ACTIVE'""",
                (channel, scope, normalized_subject_id, reason),
            ).fetchone()
            if existing:
                return existing[0]
            con.execute(
                """INSERT INTO suppression_entries(
                    suppression_id,subject_type,subject_id,channel,address,address_hash,
                    reason,scope,evidence_ref,source,author,created_at_utc,expires_at_utc,state
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid,
                    subject_type,
                    normalized_subject_id,
                    channel,
                    normalized,
                    ahash,
                    reason,
                    scope,
                    evidence_ref,
                    source,
                    author,
                    utc_now(),
                    expires_at_utc,
                    "ACTIVE",
                ),
            )
        return sid

    def add_pause(
        self,
        *,
        scope: str,
        reason: str,
        author: str,
        evidence_ref: str,
        scope_id: str = "",
        review_at_utc: str = "",
        expires_at_utc: str = "",
    ) -> str:
        from .pauses import PauseController

        return PauseController(self.store).open(
            scope=scope,
            scope_id=scope_id,
            reason=reason,
            author=author,
            evidence_ref=evidence_ref,
            review_at_utc=review_at_utc,
            expires_at_utc=expires_at_utc,
        )

    def _active_suppression(self, con, intent: SendIntent, now: str):
        ahash = address_hash(intent.address)
        recipient_domain = self._recipient_domain(intent.address)
        rows = con.execute(
            """SELECT * FROM suppression_entries
               WHERE state='ACTIVE'
                 AND (expires_at_utc='' OR expires_at_utc>?)
                 AND (channel=? OR channel='ALL' OR scope='ALL_CHANNELS')""",
            (now, intent.channel),
        ).fetchall()
        for row in rows:
            scope = row["scope"]
            if scope == "EMAIL_ADDRESS" and row["address_hash"] == ahash:
                return row
            if scope == "PERSON" and intent.lf_contact_id and row["subject_id"] == intent.lf_contact_id:
                return row
            if scope == "COMPANY" and intent.company_id and row["subject_id"] == intent.company_id:
                return row
            if scope == "DOMAIN" and recipient_domain and row["subject_id"] == recipient_domain:
                return row
            if scope in {"CHANNEL", "ALL_CHANNELS"}:
                return row
        return None

    @staticmethod
    def _active_pause(con, intent: SendIntent, now: str):
        # An expired timestamp does not silently resume sending. A separate
        # PauseController transition records EXPIRED/RELEASED with evidence.
        rows = con.execute(
            "SELECT * FROM pauses WHERE state='ACTIVE'"
        ).fetchall()
        for row in rows:
            if row["scope"] == "GLOBAL":
                return row
            if row["scope"] == "CHANNEL" and row["scope_id"] == intent.channel:
                return row
            if row["scope"] == "SEGMENT" and row["scope_id"] == intent.segment_id:
                return row
            if row["scope"] == "COHORT" and row["scope_id"] == intent.cohort_id:
                return row
            # SendIntent deliberately has no campaign/connector/inbox field in
            # this stage.  An active pause in any of those scopes must therefore
            # deny rather than be silently ignored.
            if row["scope"] in {"CAMPAIGN", "CONNECTOR", "INBOX"}:
                return row
            # A future pause scope cannot become a bypass merely because this
            # policy version does not know how to narrow it yet.
            return row
        return None

    @staticmethod
    def _active_cadence_block(con, intent: SendIntent):
        if intent.channel != "email":
            return None
        return con.execute(
            """SELECT * FROM cadence_blocks
               WHERE state='ACTIVE' AND channel=? AND address_hash=?
               ORDER BY created_at_utc DESC LIMIT 1""",
            (intent.channel, address_hash(intent.address)),
        ).fetchone()

    def _deny(self, con, intent: SendIntent, rule_id: str, reason: str) -> PolicyDecision:
        denial_fingerprint = payload_hash(
            {
                "message_id": intent.message_id,
                "authorization_id": intent.authorization_id,
                "address_hash": address_hash(intent.address),
                "rule_id": rule_id,
                "reason": reason,
            }
        )[:20]
        self.store._append_event_tx(
            con,
            event_type="send_denied",
            aggregate_type="message",
            aggregate_id=intent.message_id,
            producer="policy_engine",
            idempotency_key=f"deny:{intent.message_id}:{rule_id}:{denial_fingerprint}",
            payload={"rule_id": rule_id, "reason": reason, "channel": intent.channel},
            actor="send_gate",
        )
        return PolicyDecision(False, rule_id, reason)

    def _validate(self, con, intent: SendIntent, now: str, *, exclude_message_id: str = ""):
        if not str(intent.message_id or "").strip():
            return "LF-INTENT-MESSAGE", "message id is required"
        normalized_address = normalize_email(intent.address)
        if intent.channel == "email" and (
            not normalized_address or "@" not in normalized_address
        ):
            return "LF-INTENT-ADDRESS", "valid recipient address is required"
        derived_domain = self._recipient_domain(intent.address)
        declared_domain = normalize_domain(intent.domain)
        if intent.channel == "email" and declared_domain and declared_domain != derived_domain:
            return "LF-INTENT-DOMAIN", "declared domain does not match recipient address"
        suppression = self._active_suppression(con, intent, now)
        if suppression:
            return "LF-POL-LEGAL-SUPPRESSION", f"suppressed: {suppression['reason']}"
        cadence_block = self._active_cadence_block(con, intent)
        if cadence_block:
            return (
                "LF-POL-CADENCE-BLOCK",
                f"contact cadence is blocked: {cadence_block['reason']}",
            )
        pause = self._active_pause(con, intent, now)
        if pause:
            return "LF-POL-SAFETY-PAUSE", f"paused: {pause['reason']}"
        auth = con.execute(
            "SELECT * FROM outbound_authorizations WHERE authorization_id=?",
            (intent.authorization_id,),
        ).fetchone()
        if not auth:
            return "LF-AUTH-MISSING", "active authorization is required"
        if auth["state"] != "ACTIVE":
            return "LF-AUTH-STATE", f"authorization state is {auth['state']}"
        if auth["legal_status"] != "APPROVED" or not auth["legal_evidence_ref"]:
            return "LF-AUTH-LEGAL", "legal approval and evidence are required"
        if now < auth["valid_from_utc"] or now > auth["valid_until_utc"]:
            return "LF-AUTH-WINDOW", "authorization is outside its validity window"
        exact = {
            "channel": intent.channel,
            "segment_id": intent.segment_id,
            "cohort_id": intent.cohort_id,
            "content_version": intent.content_version,
            "sender_identity": intent.sender_identity,
        }
        for field, value in exact.items():
            if auth[field] != value:
                return "LF-AUTH-SCOPE", f"{field} is outside authorization scope"
        touch = intent.touch_type.upper()
        if touch not in {"FIRST_TOUCH", "FOLLOWUP"}:
            return "LF-AUTH-TOUCH", "unknown touch type"
        cap_field = "first_touch_cap" if touch == "FIRST_TOUCH" else "followup_cap"
        life_field = "lifetime_first_touch_cap" if touch == "FIRST_TOUCH" else "lifetime_followup_cap"
        day = self._date_prefix(now)
        daily = con.execute(
            """SELECT COUNT(*) FROM send_permits
               WHERE authorization_id=? AND touch_type=? AND issued_at_utc LIKE ?
                 AND state IN ('ISSUED','CONSUMED') AND message_id<>?""",
            (intent.authorization_id, touch, f"{day}%", exclude_message_id),
        ).fetchone()[0]
        lifetime = con.execute(
            """SELECT COUNT(*) FROM send_permits
               WHERE authorization_id=? AND touch_type=? AND state IN ('ISSUED','CONSUMED')
                 AND message_id<>?""",
            (intent.authorization_id, touch, exclude_message_id),
        ).fetchone()[0]
        if daily >= int(auth[cap_field]):
            return "LF-AUTH-DAILY-CAP", f"daily {touch.lower()} cap reached"
        if lifetime >= int(auth[life_field]):
            return "LF-AUTH-LIFETIME-CAP", f"lifetime {touch.lower()} cap reached"
        return None

    def issue_permit(self, intent: SendIntent) -> PolicyDecision:
        now = utc_now()
        with self.store.transaction() as con:
            existing = con.execute(
                "SELECT * FROM send_permits WHERE message_id=?", (intent.message_id,)
            ).fetchone()
            if existing:
                scope_problem = self._permit_scope_problem(existing, intent)
                if scope_problem:
                    raise IdempotencyConflict(f"message {intent.message_id} was reused with different scope")
                if existing["state"] not in {"ISSUED", "CONSUMED"}:
                    return self._deny(
                        con,
                        intent,
                        "LF-PERMIT-STATE",
                        f"existing permit state is {existing['state']}",
                    )
                if existing["state"] == "ISSUED" and existing["expires_at_utc"] < now:
                    return self._deny(
                        con, intent, "LF-PERMIT-STATE", "existing permit has expired"
                    )
                problem = self._validate(
                    con, intent, now, exclude_message_id=intent.message_id
                )
                if problem:
                    return self._deny(con, intent, *problem)
                return PolicyDecision(True, "LF-AUTH-IDEMPOTENT", "permit already exists", existing["permit_id"], False)
            problem = self._validate(con, intent, now)
            if problem:
                return self._deny(con, intent, *problem)
            permit_id = new_lf_id("permit")
            expires = (
                datetime.now(timezone.utc) + timedelta(minutes=self.permit_ttl_minutes)
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
            con.execute(
                """INSERT INTO send_permits(
                    permit_id,authorization_id,message_id,lf_opportunity_id,lf_contact_id,
                    company_id,address_hash,domain,channel,touch_type,segment_id,cohort_id,
                    content_version,sender_identity,state,issued_at_utc,expires_at_utc,
                    consumed_at_utc,denial_rule_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    permit_id,
                    intent.authorization_id,
                    intent.message_id,
                    intent.lf_opportunity_id or None,
                    intent.lf_contact_id or None,
                    intent.company_id,
                    address_hash(intent.address),
                    self._recipient_domain(intent.address),
                    intent.channel,
                    intent.touch_type.upper(),
                    intent.segment_id,
                    intent.cohort_id,
                    intent.content_version,
                    intent.sender_identity,
                    "ISSUED",
                    now,
                    expires,
                    "",
                    "",
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="send_permit_issued",
                aggregate_type="message",
                aggregate_id=intent.message_id,
                producer="policy_engine",
                idempotency_key=f"permit:{intent.message_id}",
                payload={
                    "permit_id": permit_id,
                    "authorization_id": intent.authorization_id,
                    "channel": intent.channel,
                    "touch_type": intent.touch_type.upper(),
                },
                actor="send_gate",
            )
            return PolicyDecision(True, "LF-AUTH-ALLOW", "permit issued", permit_id, True)

    def stage_command(
        self,
        intent: SendIntent,
        permit_id: str,
        *,
        payload_ref: str,
        payload: dict,
    ) -> PolicyDecision:
        now = utc_now()
        digest = self.payload_digest(intent, payload)
        with self.store.transaction() as con:
            if not str(payload_ref or "").strip():
                return self._deny(
                    con, intent, "LF-PAYLOAD-REF", "immutable payload reference is required"
                )
            command = con.execute("SELECT * FROM outbox WHERE message_id=?", (intent.message_id,)).fetchone()
            permit = con.execute("SELECT * FROM send_permits WHERE permit_id=?", (permit_id,)).fetchone()
            if not permit or permit["message_id"] != intent.message_id:
                return self._deny(con, intent, "LF-PERMIT-MISSING", "matching permit is required")
            permit_problem = self._permit_scope_problem(permit, intent)
            if permit_problem:
                return self._deny(con, intent, *permit_problem)
            if command:
                if (
                    command["permit_id"] != permit_id
                    or command["payload_ref"] != payload_ref
                    or command["payload_hash"] != digest
                    or command["state"] not in {"STAGED", "DISPATCHING", "SENT"}
                ):
                    raise IdempotencyConflict(
                        f"message {intent.message_id} was staged with different immutable data"
                    )
                problem = self._validate(con, intent, now, exclude_message_id=intent.message_id)
                if problem:
                    if command["state"] == "STAGED":
                        con.execute(
                            "UPDATE outbox SET state='CANCELLED',updated_at_utc=? WHERE command_id=?",
                            (now, command["command_id"]),
                        )
                    return self._deny(con, intent, *problem)
                return PolicyDecision(True, "LF-OUTBOX-IDEMPOTENT", "command already staged", permit_id, False)
            if permit["state"] != "ISSUED" or permit["expires_at_utc"] < now:
                return self._deny(con, intent, "LF-PERMIT-STATE", "permit is not active")
            problem = self._validate(con, intent, now, exclude_message_id=intent.message_id)
            if problem:
                con.execute(
                    "UPDATE send_permits SET state='REVOKED', denial_rule_id=? WHERE permit_id=?",
                    (problem[0], permit_id),
                )
                return self._deny(con, intent, *problem)
            command_id = new_lf_id("command")
            con.execute(
                """INSERT INTO outbox(
                    command_id,message_id,permit_id,command_type,channel,payload_ref,payload_hash,state,
                    attempt_count,next_retry_at_utc,last_error_class,provider_message_id,
                    correlation_id,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (command_id, intent.message_id, permit_id, "SEND_MESSAGE", intent.channel,
                 payload_ref, digest, "STAGED", 0, "", "", "", intent.message_id, now, now),
            )
            con.execute(
                "UPDATE send_permits SET state='CONSUMED', consumed_at_utc=? WHERE permit_id=?",
                (now, permit_id),
            )
            self.store._append_event_tx(
                con,
                event_type="send_command_staged",
                aggregate_type="message",
                aggregate_id=intent.message_id,
                producer="policy_engine",
                idempotency_key=f"outbox:{intent.message_id}",
                payload={"command_id": command_id, "permit_id": permit_id, "channel": intent.channel},
                actor="send_gate",
            )
            return PolicyDecision(True, "LF-OUTBOX-STAGED", "command staged; no transport called", permit_id, True)

    def authorize_dispatch(
        self,
        intent: SendIntent,
        command_id: str,
        *,
        payload_ref: str,
        payload: dict,
    ) -> PolicyDecision:
        """Final fail-closed check immediately before an external transport call.

        This method still performs no external call.  A future worker must obtain
        this transition and then reconcile an ambiguous provider result instead
        of blindly sending again.
        """
        now = utc_now()
        digest = self.payload_digest(intent, payload)
        with self.store.transaction() as con:
            writer_flag = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            if not writer_flag or writer_flag[0] != "1":
                return self._deny(
                    con, intent, "LF-WRITER-DISABLED", "external writers are disabled"
                )
            command = con.execute(
                "SELECT * FROM outbox WHERE command_id=?", (command_id,)
            ).fetchone()
            if not command or command["message_id"] != intent.message_id:
                return self._deny(con, intent, "LF-OUTBOX-MISSING", "staged command is required")
            permit = con.execute(
                "SELECT * FROM send_permits WHERE permit_id=?", (command["permit_id"],)
            ).fetchone()
            if not permit:
                return self._deny(con, intent, "LF-PERMIT-MISSING", "matching permit is required")
            permit_problem = self._permit_scope_problem(permit, intent)
            if permit_problem:
                return self._deny(con, intent, *permit_problem)
            if (
                command["state"] != "STAGED"
                or command["payload_ref"] != payload_ref
                or command["payload_hash"] != digest
            ):
                return self._deny(
                    con, intent, "LF-OUTBOX-SCOPE", "command payload or state does not match"
                )
            if permit["expires_at_utc"] < now:
                con.execute(
                    "UPDATE outbox SET state='CANCELLED',updated_at_utc=? WHERE command_id=?",
                    (now, command_id),
                )
                return self._deny(con, intent, "LF-PERMIT-STATE", "permit expired before dispatch")
            problem = self._validate(con, intent, now, exclude_message_id=intent.message_id)
            if problem:
                con.execute(
                    "UPDATE outbox SET state='CANCELLED',updated_at_utc=? WHERE command_id=?",
                    (now, command_id),
                )
                return self._deny(con, intent, *problem)
            con.execute(
                """UPDATE outbox SET state='DISPATCHING',attempt_count=attempt_count+1,
                   updated_at_utc=? WHERE command_id=? AND state='STAGED'""",
                (now, command_id),
            )
            self.store._append_event_tx(
                con,
                event_type="transport_dispatch_authorized",
                aggregate_type="message",
                aggregate_id=intent.message_id,
                producer="policy_engine",
                idempotency_key=f"dispatch:{intent.message_id}",
                payload={"command_id": command_id, "channel": intent.channel},
                actor="send_gate",
            )
            return PolicyDecision(
                True, "LF-DISPATCH-AUTHORIZED", "final transport check passed", permit["permit_id"], True
            )


__all__ = ["PolicyDecision", "SendGate", "SendIntent"]
