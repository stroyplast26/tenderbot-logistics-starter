"""Durable, default-off control plane for one Bitrix canary.

This module stages and authorises local CRM handoffs only.  It has no REST,
environment, SMTP, or scheduler dependency and never enables external writers.
The caller must use a separate, audited writer process if a future canary is
approved for dispatch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .ids import new_lf_id, normalize_email, utc_now
from .store import FactoryStore, IdempotencyConflict


BITRIX_CANARY_CONNECTOR = "bitrix_canary"
LEAD_CREATE = "BITRIX_LEAD_CREATE"
ACTIVITY_CREATE = "BITRIX_ACTIVITY_CREATE"
CHECKPOINT_OUTCOME_SENT_PAIR = "SENT_PAIR_ACTIVE_LEAD_MAPPING"


class CanaryControlError(RuntimeError):
    """A durable canary precondition was not met."""


class CanaryScopeMismatch(CanaryControlError):
    """The routed reply is outside the exact armed scope."""


class CanaryApprovalRequired(CanaryControlError):
    """No immutable approval currently admits another member."""


class CanaryCapacityExceeded(CanaryControlError):
    """The cumulative canary cap has already been consumed."""


class CanaryLeaseUnavailable(CanaryControlError):
    """Another worker currently owns the connector writer lease."""


class CanaryStaleLease(CanaryControlError):
    """A worker lost its fenced connector writer lease."""


@dataclass(frozen=True)
class ConnectorWriterLease:
    connector: str
    run_id: str
    owner_id: str
    fence_token: int
    lease_until_utc: str


@dataclass(frozen=True)
class CanaryDispatchPermit:
    """A one-operation local permit for a future dedicated canary worker.

    This is deliberately not an adapter and cannot perform a network request.
    A future worker must revalidate the permit immediately before it calls its
    transport.  Generic CRM workers do not receive this permit and remain
    unsuitable for live canary use.
    """

    connector: str
    run_id: str
    member_id: str
    approval_id: str
    operation_id: str
    operation_type: str
    action: str
    payload_hash: str
    correlation_token: str
    fence_token: int
    operation_lease_token: str


def _required_text(value: object, label: str, *, fold: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    return text.casefold() if fold else text


def _is_positive_remote_id(value: object) -> bool:
    """Accept Bitrix numeric IDs only; ``SENT`` alone is not a receipt."""
    text = str(value or "").strip()
    return text.isdigit() and int(text) > 0


def canonical_mailbox(value: object) -> str:
    """Normalise equivalent IMAP Inbox spellings for exact scope matching."""
    raw = str(value or "").strip().casefold()
    # Legacy IMAP callers use ``\\Inbox`` while the factory uses ``INBOX``.
    # The leading hierarchy marker is not part of the mailbox identity here.
    return raw.lstrip("\\/")


def canonical_campaign_id(value: object) -> str:
    """Return the one case-insensitive campaign identity used by all guards."""
    return str(value or "").strip().casefold()


def canonical_thread_identity(value: object) -> str:
    """Canonicalise one Message-ID token, accepting a legacy bare token.

    Scope arming remains strict via :func:`canonical_outbound_thread`; this
    helper also lets the legacy poll compare the Message-ID it extracted from
    ``In-Reply-To`` without losing a valid scope merely because brackets were
    omitted by a mail parser.
    """
    raw = "".join(str(value or "").strip().split())
    if not raw:
        return ""
    if raw.startswith("<") or raw.endswith(">"):
        if not (
            raw.startswith("<")
            and raw.endswith(">")
            and raw.count("<") == 1
            and raw.count(">") == 1
        ):
            return ""
        raw = raw[1:-1]
    if not raw or "@" not in raw or any(ch in raw for ch in "<>"):
        return ""
    return f"<{raw.casefold()}>"


def canonical_outbound_thread(value: object) -> str:
    """Accept one canonical Message-ID-like outbound thread identity.

    The normal form deliberately removes harmless whitespace and case variance
    so a reply cannot bypass an armed scope solely through header formatting.
    It still represents exactly one id, never a References header containing a
    set of possible conversations.
    """
    raw = "".join(str(value or "").strip().split())
    if not raw or not raw.startswith("<") or not raw.endswith(">") or raw.count("<") != 1 or raw.count(">") != 1:
        raise ValueError("canonical_outbound_thread must be one bracketed message id")
    identity = canonical_thread_identity(raw)
    if not identity:
        raise ValueError("canonical_outbound_thread must contain a message id")
    return identity


class CanaryControl:
    """Owns runs, immutable approvals, exact scopes, bindings, and leases."""

    def __init__(self, store: FactoryStore, *, connector: str = BITRIX_CANARY_CONNECTOR):
        self.store = store
        self.connector = _required_text(connector, "connector", fold=True)

    def create_run(self, *, created_by: str, run_id: str = "") -> str:
        actor = _required_text(created_by, "created_by")
        rid = str(run_id or new_lf_id("canary_run")).strip()
        if not rid:
            raise ValueError("run_id is required")
        now = utc_now()
        with self.store.transaction() as con:
            existing = con.execute("SELECT * FROM canary_runs WHERE run_id=?", (rid,)).fetchone()
            if existing:
                if existing["connector"] != self.connector or existing["created_by"] != actor:
                    raise IdempotencyConflict("canary run id has different identity")
                return rid
            con.execute(
                """INSERT INTO canary_runs(
                    run_id,connector,state,created_by,created_at_utc,activated_at_utc,stopped_at_utc,stop_reason
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (rid, self.connector, "DRAFT", actor, now, "", "", ""),
            )
            self.store._append_event_tx(
                con,
                event_type="canary_run_created",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer="canary_control",
                idempotency_key=f"canary-run-created:{rid}",
                payload={"connector": self.connector},
                actor=actor,
            )
        return rid

    def activate_run(self, run_id: str, *, actor: str, evidence_ref: str) -> None:
        rid = _required_text(run_id, "run_id")
        actor = _required_text(actor, "actor")
        evidence = _required_text(evidence_ref, "evidence_ref")
        now = utc_now()
        with self.store.transaction() as con:
            run = self._run_tx(con, rid)
            if run["state"] == "STOPPED":
                raise CanaryControlError("a stopped canary run cannot be activated")
            if run["state"] == "DRAFT":
                try:
                    con.execute(
                        "UPDATE canary_runs SET state='ACTIVE',activated_at_utc=? WHERE run_id=? AND state='DRAFT'",
                        (now, rid),
                    )
                except Exception as exc:
                    if "UNIQUE constraint failed" in str(exc):
                        raise CanaryControlError(
                            "only one active canary run is permitted for this connector"
                        ) from exc
                    raise
            self.store._append_event_tx(
                con,
                event_type="canary_run_activated",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer="canary_control",
                idempotency_key=f"canary-run-activated:{rid}",
                payload={"state": "ACTIVE"},
                evidence_ref=evidence,
                actor=actor,
            )

    def arm_scope(
        self,
        run_id: str,
        *,
        mailbox: str,
        campaign_id: str,
        contact_address: str,
        canonical_thread: str,
        lf_opportunity_id: str,
        armed_by: str,
        evidence_ref: str,
        member_id: str = "",
    ) -> str:
        """Arm only an exact, existing-opportunity conversation identity."""
        rid = _required_text(run_id, "run_id")
        box = canonical_mailbox(mailbox)
        campaign = canonical_campaign_id(campaign_id)
        if not box:
            raise ValueError("mailbox is required")
        if not campaign:
            raise ValueError("campaign_id is required")
        contact = normalize_email(contact_address)
        if not contact:
            raise ValueError("contact_address is required")
        thread = canonical_outbound_thread(canonical_thread)
        opportunity_id = _required_text(lf_opportunity_id, "lf_opportunity_id")
        actor = _required_text(armed_by, "armed_by")
        evidence = _required_text(evidence_ref, "evidence_ref")
        mid = str(member_id or new_lf_id("canary_member")).strip()
        if not mid:
            raise ValueError("member_id is required")
        now = utc_now()
        with self.store.transaction() as con:
            run = self._run_tx(con, rid)
            if run["state"] == "STOPPED":
                raise CanaryControlError("cannot arm a stopped run")
            if not con.execute(
                "SELECT 1 FROM opportunities WHERE lf_opportunity_id=?", (opportunity_id,)
            ).fetchone():
                raise KeyError("canary scope requires an existing opportunity")
            existing = con.execute(
                "SELECT * FROM canary_scope_members WHERE member_id=?", (mid,)
            ).fetchone()
            if existing:
                identity = (
                    existing["run_id"], existing["mailbox"], existing["campaign_id"],
                    existing["contact_address"], existing["canonical_outbound_thread"],
                    existing["lf_opportunity_id"],
                )
                if identity != (rid, box, campaign, contact, thread, opportunity_id):
                    raise IdempotencyConflict("canary member id has a different exact scope")
                return mid
            try:
                con.execute(
                    """INSERT INTO canary_scope_members(
                        member_id,run_id,mailbox,campaign_id,contact_address,canonical_outbound_thread,
                        lf_opportunity_id,armed_by,evidence_ref,state,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (mid, rid, box, campaign, contact, thread, opportunity_id, actor, evidence, "ARMED", now),
                )
            except Exception as exc:
                if "UNIQUE constraint failed" in str(exc):
                    raise IdempotencyConflict("the exact canary scope is already armed") from exc
                raise
            self.store._append_event_tx(
                con,
                event_type="canary_scope_armed",
                aggregate_type="canary_member",
                aggregate_id=mid,
                producer="canary_control",
                idempotency_key=f"canary-scope-armed:{mid}",
                payload={
                    "run_id": rid,
                    "mailbox": box,
                    "campaign_id": campaign,
                    "contact_address": contact,
                    "canonical_outbound_thread": thread,
                    "lf_opportunity_id": opportunity_id,
                },
                evidence_ref=evidence,
                actor=actor,
            )
        return mid

    def record_manual_checkpoint(
        self, run_id: str, *, actor: str, evidence_ref: str, outcome: str
    ) -> str:
        """Persist evidence of one fully proved canary member.

        A cap-5 expansion is deliberately stricter than a human statement that
        a member was "reviewed": both exact operations must already be SENT,
        and the sent Lead must still have its exact ACTIVE local mapping.  A
        terminal manual review is useful evidence, but it is not an automatic
        authority to expand this canary.
        """
        rid = _required_text(run_id, "run_id")
        actor = _required_text(actor, "actor")
        evidence = _required_text(evidence_ref, "evidence_ref")
        outcome = _required_text(outcome, "outcome")
        with self.store.transaction() as con:
            self._active_run_tx(con, rid)
            approval = self._latest_approval_tx(con, rid)
            if not approval or int(approval["cumulative_cap"]) != 1:
                raise CanaryApprovalRequired("manual checkpoint requires the immutable cap-1 approval")
            members = con.execute(
                """SELECT b.member_id,COUNT(*) AS binding_count
                   FROM canary_operation_bindings b WHERE b.run_id=?
                   GROUP BY b.member_id ORDER BY b.member_id""",
                (rid,),
            ).fetchall()
            if len(members) != 1 or int(members[0]["binding_count"]) != 2:
                raise CanaryApprovalRequired(
                    "manual checkpoint requires exactly one durably admitted Lead+Activity member"
                )
            member_id = str(members[0]["member_id"])
            proof = self._sent_pair_checkpoint_proof_tx(
                con, run_id=rid, member_id=member_id
            )
            event, _ = self.store._append_event_tx(
                con,
                event_type="canary_manual_checkpoint_recorded",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer="canary_control",
                idempotency_key=f"canary-checkpoint:{rid}:{member_id}:{evidence}",
                payload={
                    "approval_id": approval["approval_id"], "cumulative_cap": 1,
                    "member_id": member_id, "outcome": outcome,
                    "outcome_kind": CHECKPOINT_OUTCOME_SENT_PAIR,
                    **proof,
                },
                evidence_ref=evidence,
                actor=actor,
            )
            return str(event["event_id"])

    def create_approval(
        self,
        run_id: str,
        *,
        cumulative_cap: int,
        approver: str,
        evidence_ref: str,
        checkpoint_event_id: str = "",
        approval_id: str = "",
    ) -> str:
        """Create immutable cap=1, then cap=5 after a proved SENT pair."""
        rid = _required_text(run_id, "run_id")
        actor = _required_text(approver, "approver")
        evidence = _required_text(evidence_ref, "evidence_ref")
        cap = int(cumulative_cap)
        aid = str(approval_id or new_lf_id("canary_approval")).strip()
        if not aid:
            raise ValueError("approval_id is required")
        checkpoint = str(checkpoint_event_id or "").strip()
        now = utc_now()
        with self.store.transaction() as con:
            # Replay must be checked before progression validation: after the
            # cap-1 row exists, replaying the exact same immutable request is
            # valid rather than an attempted second cap-1 approval.
            existing = con.execute(
                "SELECT * FROM canary_approvals WHERE approval_id=?", (aid,)
            ).fetchone()
            if existing:
                if (
                    existing["run_id"], int(existing["cumulative_cap"]), existing["approver"],
                    existing["evidence_ref"], existing["checkpoint_event_id"],
                ) != (rid, cap, actor, evidence, checkpoint):
                    raise IdempotencyConflict("canary approval id has different content")
                return aid
            self._active_run_tx(con, rid)
            latest = self._latest_approval_tx(con, rid)
            if not latest:
                if cap != 1 or checkpoint:
                    raise CanaryApprovalRequired("the first canary approval must have cumulative cap exactly 1")
                sequence = 1
            else:
                if int(latest["cumulative_cap"]) != 1 or cap != 5 or not checkpoint:
                    raise CanaryApprovalRequired(
                        "only one immutable cap-5 expansion after cap-1 is allowed"
                    )
                checkpoint_row = con.execute(
                    """SELECT event_id,aggregate_id,event_type,producer,evidence_ref,recorded_at_utc
                       FROM events WHERE event_id=?""",
                    (checkpoint,),
                ).fetchone()
                if (
                    not checkpoint_row
                    or checkpoint_row["aggregate_id"] != rid
                    or checkpoint_row["event_type"] != "canary_manual_checkpoint_recorded"
                    or checkpoint_row["producer"] != "canary_control"
                    or not checkpoint_row["evidence_ref"]
                    or checkpoint_row["recorded_at_utc"] < latest["created_at_utc"]
                ):
                    raise CanaryApprovalRequired(
                        "cap-5 expansion requires a later recorded manual checkpoint with evidence"
                    )
                try:
                    checkpoint_payload = json.loads(str(
                        con.execute("SELECT payload_json FROM events WHERE event_id=?", (checkpoint,)).fetchone()[0]
                    ))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise CanaryApprovalRequired("manual checkpoint payload is invalid") from exc
                if (
                    not str(checkpoint_payload.get("member_id", "") or "")
                    or not str(checkpoint_payload.get("outcome", "") or "")
                    or checkpoint_payload.get("approval_id") != latest["approval_id"]
                    or checkpoint_payload.get("cumulative_cap") != 1
                    or checkpoint_payload.get("outcome_kind") != CHECKPOINT_OUTCOME_SENT_PAIR
                    or not isinstance(checkpoint_payload.get("operations"), list)
                    or len(checkpoint_payload["operations"]) != 2
                ):
                    raise CanaryApprovalRequired("manual checkpoint lacks proved cap-1 outcome evidence")
                try:
                    proof = self._sent_pair_checkpoint_proof_tx(
                        con,
                        run_id=rid,
                        member_id=_required_text(
                            checkpoint_payload["member_id"], "checkpoint member_id"
                        ),
                    )
                except (CanaryApprovalRequired, ValueError) as exc:
                    raise CanaryApprovalRequired(
                        "cap-5 expansion requires a currently proved SENT Lead+Activity pair"
                    ) from exc
                if (
                    checkpoint_payload.get("operations") != proof["operations"]
                    or checkpoint_payload.get("active_lead_mapping")
                    != proof["active_lead_mapping"]
                ):
                    raise CanaryApprovalRequired(
                        "manual checkpoint proof no longer matches the exact member state"
                    )
                sequence = int(latest["approval_sequence"]) + 1
            con.execute(
                """INSERT INTO canary_approvals(
                    approval_id,run_id,approval_sequence,cumulative_cap,approver,evidence_ref,
                    checkpoint_event_id,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (aid, rid, sequence, cap, actor, evidence, checkpoint, now),
            )
            self.store._append_event_tx(
                con,
                event_type="canary_approval_created",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer="canary_control",
                idempotency_key=f"canary-approval:{aid}",
                payload={"approval_id": aid, "approval_sequence": sequence, "cumulative_cap": cap,
                         "checkpoint_event_id": checkpoint},
                evidence_ref=evidence,
                actor=actor,
            )
        return aid

    @staticmethod
    def _sent_pair_checkpoint_proof_tx(
        con: Any, *, run_id: str, member_id: str
    ) -> dict[str, object]:
        """Return an exact durable proof for the automatic 1→5 expansion.

        This is intentionally based on current local state, not only on a
        historical event payload.  It prevents an approval from being granted
        after the exact Lead mapping or either successful operation has been
        altered since a checkpoint was recorded.
        """
        rows = con.execute(
            """SELECT b.operation_id,b.operation_type,o.state,o.lf_entity_type,
                      o.lf_entity_id,o.remote_entity_type,o.remote_entity_id,
                      o.dependency_operation_id,
                      m.lf_entity_id AS active_lead_mapping_id
               FROM canary_operation_bindings b JOIN crm_outbox o
                 ON o.operation_id=b.operation_id
               LEFT JOIN crm_mappings m
                 ON m.lf_entity_type=o.lf_entity_type AND m.lf_entity_id=o.lf_entity_id
                AND m.remote_entity_type='lead' AND m.remote_entity_id=o.remote_entity_id
                AND m.state='ACTIVE'
               WHERE b.run_id=? AND b.member_id=?
               ORDER BY b.operation_type,b.operation_id""",
            (run_id, member_id),
        ).fetchall()
        if len(rows) != 2:
            raise CanaryApprovalRequired(
                "checkpoint requires exactly one Lead and one Activity operation"
            )
        by_type = {str(row["operation_type"]): row for row in rows}
        if set(by_type) != {LEAD_CREATE, ACTIVITY_CREATE}:
            raise CanaryApprovalRequired(
                "checkpoint requires the exact Lead+Activity operation pair"
            )
        lead = by_type[LEAD_CREATE]
        activity = by_type[ACTIVITY_CREATE]
        if str(lead["state"]) != "SENT" or str(activity["state"]) != "SENT":
            raise CanaryApprovalRequired(
                "checkpoint requires both exact Lead and Activity operations to be SENT"
            )
        lead_remote_id = str(lead["remote_entity_id"] or "").strip()
        activity_remote_id = str(activity["remote_entity_id"] or "").strip()
        if (
            str(lead["remote_entity_type"] or "").strip().lower() != "lead"
            or not _is_positive_remote_id(lead_remote_id)
            or not lead["active_lead_mapping_id"]
        ):
            raise CanaryApprovalRequired(
                "checkpoint requires an ACTIVE mapping and positive receipt ID for the exact sent Lead"
            )
        if (
            str(activity["remote_entity_type"] or "").strip().lower() != "activity"
            or not _is_positive_remote_id(activity_remote_id)
        ):
            raise CanaryApprovalRequired(
                "checkpoint requires a positive receipt ID for the exact sent Activity"
            )
        if str(activity["dependency_operation_id"] or "") != str(lead["operation_id"]):
            raise CanaryApprovalRequired(
                "checkpoint Activity must depend on the exact sent Lead"
            )
        return {
            "operations": [
                {
                    "operation_id": str(lead["operation_id"]),
                    "operation_type": LEAD_CREATE,
                    "state": "SENT",
                },
                {
                    "operation_id": str(activity["operation_id"]),
                    "operation_type": ACTIVITY_CREATE,
                    "state": "SENT",
                },
            ],
            "active_lead_mapping": {
                "lf_entity_type": str(lead["lf_entity_type"]),
                "lf_entity_id": str(lead["lf_entity_id"]),
                "remote_entity_type": "lead",
                "remote_entity_id": lead_remote_id,
            },
        }

    def admit_handoff_tx(
        self,
        con: Any,
        *,
        run_id: str,
        member_id: str,
        mailbox: str,
        campaign_id: str,
        contact_address: str,
        canonical_thread: str,
        lf_opportunity_id: str,
        interaction_id: str,
        lead_operation_id: str,
        activity_operation_id: str,
    ) -> bool:
        """Atomically bind the Lead and Activity pair to one exact scope member.

        A member consumes one cumulative slot when its first binding is staged;
        it remains consumed regardless of later PENDING, UNCERTAIN, REVIEW,
        DEAD, or SENT state in ``crm_outbox``.
        """
        rid = _required_text(run_id, "run_id")
        mid = _required_text(member_id, "member_id")
        box = canonical_mailbox(mailbox)
        campaign = canonical_campaign_id(campaign_id)
        if not box:
            raise CanaryScopeMismatch("mailbox is required for canary admission")
        if not campaign:
            raise CanaryScopeMismatch("campaign_id is required for canary admission")
        contact = normalize_email(contact_address)
        if not contact:
            raise CanaryScopeMismatch("contact_address is required for canary admission")
        thread = canonical_outbound_thread(canonical_thread)
        opportunity_id = _required_text(lf_opportunity_id, "lf_opportunity_id")
        interaction = _required_text(interaction_id, "interaction_id")
        lead_id = _required_text(lead_operation_id, "lead_operation_id")
        activity_id = _required_text(activity_operation_id, "activity_operation_id")

        self._active_run_tx(con, rid)
        member = con.execute(
            "SELECT * FROM canary_scope_members WHERE member_id=? AND run_id=? AND state='ARMED'",
            (mid, rid),
        ).fetchone()
        if not member or (
            member["mailbox"], member["campaign_id"], member["contact_address"],
            member["canonical_outbound_thread"], member["lf_opportunity_id"],
        ) != (box, campaign, contact, thread, opportunity_id):
            raise CanaryScopeMismatch("routed handoff is outside the exact armed canary scope")
        observed = con.execute(
            """SELECT lf_interaction_id,lf_opportunity_id,address,thread_id
               FROM interactions WHERE lf_interaction_id=?""",
            (interaction,),
        ).fetchone()
        if not observed or (
            str(observed["lf_opportunity_id"] or ""), normalize_email(observed["address"]),
            canonical_outbound_thread(observed["thread_id"]),
        ) != (opportunity_id, contact, thread):
            raise CanaryScopeMismatch("persisted interaction does not prove the exact canary scope")
        self._assert_operation_pair_tx(
            con,
            lead_operation_id=lead_id,
            activity_operation_id=activity_id,
            opportunity_id=opportunity_id,
            interaction_id=interaction,
        )
        approval = self._latest_approval_tx(con, rid)
        if not approval:
            raise CanaryApprovalRequired("no immutable canary approval exists")

        existing = con.execute(
            "SELECT * FROM canary_operation_bindings WHERE operation_id IN (?,?) ORDER BY operation_id",
            (lead_id, activity_id),
        ).fetchall()
        if existing:
            if len(existing) != 2 or any(
                row["run_id"] != rid or row["member_id"] != mid or row["interaction_id"] != interaction
                for row in existing
            ):
                raise IdempotencyConflict("CRM operation already has a different canary binding")
            return False
        prior_member = con.execute(
            "SELECT 1 FROM canary_operation_bindings WHERE run_id=? AND member_id=? LIMIT 1",
            (rid, mid),
        ).fetchone()
        if prior_member:
            raise IdempotencyConflict("canary member has an incomplete operation pair")
        used_slots = int(con.execute(
            "SELECT COUNT(DISTINCT member_id) FROM canary_operation_bindings WHERE run_id=?", (rid,)
        ).fetchone()[0])
        if used_slots >= int(approval["cumulative_cap"]):
            raise CanaryCapacityExceeded("the immutable cumulative canary cap is exhausted")
        duplicate = con.execute(
            """SELECT 1 FROM canary_operation_bindings
               WHERE run_id=? AND member_id=? AND operation_type IN (?,?) LIMIT 1""",
            (rid, mid, LEAD_CREATE, ACTIVITY_CREATE),
        ).fetchone()
        if duplicate:
            raise IdempotencyConflict("canary member already has a different operation pair")
        now = utc_now()
        for operation_id, operation_type in ((lead_id, LEAD_CREATE), (activity_id, ACTIVITY_CREATE)):
            con.execute(
                """INSERT INTO canary_operation_bindings(
                    operation_id,run_id,member_id,approval_id,operation_type,interaction_id,created_at_utc
                ) VALUES(?,?,?,?,?,?,?)""",
                (operation_id, rid, mid, approval["approval_id"], operation_type, interaction, now),
            )
        self.store._append_event_tx(
            con,
            event_type="canary_handoff_admitted",
            aggregate_type="canary_member",
            aggregate_id=mid,
            producer="canary_control",
            idempotency_key=f"canary-handoff-admitted:{rid}:{mid}:{interaction}",
            payload={
                "approval_id": approval["approval_id"], "cumulative_cap": int(approval["cumulative_cap"]),
                "lead_operation_id": lead_id, "activity_operation_id": activity_id,
            },
            actor="inbound_router",
        )
        return True

    def acquire_writer_lease(
        self, run_id: str, *, owner_id: str, lease_seconds: int = 120
    ) -> ConnectorWriterLease:
        """Acquire or renew one fenced process lease for ``bitrix_canary``."""
        rid = _required_text(run_id, "run_id")
        owner = _required_text(owner_id, "owner_id")
        seconds = max(1, int(lease_seconds))
        from datetime import datetime, timedelta, timezone

        now = utc_now()
        until = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        with self.store.transaction() as con:
            self._active_run_tx(con, rid)
            con.execute(
                "INSERT OR IGNORE INTO connector_writer_leases(connector) VALUES(?)",
                (self.connector,),
            )
            row = con.execute(
                "SELECT * FROM connector_writer_leases WHERE connector=?", (self.connector,)
            ).fetchone()
            active = bool(row["owner_id"] and row["lease_until_utc"] and row["lease_until_utc"] > now)
            if active and (row["owner_id"] != owner or row["run_id"] != rid):
                raise CanaryLeaseUnavailable("bitrix canary writer lease is owned by another worker")
            fence = int(row["fence_token"])
            # Every renewal gets a new fence.  Otherwise a stale copy of an
            # earlier lease object would remain usable beside the renewed one.
            fence += 1
            con.execute(
                """UPDATE connector_writer_leases
                   SET run_id=?,owner_id=?,fence_token=?,lease_until_utc=?,
                       acquired_at_utc=?,updated_at_utc=? WHERE connector=?""",
                (rid, owner, fence, until, now, now, self.connector),
            )
            return ConnectorWriterLease(self.connector, rid, owner, fence, until)

    def release_writer_lease(self, lease: ConnectorWriterLease) -> bool:
        if not isinstance(lease, ConnectorWriterLease) or lease.connector != self.connector:
            raise CanaryStaleLease("lease identity is invalid")
        with self.store.transaction() as con:
            updated = con.execute(
                """UPDATE connector_writer_leases
                   SET run_id='',owner_id='',lease_until_utc='',fence_token=fence_token+1,
                       updated_at_utc=?
                   WHERE connector=? AND run_id=? AND owner_id=? AND fence_token=?""",
                (utc_now(), self.connector, lease.run_id, lease.owner_id, int(lease.fence_token)),
            )
            return updated.rowcount == 1

    def assert_writer_lease(self, lease: ConnectorWriterLease) -> None:
        """Recheck a fence immediately before a future external adapter call."""
        if not isinstance(lease, ConnectorWriterLease) or lease.connector != self.connector:
            raise CanaryStaleLease("lease identity is invalid")
        self.store.init()
        con = self.store.connect()
        try:
            run = con.execute("SELECT state FROM canary_runs WHERE run_id=?", (lease.run_id,)).fetchone()
            row = con.execute(
                "SELECT * FROM connector_writer_leases WHERE connector=?", (self.connector,)
            ).fetchone()
            writers = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
        finally:
            con.close()
        if (
            not run or run["state"] != "ACTIVE" or not row
            or row["run_id"] != lease.run_id or row["owner_id"] != lease.owner_id
            or int(row["fence_token"]) != int(lease.fence_token)
            or not row["lease_until_utc"] or row["lease_until_utc"] <= utc_now()
            or not writers or writers[0] != "1"
        ):
            raise CanaryStaleLease("canary writer lease or writer gate is no longer valid")

    def claim_next_dispatch(
        self,
        lease: ConnectorWriterLease,
        *,
        operation_type: str = LEAD_CREATE,
        operation_lease_seconds: int = 120,
    ) -> CanaryDispatchPermit | None:
        """Claim only the next exact operation bound to this fenced canary.

        It intentionally does not call a transport.  The generic ``CrmOutbox``
        worker is not reused here: it can select unrelated queue records and is
        therefore explicitly not a live-canary dispatch path.
        """
        if operation_type not in {LEAD_CREATE, ACTIVITY_CREATE}:
            raise ValueError("unsupported canary operation_type")
        self.assert_writer_lease(lease)
        from datetime import datetime, timedelta, timezone

        now = utc_now()
        until = (datetime.now(timezone.utc) + timedelta(seconds=max(1, int(operation_lease_seconds)))).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        with self.store.transaction() as con:
            self._assert_writer_lease_tx(con, lease, now)
            if operation_type == LEAD_CREATE:
                row = con.execute(
                    """SELECT o.operation_id,o.operation_type,o.payload_hash,o.correlation_token,
                              b.run_id,b.member_id,b.approval_id
                       FROM crm_outbox o
                       JOIN canary_operation_bindings b ON b.operation_id=o.operation_id
                       JOIN canary_runs r ON r.run_id=b.run_id AND r.connector=? AND r.state='ACTIVE'
                       JOIN canary_approvals a ON a.approval_id=b.approval_id AND a.run_id=b.run_id
                       WHERE o.operation_type=? AND o.state='PENDING'
                         AND (o.next_attempt_at_utc='' OR o.next_attempt_at_utc<=?)
                         AND (o.lease_until_utc='' OR o.lease_until_utc<=?)
                         AND b.run_id=?
                       ORDER BY o.created_at_utc,o.operation_id LIMIT 1""",
                    (self.connector, LEAD_CREATE, now, now, lease.run_id),
                ).fetchone()
            else:
                row = con.execute(
                    """SELECT a.operation_id,a.operation_type,a.payload_hash,a.correlation_token,
                              b.run_id,b.member_id,b.approval_id
                       FROM crm_outbox a
                       JOIN canary_operation_bindings b ON b.operation_id=a.operation_id
                       JOIN canary_runs r ON r.run_id=b.run_id AND r.connector=? AND r.state='ACTIVE'
                       JOIN canary_approvals ap ON ap.approval_id=b.approval_id AND ap.run_id=b.run_id
                       JOIN crm_outbox l ON l.operation_id=a.dependency_operation_id
                       JOIN canary_operation_bindings lb
                         ON lb.operation_id=l.operation_id AND lb.run_id=b.run_id AND lb.member_id=b.member_id
                       JOIN crm_mappings m
                         ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                        AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id
                        AND m.state='ACTIVE'
                       WHERE a.operation_type=? AND a.state='PENDING'
                         AND (a.next_attempt_at_utc='' OR a.next_attempt_at_utc<=?)
                         AND (a.lease_until_utc='' OR a.lease_until_utc<=?)
                         AND l.operation_type=? AND l.state='SENT' AND l.remote_entity_type='lead'
                         AND l.remote_entity_id<>'' AND b.run_id=?
                       ORDER BY a.created_at_utc,a.operation_id LIMIT 1""",
                    (self.connector, ACTIVITY_CREATE, now, now, LEAD_CREATE, lease.run_id),
                ).fetchone()
            if not row:
                return None
            operation_token = self._action_bound_operation_lease_token("CREATE")
            if not self._lease_token_matches_action(operation_token, "CREATE"):
                raise CanaryStaleLease("canary create lease lacks its durable action")
            updated = con.execute(
                """UPDATE crm_outbox SET state='UNCERTAIN',attempt_count=attempt_count+1,
                   leased_by=?,lease_token=?,lease_until_utc=?,updated_at_utc=?
                   WHERE operation_id=? AND operation_type=? AND state='PENDING'
                     AND (lease_until_utc='' OR lease_until_utc<=?)""",
                (
                    lease.owner_id, operation_token, until, now,
                    row["operation_id"], operation_type, now,
                ),
            )
            if updated.rowcount != 1:
                return None
            return CanaryDispatchPermit(
                self.connector,
                str(row["run_id"]),
                str(row["member_id"]),
                str(row["approval_id"]),
                str(row["operation_id"]),
                operation_type,
                "CREATE",
                str(row["payload_hash"]),
                str(row["correlation_token"]),
                int(lease.fence_token),
                operation_token,
            )

    def claim_next_reconcile(
        self,
        lease: ConnectorWriterLease,
        *,
        operation_lease_seconds: int = 120,
    ) -> CanaryDispatchPermit | None:
        """Claim one exact bound uncertain Lead for correlation-only reconcile.

        This selector cannot return an Activity and never returns a CREATE
        permit.  Its executor action may only look up the immutable correlation
        token; it has no path to ``create_lead``.
        """
        return self._claim_uncertain_bound_operation(
            lease,
            operation_type=LEAD_CREATE,
            action="RECONCILE",
            increment_reconcile=True,
            operation_lease_seconds=operation_lease_seconds,
        )

    def claim_next_expired_activity_review(
        self,
        lease: ConnectorWriterLease,
        *,
        operation_lease_seconds: int = 120,
    ) -> CanaryDispatchPermit | None:
        """Claim an expired ambiguous Activity only to terminally mark REVIEW.

        There is deliberately no Activity reconciliation transport because the
        remote API has no immutable correlation key that could prove identity.
        """
        return self._claim_uncertain_bound_operation(
            lease,
            operation_type=ACTIVITY_CREATE,
            action="ACTIVITY_REVIEW",
            increment_reconcile=False,
            operation_lease_seconds=operation_lease_seconds,
        )

    def assert_dispatch_permit(
        self,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        *,
        operation_id: str,
    ) -> None:
        """Reject a forged, stale, or cross-operation canary dispatch permit."""
        self._assert_dispatch_permit_identity(permit, lease, operation_id=operation_id)
        self.assert_writer_lease(lease)
        now = utc_now()
        con = self.store.connect()
        try:
            self._assert_dispatch_permit_row_tx(con, permit, lease, now)
        finally:
            con.close()

    def assert_dispatch_permit_tx(
        self,
        con: Any,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        *,
        operation_id: str,
    ) -> None:
        """Verify an exact permit while the caller owns the write barrier.

        The sealed Bitrix runtime uses this method inside the same SQLite
        ``BEGIN IMMEDIATE`` transaction that covers its final rate admission
        and the ensuing REST request.  Therefore ``stop_run`` is linear with
        that request: a prior stop is observed here; a later stop cannot
        commit until the caller has left the barrier.
        """
        self._assert_dispatch_permit_identity(permit, lease, operation_id=operation_id)
        now = utc_now()
        self._assert_writer_lease_tx(con, lease, now)
        self._assert_dispatch_permit_row_tx(con, permit, lease, now)

    def _assert_dispatch_permit_identity(
        self,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        *,
        operation_id: str,
    ) -> None:
        if (
            not isinstance(permit, CanaryDispatchPermit)
            or permit.connector != self.connector
            or permit.operation_id != str(operation_id or "").strip()
            or permit.run_id != lease.run_id
            or permit.fence_token != lease.fence_token
            or permit.action not in {"CREATE", "RECONCILE", "ACTIVITY_REVIEW"}
        ):
            raise CanaryStaleLease("canary dispatch permit is not for this exact operation and fence")

    def _assert_dispatch_permit_row_tx(
        self,
        con: Any,
        permit: CanaryDispatchPermit,
        lease: ConnectorWriterLease,
        now: str,
    ) -> None:
        row = con.execute(
            """SELECT o.state,o.operation_type,o.payload_hash,o.correlation_token,
                           o.leased_by,o.lease_token,o.lease_until_utc,
                           b.run_id,b.member_id,b.approval_id,b.operation_type AS binding_operation_type,
                           r.state AS run_state
                   FROM crm_outbox o JOIN canary_operation_bindings b ON b.operation_id=o.operation_id
                   JOIN canary_runs r ON r.run_id=b.run_id AND r.connector=?
                   JOIN canary_approvals a ON a.approval_id=b.approval_id AND a.run_id=b.run_id
                   WHERE o.operation_id=?""",
            (self.connector, permit.operation_id),
        ).fetchone()
        if (
            not row or row["state"] != "UNCERTAIN" or row["operation_type"] != permit.operation_type
            or row["binding_operation_type"] != permit.operation_type
            or row["payload_hash"] != permit.payload_hash
            or row["correlation_token"] != permit.correlation_token
            or row["leased_by"] != lease.owner_id
            or row["lease_token"] != permit.operation_lease_token
            or not row["lease_until_utc"] or row["lease_until_utc"] <= now
            or row["run_id"] != permit.run_id or row["member_id"] != permit.member_id
            or row["approval_id"] != permit.approval_id or row["run_state"] != "ACTIVE"
            or not self._lease_token_matches_action(
                str(row["lease_token"] or ""), permit.action
            )
        ):
            raise CanaryStaleLease("canary dispatch permit no longer proves this operation")

    def _claim_uncertain_bound_operation(
        self,
        lease: ConnectorWriterLease,
        *,
        operation_type: str,
        action: str,
        increment_reconcile: bool,
        operation_lease_seconds: int,
    ) -> CanaryDispatchPermit | None:
        self.assert_writer_lease(lease)
        from datetime import datetime, timedelta, timezone

        now = utc_now()
        until = (datetime.now(timezone.utc) + timedelta(
            seconds=max(1, int(operation_lease_seconds))
        )).isoformat(timespec="seconds").replace("+00:00", "Z")
        with self.store.transaction() as con:
            self._assert_writer_lease_tx(con, lease, now)
            row = con.execute(
                """SELECT o.operation_id,o.operation_type,o.payload_hash,o.correlation_token,
                          b.run_id,b.member_id,b.approval_id
                   FROM crm_outbox o
                   JOIN canary_operation_bindings b ON b.operation_id=o.operation_id
                   JOIN canary_runs r ON r.run_id=b.run_id AND r.connector=? AND r.state='ACTIVE'
                   JOIN canary_approvals a ON a.approval_id=b.approval_id AND a.run_id=b.run_id
                   WHERE o.operation_type=? AND o.state='UNCERTAIN'
                     AND (o.next_attempt_at_utc='' OR o.next_attempt_at_utc<=?)
                     AND (o.lease_until_utc='' OR o.lease_until_utc<=?)
                     AND b.run_id=?
                   ORDER BY o.updated_at_utc,o.operation_id LIMIT 1""",
                (self.connector, operation_type, now, now, lease.run_id),
            ).fetchone()
            if not row:
                return None
            token = self._action_bound_operation_lease_token(action)
            if not self._lease_token_matches_action(token, action):
                raise CanaryStaleLease("canary operation lease lacks its durable action")
            if increment_reconcile:
                updated = con.execute(
                    """UPDATE crm_outbox SET leased_by=?,lease_token=?,lease_until_utc=?,
                       reconcile_count=reconcile_count+1,updated_at_utc=?
                       WHERE operation_id=? AND operation_type=? AND state='UNCERTAIN'
                         AND (lease_until_utc='' OR lease_until_utc<=?)""",
                    (lease.owner_id, token, until, now, row["operation_id"], operation_type, now),
                )
            else:
                updated = con.execute(
                    """UPDATE crm_outbox SET leased_by=?,lease_token=?,lease_until_utc=?,updated_at_utc=?
                       WHERE operation_id=? AND operation_type=? AND state='UNCERTAIN'
                         AND (lease_until_utc='' OR lease_until_utc<=?)""",
                    (lease.owner_id, token, until, now, row["operation_id"], operation_type, now),
                )
            if updated.rowcount != 1:
                return None
            return CanaryDispatchPermit(
                self.connector,
                str(row["run_id"]),
                str(row["member_id"]),
                str(row["approval_id"]),
                str(row["operation_id"]),
                operation_type,
                action,
                str(row["payload_hash"]),
                str(row["correlation_token"]),
                int(lease.fence_token),
                token,
            )

    @staticmethod
    def _action_bound_operation_lease_token(action: str) -> str:
        """Create a durable operation lease for exactly one allowed action."""
        normalized = str(action or "").strip().upper()
        if normalized not in {"CREATE", "RECONCILE", "ACTIVITY_REVIEW"}:
            raise ValueError("unsupported canary operation action")
        return f"canary-action:{normalized}:{new_lf_id('canary_dispatch')}"

    @staticmethod
    def _lease_token_matches_action(token: str, action: str) -> bool:
        normalized = str(action or "").strip().upper()
        return bool(
            normalized in {"CREATE", "RECONCILE", "ACTIVITY_REVIEW"}
            and str(token or "").startswith(
                f"canary-action:{normalized}:lf_canary_dispatch_"
            )
        )

    def _assert_writer_lease_tx(
        self, con: Any, lease: ConnectorWriterLease, now: str
    ) -> None:
        if not isinstance(lease, ConnectorWriterLease) or lease.connector != self.connector:
            raise CanaryStaleLease("lease identity is invalid")
        run = con.execute("SELECT state FROM canary_runs WHERE run_id=?", (lease.run_id,)).fetchone()
        row = con.execute(
            "SELECT * FROM connector_writer_leases WHERE connector=?", (self.connector,)
        ).fetchone()
        writers = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        if (
            not run or run["state"] != "ACTIVE" or not row
            or row["run_id"] != lease.run_id or row["owner_id"] != lease.owner_id
            or int(row["fence_token"]) != int(lease.fence_token)
            or not row["lease_until_utc"] or row["lease_until_utc"] <= now
            or not writers or writers[0] != "1"
        ):
            raise CanaryStaleLease("canary writer lease or writer gate is no longer valid")

    def stop_run(self, run_id: str, *, actor: str, reason: str, evidence_ref: str) -> None:
        """Stop the run, revoke its fence, and close the global writer gate."""
        rid = _required_text(run_id, "run_id")
        actor = _required_text(actor, "actor")
        why = _required_text(reason, "reason")
        evidence = _required_text(evidence_ref, "evidence_ref")
        now = utc_now()
        with self.store.transaction() as con:
            run = self._run_tx(con, rid)
            if run["state"] == "STOPPED":
                if run["stop_reason"] != why:
                    raise IdempotencyConflict("a stopped canary run cannot change its stop reason")
                prior_event = con.execute(
                    """SELECT evidence_ref FROM events WHERE producer='canary_control'
                       AND idempotency_key=?""",
                    (f"canary-run-stopped:{rid}",),
                ).fetchone()
                if not prior_event or prior_event["evidence_ref"] != evidence:
                    raise IdempotencyConflict("a stopped canary run cannot change its stop evidence")
                con.execute(
                    "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('external_writers_enabled','0')"
                )
                return
            con.execute(
                """UPDATE canary_runs SET state='STOPPED',stopped_at_utc=?,stop_reason=?
                   WHERE run_id=?""",
                (now, why, rid),
            )
            con.execute(
                "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('external_writers_enabled','0')"
            )
            con.execute(
                """UPDATE connector_writer_leases
                   SET run_id='',owner_id='',lease_until_utc='',fence_token=fence_token+1,
                       updated_at_utc=? WHERE connector=? AND run_id=?""",
                (now, self.connector, rid),
            )
            self.store._append_event_tx(
                con,
                event_type="canary_run_stopped",
                aggregate_type="canary_run",
                aggregate_id=rid,
                producer="canary_control",
                idempotency_key=f"canary-run-stopped:{rid}",
                payload={"reason": why, "external_writers_enabled": False},
                evidence_ref=evidence,
                actor=actor,
            )

    def _run_tx(self, con: Any, run_id: str) -> Any:
        run = con.execute("SELECT * FROM canary_runs WHERE run_id=?", (run_id,)).fetchone()
        if not run or run["connector"] != self.connector:
            raise KeyError("canary run does not exist for this connector")
        return run

    def _active_run_tx(self, con: Any, run_id: str) -> Any:
        run = self._run_tx(con, run_id)
        if run["state"] != "ACTIVE":
            raise CanaryControlError("canary run is not active")
        return run

    @staticmethod
    def _latest_approval_tx(con: Any, run_id: str) -> Any | None:
        return con.execute(
            "SELECT * FROM canary_approvals WHERE run_id=? ORDER BY approval_sequence DESC LIMIT 1",
            (run_id,),
        ).fetchone()

    @staticmethod
    def _assert_operation_pair_tx(
        con: Any,
        *,
        lead_operation_id: str,
        activity_operation_id: str,
        opportunity_id: str,
        interaction_id: str,
    ) -> None:
        lead = con.execute("SELECT * FROM crm_outbox WHERE operation_id=?", (lead_operation_id,)).fetchone()
        activity = con.execute("SELECT * FROM crm_outbox WHERE operation_id=?", (activity_operation_id,)).fetchone()
        if (
            not lead or lead["operation_type"] != LEAD_CREATE
            or lead["lf_entity_type"] != "opportunity" or lead["lf_entity_id"] != opportunity_id
            or not activity or activity["operation_type"] != ACTIVITY_CREATE
            or activity["lf_entity_type"] != "interaction" or activity["lf_entity_id"] != interaction_id
            or activity["dependency_operation_id"] != lead_operation_id
        ):
            raise CanaryScopeMismatch("handoff must contain one exact Lead+Activity operation pair")


__all__ = [
    "ACTIVITY_CREATE",
    "BITRIX_CANARY_CONNECTOR",
    "CanaryApprovalRequired",
    "CanaryCapacityExceeded",
    "CanaryControl",
    "CanaryControlError",
    "CanaryLeaseUnavailable",
    "CanaryScopeMismatch",
    "CanaryStaleLease",
    "ConnectorWriterLease",
    "CanaryDispatchPermit",
    "LEAD_CREATE",
    "canonical_campaign_id",
    "canonical_mailbox",
    "canonical_outbound_thread",
    "canonical_thread_identity",
]
