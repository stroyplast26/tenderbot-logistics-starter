"""Offline normalized commercial spine for Lead Factory stage.

The module deliberately has no transport dependencies.  Source normalization,
opportunity state changes, and CRM outcome intake are committed through one
SQLite transaction each.  Raw source/CRM payloads are hashed but never copied
to audit events or exception messages.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Callable, Mapping

from .ids import (
    address_hash,
    new_lf_id,
    normalize_domain,
    normalize_email,
    normalize_inn,
    normalize_phone_ru,
    payload_hash,
    sha256_text,
    utc_now,
)
from .store import FactoryStore


class CommercialSpineError(RuntimeError):
    """Base error whose text is safe for an operational log."""


class CommercialSpineValidationError(CommercialSpineError):
    """A required normalized fact is missing or malformed."""


class CommercialSpineConflict(CommercialSpineError):
    """Two commands claim the same immutable identity with different facts."""


class InvalidOpportunityTransition(CommercialSpineError):
    """The requested opportunity transition is not permitted."""


class OpportunityState(str, Enum):
    INITIAL = "__INITIAL__"
    DISCOVERED = "DISCOVERED"
    SCREENED = "SCREENED"
    TARGET_ACCOUNT = "TARGET_ACCOUNT"
    SIGNAL_CONFIRMED = "SIGNAL_CONFIRMED"
    CONTACT_ALLOWED = "CONTACT_ALLOWED"
    CONTACTING = "CONTACTING"
    HUMAN_REPLY = "HUMAN_REPLY"
    DIMA_QUALIFICATION = "DIMA_QUALIFICATION"
    READY_PACKAGE = "READY_PACKAGE"
    ESTIMATE_ACCEPTED = "ESTIMATE_ACCEPTED"
    ESTIMATE_DONE = "ESTIMATE_DONE"
    PROPOSAL_SENT = "PROPOSAL_SENT"
    WON = "WON"
    LOST = "LOST"
    NURTURE = "NURTURE"
    SUPPRESSED = "SUPPRESSED"
    ORDERED = "ORDERED"
    PAID = "PAID"
    PRODUCED = "PRODUCED"
    DELIVERED = "DELIVERED"
    CLAIM = "CLAIM"
    REPEAT = "REPEAT"


class CrmOutcomeType(str, Enum):
    SCREENED = "SCREENED"
    TARGET_ACCOUNT = "TARGET_ACCOUNT"
    SIGNAL_CONFIRMED = "SIGNAL_CONFIRMED"
    CONTACT_ALLOWED = "CONTACT_ALLOWED"
    CONTACTING = "CONTACTING"
    HUMAN_REPLY = "HUMAN_REPLY"
    QUALIFIED = "QUALIFIED"
    READY_PACKAGE = "READY_PACKAGE"
    ESTIMATE_ACCEPTED = "ESTIMATE_ACCEPTED"
    ESTIMATE_DONE = "ESTIMATE_DONE"
    PROPOSAL_SENT = "PROPOSAL_SENT"
    WON = "WON"
    LOST = "LOST"
    NURTURE = "NURTURE"
    SUPPRESSED = "SUPPRESSED"
    ORDERED = "ORDERED"
    PAID = "PAID"
    PRODUCED = "PRODUCED"
    DELIVERED = "DELIVERED"
    CLAIM = "CLAIM"
    REPEAT = "REPEAT"


CRM_OUTCOME_TO_STATE: dict[CrmOutcomeType, OpportunityState] = {
    CrmOutcomeType.SCREENED: OpportunityState.SCREENED,
    CrmOutcomeType.TARGET_ACCOUNT: OpportunityState.TARGET_ACCOUNT,
    CrmOutcomeType.SIGNAL_CONFIRMED: OpportunityState.SIGNAL_CONFIRMED,
    CrmOutcomeType.CONTACT_ALLOWED: OpportunityState.CONTACT_ALLOWED,
    CrmOutcomeType.CONTACTING: OpportunityState.CONTACTING,
    CrmOutcomeType.HUMAN_REPLY: OpportunityState.HUMAN_REPLY,
    CrmOutcomeType.QUALIFIED: OpportunityState.DIMA_QUALIFICATION,
    CrmOutcomeType.READY_PACKAGE: OpportunityState.READY_PACKAGE,
    CrmOutcomeType.ESTIMATE_ACCEPTED: OpportunityState.ESTIMATE_ACCEPTED,
    CrmOutcomeType.ESTIMATE_DONE: OpportunityState.ESTIMATE_DONE,
    CrmOutcomeType.PROPOSAL_SENT: OpportunityState.PROPOSAL_SENT,
    CrmOutcomeType.WON: OpportunityState.WON,
    CrmOutcomeType.LOST: OpportunityState.LOST,
    CrmOutcomeType.NURTURE: OpportunityState.NURTURE,
    CrmOutcomeType.SUPPRESSED: OpportunityState.SUPPRESSED,
    CrmOutcomeType.ORDERED: OpportunityState.ORDERED,
    CrmOutcomeType.PAID: OpportunityState.PAID,
    CrmOutcomeType.PRODUCED: OpportunityState.PRODUCED,
    CrmOutcomeType.DELIVERED: OpportunityState.DELIVERED,
    CrmOutcomeType.CLAIM: OpportunityState.CLAIM,
    CrmOutcomeType.REPEAT: OpportunityState.REPEAT,
}


_ALLOWED_TRANSITIONS: dict[OpportunityState, frozenset[OpportunityState]] = {
    OpportunityState.INITIAL: frozenset((OpportunityState.DISCOVERED,)),
    OpportunityState.DISCOVERED: frozenset(
        (OpportunityState.SCREENED, OpportunityState.NURTURE, OpportunityState.SUPPRESSED)
    ),
    OpportunityState.SCREENED: frozenset(
        (OpportunityState.TARGET_ACCOUNT, OpportunityState.NURTURE, OpportunityState.SUPPRESSED)
    ),
    OpportunityState.TARGET_ACCOUNT: frozenset(
        (OpportunityState.SIGNAL_CONFIRMED, OpportunityState.NURTURE, OpportunityState.SUPPRESSED)
    ),
    OpportunityState.SIGNAL_CONFIRMED: frozenset(
        (
            OpportunityState.CONTACT_ALLOWED,
            OpportunityState.DIMA_QUALIFICATION,
            OpportunityState.NURTURE,
            OpportunityState.SUPPRESSED,
        )
    ),
    OpportunityState.CONTACT_ALLOWED: frozenset(
        (
            OpportunityState.CONTACTING,
            OpportunityState.HUMAN_REPLY,
            OpportunityState.NURTURE,
            OpportunityState.SUPPRESSED,
        )
    ),
    OpportunityState.CONTACTING: frozenset(
        (
            OpportunityState.HUMAN_REPLY,
            OpportunityState.DIMA_QUALIFICATION,
            OpportunityState.NURTURE,
            OpportunityState.SUPPRESSED,
        )
    ),
    OpportunityState.HUMAN_REPLY: frozenset(
        (
            OpportunityState.DIMA_QUALIFICATION,
            OpportunityState.NURTURE,
            OpportunityState.SUPPRESSED,
        )
    ),
    OpportunityState.DIMA_QUALIFICATION: frozenset(
        (
            OpportunityState.READY_PACKAGE,
            OpportunityState.LOST,
            OpportunityState.NURTURE,
            OpportunityState.SUPPRESSED,
        )
    ),
    OpportunityState.READY_PACKAGE: frozenset(
        (
            OpportunityState.ESTIMATE_ACCEPTED,
            OpportunityState.DIMA_QUALIFICATION,
            OpportunityState.LOST,
            OpportunityState.NURTURE,
        )
    ),
    OpportunityState.ESTIMATE_ACCEPTED: frozenset(
        (
            OpportunityState.ESTIMATE_DONE,
            OpportunityState.READY_PACKAGE,
            OpportunityState.LOST,
        )
    ),
    OpportunityState.ESTIMATE_DONE: frozenset(
        (
            OpportunityState.PROPOSAL_SENT,
            OpportunityState.READY_PACKAGE,
            OpportunityState.LOST,
        )
    ),
    OpportunityState.PROPOSAL_SENT: frozenset(
        (OpportunityState.WON, OpportunityState.LOST, OpportunityState.NURTURE)
    ),
    OpportunityState.WON: frozenset((OpportunityState.ORDERED,)),
    OpportunityState.ORDERED: frozenset(
        (OpportunityState.PAID, OpportunityState.PRODUCED, OpportunityState.DELIVERED)
    ),
    OpportunityState.PAID: frozenset((OpportunityState.PRODUCED, OpportunityState.DELIVERED)),
    OpportunityState.PRODUCED: frozenset((OpportunityState.DELIVERED, OpportunityState.CLAIM)),
    OpportunityState.DELIVERED: frozenset((OpportunityState.CLAIM, OpportunityState.REPEAT)),
    OpportunityState.NURTURE: frozenset(
        (OpportunityState.SIGNAL_CONFIRMED, OpportunityState.DIMA_QUALIFICATION)
    ),
    OpportunityState.LOST: frozenset((OpportunityState.NURTURE, OpportunityState.REPEAT)),
    OpportunityState.SUPPRESSED: frozenset(),
    OpportunityState.CLAIM: frozenset((OpportunityState.REPEAT,)),
    OpportunityState.REPEAT: frozenset((OpportunityState.DISCOVERED,)),
}

_REASON_REQUIRED = frozenset(
    (
        OpportunityState.LOST,
        OpportunityState.NURTURE,
        OpportunityState.SUPPRESSED,
        OpportunityState.CLAIM,
    )
)

_EVIDENCE_REQUIRED = frozenset(
    (
        OpportunityState.SIGNAL_CONFIRMED,
        OpportunityState.HUMAN_REPLY,
        OpportunityState.READY_PACKAGE,
        OpportunityState.PROPOSAL_SENT,
        OpportunityState.WON,
        OpportunityState.ORDERED,
        OpportunityState.DELIVERED,
        OpportunityState.CLAIM,
    )
)


@dataclass(frozen=True, slots=True)
class NormalizedOpportunityResult:
    created: bool
    source_record_id: str
    lf_company_id: str
    lf_contact_id: str
    lf_project_id: str
    lf_opportunity_id: str


@dataclass(frozen=True, slots=True)
class OpportunityTransitionResult:
    created: bool
    transition_id: str
    lf_opportunity_id: str
    from_state: str
    to_state: str


@dataclass(frozen=True, slots=True)
class CrmOutcomeResult:
    created: bool
    inbox_event_id: str
    state: str
    lf_opportunity_id: str = ""
    transition_id: str = ""
    error_code: str = ""


def _required(value: object, message: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise CommercialSpineValidationError(message)
    return result


def _timestamp(value: object, message: str) -> str:
    raw = _required(value, message)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise CommercialSpineValidationError(message) from None
    if parsed.tzinfo is None:
        raise CommercialSpineValidationError(message)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _payload_digest(payload: Mapping[str, Any]) -> str:
    if not isinstance(payload, Mapping):
        raise CommercialSpineValidationError("payload must be a mapping")
    try:
        rendered = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        rendered.encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise CommercialSpineValidationError("payload is not canonical JSON") from None
    return sha256_text(rendered)


def _coerce_state(value: OpportunityState | str) -> OpportunityState:
    try:
        return value if isinstance(value, OpportunityState) else OpportunityState(str(value))
    except ValueError:
        raise CommercialSpineValidationError("unknown opportunity state") from None


def _coerce_outcome(value: CrmOutcomeType | str) -> CrmOutcomeType:
    try:
        return value if isinstance(value, CrmOutcomeType) else CrmOutcomeType(str(value))
    except ValueError:
        raise CommercialSpineValidationError("unknown CRM outcome type") from None


def _event_payload_for_transition(
    *, transition_id: str, opportunity_id: str, from_state: str, to_state: str,
    reason: str, actor: str,
) -> dict[str, str]:
    return {
        "transition_id": transition_id,
        "lf_opportunity_id": opportunity_id,
        "from_state": from_state,
        "to_state": to_state,
        "reason_hash": payload_hash({"reason": reason}),
        "actor_hash": payload_hash({"actor": actor}),
    }


class OpportunityLifecycle:
    """Typed, append-only state changes for one normalized opportunity."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_transition_hook: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.after_transition_hook = after_transition_hook

    @staticmethod
    def _command_hash(
        *, opportunity_id: str, to_state: OpportunityState, reason: str,
        evidence_ref: str, actor: str,
    ) -> str:
        return payload_hash(
            {
                "lf_opportunity_id": opportunity_id,
                "to_state": to_state.value,
                "reason": reason,
                "evidence_ref": evidence_ref,
                "actor": actor,
            }
        )

    @staticmethod
    def _validate_transition(
        from_state: OpportunityState,
        to_state: OpportunityState,
        *,
        reason: str,
        evidence_ref: str,
    ) -> None:
        if to_state not in _ALLOWED_TRANSITIONS.get(from_state, frozenset()):
            raise InvalidOpportunityTransition("opportunity transition is not allowed")
        if to_state in _REASON_REQUIRED and not reason:
            raise CommercialSpineValidationError("transition reason is required")
        if to_state in _EVIDENCE_REQUIRED and not evidence_ref:
            raise CommercialSpineValidationError("transition evidence is required")

    def _transition_tx(
        self,
        con: Any,
        *,
        lf_opportunity_id: str,
        to_state: OpportunityState | str,
        reason: str = "",
        evidence_ref: str = "",
        actor: str,
        idempotency_key: str,
        occurred_at_utc: str = "",
    ) -> OpportunityTransitionResult:
        opportunity_id = _required(lf_opportunity_id, "opportunity id is required")
        target = _coerce_state(to_state)
        if target is OpportunityState.INITIAL:
            raise CommercialSpineValidationError("initial is not a target state")
        actor_id = _required(actor, "transition actor is required")
        idem = _required(idempotency_key, "transition idempotency key is required")
        reason_code = str(reason or "").strip()
        evidence = str(evidence_ref or "").strip()
        command_hash = self._command_hash(
            opportunity_id=opportunity_id,
            to_state=target,
            reason=reason_code,
            evidence_ref=evidence,
            actor=actor_id,
        )

        existing = con.execute(
            "SELECT * FROM opportunity_transitions WHERE idempotency_key=?", (idem,)
        ).fetchone()
        if existing:
            if str(existing["payload_hash"]) != command_hash:
                raise CommercialSpineConflict("transition idempotency conflict")
            return OpportunityTransitionResult(
                False,
                str(existing["transition_id"]),
                str(existing["lf_opportunity_id"]),
                str(existing["from_state"]),
                str(existing["to_state"]),
            )

        opportunity = con.execute(
            "SELECT status FROM opportunities WHERE lf_opportunity_id=?", (opportunity_id,)
        ).fetchone()
        if not opportunity:
            raise CommercialSpineValidationError("opportunity does not exist")
        current = _coerce_state(str(opportunity["status"]))
        self._validate_transition(current, target, reason=reason_code, evidence_ref=evidence)

        occurred = _timestamp(occurred_at_utc, "transition timestamp is invalid") if occurred_at_utc else utc_now()
        created = utc_now()
        transition_id = new_lf_id("transition")
        con.execute(
            """INSERT INTO opportunity_transitions(
                transition_id,lf_opportunity_id,from_state,to_state,reason,evidence_ref,
                actor,idempotency_key,payload_hash,occurred_at_utc,created_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                transition_id,
                opportunity_id,
                current.value,
                target.value,
                reason_code,
                evidence,
                actor_id,
                idem,
                command_hash,
                occurred,
                created,
            ),
        )
        if self.after_transition_hook:
            self.after_transition_hook()
        changed = con.execute(
            """UPDATE opportunities SET status=?,updated_at_utc=?
               WHERE lf_opportunity_id=? AND status=?""",
            (target.value, created, opportunity_id, current.value),
        )
        if changed.rowcount != 1:
            raise CommercialSpineConflict("opportunity state changed concurrently")
        self.store._append_event_tx(
            con,
            event_type="opportunity_transitioned",
            aggregate_type="opportunity",
            aggregate_id=opportunity_id,
            producer="commercial_spine",
            idempotency_key=f"transition:{transition_id}",
            payload=_event_payload_for_transition(
                transition_id=transition_id,
                opportunity_id=opportunity_id,
                from_state=current.value,
                to_state=target.value,
                reason=reason_code,
                actor=actor_id,
            ),
            evidence_ref=evidence,
            actor="commercial_spine",
            occurred_at_utc=occurred,
            schema_version=14,
        )
        return OpportunityTransitionResult(
            True, transition_id, opportunity_id, current.value, target.value
        )

    def transition(
        self,
        *,
        lf_opportunity_id: str,
        to_state: OpportunityState | str,
        reason: str = "",
        evidence_ref: str = "",
        actor: str,
        idempotency_key: str,
        occurred_at_utc: str = "",
    ) -> OpportunityTransitionResult:
        with self.store.transaction(min_schema_version=14) as con:
            return self._transition_tx(
                con,
                lf_opportunity_id=lf_opportunity_id,
                to_state=to_state,
                reason=reason,
                evidence_ref=evidence_ref,
                actor=actor,
                idempotency_key=idempotency_key,
                occurred_at_utc=occurred_at_utc,
            )


class NormalizedOpportunityIntake:
    """Normalize one source record into Company/Contact/Project/Opportunity."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_source_hook: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.after_source_hook = after_source_hook

    @staticmethod
    def _load_existing(con: Any, source_record_id: str) -> NormalizedOpportunityResult:
        rows = con.execute(
            """SELECT o.lf_opportunity_id,o.lf_company_id,o.lf_contact_id,o.lf_project_id
               FROM opportunities o WHERE o.source_event_id=?""",
            (source_record_id,),
        ).fetchall()
        if len(rows) != 1:
            raise CommercialSpineConflict("normalized source record is incomplete")
        row = rows[0]
        if not row["lf_contact_id"] or not row["lf_project_id"]:
            raise CommercialSpineConflict("normalized source links are incomplete")
        return NormalizedOpportunityResult(
            False,
            source_record_id,
            str(row["lf_company_id"]),
            str(row["lf_contact_id"]),
            str(row["lf_project_id"]),
            str(row["lf_opportunity_id"]),
        )

    def ingest(
        self,
        *,
        producer: str,
        external_key: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
        evidence_ref: str,
        observed_at_utc: str,
        company_name: str = "",
        company_inn: str = "",
        company_domain: str = "",
        contact_name: str = "",
        contact_email: str,
        contact_phone: str = "",
        contact_role: str = "",
        project_title: str,
        project_region: str = "",
        product_key: str = "",
        _transaction: Any | None = None,
    ) -> NormalizedOpportunityResult:
        source = _required(producer, "source producer is required")
        source_key = _required(external_key, "source external key is required")
        idem = _required(idempotency_key, "source idempotency key is required")
        evidence = _required(evidence_ref, "source evidence is required")
        observed = _timestamp(observed_at_utc, "source observation timestamp is invalid")
        raw_digest = _payload_digest(payload)
        inn = normalize_inn(company_inn)
        domain = normalize_domain(company_domain)
        if inn and len(inn) not in {10, 12}:
            raise CommercialSpineValidationError("company INN is invalid")
        if not inn and not domain:
            raise CommercialSpineValidationError("company identity is required")
        email = normalize_email(contact_email)
        if not email or "@" not in email:
            raise CommercialSpineValidationError("contact email is required")
        title = _required(project_title, "project title is required")
        normalized_company_name = str(company_name or "").strip()
        normalized_contact_name = str(contact_name or "").strip()
        normalized_contact_role = str(contact_role or "").strip()
        normalized_project_region = str(project_region or "").strip()
        normalized_product_key = str(product_key or "").strip()
        raw_phone = str(contact_phone or "").strip()
        normalized_phone = normalize_phone_ru(raw_phone)
        if raw_phone and not normalized_phone:
            raise CommercialSpineValidationError("contact phone is invalid")
        phone_digits = normalized_phone.removeprefix("+")
        command_digest = payload_hash(
            {
                "source_payload_hash": raw_digest,
                "producer": source,
                "external_key": source_key,
                "evidence_ref": evidence,
                "observed_at_utc": observed,
                "company_name": normalized_company_name,
                "company_inn": inn,
                "company_domain": domain,
                "contact_name": normalized_contact_name,
                "contact_email": email,
                "contact_phone_digits": phone_digits,
                "contact_role": normalized_contact_role,
                "project_title": title,
                "project_region": normalized_project_region,
                "product_key": normalized_product_key,
            }
        )

        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=14)
        )
        with transaction as con:
            if _transaction is not None and self.store._probe_schema(con) < 14:
                raise CommercialSpineValidationError(
                    "normalized intake transaction requires schema 14"
                )
            existing = con.execute(
                "SELECT * FROM source_records WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if (
                    str(existing["payload_hash"]) != command_digest
                    or str(existing["producer"]) != source
                    or str(existing["external_key"]) != source_key
                    or str(existing["evidence_ref"]) != evidence
                ):
                    raise CommercialSpineConflict("source idempotency conflict")
                return self._load_existing(con, str(existing["source_record_id"]))

            reused_source = con.execute(
                "SELECT 1 FROM source_records WHERE producer=? AND external_key=? LIMIT 1",
                (source, source_key),
            ).fetchone()
            graph_collision = con.execute(
                """SELECT 1 FROM projects WHERE source=? AND external_key=?
                   UNION ALL
                   SELECT 1 FROM opportunities WHERE source=? AND external_key=?
                   LIMIT 1""",
                (source, source_key, source, source_key),
            ).fetchone()
            if reused_source or graph_collision:
                raise CommercialSpineConflict("source external identity conflict")

            source_record_id = new_lf_id("source_record")
            now = utc_now()
            con.execute(
                """INSERT INTO source_records(
                    source_record_id,producer,external_key,idempotency_key,payload_hash,
                    evidence_ref,observed_at_utc,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    source_record_id,
                    source,
                    source_key,
                    idem,
                    command_digest,
                    evidence,
                    observed,
                    now,
                ),
            )
            if self.after_source_hook:
                self.after_source_hook()

            company = con.execute(
                "SELECT * FROM companies WHERE inn=?", (inn,)
            ).fetchone() if inn else None
            if company:
                company_id = str(company["lf_company_id"])
                if str(company["identity_state"]) != "EXACT":
                    raise CommercialSpineConflict("exact company identity is inconsistent")
            else:
                company_id = new_lf_id("company")
                con.execute(
                    """INSERT INTO companies(
                        lf_company_id,name,inn,domain,identity_state,source_event_id,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        company_id,
                        normalized_company_name,
                        inn,
                        domain,
                        "EXACT" if inn else "PROBABLE",
                        source_record_id,
                        now,
                    ),
                )

            email_hash = address_hash(email)
            contact = con.execute(
                """SELECT * FROM contacts
                   WHERE lf_company_id=? AND email_hash=?""",
                (company_id, email_hash),
            ).fetchone()
            if contact:
                contact_id = str(contact["lf_contact_id"])
            else:
                contact_id = new_lf_id("contact")
                phone_hash = payload_hash({"phone": phone_digits}) if phone_digits else ""
                con.execute(
                    """INSERT INTO contacts(
                        lf_contact_id,lf_company_id,name,email,email_hash,phone_hash,role,
                        source_event_id,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        contact_id,
                        company_id,
                        normalized_contact_name,
                        email,
                        email_hash,
                        phone_hash,
                        normalized_contact_role,
                        source_record_id,
                        now,
                    ),
                )

            project_id = new_lf_id("project")
            con.execute(
                """INSERT INTO projects(
                    lf_project_id,lf_company_id,source,external_key,title,region,evidence_ref,
                    source_event_id,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    project_id,
                    company_id,
                    source,
                    source_key,
                    title,
                    normalized_project_region,
                    evidence,
                    source_record_id,
                    now,
                ),
            )
            opportunity_id = new_lf_id("opportunity")
            con.execute(
                """INSERT INTO opportunities(
                    lf_opportunity_id,lf_company_id,lf_contact_id,lf_project_id,source,
                    external_key,status,product_key,source_event_id,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    opportunity_id,
                    company_id,
                    contact_id,
                    project_id,
                    source,
                    source_key,
                    OpportunityState.DISCOVERED.value,
                    normalized_product_key,
                    source_record_id,
                    now,
                    now,
                ),
            )

            linked = con.execute(
                """SELECT 1 FROM opportunities o
                   JOIN contacts c ON c.lf_contact_id=o.lf_contact_id
                   JOIN projects p ON p.lf_project_id=o.lf_project_id
                   WHERE o.lf_opportunity_id=?
                     AND o.lf_company_id=c.lf_company_id
                     AND o.lf_company_id=p.lf_company_id""",
                (opportunity_id,),
            ).fetchone()
            if not linked:
                raise CommercialSpineConflict("normalized graph crossed company boundaries")

            transition_id = new_lf_id("transition")
            transition_key = f"source:{source_record_id}:discovered"
            transition_hash = OpportunityLifecycle._command_hash(
                opportunity_id=opportunity_id,
                to_state=OpportunityState.DISCOVERED,
                reason="SOURCE_NORMALIZED",
                evidence_ref=evidence,
                actor="source_intake",
            )
            con.execute(
                """INSERT INTO opportunity_transitions(
                    transition_id,lf_opportunity_id,from_state,to_state,reason,evidence_ref,
                    actor,idempotency_key,payload_hash,occurred_at_utc,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    transition_id,
                    opportunity_id,
                    OpportunityState.INITIAL.value,
                    OpportunityState.DISCOVERED.value,
                    "SOURCE_NORMALIZED",
                    evidence,
                    "source_intake",
                    transition_key,
                    transition_hash,
                    observed,
                    now,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="normalized_opportunity_created",
                aggregate_type="opportunity",
                aggregate_id=opportunity_id,
                producer="commercial_spine",
                idempotency_key=f"normalized:{source_record_id}",
                payload={
                    "source_record_id": source_record_id,
                    "lf_company_id": company_id,
                    "lf_contact_id": contact_id,
                    "lf_project_id": project_id,
                    "lf_opportunity_id": opportunity_id,
                    "company_identity_state": "EXACT" if inn else "PROBABLE",
                    "source_payload_hash": raw_digest,
                },
                evidence_ref=evidence,
                actor="commercial_spine",
                occurred_at_utc=observed,
                schema_version=14,
            )
            return NormalizedOpportunityResult(
                True,
                source_record_id,
                company_id,
                contact_id,
                project_id,
                opportunity_id,
            )


class OfflineCrmOutcomeIntake:
    """Persist and apply versioned CRM outcomes without any CRM transport."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_inbox_hook: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.after_inbox_hook = after_inbox_hook
        self.lifecycle = OpportunityLifecycle(store)

    @staticmethod
    def _default_dedupe_key(
        remote_entity_type: str,
        remote_entity_id: str,
        remote_version: int,
        event_type: str,
        digest: str,
    ) -> str:
        return "crm:" + payload_hash(
            {
                "remote_entity_type": remote_entity_type,
                "remote_entity_id": remote_entity_id,
                "remote_version": remote_version,
                "event_type": event_type,
                "payload_hash": digest,
            }
        )

    def _audit_tx(
        self,
        con: Any,
        *,
        inbox_event_id: str,
        state: str,
        opportunity_id: str,
        error_code: str,
        evidence_ref: str,
        occurred_at_utc: str,
    ) -> None:
        self.store._append_event_tx(
            con,
            event_type="crm_outcome_processed" if state == "PROCESSED" else "crm_outcome_reviewed",
            aggregate_type="opportunity" if opportunity_id else "crm_inbox",
            aggregate_id=opportunity_id or inbox_event_id,
            producer="commercial_spine",
            idempotency_key=f"crm-outcome:{inbox_event_id}",
            payload={
                "inbox_event_id": inbox_event_id,
                "lf_opportunity_id": opportunity_id,
                "state": state,
                "error_code": error_code,
            },
            evidence_ref=evidence_ref,
            actor="commercial_spine",
            occurred_at_utc=occurred_at_utc,
            schema_version=14,
        )

    def _finish_without_transition(
        self,
        con: Any,
        *,
        inbox_event_id: str,
        state: str,
        opportunity_id: str,
        error_code: str,
        evidence_ref: str,
        received_at_utc: str,
    ) -> CrmOutcomeResult:
        processed = utc_now()
        con.execute(
            """UPDATE crm_inbox_events
               SET state=?,processed_at_utc=?,lf_opportunity_id=?,error_code=?
               WHERE inbox_event_id=? AND state='PENDING'""",
            (state, processed, opportunity_id or None, error_code, inbox_event_id),
        )
        self._audit_tx(
            con,
            inbox_event_id=inbox_event_id,
            state=state,
            opportunity_id=opportunity_id,
            error_code=error_code,
            evidence_ref=evidence_ref,
            occurred_at_utc=received_at_utc,
        )
        return CrmOutcomeResult(True, inbox_event_id, state, opportunity_id, "", error_code)

    def ingest(
        self,
        *,
        remote_entity_type: str,
        remote_entity_id: str,
        remote_version: int,
        event_type: CrmOutcomeType | str,
        payload: Mapping[str, Any],
        evidence_ref: str,
        received_at_utc: str,
        reason: str = "",
        actor: str = "crm_sync",
        dedupe_key: str = "",
    ) -> CrmOutcomeResult:
        remote_type = _required(remote_entity_type, "remote entity type is required")
        remote_id = _required(remote_entity_id, "remote entity id is required")
        if isinstance(remote_version, bool) or not isinstance(remote_version, int) or remote_version < 0:
            raise CommercialSpineValidationError("remote version is invalid")
        received = _timestamp(received_at_utc, "CRM received timestamp is invalid")
        evidence = _required(evidence_ref, "CRM outcome evidence is required")
        actor_id = _required(actor, "CRM outcome actor is required")
        outcome = _coerce_outcome(event_type)
        raw_digest = _payload_digest(payload)
        envelope_hash = payload_hash(
            {
                "event_type": outcome.value,
                "payload_hash": raw_digest,
                "reason": str(reason or "").strip(),
            }
        )
        idem = str(dedupe_key or "").strip() or self._default_dedupe_key(
            remote_type, remote_id, remote_version, outcome.value, envelope_hash
        )

        with self.store.transaction(min_schema_version=14) as con:
            prior = con.execute(
                "SELECT * FROM crm_inbox_events WHERE dedupe_key=?", (idem,)
            ).fetchone()
            if prior:
                if (
                    str(prior["payload_hash"]) != envelope_hash
                    or str(prior["remote_entity_type"]) != remote_type
                    or str(prior["remote_entity_id"]) != remote_id
                    or int(prior["remote_version"]) != remote_version
                    or str(prior["event_type"]) != outcome.value
                ):
                    raise CommercialSpineConflict("CRM inbox idempotency conflict")
                transition = con.execute(
                    """SELECT transition_id FROM opportunity_transitions
                       WHERE idempotency_key=?""",
                    (f"crm-inbox:{prior['inbox_event_id']}",),
                ).fetchone()
                return CrmOutcomeResult(
                    False,
                    str(prior["inbox_event_id"]),
                    str(prior["state"]),
                    str(prior["lf_opportunity_id"] or ""),
                    str(transition["transition_id"]) if transition else "",
                    str(prior["error_code"] or ""),
                )

            mapping = con.execute(
                """SELECT lf_entity_type,lf_entity_id FROM crm_mappings
                   WHERE remote_entity_type=? AND remote_entity_id=? AND state='ACTIVE'""",
                (remote_type, remote_id),
            ).fetchone()
            opportunity_id = (
                str(mapping["lf_entity_id"])
                if mapping and str(mapping["lf_entity_type"]) == "opportunity"
                else ""
            )
            mapping_error = "ACTIVE_OPPORTUNITY_MAPPING_REQUIRED"
            if opportunity_id and remote_type == "lead":
                sent_lead = con.execute(
                    """SELECT 1 FROM crm_outbox
                       WHERE operation_type='BITRIX_LEAD_CREATE'
                         AND lf_entity_type='opportunity' AND lf_entity_id=?
                         AND remote_entity_id=? AND state='SENT'""",
                    (opportunity_id, remote_id),
                ).fetchone()
                if not sent_lead:
                    opportunity_id = ""
                    mapping_error = "SENT_LEAD_MAPPING_REQUIRED"
            inbox_event_id = new_lf_id("crm_inbox_event")
            con.execute(
                """INSERT INTO crm_inbox_events(
                    inbox_event_id,remote_entity_type,remote_entity_id,remote_version,
                    dedupe_key,payload_hash,event_type,state,evidence_ref,received_at_utc,
                    processed_at_utc,lf_opportunity_id,error_code,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    inbox_event_id,
                    remote_type,
                    remote_id,
                    remote_version,
                    idem,
                    envelope_hash,
                    outcome.value,
                    "PENDING",
                    evidence,
                    received,
                    "",
                    opportunity_id or None,
                    "",
                    utc_now(),
                ),
            )
            if self.after_inbox_hook:
                self.after_inbox_hook()

            if not opportunity_id:
                return self._finish_without_transition(
                    con,
                    inbox_event_id=inbox_event_id,
                    state="REVIEW",
                    opportunity_id="",
                    error_code=mapping_error,
                    evidence_ref=evidence,
                    received_at_utc=received,
                )
            if not con.execute(
                "SELECT 1 FROM opportunities WHERE lf_opportunity_id=?", (opportunity_id,)
            ).fetchone():
                return self._finish_without_transition(
                    con,
                    inbox_event_id=inbox_event_id,
                    state="REVIEW",
                    opportunity_id="",
                    error_code="MAPPED_OPPORTUNITY_MISSING",
                    evidence_ref=evidence,
                    received_at_utc=received,
                )

            sync = con.execute(
                """SELECT * FROM crm_sync_state
                   WHERE remote_entity_type=? AND remote_entity_id=?""",
                (remote_type, remote_id),
            ).fetchone()
            if sync and str(sync["lf_opportunity_id"]) != opportunity_id:
                return self._finish_without_transition(
                    con,
                    inbox_event_id=inbox_event_id,
                    state="REVIEW",
                    opportunity_id=opportunity_id,
                    error_code="CRM_SYNC_MAPPING_CONFLICT",
                    evidence_ref=evidence,
                    received_at_utc=received,
                )
            if sync and remote_version < int(sync["last_remote_version"]):
                return self._finish_without_transition(
                    con,
                    inbox_event_id=inbox_event_id,
                    state="STALE",
                    opportunity_id=opportunity_id,
                    error_code="REMOTE_VERSION_STALE",
                    evidence_ref=evidence,
                    received_at_utc=received,
                )
            if sync and remote_version == int(sync["last_remote_version"]):
                if envelope_hash != str(sync["last_payload_hash"]):
                    return self._finish_without_transition(
                        con,
                        inbox_event_id=inbox_event_id,
                        state="REVIEW",
                        opportunity_id=opportunity_id,
                        error_code="REMOTE_VERSION_PAYLOAD_CONFLICT",
                        evidence_ref=evidence,
                        received_at_utc=received,
                    )
                return self._finish_without_transition(
                    con,
                    inbox_event_id=inbox_event_id,
                    state="DUPLICATE",
                    opportunity_id=opportunity_id,
                    error_code="REMOTE_VERSION_DUPLICATE",
                    evidence_ref=evidence,
                    received_at_utc=received,
                )

            # Advance the remote watermark before applying the business state.
            # A newer but invalid/reviewed CRM event must still fence older
            # versions from being applied later out of order.
            watermark_now = utc_now()
            if sync:
                con.execute(
                    """UPDATE crm_sync_state SET
                        last_remote_version=?,last_payload_hash=?,lf_opportunity_id=?,
                        last_event_id=?,updated_at_utc=?
                       WHERE remote_entity_type=? AND remote_entity_id=?""",
                    (
                        remote_version,
                        envelope_hash,
                        opportunity_id,
                        inbox_event_id,
                        watermark_now,
                        remote_type,
                        remote_id,
                    ),
                )
            else:
                con.execute(
                    """INSERT INTO crm_sync_state(
                        remote_entity_type,remote_entity_id,last_remote_version,last_payload_hash,
                        lf_opportunity_id,last_event_id,updated_at_utc
                    ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        remote_type,
                        remote_id,
                        remote_version,
                        envelope_hash,
                        opportunity_id,
                        inbox_event_id,
                        watermark_now,
                    ),
                )

            target = CRM_OUTCOME_TO_STATE[outcome]
            try:
                transition = self.lifecycle._transition_tx(
                    con,
                    lf_opportunity_id=opportunity_id,
                    to_state=target,
                    reason=str(reason or "").strip(),
                    evidence_ref=evidence,
                    actor=actor_id,
                    idempotency_key=f"crm-inbox:{inbox_event_id}",
                    occurred_at_utc=received,
                )
            except (CommercialSpineValidationError, InvalidOpportunityTransition):
                return self._finish_without_transition(
                    con,
                    inbox_event_id=inbox_event_id,
                    state="REVIEW",
                    opportunity_id=opportunity_id,
                    error_code="CRM_OUTCOME_TRANSITION_REVIEW",
                    evidence_ref=evidence,
                    received_at_utc=received,
                )

            now = utc_now()
            if sync:
                con.execute(
                    """UPDATE crm_sync_state SET
                        last_remote_version=?,last_payload_hash=?,lf_opportunity_id=?,
                        last_event_id=?,updated_at_utc=?
                       WHERE remote_entity_type=? AND remote_entity_id=?""",
                    (
                        remote_version,
                        envelope_hash,
                        opportunity_id,
                        inbox_event_id,
                        now,
                        remote_type,
                        remote_id,
                    ),
                )
            else:
                con.execute(
                    """UPDATE crm_sync_state SET updated_at_utc=?
                       WHERE remote_entity_type=? AND remote_entity_id=?""",
                    (now, remote_type, remote_id),
                )
            con.execute(
                """UPDATE crm_inbox_events SET state='PROCESSED',processed_at_utc=?,
                   lf_opportunity_id=?,error_code='' WHERE inbox_event_id=? AND state='PENDING'""",
                (now, opportunity_id, inbox_event_id),
            )
            self._audit_tx(
                con,
                inbox_event_id=inbox_event_id,
                state="PROCESSED",
                opportunity_id=opportunity_id,
                error_code="",
                evidence_ref=evidence,
                occurred_at_utc=received,
            )
            return CrmOutcomeResult(
                True,
                inbox_event_id,
                "PROCESSED",
                opportunity_id,
                transition.transition_id,
                "",
            )


def funnel_metrics(store: FactoryStore) -> dict[str, int]:
    """Count distinct opportunities that reached each typed state."""

    counts = {state.value: 0 for state in OpportunityState if state is not OpportunityState.INITIAL}
    with store.transaction(min_schema_version=14) as con:
        rows = con.execute(
            """SELECT to_state,COUNT(DISTINCT lf_opportunity_id) AS opportunity_count
               FROM opportunity_transitions GROUP BY to_state"""
        ).fetchall()
    for row in rows:
        key = str(row["to_state"])
        if key in counts:
            counts[key] = int(row["opportunity_count"])
    return counts


__all__ = [
    "CRM_OUTCOME_TO_STATE",
    "CommercialSpineConflict",
    "CommercialSpineError",
    "CommercialSpineValidationError",
    "CrmOutcomeResult",
    "CrmOutcomeType",
    "InvalidOpportunityTransition",
    "NormalizedOpportunityIntake",
    "NormalizedOpportunityResult",
    "OfflineCrmOutcomeIntake",
    "OpportunityLifecycle",
    "OpportunityState",
    "OpportunityTransitionResult",
    "funnel_metrics",
]
