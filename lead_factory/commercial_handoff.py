"""Atomic offline handoff from a persisted human reply to human/CRM work.

The handoff deliberately has no transport, environment, webhook, or caller
payload boundary.  It reconstructs the complete command from the canonical
Company/Contact/Project/Opportunity graph, immutable source record, and the
exact append-only HUMAN_REPLY transition event,
then commits the Interaction, configured operator task, Lead command, and dependent Activity
command in one SQLite transaction.

The dependent CRM Activity is bound to a dedicated commercial-qualification
task; a source signal is never mislabeled as an email reply.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .crm_identity import (
    CrmActorBinding,
    CrmActorBindingError,
    CrmActorBindingRegistry,
)
from .crm_outbox import CrmActivityOutbox, CrmOutbox
from .ids import (
    address_hash,
    new_lf_id,
    normalize_domain,
    normalize_email,
    normalize_inn,
    payload_hash,
)
from .store import FactoryStore


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAILBOX = re.compile(
    r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class CommercialHandoffError(RuntimeError):
    """Base error with text safe for an operational log."""


class CommercialHandoffInvariantError(CommercialHandoffError):
    """The persisted canonical graph cannot support a safe handoff."""


@dataclass(frozen=True, slots=True)
class CommercialHandoffResult:
    created: bool
    state: str
    lf_opportunity_id: str
    interaction_id: str
    task_id: str
    lead_operation_id: str
    activity_operation_id: str
    due_at_utc: str


@dataclass(frozen=True, slots=True)
class _CanonicalGraph:
    opportunity_id: str
    opportunity_status: str
    opportunity_source: str
    opportunity_external_key: str
    product_key: str
    company_id: str
    company_name: str
    company_inn: str
    company_domain: str
    company_identity_state: str
    contact_id: str
    contact_company_id: str
    contact_name: str
    contact_email: str
    contact_email_hash: str
    contact_role: str
    project_id: str
    project_company_id: str
    project_source: str
    project_external_key: str
    project_title: str
    project_region: str
    project_evidence_ref: str
    project_source_record_id: str
    source_record_id: str
    source_producer: str
    source_external_key: str
    source_payload_hash: str
    source_evidence_ref: str
    source_observed_at_utc: str
    reply_transition_id: str
    reply_event_id: str
    reply_evidence_ref: str
    reply_occurred_at_utc: str


class CommercialOpportunityHandoff:
    """Stage and measure one reply-qualified commercial handoff offline."""

    INTERACTION_CLASSIFICATION = "COMMERCIAL_HANDOFF"
    TASK_KIND = "COMMERCIAL_QUALIFICATION"
    TASK_PRIORITY = "A1"
    TASK_CREATION_SLO_MINUTES = 5
    HUMAN_ACTION_SLO_MINUTES = 30
    STATE = "STAGED"

    _INITIAL_ACTIONABLE_STATES = frozenset({"HUMAN_REPLY"})
    _KNOWN_STATES = frozenset(
        {
            "DISCOVERED",
            "SCREENED",
            "TARGET_ACCOUNT",
            "SIGNAL_CONFIRMED",
            "CONTACT_ALLOWED",
            "CONTACTING",
            "HUMAN_REPLY",
            "DIMA_QUALIFICATION",
            "READY_PACKAGE",
            "ESTIMATE_ACCEPTED",
            "ESTIMATE_DONE",
            "PROPOSAL_SENT",
            "WON",
            "LOST",
            "NURTURE",
            "SUPPRESSED",
            "ORDERED",
            "PAID",
            "PRODUCED",
            "DELIVERED",
            "CLAIM",
            "REPEAT",
        }
    )

    def __init__(
        self,
        store: FactoryStore,
        *,
        assignee: str,
        after_stage_hook: Callable[[], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        actor = str(assignee or "").strip()
        if (
            not actor
            or len(actor) > 160
            or not actor[0].isalnum()
            or any(not (char.isalnum() or char in "._:-") for char in actor)
        ):
            raise ValueError("commercial handoff assignee is invalid")
        self.store = store
        self.leads = CrmOutbox(store)
        self.activities = CrmActivityOutbox(store)
        self.assignee = actor
        self.after_stage_hook = after_stage_hook
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _required(value: object) -> str:
        result = str(value or "").strip()
        if not result:
            raise CommercialHandoffInvariantError("canonical graph is incomplete")
        return result

    @staticmethod
    def _timestamp(value: object) -> str:
        raw = CommercialOpportunityHandoff._required(value)
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise CommercialHandoffInvariantError(
                "canonical source timestamp is invalid"
            ) from None
        if parsed.tzinfo is None:
            raise CommercialHandoffInvariantError(
                "canonical source timestamp is invalid"
            )
        return parsed.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")

    @classmethod
    def _due_at(cls, observed_at_utc: str) -> str:
        observed = datetime.fromisoformat(observed_at_utc.replace("Z", "+00:00"))
        return (observed + timedelta(minutes=cls.HUMAN_ACTION_SLO_MINUTES)).astimezone(
            timezone.utc
        ).isoformat(timespec="seconds").replace("+00:00", "Z")

    @classmethod
    def _load_graph_tx(cls, con: Any, opportunity_id: str) -> _CanonicalGraph:
        row = con.execute(
            """SELECT
                   o.lf_opportunity_id AS opportunity_id,
                   o.status AS opportunity_status,
                   o.source AS opportunity_source,
                   o.external_key AS opportunity_external_key,
                   o.product_key AS product_key,
                   o.source_event_id AS opportunity_source_record_id,
                   co.lf_company_id AS company_id,
                   co.name AS company_name,
                   co.inn AS company_inn,
                   co.domain AS company_domain,
                   co.identity_state AS company_identity_state,
                   ct.lf_contact_id AS contact_id,
                   ct.lf_company_id AS contact_company_id,
                   ct.name AS contact_name,
                   ct.email AS contact_email,
                   ct.email_hash AS contact_email_hash,
                   ct.role AS contact_role,
                   p.lf_project_id AS project_id,
                   p.lf_company_id AS project_company_id,
                   p.source AS project_source,
                   p.external_key AS project_external_key,
                   p.title AS project_title,
                   p.region AS project_region,
                   p.evidence_ref AS project_evidence_ref,
                   p.source_event_id AS project_source_record_id,
                   sr.source_record_id AS source_record_id,
                   sr.producer AS source_producer,
                   sr.external_key AS source_external_key,
                   sr.payload_hash AS source_payload_hash,
                   sr.evidence_ref AS source_evidence_ref,
                   sr.observed_at_utc AS source_observed_at_utc
               FROM opportunities o
               JOIN companies co ON co.lf_company_id=o.lf_company_id
               JOIN contacts ct ON ct.lf_contact_id=o.lf_contact_id
               JOIN projects p ON p.lf_project_id=o.lf_project_id
               JOIN source_records sr ON sr.source_record_id=o.source_event_id
               WHERE o.lf_opportunity_id=?""",
            (opportunity_id,),
        ).fetchone()
        if not row:
            raise CommercialHandoffInvariantError(
                "canonical opportunity graph is missing"
            )

        reply_rows = con.execute(
            """SELECT
                   tr.transition_id,tr.from_state,tr.to_state,tr.evidence_ref,
                   tr.occurred_at_utc,
                   ev.event_id,ev.event_type,ev.aggregate_type,ev.aggregate_id,
                   ev.occurred_at_utc AS event_occurred_at_utc,
                   ev.evidence_ref AS event_evidence_ref,ev.payload_json
               FROM opportunity_transitions tr
               JOIN events ev
                 ON ev.producer='commercial_spine'
                AND ev.idempotency_key='transition:' || tr.transition_id
               WHERE tr.lf_opportunity_id=? AND tr.to_state='HUMAN_REPLY'""",
            (opportunity_id,),
        ).fetchall()
        if len(reply_rows) != 1:
            raise CommercialHandoffInvariantError(
                "exact persisted human reply transition is required"
            )
        reply = reply_rows[0]
        try:
            reply_payload = json.loads(str(reply["payload_json"] or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise CommercialHandoffInvariantError(
                "human reply transition event is invalid"
            ) from None
        expected_reply_payload = {
            "transition_id": str(reply["transition_id"] or ""),
            "lf_opportunity_id": opportunity_id,
            "from_state": str(reply["from_state"] or ""),
            "to_state": "HUMAN_REPLY",
        }
        if (
            not isinstance(reply_payload, dict)
            or any(
                str(reply_payload.get(key) or "") != value
                for key, value in expected_reply_payload.items()
            )
            or str(reply["event_type"] or "") != "opportunity_transitioned"
            or str(reply["aggregate_type"] or "") != "opportunity"
            or str(reply["aggregate_id"] or "") != opportunity_id
            or str(reply["to_state"] or "") != "HUMAN_REPLY"
            or str(reply["event_evidence_ref"] or "")
            != str(reply["evidence_ref"] or "")
            or str(reply["event_occurred_at_utc"] or "")
            != str(reply["occurred_at_utc"] or "")
        ):
            raise CommercialHandoffInvariantError(
                "human reply transition event is inconsistent"
            )

        graph = _CanonicalGraph(
            opportunity_id=cls._required(row["opportunity_id"]),
            opportunity_status=cls._required(row["opportunity_status"]),
            opportunity_source=cls._required(row["opportunity_source"]),
            opportunity_external_key=cls._required(row["opportunity_external_key"]),
            product_key=str(row["product_key"] or "").strip(),
            company_id=cls._required(row["company_id"]),
            company_name=str(row["company_name"] or "").strip(),
            company_inn=cls._required(row["company_inn"]),
            company_domain=str(row["company_domain"] or "").strip(),
            company_identity_state=cls._required(row["company_identity_state"]),
            contact_id=cls._required(row["contact_id"]),
            contact_company_id=cls._required(row["contact_company_id"]),
            contact_name=str(row["contact_name"] or "").strip(),
            contact_email=cls._required(row["contact_email"]),
            contact_email_hash=cls._required(row["contact_email_hash"]),
            contact_role=str(row["contact_role"] or "").strip(),
            project_id=cls._required(row["project_id"]),
            project_company_id=cls._required(row["project_company_id"]),
            project_source=cls._required(row["project_source"]),
            project_external_key=cls._required(row["project_external_key"]),
            project_title=cls._required(row["project_title"]),
            project_region=str(row["project_region"] or "").strip(),
            project_evidence_ref=cls._required(row["project_evidence_ref"]),
            project_source_record_id=cls._required(row["project_source_record_id"]),
            source_record_id=cls._required(row["source_record_id"]),
            source_producer=cls._required(row["source_producer"]),
            source_external_key=cls._required(row["source_external_key"]),
            source_payload_hash=cls._required(row["source_payload_hash"]),
            source_evidence_ref=cls._required(row["source_evidence_ref"]),
            source_observed_at_utc=cls._timestamp(row["source_observed_at_utc"]),
            reply_transition_id=cls._required(reply["transition_id"]),
            reply_event_id=cls._required(reply["event_id"]),
            reply_evidence_ref=cls._required(reply["evidence_ref"]),
            reply_occurred_at_utc=cls._timestamp(reply["occurred_at_utc"]),
        )
        cls._validate_graph(graph, row)
        return graph

    @classmethod
    def _validate_graph(cls, graph: _CanonicalGraph, row: Any) -> None:
        if graph.opportunity_status not in cls._KNOWN_STATES:
            raise CommercialHandoffInvariantError(
                "canonical opportunity state is unsupported"
            )
        if graph.company_identity_state != "EXACT":
            raise CommercialHandoffInvariantError(
                "exact company identity is required"
            )
        if normalize_inn(graph.company_inn) != graph.company_inn or len(
            graph.company_inn
        ) not in {10, 12}:
            raise CommercialHandoffInvariantError(
                "exact company identity is inconsistent"
            )
        if graph.company_domain and normalize_domain(graph.company_domain) != graph.company_domain:
            raise CommercialHandoffInvariantError(
                "canonical company domain is inconsistent"
            )
        if not (
            graph.company_id
            == graph.contact_company_id
            == graph.project_company_id
        ):
            raise CommercialHandoffInvariantError(
                "canonical graph crosses company boundaries"
            )
        email = normalize_email(graph.contact_email)
        if (
            email != graph.contact_email
            or not _MAILBOX.fullmatch(email)
            or len(email) > 254
            or any(ord(char) < 32 or ord(char) == 127 for char in email)
            or address_hash(email) != graph.contact_email_hash
        ):
            raise CommercialHandoffInvariantError(
                "canonical contact address is inconsistent"
            )
        if not (
            graph.source_record_id
            == str(row["opportunity_source_record_id"] or "")
            == graph.project_source_record_id
        ):
            raise CommercialHandoffInvariantError(
                "canonical source linkage is inconsistent"
            )
        if not (
            graph.source_producer
            == graph.opportunity_source
            == graph.project_source
            and graph.source_external_key
            == graph.opportunity_external_key
            == graph.project_external_key
        ):
            raise CommercialHandoffInvariantError(
                "canonical source identity is inconsistent"
            )
        if graph.project_evidence_ref != graph.source_evidence_ref:
            raise CommercialHandoffInvariantError(
                "canonical source evidence is inconsistent"
            )
        if not _SHA256.fullmatch(graph.source_payload_hash):
            raise CommercialHandoffInvariantError(
                "canonical source digest is invalid"
            )
        if str(row["source_observed_at_utc"] or "") != graph.source_observed_at_utc:
            raise CommercialHandoffInvariantError(
                "canonical source timestamp is inconsistent"
            )

    @classmethod
    def _source_event_tx(
        cls,
        store: FactoryStore,
        con: Any,
        graph: _CanonicalGraph,
        *,
        staged_at_utc: str,
        task_creation_elapsed_seconds: int,
    ):
        return store._append_event_tx(
            con,
            event_type="commercial_opportunity_handoff_requested",
            aggregate_type="opportunity",
            aggregate_id=graph.opportunity_id,
            producer="commercial_opportunity_handoff",
            idempotency_key=(
                f"handoff-request:{graph.reply_transition_id}:{graph.opportunity_id}"
            ),
            payload={
                "lf_company_id": graph.company_id,
                "lf_contact_id": graph.contact_id,
                "lf_project_id": graph.project_id,
                "lf_opportunity_id": graph.opportunity_id,
                "source_record_id": graph.source_record_id,
                "source_payload_hash": graph.source_payload_hash,
                "human_reply_transition_id": graph.reply_transition_id,
                "human_reply_event_id": graph.reply_event_id,
                "route": "A1",
                "task_creation_slo_minutes": cls.TASK_CREATION_SLO_MINUTES,
                "human_action_slo_minutes": cls.HUMAN_ACTION_SLO_MINUTES,
                "staged_at_utc": staged_at_utc,
                "task_creation_elapsed_seconds": task_creation_elapsed_seconds,
                "task_creation_slo_met": (
                    task_creation_elapsed_seconds
                    <= cls.TASK_CREATION_SLO_MINUTES * 60
                ),
            },
            evidence_ref=graph.reply_evidence_ref,
            actor="commercial_opportunity_handoff",
            causation_id=graph.reply_event_id,
            occurred_at_utc=staged_at_utc,
            schema_version=14,
        )

    @classmethod
    def _interaction_tx(
        cls,
        con: Any,
        graph: _CanonicalGraph,
        *,
        staged_at_utc: str,
    ) -> tuple[str, bool]:
        dedupe_key = (
            f"commercial-handoff:{graph.reply_transition_id}:{graph.opportunity_id}"
        )
        expected = {
            "lf_opportunity_id": graph.opportunity_id,
            "lf_contact_id": graph.contact_id,
            "source_event_id": graph.reply_event_id,
            "dedupe_key": dedupe_key,
            "channel": "SOURCE",
            "direction": "INBOUND",
            "classification": cls.INTERACTION_CLASSIFICATION,
            "external_message_id": "",
            "thread_id": f"transition:{graph.reply_transition_id}",
            "address": graph.contact_email,
            "address_hash": graph.contact_email_hash,
            "received_at_utc": graph.reply_occurred_at_utc,
            "evidence_ref": graph.reply_evidence_ref,
        }
        existing = con.execute(
            "SELECT * FROM interactions WHERE dedupe_key=?", (dedupe_key,)
        ).fetchone()
        competing = con.execute(
            """SELECT lf_interaction_id,dedupe_key FROM interactions
               WHERE lf_opportunity_id=? AND classification=?""",
            (graph.opportunity_id, cls.INTERACTION_CLASSIFICATION),
        ).fetchall()
        if any(str(row["dedupe_key"]) != dedupe_key for row in competing):
            raise CommercialHandoffInvariantError(
                "opportunity already has a conflicting commercial handoff"
            )
        if existing:
            if any(str(existing[key] or "") != value for key, value in expected.items()):
                raise CommercialHandoffInvariantError(
                    "persisted commercial interaction scope is inconsistent"
                )
            return str(existing["lf_interaction_id"]), False

        interaction_id = new_lf_id("interaction")
        con.execute(
            """INSERT INTO interactions(
                   lf_interaction_id,lf_opportunity_id,lf_contact_id,source_event_id,
                   dedupe_key,channel,direction,classification,external_message_id,
                   thread_id,address,address_hash,received_at_utc,evidence_ref,created_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                interaction_id,
                graph.opportunity_id,
                graph.contact_id,
                graph.reply_event_id,
                dedupe_key,
                "SOURCE",
                "INBOUND",
                cls.INTERACTION_CLASSIFICATION,
                "",
                f"transition:{graph.reply_transition_id}",
                graph.contact_email,
                graph.contact_email_hash,
                graph.reply_occurred_at_utc,
                graph.reply_evidence_ref,
                staged_at_utc,
            ),
        )
        return interaction_id, True

    def _task_tx(
        self,
        con: Any,
        graph: _CanonicalGraph,
        interaction_id: str,
        *,
        staged_at_utc: str,
    ) -> tuple[str, str, bool]:
        due_at = self._due_at(graph.reply_occurred_at_utc)
        existing = con.execute(
            """SELECT * FROM human_tasks
               WHERE lf_interaction_id=? AND kind=?""",
            (interaction_id, self.TASK_KIND),
        ).fetchone()
        competing = con.execute(
            """SELECT lf_task_id,lf_interaction_id FROM human_tasks
               WHERE lf_opportunity_id=? AND kind=?""",
            (graph.opportunity_id, self.TASK_KIND),
        ).fetchall()
        if any(str(row["lf_interaction_id"]) != interaction_id for row in competing):
            raise CommercialHandoffInvariantError(
                "opportunity already has a conflicting qualification task"
            )
        if existing:
            expected = {
                "lf_opportunity_id": graph.opportunity_id,
                "lf_interaction_id": interaction_id,
                "kind": self.TASK_KIND,
                "priority": self.TASK_PRIORITY,
                "assigned_to": self.assignee,
                "due_at_utc": due_at,
            }
            if any(str(existing[key] or "") != value for key, value in expected.items()):
                raise CommercialHandoffInvariantError(
                    "persisted qualification task scope is inconsistent"
                )
            return str(existing["lf_task_id"]), due_at, False

        task_id = new_lf_id("task")
        con.execute(
            """INSERT INTO human_tasks(
                   lf_task_id,lf_opportunity_id,lf_interaction_id,kind,status,
                   priority,assigned_to,due_at_utc,acknowledged_at_utc,
                   first_human_action_at_utc,closed_at_utc,resolution,created_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                task_id,
                graph.opportunity_id,
                interaction_id,
                self.TASK_KIND,
                "OPEN",
                self.TASK_PRIORITY,
                self.assignee,
                due_at,
                "",
                "",
                "",
                "",
                staged_at_utc,
            ),
        )
        return task_id, due_at, True

    @staticmethod
    def _lead_payload(graph: _CanonicalGraph, source_event_id: str) -> dict[str, Any]:
        evidence_digest = payload_hash(
            {
                "source_record_id": graph.source_record_id,
                "source_evidence_ref": graph.source_evidence_ref,
                "human_reply_transition_id": graph.reply_transition_id,
                "human_reply_evidence_ref": graph.reply_evidence_ref,
            }
        )
        trigger_digest = payload_hash(
            {
                "producer": graph.source_producer,
                "external_key": graph.source_external_key,
            }
        )
        provenance = "\n".join(
            (
                f"LF_OPPORTUNITY_ID={graph.opportunity_id}",
                f"LF_PROJECT_ID={graph.project_id}",
                f"LF_SOURCE_EVENT_ID={source_event_id}",
                f"LF_ORIGIN_SOURCE={graph.source_producer}",
                f"LF_TRIGGER_SOURCE_HASH={trigger_digest}",
                f"LF_PRODUCT={graph.product_key}",
                f"LF_REGION={graph.project_region}",
                f"LF_SIGNAL_AT={graph.source_observed_at_utc}",
                f"LF_REPLY_AT={graph.reply_occurred_at_utc}",
                f"LF_EVIDENCE_DIGEST={evidence_digest}",
            )
        )
        return {
            "title": graph.project_title,
            "company_title": graph.company_name or graph.company_inn,
            "name": graph.contact_name,
            "email": [{"VALUE": graph.contact_email, "VALUE_TYPE": "WORK"}],
            "comments": provenance,
            "utm_source": graph.source_producer,
            "utm_campaign": trigger_digest,
            "utm_content": graph.product_key,
            "utm_term": graph.project_region,
        }

    def _activity_payload(
        self,
        graph: _CanonicalGraph,
        source_event_id: str,
        due_at_utc: str,
        responsible: CrmActorBinding,
    ) -> dict[str, Any]:
        evidence_digest = payload_hash(
            {
                "source_record_id": graph.source_record_id,
                "source_evidence_ref": graph.source_evidence_ref,
                "human_reply_transition_id": graph.reply_transition_id,
                "human_reply_evidence_ref": graph.reply_evidence_ref,
            }
        )
        description = "\n".join(
            (
                f"LF_OPPORTUNITY_ID={graph.opportunity_id}",
                f"LF_PROJECT_ID={graph.project_id}",
                f"LF_SOURCE_EVENT_ID={source_event_id}",
                f"LF_ASSIGNEE={self.assignee}",
                f"PROJECT={graph.project_title}",
                f"LF_EVIDENCE_DIGEST={evidence_digest}",
                f"LF_RESPONSIBLE_BINDING_ID={responsible.binding_id}",
            )
        )
        return {
            "deadline": due_at_utc,
            "title": "Квалифицировать входящую B2B-возможность",
            "description": description,
            "responsible_id": responsible.remote_actor_id,
        }

    def stage(self, *, lf_opportunity_id: str) -> CommercialHandoffResult:
        """Stage the complete local handoff without invoking any external system."""

        opportunity_id = str(lf_opportunity_id or "").strip()
        if not opportunity_id:
            raise CommercialHandoffInvariantError("opportunity identity is required")

        with self.store.transaction(min_schema_version=14) as con:
            graph = self._load_graph_tx(con, opportunity_id)
            now = self.clock()
            if not isinstance(now, datetime):
                raise CommercialHandoffInvariantError("handoff clock is invalid")
            if now.tzinfo is None:
                raise CommercialHandoffInvariantError("handoff clock is invalid")
            now_utc = now.astimezone(timezone.utc)
            reply_occurred = datetime.fromisoformat(
                graph.reply_occurred_at_utc.replace("Z", "+00:00")
            )
            if reply_occurred > now_utc + timedelta(minutes=5):
                raise CommercialHandoffInvariantError(
                    "canonical human reply timestamp is in the future"
                )
            existing_interaction = con.execute(
                """SELECT created_at_utc FROM interactions
                   WHERE lf_opportunity_id=? AND classification=? LIMIT 1""",
                (opportunity_id, self.INTERACTION_CLASSIFICATION),
            ).fetchone()
            if (
                not existing_interaction
                and graph.opportunity_status not in self._INITIAL_ACTIONABLE_STATES
            ):
                raise CommercialHandoffInvariantError(
                    "only a persisted human reply is eligible for A1 handoff"
                )
            staged_at_utc = (
                self._timestamp(existing_interaction["created_at_utc"])
                if existing_interaction
                else now_utc.isoformat(timespec="seconds").replace("+00:00", "Z")
            )
            staged_at = datetime.fromisoformat(
                staged_at_utc.replace("Z", "+00:00")
            )
            if staged_at < reply_occurred - timedelta(minutes=5):
                raise CommercialHandoffInvariantError(
                    "persisted handoff predates the human reply"
                )
            task_creation_elapsed_seconds = max(
                0, int((staged_at - reply_occurred).total_seconds())
            )
            try:
                responsible = CrmActorBindingRegistry.resolve_verified_tx(
                    con, connector="bitrix", local_actor=self.assignee
                )
            except (CrmActorBindingError, ValueError):
                raise CommercialHandoffInvariantError(
                    "verified CRM responsible binding is required"
                ) from None

            request_event, request_event_created = self._source_event_tx(
                self.store,
                con,
                graph,
                staged_at_utc=staged_at_utc,
                task_creation_elapsed_seconds=task_creation_elapsed_seconds,
            )
            source_event_id = graph.reply_event_id
            interaction_id, interaction_created = self._interaction_tx(
                con, graph, staged_at_utc=staged_at_utc
            )
            task_id, due_at_utc, task_created = self._task_tx(
                con, graph, interaction_id, staged_at_utc=staged_at_utc
            )

            lead_operation_id, lead_created = self.leads.stage_lead_create_tx(
                con,
                lf_entity_id=graph.opportunity_id,
                external_event_id=source_event_id,
                payload=self._lead_payload(graph, source_event_id),
            )
            activity_operation_id, activity_created = (
                self.activities.stage_activity_create_tx(
                    con,
                    interaction_id=interaction_id,
                    task_id=task_id,
                    lead_operation_id=lead_operation_id,
                    external_event_id=source_event_id,
                    payload=self._activity_payload(
                        graph, source_event_id, due_at_utc, responsible
                    ),
                )
            )
            audit_payload = {
                "state": self.STATE,
                "lf_opportunity_id": graph.opportunity_id,
                "interaction_id": interaction_id,
                "task_id": task_id,
                "lead_operation_id": lead_operation_id,
                "activity_operation_id": activity_operation_id,
                "source_event_id": source_event_id,
                "handoff_request_event_id": str(request_event["event_id"]),
                "human_reply_transition_id": graph.reply_transition_id,
                "human_reply_occurred_at_utc": graph.reply_occurred_at_utc,
                "staged_at_utc": staged_at_utc,
                "task_creation_elapsed_seconds": task_creation_elapsed_seconds,
                "task_creation_slo_met": (
                    task_creation_elapsed_seconds
                    <= self.TASK_CREATION_SLO_MINUTES * 60
                ),
                "due_at_utc": due_at_utc,
                "responsible_binding_id": responsible.binding_id,
                "payload_digest": payload_hash(
                    {
                        "lead_operation_id": lead_operation_id,
                        "activity_operation_id": activity_operation_id,
                        "source_payload_hash": graph.source_payload_hash,
                        "human_reply_transition_id": graph.reply_transition_id,
                    }
                ),
            }
            _, audit_created = self.store._append_event_tx(
                con,
                event_type="commercial_opportunity_handoff_staged",
                aggregate_type="opportunity",
                aggregate_id=graph.opportunity_id,
                producer="commercial_opportunity_handoff",
                idempotency_key=f"handoff-staged:{graph.opportunity_id}",
                payload=audit_payload,
                evidence_ref=graph.reply_evidence_ref,
                actor="commercial_opportunity_handoff",
                causation_id=source_event_id,
                occurred_at_utc=staged_at_utc,
                schema_version=14,
            )
            if self.after_stage_hook:
                self.after_stage_hook()

            return CommercialHandoffResult(
                created=any(
                    (
                        request_event_created,
                        interaction_created,
                        task_created,
                        lead_created,
                        activity_created,
                        audit_created,
                    )
                ),
                state=self.STATE,
                lf_opportunity_id=graph.opportunity_id,
                interaction_id=interaction_id,
                task_id=task_id,
                lead_operation_id=str(lead_operation_id),
                activity_operation_id=str(activity_operation_id),
                due_at_utc=due_at_utc,
            )


__all__ = [
    "CommercialHandoffError",
    "CommercialHandoffInvariantError",
    "CommercialHandoffResult",
    "CommercialOpportunityHandoff",
]
