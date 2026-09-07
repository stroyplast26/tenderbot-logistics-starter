"""Transport-neutral operator call workflow for Bitrix/MANGO integration.

The workflow persists only stable provider identifiers, digests and structured
human decisions.  Raw audio, transcript text and temporary provider URLs never
enter the canonical event log.  External transports are deliberately absent:
MANGO and Bitrix adapters feed this boundary after their own authority checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Mapping

from .crm_identity import CrmActorBindingError, CrmActorBindingRegistry
from .ids import payload_hash, utc_now
from .store import FactoryStore, IdempotencyConflict
from .tasks import (
    TERMINAL_STATES,
    HumanTaskController,
    TaskStateError,
    TaskTransition,
)


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LANGUAGE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$")
_EVIDENCE = re.compile(r"^evidence://[A-Za-z0-9][A-Za-z0-9._:/-]{0,2028}$")
_PRODUCER = "operator_call_workflow"


class OperatorCallWorkflowError(RuntimeError):
    """A call event is invalid or cannot be applied safely."""


class OperatorCallWorkflowConflict(OperatorCallWorkflowError):
    """A replay conflicts with already persisted call evidence."""


class OperatorCallBindingRequired(OperatorCallWorkflowError):
    """A confirmed disposition requires an exact local/Bitrix binding."""


class TechnicalDisposition(str, Enum):
    CONNECTED = "CONNECTED"
    NO_ANSWER = "NO_ANSWER"
    BUSY = "BUSY"
    VOICEMAIL = "VOICEMAIL"
    WRONG_NUMBER = "WRONG_NUMBER"
    CONNECTION_DROPPED = "CONNECTION_DROPPED"


class CommercialDisposition(str, Enum):
    NOT_ASSESSED = "NOT_ASSESSED"
    GATEKEEPER = "GATEKEEPER"
    DM_IDENTIFIED = "DM_IDENTIFIED"
    DM_REACHED = "DM_REACHED"
    CALLBACK_REQUESTED = "CALLBACK_REQUESTED"
    NO_CURRENT_NEED = "NO_CURRENT_NEED"
    NOT_ICP = "NOT_ICP"
    OWN_PRODUCTION = "OWN_PRODUCTION"
    SUPPLIER_SELECTED = "SUPPLIER_SELECTED"
    RFQ_COMMITTED = "RFQ_COMMITTED"
    RFQ_RECEIVED = "RFQ_RECEIVED"
    READY_PACKAGE = "READY_PACKAGE"
    NURTURE_UNTIL = "NURTURE_UNTIL"
    DO_NOT_CONTACT = "DO_NOT_CONTACT"
    COMPLAINT = "COMPLAINT"
    QUALIFIED_FOR_GOLD_REVIEW = "QUALIFIED_FOR_GOLD_REVIEW"


class NextActionCode(str, Enum):
    NONE = "NONE"
    CALL_BACK = "CALL_BACK"
    REQUEST_RFQ = "REQUEST_RFQ"
    REQUEST_MISSING_DATA = "REQUEST_MISSING_DATA"
    SEND_APPROVED_MATERIAL = "SEND_APPROVED_MATERIAL"
    NURTURE = "NURTURE"
    GOLD_REVIEW = "GOLD_REVIEW"
    ESTIMATOR_REVIEW = "ESTIMATOR_REVIEW"


class RecordingNoticeStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class CallWorkflowState(str, Enum):
    UNBOUND_EVIDENCE = "UNBOUND_EVIDENCE"
    UNBOUND_CALL = "UNBOUND_CALL"
    BOUND = "BOUND"
    RECORDING_READY = "RECORDING_READY"
    TRANSCRIPT_READY = "TRANSCRIPT_READY"
    ANALYSIS_DRAFT = "ANALYSIS_DRAFT"
    OPERATOR_CONFIRMED = "OPERATOR_CONFIRMED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


_AI_FLAGS = frozenset(
    {
        "COMPLAINT",
        "DEADLINE_PROMISE",
        "DNC",
        "GOLD_CANDIDATE",
        "LOW_CONFIDENCE",
        "PRICE_PROMISE",
        "SCRIPT_GAP",
    }
)


def _required(value: object, label: str, *, maximum: int = 2048) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum or any(char in result for char in "\r\n\x00"):
        raise ValueError(f"{label} is invalid")
    return result


def _identifier(value: object, label: str) -> str:
    result = _required(value, label, maximum=160)
    if not _ID.fullmatch(result):
        raise ValueError(f"{label} is invalid")
    return result


def _sha256(value: object, label: str) -> str:
    result = str(value or "").strip().lower()
    if not _HEX64.fullmatch(result):
        raise ValueError(f"{label} is invalid")
    return result


def _evidence_ref(value: object) -> str:
    result = _required(value, "evidence reference")
    remainder = result.removeprefix("evidence://")
    if (
        not _EVIDENCE.fullmatch(result)
        or "://" in remainder
        or remainder.lower().startswith(("http:", "https:"))
    ):
        raise ValueError("evidence reference is invalid")
    return result


def _evidenced(payload: dict[str, Any], evidence_ref: str) -> dict[str, Any]:
    """Bind idempotency to the opaque evidence identity without duplicating it."""

    return {
        **payload,
        "_evidence_ref_sha256": payload_hash({"evidence_ref": evidence_ref}),
    }


def _utc(value: object, label: str) -> str:
    raw = _required(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError(f"{label} is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} is invalid")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _optional_utc(value: object, label: str) -> str:
    return _utc(value, label) if str(value or "").strip() else ""


def _enum(enum_type: type[Enum], value: object, label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} is invalid") from None


def _non_negative_int(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _payload(row: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(str(row["payload_json"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise OperatorCallWorkflowError("persisted call event payload is invalid") from None
    if not isinstance(value, dict):
        raise OperatorCallWorkflowError("persisted call event payload is invalid")
    return value


@dataclass(frozen=True)
class CallWorkflowResult:
    call_session_id: str
    event_id: str
    state: CallWorkflowState
    created: bool


@dataclass(frozen=True)
class CallSessionSnapshot:
    call_session_id: str
    state: CallWorkflowState
    mango_entry_id: str
    call_count: int
    recording_count: int
    transcript_count: int
    transcript_set_sha256: str
    analysis_draft_count: int
    confirmation_version: int
    lf_opportunity_id: str
    lf_task_id: str
    bitrix_call_id: str
    crm_activity_id: str
    review_reasons: tuple[str, ...]


@dataclass(frozen=True)
class CallAnalysisProposal:
    call_session_id: str
    draft_id: str
    transcript_set_sha256: str
    analysis_sha256: str
    prompt_version: str
    model_id: str
    confidence_bps: int
    proposed_commercial_disposition: CommercialDisposition | str
    proposed_next_action: NextActionCode | str
    proposed_next_action_at_utc: str
    flags: tuple[str, ...]
    evidence_spans_sha256: str
    evidence_ref: str

    def __post_init__(self) -> None:
        _identifier(self.call_session_id, "call session id")
        _identifier(self.draft_id, "analysis draft id")
        _sha256(self.transcript_set_sha256, "transcript set digest")
        _sha256(self.analysis_sha256, "analysis digest")
        _identifier(self.prompt_version, "prompt version")
        _identifier(self.model_id, "model id")
        _non_negative_int(self.confidence_bps, "analysis confidence", maximum=10_000)
        _enum(
            CommercialDisposition,
            self.proposed_commercial_disposition,
            "proposed commercial disposition",
        )
        next_action = _enum(
            NextActionCode, self.proposed_next_action, "proposed next action"
        )
        next_at = _optional_utc(
            self.proposed_next_action_at_utc, "proposed next action timestamp"
        )
        if (next_action is NextActionCode.NONE) != (not next_at):
            raise ValueError("proposed next action timestamp is inconsistent")
        if not isinstance(self.flags, tuple) or any(flag not in _AI_FLAGS for flag in self.flags):
            raise ValueError("analysis flags are invalid")
        if len(set(self.flags)) != len(self.flags):
            raise ValueError("analysis flags are invalid")
        _sha256(self.evidence_spans_sha256, "evidence spans digest")
        _evidence_ref(self.evidence_ref)


@dataclass(frozen=True)
class OperatorCallConfirmation:
    call_session_id: str
    confirmation_version: int
    operator_actor: str
    technical_disposition: TechnicalDisposition | str
    commercial_disposition: CommercialDisposition | str
    next_action: NextActionCode | str
    next_action_at_utc: str
    next_action_owner: str
    reason_code: str
    request_gold_review: bool
    request_suppression_review: bool
    recording_notice_status: RecordingNoticeStatus | str
    evidence_ref: str
    draft_id: str = ""

    def __post_init__(self) -> None:
        _identifier(self.call_session_id, "call session id")
        if (
            isinstance(self.confirmation_version, bool)
            or not isinstance(self.confirmation_version, int)
            or not 1 <= self.confirmation_version <= 10_000
        ):
            raise ValueError("confirmation version is invalid")
        _identifier(self.operator_actor, "operator actor")
        technical = _enum(
            TechnicalDisposition, self.technical_disposition, "technical disposition"
        )
        commercial = _enum(
            CommercialDisposition, self.commercial_disposition, "commercial disposition"
        )
        next_action = _enum(NextActionCode, self.next_action, "next action")
        next_at = _optional_utc(self.next_action_at_utc, "next action timestamp")
        next_owner = str(self.next_action_owner or "").strip()
        reason = str(self.reason_code or "").strip()
        if next_owner:
            _identifier(next_owner, "next action owner")
        if reason:
            _identifier(reason, "reason code")
        if not isinstance(self.request_gold_review, bool) or not isinstance(
            self.request_suppression_review, bool
        ):
            raise ValueError("review request flags are invalid")
        _enum(
            RecordingNoticeStatus,
            self.recording_notice_status,
            "recording notice status",
        )
        _evidence_ref(self.evidence_ref)
        if self.draft_id:
            _identifier(self.draft_id, "analysis draft id")

        if technical is TechnicalDisposition.CONNECTED:
            if commercial is CommercialDisposition.NOT_ASSESSED:
                raise ValueError("connected call requires a commercial disposition")
        elif commercial is not CommercialDisposition.NOT_ASSESSED:
            raise ValueError("unconnected call cannot have a commercial disposition")

        if next_action is NextActionCode.NONE:
            if next_at or next_owner or not reason:
                raise ValueError("terminal disposition requires only a reason code")
        elif not next_at or not next_owner:
            raise ValueError("next action requires timestamp and owner")

        gold = commercial is CommercialDisposition.QUALIFIED_FOR_GOLD_REVIEW
        if gold != self.request_gold_review:
            raise ValueError("Gold review request is inconsistent")
        if gold and next_action is not NextActionCode.GOLD_REVIEW:
            raise ValueError("Gold candidate requires a Gold review next action")

        dnc = commercial is CommercialDisposition.DO_NOT_CONTACT
        if dnc != self.request_suppression_review:
            raise ValueError("suppression review request is inconsistent")
        if dnc and next_action is not NextActionCode.NONE:
            raise ValueError("do-not-contact cannot schedule another contact action")


class OperatorCallWorkflow:
    """Append-only call evidence and human-confirmation boundary."""

    def __init__(self, store: FactoryStore) -> None:
        if not isinstance(store, FactoryStore):
            raise TypeError("FactoryStore is required")
        self.store = store
        self.tasks = HumanTaskController(store)

    @staticmethod
    def call_session_id(mango_entry_id: str) -> str:
        entry_id = _identifier(mango_entry_id, "MANGO entry id")
        return "call_session_" + payload_hash(
            {"provider": "MANGO", "mango_entry_id": entry_id}
        )[:32]

    @staticmethod
    def _rows_tx(con: Any, call_session_id: str) -> list[dict[str, Any]]:
        """Read one stream in its immutable SQLite insertion order."""

        session_id = _identifier(call_session_id, "call session id")
        rows = con.execute(
            """SELECT * FROM events
               WHERE producer=? AND aggregate_type='call_session' AND aggregate_id=?
               ORDER BY rowid""",
            (_PRODUCER, session_id),
        ).fetchall()
        return [dict(row) for row in rows]

    def _rows(self, call_session_id: str) -> list[dict[str, Any]]:
        session_id = _identifier(call_session_id, "call session id")
        self.store.init()
        con = self.store.connect()
        try:
            return self._rows_tx(con, session_id)
        finally:
            con.close()

    @staticmethod
    def _transcript_set(
        calls: list[dict[str, Any]],
        recordings: list[dict[str, Any]],
        transcripts: list[dict[str, Any]],
        *,
        require_complete: bool,
    ) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        call_ids = {str(call["mango_call_id"]) for call in calls}
        recording_ids = {
            str(recording["mango_recording_id"]): recording for recording in recordings
        }
        latest: dict[str, dict[str, Any]] = {}
        for transcript in transcripts:
            recording_id = str(transcript["mango_recording_id"])
            current = latest.get(recording_id)
            if current is None or int(transcript["transcript_revision"]) > int(
                current["transcript_revision"]
            ):
                latest[recording_id] = transcript
        orphan_ids = tuple(sorted(set(latest) - set(recording_ids)))
        pending_ids = tuple(sorted(set(recording_ids) - set(latest)))
        orphan_recording_ids = tuple(
            sorted(
                recording_id
                for recording_id, recording in recording_ids.items()
                if str(recording["mango_call_id"]) not in call_ids
            )
        )
        if require_complete:
            if not recording_ids:
                raise OperatorCallWorkflowError(
                    "analysis requires persisted recording evidence"
                )
            if orphan_recording_ids:
                raise OperatorCallWorkflowError(
                    "recording is not bound to a completed call leg"
                )
            if orphan_ids:
                raise OperatorCallWorkflowError(
                    "transcript is not bound to persisted recording evidence"
                )
            if pending_ids:
                raise OperatorCallWorkflowError(
                    "analysis requires a current transcript for every recording"
                )
        if (
            not recording_ids
            or orphan_ids
            or pending_ids
            or orphan_recording_ids
        ):
            return "", orphan_ids, pending_ids, orphan_recording_ids
        ordered = sorted(
            recording_ids.values(),
            key=lambda item: (int(item["seq"]), str(item["mango_recording_id"])),
        )
        digest = payload_hash(
            {
                "transcripts": [
                    {
                        "mango_recording_id": recording["mango_recording_id"],
                        "transcript_revision": latest[
                            str(recording["mango_recording_id"])
                        ]["transcript_revision"],
                        "transcript_sha256": latest[
                            str(recording["mango_recording_id"])
                        ]["transcript_sha256"],
                    }
                    for recording in ordered
                ]
            }
        )
        return digest, (), (), ()

    def current_transcript_set_sha256(self, call_session_id: str) -> str:
        rows = self._rows(call_session_id)
        calls = [
            _payload(row) for row in rows if row["event_type"] == "call_completed"
        ]
        recordings = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_recording_ready"
        ]
        transcripts = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_transcript_ready"
        ]
        digest, _orphans, _pending, _orphan_recordings = self._transcript_set(
            calls, recordings, transcripts, require_complete=True
        )
        return digest

    @staticmethod
    def _result(
        call_session_id: str, event: Mapping[str, Any], created: bool, state: CallWorkflowState
    ) -> CallWorkflowResult:
        return CallWorkflowResult(
            call_session_id,
            str(event["event_id"]),
            state,
            bool(created),
        )

    @staticmethod
    def _effective_operator(
        binding: Mapping[str, Any], reassignments: list[dict[str, Any]]
    ) -> str:
        actor = _identifier(binding.get("operator_actor"), "bound operator actor")
        seen_versions: set[int] = set()
        ordered: list[tuple[int, dict[str, Any]]] = []
        for reassignment in reassignments:
            version = _non_negative_int(
                reassignment.get("confirmation_version"),
                "operator reassignment version",
                maximum=10_000,
            )
            if version < 1 or version in seen_versions:
                raise OperatorCallWorkflowError(
                    "persisted operator reassignment sequence is invalid"
                )
            seen_versions.add(version)
            ordered.append((version, reassignment))
        for _version, reassignment in sorted(ordered, key=lambda item: item[0]):
            previous = _identifier(
                reassignment.get("from_operator_actor"), "previous operator actor"
            )
            successor = _identifier(
                reassignment.get("to_operator_actor"), "successor operator actor"
            )
            if previous != actor:
                raise OperatorCallWorkflowError(
                    "persisted operator reassignment chain is inconsistent"
                )
            actor = successor
        return actor

    def _complete_task_tx(
        self,
        con: Any,
        task: Mapping[str, Any],
        *,
        task_id: str,
        actor: str,
        evidence_ref: str,
        resolution: str,
    ) -> bool:
        status = str(task["status"])
        if status == "COMPLETED":
            return False
        if status in TERMINAL_STATES:
            raise OperatorCallWorkflowConflict(
                "terminal call task cannot be completed again"
            )
        self.tasks._assert_not_review_queue_managed(con, task_id)
        now = utc_now()
        changed = con.execute(
            """UPDATE human_tasks SET status='COMPLETED',
               acknowledged_at_utc=CASE WHEN acknowledged_at_utc='' THEN ?
                                        ELSE acknowledged_at_utc END,
               first_human_action_at_utc=CASE WHEN first_human_action_at_utc='' THEN ?
                                              ELSE first_human_action_at_utc END,
               closed_at_utc=?,resolution=?
               WHERE lf_task_id=? AND assigned_to=? AND status=?""",
            (now, now, now, resolution, task_id, actor, status),
        )
        if changed.rowcount != 1:
            raise OperatorCallWorkflowConflict(
                "call task completion lost its assignment/state race"
            )
        self.tasks._event(
            con,
            task_id=task_id,
            state="COMPLETED",
            actor=actor,
            event_type="human_task_completed",
            evidence_ref=evidence_ref,
            extra={"resolution": resolution},
        )
        return True

    def record_call_completed(
        self,
        *,
        mango_entry_id: str,
        mango_call_id: str,
        seq: int,
        direction: str,
        started_at_utc: str,
        completed_at_utc: str,
        duration_seconds: int,
        evidence_ref: str,
    ) -> CallWorkflowResult:
        entry_id = _identifier(mango_entry_id, "MANGO entry id")
        call_id = _identifier(mango_call_id, "MANGO call id")
        sequence = _non_negative_int(seq, "MANGO sequence", maximum=2_147_483_647)
        call_direction = _identifier(direction, "call direction")
        if call_direction not in {"INBOUND", "OUTBOUND"}:
            raise ValueError("call direction is invalid")
        started = _utc(started_at_utc, "call start timestamp")
        completed = _utc(completed_at_utc, "call completion timestamp")
        if completed < started:
            raise ValueError("call completion precedes call start")
        duration = _non_negative_int(
            duration_seconds, "call duration", maximum=24 * 60 * 60
        )
        evidence = _evidence_ref(evidence_ref)
        session_id = self.call_session_id(entry_id)
        try:
            event, created = self.store.append_event(
                event_type="call_completed",
                aggregate_type="call_session",
                aggregate_id=session_id,
                producer=_PRODUCER,
                idempotency_key=f"call-completed:{call_id}",
                payload=_evidenced(
                    {
                        "provider": "MANGO",
                        "mango_entry_id": entry_id,
                        "mango_call_id": call_id,
                        "seq": sequence,
                        "direction": call_direction,
                        "started_at_utc": started,
                        "completed_at_utc": completed,
                        "duration_seconds": duration,
                    },
                    evidence,
                ),
                evidence_ref=evidence,
                actor="mango_intake",
                occurred_at_utc=completed,
            )
        except IdempotencyConflict as exc:
            raise OperatorCallWorkflowConflict(str(exc)) from None
        return self._result(session_id, event, created, self.snapshot(session_id).state)

    def record_crm_candidate_review(
        self,
        *,
        mango_entry_id: str,
        crm_activity_ids: tuple[str, ...],
        candidate_snapshot_sha256: str,
        evidence_ref: str,
    ) -> CallWorkflowResult:
        """Persist an immutable ambiguous CRM match without selecting a record.

        The candidate set contains stable CRM identifiers only; phone numbers and
        other matching inputs are intentionally excluded from the canonical event.
        A different snapshot for the same unresolved call is a conflict rather than
        an implicit replacement.
        """

        entry_id = _identifier(mango_entry_id, "MANGO entry id")
        session_id = self.call_session_id(entry_id)
        if not isinstance(crm_activity_ids, tuple):
            raise ValueError("CRM candidate ids are invalid")
        candidates = tuple(
            sorted(_identifier(value, "CRM activity id") for value in crm_activity_ids)
        )
        if len(candidates) < 2 or len(set(candidates)) != len(candidates):
            raise ValueError("ambiguous CRM review requires distinct candidates")
        snapshot_digest = _sha256(
            candidate_snapshot_sha256, "CRM candidate snapshot digest"
        )
        if snapshot_digest != payload_hash({"crm_activity_ids": list(candidates)}):
            raise ValueError("CRM candidate snapshot digest does not match candidates")
        evidence = _evidence_ref(evidence_ref)
        rows = self._rows(session_id)
        if not any(row["event_type"] == "call_completed" for row in rows):
            raise OperatorCallWorkflowError(
                "CRM candidate review requires a completed call"
            )
        if any(row["event_type"] == "call_bitrix_activity_bound" for row in rows):
            raise OperatorCallWorkflowConflict(
                "CRM candidate review cannot replace an exact binding"
            )
        prior_reviews = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_crm_binding_review_requested"
        ]
        if prior_reviews and str(
            prior_reviews[-1].get("candidate_snapshot_sha256", "")
        ) != snapshot_digest:
            raise OperatorCallWorkflowConflict(
                "unresolved CRM candidate snapshot is immutable"
            )
        try:
            event, created = self.store.append_event(
                event_type="call_crm_binding_review_requested",
                aggregate_type="call_session",
                aggregate_id=session_id,
                producer=_PRODUCER,
                idempotency_key=f"crm-binding-review:{session_id}",
                payload=_evidenced(
                    {
                        "call_session_id": session_id,
                        "mango_entry_id": entry_id,
                        "reason": "AMBIGUOUS_CRM_MATCH",
                        "crm_activity_ids": list(candidates),
                        "candidate_snapshot_sha256": snapshot_digest,
                    },
                    evidence,
                ),
                evidence_ref=evidence,
                actor="crm_mapping_review",
            )
        except IdempotencyConflict as exc:
            raise OperatorCallWorkflowConflict(str(exc)) from None
        return self._result(
            session_id,
            event,
            created,
            CallWorkflowState.REVIEW_REQUIRED,
        )

    def bind_bitrix_activity(
        self,
        *,
        mango_entry_id: str,
        bitrix_call_id: str,
        crm_activity_id: str,
        lf_opportunity_id: str,
        lf_task_id: str,
        operator_actor: str,
        evidence_ref: str,
    ) -> CallWorkflowResult:
        entry_id = _identifier(mango_entry_id, "MANGO entry id")
        session_id = self.call_session_id(entry_id)
        bitrix_id = _identifier(bitrix_call_id, "Bitrix call id")
        activity_id = _identifier(crm_activity_id, "CRM activity id")
        opportunity_id = _identifier(lf_opportunity_id, "opportunity id")
        task_id = _identifier(lf_task_id, "task id")
        actor = _identifier(operator_actor, "operator actor")
        evidence = _evidence_ref(evidence_ref)
        rows = self._rows(session_id)
        if not any(row["event_type"] == "call_completed" for row in rows):
            raise OperatorCallWorkflowError("Bitrix binding requires a completed call")
        candidate_reviews = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_crm_binding_review_requested"
        ]
        if candidate_reviews and activity_id not in set(
            candidate_reviews[-1].get("crm_activity_ids", [])
        ):
            raise OperatorCallWorkflowConflict(
                "selected CRM activity is outside the immutable candidate snapshot"
            )

        with self.store.transaction() as con:
            task = con.execute(
                """SELECT lf_opportunity_id,assigned_to,status FROM human_tasks
                   WHERE lf_task_id=?""",
                (task_id,),
            ).fetchone()
            if not task or str(task["lf_opportunity_id"] or "") != opportunity_id:
                raise OperatorCallWorkflowError("call task/opportunity binding is invalid")
            if str(task["assigned_to"] or "") != actor:
                raise OperatorCallWorkflowError("call task is assigned to another operator")
            try:
                self.store._append_event_tx(
                    con,
                    event_type="call_bitrix_call_id_claimed",
                    aggregate_type="call_session",
                    aggregate_id=session_id,
                    producer=_PRODUCER,
                    idempotency_key=f"bitrix-call-claimed:{bitrix_id}",
                    payload=_evidenced(
                        {
                            "call_session_id": session_id,
                            "mango_entry_id": entry_id,
                            "bitrix_call_id": bitrix_id,
                        },
                        evidence,
                    ),
                    evidence_ref=evidence,
                    actor=actor,
                )
                self.store._append_event_tx(
                    con,
                    event_type="call_crm_activity_id_claimed",
                    aggregate_type="call_session",
                    aggregate_id=session_id,
                    producer=_PRODUCER,
                    idempotency_key=f"crm-activity-claimed:{activity_id}",
                    payload=_evidenced(
                        {
                            "call_session_id": session_id,
                            "mango_entry_id": entry_id,
                            "crm_activity_id": activity_id,
                        },
                        evidence,
                    ),
                    evidence_ref=evidence,
                    actor=actor,
                )
                event, created = self.store._append_event_tx(
                    con,
                    event_type="call_bitrix_activity_bound",
                    aggregate_type="call_session",
                    aggregate_id=session_id,
                    producer=_PRODUCER,
                    idempotency_key=f"call-binding:{session_id}",
                    payload=_evidenced(
                        {
                            "provider": "MANGO",
                            "mango_entry_id": entry_id,
                            "bitrix_call_id": bitrix_id,
                            "crm_activity_id": activity_id,
                            "lf_opportunity_id": opportunity_id,
                            "lf_task_id": task_id,
                            "operator_actor": actor,
                        },
                        evidence,
                    ),
                    evidence_ref=evidence,
                    actor=actor,
                )
                if candidate_reviews:
                    candidate_review = candidate_reviews[-1]
                    self.store._append_event_tx(
                        con,
                        event_type="call_crm_binding_review_resolved",
                        aggregate_type="call_session",
                        aggregate_id=session_id,
                        producer=_PRODUCER,
                        idempotency_key=f"crm-binding-review-resolved:{session_id}",
                        payload=_evidenced(
                            {
                                "call_session_id": session_id,
                                "candidate_snapshot_sha256": candidate_review[
                                    "candidate_snapshot_sha256"
                                ],
                                "selected_crm_activity_id": activity_id,
                                "operator_actor": actor,
                            },
                            evidence,
                        ),
                        evidence_ref=evidence,
                        actor=actor,
                        causation_id=str(event["event_id"]),
                    )
            except IdempotencyConflict:
                raise OperatorCallWorkflowConflict(
                    "Bitrix call/activity identity is already bound to another call"
                ) from None

        if str(task["status"]) not in TERMINAL_STATES:
            try:
                self.tasks.record_first_action(
                    task_id, actor=actor, evidence_ref=evidence
                )
            except TaskStateError as exc:
                raise OperatorCallWorkflowError(str(exc)) from None
        return self._result(session_id, event, created, self.snapshot(session_id).state)

    def record_recording_ready(
        self,
        *,
        mango_entry_id: str,
        mango_call_id: str,
        mango_recording_id: str,
        seq: int,
        duration_seconds: int,
        evidence_ref: str,
    ) -> CallWorkflowResult:
        entry_id = _identifier(mango_entry_id, "MANGO entry id")
        call_id = _identifier(mango_call_id, "MANGO call id")
        recording_id = _identifier(mango_recording_id, "MANGO recording id")
        sequence = _non_negative_int(seq, "MANGO sequence", maximum=2_147_483_647)
        duration = _non_negative_int(
            duration_seconds, "recording duration", maximum=24 * 60 * 60
        )
        evidence = _evidence_ref(evidence_ref)
        session_id = self.call_session_id(entry_id)
        try:
            event, created = self.store.append_event(
                event_type="call_recording_ready",
                aggregate_type="call_session",
                aggregate_id=session_id,
                producer=_PRODUCER,
                idempotency_key=f"recording-ready:{recording_id}",
                payload=_evidenced(
                    {
                        "provider": "MANGO",
                        "mango_entry_id": entry_id,
                        "mango_call_id": call_id,
                        "mango_recording_id": recording_id,
                        "seq": sequence,
                        "duration_seconds": duration,
                    },
                    evidence,
                ),
                evidence_ref=evidence,
                actor="mango_intake",
            )
        except IdempotencyConflict as exc:
            raise OperatorCallWorkflowConflict(str(exc)) from None
        return self._result(session_id, event, created, self.snapshot(session_id).state)

    def record_transcript_ready(
        self,
        *,
        mango_entry_id: str,
        mango_recording_id: str,
        transcript_revision: int,
        transcript_sha256: str,
        segment_count: int,
        speaker_count: int,
        language: str,
        evidence_ref: str,
    ) -> CallWorkflowResult:
        entry_id = _identifier(mango_entry_id, "MANGO entry id")
        recording_id = _identifier(mango_recording_id, "MANGO recording id")
        revision = _non_negative_int(
            transcript_revision, "transcript revision", maximum=1_000_000
        )
        if revision < 1:
            raise ValueError("transcript revision is invalid")
        digest = _sha256(transcript_sha256, "transcript digest")
        segments = _non_negative_int(segment_count, "transcript segment count", maximum=100_000)
        speakers = _non_negative_int(speaker_count, "transcript speaker count", maximum=100)
        if segments < 1 or speakers < 1:
            raise ValueError("transcript shape is invalid")
        lang = _required(language, "transcript language", maximum=16)
        if not _LANGUAGE.fullmatch(lang):
            raise ValueError("transcript language is invalid")
        evidence = _evidence_ref(evidence_ref)
        session_id = self.call_session_id(entry_id)
        try:
            event, created = self.store.append_event(
                event_type="call_transcript_ready",
                aggregate_type="call_session",
                aggregate_id=session_id,
                producer=_PRODUCER,
                idempotency_key=f"transcript-ready:{recording_id}:{revision}",
                payload=_evidenced(
                    {
                        "provider": "MANGO",
                        "mango_entry_id": entry_id,
                        "mango_recording_id": recording_id,
                        "transcript_revision": revision,
                        "transcript_sha256": digest,
                        "segment_count": segments,
                        "speaker_count": speakers,
                        "language": lang,
                    },
                    evidence,
                ),
                evidence_ref=evidence,
                actor="transcription_intake",
            )
        except IdempotencyConflict as exc:
            raise OperatorCallWorkflowConflict(str(exc)) from None
        return self._result(session_id, event, created, self.snapshot(session_id).state)

    def record_analysis_draft(
        self, proposal: CallAnalysisProposal
    ) -> CallWorkflowResult:
        if type(proposal) is not CallAnalysisProposal:
            raise ValueError("call analysis proposal is invalid")
        rows = self._rows(proposal.call_session_id)
        calls = [
            _payload(row) for row in rows if row["event_type"] == "call_completed"
        ]
        recordings = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_recording_ready"
        ]
        transcripts = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_transcript_ready"
        ]
        current_set, _orphans, _pending, _orphan_recordings = self._transcript_set(
            calls, recordings, transcripts, require_complete=True
        )
        if proposal.transcript_set_sha256 != current_set:
            raise OperatorCallWorkflowError(
                "analysis draft is stale for the current transcript set"
            )
        disposition = _enum(
            CommercialDisposition,
            proposal.proposed_commercial_disposition,
            "proposed commercial disposition",
        )
        next_action = _enum(
            NextActionCode, proposal.proposed_next_action, "proposed next action"
        )
        try:
            event, created = self.store.append_event(
                event_type="call_analysis_draft_recorded",
                aggregate_type="call_session",
                aggregate_id=proposal.call_session_id,
                producer=_PRODUCER,
                idempotency_key=f"analysis-draft:{proposal.draft_id}",
                payload=_evidenced(
                    {
                        "call_session_id": proposal.call_session_id,
                        "draft_id": proposal.draft_id,
                        "transcript_set_sha256": proposal.transcript_set_sha256,
                        "analysis_sha256": proposal.analysis_sha256,
                        "prompt_version": proposal.prompt_version,
                        "model_id": proposal.model_id,
                        "confidence_bps": proposal.confidence_bps,
                        "proposed_commercial_disposition": disposition.value,
                        "proposed_next_action": next_action.value,
                        "proposed_next_action_at_utc": _optional_utc(
                            proposal.proposed_next_action_at_utc,
                            "proposed next action timestamp",
                        ),
                        "flags": list(proposal.flags),
                        "evidence_spans_sha256": proposal.evidence_spans_sha256,
                    },
                    proposal.evidence_ref,
                ),
                evidence_ref=proposal.evidence_ref,
                actor="call_analysis_pipeline",
            )
        except IdempotencyConflict as exc:
            raise OperatorCallWorkflowConflict(str(exc)) from None
        return self._result(
            proposal.call_session_id,
            event,
            created,
            self.snapshot(proposal.call_session_id).state,
        )

    def confirm_disposition(
        self, confirmation: OperatorCallConfirmation
    ) -> CallWorkflowResult:
        if type(confirmation) is not OperatorCallConfirmation:
            raise ValueError("operator confirmation is invalid")
        technical = _enum(
            TechnicalDisposition,
            confirmation.technical_disposition,
            "technical disposition",
        )
        commercial = _enum(
            CommercialDisposition,
            confirmation.commercial_disposition,
            "commercial disposition",
        )
        next_action = _enum(NextActionCode, confirmation.next_action, "next action")
        notice = _enum(
            RecordingNoticeStatus,
            confirmation.recording_notice_status,
            "recording notice status",
        )
        next_at = _optional_utc(confirmation.next_action_at_utc, "next action timestamp")
        next_owner = str(confirmation.next_action_owner or "").strip()
        reason_code = str(confirmation.reason_code or "").strip()
        review_reasons: list[str] = []
        if confirmation.request_gold_review:
            review_reasons.append("GOLD_REVIEW")
        if confirmation.request_suppression_review:
            review_reasons.append("SUPPRESSION_REVIEW")
        if commercial is CommercialDisposition.COMPLAINT:
            review_reasons.append("COMPLAINT_REVIEW")
        if notice is RecordingNoticeStatus.UNKNOWN:
            review_reasons.append("RECORDING_NOTICE_REVIEW")

        try:
            with self.store.transaction() as con:
                rows = self._rows_tx(con, confirmation.call_session_id)
                bindings = [
                    _payload(row)
                    for row in rows
                    if row["event_type"] == "call_bitrix_activity_bound"
                ]
                if len(bindings) != 1:
                    raise OperatorCallBindingRequired(
                        "operator confirmation requires one exact Bitrix binding"
                    )
                binding = bindings[0]
                task_id = str(binding["lf_task_id"])
                prior_confirmations = [
                    _payload(row)
                    for row in rows
                    if row["event_type"] == "operator_call_disposition_confirmed"
                ]
                versions = [
                    int(item.get("confirmation_version", 0))
                    for item in prior_confirmations
                ]
                if len(versions) != len(set(versions)):
                    raise OperatorCallWorkflowError(
                        "persisted operator confirmation versions are invalid"
                    )
                latest = max(versions, default=0)
                if confirmation.confirmation_version > latest + 1:
                    raise OperatorCallWorkflowConflict(
                        "operator confirmation version has a gap"
                    )
                if confirmation.confirmation_version < latest:
                    raise OperatorCallWorkflowConflict(
                        "operator confirmation version is stale"
                    )
                prior_confirmation = next(
                    (
                        item
                        for item in prior_confirmations
                        if int(item.get("confirmation_version", 0))
                        == confirmation.confirmation_version
                    ),
                    None,
                )
                replay = prior_confirmation is not None
                reassignments = [
                    _payload(row)
                    for row in rows
                    if row["event_type"] == "call_operator_reassigned"
                ]
                effective_actor = self._effective_operator(binding, reassignments)
                if replay:
                    if (
                        str(prior_confirmation.get("operator_actor", ""))
                        != confirmation.operator_actor
                    ):
                        raise OperatorCallWorkflowConflict(
                            "operator confirmation replay actor is inconsistent"
                        )
                elif effective_actor != confirmation.operator_actor:
                    raise OperatorCallWorkflowError(
                        "only the currently assigned operator may confirm the call"
                    )

                if confirmation.draft_id and not replay:
                    drafts = {
                        str(payload.get("draft_id", "")): payload
                        for row in rows
                        if (payload := _payload(row))
                        if row["event_type"] == "call_analysis_draft_recorded"
                    }
                    draft = drafts.get(confirmation.draft_id)
                    if draft is None:
                        raise OperatorCallWorkflowError(
                            "analysis draft does not exist for call"
                        )
                    calls = [
                        _payload(row)
                        for row in rows
                        if row["event_type"] == "call_completed"
                    ]
                    recordings = [
                        _payload(row)
                        for row in rows
                        if row["event_type"] == "call_recording_ready"
                    ]
                    transcripts = [
                        _payload(row)
                        for row in rows
                        if row["event_type"] == "call_transcript_ready"
                    ]
                    current_set, _orphans, _pending, _orphan_recordings = (
                        self._transcript_set(
                            calls, recordings, transcripts, require_complete=True
                        )
                    )
                    if str(draft.get("transcript_set_sha256", "")) != current_set:
                        raise OperatorCallWorkflowConflict(
                            "analysis draft is stale for the current transcript set"
                        )

                if (
                    not replay
                    and any(
                        row["event_type"] == "call_recording_ready" for row in rows
                    )
                    and notice is RecordingNoticeStatus.NOT_APPLICABLE
                ):
                    raise OperatorCallWorkflowError(
                        "recording evidence requires a confirmed or reviewed notice status"
                    )
                persisted_review_reasons = {
                    str(_payload(row).get("reason", ""))
                    for row in rows
                    if row["event_type"] == "call_review_requested"
                }
                task = con.execute(
                    """SELECT *
                       FROM human_tasks WHERE lf_task_id=?""",
                    (task_id,),
                ).fetchone()
                if not task:
                    raise OperatorCallWorkflowError("bound human task does not exist")
                if str(task["lf_opportunity_id"] or "") != str(
                    binding["lf_opportunity_id"]
                ):
                    raise OperatorCallWorkflowConflict(
                        "call binding is stale after task scope change"
                    )
                if not replay and str(task["assigned_to"] or "") != effective_actor:
                    raise OperatorCallWorkflowConflict(
                        "call binding is stale after task reassignment"
                    )
                if not replay and str(task["status"]) in TERMINAL_STATES:
                    raise OperatorCallWorkflowConflict(
                        "terminal call confirmation cannot be revised in place"
                    )
                current_actor_binding = None
                if not replay:
                    try:
                        current_actor_binding = CrmActorBindingRegistry.resolve_verified_tx(
                            con,
                            connector="bitrix",
                            local_actor=effective_actor,
                        )
                    except (CrmActorBindingError, ValueError):
                        raise OperatorCallWorkflowError(
                            "assigned operator requires an exact verified Bitrix binding"
                        ) from None
                successor_binding = None
                if not replay and next_action is NextActionCode.CALL_BACK:
                    if next_owner == effective_actor:
                        successor_binding = current_actor_binding
                    else:
                        try:
                            successor_binding = (
                                CrmActorBindingRegistry.resolve_verified_tx(
                                    con,
                                    connector="bitrix",
                                    local_actor=next_owner,
                                )
                            )
                        except (CrmActorBindingError, ValueError):
                            raise OperatorCallWorkflowError(
                                "callback owner requires an exact verified Bitrix binding"
                            ) from None
                event, created = self.store._append_event_tx(
                    con,
                    event_type="operator_call_disposition_confirmed",
                    aggregate_type="call_session",
                    aggregate_id=confirmation.call_session_id,
                    producer=_PRODUCER,
                    idempotency_key=(
                        f"operator-confirmed:{confirmation.call_session_id}:"
                        f"{confirmation.confirmation_version}"
                    ),
                    payload=_evidenced(
                        {
                            "call_session_id": confirmation.call_session_id,
                            "bitrix_call_id": binding["bitrix_call_id"],
                            "crm_activity_id": binding["crm_activity_id"],
                            "lf_opportunity_id": binding["lf_opportunity_id"],
                            "lf_task_id": task_id,
                            "confirmation_version": confirmation.confirmation_version,
                            "operator_actor": confirmation.operator_actor,
                            "technical_disposition": technical.value,
                            "commercial_disposition": commercial.value,
                            "next_action": next_action.value,
                            "next_action_at_utc": next_at,
                            "next_action_owner": next_owner,
                            "reason_code": reason_code,
                            "request_gold_review": confirmation.request_gold_review,
                            "request_suppression_review": (
                                confirmation.request_suppression_review
                            ),
                            "recording_notice_status": notice.value,
                            "draft_id": confirmation.draft_id,
                            "review_reasons": review_reasons,
                        },
                        confirmation.evidence_ref,
                    ),
                    evidence_ref=confirmation.evidence_ref,
                    actor=confirmation.operator_actor,
                )
                if created:
                    for reason in review_reasons:
                        self.store._append_event_tx(
                            con,
                            event_type="call_review_requested",
                            aggregate_type="call_session",
                            aggregate_id=confirmation.call_session_id,
                            producer=_PRODUCER,
                            idempotency_key=(
                                f"call-review:{confirmation.call_session_id}:"
                                f"{confirmation.confirmation_version}:{reason}"
                            ),
                            payload=_evidenced(
                                {
                                    "confirmation_version": (
                                        confirmation.confirmation_version
                                    ),
                                    "reason": reason,
                                    "lf_opportunity_id": binding["lf_opportunity_id"],
                                    "lf_task_id": task_id,
                                },
                                confirmation.evidence_ref,
                            ),
                            evidence_ref=confirmation.evidence_ref,
                            actor=confirmation.operator_actor,
                            causation_id=str(event["event_id"]),
                        )
                    if next_action is NextActionCode.CALL_BACK:
                        if next_owner != effective_actor:
                            self.store._append_event_tx(
                                con,
                                event_type="call_operator_reassigned",
                                aggregate_type="call_session",
                                aggregate_id=confirmation.call_session_id,
                                producer=_PRODUCER,
                                idempotency_key=(
                                    f"call-operator-reassigned:"
                                    f"{confirmation.call_session_id}:"
                                    f"{confirmation.confirmation_version}"
                                ),
                                payload=_evidenced(
                                    {
                                        "confirmation_version": (
                                            confirmation.confirmation_version
                                        ),
                                        "lf_opportunity_id": binding[
                                            "lf_opportunity_id"
                                        ],
                                        "lf_task_id": task_id,
                                        "from_operator_actor": effective_actor,
                                        "to_operator_actor": next_owner,
                                        "crm_actor_binding_id": (
                                            successor_binding.binding_id
                                        ),
                                    },
                                    confirmation.evidence_ref,
                                ),
                                evidence_ref=confirmation.evidence_ref,
                                actor=confirmation.operator_actor,
                                causation_id=str(event["event_id"]),
                            )
                        updated = con.execute(
                            """UPDATE human_tasks
                               SET assigned_to=?,due_at_utc=?
                               WHERE lf_task_id=? AND assigned_to=? AND status=?""",
                            (
                                next_owner,
                                next_at,
                                task_id,
                                effective_actor,
                                str(task["status"]),
                            ),
                        )
                        if updated.rowcount != 1:
                            raise OperatorCallWorkflowConflict(
                                "callback task reassignment lost its state race"
                            )
                    elif (
                        next_action is NextActionCode.NONE
                        and not review_reasons
                        and not persisted_review_reasons
                    ):
                        self._complete_task_tx(
                            con,
                            task,
                            task_id=task_id,
                            actor=confirmation.operator_actor,
                            evidence_ref=confirmation.evidence_ref,
                            resolution=f"CALL:{commercial.value}",
                        )
        except IdempotencyConflict as exc:
            raise OperatorCallWorkflowConflict(str(exc)) from None
        except TaskStateError as exc:
            raise OperatorCallWorkflowError(str(exc)) from None
        return self._result(
            confirmation.call_session_id,
            event,
            created,
            self.snapshot(confirmation.call_session_id).state,
        )

    def reconcile_human_task(
        self, call_session_id: str
    ) -> tuple[TaskTransition, TaskTransition | None]:
        """Repair an interrupted event→task projection without external calls."""

        snapshot = self.snapshot(call_session_id)
        rows = self._rows(snapshot.call_session_id)
        bindings = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_bitrix_activity_bound"
        ]
        if len(bindings) != 1:
            raise OperatorCallBindingRequired(
                "human task reconciliation requires one exact Bitrix binding"
            )
        binding = bindings[0]
        task_id = str(binding["lf_task_id"])
        reassignments = [
            _payload(row)
            for row in rows
            if row["event_type"] == "call_operator_reassigned"
        ]
        actor = self._effective_operator(binding, reassignments)
        evidence = str(
            next(
                row["evidence_ref"]
                for row in reversed(rows)
                if row["event_type"] in {
                    "operator_call_disposition_confirmed",
                    "call_bitrix_activity_bound",
                }
            )
        )
        with self.store.transaction() as con:
            task = con.execute(
                "SELECT status,assigned_to FROM human_tasks WHERE lf_task_id=?",
                (task_id,),
            ).fetchone()
        if not task:
            raise OperatorCallWorkflowError("bound human task does not exist")
        if str(task["assigned_to"] or "") != actor:
            raise OperatorCallWorkflowConflict(
                "call binding is stale after task reassignment"
            )
        task_status = str(task["status"])
        first = (
            TaskTransition(task_id, task_status, False)
            if task_status in TERMINAL_STATES
            else self.tasks.record_first_action(
                task_id, actor=actor, evidence_ref=evidence
            )
        )
        confirmations = [
            _payload(row)
            for row in rows
            if row["event_type"] == "operator_call_disposition_confirmed"
        ]
        if not confirmations:
            return first, None
        latest = max(confirmations, key=lambda item: int(item["confirmation_version"]))
        has_pending_work = (
            str(latest["next_action"]) != NextActionCode.NONE.value
            or bool(latest.get("review_reasons"))
            or any(row["event_type"] == "call_review_requested" for row in rows)
        )
        if has_pending_work:
            return first, None
        completed = self.tasks.complete(
            task_id,
            actor=actor,
            evidence_ref=evidence,
            resolution=f"CALL:{latest['commercial_disposition']}",
        )
        return first, completed

    def snapshot(self, call_session_id: str) -> CallSessionSnapshot:
        session_id = _identifier(call_session_id, "call session id")
        rows = self._rows(session_id)
        if not rows:
            raise KeyError("call session does not exist")
        values = [(str(row["event_type"]), _payload(row)) for row in rows]
        calls = [value for event_type, value in values if event_type == "call_completed"]
        recordings = [
            value for event_type, value in values if event_type == "call_recording_ready"
        ]
        transcripts = [
            value for event_type, value in values if event_type == "call_transcript_ready"
        ]
        drafts = [
            value
            for event_type, value in values
            if event_type == "call_analysis_draft_recorded"
        ]
        bindings = [
            value
            for event_type, value in values
            if event_type == "call_bitrix_activity_bound"
        ]
        confirmations = [
            value
            for event_type, value in values
            if event_type == "operator_call_disposition_confirmed"
        ]
        (
            transcript_set,
            orphan_ids,
            _pending_ids,
            orphan_recording_ids,
        ) = self._transcript_set(
            calls, recordings, transcripts, require_complete=False
        )
        review_set = {
            str(value["reason"])
            for event_type, value in values
            if event_type == "call_review_requested"
        }
        requested_crm_reviews = {
            str(value.get("candidate_snapshot_sha256", ""))
            for event_type, value in values
            if event_type == "call_crm_binding_review_requested"
        }
        resolved_crm_reviews = {
            str(value.get("candidate_snapshot_sha256", ""))
            for event_type, value in values
            if event_type == "call_crm_binding_review_resolved"
        }
        if requested_crm_reviews - resolved_crm_reviews:
            review_set.add("CRM_BINDING_REVIEW")
        if bindings and orphan_ids:
            review_set.add("ORPHAN_TRANSCRIPT")
        if bindings and orphan_recording_ids:
            review_set.add("ORPHAN_RECORDING")
        if (
            bindings
            and drafts
            and str(drafts[-1].get("transcript_set_sha256", "")) != transcript_set
        ):
            review_set.add("STALE_ANALYSIS_DRAFT")
        reviews = sorted(review_set)
        binding = bindings[-1] if bindings else {}
        latest_confirmation = (
            max(confirmations, key=lambda item: int(item["confirmation_version"]))
            if confirmations
            else {}
        )

        if not bindings and reviews:
            state = CallWorkflowState.REVIEW_REQUIRED
        elif not bindings:
            state = (
                CallWorkflowState.UNBOUND_CALL
                if calls
                else CallWorkflowState.UNBOUND_EVIDENCE
            )
        elif reviews:
            state = CallWorkflowState.REVIEW_REQUIRED
        elif confirmations:
            state = (
                CallWorkflowState.REVIEW_REQUIRED
                if reviews
                else CallWorkflowState.OPERATOR_CONFIRMED
            )
        elif drafts:
            state = CallWorkflowState.ANALYSIS_DRAFT
        elif transcript_set:
            state = CallWorkflowState.TRANSCRIPT_READY
        elif recordings:
            state = CallWorkflowState.RECORDING_READY
        else:
            state = CallWorkflowState.BOUND

        first_payload = calls[0] if calls else (recordings[0] if recordings else transcripts[0])
        return CallSessionSnapshot(
            call_session_id=session_id,
            state=state,
            mango_entry_id=str(first_payload["mango_entry_id"]),
            call_count=len(calls),
            recording_count=len(recordings),
            transcript_count=len(transcripts),
            transcript_set_sha256=transcript_set,
            analysis_draft_count=len(drafts),
            confirmation_version=int(latest_confirmation.get("confirmation_version", 0)),
            lf_opportunity_id=str(binding.get("lf_opportunity_id", "")),
            lf_task_id=str(binding.get("lf_task_id", "")),
            bitrix_call_id=str(binding.get("bitrix_call_id", "")),
            crm_activity_id=str(binding.get("crm_activity_id", "")),
            review_reasons=tuple(reviews),
        )


__all__ = [
    "CallAnalysisProposal",
    "CallSessionSnapshot",
    "CallWorkflowResult",
    "CallWorkflowState",
    "CommercialDisposition",
    "NextActionCode",
    "OperatorCallBindingRequired",
    "OperatorCallConfirmation",
    "OperatorCallWorkflow",
    "OperatorCallWorkflowConflict",
    "OperatorCallWorkflowError",
    "RecordingNoticeStatus",
    "TechnicalDisposition",
]
