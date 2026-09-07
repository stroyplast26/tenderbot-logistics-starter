"""Offline operational queue for immutable Source Lab reviews.

The queue is an additive schema-17 read model over Source Lab and the existing
append-only Event Store.  It performs no network I/O and grants no production
identity authority.  A lease only coordinates authenticated callers supplied
by a future controller; it is not a live-access permit.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import sqlite3
from typing import Any, Callable, Mapping

from .ids import canonical_json, new_lf_id, payload_hash
from .source_lab import (
    SourceLabResolutionResult,
    SourceLabSink,
    SourceLabValidationError,
    strict_json_dumps,
)
from .store import FactoryStore


QUEUE_PRODUCER = "source_lab_review_queue"
QUEUE_SCHEMA_VERSION = 17
MIN_LEASE_SECONDS = 30
MAX_LEASE_SECONDS = 86_400
MAX_PAGE_SIZE = 100

_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_DECISIONS = frozenset({"APPROVE", "REJECT", "HOLD"})
_QUEUE_DECISIONS = _TERMINAL_DECISIONS | {"NEEDS_RESEARCH"}
_CLAIM_ACTIONS = frozenset({"CLAIM", "ASSIGN", "RECLAIM", "REASSIGN"})
_ASSIGN_REASON_CODES = frozenset(
    {
        "MANUAL_ASSIGNMENT",
        "SLA_TASK_ASSIGNMENT",
        "REVIEW_ASSIGNMENT",
        "WORKLOAD_REBALANCE",
        "NEEDS_RESEARCH_ASSIGNMENT",
    }
)
_EVENT_TYPE_BY_ACTION = {
    "CLAIM": "source_lab_review_claimed",
    "ASSIGN": "source_lab_review_assigned",
    "RECLAIM": "source_lab_review_reclaimed",
    "REASSIGN": "source_lab_review_reassigned",
    "RESOLUTION_RECORDED": "source_lab_review_resolution_recorded",
}
_QUEUE_EVENT_TYPES = frozenset(_EVENT_TYPE_BY_ACTION.values())
_TASK_PRECLAIM_STATES = frozenset({"OPEN", "ASSIGNED"})
_TASK_CLAIMED_STATES = frozenset({"ACKNOWLEDGED", "IN_PROGRESS"})
_TASK_TERMINAL_STATES = frozenset(
    {"COMPLETED", "CANCELLED", "CLOSED_LEGACY_HANDLED"}
)


class SourceReviewQueueError(RuntimeError):
    """Base error with messages safe for an offline operator."""


class SourceReviewQueueValidationError(SourceReviewQueueError):
    """The requested queue operation is malformed."""


class SourceReviewQueueConflict(SourceReviewQueueError):
    """An immutable identity or stale expected state was reused."""


class SourceReviewQueueUnavailable(SourceReviewQueueError):
    """The review cannot be claimed in its current state."""


class SourceReviewQueueStaleClaim(SourceReviewQueueError):
    """A claim is expired, fenced, restored, or owned by somebody else."""


class SourceReviewQueueIntegrityError(SourceReviewQueueError):
    """Stored queue history is not a complete append-only chain."""


@dataclass(frozen=True, slots=True, repr=False)
class ReviewClaimPermit:
    created: bool
    active: bool
    action: str
    review_id: str
    claim_event_id: str
    assignee: str
    fence: int
    lease_token: str
    issued_at_utc: str
    lease_until_utc: str
    source_read_epoch_hash: str
    review_digest: str

    def __repr__(self) -> str:
        return (
            "ReviewClaimPermit("
            f"created={self.created!r}, active={self.active!r}, "
            f"action={self.action!r}, review_id={self.review_id!r}, "
            f"assignee={self.assignee!r}, fence={self.fence!r})"
        )


@dataclass(frozen=True, slots=True)
class ReviewQueueResolutionResult:
    created: bool
    review_id: str
    decision: str
    resolution_id: str
    resolution_event_id: str
    sequence_number: int
    queue_event_id: str

    @property
    def event_id(self) -> str:
        """Compatibility name for the immutable Source Lab resolution event."""

        return self.resolution_event_id


@dataclass(frozen=True, slots=True, repr=False)
class ReviewQueueItem:
    review_id: str
    source_record_id: str
    source_id: str
    review_kind: str
    reason: str
    requested_by: str
    evidence_ref: str
    requested_at_utc: str
    record_payload_hash: str
    state: str
    state_digest: str
    assignee: str
    queue_revision: int
    head_event_id: str
    claim_event_id: str
    fence: int
    lease_until_utc: str
    latest_resolution_id: str
    latest_decision: str
    latest_resolution_reason: str
    latest_resolved_by: str
    task_id: str
    task_kind: str
    task_assigned_to: str
    task_due_at_utc: str

    def __repr__(self) -> str:
        return (
            "ReviewQueueItem("
            f"review_id={self.review_id!r}, source_id={self.source_id!r}, "
            f"review_kind={self.review_kind!r}, state={self.state!r}, "
            f"assignee={self.assignee!r})"
        )


@dataclass(frozen=True, slots=True)
class ReviewQueuePage:
    items: tuple[ReviewQueueItem, ...]
    next_cursor: str
    snapshot_event_id: str
    snapshot_event_rowid: int
    as_of_utc: str


@dataclass(frozen=True, slots=True)
class _Projection:
    review: sqlite3.Row
    latest_resolution: sqlite3.Row | None
    review_digest: str
    state: str
    state_digest: str
    head: sqlite3.Row | None
    head_payload: Mapping[str, Any] | None
    assignee: str
    revision: int
    claim_event_id: str
    fence: int
    lease_until_utc: str


def _required(value: object, message: str, *, maximum: int = 512) -> str:
    normalized = str(value or "").strip()
    try:
        encoded = normalized.encode("utf-8", "strict")
    except UnicodeError:
        raise SourceReviewQueueValidationError(message) from None
    if (
        not normalized
        or len(normalized) > maximum
        or len(encoded) > maximum * 4
        or any(ord(character) < 32 for character in normalized)
    ):
        raise SourceReviewQueueValidationError(message)
    return normalized


def _optional(value: object, message: str, *, maximum: int = 128) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    return _required(normalized, message, maximum=maximum)


def _principal(value: object, message: str) -> str:
    normalized = _required(value, message, maximum=128)
    if not _PRINCIPAL.fullmatch(normalized):
        raise SourceReviewQueueValidationError(message)
    return normalized


def _reason_code(value: object, message: str) -> str:
    normalized = _required(value, message, maximum=64).upper()
    if not _REASON_CODE.fullmatch(normalized):
        raise SourceReviewQueueValidationError(message)
    return normalized


def _evidence_ref(value: object) -> str:
    evidence = _required(value, "review queue evidence is required", maximum=2048)
    if any(character.isspace() for character in evidence):
        raise SourceReviewQueueValidationError("review queue evidence is invalid")
    return evidence


def _lease_seconds(value: object) -> int:
    if type(value) is not int or not MIN_LEASE_SECONDS <= value <= MAX_LEASE_SECONDS:
        raise SourceReviewQueueValidationError("review queue lease is outside its limit")
    return value


def _timestamp(value: object, message: str) -> tuple[str, datetime]:
    raw = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise SourceReviewQueueValidationError(message) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceReviewQueueValidationError(message)
    parsed = parsed.astimezone(timezone.utc)
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), parsed


def _clock_now(clock: Callable[[], datetime]) -> tuple[str, datetime]:
    try:
        value = clock()
    except Exception:
        raise SourceReviewQueueValidationError("review queue clock is unavailable") from None
    _rendered, parsed = _timestamp(
        value.isoformat() if isinstance(value, datetime) else value,
        "review queue clock must be UTC-aware",
    )
    # Source Lab and the commercial approval contract use canonical UTC
    # seconds.  Dropping sub-second jitter here keeps queue-owned resolution
    # facts consumable without weakening chronological or lease fencing.
    parsed = parsed.replace(microsecond=0)
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z"), parsed


def _canonical_object(value: object, message: str) -> dict[str, Any]:
    def reject_constant(_: str) -> object:
        raise ValueError("non-finite")

    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            str(value or ""),
            parse_constant=reject_constant,
            object_pairs_hook=exact_object,
        )
        canonical = strict_json_dumps(parsed)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError, SourceLabValidationError) as exc:
        raise SourceReviewQueueIntegrityError(message) from exc
    if type(parsed) is not dict or canonical != str(value):
        raise SourceReviewQueueIntegrityError(message)
    return parsed


def _epoch_hash_tx(con: sqlite3.Connection) -> str:
    row = con.execute(
        "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
    ).fetchone()
    value = str(row[0] if row else "")
    if not re.fullmatch(r"[0-9]{32}", value):
        raise SourceReviewQueueIntegrityError("review queue epoch is unavailable")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _review_row_tx(con: sqlite3.Connection, review_id: str) -> sqlite3.Row:
    row = con.execute(
        """SELECT r.*,s.source_id,s.payload_hash AS record_payload_hash,
                  e.rowid AS request_event_rowid,
                  e.occurred_at_utc AS request_event_occurred_at_utc,
                  e.recorded_at_utc AS request_event_recorded_at_utc
           FROM source_lab_reviews r
           JOIN source_lab_records s ON s.source_record_id=r.source_record_id
           JOIN events e ON e.event_id=r.event_id
           WHERE r.review_id=?""",
        (review_id,),
    ).fetchone()
    if not row:
        raise SourceReviewQueueValidationError("review does not exist")
    return row


def _latest_resolution_tx(
    con: sqlite3.Connection,
    review_id: str,
    *,
    max_event_rowid: int | None = None,
    before_sequence: int | None = None,
) -> sqlite3.Row | None:
    clauses = ["rr.review_id=?"]
    values: list[object] = [review_id]
    if max_event_rowid is not None:
        clauses.append("e.rowid<=?")
        values.append(int(max_event_rowid))
    if before_sequence is not None:
        clauses.append("rr.sequence_number<?")
        values.append(int(before_sequence))
    return con.execute(
        """SELECT rr.*,e.rowid AS resolution_event_rowid
           FROM source_lab_review_resolutions rr
           JOIN events e ON e.event_id=rr.event_id
           WHERE """
        + " AND ".join(clauses)
        + " ORDER BY rr.sequence_number DESC LIMIT 1",
        tuple(values),
    ).fetchone()


def _review_digest(review: sqlite3.Row, latest: sqlite3.Row | None) -> str:
    return payload_hash(
        {
            "source_review_queue_review_digest_version": 1,
            "review_id": str(review["review_id"]),
            "source_record_id": str(review["source_record_id"]),
            "source_id": str(review["source_id"]),
            "record_payload_hash": str(review["record_payload_hash"]),
            "review_kind": str(review["review_kind"]),
            "review_command_hash": str(review["command_hash"]),
            "review_event_id": str(review["event_id"]),
            "latest_resolution_id": str(latest["resolution_id"]) if latest else "",
            "latest_resolution_sequence": int(latest["sequence_number"]) if latest else 0,
            "latest_resolution_decision": str(latest["decision"]) if latest else "",
            "latest_resolution_command_hash": str(latest["command_hash"]) if latest else "",
            "latest_resolution_event_id": str(latest["event_id"]) if latest else "",
        }
    )


def _claim_active(payload: Mapping[str, Any], now: datetime, epoch_hash: str) -> bool:
    if str(payload.get("source_read_epoch_hash", "")) != epoch_hash:
        return False
    _, expires = _timestamp(payload.get("lease_until_utc"), "review queue lease timestamp is invalid")
    return now < expires


def _projection_state(
    *,
    latest: sqlite3.Row | None,
    head_payload: Mapping[str, Any] | None,
    now: datetime,
    epoch_hash: str,
) -> str:
    if head_payload is None:
        if latest is None:
            return "OPEN_UNASSIGNED"
        if str(latest["decision"]) == "NEEDS_RESEARCH":
            return "NEEDS_RESEARCH"
        return "RESOLVED"
    action = str(head_payload.get("action", ""))
    if action in _CLAIM_ACTIONS:
        return "CLAIMED" if _claim_active(head_payload, now, epoch_hash) else "RECLAIMABLE"
    if action == "RESOLUTION_RECORDED":
        return (
            "NEEDS_RESEARCH"
            if str(head_payload.get("decision", "")) == "NEEDS_RESEARCH"
            else "RESOLVED"
        )
    raise SourceReviewQueueIntegrityError("review queue action is invalid")


def _state_digest(
    *,
    review_digest: str,
    state: str,
    head: sqlite3.Row | None,
    head_payload: Mapping[str, Any] | None,
    epoch_hash: str,
) -> str:
    return payload_hash(
        {
            "source_review_queue_state_digest_version": 1,
            "review_digest": review_digest,
            "state": state,
            "head_event_id": str(head["event_id"]) if head else "",
            "head_payload_hash": str(head["payload_hash"]) if head else "",
            "queue_revision": int(head_payload.get("revision", 0)) if head_payload else 0,
            "assignee": str(head_payload.get("assignee", "")) if head_payload else "",
            "claim_event_id": (
                str(head["event_id"])
                if head and str(head_payload.get("action", "")) in _CLAIM_ACTIONS
                else str(head_payload.get("claim_event_id", "")) if head_payload else ""
            ),
            "fence": int(head_payload.get("fence", head_payload.get("claim_fence", 0)))
            if head_payload
            else 0,
            "lease_until_utc": str(head_payload.get("lease_until_utc", ""))
            if head_payload
            else "",
            "source_read_epoch_hash": epoch_hash,
        }
    )


def _queue_rows_tx(
    con: sqlite3.Connection,
    *,
    review_id: str | None = None,
    max_event_rowid: int | None = None,
) -> list[sqlite3.Row]:
    placeholders = ",".join("?" for _ in _QUEUE_EVENT_TYPES)
    values: list[object] = [QUEUE_PRODUCER, *sorted(_QUEUE_EVENT_TYPES)]
    clauses = [
        "(producer=? OR event_type IN ("
        + placeholders
        + ") OR payload_json LIKE '%\"queue_event_version\":1%'"
        + " OR (schema_version=17 AND aggregate_id IN "
        + "(SELECT review_id FROM source_lab_reviews))"
        + " OR (schema_version=17 AND correlation_id IN "
        + "(SELECT event_id FROM source_lab_reviews))"
        + " OR ((idempotency_key LIKE 'claim:%'"
        + " OR idempotency_key LIKE 'assign:%'"
        + " OR idempotency_key LIKE 'reclaim:%'"
        + " OR idempotency_key LIKE 'resolve:%') AND ("
        + "aggregate_id IN (SELECT review_id FROM source_lab_reviews)"
        + " OR correlation_id IN (SELECT event_id FROM source_lab_reviews))))"
    ]
    clauses.append(
        "NOT (producer='human_task_controller'"
        " AND event_type IN ('human_task_acknowledged',"
        " 'human_task_first_action','human_task_completed')"
        " AND aggregate_type='task'"
        " AND idempotency_key LIKE 'task-state:%')"
    )
    if review_id is not None:
        clauses.append("aggregate_id=?")
        values.append(review_id)
    if max_event_rowid is not None:
        clauses.append("rowid<=?")
        values.append(int(max_event_rowid))
    return con.execute(
        "SELECT rowid AS queue_event_rowid,* FROM events WHERE "
        + " AND ".join(clauses)
        + " ORDER BY rowid,event_id",
        tuple(values),
    ).fetchall()


def _claim_command_hash(payload: Mapping[str, Any], evidence_ref: str) -> str:
    return payload_hash(
        {
            "source_review_queue_claim_command_version": 1,
            "requested_operation": str(payload["requested_operation"]),
            "review_id": str(payload["review_id"]),
            "assignee": str(payload["assignee"]),
            "actor": str(payload["actor"]),
            "reason_code": str(payload["reason_code"]),
            "lease_seconds": int(payload["lease_seconds"]),
            "evidence_ref": evidence_ref,
            "expected_state_digest": str(payload["expected_state_digest"]),
            "previous_claim_event_id": str(payload["previous_claim_event_id"]),
            "idempotency_key_hash": str(payload["idempotency_key_hash"]),
        }
    )


def _resolution_command_hash(
    payload: Mapping[str, Any],
    resolution: sqlite3.Row,
    evidence_ref: str,
) -> str:
    return payload_hash(
        {
            "source_review_queue_resolution_command_version": 1,
            "review_id": str(payload["review_id"]),
            "claim_event_id": str(payload["claim_event_id"]),
            "claim_fence": int(payload["claim_fence"]),
            "lease_token_hash": str(payload["lease_token_hash"]),
            "decision": str(payload["decision"]),
            "reason": str(resolution["reason"]),
            "resolved_by": str(payload["resolved_by"]),
            "evidence_ref": evidence_ref,
            "idempotency_key_hash": str(payload["idempotency_key_hash"]),
        }
    )


def _expected_claim_keys() -> set[str]:
    return {
        "queue_event_version",
        "action",
        "requested_operation",
        "review_id",
        "review_digest",
        "expected_state_digest",
        "revision",
        "previous_event_id",
        "previous_payload_hash",
        "source_read_epoch_hash",
        "assignee",
        "actor",
        "reason_code",
        "fence",
        "lease_token",
        "issued_at_utc",
        "lease_until_utc",
        "lease_seconds",
        "command_hash",
        "previous_claim_event_id",
        "idempotency_key_hash",
    }


def _expected_resolution_keys() -> set[str]:
    return {
        "queue_event_version",
        "action",
        "review_id",
        "review_digest",
        "resolved_review_digest",
        "expected_state_digest",
        "revision",
        "previous_event_id",
        "previous_payload_hash",
        "source_read_epoch_hash",
        "claim_event_id",
        "claim_payload_hash",
        "claim_fence",
        "lease_token_hash",
        "resolved_by",
        "decision",
        "resolution_id",
        "resolution_sequence",
        "resolution_event_id",
        "resolution_command_hash",
        "recorded_at_utc",
        "command_hash",
        "idempotency_key_hash",
    }


def _payload_types_are_exact(payload: Mapping[str, Any], action: str) -> bool:
    integer_keys = {"queue_event_version", "revision"}
    if action in _CLAIM_ACTIONS:
        integer_keys.update({"fence", "lease_seconds"})
        expected_keys = _expected_claim_keys()
    elif action == "RESOLUTION_RECORDED":
        integer_keys.update({"claim_fence", "resolution_sequence"})
        expected_keys = _expected_resolution_keys()
    else:
        return False
    return all(
        type(payload[key]) is int if key in integer_keys else type(payload[key]) is str
        for key in expected_keys
    )


def _validate_review_base(con: sqlite3.Connection, review: sqlite3.Row) -> None:
    expected_command = payload_hash(
        {
            "source_lab_review_version": 1,
            "source_record_id": str(review["source_record_id"]),
            "review_kind": str(review["review_kind"]),
            "reason": str(review["reason"]),
            "requested_by": str(review["requested_by"]),
            "evidence_ref": str(review["evidence_ref"]),
        }
    )
    event = con.execute("SELECT * FROM events WHERE event_id=?", (review["event_id"],)).fetchone()
    if (
        str(review["command_hash"]) != expected_command
        or not event
        or str(event["event_type"]) != "source_lab_review_requested"
        or str(event["producer"]) != "source_lab"
        or str(event["aggregate_type"]) != "source_lab_review"
        or str(event["aggregate_id"]) != str(review["review_id"])
    ):
        raise SourceReviewQueueIntegrityError("review queue review binding is invalid")


def _validate_queue_material(
    con: sqlite3.Connection,
) -> tuple[list[dict[str, object]], tuple[str, ...]]:
    rows = _queue_rows_tx(con)
    if not rows:
        return [], ()
    user_version = int(con.execute("PRAGMA user_version").fetchone()[0])
    meta_row = con.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    try:
        meta_version = int(str(meta_row[0] if meta_row else ""))
    except ValueError:
        meta_version = -1
    if (
        user_version < QUEUE_SCHEMA_VERSION
        or meta_version < QUEUE_SCHEMA_VERSION
        or user_version != meta_version
    ):
        raise SourceReviewQueueIntegrityError(
            "review queue events require authoritative schema 17"
        )
    by_review: dict[str, list[tuple[sqlite3.Row, dict[str, Any]]]] = {}
    event_ids: list[str] = []
    for row in rows:
        event_id = str(row["event_id"])
        payload = _canonical_object(
            row["payload_json"], "review queue event payload is invalid"
        )
        _evidence_ref(row["evidence_ref"])
        action = str(payload.get("action", ""))
        expected_type = _EVENT_TYPE_BY_ACTION.get(action)
        expected_keys = (
            _expected_claim_keys() if action in _CLAIM_ACTIONS
            else _expected_resolution_keys() if action == "RESOLUTION_RECORDED"
            else set()
        )
        if (
            not expected_type
            or set(payload) != expected_keys
            or not _payload_types_are_exact(payload, action)
            or payload.get("queue_event_version") != 1
            or str(row["producer"]) != QUEUE_PRODUCER
            or str(row["event_type"]) != expected_type
            or str(row["aggregate_type"]) != "source_lab_review"
            or str(row["aggregate_id"]) != str(payload.get("review_id", ""))
            or int(row["schema_version"]) != QUEUE_SCHEMA_VERSION
            or str(row["payload_hash"]) != payload_hash(payload)
            or str(row["actor"]) != str(payload.get("actor", payload.get("resolved_by", "")))
            or str(row["correlation_id"]) == ""
            or not _HEX64.fullmatch(str(payload.get("source_read_epoch_hash", "")))
            or not _HEX64.fullmatch(str(payload.get("review_digest", "")))
            or not _HEX64.fullmatch(str(payload.get("expected_state_digest", "")))
            or not _HEX64.fullmatch(str(payload.get("command_hash", "")))
        ):
            raise SourceReviewQueueIntegrityError("review queue event envelope is invalid")
        review_id = str(payload["review_id"])
        by_review.setdefault(review_id, []).append((row, payload))
        event_ids.append(event_id)

    ledger: list[dict[str, object]] = []
    for review_id, chain in by_review.items():
        review = _review_row_tx(con, review_id)
        _validate_review_base(con, review)
        chain.sort(key=lambda item: int(item[1].get("revision", -1)))
        previous_row: sqlite3.Row | None = None
        previous_payload: dict[str, Any] | None = None
        claim_fence = 0
        for expected_revision, (row, payload) in enumerate(chain, start=1):
            action = str(payload["action"])
            event_id = str(row["event_id"])
            occurred_text, occurred = _timestamp(
                row["occurred_at_utc"], "review queue event timestamp is invalid"
            )
            _, requested_at = _timestamp(
                review["request_event_occurred_at_utc"],
                "review queue request timestamp is invalid",
            )
            previous_event_id = str(previous_row["event_id"]) if previous_row else ""
            previous_payload_hash = str(previous_row["payload_hash"]) if previous_row else ""
            causation = previous_event_id or str(review["event_id"])
            previous_time = None
            if previous_row is not None:
                _, previous_time = _timestamp(
                    previous_row["occurred_at_utc"],
                    "review queue event timestamp is invalid",
                )
            if (
                int(payload["revision"]) != expected_revision
                or str(payload["previous_event_id"]) != previous_event_id
                or str(payload["previous_payload_hash"]) != previous_payload_hash
                or str(row["causation_id"]) != causation
                or str(row["correlation_id"]) != str(review["event_id"])
                or (
                    previous_row is not None
                    and int(row["queue_event_rowid"])
                    <= int(previous_row["queue_event_rowid"])
                )
                or (
                    previous_row is None
                    and int(row["queue_event_rowid"])
                    <= int(review["request_event_rowid"])
                )
                or (previous_time is not None and occurred < previous_time)
                or occurred < requested_at
            ):
                raise SourceReviewQueueIntegrityError("review queue event chain is invalid")

            if action in _CLAIM_ACTIONS:
                latest = _latest_resolution_tx(
                    con, review_id, max_event_rowid=int(row["queue_event_rowid"]) - 1
                )
                review_digest = _review_digest(review, latest)
                prior_state = _projection_state(
                    latest=latest,
                    head_payload=previous_payload,
                    now=occurred,
                    epoch_hash=str(payload["source_read_epoch_hash"]),
                )
                prior_digest = _state_digest(
                    review_digest=review_digest,
                    state=prior_state,
                    head=previous_row,
                    head_payload=previous_payload,
                    epoch_hash=str(payload["source_read_epoch_hash"]),
                )
                requested = str(payload["requested_operation"])
                actor = str(payload["actor"])
                assignee = str(payload["assignee"])
                seconds = int(payload["lease_seconds"])
                issued_text, issued = _timestamp(
                    payload["issued_at_utc"], "review queue lease timestamp is invalid"
                )
                until_text, until = _timestamp(
                    payload["lease_until_utc"], "review queue lease timestamp is invalid"
                )
                expected_action = (
                    "RECLAIM" if requested == "RECLAIM" and actor == assignee
                    else "REASSIGN" if requested == "RECLAIM"
                    else "CLAIM" if requested == "CLAIM"
                    else "ASSIGN" if requested == "ASSIGN"
                    else ""
                )
                expected_reclaim_code = (
                    "RESTORE_EPOCH_FENCED"
                    if previous_payload is not None
                    and str(previous_payload.get("source_read_epoch_hash", ""))
                    != str(payload["source_read_epoch_hash"])
                    else "LEASE_EXPIRED"
                )
                task = _task_binding_tx(con, review)
                task_ack = None
                task_ack_time = None
                if task is not None:
                    task_ack = _task_state_event_tx(
                        con,
                        task_id=str(task["lf_task_id"]),
                        state="ACKNOWLEDGED",
                    )
                    _validate_task_state_event(
                        task_ack,
                        task_id=str(task["lf_task_id"]),
                        state="ACKNOWLEDGED",
                        actor=assignee,
                    )
                    _, task_ack_time = _timestamp(
                        task_ack["occurred_at_utc"],
                        "review queue task acknowledgement is invalid",
                    )
                if (
                    str(payload["review_digest"]) != review_digest
                    or str(payload["expected_state_digest"]) != prior_digest
                    or occurred_text != issued_text
                    or until != issued + timedelta(seconds=seconds)
                    or not MIN_LEASE_SECONDS <= seconds <= MAX_LEASE_SECONDS
                    or not _PRINCIPAL.fullmatch(actor)
                    or not _PRINCIPAL.fullmatch(assignee)
                    or not _REASON_CODE.fullmatch(str(payload["reason_code"]))
                    or not _required_token(str(payload["lease_token"]))
                    or action != expected_action
                    or str(payload["command_hash"])
                    != _claim_command_hash(payload, str(row["evidence_ref"]))
                    or not _valid_event_idempotency(
                        row["idempotency_key"], requested.lower()
                    )
                    or str(payload["idempotency_key_hash"])
                    != _event_idempotency_hash(row["idempotency_key"])
                    or assignee == str(review["requested_by"])
                    or (task is not None and str(task["assigned_to"]) != assignee)
                    or (
                        task is not None
                        and (requested not in {"CLAIM", "RECLAIM"} or actor != assignee)
                    )
                    or (
                        task_ack is not None
                        and (
                            int(task_ack["task_event_rowid"])
                            >= int(row["queue_event_rowid"])
                            or task_ack_time is None
                            or task_ack_time < requested_at
                            or task_ack_time > occurred
                        )
                    )
                    or (
                        requested == "RECLAIM"
                        and str(payload["previous_claim_event_id"])
                        != previous_event_id
                    )
                    or (
                        requested in {"CLAIM", "ASSIGN"}
                        and str(payload["previous_claim_event_id"])
                    )
                    or (
                        requested in {"CLAIM", "ASSIGN"}
                        and prior_state not in {"OPEN_UNASSIGNED", "NEEDS_RESEARCH"}
                    )
                    or (requested == "CLAIM" and actor != assignee)
                    or (
                        requested == "CLAIM"
                        and str(payload["reason_code"]) != "SELF_CLAIM"
                    )
                    or (
                        requested == "ASSIGN"
                        and str(payload["reason_code"]) not in _ASSIGN_REASON_CODES
                    )
                    or (requested == "RECLAIM" and prior_state != "RECLAIMABLE")
                    or (
                        requested == "RECLAIM"
                        and str(payload["reason_code"]) != expected_reclaim_code
                    )
                ):
                    raise SourceReviewQueueIntegrityError("review queue claim proof is invalid")
                claim_fence += 1
                if int(payload["fence"]) != claim_fence:
                    raise SourceReviewQueueIntegrityError("review queue claim fence is invalid")
            else:
                resolution = con.execute(
                    """SELECT rr.*,e.rowid AS resolution_event_rowid,
                              e.occurred_at_utc AS resolution_event_occurred_at_utc
                       FROM source_lab_review_resolutions rr
                       JOIN events e ON e.event_id=rr.event_id
                       WHERE rr.resolution_id=?""",
                    (str(payload["resolution_id"]),),
                ).fetchone()
                if not resolution:
                    raise SourceReviewQueueIntegrityError("review queue resolution is missing")
                pre_latest = _latest_resolution_tx(
                    con,
                    review_id,
                    before_sequence=int(resolution["sequence_number"]),
                )
                review_digest = _review_digest(review, pre_latest)
                prior_state = _projection_state(
                    latest=pre_latest,
                    head_payload=previous_payload,
                    now=occurred,
                    epoch_hash=str(payload["source_read_epoch_hash"]),
                )
                prior_digest = _state_digest(
                    review_digest=review_digest,
                    state=prior_state,
                    head=previous_row,
                    head_payload=previous_payload,
                    epoch_hash=str(payload["source_read_epoch_hash"]),
                )
                resolved_digest = _review_digest(review, resolution)
                if (
                    previous_row is None
                    or previous_payload is None
                    or str(previous_payload.get("action", "")) not in _CLAIM_ACTIONS
                    or prior_state != "CLAIMED"
                    or str(payload["review_digest"]) != review_digest
                    or str(payload["resolved_review_digest"]) != resolved_digest
                    or str(payload["expected_state_digest"]) != prior_digest
                    or str(payload["claim_event_id"]) != str(previous_row["event_id"])
                    or str(payload["claim_payload_hash"]) != str(previous_row["payload_hash"])
                    or int(payload["claim_fence"]) != int(previous_payload["fence"])
                    or str(payload["lease_token_hash"])
                    != payload_hash({"lease_token": str(previous_payload["lease_token"])})
                    or str(payload["resolved_by"]) != str(previous_payload["assignee"])
                    or str(payload["decision"]) != str(resolution["decision"])
                    or str(payload["decision"]) not in _QUEUE_DECISIONS
                    or str(payload["resolution_id"]) != str(resolution["resolution_id"])
                    or int(payload["resolution_sequence"]) != int(resolution["sequence_number"])
                    or str(payload["resolution_event_id"]) != str(resolution["event_id"])
                    or int(resolution["resolution_event_rowid"])
                    >= int(row["queue_event_rowid"])
                    or str(resolution["resolution_event_occurred_at_utc"])
                    != occurred_text
                    or str(resolution["created_at_utc"]) != occurred_text
                    or str(payload["resolution_command_hash"]) != str(resolution["command_hash"])
                    or str(payload["recorded_at_utc"]) != occurred_text
                    or str(payload["command_hash"])
                    != _resolution_command_hash(payload, resolution, str(row["evidence_ref"]))
                    or not _valid_event_idempotency(
                        row["idempotency_key"], "resolve"
                    )
                    or str(payload["idempotency_key_hash"])
                    != _event_idempotency_hash(row["idempotency_key"])
                ):
                    raise SourceReviewQueueIntegrityError("review queue resolution proof is invalid")
            previous_row = row
            previous_payload = payload
            ledger.append(
                {
                    "kind": "review_queue_event",
                    "id": event_id,
                    "hash": str(row["payload_hash"]),
                }
            )
            ledger.append(
                {
                    "kind": "full_row:events",
                    "id": event_id,
                    "hash": payload_hash(
                        {
                            key: row[key]
                            for key in row.keys()
                            if key != "queue_event_rowid"
                        }
                    ),
                }
            )

        task = _task_binding_tx(con, review)
        if task is not None:
            first_claim_row, first_claim_payload = next(
                (item for item in chain if str(item[1]["action"]) in _CLAIM_ACTIONS),
                (None, None),
            )
            if first_claim_row is None or first_claim_payload is None:
                raise SourceReviewQueueIntegrityError(
                    "review queue task has no claim proof"
                )
            task_id = str(task["lf_task_id"])
            ack_event = _task_state_event_tx(
                con, task_id=task_id, state="ACKNOWLEDGED"
            )
            _validate_task_state_event(
                ack_event,
                task_id=task_id,
                state="ACKNOWLEDGED",
                actor=str(first_claim_payload["assignee"]),
                evidence_ref=str(first_claim_row["evidence_ref"]),
                occurred_at_utc=str(first_claim_row["occurred_at_utc"]),
                correlation_id=str(review["event_id"]),
                causation_id=str(review["event_id"]),
            )
            if (
                str(task["acknowledged_at_utc"])
                != str(ack_event["occurred_at_utc"])
                or str(ack_event["occurred_at_utc"])
                != str(first_claim_row["occurred_at_utc"])
                or str(ack_event["evidence_ref"])
                != str(first_claim_row["evidence_ref"])
                or int(ack_event["task_event_rowid"])
                >= int(first_claim_row["queue_event_rowid"])
            ):
                raise SourceReviewQueueIntegrityError(
                    "review queue task acknowledgement changed"
                )
            final_row, final_payload = chain[-1]
            resolution_items = [
                (row, payload)
                for row, payload in chain
                if str(payload["action"]) == "RESOLUTION_RECORDED"
            ]
            first_action = _task_state_event_tx(
                con, task_id=task_id, state="IN_PROGRESS"
            )
            if resolution_items:
                first_resolution_row, first_resolution_payload = resolution_items[0]
                _validate_task_state_event(
                    first_action,
                    task_id=task_id,
                    state="IN_PROGRESS",
                    actor=str(first_resolution_payload["resolved_by"]),
                    evidence_ref=str(first_resolution_row["evidence_ref"]),
                    occurred_at_utc=str(first_resolution_row["occurred_at_utc"]),
                    correlation_id=str(review["event_id"]),
                    causation_id=str(first_resolution_payload["resolution_event_id"]),
                )
                first_source_resolution = con.execute(
                    "SELECT rowid FROM events WHERE event_id=?",
                    (str(first_resolution_payload["resolution_event_id"]),),
                ).fetchone()
                if (
                    not first_source_resolution
                    or str(task["first_human_action_at_utc"])
                    != str(first_action["occurred_at_utc"])
                    or int(first_action["task_event_rowid"])
                    <= int(first_source_resolution[0])
                    or int(first_action["task_event_rowid"])
                    >= int(first_resolution_row["queue_event_rowid"])
                    or str(first_action["occurred_at_utc"])
                    != str(first_resolution_row["occurred_at_utc"])
                    or str(first_action["evidence_ref"])
                    != str(first_resolution_row["evidence_ref"])
                ):
                    raise SourceReviewQueueIntegrityError(
                        "review queue task first action is invalid"
                    )
            elif first_action is not None or str(task["first_human_action_at_utc"]):
                raise SourceReviewQueueIntegrityError(
                    "review queue task first action is unbound"
                )
            final_decision = (
                str(final_payload["decision"])
                if str(final_payload["action"]) == "RESOLUTION_RECORDED"
                else ""
            )
            completion = _task_state_event_tx(
                con, task_id=task_id, state="COMPLETED"
            )
            if final_decision in _TERMINAL_DECISIONS:
                _validate_task_state_event(
                    completion,
                    task_id=task_id,
                    state="COMPLETED",
                    actor=str(final_payload["resolved_by"]),
                    evidence_ref=str(final_row["evidence_ref"]),
                    occurred_at_utc=str(final_row["occurred_at_utc"]),
                    correlation_id=str(review["event_id"]),
                    causation_id=str(final_payload["resolution_event_id"]),
                )
                completion_body = _canonical_object(
                    completion["payload_json"],
                    "review queue task completion is invalid",
                )
                expected_resolution = (
                    f"SOURCE_LAB_REVIEW:{final_decision}:"
                    f"{final_payload['resolution_id']}"
                )
                if (
                    str(task["status"]) != "COMPLETED"
                    or str(task["resolution"]) != expected_resolution
                    or str(task["closed_at_utc"]) != str(final_row["occurred_at_utc"])
                    or str(completion_body.get("resolution", "")) != expected_resolution
                    or int(completion["task_event_rowid"])
                    <= int(
                        con.execute(
                            "SELECT rowid FROM events WHERE event_id=?",
                            (str(final_payload["resolution_event_id"]),),
                        ).fetchone()[0]
                    )
                    or int(completion["task_event_rowid"])
                    >= int(final_row["queue_event_rowid"])
                    or str(completion["occurred_at_utc"])
                    != str(final_row["occurred_at_utc"])
                    or str(completion["evidence_ref"])
                    != str(final_row["evidence_ref"])
                ):
                    raise SourceReviewQueueIntegrityError(
                        "review queue task completion is invalid"
                    )
            elif (
                str(task["status"])
                != ("IN_PROGRESS" if resolution_items else "ACKNOWLEDGED")
                or completion is not None
                or str(task["closed_at_utc"])
                or str(task["resolution"])
            ):
                raise SourceReviewQueueIntegrityError(
                    "review queue task state is inconsistent"
                )
            for task_event in (ack_event, first_action, completion):
                if task_event is None:
                    continue
                task_event_id = str(task_event["event_id"])
                ledger.append(
                    {
                        "kind": "review_queue_task_event",
                        "id": task_event_id,
                        "hash": str(task_event["payload_hash"]),
                    }
                )
                ledger.append(
                    {
                        "kind": "full_row:events",
                        "id": task_event_id,
                        "hash": payload_hash(
                            {
                                key: task_event[key]
                                for key in task_event.keys()
                                if key != "task_event_rowid"
                            }
                        ),
                    }
                )

        first_rowid = min(int(row["queue_event_rowid"]) for row, _ in chain)
        later_resolutions = con.execute(
            """SELECT rr.resolution_id FROM source_lab_review_resolutions rr
               JOIN events e ON e.event_id=rr.event_id
               WHERE rr.review_id=? AND e.rowid>?""",
            (review_id, first_rowid),
        ).fetchall()
        bound = {
            str(payload["resolution_id"])
            for _, payload in chain
            if str(payload["action"]) == "RESOLUTION_RECORDED"
        }
        if {str(row[0]) for row in later_resolutions} != bound:
            raise SourceReviewQueueIntegrityError(
                "review queue resolution bypass is invalid"
            )

    ledger.sort(key=lambda item: (str(item["kind"]), str(item["id"])))
    return ledger, tuple(sorted(event_ids))


def _required_token(value: str) -> bool:
    return bool(re.fullmatch(r"lf_source_review_lease_[0-9a-f]{32}", value))


def _validate_claim_permit(value: object) -> ReviewClaimPermit:
    if type(value) is not ReviewClaimPermit:
        raise SourceReviewQueueValidationError("review queue claim is invalid")
    permit = value
    string_values = (
        permit.action,
        permit.review_id,
        permit.claim_event_id,
        permit.assignee,
        permit.lease_token,
        permit.issued_at_utc,
        permit.lease_until_utc,
        permit.source_read_epoch_hash,
        permit.review_digest,
    )
    if (
        type(permit.created) is not bool
        or type(permit.active) is not bool
        or type(permit.fence) is not int
        or permit.fence < 1
        or any(type(item) is not str for item in string_values)
        or permit.action not in _CLAIM_ACTIONS
        or not _required_token(permit.lease_token)
        or not _HEX64.fullmatch(permit.source_read_epoch_hash)
        or not _HEX64.fullmatch(permit.review_digest)
    ):
        raise SourceReviewQueueValidationError("review queue claim is invalid")
    _required(permit.review_id, "review queue claim is invalid")
    _required(permit.claim_event_id, "review queue claim is invalid")
    _principal(permit.assignee, "review queue claim is invalid")
    issued_text, issued = _timestamp(
        permit.issued_at_utc, "review queue claim is invalid"
    )
    until_text, until = _timestamp(
        permit.lease_until_utc, "review queue claim is invalid"
    )
    if (
        issued_text != permit.issued_at_utc
        or until_text != permit.lease_until_utc
        or until <= issued
    ):
        raise SourceReviewQueueValidationError("review queue claim is invalid")
    return permit


def _valid_event_idempotency(value: object, prefix: str) -> bool:
    text = str(value or "")
    expected = f"{prefix}:"
    suffix = text[len(expected) :] if text.startswith(expected) else ""
    return bool(
        suffix
        and len(suffix) <= 256
        and all(ord(character) >= 32 for character in suffix)
    )


def _event_idempotency_hash(value: object) -> str:
    return payload_hash(
        {
            "producer": QUEUE_PRODUCER,
            "idempotency_key": str(value or ""),
        }
    )


def validate_source_review_queue_integrity(
    con: sqlite3.Connection,
) -> dict[str, object]:
    """Validate the complete queue event chain without changing row_factory."""

    previous_row_factory = con.row_factory
    try:
        con.row_factory = sqlite3.Row
        try:
            ledger, event_ids = _validate_queue_material(con)
        except SourceReviewQueueValidationError as exc:
            raise SourceReviewQueueIntegrityError(
                "review queue stored value is invalid"
            ) from exc
        return {
            "count": len(ledger),
            "event_count": len(event_ids),
            "ledger_sha256": payload_hash(ledger),
        }
    finally:
        con.row_factory = previous_row_factory


def _source_lab_queue_ledger(
    con: sqlite3.Connection,
) -> tuple[list[dict[str, object]], tuple[str, ...]]:
    """Internal bridge used by the Source Lab recovery ledger."""

    try:
        return _validate_queue_material(con)
    except SourceReviewQueueValidationError as exc:
        raise SourceReviewQueueIntegrityError(
            "review queue stored value is invalid"
        ) from exc


def _cursor_encode(body: Mapping[str, Any]) -> str:
    envelope = {"body": dict(body), "sha256": payload_hash(dict(body))}
    raw = canonical_json(envelope).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _cursor_decode(value: str) -> dict[str, Any]:
    token = _required(value, "review queue cursor is invalid", maximum=4096)
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        envelope = _canonical_object(raw.decode("utf-8", "strict"), "review queue cursor is invalid")
    except (binascii.Error, UnicodeError, ValueError, SourceReviewQueueIntegrityError) as exc:
        raise SourceReviewQueueValidationError("review queue cursor is invalid") from exc
    if set(envelope) != {"body", "sha256"} or type(envelope.get("body")) is not dict:
        raise SourceReviewQueueValidationError("review queue cursor is invalid")
    body = envelope["body"]
    if str(envelope.get("sha256", "")) != payload_hash(body):
        raise SourceReviewQueueValidationError("review queue cursor is invalid")
    return body


def _task_binding_tx(con: sqlite3.Connection, review: sqlite3.Row) -> sqlite3.Row | None:
    rows = con.execute(
        """SELECT t.* FROM human_tasks t
           JOIN interactions i ON i.lf_interaction_id=t.lf_interaction_id
           WHERE i.source_event_id=? AND i.classification='SITE_QUALIFICATION'
             AND t.kind='SITE_QUALIFICATION'
           ORDER BY t.lf_task_id""",
        (str(review["event_id"]),),
    ).fetchall()
    if len(rows) > 1 or (str(review["requested_by"]) == "site_delivery_intake" and len(rows) != 1):
        raise SourceReviewQueueIntegrityError("review queue task binding is invalid")
    return rows[0] if rows else None


def _task_state_event_tx(
    con: sqlite3.Connection,
    *,
    task_id: str,
    state: str,
) -> sqlite3.Row | None:
    rows = con.execute(
        """SELECT rowid AS task_event_rowid,* FROM events
           WHERE producer='human_task_controller'
             AND idempotency_key=? ORDER BY rowid,event_id""",
        (f"task-state:{task_id}:{state}",),
    ).fetchall()
    if len(rows) > 1:
        raise SourceReviewQueueIntegrityError(
            "review queue task state history is ambiguous"
        )
    return rows[0] if rows else None


def _validate_task_state_event(
    event: sqlite3.Row | None,
    *,
    task_id: str,
    state: str,
    actor: str,
    evidence_ref: str = "",
    occurred_at_utc: str = "",
    correlation_id: str = "",
    causation_id: str | None = None,
) -> None:
    if event is None:
        raise SourceReviewQueueIntegrityError(
            "review queue task state proof is missing"
        )
    body = _canonical_object(
        event["payload_json"], "review queue task state proof is invalid"
    )
    expected_keys = (
        {"state", "resolution"} if state == "COMPLETED" else {"state"}
    )
    event_type = {
        "ACKNOWLEDGED": "human_task_acknowledged",
        "IN_PROGRESS": "human_task_first_action",
        "COMPLETED": "human_task_completed",
    }.get(state, "")
    if (
        set(body) != expected_keys
        or str(body.get("state", "")) != state
        or not event_type
        or str(event["event_type"]) != event_type
        or str(event["aggregate_type"]) != "task"
        or str(event["aggregate_id"]) != task_id
        or str(event["producer"]) != "human_task_controller"
        or int(event["schema_version"]) != QUEUE_SCHEMA_VERSION
        or str(event["actor"]) != actor
        or str(event["idempotency_key"]) != f"task-state:{task_id}:{state}"
        or str(event["payload_hash"]) != payload_hash(body)
        or (evidence_ref and str(event["evidence_ref"]) != evidence_ref)
        or (occurred_at_utc and str(event["occurred_at_utc"]) != occurred_at_utc)
        or (correlation_id and str(event["correlation_id"]) != correlation_id)
        or (
            causation_id is not None
            and str(event["causation_id"]) != causation_id
        )
    ):
        raise SourceReviewQueueIntegrityError(
            "review queue task state proof is invalid"
        )
    try:
        _evidence_ref(event["evidence_ref"])
    except SourceReviewQueueValidationError as exc:
        raise SourceReviewQueueIntegrityError(
            "review queue task state proof is invalid"
        ) from exc


class SourceReviewQueue:
    """Durable, offline-only review coordination over schema 17 events."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _after_resolution_before_queue_event(
        self, result: SourceLabResolutionResult
    ) -> None:
        """Fault-injection seam for atomic rollback tests."""

    def _acknowledge_site_task_tx(
        self,
        con: sqlite3.Connection,
        *,
        task: sqlite3.Row,
        actor: str,
        evidence_ref: str,
        occurred_at_utc: str,
        review_event_id: str,
    ) -> None:
        task_id = str(task["lf_task_id"])
        if (
            str(task["status"]) not in _TASK_PRECLAIM_STATES
            or str(task["acknowledged_at_utc"])
            or str(task["first_human_action_at_utc"])
            or str(task["closed_at_utc"])
            or str(task["resolution"])
        ):
            raise SourceReviewQueueConflict(
                "site qualification task must be open before its first claim"
            )
        if _task_state_event_tx(
            con, task_id=task_id, state="ACKNOWLEDGED"
        ) is not None:
            raise SourceReviewQueueIntegrityError(
                "site qualification task acknowledgement is inconsistent"
            )
        con.execute(
            """UPDATE human_tasks
               SET status='ACKNOWLEDGED',acknowledged_at_utc=?
               WHERE lf_task_id=?""",
            (occurred_at_utc, task_id),
        )
        event, created = self.store._append_event_tx(
            con,
            event_type="human_task_acknowledged",
            aggregate_type="task",
            aggregate_id=task_id,
            producer="human_task_controller",
            idempotency_key=f"task-state:{task_id}:ACKNOWLEDGED",
            payload={"state": "ACKNOWLEDGED"},
            evidence_ref=evidence_ref,
            actor=actor,
            correlation_id=review_event_id,
            causation_id=review_event_id,
            occurred_at_utc=occurred_at_utc,
            schema_version=QUEUE_SCHEMA_VERSION,
        )
        if not created:
            raise SourceReviewQueueIntegrityError(
                "site qualification task acknowledgement is inconsistent"
            )
        _validate_task_state_event(
            event,
            task_id=task_id,
            state="ACKNOWLEDGED",
            actor=actor,
            evidence_ref=evidence_ref,
            occurred_at_utc=occurred_at_utc,
            correlation_id=review_event_id,
            causation_id=review_event_id,
        )

    def _record_site_task_first_action_tx(
        self,
        con: sqlite3.Connection,
        *,
        task: sqlite3.Row,
        actor: str,
        evidence_ref: str,
        occurred_at_utc: str,
        review_event_id: str,
        resolution_event_id: str,
    ) -> None:
        task_id = str(task["lf_task_id"])
        status = str(task["status"])
        if status == "IN_PROGRESS":
            event = _task_state_event_tx(
                con, task_id=task_id, state="IN_PROGRESS"
            )
            _validate_task_state_event(
                event,
                task_id=task_id,
                state="IN_PROGRESS",
                actor=actor,
                correlation_id=review_event_id,
            )
            return
        if status != "ACKNOWLEDGED" or str(task["first_human_action_at_utc"]):
            raise SourceReviewQueueStaleClaim(
                "site qualification task cannot record this review action"
            )
        if _task_state_event_tx(
            con, task_id=task_id, state="IN_PROGRESS"
        ) is not None:
            raise SourceReviewQueueIntegrityError(
                "site qualification task first action is inconsistent"
            )
        con.execute(
            """UPDATE human_tasks SET status='IN_PROGRESS',
                   first_human_action_at_utc=? WHERE lf_task_id=?""",
            (occurred_at_utc, task_id),
        )
        event, created = self.store._append_event_tx(
            con,
            event_type="human_task_first_action",
            aggregate_type="task",
            aggregate_id=task_id,
            producer="human_task_controller",
            idempotency_key=f"task-state:{task_id}:IN_PROGRESS",
            payload={"state": "IN_PROGRESS"},
            evidence_ref=evidence_ref,
            actor=actor,
            correlation_id=review_event_id,
            causation_id=resolution_event_id,
            occurred_at_utc=occurred_at_utc,
            schema_version=QUEUE_SCHEMA_VERSION,
        )
        if not created:
            raise SourceReviewQueueIntegrityError(
                "site qualification task first action is inconsistent"
            )
        _validate_task_state_event(
            event,
            task_id=task_id,
            state="IN_PROGRESS",
            actor=actor,
            evidence_ref=evidence_ref,
            occurred_at_utc=occurred_at_utc,
            correlation_id=review_event_id,
            causation_id=resolution_event_id,
        )

    def _complete_site_task_tx(
        self,
        con: sqlite3.Connection,
        *,
        task: sqlite3.Row,
        decision: str,
        resolution_id: str,
        actor: str,
        evidence_ref: str,
        occurred_at_utc: str,
        review_event_id: str,
        resolution_event_id: str,
    ) -> None:
        task_id = str(task["lf_task_id"])
        current = con.execute(
            "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
        ).fetchone()
        if (
            not current
            or str(current["status"]) != "IN_PROGRESS"
            or not str(current["first_human_action_at_utc"])
        ):
            raise SourceReviewQueueStaleClaim(
                "site qualification task is no longer active"
            )
        if _task_state_event_tx(
            con, task_id=task_id, state="COMPLETED"
        ) is not None:
            raise SourceReviewQueueIntegrityError(
                "site qualification task completion is inconsistent"
            )
        resolution = f"SOURCE_LAB_REVIEW:{decision}:{resolution_id}"
        con.execute(
            """UPDATE human_tasks SET status='COMPLETED',
                   acknowledged_at_utc=CASE WHEN acknowledged_at_utc='' THEN ?
                                            ELSE acknowledged_at_utc END,
                   first_human_action_at_utc=CASE WHEN first_human_action_at_utc='' THEN ?
                                                  ELSE first_human_action_at_utc END,
                   closed_at_utc=?,resolution=? WHERE lf_task_id=?""",
            (
                occurred_at_utc,
                occurred_at_utc,
                occurred_at_utc,
                resolution,
                task_id,
            ),
        )
        event, created = self.store._append_event_tx(
            con,
            event_type="human_task_completed",
            aggregate_type="task",
            aggregate_id=task_id,
            producer="human_task_controller",
            idempotency_key=f"task-state:{task_id}:COMPLETED",
            payload={"state": "COMPLETED", "resolution": resolution},
            evidence_ref=evidence_ref,
            actor=actor,
            correlation_id=review_event_id,
            causation_id=resolution_event_id,
            occurred_at_utc=occurred_at_utc,
            schema_version=QUEUE_SCHEMA_VERSION,
        )
        if not created:
            raise SourceReviewQueueIntegrityError(
                "site qualification task completion is inconsistent"
            )
        _validate_task_state_event(
            event,
            task_id=task_id,
            state="COMPLETED",
            actor=actor,
            evidence_ref=evidence_ref,
            occurred_at_utc=occurred_at_utc,
            correlation_id=review_event_id,
            causation_id=resolution_event_id,
        )

    @staticmethod
    def _assert_integrity_tx(con: sqlite3.Connection) -> None:
        from .source_lab_integrity import (
            SourceLabIntegrityError,
            validate_source_lab_integrity,
        )

        try:
            validate_source_lab_integrity(con)
        except SourceLabIntegrityError as exc:
            raise SourceReviewQueueIntegrityError(
                "Source Lab review queue integrity failed"
            ) from exc

    def _projection_tx(
        self,
        con: sqlite3.Connection,
        review_id: str,
        *,
        now: datetime,
        epoch_hash: str,
        max_event_rowid: int | None = None,
    ) -> _Projection:
        review = _review_row_tx(con, review_id)
        latest = _latest_resolution_tx(
            con, review_id, max_event_rowid=max_event_rowid
        )
        queue_rows = _queue_rows_tx(
            con, review_id=review_id, max_event_rowid=max_event_rowid
        )
        head = queue_rows[-1] if queue_rows else None
        head_payload = (
            _canonical_object(head["payload_json"], "review queue event payload is invalid")
            if head
            else None
        )
        if head:
            _, head_time = _timestamp(
                head["occurred_at_utc"], "review queue event timestamp is invalid"
            )
            if now < head_time:
                raise SourceReviewQueueIntegrityError("review queue clock moved backwards")
        _, requested_at = _timestamp(
            review["request_event_occurred_at_utc"],
            "review queue request timestamp is invalid",
        )
        if now < requested_at:
            raise SourceReviewQueueIntegrityError("review queue clock precedes its review")
        digest = _review_digest(review, latest)
        state = _projection_state(
            latest=latest,
            head_payload=head_payload,
            now=now,
            epoch_hash=epoch_hash,
        )
        state_digest = _state_digest(
            review_digest=digest,
            state=state,
            head=head,
            head_payload=head_payload,
            epoch_hash=epoch_hash,
        )
        return _Projection(
            review=review,
            latest_resolution=latest,
            review_digest=digest,
            state=state,
            state_digest=state_digest,
            head=head,
            head_payload=head_payload,
            assignee=str(head_payload.get("assignee", "")) if head_payload else "",
            revision=int(head_payload.get("revision", 0)) if head_payload else 0,
            claim_event_id=(
                str(head["event_id"])
                if head and str(head_payload.get("action", "")) in _CLAIM_ACTIONS
                else str(head_payload.get("claim_event_id", "")) if head_payload else ""
            ),
            fence=int(head_payload.get("fence", head_payload.get("claim_fence", 0)))
            if head_payload
            else 0,
            lease_until_utc=str(head_payload.get("lease_until_utc", ""))
            if head_payload
            else "",
        )

    def list_open(
        self,
        *,
        limit: int = 50,
        cursor: str = "",
        source_id: str = "",
        review_kind: str = "",
    ) -> ReviewQueuePage:
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise SourceReviewQueueValidationError("review queue page size is invalid")
        source_filter = _optional(source_id, "review queue source filter is invalid")
        kind_filter = _optional(review_kind, "review queue kind filter is invalid", maximum=64).upper()
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_integrity_tx(con)
            epoch_hash = _epoch_hash_tx(con)
            now_text, now = _clock_now(self.clock)
            after_rowid = 0
            after_event_id = ""
            if cursor:
                body = _cursor_decode(cursor)
                expected_keys = {
                    "cursor_version",
                    "source_id",
                    "review_kind",
                    "limit",
                    "snapshot_event_rowid",
                    "snapshot_event_id",
                    "after_event_rowid",
                    "after_event_id",
                    "as_of_utc",
                    "source_read_epoch_hash",
                }
                if set(body) != expected_keys or body.get("cursor_version") != 1:
                    raise SourceReviewQueueValidationError("review queue cursor is invalid")
                integer_cursor_keys = {
                    "cursor_version",
                    "limit",
                    "snapshot_event_rowid",
                    "after_event_rowid",
                }
                if any(
                    type(body[key]) is not int
                    if key in integer_cursor_keys
                    else type(body[key]) is not str
                    for key in expected_keys
                ):
                    raise SourceReviewQueueValidationError(
                        "review queue cursor is invalid"
                    )
                if (
                    str(body["source_id"]) != source_filter
                    or str(body["review_kind"]) != kind_filter
                    or int(body["limit"]) != limit
                    or str(body["source_read_epoch_hash"]) != epoch_hash
                ):
                    raise SourceReviewQueueConflict("review queue cursor scope changed")
                snapshot_rowid = int(body["snapshot_event_rowid"])
                snapshot_event_id = str(body["snapshot_event_id"])
                after_rowid = int(body["after_event_rowid"])
                after_event_id = str(body["after_event_id"])
                as_of_text, as_of = _timestamp(
                    body["as_of_utc"], "review queue cursor is invalid"
                )
                snapshot_anchor = con.execute(
                    "SELECT event_id FROM events WHERE rowid=?", (snapshot_rowid,)
                ).fetchone()
                after_anchor = (
                    con.execute("SELECT event_id FROM events WHERE rowid=?", (after_rowid,)).fetchone()
                    if after_rowid
                    else None
                )
                if (
                    snapshot_rowid < 0
                    or after_rowid < 0
                    or after_rowid > snapshot_rowid
                    or (snapshot_rowid and (not snapshot_anchor or str(snapshot_anchor[0]) != snapshot_event_id))
                    or (after_rowid and (not after_anchor or str(after_anchor[0]) != after_event_id))
                ):
                    raise SourceReviewQueueConflict("review queue cursor anchor changed")
            else:
                anchor = con.execute(
                    "SELECT rowid,event_id FROM events ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
                snapshot_rowid = int(anchor[0]) if anchor else 0
                snapshot_event_id = str(anchor[1]) if anchor else ""
                as_of_text, as_of = now_text, now

            clauses = ["e.rowid>?", "e.rowid<=?"]
            values: list[object] = [after_rowid, snapshot_rowid]
            if source_filter:
                clauses.append("s.source_id=?")
                values.append(source_filter)
            if kind_filter:
                clauses.append("r.review_kind=?")
                values.append(kind_filter)
            rows = con.execute(
                """SELECT r.review_id,e.rowid AS request_event_rowid,e.event_id AS request_event_id
                   FROM source_lab_reviews r
                   JOIN source_lab_records s ON s.source_record_id=r.source_record_id
                   JOIN events e ON e.event_id=r.event_id
                   WHERE """
                + " AND ".join(clauses)
                + " ORDER BY e.rowid,e.event_id",
                tuple(values),
            ).fetchall()
            items_with_anchor: list[tuple[ReviewQueueItem, int, str]] = []
            for row in rows:
                projection = self._projection_tx(
                    con,
                    str(row["review_id"]),
                    now=as_of,
                    epoch_hash=epoch_hash,
                    max_event_rowid=snapshot_rowid,
                )
                if projection.state == "RESOLVED":
                    continue
                task = _task_binding_tx(con, projection.review)
                latest = projection.latest_resolution
                item = ReviewQueueItem(
                    review_id=str(projection.review["review_id"]),
                    source_record_id=str(projection.review["source_record_id"]),
                    source_id=str(projection.review["source_id"]),
                    review_kind=str(projection.review["review_kind"]),
                    reason=str(projection.review["reason"]),
                    requested_by=str(projection.review["requested_by"]),
                    evidence_ref=str(projection.review["evidence_ref"]),
                    requested_at_utc=str(projection.review["created_at_utc"]),
                    record_payload_hash=str(projection.review["record_payload_hash"]),
                    state=projection.state,
                    state_digest=projection.state_digest,
                    assignee=projection.assignee,
                    queue_revision=projection.revision,
                    head_event_id=str(projection.head["event_id"]) if projection.head else "",
                    claim_event_id=projection.claim_event_id,
                    fence=projection.fence,
                    lease_until_utc=projection.lease_until_utc,
                    latest_resolution_id=str(latest["resolution_id"]) if latest else "",
                    latest_decision=str(latest["decision"]) if latest else "",
                    latest_resolution_reason=str(latest["reason"]) if latest else "",
                    latest_resolved_by=str(latest["resolved_by"]) if latest else "",
                    task_id=str(task["lf_task_id"]) if task else "",
                    task_kind=str(task["kind"]) if task else "",
                    task_assigned_to=str(task["assigned_to"]) if task else "",
                    task_due_at_utc=str(task["due_at_utc"]) if task else "",
                )
                items_with_anchor.append(
                    (item, int(row["request_event_rowid"]), str(row["request_event_id"]))
                )
                if len(items_with_anchor) > limit:
                    break
            page_rows = items_with_anchor[:limit]
            next_cursor = ""
            if len(items_with_anchor) > limit and page_rows:
                _, last_rowid, last_event_id = page_rows[-1]
                next_cursor = _cursor_encode(
                    {
                        "cursor_version": 1,
                        "source_id": source_filter,
                        "review_kind": kind_filter,
                        "limit": limit,
                        "snapshot_event_rowid": snapshot_rowid,
                        "snapshot_event_id": snapshot_event_id,
                        "after_event_rowid": last_rowid,
                        "after_event_id": last_event_id,
                        "as_of_utc": as_of_text,
                        "source_read_epoch_hash": epoch_hash,
                    }
                )
            return ReviewQueuePage(
                tuple(item for item, _, _ in page_rows),
                next_cursor,
                snapshot_event_id,
                snapshot_rowid,
                as_of_text,
            )

    def _existing_claim_replay_tx(
        self,
        con: sqlite3.Connection,
        *,
        requested_operation: str,
        idempotency_key: str,
        command: Mapping[str, Any],
        now: datetime,
        epoch_hash: str,
    ) -> ReviewClaimPermit | None:
        row = con.execute(
            "SELECT * FROM events WHERE producer=? AND idempotency_key=?",
            (QUEUE_PRODUCER, f"{requested_operation.lower()}:{idempotency_key}"),
        ).fetchone()
        if not row:
            return None
        payload = _canonical_object(row["payload_json"], "review queue replay is invalid")
        if (
            str(payload.get("command_hash", "")) != payload_hash(command)
            or str(payload.get("requested_operation", "")) != requested_operation
            or str(row["event_type"]) != _EVENT_TYPE_BY_ACTION.get(str(payload.get("action", "")))
            or str(row["aggregate_id"]) != str(command["review_id"])
            or str(row["actor"]) != str(command["actor"])
            or str(row["evidence_ref"]) != str(command["evidence_ref"])
        ):
            raise SourceReviewQueueConflict("review queue idempotency conflict")
        projection = self._projection_tx(
            con,
            str(payload["review_id"]),
            now=now,
            epoch_hash=epoch_hash,
        )
        active = (
            projection.state == "CLAIMED"
            and projection.claim_event_id == str(row["event_id"])
            and projection.fence == int(payload["fence"])
            and projection.assignee == str(payload["assignee"])
            and _claim_active(payload, now, epoch_hash)
        )
        return ReviewClaimPermit(
            False,
            active,
            str(payload["action"]),
            str(payload["review_id"]),
            str(row["event_id"]),
            str(payload["assignee"]),
            int(payload["fence"]),
            str(payload["lease_token"]),
            str(payload["issued_at_utc"]),
            str(payload["lease_until_utc"]),
            str(payload["source_read_epoch_hash"]),
            str(payload["review_digest"]),
        )

    def _claim(
        self,
        *,
        requested_operation: str,
        review_id: str,
        assignee: str,
        actor: str,
        reason_code: str,
        evidence_ref: str,
        idempotency_key: str,
        expected_state_digest: str,
        lease_seconds: int,
        previous_claim_event_id: str = "",
    ) -> ReviewClaimPermit:
        review = _required(review_id, "review id is required")
        assigned = _principal(assignee, "review queue assignee is invalid")
        normalized_actor = _principal(actor, "review queue actor is invalid")
        code = _reason_code(reason_code, "review queue reason code is invalid")
        if requested_operation == "ASSIGN" and code not in _ASSIGN_REASON_CODES:
            raise SourceReviewQueueValidationError(
                "review queue assignment reason is invalid"
            )
        evidence = _evidence_ref(evidence_ref)
        idem = _required(idempotency_key, "review queue idempotency key is required", maximum=256)
        expected_digest = _required(
            expected_state_digest, "review queue expected state is required", maximum=64
        )
        if not _HEX64.fullmatch(expected_digest):
            raise SourceReviewQueueValidationError("review queue expected state is invalid")
        seconds = _lease_seconds(lease_seconds)
        previous_claim = str(previous_claim_event_id or "").strip()
        event_idempotency_key = f"{requested_operation.lower()}:{idem}"
        command = {
            "source_review_queue_claim_command_version": 1,
            "requested_operation": requested_operation,
            "review_id": review,
            "assignee": assigned,
            "actor": normalized_actor,
            "reason_code": code,
            "lease_seconds": seconds,
            "evidence_ref": evidence,
            "expected_state_digest": expected_digest,
            "previous_claim_event_id": previous_claim,
            "idempotency_key_hash": _event_idempotency_hash(
                event_idempotency_key
            ),
        }
        command_hash = payload_hash(command)
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_integrity_tx(con)
            epoch_hash = _epoch_hash_tx(con)
            now_text, now = _clock_now(self.clock)
            replay = self._existing_claim_replay_tx(
                con,
                requested_operation=requested_operation,
                idempotency_key=idem,
                command=command,
                now=now,
                epoch_hash=epoch_hash,
            )
            if replay:
                return replay
            projection = self._projection_tx(
                con, review, now=now, epoch_hash=epoch_hash
            )
            if projection.state_digest != expected_digest:
                raise SourceReviewQueueConflict("review queue state changed")
            if projection.state == "RESOLVED":
                raise SourceReviewQueueUnavailable("review is already resolved")
            if projection.state == "CLAIMED":
                raise SourceReviewQueueUnavailable("review already has an active claim")
            if requested_operation in {"CLAIM", "ASSIGN"}:
                if projection.state not in {"OPEN_UNASSIGNED", "NEEDS_RESEARCH"}:
                    raise SourceReviewQueueUnavailable("review must be reclaimed")
                if previous_claim:
                    raise SourceReviewQueueConflict("review queue prior claim is unexpected")
                if requested_operation == "CLAIM" and normalized_actor != assigned:
                    raise SourceReviewQueueValidationError("self-claim actor must be the assignee")
                action = requested_operation
            elif requested_operation == "RECLAIM":
                if projection.state != "RECLAIMABLE" or not projection.claim_event_id:
                    raise SourceReviewQueueUnavailable("review is not reclaimable")
                if previous_claim != projection.claim_event_id:
                    raise SourceReviewQueueConflict("review queue prior claim changed")
                old_epoch = str(projection.head_payload.get("source_read_epoch_hash", ""))
                expected_code = (
                    "RESTORE_EPOCH_FENCED" if old_epoch != epoch_hash else "LEASE_EXPIRED"
                )
                if code != expected_code:
                    raise SourceReviewQueueValidationError("review queue reclaim reason is invalid")
                action = "RECLAIM" if normalized_actor == assigned else "REASSIGN"
            else:
                raise SourceReviewQueueValidationError("review queue operation is invalid")

            task = _task_binding_tx(con, projection.review)
            if assigned == str(projection.review["requested_by"]):
                raise SourceReviewQueueConflict(
                    "review requester cannot claim the same review"
                )
            if task and str(task["assigned_to"]) != assigned:
                raise SourceReviewQueueConflict("review queue assignee conflicts with its SLA task")
            if task:
                if requested_operation not in {"CLAIM", "RECLAIM"} or normalized_actor != assigned:
                    raise SourceReviewQueueConflict(
                        "site qualification task must be claimed by its assignee"
                    )
                if projection.revision == 0:
                    self._acknowledge_site_task_tx(
                        con,
                        task=task,
                        actor=assigned,
                        evidence_ref=evidence,
                        occurred_at_utc=now_text,
                        review_event_id=str(projection.review["event_id"]),
                    )
                else:
                    if str(task["status"]) not in _TASK_CLAIMED_STATES:
                        raise SourceReviewQueueConflict(
                            "site qualification task is no longer active"
                        )
                    acknowledgement = _task_state_event_tx(
                        con,
                        task_id=str(task["lf_task_id"]),
                        state="ACKNOWLEDGED",
                    )
                    _validate_task_state_event(
                        acknowledgement,
                        task_id=str(task["lf_task_id"]),
                        state="ACKNOWLEDGED",
                        actor=assigned,
                    )
            issued = now
            until = issued + timedelta(seconds=seconds)
            until_text = until.isoformat(timespec="microseconds").replace("+00:00", "Z").replace(".000000Z", "Z")
            lease_token = new_lf_id("source_review_lease")
            previous_event_id = str(projection.head["event_id"]) if projection.head else ""
            previous_payload_hash = str(projection.head["payload_hash"]) if projection.head else ""
            payload = {
                "queue_event_version": 1,
                "action": action,
                "requested_operation": requested_operation,
                "review_id": review,
                "review_digest": projection.review_digest,
                "expected_state_digest": expected_digest,
                "revision": projection.revision + 1,
                "previous_event_id": previous_event_id,
                "previous_payload_hash": previous_payload_hash,
                "source_read_epoch_hash": epoch_hash,
                "assignee": assigned,
                "actor": normalized_actor,
                "reason_code": code,
                "fence": projection.fence + 1,
                "lease_token": lease_token,
                "issued_at_utc": now_text,
                "lease_until_utc": until_text,
                "lease_seconds": seconds,
                "command_hash": command_hash,
                "previous_claim_event_id": previous_claim,
                "idempotency_key_hash": command["idempotency_key_hash"],
            }
            event, created = self.store._append_event_tx(
                con,
                event_type=_EVENT_TYPE_BY_ACTION[action],
                aggregate_type="source_lab_review",
                aggregate_id=review,
                producer=QUEUE_PRODUCER,
                idempotency_key=event_idempotency_key,
                payload=payload,
                evidence_ref=evidence,
                actor=normalized_actor,
                correlation_id=str(projection.review["event_id"]),
                causation_id=previous_event_id or str(projection.review["event_id"]),
                occurred_at_utc=now_text,
                schema_version=QUEUE_SCHEMA_VERSION,
            )
            if not created:
                raise SourceReviewQueueConflict("review queue claim replay is inconsistent")
            return ReviewClaimPermit(
                True,
                True,
                action,
                review,
                str(event["event_id"]),
                assigned,
                int(payload["fence"]),
                lease_token,
                now_text,
                until_text,
                epoch_hash,
                projection.review_digest,
            )

    def claim(
        self,
        *,
        review_id: str,
        claimant: str,
        evidence_ref: str,
        idempotency_key: str,
        expected_state_digest: str,
        lease_seconds: int = 900,
    ) -> ReviewClaimPermit:
        return self._claim(
            requested_operation="CLAIM",
            review_id=review_id,
            assignee=claimant,
            actor=claimant,
            reason_code="SELF_CLAIM",
            evidence_ref=evidence_ref,
            idempotency_key=idempotency_key,
            expected_state_digest=expected_state_digest,
            lease_seconds=lease_seconds,
        )

    def assign(
        self,
        *,
        review_id: str,
        assignee: str,
        assigned_by: str,
        reason_code: str,
        evidence_ref: str,
        idempotency_key: str,
        expected_state_digest: str,
        lease_seconds: int = 900,
    ) -> ReviewClaimPermit:
        return self._claim(
            requested_operation="ASSIGN",
            review_id=review_id,
            assignee=assignee,
            actor=assigned_by,
            reason_code=reason_code,
            evidence_ref=evidence_ref,
            idempotency_key=idempotency_key,
            expected_state_digest=expected_state_digest,
            lease_seconds=lease_seconds,
        )

    def reclaim(
        self,
        *,
        review_id: str,
        assignee: str,
        actor: str,
        reason_code: str,
        previous_claim_event_id: str,
        evidence_ref: str,
        idempotency_key: str,
        expected_state_digest: str,
        lease_seconds: int = 900,
    ) -> ReviewClaimPermit:
        return self._claim(
            requested_operation="RECLAIM",
            review_id=review_id,
            assignee=assignee,
            actor=actor,
            reason_code=reason_code,
            evidence_ref=evidence_ref,
            idempotency_key=idempotency_key,
            expected_state_digest=expected_state_digest,
            lease_seconds=lease_seconds,
            previous_claim_event_id=previous_claim_event_id,
        )

    def resolve_claimed(
        self,
        permit: ReviewClaimPermit,
        *,
        decision: str,
        reason: str,
        evidence_ref: str,
        idempotency_key: str,
    ) -> ReviewQueueResolutionResult:
        permit = _validate_claim_permit(permit)
        normalized_decision = _required(
            decision, "review queue decision is required", maximum=64
        ).upper()
        if normalized_decision not in _QUEUE_DECISIONS:
            raise SourceReviewQueueValidationError("review queue decision is invalid")
        normalized_reason = _required(
            reason, "review queue resolution reason is required", maximum=2048
        )
        evidence = _evidence_ref(evidence_ref)
        idem = _required(idempotency_key, "review queue idempotency key is required", maximum=256)
        token_hash = payload_hash({"lease_token": permit.lease_token})
        event_idempotency_key = f"resolve:{idem}"
        command = {
            "source_review_queue_resolution_command_version": 1,
            "review_id": permit.review_id,
            "claim_event_id": permit.claim_event_id,
            "claim_fence": permit.fence,
            "lease_token_hash": token_hash,
            "decision": normalized_decision,
            "reason": normalized_reason,
            "resolved_by": permit.assignee,
            "evidence_ref": evidence,
            "idempotency_key_hash": _event_idempotency_hash(
                event_idempotency_key
            ),
        }
        command_hash = payload_hash(command)
        with self.store.transaction(min_schema_version=17) as con:
            self._assert_integrity_tx(con)
            now_text, now = _clock_now(self.clock)
            existing_event = con.execute(
                "SELECT * FROM events WHERE producer=? AND idempotency_key=?",
                (QUEUE_PRODUCER, f"resolve:{idem}"),
            ).fetchone()
            if existing_event:
                payload = _canonical_object(
                    existing_event["payload_json"], "review queue resolution replay is invalid"
                )
                resolution = con.execute(
                    "SELECT * FROM source_lab_review_resolutions WHERE resolution_id=?",
                    (str(payload.get("resolution_id", "")),),
                ).fetchone()
                if (
                    not resolution
                    or str(payload.get("command_hash", "")) != command_hash
                    or str(existing_event["actor"]) != permit.assignee
                    or str(existing_event["evidence_ref"]) != evidence
                ):
                    raise SourceReviewQueueConflict("review queue idempotency conflict")
                return ReviewQueueResolutionResult(
                    False,
                    permit.review_id,
                    normalized_decision,
                    str(resolution["resolution_id"]),
                    str(resolution["event_id"]),
                    int(resolution["sequence_number"]),
                    str(existing_event["event_id"]),
                )
            epoch_hash = _epoch_hash_tx(con)
            projection = self._projection_tx(
                con, permit.review_id, now=now, epoch_hash=epoch_hash
            )
            if (
                projection.state != "CLAIMED"
                or not projection.head
                or not projection.head_payload
                or projection.claim_event_id != permit.claim_event_id
                or projection.fence != permit.fence
                or projection.assignee != permit.assignee
                or str(projection.head_payload.get("lease_token", "")) != permit.lease_token
                or str(projection.head_payload.get("source_read_epoch_hash", "")) != epoch_hash
                or permit.source_read_epoch_hash != epoch_hash
                or permit.review_digest != projection.review_digest
            ):
                raise SourceReviewQueueStaleClaim("review queue claim is no longer valid")
            task = _task_binding_tx(con, projection.review)
            if task is not None and str(task["status"]) not in _TASK_CLAIMED_STATES:
                raise SourceReviewQueueStaleClaim(
                    "site qualification task is no longer active"
                )
            latest = projection.latest_resolution
            supersedes = str(latest["resolution_id"]) if latest else ""
            result = SourceLabSink(self.store)._append_review_resolution_tx(
                con,
                review_id=permit.review_id,
                decision=normalized_decision,
                reason=normalized_reason,
                resolved_by=permit.assignee,
                evidence_ref=evidence,
                idempotency_key=f"queue:{idem}",
                supersedes_resolution_id=supersedes,
                allow_queue_managed=True,
                occurred_at_utc=now_text,
            )
            if task is not None:
                self._record_site_task_first_action_tx(
                    con,
                    task=task,
                    actor=permit.assignee,
                    evidence_ref=evidence,
                    occurred_at_utc=now_text,
                    review_event_id=str(projection.review["event_id"]),
                    resolution_event_id=result.event_id,
                )
                if normalized_decision in _TERMINAL_DECISIONS:
                    self._complete_site_task_tx(
                        con,
                        task=task,
                        decision=normalized_decision,
                        resolution_id=result.resolution_id,
                        actor=permit.assignee,
                        evidence_ref=evidence,
                        occurred_at_utc=now_text,
                        review_event_id=str(projection.review["event_id"]),
                        resolution_event_id=result.event_id,
                    )
            self._after_resolution_before_queue_event(result)
            resolution = con.execute(
                "SELECT * FROM source_lab_review_resolutions WHERE resolution_id=?",
                (result.resolution_id,),
            ).fetchone()
            if not resolution:
                raise SourceReviewQueueIntegrityError("review queue resolution commit is missing")
            resolved_digest = _review_digest(projection.review, resolution)
            payload = {
                "queue_event_version": 1,
                "action": "RESOLUTION_RECORDED",
                "review_id": permit.review_id,
                "review_digest": projection.review_digest,
                "resolved_review_digest": resolved_digest,
                "expected_state_digest": projection.state_digest,
                "revision": projection.revision + 1,
                "previous_event_id": permit.claim_event_id,
                "previous_payload_hash": str(projection.head["payload_hash"]),
                "source_read_epoch_hash": epoch_hash,
                "claim_event_id": permit.claim_event_id,
                "claim_payload_hash": str(projection.head["payload_hash"]),
                "claim_fence": permit.fence,
                "lease_token_hash": token_hash,
                "resolved_by": permit.assignee,
                "decision": normalized_decision,
                "resolution_id": result.resolution_id,
                "resolution_sequence": result.sequence_number,
                "resolution_event_id": result.event_id,
                "resolution_command_hash": str(resolution["command_hash"]),
                "recorded_at_utc": now_text,
                "command_hash": command_hash,
                "idempotency_key_hash": command["idempotency_key_hash"],
            }
            event, created = self.store._append_event_tx(
                con,
                event_type=_EVENT_TYPE_BY_ACTION["RESOLUTION_RECORDED"],
                aggregate_type="source_lab_review",
                aggregate_id=permit.review_id,
                producer=QUEUE_PRODUCER,
                idempotency_key=event_idempotency_key,
                payload=payload,
                evidence_ref=evidence,
                actor=permit.assignee,
                correlation_id=str(projection.review["event_id"]),
                causation_id=permit.claim_event_id,
                occurred_at_utc=now_text,
                schema_version=QUEUE_SCHEMA_VERSION,
            )
            if not created:
                raise SourceReviewQueueConflict("review queue resolution replay is inconsistent")
            return ReviewQueueResolutionResult(
                True,
                permit.review_id,
                normalized_decision,
                result.resolution_id,
                result.event_id,
                result.sequence_number,
                str(event["event_id"]),
            )


__all__ = [
    "MAX_LEASE_SECONDS",
    "MAX_PAGE_SIZE",
    "MIN_LEASE_SECONDS",
    "QUEUE_PRODUCER",
    "ReviewClaimPermit",
    "ReviewQueueItem",
    "ReviewQueuePage",
    "ReviewQueueResolutionResult",
    "SourceReviewQueue",
    "SourceReviewQueueConflict",
    "SourceReviewQueueError",
    "SourceReviewQueueIntegrityError",
    "SourceReviewQueueStaleClaim",
    "SourceReviewQueueUnavailable",
    "SourceReviewQueueValidationError",
    "validate_source_review_queue_integrity",
]
