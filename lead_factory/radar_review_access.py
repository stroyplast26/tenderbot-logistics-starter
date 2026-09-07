"""Offline v15 controls for Radar evidence, review and source access.

There is deliberately no transport in this module.  A source access permit is
an auditable budget envelope, not an HTTP client and not authority to enable a
live connector.  Review resolutions are immutable dispositions of the object
already stored by v14; they never merge graph rows or create commercial work.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable

from .construction_radar import (
    CapabilityState,
    LicenceState,
    PassportState,
    RadarConflict,
    RadarValidationError,
    SourcePassportRegistry,
)
from .ids import new_lf_id, payload_hash
from .store import FactoryStore


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/pdf",
        "image/jpeg",
        "image/png",
        "text/csv",
        "text/plain",
    }
)
_MAX_EVIDENCE_BYTES = 262_144
_ACCESS_APPROVAL_DATA_CLASS = "RADAR_SOURCE_ACCESS_APPROVAL"
_ACCESS_BUDGET_DATA_CLASS = "RADAR_SOURCE_ACCESS_BUDGET"
_IDENTITY_REVIEW_REASONS = frozenset(
    {
        "STRONG_OBJECT_ANCHOR_REQUIRED",
        "AMBIGUOUS_OBJECT_IDENTITY",
        "STRONG_WEAK_IDENTITY_CONFLICT",
    }
)


def _required(value: object, message: str, *, limit: int = 512) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise RadarValidationError(message)
    return text


def _timestamp(value: object, message: str) -> str:
    raw = _required(value, message)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise RadarValidationError(message) from None
    if parsed.tzinfo is None:
        raise RadarValidationError(message)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _datetime(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _now(clock: Callable[[], datetime]) -> tuple[datetime, str]:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RadarValidationError("radar control clock is invalid")
    utc = value.astimezone(timezone.utc)
    return utc, utc.isoformat(timespec="seconds").replace("+00:00", "Z")


def _command_hash(value: object) -> str:
    body = asdict(value) if hasattr(value, "__dataclass_fields__") else value
    if isinstance(body, dict) and isinstance(body.get("blob"), (bytes, bytearray)):
        raw = bytes(body.pop("blob"))
        body["blob_sha256"] = hashlib.sha256(raw).hexdigest()
        body["blob_size"] = len(raw)
    for key, item in tuple(body.items()) if isinstance(body, dict) else ():
        if isinstance(item, Enum):
            body[key] = item.value
    return payload_hash(body)


def _event_payload(row: Any) -> dict[str, Any]:
    try:
        value = json.loads(str(row["payload_json"] or "{}"))
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _radar_evidence_ref(evidence_id: str) -> str:
    return f"radar-evidence://{evidence_id}"


@dataclass(frozen=True, slots=True)
class RadarEvidenceCommand:
    blob: bytes
    media_type: str
    source_label: str
    captured_at_utc: str
    actor: str
    declared_sha256: str
    data_class: str = "RADAR_AUDIT_EVIDENCE"
    classification: str = "INTERNAL"
    passport_id: str = ""


@dataclass(frozen=True, slots=True)
class RadarEvidenceResult:
    evidence_id: str
    content_sha256: str
    byte_count: int
    created: bool

    @property
    def evidence_ref(self) -> str:
        return _radar_evidence_ref(self.evidence_id)


@dataclass(frozen=True, slots=True)
class VerifiedRadarEvidence:
    evidence_id: str
    content_sha256: str
    byte_count: int
    media_type: str
    source_label: str
    captured_at_utc: str
    actor: str
    data_class: str
    classification: str
    passport_id: str
    source_key_hash: str
    created_at_utc: str


class RadarEvidenceVault:
    """A small content-verified SQLite BLOB ledger for offline fixtures.

    This is intentionally bounded and is not a general secret/document store.
    The returned verification object never exposes the stored bytes.
    """

    def __init__(
        self,
        store: FactoryStore,
        *,
        max_blob_bytes: int = _MAX_EVIDENCE_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.max_blob_bytes = min(max(1, int(max_blob_bytes)), _MAX_EVIDENCE_BYTES)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def assert_record_tx(con: Any, evidence_id: str) -> VerifiedRadarEvidence:
        row = con.execute(
            "SELECT * FROM radar_evidence_records WHERE evidence_id=?",
            (str(evidence_id),),
        ).fetchone()
        if not row:
            raise RadarValidationError("verified Radar evidence is required")
        try:
            blob = bytes(row["blob"])
        except (TypeError, ValueError):
            raise RadarValidationError("Radar evidence content is invalid") from None
        digest = hashlib.sha256(blob).hexdigest()
        if (
            not _HEX64.fullmatch(str(row["content_sha256"] or ""))
            or digest != str(row["content_sha256"])
            or len(blob) != int(row["byte_count"])
            or len(blob) <= 0
            or len(blob) > _MAX_EVIDENCE_BYTES
        ):
            raise RadarValidationError("Radar evidence integrity is invalid")
        events = con.execute(
            """SELECT * FROM events
               WHERE event_type='construction_radar_evidence_stored'
                 AND aggregate_type='radar_evidence'
                 AND aggregate_id=? AND producer='construction_radar_evidence'
                 AND idempotency_key=?""",
            (str(evidence_id), f"evidence:{evidence_id}"),
        ).fetchall()
        payload = _event_payload(events[0]) if len(events) == 1 else {}
        if (
            len(events) != 1
            or str(payload.get("command_hash", "")) != str(row["command_hash"])
            or str(payload.get("content_sha256", "")) != digest
            or int(payload.get("byte_count", -1)) != len(blob)
            or str(payload.get("media_type", "")) != str(row["media_type"])
            or str(payload.get("data_class", "")) != str(row["data_class"])
            or str(payload.get("classification", "")) != str(row["classification"])
            or str(payload.get("passport_id", ""))
            != str(row["passport_id"] or "")
            or str(payload.get("source_key_hash", ""))
            != str(row["source_key_hash"] or "")
            or str(payload.get("source_label_hash", ""))
            != payload_hash({"source_label": str(row["source_label"])})
            or str(payload.get("created_at_utc", ""))
            != str(row["created_at_utc"])
            or str(events[0]["actor"] or "") != str(row["actor"])
            or str(events[0]["occurred_at_utc"] or "")
            != str(row["captured_at_utc"])
            or str(events[0]["evidence_ref"] or "")
            != _radar_evidence_ref(str(evidence_id))
        ):
            raise RadarValidationError("Radar evidence provenance is incomplete")
        expected_command = RadarEvidenceCommand(
            blob=blob,
            media_type=str(row["media_type"]),
            source_label=str(row["source_label"]),
            captured_at_utc=str(row["captured_at_utc"]),
            actor=str(row["actor"]),
            declared_sha256=digest,
            data_class=str(row["data_class"]),
            classification=str(row["classification"]),
            passport_id=str(row["passport_id"] or ""),
        )
        if _command_hash(expected_command) != str(row["command_hash"]):
            raise RadarValidationError("Radar evidence command binding is invalid")
        passport_id = str(row["passport_id"] or "")
        source_key_hash = str(row["source_key_hash"] or "")
        if passport_id:
            passport = con.execute(
                "SELECT * FROM radar_source_passports WHERE passport_id=?",
                (passport_id,),
            ).fetchone()
            if not passport:
                raise RadarValidationError("Radar evidence source passport is missing")
            SourcePassportRegistry.assert_event_binding_tx(con, passport)
            if (
                source_key_hash
                != payload_hash({"source_key": str(passport["source_key"])})
                or not con.execute(
                    """SELECT 1 FROM radar_source_permissions
                       WHERE passport_id=? AND data_class=?""",
                    (passport_id, str(row["data_class"])),
                ).fetchone()
            ):
                raise RadarValidationError("Radar evidence source binding is invalid")
        elif source_key_hash:
            raise RadarValidationError("Radar evidence source binding is incomplete")
        return VerifiedRadarEvidence(
            evidence_id=str(evidence_id),
            content_sha256=digest,
            byte_count=len(blob),
            media_type=str(row["media_type"]),
            source_label=str(row["source_label"]),
            captured_at_utc=str(row["captured_at_utc"]),
            actor=str(row["actor"]),
            data_class=str(row["data_class"]),
            classification=str(row["classification"]),
            passport_id=passport_id,
            source_key_hash=source_key_hash,
            created_at_utc=str(row["created_at_utc"]),
        )

    def put(
        self,
        command: RadarEvidenceCommand,
        *,
        idempotency_key: str,
    ) -> RadarEvidenceResult:
        if not isinstance(command, RadarEvidenceCommand):
            raise RadarValidationError("Radar evidence command is invalid")
        if not isinstance(command.blob, (bytes, bytearray)):
            raise RadarValidationError("Radar evidence content is invalid")
        blob = bytes(command.blob)
        if not blob or len(blob) > self.max_blob_bytes:
            raise RadarValidationError("Radar evidence content exceeds the offline limit")
        content_sha256 = str(command.declared_sha256 or "").strip().lower()
        if (
            not _HEX64.fullmatch(content_sha256)
            or hashlib.sha256(blob).hexdigest() != content_sha256
        ):
            raise RadarValidationError("Radar evidence digest is invalid")
        media_type = _required(command.media_type, "Radar evidence media type is required").lower()
        if media_type not in _MEDIA_TYPES:
            raise RadarValidationError("Radar evidence media type is unsupported")
        source_label = _required(command.source_label, "Radar evidence source label is required", limit=256)
        if not _SAFE_TOKEN.fullmatch(source_label):
            raise RadarValidationError("Radar evidence source label is invalid")
        captured_at = _timestamp(command.captured_at_utc, "Radar evidence timestamp is invalid")
        actor = _required(command.actor, "Radar evidence actor is required")
        data_class = _required(command.data_class, "Radar evidence data class is required", limit=128).upper()
        classification = _required(
            command.classification, "Radar evidence classification is required", limit=64
        ).upper()
        if not _SAFE_TOKEN.fullmatch(data_class) or classification not in {
            "PUBLIC", "LICENSED", "INTERNAL"
        }:
            raise RadarValidationError("Radar evidence classification is invalid")
        passport_id = str(command.passport_id or "").strip()
        idem = _required(idempotency_key, "Radar evidence idempotency key is required")
        now, created_at = _now(self.clock)
        if _datetime(captured_at) > now + timedelta(minutes=5):
            raise RadarValidationError("future Radar evidence is not accepted")
        digest = _command_hash(
            RadarEvidenceCommand(
                blob=blob,
                media_type=media_type,
                source_label=source_label,
                captured_at_utc=captured_at,
                actor=actor,
                declared_sha256=content_sha256,
                data_class=data_class,
                classification=classification,
                passport_id=passport_id,
            )
        )
        with self.store.transaction(min_schema_version=15) as con:
            existing = con.execute(
                "SELECT * FROM radar_evidence_records WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("Radar evidence idempotency conflict")
                verified = self.assert_record_tx(con, str(existing["evidence_id"]))
                return RadarEvidenceResult(
                    verified.evidence_id,
                    verified.content_sha256,
                    verified.byte_count,
                    False,
                )
            evidence_id = new_lf_id("radar_evidence")
            source_key_hash = ""
            if passport_id:
                passport = con.execute(
                    "SELECT * FROM radar_source_passports WHERE passport_id=?",
                    (passport_id,),
                ).fetchone()
                if not passport:
                    raise RadarValidationError("Radar evidence source passport does not exist")
                SourcePassportRegistry.assert_event_binding_tx(con, passport)
                if not con.execute(
                    """SELECT 1 FROM radar_source_permissions
                       WHERE passport_id=? AND data_class=?""",
                    (passport_id, data_class),
                ).fetchone():
                    raise RadarValidationError("Radar evidence data class is not permitted")
                source_key_hash = payload_hash(
                    {"source_key": str(passport["source_key"])}
                )
            con.execute(
                """INSERT INTO radar_evidence_records(
                       evidence_id,blob,media_type,source_label,data_class,classification,
                       passport_id,source_key_hash,content_sha256,byte_count,captured_at_utc,
                       actor,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id,
                    sqlite3.Binary(blob),
                    media_type,
                    source_label,
                    data_class,
                    classification,
                    passport_id or None,
                    source_key_hash,
                    content_sha256,
                    len(blob),
                    captured_at,
                    actor,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="construction_radar_evidence_stored",
                aggregate_type="radar_evidence",
                aggregate_id=evidence_id,
                producer="construction_radar_evidence",
                idempotency_key=f"evidence:{evidence_id}",
                payload={
                    "content_sha256": content_sha256,
                    "byte_count": len(blob),
                    "media_type": media_type,
                    "data_class": data_class,
                    "classification": classification,
                    "passport_id": passport_id,
                    "source_key_hash": source_key_hash,
                    "source_label_hash": payload_hash({"source_label": source_label}),
                    "created_at_utc": created_at,
                    "command_hash": digest,
                },
                evidence_ref=_radar_evidence_ref(evidence_id),
                actor=actor,
                occurred_at_utc=captured_at,
                schema_version=15,
            )
            return RadarEvidenceResult(evidence_id, content_sha256, len(blob), True)

    def verify(self, evidence_id: str) -> VerifiedRadarEvidence:
        entity_id = _required(evidence_id, "Radar evidence identity is required")
        with self.store.transaction(min_schema_version=15) as con:
            return self.assert_record_tx(con, entity_id)


class RadarReviewResolutionDecision(str, Enum):
    CONFIRM_CURRENT_OBJECT = "CONFIRM_CURRENT_OBJECT"
    KEEP_SEPARATE = "KEEP_SEPARATE"
    REJECT_SIGNAL = "REJECT_SIGNAL"
    NEEDS_RESEARCH = "NEEDS_RESEARCH"


class RadarReviewResolutionState(str, Enum):
    RECORDED = "RECORDED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class RadarReviewResolution:
    review_id: str
    radar_object_id: str
    radar_signal_id: str
    decision: RadarReviewResolutionDecision | str
    reason_code: str
    expected_review_digest: str
    decided_at_utc: str
    actor: str
    evidence_id: str


@dataclass(frozen=True, slots=True)
class RadarReviewResolutionResult:
    resolution_id: str
    created: bool
    review_id: str
    state: RadarReviewResolutionState
    terminal: bool


class RadarReviewResolver:
    """Append an evidenced disposition without rewriting the Radar graph."""

    _TERMINAL = frozenset(
        {
            RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT.value,
            RadarReviewResolutionDecision.KEEP_SEPARATE.value,
            RadarReviewResolutionDecision.REJECT_SIGNAL.value,
        }
    )

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_resolution_hook: Callable[[], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.after_resolution_hook = after_resolution_hook
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def assert_event_binding_tx(con: Any, row: Any) -> None:
        resolution_id = str(row["resolution_id"])
        events = con.execute(
            """SELECT * FROM events
               WHERE event_type='construction_radar_review_resolved'
                 AND aggregate_type='radar_review_resolution' AND aggregate_id=?
                 AND producer='construction_radar_review'
                 AND idempotency_key=?""",
            (resolution_id, f"resolution:{resolution_id}"),
        ).fetchall()
        payload = _event_payload(events[0]) if len(events) == 1 else {}
        if (
            len(events) != 1
            or str(payload.get("command_hash", "")) != str(row["command_hash"])
            or str(payload.get("review_id", "")) != str(row["review_id"])
            or str(payload.get("radar_signal_id", "")) != str(row["radar_signal_id"])
            or str(payload.get("radar_object_id", "")) != str(row["radar_object_id"])
            or str(payload.get("decision", "")) != str(row["decision"])
            or bool(payload.get("terminal")) != bool(int(row["terminal"]))
            or str(events[0]["actor"] or "") != str(row["actor"])
            or str(events[0]["occurred_at_utc"] or "")
            != str(row["decided_at_utc"])
            or str(events[0]["evidence_ref"] or "")
            != _radar_evidence_ref(str(row["evidence_id"]))
        ):
            raise RadarValidationError("Radar review resolution provenance is incomplete")
        expected_command = RadarReviewResolution(
            review_id=str(row["review_id"]),
            radar_object_id=str(row["radar_object_id"]),
            radar_signal_id=str(row["radar_signal_id"]),
            decision=str(row["decision"]),
            reason_code=str(row["reason_code"]),
            expected_review_digest=str(row["expected_review_digest"]),
            decided_at_utc=str(row["decided_at_utc"]),
            actor=str(row["actor"]),
            evidence_id=str(row["evidence_id"]),
        )
        if _command_hash(expected_command) != str(row["command_hash"]):
            raise RadarValidationError("Radar review resolution command binding is invalid")
        verified = RadarEvidenceVault.assert_record_tx(con, str(row["evidence_id"]))
        decision_time = _datetime(str(row["decided_at_utc"]))
        if (
            _datetime(verified.captured_at_utc) > decision_time
            or _datetime(verified.created_at_utc) > decision_time
        ):
            raise RadarValidationError("Radar review evidence postdates the decision")
        signal = con.execute(
            "SELECT passport_id,source_key FROM radar_signals WHERE radar_signal_id=?",
            (str(row["radar_signal_id"]),),
        ).fetchone()
        if not signal:
            raise RadarValidationError("Radar review signal provenance is missing")
        expected_source_hash = payload_hash({"source_key": str(signal["source_key"])})
        if verified.passport_id:
            if (
                verified.passport_id != str(signal["passport_id"])
                or verified.source_key_hash != expected_source_hash
            ):
                raise RadarValidationError("Radar review evidence source scope is invalid")
        elif verified.data_class != "RADAR_AUDIT_EVIDENCE":
            raise RadarValidationError("Radar review evidence source scope is incomplete")

    @classmethod
    def effective_terminal_tx(
        cls,
        con: Any,
        review_id: str,
        *,
        as_of_utc: str,
    ) -> Any | None:
        rows = con.execute(
            """SELECT * FROM radar_review_resolutions
               WHERE review_id=? AND terminal=1 AND decided_at_utc<=?
               ORDER BY decided_at_utc,resolution_id""",
            (str(review_id), str(as_of_utc)),
        ).fetchall()
        if len(rows) > 1:
            raise RadarValidationError("Radar review has conflicting terminal resolutions")
        if not rows:
            return None
        row = rows[0]
        cls.assert_event_binding_tx(con, row)
        review = con.execute(
            """SELECT r.*,s.radar_object_id,s.radar_signal_id
               FROM radar_resolution_reviews r
               JOIN radar_signals s ON s.radar_signal_id=r.radar_signal_id
               WHERE r.review_id=?""",
            (str(review_id),),
        ).fetchone()
        if (
            not review
            or str(row["radar_signal_id"]) != str(review["radar_signal_id"])
            or str(row["radar_object_id"]) != str(review["radar_object_id"])
            or str(row["expected_review_digest"]) != str(review["candidate_digest"])
        ):
            raise RadarValidationError("Radar review resolution no longer matches its review")
        return row

    def resolve(
        self,
        command: RadarReviewResolution,
        *,
        idempotency_key: str,
    ) -> RadarReviewResolutionResult:
        if not isinstance(command, RadarReviewResolution):
            raise RadarValidationError("Radar review resolution is invalid")
        review_id = _required(command.review_id, "Radar review identity is required")
        object_id = _required(command.radar_object_id, "Radar object identity is required")
        signal_id = _required(command.radar_signal_id, "Radar signal identity is required")
        try:
            decision = RadarReviewResolutionDecision(
                str(command.decision.value if isinstance(command.decision, Enum) else command.decision)
            )
        except ValueError:
            raise RadarValidationError("Radar review decision is invalid") from None
        reason_code = _required(command.reason_code, "Radar review reason is required", limit=128)
        if not _SAFE_TOKEN.fullmatch(reason_code):
            raise RadarValidationError("Radar review reason is invalid")
        expected_digest = str(command.expected_review_digest or "").strip().lower()
        if not _HEX64.fullmatch(expected_digest):
            raise RadarValidationError("Radar review digest is invalid")
        decided_at = _timestamp(command.decided_at_utc, "Radar review timestamp is invalid")
        actor = _required(command.actor, "Radar review actor is required")
        evidence_id = _required(command.evidence_id, "verified Radar review evidence is required")
        idem = _required(idempotency_key, "Radar review idempotency key is required")
        now, created_at = _now(self.clock)
        if _datetime(decided_at) > now + timedelta(minutes=5):
            raise RadarValidationError("future Radar review decision is not accepted")
        digest = _command_hash(
            RadarReviewResolution(
                review_id=review_id,
                radar_object_id=object_id,
                radar_signal_id=signal_id,
                decision=decision.value,
                reason_code=reason_code,
                expected_review_digest=expected_digest,
                decided_at_utc=decided_at,
                actor=actor,
                evidence_id=evidence_id,
            )
        )
        terminal = decision.value in self._TERMINAL

        with self.store.transaction(min_schema_version=15) as con:
            existing = con.execute(
                "SELECT * FROM radar_review_resolutions WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("Radar review resolution idempotency conflict")
                self.assert_event_binding_tx(con, existing)
                return RadarReviewResolutionResult(
                    str(existing["resolution_id"]),
                    False,
                    str(existing["review_id"]),
                    RadarReviewResolutionState.RECORDED,
                    bool(int(existing["terminal"])),
                )
            review = con.execute(
                """SELECT r.*,s.radar_object_id,s.passport_id,s.source_key,s.source_external_key,
                          s.source_revision,s.created_at_utc AS signal_created_at_utc
                   FROM radar_resolution_reviews r
                   JOIN radar_signals s ON s.radar_signal_id=r.radar_signal_id
                   WHERE r.review_id=?""",
                (review_id,),
            ).fetchone()
            if not review or str(review["state"]) != "OPEN":
                raise RadarValidationError("open Radar review does not exist")
            if str(review["radar_signal_id"]) != signal_id or str(review["radar_object_id"]) != object_id:
                raise RadarValidationError("Radar review graph scope does not match")
            if str(review["candidate_digest"]) != expected_digest:
                raise RadarConflict("Radar review snapshot is stale")
            latest = con.execute(
                """SELECT radar_signal_id FROM radar_signals
                   WHERE source_key=? AND source_external_key=?
                   ORDER BY CAST(source_revision AS INTEGER) DESC,rowid DESC LIMIT 1""",
                (str(review["source_key"]), str(review["source_external_key"])),
            ).fetchone()
            if not latest or str(latest["radar_signal_id"]) != signal_id:
                raise RadarConflict("Radar review signal was superseded")
            if _datetime(decided_at) < _datetime(str(review["created_at_utc"])):
                raise RadarValidationError("Radar review decision predates the review")
            if terminal and con.execute(
                "SELECT 1 FROM radar_review_resolutions WHERE review_id=? AND terminal=1",
                (review_id,),
            ).fetchone():
                raise RadarConflict("Radar review already has a terminal resolution")
            if (
                terminal
                and decision is not RadarReviewResolutionDecision.REJECT_SIGNAL
                and str(review["reason"]) not in _IDENTITY_REVIEW_REASONS
            ):
                raise RadarValidationError("this Radar review needs a typed research workflow")
            verified_evidence = RadarEvidenceVault.assert_record_tx(con, evidence_id)
            decision_time = _datetime(decided_at)
            if (
                _datetime(verified_evidence.captured_at_utc) > decision_time
                or _datetime(verified_evidence.created_at_utc) > decision_time
            ):
                raise RadarValidationError("Radar review evidence postdates the decision")
            expected_source_hash = payload_hash(
                {"source_key": str(review["source_key"])}
            )
            if verified_evidence.passport_id:
                if (
                    verified_evidence.passport_id != str(review["passport_id"])
                    or verified_evidence.source_key_hash != expected_source_hash
                ):
                    raise RadarValidationError("Radar review evidence source scope is invalid")
            elif verified_evidence.data_class != "RADAR_AUDIT_EVIDENCE":
                raise RadarValidationError("Radar review evidence source scope is incomplete")
            resolution_id = new_lf_id("radar_review_resolution")
            try:
                con.execute(
                    """INSERT INTO radar_review_resolutions(
                           resolution_id,review_id,radar_object_id,radar_signal_id,decision,
                           reason_code,expected_review_digest,terminal,actor,evidence_id,
                           decided_at_utc,idempotency_key,command_hash,created_at_utc
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        resolution_id,
                        review_id,
                        object_id,
                        signal_id,
                        decision.value,
                        reason_code,
                        expected_digest,
                        1 if terminal else 0,
                        actor,
                        evidence_id,
                        decided_at,
                        idem,
                        digest,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError:
                raise RadarConflict("Radar review resolution conflicts with immutable state") from None
            if self.after_resolution_hook:
                self.after_resolution_hook()
            self.store._append_event_tx(
                con,
                event_type="construction_radar_review_resolved",
                aggregate_type="radar_review_resolution",
                aggregate_id=resolution_id,
                producer="construction_radar_review",
                idempotency_key=f"resolution:{resolution_id}",
                payload={
                    "review_id": review_id,
                    "radar_signal_id": signal_id,
                    "radar_object_id": object_id,
                    "decision": decision.value,
                    "terminal": terminal,
                    "expected_review_digest": expected_digest,
                    "command_hash": digest,
                },
                evidence_ref=_radar_evidence_ref(evidence_id),
                actor=actor,
                occurred_at_utc=decided_at,
                schema_version=15,
            )
            return RadarReviewResolutionResult(
                resolution_id,
                True,
                review_id,
                RadarReviewResolutionState.RECORDED,
                terminal,
            )


class SourceAccessMode(str, Enum):
    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    MANUAL_IMPORT = "MANUAL_IMPORT"
    READ_ONLY_API = "READ_ONLY_API"


class SourceAccessState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"


@dataclass(frozen=True, slots=True)
class SourceAccessPermit:
    passport_id: str
    data_class: str
    mode: SourceAccessMode | str
    purpose_code: str
    max_records: int
    max_bytes: int
    max_cost_minor: int
    valid_from_utc: str
    valid_until_utc: str
    approval_evidence_id: str
    budget_evidence_id: str
    approver: str
    max_operations: int = 1000
    credential_fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class SourceAccessPermitResult:
    permit_id: str
    created: bool
    state: SourceAccessState = SourceAccessState.ACTIVE


@dataclass(frozen=True, slots=True)
class SourceAccessRevocationResult:
    revocation_id: str
    created: bool


@dataclass(frozen=True, slots=True)
class SourceEvidenceCommand:
    permit_id: str
    operation_key: str
    record_count: int
    byte_count: int
    cost_minor: int
    content_sha256: str
    evidence_id: str
    observed_at_utc: str
    actor: str


@dataclass(frozen=True, slots=True)
class EvidenceReceipt:
    receipt_id: str
    created: bool
    permit_id: str
    content_sha256: str


class SourceAccessPermitLedger:
    """Issue and revoke an offline budget envelope; never perform a read."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def assert_permit_event_tx(con: Any, row: Any) -> None:
        permit_id = str(row["permit_id"])
        events = con.execute(
            """SELECT * FROM events
               WHERE event_type='radar_source_access_permit_issued'
                 AND aggregate_type='radar_source_access_permit' AND aggregate_id=?
                 AND producer='construction_radar_access' AND idempotency_key=?""",
            (permit_id, f"permit:{permit_id}"),
        ).fetchall()
        payload = _event_payload(events[0]) if len(events) == 1 else {}
        if (
            len(events) != 1
            or str(payload.get("command_hash", "")) != str(row["command_hash"])
            or str(payload.get("passport_id", "")) != str(row["passport_id"])
            or str(payload.get("data_class", "")) != str(row["data_class"])
            or str(payload.get("mode", "")) != str(row["mode"])
            or str(payload.get("source_read_epoch", ""))
            != str(row["source_read_epoch"])
            or str(events[0]["actor"] or "") != str(row["issued_by"])
            or str(events[0]["occurred_at_utc"] or "")
            != str(row["created_at_utc"])
            or str(events[0]["evidence_ref"] or "")
            != _radar_evidence_ref(str(row["approval_evidence_id"]))
        ):
            raise RadarValidationError("source access permit provenance is incomplete")
        expected_command = SourceAccessPermit(
            passport_id=str(row["passport_id"]),
            data_class=str(row["data_class"]),
            mode=str(row["mode"]),
            purpose_code=str(row["purpose_code"]),
            max_records=int(row["max_records"]),
            max_bytes=int(row["max_bytes"]),
            max_cost_minor=int(row["max_cost_minor"]),
            valid_from_utc=str(row["valid_from_utc"]),
            valid_until_utc=str(row["valid_until_utc"]),
            approval_evidence_id=str(row["approval_evidence_id"]),
            budget_evidence_id=str(row["budget_evidence_id"]),
            approver=str(row["approver"]),
            max_operations=int(row["max_operations"]),
            credential_fingerprint=str(row["credential_fingerprint"]),
        )
        if _command_hash(expected_command) != str(row["command_hash"]):
            raise RadarValidationError("source access permit command binding is invalid")
        approval_id = str(row["approval_evidence_id"])
        budget_id = str(row["budget_evidence_id"])
        if approval_id == budget_id:
            raise RadarValidationError("source access approval and budget evidence must be distinct")
        approval = RadarEvidenceVault.assert_record_tx(con, approval_id)
        budget = RadarEvidenceVault.assert_record_tx(con, budget_id)
        if (
            approval.data_class != _ACCESS_APPROVAL_DATA_CLASS
            or budget.data_class != _ACCESS_BUDGET_DATA_CLASS
            or _datetime(approval.created_at_utc) > _datetime(str(row["created_at_utc"]))
            or _datetime(budget.created_at_utc) > _datetime(str(row["created_at_utc"]))
            or (
                approval.passport_id
                and approval.passport_id != str(row["passport_id"])
            )
            or (
                budget.passport_id
                and budget.passport_id != str(row["passport_id"])
            )
        ):
            raise RadarValidationError("source access approval or budget evidence is invalid")

    @staticmethod
    def assert_revocation_event_tx(con: Any, row: Any) -> None:
        revocation_id = str(row["revocation_id"])
        events = con.execute(
            """SELECT * FROM events
               WHERE event_type='radar_source_access_revoked'
                 AND aggregate_type='radar_source_access_revocation' AND aggregate_id=?
                 AND producer='construction_radar_access' AND idempotency_key=?""",
            (revocation_id, f"revocation:{revocation_id}"),
        ).fetchall()
        payload = _event_payload(events[0]) if len(events) == 1 else {}
        if (
            len(events) != 1
            or str(payload.get("command_hash", "")) != str(row["command_hash"])
            or str(payload.get("permit_id", "")) != str(row["permit_id"])
            or str(events[0]["actor"] or "") != str(row["actor"])
            or str(events[0]["occurred_at_utc"] or "")
            != str(row["occurred_at_utc"])
            or str(events[0]["evidence_ref"] or "")
            != _radar_evidence_ref(str(row["evidence_id"]))
        ):
            raise RadarValidationError("source access revocation provenance is incomplete")
        expected_command_hash = payload_hash(
            {
                "permit_id": str(row["permit_id"]),
                "occurred_at_utc": str(row["occurred_at_utc"]),
                "actor": str(row["actor"]),
                "evidence_id": str(row["evidence_id"]),
                "reason_code": str(row["reason_code"]),
            }
        )
        if expected_command_hash != str(row["command_hash"]):
            raise RadarValidationError("source access revocation command binding is invalid")
        RadarEvidenceVault.assert_record_tx(con, str(row["evidence_id"]))

    def issue(
        self,
        command: SourceAccessPermit,
        *,
        idempotency_key: str,
        actor: str,
    ) -> SourceAccessPermitResult:
        if not isinstance(command, SourceAccessPermit):
            raise RadarValidationError("source access permit is invalid")
        passport_id = _required(command.passport_id, "source passport identity is required")
        data_class = _required(command.data_class, "source access data class is required").upper()
        try:
            mode = SourceAccessMode(
                str(command.mode.value if isinstance(command.mode, Enum) else command.mode)
            )
        except ValueError:
            raise RadarValidationError("source access mode is invalid") from None
        if mode is not SourceAccessMode.OFFLINE_FIXTURE:
            raise RadarValidationError("only offline fixture access is available in this slice")
        purpose = _required(command.purpose_code, "source access purpose is required", limit=128).upper()
        if not _SAFE_TOKEN.fullmatch(purpose):
            raise RadarValidationError("source access purpose is invalid")
        actor_id = _required(actor, "source access actor is required")
        approver = _required(command.approver, "source access approver is required")
        approval_evidence_id = _required(
            command.approval_evidence_id, "source access approval evidence is required"
        )
        budget_evidence_id = _required(
            command.budget_evidence_id, "source access budget evidence is required"
        )
        if approval_evidence_id == budget_evidence_id:
            raise RadarValidationError("source access approval and budget evidence must be distinct")
        valid_from = _timestamp(command.valid_from_utc, "source access validity is invalid")
        valid_until = _timestamp(command.valid_until_utc, "source access validity is invalid")
        if _datetime(valid_until) < _datetime(valid_from):
            raise RadarValidationError("source access validity is invalid")
        try:
            max_operations = int(command.max_operations)
            max_records = int(command.max_records)
            max_bytes = int(command.max_bytes)
            max_cost = int(command.max_cost_minor)
        except (TypeError, ValueError):
            raise RadarValidationError("source access budget is invalid") from None
        if (
            isinstance(command.max_operations, bool)
            or isinstance(command.max_records, bool)
            or isinstance(command.max_bytes, bool)
            or isinstance(command.max_cost_minor, bool)
            or min(max_operations, max_records, max_bytes, max_cost) < 0
            or max_operations > 1_000_000
            or max_records > 100_000_000
            or max_bytes > 10_000_000_000
            or max_cost > 10_000_000_000
        ):
            raise RadarValidationError("source access budget is invalid")
        credential = str(command.credential_fingerprint or "").strip().lower()
        if mode is SourceAccessMode.READ_ONLY_API:
            if not _HEX64.fullmatch(credential):
                raise RadarValidationError("read-only API credential binding is required")
        elif credential:
            raise RadarValidationError("offline source access cannot carry a credential binding")
        idem = _required(idempotency_key, "source access idempotency key is required")
        now, created_at = _now(self.clock)
        if not (_datetime(valid_from) <= now <= _datetime(valid_until)):
            raise RadarValidationError("source access permit is not currently valid")
        digest = _command_hash(
            SourceAccessPermit(
                passport_id=passport_id,
                data_class=data_class,
                mode=mode.value,
                purpose_code=purpose,
                max_records=max_records,
                max_bytes=max_bytes,
                max_cost_minor=max_cost,
                valid_from_utc=valid_from,
                valid_until_utc=valid_until,
                approval_evidence_id=approval_evidence_id,
                budget_evidence_id=budget_evidence_id,
                approver=approver,
                max_operations=max_operations,
                credential_fingerprint=credential,
            )
        )

        with self.store.transaction(min_schema_version=15) as con:
            existing = con.execute(
                "SELECT * FROM radar_source_access_permits WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest or str(existing["issued_by"]) != actor_id:
                    raise RadarConflict("source access permit idempotency conflict")
                self.assert_permit_event_tx(con, existing)
                current_epoch = con.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()
                if (
                    not current_epoch
                    or str(current_epoch[0]) != str(existing["source_read_epoch"])
                ):
                    raise RadarValidationError("source access permit belongs to an obsolete runtime epoch")
                return SourceAccessPermitResult(str(existing["permit_id"]), False)
            passport = con.execute(
                "SELECT rowid AS ledger_rowid,* FROM radar_source_passports WHERE passport_id=?",
                (passport_id,),
            ).fetchone()
            if not passport:
                raise RadarValidationError("approved source passport is required")
            SourcePassportRegistry.assert_event_binding_tx(con, passport)
            latest = con.execute(
                "SELECT passport_id FROM radar_source_passports WHERE source_key=? ORDER BY rowid DESC LIMIT 1",
                (str(passport["source_key"]),),
            ).fetchone()
            if not latest or str(latest["passport_id"]) != passport_id:
                raise RadarValidationError("source passport version has been superseded")
            if (
                str(passport["state"]) != PassportState.APPROVED.value
                or str(passport["capability_state"]) != CapabilityState.PASS.value
                or str(passport["licence_state"]) != LicenceState.ALLOWED.value
                or str(passport["acquisition_mode"]) != mode.value
                or str(passport["data_contract_version"] or "") == ""
            ):
                raise RadarValidationError("source passport does not authorize this access")
            passport_end = min(
                _datetime(passport["valid_until_utc"]),
                _datetime(passport["capability_valid_until_utc"]),
                _datetime(passport["licence_valid_until_utc"]),
            )
            if (
                _datetime(valid_from) < _datetime(passport["valid_from_utc"])
                or _datetime(valid_until) > passport_end
            ):
                raise RadarValidationError("source access exceeds the passport validity")
            if not con.execute(
                "SELECT 1 FROM radar_source_permissions WHERE passport_id=? AND data_class=?",
                (passport_id, data_class),
            ).fetchone():
                raise RadarValidationError("source data class is not permitted")
            approval_evidence = RadarEvidenceVault.assert_record_tx(
                con, approval_evidence_id
            )
            budget_evidence = RadarEvidenceVault.assert_record_tx(
                con, budget_evidence_id
            )
            if (
                approval_evidence.data_class != _ACCESS_APPROVAL_DATA_CLASS
                or budget_evidence.data_class != _ACCESS_BUDGET_DATA_CLASS
                or _datetime(approval_evidence.created_at_utc) > now
                or _datetime(budget_evidence.created_at_utc) > now
                or (
                    approval_evidence.passport_id
                    and approval_evidence.passport_id != passport_id
                )
                or (
                    budget_evidence.passport_id
                    and budget_evidence.passport_id != passport_id
                )
            ):
                raise RadarValidationError(
                    "source access approval or budget evidence is invalid"
                )
            epoch_row = con.execute(
                "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
            ).fetchone()
            source_read_epoch = str(epoch_row[0] if epoch_row else "")
            if not re.fullmatch(r"[0-9a-f]{32}", source_read_epoch):
                raise RadarValidationError("source access runtime epoch is invalid")
            permit_id = new_lf_id("radar_access_permit")
            con.execute(
                """INSERT INTO radar_source_access_permits(
                       permit_id,passport_id,source_key_hash,data_class,mode,purpose_code,
                       credential_fingerprint,max_operations,max_records,max_bytes,max_cost_minor,
                       valid_from_utc,valid_until_utc,approval_evidence_id,budget_evidence_id,
                       approver,issued_by,idempotency_key,command_hash,created_at_utc,
                       source_read_epoch
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    permit_id,
                    passport_id,
                    payload_hash({"source_key": str(passport["source_key"])}),
                    data_class,
                    mode.value,
                    purpose,
                    credential,
                    max_operations,
                    max_records,
                    max_bytes,
                    max_cost,
                    valid_from,
                    valid_until,
                    approval_evidence_id,
                    budget_evidence_id,
                    approver,
                    actor_id,
                    idem,
                    digest,
                    created_at,
                    source_read_epoch,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="radar_source_access_permit_issued",
                aggregate_type="radar_source_access_permit",
                aggregate_id=permit_id,
                producer="construction_radar_access",
                idempotency_key=f"permit:{permit_id}",
                payload={
                    "passport_id": passport_id,
                    "source_key_hash": payload_hash({"source_key": str(passport["source_key"])}),
                    "data_class": data_class,
                    "mode": mode.value,
                    "purpose_code": purpose,
                    "source_read_epoch": source_read_epoch,
                    "budget_digest": payload_hash(
                        {
                            "max_operations": max_operations,
                            "max_records": max_records,
                            "max_bytes": max_bytes,
                            "max_cost_minor": max_cost,
                        }
                    ),
                    "command_hash": digest,
                },
                evidence_ref=_radar_evidence_ref(approval_evidence_id),
                actor=actor_id,
                occurred_at_utc=created_at,
                schema_version=15,
            )
            return SourceAccessPermitResult(permit_id, True)

    def revoke(
        self,
        permit_id: str,
        *,
        occurred_at_utc: str,
        actor: str,
        evidence_id: str,
        idempotency_key: str,
        reason_code: str = "OWNER_REVOKED",
    ) -> SourceAccessRevocationResult:
        entity_id = _required(permit_id, "source access permit identity is required")
        occurred = _timestamp(occurred_at_utc, "source access revocation timestamp is invalid")
        actor_id = _required(actor, "source access revocation actor is required")
        evidence = _required(evidence_id, "source access revocation evidence is required")
        reason = _required(reason_code, "source access revocation reason is required", limit=128).upper()
        if not _SAFE_TOKEN.fullmatch(reason):
            raise RadarValidationError("source access revocation reason is invalid")
        idem = _required(idempotency_key, "source access revocation idempotency key is required")
        now, created_at = _now(self.clock)
        if _datetime(occurred) > now + timedelta(minutes=5):
            raise RadarValidationError("future source access revocation is not accepted")
        command = {
            "permit_id": entity_id,
            "occurred_at_utc": occurred,
            "actor": actor_id,
            "evidence_id": evidence,
            "reason_code": reason,
        }
        digest = payload_hash(command)
        with self.store.transaction(min_schema_version=15) as con:
            existing = con.execute(
                "SELECT * FROM radar_source_access_revocations WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("source access revocation idempotency conflict")
                self.assert_revocation_event_tx(con, existing)
                return SourceAccessRevocationResult(str(existing["revocation_id"]), False)
            permit = con.execute(
                "SELECT * FROM radar_source_access_permits WHERE permit_id=?", (entity_id,)
            ).fetchone()
            if not permit:
                raise RadarValidationError("source access permit does not exist")
            self.assert_permit_event_tx(con, permit)
            if _datetime(occurred) < _datetime(str(permit["created_at_utc"])):
                raise RadarValidationError("source access revocation predates its permit")
            collision = con.execute(
                "SELECT * FROM radar_source_access_revocations WHERE permit_id=?", (entity_id,)
            ).fetchone()
            if collision:
                self.assert_revocation_event_tx(con, collision)
                raise RadarConflict("source access permit is already revoked")
            RadarEvidenceVault.assert_record_tx(con, evidence)
            revocation_id = new_lf_id("radar_access_revocation")
            con.execute(
                """INSERT INTO radar_source_access_revocations(
                       revocation_id,permit_id,reason_code,occurred_at_utc,actor,evidence_id,
                       idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    revocation_id,
                    entity_id,
                    reason,
                    occurred,
                    actor_id,
                    evidence,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="radar_source_access_revoked",
                aggregate_type="radar_source_access_revocation",
                aggregate_id=revocation_id,
                producer="construction_radar_access",
                idempotency_key=f"revocation:{revocation_id}",
                payload={
                    "permit_id": entity_id,
                    "reason_code": reason,
                    "command_hash": digest,
                },
                evidence_ref=_radar_evidence_ref(evidence),
                actor=actor_id,
                occurred_at_utc=occurred,
                schema_version=15,
            )
            return SourceAccessRevocationResult(revocation_id, True)


class SourceEvidenceBoundary:
    """Record one already-obtained offline evidence item against a permit."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_reservation_hook: Callable[[], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.after_reservation_hook = after_reservation_hook
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _assert_receipt_tx(con: Any, row: Any) -> None:
        receipt_id = str(row["receipt_id"])
        events = con.execute(
            """SELECT * FROM events
               WHERE event_type='radar_source_evidence_recorded'
                 AND aggregate_type='radar_source_evidence_receipt' AND aggregate_id=?
                 AND producer='construction_radar_access' AND idempotency_key=?""",
            (receipt_id, f"receipt:{receipt_id}"),
        ).fetchall()
        payload = _event_payload(events[0]) if len(events) == 1 else {}
        usage = con.execute(
            "SELECT * FROM radar_source_access_usage WHERE receipt_id=?", (receipt_id,)
        ).fetchall()
        if (
            len(events) != 1
            or len(usage) != 1
            or str(payload.get("command_hash", "")) != str(row["command_hash"])
            or str(payload.get("permit_id", "")) != str(row["permit_id"])
            or str(payload.get("operation_key_hash", ""))
            != payload_hash({"operation_key": str(row["operation_key"])})
            or str(payload.get("content_sha256", "")) != str(row["content_sha256"])
            or str(payload.get("passport_id", "")) != str(row["passport_id"])
            or str(payload.get("source_key_hash", "")) != str(row["source_key_hash"])
            or int(payload.get("record_count", -1)) != int(row["record_count"])
            or int(payload.get("byte_count", -1)) != int(row["byte_count"])
            or int(payload.get("cost_minor", -1)) != int(row["cost_minor"])
            or int(usage[0]["record_count"]) != int(row["record_count"])
            or int(usage[0]["byte_count"]) != int(row["byte_count"])
            or int(usage[0]["cost_minor"]) != int(row["cost_minor"])
            or int(usage[0]["operation_count"]) != 1
            or str(usage[0]["permit_id"]) != str(row["permit_id"])
            or str(usage[0]["observed_at_utc"]) != str(row["observed_at_utc"])
            or str(events[0]["actor"] or "") != str(row["actor"])
            or str(events[0]["occurred_at_utc"] or "")
            != str(row["observed_at_utc"])
            or str(events[0]["evidence_ref"] or "")
            != _radar_evidence_ref(str(row["evidence_id"]))
        ):
            raise RadarValidationError("source evidence receipt provenance is incomplete")
        expected_command = SourceEvidenceCommand(
            permit_id=str(row["permit_id"]),
            operation_key=str(row["operation_key"]),
            record_count=int(row["record_count"]),
            byte_count=int(row["byte_count"]),
            cost_minor=int(row["cost_minor"]),
            content_sha256=str(row["content_sha256"]),
            evidence_id=str(row["evidence_id"]),
            observed_at_utc=str(row["observed_at_utc"]),
            actor=str(row["actor"]),
        )
        if _command_hash(expected_command) != str(row["command_hash"]):
            raise RadarValidationError("source evidence receipt command binding is invalid")
        verified = RadarEvidenceVault.assert_record_tx(con, str(row["evidence_id"]))
        if (
            verified.content_sha256 != str(row["content_sha256"])
            or verified.passport_id != str(row["passport_id"])
            or verified.source_key_hash != str(row["source_key_hash"])
        ):
            raise RadarValidationError("source evidence content binding is invalid")

    def capture(
        self,
        command: SourceEvidenceCommand,
        *,
        idempotency_key: str,
    ) -> EvidenceReceipt:
        if not isinstance(command, SourceEvidenceCommand):
            raise RadarValidationError("source evidence command is invalid")
        permit_id = _required(command.permit_id, "source access permit identity is required")
        operation_key = _required(command.operation_key, "source operation key is required", limit=256)
        if not _SAFE_TOKEN.fullmatch(operation_key):
            raise RadarValidationError("source operation key is invalid")
        actor = _required(command.actor, "source evidence actor is required")
        evidence_id = _required(command.evidence_id, "verified source evidence is required")
        observed = _timestamp(command.observed_at_utc, "source evidence timestamp is invalid")
        content_sha256 = str(command.content_sha256 or "").strip().lower()
        if not _HEX64.fullmatch(content_sha256):
            raise RadarValidationError("source evidence digest is invalid")
        try:
            record_count = int(command.record_count)
            byte_count = int(command.byte_count)
            cost_minor = int(command.cost_minor)
        except (TypeError, ValueError):
            raise RadarValidationError("source evidence usage is invalid") from None
        if (
            isinstance(command.record_count, bool)
            or isinstance(command.byte_count, bool)
            or isinstance(command.cost_minor, bool)
            or record_count <= 0
            or byte_count <= 0
            or cost_minor < 0
        ):
            raise RadarValidationError("source evidence usage is invalid")
        idem = _required(idempotency_key, "source evidence idempotency key is required")
        now, created_at = _now(self.clock)
        digest = _command_hash(
            SourceEvidenceCommand(
                permit_id=permit_id,
                operation_key=operation_key,
                record_count=record_count,
                byte_count=byte_count,
                cost_minor=cost_minor,
                content_sha256=content_sha256,
                evidence_id=evidence_id,
                observed_at_utc=observed,
                actor=actor,
            )
        )
        with self.store.transaction(min_schema_version=15) as con:
            existing = con.execute(
                "SELECT * FROM radar_source_evidence_receipts WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("source evidence idempotency conflict")
            permit = con.execute(
                "SELECT * FROM radar_source_access_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if not permit:
                raise RadarValidationError("source access permit does not exist")
            SourceAccessPermitLedger.assert_permit_event_tx(con, permit)
            current_epoch = con.execute(
                "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
            ).fetchone()
            if (
                not current_epoch
                or str(current_epoch[0]) != str(permit["source_read_epoch"])
            ):
                raise RadarValidationError("source access permit belongs to an obsolete runtime epoch")
            revocations = con.execute(
                "SELECT * FROM radar_source_access_revocations WHERE permit_id=?", (permit_id,)
            ).fetchall()
            if revocations:
                for revocation in revocations:
                    SourceAccessPermitLedger.assert_revocation_event_tx(con, revocation)
                raise RadarValidationError("source access permit is revoked")
            if not (
                _datetime(str(permit["valid_from_utc"]))
                <= now
                <= _datetime(str(permit["valid_until_utc"]))
            ):
                raise RadarValidationError("source access permit is expired")
            if not (
                _datetime(str(permit["valid_from_utc"]))
                <= _datetime(observed)
                <= min(now + timedelta(minutes=5), _datetime(str(permit["valid_until_utc"])))
            ):
                raise RadarValidationError("source evidence is outside the permitted period")
            passport = con.execute(
                "SELECT rowid AS ledger_rowid,* FROM radar_source_passports WHERE passport_id=?",
                (str(permit["passport_id"]),),
            ).fetchone()
            if not passport:
                raise RadarValidationError("source passport does not exist")
            SourcePassportRegistry.assert_event_binding_tx(con, passport)
            latest = con.execute(
                "SELECT passport_id FROM radar_source_passports WHERE source_key=? ORDER BY rowid DESC LIMIT 1",
                (str(passport["source_key"]),),
            ).fetchone()
            if not latest or str(latest["passport_id"]) != str(passport["passport_id"]):
                raise RadarValidationError("source passport version has been superseded")
            if (
                str(passport["state"]) != PassportState.APPROVED.value
                or str(passport["capability_state"]) != CapabilityState.PASS.value
                or str(passport["licence_state"]) != LicenceState.ALLOWED.value
            ):
                raise RadarValidationError("source passport is no longer approved")
            if str(permit["mode"]) == SourceAccessMode.READ_ONLY_API.value:
                flag = con.execute(
                    "SELECT value FROM schema_meta WHERE key='external_source_reads_enabled'"
                ).fetchone()
                if not flag or str(flag[0]) != "1":
                    raise RadarValidationError("external source reads are disabled")
            verified = RadarEvidenceVault.assert_record_tx(con, evidence_id)
            if (
                verified.content_sha256 != content_sha256
                or verified.byte_count != byte_count
                or verified.data_class != str(permit["data_class"])
                or verified.passport_id != str(permit["passport_id"])
                or verified.source_key_hash != str(permit["source_key_hash"])
                or verified.captured_at_utc != observed
            ):
                raise RadarValidationError("source evidence does not match its verified BLOB")
            if existing:
                # Idempotency never bypasses the current safety context.  A
                # restored, revoked, expired, or superseded permit must stay
                # unusable even when the receipt itself already exists.
                self._assert_receipt_tx(con, existing)
                return EvidenceReceipt(
                    str(existing["receipt_id"]),
                    False,
                    str(existing["permit_id"]),
                    str(existing["content_sha256"]),
                )
            collision = con.execute(
                """SELECT * FROM radar_source_evidence_receipts
                   WHERE permit_id=? AND operation_key=?""",
                (permit_id, operation_key),
            ).fetchone()
            if collision:
                self._assert_receipt_tx(con, collision)
                raise RadarConflict("source operation key was already used")
            prior_receipts = con.execute(
                """SELECT * FROM radar_source_evidence_receipts
                   WHERE permit_id=? ORDER BY receipt_id""",
                (permit_id,),
            ).fetchall()
            for prior_receipt in prior_receipts:
                self._assert_receipt_tx(con, prior_receipt)
            used = con.execute(
                """SELECT COUNT(*),COALESCE(SUM(record_count),0),
                          COALESCE(SUM(byte_count),0),COALESCE(SUM(cost_minor),0)
                   FROM radar_source_access_usage WHERE permit_id=?""",
                (permit_id,),
            ).fetchone()
            if (
                int(used[0]) + 1 > int(permit["max_operations"])
                or int(used[1]) + record_count > int(permit["max_records"])
                or int(used[2]) + byte_count > int(permit["max_bytes"])
                or int(used[3]) + cost_minor > int(permit["max_cost_minor"])
            ):
                raise RadarValidationError("source access budget is exhausted")
            receipt_id = new_lf_id("radar_evidence_receipt")
            usage_id = new_lf_id("radar_access_usage")
            con.execute(
                """INSERT INTO radar_source_evidence_receipts(
                       receipt_id,permit_id,operation_key,record_count,byte_count,
                       cost_minor,content_sha256,evidence_id,passport_id,source_key_hash,
                       observed_at_utc,actor,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    receipt_id,
                    permit_id,
                    operation_key,
                    record_count,
                    byte_count,
                    cost_minor,
                    content_sha256,
                    evidence_id,
                    str(permit["passport_id"]),
                    str(permit["source_key_hash"]),
                    observed,
                    actor,
                    idem,
                    digest,
                    created_at,
                ),
            )
            con.execute(
                """INSERT INTO radar_source_access_usage(
                       usage_id,permit_id,receipt_id,operation_count,record_count,
                       byte_count,cost_minor,observed_at_utc,created_at_utc
                   ) VALUES(?,?,?,1,?,?,?,?,?)""",
                (
                    usage_id,
                    permit_id,
                    receipt_id,
                    record_count,
                    byte_count,
                    cost_minor,
                    observed,
                    created_at,
                ),
            )
            if self.after_reservation_hook:
                self.after_reservation_hook()
            self.store._append_event_tx(
                con,
                event_type="radar_source_evidence_recorded",
                aggregate_type="radar_source_evidence_receipt",
                aggregate_id=receipt_id,
                producer="construction_radar_access",
                idempotency_key=f"receipt:{receipt_id}",
                payload={
                    "permit_id": permit_id,
                    "operation_key_hash": payload_hash({"operation_key": operation_key}),
                    "content_sha256": content_sha256,
                    "passport_id": str(permit["passport_id"]),
                    "source_key_hash": str(permit["source_key_hash"]),
                    "record_count": record_count,
                    "byte_count": byte_count,
                    "cost_minor": cost_minor,
                    "command_hash": digest,
                },
                evidence_ref=_radar_evidence_ref(evidence_id),
                actor=actor,
                occurred_at_utc=observed,
                schema_version=15,
            )
            return EvidenceReceipt(receipt_id, True, permit_id, content_sha256)


__all__ = (
    "EvidenceReceipt",
    "RadarEvidenceCommand",
    "RadarEvidenceResult",
    "RadarEvidenceVault",
    "RadarReviewResolution",
    "RadarReviewResolutionDecision",
    "RadarReviewResolutionResult",
    "RadarReviewResolutionState",
    "RadarReviewResolver",
    "SourceAccessMode",
    "SourceAccessPermit",
    "SourceAccessPermitLedger",
    "SourceAccessPermitResult",
    "SourceAccessRevocationResult",
    "SourceAccessState",
    "SourceEvidenceBoundary",
    "SourceEvidenceCommand",
    "VerifiedRadarEvidence",
)
