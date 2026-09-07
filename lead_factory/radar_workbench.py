"""Local research work on canonical Radar objects; no transport or CRM effects.

Work items are projections of the existing events/interactions/human_tasks tables.
Manager results are attributed human reports, never verified demand or contact
permission.  The configured actor is the authority for each local command.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .construction_radar import RadarValidationError, SourcePassportRegistry
from .ids import new_lf_id, payload_hash
from .radar_review_access import RadarEvidenceVault
from .store import FactoryStore
from .tasks import HumanTaskController


class RadarWorkbenchError(ValueError):
    """A bounded local command or object reference is invalid."""


class RadarWorkbenchConflict(RadarWorkbenchError):
    """The command is stale, its replay changed, or its projection disagrees."""


RESULT_ACTIONS = {
    "NO_ANSWER": frozenset({"CALLBACK"}),
    "CALLBACK": frozenset({"CALLBACK"}),
    "NEEDS_RESEARCH": frozenset({"RESEARCH", "VERIFY_NEED"}),
    "RFQ_REPORTED": frozenset({"PREPARE_QUOTE"}),
    "QUOTE_REPORTED": frozenset({"FOLLOW_UP"}),
    "RESEARCH_COMPLETE": frozenset({"NONE"}),
    "NOT_RELEVANT": frozenset({"NONE"}),
    "DO_NOT_CONTACT": frozenset({"NONE"}),
}
NEXT_ACTIONS = frozenset().union(*RESULT_ACTIONS.values())
_PRODUCER = "radar_research_workbench"
_KIND = "RADAR_RESEARCH"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}$")
_EVIDENCE = re.compile(r"^(?:evidence://|offline-evidence:)[^\s]{1,480}$")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RadarWorkbenchError(f"{label} is invalid")
    return value


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise RadarWorkbenchError("timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RadarWorkbenchError("timestamp is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RadarWorkbenchError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _version(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 1_000_000:
        raise RadarWorkbenchError("expected version is invalid")
    return value


class RadarResearchWorkbench:
    """Read Radar dossiers and record attributable local manager work."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        actor: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.actor = _identifier(actor, "configured actor")
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> str:
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise RadarWorkbenchError("clock must return an aware datetime")
        return _utc(now)

    @contextmanager
    def _read(self):
        # Reads never bootstrap or migrate a database.
        try:
            path = Path(self.store.path).resolve(strict=True)
        except OSError:
            raise RadarWorkbenchError("existing Radar database is required") from None
        con = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA query_only=ON")
            con.execute("BEGIN")
            if self.store._probe_schema(con) < 15:
                raise RadarWorkbenchError("Radar schema 15 or later is required")
            yield con
        finally:
            con.close()

    @staticmethod
    def _object_tx(con, object_id: str) -> dict[str, Any]:
        row = con.execute(
            """SELECT o.*,p.radar_project_id,p.creation_title FROM radar_objects o
               JOIN radar_projects p ON p.radar_object_id=o.radar_object_id
               WHERE o.radar_object_id=?""",
            (object_id,),
        ).fetchone()
        if row is None:
            raise RadarWorkbenchError("Radar object does not exist")
        return dict(row)

    @staticmethod
    def _history_tx(con, object_id: str) -> list[dict[str, Any]]:
        rows = con.execute(
            """SELECT * FROM events WHERE producer=? AND aggregate_type='radar_object'
               AND aggregate_id=? ORDER BY rowid""",
            (_PRODUCER, object_id),
        ).fetchall()
        history = []
        for number, row in enumerate(rows, 1):
            try:
                body = json.loads(row["payload_json"])
                command = body["command"]
                item = body["work_item"]
                valid = (
                    row["payload_hash"] == payload_hash(body)
                    and command["object_id"] == object_id
                    and command["actor"] == row["actor"]
                    and command["expected_version"] == number - 1
                    and item["object_id"] == object_id
                    and item["version"] == number
                    and body["command_hash"] == payload_hash(command)
                )
            except (ValueError, KeyError, TypeError):
                valid = False
            if not valid:
                raise RadarWorkbenchConflict("work item event provenance is invalid")
            history.append(
                {
                    "event_id": row["event_id"],
                    "time": row["occurred_at_utc"],
                    "actor": row["actor"],
                    "operation": command["operation"],
                    "payload": command,
                    "work_item": item,
                }
            )
        return history

    def _current_tx(self, con, object_id: str) -> dict[str, Any] | None:
        history = self._history_tx(con, object_id)
        if not history:
            return None
        item = history[-1]["work_item"]
        row = con.execute(
            """SELECT t.*,i.source_event_id,i.classification,i.channel,i.direction,
                      i.lf_opportunity_id AS interaction_opportunity
               FROM human_tasks t JOIN interactions i USING(lf_interaction_id)
               WHERE t.lf_task_id=?""",
            (item["task_id"],),
        ).fetchone()
        if row is None or any(
            (
                row["kind"] != _KIND,
                row["classification"] != _KIND,
                row["channel"] != "INTERNAL",
                row["direction"] != "INTERNAL",
                row["lf_opportunity_id"] is not None,
                row["interaction_opportunity"] is not None,
                row["source_event_id"] != history[0]["event_id"],
                row["status"] != item["state"],
                row["assigned_to"] != item["assignee"],
                row["due_at_utc"] != item["due_at_utc"],
            )
        ):
            raise RadarWorkbenchConflict("work item task projection is inconsistent")
        return dict(item)

    @staticmethod
    def _import_source_tx(con, signal: dict[str, Any]) -> dict[str, Any]:
        rows = con.execute(
            """SELECT * FROM events WHERE producer='radar_workbench_import'
               AND event_type='radar_workbench_public_imported'
               AND aggregate_type='radar_signal' AND aggregate_id=?""",
            (signal["radar_signal_id"],),
        ).fetchall()
        if not rows:
            return {}
        try:
            if len(rows) != 1:
                raise ValueError("receipt count")
            event = rows[0]
            body = json.loads(event["payload_json"])
            evidence = RadarEvidenceVault.assert_record_tx(con, body["evidence_id"])
            url = body["source_url"]
            parsed = urlsplit(url)
            alias = "evidence://radar-evidence/" + body["evidence_id"]
            valid = (
                event["payload_hash"] == payload_hash(body)
                and body["version"] == "radar-workbench-import-v1"
                and body["radar_signal_id"] == signal["radar_signal_id"]
                and body["radar_object_id"] == signal["radar_object_id"]
                and body["radar_project_id"] == signal["radar_project_id"]
                and body["passport_id"] == signal["passport_id"] == evidence.passport_id
                and body["content_sha256"] == evidence.content_sha256
                and evidence.classification == "PUBLIC"
                and evidence.data_class == "BUSINESS_PUBLIC"
                and event["actor"] == evidence.actor
                and event["occurred_at_utc"]
                == signal["observed_at_utc"]
                == evidence.captured_at_utc
                and event["evidence_ref"] == signal["evidence_ref"] == alias
                and body["acquisition_mode"] == "MANUAL_IMPORT"
                and body["evidence_semantics"] == "MANUAL_PUBLIC_SOURCE_TRANSCRIPTION"
                and body["external_requests"] == 0
                and isinstance(url, str)
                and len(url) <= 2048
                and parsed.scheme == "https"
                and bool(parsed.hostname)
                and not any((parsed.username, parsed.password, parsed.query, parsed.fragment))
                and parsed.port in (None, 443)
            )
        except (ValueError, KeyError, TypeError, RadarValidationError):
            valid = False
        if not valid:
            raise RadarWorkbenchConflict("public source import receipt is invalid")
        return {
            "source_url": url,
            "evidence_id": evidence.evidence_id,
            "evidence_semantics": body["evidence_semantics"],
            "rights_basis_ref": body["rights_basis_ref"],
            "retention_policy": body["retention_policy"],
        }

    @staticmethod
    def _signals_tx(con, object_id: str, now: str) -> list[dict[str, Any]]:
        rows = con.execute(
            """SELECT s.*,p.max_age_days,p.acquisition_mode,p.valid_until_utc AS passport_valid_until
               FROM radar_signals s JOIN radar_source_passports p USING(passport_id)
               WHERE s.radar_object_id=? ORDER BY s.observed_at_utc,s.rowid""",
            (object_id,),
        ).fetchall()
        signals = [dict(row) for row in rows]

        def revision(value):
            text = str(value)
            return (1, int(text)) if text.isdigit() else (0, text)

        latest = {}
        for row in signals:
            key = (row["source_key"], row["source_external_key"])
            if key not in latest:
                revisions = con.execute(
                    "SELECT source_revision FROM radar_signals WHERE source_key=? AND source_external_key=?",
                    key,
                ).fetchall()
                latest[key] = max(revision(value[0]) for value in revisions)
        for row in signals:
            row.update(RadarResearchWorkbench._import_source_tx(con, row))
            from .megion_radar_import import read_megion_source_metadata_tx

            try:
                row.update(read_megion_source_metadata_tx(con, row))
            except RadarValidationError:
                raise RadarWorkbenchConflict("official permit source receipt is invalid") from None
            passport = con.execute(
                "SELECT * FROM radar_source_passports WHERE passport_id=?", (row["passport_id"],)
            ).fetchone()
            try:
                SourcePassportRegistry.assert_event_binding_tx(con, passport)
            except RadarValidationError:
                raise RadarWorkbenchConflict("source passport provenance is invalid") from None
            latest_passport = con.execute(
                "SELECT * FROM radar_source_passports WHERE source_key=? ORDER BY rowid DESC LIMIT 1",
                (row["source_key"],),
            ).fetchone()
            reasons = []
            if latest_passport["passport_id"] != row["passport_id"]:
                reasons.append("SOURCE_PASSPORT_SUPERSEDED")
            if (
                passport["state"] != "APPROVED"
                or passport["capability_state"] != "PASS"
                or passport["licence_state"] != "ALLOWED"
            ):
                reasons.append("SOURCE_PASSPORT_INACTIVE")
            approval_end = min(
                _time(passport[key])
                for key in (
                    "valid_until_utc",
                    "capability_valid_until_utc",
                    "licence_valid_until_utc",
                )
            )
            if not _time(passport["valid_from_utc"]) <= _time(now) <= approval_end:
                reasons.append("SOURCE_APPROVAL_EXPIRED")
            source_date = row.get("source_publication_at_utc") or row["observed_at_utc"]
            if _time(now) - _time(source_date) > timedelta(days=row["max_age_days"]):
                reasons.append("SOURCE_DATA_STALE")
            row["source_available"] = not any(value != "SOURCE_DATA_STALE" for value in reasons)
            row["freshness_reasons"] = reasons
            row["is_current_revision"] = (
                revision(row["source_revision"])
                == latest[(row["source_key"], row["source_external_key"])]
            )
            row["freshness"] = "STALE" if reasons else "CURRENT"
        return signals

    @staticmethod
    def _reviews_tx(con, object_id: str, now: str) -> list[dict[str, Any]]:
        rows = con.execute(
            """SELECT r.*,s.radar_object_id FROM radar_resolution_reviews r
               JOIN radar_signals s USING(radar_signal_id) WHERE s.radar_object_id=?
               ORDER BY r.created_at_utc,r.rowid""",
            (object_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["resolutions"] = [
                dict(value)
                for value in con.execute(
                    """SELECT * FROM radar_review_resolutions WHERE review_id=?
                   AND decided_at_utc<=? ORDER BY rowid""",
                    (row["review_id"], now),
                )
            ]
            item["effective_state"] = (
                "RESOLVED"
                if any(value["terminal"] for value in item["resolutions"])
                else row["state"]
            )
            result.append(item)
        return result

    def _summary_tx(self, con, object_id: str, now: str) -> dict[str, Any]:
        obj = self._object_tx(con, object_id)
        signals = self._signals_tx(con, object_id, now)
        current = [row for row in signals if row["is_current_revision"]]
        identities = con.execute(
            """SELECT claim_type,normalized_value FROM radar_object_identity_claims
               WHERE radar_object_id=? ORDER BY observed_at_utc,rowid""",
            (object_id,),
        ).fetchall()
        display = {row["claim_type"]: row["normalized_value"] for row in identities}
        coordinates = display.get("LOCATION", "").split("|")
        latitude, longitude = coordinates if len(coordinates) == 2 else ("", "")
        return {
            "object_id": object_id,
            "project_id": obj["radar_project_id"],
            "title": next(
                (row["public_fields"]["title"] for row in reversed(current)
                 if row.get("public_fields", {}).get("title")),
                obj["creation_title"],
            ),
            "address": next(
                (row["public_fields"]["address"] for row in reversed(current)
                 if row.get("public_fields", {}).get("address")),
                display.get("ADDRESS", ""),
            ),
            "latitude": latitude,
            "longitude": longitude,
            "updated_at_utc": max(
                [obj["created_at_utc"]] + [row["collected_at_utc"] for row in signals]
            ),
            "source_count": len({row["source_key"] for row in current}),
            "freshness": (
                "STALE" if any(row["freshness"] == "STALE" for row in current) else "CURRENT"
            )
            if current
            else "UNKNOWN",
            "review_count": sum(
                row["effective_state"] == "OPEN" for row in self._reviews_tx(con, object_id, now)
            ),
            "work_item": self._current_tx(con, object_id),
        }

    def list_objects(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
            raise RadarWorkbenchError("pagination is invalid")
        now = self._now()
        with self._read() as con:
            rows = con.execute(
                "SELECT radar_object_id FROM radar_objects ORDER BY created_at_utc DESC,radar_object_id LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return {
                "items": [self._summary_tx(con, row[0], now) for row in rows],
                "total": con.execute("SELECT COUNT(*) FROM radar_objects").fetchone()[0],
            }

    def dossier(self, object_id: str) -> dict[str, Any]:
        object_id = _identifier(object_id, "object id")
        now = self._now()
        with self._read() as con:
            obj = self._object_tx(con, object_id)
            data = {
                "object": self._summary_tx(con, object_id, now),
                "signals": self._signals_tx(con, object_id, now),
                "reviews": self._reviews_tx(con, object_id, now),
                "history": self._history_tx(con, object_id),
                "work_item": self._current_tx(con, object_id),
            }
            for name, table, key, value in (
                ("identity_claims", "radar_object_identity_claims", "radar_object_id", object_id),
                (
                    "project_claims",
                    "radar_project_claims",
                    "radar_project_id",
                    obj["radar_project_id"],
                ),
                (
                    "participants",
                    "radar_project_participants",
                    "radar_project_id",
                    obj["radar_project_id"],
                ),
                (
                    "predictions",
                    "radar_procurement_predictions",
                    "radar_project_id",
                    obj["radar_project_id"],
                ),
                ("assessments", "radar_assessments", "radar_object_id", object_id),
                (
                    "negative_evidence",
                    "radar_negative_evidence",
                    "radar_project_id",
                    obj["radar_project_id"],
                ),
            ):
                # All SQL identifiers above are constants, never request fields.
                data[name] = [
                    dict(row)
                    for row in con.execute(
                        f"SELECT * FROM {table} WHERE {key}=? ORDER BY rowid", (value,)
                    )
                ]
            signals = {row["radar_signal_id"]: row for row in data["signals"]}
            for name in ("identity_claims", "project_claims", "participants", "predictions"):
                for row in data[name]:
                    signal = signals[row["radar_signal_id"]]
                    row.update(
                        {
                            "source_key": signal["source_key"],
                            "source_revision": signal["source_revision"],
                            "source_freshness": signal["freshness"],
                            "is_current_revision": signal["is_current_revision"],
                            "verification": "REPORTED_CLAIM",
                        }
                    )
                    claim_date = row.get("observed_at_utc") or row.get("predicted_at_utc")
                    row["freshness"] = (
                        "STALE"
                        if (
                            signal["freshness"] == "STALE"
                            or not signal["is_current_revision"]
                            or _time(now) - _time(claim_date)
                            > timedelta(days=signal["max_age_days"])
                        )
                        else "CURRENT"
                    )
            return data

    def assign(
        self,
        object_id: str,
        *,
        assignee: str,
        due_at_utc: str,
        expected_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._change(
            object_id,
            "ASSIGN",
            assignee=assignee,
            due_at_utc=due_at_utc,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
        )

    def reassign(
        self,
        object_id: str,
        *,
        assignee: str,
        due_at_utc: str,
        expected_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._change(
            object_id,
            "REASSIGN",
            assignee=assignee,
            due_at_utc=due_at_utc,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
        )

    def record_result(
        self,
        object_id: str,
        *,
        result: str,
        reason: str,
        evidence_ref: str,
        expected_version: int,
        idempotency_key: str,
        next_action: str = "NONE",
        next_action_at_utc: str = "",
    ) -> dict[str, Any]:
        if (
            not isinstance(result, str)
            or result not in RESULT_ACTIONS
            or not isinstance(next_action, str)
            or next_action not in RESULT_ACTIONS[result]
        ):
            raise RadarWorkbenchError("result and next action do not match")
        if (
            not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 1000
            or any(ord(c) < 32 and c != "\n" for c in reason)
        ):
            raise RadarWorkbenchError(
                "a brief local result note (at most 1000 characters) is required"
            )
        if not isinstance(evidence_ref, str) or _EVIDENCE.fullmatch(evidence_ref) is None:
            raise RadarWorkbenchError("a local evidence reference is required")
        if next_action == "NONE" and next_action_at_utc:
            raise RadarWorkbenchError("terminal result cannot have a next action date")
        due = _utc(_time(next_action_at_utc)) if next_action != "NONE" else ""
        return self._change(
            object_id,
            "RESULT",
            result=result,
            reason=reason.strip(),
            evidence_ref=evidence_ref,
            next_action=next_action,
            due_at_utc=due,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
        )

    def _change(
        self,
        object_id: str,
        operation: str,
        *,
        expected_version: int,
        idempotency_key: str,
        assignee: str = "",
        due_at_utc: str = "",
        result: str = "",
        reason: str = "",
        evidence_ref: str = "",
        next_action: str = "RESEARCH",
    ) -> dict[str, Any]:
        object_id = _identifier(object_id, "object id")
        idem = _identifier(idempotency_key, "idempotency key")
        expected = _version(expected_version)
        if operation != "RESULT":
            assignee = _identifier(assignee, "assignee")
            due_at_utc = _utc(_time(due_at_utc))
        command = {
            "object_id": object_id,
            "operation": operation,
            "actor": self.actor,
            "expected_version": expected,
            "assignee": assignee,
            "due_at_utc": due_at_utc,
            "result": result,
            "reason": reason,
            "evidence_ref": evidence_ref,
            "next_action": next_action,
        }
        now = self._now()
        with self.store.transaction(min_schema_version=15) as con:
            self._object_tx(con, object_id)
            current = self._current_tx(con, object_id)
            replay = con.execute(
                "SELECT * FROM events WHERE producer=? AND idempotency_key=?", (_PRODUCER, idem)
            ).fetchone()
            if replay:
                body = json.loads(replay["payload_json"])
                if body.get("command") != command or replay["payload_hash"] != payload_hash(body):
                    raise RadarWorkbenchConflict("idempotency key was reused with another command")
                return dict(body["work_item"])
            if expected != (current["version"] if current else 0):
                raise RadarWorkbenchConflict("work item version is stale")
            if current and (current["do_not_contact"] or current["state"] == "COMPLETED"):
                raise RadarWorkbenchConflict(
                    "terminal or do-not-contact work item cannot be changed"
                )
            if (operation == "ASSIGN") != (current is None):
                raise RadarWorkbenchConflict(
                    "assign requires no work item; other commands require one"
                )
            if due_at_utc and _time(due_at_utc) <= _time(now):
                raise RadarWorkbenchError("next action date must be in the future")
            if operation == "RESULT" and current["assignee"] != self.actor:
                raise RadarWorkbenchConflict("only the assigned manager may record a result")
            task_id = current["task_id"] if current else new_lf_id("task")
            item = (
                dict(current)
                if current
                else {
                    "object_id": object_id,
                    "task_id": task_id,
                    "state": "OPEN",
                    "result": "",
                    "reason": "",
                    "evidence_ref": "",
                    "reported_by": "",
                    "next_action": "RESEARCH",
                    "do_not_contact": False,
                    "verification": "HUMAN_REPORT_UNVERIFIED",
                }
            )
            item.update(version=expected + 1, updated_at_utc=now)
            if operation == "RESULT":
                terminal = next_action == "NONE"
                item.update(
                    state="COMPLETED" if terminal else "IN_PROGRESS",
                    result=result,
                    reason=reason,
                    evidence_ref=evidence_ref,
                    reported_by=self.actor,
                    next_action=next_action,
                    due_at_utc=due_at_utc or current["due_at_utc"],
                    do_not_contact=result == "DO_NOT_CONTACT",
                )
            else:
                item.update(assignee=assignee, due_at_utc=due_at_utc)
            event, _ = self.store._append_event_tx(
                con,
                event_type="radar_research_work_changed",
                aggregate_type="radar_object",
                aggregate_id=object_id,
                producer=_PRODUCER,
                idempotency_key=idem,
                payload={
                    "command": command,
                    "command_hash": payload_hash(command),
                    "work_item": item,
                },
                actor=self.actor,
                evidence_ref=evidence_ref,
                occurred_at_utc=now,
            )
            if current is None:
                interaction_id = new_lf_id("interaction")
                con.execute(
                    """INSERT INTO interactions(lf_interaction_id,source_event_id,dedupe_key,
                       channel,direction,classification,received_at_utc,created_at_utc)
                       VALUES(?,?,?,'INTERNAL','INTERNAL',?,?,?)""",
                    (
                        interaction_id,
                        event["event_id"],
                        f"radar-research:{object_id}",
                        _KIND,
                        now,
                        now,
                    ),
                )
                con.execute(
                    """INSERT INTO human_tasks(lf_task_id,lf_interaction_id,kind,status,priority,
                       assigned_to,due_at_utc,created_at_utc) VALUES(?,?,?,'OPEN','B',?,?,?)""",
                    (task_id, interaction_id, _KIND, assignee, due_at_utc, now),
                )
            else:
                task = con.execute(
                    "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
                ).fetchone()
                con.execute(
                    """UPDATE human_tasks SET assigned_to=?,due_at_utc=?,status=?,
                       acknowledged_at_utc=?,first_human_action_at_utc=?,closed_at_utc=?,resolution=?
                       WHERE lf_task_id=?""",
                    (
                        item["assignee"],
                        item["due_at_utc"],
                        item["state"],
                        task["acknowledged_at_utc"] or (now if operation == "RESULT" else ""),
                        task["first_human_action_at_utc"] or (now if operation == "RESULT" else ""),
                        now if item["state"] == "COMPLETED" else "",
                        result if item["state"] == "COMPLETED" else "",
                        task_id,
                    ),
                )
                controller = HumanTaskController(self.store)
                if operation == "RESULT" and not task["first_human_action_at_utc"]:
                    controller._event(
                        con,
                        task_id=task_id,
                        state="IN_PROGRESS",
                        actor=self.actor,
                        event_type="human_task_first_action",
                        evidence_ref=evidence_ref,
                    )
                if item["state"] == "COMPLETED":
                    controller._event(
                        con,
                        task_id=task_id,
                        state="COMPLETED",
                        actor=self.actor,
                        event_type="human_task_completed",
                        evidence_ref=evidence_ref,
                        extra={"resolution": result},
                    )
            return dict(item)
