"""Isolated conservative pilot accounting, never an external-read authority.

Every reservation consumes one attempt and its full upper cost estimate forever.
STOP prevents new dispatch intents; one previously granted request may finish.
This local journal has no anti-rollback authority and is not a billing invoice.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Iterator
from uuid import uuid4

from .radar_yandex_search import (
    ENDPOINT, MAX_RESPONSE_BYTES, VERSION, SearchPage, SearchRequest,
    YandexPreparationError, parse_yandex_response,
)

_APPLICATION_ID = 0x59504A31
_SCHEMA_VERSION = 1
_JOURNAL_VERSION = "radar-yandex-pilot-journal-v1"
_CORRELATION_HEADERS = frozenset({"x-request-id", "x-server-trace-id", "x-client-request-id"})
_SCHEMA = """
CREATE TABLE pilot (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    policy_json TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
    created_at_utc TEXT NOT NULL, last_at_utc TEXT NOT NULL,
    stopped INTEGER NOT NULL CHECK(stopped IN (0,1)),
    attempt_count INTEGER NOT NULL CHECK(attempt_count>=0),
    reserved_cost_minor INTEGER NOT NULL CHECK(reserved_cost_minor>=0)
);
CREATE TABLE attempts (
    operation_key TEXT PRIMARY KEY, reservation_id TEXT NOT NULL UNIQUE,
    request_id TEXT UNIQUE, state TEXT NOT NULL
      CHECK(state IN ('RESERVED','DISPATCH_INTENT','UNCERTAIN','COMPLETED')),
    reserved_at_utc TEXT NOT NULL, dispatched_at_utc TEXT,
    finished_at_utc TEXT, cost_minor INTEGER NOT NULL CHECK(cost_minor>=49),
    response BLOB, response_sha256 TEXT, headers_json TEXT,
    retain_until_utc TEXT, reason_code TEXT, row_sha256 TEXT NOT NULL
);
"""


class JournalError(RuntimeError):
    """A log-safe code, with no provider response, credential or filesystem path."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "JOURNAL_ERROR"
        super().__init__(self.code)


def _utc(value: str) -> datetime:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise JournalError("TIME_INVALID")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise JournalError("TIME_INVALID") from None


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(value: object) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _integer(value: int, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise JournalError("POLICY_INVALID")


@dataclass(frozen=True, slots=True)
class PilotPolicy:
    pilot_id: str
    folder_id_sha256: str
    requests: tuple[SearchRequest, ...]
    expires_at_utc: str
    max_requests: int = 100
    max_cost_minor: int = 6000
    reserve_per_request_minor: int = 49
    retention_hours: int = 24

    def __post_init__(self) -> None:
        if (type(self.pilot_id) is not str
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.pilot_id)
                or type(self.folder_id_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", self.folder_id_sha256)):
            raise JournalError("POLICY_INVALID")
        _utc(self.expires_at_utc)
        _integer(self.max_requests, 1, 100)
        _integer(self.max_cost_minor, 49, 6000)
        _integer(self.reserve_per_request_minor, 49, self.max_cost_minor)
        _integer(self.retention_hours, 1, 24)
        if type(self.requests) is not tuple or not 1 <= len(self.requests) <= 100:
            raise JournalError("POLICY_INVALID")
        try:
            if any(type(r) is not SearchRequest or SearchRequest(**asdict(r)) != r for r in self.requests):
                raise JournalError("POLICY_INVALID")
            if len({r.operation_key for r in self.requests}) != len(self.requests):
                raise JournalError("POLICY_INVALID")
        except (YandexPreparationError, TypeError, ValueError):
            raise JournalError("POLICY_INVALID") from None

    def _material(self) -> dict:
        self.__post_init__()
        return {"journal_version": _JOURNAL_VERSION, "endpoint": ENDPOINT,
                "parser_version": VERSION, "currency": "RUB", "policy": asdict(self),
                "request_templates": [r.body("FOLDER_BOUND_BY_SHA256") for r in self.requests]}

    @property
    def sha256(self) -> str:
        return _sha(self._material())


@dataclass(frozen=True, slots=True)
class Reservation:
    operation_key: str
    reservation_id: str


@dataclass(frozen=True, slots=True)
class DispatchGrant:
    operation_key: str
    reservation_id: str
    request_id: str


def _headers(values: dict[str, str]) -> dict[str, str]:
    if type(values) is not dict or len(values) > 100:
        raise JournalError("HEADERS_INVALID")
    result = {}
    for name, value in values.items():
        if type(name) is not str:
            raise JournalError("HEADERS_INVALID")
        key = name.lower()
        if key not in _CORRELATION_HEADERS:
            continue
        if (key in result or type(value) is not str
                or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", value)):
            raise JournalError("HEADERS_INVALID")
        result[key] = value
    return result


def _row_sha(row: dict) -> str:
    return _sha({k: v for k, v in row.items() if k not in {"row_sha256", "response"}})


class YandexPilotJournal:
    def __init__(self, connection: sqlite3.Connection, policy: PilotPolicy) -> None:
        self._connection = connection
        self.policy = policy
        self._expected_sha256 = policy.sha256

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=5,
                                         isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            return connection
        except (sqlite3.Error, OSError, ValueError):
            raise JournalError("JOURNAL_UNAVAILABLE") from None

    @classmethod
    def create(cls, path: str | Path, *, policy: PilotPolicy, now: str) -> YandexPilotJournal:
        if type(policy) is not PilotPolicy:
            raise JournalError("POLICY_INVALID")
        material = _json(policy._material())
        current, expiry = _utc(now), _utc(policy.expires_at_utc)
        if not current < expiry <= current + timedelta(days=14):
            raise JournalError("POLICY_EXPIRY_INVALID")
        try:
            target = Path(path).resolve(strict=False)
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
        except (OSError, ValueError, TypeError):
            raise JournalError("JOURNAL_CREATE_FAILED") from None
        connection = cls._connect(target)
        try:
            connection.executescript("BEGIN IMMEDIATE;" + _SCHEMA)
            connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            connection.execute("INSERT INTO pilot VALUES (1,?,?,?,?,0,0,0)",
                               (material, policy.sha256, now, now))
            connection.execute("COMMIT")
        except sqlite3.Error:
            connection.close()
            raise JournalError("JOURNAL_CREATE_FAILED") from None
        return cls(connection, policy)

    @classmethod
    def open(cls, path: str | Path, *, expected_policy_sha256: str) -> YandexPilotJournal:
        if type(expected_policy_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_policy_sha256):
            raise JournalError("POLICY_MISMATCH")
        try:
            target = Path(path).resolve(strict=True)
        except (OSError, ValueError, TypeError):
            raise JournalError("JOURNAL_UNAVAILABLE") from None
        connection = cls._connect(target)
        try:
            stored = connection.execute("SELECT policy_json FROM pilot WHERE singleton=1").fetchone()
            material = json.loads(stored[0])
            policy_fields = material["policy"]
            policy_fields["requests"] = tuple(SearchRequest(**r) for r in policy_fields["requests"])
            policy = PilotPolicy(**policy_fields)
            if policy.sha256 != expected_policy_sha256:
                raise JournalError("POLICY_MISMATCH")
            journal = cls(connection, policy)
            with journal._transaction():
                pass
            return journal
        except JournalError:
            connection.close()
            raise
        except (sqlite3.Error, TypeError, ValueError, KeyError, IndexError, RecursionError):
            connection.close()
            raise JournalError("JOURNAL_INTEGRITY") from None

    def close(self) -> None:
        self._connection.close()

    def _verify(self) -> sqlite3.Row:
        con = self._connection
        if (con.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
                or con.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION
                or {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                != {"pilot", "attempts"}):
            raise JournalError("JOURNAL_INTEGRITY")
        pilot = con.execute("SELECT * FROM pilot").fetchall()
        if (len(pilot) != 1 or pilot[0]["policy_json"] != _json(self.policy._material())
                or pilot[0]["policy_sha256"] != self._expected_sha256
                or self.policy.sha256 != self._expected_sha256):
            raise JournalError("POLICY_MISMATCH")
        pilot = pilot[0]
        if _utc(pilot["last_at_utc"]) < _utc(pilot["created_at_utc"]):
            raise JournalError("JOURNAL_INTEGRITY")
        rows = con.execute("SELECT * FROM attempts").fetchall()
        keys = {r.operation_key for r in self.policy.requests}
        if (len(rows) != pilot["attempt_count"]
                or sum(r["cost_minor"] for r in rows) != pilot["reserved_cost_minor"]
                or len(rows) > self.policy.max_requests
                or sum(r["cost_minor"] for r in rows) > self.policy.max_cost_minor):
            raise JournalError("JOURNAL_INTEGRITY")
        for value in rows:
            row = dict(value)
            if (row["operation_key"] not in keys or row["row_sha256"] != _row_sha(row)
                    or row["cost_minor"] != self.policy.reserve_per_request_minor
                    or (row["response"] is not None
                        and (len(row["response"]) > MAX_RESPONSE_BYTES
                             or hashlib.sha256(row["response"]).hexdigest() != row["response_sha256"]))):
                raise JournalError("JOURNAL_INTEGRITY")
        return pilot

    @contextmanager
    def _transaction(self, now: str | None = None) -> Iterator[sqlite3.Row]:
        con = self._connection
        try:
            con.execute("BEGIN IMMEDIATE")
            pilot = self._verify()
            if now is not None:
                if _utc(now) < _utc(pilot["last_at_utc"]):
                    raise JournalError("CLOCK_BACKWARDS")
                con.execute("UPDATE pilot SET last_at_utc=? WHERE singleton=1", (now,))
            con.execute("SAVEPOINT journal_work")
            try:
                yield pilot
            except JournalError:
                # Remember valid observed time even when STOP, expiry or a
                # quota check denies work. A restart cannot turn that denial
                # into permission by supplying an earlier timestamp.
                con.execute("ROLLBACK TO journal_work")
                con.execute("RELEASE journal_work")
                con.execute("COMMIT")
                raise
            con.execute("RELEASE journal_work")
            con.execute("COMMIT")
        except (JournalError, sqlite3.Error) as exc:
            if con.in_transaction:
                con.execute("ROLLBACK")
            if isinstance(exc, JournalError):
                raise
            raise JournalError("JOURNAL_UNAVAILABLE") from None
        except BaseException:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise

    def _request(self, request: SearchRequest) -> SearchRequest:
        if type(request) is not SearchRequest or request not in self.policy.requests:
            raise JournalError("REQUEST_NOT_PLANNED")
        return request

    def _active(self, pilot: sqlite3.Row, now: str) -> None:
        if pilot["stopped"]:
            raise JournalError("PILOT_STOPPED")
        if _utc(now) >= _utc(self.policy.expires_at_utc):
            raise JournalError("POLICY_EXPIRED")

    def _save(self, row: dict) -> None:
        row["row_sha256"] = _row_sha(row)
        columns = tuple(row)
        self._connection.execute(
            "INSERT OR REPLACE INTO attempts (" + ",".join(columns) + ") VALUES ("
            + ",".join("?" for _ in columns) + ")", tuple(row[c] for c in columns))

    def _reservation(self, token: Reservation | DispatchGrant) -> dict:
        if type(token) not in {Reservation, DispatchGrant}:
            raise JournalError("RESERVATION_MISMATCH")
        row = self._connection.execute("SELECT * FROM attempts WHERE operation_key=?",
                                       (token.operation_key,)).fetchone()
        if row is None or row["reservation_id"] != token.reservation_id:
            raise JournalError("RESERVATION_MISMATCH")
        if type(token) is DispatchGrant and row["request_id"] != token.request_id:
            raise JournalError("RESERVATION_MISMATCH")
        return dict(row)

    def reserve(self, request: SearchRequest, *, now: str) -> Reservation:
        request = self._request(request)
        with self._transaction(now) as pilot:
            self._active(pilot, now)
            rows = self._connection.execute("SELECT * FROM attempts").fetchall()
            if any(r["state"] != "COMPLETED" for r in rows):
                raise JournalError("RECONCILE_REQUIRED")
            if any(r["operation_key"] == request.operation_key for r in rows):
                raise JournalError("COMPLETED_ALREADY")
            dispatched = [r["dispatched_at_utc"] for r in rows if r["dispatched_at_utc"]]
            if dispatched and _utc(now) < _utc(max(dispatched)) + timedelta(seconds=1):
                raise JournalError("RATE_LIMIT")
            cost = self.policy.reserve_per_request_minor
            if len(rows) >= self.policy.max_requests or sum(r["cost_minor"] for r in rows) + cost > self.policy.max_cost_minor:
                raise JournalError("BUDGET_EXHAUSTED")
            reservation = Reservation(request.operation_key, str(uuid4()))
            self._save({"operation_key": reservation.operation_key, "reservation_id": reservation.reservation_id,
                        "request_id": None, "state": "RESERVED", "reserved_at_utc": now,
                        "dispatched_at_utc": None, "finished_at_utc": None, "cost_minor": cost,
                        "response": None, "response_sha256": None, "headers_json": None,
                        "retain_until_utc": None, "reason_code": None})
            self._connection.execute(
                "UPDATE pilot SET attempt_count=attempt_count+1,reserved_cost_minor=reserved_cost_minor+? WHERE singleton=1",
                (cost,))
            return reservation

    def mark_dispatch_intent(self, reservation: Reservation, *, now: str) -> DispatchGrant:
        with self._transaction(now) as pilot:
            self._active(pilot, now)
            if type(reservation) is not Reservation:
                raise JournalError("RESERVATION_MISMATCH")
            row = self._reservation(reservation)
            if row["state"] != "RESERVED":
                raise JournalError("RECONCILE_REQUIRED")
            grant = DispatchGrant(reservation.operation_key, reservation.reservation_id, str(uuid4()))
            row.update(state="DISPATCH_INTENT", request_id=grant.request_id, dispatched_at_utc=now)
            self._save(row)
            return grant

    def finish_response(self, grant: DispatchGrant, *, raw_response: bytes,
                        received_at_utc: str, response_headers: dict[str, str]) -> SearchPage:
        invalid = False
        page = None
        with self._transaction(received_at_utc):
            if type(grant) is not DispatchGrant:
                raise JournalError("RESERVATION_MISMATCH")
            row = self._reservation(grant)
            if row["state"] != "DISPATCH_INTENT":
                raise JournalError("RECONCILE_REQUIRED")
            request = next(r for r in self.policy.requests if r.operation_key == grant.operation_key)
            try:
                page = parse_yandex_response(raw_response, request=request, received_at_utc=received_at_utc)
                headers = _headers(response_headers)
            except (YandexPreparationError, JournalError):
                invalid = True
                row.update(state="UNCERTAIN", finished_at_utc=received_at_utc, reason_code="RESPONSE_INVALID")
            else:
                row.update(state="COMPLETED", finished_at_utc=received_at_utc, response=raw_response,
                           response_sha256=page.response_sha256, headers_json=_json(headers),
                           retain_until_utc=(_utc(received_at_utc) + timedelta(hours=self.policy.retention_hours))
                           .strftime("%Y-%m-%dT%H:%M:%SZ"))
            self._save(row)
        if invalid:
            raise JournalError("RESPONSE_INVALID")
        return page

    def finish_uncertain(self, grant: DispatchGrant, *, reason_code: str, now: str) -> None:
        if type(reason_code) is not str or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason_code):
            raise JournalError("REASON_INVALID")
        with self._transaction(now):
            if type(grant) is not DispatchGrant:
                raise JournalError("RESERVATION_MISMATCH")
            row = self._reservation(grant)
            if row["state"] == "UNCERTAIN" and row["reason_code"] == reason_code:
                return
            if row["state"] != "DISPATCH_INTENT":
                raise JournalError("RECONCILE_REQUIRED")
            row.update(state="UNCERTAIN", finished_at_utc=now, reason_code=reason_code)
            self._save(row)

    def _completed(self, request: SearchRequest, now: str) -> dict | None:
        request = self._request(request)
        row = self._connection.execute("SELECT * FROM attempts WHERE operation_key=?",
                                       (request.operation_key,)).fetchone()
        if row is None:
            return None
        if row["state"] != "COMPLETED":
            raise JournalError("RECONCILE_REQUIRED")
        if row["response"] is None or _utc(now) >= _utc(row["retain_until_utc"]):
            raise JournalError("RESULT_EXPIRED")
        return dict(row)

    def read_completed(self, request: SearchRequest, *, now: str) -> SearchPage | None:
        with self._transaction(now):
            row = self._completed(request, now)
            if row is None:
                return None
            try:
                return parse_yandex_response(row["response"], request=request,
                                             received_at_utc=row["finished_at_utc"])
            except YandexPreparationError:
                raise JournalError("JOURNAL_INTEGRITY") from None

    def read_response(self, request: SearchRequest, *, now: str) -> bytes | None:
        with self._transaction(now):
            row = self._completed(request, now)
            return None if row is None else row["response"]

    def stop(self, *, now: str) -> None:
        with self._transaction(now):
            self._connection.execute("UPDATE pilot SET stopped=1 WHERE singleton=1")

    def status(self) -> dict:
        with self._transaction() as pilot:
            rows = self._connection.execute("SELECT * FROM attempts").fetchall()
            spent = sum(r["cost_minor"] for r in rows)
            return {"policy_sha256": self._expected_sha256, "stopped": bool(pilot["stopped"]),
                    "expires_at_utc": self.policy.expires_at_utc, "attempts_reserved": len(rows),
                    "max_requests": self.policy.max_requests, "reserved_cost_minor": spent,
                    "remaining_cost_minor": self.policy.max_cost_minor - spent,
                    "currency": "RUB", "cost_semantics": "UPPER_ESTIMATE_NOT_INVOICE",
                    "states": {state: sum(r["state"] == state for r in rows)
                               for state in ("RESERVED", "DISPATCH_INTENT", "UNCERTAIN", "COMPLETED")},
                    "retained_responses": sum(r["response"] is not None for r in rows),
                    "live_authority_granted": False}

    def retention_status(self, *, now: str) -> dict[str, object]:
        """Return raw-retention deadlines only; never return payload or headers."""

        current = _utc(now)
        with self._transaction(now):
            rows = self._connection.execute(
                "SELECT retain_until_utc FROM attempts WHERE response IS NOT NULL"
            ).fetchall()
            deadlines = tuple(str(row["retain_until_utc"]) for row in rows)
            parsed = tuple(_utc(value) for value in deadlines)
            return {
                "next_purge_at_utc": min(deadlines) if deadlines else None,
                "purge_due_count": sum(deadline <= current for deadline in parsed),
                "retained_responses": len(deadlines),
            }

    def purge_expired(self, *, now: str) -> int:
        with self._transaction(now):
            rows = self._connection.execute(
                "SELECT * FROM attempts WHERE response IS NOT NULL AND retain_until_utc<=?", (now,)).fetchall()
            for value in rows:
                row = dict(value)
                row.update(response=None, headers_json=None)
                self._save(row)
            return len(rows)
