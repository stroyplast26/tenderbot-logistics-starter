"""Supplementary, zero-authority response diagnostics; legacy V1 is untouched.

Only the validated detail contract and existing native digest bindings are
stored. The native queue is always opened existing-only/read-only. Losing or
rolling back this sidecar cannot authorize retry or reconcile uncertainty.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from lead_factory import tenderplan_read_only_store as native
from lead_factory.tenderplan_response_failure_detail import (
    ResponseFailureDetailV1, ResponseFailureDetailV2, parse_response_failure_detail,
)


_PROTOCOL = "tenderplan-response-failure-store-v1"
_GENESIS = "0" * 64
_MAX_RECORDS = 4096
_MAX_BYTES = 16 * 1024 * 1024
_FLAGS = {
    "retry_eligible": False,
    "automatic_schedule_eligible": False,
    "live_release_eligible": False,
    "authorizes_reconciliation": False,
}
_TABLES = (
    ("meta", "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID"),
    ("records", "CREATE TABLE records(sequence INTEGER PRIMARY KEY CHECK(sequence>=1), "
     "run_id TEXT NOT NULL UNIQUE, material TEXT NOT NULL, "
     "event_sha256 TEXT NOT NULL UNIQUE, record_sha256 TEXT NOT NULL UNIQUE)"),
)
_SCHEMA = tuple(("table", name, name, sql) for name, sql in _TABLES) + tuple(
    ("trigger", f"{name}_no_{action.lower()}", name,
     f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} "
     "BEGIN SELECT RAISE(ABORT,'immutable response diagnostic'); END")
    for name, _sql in _TABLES for action in ("UPDATE", "DELETE")
)


class TenderPlanResponseFailureStoreError(RuntimeError):
    """A fixed error code; paths, payloads and underlying errors stay private."""

    code = "tenderplan_response_failure_store_invalid"

    def __init__(self) -> None:
        super().__init__(self.code)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _plain(path: str | Path, *, existing: bool) -> Path:
    if not isinstance(path, (str, Path)) or not str(path).strip():
        raise TenderPlanResponseFailureStoreError
    result = Path(os.path.abspath(path))
    for part in (result, *result.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if part == result and not existing:
                continue
            raise TenderPlanResponseFailureStoreError from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise TenderPlanResponseFailureStoreError
    if result.exists():
        info = result.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise TenderPlanResponseFailureStoreError
    return result


def _no_journals(path: Path) -> None:
    if any(os.path.lexists(str(path) + suffix) for suffix in ("-journal", "-wal", "-shm")):
        raise TenderPlanResponseFailureStoreError


def tenderplan_response_failure_path(main_store_path: str | Path) -> Path:
    """Derive a stable full-digest sibling; never create directories or files."""
    main = _plain(main_store_path, existing=True)
    key = hashlib.sha256(os.path.normcase(str(main)).encode("utf-8")).hexdigest()
    return main.with_name(f"tenderplan_response_failure.{key}.sqlite3")


def _binding(main: Path, run_id: str) -> dict[str, str]:
    if type(run_id) is not str or re.fullmatch(r"tpri_[0-9a-f]{32}", run_id) is None:
        raise TenderPlanResponseFailureStoreError
    _plain(main, existing=True)
    _no_journals(main)
    # A normal constructor can bootstrap/write. This existing-only entry point
    # and get_uncertain_binding both use native mode=ro/query_only transactions.
    bound = native._existing_store(main).get_uncertain_binding(run_id)  # noqa: SLF001
    return {
        "main_store_identity_sha256": bound.store_identity_sha256,
        "main_uncertain_event_sha256": bound.main_uncertain_event_sha256,
        "intent_record_sha256": bound.intent_record_sha256,
        "request_sha256": bound.request_sha256,
    }


def _metadata(main: Path, path: Path, identity: str) -> dict[str, str]:
    return {
        "protocol": _PROTOCOL,
        "main_path_sha256": _digest(os.path.normcase(str(main))),
        "sidecar_path_sha256": _digest(os.path.normcase(str(path))),
        "main_store_identity_sha256": identity,
        "schema_sha256": _digest(sorted(_SCHEMA)),
        **{key: "0" for key in _FLAGS},
    }


def _connect(path: Path, *, read_only: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(path.as_uri() + ("?mode=ro" if read_only else "?mode=rw"),
                                 uri=True, timeout=1, isolation_level=None)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema=OFF")
        if read_only:
            connection.execute("PRAGMA query_only=ON")
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise TenderPlanResponseFailureStoreError
        return connection
    except BaseException:
        connection.close()
        raise


def _records(connection: sqlite3.Connection, metadata: dict[str, str]) -> list[dict]:
    schema = [tuple(row) for row in connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    if schema != sorted(_SCHEMA) or dict(connection.execute("SELECT key,value FROM meta")) != metadata:
        raise TenderPlanResponseFailureStoreError
    if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise TenderPlanResponseFailureStoreError
    rows = connection.execute("SELECT * FROM records ORDER BY sequence LIMIT ?",
                              (_MAX_RECORDS + 1,)).fetchall()
    if len(rows) > _MAX_RECORDS:
        raise TenderPlanResponseFailureStoreError
    result = []
    previous = _GENESIS
    for sequence, row in enumerate(rows, 1):
        text = row["material"]
        if type(text) is not str or len(text) > 4096:
            raise TenderPlanResponseFailureStoreError
        value = json.loads(text)
        expected_keys = {"protocol", "sequence", "previous_record_sha256", "recorded_at_utc",
                         "detail", "binding"} | set(_FLAGS)
        if type(value) is not dict or set(value) != expected_keys:
            raise TenderPlanResponseFailureStoreError
        detail = parse_response_failure_detail(value["detail"]).to_mapping()
        binding = value["binding"]
        if type(binding) is not dict or set(binding) != {
            "main_store_identity_sha256", "main_uncertain_event_sha256",
            "intent_record_sha256", "request_sha256",
        } or any(type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None
                 for v in binding.values()):
            raise TenderPlanResponseFailureStoreError
        timestamp = value["recorded_at_utc"]
        if type(timestamp) is not str or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", timestamp
        ) is None:
            raise TenderPlanResponseFailureStoreError
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if (value["protocol"] != _PROTOCOL or type(value["sequence"]) is not int
                or value["sequence"] != sequence or row["sequence"] != sequence
                or row["run_id"] != detail["run_id"]
                or value["previous_record_sha256"] != previous
                or any(value[key] is not False for key in _FLAGS)
                or binding["main_store_identity_sha256"] != metadata["main_store_identity_sha256"]
                or any(binding[key] != detail[key] for key in ("intent_record_sha256", "request_sha256"))
                or text != _canonical(value)):
            raise TenderPlanResponseFailureStoreError
        event = _digest(value)
        record = _digest({"metadata_sha256": _digest(metadata), "event_sha256": event})
        if row["event_sha256"] != event or row["record_sha256"] != record:
            raise TenderPlanResponseFailureStoreError
        result.append({**value, "event_sha256": event, "record_sha256": record})
        previous = record
    return result


def append_tenderplan_response_failure_best_effort(
    *, detail: ResponseFailureDetailV1 | ResponseFailureDetailV2, main_store_path: str | Path,
    clock: Callable[[], datetime] | None = None,
) -> bool:
    """Append after native UNCERTAIN; exact replay succeeds, every failure is inert."""
    try:
        if type(detail) not in (ResponseFailureDetailV1, ResponseFailureDetailV2):
            return False
        payload = parse_response_failure_detail(detail.to_mapping()).to_mapping()
        main = _plain(main_store_path, existing=True)
        binding = _binding(main, payload["run_id"])
        if any(payload[key] != binding[key] for key in ("intent_record_sha256", "request_sha256")):
            return False
        now = clock() if clock is not None else datetime.now(timezone.utc)
        if type(now) is not datetime or now.tzinfo is None or not 2020 <= now.year <= 9998:
            return False
        path = _plain(tenderplan_response_failure_path(main), existing=False)
        _no_journals(path)
        metadata = _metadata(main, path, binding["main_store_identity_sha256"])
        created = False
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if not 0 < path.stat().st_size <= _MAX_BYTES:
                return False
        else:
            os.close(descriptor)
            created = True
        _plain(path, existing=True)
        with closing(_connect(path, read_only=False)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if created:
                for _kind, _name, _table, sql in _SCHEMA:
                    connection.execute(sql)
                connection.executemany("INSERT INTO meta VALUES(?,?)", sorted(metadata.items()))
            records = _records(connection, metadata)
            old = next((item for item in records if item["detail"]["run_id"] == payload["run_id"]), None)
            if old is not None:
                return old["detail"] == payload and old["binding"] == binding
            if len(records) >= _MAX_RECORDS:
                return False
            value = {"protocol": _PROTOCOL, "sequence": len(records) + 1,
                     "previous_record_sha256": records[-1]["record_sha256"] if records else _GENESIS,
                     "recorded_at_utc": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                     "detail": payload, "binding": binding, **_FLAGS}
            event = _digest(value)
            record = _digest({"metadata_sha256": _digest(metadata), "event_sha256": event})
            connection.execute("INSERT INTO records VALUES(?,?,?,?,?)",
                               (value["sequence"], payload["run_id"], _canonical(value), event, record))
            _records(connection, metadata)
            if _binding(main, payload["run_id"]) != binding:
                return False
            connection.commit()
        return True
    except BaseException:
        # Even KeyboardInterrupt in supplementary persistence must not undo or
        # hide the caller's already committed native UNCERTAIN outcome.
        return False


def read_tenderplan_response_failure(*, main_store_path: str | Path, run_id: str) -> dict:
    """Read existing evidence only; absence is explicit and conveys no authority."""
    try:
        main = _plain(main_store_path, existing=True)
        binding = _binding(main, run_id)
        path = _plain(tenderplan_response_failure_path(main), existing=False)
        _no_journals(path)
        result = {"schema": "tenderplan-response-failure-read-v1", "status": "DETAIL_UNAVAILABLE",
                  "run_id": run_id, "detail": None, **binding, **_FLAGS}
        if not path.exists():
            return result
        if not 0 < path.stat().st_size <= _MAX_BYTES:
            raise TenderPlanResponseFailureStoreError
        metadata = _metadata(main, path, binding["main_store_identity_sha256"])
        with closing(_connect(path, read_only=True)) as connection:
            connection.execute("BEGIN")
            records = _records(connection, metadata)
            found = next((item for item in records if item["detail"]["run_id"] == run_id), None)
            if found is None:
                return result
            if found["binding"] != binding:
                raise TenderPlanResponseFailureStoreError
            return {**result, "status": "DETAIL_AVAILABLE", "detail": found["detail"],
                    "event_sha256": found["event_sha256"], "record_sha256": found["record_sha256"]}
    except BaseException:
        raise TenderPlanResponseFailureStoreError from None
