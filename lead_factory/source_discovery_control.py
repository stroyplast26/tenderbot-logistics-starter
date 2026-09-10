"""Fail-closed, manual-only control for the first source-discovery slice.

Planning, checks, and status inspection are local-only.  ``run-one`` adds a
durable WIP/uncertainty fence and then delegates exactly once to an existing
source-native one-shot launcher.  This module deliberately has no CRM,
outbox, contact, advertising-spend, or scheduler integration.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Final

from lead_factory.radar_yandex_connection import run_manual_yandex_search
from lead_factory.radar_yandex_search import SearchPage, build_review_queue
from lead_factory.tenderplan_read_only_intake import (
    TENDERPLAN_READ_ONLY_CONFIRMATION,
    TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
    TenderPlanReadOnlyIntakeResult,
    run_tenderplan_read_only_intake,
)


SOURCE_DISCOVERY_CONTROL_VERSION: Final = "source-discovery-control-v1"
SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION: Final = (
    "AUTHORIZE_ONE_PREAUTHORIZED_SOURCE_READ"
)
SOURCE_DISCOVERY_STATE_PATH: Final = (
    Path(__file__).resolve().parent.parent
    / "state"
    / "lead_factory"
    / "source_discovery_control.sqlite3"
)
SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT: Final = 1
SOURCE_DISCOVERY_PILOT_CAP: Final = 1
_SCHEMA_VISIBILITY_RETRIES: Final = 20
_SCHEMA_VISIBILITY_RETRY_SECONDS: Final = 0.01
_WINDOWS_REPARSE_POINT: Final = 0x400


class SourceDiscoverySource(str, Enum):
    YANDEX = "YANDEX"
    TENDERPLAN = "TENDERPLAN"
    SABY = "SABY"
    DOMRF = "DOMRF"
    KONTUR = "KONTUR"


_RUNNABLE_SOURCES: Final = frozenset(
    {SourceDiscoverySource.YANDEX, SourceDiscoverySource.TENDERPLAN}
)
_OFFLINE_CONTRACT_SOURCES: Final = frozenset(
    {
        SourceDiscoverySource.SABY,
        SourceDiscoverySource.DOMRF,
        SourceDiscoverySource.KONTUR,
    }
)
_ATTEMPT_STATES: Final = frozenset(
    {"RUNNING", "READY_FOR_REVIEW", "COMPLETE_NO_RESULTS", "UNCERTAIN"}
)


class SourceDiscoveryControlError(RuntimeError):
    """Sanitized control error that never includes supplied source material."""

    def __init__(self, code: str = "SOURCE_DISCOVERY_CONTROL_FAILED") -> None:
        super().__init__(code)
        self.code = code


def _effects() -> dict[str, object]:
    return {
        "automatic_schedule_eligible": False,
        "campaign_spend_enabled": False,
        "contact_enabled": False,
        "crm_write_enabled": False,
        "native_metering_governed": True,
        "outbox_write_enabled": False,
        "provider_read_may_be_metered": True,
    }


def _source(value: str | SourceDiscoverySource) -> SourceDiscoverySource:
    if isinstance(value, SourceDiscoverySource):
        return value
    if type(value) is not str:
        raise SourceDiscoveryControlError("SOURCE_INVALID")
    try:
        return SourceDiscoverySource(value.strip().upper())
    except ValueError:
        raise SourceDiscoveryControlError("SOURCE_INVALID") from None


def _wip_limit(value: int) -> int:
    if type(value) is not int or value != SOURCE_DISCOVERY_PILOT_CAP:
        raise SourceDiscoveryControlError("WIP_LIMIT_INVALID")
    return value


def _assert_no_reparse_components(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            status = component.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise SourceDiscoveryControlError("CONTROL_STATE_PATH_INVALID") from None
        if component.is_symlink() or (
            getattr(status, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
        ):
            raise SourceDiscoveryControlError("CONTROL_STATE_PATH_INVALID")


def _state_path(value: str | Path) -> Path:
    try:
        supplied = Path(value)
        lexical = supplied if supplied.is_absolute() else Path.cwd() / supplied
        _assert_no_reparse_components(lexical)
        absolute = Path(os.path.abspath(lexical))
        _assert_no_reparse_components(absolute)
        path = absolute.resolve(strict=False)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise SourceDiscoveryControlError("CONTROL_STATE_PATH_INVALID") from None
    if os.path.normcase(str(path)) != os.path.normcase(str(absolute)):
        raise SourceDiscoveryControlError("CONTROL_STATE_PATH_INVALID")
    _assert_no_reparse_components(path)
    return path


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _open_read_only(path: Path) -> sqlite3.Connection:
    _assert_no_reparse_components(path)
    try:
        connection = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        return connection
    except (OSError, sqlite3.Error):
        raise SourceDiscoveryControlError("CONTROL_STATE_UNAVAILABLE") from None


def _open_for_write(path: Path) -> sqlite3.Connection:
    try:
        _assert_no_reparse_components(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        _assert_no_reparse_components(path)
        connection = sqlite3.connect(path, isolation_level=None, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS source_discovery_attempts(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempt_id TEXT NOT NULL UNIQUE CHECK(length(attempt_id)=35),
                   source TEXT NOT NULL CHECK(source IN ('YANDEX','TENDERPLAN')),
                   state TEXT NOT NULL CHECK(state IN (
                       'RUNNING','READY_FOR_REVIEW','COMPLETE_NO_RESULTS','UNCERTAIN'
                   )),
                   started_at_utc TEXT NOT NULL,
                   finished_at_utc TEXT,
                   review_count INTEGER NOT NULL DEFAULT 0
                       CHECK(review_count BETWEEN 0 AND 1000)
               )"""
        )
        connection.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS
                   source_discovery_one_unresolved
               ON source_discovery_attempts(state)
               WHERE state IN ('RUNNING','UNCERTAIN')"""
        )
        return connection
    except (OSError, sqlite3.Error):
        raise SourceDiscoveryControlError("CONTROL_STATE_UNAVAILABLE") from None


def _rows(path: Path) -> tuple[sqlite3.Row, ...]:
    for attempt in range(_SCHEMA_VISIBILITY_RETRIES):
        if not path.exists():
            return ()
        connection = _open_read_only(path)
        try:
            schema_ready = connection.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type='table' AND name='source_discovery_attempts'"""
            ).fetchone()
            if schema_ready is not None:
                rows = connection.execute(
                    """SELECT attempt_id,source,state,review_count
                       FROM source_discovery_attempts ORDER BY sequence"""
                ).fetchall()
                if any(
                    not re.fullmatch(r"sd_[0-9a-f]{32}", str(row["attempt_id"]))
                    or str(row["source"])
                    not in {source.value for source in _RUNNABLE_SOURCES}
                    or str(row["state"]) not in _ATTEMPT_STATES
                    or type(row["review_count"]) is not int
                    or not 0 <= int(row["review_count"]) <= 1000
                    for row in rows
                ):
                    raise SourceDiscoveryControlError(
                        "CONTROL_STATE_INTEGRITY_FAILED"
                    )
                return tuple(rows)
        except SourceDiscoveryControlError:
            raise
        except sqlite3.Error:
            raise SourceDiscoveryControlError(
                "CONTROL_STATE_INTEGRITY_FAILED"
            ) from None
        finally:
            connection.close()
        if attempt + 1 < _SCHEMA_VISIBILITY_RETRIES:
            time.sleep(_SCHEMA_VISIBILITY_RETRY_SECONDS)
    raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


def _snapshot(path: Path, wip_limit: int) -> dict[str, object]:
    rows = _rows(path)
    state_counts = {
        state: sum(str(row["state"]) == state for row in rows)
        for state in sorted(_ATTEMPT_STATES)
    }
    open_review_batches = state_counts["READY_FOR_REVIEW"]
    if state_counts["UNCERTAIN"]:
        gate = "BLOCKED_UNCERTAIN"
    elif state_counts["RUNNING"]:
        gate = "BLOCKED_IN_FLIGHT"
    elif open_review_batches >= wip_limit:
        gate = "BLOCKED_BACKPRESSURE"
    else:
        gate = "READY"
    latest = None
    if rows:
        row = rows[-1]
        latest = {
            "attempt_id": str(row["attempt_id"]),
            "review_count": int(row["review_count"]),
            "source": str(row["source"]),
            "state": str(row["state"]),
        }
    return {
        "attempt_count": len(rows),
        "gate": gate,
        "in_flight_count": state_counts["RUNNING"],
        "latest": latest,
        "manual_reconciliation_required": gate != "READY",
        "open_review_batches": open_review_batches,
        "pilot_cap": SOURCE_DISCOVERY_PILOT_CAP,
        "uncertain_count": state_counts["UNCERTAIN"],
        "wip_limit": wip_limit,
    }


def source_discovery_plan() -> dict[str, object]:
    """Return a deterministic local-only plan; performs no filesystem or network I/O."""

    return {
        "effects": _effects(),
        "operation": "PLAN_LOCAL_ONLY",
        "manual_reconciliation_required_after_nonempty_batch": True,
        "pilot_cap": SOURCE_DISCOVERY_PILOT_CAP,
        "sources": {
            "DOMRF": "BLOCKED_OFFLINE_CONTRACT",
            "KONTUR": "BLOCKED_OFFLINE_CONTRACT",
            "SABY": "BLOCKED_OFFLINE_CONTRACT",
            "TENDERPLAN": "ONE_SHOT_SEPARATE_AUTHORITY_REQUIRED",
            "YANDEX": "ONE_SHOT_SEPARATE_AUTHORITY_REQUIRED",
        },
        "state": "SAFE_FIRST_SLICE",
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
        "wip_unit": "OPEN_REVIEW_BATCH",
    }


def source_discovery_status(
    *,
    state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH,
    wip_limit: int = SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
) -> dict[str, object]:
    """Read an idempotent metadata-only status without creating or changing state."""

    path = _state_path(state_path)
    limit = _wip_limit(wip_limit)
    return {
        "control": _snapshot(path, limit),
        "effects": _effects(),
        "operation": "STATUS_LOCAL_ONLY",
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


def check_source_discovery(
    source: str | SourceDiscoverySource,
    *,
    state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH,
    wip_limit: int = SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
    yandex_job_path: str | Path | None = None,
    folder_id: str | None = None,
    tenderplan_query: str = TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
) -> dict[str, object]:
    """Check local configuration and backpressure only; never calls a provider."""

    selected = _source(source)
    path = _state_path(state_path)
    limit = _wip_limit(wip_limit)
    control = _snapshot(path, limit)
    if selected in _OFFLINE_CONTRACT_SOURCES:
        state = "BLOCKED_OFFLINE_CONTRACT"
    elif control["gate"] != "READY":
        state = str(control["gate"])
    elif selected is SourceDiscoverySource.YANDEX and (
        yandex_job_path is None or type(folder_id) is not str or not folder_id.strip()
    ):
        state = "BLOCKED_CONFIGURATION"
    elif selected is SourceDiscoverySource.TENDERPLAN and (
        type(tenderplan_query) is not str or not tenderplan_query.strip()
    ):
        state = "BLOCKED_CONFIGURATION"
    else:
        state = "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    return {
        "authority_verified": False,
        "control": control,
        "effects": _effects(),
        "operation": "CHECK_LOCAL_ONLY",
        "source": selected.value,
        "state": state,
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


def _blocked_run_report(
    selected: SourceDiscoverySource,
    state: str,
    *,
    path: Path,
    wip_limit: int,
) -> dict[str, object]:
    return {
        "control": _snapshot(path, wip_limit),
        "delegate_call_count": 0,
        "effects": _effects(),
        "operation": "RUN_ONE",
        "review_count": 0,
        "source": selected.value,
        "state": state,
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


def _reserve(
    path: Path,
    source: SourceDiscoverySource,
    wip_limit: int,
) -> tuple[str | None, str | None]:
    connection = _open_for_write(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            """SELECT state FROM source_discovery_attempts"""
        ).fetchall()
        states = tuple(str(row["state"]) for row in rows)
        if "UNCERTAIN" in states:
            connection.execute("ROLLBACK")
            return None, "BLOCKED_UNCERTAIN"
        if "RUNNING" in states:
            connection.execute("ROLLBACK")
            return None, "BLOCKED_IN_FLIGHT"
        if sum(state == "READY_FOR_REVIEW" for state in states) >= wip_limit:
            connection.execute("ROLLBACK")
            return None, "BLOCKED_BACKPRESSURE"
        attempt_id = f"sd_{secrets.token_hex(16)}"
        connection.execute(
            """INSERT INTO source_discovery_attempts(
                   attempt_id,source,state,started_at_utc,review_count
               ) VALUES(?,?,?, ?,0)""",
            (attempt_id, source.value, "RUNNING", _now_utc()),
        )
        connection.execute("COMMIT")
        return attempt_id, None
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_STATE_UNAVAILABLE") from None
    finally:
        connection.close()


def _finish(path: Path, attempt_id: str, state: str, review_count: int) -> None:
    if state not in {"READY_FOR_REVIEW", "COMPLETE_NO_RESULTS", "UNCERTAIN"}:
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
    connection = _open_for_write(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """UPDATE source_discovery_attempts
               SET state=?,finished_at_utc=?,review_count=?
               WHERE attempt_id=? AND state='RUNNING'""",
            (state, _now_utc(), review_count, attempt_id),
        )
        if cursor.rowcount != 1:
            connection.execute("ROLLBACK")
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        connection.execute("COMMIT")
    except SourceDiscoveryControlError:
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        connection.close()


def run_source_discovery_once(
    source: str | SourceDiscoverySource,
    *,
    confirmation: str | None,
    state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH,
    wip_limit: int = SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
    yandex_job_path: str | Path | None = None,
    folder_id: str | None = None,
    tenderplan_query: str = TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
    tenderplan_registration_path: str | Path | None = None,
    tenderplan_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Delegate once to one already-authorized source-native one-shot runner."""

    selected = _source(source)
    path = _state_path(state_path)
    limit = _wip_limit(wip_limit)
    if selected in _OFFLINE_CONTRACT_SOURCES:
        return _blocked_run_report(
            selected, "BLOCKED_OFFLINE_CONTRACT", path=path, wip_limit=limit
        )
    check = check_source_discovery(
        selected,
        state_path=path,
        wip_limit=limit,
        yandex_job_path=yandex_job_path,
        folder_id=folder_id,
        tenderplan_query=tenderplan_query,
    )
    if check["state"] != "READY_FOR_SEPARATE_AUTHORITY_CHECK":
        return _blocked_run_report(
            selected, str(check["state"]), path=path, wip_limit=limit
        )
    if confirmation != SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION:
        return _blocked_run_report(
            selected,
            "BLOCKED_EXPLICIT_CONFIRMATION_REQUIRED",
            path=path,
            wip_limit=limit,
        )
    attempt_id, blocked_state = _reserve(path, selected, limit)
    if attempt_id is None:
        # The refusal is the outcome observed under BEGIN IMMEDIATE.  The
        # snapshot added to the report below is diagnostic only and may already
        # reflect a later state transition by the competing attempt.
        if blocked_state not in {
            "BLOCKED_UNCERTAIN",
            "BLOCKED_IN_FLIGHT",
            "BLOCKED_BACKPRESSURE",
        }:
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        return _blocked_run_report(
            selected, blocked_state, path=path, wip_limit=limit
        )
    if blocked_state is not None:
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")

    try:
        if selected is SourceDiscoverySource.YANDEX:
            result = run_manual_yandex_search(
                yandex_job_path,  # type: ignore[arg-type]
                folder_id=folder_id,  # type: ignore[arg-type]
            )
            if type(result) is not SearchPage:
                raise TypeError
            review_queue = build_review_queue([result])
            review_count = len(review_queue["candidates"])
        else:
            tenderplan_options: dict[str, object] = {
                "confirmation": TENDERPLAN_READ_ONLY_CONFIRMATION,
            }
            if tenderplan_registration_path is not None:
                tenderplan_options["registration_path"] = tenderplan_registration_path
            if tenderplan_store_path is not None:
                tenderplan_options["store_path"] = tenderplan_store_path
            result = run_tenderplan_read_only_intake(
                tenderplan_query,
                **tenderplan_options,
            )
            if type(result) is not TenderPlanReadOnlyIntakeResult:
                raise TypeError
            review_count = result.queued_count
        if type(review_count) is not int or not 0 <= review_count <= 1000:
            raise ValueError
    except BaseException:
        # A catchable interruption is sealed as uncertain.  A hard process
        # termination cannot execute this branch and intentionally leaves the
        # durable RUNNING fence for external/manual reconciliation; this slice
        # has no authority to invent an automatic recovery decision.
        _finish(path, attempt_id, "UNCERTAIN", 0)
        return {
            "control": _snapshot(path, limit),
            "delegate_call_count": 1,
            "effects": _effects(),
            "error_code": "SOURCE_BOUNDARY_UNCERTAIN",
            "operation": "RUN_ONE",
            "review_count": 0,
            "source": selected.value,
            "state": "UNCERTAIN",
            "version": SOURCE_DISCOVERY_CONTROL_VERSION,
        }

    terminal = "READY_FOR_REVIEW" if review_count else "COMPLETE_NO_RESULTS"
    _finish(path, attempt_id, terminal, review_count)
    return {
        "control": _snapshot(path, limit),
        "delegate_call_count": 1,
        "effects": _effects(),
        "operation": "RUN_ONE",
        "review_count": review_count,
        "source": selected.value,
        "state": terminal,
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


__all__ = [
    "SOURCE_DISCOVERY_CONTROL_VERSION",
    "SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT",
    "SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION",
    "SOURCE_DISCOVERY_PILOT_CAP",
    "SOURCE_DISCOVERY_STATE_PATH",
    "SourceDiscoveryControlError",
    "SourceDiscoverySource",
    "check_source_discovery",
    "run_source_discovery_once",
    "source_discovery_plan",
    "source_discovery_status",
]
