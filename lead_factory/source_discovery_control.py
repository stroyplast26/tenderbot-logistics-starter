"""Fail-closed, manual-only control for the first source-discovery slice.

Planning, checks, and status inspection are local-only.  ``run-one`` adds a
durable WIP/uncertainty fence and then delegates exactly once to an existing
source-native one-shot launcher.  This module deliberately has no CRM,
outbox, contact, advertising-spend, or scheduler integration.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Final, Mapping, NoReturn

from lead_factory.radar_yandex_connection import (
    ManualYandexSearchOutcome,
    check_manual_yandex_search,
    run_manual_yandex_search_accounted,
)
from lead_factory.radar_yandex_connection_authority import ManualYandexSearchBinding
from lead_factory.radar_yandex_credential_broker import (
    YandexCredentialBrokerError,
    load_yandex_api_key,
)
from lead_factory.radar_yandex_search import SearchPage, build_review_queue
from lead_factory.radar_yandex_transport import YandexTransportError
from lead_factory.radar_yandex_source_lab_bridge import (
    SOURCE_DISCOVERY_SOURCE_LAB_PATH,
    YandexSourceLabBatchReceipt,
    YandexSourceLabBridgeError,
    inspect_yandex_batch_closure,
    list_yandex_review_batch_receipts,
    persist_yandex_review_batch,
    preflight_yandex_source_lab,
    select_yandex_reviewable_page,
)
from lead_factory.tenderplan_read_only_intake import (
    TENDERPLAN_READ_ONLY_CONFIRMATION,
    TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
    TenderPlanReadOnlyIntakeResult,
    check_tenderplan_read_only_intake,
    run_tenderplan_read_only_intake,
    _verified_registration_safe,
)
from lead_factory.tenderplan_owner_canary import TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH
from lead_factory.tenderplan_read_only_store import TENDERPLAN_READ_ONLY_QUEUE_PATH, _existing_store
from lead_factory.tenderplan_read_only_transport import (
    TENDERPLAN_READ_ONLY_MAX_RECORDS,
    TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
    tenderplan_read_only_query_policy_sha256,
    tenderplan_read_only_request_sha256,
)


SOURCE_DISCOVERY_CONTROL_VERSION: Final = "source-discovery-control-v5"
SOURCE_DISCOVERY_PREPARE_CONFIRMATION: Final = "PREPARE_LOCAL_TENDERPLAN_RECEIPT_BINDINGS"
SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION: Final = "AUTHORIZE_ONE_PREAUTHORIZED_SOURCE_READ"
SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION: Final = "CLOSE_LOCAL_SOURCE_REVIEW_ONLY"
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
_APPEND_ONLY_TABLES: Final = (
    "source_discovery_yandex_bindings",
    "source_discovery_yandex_accounting",
    "source_discovery_batch_links",
    "source_discovery_review_closures",
)
_SAFE_CONTROL_ERROR_CODES: Final = frozenset(
    {
        "CONTROL_RECONCILIATION_REQUIRED",
        "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED",
        "CONTROL_STATE_INTEGRITY_FAILED",
        "CONTROL_STATE_PATH_INVALID",
        "CONTROL_STATE_UNAVAILABLE",
        "CONTROL_SCHEMA_PREPARATION_REQUIRED",
        "CONTROL_SCHEMA_PREPARATION_CONFIRMATION_REQUIRED",
        "CONTROL_SCHEMA_PREPARATION_IN_FLIGHT",
        "TENDERPLAN_RECEIPT_INVALID",
        "LOCAL_CLOSE_CONFIRMATION_REQUIRED",
        "LOCAL_REVIEW_ACTOR_INVALID",
        "LOCAL_REVIEW_BATCH_NOT_CLOSABLE",
        "LOCAL_REVIEW_CLOSE_CONFLICT",
        "LOCAL_REVIEW_EVIDENCE_INVALID",
        "LOCAL_REVIEW_IDEMPOTENCY_INVALID",
        "LOCAL_REVIEW_STORE_MISMATCH",
        "SOURCE_BOUNDARY_UNCERTAIN",
        "SOURCE_DISCOVERY_ATTEMPT_INVALID",
        "SOURCE_DISCOVERY_CONTROL_FAILED",
        "SOURCE_INVALID",
        "SOURCE_LAB_BATCH_RECEIPT_INVALID",
        "WIP_LIMIT_INVALID",
        "YANDEX_ACCOUNTING_INCONSISTENT",
        "YANDEX_AUTHORITY_CHECK_REJECTED",
        "YANDEX_BINDING_INVALID",
    }
)
_SAFE_YANDEX_CONTROL_ERROR_CODES: Final = frozenset(
    {
        "YANDEX_SOURCE_LAB_PATH_INVALID",
        "YANDEX_SOURCE_LAB_PREFLIGHT_FAILED",
    }
)


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
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_YANDEX_ACCOUNTING_KEYS: Final = frozenset(
    {
        "attempts_reserved",
        "cost_semantics",
        "currency",
        "expires_at_utc",
        "live_authority_granted",
        "max_requests",
        "policy_sha256",
        "remaining_cost_minor",
        "reserved_cost_minor",
        "retained_responses",
        "states",
        "stopped",
    }
)
_YANDEX_ACCOUNTING_STATES: Final = (
    "RESERVED",
    "DISPATCH_INTENT",
    "UNCERTAIN",
    "COMPLETED",
)
_SANITIZED_ACCOUNTING_KEYS: Final = frozenset(
    {
        "accounting_status",
        "attempts_reserved",
        "cost_semantics",
        "currency",
        "max_requests",
        "remaining_cost_minor",
        "reserved_cost_minor",
        "retained_responses",
        "states",
        "stopped",
    }
)


class SourceDiscoveryControlError(RuntimeError):
    """Sanitized control error that never includes supplied source material."""

    def __init__(self, code: str = "SOURCE_DISCOVERY_CONTROL_FAILED") -> None:
        super().__init__(code)
        self.code = code


def _known_control_failure_code(
    error: SourceDiscoveryControlError,
    fallback: str,
) -> str:
    code = error.code
    if type(code) is str and code in _SAFE_CONTROL_ERROR_CODES:
        return code
    return fallback


def _raise_detached_control_failure(code: str) -> NoReturn:
    if code not in _SAFE_CONTROL_ERROR_CODES:
        code = "SOURCE_DISCOVERY_CONTROL_FAILED"
    raise SourceDiscoveryControlError(code) from None


def _raise_detached_yandex_control_failure(code: str) -> NoReturn:
    if code not in _SAFE_YANDEX_CONTROL_ERROR_CODES:
        code = "YANDEX_SOURCE_LAB_PREFLIGHT_FAILED"
    raise YandexSourceLabBridgeError(code) from None


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


def _accounting_marker(status: str) -> dict[str, object]:
    return {"accounting_status": status}


def _validated_yandex_accounting(
    external_requests_this_run: object,
    journal: object,
    *,
    completed: bool,
) -> tuple[int, dict[str, object]]:
    """Validate native evidence before the controller trusts an HTTP count."""

    if (
        type(external_requests_this_run) is not int
        or external_requests_this_run not in {0, 1}
        or not isinstance(journal, Mapping)
        or set(journal) != _YANDEX_ACCOUNTING_KEYS
    ):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    states = journal.get("states")
    if (
        not isinstance(states, Mapping)
        or set(states) != set(_YANDEX_ACCOUNTING_STATES)
        or any(type(states[state]) is not int for state in _YANDEX_ACCOUNTING_STATES)
        or any(not 0 <= states[state] <= 1 for state in _YANDEX_ACCOUNTING_STATES)
    ):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    attempts = journal.get("attempts_reserved")
    reserved_cost = journal.get("reserved_cost_minor")
    remaining_cost = journal.get("remaining_cost_minor")
    retained = journal.get("retained_responses")
    if (
        type(attempts) is not int
        or attempts not in {0, 1}
        or type(reserved_cost) is not int
        or reserved_cost != attempts * 49
        or type(remaining_cost) is not int
        or remaining_cost != 49 - reserved_cost
        or type(retained) is not int
        or retained != states["COMPLETED"]
        or sum(states[state] for state in _YANDEX_ACCOUNTING_STATES) != attempts
        or type(journal.get("max_requests")) is not int
        or journal.get("max_requests") != 1
        or journal.get("currency") != "RUB"
        or journal.get("cost_semantics") != "UPPER_ESTIMATE_NOT_INVOICE"
        or type(journal.get("stopped")) is not bool
        or journal.get("live_authority_granted") is not False
        or type(journal.get("policy_sha256")) is not str
        or _SHA256.fullmatch(str(journal["policy_sha256"])) is None
        or type(journal.get("expires_at_utc")) is not str
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            str(journal["expires_at_utc"]),
        )
        is None
    ):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    try:
        datetime.strptime(str(journal["expires_at_utc"]), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT") from None

    state_counts = {state: int(states[state]) for state in _YANDEX_ACCOUNTING_STATES}
    if completed:
        if attempts != 1 or state_counts != {
            "RESERVED": 0,
            "DISPATCH_INTENT": 0,
            "UNCERTAIN": 0,
            "COMPLETED": 1,
        }:
            raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    else:
        no_attempt = attempts == 0 and all(value == 0 for value in state_counts.values())
        uncertain_attempt = attempts == 1 and state_counts == {
            "RESERVED": 0,
            "DISPATCH_INTENT": 0,
            "UNCERTAIN": 1,
            "COMPLETED": 0,
        }
        if not (no_attempt or uncertain_attempt):
            raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
        if external_requests_this_run == 1 and not uncertain_attempt:
            raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")

    return external_requests_this_run, {
        "accounting_status": "VERIFIED",
        "attempts_reserved": attempts,
        "cost_semantics": "UPPER_ESTIMATE_NOT_INVOICE",
        "currency": "RUB",
        "max_requests": 1,
        "remaining_cost_minor": remaining_cost,
        "reserved_cost_minor": reserved_cost,
        "retained_responses": retained,
        "states": state_counts,
        "stopped": journal["stopped"],
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


def _source_lab_path(*, control_path: Path) -> Path:
    return _state_path(control_path.with_name(SOURCE_DISCOVERY_SOURCE_LAB_PATH.name))


def _source_lab_path_sha256(path: Path) -> str:
    return hashlib.sha256(os.path.normcase(str(path)).encode("utf-8", "strict")).hexdigest()


def _append_only_trigger_sql(table: str, operation: str) -> str:
    return (
        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.casefold()} "
        f"BEFORE {operation.upper()} ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'SOURCE_DISCOVERY_APPEND_ONLY'); END"
    )


def _normalize_control_sql(value: object) -> str:
    normalized = " ".join(str(value or "").split()).casefold()
    return normalized.replace("create trigger if not exists ", "create trigger ", 1)


def _validate_append_only_triggers(connection: sqlite3.Connection) -> None:
    expected = {
        f"{table}_no_{operation.casefold()}": (
            table,
            _normalize_control_sql(_append_only_trigger_sql(table, operation)),
        )
        for table in _APPEND_ONLY_TABLES
        for operation in ("UPDATE", "DELETE")
    }
    placeholders = ",".join("?" for _ in _APPEND_ONLY_TABLES)
    rows = connection.execute(
        f"""SELECT name,tbl_name,sql FROM sqlite_master
            WHERE type='trigger' AND tbl_name IN ({placeholders})""",
        _APPEND_ONLY_TABLES,
    ).fetchall()
    actual = {
        str(row["name"]): (
            str(row["tbl_name"]),
            _normalize_control_sql(row["sql"]),
        )
        for row in rows
    }
    if actual != expected:
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    ).hexdigest()


_CONTROL_V4_SCHEMA_SHA256 = "461c0d93475ebcb0700b1d62343067e5d05e170f344b46b7b1749537456f6246"
_CONTROL_V5_SCHEMA_SHA256 = "c516f1ab7630cc809efd835a965e12f61d376fb7ba06f849f928f9816bb854da"
_TP_BINDINGS = "source_discovery_tenderplan_bindings"
_TP_SCHEMA_SQL = (
    "ALTER TABLE source_discovery_attempts ADD COLUMN tenderplan_binding_required INTEGER NOT NULL DEFAULT 0 CHECK(tenderplan_binding_required IN (0,1))",
    """CREATE TABLE source_discovery_tenderplan_bindings(
        attempt_id TEXT PRIMARY KEY REFERENCES source_discovery_attempts(attempt_id),
        binding_required INTEGER NOT NULL CHECK(binding_required=1),
        native_store_identity_sha256 TEXT NOT NULL,
        native_path_sha256 TEXT NOT NULL,
        run_id TEXT NOT NULL,
        receipt_record_sha256 TEXT NOT NULL,
        event_sha256 TEXT NOT NULL,
        intent_record_sha256 TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        query_policy_sha256 TEXT NOT NULL,
        item_ids_json TEXT NOT NULL,
        card_count INTEGER NOT NULL CHECK(card_count BETWEEN 0 AND 5),
        binding_receipt_sha256 TEXT NOT NULL,
        recorded_at_utc TEXT NOT NULL,
        UNIQUE(native_store_identity_sha256,run_id)
    )""",
    """CREATE TRIGGER source_discovery_tenderplan_required_insert
    BEFORE INSERT ON source_discovery_attempts
    WHEN NEW.tenderplan_binding_required != (NEW.source='TENDERPLAN')
    BEGIN SELECT RAISE(ABORT, 'TENDERPLAN_BINDING_REQUIRED'); END""",
    """CREATE TRIGGER source_discovery_tenderplan_marker_immutable
    BEFORE UPDATE OF tenderplan_binding_required,attempt_id,source ON source_discovery_attempts
    WHEN NEW.tenderplan_binding_required != OLD.tenderplan_binding_required
      OR NEW.attempt_id != OLD.attempt_id OR NEW.source != OLD.source
    BEGIN SELECT RAISE(ABORT, 'TENDERPLAN_MARKER_IMMUTABLE'); END""",
)


def _control_schema_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    return _digest([
        {"type": row[0], "name": row[1], "table": row[2], "sql": _normalize_control_sql(row[3])}
        for row in rows
    ])


def _control_schema_version(connection: sqlite3.Connection) -> int:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    digest = _control_schema_digest(connection)
    if version == 0 and digest == _CONTROL_V4_SCHEMA_SHA256:
        return 4
    if version == 5 and digest == _CONTROL_V5_SCHEMA_SHA256:
        return 5
    raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


def _install_tenderplan_binding_schema(connection: sqlite3.Connection) -> None:
    for statement in _TP_SCHEMA_SQL:
        connection.execute(statement)
    for operation in ("UPDATE", "DELETE"):
        connection.execute(_append_only_trigger_sql(_TP_BINDINGS, operation))
    connection.execute("PRAGMA user_version=5")


def _tenderplan_schema_ready(path: Path) -> bool:
    if not path.exists():
        return False
    connection = _open_read_only(path)
    try:
        return _control_schema_version(connection) == 5
    finally:
        connection.close()


def prepare_source_discovery_tenderplan_bindings(
    *, state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH, confirmation: str | None,
) -> dict[str, object]:
    """Explicit atomic schema preparation; preserves every existing attempt."""
    if confirmation != SOURCE_DISCOVERY_PREPARE_CONFIRMATION:
        raise SourceDiscoveryControlError("CONTROL_SCHEMA_PREPARATION_CONFIRMATION_REQUIRED")
    path = _state_path(state_path)
    connection = _open_for_write(path, prepare_tenderplan=True)
    connection.close()
    return {
        "operation": "PREPARE_TENDERPLAN_BINDINGS_LOCAL", "state": "PREPARED",
        "schema_version": 5, "version": SOURCE_DISCOVERY_CONTROL_VERSION,
        "effects": _local_effects(),
    }


def _expected_tenderplan_run_id(attempt_id: str) -> str:
    if type(attempt_id) is not str or re.fullmatch(r"sd_[0-9a-f]{32}", attempt_id) is None:
        raise SourceDiscoveryControlError("TENDERPLAN_RECEIPT_INVALID")
    return "tpri_" + attempt_id[3:]


def _verified_tenderplan_binding(
    attempt_id: str, result: TenderPlanReadOnlyIntakeResult, query: str, store_path: str | Path,
    registration_path: str | Path,
) -> dict[str, object]:
    """Verify a causal receipt using metadata only, never decrypt or bootstrap."""
    try:
        if type(result) is not TenderPlanReadOnlyIntakeResult or result.run_id != _expected_tenderplan_run_id(attempt_id):
            raise ValueError
        # A frozen dataclass can still be replaced or forged at a boundary.
        result.__post_init__()
        policy = tenderplan_read_only_query_policy_sha256(query, maximum_records=TENDERPLAN_READ_ONLY_MAX_RECORDS)
        auth_reference, credential_target_sha256 = _verified_registration_safe(registration_path)
        auth_reference_sha256 = hashlib.sha256(auth_reference.encode("ascii")).hexdigest()
        store = _existing_store(store_path)
        with store._transaction(write=False) as connection:
            ready = store._ready_receipt(connection, result.run_id)
            operation = connection.execute(
                "SELECT intent_json FROM tenderplan_read_only_operations WHERE run_id=?", (result.run_id,)
            ).fetchone()
            intent = json.loads(operation["intent_json"])
            event = store._latest_event(connection, result.run_id)
            receipt = json.loads(event["payload_json"])
            expected_request = tenderplan_read_only_request_sha256(
                run_id=result.run_id, auth_reference_id_sha256=intent["auth_reference_id_sha256"],
                credential_target_sha256=intent["credential_target_sha256"], nonce_sha256=intent["nonce_sha256"],
                query_policy_sha256=policy, expires_at_utc=intent["expires_at_utc"],
                maximum_response_bytes=TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
                maximum_records=TENDERPLAN_READ_ONLY_MAX_RECORDS,
            )
            if (
                ready.run_id != result.run_id or ready.receipt_record_sha256 != result.receipt_record_sha256
                or ready.event_sha256 != result.event_sha256 or ready.card_count != result.queued_count
                or ready.item_ids != result.item_ids or len(set(result.item_ids)) != len(result.item_ids)
                or receipt["provider_reported_count"] != result.provider_reported_count
                or receipt["returned_count"] != result.returned_count
                or intent["query_policy_sha256"] != policy or intent["request_sha256"] != expected_request
                or intent["auth_reference_id_sha256"] != auth_reference_sha256
                or intent["credential_target_sha256"] != credential_target_sha256
                or intent["maximum_records"] != TENDERPLAN_READ_ONLY_MAX_RECORDS
                or intent["maximum_response_bytes"] != TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES
            ):
                raise ValueError
            body = {
                "attempt_id": attempt_id, "binding_required": 1,
                "native_store_identity_sha256": store.store_identity_sha256,
                "native_path_sha256": _source_lab_path_sha256(store.path),
                "run_id": result.run_id, "receipt_record_sha256": ready.receipt_record_sha256,
                "event_sha256": ready.event_sha256, "intent_record_sha256": intent["intent_record_sha256"],
                "request_sha256": expected_request, "query_policy_sha256": policy,
                "item_ids": list(ready.item_ids), "card_count": ready.card_count,
                "recorded_at_utc": _now_utc(),
            }
        return {**body, "binding_receipt_sha256": _digest(body)}
    except BaseException:
        raise SourceDiscoveryControlError("TENDERPLAN_RECEIPT_INVALID") from None


def _tenderplan_binding_body(row: sqlite3.Row) -> dict[str, object]:
    return {
        key: (json.loads(row["item_ids_json"]) if key == "item_ids" else row[key])
        for key in (
            "attempt_id", "binding_required", "native_store_identity_sha256", "native_path_sha256",
            "run_id", "receipt_record_sha256", "event_sha256", "intent_record_sha256",
            "request_sha256", "query_policy_sha256", "item_ids", "card_count", "recorded_at_utc",
        )
    }


def _validate_tenderplan_bindings(connection: sqlite3.Connection) -> dict[str, dict[str, object]]:
    try:
        if _control_schema_version(connection) != 5:
            raise ValueError
        attempts = {row["attempt_id"]: row for row in connection.execute("SELECT * FROM source_discovery_attempts")}
        bindings = {}
        for row in connection.execute("SELECT * FROM source_discovery_tenderplan_bindings"):
            body = _tenderplan_binding_body(row)
            attempt = attempts.get(body["attempt_id"])
            items = body["item_ids"]
            if (
                attempt is None or attempt["source"] != "TENDERPLAN" or attempt["tenderplan_binding_required"] != 1
                or body["binding_required"] != 1 or body["run_id"] != _expected_tenderplan_run_id(body["attempt_id"])
                or attempt["state"] not in {"READY_FOR_REVIEW", "COMPLETE_NO_RESULTS"}
                or type(items) is not list or any(type(item) is not str or re.fullmatch(r"tpri-[0-9a-f]{64}", item) is None for item in items)
                or len(items) != len(set(items)) or type(body["card_count"]) is not int
                or not 0 <= body["card_count"] <= 5 or len(items) != body["card_count"]
                or attempt["review_count"] != body["card_count"]
                or (attempt["state"] == "COMPLETE_NO_RESULTS") != (body["card_count"] == 0)
                or any(type(body[key]) is not str or _SHA256.fullmatch(body[key]) is None for key in (
                    "native_store_identity_sha256", "native_path_sha256", "receipt_record_sha256", "event_sha256",
                    "intent_record_sha256", "request_sha256", "query_policy_sha256",
                ))
                or not _valid_recorded_at(body["recorded_at_utc"])
                or _digest(body) != row["binding_receipt_sha256"]
            ):
                raise ValueError
            bindings[body["attempt_id"]] = {**body, "binding_receipt_sha256": row["binding_receipt_sha256"]}
        for attempt in attempts.values():
            marker = attempt["tenderplan_binding_required"]
            if marker not in (0, 1) or (marker == 1 and attempt["source"] != "TENDERPLAN"):
                raise ValueError
            if marker == 1 and attempt["state"] in {"READY_FOR_REVIEW", "COMPLETE_NO_RESULTS"} and attempt["attempt_id"] not in bindings:
                raise ValueError
        return bindings
    except (ValueError, TypeError, KeyError, sqlite3.Error):
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED") from None


def _local_text(value: object, *, maximum: int, code: str) -> str:
    if type(value) is not str:
        raise SourceDiscoveryControlError(code)
    normalized = value.strip()
    try:
        encoded = normalized.encode("utf-8", "strict")
    except UnicodeError:
        raise SourceDiscoveryControlError(code) from None
    if (
        not normalized
        or len(normalized) > maximum
        or len(encoded) > maximum * 4
        or any(ord(character) < 32 for character in normalized)
    ):
        raise SourceDiscoveryControlError(code)
    return normalized


def _local_effects() -> dict[str, object]:
    effects = _effects()
    effects["external_read_enabled"] = False
    effects["provider_read_may_be_metered"] = False
    return effects


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def _open_for_write(
    path: Path, *, prepare_tenderplan: bool = False, require_tenderplan: bool = False,
    require_existing: bool = False,
) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    try:
        _assert_no_reparse_components(path)
        existed = path.exists()
        if require_existing and not existed:
            raise SourceDiscoveryControlError("CONTROL_STATE_UNAVAILABLE")
        if require_tenderplan and not existed:
            raise SourceDiscoveryControlError("CONTROL_SCHEMA_PREPARATION_REQUIRED")
        if existed and (prepare_tenderplan or require_tenderplan):
            probe = _open_read_only(path)
            try:
                version = _control_schema_version(probe)
                if require_tenderplan and version != 5:
                    raise SourceDiscoveryControlError("CONTROL_SCHEMA_PREPARATION_REQUIRED")
            finally:
                probe.close()
            _rows(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        _assert_no_reparse_components(path)
        connection = sqlite3.connect(
            path.as_uri() + "?mode=rw" if existed else str(path),
            uri=existed, isolation_level=None, timeout=5,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if prepare_tenderplan:
            # Preparation must not rewrite an unexpected concurrently created
            # database merely to discover that its schema cannot be prepared.
            if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
                raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        else:
            connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        if require_existing and connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_discovery_attempts'"
        ).fetchone() is None:
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        # Recheck what is actually open under the writer fence. A file may
        # have appeared after the initial path check; it is never assumed new.
        actual_schema_present = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone() is not None
        if (prepare_tenderplan and actual_schema_present) or require_tenderplan:
            version = _control_schema_version(connection)
            if require_tenderplan and version != 5:
                raise SourceDiscoveryControlError("CONTROL_SCHEMA_PREPARATION_REQUIRED")
            _rows(path)  # Revalidate committed history while holding the writer fence.
        native_schema_present = (
            connection.execute("PRAGMA user_version").fetchone()[0] != 0
            or connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_TP_BINDINGS,)).fetchone() is not None
            or any(row[1] == "tenderplan_binding_required" for row in connection.execute("PRAGMA table_info(source_discovery_attempts)"))
        )
        if native_schema_present:
            _validate_tenderplan_bindings(connection)
        if prepare_tenderplan and actual_schema_present and connection.execute(
            "SELECT 1 FROM source_discovery_attempts WHERE state='RUNNING'"
        ).fetchone():
            raise SourceDiscoveryControlError("CONTROL_SCHEMA_PREPARATION_IN_FLIGHT")
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
        existing_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        existing_append_only_tables = set(_APPEND_ONLY_TABLES).intersection(existing_tables)
        if existing_append_only_tables and existing_append_only_tables != set(
            _APPEND_ONLY_TABLES
        ):
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        append_only_schema_preexisting = existing_append_only_tables == set(
            _APPEND_ONLY_TABLES
        )
        if append_only_schema_preexisting:
            _validate_append_only_triggers(connection)
        connection.execute(
            """CREATE TABLE IF NOT EXISTS source_discovery_yandex_bindings(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempt_id TEXT NOT NULL UNIQUE
                       REFERENCES source_discovery_attempts(attempt_id),
                   job_id TEXT NOT NULL CHECK(length(job_id)=36),
                   job_sha256 TEXT NOT NULL CHECK(length(job_sha256)=64),
                   policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
                   connection_sha256 TEXT NOT NULL CHECK(length(connection_sha256)=64),
                   journal_path_sha256 TEXT NOT NULL CHECK(length(journal_path_sha256)=64),
                   journal_identity_sha256 TEXT NOT NULL
                       CHECK(length(journal_identity_sha256)=64),
                   binding_receipt_sha256 TEXT NOT NULL
                       CHECK(length(binding_receipt_sha256)=64),
                   recorded_at_utc TEXT NOT NULL
               )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS source_discovery_yandex_accounting(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempt_id TEXT NOT NULL UNIQUE
                       REFERENCES source_discovery_attempts(attempt_id),
                   outcome TEXT NOT NULL CHECK(outcome IN ('COMPLETED','UNCERTAIN')),
                   external_requests_this_run INTEGER NOT NULL
                       CHECK(external_requests_this_run IN (0,1)),
                   binding_receipt_sha256 TEXT NOT NULL
                       CHECK(length(binding_receipt_sha256)=64),
                   sanitized_accounting_sha256 TEXT NOT NULL
                       CHECK(length(sanitized_accounting_sha256)=64),
                   accounting_receipt_sha256 TEXT NOT NULL
                       CHECK(length(accounting_receipt_sha256)=64),
                   recorded_at_utc TEXT NOT NULL
               )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS source_discovery_batch_links(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempt_id TEXT NOT NULL UNIQUE
                       REFERENCES source_discovery_attempts(attempt_id),
                   source_lab_batch_id TEXT NOT NULL
                       CHECK(length(source_lab_batch_id) BETWEEN 1 AND 128),
                   candidate_count INTEGER NOT NULL
                       CHECK(candidate_count BETWEEN 1 AND 30),
                   source_lab_receipt_sha256 TEXT NOT NULL
                       CHECK(length(source_lab_receipt_sha256)=64),
                   source_lab_path_sha256 TEXT NOT NULL
                       CHECK(length(source_lab_path_sha256)=64),
                   review_ids_sha256 TEXT NOT NULL
                       CHECK(length(review_ids_sha256)=64),
                   link_command_sha256 TEXT NOT NULL
                       CHECK(length(link_command_sha256)=64),
                   linked_at_utc TEXT NOT NULL
               )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS source_discovery_review_closures(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempt_id TEXT NOT NULL UNIQUE
                       REFERENCES source_discovery_attempts(attempt_id),
                   source_lab_receipt_sha256 TEXT NOT NULL
                       CHECK(length(source_lab_receipt_sha256)=64),
                   source_lab_path_sha256 TEXT NOT NULL
                       CHECK(length(source_lab_path_sha256)=64),
                   decisions_sha256 TEXT NOT NULL
                       CHECK(length(decisions_sha256)=64),
                   review_count INTEGER NOT NULL
                       CHECK(review_count BETWEEN 1 AND 30),
                   closed_by TEXT NOT NULL CHECK(length(closed_by) BETWEEN 1 AND 128),
                   evidence_ref TEXT NOT NULL
                       CHECK(length(evidence_ref) BETWEEN 1 AND 2048),
                   idempotency_key TEXT NOT NULL UNIQUE
                       CHECK(length(idempotency_key) BETWEEN 1 AND 256),
                   closure_command_sha256 TEXT NOT NULL
                       CHECK(length(closure_command_sha256)=64),
                   closed_at_utc TEXT NOT NULL
               )"""
        )
        if not append_only_schema_preexisting:
            for table in _APPEND_ONLY_TABLES:
                for operation in ("UPDATE", "DELETE"):
                    connection.execute(_append_only_trigger_sql(table, operation))
        _validate_append_only_triggers(connection)
        if prepare_tenderplan:
            if _control_schema_version(connection) == 4:
                _install_tenderplan_binding_schema(connection)
            _validate_tenderplan_bindings(connection)
        elif require_tenderplan:
            _validate_tenderplan_bindings(connection)
        connection.execute("COMMIT")
        return connection
    except SourceDiscoveryControlError:
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            connection.close()
        raise
    except (OSError, sqlite3.Error):
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            connection.close()
        raise SourceDiscoveryControlError("CONTROL_STATE_UNAVAILABLE") from None


def _valid_recorded_at(value: object) -> bool:
    if type(value) is not str or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _validate_yandex_receipts(
    connection: sqlite3.Connection,
    attempt_rows: tuple[sqlite3.Row, ...] | list[sqlite3.Row],
) -> None:
    attempts = {
        str(row["attempt_id"]): (str(row["source"]), str(row["state"]))
        for row in attempt_rows
    }
    bindings = connection.execute(
        "SELECT * FROM source_discovery_yandex_bindings ORDER BY sequence"
    ).fetchall()
    accounting = connection.execute(
        "SELECT * FROM source_discovery_yandex_accounting ORDER BY sequence"
    ).fetchall()
    binding_attempts = {str(row["attempt_id"]) for row in bindings}
    binding_receipts = {
        str(row["attempt_id"]): str(row["binding_receipt_sha256"])
        for row in bindings
    }
    accounting_by_attempt = {str(row["attempt_id"]): row for row in accounting}
    if len(binding_attempts) != len(bindings) or len(accounting_by_attempt) != len(accounting):
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")

    for row in bindings:
        attempt_id = str(row["attempt_id"])
        body = {
            "attempt_id": attempt_id,
            "connection_sha256": str(row["connection_sha256"]),
            "job_id": str(row["job_id"]),
            "job_sha256": str(row["job_sha256"]),
            "journal_identity_sha256": str(row["journal_identity_sha256"]),
            "journal_path_sha256": str(row["journal_path_sha256"]),
            "policy_sha256": str(row["policy_sha256"]),
            "recorded_at_utc": str(row["recorded_at_utc"]),
        }
        if (
            attempts.get(attempt_id, (None,))[0] != SourceDiscoverySource.YANDEX.value
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                body["job_id"],
            )
            is None
            or any(
                _SHA256.fullmatch(body[key]) is None
                for key in (
                    "connection_sha256",
                    "job_sha256",
                    "journal_identity_sha256",
                    "journal_path_sha256",
                    "policy_sha256",
                )
            )
            or not _valid_recorded_at(body["recorded_at_utc"])
            or _digest(body) != str(row["binding_receipt_sha256"])
        ):
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")

    for row in accounting:
        attempt_id = str(row["attempt_id"])
        external_requests = row["external_requests_this_run"]
        if type(external_requests) is not int:
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        body = {
            "attempt_id": attempt_id,
            "binding_receipt_sha256": str(row["binding_receipt_sha256"]),
            "external_requests_this_run": external_requests,
            "outcome": str(row["outcome"]),
            "recorded_at_utc": str(row["recorded_at_utc"]),
            "sanitized_accounting_sha256": str(row["sanitized_accounting_sha256"]),
        }
        if (
            attempt_id not in binding_attempts
            or attempts.get(attempt_id, (None,))[0] != SourceDiscoverySource.YANDEX.value
            or body["binding_receipt_sha256"] != binding_receipts.get(attempt_id)
            or _SHA256.fullmatch(body["binding_receipt_sha256"]) is None
            or body["outcome"] not in {"COMPLETED", "UNCERTAIN"}
            or body["external_requests_this_run"] not in {0, 1}
            or _SHA256.fullmatch(body["sanitized_accounting_sha256"]) is None
            or not _valid_recorded_at(body["recorded_at_utc"])
            or _digest(body) != str(row["accounting_receipt_sha256"])
        ):
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")

    for attempt_id, (source, state) in attempts.items():
        receipt = accounting_by_attempt.get(attempt_id)
        if source != SourceDiscoverySource.YANDEX.value and (
            attempt_id in binding_attempts or receipt is not None
        ):
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        if source == SourceDiscoverySource.YANDEX.value and state in {
            "READY_FOR_REVIEW",
            "COMPLETE_NO_RESULTS",
        } and (
            attempt_id not in binding_attempts
            or receipt is None
            or str(receipt["outcome"]) != "COMPLETED"
        ):
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


def _rows(path: Path) -> tuple[dict[str, object], ...]:
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
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                has_native_schema = (
                    _TP_BINDINGS in tables
                    or connection.execute("PRAGMA user_version").fetchone()[0] != 0
                    or any(row[1] == "tenderplan_binding_required" for row in connection.execute("PRAGMA table_info(source_discovery_attempts)"))
                )
                native_bindings = _validate_tenderplan_bindings(connection) if has_native_schema else {}
                append_only_tables = set(_APPEND_ONLY_TABLES).intersection(tables)
                if append_only_tables and append_only_tables != set(_APPEND_ONLY_TABLES):
                    raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
                if append_only_tables == set(_APPEND_ONLY_TABLES):
                    _validate_append_only_triggers(connection)
                    rows = connection.execute(
                        """SELECT a.attempt_id,a.source,a.state,a.review_count,
                                  b.job_id AS yandex_job_id,
                                  b.policy_sha256 AS yandex_policy_sha256,
                                  b.journal_path_sha256 AS yandex_journal_path_sha256,
                                  b.binding_receipt_sha256 AS yandex_binding_receipt_sha256,
                                  ya.outcome AS yandex_accounting_outcome,
                                  ya.external_requests_this_run
                                    AS yandex_external_requests_this_run,
                                  ya.accounting_receipt_sha256
                                    AS yandex_accounting_receipt_sha256,
                                  l.source_lab_batch_id,l.candidate_count,
                                  l.source_lab_receipt_sha256,
                                  l.source_lab_path_sha256,l.review_ids_sha256,
                                  l.link_command_sha256,l.linked_at_utc,
                                  c.source_lab_receipt_sha256
                                    AS closed_source_lab_receipt_sha256,
                                  c.source_lab_path_sha256
                                    AS closed_source_lab_path_sha256,
                                  c.decisions_sha256,c.review_count AS closed_review_count,
                                  c.closed_by,c.evidence_ref,c.idempotency_key,
                                  c.closure_command_sha256,c.closed_at_utc
                           FROM source_discovery_attempts a
                           LEFT JOIN source_discovery_yandex_bindings b
                             ON b.attempt_id=a.attempt_id
                           LEFT JOIN source_discovery_yandex_accounting ya
                             ON ya.attempt_id=a.attempt_id
                           LEFT JOIN source_discovery_batch_links l
                             ON l.attempt_id=a.attempt_id
                           LEFT JOIN source_discovery_review_closures c
                             ON c.attempt_id=a.attempt_id
                           ORDER BY a.sequence"""
                    ).fetchall()
                else:
                    rows = connection.execute(
                        """SELECT attempt_id,source,state,review_count,
                                  NULL AS yandex_job_id,
                                  NULL AS yandex_policy_sha256,
                                  NULL AS yandex_journal_path_sha256,
                                  NULL AS yandex_binding_receipt_sha256,
                                  NULL AS yandex_accounting_outcome,
                                  NULL AS yandex_external_requests_this_run,
                                  NULL AS yandex_accounting_receipt_sha256,
                                  NULL AS source_lab_batch_id,
                                  NULL AS candidate_count,
                                  NULL AS source_lab_receipt_sha256,
                                  NULL AS source_lab_path_sha256,
                                  NULL AS review_ids_sha256,
                                  NULL AS link_command_sha256,
                                  NULL AS linked_at_utc,
                                  NULL AS decisions_sha256,
                                  NULL AS closed_source_lab_receipt_sha256,
                                  NULL AS closed_source_lab_path_sha256,
                                  NULL AS closed_review_count,
                                  NULL AS closed_by,NULL AS evidence_ref,
                                  NULL AS idempotency_key,
                                  NULL AS closure_command_sha256,
                                  NULL AS closed_at_utc
                           FROM source_discovery_attempts ORDER BY sequence"""
                    ).fetchall()
                if any(
                    not re.fullmatch(r"sd_[0-9a-f]{32}", str(row["attempt_id"]))
                    or str(row["source"]) not in {source.value for source in _RUNNABLE_SOURCES}
                    or str(row["state"]) not in _ATTEMPT_STATES
                    or type(row["review_count"]) is not int
                    or not 0 <= int(row["review_count"]) <= 1000
                    for row in rows
                ):
                    raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
                for row in rows:
                    linked = row["source_lab_batch_id"] is not None
                    closed = row["closed_at_utc"] is not None
                    if linked:
                        link_body = {
                            "attempt_id": str(row["attempt_id"]),
                            "candidate_count": int(row["candidate_count"]),
                            "review_ids_sha256": str(row["review_ids_sha256"]),
                            "source_lab_batch_id": str(row["source_lab_batch_id"]),
                            "source_lab_path_sha256": str(row["source_lab_path_sha256"]),
                            "source_lab_receipt_sha256": str(row["source_lab_receipt_sha256"]),
                            "linked_at_utc": str(row["linked_at_utc"]),
                        }
                        if (
                            str(row["source"]) != SourceDiscoverySource.YANDEX.value
                            or (
                                str(row["state"]) in {"RUNNING", "UNCERTAIN"}
                                and (int(row["review_count"]) != 0 or closed)
                            )
                            or (
                                str(row["state"]) == "READY_FOR_REVIEW"
                                and int(row["review_count"]) != int(row["candidate_count"])
                            )
                            or str(row["state"]) not in {"RUNNING", "READY_FOR_REVIEW", "UNCERTAIN"}
                            or not 1 <= int(row["candidate_count"]) <= 30
                            or any(
                                not _SHA256.fullmatch(str(row[key] or ""))
                                for key in (
                                    "source_lab_receipt_sha256",
                                    "source_lab_path_sha256",
                                    "review_ids_sha256",
                                    "link_command_sha256",
                                )
                            )
                            or not re.fullmatch(
                                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                                r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                                str(row["linked_at_utc"] or ""),
                            )
                            or _digest(link_body) != str(row["link_command_sha256"])
                        ):
                            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
                    if closed:
                        closure_body = {
                            "attempt_id": str(row["attempt_id"]),
                            "closed_by": str(row["closed_by"]),
                            "decisions_sha256": str(row["decisions_sha256"]),
                            "evidence_ref": str(row["evidence_ref"]),
                            "idempotency_key": str(row["idempotency_key"]),
                            "review_count": int(row["closed_review_count"]),
                            "source_lab_path_sha256": str(row["closed_source_lab_path_sha256"]),
                            "source_lab_receipt_sha256": str(
                                row["closed_source_lab_receipt_sha256"]
                            ),
                            "closed_at_utc": str(row["closed_at_utc"]),
                        }
                        if (
                            not linked
                            or str(row["state"]) != "READY_FOR_REVIEW"
                            or str(row["closed_source_lab_receipt_sha256"])
                            != str(row["source_lab_receipt_sha256"])
                            or str(row["closed_source_lab_path_sha256"])
                            != str(row["source_lab_path_sha256"])
                            or int(row["closed_review_count"]) != int(row["review_count"])
                            or any(
                                not _SHA256.fullmatch(str(row[key] or ""))
                                for key in (
                                    "decisions_sha256",
                                    "closed_source_lab_path_sha256",
                                    "closure_command_sha256",
                                )
                            )
                            or not re.fullmatch(
                                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                                r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                                str(row["closed_at_utc"] or ""),
                            )
                            or _digest(closure_body) != str(row["closure_command_sha256"])
                        ):
                            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
                if append_only_tables == set(_APPEND_ONLY_TABLES):
                    _validate_yandex_receipts(connection, rows)
                return tuple({**dict(row), "tenderplan_binding": native_bindings.get(row["attempt_id"])} for row in rows)
        except SourceDiscoveryControlError:
            raise
        except sqlite3.Error:
            raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED") from None
        finally:
            connection.close()
        if attempt + 1 < _SCHEMA_VISIBILITY_RETRIES:
            time.sleep(_SCHEMA_VISIBILITY_RETRY_SECONDS)
    raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


def _validate_closed_yandex_batches(
    path: Path,
    rows: tuple[sqlite3.Row, ...],
) -> None:
    linked_rows = tuple(row for row in rows if row["source_lab_batch_id"] is not None)
    closed_rows = tuple(row for row in rows if row["closed_at_utc"] is not None)
    lab_path = _source_lab_path(control_path=path)
    if not lab_path.exists():
        if linked_rows:
            raise SourceDiscoveryControlError("CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED")
        return
    lab_path_sha256 = _source_lab_path_sha256(lab_path)
    try:
        if not lab_path.is_file() or lab_path.stat().st_size <= 0:
            raise OSError
        connection = _open_read_only(lab_path)
        try:
            if int(connection.execute("PRAGMA user_version").fetchone()[0]) != 17:
                raise sqlite3.DatabaseError
        finally:
            connection.close()
        receipts = list_yandex_review_batch_receipts(lab_path)
    except (
        OSError,
        TypeError,
        sqlite3.Error,
        SourceDiscoveryControlError,
        YandexSourceLabBridgeError,
    ):
        if not linked_rows:
            raise YandexSourceLabBridgeError("YANDEX_SOURCE_LAB_PREFLIGHT_FAILED") from None
        raise SourceDiscoveryControlError("CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED") from None

    try:
        receipts_by_attempt = {receipt.attempt_id: receipt for receipt in receipts}
        links_by_attempt = {str(row["attempt_id"]): row for row in linked_rows}
        if (
            len(receipts_by_attempt) != len(receipts)
            or len(links_by_attempt) != len(linked_rows)
            or set(receipts_by_attempt) != set(links_by_attempt)
        ):
            raise ValueError
        for attempt_id, row in links_by_attempt.items():
            receipt = receipts_by_attempt[attempt_id]
            if (
                str(row["source"]) != SourceDiscoverySource.YANDEX.value
                or str(row["source_lab_path_sha256"]) != lab_path_sha256
                or receipt.source_lab_batch_id != str(row["source_lab_batch_id"])
                or receipt.candidate_count != int(row["candidate_count"])
                or receipt.receipt_sha256 != str(row["source_lab_receipt_sha256"])
                or _digest(list(receipt.review_ids)) != str(row["review_ids_sha256"])
            ):
                raise ValueError
        for row in closed_rows:
            if (
                str(row["source"]) != SourceDiscoverySource.YANDEX.value
                or str(row["source_lab_path_sha256"]) != lab_path_sha256
                or str(row["closed_source_lab_path_sha256"]) != lab_path_sha256
            ):
                raise ValueError
            closure = inspect_yandex_batch_closure(
                attempt_id=str(row["attempt_id"]),
                source_lab_path=lab_path,
                expected_receipt_sha256=str(row["source_lab_receipt_sha256"]),
            )
            if (
                closure.attempt_id != str(row["attempt_id"])
                or closure.review_count != int(row["closed_review_count"])
                or closure.terminal_count != closure.review_count
                or closure.decisions_sha256 != str(row["decisions_sha256"])
            ):
                raise ValueError
    except (
        TypeError,
        ValueError,
        SourceDiscoveryControlError,
        YandexSourceLabBridgeError,
    ):
        raise SourceDiscoveryControlError("CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED") from None


def _snapshot(path: Path, wip_limit: int) -> dict[str, object]:
    rows = _rows(path)
    _validate_closed_yandex_batches(path, rows)
    state_counts = {
        state: sum(str(row["state"]) == state for row in rows) for state in sorted(_ATTEMPT_STATES)
    }
    open_review_batches = sum(
        str(row["state"]) == "READY_FOR_REVIEW" and row["closed_at_utc"] is None for row in rows
    )
    closed_review_batches = sum(row["closed_at_utc"] is not None for row in rows)
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
            "state": ("CLOSED_LOCAL" if row["closed_at_utc"] is not None else str(row["state"])),
        }
        if str(row["source"]) == SourceDiscoverySource.YANDEX.value:
            latest["yandex_reconciliation"] = {
                "accounting_outcome": str(row["yandex_accounting_outcome"] or ""),
                "accounting_receipt_sha256": str(
                    row["yandex_accounting_receipt_sha256"] or ""
                ),
                "binding_receipt_sha256": str(
                    row["yandex_binding_receipt_sha256"] or ""
                ),
                "external_requests_this_run": (
                    int(row["yandex_external_requests_this_run"])
                    if row["yandex_external_requests_this_run"] is not None
                    else None
                ),
                "job_id": str(row["yandex_job_id"] or ""),
                "journal_path_sha256": str(row["yandex_journal_path_sha256"] or ""),
                "policy_sha256": str(row["yandex_policy_sha256"] or ""),
            }
        elif row.get("tenderplan_binding") is not None:
            latest["tenderplan_binding"] = {
                "verification": "NATIVE_RECEIPT_VERIFIED_AT_FINALIZATION",
                **row["tenderplan_binding"],
            }
    return {
        "attempt_count": len(rows),
        "gate": gate,
        "in_flight_count": state_counts["RUNNING"],
        "closed_review_batches": closed_review_batches,
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
    tenderplan_registration_path: str | Path | None = None,
    tenderplan_store_path: str | Path | None = None,
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
    elif selected is SourceDiscoverySource.TENDERPLAN and not _tenderplan_schema_ready(path):
        state = "BLOCKED_SCHEMA_PREPARATION_REQUIRED"
    elif selected is SourceDiscoverySource.TENDERPLAN:
        native = check_tenderplan_read_only_intake(
            registration_path=tenderplan_registration_path,
            store_path=tenderplan_store_path,
        )
        state = str(native["state"])
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


def _sanitized_yandex_preflight_accounting(journal: object) -> dict[str, object]:
    """Validate local native status without returning job, request, or path data."""

    if not isinstance(journal, Mapping) or set(journal) != _YANDEX_ACCOUNTING_KEYS:
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    states = journal.get("states")
    if (
        not isinstance(states, Mapping)
        or set(states) != set(_YANDEX_ACCOUNTING_STATES)
        or any(type(states[state]) is not int for state in _YANDEX_ACCOUNTING_STATES)
        or any(not 0 <= states[state] <= 1 for state in _YANDEX_ACCOUNTING_STATES)
    ):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    state_counts = {state: int(states[state]) for state in _YANDEX_ACCOUNTING_STATES}
    attempts = journal.get("attempts_reserved")
    reserved_cost = journal.get("reserved_cost_minor")
    remaining_cost = journal.get("remaining_cost_minor")
    retained = journal.get("retained_responses")
    empty = attempts == 0 and all(value == 0 for value in state_counts.values())
    cached = attempts == 1 and state_counts == {
        "RESERVED": 0,
        "DISPATCH_INTENT": 0,
        "UNCERTAIN": 0,
        "COMPLETED": 1,
    }
    if (
        type(attempts) is not int
        or type(reserved_cost) is not int
        or reserved_cost != attempts * 49
        or type(remaining_cost) is not int
        or remaining_cost != 49 - reserved_cost
        or type(retained) is not int
        or retained != (1 if cached else 0)
        or not (empty or cached)
        or type(journal.get("max_requests")) is not int
        or journal.get("max_requests") != 1
        or journal.get("currency") != "RUB"
        or journal.get("cost_semantics") != "UPPER_ESTIMATE_NOT_INVOICE"
        or type(journal.get("stopped")) is not bool
        or journal.get("live_authority_granted") is not False
        or type(journal.get("policy_sha256")) is not str
        or _SHA256.fullmatch(str(journal["policy_sha256"])) is None
        or type(journal.get("expires_at_utc")) is not str
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            str(journal["expires_at_utc"]),
        )
        is None
    ):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    try:
        datetime.strptime(str(journal["expires_at_utc"]), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT") from None
    return {
        "accounting_status": "VERIFIED",
        "attempts_reserved": attempts,
        "cost_semantics": "UPPER_ESTIMATE_NOT_INVOICE",
        "currency": "RUB",
        "max_requests": 1,
        "remaining_cost_minor": remaining_cost,
        "reserved_cost_minor": reserved_cost,
        "retained_responses": retained,
        "states": state_counts,
        "stopped": journal["stopped"],
    }


def _verify_source_discovery_authority_core(
    source: str | SourceDiscoverySource,
    *,
    state_path: str | Path,
    wip_limit: int,
    yandex_job_path: str | Path | None,
    folder_id: str | None,
    tenderplan_query: str,
    tenderplan_registration_path: str | Path | None,
    tenderplan_store_path: str | Path | None,
) -> dict[str, object]:
    report = check_source_discovery(
        source,
        state_path=state_path,
        wip_limit=wip_limit,
        yandex_job_path=yandex_job_path,
        folder_id=folder_id,
        tenderplan_query=tenderplan_query,
        tenderplan_registration_path=tenderplan_registration_path,
        tenderplan_store_path=tenderplan_store_path,
    )
    selected = _source(source)
    if (
        selected is not SourceDiscoverySource.YANDEX
        or report["state"] != "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    ):
        return report
    native = check_manual_yandex_search(
        yandex_job_path,  # type: ignore[arg-type]
        folder_id=folder_id,  # type: ignore[arg-type]
    )
    if (
        type(native) is not dict
        or set(native) != {"ok", "connection", "request", "cached", "accounting"}
        or native["ok"] is not True
        or native["connection"] != "PERMANENT"
        or type(native["cached"]) is not bool
        or type(native["request"]) is not dict
        or set(native["request"]) != {"query_text", "region_label", "page"}
    ):
        raise SourceDiscoveryControlError("YANDEX_AUTHORITY_CHECK_REJECTED")
    accounting = _sanitized_yandex_preflight_accounting(native["accounting"])
    if native["cached"] != (accounting["attempts_reserved"] == 1):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    return {
        "authority_verified": True,
        "cached": native["cached"],
        "control": report["control"],
        "effects": {**_effects(), "provider_read_may_be_metered": False},
        "journal": accounting,
        "operation": "CHECK_NATIVE_AUTHORITY_LOCAL_ONLY",
        "source": selected.value,
        "state": "READY_FOR_EXPLICIT_CONFIRMATION",
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


def verify_source_discovery_authority(
    source: str | SourceDiscoverySource,
    *,
    state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH,
    wip_limit: int = SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
    yandex_job_path: str | Path | None = None,
    folder_id: str | None = None,
    tenderplan_query: str = TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
    tenderplan_registration_path: str | Path | None = None,
    tenderplan_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Run the supported local authority check without credentials or provider I/O."""

    try:
        return _verify_source_discovery_authority_core(
            source,
            state_path=state_path,
            wip_limit=wip_limit,
            yandex_job_path=yandex_job_path,
            folder_id=folder_id,
            tenderplan_query=tenderplan_query,
            tenderplan_registration_path=tenderplan_registration_path,
            tenderplan_store_path=tenderplan_store_path,
        )
    except SourceDiscoveryControlError as error:
        failure_code = _known_control_failure_code(
            error,
            "YANDEX_AUTHORITY_CHECK_REJECTED",
        )
    except BaseException:
        failure_code = "YANDEX_AUTHORITY_CHECK_REJECTED"
    del source, state_path, wip_limit, yandex_job_path, folder_id, tenderplan_query
    del tenderplan_registration_path, tenderplan_store_path
    _raise_detached_control_failure(failure_code)


def _blocked_run_report(
    selected: SourceDiscoverySource,
    state: str,
    *,
    path: Path,
    wip_limit: int,
) -> dict[str, object]:
    return {
        "control": _snapshot(path, wip_limit),
        "effects": _effects(),
        "external_requests_this_run": 0,
        "journal": _accounting_marker("NOT_INVOKED"),
        "native_runner_call_count": 0,
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
    connection = _open_for_write(path, require_tenderplan=source is SourceDiscoverySource.TENDERPLAN)
    try:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            """SELECT a.state,c.attempt_id AS closed_attempt_id
               FROM source_discovery_attempts a
               LEFT JOIN source_discovery_review_closures c
                 ON c.attempt_id=a.attempt_id"""
        ).fetchall()
        states = tuple(str(row["state"]) for row in rows)
        if "UNCERTAIN" in states:
            connection.execute("ROLLBACK")
            return None, "BLOCKED_UNCERTAIN"
        if "RUNNING" in states:
            connection.execute("ROLLBACK")
            return None, "BLOCKED_IN_FLIGHT"
        if (
            sum(
                str(row["state"]) == "READY_FOR_REVIEW" and row["closed_attempt_id"] is None
                for row in rows
            )
            >= wip_limit
        ):
            connection.execute("ROLLBACK")
            return None, "BLOCKED_BACKPRESSURE"
        attempt_id = f"sd_{secrets.token_hex(16)}"
        if source is SourceDiscoverySource.TENDERPLAN:
            connection.execute(
                """INSERT INTO source_discovery_attempts(
                    attempt_id,source,state,started_at_utc,review_count,tenderplan_binding_required
                ) VALUES(?,?,?, ?,0,1)""", (attempt_id, source.value, "RUNNING", _now_utc()),
            )
        else:
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


def _record_yandex_binding(
    path: Path,
    attempt_id: str,
    binding: ManualYandexSearchBinding,
) -> None:
    if type(binding) is not ManualYandexSearchBinding:
        raise SourceDiscoveryControlError("YANDEX_BINDING_INVALID")
    recorded_at_utc = _now_utc()
    body = {
        "attempt_id": attempt_id,
        "connection_sha256": binding.connection_sha256,
        "job_id": binding.job_id,
        "job_sha256": binding.job_sha256,
        "journal_identity_sha256": binding.journal_identity_sha256,
        "journal_path_sha256": binding.journal_path_sha256,
        "policy_sha256": binding.policy_sha256,
        "recorded_at_utc": recorded_at_utc,
    }
    receipt_sha256 = _digest(body)
    connection = _open_for_write(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        attempt = connection.execute(
            "SELECT source,state FROM source_discovery_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if (
            not attempt
            or str(attempt["source"]) != SourceDiscoverySource.YANDEX.value
            or str(attempt["state"]) != "RUNNING"
        ):
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        existing = connection.execute(
            "SELECT * FROM source_discovery_yandex_bindings WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if existing:
            existing_body = {
                **{key: value for key, value in body.items() if key != "recorded_at_utc"},
                "recorded_at_utc": str(existing["recorded_at_utc"]),
            }
            if (
                any(str(existing[key]) != str(value) for key, value in existing_body.items())
                or str(existing["binding_receipt_sha256"]) != _digest(existing_body)
            ):
                raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
            connection.execute("COMMIT")
            return
        if connection.execute(
            "SELECT 1 FROM source_discovery_yandex_accounting WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone():
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        connection.execute(
            """INSERT INTO source_discovery_yandex_bindings(
                   attempt_id,job_id,job_sha256,policy_sha256,connection_sha256,
                   journal_path_sha256,journal_identity_sha256,
                   binding_receipt_sha256,recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                attempt_id,
                binding.job_id,
                binding.job_sha256,
                binding.policy_sha256,
                binding.connection_sha256,
                binding.journal_path_sha256,
                binding.journal_identity_sha256,
                receipt_sha256,
                recorded_at_utc,
            ),
        )
        attempts = connection.execute(
            "SELECT attempt_id,source,state FROM source_discovery_attempts ORDER BY sequence"
        ).fetchall()
        _validate_yandex_receipts(connection, attempts)
        connection.execute("COMMIT")
    except SourceDiscoveryControlError:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        connection.close()


def _record_yandex_accounting(
    path: Path,
    attempt_id: str,
    external_requests_this_run: int,
    journal: Mapping[str, object],
    *,
    outcome: str,
) -> None:
    if (
        type(external_requests_this_run) is not int
        or external_requests_this_run not in {0, 1}
        or outcome not in {"COMPLETED", "UNCERTAIN"}
        or not isinstance(journal, Mapping)
        or set(journal) != _SANITIZED_ACCOUNTING_KEYS
        or journal.get("accounting_status") != "VERIFIED"
    ):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT")
    try:
        accounting_sha256 = _digest(journal)
    except (TypeError, UnicodeError, ValueError):
        raise SourceDiscoveryControlError("YANDEX_ACCOUNTING_INCONSISTENT") from None
    connection = _open_for_write(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        attempt = connection.execute(
            "SELECT source,state FROM source_discovery_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        binding = connection.execute(
            """SELECT binding_receipt_sha256
               FROM source_discovery_yandex_bindings WHERE attempt_id=?""",
            (attempt_id,),
        ).fetchone()
        if (
            not attempt
            or str(attempt["source"]) != SourceDiscoverySource.YANDEX.value
            or str(attempt["state"]) != "RUNNING"
            or not binding
        ):
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        recorded_at_utc = _now_utc()
        body = {
            "attempt_id": attempt_id,
            "binding_receipt_sha256": str(binding["binding_receipt_sha256"]),
            "external_requests_this_run": external_requests_this_run,
            "outcome": outcome,
            "recorded_at_utc": recorded_at_utc,
            "sanitized_accounting_sha256": accounting_sha256,
        }
        receipt_sha256 = _digest(body)
        existing = connection.execute(
            "SELECT * FROM source_discovery_yandex_accounting WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if existing:
            existing_body = {
                **{key: value for key, value in body.items() if key != "recorded_at_utc"},
                "recorded_at_utc": str(existing["recorded_at_utc"]),
            }
            if (
                any(str(existing[key]) != str(value) for key, value in existing_body.items())
                or str(existing["accounting_receipt_sha256"]) != _digest(existing_body)
            ):
                raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
            connection.execute("COMMIT")
            return
        connection.execute(
            """INSERT INTO source_discovery_yandex_accounting(
                   attempt_id,outcome,external_requests_this_run,binding_receipt_sha256,
                   sanitized_accounting_sha256,accounting_receipt_sha256,
                   recorded_at_utc
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                attempt_id,
                outcome,
                external_requests_this_run,
                binding["binding_receipt_sha256"],
                accounting_sha256,
                receipt_sha256,
                recorded_at_utc,
            ),
        )
        attempts = connection.execute(
            "SELECT attempt_id,source,state FROM source_discovery_attempts ORDER BY sequence"
        ).fetchall()
        _validate_yandex_receipts(connection, attempts)
        connection.execute("COMMIT")
    except SourceDiscoveryControlError:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        connection.close()


def _record_yandex_batch_link(
    path: Path,
    attempt_id: str,
    receipt: YandexSourceLabBatchReceipt,
    source_lab_path: Path,
) -> None:
    if (
        type(receipt) is not YandexSourceLabBatchReceipt
        or receipt.attempt_id != attempt_id
        or type(receipt.candidate_count) is not int
        or not 1 <= receipt.candidate_count <= 30
        or not _SHA256.fullmatch(receipt.receipt_sha256)
        or not receipt.review_ids
        or len(receipt.review_ids) != receipt.candidate_count
    ):
        raise SourceDiscoveryControlError("SOURCE_LAB_BATCH_RECEIPT_INVALID")
    link_base = {
        "attempt_id": attempt_id,
        "candidate_count": receipt.candidate_count,
        "review_ids_sha256": _digest(list(receipt.review_ids)),
        "source_lab_batch_id": receipt.source_lab_batch_id,
        "source_lab_path_sha256": _source_lab_path_sha256(source_lab_path),
        "source_lab_receipt_sha256": receipt.receipt_sha256,
    }
    connection = _open_for_write(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        attempt = connection.execute(
            "SELECT source,state FROM source_discovery_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if (
            not attempt
            or str(attempt["source"]) != SourceDiscoverySource.YANDEX.value
            or str(attempt["state"]) != "RUNNING"
        ):
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        existing = connection.execute(
            "SELECT * FROM source_discovery_batch_links WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if existing:
            link_body = {
                **link_base,
                "linked_at_utc": str(existing["linked_at_utc"]),
            }
            if any(str(existing[key]) != str(value) for key, value in link_base.items()) or str(
                existing["link_command_sha256"]
            ) != _digest(link_body):
                raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
            connection.execute("COMMIT")
            return
        linked_at_utc = _now_utc()
        link_body = {**link_base, "linked_at_utc": linked_at_utc}
        command_sha256 = _digest(link_body)
        connection.execute(
            """INSERT INTO source_discovery_batch_links(
                   attempt_id,source_lab_batch_id,candidate_count,
                   source_lab_receipt_sha256,source_lab_path_sha256,
                   review_ids_sha256,link_command_sha256,linked_at_utc
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                attempt_id,
                receipt.source_lab_batch_id,
                receipt.candidate_count,
                receipt.receipt_sha256,
                link_base["source_lab_path_sha256"],
                link_body["review_ids_sha256"],
                command_sha256,
                linked_at_utc,
            ),
        )
        connection.execute("COMMIT")
    except SourceDiscoveryControlError:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        connection.close()


def _finish(
    path: Path, attempt_id: str, state: str, review_count: int,
    *, tenderplan_binding: dict[str, object] | None = None,
) -> None:
    if state not in {"READY_FOR_REVIEW", "COMPLETE_NO_RESULTS", "UNCERTAIN"}:
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
    connection = _open_for_write(path, require_existing=True, require_tenderplan=tenderplan_binding is not None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        attempt = connection.execute(
            "SELECT source,state FROM source_discovery_attempts WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        if not attempt or str(attempt["state"]) != "RUNNING":
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        if (
            str(attempt["source"]) == SourceDiscoverySource.YANDEX.value
            and state in {"READY_FOR_REVIEW", "COMPLETE_NO_RESULTS"}
        ):
            durable_accounting = connection.execute(
                """SELECT a.outcome
                   FROM source_discovery_yandex_accounting a
                   INNER JOIN source_discovery_yandex_bindings b
                     ON b.attempt_id=a.attempt_id
                   WHERE a.attempt_id=?""",
                (attempt_id,),
            ).fetchone()
            if not durable_accounting or str(durable_accounting["outcome"]) != "COMPLETED":
                raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        cursor = connection.execute(
            """UPDATE source_discovery_attempts
               SET state=?,finished_at_utc=?,review_count=?
               WHERE attempt_id=? AND state='RUNNING'""",
            (state, _now_utc(), review_count, attempt_id),
        )
        if cursor.rowcount != 1:
            connection.execute("ROLLBACK")
            raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        if tenderplan_binding is not None:
            if attempt["source"] != "TENDERPLAN" or tenderplan_binding.get("attempt_id") != attempt_id:
                raise SourceDiscoveryControlError("TENDERPLAN_RECEIPT_INVALID")
            persisted = {**tenderplan_binding}
            persisted["item_ids_json"] = json.dumps(persisted.pop("item_ids"), separators=(",", ":"))
            columns = tuple(persisted)
            connection.execute(
                f"INSERT INTO source_discovery_tenderplan_bindings({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                tuple(persisted[key] for key in columns),
            )
        if connection.execute("PRAGMA user_version").fetchone()[0] == 5:
            _validate_tenderplan_bindings(connection)
        connection.execute("COMMIT")
    except SourceDiscoveryControlError:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        connection.close()


def close_source_discovery_review(
    *,
    attempt_id: str,
    confirmation: str | None,
    state_path: str | Path = SOURCE_DISCOVERY_STATE_PATH,
    actor: str,
    evidence_ref: str,
    idempotency_key: str,
) -> dict[str, object]:
    """Close one fully decided Yandex link batch; performs local I/O only."""

    if confirmation != SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION:
        raise SourceDiscoveryControlError("LOCAL_CLOSE_CONFIRMATION_REQUIRED")
    attempt = _local_text(attempt_id, maximum=35, code="SOURCE_DISCOVERY_ATTEMPT_INVALID")
    if not re.fullmatch(r"sd_[0-9a-f]{32}", attempt):
        raise SourceDiscoveryControlError("SOURCE_DISCOVERY_ATTEMPT_INVALID")
    operator = _local_text(actor, maximum=128, code="LOCAL_REVIEW_ACTOR_INVALID")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", operator):
        raise SourceDiscoveryControlError("LOCAL_REVIEW_ACTOR_INVALID")
    evidence = _local_text(evidence_ref, maximum=2048, code="LOCAL_REVIEW_EVIDENCE_INVALID")
    idem = _local_text(idempotency_key, maximum=256, code="LOCAL_REVIEW_IDEMPOTENCY_INVALID")
    path = _state_path(state_path)
    lab_path = _source_lab_path(control_path=path)
    lab_path_sha256 = _source_lab_path_sha256(lab_path)
    rows = _rows(path)
    selected = next((row for row in rows if str(row["attempt_id"]) == attempt), None)
    if (
        selected is None
        or str(selected["source"]) != SourceDiscoverySource.YANDEX.value
        or str(selected["state"]) != "READY_FOR_REVIEW"
        or selected["source_lab_batch_id"] is None
    ):
        raise SourceDiscoveryControlError("LOCAL_REVIEW_BATCH_NOT_CLOSABLE")
    if str(selected["source_lab_path_sha256"]) != lab_path_sha256:
        raise SourceDiscoveryControlError("LOCAL_REVIEW_STORE_MISMATCH")
    _validate_closed_yandex_batches(path, rows)
    expected_receipt = str(selected["source_lab_receipt_sha256"])
    closure = inspect_yandex_batch_closure(
        attempt_id=attempt,
        source_lab_path=lab_path,
        expected_receipt_sha256=expected_receipt,
    )
    if (
        closure.attempt_id != attempt
        or closure.review_count != int(selected["review_count"])
        or closure.terminal_count != closure.review_count
        or not _SHA256.fullmatch(closure.decisions_sha256)
    ):
        raise SourceDiscoveryControlError("LOCAL_REVIEW_BATCH_NOT_CLOSABLE")
    closure_base = {
        "attempt_id": attempt,
        "closed_by": operator,
        "decisions_sha256": closure.decisions_sha256,
        "evidence_ref": evidence,
        "idempotency_key": idem,
        "review_count": closure.review_count,
        "source_lab_path_sha256": lab_path_sha256,
        "source_lab_receipt_sha256": expected_receipt,
    }
    connection = _open_for_write(path)
    created = False
    command_sha256 = ""
    try:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute(
            """SELECT a.source,a.state,a.review_count,
                      l.source_lab_receipt_sha256,l.source_lab_path_sha256
               FROM source_discovery_attempts a
               LEFT JOIN source_discovery_batch_links l
                 ON l.attempt_id=a.attempt_id
               WHERE a.attempt_id=?""",
            (attempt,),
        ).fetchone()
        if (
            not current
            or str(current["source"]) != SourceDiscoverySource.YANDEX.value
            or str(current["state"]) != "READY_FOR_REVIEW"
            or int(current["review_count"]) != closure.review_count
            or str(current["source_lab_receipt_sha256"]) != expected_receipt
            or str(current["source_lab_path_sha256"]) != lab_path_sha256
        ):
            raise SourceDiscoveryControlError("LOCAL_REVIEW_BATCH_NOT_CLOSABLE")
        existing_attempt = connection.execute(
            "SELECT * FROM source_discovery_review_closures WHERE attempt_id=?",
            (attempt,),
        ).fetchone()
        existing_idem = connection.execute(
            "SELECT * FROM source_discovery_review_closures WHERE idempotency_key=?",
            (idem,),
        ).fetchone()
        existing = existing_attempt or existing_idem
        if existing:
            closure_body = {
                **closure_base,
                "closed_at_utc": str(existing["closed_at_utc"]),
            }
            command_sha256 = _digest(closure_body)
            if (
                existing_attempt is None
                or existing_idem is None
                or str(existing["attempt_id"]) != attempt
                or str(existing["closure_command_sha256"]) != command_sha256
            ):
                raise SourceDiscoveryControlError("LOCAL_REVIEW_CLOSE_CONFLICT")
        else:
            closed_at_utc = _now_utc()
            closure_body = {
                **closure_base,
                "closed_at_utc": closed_at_utc,
            }
            command_sha256 = _digest(closure_body)
            connection.execute(
                """INSERT INTO source_discovery_review_closures(
                       attempt_id,source_lab_receipt_sha256,
                       source_lab_path_sha256,decisions_sha256,review_count,
                       closed_by,evidence_ref,idempotency_key,
                       closure_command_sha256,closed_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    attempt,
                    expected_receipt,
                    lab_path_sha256,
                    closure.decisions_sha256,
                    closure.review_count,
                    operator,
                    evidence,
                    idem,
                    command_sha256,
                    closed_at_utc,
                ),
            )
            created = True
        connection.execute("COMMIT")
    except SourceDiscoveryControlError:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        connection.close()
    return {
        "attempt_id": attempt,
        "closure_receipt_sha256": command_sha256,
        "control": _snapshot(path, SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT),
        "created": created,
        "decision_counts": dict(closure.decision_counts),
        "effects": _local_effects(),
        "operation": "SOURCE_DISCOVERY_REVIEW_CLOSE_LOCAL",
        "review_count": closure.review_count,
        "state": "CLOSED_LOCAL",
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


def _run_source_discovery_once_core(
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
        return _blocked_run_report(selected, "BLOCKED_OFFLINE_CONTRACT", path=path, wip_limit=limit)
    check = check_source_discovery(
        selected,
        state_path=path,
        wip_limit=limit,
        yandex_job_path=yandex_job_path,
        folder_id=folder_id,
        tenderplan_query=tenderplan_query,
        tenderplan_registration_path=tenderplan_registration_path,
        tenderplan_store_path=tenderplan_store_path,
    )
    if check["state"] != "READY_FOR_SEPARATE_AUTHORITY_CHECK":
        return _blocked_run_report(selected, str(check["state"]), path=path, wip_limit=limit)
    if confirmation != SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION:
        return _blocked_run_report(
            selected,
            "BLOCKED_EXPLICIT_CONFIRMATION_REQUIRED",
            path=path,
            wip_limit=limit,
        )
    lab_path = (
        _source_lab_path(control_path=path) if selected is SourceDiscoverySource.YANDEX else None
    )
    if lab_path is not None:
        preflight_yandex_source_lab(lab_path)
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
        return _blocked_run_report(selected, blocked_state, path=path, wip_limit=limit)
    if blocked_state is not None:
        raise SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")

    batch_receipt: YandexSourceLabBatchReceipt | None = None
    discarded_hit_count = 0
    external_requests_this_run: int | None = 0
    journal_report = _accounting_marker("NOT_INVOKED")
    native_runner_call_count = 0
    result_classification = "UNAVAILABLE"
    try:
        if selected is SourceDiscoverySource.YANDEX:
            # Revalidate after the durable reservation so a local store change
            # between the initial preflight and the provider boundary fails
            # closed before any potentially metered read.
            _validate_closed_yandex_batches(path, _rows(path))
            if lab_path is None:
                raise TypeError
            preflight_yandex_source_lab(lab_path)
            native_runner_call_count = 1
            external_requests_this_run = None
            journal_report = _accounting_marker("UNAVAILABLE")

            def record_binding(binding: ManualYandexSearchBinding) -> None:
                _record_yandex_binding(path, attempt_id, binding)

            outcome = run_manual_yandex_search_accounted(
                yandex_job_path,  # type: ignore[arg-type]
                folder_id=folder_id,  # type: ignore[arg-type]
                credential_loader=lambda: load_yandex_api_key(
                    expected_folder_id=folder_id,  # type: ignore[arg-type]
                ),
                binding_recorder=record_binding,
            )
            if type(outcome) is not ManualYandexSearchOutcome:
                raise TypeError
            external_requests_this_run, journal_report = _validated_yandex_accounting(
                outcome.external_requests_this_run,
                outcome.journal,
                completed=True,
            )
            _record_yandex_accounting(
                path,
                attempt_id,
                external_requests_this_run,
                journal_report,
                outcome="COMPLETED",
            )
            result = outcome.page
            if type(result) is not SearchPage:
                raise TypeError
            selection = select_yandex_reviewable_page(result)
            discarded_hit_count = selection.discarded_hit_count
            review_queue = build_review_queue([selection.page])
            review_count = len(review_queue["candidates"])
            if review_count:
                result_classification = "REVIEW_QUEUE_READY"
            elif selection.raw_hit_count:
                result_classification = "NO_SAFE_REVIEWABLE_RESULTS"
            else:
                result_classification = "NO_RESULTS"
            if review_count:
                batch_receipt = persist_yandex_review_batch(
                    attempt_id=attempt_id,
                    page=selection.page,
                    source_lab_path=lab_path,
                )
                if batch_receipt.candidate_count != review_count:
                    raise ValueError
                _record_yandex_batch_link(
                    path,
                    attempt_id,
                    batch_receipt,
                    lab_path,
                )
        else:
            tenderplan_options: dict[str, object] = {
                "confirmation": TENDERPLAN_READ_ONLY_CONFIRMATION,
                "require_existing_store": True,
                "run_id": _expected_tenderplan_run_id(attempt_id),
            }
            if tenderplan_registration_path is not None:
                tenderplan_options["registration_path"] = tenderplan_registration_path
            if tenderplan_store_path is not None:
                tenderplan_options["store_path"] = tenderplan_store_path
            native_runner_call_count = 1
            external_requests_this_run = None
            journal_report = _accounting_marker("NOT_EXPOSED_FOR_SOURCE")
            result = run_tenderplan_read_only_intake(
                tenderplan_query,
                **tenderplan_options,
            )
            if type(result) is not TenderPlanReadOnlyIntakeResult:
                raise TypeError
            review_count = result.queued_count
            binding = _verified_tenderplan_binding(
                attempt_id, result, tenderplan_query,
                tenderplan_store_path if tenderplan_store_path is not None else TENDERPLAN_READ_ONLY_QUEUE_PATH,
                tenderplan_registration_path if tenderplan_registration_path is not None else TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH,
            )
            _finish(path, attempt_id, "READY_FOR_REVIEW" if review_count else "COMPLETE_NO_RESULTS",
                    review_count, tenderplan_binding=binding)
            result_classification = "REVIEW_QUEUE_READY" if review_count else "NO_RESULTS"
        if type(review_count) is not int or not 0 <= review_count <= 1000:
            raise ValueError
    except BaseException as error:
        if selected is SourceDiscoverySource.YANDEX and isinstance(
            error,
            YandexTransportError,
        ):
            try:
                external_requests_this_run, journal_report = _validated_yandex_accounting(
                    error.external_requests_this_run,
                    error.journal_status,
                    completed=False,
                )
                _record_yandex_accounting(
                    path,
                    attempt_id,
                    external_requests_this_run,
                    journal_report,
                    outcome="UNCERTAIN",
                )
            except SourceDiscoveryControlError:
                external_requests_this_run = None
                journal_report = _accounting_marker("UNAVAILABLE")
        elif isinstance(error, YandexCredentialBrokerError):
            external_requests_this_run = None
            journal_report = _accounting_marker("UNAVAILABLE")
        # A catchable interruption is sealed as uncertain.  A hard process
        # termination cannot execute this branch and intentionally leaves the
        # durable RUNNING fence for external/manual reconciliation; this slice
        # has no authority to invent an automatic recovery decision.
        _finish(path, attempt_id, "UNCERTAIN", 0)
        return {
            "attempt_id": attempt_id,
            "control": _snapshot(path, limit),
            "discarded_hit_count": discarded_hit_count,
            "effects": _effects(),
            "error_code": "SOURCE_BOUNDARY_UNCERTAIN",
            "external_requests_this_run": external_requests_this_run,
            "journal": journal_report,
            "native_runner_call_count": native_runner_call_count,
            "operation": "RUN_ONE",
            "result_classification": "UNAVAILABLE",
            "review_count": 0,
            "source": selected.value,
            "state": "UNCERTAIN",
            "version": SOURCE_DISCOVERY_CONTROL_VERSION,
        }

    terminal = "READY_FOR_REVIEW" if review_count else "COMPLETE_NO_RESULTS"
    if selected is SourceDiscoverySource.YANDEX:
        _finish(path, attempt_id, terminal, review_count)
    return {
        "attempt_id": attempt_id,
        "batch_receipt_sha256": (batch_receipt.receipt_sha256 if batch_receipt is not None else ""),
        "control": _snapshot(path, limit),
        "discarded_hit_count": discarded_hit_count,
        "effects": _effects(),
        "external_requests_this_run": external_requests_this_run,
        "journal": journal_report,
        "native_runner_call_count": native_runner_call_count,
        "operation": "RUN_ONE",
        "result_classification": result_classification,
        "review_count": review_count,
        "source_lab_batch_id": (
            batch_receipt.source_lab_batch_id if batch_receipt is not None else ""
        ),
        "source": selected.value,
        "state": terminal,
        "version": SOURCE_DISCOVERY_CONTROL_VERSION,
    }


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
    """Run one source behind a detached, sanitized public failure boundary."""

    try:
        return _run_source_discovery_once_core(
            source,
            confirmation=confirmation,
            state_path=state_path,
            wip_limit=wip_limit,
            yandex_job_path=yandex_job_path,
            folder_id=folder_id,
            tenderplan_query=tenderplan_query,
            tenderplan_registration_path=tenderplan_registration_path,
            tenderplan_store_path=tenderplan_store_path,
        )
    except YandexSourceLabBridgeError as error:
        failure_family = "YANDEX"
        failure_code = (
            error.code
            if type(error.code) is str and error.code in _SAFE_YANDEX_CONTROL_ERROR_CODES
            else "YANDEX_SOURCE_LAB_PREFLIGHT_FAILED"
        )
    except SourceDiscoveryControlError as error:
        failure_family = "CONTROL"
        failure_code = _known_control_failure_code(
            error,
            "SOURCE_BOUNDARY_UNCERTAIN",
        )
    except BaseException:
        failure_family = "CONTROL"
        failure_code = "SOURCE_BOUNDARY_UNCERTAIN"
    del (
        source,
        confirmation,
        state_path,
        wip_limit,
        yandex_job_path,
        folder_id,
        tenderplan_query,
        tenderplan_registration_path,
        tenderplan_store_path,
    )
    if failure_family == "YANDEX":
        _raise_detached_yandex_control_failure(failure_code)
    _raise_detached_control_failure(failure_code)


__all__ = [
    "SOURCE_DISCOVERY_CONTROL_VERSION",
    "SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT",
    "SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION",
    "SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION",
    "SOURCE_DISCOVERY_PILOT_CAP",
    "SOURCE_DISCOVERY_STATE_PATH",
    "SourceDiscoveryControlError",
    "SourceDiscoverySource",
    "check_source_discovery",
    "close_source_discovery_review",
    "run_source_discovery_once",
    "source_discovery_plan",
    "source_discovery_status",
    "verify_source_discovery_authority",
]
