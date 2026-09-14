"""Typed, local TenderPlan review closure used by the normal controller entry point.

The controller owns every write. Native ledgers are inspected and fenced only;
HOLD remains a pending substantive review, and closure grants no source authority.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import re
import sqlite3
from typing import Iterator, Mapping

TABLE = "source_discovery_tenderplan_review_closures"
VERSION = "source-discovery-tenderplan-review-closure/v1"
CONTROL_V9_SCHEMA_SHA256 = "9a00dd93c4e6357562203181df3545ec44e0710480f69103f570d2f80d8fc771"
SCHEMA_SQL = f"""CREATE TABLE {TABLE}(
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES source_discovery_attempts(attempt_id),
    run_id TEXT NOT NULL UNIQUE,
    native_path TEXT NOT NULL,
    preview_sha256 TEXT NOT NULL CHECK(length(preview_sha256)=64),
    record_json TEXT NOT NULL,
    record_sha256 TEXT NOT NULL UNIQUE CHECK(length(record_sha256)=64),
    idempotency_key TEXT NOT NULL UNIQUE
)"""
_HEX = re.compile(r"[0-9a-f]{64}")
_KEYS = frozenset({
    "version", "attempt_id", "run_id", "native_path", "preview_sha256",
    "native_material", "closed_at_utc", "actor", "evidence_ref", "idempotency_key",
    "hold_disposition", "authorizes_live", "launch_allowed",
})


def _control():
    from lead_factory import source_discovery_control
    return source_discovery_control


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _strict_json(value: str) -> dict:
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError
            result[key] = item
        return result
    result = json.loads(value, object_pairs_hook=pairs)
    if type(result) is not dict:
        raise ValueError
    return result


def native_material(
    path: Path, attempt: Mapping[str, object], binding: Mapping[str, object],
    *, connection: sqlite3.Connection | None = None,
) -> dict:
    """Inspect one immutable native run and current decision heads; no controller recursion."""
    from lead_factory import tenderplan_read_only_store as native
    control = _control()
    path = control._state_path(path)
    identity = control._regular_file_identity(path)
    control._assert_no_sqlite_sidecars(path)
    store = native._existing_store(path)
    if (store.store_identity_sha256 != binding["native_store_identity_sha256"]
            or control._source_lab_path_sha256(path) != binding["native_path_sha256"]):
        raise ValueError
    with ExitStack() as stack:
        con = connection or stack.enter_context(store._transaction(write=False))
        store._verify_locked(con)
        run_id = str(binding["run_id"])
        ready = store._ready_receipt(con, run_id)
        operation = con.execute(
            "SELECT operation_sha256,intent_record_sha256,intent_json FROM tenderplan_read_only_operations WHERE run_id=?",
            (run_id,),
        ).fetchone()
        rows = con.execute(
            """SELECT c.item_id,c.run_id,c.ordinal,c.encrypted_card_sha256,
                      d.decision_id,d.sequence AS decision_sequence,d.decision,d.reason_code,d.decision_sha256
               FROM tenderplan_read_only_cards c LEFT JOIN tenderplan_read_only_decisions d
                 ON d.item_id=c.item_id AND d.sequence=(
                    SELECT MAX(x.sequence) FROM tenderplan_read_only_decisions x WHERE x.item_id=c.item_id)
               WHERE c.run_id=? ORDER BY c.ordinal""", (run_id,),
        ).fetchall()
        if operation is None:
            raise ValueError
        intent = _strict_json(str(operation["intent_json"]))
        if (ready.receipt_record_sha256 != binding["receipt_record_sha256"]
                or ready.event_sha256 != binding["event_sha256"]
                or list(ready.item_ids) != binding["item_ids"]
                or ready.card_count != binding["card_count"]
                or attempt["review_count"] != ready.card_count
                or [row["item_id"] for row in rows] != list(ready.item_ids)
                or operation["intent_record_sha256"] != binding["intent_record_sha256"]
                or any(intent.get(key) != binding[key] for key in (
                    "intent_record_sha256", "request_sha256", "query_policy_sha256"))):
            raise ValueError
        counts = {"KEEP": 0, "DISMISS": 0, "HOLD": 0, "UNDECIDED": 0}
        heads = []
        for ordinal, row in enumerate(rows, 1):
            if (row["ordinal"] != ordinal or row["run_id"] != run_id
                    or row["decision"] not in {"KEEP", "DISMISS", "HOLD"} or type(row["decision_sequence"]) is not int
                    or row["decision_sequence"] < 1):
                raise ValueError
            counts[row["decision"]] += 1
            heads.append(dict(row))
        store._verify_locked(con)
        material = {
            "controller_attempt_sha256": control._digest(control._controller_attempt_body(attempt)),
            "binding_receipt_sha256": binding["binding_receipt_sha256"],
            "native_store_identity_sha256": store.store_identity_sha256,
            "native_path_sha256": binding["native_path_sha256"],
            "run_id": run_id, "operation_sha256": operation["operation_sha256"],
            "receipt_record_sha256": ready.receipt_record_sha256,
            "event_sha256": ready.event_sha256,
            "intent_record_sha256": binding["intent_record_sha256"],
            "request_sha256": binding["request_sha256"],
            "query_policy_sha256": binding["query_policy_sha256"],
            "item_ids": list(ready.item_ids), "review_count": ready.card_count,
            "decision_heads": heads, "decision_counts": counts,
        }
    control._assert_no_sqlite_sidecars(path)
    if control._regular_file_identity(path) != identity:
        raise ValueError
    return material


def validate_closures(
    connection: sqlite3.Connection, bindings: Mapping[str, Mapping[str, object]],
) -> dict[str, dict]:
    """Validate all typed records and native heads without snapshot/preview calls."""
    control = _control()
    present = connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone()
    if not present:
        return {}
    try:
        if control._control_schema_version(connection) != 9:
            raise ValueError
        attempts = {row["attempt_id"]: dict(row) for row in connection.execute("SELECT * FROM source_discovery_attempts")}
        result = {}
        for row in connection.execute(f"SELECT * FROM {TABLE} ORDER BY sequence"):
            body = _strict_json(row["record_json"])
            attempt = attempts.get(row["attempt_id"])
            binding = bindings.get(row["attempt_id"])
            if (set(body) != _KEYS or body["version"] != VERSION or attempt is None or binding is None
                    or attempt["source"] != "TENDERPLAN" or attempt["state"] != "READY_FOR_REVIEW"
                    or attempt["tenderplan_binding_required"] != 1
                    or body["attempt_id"] != row["attempt_id"] or body["run_id"] != row["run_id"]
                    or body["run_id"] != control._expected_tenderplan_run_id(row["attempt_id"])
                    or body["native_path"] != row["native_path"] or not Path(body["native_path"]).is_absolute()
                    or body["preview_sha256"] != row["preview_sha256"]
                    or type(body["preview_sha256"]) is not str or _HEX.fullmatch(body["preview_sha256"]) is None
                    or body["idempotency_key"] != row["idempotency_key"]
                    or body["hold_disposition"] != "PENDING_SUBSTANTIVE_REVIEW"
                    or body["authorizes_live"] is not False or body["launch_allowed"] is not False
                    or not control._valid_recorded_at(body["closed_at_utc"])
                    or control._digest(body) != row["record_sha256"]
                    or _canonical(body) != row["record_json"]):
                raise ValueError
            actor = control._local_text(body["actor"], maximum=128, code="LOCAL_REVIEW_ACTOR_INVALID")
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", actor) is None:
                raise ValueError
            control._local_text(body["evidence_ref"], maximum=2048, code="LOCAL_REVIEW_EVIDENCE_INVALID")
            control._local_text(body["idempotency_key"], maximum=256, code="LOCAL_REVIEW_IDEMPOTENCY_INVALID")
            if native_material(Path(body["native_path"]), attempt, binding) != body["native_material"]:
                raise ValueError
            result[row["attempt_id"]] = {**body, "record_sha256": row["record_sha256"]}
        return result
    except Exception:
        raise control.SourceDiscoveryControlError("CONTROL_TENDERPLAN_REVIEW_RECONCILIATION_REQUIRED") from None


def install_schema(connection: sqlite3.Connection) -> None:
    """Exact additive migration, only within an admitted local close transaction."""
    from lead_factory.source_discovery_no_dispatch_control import install_no_dispatch_schema
    control = _control()
    version = control._control_schema_version(connection)
    if version == 5:
        connection.execute(control._REVIEW_DEFERRAL_SCHEMA_SQL)
        for operation in ("UPDATE", "DELETE"):
            connection.execute(control._append_only_trigger_sql(control._REVIEW_DEFERRALS, operation))
        connection.execute("PRAGMA user_version=6")
        version = control._control_schema_version(connection)
    if version == 6:
        control._install_tenderplan_failed_closed_reconciliation_schema(connection)
        version = control._control_schema_version(connection)
    if version == 7:
        install_no_dispatch_schema(connection)
        version = control._control_schema_version(connection)
    if version == 8:
        connection.execute(SCHEMA_SQL)
        for operation in ("UPDATE", "DELETE"):
            connection.execute(control._append_only_trigger_sql(TABLE, operation))
        connection.execute("PRAGMA user_version=9")
    if control._control_schema_version(connection) != 9:
        raise control.SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


@contextmanager
def fence_closed_native_stores(connection: sqlite3.Connection) -> Iterator[None]:
    """Hold native writer fences during a controller reservation lacking another native fence."""
    control = _control()
    with ExitStack() as stack:
        if connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone():
            paths = [row[0] for row in connection.execute(f"SELECT DISTINCT native_path FROM {TABLE} ORDER BY native_path")]
            for value in paths:
                path = control._state_path(value)
                control._assert_no_sqlite_sidecars(path)
                native_connection = control._open_existing_local_fence(path)
                stack.callback(native_connection.close)
        yield


def close_batch(
    *, attempt_id: str, state_path: Path, native_path: Path,
    expected_preview_sha256: str, actor: str, evidence_ref: str, idempotency_key: str,
    confirmation: str | None,
) -> dict:
    """Invoked only by the controller's normal, confirmed local close command."""
    from lead_factory.tenderplan_controller_review_bridge import inspect_tenderplan_controller_review_closure
    control = _control()
    if confirmation != control.SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION:
        raise control.SourceDiscoveryControlError("LOCAL_CLOSE_CONFIRMATION_REQUIRED")
    if type(expected_preview_sha256) is not str or _HEX.fullmatch(expected_preview_sha256) is None:
        raise control.SourceDiscoveryControlError("LOCAL_REVIEW_PIN_MISMATCH")
    connection = None
    native_connection = None
    try:
        path = control._state_path(state_path)
        native_path = control._state_path(native_path)
        control._assert_no_sqlite_sidecars(path)
        control._assert_no_sqlite_sidecars(native_path)
        controller_identity = control._regular_file_identity(path)
        native_identity = control._regular_file_identity(native_path)
        connection = control._open_existing_local_fence(path)
        control._control_schema_version(connection)
        native_connection = control._open_existing_local_fence(native_path)
        if (str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete"
                or str(native_connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete"):
            raise ValueError
        rows = control._rows(path, _connection=connection)
        selected = next((row for row in rows if row["attempt_id"] == attempt_id), None)
        attempt = connection.execute("SELECT * FROM source_discovery_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        if (selected is None or attempt is None or selected["source"] != "TENDERPLAN"
                or selected["state"] != "READY_FOR_REVIEW" or selected["tenderplan_binding"] is None
                or selected["closed_at_utc"] is not None or selected["deferred_review"] is not None):
            raise control.SourceDiscoveryControlError("LOCAL_REVIEW_BATCH_NOT_CLOSABLE")
        material = native_material(native_path, dict(attempt), selected["tenderplan_binding"], connection=native_connection)
        previous = selected.get("tenderplan_review_closure")
        created = previous is None
        if previous:
            if (previous["native_path"] != str(native_path) or previous["preview_sha256"] != expected_preview_sha256
                    or previous["actor"] != actor or previous["evidence_ref"] != evidence_ref
                    or previous["idempotency_key"] != idempotency_key or previous["native_material"] != material):
                raise control.SourceDiscoveryControlError("LOCAL_REVIEW_CLOSE_CONFLICT")
            record_sha256 = previous["record_sha256"]
        else:
            preview = inspect_tenderplan_controller_review_closure(
                attempt_id, state_path=path, tenderplan_store_path=native_path)
            if preview.state != "READY_TO_CLOSE" or preview.proof_sha256 != expected_preview_sha256:
                raise control.SourceDiscoveryControlError("LOCAL_REVIEW_PIN_MISMATCH")
            body = {
                "version": VERSION, "attempt_id": attempt_id, "run_id": material["run_id"],
                "native_path": str(native_path), "preview_sha256": expected_preview_sha256,
                "native_material": material, "closed_at_utc": control._now_utc(),
                "actor": actor, "evidence_ref": evidence_ref, "idempotency_key": idempotency_key,
                "hold_disposition": "PENDING_SUBSTANTIVE_REVIEW", "authorizes_live": False, "launch_allowed": False,
            }
            record_sha256 = control._digest(body)
            install_schema(connection)
            connection.execute(
                f"INSERT INTO {TABLE}(attempt_id,run_id,native_path,preview_sha256,record_json,record_sha256,idempotency_key) VALUES(?,?,?,?,?,?,?)",
                (attempt_id, material["run_id"], str(native_path), expected_preview_sha256,
                 _canonical(body), record_sha256, idempotency_key),
            )
            control._rows(path, _connection=connection)
        if (control._regular_file_identity(path) != controller_identity
                or control._regular_file_identity(native_path) != native_identity
                or native_material(native_path, dict(attempt), selected["tenderplan_binding"], connection=native_connection) != material):
            raise ValueError
        connection.execute("COMMIT")
    except control.SourceDiscoveryControlError:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except Exception:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise control.SourceDiscoveryControlError("CONTROL_TENDERPLAN_REVIEW_RECONCILIATION_REQUIRED") from None
    finally:
        if native_connection is not None:
            native_connection.close()
        if connection is not None:
            connection.close()
    return {
        "attempt_id": attempt_id, "source": "TENDERPLAN", "state": "CLOSED_LOCAL",
        "created": created, "closure_receipt_sha256": record_sha256,
        "review_count": material["review_count"], "decision_counts": material["decision_counts"],
        "hold_disposition": "PENDING_SUBSTANTIVE_REVIEW", "authorizes_live": False, "launch_allowed": False,
        "control": control._snapshot(path, control.SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT),
        "effects": control._local_effects(), "operation": "SOURCE_DISCOVERY_REVIEW_CLOSE_LOCAL", "version": VERSION,
    }
