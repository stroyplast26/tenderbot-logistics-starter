"""Typed local controller receipts for independently proven non-dispatch.

These helpers never open a native store or grant execution authority. The caller
owns the controller transaction and obtains the native receipt under its fence.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Mapping

from lead_factory.tenderplan_no_dispatch_evidence import (
    TenderPlanNoDispatchEvidenceError,
    validate_no_dispatch_admission,
)


NO_DISPATCH_TABLE = "source_discovery_tenderplan_no_dispatch_reconciliations"
NO_DISPATCH_RECEIPT_VERSION = "source-discovery-tenderplan-no-dispatch-receipt/v1"
SOURCE_RECONCILIATION_SET_VERSION = "source-discovery-scoped-reconciliation-set/v1"
CONTROL_V8_SCHEMA_SHA256 = "0f00840f025090b799cef73a2b4c559a94d7ad236a1839c42b70f672f9f63539"
_FALSE_GATES = (
    "retry_eligible", "launch_allowed", "authority_verified", "authorizes_live",
    "automatic_schedule_eligible", "live_release_eligible",
)
NO_DISPATCH_SCHEMA_SQL = f"""CREATE TABLE {NO_DISPATCH_TABLE}(
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES source_discovery_attempts(attempt_id),
    run_id TEXT NOT NULL UNIQUE,
    controller_attempt_sha256 TEXT NOT NULL CHECK(length(controller_attempt_sha256)=64),
    native_admission_record_sha256 TEXT NOT NULL UNIQUE CHECK(length(native_admission_record_sha256)=64),
    receipt_json TEXT NOT NULL,
    reconciliation_receipt_sha256 TEXT NOT NULL UNIQUE CHECK(length(reconciliation_receipt_sha256)=64)
)"""


def _control():
    from lead_factory import source_discovery_control

    return source_discovery_control


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def install_no_dispatch_schema(connection: sqlite3.Connection) -> None:
    """Explicit V7-to-V8 migration; no implicit production-path migration."""
    control = _control()
    if control._control_schema_version(connection) != 7:
        raise control.SourceDiscoveryControlError("CONTROL_SCHEMA_PREPARATION_REQUIRED")
    connection.execute(NO_DISPATCH_SCHEMA_SQL)
    for operation in ("UPDATE", "DELETE"):
        connection.execute(control._append_only_trigger_sql(NO_DISPATCH_TABLE, operation))
    connection.execute("PRAGMA user_version=8")
    if control._control_schema_version(connection) != 8:
        raise control.SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")


def build_no_dispatch_receipt(
    attempt: Mapping[str, object],
    native_admission: Mapping[str, object],
) -> dict[str, object]:
    """Stable receipt bound to the immutable original controller attempt."""
    control = _control()
    body = {
        "receipt_version": NO_DISPATCH_RECEIPT_VERSION,
        "proof_state": "PROVEN_PRE_DISPATCH_UNCERTAIN",
        "attempt_id": str(attempt["attempt_id"]),
        "run_id": control._expected_tenderplan_run_id(str(attempt["attempt_id"])),
        "controller_attempt_sha256": control._digest(control._controller_attempt_body(attempt)),
        "native_admission": dict(native_admission),
        **dict.fromkeys(_FALSE_GATES, False),
    }
    return {**body, "reconciliation_receipt_sha256": control._digest(body)}


def validate_no_dispatch_reconciliations(
    connection: sqlite3.Connection,
) -> dict[str, dict[str, object]]:
    """Verify canonical typed records; native truth is checked separately fenced."""
    control = _control()
    try:
        if control._control_schema_version(connection) != 8:
            raise ValueError
        attempts = {
            str(row["attempt_id"]): dict(row)
            for row in connection.execute("SELECT * FROM source_discovery_attempts")
        }
        forbidden = {
            str(row[0])
            for table in (control._TP_BINDINGS, control._TP_FAILED_CLOSED_RECONCILIATIONS)
            for row in connection.execute(f"SELECT attempt_id FROM {table}")
        }
        result: dict[str, dict[str, object]] = {}
        for row in connection.execute(f"SELECT * FROM {NO_DISPATCH_TABLE} ORDER BY sequence"):
            receipt = json.loads(str(row["receipt_json"]))
            attempt_id = str(row["attempt_id"])
            attempt = attempts.get(attempt_id)
            native = receipt.get("native_admission") if type(receipt) is dict else None
            if (
                attempt is None
                or attempt_id in forbidden
                or attempt["source"] != "TENDERPLAN"
                or attempt["state"] != "UNCERTAIN"
                or attempt["review_count"] != 0
                or attempt["tenderplan_binding_required"] != 1
                or not control._valid_recorded_at(attempt["started_at_utc"])
                or not control._valid_recorded_at(attempt["finished_at_utc"])
                or type(native) is not dict
            ):
                raise ValueError
            expected = build_no_dispatch_receipt(attempt, native)
            if validate_no_dispatch_admission(native) != native:
                raise ValueError
            native_hash = native.get("record_sha256")
            if (
                receipt != expected
                or _canonical(receipt) != row["receipt_json"]
                or native.get("attempt_id") != attempt_id
                or native.get("run_id") != expected["run_id"]
                or native.get("controller_attempt_sha256") != expected["controller_attempt_sha256"]
                or type(native_hash) is not str
                or re.fullmatch(r"[0-9a-f]{64}", native_hash) is None
                or control._digest({key: value for key, value in native.items() if key != "record_sha256"}) != native_hash
                or row["run_id"] != expected["run_id"]
                or row["controller_attempt_sha256"] != expected["controller_attempt_sha256"]
                or row["native_admission_record_sha256"] != native_hash
                or row["reconciliation_receipt_sha256"] != expected["reconciliation_receipt_sha256"]
                or any(native.get(key, False) is not False for key in _FALSE_GATES)
            ):
                raise ValueError
            result[attempt_id] = receipt
        return result
    except control.SourceDiscoveryControlError:
        raise
    except (ValueError, TypeError, KeyError, sqlite3.Error, TenderPlanNoDispatchEvidenceError):
        raise control.SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED") from None


def append_no_dispatch_reconciliation(
    connection: sqlite3.Connection,
    native_admission: Mapping[str, object],
) -> dict[str, object]:
    """Append one receipt in the caller transaction; repeated exact append is inert."""
    control = _control()
    existing = validate_no_dispatch_reconciliations(connection)
    attempt_id = str(native_admission["attempt_id"])
    attempt = connection.execute(
        "SELECT * FROM source_discovery_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    if attempt is None:
        raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
    receipt = build_no_dispatch_receipt(dict(attempt), native_admission)
    if attempt_id in existing:
        if existing[attempt_id] != receipt:
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        return receipt
    connection.execute(
        f"""INSERT INTO {NO_DISPATCH_TABLE}(
            attempt_id,run_id,controller_attempt_sha256,native_admission_record_sha256,
            receipt_json,reconciliation_receipt_sha256
        ) VALUES(?,?,?,?,?,?)""",
        (attempt_id, receipt["run_id"], receipt["controller_attempt_sha256"],
         native_admission["record_sha256"], _canonical(receipt),
         receipt["reconciliation_receipt_sha256"]),
    )
    if validate_no_dispatch_reconciliations(connection).get(attempt_id) != receipt:
        raise control.SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
    return receipt


def source_reconciliation_set_sha256(
    failed_closed: Mapping[str, Mapping[str, object]],
    no_dispatch: Mapping[str, Mapping[str, object]],
    native_admission_set_sha256: str,
) -> str:
    """Domain-separated set binds both proof types and the full native V3 set."""
    control = _control()
    if (
        set(failed_closed).intersection(no_dispatch)
        or not no_dispatch
        or type(native_admission_set_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", native_admission_set_sha256) is None
    ):
        raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
    return control._digest({
        "schema": SOURCE_RECONCILIATION_SET_VERSION,
        "native_no_dispatch_admission_set_sha256": native_admission_set_sha256,
        "receipts": sorted([
            {"kind": kind, "attempt_id": key,
             "receipt_sha256": str(value["reconciliation_receipt_sha256"])}
            for kind, values in (("PRE_PROVIDER_FAILED_CLOSED", failed_closed),
                                 ("PRE_DISPATCH_UNCERTAIN", no_dispatch))
            for key, value in values.items()
        ], key=lambda value: (value["kind"], value["attempt_id"])),
    })
