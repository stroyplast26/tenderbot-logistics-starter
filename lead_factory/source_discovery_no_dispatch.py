"""Explicit, local-only admission of a reviewed historical non-dispatch proof.

The native receipt commits first. A crash before the controller commit leaves
both ordinary execution paths blocked. The same proof can complete that local
admission; it cannot replay the consumed attempt or authorize a provider call.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import re
import sqlite3

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_read_only_store as native
from lead_factory.source_discovery_no_dispatch_control import (
    append_no_dispatch_reconciliation,
    build_no_dispatch_receipt,
    install_no_dispatch_schema,
    source_reconciliation_set_sha256,
)
from lead_factory.tenderplan_no_dispatch_evidence import (
    TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
    TenderPlanNoDispatchEvidenceError,
)


SOURCE_NO_DISPATCH_CONFIRMATION = "PREPARE_LOCAL_SOURCE_NO_DISPATCH_RECONCILIATION"
_FALSE_GATES = {
    "retry_eligible": False,
    "launch_allowed": False,
    "authority_verified": False,
    "authorizes_live": False,
    "automatic_schedule_eligible": False,
    "live_release_eligible": False,
}


def _before_source_no_dispatch_commit() -> None:
    """Fault-injection seam after native commit and before controller commit."""


def _reconcile(
    *, state_path: str | Path, tenderplan_store_path: str | Path,
    acceptance_id: str, proof_path: str | Path,
    provenance_paths: Mapping[str, str | Path],
    expected_controller_file_sha256: str,
    expected_controller_snapshot_sha256: str,
    expected_native_file_sha256: str,
    apply: bool, expected_preview_sha256: str | None = None,
) -> dict[str, object]:
    pins = (expected_controller_file_sha256, expected_controller_snapshot_sha256,
            expected_native_file_sha256)
    if any(type(pin) is not str or re.fullmatch(r"[0-9a-f]{64}", pin) is None for pin in pins):
        raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
    if apply and (type(expected_preview_sha256) is not str
                  or re.fullmatch(r"[0-9a-f]{64}", expected_preview_sha256) is None):
        raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
    path = control._state_path(state_path)
    native_path = control._state_path(tenderplan_store_path)
    if path == native_path:
        raise control.SourceDiscoveryControlError("CONTROL_STATE_PATH_INVALID")
    connection = None
    committed = False
    native_created = False
    try:
        control._assert_no_sqlite_sidecars(path)
        control._assert_no_sqlite_sidecars(native_path)
        identity = control._regular_file_identity(path)
        connection = control._open_existing_local_fence(path)
        version = control._control_schema_version(connection)
        if (version not in {7, 8}
                or control._regular_file_identity(path) != identity
                or str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete"
                or control._file_sha256(path) != expected_controller_file_sha256):
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        rows = control._rows(path, _connection=connection)
        raw = control._snapshot(path, control.SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
                                _connection=connection)
        if (control._digest(raw) != expected_controller_snapshot_sha256
                or any(row["state"] == "RUNNING" for row in rows)):
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        native_kwargs = {
            "store_path": native_path, "acceptance_id": acceptance_id,
            "proof_path": proof_path, "provenance_paths": provenance_paths,
            "expected_native_file_sha256": expected_native_file_sha256,
        }
        candidate = native.preview_tenderplan_no_dispatch_admission(**native_kwargs)
        admission = candidate["admission"]
        selected = next((row for row in rows if row["attempt_id"] == admission["attempt_id"]), None)
        attempt = connection.execute(
            "SELECT * FROM source_discovery_attempts WHERE attempt_id=?", (admission["attempt_id"],)
        ).fetchone()
        if (selected is None or selected["source"] != "TENDERPLAN"
                or selected["state"] != "UNCERTAIN" or selected["review_count"] != 0
                or attempt is None or attempt["tenderplan_binding_required"] != 1
                or selected["tenderplan_binding"] is not None
                or selected["tenderplan_failed_closed_reconciliation"] is not None
                or control._digest(control._controller_attempt_body(attempt))
                != admission["controller_attempt_sha256"]):
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        receipt = build_no_dispatch_receipt(dict(attempt), admission)
        existing = selected.get("tenderplan_no_dispatch_reconciliation")
        if existing is None:
            if (version != 7
                    or expected_controller_file_sha256 != admission["controller_file_sha256"]
                    or expected_controller_snapshot_sha256 != admission["controller_snapshot_sha256"]):
                raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        elif existing != receipt:
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        failed_closed = {
            str(row["attempt_id"]): row["tenderplan_failed_closed_reconciliation"]
            for row in rows if row["tenderplan_failed_closed_reconciliation"] is not None
        }
        no_dispatch = {
            str(row["attempt_id"]): row["tenderplan_no_dispatch_reconciliation"]
            for row in rows if row.get("tenderplan_no_dispatch_reconciliation") is not None
        }
        if any(row["state"] == "UNCERTAIN"
               and row["attempt_id"] not in set(failed_closed) | set(no_dispatch) | {admission["attempt_id"]}
               for row in rows):
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        no_dispatch[str(admission["attempt_id"])] = receipt
        native_set = candidate["no_dispatch_admission_set_sha256"]
        scope_set = source_reconciliation_set_sha256(failed_closed, no_dispatch, native_set)
        preview_body = {
            "schema": "source-discovery-no-dispatch-preview/v1",
            "receipt": receipt,
            "native_preview_sha256": candidate["preview_sha256"],
            "source_reconciliation_set_sha256": scope_set,
            **_FALSE_GATES,
        }
        preview_sha256 = control._digest(preview_body)
        if apply and preview_sha256 != expected_preview_sha256:
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        if control._file_sha256(path) != expected_controller_file_sha256:
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        native_file = expected_native_file_sha256
        scoped_control = None
        if apply:
            applied = native.apply_tenderplan_no_dispatch_admission(
                **native_kwargs, expected_preview_sha256=candidate["preview_sha256"],
                confirmation=TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
            )
            native_created = applied["created"] is True
            native_file = applied["native_file_sha256"]
            if applied["admission"] != admission or applied["no_dispatch_admission_set_sha256"] != native_set:
                raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
            if existing is None:
                install_no_dispatch_schema(connection)
                if append_no_dispatch_reconciliation(connection, admission) != receipt:
                    raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
            # Validate both proof types against the native ledger before committing
            # the controller receipt. Hold the native writer fence through COMMIT.
            with control._fenced_source_reconciliation_control(
                path, control.SOURCE_DISCOVERY_DEFAULT_WIP_LIMIT,
                tenderplan_store_path=native_path,
                expected_source_reconciliation_set_sha256=scope_set,
                expected_tenderplan_store_file_sha256=native_file,
                _connection=connection,
                _allow_controller_transaction_journal=True,
            ) as (scoped_control, checked_native_set):
                if (checked_native_set != native_set
                        or control._regular_file_identity(path) != identity):
                    raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
                if existing is None:
                    _before_source_no_dispatch_commit()
                    connection.execute("COMMIT")
                    committed = True
        else:
            # The native preview validates the selected immutable event chain.
            # Older receipts are validated by the mixed fence during apply.
            if control._file_sha256(native_path) != expected_native_file_sha256:
                raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        if not committed:
            connection.execute("ROLLBACK")
        connection.close()
        connection = None
        control._assert_no_sqlite_sidecars(path)
        control._assert_no_sqlite_sidecars(native_path)
        if not committed and control._file_sha256(path) != expected_controller_file_sha256:
            raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
        return {
            "state": "APPLIED" if committed else "ALREADY_APPLIED" if existing else "READY_TO_APPLY",
            **preview_body, "preview_sha256": preview_sha256,
            "controller_file_sha256": control._file_sha256(path),
            "native_file_sha256": native_file,
            "no_dispatch_admission_set_sha256": native_set,
            "control": scoped_control if scoped_control is not None else raw,
            "effects": {
                "controller_store_write_count": int(committed),
                "native_store_write_count": int(native_created),
                "credential_read_count": 0, "provider_request_count": 0,
                "crm_write_count": 0, "message_send_count": 0,
            },
        }
    except (native.TenderPlanReadOnlyStoreError, TenderPlanNoDispatchEvidenceError,
            OSError, sqlite3.Error, KeyError, TypeError, ValueError):
        raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED") from None
    finally:
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            connection.close()


def preview_source_discovery_tenderplan_no_dispatch_reconciliation(
    *, state_path: str | Path, tenderplan_store_path: str | Path,
    acceptance_id: str, proof_path: str | Path,
    provenance_paths: Mapping[str, str | Path],
    expected_controller_file_sha256: str,
    expected_controller_snapshot_sha256: str,
    expected_native_file_sha256: str,
) -> dict[str, object]:
    return _reconcile(
        state_path=state_path, tenderplan_store_path=tenderplan_store_path,
        acceptance_id=acceptance_id, proof_path=proof_path, provenance_paths=provenance_paths,
        expected_controller_file_sha256=expected_controller_file_sha256,
        expected_controller_snapshot_sha256=expected_controller_snapshot_sha256,
        expected_native_file_sha256=expected_native_file_sha256, apply=False,
    )


def apply_source_discovery_tenderplan_no_dispatch_reconciliation(
    *, state_path: str | Path, tenderplan_store_path: str | Path,
    acceptance_id: str, proof_path: str | Path,
    provenance_paths: Mapping[str, str | Path],
    expected_controller_file_sha256: str,
    expected_controller_snapshot_sha256: str,
    expected_native_file_sha256: str, expected_preview_sha256: str, confirmation: str,
) -> dict[str, object]:
    if confirmation != SOURCE_NO_DISPATCH_CONFIRMATION:
        raise control.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")
    return _reconcile(
        state_path=state_path, tenderplan_store_path=tenderplan_store_path,
        acceptance_id=acceptance_id, proof_path=proof_path, provenance_paths=provenance_paths,
        expected_controller_file_sha256=expected_controller_file_sha256,
        expected_controller_snapshot_sha256=expected_controller_snapshot_sha256,
        expected_native_file_sha256=expected_native_file_sha256,
        expected_preview_sha256=expected_preview_sha256, apply=True,
    )
