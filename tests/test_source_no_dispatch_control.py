from __future__ import annotations

import hashlib
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import source_discovery_no_dispatch_control as receipts
from lead_factory import tenderplan_no_dispatch_evidence as evidence
from lead_factory import tenderplan_read_only_store as native
from tests.test_lead_factory_tenderplan_no_dispatch_admission import (
    ACCEPTANCE_ID, ATTEMPT_ID, RUN_ID, make_admission_fixture,
)


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external action forbidden"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    yield forbidden
    forbidden.assert_not_called()


def make_scoped_fixture(tmp_path, monkeypatch):
    native_path, arguments, account, proof = make_admission_fixture(tmp_path, monkeypatch)
    path = tmp_path / "controller.sqlite3"
    connection = control._open_for_write(path)
    connection.execute("BEGIN IMMEDIATE")
    control._install_tenderplan_binding_schema(connection)
    connection.execute(control._REVIEW_DEFERRAL_SCHEMA_SQL)
    for operation in ("UPDATE", "DELETE"):
        connection.execute(control._append_only_trigger_sql(control._REVIEW_DEFERRALS, operation))
    connection.execute("PRAGMA user_version=6")
    control._install_tenderplan_failed_closed_reconciliation_schema(connection)
    connection.execute(
        """INSERT INTO source_discovery_attempts(
            attempt_id,source,state,started_at_utc,finished_at_utc,review_count,tenderplan_binding_required
        ) VALUES(?,'TENDERPLAN','UNCERTAIN','2026-09-14T09:00:00Z','2026-09-14T09:00:01Z',0,1)""",
        (ATTEMPT_ID,),
    )
    attempt = dict(connection.execute("SELECT * FROM source_discovery_attempts").fetchone())
    connection.execute("COMMIT")
    connection.close()
    proof["controller"].update({
        "attempt_sha256": control._digest(control._controller_attempt_body(attempt)),
        "file_sha256": control._file_sha256(path),
        "snapshot_sha256": control._digest(control._snapshot(path, 1)),
    })
    proof.pop("record_sha256")
    proof["record_sha256"] = evidence.no_dispatch_digest(proof)
    arguments["proof_path"].write_bytes(evidence.canonical_no_dispatch(proof) + b"\n")
    accepted = dict(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE[ACCEPTANCE_ID])
    accepted.update({
        "proof_record_sha256": proof["record_sha256"],
        "proof_file_sha256": hashlib.sha256(arguments["proof_path"].read_bytes()).hexdigest(),
    })
    monkeypatch.setitem(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE, ACCEPTANCE_ID, accepted)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    applied = native.apply_tenderplan_no_dispatch_admission(
        **arguments, expected_preview_sha256=preview["preview_sha256"],
        confirmation=native.TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
    )
    connection = control._open_existing_local_fence(path)
    receipts.install_no_dispatch_schema(connection)
    receipt = receipts.append_no_dispatch_reconciliation(connection, applied["admission"])
    connection.execute("COMMIT")
    connection.close()
    pin = receipts.source_reconciliation_set_sha256(
        {}, {ATTEMPT_ID: receipt}, applied["no_dispatch_admission_set_sha256"]
    )
    return path, native_path, pin, applied, attempt


def _check(path, native_path, pin, source="YANDEX"):
    return control.check_source_discovery(
        source, state_path=path, tenderplan_store_path=native_path,
        expected_source_reconciliation_set_sha256=pin,
        yandex_job_path=path.parent / "unused_job.json", folder_id="synthetic-folder",
    )


def _reserve_kwargs(path, native_path, pin, check):
    return {
        "tenderplan_store_path": native_path,
        "expected_source_reconciliation_set_sha256": pin,
        "expected_controller_file_sha256": check["controller_file_sha256"],
        "expected_controller_snapshot_sha256": check["controller_snapshot_sha256"],
        "expected_tenderplan_store_file_sha256": check["tenderplan_store_file_sha256"],
    }


def test_scoped_check_preserves_raw_uncertainty_and_legacy_block(tmp_path, monkeypatch):
    path, native_path, pin, applied, original = make_scoped_fixture(tmp_path, monkeypatch)
    before = path.read_bytes(), native_path.read_bytes()
    raw = control.source_discovery_status(state_path=path)["control"]
    assert raw["gate"] == "BLOCKED_UNCERTAIN"
    for source in ("YANDEX", "TENDERPLAN"):
        assert control.check_source_discovery(source, state_path=path)["state"] == "BLOCKED_UNCERTAIN"
    check = _check(path, native_path, pin)
    assert check["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert check["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert check["control"]["blocking_uncertain_count"] == 0
    assert check["control"]["uncertain_count"] == 1
    assert check["scope"] == "FRESH_PROPOSAL_ONLY"
    assert check["tenderplan_no_dispatch_admission_set_sha256"] == applied["no_dispatch_admission_set_sha256"]
    assert all(check[key] is False for key in ("launch_allowed", "retry_eligible", "authority_verified", "authorizes_live"))
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        assert dict(connection.execute("SELECT * FROM source_discovery_attempts").fetchone()) == original
    assert (path.read_bytes(), native_path.read_bytes()) == before


@pytest.mark.parametrize("source", [control.SourceDiscoverySource.YANDEX, control.SourceDiscoverySource.TENDERPLAN])
def test_fresh_reservation_with_typed_history_keeps_single_running_fence(tmp_path, monkeypatch, source):
    path, native_path, pin, _, _ = make_scoped_fixture(tmp_path, monkeypatch)
    check = _check(path, native_path, pin)
    attempt_id, blocked = control._reserve(path, source, 1, **_reserve_kwargs(path, native_path, pin, check))
    assert blocked is None and attempt_id != ATTEMPT_ID
    rows = control._rows(path)
    assert [(row["attempt_id"], row["state"]) for row in rows] == [(ATTEMPT_ID, "UNCERTAIN"), (attempt_id, "RUNNING")]
    with sqlite3.connect(path) as connection:
        marker = connection.execute("SELECT tenderplan_binding_required FROM source_discovery_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()[0]
    assert marker == int(source is control.SourceDiscoverySource.TENDERPLAN)
    assert _check(path, native_path, pin)["state"] == "BLOCKED_IN_FLIGHT"
    assert control._reserve(path, source, 1) == (None, "BLOCKED_UNCERTAIN") or source is control.SourceDiscoverySource.TENDERPLAN


@pytest.mark.parametrize("key", ["expected_controller_file_sha256", "expected_controller_snapshot_sha256", "expected_tenderplan_store_file_sha256", "expected_source_reconciliation_set_sha256"])
def test_wrong_reservation_pins_never_reserve_or_call_native(tmp_path, monkeypatch, key):
    path, native_path, pin, _, _ = make_scoped_fixture(tmp_path, monkeypatch)
    kwargs = _reserve_kwargs(path, native_path, pin, _check(path, native_path, pin))
    kwargs[key] = "0" * 64
    before = path.read_bytes(), native_path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control._reserve(path, control.SourceDiscoverySource.YANDEX, 1, **kwargs)
    assert (path.read_bytes(), native_path.read_bytes()) == before


def test_mutually_exclusive_and_missing_native_path_are_blocked(tmp_path, monkeypatch):
    path, native_path, pin, _, _ = make_scoped_fixture(tmp_path, monkeypatch)
    with pytest.raises(control.SourceDiscoveryControlError):
        control.check_source_discovery("TENDERPLAN", state_path=path, tenderplan_store_path=native_path,
            expected_source_reconciliation_set_sha256=pin, expected_tenderplan_reconciliation_set_sha256="0" * 64)
    with pytest.raises(control.SourceDiscoveryControlError):
        control.check_source_discovery("YANDEX", state_path=path, expected_source_reconciliation_set_sha256=pin)


def test_controller_receipt_append_is_idempotent_and_append_only(tmp_path, monkeypatch):
    path, _, _, applied, _ = make_scoped_fixture(tmp_path, monkeypatch)
    before = path.read_bytes()
    connection = control._open_existing_local_fence(path)
    existing = receipts.validate_no_dispatch_reconciliations(connection)
    assert receipts.append_no_dispatch_reconciliation(connection, applied["admission"]) == existing[ATTEMPT_ID]
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(f"DELETE FROM {receipts.NO_DISPATCH_TABLE}")
    connection.execute("ROLLBACK")
    connection.close()
    assert path.read_bytes() == before


def test_unknown_new_attempt_still_blocks_scoped_gate(tmp_path, monkeypatch):
    path, native_path, pin, _, _ = make_scoped_fixture(tmp_path, monkeypatch)
    check = _check(path, native_path, pin)
    attempt_id, _ = control._reserve(path, control.SourceDiscoverySource.YANDEX, 1,
                                    **_reserve_kwargs(path, native_path, pin, check))
    control._finish(path, attempt_id, "UNCERTAIN", 0)
    check = _check(path, native_path, pin)
    assert check["state"] == "BLOCKED_UNCERTAIN"
    assert check["control"]["blocking_uncertain_count"] == 1


def test_tenderplan_scoped_native_check_and_run_receive_only_validated_pin(tmp_path, monkeypatch):
    path, native_path, pin, applied, _ = make_scoped_fixture(tmp_path, monkeypatch)
    checker = Mock(return_value={"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK"})
    runner = Mock(side_effect=RuntimeError("synthetic provider boundary remains absent"))
    monkeypatch.setattr(control, "check_tenderplan_read_only_intake", checker)
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", runner)
    check = _check(path, native_path, pin, "TENDERPLAN")
    expected_native_pin = applied["no_dispatch_admission_set_sha256"]
    assert checker.call_args.kwargs["expected_no_dispatch_admission_set_sha256"] == expected_native_pin
    result = control.run_source_discovery_once("TENDERPLAN", state_path=path,
        confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        **_reserve_kwargs(path, native_path, pin, check))
    assert result["state"] == "UNCERTAIN"
    assert result["native_runner_call_count"] == 1
    assert runner.call_args.kwargs["expected_no_dispatch_admission_set_sha256"] == expected_native_pin
    assert runner.call_args.kwargs["run_id"] != RUN_ID
