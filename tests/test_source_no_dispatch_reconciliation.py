from __future__ import annotations

import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import source_discovery_no_dispatch as reconciliation
from lead_factory import tenderplan_no_dispatch_evidence as evidence
from lead_factory import tenderplan_read_only_store as native
from tests import test_lead_factory_source_discovery_tenderplan_reconciliation as old_fixture
from tests.test_lead_factory_tenderplan_no_dispatch_admission import (
    ACCEPTANCE_ID, ATTEMPT_ID, make_admission_fixture,
)


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external effect forbidden"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", forbidden)
    monkeypatch.setattr(control, "run_manual_yandex_search_accounted", forbidden)
    yield
    forbidden.assert_not_called()


def _candidate(tmp_path, monkeypatch):
    native_path, native_args, _, proof = make_admission_fixture(tmp_path, monkeypatch)
    path = tmp_path / "controller.sqlite3"
    monkeypatch.setattr(old_fixture, "ATTEMPT_ID", ATTEMPT_ID)
    old_fixture._make_v6_uncertain_controller(path)
    connection = control._open_existing_local_fence(path)
    control._install_tenderplan_failed_closed_reconciliation_schema(connection)
    connection.execute("COMMIT")
    connection.close()
    with sqlite3.connect(path) as reader:
        reader.row_factory = sqlite3.Row
        attempt = reader.execute("SELECT * FROM source_discovery_attempts").fetchone()
    snapshot = control.source_discovery_status(state_path=path)["control"]
    proof["controller"].update({
        "file_sha256": control._file_sha256(path),
        "snapshot_sha256": control._digest(snapshot),
        "attempt_sha256": control._digest(control._controller_attempt_body(attempt)),
    })
    proof.pop("record_sha256")
    proof["record_sha256"] = evidence.no_dispatch_digest(proof)
    native_args["proof_path"].write_bytes(evidence.canonical_no_dispatch(proof) + b"\n")
    registry = dict(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE[ACCEPTANCE_ID])
    registry.update({
        "proof_file_sha256": control._file_sha256(native_args["proof_path"]),
        "proof_record_sha256": proof["record_sha256"],
    })
    monkeypatch.setitem(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE, ACCEPTANCE_ID, registry)
    arguments = {key: value for key, value in native_args.items() if key != "store_path"}
    arguments.update({
        "state_path": path, "tenderplan_store_path": native_path,
        "expected_controller_file_sha256": proof["controller"]["file_sha256"],
        "expected_controller_snapshot_sha256": proof["controller"]["snapshot_sha256"],
    })
    return path, native_path, arguments


def _apply(arguments, preview):
    return reconciliation.apply_source_discovery_tenderplan_no_dispatch_reconciliation(
        **arguments, expected_preview_sha256=preview["preview_sha256"],
        confirmation=reconciliation.SOURCE_NO_DISPATCH_CONFIRMATION,
    )


def test_preview_is_byte_identical_and_apply_preserves_raw_attempt(tmp_path, monkeypatch):
    path, native_path, arguments = _candidate(tmp_path, monkeypatch)
    before = path.read_bytes(), native_path.read_bytes()
    with sqlite3.connect(path) as reader:
        raw_attempt = reader.execute("SELECT * FROM source_discovery_attempts").fetchall()
    preview = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    assert preview == reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    assert (path.read_bytes(), native_path.read_bytes()) == before
    assert all(value == 0 for value in preview["effects"].values())
    applied = _apply(arguments, preview)
    assert applied["state"] == "APPLIED"
    assert applied["preview_sha256"] == preview["preview_sha256"]
    assert applied["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert applied["control"]["source_reconciliation_gate"] == "ELIGIBLE_FOR_NEW_PROPOSAL"
    assert applied["effects"]["controller_store_write_count"] == 1
    assert applied["effects"]["native_store_write_count"] == 1
    with sqlite3.connect(path) as reader:
        assert reader.execute("SELECT * FROM source_discovery_attempts").fetchall() == raw_attempt
    assert control.source_discovery_status(state_path=path)["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert native.validate_tenderplan_read_only_store(native_path)["active_states"]["UNCERTAIN"] == 1
    assert applied["launch_allowed"] is False
    assert not list(tmp_path.glob("*.sqlite3-*"))


def test_exact_reapply_is_inert_with_current_file_pins(tmp_path, monkeypatch):
    path, native_path, arguments = _candidate(tmp_path, monkeypatch)
    preview = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    _apply(arguments, preview)
    arguments["expected_controller_file_sha256"] = control._file_sha256(path)
    arguments["expected_controller_snapshot_sha256"] = control._digest(
        control.source_discovery_status(state_path=path)["control"])
    arguments["expected_native_file_sha256"] = control._file_sha256(native_path)
    before = path.read_bytes(), native_path.read_bytes()
    result = _apply(arguments, preview)
    assert result["state"] == "ALREADY_APPLIED"
    assert all(value == 0 for value in result["effects"].values())
    assert (path.read_bytes(), native_path.read_bytes()) == before


@pytest.mark.parametrize("fault", [
    "controller_file", "controller_snapshot", "native_file", "preview", "confirmation", "journal",
])
def test_bad_pins_and_confirmation_prevent_both_mutations(tmp_path, monkeypatch, fault):
    path, native_path, arguments = _candidate(tmp_path, monkeypatch)
    preview = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    before = path.read_bytes(), native_path.read_bytes()
    if fault in {"controller_file", "controller_snapshot", "native_file"}:
        arguments["expected_" + fault + "_sha256"] = "0" * 64
    elif fault == "preview":
        preview["preview_sha256"] = "0" * 64
    elif fault == "journal":
        path.with_name(path.name + "-journal").write_bytes(b"untrusted")
    with pytest.raises(control.SourceDiscoveryControlError):
        if fault == "confirmation":
            reconciliation.apply_source_discovery_tenderplan_no_dispatch_reconciliation(
                **arguments, expected_preview_sha256=preview["preview_sha256"], confirmation="yes")
        else:
            _apply(arguments, preview)
    assert (path.read_bytes(), native_path.read_bytes()) == before


def test_crash_between_stores_stays_blocked_and_same_proof_can_finish(tmp_path, monkeypatch):
    path, native_path, arguments = _candidate(tmp_path, monkeypatch)
    preview = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    controller_before = path.read_bytes()
    fault = Mock(side_effect=RuntimeError("simulated crash before controller commit"))
    monkeypatch.setattr(reconciliation, "_before_source_no_dispatch_commit", fault)
    with pytest.raises(RuntimeError):
        _apply(arguments, preview)
    assert path.read_bytes() == controller_before
    assert native.validate_tenderplan_read_only_store(native_path)["active_states"]["UNCERTAIN"] == 1
    assert control.source_discovery_status(state_path=path)["control"]["gate"] == "BLOCKED_UNCERTAIN"
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
    arguments["expected_native_file_sha256"] = control._file_sha256(native_path)
    monkeypatch.setattr(reconciliation, "_before_source_no_dispatch_commit", lambda: None)
    result = _apply(arguments, preview)
    assert result["state"] == "APPLIED"
    assert result["effects"]["native_store_write_count"] == 0
    assert result["effects"]["controller_store_write_count"] == 1


def test_attempt_mutation_cannot_be_admitted_with_new_caller_supplied_pins(tmp_path, monkeypatch):
    path, native_path, arguments = _candidate(tmp_path, monkeypatch)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE source_discovery_attempts SET finished_at_utc=?",
                           ("2026-08-28T22:00:03Z",))
    arguments["expected_controller_file_sha256"] = control._file_sha256(path)
    arguments["expected_controller_snapshot_sha256"] = control._digest(
        control.source_discovery_status(state_path=path)["control"])
    before = path.read_bytes(), native_path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    assert (path.read_bytes(), native_path.read_bytes()) == before
