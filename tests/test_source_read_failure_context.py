"""Context admission metadata only; every database/evidence input is synthetic."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_read_failure_context as context
from lead_factory import tenderplan_read_failure_ack as ack
from lead_factory.source_discovery_control import _controller_attempt_body, _digest


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("synthetic-only boundary"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    yield
    forbidden.assert_not_called()


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row():
    return {
        "sequence": 3, "attempt_id": "sd_" + "7" * 32,
        "source": "TENDERPLAN", "state": "UNCERTAIN",
        "started_at_utc": "2026-09-14T16:14:00Z",
        "finished_at_utc": "2026-09-14T16:15:00Z",
        "review_count": 0, "tenderplan_binding_required": 1,
    }


def _fixture(tmp_path):
    controller, native = tmp_path / "controller.sqlite3", tmp_path / "native.sqlite3"
    controller.write_bytes(b"synthetic controller unchanged")
    native.write_bytes(b"synthetic native unchanged")
    row = _row()
    record = {
        "schema": ack.ACK_PROTOCOL, "state": "ACKNOWLEDGED_READ_ONLY_UNCERTAIN",
        **dict.fromkeys(ack._HASH_FIELDS, "1" * 64),
        "attempt_id": row["attempt_id"], "run_id": "tpri_" + row["attempt_id"][3:],
        "controller_attempt_sha256": _digest(_controller_attempt_body(row)),
        "native_path_sha256": context._path_digest(native),
        **ack._FALSE, "raw_credential_read_count": None, "raw_provider_request_count": None,
        "intent_request_count": 1, "write_count": 0, "contact_count": 0,
        "spend_minor": 0, "card_count": 0, "decision_count": 0,
        "maximum_records": 5, "maximum_response_bytes": 1048576,
    }
    record["record_sha256"] = ack._digest(record)
    arguments = {
        "controller_path": controller, "native_store_path": native,
        "legacy_source_reconciliation_set_sha256": "2" * 64,
        "native_ack_set_sha256": ack._digest(ack._set_material(native, (record,))),
        "acknowledgements": (record,), "controller_attempts": [row],
        "expected_controller_file_sha256": _sha(controller),
        "expected_native_store_file_sha256": _sha(native),
    }
    return arguments, record


def _write(arguments, material=None):
    return context.write_source_read_failure_context(
        context=material or context.build_source_read_failure_context(**arguments),
        **{key: arguments[key] for key in (
            "controller_path", "native_store_path", "expected_controller_file_sha256",
            "expected_native_store_file_sha256",
        )},
    )


def _fence(arguments, digest):
    return context.fence_source_read_failure_context(
        controller_path=arguments["controller_path"], native_store_path=arguments["native_store_path"],
        controller_attempts=arguments["controller_attempts"], expected_source_reconciliation_set_sha256=digest,
    )


def test_exact_context_replay_pins_and_legacy_absence_leave_history_unchanged(tmp_path):
    arguments, record = _fixture(tmp_path)
    material = context.build_source_read_failure_context(**arguments)
    assert material["acknowledgements"] == [{
        "attempt_id": record["attempt_id"], "run_id": record["run_id"],
        "controller_attempt_sha256": record["controller_attempt_sha256"],
        "native_ack_record_sha256": record["record_sha256"],
        "proof_sha256": record["accepted_execution_evidence_sha256"],
    }]
    before = {arguments[key]: arguments[key].read_bytes() for key in ("controller_path", "native_store_path")}
    with _fence(arguments, arguments["legacy_source_reconciliation_set_sha256"]) as absent:
        assert absent is None
    assert len(list(tmp_path.iterdir())) == 2
    first = _write(arguments, material)
    saved = Path(first["context_path"]).read_bytes()
    second = _write(arguments, material)
    assert first["created"] is True and second["created"] is False
    assert first["context_sha256"] == _sha(Path(first["context_path"]))
    assert Path(first["context_path"]).read_bytes() == saved
    with _fence(arguments, first["context_sha256"]) as loaded:
        assert loaded == material
        assert all(loaded[key] is False for key in context._FALSE)
    assert {path: path.read_bytes() for path in before} == before
    assert arguments["controller_attempts"][0]["state"] == "UNCERTAIN"
    assert record["raw_provider_request_count"] is None


@pytest.mark.parametrize("field,value", [
    ("state", "FAILED_CLOSED"), ("source", "YANDEX_SEARCH"), ("review_count", 1),
    ("tenderplan_binding_required", 0), ("sequence", True), ("sequence", 4),
    ("finished_at_utc", None), ("finished_at_utc", "2026-02-30T16:15:00Z"),
    ("attempt_id", "sd_" + "8" * 32),
])
def test_current_controller_attempt_must_match_exact_uncertain_digest(tmp_path, field, value):
    arguments, _ = _fixture(tmp_path)
    receipt = _write(arguments)
    arguments["controller_attempts"][0][field] = value
    with pytest.raises(context.SourceReadFailureContextError):
        with _fence(arguments, receipt["context_sha256"]):
            pytest.fail("mismatched old attempt admitted")


def test_duplicate_or_missing_actual_attempt_rejected(tmp_path):
    arguments, _ = _fixture(tmp_path)
    receipt = _write(arguments)
    row = arguments["controller_attempts"][0]
    for rows in ([], [row, row]):
        arguments["controller_attempts"] = rows
        with pytest.raises(context.SourceReadFailureContextError):
            with _fence(arguments, receipt["context_sha256"]):
                pytest.fail("ambiguous attempt admitted")


@pytest.mark.parametrize("key", ["expected_controller_file_sha256", "expected_native_store_file_sha256",
                                 "native_ack_set_sha256"])
def test_build_checks_current_file_and_native_set_pins(tmp_path, key):
    arguments, _ = _fixture(tmp_path)
    arguments[key] = "f" * 64
    with pytest.raises(context.SourceReadFailureContextError):
        context.build_source_read_failure_context(**arguments)


def test_write_rechecks_current_file_pins_and_read_keeps_initial_hash_audit_only(tmp_path):
    arguments, _ = _fixture(tmp_path)
    material = context.build_source_read_failure_context(**arguments)
    receipt = _write(arguments, material)
    for key in ("controller_path", "native_store_path"):
        with arguments[key].open("ab") as file:
            file.write(b"later legitimate operation changes bytes but not old rows")
    with pytest.raises(context.SourceReadFailureContextError):
        _write(arguments, material)
    with _fence(arguments, receipt["context_sha256"]) as loaded:
        assert loaded == material


@pytest.mark.parametrize("key", ["controller_path", "native_store_path"])
def test_replaced_database_same_bytes_is_not_same_identity(tmp_path, key):
    arguments, _ = _fixture(tmp_path)
    receipt = _write(arguments)
    path = arguments[key]
    replacement = tmp_path / "replacement.sqlite3"
    replacement.write_bytes(path.read_bytes())
    os.replace(replacement, path)
    with pytest.raises(context.SourceReadFailureContextError):
        with _fence(arguments, receipt["context_sha256"]):
            pytest.fail("replaced store admitted")


def test_context_handle_blocks_write_delete_replace_and_existing_writer(tmp_path):
    arguments, _ = _fixture(tmp_path)
    receipt = _write(arguments)
    path = Path(receipt["context_path"])
    replacement = tmp_path / "replace.json"
    replacement.write_bytes(path.read_bytes())
    with _fence(arguments, receipt["context_sha256"]):
        for action in (lambda: path.write_bytes(b"tamper"), path.unlink,
                       lambda: os.replace(replacement, path)):
            with pytest.raises(OSError):
                action()
    with path.open("r+b"):
        with pytest.raises(context.SourceReadFailureContextError):
            with _fence(arguments, receipt["context_sha256"]):
                pytest.fail("existing writer admitted")


@pytest.mark.parametrize("fault", ["tamper", "hardlink", "directory", "noncanonical", "unknown_key",
                                  "false_flag", "cross_run", "duplicate_ref"])
def test_present_invalid_context_never_falls_back_to_legacy(tmp_path, fault):
    arguments, _ = _fixture(tmp_path)
    receipt = _write(arguments)
    path, digest = Path(receipt["context_path"]), receipt["context_sha256"]
    if fault == "hardlink":
        os.link(path, tmp_path / "hardlink.json")
    elif fault == "directory":
        path.unlink()
        path.mkdir()
    elif fault == "tamper":
        path.write_bytes(path.read_bytes() + b" ")
    else:
        material = json.loads(path.read_bytes())
        if fault == "unknown_key":
            material["raw_provider_body"] = "SENTINEL-SECRET-RAW"
        elif fault == "false_flag":
            material["launch_allowed"] = True
        elif fault == "cross_run":
            material["acknowledgements"][0]["run_id"] = "tpri_" + "8" * 32
        elif fault == "duplicate_ref":
            material["acknowledgements"] *= 2
        raw = json.dumps(material, indent=2).encode() if fault == "noncanonical" else context._canonical(material)
        digest = hashlib.sha256(raw).hexdigest()
        path = context.source_read_failure_context_path(
            controller_path=arguments["controller_path"], expected_source_reconciliation_set_sha256=digest)
        path.write_bytes(raw)
    with pytest.raises(context.SourceReadFailureContextError) as failure:
        with _fence(arguments, digest):
            pytest.fail("corrupt context admitted")
    assert "SENTINEL" not in str(failure.value)


def test_foreign_native_ack_or_forged_record_cannot_build_context(tmp_path):
    arguments, record = _fixture(tmp_path)
    for key, value in (("native_path_sha256", "f" * 64),
                       ("controller_attempt_sha256", "f" * 64),
                       ("accepted_execution_evidence_sha256", "raw-secret-evidence")):
        changed = copy.deepcopy(record)
        changed[key] = value
        changed["record_sha256"] = ack._digest({k: v for k, v in changed.items() if k != "record_sha256"})
        arguments["acknowledgements"] = (changed,)
        with pytest.raises((context.SourceReadFailureContextError, ack.TenderPlanReadFailureAcknowledgementError)):
            context.build_source_read_failure_context(**arguments)


def test_unreadable_present_context_does_not_mean_absent(tmp_path, monkeypatch):
    arguments, _ = _fixture(tmp_path)
    receipt = _write(arguments)
    monkeypatch.setattr(context, "_held_bytes", Mock(side_effect=PermissionError("raw-secret-path")))
    with pytest.raises(context.SourceReadFailureContextError, match="^source_read_failure_context_invalid$"):
        with _fence(arguments, receipt["context_sha256"]):
            pytest.fail("unreadable treated as absent")
