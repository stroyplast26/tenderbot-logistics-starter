"""Synthetic operator acknowledgement and native admission, without effects."""

from __future__ import annotations

import copy
import gc
import hashlib
import os
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_read_failure_ack as ack
from lead_factory import tenderplan_read_only_store as native
from tests.test_lead_factory_tenderplan_account_transition_store import NOW, _claim, _new_intent
from tests.test_lead_factory_tenderplan_no_dispatch_admission import make_admission_fixture


RUN_ID = "tpri_" + "7" * 32
ATTEMPT_ID = "sd_" + "7" * 32


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("synthetic-only boundary"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    yield
    forbidden.assert_not_called()


def make_ack_fixture(tmp_path, monkeypatch):
    queue, arguments, account, _ = make_admission_fixture(tmp_path, monkeypatch)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    applied = native.apply_tenderplan_no_dispatch_admission(
        **arguments, expected_preview_sha256=preview["preview_sha256"],
        confirmation=native.TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
    )
    no_dispatch_pin = applied["no_dispatch_admission_set_sha256"]
    store = native.TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    intent = _new_intent(RUN_ID, account)
    store.reserve_intent(intent, expected_no_dispatch_admission_set_sha256=no_dispatch_pin)
    _claim(queue, intent)
    store.record_terminal(RUN_ID, "UNCERTAIN")
    with store._transaction(write=True) as connection:
        record = ack.build_read_failure_acknowledgement(
            connection, store, attempt_id=ATTEMPT_ID,
            controller_attempt_sha256="1" * 64, owner_grant_capture_sha256="2" * 64,
            accepted_execution_evidence_sha256="3" * 64,
            terminal_sha256="4" * 64, diagnostic_record_sha256="5" * 64,
        )
    return queue, store, account, no_dispatch_pin, record


def _write(queue, record):
    return ack.write_read_failure_ack_set(native_path=queue, acknowledgements=(record,))


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
def test_exact_ack_preserves_raw_history_and_requires_both_explicit_pins(tmp_path, monkeypatch):
    queue, store, account, old_pin, record = make_ack_fixture(tmp_path, monkeypatch)
    before = queue.read_bytes()
    raw = native.validate_tenderplan_read_only_store(queue)
    new_pin = _write(queue, record)
    assert _write(queue, record) == new_pin
    assert queue.read_bytes() == before
    assert raw == native.validate_tenderplan_read_only_store(queue)
    assert raw["states"]["UNCERTAIN"] == 3 and raw["active_states"]["UNCERTAIN"] == 2
    assert "read_failure_ack_states" not in raw
    result = native.validate_tenderplan_read_only_store(
        queue, expected_no_dispatch_admission_set_sha256=old_pin,
        expected_read_failure_ack_set_sha256=new_pin,
    )
    assert result["states"] == raw["states"]
    assert result["active_states"] == raw["active_states"]
    assert result["no_dispatch_admission_states"]["UNCERTAIN"] == 1
    assert result["read_failure_ack_states"]["UNCERTAIN"] == 0
    assert result["acknowledged_read_failure_count"] == 1
    assert result["read_failure_acknowledgements"] == (record,)
    assert record["raw_credential_read_count"] is record["raw_provider_request_count"] is None
    assert all(record[key] is False for key in ack._FALSE)
    intent = _new_intent("tpri_" + "8" * 32, account)
    for pins in ({}, {"expected_no_dispatch_admission_set_sha256": old_pin},
                 {"expected_read_failure_ack_set_sha256": new_pin}):
        with pytest.raises(native.TenderPlanReadOnlyStoreReconciliationRequired):
            store.reserve_intent(intent, **pins)
        assert queue.read_bytes() == before
    assert store.reserve_intent(
        intent, expected_no_dispatch_admission_set_sha256=old_pin,
        expected_read_failure_ack_set_sha256=new_pin,
    ).created
    with pytest.raises(native.TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(intent, expected_no_dispatch_admission_set_sha256=old_pin,
                             expected_read_failure_ack_set_sha256=new_pin)
    _claim(queue, intent)
    store.record_terminal(intent["run_id"], "UNCERTAIN")
    after = queue.read_bytes()
    with pytest.raises(native.TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(_new_intent("tpri_" + "9" * 32, account),
                             expected_no_dispatch_admission_set_sha256=old_pin,
                             expected_read_failure_ack_set_sha256=new_pin)
    assert queue.read_bytes() == after
    current = native.validate_tenderplan_read_only_store(
        queue, expected_no_dispatch_admission_set_sha256=old_pin,
        expected_read_failure_ack_set_sha256=new_pin,
    )
    assert current["read_failure_ack_states"]["UNCERTAIN"] == 1


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
def test_mixed_fence_holds_artifact_against_write_delete_and_replace(tmp_path, monkeypatch):
    queue, _, _, old_pin, record = make_ack_fixture(tmp_path, monkeypatch)
    new_pin = _write(queue, record)
    path = ack.read_failure_ack_set_path(queue, new_pin)
    source = tmp_path / "replacement.json"
    source.write_bytes(path.read_bytes())
    before = {queue: queue.read_bytes(), path: path.read_bytes()}
    with native.fence_tenderplan_reconciled_bindings(
        queue, failed_closed_run_ids=(), expected_no_dispatch_admission_set_sha256=old_pin,
        expected_file_sha256=_sha(queue), expected_read_failure_ack_set_sha256=new_pin,
    ) as scope:
        assert scope["read_failure_acknowledgements"] == (record,)
        assert scope["read_failure_ack_set_sha256"] == new_pin
        for action in (lambda: path.write_bytes(b"replacement"), path.unlink,
                       lambda: os.replace(source, path)):
            with pytest.raises(OSError):
                action()
    assert {path: path.read_bytes() for path in before} == before
    with path.open("r+b"), pytest.raises(native.TenderPlanReadOnlyStoreReconciliationRequired):
        with native.fence_tenderplan_reconciled_bindings(
            queue, failed_closed_run_ids=(), expected_no_dispatch_admission_set_sha256=old_pin,
            expected_file_sha256=_sha(queue), expected_read_failure_ack_set_sha256=new_pin,
        ):
            pytest.fail("an already open writer must be rejected")


@pytest.mark.parametrize("field,value", [
    ("state", "PROVEN_NO_DISPATCH"), ("raw_provider_request_count", 0),
    ("retry_eligible", True), ("intent_request_count", True), ("maximum_records", 6),
    ("owner_grant_capture_sha256", "private grant text"), ("run_id", "tpri_" + "8" * 32),
])
def test_typed_ack_cannot_relabel_uncertainty_or_carry_raw_material(tmp_path, monkeypatch, field, value):
    _, _, _, _, record = make_ack_fixture(tmp_path, monkeypatch)
    record[field] = value
    record["record_sha256"] = ack._digest({k: v for k, v in record.items() if k != "record_sha256"})
    with pytest.raises(ack.TenderPlanReadFailureAcknowledgementError):
        ack.validate_read_failure_acknowledgement(record)


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
@pytest.mark.parametrize("fault", ["missing", "tamper", "hardlink", "symlink", "wrong_pin"])
def test_bad_artifact_never_changes_native_or_admits_next_run(tmp_path, monkeypatch, fault):
    queue, store, account, old_pin, record = make_ack_fixture(tmp_path, monkeypatch)
    new_pin = _write(queue, record)
    path = ack.read_failure_ack_set_path(queue, new_pin)
    if fault == "missing":
        path.unlink()
    elif fault == "tamper":
        path.write_bytes(path.read_bytes() + b" ")
    elif fault == "hardlink":
        os.link(path, tmp_path / "hardlink.json")
    elif fault == "symlink":
        other = tmp_path / "other.json"
        other.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(other)
        except OSError:
            pytest.skip("symlinks unavailable")
    else:
        new_pin = "f" * 64
    before = queue.read_bytes()
    with pytest.raises(native.TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(_new_intent("tpri_" + "8" * 32, account),
                             expected_no_dispatch_admission_set_sha256=old_pin,
                             expected_read_failure_ack_set_sha256=new_pin)
    assert queue.read_bytes() == before


def test_no_dispatch_or_failed_closed_is_not_a_claimed_failure_ack(tmp_path, monkeypatch):
    queue, store, account, _, record = make_ack_fixture(tmp_path, monkeypatch)
    with store._transaction(write=True) as connection:
        for attempt in ("sd_" + "1" * 32, "sd_" + "3" * 32):
            with pytest.raises(ack.TenderPlanReadFailureAcknowledgementError):
                ack.build_read_failure_acknowledgement(
                    connection, store, attempt_id=attempt,
                    **{key: record[key] for key in (
                        "controller_attempt_sha256", "owner_grant_capture_sha256",
                        "accepted_execution_evidence_sha256", "terminal_sha256", "diagnostic_record_sha256",
                    )},
                )
    assert native.validate_tenderplan_read_only_store(queue)["active_states"]["UNCERTAIN"] == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
def test_resealed_foreign_native_material_is_rejected_before_create(tmp_path, monkeypatch):
    queue, _, _, _, record = make_ack_fixture(tmp_path, monkeypatch)
    before = queue.read_bytes()
    for field in ("request_sha256", "dispatch_claim_event_sha256", "operation_sha256"):
        wrong = copy.deepcopy(record)
        wrong[field] = "f" * 64
        wrong["record_sha256"] = ack._digest({k: v for k, v in wrong.items() if k != "record_sha256"})
        with pytest.raises(ack.TenderPlanReadFailureAcknowledgementError):
            _write(queue, wrong)
    assert not list(tmp_path.glob("tenderplan_read_failure_ack.*.json"))
    assert queue.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
def test_missing_native_is_never_recreated_by_acknowledged_reserve(tmp_path, monkeypatch):
    queue, store, account, old_pin, record = make_ack_fixture(tmp_path, monkeypatch)
    new_pin = _write(queue, record)
    # Shared legacy fixture uses sqlite context managers which leave their
    # connection objects for collection; release those test-only descriptors.
    gc.collect()
    queue.unlink()
    with pytest.raises((sqlite3.Error, native.TenderPlanReadOnlyStoreError)):
        store.reserve_intent(_new_intent("tpri_" + "8" * 32, account),
                             expected_no_dispatch_admission_set_sha256=old_pin,
                             expected_read_failure_ack_set_sha256=new_pin)
    assert not queue.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
def test_artifact_is_still_locked_during_native_commit_validation(tmp_path, monkeypatch):
    queue, store, account, old_pin, record = make_ack_fixture(tmp_path, monkeypatch)
    new_pin = _write(queue, record)
    path = ack.read_failure_ack_set_path(queue, new_pin)
    original = store._verify_locked
    observed = []

    def check_lock(connection):
        original(connection)
        if connection.execute("SELECT COUNT(*) FROM tenderplan_read_only_operations").fetchone()[0] == 4:
            with pytest.raises(OSError):
                path.write_bytes(b"late replacement")
            observed.append(True)

    monkeypatch.setattr(store, "_verify_locked", check_lock)
    assert store.reserve_intent(_new_intent("tpri_" + "8" * 32, account),
                                expected_no_dispatch_admission_set_sha256=old_pin,
                                expected_read_failure_ack_set_sha256=new_pin).created
    assert observed


@pytest.mark.skipif(os.name != "nt", reason="Windows immutable acknowledgement handle")
def test_partial_artifact_is_not_overwritten_and_duplicate_runs_are_rejected(tmp_path, monkeypatch):
    queue, _, _, _, record = make_ack_fixture(tmp_path, monkeypatch)
    material = ack._set_material(queue, (record,))
    digest = ack._digest(material)
    path = ack.read_failure_ack_set_path(queue, digest)
    path.write_bytes(b'{"incomplete":')
    before = {queue: queue.read_bytes(), path: path.read_bytes()}
    with pytest.raises(ack.TenderPlanReadFailureAcknowledgementError):
        _write(queue, record)
    with pytest.raises(ack.TenderPlanReadFailureAcknowledgementError):
        ack.write_read_failure_ack_set(native_path=queue, acknowledgements=(record, record))
    assert {path: path.read_bytes() for path in before} == before
