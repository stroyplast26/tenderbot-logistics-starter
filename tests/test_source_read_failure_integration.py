"""Cross-store acknowledgement cannot authorize a read or hide a new failure."""

from __future__ import annotations

import copy
import hashlib
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import source_discovery_read_failure_context as context
from lead_factory import tenderplan_read_failure_ack as ack
from lead_factory import tenderplan_read_only_intake as intake
from lead_factory import tenderplan_read_only_store as native
from tests.test_source_no_dispatch_control import make_scoped_fixture, _check, _reserve_kwargs
from tests.test_lead_factory_tenderplan_account_transition_store import NOW, _claim, _new_intent


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external action forbidden"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    yield forbidden
    forbidden.assert_not_called()


def make_failure_context(tmp_path, monkeypatch):
    path, queue, old_scope, applied, _ = make_scoped_fixture(tmp_path, monkeypatch)
    check = _check(path, queue, old_scope)
    attempt_id, blocked = control._reserve(
        path, control.SourceDiscoverySource.TENDERPLAN, 1,
        **_reserve_kwargs(path, queue, old_scope, check),
    )
    assert blocked is None
    store = native.TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    intent = _new_intent("tpri_" + attempt_id[3:], store._account_transition["active_connection"])
    old_native_pin = applied["no_dispatch_admission_set_sha256"]
    store.reserve_intent(intent, expected_no_dispatch_admission_set_sha256=old_native_pin)
    _claim(queue, intent)
    store.record_terminal(intent["run_id"], "UNCERTAIN")
    control._finish(path, attempt_id, "UNCERTAIN", 0)
    with sqlite3.connect(path) as reader:
        reader.row_factory = sqlite3.Row
        attempts = [dict(row) for row in reader.execute("SELECT * FROM source_discovery_attempts ORDER BY sequence")]
    attempt = next(row for row in attempts if row["attempt_id"] == attempt_id)
    with store._transaction(write=False) as connection:
        record = ack.build_read_failure_acknowledgement(
            connection, store, attempt_id=attempt_id,
            controller_attempt_sha256=control._digest(control._controller_attempt_body(attempt)),
            owner_grant_capture_sha256="2" * 64, accepted_execution_evidence_sha256="3" * 64,
            terminal_sha256="4" * 64, diagnostic_record_sha256="5" * 64,
        )
    native_pin = ack.write_read_failure_ack_set(native_path=queue, acknowledgements=(record,))
    pins = {"expected_controller_file_sha256": control._file_sha256(path),
            "expected_native_store_file_sha256": control._file_sha256(queue)}
    document = context.build_source_read_failure_context(
        controller_path=path, native_store_path=queue, legacy_source_reconciliation_set_sha256=old_scope,
        native_ack_set_sha256=native_pin, acknowledgements=(record,), controller_attempts=attempts, **pins,
    )
    published = context.write_source_read_failure_context(
        context=document, controller_path=path, native_store_path=queue, **pins,
    )
    return path, queue, old_scope, old_native_pin, native_pin, published["context_sha256"], document, attempts


def test_exact_context_preserves_history_and_default_gate(tmp_path, monkeypatch):
    path, queue, old_scope, old_native, native_pin, scope, _, original = make_failure_context(tmp_path, monkeypatch)
    before = path.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError, match="CONTROL_RECONCILIATION_REQUIRED"):
        _check(path, queue, old_scope)
    assert control.check_source_discovery("YANDEX", state_path=path)["state"] == "BLOCKED_UNCERTAIN"
    check = _check(path, queue, scope)
    assert check["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    scoped = check["control"]
    assert scoped["uncertain_count"] == 2
    assert scoped["reconciled_uncertain_count"] == scoped["acknowledged_read_failure_count"] == 1
    assert scoped["blocking_uncertain_count"] == 0 and scoped["gate"] == "BLOCKED_UNCERTAIN"
    assert check["tenderplan_no_dispatch_admission_set_sha256"] == old_native
    assert check["tenderplan_read_failure_ack_set_sha256"] == native_pin
    assert all(check[key] is False for key in ("launch_allowed", "retry_eligible", "authority_verified", "authorizes_live"))
    assert (path.read_bytes(), queue.read_bytes()) == before
    with sqlite3.connect(path) as reader:
        reader.row_factory = sqlite3.Row
        assert [dict(row) for row in reader.execute("SELECT * FROM source_discovery_attempts ORDER BY sequence")] == original


@pytest.mark.parametrize("source", [control.SourceDiscoverySource.YANDEX, control.SourceDiscoverySource.TENDERPLAN])
def test_context_allows_one_new_reservation_and_new_failure_blocks(tmp_path, monkeypatch, source):
    path, queue, _, _, _, scope, _, original = make_failure_context(tmp_path, monkeypatch)
    check = _check(path, queue, scope)
    attempt, blocked = control._reserve(path, source, 1, **_reserve_kwargs(path, queue, scope, check))
    assert blocked is None and attempt not in {row["attempt_id"] for row in original}
    assert _check(path, queue, scope)["state"] == "BLOCKED_IN_FLIGHT"
    assert control.check_source_discovery("YANDEX", state_path=path)["state"] == "BLOCKED_UNCERTAIN"
    current = _check(path, queue, scope)
    assert control._reserve(path, source, 1, **_reserve_kwargs(path, queue, scope, current)) == (None, "BLOCKED_IN_FLIGHT")
    control._finish(path, attempt, "UNCERTAIN", 0)
    current = _check(path, queue, scope)
    assert current["state"] == "BLOCKED_UNCERTAIN"
    assert current["control"]["uncertain_count"] == 3
    assert current["control"]["acknowledged_read_failure_count"] == 1
    assert current["control"]["blocking_uncertain_count"] == 1
    assert control._reserve(path, source, 1, **_reserve_kwargs(path, queue, scope, current)) == (None, "BLOCKED_UNCERTAIN")


@pytest.mark.parametrize("mutation", ["missing_context", "missing_ack", "bad_ref", "bad_legacy", "native_identity"])
def test_missing_or_cross_bound_artifacts_block_before_reservation(tmp_path, monkeypatch, mutation):
    path, queue, _, _, native_pin, scope, document, _ = make_failure_context(tmp_path, monkeypatch)
    if mutation == "missing_context":
        context.source_read_failure_context_path(controller_path=path, expected_source_reconciliation_set_sha256=scope).unlink()
    elif mutation == "missing_ack":
        ack.read_failure_ack_set_path(queue, native_pin).unlink()
    else:
        changed = copy.deepcopy(document)
        if mutation == "bad_ref":
            changed["acknowledgements"][0]["native_ack_record_sha256"] = "f" * 64
        elif mutation == "bad_legacy":
            changed["legacy_source_reconciliation_set_sha256"] = "f" * 64
        else:
            changed["native_store_identity_sha256"] = "f" * 64
        scope = context.write_source_read_failure_context(
            context=changed, controller_path=path, native_store_path=queue,
            expected_controller_file_sha256=control._file_sha256(path),
            expected_native_store_file_sha256=control._file_sha256(queue),
        )["context_sha256"]
    before = path.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _check(path, queue, scope)
    assert (path.read_bytes(), queue.read_bytes()) == before


def test_controller_passes_only_fenced_ack_pin_to_intake(tmp_path, monkeypatch):
    path, queue, _, old_native, native_pin, scope, _, _ = make_failure_context(tmp_path, monkeypatch)
    checker = Mock(return_value={"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK"})
    runner = Mock(side_effect=RuntimeError("synthetic provider boundary"))
    monkeypatch.setattr(control, "check_tenderplan_read_only_intake", checker)
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", runner)
    check = _check(path, queue, scope, "TENDERPLAN")
    assert checker.call_args.kwargs["expected_read_failure_ack_set_sha256"] == native_pin
    result = control.run_source_discovery_once(
        "TENDERPLAN", state_path=path, confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        **_reserve_kwargs(path, queue, scope, check),
    )
    assert result["state"] == "UNCERTAIN" and result["native_runner_call_count"] == 1
    assert runner.call_args.kwargs["expected_read_failure_ack_set_sha256"] == native_pin
    assert runner.call_args.kwargs["expected_no_dispatch_admission_set_sha256"] == old_native
    assert _check(path, queue, scope)["state"] == "BLOCKED_UNCERTAIN"


def test_real_native_check_requires_both_pins_and_preserves_raw_states(tmp_path, monkeypatch):
    path, queue, _, old_native, native_pin, _, _, _ = make_failure_context(tmp_path, monkeypatch)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(intake, "_verified_account_registration", lambda _path: ("synthetic", "a" * 64, "b" * 64))
    before = hashlib.sha256(queue.read_bytes()).hexdigest()
    for options in ({}, {"expected_no_dispatch_admission_set_sha256": old_native},
                    {"expected_read_failure_ack_set_sha256": native_pin}):
        assert intake.check_tenderplan_read_only_intake(store_path=queue, **options)["state"] == "BLOCKED_TENDERPLAN_UNCERTAIN"
    checked = intake.check_tenderplan_read_only_intake(
        store_path=queue, expected_no_dispatch_admission_set_sha256=old_native,
        expected_read_failure_ack_set_sha256=native_pin,
    )
    assert checked["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert checked["states"]["UNCERTAIN"] == 3 and checked["active_states"]["UNCERTAIN"] == 2
    assert checked["no_dispatch_admission_states"]["UNCERTAIN"] == 1
    assert checked["read_failure_ack_states"]["UNCERTAIN"] == 0
    assert hashlib.sha256(queue.read_bytes()).hexdigest() == before


def test_ack_disappearing_after_check_cannot_reserve(tmp_path, monkeypatch):
    path, queue, _, _, native_pin, scope, _, _ = make_failure_context(tmp_path, monkeypatch)
    checked = _check(path, queue, scope)
    ack.read_failure_ack_set_path(queue, native_pin).unlink()
    before = path.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control._reserve(path, control.SourceDiscoverySource.TENDERPLAN, 1,
                         **_reserve_kwargs(path, queue, scope, checked))
    assert (path.read_bytes(), queue.read_bytes()) == before


def test_intake_reservation_rechecks_ack_before_transport(tmp_path, monkeypatch):
    queue = tmp_path / "absent.sqlite3"
    monkeypatch.setattr(intake, "_verified_account_registration", lambda _path: None)
    monkeypatch.setattr(intake, "_verified_registration_safe", lambda _path: ("authref_" + "a" * 32, "b" * 64))
    store = Mock()
    store.reserve_intent.side_effect = native.TenderPlanReadOnlyStoreReconciliationRequired
    monkeypatch.setattr(intake, "_existing_store", Mock(return_value=store))
    transport = Mock(side_effect=AssertionError("must not construct transport"))
    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", transport)
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "synthetic aluminium windows", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=True, clock=lambda: NOW,
            expected_no_dispatch_admission_set_sha256="a" * 64,
            expected_read_failure_ack_set_sha256="b" * 64,
        )
    assert store.reserve_intent.call_args.kwargs["expected_read_failure_ack_set_sha256"] == "b" * 64
    transport.assert_not_called()
    assert not queue.exists()
