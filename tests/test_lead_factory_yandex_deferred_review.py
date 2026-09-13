"""Independent offline regressions for explicit, evidence-bound review deferral."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import sqlite3
from threading import Barrier
from unittest.mock import Mock, patch

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_read_only_intake as intake
from lead_factory import tenderplan_windows_credential as credentials
from lead_factory.radar_yandex_source_lab_bridge import (
    YandexSourceLabBridgeError,
    list_yandex_review_batch,
    persist_yandex_review_batch,
)
from lead_factory.source_review_queue import SourceReviewQueue
from lead_factory.tenderplan_read_only_store import TenderPlanReadOnlyStore
from tests.test_lead_factory_source_discovery_review_control import (
    _controller_review_page,
    _decide_review_item,
    _run_yandex_review_batch,
)
from tests.test_lead_factory_tenderplan_read_only_intake import (
    NOW,
    _registration,
    _success_transport,
)


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external effect reached"))
    monkeypatch.setattr(control, "load_yandex_api_key", forbidden)
    monkeypatch.setattr(control, "run_manual_yandex_search_accounted", forbidden)
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", forbidden)
    monkeypatch.setattr(credentials, "_credential_api", forbidden)
    monkeypatch.setattr(intake.TenderPlanReadOnlyTransport, "post_registered_search", forbidden)
    yield forbidden
    forbidden.assert_not_called()


def _decided_batch(tmp_path, decisions=("APPROVE", "REJECT", "NEEDS_RESEARCH"), *, schema=4):
    state, lab, report = _run_yandex_review_batch(tmp_path, hits=len(decisions))
    assert report["state"] == "READY_FOR_REVIEW"
    if schema == 5:
        control.prepare_source_discovery_tenderplan_bindings(
            state_path=state, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
        )
    items = list_yandex_review_batch(
        attempt_id=report["attempt_id"], source_lab_path=lab,
        expected_receipt_sha256=report["batch_receipt_sha256"],
    )
    for index, (item, decision) in enumerate(zip(items, decisions, strict=True)):
        if decision is not None:
            _decide_review_item(
                report=report, source_lab_path=lab, review_id=item.review_id,
                state_digest=item.state_digest, decision=decision, suffix=f"defer-{index}",
            )
    return state, lab, report


def _preview(state, report):
    return control.preview_source_discovery_review_deferral(
        attempt_id=report["attempt_id"], state_path=state,
    )


def _defer_kwargs(state, report):
    preview = _preview(state, report)
    return {
        "attempt_id": report["attempt_id"], "state_path": state,
        "confirmation": control.SOURCE_DISCOVERY_LOCAL_DEFER_CONFIRMATION,
        "expected_receipt_sha256": preview["batch_receipt_sha256"],
        "expected_decisions_sha256": preview["decisions_sha256"],
        "actor": "operator_1", "reason": "INSUFFICIENT_PUBLIC_EVIDENCE",
        "evidence_ref": "evidence://local-review/defer-incomplete",
        "idempotency_key": "defer_incomplete_batch",
    }


def _table_rows(path):
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        return {
            table: [dict(row) for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')]
            for table in tables
        }


def _assert_existing_rows_unchanged(before, after):
    for table, rows in before.items():
        assert len(after[table]) == len(rows), table
        assert [{key: row[key] for key in old} for row, old in zip(after[table], rows, strict=True)] == rows


def _assert_no_deferrals(path):
    assert _table_rows(path).get("source_discovery_review_deferrals", []) == []


@pytest.mark.parametrize("schema", [4, 5])
def test_defer_527_preserves_history_accounting_and_releases_one_slot(tmp_path, schema):
    state, lab, report = _decided_batch(
        tmp_path, ("APPROVE",) * 5 + ("REJECT",) * 2 + ("NEEDS_RESEARCH",) * 3, schema=schema,
    )
    before_rows, before_lab = _table_rows(state), lab.read_bytes()
    prior_status = control.source_discovery_status(state_path=state)["control"]
    kwargs = _defer_kwargs(state, report)
    result = control.defer_source_discovery_review(**kwargs)
    assert result["state"] == "DEFERRED_LOCAL" and result["created"] is True
    assert result["decision_counts"] == {"APPROVE": 5, "REJECT": 2, "NEEDS_RESEARCH": 3}
    assert len(result["unresolved_review_ids"]) == 3
    assert result["control"]["gate"] == "READY"
    assert result["control"]["open_review_batches"] == 0
    assert result["control"]["closed_review_batches"] == 0
    assert result["control"]["deferred_review_batches"] == 1
    assert result["control"]["latest"]["state"] == "DEFERRED_LOCAL"
    assert result["control"]["latest"]["review_count"] == 10
    assert result["control"]["latest"]["yandex_reconciliation"] == prior_status["latest"]["yandex_reconciliation"]
    for key in ("provider_read_may_be_metered", "crm_write_enabled", "automatic_schedule_eligible", "contact_enabled"):
        assert result["effects"][key] is False
    assert lab.read_bytes() == before_lab
    after_rows = _table_rows(state)
    _assert_existing_rows_unchanged(before_rows, after_rows)
    assert after_rows["source_discovery_attempts"][0]["state"] == "READY_FOR_REVIEW"
    assert len(after_rows["source_discovery_review_deferrals"]) == 1
    assert after_rows["source_discovery_review_closures"] == []
    assert after_rows["source_discovery_tenderplan_bindings"] == []
    with sqlite3.connect(state) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
    # Exercise the real reservation calculation, with no native/provider launcher.
    next_attempt, blocked = control._reserve(state, control.SourceDiscoverySource.YANDEX, 1)
    assert next_attempt is not None and blocked is None
    second_attempt, second_blocked = control._reserve(state, control.SourceDiscoverySource.YANDEX, 1)
    assert second_attempt is None and second_blocked == "BLOCKED_IN_FLIGHT"
    assert lab.read_bytes() == before_lab


def test_preview_is_read_only_and_replays(tmp_path):
    state, lab, report = _decided_batch(tmp_path)
    before_state, before_lab = state.read_bytes(), lab.read_bytes()
    first = _preview(state, report)
    assert first["state"] == "READY_TO_DEFER"
    assert first == _preview(state, report)
    assert first["review_count"] == 3
    assert len(first["unresolved_review_ids"]) == 1
    assert state.read_bytes() == before_state and lab.read_bytes() == before_lab
    kwargs = _defer_kwargs(state, report)
    applied = control.defer_source_discovery_review(**kwargs)
    applied_bytes = state.read_bytes()
    replay = control.defer_source_discovery_review(**kwargs)
    assert replay["state"] == "DEFERRED_LOCAL" and replay["created"] is False
    assert replay["deferral_receipt_sha256"] == applied["deferral_receipt_sha256"]
    assert _preview(state, report)["state"] == "DEFERRED_LOCAL"
    assert control.source_discovery_status(state_path=state)["control"] == applied["control"]
    assert state.read_bytes() == applied_bytes and lab.read_bytes() == before_lab


@pytest.mark.parametrize("confirmation", [None, "", "DEFER", "CLOSE_LOCAL_SOURCE_REVIEW_ONLY"])
def test_defer_requires_explicit_confirmation(tmp_path, confirmation):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = {**_defer_kwargs(state, report), "confirmation": confirmation}
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError) as error:
        control.defer_source_discovery_review(**kwargs)
    assert error.value.code == "LOCAL_DEFER_CONFIRMATION_REQUIRED"
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("operation", ["preview", "apply"])
def test_missing_state_is_not_bootstrapped(tmp_path, operation):
    state = tmp_path / "missing" / "controller.sqlite3"
    with pytest.raises(control.SourceDiscoveryControlError):
        if operation == "preview":
            control.preview_source_discovery_review_deferral(attempt_id="sd_" + "a" * 32, state_path=state)
        else:
            control.defer_source_discovery_review(
                attempt_id="sd_" + "a" * 32, state_path=state,
                confirmation=control.SOURCE_DISCOVERY_LOCAL_DEFER_CONFIRMATION,
                expected_receipt_sha256="a" * 64, expected_decisions_sha256="b" * 64,
                actor="operator_1", reason="INSUFFICIENT_PUBLIC_EVIDENCE",
                evidence_ref="evidence://local-review/missing", idempotency_key="missing_store",
            )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("field,value", [
    ("expected_receipt_sha256", "f" * 64), ("expected_decisions_sha256", "f" * 64),
    ("expected_receipt_sha256", ""), ("expected_decisions_sha256", "bad-hash"),
])
def test_wrong_pins_leave_no_mutation(tmp_path, field, value):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = {**_defer_kwargs(state, report), field: value}
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.defer_source_discovery_review(**kwargs)
    assert (state.read_bytes(), lab.read_bytes()) == before


def test_same_decision_with_new_evidence_invalidates_preview_pin(tmp_path):
    state, lab, report = _decided_batch(tmp_path, ("NEEDS_RESEARCH",))
    kwargs = _defer_kwargs(state, report)
    item = list_yandex_review_batch(
        attempt_id=report["attempt_id"], source_lab_path=lab,
        expected_receipt_sha256=report["batch_receipt_sha256"],
    )[0]
    _decide_review_item(
        report=report, source_lab_path=lab, review_id=item.review_id,
        state_digest=item.state_digest, decision="NEEDS_RESEARCH", suffix="new-research-evidence",
    )
    current = _preview(state, report)
    assert current["decisions_sha256"] != kwargs["expected_decisions_sha256"]
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError) as error:
        control.defer_source_discovery_review(**kwargs)
    assert error.value.code == "LOCAL_REVIEW_PIN_MISMATCH"
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("field,value", [
    ("actor", ""), ("reason", ""), ("evidence_ref", ""), ("idempotency_key", ""),
])
def test_audit_identity_is_required_before_mutation(tmp_path, field, value):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = {**_defer_kwargs(state, report), field: value}
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.defer_source_discovery_review(**kwargs)
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("field,value", [
    ("actor", "operator_2"), ("reason", "CHANGED_REASON"),
    ("evidence_ref", "evidence://local-review/another"), ("idempotency_key", "another_deferral"),
])
def test_deferral_replay_conflicts(tmp_path, field, value):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = _defer_kwargs(state, report)
    control.defer_source_discovery_review(**kwargs)
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError) as error:
        control.defer_source_discovery_review(**{**kwargs, field: value})
    assert error.value.code == "LOCAL_REVIEW_DEFER_CONFLICT"
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("decisions", [(None,), ("APPROVE",), ("REJECT",), ("NEEDS_RESEARCH", None)])
def test_unresolved_requires_actual_latest_decision(tmp_path, decisions):
    state, lab, report = _decided_batch(tmp_path, decisions)
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises((control.SourceDiscoveryControlError, YandexSourceLabBridgeError)):
        _preview(state, report)
    assert (state.read_bytes(), lab.read_bytes()) == before


def test_active_claim_is_not_deferrable(tmp_path):
    state, lab, report = _decided_batch(tmp_path, ("NEEDS_RESEARCH",))
    kwargs = _defer_kwargs(state, report)
    item = list_yandex_review_batch(
        attempt_id=report["attempt_id"], source_lab_path=lab,
        expected_receipt_sha256=report["batch_receipt_sha256"],
    )[0]
    with patch.object(SourceReviewQueue, "resolve_claimed", side_effect=RuntimeError("synthetic claim crash")):
        with pytest.raises(YandexSourceLabBridgeError):
            _decide_review_item(
                report=report, source_lab_path=lab, review_id=item.review_id,
                state_digest=item.state_digest, decision="APPROVE", suffix="active-claim",
            )
    before = state.read_bytes(), lab.read_bytes()
    for operation in (_preview, lambda state, report: control.defer_source_discovery_review(**kwargs)):
        with pytest.raises((control.SourceDiscoveryControlError, YandexSourceLabBridgeError)):
            operation(state, report)
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("other_state", ["RUNNING", "UNCERTAIN"])
def test_other_controller_gate_blocks_deferral(tmp_path, other_state):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = _defer_kwargs(state, report)
    with sqlite3.connect(state) as connection:
        connection.execute(
            "INSERT INTO source_discovery_attempts(attempt_id,source,state,started_at_utc) VALUES(?,?,?,?)",
            ("sd_" + "a" * 32, "YANDEX", other_state, "2026-09-13T00:00:00Z"),
        )
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.defer_source_discovery_review(**kwargs)
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("source,attempt_state", [
    ("TENDERPLAN", "READY_FOR_REVIEW"), ("YANDEX", "RUNNING"), ("YANDEX", "UNCERTAIN"),
])
def test_wrong_source_or_nonready_target_is_not_deferrable(tmp_path, source, attempt_state):
    state, lab, _ = _decided_batch(tmp_path)
    target = "sd_" + "c" * 32
    with sqlite3.connect(state) as connection:
        connection.execute(
            "INSERT INTO source_discovery_attempts(attempt_id,source,state,started_at_utc,review_count) VALUES(?,?,?,?,?)",
            (target, source, attempt_state, "2026-09-13T00:00:00Z", int(attempt_state == "READY_FOR_REVIEW")),
        )
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.preview_source_discovery_review_deferral(attempt_id=target, state_path=state)
    assert (state.read_bytes(), lab.read_bytes()) == before


def test_orphan_source_lab_batch_blocks_deferral(tmp_path):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = _defer_kwargs(state, report)
    persist_yandex_review_batch(
        attempt_id="sd_" + "b" * 32, page=_controller_review_page(hits=1), source_lab_path=lab,
    )
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError) as error:
        control.defer_source_discovery_review(**kwargs)
    assert error.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("first", ["close", "defer"])
def test_normal_close_and_defer_exclude_each_other(tmp_path, first):
    decisions = ("APPROVE",) if first == "close" else ("NEEDS_RESEARCH",)
    state, lab, report = _decided_batch(tmp_path, decisions)
    close_kwargs = {
        "attempt_id": report["attempt_id"], "state_path": state,
        "confirmation": control.SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        "actor": "operator_1", "evidence_ref": "evidence://local-review/terminal",
        "idempotency_key": "normal_close",
    }
    if first == "close":
        control.close_source_discovery_review(**close_kwargs)
    else:
        control.defer_source_discovery_review(**_defer_kwargs(state, report))
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises((control.SourceDiscoveryControlError, YandexSourceLabBridgeError)):
        if first == "close":
            _preview(state, report)
        else:
            control.close_source_discovery_review(**close_kwargs)
    assert (state.read_bytes(), lab.read_bytes()) == before
    rows = _table_rows(state)
    assert len(rows["source_discovery_review_closures"]) == (first == "close")
    assert len(rows.get("source_discovery_review_deferrals", [])) == (first == "defer")


def test_deferred_decision_change_blocks_status_and_reserve(tmp_path):
    state, lab, report = _decided_batch(tmp_path, ("NEEDS_RESEARCH",))
    kwargs = _defer_kwargs(state, report)
    control.defer_source_discovery_review(**kwargs)
    item = list_yandex_review_batch(
        attempt_id=report["attempt_id"], source_lab_path=lab,
        expected_receipt_sha256=report["batch_receipt_sha256"],
    )[0]
    _decide_review_item(
        report=report, source_lab_path=lab, review_id=item.review_id,
        state_digest=item.state_digest, decision="APPROVE", suffix="after-defer",
    )
    before = state.read_bytes(), lab.read_bytes()
    operations = (
        lambda: control.source_discovery_status(state_path=state),
        lambda: control._reserve(state, control.SourceDiscoverySource.YANDEX, 1),
        lambda: control.defer_source_discovery_review(**kwargs),
        lambda: control.run_source_discovery_once(
            "YANDEX", state_path=state, confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            yandex_job_path=tmp_path / "never-read.json", folder_id="folder",
        ),
    )
    for operation in operations:
        with pytest.raises(control.SourceDiscoveryControlError) as error:
            operation()
        assert error.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("statement", [
    "UPDATE source_discovery_review_deferrals SET reason='tampered'",
    "DELETE FROM source_discovery_review_deferrals",
])
def test_deferral_receipt_cannot_be_mutated_or_deleted(tmp_path, statement):
    state, lab, report = _decided_batch(tmp_path)
    control.defer_source_discovery_review(**_defer_kwargs(state, report))
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(sqlite3.IntegrityError):
        with sqlite3.connect(state) as connection:
            connection.execute(statement)
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("tamper", ["reason", "manifest", "trigger", "table", "future-version"])
def test_tampered_deferral_fails_closed(tmp_path, tamper):
    state, lab, report = _decided_batch(tmp_path)
    control.defer_source_discovery_review(**_defer_kwargs(state, report))
    with sqlite3.connect(state) as connection:
        if tamper in {"reason", "manifest"}:
            connection.execute("DROP TRIGGER source_discovery_review_deferrals_no_update")
            if tamper == "reason":
                connection.execute("UPDATE source_discovery_review_deferrals SET reason='tampered'")
            else:
                connection.execute("UPDATE source_discovery_review_deferrals SET manifest_json='[]'")
            connection.execute(control._append_only_trigger_sql("source_discovery_review_deferrals", "UPDATE"))
        elif tamper == "trigger":
            connection.execute("DROP TRIGGER source_discovery_review_deferrals_no_update")
        elif tamper == "table":
            connection.execute("DROP TABLE source_discovery_review_deferrals")
        else:
            connection.execute("PRAGMA user_version=999")
    before = state.read_bytes(), lab.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError) as error:
        control.source_discovery_status(state_path=state)
    assert error.value.code == "CONTROL_STATE_INTEGRITY_FAILED"
    with pytest.raises(control.SourceDiscoveryControlError):
        control._reserve(state, control.SourceDiscoverySource.YANDEX, 1)
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("schema", [4, 5])
def test_ddl_failure_rolls_back_entire_migration(tmp_path, monkeypatch, schema):
    state, lab, report = _decided_batch(tmp_path, schema=schema)
    kwargs = _defer_kwargs(state, report)
    before = state.read_bytes(), lab.read_bytes()
    original = control._append_only_trigger_sql

    def invalid_final_trigger(table, operation):
        if table == "source_discovery_review_deferrals" and operation == "DELETE":
            return "INVALID DDL"
        return original(table, operation)

    monkeypatch.setattr(control, "_append_only_trigger_sql", invalid_final_trigger)
    with pytest.raises(control.SourceDiscoveryControlError):
        control.defer_source_discovery_review(**kwargs)
    assert (state.read_bytes(), lab.read_bytes()) == before
    _assert_no_deferrals(state)
    monkeypatch.setattr(control, "_append_only_trigger_sql", original)
    assert control.defer_source_discovery_review(**kwargs)["state"] == "DEFERRED_LOCAL"


def test_simultaneous_apply_creates_one_receipt(tmp_path):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = _defer_kwargs(state, report)
    before_lab = lab.read_bytes()
    barrier = Barrier(2)

    def apply_at_barrier():
        barrier.wait(timeout=10)
        return control.defer_source_discovery_review(**kwargs)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(apply_at_barrier) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert sorted(result["created"] for result in results) == [False, True]
    assert len({result["deferral_receipt_sha256"] for result in results}) == 1
    assert len(_table_rows(state)["source_discovery_review_deferrals"]) == 1
    assert lab.read_bytes() == before_lab


def test_v6_remains_compatible_with_native_tenderplan(tmp_path, monkeypatch):
    state, lab, report = _decided_batch(tmp_path)
    control.defer_source_discovery_review(**_defer_kwargs(state, report))
    before_lab = lab.read_bytes()
    queue, registration = tmp_path / "native.sqlite3", tmp_path / "registration.json"
    _registration(registration)
    TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    fake_type = _success_transport(queue, 0)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(intake, "TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH", registration)
    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", fake_type)
    original = intake.run_tenderplan_read_only_intake

    def local_native(query, **kwargs):
        return original(query, **kwargs, clock=lambda: NOW, transport=fake_type())

    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", local_native)
    result = control.run_source_discovery_once(
        "TENDERPLAN", state_path=state, confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        tenderplan_query="окна", tenderplan_registration_path=registration, tenderplan_store_path=queue,
    )
    assert result["state"] == "COMPLETE_NO_RESULTS"
    assert fake_type.calls == 1
    assert result["control"]["gate"] == "READY"
    assert result["control"]["deferred_review_batches"] == 1
    assert result["control"]["latest"]["tenderplan_binding"]["verification"] == "NATIVE_RECEIPT_VERIFIED_AT_FINALIZATION"
    assert len(_table_rows(state)["source_discovery_tenderplan_bindings"]) == 1
    assert lab.read_bytes() == before_lab
    assert control.source_discovery_status(state_path=state)["control"] == result["control"]
