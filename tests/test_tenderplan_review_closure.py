"""Normal local closure of a fully reviewed, genuinely sealed V3 TP batch."""
from __future__ import annotations

import json
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_controller_review_bridge as bridge
from lead_factory import tenderplan_read_only_store as native
from tests import test_lead_factory_tenderplan_read_only_store as card_fixtures
from tests.test_lead_factory_tenderplan_account_transition_store import NOW, _claim, _new_intent
from tests.test_source_no_dispatch_control import _check, _reserve_kwargs
from tests.test_source_read_failure_integration import make_failure_context
from tests.test_tenderplan_controller_review_bridge_v3 import _fixture, _inspect


TABLE = "source_discovery_tenderplan_review_closures"
DECISIONS = ("KEEP", "DISMISS", "HOLD", "KEEP", "HOLD")
COUNTS = {"KEEP": 2, "DISMISS": 1, "HOLD": 2, "UNDECIDED": 0}


@pytest.fixture(autouse=True)
def no_external_or_plaintext(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external or plaintext boundary"))
    for target in (
        "lead_factory.tenderplan_windows_credential._credential_api",
        "lead_factory.tenderplan_read_only_crypto.decrypt_tenderplan_card",
        "lead_factory.tenderplan_workbench_review.decrypt_tenderplan_card",
        "requests.sessions.Session.request",
        "socket.create_connection",
        "subprocess.Popen",
    ):
        monkeypatch.setattr(target, forbidden)
    yield forbidden
    forbidden.assert_not_called()


def _decide(queue, items, decisions=DECISIONS):
    store = native._existing_store(queue, clock=lambda: NOW)
    for item, decision in zip(items, decisions, strict=True):
        store.append_decision(
            item, native.TenderPlanReadOnlyDecision(decision), "SYNTHETIC_REVIEW"
        )


def _ready(tmp_path, monkeypatch):
    attempt, controller, queue, items = _fixture(tmp_path, monkeypatch)
    _decide(queue, items)
    preview = _inspect(attempt, controller, queue)
    assert preview.state == "READY_TO_CLOSE"
    return attempt, controller, queue, items, preview


def _close(attempt, controller, queue, preview, **overrides):
    arguments = {
        "attempt_id": attempt,
        "confirmation": control.SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        "state_path": controller,
        "actor": "synthetic-reviewer",
        "evidence_ref": "evidence://test/review",
        "idempotency_key": "test-tp-close",
        "tenderplan_store_path": queue,
        "expected_tenderplan_preview_sha256": preview.proof_sha256,
    }
    return control.close_source_discovery_review(**{**arguments, **overrides})


def _read_rows(path, table):
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]


def _assert_closed(controller, attempt):
    snapshot = control.source_discovery_status(state_path=controller)["control"]
    assert snapshot["open_review_batches"] == 0
    assert snapshot["closed_review_batches"] == 1
    assert snapshot["latest"]["attempt_id"] == attempt
    assert snapshot["latest"]["state"] == "CLOSED_LOCAL"
    assert snapshot["gate"] == "READY"


def test_mixed_decisions_close_once_release_wip_and_preserve_native_and_raw_history(
    tmp_path, monkeypatch
):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    before_native = queue.read_bytes()
    before_attempts = _read_rows(controller, "source_discovery_attempts")
    before_bindings = _read_rows(controller, "source_discovery_tenderplan_bindings")
    assert control.source_discovery_status(state_path=controller)["control"]["open_review_batches"] == 1
    with sqlite3.connect(controller) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5

    result = _close(attempt, controller, queue, preview)

    assert result["state"] == "CLOSED_LOCAL"
    assert result["source"] == "TENDERPLAN"
    assert result["created"] is True
    assert result["review_count"] == 5
    assert result["decision_counts"] == COUNTS
    assert result["control"]["open_review_batches"] == 0
    assert queue.read_bytes() == before_native
    assert _read_rows(controller, "source_discovery_attempts") == before_attempts
    assert _read_rows(controller, "source_discovery_tenderplan_bindings") == before_bindings
    assert before_attempts[0]["state"] == "READY_FOR_REVIEW"
    assert native.validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 2
    with sqlite3.connect(controller) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 9
    closures = _read_rows(controller, TABLE)
    assert len(closures) == 1
    assert closures[0]["attempt_id"] == attempt
    assert closures[0]["run_id"] == preview.run_id
    assert closures[0]["preview_sha256"] == preview.proof_sha256
    assert closures[0]["idempotency_key"] == "test-tp-close"
    assert _read_rows(controller, "source_discovery_review_closures") == []
    _assert_closed(controller, attempt)


def test_exact_replay_uses_original_preview_pin_without_another_write(tmp_path, monkeypatch):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    first = _close(attempt, controller, queue, preview)
    before = controller.read_bytes(), queue.read_bytes()
    replay = _close(attempt, controller, queue, preview)
    assert replay["created"] is False
    assert replay["closure_receipt_sha256"] == first["closure_receipt_sha256"]
    assert replay["decision_counts"] == COUNTS
    assert (controller.read_bytes(), queue.read_bytes()) == before
    assert len(_read_rows(controller, TABLE)) == 1


@pytest.mark.parametrize("overrides", [
    {"actor": "another-reviewer"},
    {"evidence_ref": "evidence://test/different-review"},
    {"idempotency_key": "different-idempotency-key"},
    {"expected_tenderplan_preview_sha256": "f" * 64},
])
def test_conflicting_replay_cannot_replace_existing_closure(tmp_path, monkeypatch, overrides):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    _close(attempt, controller, queue, preview)
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview, **overrides)
    assert (controller.read_bytes(), queue.read_bytes()) == before
    _assert_closed(controller, attempt)


@pytest.mark.parametrize("decided_count", [0, 4])
def test_undecided_cards_do_not_allow_closure_or_schema_migration(tmp_path, monkeypatch, decided_count):
    attempt, controller, queue, items = _fixture(tmp_path, monkeypatch)
    _decide(queue, items[:decided_count], DECISIONS[:decided_count])
    preview = _inspect(attempt, controller, queue)
    assert preview.state == "BLOCKED_REVIEW_INCOMPLETE"
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview)
    assert (controller.read_bytes(), queue.read_bytes()) == before
    assert control.source_discovery_status(state_path=controller)["control"]["open_review_batches"] == 1


def test_decision_superseded_after_preview_rejects_stale_pin_and_accepts_fresh_proof(
    tmp_path, monkeypatch
):
    attempt, controller, queue, items, preview = _ready(tmp_path, monkeypatch)
    native._existing_store(queue, clock=lambda: NOW).append_decision(
        items[-1], native.TenderPlanReadOnlyDecision.KEEP, "SYNTHETIC_SUPERSEDE"
    )
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview)
    assert (controller.read_bytes(), queue.read_bytes()) == before
    fresh = _inspect(attempt, controller, queue)
    assert fresh.proof_sha256 != preview.proof_sha256
    assert _close(attempt, controller, queue, fresh)["decision_counts"] == {
        "KEEP": 3, "DISMISS": 1, "HOLD": 1, "UNDECIDED": 0
    }


@pytest.mark.parametrize("overrides", [
    {"confirmation": None},
    {"actor": ""},
    {"evidence_ref": ""},
    {"idempotency_key": ""},
    {"expected_tenderplan_preview_sha256": None},
    {"expected_tenderplan_preview_sha256": "invalid"},
    {"expected_tenderplan_preview_sha256": "f" * 64},
    {"attempt_id": "sd_" + "0" * 32},
])
def test_invalid_arguments_fail_before_any_local_write(tmp_path, monkeypatch, overrides):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview, **overrides)
    assert (controller.read_bytes(), queue.read_bytes()) == before


def test_wrong_native_store_fails_without_touching_either_store(tmp_path, monkeypatch):
    first_root, second_root = tmp_path / "first", tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    attempt, controller, queue, _items, preview = _ready(first_root, monkeypatch)
    _other_attempt, _other_controller, other_queue, _other_items, _other_preview = _ready(second_root, monkeypatch)
    before = controller.read_bytes(), queue.read_bytes(), other_queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview, tenderplan_store_path=other_queue)
    assert (controller.read_bytes(), queue.read_bytes(), other_queue.read_bytes()) == before


def test_later_native_decision_invalidates_status_preview_and_replay_without_reopening(
    tmp_path, monkeypatch
):
    attempt, controller, queue, items, preview = _ready(tmp_path, monkeypatch)
    _close(attempt, controller, queue, preview)
    native._existing_store(queue, clock=lambda: NOW).append_decision(
        items[-1], native.TenderPlanReadOnlyDecision.KEEP, "SYNTHETIC_POST_CLOSE"
    )
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.source_discovery_status(state_path=controller)
    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError):
        _inspect(attempt, controller, queue)
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview)
    assert (controller.read_bytes(), queue.read_bytes()) == before
    assert len(_read_rows(controller, TABLE)) == 1


def test_unrelated_native_history_append_does_not_invalidate_closed_batch(tmp_path, monkeypatch):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    _close(attempt, controller, queue, preview)
    account = native.validate_tenderplan_read_only_store(queue)["account_transition"]["active_connection"]
    admission_pin = native.read_tenderplan_no_dispatch_admissions(queue)["no_dispatch_admission_set_sha256"]
    unrelated = _new_intent("tpri_" + "f" * 32, account)
    store = native._existing_store(queue, clock=lambda: NOW)
    before_native = queue.read_bytes()
    store.reserve_intent(unrelated, expected_no_dispatch_admission_set_sha256=admission_pin)
    store.record_terminal(unrelated["run_id"], "FAILED_CLOSED")
    assert queue.read_bytes() != before_native
    _assert_closed(controller, attempt)
    before = controller.read_bytes(), queue.read_bytes()
    assert _close(attempt, controller, queue, preview)["created"] is False
    assert (controller.read_bytes(), queue.read_bytes()) == before


@pytest.mark.parametrize("statement", [
    f"UPDATE {TABLE} SET preview_sha256='tampered'",
    f"DELETE FROM {TABLE}",
])
def test_closure_rows_are_append_only(tmp_path, monkeypatch, statement):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    _close(attempt, controller, queue, preview)
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(sqlite3.IntegrityError):
        with sqlite3.connect(controller) as connection:
            connection.execute(statement)
    assert (controller.read_bytes(), queue.read_bytes()) == before
    _assert_closed(controller, attempt)


@pytest.mark.parametrize("fault", ["record_hash", "record_body", "run_id", "preview_pin", "schema", "version", "trigger"])
def test_forged_closure_or_schema_tampering_is_detected_by_status_and_close(tmp_path, monkeypatch, fault):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    _close(attempt, controller, queue, preview)
    with sqlite3.connect(controller) as connection:
        triggers = connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (TABLE,)
        ).fetchall()
        assert len(triggers) >= 2
        if fault == "schema":
            connection.execute(f"ALTER TABLE {TABLE} ADD COLUMN unauthorized TEXT")
        elif fault == "version":
            connection.execute("PRAGMA user_version=8")
        elif fault == "trigger":
            connection.execute(f'DROP TRIGGER "{triggers[0][0]}"')
        else:
            for name, _sql in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            if fault == "record_hash":
                connection.execute(f"UPDATE {TABLE} SET record_sha256=?", ("f" * 64,))
            elif fault == "record_body":
                body = json.loads(connection.execute(f"SELECT record_json FROM {TABLE}").fetchone()[0])
                body["evidence_ref"] = "evidence://test/forged"
                connection.execute(f"UPDATE {TABLE} SET record_json=?", (json.dumps(body),))
            elif fault == "run_id":
                connection.execute(f"UPDATE {TABLE} SET run_id=?", ("tpri_" + "e" * 32,))
            else:
                connection.execute(f"UPDATE {TABLE} SET preview_sha256=?", ("e" * 64,))
            for _name, sql in triggers:
                connection.execute(sql)
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.source_discovery_status(state_path=controller)
    with pytest.raises(control.SourceDiscoveryControlError):
        _close(attempt, controller, queue, preview)
    assert (controller.read_bytes(), queue.read_bytes()) == before


def _scoped_ready_batch(controller, queue, scope, native_pin, monkeypatch, *, ack_pin=None):
    checked = _check(controller, queue, scope)
    assert checked["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    attempt, blocked = control._reserve(
        controller, control.SourceDiscoverySource.TENDERPLAN, 1,
        **_reserve_kwargs(controller, queue, scope, checked),
    )
    assert blocked is None and attempt is not None
    store = native._existing_store(queue, clock=lambda: NOW)
    account = native.validate_tenderplan_read_only_store(queue)["account_transition"]["active_connection"]
    intent = _new_intent("tpri_" + attempt[3:], account)
    store.reserve_intent(
        intent, expected_no_dispatch_admission_set_sha256=native_pin,
        **({"expected_read_failure_ack_set_sha256": ack_pin} if ack_pin is not None else {}),
    )
    _claim(queue, intent)
    cards = tuple(
        card_fixtures._encrypted_card(intent, tender_id=f"{index + 1:024x}")
        for index in range(5)
    )
    with monkeypatch.context() as local:
        local.setattr(card_fixtures, "REQUESTED_AT_UTC", intent["requested_at_utc"])
        receipt = card_fixtures._receipt(intent, cards)
    ready = store.commit_ready(intent["run_id"], cards, receipt)
    binding = {
        "attempt_id": attempt, "binding_required": 1,
        "native_store_identity_sha256": store.store_identity_sha256,
        "native_path_sha256": control._source_lab_path_sha256(queue),
        "run_id": intent["run_id"], "receipt_record_sha256": ready.receipt_record_sha256,
        "event_sha256": ready.event_sha256, "intent_record_sha256": intent["intent_record_sha256"],
        "request_sha256": intent["request_sha256"], "query_policy_sha256": intent["query_policy_sha256"],
        "item_ids": list(ready.item_ids), "card_count": 5, "recorded_at_utc": control._now_utc(),
    }
    control._finish(
        controller, attempt, "READY_FOR_REVIEW", 5,
        tenderplan_binding={**binding, "binding_receipt_sha256": control._digest(binding)},
    )
    _decide(queue, ready.item_ids)
    preview = _inspect(attempt, controller, queue)
    assert preview.state == "READY_TO_CLOSE"
    return attempt, preview


def test_v9_close_preserves_same_ack_context_for_scoped_yandex_and_raw_uncertainty(
    tmp_path, monkeypatch
):
    from lead_factory import source_discovery_read_failure_context as context
    from lead_factory import tenderplan_read_failure_ack as ack

    controller, queue, _old_scope, native_pin, ack_pin, scope, _document, history = make_failure_context(
        tmp_path, monkeypatch
    )
    context_path = context.source_read_failure_context_path(
        controller_path=controller, expected_source_reconciliation_set_sha256=scope
    )
    ack_path = ack.read_failure_ack_set_path(queue, ack_pin)
    preserved = context_path.read_bytes(), ack_path.read_bytes()
    attempt, preview = _scoped_ready_batch(
        controller, queue, scope, native_pin, monkeypatch, ack_pin=ack_pin
    )
    assert _check(controller, queue, scope)["state"] == "BLOCKED_BACKPRESSURE"
    before_native = queue.read_bytes()

    closed = _close(attempt, controller, queue, preview)

    assert closed["created"] is True
    with sqlite3.connect(controller) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 9
    checked = _check(controller, queue, scope)
    assert checked["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert checked["source_reconciliation_set_sha256"] == scope
    assert checked["tenderplan_no_dispatch_admission_set_sha256"] == native_pin
    assert checked["tenderplan_read_failure_ack_set_sha256"] == ack_pin
    scoped = checked["control"]
    assert scoped["uncertain_count"] == 2
    assert scoped["reconciled_uncertain_count"] == scoped["acknowledged_read_failure_count"] == 1
    assert scoped["blocking_uncertain_count"] == scoped["open_review_batches"] == 0
    assert scoped["closed_review_batches"] == 1
    assert scoped["gate"] == "BLOCKED_UNCERTAIN"
    assert all(checked[key] is False for key in (
        "launch_allowed", "retry_eligible", "authority_verified", "authorizes_live"
    ))
    assert control.check_source_discovery("YANDEX", state_path=controller)["state"] == "BLOCKED_UNCERTAIN"
    assert queue.read_bytes() == before_native
    assert (context_path.read_bytes(), ack_path.read_bytes()) == preserved
    historical_ids = {row["attempt_id"] for row in history}
    assert [row for row in _read_rows(controller, "source_discovery_attempts")
            if row["attempt_id"] in historical_ids] == history


def test_decision_racing_before_native_close_fence_invalidates_initial_preview(
    tmp_path, monkeypatch
):
    attempt, controller, queue, items, preview = _ready(tmp_path, monkeypatch)
    before_controller = controller.read_bytes()
    original_open = control._open_existing_local_fence
    raced = []

    def open_after_competing_decision(path):
        if path == queue and not raced:
            # The controller fence is already held; the native fence is not.
            native._existing_store(queue, clock=lambda: NOW).append_decision(
                items[-1], native.TenderPlanReadOnlyDecision.KEEP, "SYNTHETIC_CLOSE_RACE"
            )
            raced.append(True)
        return original_open(path)

    with monkeypatch.context() as local:
        local.setattr(control, "_open_existing_local_fence", open_after_competing_decision)
        with pytest.raises(control.SourceDiscoveryControlError):
            _close(attempt, controller, queue, preview)
    assert raced == [True]
    assert controller.read_bytes() == before_controller
    fresh = _inspect(attempt, controller, queue)
    assert fresh.proof_sha256 != preview.proof_sha256
    assert fresh.decision_heads[-1]["decision_sequence"] == 2
    before_native = queue.read_bytes()
    assert _close(attempt, controller, queue, fresh)["created"] is True
    assert queue.read_bytes() == before_native


def test_plain_reservation_keeps_closed_native_writer_fence_until_controller_commit(
    tmp_path, monkeypatch
):
    attempt, controller, queue, _items, preview = _ready(tmp_path, monkeypatch)
    _close(attempt, controller, queue, preview)
    before_native = queue.read_bytes()
    original_open = control._open_for_write
    observed_commits = []

    class CommitProbe:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, statement, *arguments):
            if statement.strip().upper() == "COMMIT":
                snapshot = control.source_discovery_status(state_path=controller)["control"]
                assert snapshot["closed_review_batches"] == 1
                assert snapshot["open_review_batches"] == 0
                competitor = sqlite3.connect(
                    queue.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0.05
                )
                try:
                    with pytest.raises(sqlite3.OperationalError, match="locked"):
                        competitor.execute("BEGIN IMMEDIATE")
                finally:
                    competitor.close()
                observed_commits.append(True)
            return self.connection.execute(statement, *arguments)

    def open_with_commit_probe(path, **arguments):
        return CommitProbe(original_open(path, **arguments))

    with monkeypatch.context() as local:
        local.setattr(control, "_open_for_write", open_with_commit_probe)
        reservation, blocked = control._reserve(controller, control.SourceDiscoverySource.YANDEX, 1)
    assert blocked is None and reservation is not None and reservation != attempt
    assert observed_commits == [True]
    assert queue.read_bytes() == before_native
    competitor = sqlite3.connect(queue.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0.05)
    try:
        competitor.execute("BEGIN IMMEDIATE")
        competitor.execute("ROLLBACK")
    finally:
        competitor.close()
    assert control.source_discovery_status(state_path=controller)["control"]["in_flight_count"] == 1


def test_existing_no_dispatch_replay_after_v9_closure_is_inert(tmp_path, monkeypatch):
    from lead_factory import source_discovery_no_dispatch as reconciliation
    from tests.test_source_no_dispatch_reconciliation import _apply, _candidate

    controller, queue, arguments = _candidate(tmp_path, monkeypatch)
    original_preview = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    admitted = _apply(arguments, original_preview)
    scope = admitted["source_reconciliation_set_sha256"]
    attempt, preview = _scoped_ready_batch(
        controller, queue, scope, admitted["no_dispatch_admission_set_sha256"], monkeypatch
    )
    _close(attempt, controller, queue, preview)
    arguments.update({
        "expected_controller_file_sha256": control._file_sha256(controller),
        "expected_controller_snapshot_sha256": control._digest(
            control.source_discovery_status(state_path=controller)["control"]
        ),
        "expected_native_file_sha256": control._file_sha256(queue),
    })
    before = controller.read_bytes(), queue.read_bytes()
    closure_rows = _read_rows(controller, TABLE)
    fresh = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    replay = _apply(arguments, fresh)
    assert fresh["state"] == replay["state"] == "ALREADY_APPLIED"
    assert fresh["preview_sha256"] == original_preview["preview_sha256"]
    assert replay["source_reconciliation_set_sha256"] == scope
    assert all(value == 0 for value in replay["effects"].values())
    assert (controller.read_bytes(), queue.read_bytes()) == before
    assert _read_rows(controller, TABLE) == closure_rows
    assert _check(controller, queue, scope)["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"


def test_scoped_yandex_rechecks_closed_native_decisions_under_held_fence(tmp_path, monkeypatch):
    controller, queue, _old_scope, native_pin, ack_pin, scope, _document, _history = make_failure_context(
        tmp_path, monkeypatch
    )
    attempt, preview = _scoped_ready_batch(
        controller, queue, scope, native_pin, monkeypatch, ack_pin=ack_pin
    )
    _close(attempt, controller, queue, preview)
    assert _check(controller, queue, scope)["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    before_controller = controller.read_bytes()
    before_native = queue.read_bytes()
    original_snapshot = control._snapshot
    raced = []

    def snapshot_then_competing_decision(path, wip_limit, **options):
        snapshot = original_snapshot(path, wip_limit, **options)
        if path == controller and options.get("_connection") is not None and not raced:
            # The scoped snapshot has observed the closure, but its native file
            # hash and writer fence have not yet been acquired.
            assert snapshot["closed_review_batches"] == 1
            assert snapshot["open_review_batches"] == 0
            native._existing_store(queue, clock=lambda: NOW).append_decision(
                preview.item_ids[-1], native.TenderPlanReadOnlyDecision.KEEP,
                "SYNTHETIC_SCOPED_CHECK_RACE",
            )
            raced.append(True)
        return snapshot

    with monkeypatch.context() as local:
        local.setattr(control, "_snapshot", snapshot_then_competing_decision)
        try:
            result = _check(controller, queue, scope)
        except control.SourceDiscoveryControlError:
            pass
        else:
            assert result["state"] == "BLOCKED_CONTROL_RECONCILIATION"
    assert raced == [True]
    assert controller.read_bytes() == before_controller
    assert queue.read_bytes() != before_native
    assert len(_read_rows(queue, "tenderplan_read_only_decisions")) == 6


def test_direct_close_helper_requires_confirmation_before_io(tmp_path, monkeypatch):
    from lead_factory import tenderplan_review_closure as closure

    forbidden = Mock(side_effect=AssertionError("unconfirmed helper must not inspect state"))
    with monkeypatch.context() as local:
        for name in ("_state_path", "_regular_file_identity", "_assert_no_sqlite_sidecars",
                     "_open_existing_local_fence"):
            local.setattr(control, name, forbidden)
        with pytest.raises(control.SourceDiscoveryControlError, match="^LOCAL_CLOSE_CONFIRMATION_REQUIRED$"):
            closure.close_batch(
                attempt_id="sd_" + "a" * 32, state_path=tmp_path / "controller.sqlite3",
                native_path=tmp_path / "native.sqlite3", expected_preview_sha256="b" * 64,
                actor="synthetic-reviewer", evidence_ref="evidence://test/direct-close",
                idempotency_key="unconfirmed-direct-close", confirmation=None,
            )
    forbidden.assert_not_called()
    assert not list(tmp_path.iterdir())
