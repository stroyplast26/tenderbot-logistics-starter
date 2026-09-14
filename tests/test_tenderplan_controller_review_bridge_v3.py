"""Read-only closure previews against a genuine synthetic V3 native ledger."""
from __future__ import annotations

import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_controller_review_bridge as bridge
from lead_factory import tenderplan_read_only_store as native
from lead_factory import tenderplan_workbench_review as workbench
from tests import test_lead_factory_tenderplan_read_only_store as card_fixtures
from tests.test_lead_factory_tenderplan_account_transition_store import NOW, _claim, _new_intent
from tests.test_lead_factory_tenderplan_no_dispatch_admission import make_admission_fixture, _apply


@pytest.fixture(autouse=True)
def no_external_or_plaintext(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external or plaintext boundary"))
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    monkeypatch.setattr(workbench, "decrypt_tenderplan_card", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    yield forbidden
    forbidden.assert_not_called()


def _fixture(tmp_path, monkeypatch):
    queue, arguments, account, _proof = make_admission_fixture(tmp_path, monkeypatch)
    admission = _apply(arguments, native.preview_tenderplan_no_dispatch_admission(**arguments))
    controller = tmp_path / "controller.sqlite3"
    control.prepare_source_discovery_tenderplan_bindings(
        state_path=controller, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION)
    attempt_id, blocked = control._reserve(controller, control.SourceDiscoverySource.TENDERPLAN, 1)
    assert blocked is None and attempt_id is not None
    run_id = "tpri_" + attempt_id[3:]
    intent = _new_intent(run_id, account)
    store = native._existing_store(queue, clock=lambda: NOW)
    store.reserve_intent(intent, expected_no_dispatch_admission_set_sha256=admission["no_dispatch_admission_set_sha256"])
    _claim(queue, intent)
    cards = tuple(card_fixtures._encrypted_card(intent, tender_id=f"{index + 1:024x}") for index in range(5))
    with monkeypatch.context() as local:
        local.setattr(card_fixtures, "REQUESTED_AT_UTC", intent["requested_at_utc"])
        receipt = card_fixtures._receipt(intent, cards)
    ready = store.commit_ready(run_id, cards, receipt)
    body = {
        "attempt_id": attempt_id, "binding_required": 1,
        "native_store_identity_sha256": store.store_identity_sha256,
        "native_path_sha256": control._source_lab_path_sha256(queue),
        "run_id": run_id, "receipt_record_sha256": ready.receipt_record_sha256,
        "event_sha256": ready.event_sha256, "intent_record_sha256": intent["intent_record_sha256"],
        "request_sha256": intent["request_sha256"], "query_policy_sha256": intent["query_policy_sha256"],
        "item_ids": list(ready.item_ids), "card_count": 5, "recorded_at_utc": control._now_utc(),
    }
    control._finish(controller, attempt_id, "READY_FOR_REVIEW", 5,
                    tenderplan_binding={**body, "binding_receipt_sha256": control._digest(body)})
    assert native.validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 2
    return attempt_id, controller, queue, ready.item_ids


def _inspect(attempt_id, controller, queue):
    return bridge.inspect_tenderplan_controller_review_closure(
        attempt_id, state_path=controller, tenderplan_store_path=queue)


def _assert_no_release(preview):
    assert preview.closure_written is preview.controller_wip_released is False
    assert preview.production_apply_allowed is preview.authorizes_live is False
    assert preview.retry_eligible is preview.launch_allowed is False
    assert preview.snapshot_atomic_across_stores is False
    assert preview.controller_write_count == preview.native_store_write_count == 0
    assert preview.decrypt_count == preview.credential_read_count == preview.provider_request_count == 0


def test_v3_pending_five_cards_are_incomplete_and_both_stores_remain_unchanged(tmp_path, monkeypatch):
    attempt_id, controller, queue, items = _fixture(tmp_path, monkeypatch)
    before = controller.read_bytes(), queue.read_bytes()
    preview = _inspect(attempt_id, controller, queue)
    assert preview.state == "BLOCKED_REVIEW_INCOMPLETE"
    assert preview.native_schema_fingerprint_sha256 == native.TENDERPLAN_NO_DISPATCH_SCHEMA_FINGERPRINT_SHA256
    assert preview.item_ids == preview.unresolved_item_ids == items
    assert dict(preview.decision_counts) == {"KEEP": 0, "DISMISS": 0, "HOLD": 0, "UNDECIDED": 5}
    refs = workbench.TenderPlanWorkbenchReview(queue, clock=lambda: NOW).list_references()["items"]
    assert {row["item_id"]: row["reference_id"] for row in preview.decision_heads} == {
        row["item_id"]: row["reference_id"] for row in refs}
    _assert_no_release(preview)
    assert (controller.read_bytes(), queue.read_bytes()) == before


def test_v3_completed_decisions_make_stable_exact_proof_without_closing_batch(tmp_path, monkeypatch):
    attempt_id, controller, queue, items = _fixture(tmp_path, monkeypatch)
    store = native._existing_store(queue, clock=lambda: NOW)
    decisions = ("KEEP", "DISMISS", "HOLD", "KEEP", "HOLD")
    for item, decision in zip(items, decisions, strict=True):
        store.append_decision(item, native.TenderPlanReadOnlyDecision(decision), "SYNTHETIC_REVIEW")
    before = controller.read_bytes(), queue.read_bytes()
    first = _inspect(attempt_id, controller, queue)
    repeated = _inspect(attempt_id, controller, queue)
    assert first.state == "READY_TO_CLOSE" and first.unresolved_item_ids == ()
    assert dict(first.decision_counts) == {"KEEP": 2, "DISMISS": 1, "HOLD": 2, "UNDECIDED": 0}
    assert first.proof_sha256 == repeated.proof_sha256
    assert [row["decision"] for row in first.decision_heads] == list(decisions)
    _assert_no_release(first)
    assert (controller.read_bytes(), queue.read_bytes()) == before
    store.append_decision(items[-1], native.TenderPlanReadOnlyDecision.KEEP, "SYNTHETIC_SUPERSEDE")
    changed = _inspect(attempt_id, controller, queue)
    assert changed.state == "READY_TO_CLOSE" and changed.proof_sha256 != first.proof_sha256
    assert changed.decision_heads[-1]["decision_sequence"] == 2
    assert native.validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 2
    _assert_no_release(changed)


@pytest.mark.parametrize("fault", ["version", "schema", "admission", "transition", "controller_binding"])
def test_invalid_v3_metadata_or_cross_store_binding_still_fails_closed(tmp_path, monkeypatch, fault):
    attempt_id, controller, queue, _items = _fixture(tmp_path, monkeypatch)
    target = controller if fault == "controller_binding" else queue
    with sqlite3.connect(target) as con:
        if fault == "version":
            con.execute("PRAGMA user_version=4")
        elif fault == "schema":
            con.execute("CREATE TABLE unauthorized_extension(value TEXT)")
        else:
            table, trigger, column = {
                "admission": ("tenderplan_read_only_no_dispatch_admissions", "trg_tenderplan_no_dispatch_no_update", "record_sha256"),
                "transition": ("tenderplan_read_only_account_transition", "trg_tenderplan_account_transition_no_update", "record_sha256"),
                "controller_binding": ("source_discovery_tenderplan_bindings", "source_discovery_tenderplan_bindings_no_update", "binding_receipt_sha256"),
            }[fault]
            sql = con.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)).fetchone()[0]
            con.execute(f"DROP TRIGGER {trigger}")
            con.execute(f"UPDATE {table} SET {column}=?", ("f" * 64,))
            con.execute(sql)
    before = controller.read_bytes(), queue.read_bytes()
    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError):
        _inspect(attempt_id, controller, queue)
    assert (controller.read_bytes(), queue.read_bytes()) == before
