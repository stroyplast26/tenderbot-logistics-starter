from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_controller_review_bridge as bridge
from lead_factory import tenderplan_workbench_review as workbench
from lead_factory import tenderplan_windows_credential as credentials
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256,
    TenderPlanReadOnlyDecision,
    TenderPlanReadOnlyStore,
    _existing_store,
    verify_worker_intent,
)
from tests.test_lead_factory_source_discovery_tenderplan_binding import (
    _run as _run_bound_batch,
)
from tests.test_lead_factory_tenderplan_read_only_intake import NOW
from tests.test_lead_factory_tenderplan_read_only_store import NOW as STORE_NOW
from tests.test_lead_factory_tenderplan_read_only_store import _intent, _verify_arguments


@pytest.fixture(autouse=True)
def no_external_or_plaintext(monkeypatch: pytest.MonkeyPatch) -> Mock:
    forbidden = Mock(side_effect=AssertionError("external or plaintext boundary"))
    monkeypatch.setattr(credentials, "_credential_api", forbidden)
    monkeypatch.setattr(workbench, "decrypt_tenderplan_card", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    return forbidden


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _files(path: Path) -> dict[str, bytes]:
    return {item.name: item.read_bytes() for item in path.iterdir() if item.is_file()}


def _bound_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int = 3,
) -> tuple[str, Path, Path, tuple[str, ...]]:
    report, controller_path, native_path, captured, _transport = _run_bound_batch(
        tmp_path,
        monkeypatch,
        count=count,
    )
    result = captured["result"]
    return (
        str(report["attempt_id"]),
        controller_path,
        native_path,
        tuple(result.item_ids),
    )


def _decide(
    native_path: Path,
    item_ids: tuple[str, ...],
    decisions: tuple[TenderPlanReadOnlyDecision, ...],
) -> None:
    store = _existing_store(native_path, clock=lambda: NOW)
    for index, (item_id, decision) in enumerate(zip(item_ids, decisions, strict=True), start=1):
        store.append_decision(item_id, decision, f"SYNTHETIC_REASON_{index}")


def _inspect(attempt_id: str, controller_path: Path, native_path: Path):
    return bridge.inspect_tenderplan_controller_review_closure(
        attempt_id,
        state_path=controller_path,
        tenderplan_store_path=native_path,
    )


def test_complete_batch_is_exact_ready_to_close_and_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_external_or_plaintext: Mock,
) -> None:
    attempt_id, controller_path, native_path, item_ids = _bound_batch(tmp_path, monkeypatch)
    _decide(
        native_path,
        item_ids,
        (
            TenderPlanReadOnlyDecision.KEEP,
            TenderPlanReadOnlyDecision.DISMISS,
            TenderPlanReadOnlyDecision.HOLD,
        ),
    )
    before = _files(tmp_path)

    first = _inspect(attempt_id, controller_path, native_path)
    second = _inspect(attempt_id, controller_path, native_path)

    assert first.state == "READY_TO_CLOSE"
    assert first.proof_sha256 == second.proof_sha256
    assert first.item_ids == item_ids
    assert dict(first.decision_counts) == {
        "KEEP": 1,
        "DISMISS": 1,
        "HOLD": 1,
        "UNDECIDED": 0,
    }
    assert first.unresolved_item_ids == ()
    assert [item["decision"] for item in first.decision_heads] == [
        "KEEP",
        "DISMISS",
        "HOLD",
    ]
    references = workbench.TenderPlanWorkbenchReview(
        native_path, clock=lambda: NOW
    ).list_references()["items"]
    expected_references = {item["item_id"]: item["reference_id"] for item in references}
    assert {
        item["item_id"]: item["reference_id"] for item in first.decision_heads
    } == expected_references
    assert first.closure_written is first.controller_wip_released is False
    assert first.production_apply_allowed is first.snapshot_atomic_across_stores is False
    assert first.retry_eligible is first.launch_allowed is first.authorizes_live is False
    assert (
        first.controller_write_count
        == first.native_store_write_count
        == first.decrypt_count
        == first.credential_read_count
        == first.provider_request_count
        == first.provider_write_count
        == first.crm_write_count
        == first.message_count
        == first.schedule_count
        == first.contact_count
        == first.spend_minor
        == 0
    )
    assert _files(tmp_path) == before
    no_external_or_plaintext.assert_not_called()


def test_missing_decision_blocks_without_mutating_either_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_external_or_plaintext: Mock,
) -> None:
    attempt_id, controller_path, native_path, item_ids = _bound_batch(tmp_path, monkeypatch)
    _decide(
        native_path,
        item_ids[:2],
        (TenderPlanReadOnlyDecision.KEEP, TenderPlanReadOnlyDecision.DISMISS),
    )
    before = _files(tmp_path)

    preview = _inspect(attempt_id, controller_path, native_path)

    assert preview.state == "BLOCKED_REVIEW_INCOMPLETE"
    assert preview.unresolved_item_ids == (item_ids[2],)
    assert dict(preview.decision_counts)["UNDECIDED"] == 1
    assert preview.closure_written is preview.controller_wip_released is False
    assert _files(tmp_path) == before
    no_external_or_plaintext.assert_not_called()


def test_superseding_hold_with_keep_changes_exact_preview_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt_id, controller_path, native_path, item_ids = _bound_batch(tmp_path, monkeypatch)
    _decide(
        native_path,
        item_ids,
        (
            TenderPlanReadOnlyDecision.KEEP,
            TenderPlanReadOnlyDecision.DISMISS,
            TenderPlanReadOnlyDecision.HOLD,
        ),
    )
    held = _inspect(attempt_id, controller_path, native_path)

    _existing_store(native_path, clock=lambda: NOW).append_decision(
        item_ids[2], TenderPlanReadOnlyDecision.KEEP, "SYNTHETIC_SUPERSEDE"
    )
    kept = _inspect(attempt_id, controller_path, native_path)

    assert held.state == kept.state == "READY_TO_CLOSE"
    assert held.proof_sha256 != kept.proof_sha256
    assert held.native_file_sha256 != kept.native_file_sha256
    assert held.decision_heads[2]["decision"] == "HOLD"
    assert kept.decision_heads[2]["decision"] == "KEEP"
    assert kept.decision_heads[2]["decision_sequence"] == 2
    assert dict(kept.decision_counts) == {
        "KEEP": 2,
        "DISMISS": 1,
        "HOLD": 0,
        "UNDECIDED": 0,
    }


@pytest.mark.parametrize("fault", ["controller-binding", "native-path"])
def test_tampered_or_wrong_exact_binding_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    attempt_id, controller_path, native_path, _item_ids = _bound_batch(tmp_path, monkeypatch)
    selected_controller = controller_path
    selected_native = native_path
    if fault == "controller-binding":
        selected_controller = tmp_path / "tampered-controller.sqlite3"
        shutil.copy2(controller_path, selected_controller)
        with sqlite3.connect(selected_controller) as connection:
            trigger = connection.execute(
                """SELECT sql FROM sqlite_master
                   WHERE type='trigger'
                     AND name='source_discovery_tenderplan_bindings_no_update'"""
            ).fetchone()[0]
            connection.execute("DROP TRIGGER source_discovery_tenderplan_bindings_no_update")
            connection.execute(
                """UPDATE source_discovery_tenderplan_bindings
                   SET binding_receipt_sha256=?""",
                ("f" * 64,),
            )
            connection.execute(trigger)
    else:
        selected_native = tmp_path / "moved-native.sqlite3"
        shutil.copy2(native_path, selected_native)
    before = _files(tmp_path)

    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError):
        _inspect(attempt_id, selected_controller, selected_native)

    assert _files(tmp_path) == before


def _uncertain_fixture(
    tmp_path: Path, *, claimed: bool = False
) -> tuple[str, Path, Path, Path, str, str]:
    controller_path = tmp_path / "uncertain-controller.sqlite3"
    native_path = tmp_path / "uncertain-native.sqlite3"
    proof_path = tmp_path / "attested-proof.json"
    control.prepare_source_discovery_tenderplan_bindings(
        state_path=controller_path,
        confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
    )
    attempt_id, blocked = control._reserve(
        controller_path, control.SourceDiscoverySource.TENDERPLAN, 1
    )
    assert attempt_id is not None and blocked is None
    control._finish(controller_path, attempt_id, "UNCERTAIN", 0)
    with sqlite3.connect(controller_path) as connection:
        connection.row_factory = sqlite3.Row
        attempt_row = connection.execute(
            "SELECT * FROM source_discovery_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
    assert attempt_row is not None
    attempt_material = {
        "sequence": int(attempt_row["sequence"]),
        "attempt_id": str(attempt_row["attempt_id"]),
        "source": str(attempt_row["source"]),
        "state": str(attempt_row["state"]),
        "started_at_utc": str(attempt_row["started_at_utc"]),
        "finished_at_utc": str(attempt_row["finished_at_utc"] or ""),
        "review_count": int(attempt_row["review_count"]),
        "tenderplan_binding_required": int(attempt_row["tenderplan_binding_required"]),
    }
    controller_snapshot = control.source_discovery_status(state_path=controller_path)["control"]
    run_id = "tpri_" + attempt_id[3:]
    intent = _intent(run_id)
    store = TenderPlanReadOnlyStore(native_path, clock=lambda: STORE_NOW)
    store.reserve_intent(intent)
    if claimed:
        verify_worker_intent(native_path, **_verify_arguments(intent), clock=lambda: STORE_NOW)
    store.record_terminal(run_id, "UNCERTAIN")
    with sqlite3.connect(native_path) as connection:
        connection.row_factory = sqlite3.Row
        operation = connection.execute(
            "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?", (run_id,)
        ).fetchone()
        events = connection.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id=? ORDER BY sequence",
            (run_id,),
        ).fetchall()
    proof: dict[str, object] = {
        "schema": "tenderplan-attested-no-dispatch-proof-v1",
        "proof_state": ("PROVEN_NO_DISPATCH_UNDER_ATTESTED_CLAIM_BEFORE_CREDENTIAL_PROTOCOL"),
        "recorded_at_utc": "2026-09-14T12:00:00.000000Z",
        "attempt_id": attempt_id,
        "run_id": run_id,
        "controller": {
            "raw_state": "UNCERTAIN",
            "raw_gate": "BLOCKED_UNCERTAIN",
            "file_sha256": _file_sha256(controller_path),
            "attempt_sha256": _sha256(_canonical(attempt_material)),
            "snapshot_sha256": _sha256(_canonical(controller_snapshot)),
            "binding_count": 0,
            "reconciliation_count": 0,
        },
        "native": {
            "raw_state": "UNCERTAIN",
            "file_sha256": _file_sha256(native_path),
            "path_sha256": control._source_lab_path_sha256(native_path.resolve()),
            "store_identity_sha256": store.store_identity_sha256,
            "schema_fingerprint_sha256": (TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256),
            "event_count": 2,
            "dispatch_claim_count": 0,
            "card_count": 0,
            "decision_count": 0,
            "operation_sha256": str(operation["operation_sha256"]),
            "intent_record_sha256": str(operation["intent_record_sha256"]),
            "request_sha256": str(intent["request_sha256"]),
            "query_policy_sha256": str(intent["query_policy_sha256"]),
            "maximum_records": int(intent["maximum_records"]),
            "maximum_response_bytes": int(intent["maximum_response_bytes"]),
            "request_count": int(intent["request_count"]),
            "write_count": int(intent["write_count"]),
            "spend_minor": int(intent["spend_minor"]),
            "intent_event_sha256": str(events[0]["event_sha256"]),
            "uncertain_event_sha256": str(events[-1]["event_sha256"]),
        },
        "result": {
            "classification": "AUTHORIZED_ATTEMPT_FAILED_PRE_CREDENTIAL_PRE_PROVIDER",
            "credential_read_count": 0,
            "provider_request_count": 0,
            "provider_write_count": 0,
            "card_count": 0,
            "decision_count": 0,
            "provider_result": "UNKNOWN",
            "import_result": "ABSENT",
        },
        "gates": {
            "authority_verified_for_new_action": False,
            "authorizes_live": False,
            "changes_controller_gate": False,
            "changes_native_outcome": False,
            "changes_terminal_counts": False,
            "creates_proposal": False,
            "launch_allowed": False,
            "retry_eligible": False,
            "sidecar_used_as_authority": False,
        },
        "evidence": {
            "diagnostic_observation_unchanged_during_proof": True,
            "post_run_forensic_sha256": "b" * 64,
            "state_files_byte_identical_before_after": True,
            "sqlite_sidecars_absent_before_after": True,
            "terminal_preserved": True,
        },
        "corroborative_diagnostic": {
            "currently_present": True,
            "current_file_sha256": "a" * 64,
            "forensic_recorded_file_sha256": "a" * 64,
            "diagnostic_code": "WORKER_PRE_DISPATCH_VALIDATION",
            "observation_stage": "WORKER_PRE_PROVIDER",
            "retry_eligible": False,
            "used_as_authority": False,
        },
        "local_fix": {
            "commit": "b" * 40,
            "published": True,
            "authorizes_retry": False,
            "test_source_sha256": "c" * 64,
            "transport_source_sha256": "d" * 64,
        },
        "claim_before_credential_protocol": {
            "claim_call_line": 10,
            "credential_call_lines": [20, 30],
            "provider_call_line": 40,
            "dispatch_claim_append_line": 100,
            "verified_intent_return_line": 110,
            "transaction_yield_line": 50,
            "transaction_commit_line": 60,
            "conclusion": ("COMMITTED_DISPATCH_CLAIM_PRECEDES_CREDENTIAL_AND_PROVIDER_ENTRY"),
        },
        "execution_provenance": {
            "source_commit": "c" * 40,
            "proposal_id": "tpp_" + "d" * 32,
            "authorization_id": "tpa_" + "e" * 32,
            "authority_consumed": True,
            "sealed_worker_member_count": 1,
            "terminal_raw_credential_read_count": None,
            "terminal_raw_provider_request_count": None,
            **{
                key: "f" * 64
                for key in (
                    "proposal_file_sha256",
                    "proposal_record_sha256",
                    "authority_file_sha256",
                    "authority_record_sha256",
                    "authorization_transcript_sha256",
                    "consumption_marker_file_sha256",
                    "consumption_marker_record_sha256",
                    "terminal_file_sha256",
                    "terminal_record_sha256",
                    "runtime_manifest_sha256",
                    "sealed_worker_bundle_sha256",
                    "sealed_worker_embedded_manifest_sha256",
                    "tenderplan_store_source_sha256",
                    "tenderplan_transport_source_sha256",
                    "source_discovery_control_source_sha256",
                    "runner_sha256",
                    "launcher_sha256",
                )
            },
        },
    }
    record_sha256 = _sha256(_canonical(proof))
    proof["record_sha256"] = record_sha256
    payload = _canonical(proof)
    proof_path.write_bytes(payload)
    return (
        attempt_id,
        controller_path,
        native_path,
        proof_path,
        _sha256(payload),
        record_sha256,
    )


def _resign_proof(proof_path: Path) -> str:
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof.pop("record_sha256", None)
    proof["record_sha256"] = _sha256(_canonical(proof))
    payload = _canonical(proof)
    proof_path.write_bytes(payload)
    return _sha256(payload)


def test_exact_attested_pre_provider_attempt_is_not_a_review_batch(
    tmp_path: Path,
    no_external_or_plaintext: Mock,
) -> None:
    (
        attempt_id,
        controller_path,
        native_path,
        proof_path,
        proof_file_sha256,
        proof_record_sha256,
    ) = _uncertain_fixture(tmp_path)
    before = _files(tmp_path)

    first = bridge.inspect_tenderplan_controller_review_closure(
        attempt_id,
        state_path=controller_path,
        tenderplan_store_path=native_path,
        attested_no_dispatch_proof_path=proof_path,
        expected_attested_no_dispatch_proof_sha256=proof_file_sha256,
    )
    second = bridge.inspect_tenderplan_controller_review_closure(
        attempt_id,
        state_path=controller_path,
        tenderplan_store_path=native_path,
        attested_no_dispatch_proof_path=proof_path,
        expected_attested_no_dispatch_proof_sha256=proof_file_sha256,
    )

    assert first.state == "NOT_APPLICABLE_FAILED_PRE_PROVIDER"
    assert first.proof_sha256 == second.proof_sha256
    assert first.attested_no_dispatch_file_sha256 == proof_file_sha256
    assert first.attested_no_dispatch_record_sha256 == proof_record_sha256
    assert first.item_ids == first.decision_heads == first.unresolved_item_ids == ()
    assert sum(first.decision_counts.values()) == 0
    assert first.retry_eligible is first.launch_allowed is False
    assert _files(tmp_path) == before
    no_external_or_plaintext.assert_not_called()

    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError) as missing:
        _inspect(attempt_id, controller_path, native_path)
    assert missing.value.code == "TENDERPLAN_REVIEW_CLOSURE_PROOF_REQUIRED"
    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError) as wrong_pin:
        bridge.inspect_tenderplan_controller_review_closure(
            attempt_id,
            state_path=controller_path,
            tenderplan_store_path=native_path,
            attested_no_dispatch_proof_path=proof_path,
            expected_attested_no_dispatch_proof_sha256="f" * 64,
        )
    assert wrong_pin.value.code == "TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID"
    assert _files(tmp_path) == before


@pytest.mark.parametrize("fault", ["protocol", "boolean-zero"])
def test_re_signed_semantically_false_proof_fails_closed(tmp_path: Path, fault: str) -> None:
    attempt_id, controller_path, native_path, proof_path, _file_sha, _record_sha = (
        _uncertain_fixture(tmp_path)
    )
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    if fault == "protocol":
        proof["claim_before_credential_protocol"]["conclusion"] = "CLAIM_NOT_PROVEN"
    else:
        proof["result"]["credential_read_count"] = False
    proof_path.write_bytes(_canonical(proof))
    proof_file_sha256 = _resign_proof(proof_path)
    before = _files(tmp_path)

    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError) as caught:
        bridge.inspect_tenderplan_controller_review_closure(
            attempt_id,
            state_path=controller_path,
            tenderplan_store_path=native_path,
            attested_no_dispatch_proof_path=proof_path,
            expected_attested_no_dispatch_proof_sha256=proof_file_sha256,
        )

    assert caught.value.code == "TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID"
    assert _files(tmp_path) == before


def test_claimed_uncertain_native_cannot_use_pre_dispatch_attestation(
    tmp_path: Path,
) -> None:
    attempt_id, controller_path, native_path, proof_path, proof_sha, _record_sha = (
        _uncertain_fixture(tmp_path, claimed=True)
    )
    before = _files(tmp_path)

    with pytest.raises(bridge.TenderPlanControllerReviewBridgeError) as caught:
        bridge.inspect_tenderplan_controller_review_closure(
            attempt_id,
            state_path=controller_path,
            tenderplan_store_path=native_path,
            attested_no_dispatch_proof_path=proof_path,
            expected_attested_no_dispatch_proof_sha256=proof_sha,
        )

    assert caught.value.code == "TENDERPLAN_REVIEW_CLOSURE_PROOF_INVALID"
    assert _files(tmp_path) == before
