from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from unittest.mock import patch

import pytest

import lead_factory.source_discovery_control as control
import lead_factory.tenderplan_read_only_intake as intake
import lead_factory.tenderplan_windows_credential as credentials
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedUncertain
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_INTENT_VERSION,
    TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
    TenderPlanReadOnlyStore,
    seal_tenderplan_read_only_intent,
    seal_tenderplan_read_only_receipt,
    validate_tenderplan_read_only_store,
    verify_worker_intent,
)
import scripts.run_source_discovery_once as source_cli
from lead_factory.tenderplan_windows_credential import (
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
    TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
)


NOW = datetime(2026, 8, 28, 22, tzinfo=timezone.utc)
AUTH_REFERENCE = "authref_" + "a" * 32


@pytest.fixture(autouse=True)
def no_external_effects():
    with (
        patch.object(credentials, "_credential_api", side_effect=AssertionError("credential read")),
        patch("subprocess.Popen", side_effect=AssertionError("worker launch")),
        patch.object(intake, "decrypt_tenderplan_card", side_effect=AssertionError("decryption")),
        patch.object(intake, "append_tenderplan_read_only_diagnostic_best_effort"),
        patch.object(
            intake.TenderPlanReadOnlyTransport, "post_registered_search",
            side_effect=AssertionError("provider call"),
        ),
    ):
        yield


def _registration(path: Path) -> None:
    material = {
        "auth_reference_id": AUTH_REFERENCE,
        "credential_target_sha256": hashlib.sha256(
            f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{AUTH_REFERENCE}".encode("ascii")
        ).hexdigest(),
        "live_release_eligible": False,
        "registration_version": TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
        "source_file_retained": True,
        "state": "VERIFIED",
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
    document = {**material, "record_sha256": hashlib.sha256(canonical).hexdigest()}
    path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
        newline="\n",
    )


def _intent() -> dict[str, object]:
    return seal_tenderplan_read_only_intent(
        {
            "automatic_schedule_eligible": False,
            "auth_reference_id_sha256": "1" * 64,
            "contact_count": 0,
            "credential_target_sha256": "2" * 64,
            "expires_at_utc": "2026-08-29T20:00:00.000000Z",
            "live_release_eligible": False,
            "maximum_records": 5,
            "maximum_response_bytes": 65_536,
            "nonce_sha256": "3" * 64,
            "protocol": TENDERPLAN_READ_ONLY_INTENT_VERSION,
            "query_policy_sha256": "4" * 64,
            "request_count": 1,
            "request_sha256": "5" * 64,
            "requested_at_utc": "2026-08-28T22:00:00.000000Z",
            "run_id": "tpri_" + "a" * 32,
            "spend_minor": 0,
            "write_count": 0,
        }
    )


def _claim(queue: Path, intent: dict[str, object]) -> None:
    verify_worker_intent(
        queue,
        clock=lambda: NOW,
        **{
            key: intent[key] for key in (
                "run_id", "intent_record_sha256", "auth_reference_id_sha256",
                "credential_target_sha256", "nonce_sha256", "query_policy_sha256",
                "request_sha256", "maximum_response_bytes", "maximum_records", "expires_at_utc",
            )
        },
    )


@pytest.fixture
def prepared_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    _registration(registration)
    TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    monkeypatch.setattr(intake, "TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH", registration)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    return registration, queue


def test_existing_native_uncertain_blocks_before_controller_reservation(
    tmp_path: Path, prepared_state: tuple[Path, Path],
) -> None:
    registration, queue = prepared_state
    native = TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    intent = _intent()
    native.reserve_intent(intent)
    native.record_terminal(str(intent["run_id"]), "UNCERTAIN")
    before = queue.read_bytes()
    state_path = tmp_path / "control.sqlite3"
    with patch.object(intake.TenderPlanReadOnlyTransport, "post_registered_search") as provider:
        result = control.run_source_discovery_once(
            "TENDERPLAN",
            confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            tenderplan_registration_path=registration,
            tenderplan_store_path=queue,
        )
    assert result["state"] == "BLOCKED_TENDERPLAN_UNCERTAIN"
    assert result["native_runner_call_count"] == 0
    assert result["external_requests_this_run"] == 0
    assert not state_path.exists()
    assert queue.read_bytes() == before
    provider.assert_not_called()


@pytest.mark.parametrize(
    "state,expected",
    [("INTENT", "BLOCKED_TENDERPLAN_IN_FLIGHT"),
     ("DISPATCH_CLAIMED", "BLOCKED_TENDERPLAN_IN_FLIGHT"),
     ("FAILED_CLOSED", "READY_FOR_SEPARATE_AUTHORITY_CHECK")],
)
def test_native_latest_states_are_checked_without_expiry_recovery(
    prepared_state: tuple[Path, Path], state: str, expected: str,
) -> None:
    registration, queue = prepared_state
    store = TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    intent = _intent()
    store.reserve_intent(intent)
    if state == "DISPATCH_CLAIMED":
        _claim(queue, intent)
    elif state == "FAILED_CLOSED":
        store.record_terminal(str(intent["run_id"]), state)
    before = queue.read_bytes()
    result = intake.check_tenderplan_read_only_intake(
        registration_path=registration, store_path=queue,
    )
    assert result["state"] == expected
    assert result["states"][state] == 1
    assert sum(result["states"].values()) == 1
    assert result["authority_verified"] is False
    assert queue.read_bytes() == before


def test_fresh_prepared_queue_is_checked_without_constructor_or_writes(
    tmp_path: Path, prepared_state: tuple[Path, Path],
) -> None:
    registration, queue = prepared_state
    before = {path: path.read_bytes() for path in (registration, queue)}
    files_before = set(tmp_path.iterdir())
    with patch.object(TenderPlanReadOnlyStore, "__init__", side_effect=AssertionError("bootstrap")):
        for _ in range(2):
            result = intake.check_tenderplan_read_only_intake()
            assert result["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
            assert result["authority_verified"] is False
            assert result["request_count"] == result["write_count"] == 0
            assert sum(result["states"].values()) == 0
    assert {path: path.read_bytes() for path in before} == before
    assert set(tmp_path.iterdir()) == files_before
    serialized = json.dumps(result)
    assert AUTH_REFERENCE not in serialized
    assert str(tmp_path) not in serialized


@pytest.mark.parametrize("invalid", [False, True])
def test_missing_or_invalid_registration_is_local_block(
    tmp_path: Path, prepared_state: tuple[Path, Path], invalid: bool,
) -> None:
    _, queue = prepared_state
    registration = tmp_path / "unverified-registration.json"
    if invalid:
        registration.write_text('{"private": "DO_NOT_ECHO"}', encoding="ascii")
    before = queue.read_bytes()
    with patch.object(control, "_reserve") as reserve:
        result = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=tmp_path / "control.sqlite3",
            tenderplan_registration_path=registration, tenderplan_store_path=queue,
        )
    assert result["state"] == "BLOCKED_TENDERPLAN_REGISTRATION"
    assert result["native_runner_call_count"] == 0
    assert not (tmp_path / "control.sqlite3").exists()
    assert queue.read_bytes() == before
    assert "DO_NOT_ECHO" not in json.dumps(result)
    assert str(tmp_path) not in json.dumps(result)
    reserve.assert_not_called()


@pytest.mark.parametrize("damage", ["missing", "empty", "unrelated", "schema", "content", "chain"])
def test_unusable_store_blocks_without_bootstrap_or_controller_reservation(
    tmp_path: Path, prepared_state: tuple[Path, Path], damage: str,
) -> None:
    registration, queue = prepared_state
    if damage == "missing":
        queue.unlink()
    elif damage == "empty":
        queue.write_bytes(b"")
    elif damage == "unrelated":
        queue.write_bytes(b"not a sqlite database")
    elif damage == "schema":
        with sqlite3.connect(queue) as connection:
            connection.execute("PRAGMA user_version=999")
    else:
        store = TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
        intent = _intent()
        store.reserve_intent(intent)
        store.record_terminal(str(intent["run_id"]), "FAILED_CLOSED")
        table, column = (
            ("tenderplan_read_only_operations", "operation_sha256")
            if damage == "content" else ("tenderplan_read_only_events", "previous_event_sha256")
        )
        trigger = f"trg_{table}_no_update"
        with sqlite3.connect(queue) as connection:
            sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,),
            ).fetchone()[0]
            connection.execute(f"DROP TRIGGER {trigger}")
            connection.execute(f"UPDATE {table} SET {column}=?", ("e" * 64,))
            connection.execute(sql)
    before = queue.read_bytes() if queue.exists() else None
    with (
        patch.object(control, "_reserve") as reserve,
        patch.object(TenderPlanReadOnlyStore, "__init__", side_effect=AssertionError("bootstrap")),
    ):
        checked = control.verify_source_discovery_authority(
            "TENDERPLAN", state_path=tmp_path / "control.sqlite3",
            tenderplan_registration_path=registration, tenderplan_store_path=queue,
        )
        result = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=tmp_path / "control.sqlite3",
            tenderplan_registration_path=registration, tenderplan_store_path=queue,
        )
    assert checked["state"] == result["state"] == "BLOCKED_TENDERPLAN_STORE_RECONCILIATION"
    assert result["native_runner_call_count"] == 0
    assert not (tmp_path / "control.sqlite3").exists()
    assert (queue.read_bytes() if queue.exists() else None) == before
    reserve.assert_not_called()


def test_noncanonical_queue_and_moved_binding_both_fail_closed(
    tmp_path: Path, prepared_state: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration, queue = prepared_state
    other = tmp_path / "other.sqlite3"
    TenderPlanReadOnlyStore(other, clock=lambda: NOW)
    result = intake.check_tenderplan_read_only_intake(store_path=other)
    assert result["state"] == "BLOCKED_TENDERPLAN_STORE_LOCATION"
    moved = tmp_path / "moved.sqlite3"
    shutil.copyfile(queue, moved)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", moved)
    before = moved.read_bytes()
    result = control.check_source_discovery(
        "TENDERPLAN", state_path=tmp_path / "control.sqlite3",
        tenderplan_registration_path=registration, tenderplan_store_path=moved,
    )
    assert result["state"] == "BLOCKED_TENDERPLAN_STORE_RECONCILIATION"
    assert moved.read_bytes() == before
    assert not (tmp_path / "control.sqlite3").exists()


def test_cli_check_uses_explicit_native_paths(
    tmp_path: Path, prepared_state: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registration, queue = prepared_state
    monkeypatch.setattr(source_cli, "SOURCE_DISCOVERY_STATE_PATH", tmp_path / "control.sqlite3")
    for registration_arg, store_arg, expected in (
        (registration, queue, "READY_FOR_SEPARATE_AUTHORITY_CHECK"),
        (tmp_path / "missing.json", queue, "BLOCKED_TENDERPLAN_REGISTRATION"),
        (registration, tmp_path / "other.sqlite3", "BLOCKED_TENDERPLAN_STORE_LOCATION"),
    ):
        code = source_cli.main([
            "check", "--source", "TENDERPLAN",
            "--tenderplan-registration", str(registration_arg), "--tenderplan-store", str(store_arg),
        ])
        output = capsys.readouterr()
        result = json.loads(output.out)
        assert result["state"] == expected
        assert result["authority_verified"] is False
        assert code == (2 if expected.startswith("BLOCKED_") else 0)
        assert str(tmp_path) not in output.out + output.err
    assert not (tmp_path / "control.sqlite3").exists()


@pytest.mark.parametrize("race", ["uncertain", "missing", "empty", "replaced"])
def test_readiness_race_remains_uncertain_without_dispatch_or_bootstrap(
    tmp_path: Path, prepared_state: tuple[Path, Path], race: str,
) -> None:
    registration, queue = prepared_state
    original_check = control.check_source_discovery

    def racing_check(*args: object, **kwargs: object) -> dict[str, object]:
        checked = original_check(*args, **kwargs)
        assert checked["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
        if race == "uncertain":
            store = TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
            intent = _intent()
            store.reserve_intent(intent)
            store.record_terminal(str(intent["run_id"]), "UNCERTAIN")
        elif race == "missing":
            queue.unlink()
        elif race == "replaced":
            replacement = tmp_path / "replacement.sqlite3"
            TenderPlanReadOnlyStore(replacement, clock=lambda: NOW)
            shutil.copyfile(replacement, queue)
        else:
            queue.write_bytes(b"")
        return checked

    with (
        patch.object(control, "check_source_discovery", side_effect=racing_check),
        patch.object(intake.TenderPlanReadOnlyTransport, "post_registered_search") as provider,
    ):
        result = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=tmp_path / "control.sqlite3",
            tenderplan_registration_path=registration, tenderplan_store_path=queue,
        )
    assert result["state"] == "UNCERTAIN"
    assert result["control"]["attempt_count"] == result["control"]["uncertain_count"] == 1
    provider.assert_not_called()
    if race == "missing":
        assert not queue.exists()
    elif race == "empty":
        assert queue.read_bytes() == b""
    elif race == "replaced":
        assert queue.read_bytes() == (tmp_path / "replacement.sqlite3").read_bytes()
    else:
        assert validate_tenderplan_read_only_store(queue)["operation_count"] == 1


def test_completed_run_is_ready_but_next_unresolved_run_is_still_blocked(
    prepared_state: tuple[Path, Path],
) -> None:
    _, queue = prepared_state
    store = TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    intent = _intent()
    store.reserve_intent(intent)
    _claim(queue, intent)
    receipt = seal_tenderplan_read_only_receipt(
        {
            "automatic_schedule_eligible": False,
            "card_count": 0,
            "cards_sha256": hashlib.sha256(b"[]").hexdigest(),
            "captured_at_utc": intent["requested_at_utc"],
            "contact_count": 0,
            "intent_record_sha256": intent["intent_record_sha256"],
            "live_release_eligible": False,
            "projection_sha256": "6" * 64,
            "provider_reported_count": 0,
            "receipt_version": TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
            "request_count": 1,
            "request_sha256": intent["request_sha256"],
            "response_body_sha256": "7" * 64,
            "response_byte_count": 20,
            "returned_count": 0,
            "run_id": intent["run_id"],
            "spend_minor": 0,
            "write_count": 0,
        }, (),
    )
    store.commit_ready(str(intent["run_id"]), (), receipt)
    checked = intake.check_tenderplan_read_only_intake()
    assert checked["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert checked["states"]["READY_FOR_REVIEW"] == 1
    assert checked["states"]["INTENT"] == checked["states"]["DISPATCH_CLAIMED"] == 0
    next_material = dict(intent)
    next_material.pop("intent_record_sha256")
    next_material["run_id"] = "tpri_" + "b" * 32
    next_intent = seal_tenderplan_read_only_intent(next_material)
    store.reserve_intent(next_intent)
    store.record_terminal(str(next_intent["run_id"]), "UNCERTAIN")
    before = queue.read_bytes()
    blocked = intake.check_tenderplan_read_only_intake()
    assert blocked["state"] == "BLOCKED_TENDERPLAN_UNCERTAIN"
    assert blocked["states"]["READY_FOR_REVIEW"] == blocked["states"]["UNCERTAIN"] == 1
    assert queue.read_bytes() == before


def test_postdispatch_fault_keeps_both_native_and_controller_uncertain(
    tmp_path: Path, prepared_state: tuple[Path, Path],
) -> None:
    registration, queue = prepared_state

    def claimed_failure(query: str, reference: str, **values: object) -> None:
        assert query == "окна"
        verify_worker_intent(
            queue, auth_reference_id_sha256=hashlib.sha256(reference.encode("ascii")).hexdigest(),
            **values,
        )
        raise TenderPlanIsolatedUncertain("PRIVATE_ERROR_MUST_NOT_ESCAPE")

    state_path = tmp_path / "control.sqlite3"
    with patch.object(
        intake.TenderPlanReadOnlyTransport, "post_registered_search", side_effect=claimed_failure,
    ) as provider:
        result = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            tenderplan_registration_path=registration, tenderplan_store_path=queue,
        )
    assert provider.call_count == 1
    assert result["state"] == "UNCERTAIN"
    assert "PRIVATE_ERROR_MUST_NOT_ESCAPE" not in json.dumps(result)
    summary = validate_tenderplan_read_only_store(queue)
    assert summary["states"]["UNCERTAIN"] == 1
    assert summary["event_count"] == 3  # intent, dispatch claim, uncertain
    before = queue.read_bytes(), state_path.read_bytes()
    with patch.object(control, "check_tenderplan_read_only_intake") as preflight:
        blocked = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            tenderplan_registration_path=registration, tenderplan_store_path=queue,
        )
    assert blocked["state"] == "BLOCKED_UNCERTAIN"
    assert (queue.read_bytes(), state_path.read_bytes()) == before
    preflight.assert_not_called()
