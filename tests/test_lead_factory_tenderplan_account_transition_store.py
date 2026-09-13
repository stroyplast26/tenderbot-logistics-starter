from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import threading

import pytest

import lead_factory.tenderplan_read_only_store as store_module
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_ACCOUNT_TRANSITION_CONFIRMATION,
    TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
    TenderPlanReadOnlyRunState,
    TenderPlanReadOnlyStore,
    TenderPlanReadOnlyStoreError,
    TenderPlanReadOnlyStoreIntegrityError,
    TenderPlanReadOnlyStoreReconciliationRequired,
    TenderPlanReadOnlyStoreValidationError,
    prepare_tenderplan_account_transition,
    seal_tenderplan_read_only_intent,
    validate_tenderplan_read_only_store,
    verify_worker_intent,
)


NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
LEGACY_RUN = "tpri_" + "1" * 32
NEW_RUN = "tpri_" + "2" * 32


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _new_intent(run_id: str, account: dict | None = None) -> dict:
    return seal_tenderplan_read_only_intent({
        "automatic_schedule_eligible": False,
        "auth_reference_id_sha256": _sha(account["auth_reference_id"].encode("ascii")) if account else "a" * 64,
        "contact_count": 0,
        "credential_target_sha256": account["credential_target_sha256"] if account else "b" * 64,
        "expires_at_utc": "2026-09-11T12:00:00.000000Z",
        "live_release_eligible": False,
        "maximum_records": 5,
        "maximum_response_bytes": 65536,
        "nonce_sha256": "c" * 64,
        "protocol": store_module.TENDERPLAN_READ_ONLY_INTENT_VERSION,
        "query_policy_sha256": "d" * 64,
        "request_count": 1,
        "request_sha256": "e" * 64,
        "requested_at_utc": "2026-09-10T12:00:00.000000Z",
        "run_id": run_id,
        "spend_minor": 0,
        "write_count": 0,
    })


def _claim(path: Path, intent: dict):
    keys = (
        "run_id", "intent_record_sha256", "auth_reference_id_sha256",
        "credential_target_sha256", "nonce_sha256", "query_policy_sha256",
        "request_sha256", "maximum_response_bytes", "maximum_records", "expires_at_utc",
    )
    return verify_worker_intent(path, **{key: intent[key] for key in keys}, clock=lambda: NOW)


def make_transition_fixture(
    tmp_path: Path, *, moved: bool = True, terminal: str = "UNCERTAIN",
) -> tuple[Path, dict, dict]:
    """Synthetic store/profile metadata only; never resolves a credential."""
    origin = tmp_path / "original.sqlite3"
    store = TenderPlanReadOnlyStore(origin, clock=lambda: NOW)
    intent = _new_intent(LEGACY_RUN)
    store.reserve_intent(intent)
    if terminal == "UNCERTAIN":
        _claim(origin, intent)
        store.record_terminal(LEGACY_RUN, state=TenderPlanReadOnlyRunState.UNCERTAIN.value)
    elif terminal == "FAILED_CLOSED":
        store.record_terminal(LEGACY_RUN, state=TenderPlanReadOnlyRunState.FAILED_CLOSED.value)
    elif terminal != "INTENT":
        raise AssertionError(terminal)
    current = tmp_path / "relocated.sqlite3" if moved else origin
    if moved:
        shutil.copyfile(origin, current)
    reference = "authref_" + "3" * 32
    account = {
        "firm_id": "4" * 24,
        "auth_reference_id": reference,
        "credential_target_sha256": _sha((
            "TenderBot/TenderPlan/PAT/resources-personal/v1/" + reference
        ).encode("ascii")),
        "profile_path": str(tmp_path / "connection.json"),
        "profile_sha256": "5" * 64,
        "profile_record_sha256": "6" * 64,
        "verified_at_utc": "2026-09-10T11:01:00+00:00",
        "credential_created_at_utc": "2026-09-10T11:00:00+00:00",
    }
    arguments = {
        "expected_store_sha256": _sha(current.read_bytes()),
        "expected_origin_path_sha256": store_module._path_sha256(origin),
        "expected_store_identity_sha256": store.store_identity_sha256,
        "legacy_run_id": LEGACY_RUN,
        "active_connection": account,
        "owner_confirmation_sha256": "7" * 64,
        "confirmation": TENDERPLAN_ACCOUNT_TRANSITION_CONFIRMATION,
    }
    return current, arguments, intent


def _legacy_rows(path: Path) -> dict:
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return {
            table: [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]
            for table in (
                "tenderplan_read_only_meta", "tenderplan_read_only_operations",
                "tenderplan_read_only_events", "tenderplan_read_only_cards",
                "tenderplan_read_only_decisions",
            )
        }


def test_preview_read_only_then_apply_preserves_complete_history_and_identity(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    before = path.read_bytes()
    rows = _legacy_rows(path)
    files = set(tmp_path.iterdir())
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        validate_tenderplan_read_only_store(path)
    preview = prepare_tenderplan_account_transition(path, **arguments)
    assert preview["state"] == "READY_TO_APPLY"
    assert preview["applied"] is False
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == files
    prepared = prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert prepared["state"] == "PREPARED"
    assert prepared["legacy_outcome_resolved"] is False
    assert prepared["authorizes_live"] is False
    assert _legacy_rows(path) == rows
    report = validate_tenderplan_read_only_store(path)
    assert report["states"]["UNCERTAIN"] == 1
    assert report["active_states"]["UNCERTAIN"] == 0
    assert report["operation_count"] == 1 and report["card_count"] == 0
    assert report["store_identity_sha256"] == arguments["expected_store_identity_sha256"]
    assert report["schema_fingerprint_sha256"] == TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256
    assert report["account_transition"]["active_connection"] == arguments["active_connection"]
    assert report["account_transition"]["record_sha256"] == prepared["account_transition"]["record_sha256"]
    assert TenderPlanReadOnlyStore(path).store_identity_sha256 == arguments["expected_store_identity_sha256"]


def test_new_account_claim_returns_atomic_descriptor_and_new_uncertain_blocks(tmp_path):
    path, arguments, legacy = make_transition_fixture(tmp_path)
    prepare_tenderplan_account_transition(path, **arguments, apply=True)
    store = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(legacy)
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(_new_intent(NEW_RUN))
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        _claim(path, legacy)
    intent = _new_intent(NEW_RUN, arguments["active_connection"])
    assert store.reserve_intent(intent).created is True
    claimed = _claim(path, intent)
    assert claimed.account_connection == arguments["active_connection"]
    assert "authref_" not in repr(claimed)
    claimed.account_connection["firm_id"] = "9" * 24
    assert validate_tenderplan_read_only_store(path)["account_transition"]["active_connection"] == arguments["active_connection"]
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        _claim(path, intent)
    store.record_terminal(NEW_RUN, state=TenderPlanReadOnlyRunState.UNCERTAIN.value)
    report = validate_tenderplan_read_only_store(path)
    assert report["states"]["UNCERTAIN"] == 2
    assert report["active_states"]["UNCERTAIN"] == 1
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(_new_intent("tpri_" + "8" * 32, arguments["active_connection"]))


def test_legacy_v1_output_and_worker_result_unchanged(tmp_path):
    path, _, intent = make_transition_fixture(tmp_path, moved=False, terminal="INTENT")
    report = validate_tenderplan_read_only_store(path)
    assert "active_states" not in report and "account_transition" not in report
    assert _claim(path, intent).account_connection is None


@pytest.mark.parametrize("key", ["expected_store_sha256", "expected_origin_path_sha256", "expected_store_identity_sha256"])
def test_stale_or_wrong_pins_leave_bytes_unchanged(tmp_path, key):
    path, arguments, _ = make_transition_fixture(tmp_path)
    before = path.read_bytes()
    arguments[key] = "f" * 64
    with pytest.raises(TenderPlanReadOnlyStoreError):
        prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert path.read_bytes() == before


@pytest.mark.parametrize("terminal", ["INTENT", "FAILED_CLOSED"])
def test_only_exact_legacy_uncertain_is_eligible(tmp_path, terminal):
    path, arguments, _ = make_transition_fixture(tmp_path, terminal=terminal)
    before = path.read_bytes()
    with pytest.raises(TenderPlanReadOnlyStoreError):
        prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert path.read_bytes() == before


@pytest.mark.parametrize("kind", ["missing", "empty", "unknown", "schema_tamper", "event_tamper"])
def test_missing_unknown_or_tampered_database_never_repaired(tmp_path, kind):
    path, arguments, _ = make_transition_fixture(tmp_path)
    if kind == "missing":
        path.unlink()
    elif kind == "empty":
        path.write_bytes(b"")
    elif kind == "unknown":
        path.unlink()
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE unknown_table(x)")
    elif kind == "schema_tamper":
        with sqlite3.connect(path) as connection:
            connection.execute("DROP TRIGGER trg_tenderplan_read_only_events_no_update")
    elif kind == "event_tamper":
        with sqlite3.connect(path) as connection:
            sql = connection.execute("SELECT sql FROM sqlite_master WHERE name='trg_tenderplan_read_only_events_no_update'").fetchone()[0]
            connection.execute("DROP TRIGGER trg_tenderplan_read_only_events_no_update")
            connection.execute("UPDATE tenderplan_read_only_events SET event_sha256=? WHERE sequence=3", ("f" * 64,))
            connection.execute(sql)
    before = path.read_bytes() if path.exists() else None
    if before is not None:
        arguments["expected_store_sha256"] = _sha(before)
    with pytest.raises(TenderPlanReadOnlyStoreError):
        prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert (path.read_bytes() if path.exists() else None) == before


def test_transition_is_immutable_replay_and_third_path_rejected(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    prepare_tenderplan_account_transition(path, **arguments, apply=True)
    before = path.read_bytes()
    for statement in (
        "DELETE FROM tenderplan_read_only_account_transition",
        "UPDATE tenderplan_read_only_account_transition SET record_json='{}'",
        "INSERT INTO tenderplan_read_only_account_transition SELECT * FROM tenderplan_read_only_account_transition",
    ):
        with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement)
    for apply in (False, True):
        with pytest.raises(TenderPlanReadOnlyStoreError):
            prepare_tenderplan_account_transition(path, **arguments, apply=apply)
    assert path.read_bytes() == before
    copied = tmp_path / "third.sqlite3"
    shutil.copyfile(path, copied)
    for opener in (validate_tenderplan_read_only_store, TenderPlanReadOnlyStore):
        with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
            opener(copied)
    assert copied.read_bytes() == before


def test_apply_failure_rolls_back_schema_record_and_history(tmp_path, monkeypatch):
    path, arguments, _ = make_transition_fixture(tmp_path)
    before = path.read_bytes()
    def fail():
        raise RuntimeError("synthetic commit fault")
    monkeypatch.setattr(store_module, "_before_account_transition_commit", fail)
    with pytest.raises(RuntimeError, match="synthetic commit fault"):
        prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert path.read_bytes() == before
    assert prepare_tenderplan_account_transition(path, **arguments)["state"] == "READY_TO_APPLY"


def test_concurrent_apply_has_exactly_one_winner(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    barrier = threading.Barrier(2)
    def apply():
        barrier.wait()
        try:
            return prepare_tenderplan_account_transition(path, **arguments, apply=True)["state"]
        except TenderPlanReadOnlyStoreError:
            return "REJECTED"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: apply(), range(2)))
    assert sorted(results) == ["PREPARED", "REJECTED"]
    assert validate_tenderplan_read_only_store(path)["operation_count"] == 1


@pytest.mark.parametrize("mutation", ["extra", "missing", "firm", "reference", "target", "relative_path", "timestamp", "reverse_time", "same_reference", "same_target"])
def test_strict_active_descriptor_rejected_without_writes(tmp_path, mutation):
    path, arguments, _ = make_transition_fixture(tmp_path)
    active = arguments["active_connection"]
    if mutation == "extra":
        active["token"] = "synthetic-invalid-field"
    elif mutation == "missing":
        del active["firm_id"]
    elif mutation == "firm":
        active["firm_id"] = "unverified firm name"
    elif mutation == "reference":
        active["auth_reference_id"] = "invalid"
    elif mutation == "target":
        active["credential_target_sha256"] = "0" * 64
    elif mutation == "relative_path":
        active["profile_path"] = "profile.json"
    elif mutation == "timestamp":
        active["verified_at_utc"] = "2026-09-10T11:01:00+03:00"
    elif mutation == "reverse_time":
        active["credential_created_at_utc"] = "2026-09-11T11:01:00Z"
    elif mutation in {"same_reference", "same_target"}:
        # Change the synthetic original intent using its legitimate producer.
        path.unlink()
        origin = tmp_path / "original.sqlite3"
        origin.unlink()
        store = TenderPlanReadOnlyStore(origin, clock=lambda: NOW)
        old = _new_intent(LEGACY_RUN, active)
        if mutation == "same_reference":
            old["credential_target_sha256"] = "b" * 64
        else:
            old["auth_reference_id_sha256"] = "a" * 64
        old.pop("intent_record_sha256")
        old = seal_tenderplan_read_only_intent(old)
        store.reserve_intent(old)
        store.record_terminal(LEGACY_RUN, state=TenderPlanReadOnlyRunState.UNCERTAIN.value)
        shutil.copyfile(origin, path)
        arguments["expected_store_sha256"] = _sha(path.read_bytes())
    before = path.read_bytes()
    with pytest.raises(TenderPlanReadOnlyStoreValidationError):
        prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert path.read_bytes() == before


def test_resealed_transition_cannot_change_frozen_history_or_account(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    prepare_tenderplan_account_transition(path, **arguments, apply=True)
    with sqlite3.connect(path) as connection:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='trg_tenderplan_account_transition_no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER trg_tenderplan_account_transition_no_update")
        record = json.loads(connection.execute("SELECT record_json FROM tenderplan_read_only_account_transition").fetchone()[0])
        record["frozen_manifest"]["history_sha256"] = "f" * 64
        record.pop("record_sha256")
        record["record_sha256"] = store_module._sha256_json(record)
        connection.execute("UPDATE tenderplan_read_only_account_transition SET record_json=?,record_sha256=?", (store_module._canonical_json(record), record["record_sha256"]))
        connection.execute(trigger)
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        validate_tenderplan_read_only_store(path)


def test_hardlink_apply_rejected_without_changing_either_name(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    linked = tmp_path / "hardlink.sqlite3"
    try:
        linked.hardlink_to(path)
    except OSError:
        pytest.skip("filesystem does not support hard links")
    before = path.read_bytes()
    for candidate in (path, linked):
        with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
            prepare_tenderplan_account_transition(candidate, **arguments, apply=True)
    assert path.read_bytes() == linked.read_bytes() == before


@pytest.mark.parametrize("mutation", ["missing", "unknown", "hardlink"])
def test_candidate_changed_between_preview_and_writer_open_fails_closed(tmp_path, monkeypatch, mutation):
    path, arguments, _ = make_transition_fixture(tmp_path)
    original_connect = sqlite3.connect
    changed = False
    changed_bytes = None
    def connect(database, *args, **kwargs):
        nonlocal changed, changed_bytes
        if str(database).endswith("?mode=rw") and not changed:
            changed = True
            if mutation == "hardlink":
                (tmp_path / "racing-hardlink.sqlite3").hardlink_to(path)
                changed_bytes = path.read_bytes()
            else:
                path.unlink()
                if mutation == "unknown":
                    connection = original_connect(path)
                    try:
                        connection.execute("CREATE TABLE racing_unknown(x)")
                        connection.commit()
                    finally:
                        connection.close()
                    changed_bytes = path.read_bytes()
        return original_connect(database, *args, **kwargs)
    monkeypatch.setattr(store_module.sqlite3, "connect", connect)
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert changed
    assert (path.read_bytes() if path.exists() else None) == changed_bytes


def test_stale_v1_writer_cannot_append_foreign_account_after_prepare(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path, moved=False)
    old_writer = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    prepare_tenderplan_account_transition(path, **arguments, apply=True)
    before = path.read_bytes()
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        old_writer.reserve_intent(_new_intent(NEW_RUN))
    assert path.read_bytes() == before
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        old_writer.reserve_intent(_new_intent(NEW_RUN, arguments["active_connection"]))
    fresh = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    assert fresh.reserve_intent(_new_intent(NEW_RUN, arguments["active_connection"])).created


def test_full_verifier_rejects_foreign_account_operation_with_valid_seals(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    prepare_tenderplan_account_transition(path, **arguments, apply=True)
    source = TenderPlanReadOnlyStore(tmp_path / "foreign.sqlite3", clock=lambda: NOW)
    source.reserve_intent(_new_intent(NEW_RUN))
    # Its operation is correctly sealed by the real v1 writer. The v2 verifier
    # rejects its credential binding even before the missing-event check.
    with sqlite3.connect(source.path) as origin:
        operation = origin.execute("SELECT * FROM tenderplan_read_only_operations").fetchone()
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO tenderplan_read_only_operations VALUES(?,?,?,?,?)", operation)
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        validate_tenderplan_read_only_store(path)


def test_expected_transition_pin_rejects_v1_or_different_record_before_insert(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path, moved=False)
    intent = _new_intent(NEW_RUN, arguments["active_connection"])
    before = path.read_bytes()
    v1 = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        v1.reserve_intent(intent, expected_account_transition_sha256="f" * 64)
    assert path.read_bytes() == before
    prepared = prepare_tenderplan_account_transition(path, **arguments, apply=True)
    v2 = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    before = path.read_bytes()
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        v2.reserve_intent(intent, expected_account_transition_sha256="f" * 64)
    assert path.read_bytes() == before
    assert v2.reserve_intent(
        intent, expected_account_transition_sha256=prepared["account_transition"]["record_sha256"]
    ).created


def test_complete_exact_account_pin_bundle_is_accepted_atomically(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path, moved=False)
    prepared = prepare_tenderplan_account_transition(path, **arguments, apply=True)
    account = arguments["active_connection"]
    store = TenderPlanReadOnlyStore(path, clock=lambda: NOW)

    receipt = store.reserve_intent(
        _new_intent(NEW_RUN, account),
        expected_account_transition_sha256=prepared["account_transition"][
            "record_sha256"
        ],
        expected_connection_profile_sha256=account["profile_sha256"],
        expected_connection_profile_record_sha256=account[
            "profile_record_sha256"
        ],
        expected_credential_target_sha256=account["credential_target_sha256"],
    )

    assert receipt.created is True
    assert validate_tenderplan_read_only_store(path)["operation_count"] == 2


def test_pinned_v2_object_rejects_same_path_v1_replacement(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path, moved=False)
    original_v1 = path.read_bytes()
    prepared = prepare_tenderplan_account_transition(path, **arguments, apply=True)
    v2 = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    path.write_bytes(original_v1)
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        v2.reserve_intent(
            _new_intent(NEW_RUN, arguments["active_connection"]),
            expected_account_transition_sha256=prepared["account_transition"]["record_sha256"],
        )
    assert path.read_bytes() == original_v1


def test_two_event_legacy_uncertain_is_frozen_without_reinterpreting_outcome(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path, moved=False, terminal="INTENT")
    store = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    store.record_terminal(LEGACY_RUN, state="UNCERTAIN")
    arguments["expected_store_sha256"] = _sha(path.read_bytes())
    result = prepare_tenderplan_account_transition(path, **arguments, apply=True)
    assert result["account_transition"]["frozen_manifest"]["event_count"] == 2
    report = validate_tenderplan_read_only_store(path)
    assert report["states"]["UNCERTAIN"] == 1 and report["active_states"]["UNCERTAIN"] == 0


def test_transitioned_ready_empty_allows_following_account_intent(tmp_path):
    path, arguments, _ = make_transition_fixture(tmp_path)
    prepare_tenderplan_account_transition(path, **arguments, apply=True)
    store = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    intent = _new_intent(NEW_RUN, arguments["active_connection"])
    store.reserve_intent(intent)
    _claim(path, intent)
    receipt = store_module.seal_tenderplan_read_only_receipt({
        "automatic_schedule_eligible": False,
        "card_count": 0,
        "cards_sha256": _sha(b"[]"),
        "captured_at_utc": intent["requested_at_utc"],
        "contact_count": 0,
        "intent_record_sha256": intent["intent_record_sha256"],
        "live_release_eligible": False,
        "projection_sha256": "8" * 64,
        "provider_reported_count": 0,
        "receipt_version": store_module.TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
        "request_count": 1,
        "request_sha256": intent["request_sha256"],
        "response_body_sha256": "9" * 64,
        "response_byte_count": 16,
        "returned_count": 0,
        "run_id": NEW_RUN,
        "spend_minor": 0,
        "write_count": 0,
    }, ())
    ready = store.commit_ready(NEW_RUN, (), receipt)
    assert ready.item_ids == ()
    assert store.reserve_intent(_new_intent("tpri_" + "8" * 32, arguments["active_connection"])).created
    report = validate_tenderplan_read_only_store(path)
    assert report["active_states"]["READY_FOR_REVIEW"] == 1
    assert report["active_states"]["INTENT"] == 1
    assert report["active_states"]["UNCERTAIN"] == 0
