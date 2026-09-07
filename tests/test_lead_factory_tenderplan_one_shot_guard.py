from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
from threading import Event, Lock

import pytest

from lead_factory.tenderplan_one_shot_guard import (
    TENDERPLAN_ONE_SHOT_APPLICATION_ID,
    TENDERPLAN_ONE_SHOT_OPERATION_ID,
    TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256,
    TENDERPLAN_ONE_SHOT_SCHEMA_VERSION,
    TenderPlanOneShotBinding,
    TenderPlanOneShotConflict,
    TenderPlanOneShotGuard,
    TenderPlanOneShotIntegrityError,
    TenderPlanOneShotReconciliationRequired,
    TenderPlanOneShotState,
    TenderPlanOneShotStopped,
    TenderPlanOneShotSuccessEvidence,
    TenderPlanOneShotUncertain,
    TenderPlanOneShotUncertainReason,
    TenderPlanOneShotValidationError,
    tenderplan_one_shot_binding_sha256,
)


HEX = tuple(character * 64 for character in "0123456789abcdef")
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
_DEFAULT_LIVE_FENCE = TenderPlanOneShotGuard._assert_live_admission


@pytest.fixture(autouse=True)
def _offline_state_machine_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests may exercise storage transitions; production remains default-off."""

    monkeypatch.setattr(
        TenderPlanOneShotGuard,
        "_assert_live_admission",
        lambda _self, _binding: None,
    )


def _binding(**changes: str) -> TenderPlanOneShotBinding:
    value = TenderPlanOneShotBinding(
        operation_id=TENDERPLAN_ONE_SHOT_OPERATION_ID,
        command_sha256=HEX[1],
        authorization_sha256=HEX[2],
        authorization_receipt_sha256=HEX[3],
        external_admission_sha256=HEX[4],
        stop_policy_sha256=HEX[5],
        source_read_epoch_sha256=HEX[6],
        passport_sha256=HEX[7],
        stream_sha256=HEX[8],
        query_policy_sha256=HEX[9],
        auth_reference_sha256=HEX[10],
    )
    return replace(value, **changes)


def _evidence(**changes: object) -> TenderPlanOneShotSuccessEvidence:
    value = TenderPlanOneShotSuccessEvidence(
        response_body_sha256=HEX[11],
        projection_sha256=HEX[12],
        upstream_receipt_sha256=HEX[13],
        record_count=1,
        byte_count=4_096,
    )
    return replace(value, **changes)


def _guard(path: Path, *, clock=None) -> TenderPlanOneShotGuard:
    return TenderPlanOneShotGuard(path, clock=clock or (lambda: NOW))


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    return connection


def test_new_store_is_path_bound_default_off_and_contains_no_sensitive_columns(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guard.sqlite3"
    guard = _guard(path)

    assert guard.live_release_eligible is False
    assert guard.authorizes_live is False
    assert guard.maximum_provider_entries == 1
    assert (guard.write_count, guard.contact_count, guard.spend_minor) == (0, 0, 0)
    assert len(guard.store_identity_sha256) == 64
    assert "authorizes_live=False" in repr(guard)
    assert "live_release_eligible=False" in repr(guard)

    with _connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == (
            TENDERPLAN_ONE_SHOT_APPLICATION_ID
        )
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            TENDERPLAN_ONE_SHOT_SCHEMA_VERSION
        )
        metadata = dict(
            connection.execute(
                "SELECT key,value FROM tenderplan_one_shot_meta"
            ).fetchall()
        )
        assert metadata["schema_fingerprint_sha256"] == (
            TENDERPLAN_ONE_SHOT_SCHEMA_FINGERPRINT_SHA256
        )
        assert metadata["live_release_eligible"] == "0"
        assert metadata["authorizes_live"] == "0"
        assert metadata["token_material_allowed"] == "0"
        assert metadata["query_text_allowed"] == "0"
        assert metadata["raw_response_allowed"] == "0"
        columns = {
            str(row[1])
            for table in (
                "tenderplan_one_shot_meta",
                "tenderplan_one_shot_intent",
                "tenderplan_one_shot_events",
            )
            for row in connection.execute(f"PRAGMA table_info({table})")
        }
    assert "token" not in columns
    assert "query" not in columns
    assert "raw_response" not in columns


def test_default_live_fence_denies_before_intent_stop_and_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        TenderPlanOneShotGuard,
        "_assert_live_admission",
        _DEFAULT_LIVE_FENCE,
    )
    guard = _guard(tmp_path / "guard.sqlite3")
    stop_calls: list[str] = []
    provider_calls: list[str] = []

    with pytest.raises(TenderPlanOneShotStopped, match="live admission"):
        guard.dispatch(
            _binding(),
            stop_check=lambda _intent: stop_calls.append("stop"),
            provider_entry=lambda _intent: provider_calls.append("provider"),
        )

    assert stop_calls == []
    assert provider_calls == []
    with _connect(guard.path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_one_shot_intent"
            ).fetchone()[0]
            == 0
        )


def test_dispatch_commits_intent_before_stop_and_provider_then_replays_success(
    tmp_path: Path,
) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    binding = _binding()
    order: list[str] = []

    def stop_check(intent) -> None:
        order.append("stop")
        durable = guard.inspect(binding)
        assert durable.state is TenderPlanOneShotState.DISPATCH_INTENT
        assert durable.binding_sha256 == intent.binding_sha256
        assert durable.reconcile_only is True

    def provider_entry(intent):
        order.append("provider")
        durable = guard.inspect(binding)
        assert durable.state is TenderPlanOneShotState.DISPATCH_INTENT
        assert durable.intent_event_sha256 == intent.intent_event_sha256
        return _evidence()

    completed = guard.dispatch(
        binding, stop_check=stop_check, provider_entry=provider_entry
    )

    assert order == ["stop", "provider"]
    assert completed.state is TenderPlanOneShotState.SUCCESS
    assert completed.provider_entered is True
    assert completed.success_evidence_sha256 == _evidence().evidence_sha256
    assert completed.reconcile_only is False
    assert completed.live_release_eligible is False
    assert (completed.write_count, completed.contact_count, completed.spend_minor) == (
        0,
        0,
        0,
    )

    replay_calls: list[str] = []
    replay = _guard(guard.path).dispatch(
        binding,
        stop_check=lambda _intent: replay_calls.append("stop"),
        provider_entry=lambda _intent: replay_calls.append("provider"),
    )
    assert replay.state is TenderPlanOneShotState.SUCCESS
    assert replay.created is False
    assert replay_calls == []


def test_binding_digest_covers_every_authority_and_policy_digest() -> None:
    baseline = _binding()
    baseline_sha = tenderplan_one_shot_binding_sha256(baseline)
    assert baseline.binding_sha256 == baseline_sha
    for field in (
        "command_sha256",
        "authorization_sha256",
        "authorization_receipt_sha256",
        "external_admission_sha256",
        "stop_policy_sha256",
        "source_read_epoch_sha256",
        "passport_sha256",
        "stream_sha256",
        "query_policy_sha256",
        "auth_reference_sha256",
    ):
        assert (
            tenderplan_one_shot_binding_sha256(replace(baseline, **{field: HEX[15]}))
            != baseline_sha
        )
    assert "digest-only" in repr(baseline)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation_id", "other.operation"),
        ("command_sha256", "not-a-hash"),
        ("authorization_sha256", "A" * 64),
        ("query_policy_sha256", "0" * 63),
    ],
)
def test_invalid_binding_fails_before_store_reservation(
    tmp_path: Path, field: str, value: str
) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    with pytest.raises(TenderPlanOneShotValidationError):
        guard.reserve(replace(_binding(), **{field: value}))
    with _connect(guard.path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_one_shot_intent"
            ).fetchone()[0]
            == 0
        )


def test_stop_veto_is_terminal_uncertain_and_never_enters_provider(
    tmp_path: Path,
) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    provider_calls: list[str] = []
    leaked = "secret-stop-detail-that-must-not-cross"

    def stopped(_intent) -> None:
        raise RuntimeError(leaked)

    with pytest.raises(TenderPlanOneShotStopped) as caught:
        guard.dispatch(
            _binding(),
            stop_check=stopped,
            provider_entry=lambda _intent: provider_calls.append("called"),
        )
    assert leaked not in str(caught.value)
    assert provider_calls == []
    record = guard.inspect(_binding())
    assert record.state is TenderPlanOneShotState.UNCERTAIN
    assert record.provider_entered is False
    assert record.uncertain_reason is (
        TenderPlanOneShotUncertainReason.STOP_CHECK_REJECTED
    )
    assert record.reconcile_only is True


def test_stop_callback_cannot_return_positive_authority(tmp_path: Path) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    provider_calls: list[str] = []
    with pytest.raises(TenderPlanOneShotStopped):
        guard.dispatch(
            _binding(),
            stop_check=lambda _intent: True,  # type: ignore[arg-type,return-value]
            provider_entry=lambda _intent: provider_calls.append("called"),
        )
    assert provider_calls == []
    assert guard.inspect(_binding()).state is TenderPlanOneShotState.UNCERTAIN


def test_provider_failure_is_sanitized_terminal_uncertain_and_restart_cannot_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guard.sqlite3"
    guard = _guard(path)
    leaked = "Bearer live-secret-must-never-persist"
    calls = 0

    def provider(_intent):
        nonlocal calls
        calls += 1
        raise RuntimeError(leaked)

    with pytest.raises(TenderPlanOneShotUncertain) as caught:
        guard.dispatch(
            _binding(), stop_check=lambda _intent: None, provider_entry=provider
        )
    assert leaked not in str(caught.value)
    assert calls == 1
    uncertain = guard.inspect(_binding())
    assert uncertain.state is TenderPlanOneShotState.UNCERTAIN
    assert uncertain.provider_entered is True
    assert uncertain.uncertain_reason is (
        TenderPlanOneShotUncertainReason.PROVIDER_OUTCOME_UNKNOWN
    )

    restarted_calls: list[str] = []
    with pytest.raises(TenderPlanOneShotReconciliationRequired):
        _guard(path).dispatch(
            _binding(),
            stop_check=lambda _intent: restarted_calls.append("stop"),
            provider_entry=lambda _intent: restarted_calls.append("provider"),
        )
    assert restarted_calls == []
    assert leaked.encode() not in path.read_bytes()


def test_invalid_provider_evidence_becomes_uncertain_without_storing_values(
    tmp_path: Path,
) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    with pytest.raises(TenderPlanOneShotUncertain):
        guard.dispatch(
            _binding(),
            stop_check=lambda _intent: None,
            provider_entry=lambda _intent: _evidence(record_count=2),
        )
    record = guard.inspect(_binding())
    assert record.state is TenderPlanOneShotState.UNCERTAIN
    assert record.uncertain_reason is (
        TenderPlanOneShotUncertainReason.PROVIDER_EVIDENCE_INVALID
    )
    assert record.success_evidence_sha256 is None


def test_restart_after_committed_intent_is_reconcile_only_without_blind_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guard.sqlite3"
    binding = _binding()
    reserved = _guard(path).reserve(binding)
    assert reserved.created is True
    assert reserved.state is TenderPlanOneShotState.DISPATCH_INTENT

    callbacks: list[str] = []
    restarted = _guard(path)
    with pytest.raises(TenderPlanOneShotReconciliationRequired):
        restarted.dispatch(
            binding,
            stop_check=lambda _intent: callbacks.append("stop"),
            provider_entry=lambda _intent: callbacks.append("provider"),
        )
    assert callbacks == []

    reconciled = restarted.reconcile_success(binding, _evidence())
    assert reconciled.state is TenderPlanOneShotState.SUCCESS
    assert reconciled.provider_entered is True
    final = _guard(path).inspect(binding)
    assert final.state is TenderPlanOneShotState.SUCCESS
    assert final.success_evidence_sha256 == _evidence().evidence_sha256


def test_uncertain_reconciliation_is_terminal_and_idempotent(tmp_path: Path) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    binding = _binding()
    guard.reserve(binding)
    first = guard.reconcile_uncertain(
        binding,
        TenderPlanOneShotUncertainReason.OPERATOR_RECONCILIATION,
        provider_entered=True,
    )
    replay = guard.reconcile_uncertain(
        binding,
        TenderPlanOneShotUncertainReason.OPERATOR_RECONCILIATION,
        provider_entered=True,
    )
    assert first.state is replay.state is TenderPlanOneShotState.UNCERTAIN
    with pytest.raises(TenderPlanOneShotConflict):
        guard.reconcile_success(binding, _evidence())
    with pytest.raises(TenderPlanOneShotConflict):
        guard.reconcile_uncertain(
            binding,
            TenderPlanOneShotUncertainReason.OPERATOR_RECONCILIATION,
            provider_entered=False,
        )


def test_changed_binding_loses_the_single_slot(tmp_path: Path) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    guard.reserve(_binding())
    changed = _binding(query_policy_sha256=HEX[15])
    with pytest.raises(TenderPlanOneShotConflict):
        guard.reserve(changed)
    with pytest.raises(TenderPlanOneShotConflict):
        guard.inspect(changed)


def test_two_process_guards_have_one_provider_winner(tmp_path: Path) -> None:
    path = tmp_path / "guard.sqlite3"
    first = _guard(path)
    second = _guard(path)
    binding = _binding()
    entered = Event()
    release = Event()
    count_lock = Lock()
    provider_count = 0

    def provider(_intent):
        nonlocal provider_count
        with count_lock:
            provider_count += 1
        entered.set()
        assert release.wait(5)
        return _evidence()

    with ThreadPoolExecutor(max_workers=2) as executor:
        future = executor.submit(
            first.dispatch,
            binding,
            stop_check=lambda _intent: None,
            provider_entry=provider,
        )
        assert entered.wait(5)
        with pytest.raises(TenderPlanOneShotReconciliationRequired):
            second.dispatch(
                binding,
                stop_check=lambda _intent: None,
                provider_entry=lambda _intent: _evidence(),
            )
        release.set()
        assert future.result(timeout=5).state is TenderPlanOneShotState.SUCCESS
    assert provider_count == 1


def test_clock_rollback_after_provider_leaves_durable_reconcile_only_intent(
    tmp_path: Path,
) -> None:
    values = iter(
        (
            datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 28, 11, 59, tzinfo=timezone.utc),
            datetime(2026, 8, 28, 11, 59, tzinfo=timezone.utc),
        )
    )
    guard = _guard(tmp_path / "guard.sqlite3", clock=lambda: next(values))
    provider_calls: list[str] = []
    with pytest.raises(TenderPlanOneShotUncertain):
        guard.dispatch(
            _binding(),
            stop_check=lambda _intent: None,
            provider_entry=lambda _intent: (
                provider_calls.append("provider") or _evidence()
            ),
        )
    assert provider_calls == ["provider"]
    assert _guard(guard.path).inspect(_binding()).state is (
        TenderPlanOneShotState.DISPATCH_INTENT
    )
    with pytest.raises(TenderPlanOneShotReconciliationRequired):
        _guard(guard.path).dispatch(
            _binding(),
            stop_check=lambda _intent: None,
            provider_entry=lambda _intent: _evidence(),
        )


def test_copying_store_to_another_path_fails_path_binding(tmp_path: Path) -> None:
    original = tmp_path / "original.sqlite3"
    copied = tmp_path / "copied.sqlite3"
    _guard(original).reserve(_binding())
    shutil.copy2(original, copied)
    with pytest.raises(TenderPlanOneShotIntegrityError):
        _guard(copied)


def test_unknown_existing_sqlite_store_is_never_auto_migrated(tmp_path: Path) -> None:
    path = tmp_path / "unknown.sqlite3"
    with _connect(path) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
    with pytest.raises(TenderPlanOneShotIntegrityError):
        _guard(path)


@pytest.mark.parametrize("tamper", ["version", "record", "schema"])
def test_version_record_and_schema_tamper_fail_closed(
    tmp_path: Path, tamper: str
) -> None:
    path = tmp_path / f"tampered-{tamper}.sqlite3"
    guard = _guard(path)
    guard.reserve(_binding())
    with _connect(path) as connection:
        if tamper == "version":
            connection.execute("PRAGMA user_version=99")
        elif tamper == "record":
            connection.execute(
                "UPDATE tenderplan_one_shot_intent SET record_sha256=? WHERE slot=1",
                (HEX[15],),
            )
        else:
            connection.execute("DROP TRIGGER trg_tenderplan_one_shot_events_no_delete")
    with pytest.raises(TenderPlanOneShotIntegrityError):
        _guard(path)


def test_metadata_and_history_are_physically_immutable(tmp_path: Path) -> None:
    path = tmp_path / "guard.sqlite3"
    guard = _guard(path)
    guard.reserve(_binding())
    with _connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE tenderplan_one_shot_meta SET value='1' WHERE key='authorizes_live'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM tenderplan_one_shot_events")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM tenderplan_one_shot_intent")
    assert guard.inspect(_binding()).state is TenderPlanOneShotState.DISPATCH_INTENT


def test_digest_only_store_never_persists_token_query_or_raw_response(
    tmp_path: Path,
) -> None:
    path = tmp_path / "guard.sqlite3"
    token = "tenderplan-live-token-NEVER-STORE-123"
    query = "secret procurement query phrase NEVER STORE"
    raw_response = '{"orderName":"secret raw tender NEVER STORE"}'
    guard = _guard(path)
    guard.dispatch(
        _binding(),
        stop_check=lambda _intent: None,
        provider_entry=lambda _intent: _evidence(),
    )
    database_bytes = path.read_bytes()
    for forbidden in (token, query, raw_response):
        assert forbidden.encode("utf-8") not in database_bytes
    with _connect(path) as connection:
        binding_json = str(
            connection.execute(
                "SELECT binding_json FROM tenderplan_one_shot_intent"
            ).fetchone()[0]
        )
        evidence_json = str(
            connection.execute(
                "SELECT success_evidence_json FROM tenderplan_one_shot_intent"
            ).fetchone()[0]
        )
    assert "query_policy_sha256" in binding_json
    assert "response_body_sha256" in evidence_json
    assert token not in binding_json + evidence_json
    assert query not in binding_json + evidence_json
    assert raw_response not in binding_json + evidence_json


@pytest.mark.parametrize(
    "changes",
    [
        {"http_status": 201},
        {"write_count": 1},
        {"contact_count": 1},
        {"spend_minor": 1},
        {"live_release_eligible": True},
        {"byte_count": 0},
        {"byte_count": 16_385},
        {"record_count": -1},
    ],
)
def test_success_evidence_cannot_exceed_zero_effect_offline_boundary(
    changes: dict[str, object],
) -> None:
    with pytest.raises(TenderPlanOneShotValidationError):
        _evidence(**changes).evidence_sha256


def test_dispatch_requires_both_external_callbacks_before_reservation(
    tmp_path: Path,
) -> None:
    guard = _guard(tmp_path / "guard.sqlite3")
    with pytest.raises(TenderPlanOneShotValidationError):
        guard.dispatch(
            _binding(),
            stop_check=None,  # type: ignore[arg-type]
            provider_entry=lambda _intent: _evidence(),
        )
    with _connect(guard.path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_one_shot_intent"
            ).fetchone()[0]
            == 0
        )
