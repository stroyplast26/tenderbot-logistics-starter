from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

import lead_factory.tenderplan_read_only_intake as intake


PIN = "a" * 64
NOW = datetime(2026, 9, 14, 14, tzinfo=timezone.utc)


@pytest.fixture
def isolated_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(intake, "_verified_account_registration", lambda _path: None)
    monkeypatch.setattr(
        intake, "_verified_registration_safe", lambda _path: ("authref_" + "a" * 32, "b" * 64),
    )


@pytest.mark.parametrize("pin", [None, PIN])
def test_check_preserves_native_rejection_and_threads_only_explicit_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_registration: None,
    pin: str | None,
) -> None:
    queue = tmp_path / "not-created.sqlite3"
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    native_check = Mock(side_effect=intake.TenderPlanReadOnlyStoreError)
    monkeypatch.setattr(intake, "validate_tenderplan_read_only_store", native_check)

    result = intake.check_tenderplan_read_only_intake(
        store_path=queue, expected_no_dispatch_admission_set_sha256=pin,
    )

    options = {} if pin is None else {"expected_no_dispatch_admission_set_sha256": pin}
    native_check.assert_called_once_with(queue, **options)
    assert result["state"] == "BLOCKED_TENDERPLAN_STORE_RECONCILIATION"
    assert result["request_count"] == result["write_count"] == 0
    assert not queue.exists()


@pytest.mark.parametrize("pin", [None, PIN])
def test_reservation_revalidates_exact_pin_before_any_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_registration: None,
    pin: str | None,
) -> None:
    queue = tmp_path / "not-created.sqlite3"
    store = Mock()
    store.reserve_intent.side_effect = intake.TenderPlanReadOnlyStoreError
    existing = Mock(return_value=store)
    monkeypatch.setattr(intake, "_existing_store", existing)
    transport = Mock(side_effect=AssertionError("transport must remain untouched"))
    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", transport)

    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "алюминиевые окна",
            confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue,
            require_existing_store=True,
            clock=lambda: NOW,
            expected_no_dispatch_admission_set_sha256=pin,
        )

    assert store.reserve_intent.call_count == 1
    passed = store.reserve_intent.call_args.kwargs
    if pin is None:
        assert "expected_no_dispatch_admission_set_sha256" not in passed
    else:
        assert passed["expected_no_dispatch_admission_set_sha256"] == pin
    assert existing.call_args.args == (queue,)
    transport.assert_not_called()
    assert not queue.exists()


@pytest.mark.parametrize(
    "pin,returned_pin,include_states,expected",
    [
        (None, PIN, True, "BLOCKED_TENDERPLAN_UNCERTAIN"),
        (PIN, PIN, True, "READY_FOR_SEPARATE_AUTHORITY_CHECK"),
        (PIN, "c" * 64, True, "BLOCKED_TENDERPLAN_STORE_RECONCILIATION"),
        (PIN, PIN, False, "BLOCKED_TENDERPLAN_STORE_RECONCILIATION"),
    ],
)
def test_check_uses_separate_admitted_states_only_with_matching_explicit_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, isolated_registration: None,
    pin: str | None, returned_pin: str, include_states: bool, expected: str,
) -> None:
    queue = tmp_path / "not-created.sqlite3"
    raw_states = {state.value: 0 for state in intake.TenderPlanReadOnlyRunState}
    raw_states["UNCERTAIN"] = 1
    scoped_states = {**raw_states, "UNCERTAIN": 0}
    validated = {
        "states": raw_states,
        "active_states": dict(raw_states),
        "account_transition": {"record_sha256": "d" * 64},
        "no_dispatch_admission_set_sha256": returned_pin,
    }
    if include_states:
        validated["no_dispatch_admission_states"] = scoped_states
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(intake, "validate_tenderplan_read_only_store", Mock(return_value=validated))

    result = intake.check_tenderplan_read_only_intake(
        store_path=queue, expected_no_dispatch_admission_set_sha256=pin,
    )

    assert result["state"] == expected
    assert result["states"]["UNCERTAIN"] == result["active_states"]["UNCERTAIN"] == 1
    if expected == "READY_FOR_SEPARATE_AUTHORITY_CHECK":
        assert result["no_dispatch_admission_states"]["UNCERTAIN"] == 0
        assert result["no_dispatch_admission_set_sha256"] == PIN
    else:
        assert "no_dispatch_admission_states" not in result
    assert not queue.exists()
