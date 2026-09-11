from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
from threading import Event
from unittest.mock import patch

import pytest

from lead_factory.radar_yandex_connection import ManualYandexSearchOutcome
from lead_factory.radar_yandex_connection_authority import ManualYandexSearchBinding
from lead_factory.radar_yandex_search import SearchHit, SearchPage, SearchRequest
from lead_factory.radar_yandex_transport import YandexTransportError
import lead_factory.source_discovery_control as control
from lead_factory.source_discovery_control import (
    SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
    SourceDiscoveryControlError,
    check_source_discovery,
    run_source_discovery_once,
    source_discovery_plan,
    source_discovery_status,
)
from lead_factory.tenderplan_read_only_intake import (
    TENDERPLAN_READ_ONLY_CONFIRMATION,
    TenderPlanReadOnlyIntakeResult,
)
import scripts.run_source_discovery_once as source_cli


def _page(query: str, *, hits: int = 1) -> SearchPage:
    values = tuple(
        SearchHit(
            rank=index + 1,
            url=f"https://secret.example/{index}",
            url_key=f"https://secret.example/{index}",
            title="RAW SECRET TITLE",
            passages=("RAW SECRET PAYLOAD",),
            provider_modtime="",
        )
        for index in range(hits)
    )
    return SearchPage(
        request=SearchRequest(query, "Москва"),
        received_at_utc="2026-09-10T00:00:00Z",
        response_sha256="a" * 64,
        hits=values,
        status="RESULTS" if values else "NO_RESULTS",
    )


def _accounted_page(
    query: str,
    *,
    hits: int = 1,
    external_requests: int = 1,
) -> ManualYandexSearchOutcome:
    return ManualYandexSearchOutcome(
        page=_page(query, hits=hits),
        external_requests_this_run=external_requests,
        journal={
            "policy_sha256": "f" * 64,
            "stopped": False,
            "expires_at_utc": "2026-09-11T23:59:59Z",
            "attempts_reserved": 1,
            "max_requests": 1,
            "reserved_cost_minor": 49,
            "remaining_cost_minor": 0,
            "currency": "RUB",
            "cost_semantics": "UPPER_ESTIMATE_NOT_INVOICE",
            "states": {
                "RESERVED": 0,
                "DISPATCH_INTENT": 0,
                "UNCERTAIN": 0,
                "COMPLETED": 1,
            },
            "retained_responses": 1,
            "live_authority_granted": False,
        },
    )


def _uncertain_journal() -> dict[str, object]:
    return {
        "policy_sha256": "f" * 64,
        "stopped": False,
        "expires_at_utc": "2026-09-11T23:59:59Z",
        "attempts_reserved": 1,
        "max_requests": 1,
        "reserved_cost_minor": 49,
        "remaining_cost_minor": 0,
        "currency": "RUB",
        "cost_semantics": "UPPER_ESTIMATE_NOT_INVOICE",
        "states": {
            "RESERVED": 0,
            "DISPATCH_INTENT": 0,
            "UNCERTAIN": 1,
            "COMPLETED": 0,
        },
        "retained_responses": 0,
        "live_authority_granted": False,
    }


def _binding() -> ManualYandexSearchBinding:
    return ManualYandexSearchBinding(
        job_id="11111111-1111-4111-8111-111111111111",
        job_sha256="1" * 64,
        policy_sha256="2" * 64,
        connection_sha256="3" * 64,
        journal_path_sha256="4" * 64,
        journal_identity_sha256="5" * 64,
    )


def _recorded_result(outcome: ManualYandexSearchOutcome):
    def fake_runner(
        _job_path: object,
        *,
        folder_id: object,
        credential_loader: object,
        binding_recorder: object,
    ) -> ManualYandexSearchOutcome:
        assert folder_id == "folder"
        assert callable(credential_loader)
        assert callable(binding_recorder)
        binding_recorder(_binding())
        return outcome

    return fake_runner


def _recorded_failure(error: BaseException):
    def fake_runner(
        _job_path: object,
        *,
        folder_id: object,
        credential_loader: object,
        binding_recorder: object,
    ) -> ManualYandexSearchOutcome:
        assert folder_id == "folder"
        assert callable(credential_loader)
        assert callable(binding_recorder)
        binding_recorder(_binding())
        raise error

    return fake_runner


def _tenderplan_result(*, queued_count: int = 1) -> TenderPlanReadOnlyIntakeResult:
    return TenderPlanReadOnlyIntakeResult(
        run_id="tpri_" + "a" * 32,
        state="READY_FOR_REVIEW",
        receipt_record_sha256="b" * 64,
        event_sha256="c" * 64,
        provider_reported_count=queued_count,
        returned_count=queued_count,
        queued_count=queued_count,
        item_ids=tuple(f"item_{index}" for index in range(queued_count)),
    )


def _serialized(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def test_plan_status_and_check_are_local_only_and_idempotent(tmp_path: Path) -> None:
    state_path = tmp_path / "control.sqlite3"
    with (
        patch(
            "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
            side_effect=AssertionError("network runner called"),
        ),
        patch(
            "lead_factory.source_discovery_control.run_tenderplan_read_only_intake",
            side_effect=AssertionError("network runner called"),
        ),
    ):
        first_plan = source_discovery_plan()
        first_status = source_discovery_status(state_path=state_path)
        second_status = source_discovery_status(state_path=state_path)
        checked = check_source_discovery(
            "YANDEX",
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    assert first_plan["sources"]["SABY"] == "BLOCKED_OFFLINE_CONTRACT"
    assert first_plan["pilot_cap"] == 1
    assert first_plan["manual_reconciliation_required_after_nonempty_batch"] is True
    assert first_plan["effects"]["campaign_spend_enabled"] is False
    assert first_plan["effects"]["provider_read_may_be_metered"] is True
    assert first_plan["effects"]["native_metering_governed"] is True
    assert first_status == second_status
    assert checked["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert not state_path.exists()


def test_yandex_delegates_exactly_once_and_report_is_sanitized(tmp_path: Path) -> None:
    state_path = tmp_path / "control.sqlite3"
    secret_query = "QUERY MUST NEVER APPEAR"
    calls: list[tuple[object, object]] = []

    def fake_runner(
        job_path: object,
        *,
        folder_id: object,
        credential_loader: object,
        binding_recorder: object,
    ) -> ManualYandexSearchOutcome:
        calls.append((job_path, folder_id))
        assert callable(credential_loader)
        assert callable(binding_recorder)
        binding_recorder(_binding())
        return _accounted_page(secret_query)

    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
        side_effect=fake_runner,
    ):
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    assert len(calls) == 1
    assert report["native_runner_call_count"] == 1
    assert report["external_requests_this_run"] == 1
    assert report["journal"]["accounting_status"] == "VERIFIED"
    assert report["state"] == "READY_FOR_REVIEW"
    assert report["control"]["manual_reconciliation_required"] is True
    reconciliation = report["control"]["latest"]["yandex_reconciliation"]
    assert reconciliation["job_id"] == _binding().job_id
    assert reconciliation["policy_sha256"] == _binding().policy_sha256
    assert reconciliation["journal_path_sha256"] == _binding().journal_path_sha256
    assert len(reconciliation["binding_receipt_sha256"]) == 64
    assert len(reconciliation["accounting_receipt_sha256"]) == 64
    assert reconciliation["accounting_outcome"] == "COMPLETED"
    assert reconciliation["external_requests_this_run"] == 1
    assert "connection_sha256" not in reconciliation
    safe = _serialized(report)
    assert secret_query not in safe
    assert "RAW SECRET" not in safe
    assert "secret.example" not in safe
    assert source_discovery_status(state_path=state_path) == source_discovery_status(
        state_path=state_path
    )
    assert secret_query.encode() not in state_path.read_bytes()


def test_status_exposes_sanitized_binding_and_linked_accounting_after_crash(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    attempt_id, blocked = control._reserve(  # noqa: SLF001
        state_path,
        control.SourceDiscoverySource.YANDEX,
        1,
    )
    assert attempt_id is not None
    assert blocked is None
    control._record_yandex_binding(state_path, attempt_id, _binding())  # noqa: SLF001

    after_binding = source_discovery_status(state_path=state_path)
    latest = after_binding["control"]["latest"]
    assert latest["state"] == "RUNNING"
    reconciliation = latest["yandex_reconciliation"]
    assert reconciliation["job_id"] == _binding().job_id
    assert reconciliation["policy_sha256"] == _binding().policy_sha256
    assert reconciliation["journal_path_sha256"] == _binding().journal_path_sha256
    assert len(reconciliation["binding_receipt_sha256"]) == 64
    assert reconciliation["accounting_receipt_sha256"] == ""
    assert reconciliation["accounting_outcome"] == ""
    assert reconciliation["external_requests_this_run"] is None

    external, sanitized = control._validated_yandex_accounting(  # noqa: SLF001
        _accounted_page("hidden", hits=0, external_requests=0).external_requests_this_run,
        _accounted_page("hidden", hits=0, external_requests=0).journal,
        completed=True,
    )
    control._record_yandex_accounting(  # noqa: SLF001
        state_path,
        attempt_id,
        external,
        sanitized,
        outcome="COMPLETED",
    )
    after_accounting = source_discovery_status(state_path=state_path)
    reconciliation = after_accounting["control"]["latest"]["yandex_reconciliation"]
    assert reconciliation["accounting_outcome"] == "COMPLETED"
    assert reconciliation["external_requests_this_run"] == 0
    assert len(reconciliation["accounting_receipt_sha256"]) == 64
    with sqlite3.connect(state_path) as connection:
        binding_receipt = connection.execute(
            "SELECT binding_receipt_sha256 FROM source_discovery_yandex_bindings"
        ).fetchone()[0]
        accounting_binding_receipt = connection.execute(
            "SELECT binding_receipt_sha256 FROM source_discovery_yandex_accounting"
        ).fetchone()[0]
    assert accounting_binding_receipt == binding_receipt
    serialized = _serialized(after_accounting)
    assert "folder" not in serialized
    assert str(tmp_path) not in serialized


def test_yandex_cache_accounting_reports_zero_without_loading_credential(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    with (
        patch.object(
            control,
            "run_manual_yandex_search_accounted",
            side_effect=_recorded_result(
                _accounted_page("hidden", hits=0, external_requests=0)
            ),
        ) as runner,
        patch.object(
            control,
            "load_yandex_api_key",
            side_effect=AssertionError("controller eagerly loaded credential"),
        ) as broker,
    ):
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_called_once()
    broker.assert_not_called()
    assert callable(runner.call_args.kwargs["credential_loader"])
    assert report["state"] == "COMPLETE_NO_RESULTS"
    assert report["external_requests_this_run"] == 0
    assert report["journal"]["accounting_status"] == "VERIFIED"


def test_yandex_inconsistent_or_missing_accounting_is_durably_uncertain(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    invalid = ManualYandexSearchOutcome(
        page=_page("hidden", hits=0),
        external_requests_this_run=1,
        journal={"accounting_status": "UNAVAILABLE"},
    )
    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_result(invalid),
    ):
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    assert report["state"] == "UNCERTAIN"
    assert report["external_requests_this_run"] is None
    assert report["journal"] == {"accounting_status": "UNAVAILABLE"}
    assert report["control"]["gate"] == "BLOCKED_UNCERTAIN"


def test_yandex_transport_failure_reports_one_only_with_coherent_journal(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    secret = "PRIVATE RAW FAILURE"
    failure = YandexTransportError(
        secret,
        external_requests_this_run=1,
        journal_status=_uncertain_journal(),
    )
    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_failure(failure),
    ):
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    serialized = _serialized(report)
    assert report["state"] == "UNCERTAIN"
    assert report["external_requests_this_run"] == 1
    assert report["journal"]["accounting_status"] == "VERIFIED"
    assert report["journal"]["states"]["UNCERTAIN"] == 1
    assert secret not in serialized


def test_tenderplan_delegates_exactly_once_without_storing_query(tmp_path: Path) -> None:
    state_path = tmp_path / "control.sqlite3"
    secret_query = "TENDER QUERY MUST NEVER APPEAR"
    calls: list[tuple[object, object]] = []

    def fake_runner(query: object, **options: object) -> TenderPlanReadOnlyIntakeResult:
        calls.append((query, options))
        return _tenderplan_result()

    with patch(
        "lead_factory.source_discovery_control.run_tenderplan_read_only_intake",
        side_effect=fake_runner,
    ):
        report = run_source_discovery_once(
            "TENDERPLAN",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            tenderplan_query=secret_query,
            tenderplan_registration_path=tmp_path / "registration.json",
            tenderplan_store_path=tmp_path / "queue.sqlite3",
        )
    assert len(calls) == 1
    assert calls[0][0] == secret_query
    assert calls[0][1]["confirmation"] == TENDERPLAN_READ_ONLY_CONFIRMATION
    assert calls[0][1]["registration_path"] == tmp_path / "registration.json"
    assert calls[0][1]["store_path"] == tmp_path / "queue.sqlite3"
    assert report["state"] == "READY_FOR_REVIEW"
    assert secret_query not in _serialized(report)
    assert secret_query.encode() not in state_path.read_bytes()


def test_offline_contract_sources_are_explicitly_blocked_without_state(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    with (
        patch(
            "lead_factory.source_discovery_control.run_manual_yandex_search_accounted"
        ) as yandex,
        patch(
            "lead_factory.source_discovery_control.run_tenderplan_read_only_intake"
        ) as tenderplan,
    ):
        reports = [
            run_source_discovery_once(
                source,
                confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
                state_path=state_path,
            )
            for source in ("SABY", "DOMRF", "KONTUR")
        ]
    assert {report["state"] for report in reports} == {
        "BLOCKED_OFFLINE_CONTRACT"
    }
    yandex.assert_not_called()
    tenderplan.assert_not_called()
    assert not state_path.exists()


def test_open_review_batch_applies_backpressure_before_second_call(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
        side_effect=_recorded_result(_accounted_page("hidden")),
    ) as runner:
        first = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
        second = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    assert first["state"] == "READY_FOR_REVIEW"
    assert second["state"] == "BLOCKED_BACKPRESSURE"
    assert runner.call_count == 1


def test_reservation_block_reason_survives_late_ready_snapshot_and_cli_exits_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_path = tmp_path / "control.sqlite3"
    entered = Event()
    release = Event()
    finished = Event()
    snapshot_race_triggered = Event()
    original_finish = control._finish
    original_snapshot = control._snapshot

    def slow_runner(
        _job_path: object,
        *,
        folder_id: object,
        credential_loader: object,
        binding_recorder: object,
    ) -> ManualYandexSearchOutcome:
        assert folder_id == "folder"
        assert callable(credential_loader)
        assert callable(binding_recorder)
        binding_recorder(_binding())
        entered.set()
        assert release.wait(timeout=5)
        return _accounted_page("hidden", hits=0)

    def signaling_finish(
        path: Path,
        attempt_id: str,
        state: str,
        review_count: int,
    ) -> None:
        original_finish(path, attempt_id, state, review_count)
        if state == "COMPLETE_NO_RESULTS":
            finished.set()

    def racing_snapshot(
        path: Path,
        wip_limit: int,
    ) -> dict[str, object]:
        if not snapshot_race_triggered.is_set():
            snapshot_race_triggered.set()
            release.set()
            assert finished.wait(timeout=5)
        return original_snapshot(path, wip_limit)

    with (
        patch.object(
            control,
            "check_source_discovery",
            return_value={"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK"},
        ),
        patch.object(
            control,
            "run_manual_yandex_search_accounted",
            side_effect=slow_runner,
        ) as runner,
        patch.object(control, "_finish", side_effect=signaling_finish),
        patch.object(control, "_snapshot", side_effect=racing_snapshot),
    ):
        with ThreadPoolExecutor(max_workers=1) as pool:
            first_future = pool.submit(
                run_source_discovery_once,
                "YANDEX",
                confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
                state_path=state_path,
                yandex_job_path=tmp_path / "job.json",
                folder_id="folder",
            )
            assert entered.wait(timeout=5)
            second = run_source_discovery_once(
                "TENDERPLAN",
                confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
                state_path=state_path,
                tenderplan_query="hidden",
            )
            first = first_future.result(timeout=5)
    assert runner.call_count == 1
    assert snapshot_race_triggered.is_set()
    assert second["state"] == "BLOCKED_IN_FLIGHT"
    assert second["native_runner_call_count"] == 0
    assert second["external_requests_this_run"] == 0
    assert second["control"]["gate"] == "READY"
    assert first["state"] == "COMPLETE_NO_RESULTS"

    with patch.object(
        source_cli, "run_source_discovery_once", return_value=second
    ) as cli_runner, patch.dict(
        os.environ,
        {
            source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME:
                source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE
        },
    ):
        exit_code = source_cli.main(
            [
                "run-one",
                "--source",
                "TENDERPLAN",
                "--confirm-one-authorized-read",
            ]
        )
    assert exit_code == 2
    cli_runner.assert_called_once()
    assert json.loads(capsys.readouterr().out)["state"] == "BLOCKED_IN_FLIGHT"


def test_uncertain_result_blocks_every_new_source_call_and_hides_error(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    secret = "TOKEN AND RAW RESPONSE MUST NEVER APPEAR"
    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
        side_effect=RuntimeError(secret),
    ) as yandex:
        uncertain = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    with patch(
        "lead_factory.source_discovery_control.run_tenderplan_read_only_intake"
    ) as tenderplan:
        blocked = run_source_discovery_once(
            "TENDERPLAN",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            tenderplan_query="another hidden query",
        )
    assert yandex.call_count == 1
    tenderplan.assert_not_called()
    assert uncertain["state"] == "UNCERTAIN"
    assert uncertain["external_requests_this_run"] is None
    assert uncertain["journal"] == {"accounting_status": "UNAVAILABLE"}
    assert blocked["state"] == "BLOCKED_UNCERTAIN"
    assert secret not in _serialized(uncertain)
    assert secret.encode() not in state_path.read_bytes()


def test_keyboard_interrupt_after_reservation_is_durably_uncertain(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
        side_effect=KeyboardInterrupt,
    ) as runner:
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    assert runner.call_count == 1
    assert report["state"] == "UNCERTAIN"
    assert report["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert source_discovery_status(state_path=state_path)["control"]["gate"] == (
        "BLOCKED_UNCERTAIN"
    )


def test_yandex_rejected_hits_do_not_create_false_review_backpressure(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "control.sqlite3"
    page = SearchPage(
        request=SearchRequest("hidden", "Москва"),
        received_at_utc="2026-09-10T00:00:00Z",
        response_sha256="d" * 64,
        hits=(
            SearchHit(
                rank=1,
                url="",
                url_key="",
                title="RAW SECRET TITLE",
                passages=("RAW SECRET PAYLOAD",),
                provider_modtime="",
                rejection_reason="MISSING_OR_UNSAFE_URL",
            ),
        ),
        status="RESULTS",
    )
    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
        side_effect=_recorded_result(
            ManualYandexSearchOutcome(
                page=page,
                external_requests_this_run=1,
                journal=_accounted_page("hidden").journal,
            )
        ),
    ):
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    assert report["state"] == "COMPLETE_NO_RESULTS"
    assert report["review_count"] == 0
    assert report["control"]["gate"] == "READY"
    assert "RAW SECRET" not in _serialized(report)
    assert b"RAW SECRET" not in state_path.read_bytes()


def test_state_path_rejects_lexical_symlink_before_resolve(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    link = tmp_path / "state-link.sqlite3"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlink creation is unavailable for this test user")
    with pytest.raises(SourceDiscoveryControlError) as captured:
        source_discovery_status(state_path=link)
    assert captured.value.code == "CONTROL_STATE_PATH_INVALID"


def test_status_waits_for_first_writer_schema_visibility(tmp_path: Path) -> None:
    state_path = tmp_path / "control.sqlite3"
    state_path.touch()
    initialized = False

    def finish_initialization(_seconds: float) -> None:
        nonlocal initialized
        if initialized:
            return
        initialized = True
        connection = control._open_for_write(state_path)
        connection.close()

    with patch(
        "lead_factory.source_discovery_control.time.sleep",
        side_effect=finish_initialization,
    ) as sleeper:
        report = source_discovery_status(state_path=state_path)
    assert sleeper.call_count == 1
    assert report["control"]["gate"] == "READY"


def test_cli_status_uses_canonical_state_and_exits_attention_for_nested_gate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch.object(
        source_cli,
        "source_discovery_status",
        return_value={"control": {"gate": "BLOCKED_UNCERTAIN"}},
    ) as status:
        exit_code = source_cli.main(["status"])
    assert exit_code == 2
    status.assert_called_once_with(
        state_path=source_cli.SOURCE_DISCOVERY_STATE_PATH,
        wip_limit=1,
    )
    assert json.loads(capsys.readouterr().out)["control"]["gate"] == (
        "BLOCKED_UNCERTAIN"
    )


def test_cli_rejects_alternate_state_path() -> None:
    with pytest.raises(SystemExit) as captured:
        source_cli.main(["status", "--state-path", "alternate.sqlite3"])
    assert captured.value.code == 2


def test_missing_confirmation_fails_before_state_or_delegate(tmp_path: Path) -> None:
    state_path = tmp_path / "control.sqlite3"
    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted"
    ) as runner:
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=None,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    runner.assert_not_called()
    assert report["state"] == "BLOCKED_EXPLICIT_CONFIRMATION_REQUIRED"
    assert not state_path.exists()


def test_tampered_metadata_is_rejected_instead_of_echoed(tmp_path: Path) -> None:
    state_path = tmp_path / "control.sqlite3"
    with patch(
        "lead_factory.source_discovery_control.run_manual_yandex_search_accounted",
        side_effect=_recorded_result(_accounted_page("hidden", hits=0)),
    ):
        run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "job.json",
            folder_id="folder",
        )
    secret = "RAW QUERY FROM TAMPERED STATE"
    with sqlite3.connect(state_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE source_discovery_attempts SET attempt_id=?", (secret,)
        )
    try:
        source_discovery_status(state_path=state_path)
    except SourceDiscoveryControlError as error:
        assert error.code == "CONTROL_STATE_INTEGRITY_FAILED"
        assert secret not in str(error)
    else:
        raise AssertionError("tampered metadata was accepted")
