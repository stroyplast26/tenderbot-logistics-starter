from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
from unittest.mock import patch

import pytest

from lead_factory.radar_yandex_connection import ManualYandexSearchOutcome
from lead_factory.radar_yandex_connection_authority import ManualYandexSearchBinding
from lead_factory.radar_yandex_search import SearchHit, SearchPage, SearchRequest
from lead_factory.radar_yandex_source_lab_bridge import (
    SOURCE_DISCOVERY_SOURCE_LAB_PATH,
    YandexSourceLabBridgeError,
    decide_yandex_review_candidate,
    list_yandex_review_batch,
    persist_yandex_review_batch,
)
import lead_factory.source_discovery_control as control
from lead_factory.source_discovery_control import (
    SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
    SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
    SourceDiscoveryControlError,
    close_source_discovery_review,
    run_source_discovery_once,
    source_discovery_status,
)


def _controller_review_page(*, hits: int = 2) -> SearchPage:
    values = tuple(
        SearchHit(
            rank=index + 1,
            url=f"https://public.example/project/{index}",
            url_key=f"https://public.example/project/{index}",
            title=f"PRIVATE TITLE {index}",
            passages=(f"PRIVATE SNIPPET {index}",),
            provider_modtime="",
        )
        for index in range(hits)
    )
    return SearchPage(
        request=SearchRequest("PRIVATE QUERY", "PRIVATE REGION"),
        received_at_utc="2026-09-11T00:00:00Z",
        response_sha256="a" * 64,
        hits=values,
        status="RESULTS" if values else "NO_RESULTS",
    )


def _accounted_review_page(*, hits: int = 2) -> ManualYandexSearchOutcome:
    return ManualYandexSearchOutcome(
        page=_controller_review_page(hits=hits),
        external_requests_this_run=1,
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


def _recorded_review_result(outcome: ManualYandexSearchOutcome):
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
        binding_recorder(
            ManualYandexSearchBinding(
                job_id="22222222-2222-4222-8222-222222222222",
                job_sha256="1" * 64,
                policy_sha256="2" * 64,
                connection_sha256="3" * 64,
                journal_path_sha256="4" * 64,
                journal_identity_sha256="5" * 64,
            )
        )
        return outcome

    return fake_runner


def _run_yandex_review_batch(
    tmp_path: Path, *, hits: int = 2
) -> tuple[Path, Path, dict[str, object]]:
    state_path = tmp_path / "source-discovery.sqlite3"
    source_lab_path = state_path.with_name(SOURCE_DISCOVERY_SOURCE_LAB_PATH.name)
    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(_accounted_review_page(hits=hits)),
    ) as runner:
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_called_once()
    return state_path, source_lab_path, report


def _decide_review_item(
    *,
    report: dict[str, object],
    source_lab_path: Path,
    review_id: str,
    state_digest: str,
    decision: str,
    suffix: str,
) -> object:
    return decide_yandex_review_candidate(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
        review_id=review_id,
        expected_state_digest=state_digest,
        reviewer="reviewer_1",
        decision=decision,
        reason="MANUAL_SOURCE_REVIEW",
        evidence_ref=f"evidence://local-review/{suffix}",
        idempotency_key=f"decision_{suffix}",
    )


def test_yandex_review_round_trip_closes_batch_and_releases_backpressure(
    tmp_path: Path,
) -> None:
    state_path, source_lab_path, report = _run_yandex_review_batch(tmp_path)
    assert report["state"] == "READY_FOR_REVIEW"
    assert report["review_count"] == 2
    assert len(str(report["batch_receipt_sha256"])) == 64
    assert str(report["source_lab_batch_id"]).startswith("lf_source_lab_batch_")
    assert report["control"]["gate"] == "BLOCKED_BACKPRESSURE"  # type: ignore[index]

    items = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )
    assert len(items) == 2
    assert {item.url for item in items} == {
        "https://public.example/project/0",
        "https://public.example/project/1",
    }
    predecision_source_lab = tmp_path / "source-lab-predecision.sqlite3"
    shutil.copy2(source_lab_path, predecision_source_lab)
    for index, item in enumerate(items):
        _decide_review_item(
            report=report,
            source_lab_path=source_lab_path,
            review_id=item.review_id,
            state_digest=item.state_digest,
            decision="APPROVE" if index == 0 else "REJECT",
            suffix=str(index),
        )

    closed = close_source_discovery_review(
        attempt_id=str(report["attempt_id"]),
        confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        state_path=state_path,
        actor="operator_1",
        evidence_ref="evidence://local-review/close",
        idempotency_key="close_round_trip",
    )
    assert closed["state"] == "CLOSED_LOCAL"
    assert closed["created"] is True
    assert closed["decision_counts"] == {"APPROVE": 1, "REJECT": 1}
    assert closed["control"]["gate"] == "READY"  # type: ignore[index]
    assert source_discovery_status(state_path=state_path)["control"] == closed["control"]

    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(_accounted_review_page(hits=0)),
    ) as runner:
        next_report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "next-job.json",
            folder_id="folder",
        )
    runner.assert_called_once()
    assert next_report["state"] == "COMPLETE_NO_RESULTS"

    shutil.copy2(predecision_source_lab, source_lab_path)
    with pytest.raises(SourceDiscoveryControlError) as rolled_back:
        source_discovery_status(state_path=state_path)
    assert rolled_back.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"
    with patch.object(control, "run_manual_yandex_search_accounted") as blocked_runner:
        with pytest.raises(SourceDiscoveryControlError) as blocked:
            run_source_discovery_once(
                "YANDEX",
                confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
                state_path=state_path,
                yandex_job_path=tmp_path / "rollback-job.json",
                folder_id="folder",
            )
    blocked_runner.assert_not_called()
    assert blocked.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"


def test_source_lab_swap_after_preflight_fails_before_provider_read(
    tmp_path: Path,
) -> None:
    state_path, source_lab_path, report = _run_yandex_review_batch(tmp_path, hits=1)
    item = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )[0]
    predecision_source_lab = tmp_path / "source-lab-predecision.sqlite3"
    shutil.copy2(source_lab_path, predecision_source_lab)
    _decide_review_item(
        report=report,
        source_lab_path=source_lab_path,
        review_id=item.review_id,
        state_digest=item.state_digest,
        decision="REJECT",
        suffix="swap-after-preflight",
    )
    close_source_discovery_review(
        attempt_id=str(report["attempt_id"]),
        confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        state_path=state_path,
        actor="operator_1",
        evidence_ref="evidence://local-review/swap-after-preflight",
        idempotency_key="close_swap_after_preflight",
    )

    original_reserve = control._reserve  # noqa: SLF001

    def swap_then_reserve(*args: object, **kwargs: object) -> object:
        shutil.copy2(predecision_source_lab, source_lab_path)
        return original_reserve(*args, **kwargs)

    with (
        patch.object(control, "_reserve", side_effect=swap_then_reserve),
        patch.object(control, "run_manual_yandex_search_accounted") as runner,
        pytest.raises(SourceDiscoveryControlError) as blocked,
    ):
        run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "second-job.json",
            folder_id="folder",
        )
    runner.assert_not_called()
    assert blocked.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"


def test_controller_rollback_cannot_orphan_source_lab_batch(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(_accounted_review_page(hits=0)),
    ):
        baseline = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "baseline-job.json",
            folder_id="folder",
        )
    assert baseline["state"] == "COMPLETE_NO_RESULTS"
    controller_backup = tmp_path / "controller-before-batch.sqlite3"
    shutil.copy2(state_path, controller_backup)

    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(_accounted_review_page(hits=1)),
    ):
        batch = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "batch-job.json",
            folder_id="folder",
        )
    assert batch["state"] == "READY_FOR_REVIEW"
    shutil.copy2(controller_backup, state_path)

    with (
        patch.object(control, "run_manual_yandex_search_accounted") as runner,
        pytest.raises(SourceDiscoveryControlError) as blocked,
    ):
        run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "after-rollback-job.json",
            folder_id="folder",
        )
    runner.assert_not_called()
    assert blocked.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"


def test_yandex_bridge_failure_is_uncertain_and_never_retried(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    secret = "PRIVATE BRIDGE EXCEPTION"
    with (
        patch.object(
            control,
            "run_manual_yandex_search_accounted",
            side_effect=_recorded_review_result(_accounted_review_page()),
        ) as runner,
        patch.object(
            control,
            "persist_yandex_review_batch",
            side_effect=RuntimeError(secret),
        ),
    ):
        uncertain = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_called_once()
    assert uncertain["state"] == "UNCERTAIN"
    assert uncertain["error_code"] == "SOURCE_BOUNDARY_UNCERTAIN"
    assert secret not in json.dumps(uncertain)
    assert secret.encode() not in state_path.read_bytes()

    with patch.object(control, "run_manual_yandex_search_accounted") as second_runner:
        blocked = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "second-job.json",
            folder_id="folder",
        )
    second_runner.assert_not_called()
    assert blocked["state"] == "BLOCKED_UNCERTAIN"
    assert blocked["native_runner_call_count"] == 0


def test_committed_batch_link_then_exception_remains_blocked_uncertain(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    original_record_link = control._record_yandex_batch_link  # noqa: SLF001

    def record_link_then_fail(*args: object, **kwargs: object) -> None:
        original_record_link(*args, **kwargs)
        raise RuntimeError("PRIVATE POST-COMMIT FAILURE")

    with (
        patch.object(
            control,
            "run_manual_yandex_search_accounted",
            side_effect=_recorded_review_result(_accounted_review_page(hits=1)),
        ) as runner,
        patch.object(
            control,
            "_record_yandex_batch_link",
            side_effect=record_link_then_fail,
        ),
    ):
        uncertain = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )

    runner.assert_called_once()
    assert uncertain["state"] == "UNCERTAIN"
    assert uncertain["error_code"] == "SOURCE_BOUNDARY_UNCERTAIN"
    assert uncertain["control"]["gate"] == "BLOCKED_UNCERTAIN"  # type: ignore[index]
    assert source_discovery_status(state_path=state_path)["control"]["gate"] == (
        "BLOCKED_UNCERTAIN"
    )

    with patch.object(control, "run_manual_yandex_search_accounted") as second_runner:
        blocked = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "second-job.json",
            folder_id="folder",
        )
    second_runner.assert_not_called()
    assert blocked["state"] == "BLOCKED_UNCERTAIN"
    assert blocked["native_runner_call_count"] == 0


@pytest.mark.parametrize("failure_mode", ("corrupt", "future-schema"))
def test_corrupt_source_lab_fails_before_yandex_provider_read(
    tmp_path: Path,
    failure_mode: str,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    source_lab_path = state_path.with_name(SOURCE_DISCOVERY_SOURCE_LAB_PATH.name)
    if failure_mode == "corrupt":
        source_lab_path.write_bytes(b"not-a-sqlite-database")
    else:
        with sqlite3.connect(source_lab_path) as connection:
            connection.execute("PRAGMA user_version=999")

    with patch.object(control, "run_manual_yandex_search_accounted") as runner:
        with pytest.raises(YandexSourceLabBridgeError) as failed:
            run_source_discovery_once(
                "YANDEX",
                confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
                state_path=state_path,
                yandex_job_path=tmp_path / "manual-job.json",
                folder_id="folder",
            )
    runner.assert_not_called()
    assert failed.value.code == "YANDEX_SOURCE_LAB_PREFLIGHT_FAILED"
    assert not state_path.exists()


def test_second_preflight_failure_reports_zero_provider_calls(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    with (
        patch.object(
            control,
            "preflight_yandex_source_lab",
            side_effect=(None, YandexSourceLabBridgeError("PREFLIGHT_STOP")),
        ),
        patch.object(control, "run_manual_yandex_search_accounted") as runner,
    ):
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_not_called()
    assert report["state"] == "UNCERTAIN"
    assert report["native_runner_call_count"] == 0


def test_query_url_is_discarded_without_wedging_the_controller(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    query_url = "https://public.example/object?id=123"
    page = SearchPage(
        request=SearchRequest("PRIVATE QUERY", "PRIVATE REGION"),
        received_at_utc="2026-09-11T00:00:00Z",
        response_sha256="b" * 64,
        hits=(
            SearchHit(
                rank=1,
                url=query_url,
                url_key=query_url,
                title="PRIVATE TITLE",
                passages=("PRIVATE SNIPPET",),
                provider_modtime="",
            ),
        ),
        status="RESULTS",
    )
    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(
            ManualYandexSearchOutcome(
                page=page,
                external_requests_this_run=1,
                journal=_accounted_review_page().journal,
            )
        ),
    ) as runner:
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_called_once()
    assert report["state"] == "COMPLETE_NO_RESULTS"
    assert report["result_classification"] == "NO_SAFE_REVIEWABLE_RESULTS"
    assert report["discarded_hit_count"] == 1
    assert report["control"]["gate"] == "READY"  # type: ignore[index]
    source_lab_path = state_path.with_name(SOURCE_DISCOVERY_SOURCE_LAB_PATH.name)
    assert query_url.encode() not in source_lab_path.read_bytes()

    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(_accounted_review_page(hits=0)),
    ) as second_runner:
        second = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "second-job.json",
            folder_id="folder",
        )
    second_runner.assert_called_once()
    assert second["state"] == "COMPLETE_NO_RESULTS"


def test_mixed_query_and_safe_urls_persist_only_safe_candidate(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    query_url = "https://public.example/object?id=123"
    safe_url = "https://public.example/project/safe"
    page = SearchPage(
        request=SearchRequest("PRIVATE QUERY", "PRIVATE REGION"),
        received_at_utc="2026-09-11T00:00:00Z",
        response_sha256="c" * 64,
        hits=(
            SearchHit(1, query_url, query_url, "PRIVATE ONE", (), ""),
            SearchHit(2, safe_url, safe_url, "PRIVATE TWO", (), ""),
        ),
        status="RESULTS",
    )
    with patch.object(
        control,
        "run_manual_yandex_search_accounted",
        side_effect=_recorded_review_result(
            ManualYandexSearchOutcome(
                page=page,
                external_requests_this_run=1,
                journal=_accounted_review_page().journal,
            )
        ),
    ) as runner:
        report = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_called_once()
    assert report["state"] == "READY_FOR_REVIEW"
    assert report["result_classification"] == "REVIEW_QUEUE_READY"
    assert report["review_count"] == 1
    assert report["discarded_hit_count"] == 1
    source_lab_path = state_path.with_name(SOURCE_DISCOVERY_SOURCE_LAB_PATH.name)
    items = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )
    assert [item.url for item in items] == [safe_url]
    assert query_url.encode() not in source_lab_path.read_bytes()


def test_controller_schema_creation_rolls_back_after_ddl_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "source-discovery.sqlite3"
    original = control._append_only_trigger_sql  # noqa: SLF001

    def fail_during_trigger_creation(table: str, operation: str) -> str:
        if table == "source_discovery_batch_links" and operation == "DELETE":
            return "INVALID DDL"
        return original(table, operation)

    monkeypatch.setattr(control, "_append_only_trigger_sql", fail_during_trigger_creation)
    with pytest.raises(SourceDiscoveryControlError) as failed:
        control._open_for_write(state_path)  # noqa: SLF001
    assert failed.value.code == "CONTROL_STATE_UNAVAILABLE"

    monkeypatch.setattr(control, "_append_only_trigger_sql", original)
    recovered = control._open_for_write(state_path)  # noqa: SLF001
    recovered.close()
    with sqlite3.connect(state_path) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
    assert {
        "source_discovery_attempts",
        "source_discovery_yandex_bindings",
        "source_discovery_yandex_accounting",
        "source_discovery_batch_links",
        "source_discovery_review_closures",
    }.issubset(tables)
    assert triggers == {
        "source_discovery_yandex_bindings_no_delete",
        "source_discovery_yandex_bindings_no_update",
        "source_discovery_yandex_accounting_no_delete",
        "source_discovery_yandex_accounting_no_update",
        "source_discovery_batch_links_no_delete",
        "source_discovery_batch_links_no_update",
        "source_discovery_review_closures_no_delete",
        "source_discovery_review_closures_no_update",
    }


def test_local_close_requires_terminal_reviews_confirmation_and_exact_replay(
    tmp_path: Path,
) -> None:
    state_path, source_lab_path, report = _run_yandex_review_batch(tmp_path, hits=1)
    common = {
        "attempt_id": str(report["attempt_id"]),
        "state_path": state_path,
        "actor": "operator_1",
        "evidence_ref": "evidence://local-review/close",
        "idempotency_key": "close_exact_replay",
    }
    with pytest.raises(SourceDiscoveryControlError) as missing_confirmation:
        close_source_discovery_review(confirmation=None, **common)
    assert missing_confirmation.value.code == "LOCAL_CLOSE_CONFIRMATION_REQUIRED"

    with pytest.raises(YandexSourceLabBridgeError) as incomplete:
        close_source_discovery_review(
            confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
            **common,
        )
    assert incomplete.value.code == "YANDEX_REVIEW_BATCH_INCOMPLETE"

    item = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )[0]
    _decide_review_item(
        report=report,
        source_lab_path=source_lab_path,
        review_id=item.review_id,
        state_digest=item.state_digest,
        decision="NEEDS_RESEARCH",
        suffix="research",
    )
    research_item = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )[0]
    assert research_item.latest_decision == "NEEDS_RESEARCH"
    with pytest.raises(YandexSourceLabBridgeError) as still_incomplete:
        close_source_discovery_review(
            confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
            **common,
        )
    assert still_incomplete.value.code == "YANDEX_REVIEW_BATCH_INCOMPLETE"

    _decide_review_item(
        report=report,
        source_lab_path=source_lab_path,
        review_id=research_item.review_id,
        state_digest=research_item.state_digest,
        decision="APPROVE",
        suffix="approved",
    )
    first = close_source_discovery_review(
        confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        **common,
    )
    replay = close_source_discovery_review(
        confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        **common,
    )
    assert first["created"] is True
    assert replay["created"] is False
    assert replay["closure_receipt_sha256"] == first["closure_receipt_sha256"]

    with pytest.raises(SourceDiscoveryControlError) as conflict:
        close_source_discovery_review(
            confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
            **{**common, "idempotency_key": "close_conflict"},
        )
    assert conflict.value.code == "LOCAL_REVIEW_CLOSE_CONFLICT"


def test_local_close_rejects_preexisting_orphan_before_writing_closure(
    tmp_path: Path,
) -> None:
    state_path, source_lab_path, report = _run_yandex_review_batch(tmp_path, hits=1)
    item = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )[0]
    _decide_review_item(
        report=report,
        source_lab_path=source_lab_path,
        review_id=item.review_id,
        state_digest=item.state_digest,
        decision="APPROVE",
        suffix="orphan-precondition",
    )
    persist_yandex_review_batch(
        attempt_id="sd_" + "9" * 32,
        page=_controller_review_page(hits=1),
        source_lab_path=source_lab_path,
    )

    with pytest.raises(SourceDiscoveryControlError) as blocked:
        close_source_discovery_review(
            attempt_id=str(report["attempt_id"]),
            confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
            state_path=state_path,
            actor="operator_1",
            evidence_ref="evidence://local-review/orphan-precondition",
            idempotency_key="close_orphan_precondition",
        )
    assert blocked.value.code == "CONTROL_SOURCE_LAB_RECONCILIATION_REQUIRED"
    with sqlite3.connect(state_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM source_discovery_review_closures"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM source_discovery_attempts WHERE attempt_id=?",
            (str(report["attempt_id"]),),
        ).fetchone()[0] == "READY_FOR_REVIEW"


def test_controller_links_and_closures_are_append_only_and_tamper_evident(
    tmp_path: Path,
) -> None:
    state_path, source_lab_path, report = _run_yandex_review_batch(tmp_path, hits=1)
    with pytest.raises(sqlite3.IntegrityError):
        with sqlite3.connect(state_path) as connection:
            connection.execute("UPDATE source_discovery_batch_links SET linked_at_utc='tampered'")

    state_tamper_path = tmp_path / "state-tamper.sqlite3"
    shutil.copy2(state_path, state_tamper_path)
    with sqlite3.connect(state_tamper_path) as connection:
        connection.execute(
            """UPDATE source_discovery_attempts
               SET state='COMPLETE_NO_RESULTS',review_count=0"""
        )
    with pytest.raises(SourceDiscoveryControlError) as state_tampered:
        source_discovery_status(state_path=state_tamper_path)
    assert state_tampered.value.code == "CONTROL_STATE_INTEGRITY_FAILED"

    clone_root = tmp_path / "copied-control"
    clone_root.mkdir()
    cloned_state_path = clone_root / state_path.name
    cloned_source_lab_path = cloned_state_path.with_name(SOURCE_DISCOVERY_SOURCE_LAB_PATH.name)
    shutil.copy2(state_path, cloned_state_path)
    shutil.copy2(source_lab_path, cloned_source_lab_path)
    cloned_item = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=cloned_source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )[0]
    _decide_review_item(
        report=report,
        source_lab_path=cloned_source_lab_path,
        review_id=cloned_item.review_id,
        state_digest=cloned_item.state_digest,
        decision="REJECT",
        suffix="copied-store",
    )
    with pytest.raises(SourceDiscoveryControlError) as copied_store:
        close_source_discovery_review(
            attempt_id=str(report["attempt_id"]),
            confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
            state_path=cloned_state_path,
            actor="operator_1",
            evidence_ref="evidence://local-review/copied-store",
            idempotency_key="close_copied_store",
        )
    assert copied_store.value.code == "LOCAL_REVIEW_STORE_MISMATCH"

    item = list_yandex_review_batch(
        attempt_id=str(report["attempt_id"]),
        source_lab_path=source_lab_path,
        expected_receipt_sha256=str(report["batch_receipt_sha256"]),
    )[0]
    _decide_review_item(
        report=report,
        source_lab_path=source_lab_path,
        review_id=item.review_id,
        state_digest=item.state_digest,
        decision="REJECT",
        suffix="reject",
    )
    close_source_discovery_review(
        attempt_id=str(report["attempt_id"]),
        confirmation=SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        state_path=state_path,
        actor="operator_1",
        evidence_ref="evidence://local-review/close",
        idempotency_key="close_append_only",
    )
    with pytest.raises(sqlite3.IntegrityError):
        with sqlite3.connect(state_path) as connection:
            connection.execute("DELETE FROM source_discovery_review_closures")

    timestamp_tamper_path = tmp_path / "timestamp-tamper.sqlite3"
    shutil.copy2(state_path, timestamp_tamper_path)
    with sqlite3.connect(timestamp_tamper_path) as connection:
        connection.execute("DROP TRIGGER source_discovery_review_closures_no_update")
        connection.execute(
            """UPDATE source_discovery_review_closures
               SET closed_at_utc='2026-09-11T23:59:59Z'"""
        )
        connection.execute(
            control._append_only_trigger_sql(  # noqa: SLF001
                "source_discovery_review_closures", "UPDATE"
            )
        )
    with pytest.raises(SourceDiscoveryControlError) as timestamp_tampered:
        source_discovery_status(state_path=timestamp_tamper_path)
    assert timestamp_tampered.value.code == "CONTROL_STATE_INTEGRITY_FAILED"

    trigger_tamper_path = tmp_path / "trigger-tamper.sqlite3"
    shutil.copy2(state_path, trigger_tamper_path)
    with sqlite3.connect(trigger_tamper_path) as connection:
        connection.execute("DROP TRIGGER source_discovery_batch_links_no_update")
    with pytest.raises(SourceDiscoveryControlError) as trigger_tampered:
        source_discovery_status(state_path=trigger_tamper_path)
    assert trigger_tampered.value.code == "CONTROL_STATE_INTEGRITY_FAILED"


def test_legacy_ready_batch_without_bridge_link_remains_blocked(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "legacy-control.sqlite3"
    attempt_id = "sd_" + "1" * 32
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            """CREATE TABLE source_discovery_attempts(
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   attempt_id TEXT NOT NULL UNIQUE,
                   source TEXT NOT NULL,
                   state TEXT NOT NULL,
                   started_at_utc TEXT NOT NULL,
                   finished_at_utc TEXT,
                   review_count INTEGER NOT NULL DEFAULT 0
               )"""
        )
        connection.execute(
            """INSERT INTO source_discovery_attempts(
                   attempt_id,source,state,started_at_utc,finished_at_utc,review_count
               ) VALUES(?,?,?,?,?,?)""",
            (
                attempt_id,
                "YANDEX",
                "READY_FOR_REVIEW",
                "2026-09-10T00:00:00Z",
                "2026-09-10T00:00:01Z",
                1,
            ),
        )

    status = source_discovery_status(state_path=state_path)
    assert status["version"] == "source-discovery-control-v3"
    assert status["control"]["gate"] == "BLOCKED_BACKPRESSURE"  # type: ignore[index]
    assert status["control"]["open_review_batches"] == 1  # type: ignore[index]
    with patch.object(control, "run_manual_yandex_search_accounted") as runner:
        blocked = run_source_discovery_once(
            "YANDEX",
            confirmation=SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=state_path,
            yandex_job_path=tmp_path / "manual-job.json",
            folder_id="folder",
        )
    runner.assert_not_called()
    assert blocked["state"] == "BLOCKED_BACKPRESSURE"
