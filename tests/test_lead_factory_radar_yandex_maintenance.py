from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_maintenance as maintenance
from lead_factory.radar_yandex_journal import YandexPilotJournal
from tests.test_lead_factory_radar_yandex_connection import FOLDER, make_manual_job
from tests.test_lead_factory_radar_yandex_transport import supplied_response


def _job_id(job_path: Path) -> str:
    return job_path.parent.name


def _assert_not_serialized(report: dict[str, object], *values: str) -> None:
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    for value in values:
        assert value not in serialized
        assert json.dumps(value, ensure_ascii=False)[1:-1] not in serialized


def test_status_uses_archived_activation_without_connection_and_hides_sensitive_material(
    tmp_path: Path,
) -> None:
    root = tmp_path / "yandex-search"
    job_path, _policy = make_manual_job(root)
    job = json.loads(job_path.read_bytes())
    connection = json.loads((root / "connection.json").read_bytes())
    (root / "request-activation.json").replace(
        root / "request-activation.expired-test.json"
    )
    (root / "connection.json").unlink()
    with patch.object(authority, "_STATE_ROOT", root):
        report = maintenance.yandex_journal_status(_job_id(job_path))

    assert report["operation"] == "YANDEX_JOURNAL_STATUS_LOCAL"
    assert report["state"] == "NO_RAW_RESPONSE_RETAINED"
    assert report["journal"]["attempts_reserved"] == 0
    assert report["retention"] == {
        "next_purge_at_utc": None,
        "purge_due_count": 0,
        "retained_responses": 0,
    }
    _assert_not_serialized(
        report,
        _job_id(job_path),
        job["request"]["query_text"],
        job["request"]["region_label"],
        FOLDER,
        str(root),
        str(root.resolve()),
        str(job_path),
        str(job_path.resolve()),
        job["journal_path"],
        job["workspace_root"],
        connection["credential_sha256"],
    )


def test_status_uses_preferred_per_job_retention_activation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "yandex-search"
    job_path, _policy = make_manual_job(root)
    (root / "request-activation.json").replace(
        job_path.parent / "retention-activation.json"
    )
    (root / "connection.json").unlink()

    with patch.object(authority, "_STATE_ROOT", root):
        report = maintenance.yandex_journal_status(_job_id(job_path))

    assert report["operation"] == "YANDEX_JOURNAL_STATUS_LOCAL"
    assert report["state"] == "NO_RAW_RESPONSE_RETAINED"


def test_invalid_preferred_activation_cannot_fall_back_to_valid_root_pin(
    tmp_path: Path,
) -> None:
    root = tmp_path / "yandex-search"
    job_path, _policy = make_manual_job(root)
    pin = json.loads((root / "request-activation.json").read_bytes())
    pin["job_sha256"] = "0" * 64
    (job_path.parent / "retention-activation.json").write_text(
        json.dumps(pin, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with patch.object(authority, "_STATE_ROOT", root):
        with pytest.raises(maintenance.YandexJournalMaintenanceError) as denied:
            maintenance.yandex_journal_status(_job_id(job_path))

    assert denied.value.code == "YANDEX_JOURNAL_MAINTENANCE_REJECTED"


def test_purge_requires_confirmation_and_removes_only_expired_raw_response(
    tmp_path: Path,
) -> None:
    root = tmp_path / "yandex-search"
    job_path, policy = make_manual_job(root)
    journal_path = job_path.parent / "request.sqlite"
    journal = YandexPilotJournal.open(
        journal_path,
        expected_policy_sha256=policy.sha256,
    )
    try:
        reservation = journal.reserve(policy.requests[0], now="2026-09-09T20:00:01Z")
        grant = journal.mark_dispatch_intent(
            reservation,
            now="2026-09-09T20:00:02Z",
        )
        journal.finish_response(
            grant,
            raw_response=supplied_response(),
            received_at_utc="2026-09-09T20:00:03Z",
            response_headers={"x-request-id": "synthetic-request"},
        )
    finally:
        journal.close()

    job_id = _job_id(job_path)
    with patch.object(authority, "_STATE_ROOT", root):
        with pytest.raises(maintenance.YandexJournalMaintenanceError) as denied:
            maintenance.purge_yandex_journal(job_id, confirmation=None)
        assert denied.value.code == "YANDEX_RAW_PURGE_CONFIRMATION_REQUIRED"
        with patch.object(
            maintenance,
            "_now_utc",
            return_value="2026-09-10T20:00:02Z",
        ):
            pending = maintenance.yandex_journal_status(job_id)
        assert pending["state"] == "RAW_RETENTION_PENDING"
        assert pending["retention"] == {
            "next_purge_at_utc": "2026-09-10T20:00:03Z",
            "purge_due_count": 0,
            "retained_responses": 1,
        }
        with patch.object(
            maintenance,
            "_now_utc",
            return_value="2026-09-10T20:00:03Z",
        ):
            report = maintenance.purge_yandex_journal(
                job_id,
                confirmation=maintenance.YANDEX_RAW_PURGE_CONFIRMATION,
            )
            replay = maintenance.purge_yandex_journal(
                job_id,
                confirmation=maintenance.YANDEX_RAW_PURGE_CONFIRMATION,
            )

    assert report["operation"] == "YANDEX_JOURNAL_PURGE_LOCAL"
    assert report["purged_results"] == 1
    assert report["journal"]["attempts_reserved"] == 1
    assert report["journal"]["max_requests"] == 1
    assert report["journal"]["reserved_cost_minor"] == 49
    assert report["journal"]["remaining_cost_minor"] == 0
    assert report["journal"]["states"]["COMPLETED"] == 1
    assert report["journal"]["retained_responses"] == 0
    assert report["journal"]["policy_sha256"] == policy.sha256
    assert report["state"] == "NO_RAW_RESPONSE_RETAINED"
    assert report["retention"]["purge_due_count"] == 0
    assert replay["purged_results"] == 0
    assert replay["journal"] == report["journal"]
    assert replay["retention"] == report["retention"]


def test_purge_captures_one_clock_value_for_delete_and_report(tmp_path: Path) -> None:
    root = tmp_path / "yandex-search"
    job_path, policy = make_manual_job(root)
    journal = YandexPilotJournal.open(
        job_path.parent / "request.sqlite",
        expected_policy_sha256=policy.sha256,
    )
    try:
        reservation = journal.reserve(policy.requests[0], now="2026-09-09T20:00:01Z")
        grant = journal.mark_dispatch_intent(
            reservation,
            now="2026-09-09T20:00:02Z",
        )
        journal.finish_response(
            grant,
            raw_response=supplied_response(),
            received_at_utc="2026-09-09T20:00:03Z",
            response_headers={"x-request-id": "synthetic-request"},
        )
    finally:
        journal.close()

    with (
        patch.object(authority, "_STATE_ROOT", root),
        patch.object(
            maintenance,
            "_now_utc",
            side_effect=["2026-09-10T20:00:03Z", "2026-09-10T20:00:02Z"],
        ) as clock,
    ):
        report = maintenance.purge_yandex_journal(
            _job_id(job_path),
            confirmation=maintenance.YANDEX_RAW_PURGE_CONFIRMATION,
        )

    assert clock.call_count == 1
    assert report["purged_results"] == 1
    assert report["journal"]["retained_responses"] == 0
    assert report["retention"]["retained_responses"] == 0


def test_maintenance_rejects_invalid_uuid_without_leaking_value(
    tmp_path: Path,
) -> None:
    root = tmp_path / "yandex-search"
    marker = "PRIVATE-INVALID-JOB-ID"

    with patch.object(authority, "_STATE_ROOT", root):
        with pytest.raises(maintenance.YandexJournalMaintenanceError) as denied:
            maintenance.yandex_journal_status(marker)

    assert denied.value.code == "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
    assert marker not in str(denied.value)
    assert denied.value.__cause__ is None
    assert denied.value.__context__ is None


def test_maintenance_rejects_job_without_preserved_activation(tmp_path: Path) -> None:
    root = tmp_path / "yandex-search"
    job_path, _policy = make_manual_job(root)
    (root / "request-activation.json").unlink()

    with patch.object(authority, "_STATE_ROOT", root):
        with pytest.raises(maintenance.YandexJournalMaintenanceError) as denied:
            maintenance.yandex_journal_status(_job_id(job_path))

    assert denied.value.code == "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
    assert denied.value.__cause__ is None
    assert denied.value.__context__ is None


def test_maintenance_rejects_tampered_archived_activation(tmp_path: Path) -> None:
    root = tmp_path / "yandex-search"
    job_path, _policy = make_manual_job(root)
    active = root / "request-activation.json"
    archived = root / "request-activation.expired-test.json"
    pin = json.loads(active.read_bytes())
    pin["job_sha256"] = "0" * 64
    archived.write_text(
        json.dumps(pin, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    active.unlink()

    with patch.object(authority, "_STATE_ROOT", root):
        with pytest.raises(maintenance.YandexJournalMaintenanceError) as denied:
            maintenance.yandex_journal_status(_job_id(job_path))

    assert denied.value.code == "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
    assert denied.value.__cause__ is None
    assert denied.value.__context__ is None
