"""Synthetic tests for the inert Yandex job preparer; no credential or HTTP."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
from threading import Barrier
from unittest.mock import patch
from uuid import uuid5

import pytest

from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_job_preparer as preparer
from lead_factory import radar_yandex_pilot_authority as common
from lead_factory.radar_yandex_journal import (
    JournalError,
    PilotPolicy,
    YandexPilotJournal,
)
from lead_factory.radar_yandex_search import SearchRequest


NOW = "2026-09-12T08:00:00Z"
LATER = "2026-09-12T15:00:00Z"
FOLDER = "synthetic-folder"
QUERY = "PRIVATE_QUERY_SENTINEL public construction"
REGION = "PRIVATE_REGION_SENTINEL"
KEY = "YANDEX-PREPARE-SYNTHETIC-V1"


def _connection() -> dict[str, object]:
    return {
        "version": "radar-yandex-connection-v1",
        "status": "ACTIVE",
        "folder_id": FOLDER,
        "service_account_id": "synthetic-service-account",
        "api_key_id": "synthetic-api-key-id",
        "scope": "yc.search-api.execute",
        "expires_at": None,
        "credential_sha256": hashlib.sha256(b"synthetic-secret").hexdigest(),
        "registered_at_utc": "2026-09-12T07:00:00Z",
        "owner_instruction_sha256": common._digest(
            "SYNTHETIC CONNECTION AUTHORITY"
        ),
    }


@contextmanager
def _inert_state(tmp_path: Path):
    root = tmp_path / "yandex-search"
    requests = root / "requests"
    requests.mkdir(parents=True)
    connection_path = root / "connection.json"
    connection_path.write_bytes(common._canonical(_connection()))
    credential = root / "credential.dpapi"
    credential.write_bytes(b"PRIVATE_CREDENTIAL_SENTINEL")
    unrelated_activation = root / "request-activation.expired-consumed.json"
    unrelated_activation.write_bytes(b"PRIVATE_ACTIVATION_SENTINEL")
    guarded = {
        path: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
        for path in (connection_path, credential, unrelated_activation)
    }
    with (
        patch.object(authority, "_STATE_ROOT", root),
        patch.object(common, "_now_utc", return_value=NOW),
        patch.object(preparer, "_check_acl") as acl_check,
    ):
        yield root, guarded, acl_check
    for path, expected in guarded.items():
        assert (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino) == expected


def _prepare() -> dict[str, object]:
    return preparer.prepare_inactive_yandex_job(
        QUERY,
        REGION,
        KEY,
        confirmation=preparer.YANDEX_INACTIVE_PREPARATION_CONFIRMATION,
    )


def _snapshot_job(job_directory: Path) -> dict[str, tuple[bytes | None, int, int]]:
    snapshot: dict[str, tuple[bytes | None, int, int]] = {}
    for path in (job_directory, *sorted(job_directory.iterdir())):
        content = path.read_bytes() if path.is_file() else None
        metadata = path.stat()
        snapshot[path.name] = (content, metadata.st_mtime_ns, metadata.st_ino)
    return snapshot


def test_prepares_only_an_inert_exact_scope_and_never_live_authority(
    tmp_path: Path,
) -> None:
    with _inert_state(tmp_path) as (root, _, acl_check):
        result = _prepare()
        assert result["state"] == "PREPARED_NOT_ACTIVATED"
        assert result["created"] is True
        assert result["replayed"] is False
        assert result["authority_verified"] is False
        assert result["launch_allowed"] is False
        assert result["missing_gates"] == [
            "OWNER_INSTRUCTION",
            "INDEPENDENT_CODE_ACCEPTANCE",
            "BILLING_API_READINESS",
            "FINAL_JOB_INSTALL",
            "EXPLICIT_ACTIVATION",
        ]
        assert result["effects"] == {
            "activation_created": False,
            "automatic_schedule_eligible": False,
            "campaign_spend_enabled": False,
            "contact_enabled": False,
            "credential_read": False,
            "crm_write_enabled": False,
            "external_requests_this_run": 0,
            "outbox_write_enabled": False,
            "provider_read_may_be_metered": False,
        }
        public_output = json.dumps(result, ensure_ascii=False)
        for private in (
            QUERY,
            REGION,
            FOLDER,
            "synthetic-service-account",
            str(root),
        ):
            assert private not in public_output

        job_directory = root / "requests" / str(result["job_id"])
        assert {path.name for path in job_directory.iterdir()} == {
            "dispatch-claims",
            "request.sqlite",
            "request.draft.json",
        }
        assert not (job_directory / "request.json").exists()
        assert not (root / "request-activation.json").exists()
        assert not (job_directory / "retention-activation.json").exists()
        assert list((job_directory / "dispatch-claims").iterdir()) == []

        draft_path = job_directory / "request.draft.json"
        draft = json.loads(draft_path.read_bytes())
        assert draft["state"] == "PREPARED_NOT_ACTIVATED"
        assert draft["request"] == asdict(SearchRequest(QUERY, REGION, 0))
        assert draft["max_requests"] == 1
        assert draft["max_cost_minor"] == 49
        assert draft["reserve_per_request_minor"] == 49
        assert draft["retention_hours"] == 24
        for forbidden in (
            "owner_receipt",
            "independent_acceptance",
            "readiness",
            "credential",
            "activation",
        ):
            assert forbidden not in draft

        policy = PilotPolicy(
            str(result["job_id"]),
            hashlib.sha256(FOLDER.encode()).hexdigest(),
            (SearchRequest(QUERY, REGION, 0),),
            draft["expires_at_utc"],
            1,
            49,
            49,
            24,
        )
        journal = YandexPilotJournal.open(
            job_directory / "request.sqlite",
            expected_policy_sha256=policy.sha256,
        )
        try:
            status = journal.status()
        finally:
            journal.close()
        assert status["attempts_reserved"] == 0
        assert status["reserved_cost_minor"] == 0
        assert status["retained_responses"] == 0
        assert status["live_authority_granted"] is False

        synthetic_pin = {
            "version": "radar-yandex-manual-activation-v1",
            "status": "ACTIVE",
            "job_path": str(draft_path.resolve()),
            "job_sha256": hashlib.sha256(draft_path.read_bytes()).hexdigest(),
            "connection_sha256": draft["connection_sha256"],
            "policy_sha256": draft["policy_sha256"],
            "activated_at_utc": NOW,
            "expires_at_utc": draft["expires_at_utc"],
        }
        (root / "request-activation.json").write_bytes(
            common._canonical(synthetic_pin)
        )
        with pytest.raises(authority.ConnectionAuthorityError):
            authority.verify_manual_grant(draft_path, now=NOW)
        acl_check.assert_any_call("Root")
        acl_check.assert_any_call("Job", job_id=result["job_id"])


def test_exact_replay_is_byte_and_time_stable_but_changed_input_conflicts(
    tmp_path: Path,
) -> None:
    with _inert_state(tmp_path) as (root, _, _):
        first = _prepare()
        job_directory = root / "requests" / str(first["job_id"])
        before = _snapshot_job(job_directory)

        second = _prepare()
        assert second == {**first, "created": False, "replayed": True}
        assert _snapshot_job(job_directory) == before

        for query, region in ((QUERY + " changed", REGION), (QUERY, REGION + " changed")):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_CONFLICT$",
            ):
                preparer.prepare_inactive_yandex_job(
                    query,
                    region,
                    KEY,
                    confirmation=preparer.YANDEX_INACTIVE_PREPARATION_CONFIRMATION,
                )
            assert _snapshot_job(job_directory) == before


def test_expired_code_or_connection_drift_never_overwrites_published_job(
    tmp_path: Path,
) -> None:
    with _inert_state(tmp_path) as (root, _, _):
        result = _prepare()
        job_directory = root / "requests" / str(result["job_id"])
        before = _snapshot_job(job_directory)

        with patch.object(common, "_now_utc", return_value=LATER):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_CONFLICT$",
            ):
                _prepare()
        assert _snapshot_job(job_directory) == before

        current_code = preparer._current_code_hashes()
        changed_code = dict(current_code)
        first_name = next(iter(changed_code))
        changed_code[first_name] = "0" * 64
        with patch.object(preparer, "_current_code_hashes", return_value=changed_code):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_CONFLICT$",
            ):
                _prepare()
        assert _snapshot_job(job_directory) == before

        connection = _connection()
        connection["api_key_id"] = "different-synthetic-key-id"
        changed_connection_sha256 = hashlib.sha256(
            common._canonical(connection)
        ).hexdigest()
        with patch.object(
            authority,
            "_read_connection",
            return_value=(connection, changed_connection_sha256),
        ):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_CONFLICT$",
            ):
                _prepare()
        assert _snapshot_job(job_directory) == before


def test_exact_code_is_verified_before_acl_helper_execution(tmp_path: Path) -> None:
    with _inert_state(tmp_path) as (root, _, acl_check):
        with patch.object(
            preparer,
            "_current_code_hashes",
            side_effect=preparer.YandexJobPreparationError(),
        ):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_REJECTED$",
            ):
                _prepare()
        acl_check.assert_not_called()
        assert list((root / "requests").iterdir()) == []


def test_post_publish_connection_drift_fails_and_preserves_inert_job(
    tmp_path: Path,
) -> None:
    with _inert_state(tmp_path) as (root, _, _):
        original = _connection()
        original_sha256 = hashlib.sha256(common._canonical(original)).hexdigest()
        changed = dict(original)
        changed["api_key_id"] = "post-publish-different-key"
        changed_sha256 = hashlib.sha256(common._canonical(changed)).hexdigest()
        with patch.object(
            authority,
            "_read_connection",
            side_effect=[
                (original, original_sha256),
                (original, original_sha256),
                (changed, changed_sha256),
            ],
        ):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_RECONCILIATION_REQUIRED$",
            ):
                _prepare()

        job_id = str(uuid5(preparer._JOB_NAMESPACE, KEY))
        job_directory = root / "requests" / job_id
        assert job_directory.is_dir()
        assert {path.name for path in job_directory.iterdir()} == {
            "dispatch-claims",
            "request.sqlite",
            "request.draft.json",
        }
        assert not (root / "request-activation.json").exists()
        replay = _prepare()
        assert replay["created"] is False
        assert replay["replayed"] is True


def test_concurrent_same_key_publishes_once_and_replays_once(tmp_path: Path) -> None:
    with _inert_state(tmp_path) as (root, _, _):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: _prepare(), range(2)))
        assert {result["job_id"] for result in results} == {
            str(uuid5(preparer._JOB_NAMESPACE, KEY))
        }
        assert sorted(result["created"] for result in results) == [False, True]
        assert sorted(result["replayed"] for result in results) == [False, True]
        jobs = [path for path in (root / "requests").iterdir() if not path.name.startswith(".")]
        assert len(jobs) == 1
        assert not any(path.name.startswith(".preparing-") for path in (root / "requests").iterdir())


def test_concurrent_changed_input_reports_conflict_not_reconciliation(
    tmp_path: Path,
) -> None:
    with _inert_state(tmp_path) as (root, _, _):
        rendezvous = Barrier(2)
        real_rename = os.rename

        def racing_rename(source: str | Path, destination: str | Path) -> None:
            rendezvous.wait(timeout=10)
            real_rename(source, destination)

        def invoke(query: str) -> str:
            try:
                preparer.prepare_inactive_yandex_job(
                    query,
                    REGION,
                    KEY,
                    confirmation=preparer.YANDEX_INACTIVE_PREPARATION_CONFIRMATION,
                )
            except preparer.YandexJobPreparationError as error:
                return error.code
            return "SUCCESS"

        with patch.object(preparer.os, "rename", side_effect=racing_rename):
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(invoke, (QUERY, QUERY + " changed")))

        assert sorted(outcomes) == ["SUCCESS", "YANDEX_JOB_PREPARATION_CONFLICT"]
        assert len(list((root / "requests").iterdir())) == 1
        assert not any(
            path.name.startswith(".preparing-")
            for path in (root / "requests").iterdir()
        )


def test_pre_publish_failure_cleans_only_its_stage(tmp_path: Path) -> None:
    with _inert_state(tmp_path) as (root, _, _):
        with patch.object(preparer.os, "rename", side_effect=PermissionError):
            with pytest.raises(preparer.YandexJobPreparationError):
                _prepare()
        assert list((root / "requests").iterdir()) == []


def test_partial_journal_creation_failure_is_removed_from_stage(
    tmp_path: Path,
) -> None:
    def fail_after_exclusive_create(
        path: str | Path,
        *,
        policy: PilotPolicy,
        now: str,
    ) -> None:
        assert type(policy) is PilotPolicy
        assert now == NOW
        Path(path).write_bytes(b"synthetic partial SQLite file")
        raise JournalError("JOURNAL_CREATE_FAILED")

    with _inert_state(tmp_path) as (root, _, _):
        with patch.object(
            preparer.YandexPilotJournal,
            "create",
            side_effect=fail_after_exclusive_create,
        ):
            with pytest.raises(
                preparer.YandexJobPreparationError,
                match="^YANDEX_JOB_PREPARATION_REJECTED$",
            ):
                _prepare()
        assert list((root / "requests").iterdir()) == []


def test_post_publish_acl_failure_keeps_inert_job_for_reconciliation(
    tmp_path: Path,
) -> None:
    with _inert_state(tmp_path) as (root, _, acl_check):
        acl_check.side_effect = [
            None,
            preparer.YandexJobPreparationError("YANDEX_STATE_ACL_REJECTED"),
        ]
        with pytest.raises(
            preparer.YandexJobPreparationError,
            match="^YANDEX_JOB_PREPARATION_RECONCILIATION_REQUIRED$",
        ):
            _prepare()
        job_id = str(uuid5(preparer._JOB_NAMESPACE, KEY))
        job_directory = root / "requests" / job_id
        assert job_directory.is_dir()
        assert not (job_directory / "request.json").exists()
        assert not (root / "request-activation.json").exists()

        acl_check.side_effect = None
        replay = _prepare()
        assert replay["job_id"] == job_id
        assert replay["created"] is False
        assert replay["replayed"] is True


def test_failures_and_module_boundary_do_not_expose_private_inputs(
    tmp_path: Path,
) -> None:
    source = Path(preparer.__file__).read_text(encoding="utf-8")
    assert "radar_yandex_credential_broker" not in source
    assert "radar_yandex_transport" not in source
    assert "urllib" not in source

    with _inert_state(tmp_path):
        marker = "PRIVATE_FAILURE_INPUT_SENTINEL"
        try:
            preparer.prepare_inactive_yandex_job(
                marker,
                REGION,
                KEY,
                confirmation="WRONG_CONFIRMATION",
            )
        except preparer.YandexJobPreparationError as error:
            assert str(error) == "YANDEX_INACTIVE_PREPARATION_CONFIRMATION_REQUIRED"
            assert error.__cause__ is None
            assert error.__context__ is None
            production_locals: list[str] = []
            traceback = error.__traceback__
            while traceback is not None:
                filename = traceback.tb_frame.f_code.co_filename.replace("\\", "/")
                if filename.endswith("/lead_factory/radar_yandex_job_preparer.py"):
                    production_locals.append(repr(traceback.tb_frame.f_locals))
                traceback = traceback.tb_next
            assert marker not in "\n".join(production_locals)
        else:
            raise AssertionError("preparation should have failed")


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
def test_acl_helper_parses_and_rejects_safely_without_state_access() -> None:
    helper = Path(__file__).resolve().parents[1] / "scripts" / "check_yandex_state_acl.ps1"
    source = helper.read_text(encoding="utf-8")
    assert "#Requires -Version 5.1" in source
    assert "[Environment]::GetFolderPath('UserProfile')" in source
    assert "'connection.json'" in source
    assert "radar-yandex-connection.json" not in source
    for forbidden in (
        "Get-Acl",
        "Set-Acl",
        "New-Item",
        "Remove-Item",
        "Set-Content",
        "Add-Content",
    ):
        assert forbidden not in source
    assert "credential" not in source.casefold()
    assert "request-activation" not in source.casefold()

    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    quoted = str(helper).replace("'", "''")
    parser_probe = (
        "$tokens=$null;$errors=$null;"
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        f"'{quoted}',[ref]$tokens,[ref]$errors);"
        "if(@($errors).Count-ne 0){exit 4}"
    )
    parsed = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser_probe],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert parsed.returncode == 0, parsed.stdout + parsed.stderr

    for arguments in (
        ("-Scope", "Invalid-Scope"),
        ("-Scope",),
        ("-Bogus", "value"),
    ):
        checked = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(helper),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert checked.returncode == 2
        assert checked.stdout.strip() == "YANDEX_STATE_ACL_REJECTED"
        assert checked.stderr == ""
