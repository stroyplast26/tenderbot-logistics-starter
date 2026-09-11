from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import scripts.run_source_discovery_once as source_cli


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "run_safe_lead_flow.ps1"
BOOTSTRAP = ROOT / "scripts" / "bootstrap_python_runtime.ps1"
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
CANONICAL_SOURCE_STATE = ROOT / "state" / "lead_factory" / "source_discovery_control.sqlite3"


def _windows_powershell() -> Path:
    return (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )


def _run_launcher(tmp_path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    secret_marker = "must-not-appear-safe-launch-secret"
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_INDEX_URL": f"https://{secret_marker}.invalid/simple",
            "PIP_EXTRA_INDEX_URL": f"https://{secret_marker}.invalid/extra",
            "PIP_NO_INDEX": "1",
            "TENDERBOT_PYTHON": str(tmp_path / "must-not-run-python.exe"),
        }
    )
    result = subprocess.run(
        [
            str(_windows_powershell()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(LAUNCHER),
            *arguments,
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert secret_marker not in result.stdout
    assert secret_marker not in result.stderr
    return result


def test_launcher_source_is_an_exact_fail_closed_allowlist() -> None:
    source = LAUNCHER.read_text(encoding="utf-8")

    assert "#Requires -Version 5.1" in source
    assert "$PSScriptRoot" in source
    assert "bootstrap_python_runtime.ps1" in source
    assert "$null = & $BootstrapPath -CheckOnly" in source
    assert "'.venv\\Scripts\\python.exe'" in source
    assert "& $VenvPython @PythonArguments" in source
    assert ") + @($CommandArguments)" in source
    assert "exit $SafeLeadFlowExitCode" in source
    assert "SAFE_LEAD_FLOW_FAILED" in source
    assert source.index("Remove-Item -LiteralPath $SensitiveEnvironmentPath") < source.index(
        "$ScriptDirectory ="
    )
    assert "Test-Path -LiteralPath $SensitiveEnvironmentPath" in source
    assert "} finally {" in source
    assert source.index("& $BootstrapPath -CheckOnly") < source.index(
        "Set-Item -LiteralPath $LauncherMarkerPath"
    )
    assert source.count("Remove-Item -LiteralPath $LauncherMarkerPath") == 2

    expected_routes = {
        "source|plan",
        "source|status",
        "source|check",
        "source|run-one",
        "source|review-list",
        "source|review-decide",
        "source|review-close",
        "gold|prepare",
        "gold|admit",
        "gold|report",
        "gold|revalidate",
    }
    for route in expected_routes:
        assert source.count(f"'{route}'") == 1
    assert source.count(" = @('run_source_discovery_once.py',") == 7
    assert source.count(" = @('run_gold_acceptance.py',") == 4

    forbidden = (
        "Invoke-Expression",
        "Start-Process",
        "python_runtime.bat",
        "cmd.exe",
        "py.exe",
        "Get-Command python",
    )
    assert not any(token in source for token in forbidden)


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser contract")
def test_launcher_parses_in_windows_powershell_51() -> None:
    powershell = _windows_powershell()
    quoted_script = str(LAUNCHER).replace("'", "''")
    parser_probe = (
        "$tokens=$null; $errors=$null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        f"'{quoted_script}',[ref]$tokens,[ref]$errors); "
        "if(@($errors).Count -ne 0){$errors | % Message; exit 4}"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            parser_probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(
    os.name != "nt" or not VENV_PYTHON.is_file(),
    reason="requires Windows PowerShell 5.1 and the repo-local virtual environment",
)
def test_launcher_scrubs_case_variant_yandex_key_before_bootstrap_and_entrypoint(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "synthetic-repo"
    scripts = repo / "scripts"
    venv_scripts = repo / ".venv" / "Scripts"
    scripts.mkdir(parents=True)
    venv_scripts.mkdir(parents=True)
    shutil.copy2(LAUNCHER, scripts / LAUNCHER.name)
    shutil.copy2(VENV_PYTHON, venv_scripts / "python.exe")
    shutil.copy2(ROOT / ".venv" / "pyvenv.cfg", repo / ".venv" / "pyvenv.cfg")

    bootstrap_probe = tmp_path / "bootstrap-environment.txt"
    entry_probe = tmp_path / "entry-environment.txt"
    (scripts / "bootstrap_python_runtime.ps1").write_text(
        """#Requires -Version 5.1
param([switch]$CheckOnly)
$CredentialPresent = Test-Path -LiteralPath 'Env:YANDEX_SEARCH_API_KEY'
$MarkerPresent = Test-Path -LiteralPath 'Env:TENDERBOT_SAFE_LEAD_FLOW_LAUNCHER'
[IO.File]::WriteAllText(
    $env:SAFE_LEAD_FLOW_BOOTSTRAP_PROBE,
    ($CredentialPresent.ToString() + ',' + $MarkerPresent.ToString())
)
if ($CredentialPresent -or $MarkerPresent) { throw 'AMBIENT_VALUE_REACHED_BOOTSTRAP' }
""",
        encoding="utf-8",
    )
    (scripts / "run_source_discovery_once.py").write_text(
        """import json
import os
from pathlib import Path

present = any(
    name.casefold() == "yandex_search_api_key" for name in os.environ
)
marker_present = (
    os.environ.get("TENDERBOT_SAFE_LEAD_FLOW_LAUNCHER") == "source-discovery-v3"
)
Path(os.environ["SAFE_LEAD_FLOW_ENTRY_PROBE"]).write_text(
    f"credential={present};marker={marker_present}", encoding="utf-8"
)
print(json.dumps({"credential_present": present, "launcher_marker_present": marker_present}))
raise SystemExit(97 if present or not marker_present else 0)
""",
        encoding="utf-8",
    )

    secret_marker = "ambient-yandex-key-must-not-reach-child"
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.casefold() != "yandex_search_api_key"
    }
    environment.update(
        {
            "yAnDeX_SeArCh_ApI_kEy": secret_marker,
            "SAFE_LEAD_FLOW_BOOTSTRAP_PROBE": str(bootstrap_probe),
            "SAFE_LEAD_FLOW_ENTRY_PROBE": str(entry_probe),
        }
    )
    result = subprocess.run(
        [
            str(_windows_powershell()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(scripts / LAUNCHER.name),
            "source",
            "run-one",
            "--confirm-one-authorized-read",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "credential_present": False,
        "launcher_marker_present": True,
    }
    assert bootstrap_probe.read_text(encoding="utf-8") == "False,False"
    assert entry_probe.read_text(encoding="utf-8") == "credential=False;marker=True"
    assert secret_marker not in result.stdout
    assert secret_marker not in result.stderr


def test_source_cli_direct_run_one_is_denied_before_controller_or_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_path = tmp_path / "must-not-exist.sqlite3"
    with (
        patch.object(source_cli, "SOURCE_DISCOVERY_STATE_PATH", state_path),
        patch.object(source_cli, "run_source_discovery_once") as controller,
        patch.dict(
            os.environ,
            {source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME: "ambient-untrusted-marker"},
        ),
    ):
        exit_code = source_cli.main(
            [
                "run-one",
                "--source",
                "YANDEX",
                "--yandex-job",
                str(tmp_path / "job.json"),
                "--folder-id",
                "folder",
                "--confirm-one-authorized-read",
            ]
        )

    assert exit_code == 2
    controller.assert_not_called()
    assert not state_path.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    payload = json.loads(captured.err)
    assert payload["state"] == "FAILED_CLOSED"
    assert payload["error_code"] == "SAFE_LEAD_FLOW_LAUNCHER_REQUIRED"
    assert "ambient-untrusted-marker" not in captured.err


@pytest.mark.skipif(
    os.name != "nt" or not VENV_PYTHON.is_file(),
    reason="requires the checked repo-local Windows virtual environment",
)
def test_launcher_runs_local_source_plan_from_any_cwd(tmp_path: Path) -> None:
    result = _run_launcher(tmp_path, "source", "plan")

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["operation"] == "PLAN_LOCAL_ONLY"
    assert payload["state"] == "SAFE_FIRST_SLICE"
    assert payload["effects"] == {
        "automatic_schedule_eligible": False,
        "campaign_spend_enabled": False,
        "contact_enabled": False,
        "crm_write_enabled": False,
        "native_metering_governed": True,
        "outbox_write_enabled": False,
        "provider_read_may_be_metered": True,
    }


@pytest.mark.skipif(
    os.name != "nt" or not VENV_PYTHON.is_file(),
    reason="requires the checked repo-local Windows virtual environment",
)
def test_launcher_passes_arguments_literally_and_propagates_block(tmp_path: Path) -> None:
    injection_marker = tmp_path / "must-not-be-evaluated.txt"
    literal = f"$([IO.File]::WriteAllText('{injection_marker}','owned'))"
    state_before = CANONICAL_SOURCE_STATE.read_bytes() if CANONICAL_SOURCE_STATE.exists() else None

    result = _run_launcher(
        tmp_path,
        "source",
        "check",
        "--source",
        "SABY",
        "--folder-id",
        literal,
    )

    assert result.returncode == 2, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["state"] == "BLOCKED_OFFLINE_CONTRACT"
    state_after = CANONICAL_SOURCE_STATE.read_bytes() if CANONICAL_SOURCE_STATE.exists() else None
    assert state_after == state_before
    assert not injection_marker.exists()


@pytest.mark.skipif(
    os.name != "nt" or not VENV_PYTHON.is_file(),
    reason="requires the checked repo-local Windows virtual environment",
)
def test_launcher_rejects_cross_flow_operation_before_child_dispatch(
    tmp_path: Path,
) -> None:
    result = _run_launcher(tmp_path, "source", "admit")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "SAFE_LEAD_FLOW_FAILED" in result.stderr
    assert not any(tmp_path.iterdir())


def test_launcher_and_bootstrap_are_documented_by_the_canonical_runbook() -> None:
    runbook = ROOT / "docs" / "SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md"
    text = runbook.read_text(encoding="utf-8")

    assert "bootstrap_python_runtime.ps1" in text
    assert "run_safe_lead_flow.ps1" in text
    assert "provider read" in text.casefold()
    assert "Gold signer" in text
    assert "review-list" in text
    assert "review-decide" in text
    assert "review-close" in text
    assert "APPROVE" in text
    assert "TenderPlan" in text
    assert "STOP" in text


def test_source_cli_review_commands_use_only_canonical_local_paths(
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempt_id = "sd_" + "1" * 32
    review_id = "lf_source_review_" + "2" * 32
    receipt_sha256 = "a" * 64
    state_digest = "b" * 64
    listed_item = SimpleNamespace(
        attempt_id=attempt_id,
        review_id=review_id,
        source_record_id="lf_source_record_" + "3" * 32,
        url="https://public.example/project",
        evidence_semantics="SUPPLIED_SEARCH_RESPONSE_UNVERIFIED",
        state="OPEN",
        state_digest=state_digest,
        latest_decision="",
        record_payload_hash="c" * 64,
        requested_at_utc="2026-09-11T00:00:00Z",
        query="PRIVATE_QUERY_SENTINEL",
        title="PRIVATE_TITLE_SENTINEL",
        token="PRIVATE_TOKEN_SENTINEL",
    )
    resolution = SimpleNamespace(
        created=True,
        review_id=review_id,
        decision="REJECT",
        resolution_id="lf_source_review_resolution_" + "4" * 32,
        resolution_event_id="lf_event_" + "5" * 32,
        sequence_number=1,
        queue_event_id="lf_event_" + "6" * 32,
        private_payload="PRIVATE_RESOLUTION_SENTINEL",
    )
    closed = {"operation": "SOURCE_DISCOVERY_REVIEW_CLOSE_LOCAL", "state": "CLOSED"}

    with patch.object(
        source_cli, "list_yandex_review_batch", return_value=(listed_item,)
    ) as list_batch:
        assert (
            source_cli.main(
                [
                    "review-list",
                    "--attempt-id",
                    attempt_id,
                    "--expected-receipt-sha256",
                    receipt_sha256,
                ]
            )
            == 0
        )
    listed = json.loads(capsys.readouterr().out)
    assert listed["attempt_id"] == attempt_id
    assert listed["batch_receipt_sha256"] == receipt_sha256
    assert listed["effects"]["provider_read_may_be_metered"] is False
    assert listed["items"] == [
        {
            "attempt_id": attempt_id,
            "evidence_semantics": "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED",
            "latest_decision": "",
            "record_payload_hash": "c" * 64,
            "requested_at_utc": "2026-09-11T00:00:00Z",
            "review_id": review_id,
            "source_record_id": "lf_source_record_" + "3" * 32,
            "state": "OPEN",
            "state_digest": state_digest,
            "url": "https://public.example/project",
        }
    ]
    assert "PRIVATE_" not in json.dumps(listed)
    list_batch.assert_called_once_with(
        source_lab_path=source_cli.SOURCE_DISCOVERY_SOURCE_LAB_PATH,
        attempt_id=attempt_id,
        expected_receipt_sha256=receipt_sha256,
    )

    with patch.object(
        source_cli, "decide_yandex_review_candidate", return_value=resolution
    ) as decide:
        assert (
            source_cli.main(
                [
                    "review-decide",
                    "--attempt-id",
                    attempt_id,
                    "--expected-receipt-sha256",
                    receipt_sha256,
                    "--review-id",
                    review_id,
                    "--expected-state-digest",
                    state_digest,
                    "--reviewer",
                    "operator-1",
                    "--decision",
                    "REJECT",
                    "--reason",
                    "NOT_RELEVANT",
                    "--evidence-ref",
                    "evidence://review/1",
                    "--idempotency-key",
                    "decision-1",
                ]
            )
            == 0
        )
    decided = json.loads(capsys.readouterr().out)
    assert decided["attempt_id"] == attempt_id
    assert decided["batch_receipt_sha256"] == receipt_sha256
    assert decided["effects"]["provider_read_may_be_metered"] is False
    assert decided["resolution"] == {
        "created": True,
        "decision": "REJECT",
        "queue_event_id": "lf_event_" + "6" * 32,
        "resolution_event_id": "lf_event_" + "5" * 32,
        "resolution_id": "lf_source_review_resolution_" + "4" * 32,
        "review_id": review_id,
        "sequence_number": 1,
    }
    assert "PRIVATE_" not in json.dumps(decided)
    decide.assert_called_once_with(
        source_lab_path=source_cli.SOURCE_DISCOVERY_SOURCE_LAB_PATH,
        attempt_id=attempt_id,
        expected_receipt_sha256=receipt_sha256,
        review_id=review_id,
        expected_state_digest=state_digest,
        reviewer="operator-1",
        decision="REJECT",
        reason="NOT_RELEVANT",
        evidence_ref="evidence://review/1",
        idempotency_key="decision-1",
    )

    with patch.object(source_cli, "close_source_discovery_review", return_value=closed) as close:
        assert (
            source_cli.main(
                [
                    "review-close",
                    "--attempt-id",
                    attempt_id,
                    "--actor",
                    "operator-1",
                    "--evidence-ref",
                    "evidence://review/close-1",
                    "--idempotency-key",
                    "close-1",
                    "--confirm-local-close",
                ]
            )
            == 0
        )
    assert json.loads(capsys.readouterr().out) == closed
    close.assert_called_once_with(
        attempt_id=attempt_id,
        confirmation=source_cli.SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
        state_path=source_cli.SOURCE_DISCOVERY_STATE_PATH,
        actor="operator-1",
        evidence_ref="evidence://review/close-1",
        idempotency_key="close-1",
    )


def test_source_cli_local_review_errors_report_no_provider_read(
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempt_id = "sd_" + "1" * 32
    receipt_sha256 = "a" * 64
    with patch.object(
        source_cli,
        "list_yandex_review_batch",
        side_effect=source_cli.YandexSourceLabBridgeError("LOCAL_REVIEW_FAILED"),
    ):
        assert (
            source_cli.main(
                [
                    "review-list",
                    "--attempt-id",
                    attempt_id,
                    "--expected-receipt-sha256",
                    receipt_sha256,
                ]
            )
            == 2
        )
    payload = json.loads(capsys.readouterr().err)
    assert payload["state"] == "FAILED_CLOSED"
    assert payload["error_code"] == "LOCAL_REVIEW_FAILED"
    assert payload["effects"]["provider_read_may_be_metered"] is False


def test_source_cli_rejects_unsafe_review_tokens_before_bridge_call(
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempt_id = "sd_" + "1" * 32
    receipt_sha256 = "a" * 64
    state_digest = "b" * 64
    unsafe_reviewer = 'review"er'
    with patch.object(source_cli, "decide_yandex_review_candidate") as decide:
        with pytest.raises(SystemExit) as captured:
            source_cli.main(
                [
                    "review-decide",
                    "--attempt-id",
                    attempt_id,
                    "--expected-receipt-sha256",
                    receipt_sha256,
                    "--review-id",
                    "lf_source_review_" + "2" * 32,
                    "--expected-state-digest",
                    state_digest,
                    "--reviewer",
                    unsafe_reviewer,
                    "--decision",
                    "REJECT",
                    "--reason",
                    "NOT_RELEVANT",
                    "--evidence-ref",
                    "evidence://review/1",
                    "--idempotency-key",
                    "decision-1",
                ]
            )
    assert captured.value.code == 2
    decide.assert_not_called()
    error = capsys.readouterr().err
    assert unsafe_reviewer not in error
    assert "invalid reviewer or actor token" in error

    oversized_idempotency_key = "k" * 129
    with patch.object(source_cli, "decide_yandex_review_candidate") as decide:
        with pytest.raises(SystemExit) as captured:
            source_cli.main(
                [
                    "review-decide",
                    "--attempt-id",
                    attempt_id,
                    "--expected-receipt-sha256",
                    receipt_sha256,
                    "--review-id",
                    "lf_source_review_" + "2" * 32,
                    "--expected-state-digest",
                    state_digest,
                    "--reviewer",
                    "operator-1",
                    "--decision",
                    "REJECT",
                    "--reason",
                    "NOT_RELEVANT",
                    "--evidence-ref",
                    "evidence://review/1",
                    "--idempotency-key",
                    oversized_idempotency_key,
                ]
            )
    assert captured.value.code == 2
    decide.assert_not_called()
    error = capsys.readouterr().err
    assert oversized_idempotency_key not in error
    assert "invalid idempotency token" in error


@pytest.mark.skipif(
    os.name != "nt" or not VENV_PYTHON.is_file(),
    reason="requires the checked repo-local Windows virtual environment",
)
def test_launcher_rejects_quote_bearing_review_token_before_native_dispatch(
    tmp_path: Path,
) -> None:
    attempt_id = "sd_" + "1" * 32
    unsafe_reviewer = 'review"er'
    result = _run_launcher(
        tmp_path,
        "source",
        "Review-Decide",
        "--attempt-id",
        attempt_id,
        "--expected-receipt-sha256",
        "a" * 64,
        "--review-id",
        "lf_source_review_" + "2" * 32,
        "--expected-state-digest",
        "b" * 64,
        "--reviewer",
        unsafe_reviewer,
        "--decision",
        "REJECT",
        "--reason",
        "NOT_RELEVANT",
        "--evidence-ref",
        "evidence://review/1",
        "--idempotency-key",
        "decision-1",
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "SAFE_LEAD_FLOW_FAILED"
    assert unsafe_reviewer not in result.stderr

    secret_decision = "SECRET_API_TOKEN_ABC123"
    result = _run_launcher(
        tmp_path,
        "source",
        "review-decide",
        "--attempt-id",
        attempt_id,
        "--expected-receipt-sha256",
        "a" * 64,
        "--review-id",
        "lf_source_review_" + "2" * 32,
        "--expected-state-digest",
        "b" * 64,
        "--reviewer",
        "operator-1",
        "--decision",
        secret_decision,
        "--reason",
        "NOT_RELEVANT",
        "--evidence-ref",
        "evidence://review/1",
        "--idempotency-key",
        "decision-1",
    )
    assert result.returncode == 2
    assert secret_decision not in result.stdout
    assert secret_decision not in result.stderr
    assert "invalid review decision" in result.stderr
