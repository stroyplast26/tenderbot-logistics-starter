from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "run_safe_lead_flow.ps1"
BOOTSTRAP = ROOT / "scripts" / "bootstrap_python_runtime.ps1"
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
CANONICAL_SOURCE_STATE = (
    ROOT / "state" / "lead_factory" / "source_discovery_control.sqlite3"
)


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
    assert "exit ([int]$ChildExitCode)" in source
    assert "SAFE_LEAD_FLOW_FAILED" in source

    expected_routes = {
        "source|plan",
        "source|status",
        "source|check",
        "source|run-one",
        "gold|prepare",
        "gold|admit",
        "gold|report",
        "gold|revalidate",
    }
    for route in expected_routes:
        assert source.count(f"'{route}'") == 1
    assert source.count(" = @('run_source_discovery_once.py',") == 4
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
    state_before = (
        CANONICAL_SOURCE_STATE.read_bytes() if CANONICAL_SOURCE_STATE.exists() else None
    )

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
    state_after = (
        CANONICAL_SOURCE_STATE.read_bytes() if CANONICAL_SOURCE_STATE.exists() else None
    )
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
    assert "STOP" in text
