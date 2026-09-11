from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap_python_runtime.ps1"
LOCK = ROOT / "requirements-dev-win-py311.lock.txt"
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _windows_powershell() -> Path:
    return (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )


def test_bootstrap_source_keeps_runtime_setup_fail_closed() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "#Requires -Version 5.1" in source
    assert "[switch]$CheckOnly" in source
    assert "$PSScriptRoot" in source
    assert "Get-Location" not in source
    assert "requirements-dev-win-py311.lock.txt" in source
    assert "'.venv'" in source
    assert source.count("sys.implementation.name == 'cpython'") == 2
    assert source.count("sys.version_info[:3] == (3, 11, 9)") == 2
    assert source.count("sys.version_info.releaselevel == 'final'") == 2
    assert source.count("sys.version_info.serial == 0") == 2
    assert source.count("struct.calcsize('P') * 8 == 64") == 2
    assert "-m', 'venv'" in source
    assert "-m', 'ensurepip', '--upgrade'" in source
    assert "--isolated" in source
    assert "'pip' = '26.2.1'" in source
    assert "'setuptools' = '65.5.0'" in source
    assert '"pip==$($BootstrapToolPins[\'pip\'])"' in source
    assert '"setuptools==$($BootstrapToolPins[\'setuptools\'])"' in source
    assert "--no-deps" in source
    assert "--only-binary=:all:" in source
    assert "--requirement" in source
    assert source.count("'install'") == 2
    assert source.count("'--requirement'") == 1
    assert "'check'" in source
    assert "import pytest, requests" in source
    assert "Get-ChildItem Env:" not in source
    assert "python_runtime.bat" not in source
    assert "Artifact hashes remain an explicit release gap" in source

    check_start = source.index("if ($CheckOnly.IsPresent)")
    check_exit = source.index("return", check_start)
    check_block = source[check_start:check_exit]
    assert "'install'" not in check_block
    assert "ensurepip" not in check_block
    assert "Find-Python311" not in check_block


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser contract")
def test_bootstrap_parses_in_windows_powershell_51() -> None:
    powershell = _windows_powershell()
    quoted_script = str(SCRIPT).replace("'", "''")
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
    reason="requires an existing repo-local Windows virtual environment",
)
def test_check_only_is_any_cwd_offline_and_idempotent(tmp_path: Path) -> None:
    powershell = _windows_powershell()
    secret_marker = "must-not-appear-runtime-secret"
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_INDEX_URL": f"https://{secret_marker}.invalid/simple",
            "PIP_EXTRA_INDEX_URL": f"https://{secret_marker}.invalid/extra",
            "PIP_NO_INDEX": "1",
        }
    )
    before = {SCRIPT: _sha256(SCRIPT), LOCK: _sha256(LOCK)}
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCRIPT),
        "-CheckOnly",
    ]

    results = [
        subprocess.run(
            command,
            cwd=tmp_path,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        for _ in range(2)
    ]

    for result in results:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "runtime check passed" in result.stdout.lower()
        assert "cpython 3.11.9 64-bit" in result.stdout.lower()
        assert "pinned toolchain and dependencies" in result.stdout.lower()
        assert secret_marker not in result.stdout
        assert secret_marker not in result.stderr
    assert results[0].stdout == results[1].stdout
    assert before == {SCRIPT: _sha256(SCRIPT), LOCK: _sha256(LOCK)}
