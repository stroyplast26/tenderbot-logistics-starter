"""Windows PowerShell 5.1 contract for the local-only Yandex activation ACL probe."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


HELPER = Path(__file__).resolve().parents[1] / "scripts" / "check_yandex_activation_acl.ps1"
JOB_ID = "00000000-0000-0000-0000-000000000000"
SHA256 = "0" * 64


def test_activation_acl_helper_has_a_read_only_fixed_path_contract() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "#Requires -Version 5.1" in source
    assert "[Environment]::GetFolderPath('UserProfile')" in source
    assert "'activation-evidence'" in source
    assert "'request-activation.json'" in source
    assert "'request.draft.json'" in source
    assert "'retention-activation.json'" in source
    assert "YANDEX_ACTIVATION_ACL_READY" in source
    assert "YANDEX_ACTIVATION_ACL_REJECTED" in source
    assert "\\A[0-9a-f]{64}\\z" in source
    assert '".preparing-$JobId-*"' in source
    assert '".activating-$JobId-*"' in source
    for forbidden in (
        "ConvertFrom-Json",
        "Get-Content",
        "OpenRead",
        "ReadAll",
        "StreamReader",
        "FileStream",
        "Set-Acl",
        "New-Item",
        "Remove-Item",
        "Set-Content",
        "Add-Content",
    ):
        assert forbidden not in source
    assert "credential" not in source.casefold()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
def test_activation_acl_helper_parses_and_rejects_before_state_access() -> None:
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    quoted = str(HELPER).replace("'", "''")
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

    cases = (
        ("-Phase", "Draft"),
        ("-JobId", "PRIVATE-JOB-SENTINEL", "-EvidenceSha256", SHA256, "-Phase", "Draft"),
        ("-JobId", JOB_ID, "-EvidenceSha256", "A" * 64, "-Phase", "Draft"),
        ("-JobId", JOB_ID, "-EvidenceSha256", "0" * 63, "-Phase", "Draft"),
        ("-JobId", JOB_ID, "-EvidenceSha256", SHA256 + "\n", "-Phase", "Draft"),
        ("-JobId", JOB_ID, "-EvidenceSha256", SHA256, "-Phase", "draft"),
        ("-Phase", "Draft", "-JobId", JOB_ID, "-EvidenceSha256", SHA256),
    )
    for arguments in cases:
        checked = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(HELPER),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert checked.returncode == 2
        assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_REJECTED"
        assert checked.stderr == ""
        assert "PRIVATE" not in checked.stdout
