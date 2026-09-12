"""Windows PowerShell 5.1 contract for the local-only Yandex activation ACL probe."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest


HELPER = Path(__file__).resolve().parents[1] / "scripts" / "check_yandex_activation_acl.ps1"
JOB_ID = "00000000-0000-0000-0000-000000000000"
SHA256 = "0" * 64


def _windows_powershell() -> Path:
    return (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )


def _set_exact_root_acl(path: Path) -> None:
    quoted = str(path).replace("'", "''")
    command = (
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
        "$sddl='D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+$sid+')';"
        "$acl=New-Object Security.AccessControl.DirectorySecurity;"
        "$acl.SetSecurityDescriptorSddlForm("
        "$sddl,[Security.AccessControl.AccessControlSections]::Access);"
        f"[IO.Directory]::SetAccessControl('{quoted}',$acl)"
    )
    configured = subprocess.run(
        [
            str(_windows_powershell()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr


def _synthetic_phase(tmp_path: Path, phase: str) -> dict[str, Path]:
    profile_suffix = hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:8]
    profile = tmp_path.parent / f"p-{profile_suffix}"
    state_root = (
        profile / ".codex" / "local_state" / "TenderBot" / "yandex-search"
    )
    state_root.mkdir(parents=True)
    _set_exact_root_acl(state_root)

    requests = state_root / "requests"
    job = requests / JOB_ID
    claims = job / "dispatch-claims"
    evidence_job = state_root / "activation-evidence" / JOB_ID
    claims.mkdir(parents=True)
    evidence_job.mkdir(parents=True)
    (state_root / "connection.json").write_bytes(b"synthetic-connection")
    (job / "request.sqlite").write_bytes(b"synthetic-journal")
    (job / "request.draft.json").write_bytes(b"synthetic-draft")
    evidence = evidence_job / f"{SHA256}.json"
    evidence.write_bytes(b"synthetic-evidence")
    if phase in {"Request", "Retention", "Active"}:
        (job / "request.json").write_bytes(b"synthetic-request")
    if phase in {"Retention", "Active"}:
        (job / "retention-activation.json").write_bytes(b"synthetic-pin")
    if phase == "Active":
        (state_root / "request-activation.json").write_bytes(b"synthetic-pin")

    helper_source = HELPER.read_text(encoding="utf-8")
    profile_lookup = "[Environment]::GetFolderPath('UserProfile')"
    assert helper_source.count(profile_lookup) == 1
    synthetic_helper = tmp_path / "check_yandex_activation_acl.synthetic.ps1"
    quoted_profile = str(profile).replace("'", "''")
    synthetic_helper.write_text(
        helper_source.replace(profile_lookup, f"'{quoted_profile}'"),
        encoding="utf-8",
    )
    return {
        "claims": claims,
        "evidence": evidence,
        "evidence_job": evidence_job,
        "helper": synthetic_helper,
        "job": job,
        "requests": requests,
        "state_root": state_root,
        "tmp": tmp_path,
    }


def _run_synthetic_helper(fixture: dict[str, Path], phase: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(_windows_powershell()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(fixture["helper"]),
            "-JobId",
            JOB_ID,
            "-EvidenceSha256",
            SHA256,
            "-Phase",
            phase,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


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
    powershell = _windows_powershell()
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
        (
            "-JobId",
            "01234567-89ab-4cde-8fab-0123456789AB",
            "-EvidenceSha256",
            SHA256,
            "-Phase",
            "Draft",
        ),
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


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize("phase", ("Draft", "Request", "Retention", "Active"))
def test_activation_acl_helper_accepts_each_exact_phase_layout(
    tmp_path: Path,
    phase: str,
) -> None:
    fixture = _synthetic_phase(tmp_path, phase)

    checked = _run_synthetic_helper(fixture, phase)

    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_READY"
    assert checked.stderr == ""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize(
    "mutation",
    (
        "unexpected-job-entry",
        "nonempty-claims",
        "preparing-residue",
        "activating-residue",
        "root-stage-residue",
        "invalid-evidence-name",
        "extra-evidence-ace",
        "claims-junction",
    ),
)
def test_activation_acl_helper_rejects_unsafe_layout_acl_and_reparse(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _synthetic_phase(tmp_path, "Draft")
    if mutation == "unexpected-job-entry":
        (fixture["job"] / "unexpected.txt").write_bytes(b"unexpected")
    elif mutation == "nonempty-claims":
        (fixture["claims"] / "claim.json").write_bytes(b"claim")
    elif mutation == "preparing-residue":
        (fixture["requests"] / f".preparing-{JOB_ID}-synthetic").mkdir()
    elif mutation == "activating-residue":
        (fixture["requests"] / f".activating-{JOB_ID}-synthetic").mkdir()
    elif mutation == "root-stage-residue":
        (fixture["state_root"] / ".request-activation.json.stage-synthetic").write_bytes(
            b"stage"
        )
    elif mutation == "invalid-evidence-name":
        (fixture["evidence_job"] / "unexpected.json").write_bytes(b"unexpected")
    elif mutation == "extra-evidence-ace":
        icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
        changed = subprocess.run(
            [
                str(icacls),
                str(fixture["evidence"]),
                "/grant",
                "*S-1-5-32-544:R",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert changed.returncode == 0, changed.stdout + changed.stderr
    elif mutation == "claims-junction":
        fixture["claims"].rmdir()
        target = fixture["tmp"] / "junction-target"
        target.mkdir()
        created = subprocess.run(
            [
                str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"),
                "/d",
                "/c",
                "mklink",
                "/J",
                str(fixture["claims"]),
                str(target),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert created.returncode == 0, created.stdout + created.stderr
    else:  # pragma: no cover - parameter list is fixed above
        raise AssertionError("unknown synthetic mutation")

    checked = _run_synthetic_helper(fixture, "Draft")

    assert checked.returncode == 2
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_REJECTED"
    assert checked.stderr == ""
    assert str(tmp_path) not in checked.stdout
