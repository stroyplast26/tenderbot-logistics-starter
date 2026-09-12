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
    candidate_root = state_root / "activation-candidates"
    candidate_job = candidate_root / JOB_ID
    candidate = candidate_job / "candidate.json"
    if phase == "Evidence":
        candidate_job.mkdir(parents=True)
        candidate.write_bytes(b"synthetic-unread-candidate")
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
        "candidate": candidate,
        "candidate_job": candidate_job,
        "candidate_root": candidate_root,
        "claims": claims,
        "connection": state_root / "connection.json",
        "draft": job / "request.draft.json",
        "evidence": evidence,
        "evidence_job": evidence_job,
        "evidence_root": evidence_job.parent,
        "helper": synthetic_helper,
        "job": job,
        "journal": job / "request.sqlite",
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


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize(
    "destination", ("absent-root", "absent-job", "empty-job", "other-evidence", "selected")
)
def test_evidence_phase_accepts_only_optional_destination_layouts(
    tmp_path: Path, destination: str
) -> None:
    fixture = _synthetic_phase(tmp_path, "Evidence")
    if destination != "selected":
        fixture["evidence"].unlink()
    if destination in {"absent-root", "absent-job"}:
        fixture["evidence_job"].rmdir()
    if destination == "absent-root":
        fixture["evidence_root"].rmdir()
    if destination == "other-evidence":
        (fixture["evidence_job"] / f"{'1' * 64}.json").write_bytes(b"other-evidence")

    checked = _run_synthetic_helper(fixture, "Evidence")

    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_READY"
    assert checked.stderr == ""
    assert fixture["candidate"].read_bytes() == b"synthetic-unread-candidate"
    assert not (fixture["state_root"] / "request-activation.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize("phase", ("Draft", "Request", "Retention", "Active"))
@pytest.mark.parametrize("destination", ("absent-root", "empty-job", "other-evidence"))
def test_existing_phases_still_require_the_selected_evidence(
    tmp_path: Path, phase: str, destination: str
) -> None:
    fixture = _synthetic_phase(tmp_path, phase)
    fixture["evidence"].unlink()
    if destination == "absent-root":
        fixture["evidence_job"].rmdir()
        fixture["evidence_root"].rmdir()
    if destination == "other-evidence":
        (fixture["evidence_job"] / f"{'1' * 64}.json").write_bytes(b"other-evidence")

    checked = _run_synthetic_helper(fixture, phase)

    assert checked.returncode == 2
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_REJECTED"
    assert checked.stderr == ""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize(
    "mutation",
    (
        "missing-candidate", "missing-inbox", "missing-candidate-root",
        "candidate-directory", "inbox-file", "candidate-root-file",
        "extra-inbox-entry", "inbox-stage", "active-root", "active-job",
        "nonempty-claims", "job-stage", "preparing-residue", "activating-residue",
        "root-stage", "invalid-evidence-name", "uppercase-evidence-name",
        "evidence-stage", "evidence-root-file", "evidence-job-file",
    ),
)
def test_evidence_phase_rejects_unsafe_inbox_destination_and_job_layouts(
    tmp_path: Path, mutation: str
) -> None:
    fixture = _synthetic_phase(tmp_path, "Evidence")
    if mutation in {
        "missing-candidate", "missing-inbox", "missing-candidate-root",
        "candidate-directory", "inbox-file", "candidate-root-file",
    }:
        fixture["candidate"].unlink()
        if mutation in {"missing-inbox", "inbox-file", "missing-candidate-root", "candidate-root-file"}:
            fixture["candidate_job"].rmdir()
        if mutation in {"missing-candidate-root", "candidate-root-file"}:
            fixture["candidate_root"].rmdir()
        if mutation == "candidate-directory":
            fixture["candidate"].mkdir()
        if mutation == "inbox-file":
            fixture["candidate_job"].write_bytes(b"not-directory")
        if mutation == "candidate-root-file":
            fixture["candidate_root"].write_bytes(b"not-directory")
    elif mutation in {"extra-inbox-entry", "inbox-stage"}:
        name = "extra.json" if mutation == "extra-inbox-entry" else ".candidate.json.stage-x"
        (fixture["candidate_job"] / name).write_bytes(b"untrusted")
    elif mutation == "active-root":
        (fixture["state_root"] / "request-activation.json").write_bytes(b"pin")
    elif mutation == "active-job":
        (fixture["job"] / "request.json").write_bytes(b"active")
    elif mutation == "nonempty-claims":
        (fixture["claims"] / "claim.json").write_bytes(b"claim")
    elif mutation == "job-stage":
        (fixture["job"] / ".request.json.stage-x").write_bytes(b"stage")
    elif mutation in {"preparing-residue", "activating-residue"}:
        prefix = "preparing" if mutation == "preparing-residue" else "activating"
        (fixture["requests"] / f".{prefix}-{JOB_ID}-x").mkdir()
    elif mutation == "root-stage":
        (fixture["state_root"] / ".request-activation.json.stage-x").write_bytes(b"stage")
    elif mutation in {"invalid-evidence-name", "uppercase-evidence-name", "evidence-stage"}:
        names = {
            "invalid-evidence-name": "untrusted.json",
            "uppercase-evidence-name": f"{'A' * 64}.json",
            "evidence-stage": ".evidence.json.stage-x",
        }
        (fixture["evidence_job"] / names[mutation]).write_bytes(b"untrusted")
    elif mutation in {"evidence-root-file", "evidence-job-file"}:
        fixture["evidence"].unlink()
        fixture["evidence_job"].rmdir()
        target = fixture["evidence_job"]
        if mutation == "evidence-root-file":
            target = fixture["evidence_root"]
            target.rmdir()
        target.write_bytes(b"not-directory")
    else:  # pragma: no cover - fixed parameter list
        raise AssertionError("unknown synthetic mutation")

    checked = _run_synthetic_helper(fixture, "Evidence")

    assert checked.returncode == 2
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_REJECTED"
    assert checked.stderr == ""
    assert str(tmp_path) not in checked.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize(
    "key",
    (
        "state_root", "requests", "job", "claims", "connection", "journal", "draft",
        "candidate_root", "candidate_job", "candidate", "evidence_root", "evidence_job",
        "evidence",
    ),
)
def test_evidence_phase_rejects_wrong_acl_on_every_fixed_path(
    tmp_path: Path, key: str
) -> None:
    fixture = _synthetic_phase(tmp_path, "Evidence")
    changed = subprocess.run(
        [str(Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"),
         str(fixture[key]), "/grant", "*S-1-5-32-544:R"],
        check=False, capture_output=True, text=True, timeout=20,
    )
    assert changed.returncode == 0, changed.stdout + changed.stderr

    checked = _run_synthetic_helper(fixture, "Evidence")

    assert checked.returncode == 2
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_REJECTED"
    assert checked.stderr == ""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL helper contract")
@pytest.mark.parametrize(
    "key", ("candidate_root", "candidate_job", "candidate", "evidence_root", "evidence_job", "evidence")
)
@pytest.mark.parametrize("dangling", (False, True))
def test_evidence_phase_rejects_reparse_inbox_and_destination(
    tmp_path: Path, key: str, dangling: bool
) -> None:
    fixture = _synthetic_phase(tmp_path, "Evidence")
    target = tmp_path / "junction-target"
    target.mkdir()
    original = fixture[key]
    preserved = tmp_path / "preserved-fixture"
    assert original.resolve().is_relative_to(fixture["state_root"].resolve())
    assert preserved.resolve().is_relative_to(tmp_path.resolve())
    original.rename(preserved)
    created = subprocess.run(
        [str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"), "/d", "/c",
         "mklink", "/J", str(original), str(target)],
        check=False, capture_output=True, text=True, timeout=20,
    )
    assert created.returncode == 0, created.stdout + created.stderr
    if dangling:
        target.rmdir()

    checked = _run_synthetic_helper(fixture, "Evidence")

    assert checked.returncode == 2
    assert checked.stdout.strip() == "YANDEX_ACTIVATION_ACL_REJECTED"
    assert checked.stderr == ""
