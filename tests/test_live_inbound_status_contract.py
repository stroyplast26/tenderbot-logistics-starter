from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

import pytest

from lead_factory.live_mail_bitrix import (
    AUTHORITY_REVOKE_CONFIRMATION,
    revoke_persisted_authority,
)
from tests.test_lead_factory_live_mail_bitrix import create_fresh_v3_state


ROOT = Path(__file__).resolve().parents[1]
STATUS_SCRIPT = ROOT / "scripts" / "live_inbound_task_status.ps1"


def _status_source() -> str:
    return STATUS_SCRIPT.read_text(encoding="utf-8")


def _authority_probe_source() -> str:
    match = re.search(
        r"\$AuthorityProbeSource = @'\r?\n(?P<source>.*?)\r?\n'@",
        _status_source(),
        flags=re.DOTALL,
    )
    assert match is not None
    return match.group("source")


def _authority_observation_function_source() -> str:
    source = _status_source()
    start = source.index("function Get-LiveInboundAuthorityObservation")
    return source[start : source.index("$CurrentSid =", start)]


def _prepared_receipt_function_source() -> str:
    source = _status_source()
    return source[
        source.index("function Get-LatestPreparedReleaseReceipt") :
        source.index("function Test-LiveInboundRuntimePayload")
    ]


def _create_authority_database(state_dir: Path, *, state: str) -> Path:
    revoke_persisted_authority(
        state_dir=state_dir,
        release_sha256="c" * 64,
        runtime_sha256="d" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    path = state_dir / "live_mail_bitrix.sqlite3"
    inbound = 1 if state == "ACTIVE" else 0
    columns = (
        "singleton",
        "authority_version",
        "imap_inbox_read",
        "bitrix_lead_list",
        "bitrix_lead_add",
        "bitrix_lead_get",
        "bitrix_activity_list",
        "bitrix_activity_add",
        "bitrix_activity_get",
        "bitrix_timeline_comment_list",
        "bitrix_timeline_comment_add",
        "bitrix_timeline_comment_get",
        "smtp_send",
        "unisender_send",
        "tenderplan_access",
        "confirmation_hash",
        "connection_scope_hash",
        "mailbox_scope_hash",
        "bitrix_scope_hash",
        "release_sha256",
        "runtime_sha256",
        "authority_generation",
        "authority_state",
        "revoked_at_utc",
        "revocation_reason_hash",
        "revoked_by_release_sha256",
        "revoked_by_runtime_sha256",
        "authority_expires_at_utc",
        "write_attempt_budget",
        "write_attempts_used",
        "authorized_at_utc",
    )
    values = (
        1,
        "MailToBitrixInbound.v4",
        *([inbound] * 10),
        0,
        0,
        0,
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "4" * 64,
        "a" * 64,
        "b" * 64,
        7,
        state,
        "" if state == "ACTIVE" else "2026-09-02T00:00:00Z",
        "" if state == "ACTIVE" else "5" * 64,
        "" if state == "ACTIVE" else "c" * 64,
        "" if state == "ACTIVE" else "d" * 64,
        "2026-09-03T00:00:00Z" if state == "ACTIVE" else "",
        10,
        2,
        "2026-09-02T00:00:00Z",
    )
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "INSERT INTO scoped_authority(" + ",".join(columns) + ") VALUES(" +
            ",".join("?" for _ in columns) + ")",
            values,
        )
        connection.execute(
            "UPDATE meta SET value='7' WHERE key='authority_generation_counter'"
        )
        if state == "REVOKED":
            connection.executemany(
                "UPDATE meta SET value=? WHERE key=?",
                (
                    ("2026-09-02T00:00:00Z", "authority_last_revoked_at_utc"),
                    ("7", "authority_last_revoked_generation"),
                    ("c" * 64, "authority_last_revoked_by_release_sha256"),
                    ("d" * 64, "authority_last_revoked_by_runtime_sha256"),
                ),
            )
        connection.commit()
    return path


def _insert_active_v3_authority(database: Path, *, generation: int = 4) -> None:
    columns = (
        "singleton",
        "authority_version",
        "imap_inbox_read",
        "bitrix_lead_list",
        "bitrix_lead_add",
        "bitrix_lead_get",
        "smtp_send",
        "unisender_send",
        "tenderplan_access",
        "confirmation_hash",
        "connection_scope_hash",
        "mailbox_scope_hash",
        "bitrix_scope_hash",
        "release_sha256",
        "runtime_sha256",
        "authority_generation",
        "authority_state",
        "authority_expires_at_utc",
        "write_attempt_budget",
        "write_attempts_used",
        "authorized_at_utc",
    )
    values = (
        1,
        "MailToBitrixInbound.v3",
        1,
        1,
        1,
        1,
        0,
        0,
        0,
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "4" * 64,
        "e" * 64,
        "f" * 64,
        generation,
        "ACTIVE",
        "2026-09-08T00:00:00Z",
        20,
        2,
        "2026-09-01T00:00:00Z",
    )
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO scoped_authority(" + ",".join(columns) + ") VALUES(" +
            ",".join("?" for _ in columns) + ")",
            values,
        )
        connection.commit()


def _run_authority_probe(database: Path) -> dict[str, object]:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            _authority_probe_source(),
            str(database),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def test_status_contract_is_read_only_and_fail_closed() -> None:
    source = _status_source()
    for mutating_command in (
        "Disable-ScheduledTask",
        "Enable-ScheduledTask",
        "Register-ScheduledTask",
        "Unregister-ScheduledTask",
        "Start-ScheduledTask",
        "Stop-ScheduledTask",
        ".SetSecurityDescriptor(",
    ):
        assert mutating_command not in source
    for network_surface in (
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "System.Net.",
        "Net.WebClient",
        "HttpClient",
        "SmtpClient",
    ):
        assert network_surface not in source
    assert "-Command verify-release" not in source
    assert "& $PowerShellPath" not in source
    assert "?mode=ro&immutable=1" in source
    assert 'connection.execute("PRAGMA query_only=ON")' in source
    assert "Get-LiveInboundAuthorityObservation" in source
    probe = _authority_probe_source().upper()
    for sql_write in (
        '"INSERT ',
        '"UPDATE ',
        '"DELETE ',
        '"CREATE ',
        '"DROP ',
        '"ALTER ',
        '"REPLACE ',
        '"VACUUM',
        '"ATTACH ',
    ):
        assert sql_write not in probe


def test_status_contract_uses_only_the_pinned_precompiled_label_reader() -> None:
    source = _status_source()
    for forbidden_loader in (
        "Add-Type",
        "TypeDefinition",
        "Reflection.Assembly]::LoadFrom",
        "Reflection.Assembly]::LoadFile",
        "DllImport",
    ):
        assert forbidden_loader not in source

    loader = source[
        source.index("function Import-PinnedMandatoryLabelReader") :
        source.index("$TaskName = 'TenderBot Live Inbound'")
    ]
    exact_read = loader.index("Read-ExactFileBytes")
    byte_hash = loader.index("Get-Sha256HexFromBytes", exact_read)
    hash_gate = loader.index("-cne $ExpectedSha256", byte_hash)
    byte_load = loader.index("[Reflection.Assembly]::Load($Bytes)", hash_gate)
    identity_gate = loader.index(
        "mandatory_label_reader, Version=1.0.0.0, Culture=neutral, "
        "PublicKeyToken=null",
        byte_load,
    )
    type_gate = loader.index(
        "TenderBot.LiveInbound.Security.MandatoryLabelReader", identity_gate
    )
    method_gate = loader.index("$_.Name -ceq 'Read'", type_gate)
    assert exact_read < byte_hash < hash_gate < byte_load
    assert byte_load < identity_gate < type_gate < method_gate
    assert "[string]$Assembly.Location" in loader
    assert "$_.ReturnType -eq [string]" in loader
    assert "$_.GetParameters()[0].ParameterType -eq [string]" in loader


def test_status_contract_requires_v4_self_and_helper_pins() -> None:
    source = _status_source()
    parser = source[: source.index("if ($PSVersionTable.PSEdition")]
    ordered_v4_fields = (
        "release_sha256=(?<release>",
        "runtime_sha256=(?<runtime>",
        "manifest_sha256=(?<manifest>",
        "artifact_sha256=(?<artifact>",
        "status_script_sha256=(?<status>",
        "mandatory_label_reader_sha256=(?<reader>",
        "interval_seconds=(?<interval>",
    )
    offsets = [parser.index(field, parser.index("$CurrentPattern")) for field in ordered_v4_fields]
    assert offsets == sorted(offsets)
    assert "$DescriptionVerified = $null -ne $DescriptionMarker -and " in source
    assert "$TaskMarkerVersion -eq 4" in source
    assert "if (-not $DescriptionVerified)" in source
    assert "task_upgrade_recommended = $TaskMarkerVersion -eq 3" in source
    assert "release_pinned = $DescriptionVerified -and $TaskMarkerVersion -eq 4" in source


def test_status_contract_authenticates_task_before_reading_description() -> None:
    source = _status_source()
    main = source[source.rindex(
        "$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    ) :]
    initial_acl = main.index("$InitialRegisteredCom.GetSecurityDescriptor(0x07)")
    authenticated_description_gate = main.index(
        "if ($InitialTaskAclVerified)", initial_acl
    )
    description_read = main.index(
        "$InitialDescription = [string]$TaskMatches[0].Description"
    )
    fail_closed_gate = main.index(
        "if (-not $TaskIdentityUnambiguous -or -not $InitialTaskAclVerified)"
    )
    assert initial_acl < authenticated_description_gate < description_read
    assert description_read < fail_closed_gate
    assert "$Description = $InitialDescription" in main
    assert main.index("$ProtectedStatusPathVerified -and $StatusScriptVerified") < main.index(
        "$ConfigurationVerified = ("
    )
    assert "[IO.Path]::GetFullPath($PSCommandPath) -ceq" in main
    assert "[IO.Path]::GetFullPath($StatusPath)" in main


def test_status_contract_validates_protected_prepare_receipt_before_loading_dll() -> None:
    receipt = _prepared_receipt_function_source()
    assert "'prepare-receipt.json'" in receipt
    assert "'TenderBot.LiveInbound.AdminPrepareReceipt.v1'" in receipt
    assert "'reservation_description_sha256'" in receipt
    assert "'reservation_kind'" in receipt
    first_acl = receipt.index("Test-ProtectedReleaseAcl")
    receipt_read = receipt.index("Read-ExactFileBytes")
    status_bind = receipt.index("Get-Sha256HexFromBytes -Bytes $StatusBytes")
    helper_bind = receipt.index("Get-Sha256HexFromBytes -Bytes $ReaderBytes")
    dll_load = receipt.index("Import-PinnedMandatoryLabelReader")
    mic_check = receipt.index("Test-HighIntegrityLabel", dll_load)
    assert first_acl < receipt_read < status_bind < helper_bind < dll_load < mic_check
    assert "[string]$Receipt.status_script_sha256" in receipt
    assert "[string]$Receipt.mandatory_label_reader_sha256" in receipt


@pytest.mark.skipif(os.name != "nt", reason="Windows runtime manifest contract")
def test_protected_status_accepts_manifested_zero_byte_runtime_file(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    files = {
        "empty.py": b"",
        "module.py": b"value = 1\n",
    }
    entries: list[dict[str, object]] = []
    for relative, content in files.items():
        (runtime / relative).write_bytes(content)
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    escaped_status = str(STATUS_SCRIPT.resolve()).replace("'", "''")
    probe = (
        "$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped_status}',[ref]$tokens,[ref]$errors);"
        "$exact=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Test-ExactJsonProperties'},$true);"
        "$runtime=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Test-LiveInboundRuntimePayload'},$true);"
        "if($null -eq $exact -or $null -eq $runtime -or "
        "@($errors).Count -ne 0){exit 20};"
        "Invoke-Expression $exact.Extent.Text;"
        "Invoke-Expression $runtime.Extent.Text;"
        "function Test-ProtectedReleaseAcl {param($LiteralPath,$ExecutionSid) "
        "return $true};"
        "function Test-HighIntegrityLabel {"
        "param($LiteralPath,$ReaderType,[switch]$RequireInheritance) return $true};"
        "function Get-FileHash {param($LiteralPath,$Algorithm);"
        "$bytes=[IO.File]::ReadAllBytes($LiteralPath);"
        "$sha=[Security.Cryptography.SHA256]::Create();"
        "try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-',"
        "'')}finally{$sha.Dispose()};[pscustomobject]@{Hash=$hash}};"
        "$manifest=[pscustomobject]@{runtime_files=(ConvertFrom-Json "
        "$env:LF_RUNTIME_ENTRIES)};"
        "$canonical=[ordered]@{files=@($manifest.runtime_files|ForEach-Object{"
        "[ordered]@{path=[string]$_.path;sha256=[string]$_.sha256;"
        "size=[int64]$_.size}});"
        "format='TenderBot.LiveInbound.RuntimeTree.v1'}|"
        "ConvertTo-Json -Compress -Depth 5;"
        "$hasher=[Security.Cryptography.SHA256]::Create();"
        "try{$runtimeSha=([BitConverter]::ToString($hasher.ComputeHash("
        "[Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-',"
        "'').ToLowerInvariant()}finally{$hasher.Dispose()};"
        "$ok=Test-LiveInboundRuntimePayload "
        "-RuntimeDir $env:LF_RUNTIME_ROOT -Manifest $manifest "
        "-RuntimeSha256 $runtimeSha "
        "-ExecutionSid 'S-1-5-21-1-2-3-1001' "
        "-MandatoryLabelReaderType ([type][object]);"
        "if(-not $ok){exit 21}"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "LF_RUNTIME_ENTRIES": json.dumps(entries, separators=(",", ":")),
            "LF_RUNTIME_ROOT": str(runtime),
        }
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
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 runtime contract")
@pytest.mark.parametrize("invalid_directory", [False, True])
def test_prepare_receipt_lookup_returns_null_for_empty_or_invalid_set(
    tmp_path: Path,
    invalid_directory: bool,
) -> None:
    request_root = tmp_path / "requests"
    release_root = tmp_path / "releases"
    request_root.mkdir()
    release_root.mkdir()
    if invalid_directory:
        (request_root / "not-a-request-id").mkdir()

    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    escaped_requests = str(request_root.resolve()).replace("'", "''")
    escaped_releases = str(release_root.resolve()).replace("'", "''")
    command = (
        "Set-StrictMode -Version Latest;"
        "function Test-ProtectedReleaseAcl { return $true };"
        + _prepared_receipt_function_source()
        + "$result=Get-LatestPreparedReleaseReceipt "
        + f"-RequestRoot '{escaped_requests}' "
        + f"-ReleaseRoot '{escaped_releases}' "
        + "-ExecutionSid 'S-1-5-21-1-2-3-1001';"
        + "if($null -ne $result){exit 3};Write-Output 'NULL'"
    )
    result = subprocess.run(
        [
            str(powershell),
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
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "NULL"


def test_matching_final_v4_task_consumes_only_its_exact_prepare_receipt() -> None:
    source = _status_source()
    start = source.index("$PreparedReceiptConsumedByFinalTask = (")
    pending_gate = source.index(
        "if ($null -ne $PreparedReceipt -and "
        "-not $PreparedReceiptConsumedByFinalTask)",
        start,
    )
    binding = source[start:pending_gate]
    for field in (
        "Version",
        "ReleaseSha256",
        "RuntimeSha256",
        "ManifestSha256",
        "ArtifactSha256",
        "StatusScriptSha256",
        "MandatoryLabelReaderSha256",
        "IntervalSeconds",
    ):
        assert f"$InitialDescriptionMarker.{field}" in binding
    assert "[int]$InitialDescriptionMarker.Version -eq 4" in binding
    assert "status = 'prepared_pending_revoke'" in source[pending_gate:]
    assert (
        "prepared_receipt_consumed_by_final_task = "
        "$PreparedReceiptConsumedByFinalTask"
    ) in source


def test_status_contract_requires_exact_six_entry_release_and_manifest() -> None:
    source = _status_source()
    main = source[source.index("$ExpectedTopLevel = @(", source.index("$Description =")) :]
    release_entries = (
        "'live-inbound.pyz'",
        "'mandatory-label-reader.dll'",
        "'read-status.ps1'",
        "'release.json'",
        "'runtime'",
        "'verify-and-run.ps1'",
    )
    top_level_block = main[: main.index(")", main.index("$ExpectedTopLevel = @(")) + 1]
    assert all(entry in top_level_block for entry in release_entries)
    assert "$TopLevel.Count -eq $ExpectedTopLevel.Count" in main
    assert "-CaseSensitive).Count -eq 0" in main

    manifest_fields = (
        "'artifact'",
        "'artifact_sha256'",
        "'format'",
        "'installer_sha256'",
        "'launcher'",
        "'launcher_sha256'",
        "'mandatory_label_reader'",
        "'mandatory_label_reader_sha256'",
        "'python_version'",
        "'release_sha256'",
        "'runtime_dependency_contract'",
        "'runtime_executable'",
        "'runtime_files'",
        "'runtime_sha256'",
        "'source_provenance'",
        "'source_sha256'",
        "'status_script'",
        "'status_script_sha256'",
    )
    manifest_start = main.index("Test-ExactJsonProperties -Value $Manifest -Expected @(")
    manifest_end = main.index(")) -and", manifest_start)
    manifest_block = main[manifest_start:manifest_end]
    assert all(field in manifest_block for field in manifest_fields)
    assert "-Expected @('path', 'sha256', 'size')" in source


def test_status_action_binds_the_mandatory_label_reader_pin() -> None:
    source = _status_source()
    action = source[
        source.index("$ActionArguments = (") : source.index("$FinalTaskMatches = @(")
    ]
    artifact_pin = action.index("-ArtifactSha256 $ArtifactSha256")
    helper_pin = action.index(
        "-MandatoryLabelReaderSha256 $MandatoryLabelReaderSha256"
    )
    sid_pin = action.index("-ExpectedSid $CurrentSid")
    assert artifact_pin < helper_pin < sid_pin
    assert "mandatory_label_reader_sha256 = $MandatoryLabelReaderSha256" in source
    assert "mandatory_label_reader_verified = $MandatoryLabelReaderVerified" in source
    assert "status_script_sha256 = $StatusScriptSha256" in source
    assert "status_script_verified = $StatusScriptVerified" in source


def test_status_contract_exposes_distinct_phase_and_authority_states() -> None:
    source = _status_source()
    for status in (
        "prepared_pending_revoke",
        "installed_revoked",
        "observer_active",
        "authority_unknown",
        "authority_release_mismatch",
        "authority_revocation_mismatch",
        "authority_task_mismatch",
        "configuration_mismatch",
    ):
        assert f"'{status}'" in source
    assert "Get-LatestPreparedReleaseReceipt" in source
    assert "'PREPARED_PENDING'" in source
    assert "'REVOKED_LEGACY_STORE'" in source
    assert source.index("$AuthorityState -ceq 'ACTIVE' -and -not") < source.index(
        "$AuthorityState -ceq 'ACTIVE')"
    )
    assert "$AuthorityRevoked = $AuthorityState -in" in source
    assert source.index("$AuthorityRevoked -and -not") < source.index(
        "$AuthorityRevoked -and ($Running"
    ) < source.index("} elseif ($AuthorityRevoked) {")


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 parser contract")
def test_status_script_parses_with_windows_powershell_51() -> None:
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    escaped = str(STATUS_SCRIPT.resolve()).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped}',[ref]$tokens,[ref]$errors)|Out-Null;"
        "if(@($errors).Count){$errors|ForEach-Object{$_.ToString()};exit 1}"
    )
    result = subprocess.run(
        [
            str(powershell),
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
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 runtime contract")
def test_status_authority_loader_forwards_database_path(tmp_path: Path) -> None:
    database = _create_authority_database(tmp_path / "revoked", state="REVOKED")
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    probe_script = tmp_path / "authority-observation.ps1"
    escaped_runtime = str(Path(sys.executable).resolve()).replace("'", "''")
    escaped_database = str(database.resolve()).replace("'", "''")
    probe_script.write_text(
        _authority_observation_function_source()
        + "\n$observed = Get-LiveInboundAuthorityObservation "
        + f"-RuntimePath '{escaped_runtime}' -DatabasePath '{escaped_database}'\n"
        + "$observed | ConvertTo-Json -Compress\n",
        encoding="utf-8-sig",
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe_script),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["authority_state"] == "REVOKED"
    assert observed["authority_generation"] == 7
    assert observed["revoked_by_release_sha256"] == "c" * 64
    assert observed["revoked_by_runtime_sha256"] == "d" * 64


def test_authority_probe_reports_active_revoked_absent_and_unstable_wal(
    tmp_path: Path,
) -> None:
    active = _create_authority_database(tmp_path / "active", state="ACTIVE")
    revoked = _create_authority_database(tmp_path / "revoked", state="REVOKED")
    absent = tmp_path / "absent" / "live_mail_bitrix.sqlite3"

    active_result = _run_authority_probe(active)
    assert active_result["authority_state"] == "UNKNOWN"
    assert active_result["authority_mode"] == "WRITER_V4_BLOCKED"
    assert active_result["external_writes_enabled"] is True
    assert active_result["authority_generation"] == 7
    assert active_result["release_sha256"] == "a" * 64
    assert active_result["runtime_sha256"] == "b" * 64

    revoked_result = _run_authority_probe(revoked)
    assert revoked_result["authority_state"] == "REVOKED"
    assert revoked_result["revoked_by_release_sha256"] == "c" * 64
    assert revoked_result["revoked_by_runtime_sha256"] == "d" * 64

    assert _run_authority_probe(absent)["authority_state"] == "ABSENT"

    active.with_name(active.name + "-wal").write_bytes(b"uncheckpointed")
    unstable_result = _run_authority_probe(active)
    assert unstable_result["authority_state"] == "UNKNOWN"
    assert unstable_result["authority_mode"] == "UNKNOWN"
    assert unstable_result["external_writes_enabled"] is None


def test_empty_state_revoke_is_observed_as_bound_revoked_no_grant(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    result = revoke_persisted_authority(
        state_dir=state_dir,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )

    observed = _run_authority_probe(state_dir / "live_mail_bitrix.sqlite3")

    assert result["authority_state"] == "REVOKED"
    assert observed["authority_state"] == "REVOKED_NO_GRANT"
    assert observed["authority_generation"] == result["authority_generation"]
    assert observed["revoked_by_release_sha256"] == "a" * 64
    assert observed["revoked_by_runtime_sha256"] == "b" * 64


def test_repeated_revoke_uses_latest_meta_binding_for_existing_revoked_row(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    first = revoke_persisted_authority(
        state_dir=state_dir,
        release_sha256="c" * 64,
        runtime_sha256="d" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    database = state_dir / "live_mail_bitrix.sqlite3"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            """
            INSERT INTO scoped_authority(
                singleton,authority_version,imap_inbox_read,bitrix_lead_list,
                bitrix_lead_add,bitrix_lead_get,smtp_send,unisender_send,
                tenderplan_access,confirmation_hash,release_sha256,runtime_sha256,
                authority_generation,authority_state,revoked_at_utc,
                revoked_by_release_sha256,revoked_by_runtime_sha256,authorized_at_utc
            ) VALUES(1,'MailToBitrixInbound.v4',0,0,0,0,0,0,0,'fixture',?,?,?,
                     'REVOKED','2026-09-02T00:00:00+00:00',?,?,'2026-09-02T00:00:00+00:00')
            """,
            (
                "c" * 64,
                "d" * 64,
                first["authority_generation"],
                "c" * 64,
                "d" * 64,
            ),
        )
        connection.commit()

    second = revoke_persisted_authority(
        state_dir=state_dir,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    observed = _run_authority_probe(database)

    assert second["already_revoked"] is True
    assert observed["authority_state"] == "REVOKED"
    assert observed["release_sha256"] == "c" * 64
    assert observed["runtime_sha256"] == "d" * 64
    assert observed["revoked_by_release_sha256"] == "a" * 64
    assert observed["revoked_by_runtime_sha256"] == "b" * 64


def test_repeated_v4_revoke_normalizes_zero_generation_and_version(
    tmp_path: Path,
) -> None:
    database = _create_authority_database(tmp_path / "v4-zero-generation", state="REVOKED")
    historical_revoked_at = "2026-09-01T11:00:00Z"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE scoped_authority SET authority_version='legacy-v4-row',"
            "authority_generation=0,revoked_at_utc=?,"
            "revoked_by_release_sha256=?,revoked_by_runtime_sha256=? "
            "WHERE singleton=1",
            (historical_revoked_at, "e" * 64, "f" * 64),
        )
        connection.execute(
            "UPDATE meta SET value='11' WHERE key='authority_generation_counter'"
        )
        connection.commit()

    revoked = revoke_persisted_authority(
        state_dir=database.parent,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    observed = _run_authority_probe(database)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT authority_version,authority_generation,revoked_at_utc,"
            "revoked_by_release_sha256,revoked_by_runtime_sha256 "
            "FROM scoped_authority WHERE singleton=1"
        ).fetchone()

    assert revoked["already_revoked"] is True
    assert revoked["authority_generation"] == 11
    assert row == (
        "MailToBitrixInbound.v4",
        11,
        historical_revoked_at,
        "e" * 64,
        "f" * 64,
    )
    assert observed["authority_state"] == "REVOKED"
    assert observed["authority_generation"] == 11
    assert observed["revoked_by_release_sha256"] == "a" * 64
    assert observed["revoked_by_runtime_sha256"] == "b" * 64


def test_authority_probe_rejects_active_outbound_capability(tmp_path: Path) -> None:
    database = _create_authority_database(tmp_path / "unsafe", state="ACTIVE")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE scoped_authority SET smtp_send=1 WHERE singleton=1"
        )
        connection.commit()
    assert _run_authority_probe(database)["authority_state"] == "UNKNOWN"

    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE scoped_authority SET smtp_send=0, authority_version="
            "'MailToBitrixInbound.v3' WHERE singleton=1"
        )
        connection.commit()
    assert _run_authority_probe(database)["authority_state"] == "UNKNOWN"


def test_active_v3_revoke_is_observed_as_bound_legacy_store(tmp_path: Path) -> None:
    database = create_fresh_v3_state(tmp_path / "legacy-active")
    _insert_active_v3_authority(database, generation=4)

    assert _run_authority_probe(database)["authority_state"] == "UNKNOWN"
    revoked = revoke_persisted_authority(
        state_dir=database.parent,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    observed = _run_authority_probe(database)

    with closing(sqlite3.connect(database)) as connection:
        meta = dict(connection.execute("SELECT key,value FROM meta").fetchall())
    assert int(meta["authority_revocation_fence"]) != revoked["authority_generation"]
    assert observed["authority_state"] == "REVOKED_LEGACY_STORE"
    assert observed["authority_generation"] == 4
    assert observed["release_sha256"] == "e" * 64
    assert observed["runtime_sha256"] == "f" * 64
    assert observed["revoked_by_release_sha256"] == "a" * 64
    assert observed["revoked_by_runtime_sha256"] == "b" * 64


def test_repeated_v3_revoke_normalizes_zero_generation_without_rewriting_history(
    tmp_path: Path,
) -> None:
    database = create_fresh_v3_state(tmp_path / "legacy-zero-generation")
    _insert_active_v3_authority(database, generation=0)
    historical_revoked_at = "2026-09-01T10:00:00Z"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            """
            UPDATE scoped_authority SET
                authority_version='legacy-revoked-row',
                authority_state='REVOKED',
                imap_inbox_read=0,bitrix_lead_list=0,bitrix_lead_add=0,
                bitrix_lead_get=0,smtp_send=0,unisender_send=0,
                tenderplan_access=0,authority_generation=0,
                revoked_at_utc=?,revocation_reason_hash=?,
                revoked_by_release_sha256=?,revoked_by_runtime_sha256=?
            WHERE singleton=1
            """,
            (historical_revoked_at, "9" * 64, "c" * 64, "d" * 64),
        )
        connection.execute(
            "INSERT INTO meta(key,value) VALUES('authority_generation_counter','7') "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
        connection.commit()

    revoked = revoke_persisted_authority(
        state_dir=database.parent,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    observed = _run_authority_probe(database)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT authority_version,authority_generation,revoked_at_utc,"
            "revoked_by_release_sha256,revoked_by_runtime_sha256 "
            "FROM scoped_authority WHERE singleton=1"
        ).fetchone()

    assert revoked["already_revoked"] is True
    assert revoked["authority_generation"] == 7
    assert row == (
        "MailToBitrixInbound.v3",
        7,
        historical_revoked_at,
        "c" * 64,
        "d" * 64,
    )
    assert observed["authority_state"] == "REVOKED_LEGACY_STORE"
    assert observed["authority_generation"] == 7
    assert observed["revoked_by_release_sha256"] == "a" * 64
    assert observed["revoked_by_runtime_sha256"] == "b" * 64


def test_rowless_v3_revoke_is_observed_as_bound_legacy_store(
    tmp_path: Path,
) -> None:
    database = create_fresh_v3_state(tmp_path / "legacy-rowless")
    revoked = revoke_persisted_authority(
        state_dir=database.parent,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )

    observed = _run_authority_probe(database)

    assert observed["authority_state"] == "REVOKED_LEGACY_STORE"
    assert observed["authority_generation"] == revoked["authority_generation"]
    assert observed["release_sha256"] == ""
    assert observed["runtime_sha256"] == ""
    assert observed["revoked_by_release_sha256"] == "a" * 64
    assert observed["revoked_by_runtime_sha256"] == "b" * 64


def test_legacy_probe_rejects_schema_drift_and_receipt_mismatch(
    tmp_path: Path,
) -> None:
    drifted = create_fresh_v3_state(tmp_path / "legacy-drift")
    revoke_persisted_authority(
        state_dir=drifted.parent,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    with closing(sqlite3.connect(drifted)) as connection:
        connection.execute(
            "CREATE TRIGGER unexpected_meta_trigger AFTER INSERT ON meta "
            "BEGIN SELECT 1; END"
        )
        connection.commit()
    assert _run_authority_probe(drifted)["authority_state"] == "UNKNOWN"

    mismatched = create_fresh_v3_state(tmp_path / "legacy-mismatch")
    revoke_persisted_authority(
        state_dir=mismatched.parent,
        release_sha256="a" * 64,
        runtime_sha256="b" * 64,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="release_replacement",
    )
    with closing(sqlite3.connect(mismatched)) as connection:
        connection.execute(
            "UPDATE meta SET value='2' "
            "WHERE key='authority_last_revoked_generation'"
        )
        connection.commit()
    assert _run_authority_probe(mismatched)["authority_state"] == "UNKNOWN"
