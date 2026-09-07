"""Concrete, reversible Windows writer quiesce provider.

The provider owns only the fixed legacy writer inventory already used by
``windows_canary_readiness``.  Raw task paths, process command lines and the
HKCU Run value remain inside an opaque receipt and are never rendered in an
exception or ``repr``.  The production runner passes that receipt to a fixed
PowerShell program through stdin, so host-controlled values do not appear in
the PowerShell command line.

Construction and imports are inert.  Windows is observed or changed only when
``capture``, ``quiesce`` or ``restore`` is explicitly called.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import ctypes
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Protocol

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .windows_canary_readiness import (
    PROCESS_COMPONENTS,
    TASK_COMPONENTS,
    WindowsCanaryReadinessReport,
    check_windows_canary_readiness,
)


class WindowsCanaryProviderError(RuntimeError):
    """A reversible Windows operation could not be proven."""


class WindowsControlRunner(Protocol):
    """Narrow injected OS mutation boundary used by the provider."""

    def run(self, action: str, payload: Mapping[str, object]) -> Mapping[str, object]:
        """Execute one allowlisted action and return structured evidence."""


_TASK_NAMES = {
    "scheduled_task.alt_dealer_poll": "ALT_DealerPoll",
    "scheduled_task.alt_builder_poll": "ALT_BuilderPoll",
    "scheduled_task.alt_dealer_send": "ALT_DealerSend",
    "scheduled_task.alt_morning_resume": "ALT_MorningResume",
    "scheduled_task.tenderbot_resume": "TenderBotResume",
    "scheduled_task.tenderbot_watchdog": "TenderBotWatchdog",
    "scheduled_task.tenderbot_engine": "TenderBotEngine",
}

if tuple(_TASK_NAMES) != TASK_COMPONENTS:  # pragma: no cover - import invariant
    raise RuntimeError("windows quiesce task inventory drifted")


# This program accepts exactly one JSON envelope on stdin.  It deliberately
# emits only JSON; stderr is discarded by the runner.  Receipt fields may
# contain credentials, paths, or commands and therefore must never be logged.
_POWERSHELL_CONTROL_SCRIPT = r"""
param($TransportEnvelope)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Get-WriterComponent([string] $line) {
    $normal = $line.ToLowerInvariant().Replace('\', '/')
    if ($normal.Contains('tb_bot.py')) { return 'process.tb_bot' }
    if ((($normal.Contains('tb_dealer_campaign.py')) -and $normal.Contains('--poll')) -or
        $normal.Contains('dealer_poll.bat') -or
        (($normal.Contains('scheduled_runner.py')) -and $normal.Contains('dealer_poll'))) {
        return 'process.dealer_poll'
    }
    if ((($normal.Contains('tb_dealer_campaign.py')) -and $normal.Contains('--send')) -or
        $normal.Contains('dealer_send.bat') -or
        (($normal.Contains('scheduled_runner.py')) -and $normal.Contains('dealer_send'))) {
        return 'process.dealer_send'
    }
    if ((($normal.Contains('tb_builder_campaign.py')) -and $normal.Contains('--poll')) -or
        $normal.Contains('builder_poll.bat') -or
        $normal.Contains('builder_poll_scheduled.bat') -or
        (($normal.Contains('scheduled_runner.py')) -and $normal.Contains('builder_poll'))) {
        return 'process.builder_poll'
    }
    if ((($normal.Contains('tb_builder_campaign.py')) -and $normal.Contains('--send')) -or
        $normal.Contains('builder_send.bat') -or
        (($normal.Contains('scheduled_runner.py')) -and $normal.Contains('builder_send'))) {
        return 'process.builder_send'
    }
    if ($normal.Contains('taskbot.supervisor') -or $normal.Contains('taskbot/supervisor.py')) {
        return 'process.taskbot_supervisor'
    }
    if ($normal.Contains('taskbot.app') -or $normal.Contains('taskbot/app.py')) {
        return 'process.taskbot_app'
    }
    return $null
}

function Capture-State($payload) {
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
    $tasks = @()
    $missingTasks = @()
    foreach ($spec in @($payload.task_specs)) {
        $matches = @($allTasks | Where-Object { $_.TaskName -eq [string]$spec.task_name })
        if ($matches.Count -eq 0) {
            $missingTasks += [ordered]@{
                component_id = [string]$spec.component_id
                task_name = [string]$spec.task_name
            }
        }
        foreach ($task in $matches) {
            if ($null -eq $task.Settings -or $null -eq $task.Settings.Enabled) {
                throw 'task enabled state is unavailable'
            }
            $tasks += [ordered]@{
                component_id = [string]$spec.component_id
                task_name = [string]$task.TaskName
                task_path = [string]$task.TaskPath
                enabled = [bool]$task.Settings.Enabled
                running = (([string]$task.State) -eq 'Running')
            }
        }
    }

    $candidateHosts = @(
        'python.exe', 'pythonw.exe', 'py.exe', 'cmd.exe',
        'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe'
    )
    $processes = @()
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $name = ([string]$process.Name).ToLowerInvariant()
        $command = [string]$process.CommandLine
        if (($candidateHosts -contains $name) -and [string]::IsNullOrWhiteSpace($command)) {
            throw 'candidate process identity is unavailable'
        }
        $component = Get-WriterComponent $command
        if ($null -ne $component) {
            if ([string]::IsNullOrWhiteSpace([string]$process.CreationDate)) {
                throw 'process creation identity is unavailable'
            }
            $processes += [ordered]@{
                component_id = [string]$component
                process_id = [int64]$process.ProcessId
                parent_process_id = [int64]$process.ParentProcessId
                creation_date = [string]$process.CreationDate
                command_line = $command
                working_directory = [string]$payload.working_directory
            }
        }
    }

    $keyPath = 'Software\Microsoft\Windows\CurrentVersion\Run'
    $valueName = 'TenderBotTaskBot'
    $autorun = [ordered]@{ present = $false; kind = ''; value = '' }
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $false)
        if ($null -ne $key) {
            try {
                $names = @($key.GetValueNames())
                if ($names -contains $valueName) {
                    $kind = [string]$key.GetValueKind($valueName)
                    if ($kind -ne 'String' -and $kind -ne 'ExpandString') {
                        throw 'unsupported autorun value kind'
                    }
                    $autorun = [ordered]@{
                        present = $true
                        kind = $kind
                        value = [string]$key.GetValue($valueName, $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    }
                }
            }
            finally { $key.Dispose() }
        }
    }
    catch { throw }
    return [ordered]@{
        tasks = $tasks
        missing_tasks = $missingTasks
        processes = $processes
        autorun = $autorun
    }
}

function Open-RunKey([bool] $writable) {
    $path = 'Software\Microsoft\Windows\CurrentVersion\Run'
    if ($writable) {
        return [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($path, $true)
    }
    return [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path, $false)
}

function Assert-Task($item) {
    $matches = @(Get-ScheduledTask -TaskName ([string]$item.task_name) -ErrorAction Stop |
        Where-Object { $_.TaskPath -eq [string]$item.task_path })
    if ($matches.Count -ne 1) { throw 'captured scheduled task identity changed' }
    return $matches[0]
}

function Assert-MissingTask($item) {
    $matches = @(Get-ScheduledTask -TaskName ([string]$item.task_name) -ErrorAction SilentlyContinue)
    if ($matches.Count -ne 0) { throw 'missing scheduled task appeared after capture' }
}

function Wait-TaskState($item, [bool] $running) {
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        $task = Assert-Task $item
        $isRunning = (([string]$task.State) -eq 'Running')
        if ($isRunning -eq $running) { return $task }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($running) { throw 'scheduled task start was not proven' }
    throw 'scheduled task stop was not proven'
}

function Quiesce-State($state) {
    foreach ($item in @($state.missing_tasks)) { Assert-MissingTask $item }
    $key = Open-RunKey $true
    try {
        $names = @($key.GetValueNames())
        if ([bool]$state.autorun.present) {
            if ($names -contains 'TenderBotTaskBot') {
                $currentKind = [string]$key.GetValueKind('TenderBotTaskBot')
                $currentValue = [string]$key.GetValue('TenderBotTaskBot', $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($currentKind -ne [string]$state.autorun.kind -or
                    $currentValue -ne [string]$state.autorun.value) {
                    throw 'autorun identity changed after capture'
                }
                $key.DeleteValue('TenderBotTaskBot', $false)
            }
        }
        elseif ($names -contains 'TenderBotTaskBot') {
            throw 'autorun appeared after capture'
        }
    }
    finally { if ($null -ne $key) { $key.Dispose() } }

    foreach ($item in @($state.tasks)) {
        $task = Assert-Task $item
        if (([string]$task.State) -eq 'Running') {
            Stop-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
            $task = Wait-TaskState $item $false
        }
        Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
    }

    foreach ($item in @($state.processes)) {
        $current = Get-CimInstance Win32_Process -Filter ("ProcessId = " + [int64]$item.process_id) -ErrorAction Stop
        if ($null -eq $current) { continue }
        if ([string]$current.CreationDate -ne [string]$item.creation_date -or
            [string]$current.CommandLine -ne [string]$item.command_line) {
            throw 'captured process identity changed'
        }
        $result = Invoke-CimMethod -InputObject $current -MethodName Terminate -ErrorAction Stop
        if ([int]$result.ReturnValue -ne 0) { throw 'process termination was not proven' }
    }
    return [ordered]@{ applied = $true }
}

function Restore-State($state) {
    foreach ($item in @($state.missing_tasks)) { Assert-MissingTask $item }
    foreach ($item in @($state.tasks)) {
        $task = Assert-Task $item
        if ([bool]$item.running) {
            Enable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
            $fresh = Assert-Task $item
            if (([string]$fresh.State) -ne 'Running') {
                Start-ScheduledTask -InputObject $fresh -ErrorAction Stop
                $fresh = Wait-TaskState $item $true
            }
            if (-not [bool]$item.enabled) {
                Disable-ScheduledTask -InputObject $fresh -ErrorAction Stop | Out-Null
            }
        }
        else {
            if (([string]$task.State) -eq 'Running') {
                Stop-ScheduledTask -InputObject $task -ErrorAction Stop
                $task = Wait-TaskState $item $false
            }
            $fresh = $task
            if ([bool]$item.enabled) {
                Enable-ScheduledTask -InputObject $fresh -ErrorAction Stop | Out-Null
            }
            else {
                Disable-ScheduledTask -InputObject $fresh -ErrorAction Stop | Out-Null
            }
        }
    }

    # Only process-tree roots are recreated.  Starting both a captured wrapper
    # and each of its children would duplicate the writer.  Scheduled-task
    # roots may already have returned above and are therefore exact-command
    # checked before any process create.
    $capturedProcessIds = @{}
    foreach ($item in @($state.processes)) {
        $capturedProcessIds[[string]$item.process_id] = $true
    }
    foreach ($item in @($state.processes)) {
        if ($capturedProcessIds.ContainsKey([string]$item.parent_process_id)) { continue }
        $currentCount = @(
            Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { [string]$_.CommandLine -eq [string]$item.command_line }
        ).Count
        $requiredCount = @(
            @($state.processes) | Where-Object {
                (-not $capturedProcessIds.ContainsKey([string]$_.parent_process_id)) -and
                [string]$_.command_line -eq [string]$item.command_line
            }
        ).Count
        if ($currentCount -lt $requiredCount) {
            $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                -Arguments @{
                    CommandLine = [string]$item.command_line
                    CurrentDirectory = [string]$item.working_directory
                } -ErrorAction Stop
            if ([int]$created.ReturnValue -ne 0) { throw 'process restoration was not proven' }
        }
    }

    $key = Open-RunKey $true
    try {
        if ([bool]$state.autorun.present) {
            $kind = if ([string]$state.autorun.kind -eq 'ExpandString') {
                [Microsoft.Win32.RegistryValueKind]::ExpandString
            } else { [Microsoft.Win32.RegistryValueKind]::String }
            $key.SetValue('TenderBotTaskBot', [string]$state.autorun.value, $kind)
        }
        else { $key.DeleteValue('TenderBotTaskBot', $false) }
    }
    finally { if ($null -ne $key) { $key.Dispose() } }
    return [ordered]@{ restored = $true }
}

$safeErrors = @{
    'missing envelope' = 'ENVELOPE_MISSING'
    'task enabled state is unavailable' = 'TASK_STATE_UNAVAILABLE'
    'candidate process identity is unavailable' = 'PROCESS_IDENTITY_UNAVAILABLE'
    'process creation identity is unavailable' = 'PROCESS_CREATION_UNAVAILABLE'
    'unsupported autorun value kind' = 'AUTORUN_KIND_UNSUPPORTED'
    'captured scheduled task identity changed' = 'TASK_IDENTITY_CHANGED'
    'missing scheduled task appeared after capture' = 'TASK_APPEARED'
    'scheduled task start was not proven' = 'TASK_START_UNPROVEN'
    'scheduled task stop was not proven' = 'TASK_STOP_UNPROVEN'
    'autorun identity changed after capture' = 'AUTORUN_IDENTITY_CHANGED'
    'autorun appeared after capture' = 'AUTORUN_APPEARED'
    'captured process identity changed' = 'PROCESS_IDENTITY_CHANGED'
    'process termination was not proven' = 'PROCESS_STOP_UNPROVEN'
    'process restoration was not proven' = 'PROCESS_RESTORE_UNPROVEN'
}
try {
    if ($null -eq $TransportEnvelope) { throw 'missing envelope' }
    $envelope = $TransportEnvelope
    switch ([string]$envelope.action) {
        'capture' { $result = Capture-State $envelope.payload }
        'quiesce' { $result = Quiesce-State $envelope.payload.state }
        'restore' { $result = Restore-State $envelope.payload.state }
        default { throw 'unsupported action' }
    }
    [ordered]@{ ok = $true; result = $result } | ConvertTo-Json -Compress -Depth 12
}
catch {
    $code = $safeErrors[[string]$_.Exception.Message]
    if ([string]::IsNullOrWhiteSpace($code)) { $code = 'UNCLASSIFIED' }
    [ordered]@{ ok = $false; error_code = $code } | ConvertTo-Json -Compress
    exit 1
}
"""


# Windows limits the command line to 32,767 characters.  The fixed control
# program is intentionally too substantial to fit safely as EncodedCommand,
# so a small fixed bootstrap reads both the fixed program and the data
# envelope from stdin.  Only the fixed program becomes a ScriptBlock; receipt
# data remains a separate parsed object and is never evaluated as code.
_POWERSHELL_STDIN_BOOTSTRAP = (
    "$ErrorActionPreference='Stop';"
    "$raw=[Console]::In.ReadToEnd();"
    "$transport=$raw|ConvertFrom-Json;"
    "$bytes=[Convert]::FromBase64String([string]$transport.script);"
    "$code=[Text.Encoding]::UTF8.GetString($bytes);"
    "& ([ScriptBlock]::Create($code)) $transport.envelope"
)


class PowerShellWindowsControlRunner:
    """Fixed-script production runner; receipt data travels only over stdin."""

    _MAX_OUTPUT = 128 * 1024
    _ACTIONS = frozenset(("capture", "quiesce", "restore"))

    def run(self, action: str, payload: Mapping[str, object]) -> Mapping[str, object]:
        if action not in self._ACTIONS or not isinstance(payload, Mapping):
            raise WindowsCanaryProviderError("windows control request is invalid")
        if os.name != "nt":
            raise WindowsCanaryProviderError("windows control runner is unavailable")
        try:
            encoded_script = base64.b64encode(
                _POWERSHELL_CONTROL_SCRIPT.encode("utf-8")
            ).decode("ascii")
            transport = json.dumps(
                {
                    "script": encoded_script,
                    "envelope": {"action": action, "payload": payload},
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
            completed = subprocess.run(
                (
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    _POWERSHELL_STDIN_BOOTSTRAP,
                ),
                input=transport,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=45,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = completed.stdout or b""
            if not stdout or len(stdout) > self._MAX_OUTPUT:
                raise WindowsCanaryProviderError("windows control operation failed")
            decoded = json.loads(stdout.decode("utf-8-sig", errors="strict"))
            if not isinstance(decoded, Mapping):
                raise WindowsCanaryProviderError("windows control operation failed")
            if completed.returncode != 0 or decoded.get("ok") is not True:
                code = str(decoded.get("error_code", "") or "")
                if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
                    code = "UNCLASSIFIED"
                raise WindowsCanaryProviderError(
                    f"windows control operation failed ({code})"
                )
            result = decoded.get("result")
            if not isinstance(result, Mapping):
                raise WindowsCanaryProviderError("windows control operation failed")
            return result
        except WindowsCanaryProviderError:
            raise
        except Exception:
            raise WindowsCanaryProviderError("windows control operation failed") from None


@dataclass(frozen=True, slots=True, repr=False)
class _WindowsQuiesceReceipt:
    owner_token: str = field(repr=False)
    state: Mapping[str, object] = field(repr=False)
    capsule_digest: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "<WindowsQuiesceReceipt opaque>"


class _RecoveryCapsuleStore:
    """Bounded authenticated storage for one outstanding restore receipt."""

    _MAGIC = b"TBWQCAP1"
    _AAD = b"TenderBot/WindowsQuiesceRecovery/v1"
    _MAX_PLAINTEXT = 128 * 1024
    _MAX_CAPSULE = 160 * 1024

    def __init__(
        self,
        path: str | os.PathLike[str],
        root: str | os.PathLike[str],
        key: bytes,
    ) -> None:
        if type(key) is not bytes or len(key) != 32:
            raise WindowsCanaryProviderError("windows recovery key is invalid")
        try:
            bounded_root = Path(root).resolve(strict=True)
            if not bounded_root.is_dir():
                raise ValueError
            selected = Path(path)
            if not selected.is_absolute():
                selected = bounded_root / selected
            selected = selected.resolve(strict=False)
            selected.relative_to(bounded_root)
            if selected.parent.resolve(strict=True) != selected.parent:
                raise ValueError
            selected.parent.relative_to(bounded_root)
            if selected.suffix != ".wqcap":
                raise ValueError
            if selected.exists() and (selected.is_symlink() or not selected.is_file()):
                raise ValueError
        except Exception:
            raise WindowsCanaryProviderError(
                "windows recovery capsule path is invalid"
            ) from None
        self._path = selected
        self._root = bounded_root
        self._key = key

    @staticmethod
    def _digest(blob: bytes) -> str:
        return hashlib.sha256(blob).hexdigest()

    def _entropy(self) -> bytes:
        return hmac.new(self._key, self._AAD, hashlib.sha256).digest()

    def _crypt_protect(self, data: bytes, *, decrypt: bool) -> bytes:
        """Use authenticated, same-user Windows DPAPI without any UI."""
        if os.name != "nt":
            raise WindowsCanaryProviderError(
                "windows recovery encryption is unavailable"
            )
        try:
            class DataBlob(ctypes.Structure):
                _fields_ = (
                    ("size", ctypes.c_ulong),
                    ("data", ctypes.POINTER(ctypes.c_ubyte)),
                )

            data_buffer = ctypes.create_string_buffer(data)
            source = DataBlob(
                len(data),
                ctypes.cast(data_buffer, ctypes.POINTER(ctypes.c_ubyte)),
            )
            entropy_bytes = self._entropy()
            entropy_buffer = ctypes.create_string_buffer(entropy_bytes)
            entropy = DataBlob(
                len(entropy_bytes),
                ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte)),
            )
            destination = DataBlob()
            crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            if decrypt:
                operation = crypt32.CryptUnprotectData
                second_argument: object = None
            else:
                operation = crypt32.CryptProtectData
                second_argument = "TenderBot Windows quiesce recovery"
            operation.argtypes = (
                ctypes.POINTER(DataBlob),
                ctypes.c_void_p if decrypt else ctypes.c_wchar_p,
                ctypes.POINTER(DataBlob),
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.POINTER(DataBlob),
            )
            operation.restype = ctypes.c_int
            if not operation(
                ctypes.byref(source),
                second_argument,
                ctypes.byref(entropy),
                None,
                None,
                1,  # CRYPTPROTECT_UI_FORBIDDEN
                ctypes.byref(destination),
            ):
                raise OSError
            try:
                return ctypes.string_at(destination.data, destination.size)
            finally:
                local_free = kernel32.LocalFree
                local_free.argtypes = (ctypes.c_void_p,)
                local_free.restype = ctypes.c_void_p
                local_free(ctypes.cast(destination.data, ctypes.c_void_p))
        except WindowsCanaryProviderError:
            raise
        except Exception:
            message = (
                "windows recovery capsule authentication failed"
                if decrypt
                else "windows recovery encryption failed"
            )
            raise WindowsCanaryProviderError(message) from None

    def _read_blob(self) -> bytes:
        try:
            path = self._path.resolve(strict=True)
            path.relative_to(self._root)
            if path != self._path or path.is_symlink() or not path.is_file():
                raise ValueError
            size = path.stat().st_size
            if size <= len(self._MAGIC) + 16 or size > self._MAX_CAPSULE:
                raise ValueError
            blob = path.read_bytes()
            if len(blob) != size:
                raise ValueError
            return blob
        except Exception:
            raise WindowsCanaryProviderError(
                "windows recovery capsule is unavailable"
            ) from None

    def persist(self, state: Mapping[str, object]) -> str:
        temporary: Path | None = None
        try:
            if self._path.exists():
                raise WindowsCanaryProviderError(
                    "windows recovery capsule is already active"
                )
            plaintext = json.dumps(
                {"version": 1, "state": state},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if not plaintext or len(plaintext) > self._MAX_PLAINTEXT:
                raise WindowsCanaryProviderError(
                    "windows recovery capsule is too large"
                )
            encrypted = self._crypt_protect(plaintext, decrypt=False)
            blob = self._MAGIC + encrypted
            if len(blob) > self._MAX_CAPSULE:
                raise WindowsCanaryProviderError(
                    "windows recovery capsule is too large"
                )
            temporary = self._path.with_name(
                f".{self._path.name}.{secrets.token_hex(12)}.tmp"
            )
            with temporary.open("xb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            # On Windows os.rename is atomic and refuses to replace an existing
            # destination.  The pre-check makes the same single-capsule rule
            # explicit for test hosts.
            if self._path.exists():
                raise WindowsCanaryProviderError(
                    "windows recovery capsule is already active"
                )
            os.rename(temporary, self._path)
            temporary = None
            return self._digest(blob)
        except WindowsCanaryProviderError:
            raise
        except Exception:
            raise WindowsCanaryProviderError(
                "windows recovery capsule could not be sealed"
            ) from None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def load(self) -> tuple[Mapping[str, object], str]:
        try:
            blob = self._read_blob()
            if not blob.startswith(self._MAGIC):
                raise ValueError
            plaintext = self._crypt_protect(
                blob[len(self._MAGIC) :],
                decrypt=True,
            )
            if not plaintext or len(plaintext) > self._MAX_PLAINTEXT:
                raise ValueError
            decoded = json.loads(plaintext.decode("utf-8", errors="strict"))
            if (
                not isinstance(decoded, Mapping)
                or decoded.get("version") != 1
                or not isinstance(decoded.get("state"), Mapping)
            ):
                raise ValueError
            state = _validate_capture(decoded["state"])
            return state, self._digest(blob)
        except WindowsCanaryProviderError:
            raise
        except Exception:
            raise WindowsCanaryProviderError(
                "windows recovery capsule authentication failed"
            ) from None

    def delete_proven(self, expected_digest: str) -> None:
        try:
            blob = self._read_blob()
            if not hmac.compare_digest(self._digest(blob), expected_digest):
                raise ValueError
            self._path.unlink()
            if self._path.exists():
                raise ValueError
        except Exception:
            raise WindowsCanaryProviderError(
                "windows recovery capsule cleanup failed"
            ) from None


def _require_bool(value: object) -> bool:
    if type(value) is not bool:
        raise WindowsCanaryProviderError("windows capture evidence is invalid")
    return value


def _require_text(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise WindowsCanaryProviderError("windows capture evidence is invalid")
    return value


def _validate_capture(raw: Mapping[str, object]) -> Mapping[str, object]:
    """Deep-copy and validate raw evidence without rendering its values."""
    tasks_raw = raw.get("tasks")
    missing_tasks_raw = raw.get("missing_tasks")
    processes_raw = raw.get("processes")
    autorun_raw = raw.get("autorun")
    if (
        not isinstance(tasks_raw, list)
        or not isinstance(missing_tasks_raw, list)
        or not isinstance(processes_raw, list)
        or not isinstance(autorun_raw, Mapping)
    ):
        raise WindowsCanaryProviderError("windows capture evidence is invalid")

    tasks: list[dict[str, object]] = []
    identities: set[tuple[str, str]] = set()
    present_components: set[str] = set()
    for raw_task in tasks_raw:
        if not isinstance(raw_task, Mapping):
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        component_id = _require_text(raw_task.get("component_id"))
        task_name = _require_text(raw_task.get("task_name"))
        task_path = _require_text(raw_task.get("task_path"))
        if component_id not in _TASK_NAMES or task_name != _TASK_NAMES[component_id]:
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        identity = (task_path.casefold(), task_name.casefold())
        if identity in identities:
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        identities.add(identity)
        present_components.add(component_id)
        tasks.append(
            {
                "component_id": component_id,
                "task_name": task_name,
                "task_path": task_path,
                "enabled": _require_bool(raw_task.get("enabled")),
                "running": _require_bool(raw_task.get("running")),
            }
        )

    missing_tasks: list[dict[str, str]] = []
    missing_components: set[str] = set()
    for raw_task in missing_tasks_raw:
        if not isinstance(raw_task, Mapping):
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        component_id = _require_text(raw_task.get("component_id"))
        task_name = _require_text(raw_task.get("task_name"))
        if (
            component_id not in _TASK_NAMES
            or task_name != _TASK_NAMES[component_id]
            or component_id in present_components
            or component_id in missing_components
        ):
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        missing_components.add(component_id)
        missing_tasks.append({"component_id": component_id, "task_name": task_name})
    if present_components | missing_components != set(TASK_COMPONENTS):
        raise WindowsCanaryProviderError("windows capture evidence is invalid")

    processes: list[dict[str, object]] = []
    process_ids: set[int] = set()
    for raw_process in processes_raw:
        if not isinstance(raw_process, Mapping):
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        component_id = _require_text(raw_process.get("component_id"))
        process_id = raw_process.get("process_id")
        parent_process_id = raw_process.get("parent_process_id")
        if (
            component_id not in PROCESS_COMPONENTS
            or type(process_id) is not int
            or process_id <= 0
            or process_id in process_ids
            or type(parent_process_id) is not int
            or parent_process_id < 0
        ):
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        process_ids.add(process_id)
        working_directory = _require_text(raw_process.get("working_directory"))
        if not re.match(r"^(?:[A-Za-z]:[\\/]|\\\\)", working_directory):
            raise WindowsCanaryProviderError("windows capture evidence is invalid")
        processes.append(
            {
                "component_id": component_id,
                "process_id": process_id,
                "parent_process_id": parent_process_id,
                "creation_date": _require_text(raw_process.get("creation_date")),
                "command_line": _require_text(raw_process.get("command_line")),
                "working_directory": working_directory,
            }
        )

    present = _require_bool(autorun_raw.get("present"))
    kind = _require_text(autorun_raw.get("kind"), allow_empty=True)
    value = _require_text(autorun_raw.get("value"), allow_empty=True)
    if (present and kind not in ("String", "ExpandString")) or (
        not present and (kind or value)
    ):
        raise WindowsCanaryProviderError("windows capture evidence is invalid")

    return {
        "tasks": tasks,
        "missing_tasks": missing_tasks,
        "processes": processes,
        "autorun": {"present": present, "kind": kind, "value": value},
    }


class DefaultWindowsQuiesceProvider:
    """Concrete provider compatible with :class:`ReversibleWindowsQuiesce`."""

    def __init__(
        self,
        runner: WindowsControlRunner | None = None,
        *,
        readiness_check: Callable[[], WindowsCanaryReadinessReport] | None = None,
        recovery_capsule_path: str | os.PathLike[str] | None = None,
        recovery_capsule_root: str | os.PathLike[str] | None = None,
        recovery_key: bytes | None = None,
    ) -> None:
        recovery_values = (
            recovery_capsule_path,
            recovery_capsule_root,
            recovery_key,
        )
        if any(value is not None for value in recovery_values) and not all(
            value is not None for value in recovery_values
        ):
            raise WindowsCanaryProviderError(
                "windows recovery capsule configuration is incomplete"
            )
        self._runner = PowerShellWindowsControlRunner() if runner is None else runner
        self._readiness_check = (
            check_windows_canary_readiness
            if readiness_check is None
            else readiness_check
        )
        self._capsule = (
            None
            if recovery_capsule_path is None
            else _RecoveryCapsuleStore(
                recovery_capsule_path,
                recovery_capsule_root,  # type: ignore[arg-type]
                recovery_key,  # type: ignore[arg-type]
            )
        )
        self._owner_token = secrets.token_hex(32)
        self._known_receipts: dict[int, str] = {}

    @staticmethod
    def _capture_payload() -> dict[str, object]:
        return {
            "working_directory": str(Path(__file__).resolve().parents[1]),
            "task_specs": [
                {"component_id": component_id, "task_name": task_name}
                for component_id, task_name in _TASK_NAMES.items()
            ],
        }

    @staticmethod
    def _semantic_state(state: Mapping[str, object]) -> tuple[object, ...]:
        tasks = tuple(
            sorted(
                (
                    item["component_id"],
                    item["task_name"],
                    item["task_path"],
                    item["enabled"],
                    item["running"],
                )
                for item in state["tasks"]  # type: ignore[index]
            )
        )
        missing = tuple(
            sorted(
                (item["component_id"], item["task_name"])
                for item in state["missing_tasks"]  # type: ignore[index]
            )
        )
        processes = tuple(
            sorted(
                (
                    item["component_id"],
                    item["command_line"],
                    item["working_directory"],
                )
                for item in state["processes"]  # type: ignore[index]
            )
        )
        autorun = state["autorun"]  # type: ignore[index]
        return (
            tasks,
            missing,
            processes,
            autorun["present"],
            autorun["kind"],
            autorun["value"],
        )

    @staticmethod
    def _restore_would_reanimate(state: Mapping[str, object]) -> bool:
        """Whether restoring the validated receipt can restart a legacy writer."""

        return (
            any(
                bool(item["enabled"]) or bool(item["running"])
                for item in state["tasks"]  # type: ignore[index]
            )
            or bool(state["processes"])
            or bool(state["autorun"]["present"])  # type: ignore[index]
        )

    def _receipt(self, value: object) -> _WindowsQuiesceReceipt:
        if (
            type(value) is not _WindowsQuiesceReceipt
            or value.owner_token != self._owner_token
            or self._known_receipts.get(id(value))
            not in ("captured", "quiescing", "quiesced", "recovered")
        ):
            raise WindowsCanaryProviderError("windows quiesce receipt is invalid")
        return value

    def capture(self) -> object:
        try:
            raw = self._runner.run(
                "capture",
                self._capture_payload(),
            )
            if not isinstance(raw, Mapping):
                raise WindowsCanaryProviderError("windows capture evidence is invalid")
            state = _validate_capture(raw)
            capsule_digest = None
            if self._capsule is not None:
                capsule_digest = self._capsule.persist(state)
            receipt = _WindowsQuiesceReceipt(
                self._owner_token,
                state,
                capsule_digest,
            )
            self._known_receipts[id(receipt)] = "captured"
            return receipt
        except WindowsCanaryProviderError:
            raise
        except Exception:
            raise WindowsCanaryProviderError("windows capture failed") from None

    def quiesce(self, receipt: object) -> None:
        selected = self._receipt(receipt)
        if self._known_receipts[id(selected)] != "captured":
            raise WindowsCanaryProviderError("windows quiesce receipt is invalid")
        self._known_receipts[id(selected)] = "quiescing"
        try:
            result = self._runner.run("quiesce", {"state": selected.state})
            if result.get("applied") is not True:
                raise WindowsCanaryProviderError("windows quiesce was not proven")
        except WindowsCanaryProviderError:
            raise
        except Exception:
            raise WindowsCanaryProviderError("windows quiesce failed") from None
        self._known_receipts[id(selected)] = "quiesced"

    def import_recovery_capsule(self) -> object:
        """Import one authenticated capsule into a fresh restore-only provider."""
        if self._capsule is None or self._known_receipts:
            raise WindowsCanaryProviderError(
                "windows recovery capsule import is unavailable"
            )
        state, capsule_digest = self._capsule.load()
        receipt = _WindowsQuiesceReceipt(
            self._owner_token,
            state,
            capsule_digest,
        )
        self._known_receipts[id(receipt)] = "recovered"
        return receipt

    def recovery_diagnostics(self) -> Mapping[str, tuple[str, ...]]:
        """Compare an outstanding capsule without exposing host details.

        This is read-only.  It returns only fixed component identifiers and
        mismatch categories, never command lines, paths, registry values, PIDs,
        timestamps, or the encrypted receipt itself.
        """
        if self._capsule is None or self._known_receipts:
            raise WindowsCanaryProviderError("windows recovery diagnostics unavailable")
        expected, _ = self._capsule.load()
        observed = _validate_capture(
            self._runner.run("capture", self._capture_payload())
        )
        task_expected = {
            str(item["component_id"]): (item["enabled"], item["running"])
            for item in expected["tasks"]  # type: ignore[index]
        }
        task_observed = {
            str(item["component_id"]): (item["enabled"], item["running"])
            for item in observed["tasks"]  # type: ignore[index]
        }
        process_expected = {
            str(item["component_id"]): 0
            for item in expected["processes"]  # type: ignore[index]
        }
        process_observed = {
            str(item["component_id"]): 0
            for item in observed["processes"]  # type: ignore[index]
        }
        for item in expected["processes"]:  # type: ignore[index]
            process_expected[str(item["component_id"])] += 1
        for item in observed["processes"]:  # type: ignore[index]
            process_observed[str(item["component_id"])] += 1
        task_mismatch = tuple(
            sorted(
                component
                for component in set(task_expected) | set(task_observed)
                if task_expected.get(component) != task_observed.get(component)
            )
        )
        process_mismatch = tuple(
            sorted(
                component
                for component in set(process_expected) | set(process_observed)
                if process_expected.get(component) != process_observed.get(component)
            )
        )
        autorun_mismatch = ()
        expected_autorun = expected["autorun"]  # type: ignore[index]
        observed_autorun = observed["autorun"]  # type: ignore[index]
        if (
            expected_autorun["present"] != observed_autorun["present"]
            or expected_autorun["kind"] != observed_autorun["kind"]
            or expected_autorun["value"] != observed_autorun["value"]
        ):
            autorun_mismatch = ("autorun.tenderbot_taskbot",)
        return {
            "task_state_mismatch": task_mismatch,
            "process_count_mismatch": process_mismatch,
            "autorun_mismatch": autorun_mismatch,
        }

    def readiness(self) -> WindowsCanaryReadinessReport:
        try:
            report = self._readiness_check()
        except Exception:
            raise WindowsCanaryProviderError("windows readiness failed") from None
        if type(report) is not WindowsCanaryReadinessReport:
            raise WindowsCanaryProviderError("windows readiness failed")
        return report

    def restore(self, receipt: object) -> None:
        selected = self._receipt(receipt)
        try:
            if self._restore_would_reanimate(selected.state):
                assert_external_allowed("windows.restore_legacy_writers")
            result = self._runner.run("restore", {"state": selected.state})
            if result.get("restored") is not True:
                raise WindowsCanaryProviderError("windows restoration was not proven")
            observed_raw = self._runner.run("capture", self._capture_payload())
            observed = _validate_capture(observed_raw)
            if self._semantic_state(observed) != self._semantic_state(selected.state):
                raise WindowsCanaryProviderError("windows restoration was not proven")
            if selected.capsule_digest is not None:
                if self._capsule is None:
                    raise WindowsCanaryProviderError(
                        "windows recovery capsule cleanup failed"
                    )
                self._capsule.delete_proven(selected.capsule_digest)
        except (ExternalAuthorityError, WindowsCanaryProviderError):
            raise
        except Exception:
            raise WindowsCanaryProviderError("windows restoration failed") from None
        self._known_receipts.pop(id(selected), None)


__all__ = [
    "DefaultWindowsQuiesceProvider",
    "PowerShellWindowsControlRunner",
    "WindowsCanaryProviderError",
    "WindowsControlRunner",
]
