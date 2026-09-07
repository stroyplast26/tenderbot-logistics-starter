"""Read-only Windows readiness check for a future Bitrix canary.

The checker inventories the known legacy writer entry points.  It never
stops a process, changes a Scheduled Task, edits the registry, or enables a
factory writer.  OS discovery is behind a deliberately narrow provider so
tests and preflight composition can inject a fully synthetic snapshot.

Reports contain only stable component identifiers and allowlisted status
tokens.  Process IDs, command lines, paths, task actions, registry values,
provider errors, and other host-controlled data are never exposed.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
import subprocess
from types import MappingProxyType
from typing import Mapping, Protocol


UNKNOWN = "unknown"

TASK_COMPONENTS = (
    "scheduled_task.alt_dealer_poll",
    "scheduled_task.alt_builder_poll",
    "scheduled_task.alt_dealer_send",
    "scheduled_task.alt_morning_resume",
    "scheduled_task.tenderbot_resume",
    "scheduled_task.tenderbot_watchdog",
    "scheduled_task.tenderbot_engine",
)

PROCESS_COMPONENTS = (
    "process.tb_bot",
    "process.dealer_poll",
    "process.dealer_send",
    "process.builder_poll",
    "process.builder_send",
    "process.taskbot_supervisor",
    "process.taskbot_app",
)

AUTORUN_COMPONENTS = ("autorun.tenderbot_taskbot",)

ALL_COMPONENTS = TASK_COMPONENTS + PROCESS_COMPONENTS + AUTORUN_COMPONENTS

_TASK_STATUSES = frozenset(("missing", "disabled", "enabled", "running", UNKNOWN))
_PROCESS_STATUSES = frozenset(("not_running", "running", UNKNOWN))
_AUTORUN_STATUSES = frozenset(("absent", "present", UNKNOWN))

_SAFE_STATUSES = frozenset(("missing", "disabled", "not_running", "absent"))


def _safe_observations(
    raw: Mapping[str, object],
    component_ids: tuple[str, ...],
    allowed_statuses: frozenset[str],
) -> Mapping[str, str]:
    """Copy only inventoried IDs and allowlisted status tokens."""
    if not isinstance(raw, Mapping):
        raise TypeError("readiness observations must be a mapping")
    safe: dict[str, str] = {}
    for component_id in component_ids:
        value = raw.get(component_id, UNKNOWN)
        safe[component_id] = (
            value if isinstance(value, str) and value in allowed_statuses else UNKNOWN
        )
    return MappingProxyType(safe)


@dataclass(frozen=True, slots=True)
class WindowsReadinessSnapshot:
    """Provider result reduced to safe states for the fixed inventory."""

    scheduled_tasks: Mapping[str, object]
    processes: Mapping[str, object]
    autoruns: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scheduled_tasks",
            _safe_observations(self.scheduled_tasks, TASK_COMPONENTS, _TASK_STATUSES),
        )
        object.__setattr__(
            self,
            "processes",
            _safe_observations(self.processes, PROCESS_COMPONENTS, _PROCESS_STATUSES),
        )
        object.__setattr__(
            self,
            "autoruns",
            _safe_observations(self.autoruns, AUTORUN_COMPONENTS, _AUTORUN_STATUSES),
        )


class WindowsReadinessProvider(Protocol):
    """Narrow read-only provider boundary used by the checker."""

    def snapshot(self) -> WindowsReadinessSnapshot:
        """Return observations without raw operating-system evidence."""


@dataclass(frozen=True, slots=True)
class WindowsReadinessComponent:
    component_id: str
    status: str


class WindowsCanaryNotReady(RuntimeError):
    """A future canary must not start while readiness is unproven."""


@dataclass(frozen=True, slots=True)
class WindowsCanaryReadinessReport:
    ok: bool
    components: tuple[WindowsReadinessComponent, ...]

    @property
    def not_ready_component_ids(self) -> tuple[str, ...]:
        return tuple(
            component.component_id
            for component in self.components
            if component.status not in _SAFE_STATUSES
        )

    def require_ok(self) -> None:
        """Fail without disclosing host evidence if the report is not safe."""
        if not self.ok:
            raise WindowsCanaryNotReady("windows canary readiness is not proven")


def _unknown_report() -> WindowsCanaryReadinessReport:
    return WindowsCanaryReadinessReport(
        ok=False,
        components=tuple(
            WindowsReadinessComponent(component_id=component_id, status=UNKNOWN)
            for component_id in ALL_COMPONENTS
        ),
    )


class WindowsCanaryReadinessChecker:
    """Fail-closed evaluator for one injected read-only snapshot provider."""

    def __init__(self, provider: WindowsReadinessProvider) -> None:
        self._provider = provider

    def check(self) -> WindowsCanaryReadinessReport:
        try:
            snapshot = self._provider.snapshot()
            if type(snapshot) is not WindowsReadinessSnapshot:
                return _unknown_report()
            status_by_id = {
                **snapshot.scheduled_tasks,
                **snapshot.processes,
                **snapshot.autoruns,
            }
            components = tuple(
                WindowsReadinessComponent(
                    component_id=component_id,
                    status=status_by_id.get(component_id, UNKNOWN),
                )
                for component_id in ALL_COMPONENTS
            )
        except Exception:
            # Provider-controlled exception text may contain a path, command
            # line, registry value, or secret.  It is intentionally discarded.
            return _unknown_report()
        return WindowsCanaryReadinessReport(
            ok=all(component.status in _SAFE_STATUSES for component in components),
            components=components,
        )


class WindowsReadinessProviderError(RuntimeError):
    """The default provider could not produce a trustworthy safe snapshot."""


# The script emits only fixed component IDs and allowlisted state tokens.  It
# may inspect command lines in memory to identify Python/cmd-hosted writers,
# but those values are never returned by PowerShell or retained in a report.
_READ_ONLY_POWERSHELL_PROBE = r"""
$ErrorActionPreference = 'Stop'

$taskSpecs = [ordered]@{
    'scheduled_task.alt_dealer_poll' = 'ALT_DealerPoll'
    'scheduled_task.alt_builder_poll' = 'ALT_BuilderPoll'
    'scheduled_task.alt_dealer_send' = 'ALT_DealerSend'
    'scheduled_task.alt_morning_resume' = 'ALT_MorningResume'
    'scheduled_task.tenderbot_resume' = 'TenderBotResume'
    'scheduled_task.tenderbot_watchdog' = 'TenderBotWatchdog'
    'scheduled_task.tenderbot_engine' = 'TenderBotEngine'
}
$taskResult = [ordered]@{}
try {
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($spec in $taskSpecs.GetEnumerator()) {
        $matches = @($allTasks | Where-Object { $_.TaskName -eq $spec.Value })
        if ($matches.Count -eq 0) {
            $taskResult[$spec.Key] = 'missing'
        }
        elseif (@($matches | Where-Object { ([string]$_.State) -eq 'Running' }).Count -gt 0) {
            $taskResult[$spec.Key] = 'running'
        }
        elseif (@($matches | Where-Object { $_.Settings.Enabled -eq $true }).Count -gt 0) {
            $taskResult[$spec.Key] = 'enabled'
        }
        elseif (@($matches | Where-Object {
            ($null -eq $_.Settings) -or ($null -eq $_.Settings.Enabled)
        }).Count -gt 0) {
            $taskResult[$spec.Key] = 'unknown'
        }
        else {
            $taskResult[$spec.Key] = 'disabled'
        }
    }
}
catch {
    foreach ($componentId in $taskSpecs.Keys) {
        $taskResult[$componentId] = 'unknown'
    }
}

$processIds = @(
    'process.tb_bot',
    'process.dealer_poll',
    'process.dealer_send',
    'process.builder_poll',
    'process.builder_send',
    'process.taskbot_supervisor',
    'process.taskbot_app'
)
$processFound = [ordered]@{}
foreach ($componentId in $processIds) { $processFound[$componentId] = $false }
$processScanComplete = $true
try {
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $candidateHosts = @(
        'python.exe', 'pythonw.exe', 'py.exe', 'cmd.exe',
        'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe'
    )
    foreach ($process in $processes) {
        $name = ([string]$process.Name).ToLowerInvariant()
        $command = [string]$process.CommandLine
        if (($candidateHosts -contains $name) -and [string]::IsNullOrWhiteSpace($command)) {
            $processScanComplete = $false
            continue
        }
        $line = $command.ToLowerInvariant().Replace('\', '/')

        if ($line.Contains('tb_bot.py')) {
            $processFound['process.tb_bot'] = $true
        }
        if (
            ($line.Contains('tb_dealer_campaign.py') -and $line.Contains('--poll')) -or
            $line.Contains('dealer_poll.bat') -or
            ($line.Contains('scheduled_runner.py') -and $line.Contains('dealer_poll'))
        ) {
            $processFound['process.dealer_poll'] = $true
        }
        if (
            ($line.Contains('tb_dealer_campaign.py') -and $line.Contains('--send')) -or
            $line.Contains('dealer_send.bat') -or
            ($line.Contains('scheduled_runner.py') -and $line.Contains('dealer_send'))
        ) {
            $processFound['process.dealer_send'] = $true
        }
        if (
            ($line.Contains('tb_builder_campaign.py') -and $line.Contains('--poll')) -or
            $line.Contains('builder_poll.bat') -or
            $line.Contains('builder_poll_scheduled.bat') -or
            ($line.Contains('scheduled_runner.py') -and $line.Contains('builder_poll'))
        ) {
            $processFound['process.builder_poll'] = $true
        }
        if (
            ($line.Contains('tb_builder_campaign.py') -and $line.Contains('--send')) -or
            $line.Contains('builder_send.bat') -or
            ($line.Contains('scheduled_runner.py') -and $line.Contains('builder_send'))
        ) {
            $processFound['process.builder_send'] = $true
        }
        if ($line.Contains('taskbot.supervisor') -or $line.Contains('taskbot/supervisor.py')) {
            $processFound['process.taskbot_supervisor'] = $true
        }
        if ($line.Contains('taskbot.app') -or $line.Contains('taskbot/app.py')) {
            $processFound['process.taskbot_app'] = $true
        }
    }
}
catch {
    $processScanComplete = $false
}

$processResult = [ordered]@{}
foreach ($componentId in $processIds) {
    if ($processFound[$componentId]) {
        $processResult[$componentId] = 'running'
    }
    elseif ($processScanComplete) {
        $processResult[$componentId] = 'not_running'
    }
    else {
        $processResult[$componentId] = 'unknown'
    }
}

[ordered]@{
    scheduled_tasks = $taskResult
    processes = $processResult
} | ConvertTo-Json -Compress -Depth 4
"""

_POWERSHELL_UTF8_PREFIX = r"""
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom
"""


class DefaultWindowsReadinessProvider:
    """Production-shaped read-only Windows inventory provider.

    Calling :meth:`snapshot` performs two observations only: a PowerShell
    Scheduled Tasks/CIM query and an HKCU ``Run`` value-presence query.  No raw
    output is logged or included in errors.
    """

    _MAX_PROBE_OUTPUT = 64 * 1024

    @staticmethod
    def _powershell_observations() -> tuple[Mapping[str, object], Mapping[str, object]]:
        try:
            # Windows PowerShell expects EncodedCommand as UTF-16LE.  Passing
            # one complete script avoids the line-oriented behaviour of
            # ``-Command -`` for multiline blocks.  The script itself forces
            # UTF-8 JSON; stderr stays bytes and is discarded without ever
            # being decoded, logged, or attached to an exception.
            encoded_probe = base64.b64encode(
                (_POWERSHELL_UTF8_PREFIX + _READ_ONLY_POWERSHELL_PROBE).encode(
                    "utf-16le"
                )
            ).decode("ascii")
            completed = subprocess.run(
                (
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    encoded_probe,
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = completed.stdout or b""
            if completed.returncode != 0 or not stdout or len(stdout) > DefaultWindowsReadinessProvider._MAX_PROBE_OUTPUT:
                raise WindowsReadinessProviderError("windows readiness probe failed")
            parsed = json.loads(stdout.decode("utf-8-sig", errors="strict"))
            tasks = parsed.get("scheduled_tasks")
            processes = parsed.get("processes")
            if not isinstance(tasks, Mapping) or not isinstance(processes, Mapping):
                raise WindowsReadinessProviderError("windows readiness probe failed")
            return tasks, processes
        except WindowsReadinessProviderError:
            raise
        except Exception:
            raise WindowsReadinessProviderError(
                "windows readiness probe failed"
            ) from None

    @staticmethod
    def _autorun_observation() -> str:
        try:
            import winreg
        except ImportError:
            return UNKNOWN

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                key_path,
                0,
                winreg.KEY_READ,
            ) as key:
                try:
                    winreg.QueryValueEx(key, "TenderBotTaskBot")
                except FileNotFoundError:
                    return "absent"
                return "present"
        except FileNotFoundError:
            return "absent"
        except OSError:
            return UNKNOWN

    def snapshot(self) -> WindowsReadinessSnapshot:
        if os.name != "nt":
            raise WindowsReadinessProviderError("windows readiness probe unavailable")
        tasks, processes = self._powershell_observations()
        return WindowsReadinessSnapshot(
            scheduled_tasks=tasks,
            processes=processes,
            autoruns={
                "autorun.tenderbot_taskbot": self._autorun_observation(),
            },
        )


def check_windows_canary_readiness(
    provider: WindowsReadinessProvider | None = None,
) -> WindowsCanaryReadinessReport:
    """Run the read-only check, using the Windows provider only on demand."""
    selected = DefaultWindowsReadinessProvider() if provider is None else provider
    return WindowsCanaryReadinessChecker(selected).check()


__all__ = [
    "ALL_COMPONENTS",
    "AUTORUN_COMPONENTS",
    "DefaultWindowsReadinessProvider",
    "PROCESS_COMPONENTS",
    "TASK_COMPONENTS",
    "UNKNOWN",
    "WindowsCanaryNotReady",
    "WindowsCanaryReadinessChecker",
    "WindowsCanaryReadinessReport",
    "WindowsReadinessComponent",
    "WindowsReadinessProvider",
    "WindowsReadinessProviderError",
    "WindowsReadinessSnapshot",
    "check_windows_canary_readiness",
]
