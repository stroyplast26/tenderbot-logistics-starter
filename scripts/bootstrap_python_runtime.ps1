#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$CheckOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BootstrapToolPins = @{
    'pip' = '26.2.1'
    'setuptools' = '65.5.0'
}

function Normalize-PackageName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return ([Text.RegularExpressions.Regex]::Replace(
        $Name,
        '[-_.]+',
        '-'
    )).ToLowerInvariant()
}

function Read-PinnedRequirements {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Pins = @{}
    foreach ($Line in [IO.File]::ReadAllLines($Path)) {
        $Trimmed = $Line.Trim()
        if ($Trimmed.Length -eq 0 -or $Trimmed.StartsWith('#')) {
            continue
        }
        if ($Trimmed -cnotmatch `
            '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?<version>[^=\s;][^\s;]*)$') {
            throw 'The Windows Python lock contains a non-exact requirement.'
        }
        $RequirementName = [string]$Matches['name']
        $RequirementVersion = [string]$Matches['version']
        $Name = Normalize-PackageName -Name $RequirementName
        if ($Pins.ContainsKey($Name)) {
            throw 'The Windows Python lock contains a duplicate package.'
        }
        $Pins[$Name] = $RequirementVersion
    }
    if ($Pins.Count -eq 0) {
        throw 'The Windows Python lock does not contain package pins.'
    }
    return $Pins
}

function Test-ReparsePoint {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $Item = Get-Item -LiteralPath $LiteralPath -Force
    return [bool](
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint
    )
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & $Executable @Arguments *> $null
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

function Find-Python311 {
    $Candidates = New-Object 'Collections.Generic.List[object]'
    if (
        -not [string]::IsNullOrWhiteSpace($env:TENDERBOT_PYTHON) -and
        [IO.File]::Exists($env:TENDERBOT_PYTHON)
    ) {
        $Candidates.Add([pscustomobject]@{
            Executable = [IO.Path]::GetFullPath($env:TENDERBOT_PYTHON)
            PrefixArguments = @()
        })
    }

    $LocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not [string]::IsNullOrWhiteSpace($LocalAppData)) {
        $LocalPython = Join-Path `
            $LocalAppData `
            'Programs\Python\Python311\python.exe'
        if ([IO.File]::Exists($LocalPython)) {
            $Candidates.Add([pscustomobject]@{
                Executable = [IO.Path]::GetFullPath($LocalPython)
                PrefixArguments = @()
            })
        }
    }

    $Launcher = Get-Command py.exe -CommandType Application `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $Launcher) {
        $Candidates.Add([pscustomobject]@{
            Executable = [string]$Launcher.Source
            PrefixArguments = @('-3.11')
        })
    }

    $PathPython = Get-Command python.exe -CommandType Application `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $PathPython) {
        $Candidates.Add([pscustomobject]@{
            Executable = [string]$PathPython.Source
            PrefixArguments = @()
        })
    }

    $VersionProbe = @'
import struct
import sys
valid = (
    sys.implementation.name == 'cpython'
    and sys.version_info[:3] == (3, 11, 9)
    and sys.version_info.releaselevel == 'final'
    and sys.version_info.serial == 0
    and struct.calcsize('P') * 8 == 64
)
raise SystemExit(0 if valid else 31)
'@
    foreach ($Candidate in $Candidates) {
        $ProbeArguments = @($Candidate.PrefixArguments) + @(
            '-I', '-B', '-c', $VersionProbe
        )
        & $Candidate.Executable @ProbeArguments *> $null
        if ($LASTEXITCODE -eq 0) {
            return $Candidate
        }
    }
    throw 'A working CPython 3.11.9 64-bit interpreter was not found.'
}

function Assert-RepoLocalVenv {
    param(
        [Parameter(Mandatory = $true)][string]$VenvPath,
        [Parameter(Mandatory = $true)][string]$PythonPath
    )

    if (-not (Test-Path -LiteralPath $VenvPath -PathType Container)) {
        throw 'The repo-local .venv directory is missing.'
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw 'The repo-local .venv Python executable is missing.'
    }
    $LocalRuntimePaths = @(
        $VenvPath,
        (Join-Path $VenvPath 'Scripts'),
        (Join-Path $VenvPath 'Lib'),
        (Join-Path $VenvPath 'Lib\site-packages'),
        $PythonPath
    )
    foreach ($LocalRuntimePath in $LocalRuntimePaths) {
        if (
            (Test-Path -LiteralPath $LocalRuntimePath) -and
            (Test-ReparsePoint -LiteralPath $LocalRuntimePath)
        ) {
            throw 'The repo-local .venv must not contain reparse points on runtime paths.'
        }
    }

    $VenvProbe = @'
import os
import struct
import sys
expected = os.path.normcase(os.path.abspath(sys.argv[1]))
actual = os.path.normcase(os.path.abspath(sys.prefix))
valid = (
    sys.implementation.name == 'cpython'
    and sys.version_info[:3] == (3, 11, 9)
    and sys.version_info.releaselevel == 'final'
    and sys.version_info.serial == 0
    and struct.calcsize('P') * 8 == 64
    and actual == expected
)
raise SystemExit(0 if valid else 32)
'@
    Invoke-CheckedNative `
        -Executable $PythonPath `
        -Arguments @('-I', '-B', '-c', $VenvProbe, $VenvPath) `
        -FailureMessage 'The repo-local .venv is not CPython 3.11.9 64-bit.'
}

function Assert-PinnedPackageSet {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][hashtable]$Pins,
        [Parameter(Mandatory = $true)][hashtable]$BootstrapPins
    )

    $InstalledJson = @(
        & $PythonPath -I -B -m pip --isolated `
            --disable-pip-version-check list --format=json 2>$null
    )
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect the repo-local Python package set.'
    }
    $InstalledRows = (
        $InstalledJson -join [Environment]::NewLine
    ) | ConvertFrom-Json -ErrorAction Stop
    $Installed = @{}
    foreach ($Row in $InstalledRows) {
        $Name = Normalize-PackageName -Name ([string]$Row.name)
        if ($Installed.ContainsKey($Name)) {
            throw 'The repo-local Python package set contains a duplicate name.'
        }
        $Installed[$Name] = [string]$Row.version
    }

    $Expected = @{}
    foreach ($Name in $Pins.Keys) {
        $Expected[$Name] = [string]$Pins[$Name]
    }
    foreach ($Name in $BootstrapPins.Keys) {
        if ($Expected.ContainsKey($Name)) {
            throw "Bootstrap package '$Name' must not also appear in the dependency lock."
        }
        $Expected[$Name] = [string]$BootstrapPins[$Name]
    }

    foreach ($Name in $Expected.Keys) {
        if (-not $Installed.ContainsKey($Name)) {
            throw "The repo-local Python package set is missing expected package '$Name'."
        }
        if ([string]$Installed[$Name] -cne [string]$Expected[$Name]) {
            throw "The installed version of expected package '$Name' differs from its pin."
        }
    }

    foreach ($Name in $Installed.Keys) {
        if (-not $Expected.ContainsKey($Name)) {
            throw "The repo-local Python package set contains unlocked package '$Name'."
        }
    }
}

function Assert-RuntimeHealthy {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][hashtable]$Pins,
        [Parameter(Mandatory = $true)][hashtable]$BootstrapPins
    )

    Invoke-CheckedNative `
        -Executable $PythonPath `
        -Arguments @(
            '-I', '-B', '-m', 'pip', '--isolated',
            '--disable-pip-version-check', 'check'
        ) `
        -FailureMessage 'pip check failed for the repo-local Python environment.'
    Assert-PinnedPackageSet `
        -PythonPath $PythonPath `
        -Pins $Pins `
        -BootstrapPins $BootstrapPins
    Invoke-CheckedNative `
        -Executable $PythonPath `
        -Arguments @(
            '-I', '-B', '-c',
            'import pytest, requests; raise SystemExit(0)'
        ) `
        -FailureMessage 'pytest or requests is unavailable in the repo-local environment.'
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This bootstrap supports Windows only.'
}

$ScriptDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..'))
$LockPath = Join-Path $RepoRoot 'requirements-dev-win-py311.lock.txt'
$VenvPath = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path $VenvPath 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
    throw 'The pinned Windows Python lock is missing.'
}
if (Test-ReparsePoint -LiteralPath $LockPath) {
    throw 'The pinned Windows Python lock must not be a reparse point.'
}
$Pins = Read-PinnedRequirements -Path $LockPath

$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONNOUSERSITE = '1'

if ($CheckOnly.IsPresent) {
    Assert-RepoLocalVenv -VenvPath $VenvPath -PythonPath $VenvPython
    Assert-RuntimeHealthy `
        -PythonPath $VenvPython `
        -Pins $Pins `
        -BootstrapPins $BootstrapToolPins
    Write-Output 'TenderBot Python runtime check passed (CPython 3.11.9 64-bit, pinned toolchain and dependencies).'
    return
}

if (Test-Path -LiteralPath $VenvPath) {
    if (-not (Test-Path -LiteralPath $VenvPath -PathType Container)) {
        throw 'The repo-local .venv path exists but is not a directory.'
    }
    Assert-RepoLocalVenv -VenvPath $VenvPath -PythonPath $VenvPython
} else {
    $BasePython = Find-Python311
    $CreateArguments = @($BasePython.PrefixArguments) + @(
        '-I', '-B', '-m', 'venv', $VenvPath
    )
    Invoke-CheckedNative `
        -Executable ([string]$BasePython.Executable) `
        -Arguments $CreateArguments `
        -FailureMessage 'Unable to create the repo-local CPython 3.11.9 64-bit environment.'
    Assert-RepoLocalVenv -VenvPath $VenvPath -PythonPath $VenvPython
}

# Refresh pip from CPython's bundled, offline wheel before installing the exact
# bootstrap-tool pins. Artifact hashes remain an explicit release gap; this
# bootstrap must not be represented as hash-locked until a reviewed hash lock
# and wheel provenance are supplied.
Invoke-CheckedNative `
    -Executable $VenvPython `
    -Arguments @('-I', '-B', '-m', 'ensurepip', '--upgrade', '--default-pip') `
    -FailureMessage 'Unable to refresh pip from the CPython bundle.'
Invoke-CheckedNative `
    -Executable $VenvPython `
    -Arguments @(
        '-I', '-B', '-m', 'pip', '--isolated',
        '--disable-pip-version-check', 'install', '--quiet', '--no-input',
        '--upgrade',
        "pip==$($BootstrapToolPins['pip'])",
        "setuptools==$($BootstrapToolPins['setuptools'])",
        '--no-deps', '--only-binary=:all:',
        '--index-url', 'https://pypi.org/simple'
    ) `
    -FailureMessage 'Unable to safely update pip in the repo-local environment.'

# Every application/test dependency must be an exact pin from the dedicated
# Windows 3.11 lock. --no-deps prevents pip from resolving anything undeclared.
Invoke-CheckedNative `
    -Executable $VenvPython `
    -Arguments @(
        '-I', '-B', '-m', 'pip', '--isolated',
        '--disable-pip-version-check', 'install', '--quiet', '--no-input',
        '--no-deps', '--only-binary=:all:',
        '--index-url', 'https://pypi.org/simple',
        '--requirement', $LockPath
    ) `
    -FailureMessage 'Unable to install the pinned Windows Python dependencies.'

Assert-RuntimeHealthy `
    -PythonPath $VenvPython `
    -Pins $Pins `
    -BootstrapPins $BootstrapToolPins
Write-Output 'TenderBot Python runtime is ready (CPython 3.11.9 64-bit, pinned toolchain and dependencies).'
