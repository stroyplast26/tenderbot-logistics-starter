#Requires -Version 5.1
[CmdletBinding(PositionalBinding = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('source', 'gold')]
    [string]$Flow,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateSet(
        'plan',
        'status',
        'check',
        'run-one',
        'prepare',
        'admit',
        'report',
        'revalidate'
    )]
    [string]$Operation,

    [Parameter(Position = 2, ValueFromRemainingArguments = $true)]
    [AllowEmptyCollection()]
    [string[]]$CommandArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $ScriptDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
    $RepoRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..'))
    $BootstrapPath = Join-Path $ScriptDirectory 'bootstrap_python_runtime.ps1'
    $VenvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'

    $Dispatch = @{
        'source|plan' = @('run_source_discovery_once.py', 'plan')
        'source|status' = @('run_source_discovery_once.py', 'status')
        'source|check' = @('run_source_discovery_once.py', 'check')
        'source|run-one' = @('run_source_discovery_once.py', 'run-one')
        'gold|prepare' = @('run_gold_acceptance.py', 'prepare')
        'gold|admit' = @('run_gold_acceptance.py', 'admit')
        'gold|report' = @('run_gold_acceptance.py', 'report')
        'gold|revalidate' = @('run_gold_acceptance.py', 'revalidate')
    }
    $DispatchKey = "$Flow|$Operation"
    if (-not $Dispatch.ContainsKey($DispatchKey)) {
        throw 'SAFE_LEAD_FLOW_COMMAND_NOT_ALLOWED'
    }
    if ($CommandArguments.Count -gt 128) {
        throw 'SAFE_LEAD_FLOW_ARGUMENT_LIMIT_EXCEEDED'
    }

    # The bootstrap check is the admission gate. It returns to this script only
    # after validating the exact repo-local interpreter and package set.
    $null = & $BootstrapPath -CheckOnly
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        throw 'SAFE_LEAD_FLOW_RUNTIME_UNAVAILABLE'
    }

    $Route = $Dispatch[$DispatchKey]
    $EntryPoint = Join-Path $ScriptDirectory ([string]$Route[0])
    if (-not (Test-Path -LiteralPath $EntryPoint -PathType Leaf)) {
        throw 'SAFE_LEAD_FLOW_ENTRYPOINT_UNAVAILABLE'
    }
    $PythonArguments = @(
        '-I',
        '-B',
        $EntryPoint,
        [string]$Route[1]
    ) + @($CommandArguments)

    # Array splatting passes every child argument literally. There is no shell,
    # command-string construction, fallback interpreter, or expression eval.
    & $VenvPython @PythonArguments
    $ChildExitCode = $LASTEXITCODE
    if ($null -eq $ChildExitCode) {
        throw 'SAFE_LEAD_FLOW_CHILD_EXIT_UNAVAILABLE'
    }
    exit ([int]$ChildExitCode)
} catch {
    [Console]::Error.WriteLine('SAFE_LEAD_FLOW_FAILED')
    exit 2
}
