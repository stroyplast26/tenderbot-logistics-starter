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
        'review-list',
        'review-decide',
        'review-close',
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

$SensitiveEnvironmentPath = 'Env:YANDEX_SEARCH_API_KEY'
$GoldSensitiveEnvironmentPath = 'Env:TENDERBOT_GOLD_APPROVAL_SECRET_B64'
$LauncherMarkerPath = 'Env:TENDERBOT_SAFE_LEAD_FLOW_LAUNCHER'
$LauncherMarkerValue = 'source-discovery-v3'
$SafeLeadFlowExitCode = 2

try {
    # Windows PowerShell's Environment provider is case-insensitive on Windows.
    # Delete the ambient credential without reading its value before any child
    # process can inherit it, and fail closed if the name remains present.
    Remove-Item -LiteralPath $SensitiveEnvironmentPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GoldSensitiveEnvironmentPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $LauncherMarkerPath -Force -ErrorAction SilentlyContinue
    if (
        (Test-Path -LiteralPath $SensitiveEnvironmentPath) -or
        (Test-Path -LiteralPath $GoldSensitiveEnvironmentPath)
    ) {
        throw 'SAFE_LEAD_FLOW_AMBIENT_CREDENTIAL_REJECTED'
    }

    $ScriptDirectory = [IO.Path]::GetFullPath($PSScriptRoot)
    $RepoRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..'))
    $BootstrapPath = Join-Path $ScriptDirectory 'bootstrap_python_runtime.ps1'
    $VenvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'

    $Dispatch = @{
        'source|plan' = @('run_source_discovery_once.py', 'plan')
        'source|status' = @('run_source_discovery_once.py', 'status')
        'source|check' = @('run_source_discovery_once.py', 'check')
        'source|run-one' = @('run_source_discovery_once.py', 'run-one')
        'source|review-list' = @('run_source_discovery_once.py', 'review-list')
        'source|review-decide' = @('run_source_discovery_once.py', 'review-decide')
        'source|review-close' = @('run_source_discovery_once.py', 'review-close')
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

    $LocalReviewOperations = @('review-list', 'review-decide', 'review-close')
    if ($Flow -eq 'source' -and $LocalReviewOperations -contains $Operation) {
        $ReviewValueFlags = @(
            switch ($Operation) {
                'review-list' {
                    '--attempt-id'
                    '--expected-receipt-sha256'
                }
                'review-decide' {
                    '--attempt-id'
                    '--expected-receipt-sha256'
                    '--review-id'
                    '--expected-state-digest'
                    '--reviewer'
                    '--decision'
                    '--reason'
                    '--evidence-ref'
                    '--idempotency-key'
                }
                'review-close' {
                    '--attempt-id'
                    '--actor'
                    '--evidence-ref'
                    '--idempotency-key'
                }
            }
        )
        $ReviewSwitchFlags = @(
            if ($Operation -eq 'review-close') {
                '--confirm-local-close'
            }
        )
        $ExpectedReviewArgumentCount = (
            (2 * $ReviewValueFlags.Count) + $ReviewSwitchFlags.Count
        )
        if ($CommandArguments.Count -ne $ExpectedReviewArgumentCount) {
            throw 'SAFE_LEAD_FLOW_REVIEW_ARGUMENTS_INVALID'
        }

        $SeenReviewFlags = @{}
        $ArgumentIndex = 0
        while ($ArgumentIndex -lt $CommandArguments.Count) {
            $Token = [string]$CommandArguments[$ArgumentIndex]
            if ($ReviewSwitchFlags -ccontains $Token) {
                if ($SeenReviewFlags.ContainsKey($Token)) {
                    throw 'SAFE_LEAD_FLOW_REVIEW_ARGUMENTS_INVALID'
                }
                $SeenReviewFlags[$Token] = $true
                $ArgumentIndex += 1
                continue
            }
            if (-not ($ReviewValueFlags -ccontains $Token)) {
                throw 'SAFE_LEAD_FLOW_REVIEW_ARGUMENTS_INVALID'
            }
            if (
                $SeenReviewFlags.ContainsKey($Token) -or
                ($ArgumentIndex + 1) -ge $CommandArguments.Count
            ) {
                throw 'SAFE_LEAD_FLOW_REVIEW_ARGUMENTS_INVALID'
            }
            $Value = [string]$CommandArguments[$ArgumentIndex + 1]
            if (
                [string]::IsNullOrEmpty($Value) -or
                $Value.StartsWith('--') -or
                $Value -notmatch '\A[A-Za-z0-9._~:/?#\[\]@%+=,-]+\z'
            ) {
                throw 'SAFE_LEAD_FLOW_REVIEW_TOKEN_INVALID'
            }
            $SeenReviewFlags[$Token] = $true
            $ArgumentIndex += 2
        }
        foreach ($RequiredReviewFlag in @($ReviewValueFlags + $ReviewSwitchFlags)) {
            if (-not $SeenReviewFlags.ContainsKey($RequiredReviewFlag)) {
                throw 'SAFE_LEAD_FLOW_REVIEW_ARGUMENTS_INVALID'
            }
        }
    }

    # The bootstrap check is the admission gate. It returns to this script only
    # after validating the exact repo-local interpreter and package set.
    $null = & $BootstrapPath -CheckOnly
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        throw 'SAFE_LEAD_FLOW_RUNTIME_UNAVAILABLE'
    }

    if ($Flow -eq 'source' -and $Operation -eq 'run-one') {
        Set-Item -LiteralPath $LauncherMarkerPath -Value $LauncherMarkerValue -Force
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

    # Array splatting avoids command-string construction and expression eval.
    # Local-review values are restricted above to a quote-free ASCII grammar
    # before they cross the Windows PowerShell 5.1 native-process boundary.
    & $VenvPython @PythonArguments
    $ChildExitCode = $LASTEXITCODE
    if ($null -eq $ChildExitCode) {
        throw 'SAFE_LEAD_FLOW_CHILD_EXIT_UNAVAILABLE'
    }
    $SafeLeadFlowExitCode = [int]$ChildExitCode
} catch {
    [Console]::Error.WriteLine('SAFE_LEAD_FLOW_FAILED')
    $SafeLeadFlowExitCode = 2
} finally {
    # Keep the launcher process clean even if validation or child execution
    # fails after a component attempted to recreate the ambient name.
    Remove-Item -LiteralPath $SensitiveEnvironmentPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GoldSensitiveEnvironmentPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $LauncherMarkerPath -Force -ErrorAction SilentlyContinue
}

exit $SafeLeadFlowExitCode
