#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ReleaseSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$RuntimeSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ManifestSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ArtifactSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$MandatoryLabelReaderSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^S-1-')]
    [string]$ExpectedSid,

    [Parameter(Mandatory = $true)]
    [string]$StateDir,

    [ValidateRange(30, 3600)]
    [int]$IntervalSeconds = 60,

    [ValidateSet('serve', 'verify-release', 'revoke')]
    [string]$Command = 'serve',

    [ValidateSet('operator', 'release_replacement', 'scheduled_task_uninstall')]
    [string]$RevokeReason = 'operator'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Exit-LiveInboundLauncher {
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [switch]$PermanentForServe
    )
    if ($Command -eq 'serve' -and $PermanentForServe) {
        # Task Scheduler restarts every non-zero result.  A deterministic
        # integrity/configuration failure cannot heal through repetition.
        exit 0
    }
    exit $ExitCode
}

trap {
    # Any unexpected terminating validation error is deterministic for this
    # immutable invocation.  Do not let Task Scheduler hammer it forever.
    if ($Command -eq 'serve') {
        exit 0
    }
    exit 78
}

if ($PSVersionTable.PSEdition -cne 'Desktop') {
    Exit-LiveInboundLauncher -ExitCode 75 -PermanentForServe
}
if (-not [Environment]::Is64BitProcess) {
    Exit-LiveInboundLauncher -ExitCode 75 -PermanentForServe
}
$env:PSModulePath = "$PSHOME\Modules"
foreach ($TrustedModuleName in @(
    'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.Security',
    'Microsoft.PowerShell.Utility'
)) {
    $TrustedModulePath = "$PSHOME\Modules\$TrustedModuleName\$TrustedModuleName.psd1"
    if (-not [IO.File]::Exists($TrustedModulePath)) {
        Exit-LiveInboundLauncher -ExitCode 75 -PermanentForServe
    }
    Import-Module -Name $TrustedModulePath -Force -ErrorAction Stop
}
$PSModuleAutoLoadingPreference = 'None'
$EmbeddedMandatoryLabelReaderSha256 = `
    '83c7b4c72a34e9f74a15ddd0f7f1881df4b51aaa79b89d395d7232819c93d2ee'
if ($MandatoryLabelReaderSha256 -cne $EmbeddedMandatoryLabelReaderSha256) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}

$SystemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$ProgramFilesDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles
)
if (
    [string]::IsNullOrWhiteSpace($SystemDirectory) -or
    [string]::IsNullOrWhiteSpace($ProgramFilesDirectory)
) {
    Exit-LiveInboundLauncher -ExitCode 75 -PermanentForServe
}

function Import-PinnedMandatoryLabelReader {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $Item = Get-Item -LiteralPath $LiteralPath -Force
    if (
        $Item.PSIsContainer -or $Item.Length -lt 1 -or $Item.Length -gt 1MB -or
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$Item.LinkType)
    ) { throw 'Mandatory integrity label reader path is invalid.' }
    $Bytes = New-Object byte[] ([int]$Item.Length)
    $Stream = [IO.File]::Open(
        $Item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read
    )
    try {
        if ($Stream.Length -ne $Bytes.Length) {
            throw 'Mandatory integrity label reader changed while opening.'
        }
        $Offset = 0
        while ($Offset -lt $Bytes.Length) {
            $Read = $Stream.Read($Bytes,$Offset,$Bytes.Length - $Offset)
            if ($Read -le 0) {
                throw 'Mandatory integrity label reader read was truncated.'
            }
            $Offset += $Read
        }
        if ($Stream.ReadByte() -ne -1) {
            throw 'Mandatory integrity label reader grew while reading.'
        }
    } finally { $Stream.Dispose() }
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $ObservedSha256 = ([BitConverter]::ToString(
            $Hasher.ComputeHash($Bytes)
        )).Replace('-','').ToLowerInvariant()
    } finally { $Hasher.Dispose() }
    if ($ObservedSha256 -cne $ExpectedSha256) {
        throw 'Mandatory integrity label reader hash is not trusted.'
    }
    $Assembly = [Reflection.Assembly]::Load($Bytes)
    if (
        [string]$Assembly.FullName -cne
            'mandatory_label_reader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null' -or
        -not [string]::IsNullOrEmpty([string]$Assembly.Location)
    ) { throw 'Mandatory integrity label reader assembly identity is invalid.' }
    $Exported = @($Assembly.GetExportedTypes())
    $Reader = $Assembly.GetType(
        'TenderBot.LiveInbound.Security.MandatoryLabelReader',$true,$false
    )
    $Method = $Reader.GetMethod(
        'Read',[Reflection.BindingFlags]'Public,Static',$null,
        [Type[]]@([string]),$null
    )
    if (
        $Exported.Count -ne 1 -or $Exported[0] -ne $Reader -or
        $null -eq $Method -or $Method.ReturnType -ne [string]
    ) { throw 'Mandatory integrity label reader contract is invalid.' }
    return $Reader
}

function Resolve-SidValue {
    param([Parameter(Mandatory = $true)]$IdentityReference)
    if ([string]$IdentityReference -match '^S-1-') {
        return (New-Object Security.Principal.SecurityIdentifier(
            [string]$IdentityReference
        )).Value
    }
    $Reference = if ($IdentityReference -is [Security.Principal.IdentityReference]) {
        $IdentityReference
    } else {
        New-Object Security.Principal.NTAccount([string]$IdentityReference)
    }
    return $Reference.Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}

function Test-ReparsePoint {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    return [bool](
        (Get-Item -LiteralPath $LiteralPath -Force).Attributes -band
        [IO.FileAttributes]::ReparsePoint
    )
}

function Test-ExactProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    try {
        $Item = Get-Item -LiteralPath $LiteralPath -Force
        $Acl = Get-Acl -LiteralPath $LiteralPath
        if (
            (Resolve-SidValue -IdentityReference $Acl.Owner) -cne 'S-1-5-18' -or
            -not $Acl.AreAccessRulesProtected
        ) {
            return $false
        }
        $Expected = @{
            'S-1-5-18' = [int64]([Security.AccessControl.FileSystemRights]::FullControl)
            'S-1-5-32-544' = [int64]([Security.AccessControl.FileSystemRights]::FullControl)
            $ExecutionSid = (
                [int64]([Security.AccessControl.FileSystemRights]::ReadAndExecute) -bor
                [int64]([Security.AccessControl.FileSystemRights]::Synchronize)
            )
        }
        $Rules = @($Acl.Access)
        if ($Rules.Count -ne $Expected.Count) { return $false }
        $Seen = New-Object 'Collections.Generic.HashSet[string]' (
            [StringComparer]::Ordinal
        )
        $ExpectedInheritance = if ($Item.PSIsContainer) {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
        } else {
            [Security.AccessControl.InheritanceFlags]::None
        }
        foreach ($Rule in $Rules) {
            $RuleSid = Resolve-SidValue -IdentityReference $Rule.IdentityReference
            if (
                $Rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                -not $Expected.ContainsKey($RuleSid) -or
                -not $Seen.Add($RuleSid) -or
                [int64]$Rule.FileSystemRights -ne [int64]$Expected[$RuleSid] -or
                $Rule.InheritanceFlags -ne $ExpectedInheritance -or
                $Rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
                $Rule.IsInherited
            ) {
                return $false
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-HighIntegritySddl {
    param(
        [Parameter(Mandatory = $true)][string]$Sddl,
        [switch]$RequireInheritance
    )
    $Sacl = [Text.RegularExpressions.Regex]::Match(
        $Sddl,
        'S:[A-Z]*(?<aces>(?:\([^\r\n)]*\))*)',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $Sacl.Success) { return $false }
    $Labels = [Text.RegularExpressions.Regex]::Matches(
        $Sacl.Groups['aces'].Value,
        '\(ML;[^\r\n)]*\)',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($Labels.Count -ne 1) { return $false }
    $Pattern = if ($RequireInheritance.IsPresent) {
        '^\(ML;(?=[A-Z]*OI)(?=[A-Z]*CI)[A-Z]*;NW;;;HI\)$'
    } else {
        '^\(ML;[A-Z]*;NW;;;HI\)$'
    }
    return [bool]($Labels[0].Value -cmatch $Pattern)
}

function Test-HighIntegrityLabel {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Recursive
    )
    try {
        $Paths = @($LiteralPath)
        if ($Recursive.IsPresent) {
            $Paths += @(
                Get-ChildItem -LiteralPath $LiteralPath -Force -Recurse |
                    ForEach-Object { [string]$_.FullName }
            )
        }
        for ($Index = 0; $Index -lt $Paths.Count; $Index++) {
            $Sddl = $MandatoryLabelReaderType::Read([string]$Paths[$Index])
            $Verified = if ($Index -eq 0 -and $Recursive.IsPresent) {
                Test-HighIntegritySddl -Sddl $Sddl -RequireInheritance
            } else {
                Test-HighIntegritySddl -Sddl $Sddl
            }
            if (-not $Verified) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $Identity.User.Value
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
$IsAdministrator = $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$WhoAmIPath = Join-Path $SystemDirectory 'whoami.exe'
$IntegrityRows = if (Test-Path -LiteralPath $WhoAmIPath -PathType Leaf) {
    $Rows = @(& $WhoAmIPath /groups /fo csv /nh 2>$null)
    $IntegrityProbeExit = $LASTEXITCODE
    $Rows
} else {
    $IntegrityProbeExit = -1
    @()
}
$MediumIntegrityRows = @(
    $IntegrityRows | Where-Object { $_ -match '"S-1-16-8192"' }
)
$ExecutionContextVerified = -not $IsAdministrator -and $MediumIntegrityRows.Count -eq 1
if (
    $CurrentSid -cne $ExpectedSid -or
    $IntegrityProbeExit -ne 0 -or
    -not $ExecutionContextVerified
) {
    Exit-LiveInboundLauncher -ExitCode 76 -PermanentForServe
}

$ReleaseDir = [IO.Path]::GetFullPath($PSScriptRoot)
$ManifestPath = Join-Path $ReleaseDir 'release.json'
$ArtifactPath = Join-Path $ReleaseDir 'live-inbound.pyz'
$StatusPath = Join-Path $ReleaseDir 'read-status.ps1'
$MandatoryLabelReaderPath = Join-Path $ReleaseDir 'mandatory-label-reader.dll'
$RuntimeDir = Join-Path $ReleaseDir 'runtime'
$RuntimePath = Join-Path $RuntimeDir 'python.exe'
$ExpectedReleaseRoot = [IO.Path]::GetFullPath(
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\releases')
)
$ExpectedReleaseDir = [IO.Path]::GetFullPath(
    (Join-Path $ExpectedReleaseRoot $ReleaseSha256)
)
$ExpectedStateDir = [IO.Path]::GetFullPath(
    (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.tenderbot\live_inbound')
)
$StateDir = [IO.Path]::GetFullPath($StateDir)

if (
    $ReleaseDir -cne $ExpectedReleaseDir -or
    ($StateDir -cne $ExpectedStateDir) -or
    -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $StatusPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $MandatoryLabelReaderPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $RuntimePath -PathType Leaf) -or
    (Test-ReparsePoint -LiteralPath $ReleaseDir) -or
    (Test-ReparsePoint -LiteralPath $ManifestPath) -or
    (Test-ReparsePoint -LiteralPath $ArtifactPath) -or
    (Test-ReparsePoint -LiteralPath $StatusPath) -or
    (Test-ReparsePoint -LiteralPath $MandatoryLabelReaderPath) -or
    (Test-ReparsePoint -LiteralPath $RuntimeDir) -or
    (Test-ReparsePoint -LiteralPath $RuntimePath)
) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}

$ProtectedDirectories = @(
    (Join-Path $ProgramFilesDirectory 'TenderBot'),
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound'),
    $ExpectedReleaseRoot,
    $ReleaseDir
)
foreach ($ProtectedDirectory in $ProtectedDirectories) {
    if (
        -not (Test-Path -LiteralPath $ProtectedDirectory -PathType Container) -or
        (Test-ReparsePoint -LiteralPath $ProtectedDirectory) -or
        -not (Test-ExactProtectedAcl `
            -LiteralPath $ProtectedDirectory `
            -ExecutionSid $ExpectedSid)
    ) {
        Exit-LiveInboundLauncher -ExitCode 79 -PermanentForServe
    }
}
$TopLevelItems = @(Get-ChildItem -LiteralPath $ReleaseDir -Force)
$ExpectedTopLevel = @(
    'live-inbound.pyz',
    'mandatory-label-reader.dll',
    'read-status.ps1',
    'release.json',
    'runtime',
    'verify-and-run.ps1'
)
if (
    $TopLevelItems.Count -ne $ExpectedTopLevel.Count -or
    @($TopLevelItems | Where-Object { $_.Name -cnotin $ExpectedTopLevel }).Count -ne 0
) {
    Exit-LiveInboundLauncher -ExitCode 78 -PermanentForServe
}
foreach ($TopLevelItem in $TopLevelItems) {
    if (
        (Test-ReparsePoint -LiteralPath $TopLevelItem.FullName) -or
        -not (Test-ExactProtectedAcl `
            -LiteralPath $TopLevelItem.FullName `
            -ExecutionSid $ExpectedSid)
    ) {
        Exit-LiveInboundLauncher -ExitCode 79 -PermanentForServe
    }
}

try {
    $MandatoryLabelReaderType = Import-PinnedMandatoryLabelReader `
        -LiteralPath $MandatoryLabelReaderPath `
        -ExpectedSha256 $MandatoryLabelReaderSha256
} catch {
    Exit-LiveInboundLauncher -ExitCode 79 -PermanentForServe
}
foreach ($ProtectedDirectory in $ProtectedDirectories) {
    if (-not (Test-HighIntegrityLabel -LiteralPath $ProtectedDirectory)) {
        Exit-LiveInboundLauncher -ExitCode 79 -PermanentForServe
    }
}
if (-not (Test-HighIntegrityLabel -LiteralPath $ReleaseDir -Recursive)) {
    Exit-LiveInboundLauncher -ExitCode 79 -PermanentForServe
}

if ((Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $ManifestSha256) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -ErrorAction Stop
if (
    ([string]$Manifest.format -cne 'TenderBot.LiveInbound.Release.v2') -or
    ([string]$Manifest.release_sha256 -cne $ReleaseSha256) -or
    ([string]$Manifest.runtime_sha256 -cne $RuntimeSha256) -or
    ([string]$Manifest.artifact_sha256 -cne $ArtifactSha256) -or
    ([string]$Manifest.artifact -cne 'live-inbound.pyz') -or
    ([string]$Manifest.runtime_executable -cne 'runtime/python.exe') -or
    ([string]$Manifest.launcher -cne 'verify-and-run.ps1') -or
    ([string]$Manifest.status_script -cne 'read-status.ps1') -or
    ([string]$Manifest.mandatory_label_reader -cne 'mandatory-label-reader.dll') -or
    ([string]$Manifest.mandatory_label_reader_sha256 -cne
        $MandatoryLabelReaderSha256) -or
    ([string]$Manifest.runtime_dependency_contract -cne 'cpython-stdlib-copy-no-site-v2')
) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}
if ((Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $ArtifactSha256) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}
if ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    [string]$Manifest.launcher_sha256) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}
if ((Get-FileHash -LiteralPath $StatusPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    [string]$Manifest.status_script_sha256) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}
if ((Get-FileHash -LiteralPath $MandatoryLabelReaderPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    [string]$Manifest.mandatory_label_reader_sha256) {
    Exit-LiveInboundLauncher -ExitCode 77 -PermanentForServe
}

$ExpectedFiles = @($Manifest.runtime_files)
$ActualFiles = @(Get-ChildItem -LiteralPath $RuntimeDir -File -Recurse -Force)
$RuntimeDirectories = @(
    Get-ChildItem -LiteralPath $RuntimeDir -Directory -Recurse -Force
)
foreach ($RuntimeDirectory in $RuntimeDirectories) {
    if (
        (Test-ReparsePoint -LiteralPath $RuntimeDirectory.FullName) -or
        -not (Test-ExactProtectedAcl `
            -LiteralPath $RuntimeDirectory.FullName `
            -ExecutionSid $ExpectedSid)
    ) {
        Exit-LiveInboundLauncher -ExitCode 79 -PermanentForServe
    }
}
if ($ExpectedFiles.Count -ne $ActualFiles.Count -or $ExpectedFiles.Count -lt 1) {
    Exit-LiveInboundLauncher -ExitCode 78 -PermanentForServe
}
$RuntimePrefix = $RuntimeDir.TrimEnd('\') + '\'
$Seen = New-Object 'Collections.Generic.HashSet[string]' (
    [StringComparer]::OrdinalIgnoreCase
)
$CanonicalRuntimeEntries = New-Object 'Collections.Generic.List[object]'
foreach ($Entry in $ExpectedFiles) {
    $Relative = [string]$Entry.path
    if (
        [string]::IsNullOrWhiteSpace($Relative) -or
        $Relative.Contains('\') -or
        $Relative.Contains(':') -or
        $Relative -match '(^|/)\.\.(/|$)' -or
        $Relative -match '(^|/)\.(/|$)' -or
        $Relative.Contains('//') -or
        $Relative.EndsWith('/') -or
        -not $Seen.Add($Relative)
    ) {
        Exit-LiveInboundLauncher -ExitCode 78 -PermanentForServe
    }
    $Candidate = [IO.Path]::GetFullPath(
        (Join-Path $RuntimeDir ($Relative.Replace('/', '\')))
    )
    if (
        -not $Candidate.StartsWith($RuntimePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $Candidate -PathType Leaf) -or
        (Test-ReparsePoint -LiteralPath $Candidate) -or
        -not (Test-ExactProtectedAcl `
            -LiteralPath $Candidate `
            -ExecutionSid $ExpectedSid) -or
        (Get-Item -LiteralPath $Candidate -Force).Length -ne [int64]$Entry.size -or
        (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$Entry.sha256
    ) {
        Exit-LiveInboundLauncher -ExitCode 78 -PermanentForServe
    }
    [void]$CanonicalRuntimeEntries.Add([ordered]@{
        path = $Relative
        sha256 = [string]$Entry.sha256
        size = [int64]$Entry.size
    })
}
$RuntimeReceipt = [ordered]@{
    files = $CanonicalRuntimeEntries.ToArray()
    format = 'TenderBot.LiveInbound.RuntimeTree.v1'
} | ConvertTo-Json -Compress -Depth 5
$RuntimeHasher = [Security.Cryptography.SHA256]::Create()
try {
    $ComputedRuntimeSha256 = ([BitConverter]::ToString(
        $RuntimeHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($RuntimeReceipt))
    )).Replace('-', '').ToLowerInvariant()
} finally {
    $RuntimeHasher.Dispose()
}
if ($ComputedRuntimeSha256 -cne $RuntimeSha256) {
    Exit-LiveInboundLauncher -ExitCode 78 -PermanentForServe
}

$CommonArguments = @(
    '-I', '-S', '-B', $ArtifactPath,
    '--release-sha256', $ReleaseSha256,
    '--runtime-sha256', $RuntimeSha256,
    '--manifest-sha256', $ManifestSha256,
    '--artifact-sha256', $ArtifactSha256,
    '--state-dir', $StateDir
)
if ($Command -eq 'serve') {
    & $RuntimePath @CommonArguments serve --interval-seconds $IntervalSeconds
} elseif ($Command -eq 'verify-release') {
    & $RuntimePath @CommonArguments verify-release
} else {
    & $RuntimePath @CommonArguments revoke `
        --confirm-revoke 'MAIL-TO-BITRIX-INBOUND-REVOKE-V1' `
        --reason $RevokeReason
}
$RuntimeExitCode = $LASTEXITCODE
Exit-LiveInboundLauncher `
    -ExitCode $RuntimeExitCode `
    -PermanentForServe:($RuntimeExitCode -eq 78)
