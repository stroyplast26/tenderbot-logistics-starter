#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(30, 3600)]
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = 'Stop'
$WrapperSource = [string]$MyInvocation.MyCommand.ScriptContents
$BeginMarker = '# TRUSTED_FRESH_' + 'CORE_BEGIN'
$EndMarker = '# TRUSTED_FRESH_' + 'CORE_END'
$BeginIndex = $WrapperSource.IndexOf($BeginMarker, [StringComparison]::Ordinal)
$EndIndex = $WrapperSource.IndexOf($EndMarker, [StringComparison]::Ordinal)
if ($BeginIndex -lt 0 -or $EndIndex -le $BeginIndex) {
    throw 'Parsed trusted core markers are invalid.'
}
$CoreStart = $BeginIndex + $BeginMarker.Length
$TrustedCore = $WrapperSource.Substring($CoreStart, $EndIndex - $CoreStart)
$ChildSource = @'
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(30, 3600)][int]$IntervalSeconds,
    [Parameter(Mandatory = $true)][string]$OriginalProjectRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedWrapperSha256
)
'@ + $TrustedCore + @'

Invoke-LiveInboundTrustedCore `
    -IntervalSeconds $IntervalSeconds `
    -OriginalProjectRoot $OriginalProjectRoot `
    -ExpectedWrapperSha256 $ExpectedWrapperSha256 `
    -WhatIf:$WhatIfPreference
'@
$Utf8 = [System.Text.UTF8Encoding]::new($false)
$ChildBytes = $Utf8.GetBytes($ChildSource)
$WrapperBytes = $Utf8.GetBytes($WrapperSource)
$Hasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $ChildSha256 = ([System.BitConverter]::ToString(
        $Hasher.ComputeHash($ChildBytes)
    )).Replace('-', '').ToLowerInvariant()
    $WrapperSha256 = ([System.BitConverter]::ToString(
        $Hasher.ComputeHash($WrapperBytes)
    )).Replace('-', '').ToLowerInvariant()
} finally {
    $Hasher.Dispose()
}
$LoaderSource = @'
$ErrorActionPreference='Stop'
$Utf8=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=$Utf8
[Console]::Error.Write('')
$Payload=[Console]::In.ReadToEnd()
$Bytes=[Convert]::FromBase64String($Payload)
if($Bytes.Length-lt 1-or$Bytes.Length-gt 4MB){throw 'core size'}
$H=[Security.Cryptography.SHA256]::Create()
try{$Observed=([BitConverter]::ToString($H.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$H.Dispose()}
if($Observed-cne'__CORE_SHA256__'){throw 'core hash'}
$Source=[Text.Encoding]::UTF8.GetString($Bytes)
$Core=[Management.Automation.ScriptBlock]::Create($Source)
try{
  &$Core -IntervalSeconds ([int][Environment]::GetEnvironmentVariable('TENDERBOT_LIVE_INBOUND_INTERVAL')) -OriginalProjectRoot ([Environment]::GetEnvironmentVariable('TENDERBOT_LIVE_INBOUND_PROJECT_ROOT')) -ExpectedWrapperSha256 ([Environment]::GetEnvironmentVariable('TENDERBOT_LIVE_INBOUND_WRAPPER_SHA256')) -WhatIf:([bool]::Parse([Environment]::GetEnvironmentVariable('TENDERBOT_LIVE_INBOUND_WHATIF')))
  exit 0
}catch{[Console]::Error.WriteLine($_.Exception.ToString());exit 1}
'@
$LoaderSource = $LoaderSource.Replace('__CORE_SHA256__', $ChildSha256)
$EncodedLoader = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($LoaderSource)
)
$SystemDirectory = [System.Environment]::GetFolderPath(
    [System.Environment+SpecialFolder]::System
)
$PowerShellPath = [System.IO.Path]::Combine(
    $SystemDirectory,
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe'
)
$OriginalProjectRoot = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::Combine($PSScriptRoot, '..')
)
if (
    $PSVersionTable.PSEdition -cne 'Desktop' -or
    -not [System.Environment]::Is64BitProcess -or
    -not [System.IO.File]::Exists($PowerShellPath)
) {
    throw 'Start with canonical 64-bit Windows PowerShell 5.1.'
}
$StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
$StartInfo.FileName = $PowerShellPath
$StartInfo.UseShellExecute = $false
$StartInfo.RedirectStandardInput = $true
$StartInfo.RedirectStandardOutput = $true
$StartInfo.RedirectStandardError = $true
$StartInfo.CreateNoWindow = $true
$StartInfo.StandardOutputEncoding = $Utf8
$StartInfo.StandardErrorEncoding = $Utf8
$StartInfo.Arguments = (
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    '-EncodedCommand ' + $EncodedLoader
)
$StartInfo.EnvironmentVariables['TENDERBOT_LIVE_INBOUND_INTERVAL'] = (
    $IntervalSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
)
$StartInfo.EnvironmentVariables['TENDERBOT_LIVE_INBOUND_PROJECT_ROOT'] = (
    $OriginalProjectRoot
)
$StartInfo.EnvironmentVariables['TENDERBOT_LIVE_INBOUND_WRAPPER_SHA256'] = (
    $WrapperSha256
)
$StartInfo.EnvironmentVariables['TENDERBOT_LIVE_INBOUND_WHATIF'] = (
    [bool]$WhatIfPreference
).ToString()
$FreshProcess = [System.Diagnostics.Process]::Start($StartInfo)
$FreshProcess.StandardInput.Write([Convert]::ToBase64String($ChildBytes))
$FreshProcess.StandardInput.Close()
$FreshOutput = $FreshProcess.StandardOutput.ReadToEnd()
$FreshError = $FreshProcess.StandardError.ReadToEnd()
$FreshProcess.WaitForExit()
[System.Console]::Out.Write($FreshOutput)
[System.Console]::Error.Write($FreshError)
exit $FreshProcess.ExitCode

# TRUSTED_FRESH_CORE_BEGIN
function Invoke-LiveInboundTrustedCore {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateRange(30, 3600)][int]$IntervalSeconds,
        [Parameter(Mandatory = $true)][string]$OriginalProjectRoot,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedWrapperSha256
    )

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This already-parsed wrapper is the initial trust anchor.  None of these
# component pins may come from the workspace Python process or its JSON output.
$TrustedArtifactSha256 = 'fb437bfeedf4f11ae83e44b3c8714194943da4f2638b1dc8cb5c0cab00576416'
$TrustedRuntimeSha256 = '25ccdab4b3f249af8ea5f3fd9ac910a892f5bb28f6dac565b96673009a3c5c02'
$TrustedPythonSignerThumbprint = '36168EE17C1A240517388540C903BB6717DD2563'
$TrustedSourceSha256 = [ordered]@{
    'lead_factory/facade_inquiry_parser.py' = 'c569eb155800cb1c1e9bdcc45617ba1f31baff3bc0ec6160172d4ae10471bde8'
    'lead_factory/live_connection_credentials.py' = 'd132c6ccb4a7d0b74f58396e9b6aca0037236665f6e34def5a7bcce976e26561'
    'lead_factory/live_mail_bitrix.py' = '6005090d0c80f1de70f063d57889058c5816d8d3cc285f17449a5687a39a2d85'
    'lead_factory/native_bitrix_mail_observer.py' = 'cd68fc1404f29064bd1950eaca99893a667b485ea6a92ecc01bfc22146294b80'
    'lead_factory/mail_bitrix_projection.py' = '8ce44273420249fda0c2a5a0cefdb5f9e5c91ce706907517167d96996ed32878'
    'lead_factory/mail_threading.py' = 'bb580878fe96e0a625f5049ddb3c1f977ee27e4bfe11567a991d1fc98ffce63e'
    'scripts/build_live_inbound_release.py' = 'ef949e1b7a50b4fe0a62f02f3798a963653095ebd49c49cc9d8189f7a8cd7e5b'
    'scripts/install_live_inbound_task_admin.ps1' = '7e9af77933b0076033b151b72cf988d93053cd27c8d23d1ef6371c1fde2b6d88'
    'scripts/live_inbound_launcher.ps1' = 'c0895663bacc0aaa1e8cf4453f707b68f01028bfd0f172c156bdf169f7a5cee9'
    'scripts/live_inbound_task_status.ps1' = '7d62421736d880a5a0b87b1ba59375f790c07982b238ef05c335603c584e41b6'
    'scripts/mandatory_label_reader.cs' = '7f147fcce1dc4436583228a8c6394d1a27f599405915d6416e95d121db4b0c5a'
    'scripts/mandatory_label_reader.dll' = '83c7b4c72a34e9f74a15ddd0f7f1881df4b51aaa79b89d395d7232819c93d2ee'
    'scripts/run_live_inbound.py' = '2934f6b115d6e0e396239b7d7d382501ac42ff474728e8a1335a6c5addb2e627'
    'scripts/run_native_bitrix_observer.py' = '0c37cf86c61e319cd6b8a574bbc837f854cbdc308b42c4df37c2e88c64c0c01c'
}

function Assert-PinnedWorkspaceFile {
    param(
        [Parameter(Mandatory = $true)][string]$ProjectRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $Root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\') + '\'
    $Candidate = [IO.Path]::GetFullPath(
        (Join-Path $ProjectRoot $RelativePath.Replace('/', '\'))
    )
    if (-not $Candidate.StartsWith($Root, [StringComparison]::Ordinal)) {
        throw 'Trusted workspace source escaped the project root.'
    }
    $Item = Get-Item -LiteralPath $Candidate -Force
    if (
        $Item.PSIsContainer -or
        $Item.Length -lt 1 -or
        $Item.Length -gt 4MB -or
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$Item.LinkType) -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash.ToLowerInvariant() `
            -cne $ExpectedSha256
    ) {
        throw "Trusted workspace source pin failed: $RelativePath"
    }
}

function Copy-PinnedWorkspaceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $Item = Get-Item -LiteralPath $SourcePath -Force
    if (
        $Item.PSIsContainer -or
        $Item.Length -lt 1 -or
        $Item.Length -gt 2MB -or
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$Item.LinkType)
    ) {
        throw 'Privileged installer source is invalid.'
    }
    $Source = [IO.File]::Open(
        $SourcePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $Hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $ObservedSha256 = ([BitConverter]::ToString(
                $Hasher.ComputeHash($Source)
            )).Replace('-', '').ToLowerInvariant()
        } finally {
            $Hasher.Dispose()
        }
        if ($ObservedSha256 -cne $ExpectedSha256) {
            throw 'Privileged installer source pin failed.'
        }
        $Source.Position = 0
        $Destination = [IO.File]::Open(
            $DestinationPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $Source.CopyTo($Destination)
            $Destination.Flush($true)
        } finally {
            $Destination.Dispose()
        }
        return [int64]$Source.Length
    } finally {
        $Source.Dispose()
    }
}

function Get-PreparedRuntimeSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)]$ManifestEntries
    )
    $Root = [IO.Path]::GetFullPath($RuntimeRoot)
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (
        -not $RootItem.PSIsContainer -or
        $RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$RootItem.LinkType)
    ) {
        throw 'Prepared runtime root is invalid.'
    }
    $Entries = @($ManifestEntries)
    $ActualFiles = @(Get-ChildItem -LiteralPath $Root -File -Force -Recurse)
    $ActualDirectories = @(Get-ChildItem -LiteralPath $Root -Directory -Force -Recurse)
    if (
        $Entries.Count -lt 1 -or
        $Entries.Count -gt 10000 -or
        $ActualFiles.Count -ne $Entries.Count -or
        @($ActualDirectories | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not [string]::IsNullOrEmpty([string]$_.LinkType)
        }).Count -ne 0
    ) {
        throw 'Prepared runtime tree is invalid.'
    }
    $RootPrefix = $Root.TrimEnd('\') + '\'
    $Seen = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::OrdinalIgnoreCase
    )
    $CanonicalEntries = New-Object 'Collections.Generic.List[object]'
    foreach ($Entry in $Entries) {
        $Relative = [string]$Entry.path
        $ExpectedSize = [int64]$Entry.size
        $ExpectedSha256 = [string]$Entry.sha256
        if (
            [string]::IsNullOrWhiteSpace($Relative) -or
            $Relative.Contains('\') -or
            $Relative.Contains(':') -or
            $Relative -match '(^|/)\.\.(/|$)' -or
            $Relative -match '(^|/)\.(/|$)' -or
            $Relative.Contains('//') -or
            $Relative.EndsWith('/') -or
            $Relative.StartsWith('/') -or
            -not $Seen.Add($Relative) -or
            $ExpectedSize -lt 0 -or
            $ExpectedSize -gt 256MB -or
            $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$'
        ) {
            throw 'Prepared runtime entry is invalid.'
        }
        $Candidate = [IO.Path]::GetFullPath(
            (Join-Path $Root $Relative.Replace('/', '\'))
        )
        $Item = Get-Item -LiteralPath $Candidate -Force
        if (
            -not $Candidate.StartsWith($RootPrefix, [StringComparison]::Ordinal) -or
            $Item.PSIsContainer -or
            $Item.Length -ne $ExpectedSize -or
            $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not [string]::IsNullOrEmpty([string]$Item.LinkType) -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash.ToLowerInvariant() `
                -cne $ExpectedSha256
        ) {
            throw 'Prepared runtime file does not match its manifest entry.'
        }
        [void]$CanonicalEntries.Add([ordered]@{
            path = $Relative
            sha256 = $ExpectedSha256
            size = $ExpectedSize
        })
    }
    $Receipt = [ordered]@{
        files = $CanonicalEntries.ToArray()
        format = 'TenderBot.LiveInbound.RuntimeTree.v1'
    } | ConvertTo-Json -Compress -Depth 5
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Receipt))
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
}

function Assert-PreparedArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactPath,
        [Parameter(Mandatory = $true)]$SourcePins
    )
    [void][Reflection.Assembly]::Load(
        'System.IO.Compression, Version=4.0.0.0, Culture=neutral, ' +
        'PublicKeyToken=b77a5c561934e089'
    )
    $Expected = [ordered]@{}
    foreach ($Relative in @(
        'lead_factory/facade_inquiry_parser.py',
        'lead_factory/live_connection_credentials.py',
        'lead_factory/mail_bitrix_projection.py',
        'lead_factory/mail_threading.py',
        'lead_factory/live_mail_bitrix.py',
        'lead_factory/native_bitrix_mail_observer.py',
        'scripts/run_live_inbound.py',
        'scripts/run_native_bitrix_observer.py'
    )) {
        $Expected[$Relative] = [string]$SourcePins[$Relative]
    }
    $Generated = [ordered]@{
        '__main__.py' = (
            "from scripts.run_native_bitrix_observer import live_inbound_main`n" +
            "raise SystemExit(live_inbound_main())`n"
        )
        'lead_factory/__init__.py' = '"""Pinned live-inbound runtime package."""' + "`n"
        'scripts/__init__.py' = '"""Pinned live-inbound command package."""' + "`n"
    }
    foreach ($Pair in $Generated.GetEnumerator()) {
        $Hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $Expected[$Pair.Key] = ([BitConverter]::ToString(
                $Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Pair.Value))
            )).Replace('-', '').ToLowerInvariant()
        } finally {
            $Hasher.Dispose()
        }
    }
    $Artifact = [IO.File]::Open(
        $ArtifactPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $Archive = [IO.Compression.ZipArchive]::new(
            $Artifact,
            [IO.Compression.ZipArchiveMode]::Read,
            $false
        )
        try {
            $Entries = @($Archive.Entries)
            if ($Entries.Count -ne $Expected.Count) {
                throw 'Prepared application archive entry count is invalid.'
            }
            $Seen = New-Object 'Collections.Generic.HashSet[string]' (
                [StringComparer]::OrdinalIgnoreCase
            )
            foreach ($Entry in $Entries) {
                $Relative = [string]$Entry.FullName
                if (
                    -not $Expected.Contains($Relative) -or
                    -not $Seen.Add($Relative) -or
                    $Relative.Contains('\') -or
                    $Relative.Contains(':') -or
                    $Relative -match '(^|/)\.\.?(/|$)' -or
                    $Relative.StartsWith('/') -or
                    $Relative.EndsWith('/') -or
                    $Entry.Length -lt 1 -or
                    $Entry.Length -gt 4MB
                ) {
                    throw 'Prepared application archive path is invalid.'
                }
                $EntryStream = $Entry.Open()
                try {
                    $Hasher = [Security.Cryptography.SHA256]::Create()
                    try {
                        $Observed = ([BitConverter]::ToString(
                            $Hasher.ComputeHash($EntryStream)
                        )).Replace('-', '').ToLowerInvariant()
                    } finally {
                        $Hasher.Dispose()
                    }
                } finally {
                    $EntryStream.Dispose()
                }
                if ($Observed -cne [string]$Expected[$Relative]) {
                    throw 'Prepared application archive entry pin failed.'
                }
            }
        } finally {
            $Archive.Dispose()
        }
    } finally {
        $Artifact.Dispose()
    }
}

if ($PSVersionTable.PSEdition -cne 'Desktop') {
    throw 'Run this bootstrap with Windows PowerShell 5.1 (powershell.exe).'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Run this bootstrap with 64-bit Windows PowerShell 5.1.'
}
$env:PSModulePath = "$PSHOME\Modules"
foreach ($TrustedModuleName in @(
    'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.Security',
    'Microsoft.PowerShell.Utility'
)) {
    $TrustedModulePath = "$PSHOME\Modules\$TrustedModuleName\$TrustedModuleName.psd1"
    if (-not [IO.File]::Exists($TrustedModulePath)) {
        throw 'A trusted Windows PowerShell module is unavailable.'
    }
    Import-Module -Name $TrustedModulePath -Force -ErrorAction Stop
}
$PSModuleAutoLoadingPreference = 'None'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run the preparation bootstrap from a non-elevated Windows PowerShell session.'
}
$CurrentSid = $Identity.User.Value
if ($CurrentSid -notmatch '^S-1-') {
    throw 'Cannot resolve the execution Windows SID.'
}

$SystemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$ProgramFilesDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles
)
$LocalAppDataDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)
if (
    [string]::IsNullOrWhiteSpace($SystemDirectory) -or
    [string]::IsNullOrWhiteSpace($ProgramFilesDirectory) -or
    [string]::IsNullOrWhiteSpace($LocalAppDataDirectory)
) {
    throw 'Canonical Windows directories are unavailable.'
}
$PowerShellPath = Join-Path $SystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$ProjectRoot = [IO.Path]::GetFullPath($OriginalProjectRoot)
$BuildPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$BuildScript = Join-Path $ProjectRoot 'scripts\build_live_inbound_release.py'
$AdminInstallerSource = Join-Path $ProjectRoot 'scripts\install_live_inbound_task_admin.ps1'
if (
    -not [IO.File]::Exists($PowerShellPath) -or
    -not [IO.File]::Exists($BuildPython) -or
    -not [IO.File]::Exists($BuildScript) -or
    -not [IO.File]::Exists($AdminInstallerSource)
) {
    throw 'Live inbound preparation prerequisites are missing.'
}
if (-not $PSCmdlet.ShouldProcess(
    'TenderBot Live Inbound',
    'Prepare a clean pinned release and request two protected cutover elevations'
)) {
    return
}

$InstallerSha256 = [string]$TrustedSourceSha256[
    'scripts/install_live_inbound_task_admin.ps1'
]
$LauncherSha256 = [string]$TrustedSourceSha256['scripts/live_inbound_launcher.ps1']
$StatusSha256 = [string]$TrustedSourceSha256['scripts/live_inbound_task_status.ps1']
$MandatoryLabelReaderSha256 = [string]$TrustedSourceSha256[
    'scripts/mandatory_label_reader.dll'
]
$ArtifactSha256 = $TrustedArtifactSha256
$RuntimeSha256 = $TrustedRuntimeSha256
foreach ($Pin in $TrustedSourceSha256.GetEnumerator()) {
    Assert-PinnedWorkspaceFile `
        -ProjectRoot $ProjectRoot `
        -RelativePath ([string]$Pin.Key) `
        -ExpectedSha256 ([string]$Pin.Value)
}

$RequestId = [Guid]::NewGuid().ToString('N')
$RequestRoot = [IO.Path]::GetFullPath((Join-Path (
    Join-Path $LocalAppDataDirectory 'TenderBot\LiveInbound\prepared'
) $RequestId))
$PreparedReleaseRoot = Join-Path $RequestRoot 'releases'
[void](New-Item -ItemType Directory -Path $PreparedReleaseRoot -Force)
$AdminSnapshot = Join-Path $RequestRoot 'install-live-inbound-admin.ps1'
$InstallerSize = Copy-PinnedWorkspaceSnapshot `
    -SourcePath $AdminInstallerSource `
    -DestinationPath $AdminSnapshot `
    -ExpectedSha256 $InstallerSha256

$BuildOutput = & $BuildPython $BuildScript `
    --output-root $PreparedReleaseRoot `
    --require-clean-git-head
if ($LASTEXITCODE -ne 0) {
    throw 'Clean committed live inbound release preparation failed.'
}
$PreparedCandidates = @(
    Get-ChildItem -LiteralPath $PreparedReleaseRoot -Directory -Force
)
if (
    $PreparedCandidates.Count -ne 1 -or
    $PreparedCandidates[0].Name -cnotmatch '^[0-9a-f]{64}$' -or
    $PreparedCandidates[0].Attributes -band [IO.FileAttributes]::ReparsePoint -or
    -not [string]::IsNullOrEmpty([string]$PreparedCandidates[0].LinkType)
) {
    throw 'Prepared release identity is ambiguous.'
}
$PreparedReleaseDir = [IO.Path]::GetFullPath($PreparedCandidates[0].FullName)
$ReleaseSha256 = [string]$PreparedCandidates[0].Name
$ExpectedPreparedReleaseDir = [IO.Path]::GetFullPath(
    (Join-Path $PreparedReleaseRoot $ReleaseSha256)
)
if ($PreparedReleaseDir -cne $ExpectedPreparedReleaseDir) {
    throw 'Prepared release path is outside the request boundary.'
}
$PreparedTopLevel = @(Get-ChildItem -LiteralPath $PreparedReleaseDir -Force)
$ExpectedTopLevel = @(
    'live-inbound.pyz',
    'mandatory-label-reader.dll',
    'read-status.ps1',
    'release.json',
    'runtime',
    'verify-and-run.ps1'
)
if (
    $PreparedTopLevel.Count -ne $ExpectedTopLevel.Count -or
    @($PreparedTopLevel | Where-Object {
        $_.Name -cnotin $ExpectedTopLevel -or
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$_.LinkType)
    }).Count -ne 0
) {
    throw 'Prepared release top-level contract is invalid.'
}
$ManifestPath = Join-Path $PreparedReleaseDir 'release.json'
$ArtifactPath = Join-Path $PreparedReleaseDir 'live-inbound.pyz'
$LauncherPath = Join-Path $PreparedReleaseDir 'verify-and-run.ps1'
$StatusPath = Join-Path $PreparedReleaseDir 'read-status.ps1'
$MandatoryLabelReaderPath = Join-Path $PreparedReleaseDir 'mandatory-label-reader.dll'
$RuntimeRoot = Join-Path $PreparedReleaseDir 'runtime'
$ManifestItem = Get-Item -LiteralPath $ManifestPath -Force
if ($ManifestItem.Length -lt 1 -or $ManifestItem.Length -gt 4MB) {
    throw 'Prepared release manifest size is invalid.'
}
$ManifestSha256 = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $ManifestPath
).Hash.ToLowerInvariant()
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json -ErrorAction Stop
$SourceGitHead = [string]$Manifest.source_provenance.git_head
if (
    [string]$Manifest.format -cne 'TenderBot.LiveInbound.Release.v2' -or
    [string]$Manifest.release_sha256 -cne $ReleaseSha256 -or
    [string]$Manifest.artifact -cne 'live-inbound.pyz' -or
    [string]$Manifest.artifact_sha256 -cne $ArtifactSha256 -or
    [string]$Manifest.launcher -cne 'verify-and-run.ps1' -or
    [string]$Manifest.launcher_sha256 -cne $LauncherSha256 -or
    [string]$Manifest.status_script -cne 'read-status.ps1' -or
    [string]$Manifest.status_script_sha256 -cne $StatusSha256 -or
    [string]$Manifest.mandatory_label_reader -cne 'mandatory-label-reader.dll' -or
    [string]$Manifest.mandatory_label_reader_sha256 -cne
        $MandatoryLabelReaderSha256 -or
    [string]$Manifest.installer_sha256 -cne $InstallerSha256 -or
    [string]$Manifest.runtime_executable -cne 'runtime/python.exe' -or
    [string]$Manifest.runtime_sha256 -cne $RuntimeSha256 -or
    [string]$Manifest.runtime_dependency_contract -cne
        'cpython-stdlib-copy-no-site-v2' -or
    [string]$Manifest.source_provenance.builder_sha256 -cne
        [string]$TrustedSourceSha256['scripts/build_live_inbound_release.py'] -or
    [string]$Manifest.source_provenance.source_kind -cne 'git_head' -or
    -not [bool]$Manifest.source_provenance.reproducible_from_git_head -or
    $SourceGitHead -cnotmatch '^[0-9a-f]{40}$'
) {
    throw 'Prepared release manifest does not match the embedded trust anchor.'
}
if (
    (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToLowerInvariant() `
        -cne $ArtifactSha256 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $LauncherPath).Hash.ToLowerInvariant() `
        -cne $LauncherSha256 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $StatusPath).Hash.ToLowerInvariant() `
        -cne $StatusSha256 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $MandatoryLabelReaderPath).Hash.ToLowerInvariant() `
        -cne $MandatoryLabelReaderSha256 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $AdminSnapshot).Hash.ToLowerInvariant() `
        -cne $InstallerSha256 -or
    (Get-PreparedRuntimeSha256 `
        -RuntimeRoot $RuntimeRoot `
        -ManifestEntries $Manifest.runtime_files) -cne $RuntimeSha256
) {
    throw 'Prepared release bytes do not match the embedded trust anchor.'
}
Assert-PreparedArtifact `
    -ArtifactPath $ArtifactPath `
    -SourcePins $TrustedSourceSha256
foreach ($SignedRuntimeRelative in @('python.exe', 'python3.dll', 'python311.dll')) {
    $Signature = Get-AuthenticodeSignature -LiteralPath (
        Join-Path $RuntimeRoot $SignedRuntimeRelative
    )
    if (
        [string]$Signature.Status -cne 'Valid' -or
        $null -eq $Signature.SignerCertificate -or
        [string]$Signature.SignerCertificate.Thumbprint -cne
            $TrustedPythonSignerThumbprint
    ) {
        throw 'Prepared runtime publisher signature is not trusted.'
    }
}
$ProvenanceEntries = @($Manifest.source_provenance.sources)
$ExpectedProvenancePaths = @($TrustedSourceSha256.Keys) + @(
    'scripts/install_live_inbound_task.ps1'
)
$ObservedProvenancePaths = @(
    $ProvenanceEntries | ForEach-Object { [string]$_.path }
)
if (
    $ProvenanceEntries.Count -ne $ExpectedProvenancePaths.Count -or
    @(
        Compare-Object `
            -ReferenceObject $ExpectedProvenancePaths `
            -DifferenceObject $ObservedProvenancePaths `
            -CaseSensitive
    ).Count -ne 0 -or
    @($ProvenanceEntries | Where-Object {
        [string]$_.git_state -cne 'tracked_clean' -or
        [string]$_.git_head_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$_.git_head_sha256 -cne [string]$_.worktree_sha256
    }).Count -ne 0
) {
    throw 'Prepared release provenance set is not clean and exact.'
}
foreach ($Pin in $TrustedSourceSha256.GetEnumerator()) {
    $Bound = @($ProvenanceEntries | Where-Object {
        [string]$_.path -ceq [string]$Pin.Key
    })
    if (
        $Bound.Count -ne 1 -or
        [string]$Bound[0].worktree_sha256 -cne [string]$Pin.Value
    ) {
        throw 'Prepared release provenance does not match the embedded source pins.'
    }
}
$WrapperBound = @($ProvenanceEntries | Where-Object {
    [string]$_.path -ceq 'scripts/install_live_inbound_task.ps1'
})
if (
    $WrapperBound.Count -ne 1 -or
    [string]$WrapperBound[0].worktree_sha256 -cne $ExpectedWrapperSha256
) {
    throw 'Prepared release provenance does not bind the parsed trust anchor.'
}

function Write-PinnedElevationRequest {
    param(
        [Parameter(Mandatory = $true)][string]$RequestRoot,
        [Parameter(Mandatory = $true)]$Request
    )
    $Json = $Request | ConvertTo-Json -Compress
    $Bytes = [Text.Encoding]::UTF8.GetBytes($Json)
    if ($Bytes.Length -lt 1 -or $Bytes.Length -gt 64KB) {
        throw 'Elevation request size is invalid.'
    }
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $Sha256 = ([BitConverter]::ToString(
            $Hasher.ComputeHash($Bytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
    $Path = Join-Path $RequestRoot ($Sha256 + '.json')
    $Stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    } finally {
        $Stream.Dispose()
    }
    return [pscustomobject]@{ Path = $Path; Sha256 = $Sha256 }
}

function ConvertTo-CompressedEncodedCommand {
    param([Parameter(Mandatory = $true)][string]$Source)
    $SourceBytes = [Text.Encoding]::UTF8.GetBytes($Source)
    if ($SourceBytes.Length -lt 1 -or $SourceBytes.Length -gt 128KB) {
        throw 'Trusted elevation bootstrap source size is invalid.'
    }
    $SourceHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $SourceSha256 = ([BitConverter]::ToString(
            $SourceHasher.ComputeHash($SourceBytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $SourceHasher.Dispose()
    }
    $CompressedStream = New-Object IO.MemoryStream
    try {
        $Compressor = New-Object IO.Compression.GZipStream(
            $CompressedStream,
            [IO.Compression.CompressionMode]::Compress,
            $true
        )
        try {
            $Compressor.Write($SourceBytes, 0, $SourceBytes.Length)
        } finally {
            $Compressor.Dispose()
        }
        $CompressedBytes = $CompressedStream.ToArray()
    } finally {
        $CompressedStream.Dispose()
    }
    $CompressedHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $CompressedSha256 = ([BitConverter]::ToString(
            $CompressedHasher.ComputeHash($CompressedBytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $CompressedHasher.Dispose()
    }
    $Payload = [Convert]::ToBase64String($CompressedBytes)
    $LoaderTemplate = @'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Payload=[Convert]::FromBase64String('__PAYLOAD__')
$Hasher=[Security.Cryptography.SHA256]::Create()
try{$PayloadSha=([BitConverter]::ToString($Hasher.ComputeHash($Payload))).Replace('-','').ToLowerInvariant()}finally{$Hasher.Dispose()}
if($PayloadSha -cne '__PAYLOAD_SHA256__'){throw 'E01'}
$Input=New-Object IO.MemoryStream(,$Payload)
$Output=New-Object IO.MemoryStream
try{
  $Gzip=New-Object IO.Compression.GZipStream($Input,[IO.Compression.CompressionMode]::Decompress)
  try{$Gzip.CopyTo($Output)}finally{$Gzip.Dispose()}
  $SourceBytes=$Output.ToArray()
}finally{$Output.Dispose();$Input.Dispose()}
if($SourceBytes.Length -lt 1 -or $SourceBytes.Length -gt 128KB){throw 'E02'}
$Hasher=[Security.Cryptography.SHA256]::Create()
try{$SourceSha=([BitConverter]::ToString($Hasher.ComputeHash($SourceBytes))).Replace('-','').ToLowerInvariant()}finally{$Hasher.Dispose()}
if($SourceSha -cne '__SOURCE_SHA256__'){throw 'E03'}
$Source=[Text.Encoding]::UTF8.GetString($SourceBytes)
& ([ScriptBlock]::Create($Source))
'@
    $Loader = $LoaderTemplate.Replace('__PAYLOAD__', $Payload).Replace(
        '__PAYLOAD_SHA256__',
        $CompressedSha256
    ).Replace('__SOURCE_SHA256__', $SourceSha256)
    $Encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Loader)
    )
    if ($Encoded.Length -gt 30000) {
        throw 'Trusted elevation bootstrap exceeds the Windows command boundary.'
    }
    return $Encoded
}

$Request = [ordered]@{
    artifact_sha256 = $ArtifactSha256
    execution_sid = $CurrentSid
    install_phase = 'PrepareAndQuiesce'
    installer_sha256 = $InstallerSha256
    installer_size = $InstallerSize
    interval_seconds = $IntervalSeconds
    launcher_sha256 = $LauncherSha256
    mandatory_label_reader_sha256 = $MandatoryLabelReaderSha256
    manifest_sha256 = $ManifestSha256
    prepare_nonce = ''
    prepared_release_dir = $PreparedReleaseDir
    prepared_installer_path = [IO.Path]::GetFullPath($AdminSnapshot)
    release_sha256 = $ReleaseSha256
    request_id = $RequestId
    revocation_correlation_sha256 = ''
    runtime_sha256 = $RuntimeSha256
    source_git_head = $SourceGitHead
    status_script_sha256 = $StatusSha256
}
$PreparedRequest = Write-PinnedElevationRequest `
    -RequestRoot $RequestRoot `
    -Request $Request

$BootstrapTemplate = @'
$script:BootstrapFailureExitCode = 197
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
trap {
    $KnownFailure = [regex]::Match(
        [string]$_.Exception.Message,
        '^B(?<code>[0-9]{2})(?:[A-H])?$'
    )
    if ($KnownFailure.Success) {
        exit (100 + [int]$KnownFailure.Groups['code'].Value)
    }
    exit $script:BootstrapFailureExitCode
}
if ($PSVersionTable.PSEdition -cne 'Desktop') { throw 'B01' }
if (-not [Environment]::Is64BitProcess) { throw 'B02' }
$env:PSModulePath = "$PSHOME\Modules"
foreach ($Name in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility')) {
    $Module = "$PSHOME\Modules\$Name\$Name.psd1"
    if (-not [IO.File]::Exists($Module)) { throw 'B03' }
    Import-Module -Name $Module -Force -ErrorAction Stop
}
$PSModuleAutoLoadingPreference = 'None'
$EmbeddedRequestId = '__REQUEST_ID__'
$ExpectedRequestSha256 = '__REQUEST_SHA256__'
$Request = $null
$Required = @('artifact_sha256','execution_sid','install_phase','installer_sha256',
    'installer_size','interval_seconds','launcher_sha256','mandatory_label_reader_sha256',
    'manifest_sha256','prepare_nonce',
    'prepared_release_dir','prepared_installer_path','release_sha256','request_id',
    'revocation_correlation_sha256','runtime_sha256','source_git_head',
    'status_script_sha256')
$SystemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$ProgramFilesDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$LocalAppDataDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrWhiteSpace($SystemDirectory) -or [string]::IsNullOrWhiteSpace($ProgramFilesDirectory) -or [string]::IsNullOrWhiteSpace($LocalAppDataDirectory)) {
    throw 'B04'
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
    ) { throw 'B04A' }
    $Bytes = New-Object byte[] ([int]$Item.Length)
    $Stream = [IO.File]::Open(
        $Item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read
    )
    try {
        if ($Stream.Length -ne $Bytes.Length) { throw 'B04B' }
        $Offset = 0
        while ($Offset -lt $Bytes.Length) {
            $Read = $Stream.Read($Bytes,$Offset,$Bytes.Length - $Offset)
            if ($Read -le 0) { throw 'B04C' }
            $Offset += $Read
        }
        if ($Stream.ReadByte() -ne -1) { throw 'B04D' }
    } finally { $Stream.Dispose() }
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $ObservedSha256 = ([BitConverter]::ToString(
            $Hasher.ComputeHash($Bytes)
        )).Replace('-','').ToLowerInvariant()
    } finally { $Hasher.Dispose() }
    if ($ObservedSha256 -cne $ExpectedSha256) { throw 'B04E' }
    $Assembly = [Reflection.Assembly]::Load($Bytes)
    if (
        [string]$Assembly.FullName -cne
            'mandatory_label_reader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null' -or
        -not [string]::IsNullOrEmpty([string]$Assembly.Location)
    ) { throw 'B04F' }
    $Exported = @($Assembly.GetExportedTypes())
    $Reader = $Assembly.GetType(
        'TenderBot.LiveInbound.Security.MandatoryLabelReader',$true,$false
    )
    if ($Exported.Count -ne 1 -or $Exported[0] -ne $Reader) { throw 'B04G' }
    $Method = $Reader.GetMethod(
        'Read',[Reflection.BindingFlags]'Public,Static',$null,
        [Type[]]@([string]),$null
    )
    if ($null -eq $Method -or $Method.ReturnType -ne [string]) { throw 'B04H' }
    return $Reader
}
$PowerShellPath = Join-Path $SystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$PreparedRequestRoot = [IO.Path]::GetFullPath((Join-Path (
    Join-Path $LocalAppDataDirectory 'TenderBot\LiveInbound\prepared'
) $EmbeddedRequestId))
$RequestPath = Join-Path $PreparedRequestRoot ($ExpectedRequestSha256 + '.json')
if (
    $EmbeddedRequestId -cnotmatch '^[0-9a-f]{32}$' -or
    $ExpectedRequestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not [IO.File]::Exists($RequestPath)
) { throw 'B05' }
$RequestBytes = [IO.File]::ReadAllBytes($RequestPath)
if ($RequestBytes.Length -lt 1 -or $RequestBytes.Length -gt 64KB) {
    throw 'B06'
}
$RequestHasher = [Security.Cryptography.SHA256]::Create()
try {
    $ObservedRequestSha256 = ([BitConverter]::ToString(
        $RequestHasher.ComputeHash($RequestBytes)
    )).Replace('-', '').ToLowerInvariant()
} finally { $RequestHasher.Dispose() }
if ($ObservedRequestSha256 -cne $ExpectedRequestSha256) {
    throw 'B07'
}
$Request = [Text.Encoding]::UTF8.GetString($RequestBytes) |
    ConvertFrom-Json -ErrorAction Stop
$Names = @($Request.PSObject.Properties.Name)
if (@(Compare-Object -ReferenceObject $Required -DifferenceObject $Names).Count -ne 0) {
    throw 'B08'
}
foreach ($Name in @(
    'artifact_sha256','installer_sha256','launcher_sha256',
    'mandatory_label_reader_sha256','manifest_sha256','release_sha256',
    'runtime_sha256','status_script_sha256'
)) {
    if ([string]$Request.$Name -cnotmatch '^[0-9a-f]{64}$') { throw 'B09' }
}
if (
    [string]$Request.source_git_head -cnotmatch '^[0-9a-f]{40}$' -or
    [string]$Request.request_id -cne $EmbeddedRequestId -or
    [string]$Request.execution_sid -cnotmatch '^S-1-' -or
    [int]$Request.interval_seconds -lt 30 -or [int]$Request.interval_seconds -gt 3600 -or
    [int64]$Request.installer_size -lt 1 -or [int64]$Request.installer_size -gt 2MB
) { throw 'B10' }
if (
    [string]$Request.install_phase -cnotin @('PrepareAndQuiesce','Commit') -or
    ([string]$Request.install_phase -ceq 'PrepareAndQuiesce' -and
        (-not [string]::IsNullOrEmpty([string]$Request.prepare_nonce) -or
         -not [string]::IsNullOrEmpty([string]$Request.revocation_correlation_sha256))) -or
    ([string]$Request.install_phase -ceq 'Commit' -and
        ([string]$Request.prepare_nonce -cnotmatch '^[0-9a-f]{64}$' -or
         [string]$Request.revocation_correlation_sha256 -cnotmatch '^[0-9a-f]{64}$'))
) { throw 'B11' }
if ($CurrentSid -cne [string]$Request.execution_sid) { throw 'B12' }
$PreparedInstaller = [IO.Path]::GetFullPath([string]$Request.prepared_installer_path)
$PreparedRelease = [IO.Path]::GetFullPath([string]$Request.prepared_release_dir)
if (
    $PreparedInstaller -cne (Join-Path $PreparedRequestRoot 'install-live-inbound-admin.ps1') -or
    $PreparedRelease -cne (Join-Path (Join-Path $PreparedRequestRoot 'releases') ([string]$Request.release_sha256))
) { throw 'B13' }
$PreparedMandatoryLabelReader = [IO.Path]::GetFullPath(
    (Join-Path $PreparedRelease 'mandatory-label-reader.dll')
)
if (
    $PreparedMandatoryLabelReader -cne
        (Join-Path $PreparedRelease 'mandatory-label-reader.dll') -or
    -not [IO.File]::Exists($PreparedMandatoryLabelReader)
) { throw 'B14' }
$MandatoryLabelReaderType = Import-PinnedMandatoryLabelReader `
    -LiteralPath $PreparedMandatoryLabelReader `
    -ExpectedSha256 ([string]$Request.mandatory_label_reader_sha256)

function Resolve-SidValue {
    param([Parameter(Mandatory = $true)]$IdentityReference)
    if ([string]$IdentityReference -match '^S-1-') { return [string]$IdentityReference }
    return (New-Object Security.Principal.NTAccount([string]$IdentityReference)).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}
function Assert-HighLabel {
    param([Parameter(Mandatory = $true)][string]$LiteralPath,[switch]$Container)
    $Sddl = $MandatoryLabelReaderType::Read($LiteralPath)
    $Pattern = if ($Container.IsPresent) { '^S:[A-Z]*\(ML;(?=[A-Z]*OI)(?=[A-Z]*CI)[A-Z]*;NW;;;HI\)$' } else { '^S:[A-Z]*\(ML;[A-Z]*;NW;;;HI\)$' }
    if ($Sddl -cnotmatch $Pattern) { throw 'B15' }
}
function Protect-TrustedPath {
    param([Parameter(Mandatory = $true)][string]$LiteralPath,[Parameter(Mandatory = $true)][string]$ExecutionSid,[switch]$Container)
    $script:BootstrapFailureExitCode = 201
    $Item = Get-Item -LiteralPath $LiteralPath -Force
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or -not [string]::IsNullOrEmpty([string]$Item.LinkType)) {
        throw 'B16'
    }
    $Icacls = Join-Path $SystemDirectory 'icacls.exe'
    $script:BootstrapFailureExitCode = 202
    $CurrentAcl = Get-Acl -LiteralPath $Item.FullName
    if ((Resolve-SidValue $CurrentAcl.Owner) -cne 'S-1-5-18') {
        $script:BootstrapFailureExitCode = 203
        & $Icacls $Item.FullName /setowner '*S-1-5-18' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'B17' }
    }
    $Inheritance = if ($Container.IsPresent) { 'OICI' } else { '' }
    $Sddl = 'D:P' + "(A;$Inheritance;FA;;;SY)" + "(A;$Inheritance;FA;;;BA)" + "(A;$Inheritance;FRFX;;;$ExecutionSid)"
    $Acl = if ($Container.IsPresent) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $Acl.SetSecurityDescriptorSddlForm($Sddl,[Security.AccessControl.AccessControlSections]::Access)
    $script:BootstrapFailureExitCode = 204
    Set-Acl -LiteralPath $Item.FullName -AclObject $Acl
    $IntegrityAlreadyVerified = $false
    $script:BootstrapFailureExitCode = 205
    try {
        Assert-HighLabel -LiteralPath $Item.FullName -Container:$Container.IsPresent
        $IntegrityAlreadyVerified = $true
    } catch {
        if ([string]$_.Exception.Message -cne 'B15') { throw }
    }
    if (-not $IntegrityAlreadyVerified) {
        $script:BootstrapFailureExitCode = 206
        $Integrity = @($Item.FullName,'/setintegritylevel')
        if ($Container.IsPresent) { $Integrity += '(OI)(CI)H' } else { $Integrity += 'H' }
        & $Icacls @Integrity | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'B18' }
    }
    $script:BootstrapFailureExitCode = 207
    $Readback = Get-Acl -LiteralPath $Item.FullName
    if ((Resolve-SidValue $Readback.Owner) -cne 'S-1-5-18' -or -not $Readback.AreAccessRulesProtected -or @($Readback.Access).Count -ne 3) {
        throw 'B19'
    }
    Assert-HighLabel -LiteralPath $Item.FullName -Container:$Container.IsPresent
    $script:BootstrapFailureExitCode = 197
}

$Parents = @(
    (Join-Path $ProgramFilesDirectory 'TenderBot'),
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound'),
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\installers'),
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\requests')
)
foreach ($Path in $Parents) {
    if (-not [IO.Directory]::Exists($Path)) { [void](New-Item -ItemType Directory -Path $Path) }
    Protect-TrustedPath -LiteralPath $Path -ExecutionSid $CurrentSid -Container
}
$InstallerDirectory = Join-Path $Parents[2] ([string]$Request.installer_sha256)
if (-not [IO.Directory]::Exists($InstallerDirectory)) { [void](New-Item -ItemType Directory -Path $InstallerDirectory) }
Protect-TrustedPath -LiteralPath $InstallerDirectory -ExecutionSid $CurrentSid -Container
$TrustedInstaller = Join-Path $InstallerDirectory 'install-live-inbound-admin.ps1'
if (-not [IO.File]::Exists($TrustedInstaller)) {
    $SourceItem = Get-Item -LiteralPath $PreparedInstaller -Force
    if ($SourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or -not [string]::IsNullOrEmpty([string]$SourceItem.LinkType)) {
        throw 'B20'
    }
    $Source = [IO.File]::Open($PreparedInstaller,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($Source.Length -ne [int64]$Request.installer_size) { throw 'B21' }
        $Destination = [IO.File]::Open($TrustedInstaller,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $Source.CopyTo($Destination); $Destination.Flush($true) } finally { $Destination.Dispose() }
    } finally { $Source.Dispose() }
}
Protect-TrustedPath -LiteralPath $TrustedInstaller -ExecutionSid $CurrentSid
if (
    (Get-Item -LiteralPath $TrustedInstaller -Force).Length -ne [int64]$Request.installer_size -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $TrustedInstaller).Hash.ToLowerInvariant() -cne [string]$Request.installer_sha256
) { throw 'B22' }
$TrustedMandatoryLabelReader = Join-Path $InstallerDirectory 'mandatory-label-reader.dll'
if (-not [IO.File]::Exists($TrustedMandatoryLabelReader)) {
    $ReaderSourceItem = Get-Item -LiteralPath $PreparedMandatoryLabelReader -Force
    if (
        $ReaderSourceItem.PSIsContainer -or $ReaderSourceItem.Length -lt 1 -or
        $ReaderSourceItem.Length -gt 1MB -or
        $ReaderSourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$ReaderSourceItem.LinkType)
    ) { throw 'B22A' }
    $ReaderSource = [IO.File]::Open(
        $PreparedMandatoryLabelReader,[IO.FileMode]::Open,
        [IO.FileAccess]::Read,[IO.FileShare]::Read
    )
    try {
        $ReaderDestination = [IO.File]::Open(
            $TrustedMandatoryLabelReader,[IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,[IO.FileShare]::None
        )
        try {
            $ReaderSource.CopyTo($ReaderDestination)
            $ReaderDestination.Flush($true)
        } finally { $ReaderDestination.Dispose() }
    } finally { $ReaderSource.Dispose() }
}
Protect-TrustedPath -LiteralPath $TrustedMandatoryLabelReader -ExecutionSid $CurrentSid
if (
    (Get-Item -LiteralPath $TrustedMandatoryLabelReader -Force).Length -lt 1 -or
    (Get-Item -LiteralPath $TrustedMandatoryLabelReader -Force).Length -gt 1MB -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $TrustedMandatoryLabelReader).Hash.ToLowerInvariant() -cne
        [string]$Request.mandatory_label_reader_sha256
) { throw 'B22B' }
$RequestDirectory = Join-Path $Parents[3] ([string]$Request.request_id)
if (-not [IO.Directory]::Exists($RequestDirectory)) { [void](New-Item -ItemType Directory -Path $RequestDirectory) }
Protect-TrustedPath -LiteralPath $RequestDirectory -ExecutionSid $CurrentSid -Container
$ResultPath = Join-Path $RequestDirectory 'result.json'
$Arguments = @(
    '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$TrustedInstaller,
    '-RequestId',[string]$Request.request_id,
    '-ExpectedInstallerSha256',[string]$Request.installer_sha256,
    '-ExpectedReleaseSha256',[string]$Request.release_sha256,
    '-ExpectedRuntimeSha256',[string]$Request.runtime_sha256,
    '-ExpectedManifestSha256',[string]$Request.manifest_sha256,
    '-ExpectedArtifactSha256',[string]$Request.artifact_sha256,
    '-ExpectedLauncherSha256',[string]$Request.launcher_sha256,
    '-ExpectedStatusScriptSha256',[string]$Request.status_script_sha256,
    '-ExpectedMandatoryLabelReaderSha256',
        [string]$Request.mandatory_label_reader_sha256,
    '-ExpectedGitHead',[string]$Request.source_git_head,
    '-ExpectedExecutionSid',[string]$Request.execution_sid,
    '-InstallPhase',[string]$Request.install_phase,
    '-IntervalSeconds',[string]$Request.interval_seconds
)
if ([string]$Request.install_phase -ceq 'Commit') {
    $Arguments += @(
        '-ExpectedPrepareNonce',
        [string]$Request.prepare_nonce,
        '-ExpectedRevocationCorrelationSha256',
        [string]$Request.revocation_correlation_sha256
    )
}
$Output = & $PowerShellPath @Arguments
$ExitCode = $LASTEXITCODE
$OutputText = @($Output) -join [Environment]::NewLine
if ([string]::IsNullOrWhiteSpace($OutputText)) { $OutputText = '{"status":"error","error":"protected_admin_installer_failed"}' }
[IO.File]::WriteAllText($ResultPath,$OutputText,(New-Object Text.UTF8Encoding($false)))
Protect-TrustedPath -LiteralPath $ResultPath -ExecutionSid $CurrentSid
if ($ExitCode -ne 0) { exit $ExitCode }
exit 0
'@
$BootstrapSource = $BootstrapTemplate.Replace(
    '__REQUEST_ID__',
    $RequestId
).Replace(
    '__REQUEST_SHA256__',
    [string]$PreparedRequest.Sha256
)
$EncodedCommand = ConvertTo-CompressedEncodedCommand -Source $BootstrapSource
$Elevated = Start-Process `
    -FilePath $PowerShellPath `
    -ArgumentList @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        $EncodedCommand
    ) `
    -Verb RunAs `
    -WindowStyle Hidden `
    -Wait `
    -PassThru
$ResultPath = Join-Path (
    Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\requests'
) "$RequestId\result.json"
if ($Elevated.ExitCode -ne 0 -or -not [IO.File]::Exists($ResultPath)) {
    throw (
        'Protected elevated installation failed before a verified receipt was produced ' +
        "(bootstrap_exit=$($Elevated.ExitCode))."
    )
}
$ResultText = [IO.File]::ReadAllText($ResultPath, [Text.Encoding]::UTF8)
$Result = $ResultText | ConvertFrom-Json -ErrorAction Stop
if (
    [string]$Result.status -cne 'release_prepared_task_quiesced_pending_revoke' -or
    -not [bool]$Result.task_quiesced -or
    [string]$Result.release_sha256 -cne $ReleaseSha256 -or
    [string]$Result.runtime_sha256 -cne $RuntimeSha256 -or
    [string]$Result.manifest_sha256 -cne $ManifestSha256 -or
    [string]$Result.artifact_sha256 -cne $ArtifactSha256 -or
    [string]$Result.installer_sha256 -cne $InstallerSha256 -or
    [string]$Result.status_script_sha256 -cne $StatusSha256 -or
    [string]$Result.mandatory_label_reader_sha256 -cne
        $MandatoryLabelReaderSha256 -or
    [string]$Result.prepare_nonce -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$Result.prepare_receipt_format -cne
        'TenderBot.LiveInbound.AdminPrepareReceipt.v1' -or
    [string]$Result.prepare_receipt_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not [bool]$Result.prepare_receipt_verified -or
    [string]$Result.reservation_kind -cnotin @(
        'existing_task_quiesced','maintenance_placeholder'
    ) -or
    -not [bool]$Result.task_name_reserved
) {
    throw 'Protected preparation did not reach the quiesced pre-revoke state.'
}
$PrepareNonce = [string]$Result.prepare_nonce
$PrepareReceiptSha256 = [string]$Result.prepare_receipt_sha256
$ReservationKind = [string]$Result.reservation_kind
$ProtectedReleaseDir = [IO.Path]::GetFullPath((Join-Path (
    Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\releases'
) $ReleaseSha256))
$ProtectedLauncher = Join-Path $ProtectedReleaseDir 'verify-and-run.ps1'
$ProtectedStatus = Join-Path $ProtectedReleaseDir 'read-status.ps1'
$ProtectedMandatoryLabelReader = Join-Path (
    $ProtectedReleaseDir
) 'mandatory-label-reader.dll'
if (
    -not [IO.File]::Exists($ProtectedLauncher) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $ProtectedLauncher).Hash.ToLowerInvariant() `
        -cne $LauncherSha256 -or
    -not [IO.File]::Exists($ProtectedStatus) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $ProtectedStatus).Hash.ToLowerInvariant() `
        -cne $StatusSha256 -or
    -not [IO.File]::Exists($ProtectedMandatoryLabelReader) -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $ProtectedMandatoryLabelReader).Hash.ToLowerInvariant() `
        -cne $MandatoryLabelReaderSha256
) {
    throw 'Protected release scripts do not match the embedded trust anchor.'
}
$StateDir = [IO.Path]::GetFullPath((Join-Path (
    [Environment]::GetFolderPath('UserProfile')
) '.tenderbot\live_inbound'))
$LauncherArguments = @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', $ProtectedLauncher,
    '-ReleaseSha256', $ReleaseSha256,
    '-RuntimeSha256', $RuntimeSha256,
    '-ManifestSha256', $ManifestSha256,
    '-ArtifactSha256', $ArtifactSha256,
    '-MandatoryLabelReaderSha256', $MandatoryLabelReaderSha256,
    '-ExpectedSid', $CurrentSid,
    '-StateDir', $StateDir,
    '-IntervalSeconds', $IntervalSeconds
)
function Invoke-BoundedMediumRevoke {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellPath,
        [Parameter(Mandatory = $true)][object[]]$LauncherArguments,
        [Parameter(Mandatory = $true)][string]$Reason,
        [ValidateRange(1, 241)][int]$MaximumAttempts = 121
    )
    for ($Attempt = 1; $Attempt -le $MaximumAttempts; $Attempt++) {
        $PreviousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $Raw = @(& $PowerShellPath `
                @LauncherArguments `
                -Command revoke `
                -RevokeReason $Reason 2>&1)
            $ExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $PreviousPreference
        }
        $Payload = $null
        foreach ($Candidate in @($Raw | Select-Object -Last 3)) {
            try {
                $Payload = ([string]$Candidate) | ConvertFrom-Json -ErrorAction Stop
            } catch {
                continue
            }
        }
        if (
            $ExitCode -eq 0 -and
            $null -ne $Payload -and
            [bool]$Payload.ok -and
            [string]$Payload.authority_state -ceq 'REVOKED' -and
            -not [bool]$Payload.operational_ready -and
            [int64]$Payload.authority_generation -ge 1
        ) {
            return $Payload
        }
        if ($Attempt -lt $MaximumAttempts) {
            Start-Sleep -Milliseconds 250
        }
    }
    throw 'Medium-integrity authority revoke did not reach a durable idle gap.'
}
Push-Location $ProtectedReleaseDir
try {
    $VerifyOutput = & $PowerShellPath @LauncherArguments -Command verify-release
    $VerifyExit = $LASTEXITCODE
    $Verify = $VerifyOutput | ConvertFrom-Json -ErrorAction Stop
    if (
        $VerifyExit -ne 0 -or
        -not [bool]$Verify.release_verified -or
        -not [bool]$Verify.runtime_verified -or
        -not [bool]$Verify.isolated_runtime
    ) {
        throw 'Medium-integrity private runtime verification failed.'
    }
    $Revoke = Invoke-BoundedMediumRevoke `
        -PowerShellPath $PowerShellPath `
        -LauncherArguments $LauncherArguments `
        -Reason release_replacement
} finally {
    Pop-Location
}
$InitialAuthorityGeneration = [int64]$Revoke.authority_generation
$RevocationCorrelation = [ordered]@{
    artifact_sha256 = $ArtifactSha256
    authority_generation = $InitialAuthorityGeneration
    authority_state = 'REVOKED'
    manifest_sha256 = $ManifestSha256
    operational_ready = $false
    release_sha256 = $ReleaseSha256
    request_id = $RequestId
    runtime_sha256 = $RuntimeSha256
} | ConvertTo-Json -Compress
$CorrelationHasher = [Security.Cryptography.SHA256]::Create()
try {
    $RevocationCorrelationSha256 = ([BitConverter]::ToString(
        $CorrelationHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($RevocationCorrelation))
    )).Replace('-', '').ToLowerInvariant()
} finally {
    $CorrelationHasher.Dispose()
}
$Request['install_phase'] = 'Commit'
$Request['prepare_nonce'] = $PrepareNonce
$Request['revocation_correlation_sha256'] = $RevocationCorrelationSha256
$CommitPreparedRequest = Write-PinnedElevationRequest `
    -RequestRoot $RequestRoot `
    -Request $Request
$CommitBootstrapSource = $BootstrapTemplate.Replace(
    '__REQUEST_ID__',
    $RequestId
).Replace(
    '__REQUEST_SHA256__',
    [string]$CommitPreparedRequest.Sha256
)
$CommitEncodedCommand = ConvertTo-CompressedEncodedCommand `
    -Source $CommitBootstrapSource
$CommitResult = $null
$CommitFailure = $null
$FinalRevoke = $null
$FinalRevokeFailure = $null
try {
    $CommitElevated = Start-Process `
        -FilePath $PowerShellPath `
        -ArgumentList @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-EncodedCommand',
            $CommitEncodedCommand
        ) `
        -Verb RunAs `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    if ($CommitElevated.ExitCode -ne 0 -or -not [IO.File]::Exists($ResultPath)) {
        throw (
            'Protected commit failed after authority was safely revoked ' +
            "(bootstrap_exit=$($CommitElevated.ExitCode))."
        )
    }
    $CommitResultText = [IO.File]::ReadAllText(
        $ResultPath,
        [Text.Encoding]::UTF8
    )
    $CommitResult = $CommitResultText | ConvertFrom-Json -ErrorAction Stop
    if (
        [string]$CommitResult.status -cne 'installed_not_authorized' -or
        [bool]$CommitResult.task_enabled -or
        [string]$CommitResult.authority_revocation_correlation_sha256 -cne
            $RevocationCorrelationSha256 -or
        [string]$CommitResult.release_sha256 -cne $ReleaseSha256 -or
        [string]$CommitResult.runtime_sha256 -cne $RuntimeSha256 -or
        [string]$CommitResult.manifest_sha256 -cne $ManifestSha256 -or
        [string]$CommitResult.artifact_sha256 -cne $ArtifactSha256 -or
        [string]$CommitResult.status_script_sha256 -cne $StatusSha256 -or
        [string]$CommitResult.mandatory_label_reader_sha256 -cne
            $MandatoryLabelReaderSha256 -or
        -not [bool]$CommitResult.prepare_nonce_verified -or
        [string]$CommitResult.prepare_receipt_format -cne
            'TenderBot.LiveInbound.AdminPrepareReceipt.v1' -or
        [string]$CommitResult.prepare_receipt_sha256 -cne
            $PrepareReceiptSha256 -or
        -not [bool]$CommitResult.prepare_receipt_verified -or
        [string]$CommitResult.reservation_kind -cne $ReservationKind -or
        -not [bool]$CommitResult.task_name_reserved
    ) {
        throw 'Protected commit did not reach the disabled V4 state.'
    }
} catch {
    $CommitFailure = $_
} finally {
    try {
        $FinalRevoke = Invoke-BoundedMediumRevoke `
            -PowerShellPath $PowerShellPath `
            -LauncherArguments $LauncherArguments `
            -Reason release_replacement
    } catch {
        $FinalRevokeFailure = $_
    }
}
if ($null -ne $FinalRevokeFailure) {
    $Primary = if ($null -ne $CommitFailure) {
        [string]$CommitFailure.Exception.Message
    } else {
        'none'
    }
    throw (
        'Final medium-integrity authority revoke failed; commit error: ' +
        $Primary + '; revoke error: ' +
        [string]$FinalRevokeFailure.Exception.Message
    )
}
if ($null -ne $CommitFailure) {
    throw $CommitFailure
}
$FinalAuthorityGeneration = [int64]$FinalRevoke.authority_generation
[ordered]@{
    action_verified = [bool]$CommitResult.action_verified
    artifact_sha256 = $ArtifactSha256
    artifact_verified = [bool]$CommitResult.artifact_verified
    authority_final_state_verified_by_medium = $true
    authority_generation = $FinalAuthorityGeneration
    authority_generation_changed_during_cutover = [bool](
        $FinalAuthorityGeneration -ne $InitialAuthorityGeneration
    )
    authority_initial_revoked_generation = $InitialAuthorityGeneration
    authority_reauthorization_window_closed = $true
    authority_state = 'REVOKED'
    current_user_sid_verified = [bool]$CommitResult.current_user_sid_verified
    integrity_acl_verified = [bool]$CommitResult.integrity_acl_verified
    installer_sha256 = $InstallerSha256
    installer_verified = [bool]$CommitResult.installer_verified
    manifest_sha256 = $ManifestSha256
    manifest_verified = [bool]$CommitResult.manifest_verified
    mandatory_label_reader_sha256 = $MandatoryLabelReaderSha256
    medium_runtime_verified = $true
    prepare_nonce_verified = [bool]$CommitResult.prepare_nonce_verified
    prepare_receipt_format = [string]$CommitResult.prepare_receipt_format
    prepare_receipt_sha256 = $PrepareReceiptSha256
    release_pinned = [bool]$CommitResult.release_pinned
    release_sha256 = $ReleaseSha256
    reservation_kind = $ReservationKind
    prepare_receipt_verified = [bool]$CommitResult.prepare_receipt_verified
    runtime_sha256 = $RuntimeSha256
    source_component_set_verified = $true
    source_git_head_claim = $SourceGitHead
    status = 'installed_not_authorized'
    status_path = $ProtectedStatus
    status_script_sha256 = $StatusSha256
    task_enabled = $false
    task_name_reserved = [bool]$CommitResult.task_name_reserved
    task_acl_verified = [bool]$CommitResult.task_acl_verified
    task_name = [string]$CommitResult.task_name
} | ConvertTo-Json -Compress
}
# TRUSTED_FRESH_CORE_END
