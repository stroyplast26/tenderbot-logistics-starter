#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-LiveInboundTaskDescription {
    param([Parameter(Mandatory = $true)][string]$Description)
    $LegacyPattern = (
        '^TenderBot Live Inbound v3; release_sha256=(?<release>[0-9a-f]{64}); ' +
        'runtime_sha256=(?<runtime>[0-9a-f]{64}); ' +
        'manifest_sha256=(?<manifest>[0-9a-f]{64}); ' +
        'artifact_sha256=(?<artifact>[0-9a-f]{64}); ' +
        'interval_seconds=(?<interval>[0-9]{2,4})\. ' +
        'IMAP INBOX read-only intake and bounded idempotent Bitrix lead delivery; ' +
        'no outbound email, no UniSender send, no TenderPlan access\.$'
    )
    $CurrentPattern = (
        '^TenderBot Live Inbound v4; release_sha256=(?<release>[0-9a-f]{64}); ' +
        'runtime_sha256=(?<runtime>[0-9a-f]{64}); ' +
        'manifest_sha256=(?<manifest>[0-9a-f]{64}); ' +
        'artifact_sha256=(?<artifact>[0-9a-f]{64}); ' +
        'status_script_sha256=(?<status>[0-9a-f]{64}); ' +
        'mandatory_label_reader_sha256=(?<reader>[0-9a-f]{64}); ' +
        'interval_seconds=(?<interval>[0-9]{2,4})\. ' +
        'IMAP INBOX and native Bitrix Mail activity observation; local evidence and ' +
        'review only; no CRM writes, no operator Todo, no outbound email, no UniSender ' +
        'send, no TenderPlan access\.$'
    )
    foreach ($Candidate in @(
        [pscustomobject]@{ Version = 3; Pattern = $LegacyPattern },
        [pscustomobject]@{ Version = 4; Pattern = $CurrentPattern }
    )) {
        $Match = [regex]::Match(
            $Description,
            [string]$Candidate.Pattern,
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $Match.Success) { continue }
        $ParsedInterval = [int]$Match.Groups['interval'].Value
        if ($ParsedInterval -lt 30 -or $ParsedInterval -gt 3600) { return $null }
        $StatusScriptSha256 = ''
        $MandatoryLabelReaderSha256 = ''
        if ([int]$Candidate.Version -eq 4) {
            $StatusScriptSha256 = [string]$Match.Groups['status'].Value
            $MandatoryLabelReaderSha256 = [string]$Match.Groups['reader'].Value
        }
        return [pscustomobject]@{
            Version = [int]$Candidate.Version
            ReleaseSha256 = [string]$Match.Groups['release'].Value
            RuntimeSha256 = [string]$Match.Groups['runtime'].Value
            ManifestSha256 = [string]$Match.Groups['manifest'].Value
            ArtifactSha256 = [string]$Match.Groups['artifact'].Value
            StatusScriptSha256 = $StatusScriptSha256
            MandatoryLabelReaderSha256 = $MandatoryLabelReaderSha256
            IntervalSeconds = $ParsedInterval
        }
    }
    return $null
}

if ($PSVersionTable.PSEdition -cne 'Desktop') {
    throw 'Run this status check with Windows PowerShell 5.1 (powershell.exe).'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Run this status check with 64-bit Windows PowerShell 5.1.'
}
$env:PSModulePath = "$PSHOME\Modules"
foreach ($TrustedModuleName in @(
    'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.Security',
    'Microsoft.PowerShell.Utility',
    'ScheduledTasks'
)) {
    $TrustedModulePath = "$PSHOME\Modules\$TrustedModuleName\$TrustedModuleName.psd1"
    if (-not [IO.File]::Exists($TrustedModulePath)) {
        throw 'A trusted Windows PowerShell module is unavailable.'
    }
    Import-Module -Name $TrustedModulePath -Force -ErrorAction Stop
}
$PSModuleAutoLoadingPreference = 'None'

$SystemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$ProgramFilesDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles
)
if (
    [string]::IsNullOrWhiteSpace($SystemDirectory) -or
    [string]::IsNullOrWhiteSpace($ProgramFilesDirectory)
) {
    throw 'Canonical Windows system directories are unavailable.'
}

function Read-ExactFileBytes {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [ValidateRange(1, 4194304)][int64]$MaximumBytes = 1MB
    )
    $Item = Get-Item -LiteralPath $LiteralPath -Force
    if (
        $Item.PSIsContainer -or
        $Item.Length -lt 1 -or
        $Item.Length -gt $MaximumBytes -or
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$Item.LinkType)
    ) {
        throw 'Pinned file is linked, empty, or outside its size contract.'
    }
    $Stream = [IO.File]::Open(
        $Item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($Stream.Length -ne [int64]$Item.Length) {
            throw 'Pinned file size changed before its exact read.'
        }
        $Bytes = New-Object byte[] ([int]$Stream.Length)
        $Offset = 0
        while ($Offset -lt $Bytes.Length) {
            $Read = $Stream.Read($Bytes, $Offset, $Bytes.Length - $Offset)
            if ($Read -le 0) { throw 'Pinned file ended during its exact read.' }
            $Offset += $Read
        }
        if ($Stream.ReadByte() -ne -1) {
            throw 'Pinned file grew during its exact read.'
        }
        return ,$Bytes
    } finally {
        $Stream.Dispose()
    }
}

function Get-Sha256HexFromBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $Hasher.ComputeHash($Bytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
}

function Import-PinnedMandatoryLabelReader {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedSha256
    )
    $Bytes = [byte[]](Read-ExactFileBytes -LiteralPath $LiteralPath -MaximumBytes 1MB)
    $ObservedSha256 = Get-Sha256HexFromBytes -Bytes $Bytes
    if ($ObservedSha256 -cne $ExpectedSha256) {
        throw 'Mandatory label reader bytes do not match their protected pin.'
    }
    $Assembly = [Reflection.Assembly]::Load($Bytes)
    if (
        [string]$Assembly.FullName -cne
            'mandatory_label_reader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null' -or
        -not [string]::IsNullOrEmpty([string]$Assembly.Location)
    ) {
        throw 'Mandatory label reader assembly identity is invalid.'
    }
    $Types = @($Assembly.GetTypes())
    $ReaderType = $Assembly.GetType(
        'TenderBot.LiveInbound.Security.MandatoryLabelReader',
        $false,
        $false
    )
    if ($Types.Count -ne 1 -or $null -eq $ReaderType) {
        throw 'Mandatory label reader type contract is invalid.'
    }
    $ReadMethods = @($ReaderType.GetMethods(
        [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static
    ) | Where-Object {
        $_.Name -ceq 'Read' -and
        $_.ReturnType -eq [string] -and
        @($_.GetParameters()).Count -eq 1 -and
        $_.GetParameters()[0].ParameterType -eq [string]
    })
    if ($ReadMethods.Count -ne 1) {
        throw 'Mandatory label reader method contract is invalid.'
    }
    return $ReaderType
}
$TaskName = 'TenderBot Live Inbound'
$TaskMarker = 'TenderBot Live Inbound v4'

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

function Test-ProtectedReleaseAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    try {
        $Item = Get-Item -LiteralPath $LiteralPath -Force
        if (
            $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not [string]::IsNullOrEmpty([string]$Item.LinkType)
        ) { return $false }
        $Acl = Get-Acl -LiteralPath $LiteralPath
        if (
            (Resolve-SidValue -IdentityReference $Acl.Owner) -cne 'S-1-5-18' -or
            -not $Acl.AreAccessRulesProtected
        ) { return $false }
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
            ) { return $false }
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
        [Parameter(Mandatory = $true)]$ReaderType,
        [switch]$RequireInheritance
    )
    try {
        return [bool](
            Test-HighIntegritySddl `
                -Sddl $ReaderType::Read($LiteralPath) `
                -RequireInheritance:$RequireInheritance.IsPresent
        )
    } catch {
        return $false
    }
}

function Test-ExactJsonProperties {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )
    try {
        $Actual = @($Value.PSObject.Properties.Name)
        return [bool](
            $Actual.Count -eq $Expected.Count -and
            @(Compare-Object `
                -ReferenceObject $Expected `
                -DifferenceObject $Actual `
                -CaseSensitive).Count -eq 0
        )
    } catch {
        return $false
    }
}

function Test-TaskSecurityDescriptor {
    param(
        [Parameter(Mandatory = $true)][string]$Sddl,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    try {
        $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
        if (
            $Descriptor.Owner.Value -cne 'S-1-5-32-544' -or
            $Descriptor.Group.Value -cne 'S-1-5-32-544' -or
            -not ($Descriptor.ControlFlags -band
                [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
        ) { return $false }
        $Expected = @{
            'S-1-5-18' = 0x1F01FF
            'S-1-5-32-544' = 0x1F01FF
            $ExecutionSid = 0x1200A9
        }
        $Observed = @{}
        $Aces = @($Descriptor.DiscretionaryAcl)
        if ($Aces.Count -ne $Expected.Count) { return $false }
        foreach ($Ace in $Aces) {
            if (
                $Ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
                $Ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
                $Observed.ContainsKey($Ace.SecurityIdentifier.Value)
            ) {
                return $false
            }
            $Observed[$Ace.SecurityIdentifier.Value] = [int]$Ace.AccessMask
        }
        if ($Observed.Count -ne $Expected.Count) { return $false }
        foreach ($Sid in $Expected.Keys) {
            if (-not $Observed.ContainsKey($Sid) -or $Observed[$Sid] -ne $Expected[$Sid]) {
                return $false
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Get-LatestPreparedReleaseReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$RequestRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseRoot,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    if (
        -not (Test-Path -LiteralPath $RequestRoot -PathType Container) -or
        -not (Test-ProtectedReleaseAcl `
            -LiteralPath $RequestRoot `
            -ExecutionSid $ExecutionSid)
    ) {
        return $null
    }
    $Receipts = New-Object 'Collections.Generic.List[object]'
    foreach ($RequestDirectory in @(Get-ChildItem -LiteralPath $RequestRoot -Directory -Force)) {
        $ReceiptPath = Join-Path $RequestDirectory.FullName 'prepare-receipt.json'
        if (
            $RequestDirectory.Name -cnotmatch '^[0-9a-f]{32}$' -or
            $RequestDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not [string]::IsNullOrEmpty([string]$RequestDirectory.LinkType) -or
            -not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf) -or
            -not (Test-ProtectedReleaseAcl `
                -LiteralPath $RequestDirectory.FullName `
                -ExecutionSid $ExecutionSid) -or
            -not (Test-ProtectedReleaseAcl `
                -LiteralPath $ReceiptPath `
                -ExecutionSid $ExecutionSid)
        ) { continue }
        try {
            $ReceiptBytes = [byte[]](Read-ExactFileBytes `
                -LiteralPath $ReceiptPath `
                -MaximumBytes 16KB)
            $Receipt = (New-Object Text.UTF8Encoding($false, $true)).GetString(
                $ReceiptBytes
            ) |
                ConvertFrom-Json -ErrorAction Stop
            if (
                -not (Test-ExactJsonProperties -Value $Receipt -Expected @(
                    'artifact_sha256',
                    'existing_task_found',
                    'execution_sid',
                    'format',
                    'installer_sha256',
                    'interval_seconds',
                    'launcher_sha256',
                    'mandatory_label_reader_sha256',
                    'manifest_sha256',
                    'prepare_nonce_sha256',
                    'release_sha256',
                    'request_id',
                    'reservation_description_sha256',
                    'reservation_kind',
                    'runtime_sha256',
                    'status_script_sha256',
                    'task_name',
                    'task_quiesced'
                )) -or
                [string]$Receipt.format -cne
                    'TenderBot.LiveInbound.AdminPrepareReceipt.v1' -or
                [string]$Receipt.request_id -cne $RequestDirectory.Name -or
                [string]$Receipt.execution_sid -cne $ExecutionSid -or
                [string]$Receipt.task_name -cne $TaskName -or
                -not ($Receipt.task_quiesced -is [bool]) -or
                -not [bool]$Receipt.task_quiesced -or
                -not ($Receipt.existing_task_found -is [bool]) -or
                [string]$Receipt.reservation_description_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$Receipt.reservation_kind -cnotin @(
                    'existing_task_quiesced',
                    'maintenance_placeholder'
                ) -or
                ([bool]$Receipt.existing_task_found -and
                    [string]$Receipt.reservation_kind -cne
                        'existing_task_quiesced') -or
                (-not [bool]$Receipt.existing_task_found -and
                    [string]$Receipt.reservation_kind -cne
                        'maintenance_placeholder') -or
                [int]$Receipt.interval_seconds -lt 30 -or
                [int]$Receipt.interval_seconds -gt 3600 -or
                [string]$Receipt.prepare_nonce_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                @(@(
                    [string]$Receipt.artifact_sha256,
                    [string]$Receipt.installer_sha256,
                    [string]$Receipt.launcher_sha256,
                    [string]$Receipt.mandatory_label_reader_sha256,
                    [string]$Receipt.manifest_sha256,
                    [string]$Receipt.release_sha256,
                    [string]$Receipt.runtime_sha256,
                    [string]$Receipt.status_script_sha256
                ) | Where-Object {
                    $_ -cnotmatch '^[0-9a-f]{64}$'
                }).Count -ne 0
            ) { continue }
            [void]$Receipts.Add([pscustomobject]@{
                Payload = $Receipt
                ReceiptPath = $ReceiptPath
                RequestDirectory = $RequestDirectory.FullName
                WrittenAtUtc = (Get-Item -LiteralPath $ReceiptPath -Force).LastWriteTimeUtc
            })
        } catch {
            continue
        }
    }
    $SortedReceipts = @(
        $Receipts | Sort-Object WrittenAtUtc -Descending | Select-Object -First 1
    )
    if ($SortedReceipts.Count -eq 0) { return $null }
    $Latest = $SortedReceipts[0]
    try {
        $Receipt = $Latest.Payload
        $ReleaseDir = [IO.Path]::GetFullPath(
            (Join-Path $ReleaseRoot ([string]$Receipt.release_sha256))
        )
        $ManifestPath = Join-Path $ReleaseDir 'release.json'
        $ArtifactPath = Join-Path $ReleaseDir 'live-inbound.pyz'
        $LauncherPath = Join-Path $ReleaseDir 'verify-and-run.ps1'
        $StatusPath = Join-Path $ReleaseDir 'read-status.ps1'
        $ReaderPath = Join-Path $ReleaseDir 'mandatory-label-reader.dll'
        $RuntimePath = Join-Path $ReleaseDir 'runtime\python.exe'
        $LiveInboundRoot = [IO.Path]::GetFullPath(
            (Split-Path -Parent $ReleaseRoot)
        )
        $TenderBotRoot = [IO.Path]::GetFullPath(
            (Split-Path -Parent $LiveInboundRoot)
        )
        $ExpectedTopLevel = @(
            'live-inbound.pyz',
            'mandatory-label-reader.dll',
            'read-status.ps1',
            'release.json',
            'runtime',
            'verify-and-run.ps1'
        )
        $TopLevel = @(Get-ChildItem -LiteralPath $ReleaseDir -Force)
        if (
            [string]::IsNullOrWhiteSpace($PSCommandPath) -or
            [IO.Path]::GetFullPath($PSCommandPath) -cne
                [IO.Path]::GetFullPath($StatusPath) -or
            -not (Test-ProtectedReleaseAcl `
                -LiteralPath $TenderBotRoot `
                -ExecutionSid $ExecutionSid) -or
            -not (Test-ProtectedReleaseAcl `
                -LiteralPath $LiveInboundRoot `
                -ExecutionSid $ExecutionSid) -or
            -not (Test-ProtectedReleaseAcl `
                -LiteralPath $ReleaseRoot `
                -ExecutionSid $ExecutionSid) -or
            -not (Test-ProtectedReleaseAcl `
                -LiteralPath $ReleaseDir `
                -ExecutionSid $ExecutionSid) -or
            -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $StatusPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $ReaderPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $RuntimePath -PathType Leaf) -or
            $TopLevel.Count -ne $ExpectedTopLevel.Count -or
            @(Compare-Object `
                -ReferenceObject $ExpectedTopLevel `
                -DifferenceObject @($TopLevel.Name) `
                -CaseSensitive).Count -ne 0
        ) { return $null }
        foreach ($Item in $TopLevel) {
            if (-not (Test-ProtectedReleaseAcl `
                -LiteralPath $Item.FullName `
                -ExecutionSid $ExecutionSid)) { return $null }
        }
        $StatusBytes = [byte[]](Read-ExactFileBytes `
            -LiteralPath $StatusPath `
            -MaximumBytes 4MB)
        $ReaderBytes = [byte[]](Read-ExactFileBytes `
            -LiteralPath $ReaderPath `
            -MaximumBytes 1MB)
        if (
            (Get-Sha256HexFromBytes -Bytes $StatusBytes) -cne
                [string]$Receipt.status_script_sha256 -or
            (Get-Sha256HexFromBytes -Bytes $ReaderBytes) -cne
                [string]$Receipt.mandatory_label_reader_sha256
        ) { return $null }
        $ReaderType = Import-PinnedMandatoryLabelReader `
            -LiteralPath $ReaderPath `
            -ExpectedSha256 ([string]$Receipt.mandatory_label_reader_sha256)
        if (
            -not (Test-HighIntegrityLabel `
                -LiteralPath $TenderBotRoot `
                -ReaderType $ReaderType `
                -RequireInheritance) -or
            -not (Test-HighIntegrityLabel `
                -LiteralPath $LiveInboundRoot `
                -ReaderType $ReaderType `
                -RequireInheritance) -or
            -not (Test-HighIntegrityLabel `
                -LiteralPath $RequestRoot `
                -ReaderType $ReaderType `
                -RequireInheritance) -or
            -not (Test-HighIntegrityLabel `
                -LiteralPath ([string]$Latest.RequestDirectory) `
                -ReaderType $ReaderType `
                -RequireInheritance) -or
            -not (Test-HighIntegrityLabel `
                -LiteralPath ([string]$Latest.ReceiptPath) `
                -ReaderType $ReaderType) -or
            -not (Test-HighIntegrityLabel `
                -LiteralPath $ReleaseRoot `
                -ReaderType $ReaderType `
                -RequireInheritance) -or
            -not (Test-HighIntegrityLabel `
                -LiteralPath $ReleaseDir `
                -ReaderType $ReaderType `
                -RequireInheritance)
        ) { return $null }
        foreach ($Item in $TopLevel) {
            if (-not (Test-HighIntegrityLabel `
                -LiteralPath $Item.FullName `
                -ReaderType $ReaderType `
                -RequireInheritance:$Item.PSIsContainer)) { return $null }
        }
        $ManifestBytes = [byte[]](Read-ExactFileBytes `
            -LiteralPath $ManifestPath `
            -MaximumBytes 4MB)
        if ((Get-Sha256HexFromBytes -Bytes $ManifestBytes) -cne
            [string]$Receipt.manifest_sha256) { return $null }
        $Manifest = (New-Object Text.UTF8Encoding($false, $true)).GetString(
            $ManifestBytes
        ) |
            ConvertFrom-Json -ErrorAction Stop
        if (
            -not (Test-ExactJsonProperties -Value $Manifest -Expected @(
                'artifact', 'artifact_sha256', 'format', 'installer_sha256',
                'launcher', 'launcher_sha256', 'mandatory_label_reader',
                'mandatory_label_reader_sha256', 'python_version',
                'release_sha256', 'runtime_dependency_contract',
                'runtime_executable', 'runtime_files', 'runtime_sha256',
                'source_provenance', 'source_sha256', 'status_script',
                'status_script_sha256'
            )) -or
            [string]$Manifest.format -cne 'TenderBot.LiveInbound.Release.v2' -or
            [string]$Manifest.release_sha256 -cne [string]$Receipt.release_sha256 -or
            [string]$Manifest.runtime_sha256 -cne [string]$Receipt.runtime_sha256 -or
            [string]$Manifest.artifact_sha256 -cne [string]$Receipt.artifact_sha256 -or
            [string]$Manifest.artifact -cne 'live-inbound.pyz' -or
            [string]$Manifest.launcher -cne 'verify-and-run.ps1' -or
            [string]$Manifest.status_script -cne 'read-status.ps1' -or
            [string]$Manifest.status_script_sha256 -cne
                [string]$Receipt.status_script_sha256 -or
            [string]$Manifest.mandatory_label_reader -cne
                'mandatory-label-reader.dll' -or
            [string]$Manifest.mandatory_label_reader_sha256 -cne
                [string]$Receipt.mandatory_label_reader_sha256 -or
            [string]$Manifest.installer_sha256 -cne
                [string]$Receipt.installer_sha256 -or
            [string]$Manifest.launcher_sha256 -cne
                [string]$Receipt.launcher_sha256 -or
            [string]$Manifest.runtime_executable -cne 'runtime/python.exe' -or
            [string]$Manifest.runtime_dependency_contract -cne
                'cpython-stdlib-copy-no-site-v2' -or
            (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant() `
                -cne [string]$Receipt.artifact_sha256 -or
            (Get-FileHash -LiteralPath $LauncherPath -Algorithm SHA256).Hash.ToLowerInvariant() `
                -cne [string]$Manifest.launcher_sha256
        ) { return $null }
        if (-not (Test-LiveInboundRuntimePayload `
            -RuntimeDir (Join-Path $ReleaseDir 'runtime') `
            -Manifest $Manifest `
            -RuntimeSha256 ([string]$Receipt.runtime_sha256) `
            -ExecutionSid $ExecutionSid `
            -MandatoryLabelReaderType $ReaderType)) { return $null }
        return [pscustomobject]@{
            ArtifactSha256 = [string]$Receipt.artifact_sha256
            MandatoryLabelReaderSha256 = [string]$Receipt.mandatory_label_reader_sha256
            MandatoryLabelReaderType = $ReaderType
            ManifestSha256 = [string]$Receipt.manifest_sha256
            IntervalSeconds = [int]$Receipt.interval_seconds
            ReleaseSha256 = [string]$Receipt.release_sha256
            ReceiptPath = [string]$Latest.ReceiptPath
            RuntimeSha256 = [string]$Receipt.runtime_sha256
            StatusScriptSha256 = [string]$Receipt.status_script_sha256
            WrittenAtUtc = $Latest.WrittenAtUtc
        }
    } catch {
        return $null
    }
}

function Test-LiveInboundRuntimePayload {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeDir,
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$RuntimeSha256,
        [Parameter(Mandatory = $true)][string]$ExecutionSid,
        [Parameter(Mandatory = $true)]$MandatoryLabelReaderType
    )
    try {
        $RuntimeDirectories = @(
            Get-Item -LiteralPath $RuntimeDir -Force
            Get-ChildItem -LiteralPath $RuntimeDir -Directory -Recurse -Force
        )
        foreach ($RuntimeDirectory in $RuntimeDirectories) {
            if (
                $RuntimeDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint -or
                -not (Test-ProtectedReleaseAcl `
                    -LiteralPath $RuntimeDirectory.FullName `
                    -ExecutionSid $ExecutionSid) -or
                -not (Test-HighIntegrityLabel `
                    -LiteralPath $RuntimeDirectory.FullName `
                    -ReaderType $MandatoryLabelReaderType `
                    -RequireInheritance)
            ) { return $false }
        }
        $ExpectedFiles = @($Manifest.runtime_files)
        $ActualFiles = @(Get-ChildItem -LiteralPath $RuntimeDir -File -Recurse -Force)
        if ($ExpectedFiles.Count -ne $ActualFiles.Count -or $ExpectedFiles.Count -lt 1) {
            return $false
        }
        $RuntimePrefix = $RuntimeDir.TrimEnd('\') + '\'
        $Seen = New-Object 'Collections.Generic.HashSet[string]' (
            [StringComparer]::OrdinalIgnoreCase
        )
        $CanonicalEntries = New-Object 'Collections.Generic.List[object]'
        foreach ($Entry in $ExpectedFiles) {
            if (
                -not (Test-ExactJsonProperties `
                    -Value $Entry `
                    -Expected @('path', 'sha256', 'size')) -or
                [string]$Entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [int64]$Entry.size -lt 0
            ) { return $false }
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
            ) { return $false }
            $Candidate = [IO.Path]::GetFullPath(
                (Join-Path $RuntimeDir ($Relative.Replace('/', '\')))
            )
            if (
                -not $Candidate.StartsWith(
                    $RuntimePrefix,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not (Test-Path -LiteralPath $Candidate -PathType Leaf) -or
                (Get-Item -LiteralPath $Candidate -Force).Attributes -band
                    [IO.FileAttributes]::ReparsePoint -or
                -not (Test-ProtectedReleaseAcl `
                    -LiteralPath $Candidate `
                    -ExecutionSid $ExecutionSid) -or
                -not (Test-HighIntegrityLabel `
                    -LiteralPath $Candidate `
                    -ReaderType $MandatoryLabelReaderType) -or
                (Get-Item -LiteralPath $Candidate -Force).Length -ne [int64]$Entry.size -or
                (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash.ToLowerInvariant() `
                    -cne [string]$Entry.sha256
            ) { return $false }
            [void]$CanonicalEntries.Add([ordered]@{
                path = $Relative
                sha256 = [string]$Entry.sha256
                size = [int64]$Entry.size
            })
        }
        $RuntimeReceipt = [ordered]@{
            files = $CanonicalEntries.ToArray()
            format = 'TenderBot.LiveInbound.RuntimeTree.v1'
        } | ConvertTo-Json -Compress -Depth 5
        $Hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $ComputedSha256 = ([BitConverter]::ToString(
                $Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($RuntimeReceipt))
            )).Replace('-', '').ToLowerInvariant()
        } finally {
            $Hasher.Dispose()
        }
        return $ComputedSha256 -ceq $RuntimeSha256
    } catch {
        return $false
    }
}

function Get-LiveInboundAuthorityObservation {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimePath,
        [Parameter(Mandatory = $true)][string]$DatabasePath
    )
    $Unknown = [pscustomobject]@{
        authority_generation = 0
        authority_mode = 'UNKNOWN'
        authority_state = 'UNKNOWN'
        external_writes_enabled = $null
        release_sha256 = ''
        revoked_by_release_sha256 = ''
        revoked_by_runtime_sha256 = ''
        runtime_sha256 = ''
    }
$AuthorityProbeSource = @'
import hashlib
import json
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timezone

V4_OBJECTS = frozenset({
    "meta", "cursor", "scoped_authority", "messages",
    "idx_messages_state", "idx_messages_mid", "message_deliveries",
    "legacy_message_state", "crm_outbox", "idx_crm_outbox_state",
    "crm_delivery_outbox", "idx_crm_delivery_outbox_state", "runs",
    "idx_runs_started",
})
V3_OBJECTS = V4_OBJECTS - {
    "crm_delivery_outbox", "idx_crm_delivery_outbox_state",
}
SCHEMA_CONTRACTS = {
    "3": frozenset({
        "95aba4076a659a7108c5bfb7f1299256c0fb371d5495c4f8d3a37fe96b156a5b",
        "3d394942d6ffcf7cf681b92a545b0e8238f9063587561104098347a765f914a3",
    }),
    "4": frozenset({
        "532bb07f870d69d840b9b0c27fb5627b9987c6b4cd9dbb3837558868c8f93f23",
        "bcfa740fb1cef0e5b79ce3c8e3ac23fce61e12671a7a7e5261bbb0fbefb22583",
        "69b355bfb7ee11f0cdd1ce38095707118e062cc878c5b35835d6a99be6374365",
    }),
}
OBSERVER_AUTHORITY_VERSION = "NativeBitrixMailObserver.v1"
OBSERVER_CONFIRMATION_HASH = hashlib.sha256(
    b"NATIVE-BITRIX-MAIL-PRIMARY-OBSERVER-V1"
).hexdigest()

def emit(state="UNKNOWN", **values):
    payload = {
        "authority_generation": 0,
        "authority_mode": "UNKNOWN",
        "authority_state": state,
        "external_writes_enabled": None,
        "release_sha256": "",
        "revoked_by_release_sha256": "",
        "revoked_by_runtime_sha256": "",
        "runtime_sha256": "",
    }
    payload.update(values)
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))

def valid_hash(value):
    value = str(value)
    return bool(
        re.fullmatch(r"[0-9a-f]{64}", value)
        and any(character != "0" for character in value)
    )

def utc_timestamp(value):
    if type(value) is not str or not value.strip():
        raise ValueError("timestamp is unavailable")
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)

def schema_contract(connection, object_names):
    selected = tuple(sorted(object_names))
    placeholders = ",".join("?" for _ in selected)
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name IN (" + placeholders + ") ORDER BY type,name",
        selected,
    ).fetchall()
    contract = [
        {
            "name": str(row[1]),
            "sql": re.sub(r"\s+", " ", str(row[3] or "").strip()),
            "table": str(row[2]),
            "type": str(row[0]),
        }
        for row in rows
    ]
    material = json.dumps(
        contract, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

def revocation_receipt(meta, expected_generation=None):
    keys = {
        "authority_generation_counter", "authority_revocation_fence",
        "authority_last_revoked_at_utc", "authority_last_revoked_generation",
        "authority_last_revoked_by_release_sha256",
        "authority_last_revoked_by_runtime_sha256",
    }
    present = keys.intersection(meta)
    if not present:
        return "ABSENT", None
    if not keys.issubset(meta):
        return "INVALID", None
    try:
        counter = int(meta["authority_generation_counter"])
        fence = int(meta["authority_revocation_fence"])
        generation = int(meta["authority_last_revoked_generation"])
    except (TypeError, ValueError):
        return "INVALID", None
    release = str(meta["authority_last_revoked_by_release_sha256"])
    runtime = str(meta["authority_last_revoked_by_runtime_sha256"])
    if (
        generation < 1 or counter != generation or fence < 1
        or (expected_generation is not None and generation != expected_generation)
        or not str(meta["authority_last_revoked_at_utc"])
        or not valid_hash(release) or not valid_hash(runtime)
    ):
        return "INVALID", None
    return "VALID", {
        "generation": generation,
        "release": release,
        "runtime": runtime,
    }

database = pathlib.Path(sys.argv[1])
if not database.is_file():
    emit("ABSENT")
    raise SystemExit(0)
wal = pathlib.Path(str(database) + "-wal")
if wal.is_file() and wal.stat().st_size:
    emit("UNKNOWN")
    raise SystemExit(0)
try:
    connection = sqlite3.connect(
        database.resolve().as_uri() + "?mode=ro&immutable=1",
        uri=True,
        timeout=1,
    )
    connection.execute("PRAGMA query_only=ON")
    integrity = connection.execute("PRAGMA quick_check").fetchone()
    if not integrity or integrity[0] != "ok":
        emit("UNKNOWN")
        raise SystemExit(0)
    meta = dict(connection.execute("SELECT key,value FROM meta").fetchall())
    schema_version = str(meta.get("schema_version", ""))
    expected_objects = {"3": V3_OBJECTS, "4": V4_OBJECTS}.get(schema_version)
    if expected_objects is None:
        emit("UNKNOWN")
        raise SystemExit(0)
    actual_objects = frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type IN ('table','index','trigger','view') "
            "AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    )
    contract = schema_contract(connection, expected_objects)
    if (
        actual_objects != expected_objects
        or contract not in SCHEMA_CONTRACTS[schema_version]
        or (
            schema_version == "4"
            and str(meta.get("schema_contract_sha256", "")) != contract
        )
    ):
        emit("UNKNOWN")
        raise SystemExit(0)
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(scoped_authority)")
    }
    inbound_capability_columns = {
        "imap_inbox_read", "bitrix_lead_list", "bitrix_lead_add", "bitrix_lead_get",
    }
    if schema_version == "4":
        inbound_capability_columns |= {
            "bitrix_activity_list", "bitrix_activity_add", "bitrix_activity_get",
            "bitrix_timeline_comment_list", "bitrix_timeline_comment_add",
            "bitrix_timeline_comment_get",
        }
    outbound_capability_columns = {
        "smtp_send", "unisender_send", "tenderplan_access",
    }
    capability_columns = inbound_capability_columns | outbound_capability_columns
    required = capability_columns | {
        "singleton", "authority_version", "authority_generation",
        "authority_state", "release_sha256", "runtime_sha256",
        "revoked_at_utc", "revoked_by_release_sha256",
        "revoked_by_runtime_sha256", "confirmation_hash",
        "connection_scope_hash", "mailbox_scope_hash", "bitrix_scope_hash",
        "authority_expires_at_utc", "write_attempt_budget", "write_attempts_used",
    }
    if not required.issubset(columns):
        emit("UNKNOWN")
        raise SystemExit(0)
    selected = [
        "authority_version", "authority_generation", "authority_state",
        "release_sha256", "runtime_sha256", "revoked_at_utc",
        "revoked_by_release_sha256", "revoked_by_runtime_sha256",
        "confirmation_hash", "connection_scope_hash", "mailbox_scope_hash",
        "bitrix_scope_hash", "authority_expires_at_utc", "write_attempt_budget",
        "write_attempts_used",
    ] + sorted(capability_columns)
    rows = connection.execute(
        "SELECT " + ",".join(selected) +
        " FROM scoped_authority WHERE singleton=1"
    ).fetchall()
    if not rows:
        receipt_state, receipt = revocation_receipt(meta)
        if receipt_state == "ABSENT":
            emit("ABSENT")
            raise SystemExit(0)
        if receipt_state != "VALID":
            emit("UNKNOWN")
            raise SystemExit(0)
        emit(
            "REVOKED_NO_GRANT" if schema_version == "4" else "REVOKED_LEGACY_STORE",
            authority_generation=receipt["generation"],
            revoked_by_release_sha256=receipt["release"],
            revoked_by_runtime_sha256=receipt["runtime"],
        )
        raise SystemExit(0)
    if len(rows) != 1:
        emit("UNKNOWN")
        raise SystemExit(0)
    values = dict(zip(selected, rows[0]))
    state = str(values["authority_state"])
    authority_version = str(values["authority_version"])
    writer_authority_version = "MailToBitrixInbound.v" + schema_version
    generation = values["authority_generation"]
    hashes = (
        str(values["release_sha256"]), str(values["runtime_sha256"]),
        str(values["revoked_by_release_sha256"]),
        str(values["revoked_by_runtime_sha256"]),
    )
    if (
        state not in {"ACTIVE", "REVOKED"}
        or authority_version not in {
            writer_authority_version,
            OBSERVER_AUTHORITY_VERSION,
        }
        or type(generation) is not int or generation < 1
        or any(value and not valid_hash(value) for value in hashes)
    ):
        emit("UNKNOWN")
        raise SystemExit(0)
    capabilities = {name: values[name] for name in capability_columns}
    if any(type(value) is not int or value not in {0, 1} for value in capabilities.values()):
        emit("UNKNOWN")
        raise SystemExit(0)
    budget = values["write_attempt_budget"]
    used = values["write_attempts_used"]
    if (
        type(budget) is not int or type(used) is not int
        or budget < 0 or used < 0 or used > budget
    ):
        emit("UNKNOWN")
        raise SystemExit(0)
    if state == "REVOKED" and (
        any(capabilities.values()) or not str(values["revoked_at_utc"])
    ):
        emit("UNKNOWN")
        raise SystemExit(0)
    if state == "REVOKED":
        receipt_state, receipt = revocation_receipt(meta, generation)
        if receipt_state != "VALID":
            emit("UNKNOWN")
            raise SystemExit(0)
        hashes = (hashes[0], hashes[1], receipt["release"], receipt["runtime"])
    if state == "ACTIVE":
        if authority_version == writer_authority_version:
            emit(
                "UNKNOWN",
                authority_generation=generation,
                authority_mode="WRITER_V4_BLOCKED",
                external_writes_enabled=True,
                release_sha256=hashes[0],
                runtime_sha256=hashes[1],
            )
            raise SystemExit(0)
        observer_enabled = {
            "imap_inbox_read", "bitrix_activity_list", "bitrix_activity_get",
        }
        observer_expires_at = utc_timestamp(values["authority_expires_at_utc"])
        observed_now = datetime.now(timezone.utc)
        if (
            schema_version != "4"
            or any(
                capabilities[name] != int(name in observer_enabled)
                for name in capability_columns
            )
            or str(values["revoked_at_utc"])
            or any(hashes[index] for index in (2, 3))
            or not valid_hash(hashes[0]) or not valid_hash(hashes[1])
            or str(values["confirmation_hash"]) != OBSERVER_CONFIRMATION_HASH
            or any(
                not valid_hash(values[name])
                for name in (
                    "connection_scope_hash", "mailbox_scope_hash", "bitrix_scope_hash",
                )
            )
            or observer_expires_at <= observed_now
            or budget != 0 or used != 0
        ):
            emit("UNKNOWN")
            raise SystemExit(0)
    emit(
        "REVOKED_LEGACY_STORE" if state == "REVOKED" and schema_version == "3" else state,
        authority_generation=generation,
        authority_mode=(
            "NATIVE_BITRIX_MAIL_OBSERVER" if state == "ACTIVE" else "REVOKED"
        ),
        external_writes_enabled=False,
        release_sha256=hashes[0],
        runtime_sha256=hashes[1],
        revoked_by_release_sha256=hashes[2],
        revoked_by_runtime_sha256=hashes[3],
    )
except SystemExit:
    raise
except Exception:
    emit("UNKNOWN")
finally:
    try:
        connection.close()
    except Exception:
        pass
'@
    try {
        $ProbePayload = [Convert]::ToBase64String(
            [Text.Encoding]::UTF8.GetBytes($AuthorityProbeSource)
        )
        if ($ProbePayload.Length -lt 1 -or $ProbePayload.Length -gt 24000) {
            return $Unknown
        }
        $ProbeLoader = (
            "import base64,sys;" +
            "payload=base64.b64decode(sys.argv.pop(1),validate=True);" +
            "exec(compile(payload,'<authority-probe>','exec'))"
        )
        $Raw = & $RuntimePath -I -S -B -c `
            $ProbeLoader $ProbePayload $DatabasePath 2>$null
        if ($LASTEXITCODE -ne 0) { return $Unknown }
        $Observed = (@($Raw) -join [Environment]::NewLine) |
            ConvertFrom-Json -ErrorAction Stop
        if ([string]$Observed.authority_state -cnotin @(
            'ABSENT', 'ACTIVE', 'REVOKED', 'REVOKED_NO_GRANT',
            'REVOKED_LEGACY_STORE', 'UNKNOWN'
        )) { return $Unknown }
        return $Observed
    } catch {
        return $Unknown
    }
}

$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$StateDir = [IO.Path]::GetFullPath(
    (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.tenderbot\live_inbound')
)
$LiveInboundRoot = [IO.Path]::GetFullPath(
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound')
)
$ReleaseRoot = [IO.Path]::GetFullPath(
    (Join-Path $LiveInboundRoot 'releases')
)
$RequestRoot = [IO.Path]::GetFullPath(
    (Join-Path $LiveInboundRoot 'requests')
)
$PowerShellPath = Join-Path $SystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'

$TaskMatches = @(
    Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue
)
$TaskIdentityUnambiguous = (
    $TaskMatches.Count -eq 1 -and [string]$TaskMatches[0].TaskPath -ceq '\'
)
$InitialTaskAclVerified = $false
$InitialDescription = ''
$InitialDescriptionMarker = $null
if ($TaskIdentityUnambiguous) {
    try {
        $InitialScheduler = New-Object -ComObject 'Schedule.Service'
        $InitialScheduler.Connect()
        $InitialRegisteredCom = $InitialScheduler.GetFolder('\').GetTask("\$TaskName")
        $InitialTaskAclVerified = Test-TaskSecurityDescriptor `
            -Sddl $InitialRegisteredCom.GetSecurityDescriptor(0x07) `
            -ExecutionSid $CurrentSid
    } catch {
        $InitialTaskAclVerified = $false
    }
    if ($InitialTaskAclVerified) {
        # The description is not read until the exact protected task DACL is known.
        $InitialDescription = [string]$TaskMatches[0].Description
        $InitialDescriptionMarker = ConvertFrom-LiveInboundTaskDescription `
            -Description $InitialDescription
    }
}

$PreparedReceipt = Get-LatestPreparedReleaseReceipt `
    -RequestRoot $RequestRoot `
    -ReleaseRoot $ReleaseRoot `
    -ExecutionSid $CurrentSid
$PreparedReceiptConsumedByFinalTask = (
    $null -ne $PreparedReceipt -and
    $null -ne $InitialDescriptionMarker -and
    [int]$InitialDescriptionMarker.Version -eq 4 -and
    [string]$InitialDescriptionMarker.ReleaseSha256 -ceq
        [string]$PreparedReceipt.ReleaseSha256 -and
    [string]$InitialDescriptionMarker.RuntimeSha256 -ceq
        [string]$PreparedReceipt.RuntimeSha256 -and
    [string]$InitialDescriptionMarker.ManifestSha256 -ceq
        [string]$PreparedReceipt.ManifestSha256 -and
    [string]$InitialDescriptionMarker.ArtifactSha256 -ceq
        [string]$PreparedReceipt.ArtifactSha256 -and
    [string]$InitialDescriptionMarker.StatusScriptSha256 -ceq
        [string]$PreparedReceipt.StatusScriptSha256 -and
    [string]$InitialDescriptionMarker.MandatoryLabelReaderSha256 -ceq
        [string]$PreparedReceipt.MandatoryLabelReaderSha256 -and
    [int]$InitialDescriptionMarker.IntervalSeconds -eq
        [int]$PreparedReceipt.IntervalSeconds
)
if ($null -ne $PreparedReceipt -and -not $PreparedReceiptConsumedByFinalTask) {
    [ordered]@{
        authority_state = 'UNKNOWN'
        configuration_verified = $false
        installed = $TaskMatches.Count -gt 0
        legacy_task_present = $TaskMatches.Count -gt 0
        mandatory_label_reader_sha256 = (
            [string]$PreparedReceipt.MandatoryLabelReaderSha256
        )
        phase = 'PREPARED_PENDING'
        prepared_release_sha256 = [string]$PreparedReceipt.ReleaseSha256
        running = $false
        status_script_sha256 = [string]$PreparedReceipt.StatusScriptSha256
        status = 'prepared_pending_revoke'
        task_name = $TaskName
    } | ConvertTo-Json -Compress
    exit 4
}

if ($TaskMatches.Count -eq 0) {
    [ordered]@{
        authority_state = 'UNKNOWN'
        configuration_verified = $false
        installed = $false
        phase = 'ABSENT'
        prepared_release_sha256 = ''
        running = $false
        status = 'not_installed'
        task_name = $TaskName
    } | ConvertTo-Json -Compress
    exit 1
}

if (-not $TaskIdentityUnambiguous -or -not $InitialTaskAclVerified) {
    [ordered]@{
        authority_state = 'UNKNOWN'
        configuration_verified = $false
        initial_task_acl_verified = $InitialTaskAclVerified
        installed = $true
        release_pinned = $false
        running = $false
        status = 'configuration_mismatch'
        task_acl_verified = $false
        task_name = $TaskName
    } | ConvertTo-Json -Compress
    exit 2
}

# Description is security-sensitive input. It is read only after the task's COM DACL
# has been independently verified above.
$Task = $TaskMatches[0]
$Description = $InitialDescription
$DescriptionMarker = $InitialDescriptionMarker
$TaskMarkerVersion = if ($null -ne $DescriptionMarker) {
    [int]$DescriptionMarker.Version
} else { 0 }
$DescriptionVerified = $null -ne $DescriptionMarker -and $TaskMarkerVersion -eq 4
$ReleaseSha256 = if ($null -ne $DescriptionMarker) {
    [string]$DescriptionMarker.ReleaseSha256
} else { '' }
$RuntimeSha256 = if ($null -ne $DescriptionMarker) {
    [string]$DescriptionMarker.RuntimeSha256
} else { '' }
$ManifestSha256 = if ($null -ne $DescriptionMarker) {
    [string]$DescriptionMarker.ManifestSha256
} else { '' }
$ArtifactSha256 = if ($null -ne $DescriptionMarker) {
    [string]$DescriptionMarker.ArtifactSha256
} else { '' }
$StatusScriptSha256 = if ($DescriptionVerified) {
    [string]$DescriptionMarker.StatusScriptSha256
} else { '' }
$MandatoryLabelReaderSha256 = if ($DescriptionVerified) {
    [string]$DescriptionMarker.MandatoryLabelReaderSha256
} else { '' }
$IntervalSeconds = if ($null -ne $DescriptionMarker) {
    [int]$DescriptionMarker.IntervalSeconds
} else { 0 }

if (-not $DescriptionVerified) {
    $LegacyRunning = $false
    $LegacyState = 'Unknown'
    try {
        $LegacyRunning = [string]$Task.State -ceq 'Running'
        $LegacyState = [string]$Task.State
    } catch {
        $LegacyRunning = $false
    }
    [ordered]@{
        authority_state = 'UNKNOWN'
        configuration_verified = $false
        description_verified = $false
        initial_task_acl_verified = $InitialTaskAclVerified
        installed = $true
        legacy_runtime_status = 'configuration_unverified'
        mandatory_label_reader_sha256 = ''
        release_pinned = $false
        release_sha256 = $ReleaseSha256
        running = $LegacyRunning
        state = $LegacyState
        status = 'configuration_mismatch'
        status_script_sha256 = ''
        task_acl_verified = $InitialTaskAclVerified
        task_marker_version = $TaskMarkerVersion
        task_name = $TaskName
        task_upgrade_recommended = $TaskMarkerVersion -eq 3
    } | ConvertTo-Json -Compress
    exit 2
}

$ReleaseDir = [IO.Path]::GetFullPath((Join-Path $ReleaseRoot $ReleaseSha256))
$ManifestPath = Join-Path $ReleaseDir 'release.json'
$ArtifactPath = Join-Path $ReleaseDir 'live-inbound.pyz'
$RuntimePath = Join-Path $ReleaseDir 'runtime\python.exe'
$LauncherPath = Join-Path $ReleaseDir 'verify-and-run.ps1'
$StatusPath = Join-Path $ReleaseDir 'read-status.ps1'
$MandatoryLabelReaderPath = Join-Path $ReleaseDir 'mandatory-label-reader.dll'
$ExpectedTopLevel = @(
    'live-inbound.pyz',
    'mandatory-label-reader.dll',
    'read-status.ps1',
    'release.json',
    'runtime',
    'verify-and-run.ps1'
)

$ManifestVerified = $false
$ArtifactVerified = $false
$StatusScriptVerified = $false
$MandatoryLabelReaderVerified = $false
$ReleaseDirectoryShapeVerified = $false
$ReleaseDaclVerified = $false
$ReleaseMicVerified = $false
$ReleaseAclVerified = $false
$RuntimeProbeVerified = $false
$MandatoryLabelReaderType = $null
$ProtectedStatusPathVerified = $false
try {
    $ProtectedStatusPathVerified = (
        -not [string]::IsNullOrWhiteSpace($PSCommandPath) -and
        [IO.Path]::GetFullPath($PSCommandPath) -ceq
            [IO.Path]::GetFullPath($StatusPath)
    )
} catch {
    $ProtectedStatusPathVerified = $false
}

if ($ProtectedStatusPathVerified) {
    try {
        $TopLevel = @(Get-ChildItem -LiteralPath $ReleaseDir -Force)
        $ReleaseDirectoryShapeVerified = (
            (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -and
            (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) -and
            (Test-Path -LiteralPath $RuntimePath -PathType Leaf) -and
            (Test-Path -LiteralPath $LauncherPath -PathType Leaf) -and
            (Test-Path -LiteralPath $StatusPath -PathType Leaf) -and
            (Test-Path -LiteralPath $MandatoryLabelReaderPath -PathType Leaf) -and
            $TopLevel.Count -eq $ExpectedTopLevel.Count -and
            @(Compare-Object `
                -ReferenceObject $ExpectedTopLevel `
                -DifferenceObject @($TopLevel.Name) `
                -CaseSensitive).Count -eq 0
        )
        $ReleaseDaclVerified = $ReleaseDirectoryShapeVerified
        $ProtectedReleasePaths = @(
            (Join-Path $ProgramFilesDirectory 'TenderBot'),
            $LiveInboundRoot,
            $ReleaseRoot,
            $ReleaseDir
        )
        foreach ($ProtectedPath in @($ProtectedReleasePaths) + @($TopLevel.FullName)) {
            if (-not (Test-ProtectedReleaseAcl `
                -LiteralPath $ProtectedPath `
                -ExecutionSid $CurrentSid)) {
                $ReleaseDaclVerified = $false
                break
            }
        }
        if ($ReleaseDaclVerified) {
            $StatusBytes = [byte[]](Read-ExactFileBytes `
                -LiteralPath $StatusPath `
                -MaximumBytes 4MB)
            $ReaderBytes = [byte[]](Read-ExactFileBytes `
                -LiteralPath $MandatoryLabelReaderPath `
                -MaximumBytes 1MB)
            $StatusScriptVerified = (
                (Get-Sha256HexFromBytes -Bytes $StatusBytes) -ceq
                    $StatusScriptSha256
            )
            $ReaderBytesVerified = (
                (Get-Sha256HexFromBytes -Bytes $ReaderBytes) -ceq
                    $MandatoryLabelReaderSha256
            )
            if ($StatusScriptVerified -and $ReaderBytesVerified) {
                $MandatoryLabelReaderType = Import-PinnedMandatoryLabelReader `
                    -LiteralPath $MandatoryLabelReaderPath `
                    -ExpectedSha256 $MandatoryLabelReaderSha256
                $MandatoryLabelReaderVerified = $true
            }
        }
        if ($MandatoryLabelReaderVerified) {
            $ReleaseMicVerified = $true
            foreach ($ProtectedDirectory in $ProtectedReleasePaths) {
                if (-not (Test-HighIntegrityLabel `
                    -LiteralPath $ProtectedDirectory `
                    -ReaderType $MandatoryLabelReaderType `
                    -RequireInheritance)) {
                    $ReleaseMicVerified = $false
                    break
                }
            }
            if ($ReleaseMicVerified) {
                foreach ($Item in $TopLevel) {
                    if (-not (Test-HighIntegrityLabel `
                        -LiteralPath $Item.FullName `
                        -ReaderType $MandatoryLabelReaderType `
                        -RequireInheritance:$Item.PSIsContainer)) {
                        $ReleaseMicVerified = $false
                        break
                    }
                }
            }
        }
        $ReleaseAclVerified = $ReleaseDaclVerified -and $ReleaseMicVerified
    } catch {
        $MandatoryLabelReaderVerified = $false
        $ReleaseAclVerified = $false
        $ReleaseMicVerified = $false
    }
}

if (
    $ProtectedStatusPathVerified -and
    $StatusScriptVerified -and
    $MandatoryLabelReaderVerified -and
    $ReleaseAclVerified
) {
    try {
        $ManifestBytes = [byte[]](Read-ExactFileBytes `
            -LiteralPath $ManifestPath `
            -MaximumBytes 4MB)
        $ManifestHashVerified = (
            (Get-Sha256HexFromBytes -Bytes $ManifestBytes) -ceq $ManifestSha256
        )
        $Manifest = (New-Object Text.UTF8Encoding($false, $true)).GetString(
            $ManifestBytes
        ) | ConvertFrom-Json -ErrorAction Stop
        $ManifestContractVerified = (
            $ManifestHashVerified -and
            (Test-ExactJsonProperties -Value $Manifest -Expected @(
                'artifact',
                'artifact_sha256',
                'format',
                'installer_sha256',
                'launcher',
                'launcher_sha256',
                'mandatory_label_reader',
                'mandatory_label_reader_sha256',
                'python_version',
                'release_sha256',
                'runtime_dependency_contract',
                'runtime_executable',
                'runtime_files',
                'runtime_sha256',
                'source_provenance',
                'source_sha256',
                'status_script',
                'status_script_sha256'
            )) -and
            [string]$Manifest.format -ceq 'TenderBot.LiveInbound.Release.v2' -and
            [string]$Manifest.release_sha256 -ceq $ReleaseSha256 -and
            [string]$Manifest.runtime_sha256 -ceq $RuntimeSha256 -and
            [string]$Manifest.artifact -ceq 'live-inbound.pyz' -and
            [string]$Manifest.artifact_sha256 -ceq $ArtifactSha256 -and
            [string]$Manifest.launcher -ceq 'verify-and-run.ps1' -and
            [string]$Manifest.launcher_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$Manifest.status_script -ceq 'read-status.ps1' -and
            [string]$Manifest.status_script_sha256 -ceq $StatusScriptSha256 -and
            [string]$Manifest.mandatory_label_reader -ceq
                'mandatory-label-reader.dll' -and
            [string]$Manifest.mandatory_label_reader_sha256 -ceq
                $MandatoryLabelReaderSha256 -and
            [string]$Manifest.installer_sha256 -cmatch '^[0-9a-f]{64}$' -and
            [string]$Manifest.python_version -cmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -and
            [string]$Manifest.runtime_executable -ceq 'runtime/python.exe' -and
            [string]$Manifest.runtime_dependency_contract -ceq
                'cpython-stdlib-copy-no-site-v2'
        )
        if ($ManifestContractVerified) {
            $ObservedArtifactSha256 = (
                Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $ObservedLauncherSha256 = (
                Get-FileHash -LiteralPath $LauncherPath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $ArtifactVerified = $ObservedArtifactSha256 -ceq $ArtifactSha256
            $LauncherVerified = (
                $ObservedLauncherSha256 -ceq [string]$Manifest.launcher_sha256
            )
            $ManifestVerified = $LauncherVerified
        }
        if ($ManifestVerified -and $ArtifactVerified) {
            $RuntimeProbeVerified = Test-LiveInboundRuntimePayload `
                -RuntimeDir (Join-Path $ReleaseDir 'runtime') `
                -Manifest $Manifest `
                -RuntimeSha256 $RuntimeSha256 `
                -ExecutionSid $CurrentSid `
                -MandatoryLabelReaderType $MandatoryLabelReaderType
        }
    } catch {
        $ManifestVerified = $false
        $ArtifactVerified = $false
        $RuntimeProbeVerified = $false
    }
}

$ActionArguments = (
    "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass " +
    "-File `"$LauncherPath`" " +
    "-ReleaseSha256 $ReleaseSha256 -RuntimeSha256 $RuntimeSha256 " +
    "-ManifestSha256 $ManifestSha256 -ArtifactSha256 $ArtifactSha256 " +
    "-MandatoryLabelReaderSha256 $MandatoryLabelReaderSha256 " +
    "-ExpectedSid $CurrentSid -StateDir `"$StateDir`" " +
    "-IntervalSeconds $IntervalSeconds -Command serve"
)
$FinalTaskMatches = @(
    Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue
)
$FinalTaskPresent = (
    $FinalTaskMatches.Count -eq 1 -and
    [string]$FinalTaskMatches[0].TaskPath -ceq '\'
)
$TaskAclVerified = $false
$TaskStable = $false
$ActionVerified = $false
$PrincipalVerified = $false
$LogonTriggerVerified = $false
$SettingsVerified = $false
$TaskInfoVerified = $false
$Info = $null
$Running = $false
$TaskEnabled = $false
$FinalState = 'Missing'
$LastTaskResult = $null
if ($FinalTaskPresent) {
    $Task = $FinalTaskMatches[0]
    try {
        $FinalScheduler = New-Object -ComObject 'Schedule.Service'
        $FinalScheduler.Connect()
        $FinalRegisteredCom = $FinalScheduler.GetFolder('\').GetTask("\$TaskName")
        $TaskAclVerified = Test-TaskSecurityDescriptor `
            -Sddl $FinalRegisteredCom.GetSecurityDescriptor(0x07) `
            -ExecutionSid $CurrentSid
    } catch {
        $TaskAclVerified = $false
    }
    if ($TaskAclVerified) {
        $TaskStable = [string]$Task.Description -ceq $Description
        try {
            $Actions = @($Task.Actions)
            $Action = if ($Actions.Count -eq 1) { $Actions[0] } else { $null }
            $ActionVerified = (
                $TaskStable -and $null -ne $Action -and
                ([string]$Action.Execute).Equals(
                    $PowerShellPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                ([string]$Action.WorkingDirectory).Equals(
                    $ReleaseDir,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                [string]$Action.Arguments -ceq $ActionArguments
            )
            try {
                $PrincipalSid = Resolve-SidValue `
                    -IdentityReference $Task.Principal.UserId
            } catch {
                $PrincipalSid = ''
            }
            $PrincipalVerified = (
                $PrincipalSid -ceq $CurrentSid -and
                ([string]$Task.Principal.LogonType -in @(
                    'Interactive',
                    'InteractiveToken'
                )) -and
                [string]$Task.Principal.RunLevel -eq 'Limited'
            )
            $Triggers = @($Task.Triggers)
            $LogonTriggerVerified = $Triggers.Count -eq 1
            foreach ($Trigger in $Triggers) {
                if ($Trigger.CimClass.CimClassName -cne 'MSFT_TaskLogonTrigger') {
                    $LogonTriggerVerified = $false
                    continue
                }
                try {
                    $TriggerSid = Resolve-SidValue -IdentityReference $Trigger.UserId
                } catch {
                    $TriggerSid = ''
                }
                if ($TriggerSid -cne $CurrentSid) {
                    $LogonTriggerVerified = $false
                }
            }
            $SettingsVerified = (
                [bool]$Task.Settings.Hidden -and
                [bool]$Task.Settings.StartWhenAvailable -and
                -not [bool]$Task.Settings.DisallowStartIfOnBatteries -and
                -not [bool]$Task.Settings.StopIfGoingOnBatteries -and
                [string]$Task.Settings.MultipleInstances -eq 'IgnoreNew' -and
                [string]$Task.Settings.ExecutionTimeLimit -eq 'PT0S' -and
                [int]$Task.Settings.RestartCount -eq 999 -and
                [string]$Task.Settings.RestartInterval -eq 'PT1M'
            )
            $Info = Get-ScheduledTaskInfo `
                -TaskPath '\' `
                -TaskName $TaskName `
                -ErrorAction Stop
            $TaskInfoVerified = $true
            $Running = [string]$Task.State -ceq 'Running'
            $TaskEnabled = [bool]$Task.Settings.Enabled
            $FinalState = [string]$Task.State
            $LastTaskResult = $Info.LastTaskResult
        } catch {
            $ActionVerified = $false
            $TaskInfoVerified = $false
        }
    }
}
$PreFinalConfigurationVerified = (
    $DescriptionVerified -and $TaskMarkerVersion -eq 4 -and
    $InitialTaskAclVerified -and $TaskAclVerified -and $TaskStable -and
    $ProtectedStatusPathVerified -and $StatusScriptVerified -and
    $MandatoryLabelReaderVerified -and $ReleaseDirectoryShapeVerified -and
    $ManifestVerified -and $ArtifactVerified -and $ReleaseAclVerified -and
    $RuntimeProbeVerified -and $ActionVerified -and $PrincipalVerified -and
    $LogonTriggerVerified -and $SettingsVerified -and $TaskInfoVerified
)
$ConfigurationVerified = (
    $PreFinalConfigurationVerified -and $FinalTaskPresent
)
$AuthorityObservation = [pscustomobject]@{
    authority_generation = 0
    authority_mode = 'UNKNOWN'
    authority_state = 'UNKNOWN'
    external_writes_enabled = $null
    release_sha256 = ''
    revoked_by_release_sha256 = ''
    revoked_by_runtime_sha256 = ''
    runtime_sha256 = ''
}
if ($ConfigurationVerified -and $RuntimeProbeVerified) {
    $AuthorityObservation = Get-LiveInboundAuthorityObservation `
        -RuntimePath $RuntimePath `
        -DatabasePath (Join-Path $StateDir 'live_mail_bitrix.sqlite3')
}
$AuthorityState = [string]$AuthorityObservation.authority_state
$AuthorityRevoked = $AuthorityState -in @(
    'REVOKED', 'REVOKED_NO_GRANT', 'REVOKED_LEGACY_STORE'
)
$AuthorityBindingVerified = (
    $AuthorityState -ceq 'ACTIVE' -and
    [string]$AuthorityObservation.authority_mode -ceq 'NATIVE_BITRIX_MAIL_OBSERVER' -and
    [object]$AuthorityObservation.external_writes_enabled -eq $false -and
    [string]$AuthorityObservation.release_sha256 -ceq $ReleaseSha256 -and
    [string]$AuthorityObservation.runtime_sha256 -ceq $RuntimeSha256
)
$AuthorityRevocationBindingVerified = (
    $AuthorityRevoked -and
    [string]$AuthorityObservation.revoked_by_release_sha256 -ceq $ReleaseSha256 -and
    [string]$AuthorityObservation.revoked_by_runtime_sha256 -ceq $RuntimeSha256
)
$Status = if (-not $ConfigurationVerified) {
    'configuration_mismatch'
} elseif ($AuthorityState -ceq 'ACTIVE' -and -not $AuthorityBindingVerified) {
    'authority_release_mismatch'
} elseif ($AuthorityState -ceq 'ACTIVE') {
    'observer_active'
} elseif ($AuthorityRevoked -and -not $AuthorityRevocationBindingVerified) {
    'authority_revocation_mismatch'
} elseif ($AuthorityRevoked -and ($Running -or $TaskEnabled)) {
    'authority_task_mismatch'
} elseif ($AuthorityRevoked) {
    'installed_revoked'
} else {
    'authority_unknown'
}
$LastRunTimeUtc = if (
    $null -eq $Info -or $null -eq $Info.LastRunTime -or
    $Info.LastRunTime -eq [datetime]::MinValue
) { $null } else { $Info.LastRunTime.ToUniversalTime().ToString('o') }

[ordered]@{
    action_verified = $ActionVerified
    artifact_sha256 = $ArtifactSha256
    artifact_verified = $ArtifactVerified
    authority_binding_verified = $AuthorityBindingVerified
    authority_generation = [int64]$AuthorityObservation.authority_generation
    authority_mode = [string]$AuthorityObservation.authority_mode
    authority_release_sha256 = [string]$AuthorityObservation.release_sha256
    authority_revocation_binding_verified = $AuthorityRevocationBindingVerified
    authority_revoked_by_release_sha256 = (
        [string]$AuthorityObservation.revoked_by_release_sha256
    )
    authority_revoked_by_runtime_sha256 = (
        [string]$AuthorityObservation.revoked_by_runtime_sha256
    )
    authority_runtime_sha256 = [string]$AuthorityObservation.runtime_sha256
    authority_state = $AuthorityState
    configuration_verified = $ConfigurationVerified
    description_verified = $DescriptionVerified
    external_writes_enabled = [object]$AuthorityObservation.external_writes_enabled
    initial_task_acl_verified = $InitialTaskAclVerified
    installed = $FinalTaskPresent
    last_run_time = $LastRunTimeUtc
    last_task_result = $LastTaskResult
    mandatory_label_reader_sha256 = $MandatoryLabelReaderSha256
    mandatory_label_reader_verified = $MandatoryLabelReaderVerified
    manifest_sha256 = $ManifestSha256
    manifest_verified = $ManifestVerified
    prepared_receipt_consumed_by_final_task = $PreparedReceiptConsumedByFinalTask
    principal_sid_verified = $PrincipalVerified
    protected_status_path_verified = $ProtectedStatusPathVerified
    release_acl_verified = $ReleaseAclVerified
    release_directory_shape_verified = $ReleaseDirectoryShapeVerified
    release_pinned = $DescriptionVerified -and $TaskMarkerVersion -eq 4
    release_sha256 = $ReleaseSha256
    running = $Running
    runtime_probe_verified = $RuntimeProbeVerified
    runtime_sha256 = $RuntimeSha256
    settings_verified = $SettingsVerified
    state = $FinalState
    status_script_sha256 = $StatusScriptSha256
    status_script_verified = $StatusScriptVerified
    legacy_runtime_status = if (-not $ConfigurationVerified) {
        'configuration_unverified'
    } elseif ($Running) {
        'integrity_verified_running'
    } elseif (-not $TaskEnabled) {
        'integrity_verified_disabled'
    } else {
        'integrity_verified_not_running'
    }
    status = $Status
    task_acl_verified = $TaskAclVerified
    task_enabled = $TaskEnabled
    task_info_verified = $TaskInfoVerified
    task_marker_version = $TaskMarkerVersion
    task_name = $TaskName
    task_upgrade_recommended = $TaskMarkerVersion -eq 3
    trigger_sid_verified = $LogonTriggerVerified
} | ConvertTo-Json -Compress

if (-not $ConfigurationVerified) { exit 2 }
if ($Status -in @(
    'authority_release_mismatch', 'authority_revocation_mismatch',
    'authority_task_mismatch', 'authority_unknown'
)) { exit 2 }
if ($Status -ceq 'installed_revoked') { exit 3 }
if (-not $Running) { exit 3 }
