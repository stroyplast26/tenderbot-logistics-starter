#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RequestId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedInstallerSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedReleaseSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedRuntimeSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedManifestSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedArtifactSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedLauncherSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedStatusScriptSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedMandatoryLabelReaderSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedGitHead,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^S-1-')]
    [string]$ExpectedExecutionSid,
    [Parameter(Mandatory = $true)]
    [ValidateSet('PrepareAndQuiesce', 'Commit')]
    [string]$InstallPhase,
    [string]$ExpectedRevocationCorrelationSha256 = '',
    [string]$ExpectedPrepareNonce = '',
    [ValidateRange(30, 3600)]
    [int]$IntervalSeconds = 60
)

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
    $WriterV4Pattern = (
        '^TenderBot Live Inbound v4; release_sha256=(?<release>[0-9a-f]{64}); ' +
        'runtime_sha256=(?<runtime>[0-9a-f]{64}); ' +
        'manifest_sha256=(?<manifest>[0-9a-f]{64}); ' +
        'artifact_sha256=(?<artifact>[0-9a-f]{64}); ' +
        'status_script_sha256=(?<status>[0-9a-f]{64}); ' +
        'mandatory_label_reader_sha256=(?<reader>[0-9a-f]{64}); ' +
        'interval_seconds=(?<interval>[0-9]{2,4})\. ' +
        'IMAP INBOX read-only intake and bounded idempotent Bitrix Lead, operator ' +
        'Todo and mail timeline delivery; local attachment quarantine; no outbound ' +
        'email, no UniSender send, no TenderPlan access\.\z'
    )
    foreach ($Candidate in @(
        [pscustomobject]@{
            Version = 3
            Kind = 'legacy_v3'
            CanonicalInterval = $false
            Pattern = $LegacyPattern
        },
        [pscustomobject]@{
            Version = 4
            Kind = 'legacy_writer_v4'
            CanonicalInterval = $true
            Pattern = $WriterV4Pattern
        },
        [pscustomobject]@{
            Version = 4
            Kind = 'observer_v4'
            CanonicalInterval = $false
            Pattern = $CurrentPattern
        }
    )) {
        $Match = [regex]::Match(
            $Description,
            [string]$Candidate.Pattern,
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $Match.Success) { continue }
        $ParsedInterval = [int]$Match.Groups['interval'].Value
        if ($ParsedInterval -lt 30 -or $ParsedInterval -gt 3600) { return $null }
        if (
            [bool]$Candidate.CanonicalInterval -and
            [string]$Match.Groups['interval'].Value -cne
                $ParsedInterval.ToString([Globalization.CultureInfo]::InvariantCulture)
        ) {
            return $null
        }
        return [pscustomobject]@{
            Version = [int]$Candidate.Version
            Kind = [string]$Candidate.Kind
            ReleaseSha256 = [string]$Match.Groups['release'].Value
            RuntimeSha256 = [string]$Match.Groups['runtime'].Value
            ManifestSha256 = [string]$Match.Groups['manifest'].Value
            ArtifactSha256 = [string]$Match.Groups['artifact'].Value
            StatusScriptSha256 = [string]$Match.Groups['status'].Value
            MandatoryLabelReaderSha256 = [string]$Match.Groups['reader'].Value
            IntervalSeconds = $ParsedInterval
        }
    }
    return $null
}

if ($PSVersionTable.PSEdition -cne 'Desktop') {
    throw 'Run this installer with Windows PowerShell 5.1 (powershell.exe).'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Run this installer with 64-bit Windows PowerShell 5.1.'
}
$env:PSModulePath = "$PSHOME\Modules"
foreach ($TrustedModuleName in @(
    'CimCmdlets',
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
$LocalAppDataDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)
if (
    [string]::IsNullOrWhiteSpace($SystemDirectory) -or
    [string]::IsNullOrWhiteSpace($ProgramFilesDirectory) -or
    [string]::IsNullOrWhiteSpace($LocalAppDataDirectory)
) {
    throw 'Canonical Windows system directories are unavailable.'
}

# These pins deliberately exclude this installer and its medium-integrity wrapper: the
# wrapper embeds this installer's digest, so pinning either one here would form a hash
# cycle. The protected installer path and external self digest bind this file instead.
$TrustedArtifactSha256 = 'fb437bfeedf4f11ae83e44b3c8714194943da4f2638b1dc8cb5c0cab00576416'
$TrustedRuntimeSha256 = '25ccdab4b3f249af8ea5f3fd9ac910a892f5bb28f6dac565b96673009a3c5c02'
$TrustedLauncherSha256 = 'c0895663bacc0aaa1e8cf4453f707b68f01028bfd0f172c156bdf169f7a5cee9'
$TrustedStatusSha256 = '7d62421736d880a5a0b87b1ba59375f790c07982b238ef05c335603c584e41b6'
$TrustedMandatoryLabelReaderSha256 = '83c7b4c72a34e9f74a15ddd0f7f1881df4b51aaa79b89d395d7232819c93d2ee'
$TrustedRuntimeSignerCertificateSha256 = '6045e624888e299179d5ae0ceda57c9874ff6ccf889fa14b2d50f751bfb9e2f8'
$TrustedPythonVersion = '3.11.9'
$TrustedIndependentSources = @(
    [pscustomobject]@{
        Path = 'lead_factory/facade_inquiry_parser.py'
        Sha256 = 'c569eb155800cb1c1e9bdcc45617ba1f31baff3bc0ec6160172d4ae10471bde8'
    },
    [pscustomobject]@{
        Path = 'lead_factory/live_connection_credentials.py'
        Sha256 = 'd132c6ccb4a7d0b74f58396e9b6aca0037236665f6e34def5a7bcce976e26561'
    },
    [pscustomobject]@{
        Path = 'lead_factory/mail_bitrix_projection.py'
        Sha256 = '8ce44273420249fda0c2a5a0cefdb5f9e5c91ce706907517167d96996ed32878'
    },
    [pscustomobject]@{
        Path = 'lead_factory/mail_threading.py'
        Sha256 = 'bb580878fe96e0a625f5049ddb3c1f977ee27e4bfe11567a991d1fc98ffce63e'
    },
    [pscustomobject]@{
        Path = 'lead_factory/live_mail_bitrix.py'
        Sha256 = '6005090d0c80f1de70f063d57889058c5816d8d3cc285f17449a5687a39a2d85'
    },
    [pscustomobject]@{
        Path = 'lead_factory/native_bitrix_mail_observer.py'
        Sha256 = 'cd68fc1404f29064bd1950eaca99893a667b485ea6a92ecc01bfc22146294b80'
    },
    [pscustomobject]@{
        Path = 'scripts/run_live_inbound.py'
        Sha256 = '2934f6b115d6e0e396239b7d7d382501ac42ff474728e8a1335a6c5addb2e627'
    },
    [pscustomobject]@{
        Path = 'scripts/run_native_bitrix_observer.py'
        Sha256 = '0c37cf86c61e319cd6b8a574bbc837f854cbdc308b42c4df37c2e88c64c0c01c'
    },
    [pscustomobject]@{
        Path = 'scripts/live_inbound_launcher.ps1'
        Sha256 = $TrustedLauncherSha256
    },
    [pscustomobject]@{
        Path = 'scripts/build_live_inbound_release.py'
        Sha256 = 'ef949e1b7a50b4fe0a62f02f3798a963653095ebd49c49cc9d8189f7a8cd7e5b'
    },
    [pscustomobject]@{
        Path = 'scripts/live_inbound_task_status.ps1'
        Sha256 = $TrustedStatusSha256
    },
    [pscustomobject]@{
        Path = 'scripts/mandatory_label_reader.cs'
        Sha256 = '7f147fcce1dc4436583228a8c6394d1a27f599405915d6416e95d121db4b0c5a'
    },
    [pscustomobject]@{
        Path = 'scripts/mandatory_label_reader.dll'
        Sha256 = $TrustedMandatoryLabelReaderSha256
    }
)
if (
    $ExpectedArtifactSha256 -cne $TrustedArtifactSha256 -or
    $ExpectedRuntimeSha256 -cne $TrustedRuntimeSha256 -or
    $ExpectedLauncherSha256 -cne $TrustedLauncherSha256 -or
    $ExpectedStatusScriptSha256 -cne $TrustedStatusSha256 -or
    $ExpectedMandatoryLabelReaderSha256 -cne $TrustedMandatoryLabelReaderSha256
) {
    throw 'Caller-supplied release components do not match the immutable admin trust anchor.'
}

function Import-PinnedMandatoryLabelReader {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $Item = Get-Item -LiteralPath $LiteralPath -Force
    if (
        $Item.PSIsContainer -or
        $Item.Length -lt 1 -or
        $Item.Length -gt 1MB -or
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$Item.LinkType)
    ) {
        throw 'Mandatory integrity label reader binary is invalid.'
    }
    $Stream = [IO.File]::Open(
        $Item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if (
            $Stream.Length -ne [int64]$Item.Length -or
            $Stream.Length -lt 1 -or
            $Stream.Length -gt 1MB
        ) {
            throw 'Mandatory integrity label reader size changed while opening.'
        }
        $Bytes = New-Object byte[] ([int]$Stream.Length)
        $Offset = 0
        while ($Offset -lt $Bytes.Length) {
            $Read = $Stream.Read($Bytes, $Offset, $Bytes.Length - $Offset)
            if ($Read -le 0) {
                throw 'Mandatory integrity label reader binary changed while loading.'
            }
            $Offset += $Read
        }
        if ($Stream.ReadByte() -ne -1) {
            throw 'Mandatory integrity label reader binary grew while loading.'
        }
    } finally {
        $Stream.Dispose()
    }
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $ObservedSha256 = ([BitConverter]::ToString(
            $Hasher.ComputeHash($Bytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
    if ($ObservedSha256 -cne $ExpectedSha256) {
        throw 'Mandatory integrity label reader does not match its immutable pin.'
    }
    $Assembly = [Reflection.Assembly]::Load($Bytes)
    $ExpectedTypeName = 'TenderBot.LiveInbound.Security.MandatoryLabelReader'
    $ExpectedAssemblyName = (
        'mandatory_label_reader, Version=1.0.0.0, Culture=neutral, ' +
        'PublicKeyToken=null'
    )
    $Exported = @($Assembly.GetExportedTypes())
    $Reader = $Assembly.GetType($ExpectedTypeName, $true, $false)
    $ReaderMethods = @($Reader.GetMethods(
        [Reflection.BindingFlags]'Public,Static,DeclaredOnly'
    ))
    $ReadParameters = @(
        if ($ReaderMethods.Count -eq 1) {
            $ReaderMethods[0].GetParameters()
        }
    )
    if (
        -not [string]::IsNullOrEmpty([string]$Assembly.Location) -or
        [string]$Assembly.FullName -cne $ExpectedAssemblyName -or
        $Exported.Count -ne 1 -or
        $null -eq $Reader -or
        [string]$Exported[0].FullName -cne $ExpectedTypeName -or
        [string]$Reader.FullName -cne $ExpectedTypeName -or
        -not $Reader.IsAbstract -or
        -not $Reader.IsSealed -or
        $ReaderMethods.Count -ne 1 -or
        [string]$ReaderMethods[0].Name -cne 'Read' -or
        $ReaderMethods[0].ReturnType -ne [string] -or
        $ReaderMethods[0].IsGenericMethod -or
        $ReadParameters.Count -ne 1 -or
        $ReadParameters[0].ParameterType -ne [string]
    ) {
        throw 'Mandatory integrity label reader assembly contract is invalid.'
    }
    return $Reader
}
$TaskName = 'TenderBot Live Inbound'
$TaskMarker = 'TenderBot Live Inbound v4'
$Profile = [Environment]::GetFolderPath('UserProfile')
$StateDir = [IO.Path]::GetFullPath((Join-Path $Profile '.tenderbot\live_inbound'))
$ReleaseRoot = [IO.Path]::GetFullPath(
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\releases')
)
$PowerShellPath = Join-Path $SystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$InstallerRoot = [IO.Path]::GetFullPath(
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\installers')
)
$ExpectedInstallerDir = [IO.Path]::GetFullPath(
    (Join-Path $InstallerRoot $ExpectedInstallerSha256)
)
$ExpectedInstallerPath = [IO.Path]::GetFullPath(
    (Join-Path $ExpectedInstallerDir 'install-live-inbound-admin.ps1')
)
$MandatoryLabelReaderPath = [IO.Path]::GetFullPath(
    (Join-Path $ExpectedInstallerDir 'mandatory-label-reader.dll')
)
$ProtectedRequestRoot = [IO.Path]::GetFullPath(
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound\requests')
)
$ProtectedRequestDir = [IO.Path]::GetFullPath(
    (Join-Path $ProtectedRequestRoot $RequestId)
)
$PrepareReceiptPath = [IO.Path]::GetFullPath(
    (Join-Path $ProtectedRequestDir 'prepare-receipt.json')
)
$PreparedRequestRoot = [IO.Path]::GetFullPath(
    (Join-Path (
        (Join-Path $LocalAppDataDirectory 'TenderBot\LiveInbound\prepared')
    ) $RequestId)
)
$PreparedReleaseDir = [IO.Path]::GetFullPath(
    (Join-Path (Join-Path $PreparedRequestRoot 'releases') $ExpectedReleaseSha256)
)
$ReleaseSha256 = $ExpectedReleaseSha256
$RuntimeSha256 = $ExpectedRuntimeSha256
$ManifestSha256 = $ExpectedManifestSha256
$ArtifactSha256 = $ExpectedArtifactSha256

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

function Assert-ExactJsonProperties {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$ContractName
    )
    if ($null -eq $Value) {
        throw "$ContractName is missing."
    }
    $Observed = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if (
        $Observed.Count -ne $Expected.Count -or
        @(
            Compare-Object `
                -ReferenceObject $Expected `
                -DifferenceObject $Observed `
                -CaseSensitive
        ).Count -ne 0
    ) {
        throw "$ContractName has missing or unexpected fields."
    }
}

function Assert-ProtectedReleaseAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExecutionSid,
        [switch]$Recursive
    )
    $Items = @((Get-Item -LiteralPath $LiteralPath -Force))
    if ($Recursive.IsPresent) {
        $Items += @(Get-ChildItem -LiteralPath $LiteralPath -Force -Recurse)
    }
    $Expected = @{
        'S-1-5-18' = [int64]([Security.AccessControl.FileSystemRights]::FullControl)
        'S-1-5-32-544' = [int64]([Security.AccessControl.FileSystemRights]::FullControl)
        $ExecutionSid = (
            [int64]([Security.AccessControl.FileSystemRights]::ReadAndExecute) -bor
            [int64]([Security.AccessControl.FileSystemRights]::Synchronize)
        )
    }
    foreach ($Item in $Items) {
        if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Release tree contains a reparse point.'
        }
        $Acl = Get-Acl -LiteralPath $Item.FullName
        if (
            (Resolve-SidValue -IdentityReference $Acl.Owner) -cne 'S-1-5-18' -or
            -not $Acl.AreAccessRulesProtected
        ) {
            throw 'Release owner or protected DACL verification failed.'
        }
        $Rules = @($Acl.Access)
        if ($Rules.Count -ne $Expected.Count) {
            throw 'Release DACL contains an unexpected number of ACEs.'
        }
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
                throw 'Release DACL does not match the exact allowlist.'
            }
        }
    }
}

function Protect-ReleasePath {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExecutionSid,
        [switch]$Recursive
    )
    $Items = @((Get-Item -LiteralPath $LiteralPath -Force))
    if ($Recursive.IsPresent) {
        $Items += @(Get-ChildItem -LiteralPath $LiteralPath -Force -Recurse)
    }
    foreach ($Item in $Items) {
        if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Refusing to protect a release tree containing a reparse point.'
        }
    }
    $IcaclsPath = Join-Path $SystemDirectory 'icacls.exe'
    $SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    foreach ($Item in $Items) {
        $OwnerAcl = Get-Acl -LiteralPath $Item.FullName
        if ((Resolve-SidValue -IdentityReference $OwnerAcl.Owner) -cne $SystemSid.Value) {
            $OwnerArguments = @($Item.FullName, '/setowner', '*S-1-5-18')
            & $IcaclsPath @OwnerArguments | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to set SYSTEM as release owner for '$($Item.FullName)'."
            }
            $OwnerReadback = Get-Acl -LiteralPath $Item.FullName
            if (
                (Resolve-SidValue -IdentityReference $OwnerReadback.Owner) -cne
                    $SystemSid.Value
            ) {
                throw "Release owner readback failed for '$($Item.FullName)'."
            }
        }
    }
    $Sections = [Security.AccessControl.AccessControlSections]::Access
    foreach ($Item in $Items) {
        $Inheritance = if ($Item.PSIsContainer) { 'OICI' } else { '' }
        $Sddl = (
            'D:P' +
            "(A;$Inheritance;FA;;;SY)" +
            "(A;$Inheritance;FA;;;BA)" +
            "(A;$Inheritance;FRFX;;;$ExecutionSid)"
        )
        $Acl = if ($Item.PSIsContainer) {
            New-Object Security.AccessControl.DirectorySecurity
        } else {
            New-Object Security.AccessControl.FileSecurity
        }
        $Acl.SetSecurityDescriptorSddlForm($Sddl, $Sections)
        Set-Acl -LiteralPath $Item.FullName -AclObject $Acl
    }
    $IntegrityAlreadyVerified = $false
    try {
        if ($Recursive.IsPresent) {
            Assert-HighIntegrityLabel -LiteralPath $LiteralPath -Recursive
        } else {
            Assert-HighIntegrityLabel -LiteralPath $LiteralPath
        }
        $IntegrityAlreadyVerified = $true
    } catch {
        if (
            [string]$_.Exception.Message -cne
                'Release high-integrity label verification failed.'
        ) {
            throw
        }
    }
    if (-not $IntegrityAlreadyVerified) {
        $IntegrityArguments = @($LiteralPath, '/setintegritylevel', '(OI)(CI)H')
        if ($Recursive.IsPresent) { $IntegrityArguments += '/T' }
        & $IcaclsPath @IntegrityArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set release integrity label for '$LiteralPath'."
        }
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

function Assert-HighIntegrityLabel {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Recursive
    )
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
        if (-not $Verified) {
            throw 'Release high-integrity label verification failed.'
        }
    }
}

function Assert-TaskSecurityDescriptor {
    param(
        [Parameter(Mandatory = $true)][string]$Sddl,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    if (
        $Descriptor.Owner.Value -cne 'S-1-5-32-544' -or
        $Descriptor.Group.Value -cne 'S-1-5-32-544' -or
        -not ($Descriptor.ControlFlags -band
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    ) {
        throw 'Scheduled Task owner or protected DACL verification failed.'
    }
    $Expected = @{
        'S-1-5-18' = 0x1F01FF
        'S-1-5-32-544' = 0x1F01FF
        $ExecutionSid = 0x1200A9
    }
    $Observed = @{}
    $Aces = @($Descriptor.DiscretionaryAcl)
    if ($Aces.Count -ne $Expected.Count) {
        throw 'Scheduled Task DACL contains an unexpected number of ACEs.'
    }
    foreach ($Ace in $Aces) {
        if (
            $Ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
            $Ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
            $Observed.ContainsKey($Ace.SecurityIdentifier.Value)
        ) {
            throw 'Scheduled Task DACL contains an unexpected ACE type.'
        }
        $Observed[$Ace.SecurityIdentifier.Value] = [int]$Ace.AccessMask
    }
    if ($Observed.Count -ne $Expected.Count) {
        throw 'Scheduled Task DACL contains unexpected principals.'
    }
    foreach ($Sid in $Expected.Keys) {
        if (-not $Observed.ContainsKey($Sid) -or $Observed[$Sid] -ne $Expected[$Sid]) {
            throw 'Scheduled Task DACL rights verification failed.'
        }
    }
}

function Assert-MaintenanceTaskSecurityDescriptor {
    param([Parameter(Mandatory = $true)][string]$Sddl)
    $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    if (
        $Descriptor.Owner.Value -cne 'S-1-5-32-544' -or
        $Descriptor.Group.Value -cne 'S-1-5-32-544' -or
        -not ($Descriptor.ControlFlags -band
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
    ) {
        throw 'Maintenance task owner or protected DACL verification failed.'
    }
    $Expected = @{
        'S-1-5-18' = 0x1F01FF
        'S-1-5-32-544' = 0x1F01FF
    }
    $Aces = @($Descriptor.DiscretionaryAcl)
    if ($Aces.Count -ne $Expected.Count) {
        throw 'Maintenance task DACL contains unexpected ACEs.'
    }
    $Seen = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    foreach ($Ace in $Aces) {
        $Sid = $Ace.SecurityIdentifier.Value
        if (
            $Ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
            $Ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
            -not $Expected.ContainsKey($Sid) -or
            -not $Seen.Add($Sid) -or
            [int]$Ace.AccessMask -ne [int]$Expected[$Sid]
        ) {
            throw 'Maintenance task DACL does not match the exact allowlist.'
        }
    }
}

function Get-MaintenanceReservationDescription {
    param([Parameter(Mandatory = $true)][string]$PrepareNonceSha256)
    return (
        'TenderBot Live Inbound v4 maintenance reservation; ' +
        "request_id=$RequestId; prepare_nonce_sha256=$PrepareNonceSha256; " +
        "release_sha256=$ReleaseSha256; manifest_sha256=$ManifestSha256; " +
        "installer_sha256=$ExpectedInstallerSha256."
    )
}

function Assert-MaintenanceReservationTask {
    param(
        [Parameter(Mandatory = $true)]$RegisteredTask,
        [Parameter(Mandatory = $true)][string]$ExpectedDescription
    )
    if ($null -eq $RegisteredTask -or [bool]$RegisteredTask.Enabled) {
        throw 'Maintenance task-name reservation is missing or enabled.'
    }
    Assert-MaintenanceTaskSecurityDescriptor `
        -Sddl $RegisteredTask.GetSecurityDescriptor(0x07)
    $Definition = $RegisteredTask.Definition
    $Actions = $Definition.Actions
    $Triggers = $Definition.Triggers
    if (
        [string]$Definition.RegistrationInfo.Description -cne $ExpectedDescription -or
        [int]$Actions.Count -ne 1 -or
        [int]$Triggers.Count -ne 0 -or
        (Resolve-SidValue -IdentityReference $Definition.Principal.UserId) -cne
            $CurrentSid -or
        [int]$Definition.Principal.LogonType -ne 3 -or
        [int]$Definition.Principal.RunLevel -ne 0
    ) {
        throw 'Maintenance task-name reservation identity is invalid.'
    }
    $Action = $Actions.Item(1)
    $ReservationActionArguments = '-NoProfile -NonInteractive -Command "exit 0"'
    if (
        [int]$Action.Type -ne 0 -or
        -not ([string]$Action.Path).Equals(
            $PowerShellPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]$Action.Arguments -cne $ReservationActionArguments -or
        -not ([string]$Action.WorkingDirectory).Equals(
            $ExpectedInstallerDir,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [bool]$Definition.Settings.Enabled -or
        [bool]$Definition.Settings.AllowDemandStart -or
        -not [bool]$Definition.Settings.Hidden -or
        [int]$Definition.Settings.MultipleInstances -ne 2 -or
        [string]$Definition.Settings.ExecutionTimeLimit -cne 'PT0S'
    ) {
        throw 'Maintenance task-name reservation behavior is invalid.'
    }
}

function New-MaintenanceReservationTask {
    param([Parameter(Mandatory = $true)][string]$Description)
    $Scheduler = New-Object -ComObject 'Schedule.Service'
    $Scheduler.Connect()
    $ReservationFolder = $Scheduler.GetFolder('\')
    $Definition = $Scheduler.NewTask(0)
    $Definition.RegistrationInfo.Description = $Description
    $Definition.Principal.UserId = $CurrentSid
    $Definition.Principal.LogonType = 3
    $Definition.Principal.RunLevel = 0
    $Action = $Definition.Actions.Create(0)
    $Action.Id = 'MaintenanceReservation'
    $Action.Path = $PowerShellPath
    $Action.Arguments = '-NoProfile -NonInteractive -Command "exit 0"'
    $Action.WorkingDirectory = $ExpectedInstallerDir
    $Definition.Settings.AllowDemandStart = $false
    $Definition.Settings.Enabled = $false
    $Definition.Settings.ExecutionTimeLimit = 'PT0S'
    $Definition.Settings.Hidden = $true
    $Definition.Settings.MultipleInstances = 2
    $MaintenanceSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    $ReservationRegistrationFlags = 6 -bor 8 -bor 16
    if ($ReservationRegistrationFlags -ne 30) {
        throw 'Maintenance reservation Task Scheduler flags contract is invalid.'
    }
    $Registered = $ReservationFolder.RegisterTaskDefinition(
        $TaskName,
        $Definition,
        $ReservationRegistrationFlags,
        $CurrentSid,
        $null,
        3,
        $MaintenanceSddl
    )
    if ($null -eq $Registered) {
        throw 'Maintenance task-name reservation registration failed.'
    }
    $Registered.SetSecurityDescriptor($MaintenanceSddl, 0x10)
    Assert-MaintenanceReservationTask `
        -RegisteredTask $Registered `
        -ExpectedDescription $Description
    return $Registered
}

function Stop-VerifiedLiveInboundRuntimeProcesses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ReleaseRoot,
        [Parameter(Mandatory = $true)][string]$StateDirectory,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    $ReleasePrefix = [IO.Path]::GetFullPath($ReleaseRoot).TrimEnd('\') + '\'
    $CanonicalStateDirectory = [IO.Path]::GetFullPath($StateDirectory)
    $FindVerifiedProcesses = {
        param(
            [string]$ExpectedReleasePrefix,
            [string]$ExpectedStateDirectory,
            [string]$ExpectedOwnerSid
        )
        $VerifiedProcesses = New-Object 'Collections.Generic.List[object]'
        $Processes = @(
            Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction Stop
        )
        foreach ($Candidate in $Processes) {
            $ExecutablePath = [string]$Candidate.ExecutablePath
            $CommandLine = [string]$Candidate.CommandLine
            if (
                [string]::IsNullOrWhiteSpace($ExecutablePath) -or
                [string]::IsNullOrWhiteSpace($CommandLine)
            ) {
                continue
            }
            $CanonicalExecutable = [IO.Path]::GetFullPath($ExecutablePath)
            if (-not $CanonicalExecutable.StartsWith(
                $ExpectedReleasePrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                continue
            }
            if ($CommandLine -notmatch '(?i)(?:^|\s)serve(?:\s|$)') {
                continue
            }
            $RelativeExecutable = $CanonicalExecutable.Substring(
                $ExpectedReleasePrefix.Length
            ).Replace('/', '\')
            $ReleaseMatch = [regex]::Match(
                $RelativeExecutable,
                '^([0-9a-f]{64})\\runtime\\python\.exe$',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            if (-not $ReleaseMatch.Success) {
                throw 'A live inbound runtime process has an unexpected executable path.'
            }
            $ReleaseDigest = $ReleaseMatch.Groups[1].Value.ToLowerInvariant()
            $ReleaseDirectory = Join-Path $ReleaseRoot $ReleaseDigest
            $ExpectedArtifact = Join-Path $ReleaseDirectory 'live-inbound.pyz'
            foreach ($Marker in @(
                $CanonicalExecutable,
                $ExpectedArtifact,
                "--release-sha256 $ReleaseDigest",
                '--state-dir',
                $ExpectedStateDirectory,
                '-I -S -B'
            )) {
                if ($CommandLine.IndexOf(
                    $Marker,
                    [StringComparison]::OrdinalIgnoreCase
                ) -lt 0) {
                    throw 'A live inbound runtime process does not match the pinned command.'
                }
            }
            $Owner = Invoke-CimMethod -InputObject $Candidate -MethodName GetOwnerSid -ErrorAction Stop
            if (
                [int]$Owner.ReturnValue -ne 0 -or
                [string]$Owner.Sid -cne $ExpectedOwnerSid
            ) {
                throw 'A live inbound runtime process owner could not be verified.'
            }
            if ($null -eq $Candidate.CreationDate) {
                throw 'A live inbound runtime process has no stable creation identity.'
            }
            [void]$VerifiedProcesses.Add([pscustomobject]@{
                CommandLine = $CommandLine
                CreationDateUtc = ([DateTime]$Candidate.CreationDate).ToUniversalTime()
                ExecutablePath = $CanonicalExecutable
                ProcessId = [int]$Candidate.ProcessId
            })
        }
        return $VerifiedProcesses.ToArray()
    }

    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $VerifiedProcesses = @(
            & $FindVerifiedProcesses $ReleasePrefix $CanonicalStateDirectory $ExecutionSid
        )
        if ($VerifiedProcesses.Count -eq 0) {
            return
        }
        foreach ($VerifiedProcess in $VerifiedProcesses) {
            $ProcessId = [int]$VerifiedProcess.ProcessId
            $Revalidated = @(
                Get-CimInstance `
                    Win32_Process `
                    -Filter "ProcessId = $ProcessId" `
                    -ErrorAction Stop
            )
            if ($Revalidated.Count -eq 0) { continue }
            if ($Revalidated.Count -ne 1) {
                throw 'Live inbound runtime process identity became ambiguous.'
            }
            $Current = $Revalidated[0]
            $CurrentOwner = Invoke-CimMethod `
                -InputObject $Current `
                -MethodName GetOwnerSid `
                -ErrorAction Stop
            $CurrentExecutable = [IO.Path]::GetFullPath([string]$Current.ExecutablePath)
            $CurrentCreationUtc = ([DateTime]$Current.CreationDate).ToUniversalTime()
            if (
                [int]$Current.ProcessId -ne $ProcessId -or
                $CurrentExecutable -cne [string]$VerifiedProcess.ExecutablePath -or
                [string]$Current.CommandLine -cne [string]$VerifiedProcess.CommandLine -or
                $CurrentCreationUtc.Ticks -ne
                    ([DateTime]$VerifiedProcess.CreationDateUtc).Ticks -or
                [int]$CurrentOwner.ReturnValue -ne 0 -or
                [string]$CurrentOwner.Sid -cne $ExecutionSid
            ) {
                throw 'Live inbound runtime process changed before termination.'
            }
            try {
                $StableProcess = [Diagnostics.Process]::GetProcessById($ProcessId)
            } catch [ArgumentException] {
                continue
            }
            try {
                # Opening SafeHandle before the final identity comparison makes Kill target
                # this process object, not a later process that happens to reuse the PID.
                $StableHandle = $StableProcess.SafeHandle
                $StableExecutable = [IO.Path]::GetFullPath(
                    [string]$StableProcess.MainModule.FileName
                )
                $StableCreationUtc = $StableProcess.StartTime.ToUniversalTime()
                if (
                    $StableHandle.IsInvalid -or
                    $StableHandle.IsClosed -or
                    $StableExecutable -cne [string]$VerifiedProcess.ExecutablePath -or
                    $StableCreationUtc.Ticks -ne
                        ([DateTime]$VerifiedProcess.CreationDateUtc).Ticks
                ) {
                    throw 'Stable live inbound runtime process handle failed identity verification.'
                }
                $StableProcess.Kill()
                if (-not $StableProcess.WaitForExit(5000)) {
                    throw 'Verified live inbound runtime process did not exit after termination.'
                }
            } finally {
                $StableProcess.Dispose()
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $Deadline)
    throw 'Verified live inbound runtime processes did not stop.'
}

function Get-PreparedReleaseContract {
    param([Parameter(Mandatory = $true)][string]$SourceRoot)
    $Root = [IO.Path]::GetFullPath($SourceRoot)
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (
        -not $RootItem.PSIsContainer -or
        $RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$RootItem.LinkType)
    ) {
        throw 'Prepared release root is linked, reparsed, or not a directory.'
    }
    $ManifestSource = Join-Path $Root 'release.json'
    $ManifestItem = Get-Item -LiteralPath $ManifestSource -Force
    if (
        $ManifestItem.Length -lt 1 -or
        $ManifestItem.Length -gt 4MB -or
        $ManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$ManifestItem.LinkType)
    ) {
        throw 'Prepared release manifest file is invalid.'
    }
    $ManifestStream = [IO.File]::Open(
        $ManifestSource,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if (
            $ManifestStream.Length -ne [int64]$ManifestItem.Length -or
            $ManifestStream.Length -lt 1 -or
            $ManifestStream.Length -gt 4MB
        ) {
            throw 'Prepared release manifest size changed while opening.'
        }
        $ManifestBytes = New-Object byte[] ([int]$ManifestStream.Length)
        $Offset = 0
        while ($Offset -lt $ManifestBytes.Length) {
            $Read = $ManifestStream.Read(
                $ManifestBytes,
                $Offset,
                $ManifestBytes.Length - $Offset
            )
            if ($Read -le 0) {
                throw 'Prepared release manifest changed while reading.'
            }
            $Offset += $Read
        }
        if ($ManifestStream.ReadByte() -ne -1) {
            throw 'Prepared release manifest grew while reading.'
        }
    } finally {
        $ManifestStream.Dispose()
    }
    if ((Get-Sha256HexFromBytes -Bytes $ManifestBytes) -cne $ManifestSha256) {
        throw 'Prepared release manifest does not match its external pin.'
    }
    $ManifestText = (New-Object Text.UTF8Encoding($false, $true)).GetString(
        $ManifestBytes
    )
    if (
        -not $ManifestText.EndsWith("`n", [StringComparison]::Ordinal) -or
        $ManifestText.Contains("`r") -or
        [int][char]$ManifestText[0] -eq 0xFEFF
    ) {
        throw 'Prepared release manifest encoding is not canonical UTF-8 with LF.'
    }
    $Manifest = $ManifestText | ConvertFrom-Json -ErrorAction Stop
    Assert-ExactJsonProperties `
        -Value $Manifest `
        -Expected @(
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
        ) `
        -ContractName 'Prepared release manifest'
    Assert-ExactJsonProperties `
        -Value $Manifest.source_provenance `
        -Expected @(
            'builder_sha256',
            'git_head',
            'git_status_snapshot_sha256',
            'reproducible_from_git_head',
            'source_kind',
            'sources'
        ) `
        -ContractName 'Prepared release provenance'
    if (
        [string]$Manifest.format -cne 'TenderBot.LiveInbound.Release.v2' -or
        [string]$Manifest.release_sha256 -cne $ReleaseSha256 -or
        [string]$Manifest.runtime_sha256 -cne $RuntimeSha256 -or
        [string]$Manifest.artifact_sha256 -cne $ArtifactSha256 -or
        [string]$Manifest.launcher_sha256 -cne $ExpectedLauncherSha256 -or
        [string]$Manifest.status_script_sha256 -cne $ExpectedStatusScriptSha256 -or
        [string]$Manifest.mandatory_label_reader_sha256 -cne
            $ExpectedMandatoryLabelReaderSha256 -or
        [string]$Manifest.installer_sha256 -cne $ExpectedInstallerSha256 -or
        [string]$Manifest.artifact -cne 'live-inbound.pyz' -or
        [string]$Manifest.launcher -cne 'verify-and-run.ps1' -or
        [string]$Manifest.status_script -cne 'read-status.ps1' -or
        [string]$Manifest.mandatory_label_reader -cne 'mandatory-label-reader.dll' -or
        [string]$Manifest.python_version -cne $TrustedPythonVersion -or
        [string]$Manifest.runtime_executable -cne 'runtime/python.exe' -or
        [string]$Manifest.runtime_dependency_contract -cne 'cpython-stdlib-copy-no-site-v2' -or
        [string]$Manifest.source_provenance.git_head -cne $ExpectedGitHead -or
        [string]$Manifest.source_provenance.git_head -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Manifest.source_provenance.git_status_snapshot_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Manifest.source_provenance.source_kind -cne 'git_head' -or
        -not [bool]$Manifest.source_provenance.reproducible_from_git_head
    ) {
        throw 'Prepared release manifest contract is invalid.'
    }
    $ManifestWithoutLf = $ManifestText.Substring(0, $ManifestText.Length - 1)
    $ReleaseIdentityField = ',"release_sha256":"' + $ReleaseSha256 + '"'
    $ReleaseIdentityOffset = $ManifestWithoutLf.IndexOf(
        $ReleaseIdentityField,
        [StringComparison]::Ordinal
    )
    if (
        $ReleaseIdentityOffset -lt 1 -or
        $ReleaseIdentityOffset -ne $ManifestWithoutLf.LastIndexOf(
            $ReleaseIdentityField,
            [StringComparison]::Ordinal
        )
    ) {
        throw 'Prepared release manifest identity field is not canonical.'
    }
    $ManifestCoreText = $ManifestWithoutLf.Remove(
        $ReleaseIdentityOffset,
        $ReleaseIdentityField.Length
    )
    if (
        (Get-Sha256HexFromBytes -Bytes (
            [Text.Encoding]::UTF8.GetBytes($ManifestCoreText)
        )) -cne $ReleaseSha256
    ) {
        throw 'Prepared release identity does not match its manifest core.'
    }
    $ProvenanceEntries = @($Manifest.source_provenance.sources)
    $ExpectedProvenancePaths = @(
        'lead_factory/facade_inquiry_parser.py',
        'lead_factory/live_connection_credentials.py',
        'lead_factory/mail_bitrix_projection.py',
        'lead_factory/mail_threading.py',
        'lead_factory/live_mail_bitrix.py',
        'lead_factory/native_bitrix_mail_observer.py',
        'scripts/run_live_inbound.py',
        'scripts/run_native_bitrix_observer.py',
        'scripts/live_inbound_launcher.ps1',
        'scripts/build_live_inbound_release.py',
        'scripts/install_live_inbound_task_admin.ps1',
        'scripts/install_live_inbound_task.ps1',
        'scripts/live_inbound_task_status.ps1',
        'scripts/mandatory_label_reader.cs',
        'scripts/mandatory_label_reader.dll'
    )
    if ($ProvenanceEntries.Count -ne $ExpectedProvenancePaths.Count) {
        throw 'Prepared release provenance is not clean and reproducible.'
    }
    $StatusReceiptBuilder = New-Object Text.StringBuilder
    for ($Index = 0; $Index -lt $ProvenanceEntries.Count; $Index++) {
        $Entry = $ProvenanceEntries[$Index]
        Assert-ExactJsonProperties `
            -Value $Entry `
            -Expected @('git_head_sha256', 'git_state', 'path', 'size', 'worktree_sha256') `
            -ContractName 'Prepared release provenance entry'
        $EntryPath = [string]$Entry.path
        $EntryHeadSha256 = [string]$Entry.git_head_sha256
        $EntryWorktreeSha256 = [string]$Entry.worktree_sha256
        if (
            $EntryPath -cne $ExpectedProvenancePaths[$Index] -or
            [string]$Entry.git_state -cne 'tracked_clean' -or
            $EntryHeadSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $EntryHeadSha256 -cne $EntryWorktreeSha256 -or
            [int64]$Entry.size -lt 1 -or
            [int64]$Entry.size -gt 4MB
        ) {
            throw 'Prepared release provenance is not clean and reproducible.'
        }
        $TrustedMatch = @($TrustedIndependentSources | Where-Object {
            [string]$_.Path -ceq $EntryPath
        })
        if ($EntryPath -ceq 'scripts/install_live_inbound_task_admin.ps1') {
            if ($EntryWorktreeSha256 -cne $ExpectedInstallerSha256) {
                throw 'Prepared release does not bind the privileged installer.'
            }
        } elseif ($EntryPath -ceq 'scripts/install_live_inbound_task.ps1') {
            if ($TrustedMatch.Count -ne 0) {
                throw 'Medium wrapper provenance unexpectedly participates in the admin hash cycle.'
            }
        } elseif (
            $TrustedMatch.Count -ne 1 -or
            $EntryWorktreeSha256 -cne [string]$TrustedMatch[0].Sha256
        ) {
            throw 'Prepared release source does not match the immutable admin trust anchor.'
        }
        [void]$StatusReceiptBuilder.Append($EntryPath)
        [void]$StatusReceiptBuilder.Append("`0tracked_clean`0")
        [void]$StatusReceiptBuilder.Append($EntryHeadSha256)
        [void]$StatusReceiptBuilder.Append("`0")
        [void]$StatusReceiptBuilder.Append($EntryWorktreeSha256)
        [void]$StatusReceiptBuilder.Append("`n")
    }
    $ComputedStatusReceiptSha256 = Get-Sha256HexFromBytes -Bytes (
        [Text.Encoding]::UTF8.GetBytes($StatusReceiptBuilder.ToString())
    )
    if (
        $ComputedStatusReceiptSha256 -cne
            [string]$Manifest.source_provenance.git_status_snapshot_sha256
    ) {
        throw 'Prepared release provenance receipt is invalid.'
    }
    $BuilderProvenance = @($ProvenanceEntries | Where-Object {
        [string]$_.path -ceq 'scripts/build_live_inbound_release.py'
    })
    if (
        $BuilderProvenance.Count -ne 1 -or
        [string]$Manifest.source_provenance.builder_sha256 -cne
            [string]$BuilderProvenance[0].worktree_sha256 -or
        [string]$Manifest.source_provenance.builder_sha256 -cne
            [string](@($TrustedIndependentSources | Where-Object {
                [string]$_.Path -ceq 'scripts/build_live_inbound_release.py'
            })[0].Sha256)
    ) {
        throw 'Prepared release does not bind its builder provenance.'
    }

    $PythonSourcePaths = @(
        'lead_factory/facade_inquiry_parser.py',
        'lead_factory/live_connection_credentials.py',
        'lead_factory/live_mail_bitrix.py',
        'lead_factory/native_bitrix_mail_observer.py',
        'lead_factory/mail_bitrix_projection.py',
        'lead_factory/mail_threading.py',
        'scripts/run_live_inbound.py',
        'scripts/run_native_bitrix_observer.py'
    )
    $TrustedGeneratedPythonSourceSha256 = [ordered]@{
        '__main__.py' = '54bce33291df06a42e83f2aec0693183dd615f1ac5deae9fa5fed7b46ed18846'
        'lead_factory/__init__.py' = '7644f10859480fe82fc8adde3ffde18effe98d73a8b015f29299db80c7a58891'
        'scripts/__init__.py' = 'fce065fa93ee1544d0825302cee694f8134ae10d5a7e6a81f667ae5f9769b788'
    }
    $ExpectedPythonSourcePaths = @($PythonSourcePaths) + @(
        $TrustedGeneratedPythonSourceSha256.Keys
    )
    Assert-ExactJsonProperties `
        -Value $Manifest.source_sha256 `
        -Expected $ExpectedPythonSourcePaths `
        -ContractName 'Prepared release Python source digest map'
    foreach ($PythonSourcePath in $PythonSourcePaths) {
        $TrustedMatch = @($TrustedIndependentSources | Where-Object {
            [string]$_.Path -ceq $PythonSourcePath
        })
        if (
            $TrustedMatch.Count -ne 1 -or
            [string]$Manifest.source_sha256.$PythonSourcePath -cne
                [string]$TrustedMatch[0].Sha256
        ) {
            throw 'Prepared release Python source digest map is invalid.'
        }
    }
    foreach (
        $GeneratedPythonSourcePath in @($TrustedGeneratedPythonSourceSha256.Keys)
    ) {
        $ObservedGeneratedSha256 = [string](
            $Manifest.source_sha256.PSObject.Properties[
                [string]$GeneratedPythonSourcePath
            ].Value
        )
        if (
            $ObservedGeneratedSha256 -cne
                [string]$TrustedGeneratedPythonSourceSha256[
                    [string]$GeneratedPythonSourcePath
                ]
        ) {
            throw 'Prepared release generated Python source digest is invalid.'
        }
    }

    $Files = New-Object 'Collections.Generic.List[object]'
    $Directories = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    [void]$Directories.Add('runtime')
    [void]$Files.Add([pscustomobject]@{
        Path = 'release.json'
        Sha256 = $ManifestSha256
        Size = [int64]$ManifestItem.Length
    })
    foreach ($TopLevel in @(
        [pscustomobject]@{
            Path = 'live-inbound.pyz'
            Sha256 = $ArtifactSha256
            Maximum = 32MB
        },
        [pscustomobject]@{
            Path = 'verify-and-run.ps1'
            Sha256 = $ExpectedLauncherSha256
            Maximum = 2MB
        },
        [pscustomobject]@{
            Path = 'read-status.ps1'
            Sha256 = $ExpectedStatusScriptSha256
            Maximum = 4MB
        },
        [pscustomobject]@{
            Path = 'mandatory-label-reader.dll'
            Sha256 = $ExpectedMandatoryLabelReaderSha256
            Maximum = 1MB
        }
    )) {
        $Candidate = Join-Path $Root ([string]$TopLevel.Path)
        $Item = Get-Item -LiteralPath $Candidate -Force
        if ($Item.Length -lt 1 -or $Item.Length -gt [int64]$TopLevel.Maximum) {
            throw 'Prepared release file size is invalid.'
        }
        [void]$Files.Add([pscustomobject]@{
            Path = [string]$TopLevel.Path
            Sha256 = [string]$TopLevel.Sha256
            Size = [int64]$Item.Length
        })
    }
    $RuntimeEntries = @($Manifest.runtime_files)
    if ($RuntimeEntries.Count -lt 1 -or $RuntimeEntries.Count -gt 10000) {
        throw 'Prepared runtime manifest count is invalid.'
    }
    $SeenRuntime = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::OrdinalIgnoreCase
    )
    $CanonicalRuntimeEntries = New-Object 'Collections.Generic.List[object]'
    $TotalRuntimeBytes = [int64]0
    foreach ($Entry in $RuntimeEntries) {
        Assert-ExactJsonProperties `
            -Value $Entry `
            -Expected @('path', 'sha256', 'size') `
            -ContractName 'Prepared runtime manifest entry'
        $Relative = [string]$Entry.path
        $Size = [int64]$Entry.size
        $Sha256 = [string]$Entry.sha256
        if (
            [string]::IsNullOrWhiteSpace($Relative) -or
            $Relative.Contains('\') -or
            $Relative.Contains(':') -or
            $Relative -match '(^|/)\.\.(/|$)' -or
            $Relative -match '(^|/)\.(/|$)' -or
            $Relative.Contains('//') -or
            $Relative.EndsWith('/') -or
            $Relative.StartsWith('/') -or
            -not $SeenRuntime.Add($Relative) -or
            $Size -lt 0 -or $Size -gt 256MB -or
            $Sha256 -cnotmatch '^[0-9a-f]{64}$'
        ) {
            throw 'Prepared runtime manifest entry is invalid.'
        }
        $TotalRuntimeBytes += $Size
        if ($TotalRuntimeBytes -gt 2GB) {
            throw 'Prepared runtime exceeds its bounded size.'
        }
        $Segments = $Relative.Split('/')
        if ($Segments.Count -gt 1) {
            for ($Index = 1; $Index -lt $Segments.Count; $Index++) {
                [void]$Directories.Add(
                    'runtime/' + (($Segments[0..($Index - 1)]) -join '/')
                )
            }
        }
        [void]$Files.Add([pscustomobject]@{
            Path = 'runtime/' + $Relative
            Sha256 = $Sha256
            Size = $Size
        })
        [void]$CanonicalRuntimeEntries.Add([ordered]@{
            path = $Relative
            sha256 = $Sha256
            size = $Size
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
        throw 'Prepared runtime file contract does not match its external pin.'
    }

    $ExpectedFiles = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    $ExpectedFilesFolded = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($File in $Files) {
        if (-not $ExpectedFiles.Add([string]$File.Path) -or -not $ExpectedFilesFolded.Add([string]$File.Path)) {
            throw 'Prepared release contains a file path collision.'
        }
    }
    $RootPrefix = $Root.TrimEnd('\') + '\'
    $ObservedFiles = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    $ObservedDirectories = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    foreach ($Item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse)) {
        if (
            $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
            -not [string]::IsNullOrEmpty([string]$Item.LinkType) -or
            -not $Item.FullName.StartsWith($RootPrefix, [StringComparison]::Ordinal)
        ) {
            throw 'Prepared release contains a linked or escaped item.'
        }
        $Relative = $Item.FullName.Substring($RootPrefix.Length).Replace('\', '/')
        if ($Item.PSIsContainer) {
            if (-not $ObservedDirectories.Add($Relative)) {
                throw 'Prepared release directory identity is ambiguous.'
            }
        } elseif (-not $ObservedFiles.Add($Relative)) {
            throw 'Prepared release file identity is ambiguous.'
        }
    }
    if (
        @(
            Compare-Object -ReferenceObject @($ExpectedFiles) -DifferenceObject @($ObservedFiles) -CaseSensitive
        ).Count -ne 0 -or
        @(
            Compare-Object -ReferenceObject @($Directories) -DifferenceObject @($ObservedDirectories) -CaseSensitive
        ).Count -ne 0
    ) {
        throw 'Prepared release tree contains missing or unexpected items.'
    }
    return [pscustomobject]@{
        Directories = @($Directories)
        Files = $Files.ToArray()
        Manifest = $Manifest
    }
}

function Copy-LockedPreparedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][int64]$ExpectedSize,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $SourceItem = Get-Item -LiteralPath $Source -Force
    if (
        $SourceItem.PSIsContainer -or
        $SourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$SourceItem.LinkType)
    ) {
        throw 'Prepared release source file is linked or invalid.'
    }
    $SourceStream = [IO.File]::Open(
        $Source,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($SourceStream.Length -ne $ExpectedSize) {
            throw 'Prepared release source size changed during copy.'
        }
        $DestinationStream = [IO.File]::Open(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $SourceStream.CopyTo($DestinationStream)
            $DestinationStream.Flush($true)
        } finally {
            $DestinationStream.Dispose()
        }
    } finally {
        $SourceStream.Dispose()
    }
    if (
        (Get-Item -LiteralPath $Destination -Force).Length -ne $ExpectedSize -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant() `
            -cne $ExpectedSha256
    ) {
        throw 'Protected release copy failed its external hash pin.'
    }
}

function Assert-ProtectedReleasePayload {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)]$Contract,
        [Parameter(Mandatory = $true)][string]$ExecutionSid
    )
    Assert-ProtectedReleaseAcl `
        -LiteralPath $LiteralPath `
        -ExecutionSid $ExecutionSid `
        -Recursive
    Assert-HighIntegrityLabel -LiteralPath $LiteralPath -Recursive
    $RootPrefix = $LiteralPath.TrimEnd('\') + '\'
    $Files = @(Get-ChildItem -LiteralPath $LiteralPath -File -Force -Recurse)
    if ($Files.Count -ne @($Contract.Files).Count) {
        throw 'Protected release file count is invalid.'
    }
    foreach ($Expected in @($Contract.Files)) {
        $Candidate = [IO.Path]::GetFullPath(
            (Join-Path $LiteralPath ([string]$Expected.Path).Replace('/', '\'))
        )
        if (
            -not $Candidate.StartsWith($RootPrefix, [StringComparison]::Ordinal) -or
            -not [IO.File]::Exists($Candidate) -or
            (Get-Item -LiteralPath $Candidate -Force).Length -ne [int64]$Expected.Size -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash.ToLowerInvariant() `
                -cne [string]$Expected.Sha256
        ) {
            throw 'Protected release payload verification failed.'
        }
    }
}

function Assert-PinnedRuntimeSignature {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $Signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
    if (
        $null -eq $Signature -or
        [string]$Signature.Status -cne 'Valid' -or
        $null -eq $Signature.SignerCertificate
    ) {
        throw 'Protected runtime Authenticode signature is invalid.'
    }
    $CertificateSha256 = Get-Sha256HexFromBytes -Bytes (
        [byte[]]$Signature.SignerCertificate.RawData
    )
    if (
        $CertificateSha256 -cne $TrustedRuntimeSignerCertificateSha256 -or
        [string]$Signature.SignerCertificate.Subject -cne
            'CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US'
    ) {
        throw 'Protected runtime signer does not match the immutable publisher pin.'
    }
}

function ConvertFrom-HexString {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -cnotmatch '^(?:[0-9a-f]{2})+$') {
        throw 'Hexadecimal contract value is invalid.'
    }
    $Bytes = New-Object byte[] ([int]($Value.Length / 2))
    for ($Index = 0; $Index -lt $Bytes.Length; $Index++) {
        $Bytes[$Index] = [byte]::Parse(
            $Value.Substring($Index * 2, 2),
            [Globalization.NumberStyles]::HexNumber,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    return $Bytes
}

function New-AdminPrepareNonce {
    $NonceBytes = New-Object byte[] 32
    $Random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Random.GetBytes($NonceBytes)
    } finally {
        $Random.Dispose()
    }
    return ([BitConverter]::ToString($NonceBytes)).Replace('-', '').ToLowerInvariant()
}

function New-AdminPrepareReceipt {
    param(
        [Parameter(Mandatory = $true)][bool]$ExistingTaskFound,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)]
        [ValidateSet('existing_task_quiesced', 'maintenance_placeholder')]
        [string]$ReservationKind,
        [Parameter(Mandatory = $true)][string]$ReservationDescription
    )
    if ([IO.File]::Exists($PrepareReceiptPath)) {
        throw 'Protected prepare receipt identity already exists.'
    }
    $NonceBytes = ConvertFrom-HexString -Value $Nonce
    $NonceSha256 = Get-Sha256HexFromBytes -Bytes $NonceBytes
    $ReservationDescriptionSha256 = Get-Sha256HexFromBytes -Bytes (
        [Text.Encoding]::UTF8.GetBytes($ReservationDescription)
    )
    $ReceiptText = [ordered]@{
        artifact_sha256 = $ArtifactSha256
        existing_task_found = $ExistingTaskFound
        execution_sid = $CurrentSid
        format = 'TenderBot.LiveInbound.AdminPrepareReceipt.v1'
        installer_sha256 = $ExpectedInstallerSha256
        interval_seconds = $IntervalSeconds
        launcher_sha256 = $ExpectedLauncherSha256
        mandatory_label_reader_sha256 = $ExpectedMandatoryLabelReaderSha256
        manifest_sha256 = $ManifestSha256
        prepare_nonce_sha256 = $NonceSha256
        release_sha256 = $ReleaseSha256
        request_id = $RequestId
        reservation_description_sha256 = $ReservationDescriptionSha256
        reservation_kind = $ReservationKind
        runtime_sha256 = $RuntimeSha256
        status_script_sha256 = $ExpectedStatusScriptSha256
        task_name = $TaskName
        task_quiesced = $true
    } | ConvertTo-Json -Compress
    $ReceiptBytes = (New-Object Text.UTF8Encoding($false, $true)).GetBytes($ReceiptText)
    $Stream = [IO.File]::Open(
        $PrepareReceiptPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $Stream.Write($ReceiptBytes, 0, $ReceiptBytes.Length)
        $Stream.Flush($true)
    } finally {
        $Stream.Dispose()
    }
    Protect-ReleasePath -LiteralPath $PrepareReceiptPath -ExecutionSid $CurrentSid
    Assert-ProtectedReleaseAcl `
        -LiteralPath $PrepareReceiptPath `
        -ExecutionSid $CurrentSid
    Assert-HighIntegrityLabel -LiteralPath $PrepareReceiptPath
    if (
        (Get-FileHash -Algorithm SHA256 -LiteralPath $PrepareReceiptPath).Hash.ToLowerInvariant() `
            -cne (Get-Sha256HexFromBytes -Bytes $ReceiptBytes)
    ) {
        throw 'Protected prepare receipt write failed its exact readback.'
    }
    return [pscustomobject]@{
        Nonce = $Nonce
        ReceiptSha256 = Get-Sha256HexFromBytes -Bytes $ReceiptBytes
    }
}

function Read-AdminPrepareReceipt {
    param([Parameter(Mandatory = $true)][string]$ExpectedNonce)
    $Item = Get-Item -LiteralPath $PrepareReceiptPath -Force
    if (
        $Item.PSIsContainer -or
        $Item.Length -lt 1 -or
        $Item.Length -gt 16KB -or
        $Item.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not [string]::IsNullOrEmpty([string]$Item.LinkType)
    ) {
        throw 'Protected prepare receipt file is invalid.'
    }
    Assert-ProtectedReleaseAcl `
        -LiteralPath $PrepareReceiptPath `
        -ExecutionSid $CurrentSid
    Assert-HighIntegrityLabel -LiteralPath $PrepareReceiptPath
    $Stream = [IO.File]::Open(
        $PrepareReceiptPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if (
            $Stream.Length -ne [int64]$Item.Length -or
            $Stream.Length -lt 1 -or
            $Stream.Length -gt 16KB
        ) {
            throw 'Protected prepare receipt size changed while opening.'
        }
        $ReceiptBytes = New-Object byte[] ([int]$Stream.Length)
        $Offset = 0
        while ($Offset -lt $ReceiptBytes.Length) {
            $Read = $Stream.Read($ReceiptBytes, $Offset, $ReceiptBytes.Length - $Offset)
            if ($Read -le 0) { throw 'Protected prepare receipt changed while reading.' }
            $Offset += $Read
        }
        if ($Stream.ReadByte() -ne -1) {
            throw 'Protected prepare receipt grew while reading.'
        }
    } finally {
        $Stream.Dispose()
    }
    $ReceiptText = (New-Object Text.UTF8Encoding($false, $true)).GetString($ReceiptBytes)
    $Receipt = $ReceiptText | ConvertFrom-Json -ErrorAction Stop
    Assert-ExactJsonProperties `
        -Value $Receipt `
        -Expected @(
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
        ) `
        -ContractName 'Protected prepare receipt'
    $ExpectedNonceBytes = ConvertFrom-HexString -Value $ExpectedNonce
    if (
        [string]$Receipt.format -cne 'TenderBot.LiveInbound.AdminPrepareReceipt.v1' -or
        [string]$Receipt.request_id -cne $RequestId -or
        [string]$Receipt.execution_sid -cne $CurrentSid -or
        [string]$Receipt.installer_sha256 -cne $ExpectedInstallerSha256 -or
        [string]$Receipt.release_sha256 -cne $ReleaseSha256 -or
        [string]$Receipt.runtime_sha256 -cne $RuntimeSha256 -or
        [string]$Receipt.manifest_sha256 -cne $ManifestSha256 -or
        [string]$Receipt.artifact_sha256 -cne $ArtifactSha256 -or
        [string]$Receipt.launcher_sha256 -cne $ExpectedLauncherSha256 -or
        [string]$Receipt.status_script_sha256 -cne $ExpectedStatusScriptSha256 -or
        [string]$Receipt.mandatory_label_reader_sha256 -cne
            $ExpectedMandatoryLabelReaderSha256 -or
        [int]$Receipt.interval_seconds -ne $IntervalSeconds -or
        [string]$Receipt.task_name -cne $TaskName -or
        -not [bool]$Receipt.task_quiesced -or
        [string]$Receipt.reservation_description_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Receipt.reservation_kind -cnotin @(
            'existing_task_quiesced',
            'maintenance_placeholder'
        ) -or
        ([bool]$Receipt.existing_task_found -and
            [string]$Receipt.reservation_kind -cne 'existing_task_quiesced') -or
        (-not [bool]$Receipt.existing_task_found -and
            [string]$Receipt.reservation_kind -cne 'maintenance_placeholder') -or
        [string]$Receipt.prepare_nonce_sha256 -cne
            (Get-Sha256HexFromBytes -Bytes $ExpectedNonceBytes)
    ) {
        throw 'Commit does not match the protected admin-owned prepare receipt.'
    }
    return [pscustomobject]@{
        Receipt = $Receipt
        ReceiptSha256 = Get-Sha256HexFromBytes -Bytes $ReceiptBytes
    }
}

if (
    -not (Test-Path -LiteralPath $PowerShellPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $PreparedReleaseDir -PathType Container) -or
    -not (Test-Path -LiteralPath $MandatoryLabelReaderPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ProtectedRequestRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $ProtectedRequestDir -PathType Container) -or
    [string]::IsNullOrWhiteSpace($PSCommandPath)
) {
    throw 'Protected live inbound install prerequisites are missing.'
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $Identity.User.Value
if ($CurrentSid -cne $ExpectedExecutionSid) {
    throw 'Protected installer execution principal changed.'
}
$CanonicalCommandPath = [IO.Path]::GetFullPath($PSCommandPath)
if (
    $CanonicalCommandPath -cne $ExpectedInstallerPath -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $CanonicalCommandPath).Hash.ToLowerInvariant() `
        -cne $ExpectedInstallerSha256
) {
    throw 'Privileged installer is not executing from its protected external pin.'
}
$AdminProtectedPaths = @(
    $InstallerRoot,
    $ExpectedInstallerDir,
    $ExpectedInstallerPath,
    $MandatoryLabelReaderPath,
    $ProtectedRequestRoot,
    $ProtectedRequestDir
)
foreach ($ProtectedInstallerPath in $AdminProtectedPaths) {
    Assert-ProtectedReleaseAcl `
        -LiteralPath $ProtectedInstallerPath `
        -ExecutionSid $CurrentSid
}
$InstallerChildren = @(Get-ChildItem -LiteralPath $ExpectedInstallerDir -Force)
if (
    $InstallerChildren.Count -ne 2 -or
    @($InstallerChildren | Where-Object {
        $_.PSIsContainer -or
        [string]$_.Name -cnotin @(
            'install-live-inbound-admin.ps1',
            'mandatory-label-reader.dll'
        )
    }).Count -ne 0
) {
    throw 'Protected installer directory contains unexpected items.'
}
$MandatoryLabelReaderType = Import-PinnedMandatoryLabelReader `
    -LiteralPath $MandatoryLabelReaderPath `
    -ExpectedSha256 $TrustedMandatoryLabelReaderSha256
foreach ($ProtectedInstallerPath in $AdminProtectedPaths) {
    Assert-HighIntegrityLabel -LiteralPath $ProtectedInstallerPath
}
if (-not $PSCmdlet.ShouldProcess(
    $TaskName,
    "Run protected live-inbound installation phase: $InstallPhase"
)) {
    return
}
if (
    ($InstallPhase -ceq 'PrepareAndQuiesce' -and
        (-not [string]::IsNullOrEmpty($ExpectedRevocationCorrelationSha256) -or
         -not [string]::IsNullOrEmpty($ExpectedPrepareNonce))) -or
    ($InstallPhase -ceq 'Commit' -and
        ($ExpectedRevocationCorrelationSha256 -cnotmatch '^[0-9a-f]{64}$' -or
         $ExpectedPrepareNonce -cnotmatch '^[0-9a-f]{64}$'))
) {
    throw 'Installation phase correlation contract is invalid.'
}
$ProtectedPrepareReceipt = if ($InstallPhase -ceq 'Commit') {
    Read-AdminPrepareReceipt -ExpectedNonce $ExpectedPrepareNonce
} else {
    if ([IO.File]::Exists($PrepareReceiptPath)) {
        throw 'Protected prepare receipt identity is not fresh.'
    }
    $null
}

$ExistingMatches = @(
    Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue
)
if ($ExistingMatches.Count -gt 1) {
    throw 'Scheduled Task identity is ambiguous.'
}
$Existing = if ($ExistingMatches.Count -eq 1) { $ExistingMatches[0] } else { $null }
$ExistingTaskFoundAtPrepare = [bool](
    $InstallPhase -ceq 'PrepareAndQuiesce' -and $null -ne $Existing
)
if ($InstallPhase -ceq 'PrepareAndQuiesce' -and $null -ne $Existing) {
    $ExistingDescription = [string]$Existing.Description
    $ExistingMarker = ConvertFrom-LiveInboundTaskDescription `
        -Description $ExistingDescription
    if ($null -eq $ExistingMarker) {
        throw 'A different Scheduled Task already uses the requested name.'
    }
    try {
        $ExistingSid = Resolve-SidValue -IdentityReference $Existing.Principal.UserId
    } catch {
        throw 'Existing live inbound task principal SID could not be resolved.'
    }
    if ($ExistingSid -cne $CurrentSid) {
        throw 'Refusing to replace a live inbound task owned by another Windows principal.'
    }
    if ([string]$ExistingMarker.Kind -ceq 'legacy_writer_v4') {
        if ([bool]$Existing.Settings.Enabled) {
            throw 'Legacy writer-v4 task must already be disabled before migration.'
        }
        $ExistingVerificationScheduler = New-Object -ComObject 'Schedule.Service'
        $ExistingVerificationScheduler.Connect()
        $ExistingVerificationCom = $ExistingVerificationScheduler.GetFolder('\').GetTask(
            "\$TaskName"
        )
        Assert-TaskSecurityDescriptor `
            -Sddl $ExistingVerificationCom.GetSecurityDescriptor(0x07) `
            -ExecutionSid $CurrentSid
        if ([int]$ExistingVerificationCom.GetInstances(0).Count -ne 0) {
            throw 'Legacy writer-v4 task must not be running during migration.'
        }
    }
} elseif ($InstallPhase -ceq 'Commit') {
    if ($null -eq $Existing) {
        throw 'Protected task-name reservation disappeared before commit.'
    }
    $ExistingDescription = [string]$Existing.Description
    $ExistingDescriptionSha256 = Get-Sha256HexFromBytes -Bytes (
        [Text.Encoding]::UTF8.GetBytes($ExistingDescription)
    )
    if (
        $ExistingDescriptionSha256 -cne
            [string]$ProtectedPrepareReceipt.Receipt.reservation_description_sha256
    ) {
        throw 'Protected task-name reservation description changed before commit.'
    }
    try {
        $ExistingSid = Resolve-SidValue -IdentityReference $Existing.Principal.UserId
    } catch {
        throw 'Reserved live inbound task principal SID could not be resolved.'
    }
    if ($ExistingSid -cne $CurrentSid -or [bool]$Existing.Settings.Enabled) {
        throw 'Protected task-name reservation principal or disabled state changed.'
    }
    $CommitReservationScheduler = New-Object -ComObject 'Schedule.Service'
    $CommitReservationScheduler.Connect()
    $CommitReservationCom = $CommitReservationScheduler.GetFolder('\').GetTask(
        "\$TaskName"
    )
    if (
        [string]$ProtectedPrepareReceipt.Receipt.reservation_kind -ceq
            'maintenance_placeholder'
    ) {
        $ExpectedReservationDescription = Get-MaintenanceReservationDescription `
            -PrepareNonceSha256 (Get-Sha256HexFromBytes -Bytes (
                ConvertFrom-HexString -Value $ExpectedPrepareNonce
            ))
        if ($ExistingDescription -cne $ExpectedReservationDescription) {
            throw 'Maintenance task-name reservation is not bound to the prepare nonce.'
        }
        Assert-MaintenanceReservationTask `
            -RegisteredTask $CommitReservationCom `
            -ExpectedDescription $ExpectedReservationDescription
    } else {
        $ExistingMarker = ConvertFrom-LiveInboundTaskDescription `
            -Description $ExistingDescription
        if ($null -eq $ExistingMarker) {
            throw 'Quiesced live inbound task marker changed before commit.'
        }
        Assert-MaintenanceTaskSecurityDescriptor `
            -Sddl $CommitReservationCom.GetSecurityDescriptor(0x07)
    }
}

$ProtectedParents = @(
    (Join-Path $ProgramFilesDirectory 'TenderBot'),
    (Join-Path $ProgramFilesDirectory 'TenderBot\LiveInbound'),
    $ReleaseRoot
)
foreach ($ProtectedParent in $ProtectedParents) {
    if (-not (Test-Path -LiteralPath $ProtectedParent -PathType Container)) {
        New-Item -ItemType Directory -Path $ProtectedParent -Force | Out-Null
    }
    Protect-ReleasePath -LiteralPath $ProtectedParent -ExecutionSid $CurrentSid
    Assert-ProtectedReleaseAcl -LiteralPath $ProtectedParent -ExecutionSid $CurrentSid
    Assert-HighIntegrityLabel -LiteralPath $ProtectedParent
}

$Contract = Get-PreparedReleaseContract -SourceRoot $PreparedReleaseDir
$ExpectedReleaseDir = [IO.Path]::GetFullPath((Join-Path $ReleaseRoot $ReleaseSha256))
$ReleaseDir = $ExpectedReleaseDir
if (Test-Path -LiteralPath $ReleaseDir) {
    if (-not (Test-Path -LiteralPath $ReleaseDir -PathType Container)) {
        throw 'Pinned release destination is not a directory.'
    }
    Assert-ProtectedReleasePayload `
        -LiteralPath $ReleaseDir `
        -Contract $Contract `
        -ExecutionSid $CurrentSid
} else {
    $StageDir = [IO.Path]::GetFullPath(
        (Join-Path $ReleaseRoot ('.stage-' + $RequestId))
    )
    if (Test-Path -LiteralPath $StageDir) {
        throw 'Protected release staging identity already exists.'
    }
    New-Item -ItemType Directory -Path $StageDir | Out-Null
    Protect-ReleasePath -LiteralPath $StageDir -ExecutionSid $CurrentSid
    foreach ($RelativeDirectory in @($Contract.Directories | Sort-Object {
        ([string]$_).Split('/').Count
    }, { [string]$_ })) {
        $DirectoryPath = [IO.Path]::GetFullPath(
            (Join-Path $StageDir ([string]$RelativeDirectory).Replace('/', '\'))
        )
        New-Item -ItemType Directory -Path $DirectoryPath | Out-Null
    }
    Protect-ReleasePath `
        -LiteralPath $StageDir `
        -ExecutionSid $CurrentSid `
        -Recursive
    Assert-ProtectedReleaseAcl `
        -LiteralPath $StageDir `
        -ExecutionSid $CurrentSid `
        -Recursive
    Assert-HighIntegrityLabel -LiteralPath $StageDir -Recursive
    foreach ($File in @($Contract.Files)) {
        $Source = [IO.Path]::GetFullPath(
            (Join-Path $PreparedReleaseDir ([string]$File.Path).Replace('/', '\'))
        )
        $Destination = [IO.Path]::GetFullPath(
            (Join-Path $StageDir ([string]$File.Path).Replace('/', '\'))
        )
        Copy-LockedPreparedFile `
            -Source $Source `
            -Destination $Destination `
            -ExpectedSize ([int64]$File.Size) `
            -ExpectedSha256 ([string]$File.Sha256)
    }
    [void](Get-PreparedReleaseContract -SourceRoot $PreparedReleaseDir)
    Protect-ReleasePath `
        -LiteralPath $StageDir `
        -ExecutionSid $CurrentSid `
        -Recursive
    Assert-ProtectedReleasePayload `
        -LiteralPath $StageDir `
        -Contract $Contract `
        -ExecutionSid $CurrentSid
    Move-Item -LiteralPath $StageDir -Destination $ReleaseDir
    Assert-ProtectedReleasePayload `
        -LiteralPath $ReleaseDir `
        -Contract $Contract `
        -ExecutionSid $CurrentSid
}

foreach ($ProtectedParent in $ProtectedParents) {
    Assert-ProtectedReleaseAcl -LiteralPath $ProtectedParent -ExecutionSid $CurrentSid
    Assert-HighIntegrityLabel -LiteralPath $ProtectedParent
}
$ArtifactPath = Join-Path $ReleaseDir 'live-inbound.pyz'
$RuntimePath = Join-Path $ReleaseDir 'runtime\python.exe'
$ManifestPath = Join-Path $ReleaseDir 'release.json'
$LauncherPath = Join-Path $ReleaseDir 'verify-and-run.ps1'
$StatusPath = Join-Path $ReleaseDir 'read-status.ps1'
$ReleaseMandatoryLabelReaderPath = Join-Path $ReleaseDir 'mandatory-label-reader.dll'
if (
    -not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $RuntimePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $StatusPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ReleaseMandatoryLabelReaderPath -PathType Leaf)
) {
    throw 'Pinned protected release layout is invalid.'
}
$IcaclsPath = Join-Path $SystemDirectory 'icacls.exe'
& $IcaclsPath $ReleaseDir /verify /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Release ACL verification failed.' }
Assert-PinnedRuntimeSignature -LiteralPath $RuntimePath

if ($null -ne $Existing) {
    $Scheduler = New-Object -ComObject 'Schedule.Service'
    $Scheduler.Connect()
    $ExistingCom = $Scheduler.GetFolder('\').GetTask("\$TaskName")
    $MaintenanceSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    $ExistingCom.SetSecurityDescriptor($MaintenanceSddl, 0x10)
    Assert-MaintenanceTaskSecurityDescriptor `
        -Sddl $ExistingCom.GetSecurityDescriptor(0x07)
    Disable-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction Stop | Out-Null
    $Existing = Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction Stop
    $ExistingCom = $Scheduler.GetFolder('\').GetTask("\$TaskName")
    Assert-MaintenanceTaskSecurityDescriptor `
        -Sddl $ExistingCom.GetSecurityDescriptor(0x07)
    $RefreshedDescription = [string]$Existing.Description
    try {
        $RefreshedSid = Resolve-SidValue -IdentityReference $Existing.Principal.UserId
    } catch {
        throw 'Quiesced live inbound task principal SID could not be resolved.'
    }
    if ([bool]$Existing.Settings.Enabled) {
        throw 'Existing live inbound task could not be disabled before quiesce.'
    }
    if ($RefreshedSid -cne $CurrentSid) {
        throw 'Quiesced live inbound task principal changed during cutover.'
    }
    if ($InstallPhase -ceq 'PrepareAndQuiesce') {
        if ($null -eq (ConvertFrom-LiveInboundTaskDescription $RefreshedDescription)) {
            throw 'Live inbound task marker changed while entering maintenance.'
        }
    } else {
        $RefreshedDescriptionSha256 = Get-Sha256HexFromBytes -Bytes (
            [Text.Encoding]::UTF8.GetBytes($RefreshedDescription)
        )
        if (
            $RefreshedDescriptionSha256 -cne
                [string]$ProtectedPrepareReceipt.Receipt.reservation_description_sha256
        ) {
            throw 'Protected task-name reservation changed during commit.'
        }
        if (
            [string]$ProtectedPrepareReceipt.Receipt.reservation_kind -ceq
                'maintenance_placeholder'
        ) {
            Assert-MaintenanceReservationTask `
                -RegisteredTask $ExistingCom `
                -ExpectedDescription $RefreshedDescription
        }
    }
    $ExistingCom.Stop(0)
    $Deadline = [DateTime]::UtcNow.AddSeconds(30)
    $RunningInstances = $ExistingCom.GetInstances(0)
    while (
        [int]$RunningInstances.Count -gt 0 -and
        [DateTime]::UtcNow -lt $Deadline
    ) {
        Start-Sleep -Milliseconds 250
        $RunningInstances = $ExistingCom.GetInstances(0)
    }
    if ([int]$RunningInstances.Count -gt 0) {
        throw 'Existing live inbound task instances did not stop.'
    }
}
Stop-VerifiedLiveInboundRuntimeProcesses `
    -ReleaseRoot $ReleaseRoot `
    -StateDirectory $StateDir `
    -ExecutionSid $CurrentSid

if ($InstallPhase -ceq 'PrepareAndQuiesce') {
    $PrepareNonce = New-AdminPrepareNonce
    $PrepareNonceSha256 = Get-Sha256HexFromBytes -Bytes (
        ConvertFrom-HexString -Value $PrepareNonce
    )
    if ($ExistingTaskFoundAtPrepare) {
        $ReservationKind = 'existing_task_quiesced'
        $ReservationDescription = [string]$Existing.Description
    } else {
        $ReservationKind = 'maintenance_placeholder'
        $ReservationDescription = Get-MaintenanceReservationDescription `
            -PrepareNonceSha256 $PrepareNonceSha256
        [void](New-MaintenanceReservationTask -Description $ReservationDescription)
    }
    $PrepareReceipt = New-AdminPrepareReceipt `
        -ExistingTaskFound $ExistingTaskFoundAtPrepare `
        -Nonce $PrepareNonce `
        -ReservationKind $ReservationKind `
        -ReservationDescription $ReservationDescription
    [ordered]@{
        artifact_sha256 = $ArtifactSha256
        artifact_verified = $true
        current_user_sid_verified = $true
        installer_sha256 = $ExpectedInstallerSha256
        installer_verified = $true
        manifest_sha256 = $ManifestSha256
        manifest_verified = $true
        mandatory_label_reader_sha256 = $ExpectedMandatoryLabelReaderSha256
        prepare_nonce = [string]$PrepareReceipt.Nonce
        prepare_receipt_format = 'TenderBot.LiveInbound.AdminPrepareReceipt.v1'
        prepare_receipt_sha256 = [string]$PrepareReceipt.ReceiptSha256
        prepare_receipt_verified = $true
        reservation_kind = $ReservationKind
        release_pinned = $true
        release_sha256 = $ReleaseSha256
        runtime_payload_verified = $true
        runtime_signature_verified = $true
        runtime_sha256 = $RuntimeSha256
        source_component_contract_verified = $true
        source_git_head_claim = $ExpectedGitHead
        status_script_sha256 = $ExpectedStatusScriptSha256
        existing_task_found = $ExistingTaskFoundAtPrepare
        status = 'release_prepared_task_quiesced_pending_revoke'
        task_mutated = $true
        task_name_reserved = $true
        task_quiesced = $true
        task_name = $TaskName
    } | ConvertTo-Json -Compress
    return
}

$ActionArguments = (
    "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass " +
    "-File `"$LauncherPath`" " +
    "-ReleaseSha256 $ReleaseSha256 -RuntimeSha256 $RuntimeSha256 " +
    "-ManifestSha256 $ManifestSha256 -ArtifactSha256 $ArtifactSha256 " +
    "-MandatoryLabelReaderSha256 $ExpectedMandatoryLabelReaderSha256 " +
    "-ExpectedSid $CurrentSid -StateDir `"$StateDir`" " +
    "-IntervalSeconds $IntervalSeconds -Command serve"
)
$Description = (
    "$TaskMarker; release_sha256=$ReleaseSha256; runtime_sha256=$RuntimeSha256; " +
    "manifest_sha256=$ManifestSha256; artifact_sha256=$ArtifactSha256; " +
    "status_script_sha256=$ExpectedStatusScriptSha256; " +
    "mandatory_label_reader_sha256=$ExpectedMandatoryLabelReaderSha256; " +
    "interval_seconds=$IntervalSeconds. IMAP INBOX and native Bitrix Mail activity " +
    "observation; local evidence and review only; no CRM writes, no operator Todo, " +
    "no outbound email, no UniSender send, no TenderPlan access."
)

$TaskSddl = (
    'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' +
    "(A;;FRFX;;;$CurrentSid)"
)
$RegistrationScheduler = New-Object -ComObject 'Schedule.Service'
$RegistrationScheduler.Connect()
$Folder = $RegistrationScheduler.GetFolder('\')
$Definition = $RegistrationScheduler.NewTask(0)
$Definition.RegistrationInfo.Description = $Description
$Definition.Principal.UserId = $CurrentSid
$Definition.Principal.LogonType = 3
$Definition.Principal.RunLevel = 0
$ComAction = $Definition.Actions.Create(0)
$ComAction.Id = 'Serve'
$ComAction.Path = $PowerShellPath
$ComAction.Arguments = $ActionArguments
$ComAction.WorkingDirectory = $ReleaseDir
$ComTrigger = $Definition.Triggers.Create(9)
$ComTrigger.Id = 'Logon'
$ComTrigger.Enabled = $true
$ComTrigger.UserId = $CurrentSid
$Definition.Settings.AllowDemandStart = $true
$Definition.Settings.DisallowStartIfOnBatteries = $false
$Definition.Settings.Enabled = $false
$Definition.Settings.ExecutionTimeLimit = 'PT0S'
$Definition.Settings.Hidden = $true
$Definition.Settings.MultipleInstances = 2
$Definition.Settings.RestartCount = 999
$Definition.Settings.RestartInterval = 'PT1M'
$Definition.Settings.StartWhenAvailable = $true
$Definition.Settings.StopIfGoingOnBatteries = $false
$TaskCreateOrUpdateDisabledExactAcl = 6 -bor 8 -bor 16
if ($TaskCreateOrUpdateDisabledExactAcl -ne 30) {
    throw 'Task Scheduler registration flags contract is invalid.'
}
$RegisteredCom = $Folder.RegisterTaskDefinition(
    $TaskName,
    $Definition,
    $TaskCreateOrUpdateDisabledExactAcl,
    $CurrentSid,
    $null,
    3,
    $TaskSddl
)
if ($null -eq $RegisteredCom -or [bool]$RegisteredCom.Enabled) {
    throw 'Scheduled Task atomic disabled registration failed.'
}
$RegisteredCom.SetSecurityDescriptor($TaskSddl, 0x10)
$TaskSddlReadback = $RegisteredCom.GetSecurityDescriptor(0x07)
Assert-TaskSecurityDescriptor -Sddl $TaskSddlReadback -ExecutionSid $CurrentSid

$RegisteredMatches = @(
    Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction Stop
)
if ($RegisteredMatches.Count -ne 1) {
    throw 'Scheduled Task protected readback is ambiguous.'
}
$Registered = $RegisteredMatches[0]
$RegisteredActions = @($Registered.Actions)
$RegisteredTriggers = @($Registered.Triggers)
$RegisteredAction = if ($RegisteredActions.Count -eq 1) {
    $RegisteredActions[0]
} else {
    $null
}
$RegisteredSid = Resolve-SidValue -IdentityReference $Registered.Principal.UserId
$Verified = (
    $null -ne $RegisteredAction -and
    $RegisteredTriggers.Count -eq 1 -and
    $RegisteredTriggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and
    (Resolve-SidValue -IdentityReference $RegisteredTriggers[0].UserId) -ceq $CurrentSid -and
    ([string]$Registered.TaskPath -ceq '\') -and
    ([string]$Registered.Description -ceq $Description) -and
    ([string]$RegisteredAction.Execute).Equals(
        $PowerShellPath, [StringComparison]::OrdinalIgnoreCase
    ) -and
    ([string]$RegisteredAction.WorkingDirectory).Equals(
        $ReleaseDir, [StringComparison]::OrdinalIgnoreCase
    ) -and
    ([string]$RegisteredAction.Arguments -ceq $ActionArguments) -and
    ($RegisteredSid -ceq $CurrentSid) -and
    ([string]$Registered.Principal.LogonType -in @('Interactive', 'InteractiveToken')) -and
    ([string]$Registered.Principal.RunLevel -eq 'Limited') -and
    ([string]$Registered.Settings.MultipleInstances -eq 'IgnoreNew') -and
    -not [bool]$Registered.Settings.Enabled -and
    [bool]$Registered.Settings.Hidden -and
    [bool]$Registered.Settings.StartWhenAvailable -and
    -not [bool]$Registered.Settings.DisallowStartIfOnBatteries -and
    -not [bool]$Registered.Settings.StopIfGoingOnBatteries -and
    ([string]$Registered.Settings.ExecutionTimeLimit -eq 'PT0S') -and
    ([int]$Registered.Settings.RestartCount -eq 999) -and
    ([string]$Registered.Settings.RestartInterval -eq 'PT1M')
)
if (-not $Verified) {
    throw 'Scheduled Task protected readback verification failed.'
}

[ordered]@{
    action_verified = $true
    artifact_sha256 = $ArtifactSha256
    artifact_verified = $true
    authority_revocation_correlation_sha256 = $ExpectedRevocationCorrelationSha256
    caller_revocation_correlation_recorded = $true
    current_user_sid_verified = $true
    integrity_acl_verified = $true
    installer_sha256 = $ExpectedInstallerSha256
    installer_verified = $true
    manifest_sha256 = $ManifestSha256
    manifest_verified = $true
    mandatory_label_reader_sha256 = $ExpectedMandatoryLabelReaderSha256
    prepare_nonce_verified = $true
    prepare_receipt_format = 'TenderBot.LiveInbound.AdminPrepareReceipt.v1'
    prepare_receipt_sha256 = [string]$ProtectedPrepareReceipt.ReceiptSha256
    prepare_receipt_verified = $true
    reservation_kind = [string]$ProtectedPrepareReceipt.Receipt.reservation_kind
    release_pinned = $true
    release_sha256 = $ReleaseSha256
    runtime_sha256 = $RuntimeSha256
    runtime_payload_verified = $true
    runtime_signature_verified = $true
    source_component_contract_verified = $true
    source_git_head_claim = $ExpectedGitHead
    status_script_sha256 = $ExpectedStatusScriptSha256
    status = 'installed_not_authorized'
    task_enabled = $false
    task_acl_verified = $true
    task_name = $TaskName
    task_name_reserved = $true
} | ConvertTo-Json -Compress
