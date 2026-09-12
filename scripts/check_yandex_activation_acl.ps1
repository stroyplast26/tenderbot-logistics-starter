#Requires -Version 5.1

param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

$ReadyMarker = 'YANDEX_ACTIVATION_ACL_READY'
$RejectedMarker = 'YANDEX_ACTIVATION_ACL_REJECTED'
$SystemSid = 'S-1-5-18'

function Resolve-SidValue {
    param(
        [Parameter(Mandatory = $true)]
        $IdentityReference
    )

    if ([string]$IdentityReference -match '^S-1-') {
        return [string]$IdentityReference
    }
    return (New-Object Security.Principal.NTAccount(
        [string]$IdentityReference
    )).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
}

function Get-PlainLocalItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [bool]$RequireContainer
    )

    $FullPath = [IO.Path]::GetFullPath($LiteralPath)
    $Anchor = [IO.Path]::GetPathRoot($FullPath)
    if (
        [string]::IsNullOrEmpty($Anchor) -or
        $Anchor -cnotmatch '^[A-Za-z]:\\$' -or
        $FullPath.StartsWith('\\', [StringComparison]::Ordinal)
    ) {
        throw 'unsafe local path'
    }

    $Components = New-Object 'Collections.Generic.List[string]'
    $Current = $FullPath
    while ($true) {
        [void]$Components.Add($Current)
        $Parent = [IO.Directory]::GetParent($Current)
        if ($null -eq $Parent) {
            break
        }
        $Current = $Parent.FullName
    }

    $Leaf = $null
    for ($Index = $Components.Count - 1; $Index -ge 0; $Index--) {
        $Item = Get-Item -LiteralPath $Components[$Index] -Force -ErrorAction Stop
        $LinkProperty = $Item.PSObject.Properties['LinkType']
        if (
            ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (
                $null -ne $LinkProperty -and
                -not [string]::IsNullOrEmpty([string]$LinkProperty.Value)
            )
        ) {
            throw 'path indirection is forbidden'
        }
        if ($Index -gt 0 -and -not $Item.PSIsContainer) {
            throw 'parent path is not a directory'
        }
        if ($Index -eq 0) {
            $Leaf = $Item
        }
    }

    if (
        $null -eq $Leaf -or
        ($RequireContainer -and -not $Leaf.PSIsContainer) -or
        (-not $RequireContainer -and $Leaf.PSIsContainer)
    ) {
        throw 'path type mismatch'
    }
    return $Leaf
}

function Assert-ExactAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$CurrentSid,

        [Parameter(Mandatory = $true)]
        [bool]$Container,

        [Parameter(Mandatory = $true)]
        [bool]$RootAcl
    )

    $Sections = (
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    )
    $Acl = if ($Container) {
        [IO.Directory]::GetAccessControl($LiteralPath, $Sections)
    } else {
        [IO.File]::GetAccessControl($LiteralPath, $Sections)
    }
    $OwnerSid = $Acl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    if ($OwnerSid -cne $CurrentSid) {
        throw 'owner mismatch'
    }
    if ([bool]$Acl.AreAccessRulesProtected -ne $RootAcl) {
        throw 'acl inheritance mismatch'
    }

    $Rules = @(
        $Acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
    )
    if ($Rules.Count -ne 2) {
        throw 'acl rule count mismatch'
    }
    $Seen = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    $ExpectedInheritance = if ($Container) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $ExpectedInherited = -not $RootAcl

    foreach ($Rule in $Rules) {
        $RuleSid = Resolve-SidValue -IdentityReference $Rule.IdentityReference
        if (
            ($RuleSid -cne $CurrentSid -and $RuleSid -cne $SystemSid) -or
            -not $Seen.Add($RuleSid) -or
            $Rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            [int64]$Rule.FileSystemRights -ne
                [int64]([Security.AccessControl.FileSystemRights]::FullControl) -or
            $Rule.InheritanceFlags -ne $ExpectedInheritance -or
            $Rule.PropagationFlags -ne
                [Security.AccessControl.PropagationFlags]::None -or
            [bool]$Rule.IsInherited -ne $ExpectedInherited
        ) {
            throw 'acl rule mismatch'
        }
    }
    if (-not $Seen.Contains($CurrentSid) -or -not $Seen.Contains($SystemSid)) {
        throw 'required acl rule is absent'
    }
}

function Assert-PlainPathAndAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$CurrentSid,

        [Parameter(Mandatory = $true)]
        [bool]$Container,

        [Parameter(Mandatory = $true)]
        [bool]$RootAcl
    )

    $Item = Get-PlainLocalItem `
        -LiteralPath $LiteralPath `
        -RequireContainer $Container
    Assert-ExactAcl `
        -LiteralPath $Item.FullName `
        -CurrentSid $CurrentSid `
        -Container $Container `
        -RootAcl $RootAcl
}

function Assert-ExactDirectoryNames {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedNames
    )

    $Expected = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    foreach ($Name in $ExpectedNames) {
        if (-not $Expected.Add($Name)) {
            throw 'duplicate expected entry'
        }
    }
    $Observed = New-Object 'Collections.Generic.HashSet[string]' (
        [StringComparer]::Ordinal
    )
    $Entries = @(Get-ChildItem -LiteralPath $LiteralPath -Force -ErrorAction Stop)
    if ($Entries.Count -ne $Expected.Count) {
        throw 'directory layout mismatch'
    }
    foreach ($Entry in $Entries) {
        if (-not $Expected.Contains($Entry.Name) -or -not $Observed.Add($Entry.Name)) {
            throw 'directory layout mismatch'
        }
    }
    if ($Observed.Count -ne $Expected.Count) {
        throw 'directory layout mismatch'
    }
}

function Assert-EvidenceDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$SelectedName,

        [Parameter(Mandatory = $true)]
        [string]$CurrentSid
    )

    $SelectedFound = $false
    $Entries = @(Get-ChildItem -LiteralPath $LiteralPath -Force -ErrorAction Stop)
    if ($Entries.Count -eq 0) {
        throw 'evidence is absent'
    }
    foreach ($Entry in $Entries) {
        if ($Entry.Name -cnotmatch '\A[0-9a-f]{64}\.json\z') {
            throw 'evidence layout mismatch'
        }
        Assert-PlainPathAndAcl `
            -LiteralPath $Entry.FullName `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false
        if ($Entry.Name -ceq $SelectedName) {
            $SelectedFound = $true
        }
    }
    if (-not $SelectedFound) {
        throw 'selected evidence is absent'
    }
}

try {
    $RawArguments = @($args)
    if (
        $RawArguments.Count -ne 6 -or
        [string]$RawArguments[0] -cne '-JobId' -or
        [string]$RawArguments[2] -cne '-EvidenceSha256' -or
        [string]$RawArguments[4] -cne '-Phase'
    ) {
        throw 'arguments are invalid'
    }

    $JobId = [string]$RawArguments[1]
    $EvidenceSha256 = [string]$RawArguments[3]
    $Phase = [string]$RawArguments[5]
    $ParsedJobId = [Guid]::Empty
    if (
        [string]::IsNullOrEmpty($JobId) -or
        -not [Guid]::TryParseExact($JobId, 'D', [ref]$ParsedJobId) -or
        $ParsedJobId.ToString('D') -cne $JobId -or
        $EvidenceSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $Phase -cnotin @('Draft', 'Request', 'Retention', 'Active')
    ) {
        throw 'argument value is invalid'
    }

    $ProfilePath = [Environment]::GetFolderPath('UserProfile')
    if ([string]::IsNullOrEmpty($ProfilePath)) {
        throw 'profile is unavailable'
    }
    $StateRoot = [IO.Path]::GetFullPath(
        (Join-Path $ProfilePath '.codex\local_state\TenderBot\yandex-search')
    )
    $RequestsPath = [IO.Path]::GetFullPath((Join-Path $StateRoot 'requests'))
    $ConnectionPath = [IO.Path]::GetFullPath((Join-Path $StateRoot 'connection.json'))
    $JobPath = [IO.Path]::GetFullPath((Join-Path $RequestsPath $JobId))
    $ClaimsPath = [IO.Path]::GetFullPath((Join-Path $JobPath 'dispatch-claims'))
    $JournalPath = [IO.Path]::GetFullPath((Join-Path $JobPath 'request.sqlite'))
    $DraftPath = [IO.Path]::GetFullPath((Join-Path $JobPath 'request.draft.json'))
    $RequestPath = [IO.Path]::GetFullPath((Join-Path $JobPath 'request.json'))
    $RetentionPath = [IO.Path]::GetFullPath(
        (Join-Path $JobPath 'retention-activation.json')
    )
    $RootPinPath = [IO.Path]::GetFullPath(
        (Join-Path $StateRoot 'request-activation.json')
    )
    $EvidenceRoot = [IO.Path]::GetFullPath(
        (Join-Path $StateRoot 'activation-evidence')
    )
    $EvidenceJobPath = [IO.Path]::GetFullPath((Join-Path $EvidenceRoot $JobId))
    $EvidenceName = $EvidenceSha256 + '.json'
    $EvidencePath = [IO.Path]::GetFullPath(
        (Join-Path $EvidenceJobPath $EvidenceName)
    )
    $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::IsNullOrEmpty($CurrentSid)) {
        throw 'current principal is unavailable'
    }

    foreach ($Directory in @($StateRoot, $RequestsPath, $JobPath, $ClaimsPath, $EvidenceRoot, $EvidenceJobPath)) {
        Assert-PlainPathAndAcl `
            -LiteralPath $Directory `
            -CurrentSid $CurrentSid `
            -Container $true `
            -RootAcl ($Directory -ceq $StateRoot)
    }
    $RequestStageEntries = @(
        Get-ChildItem -LiteralPath $RequestsPath -Force -ErrorAction Stop |
            Where-Object {
                $_.Name -ilike ".preparing-$JobId-*" -or
                $_.Name -ilike ".activating-$JobId-*"
            }
    )
    if ($RequestStageEntries.Count -ne 0) {
        throw 'request stage residue is forbidden'
    }
    foreach ($File in @($ConnectionPath, $JournalPath, $DraftPath, $EvidencePath)) {
        Assert-PlainPathAndAcl `
            -LiteralPath $File `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false
    }
    Assert-EvidenceDirectory `
        -LiteralPath $EvidenceJobPath `
        -SelectedName $EvidenceName `
        -CurrentSid $CurrentSid

    $ExpectedJobNames = @('dispatch-claims', 'request.sqlite', 'request.draft.json')
    if ($Phase -cin @('Request', 'Retention', 'Active')) {
        $ExpectedJobNames += 'request.json'
        Assert-PlainPathAndAcl `
            -LiteralPath $RequestPath `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false
    }
    if ($Phase -cin @('Retention', 'Active')) {
        $ExpectedJobNames += 'retention-activation.json'
        Assert-PlainPathAndAcl `
            -LiteralPath $RetentionPath `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false
    }
    Assert-ExactDirectoryNames `
        -LiteralPath $JobPath `
        -ExpectedNames $ExpectedJobNames
    if (@(Get-ChildItem -LiteralPath $ClaimsPath -Force -ErrorAction Stop).Count -ne 0) {
        throw 'dispatch claims must be empty'
    }

    $RootEntries = @(
        Get-ChildItem -LiteralPath $StateRoot -Force -ErrorAction Stop |
            Where-Object { $_.Name -ieq 'request-activation.json' }
    )
    $StageEntries = @(
        Get-ChildItem -LiteralPath $StateRoot -Force -ErrorAction Stop |
            Where-Object { $_.Name -ilike '.request-activation.json.stage-*' }
    )
    if ($StageEntries.Count -ne 0) {
        throw 'root stage residue is forbidden'
    }
    if ($Phase -ceq 'Active') {
        if ($RootEntries.Count -ne 1 -or $RootEntries[0].Name -cne 'request-activation.json') {
            throw 'root activation layout mismatch'
        }
        Assert-PlainPathAndAcl `
            -LiteralPath $RootPinPath `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false
    } elseif ($RootEntries.Count -ne 0) {
        throw 'root activation must be absent'
    }
} catch {
    [Console]::Out.WriteLine($RejectedMarker)
    exit 2
}

[Console]::Out.WriteLine($ReadyMarker)
exit 0
