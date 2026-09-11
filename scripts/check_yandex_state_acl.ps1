#Requires -Version 5.1

param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

$ReadyMarker = 'YANDEX_STATE_ACL_READY'
$RejectedMarker = 'YANDEX_STATE_ACL_REJECTED'
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

try {
    $RawArguments = @($args)
    $Scope = $null
    $JobId = $null
    if (
        $RawArguments.Count -notin @(2, 4) -or
        [string]$RawArguments[0] -cne '-Scope'
    ) {
        throw 'arguments are invalid'
    }
    $Scope = [string]$RawArguments[1]
    if ($Scope -ceq 'Root') {
        if ($RawArguments.Count -ne 2) {
            throw 'arguments are invalid'
        }
    } elseif ($Scope -ceq 'Job') {
        if (
            $RawArguments.Count -ne 4 -or
            [string]$RawArguments[2] -cne '-JobId'
        ) {
            throw 'arguments are invalid'
        }
        $JobId = [string]$RawArguments[3]
        $ParsedJobId = [Guid]::Empty
        if (
            [string]::IsNullOrEmpty($JobId) -or
            -not [Guid]::TryParseExact($JobId, 'D', [ref]$ParsedJobId) -or
            $ParsedJobId.ToString('D') -cne $JobId
        ) {
            throw 'job id is invalid'
        }
    } else {
        throw 'scope is invalid'
    }

    $ProfilePath = [Environment]::GetFolderPath('UserProfile')
    if ([string]::IsNullOrEmpty($ProfilePath)) {
        throw 'profile is unavailable'
    }
    $StateRoot = [IO.Path]::GetFullPath(
        (Join-Path $ProfilePath '.codex\local_state\TenderBot\yandex-search')
    )
    $RequestsPath = [IO.Path]::GetFullPath((Join-Path $StateRoot 'requests'))
    $ConnectionPath = [IO.Path]::GetFullPath(
        (Join-Path $StateRoot 'connection.json')
    )
    $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::IsNullOrEmpty($CurrentSid)) {
        throw 'current principal is unavailable'
    }

    Assert-PlainPathAndAcl `
        -LiteralPath $StateRoot `
        -CurrentSid $CurrentSid `
        -Container $true `
        -RootAcl $true
    Assert-PlainPathAndAcl `
        -LiteralPath $RequestsPath `
        -CurrentSid $CurrentSid `
        -Container $true `
        -RootAcl $false
    Assert-PlainPathAndAcl `
        -LiteralPath $ConnectionPath `
        -CurrentSid $CurrentSid `
        -Container $false `
        -RootAcl $false

    if ($Scope -ceq 'Job') {
        $JobPath = [IO.Path]::GetFullPath((Join-Path $RequestsPath $JobId))
        $ClaimsPath = [IO.Path]::GetFullPath(
            (Join-Path $JobPath 'dispatch-claims')
        )
        $JournalPath = [IO.Path]::GetFullPath(
            (Join-Path $JobPath 'request.sqlite')
        )
        $DraftPath = [IO.Path]::GetFullPath(
            (Join-Path $JobPath 'request.draft.json')
        )

        Assert-PlainPathAndAcl `
            -LiteralPath $JobPath `
            -CurrentSid $CurrentSid `
            -Container $true `
            -RootAcl $false
        Assert-PlainPathAndAcl `
            -LiteralPath $ClaimsPath `
            -CurrentSid $CurrentSid `
            -Container $true `
            -RootAcl $false
        Assert-PlainPathAndAcl `
            -LiteralPath $JournalPath `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false
        Assert-PlainPathAndAcl `
            -LiteralPath $DraftPath `
            -CurrentSid $CurrentSid `
            -Container $false `
            -RootAcl $false

        $ExpectedNames = New-Object 'Collections.Generic.HashSet[string]' (
            [StringComparer]::Ordinal
        )
        foreach ($Name in @('dispatch-claims', 'request.sqlite', 'request.draft.json')) {
            [void]$ExpectedNames.Add($Name)
        }
        $ObservedNames = New-Object 'Collections.Generic.HashSet[string]' (
            [StringComparer]::Ordinal
        )
        $Entries = @(Get-ChildItem -LiteralPath $JobPath -Force -ErrorAction Stop)
        if ($Entries.Count -ne $ExpectedNames.Count) {
            throw 'job layout mismatch'
        }
        foreach ($Entry in $Entries) {
            if (
                -not $ExpectedNames.Contains($Entry.Name) -or
                -not $ObservedNames.Add($Entry.Name)
            ) {
                throw 'job layout mismatch'
            }
        }
        if (
            $ObservedNames.Contains('request.json') -or
            $ObservedNames.Contains('retention-activation.json') -or
            $ObservedNames.Count -ne $ExpectedNames.Count
        ) {
            throw 'active job material is forbidden'
        }
        if (@(Get-ChildItem -LiteralPath $ClaimsPath -Force -ErrorAction Stop).Count -ne 0) {
            throw 'dispatch claims must be empty'
        }
    }
} catch {
    [Console]::Out.WriteLine($RejectedMarker)
    exit 2
}

[Console]::Out.WriteLine($ReadyMarker)
exit 0
