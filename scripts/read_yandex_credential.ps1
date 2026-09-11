#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._~-]{2,127}\z')]
    [string]$ExpectedFolderId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$BrokerExitCode = 2
$BrokerPointer = [IntPtr]::Zero
$BrokerSecure = $null
$BrokerPlain = $null
$BrokerKeyBytes = $null
$BrokerDigestBytes = $null
$BrokerSha256 = $null
$BrokerCredential = $null
$BrokerConnection = $null
$BrokerCredentialJson = $null
$BrokerConnectionJson = $null

function Test-ExactPropertySet {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    $Actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $Wanted = @($Expected | Sort-Object)
    return @(
        Compare-Object -ReferenceObject $Wanted -DifferenceObject $Actual -CaseSensitive
    ).Count -eq 0
}

function Assert-FixedItem {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Leaf
    )

    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'BROKER_PATH_REJECTED'
    }
    if ($Leaf -and $Item.PSIsContainer) {
        throw 'BROKER_PATH_REJECTED'
    }
    if ((-not $Leaf) -and (-not $Item.PSIsContainer)) {
        throw 'BROKER_PATH_REJECTED'
    }
}

try {
    # The helper is an internal pipe endpoint, not an operator command.  Refuse
    # an interactive console before opening or decrypting the credential.
    if (-not [Console]::IsOutputRedirected) {
        throw 'BROKER_OUTPUT_NOT_REDIRECTED'
    }

    $BrokerUserProfile = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::UserProfile
    )
    if ([string]::IsNullOrWhiteSpace($BrokerUserProfile)) {
        throw 'BROKER_PATH_REJECTED'
    }
    $BrokerUserProfile = [IO.Path]::GetFullPath($BrokerUserProfile)
    $BrokerCodexRoot = Join-Path $BrokerUserProfile '.codex'
    $BrokerLocalState = Join-Path $BrokerCodexRoot 'local_state'
    $BrokerProductRoot = Join-Path $BrokerLocalState 'TenderBot'
    $BrokerStateRoot = Join-Path $BrokerProductRoot 'yandex-search'
    $BrokerCredentialPath = Join-Path $BrokerStateRoot 'credential.json'
    $BrokerConnectionPath = Join-Path $BrokerStateRoot 'connection.json'

    foreach ($BrokerDirectory in @(
        $BrokerUserProfile,
        $BrokerCodexRoot,
        $BrokerLocalState,
        $BrokerProductRoot,
        $BrokerStateRoot
    )) {
        Assert-FixedItem -Path $BrokerDirectory -Leaf $false
    }
    Assert-FixedItem -Path $BrokerCredentialPath -Leaf $true
    Assert-FixedItem -Path $BrokerConnectionPath -Leaf $true

    $BrokerCredentialItem = Get-Item -LiteralPath $BrokerCredentialPath -Force
    $BrokerConnectionItem = Get-Item -LiteralPath $BrokerConnectionPath -Force
    if (
        $BrokerCredentialItem.Length -le 0 -or
        $BrokerCredentialItem.Length -gt 16384 -or
        $BrokerConnectionItem.Length -le 0 -or
        $BrokerConnectionItem.Length -gt 16384
    ) {
        throw 'BROKER_FILE_REJECTED'
    }

    $BrokerUtf8 = New-Object Text.UTF8Encoding($false, $true)
    $BrokerCredentialJson = [IO.File]::ReadAllText($BrokerCredentialPath, $BrokerUtf8)
    $BrokerConnectionJson = [IO.File]::ReadAllText($BrokerConnectionPath, $BrokerUtf8)
    $BrokerCredential = $BrokerCredentialJson | ConvertFrom-Json
    $BrokerConnection = $BrokerConnectionJson | ConvertFrom-Json

    $BrokerCredentialProperties = @(
        'api_key_id',
        'encryption',
        'expires_at',
        'folder_id',
        'saved_at',
        'scope',
        'secret_dpapi',
        'service_account_id',
        'version'
    )
    $BrokerConnectionProperties = @(
        'api_key_id',
        'credential_sha256',
        'expires_at',
        'folder_id',
        'owner_instruction_sha256',
        'registered_at_utc',
        'scope',
        'service_account_id',
        'status',
        'version'
    )
    if (
        -not (Test-ExactPropertySet -Value $BrokerCredential -Expected $BrokerCredentialProperties) -or
        -not (Test-ExactPropertySet -Value $BrokerConnection -Expected $BrokerConnectionProperties)
    ) {
        throw 'BROKER_METADATA_REJECTED'
    }

    $BrokerIdentifierPattern = '\A[A-Za-z0-9][A-Za-z0-9._~-]{2,127}\z'
    if (
        $BrokerCredential.version -cne 'tenderbot-yandex-credential-v1' -or
        $BrokerCredential.encryption -cne 'Windows DPAPI CurrentUser via PowerShell SecureString' -or
        $BrokerConnection.version -cne 'radar-yandex-connection-v1' -or
        $BrokerConnection.status -cne 'ACTIVE' -or
        $BrokerCredential.folder_id -cne $ExpectedFolderId -or
        $BrokerConnection.folder_id -cne $ExpectedFolderId -or
        $BrokerCredential.service_account_id -cne $BrokerConnection.service_account_id -or
        $BrokerCredential.api_key_id -cne $BrokerConnection.api_key_id -or
        [string]$BrokerCredential.service_account_id -cnotmatch $BrokerIdentifierPattern -or
        [string]$BrokerCredential.api_key_id -cnotmatch $BrokerIdentifierPattern -or
        $BrokerCredential.scope -cne 'yc.search-api.execute' -or
        $BrokerConnection.scope -cne 'yc.search-api.execute' -or
        $null -ne $BrokerCredential.expires_at -or
        $null -ne $BrokerConnection.expires_at -or
        [string]$BrokerConnection.credential_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        [string]$BrokerConnection.owner_instruction_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        [string]$BrokerCredential.secret_dpapi -cnotmatch '\A[0-9A-Fa-f]{64,8192}\z'
    ) {
        throw 'BROKER_METADATA_REJECTED'
    }

    $BrokerSecure = ConvertTo-SecureString -String ([string]$BrokerCredential.secret_dpapi)
    $BrokerPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BrokerSecure)
    $BrokerPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BrokerPointer)
    if ($BrokerPlain -cnotmatch '\A[A-Za-z0-9._~-]{16,512}\z') {
        throw 'BROKER_CREDENTIAL_REJECTED'
    }

    $BrokerKeyBytes = [Text.Encoding]::UTF8.GetBytes($BrokerPlain)
    $BrokerSha256 = [Security.Cryptography.SHA256]::Create()
    $BrokerDigestBytes = $BrokerSha256.ComputeHash($BrokerKeyBytes)
    $BrokerFingerprint = -join @(
        $BrokerDigestBytes | ForEach-Object { $_.ToString('x2') }
    )
    if ($BrokerFingerprint -cne [string]$BrokerConnection.credential_sha256) {
        throw 'BROKER_CREDENTIAL_REJECTED'
    }

    # This is the helper's only success output.  The Python parent captures it
    # privately; it is never inherited through argv or an environment variable.
    [Console]::Out.Write($BrokerPlain)
    $BrokerExitCode = 0
} catch {
    # Never include the underlying exception, a path, metadata, or child output.
    [Console]::Error.WriteLine('YANDEX_CREDENTIAL_HELPER_REJECTED')
    $BrokerExitCode = 2
} finally {
    try {
        if ($null -ne $BrokerKeyBytes) {
            [Array]::Clear($BrokerKeyBytes, 0, $BrokerKeyBytes.Length)
        }
    } catch {
        # Cleanup is best-effort and must not produce a diagnostic error.
    }
    try {
        if ($null -ne $BrokerDigestBytes) {
            [Array]::Clear($BrokerDigestBytes, 0, $BrokerDigestBytes.Length)
        }
    } catch {
    }
    try {
        if ($null -ne $BrokerSha256) {
            $BrokerSha256.Dispose()
        }
    } catch {
    }
    try {
        if ($BrokerPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BrokerPointer)
            $BrokerPointer = [IntPtr]::Zero
        }
    } catch {
    }
    try {
        if ($null -ne $BrokerSecure) {
            $BrokerSecure.Dispose()
        }
    } catch {
    }
    $BrokerPlain = $null
    $BrokerFingerprint = $null
    $BrokerCredential = $null
    $BrokerConnection = $null
    $BrokerCredentialJson = $null
    $BrokerConnectionJson = $null
}

exit $BrokerExitCode
