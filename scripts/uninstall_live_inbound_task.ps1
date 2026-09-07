[CmdletBinding()]
param(
    [string]$TaskName = 'TenderBot-Live-Mail-Bitrix'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Automated removal is deliberately outside the first V4 release. A correct
# flow needs a protected admin quiesce, a medium-integrity durable revoke, and a
# protected unregister commit. This workspace script must never become an
# unpinned elevated-code path.
[ordered]@{
    automated_uninstall_available = $false
    changed = $false
    preserved = @('scheduled_task', 'release', 'state', 'credentials', 'receipts')
    reason = 'protected_uninstall_workflow_not_released'
    status = 'blocked'
    task_name = $TaskName
} | ConvertTo-Json -Compress
exit 78
