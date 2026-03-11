<#
.SYNOPSIS
    Orchestrator for the AD Landing Zone deployer.

.DESCRIPTION
    Instantiates an Enterprise Access Model tiered Landing Zone within an
    existing Active Directory domain. Produces modular, idempotent output --
    safe to re-run; existing objects are skipped and logged, never deleted.

    Execution order enforced by this script:
        1. Pre-Flight       (Test-LZPreFlight)
        2. OUs              (Deploy-LZOUs)
        3. Groups           (Deploy-LZGroups)
        4. ACLs             (Deploy-LZACLs)
        5. Auth             (Deploy-LZAuthPolicies)
        6. Protected        (Deploy-LZProtectedUsers)
        7. T0DeviceGroup    (Deploy-LZT0DeviceGroup)   [v2]
        8. gMSAs            (Deploy-LZgMSAs)           [v2, skipped if -DeployGmsas:$false]
        9. GPOs             (Deploy-LZGPOs)            [v2, skipped if -DeployGpos:$false]

    Domain context (FQDN, DN) is derived from the ambient session via
    Get-ADDomain. No domain values are hardcoded or accepted as parameters.

    Requires: PowerShell session authenticated as Domain Admin against the
    target domain. Windows Server 2016+ domain functional level.

.PARAMETER TierCount
    Number of tiers to deploy. Minimum 2 (T0 + T1). Typical value is 3.

.PARAMETER LogPath
    Full path for the structured CSV deployment log.
    The file and its parent directory are created if they do not exist.

.PARAMETER SkipGmsas
    When present, Phase 8 (gMSA provisioning) is skipped. Use this when a KDS
    Root Key is not yet effective or replication is still in progress.
    Phase 7 (T0DeviceGroup) always runs regardless of this switch.

.PARAMETER SkipGpos
    When present, Phase 9 (GPO scaffolding) is skipped. Use this when running
    in an environment without GPMC RSAT installed or when GPO management is
    handled by a separate team.

.EXAMPLE
    .\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv

.EXAMPLE
    .\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv -SkipGmsas

.EXAMPLE
    .\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv -SkipGpos
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateRange(2, 10)]
    [int]$TierCount,

    [Parameter(Mandatory)]
    [string]$LogPath,

    [switch]$SkipGmsas,

    [switch]$SkipGpos
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# Dot-source helpers first (Write-LZLog must be available before any
# module is loaded, since modules reference it at definition time).
# ------------------------------------------------------------------
. "$PSScriptRoot\Helpers\Write-LZLog.ps1"
. "$PSScriptRoot\Helpers\Test-LZPreFlight.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-OUs.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-Groups.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-ACLs.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-AuthPolicies.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-ProtectedUsers.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-T0DeviceGroup.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-gMSAs.ps1"
. "$PSScriptRoot\Modules\Deploy-LZ-GPOs.ps1"

# ------------------------------------------------------------------
# Ensure the ActiveDirectory module is available.
# ------------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "FATAL: Cannot import the ActiveDirectory module. Install RSAT or run from a domain controller. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------
# Ensure the log directory exists before the first Write-LZLog call.
# (Write-LZLog also does this, but doing it here produces a cleaner
# error message if the path is invalid.)
# ------------------------------------------------------------------
$logDir = Split-Path -Parent $LogPath
if ($logDir -and -not (Test-Path $logDir)) {
    try {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    catch {
        Write-Host "FATAL: Cannot create log directory '$logDir': $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host '  AD Landing Zone Deployer  [v2]' -ForegroundColor Cyan
Write-Host "  TierCount   : $TierCount" -ForegroundColor Cyan
Write-Host "  LogPath     : $LogPath" -ForegroundColor Cyan
Write-Host "  SkipGmsas   : $($SkipGmsas.IsPresent)" -ForegroundColor Cyan
Write-Host "  SkipGpos    : $($SkipGpos.IsPresent)" -ForegroundColor Cyan
Write-Host "  Started     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC+0 (local clock)" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Phase 1 -- Pre-Flight
# Derives domain context and validates environment. Returns a context
# object consumed by all subsequent phases. Any failure throws and
# halts execution before any AD object is created.
# ------------------------------------------------------------------
Write-Host '[Phase 1/9] Pre-Flight Checks' -ForegroundColor Cyan

$context = Test-LZPreFlight -LogPath $LogPath -TierCount $TierCount

$DomainDN   = $context.DomainDN
$DomainFQDN = $context.DomainFQDN

Write-Host ''

# ------------------------------------------------------------------
# Phase 2 -- OU Structure
# ------------------------------------------------------------------
Write-Host '[Phase 2/9] Deploying OU Structure' -ForegroundColor Cyan

Deploy-LZOUs -DomainDN $DomainDN -TierCount $TierCount -LogPath $LogPath

Write-Host ''

# ------------------------------------------------------------------
# Phase 3 -- Security Groups
# Groups must exist before ACLs reference them in Phase 4.
# ------------------------------------------------------------------
Write-Host '[Phase 3/9] Deploying Security Groups' -ForegroundColor Cyan

Deploy-LZGroups -DomainDN $DomainDN -TierCount $TierCount -LogPath $LogPath

Write-Host ''

# ------------------------------------------------------------------
# Phase 4 -- ACL Delegations
# Depends on groups from Phase 3 existing.
# ------------------------------------------------------------------
Write-Host '[Phase 4/9] Applying ACL Delegations' -ForegroundColor Cyan

Deploy-LZACLs -DomainDN $DomainDN -TierCount $TierCount -LogPath $LogPath

Write-Host ''

# ------------------------------------------------------------------
# Phase 5 -- Authentication Policies and Silos
# ------------------------------------------------------------------
Write-Host '[Phase 5/9] Deploying Authentication Policies and Silos' -ForegroundColor Cyan

Deploy-LZAuthPolicies -DomainDN $DomainDN -TierCount $TierCount -LogPath $LogPath

Write-Host ''

# ------------------------------------------------------------------
# Phase 6 -- Protected Users
# ------------------------------------------------------------------
Write-Host '[Phase 6/9] Configuring Protected Users Membership' -ForegroundColor Cyan

Deploy-LZProtectedUsers -DomainDN $DomainDN -LogPath $LogPath

Write-Host ''

# ------------------------------------------------------------------
# Phase 7 -- T0 Device Group and Auth Policy Upgrade  [v2]
# Creates GS-LZ-T0-Devices and upgrades the T0 auth policy SDDL
# from the baseline domain-joined condition to a group-SID condition.
# ------------------------------------------------------------------
Write-Host '[Phase 7/9] Deploying T0 Device Group and Upgrading Auth Policy' -ForegroundColor Cyan

Deploy-LZT0DeviceGroup -DomainDN $DomainDN -LogPath $LogPath

Write-Host ''

# ------------------------------------------------------------------
# Phase 8 -- gMSA Provisioning  [v2]
# Skipped if -DeployGmsas:$false (e.g. KDS Root Key not yet ready).
# ------------------------------------------------------------------
if (-not $SkipGmsas) {
    Write-Host '[Phase 8/9] Provisioning Group Managed Service Accounts' -ForegroundColor Cyan

    Deploy-LZgMSAs `
        -DomainDN   $DomainDN `
        -DomainFQDN $DomainFQDN `
        -TierCount  $TierCount `
        -LogPath    $LogPath
}
else {
    Write-Host '[Phase 8/9] gMSA Provisioning SKIPPED (-SkipGmsas)' -ForegroundColor Yellow

    Write-LZLog -LogPath $LogPath -Module 'Orchestrator' -Action 'Skipped' `
        -ObjectType 'gMSA' -ObjectDN $DomainDN `
        -Detail "gMSA provisioning skipped (-SkipGmsas). Re-run without -SkipGmsas when a KDS Root Key is effective."
}

Write-Host ''

# ------------------------------------------------------------------
# Phase 9 -- GPO Scaffolding  [v2]
# Creates empty GPOs for each tier, links them, adds WMI filter stubs,
# and blocks GPO inheritance on each tier OU.
# Skipped if -DeployGpos:$false or if the GroupPolicy module is absent.
# ------------------------------------------------------------------
if (-not $SkipGpos) {
    Write-Host '[Phase 9/9] Deploying GPO Scaffolding' -ForegroundColor Cyan

    Deploy-LZGPOs `
        -DomainDN   $DomainDN `
        -DomainFQDN $DomainFQDN `
        -TierCount  $TierCount `
        -LogPath    $LogPath
}
else {
    Write-Host '[Phase 9/9] GPO Scaffolding SKIPPED (-SkipGpos)' -ForegroundColor Yellow

    Write-LZLog -LogPath $LogPath -Module 'Orchestrator' -Action 'Skipped' `
        -ObjectType 'GPO' -ObjectDN $DomainDN `
        -Detail "GPO scaffolding skipped (-SkipGpos). Re-run without -SkipGpos to create GPO scaffolds."
}

Write-Host ''

# ------------------------------------------------------------------
# Summary -- read from the CSV log.
#
# The spec requires the summary to be derived from the written log
# rather than from in-memory counters. This also serves as an
# end-to-end validation that the CSV was written correctly: if
# Import-Csv returns no rows, the log pipeline is broken and the
# summary will make that obvious.
# ------------------------------------------------------------------
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host '  Deployment Summary' -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan

# Initialise summary variables so they are accessible outside the try block.
# This ensures the error-detail section always runs independently of whether
# the CSV import itself succeeded.
$logEntries    = @()
$totalCreated  = 0
$totalModified = 0
$totalSkipped  = 0
$totalWarnings = 0
$totalErrors   = 0
$totalEntries  = 0
$summaryOk     = $false

try {
    $logEntries    = @(Import-Csv -Path $LogPath -ErrorAction Stop)
    $totalCreated  = @($logEntries | Where-Object { $_.Action -eq 'Created'  }).Count
    $totalModified = @($logEntries | Where-Object { $_.Action -eq 'Modified' }).Count
    $totalSkipped  = @($logEntries | Where-Object { $_.Action -eq 'Skipped'  }).Count
    $totalWarnings = @($logEntries | Where-Object { $_.Action -eq 'Warning'  }).Count
    $totalErrors   = @($logEntries | Where-Object { $_.Action -eq 'Error'    }).Count
    $totalEntries  = $logEntries.Count
    $summaryOk     = $true
}
catch {
    Write-Host "  WARNING: Could not read deployment log from '$LogPath': $($_.Exception.Message)" -ForegroundColor Magenta
    Write-Host "  The deployment may have completed but the summary cannot be verified." -ForegroundColor Magenta
}

if ($summaryOk) {
    $errColor = if ($totalErrors -gt 0) { 'Red' } else { 'Green' }
    Write-Host "  Total log entries : $totalEntries"
    Write-Host "  Created           : $totalCreated"  -ForegroundColor Green
    Write-Host "  Modified          : $totalModified" -ForegroundColor Cyan
    Write-Host "  Skipped           : $totalSkipped"  -ForegroundColor Yellow
    Write-Host "  Warnings          : $totalWarnings" -ForegroundColor Magenta
    Write-Host "  Errors            : $totalErrors"   -ForegroundColor $errColor
    Write-Host ''
    Write-Host "  Full log          : $LogPath"
}

Write-Host ('=' * 72) -ForegroundColor Cyan

# Error detail section is intentionally outside the try/catch above.
# If the CSV import fails, $totalErrors stays 0 and this block is skipped.
# If the import succeeds but this display loop throws (e.g. a malformed row),
# the error surfaces directly rather than being caught and misreported as a
# log-read failure.
if ($totalErrors -gt 0) {
    Write-Host ''
    Write-Host "  $totalErrors error(s) were recorded. Review the log for details:" -ForegroundColor Red
    $logEntries | Where-Object { $_.Action -eq 'Error' } | ForEach-Object {
        Write-Host "    [$($_.Module)] $($_.ObjectDN): $($_.Detail)" -ForegroundColor Red
    }
    Write-Host ''
}

Write-Host ''
Write-Host "  Domain  : $DomainFQDN" -ForegroundColor Cyan
Write-Host "  Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Post-deployment: T0 hardening reminder
#
# Deploy-LZ-T0Hardening.ps1 is deliberately NOT called by this
# orchestrator -- it populates Restricted Groups and Deny Logon
# settings into LZ-T0-GPO, which should only be applied after the
# operator has verified that all T0 accounts authenticate via
# Kerberos. Applying it prematurely can lock administrators out of
# T0 infrastructure. However, it must not be forgotten.
# ------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Yellow
Write-Host '  NEXT STEP: T0 GPO Hardening' -ForegroundColor Yellow
Write-Host ('=' * 72) -ForegroundColor Yellow
Write-Host ''
Write-Host '  Deploy-LZ-T0Hardening.ps1 has NOT been run automatically.' -ForegroundColor Yellow
Write-Host ''
Write-Host '  This script populates LZ-T0-GPO with:' -ForegroundColor Yellow
Write-Host '    - Restricted Groups: locks local Administrators on T0 devices' -ForegroundColor Yellow
Write-Host '      to Domain Admins + GS-LZ-T0-Admins only.' -ForegroundColor Yellow
Write-Host '    - User Rights: denies interactive and RDP logon to T1/T2 admin' -ForegroundColor Yellow
Write-Host '      groups on T0 assets.' -ForegroundColor Yellow
Write-Host ''
Write-Host '  Run ONLY after verifying that all T0 admin accounts authenticate' -ForegroundColor Yellow
Write-Host '  exclusively via Kerberos. Premature application can lock you out.' -ForegroundColor Yellow
Write-Host ''
Write-Host "  Command: .\Deploy-LZ-T0Hardening.ps1" -ForegroundColor Yellow
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Yellow
Write-Host ''
