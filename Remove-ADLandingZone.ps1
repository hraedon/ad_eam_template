<#
.SYNOPSIS
    Removes the AD Landing Zone (EAM) structure created by Deploy-ADLandingZone.ps1.

.DESCRIPTION
    Removes all objects in the _LZ_ / GS-LZ- namespace in the reverse order they
    were created. Every deletion is logged to a CSV at $LogPath.

    Removal order (reverse of deployment):
      1. Protected Users membership (GS-LZ-T0-Admins)
      2. Authentication Policy Silos
      3. Authentication Policies
      4. gMSA accounts
      5. GPO links, WMI filters, GPO objects
      6. Security groups and CN=_LZ_Groups container
      7. Sub-OUs, Tier OUs, Quarantine OU

    IMPORTANT:
    - Any user, computer, or other objects you manually placed inside _LZ_ OUs
      will cause OU removal to fail. Remove them first, or move them out.
    - GS-LZ-T0-Admins is removed from Protected Users. Any account that was
      indirectly protected through that group membership will immediately lose
      Protected Users protections. Verify operational impact before running.

.PARAMETER TierCount
    Number of tiers that were deployed (must match the original deployment value).

.PARAMETER LogPath
    Output path for the structured removal log (CSV).

.PARAMETER Force
    Switch. When specified, suppresses the interactive confirmation prompt and
    proceeds immediately. Use with caution in automated pipelines.

    Without -Force, the script requires the operator to type 'REMOVE' at the
    console prompt before any deletions occur.

    Note: -WhatIf and -Confirm from PowerShell's SupportsShouldProcess are
    available as built-in parameters but do not propagate to the individual
    removal modules in v2.5. Full -WhatIf support is a v3 enhancement.

.EXAMPLE
    .\Remove-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Remove.csv

.EXAMPLE
    .\Remove-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Remove.csv -Force
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateRange(2, 9)]
    [int]    $TierCount,

    [Parameter(Mandatory)]
    [string] $LogPath,

    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Pre-flight -----------------------------------------------------------

# Resolve domain context from the ambient session.
try {
    $domain     = Get-ADDomain
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
}
catch {
    throw "Cannot retrieve domain context from current session. Error: $($_.Exception.Message)"
}

# Verify Domain Admin.
$currentUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isDomainAdmin = $currentUser.Groups | Where-Object {
    try { $_.Translate([System.Security.Principal.NTAccount]).Value -match 'Domain Admins' }
    catch { $false }
}
if (-not $isDomainAdmin) {
    throw 'Current session is not running as Domain Admin. Launch as a Domain Admin account and retry.'
}

#endregion

#region --- Confirmation prompt --------------------------------------------------

Write-Host ''
Write-Host '========================================================================'
Write-Host '  AD Landing Zone REMOVAL Script'
Write-Host '========================================================================'
Write-Host "  Domain    : $DomainFQDN ($DomainDN)"
Write-Host "  TierCount : $TierCount"
Write-Host "  LogPath   : $LogPath"
Write-Host ''
Write-Host '  This script will PERMANENTLY DELETE:'
Write-Host "    - OUs:         OU=_LZ_T0.._LZ_T$($TierCount-1) and all sub-OUs + OU=_LZ_Quarantine"
Write-Host "    - Groups:      All GS-LZ-* in CN=_LZ_Groups + the container itself"
Write-Host "    - GPOs:        LZ-T0-GPO through LZ-T$($TierCount-1)-GPO, WMI filters, GPO links"
Write-Host "    - AuthPolicy:  LZ-T0..T$($TierCount-1)-AuthPolicy and matching Silos"
Write-Host "    - gMSAs:       gMSA-LZ-T0..T$($TierCount-1)"
Write-Host "    - Memberships: GS-LZ-T0-Admins removed from Protected Users"
Write-Host ''
Write-Host '  Objects you manually placed inside _LZ_ OUs will cause OU removal'
Write-Host '  to fail. Remove or move them before proceeding.'
Write-Host ''

if (-not $Force) {
    $answer = Read-Host "  Type 'REMOVE' to confirm permanent deletion, or anything else to abort"
    if ($answer -ne 'REMOVE') {
        Write-Host '  Aborted. No changes made.'
        exit 0
    }
}

#endregion

#region --- Logging setup --------------------------------------------------------

$logDir = Split-Path -Parent $LogPath
if ($logDir -and -not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Seed the CSV with headers if it does not yet exist.
if (-not (Test-Path $LogPath)) {
    [PSCustomObject]@{
        Timestamp  = ''; Module = ''; Action = ''; ObjectType = ''
        ObjectDN   = ''; Detail = ''
    } | Export-Csv -Path $LogPath -NoTypeInformation
    # Remove the seed row — we just needed the header.
    $null = Import-Csv $LogPath
    [PSCustomObject[]]@() | Export-Csv -Path $LogPath -NoTypeInformation
}

#endregion

#region --- Module execution -----------------------------------------------------

$modulesPath = Join-Path $PSScriptRoot 'Modules'
$helpersPath = Join-Path $PSScriptRoot 'Helpers'

# Common parameter set passed to all removal modules.
$common = @{
    TierCount  = $TierCount
    DomainDN   = $DomainDN
    DomainFQDN = $DomainFQDN
    LogPath    = $LogPath
}

Write-Host ''

# Phase 1: Protected Users
Write-Host "[Phase 1/7] Removing Protected Users membership..."
& "$modulesPath\Remove-LZ-ProtectedUsers.ps1" @common

# Phase 2 & 3: Auth Silos + Auth Policies (handled in single module)
Write-Host "[Phase 2/7] Removing Authentication Policy Silos and Policies..."
& "$modulesPath\Remove-LZ-AuthPolicies.ps1" @common

# Phase 3: gMSAs (must precede OU removal)
Write-Host "[Phase 3/7] Removing gMSA accounts..."
& "$modulesPath\Remove-LZ-gMSAs.ps1" -TierCount $TierCount -DomainDN $DomainDN -LogPath $LogPath

# Phase 4: GPOs + WMI filters
Write-Host "[Phase 4/7] Removing GPOs and WMI filters..."
& "$modulesPath\Remove-LZ-GPOs.ps1" @common

# Phase 5: Security groups + container
Write-Host "[Phase 5/7] Removing security groups and CN=_LZ_Groups container..."
& "$modulesPath\Remove-LZ-Groups.ps1" -TierCount $TierCount -DomainDN $DomainDN -LogPath $LogPath

# Phase 6: OUs (sub-OUs first, then tier OUs, then Quarantine)
Write-Host "[Phase 6/7] Removing OUs..."
& "$modulesPath\Remove-LZ-OUs.ps1" -TierCount $TierCount -DomainDN $DomainDN -LogPath $LogPath

#endregion

#region --- Summary (read from CSV — source of truth) ----------------------------

Write-Host ''
Write-Host "[Phase 7/7] Summary"
Write-Host '========================================================================'

try {
    $log      = Import-Csv -Path $LogPath
    $removed  = ($log | Where-Object { $_.Action -eq 'Removed'  }).Count
    $skipped  = ($log | Where-Object { $_.Action -eq 'Skipped'  }).Count
    $errors   = ($log | Where-Object { $_.Action -eq 'Error'    }).Count

    Write-Host "  Removed : $removed"
    Write-Host "  Skipped : $skipped  (objects not present — already clean)"
    Write-Host "  Errors  : $errors"
    Write-Host "  Log     : $LogPath"
    Write-Host '========================================================================'

    if ($errors -gt 0) {
        Write-Warning "$errors error(s) occurred. Review $LogPath for details."
    }
}
catch {
    Write-Warning "Could not read log file for summary: $($_.Exception.Message)"
}

Write-Host ''
Write-Host '  Remove-ADLandingZone complete.'
Write-Host ''
