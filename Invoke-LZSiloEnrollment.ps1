<#
.SYNOPSIS
    Enrolls accounts into the appropriate Authentication Policy Silo for their tier.

.DESCRIPTION
    Operator-invoked script (NOT called by Deploy-ADLandingZone.ps1).
    Enrollment is always a deliberate, explicit administrative action.

    For each account in the provided list, this script:
      1. Verifies the account exists in AD.
      2. Verifies the account is located within the expected tier OU
         (OU=_LZ_T{Tier} subtree). Accounts outside this OU are rejected
         with a warning -- this prevents accidentally enrolling accounts
         from the wrong tier or from outside the LZ structure.
      3. Enrolls the account into the silo via
         Grant-ADAuthenticationPolicySiloAccess.
      4. Logs every action (enrolled, skipped, rejected, error).

    The silo must already exist (created by Deploy-ADLandingZone.ps1).

    Re-running this script against already-enrolled accounts logs them as
    Skipped and makes no changes.

.PARAMETER Tier
    The tier number (0, 1, or 2) for enrollment.
    Determines which silo the accounts are enrolled in:
        0 -> LZ-T0-Silo
        1 -> LZ-T1-Silo
        2 -> LZ-T2-Silo

.PARAMETER Accounts
    Array of account SamAccountNames to enroll.

.PARAMETER LogPath
    Full path to the CSV log file.

.PARAMETER Force
    If specified, skips the per-account OU location check.
    Use only when you have a deliberate reason to enroll an account that
    is not yet in the expected tier OU (e.g. staged migration).
    Each bypassed check is logged as a Warning, not a Skipped.

.EXAMPLE
    .\Invoke-LZSiloEnrollment.ps1 -Tier 0 -Accounts @('t0-admin1','t0-admin2') -LogPath C:\Logs\silo-enroll.csv

.EXAMPLE
    .\Invoke-LZSiloEnrollment.ps1 -Tier 1 -Accounts @('t1-svcacct') -LogPath C:\Logs\silo-enroll.csv -Force

.NOTES
    Run from a Domain Admin session. The AD and GroupPolicy modules must be
    available. The deployer must have run successfully first.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateRange(0, 9)]
    [int]$Tier,

    [Parameter(Mandatory)]
    [string[]]$Accounts,

    [Parameter(Mandatory)]
    [string]$LogPath,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\Helpers\Write-LZLog.ps1"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "FATAL: ActiveDirectory module unavailable: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

try {
    $domain     = Get-ADDomain
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
}
catch {
    Write-Host "FATAL: Cannot retrieve domain context: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$module    = 'SiloEnrollment'
$siloName  = "LZ-T$Tier-Silo"
$tierOuDN  = "OU=_LZ_T$Tier,$DomainDN"

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "  Silo Enrollment Tool  [v2]" -ForegroundColor Cyan
Write-Host "  Tier     : $Tier  ->  Silo: $siloName" -ForegroundColor Cyan
Write-Host "  Accounts : $($Accounts.Count)" -ForegroundColor Cyan
Write-Host "  Domain   : $DomainFQDN" -ForegroundColor Cyan
Write-Host "  Force    : $($Force.IsPresent)" -ForegroundColor $(if ($Force) { 'Yellow' } else { 'Cyan' })
Write-Host "  LogPath  : $LogPath" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Verify the silo exists.
# ------------------------------------------------------------------
try {
    Get-ADAuthenticationPolicySilo -Identity $siloName -ErrorAction Stop | Out-Null
}
catch {
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
        -ObjectType 'Silo' -ObjectDN "CN=$siloName,CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,$DomainDN" `
        -Detail "Silo '$siloName' not found. Run Deploy-ADLandingZone.ps1 first. Error: $($_.Exception.Message)"
    Write-Host "FATAL: Silo '$siloName' does not exist. Run the deployer first." -ForegroundColor Red
    exit 1
}

Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
    -ObjectType 'Silo' -ObjectDN $siloName `
    -Detail "Silo '$siloName' verified. Processing $($Accounts.Count) account(s)."

# ------------------------------------------------------------------
# Process each account.
# ------------------------------------------------------------------
$enrolled = 0
$skipped  = 0
$rejected = 0
$errors   = 0

foreach ($accountName in $Accounts) {

    $accountDN = $null

    # Step 1: Resolve the account.
    $adAccount = $null
    try {
        $adAccount = Get-ADUser -Identity $accountName -Properties DistinguishedName -ErrorAction Stop
        $accountDN = $adAccount.DistinguishedName
    }
    catch {
        try {
            # Try as a computer account if not found as user.
            $adAccount = Get-ADComputer -Identity $accountName -Properties DistinguishedName -ErrorAction Stop
            $accountDN = $adAccount.DistinguishedName
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'GroupMembership' -ObjectDN "CN=$accountName,$DomainDN" `
                -Detail "Account '$accountName' not found in AD (tried both user and computer). Skipping."
            $errors++
            continue
        }
    }

    # Step 2: Verify the account is in the expected tier OU (unless -Force).
    $inTierOU = $accountDN -like "*$tierOuDN"

    if (-not $inTierOU) {
        if ($Force) {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
                -ObjectType 'GroupMembership' -ObjectDN $accountDN `
                -Detail ("Account '$accountName' is NOT in '$tierOuDN' " +
                         "(actual location: $accountDN). " +
                         "-Force specified -- bypassing OU check. " +
                         "Verify this is intentional.")
        }
        else {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'GroupMembership' -ObjectDN $accountDN `
                -Detail ("Account '$accountName' is NOT in tier OU '$tierOuDN' " +
                         "(actual location: $accountDN). " +
                         "Enrollment rejected. Move the account to the correct tier OU first, " +
                         "or use -Force to bypass this check.")
            $rejected++
            continue
        }
    }

    # Step 3: Check if already enrolled.
    $alreadyEnrolled = $false
    try {
        # Get-ADAuthenticationPolicySiloData returns accounts enrolled in the silo.
        # We compare the account DN to the enrolled members.
        $enrolled_accounts = @(Get-ADAuthenticationPolicySiloData -Identity $siloName -ErrorAction Stop)
        $alreadyEnrolled = ($enrolled_accounts | Where-Object { $_.DistinguishedName -eq $accountDN }) -ne $null
    }
    catch {
        # If the cmdlet fails, assume not enrolled and attempt enrollment.
        # Grant-ADAuthenticationPolicySiloAccess is idempotent.
    }

    if ($alreadyEnrolled) {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
            -ObjectType 'GroupMembership' -ObjectDN $accountDN `
            -Detail "Account '$accountName' is already enrolled in silo '$siloName'. No changes made."
        $skipped++
        continue
    }

    # Step 4: Enroll.
    if ($PSCmdlet.ShouldProcess("$accountName -> $siloName", 'Enroll in Authentication Policy Silo')) {
        try {
            Grant-ADAuthenticationPolicySiloAccess `
                -Identity $siloName `
                -Account  $accountName `
                -ErrorAction Stop

            Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                -ObjectType 'GroupMembership' -ObjectDN $accountDN `
                -Detail "Enrolled '$accountName' into silo '$siloName'."
            $enrolled++
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'GroupMembership' -ObjectDN $accountDN `
                -Detail "Failed to enroll '$accountName' into '$siloName': $($_.Exception.Message)"
            $errors++
        }
    }
}

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "  Silo Enrollment Summary" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "  Silo     : $siloName" -ForegroundColor Cyan
Write-Host "  Enrolled : $enrolled" -ForegroundColor Green
Write-Host "  Skipped  : $skipped"  -ForegroundColor Yellow
Write-Host "  Rejected : $rejected" -ForegroundColor $(if ($rejected -gt 0) { 'Magenta' } else { 'White' })
$errColor = if ($errors -gt 0) { 'Red' } else { 'White' }
Write-Host "  Errors   : $errors"   -ForegroundColor $errColor
Write-Host "  Log      : $LogPath"  -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

if ($errors -gt 0) { exit 1 }
