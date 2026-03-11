<#
.SYNOPSIS
    Runs the full AD Landing Zone Pester test suite and reports results.

.DESCRIPTION
    Orchestrates all LZ test files. Tests are read-only -- no AD objects are
    created or modified. Run this after any deployment or incremental run to
    verify the expected state.

    Requires Pester 5.0 or later. Install with:
        Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck

    All test files derive domain context from the ambient session via
    Get-ADDomain -- no parameters are passed to individual test files.
    Run from a session authenticated as a Domain Admin.

.PARAMETER TierCount
    Expected number of tiers in the deployment. Passed to test files that
    need to know which tier objects to expect. Default 3.

.PARAMETER OutputPath
    Optional path for a Pester NUnit XML report. Useful for CI integration.
    If omitted, results are written to the console only.

.PARAMETER Tag
    Optional Pester tag filter. Valid tags: OUs, Groups, ACLs, AuthPolicies,
    ProtectedUsers, gMSAs, GPOs, Canary. Omit to run all tests.

    The Canary tag runs behavioral and isolation tests in LZ-Canary.Tests.ps1,
    including ProtectedFromAccidentalDeletion enforcement, cross-tier write
    isolation checks, and AdminSDHolder protection awareness.

.EXAMPLE
    .\Tests\Invoke-LZPesterTests.ps1 -TierCount 3

.EXAMPLE
    .\Tests\Invoke-LZPesterTests.ps1 -TierCount 3 -OutputPath C:\Logs\LZ-Pester.xml
#>
[CmdletBinding()]
param(
    [ValidateRange(2, 10)]
    [int]$TierCount = 3,

    [string]$OutputPath = '',

    [string[]]$Tag = @()
)

# ------------------------------------------------------------------
# Verify Pester is available at v5+
# ------------------------------------------------------------------
$pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    Write-Host "FATAL: Pester module not found. Install with: Install-Module Pester -MinimumVersion 5.0 -Force" -ForegroundColor Red
    exit 1
}
if ($pester.Version.Major -lt 5) {
    Write-Host "FATAL: Pester $($pester.Version) found but v5+ is required. Upgrade with: Install-Module Pester -MinimumVersion 5.0 -Force" -ForegroundColor Red
    exit 1
}

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

# ------------------------------------------------------------------
# Verify AD module and domain context
# ------------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
}
catch {
    Write-Host "FATAL: Cannot connect to domain -- $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host '  AD Landing Zone Pester Test Suite  [v2]' -ForegroundColor Cyan
Write-Host "  Domain    : $DomainFQDN ($DomainDN)" -ForegroundColor Cyan
Write-Host "  TierCount : $TierCount" -ForegroundColor Cyan
Write-Host "  Pester    : $($pester.Version)" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Configure Pester
# ------------------------------------------------------------------
$config = New-PesterConfiguration

$config.Run.Path = $PSScriptRoot

# Pass TierCount to test files via Pester's Data parameter mechanism
# by exporting it as a well-known environment variable that test files
# can read. We use a dedicated prefix to avoid collisions.
$env:LZ_TEST_TIERCOUNT = $TierCount.ToString()
$env:LZ_TEST_DOMAINDN  = $DomainDN
$env:LZ_TEST_DOMAINFQDN = $DomainFQDN

$config.Output.Verbosity = 'Detailed'

if ($Tag.Count -gt 0) {
    $config.Filter.Tag = $Tag
}

if ($OutputPath) {
    $config.TestResult.Enabled    = $true
    $config.TestResult.OutputPath = $OutputPath
    $config.TestResult.OutputFormat = 'NUnitXml'
    Write-Host "  XML report: $OutputPath" -ForegroundColor Cyan
    Write-Host ''
}

# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
$result = Invoke-Pester -Configuration $config

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host '  Pester Summary' -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan

$passColor = if ($result.FailedCount -gt 0) { 'Red' } else { 'Green' }
Write-Host "  Passed  : $($result.PassedCount)"  -ForegroundColor Green
Write-Host "  Failed  : $($result.FailedCount)"  -ForegroundColor $passColor
Write-Host "  Skipped : $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "  Total   : $($result.TotalCount)"
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

# Clean up environment variables
Remove-Item Env:\LZ_TEST_TIERCOUNT  -ErrorAction SilentlyContinue
Remove-Item Env:\LZ_TEST_DOMAINDN   -ErrorAction SilentlyContinue
Remove-Item Env:\LZ_TEST_DOMAINFQDN -ErrorAction SilentlyContinue

if ($result.FailedCount -gt 0) {
    exit 1
}
exit 0
