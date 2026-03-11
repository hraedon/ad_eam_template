<#
.SYNOPSIS
    Signs all AD Landing Zone deployer scripts with a code-signing certificate.

.DESCRIPTION
    Applies an Authenticode signature to every .ps1 file in the deployer tree
    using a certificate identified by thumbprint. This is required when the
    target system enforces an AllSigned execution policy (common in domain
    environments controlled by GPO).

    OPERATOR RESPONSIBILITY: Obtaining, storing, and protecting the
    code-signing certificate is the operator's responsibility and is
    intentionally out of scope for this deployer. The certificate must:
      - Have the Code Signing extended key usage (EKU: 1.3.6.1.5.5.7.3.3).
      - Be trusted by the target machine (certificate chain resolves to a
        trusted root in the machine's certificate store).
      - Be accessible in the certificate store of the account running this
        script (typically LocalMachine\My or CurrentUser\My).

    Scripts signed:
      All .ps1 files found recursively under the deployer root (the directory
      containing this file's parent). This includes all deploy modules, removal
      modules, helpers, operator tools, and Pester test files. New scripts added
      to the tree are automatically included without updating this helper.

.PARAMETER Thumbprint
    SHA-1 thumbprint of the code-signing certificate to use.
    Example: 'A1B2C3D4E5F6...' (40 hex characters, no spaces).

.PARAMETER TimestampServer
    Optional. URI of an RFC 3161 timestamp server. Using a timestamp server
    ensures the signature remains valid after the signing certificate expires.
    Recommended for production. Common servers:
      http://timestamp.digicert.com
      http://timestamp.sectigo.com
      http://timestamp.globalsign.com/scripts/timstamp.dll

.EXAMPLE
    .\Helpers\Sign-LZScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...'

.EXAMPLE
    .\Helpers\Sign-LZScripts.ps1 -Thumbprint 'A1B2C3D4E5F6...' `
        -TimestampServer 'http://timestamp.digicert.com'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$Thumbprint,

    [Parameter()]
    [string]$TimestampServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# Resolve the code-signing certificate from the certificate stores.
# Check CurrentUser first, then LocalMachine.
# ------------------------------------------------------------------
$cert = $null
foreach ($store in 'CurrentUser', 'LocalMachine') {
    $cert = Get-ChildItem "Cert:\$store\My\$Thumbprint" -ErrorAction SilentlyContinue
    if ($cert) { break }
}

if (-not $cert) {
    throw "Certificate with thumbprint '$Thumbprint' not found in CurrentUser\My or LocalMachine\My. Ensure the certificate is imported into the correct store."
}

if ($cert.NotAfter -lt (Get-Date)) {
    Write-Warning "Certificate '$($cert.Subject)' expired on $($cert.NotAfter). Signatures applied with an expired certificate will be invalid unless a timestamp server was used."
}

$hasCodeSigningEku = $cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }
if (-not $hasCodeSigningEku) {
    throw "Certificate '$($cert.Subject)' does not have the Code Signing EKU (1.3.6.1.5.5.7.3.3). Use a certificate issued for code signing."
}

Write-Host "Using certificate: $($cert.Subject)" -ForegroundColor Cyan
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Expires    : $($cert.NotAfter)"
Write-Host ''

# ------------------------------------------------------------------
# Enumerate all .ps1 files in the deployer tree.
# Using a recursive glob rather than a hardcoded list so that new
# scripts are automatically included without editing this helper.
# ------------------------------------------------------------------
$root = Split-Path -Parent $PSScriptRoot   # one level up from Helpers\

$scripts = @(
    Get-ChildItem -Path $root -Recurse -Filter '*.ps1' |
        Select-Object -ExpandProperty FullName
)

$signed  = 0
$skipped = 0
$failed  = 0

foreach ($script in $scripts) {
    if (-not (Test-Path $script)) {
        Write-Warning "Script not found, skipping: $script"
        $skipped++
        continue
    }

    $setParams = @{
        FilePath    = $script
        Certificate = $cert
        ErrorAction = 'Stop'
    }
    if ($TimestampServer) {
        $setParams['TimestampServer'] = $TimestampServer
    }

    try {
        $result = Set-AuthenticodeSignature @setParams

        if ($result.Status -eq 'Valid') {
            Write-Host "  Signed   : $(Split-Path -Leaf $script)" -ForegroundColor Green
            $signed++
        }
        else {
            Write-Host "  FAILED   : $(Split-Path -Leaf $script) -- Status: $($result.Status)" -ForegroundColor Red
            $failed++
        }
    }
    catch {
        Write-Host "  ERROR    : $(Split-Path -Leaf $script) -- $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ''
Write-Host "Signing complete. Signed: $signed  Skipped: $skipped  Failed: $failed" -ForegroundColor $(
    if ($failed -gt 0) { 'Red' } elseif ($skipped -gt 0) { 'Yellow' } else { 'Green' }
)

if (-not $TimestampServer) {
    Write-Host ''
    Write-Host 'NOTE: No timestamp server was specified. Signatures will become invalid when' -ForegroundColor Yellow
    Write-Host '      the signing certificate expires. Re-run with -TimestampServer for' -ForegroundColor Yellow
    Write-Host '      production use.' -ForegroundColor Yellow
}
