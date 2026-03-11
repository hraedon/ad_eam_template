<#
.SYNOPSIS
    Applies Tier 0 hardening settings to the LZ-T0-GPO.

.DESCRIPTION
    Operator-invoked script (NOT called by Deploy-ADLandingZone.ps1).
    Run after the deployer has created the GPO scaffold.

    Populates two security configuration sections in LZ-T0-GPO's GptTmpl.inf:

    1. Restricted Groups
       Constrains membership of the local Administrators group on T0 devices
       to Domain Admins and GS-LZ-T0-Admins only. This prevents lateral
       movement from lower-tier accounts gaining local administrator access
       on T0 infrastructure.

       GptTmpl.inf [Group Membership] syntax:
           *<Builtin-Admins-SID>__Memberof =
           *<Builtin-Admins-SID>__Members = *<Domain-Admins-SID>,*<GS-LZ-T0-Admins-SID>

    2. User Rights Assignment
       Denies the following logon types to T1 and T2 admin groups on T0 assets:
           SeDenyInteractiveLogonRight      (Deny log on locally)
           SeDenyRemoteInteractiveLogonRight (Deny log on through RDP)

       Groups denied: GS-LZ-T1-Admins, GS-LZ-T2-Admins.
       (T0 accounts are not in this deny list -- they must be able to log on.)

    Why GptTmpl.inf instead of the GroupPolicy module?
        The PowerShell GroupPolicy module's Set-GPRegistryValue cmdlet only
        covers registry-based settings. Restricted Groups and User Rights
        Assignment are security template settings stored in GptTmpl.inf.
        The GPMC COM API can modify these, but it requires a GUI-capable
        Windows session context. Direct GptTmpl.inf editing with subsequent
        GPO metadata updates (gPCMachineExtensionNames, gPCVersion) is the
        most portable and auditable approach available in a pure PowerShell
        context and is documented as the authoritative method for scripted
        security template management.

    After writing GptTmpl.inf, this script increments the GPO version number
    and updates gPCMachineExtensionNames to include the Security Settings
    extension GUID, so domain clients know the GPO has security settings to
    process.

    Idempotent: re-running rewrites GptTmpl.inf with the current group SIDs.
    If group SIDs have not changed, the content is identical and the GPO
    version is not incremented unnecessarily. (Hash comparison guards this.)

    IMPORTANT: This script targets only LZ-T0-GPO and only T0 assets.
    It does not modify T1 or T2 GPOs.

.PARAMETER LogPath
    Full path to the CSV log file.

.EXAMPLE
    .\Deploy-LZ-T0Hardening.ps1 -LogPath C:\Logs\LZ-T0Hardening.csv

.NOTES
    Run from a Domain Admin session after Deploy-ADLandingZone.ps1 has
    completed successfully (GPO scaffold must exist).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\Helpers\Write-LZLog.ps1"

# ------------------------------------------------------------------
# Module imports and domain context
# ------------------------------------------------------------------
try {
    Import-Module ActiveDirectory  -ErrorAction Stop
    Import-Module GroupPolicy      -ErrorAction Stop
}
catch {
    Write-Host "FATAL: Required modules unavailable: $($_.Exception.Message)" -ForegroundColor Red
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

$module  = 'T0Hardening'
$gpoName = 'LZ-T0-GPO'

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "  T0 Hardening Script  [v2]" -ForegroundColor Cyan
Write-Host "  GPO     : $gpoName" -ForegroundColor Cyan
Write-Host "  Domain  : $DomainFQDN" -ForegroundColor Cyan
Write-Host "  LogPath : $LogPath" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Verify the GPO exists
# ------------------------------------------------------------------
$gpo = $null
try {
    $gpo = Get-GPO -Name $gpoName -Domain $DomainFQDN -ErrorAction Stop
}
catch {
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
        -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
        -Detail "GPO '$gpoName' not found. Run Deploy-ADLandingZone.ps1 first to create the GPO scaffold. Error: $($_.Exception.Message)"
    Write-Host "FATAL: GPO '$gpoName' does not exist. Run the deployer first." -ForegroundColor Red
    exit 1
}

Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
    -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
    -Detail "Found GPO '$gpoName' (GUID: $($gpo.Id))."

# ------------------------------------------------------------------
# Resolve required group SIDs
# ------------------------------------------------------------------
function Resolve-SID {
    param([string]$GroupName)
    try {
        $g = Get-ADGroup -Identity $GroupName -ErrorAction Stop
        return $g.SID.Value
    }
    catch {
        throw "Cannot resolve SID for group '$GroupName': $($_.Exception.Message)"
    }
}

$sidBuiltinAdmins  = 'S-1-5-32-544'    # BUILTIN\Administrators -- well-known SID, no lookup needed
$sidDomainAdmins   = $null
$sidT0Admins       = $null
$sidT1Admins       = $null
$sidT2Admins       = $null

try {
    $sidDomainAdmins = Resolve-SID 'Domain Admins'
    $sidT0Admins     = Resolve-SID 'GS-LZ-T0-Admins'
    $sidT1Admins     = Resolve-SID 'GS-LZ-T1-Admins'
    $sidT2Admins     = Resolve-SID 'GS-LZ-T2-Admins'

    Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
        -ObjectType 'Group' -ObjectDN $DomainDN `
        -Detail ("SIDs resolved. DomainAdmins=$sidDomainAdmins  T0Admins=$sidT0Admins  " +
                 "T1Admins=$sidT1Admins  T2Admins=$sidT2Admins")
}
catch {
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
        -ObjectType 'Group' -ObjectDN $DomainDN `
        -Detail "Failed to resolve required group SIDs: $($_.Exception.Message)"
    Write-Host "FATAL: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------
# Locate the GPO's SYSVOL machine security template path.
# Path: \\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\Machine\
#                 Microsoft\Windows NT\SecEdit\GptTmpl.inf
# ------------------------------------------------------------------
$gpoGuid    = $gpo.Id.ToString('B').ToUpper()   # {GUID}
$sysvolRoot = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies"
$gpoPath    = Join-Path $sysvolRoot $gpoGuid
$secEditDir = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit'
$gptTmplPath = Join-Path $secEditDir 'GptTmpl.inf'

if (-not (Test-Path $gpoPath)) {
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
        -ObjectType 'GPO' -ObjectDN $gpoPath `
        -Detail "GPO SYSVOL path not found at '$gpoPath'. SYSVOL may not be replicated yet."
    Write-Host "FATAL: GPO SYSVOL path not found: $gpoPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $secEditDir)) {
    New-Item -ItemType Directory -Path $secEditDir -Force | Out-Null
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
        -ObjectType 'GPO' -ObjectDN $secEditDir `
        -Detail "Created SecEdit directory in GPO SYSVOL path."
}

# ------------------------------------------------------------------
# Build the GptTmpl.inf content.
#
# [Unicode] and [Version] headers are required for Windows to parse
# the file correctly. signature="$CHICAGO$" is the required literal.
#
# [Group Membership]:
#     *<Builtin-Admins-SID>__Members = *<DomainAdmins>,*<T0Admins>
#     The __Memberof key is left blank (group has no mandatory parent
#     membership). Both keys must be present even if __Memberof is empty.
#
# [Privilege Rights]:
#     SeDenyInteractiveLogonRight    = *<T1Admins>,*<T2Admins>
#     SeDenyRemoteInteractiveLogonRight = *<T1Admins>,*<T2Admins>
# ------------------------------------------------------------------
$newContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Group Membership]
*$sidBuiltinAdmins`__Memberof =
*$sidBuiltinAdmins`__Members = *$sidDomainAdmins,*$sidT0Admins
[Privilege Rights]
SeDenyInteractiveLogonRight = *$sidT1Admins,*$sidT2Admins
SeDenyRemoteInteractiveLogonRight = *$sidT1Admins,*$sidT2Admins
"@

# Idempotency: compare hash of new content with existing file (if any).
$existingHash = $null
$newHash      = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::Unicode.GetBytes($newContent)
) | ForEach-Object { $_.ToString('x2') }
$newHash = $newHash -join ''

if (Test-Path $gptTmplPath) {
    $existingBytes = [System.IO.File]::ReadAllBytes($gptTmplPath)
    $existingHash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($existingBytes) |
        ForEach-Object { $_.ToString('x2') }
    $existingHash  = $existingHash -join ''
}

$contentChanged = ($existingHash -ne $newHash)

if (-not $contentChanged) {
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
        -ObjectType 'GPO' -ObjectDN $gptTmplPath `
        -Detail "GptTmpl.inf content is unchanged (hash match). No GPO version increment needed."
}
else {
    # Write GptTmpl.inf as UTF-16 LE with BOM (required for Windows INF parsing).
    [System.IO.File]::WriteAllText($gptTmplPath, $newContent, [System.Text.Encoding]::Unicode)

    Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
        -ObjectType 'GPO' -ObjectDN $gptTmplPath `
        -Detail ("Written GptTmpl.inf to '$gptTmplPath'. " +
                 "RestrictedGroups: BUILTIN\Administrators = Domain Admins + GS-LZ-T0-Admins. " +
                 "DenyInteractiveLogon + DenyRDP: GS-LZ-T1-Admins, GS-LZ-T2-Admins.")

    # ------------------------------------------------------------------
    # Update the GPO's AD object:
    #   1. gPCMachineExtensionNames -- add Security Settings extension GUIDs
    #      so clients know they need to process the security template.
    #   2. Increment gPCVersion (lower 16 bits = machine version counter).
    # ------------------------------------------------------------------

    # Security Settings CSE and tool extension GUIDs (well-known, constant).
    $secExtGuid = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

    $gpoDN = "CN={$($gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$DomainDN"

    try {
        $gpADObj = Get-ADObject -Identity $gpoDN `
            -Properties gPCMachineExtensionNames, versionNumber `
            -ErrorAction Stop

        # gPCMachineExtensionNames
        $currentExtNames = $gpADObj.gPCMachineExtensionNames
        if ($currentExtNames -and $currentExtNames -like "*$secExtGuid*") {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'GPO' -ObjectDN $gpoDN `
                -Detail "gPCMachineExtensionNames already includes Security Settings GUID; no change needed."
        }
        else {
            $newExtNames = if ($currentExtNames) { "$currentExtNames$secExtGuid" } else { $secExtGuid }
            Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $newExtNames } -ErrorAction Stop
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
                -ObjectType 'GPO' -ObjectDN $gpoDN `
                -Detail "Updated gPCMachineExtensionNames to include Security Settings extension GUID."
        }

        # Increment machine version counter (lower 16 bits of versionNumber).
        # versionNumber = (userVersion << 16) | machineVersion
        # We only increment the machine side.
        $currentVersion  = [int]$gpADObj.versionNumber
        $userVersion     = ($currentVersion -shr 16) -band 0xFFFF
        $machineVersion  = ($currentVersion -band 0xFFFF) + 1
        $newVersion      = ($userVersion -shl 16) -bor $machineVersion

        Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVersion } -ErrorAction Stop

        # Also update the gpt.ini file in SYSVOL to keep AD and SYSVOL in sync.
        $gptIniPath = Join-Path $gpoPath 'GPT.INI'
        if (Test-Path $gptIniPath) {
            $gptIni = Get-Content $gptIniPath -Raw
            $gptIni = $gptIni -replace 'Version=\d+', "Version=$newVersion"
            [System.IO.File]::WriteAllText($gptIniPath, $gptIni, [System.Text.Encoding]::ASCII)
        }
        else {
            $gptIniContent = "[General]`r`nVersion=$newVersion`r`n"
            [System.IO.File]::WriteAllText($gptIniPath, $gptIniContent, [System.Text.Encoding]::ASCII)
        }

        Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
            -ObjectType 'GPO' -ObjectDN $gpoDN `
            -Detail "Incremented GPO version to $newVersion (machineVersion=$machineVersion). GPT.INI updated."
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'GPO' -ObjectDN $gpoDN `
            -Detail "Failed to update GPO AD object metadata: $($_.Exception.Message)"
        Write-Host "WARNING: GptTmpl.inf was written but GPO metadata update failed. Domain clients may not process settings until metadata is corrected. Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "  T0 Hardening Complete" -ForegroundColor Cyan
Write-Host "  GPO         : $gpoName ($($gpo.Id))" -ForegroundColor Cyan
Write-Host "  GptTmpl.inf : $gptTmplPath" -ForegroundColor Cyan
Write-Host "  Log         : $LogPath" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

# Read and print log summary
try {
    $entries = @(Import-Csv -Path $LogPath -ErrorAction Stop)
    $mine    = $entries | Where-Object { $_.Module -eq $module }
    Write-Host "  T0Hardening entries: $($mine.Count)  (Created=$(@($mine | Where-Object {$_.Action -eq 'Created'}).Count)  Modified=$(@($mine | Where-Object {$_.Action -eq 'Modified'}).Count)  Skipped=$(@($mine | Where-Object {$_.Action -eq 'Skipped'}).Count)  Errors=$(@($mine | Where-Object {$_.Action -eq 'Error'}).Count))"
}
catch { }
Write-Host ''
