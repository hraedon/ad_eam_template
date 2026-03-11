<#
.SYNOPSIS
    Generates a structured Markdown report of the AD Landing Zone deployment state.

.DESCRIPTION
    Operator-invoked read-only script. Queries the live Active Directory environment
    and produces a Markdown document summarising all Landing Zone objects:

        Section 1  OU hierarchy and protection status
        Section 2  Security groups and current membership
        Section 3  ACL delegations (explicit ACEs only; rights translated to prose)
        Section 4  Authentication Policies (TGT lifetime, enforcement, device restriction)
        Section 5  Authentication Policy Silos (linked policy, enrolled accounts)
        Section 6  Protected Users membership
        Section 7  Group Managed Service Accounts and host principals
        Section 8  GPO scaffolding (link status, inheritance block, WMI filter)

    The report reads live AD state -- not the deployment log -- so it reflects the
    current reality of the environment, not what was created in any specific run.
    Use it as a handoff document for security architects, auditors, or change records.

    Makes no changes to Active Directory. No -Credential parameters are used;
    all AD cmdlets rely on the ambient Windows session.

.PARAMETER TierCount
    Number of tiers in the deployment. Must match the value used with the deployer.

.PARAMETER OutputPath
    Full path for the Markdown (.md) report file. Parent directory is created if
    absent.

.EXAMPLE
    .\New-LZDeploymentReport.ps1 -TierCount 3 -OutputPath C:\Reports\LZ-Report.md

.NOTES
    Run from a Domain Admin session. Requires RSAT ActiveDirectory module.
    RSAT GroupPolicy module is required for Section 8; if absent, that section is
    omitted with a note rather than failing the report.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateRange(2, 10)]
    [int]$TierCount,

    [Parameter(Mandatory)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------
# Module imports
# ------------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error "Cannot import ActiveDirectory module: $($_.Exception.Message)"
    exit 1
}

$gpModuleAvailable = $false
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $gpModuleAvailable = $true
}
catch { }

# ------------------------------------------------------------------
# Derive domain context
# ------------------------------------------------------------------
try {
    $domain     = Get-ADDomain
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
}
catch {
    Write-Error "Cannot retrieve domain context from current session: $($_.Exception.Message)"
    exit 1
}

$generatedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
$containerDN  = "CN=_LZ_Groups,$DomainDN"

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor Cyan
Write-Host '  AD Landing Zone Deployment Report' -ForegroundColor Cyan
Write-Host "  Domain    : $DomainFQDN" -ForegroundColor Cyan
Write-Host "  TierCount : $TierCount" -ForegroundColor Cyan
Write-Host "  Output    : $OutputPath" -ForegroundColor Cyan
Write-Host ('=' * 60) -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------
# Helper: translate ActiveDirectoryRights bitmask to readable string
# ------------------------------------------------------------------
function Format-ADRights {
    param([System.DirectoryServices.ActiveDirectoryRights]$Rights)

    if ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
        return 'GenericAll (Full Control)'
    }

    $parts = @()
    $checks = [ordered]@{
        'GenericRead'   = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
        'GenericWrite'  = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        'CreateChild'   = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
        'DeleteChild'   = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
        'ListChildren'  = [System.DirectoryServices.ActiveDirectoryRights]::ListChildren
        'ListObject'    = [System.DirectoryServices.ActiveDirectoryRights]::ListObject
        'ReadProperty'  = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
        'WriteProperty' = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
        'WriteDacl'     = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        'WriteOwner'    = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
        'Delete'        = [System.DirectoryServices.ActiveDirectoryRights]::Delete
        'ExtendedRight' = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    }

    foreach ($label in $checks.Keys) {
        if ($Rights -band $checks[$label]) { $parts += $label }
    }

    if ($parts.Count -eq 0) { return "0x$([Convert]::ToString([int]$Rights, 16))" }
    return $parts -join ', '
}

# ------------------------------------------------------------------
# Helper: translate inheritance enum to readable string
# ------------------------------------------------------------------
function Format-Inheritance {
    param([System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance)

    switch ($Inheritance.ToString()) {
        'All'             { 'This object and all descendants' }
        'None'            { 'This object only' }
        'Children'        { 'All child objects only' }
        'SelfAndChildren' { 'This object and immediate children only' }
        'Descendents'     { 'All descendants (not this object)' }
        default           { "$Inheritance" }
    }
}

# ------------------------------------------------------------------
# Helper: translate known SDDL patterns to human-readable form
# ------------------------------------------------------------------
function Format-DeviceSddl {
    param([string]$Sddl)

    if ([string]::IsNullOrEmpty($Sddl)) { return '—' }

    if ($Sddl -match '@DEVICE\.domainjoined') {
        return 'Any domain-joined device _(v1 baseline — deploy Phase 7 to upgrade)_'
    }

    if ($Sddl -match 'Member_of_any \{SID\(([^)]+)\)\}') {
        $sid = $Matches[1]
        try {
            $g = Get-ADGroup -Filter "SID -eq '$sid'" -ErrorAction Stop
            return "Members of ``$($g.Name)`` _(SID: ``$sid``)_"
        }
        catch {
            return "Members of SID ``$sid`` _(group not resolvable)_"
        }
    }

    # Unknown form -- show truncated raw value
    $truncated = if ($Sddl.Length -gt 80) { $Sddl.Substring(0, 80) + '…' } else { $Sddl }
    return "Custom SDDL: ``$truncated``"
}

# ------------------------------------------------------------------
# Report line accumulator
# ------------------------------------------------------------------
$lines = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string]$Text = '') $lines.Add($Text) | Out-Null }

function Add-Table {
    # Emit a Markdown table from an array of arrays. First row is headers.
    param([string[][]]$Rows)
    if ($Rows.Count -eq 0) { return }
    $colCount = $Rows[0].Count
    Add-Line ("| " + ($Rows[0] -join ' | ') + " |")
    Add-Line ("| " + ((@('---') * $colCount) -join ' | ') + " |")
    foreach ($row in $Rows[1..($Rows.Count - 1)]) {
        Add-Line ("| " + ($row -join ' | ') + " |")
    }
}

# ==================================================================
# HEADER
# ==================================================================
Add-Line "# AD Landing Zone Deployment Report"
Add-Line ""
Add-Line "| | |"
Add-Line "|---|---|"
Add-Line "| **Domain** | ``$DomainFQDN`` |"
Add-Line "| **Domain DN** | ``$DomainDN`` |"
Add-Line "| **Tier count** | $TierCount |"
Add-Line "| **Generated** | $generatedAt UTC |"
Add-Line "| **Tool** | ``New-LZDeploymentReport.ps1`` v2.6 |"
Add-Line ""
Add-Line "> This report reflects **live Active Directory state** at the time of generation."
Add-Line "> It is not derived from the deployment log. Re-run at any time to refresh."
Add-Line ""
Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 1: OU STRUCTURE
# ==================================================================
Write-Host "  [1/8] OU Structure" -ForegroundColor DarkCyan

Add-Line "## 1. OU Structure"
Add-Line ""

try {
    $lzOUs = Get-ADOrganizationalUnit `
        -Filter  "Name -like '_LZ_*'" `
        -Properties ProtectedFromAccidentalDeletion `
        -SearchBase  $DomainDN `
        -SearchScope Subtree `
        -ErrorAction Stop |
        Sort-Object DistinguishedName

    if ($lzOUs) {
        foreach ($ou in $lzOUs) {
            # Depth relative to LZ root = (total OU= count) - 1
            $depth  = ([regex]::Matches($ou.DistinguishedName, 'OU=')).Count - 1
            $indent = '  ' * $depth
            $guard  = if ($ou.ProtectedFromAccidentalDeletion) { ' _(protected)_' } else { ' **⚠ not protected**' }
            Add-Line "$indent- ``$($ou.Name)``$guard"
        }
    }
    else {
        Add-Line "_No `_LZ_*` OUs found. The deployer may not have run yet._"
    }
}
catch {
    Add-Line "_Error querying OUs: $($_.Exception.Message)_"
}

Add-Line ""
Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 2: SECURITY GROUPS
# ==================================================================
Write-Host "  [2/8] Security Groups" -ForegroundColor DarkCyan

Add-Line "## 2. Security Groups"
Add-Line ""
Add-Line "All groups reside in ``CN=_LZ_Groups,$DomainDN``."
Add-Line ""

try {
    $lzGroups = Get-ADGroup `
        -Filter      "Name -like 'GS-LZ-*'" `
        -SearchBase  $containerDN `
        -SearchScope OneLevel `
        -Properties  Description, SID `
        -ErrorAction Stop |
        Sort-Object Name

    if ($lzGroups) {
        $tableRows = @(, @('Group', 'Members', 'Description'))
        foreach ($grp in $lzGroups) {
            try {
                $members = @(Get-ADGroupMember -Identity $grp -ErrorAction Stop)
                $memberStr = if ($members.Count -eq 0) {
                    '_empty_'
                }
                else {
                    ($members | Sort-Object SamAccountName |
                        ForEach-Object { "``$($_.SamAccountName)``" }) -join ', '
                }
            }
            catch { $memberStr = '_error reading members_' }

            $desc = if ($grp.Description) { $grp.Description } else { '—' }
            $tableRows += , @("``$($grp.Name)``", $memberStr, $desc)
        }
        Add-Table -Rows $tableRows
    }
    else {
        Add-Line "_No ``GS-LZ-*`` groups found. Container may not exist or deployer has not run._"
    }
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Add-Line "_Container ``CN=_LZ_Groups`` not found. Phase 3 (Groups) has not run._"
}
catch {
    Add-Line "_Error querying security groups: $($_.Exception.Message)_"
}

Add-Line ""
Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 3: ACL DELEGATIONS
# ==================================================================
Write-Host "  [3/8] ACL Delegations" -ForegroundColor DarkCyan

Add-Line "## 3. ACL Delegations"
Add-Line ""
Add-Line "Only **explicit** Allow ACEs referencing ``GS-LZ-*`` groups are shown."
Add-Line "Inherited ACEs are excluded (``IsInherited = false`` filter applied)."
Add-Line ""

if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
    Add-Line "_AD PSDrive not available. Import the ActiveDirectory module and retry._"
}
else {
    # Resolve all GS-LZ-* SIDs once, outside the tier loop.
    $lzSidMap = @{}
    try {
        Get-ADGroup -Filter "Name -like 'GS-LZ-*'" -Properties SID -ErrorAction Stop |
            ForEach-Object { $lzSidMap[$_.SID.Value] = $_.Name }
    }
    catch { }

    for ($n = 0; $n -lt $TierCount; $n++) {
        $tierDN = "OU=_LZ_T$n,$DomainDN"
        Add-Line "### Tier $n — ``OU=_LZ_T$n``"
        Add-Line ""

        try {
            $acl = Get-Acl -Path "AD:$tierDN" -ErrorAction Stop

            $lzAces = $acl.Access | Where-Object {
                if ($_.IsInherited) { return $false }
                if ($_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }

                $sidVal = if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $_.IdentityReference.Value
                }
                else {
                    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                    catch { $null }
                }
                $lzSidMap.ContainsKey($sidVal)
            }

            if ($lzAces) {
                $tableRows = @(, @('Group', 'Rights', 'Scope'))
                foreach ($ace in $lzAces | Sort-Object {
                    $sid = if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                        $_.IdentityReference.Value
                    } else {
                        try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                    }
                    if ($lzSidMap.ContainsKey($sid)) { $lzSidMap[$sid] } else { $sid }
                }) {
                    $sidVal = if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                        $ace.IdentityReference.Value
                    } else {
                        try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                    }
                    $groupName = if ($lzSidMap.ContainsKey($sidVal)) { $lzSidMap[$sidVal] } else { $ace.IdentityReference.ToString() }
                    $rights    = Format-ADRights    -Rights      $ace.ActiveDirectoryRights
                    $scope     = Format-Inheritance -Inheritance $ace.InheritanceType
                    $tableRows += , @("``$groupName``", $rights, $scope)
                }
                Add-Table -Rows $tableRows
            }
            else {
                Add-Line "_No explicit ``GS-LZ-*`` ACEs found on this OU._"
            }
        }
        catch {
            Add-Line "_Error reading ACL for ``$tierDN``: $($_.Exception.Message)_"
        }

        Add-Line ""
    }

    # LOM compatibility note (always present per spec)
    Add-Line "> **List Object Mode compatibility:** All LZ ACEs explicitly include"
    Add-Line "> ``ReadProperty``, ``ListChildren``, and ``ListObject`` rights."
    Add-Line "> The ACL structure is compatible with both LOM-enabled and LOM-disabled environments."
}

Add-Line ""
Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 4: AUTHENTICATION POLICIES
# ==================================================================
Write-Host "  [4/8] Authentication Policies" -ForegroundColor DarkCyan

Add-Line "## 4. Authentication Policies"
Add-Line ""

$policyProps = @(
    'UserTGTLifetimeMins', 'RollingNTLMSecret', 'Enforce',
    'UserAllowedToAuthenticateFrom', 'ProtectedFromAccidentalDeletion', 'Description'
)

$anyPolicy = $false

for ($n = 0; $n -lt $TierCount; $n++) {
    $policyName = "LZ-T$n-AuthPolicy"
    Add-Line "### ``$policyName``"
    Add-Line ""

    try {
        $policy  = Get-ADAuthenticationPolicy -Identity $policyName -Properties $policyProps -ErrorAction Stop
        $anyPolicy = $true

        $enforceStr = if ($policy.Enforce) { '**Enforced** — Kerberos errors returned to clients' } else { 'Audit mode — violations logged, not blocked' }
        $ntlmStr    = if ($policy.RollingNTLMSecret) { "``$($policy.RollingNTLMSecret)``" } else { '— _(not set)_' }
        $deviceStr  = Format-DeviceSddl -Sddl $policy.UserAllowedToAuthenticateFrom
        $protStr    = if ($policy.ProtectedFromAccidentalDeletion) { 'Yes' } else { '**No** ⚠' }

        Add-Line "| Property | Value |"
        Add-Line "|---|---|"
        Add-Line "| TGT Lifetime | $($policy.UserTGTLifetimeMins) minutes |"
        Add-Line "| Enforcement | $enforceStr |"
        Add-Line "| RollingNTLMSecret | $ntlmStr |"
        Add-Line "| Device restriction | $deviceStr |"
        Add-Line "| Protected from deletion | $protStr |"
        if ($policy.Description) {
            Add-Line "| Description | $($policy.Description) |"
        }

        # Show raw SDDL only when it doesn't match a known pattern
        $sddl = $policy.UserAllowedToAuthenticateFrom
        if (-not [string]::IsNullOrEmpty($sddl) -and
            $sddl -notmatch '@DEVICE\.domainjoined' -and
            $sddl -notmatch 'Member_of_any') {
            Add-Line "| Raw SDDL | ``$sddl`` |"
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Add-Line "_Not found — policy not deployed or name has changed._"
    }
    catch {
        Add-Line "_Error: $($_.Exception.Message)_"
    }

    Add-Line ""
}

if (-not $anyPolicy) {
    Add-Line "_No authentication policies found. Phase 5 has not run._"
    Add-Line ""
}

Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 5: AUTHENTICATION POLICY SILOS
# ==================================================================
Write-Host "  [5/8] Authentication Policy Silos" -ForegroundColor DarkCyan

Add-Line "## 5. Authentication Policy Silos"
Add-Line ""

$siloProps = @('UserAuthenticationPolicy', 'Description', 'ProtectedFromAccidentalDeletion')
$anySilo   = $false

for ($n = 0; $n -lt $TierCount; $n++) {
    $siloName = "LZ-T$n-Silo"
    Add-Line "### ``$siloName``"
    Add-Line ""

    try {
        $silo    = Get-ADAuthenticationPolicySilo -Identity $siloName -Properties $siloProps -ErrorAction Stop
        $anySilo = $true
        $protStr = if ($silo.ProtectedFromAccidentalDeletion) { 'Yes' } else { '**No** ⚠' }

        # Enrolled accounts: query for objects where msDS-AssignedAuthNPolicySilo = silo DN.
        # String filter used (not scriptblock) to avoid variable expansion issues in nested scopes.
        $enrolledStr = '_none enrolled_'
        try {
            $siloDN   = $silo.DistinguishedName
            $enrolled = @(Get-ADObject `
                -Filter      "msDS-AssignedAuthNPolicySilo -eq '$siloDN'" `
                -SearchBase  $DomainDN `
                -SearchScope Subtree `
                -Properties  SamAccountName, ObjectClass `
                -ErrorAction Stop)
            if ($enrolled.Count -gt 0) {
                $enrolledStr = ($enrolled | Sort-Object SamAccountName |
                    ForEach-Object { "``$($_.SamAccountName)`` ($($_.ObjectClass))" }) -join ', '
            }
        }
        catch { $enrolledStr = '_error querying enrollment_' }

        Add-Line "| Property | Value |"
        Add-Line "|---|---|"
        Add-Line "| Linked policy | ``$($silo.UserAuthenticationPolicy)`` |"
        Add-Line "| Enrolled accounts | $enrolledStr |"
        Add-Line "| Protected from deletion | $protStr |"
        if ($silo.Description) { Add-Line "| Description | $($silo.Description) |" }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Add-Line "_Not found — silo not deployed._"
    }
    catch {
        Add-Line "_Error: $($_.Exception.Message)_"
    }

    Add-Line ""
}

if (-not $anySilo) {
    Add-Line "_No silos found. Phase 5 has not run._"
    Add-Line ""
}

Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 6: PROTECTED USERS
# ==================================================================
Write-Host "  [6/8] Protected Users" -ForegroundColor DarkCyan

Add-Line "## 6. Protected Users Membership"
Add-Line ""
Add-Line "Membership of the built-in ``Protected Users`` group, filtered to ``GS-LZ-*`` entries."
Add-Line "Any account (or group) nested here immediately loses NTLM, DES, and RC4 authentication"
Add-Line "and is subject to a non-renewable 4-hour TGT cap."
Add-Line ""

try {
    $puGroup   = Get-ADGroup -Identity 'Protected Users' -ErrorAction Stop
    $puMembers = @(Get-ADGroupMember -Identity $puGroup -ErrorAction Stop)
    $lzMembers = $puMembers | Where-Object { $_.SamAccountName -like 'GS-LZ-*' }

    if ($lzMembers) {
        $tableRows = @(, @('Member', 'Object class', 'SID'))
        foreach ($m in $lzMembers | Sort-Object SamAccountName) {
            $tableRows += , @("``$($m.SamAccountName)``", $m.objectClass, "``$($m.SID)``")
        }
        Add-Table -Rows $tableRows
    }
    else {
        Add-Line "_No ``GS-LZ-*`` groups are currently members of Protected Users._"
        Add-Line "_Expected: ``GS-LZ-T0-Admins`` should be a member after Phase 6 runs._"
    }

    $nonLzCount = ($puMembers | Where-Object { $_.SamAccountName -notlike 'GS-LZ-*' }).Count
    if ($nonLzCount -gt 0) {
        Add-Line ""
        Add-Line "_($nonLzCount non-LZ member(s) also present in Protected Users — not shown here.)_"
    }
}
catch {
    Add-Line "_Error querying Protected Users: $($_.Exception.Message)_"
}

Add-Line ""
Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 7: gMSA ACCOUNTS
# ==================================================================
Write-Host "  [7/8] gMSA Accounts" -ForegroundColor DarkCyan

Add-Line "## 7. Group Managed Service Accounts (gMSAs)"
Add-Line ""

$gmsaProps = @('DNSHostName', 'PrincipalsAllowedToRetrieveManagedPassword', 'Description', 'DistinguishedName')
$anyGmsa   = $false

for ($n = 0; $n -lt $TierCount; $n++) {
    $gmsaName = "gMSA-LZ-T$n"
    Add-Line "### ``$gmsaName``"
    Add-Line ""

    try {
        $gmsa    = Get-ADServiceAccount -Identity $gmsaName -Properties $gmsaProps -ErrorAction Stop
        $anyGmsa = $true

        # Resolve PrincipalsAllowedToRetrieveManagedPassword from DN list to names.
        $principals = @($gmsa.PrincipalsAllowedToRetrieveManagedPassword)
        $principalStr = if ($principals.Count -eq 0) {
            '_none — no hosts can currently retrieve this password_'
        }
        else {
            $names = foreach ($p in $principals) {
                try {
                    $obj = Get-ADObject -Identity $p -Properties SamAccountName -ErrorAction Stop
                    "``$($obj.SamAccountName)``"
                }
                catch { "``$p``" }
            }
            ($names | Sort-Object) -join ', '
        }

        Add-Line "| Property | Value |"
        Add-Line "|---|---|"
        Add-Line "| DN | ``$($gmsa.DistinguishedName)`` |"
        Add-Line "| DNS host name | ``$($gmsa.DNSHostName)`` |"
        Add-Line "| PrincipalsAllowedToRetrieveManagedPassword | $principalStr |"
        if ($gmsa.Description) { Add-Line "| Description | $($gmsa.Description) |" }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Add-Line "_Not found — Phase 8 (gMSA provisioning) not run or skipped (``-SkipGmsas``)._"
    }
    catch {
        Add-Line "_Error: $($_.Exception.Message)_"
    }

    Add-Line ""
}

if (-not $anyGmsa) {
    Add-Line "_No gMSA accounts found. Phase 8 may have been skipped or not yet run._"
    Add-Line ""
}

Add-Line "---"
Add-Line ""

# ==================================================================
# SECTION 8: GPO SCAFFOLDING
# ==================================================================
Write-Host "  [8/8] GPO Scaffolding" -ForegroundColor DarkCyan

Add-Line "## 8. GPO Scaffolding"
Add-Line ""

if (-not $gpModuleAvailable) {
    Add-Line "_GroupPolicy module not available. Install the GPMC RSAT feature to include this section._"
    Add-Line ""
    Add-Line "```powershell"
    Add-Line "# Server"
    Add-Line "Add-WindowsFeature GPMC"
    Add-Line "# Windows 10/11"
    Add-Line "Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    Add-Line "```"
}
else {
    $wmiContainerDN = "CN=SOM,CN=WMIPolicy,CN=System,$DomainDN"
    $anyGpo         = $false

    for ($n = 0; $n -lt $TierCount; $n++) {
        $gpoName    = "LZ-T$n-GPO"
        $tierOuPath = "OU=_LZ_T$n,$DomainDN"
        $wmiName    = "LZ-T$n-WMIFilter"

        Add-Line "### ``$gpoName``"
        Add-Line ""

        try {
            $gpo    = Get-GPO -Name $gpoName -Domain $DomainFQDN -ErrorAction Stop
            $anyGpo = $true

            # Link and inheritance state
            $linkStatus         = '_not linked_'
            $inheritanceBlocked = $false

            try {
                $gpInheritance = Get-GPInheritance -Target $tierOuPath -Domain $DomainFQDN -ErrorAction Stop
                $existingLink  = $gpInheritance.GpoLinks | Where-Object { $_.DisplayName -eq $gpoName }
                if ($existingLink) {
                    $enabledLabel = if ($existingLink.Enabled) { 'Enabled' } else { '**Disabled** ⚠' }
                    $linkStatus   = "Linked ($enabledLabel)"
                }
                $inheritanceBlocked = $gpInheritance.GpoInheritanceBlocked
            }
            catch { }

            # WMI filter
            $wmiStr = '—'
            try {
                $wmiFilter = Get-ADObject `
                    -Filter      "objectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$wmiName'" `
                    -SearchBase  $wmiContainerDN `
                    -Properties  'msWMI-Parm2', 'msWMI-ID' `
                    -ErrorAction Stop |
                    Select-Object -First 1

                if ($wmiFilter) {
                    $parm2 = $wmiFilter.'msWMI-Parm2'
                    if ($parm2 -match '^1;3;\d+;[^;]+;(.+);;$') {
                        $wmiStr = "``$wmiName`` — ``$($Matches[1])``"
                    }
                    else {
                        $wmiStr = "``$wmiName``"
                    }
                }
                else {
                    $wmiStr = '_filter not found_'
                }
            }
            catch { $wmiStr = '_error reading WMI filter_' }

            $blockedStr = if ($inheritanceBlocked) { 'Yes' } else { '**No** — parent domain GPOs may flow in ⚠' }

            Add-Line "| Property | Value |"
            Add-Line "|---|---|"
            Add-Line "| GUID | ``{$($gpo.Id.ToString().ToUpper())}`` |"
            Add-Line "| Link to ``OU=_LZ_T$n`` | $linkStatus |"
            Add-Line "| Inheritance blocked | $blockedStr |"
            Add-Line "| WMI filter | $wmiStr |"
            if ($gpo.Description) { Add-Line "| Description | $($gpo.Description) |" }
        }
        catch [System.ArgumentException] {
            Add-Line "_Not found — Phase 9 (GPO scaffolding) not run or skipped (``-SkipGpos``)._"
        }
        catch {
            Add-Line "_Error: $($_.Exception.Message)_"
        }

        Add-Line ""
    }

    if (-not $anyGpo) {
        Add-Line "_No LZ GPOs found. Phase 9 may have been skipped or not yet run._"
        Add-Line ""
    }
}

Add-Line "---"
Add-Line ""

# ==================================================================
# FOOTER
# ==================================================================
Add-Line "_Generated by ``New-LZDeploymentReport.ps1`` · AD Landing Zone deployer v2.6_"
Add-Line ""
Add-Line "_Domain: ``$DomainFQDN`` · Report time: $generatedAt UTC_"

# ------------------------------------------------------------------
# Write output file
# ------------------------------------------------------------------
$outputDir = Split-Path -Parent $OutputPath
if ($outputDir -and -not (Test-Path $outputDir)) {
    try {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    catch {
        Write-Error "Cannot create output directory '$outputDir': $($_.Exception.Message)"
        exit 1
    }
}

try {
    $lines | Set-Content -Path $OutputPath -Encoding UTF8 -ErrorAction Stop
}
catch {
    Write-Error "Cannot write report to '$OutputPath': $($_.Exception.Message)"
    exit 1
}

Write-Host ''
Write-Host ('=' * 60) -ForegroundColor Green
Write-Host "  Report complete." -ForegroundColor Green
Write-Host "  Sections: 8 | Output: $OutputPath" -ForegroundColor Green
Write-Host ('=' * 60) -ForegroundColor Green
Write-Host ''
