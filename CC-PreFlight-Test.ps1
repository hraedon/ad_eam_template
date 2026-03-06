# CC-PreFlight-Test.ps1
# Run this manually before invoking the deployer against the target domain.
# Verifies that the current session has the access the deployer will need.
#
# No parameters required. All domain context is inferred from the ambient
# PowerShell session. Run from a session authenticated as a Domain Admin.
# The deployer uses the same ambient context -- no -Credential flags anywhere.

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Test-Item {
    param($Name, [scriptblock]$ScriptBlock)
    try {
        $result = & $ScriptBlock
        $status = if ($result -eq $false) { "FAIL" } else { "PASS" }
        $detail = if ($result -is [string]) { $result } else { "" }
    } catch {
        $status = "FAIL"
        $detail = $_.Exception.Message
    }
    $results.Add([PSCustomObject]@{ Test = $Name; Status = $status; Detail = $detail })
    $color = if ($status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "$status  $Name$(if ($detail) { " -- $detail" })" -ForegroundColor $color
}

# Derive domain context from session -- no parameters, no hardcoded values.
# If this fails, the session is not connected to a domain and nothing else will work.
try {
    $domain     = Get-ADDomain
    $DomainFQDN = $domain.DNSRoot
    $DomainDN   = $domain.DistinguishedName
} catch {
    Write-Host "FATAL  Cannot retrieve domain context from current session." -ForegroundColor Red
    Write-Host "       Ensure you are running from a session joined to and authenticated against the target domain." -ForegroundColor Red
    Write-Host "       Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`nAD Landing Zone -- Pre-Flight Access Test" -ForegroundColor Cyan
Write-Host "Domain: $DomainFQDN  ($DomainDN)`n"

# 1. Verify current session is Domain Admin
Test-Item "Running as Domain Admin" {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isDomainAdmin = $currentUser.Groups | Where-Object {
        $_.Translate([System.Security.Principal.NTAccount]).Value -match 'Domain Admins'
    }
    if (-not $isDomainAdmin) { throw "Current user is not a member of Domain Admins" }
    "User: $($currentUser.Name)"
}

# 2. Functional level gate (domain object already retrieved above -- no second call)
Test-Item "Functional level 2016+" {
    if ($domain.DomainMode -lt 'Windows2016Domain') {
        throw "Detected: $($domain.DomainMode). Must be Windows2016Domain or higher."
    }
    "Functional level: $($domain.DomainMode)"
}

# 3. Can we read the domain root object?
Test-Item "Read domain root" {
    Get-ADObject -Identity $DomainDN | Out-Null
}

# 4. Can we create/delete an OU with ProtectedFromAccidentalDeletion?
#    Creates with the flag set to exercise the exact write path the deployer uses.
Test-Item "OU create/delete rights (with AccidentalDeletion protection)" {
    $testName = "_LZ_CC_CanaryTest"
    $testDN   = "OU=$testName,$DomainDN"
    New-ADOrganizationalUnit -Name $testName -Path $DomainDN -ProtectedFromAccidentalDeletion $true
    Set-ADObject -Identity $testDN -ProtectedFromAccidentalDeletion $false
    Remove-ADOrganizationalUnit -Identity $testDN -Confirm:$false
}

# 5. Can we create/delete a group in CN=Users (deployer uses a dedicated container;
#    this exercises the same permission scope at domain root level)?
Test-Item "Group create/delete rights" {
    $testGroup = "GS-LZ-CC-CanaryTest"
    New-ADGroup -Name $testGroup -GroupScope Global -GroupCategory Security -Path "CN=Users,$DomainDN"
    Remove-ADGroup -Identity $testGroup -Confirm:$false
}

# 6. Can we read AND write ACLs on an OU?
#    ACL write is the most likely real-world permission failure for the deployer.
#    Creates a canary OU, writes a dummy ACE, removes it, then removes the OU.
Test-Item "ACL read/write on OU" {
    $testName = "_LZ_CC_AclCanary"
    $testDN   = "OU=$testName,$DomainDN"

    New-ADOrganizationalUnit -Name $testName -Path $DomainDN -ProtectedFromAccidentalDeletion $false

    $acl    = Get-Acl -Path "AD:\$testDN"
    $sid    = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-545' # BUILTIN\Users - benign test identity
    $rule   = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path "AD:\$testDN" -AclObject $acl

    Remove-ADOrganizationalUnit -Identity $testDN -Confirm:$false
    "ACL write succeeded"
}

# 7. Can we create/delete Authentication Policies?
#    Creates a canary policy used by the silo test below -- validates the dependency order
#    the deployer relies on (policy must exist before silo is created).
Test-Item "AuthPolicy create/delete rights" {
    New-ADAuthenticationPolicy -Name "LZ-CC-CanaryPolicy" -UserTGTLifetimeMins 60
    # Intentionally not removed here -- silo test depends on it existing
}

# 8. Can we create/delete Authentication Policy Silos bound to a policy?
#    Deployer always creates silos bound to policies; unbound silo creation
#    does not validate the right permission path.
#    NOTE: the correct parameter is -UserAuthenticationPolicy (not -AuthenticationPolicy).
#    Validated against the Windows Server 2025 ActiveDirectory PowerShell module.
Test-Item "AuthPolicySilo create/delete rights (bound to policy)" {
    New-ADAuthenticationPolicySilo -Name "LZ-CC-CanarySilo" -UserAuthenticationPolicy "LZ-CC-CanaryPolicy"
    Remove-ADAuthenticationPolicySilo -Identity "LZ-CC-CanarySilo" -Confirm:$false
    Remove-ADAuthenticationPolicy -Identity "LZ-CC-CanaryPolicy" -Confirm:$false
}

# 9. Can we read the Protected Users group?
Test-Item "Protected Users group readable" {
    $pu = Get-ADGroup -Identity "Protected Users"
    "SID: $($pu.SID)"
}

# 10. Can we add/remove a member to Protected Users?
Test-Item "Protected Users write rights" {
    $testUser = "LZ-CC-CanaryUser"
    $testDN   = "CN=$testUser,CN=Users,$DomainDN"
    New-ADUser -Name $testUser -Path "CN=Users,$DomainDN"
    Add-ADGroupMember    -Identity "Protected Users" -Members $testUser
    Remove-ADGroupMember -Identity "Protected Users" -Members $testUser -Confirm:$false
    Remove-ADUser        -Identity $testDN -Confirm:$false
}

# 11. dsHeuristics readable -- List Object Mode check.
#     Warning-only per spec: LOM enabled changes ACL behavior but does not block deployment.
#     No output file is written by this script; this result is console-only by design.
Test-Item "dsHeuristics readable (List Object Mode check)" {
    $dsSvc = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DomainDN"
    $obj   = Get-ADObject -Identity $dsSvc -Properties dsHeuristics
    if ($obj.dsHeuristics -and $obj.dsHeuristics.Length -ge 7 -and $obj.dsHeuristics[6] -eq '1') {
        "WARNING: List Object Mode ENABLED -- ACL behavior will differ. Deployment will proceed but review ACL module output carefully."
    } else {
        "List Object Mode disabled"
    }
}

# Summary
Write-Host "`n--- Summary ---"
$pass = ($results | Where-Object Status -eq "PASS").Count
$fail = ($results | Where-Object Status -eq "FAIL").Count
$color = if ($fail -gt 0) { "Yellow" } else { "Green" }
Write-Host "PASS: $pass  FAIL: $fail" -ForegroundColor $color
if ($fail -gt 0) {
    Write-Host "`nResolve all FAILs before running the deployer." -ForegroundColor Yellow
    $results | Where-Object Status -eq "FAIL" | ForEach-Object {
        Write-Host "  FAIL: $($_.Test) -- $($_.Detail)" -ForegroundColor Red
    }
} else {
    Write-Host "`nAll checks passed. The session has the access the deployer needs." -ForegroundColor Green
}
