<#
.SYNOPSIS
    Canary and behavioral tests for the AD Landing Zone.

.DESCRIPTION
    These tests go beyond structural verification (does the object exist?) to
    verify that key security properties actually function as intended:

      1. ProtectedFromAccidentalDeletion enforcement
         Verifies that attempting to delete a protected LZ OU throws an error,
         proving the protection flag is enforced by the AD provider -- not just
         set as an attribute value.

      2. Cross-tier write isolation (ACL canary)
         Verifies that GS-LZ-T{n}-Admins has NO GenericAll ACE on the sibling
         tier OU. The structural ACL tests in LZ-ACLs.Tests.ps1 confirm correct
         groups are present; these tests confirm incorrect groups are absent.

      3. AdminSDHolder protection awareness
         Verifies that no GS-LZ group appears with an explicit ACE on the
         Domain Admins built-in group. The deployer spec forbids applying ACLs
         to AdminSDHolder-protected objects. This test catches regression if a
         future code change violates that constraint.

    KNOWN GAPS -- tests that require additional infrastructure:

    a) NTLM rejection for T0 accounts
       Protected Users membership prevents NTLM for all members of GS-LZ-T0-Admins.
       Testing actual NTLM rejection requires:
         - A test user account that is a member of GS-LZ-T0-Admins (or directly in
           Protected Users) with a known password
         - A service configured to accept only NTLM (LmCompatibilityLevel = 0) on
           a separate machine
         - An authentication attempt from that account to that service
         - Verification that the attempt fails with ERROR_LOGON_FAILURE and the
           DC logs event 4776 (NTLM auth attempt for a Protected User)
       This is out of scope for the AD deployer's Pester suite. Create a dedicated
       infrastructure test script if NTLM rejection verification is required.

    b) Silo behavioral enforcement
       Verifying that the auth policy silos actually restrict TGT issuance requires:
         - A test account enrolled in a silo via Grant-ADAuthenticationPolicySiloAccess
         - An attempt to authenticate from a device NOT in the allowed set
         - Verification that the DC returns KDC_ERR_POLICY (error code 0x6F)
       This requires a two-machine setup and Kerberos-level tooling (Rubeus, klist /tgt).
       Structural silo verification (existence, policy linkage, Protected Users) is
       covered in LZ-AuthPolicies.Tests.ps1 and LZ-ProtectedUsers.Tests.ps1.
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

$script:DomainDN = $env:LZ_TEST_DOMAINDN
if (-not $script:DomainDN) { $script:DomainDN = (Get-ADDomain).DistinguishedName }

# ---------------------------------------------------------------------------
# Discovery-time data: tier OU cases for ProtectedFromAccidentalDeletion tests
# ---------------------------------------------------------------------------
$script:ProtectedOuCases = @(
    for ($n = 0; $n -lt $script:TierCount; $n++) {
        @{
            TierN   = $n
            OuName  = "_LZ_T$n"
            OuDN    = "OU=_LZ_T$n,$($script:DomainDN)"
        }
    }
    @{
        TierN   = -1
        OuName  = '_LZ_Quarantine'
        OuDN    = "OU=_LZ_Quarantine,$($script:DomainDN)"
    }
)

# ---------------------------------------------------------------------------
# Discovery-time data: cross-tier isolation cases
# Build every (source-tier, target-tier) pair where source != target.
# We verify that source-Admins has NO GenericAll on target tier OU.
# ---------------------------------------------------------------------------
$script:CrossTierCases = for ($src = 0; $src -lt $script:TierCount; $src++) {
    for ($tgt = 0; $tgt -lt $script:TierCount; $tgt++) {
        if ($src -ne $tgt) {
            @{
                SrcTier      = $src
                TgtTier      = $tgt
                AdminsName   = "GS-LZ-T$src-Admins"
                TgtOuDN      = "OU=_LZ_T$tgt,$($script:DomainDN)"
                TgtOuLabel   = "OU=_LZ_T$tgt"
            }
        }
    }
}


Describe 'LZ Canary: ProtectedFromAccidentalDeletion enforcement' -Tag 'Canary' {

    # OuDN is embedded in $script:ProtectedOuCases at discovery time.
    # ForEach hashtable fields are reliably available in It blocks at execution time
    # (Pester 5 scope rule -- see agent-notes.md #1).
    Context 'OU: <OuName>' -ForEach $script:ProtectedOuCases {

        It '<OuName> has ProtectedFromAccidentalDeletion = true' {
            $ou = Get-ADOrganizationalUnit -Identity $OuDN `
                -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
            $ou.ProtectedFromAccidentalDeletion | Should -Be $true
        }

        It 'Remove-ADOrganizationalUnit on <OuName> throws without removing protection first' {
            # This call MUST throw. The OU must NOT be deleted by this test.
            # ErrorAction Stop converts the non-terminating error to a terminating one
            # so Should -Throw catches it. Without -ErrorAction Stop the cmdlet emits
            # an error stream entry and returns normally, causing the test to pass
            # even if the cmdlet somehow completed the deletion.
            { Remove-ADOrganizationalUnit -Identity $OuDN -Confirm:$false -ErrorAction Stop } |
                Should -Throw
        }
    }
}


Describe 'LZ Canary: Cross-tier write isolation' -Tag 'Canary' {

    BeforeAll {
        # Rights constants matching Deploy-LZ-ACLs.ps1
        $script:FullControlRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $script:InheritAll        = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
        $script:ReadListRights    = (
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor
            [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
            [System.DirectoryServices.ActiveDirectoryRights]::ListObject
        )

        # Helper: returns $true if the given explicit ACE is present on the OU.
        function Test-LZExplicitAcePresent {
            param(
                [string]$OuDN,
                [System.Security.Principal.SecurityIdentifier]$GroupSid,
                [System.DirectoryServices.ActiveDirectoryRights]$Rights,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance
            )
            $acl = Get-Acl -Path "AD:$OuDN" -ErrorAction Stop
            $match = $acl.Access | Where-Object {
                if ($_.IsInherited -ne $false) { return $false }
                if ($_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
                if ($_.ActiveDirectoryRights -ne $Rights) { return $false }
                if ($_.InheritanceType -ne $Inheritance) { return $false }
                $sid = $null
                if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid = $_.IdentityReference
                }
                else {
                    try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
                    catch { return $false }
                }
                return ($sid.Value -eq $GroupSid.Value)
            }
            return ($null -ne $match)
        }
    }

    Context 'GS-LZ-T<SrcTier>-Admins has no Full Control on <TgtOuLabel>' -ForEach $script:CrossTierCases {

        It 'GS-LZ-T<SrcTier>-Admins has NO explicit GenericAll ACE on <TgtOuLabel>' {
            # If this fails, a T{src} admin group has Full Control over T{tgt} infrastructure.
            # That is a tier isolation failure: the entire purpose of the EAM model is to
            # prevent exactly this cross-tier privilege.
            $adminSid = (Get-ADGroup -Identity $AdminsName -ErrorAction Stop).SID
            Test-LZExplicitAcePresent `
                -OuDN        $TgtOuDN `
                -GroupSid    $adminSid `
                -Rights      $script:FullControlRights `
                -Inheritance $script:InheritAll |
                Should -Be $false
        }

        It 'GS-LZ-T<SrcTier>-Admins has NO explicit ReadList ACE on <TgtOuLabel>' {
            # Readers have no rights on sibling tiers (verified in LZ-ACLs.Tests.ps1).
            # Confirm the same for Admins: the admin group's ReadList rights come from
            # the GenericAll ACE on the correct tier, not from separate ReadList grants
            # on other tiers.
            $adminSid = (Get-ADGroup -Identity $AdminsName -ErrorAction Stop).SID
            Test-LZExplicitAcePresent `
                -OuDN        $TgtOuDN `
                -GroupSid    $adminSid `
                -Rights      $script:ReadListRights `
                -Inheritance $script:InheritAll |
                Should -Be $false
        }
    }
}


Describe 'LZ Canary: AdminSDHolder -- LZ groups not applied to protected objects' -Tag 'Canary' {

    BeforeAll {
        $dn = (Get-ADDomain).DistinguishedName
        # Domain Admins DN is predictable (CN=Users container, not configurable).
        $script:DomainAdminsDN = "CN=Domain Admins,CN=Users,$dn"

        # Collect all GS-LZ group SIDs so we can check for their presence in ACLs.
        $script:LzGroupSids = @(
            Get-ADGroup -Filter "Name -like 'GS-LZ-*'" -ErrorAction Stop |
                ForEach-Object { $_.SID }
        )
    }

    Context 'Domain Admins group ACL' {

        It 'At least one GS-LZ group exists (prerequisite for meaningful test)' {
            $script:LzGroupSids.Count | Should -BeGreaterThan 0
        }

        It 'Domain Admins ACL contains no explicit ACEs from GS-LZ groups' {
            # The deployer spec forbids applying ACLs to AdminSDHolder-protected objects.
            # If any GS-LZ group SID appears in an explicit ACE on Domain Admins, either
            # the deployer violated the spec or an operator manually applied an ACE.
            # Either way this is a security finding that must be investigated.
            $acl = Get-Acl -Path "AD:$($script:DomainAdminsDN)" -ErrorAction Stop
            $lzSidValues = $script:LzGroupSids | ForEach-Object { $_.Value }

            $violations = $acl.Access | Where-Object {
                if ($_.IsInherited -ne $false) { return $false }   # inherited = not our concern
                $sid = $null
                if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid = $_.IdentityReference
                }
                else {
                    try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
                    catch { return $false }
                }
                return ($lzSidValues -contains $sid.Value)
            }

            $violations | Should -BeNullOrEmpty -Because `
                'The deployer must not apply ACEs to AdminSDHolder-protected groups. ' +
                "Any GS-LZ group ACE found on Domain Admins indicates the deployer violated its own spec. " +
                "Additionally, AdminSDHolder runs every 60 minutes and will overwrite ACLs on protected objects, " +
                "so any such ACE would be removed and the delegation would silently break."
        }
    }

    Context 'Schema Admins group ACL' {

        BeforeAll {
            $dn = (Get-ADDomain).DistinguishedName
            $forest = Get-ADForest -ErrorAction SilentlyContinue
            if ($forest) {
                $forestDN = $forest.RootDomain -replace '\.', ',DC=' | ForEach-Object { "DC=$_" }
                # Schema Admins lives in the forest root domain's Users container.
                $script:SchemaAdminsDN = "CN=Schema Admins,CN=Users,DC=$($forest.RootDomain -replace '\.', ',DC=')"
            }
            else {
                $script:SchemaAdminsDN = "CN=Schema Admins,CN=Users,$dn"
            }
        }

        It 'Schema Admins ACL contains no explicit ACEs from GS-LZ groups' {
            $acl = Get-Acl -Path "AD:$($script:SchemaAdminsDN)" -ErrorAction Stop
            $lzSidValues = $script:LzGroupSids | ForEach-Object { $_.Value }

            $violations = $acl.Access | Where-Object {
                if ($_.IsInherited -ne $false) { return $false }
                $sid = $null
                if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                    $sid = $_.IdentityReference
                }
                else {
                    try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
                    catch { return $false }
                }
                return ($lzSidValues -contains $sid.Value)
            }

            $violations | Should -BeNullOrEmpty
        }
    }
}
