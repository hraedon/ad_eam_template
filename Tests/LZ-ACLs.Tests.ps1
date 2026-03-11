<#
.SYNOPSIS
    Pester tests for the AD Landing Zone ACL delegations.

.DESCRIPTION
    Verifies that the expected ACEs are present and explicit (not inherited)
    on each tier OU. Uses the same rights constants as the deployment module.

    Group SIDs are resolved inside each It block rather than in BeforeAll to
    avoid Pester 5 scope issues with hashtable lookups inside ForEach contexts.
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

$script:DomainDN = $env:LZ_TEST_DOMAINDN
if (-not $script:DomainDN) { $script:DomainDN = (Get-ADDomain).DistinguishedName }

# Build per-tier test case data at discovery time.
$script:TierAclCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    @{
        TierN         = $n
        TierOU        = "OU=_LZ_T$n,$($script:DomainDN)"
        TierLabel     = "OU=_LZ_T$n"
        AdminsName    = "GS-LZ-T$n-Admins"
        ReadersName   = "GS-LZ-T$n-Readers"
    }
}

# Pre-compute OUs used in cross-tier isolation tests at discovery time.
# $script: vars set at top-level are NOT reliably accessible inside It blocks
# that are inside non-ForEach Contexts at test execution time in Pester 5.
$script:T0OuDN = "OU=_LZ_T0,$($script:DomainDN)"
$script:T1OuDN = "OU=_LZ_T1,$($script:DomainDN)"

Describe 'LZ ACL Delegations' -Tag 'ACLs' {

    BeforeAll {
        # Rights constants matching the deployment module.
        $script:ReadListRights    = (
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor
            [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
            [System.DirectoryServices.ActiveDirectoryRights]::ListObject
        )
        $script:FullControlRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $script:InheritAll        = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
        $script:GlobalReaderSid   = (Get-ADGroup -Identity 'GS-LZ-Global-Readers').SID

        # Helper: test that a specific EXPLICIT ACE is present on an OU.
        function Test-LZAcePresent {
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

    Context "ACEs on <TierLabel>" -ForEach $script:TierAclCases {

        It "GS-LZ-Global-Readers has explicit ReadList ACE on <TierLabel> (InheritAll)" {
            Test-LZAcePresent `
                -OuDN        $TierOU `
                -GroupSid    $script:GlobalReaderSid `
                -Rights      $script:ReadListRights `
                -Inheritance $script:InheritAll |
                Should -Be $true
        }

        It "GS-LZ-T<TierN>-Admins has explicit GenericAll ACE on <TierLabel> (InheritAll)" {
            # Resolve SID inline to avoid Pester 5 hashtable-in-ForEach scope limitation.
            $adminSid = (Get-ADGroup -Identity $AdminsName).SID
            Test-LZAcePresent `
                -OuDN        $TierOU `
                -GroupSid    $adminSid `
                -Rights      $script:FullControlRights `
                -Inheritance $script:InheritAll |
                Should -Be $true
        }

        It "GS-LZ-T<TierN>-Readers has explicit ReadList ACE on <TierLabel> (InheritAll)" {
            $readerSid = (Get-ADGroup -Identity $ReadersName).SID
            Test-LZAcePresent `
                -OuDN        $TierOU `
                -GroupSid    $readerSid `
                -Rights      $script:ReadListRights `
                -Inheritance $script:InheritAll |
                Should -Be $true
        }
    }

    Context 'Cross-tier isolation' {

        It "GS-LZ-T0-Readers has no explicit ACE on OU=_LZ_T1" -Skip:($script:TierCount -lt 2) {
            $t0ReaderSid = (Get-ADGroup -Identity 'GS-LZ-T0-Readers').SID
            Test-LZAcePresent `
                -OuDN        $script:T1OuDN `
                -GroupSid    $t0ReaderSid `
                -Rights      $script:ReadListRights `
                -Inheritance $script:InheritAll |
                Should -Be $false
        }

        It "GS-LZ-T1-Readers has no explicit ACE on OU=_LZ_T0" -Skip:($script:TierCount -lt 2) {
            $t1ReaderSid = (Get-ADGroup -Identity 'GS-LZ-T1-Readers').SID
            Test-LZAcePresent `
                -OuDN        $script:T0OuDN `
                -GroupSid    $t1ReaderSid `
                -Rights      $script:ReadListRights `
                -Inheritance $script:InheritAll |
                Should -Be $false
        }
    }
}
