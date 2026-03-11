<#
.SYNOPSIS
    Pester tests for the AD Landing Zone OU structure.
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

$script:DomainDN = $env:LZ_TEST_DOMAINDN
if (-not $script:DomainDN) { $script:DomainDN = (Get-ADDomain).DistinguishedName }

# Build per-tier test cases at discovery time so -ForEach can use them.
# Pester 5 requires data to be passed explicitly via -ForEach; variables
# captured in for-loop bodies are not reliably accessible inside It blocks.
$script:TierOuCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    @{
        TierN    = $n
        TierName = "_LZ_T$n"
        TierDN   = "OU=_LZ_T$n,$($script:DomainDN)"
    }
}

$script:QuarantineDN = "OU=_LZ_Quarantine,$($script:DomainDN)"

$script:SubOuCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    foreach ($category in 'Accounts', 'Devices', 'ServiceAccounts') {
        @{
            TierN      = $n
            Category   = $category
            SubName    = "_LZ_T${n}_$category"
            SubDN      = "OU=_LZ_T${n}_$category,OU=_LZ_T$n,$($script:DomainDN)"
            ParentName = "_LZ_T$n"
        }
    }
}

Describe 'LZ OU Structure' -Tag 'OUs' {

    BeforeAll {
        # Describe-level BeforeAll runs at execution time. $script: vars set here
        # are accessible in all child Context/It blocks, including non-ForEach ones.
        # Re-derive DomainDN directly rather than depending on the discovery-time
        # $script:DomainDN, which is not reliably accessible at execution time.
        $script:QuarantineDN = "OU=_LZ_Quarantine,$((Get-ADDomain).DistinguishedName)"
    }

    Context 'Tier OU: <TierName>' -ForEach $script:TierOuCases {

        It '<TierName> exists at domain root' {
            { Get-ADOrganizationalUnit -Identity $TierDN -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<TierName> has ProtectedFromAccidentalDeletion = true' {
            $ou = Get-ADOrganizationalUnit -Identity $TierDN -Properties ProtectedFromAccidentalDeletion
            $ou.ProtectedFromAccidentalDeletion | Should -Be $true
        }
    }

    Context 'Sub-OU: <SubName> (under <ParentName>)' -ForEach $script:SubOuCases {

        It '<SubName> exists under <ParentName>' {
            { Get-ADOrganizationalUnit -Identity $SubDN -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<SubName> has ProtectedFromAccidentalDeletion = true' {
            $ou = Get-ADOrganizationalUnit -Identity $SubDN -Properties ProtectedFromAccidentalDeletion
            $ou.ProtectedFromAccidentalDeletion | Should -Be $true
        }
    }

    Context 'Quarantine OU' {

        It 'OU=_LZ_Quarantine exists at domain root' {
            { Get-ADOrganizationalUnit -Identity $script:QuarantineDN -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'OU=_LZ_Quarantine has ProtectedFromAccidentalDeletion = true' {
            $ou = Get-ADOrganizationalUnit -Identity $script:QuarantineDN -Properties ProtectedFromAccidentalDeletion
            $ou.ProtectedFromAccidentalDeletion | Should -Be $true
        }
    }
}
