<#
.SYNOPSIS
    Pester tests for the AD Landing Zone security groups.
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

$script:DomainDN = $env:LZ_TEST_DOMAINDN
if (-not $script:DomainDN) { $script:DomainDN = (Get-ADDomain).DistinguishedName }

$script:ContainerDN = "CN=_LZ_Groups,$($script:DomainDN)"

# Pre-compute DNs used in non-ForEach contexts at discovery time.
# BeforeAll blocks cannot access $script: vars set here; move all
# string computations that depend on DomainDN to this top-level section.
$script:ContainerDNLocal      = "CN=_LZ_Groups,$($script:DomainDN)"
$script:GlobalReaderExpectedDN = "CN=GS-LZ-Global-Readers,CN=_LZ_Groups,$($script:DomainDN)"
$script:T0DevicesExpectedDN   = "CN=GS-LZ-T0-Devices,CN=_LZ_Groups,$($script:DomainDN)"

# Build parameterised test case data at discovery time.
# Pester 5 requires data to be passed via -ForEach; for-loop captured
# variables are not reliably accessible inside It blocks.
# ExpectedDN is embedded in each case because $script:ContainerDN is not
# reliably accessible inside ForEach It blocks at test execution time.

# Per-tier group cases: three groups per tier.
$script:TierGroupCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    foreach ($role in 'Admins', 'Readers') {
        @{
            TierN      = $n
            GroupName  = "GS-LZ-T$n-$role"
            ExpectedDN = "CN=GS-LZ-T$n-$role,CN=_LZ_Groups,$($script:DomainDN)"
        }
    }
    # SvcAccts has an extra SamAccountName-length test, handled separately.
    @{
        TierN      = $n
        GroupName  = "GS-LZ-T$n-SvcAccts"
        ExpectedDN = "CN=GS-LZ-T$n-SvcAccts,CN=_LZ_Groups,$($script:DomainDN)"
    }
}

$script:SvcAcctCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    @{ TierN = $n; GroupName = "GS-LZ-T$n-SvcAccts" }
}

$script:GmsaHostCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    @{
        TierN      = $n
        GroupName  = "GS-LZ-T$n-gMSAHosts"
        ExpectedDN = "CN=GS-LZ-T$n-gMSAHosts,CN=_LZ_Groups,$($script:DomainDN)"
    }
}

Describe 'LZ Security Groups' -Tag 'Groups' {

    BeforeAll {
        # Describe-level BeforeAll runs at execution time. $script: vars set here
        # are accessible in all child Context/It blocks, including non-ForEach ones.
        # Re-derive DomainDN directly; top-level $script:DomainDN is only available
        # at discovery time and is not reliably accessible at execution time.
        $dn = (Get-ADDomain).DistinguishedName
        $script:ContainerDNLocal      = "CN=_LZ_Groups,$dn"
        $script:GlobalReaderExpectedDN = "CN=GS-LZ-Global-Readers,CN=_LZ_Groups,$dn"
        $script:T0DevicesExpectedDN   = "CN=GS-LZ-T0-Devices,CN=_LZ_Groups,$dn"
    }

    Context 'CN=_LZ_Groups container' {

        It 'CN=_LZ_Groups container exists at domain root' {
            { Get-ADObject -Identity $script:ContainerDNLocal -ErrorAction Stop } |
                Should -Not -Throw
        }
    }

    Context 'Global Reader group' {

        It 'GS-LZ-Global-Readers exists' {
            { Get-ADGroup -Identity 'GS-LZ-Global-Readers' -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'GS-LZ-Global-Readers is a Global Security group' {
            $g = Get-ADGroup -Identity 'GS-LZ-Global-Readers'
            $g.GroupScope    | Should -Be 'Global'
            $g.GroupCategory | Should -Be 'Security'
        }

        It 'GS-LZ-Global-Readers is in CN=_LZ_Groups' {
            $g = Get-ADGroup -Identity 'GS-LZ-Global-Readers'
            $g.DistinguishedName | Should -Be $script:GlobalReaderExpectedDN
        }
    }

    Context 'Per-tier group: <GroupName>' -ForEach $script:TierGroupCases {

        It '<GroupName> exists' {
            { Get-ADGroup -Identity $GroupName -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<GroupName> is a Global Security group' {
            $g = Get-ADGroup -Identity $GroupName
            $g.GroupScope    | Should -Be 'Global'
            $g.GroupCategory | Should -Be 'Security'
        }

        It '<GroupName> is in CN=_LZ_Groups' {
            $g = Get-ADGroup -Identity $GroupName
            $g.DistinguishedName | Should -Be $ExpectedDN
        }
    }

    Context 'SamAccountName length: <GroupName>' -ForEach $script:SvcAcctCases {
        It '<GroupName> SamAccountName is within 20-character limit' {
            $g = Get-ADGroup -Identity $GroupName
            $g.SamAccountName.Length | Should -BeLessOrEqual 20
        }
    }

    Context 'V2: GS-LZ-T0-Devices group' {

        It 'GS-LZ-T0-Devices exists' {
            { Get-ADGroup -Identity 'GS-LZ-T0-Devices' -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'GS-LZ-T0-Devices is a Global Security group in CN=_LZ_Groups' {
            $g = Get-ADGroup -Identity 'GS-LZ-T0-Devices'
            $g.GroupScope    | Should -Be 'Global'
            $g.GroupCategory | Should -Be 'Security'
            $g.DistinguishedName | Should -Be $script:T0DevicesExpectedDN
        }
    }

    Context 'V2: gMSA host group: <GroupName>' -ForEach $script:GmsaHostCases {

        It '<GroupName> exists' {
            { Get-ADGroup -Identity $GroupName -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<GroupName> is a Global Security group in CN=_LZ_Groups' {
            $g = Get-ADGroup -Identity $GroupName
            $g.GroupScope    | Should -Be 'Global'
            $g.GroupCategory | Should -Be 'Security'
            $g.DistinguishedName | Should -Be $ExpectedDN
        }

        It '<GroupName> SamAccountName is within 20-character limit' {
            $g = Get-ADGroup -Identity $GroupName
            $g.SamAccountName.Length | Should -BeLessOrEqual 20
        }
    }
}
