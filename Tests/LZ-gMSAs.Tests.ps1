<#
.SYNOPSIS
    Pester tests for the AD Landing Zone gMSA accounts (v2).
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

$script:DomainDN = $env:LZ_TEST_DOMAINDN
if (-not $script:DomainDN) { $script:DomainDN = (Get-ADDomain).DistinguishedName }

$script:DomainFQDN = $env:LZ_TEST_DOMAINFQDN
if (-not $script:DomainFQDN) { $script:DomainFQDN = (Get-ADDomain).DNSRoot }

# Build per-tier gMSA test cases at discovery time.
$script:GmsaCases = for ($n = 0; $n -lt $script:TierCount; $n++) {
    @{
        TierN         = $n
        HostGroupName = "GS-LZ-T$n-gMSAHosts"
        GmsaName      = "gMSA-LZ-T$n"
        GmsaDNS       = "gMSA-LZ-T$n.$($script:DomainFQDN)"
        GmsaDN        = "CN=gMSA-LZ-T$n,OU=_LZ_T${n}_ServiceAccounts,OU=_LZ_T$n,$($script:DomainDN)"
    }
}

Describe 'LZ gMSA Accounts' -Tag 'gMSAs' {

    Context 'KDS Root Key' {

        It 'At least one KDS Root Key exists' {
            $keys = @(Get-KdsRootKey -ErrorAction SilentlyContinue)
            $keys.Count | Should -BeGreaterThan 0
        }

        It 'At least one KDS Root Key is currently effective' {
            $keys   = @(Get-KdsRootKey -ErrorAction SilentlyContinue)
            $usable = $keys | Where-Object { $_.EffectiveTime -le (Get-Date) }
            $usable | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Tier <TierN> gMSA: <GmsaName>' -ForEach $script:GmsaCases {

        It '<GmsaName> gMSA account exists' {
            { Get-ADServiceAccount -Identity $GmsaName -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<GmsaName> is located in OU=_LZ_T<TierN>_ServiceAccounts' {
            $acct = Get-ADServiceAccount -Identity $GmsaName
            $acct.DistinguishedName | Should -Be $GmsaDN
        }

        It "<GmsaName> DNSHostName is correct" {
            $acct = Get-ADServiceAccount -Identity $GmsaName -Properties DNSHostName
            $acct.DNSHostName | Should -Be $GmsaDNS
        }

        It '<GmsaName> PrincipalsAllowedToRetrieveManagedPassword includes <HostGroupName>' {
            $acct = Get-ADServiceAccount `
                -Identity   $GmsaName `
                -Properties PrincipalsAllowedToRetrieveManagedPassword `
                -ErrorAction Stop

            $hostGroup  = Get-ADGroup -Identity $HostGroupName
            $principals = @($acct.PrincipalsAllowedToRetrieveManagedPassword)
            $found      = $principals | Where-Object {
                try {
                    $resolved = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                    $resolved -and ($resolved.SID.Value -eq $hostGroup.SID.Value)
                }
                catch { $false }
            }
            $found | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Tier <TierN> host group: <HostGroupName>' -ForEach $script:GmsaCases {

        It '<HostGroupName> exists' {
            { Get-ADGroup -Identity $HostGroupName -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<HostGroupName> is a Global Security group' {
            $g = Get-ADGroup -Identity $HostGroupName
            $g.GroupScope    | Should -Be 'Global'
            $g.GroupCategory | Should -Be 'Security'
        }

        It '<HostGroupName> SamAccountName is within 20-character limit' {
            $g = Get-ADGroup -Identity $HostGroupName
            $g.SamAccountName.Length | Should -BeLessOrEqual 20
        }
    }
}
