<#
.SYNOPSIS
    Pester tests for the AD Landing Zone Authentication Policies and Silos.
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

# Build test case data at discovery time.
$allTierConfig = @(
    @{ Tier = 0; PolicyName = 'LZ-T0-AuthPolicy'; SiloName = 'LZ-T0-Silo'; TgtMins = 240; Enforce = $true }
    @{ Tier = 1; PolicyName = 'LZ-T1-AuthPolicy'; SiloName = 'LZ-T1-Silo'; TgtMins = 480; Enforce = $false }
    @{ Tier = 2; PolicyName = 'LZ-T2-AuthPolicy'; SiloName = 'LZ-T2-Silo'; TgtMins = 600; Enforce = $false }
)
$script:TierPolicyCases = $allTierConfig | Where-Object { $_.Tier -lt $script:TierCount }
$script:TierSiloCases   = $allTierConfig | Where-Object { $_.Tier -lt $script:TierCount }

Describe 'LZ Authentication Policies' -Tag 'AuthPolicies' {

    Context 'Policy: <PolicyName>' -ForEach $script:TierPolicyCases {

        It '<PolicyName> exists' {
            { Get-ADAuthenticationPolicy -Identity $PolicyName -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<PolicyName> has UserTGTLifetimeMins = <TgtMins>' {
            $pol = Get-ADAuthenticationPolicy -Identity $PolicyName -Properties UserTGTLifetimeMins
            $pol.UserTGTLifetimeMins | Should -Be $TgtMins
        }

        It '<PolicyName> Enforce = <Enforce>' {
            $pol = Get-ADAuthenticationPolicy -Identity $PolicyName
            $pol.Enforce | Should -Be $Enforce
        }

        It '<PolicyName> is ProtectedFromAccidentalDeletion' {
            $pol = Get-ADAuthenticationPolicy -Identity $PolicyName -Properties ProtectedFromAccidentalDeletion
            $pol.ProtectedFromAccidentalDeletion | Should -Be $true
        }
    }

    Context 'T0 device restriction (v2)' {

        It 'LZ-T0-AuthPolicy has UserAllowedToAuthenticateFrom set (non-empty)' {
            $pol = Get-ADAuthenticationPolicy -Identity 'LZ-T0-AuthPolicy' -Properties UserAllowedToAuthenticateFrom
            $pol.UserAllowedToAuthenticateFrom | Should -Not -BeNullOrEmpty
        }

        It 'LZ-T0-AuthPolicy UserAllowedToAuthenticateFrom contains GS-LZ-T0-Devices SID' {
            $pol       = Get-ADAuthenticationPolicy -Identity 'LZ-T0-AuthPolicy' -Properties UserAllowedToAuthenticateFrom
            $sidValue  = (Get-ADGroup -Identity 'GS-LZ-T0-Devices').SID.Value
            $pol.UserAllowedToAuthenticateFrom | Should -Match $sidValue
        }

        It 'LZ-T0-AuthPolicy uses Member_of_any restriction (not baseline @DEVICE.domainjoined)' {
            $pol = Get-ADAuthenticationPolicy -Identity 'LZ-T0-AuthPolicy' -Properties UserAllowedToAuthenticateFrom
            $pol.UserAllowedToAuthenticateFrom | Should -Match 'Member_of_any'
            $pol.UserAllowedToAuthenticateFrom | Should -Not -Match '@DEVICE\.domainjoined'
        }
    }

    Context 'Silo: <SiloName>' -ForEach $script:TierSiloCases {

        It '<SiloName> exists' {
            { Get-ADAuthenticationPolicySilo -Identity $SiloName -ErrorAction Stop } |
                Should -Not -Throw
        }

        It '<SiloName> is linked to <PolicyName>' {
            $silo = Get-ADAuthenticationPolicySilo -Identity $SiloName -Properties UserAuthenticationPolicy
            $silo.UserAuthenticationPolicy | Should -Match $PolicyName
        }

        It '<SiloName> is ProtectedFromAccidentalDeletion' {
            $silo = Get-ADAuthenticationPolicySilo -Identity $SiloName -Properties ProtectedFromAccidentalDeletion
            $silo.ProtectedFromAccidentalDeletion | Should -Be $true
        }
    }
}
