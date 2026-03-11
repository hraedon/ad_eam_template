<#
.SYNOPSIS
    Pester tests for the Protected Users group membership.
#>

Import-Module ActiveDirectory -ErrorAction Stop

$script:TierCount = 3
if ($env:LZ_TEST_TIERCOUNT) { $script:TierCount = [int]$env:LZ_TEST_TIERCOUNT }

Describe 'LZ Protected Users' -Tag 'ProtectedUsers' {

    Context 'GS-LZ-T0-Admins membership in Protected Users' {

        It 'Protected Users group is accessible' {
            { Get-ADGroup -Identity 'Protected Users' -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'GS-LZ-T0-Admins is a direct member of Protected Users' {
            $t0Group = Get-ADGroup -Identity 'GS-LZ-T0-Admins'
            $members = Get-ADGroupMember -Identity 'Protected Users'
            $found   = $members | Where-Object { $_.SID -eq $t0Group.SID }
            $found | Should -Not -BeNullOrEmpty
        }
    }

    Context 'T1 and T2 admin groups are NOT in Protected Users (by design)' {

        It 'GS-LZ-T1-Admins is NOT a direct member of Protected Users' {
            $t1Group = Get-ADGroup -Identity 'GS-LZ-T1-Admins'
            $members = Get-ADGroupMember -Identity 'Protected Users'
            $found   = $members | Where-Object { $_.SID -eq $t1Group.SID }
            $found | Should -BeNullOrEmpty
        }

        It 'GS-LZ-T2-Admins is NOT a direct member of Protected Users' -Skip:($script:TierCount -lt 3) {
            $t2Group = Get-ADGroup -Identity 'GS-LZ-T2-Admins' -ErrorAction SilentlyContinue
            if (-not $t2Group) { return }
            $members = Get-ADGroupMember -Identity 'Protected Users'
            $found   = $members | Where-Object { $_.SID -eq $t2Group.SID }
            $found | Should -BeNullOrEmpty
        }
    }
}
