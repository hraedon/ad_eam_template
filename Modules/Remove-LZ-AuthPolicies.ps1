<#
.SYNOPSIS
    Removes LZ Authentication Policy Silos and Authentication Policies.
    Silos must be removed before policies (silos hold policy references).
    Called by Remove-ADLandingZone.ps1 — do not invoke directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [int]    $TierCount,
    [Parameter(Mandatory)] [string] $DomainDN,
    [Parameter(Mandatory)] [string] $DomainFQDN,
    [Parameter(Mandatory)] [string] $LogPath
)

function Remove-LZAuthPolicies {
    param(
        [int]    $TierCount,
        [string] $DomainDN,
        [string] $DomainFQDN,
        [string] $LogPath
    )

    # Remove silos first (they reference policies).
    for ($n = 0; $n -lt $TierCount; $n++) {
        $siloName = "LZ-T$n-Silo"
        try {
            $silo = Get-ADAuthenticationPolicySilo -Identity $siloName -ErrorAction SilentlyContinue
            if ($silo) {
                # Disable accidental deletion protection before removing.
                Set-ADAuthenticationPolicySilo -Identity $siloName `
                    -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                Remove-ADAuthenticationPolicySilo -Identity $siloName -Confirm:$false -ErrorAction Stop
                Write-LZLog -LogPath $LogPath -Module 'RemoveAuthPolicies' -Action 'Removed' `
                    -ObjectType 'Silo' -ObjectDN $siloName `
                    -Detail "Authentication policy silo $siloName removed"
                Write-Host "  [Removed] $siloName"
            }
            else {
                Write-LZLog -LogPath $LogPath -Module 'RemoveAuthPolicies' -Action 'Skipped' `
                    -ObjectType 'Silo' -ObjectDN $siloName -Detail "$siloName not found"
                Write-Host "  [Skipped] $siloName not found"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module 'RemoveAuthPolicies' -Action 'Error' `
                -ObjectType 'Silo' -ObjectDN $siloName -Detail $_.Exception.Message
            Write-Warning "  [Error] $siloName : $($_.Exception.Message)"
        }
    }

    # Remove policies.
    for ($n = 0; $n -lt $TierCount; $n++) {
        $policyName = "LZ-T$n-AuthPolicy"
        try {
            $policy = Get-ADAuthenticationPolicy -Identity $policyName -ErrorAction SilentlyContinue
            if ($policy) {
                Set-ADAuthenticationPolicy -Identity $policyName `
                    -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                Remove-ADAuthenticationPolicy -Identity $policyName -Confirm:$false -ErrorAction Stop
                Write-LZLog -LogPath $LogPath -Module 'RemoveAuthPolicies' -Action 'Removed' `
                    -ObjectType 'AuthPolicy' -ObjectDN $policyName `
                    -Detail "Authentication policy $policyName removed"
                Write-Host "  [Removed] $policyName"
            }
            else {
                Write-LZLog -LogPath $LogPath -Module 'RemoveAuthPolicies' -Action 'Skipped' `
                    -ObjectType 'AuthPolicy' -ObjectDN $policyName -Detail "$policyName not found"
                Write-Host "  [Skipped] $policyName not found"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module 'RemoveAuthPolicies' -Action 'Error' `
                -ObjectType 'AuthPolicy' -ObjectDN $policyName -Detail $_.Exception.Message
            Write-Warning "  [Error] $policyName : $($_.Exception.Message)"
        }
    }
}

Remove-LZAuthPolicies -TierCount $TierCount -DomainDN $DomainDN -DomainFQDN $DomainFQDN -LogPath $LogPath
