<#
.SYNOPSIS
    Removes all _LZ_ OUs created by the deployer.
    Disables ProtectedFromAccidentalDeletion on each OU before removal.
    Removes sub-OUs before tier OUs, and tier OUs before Quarantine.
    IMPORTANT: Caller must ensure all user/computer objects inside the OUs
    are removed before calling this module. This module only removes the
    OU objects themselves; it will error if any OU contains remaining objects.
    Called by Remove-ADLandingZone.ps1 — do not invoke directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [int]    $TierCount,
    [Parameter(Mandatory)] [string] $DomainDN,
    [Parameter(Mandatory)] [string] $LogPath
)

function Remove-LZOU {
    param(
        [string] $OuDN,
        [string] $Label,
        [string] $LogPath
    )

    try {
        $ou = Get-ADOrganizationalUnit -Identity $OuDN -ErrorAction SilentlyContinue
        if ($ou) {
            # Disable accidental deletion protection first.
            Set-ADOrganizationalUnit -Identity $OuDN `
                -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
            Remove-ADOrganizationalUnit -Identity $OuDN -Confirm:$false -ErrorAction Stop
            Write-LZLog -LogPath $LogPath -Module 'RemoveOUs' -Action 'Removed' `
                -ObjectType 'OU' -ObjectDN $OuDN -Detail "$Label removed"
            Write-Host "  [Removed] $Label ($OuDN)"
        }
        else {
            Write-LZLog -LogPath $LogPath -Module 'RemoveOUs' -Action 'Skipped' `
                -ObjectType 'OU' -ObjectDN $OuDN -Detail "$Label not found"
            Write-Host "  [Skipped] $Label not found"
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module 'RemoveOUs' -Action 'Error' `
            -ObjectType 'OU' -ObjectDN $OuDN -Detail $_.Exception.Message
        Write-Warning "  [Error] $Label : $($_.Exception.Message)"
    }
}

# Sub-OUs must be removed before their parent tier OUs.
for ($n = 0; $n -lt $TierCount; $n++) {
    $tierDN = "OU=_LZ_T$n,$DomainDN"
    foreach ($category in 'Accounts', 'Devices', 'ServiceAccounts') {
        $subDN = "OU=_LZ_T${n}_$category,$tierDN"
        Remove-LZOU -OuDN $subDN -Label "_LZ_T${n}_$category" -LogPath $LogPath
    }
}

# Now remove tier OUs.
for ($n = 0; $n -lt $TierCount; $n++) {
    $tierDN = "OU=_LZ_T$n,$DomainDN"
    Remove-LZOU -OuDN $tierDN -Label "_LZ_T$n" -LogPath $LogPath
}

# Remove Quarantine OU.
$quarantineDN = "OU=_LZ_Quarantine,$DomainDN"
Remove-LZOU -OuDN $quarantineDN -Label '_LZ_Quarantine' -LogPath $LogPath
