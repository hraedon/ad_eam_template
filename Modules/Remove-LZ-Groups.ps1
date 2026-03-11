<#
.SYNOPSIS
    Removes all GS-LZ-* security groups and the CN=_LZ_Groups container.
    Removes groups in dependency order: per-tier groups, gMSA host groups,
    T0-Devices group, Global-Readers, then the container itself.
    Called by Remove-ADLandingZone.ps1 — do not invoke directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [int]    $TierCount,
    [Parameter(Mandatory)] [string] $DomainDN,
    [Parameter(Mandatory)] [string] $LogPath
)

function Remove-LZGroups {
    param(
        [int]    $TierCount,
        [string] $DomainDN,
        [string] $LogPath
    )

    $containerDN  = "CN=_LZ_Groups,$DomainDN"

    # Build the full list of groups to remove, in a safe removal order.
    # Groups that are members of other groups come first (so memberships
    # are already cleared when the containing group is removed).
    $groupsToRemove = [System.Collections.Generic.List[string]]::new()

    # Per-tier groups (Admins, Readers, SvcAccts, gMSAHosts).
    for ($n = 0; $n -lt $TierCount; $n++) {
        foreach ($role in 'Admins', 'Readers', 'SvcAccts', 'gMSAHosts') {
            $groupsToRemove.Add("GS-LZ-T$n-$role")
        }
    }

    # T0-Devices and Global-Readers.
    $groupsToRemove.Add('GS-LZ-T0-Devices')
    $groupsToRemove.Add('GS-LZ-Global-Readers')

    foreach ($groupName in $groupsToRemove) {
        try {
            $grp = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if ($grp) {
                Remove-ADGroup -Identity $groupName -Confirm:$false -ErrorAction Stop
                Write-LZLog -LogPath $LogPath -Module 'RemoveGroups' -Action 'Removed' `
                    -ObjectType 'Group' -ObjectDN $grp.DistinguishedName `
                    -Detail "Security group $groupName removed"
                Write-Host "  [Removed] $groupName"
            }
            else {
                Write-LZLog -LogPath $LogPath -Module 'RemoveGroups' -Action 'Skipped' `
                    -ObjectType 'Group' -ObjectDN "CN=$groupName,$containerDN" `
                    -Detail "$groupName not found"
                Write-Host "  [Skipped] $groupName not found"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module 'RemoveGroups' -Action 'Error' `
                -ObjectType 'Group' -ObjectDN "CN=$groupName,$containerDN" `
                -Detail $_.Exception.Message
            Write-Warning "  [Error] $groupName : $($_.Exception.Message)"
        }
    }

    # Remove the container itself (must be empty at this point).
    try {
        $container = Get-ADObject -Identity $containerDN -ErrorAction SilentlyContinue
        if ($container) {
            Remove-ADObject -Identity $containerDN -Confirm:$false -ErrorAction Stop
            Write-LZLog -LogPath $LogPath -Module 'RemoveGroups' -Action 'Removed' `
                -ObjectType 'Container' -ObjectDN $containerDN `
                -Detail 'CN=_LZ_Groups container removed'
            Write-Host "  [Removed] CN=_LZ_Groups container"
        }
        else {
            Write-LZLog -LogPath $LogPath -Module 'RemoveGroups' -Action 'Skipped' `
                -ObjectType 'Container' -ObjectDN $containerDN -Detail 'Container not found'
            Write-Host "  [Skipped] CN=_LZ_Groups container not found"
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module 'RemoveGroups' -Action 'Error' `
            -ObjectType 'Container' -ObjectDN $containerDN -Detail $_.Exception.Message
        Write-Warning "  [Error] Container removal: $($_.Exception.Message)"
    }
}

Remove-LZGroups -TierCount $TierCount -DomainDN $DomainDN -LogPath $LogPath
