<#
.SYNOPSIS
    Creates the AD Landing Zone security groups.

.DESCRIPTION
    Creates the CN=_LZ_Groups container under the domain root (if absent), then
    creates all Global Security groups required by the Landing Zone. Fully
    idempotent — existing groups are logged as Skipped and left untouched.

    Groups created:

        CN=_LZ_Groups,$DomainDN          (container)
        +-- GS-LZ-Global-Readers         (LZ-wide read/list -- monitoring, SIEM, audit)
        +-- Per tier (n = 0 ... TierCount-1):
            +-- GS-LZ-T{n}-Admins        (Full Control on _LZ_T{n} subtree)
            +-- GS-LZ-T{n}-Readers       (Read+List on _LZ_T{n} subtree only)
            +-- GS-LZ-T{n}-SvcAccts      (placeholder for managed service accounts; abbreviated to stay within 20-char SamAccountName limit)

    All groups are Global scope, Security category, placed in CN=_LZ_Groups.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER TierCount
    Number of tiers to deploy.

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZGroups {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module      = 'Groups'
    $containerDN = "CN=_LZ_Groups,$DomainDN"

    # ------------------------------------------------------------------
    # Ensure the _LZ_Groups container exists.
    # This is a CN=Container object, not an OU, so that groups are
    # separated from the tier OU hierarchy and have a single predictable
    # lookup path for all downstream tooling.
    # ------------------------------------------------------------------
    try {
        Get-ADObject -Identity $containerDN -ErrorAction Stop | Out-Null

        Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
            -ObjectType 'Container' -ObjectDN $containerDN `
            -Detail "Container CN=_LZ_Groups already exists; no changes made."
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        if ($PSCmdlet.ShouldProcess($containerDN, 'New-ADObject (Container)')) {
            try {
                New-ADObject -Type Container -Name '_LZ_Groups' -Path $DomainDN -ErrorAction Stop

                Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                    -ObjectType 'Container' -ObjectDN $containerDN `
                    -Detail "Created CN=_LZ_Groups container under domain root."
            }
            catch {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                    -ObjectType 'Container' -ObjectDN $containerDN `
                    -Detail "Failed to create _LZ_Groups container: $($_.Exception.Message)"
                throw
            }
        }
        else {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                -ObjectType 'Container' -ObjectDN $containerDN `
                -Detail "Would create CN=_LZ_Groups container under domain root."
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'Container' -ObjectDN $containerDN `
            -Detail "Unexpected error checking _LZ_Groups container: $($_.Exception.Message)"
        throw
    }

    # ------------------------------------------------------------------
    # Internal helper: create a single Global Security group idempotently.
    # Looks up by SamAccountName so the check is not path-sensitive.
    # ------------------------------------------------------------------
    function New-LZGroup {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$Name,
            [string]$Description
        )

        $dn = "CN=$Name,$containerDN"

        try {
            Get-ADGroup -Identity $Name -ErrorAction Stop | Out-Null

            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'Group' -ObjectDN $dn `
                -Detail "Group '$Name' already exists; no changes made."
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($PSCmdlet.ShouldProcess($dn, 'New-ADGroup')) {
                try {
                    New-ADGroup `
                        -Name        $Name `
                        -SamAccountName $Name `
                        -GroupScope  Global `
                        -GroupCategory Security `
                        -Path        $containerDN `
                        -Description $Description `
                        -ErrorAction Stop

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'Group' -ObjectDN $dn `
                        -Detail "Created Global Security group. Description: $Description"
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'Group' -ObjectDN $dn `
                        -Detail "Failed to create group '$Name': $($_.Exception.Message)"
                    throw
                }
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'Group' -ObjectDN $dn `
                    -Detail "Would create Global Security group. Description: $Description"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'Group' -ObjectDN $dn `
                -Detail "Unexpected error checking group '$Name': $($_.Exception.Message)"
            throw
        }
    }

    # ------------------------------------------------------------------
    # Global Reader — one group covering all LZ tiers.
    # Intended for monitoring accounts, SIEM service accounts, and audit
    # tooling. ACL module applies read/list rights to every tier OU.
    # ------------------------------------------------------------------
    New-LZGroup `
        -Name        'GS-LZ-Global-Readers' `
        -Description 'Read and List on all _LZ_ OUs. Intended for monitoring accounts, SIEM service accounts, and audit tooling.'

    # ------------------------------------------------------------------
    # Per-tier groups
    # ------------------------------------------------------------------
    for ($n = 0; $n -lt $TierCount; $n++) {

        New-LZGroup `
            -Name        "GS-LZ-T$n-Admins" `
            -Description "Full Control on _LZ_T$n subtree. Members require T$n PAW devices and are enrolled in LZ-T$n-Silo."

        New-LZGroup `
            -Name        "GS-LZ-T$n-Readers" `
            -Description "Read and List rights on _LZ_T$n subtree only. No access to sibling tiers."

        New-LZGroup `
            -Name        "GS-LZ-T$n-SvcAccts" `
            -Description "Placeholder group for managed service accounts at Tier $n. SamAccountName abbreviated to stay within 20 characters. Populated during migration phase."
    }
}
