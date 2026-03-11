<#
.SYNOPSIS
    Creates the AD Landing Zone OU structure.

.DESCRIPTION
    Builds the tier OUs and their standard sub-OUs directly under the domain root,
    plus the always-present _LZ_Quarantine OU. All OUs are created with
    ProtectedFromAccidentalDeletion = $true. Fully idempotent — safe to re-run;
    existing OUs are logged as Skipped and left untouched.

    Structure produced (example for TierCount = 3):

        $DomainDN
        +-- OU=_LZ_T0
        |   +-- OU=_LZ_T0_Accounts
        |   +-- OU=_LZ_T0_Devices
        |   +-- OU=_LZ_T0_ServiceAccounts
        +-- OU=_LZ_T1
        |   +-- OU=_LZ_T1_Accounts
        |   +-- OU=_LZ_T1_Devices
        |   +-- OU=_LZ_T1_ServiceAccounts
        +-- OU=_LZ_T2
        |   +-- OU=_LZ_T2_Accounts
        |   +-- OU=_LZ_T2_Devices
        |   +-- OU=_LZ_T2_ServiceAccounts
        +-- OU=_LZ_Quarantine

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER TierCount
    Number of tiers to deploy (2 = T0+T1, 3 = T0+T1+T2, etc.).

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZOUs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module = 'OUs'

    # ------------------------------------------------------------------
    # Internal helper: create a single OU idempotently.
    # $Name  - the OU's CN (e.g. _LZ_T0)
    # $Path  - the parent DN under which the OU will be created
    # ------------------------------------------------------------------
    function New-LZOU {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$Name,
            [string]$Path
        )

        $dn = "OU=$Name,$Path"

        try {
            Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop | Out-Null

            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'OU' -ObjectDN $dn `
                -Detail "OU already exists; no changes made."
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # OU does not exist — create it (or preview creation in WhatIf mode).
            if ($PSCmdlet.ShouldProcess($dn, 'New-ADOrganizationalUnit')) {
                try {
                    New-ADOrganizationalUnit `
                        -Name $Name `
                        -Path $Path `
                        -ProtectedFromAccidentalDeletion $true `
                        -ErrorAction Stop

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'OU' -ObjectDN $dn `
                        -Detail "Created OU with ProtectedFromAccidentalDeletion=true."
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'OU' -ObjectDN $dn `
                        -Detail "Failed to create OU: $($_.Exception.Message)"
                    throw
                }
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'OU' -ObjectDN $dn `
                    -Detail "Would create OU with ProtectedFromAccidentalDeletion=true."
            }
        }
        catch {
            # Unexpected error querying for the OU.
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'OU' -ObjectDN $dn `
                -Detail "Unexpected error checking OU existence: $($_.Exception.Message)"
            throw
        }
    }

    # ------------------------------------------------------------------
    # Tier OUs and their sub-OUs
    # ------------------------------------------------------------------
    for ($n = 0; $n -lt $TierCount; $n++) {
        $tierName = "_LZ_T$n"

        # Create the tier root OU under the domain root.
        New-LZOU -Name $tierName -Path $DomainDN

        # Create the three standard sub-OUs inside the tier OU.
        $tierDN = "OU=$tierName,$DomainDN"
        foreach ($category in 'Accounts', 'Devices', 'ServiceAccounts') {
            New-LZOU -Name "_LZ_T${n}_$category" -Path $tierDN
        }
    }

    # ------------------------------------------------------------------
    # Quarantine OU — always created regardless of TierCount.
    # This OU is a staging area for objects pending tier assignment and
    # is intentionally placed outside the tier hierarchy so it inherits
    # no production GPOs.
    # ------------------------------------------------------------------
    New-LZOU -Name '_LZ_Quarantine' -Path $DomainDN
}
