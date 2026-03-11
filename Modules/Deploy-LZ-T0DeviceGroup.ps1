<#
.SYNOPSIS
    Creates the T0 device restriction group and upgrades the T0 authentication
    policy to restrict access to devices in that group.

.DESCRIPTION
    V2 module. Performs two related operations:

    1. Creates GS-LZ-T0-Devices in CN=_LZ_Groups -- a Global Security group
       whose members will be the computer accounts of T0 PAW devices.

    2. Updates LZ-T0-AuthPolicy.UserAllowedToAuthenticateFrom from the v1
       baseline SDDL (domain-joined device condition) to a group-SID condition
       that restricts T0 account authentication to devices in GS-LZ-T0-Devices.

       Baseline SDDL (set by v1 Deploy-LZ-AuthPolicies):
           O:SYG:SYD:(XA;OICI;CR;;;WD;(@DEVICE.domainjoined))

       Upgraded SDDL (set by this module):
           O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(<GS-LZ-T0-Devices-SID>)}))

       This is the migration-phase action anticipated by the v1 spec. The group
       starts empty; populate it with T0 PAW computer accounts before enforcing.

    Idempotent:
    - If GS-LZ-T0-Devices already exists, it is logged as Skipped.
    - If the policy's SDDL already contains the GS-LZ-T0-Devices SID, it is
      logged as Skipped.
    - If the policy contains a custom SDDL that is neither the baseline nor
      the expected group-SID form, the module logs a Warning and does NOT
      overwrite it. Manual review is required.

    ACL module note: GS-LZ-T0-Devices does NOT receive ACL delegations on the
    tier OUs. It is a device identity group, not an administrative delegation
    group. Its only function is to serve as the PrincipalsAllowedToAuthenticate
    boundary in the T0 auth policy.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZT0DeviceGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module         = 'T0DeviceGroup'
    $groupName      = 'GS-LZ-T0-Devices'
    $containerDN    = "CN=_LZ_Groups,$DomainDN"
    $groupDN        = "CN=$groupName,$containerDN"
    $policyName     = 'LZ-T0-AuthPolicy'
    $policyDN       = "CN=$policyName,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,$DomainDN"

    # Baseline SDDL written by the v1 auth policies module.
    # This is the exact string we expect to find if the policy has not yet been
    # upgraded. Comparison is case-insensitive because SDDL casing can vary.
    $baselineSddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@DEVICE.domainjoined))'

    # ------------------------------------------------------------------
    # Step 1: Create GS-LZ-T0-Devices
    # ------------------------------------------------------------------
    $deviceGroup = $null

    try {
        $deviceGroup = Get-ADGroup -Identity $groupName -ErrorAction Stop

        Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
            -ObjectType 'Group' -ObjectDN $groupDN `
            -Detail "Group '$groupName' already exists; no changes made."
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        try {
            New-ADGroup `
                -Name           $groupName `
                -SamAccountName $groupName `
                -GroupScope     Global `
                -GroupCategory  Security `
                -Path           $containerDN `
                -Description    'T0 PAW device computer accounts. Members of this group are the only devices from which T0 admin accounts may authenticate (enforced by LZ-T0-AuthPolicy). Populated during migration phase.' `
                -ErrorAction    Stop

            $deviceGroup = Get-ADGroup -Identity $groupName -ErrorAction Stop

            Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                -ObjectType 'Group' -ObjectDN $groupDN `
                -Detail "Created '$groupName'. Populate with T0 PAW computer accounts before relying on the device restriction for T0 auth policy enforcement."
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'Group' -ObjectDN $groupDN `
                -Detail "Failed to create '$groupName': $($_.Exception.Message)"
            throw
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'Group' -ObjectDN $groupDN `
            -Detail "Unexpected error checking '$groupName': $($_.Exception.Message)"
        throw
    }

    # ------------------------------------------------------------------
    # Step 2: Update LZ-T0-AuthPolicy UserAllowedToAuthenticateFrom
    # ------------------------------------------------------------------
    # Retrieve the group's SID -- needed to build the upgraded SDDL.
    if (-not $deviceGroup) {
        # Should not be reachable, but guard defensively.
        throw "GS-LZ-T0-Devices group SID is unavailable. Cannot build device-restriction SDDL."
    }

    $deviceGroupSid = $deviceGroup.SID.Value
    # The upgraded SDDL uses Member_of_any with the group SID.
    $upgradedSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($deviceGroupSid)}))"

    # Retrieve the current policy and its UserAllowedToAuthenticateFrom value.
    $existingPolicy = $null
    try {
        $existingPolicy = Get-ADAuthenticationPolicy `
            -Identity   $policyName `
            -Properties UserAllowedToAuthenticateFrom `
            -ErrorAction Stop
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
            -Detail "Cannot retrieve '$policyName' to update device restriction: $($_.Exception.Message)"
        throw
    }

    $currentSddl = $existingPolicy.UserAllowedToAuthenticateFrom

    # Determine what state the SDDL is in.
    if ([string]::IsNullOrEmpty($currentSddl)) {
        # No restriction set at all -- write the upgraded SDDL.
        $sddlState = 'None'
    }
    elseif ($currentSddl.ToUpper() -eq $baselineSddl.ToUpper()) {
        # Policy has the v1 baseline SDDL -- safe to upgrade.
        $sddlState = 'Baseline'
    }
    elseif ($currentSddl -like "*$deviceGroupSid*") {
        # Policy already references the GS-LZ-T0-Devices SID -- already upgraded.
        $sddlState = 'Current'
    }
    else {
        # Policy has a custom SDDL we did not set -- do not overwrite.
        $sddlState = 'Custom'
    }

    switch ($sddlState) {
        'Current' {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                -Detail ("'$policyName' UserAllowedToAuthenticateFrom already contains " +
                         "the GS-LZ-T0-Devices SID. No changes made.")
        }

        { $_ -in 'Baseline', 'None' } {
            try {
                Set-ADAuthenticationPolicy `
                    -Identity                    $policyName `
                    -UserAllowedToAuthenticateFrom $upgradedSddl `
                    -ErrorAction                 Stop

                $fromDesc = if ($sddlState -eq 'None') {
                    'UserAllowedToAuthenticateFrom was unset'
                } else {
                    "was v1 baseline (@DEVICE.domainjoined)"
                }

                Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
                    -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                    -Detail ("Updated '$policyName' UserAllowedToAuthenticateFrom: $fromDesc. " +
                             "New condition restricts T0 authentication to members of '$groupName'. " +
                             "The group is currently empty -- populate with T0 PAW computer accounts " +
                             "before relying on this restriction. SDDL: $upgradedSddl")
            }
            catch {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                    -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                    -Detail "Failed to update '$policyName' UserAllowedToAuthenticateFrom: $($_.Exception.Message)"
                throw
            }
        }

        'Custom' {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
                -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                -Detail ("'$policyName' has a custom UserAllowedToAuthenticateFrom SDDL that is " +
                         "neither the v1 baseline nor the expected group-SID form. " +
                         "The deployer will NOT overwrite a custom SDDL. " +
                         "Review the policy manually and update UserAllowedToAuthenticateFrom " +
                         "to include the GS-LZ-T0-Devices SID ($deviceGroupSid) if appropriate. " +
                         "Current SDDL: $currentSddl")
        }
    }
}
