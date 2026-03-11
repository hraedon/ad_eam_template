<#
.SYNOPSIS
    Creates Authentication Policies and Authentication Policy Silos for each
    Landing Zone tier.

.DESCRIPTION
    Requires Windows Server 2016+ domain functional level (enforced in pre-flight).

    For each tier, creates:
      - An ADAuthenticationPolicy controlling TGT lifetime and NTLM behaviour.
      - An ADAuthenticationPolicySilo linking accounts to that policy.

    Policy configuration per tier:

        Tier 0  LZ-T0-AuthPolicy   TGT=240 min  StrongNTLMPolicy=Required  Enforce=$true
                LZ-T0-Silo         Assigned policy: LZ-T0-AuthPolicy
                UserAllowedToAuthenticateFrom: domain-joined devices (SDDL baseline).
                Full restriction to _LZ_T0_Devices OU requires populating a device
                group and updating the policy -- this is a migration-phase action.

        Tier 1  LZ-T1-AuthPolicy   TGT=480 min  Enforce=$false (audit mode)
                LZ-T1-Silo         Assigned policy: LZ-T1-AuthPolicy

        Tier 2  LZ-T2-AuthPolicy   TGT=600 min  Enforce=$false (audit mode)
                LZ-T2-Silo         Assigned policy: LZ-T2-AuthPolicy
                (only created when TierCount >= 3)

    Individual account enrollment into silos is NOT performed by this deployer --
    that is a migration-phase action. The deployer creates and validates the
    policy/silo structure only.

    Fully idempotent -- existing policies and silos are logged as Skipped.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER TierCount
    Number of tiers to process.

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZAuthPolicies {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module = 'AuthPolicies'

    # ------------------------------------------------------------------
    # T0 device restriction -- SDDL condition.
    #
    # The spec requires T0 accounts to authenticate only from devices in
    # OU=_LZ_T0_Devices. AD Authentication Policies express device
    # restrictions via an SDDL security descriptor, not an OU path.
    # OU membership cannot be referenced directly in this SDDL.
    #
    # For v1, the condition requires the authenticating device to be
    # domain-joined. This is the correct baseline for a PAW environment
    # and prevents authentication from non-domain devices entirely.
    #
    # Full restriction to T0 PAWs requires:
    #   1. A security group (e.g. GS-LZ-T0-Devices) populated with T0 PAW
    #      computer accounts during the migration phase.
    #   2. Update LZ-T0-AuthPolicy -UserAllowedToAuthenticateFrom with:
    #      O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(<group-sid>)}))
    #
    # This limitation is logged prominently at runtime.
    # ------------------------------------------------------------------
    # Standalone boolean form -- @DEVICE.domainjoined evaluates as truthy in the
    # SDDL conditional ACE language without a comparison operator, matching the
    # canonical form in Microsoft's SDDL documentation (cf. @Device.Bitlocker usage).
    # Do NOT use '== TRUE' (boolean literal) or '== 1' (integer form); the bare
    # attribute reference is the correct and most portable expression for device
    # boolean claims in Kerberos compound authentication contexts.
    $t0DeviceConditionSddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@DEVICE.domainjoined))'

    # ------------------------------------------------------------------
    # Per-tier policy configuration table.
    # TGT lifetime, NTLM policy, and enforcement follow the spec exactly.
    # ------------------------------------------------------------------
    $tierConfig = @(
        @{
            Tier                 = 0
            PolicyName           = 'LZ-T0-AuthPolicy'
            SiloName             = 'LZ-T0-Silo'
            TgtLifetimeMins      = 240
            # RollingNTLMSecret is the correct parameter name (ADStrongNTLMPolicyType enum).
            # 'Required' = enforce strong NTLM / require Kerberos for accounts on this policy.
            # Valid values confirmed on WS2025 AD module: Disabled, Optional, Required.
            # 'StrongNTLMPolicy' is not a valid parameter name on this module version.
            RollingNTLMSecret    = 'Required'
            Enforce              = $true
            DeviceSddl           = $t0DeviceConditionSddl
            PolicyDescription    = 'T0 Identity Infrastructure auth policy. TGT=4h, RollingNTLMSecret=Required, Enforced.'
            SiloDescription      = 'T0 Authentication Policy Silo. Enroll GS-LZ-T0-Admins members individually during migration phase.'
        },
        @{
            Tier                 = 1
            PolicyName           = 'LZ-T1-AuthPolicy'
            SiloName             = 'LZ-T1-Silo'
            TgtLifetimeMins      = 480
            RollingNTLMSecret    = $null   # Not set for T1 -- spec only mandates RollingNTLMSecret for T0.
            Enforce              = $false
            DeviceSddl           = $null
            PolicyDescription    = 'T1 Server/Enterprise Applications auth policy. TGT=8h, Audit mode.'
            SiloDescription      = 'T1 Authentication Policy Silo. Enroll GS-LZ-T1-Admins members individually during migration phase.'
        },
        @{
            Tier                 = 2
            PolicyName           = 'LZ-T2-AuthPolicy'
            SiloName             = 'LZ-T2-Silo'
            TgtLifetimeMins      = 600
            RollingNTLMSecret    = $null   # Not set for T2 -- spec only mandates RollingNTLMSecret for T0.
            Enforce              = $false
            DeviceSddl           = $null
            PolicyDescription    = 'T2 Workstation/End-user auth policy. TGT=10h, Audit mode.'
            SiloDescription      = 'T2 Authentication Policy Silo. Enroll GS-LZ-T2-Admins members individually during migration phase.'
        }
    )

    # ------------------------------------------------------------------
    # Process each tier up to TierCount.
    # ------------------------------------------------------------------
    foreach ($cfg in $tierConfig) {
        if ($cfg.Tier -ge $TierCount) { continue }

        $policyName = $cfg.PolicyName
        $siloName   = $cfg.SiloName
        $policyDN   = "CN=$policyName,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,$DomainDN"
        $siloDN     = "CN=$siloName,CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,$DomainDN"

        # --------------------------------------------------------------
        # Authentication Policy
        # --------------------------------------------------------------
        $existingPolicy = $null
        try {
            $existingPolicy = Get-ADAuthenticationPolicy -Identity $policyName -ErrorAction Stop
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                -Detail "Authentication policy '$policyName' already exists; no changes made."
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # Policy does not exist -- build the parameter set and create it.
            $policyParams = @{
                Name                         = $policyName
                Description                  = $cfg.PolicyDescription
                UserTGTLifetimeMins          = $cfg.TgtLifetimeMins
                ProtectedFromAccidentalDeletion = $true
                ErrorAction                  = 'Stop'
            }

            # Enforce flag: $true for T0 (immediately enforced), $false for T1/T2 (audit).
            # The -Enforce parameter is a switch on New-ADAuthenticationPolicy;
            # we only pass it when we want enforcement -- omitting it defaults to audit.
            if ($cfg.Enforce) {
                $policyParams['Enforce'] = $true
            }

            # RollingNTLMSecret (ADStrongNTLMPolicyType): only set for T0.
            # T1/T2 have $null in the config table -- omit the parameter entirely for those tiers.
            if ($null -ne $cfg.RollingNTLMSecret) {
                $policyParams['RollingNTLMSecret'] = $cfg.RollingNTLMSecret
            }

            # Device restriction SDDL (T0 only).
            if ($cfg.DeviceSddl) {
                $policyParams['UserAllowedToAuthenticateFrom'] = $cfg.DeviceSddl
            }

            if ($PSCmdlet.ShouldProcess($policyDN, 'New-ADAuthenticationPolicy')) {
                try {
                    New-ADAuthenticationPolicy @policyParams

                    $deviceNote = if ($cfg.DeviceSddl) {
                        " UserAllowedToAuthenticateFrom set to domain-joined device condition (SDDL baseline). " +
                        "Full PAW restriction requires populating a T0 device group and updating this policy during migration phase."
                    } else { '' }

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                        -Detail ("Created '$policyName': TGT=$($cfg.TgtLifetimeMins)min, " +
                                 "RollingNTLMSecret=$($cfg.RollingNTLMSecret), " +
                                 "Enforce=$($cfg.Enforce).$deviceNote")
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                        -Detail "Failed to create '$policyName': $($_.Exception.Message)"
                    throw
                }
            }
            else {
                $deviceNote = if ($cfg.DeviceSddl) { ' UserAllowedToAuthenticateFrom: domain-joined baseline.' } else { '' }
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                    -Detail ("Would create '$policyName': TGT=$($cfg.TgtLifetimeMins)min, " +
                             "RollingNTLMSecret=$($cfg.RollingNTLMSecret), " +
                             "Enforce=$($cfg.Enforce).$deviceNote")
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'AuthPolicy' -ObjectDN $policyDN `
                -Detail "Unexpected error checking '$policyName': $($_.Exception.Message)"
            throw
        }

        # --------------------------------------------------------------
        # Authentication Policy Silo
        # Silos are created after their policy exists (enforced by order).
        # --------------------------------------------------------------
        try {
            Get-ADAuthenticationPolicySilo -Identity $siloName -ErrorAction Stop | Out-Null
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'Silo' -ObjectDN $siloDN `
                -Detail "Authentication policy silo '$siloName' already exists; no changes made."
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($PSCmdlet.ShouldProcess($siloDN, 'New-ADAuthenticationPolicySilo')) {
                try {
                    New-ADAuthenticationPolicySilo `
                        -Name                    $siloName `
                        -Description             $cfg.SiloDescription `
                        -UserAuthenticationPolicy $policyName `
                        -ProtectedFromAccidentalDeletion $true `
                        -ErrorAction             Stop

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'Silo' -ObjectDN $siloDN `
                        -Detail ("Created '$siloName' linked to '$policyName'. " +
                                 "To enroll accounts: Grant-ADAuthenticationPolicySiloAccess " +
                                 "-Identity '$siloName' -Account <SamAccountName>. " +
                                 "Enrollment of individual accounts is a migration-phase action.")
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'Silo' -ObjectDN $siloDN `
                        -Detail "Failed to create '$siloName': $($_.Exception.Message)"
                    throw
                }
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'Silo' -ObjectDN $siloDN `
                    -Detail "Would create '$siloName' linked to '$policyName'. Enrollment of individual accounts is a migration-phase action."
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'Silo' -ObjectDN $siloDN `
                -Detail "Unexpected error checking '$siloName': $($_.Exception.Message)"
            throw
        }
    }
}
