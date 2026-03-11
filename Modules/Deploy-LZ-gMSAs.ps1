<#
.SYNOPSIS
    Provisions Group Managed Service Accounts (gMSAs) for each Landing Zone tier.

.DESCRIPTION
    V2 module. For each tier (0 ... TierCount-1), this module:

      1. Verifies the KDS Root Key is present and effective. If no usable key
         exists, the module throws a terminating error -- gMSA creation cannot
         succeed without it.

      2. Creates a host principal group GS-LZ-T{n}-gMSAHosts in CN=_LZ_Groups.
         This group will contain the computer accounts of servers authorised to
         retrieve and use the tier gMSA password. It starts empty and is
         populated during the migration phase.

      3. Creates the gMSA gMSA-LZ-T{n} in OU=_LZ_T{n}_ServiceAccounts.
         PrincipalsAllowedToRetrieveManagedPassword is set to GS-LZ-T{n}-gMSAHosts.

    gMSA naming:
        Account name   : gMSA-LZ-T{n}            (10 chars)
        SamAccountName : gMSA-LZ-T{n}$           (11 chars -- within the 20-char limit)
        DNSHostName    : gMSA-LZ-T{n}.$DomainFQDN

    Host group naming:
        GS-LZ-T{n}-gMSAHosts (18 chars for T0 -- within the 20-char SamAccountName limit)

    Why GS-LZ-T{n}-gMSAHosts rather than GS-LZ-T{n}-Admins:
        PrincipalsAllowedToRetrieveManagedPassword grants the LAPS-equivalent
        ability to retrieve the gMSA password. This is a machine identity
        permission, not an administrative delegation. Using the admin group would
        conflate human delegation with machine service identity. The dedicated
        gMSAHosts group follows the Microsoft-recommended gMSA deployment pattern
        and makes the access model explicit.

    Idempotent:
    - Host groups already present are logged as Skipped.
    - gMSAs already present are logged as Skipped. The
      PrincipalsAllowedToRetrieveManagedPassword is NOT modified on an existing
      gMSA -- if it differs from the expected value, a Warning is logged so the
      operator can review and correct it manually.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER DomainFQDN
    DNS root of the domain (e.g. ad.hraedon.com). Used to construct the
    gMSA DNSHostName.

.PARAMETER TierCount
    Number of tiers to process.

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZgMSAs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$DomainFQDN,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module      = 'gMSAs'
    $containerDN = "CN=_LZ_Groups,$DomainDN"

    # ------------------------------------------------------------------
    # Pre-check: KDS Root Key must be present and its EffectiveTime must
    # be in the past (i.e. the key is usable).
    #
    # In production, allow 10 hours after Add-KdsRootKey for forest-wide
    # replication before provisioning gMSAs. In a lab created with
    # Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10), the key is
    # immediately effective.
    #
    # We do not create a KDS Root Key -- that is a deliberate manual
    # administrative action (per v1 spec and v2 intent).
    # ------------------------------------------------------------------
    $kdsKeyDN = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,$DomainDN"

    try {
        $kdsKeys = @(Get-KdsRootKey -ErrorAction Stop)
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
            -Detail "Cannot query KDS Root Keys: $($_.Exception.Message). gMSA provisioning cannot proceed."
        throw
    }

    if ($kdsKeys.Count -eq 0) {
        $msg = ("No KDS Root Key exists. gMSA creation will fail without one. " +
                "In production, run 'Add-KdsRootKey -EffectiveImmediately' and allow 10 hours for replication. " +
                "In a lab, 'Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)' creates a backdated key. " +
                "Key creation is a deliberate manual action -- this deployer will not create it.")
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN -Detail $msg
        throw $msg
    }

    # Find the most recently effective key. Keys become effective at their
    # EffectiveTime; if EffectiveTime is in the future the key is not yet usable.
    $usableKeys = $kdsKeys | Where-Object { $_.EffectiveTime -le (Get-Date) }
    if (-not $usableKeys) {
        $earliest = ($kdsKeys | Sort-Object EffectiveTime | Select-Object -First 1).EffectiveTime
        $msg = ("KDS Root Key found but it is not yet effective. " +
                "EffectiveTime: $($earliest.ToString('yyyy-MM-ddTHH:mm:ssZ')). " +
                "Wait until after this time (production: allow 10 hours for replication) before running gMSA provisioning.")
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN -Detail $msg
        throw $msg
    }

    $latestKey = $usableKeys | Sort-Object EffectiveTime -Descending | Select-Object -First 1
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
        -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
        -Detail ("KDS Root Key check passed. $($usableKeys.Count) usable key(s). " +
                 "Most recent effective: $($latestKey.EffectiveTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')).")

    # ------------------------------------------------------------------
    # Process each tier
    # ------------------------------------------------------------------
    for ($n = 0; $n -lt $TierCount; $n++) {

        $hostGroupName = "GS-LZ-T$n-gMSAHosts"
        $hostGroupDN   = "CN=$hostGroupName,$containerDN"
        $gmsaName      = "gMSA-LZ-T$n"
        $gmsaDNS       = "$gmsaName.$DomainFQDN"
        $gmsaPath      = "OU=_LZ_T${n}_ServiceAccounts,OU=_LZ_T$n,$DomainDN"
        $gmsaDN        = "CN=$gmsaName,$gmsaPath"

        # --------------------------------------------------------------
        # Step A: Create GS-LZ-T{n}-gMSAHosts host group
        # --------------------------------------------------------------
        $hostGroup = $null

        try {
            $hostGroup = Get-ADGroup -Identity $hostGroupName -ErrorAction Stop

            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'Group' -ObjectDN $hostGroupDN `
                -Detail "Host group '$hostGroupName' already exists; no changes made."
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($PSCmdlet.ShouldProcess($hostGroupDN, 'New-ADGroup')) {
                try {
                    New-ADGroup `
                        -Name           $hostGroupName `
                        -SamAccountName $hostGroupName `
                        -GroupScope     Global `
                        -GroupCategory  Security `
                        -Path           $containerDN `
                        -Description    ("Tier $n gMSA host computers. Members of this group may retrieve the password for gMSA-LZ-T$n. " +
                                         "Add T$n server computer accounts here during migration phase.") `
                        -ErrorAction    Stop

                    $hostGroup = Get-ADGroup -Identity $hostGroupName -ErrorAction Stop

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'Group' -ObjectDN $hostGroupDN `
                        -Detail "Created '$hostGroupName'. Add T$n server computer accounts during migration to grant gMSA password retrieval."
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'Group' -ObjectDN $hostGroupDN `
                        -Detail "Failed to create '$hostGroupName': $($_.Exception.Message)"
                    throw
                }
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'Group' -ObjectDN $hostGroupDN `
                    -Detail "Would create '$hostGroupName' (gMSA host principals group for Tier $n)."
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'Group' -ObjectDN $hostGroupDN `
                -Detail "Unexpected error checking '$hostGroupName': $($_.Exception.Message)"
            throw
        }

        # --------------------------------------------------------------
        # Step B: Create gMSA-LZ-T{n}
        # --------------------------------------------------------------
        try {
            $existingGmsa = Get-ADServiceAccount -Identity $gmsaName -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction Stop

            # gMSA exists -- verify PrincipalsAllowedToRetrieveManagedPassword is correct.
            $principals = @($existingGmsa.PrincipalsAllowedToRetrieveManagedPassword)
            $hasHostGroup = $principals | Where-Object {
                try {
                    $resolved = Get-ADGroup -Identity $_ -ErrorAction Stop
                    $resolved.SID.Value -eq $hostGroup.SID.Value
                }
                catch { $false }
            }

            if ($hasHostGroup) {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                    -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                    -Detail ("gMSA '$gmsaName' already exists with '$hostGroupName' in PrincipalsAllowedToRetrieveManagedPassword. No changes made.")
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
                    -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                    -Detail ("gMSA '$gmsaName' already exists but PrincipalsAllowedToRetrieveManagedPassword " +
                             "does not include '$hostGroupName'. This deployer will not modify an existing gMSA's principals. " +
                             "Review and update manually: Set-ADServiceAccount -Identity '$gmsaName' " +
                             "-PrincipalsAllowedToRetrieveManagedPassword '$hostGroupName'")
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # gMSA does not exist -- create it (or preview in WhatIf mode).
            if (-not $hostGroup) {
                # WhatIf mode: host group was not yet created, so we cannot pass it
                # as a principal. Log the preview entry and move on.
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                    -Detail "Would create gMSA '$gmsaName' in '$gmsaPath' once '$hostGroupName' exists."
            }
            elseif ($PSCmdlet.ShouldProcess($gmsaDN, 'New-ADServiceAccount')) {
                try {
                    New-ADServiceAccount `
                        -Name                                    $gmsaName `
                        -DNSHostName                             $gmsaDNS `
                        -Path                                    $gmsaPath `
                        -PrincipalsAllowedToRetrieveManagedPassword $hostGroup `
                        -Description                             ("Tier $n infrastructure gMSA. Used by T$n services enrolled during migration phase. " +
                                                                  "Password retrieval: members of $hostGroupName only.") `
                        -ErrorAction                             Stop

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                        -Detail ("Created gMSA '$gmsaName' in '$gmsaPath'. " +
                                 "PrincipalsAllowedToRetrieveManagedPassword: '$hostGroupName' (currently empty -- add server computer accounts during migration). " +
                                 "DNSHostName: $gmsaDNS.")
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                        -Detail "Failed to create gMSA '$gmsaName': $($_.Exception.Message)"
                    throw
                }
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                    -Detail "Would create gMSA '$gmsaName' in '$gmsaPath' with '$hostGroupName' as PrincipalsAllowedToRetrieveManagedPassword. DNSHostName: $gmsaDNS."
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'gMSA' -ObjectDN $gmsaDN `
                -Detail "Unexpected error checking gMSA '$gmsaName': $($_.Exception.Message)"
            throw
        }
    }
}
