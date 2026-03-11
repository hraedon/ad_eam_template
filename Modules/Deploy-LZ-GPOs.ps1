<#
.SYNOPSIS
    Creates and links GPO scaffolding for each Landing Zone tier.

.DESCRIPTION
    V2 module. For each tier (0 ... TierCount-1), this module:

      1. Creates an empty GPO named LZ-T{n}-GPO.

      2. Creates a WMI filter stub (msWMI-Som object in CN=SOM,CN=WMIPolicy,
         CN=System,<DomainDN>) appropriate to the tier's expected target OS
         type. Filters are stubs -- operators are expected to refine them
         during the migration phase. Each filter is linked to the GPO.

      3. Links the GPO to OU=_LZ_T{n} with Link Enabled.

      4. Blocks GPO inheritance on OU=_LZ_T{n} so parent-domain GPOs do not
         flow into LZ tier OUs.

    WMI filter query stubs per tier:
        T0  (DCs / PAWs / PKI):  ProductType = 2 OR ProductType = 3
            (DC=2, Server=3; PAWs will typically be servers or managed workstations)
        T1  (Enterprise Servers): ProductType = 2 OR ProductType = 3
        T2  (Workstations):       ProductType = 1

    Why stub WMI filters rather than true pass-through?
        Pre-seeding a tier-appropriate query gives operators a starting point
        that matches the tier's expected scope. A pure pass-through (e.g.
        "Version IS NOT NULL") would silently apply GPO settings to all
        machines during the migration phase before the operator has reviewed
        and tightened the filter, creating unintended scope creep.

    Why block GPO inheritance at the tier OU?
        The LZ tier OUs are designed to be hardened enclaves. Inheriting
        GPOs from the broader domain (e.g. a domain-wide AllowNTLM policy)
        could silently undermine the LZ security posture. Blocking inheritance
        makes the tier GPO the explicit, auditable source of truth for
        machine configuration at that tier.

    WMI filter creation uses ADSI (New-ADObject against msWMI-Som) because
    the built-in GroupPolicy module does not expose a New-GPWmiFilter cmdlet.
    This is a documented limitation; direct LDAP creation is the standard
    workaround confirmed in Microsoft documentation and community practice.

    Idempotent:
    - If the GPO already exists, it is logged as Skipped.
    - If the WMI filter already exists (matched by msWMI-Name), it is Skipped.
    - GPO link: if a link to the tier OU already exists, it is Skipped.
    - Inheritance block: if already blocked, it is Skipped.
    - WMI filter-to-GPO association: if already set, it is Skipped.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER DomainFQDN
    DNS root of the domain (e.g. ad.hraedon.com). Used for GPO cmdlet paths.

.PARAMETER TierCount
    Number of tiers to process.

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZGPOs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$DomainFQDN,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module = 'GPOs'

    # Ensure the GroupPolicy module is available.
    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'GPO' -ObjectDN $DomainDN `
            -Detail "Cannot import GroupPolicy module. Install the GPMC RSAT feature. Error: $($_.Exception.Message)"
        throw
    }

    # WMI filter container DN.
    $wmiFilterContainerDN = "CN=SOM,CN=WMIPolicy,CN=System,$DomainDN"

    # ------------------------------------------------------------------
    # Per-tier WMI filter stub queries.
    # ProductType: 1 = workstation, 2 = domain controller, 3 = server.
    # ------------------------------------------------------------------
    $wmiQueries = @(
        # T0: DCs, PAWs, PKI servers -- all are server or DC class machines.
        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = 2 OR ProductType = 3',
        # T1: Enterprise servers.
        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = 2 OR ProductType = 3',
        # T2: End-user workstations.
        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = 1'
    )

    # ------------------------------------------------------------------
    # Internal helper: create a WMI filter via ADSI if it does not exist.
    # Returns the msWMI-ID (GUID string) of the filter, whether new or pre-existing.
    #
    # The msWMI-Som object format:
    #   msWMI-Name         display name
    #   msWMI-Parm1        description
    #   msWMI-Parm2        WQL query block (format: "1;3;<len>;<query>;;")
    #   msWMI-Author       author UPN
    #   msWMI-CreationDate FILETIME string
    #   msWMI-ChangeDate   FILETIME string
    #   The CN of the object is a GUID string prefixed with '{' '}'.
    # ------------------------------------------------------------------
    function New-LZWmiFilter {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$FilterName,
            [string]$Description,
            [string]$WqlQuery,
            [string]$ContainerDN
        )

        # Check for an existing filter with this name.
        # Use string-form -Filter because script block filters do not
        # reliably expand local variables in nested function scopes.
        try {
            $filterQuery = "objectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$FilterName'"
            $existing = Get-ADObject `
                -Filter $filterQuery `
                -SearchBase $ContainerDN `
                -Properties 'msWMI-ID','msWMI-Name' `
                -ErrorAction Stop |
                Select-Object -First 1

            if ($existing) {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                    -ObjectType 'WmiFilter' -ObjectDN $existing.DistinguishedName `
                    -Detail "WMI filter '$FilterName' already exists; no changes made."
                return $existing.'msWMI-ID'
            }
        }
        catch {
            # If the container doesn't exist or search fails, we'll catch the real error on creation.
        }

        # Build the FILETIME-formatted date string (yyyymmddHHmmss.ffffff+000).
        $now = (Get-Date).ToUniversalTime()
        $timeStr = $now.ToString('yyyyMMddHHmmss') + '.000000+000'

        # WMI filter Parm2 format: "1;3;<query-length>;<namespace>;<query>;;"
        # Namespace is ROOT\CIMv2, which is the standard for Win32 classes.
        $namespace  = 'root\\CIMv2'
        $parm2      = "1;3;$($WqlQuery.Length);$namespace;$WqlQuery;;"

        # The CN must be a GUID in braces.
        $filterId = [System.Guid]::NewGuid().ToString('B').ToUpper()   # {XXXXXXXX-...}

        $filterDN = "CN=$filterId,$ContainerDN"

        if ($PSCmdlet.ShouldProcess($filterDN, 'New-ADObject (msWMI-Som)')) {
            try {
                New-ADObject `
                    -Type          'msWMI-Som' `
                    -Name          $filterId `
                    -Path          $ContainerDN `
                    -OtherAttributes @{
                        'msWMI-Name'         = $FilterName
                        'msWMI-Parm1'        = $Description
                        'msWMI-Parm2'        = $parm2
                        'msWMI-Author'       = "$env:USERNAME@$DomainFQDN"
                        'msWMI-CreationDate' = $timeStr
                        'msWMI-ChangeDate'   = $timeStr
                        'msWMI-ID'           = $filterId
                    } `
                    -ErrorAction Stop

                Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                    -ObjectType 'WmiFilter' -ObjectDN $filterDN `
                    -Detail "Created WMI filter '$FilterName'. Query: $WqlQuery. Stub -- refine during migration phase."

                return $filterId
            }
            catch {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                    -ObjectType 'WmiFilter' -ObjectDN $filterDN `
                    -Detail "Failed to create WMI filter '$FilterName': $($_.Exception.Message)"
                throw
            }
        }
        else {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                -ObjectType 'WmiFilter' -ObjectDN $filterDN `
                -Detail "Would create WMI filter '$FilterName'. Query: $WqlQuery."
            return $null
        }
    }

    # ------------------------------------------------------------------
    # Process each tier.
    # ------------------------------------------------------------------
    for ($n = 0; $n -lt $TierCount; $n++) {
        $gpoName      = "LZ-T$n-GPO"
        $tierOuPath   = "OU=_LZ_T$n,$DomainDN"
        $filterName   = "LZ-T$n-WMIFilter"
        $filterDesc   = "Tier $n WMI filter stub. Refine query during migration phase to match intended T$n device scope."
        $wqlQuery     = if ($n -lt $wmiQueries.Count) { $wmiQueries[$n] } else { $wmiQueries[-1] }

        # --------------------------------------------------------------
        # Step 1: Create the GPO
        # --------------------------------------------------------------
        $gpo = $null
        try {
            $gpo = Get-GPO -Name $gpoName -Domain $DomainFQDN -ErrorAction Stop
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
                -Detail "GPO '$gpoName' already exists; no changes made."
        }
        catch [System.ArgumentException] {
            # Get-GPO throws ArgumentException when the GPO does not exist.
            if ($PSCmdlet.ShouldProcess("GPO=$gpoName,$DomainDN", 'New-GPO')) {
                try {
                    $gpo = New-GPO `
                        -Name    $gpoName `
                        -Domain  $DomainFQDN `
                        -Comment "AD Landing Zone Tier $n GPO scaffold. Created by Deploy-ADLandingZone v2. Populate settings via Deploy-LZ-T0Hardening.ps1 (T0) or equivalent hardening scripts." `
                        -ErrorAction Stop

                    # Brief pause after New-GPO so the AD object is queryable by
                    # the ActiveDirectory module. New-GPO writes via the GPMC stack
                    # and even on a single DC there can be a few hundred ms before
                    # Get-ADObject sees the new object.
                    Start-Sleep -Milliseconds 800

                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                        -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
                        -Detail "Created GPO '$gpoName' (GUID: $($gpo.Id)). Empty scaffold; settings are populated by tier-specific hardening scripts."
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
                        -Detail "Failed to create GPO '$gpoName': $($_.Exception.Message)"
                    throw
                }
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
                    -Detail "Would create GPO '$gpoName' (empty scaffold)."
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
                -Detail "Unexpected error checking GPO '$gpoName': $($_.Exception.Message)"
            throw
        }

        # --------------------------------------------------------------
        # Step 2: Create the WMI filter stub and link it to the GPO.
        # --------------------------------------------------------------
        try {
            $filterId = New-LZWmiFilter `
                -FilterName   $filterName `
                -Description  $filterDesc `
                -WqlQuery     $wqlQuery `
                -ContainerDN  $wmiFilterContainerDN

            if ($filterId -and $gpo) {
                # Link the WMI filter to the GPO by setting the gPCWQLFilter attribute
                # on the GPO's AD object. Format: "[<DomainDN>;<filterId>;0]"
                $gpoDN     = "CN={$($gpo.Id.ToString().ToUpper())},CN=Policies,CN=System,$DomainDN"
                $filterRef = "[$DomainDN;$filterId;0]"

                try {
                    # Retry up to 3 times with 500 ms delay. On first creation,
                    # the AD object may not be immediately visible even on a
                    # single DC, because New-GPO writes via a different stack.
                    $gpObj = $null
                    for ($attempt = 1; $attempt -le 3; $attempt++) {
                        try {
                            $gpObj = Get-ADObject -Identity $gpoDN -Properties gPCWQLFilter -ErrorAction Stop
                            break
                        }
                        catch {
                            if ($attempt -lt 3) { Start-Sleep -Milliseconds 500 }
                            else { throw }
                        }
                    }

                    if ($gpObj.gPCWQLFilter -eq $filterRef) {
                        Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                            -ObjectType 'GPO' -ObjectDN $gpoDN `
                            -Detail "WMI filter '$filterName' already linked to GPO '$gpoName'; no changes made."
                    }
                    else {
                        if ($PSCmdlet.ShouldProcess($gpoDN, "Set-ADObject (link WMI filter '$filterName')")) {
                            Set-ADObject -Identity $gpoDN -Replace @{ gPCWQLFilter = $filterRef } -ErrorAction Stop
                            Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
                                -ObjectType 'GPO' -ObjectDN $gpoDN `
                                -Detail "Linked WMI filter '$filterName' ($filterId) to GPO '$gpoName'."
                        }
                        else {
                            Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                                -ObjectType 'GPO' -ObjectDN $gpoDN `
                                -Detail "Would link WMI filter '$filterName' ($filterId) to GPO '$gpoName'."
                        }
                    }
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                        -ObjectType 'GPO' -ObjectDN $gpoDN `
                        -Detail "Failed to link WMI filter to GPO '$gpoName': $($_.Exception.Message)"
                    # Non-fatal: GPO can still function without WMI filter. Log and continue.
                }
            }
            elseif (-not $gpo) {
                # WhatIf mode: GPO was not created, so linkage cannot be evaluated.
                Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                    -ObjectType 'GPO' -ObjectDN "GPO=$gpoName,$DomainDN" `
                    -Detail "Would link WMI filter '$filterName' to GPO '$gpoName' once GPO exists."
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'WmiFilter' -ObjectDN $wmiFilterContainerDN `
                -Detail "WMI filter step failed for tier ${n}: $($_.Exception.Message)"
            throw
        }

        # --------------------------------------------------------------
        # Step 3: Link the GPO to the tier OU.
        # --------------------------------------------------------------
        if (-not $gpo) {
            # WhatIf mode: GPO was not created, so we cannot link it.
            Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                -ObjectType 'GPO' -ObjectDN $tierOuPath `
                -Detail "Would link GPO '$gpoName' to '$tierOuPath' (LinkEnabled=Yes) once GPO exists."
        }
        else {
            $existingLink = $null
            try {
                $inheritanceInfo = Get-GPInheritance -Target $tierOuPath -Domain $DomainFQDN -ErrorAction Stop
                $existingLink = $inheritanceInfo.GpoLinks | Where-Object { $_.DisplayName -eq $gpoName }
            }
            catch {
                # Unable to query inheritance -- will attempt link creation anyway.
            }

            if ($existingLink) {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                    -ObjectType 'GPO' -ObjectDN $tierOuPath `
                    -Detail "GPO '$gpoName' is already linked to '$tierOuPath'; no changes made."
            }
            else {
                if ($PSCmdlet.ShouldProcess($tierOuPath, "New-GPLink '$gpoName'")) {
                    try {
                        New-GPLink `
                            -Name    $gpoName `
                            -Target  $tierOuPath `
                            -Domain  $DomainFQDN `
                            -LinkEnabled Yes `
                            -ErrorAction Stop | Out-Null

                        Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                            -ObjectType 'GPO' -ObjectDN $tierOuPath `
                            -Detail "Linked GPO '$gpoName' to '$tierOuPath' (LinkEnabled=Yes)."
                    }
                    catch {
                        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                            -ObjectType 'GPO' -ObjectDN $tierOuPath `
                            -Detail "Failed to link GPO '$gpoName' to '$tierOuPath': $($_.Exception.Message)"
                        throw
                    }
                }
                else {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                        -ObjectType 'GPO' -ObjectDN $tierOuPath `
                        -Detail "Would link GPO '$gpoName' to '$tierOuPath' (LinkEnabled=Yes)."
                }
            }
        }

        # --------------------------------------------------------------
        # Step 4: Block GPO inheritance on the tier OU.
        # --------------------------------------------------------------
        try {
            $inheritanceInfo = Get-GPInheritance -Target $tierOuPath -Domain $DomainFQDN -ErrorAction Stop
            if ($inheritanceInfo.GpoInheritanceBlocked) {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                    -ObjectType 'GPO' -ObjectDN $tierOuPath `
                    -Detail "GPO inheritance already blocked on '$tierOuPath'; no changes made."
            }
            else {
                if ($PSCmdlet.ShouldProcess($tierOuPath, 'Set-GPInheritance -IsBlocked Yes')) {
                    Set-GPInheritance -Target $tierOuPath -Domain $DomainFQDN -IsBlocked Yes -ErrorAction Stop | Out-Null
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
                        -ObjectType 'GPO' -ObjectDN $tierOuPath `
                        -Detail "Blocked GPO inheritance on '$tierOuPath'. Parent domain GPOs will not flow into this tier OU."
                }
                else {
                    Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                        -ObjectType 'GPO' -ObjectDN $tierOuPath `
                        -Detail "Would block GPO inheritance on '$tierOuPath'."
                }
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'GPO' -ObjectDN $tierOuPath `
                -Detail "Failed to set/check GPO inheritance block on '$tierOuPath': $($_.Exception.Message)"
            throw
        }
    }
}
