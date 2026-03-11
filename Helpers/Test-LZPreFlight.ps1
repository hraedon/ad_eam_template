<#
.SYNOPSIS
    Pre-flight validation for the AD Landing Zone deployer.

.DESCRIPTION
    Runs all pre-flight checks in order. Any fatal condition throws a terminating
    error and halts the deployer before any object is created. Non-fatal conditions
    are logged as warnings and execution continues.

    Checks performed (in order):
      1. Derive domain context via Get-ADDomain.
      2. Verify the calling session is running as Domain Admin.
      3. Gate on domain functional level >= Windows Server 2016.
      4. Inspect dsHeuristics for List Object Mode state.
      5. Check for an existing KDS Root Key.
      6. Detect whether this is a fresh or incremental LZ deployment.

.PARAMETER LogPath
    Full path to the CSV log file (passed through to Write-LZLog).

.PARAMETER TierCount
    Number of tiers requested. Validated here so the orchestrator can rely on it.

.OUTPUTS
    PSCustomObject with:
      DomainFQDN       -- DNS root of the domain (e.g. ad.hraedon.com)
      DomainDN         -- Distinguished name root (e.g. DC=ad,DC=hraedon,DC=com)
      IsIncrementalRun -- $true if OU=_LZ_T0 already exists
      LOMEnabled       -- $true if List Object Mode is active
#>
function Test-LZPreFlight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount
    )

    $module = 'PreFlight'

    # ------------------------------------------------------------------
    # 1. Derive domain context
    # ------------------------------------------------------------------
    try {
        $domain     = Get-ADDomain
        $DomainFQDN = $domain.DNSRoot
        $DomainDN   = $domain.DistinguishedName
    }
    catch {
        # Cannot log to CSV yet -- Write-Host directly so the error is visible.
        Write-Host "FATAL: Cannot retrieve domain context. $($_.Exception.Message)" -ForegroundColor Red
        throw "Cannot retrieve domain context from current session. Ensure you are running from a session joined to and authenticated against the target domain. Error: $($_.Exception.Message)"
    }

    Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
        -ObjectType 'Domain' -ObjectDN $DomainDN `
        -Detail "Domain context derived: FQDN=$DomainFQDN  DN=$DomainDN"

    # ------------------------------------------------------------------
    # 2. Verify Domain Admin membership
    # ------------------------------------------------------------------
    $currentUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isDomainAdmin = $currentUser.Groups | Where-Object {
        try {
            $_.Translate([System.Security.Principal.NTAccount]).Value -match 'Domain Admins'
        }
        catch { $false }
    }

    if (-not $isDomainAdmin) {
        throw "Current session is not running as Domain Admin. Launch terminal as a Domain Admin account and retry."
    }

    Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
        -ObjectType 'Session' -ObjectDN $DomainDN `
        -Detail "Domain Admin context verified for: $($currentUser.Name)"

    # ------------------------------------------------------------------
    # 3. Domain functional level gate -- hard stop below Windows 2016
    # ------------------------------------------------------------------
    # DomainMode is compared as an enum; Windows2016Domain is the minimum required.
    # The -lt operator works on the underlying integer values of the enum.
    if ($domain.DomainMode -lt [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain) {
        throw "Domain functional level must be Windows Server 2016 or higher. Detected: $($domain.DomainMode). Raise the functional level and retry."
    }

    Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
        -ObjectType 'Domain' -ObjectDN $DomainDN `
        -Detail "Domain functional level OK: $($domain.DomainMode)"

    # ------------------------------------------------------------------
    # 4. List Object Mode check (dsHeuristics, 7th character)
    # ------------------------------------------------------------------
    $dsHeuristicsPath = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DomainDN"
    $lomEnabled = $false

    try {
        $dsObj = Get-ADObject -Identity $dsHeuristicsPath -Properties dsHeuristics -ErrorAction Stop
        $dsH   = $dsObj.dsHeuristics

        # The 7th character (index 6) of dsHeuristics == '1' means LOM is enabled.
        if ($dsH -and $dsH.Length -ge 7 -and $dsH[6] -eq '1') {
            $lomEnabled = $true
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
            -ObjectType 'Domain' -ObjectDN $dsHeuristicsPath `
            -Detail "Could not read dsHeuristics object: $($_.Exception.Message). Assuming List Object Mode is disabled and proceeding."
    }

    if ($lomEnabled) {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
            -ObjectType 'Domain' -ObjectDN $dsHeuristicsPath `
            -Detail "List Object Mode is ENABLED (dsHeuristics[6]='1'). ACL behaviour will differ from a standard environment. The deployer applies ListObject rights explicitly on all delegated OUs, so deployment will proceed safely. Verify ACL results post-deployment."
    }
    else {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
            -ObjectType 'Domain' -ObjectDN $dsHeuristicsPath `
            -Detail "List Object Mode is disabled (dsHeuristics[6] != '1'). Proceeding normally."
    }

    # ------------------------------------------------------------------
    # 5. KDS Root Key check -- warn if absent; never create
    # ------------------------------------------------------------------
    $kdsKeyDN = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,$DomainDN"

    try {
        $kdsKeys = @(Get-KdsRootKey -ErrorAction Stop)

        if ($kdsKeys.Count -gt 0) {
            $latest = $kdsKeys | Sort-Object CreationTime -Descending | Select-Object -First 1
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
                -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
                -Detail "KDS Root Key(s) found: $($kdsKeys.Count) key(s). Most recent created: $($latest.CreationTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))."
        }
        else {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
                -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
                -Detail ("No KDS Root Key found. gMSA provisioning (planned for v2) will not be possible until a key is created and has replicated. " +
                         "In production, allow 10 hours after key creation before provisioning gMSAs. " +
                         "In a lab, 'Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)' may be used but is unsafe in production. " +
                         "Key creation is intentionally out of scope for this deployer -- create the key manually as a deliberate administrative action before beginning v2 work.")
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
            -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
            -Detail "Could not query KDS Root Keys: $($_.Exception.Message). gMSA availability is unknown. Proceeding."
    }

    # ------------------------------------------------------------------
    # 5b. KDS Root Key replication check (multi-DC environments)
    #
    # If a KDS Root Key was found above, verify it has replicated to every
    # domain controller. On a single-DC lab this is trivially satisfied.
    # On a multi-DC domain, a gMSA provisioning call directed at a DC that
    # has not yet received the key will fail with a KDS error.
    #
    # We query the KDS container on each DC directly via -Server rather than
    # calling Get-KdsRootKey -Server (that cmdlet has no -Server parameter).
    # ------------------------------------------------------------------
    try {
        $allDCs = @(Get-ADDomainController -Filter * -ErrorAction Stop)

        if ($allDCs.Count -le 1) {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
                -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
                -Detail "KDS Root Key replication check: single-DC environment, replication not applicable."
        }
        else {
            $kdsContainerDN = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,$DomainDN"
            $missingDCs     = @()

            foreach ($dc in $allDCs) {
                try {
                    $keysOnDC = @(Get-ADObject `
                        -Server     $dc.HostName `
                        -SearchBase $kdsContainerDN `
                        -Filter     * `
                        -ErrorAction Stop)

                    if ($keysOnDC.Count -eq 0) {
                        $missingDCs += $dc.HostName
                    }
                }
                catch {
                    $missingDCs += "$($dc.HostName) [query error: $($_.Exception.Message)]"
                }
            }

            if ($missingDCs.Count -gt 0) {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
                    -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
                    -Detail ("KDS Root Key has NOT yet replicated to the following DCs: " +
                             "$($missingDCs -join ', '). " +
                             "gMSA provisioning (Phase 8) may fail on these DCs until replication completes. " +
                             "If the key was recently created, wait for AD replication (typically 15 minutes) and re-run pre-flight.")
            }
            else {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
                    -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
                    -Detail "KDS Root Key replication confirmed on all $($allDCs.Count) DCs: $($allDCs.HostName -join ', ')."
            }
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Warning' `
            -ObjectType 'KdsRootKey' -ObjectDN $kdsKeyDN `
            -Detail "Could not enumerate domain controllers for KDS replication check: $($_.Exception.Message). Proceeding."
    }

    # ------------------------------------------------------------------
    # 6. Detect existing LZ deployment (incremental vs. fresh)
    # ------------------------------------------------------------------
    $lzT0DN      = "OU=_LZ_T0,$DomainDN"
    $isIncremental = $false

    try {
        Get-ADOrganizationalUnit -Identity $lzT0DN -ErrorAction Stop | Out-Null
        $isIncremental = $true
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
            -ObjectType 'OU' -ObjectDN $lzT0DN `
            -Detail "Existing LZ deployment detected (OU=_LZ_T0 exists). This is an incremental run. All operations will proceed idempotently -- no existing objects will be modified or deleted."
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
            -ObjectType 'OU' -ObjectDN $lzT0DN `
            -Detail "No existing LZ deployment found (OU=_LZ_T0 absent). This is a fresh deployment."
    }

    # ------------------------------------------------------------------
    # Return domain context so the orchestrator and modules can use it
    # without re-querying AD.
    # ------------------------------------------------------------------
    return [PSCustomObject]@{
        DomainFQDN       = $DomainFQDN
        DomainDN         = $DomainDN
        IsIncrementalRun = $isIncremental
        LOMEnabled       = $lomEnabled
    }
}
