<#
.SYNOPSIS
    Removes LZ GPO scaffolding: unlinks GPOs from tier OUs, removes WMI filters,
    removes the GPO objects, and re-enables GPO inheritance on tier OUs.
    Called by Remove-ADLandingZone.ps1 — do not invoke directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [int]    $TierCount,
    [Parameter(Mandatory)] [string] $DomainDN,
    [Parameter(Mandatory)] [string] $DomainFQDN,
    [Parameter(Mandatory)] [string] $LogPath
)

function Remove-LZGPOs {
    param(
        [int]    $TierCount,
        [string] $DomainDN,
        [string] $DomainFQDN,
        [string] $LogPath
    )

    $wmiContainer  = "CN=SOM,CN=WMIPolicy,CN=System,$DomainDN"

    for ($n = 0; $n -lt $TierCount; $n++) {
        $gpoName   = "LZ-T$n-GPO"
        $tierOuDN  = "OU=_LZ_T$n,$DomainDN"
        $filterName = "LZ-T$n-WMIFilter"

        # --- Unlink GPO and re-enable inheritance on tier OU ---
        try {
            $gpo = Get-GPO -Name $gpoName -Domain $DomainFQDN -ErrorAction SilentlyContinue
            if ($gpo) {
                # Remove GPO link from tier OU (suppress if already absent).
                try {
                    Remove-GPLink -Guid $gpo.Id -Target $tierOuDN -Domain $DomainFQDN `
                        -ErrorAction Stop
                    Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Removed' `
                        -ObjectType 'GPOLink' -ObjectDN $tierOuDN `
                        -Detail "$gpoName link removed from $tierOuDN"
                    Write-Host "  [Removed] $gpoName link from $tierOuDN"
                }
                catch {
                    # Link may already be absent; log and continue.
                    Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Skipped' `
                        -ObjectType 'GPOLink' -ObjectDN $tierOuDN `
                        -Detail "Link removal skipped or already absent: $($_.Exception.Message)"
                }

                # Re-enable GPO inheritance on the tier OU.
                try {
                    Set-GPInheritance -Target $tierOuDN -Domain $DomainFQDN `
                        -IsBlocked No -ErrorAction Stop
                    Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Modified' `
                        -ObjectType 'OU' -ObjectDN $tierOuDN `
                        -Detail "GPO inheritance re-enabled on $tierOuDN"
                    Write-Host "  [Modified] GPO inheritance re-enabled on $tierOuDN"
                }
                catch {
                    Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Error' `
                        -ObjectType 'OU' -ObjectDN $tierOuDN `
                        -Detail "Failed to re-enable inheritance: $($_.Exception.Message)"
                    Write-Warning "  [Error] Inheritance re-enable failed on $tierOuDN: $($_.Exception.Message)"
                }

                # Remove the GPO object itself.
                Remove-GPO -Name $gpoName -Domain $DomainFQDN -ErrorAction Stop
                Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Removed' `
                    -ObjectType 'GPO' -ObjectDN $gpoName `
                    -Detail "GPO $gpoName removed"
                Write-Host "  [Removed] GPO $gpoName"
            }
            else {
                Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Skipped' `
                    -ObjectType 'GPO' -ObjectDN $gpoName -Detail "$gpoName not found"
                Write-Host "  [Skipped] GPO $gpoName not found"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Error' `
                -ObjectType 'GPO' -ObjectDN $gpoName -Detail $_.Exception.Message
            Write-Warning "  [Error] GPO removal failed for $gpoName : $($_.Exception.Message)"
        }

        # --- Remove WMI filter from CN=SOM ---
        try {
            $wmiQuery   = "objectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$filterName'"
            $wmiFilter  = Get-ADObject -Filter $wmiQuery -SearchBase $wmiContainer `
                              -ErrorAction SilentlyContinue
            if ($wmiFilter) {
                Remove-ADObject -Identity $wmiFilter.DistinguishedName -Confirm:$false -ErrorAction Stop
                Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Removed' `
                    -ObjectType 'WMIFilter' -ObjectDN $wmiFilter.DistinguishedName `
                    -Detail "WMI filter $filterName removed"
                Write-Host "  [Removed] WMI filter $filterName"
            }
            else {
                Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Skipped' `
                    -ObjectType 'WMIFilter' -ObjectDN "CN=$filterName,$wmiContainer" `
                    -Detail "$filterName not found in CN=SOM"
                Write-Host "  [Skipped] WMI filter $filterName not found"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module 'RemoveGPOs' -Action 'Error' `
                -ObjectType 'WMIFilter' -ObjectDN "CN=$filterName,$wmiContainer" `
                -Detail $_.Exception.Message
            Write-Warning "  [Error] WMI filter removal failed for $filterName : $($_.Exception.Message)"
        }
    }
}

Remove-LZGPOs -TierCount $TierCount -DomainDN $DomainDN -DomainFQDN $DomainFQDN -LogPath $LogPath
