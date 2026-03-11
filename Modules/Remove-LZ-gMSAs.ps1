<#
.SYNOPSIS
    Removes LZ gMSA accounts (gMSA-LZ-T{n}) from their tier service-account OUs.
    Must run before Remove-LZ-OUs.ps1 so the OU is empty when removed.
    Called by Remove-ADLandingZone.ps1 — do not invoke directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [int]    $TierCount,
    [Parameter(Mandatory)] [string] $DomainDN,
    [Parameter(Mandatory)] [string] $LogPath
)

function Remove-LZgMSAs {
    param(
        [int]    $TierCount,
        [string] $DomainDN,
        [string] $LogPath
    )

    for ($n = 0; $n -lt $TierCount; $n++) {
        $gmsaName = "gMSA-LZ-T$n"
        try {
            $gmsa = Get-ADServiceAccount -Identity $gmsaName -ErrorAction SilentlyContinue
            if ($gmsa) {
                Remove-ADServiceAccount -Identity $gmsaName -Confirm:$false -ErrorAction Stop
                Write-LZLog -LogPath $LogPath -Module 'RemovegMSAs' -Action 'Removed' `
                    -ObjectType 'gMSA' -ObjectDN $gmsa.DistinguishedName `
                    -Detail "gMSA account $gmsaName removed"
                Write-Host "  [Removed] $gmsaName"
            }
            else {
                Write-LZLog -LogPath $LogPath -Module 'RemovegMSAs' -Action 'Skipped' `
                    -ObjectType 'gMSA' -ObjectDN "CN=$gmsaName,OU=_LZ_T${n}_ServiceAccounts,OU=_LZ_T$n,$DomainDN" `
                    -Detail "$gmsaName not found"
                Write-Host "  [Skipped] $gmsaName not found"
            }
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module 'RemovegMSAs' -Action 'Error' `
                -ObjectType 'gMSA' -ObjectDN "CN=$gmsaName,OU=_LZ_T${n}_ServiceAccounts,OU=_LZ_T$n,$DomainDN" `
                -Detail $_.Exception.Message
            Write-Warning "  [Error] $gmsaName : $($_.Exception.Message)"
        }
    }
}

Remove-LZgMSAs -TierCount $TierCount -DomainDN $DomainDN -LogPath $LogPath
