<#
.SYNOPSIS
    Removes GS-LZ-T0-Admins from the built-in Protected Users group.
    Called by Remove-ADLandingZone.ps1 — do not invoke directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $DomainDN,
    [Parameter(Mandatory)] [string] $DomainFQDN,
    [Parameter(Mandatory)] [string] $LogPath
)

function Remove-LZProtectedUsers {
    param(
        [string] $DomainDN,
        [string] $DomainFQDN,
        [string] $LogPath
    )

    Write-Verbose '[Remove-LZ-ProtectedUsers] Starting'

    $groupName = 'GS-LZ-T0-Admins'

    try {
        $protectedUsers = Get-ADGroup -Identity 'Protected Users' -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $protectedUsers -ErrorAction Stop
        $isMember = $members | Where-Object { $_.SamAccountName -eq $groupName }

        if ($isMember) {
            Remove-ADGroupMember -Identity $protectedUsers -Members $groupName -Confirm:$false -ErrorAction Stop
            Write-LZLog -LogPath $LogPath `
                -Module 'RemoveProtectedUsers' -Action 'Removed' -ObjectType 'GroupMembership' `
                -ObjectDN "CN=$groupName,CN=Protected Users,$DomainDN" `
                -Detail "$groupName removed from Protected Users"
            Write-Host "  [Removed] $groupName removed from Protected Users"
        }
        else {
            Write-LZLog -LogPath $LogPath `
                -Module 'RemoveProtectedUsers' -Action 'Skipped' -ObjectType 'GroupMembership' `
                -ObjectDN "CN=$groupName,CN=Protected Users,$DomainDN" `
                -Detail "$groupName was not a member of Protected Users"
            Write-Host "  [Skipped] $groupName not found in Protected Users"
        }
    }
    catch {
        Write-LZLog -LogPath $LogPath `
            -Module 'RemoveProtectedUsers' -Action 'Error' -ObjectType 'GroupMembership' `
            -ObjectDN "CN=$groupName,CN=Protected Users,$DomainDN" `
            -Detail $_.Exception.Message
        Write-Warning "  [Error] Protected Users removal failed: $($_.Exception.Message)"
    }
}

Remove-LZProtectedUsers -DomainDN $DomainDN -DomainFQDN $DomainFQDN -LogPath $LogPath
