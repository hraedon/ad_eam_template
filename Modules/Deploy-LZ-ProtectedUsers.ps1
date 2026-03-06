<#
.SYNOPSIS
    Adds GS-LZ-T0-Admins to the built-in Protected Users security group.

.DESCRIPTION
    Placing GS-LZ-T0-Admins in Protected Users applies non-configurable
    Kerberos-only restrictions to every account subsequently placed in that
    group or any of its member groups:

        - NTLM, DES, and RC4 authentication are rejected outright.
        - Kerberos TGTs are capped at 4 hours and are non-renewable.
        - Unconstrained and constrained delegation are blocked.
        - Credential caching (CredSSP, WDigest) is disabled.

    These restrictions are enforced immediately upon group membership, with
    no grace period. Do NOT add accounts to GS-LZ-T0-Admins (or any group
    nested in it) until you have confirmed those accounts can authenticate
    exclusively via Kerberos/AES and can tolerate the 4-hour TGT limit.

    T1 and T2 admin groups are NOT added to Protected Users in v1. Protected
    Users disables NTLM entirely, which may break legacy service authentication
    at those tiers. This is by design.

    Fully idempotent -- existing membership is detected and logged as Skipped.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZProtectedUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module          = 'ProtectedUsers'
    $t0AdminName     = 'GS-LZ-T0-Admins'
    $t0AdminDN       = "CN=$t0AdminName,CN=_LZ_Groups,$DomainDN"
    $protectedUsersName = 'Protected Users'

    # ------------------------------------------------------------------
    # Resolve Protected Users group -- it is a well-known built-in group
    # present in every Windows Server 2012 R2+ domain, so failure here
    # indicates a serious environmental problem.
    # ------------------------------------------------------------------
    try {
        $protectedUsersGroup = Get-ADGroup -Identity $protectedUsersName -ErrorAction Stop
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'GroupMembership' -ObjectDN $t0AdminDN `
            -Detail "Cannot resolve 'Protected Users' group: $($_.Exception.Message)"
        throw
    }

    # ------------------------------------------------------------------
    # Resolve GS-LZ-T0-Admins -- must exist (Groups module ran first).
    # ------------------------------------------------------------------
    try {
        $t0AdminGroup = Get-ADGroup -Identity $t0AdminName -ErrorAction Stop
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'GroupMembership' -ObjectDN $t0AdminDN `
            -Detail "Cannot resolve '$t0AdminName': $($_.Exception.Message). Ensure Deploy-LZGroups ran successfully."
        throw
    }

    # ------------------------------------------------------------------
    # Idempotency check: is GS-LZ-T0-Admins already a member?
    # Get-ADGroupMember returns direct members; we compare by SID so the
    # check is robust against DN changes.
    # ------------------------------------------------------------------
    $alreadyMember = $false
    try {
        $members = Get-ADGroupMember -Identity $protectedUsersGroup -ErrorAction Stop
        $alreadyMember = ($members | Where-Object { $_.SID -eq $t0AdminGroup.SID }) -ne $null
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'GroupMembership' -ObjectDN $t0AdminDN `
            -Detail "Cannot enumerate members of 'Protected Users': $($_.Exception.Message)"
        throw
    }

    if ($alreadyMember) {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
            -ObjectType 'GroupMembership' -ObjectDN $t0AdminDN `
            -Detail "'$t0AdminName' is already a member of 'Protected Users'. No changes made."
        return
    }

    # ------------------------------------------------------------------
    # Add GS-LZ-T0-Admins to Protected Users.
    # ------------------------------------------------------------------
    try {
        Add-ADGroupMember -Identity $protectedUsersGroup -Members $t0AdminGroup -ErrorAction Stop

        Write-LZLog -LogPath $LogPath -Module $module -Action 'Modified' `
            -ObjectType 'GroupMembership' -ObjectDN $t0AdminDN `
            -Detail "'$t0AdminName' added to 'Protected Users' ($($protectedUsersGroup.DistinguishedName))."
    }
    catch {
        Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
            -ObjectType 'GroupMembership' -ObjectDN $t0AdminDN `
            -Detail "Failed to add '$t0AdminName' to 'Protected Users': $($_.Exception.Message)"
        throw
    }

    # ------------------------------------------------------------------
    # Mandatory console warning block -- spec requires this to be prominent
    # and impossible to miss in scrollback. Written to host (not log only)
    # using a bordered block with a high-contrast colour scheme.
    # ------------------------------------------------------------------
    $border  = '!' * 78
    $padding = '!' + (' ' * 76) + '!'

    Write-Host ''
    Write-Host $border                                                    -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host $padding                                                   -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  WARNING: GS-LZ-T0-Admins has been added to Protected Users.              !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host $padding                                                   -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  All accounts placed into this group or any member group will immediately  !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  lose the ability to use NTLM, DES, or RC4 authentication. Kerberos is    !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  required. TGTs will not renew beyond 4 hours, meaning active sessions     !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  will be terminated more frequently.                                       !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host $padding                                                   -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  Before moving any account into a group that is a member of Protected      !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  Users, verify it can authenticate exclusively via Kerberos and that the   !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host '!  4-hour TGT limit is operationally acceptable.                             !' -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host $padding                                                   -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host $border                                                    -ForegroundColor Yellow -BackgroundColor DarkRed
    Write-Host ''
}
