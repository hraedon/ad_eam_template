<#
.SYNOPSIS
    Applies Access Control List delegations to the AD Landing Zone OUs.

.DESCRIPTION
    Grants the minimum required rights to each LZ security group on the
    relevant tier OUs. Uses explicit ActiveDirectoryAccessRule objects --
    no raw SDDL strings.

    All rules include ListObject rights, making the ACL structure compatible
    with both List Object Mode-enabled and disabled environments.

    Delegations applied:

        GS-LZ-Global-Readers
            ReadProperty + ListChildren + ListObject
            Scope: each _LZ_T{n} OU and all descendants (Inheritance=All)

        GS-LZ-T{n}-Admins
            GenericAll (Full Control)
            Scope: OU=_LZ_T{n} and all descendants (Inheritance=All)

        GS-LZ-T{n}-Readers
            ReadProperty + ListChildren + ListObject
            Scope: OU=_LZ_T{n} and all descendants (Inheritance=All)

    ACL application order: Groups module must have run successfully before
    this module is called.

    Idempotent: each ACE is checked for exact identity + rights + inheritance
    match before being added. Re-running produces Skipped entries, not duplicates.

.PARAMETER DomainDN
    Distinguished name of the domain root (e.g. DC=ad,DC=hraedon,DC=com).

.PARAMETER TierCount
    Number of tiers to process.

.PARAMETER LogPath
    Full path to the CSV log file.
#>
function Deploy-LZACLs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][ValidateRange(2, 10)][int]$TierCount,
        [Parameter(Mandatory)][string]$LogPath
    )

    $module = 'ACLs'

    # Ensure the AD PSDrive is available (requires ActiveDirectory module).
    if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
        throw "AD PSDrive is not available. Ensure the ActiveDirectory module is imported before calling Deploy-LZACLs."
    }

    # ------------------------------------------------------------------
    # Helper: resolve a group's SID from its SamAccountName.
    # Throws a descriptive error if the group cannot be found -- this
    # prevents silent ACL misapplication when a group name is wrong.
    # ------------------------------------------------------------------
    function Get-LZGroupSid {
        param([string]$SamAccountName)

        try {
            $group = Get-ADGroup -Identity $SamAccountName -ErrorAction Stop
            return [System.Security.Principal.SecurityIdentifier]$group.SID
        }
        catch {
            throw "Cannot resolve SID for group '$SamAccountName'. Ensure Deploy-LZGroups has run successfully. Error: $($_.Exception.Message)"
        }
    }

    # ------------------------------------------------------------------
    # Helper: add a single ACE to an OU's DACL, idempotently.
    #
    # Idempotency check: an existing ACE is considered a match when the
    # resolved SID, the ActiveDirectoryRights bitmask, the AccessControlType,
    # and the InheritanceType all match exactly. This avoids duplicate ACEs
    # accumulating on repeated runs while still allowing legitimate ACE
    # changes (e.g. rights expansion) to be detected and applied.
    # ------------------------------------------------------------------
    function Add-LZAce {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [string]$OuDN,
            [System.Security.Principal.SecurityIdentifier]$GroupSid,
            [System.DirectoryServices.ActiveDirectoryRights]$Rights,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]$Inheritance,
            [string]$GroupName,
            [string]$Detail
        )

        $adPath = "AD:$OuDN"

        try {
            $acl = Get-Acl -Path $adPath -ErrorAction Stop
        }
        catch {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                -ObjectType 'ACL' -ObjectDN $OuDN `
                -Detail "Cannot read ACL for OU: $($_.Exception.Message)"
            throw
        }

        # Check whether an equivalent EXPLICIT ACE already exists.
        # IsInherited -eq $false is required: an inherited ACE (propagated from
        # a parent OU) matching our criteria must NOT satisfy the idempotency
        # check. If we skipped on an inherited match, Set-Acl would not add an
        # explicit ACE on this OU, leaving the permission dependent on the parent
        # ACL remaining intact. We always want an explicit ACE on the OU itself.
        $existing = $acl.Access | Where-Object {
            if ($_.IsInherited -ne $false) { return $false }
            if ($_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $false }
            if ($_.ActiveDirectoryRights -ne $Rights) { return $false }
            if ($_.InheritanceType -ne $Inheritance) { return $false }
            # Resolve IdentityReference to a SID for comparison. ACEs we applied
            # are stored as SecurityIdentifier directly; pre-existing ACEs may be
            # stored as NTAccount. The fast path avoids Translate() for our own ACEs.
            # try/catch used here as a statement (not as an expression value) to
            # avoid the Invoke-Expression parser edge case that affects try/catch
            # when used inside parenthesised expression context in Where-Object.
            if ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                return $_.IdentityReference.Value -eq $GroupSid.Value
            }
            $sidMatch = $false
            try {
                $resolved = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                $sidMatch = ($resolved.Value -eq $GroupSid.Value)
            } catch { }
            return $sidMatch
        }

        if ($existing) {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'Skipped' `
                -ObjectType 'ACL' -ObjectDN $OuDN `
                -Detail "Explicit ACE already present for '$GroupName' (Rights=$Rights, Inheritance=$Inheritance). No changes made."
            return
        }

        # Build the rule using the six-parameter constructor so object type
        # GUIDs are explicitly Guid.Empty (applies to all object types).
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $GroupSid,
            $Rights,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [Guid]::Empty,
            $Inheritance,
            [Guid]::Empty
        )

        if ($PSCmdlet.ShouldProcess($OuDN, "Set-Acl (add ACE for '$GroupName')")) {
            try {
                $acl.AddAccessRule($rule)
                Set-Acl -Path $adPath -AclObject $acl -ErrorAction Stop

                Write-LZLog -LogPath $LogPath -Module $module -Action 'Created' `
                    -ObjectType 'ACL' -ObjectDN $OuDN `
                    -Detail "ACE applied for '$GroupName': Rights=$Rights, Inheritance=$Inheritance. $Detail"
            }
            catch {
                Write-LZLog -LogPath $LogPath -Module $module -Action 'Error' `
                    -ObjectType 'ACL' -ObjectDN $OuDN `
                    -Detail "Failed to apply ACE for '$GroupName': $($_.Exception.Message)"
                throw
            }
        }
        else {
            Write-LZLog -LogPath $LogPath -Module $module -Action 'WhatIf' `
                -ObjectType 'ACL' -ObjectDN $OuDN `
                -Detail "Would add ACE for '$GroupName': Rights=$Rights, Inheritance=$Inheritance. $Detail"
        }
    }

    # ------------------------------------------------------------------
    # Rights constants used across all delegations.
    # ListObject is always included for List Object Mode compatibility.
    # ------------------------------------------------------------------
    $readListRights = (
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListChildren -bor
        [System.DirectoryServices.ActiveDirectoryRights]::ListObject
    )

    $fullControlRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll

    $inheritAll = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

    # ------------------------------------------------------------------
    # Resolve all group SIDs up front. Fail loudly if any group is missing
    # before touching any ACL.
    # ------------------------------------------------------------------
    $globalReaderSid = Get-LZGroupSid -SamAccountName 'GS-LZ-Global-Readers'

    $tierSids = @{}
    for ($n = 0; $n -lt $TierCount; $n++) {
        $tierSids["T$n-Admins"]  = Get-LZGroupSid -SamAccountName "GS-LZ-T$n-Admins"
        $tierSids["T$n-Readers"] = Get-LZGroupSid -SamAccountName "GS-LZ-T$n-Readers"
    }

    # ------------------------------------------------------------------
    # Apply delegations tier by tier.
    # ------------------------------------------------------------------
    for ($n = 0; $n -lt $TierCount; $n++) {
        $tierOuDN = "OU=_LZ_T$n,$DomainDN"

        # GS-LZ-Global-Readers: read + list on this tier OU and its subtree.
        Add-LZAce `
            -OuDN       $tierOuDN `
            -GroupSid   $globalReaderSid `
            -Rights     $readListRights `
            -Inheritance $inheritAll `
            -GroupName  'GS-LZ-Global-Readers' `
            -Detail     "LZ-wide read/list delegation."

        # GS-LZ-T{n}-Admins: Full Control on this tier OU and its subtree.
        Add-LZAce `
            -OuDN       $tierOuDN `
            -GroupSid   $tierSids["T$n-Admins"] `
            -Rights     $fullControlRights `
            -Inheritance $inheritAll `
            -GroupName  "GS-LZ-T$n-Admins" `
            -Detail     "Tier $n administrative Full Control delegation."

        # GS-LZ-T{n}-Readers: read + list on this tier OU only (no cross-tier rights).
        Add-LZAce `
            -OuDN       $tierOuDN `
            -GroupSid   $tierSids["T$n-Readers"] `
            -Rights     $readListRights `
            -Inheritance $inheritAll `
            -GroupName  "GS-LZ-T$n-Readers" `
            -Detail     "Tier $n scoped read/list delegation. No rights granted on sibling tiers."
    }

    # ------------------------------------------------------------------
    # List Object Mode compatibility statement.
    # Logged unconditionally regardless of whether LOM is enabled, as
    # required by the spec.
    # ------------------------------------------------------------------
    Write-LZLog -LogPath $LogPath -Module $module -Action 'Info' `
        -ObjectType 'ACL' -ObjectDN $DomainDN `
        -Detail ("ACLs applied are List Object Mode compatible. " +
                 "ReadProperty + ListChildren + ListObject rights are granted explicitly on all delegated OUs. " +
                 "No SDDL workarounds were required.")
}
