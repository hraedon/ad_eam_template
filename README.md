# AD Landing Zone Deployer

Modular, idempotent PowerShell deployer for an Enterprise Access Model (EAM)
tiered Landing Zone within an existing Active Directory domain.

---

## What It Does

Creates the following structures under the domain root -- all prefixed with
`_LZ_` (OUs) or `GS-LZ-` (groups) so they coexist safely with any legacy AD
structure:

- **OU hierarchy** per tier (Accounts / Devices / ServiceAccounts sub-OUs)
  plus a permanent `_LZ_Quarantine` OU
- **Security groups** for admin delegation, read-only access, and service
  account placeholders, placed in a flat `CN=_LZ_Groups` container
- **ACL delegations** on each tier OU using explicit `ActiveDirectoryAccessRule`
  objects (no raw SDDL); List Object Mode compatible
- **Authentication Policies and Silos** (one pair per tier) controlling TGT
  lifetime and -- for T0 -- enforcing Kerberos-only authentication from
  domain-joined devices
- **Protected Users membership** for `GS-LZ-T0-Admins`, with a prominent
  console warning at creation time

Everything is idempotent. Re-running the deployer on a domain where the
objects already exist logs each object as Skipped and makes no changes.

---

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| RSAT: Active Directory | `Add-WindowsFeature RSAT-AD-PowerShell` on Server, or `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` on Windows 10/11 |
| Domain functional level | Windows Server 2016 or higher (hard gate -- deployer aborts if this is not met) |
| Session context | Must be authenticated as a Domain Admin. No `-Credential` parameters are used; all AD cmdlets rely on the ambient Windows session. |
| Domain controller reachability | The session must be able to reach a writable DC. Run from a machine joined to and authenticated against the target domain. |

---

## Execution Policy

Domain environments commonly enforce an **AllSigned** execution policy via GPO.
This policy overrides the `-ExecutionPolicy Bypass` flag on `powershell.exe`,
so unsigned scripts will not run even when the flag is present.

### Option A: Sign the scripts (recommended for production)

Use the included helper to apply an Authenticode signature:

```powershell
.\Helpers\Sign-LZScripts.ps1 -Thumbprint '<cert-thumbprint>' `
    -TimestampServer 'http://timestamp.digicert.com'
```

The signing certificate must have the Code Signing EKU and be trusted by the
target machine. See the script's comment block for certificate requirements.

Once signed, the orchestrator can be run normally:

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

### Option B: Invoke-Expression workaround (lab / test use)

If signing infrastructure is not available, the script can be loaded into
memory and executed without writing a signed file to disk:

```powershell
$root = 'C:\path\to\ad_eam_template'
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Helpers\Write-LZLog.ps1",      [System.Text.Encoding]::UTF8))
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Helpers\Test-LZPreFlight.ps1", [System.Text.Encoding]::UTF8))
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Modules\Deploy-LZ-OUs.ps1",   [System.Text.Encoding]::UTF8))
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Modules\Deploy-LZ-Groups.ps1",[System.Text.Encoding]::UTF8))
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Modules\Deploy-LZ-ACLs.ps1",  [System.Text.Encoding]::UTF8))
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Modules\Deploy-LZ-AuthPolicies.ps1",   [System.Text.Encoding]::UTF8))
Invoke-Expression ([System.IO.File]::ReadAllText("$root\Modules\Deploy-LZ-ProtectedUsers.ps1", [System.Text.Encoding]::UTF8))

Import-Module ActiveDirectory
$TierCount = 3
$LogPath   = 'C:\Logs\LZ-Deploy.csv'

$ctx = Test-LZPreFlight -LogPath $LogPath -TierCount $TierCount
Deploy-LZOUs            -DomainDN $ctx.DomainDN -TierCount $TierCount -LogPath $LogPath
Deploy-LZGroups         -DomainDN $ctx.DomainDN -TierCount $TierCount -LogPath $LogPath
Deploy-LZACLs           -DomainDN $ctx.DomainDN -TierCount $TierCount -LogPath $LogPath
Deploy-LZAuthPolicies   -DomainDN $ctx.DomainDN -TierCount $TierCount -LogPath $LogPath
Deploy-LZProtectedUsers -DomainDN $ctx.DomainDN -LogPath $LogPath
```

**Important:** Always read files with explicit `[System.Text.Encoding]::UTF8`
to prevent em-dash or other non-ASCII comment characters from corrupting
string literals at load time (a known issue with the default encoding on some
PowerShell hosts).

The `Invoke-Expression` approach bypasses AllSigned because the code is
executed as a string in memory rather than loaded from a signed file. Do not
use this in environments where the policy exists for security reasons.

---

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `TierCount` | `int` | Yes | Number of tiers to deploy. Minimum 2 (T0 + T1). Typical value 3. Maximum 10. |
| `LogPath` | `string` | Yes | Full path for the structured CSV deployment log. Parent directory is created if absent. |

---

## Running the Pre-Flight Check

Before the first deployment, run the pre-flight access test to confirm the
session has all required permissions:

```powershell
.\CC-PreFlight-Test.ps1
```

If any test fails, resolve the access issue before running the deployer.

---

## Output and Logging

Every action is written to both the console (colour-coded) and the CSV at
`$LogPath`. After all phases complete, the orchestrator reads the CSV and
prints a summary:

```
  Total log entries : 47
  Created           : 6
  Modified          : 1
  Skipped           : 40
  Warnings          : 0
  Errors            : 0
```

The summary is derived from the CSV rather than from in-memory counters.
This is intentional: if `Import-Csv` returns zero rows when work was done,
the log pipeline itself has a problem (permissions, path, encoding) that
would otherwise be invisible.

---

## Script Structure

```
Deploy-ADLandingZone.ps1      -- Orchestrator
Helpers\
  Write-LZLog.ps1             -- Structured logging helper
  Test-LZPreFlight.ps1        -- Pre-flight validation (6 checks)
  Sign-LZScripts.ps1          -- Authenticode signing helper (operator responsibility)
Modules\
  Deploy-LZ-OUs.ps1           -- Phase 2: OU structure
  Deploy-LZ-Groups.ps1        -- Phase 3: Security groups
  Deploy-LZ-ACLs.ps1          -- Phase 4: ACL delegations
  Deploy-LZ-AuthPolicies.ps1  -- Phase 5: Auth Policies and Silos
  Deploy-LZ-ProtectedUsers.ps1 -- Phase 6: Protected Users membership
```

---

## AD Module Parameter Name Caveat

The `New-ADAuthenticationPolicy` and `New-ADAuthenticationPolicySilo` cmdlet
parameter names **vary by AD module version**. This deployer was developed and
validated against the **Windows Server 2025** ActiveDirectory PowerShell module.

| Cmdlet | Parameter used | Common wrong name | Notes |
|---|---|---|---|
| `New-ADAuthenticationPolicy` | `-RollingNTLMSecret` | `-StrongNTLMPolicy` | Type: `ADStrongNTLMPolicyType`. Values: `Disabled`, `Optional`, `Required`. |
| `New-ADAuthenticationPolicySilo` | `-UserAuthenticationPolicy` | `-AuthenticationPolicy` | Accepts policy name or DN. |

If deploying against a pre-2025 AD module, run:

```powershell
Get-Help New-ADAuthenticationPolicy -Parameter *
Get-Help New-ADAuthenticationPolicySilo -Parameter *
```

and update the parameter names in `Deploy-LZ-AuthPolicies.ps1` accordingly.

---

## What Is Out of Scope (v1)

- GPO creation, linking, or modification
- Migration of existing AD objects into the LZ structure
- Individual account enrollment into Authentication Policy Silos
  (use `Grant-ADAuthenticationPolicySiloAccess` during the migration phase)
- Cross-forest or cross-domain trust configuration
- Cleanup / removal of LZ objects
- Azure AD / Entra ID integration
- KDS Root Key creation (checked in pre-flight; create manually before v2 work)
- gMSA provisioning (planned for v2)
