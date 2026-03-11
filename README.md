# AD Landing Zone Deployer

Modular, idempotent PowerShell deployer for an Enterprise Access Model (EAM)
tiered Landing Zone within an existing Active Directory domain.

---

## What It Does

Creates the following structures under the domain root — all prefixed with
`_LZ_` (OUs) or `GS-LZ-` (groups) so they coexist safely with any legacy AD
structure:

- **OU hierarchy** per tier (Accounts / Devices / ServiceAccounts sub-OUs)
  plus a permanent `_LZ_Quarantine` OU
- **Security groups** for admin delegation, read-only access, service account
  placeholders, gMSA host tracking, and T0 device restriction; placed in a
  flat `CN=_LZ_Groups` container
- **ACL delegations** on each tier OU using explicit `ActiveDirectoryAccessRule`
  objects (no raw SDDL); List Object Mode compatible
- **Authentication Policies and Silos** (one pair per tier) controlling TGT
  lifetime and — for T0 — enforcing Kerberos-only authentication from
  devices in `GS-LZ-T0-Devices`
- **Protected Users membership** for `GS-LZ-T0-Admins`, with a prominent
  console warning at creation time
- **gMSA accounts** (`gMSA-LZ-T{n}`) in each tier's ServiceAccounts OU, with
  dedicated `GS-LZ-T{n}-gMSAHosts` principal groups controlling password retrieval
- **GPO scaffolding** — one empty GPO per tier linked to its tier OU, with a
  WMI filter stub targeting the correct ProductType (servers vs. workstations);
  GPO inheritance is blocked on each tier OU to prevent policy bleed-through
- **T0 device restriction** — `GS-LZ-T0-Devices` group created; T0 auth policy
  SDDL upgraded from the baseline domain-joined condition to a group-membership
  condition (`Member_of_any {SID(...)}`)

Everything is idempotent. Re-running the deployer on a domain where the
objects already exist logs each object as Skipped and makes no changes.

---

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| RSAT: Active Directory | `Add-WindowsFeature RSAT-AD-PowerShell` on Server, or `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` on Windows 10/11 |
| RSAT: Group Policy | `Add-WindowsFeature GPMC` on Server (required for GPO scaffolding) |
| Domain functional level | Windows Server 2016 or higher (hard gate — deployer aborts if not met) |
| KDS Root Key | Required for gMSA provisioning. Must exist and be effective before running Phase 8. Create manually: `Add-KdsRootKey -EffectiveImmediately` (lab) or allow 10 hours after creation in production. |
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

If signing infrastructure is not available, scripts can be loaded into memory
and executed without writing signed files to disk. See the v1 README history
for the full Invoke-Expression sequence. For lab use, running with
`-ExecutionPolicy Bypass` in an elevated session is the simpler path:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File ".\Deploy-ADLandingZone.ps1" -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

The `Invoke-Expression` approach bypasses AllSigned because the code is
executed as a string in memory rather than loaded from a signed file. Do not
use this in environments where the policy exists for security reasons.

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `TierCount` | `int` (mandatory) | Number of tiers to deploy. Minimum 2 (T0 + T1). Typical value 3. Maximum 10. |
| `LogPath` | `string` (mandatory) | Full path for the structured CSV deployment log. Parent directory is created if absent. |
| `SkipGmsas` | `switch` | When present, skips Phase 8 (gMSA provisioning). Use when a KDS Root Key is not yet effective. |
| `SkipGpos` | `switch` | When present, skips Phase 9 (GPO scaffolding). Use when GPMC RSAT is not installed or GPOs are managed separately. |
| `-WhatIf` | common | Preview all phases without writing any objects to AD. See [WhatIf / Preview Mode](#whatif--preview-mode) below. |

Both skip flags are absent by default — all phases run unless explicitly skipped.

```powershell
# Full deployment (all phases)
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv

# Skip gMSA phase (KDS key not yet ready)
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv -SkipGmsas

# Skip both optional phases
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv -SkipGmsas -SkipGpos
```

---

## WhatIf / Preview Mode

Pass `-WhatIf` to preview the complete change set without writing anything to
Active Directory:

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-WhatIf.csv -WhatIf
```

**What happens during a WhatIf run:**

- All nine phases execute, but every `New-AD*`, `Set-Acl`, `Add-ADGroupMember`,
  `New-GPO`, `New-GPLink`, `Set-GPInheritance`, and related mutation calls are
  suppressed. PowerShell emits the standard "What if: Performing the operation..."
  messages to the console for each suppressed call.
- Read operations (`Get-ADOrganizationalUnit`, `Get-ADGroup`, etc.) still
  execute, so objects that already exist are correctly reported as `Skipped`
  rather than `WhatIf`. You see the real diff: what would be created vs. what
  is already in place.
- The CSV at `$LogPath` is still written, with `Action=WhatIf` entries in place
  of `Action=Created` or `Action=Modified`. This gives you a structured change
  manifest you can review, diff, or attach to a change request before committing.
- The summary at the end includes a `WhatIf (preview): N` line showing how many
  objects would be created or modified.

**Typical workflow:**

```powershell
# 1. Preview
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-WhatIf.csv -WhatIf

# 2. Review the CSV
Import-Csv C:\Logs\LZ-WhatIf.csv | Where-Object { $_.Action -eq 'WhatIf' } | Format-Table

# 3. Commit (reuse same LogPath or a new one for the real run)
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

Note: `-WhatIf` is a standard PowerShell common parameter derived from
`[CmdletBinding(SupportsShouldProcess)]`. It is honored by all 8 deploy modules
and their inner helper functions.

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

Every action is written to three sinks simultaneously:

1. **Console** — colour-coded: green (Created), yellow (Skipped), cyan
   (Modified), red (Error), magenta (Warning), dark-cyan (WhatIf).
2. **CSV** at `$LogPath` — the canonical deployment record; the summary is
   derived from this file, not from in-memory counters.
3. **Windows Event Log** — Application log, source `ADLandingZone`. Provides
   an immutable, SIEM-consumable trail that a Domain Admin cannot silently edit.
   Source is registered on first use. Event IDs: 1001 Created · 1002 Skipped ·
   1003 Modified · 1004 Error · 1005 Warning · 1006 Info · 1007 WhatIf.
   The Event Log is a secondary sink; if it is unavailable the run continues
   and CSV + console remain authoritative.

After all phases complete, the orchestrator reads the CSV and prints a summary:

```
  Total log entries : 63
  Created           : 0
  Modified          : 0
  Skipped           : 63
  Warnings          : 0
  Errors            : 0
```

On a WhatIf run the summary includes an additional line:

```
  WhatIf (preview)  : 42
```

The summary is derived from the CSV rather than from in-memory counters.
This is intentional: if `Import-Csv` returns zero rows when work was done,
the log pipeline itself has a problem (permissions, path, encoding) that
would otherwise be invisible.

---

## Script Structure

```
Deploy-ADLandingZone.ps1       -- Orchestrator (9 phases)
Remove-ADLandingZone.ps1       -- Removal orchestrator (requires 'REMOVE' confirmation)
CC-PreFlight-Test.ps1          -- Standalone pre-flight check
Deploy-LZ-T0Hardening.ps1      -- Operator tool: writes T0 GPO security template (GptTmpl.inf)
Invoke-LZSiloEnrollment.ps1    -- Operator tool: enrolls accounts into Auth Policy Silos
New-LZDeploymentReport.ps1     -- Operator tool: queries live AD and produces Markdown handoff report

Helpers\
  Write-LZLog.ps1              -- Structured logging helper (console + CSV + Event Log)
  Test-LZPreFlight.ps1         -- Pre-flight validation (7 checks, incl. KDS replication)
  Sign-LZScripts.ps1           -- Authenticode signing helper (operator responsibility)

Modules\
  Deploy-LZ-OUs.ps1            -- Phase 2: OU structure
  Deploy-LZ-Groups.ps1         -- Phase 3: Security groups
  Deploy-LZ-ACLs.ps1           -- Phase 4: ACL delegations
  Deploy-LZ-AuthPolicies.ps1   -- Phase 5: Auth Policies and Silos
  Deploy-LZ-ProtectedUsers.ps1 -- Phase 6: Protected Users membership
  Deploy-LZ-T0DeviceGroup.ps1  -- Phase 7: T0 device group + auth policy SDDL upgrade
  Deploy-LZ-gMSAs.ps1          -- Phase 8: gMSA accounts and host groups
  Deploy-LZ-GPOs.ps1           -- Phase 9: GPO scaffolding and WMI filters
  Remove-LZ-ProtectedUsers.ps1 -- Removal: Protected Users membership
  Remove-LZ-AuthPolicies.ps1   -- Removal: Auth Silos and Policies
  Remove-LZ-gMSAs.ps1          -- Removal: gMSA accounts
  Remove-LZ-GPOs.ps1           -- Removal: GPO links, WMI filters, GPO objects
  Remove-LZ-Groups.ps1         -- Removal: Security groups and container
  Remove-LZ-OUs.ps1            -- Removal: OUs (sub-OUs first, then tier OUs)

Tests\
  Invoke-LZPesterTests.ps1     -- Pester test suite orchestrator
  LZ-OUs.Tests.ps1             -- OU structure tests
  LZ-Groups.Tests.ps1          -- Security group tests
  LZ-ACLs.Tests.ps1            -- ACL delegation tests
  LZ-AuthPolicies.Tests.ps1    -- Auth Policy and Silo tests
  LZ-ProtectedUsers.Tests.ps1  -- Protected Users membership tests
  LZ-gMSAs.Tests.ps1           -- gMSA account tests
  LZ-GPOs.Tests.ps1            -- GPO scaffolding and WMI filter tests
  LZ-Canary.Tests.ps1          -- Behavioral/canary tests (ProtectedFromAccidentalDeletion,
                                  cross-tier write isolation, AdminSDHolder protection)
```

---

## Operator Tools

### T0 Hardening (`Deploy-LZ-T0Hardening.ps1`)

Writes security template settings into the `LZ-T0-GPO` SYSVOL path. This is
an operator-invoked script, not called by the deployer. Run it after the
deployer has created `LZ-T0-GPO` and after group SIDs are stable.

```powershell
.\Deploy-LZ-T0Hardening.ps1
```

Writes a `GptTmpl.inf` containing:
- **Restricted Groups**: restricts membership of `BUILTIN\Administrators` on
  T0 assets to Domain Admins and `GS-LZ-T0-Admins`
- **User Rights Assignment**: denies interactive and RDS logon for
  `GS-LZ-T1-Admins` and `GS-LZ-T2-Admins` on T0 assets

Idempotent via SHA256 hash comparison — rewrites only if content has changed.

### Deployment Report (`New-LZDeploymentReport.ps1`)

Read-only operator script that queries live AD state and produces a Markdown
handoff document — suitable for security architects, auditors, or change advisory
boards. No objects are created or modified.

```powershell
.\New-LZDeploymentReport.ps1 -TierCount 3 -OutputPath C:\Reports\LZ-Report.md
```

The report covers eight sections:

1. **OU Hierarchy** — indented tree with ProtectedFromAccidentalDeletion status
2. **Security Groups** — all `GS-LZ-*` groups with current membership counts
3. **ACL Delegations** — explicit ACEs per tier OU, rights translated to prose,
   inheritance scope described in plain English
4. **Authentication Policies** — TGT lifetime, enforcement mode, NTLM secret
   policy, and device restriction in human-readable form (not raw SDDL)
5. **Authentication Policy Silos** — linked policy and currently enrolled accounts
6. **Protected Users** — `GS-LZ-*` entries in the built-in group
7. **gMSA Accounts** — DN, DNSHostName, and principals allowed to retrieve the
   managed password (resolved to names)
8. **GPO Scaffolding** — GUID, link status, inheritance block, WMI filter query
   (requires GPMC; section is omitted gracefully if the GroupPolicy module is absent)

Each section handles the "phase not yet run" case gracefully rather than failing
the whole report.

### Silo Enrollment (`Invoke-LZSiloEnrollment.ps1`)

Enrolls user or computer accounts into their tier's Authentication Policy Silo.

```powershell
.\Invoke-LZSiloEnrollment.ps1 -Tier 0 -Accounts 'alice','bob' `
    -LogPath C:\Logs\LZ-Silo-Enroll.csv
```

Validates that each account exists and is located inside the correct tier OU
before enrolling. Supports `-WhatIf`. Never called by the deployer — enrollment
is always an explicit operator action.

---

## Removal

`Remove-ADLandingZone.ps1` removes all `_LZ_` OUs, `GS-LZ-` groups, GPOs,
WMI filters, Auth Policies, Auth Silos, and gMSA accounts created by the deployer.

```powershell
# Interactive (prompts for 'REMOVE' confirmation)
.\Remove-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Remove.csv

# Non-interactive (automated pipelines)
.\Remove-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Remove.csv -Force
```

Without `-Force`, the script requires typing `REMOVE` at the console prompt
before any deletions occur. Removal order is the reverse of deployment
(Protected Users → Auth Silos/Policies → gMSAs → GPOs → Groups → OUs).
Every deletion is logged to the CSV.

**Note:** Any user or computer objects you manually placed inside `_LZ_` OUs
must be moved or removed before running the removal script; the OU removal step
will fail if OUs are non-empty.

---

## Running the Pester Tests

Requires Pester 5.x (`Install-Module Pester -Force -SkipPublisherCheck`).

```powershell
.\Tests\Invoke-LZPesterTests.ps1 -TierCount 3 -OutputPath C:\Logs\LZ-Pester.xml
```

Tests verify the deployed state against the live AD environment. All structural
tests pass on a clean deployment. Five T0 hardening tests skip by design until
`Deploy-LZ-T0Hardening.ps1` has been run.

Run only the canary tests with:

```powershell
.\Tests\Invoke-LZPesterTests.ps1 -TierCount 3 -Tag Canary
```

Available tags: `OUs`, `Groups`, `ACLs`, `AuthPolicies`, `ProtectedUsers`,
`gMSAs`, `GPOs`, `Canary`. Omit `-Tag` to run the full suite.

Tests are read-only — they do not create or modify AD objects. The Canary
tests include one test that attempts (and expects to fail) an OU deletion;
the OU is never actually removed.

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

## What Is Out of Scope

- Migration of existing AD objects into the LZ structure
- Automatic silo enrollment during deployment (always an explicit operator action
  via `Invoke-LZSiloEnrollment.ps1`)
- GPO settings population beyond the T0 hardening template (arbitrary GPO content
  modification remains out of scope)
- Cross-forest or cross-domain trust configuration
- Azure AD / Entra ID integration
- KDS Root Key creation (checked in pre-flight; create manually as a deliberate
  administrative action before running Phase 8)
