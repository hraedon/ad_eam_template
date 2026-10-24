# AD Landing Zone Deployer

Modular PowerShell deployer for an Enterprise Access Model (EAM) tiered Landing Zone inside an existing Active Directory domain. You can run it again safely: objects that already exist are skipped and logged, never changed or deleted.

**Who it is for:** a Windows / Active Directory administrator who wants tier 0 / 1 / 2 OUs, tier admin groups, delegated permissions, authentication policies and silos, and GPO scaffolding in place before moving accounts and machines into tiers.

**Status:** the orchestrator reports version 2.6 (`[v2.6]` banner); releases are tagged `v2.5.0` and `v2.6.0`, and history is in [CHANGELOG.md](CHANGELOG.md). Read [Known issues](#known-issues) before running anything. Two scripts do not currently parse and the removal logging is wrong.

**What it does not do:** it does not move existing objects into the structure, enroll accounts in silos, create a KDS root key, populate GPOs beyond the optional T0 hardening template, or touch trusts, other forests or Entra ID. See [What is out of scope](#what-is-out-of-scope). Security details: [SECURITY.md](SECURITY.md). A longer walkthrough for operators: [TUTORIAL.md](TUTORIAL.md).

---

## Contents

- [What it does](#what-it-does)
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [Execution policy](#execution-policy)
- [Parameters](#parameters)
- [WhatIf / preview mode](#whatif--preview-mode)
- [Running the pre-flight check](#running-the-pre-flight-check)
- [Output and logging](#output-and-logging)
- [Script structure](#script-structure)
- [Operator tools](#operator-tools)
- [Verification](#verification)
- [Removal](#removal)
- [Running the Pester tests](#running-the-pester-tests)
- [Known issues](#known-issues)
- [Troubleshooting](#troubleshooting)
- [AD module parameter name caveat](#ad-module-parameter-name-caveat)
- [What is out of scope](#what-is-out-of-scope)
- [For maintainers (handover)](#for-maintainers-handover)

---

## What it does

Creates the following under the domain root. OUs are prefixed `_LZ_` and groups `GS-LZ-`, so they coexist with any legacy structure:

- **OU hierarchy** per tier (Accounts / Devices / ServiceAccounts sub-OUs) plus a permanent `_LZ_Quarantine` OU. All OUs are protected from accidental deletion.
- **Security groups** for admin delegation, read-only access, service account placeholders, gMSA host tracking, and T0 device restriction, in a flat `CN=_LZ_Groups` container.
- **ACL delegations** on each tier OU using explicit `ActiveDirectoryAccessRule` objects (no raw SDDL); List Object Mode compatible. Exact rights are in [SECURITY.md](SECURITY.md).
- **Authentication Policies and Silos** controlling TGT lifetime and, for T0, Kerberos-only authentication from devices in `GS-LZ-T0-Devices`. Only tiers 0, 1 and 2 get a policy and silo (see [Known issues](#known-issues)). The T0 policy is enforced; the T1 and T2 policies are in audit mode.
- **Protected Users membership** for `GS-LZ-T0-Admins`, with a prominent console warning at creation time.
- **gMSA accounts** (`gMSA-LZ-T{n}`) in each tier's ServiceAccounts OU, with a dedicated `GS-LZ-T{n}-gMSAHosts` group controlling password retrieval.
- **GPO scaffolding** — one empty GPO per tier linked to its tier OU, with a WMI filter stub targeting the correct ProductType (servers vs. workstations). GPO inheritance is blocked on each tier OU to prevent policy bleed-through. Domain-linked GPOs therefore do not apply to machines in tier OUs unless they are enforced; plan for that before moving machines in.
- **T0 device restriction** — `GS-LZ-T0-Devices` group created; the T0 auth policy SDDL is upgraded from the baseline domain-joined condition to a group-membership condition (`Member_of_any {SID(...)}`). The group starts empty.

Everything is idempotent. Re-running the deployer on a domain where the objects already exist logs each object as Skipped and makes no changes.

Object names (from the code):

| Kind | Names |
|---|---|
| OUs | `_LZ_T{n}`; `_LZ_T{n}_Accounts`, `_LZ_T{n}_Devices`, `_LZ_T{n}_ServiceAccounts`; `_LZ_Quarantine` |
| Container | `CN=_LZ_Groups` |
| Groups | `GS-LZ-Global-Readers`; per tier `GS-LZ-T{n}-Admins`, `-Readers`, `-SvcAccts`, `-gMSAHosts`; `GS-LZ-T0-Devices` |
| Auth policies / silos | `LZ-T{n}-AuthPolicy`, `LZ-T{n}-Silo` (n = 0 to 2 only) |
| gMSAs | `gMSA-LZ-T{n}` |
| GPOs / WMI filters | `LZ-T{n}-GPO`, `LZ-T{n}-WMIFilter` |

---

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later (Windows PowerShell; the scripts use `New-EventLog` / `Write-EventLog`, which PowerShell 7 does not include). |
| RSAT: Active Directory | `Add-WindowsFeature RSAT-AD-PowerShell` on Server, or `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` on Windows 10/11 |
| RSAT: Group Policy | `Add-WindowsFeature GPMC` on Server (required for GPO scaffolding; use `-SkipGpos` if you do not have it) |
| Domain functional level | Windows Server 2016 or higher (hard gate — the deployer aborts if not met) |
| KDS Root Key | Required for gMSA provisioning. It must exist and be effective before Phase 8. Create it manually: `Add-KdsRootKey -EffectiveImmediately` (lab) or allow 10 hours after creation in production. Pre-flight only warns if it is missing; Phase 8 stops the run with an error (use `-SkipGmsas` to skip it). |
| Session context | Authenticated as a Domain Admin. The check is a name match: any token group whose name contains "Domain Admins" passes, and a non-English domain may not match. No `-Credential` parameters are used; all AD cmdlets use the ambient Windows session. |
| Domain controller reachability | The session must reach a writable DC. Run from a machine joined to and authenticated against the target domain. |
| SYSVOL access | Only for `Deploy-LZ-T0Hardening.ps1`, which writes files to `\\<domain>\SYSVOL\...`. |
| Elevation | Needed to register the `ADLandingZone` Windows event source. Without it the run continues and logs to console and CSV only. |

What the deployer touches, so you can plan change control: objects under the domain root; authentication policies and silos in the Configuration partition; WMI filters under `CN=System`; GPOs (and SYSVOL); and one membership change in the built-in `Protected Users` group.

---

## Quickstart

Run from an elevated Windows PowerShell 5.1 session as a Domain Admin, in the repository folder. Always preview first.

```powershell
# 1. Check the session has the access the deployer needs.
#    This creates and deletes small temporary objects. See "Running the pre-flight check".
.\CC-PreFlight-Test.ps1

# 2. Preview. Nothing is written to AD; the CSV is still written.
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-WhatIf.csv -WhatIf

# 3. Deploy
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv

# 4. Verify (see "Verification")
.\Tests\Invoke-LZPesterTests.ps1 -TierCount 3
```

Use `-TierCount 3` unless you have a reason not to: `Deploy-LZ-T0Hardening.ps1` and the T2 tests need three tiers. If you have no KDS root key yet, add `-SkipGmsas`; without GPMC, add `-SkipGpos`.

Do not add accounts to `GS-LZ-T0-Admins` until you have read [SECURITY.md](SECURITY.md) (Protected Users takes effect immediately).

---

## Execution policy

Domain environments commonly enforce an **AllSigned** execution policy via GPO. This policy overrides the `-ExecutionPolicy Bypass` flag on `powershell.exe`, so unsigned scripts will not run even when the flag is present.

### Option A: Sign the scripts (recommended for production)

Use the included helper to apply an Authenticode signature to every `.ps1` file in the tree:

```powershell
.\Helpers\Sign-LZScripts.ps1 -Thumbprint '<cert-thumbprint>' `
    -TimestampServer 'http://timestamp.digicert.com'
```

The signing certificate must have the Code Signing EKU and be trusted by the target machine. The thumbprint is 40 hex characters. See the script's comment block for certificate requirements. Any later edit invalidates the signature; re-sign after every change.

Once signed, run the orchestrator normally:

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

### Option B: Bypass (lab / test use)

If signing infrastructure is not available, running with `-ExecutionPolicy Bypass` in an elevated session is the simple path for a lab:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File ".\Deploy-ADLandingZone.ps1" -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

This does not work where `AllSigned` is set by GPO. An older approach loaded the scripts into memory with `Invoke-Expression`, which gets around `AllSigned` because the code is run as a string, not a signed file. Do not use it in environments where the policy exists for security reasons. The earlier README text for it is in the git history (v1).

---

## Parameters

`Deploy-ADLandingZone.ps1`:

| Parameter | Type | Description |
|---|---|---|
| `TierCount` | `int` (mandatory) | Number of tiers to deploy. Minimum 2 (T0 + T1). Typical value 3. Maximum 10. |
| `LogPath` | `string` (mandatory) | Full path for the structured CSV deployment log. The parent directory is created if absent. |
| `SkipGmsas` | `switch` | Skips Phase 8 (gMSA provisioning). Use when a KDS Root Key is not yet effective. |
| `SkipGpos` | `switch` | Skips Phase 9 (GPO scaffolding). Use when GPMC RSAT is not installed or GPOs are managed separately. |
| `-WhatIf` | common | Previews all phases without writing any objects to AD. See [WhatIf / preview mode](#whatif--preview-mode). |

Both skip flags are absent by default: all phases run unless you skip them.

```powershell
# Full deployment (all phases)
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv

# Skip gMSA phase (KDS key not yet ready)
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv -SkipGmsas

# Skip both optional phases
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv -SkipGmsas -SkipGpos
```

Phases, in order: 1 Pre-flight, 2 OUs, 3 Groups, 4 ACLs, 5 Auth policies and silos, 6 Protected Users, 7 T0 device group, 8 gMSAs, 9 GPOs. If a phase fails, the run stops there (earlier phases stay in place); fix the cause and re-run.

The orchestrator does not set a non-zero exit code for logged errors. Check the summary and the CSV.

---

## WhatIf / preview mode

Pass `-WhatIf` to preview the complete change set without writing anything to Active Directory:

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-WhatIf.csv -WhatIf
```

**What happens during a WhatIf run:**

- All nine phases execute, but every `New-AD*`, `Set-Acl`, `Add-ADGroupMember`, `New-GPO`, `New-GPLink`, `Set-GPInheritance`, and related mutation call is suppressed. PowerShell prints the standard "What if: Performing the operation..." messages for each suppressed call.
- Read operations (`Get-ADOrganizationalUnit`, `Get-ADGroup`, etc.) still run, so objects that already exist are reported as `Skipped`, not `WhatIf`. You see the real difference: what would be created versus what is already in place.
- The CSV at `$LogPath` is still written, with `Action=WhatIf` entries in place of `Action=Created` or `Action=Modified`. This gives you a change manifest to review, diff, or attach to a change request.
- The summary at the end includes a `WhatIf (preview): N` line.

**Typical workflow:**

```powershell
# 1. Preview
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-WhatIf.csv -WhatIf

# 2. Review the CSV
Import-Csv C:\Logs\LZ-WhatIf.csv | Where-Object { $_.Action -eq 'WhatIf' } | Format-Table

# 3. Commit (reuse the same LogPath or use a new one for the real run)
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

`-WhatIf` is the standard PowerShell common parameter from `[CmdletBinding(SupportsShouldProcess)]`. It is honored by all 8 deploy modules and their inner helper functions.

Scope of `-WhatIf`: it applies to `Deploy-ADLandingZone.ps1` and `Invoke-LZSiloEnrollment.ps1`. It is not supported by `Deploy-LZ-T0Hardening.ps1`, and do not rely on it for `Remove-ADLandingZone.ps1` (the script's own help says it does not reach the removal modules).

---

## Running the pre-flight check

Before the first deployment, run the pre-flight access test to confirm the session has the permissions the deployer needs:

```powershell
.\CC-PreFlight-Test.ps1
```

If any test fails, resolve the access issue before running the deployer.

**This script is not read-only.** It runs 11 checks, and several create and then delete real objects: the OUs `_LZ_CC_CanaryTest` and `_LZ_CC_AclCanary` under the domain root, the group `GS-LZ-CC-CanaryTest` in `CN=Users`, the authentication policy `LZ-CC-CanaryPolicy` and silo `LZ-CC-CanarySilo`, and the user `LZ-CC-CanaryUser` in `CN=Users`, which it briefly adds to `Protected Users`. Cleanup is not in a `finally` block, so a failed check can leave one of these behind. If a check fails, look for leftovers with those names and delete them by hand. The check is not a dry run, so do not run it where creating those objects is not allowed.

It does not test rights for gMSAs, GPOs, the KDS root key or SYSVOL.

---

## Output and logging

Every action is written to three places at once:

1. **Console** — colour-coded: green (Created), yellow (Skipped), cyan (Modified), red (Error), magenta (Warning), dark-cyan (WhatIf).
2. **CSV** at `$LogPath` — the canonical deployment record; the summary is derived from this file, not from in-memory counters. Columns: `Timestamp` (UTC), `Module`, `Action`, `ObjectType`, `ObjectDN`, `Detail`.
3. **Windows Event Log** — Application log, source `ADLandingZone`. It is harder to edit than the CSV (a local administrator can still clear the log) and a SIEM can read it. The source is registered on first use. Event IDs: 1001 Created, 1002 Skipped, 1003 Modified, 1004 Error, 1005 Warning, 1006 Info, 1007 WhatIf. The event log is a secondary sink; if it is unavailable the run continues and CSV and console remain authoritative.

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

The summary is derived from the CSV on purpose: if `Import-Csv` returns zero rows when work was done, the log pipeline itself has a problem (permissions, path, encoding) that would otherwise be invisible.

---

## Script structure

```
Deploy-ADLandingZone.ps1       -- Orchestrator (9 phases)
Remove-ADLandingZone.ps1       -- Removal orchestrator (requires 'REMOVE' confirmation)
CC-PreFlight-Test.ps1          -- Standalone access check (creates and deletes temporary objects)
Deploy-LZ-T0Hardening.ps1      -- Operator tool: writes T0 GPO security template (GptTmpl.inf)
Invoke-LZSiloEnrollment.ps1    -- Operator tool: enrolls accounts into Auth Policy Silos
New-LZDeploymentReport.ps1     -- Operator tool: queries live AD and produces Markdown handoff report (does not currently parse, see Known issues)

Helpers\
  Write-LZLog.ps1              -- Structured logging helper (console + CSV + Event Log)
  Test-LZPreFlight.ps1         -- Pre-flight validation, 7 checks (domain, Domain Admin, functional level, List Object Mode, KDS key and its replication, existing deployment)
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
  Remove-LZ-GPOs.ps1           -- Removal: GPO links, WMI filters, GPO objects (does not currently parse, see Known issues)
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

## Operator tools

### T0 Hardening (`Deploy-LZ-T0Hardening.ps1`)

Writes security template settings into the `LZ-T0-GPO` SYSVOL path. The deployer does not call it. Run it after the deployer has created `LZ-T0-GPO` and after group SIDs are stable. `-LogPath` is mandatory (PowerShell prompts for it if you omit it; the deployer's end-of-run reminder omits it):

```powershell
.\Deploy-LZ-T0Hardening.ps1 -LogPath C:\Logs\LZ-T0Hardening.csv
```

It writes a `GptTmpl.inf` containing:

- **Restricted Groups**: sets the membership of `BUILTIN\Administrators` to exactly Domain Admins and `GS-LZ-T0-Admins`. This list is authoritative. With standard Restricted Groups behaviour, any other member of local Administrators on affected machines (including the built-in local Administrator account) is removed when the policy applies. Test on one machine first (standard Windows behaviour, not verified in this repository).
- **User Rights Assignment**: denies interactive and RDS logon (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`) for `GS-LZ-T1-Admins` and `GS-LZ-T2-Admins`.

The GPO is linked to `OU=_LZ_T0`, so it applies only to computers placed in that OU tree and passing the WMI filter stub (servers and domain controllers). It resolves the groups `GS-LZ-T1-Admins` and `GS-LZ-T2-Admins`, so it needs a deployment with at least 3 tiers. It also updates the GPO's `gPCMachineExtensionNames` and version number (AD and `GPT.INI`).

Run it only after confirming all T0 admin accounts authenticate by Kerberos; applied too early it can lock administrators out of T0 infrastructure.

Idempotency note: the script is meant to skip rewriting when the content is unchanged, but its hash comparison always differs (see [Known issues](#known-issues)), so each run rewrites the file and increments the GPO version.

### Deployment report (`New-LZDeploymentReport.ps1`)

Read-only operator script that queries live AD state and produces a Markdown handoff document for security architects, auditors, or change advisory boards. No objects are created or modified. **It does not currently parse (see [Known issues](#known-issues)), so it cannot be run until fixed.**

```powershell
.\New-LZDeploymentReport.ps1 -TierCount 3 -OutputPath C:\Reports\LZ-Report.md
```

The report is designed to cover eight sections:

1. **OU Hierarchy** — indented tree with ProtectedFromAccidentalDeletion status
2. **Security Groups** — all `GS-LZ-*` groups with current membership counts
3. **ACL Delegations** — explicit ACEs per tier OU, rights translated to prose, inheritance scope described in plain English
4. **Authentication Policies** — TGT lifetime, enforcement mode, NTLM secret policy, and device restriction in human-readable form (not raw SDDL)
5. **Authentication Policy Silos** — linked policy and currently enrolled accounts
6. **Protected Users** — `GS-LZ-*` entries in the built-in group
7. **gMSA Accounts** — DN, DNSHostName, and principals allowed to retrieve the managed password (resolved to names)
8. **GPO Scaffolding** — GUID, link status, inheritance block, WMI filter query (requires GPMC; the section is omitted gracefully if the GroupPolicy module is absent)

Each section is designed to handle the "phase not yet run" case without failing the whole report.

### Silo enrollment (`Invoke-LZSiloEnrollment.ps1`)

Enrolls user or computer accounts into their tier's Authentication Policy Silo. The deployer never calls it; enrollment is always an explicit operator action.

```powershell
.\Invoke-LZSiloEnrollment.ps1 -Tier 0 -Accounts 'alice','bob' `
    -LogPath C:\Logs\LZ-Silo-Enroll.csv
```

It checks that the silo exists, that each account exists (user, then computer), and that the account is inside `OU=_LZ_T{Tier}`; accounts outside are skipped and counted as rejected unless you pass `-Force` (logged as a warning). It supports `-WhatIf`, and skips accounts already enrolled. `-Tier` accepts 0 to 9, but silos exist only for tiers 0 to 2.

The script calls `Grant-ADAuthenticationPolicySiloAccess` and nothing else. Whether an account also needs its authentication policy silo set (Microsoft documents `Set-ADAccountAuthenticationPolicySilo` as a separate step) is not handled or documented in this repository: not yet documented, verify before relying on enrollment in production.

---

## Verification

After a deployment:

1. Read the summary and the CSV: `Errors` should be 0 and, on a second run, everything should be `Skipped`.
2. Run the Pester suite (see below). It reads live AD and changes nothing.
3. Spot-check by hand:

```powershell
Get-ADOrganizationalUnit -Filter 'Name -like "_LZ_*"' | Select-Object DistinguishedName
Get-ADGroup -Filter 'Name -like "GS-LZ-*"' | Select-Object Name, DistinguishedName
Get-ADAuthenticationPolicy -Filter 'Name -like "LZ-*"'
Get-ADAuthenticationPolicySilo -Filter 'Name -like "LZ-*"'
Get-ADGroupMember 'Protected Users' | Where-Object Name -like 'GS-LZ-*'
(Get-Acl 'AD:\OU=_LZ_T0,DC=ad,DC=example,DC=com').Access |
    Where-Object { $_.IdentityReference -like '*GS-LZ-*' }
```

(Replace the domain DN. The ACL check shows the explicit entries for the LZ groups; expect Full Control for `GS-LZ-T0-Admins` and read/list for the two reader groups.)

---

## Removal

`Remove-ADLandingZone.ps1` removes all `_LZ_` OUs, `GS-LZ-` groups, GPOs, WMI filters, Auth Policies, Auth Silos, and gMSA accounts created by the deployer. **Read [Known issues](#known-issues) first: the GPO removal module does not parse, so the script is expected to stop at phase 4, and deletions are logged as errors.**

```powershell
# Interactive (prompts for 'REMOVE' confirmation)
.\Remove-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Remove.csv

# Non-interactive (automated pipelines)
.\Remove-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Remove.csv -Force
```

Without `-Force`, the script requires you to type `REMOVE` at the console prompt before any deletion. `-TierCount` must match the original deployment, and the script accepts 2 to 9 (the deployer accepts up to 10). Removal order is the reverse of deployment (Protected Users, Auth Silos/Policies, gMSAs, GPOs, Groups, OUs). Removing `GS-LZ-T0-Admins` from Protected Users takes effect immediately for every account in that group.

**Note:** Any user or computer objects you placed inside `_LZ_` OUs must be moved or removed before running the removal script; the OU removal step fails if OUs are non-empty.

**Rollback.** Removal is the rollback. It deletes the groups, so any other permission that referenced them stops working, and recreating a group later gives it a new SID. The ACEs are on the tier OUs and disappear with them. The deployer never changed anything outside the LZ names except the `Protected Users` membership, so there is nothing else to undo. After a partial or failed removal, the script is safe to re-run once the cause is fixed: objects already gone are logged as Skipped.

---

## Running the Pester tests

Requires Pester 5.x (`Install-Module Pester -Force -SkipPublisherCheck`).

```powershell
.\Tests\Invoke-LZPesterTests.ps1 -TierCount 3 -OutputPath C:\Logs\LZ-Pester.xml
```

The tests check the deployed state against the live AD environment, so they need a domain, the RSAT module, and a deployment to test. All structural tests pass on a clean deployment (not re-run for this documentation pass, which had no AD). Five T0 hardening tests skip by design until `Deploy-LZ-T0Hardening.ps1` has been run.

Run only the canary tests with:

```powershell
.\Tests\Invoke-LZPesterTests.ps1 -TierCount 3 -Tag Canary
```

Available tags: `OUs`, `Groups`, `ACLs`, `AuthPolicies`, `ProtectedUsers`, `gMSAs`, `GPOs`, `Canary`. Omit `-Tag` to run the full suite. About 67 test cases are counted by a static search for `It` blocks (the number Pester reports can differ).

Tests are read-only — they do not create or modify AD objects. The Canary tests include one test that attempts (and expects to fail) an OU deletion; the OU is never actually removed.

Static checks run for this documentation pass (PowerShell 7.6.6 on Linux, no AD): 2 of the 32 `.ps1` files fail to parse (see [Known issues](#known-issues)); the Pester files cannot load without the `ActiveDirectory` module, so none could run. PSScriptAnalyzer 1.25.0 with default rules reports no error-level findings besides those parse errors; the warnings are mostly `PSAvoidUsingWriteHost` (271), plus a few empty catch blocks, missing BOMs, and singular-noun naming. The repository has no PSScriptAnalyzer settings file and no CI configuration.

---

## Known issues

Found by reading the code and parsing the scripts. The parse failures and the logging mismatch were confirmed by running the PowerShell parser and function here; the rest are from the code. None was run against a live domain. They are documented, not fixed (this documentation pass changed no code).

| # | Issue | Evidence | Effect and workaround |
|---|---|---|---|
| 1 | `Modules\Remove-LZ-GPOs.ps1` does not parse | Line 63: `"... on $tierOuDN: $(...)"`. In PowerShell, `$name:` followed by text is read as a drive-qualified variable and is a parse error. The parser reports "Variable reference is not valid". | `Remove-ADLandingZone.ps1` dot-sources this file in phase 4, so it is expected to stop there after phases 1 to 3 (Protected Users, auth silos/policies, gMSAs). GPOs, WMI filters, groups and OUs are left. Fix: write `${tierOuDN}:`. Until fixed, remove those objects by hand or by a patched copy. |
| 2 | `New-LZDeploymentReport.ps1` does not parse | Line 641: `Add-Line "```"` has an unterminated string (backtick-escaped quote). Parser error reported first at line 701 under PowerShell 7.6.6. Not tested in Windows PowerShell 5.1, but the quoting rule is the same. | The report cannot be generated. Fix the quoting on line 641 so the string ends (a literal three-backtick line needs the backticks written as single-quoted text). |
| 3 | Removal logs every deletion as an error | `Write-LZLog` accepts only `Created, Skipped, Modified, Error, Warning, Info, WhatIf`; the removal modules log `Action 'Removed'`. Calling it throws `ParameterBindingValidationException` (reproduced). The throw happens after the delete, inside the module's `try`, so its `catch` records an `Error`. | Objects are deleted but the CSV shows `Error` rows and the summary shows `Removed: 0`. Read the console `[Removed]`/`[Skipped]` lines and check AD directly. Fix: add `'Removed'` to the `ValidateSet`. |
| 4 | T0 hardening always rewrites `GptTmpl.inf` | The new-content hash is taken over the text without a byte-order mark, but the file is written with `Encoding.Unicode`, which adds one. The two hashes never match (reproduced on a sample). | Each run rewrites the file and increments the GPO version. Harmless but not idempotent as described. |
| 5 | Auth policies and silos exist only for tiers 0, 1, 2 | `Deploy-LZ-AuthPolicies.ps1` has three fixed configurations. | With `-TierCount` of 4 or more, tiers 3 and above get OUs, groups, ACLs, gMSAs and GPOs but no policy or silo. Their WMI filter uses the workstation query. |
| 6 | TierCount limits differ | Deployer, report, tests accept 2 to 10; `Remove-ADLandingZone.ps1` accepts 2 to 9. | A 10-tier deployment cannot be removed with the script. |
| 7 | `GS-LZ-Global-Readers` does not cover every `_LZ_` OU | `Deploy-LZ-ACLs.ps1` applies the ACE to the tier OUs only. The group's description says "all _LZ_ OUs". | `_LZ_Quarantine` and `CN=_LZ_Groups` are not covered. |
| 8 | `Deploy-LZ-T0Hardening.ps1` needs 3 or more tiers | It resolves `GS-LZ-T2-Admins` and exits if it does not exist. | Not usable with `-TierCount 2`. |
| 9 | The deployer's end-of-run hint for T0 hardening omits `-LogPath` | The script's `-LogPath` is mandatory. | PowerShell prompts for it. |
| 10 | Phase 8 is a hard stop without a KDS root key | `Deploy-LZgMSAs` throws if no effective key exists; pre-flight only warns. | Phase 9 does not run. Use `-SkipGmsas` or create the key and wait. Re-running is safe. |
| 11 | `Remove-ADLandingZone.ps1` has no usable `-WhatIf` | Its help says `-WhatIf` does not reach the removal modules. | Do not use it as a preview. |
| 12 | The Domain Admin check is a name match | `-match 'Domain Admins'` against token group names. | Passes any group with that text; may fail in non-English domains. |

---

## Troubleshooting

| Symptom | Likely cause / action |
|---|---|
| `Cannot import the ActiveDirectory module` | RSAT not installed (see [Prerequisites](#prerequisites)). |
| `Current session is not running as Domain Admin` | Start the session as a Domain Admin account. |
| `Domain functional level must be Windows Server 2016 or higher` | Raise the functional level, then re-run. |
| `No KDS Root Key exists` / `not yet effective` (Phase 8) | Create the key and wait for it to be effective (production: 10 hours), or re-run with `-SkipGmsas`. |
| Warning "KDS Root Key has NOT yet replicated to ..." | Wait for AD replication (the log says typically 15 minutes) before Phase 8. |
| `GroupPolicy` module import fails (Phase 9) | Install GPMC, or re-run with `-SkipGpos`. |
| Auth policy cmdlet "parameter not found" | See [AD module parameter name caveat](#ad-module-parameter-name-caveat). |
| Warning that `UserAllowedToAuthenticateFrom` is a custom SDDL | The deployer will not overwrite it. Review the T0 policy by hand and add the `GS-LZ-T0-Devices` SID if appropriate. |
| Warning that an existing gMSA does not include the host group | The deployer does not change existing gMSAs. Run the `Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword` command shown in the log. |
| Summary shows 0 log entries after work was done | The CSV could not be written or read. Check the path, permissions and encoding. |
| No event log entries | Run elevated once so the `ADLandingZone` source can be registered. CSV and console are unaffected. |
| OU removal fails | The OU contains objects. Move or delete them. |
| Parse errors when running a script | See [Known issues](#known-issues), items 1 and 2. |

---

## AD module parameter name caveat

The `New-ADAuthenticationPolicy` and `New-ADAuthenticationPolicySilo` cmdlet parameter names **vary by AD module version**. This deployer was developed and validated against the **Windows Server 2025** ActiveDirectory PowerShell module.

| Cmdlet | Parameter used | Common wrong name | Notes |
|---|---|---|---|
| `New-ADAuthenticationPolicy` | `-RollingNTLMSecret` | `-StrongNTLMPolicy` | Type: `ADStrongNTLMPolicyType`. Values: `Disabled`, `Optional`, `Required`. |
| `New-ADAuthenticationPolicySilo` | `-UserAuthenticationPolicy` | `-AuthenticationPolicy` | Accepts policy name or DN. |

If deploying against a pre-2025 AD module, run:

```powershell
Get-Help New-ADAuthenticationPolicy -Parameter *
Get-Help New-ADAuthenticationPolicySilo -Parameter *
```

and update the parameter names in `Deploy-LZ-AuthPolicies.ps1` accordingly. (That file's header comment still says `StrongNTLMPolicy`; the code uses `RollingNTLMSecret`.)

---

## What is out of scope

- Migration of existing AD objects into the LZ structure
- Automatic silo enrollment during deployment (always an explicit operator action via `Invoke-LZSiloEnrollment.ps1`)
- GPO settings population beyond the T0 hardening template (arbitrary GPO content modification remains out of scope)
- Cross-forest or cross-domain trust configuration
- Azure AD / Entra ID integration
- KDS Root Key creation (checked in pre-flight; create manually as a deliberate administrative action before running Phase 8)

---

## For maintainers (handover)

**Architecture in one page.** `Deploy-ADLandingZone.ps1` dot-sources `Helpers\Write-LZLog.ps1`, `Helpers\Test-LZPreFlight.ps1` and the eight `Modules\Deploy-LZ-*.ps1` files, then calls one function per phase in a fixed order (OUs, groups, ACLs, auth, protected users, T0 devices, gMSAs, GPOs). Each function takes `-DomainDN` (and where needed `-TierCount`, `-DomainFQDN`) and `-LogPath`, uses `SupportsShouldProcess`, checks for the object first, and logs `Created`, `Skipped`, `Modified`, `WhatIf`, `Warning` or `Error` through `Write-LZLog`. Domain values come from `Get-ADDomain` at run time; nothing is hard-coded. Phase 1 returns a context object. `Remove-ADLandingZone.ps1` is separate: it dot-sources six `Remove-LZ-*.ps1` scripts in reverse order; each defines a function and calls it at once.

**Where things live.**

| Topic | Location |
|---|---|
| Tier configuration (names, TGT minutes, enforce flag, SDDL) | the `$tierConfig` list in `Modules\Deploy-LZ-AuthPolicies.ps1` (T0: 240 min, enforced, RollingNTLMSecret Required; T1: 480 min, audit; T2: 600 min, audit) |
| ACL rights per group | `Modules\Deploy-LZ-ACLs.ps1` (idempotency requires an exact explicit match of SID, rights, type and inheritance) |
| WMI filter queries | `$wmiQueries` in `Modules\Deploy-LZ-GPOs.ps1` |
| T0 hardening template | the here-string in `Deploy-LZ-T0Hardening.ps1` |
| Log action names and event IDs | `Helpers\Write-LZLog.ps1` |
| Pre-flight checks | `Helpers\Test-LZPreFlight.ps1` |

**Build, test, release.** There is no build or CI. Test by running the deployer with `-WhatIf` and then for real in a lab domain, then `Tests\Invoke-LZPesterTests.ps1`. Release by updating [CHANGELOG.md](CHANGELOG.md) and the version banner in `Deploy-ADLandingZone.ps1`; tag the release commit (`v2.6.0` is the latest tag); there is no packaging step. If you ship to an AllSigned environment, re-sign every file after each edit.

**Conventions.** New objects need an existence check, a `ShouldProcess` guard, and log rows for Created / Skipped / WhatIf. Add any new log action to the `ValidateSet` in `Write-LZLog` first (see Known issues item 3). In double-quoted strings, write `${var}:` not `$var:`. Keep the code compatible with Windows PowerShell 5.1.

**Known gaps and debts.** The table under [Known issues](#known-issues); also: no Pester unit tests that run without AD; no documented least-privilege set (Domain Admin is required by the code); silo enrollment may need a second step (see Operator tools); a tutorial step suggests moving domain controllers into `OU=_LZ_T0_Devices`, which is not supported by any other part of this repository (see [TUTORIAL.md](TUTORIAL.md)).

**Depends on.** RSAT ActiveDirectory and GroupPolicy modules, a Windows Server 2016+ functional level, a KDS root key (gMSAs), Pester 5 (tests), a code-signing certificate (AllSigned only).

**Licence.** Apache-2.0 (see `LICENSE`).
