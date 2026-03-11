# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [v2.5.0] — 2026-03-11

### Added
- **Canary test suite** (`Tests/LZ-Canary.Tests.ps1`, tag `Canary`):
  - ProtectedFromAccidentalDeletion enforcement — attempts deletion of each protected OU and asserts it throws, verifying the flag is enforced by the AD provider rather than just stored as a property value.
  - Cross-tier write isolation — verifies that `GS-LZ-T{n}-Admins` has neither `GenericAll` nor `ReadList` ACEs on sibling tier OUs.
  - AdminSDHolder protection awareness — verifies no `GS-LZ-*` group appears in explicit ACEs on `Domain Admins` or `Schema Admins`.
- **KDS Root Key replication check** (pre-flight check 5b in `Helpers/Test-LZPreFlight.ps1`): on multi-DC domains, queries each DC's KDS container via `Get-ADObject -Server` and warns if any DC has not yet received the key. Single-DC environments log "not applicable".
- **Post-deployment T0 hardening reminder**: `Deploy-ADLandingZone.ps1` now prints a yellow banner at the end of every run reminding the operator to run `Deploy-LZ-T0Hardening.ps1` with the rationale for why it is not called automatically.
- **`[CmdletBinding(SupportsShouldProcess)]`** added to `Deploy-ADLandingZone.ps1` to scaffold `-WhatIf` / `-Confirm` support; individual module operations are not yet wrapped (v3 enhancement).

### Changed
- **Deployer skip flags** (`Deploy-ADLandingZone.ps1`): `[bool]$DeployGmsas = $true` and `[bool]$DeployGpos = $true` replaced with `[switch]$SkipGmsas` and `[switch]$SkipGpos`. Call `-SkipGmsas` to skip Phase 8; `-SkipGpos` to skip Phase 9. Both absent by default (all phases run).
- **Removal confirmation** (`Remove-ADLandingZone.ps1`): custom `[switch]$Confirm` parameter (which shadowed `SupportsShouldProcess`'s built-in `-Confirm`) replaced with `[switch]$Force`. Use `-Force` to bypass the interactive `REMOVE` prompt.
- **Removal phase numbering** (`Remove-ADLandingZone.ps1`): phase labels corrected from `[Phase X/7]` to `[Phase X/6]` (6 operational phases); the summary block is now labelled `Removal Summary` rather than `[Phase 7/7] Summary`.
- **Version banner** updated from `[v2]` to `[v2.5]`.
- **`.DESCRIPTION` comment** in deployer updated to reflect `-SkipGmsas` / `-SkipGpos` flag names.

### Documentation
- `README.md`: parameters table updated for switch rename; pre-flight check count updated to 7; `LZ-Canary.Tests.ps1` added to script structure; Pester section documents `Canary` tag and all valid tag names; removal section documents `-Force`.
- `TUTORIAL.md`: adds Step 3 (T0 hardening) between deployment and migration; renumbers subsequent steps; rewrites Section 5 to current v2.5 scope; corrects T0 device restriction description and PAW enforcement table row.

---

## [v2.0.0] — 2026-03-10

### Added
- **GPO scaffolding** (`Modules/Deploy-LZ-GPOs.ps1`, Phase 9): one empty GPO per tier linked to its tier OU, WMI filter stubs (OS type targeting), GPO inheritance blocked per tier OU.
- **T0 GPO hardening** (`Deploy-LZ-T0Hardening.ps1`): operator-invoked script that writes `GptTmpl.inf` into `LZ-T0-GPO` SYSVOL path with Restricted Groups (locks `BUILTIN\Administrators` to Domain Admins + `GS-LZ-T0-Admins`) and User Rights Assignment (denies interactive/RDP logon for T1/T2 admin groups on T0 assets). UTF-16 LE with BOM encoding; idempotent via SHA256 hash comparison.
- **gMSA provisioning** (`Modules/Deploy-LZ-gMSAs.ps1`, Phase 8): one `gMSA-LZ-T{n}` per tier placed in `_LZ_T{n}_ServiceAccounts`; dedicated `GS-LZ-T{n}-gMSAHosts` groups control password retrieval.
- **T0 device group** (`Modules/Deploy-LZ-T0DeviceGroup.ps1`, Phase 7): creates `GS-LZ-T0-Devices`; upgrades `LZ-T0-AuthPolicy -UserAllowedToAuthenticateFrom` from the baseline `@DEVICE.domainjoined` SDDL to a `Member_of_any {SID(...)}` group-membership condition.
- **Silo enrollment tool** (`Invoke-LZSiloEnrollment.ps1`): operator-invoked; validates accounts are in the correct tier OU before calling `Grant-ADAuthenticationPolicySiloAccess`; supports `-WhatIf`.
- **Cleanup scripts**: `Remove-ADLandingZone.ps1` orchestrator plus six `Modules/Remove-LZ-*.ps1` modules. Removal order is the strict reverse of deployment with explicit dependency management (silos before policies, gMSAs before OUs, etc.).
- **Pester test suite** (`Tests/`): 155 structural tests across 8 test files covering OUs, Groups, ACLs, AuthPolicies, ProtectedUsers, gMSAs, GPOs. Tests are read-only (no AD writes). Five T0 hardening tests skip until `Deploy-LZ-T0Hardening.ps1` is run.
- **`-DeployGmsas`** and **`-DeployGpos`** `[bool]` parameters added to orchestrator (superseded by `[switch]` equivalents in v2.5).

### Changed
- Orchestrator expanded from 6 to 9 phases.
- `Helpers/Test-LZPreFlight.ps1`: KDS Root Key check added (warns if absent; never creates).

---

## [v1.0.0] — 2026-01-26

### Added
- **OU structure** (`Modules/Deploy-LZ-OUs.ps1`): per-tier OUs (`_LZ_T{n}`) with `Accounts`, `Devices`, `ServiceAccounts` sub-OUs; `_LZ_Quarantine` OU; all protected from accidental deletion.
- **Security groups** (`Modules/Deploy-LZ-Groups.ps1`): `GS-LZ-Global-Readers`; per-tier `GS-LZ-T{n}-Admins`, `GS-LZ-T{n}-Readers`, `GS-LZ-T{n}-SvcAccts`; placed in flat `CN=_LZ_Groups` container.
- **ACL delegations** (`Modules/Deploy-LZ-ACLs.ps1`): explicit `ActiveDirectoryAccessRule` objects (no raw SDDL); `ReadProperty + ListChildren + ListObject` for readers and global reader; `GenericAll` for tier admins; `InheritAll` inheritance; List Object Mode compatible; explicit-ACE check filters `IsInherited -eq $false`.
- **Authentication Policies and Silos** (`Modules/Deploy-LZ-AuthPolicies.ps1`): one policy/silo pair per tier; T0: 240 min TGT, `RollingNTLMSecret = Required`, `Enforce = $true`, `UserAllowedToAuthenticateFrom` baseline SDDL (`@DEVICE.domainjoined`); T1: 480 min; T2: 600 min.
- **Protected Users membership** (`Modules/Deploy-LZ-ProtectedUsers.ps1`): `GS-LZ-T0-Admins` added to built-in `Protected Users`; prominent console warning block emitted.
- **Pre-flight validation** (`Helpers/Test-LZPreFlight.ps1`): domain context derivation, Domain Admin check, functional level gate (≥ WS2016), List Object Mode inspection, KDS Root Key check, incremental vs. fresh deployment detection.
- **Structured logging** (`Helpers/Write-LZLog.ps1`): every action written to console (verbose stream) and CSV simultaneously; summary derived from CSV (not in-memory counters).
- **Standalone pre-flight script** (`CC-PreFlight-Test.ps1`).
- **Authenticode signing helper** (`Helpers/Sign-LZScripts.ps1`).
