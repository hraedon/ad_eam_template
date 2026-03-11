# Tutorial: Implementing the Tiered AD Landing Zone

This tutorial explains how to use this AD Landing Zone deployer, how it differs
from a stock Active Directory implementation, and the specific restrictions it
enforces to secure your identity infrastructure.

---

## 1. Conceptual Overview: Stock AD vs. Landing Zone

In a stock AD implementation, all objects often reside in default containers
(e.g., `CN=Users`, `CN=Computers`), and administrative power is frequently
consolidated in a few high-privilege groups like "Domain Admins." A compromised
Domain Admin account has unrestricted access to everything with no boundary
enforcement.

This Landing Zone implements an **Enterprise Access Model (EAM)** that
physically and logically separates assets into Tiers:

- **Tier 0 (T0):** The "Keys to the Kingdom." Domain Controllers, PKI,
  identity management servers (e.g., AD Connect), and their administrators.
- **Tier 1 (T1):** Enterprise applications and servers.
- **Tier 2 (T2):** End-user devices and standard workstation accounts.

The deployer creates the OU structure, security groups, ACL delegations, and
authentication policies for this model. **It does not migrate existing objects**
-- that is a manual, phased operation described in Section 3.

---

## 2. Authentication Workflows and Restrictions

The Landing Zone introduces native AD security features that change how
privileged users authenticate compared to a standard setup.

### A. Authentication Policies and Silos

Unlike stock AD, where a Domain Admin can interactively log in to any
workstation anywhere, this implementation uses Authentication Policy Silos to
prevent lateral movement:

- **Tiered Isolation:** Accounts enrolled in a Silo (e.g., `LZ-T0-Silo`) are
  bound by the corresponding Authentication Policy and cannot authenticate
  outside its restrictions.
- **T0 Device Restriction:** The `GS-LZ-T0-Devices` group is created and the
  `LZ-T0-AuthPolicy` SDDL is set to `Member_of_any {SID(GS-LZ-T0-Devices)}`.
  Tier 0 accounts are restricted to authenticating from devices that are members
  of this group. The group starts empty — populate it with T0 PAW computer
  accounts during the migration phase to activate the restriction.
- **Shortened TGT Lifetimes:** Ticket Granting Ticket (TGT) lifetimes are
  significantly reduced to limit the window for credential theft:

  | Tier | TGT Lifetime | vs. AD Default (10 hrs) |
  |------|-------------|------------------------|
  | T0   | 4 hours     | -60%                   |
  | T1   | 8 hours     | -20%                   |
  | T2   | 10 hours    | Equivalent             |

  T2 matches the AD default TGT lifetime, but T2 accounts are still isolated
  within a silo and subject to the group-scoped delegation controls below.
  The value of the silo at T2 is boundary enforcement and auditability, not
  TGT reduction.

### B. The Protected Users Group

`GS-LZ-T0-Admins` is automatically nested into the built-in `Protected Users`
group. This enforces non-configurable restrictions for every account that is a
member of `GS-LZ-T0-Admins` or any group nested within it:

- **No NTLM, DES, or RC4:** Authentication must be Kerberos/AES only.
- **No delegation:** Accounts cannot be used for constrained or unconstrained
  delegation.
- **No credential caching:** Credentials are not cached on workstations
  (WDigest, CredSSP disabled).
- **TGTs capped at 4 hours, non-renewable:** Active sessions will be terminated
  more frequently as a result.

> **Critical:** These restrictions take effect **immediately** when an account
> is added to `GS-LZ-T0-Admins` -- there is no grace period. Do not place any
> account into `GS-LZ-T0-Admins` until you have confirmed it can authenticate
> exclusively via Kerberos and that the 4-hour TGT limit is operationally
> acceptable. An account that relies on NTLM or delegation will break
> immediately and silently upon membership.

T1 and T2 admin groups are **not** added to Protected Users in v1. Protected
Users disables NTLM entirely, which may break legacy service authentication at
those tiers.

---

## 3. Utilization Guide

### Step 1: Pre-Flight

Before the first deployment, run the pre-flight access test to confirm the
session has all required permissions:

```powershell
.\CC-PreFlight-Test.ps1
```

All 11 checks must pass before proceeding. Resolve any failures -- they
indicate permission gaps that will cause the deployer to fail mid-run, which is
harder to recover from than fixing them upfront.

### Step 2: Deployment

#### 2a. Preview first (recommended)

Before writing anything to AD, run with `-WhatIf` to see exactly what the
deployer would create. Existing objects are still queried, so the output
shows a real diff — objects already present appear as `Skipped`, objects
that would be created appear as `WhatIf`:

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-WhatIf.csv -WhatIf
```

The CSV at `C:\Logs\LZ-WhatIf.csv` will contain one row per action. Review it:

```powershell
Import-Csv C:\Logs\LZ-WhatIf.csv | Where-Object { $_.Action -eq 'WhatIf' } | Format-Table
```

This is particularly valuable when presenting to a change advisory board or
running against a production domain for the first time.

#### 2b. Commit

Run the orchestrator without `-WhatIf` to instantiate the structure. This is
an **additive-only** process — it will not modify or delete any existing
objects outside the `_LZ_` / `GS-LZ-` namespace.

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

Review the CSV log after the run. The summary printed at the end is derived
from the CSV, so a zero-row log despite console output indicates a log write
problem worth investigating before proceeding.

Every action is also written to the Windows Application Event Log under the
source `ADLandingZone` (Event IDs 1001–1007). These entries are immutable
after the fact — unlike the CSV, they cannot be silently edited — which
satisfies most change-record retention requirements and makes the deployment
consumable by SIEM tooling without additional integration work.

### Step 3: T0 GPO Hardening (Operator Action)

After deployment, the `LZ-T0-GPO` scaffold exists but contains no security
settings. Run the hardening script to populate it:

```powershell
.\Deploy-LZ-T0Hardening.ps1
```

**Run this only after verifying that all T0 admin accounts authenticate
exclusively via Kerberos.** The hardening template denies interactive and RDP
logon for T1/T2 admin groups on T0 assets. Applying it before Kerberos
readiness is confirmed can lock you out of T0 infrastructure.

The deployer prints a reminder notice at the end of its run — the notice
includes this command and the rationale.

### Step 4: Generate a Deployment Report (Recommended)

Before migrating any objects, generate a Markdown handoff document that captures
the full deployed state — OU hierarchy, groups, ACLs, auth policies, silos,
Protected Users, gMSAs, and GPO scaffolding — in a single reviewable artifact:

```powershell
.\New-LZDeploymentReport.ps1 -TierCount 3 -OutputPath C:\Reports\LZ-Report.md
```

The script is read-only. It queries live AD and writes a structured Markdown file
at `OutputPath`. Use it to:

- Attach a before/after snapshot to a change request
- Provide a handoff document to the security architect or auditor
- Verify that every phase ran successfully before beginning object migration

If the GroupPolicy module (`GPMC`) is not installed, Section 8 (GPO scaffolding)
is omitted from the report with an install note; all other sections still render.

### Step 5: Migration (Manual)

The Landing Zone provides the structure, but you must move objects into it.
This is a deliberate manual phase -- the deployer does not touch existing
objects.

1. Move Domain Controllers and PKI servers to `OU=_LZ_T0_Devices`.
2. Move T0 admin accounts to `OU=_LZ_T0_Accounts`.
3. Move application and infrastructure servers to `OU=_LZ_T1_Devices`.
4. Move T1 admin accounts to `OU=_LZ_T1_Accounts`.
5. Move workstations to `OU=_LZ_T2_Devices`.
6. Move standard user accounts to `OU=_LZ_T2_Accounts`.
7. Use `OU=_LZ_Quarantine` as a staging area for objects whose tier
   assignment is not yet determined.

**Before moving any account to `OU=_LZ_T0_Accounts` or adding it to
`GS-LZ-T0-Admins`:** confirm it can authenticate via Kerberos only and
tolerate the 4-hour TGT limit. See the Protected Users warning in Section 2B.

### Step 6: Silo Enrollment (Manual)

Moving an account into a tier OU does not automatically enroll it in the
Authentication Policy Silo. Enrollment is a separate, explicit action:

```powershell
Grant-ADAuthenticationPolicySiloAccess -Identity 'LZ-T0-Silo' -Account <SamAccountName>
```

Repeat for each account being activated at a given tier. Silo enrollment is
what activates the TGT lifetime restrictions and device authentication
requirements defined in Section 2A.

---

## 4. Summary of Key Differences

| Feature | Stock AD | LZ Tiered Implementation |
|---|---|---|
| OU Structure | Often flat / default containers | Tiered (T0/T1/T2) for physical isolation |
| Admin Rights | Broad (e.g., Domain Admins) | Scoped via per-tier Admin groups and ACL delegation |
| Lateral Movement | High risk -- Admins can log in anywhere | Blocked via Authentication Silos and Policies |
| TGT Lifetime | Default 10 hours | T0: 4 hrs / T1: 8 hrs / T2: 10 hrs (silo-enforced) |
| Legacy Auth (NTLM) | Often permitted | Blocked for T0 via Protected Users; audited at T1/T2 |
| Read Access | Often unmanaged | Scoped via tiered Reader groups; LOM-compatible ACLs |
| PAW Enforcement | None | Domain-joined baseline (v1); PAW group restriction via `GS-LZ-T0-Devices` (v2) |
| Deployment audit trail | None / file-based | Event Log (immutable) + CSV + console; SIEM-consumable |
| Change preview | None | `-WhatIf` previews all phases; CSV records the proposed change set |

---

## 5. What This Deployer Does Not Do

- **Migrate existing AD objects** into the LZ structure — this is a deliberate
  manual phase (see Step 5 above)
- **Enroll individual accounts into Auth Policy Silos** — always an explicit
  operator action via `Invoke-LZSiloEnrollment.ps1` (never automatic)
- **Populate GPO security settings arbitrarily** — only the T0 hardening
  template (Restricted Groups, Deny Logon) is in scope; use
  `Deploy-LZ-T0Hardening.ps1` for that
- **Configure cross-forest or cross-domain trusts**
- **Integrate with Azure AD / Entra ID**
- **Create a KDS Root Key** — checked in pre-flight and warned if absent; key
  creation is a deliberate manual administrative action
  (`Add-KdsRootKey -EffectiveImmediately` in a lab; allow 10 hours in
  production before running Phase 8)

### Test Coverage

A Pester test suite (`Tests/Invoke-LZPesterTests.ps1`) verifies deployed state
against the live AD environment. Tests are read-only. Run after any deployment
or incremental run:

```powershell
.\Tests\Invoke-LZPesterTests.ps1 -TierCount 3
```

The **Canary** tag (`-Tag Canary`) runs behavioral tests that go beyond
structural checks: ProtectedFromAccidentalDeletion enforcement (verifies the
flag actually blocks deletion), cross-tier write isolation (verifies T{n}-Admins
cannot write to sibling tiers via ACL inspection), and AdminSDHolder protection
(verifies no GS-LZ group has been accidentally applied to a built-in protected
group like Domain Admins).
