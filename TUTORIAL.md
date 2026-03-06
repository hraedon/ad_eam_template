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
- **T0 Device Restriction (baseline):** Tier 0 accounts are restricted to
  authenticating from domain-joined devices. This is the v1 baseline.
  Full restriction to designated Privileged Access Workstations (PAWs) requires
  populating a T0 device security group and updating `LZ-T0-AuthPolicy` with a
  group-membership SDDL condition -- this is a migration-phase action.
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

Run the orchestrator script to instantiate the structure. This is an
**additive-only** process -- it will not modify or delete any existing objects
outside the `_LZ_` / `GS-LZ-` namespace.

```powershell
.\Deploy-ADLandingZone.ps1 -TierCount 3 -LogPath C:\Logs\LZ-Deploy.csv
```

Review the CSV log after the run. The summary printed at the end is derived
from the CSV, so a zero-row log despite console output indicates a log write
problem worth investigating before proceeding.

### Step 3: Migration (Manual)

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

### Step 4: Silo Enrollment (Manual)

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
| PAW Enforcement | None | Domain-joined baseline (v1); full PAW restriction in v2 |

---

## 5. What This Deployer Does Not Do (v1)

- Create, link, or modify Group Policy Objects
- Migrate existing AD objects into the LZ structure
- Enroll individual accounts into Authentication Policy Silos
- Configure cross-forest or cross-domain trusts
- Provide cleanup or removal scripts
- Integrate with Azure AD / Entra ID
- Create a KDS Root Key (required for gMSA support, planned for v2)
- Provision Group Managed Service Accounts (v2)
