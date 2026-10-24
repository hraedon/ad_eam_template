# Security

This document says what the Landing Zone deployer changes in your domain, which rights it grants and to whom, and how to report a problem.

## What it grants, and to whom

All rights below are ACEs on the tier OUs `OU=_LZ_T{n}` (one per tier), with inheritance to all descendants. They are explicit entries added to the OU's DACL; the deployer never removes or edits existing ones.

| Principal | Right | Scope |
|---|---|---|
| `GS-LZ-T{n}-Admins` | `GenericAll` (Full Control) | `OU=_LZ_T{n}` and everything under it |
| `GS-LZ-T{n}-Readers` | `ReadProperty`, `ListChildren`, `ListObject` | `OU=_LZ_T{n}` and everything under it |
| `GS-LZ-Global-Readers` | `ReadProperty`, `ListChildren`, `ListObject` | every tier OU and its subtree (not `_LZ_Quarantine`, not `CN=_LZ_Groups`) |

`GS-LZ-T0-Devices`, `GS-LZ-T{n}-SvcAccts` and `GS-LZ-T{n}-gMSAHosts` receive no ACEs. All groups are created empty. Nobody gets any of these rights until you add members, so whoever can change membership of the Admins groups controls Full Control over that tier. Protect those groups.

## Other changes with security effect

| Change | Effect |
|---|---|
| `GS-LZ-T0-Admins` added to the built-in `Protected Users` group (Phase 6) | Takes effect immediately for every account that is a member of that group, directly or through nesting: no NTLM, DES or RC4; Kerberos TGTs capped at 4 hours and non-renewable; no delegation; no credential caching. An account that relies on NTLM or delegation breaks at once. Do not add accounts until you have checked each one. Removing the group from Protected Users also takes effect immediately. |
| `LZ-T0-AuthPolicy` is enforced (TGT 240 minutes, `RollingNTLMSecret` Required) | Applies to accounts enrolled in `LZ-T0-Silo`. Phase 7 sets the policy so T0 accounts may authenticate only from members of `GS-LZ-T0-Devices`. That group starts empty; populate it with T0 PAW computer accounts before enrolling accounts, or enrolled accounts have nowhere to sign in. |
| `LZ-T1-AuthPolicy`, `LZ-T2-AuthPolicy` are in audit mode (TGT 480 and 600 minutes) | Audit mode records what would happen; it does not enforce. These tiers have no auth policy beyond that. Tiers 3 and above have none at all. |
| GPO inheritance blocked on each tier OU | Domain-linked GPOs, including security baselines, do not reach machines in tier OUs unless they are Enforced. Each tier GPO (`LZ-T{n}-GPO`) is empty after deployment. |
| `Deploy-LZ-T0Hardening.ps1` (optional, manual) | Sets `BUILTIN\Administrators` membership on in-scope T0 machines to Domain Admins plus `GS-LZ-T0-Admins`, and denies interactive and RDP logon to `GS-LZ-T1-Admins` and `GS-LZ-T2-Admins`. Run only after confirming T0 admins use Kerberos. The Restricted Groups list is authoritative; other local administrators, including the built-in local Administrator, are expected to be removed when it applies (standard behaviour; test first). It writes to SYSVOL and edits GPO attributes. |
| gMSAs (`gMSA-LZ-T{n}`) | Password retrievable by members of `GS-LZ-T{n}-gMSAHosts`. Keep that group to the intended server computer accounts. |

## What it never does

It never creates the KDS root key, never changes existing ACEs, never modifies objects outside the `_LZ_` / `GS-LZ-` / `LZ-` names (apart from the `Protected Users` membership), and never accepts or stores credentials (it uses the signed-in session).

## Things to check before use

- Run from an administrative workstation, as a Domain Admin, in a change window.
- Preview with `-WhatIf` and keep the CSV as the change record. The Event Log copy (source `ADLandingZone`) is harder to alter than the CSV.
- `CC-PreFlight-Test.ps1` creates and deletes temporary objects (OUs, a group, an auth policy and silo, a user briefly added to Protected Users). Do not run it where that is not allowed. A failed check can leave them behind.
- Known issues that affect safe operation are listed in the README under "Known issues".
- The tutorial suggests moving domain controllers into `OU=_LZ_T0_Devices`. Domain controllers are normally in the Domain Controllers OU, where the Default Domain Controllers Policy is linked, and tier OUs block GPO inheritance. This repository does not address what that move does to DC policy. Test it before doing it.
- Code signing: sign the scripts for AllSigned environments (`Helpers\Sign-LZScripts.ps1`). Do not use the `Invoke-Expression` workaround in production.

## Reporting a vulnerability

Not yet documented: the monitored contact and process for security reports. Until the owning teams fill this in, report privately to the repository owner or your internal security team. Do not open a public issue.
