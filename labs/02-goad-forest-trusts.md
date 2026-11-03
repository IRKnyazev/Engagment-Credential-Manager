# Lab 02 — Crossing the Narrow Sea (GOAD, forest & trusts)

**Range style:** [GOAD](https://github.com/Orange-Cyberdefense/GOAD) full lab —
three domains across two forests, linked by trusts.
**Goal:** pivot from a compromised child domain up to the forest root and across a
forest trust, keeping **three domains straight in one engagement DB**.

> Mock data. Hashes/passwords invented.

## Topology

| Host | IP | Domain | Role | Trust |
|---|---|---|---|---|
| `winterfell` | .11 | north.sevenkingdoms.local | child DC | child of sevenkingdoms |
| `kingslanding` | .10 | sevenkingdoms.local | forest-root DC | parent; forest trust to essos |
| `meereen` | .12 | essos.local | DC (2nd forest) | forest trust to sevenkingdoms |
| `castelblack` / `braavos` | .22 / .23 | north / essos | MSSQL members | linked servers across the trust |

One `cm` DB holds the **whole forest** — each account's realm keeps the domains
apart. Starting point: you already own the NORTH child domain (from Lab 01).

```bash
export CM_DB=~/engagements/goad/forest.db
cm init
```

---

## Step 1 — Carry over what you own: NORTH's `krbtgt`

```bash
cm cred 'north.sevenkingdoms.local\krbtgt' --nt 9f8a2c1b3d4e5f60718293a4b5c6d7e8 --src 'DCSync winterfell'
```
```
  + domain north.sevenkingdoms.local
  + user north.sevenkingdoms.local\krbtgt
  + secret #1 ntlm 9f8a2c1b3d4e5f6071829...
```

---

## Step 2 — Child → parent: forge an inter-realm ticket

With the child `krbtgt` and the Enterprise Admins SID you forge an inter-realm TGT
that impersonates the forest-root Administrator. **Store the forged ticket as a
secret of the principal it impersonates**, with its expiry.

```bash
# attack
ticketer.py -nthash <north-krbtgt> -domain north.sevenkingdoms.local \
  -extra-sid <EA-SID> -spn krbtgt/sevenkingdoms.local Administrator
```
```bash
cm cred 'sevenkingdoms.local\Administrator' --ticket ea.kirbi --expires '2026-11-03 20:00' \
  --src 'forged inter-realm TGT via north krbtgt + Enterprise Admins SID history'
```
```
  + domain sevenkingdoms.local
  + user sevenkingdoms.local\Administrator
  + secret #2 kerberos_ticket (blob)
  + link sevenkingdoms.local\Administrator <-> #2 kerberos_ticket (blob)
```

A ticket is a first-class secret type (`--ticket`, stored as a blob with
`--expires`) — so a forged/stolen TGT lives in the DB alongside passwords and
hashes, and you can dump it back out later with `cm export key '#2' > ea.kirbi`.

---

## Step 3 — That ticket logs you into the forest root as Enterprise Admin

```bash
cm works 'sevenkingdoms.local\Administrator' --at kingslanding --proto smb --priv 'enterprise_admin'
```
```
  + host kingslanding
  + access sevenkingdoms.local\Administrator -> smb/kingslanding [valid, enterprise_admin]
```

`--priv` is free text — `enterprise_admin`, `domain_admin`, `local_admin`, or
whatever an app calls it. Record the privilege you actually got.

---

## Step 4 — DCSync the forest root

```bash
cm import samdump --domain sevenkingdoms.local kingslanding_ntds.txt
```
```
imported: 4 NT hash(es)
```

This NTDS dump includes the DC **machine account** `kingslanding$` — a machine
account is just a domain account in `cm` (handy later for delegation / S4U).

---

## Step 5 — Across the forest trust: MSSQL linked servers into ESSOS

`castelblack`'s MSSQL has a trusted link to `braavos` in the `essos.local` forest;
`EXEC … AT` runs there, you get SYSTEM on braavos, dump it, and DCSync essos.

```bash
cm import samdump --domain essos.local braavos_ntds.txt
```
```
  + domain essos.local
imported: 3 NT hash(es)
```

Three domains now live in the one DB, each account filed under its own realm.

---

## Step 6 — Crack propagation

You crack `tywin.lannister`'s NT hash (from the forest-root DCSync) to a plaintext.
`cracked` links the plaintext **and** records that it cracks the hash:

```bash
cm cracked '#5' --pass 'L1on0fCasterlyR0ck'
```
```
  + secret #10 plaintext L1on0fCasterlyR0ck
  + cracks #10 plaintext L1on0fCasterlyR0ck -> #5 ntlm 330fe4fd406f9d0180d67...
  + link sevenkingdoms.local\tywin.lannister <-> secret #10 plaintext
```

---

## Step 7 — Password rotation mid-engagement → `supersede`

The blue team resets `tywin`'s password while you're still testing. Don't delete
the old one (it's history, and it still cracked the old hash) — mark it **stale**
so it stops showing up in spray exports:

```bash
cm supersede 'sevenkingdoms.local\tywin.lannister' --secret '#10'
cm export pairs --type plaintext       # tywin's stale password is gone from the list
```
```
  - supersede sevenkingdoms.local\tywin.lannister <-> #10 plaintext L1on0fCasterlyR0ck
```

In `cm ls` it stays visible, tagged `[superseded]`, so you keep the record without
polluting live credential sets. (`reset` does this automatically when *you* change
a target's password — see Lab 03.)

---

## Step 8 — Machine account is just a domain account

```bash
cm show user 'sevenkingdoms.local\kingslanding$'
```
```
sevenkingdoms.local\kingslanding$
  secrets:
    #6 ntlm 7c0f8e9d6a5b4c3d2e1f00112233abcd
  found via: ntds-dump
```

---

## Review — the whole forest at a glance

```bash
cm ls
```
```
domains (3):
  essos.local
  north.sevenkingdoms.local
  sevenkingdoms.local

identities (8):
  sevenkingdoms.local\Administrator
      #2 kerberos_ticket (blob)
      #3 ntlm 2892d26cdf84d7a70e2eb3b9f05c425e
      -> smb/kingslanding  valid  enterprise_admin
  …
  sevenkingdoms.local\tywin.lannister
      #5 ntlm 330fe4fd406f9d0180d67adb0bd2a799
      #10 plaintext L1on0fCasterlyR0ck  [superseded]
```

Scope any view to one domain:
```bash
cm users --domain essos.local
cm ls --domain sevenkingdoms.local
```

## `cm` features this lab exercised

- **Multiple domains in one DB** — realm per account keeps forests separate
- `cred --ticket … --expires` — a forged/stolen **Kerberos ticket** as a blob secret
- `--priv` free text — `enterprise_admin` / `domain_admin`
- machine accounts (`host$`) as ordinary domain accounts
- `cracked` **crack propagation** (`cracks` link hash ↔ plaintext)
- **`supersede`** — retire a rotated password without losing the record
- `ls --domain` / `users --domain` — per-domain review
