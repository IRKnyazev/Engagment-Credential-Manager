# cm — engagement credential manager

A single-file, **stdlib-only** Python 3 CLI for tracking usernames, passwords,
hashes and **what you've done with them** during a pentest / CTF / OSCP·PNPT·CPTS
engagement. One SQLite database per engagement boundary (a standalone box, or an
AD domain).

It kills the "I found a cred but lost track of whether it works and where"
problem: every credential, every place it works (or doesn't), and every place
you found it — in one store you can query at a glance and feed straight back
into hashcat / NetExec.

```
no dependencies · one file · scp it onto any box · python3 cm --help
```

---

## Install

```bash
chmod +x cm
sudo cp cm /usr/local/bin/cm          # or just run ./cm
export CM_DB=engagement.db            # set once per engagement (or pass --db each time)
cm init
```

Stock Kali has everything it needs (Python 3 + sqlite3). Nothing to `pip install`.
Add `-q` to any command to silence the teaching echo lines; set `NO_COLOR=1` to
disable colour.

---

## 1. Seeing what's in your database  ← start here

**`cm ls` is the overview — every identity, its secrets, and where it works.**
This is the "what do I actually have?" command.

```
$ cm ls
engagement: engagement.db

hosts (5):
  10.0.0.9
  192.168.107.210
  HOST1
  HOST2
  HOST4

domains (1):
  CORP

identities (3):
  CORP\jsmith
      #1 netntlmv2 jsmith::CORP:aa:bb:cc
      #2 plaintext Autumn2024!
      -> smb/HOST1  valid
      -> smb/HOST2  valid
      -> smb/HOST4  valid  local_admin
  sam@192.168.107.210
      #3 plaintext DISISMYPASSWORD
      -> rdp/192.168.107.210  valid  local_admin
  sa@10.0.0.9:1433
      #4 plaintext Str0ngP@ss
      -> mssql/10.0.0.9:1433  untested

to crack (1): run `cm todo-crack` for the list
```

Narrow it when the engagement gets big:

```bash
cm ls --host 10.0.0.9      # one host (and its services)
cm ls --domain CORP.LOCAL  # one domain
cm ls --valid              # hide untested/invalid, show only confirmed logins
```

The rest of the query surface, by question:

| You want to know… | Command |
|---|---|
| the whole picture | `cm ls` |
| just the counts | `cm stats` |
| everything about one identity | `cm show user 'CORP\jsmith'` |
| everything about one secret (and who owns it) | `cm show secret '#7'` |
| where does **this cred** work | `cm where --user 'CORP\jsmith'` |
| who works on **this box** | `cm where --host HOST4` |
| every confirmed login (lateral-movement view) | `cm where --valid` |
| list identities | `cm users` · `cm users --domain CORP.LOCAL` · `cm users --host 10.0.0.5` |
| hashes of one type | `cm hashes --type kerberos_tgs` |
| what's left to crack | `cm todo-crack` |

Colours in `cm ls` / `cm where`: green = `valid`, yellow = `untested`,
red = `invalid`, dim = `expired`/superseded.

---

## 2. Recording things as you find them

**Everyday macros** auto-create hosts/services/identities/secrets as you
reference them, and echo the atomic steps they ran so you can see what happened.

`cm cred` takes **either** a flat `key:value` line (order-free, like Metasploit
`creds add`) **or** the `IDENT --flags` grammar — pick whichever reads better,
they do the exact same thing. Each flat key is just the matching `--flag` without
the dashes:

```bash
# flat form — nothing to learn but key:value
cm cred user:jsmith pass:Summer2024 realm:CORP
cm cred user:admin host:10.0.0.5 pass:root            # a LOCAL account on a host
cm cred user:svc nt:00112233... realm:CORP at:10.0.0.9 proto:mssql
cm cred --null at:10.0.0.5 proto:smb                  # SMB null session

# grammar form — same result
cm cred 'CORP\jsmith' --nt 00112233...  --src responder-mitm@10.0.0.50
cm cred 'admin@10.0.0.20:8080' --pass Welcome1 --at 10.0.0.20:8080   # defaults to untested

# confirm (or disprove) a login
cm works 'CORP\jsmith' --at HOST1,HOST2,HOST3 --proto smb            # status=valid
cm works 'CORP\jsmith' --at HOST4 --proto smb --priv local_admin
cm fail  'CORP\jsmith' --at HOST9                                    # status=invalid,
                                                                    #   never pollutes spray lists

# a hash got cracked (single, or bulk from hashcat)
cm cracked '#3' --pass Autumn2024!
cm cracked --from hashcat.potfile          # matches by hash value, idempotent

# you changed a target's password during the test (phantom cred)
cm reset 'CORP\victim' --pass Pentest123!  # supersedes the old, adds yours as "introduced"
```

`cred` = "I have this credential." `works`/`fail` = "I tried it and it did / didn't
log in." `cracked` = "this hash resolved to this plaintext." Cracking links the
plaintext but creates **no** access — you only get a `valid` access from `works`.

**Atomic commands** underneath, for surgical edits:
`cm add host|domain|service|user|secret` · `cm link` · `cm access` ·
`cm supersede` · `cm observe` · `cm unlock` · `cm merge`.

---

## 3. Naming identities and targets

**Identity:**

| You type | Realm it means |
|---|---|
| `CORP\jsmith` or `CORP.LOCAL\jsmith` | **domain** account |
| `sam@10.0.0.5` or `sam@WS01` | **host-local** account |
| `admin@10.0.0.20:8080` | account in a **service** (that host:port) |
| `--null` | the SMB null session (empty username) |
| add `--realm domain:X` / `host:X` / `service:H:P` | force it explicitly |

> **Standalone / workgroup boxes (common in OSCP):** a local account whose prefix
> is the *computer name* — e.g. Responder shows `MARKETINGWK01\sam`, or nxc needs
> `--local-auth` — is **local, not domain**. Enter it as **`sam@<host>`**, not
> `MARKETINGWK01\sam` (the `\` form is read as a domain and will split it from the
> same account seen via nxc/SAM). Tell-tale that it's local: your scan shows
> `NetBIOS_Domain_Name == NetBIOS_Computer_Name`. If a split already happened,
> fix it with `cm merge 'MARKETINGWK01\sam' sam@<host>` (folds the first into the
> second, moving its secrets/accesses/observations).

**Secret** (one of): `--pass X` · `--nt X` · `--hash TYPE:VALUE` · `--key FILE` ·
`--pfx FILE` · `--ticket FILE`. Reference an **existing** one by `#id`,
`type:value`, or a unique value-prefix.

**Flat keys for `cm cred`** — each is the `--flag` above without the dashes, so
there's one vocabulary to learn, not two. Order-free, one keyword per field:

| key | = flag | key | = flag |
|---|---|---|---|
| `user:` | the IDENT username | `at:` | `--at` (target) |
| `pass:` | `--pass` | `proto:` | `--proto` |
| `nt:` | `--nt` | `priv:` | `--priv` |
| `hash:` | `--hash` (`TYPE:VALUE`) | `status:` | `--status` |
| `key:`/`pfx:`/`ticket:` | the blob flags | `src:` | `--src` |
| `realm:` / `host:` / `service:` | the realm (pick one) | `desc:`/`origin:` | `--desc`/`--origin` |

`realm:CORP` = a domain account, `host:10.0.0.5` = a host-local account,
`service:HOST:PORT` = a service account — give at most one. Values may contain
colons (`pass:a:b`, `hash:kerberos_tgs:$krb5tgs$…`); only the first `:` splits.

**Target** (`--at`): `HOST` → host scope; `HOST:PORT` → service scope. `--proto`
sets a sensible default scope + port (`smb`→host:445, `mysql`→service:3306, …);
`--scope host|service` forces it. **Every assumption the tool makes is printed**,
e.g. `[assumed: mssql -> service-auth (scope=service); port 1433 for mssql]`.

---

## 4. Importing from your tools

```bash
cm import passwd         --host 10.0.0.5 passwd.txt     # login-shell users only
cm import shadow         --host 10.0.0.5 shadow.txt     # attaches $6$/$y$/… hashes to them
cm import ldapdomaindump --domain CORP.LOCAL domain_users.json
cm import samdump        --host 10.0.0.5 relay.log      # SAM dump -> local accounts
cm import samdump        --domain CORP.LOCAL ntds.out   # NTDS dump -> domain accounts
cm import nxc            smb.nxc                        # NetExec console output; Pwn3d! -> admin
```

`samdump` is the `name:rid:lmhash:nthash:::` (pwdump) format — from
impacket-secretsdump, `nxc --sam/--ntds`, or an ntlmrelayx SAM dump. It ignores
every non-hash line, so you can feed it the whole tool log. (`pwdump` and
`secretsdump` are accepted as aliases.)

**Not sure what a parser eats? Run it with no file** and it prints the exact
format and an example:

```
$ cm import samdump
cm import pwdump - expected input:
  pwdump / SAM / NTDS dump  (aliases: samdump, secretsdump)
  needs: --host <name|ip>   local SAM dump  -> local accounts
         --domain <fqdn>    NTDS/domain dump -> domain accounts
  line:  name:rid:lmhash:nthash:::
  from:  impacket-secretsdump, nxc --sam/--ntds, ntlmrelayx SAM dump
  ...
```

**Cracking back in:** `cm cracked --from hashcat.potfile` (or `--stdin`) matches
`hash:plaintext` lines against stored hashes **by hash value** — robust to the
colons inside NetNTLM/Kerberos hashes, **case-insensitive** on the hash (an
uppercase-stored hash still matches hashcat's lowercase potfile; the password's
case is kept), idempotent on re-run, and it **prints in full any cracked hash it
can't find in the db** so you notice one you forgot to add.

**Which mode?** `cm hashes`, `cm todo-crack` and `cm export hashes` print the
exact `hashcat -m …` / `john --format=…` for each hash type **to stderr**, so you
never look it up — and because it's stderr, your redirect (`> v2.hash`) stays
clean:

```
$ cm export hashes --type netntlmv2 > v2.hash
# netntlmv2      hashcat -m 5600 | john --format=netntlmv2
```

Typical round-trip:
```bash
cm export hashes --type netntlmv2 > v2.hash   # tells you it's -m 5600
hashcat -m 5600 v2.hash rockyou.txt
cm cracked --from ~/.local/share/hashcat/hashcat.potfile
```

`examples/` contains a sample of each import format.

---

## 5. Exporting for other tools

```bash
cm export users                      # deduped username list
cm export passwords                  # deduped wordlist of found/cracked passwords
                                     #   (excludes planted creds, key passphrases,
                                     #    failed guesses; --all = every plaintext)
cm export pairs --type plaintext     # user:password
cm export pairs --type ntlm          # user:nthash   (pass-the-hash spray)
cm export pairs --type plaintext --introduced   # only creds YOU planted (cleanup/report)
cm export hashes --type kerberos_tgs > tgs.hash  # straight into hashcat/john
cm export key '#12' > id_rsa                     # write a key/pfx/ticket blob back out
```

**Online attacks (spray / reuse / pass-the-hash)** — split lists feed NetExec,
hydra or kerbrute directly. `export passwords` is already a reuse wordlist of
plaintexts *actually seen in the environment*, so spraying it hunts password
reuse without noise:

```bash
cm export users     > users.txt
cm export passwords > pass.txt
nxc smb 10.0.0.0/24 -u users.txt -p pass.txt --continue-on-success   # reuse spray
cm export pairs --type ntlm | sed 's/:/ /' | while read u h; do \
    nxc smb TARGET -u "$u" -H "$h"; done                             # pass-the-hash
```

`fail` keeps spray lists safe: a disproven guess is recorded as an `invalid`
access but never re-emitted into `export pairs`, so you don't re-spray a known-bad
credential (and risk lockout).

---

## 6. The data model (why queries behave as they do)

| table | meaning |
|---|---|
| `hosts` / `domains` / `services` | **places** things live |
| `identities` | a **who** — in a realm: a domain, a host, or a service |
| `secrets` | a **what** — password / hash / key-blob / ticket. **Unique by `(type,value)`** — the same secret found twice is one row |
| `identity_secrets` | who **owns/uses** what (`origin` discovered/introduced, per-link `superseded`) |
| `secret_links` | one secret **cracks** or **unlocks** another |
| `accesses` | a (identity + secret) **logs into** a host/service — `status`, `privilege` |
| `observations` | **every place/way** something was found (provenance, from `--src`) |

Rules the tool enforces:

- **A file is never a realm** — a filename is provenance (`--src`), not a realm.
- **Cracked ≠ verified** — a crack links the plaintext (and propagates it to the
  hash's owners) but creates no access; `valid` comes only from `works`.
- **`superseded` is per-link** — if a shared hash's password rotates for one
  owner, only that owner's link goes stale; the hash stays a crack target for the
  others.
- **Nothing is pre-declared** — reference a host/service/identity and it exists.

**Secret types:** `plaintext`, `ntlm`, `lm`, `netntlmv1`, `netntlmv2`,
`kerberos_tgs`, `kerberos_asrep`, `dcc2`, `sha512crypt`, `sha256crypt`,
`md5crypt`, `bcrypt`, `yescrypt`, `ssh_private_key`, `certificate_pfx`,
`kerberos_ticket`, `other` (free-text `--label`).

---

## 7. Command reference

```
init                 create / ensure an engagement db
# record
cred    IDENT ... | user:…pass:…realm:…    record a credential (+ optional target)
works   IDENT --at   confirm a working login (status=valid)
fail    IDENT --at   record a failed login (status=invalid)
cracked REF|--from   a hash resolved to a plaintext
reset   IDENT        you changed the target's password (introduced)
# query
ls                   whole-engagement overview            (--host/--domain/--valid)
stats                summary counts
show    user|secret  one identity / secret in full
where                accesses: --user X | --host Y | (none)=all | --valid
users                list identities                      (--domain/--host/--realm)
hashes  --type T     list stored hashes of a type   (+ hashcat/john hint on stderr)
todo-crack           crackable, not yet cracked, still live  (+ crack command)
# export
export  users|passwords|pairs|hashes|key
# import   (run any with no file to print its expected format)
import  passwd|shadow|ldapdomaindump|samdump|nxc    # samdump aka pwdump/secretsdump
# atomic / fix-ups
add host|domain|service|user|secret · link · access · supersede · observe · unlock · merge
```

`cm <command> --help` details any one of them.

---

## 8. A worked example

```bash
export CM_DB=corp.db && cm init
cm import ldapdomaindump --domain CORP.LOCAL users.json    # names, no creds yet
cm import nxc spray.out                                    # jsmith valid on 3 boxes, admin on 1
cm cred 'CORP\svc_sql' --hash kerberos_tgs:'$krb5tgs$...' --desc 'SPN MSSQLSvc/sql01'
cm export hashes --type kerberos_tgs > roast.hash          # crack offline
cm cracked --from hashcat.potfile                          # plaintext propagates to svc_sql
cm works 'CORP\svc_sql' --at 10.0.0.9:1433 --proto mssql   # confirm it actually logs in
cm ls --valid                                              # what do I have that works?
```

---

## 9. Notes & limits

- Usernames and realm names match **verbatim** (case-sensitive) — be consistent
  (`FILES01`, not sometimes `FILE01`). `cm ls` / `cm users` make stray duplicates
  easy to spot, and `cm merge` reconciles them.
- The db stores credentials in the clear by design (it's your loot). Keep it with
  your engagement data and dispose of it per your rules of engagement.
- `import nxc` parses console output heuristically; spot-check with
  `cm where --host <ip>` or `cm ls --host <ip>`.
- Any unexpected error prints a clean `error: …` line; set `CM_DEBUG=1` to see a
  full traceback if you're reporting a bug.

## Tests

```bash
python3 tests/test_scenarios.py     # replays 33 engagement scenarios against a real db
```
