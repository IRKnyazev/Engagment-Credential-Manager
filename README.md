# cm — engagement credential manager

A single-file, **stdlib-only** Python 3 CLI for tracking usernames, passwords,
hashes and **what you've done with them** during a pentest / CTF / OSCP|PNPT|CPTS
engagement. One SQLite database per engagement boundary.

It exists to kill the "I found a cred but lost track of whether it works and
where" problem: every credential, every place it works (or doesn't), and every
place you found it, in one queryable store you can feed straight back into
hashcat, NetExec and friends.

```
no dependencies · one file · scp it onto any box · python3 cm --help
```

## Install

```bash
chmod +x cm
sudo cp cm /usr/local/bin/cm        # or just ./cm
export CM_DB=engagement.db          # per-engagement; or pass --db each time
cm init
```

Runs on a stock Kali (Python 3, sqlite3 — both in the base image). Nothing to
`pip install`.

## The model in 30 seconds

| table | meaning |
|-------|---------|
| `hosts` / `domains` / `services` | **places** things live |
| `identities` | a **who** — belongs to a realm: a domain, a host, or a service |
| `secrets` | a **what** — password / hash / key-blob / ticket. **Unique by `(type,value)`** — the same secret found twice is one row |
| `identity_secrets` | who **owns/uses** what (`origin` discovered/introduced, per-link `superseded`) |
| `secret_links` | one secret **cracks** or **unlocks** another |
| `accesses` | a (identity + secret) **logs into** a host or service — `status`, `privilege` |
| `observations` | **every place/way** something was found (provenance) |

Guiding rules the tool enforces for you:

- **Realm = who an identity is. A file is never a realm** — a filename is
  provenance (`--src`), not a realm.
- **Cracked ≠ verified.** Recording a crack links the plaintext and propagates
  it to the hash's owners, but creates **no** access. You only get a `valid`
  access when a login confirms it.
- **`superseded` is per-link.** If a hash is shared by two users and one rotates,
  only that user's link goes stale; the other stays live (and the hash stays a
  crack target).
- Nothing is pre-declared — **reference a host/service/identity and it's created.**

## Two tiers

**Everyday macros** (what you type 95% of the time — they auto-create everything
and *echo the atomic steps they ran* so you learn the model):

```bash
cm cred  'CORP\jsmith' --nt 00112233...  --src responder-mitm@10.0.0.50
cm works 'CORP\jsmith' --at HOST1,HOST2,HOST3 --proto smb           # status=valid
cm works 'CORP\jsmith' --at HOST4 --proto smb --priv local_admin
cm fail  'CORP\jsmith' --at HOST9                                   # status=invalid
cm cracked --from hashcat.potfile                                  # bulk, idempotent
cm reset 'CORP\victim' --pass Pentest123!                          # you changed their pw
```

**Atomic commands** (surgical; the macros are built from these):

```bash
cm add host|domain|service|user|secret ...
cm link / cm access / cm supersede / cm observe / cm unlock
```

## Referring to things

- **Identity:** `DOMAIN\user` (domain), `user@host` (host-local), `user@host:port`
  (a service), or `--null` for the SMB null session (empty username). `--realm
  domain:X | host:X | service:HOST:PORT` overrides.
- **Secret:** inline `--pass` / `--nt` / `--hash TYPE:VALUE` / `--key FILE` /
  `--pfx FILE` / `--ticket FILE`; or reference an existing one by `#id`,
  `type:value`, or a unique value-prefix.
- **Target:** `--at HOST` (host scope) or `--at HOST:PORT` (service). `--proto`
  sets a sensible default scope+port; `--scope` forces it. **Every assumption the
  tool makes is printed.**

## Finding things again

```bash
cm users [--domain CORP.LOCAL | --host 10.0.0.5]   # who
cm show user 'CORP\jsmith'                          # everything about one identity
cm show secret '#7'
cm where --user 'CORP\jsmith'                       # where a cred works
cm where --host HOST4                               # who works on a box
cm where                                            # every access (add --valid to filter)
cm hashes --type kerberos_tgs                       # list hashes of a type
cm todo-crack                                       # crackable, not yet cracked, still live
cm stats                                            # engagement summary
```

## Feeding other tools

```bash
cm export users     > users.txt            # deduped
cm export passwords > passwords.txt        # deduped wordlist of found plaintexts
cm export pairs --type plaintext           # user:password
cm export pairs --type ntlm                # user:nthash  (pass-the-hash spray)
cm export pairs --type plaintext --introduced   # only creds YOU planted (cleanup/report)
cm export hashes --type netntlmv2 > v2.hash     # straight into hashcat/john
cm export key '#12' > id_rsa                    # write a key/pfx/ticket blob back out
```

## Importing (begin with the easy, structured ones)

```bash
cm import passwd         --host 10.0.0.5 passwd.txt     # login-shell users only
cm import shadow         --host 10.0.0.5 shadow.txt     # attaches $6$/$y$ hashes
cm import ldapdomaindump --domain CORP.LOCAL domain_users.json
cm import secretsdump    --domain CORP.LOCAL ntds.out   # or --host for a SAM dump
cm import nxc            nxc_smb.out                    # Pwn3d! -> local_admin
```

`cm cracked --from hashcat.potfile` matches `hash:plaintext` lines against stored
hashes by value (robust to colons in the hash, and **case-insensitive** — an
uppercase-stored NetNTLM/NTLM hash still matches hashcat's lowercase potfile
line; the password's own case is preserved), is idempotent on re-run, and
**echoes in full any cracked hash it can't find in the db** — a nudge that you
forgot to add one.

See `examples/` for the exact input formats each importer expects.

## Secret types

`plaintext`, `ntlm`, `lm`, `netntlmv1`, `netntlmv2`, `kerberos_tgs`,
`kerberos_asrep`, `dcc2`, `sha512crypt`, `sha256crypt`, `md5crypt`, `bcrypt`,
`yescrypt`, `ssh_private_key`, `certificate_pfx`, `kerberos_ticket`, and `other`
(with a free-text `--label` for anything unforeseen).

## A 60-second flow

```bash
cm init corp.db
cm import ldapdomaindump --domain CORP.LOCAL users.json    # names, no creds yet
cm import nxc spray.out                                    # jsmith valid on 3, admin on 1
cm cred 'CORP\svc_sql' --hash kerberos_tgs:'$krb5tgs$...' --desc 'SPN MSSQLSvc/sql01'
cm export hashes --type kerberos_tgs > roast.hash          # crack offline
cm cracked --from hashcat.potfile                          # plaintext propagates to svc_sql
cm works 'CORP\svc_sql' --at 10.0.0.9:1433 --proto mssql   # confirm it actually logs in
cm where --host 10.0.0.9
```

## Tests

```bash
python3 tests/test_scenarios.py     # replays 17 engagement scenarios against a real db
```

## Notes & limits

- Usernames are stored and matched **verbatim** (case-sensitive). Be consistent
  (`CORP\jsmith`, not sometimes `CORP\JSmith`).
- The database stores credentials in the clear by design (it's your working
  loot). Keep the `.db` with the rest of your engagement data and dispose of it
  per your rules of engagement.
- `import nxc` parses console output heuristically; spot-check the result with
  `cm where --host <ip>`.
