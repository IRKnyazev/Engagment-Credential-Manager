#!/usr/bin/env python3
"""
Scenario smoke-test for `cm`.

Replays every scenario worked out during design against a real SQLite db and
asserts the resulting rows. Runs the actual CLI as a subprocess (so argument
parsing, realm/target inference and echoes are all exercised).

Usage:
    python3 tests/test_scenarios.py          # run all, exit non-zero on failure

It is intentionally dependency-free (no pytest required), but pytest will also
collect the `test_*` functions if you prefer `pytest tests/`.
"""

import base64
import os
import subprocess
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CM = os.path.join(ROOT, "cm")

_FAILS = []


class Ctx:
    def __init__(self, db, workdir):
        self.db = db
        self.workdir = workdir

    def run(self, *args, **kw):
        expect_fail = kw.pop("expect_fail", False)
        env = dict(os.environ, NO_COLOR="1", CM_DB=self.db)
        proc = subprocess.run([sys.executable, CM, *args],
                              capture_output=True, text=True, env=env, cwd=self.workdir)
        if expect_fail:
            assert proc.returncode != 0, "expected failure but succeeded: %s\n%s" % (args, proc.stdout)
        else:
            assert proc.returncode == 0, "command failed: cm %s\nSTDERR: %s\nSTDOUT: %s" % (
                " ".join(args), proc.stderr, proc.stdout)
        return proc.stdout + proc.stderr

    def q1(self, sql, params=()):
        con = sqlite3.connect(self.db)
        try:
            r = con.execute(sql, params).fetchone()
            return r[0] if r else None
        finally:
            con.close()

    def qall(self, sql, params=()):
        con = sqlite3.connect(self.db)
        con.row_factory = sqlite3.Row
        try:
            return con.execute(sql, params).fetchall()
        finally:
            con.close()


def check(name, fn):
    try:
        fn()
        print("  PASS  " + name)
    except AssertionError as e:
        print("  FAIL  " + name + "  ::  " + str(e))
        _FAILS.append(name)
    except Exception as e:  # noqa
        print("  ERROR " + name + "  ::  " + repr(e))
        _FAILS.append(name)


# --------------------------------------------------------------------------

def scenario_1_webapp(cx):
    cx.run("cred", "admin@10.0.0.20:8080", "--pass", "Welcome1", "--at", "10.0.0.20:8080")
    cx.run("works", "admin@10.0.0.20:8080", "--at", "10.0.0.20:8080", "--priv", "wp-admin")
    assert cx.q1("SELECT realm_type FROM identities WHERE username='admin'") == "service"
    a = cx.qall("SELECT * FROM accesses JOIN identities USING(id) WHERE username='admin'")
    # access row for admin
    row = cx.qall("SELECT a.* FROM accesses a JOIN identities i ON i.id=a.identity_id "
                  "WHERE i.username='admin'")[0]
    assert row["scope"] == "service", "webapp must be service scope"
    assert row["status"] == "valid"
    assert row["privilege"] == "wp-admin"


def scenario_2_filehash(cx):
    cx.run("add", "secret", "--hash", "bcrypt:$2b$12$abcdefghijklmnopqrstuv",
           "--src", "vault.kdbx on HOST3")
    cx.run("cracked", "bcrypt:$2b$12$abcdefghijklmnopqrstuv", "--pass", "Summer2024!")
    sid = cx.q1("SELECT id FROM secrets WHERE type='bcrypt'")
    assert sid is not None
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets WHERE secret_id=?", (sid,)) == 0, \
        "file hash must have no owner"
    # a cracks link now exists from the plaintext to the bcrypt hash
    assert cx.q1("SELECT COUNT(*) FROM secret_links WHERE to_secret_id=? AND relation='cracks'",
                 (sid,)) == 1
    assert cx.q1("SELECT COUNT(*) FROM secrets WHERE type='plaintext' AND value='Summer2024!'") == 1


def scenario_3_netntlmv2(cx):
    v2 = "mjones::CORP:1122334455667788:AABBCCDD:0101000000000000FEEDFACE"
    cx.run("cred", "CORP\\mjones", "--hash", "netntlmv2:" + v2, "--src", "responder-mitm@10.0.0.50")
    sid = cx.q1("SELECT id FROM secrets WHERE type='netntlmv2'")
    cx.run("cracked", "#%d" % sid, "--pass", "Autumn2024!")
    cx.run("works", "CORP\\mjones", "--at", "HOST1,HOST2,HOST3", "--proto", "smb")
    cx.run("works", "CORP\\mjones", "--at", "HOST4", "--proto", "smb", "--priv", "local_admin")
    iid = cx.q1("SELECT id FROM identities WHERE username='mjones' AND realm_type='domain'")
    assert iid is not None
    # plaintext propagated to mjones
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets il JOIN secrets s ON s.id=il.secret_id "
                 "WHERE il.identity_id=? AND s.type='plaintext' AND s.value='Autumn2024!'", (iid,)) == 1
    accs = cx.qall("SELECT * FROM accesses WHERE identity_id=?", (iid,))
    assert len(accs) == 4, "expected 4 host accesses, got %d" % len(accs)
    assert all(a["scope"] == "host" and a["status"] == "valid" for a in accs)
    privs = sorted(a["privilege"] for a in accs)
    assert privs == ["", "", "", "local_admin"], "one local_admin, three user(blank): %s" % privs
    assert cx.q1("SELECT COUNT(*) FROM observations WHERE method='responder-mitm@10.0.0.50'") == 1


def scenario_4_pth(cx):
    H = "31d6cfe0d16ae931b73c59d7e0c089c0"
    cx.run("cred", "Administrator@HOST1", "--nt", H, "--src", "sam-dump@HOST1")
    sid = cx.q1("SELECT id FROM secrets WHERE type='ntlm' AND value=?", (H,))
    # admin on HOST1 (that is how we dumped its SAM) + PtH to the rest
    for h in ("HOST1", "HOST2", "HOST3", "HOST4", "HOST5"):
        cx.run("works", "Administrator@" + h, "--secret", "#%d" % sid,
               "--at", h, "--proto", "smb", "--priv", "local_admin")
    # one secret, five host-local Administrator identities, five local_admin accesses
    assert cx.q1("SELECT COUNT(*) FROM secrets WHERE type='ntlm' AND value=?", (H,)) == 1
    owners = cx.q1("SELECT COUNT(*) FROM identity_secrets WHERE secret_id=?", (sid,))
    assert owners == 5, "shared hash should have 5 owners, got %d" % owners
    accs = cx.q1("SELECT COUNT(*) FROM accesses WHERE secret_id=? AND privilege='local_admin'", (sid,))
    assert accs == 5, "expected 5 local_admin accesses, got %d" % accs
    # not cracked -> still a crack target
    out = cx.run("todo-crack")
    assert H in out, "uncracked shared NT hash should be in todo-crack"


def scenario_5_reuse(cx):
    before = cx.q1("SELECT id FROM secrets WHERE type='plaintext' AND value='Summer2024!'")
    cx.run("cred", "CORP\\svc_backup", "--pass", "Summer2024!")
    cx.run("works", "CORP\\svc_backup", "--at", "HOST7", "--proto", "winrm")
    after = cx.q1("SELECT id FROM secrets WHERE type='plaintext' AND value='Summer2024!'")
    assert before == after, "reused password must be the SAME secret row (dedup)"
    owners = cx.q1("SELECT COUNT(*) FROM identity_secrets WHERE secret_id=?", (after,))
    assert owners >= 1


def scenario_6_ldap(cx):
    path = os.path.join(cx.workdir, "domain_users.json")
    with open(path, "w") as fh:
        fh.write('[{"attributes": {"sAMAccountName": ["jsmith"], "description": ["Helpdesk operator"]}},'
                 ' {"attributes": {"sAMAccountName": ["asmith"], "description": ["Finance"]}}]')
    cx.run("import", "ldapdomaindump", "--domain", "CORP.LOCAL", path)
    n = cx.q1("SELECT COUNT(*) FROM identities WHERE realm_type='domain' AND "
              "realm_id=(SELECT id FROM domains WHERE fqdn='CORP.LOCAL') AND username IN ('jsmith','asmith')")
    assert n == 2, "expected 2 ldap users"
    assert cx.q1("SELECT description FROM identities WHERE username='jsmith'") == "Helpdesk operator"
    # identities only - no secrets linked for these
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets il JOIN identities i ON i.id=il.identity_id "
                 "WHERE i.username='asmith'") == 0


def scenario_7_passwd_shadow(cx):
    pw = os.path.join(cx.workdir, "passwd.txt")
    sh = os.path.join(cx.workdir, "shadow.txt")
    with open(pw, "w") as fh:
        fh.write("root:x:0:0:root:/root:/bin/bash\n"
                 "bob:x:1000:1000:Bob,,,:/home/bob:/bin/bash\n"
                 "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                 "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
    sha_bob = "$6$abc$" + "d" * 40
    with open(sh, "w") as fh:
        fh.write("root:$6$rootsalt$" + "e" * 40 + ":19000:0:99999:7:::\n")
        fh.write("bob:" + sha_bob + ":19000:0:99999:7:::\n")
        fh.write("www-data:*:19000:0:99999:7:::\n")
    cx.run("import", "passwd", "--host", "10.0.0.5", pw)
    cx.run("import", "shadow", "--host", "10.0.0.5", sh)
    hid = cx.q1("SELECT id FROM hosts WHERE name='10.0.0.5'")
    users = sorted(r["username"] for r in cx.qall(
        "SELECT username FROM identities WHERE realm_type='host' AND realm_id=?", (hid,)))
    assert users == ["bob", "root"], "only login-shell users imported, got %s" % users
    assert cx.q1("SELECT shell FROM identities WHERE username='bob' AND realm_id=?", (hid,)) == "/bin/bash"
    assert cx.q1("SELECT COUNT(*) FROM secrets WHERE type='sha512crypt'") >= 2
    # crack bob via a potfile
    pot = os.path.join(cx.workdir, "hc.pot")
    with open(pot, "w") as fh:
        fh.write(sha_bob + ":bobpassword\n")
    out = cx.run("cracked", "--from", pot)
    assert "1 new" in out, out
    assert cx.q1("SELECT COUNT(*) FROM secrets WHERE type='plaintext' AND value='bobpassword'") == 1


def scenario_8_anon_null(cx):
    cx.run("cred", "anonymous@10.0.0.30:21", "--pass", "")
    cx.run("works", "anonymous@10.0.0.30:21", "--at", "10.0.0.30:21", "--proto", "ftp", "--scope", "service")
    assert cx.q1("SELECT COUNT(*) FROM identities WHERE username='anonymous'") == 1
    assert cx.q1("SELECT COUNT(*) FROM secrets WHERE type='plaintext' AND value=''") == 1, \
        "blank password stored as empty-string secret"
    # null session: empty username, host scope
    cx.run("works", "--null", "--at", "DC01:445", "--proto", "smb")
    nid = cx.q1("SELECT id FROM identities WHERE username='' AND realm_type='host'")
    assert nid is not None, "null session identity has empty username + host realm"
    sc = cx.q1("SELECT scope FROM accesses WHERE identity_id=?", (nid,))
    assert sc == "host", "smb null session must be host scope even with :445, got %s" % sc


def scenario_9_nxc(cx):
    path = os.path.join(cx.workdir, "nxc.txt")
    with open(path, "w") as fh:
        fh.write("SMB         10.0.0.60       445    FILESRV          [*] Windows 10\n")
        fh.write("SMB         10.0.0.60       445    FILESRV          [+] CORP.LOCAL\\jsmith:Autumn2024! \n")
        fh.write("SMB         10.0.0.61       445    WEBSRV           [+] CORP.LOCAL\\admin:Hunter2 (Pwn3d!)\n")
        fh.write("SMB         10.0.0.62       445    WS09             [+] WS09\\Administrator:ffeeddccbbaa99887766554433221100 (Pwn3d!)\n")
    cx.run("import", "nxc", path)
    # the domain Pwn3d! line becomes a local_admin valid access
    pwned = cx.qall("SELECT a.* FROM accesses a JOIN identities i ON i.id=a.identity_id "
                    "WHERE i.username='admin' AND a.privilege='local_admin' AND a.status='valid'")
    assert len(pwned) == 1, "nxc Pwn3d! should map to local_admin"
    # HOSTNAME\\user where the domain equals the hostname must be a HOST-local account,
    # not a bogus domain (regression: hostname-column off-by-one)
    assert cx.q1("SELECT COUNT(*) FROM domains WHERE fqdn='WS09'") == 0, \
        "local-auth HOSTNAME\\user must not create a domain"
    assert cx.q1("SELECT realm_type FROM identities WHERE username='Administrator' AND "
                 "realm_id=(SELECT id FROM hosts WHERE name='10.0.0.62')") == "host"


def scenario_10_sshkey(cx):
    key = os.path.join(cx.workdir, "id_rsa")
    with open(key, "w") as fh:
        fh.write("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----\n")
    cx.run("cred", "deploy@10.0.0.70", "--key", key, "--src", "/home/deploy/.ssh")
    kid = cx.q1("SELECT id FROM secrets WHERE type='ssh_private_key'")
    assert kid is not None
    cx.run("unlock", "--key", "#%d" % kid, "--passphrase", "S3cret!")
    # passphrase is an 'unlocks' link to the key, NOT a login for deploy
    assert cx.q1("SELECT COUNT(*) FROM secret_links WHERE to_secret_id=? AND relation='unlocks'", (kid,)) == 1
    did = cx.q1("SELECT id FROM identities WHERE username='deploy'")
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets il JOIN secrets s ON s.id=il.secret_id "
                 "WHERE il.identity_id=? AND s.value='S3cret!'", (did,)) == 0, \
        "passphrase must NOT be attached to the login identity"


def scenario_11_kerberoast(cx):
    tgs = "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc*$abcdef0123456789$feedface"
    cx.run("cred", "CORP\\svc_sql", "--hash", "kerberos_tgs:" + tgs,
           "--desc", "SPN MSSQLSvc/sql01; roastable")
    out = cx.run("export", "hashes", "--type", "kerberos_tgs")
    assert tgs in out
    sid = cx.q1("SELECT id FROM secrets WHERE type='kerberos_tgs'")
    cx.run("cracked", "#%d" % sid, "--pass", "P@ssw0rd1")
    # cracked != verified: no access yet
    iid = cx.q1("SELECT id FROM identities WHERE username='svc_sql'")
    assert cx.q1("SELECT COUNT(*) FROM accesses WHERE identity_id=?", (iid,)) == 0, \
        "cracking must not create an access"
    cx.run("works", "CORP\\svc_sql", "--at", "10.0.0.9:1433", "--proto", "mssql")
    a = cx.qall("SELECT * FROM accesses WHERE identity_id=?", (iid,))
    assert len(a) == 1 and a[0]["scope"] == "service"


def scenario_12_dedup_merge(cx):
    ntA = "aabbccddeeff00112233445566778899"
    cx.run("cred", "CORP\\alice", "--nt", ntA)
    before = cx.q1("SELECT id FROM secrets WHERE type='plaintext' AND value='Autumn2024!'")
    assert before is not None, "Autumn2024! should already exist from scenario 3"
    cx.run("cracked", "#%d" % cx.q1("SELECT id FROM secrets WHERE value=?", (ntA,)), "--pass", "Autumn2024!")
    after = cx.q1("SELECT id FROM secrets WHERE type='plaintext' AND value='Autumn2024!'")
    assert before == after, "cracked value already present must reuse the existing plaintext row"
    aid = cx.q1("SELECT id FROM identities WHERE username='alice'")
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets WHERE identity_id=? AND secret_id=?",
                 (aid, after)) == 1, "alice should now carry the shared plaintext"


def scenario_13_config_untested(cx):
    cx.run("cred", "MSSQL\\sa", "--pass", "Str0ngP@ss", "--at", "10.0.0.9:1433",
           "--proto", "mssql", "--src", "web.config on HOST5", "--realm", "service:10.0.0.9:1433")
    row = cx.qall("SELECT a.* FROM accesses a JOIN identities i ON i.id=a.identity_id "
                  "WHERE i.username='sa'")[0]
    assert row["status"] == "untested", "config-file cred defaults to untested"
    assert cx.q1("SELECT COUNT(*) FROM observations WHERE method='web.config on HOST5'") == 1


def scenario_14_phantom_reset(cx):
    cx.run("cred", "CORP\\victim", "--nt", "00000000000000000000000000000001")
    cx.run("reset", "CORP\\victim", "--pass", "Pentest123!")
    vid = cx.q1("SELECT id FROM identities WHERE username='victim'")
    # old nt link superseded, new plaintext introduced + live
    old = cx.qall("SELECT il.superseded FROM identity_secrets il JOIN secrets s ON s.id=il.secret_id "
                  "WHERE il.identity_id=? AND s.type='ntlm'", (vid,))[0]
    assert old["superseded"] == 1, "reset must supersede the old secret"
    newrow = cx.qall("SELECT il.* FROM identity_secrets il JOIN secrets s ON s.id=il.secret_id "
                     "WHERE il.identity_id=? AND s.value='Pentest123!'", (vid,))[0]
    assert newrow["origin"] == "introduced" and newrow["superseded"] == 0
    cx.run("works", "CORP\\victim", "--at", "HOST8", "--proto", "smb")
    out = cx.run("export", "pairs", "--type", "plaintext", "--introduced")
    assert "victim:Pentest123!" in out, "introduced export should list the planted password"


def scenario_15_shared_supersede(cx):
    H = "99887766554433221100ffeeddccbbaa"
    cx.run("cred", "CORP\\userA", "--nt", H)
    cx.run("cred", "CORP\\userB", "--nt", H)
    cx.run("supersede", "CORP\\userA")
    sid = cx.q1("SELECT id FROM secrets WHERE value=?", (H,))
    a = cx.q1("SELECT superseded FROM identity_secrets WHERE secret_id=? AND identity_id="
              "(SELECT id FROM identities WHERE username='userA')", (sid,))
    b = cx.q1("SELECT superseded FROM identity_secrets WHERE secret_id=? AND identity_id="
              "(SELECT id FROM identities WHERE username='userB')", (sid,))
    assert a == 1 and b == 0, "supersede must touch only userA's link (a=%s b=%s)" % (a, b)
    # still a live crack target because userB's link is live
    assert H in cx.run("todo-crack")


def scenario_16_ticket_pfx(cx):
    tkt = os.path.join(cx.workdir, "admin.ccache")
    tkt_bytes = bytes(range(0, 60))
    with open(tkt, "wb") as fh:
        fh.write(tkt_bytes)
    cx.run("cred", "CORP\\Administrator", "--ticket", tkt, "--expires", "2026-10-08 18:00")
    sid = cx.q1("SELECT id FROM secrets WHERE type='kerberos_ticket'")
    assert cx.q1("SELECT expires_at FROM secrets WHERE id=?", (sid,)) == "2026-10-08 18:00"
    # export key round-trips the exact bytes
    env = dict(os.environ, NO_COLOR="1", CM_DB=cx.db)
    proc = subprocess.run([sys.executable, CM, "export", "key", "#%d" % sid],
                          capture_output=True, env=env, cwd=cx.workdir)
    assert proc.returncode == 0
    assert proc.stdout == tkt_bytes, "export key must round-trip the exact blob bytes"
    # pfx + unlock reuses the same machinery
    pfx = os.path.join(cx.workdir, "da.pfx")
    with open(pfx, "wb") as fh:
        fh.write(b"\x30\x82FAKEPFX")
    cx.run("cred", "CORP\\da_admin", "--pfx", pfx)
    pid = cx.q1("SELECT id FROM secrets WHERE type='certificate_pfx'")
    cx.run("unlock", "--pfx", "#%d" % pid, "--passphrase", "pfxpass")
    assert cx.q1("SELECT COUNT(*) FROM secret_links WHERE to_secret_id=? AND relation='unlocks'", (pid,)) == 1


def invariant_potfile_idempotent(cx):
    # re-running the same potfile must not create duplicate cracks links, and
    # must echo any hash it could not find in the db.
    pot = os.path.join(cx.workdir, "idem.pot")
    H = "31d6cfe0d16ae931b73c59d7e0c089c0"  # the scenario-4 hash, uncracked
    missing = "deadbeefdeadbeefdeadbeefdeadbeef"
    with open(pot, "w") as fh:
        fh.write(H + ":BlankPwChanged\n")
        fh.write(missing + ":whoops\n")
    out1 = cx.run("cracked", "--from", pot)
    assert "1 new" in out1
    assert missing in out1, "a cracked hash not in the db must be echoed back in full"
    links_after_first = cx.q1(
        "SELECT COUNT(*) FROM secret_links sl JOIN secrets s ON s.id=sl.to_secret_id "
        "WHERE s.value=? AND sl.relation='cracks'", (H,))
    out2 = cx.run("cracked", "--from", pot)
    assert "already linked" in out2 and "1 new" not in out2.split("\n")[1]
    links_after_second = cx.q1(
        "SELECT COUNT(*) FROM secret_links sl JOIN secrets s ON s.id=sl.to_secret_id "
        "WHERE s.value=? AND sl.relation='cracks'", (H,))
    assert links_after_first == links_after_second == 1, "potfile re-run must be idempotent"


def main():
    tmp = tempfile.mkdtemp(prefix="cm_test_")
    db = os.path.join(tmp, "corp.db")
    cx = Ctx(db, tmp)
    cx.run("init")
    scenarios = [
        ("S1  web application credentials", scenario_1_webapp),
        ("S2  file hash cracked (ownerless)", scenario_2_filehash),
        ("S3  NetNTLMv2 mitm -> crack -> spray", scenario_3_netntlmv2),
        ("S4  SAM local-admin PtH everywhere", scenario_4_pth),
        ("S5  password reused for service acct", scenario_5_reuse),
        ("S6  ldapdomaindump identities only", scenario_6_ldap),
        ("S7  /etc/passwd + /etc/shadow + crack", scenario_7_passwd_shadow),
        ("S8  anonymous + SMB null session", scenario_8_anon_null),
        ("S9  nxc spray output import", scenario_9_nxc),
        ("S10 ssh private key + passphrase", scenario_10_sshkey),
        ("S11 kerberoast (cracked != verified)", scenario_11_kerberoast),
        ("S12 cracked value already present", scenario_12_dedup_merge),
        ("S13 creds in config file (untested)", scenario_13_config_untested),
        ("S14 tester-changed password (phantom)", scenario_14_phantom_reset),
        ("S15 shared hash, one owner superseded", scenario_15_shared_supersede),
        ("S16 kerberos ticket + pfx (blob round-trip)", scenario_16_ticket_pfx),
        ("INV potfile import is idempotent + echoes misses", invariant_potfile_idempotent),
    ]
    print("running %d scenario checks against %s\n" % (len(scenarios), db))
    for name, fn in scenarios:
        check(name, lambda fn=fn: fn(cx))
    print()
    if _FAILS:
        print("FAILED: %d/%d" % (len(_FAILS), len(scenarios)))
        return 1
    print("ALL %d SCENARIOS PASSED" % len(scenarios))
    return 0


if __name__ == "__main__":
    sys.exit(main())
