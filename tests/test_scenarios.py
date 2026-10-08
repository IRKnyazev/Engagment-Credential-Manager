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


def invariant_potfile_case_insensitive(cx):
    # real-world (reported) bug: a NetNTLMv2 stored with UPPER-case hex + a given
    # username case must still match a hashcat potfile line that is lower-case hex
    # with a different username case. The PASSWORD case must be preserved.
    stored = ("paul::FILES01:0A79D604907FE974:4BECA034B4C57D5C14AFAA25919EDC63:"
              "0101000000000000804B6179E256DD01")
    cx.run("cred", "FILES01\\paul", "--hash", "netntlmv2:" + stored, "--realm", "host:FILES01")
    pot = os.path.join(cx.workdir, "ntlmv2.pot")
    potline = stored.upper().replace("PAUL::FILES01", "PAUL::FILES01").lower()  # lowercase all
    # also flip the username to uppercase to mimic responder vs hashcat differences
    potline = "PAUL" + potline[4:]
    with open(pot, "w") as fh:
        fh.write(potline + ":123Password123\n")
    out = cx.run("cracked", "--from", pot)
    assert "1 new" in out, "case-differing potfile line must match the stored hash:\n" + out
    assert cx.q1("SELECT COUNT(*) FROM secrets WHERE type='plaintext' AND value='123Password123'") == 1
    pid = cx.q1("SELECT id FROM identities WHERE username='paul'")
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets il JOIN secrets s ON s.id=il.secret_id "
                 "WHERE il.identity_id=? AND s.value='123Password123'", (pid,)) == 1, \
        "cracked plaintext must link to paul"


def invariant_crack_backpropagates(cx):
    # crack a hash FIRST, then discover another owner of that (deduped) hash later;
    # the plaintext must back-link so export pairs / show include the new owner.
    H = "aa11bb22cc33dd44ee55ff6677889900"
    cx.run("cred", "CORP\\early", "--nt", H)
    cx.run("cracked", "#%d" % cx.q1("SELECT id FROM secrets WHERE value=?", (H,)), "--pass", "ReusePW1")
    cx.run("cred", "CORP\\late", "--nt", H)          # owner discovered AFTER the crack
    out = cx.run("export", "pairs", "--type", "plaintext")
    assert "late:ReusePW1" in out, "owner linked after the crack must appear in export pairs:\n" + out
    assert "early:ReusePW1" in out


def invariant_works_without_at_clean_error(cx):
    cx.run("cred", "CORP\\noat", "--pass", "pw")
    out = cx.run("works", "CORP\\noat", expect_fail=True)
    assert "--at" in out, "missing --at must be a clean error, not a traceback"
    assert "Traceback" not in out and "AttributeError" not in out


def invariant_null_multitarget_no_phantom_host(cx):
    cx.run("works", "--null", "--at", "DCA,DCB", "--proto", "smb")
    assert cx.q1("SELECT COUNT(*) FROM hosts WHERE name='DCA,DCB'") == 0, \
        "multi-target null session must not create a comma-named phantom host"
    assert cx.q1("SELECT COUNT(*) FROM hosts WHERE name='DCA'") == 1
    assert cx.q1("SELECT COUNT(*) FROM hosts WHERE name='DCB'") == 1


def invariant_nxc_service_port_and_pwned(cx):
    path = os.path.join(cx.workdir, "nxc_mssql.txt")
    with open(path, "w") as fh:
        fh.write("MSSQL       10.0.0.80       14330  SQLBOX           [+] CORP.LOCAL\\sa:pw (Pwn3d!)\n")
    cx.run("import", "nxc", path)
    row = cx.qall("SELECT a.*, sv.port AS p FROM accesses a JOIN services sv ON sv.id=a.service_id "
                  "JOIN hosts h ON h.id=sv.host_id WHERE h.name='10.0.0.80'")
    assert len(row) == 1, "mssql service access expected"
    assert row[0]["p"] == 14330, "must use the real nxc port column, not the proto default (got %s)" % row[0]["p"]
    assert row[0]["privilege"] == "admin", "Pwn3d! on a service must record admin, not blank"


def invariant_ldap_bad_json_clean_error(cx):
    bad = os.path.join(cx.workdir, "bad.json")
    with open(bad, "w") as fh:
        fh.write("null")
    out = cx.run("import", "ldapdomaindump", "--domain", "X.LOCAL", bad, expect_fail=True)
    assert "Traceback" not in out and "AttributeError" not in out, "bad ldap json must be a clean error"


def invariant_fail_no_lockout(cx):
    # a FAILED guess must NOT become an owned credential or re-appear in the
    # spray exports (account-lockout hazard), but the invalid access is recorded.
    cx.run("fail", "CORP\\lockme", "--pass", "BadGuess9", "--at", "HOSTX", "--proto", "smb")
    lid = cx.q1("SELECT id FROM identities WHERE username='lockme'")
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets WHERE identity_id=?", (lid,)) == 0, \
        "fail must not create an ownership link"
    assert "lockme:BadGuess9" not in cx.run("export", "pairs", "--type", "plaintext"), \
        "a failed guess must not be re-emitted into export pairs"
    assert "BadGuess9" not in cx.run("export", "passwords"), \
        "a failed guess must not pollute the spray wordlist"
    # the attempt is still recorded as an invalid access (so you know you tried it)
    assert cx.q1("SELECT status FROM accesses WHERE identity_id=?", (lid,)) == "invalid"


def invariant_export_passwords_clean(cx):
    # the default spray wordlist excludes tester-planted (introduced) passwords
    # and key passphrases, but includes owned + cracked found passwords; --all dumps all.
    cx.run("cred", "CORP\\realuser", "--pass", "FoundInShare1")      # owned/discovered
    cx.run("reset", "CORP\\planted", "--pass", "PlantedPw2")          # introduced
    keyf = os.path.join(cx.workdir, "k_ep")
    with open(keyf, "w") as fh:
        fh.write("KEY")
    cx.run("cred", "svc@10.0.0.200", "--key", keyf)
    kid = cx.q1("SELECT id FROM secrets WHERE type='ssh_private_key'")
    cx.run("unlock", "--key", "#%d" % kid, "--passphrase", "PassphraseZZ")
    out = cx.run("export", "passwords")
    assert "FoundInShare1" in out, "owned discovered password should be in the wordlist"
    assert "PlantedPw2" not in out, "tester-planted password should be excluded by default"
    assert "PassphraseZZ" not in out, "key passphrase should be excluded by default"
    assert "PlantedPw2" in cx.run("export", "passwords", "--all"), "--all dumps every plaintext"


def invariant_passwd_extra_colon(cx):
    # a malformed passwd line (colon in GECOS) must still read the shell correctly
    pw = os.path.join(cx.workdir, "pw_badcolon.txt")
    with open(pw, "w") as fh:
        fh.write("colonuser:x:1500:1500:Last:First:/home/colonuser:/bin/bash\n")
    cx.run("import", "passwd", "--host", "10.0.0.201", pw)
    hid = cx.q1("SELECT id FROM hosts WHERE name='10.0.0.201'")
    sh = cx.q1("SELECT shell FROM identities WHERE username='colonuser' AND realm_id=?", (hid,))
    assert sh == "/bin/bash", "shell must be read from the last field, got %r" % sh


def invariant_merge_local_domain_split(cx):
    # the real MARKETINGWK01 scenario: a Responder capture filed under the
    # computer name as a domain (DOMAIN\user), and nxc local logins filed under
    # the host (user@host) are the same principal. merge reconciles them.
    cx.run("cred", "WK01\\sam", "--hash", "netntlmv2:sam::WK01:aa11:bb22:cc33")  # domain realm
    p = os.path.join(cx.workdir, "wk01.nxc")
    with open(p, "w") as fh:
        fh.write("SMB   10.0.0.90   445   WK01   [+] WK01\\sam:Pw (Pwn3d!)\n")
    cx.run("import", "nxc", p)                                                   # host realm + access
    assert cx.q1("SELECT COUNT(*) FROM identities WHERE username='sam'") == 2, "two sams expected pre-merge"
    cx.run("merge", "WK01\\sam", "sam@10.0.0.90")
    assert cx.q1("SELECT COUNT(*) FROM identities WHERE username='sam'") == 1, "merge should leave one sam"
    assert cx.q1("SELECT COUNT(*) FROM identities WHERE realm_type='domain' AND username='sam'") == 0
    host_sam = cx.q1("SELECT id FROM identities WHERE username='sam' AND realm_type='host'")
    # host sam now carries BOTH the netntlmv2 secret and the nxc access
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets il JOIN secrets s ON s.id=il.secret_id "
                 "WHERE il.identity_id=? AND s.type='netntlmv2'", (host_sam,)) == 1
    assert cx.q1("SELECT COUNT(*) FROM accesses WHERE identity_id=?", (host_sam,)) == 1


def invariant_samdump_import(cx):
    # ntlmrelayx/secretsdump SAM dump: whole log fed in, noise ignored, local
    # accounts created, shared NT hash deduped. Uses the `samdump` alias.
    log = os.path.join(cx.workdir, "relay.log")
    with open(log, "w") as fh:
        fh.write("[*] (SMB): Authenticating connection ... SUCCEED [1]\n")
        fh.write("[*] smb://X@192.168.134.212 [1] -> Target system bootKey: 0xdeadbeef\n")
        fh.write("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n")
        fh.write("Administrator:500:aad3b435b51404eeaad3b435b51404ee:23ecf03bf097593a4822d0874733c989:::\n")
        fh.write("files02admin:1000:aad3b435b51404eeaad3b435b51404ee:23ecf03bf097593a4822d0874733c989:::\n")
        fh.write("anastasia:1001:aad3b435b51404eeaad3b435b51404ee:62aa7a9e9a8de35fefd17c17058a9983:::\n")
    cx.run("import", "samdump", "--host", "192.168.134.212", log)   # alias of pwdump
    hid = cx.q1("SELECT id FROM hosts WHERE name='192.168.134.212'")
    users = sorted(r["username"] for r in cx.qall(
        "SELECT username FROM identities WHERE realm_type='host' AND realm_id=?", (hid,)))
    assert users == ["Administrator", "anastasia", "files02admin"], \
        "only the 3 SAM rows, noise ignored: %s" % users
    # the shared NT hash is one secret owned by both Administrator and files02admin
    sid = cx.q1("SELECT id FROM secrets WHERE type='ntlm' AND value='23ecf03bf097593a4822d0874733c989'")
    assert cx.q1("SELECT COUNT(*) FROM identity_secrets WHERE secret_id=?", (sid,)) == 2, \
        "shared NT hash should dedupe to one secret with two owners"


def invariant_import_format_help(cx):
    # running an importer with no file prints its expected input format (exit 0)
    out = cx.run("import", "samdump")
    assert "name:rid:lmhash:nthash" in out, "samdump should print its format:\n" + out
    for kind in ("passwd", "shadow", "ldapdomaindump", "nxc"):
        o = cx.run("import", kind)
        assert "expected input" in o, "%s should print a format card:\n%s" % (kind, o)


def invariant_superseded_reconcile(cx):
    # one identity owns two hashes that crack to the same plaintext; supersede the
    # first, crack it, then crack the still-live one -> the plaintext link stays live.
    H1 = "1111111111111111aaaaaaaaaaaaaaaa"
    v2 = "zz::Z:1111:2222333344445555:ABCD"
    cx.run("cred", "CORP\\zz", "--nt", H1)
    cx.run("cred", "CORP\\zz", "--hash", "netntlmv2:" + v2)
    cx.run("supersede", "CORP\\zz", "--secret", "#%d" % cx.q1("SELECT id FROM secrets WHERE value=?", (H1,)))
    cx.run("cracked", "#%d" % cx.q1("SELECT id FROM secrets WHERE value=?", (H1,)), "--pass", "LiveReuse")
    cx.run("cracked", "#%d" % cx.q1("SELECT id FROM secrets WHERE value=?", (v2,)), "--pass", "LiveReuse")
    out = cx.run("export", "pairs", "--type", "plaintext")
    assert "zz:LiveReuse" in out, "a live hash yielding the plaintext must keep the pair live:\n" + out


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
        ("INV potfile matching is case-insensitive (reported bug)", invariant_potfile_case_insensitive),
        ("INV crack back-propagates to owners found later", invariant_crack_backpropagates),
        ("INV works without --at is a clean error", invariant_works_without_at_clean_error),
        ("INV null multi-target makes no phantom host", invariant_null_multitarget_no_phantom_host),
        ("INV nxc service uses real port + Pwn3d admin", invariant_nxc_service_port_and_pwned),
        ("INV ldap bad json is a clean error", invariant_ldap_bad_json_clean_error),
        ("INV fail does not create lockout-risk spray entries", invariant_fail_no_lockout),
        ("INV export passwords excludes planted/passphrase", invariant_export_passwords_clean),
        ("INV passwd tolerates a colon in GECOS", invariant_passwd_extra_colon),
        ("INV merge reconciles a local/domain identity split", invariant_merge_local_domain_split),
        ("INV samdump import (noise ignored, shared-hash dedupe)", invariant_samdump_import),
        ("INV importers print their format when run with no file", invariant_import_format_help),
        ("INV superseded reconciles when a live hash yields it", invariant_superseded_reconcile),
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
