"""Phase 9: security reports, host/site audits, isolation self-test (unit level)."""

from __future__ import annotations

import argparse
import io
import json
import os
import pwd
import stat
from pathlib import Path
from typing import Any

import pytest

from domainpilot.cli import security_handlers
from domainpilot.core import proc
from domainpilot.core.errors import OperationFailed, PreconditionFailed
from domainpilot.core.paths import Paths
from domainpilot.health import Report
from domainpilot.isolation import db, fcgi
from domainpilot.security import host_audit as ha
from domainpilot.security.isolation_test import IsolationTester, evaluate
from domainpilot.security.report import DISCLAIMER, Finding, SecurityReport
from domainpilot.security.site_audit import UNIT_EXPECT, SiteAuditor, SiteFacts
from domainpilot.sites.lifecycle import CreateRequest
from domainpilot.tls.acme import Certbot

# --- report ------------------------------------------------------------------------------


def test_report_model() -> None:
    rep = SecurityReport("system")
    assert rep.worst == "ok" and rep.lines(verbose=False)[-1].startswith("0 checks")
    rep.add("A", True, "fine", threats=("TH1",))
    rep.add("B", False, "broken", detail="why", fix="do this", severity="warn")
    rep.add("C", False, "very broken", fix="now")
    rep.info("D", "fyi")
    assert rep.worst == "critical" and rep.counts() == {
        "ok": 1,
        "info": 1,
        "warn": 1,
        "critical": 1,
    }
    assert [f.id for f in rep.problems()] == ["C", "B"]
    short = rep.lines(verbose=False)
    assert short[0].startswith("CRIT  C") and "fix: now" in short[1] and "A " not in "".join(short)
    assert any(line.startswith("ok    A") for line in rep.lines(verbose=True))
    data = rep.as_dict()
    assert data["disclaimer"] == DISCLAIMER and data["findings"][0]["threats"] == ["TH1"]
    assert rep.findings[0].fix == ""  # passing checks carry no fix
    other = SecurityReport("x")
    other.add("E", True, "e")
    rep.extend(other)
    assert len(rep.findings) == 5
    with pytest.raises(ValueError):
        Finding("X", "fatal", "t")


# --- isolation self-test ------------------------------------------------------------------

GOOD_PROBE: dict[str, Any] = {
    "euid": 20001,
    "no_new_privs": True,
    "seccomp_filter": True,
    "cap_eff_zero": True,
    "apparmor_label": "domainpilot-tenant-t0001//&unconfined (enforce)",
    "own_read_code": True,
    "own_write_code": False,
    "own_write_data": True,
    "own_write_tmp": True,
    "other_paths_visible": [],
    "srv_tenants_listing": ["t0001"],
    "host_secret_paths_readable": [],
    "other_sockets_connectable": [],
    "foreign_processes_visible": 0,
    "exec_functions_available": [],
    "net": {
        "loopback_ssh_v4": False,
        "loopback_http_v4": False,
        "loopback_ssh_v6": False,
        "cloud_metadata": False,
        "private_10": False,
        "private_192_168": False,
        "public_dns_tcp": False,
        "public_https": True,
    },
    "db_own_login": True,
    "db_other_access": False,
    "db_global_privs": False,
    "cache_own_ping": True,
    "cache_config_allowed": False,
    "dns_resolves": True,
}


def test_evaluate_clean_probe() -> None:
    rep = evaluate(GOOD_PROBE, tenant="t0001", uid=20001, writable_code=False)
    assert rep.worst == "info", rep.problems()
    assert any(f.id == "WORKS:public_https" for f in rep.findings)


def test_evaluate_escapes_are_critical() -> None:
    bad = json.loads(json.dumps(GOOD_PROBE))
    bad.update(
        euid=0,
        own_write_code=True,
        other_paths_visible=["/srv/tenants/t0002/app"],
        srv_tenants_listing=["t0001", "t0002"],
        apparmor_label="unconfined",
        exec_functions_available=["system"],
    )
    bad["net"]["cloud_metadata"] = True
    rep = evaluate(bad, tenant="t0001", uid=20001, writable_code=False)
    failed = {f.id for f in rep.problems()}
    assert {
        "SBX-UID",
        "FS-CODE",
        "FS-OTHERS",
        "FS-LISTING",
        "SBX-APPARMOR",
        "PHP-EXEC",
        "NET-META:cloud_metadata",
    } <= failed
    assert all(f.severity == "critical" for f in rep.problems())
    weaker = evaluate(GOOD_PROBE, tenant="t0001", uid=20001, writable_code=True)
    assert [f.severity for f in weaker.problems()] == ["warn"]
    # A foreign profile stacked with ours does not count as ours.
    stacked = dict(GOOD_PROBE, apparmor_label="domainpilot-tenant-t0001//&other (enforce)")
    assert "SBX-APPARMOR" in {
        f.id for f in evaluate(stacked, tenant="t0001", uid=20001, writable_code=False).problems()
    }


def test_isolation_tester_writes_as_owner_and_cleans_up(tmp_path: Path) -> None:
    paths = Paths.under(tmp_path)
    public = paths.tenant_root("t0001") / "app" / "public"
    public.mkdir(parents=True)
    owner = os.getuid() or 4242
    if os.geteuid() == 0:
        os.chown(public, owner, 4243)
    calls: list[list[str]] = []
    written: dict[str, str] = {}

    def run(argv: list[str], **kw: Any) -> proc.Result:
        calls.append(argv)
        if "/usr/bin/tee" in argv:
            written["path"] = argv[-1]
            written["body"] = kw["stdin"]
        return proc.Result(tuple(argv), 0, "", "")

    seen: dict[str, Any] = {}

    def request(sock: Path, params: dict[str, str], **_kw: Any) -> fcgi.Response:
        seen.update(params)
        return fcgi.Response(200, body=json.dumps(GOOD_PROBE).encode())

    probe_src = tmp_path / "probe.php"
    probe_src.write_text("<?php echo '{}';")
    tester = IsolationTester(paths, run=run, request=request, probe_source=probe_src)
    result = tester.run_probe("t0001", others=["t0002"], other_db="t0002_app")
    assert result["euid"] == 20001
    name = Path(written["path"]).name
    assert name.startswith(".dp-probe-") and name.endswith(".php")  # nginx 404s dot-files
    assert seen["SCRIPT_FILENAME"] == written["path"] and seen["DP_OTHERS"] == "t0002"
    setprivs = [c for c in calls if c[0] == "/usr/bin/setpriv"]
    assert len(setprivs) == 2 and setprivs[1][-1] == written["path"]  # removed again
    assert all(f"--reuid={public.stat().st_uid}" in c for c in setprivs)
    assert all("--no-new-privs" in c for c in setprivs)

    def failing(sock: Path, params: dict[str, str], **_kw: Any) -> fcgi.Response:
        return fcgi.Response(502)

    calls.clear()
    with pytest.raises(OperationFailed, match="did not run"):
        IsolationTester(paths, run=run, request=failing, probe_source=probe_src).run_probe(
            "t0001", others=[]
        )
    assert calls[-1][-1].endswith(".php") and "/usr/bin/rm" in calls[-1]  # cleaned up anyway

    def garbage(sock: Path, params: dict[str, str], **_kw: Any) -> fcgi.Response:
        return fcgi.Response(200, body=b"<html>")

    with pytest.raises(OperationFailed, match="no usable result"):
        IsolationTester(paths, run=run, request=garbage, probe_source=probe_src).run_probe(
            "t0001", others=[]
        )


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
def test_isolation_tester_refuses_root_owned_public(tmp_path: Path) -> None:
    paths = Paths.under(tmp_path)
    public = paths.tenant_root("t0001") / "app" / "public"
    public.mkdir(parents=True)
    os.chown(public, 0, 0)
    tester = IsolationTester(paths, run=lambda *a, **k: proc.Result((), 0, "", ""))
    with pytest.raises(PreconditionFailed, match="owned by root"):
        tester.run_probe("t0001", others=[])


# --- host audit ---------------------------------------------------------------------------

SSHD_T = """port 22
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
permitemptypasswords no
x11forwarding no
permittunnel no
allowagentforwarding no
permituserenvironment no
authenticationmethods publickey
allowgroups dp-admins dp-sftp
maxauthtries 3
authorizedkeysfile /etc/ssh/authorized_keys.d/%u
"""
NGINX_T = """http {
    server_tokens off;
    limit_req_zone $binary_remote_addr zone=dp_req:10m rate=20r/s;
    limit_conn_zone $binary_remote_addr zone=dp_conn:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    set_real_ip_from 173.245.48.0/20;
    server { listen 80 default_server; return 444; }
    server { listen 443 ssl default_server; ssl_reject_handshake on; }
}
"""
SS_OUT = """tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*
tcp LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*
tcp LISTEN 0 80 [::1]:3306 [::]:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
"""


def fake_host(tmp_path: Path, overrides: dict[str, str | None] | None = None) -> ha.HostView:
    outputs: dict[str, str | None] = {
        "sshd -T": SSHD_T,
        "nft list chain inet domainpilot input": "chain input { policy drop; }",
        "nft list chain inet domainpilot tenant_egress": "tenant_egress { drop }",
        "ss -H -l -n -t -u": SS_OUT,
        "mariadb --batch --skip-column-names -e SELECT @@skip": "1\t0\n",
        "mariadb --batch --skip-column-names -e SELECT CONCAT": "",
        "lsattr -d": "-----a--------e------- /var/log/domainpilot/audit.jsonl",
        "systemctl is-active": "active\n",
        "fail2ban-client status sshd": "Status for the jail: sshd\n",
        "nginx -T": NGINX_T,
    }
    outputs |= overrides or {}

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        line = " ".join([Path(argv[0]).name, *argv[1:]])
        for prefix, out in outputs.items():
            if line.startswith(prefix):
                if out is None:
                    return proc.Result(tuple(argv), 1, "", "failed")
                return proc.Result(tuple(argv), 0, out, "")
        raise OperationFailed(f"unexpected: {line}")

    root = tmp_path / "host"
    for d, mode in (
        ("etc/domainpilot", 0o750),
        ("etc/domainpilot/secrets/backup", 0o700),
        ("var/lib/domainpilot", 0o700),
        ("var/log/domainpilot", 0o750),
        ("etc/sysctl.d", 0o755),
        ("proc/sys/kernel", 0o755),
        ("sys/module/apparmor/parameters", 0o755),
    ):
        (root / d).mkdir(parents=True, exist_ok=True)
        (root / d).chmod(mode)
    (root / "etc/domainpilot/secrets").chmod(0o700)
    cred = root / "etc/domainpilot/secrets/backup/master.cred"
    cred.write_text("x")
    cred.chmod(0o600)
    (root / "var/log/domainpilot/audit.jsonl").write_text("")
    (root / "etc/sysctl.d/99-domainpilot.conf").write_text(
        "# hardening\nkernel.kptr_restrict = 2\nkernel.dmesg_restrict=1\nnet.ipv4.tcp_x = 1 2\n"
        "bad key = 1\n"
    )
    (root / "proc/sys/kernel/kptr_restrict").write_text("2\n")
    (root / "proc/sys/kernel/dmesg_restrict").write_text("1\n")
    (root / "sys/module/apparmor/parameters/enabled").write_text("Y\n")
    (root / "etc/domainpilot/backup.json").write_text('{"repository": "s3:https://s3.x/b"}')
    (root / "etc/domainpilot/alerts.json").write_text("{}")
    return ha.HostView(run=run, root=root)


def owned_by_root(view: ha.HostView) -> list[ha.PathRule]:
    """Path rules adjusted to the uid running the tests (root in CI containers)."""
    return [
        ha.PathRule(r.path, r.max_mode, os.getuid(), r.fid, r.threats, r.recursive_files)
        for r in ha.PATH_RULES
    ]


def test_host_audit_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    view = fake_host(tmp_path)
    monkeypatch.setattr(ha, "PATH_RULES", tuple(owned_by_root(view)))
    monkeypatch.setattr(
        ha,
        "ALL_CHECKS",
        tuple(
            c if c is not ha.check_paths else (lambda v, r: ha.check_paths(v, r, owned_by_root(v)))
            for c in ha.ALL_CHECKS
        ),
    )
    rep = ha.audit_host(view)
    assert rep.problems() == [], rep.lines(verbose=False)
    assert {
        "SSH-PASSWORDAUTHENTICATION",
        "FW-DEFAULT-DENY",
        "DB-NO-TCP",
        "KERN-SYSCTL",
        "NGX-DEFAULT-444",
        "AUDIT-APPEND-ONLY",
        "BKP-OFFSITE",
    } <= {f.id for f in rep.findings}


def test_host_audit_finds_drift(tmp_path: Path) -> None:
    weak_sshd = SSHD_T.replace("passwordauthentication no", "passwordauthentication yes").replace(
        "maxauthtries 3", "maxauthtries 6"
    )
    view = fake_host(
        tmp_path,
        {
            "sshd -T": weak_sshd,
            "nft list chain inet domainpilot input": "chain input { policy accept; }",
            "nft list chain inet domainpilot tenant_egress": None,
            "ss -H -l -n -t -u": SS_OUT + "tcp LISTEN 0 80 0.0.0.0:3306 0.0.0.0:*\n",
            "mariadb --batch --skip-column-names -e SELECT @@skip": "0\t1\n@%\nbob@10.0.0.5\n",
            "mariadb --batch --skip-column-names -e SELECT CONCAT": "t0001@localhost\n",
            "lsattr -d": "--------------e------- /x",
            "systemctl is-active": "inactive\n",
            "fail2ban-client status sshd": None,
            "nginx -T": NGINX_T.replace("server_tokens off;", "")
            .replace("set_real_ip_from 173.245.48.0/20;", "set_real_ip_from 0.0.0.0/0;")
            .replace("TLSv1.2 TLSv1.3", "TLSv1 TLSv1.2"),
        },
    )
    (view.root / "proc/sys/kernel/kptr_restrict").write_text("0\n")
    (view.root / "var/lib/domainpilot/firewall").mkdir()
    (view.root / "var/lib/domainpilot/firewall/pending").write_text("")
    (view.root / "etc/domainpilot/backup.json").write_text('{"repository": "/var/backups"}')
    (view.root / "etc/domainpilot/alerts.json").unlink()
    (view.root / "etc/domainpilot").chmod(0o757)
    (view.root / "sys/module/apparmor/parameters/enabled").write_text("N\n")
    rep = ha.audit_host(view)
    failed = {f.id for f in rep.problems()}
    expected = {
        "SSH-PASSWORDAUTHENTICATION", "SSH-MAXAUTHTRIES", "FW-DEFAULT-DENY", "FW-TENANT-EGRESS",
        "FW-PENDING", "NET-LISTENERS", "KERN-SYSCTL", "DB-NO-TCP", "DB-LOCAL-INFILE",
        "DB-ACCOUNTS", "DB-TENANT-GLOBAL", "PERM-ETC", "AUDIT-APPEND-ONLY", "AA-ENABLED",
        "F2B-SSHD", "UPD-TIMER", "NGX-TOKENS", "NGX-REALIP", "NGX-TLS-PROTOCOLS",
        "BKP-OFFSITE", "MON-ALERTS",
    }  # fmt: skip
    assert expected <= failed, expected - failed
    listeners = next(f for f in rep.findings if f.id == "NET-LISTENERS")
    assert "3306" in listeners.detail and "9100" not in listeners.detail


def test_host_audit_when_tools_fail(tmp_path: Path) -> None:
    view = fake_host(
        tmp_path,
        {
            "sshd -T": None,
            "nginx -T": None,
            "ss -H": None,
            "mariadb --batch --skip-column-names -e SELECT @@skip": None,
            "nft list chain inet domainpilot input": None,
        },
    )
    (view.root / "etc/sysctl.d/99-domainpilot.conf").unlink()
    (view.root / "etc/domainpilot/backup.json").unlink()
    (view.root / "var/log/domainpilot/audit.jsonl").unlink()
    rep = ha.audit_host(view)
    failed = {f.id for f in rep.problems()}
    assert {
        "SSH-CONFIG",
        "NGX-CONFIG",
        "DB-REACHABLE",
        "FW-TABLE",
        "KERN-SYSCTL",
        "BKP-CONFIGURED",
    } <= failed
    assert (
        ha.HostView(run=lambda *a, **k: (_ for _ in ()).throw(OperationFailed("x"))).out("/bin/x")
        is None
    )


def test_path_rules(tmp_path: Path) -> None:
    view = ha.HostView(root=tmp_path)
    keys = tmp_path / "etc/ssh/authorized_keys.d"
    keys.mkdir(parents=True)
    keys.chmod(0o755)
    good = keys / "alice"
    good.write_text("k")
    good.chmod(0o644)
    rule = ha.PathRule("/etc/ssh/authorized_keys.d", 0o755, os.getuid(), "K", recursive_files=0o644)
    rep = SecurityReport("x")
    ha.check_paths(view, rep, [rule, ha.PathRule("/missing", 0o700)])
    assert rep.worst == "ok" and len(rep.findings) == 1
    good.chmod(0o666)
    (keys / "link").symlink_to("/etc/passwd")
    rep = SecurityReport("x")
    ha.check_paths(view, rep, [rule])
    assert rep.worst == "critical" and "alice: 0666" in rep.findings[0].detail


# --- site audit -----------------------------------------------------------------------------


@pytest.fixture
def site_tree(tmp_path: Path) -> dict[str, Any]:
    paths = Paths.under(tmp_path)
    root = paths.tenant_root("t0001")
    uid, gid = os.getuid(), os.getgid()
    for sub, mode in (
        ("", 0o750),
        ("app", 0o2750),
        ("app/public", 0o2750),
        ("data", 0o2770),
        ("tmp", 0o700),
    ):
        d = root / sub if sub else root
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(mode)
    sock = paths.php_socket("t0001").parent
    sock.mkdir(parents=True)
    sock.chmod(0o750)
    etc = paths.tenant_etc("t0001")
    etc.mkdir(parents=True)
    (etc / "php-fpm.conf").write_text(
        "php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,"
        "pcntl_exec,pcntl_fork,pcntl_signal,posix_kill,posix_setuid,posix_setgid,dl\n"
        "php_admin_value[open_basedir] = /srv/tenants/t0001/:/tmp/\n"
        "php_admin_flag[display_errors] = off\n"
    )
    users = {
        "t0001": pwd.struct_passwd(("t0001", "x", uid, gid, "", str(root), "/usr/sbin/nologin")),
        "t0001-deploy": pwd.struct_passwd(
            ("t0001-deploy", "x", uid, gid, "", str(root), "/usr/sbin/nologin")
        ),
    }

    class Group:
        def __init__(self, members: list[str]) -> None:
            self.gr_mem = members

    groups = {"sudo": Group(["alice"]), "adm": Group([])}
    props = {k: v for k, v in UNIT_EXPECT.items()} | {
        "User": "t0001",
        "Slice": "dptenants-t0001.slice",
        "IPAddressDeny": "169.254.0.0/16 fe80::/10",
        "MemoryMax": "1073741824",
        "TasksMax": "256",
        "CPUQuotaPerSecUSec": "1s",
    }
    grants = "GRANT USAGE ON *.* TO `t0001`@`localhost` IDENTIFIED VIA unix_socket\n" + (
        "GRANT ALL PRIVILEGES ON `t0001\\_%`.* TO `t0001`@`localhost`\n"
    )
    state: dict[str, Any] = {"props": props, "grants": grants, "grants_rc": 0}

    def run(argv: list[str], **kw: Any) -> proc.Result:
        if argv[0].endswith("systemctl"):
            wanted = [a.split("=", 1)[1] for a in argv if a.startswith("--property=")]
            text = "".join(f"{k}={state['props'].get(k, '')}\n" for k in wanted)
            return proc.Result(tuple(argv), 0, text, "")
        if argv[0].endswith("mariadb"):
            return proc.Result(tuple(argv), state["grants_rc"], state["grants"], "")
        raise AssertionError(argv)

    auditor = SiteAuditor(
        paths,
        run=run,
        getpwnam=lambda n: users[n],
        getgrnam=lambda n: groups[n],
        exposure=lambda unit: 1.6,
        apparmor=lambda profile: "enforce",
    )
    facts = SiteFacts(
        tenant="t0001",
        domain="example.com",
        cert_days_left=60,
        sftp_accounts=[{"account": "a", "type": "ssh-ed25519"}],
        backup_state={"ok": True, "last_success": "2026-11-09T02:30:00"},
    )
    return {
        "auditor": auditor,
        "facts": facts,
        "root": root,
        "state": state,
        "users": users,
        "groups": groups,
        "Group": Group,
        "paths": paths,
    }


def test_site_audit_clean(site_tree: dict[str, Any]) -> None:
    rep = site_tree["auditor"].security(site_tree["facts"])
    assert rep.problems() == [], rep.lines(verbose=False)
    assert {
        "SBX-PROPERTIES",
        "FS-LAYOUT",
        "DB-GRANTS",
        "PHP-DISABLE-FUNCTIONS",
        "FILES-SETUID",
        "TLS-CERT",
        "BKP-SITE",
    } <= {f.id for f in rep.findings}


def test_site_audit_finds_problems(site_tree: dict[str, Any]) -> None:
    root, state = site_tree["root"], site_tree["state"]
    state["props"] = dict(
        state["props"],
        ProtectSystem="full",
        User="root",
        Slice="system.slice",
        IPAddressDeny="",
        MemoryMax="infinity",
    )
    state["grants"] += "GRANT SELECT ON `t0002\\_%`.* TO `t0001`@`localhost`\n"
    (root / "tmp").chmod(0o777)
    public = root / "app" / "public"
    (public / ".env").write_text("DB_PASSWORD=x")
    (public / "dump.sql.gz").write_text("x")
    suid = root / "data" / "tool"
    suid.write_text("x")
    suid.chmod(0o4755)
    ww = root / "data" / "open.txt"
    ww.write_text("x")
    ww.chmod(0o666)
    (public / "passwd").symlink_to("/etc/passwd")
    (public / "inside").symlink_to(root / "data")
    (root / "tmp" / "ignored.sql").write_text("tmp is not scanned")
    site_tree["groups"]["sudo"] = site_tree["Group"](["t0001-deploy"])
    users = site_tree["users"]
    users["t0001"] = pwd.struct_passwd(
        ("t0001", "x", users["t0001"].pw_uid, users["t0001"].pw_gid, "", str(root), "/bin/bash")
    )
    (site_tree["paths"].tenant_etc("t0001") / "php-fpm.conf").write_text(
        "php_admin_value[disable_functions] = exec\n"
    )
    facts = site_tree["facts"]
    facts.cert_days_left = 2
    facts.backup_state = {"ok": False, "error": "s3 down"}
    auditor: SiteAuditor = site_tree["auditor"]
    auditor.exposure = lambda unit: 5.2
    auditor.apparmor = lambda profile: "complain"
    rep = auditor.security(facts)
    failed = {f.id: f for f in rep.problems()}
    expected = {
        "SBX-PROPERTIES",
        "SBX-USER",
        "SBX-SLICE",
        "NET-META-UNIT",
        "SBX-EXPOSURE",
        "AA-PROFILE",
        "RES-LIMITS",
        "FS-LAYOUT",
        "DB-GRANTS",
        "PRIV-GROUPS",
        "PRIV-SHELL",
        "FILES-WORLD-WRITABLE",
        "FILES-SETUID",
        "FILES-PUBLIC-SECRETS",
        "FILES-SYMLINKS-OUT",
        "PHP-DISABLE-FUNCTIONS",
        "PHP-OPEN-BASEDIR",
        "PHP-DISPLAY-ERRORS",
        "TLS-CERT",
        "BKP-SITE",
    }
    assert expected <= set(failed), expected - set(failed)
    assert failed["TLS-CERT"].severity == "critical"
    assert "passwd -> /etc/passwd" in failed["FILES-SYMLINKS-OUT"].detail
    assert "inside" not in failed["FILES-SYMLINKS-OUT"].detail
    assert "ignored.sql" not in failed["FILES-PUBLIC-SECRETS"].detail
    assert "t0002" in failed["DB-GRANTS"].detail


def test_site_audit_edge_cases(site_tree: dict[str, Any]) -> None:
    auditor: SiteAuditor = site_tree["auditor"]
    facts: SiteFacts = site_tree["facts"]
    facts.cert_days_left = None
    facts.backup_state = None
    facts.php = False
    site_tree["state"]["grants_rc"] = 1  # no database user: nothing to check
    (site_tree["paths"].tenant_etc("t0001") / "php-fpm.conf").unlink()
    rep = auditor.security(facts)
    sev = {f.id: f.severity for f in rep.findings}
    assert sev["TLS-CERT"] == "warn" and sev["BKP-SITE"] == "warn"
    assert "DB-GRANTS" not in sev and "SBX-PROPERTIES" not in sev and "PHP-CONFIG" not in sev
    facts.php = True
    rep = auditor.security(facts)
    assert {f.id for f in rep.problems()} >= {"PHP-CONFIG"}
    broken = SiteAuditor(
        site_tree["paths"],
        run=lambda *a, **k: (_ for _ in ()).throw(OperationFailed("no systemctl")),
        getpwnam=lambda n: (_ for _ in ()).throw(KeyError(n)),
        getgrnam=lambda n: (_ for _ in ()).throw(KeyError(n)),
        exposure=lambda u: None,
        apparmor=lambda p: "not loaded",
    )
    rep = broken.isolation_audit(facts)
    assert {"SBX-UNIT", "AA-PROFILE", "FS-ACCOUNTS", "RES-LIMITS"} <= {f.id for f in rep.problems()}


# --- CLI handlers ---------------------------------------------------------------------------


def _ctx(system: dict[str, Any], domain: str | None = None) -> Any:
    from conftest import FakeProbe

    from domainpilot.cli.context import Context
    from domainpilot.core.config import Config
    from domainpilot.core.output import Output

    ctx = Context(
        paths=system["paths"],
        out=Output(stdout=io.StringIO(), stderr=io.StringIO()),
        probe=FakeProbe(system["paths"].etc),
        config=Config(),
        argv=["site"],
        domain=domain,
        use_syslog=False,
    )
    ctx._registry = system["registry"]
    return ctx


def test_security_handlers(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    mgr.create(CreateRequest("other.example.com"))
    (system["paths"].etc / "backup.json").write_text("{}")
    seen: dict[str, Any] = {}

    def fake_security(self: SiteAuditor, facts: SiteFacts) -> SecurityReport:
        seen["facts"] = facts
        rep = SecurityReport(facts.domain)
        rep.add("X", False, "x", severity="warn")
        return rep

    monkeypatch.setattr(SiteAuditor, "security", fake_security)
    monkeypatch.setattr(SiteAuditor, "isolation_audit", fake_security)
    monkeypatch.setattr(Certbot, "exists", lambda self, d: False)
    ns = argparse.Namespace(verbose_report=False)
    out = security_handlers.site_security(_ctx(system, "example.com"), ns)
    assert out.exit_code != 0 and out.disclaimer and out.data["worst"] == "warn"
    assert seen["facts"].tenant == "t0001" and seen["facts"].backup_state == {}
    security_handlers.isolation_audit(_ctx(system, "example.com"), ns)

    def fake_probe(
        self: IsolationTester, tenant: str, *, others: list[str], other_db: str = ""
    ) -> dict[str, Any]:
        seen["probe"] = (tenant, others, other_db)
        return dict(GOOD_PROBE, euid=system["registry"].get_tenant(tenant).uid)

    monkeypatch.setattr(IsolationTester, "run_probe", fake_probe)
    monkeypatch.setattr(
        db,
        "list_databases",
        lambda t, run=None: (_ for _ in ()).throw(OperationFailed("no db")),
    )
    tested = security_handlers.isolation_test(_ctx(system, "example.com"), ns)
    assert tested.exit_code == 0 and tested.data["compared_with"] == ["t0002"]
    assert seen["probe"] == ("t0001", ["t0002"], "t0002_app")

    def host_report(view: Any = None) -> SecurityReport:
        rep = SecurityReport("system")
        rep.add("A", True, "a")
        return rep

    monkeypatch.setattr(security_handlers, "audit_host", host_report)
    report = Report()
    report.add("warn", "reboot", "a reboot is required")
    monkeypatch.setattr(security_handlers, "_health_report", lambda ctx: report)
    assert security_handlers.system_audit(_ctx(system), ns).exit_code == 0
    sec = security_handlers.system_security(_ctx(system), ns)
    assert any(f["id"] == "HEALTH-REBOOT" for f in sec.data["findings"])
    assert "security-report.md" in sec.text[-1]

    mgr.create(CreateRequest("static.example.com", site_type="static"))
    with pytest.raises(PreconditionFailed, match="no PHP"):
        security_handlers.isolation_test(_ctx(system, "static.example.com"), ns)
    mgr.delete("other.example.com", purge=False)
    with pytest.raises(PreconditionFailed, match="not active"):
        security_handlers.site_security(_ctx(system, "other.example.com"), ns)


def test_scan_mode_bits_helper() -> None:
    assert ha._too_open(0o755, 0o750) and not ha._too_open(0o640, 0o750)
    assert stat.S_IMODE(0o104755) == 0o4755
