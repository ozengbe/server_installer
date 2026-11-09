"""Phase 9 acceptance: security commands on a real host + negative tests.

* `system audit`, `site <d> isolation audit|test`, `site <d> security` run
  against the live server and real sites, and must report no critical finding.
* Negative tests attack DomainPilot itself, the way a malicious tenant (T2) or
  a hostile argument would: injection and traversal through the real binary,
  symlinks planted by the tenant against root's backup/restore/purge, setuid
  uploads.

Disposable test host only (/etc/domainpilot-test-vm).
"""

from __future__ import annotations

import hashlib
import json
import pwd
import secrets
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
A, B = "p9a.example.com", "p9b.example.com"
REPO = Path("/var/backups/domainpilot-p9test")
ETC = Path("/etc/domainpilot")


def site(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([SITE, *args], input=stdin, capture_output=True, text=True, timeout=900)


def site_json(*args: str, codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    r = site("--json", *args)
    data = json.loads(r.stdout)
    assert r.returncode in codes, r.stdout + r.stderr
    result: dict[str, Any] = data["result"] if data["ok"] else data
    return result


def as_user(user: str, group: str, *argv: str) -> subprocess.CompletedProcess[str]:
    """Act as the tenant would (its own UID, no privileges)."""
    return subprocess.run(
        ["/usr/bin/setpriv", f"--reuid={user}", f"--regid={group}", "--clear-groups",
         "--no-new-privs", "--", *argv],
        capture_output=True, text=True, timeout=60,
    )  # fmt: skip


def sha(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def problems(report: dict[str, Any], severity: str = "critical") -> list[str]:
    return [
        f"{f['id']}: {f['title']} ({f['detail']})"
        for f in report["findings"]
        if f["severity"] == severity
    ]


@pytest.fixture(scope="module")
def sites(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    assert Path("/etc/domainpilot-test-vm").is_file(), "test host only"
    saved = tmp_path_factory.mktemp("saved")
    had_backup = (ETC / "backup.json").exists()
    if had_backup:
        shutil.copy2(ETC / "backup.json", saved / "backup.json")
    for d in (A, B):
        site(d, "delete", "--purge", "--confirm", d)
    tenants = {d: site_json(d, "create")["tenant"] for d in (A, B)}
    site_json(B, "db", "create")
    yield tenants
    for d in (A, B):
        site(d, "delete", "--purge", "--confirm", d)
    shutil.rmtree(REPO, ignore_errors=True)
    (ETC / "backup.json").unlink(missing_ok=True)
    if had_backup:
        shutil.copy2(saved / "backup.json", ETC / "backup.json")


# --- the security commands on the real host ------------------------------------------------


def test_system_audit_has_no_critical_findings(sites: dict[str, str]) -> None:
    report = site_json("system", "audit", codes=(0, 10, 11))
    assert report["disclaimer"].startswith("Automated checks passed for the listed controls")
    assert problems(report) == [], problems(report)
    ids = {f["id"] for f in report["findings"]}
    assert {
        "SSH-PASSWORDAUTHENTICATION",
        "FW-DEFAULT-DENY",
        "DB-NO-TCP",
        "KERN-SYSCTL",
        "PERM-SECRETS",
        "NGX-DEFAULT-444",
        "AUDIT-APPEND-ONLY",
    } <= ids
    ok = {f["id"] for f in report["findings"] if f["severity"] == "ok"}
    assert "AUDIT-APPEND-ONLY" in ok  # TH19: installer sets chattr +a


def test_site_isolation_audit_and_security(sites: dict[str, str]) -> None:
    audit = site_json(A, "isolation", "audit", codes=(0, 10))
    assert problems(audit) == [], problems(audit)
    security = site_json(A, "security", codes=(0, 10))
    assert problems(security) == [], problems(security)


def test_isolation_test_from_inside_a_live_site(sites: dict[str, str]) -> None:
    result = site_json(A, "isolation", "test", codes=(0, 10))
    assert problems(result) == [], problems(result)
    assert sites[B] in result["compared_with"]
    net = result["probe"]["net"]
    assert net["cloud_metadata"] is False and net["loopback_ssh_v6"] is False  # TH4/TH5
    assert result["probe"]["db_other_access"] is False  # TH7, against B's real database
    public = Path(f"/srv/tenants/{sites[A]}/app/public")
    assert not [p for p in public.iterdir() if p.name.startswith(".dp-probe-")]  # cleaned up


# --- negative tests: hostile input through the real binary ---------------------------------

MARK = Path("/tmp") / f"dp-pwned-{secrets.token_hex(4)}"
HOSTILE = [
    f"a.com;touch {MARK}",
    f"$(touch {MARK}).com",
    f"`touch {MARK}`.com",
    "../../etc/passwd",
    "example.com/../../x",
    "a\nb.com",
    "-rf",
    "x" * 300 + ".com",
    "ex ample.com",
]


@pytest.mark.parametrize("target", HOSTILE)
def test_hostile_domains_are_rejected(sites: dict[str, str], target: str) -> None:
    before = {p.pw_name for p in pwd.getpwall()}
    for command in (["create"], ["status"], ["backup"], ["security"]):
        r = site("--json", target, *command)
        assert r.returncode != 0, (target, command)
    assert not MARK.exists()
    assert {p.pw_name for p in pwd.getpwall()} == before  # nothing was provisioned


@pytest.mark.parametrize(
    "argv",
    [
        [A, "sftp", "create", "--key-stdin", "--name", f"x;touch {MARK}"],
        [A, "sftp", "create", "--key-stdin", "--name", "../../root"],
        [A, "sftp", "revoke", "../../etc/passwd", "--confirm", A],
        [A, "restore", "--snapshot", "../../etc", "--to-staging", "--confirm", A],
        [A, "restore", "--snapshot", f"$(touch {MARK})", "--to-staging", "--confirm", A],
        [A, "db", "create", "--name", "x`; DROP DATABASE mysql; --"],
        ["system", "backup", "setup", "--repository", f"/srv/tenants/{'t0001'}/steal"],
        ["system", "backup", "setup", "--repository", "/var/../etc/backups"],
        ["system", "backup", "setup", "--repository", f"s3:https://x.com/b;touch {MARK}"],
    ],
)
def test_hostile_option_values_are_rejected(sites: dict[str, str], argv: list[str]) -> None:
    r = site("--json", *argv, stdin="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl0aXNhdGVzdGtleQ x\n")
    assert r.returncode != 0, r.stdout
    assert not MARK.exists()
    assert (
        subprocess.run(
            ["/usr/bin/mariadb", "-NBe", "SELECT 1 FROM mysql.user LIMIT 1"], capture_output=True
        ).returncode
        == 0
    )  # the mysql schema is still there


def test_alert_url_must_be_https(sites: dict[str, str]) -> None:
    for url in ("file:///etc/shadow", "http://169.254.169.254/latest/meta-data", "gopher://x"):
        r = site("--json", "system", "alerts", "setup", "--kind", "webhook", "--url-stdin",
                 stdin=url + "\n")  # fmt: skip
        assert r.returncode != 0, url
    assert not (ETC / "alerts.json").exists() or "169.254" not in (ETC / "alerts.json").read_text()


# --- negative tests: a malicious tenant against root's operations --------------------------


def test_tenant_symlinks_never_redirect_root(sites: dict[str, str]) -> None:
    """TH8: plant symlinks, then make root back up, restore and erase the site.

    The bait is a root-only file outside the tenant tree (not /etc/shadow: purging
    a site legitimately rewrites /etc/shadow when its users are deleted).
    """
    t, other = sites[A], sites[B]
    deploy = f"{t}-deploy"
    bait = Path(f"/root/dp-p9-bait-{secrets.token_hex(4)}")
    bait.write_text(secrets.token_hex(32))
    bait.chmod(0o600)
    bait_hash = sha(str(bait))
    victim = Path(f"/srv/tenants/{other}/app/public/index.php")
    victim_hash = sha(str(victim))
    data, public = f"/srv/tenants/{t}/data", f"/srv/tenants/{t}/app/public"
    try:
        for link, target in (
            (f"{data}/bait", str(bait)),
            (f"{data}/etc", "/etc"),
            (f"{public}/neighbour", f"/srv/tenants/{other}/app/public"),
            (f"{public}/index.php.bak", str(victim)),
        ):
            user = t if link.startswith(data) else deploy
            r = as_user(user, t, "/usr/bin/ln", "-s", target, link)
            assert r.returncode == 0, r.stderr

        report = site_json(A, "security", codes=(0, 10))
        outside = next(f for f in report["findings"] if f["id"] == "FILES-SYMLINKS-OUT")
        assert outside["severity"] == "warn" and bait.name in outside["detail"]

        site_json("system", "backup", "setup", "--repository", str(REPO))
        site_json(A, "backup")
        staged = site_json(A, "restore", "--files", "--to-staging", "--confirm", A)
        copy = Path(staged["files"]["path"]) / "data" / "bait"
        assert copy.is_symlink() and copy.readlink() == bait  # stored as a link, not content
        site_json(A, "restore", "--files", "--confirm", A)
        assert Path(f"{data}/bait").is_symlink()
        assert sha(str(bait)) == bait_hash and sha(str(victim)) == victim_hash

        site_json(A, "delete", "--purge", "--confirm", A)
        assert bait.exists() and sha(str(bait)) == bait_hash  # erase never followed the link
        assert Path("/etc/passwd").exists() and Path("/etc/hostname").exists()
        assert victim.exists() and sha(str(victim)) == victim_hash  # B untouched
        assert site_json(B, "status")["tenant"]["status"] == "active"
    finally:
        bait.unlink(missing_ok=True)
        if site("--json", A, "status").returncode != 0:
            sites[A] = site_json(A, "create")["tenant"]  # fresh A for the remaining tests


def test_setuid_uploads_are_flagged_and_stripped_on_restore(sites: dict[str, str]) -> None:
    t = sites[A]
    tool = f"/srv/tenants/{t}/data/tool"
    assert as_user(t, t, "/usr/bin/cp", "/usr/bin/true", tool).returncode == 0
    assert as_user(t, t, "/usr/bin/chmod", "4755", tool).returncode == 0
    report = site_json(A, "security", codes=(10, 11))
    flagged = next(f for f in report["findings"] if f["id"] == "FILES-SETUID")
    assert flagged["severity"] == "critical" and "tool" in flagged["detail"]
    if not (ETC / "backup.json").exists():
        site_json("system", "backup", "setup", "--repository", str(REPO))
    site_json(A, "backup")
    site_json(A, "restore", "--files", "--confirm", A)
    assert not Path(tool).stat().st_mode & 0o6000  # restore never brings setuid back


def test_tenant_users_have_no_privileges(sites: dict[str, str]) -> None:
    for user in (sites[A], f"{sites[A]}-deploy"):
        entry = pwd.getpwnam(user)
        assert entry.pw_shell in ("/usr/sbin/nologin", "/bin/false")
        groups = subprocess.run(["/usr/bin/id", "-nG", user], capture_output=True, text=True)
        assert not {"sudo", "adm", "dp-admins", "root"} & set(groups.stdout.split())
    sudoers = subprocess.run(
        ["/usr/bin/grep", "-rlw", sites[A], "/etc/sudoers", "/etc/sudoers.d"],
        capture_output=True,
        text=True,
    )
    assert sudoers.stdout == ""  # no sudo rule mentions the site's users
