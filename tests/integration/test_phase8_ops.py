"""Phase 8 acceptance: backups + restore drill, chrooted SFTP, bounded recovery + alerts.

Runs only on a disposable test host (/etc/ozenix-test-vm). Backups go to a
local restic repository (stand-in for the S3 bucket); any backup/alert
configuration that existed before is put back afterwards.
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import pwd
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
DOMAIN = "p8.example.com"
REPO = Path("/var/backups/ozenix-p8test")
ETC = Path("/etc/ozenix")
SAVED = [ETC / "backup.json", ETC / "alerts.json"]
SECRET_DIRS = [ETC / "secrets" / "backup", ETC / "secrets" / "alerts"]


def site(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([SITE, *args], input=stdin, capture_output=True, text=True, timeout=1800)


def site_json(*args: str, stdin: str | None = None) -> dict[str, Any]:
    for _ in range(3):  # a background dp-monitor run may hold the job lock briefly
        r = site("--json", *args, stdin=stdin)
        data = json.loads(r.stdout)
        if r.returncode == 0 or "holds" not in r.stdout:
            break
        time.sleep(5)
    assert r.returncode == 0 and data["ok"], r.stdout + r.stderr
    result: dict[str, Any] = data["result"]
    return result


def sh(*args: str, timeout: float = 60, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=check)


def mariadb(sql: str) -> str:
    return sh("/usr/bin/mariadb", "-NBe", sql).stdout.strip()


def http_get(path: str = "/") -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=15)
    try:
        conn.request("GET", path, headers={"Host": DOMAIN})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


@pytest.fixture(scope="module", autouse=True)
def environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    assert Path("/etc/ozenix-test-vm").is_file(), "test host only"
    keep = tmp_path_factory.mktemp("saved")
    for path in SAVED:
        if path.exists():
            shutil.copy2(path, keep / path.name)
    for directory in SECRET_DIRS:
        if directory.exists():
            shutil.copytree(directory, keep / directory.name)
    site(DOMAIN, "delete", "--purge", "--confirm", DOMAIN)
    shutil.rmtree(REPO, ignore_errors=True)
    created = site_json(DOMAIN, "create")
    tenant = created["tenant"]
    site_json(DOMAIN, "db", "create")
    yield {"tenant": tenant, "work": tmp_path_factory.mktemp("work")}
    site(DOMAIN, "delete", "--purge", "--confirm", DOMAIN)
    shutil.rmtree(REPO, ignore_errors=True)
    for path in SAVED:
        path.unlink(missing_ok=True)
        if (keep / path.name).exists():
            shutil.copy2(keep / path.name, path)
    for directory in SECRET_DIRS:
        shutil.rmtree(directory, ignore_errors=True)
        if (keep / directory.name).exists():
            shutil.copytree(keep / directory.name, directory)
    Path("/var/lib/ozenix/backup/state.json").unlink(missing_ok=True)


def write_app(tenant: str, name: str, content: str) -> Path:
    deploy = pwd.getpwnam(f"{tenant}-deploy")
    target = Path(f"/srv/tenants/{tenant}/app/public/{name}")
    target.write_text(content)
    os.chown(target, deploy.pw_uid, deploy.pw_gid)
    target.chmod(0o640)
    return target


# --- backups ----------------------------------------------------------------------------


def test_backup_and_restore_roundtrip(environment: dict[str, Any]) -> None:
    tenant = environment["tenant"]
    db = f"{tenant}_app"
    setup = site_json("system", "backup", "setup", "--repository", str(REPO))
    assert setup["repository"] == str(REPO)
    write_app(tenant, "index.php", "<?php echo 'version-1';")
    mariadb(f"CREATE TABLE {db}.t (x INT); INSERT INTO {db}.t VALUES (42);")  # noqa: S608

    backed = site_json(DOMAIN, "backup")
    assert backed["files"] and db in backed["databases"]
    kinds = {s["kind"] for s in site_json(DOMAIN, "backup", "list")["snapshots"]}
    assert kinds == {"files", "db"}
    repo = REPO / tenant
    assert repo.is_dir() and repo.stat().st_mode & 0o007 == 0  # not readable by others

    # Damage both, then restore to staging first: nothing live may change.
    write_app(tenant, "index.php", "<?php echo 'defaced';")
    mariadb(f"DROP TABLE {db}.t")
    staged = site_json(DOMAIN, "restore", "--all", "--to-staging", "--confirm", DOMAIN)
    assert "version-1" in Path(staged["files"]["path"], "app", "public", "index.php").read_text()
    assert "defaced" in Path(f"/srv/tenants/{tenant}/app/public/index.php").read_text()

    restored = site_json(DOMAIN, "restore", "--all", "--confirm", DOMAIN)
    assert restored["databases"][db]["safety_snapshot"]  # pre-restore copy was taken
    assert http_get() == (200, "version-1")
    assert mariadb(f"SELECT x FROM {db}.t") == "42"  # noqa: S608
    index = Path(f"/srv/tenants/{tenant}/app/public/index.php")
    assert pwd.getpwuid(index.stat().st_uid).pw_name == f"{tenant}-deploy"  # owner kept

    # Server configuration backup + whole-server run.
    everything = site_json("system", "backup")
    assert everything["failed"] == [] and everything["system"]["snapshot"]


def test_verify_and_scheduled_restore_drill(environment: dict[str, Any]) -> None:
    assert site_json("system", "backup", "--verify")["ok"]
    drill = site_json("system", "backup", "--test-restore")
    assert drill["ok"] and drill["sites"][environment["tenant"]]["ok"]
    for timer in ("dp-backup.timer", "dp-backup-drill.timer"):
        assert sh("/usr/bin/systemctl", "is-enabled", timer).stdout.strip() == "enabled"
    # The scheduled drill itself, exactly as the timer runs it.
    sh("/usr/bin/systemctl", "start", "dp-backup-drill.service", timeout=1800)
    result = sh(
        "/usr/bin/systemctl", "show", "dp-backup-drill.service", "-p", "Result", "--value"
    ).stdout.strip()
    assert result == "success"
    status = site_json("system", "backup", "--status")
    assert status["state"]["test_restore"]["ok"] is True


# --- SFTP -------------------------------------------------------------------------------


def sftp(
    env: dict[str, Any], commands: str, timeout: float = 60
) -> subprocess.CompletedProcess[str]:
    batch = env["work"] / "batch"
    batch.write_text(commands)
    return sh(
        "/usr/bin/sftp",
        "-i", str(env["work"] / "key"),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-b", str(batch),
        f"{env['tenant']}-deploy@127.0.0.1",
        timeout=timeout,
        check=False,
    )  # fmt: skip


def ssh(env: dict[str, Any], *args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return sh(
        "/usr/bin/ssh",
        "-i", str(env["work"] / "key"),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        *args,
        f"{env['tenant']}-deploy@127.0.0.1",
        timeout=timeout,
        check=False,
    )  # fmt: skip


def run_as_site_user(env: dict[str, Any], command: str) -> subprocess.CompletedProcess[str]:
    return sh(
        "/usr/bin/ssh",
        "-i", str(env["work"] / "key"),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        f"{env['tenant']}-deploy@127.0.0.1",
        command,
        timeout=30,
        check=False,
    )  # fmt: skip


def test_site_user_ssh_sftp_and_escapes(environment: dict[str, Any]) -> None:
    """CloudPanel-style site user: SSH key login with SFTP and a shell in its own
    site; other sites and host secrets stay unreachable; no tunnels."""
    env, tenant = environment, environment["tenant"]
    key = env["work"] / "key"
    sh("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    made = site_json(DOMAIN, "sftp", "create", "--key", f"{key}.pub", "--name", "tester")
    assert made["username"] == f"{tenant}-deploy"

    local = env["work"] / "up.txt"
    local.write_text("uploaded over sftp\n")
    ok = sftp(env, f"put {local} app/public/up.txt\nls -1\n")
    assert ok.returncode == 0, ok.stderr
    uploaded = Path(f"/srv/tenants/{tenant}/app/public/up.txt")
    assert pwd.getpwuid(uploaded.stat().st_uid).pw_name == f"{tenant}-deploy"
    assert http_get("/up.txt") == (200, "uploaded over sftp\n")

    # A shell, as the site user, in the site.
    who = run_as_site_user(env, "id -un; pwd")
    assert who.returncode == 0, who.stderr
    assert who.stdout.split() == [f"{tenant}-deploy", f"/srv/tenants/{tenant}"]

    # Escapes: host secrets, the list of sites and other sites' files stay closed.
    for attempt in (
        "cat /etc/shadow",
        "ls /srv/tenants",
        "ls /etc/ozenix/secrets",
        "cat /var/lib/ozenix/registry.sqlite3",
        "ls /root",
    ):
        r = run_as_site_user(env, attempt)
        assert r.returncode != 0, f"{attempt!r} should fail: {r.stdout[:200]}"
    other = sorted(p.name for p in Path("/srv/tenants").iterdir() if p.name != tenant)
    if other and other[0].startswith("t"):
        r = run_as_site_user(env, f"ls /srv/tenants/{other[0]}")
        assert r.returncode != 0, "another site's files are readable"
    assert run_as_site_user(env, "touch ~/.ssh_test").returncode != 0  # home is root-owned
    # The site egress policy applies to site users too: no loopback services,
    # no cloud metadata (the shell is not a way around the firewall).
    for target in ("127.0.0.1', 9100", "169.254.169.254', 80"):
        probe = run_as_site_user(
            env,
            'python3 -c "import socket; s=socket.socket(); s.settimeout(3); '
            f"s.connect(('{target}))\"",
        )
        assert probe.returncode != 0, f"site user reached {target}"
    assert run_as_site_user(env, "crontab -l 2>&1 | grep -qi 'not allowed'").returncode == 0
    # A symlink to a system file inside the site: nginx refuses to serve it.
    assert run_as_site_user(env, "ln -s /etc/passwd app/public/leak.txt").returncode == 0
    status, body = http_get("/leak.txt")
    assert "root:" not in body, (status, body[:200])
    # No forwarding of any kind.
    forward = ssh(env, "-N", "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:19999:127.0.0.1:22")
    assert forward.returncode != 0

    listed = site_json(DOMAIN, "sftp", "list")["accounts"]
    assert [a["account"] for a in listed] == ["tester"]
    site_json(DOMAIN, "sftp", "revoke", "tester", "--confirm", DOMAIN)
    assert run_as_site_user(env, "true").returncode != 0  # revoked: login refused


# --- monitoring -------------------------------------------------------------------------


@pytest.fixture
def receiver() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(json.loads(body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_a: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/hook", received
    server.shutdown()


def nrestarts(unit: str) -> int:
    return int(sh("/usr/bin/systemctl", "show", unit, "-p", "NRestarts", "--value").stdout)


def wait_for(predicate: Any, timeout: float = 60) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(1)
    return False


def test_killed_service_recovers_and_alerts(
    environment: dict[str, Any], receiver: tuple[str, list[dict[str, Any]]]
) -> None:
    url, received = receiver
    site_json("system", "alerts", "setup", "--kind", "webhook", "--url-stdin", stdin=url + "\n")
    site_json("system", "alerts", "test")
    assert wait_for(lambda: any(a["state"] == "test" for a in received), 10)
    site_json("system", "monitor", "--notify")  # baseline restart counters

    before = nrestarts("nginx.service")
    sh("/usr/bin/systemctl", "kill", "--signal=SIGKILL", "nginx.service")
    assert wait_for(lambda: nrestarts("nginx.service") > before, 60), "nginx was not restarted"
    assert wait_for(
        lambda: sh("/usr/bin/systemctl", "is-active", "nginx", check=False).stdout.strip()
        == "active",
        30,
    )
    assert wait_for(lambda: http_get()[0] == 200, 30)  # serving again by itself

    site_json("system", "monitor", "--notify")
    assert wait_for(lambda: any(a["key"] == "crash:nginx.service" for a in received), 10), received

    # Bounded: limited restarts, then OnFailure -> dp-alert@ (exercised directly).
    show = sh(
        "/usr/bin/systemctl", "show", "nginx", "-p", "StartLimitBurst", "-p", "OnFailure"
    ).stdout
    assert "StartLimitBurst=5" in show and "dp-alert@nginx.service" in show
    sh("/usr/bin/systemctl", "start", "dp-alert@dp-test-unit.service", timeout=120)
    assert wait_for(lambda: any(a["key"] == "failed:dp-test-unit" for a in received), 10)
    site_json("system", "alerts", "remove", "--confirm", "system")


def test_monitor_timer_exporter_and_logs() -> None:
    assert sh("/usr/bin/systemctl", "is-active", "dp-monitor.timer").stdout.strip() == "active"
    listening = sh("/usr/bin/ss", "-ltnH", "sport = :9100").stdout.split("\n")
    addresses = [line.split()[3] for line in listening if line.strip()]
    assert addresses and all(a.startswith(("127.0.0.1:", "[::1]:")) for a in addresses)
    events = site_json("system", "logs", "--audit", "-n", "20")["events"]
    assert any(e.get("event", "").startswith("backup.") for e in events)
