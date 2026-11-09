"""Phase 5 acceptance: site lifecycle through the installed `site` command.

Runs the real CLI (/usr/local/bin/site) and checks real HTTP responses from
nginx on this host. Includes crash injection after every creation step,
each followed by `site <domain> repair`.
"""

from __future__ import annotations

import http.client
import json
import os
import pwd
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
PHP_SITE = "p5-php.example.com"
STATIC_SITE = "p5-static.example.com"
CRASH_SITE = "p5-crash.example.com"
CREATE_STEPS = [
    "preflight",
    "group",
    "runtime-user",
    "deploy-user",
    "web-server-access",
    "directories",
    "configuration",
    "apparmor",
    "database-user",
    "systemd-reload",
    "start",
    "verify",
    "starter-page",
    "web-logs",
    "vhost",
    "register",
]


def site(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [SITE, *args],
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, **(env or {})},
    )


def site_json(*args: str) -> dict[str, Any]:
    r = site("--json", *args)
    data: dict[str, Any] = json.loads(r.stdout)
    assert r.returncode == 0 and data["ok"], r.stdout + r.stderr
    result: dict[str, Any] = data["result"]
    return result


def http_get(host: str, path: str = "/") -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=15)
    try:
        conn.request("GET", path, headers={"Host": host})
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    except (http.client.RemoteDisconnected, ConnectionResetError):
        return 444, ""
    finally:
        conn.close()


def purge(domain: str) -> None:
    site(domain, "delete", "--purge", "--confirm", domain)
    site(domain, "repair")


@pytest.fixture(scope="module", autouse=True)
def clean() -> Iterator[None]:
    assert os.geteuid() == 0 and Path("/etc/domainpilot-test-vm").is_file(), "test VM only"
    for d in (PHP_SITE, STATIC_SITE, CRASH_SITE):
        purge(d)
    yield
    for d in (PHP_SITE, STATIC_SITE, CRASH_SITE):
        purge(d)


@pytest.fixture(scope="module")
def php_site() -> dict[str, Any]:
    return site_json(PHP_SITE, "create")


# --- PHP site -------------------------------------------------------------------------


def test_php_site_serves_through_its_sandbox(php_site: dict[str, Any]) -> None:
    status, body = http_get(PHP_SITE)
    assert status == 200 and "Site ready" in body
    assert http_get("unknown.example.org")[0] == 444  # default server untouched


def test_isolation_status_reports_enforcement(php_site: dict[str, Any]) -> None:
    st = site_json(PHP_SITE, "isolation", "status")
    assert st["apparmor"] == "enforce"
    assert st["sockets"] == {"php": True, "cache": True}
    for unit, score in st["exposure"].items():
        if unit != "target":
            assert score is not None and score <= st["exposure"]["target"], (unit, score)


def test_php_status_and_restart(php_site: dict[str, Any]) -> None:
    assert site_json(PHP_SITE, "php", "status")["socket"] is True
    site_json(PHP_SITE, "php", "restart")
    assert http_get(PHP_SITE)[0] == 200


def test_symlink_to_host_file_is_not_served(php_site: dict[str, Any]) -> None:
    tenant = php_site["tenant"]
    public = Path(f"/srv/tenants/{tenant}/app/public")
    link = public / "passwd.txt"
    deploy = pwd.getpwnam(f"{tenant}-deploy")
    # Planted by the deploy user (as an SFTP upload could), pointing at a root file.
    subprocess.run(
        [
            "/usr/bin/setpriv",
            f"--reuid={deploy.pw_uid}",
            f"--regid={deploy.pw_gid}",
            "--clear-groups",
            "/usr/bin/ln",
            "-s",
            "/etc/passwd",
            str(link),
        ],
        check=True,
    )
    try:
        status, body = http_get(PHP_SITE, "/passwd.txt")
        # nginx refuses the link (disable_symlinks); a PHP site then falls back to
        # its front controller (index.php), as CMSs expect. What matters: the
        # target's content is never served.
        assert "root:" not in body, (status, body[:200])
        assert status in (200, 403, 404) and ("Site ready" in body or status != 200)
    finally:
        link.unlink()


def test_sensitive_files_are_hidden(php_site: dict[str, Any]) -> None:
    for path in ("/.env", "/.git/config", "/composer.json", "/backup.sql"):
        assert http_get(PHP_SITE, path)[0] == 404, path


def test_database_lifecycle(php_site: dict[str, Any]) -> None:
    tenant = php_site["tenant"]
    assert site_json(PHP_SITE, "db", "create")["database"] == f"{tenant}_app"
    assert f"{tenant}_app" in site_json(PHP_SITE, "db", "status")["databases"]
    creds = site_json(PHP_SITE, "db", "credentials", "--show-secret")
    hidden = site_json(PHP_SITE, "db", "credentials")
    assert creds["password"] and hidden["password"] is None
    login = subprocess.run(
        [
            "/usr/bin/mariadb",
            f"--user={tenant}",
            f"--password={creds['password']}",
            "-NBe",
            "SELECT DATABASE() IS NULL",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert login.returncode == 0, login.stderr
    rotated = site_json(PHP_SITE, "db", "credentials", "--rotate", "--show-secret")
    assert rotated["password"] != creds["password"]


def test_disable_and_enable(php_site: dict[str, Any]) -> None:
    site_json(PHP_SITE, "disable")
    status, _ = http_get(PHP_SITE)
    assert status == 503
    site_json(PHP_SITE, "enable")
    assert http_get(PHP_SITE)[0] == 200


def test_access_log(php_site: dict[str, Any]) -> None:
    http_get(PHP_SITE, "/?logged=1")
    lines = site_json(PHP_SITE, "logs", "--lines", "20")["lines"]
    assert any("logged=1" in line for line in lines)


# --- static site ------------------------------------------------------------------------


def test_static_site() -> None:
    created = site_json(STATIC_SITE, "create", "--type", "static")
    assert created["type"] == "static"
    status, body = http_get(STATIC_SITE)
    assert status == 200 and "Site ready" in body
    assert http_get(STATIC_SITE, "/index.php")[0] == 404
    units = subprocess.run(
        ["/usr/bin/systemctl", "is-active", f"dp-php@{created['tenant']}"],
        capture_output=True,
        text=True,
    )
    assert units.stdout.strip() != "active"  # no PHP runtime for static sites


# --- deletion ---------------------------------------------------------------------------


def test_delete_requires_confirmation_then_archives_then_purges(php_site: dict[str, Any]) -> None:
    tenant = php_site["tenant"]
    refused = site(PHP_SITE, "delete")
    assert refused.returncode == 6  # confirmation required (stdin is not a TTY)
    assert http_get(PHP_SITE)[0] == 200

    archived = site_json(PHP_SITE, "delete", "--confirm", PHP_SITE)
    assert archived["purge"] is False
    assert http_get(PHP_SITE)[0] == 444  # no longer served
    assert Path(f"/srv/tenants/{tenant}/app/public/index.php").exists()  # data kept

    purged = site_json(PHP_SITE, "delete", "--purge", "--confirm", PHP_SITE)
    assert purged["problems"] == []
    assert not Path(f"/srv/tenants/{tenant}").exists()
    with pytest.raises(KeyError):
        pwd.getpwnam(tenant)


# --- crash injection ----------------------------------------------------------------------


def _assert_no_trace(domain: str) -> None:
    listing = site_json("list")["sites"]
    assert all(s["domain"] != domain for s in listing)
    assert not Path(f"/etc/nginx/domainpilot/sites/{domain}.conf").exists()
    users = {p.pw_name for p in pwd.getpwall()}
    tenants = {u for u in users if u.startswith("t") and u[1:5].isdigit()}
    live = subprocess.run(
        ["/usr/bin/systemctl", "list-units", "dp-*", "--no-legend", "--plain"],
        capture_output=True,
        text=True,
    ).stdout
    # Only tenants of other (still existing) sites may remain.
    for line in live.splitlines():
        unit = line.split()[0]
        if not unit.startswith(("dp-php@", "dp-cache@")):
            continue  # host units (dp-monitor, dp-backup, dp-alert@<unit>) are not tenants'
        owner = unit.split("@")[1].split(".")[0]
        assert owner in tenants, f"orphan unit {unit}"


@pytest.mark.parametrize("step", CREATE_STEPS)
def test_crash_after_each_step_is_repairable(step: str) -> None:
    crashed = site(CRASH_SITE, "create", env={"DP_TEST_CRASH_AFTER_STEP": step})
    assert crashed.returncode == 137, (step, crashed.stdout, crashed.stderr)
    blocked = site(CRASH_SITE, "create")
    assert blocked.returncode == 5 and "repair" in blocked.stderr  # refuses until repaired
    repaired = site("--json", CRASH_SITE, "repair")
    assert repaired.returncode == 0, repaired.stdout + repaired.stderr
    _assert_no_trace(CRASH_SITE)


def test_create_works_after_crash_recoveries() -> None:
    site_json(CRASH_SITE, "create")
    assert http_get(CRASH_SITE)[0] == 200
    purge(CRASH_SITE)
    _assert_no_trace(CRASH_SITE)
