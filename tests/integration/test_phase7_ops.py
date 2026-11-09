"""Phase 7 acceptance: tuning with byte-exact rollback, health, updates."""

from __future__ import annotations

import hashlib
import http.client
import json
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
DOMAIN = "p7.example.com"
TUNING = [
    Path("/etc/nginx/domainpilot/tuning-events.conf"),
    Path("/etc/nginx/domainpilot/tuning-http.conf"),
    Path("/etc/mysql/mariadb.conf.d/98-domainpilot-tuning.cnf"),
]


def site(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([SITE, *args], capture_output=True, text=True, timeout=900)


def site_json(*args: str, codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    r = site("--json", *args)
    data = json.loads(r.stdout)
    assert r.returncode in codes and data["ok"], r.stdout + r.stderr
    result: dict[str, Any] = data["result"]
    return result


def digest(paths: list[Path]) -> dict[str, str | None]:
    return {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None for p in paths
    }


def mariadb(sql: str) -> list[str]:
    out = subprocess.run(
        ["/usr/bin/mariadb", "-NBe", sql], capture_output=True, text=True, check=True
    ).stdout
    return out.split()


def http_get(path: str = "/") -> int:
    """Status code; 444 = nginx closed the connection without answering (default vhost)."""
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=15)
    try:
        conn.request("GET", path, headers={"Host": DOMAIN})
        return conn.getresponse().status
    except (http.client.RemoteDisconnected, ConnectionResetError):
        return 444
    finally:
        conn.close()


@pytest.fixture(scope="module", autouse=True)
def clean() -> Iterator[None]:
    assert Path("/etc/domainpilot-test-vm").is_file(), "test host only"
    site(DOMAIN, "delete", "--purge", "--confirm", DOMAIN)
    yield
    site(DOMAIN, "delete", "--purge", "--confirm", DOMAIN)


# --- server tuning ----------------------------------------------------------------------


def test_server_optimize_apply_and_byte_exact_rollback() -> None:
    before = digest(TUNING)
    live_before = mariadb("SELECT @@max_connections, @@innodb_buffer_pool_size")
    uptime_before = int(mariadb("SHOW GLOBAL STATUS LIKE 'Uptime'")[1])

    analysis = site_json("system", "optimize", "--analyze")
    assert analysis["profile"] in ("medium", "large", "dedicated") and not analysis["applied"]
    assert digest(TUNING) == before  # analysis changes nothing

    applied = site_json("system", "optimize", "--apply")
    rec = applied["recommended"]
    assert applied["applied"] and applied["snapshot"]
    try:
        dump = subprocess.run(["/usr/sbin/nginx", "-T"], capture_output=True, text=True).stdout
        assert f"worker_connections {rec['nginx_worker_connections']};" in dump
        live = mariadb("SELECT @@max_connections, @@innodb_buffer_pool_size")
        assert int(live[0]) == rec["mariadb_max_connections"]
        # Applied live, not just written (capped at innodb_buffer_pool_size_max).
        assert int(live[1]) == rec["mariadb_buffer_pool_mb"] * 1024 * 1024
        assert http_get() in (200, 444)  # nginx still serving after reload
        history = site_json("system", "optimize", "--history")["snapshots"]
        assert history[0]["id"] == applied["snapshot"]
    finally:
        site_json("system", "optimize", "--rollback", applied["snapshot"])
    assert digest(TUNING) == before  # byte-identical
    assert mariadb("SELECT @@max_connections, @@innodb_buffer_pool_size") == live_before
    uptime_after = int(mariadb("SHOW GLOBAL STATUS LIKE 'Uptime'")[1])
    assert uptime_after >= uptime_before  # MariaDB was never restarted


def test_optimize_is_idempotent() -> None:
    first = site_json("system", "optimize", "--apply")
    try:
        assert first["applied"] and first["snapshot"]
        second = site_json("system", "optimize", "--apply")
        assert second["changes"] == [] and not second["applied"] and second["snapshot"] is None
    finally:
        if first["snapshot"]:
            site_json("system", "optimize", "--rollback", first["snapshot"])


# --- per-site tuning and PHP --------------------------------------------------------------


def test_site_optimize_and_rollback() -> None:
    created = site_json(DOMAIN, "create")
    conf = Path(f"/etc/domainpilot/tenants/{created['tenant']}/php-fpm.conf")
    for _ in range(5):  # give the pool something to measure
        assert http_get() == 200
    before = conf.read_bytes()
    plan = site_json(DOMAIN, "optimize")
    assert "php_max_children" in plan["recommended"]
    if plan["changed"]:
        applied = site_json(DOMAIN, "optimize", "--apply")
        unit = f"dp-php@{created['tenant']}.service"
        try:
            text = conf.read_text()
            assert f"pm.max_children = {plan['recommended']['php_max_children']}" in text
            assert http_get() == 200
            # Still running a moment later (a failed re-exec would exit just after).
            subprocess.run(["/usr/bin/sleep", "2"], check=True)
            active = subprocess.run(["/usr/bin/systemctl", "is-active", unit], capture_output=True)
            assert active.returncode == 0 and http_get() == 200
        finally:
            site_json(DOMAIN, "optimize", "--rollback", applied["snapshot"])
        assert conf.read_bytes() == before
        assert http_get() == 200


def test_php_switch_guards() -> None:
    status = site_json(DOMAIN, "php", "status")
    current = status["php_version"]
    same = site_json(DOMAIN, "php", current)
    assert same["changed"] is False
    missing = site("--json", DOMAIN, "php", "8.1")
    assert missing.returncode == 5 and "not installed" in missing.stdout


# --- health & updates ---------------------------------------------------------------------


def test_system_health() -> None:
    r = site("--json", "system", "health")
    data = json.loads(r.stdout)
    assert r.returncode in (0, 10, 11) and data["ok"]
    checks = {c["check"] for c in data["result"]["checks"]}
    assert {"service", "nginx", "firewall", "disk", "memory"} <= checks
    services = {c["message"] for c in data["result"]["checks"] if c["check"] == "service"}
    assert "nginx is active" in services and "mariadb is active" in services


def test_update_check_and_history() -> None:
    checked = site_json("system", "update", "--check")
    assert {"pending", "security", "major"} <= set(checked)
    assert all({"name", "old", "new", "security", "major"} <= set(p) for p in checked["pending"])
    history = site_json("system", "update", "--history")["history"]
    assert isinstance(history, list)
