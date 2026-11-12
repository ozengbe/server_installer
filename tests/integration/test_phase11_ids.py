"""Phase 11: intrusion prevention (CrowdSec where available, fail2ban elsewhere).

Runs on whichever engine the installer chose for this host (host.toml "ids").
Uses documentation addresses (RFC 5737) only: nothing real is ever blocked.
"""

from __future__ import annotations

import json
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
HOST_TOML = Path("/etc/ozenix/host.toml")
TEST_IP = "192.0.2.77"  # TEST-NET-1
TEST_RANGE = "198.51.100.0/24"  # TEST-NET-2


def engine() -> str:
    return str(tomllib.loads(HOST_TOML.read_text())["host"].get("ids", "fail2ban"))


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=120, check=check)


def site_json(*args: str, codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    r = subprocess.run(
        [SITE, "--json", *args], capture_output=True, text=True, timeout=300, check=False
    )
    assert r.returncode in codes, r.stdout + r.stderr
    result: dict[str, Any] = json.loads(r.stdout)["result"]
    return result


def blocked() -> list[str]:
    return [b["target"] for b in site_json("system", "security", "blocks")["blocks"]]


crowdsec_only = pytest.mark.skipif(
    not HOST_TOML.exists() or engine() != "crowdsec", reason="host uses fail2ban"
)


def test_engine_matches_what_runs() -> None:
    units = ["crowdsec", "crowdsec-firewall-bouncer"] if engine() == "crowdsec" else ["fail2ban"]
    for unit in units:
        assert run("/usr/bin/systemctl", "is-active", unit).stdout.strip() == "active", unit
    other = "fail2ban" if engine() == "crowdsec" else "crowdsec"
    state = run("/usr/bin/systemctl", "is-active", other, check=False).stdout.strip()
    assert state != "active", f"{other} must not run next to {engine()}"


def test_audit_reports_ssh_protection() -> None:
    report = site_json("system", "audit", codes=(0, 10, 11))  # 10/11: warnings elsewhere
    check = next(f for f in report["findings"] if f["id"] == "IDS-SSH")
    assert check["severity"] == "ok", check


def test_manual_block_and_unblock_are_enforced_and_audited() -> None:
    assert TEST_IP not in blocked()
    site_json("system", "security", "block", TEST_IP, "--for", "5m", "--reason", "phase11 test")
    try:
        deadline = time.monotonic() + 30
        while TEST_IP not in blocked() and time.monotonic() < deadline:
            time.sleep(1)
        assert TEST_IP in blocked()
        if engine() == "crowdsec":
            # The bouncer pulls decisions every 10 s and puts them in its own nft set.
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if TEST_IP in run("/usr/sbin/nft", "list", "table", "ip", "crowdsec").stdout:
                    break
                time.sleep(2)
            assert TEST_IP in run("/usr/sbin/nft", "list", "table", "ip", "crowdsec").stdout
    finally:
        result = site_json("system", "security", "unblock", TEST_IP)
    assert result["removed"] >= 1
    assert TEST_IP not in blocked()
    log = Path("/var/log/ozenix/audit.jsonl").read_text().splitlines()[-50:]
    events = [json.loads(line).get("event") for line in log]
    assert "ids.block" in events and "ids.unblock" in events


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.0/8", "192.0.2.1; id", "--help"])
def test_dangerous_targets_refused(target: str) -> None:
    r = subprocess.run(
        [SITE, "system", "security", "block", "--", target],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode != 0
    assert target.split(";")[0] not in blocked()


def test_dry_run_changes_nothing() -> None:
    site_json("--dry-run", "system", "security", "block", TEST_IP)
    assert TEST_IP not in blocked()


@crowdsec_only
def test_crowdsec_range_block() -> None:
    site_json("system", "security", "block", TEST_RANGE, "--for", "5m")
    try:
        assert TEST_RANGE in blocked()
    finally:
        site_json("system", "security", "unblock", TEST_RANGE)
    assert TEST_RANGE not in blocked()


@crowdsec_only
def test_crowdsec_local_api_is_loopback_only() -> None:
    out = run("/usr/bin/ss", "-Hltnp").stdout
    lines = [line for line in out.splitlines() if "crowdsec" in line]
    assert lines, "crowdsec listens nowhere?"
    for line in lines:
        local = line.split()[3]
        assert local.startswith(("127.0.0.1:", "[::1]:")), line


@crowdsec_only
def test_crowdsec_shares_nothing_by_default() -> None:
    pid = run("/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "crowdsec").stdout.strip()
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    assert b"-no-capi" in cmdline


@crowdsec_only
def test_crowdsec_repository_is_pinned() -> None:
    prefs = Path("/etc/apt/preferences.d/ozenix-crowdsec").read_text()
    assert "Pin-Priority: -1" in prefs
    policy = run("/usr/bin/apt-cache", "policy", "crowdsec").stdout
    assert "packagecloud.io/crowdsec" in policy


@crowdsec_only
def test_crowdsec_parses_site_json_logs_and_detects_attacks(tmp_path: Path) -> None:
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    lines = []
    for path in ("/.env", "/.git/config", "/backup.sql", "/.aws/credentials", "/db.sql"):
        entry = {
            "time": now, "host": "probe.example.com", "remote": "203.0.113.9",
            "method": "GET", "uri": path, "status": 404, "bytes": 0, "rt": 0.001,
            "urt": "", "ua": "Mozilla/5.0", "proto": "HTTP/1.1", "tls": "",
        }  # fmt: skip
        lines.append(json.dumps(entry))
    sample = tmp_path / "access.log"
    sample.write_text("\n".join(lines) + "\n")
    out = run("/usr/bin/cscli", "explain", "--file", str(sample), "--type", "ozenix-nginx").stdout
    assert "ozenix/nginx-json-logs" in out
    assert "crowdsecurity/http-sensitive-files" in out


@crowdsec_only
def test_crowdsec_reads_every_site_log() -> None:
    # CrowdSec logs each file it starts reading; every site has an access log.
    logged = Path("/var/log/crowdsec.log").read_text(errors="replace")
    for access in Path("/var/log/nginx/ozenix").glob("*/access.log"):
        assert str(access) in logged, f"CrowdSec does not read {access}"
