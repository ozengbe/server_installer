"""Phase 6b acceptance against a real Cloudflare zone (staging certificates only).

Needs DP_TEST_CF_BASE: a subdomain inside a Cloudflare zone for which a token
is stored (e.g. "dp-test.firr.net"). Only names under that base are created,
and the test proves every pre-existing record in the zone is left untouched.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

BASE = os.environ.get("DP_TEST_CF_BASE", "")
NAME = f"p6b.{BASE}"
SITE = "/usr/local/bin/site"
CONFIG = Path("/etc/domainpilot/domainpilot.toml")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not BASE, reason="DP_TEST_CF_BASE (subdomain of a Cloudflare zone) not set"),
]


def site(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([SITE, *args], capture_output=True, text=True, timeout=900)


def site_json(*args: str) -> dict[str, Any]:
    r = site("--json", *args)
    data = json.loads(r.stdout)
    assert r.returncode in (0, 10) and data["ok"], r.stdout + r.stderr
    result: dict[str, Any] = data["result"]
    return result


def zone_snapshot() -> list[tuple[str, str, str, bool, str]]:
    """Every record in the zone, read with DomainPilot's own client and token."""
    sys.path.insert(0, "/usr/lib/domainpilot")
    from domainpilot.cloudflare.creds import CredentialStore
    from domainpilot.cloudflare.manager import CloudflareManager

    mgr = CloudflareManager(CredentialStore())
    ref = mgr.zone_for(NAME)
    assert ref is not None, "no stored token reaches this zone"
    return sorted(
        (r.type, r.name, r.content, r.proxied, r.comment)
        for r in mgr.client(ref.label).records(ref.zone.id)
    )


@pytest.fixture(scope="module")
def created() -> Iterator[dict[str, Any]]:
    assert Path("/etc/domainpilot-test-vm").is_file(), "test host only"
    backup = CONFIG.read_bytes() if CONFIG.exists() else None
    CONFIG.write_text("[ssl]\nstaging = true\nautossl = true\n")
    site(NAME, "delete", "--purge", "--confirm", NAME)
    site(NAME, "repair")
    before = [r for r in zone_snapshot() if not r[1].endswith(BASE)]
    try:
        result = site_json(NAME, "create")
        result["_before"] = before
        yield result
    finally:
        site(NAME, "delete", "--purge", "--confirm", NAME)
        if backup is None:
            CONFIG.unlink(missing_ok=True)
        else:
            CONFIG.write_bytes(backup)


def test_token_is_usable() -> None:
    tokens = site_json("system", "cloudflare", "token", "list")["tokens"]
    assert any(t["status"] == "active" and t.get("zones") for t in tokens)


def test_create_adds_tagged_proxied_records(created: dict[str, Any]) -> None:
    assert created["cloudflare"].startswith("proxied through Cloudflare zone"), created
    ours = [r for r in zone_snapshot() if r[1] == NAME]
    assert {r[0] for r in ours} >= {"A"}
    for rtype, _name, _content, proxied, comment in ours:
        assert proxied and comment == f"domainpilot:{created['tenant']}", (rtype, comment)


def test_certificate_issued_via_dns01(created: dict[str, Any]) -> None:
    assert created["ssl"] == "issued", created
    st = site_json(NAME, "ssl", "status")
    assert st["challenge"] == "dns-01 (Cloudflare)" and st["certificate"]["staging"]
    assert NAME in st["certificate"]["names"]
    assert not list(Path("/run/domainpilot/cloudflare").glob("*.ini"))  # token not left in RAM


def test_origin_serves_https(created: dict[str, Any]) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection(("127.0.0.1", 443), timeout=15) as raw,
        ctx.wrap_socket(raw, server_hostname=NAME) as tls,
    ):
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {NAME}\r\nConnection: close\r\n\r\n".encode())
        reply = tls.recv(4096).decode("latin-1")
    assert reply.startswith("HTTP/1.1 200"), reply[:200]


def test_public_name_goes_through_cloudflare(created: dict[str, Any]) -> None:
    addrs = {ai[4][0] for ai in socket.getaddrinfo(NAME, 80, proto=socket.IPPROTO_TCP)}
    assert "80.241.220.98" not in addrs  # proxied: the origin IP is hidden
    conn = http.client.HTTPConnection(NAME, 80, timeout=20)
    conn.request("GET", "/")
    resp = conn.getresponse()
    assert resp.getheader("server", "").lower() == "cloudflare" and resp.getheader("cf-ray")


def test_dns_audit(created: dict[str, Any]) -> None:
    audit = site_json(NAME, "cloudflare", "dns")
    assert audit["managed"] is True
    assert all(f["severity"] == "ok" for f in audit["findings"] if f["check"] == "dns")


def test_real_ip_trusts_cloudflare_only() -> None:
    dump = subprocess.run(["/usr/sbin/nginx", "-T"], capture_output=True, text=True).stdout
    assert "real_ip_header CF-Connecting-IP;" in dump
    assert "set_real_ip_from 173.245.48.0/20;" in dump


def test_purge_removes_only_our_records(created: dict[str, Any]) -> None:
    site_json(NAME, "delete", "--purge", "--confirm", NAME)
    after = zone_snapshot()
    assert not [r for r in after if r[1] == NAME]
    assert [r for r in after if not r[1].endswith(BASE)] == created["_before"]
