"""Phase 6 acceptance: real certificates from the Let's Encrypt STAGING CA.

Needs a public DNS name that resolves to this host, given as
DP_TEST_ACME_NAME (e.g. "p6.<ip-with-dashes>.sslip.io"). Skipped otherwise
(CI runners have no public name). Always uses the staging CA.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import stat
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

NAME = os.environ.get("DP_TEST_ACME_NAME", "")
SITE = "/usr/local/bin/site"
CONFIG = Path("/etc/domainpilot/domainpilot.toml")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not NAME, reason="DP_TEST_ACME_NAME (public name for this host) not set"),
]


def site(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([SITE, *args], capture_output=True, text=True, timeout=600)


def site_json(*args: str) -> dict[str, Any]:
    r = site("--json", *args)
    data = json.loads(r.stdout)
    assert r.returncode == 0 and data["ok"], r.stdout + r.stderr
    result: dict[str, Any] = data["result"]
    return result


def tls_handshake(name: str) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # staging CA is untrusted on purpose
    with (
        socket.create_connection(("127.0.0.1", 443), timeout=15) as raw,
        ctx.wrap_socket(raw, server_hostname=name) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
        assert der is not None
        pem = ssl.DER_cert_to_PEM_cert(der)
    text = subprocess.run(
        ["/usr/bin/openssl", "x509", "-noout", "-issuer", "-ext", "subjectAltName"],
        input=pem,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {"text": text, "version": "n/a"}


def http_get(name: str, path: str = "/") -> tuple[int, dict[str, str]]:
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=15)
    conn.request("GET", path, headers={"Host": name})
    resp = conn.getresponse()
    resp.read()
    return resp.status, {k.lower(): v for k, v in resp.getheaders()}


@pytest.fixture(scope="module")
def created() -> Iterator[dict[str, Any]]:
    assert Path("/etc/domainpilot-test-vm").is_file(), "test host only"
    backup = CONFIG.read_bytes() if CONFIG.exists() else None
    CONFIG.write_text("[ssl]\nstaging = true\nautossl = true\n")  # never touch production CA
    site(NAME, "delete", "--purge", "--confirm", NAME)
    site(NAME, "repair")
    try:
        yield site_json(NAME, "create")
    finally:
        site(NAME, "delete", "--purge", "--confirm", NAME)
        if backup is None:
            CONFIG.unlink(missing_ok=True)
        else:
            CONFIG.write_bytes(backup)


class SNIHTTPSConnection(http.client.HTTPSConnection):
    """Connect to 127.0.0.1 but send the site's name in SNI."""

    def __init__(self, name: str, **kw: Any) -> None:
        super().__init__("127.0.0.1", 443, **kw)
        self._sni = name

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)  # type: ignore[attr-defined]


def https(name: str, path: str = "/") -> tuple[int, dict[str, str], str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = SNIHTTPSConnection(name, timeout=15, context=ctx)
    conn.request("GET", path, headers={"Host": name})
    resp = conn.getresponse()
    return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read().decode()


def test_autossl_issued_on_create(created: dict[str, Any]) -> None:
    assert created["ssl"] == "issued", created


def test_https_serves_staging_certificate(created: dict[str, Any]) -> None:
    cert = tls_handshake(NAME)["text"]
    assert "(STAGING)" in cert and f"DNS:{NAME}" in cert
    status, headers, body = https(NAME)
    assert status == 200 and "Site ready" in body
    assert headers.get("strict-transport-security") == "max-age=300"


def test_http_redirects_but_still_answers_acme(created: dict[str, Any]) -> None:
    status, headers = http_get(NAME, "/some/page?x=1")
    assert status == 301 and headers["location"] == f"https://{NAME}/some/page?x=1"
    token_dir = Path("/var/lib/domainpilot-acme/.well-known/acme-challenge")
    token_dir.mkdir(parents=True, exist_ok=True)
    token = token_dir / "dp-test-token"
    token.write_text("dp-test")
    try:
        assert http_get(NAME, "/.well-known/acme-challenge/dp-test-token")[0] == 200
    finally:
        token.unlink()


def test_status_and_key_protection(created: dict[str, Any]) -> None:
    st = site_json(NAME, "ssl", "status")
    cert = st["certificate"]
    assert st["https"] and st["autossl"] and cert["staging"] and cert["covers_all_names"]
    # Let's Encrypt is shortening lifetimes (90 -> ~64 -> 45 days): require a sane margin.
    assert cert["days_left"] >= 30
    key = Path(f"/etc/letsencrypt/live/{NAME}/privkey.pem").resolve()
    info = key.stat()
    assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) & 0o077 == 0


def test_renewal_infrastructure(created: dict[str, Any]) -> None:
    timer = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "certbot.timer"], capture_output=True, text=True
    )
    assert timer.stdout.strip() == "active"
    hook = Path("/etc/letsencrypt/renewal-hooks/deploy/50-domainpilot-nginx")
    assert hook.is_file() and os.access(hook, os.X_OK)


def test_forced_renewal_keeps_serving(created: dict[str, Any]) -> None:
    before = site_json(NAME, "ssl", "status")["certificate"]["not_after"]
    renewed = site_json(NAME, "ssl", "renew", "--force")
    assert renewed["days_left"] >= 30
    assert https(NAME)[0] == 200
    assert site_json(NAME, "ssl", "status")["certificate"]["not_after"] >= before


def test_revoke_returns_to_http(created: dict[str, Any]) -> None:
    assert site(NAME, "ssl", "revoke").returncode == 6  # destructive: needs --confirm
    result = site_json(NAME, "ssl", "revoke", "--confirm", NAME)
    assert result["revoked"] and result["autossl"] is False
    assert http_get(NAME)[0] == 200  # plain HTTP again
    with pytest.raises(ssl.SSLError):
        tls_handshake(NAME)  # default server rejects the handshake
    st = site_json(NAME, "ssl", "status")
    assert st["certificate"] is None and not st["https"]
