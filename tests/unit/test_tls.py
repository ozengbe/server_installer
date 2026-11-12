from __future__ import annotations

import argparse
import io
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ozenix.cli import tls_handlers
from ozenix.core import proc
from ozenix.core.config import Config, load
from ozenix.core.errors import (
    NotImplementedYet,
    OperationFailed,
    PreconditionFailed,
    ValidationError,
)
from ozenix.core.output import Output
from ozenix.core.paths import Paths
from ozenix.tls import dns
from ozenix.tls.acme import Certbot, CertInfo, parse_x509_text, validate_email
from ozenix.web.nginx import Nginx, TlsFiles

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)

X509_PROD = """notAfter=Feb  7 11:00:00 2027 GMT
issuer=C=US, O=Let's Encrypt, CN=E6
X509v3 Subject Alternative Name:
    DNS:example.com, DNS:www.example.com
"""
X509_STAGING = X509_PROD.replace(
    "O=Let's Encrypt, CN=E6", "O=(STAGING) Let's Encrypt, CN=(STAGING) Ersatz Edamame E1"
)


# --- parsing ---------------------------------------------------------------------


def test_parse_x509() -> None:
    info = parse_x509_text(X509_PROD, NOW)
    assert info.names == ("example.com", "www.example.com")
    assert info.not_after == datetime(2027, 2, 7, 11, 0, tzinfo=UTC)
    assert info.days_left == 89 and not info.staging
    assert parse_x509_text(X509_STAGING, NOW).staging


def test_parse_x509_garbage() -> None:
    with pytest.raises(OperationFailed):
        parse_x509_text("nonsense", NOW)


@pytest.mark.parametrize("bad", ["x", "a@b", "a b@example.com", "x@example.com\n"])
def test_validate_email(bad: str) -> None:
    assert validate_email("ops@example.com") == "ops@example.com"
    with pytest.raises(OperationFailed):
        validate_email(bad)


# --- certbot wrapper ----------------------------------------------------------------


class FakeCA:
    """Records certbot/openssl calls and fakes their effect on the live dir."""

    def __init__(self, live: Path) -> None:
        self.live = live
        self.calls: list[list[str]] = []
        self.issuer_staging = False
        self.not_after = "Feb  7 11:00:00 2027 GMT"
        self.key_matches = True
        self.names: list[str] = []
        self.fail_issue = False

    def write(self, domain: str, names: list[str]) -> None:
        d = self.live / domain
        d.mkdir(parents=True, exist_ok=True)
        for f in ("cert.pem", "fullchain.pem", "privkey.pem"):
            (d / f).write_text(f"{f}\n")
        (d / "privkey.pem").chmod(0o600)
        self.names = names

    def __call__(self, argv: list[str], **_kw: Any) -> proc.Result:
        self.calls.append(list(argv))
        out = ""
        if argv[0] == "/usr/bin/certbot":
            if argv[1] == "certonly":
                if self.fail_issue:
                    raise OperationFailed("certbot exited with status 1: Challenge failed")
                names = [argv[i + 1] for i, a in enumerate(argv) if a == "-d"]
                self.issuer_staging = "--staging" in argv
                self.write(argv[argv.index("--cert-name") + 1], names)
            elif argv[1] in ("revoke", "delete"):
                d = self.live / argv[argv.index("--cert-name") + 1]
                for f in d.glob("*"):
                    f.unlink()
                d.rmdir()
        elif argv[:2] == ["/usr/bin/openssl", "x509"] and "-enddate" in argv:
            issuer = "O=(STAGING) Let's Encrypt" if self.issuer_staging else "O=Let's Encrypt"
            sans = ", ".join(f"DNS:{n}" for n in self.names)
            out = f"notAfter={self.not_after}\nissuer=C=US, {issuer}\nX509v3 SAN:\n    {sans}\n"
        elif argv[:2] == ["/usr/bin/openssl", "x509"]:
            out = "PUBKEY-A\n"
        elif argv[:2] == ["/usr/bin/openssl", "pkey"]:
            out = "PUBKEY-A\n" if self.key_matches else "PUBKEY-B\n"
        elif argv[0] == "/usr/sbin/ip":
            out = json.dumps(
                [
                    {
                        "addr_info": [
                            {
                                "scope": "global",
                                "local": "203.0.113.10",
                            },  # documentation range: not global
                            {"scope": "global", "local": "80.241.220.98"},
                            {"scope": "host", "local": "127.0.0.1"},
                        ]
                    }
                ]
            )
        return proc.Result(tuple(argv), 0, out, "")


@pytest.fixture
def ca(tmp_path: Path) -> FakeCA:
    return FakeCA(tmp_path / "live")


def certbot(ca: FakeCA) -> Certbot:
    return Certbot(run=ca, live=ca.live, now=lambda: NOW)


def test_issue_argv(ca: FakeCA) -> None:
    cb = certbot(ca)
    cb.issue("example.com", ["example.com", "www.example.com"], staging=True, email=None)
    argv = ca.calls[-1]
    assert argv[:2] == ["/usr/bin/certbot", "certonly"]
    assert "--webroot" in argv and "--register-unsafely-without-email" in argv
    assert "--staging" in argv and "--force-renewal" not in argv
    assert argv.count("-d") == 2 and "ecdsa" in argv
    # Switching staging -> production forces a fresh certificate.
    cb.issue("example.com", ["example.com"], staging=False, email="ops@example.com")
    argv = ca.calls[-1]
    assert "--email" in argv and "--force-renewal" in argv and "--staging" not in argv


def test_info_verify_renew_revoke(ca: FakeCA) -> None:
    cb = certbot(ca)
    assert cb.info("example.com") is None
    cb.issue("example.com", ["example.com"], staging=True, email=None)
    info = cb.verify("example.com", ["example.com"])
    assert isinstance(info, CertInfo) and info.staging and info.days_left == 89
    cb.renew("example.com", force=True)
    assert "--force-renewal" in ca.calls[-1] and "--no-random-sleep-on-renew" in ca.calls[-1]
    cb.revoke("example.com")
    assert "--staging" in ca.calls[-1] and not cb.exists("example.com")
    cb.delete("example.com")  # nothing left: no call
    assert ca.calls[-1][1] == "revoke"


def test_verify_failures(ca: FakeCA) -> None:
    cb = certbot(ca)
    with pytest.raises(OperationFailed, match="no certificate"):
        cb.verify("example.com", ["example.com"])
    cb.issue("example.com", ["example.com"], staging=False, email=None)
    with pytest.raises(OperationFailed, match="does not cover"):
        cb.verify("example.com", ["example.com", "www.example.com"])
    ca.key_matches = False
    with pytest.raises(OperationFailed, match="do not match"):
        cb.verify("example.com", ["example.com"])
    ca.key_matches = True
    ca.not_after = "Nov  1 00:00:00 2026 GMT"
    with pytest.raises(OperationFailed, match="expired"):
        cb.verify("example.com", ["example.com"])
    ca.not_after = "Feb  7 11:00:00 2027 GMT"
    (ca.live / "example.com" / "privkey.pem").chmod(0o644)
    if os.geteuid() == 0:
        with pytest.raises(OperationFailed, match="readable by non-root"):
            cb.verify("example.com", ["example.com"])


# --- DNS eligibility -------------------------------------------------------------


def test_host_addresses(ca: FakeCA) -> None:
    assert dns.host_addresses(ca) == {"80.241.220.98"}

    def broken(*_a: Any, **_k: Any) -> proc.Result:
        raise OperationFailed("no ip")

    assert dns.host_addresses(broken) == set()


def test_dns_problems() -> None:
    host = {"80.241.220.98", "2a02:c207::1"}
    table = {
        "ok.example.com": {"80.241.220.98"},
        "v6.example.com": {"80.241.220.98", "2a02:c207::1"},
        "stale.example.com": {"80.241.220.98", "2001:db8::5"},
        "none.example.com": set(),
    }
    assert dns.problems(["ok.example.com", "v6.example.com"], host, table.__getitem__) == []
    out = dns.problems(["stale.example.com", "none.example.com"], host, table.__getitem__)
    assert "2001:db8::5" in out[0] and "does not resolve" in out[1]
    assert dns.problems(["ok.example.com"], set(), table.__getitem__)[0].startswith("this server")
    assert dns.resolve("nonexistent.invalid") == set()


# --- HTTPS vhost ------------------------------------------------------------------


def test_render_https(tmp_path: Path) -> None:
    nginx = Nginx(Paths.under(tmp_path))
    tls = TlsFiles(
        Path("/etc/letsencrypt/live/example.com/fullchain.pem"),
        Path("/etc/letsencrypt/live/example.com/privkey.pem"),
    )
    out = nginx.render(
        "static", domain="example.com", aliases=[], tenant="t0001", tls=tls, hsts_max_age=300
    )
    assert "listen 443 ssl;" in out and "http2 on;" in out
    assert "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;" in out
    assert "return 301 https://$host$request_uri;" in out
    assert out.count("snippets/acme.conf") == 1  # only on the port-80 server
    assert out.count('Strict-Transport-Security "max-age=300"') == 2  # server + assets location
    http = nginx.render("static", domain="example.com", aliases=[], tenant="t0001")
    assert "Strict-Transport-Security" not in http and "snippets/acme.conf" in http
    assert "listen 443" not in http
    with pytest.raises(ValidationError):
        nginx.render(
            "php", domain="example.com", aliases=[], tenant="t0001", tls=tls, hsts_max_age=-1
        )
    off = nginx.render(
        "php", domain="example.com", aliases=[], tenant="t0001", tls=tls, hsts_max_age=0
    )
    assert "Strict-Transport-Security" not in off


# --- config ------------------------------------------------------------------------


def test_ssl_config(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text('[ssl]\nautossl = false\nstaging = true\nemail = "ops@example.com"\n')
    cfg = load(f)
    assert (cfg.autossl, cfg.ssl_staging, cfg.ssl_email) == (False, True, "ops@example.com")
    f.write_text('[ssl]\nemail = "nope"\n')
    with pytest.raises(ValidationError):
        load(f)
    f.write_text("[ssl]\nstaging = 1\n")
    with pytest.raises(ValidationError):
        load(f)


# --- lifecycle with certificates ------------------------------------------------------------


@pytest.fixture
def tls_system(system: dict[str, Any], ca: FakeCA) -> dict[str, Any]:
    from ozenix.sites.lifecycle import SiteManager

    resolver_table: dict[str, set[str]] = {}
    base = system["manager"]

    def manager(dry_run: bool = False, autossl: bool = True) -> SiteManager:
        m: SiteManager = base(dry_run)
        m.config = Config(autossl=autossl, ssl_staging=True)
        m.certbot = certbot(ca)
        m.host_ips = lambda: {"80.241.220.98"}
        m.resolver = lambda name: resolver_table.get(name, set())
        return m

    system["tls_manager"] = manager
    system["dns"] = resolver_table
    system["ca"] = ca
    return system


def test_create_with_autossl_when_dns_ready(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    tls_system["dns"].update(
        {"example.com": {"80.241.220.98"}, "www.example.com": {"80.241.220.98"}}
    )
    result = tls_system["tls_manager"]().create(
        CreateRequest("example.com", aliases=["www.example.com"])
    )
    assert result["ssl"] == "issued"
    vhost = (tls_system["conf"] / "example.com.conf").read_text()
    assert "listen 443 ssl;" in vhost and "fullchain.pem" in vhost
    st = tls_system["tls_manager"]().ssl_status("example.com")
    assert st["https"] and st["certificate"]["staging"] and st["certificate"]["covers_all_names"]


def test_create_without_dns_stays_http(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    result = tls_system["tls_manager"]().create(CreateRequest("example.com"))
    assert result["ssl"].startswith("not issued yet")
    assert "listen 443" not in (tls_system["conf"] / "example.com.conf").read_text()
    with pytest.raises(PreconditionFailed, match="not eligible"):
        tls_system["tls_manager"]().ssl_issue("example.com")
    off = tls_system["tls_manager"](autossl=False).create(CreateRequest("other.example.com"))
    assert off["ssl"].startswith("AutoSSL is off")


def test_failed_verification_keeps_http(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    mgr = tls_system["tls_manager"](autossl=False)
    mgr.create(CreateRequest("example.com"))
    tls_system["dns"]["example.com"] = {"80.241.220.98"}
    tls_system["ca"].key_matches = False
    with pytest.raises(OperationFailed, match="do not match"):
        mgr.ssl_issue("example.com")
    assert "listen 443" not in (tls_system["conf"] / "example.com.conf").read_text()
    assert mgr.ssl_status("example.com")["https"] is False


def test_renew_revoke_autossl(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    mgr = tls_system["tls_manager"](autossl=False)
    mgr.create(CreateRequest("example.com"))
    with pytest.raises(PreconditionFailed, match="no certificate"):
        mgr.ssl_renew("example.com", force=False)
    tls_system["dns"]["example.com"] = {"80.241.220.98"}
    assert mgr.set_autossl("example.com", True)["issued"] is True
    assert mgr.ssl_renew("example.com", force=True)["days_left"] == 89
    mgr.set_enabled("example.com", False)  # maintenance keeps HTTPS
    vhost = (tls_system["conf"] / "example.com.conf").read_text()
    assert "listen 443 ssl;" in vhost and "return 503" in vhost
    mgr.set_enabled("example.com", True)
    result = mgr.ssl_revoke("example.com")
    assert result["revoked"] and result["autossl"] is False
    assert "listen 443" not in (tls_system["conf"] / "example.com.conf").read_text()
    with pytest.raises(PreconditionFailed):
        mgr.ssl_revoke("example.com")
    waiting = mgr.set_autossl("example.com", True)
    assert waiting["issued"] is True
    tls_system["dns"].clear()
    mgr.ssl_revoke("example.com")
    assert mgr.set_autossl("example.com", True)["waiting_for"]
    assert mgr.set_autossl("example.com", False)["autossl"] is False


def test_purge_deletes_certificate(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    tls_system["dns"]["example.com"] = {"80.241.220.98"}
    mgr = tls_system["tls_manager"]()
    mgr.create(CreateRequest("example.com"))
    mgr.delete("example.com", purge=True)
    assert not (tls_system["ca"].live / "example.com").exists()


def test_tls_dry_runs(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    tls_system["dns"]["example.com"] = {"80.241.220.98"}
    tls_system["tls_manager"]().create(CreateRequest("example.com"))
    dry = tls_system["tls_manager"](dry_run=True)
    assert dry.ssl_issue("example.com")["dry_run"]
    assert dry.ssl_renew("example.com", force=False)["dry_run"]
    assert dry.ssl_revoke("example.com")["dry_run"]
    assert dry.set_autossl("example.com", False)["dry_run"]


# --- CLI handlers --------------------------------------------------------------------


def test_tls_handlers(tls_system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from ozenix.cli.context import Context
    from ozenix.core.sysinfo import SystemProbe
    from ozenix.sites.lifecycle import CreateRequest

    monkeypatch.setattr(
        tls_handlers, "_manager", lambda ctx: tls_system["tls_manager"](ctx.dry_run)
    )
    tls_system["tls_manager"](autossl=False).create(CreateRequest("example.com"))
    tls_system["dns"]["example.com"] = {"80.241.220.98"}
    out = Output(stdout=io.StringIO(), stderr=io.StringIO())
    ctx = Context(
        paths=tls_system["paths"],
        out=out,
        probe=SystemProbe(),
        config=Config(),
        argv=["site"],
        domain="example.com",
        use_syslog=False,
    )
    with pytest.raises(NotImplementedYet):
        tls_handlers.ssl_issue(ctx, argparse.Namespace(staging=False, challenge="dns"))
    issued = tls_handlers.ssl_issue(ctx, argparse.Namespace(staging=True, challenge="http"))
    assert "STAGING" in issued.text[0]
    status = tls_handlers.ssl_status(ctx, argparse.Namespace())
    assert "HTTPS:    on" in status.text[0]
    assert "STAGING" in out.stderr.getvalue()  # type: ignore[attr-defined]
    assert "89 more days" in tls_handlers.ssl_renew(ctx, argparse.Namespace(force=True)).text[0]
    assert "revoked" in tls_handlers.ssl_revoke(ctx, argparse.Namespace()).text[0]
    assert "AutoSSL on" in tls_handlers.autossl(ctx, argparse.Namespace(state="on")).text[0]
    tls_system["ca"].not_after = (NOW + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    tls_handlers.ssl_status(ctx, argparse.Namespace())
    assert "expires in" in out.stderr.getvalue()  # type: ignore[attr-defined]


# --- placeholder certificate, Cloudflare proxy, AutoSSL retry ---------------------------


def _with_openssl(m: Any) -> Any:
    """Let the placeholder's openssl call create real files."""
    from ozenix.tls import selfsigned

    original = m.run

    def run(argv: list[str], **kw: Any) -> Any:
        if argv[:2] == [selfsigned.OPENSSL, "req"]:
            Path(argv[argv.index("-keyout") + 1]).write_text("KEY")
            Path(argv[argv.index("-out") + 1]).write_text("CERT")
        return original(argv, **kw)

    m.run = run
    return m


def test_new_site_gets_self_signed_https(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest
    from ozenix.tls import selfsigned

    mgr = _with_openssl(tls_system["tls_manager"]())
    result = mgr.create(CreateRequest("example.com", aliases=["www.example.com"]))
    assert result["ssl"].startswith("not issued yet") and 'mode "Full"' in result["ssl"]
    assert result["cloudflare"] is None  # DNS is never touched by default
    vhost = (tls_system["conf"] / "example.com.conf").read_text()
    assert "listen 443 ssl;" in vhost and "selfsigned/example.com/cert.pem" in vhost
    assert "return 301" not in vhost and "Strict-Transport-Security" not in vhost
    assert vhost.count("fastcgi_pass") == 2  # served on port 80 and 443
    files = selfsigned.files(mgr.selfsigned_dir, "example.com")
    assert files is not None and stat.S_IMODE(files.key.stat().st_mode) == 0o600
    assert stat.S_IMODE(mgr.selfsigned_dir.stat().st_mode) == 0o700
    st = mgr.ssl_status("example.com")
    assert st["https"] and st["certificate_kind"] == "self-signed placeholder"
    # Let's Encrypt replaces it: redirect + HSTS come back, placeholder no longer used.
    tls_system["dns"].update(
        {"example.com": {"80.241.220.98"}, "www.example.com": {"80.241.220.98"}}
    )
    mgr.ssl_issue("example.com")
    vhost = (tls_system["conf"] / "example.com.conf").read_text()
    assert "fullchain.pem" in vhost and "return 301" in vhost and "selfsigned" not in vhost
    assert mgr.ssl_status("example.com")["certificate_kind"] == "lets-encrypt"
    mgr.delete("example.com", purge=True)
    assert selfsigned.files(mgr.selfsigned_dir, "example.com") is None


def test_placeholder_failure_keeps_http(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    mgr = tls_system["tls_manager"]()  # openssl "runs" but writes nothing
    mgr.create(CreateRequest("example.com"))
    assert "listen 443" not in (tls_system["conf"] / "example.com.conf").read_text()
    assert any("no placeholder certificate" in m for m, _ in tls_system["reported"])


def test_cloudflare_proxied_names_are_eligible(tls_system: dict[str, Any], tmp_path: Path) -> None:
    import ipaddress

    from ozenix.sites.lifecycle import CreateRequest
    from ozenix.tls import dns

    conf = tmp_path / "realip.conf"
    conf.write_text(
        "# Managed\nset_real_ip_from 104.16.0.0/13;\nset_real_ip_from 2606:4700::/32;\n"
        "set_real_ip_from bogus;\nreal_ip_header CF-Connecting-IP;\n"
    )
    ranges = dns.cloudflare_ranges(conf)
    assert ranges == [ipaddress.ip_network("104.16.0.0/13"), ipaddress.ip_network("2606:4700::/32")]
    assert dns.cloudflare_ranges(tmp_path / "missing") == []
    assert dns.behind({"104.21.88.101", "2606:4700:3037::6815:5865"}, ranges)
    assert not dns.behind({"104.21.88.101", "198.51.100.1"}, ranges)
    assert not dns.behind({"not-an-ip"}, ranges) and not dns.behind(set(), ranges)
    assert not dns.behind({"104.21.88.101"}, [])

    tls_system["dns"]["proxied.example.com"] = {"104.21.88.101", "2606:4700:3037::6815:5865"}
    mgr = tls_system["tls_manager"]()
    mgr.proxy_ranges = lambda: ranges
    result = mgr.create(CreateRequest("proxied.example.com"))
    assert result["ssl"] == "issued"  # through the Cloudflare proxy (HTTP-01)


def test_autossl_retry_issues_when_dns_is_ready(tls_system: dict[str, Any]) -> None:
    from ozenix.sites.lifecycle import CreateRequest

    mgr = tls_system["tls_manager"]()
    mgr.create(CreateRequest("example.com"))
    mgr.create(CreateRequest("off.example.com", ssl=False))
    assert mgr.autossl_pending(now=1000.0) == {"example.com": "waiting for DNS"}
    tls_system["dns"]["example.com"] = {"80.241.220.98"}
    tls_system["ca"].key_matches = False
    assert mgr.autossl_pending(now=1000.0)["example.com"].startswith("failed")
    tls_system["ca"].key_matches = True
    assert mgr.autossl_pending(now=1500.0) == {}  # throttled: at most once an hour
    assert mgr.autossl_pending(now=5000.0) == {"example.com": "issued"}
    assert mgr.autossl_pending(now=99999.0) == {}  # done
