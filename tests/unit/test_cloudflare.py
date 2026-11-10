from __future__ import annotations

import argparse
import io
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from domainpilot.cli import cf_handlers
from domainpilot.cloudflare import api as cf_api
from domainpilot.cloudflare.api import Client, CloudflareError
from domainpilot.cloudflare.creds import CredentialStore, validate_label
from domainpilot.cloudflare.manager import CloudflareManager, tag
from domainpilot.core import proc
from domainpilot.core.errors import (
    ExitCode,
    OperationFailed,
    PreconditionFailed,
    UsageError,
    ValidationError,
)
from domainpilot.tls.acme import Certbot

HOST = {"80.241.220.98", "2a02:c207:2367:8894::1"}


class FakeCF:
    """In-memory Cloudflare API: zones, DNS records with comments, settings."""

    def __init__(
        self, zones: list[tuple[str, str]], settings: dict[str, Any] | None = None
    ) -> None:
        self.zones = [
            {"id": zid, "name": name, "status": "active", "plan": {"name": "Free"}}
            for zid, name in zones
        ]
        self.records: dict[str, dict[str, Any]] = {}
        self.settings = (
            settings
            if settings is not None
            else {
                "ssl": "strict",
                "min_tls_version": "1.2",
                "always_use_https": "on",
                "tls_1_3": "on",
                "automatic_https_rewrites": "on",
                "security_level": "medium",
                "browser_check": "on",
                "tls_client_auth": "off",
            }
        )
        self.settings_forbidden = False
        self.calls: list[tuple[str, str]] = []
        self.token_seen: list[str] = []
        self.next_id = 1

    def add(
        self,
        zone: str,
        rtype: str,
        name: str,
        content: str,
        *,
        proxied: bool = True,
        comment: str = "",
    ) -> None:
        rid = f"r{self.next_id}"
        self.next_id += 1
        self.records[rid] = {
            "id": rid,
            "zone": zone,
            "type": rtype,
            "name": name,
            "content": content,
            "proxied": proxied,
            "comment": comment,
        }

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, dict[str, Any]]:
        import json
        from urllib.parse import parse_qs, urlsplit

        self.token_seen.append(headers["Authorization"])
        parts = urlsplit(url)
        path = parts.path.removeprefix("/client/v4")
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.calls.append((method, path))

        def ok(result: Any) -> tuple[int, dict[str, Any]]:
            return 200, {"success": True, "result": result, "result_info": {"total_pages": 1}}

        if path == "/user/tokens/verify":
            return ok({"status": "active"})
        if path == "/zones":
            return ok(self.zones)
        segs = path.strip("/").split("/")
        zone = segs[1]
        if segs[2] == "settings":
            if self.settings_forbidden:
                return 403, {
                    "success": False,
                    "errors": [{"code": 9109, "message": "Unauthorized"}],
                }
            return ok({"value": self.settings.get(segs[3])})
        if segs[2] == "dns_records" and method == "GET":
            recs = [
                r
                for r in self.records.values()
                if r["zone"] == zone and ("name" not in query or r["name"] == query["name"])
            ]
            return ok(recs)
        if segs[2] == "dns_records" and method == "POST":
            data = json.loads(body or b"{}")
            self.add(
                zone,
                data["type"],
                data["name"],
                data["content"],
                proxied=data["proxied"],
                comment=data.get("comment", ""),
            )
            return ok(self.records[f"r{self.next_id - 1}"])
        if segs[2] == "dns_records" and method == "DELETE":
            self.records.pop(segs[3])
            return ok({"id": segs[3]})
        return 404, {"success": False, "errors": [{"code": 7003, "message": "not found"}]}


class FakeStore(CredentialStore):
    def __init__(self, tokens: dict[str, str], tmp: Path) -> None:
        super().__init__(store=tmp / "store", runtime=tmp / "run")
        self.tokens = tokens

    def labels(self) -> list[str]:
        return sorted(self.tokens)

    def load(self, label: str) -> str:
        if label not in self.tokens:
            raise OperationFailed("no credential")
        return self.tokens[label]


def manager(fake: FakeCF, tmp: Path, tokens: dict[str, str] | None = None) -> CloudflareManager:
    store = FakeStore(tokens or {"main": "tok_main"}, tmp)
    return CloudflareManager(store, client_factory=lambda t: Client(t, transport=fake))


# --- API client --------------------------------------------------------------------


def test_client_basics() -> None:
    fake = FakeCF([("z1", "example.com")])
    client = Client("secret-token", transport=fake)
    assert client.verify() == "active"
    assert [z.name for z in client.zones()] == ["example.com"]
    assert "secret-token" not in repr(client)
    assert fake.token_seen[0] == "Bearer secret-token"
    with pytest.raises(CloudflareError):
        Client("has space")
    with pytest.raises(CloudflareError):
        Client("")


def test_client_error_and_pagination() -> None:
    pages: list[int] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        if "page=" in url:
            page = int(url.split("page=")[1].split("&")[0])
            pages.append(page)
            return 200, {
                "success": True,
                "result": [{"id": f"z{page}", "name": f"d{page}.com"}],
                "result_info": {"total_pages": 3},
            }
        return 403, {
            "success": False,
            "errors": [{"code": 9109, "message": "Cannot use the access token from location"}],
        }

    client = Client("t", transport=transport)
    assert [z.name for z in client.zones()] == ["d1.com", "d2.com", "d3.com"]
    with pytest.raises(CloudflareError) as info:
        client.verify()
    assert info.value.codes == (9109,) and "location" in info.value.message


def test_urllib_transport_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(CloudflareError, match="cannot reach"):
        cf_api.urllib_transport("GET", cf_api.API + "/x", {}, None)


# --- credential store ---------------------------------------------------------------


def test_credential_store_roundtrip(tmp_path: Path) -> None:
    calls: list[tuple[list[str], str | None]] = []
    vault: dict[str, str] = {}

    def run(argv: list[str], **kw: Any) -> proc.Result:
        calls.append((argv, kw.get("stdin")))
        if argv[1] == "encrypt":
            Path(argv[-1]).write_bytes(b"ENCRYPTED")
            vault[argv[2]] = kw["stdin"]
            return proc.Result(tuple(argv), 0, "", "")
        return proc.Result(tuple(argv), 0, vault[argv[2]], "")

    store = CredentialStore(store=tmp_path / "s" / "cf", runtime=tmp_path / "run", run=run)
    assert store.labels() == []
    store.save("example.com", "tok123")
    assert store.labels() == ["example.com"]
    assert all("tok123" not in " ".join(argv) for argv, _ in calls)  # never in argv
    assert store.path("example.com").stat().st_mode & 0o777 == 0o600
    assert store.load("example.com") == "tok123"
    ini = store.certbot_ini("example.com")
    assert ini.read_text() == "dns_cloudflare_api_token = tok123\n"
    assert ini.stat().st_mode & 0o777 == 0o600
    store.discard_ini("example.com")
    assert not ini.exists()
    store.remove("example.com")
    assert store.labels() == []
    with pytest.raises(OperationFailed):
        store.load("example.com")
    with pytest.raises(ValidationError):
        store.save("x", "two words")
    with pytest.raises(ValidationError):
        validate_label("../evil")


# --- manager: zones and records ---------------------------------------------------------


def test_zone_for_longest_suffix_and_broken_tokens(tmp_path: Path) -> None:
    fake = FakeCF([("z1", "example.com"), ("z2", "shop.example.com")])
    mgr = manager(fake, tmp_path, {"broken": "x", "main": "tok"})
    original = mgr.client_factory

    def factory(token: str) -> Client:
        if token == "x":
            return Client("x", transport=lambda *a: (403, {"success": False, "errors": []}))
        return original(token)

    mgr.client_factory = factory
    ref = mgr.zone_for("api.shop.example.com")
    assert ref is not None and ref.zone.name == "shop.example.com" and ref.label == "main"
    assert mgr.zone_for("example.com").zone.name == "example.com"  # type: ignore[union-attr]
    assert mgr.zone_for("other.org") is None


def test_ensure_and_remove_records(tmp_path: Path) -> None:
    fake = FakeCF([("z1", "example.com")])
    fake.add("z1", "TXT", "example.com", "v=spf1 -all", comment="")  # someone else's, untouched
    mgr = manager(fake, tmp_path)
    ref = mgr.zone_for("example.com")
    assert ref is not None
    plan = mgr.ensure_records(ref, ["dp.example.com"], HOST, "t0001", dry_run=True)
    assert len(plan) == 2 and not [
        r for r in fake.records.values() if r["name"] == "dp.example.com"
    ]
    actions = mgr.ensure_records(ref, ["dp.example.com"], HOST, "t0001")
    assert actions == [
        "create A dp.example.com -> 80.241.220.98 (proxied)",
        "create AAAA dp.example.com -> 2a02:c207:2367:8894::1 (proxied)",
    ]
    assert mgr.ensure_records(ref, ["dp.example.com"], HOST, "t0001") == []  # idempotent
    assert mgr.records_ok(ref, ["dp.example.com"], HOST) == []
    assert mgr.records_ok(ref, ["missing.example.com"], HOST)[0].endswith(
        "no A/AAAA record in Cloudflare"
    )
    removed = mgr.remove_records(ref, ["dp.example.com", "example.com"], "t0001")
    assert len(removed) == 2
    assert [r["type"] for r in fake.records.values()] == ["TXT"]  # foreign record untouched


def test_foreign_records_are_never_overwritten(tmp_path: Path) -> None:
    fake = FakeCF([("z1", "example.com")])
    fake.add("z1", "A", "www.example.com", "198.51.100.7", comment="")
    fake.add("z1", "A", "other.example.com", "80.241.220.98", comment=tag("t0002"))
    mgr = manager(fake, tmp_path)
    ref = mgr.zone_for("example.com")
    assert ref is not None
    with pytest.raises(PreconditionFailed, match="did not create"):
        mgr.ensure_records(ref, ["www.example.com"], HOST, "t0001")
    with pytest.raises(PreconditionFailed):  # another tenant's record is foreign too
        mgr.ensure_records(ref, ["other.example.com"], HOST, "t0001")
    assert mgr.remove_records(ref, ["www.example.com", "other.example.com"], "t0001") == []
    assert len(fake.records) == 2
    assert "elsewhere" in mgr.records_ok(ref, ["www.example.com"], HOST)[0]
    with pytest.raises(PreconditionFailed, match="IPv4"):
        mgr.ensure_records(ref, ["new.example.com"], {"2a02:c207:2367:8894::1"}, "t0001")


# --- audits -------------------------------------------------------------------------------


def test_audit_good_and_bad(tmp_path: Path) -> None:
    fake = FakeCF([("z1", "example.com")])
    fake.add("z1", "A", "dp.example.com", "80.241.220.98", comment=tag("t0001"))
    mgr = manager(fake, tmp_path)
    ref = mgr.zone_for("example.com")
    assert ref is not None
    good = mgr.audit(ref, ["dp.example.com"], HOST, sections=["dns", "ssl", "security"])
    assert good.worst == "info" and any("Full (strict)" in f.message for f in good.findings)

    fake.settings.update(
        {
            "ssl": "flexible",
            "min_tls_version": "1.0",
            "always_use_https": "off",
            "security_level": "essentially_off",
        }
    )
    fake.add("z1", "A", "dns-only.example.com", "80.241.220.98", proxied=False)
    fake.add("z1", "A", "away.example.com", "198.51.100.7")
    bad = mgr.audit(
        ref,
        ["dns-only.example.com", "away.example.com", "none.example.com"],
        HOST,
        sections=["dns", "ssl", "security"],
    )
    text = " | ".join(f"{f.severity}:{f.message}" for f in bad.findings)
    assert bad.worst == "critical"
    for needle in (
        "not (properly) encrypted",
        "set at least 1.2",
        "DNS only",
        "not to this server",
        "no record in Cloudflare",
        "security level is essentially_off",
    ):
        assert needle in text, needle
    fake.settings["ssl"] = "full"
    assert "not strict" in " ".join(
        f.message for f in mgr.audit(ref, [], HOST, sections=["ssl"]).findings
    )


def test_audit_without_settings_permission(tmp_path: Path) -> None:
    fake = FakeCF([("z1", "example.com")])
    fake.settings_forbidden = True
    mgr = manager(fake, tmp_path)
    ref = mgr.zone_for("example.com")
    assert ref is not None
    audit = mgr.audit(ref, [], HOST, sections=["ssl", "security"])
    assert audit.findings[0].check == "permissions" and audit.worst == "warn"


# --- certbot DNS-01 ------------------------------------------------------------------------


def test_certbot_dns01_argv(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(argv)
        return proc.Result((), 0, "", "")

    cb = Certbot(
        run=run,
        live=tmp_path / "live",
    )
    cb.issue(
        "dp.example.com",
        ["dp.example.com"],
        staging=True,
        email=None,
        dns_credentials=tmp_path / "cf.ini",
    )
    argv = calls[-1]
    assert "--dns-cloudflare" in argv and "--webroot" not in argv
    assert argv[argv.index("--dns-cloudflare-credentials") + 1] == str(tmp_path / "cf.ini")


# --- lifecycle with Cloudflare ---------------------------------------------------------------


@pytest.fixture
def cf_system(system: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    from test_tls import FakeCA, certbot

    fake = FakeCF([("z1", "example.com")])
    ca = FakeCA(tmp_path / "live")
    cfm = manager(fake, tmp_path)
    inis: list[str] = []

    def certbot_ini(label: str) -> Path:
        inis.append(label)
        return tmp_path / "cf.ini"

    def discard_ini(label: str) -> None:
        inis.append("discard:" + label)

    cfm.store.certbot_ini = certbot_ini  # type: ignore[method-assign]
    cfm.store.discard_ini = discard_ini  # type: ignore[method-assign]

    def make(dry_run: bool = False) -> Any:
        from domainpilot.core.config import Config

        m = system["manager"](dry_run)
        m.config = Config(autossl=True, ssl_staging=True)
        m.certbot = certbot(ca)
        m.cloudflare = cfm
        m.host_ips = lambda: set(HOST)
        m.resolver = lambda name: set()  # public DNS would show Cloudflare IPs: irrelevant
        return m

    system.update({"cf": fake, "cf_manager": make, "inis": inis, "ca": ca})
    return system


def test_create_on_cloudflare_zone(cf_system: dict[str, Any]) -> None:
    from domainpilot.sites.lifecycle import CreateRequest

    result = cf_system["cf_manager"]().create(
        CreateRequest("dp.example.com", aliases=["www.dp.example.com"], cloudflare=True)
    )
    assert result["cloudflare"] == "proxied through Cloudflare zone example.com"
    assert result["ssl"] == "issued"
    assert cf_system["inis"] == ["main", "discard:main"]  # token in RAM only while certbot ran
    dns01 = [c for c in cf_system["ca"].calls if "certonly" in c][-1]
    assert "--dns-cloudflare" in dns01
    names = sorted({r["name"] for r in cf_system["cf"].records.values()})
    assert names == ["dp.example.com", "www.dp.example.com"]
    assert all(
        r["proxied"] and r["comment"] == "domainpilot:t0001"
        for r in cf_system["cf"].records.values()
    )
    status = cf_system["cf_manager"]().ssl_status("dp.example.com")
    assert status["challenge"] == "dns-01 (Cloudflare)" and status["eligibility_problems"] == []
    audit = cf_system["cf_manager"]().cloudflare_audit("dp.example.com", ["dns", "ssl"])
    assert audit["managed"] is True and audit["worst"] in ("ok", "info")
    cf_system["cf_manager"]().delete("dp.example.com", purge=False)
    assert cf_system["cf"].records == {}  # records removed when the site stops being served


def test_create_with_no_cloudflare_and_foreign_record(cf_system: dict[str, Any]) -> None:
    from domainpilot.sites.lifecycle import CreateRequest

    plain = cf_system["cf_manager"]().create(CreateRequest("a.example.com", cloudflare=False))
    assert plain["cloudflare"] is None and cf_system["cf"].records == {}
    cf_system["cf"].add("z1", "A", "b.example.com", "198.51.100.7")
    clash = cf_system["cf_manager"]().create(CreateRequest("b.example.com", cloudflare=True))
    assert clash["cloudflare"].startswith("not configured") and len(cf_system["cf"].records) == 1
    elsewhere = cf_system["cf_manager"]().create(CreateRequest("site.other.org", cloudflare=True))
    assert elsewhere["cloudflare"] is None


def test_cloudflare_sync_and_unmanaged_audit(cf_system: dict[str, Any]) -> None:
    from domainpilot.sites.lifecycle import CreateRequest

    mgr = cf_system["cf_manager"]()
    mgr.create(CreateRequest("c.example.com", cloudflare=False))
    plan = cf_system["cf_manager"](dry_run=True).cloudflare_sync("c.example.com")
    assert plan["dry_run"] and len(plan["actions"]) == 2 and cf_system["cf"].records == {}
    applied = mgr.cloudflare_sync("c.example.com")
    assert len(applied["actions"]) == 2 and len(cf_system["cf"].records) == 2
    mgr.create(CreateRequest("x.other.org", cloudflare=False))
    with pytest.raises(PreconditionFailed, match="not in any Cloudflare zone"):
        mgr.cloudflare_audit("x.other.org", ["dns"])
    with pytest.raises(PreconditionFailed):
        mgr.cloudflare_sync("x.other.org")


# --- CLI handlers ------------------------------------------------------------------------------


def _ctx(
    cf_system: dict[str, Any], domain: str | None = "dp.example.com", dry_run: bool = False
) -> Any:
    from domainpilot.cli.context import Context
    from domainpilot.core.config import Config
    from domainpilot.core.output import Output
    from domainpilot.core.sysinfo import SystemProbe

    out = Output(stdout=io.StringIO(), stderr=io.StringIO())
    ctx = Context(
        paths=cf_system["paths"],
        out=out,
        probe=SystemProbe(),
        config=Config(),
        argv=["site"],
        domain=domain,
        dry_run=dry_run,
        use_syslog=False,
    )
    ctx._registry = cf_system["registry"]
    return ctx


def test_cf_handlers(cf_system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from domainpilot.sites.lifecycle import CreateRequest

    monkeypatch.setattr(cf_handlers, "_manager", lambda ctx: cf_system["cf_manager"](ctx.dry_run))
    cf_system["cf_manager"]().create(CreateRequest("dp.example.com", cloudflare=True))
    ctx = _ctx(cf_system)
    res = cf_handlers.status(ctx, argparse.Namespace())
    assert res.exit_code == ExitCode.OK and res.disclaimer and "Full (strict)" in " ".join(res.text)
    cf_system["cf"].settings["ssl"] = "flexible"
    assert (
        cf_handlers.ssl(ctx, argparse.Namespace(apply=False)).exit_code == ExitCode.AUDIT_CRITICAL
    )
    cf_system["cf"].settings["security_level"] = "off"
    assert (
        cf_handlers.security(ctx, argparse.Namespace(apply=False)).exit_code
        == ExitCode.AUDIT_WARNINGS
    )
    with pytest.raises(UsageError, match="does not change"):
        cf_handlers.ssl(ctx, argparse.Namespace(apply=True))
    assert "already correct" in cf_handlers.dns(ctx, argparse.Namespace(apply=True)).text[0]
    assert cf_handlers.dns(ctx, argparse.Namespace(apply=False)).data["zone"] == "example.com"


def test_token_handlers(
    cf_system: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = cf_system["cf"]
    store = FakeStore({}, tmp_path)
    saved: dict[str, str] = {}
    store.save = lambda label, token: saved.__setitem__(label, token)  # type: ignore[method-assign]
    store.labels = lambda: sorted(saved)  # type: ignore[method-assign]
    store.load = lambda label: saved[label]  # type: ignore[method-assign]

    def remove(label: str) -> None:
        saved.pop(label)

    store.remove = remove  # type: ignore[method-assign]
    monkeypatch.setattr(cf_handlers, "_store", lambda: store)
    monkeypatch.setattr(cf_handlers, "Client", lambda token: Client(token, transport=fake))
    monkeypatch.setattr(cf_handlers, "_read_token", lambda: "tok_new")
    ctx = _ctx(cf_system, domain=None)
    assert "No Cloudflare tokens" in cf_handlers.token_list(ctx, argparse.Namespace()).text[0]
    added = cf_handlers.token_add(ctx, argparse.Namespace(label=None))
    assert added.data["label"] == "example.com" and saved == {"example.com": "tok_new"}
    assert "tok_new" not in " ".join(added.text)
    assert "example.com: active" in cf_handlers.token_list(ctx, argparse.Namespace()).text[0]
    cf_handlers.token_remove(ctx, argparse.Namespace(label="example.com"))
    assert saved == {}
    with pytest.raises(PreconditionFailed):
        cf_handlers.token_remove(ctx, argparse.Namespace(label="example.com"))
    monkeypatch.setattr(cf_handlers, "_read_token", lambda: "")
    with pytest.raises(UsageError):
        cf_handlers.token_add(ctx, argparse.Namespace(label=None))
    monkeypatch.setattr(cf_handlers, "_read_token", lambda: "tok_x")
    fake.zones = []
    with pytest.raises(PreconditionFailed, match="cannot see any zone"):
        cf_handlers.token_add(ctx, argparse.Namespace(label=None))
