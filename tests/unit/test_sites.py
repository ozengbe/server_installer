from __future__ import annotations

import argparse
import io
import socket
from pathlib import Path
from typing import Any

import pytest

from ozenix.cli import site_handlers
from ozenix.cli.context import Context
from ozenix.core import fsutil, proc
from ozenix.core.config import Config, HostFacts
from ozenix.core.errors import (
    NotImplementedYet,
    OperationFailed,
    PreconditionFailed,
    UsageError,
    ValidationError,
)
from ozenix.core.output import Output
from ozenix.core.paths import Paths
from ozenix.core.registry import Registry
from ozenix.core.sysinfo import SystemProbe
from ozenix.isolation import db as db_module
from ozenix.sites.lifecycle import CreateRequest
from ozenix.web.nginx import Nginx, Upstream, parse_upstream

HOST = HostFacts(release="26.04", default_php_version="8.5", php_versions=("8.5",))


def public_resolver(_host: str, _port: int) -> list[str]:
    return ["93.184.215.14"]


# --- upstream validation (SSRF guard) ---------------------------------------------


def test_parse_upstream_ok() -> None:
    up = parse_upstream("https://api.example.org", resolve=public_resolver)
    assert (up.url, up.host_header) == ("https://api.example.org", "api.example.org")
    up = parse_upstream("https://api.example.org:8443/", resolve=public_resolver)
    assert (up.url, up.host_header) == ("https://api.example.org:8443", "api.example.org:8443")


@pytest.mark.parametrize(
    "value",
    [
        "http://api.example.org",
        "https://user:pw@api.example.org",
        "https://api.example.org/path",
        "https://api.example.org?x=1",
        "https://127.0.0.1",
        "https://localhost",
        "https://api.example.org:99999",
        "https://bad_host.org",
    ],
)
def test_parse_upstream_rejects(value: str) -> None:
    with pytest.raises(ValidationError):
        parse_upstream(value, resolve=public_resolver)


@pytest.mark.parametrize("addr", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fd00::1"])
def test_parse_upstream_rejects_private_resolution(addr: str) -> None:
    with pytest.raises(ValidationError, match="non-public"):
        parse_upstream("https://rebind.example.org", resolve=lambda h, p: [addr])


def test_parse_upstream_unresolvable() -> None:
    def fail(_h: str, _p: int) -> list[str]:
        raise socket.gaierror("no such host")

    with pytest.raises(ValidationError, match="does not resolve"):
        parse_upstream("https://nx.example.org", resolve=fail)
    with pytest.raises(ValidationError, match="does not resolve"):
        parse_upstream("https://nx.example.org", resolve=lambda h, p: [])


# --- nginx rendering --------------------------------------------------------------


def make_nginx(tmp_path: Path, run: Any = None) -> Nginx:
    paths = Paths.under(tmp_path / "root")
    conf = tmp_path / "sites"
    logs = tmp_path / "nginxlogs"
    conf.mkdir(mode=0o755)
    logs.mkdir(mode=0o750)
    calls: list[list[str]] = []

    def ok(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(list(argv))
        return proc.Result(tuple(argv), 0, "", "")

    nginx = Nginx(paths, conf_dir=conf, log_root=logs, run=run or ok)
    nginx.calls = calls  # type: ignore[attr-defined]
    return nginx


@pytest.mark.parametrize("kind", ["php", "static", "maintenance"])
def test_render_kinds(tmp_path: Path, kind: str) -> None:
    out = make_nginx(tmp_path).render(
        kind, domain="example.com", aliases=["www.example.com"], tenant="t0001"
    )
    assert "server_name example.com www.example.com;" in out
    assert "${" not in out and "$$" not in out
    if kind == "php":
        assert "fastcgi_pass unix:" in out and "/t0001/php/php.sock" in out
        assert "disable_symlinks if_not_owner" in out and "$document_root" in out
    if kind == "static":
        assert "location ~* \\.php$" in out and "return 404" in out
    if kind == "maintenance":
        assert "return 503" in out


def test_render_proxy(tmp_path: Path) -> None:
    nginx = make_nginx(tmp_path)
    out = nginx.render(
        "proxy",
        domain="example.com",
        aliases=[],
        tenant="t0001",
        upstream=Upstream("api.example.org", 443),
    )
    assert "proxy_pass https://api.example.org;" in out and "proxy_ssl_verify on;" in out
    with pytest.raises(ValidationError, match="upstream"):
        nginx.render("proxy", domain="example.com", aliases=[], tenant="t0001")
    with pytest.raises(ValidationError):
        nginx.render("cgi", domain="example.com", aliases=[], tenant="t0001")
    with pytest.raises(ValidationError):
        nginx.render("php", domain="example.com", aliases=["evil.com;"], tenant="t0001")


def test_apply_validates_and_restores(tmp_path: Path) -> None:
    state = {"fail": False}

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        if argv[:2] == ["/usr/sbin/nginx", "-t"] and state["fail"]:
            return proc.Result(tuple(argv), 1, "", "nginx: [emerg] unknown directive\n")
        return proc.Result(tuple(argv), 0, "", "")

    nginx = make_nginx(tmp_path, run)
    assert nginx.apply("example.com", "server { }\n") is None
    path = nginx.conf_path("example.com")
    assert path.read_text() == "server { }\n"
    state["fail"] = True
    with pytest.raises(OperationFailed, match="unknown directive"):
        nginx.apply("example.com", "broken\n")
    assert path.read_text() == "server { }\n"  # previous config restored
    with pytest.raises(OperationFailed):
        nginx.remove("example.com")
    assert path.exists()  # removal rolled back too
    state["fail"] = False
    assert nginx.remove("example.com") == b"server { }\n"
    assert nginx.remove("example.com") is None
    with pytest.raises(OperationFailed):
        state["fail"] = True
        nginx.apply("new.example.com", "broken\n")
    assert not nginx.conf_path("new.example.com").exists()  # new file removed


def test_create_php_site(system: dict[str, Any]) -> None:
    result = system["manager"]().create(CreateRequest("Example.com", aliases=["www.example.com"]))
    assert result["tenant"] == "t0001" and result["type"] == "php"
    reg: Registry = system["registry"]
    site = reg.get_site("example.com")
    assert site is not None and site.is_primary and site.php_version == "8.5"
    alias = reg.get_site("www.example.com")
    assert alias is not None and not alias.is_primary
    tenant = reg.get_tenant("t0001")
    assert tenant is not None and tenant.status == "active"
    vhost = (system["conf"] / "example.com.conf").read_text()
    assert "server_name example.com www.example.com;" in vhost
    starter = system["paths"].tenant_root("t0001") / "app" / "public" / "index.php"
    assert "Site ready" in starter.read_text() and starter.stat().st_mode & 0o777 == 0o640
    assert ["/usr/bin/systemctl", "reload", "nginx"] in system["calls"]


def test_create_static_and_proxy(system: dict[str, Any]) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("static.example.com", site_type="static"))
    assert (system["paths"].tenant_root("t0001") / "app" / "public" / "index.html").exists()
    settings = system["registry"].get_tenant_settings("t0001")
    assert settings["php"] is False and settings["cache"] is False
    assert not any("dp-php@" in " ".join(c) for c in system["calls"])
    mgr.create(
        CreateRequest("proxy.example.com", site_type="proxy", upstream="https://api.example.org")
    )
    vhost = (system["conf"] / "proxy.example.com.conf").read_text()
    assert "proxy_pass https://api.example.org;" in vhost


@pytest.mark.parametrize(
    ("req", "error"),
    [
        (CreateRequest("a.example.com", tier="c"), NotImplementedYet),
        (CreateRequest("a.example.com", writable_code=True), NotImplementedYet),
        (CreateRequest("a.example.com", site_type="cgi"), PreconditionFailed),
        (CreateRequest("a.example.com", php_version="8.3"), PreconditionFailed),
        (CreateRequest("a.example.com", upstream="https://api.example.org"), PreconditionFailed),
        (CreateRequest("a.example.com;id"), ValidationError),
    ],
)
def test_create_rejects(system: dict[str, Any], req: CreateRequest, error: type[Exception]) -> None:
    with pytest.raises(error):
        system["manager"]().create(req)


def test_create_rejects_duplicates(system: dict[str, Any]) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com", aliases=["www.example.com"]))
    with pytest.raises(PreconditionFailed, match="already"):
        mgr.create(CreateRequest("www.example.com"))


def test_create_dry_run_changes_nothing(system: dict[str, Any]) -> None:
    result = system["manager"](dry_run=True).create(CreateRequest("example.com"))
    assert result["dry_run"] and result["plan"]
    assert system["registry"].list_tenants() == []
    assert not list(system["conf"].iterdir())
    assert any(status == "planned" for _, status in system["reported"])


def test_create_rolls_back_on_nginx_failure(system: dict[str, Any]) -> None:
    system["state"]["nginx_fail"] = True
    with pytest.raises(OperationFailed, match="nginx rejected"):
        system["manager"]().create(CreateRequest("example.com"))
    reg: Registry = system["registry"]
    assert reg.get_site("example.com") is None
    assert reg.list_tenants()[0].status == "purged"
    assert not system["paths"].tenant_root("t0001").exists()
    assert not (system["conf"] / "example.com.conf").exists()
    assert "t0001" not in system["users"]


def test_disable_enable(system: dict[str, Any]) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    assert mgr.set_enabled("example.com", False)["changed"] is True
    assert "return 503" in (system["conf"] / "example.com.conf").read_text()
    assert [
        "/usr/bin/systemctl",
        "disable",
        "--now",
        "dp-cache@t0001.service",
        "dp-php@t0001.service",
    ] in system["calls"]
    site = system["registry"].get_site("example.com")
    assert site is not None and not site.enabled
    assert mgr.set_enabled("example.com", False)["changed"] is False
    mgr.set_enabled("example.com", True)
    assert "fastcgi_pass" in (system["conf"] / "example.com.conf").read_text()


def test_alias_and_unknown_are_rejected(system: dict[str, Any]) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com", aliases=["www.example.com"]))
    with pytest.raises(PreconditionFailed, match="alias of example.com"):
        mgr.set_enabled("www.example.com", False)
    with pytest.raises(PreconditionFailed, match="not an ozenix site"):
        mgr.delete("nope.example.com", purge=False)


def test_delete_archive_then_purge(system: dict[str, Any]) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    result = mgr.delete("example.com", purge=False)
    assert result["purge"] is False
    reg: Registry = system["registry"]
    tenant = reg.get_tenant("t0001")
    assert tenant is not None and tenant.status == "archived"
    assert system["paths"].tenant_root("t0001").exists()  # data kept
    assert not (system["conf"] / "example.com.conf").exists()
    with pytest.raises(PreconditionFailed, match="archived"):
        mgr.set_enabled("example.com", True)
    with pytest.raises(PreconditionFailed, match="already"):
        mgr.create(CreateRequest("example.com"))
    assert mgr.delete("example.com", purge=True)["purge"] is True
    assert reg.get_site("example.com") is None
    assert not system["paths"].tenant_root("t0001").exists()
    mgr.create(CreateRequest("example.com"))  # domain is free again (new tenant)
    assert reg.get_site("example.com").tenant_id == "t0002"  # type: ignore[union-attr]


def test_delete_dry_run(system: dict[str, Any]) -> None:
    system["manager"]().create(CreateRequest("example.com"))
    result = system["manager"](dry_run=True).delete("example.com", purge=True)
    assert result["dry_run"] and any("ERASE" in line for line in result["plan"])
    assert (system["conf"] / "example.com.conf").exists()


def test_repair_removes_unfinished_creation(system: dict[str, Any]) -> None:
    reg: Registry = system["registry"]
    # Simulate a crash mid-creation: tenant left "provisioning", files on disk.
    t = reg.allocate_tenant()
    reg.set_tenant_settings(t.id, {"domain": "example.com", "php": True, "cache": True})
    root = system["paths"].tenant_root(t.id)
    root.mkdir(mode=0o750)
    (root / "leftover").write_text("x")
    op = reg.begin_operation(
        actor="a", command=["site", "example.com", "create"], target="example.com"
    )
    mgr = system["manager"]()
    with pytest.raises(PreconditionFailed, match="did not finish") as info:
        mgr.create(CreateRequest("example.com"))
    assert info.value.hint is not None and "repair" in info.value.hint
    plan = system["manager"](dry_run=True).repair("example.com")
    assert plan["actions"] == [f"remove unfinished creation {t.id}"]
    result = mgr.repair("example.com")
    assert not root.exists()
    assert reg.get_tenant(t.id).status == "purged"  # type: ignore[union-attr]
    assert reg.get_operation(op).status == "rolled_back"  # type: ignore[union-attr]
    assert any("closed interrupted operation" in a for a in result["actions"])
    mgr.create(CreateRequest("example.com"))  # now succeeds


def test_repair_reapplies_existing_site(system: dict[str, Any]) -> None:
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    (system["conf"] / "example.com.conf").write_text("# tampered\n")
    result = mgr.repair("example.com")
    assert "re-applied nginx and runtime state for example.com" in result["actions"]
    assert "fastcgi_pass" in (system["conf"] / "example.com.conf").read_text()
    assert mgr.repair("nothing.example.com")["actions"] == []


# --- CLI handlers -------------------------------------------------------------------


def make_ctx(
    system: dict[str, Any], domain: str, *, dry_run: bool = False, json_mode: bool = False
) -> Context:
    out = Output(json_mode=json_mode, stdout=io.StringIO(), stderr=io.StringIO())
    ctx = Context(
        paths=system["paths"],
        out=out,
        probe=SystemProbe(),
        config=Config(),
        argv=["site", domain],
        domain=domain,
        dry_run=dry_run,
        use_syslog=False,
    )
    ctx._registry = system["registry"]
    return ctx


def test_handlers_end_to_end(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(site_handlers, "_manager", lambda ctx: system["manager"](ctx.dry_run))
    ctx = make_ctx(system, "example.com")
    ns = argparse.Namespace(
        site_type=None,
        php_version=None,
        tier=None,
        alias=[],
        upstream=None,
        writable_code=False,
        no_ssl=True,
    )
    res = site_handlers.create(ctx, ns)
    assert res.data["tenant"] == "t0001" and any("Next steps" in t for t in res.text)
    assert site_handlers.create(make_ctx(system, "dry.example.com", dry_run=True), ns).data[
        "dry_run"
    ]
    assert "disabled" in site_handlers.disable(ctx, ns).text[0]
    assert "already disabled" in site_handlers.disable(ctx, ns).text[0]
    assert "enabled" in site_handlers.enable(ctx, ns).text[0]
    assert site_handlers.repair(ctx, ns).exit_code == 0
    archived = site_handlers.delete(ctx, argparse.Namespace(purge=False))
    assert "archived" in archived.text[0]


def test_db_handlers(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    system["manager"]().create(CreateRequest("example.com"))
    sql: list[str] = []
    monkeypatch.setattr(db_module, "execute", lambda s, run=None: sql.append(s))
    ctx = make_ctx(system, "example.com")
    res = site_handlers.db_create(ctx, argparse.Namespace(name="shop"))
    assert res.data["database"] == "t0001_shop" and "t0001_shop" in sql[-1]
    with pytest.raises(ValidationError):
        site_handlers.db_create(ctx, argparse.Namespace(name="Shop;"))
    dry = site_handlers.db_create(
        make_ctx(system, "example.com", dry_run=True), argparse.Namespace(name="x")
    )
    assert dry.data["dry_run"]
    hidden = site_handlers.db_credentials(ctx, argparse.Namespace(rotate=False, show_secret=False))
    assert hidden.data["password"] is None and "hidden" in hidden.text[2]
    shown = site_handlers.db_credentials(ctx, argparse.Namespace(rotate=False, show_secret=True))
    old = shown.data["password"]
    assert old
    rotated = site_handlers.db_credentials(ctx, argparse.Namespace(rotate=True, show_secret=True))
    assert rotated.data["password"] != old and "ALTER USER" in sql[-1]
    with pytest.raises(PreconditionFailed):
        site_handlers.db_create(make_ctx(system, "nope.example.com"), argparse.Namespace(name="a"))


def test_logs_handler(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    system["manager"]().create(CreateRequest("example.com"))
    log_root: Path = system["conf"].parent / "nginxlogs"
    monkeypatch.setattr(site_handlers, "Nginx", lambda paths: Nginx(paths, log_root=log_root))
    (log_root / "t0001" / "access.log").write_text("".join(f"line {i}\n" for i in range(100)))
    ctx = make_ctx(system, "example.com")
    res = site_handlers.logs(ctx, argparse.Namespace(kind=None, lines=3))
    assert res.data["lines"] == ["line 97", "line 98", "line 99"]
    empty = site_handlers.logs(ctx, argparse.Namespace(kind="error", lines=5))
    assert "is empty" in empty.text[0]
    with pytest.raises(UsageError):
        site_handlers.logs(ctx, argparse.Namespace(kind=None, lines=0))
    php_log = system["paths"].tenant_log("t0001") / "php-error.log"
    php_log.symlink_to("/etc/passwd")  # tenant-owned dir: must never be followed
    with pytest.raises(OperationFailed, match="symlink"):
        site_handlers.logs(ctx, argparse.Namespace(kind="php", lines=5))


def test_create_exclusive_refuses_existing_and_symlink(tmp_path: Path) -> None:
    target = tmp_path / "f"
    fsutil.create_exclusive(target, "x", mode=0o640)
    assert target.read_text() == "x" and target.stat().st_mode & 0o777 == 0o640
    with pytest.raises(FileExistsError):
        fsutil.create_exclusive(target, "y")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "victim")
    with pytest.raises(FileExistsError):
        fsutil.create_exclusive(link, "pwned")
    assert not (tmp_path / "victim").exists()


def _fake_proc(root: Path, procs: dict[int, int]) -> None:
    for pid, ppid in procs.items():
        d = root / str(pid)
        d.mkdir(exist_ok=True)
        (d / "stat").write_text(f"{pid} (nginx: worker) S {ppid} 1 1 0\n")


def test_reload_waits_for_new_workers(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    (proc_root / "self").mkdir()
    pid_file = tmp_path / "nginx.pid"
    pid_file.write_text("100\n")
    _fake_proc(proc_root, {100: 1, 101: 100, 102: 100})

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        if argv[1:] == ["reload", "nginx"]:
            for old in (101, 102):
                (proc_root / str(old) / "stat").unlink()
                (proc_root / str(old)).rmdir()
            _fake_proc(proc_root, {201: 100, 202: 100})
        return proc.Result(tuple(argv), 0, "", "")

    nginx = Nginx(Paths.under(tmp_path), run=run, pid_file=pid_file, proc_root=proc_root)
    assert nginx._workers() == {101, 102}
    nginx.reload()
    assert nginx._workers() == {201, 202}


def test_reload_times_out_without_new_workers(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    pid_file = tmp_path / "nginx.pid"
    pid_file.write_text("100\n")
    _fake_proc(proc_root, {100: 1, 101: 100})
    (proc_root / "999").mkdir()  # unreadable entry is skipped
    nginx = Nginx(
        Paths.under(tmp_path),
        run=lambda argv, **kw: proc.Result(tuple(argv), 0, "", ""),
        pid_file=pid_file,
        proc_root=proc_root,
        reload_timeout=0.2,
    )
    with pytest.raises(OperationFailed, match="new workers"):
        nginx.reload()
    pid_file.write_text("garbage")
    assert nginx._workers() == set()
