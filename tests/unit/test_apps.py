"""Node.js and Python sites: a sandboxed app per site behind nginx."""

from __future__ import annotations

import argparse
import dataclasses
from typing import Any

import pytest

from ozenix.cli import site_handlers
from ozenix.core import validate
from ozenix.core.config import HostFacts
from ozenix.core.errors import PreconditionFailed, UsageError, ValidationError
from ozenix.isolation.provision import Provisioner
from ozenix.isolation.render import AppSpec, app_port, systemd_exec
from ozenix.sites.lifecycle import CreateRequest

HOST = HostFacts(
    release="26.04",
    default_php_version="8.5",
    php_versions=("8.2", "8.3", "8.4", "8.5"),
    node_versions=("22", "24", "26"),
    default_node_version="24",
    python_sites=True,
)


def _mgr(system: dict[str, Any], host: HostFacts = HOST, dry_run: bool = False) -> Any:
    m = system["manager"](dry_run)
    m.host = host
    m.provisioner = Provisioner(system["paths"], host, run=m.run)
    return m


def test_systemd_exec_quoting() -> None:
    assert systemd_exec("npm start") == '"npm start"'
    # systemd must not expand $ or %; the shell gets the command verbatim.
    assert systemd_exec('gunicorn -b "127.0.0.1:$PORT" app:app') == (
        '"gunicorn -b \\"127.0.0.1:$$PORT\\" app:app"'
    )
    assert systemd_exec("echo 100% \\o/") == '"echo 100%% \\\\o/"'


@pytest.mark.parametrize("bad", ["", "a\nb", "x\x00", "x" * 501, "tab\there"])
def test_app_command_validation(bad: str) -> None:
    with pytest.raises(ValidationError):
        validate.app_command(bad)


@pytest.mark.parametrize("bad", ["", "8", "024", "24.1", "v24", "abc"])
def test_node_version_validation(bad: str) -> None:
    with pytest.raises(ValidationError):
        validate.node_version(bad)


def test_app_spec_checks() -> None:
    assert app_port("t0001") == 10001 and app_port("t9999") == 19999
    with pytest.raises(ValueError, match="runtime"):
        AppSpec("ruby", "x", 10001)
    with pytest.raises(ValueError, match="port"):
        AppSpec("python", "x", 20000)
    with pytest.raises(ValidationError):
        AppSpec("node", "npm start", 10001, node_version=None)


def test_create_nodejs_site(system: dict[str, Any]) -> None:
    mgr = _mgr(system)
    result = mgr.create(CreateRequest("node.example.com", site_type="nodejs", node_version="22"))
    t = result["tenant"]
    port = app_port(t)
    dropin = (system["paths"].systemd / f"dp-app@{t}.service.d" / "10-tenant.conf").read_text()
    assert f"PORT={port}" in dropin and f"SocketBindAllow=tcp:{port}" in dropin
    assert "/opt/ozenix/node/22/bin" in dropin and 'ExecStart=/bin/sh -c "npm start"' in dropin
    app_dir = system["paths"].tenant_root(t) / "app"
    assert (app_dir / "package.json").exists() and (app_dir / "server.js").exists()
    vhost = (system["conf"] / "node.example.com.conf").read_text()
    assert f"proxy_pass http://127.0.0.1:{port};" in vhost and "dp_connection_upgrade" in vhost
    started = [c for c in system["calls"] if c[:2] == ["/usr/bin/systemctl", "restart"]]
    assert [f"dp-app@{t}.service"] in [c[2:] for c in started]
    profile = (system["paths"].tenant_root(t) / ".profile").read_text()
    assert "/opt/ozenix/node/22/bin" in profile and f"PORT={port}" in profile
    assert f"dp-app@{t}.service" in mgr._units(t)

    status = mgr.app_status("node.example.com")
    assert status["runtime"] == "node" and status["port"] == port
    changed = mgr.app_set("node.example.com", start="node dist/main.js", node_version="26")
    assert changed["changed"] and changed["node_version"] == "26"
    dropin = (system["paths"].systemd / f"dp-app@{t}.service.d" / "10-tenant.conf").read_text()
    assert "/opt/ozenix/node/26/bin" in dropin and '"node dist/main.js"' in dropin
    assert mgr.app_set("node.example.com", start="node dist/main.js")["changed"] is False
    assert mgr.app_restart("node.example.com")["restarted"]
    with pytest.raises(PreconditionFailed, match="not installed"):
        mgr.app_set("node.example.com", node_version="20")


def test_create_python_site(system: dict[str, Any]) -> None:
    mgr = _mgr(system)
    result = mgr.create(
        CreateRequest("py.example.com", site_type="python", start=".venv/bin/gunicorn app:app")
    )
    t = result["tenant"]
    dropin = (system["paths"].systemd / f"dp-app@{t}.service.d" / "10-tenant.conf").read_text()
    assert f"{system['paths'].tenant_root(t)}/app/.venv/bin" in dropin
    assert (system["paths"].tenant_root(t) / "app" / "app.py").exists()
    with pytest.raises(PreconditionFailed, match="Python site"):
        mgr.app_set("py.example.com", node_version="24")
    assert ".venv/bin/activate" in (system["paths"].tenant_root(t) / ".profile").read_text()


def test_app_site_preconditions(system: dict[str, Any]) -> None:
    mgr = _mgr(system)
    with pytest.raises(PreconditionFailed, match="are for --type"):
        mgr.create(CreateRequest("php.example.com", node_version="24"))
    with pytest.raises(PreconditionFailed, match="only for --type nodejs"):
        mgr.create(CreateRequest("p.example.com", site_type="python", node_version="24"))
    with pytest.raises(PreconditionFailed, match="not installed"):
        mgr.create(CreateRequest("n.example.com", site_type="nodejs", node_version="20"))
    bare = dataclasses.replace(HOST, node_versions=(), default_node_version="", python_sites=False)
    with pytest.raises(PreconditionFailed, match="Node.js is not installed"):
        _mgr(system, bare).create(CreateRequest("n.example.com", site_type="nodejs"))
    with pytest.raises(PreconditionFailed, match="not enabled"):
        _mgr(system, bare).create(CreateRequest("p.example.com", site_type="python"))
    mgr.create(CreateRequest("plain.example.com"))
    with pytest.raises(PreconditionFailed, match="not a Node.js or Python site"):
        mgr.app_status("plain.example.com")
    # PHP sites can use any installed PHP version.
    eight_two = mgr.create(CreateRequest("old.example.com", php_version="8.2"))
    assert eight_two["php_version"] == "8.2"


def test_app_cli_handlers(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from test_phase8 import _ctx

    mgr = _mgr(system)
    mgr.create(CreateRequest("node.example.com", site_type="nodejs"))
    monkeypatch.setattr(site_handlers, "_manager", lambda ctx: mgr)
    ctx = _ctx(system, "node.example.com")
    shown = site_handlers.app_status(ctx, argparse.Namespace())
    assert "Node.js 24" in shown.text[0]
    assert "restarted" in site_handlers.app_restart(ctx, argparse.Namespace()).text[0]
    with pytest.raises(UsageError, match="nothing to change"):
        site_handlers.app_set(ctx, argparse.Namespace(start=None, node_version=None))
    done = site_handlers.app_set(ctx, argparse.Namespace(start="node app.js", node_version=None))
    assert "node app.js" in done.text[0]
    same = site_handlers.app_set(ctx, argparse.Namespace(start="node app.js", node_version=None))
    assert same.text == ["Nothing changed."]
