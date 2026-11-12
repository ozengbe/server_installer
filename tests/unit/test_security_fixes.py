"""Fixes from the security review of the site-user changes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from test_apps import HOST, _mgr

from ozenix.isolation import logins
from ozenix.isolation.limits import TenantLimits
from ozenix.security.site_audit import _parse_env
from ozenix.sites.lifecycle import CreateRequest

jinja2 = pytest.importorskip("jinja2")
ROOT = Path(__file__).resolve().parents[2]


def test_site_users_are_inside_the_egress_policy() -> None:
    text = (ROOT / "ansible/roles/firewall/templates/ozenix.nft.j2").read_text()
    assert "meta skuid 20000-39999 jump tenant_egress" in text  # runtime + site users
    assert "meta skuid 30000-39999 tcp dport 22 accept" in text  # git over SSH only


def test_nginx_checks_symlinks_from_the_site_root(system: dict[str, Any]) -> None:
    mgr = _mgr(system, HOST)
    for kind, name in (("php", "a.example.com"), ("laravel", "b.example.com")):
        t = mgr.create(CreateRequest(name, site_type=kind))["tenant"]
        vhost = (system["conf"] / f"{name}.conf").read_text()
        root = system["paths"].tenant_root(t)
        assert f"disable_symlinks if_not_owner from={root};" in vhost
        assert "from=$document_root" not in vhost
    vhost = (system["conf"] / "b.example.com.conf").read_text()
    storage = vhost.split("location ^~ /storage/ {", 1)[1].split("\n    }\n", 1)[0]
    assert "location ~ /\\. { return 404; }" in storage and "env|" in storage


def test_site_user_limits(tmp_path: Path) -> None:
    from ozenix.core.paths import Paths

    paths = Paths.under(tmp_path)
    for d in (paths.systemd, paths.system_etc):
        d.mkdir(parents=True)
    (paths.system_etc / "cron.deny").write_text("someone\n")
    calls: list[list[str]] = []

    def run(argv: list[str], **_kw: Any) -> Any:
        calls.append(argv)

    limits = TenantLimits()
    logins.apply(paths, "john", 30001, limits, run)
    logins.apply(paths, "john", 30001, limits, run)  # idempotent
    assert (paths.system_etc / "cron.deny").read_text() == "someone\njohn\n"
    assert (paths.system_etc / "at.deny").read_text() == "john\n"
    dropin = (paths.systemd / "user-30001.slice.d" / "50-ozenix.conf").read_text()
    assert (
        f"MemoryMax={limits.memory_max_mb}M" in dropin and f"TasksMax={limits.tasks_max}" in dropin
    )
    logins.remove(paths, "john", 30001, run)
    assert (paths.system_etc / "cron.deny").read_text() == "someone\n"
    assert not (paths.systemd / "user-30001.slice.d").exists()
    logins.end_sessions("t0001-deploy", run)
    assert ["/usr/bin/loginctl", "terminate-user", "t0001-deploy"] in calls
    with pytest.raises(Exception):  # noqa: B017 - any validation error
        logins.apply(paths, "root", 0, limits, run)


def test_refresh_all_is_idempotent(system: dict[str, Any]) -> None:
    mgr = _mgr(system, HOST)
    t = mgr.create(CreateRequest("shop.example.com", site_type="laravel"))["tenant"]
    vhost = system["conf"] / "shop.example.com.conf"
    first = mgr.refresh_all()
    assert first["problems"] == {}
    assert mgr.refresh_all()["changed"] == {}  # nothing left to change
    # An old vhost (as left by a previous release) is brought up to date.
    vhost.write_text(
        vhost.read_text().replace(f"from={system['paths'].tenant_root(t)}", "from=$document_root")
    )
    pool = system["paths"].tenant_etc(t) / "php-fpm.conf"
    pool.write_text("STALE-CONFIG\n")
    again = mgr.refresh_all()
    assert set(again["changed"][t]) >= {
        "vhost:shop.example.com",
        "file:php-fpm.conf",
        f"restart:dp-php@{t}.service",
    }
    assert "STALE-CONFIG" not in pool.read_text()
    assert ["/usr/bin/systemctl", "try-restart", f"dp-php@{t}.service"] in system["calls"]
    assert mgr.refresh_all()["changed"] == {}


def test_parse_env_refuses_fifos(tmp_path: Path) -> None:
    fifo = tmp_path / ".env"
    os.mkfifo(fifo)
    assert _parse_env(fifo) == {}  # returns at once instead of blocking


def test_exec_profile_only_allows_known_programs(system: dict[str, Any]) -> None:
    mgr = _mgr(system, HOST)
    t = mgr.create(CreateRequest("node.example.com", site_type="nodejs"))["tenant"]
    profile = (system["paths"].apparmor / f"tenant-{t}").read_text()
    php, exec_part = profile.split(f"profile ozenix-tenant-{t}-exec ", 1)
    assert " ix," not in php and "mrix" not in php  # PHP still may not run programs
    for allowed in ("/usr/bin/php[0-9]* mrix", "/opt/ozenix/node/** mrix", "/usr/bin/dash mrix"):
        assert allowed in exec_part
    assert "/usr/bin/curl" not in exec_part and "/bin/** " not in exec_part
    unit = (ROOT / "ansible/roles/isolation/files/dp-app@.service").read_text()
    assert "AppArmorProfile=ozenix-tenant-%i-exec" in unit
