"""Laravel sites (read-only code, storage in data/, scheduler, queue) and .env security."""

from __future__ import annotations

import argparse
import os
import pwd
from pathlib import Path
from typing import Any

import pytest
from test_apps import HOST, _mgr

from ozenix.cli import site_handlers
from ozenix.core.errors import PreconditionFailed
from ozenix.security.report import SecurityReport
from ozenix.security.site_audit import SiteAuditor, _parse_env
from ozenix.sites.lifecycle import CreateRequest


def test_create_laravel_site(system: dict[str, Any]) -> None:
    mgr = _mgr(system, HOST)
    result = mgr.create(CreateRequest("shop.example.com", site_type="laravel", php_version="8.4"))
    t = result["tenant"]
    root = system["paths"].tenant_root(t)
    assert system["registry"].get_site("shop.example.com").site_type == "php"
    settings = system["registry"].get_tenant_settings(t)
    assert settings["framework"] == "laravel" and settings["php_version"] == "8.4"

    pool = (system["paths"].tenant_etc(t) / "php-fpm.conf").read_text()
    assert f"env[LARAVEL_STORAGE_PATH] = {root}/data/storage" in pool
    assert f"env[APP_CONFIG_CACHE] = {root}/data/cache/config.php" in pool
    assert 'php_admin_value[variables_order] = "EGPCS"' in pool
    env = (system["paths"].tenant_etc(t) / "laravel.env").read_text()
    assert "PHP_BIN=/usr/bin/php8.4" in env and f"LARAVEL_STORAGE_PATH={root}/data/storage" in env

    vhost = (system["conf"] / "shop.example.com.conf").read_text()
    assert "location = /index.php {" in vhost  # only the front controller runs PHP
    assert f"alias {root}/data/storage/app/public/;" in vhost
    assert "try_files $uri $uri/ /index.php?$query_string;" in vhost

    mkdir = next(c for c in system["calls"] if c[0] == "/usr/bin/setpriv" and "/usr/bin/mkdir" in c)
    assert "--no-new-privs" in mkdir and mkdir[mkdir.index("-m") + 1] == "2770"
    assert f"{root}/data/storage/framework/views" in mkdir and f"{root}/data/cache" in mkdir
    assert ["/usr/bin/systemctl", "enable", "--now", f"dp-laravel-schedule@{t}.timer"] in system[
        "calls"
    ]
    assert f"dp-laravel-schedule@{t}.timer" in mgr._units(t)
    profile = (root / ".profile").read_text()
    assert "alias php='/usr/bin/php8.4 -d variables_order=EGPCS'" in profile
    assert f"export LARAVEL_STORAGE_PATH={root}/data/storage" in profile
    assert "umask 027" in profile

    on = mgr.laravel_queue("shop.example.com", True)
    assert on["queue"] and f"dp-laravel-queue@{t}.service" in mgr._units(t)
    mgr.laravel_queue("shop.example.com", False)
    assert f"dp-laravel-queue@{t}.service" not in mgr._units(t)
    mgr.create(CreateRequest("plain.example.com"))
    with pytest.raises(PreconditionFailed, match="not a Laravel site"):
        mgr.laravel_queue("plain.example.com", True)


def test_laravel_cli(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from test_phase8 import _ctx

    mgr = _mgr(system, HOST)
    mgr.create(CreateRequest("shop.example.com", site_type="laravel"))
    monkeypatch.setattr(site_handlers, "_manager", lambda ctx: mgr)
    ctx = _ctx(system, "shop.example.com")
    assert "started" in site_handlers.laravel_queue(ctx, argparse.Namespace(state="on")).text[0]
    assert "stopped" in site_handlers.laravel_queue(ctx, argparse.Namespace(state="off")).text[0]
    assert site_handlers.env_protect(ctx, argparse.Namespace()).text == ["No .env file in ~/app."]


def test_env_protect(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = _mgr(system, HOST)
    t = mgr.create(CreateRequest("shop.example.com", site_type="laravel"))["tenant"]
    app = system["paths"].tenant_root(t) / "app"
    (app / ".env").write_text("APP_KEY=x\n")
    (app / ".env").chmod(0o666)
    (app / ".env.example").write_text("APP_KEY=\n")
    (app / ".env.example").chmod(0o644)
    (app / ".env.production").symlink_to("/etc/passwd")
    owners: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: owners.append((uid, gid)))
    result = mgr.env_protect("shop.example.com")
    assert result["fixed"] == [".env"] and "symlink" in result["skipped"][0]
    assert (app / ".env").stat().st_mode & 0o777 == 0o640
    assert owners and owners[0][0] == system["registry"].get_tenant(t).uid + 10000
    assert (app / ".env.example").stat().st_mode & 0o777 != 0o640  # untouched
    assert mgr.env_protect("shop.example.com").__class__ is dict


def test_parse_env(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        '# comment\nAPP_ENV=local\nexport APP_DEBUG=true\nAPP_KEY="base64:a #b"\n'
        "DB_PASSWORD=secret # inline\nBROKEN\n"
    )
    values = _parse_env(env)
    assert values["APP_ENV"] == "local" and values["APP_DEBUG"] == "true"
    assert values["APP_KEY"] == "base64:a #b" and values["DB_PASSWORD"] == "secret"
    assert "BROKEN" not in values
    link = tmp_path / "link"
    link.symlink_to(env)
    assert _parse_env(link) == {}  # never follows symlinks


def _auditor(system: dict[str, Any], t: str, runtime_uid: int) -> SiteAuditor:
    def getpwnam(name: str) -> Any:
        if name == t:
            return pwd.struct_passwd((t, "x", runtime_uid, runtime_uid, "", "", ""))
        raise KeyError(name)

    return SiteAuditor(system["paths"], getpwnam=getpwnam)


def test_env_audit(system: dict[str, Any]) -> None:
    mgr = _mgr(system, HOST)
    t = mgr.create(CreateRequest("shop.example.com", site_type="laravel"))["tenant"]
    root = system["paths"].tenant_root(t)
    app = root / "app"
    env = app / ".env"
    env.write_text("APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:abc\n")
    env.chmod(0o640)
    rep = SecurityReport(t)
    _auditor(system, t, os.getuid() + 1)._env_files(rep, t, "shop.example.com")
    assert rep.worst == "ok", [(f.id, f.detail) for f in rep.problems()]

    env.write_text("APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=\n")
    env.chmod(0o666)
    (app / "public" / ".env.backup").write_text("leak")
    rep = SecurityReport(t)
    _auditor(system, t, os.getuid())._env_files(rep, t, "shop.example.com")
    failed = {f.id: f for f in rep.problems()}
    assert set(failed) == {"ENV-PUBLIC", "ENV-PERMS", "ENV-DEBUG", "ENV-APP-ENV", "ENV-APP-KEY"}
    assert (
        failed["ENV-PUBLIC"].severity == "critical"
        and "public/.env.backup" in failed["ENV-PUBLIC"].detail
    )
    perms = failed["ENV-PERMS"].detail
    assert "owned by the PHP user" in perms and "writable by group/others" in perms
    assert "s3cr3t-Value" not in str(rep.as_dict())  # values are never reported
