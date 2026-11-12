from __future__ import annotations

import grp
import os
import pwd
import socket
import struct
import threading
from pathlib import Path
from typing import Any

import pytest

from ozenix.core import proc
from ozenix.core.config import HostFacts, load_host
from ozenix.core.errors import OperationFailed, PreconditionFailed, ValidationError
from ozenix.core.paths import Paths
from ozenix.isolation import db, fcgi, status
from ozenix.isolation.limits import TenantLimits
from ozenix.isolation.provision import Provisioner
from ozenix.isolation.render import TenantSpec, render

HOST = HostFacts(release="26.04", default_php_version="8.5", php_versions=("8.5",))


def spec(**kw: Any) -> TenantSpec:
    base: dict[str, Any] = {
        "tenant": "t0001",
        "uid": 20001,
        "php_version": "8.5",
        "limits": TenantLimits(),
    }
    base.update(kw)
    return TenantSpec(**base)


# --- limits ----------------------------------------------------------------


def test_limits_defaults_and_roundtrip() -> None:
    lim = TenantLimits()
    assert TenantLimits.from_dict(lim.to_dict()) == lim


@pytest.mark.parametrize(
    "kw",
    [
        {"cpu_quota_percent": 0},
        {"memory_max_mb": 64},
        {"tasks_max": True},
        {"memory_high_mb": 2048, "memory_max_mb": 1024},
        {"php_memory_limit_mb": 1024, "memory_max_mb": 1024},
        {"php_max_children": "8"},
    ],
)
def test_limits_rejected(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TenantLimits(**kw)


def test_limits_unknown_key() -> None:
    with pytest.raises(ValidationError, match="unknown limit"):
        TenantLimits.from_dict({"bogus": 1})


# --- rendering --------------------------------------------------------------


def test_render_all_files(tmp_path: Path) -> None:
    paths = Paths.under(tmp_path)
    files = {f.path.name: f for f in render(spec(), paths, HOST)}
    assert set(files) == {
        "php-fpm.conf",
        "10-tenant.conf",
        "dptenants-t0001.slice",
        "tenant-t0001",
        "cache.conf",
    }
    for f in render(spec(), paths, HOST):
        assert "${" not in f.content, f.path
    php = files["php-fpm.conf"].content
    assert f"listen = {paths.php_socket('t0001')}" in php
    assert "listen.mode = 0660" in php
    assert "php_admin_value[open_basedir]" in php
    assert "shell_exec" in php and "pcre.jit] = off" in php
    assert files["php-fpm.conf"].mode == 0o640 and files["php-fpm.conf"].group_is_tenant
    aa = files["tenant-t0001"].content
    assert "profile ozenix-tenant-t0001" in aa and "/usr/bin/valkey-server mr," in aa
    assert "t0002" not in aa
    sl = files["dptenants-t0001.slice"].content
    assert "MemoryMax=1024M" in sl and "CPUQuota=100%" in sl and "TasksMax=256" in sl


def test_render_without_cache_and_open_basedir(tmp_path: Path) -> None:
    files = render(spec(cache=False, php_open_basedir=False), Paths.under(tmp_path), HOST)
    names = {f.path.name for f in files}
    assert "cache.conf" not in names
    php = next(f for f in files if f.path.name == "php-fpm.conf").content
    assert "php_admin_value[open_basedir]" not in php


def test_render_cache_dropin_uses_engine(tmp_path: Path) -> None:
    redis_host = HostFacts(cache_engine="redis")
    files = render(spec(), Paths.under(tmp_path), redis_host)
    dropins = [f.content for f in files if f.path.name == "10-tenant.conf"]
    assert any("/usr/bin/redis-server" in c for c in dropins)


@pytest.mark.parametrize(
    "kw", [{"tenant": "t1"}, {"tenant": "../x"}, {"php_version": "7.4"}, {"uid": 1000}]
)
def test_spec_validation(kw: dict[str, Any]) -> None:
    with pytest.raises((ValidationError, ValueError)):
        spec(**kw)


def test_spec_derived_names() -> None:
    s = spec()
    assert (s.deploy_user, s.deploy_uid, s.slice) == (
        "t0001-deploy",
        30001,
        "dptenants-t0001.slice",
    )


# --- database SQL -------------------------------------------------------------


def test_db_sql() -> None:
    sql = db.create_user_sql("t0001", "abc-DEF_123")
    assert "'t0001'@'localhost'" in sql and "unix_socket" in sql
    assert "ON `t0001\\_%`.*" in sql and "MAX_USER_CONNECTIONS 20" in sql
    assert db.drop_user_sql("t0001") == "DROP USER IF EXISTS 't0001'@'localhost';\n"
    assert "`t0001_app`" in db.create_database_sql("t0001", "app")
    assert db.drop_databases_sql("t0001", ["t0001_app"]) == "DROP DATABASE IF EXISTS `t0001_app`;\n"
    assert len(db.new_password()) >= 32


@pytest.mark.parametrize("bad", ["", "a'b", "x;DROP", "a b"])
def test_db_password_checked(bad: str) -> None:
    with pytest.raises(ValueError):
        db.create_user_sql("t0001", bad)


def test_db_rejects_foreign_or_bad_names() -> None:
    with pytest.raises(ValueError):
        db.drop_databases_sql("t0001", ["t0002_app"])
    with pytest.raises(ValidationError):
        db.drop_databases_sql("t0001", ["t0001_App;"])
    with pytest.raises(ValidationError):
        db.create_database_sql("t0001", "a-b")


def test_db_queries_use_stdin() -> None:
    calls: list[tuple[list[str], str]] = []

    def fake(argv: list[str], **kw: Any) -> proc.Result:
        calls.append((argv, kw["stdin"]))
        out = "t0001_app\nt0001_wp\n" if "schemata" in kw["stdin"] else "1\n"
        return proc.Result(tuple(argv), 0, out, "")

    assert db.list_databases("t0001", fake) == ["t0001_app", "t0001_wp"]
    assert db.user_exists("t0001", fake) is True
    assert all(argv == [db.MARIADB, "--batch", "--skip-column-names"] for argv, _ in calls)


# --- FastCGI client --------------------------------------------------------------


def test_encode_params_lengths() -> None:
    enc = fcgi.encode_params({"A": "x" * 200})
    assert enc[0] == 1 and enc[1:5] == struct.pack("!I", 200 | 0x80000000)


def test_parse_response() -> None:
    status_code, headers, body = fcgi.parse_response(b"Status: 403 Forbidden\r\nX-A: b\r\n\r\nno")
    assert (status_code, headers["x-a"], body) == (403, "b", b"no")
    assert fcgi.parse_response(b"Content-Type: x\n\nok")[0] == 200


def _fake_fpm(sock_path: Path, reply: bytes) -> threading.Thread:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            data = b""
            while b"\x01\x05\x00\x01\x00\x00" not in data:  # empty STDIN record = end of request
                data += conn.recv(65536)
            conn.sendall(
                fcgi._record(fcgi.STDOUT, reply)
                + fcgi._record(fcgi.STDERR, b"warn")
                + fcgi._record(fcgi.END_REQUEST, struct.pack("!IB3x", 0, 0))
            )
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_fcgi_request_roundtrip(tmp_path: Path) -> None:
    sock = tmp_path / "fpm.sock"
    thread = _fake_fpm(sock, b'Content-Type: application/json\r\n\r\n{"ok": true}')
    resp = fcgi.request(
        sock, fcgi.php_params(Path("/srv/tenants/t0001/app/public/p.php"), query="a=1")
    )
    thread.join(5)
    assert resp.status == 200 and resp.body == b'{"ok": true}' and resp.stderr == b"warn"


def test_fcgi_closed_connection(tmp_path: Path) -> None:
    sock = tmp_path / "dead.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock))
    server.listen(1)

    def close_immediately() -> None:
        conn, _ = server.accept()
        conn.close()
        server.close()

    threading.Thread(target=close_immediately, daemon=True).start()
    with pytest.raises(fcgi.FastCGIError):
        fcgi.request(sock, {"A": "b"}, timeout=5)


# --- status parsing -----------------------------------------------------------------


def test_apparmor_mode(tmp_path: Path) -> None:
    f = tmp_path / "profiles"
    f.write_text("ozenix-tenant-t0001 (enforce)\nnginx (complain)\n")
    assert status.apparmor_mode("ozenix-tenant-t0001", f) == "enforce"
    assert status.apparmor_mode("ozenix-tenant-t0002", f) == "not loaded"
    assert status.apparmor_mode("x", tmp_path / "missing") == "unknown"


def test_exposure_and_tenant_status(tmp_path: Path) -> None:
    def fake(argv: list[str], **_kw: Any) -> proc.Result:
        if argv[0] == status.SYSTEMD_ANALYZE:
            out = "→ Overall exposure level for dp-php@t0001.service: 1.4 OK :-)\n"
        else:
            out = "ActiveState=active\nSubState=running\nMemoryMax=1073741824\n"
        return proc.Result(tuple(argv), 0, out, "")

    st = status.tenant_status(Paths.under(tmp_path), "t0001", run=fake)
    assert st["exposure"]["dp-php@t0001.service"] == 1.4
    assert st["units"]["dp-php@t0001.service"]["ActiveState"] == "active"
    assert st["sockets"] == {"php": False, "cache": False}

    def broken(*_a: Any, **_k: Any) -> proc.Result:
        raise OperationFailed("nope")

    assert status.exposure_score("x", broken) is None
    assert status.tenant_status(Paths.under(tmp_path), "t0001", run=broken)["slice"] == {}


# --- host facts -------------------------------------------------------------------


def test_load_host(tmp_path: Path) -> None:
    assert load_host(tmp_path / "missing.toml") == HostFacts()
    f = tmp_path / "host.toml"
    f.write_text(
        '[host]\nrelease = "26.04"\ndefault_php_version = "8.5"\nphp_versions = ["8.5"]\n'
        'cache_engine = "valkey"\nnginx_user = "nginx"\n'
    )
    facts = load_host(f)
    assert facts.default_php_version == "8.5" and facts.cache_server == "/usr/bin/valkey-server"


@pytest.mark.parametrize(
    "content",
    [
        "[other]\nx = 1\n",
        "[host]\nbogus = 1\n",
        '[host]\nphp_versions = "8.5"\n',
        '[host]\nphp_versions = ["8.5"]\ndefault_php_version = "8.3"\n',
        '[host]\ncache_engine = "memcached"\n',
        '[host]\nnginx_user = "root"\n',
        "not = = toml",
    ],
)
def test_load_host_rejects(tmp_path: Path, content: str) -> None:
    f = tmp_path / "host.toml"
    f.write_text(content)
    with pytest.raises(ValidationError):
        load_host(f)


# --- provisioner (fake system) ---------------------------------------------------------


@pytest.fixture
def fake_system(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Paths, list[list[str]]]:
    paths = Paths.under(tmp_path / "root")
    for d in (
        paths.tenants,
        paths.etc / "tenants",
        paths.log / "tenants",
        paths.var_lib / "cache",
        paths.systemd,
        paths.apparmor,
        paths.run,
        paths.system_etc,
    ):
        d.mkdir(parents=True, mode=0o755)
    calls: list[list[str]] = []
    users: set[str] = set()

    def fake_run(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(list(argv))
        if argv[0] == "/usr/sbin/useradd":
            users.add(argv[-1])
        if argv[:3] == ["/usr/bin/systemctl", "enable", "--now"]:
            for sock in (paths.php_socket("t0001"), paths.cache_socket("t0001")):
                sock.parent.mkdir(parents=True, exist_ok=True)
                s = socket.socket(socket.AF_UNIX)
                s.bind(str(sock))
                s.close()
        return proc.Result(tuple(argv), 0, "", "")

    def getpwnam(name: str) -> Any:
        if name in users:
            return pwd.struct_passwd((name, "x", 0, 0, "", "", ""))
        raise KeyError(name)

    def getpwuid(uid: int) -> Any:
        raise KeyError(uid)

    def getgrgid(gid: int) -> Any:
        raise KeyError(gid)

    def getgrnam(name: str) -> Any:
        return grp.struct_group((name, "x", os.getgid(), []))

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(pwd, "getpwuid", getpwuid)
    monkeypatch.setattr(grp, "getgrgid", getgrgid)
    monkeypatch.setattr(grp, "getgrnam", getgrnam)
    if os.geteuid() != 0:  # CI runs unprivileged: ownership changes become no-ops
        monkeypatch.setattr(os, "chown", lambda *a, **k: None)
        monkeypatch.setattr(os, "fchown", lambda *a, **k: None)
    calls.clear()
    return paths, calls


def _run_steps(steps: list[Any]) -> list[str]:
    done = []
    for step in steps:
        step.apply()
        done.append(step.name)
    return done


def test_provision_plan_and_execution(fake_system: tuple[Paths, list[list[str]]]) -> None:
    paths, calls = fake_system
    prov = Provisioner(paths, HOST, run=lambda argv, **kw: _record(calls, argv), socket_timeout=1)
    prov.run = fake_system_run(paths, calls)
    steps = prov.create_steps(spec(), db_password="pw_123")
    names = [s.name for s in steps]
    assert names == [
        "preflight",
        "group",
        "runtime-user",
        "deploy-user",
        "site-user-limits",
        "web-server-access",
        "directories",
        "configuration",
        "apparmor",
        "database-user",
        "systemd-reload",
        "start",
        "verify",
    ]
    assert all(
        s.undo is not None for s in steps if s.name not in ("preflight", "systemd-reload", "verify")
    )
    _run_steps(steps)
    root = paths.tenant_root("t0001")
    assert (root / "app" / "public").is_dir() and (root / "data").is_dir()
    assert (root / "data").stat().st_mode & 0o7777 == 0o2770
    secret = paths.tenant_etc("t0001") / "secrets" / "db.env"
    assert "DB_PASSWORD=pw_123" in secret.read_text() and secret.stat().st_mode & 0o777 == 0o640
    flat = [" ".join(c) for c in calls]
    assert any(c.startswith("/usr/sbin/groupadd --gid 20001 t0001") for c in flat)
    assert any(
        c == "/usr/bin/systemctl enable --now dp-cache@t0001.service dp-php@t0001.service"
        for c in flat
    )

    # undo everything in reverse, like a failed transaction would
    for step in reversed(steps):
        if step.undo:
            step.undo()
    assert not root.exists()
    assert not secret.exists()


def _record(calls: list[list[str]], argv: list[str]) -> proc.Result:
    calls.append(list(argv))
    return proc.Result(tuple(argv), 0, "", "")


def fake_system_run(paths: Paths, calls: list[list[str]]) -> Any:
    def run(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(list(argv))
        if argv[:3] == ["/usr/bin/systemctl", "enable", "--now"]:
            for sock in (paths.php_socket("t0001"), paths.cache_socket("t0001")):
                sock.parent.mkdir(parents=True, exist_ok=True)
                s = socket.socket(socket.AF_UNIX)
                s.bind(str(sock))
                s.close()
        return proc.Result(tuple(argv), 0, "", "")

    return run


def test_provision_refuses_taken_identity(
    fake_system: tuple[Paths, list[list[str]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _calls = fake_system
    monkeypatch.setattr(
        pwd, "getpwnam", lambda name: pwd.struct_passwd((name, "x", 1, 1, "", "", ""))
    )
    steps = Provisioner(paths, HOST, run=lambda *a, **k: proc.Result((), 0, "", "")).create_steps(
        spec(), db_password="pw"
    )
    with pytest.raises(PreconditionFailed, match="already exists"):
        steps[0].apply()


def test_provision_requires_installer_dirs(tmp_path: Path) -> None:
    steps = Provisioner(Paths.under(tmp_path / "empty"), HOST).create_steps(
        spec(), db_password="pw"
    )
    with pytest.raises(PreconditionFailed, match="is missing") as info:
        steps[0].apply()
    assert info.value.hint is not None and "installer" in info.value.hint


def test_provision_verify_times_out(fake_system: tuple[Paths, list[list[str]]]) -> None:
    paths, calls = fake_system
    prov = Provisioner(paths, HOST, run=lambda argv, **kw: _record(calls, argv), socket_timeout=0.3)
    verify = prov.create_steps(spec(), db_password="pw")[-1]
    with pytest.raises(OperationFailed, match="did not start"):
        verify.apply()


def test_purge_is_best_effort(fake_system: tuple[Paths, list[list[str]]]) -> None:
    paths, calls = fake_system
    prov = Provisioner(paths, HOST, run=fake_system_run(paths, calls), socket_timeout=1)
    _run_steps(prov.create_steps(spec(), db_password="pw_1"))
    problems = prov.purge("t0001")
    assert problems == []
    assert not paths.tenant_root("t0001").exists() and not paths.tenant_etc("t0001").exists()
    flat = [" ".join(c) for c in calls]
    assert any(c.startswith("/usr/sbin/userdel t0001") for c in flat)
    assert "/usr/bin/systemctl stop dptenants-t0001.slice" in flat
    assert any(c.startswith("/usr/bin/systemctl reset-failed") for c in flat)

    def failing(argv: list[str], **_kw: Any) -> proc.Result:
        raise OperationFailed("systemctl broke")

    problems = Provisioner(paths, HOST, run=failing).purge("t0002")
    assert problems and all(isinstance(p, str) for p in problems)
