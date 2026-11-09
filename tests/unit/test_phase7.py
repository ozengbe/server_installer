from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
from typing import Any

import pytest

from domainpilot import health, updates
from domainpilot.cli import ops_handlers
from domainpilot.core import fsutil, proc
from domainpilot.core.errors import ExitCode, OperationFailed, PreconditionFailed, UsageError
from domainpilot.isolation.limits import TenantLimits
from domainpilot.optimize import profiles
from domainpilot.optimize.server import Layout, ServerTuner, parse_db_values, render
from domainpilot.optimize.site import WorkerStats, measure_workers, recommend_limits
from domainpilot.optimize.snapshot import SnapshotStore

MIB = 1024 * 1024


def facts(
    mem_mb: int, tenants: int = 3, promised: int = 3072, ssd: bool = True
) -> profiles.HostFacts:
    return profiles.HostFacts(
        cpu_count=4,
        memory_bytes=mem_mb * MIB,
        ssd=ssd,
        tenants=tenants,
        tenant_memory_promised_mb=promised,
    )


# --- profiles -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mem", "profile"), [(1024, "small"), (4096, "medium"), (16384, "large"), (65536, "dedicated")]
)
def test_choose_profile(mem: int, profile: str) -> None:
    assert profiles.choose_profile(facts(mem)) == profile


def test_recommend_is_deterministic_and_sane() -> None:
    f = facts(24 * 1024, tenants=40)
    t = profiles.recommend(f)
    assert t == profiles.recommend(f)  # same input, same output: no load-driven churn
    assert t.profile == "large" and t.mariadb_buffer_pool_mb % 64 == 0
    assert t.mariadb_buffer_pool_mb <= 24 * 1024 * 0.25
    assert t.mariadb_max_connections >= 40 * 20  # every tenant may use 20 connections
    assert profiles.recommend(facts(1024, ssd=False)).mariadb_io_capacity == 200
    assert profiles.recommend(f, "high-traffic").nginx_worker_connections == 32768
    with pytest.raises(ValueError):
        profiles.recommend(f, "turbo")


def test_overcommit_warnings() -> None:
    assert (
        profiles.overcommit_warnings(facts(8192, promised=1024), profiles.recommend(facts(8192)))
        == []
    )
    mild = profiles.overcommit_warnings(facts(4096, promised=4096), profiles.recommend(facts(4096)))
    assert mild and "fine while" in mild[0]
    heavy = profiles.overcommit_warnings(
        facts(2048, promised=20000), profiles.recommend(facts(2048))
    )
    assert "2x overcommit" in heavy[0]


def test_read_facts(tmp_path: Path) -> None:
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc" / "meminfo").write_text("MemTotal:  8000000 kB\n")
    for name, rot in (("sda", "1"), ("nvme0n1", "0"), ("loop0", "1")):
        q = tmp_path / "block" / name / "queue"
        q.mkdir(parents=True)
        (q / "rotational").write_text(rot + "\n")
    f = profiles.read_facts(
        tenants=2,
        tenant_memory_promised_mb=2048,
        proc_root=tmp_path / "proc",
        sys_block=tmp_path / "block",
        cpu_count=8,
    )
    assert f.memory_mb == 7812 and f.ssd is False and f.cpu_count == 8  # sda is spinning
    empty = profiles.read_facts(
        tenants=0,
        tenant_memory_promised_mb=0,
        proc_root=tmp_path / "none",
        sys_block=tmp_path / "none",
    )
    assert empty.memory_bytes == 0 and empty.ssd


# --- snapshots & server tuner -------------------------------------------------------------


def layout(tmp_path: Path) -> Layout:
    for d in ("nginx", "mysql", "php"):
        (tmp_path / d).mkdir(mode=0o755, parents=True)
    return Layout(
        nginx_events=tmp_path / "nginx" / "tuning-events.conf",
        nginx_http=tmp_path / "nginx" / "tuning-http.conf",
        mariadb=tmp_path / "mysql" / "98-domainpilot-tuning.cnf",
        php_conf_d=[tmp_path / "php"],
    )


def test_snapshot_roundtrip_is_byte_identical(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "snaps")
    existing = tmp_path / "a.conf"
    existing.write_bytes(b"original\x00bytes\n")
    existing.chmod(0o640)
    missing = tmp_path / "b.conf"
    snap = store.take("server", [existing, missing], note="test")
    existing.write_text("changed")
    missing.write_text("new file")
    changed = store.restore(snap)
    assert set(changed) == {str(existing), str(missing)}
    assert (
        existing.read_bytes() == b"original\x00bytes\n" and existing.stat().st_mode & 0o777 == 0o640
    )
    assert not missing.exists()
    assert store.get(snap.id).note == "test" and store.entries()[0].id == snap.id
    with pytest.raises(PreconditionFailed):
        store.get("nope")
    (store.root / snap.id / "0.orig").write_bytes(b"tampered")
    with pytest.raises(PreconditionFailed, match="damaged"):
        store.restore(snap)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
def test_snapshot_restores_owner(tmp_path: Path) -> None:
    """php-fpm.conf is root:<tenant> 0640; a rollback must not make it root:root."""
    store = SnapshotStore(tmp_path / "snaps")
    conf = tmp_path / "php-fpm.conf"
    conf.write_text("pm.max_children = 8\n")
    conf.chmod(0o640)
    os.chown(conf, 0, 20001)
    snap = store.take("site:x", [conf])
    fsutil.atomic_write(conf, "pm.max_children = 22\n", mode=0o640, uid=0, gid=0)
    store.restore(snap)
    assert conf.stat().st_gid == 20001 and conf.read_text() == "pm.max_children = 8\n"


def test_snapshot_prune(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from domainpilot.optimize import snapshot as snapmod

    monkeypatch.setattr(snapmod, "KEEP", 2)
    store = SnapshotStore(tmp_path / "s")
    ids = [store.take("server", [], note=str(i)).id for i in range(4)]
    assert len(store.entries()) == 2 and {s.id for s in store.entries()} <= set(ids)


def test_server_tuner_apply_and_rollback(tmp_path: Path) -> None:
    lay = layout(tmp_path)
    lay.nginx_events.write_text("worker_connections 4096;\n")
    original = lay.nginx_events.read_bytes()
    calls: list[list[str]] = []
    sql: list[str] = []

    def run(argv: list[str], **kw: Any) -> proc.Result:
        calls.append(argv)
        if argv[0].endswith("mariadb"):
            sql.append(kw["stdin"])
        return proc.Result(tuple(argv), 0, "", "")

    reloads: list[int] = []
    tuner = ServerTuner(
        lay, SnapshotStore(tmp_path / "snaps"), run=run, nginx_reload=lambda: reloads.append(1)
    )
    tuning = profiles.recommend(facts(16384))
    diff = tuner.diff(tuning)
    assert {Path(c["path"]).name for c in diff} == {
        "tuning-events.conf",
        "tuning-http.conf",
        "98-domainpilot-tuning.cnf",
        "98-domainpilot-tuning.ini",
    }
    snap, warnings = tuner.apply(tuning)
    assert warnings == [] and reloads == [1]
    assert "worker_connections 8192;" in lay.nginx_events.read_text()
    assert f"SET GLOBAL innodb_buffer_pool_size = {tuning.mariadb_buffer_pool_mb * MIB};" in sql[0]
    assert ["/usr/bin/systemctl", "try-restart", "dp-php@*.service"] in calls
    assert tuner.diff(tuning) == []  # applied twice: no change
    _snap, changed, _w = tuner.rollback(snap.id)
    assert lay.nginx_events.read_bytes() == original  # byte-identical
    assert not lay.mariadb.exists() and str(lay.mariadb) in changed


def test_server_tuner_restores_on_nginx_failure(tmp_path: Path) -> None:
    lay = layout(tmp_path)
    lay.nginx_events.write_text("worker_connections 1024;\n")

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        if argv[0].endswith("nginx"):
            return proc.Result(tuple(argv), 1, "", "nginx: [emerg] bad\n")
        return proc.Result(tuple(argv), 0, "", "")

    tuner = ServerTuner(lay, SnapshotStore(tmp_path / "snaps"), run=run, nginx_reload=lambda: None)
    with pytest.raises(OperationFailed, match="nginx rejected"):
        tuner.apply(profiles.recommend(facts(16384)))
    assert lay.nginx_events.read_text() == "worker_connections 1024;\n"


def test_mariadb_live_failure_is_a_warning(tmp_path: Path) -> None:
    lay = layout(tmp_path)

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        if argv[0].endswith("mariadb"):
            raise OperationFailed("mariadb down")
        return proc.Result(tuple(argv), 0, "", "")

    tuner = ServerTuner(lay, SnapshotStore(tmp_path / "s"), run=run, nginx_reload=lambda: None)
    _snap, warnings = tuner.apply(profiles.recommend(facts(4096)))
    assert "next MariaDB restart" in warnings[0]


def _db_runner(live: list[dict[str, int]]) -> Any:
    """mariadb stub: SET statements are accepted, SELECTs answer from `live` in turn."""

    def run(argv: list[str], **kw: Any) -> proc.Result:
        if argv[0].endswith("mariadb") and kw.get("stdin", "").startswith("SELECT"):
            keys = [k.removeprefix("@@GLOBAL.") for k in kw["stdin"][7:-2].split(", ")]
            row = live.pop(0) if len(live) > 1 else live[0]
            return proc.Result(tuple(argv), 0, "\t".join(str(row[k]) for k in keys) + "\n", "")
        return proc.Result(tuple(argv), 0, "", "")

    return run


def test_mariadb_values_are_read_back(tmp_path: Path) -> None:
    lay = layout(tmp_path)
    tuning = profiles.recommend(facts(16384))
    wanted = {
        "innodb_buffer_pool_size": tuning.mariadb_buffer_pool_mb * MIB,
        "max_connections": tuning.mariadb_max_connections,
        "table_open_cache": tuning.mariadb_table_open_cache,
        "tmp_table_size": tuning.mariadb_tmp_table_mb * MIB,
        "max_heap_table_size": tuning.mariadb_tmp_table_mb * MIB,
        "innodb_io_capacity": tuning.mariadb_io_capacity,
    }
    # The buffer pool resizes in the background: first read old, then new.
    sleeps: list[float] = []
    resizing = [wanted | {"innodb_buffer_pool_size": 256 * MIB}, wanted]
    tuner = ServerTuner(
        lay,
        SnapshotStore(tmp_path / "a"),
        run=_db_runner(resizing),
        nginx_reload=lambda: None,
        sleep=sleeps.append,
    )
    _snap, warnings = tuner.apply(tuning)
    assert warnings == [] and sleeps == [1]

    # A value MariaDB refused (capped) is reported, never claimed.
    lay2 = layout(tmp_path / "b")
    capped = [wanted | {"innodb_buffer_pool_size": 256 * MIB}]
    tuner2 = ServerTuner(
        lay2,
        SnapshotStore(tmp_path / "b" / "s"),
        run=_db_runner(capped),
        nginx_reload=lambda: None,
        sleep=lambda _s: None,
    )
    _snap, warnings = tuner2.apply(tuning)
    assert len(warnings) == 1 and "innodb_buffer_pool_size = 268435456" in warnings[0]


def test_recommend_respects_buffer_pool_ceiling() -> None:
    f = facts(24 * 1024)
    assert profiles.recommend(f).mariadb_buffer_pool_mb > 256
    capped = profiles.HostFacts(**{**f.__dict__, "db_pool_max_mb": 300})
    assert profiles.recommend(capped).mariadb_buffer_pool_mb == 256  # whole 64 MiB chunks
    tiny = profiles.HostFacts(**{**f.__dict__, "db_pool_max_mb": 16})
    assert profiles.recommend(tiny).mariadb_buffer_pool_mb == 128


def test_db_pool_max_mb() -> None:
    def answer(out: str, rc: int = 0) -> Any:
        return lambda argv, **kw: proc.Result(tuple(argv), rc, out, "")

    assert ops_handlers._db_pool_max_mb(answer(f"{1024 * MIB}\n")) == 1024
    assert ops_handlers._db_pool_max_mb(answer("NULL\n")) is None
    assert ops_handlers._db_pool_max_mb(answer("", 1)) is None

    def boom(argv: list[str], **kw: Any) -> proc.Result:
        raise OperationFailed("no mariadb")

    assert ops_handlers._db_pool_max_mb(boom) is None


def test_render_and_parse_db() -> None:
    t = profiles.recommend(facts(4096))
    files = render(t, Layout(php_conf_d=[]))
    cnf = files[Layout().mariadb]
    assert parse_db_values(cnf)["max_connections"] == str(t.mariadb_max_connections)
    assert parse_db_values("evil = 1\nmax_connections = 5; DROP\n") == {}


# --- per-site tuning ------------------------------------------------------------------------


def test_measure_workers(tmp_path: Path) -> None:
    cg = tmp_path / "cg" / "dptenants.slice" / "dptenants-t0001.slice" / "dp-php@t0001.service"
    cg.mkdir(parents=True)
    (cg / "cgroup.procs").write_text("10\n11\n12\n99\n")
    procs = tmp_path / "proc"
    for pid, name, rss in (
        (10, "php-fpm8.5", 20000),
        (11, "php-fpm8.5", 80000),
        (12, "php-fpm8.5", 100000),
    ):
        (procs / str(pid)).mkdir(parents=True)
        (procs / str(pid) / "status").write_text(f"Name:\t{name}\nVmRSS:\t{rss} kB\n")
    stats = measure_workers("t0001", cgroup_root=tmp_path / "cg", proc_root=procs)
    assert stats == WorkerStats(2, 87)  # master (smallest) dropped
    assert measure_workers("t0002", cgroup_root=tmp_path / "cg", proc_root=procs) == WorkerStats(
        0, None
    )


def test_recommend_limits() -> None:
    base = TenantLimits()  # 1024 MiB max, 64 MiB cache
    measured, basis = recommend_limits(base, WorkerStats(4, 40))
    assert measured.php_max_children == (1024 - 64 - 64) // 40 and "measured" in basis
    assumed, basis2 = recommend_limits(base, WorkerStats(0, None))
    assert assumed.php_max_children == (1024 - 64 - 64) // 64 and "assumed" in basis2
    tiny = recommend_limits(
        TenantLimits(memory_max_mb=128, memory_high_mb=96, php_memory_limit_mb=64),
        WorkerStats(1, 500),
    )[0]
    assert tiny.php_max_children == 2


# --- updates --------------------------------------------------------------------------------

APT_LIST = """Listing... Done
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: 3.0.13-0ubuntu3.5]
nginx/noble 1.32.0-1~noble amd64 [upgradable from: 1.30.6-1~noble]
curl/noble-updates 8.5.0-2ubuntu10.7 amd64 [upgradable from: 8.5.0-2ubuntu10.6]
"""


def test_parse_upgradable() -> None:
    items = {p.name: p for p in updates.parse_upgradable(APT_LIST)}
    assert items["openssl"].security and not items["openssl"].major
    assert items["nginx"].major and not items["nginx"].security
    assert not items["curl"].security


def test_apply_holds_majors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    state = {"after": False}

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(argv)
        if argv[:2] == [updates.APT, "list"]:
            return proc.Result(
                tuple(argv),
                0,
                "nginx/noble 1.32.0-1~noble amd64 [upgradable from: " "1.30.6-1~noble]\n"
                if state["after"]
                else APT_LIST,
                "",
            )
        if "upgrade" in argv:
            state["after"] = True
        return proc.Result(tuple(argv), 0, "", "")

    monkeypatch.setattr(updates, "REBOOT", tmp_path / "reboot-required")
    result = updates.apply(run, security_only=False)
    assert result["held_major"] == ["nginx"] and set(result["upgraded"]) == {"openssl", "curl"}
    assert [updates.APT_MARK, "hold", "nginx"] in calls
    assert [updates.APT_MARK, "unhold", "nginx"] in calls
    assert result["reboot_required"] is False
    state["after"] = False
    calls.clear()
    updates.apply(run, security_only=True)
    assert [updates.UNATTENDED, "-v"] in calls and not any("hold" in c for c in calls)


def test_history(tmp_path: Path) -> None:
    log = tmp_path / "history.log"
    log.write_text(
        "\nStart-Date: 2026-11-08  04:10:01\nCommandline: /usr/bin/unattended-upgrade\n"
        "Upgrade: openssl:amd64 (3.0.13-0ubuntu3.5, 3.0.13-0ubuntu3.6), libssl3t64:amd64 (a, b)\n"
        "End-Date: 2026-11-08  04:10:20\n\n"
        "Start-Date: 2026-11-09  10:00:00\nCommandline: apt-get install foo\n"
        "Install: foo:amd64 (1.0)\nError: Sub-process returned an error code\n"
        "End-Date: 2026-11-09  10:00:05\n"
    )
    entries = updates.history(log)
    assert entries[0]["command"] == "apt-get install foo" and entries[0]["error"]
    assert entries[1]["packages"] == ["libssl3t64", "openssl"]
    assert updates.history(tmp_path / "missing") == []


# --- health ----------------------------------------------------------------------------------


def test_health_report(tmp_path: Path) -> None:
    from conftest import FakeProbe

    probe = FakeProbe(tmp_path, services={"fail2ban": "failed"})
    probe.reboot = True

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        if "list-units" in argv:
            return proc.Result(
                tuple(argv),
                0,
                "dp-php@t0001.service loaded failed failed X\n"
                "foo.service loaded failed failed Y\n",
                "",
            )
        return proc.Result(tuple(argv), 0, "", "")

    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal: 1000 kB\nMemAvailable: 80 kB\n")
    report = health.check(
        probe=probe,
        run=run,
        certificates=[("a.com", 5), ("b.com", 30), ("c.com", None)],
        pending_security=3,
        firewall_pending=True,
        disks=("/",),
        meminfo=meminfo,
    )
    text = " | ".join(f"{c['severity']}:{c['message']}" for c in report.checks)
    assert report.worst == "critical"
    for needle in (
        "critical:fail2ban is failed",
        "critical:failed tenant services: dp-php@t0001",
        "warn:failed units: foo.service",
        "warn:a reboot",
        "warn:3 security",
        "critical:a.com: 5 days",
        "ok:b.com: 30 days",
        "warn:8% memory",
        "waiting for confirmation",
    ):
        assert needle in text, needle
    healthy = health.check(
        probe=FakeProbe(tmp_path),
        run=lambda a, **k: proc.Result((), 0, "", ""),
        disks=(),
        meminfo=tmp_path / "none",
    )
    assert healthy.worst == "ok"


# --- lifecycle: site tuning & PHP switch -----------------------------------------------------


def test_site_optimize_and_rollback(
    system: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from domainpilot.sites import lifecycle
    from domainpilot.sites.lifecycle import CreateRequest

    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    monkeypatch.setattr(lifecycle, "measure_workers", lambda t: WorkerStats(3, 40))
    plan = mgr.site_optimize("example.com", apply=False)
    assert plan["changed"] and plan["recommended"]["php_max_children"] == 22 and not plan["applied"]
    conf = system["paths"].tenant_etc("t0001") / "php-fpm.conf"
    before = conf.read_bytes()
    applied = mgr.site_optimize("example.com", apply=True)
    assert applied["applied"] and "pm.max_children = 22" in conf.read_text()
    assert system["registry"].get_tenant_settings("t0001")["limits"]["php_max_children"] == 22
    assert mgr.site_optimize("example.com", apply=True)["changed"] is False
    mgr.site_optimize_rollback("example.com", applied["snapshot"])
    assert conf.read_bytes() == before
    assert system["registry"].get_tenant_settings("t0001")["limits"]["php_max_children"] == 8
    mgr.create(CreateRequest("other.example.com"))
    with pytest.raises(PreconditionFailed, match="does not belong"):
        mgr.site_optimize_rollback("other.example.com", applied["snapshot"])
    mgr.create(CreateRequest("static.example.com", site_type="static"))
    with pytest.raises(PreconditionFailed, match="no PHP"):
        mgr.site_optimize("static.example.com", apply=False)


def test_php_switch(system: dict[str, Any]) -> None:
    from dataclasses import replace

    from domainpilot.sites.lifecycle import CreateRequest

    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    assert mgr.php_switch("example.com", "8.5")["changed"] is False
    with pytest.raises(PreconditionFailed, match="not installed"):
        mgr.php_switch("example.com", "8.4")
    mgr.host = replace(mgr.host, php_versions=("8.4", "8.5"))
    result = mgr.php_switch("example.com", "8.4")
    assert result == {"domain": "example.com", "from": "8.5", "to": "8.4", "changed": True}
    dropin = system["paths"].systemd / "dp-php@t0001.service.d" / "10-tenant.conf"
    assert "php-fpm8.4" in dropin.read_text()
    assert system["registry"].get_site("example.com").php_version == "8.4"


# --- CLI handlers ----------------------------------------------------------------------------


def _ctx(system: dict[str, Any], domain: str | None = None, dry_run: bool = False) -> Any:
    from conftest import FakeProbe

    from domainpilot.cli.context import Context
    from domainpilot.core.config import Config
    from domainpilot.core.output import Output

    ctx = Context(
        paths=system["paths"],
        out=Output(stdout=io.StringIO(), stderr=io.StringIO()),
        probe=FakeProbe(system["paths"].etc),
        config=Config(),
        argv=["site"],
        domain=domain,
        dry_run=dry_run,
        use_syslog=False,
    )
    ctx._registry = system["registry"]
    return ctx


def test_system_optimize_handler(
    system: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lay = layout(tmp_path / "lay")
    monkeypatch.setattr(ops_handlers, "_layout", lambda ctx: lay)
    monkeypatch.setattr(ops_handlers, "_facts", lambda ctx: facts(16384))
    monkeypatch.setattr(ServerTuner, "_activate", lambda self, w: None)
    ctx = _ctx(system)
    ns = argparse.Namespace(history=False, rollback=None, profile=None, apply=False, analyze=True)
    analyzed = ops_handlers.system_optimize(ctx, ns)
    assert analyzed.data["profile"] == "large" and not analyzed.data["applied"]
    assert not lay.nginx_events.exists()
    applied = ops_handlers.system_optimize(ctx, argparse.Namespace(**{**vars(ns), "apply": True}))
    snap = applied.data["snapshot"]
    assert lay.nginx_events.exists() and "--rollback" in applied.text[-1]
    again = ops_handlers.system_optimize(ctx, argparse.Namespace(**{**vars(ns), "apply": True}))
    assert "already matches" in again.text[-1]
    hist = ops_handlers.system_optimize(ctx, argparse.Namespace(**{**vars(ns), "history": True}))
    assert hist.data["snapshots"][0]["id"] == snap
    ops_handlers.system_optimize(ctx, argparse.Namespace(**{**vars(ns), "rollback": snap}))
    assert not lay.nginx_events.exists()


def test_update_and_health_handlers(
    system: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        updates, "pending", lambda run=None, refresh=True: updates.parse_upgradable(APT_LIST)
    )
    monkeypatch.setattr(
        updates,
        "history",
        lambda: [{"start": "x", "packages": ["a"], "command": "c", "error": None}],
    )
    monkeypatch.setattr(
        updates,
        "apply",
        lambda **kw: {
            "upgraded": ["a"],
            "held_major": ["nginx"],
            "still_pending": [],
            "reboot_required": True,
        },
    )
    ctx = _ctx(system)
    ns = argparse.Namespace(check=True, security=False, history=False, include_major=False)
    checked = ops_handlers.system_update(ctx, ns)
    assert checked.data["security"] == 1 and checked.data["major"] == 1
    hist = ops_handlers.system_update(
        ctx, argparse.Namespace(**{**vars(ns), "check": False, "history": True})
    )
    assert hist.data["history"][0]["packages"] == ["a"]
    done = ops_handlers.system_update(ctx, argparse.Namespace(**{**vars(ns), "check": False}))
    assert "Held back" in done.text[1] and "health" in done.data
    rep = ops_handlers.system_health(ctx, argparse.Namespace())
    assert rep.exit_code in (ExitCode.OK, ExitCode.AUDIT_WARNINGS, ExitCode.AUDIT_CRITICAL)


def test_site_optimize_handler_rejects_server_flags(
    system: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ops_handlers, "_manager", lambda ctx: system["manager"]())
    ctx = _ctx(system, domain="example.com")
    with pytest.raises(UsageError):
        ops_handlers.site_optimize(
            ctx, argparse.Namespace(profile="small", history=False, rollback=None, apply=False)
        )
