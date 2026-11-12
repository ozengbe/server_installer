"""Phase 7 commands: optimization, updates, health, PHP version switch."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ozenix import health as health_mod
from ozenix import updates
from ozenix.cli.context import CommandResult, Context
from ozenix.cli.site_handlers import _domain, _manager
from ozenix.core import proc
from ozenix.core.errors import DPError, ExitCode, UsageError
from ozenix.optimize import profiles
from ozenix.optimize.server import Layout, ServerTuner
from ozenix.optimize.snapshot import SnapshotStore
from ozenix.tls.acme import Certbot
from ozenix.web.nginx import Nginx

SEVERITY_EXIT = {"critical": ExitCode.AUDIT_CRITICAL, "warn": ExitCode.AUDIT_WARNINGS}


# --- server optimization ----------------------------------------------------------------


def _layout(ctx: Context) -> Layout:
    dirs = [Path(f"/etc/php/{v}/fpm/conf.d") for v in ctx.host().php_versions]
    return Layout(php_conf_d=[d for d in dirs if d.is_dir()])


def _facts(ctx: Context) -> profiles.HostFacts:
    registry = ctx.registry(create=False)
    active = [t for t in (registry.list_tenants() if registry else []) if t.status == "active"]
    promised = (
        sum(
            int(registry.get_tenant_settings(t.id).get("limits", {}).get("memory_max_mb", 0))
            for t in active
        )
        if registry
        else 0
    )
    return profiles.read_facts(
        tenants=len(active), tenant_memory_promised_mb=promised, db_pool_max_mb=_db_pool_max_mb()
    )


def _db_pool_max_mb(run: Any = proc.run) -> int | None:
    """innodb_buffer_pool_size_max in MiB (MariaDB 11.8+), None when absent/unknown."""
    try:
        result = run(
            ["/usr/bin/mariadb", "--batch", "--skip-column-names"],
            stdin="SELECT @@GLOBAL.innodb_buffer_pool_size_max;\n",
            check=False,
            timeout=30,
        )
    except DPError:
        return None
    value = result.stdout.strip()
    return int(value) // (1024 * 1024) if result.ok and value.isdigit() else None


def system_optimize(ctx: Context, args: argparse.Namespace) -> CommandResult:
    snapshots = SnapshotStore(ctx.paths.var_lib / "optimize")
    tuner = ServerTuner(_layout(ctx), snapshots, nginx_reload=Nginx(ctx.paths).reload)
    if args.history:
        snaps = [s.__dict__ | {"files": len(s.files)} for s in snapshots.entries()]
        lines = [f"{s['id']}  {s['kind']:<22} {s['note']}" for s in snaps] or ["No snapshots yet."]
        return CommandResult({"snapshots": snaps}, lines)
    if args.rollback:
        if ctx.dry_run:
            return CommandResult(
                {"rollback": args.rollback, "dry_run": True},
                [f"Dry run: would restore snapshot {args.rollback}."],
            )
        snap, changed, warnings = tuner.rollback(args.rollback)
        for w in warnings:
            ctx.out.warn(w)
        ctx.audit().record(
            "system.optimize.rollback",
            argv=ctx.argv,
            outcome="success",
            details={"snapshot": snap.id, "files": changed},
        )
        return CommandResult(
            {"snapshot": snap.id, "restored": changed},
            [f"Restored snapshot {snap.id} ({len(changed)} file(s) changed)."],
        )

    facts = _facts(ctx)
    tuning = profiles.recommend(facts, args.profile)
    changes = tuner.diff(tuning)
    for warning in profiles.overcommit_warnings(facts, tuning):
        ctx.out.warn(warning)
    data: dict[str, Any] = {
        "facts": facts.__dict__ | {"memory_mb": facts.memory_mb},
        "profile": tuning.profile,
        "recommended": tuning.as_dict(),
        "changes": changes,
        "applied": False,
        "snapshot": None,
    }
    lines = [
        f"Host: {facts.cpu_count} CPU, {facts.memory_mb} MiB RAM, "
        f"{'SSD' if facts.ssd else 'HDD'}, {facts.tenants} active tenant(s)",
        f"Profile: {tuning.profile}",
    ]
    if not changes:
        lines.append("Configuration already matches the recommendation; nothing to change.")
        return CommandResult(data, lines)
    for change in changes:
        lines.append(change["diff"].rstrip())
    if not args.apply or ctx.dry_run:
        lines.append("Nothing changed. Apply with: sudo site system optimize --apply")
        return CommandResult(data, lines)
    snap, warnings = tuner.apply(tuning)
    for w in warnings:
        ctx.out.warn(w)
    ctx.audit().record(
        "system.optimize",
        argv=ctx.argv,
        outcome="success",
        details={"profile": tuning.profile, "snapshot": snap.id},
    )
    data.update(applied=True, snapshot=snap.id)
    lines.append(f"Applied. Undo with: sudo site system optimize --rollback {snap.id}")
    return CommandResult(data, lines)


# --- per-site ---------------------------------------------------------------------------


def site_optimize(ctx: Context, args: argparse.Namespace) -> CommandResult:
    manager = _manager(ctx)
    if getattr(args, "rollback", None):
        result = manager.site_optimize_rollback(_domain(ctx), args.rollback)
        return CommandResult(result, [f"Restored {_domain(ctx)} from snapshot {args.rollback}."])
    if getattr(args, "profile", None) or getattr(args, "history", False):
        raise UsageError("--profile and --history apply to: site system optimize")
    result = manager.site_optimize(_domain(ctx), apply=bool(getattr(args, "apply", False)))
    lines = [
        f"PHP workers (pm.max_children): {result['current']['php_max_children']} -> "
        f"{result['recommended']['php_max_children']} ({result['basis']})",
    ]
    if result["applied"]:
        lines.append(
            f"Applied. Undo with: sudo site {_domain(ctx)} optimize "
            f"--rollback {result['snapshot']}"
        )
    elif result["changed"]:
        lines.append(f"Nothing changed. Apply with: sudo site {_domain(ctx)} optimize --apply")
    else:
        lines.append("Already optimal.")
    return CommandResult(result, lines)


def php_switch(ctx: Context, args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).php_switch(_domain(ctx), args.version)
    if not result.get("changed", True) and not result.get("dry_run"):
        return CommandResult(result, [f"{_domain(ctx)} already uses PHP {args.version}."])
    if result.get("dry_run"):
        return CommandResult(result, [f"Dry run: would switch to PHP {args.version}."])
    return CommandResult(result, [f"{_domain(ctx)}: PHP {result['from']} -> {result['to']}."])


# --- updates ------------------------------------------------------------------------------


def system_update(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if args.history:
        entries = updates.history()
        lines = [
            f"{e['start']}  {len(e['packages'])} package(s)  {e['command']}"
            + (f"  ERROR: {e['error']}" if e["error"] else "")
            for e in entries
        ]
        return CommandResult({"history": entries}, lines or ["No update history yet."])
    if args.check or ctx.dry_run:
        items = updates.pending()
        sec = [p for p in items if p.security]
        major = [p for p in items if p.major]
        lines = [f"{len(items)} update(s) pending, {len(sec)} security."]
        lines += [
            f"  {'SEC ' if p.security else '    '}{p.name} {p.old} -> {p.new}"
            + ("  (major: held unless --include-major)" if p.major else "")
            for p in items
        ]
        if updates.REBOOT.exists():
            ctx.out.warn("a reboot is required to finish earlier updates")
        return CommandResult(
            {"pending": updates.as_dicts(items), "security": len(sec), "major": len(major)}, lines
        )
    result = updates.apply(security_only=args.security, include_major=args.include_major)
    ctx.audit().record(
        "system.update",
        argv=ctx.argv,
        outcome="success",
        details={"upgraded": result["upgraded"], "held": result["held_major"]},
    )
    lines = [f"Upgraded {len(result['upgraded'])} package(s)."]
    if result["held_major"]:
        lines.append("Held back (major branch change): " + ", ".join(result["held_major"]))
    report = _health_report(ctx)
    lines.append(f"Health after update: {report.worst}")
    if result["reboot_required"]:
        ctx.out.warn("a reboot is required (ozenix never reboots on its own)")
    result["health"] = health_mod.as_dict(report)
    return CommandResult(result, lines)


# --- health -------------------------------------------------------------------------------


def _health_report(ctx: Context) -> health_mod.Report:
    registry = ctx.registry(create=False)
    certbot = Certbot()
    certs: list[tuple[str, int | None]] = []
    for site in registry.list_sites() if registry else []:
        if site.is_primary and certbot.exists(site.domain):
            info = certbot.info(site.domain)
            certs.append((site.domain, info.days_left if info else None))
    try:
        security = sum(1 for p in updates.pending(refresh=False) if p.security)
    except Exception:  # health must never fail because apt is busy
        security = None
    return health_mod.check(
        probe=ctx.probe,
        certificates=certs,
        pending_security=security,
        firewall_pending=ctx.paths.firewall_pending.exists(),
    )


def system_health(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    report = _health_report(ctx)
    symbol = {"ok": "ok  ", "info": "info", "warn": "WARN", "critical": "CRIT"}
    lines = [
        f"{symbol[c['severity']]}  {c['check']:<12} {c['message']}"
        for c in sorted(report.checks, key=lambda c: -health_mod.ORDER.index(c["severity"]))
    ]
    return CommandResult(
        health_mod.as_dict(report),
        lines,
        exit_code=int(SEVERITY_EXIT.get(report.worst, ExitCode.OK)),
    )
