"""Phase 8 commands: SFTP accounts, monitoring, alerts, logs."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

from ozenix.cli.context import CommandResult, Context
from ozenix.cli.ops_handlers import _health_report
from ozenix.cli.site_handlers import _domain, _manager
from ozenix.core import fsutil, proc
from ozenix.core.errors import DPError, LockBusy, PreconditionFailed, UsageError
from ozenix.core.locks import FileLock
from ozenix.monitor import monitor as mon
from ozenix.monitor.alerts import Alert, AlertSettings, Notifier
from ozenix.sftp import SftpManager

JOURNALCTL = "/usr/bin/journalctl"
LOG_UNITS = ("nginx", "mariadb", "fail2ban", "ssh", "dp-backup", "dp-monitor", "dp-php@*")


# --- SFTP -------------------------------------------------------------------------------


def _sftp(ctx: Context) -> tuple[SftpManager, str]:
    _site, tenant = _manager(ctx).primary_site(_domain(ctx))
    if tenant.status != "active":
        raise PreconditionFailed(f"{_domain(ctx)} is not active")
    return (
        SftpManager(
            audit=ctx.audit(),
            argv=ctx.argv,
            keys_dir=ctx.paths.ssh_keys,
            hostname=socket.getfqdn(),
        ),
        tenant.id,
    )


def sftp_create(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if bool(args.key) == bool(args.key_stdin):
        raise UsageError("give the public key with --key <file.pub> or --key-stdin")
    if args.key:
        path = Path(args.key)
        if path.stat().st_size > 16384:
            raise UsageError("that file is too large to be a public key")
        text = path.read_text(encoding="ascii", errors="replace")
    else:
        text = sys.stdin.read(16384)
    manager, tenant = _sftp(ctx)
    result = manager.create(tenant, text, args.name)
    return CommandResult(
        result,
        [
            f"SFTP account {result['account']!r} added ({result['fingerprint']}).",
            f"Connect: {result['connect']}   (SFTP: same user and key)",
            f"Folders: {result['directory']}",
        ],
    )


def sftp_list(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    manager, tenant = _sftp(ctx)
    accounts = manager.list(tenant)
    lines = [
        f"{a['account']:<20} {a['username']:<14} {a['type']:<12} {a['fingerprint']}"
        for a in accounts
    ] or ["No SFTP accounts."]
    return CommandResult({"accounts": accounts}, lines)


def sftp_revoke(ctx: Context, args: argparse.Namespace) -> CommandResult:
    manager, tenant = _sftp(ctx)
    result = manager.revoke(tenant, args.username)
    return CommandResult(result, [f"Revoked SFTP account {args.username!r}."])


# --- monitoring -------------------------------------------------------------------------


def _notifier(ctx: Context) -> Notifier:
    return Notifier(ctx.paths.etc)


def collect(ctx: Context) -> tuple[list[mon.Problem], dict[str, int]]:
    problems = mon.from_health(_health_report(ctx))
    registry = ctx.registry(create=False)
    if registry is not None:
        active = {t.id: t for t in registry.list_tenants() if t.status == "active"}
        domains = [
            s.domain
            for s in registry.list_sites()
            if s.is_primary and s.enabled and s.tenant_id in active
        ]
        problems += mon.site_problems(domains)
        backup_conf = ctx.paths.etc / "backup.json"
        if backup_conf.exists():
            state_file = ctx.paths.var_lib / "backup" / "state.json"
            try:
                state = json.loads(fsutil.read_text_nofollow(state_file))
            except (OSError, ValueError):
                state = {}
            problems += mon.backup_problems(state, [(t.id, t.created_at) for t in active.values()])
        units = [*mon.WATCHED_UNITS, *(f"dp-php@{t}.service" for t in active)]
    else:
        units = list(mon.WATCHED_UNITS)
    return problems, mon.restart_counts(units)


def _autossl_retry(ctx: Context) -> None:
    """Issue certificates for sites whose DNS became ready since creation.

    Certificate issuance changes nginx and the registry, so it takes the global
    lock; if an admin command holds it, this run simply skips (next one in 5 min).
    """
    try:
        with FileLock(ctx.paths.global_lock, timeout=1):
            results = _manager(ctx).autossl_pending(now=time.time())
    except LockBusy:
        return
    except DPError as exc:
        ctx.out.warn(f"AutoSSL retry: {exc.message}")
        return
    for domain, outcome in results.items():
        if outcome != "waiting for DNS":
            ctx.out.info(f"AutoSSL {domain}: {outcome}")


def system_monitor(ctx: Context, args: argparse.Namespace) -> CommandResult:
    notifier = _notifier(ctx)
    monitor = mon.Monitor(
        ctx.paths.var_lib / "monitor" / "state.json", notifier, host=socket.getfqdn()
    )
    if args.notify:  # timer mode: also finish pending AutoSSL certificates
        _autossl_retry(ctx)
    problems, restarts = collect(ctx)
    alerts = monitor.evaluate(problems, restarts, failed_unit=args.unit_failed)
    delivery = monitor.deliver(alerts) if args.notify else {"sent": 0, "skipped": len(alerts)}
    for error in delivery.get("errors", []):
        ctx.out.warn(f"alert not delivered: {error}")
    data: dict[str, Any] = {
        "problems": [p.__dict__ for p in problems],
        "alerts": [a.__dict__ | {"title": a.title} for a in alerts],
        "delivery": delivery,
    }
    lines = [f"{p.severity.upper():<8} {p.key:<28} {p.message}" for p in problems] or [
        "No problems."
    ]
    if alerts:
        lines.append(
            f"{len(alerts)} change(s); "
            + (f"{delivery['sent']} alert(s) sent" if args.notify else "not sent (no --notify)")
        )
    return CommandResult(data, lines)


def alerts_setup(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if not args.url_stdin:
        raise UsageError(
            "the alert URL is a secret: give it on stdin",
            hint="echo 'https://ntfy.sh/<topic>' | sudo site system alerts setup "
            "--kind ntfy --url-stdin",
        )
    url = sys.stdin.readline().strip()
    settings = AlertSettings(args.kind, args.min_severity, args.reminder_hours)
    notifier = _notifier(ctx)
    notifier.setup(settings, url)
    ctx.audit().record(
        "alerts.setup", argv=ctx.argv, outcome="success", details={"kind": args.kind}
    )
    return CommandResult(
        {"kind": args.kind, "min_severity": args.min_severity},
        [f"Alerts go to {args.kind}. Test with: sudo site system alerts test"],
    )


def alerts_test(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    notifier = _notifier(ctx)
    host = socket.getfqdn()
    notifier.send(Alert("test", "info", "ozenix alert test: delivery works.", "test", host))
    return CommandResult({"sent": True}, ["Test alert sent."])


def alerts_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    notifier = _notifier(ctx)
    if not notifier.configured():
        return CommandResult({"configured": False}, ["Alerts are not configured."])
    settings = notifier.settings()
    return CommandResult(
        {"configured": True, **settings.__dict__},
        [
            f"Alerts: {settings.kind}, from severity {settings.min_severity}, "
            f"reminders every {settings.reminder_hours}h"
        ],
    )


def alerts_remove(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    _notifier(ctx).remove()
    ctx.audit().record("alerts.remove", argv=ctx.argv, outcome="success", details={})
    return CommandResult({"removed": True}, ["Alert destination removed."])


# --- logs -------------------------------------------------------------------------------


def system_logs(ctx: Context, args: argparse.Namespace) -> CommandResult:
    lines_wanted = max(1, min(args.lines, 2000))
    if args.audit:
        try:
            text = fsutil.read_text_nofollow(ctx.paths.audit_log)
        except OSError:
            text = ""
        events = []
        for line in text.splitlines()[-lines_wanted:]:
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        lines = [
            f"{e.get('ts', '?')}  {e.get('actor', '?'):<10} {e.get('event', '?'):<22} "
            f"{e.get('outcome', '')}  {' '.join(e.get('argv', [])[1:])}"
            for e in events
        ]
        return CommandResult({"events": events}, lines or ["No audit events."])
    argv = [JOURNALCTL, "--no-pager", "-o", "short-iso", "-n", str(lines_wanted)]
    for unit in LOG_UNITS:
        argv += ["-u", unit]
    if args.errors:
        argv += ["-p", "warning"]
    out = proc.run(argv, check=False, timeout=60).stdout.splitlines()
    return CommandResult({"lines": out}, out or ["No log lines."])
