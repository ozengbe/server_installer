"""Phase 8 commands: backups and restores."""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from typing import Any

from domainpilot.backup.config import (
    BackupConfig,
    BackupSettings,
    Retention,
    parse_s3_env,
    validate_repository,
)
from domainpilot.backup.manager import BackupManager
from domainpilot.backup.restic import validate_snapshot_id
from domainpilot.cli.context import CommandResult, Context
from domainpilot.cli.site_handlers import HIDDEN, _domain
from domainpilot.core.errors import ExitCode, OperationFailed, UsageError

KEY_WARNING = (
    "STORE THIS MASTER KEY OFFLINE NOW (password manager / paper). Together with the bucket "
    "credentials it is the ONLY way to read these backups if this server is lost: the copy "
    "on this server is encrypted with this server's own key."
)


def _settings(ctx: Context) -> BackupSettings:
    return BackupSettings(ctx.paths.etc)


def _manager(ctx: Context) -> BackupManager:
    registry = ctx.registry(create=True)
    if registry is None:  # pragma: no cover - create=True always returns one
        raise OperationFailed("could not open the site registry")
    return BackupManager(
        paths=ctx.paths,
        registry=registry,
        settings=_settings(ctx),
        audit=ctx.audit(),
        argv=ctx.argv,
        reporter=ctx.out.step,
    )


def _show_secret(ctx: Context, args: argparse.Namespace) -> bool:
    return bool(getattr(args, "show_secret", False)) or (
        not ctx.out.json_mode and ctx.out.stdout.isatty()
    )


def _read_stdin(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.read()


# --- setup ------------------------------------------------------------------------------


def setup(ctx: Context, args: argparse.Namespace) -> CommandResult:
    repository = validate_repository(args.repository, tenants_root=ctx.paths.tenants)
    settings = _settings(ctx)
    config = BackupConfig(
        repository=repository,
        retention=Retention(args.keep_daily, args.keep_weekly, args.keep_monthly),
        configured_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    )
    if config.is_s3:
        if not args.credentials_stdin:
            raise UsageError(
                "an S3 repository needs credentials",
                hint="printf 'AWS_ACCESS_KEY_ID=...\\nAWS_SECRET_ACCESS_KEY=...\\n' | "
                "sudo site system backup setup --repository s3:... --credentials-stdin",
            )
        settings.secrets.save(
            "s3", "".join(f"{k}={v}\n" for k, v in parse_s3_env(_read_stdin("")).items())
        )
    elif args.credentials_stdin:
        raise UsageError("--credentials-stdin is only for s3: repositories")
    new_key = settings.ensure_master()
    settings.save(config)
    ctx.audit().record(
        "backup.setup",
        argv=ctx.argv,
        outcome="success",
        details={"repository": repository, "new_master_key": bool(new_key)},
    )
    show = _show_secret(ctx, args)
    data: dict[str, Any] = {
        "repository": repository,
        "retention": config.retention.__dict__,
        "master_key": (new_key if show else HIDDEN) if new_key else None,
    }
    lines = [f"Backups go to: {repository}"]
    if new_key:
        lines += ["", f"Master key: {new_key if show else HIDDEN}", "", KEY_WARNING]
    else:
        lines.append("Existing master key kept (show it with: sudo site system backup show-key).")
    lines.append("Run a first backup with: sudo site system backup")
    return CommandResult(data, lines)


def show_key(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if not _show_secret(ctx, args):
        raise UsageError("the master key is only shown on a terminal (or with --show-secret)")
    key = _settings(ctx).secrets.load("master").strip()
    ctx.audit().record("backup.show_key", argv=ctx.argv, outcome="success", details={})
    return CommandResult({"master_key": key}, [f"Master key: {key}", "", KEY_WARNING])


def import_key(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    """Disaster recovery: reuse the master key of a lost server on a new one."""
    settings = _settings(ctx)
    if settings.secrets.exists("master"):
        raise UsageError(
            "this server already has a master key",
            hint="importing would make its existing backups unreadable; remove it deliberately",
        )
    settings.import_master(_read_stdin("Master key (input hidden): "))
    ctx.audit().record("backup.import_key", argv=ctx.argv, outcome="success", details={})
    return CommandResult({"imported": True}, ["Master key imported."])


def rotate_key(ctx: Context, args: argparse.Namespace) -> CommandResult:
    """Two steps so the old key never disappears before the new one is stored offline."""
    manager = _manager(ctx)
    if args.finish:
        data = manager.finish_rotation()
        lines = [f"  {name}: {what}" for name, what in data["repositories"].items()]
        return CommandResult(
            data,
            [
                "Old key removed from every repository. Destroy offline copies of the OLD key.",
                *lines,
            ],
        )
    if not _show_secret(ctx, args):
        raise UsageError(
            "rotation prints the new master key: run it in a terminal or add --show-secret"
        )
    data = manager.rotate_key()
    key = _settings(ctx).secrets.load("master").strip()
    lines = [f"  {name}: {what}" for name, what in data["repositories"].items()]
    return CommandResult(
        {**data, "master_key": key},
        [
            "New key added to every repository and now in use. The old key still works.",
            *lines,
            "",
            f"New master key: {key}",
            "",
            KEY_WARNING,
            "Then remove the old key: sudo site system backup rotate-key --finish",
        ],
    )


def recorded_sites(ctx: Context, args: argparse.Namespace) -> CommandResult:
    """Disaster recovery: what the lost server hosted, and under which tenant ids."""
    snapshot = validate_snapshot_id(args.snapshot) if args.snapshot else None
    data = _manager(ctx).recorded_sites(snapshot)
    lines = [f"Sites in server backup {data['snapshot']} ({data['time']}):"]
    for s in data["sites"]:
        role = "" if s["primary"] else " (alias)"
        lines.append(f"  {s['tenant']}  {s['domain']}{role}  {s['type']}  {s['status']}")
    lines += [
        "",
        "Recreate each primary domain with its id, then restore it:",
        "  sudo site <domain> create --type <type> --tenant-id <tNNNN>",
        "  sudo site <domain> restore --all --confirm <domain>",
    ]
    return CommandResult(data, lines)


# --- backups ----------------------------------------------------------------------------


def system_backup(ctx: Context, args: argparse.Namespace) -> CommandResult:
    manager = _manager(ctx)
    if args.status:
        return _status(ctx, manager)
    if args.verify:
        result = manager.verify()
        lines = [f"{name:<8} {res}" for name, res in result["repositories"].items()]
        return CommandResult(result, lines, exit_code=0 if result["ok"] else ExitCode.FAILED)
    if args.test_restore:
        result = manager.test_restore()
        lines = [
            f"{tid}: {'ok' if r['ok'] else 'FAILED - ' + r.get('error', '?')}"
            for tid, r in result["sites"].items()
        ] or ["No sites to test."]
        return CommandResult(result, lines, exit_code=0 if result["ok"] else ExitCode.FAILED)
    result = manager.backup_all()
    failed = result["failed"]
    lines = [f"Backed up {len(result['sites']) - len(failed)} site(s) and the server configuration"]
    if failed:
        lines = [f"Backup FAILED for: {', '.join(failed)}"]
    return CommandResult(result, lines, exit_code=ExitCode.FAILED if failed else 0)


def _status(ctx: Context, manager: BackupManager) -> CommandResult:
    settings = _settings(ctx)
    configured = settings.configured()
    state = manager.load_state()
    data: dict[str, Any] = {
        "configured": configured,
        "repository": settings.load().repository if configured else None,
        "state": state,
    }
    lines = [f"Repository: {data['repository'] or 'not configured'}"]
    for tid, entry in sorted(state.get("sites", {}).items()):
        status = "ok" if entry.get("ok") else f"FAILED ({entry.get('error', '?')})"
        lines.append(f"{tid}: last success {entry.get('last_success', 'never')} - {status}")
    drill = state.get("test_restore", {})
    if drill:
        lines.append(f"Restore test: last success {drill.get('last_success', 'never')}")
    return CommandResult(data, lines)


def site_backup(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    manager = _manager(ctx)
    tenant = manager.tenant_for(_domain(ctx))
    result = manager.backup_tenant(tenant)
    return CommandResult(result, [f"Backed up {_domain(ctx)} (run {result['run']})."])


def db_backup(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    manager = _manager(ctx)
    tenant = manager.tenant_for(_domain(ctx))
    result = manager.backup_tenant(tenant, files=False)
    names = ", ".join(result["databases"]) or "no databases"
    return CommandResult(result, [f"Backed up {names}."])


def backup_list(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    manager = _manager(ctx)
    snaps = manager.snapshots(manager.tenant_for(_domain(ctx)))
    lines = [
        f"{s['id']}  {s['time'][:19]}  {s['kind']:<5} {s['database'] or ''}"
        + ("  (pre-restore safety copy)" if "pre-restore" in s["tags"] else "")
        for s in snaps
    ] or ["No backups yet."]
    return CommandResult({"snapshots": snaps}, lines)


def restore(ctx: Context, args: argparse.Namespace) -> CommandResult:
    what = "files" if args.files else "db" if args.db else "all"
    return _restore(ctx, args, what)


def db_restore(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if args.files or args.all:
        raise UsageError("db restore restores databases only; use: site <d> restore --all")
    return _restore(ctx, args, "db")


def _restore(ctx: Context, args: argparse.Namespace, what: str) -> CommandResult:
    manager = _manager(ctx)
    result = manager.restore(
        _domain(ctx), snapshot=args.snapshot, what=what, to_staging=args.to_staging
    )
    if args.to_staging:
        lines = [f"Restored into staging (nothing live changed): {result['staging']}"]
    else:
        lines = [f"Restored {what} of {_domain(ctx)}."]
        previous = result.get("files", {}).get("previous")
        if previous:
            lines.append(f"The replaced files are kept in {previous}")
    return CommandResult(result, lines)
