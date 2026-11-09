"""Phase 5 commands: site lifecycle, logs and per-site databases."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from domainpilot.cli.context import CommandResult, Context
from domainpilot.core import fsutil, validate
from domainpilot.core.errors import OperationFailed, PreconditionFailed, UsageError
from domainpilot.core.registry import Registry
from domainpilot.isolation import db
from domainpilot.sites.lifecycle import CreateRequest, SiteManager
from domainpilot.web.nginx import Nginx

MAX_LOG_LINES = 2000
HIDDEN = "(hidden: run in a terminal or add --show-secret)"


def _manager(ctx: Context) -> SiteManager:
    registry = ctx.registry(create=True)
    if registry is None:  # pragma: no cover - create=True always returns one
        raise OperationFailed("could not open the site registry")
    return SiteManager(
        paths=ctx.paths,
        host=ctx.host(),
        registry=registry,
        audit=ctx.audit(),
        argv=ctx.argv,
        reporter=ctx.out.step,
        dry_run=ctx.dry_run,
        config=ctx.config,
    )


def _domain(ctx: Context) -> str:
    if ctx.domain is None:  # pragma: no cover - dispatcher guarantees it
        raise UsageError("no domain given")
    return ctx.domain


def create(ctx: Context, args: argparse.Namespace) -> CommandResult:
    domain = _domain(ctx)
    if args.no_ssl:
        ctx.out.warn("--no-ssl: certificates arrive in Phase 6; sites are HTTP-only until then")
    req = CreateRequest(
        domain=domain,
        site_type=args.site_type or ctx.config.default_site_type,
        aliases=list(args.alias),
        php_version=args.php_version,
        tier=args.tier or ctx.config.default_tier,
        upstream=args.upstream,
        writable_code=args.writable_code,
        cloudflare=not getattr(args, "no_cloudflare", False),
    )
    result = _manager(ctx).create(req)
    if result["dry_run"]:
        return CommandResult(result, [f"Dry run: nothing was changed for {domain}."])
    text = [
        f"Created {domain} ({result['type']}) as tenant {result['tenant']}.",
        "Next steps:",
        (
            f"  - Cloudflare: {result['cloudflare']}"
            if result.get("cloudflare")
            else f"  - point DNS for {', '.join([domain, *result['aliases']])} at this server"
        ),
        "  - upload files over SFTP (Phase 8) into the tenant's app/public directory",
        f"  - database: sudo site {domain} db create" if result["type"] == "php" else "",
        "  - HTTPS certificates arrive in Phase 6",
    ]
    return CommandResult(result, [line for line in text if line])


def delete(ctx: Context, args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).delete(_domain(ctx), purge=args.purge)
    if result.get("dry_run"):
        return CommandResult(result, ["Dry run: nothing was changed."])
    for problem in result["problems"]:
        ctx.out.warn(problem)
    if result["purge"]:
        text = [f"Erased {result['domain']} and tenant {result['tenant']}."]
    else:
        text = [
            f"Deleted {result['domain']}: no longer served; tenant {result['tenant']} archived.",
            "Files and databases were kept. Erase them with:"
            f" sudo site {result['domain']} delete --purge",
        ]
    return CommandResult(result, text, exit_code=1 if result["problems"] else 0)


def enable(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).set_enabled(_domain(ctx), True)
    msg = "already enabled" if not result["changed"] else "enabled"
    return CommandResult(result, [f"{result['domain']} {msg}."])


def disable(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).set_enabled(_domain(ctx), False)
    msg = "already disabled" if not result["changed"] else "disabled (503 maintenance page)"
    return CommandResult(result, [f"{result['domain']} {msg}."])


def repair(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).repair(_domain(ctx))
    for problem in result["problems"]:
        ctx.out.warn(problem)
    if not result["actions"]:
        return CommandResult(result, [f"Nothing to repair for {result['domain']}."])
    return CommandResult(result, [], exit_code=1 if result["problems"] else 0)


# --- logs ---------------------------------------------------------------------


def _tail(path: Path, lines: int) -> list[str]:
    if not path.exists():
        return []
    data = fsutil.read_bytes_nofollow(path, max_bytes=64 * 1024 * 1024)
    return data.decode("utf-8", "replace").splitlines()[-lines:]


def logs(ctx: Context, args: argparse.Namespace) -> CommandResult:
    registry = ctx.registry(create=False)
    site = registry.get_site(_domain(ctx)) if registry else None
    if site is None:
        raise PreconditionFailed(f"{ctx.domain} is not a DomainPilot site")
    lines = args.lines
    if not 1 <= lines <= MAX_LOG_LINES:
        raise UsageError(f"--lines must be between 1 and {MAX_LOG_LINES}")
    nginx_logs = Nginx(ctx.paths).log_dir(site.tenant_id)
    choice = args.kind or "access"
    path = {
        "access": nginx_logs / "access.log",
        "error": nginx_logs / "error.log",
        # Tenant-owned directory: read without following symlinks.
        "php": ctx.paths.tenant_log(site.tenant_id) / "php-error.log",
    }[choice]
    content = _tail(path, lines)
    return CommandResult({"log": str(path), "lines": content}, content or [f"({path} is empty)"])


# --- databases -------------------------------------------------------------------


def _tenant_of(ctx: Context) -> tuple[Registry, str]:
    registry = ctx.registry(create=False)
    site = registry.get_site(_domain(ctx)) if registry else None
    if site is None or registry is None:
        raise PreconditionFailed(f"{ctx.domain} is not a DomainPilot site")
    return registry, site.tenant_id


def db_create(ctx: Context, args: argparse.Namespace) -> CommandResult:
    _registry, tenant = _tenant_of(ctx)
    name = db.database_name(tenant, validate.db_name(args.name))
    if ctx.dry_run:
        ctx.out.step(f"create database {name}", "planned")
        return CommandResult({"database": name, "dry_run": True})
    db.execute(db.create_database_sql(tenant, args.name))
    ctx.audit().record("db.create", argv=ctx.argv, outcome="success", details={"database": name})
    ctx.out.step(f"created database {name}")
    return CommandResult(
        {"database": name, "user": tenant},
        [f"Database {name} is ready. Credentials: sudo site {ctx.domain} db credentials"],
    )


def _secret_file(ctx: Context, tenant: str) -> Path:
    return ctx.paths.tenant_etc(tenant) / "secrets" / "db.env"


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in fsutil.read_text_nofollow(path).splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key] = value
    return values


def db_credentials(ctx: Context, args: argparse.Namespace) -> CommandResult:
    _registry, tenant = _tenant_of(ctx)
    secret = _secret_file(ctx, tenant)
    if args.rotate:
        if ctx.dry_run:
            ctx.out.step(f"rotate the database password of {tenant}", "planned")
            return CommandResult({"dry_run": True})
        password = db.new_password()
        db.execute(db.alter_password_sql(tenant, password))
        env = _read_env(secret)
        env["DB_PASSWORD"] = password
        fsutil.atomic_write(
            secret,
            "".join(f"{k}={v}\n" for k, v in env.items()),
            mode=0o640,
            uid=0,
            gid=secret.stat().st_gid,
        )
        ctx.audit().record("db.rotate", argv=ctx.argv, outcome="success", details={"user": tenant})
        ctx.out.step(f"rotated the database password of {tenant}")
    env = _read_env(secret)
    show = args.show_secret or (not ctx.out.json_mode and ctx.out.stdout.isatty())
    data: dict[str, Any] = {
        "user": env.get("DB_USER", tenant),
        "socket": env.get("DB_SOCKET", "/run/mysqld/mysqld.sock"),
        "host": "localhost",
        "password": env.get("DB_PASSWORD") if show else None,
        "unix_socket_auth": True,
    }
    if not env.get("DB_PASSWORD"):
        raise OperationFailed(f"no stored credentials in {secret}")
    text = [
        f"User:     {data['user']}",
        f"Host:     localhost (socket {data['socket']})",
        f"Password: {data['password'] if show else HIDDEN}",
        "PHP code running as this site can also log in without a password (unix_socket).",
    ]
    return CommandResult(data, text)
