"""Phase 5 commands: site lifecycle, logs and per-site databases."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from ozenix.cli.context import CommandResult, Context
from ozenix.core import fsutil, validate
from ozenix.core.errors import OperationFailed, PreconditionFailed, UsageError
from ozenix.core.registry import Registry
from ozenix.isolation import db
from ozenix.sites.lifecycle import CreateRequest, SiteManager
from ozenix.web.nginx import Nginx

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


def _site_login(ctx: Context, args: argparse.Namespace) -> tuple[str | None, str | None]:
    """The site's own user and its SSH key (`--user`, `--key`/`--key-stdin`).

    On a terminal, missing values are asked for (like CloudPanel's form). In
    scripts they are optional: without them the site gets the automatic user
    `<tid>-deploy` and keys can be added later with `sftp create`.
    """
    user = getattr(args, "site_user", None)
    key_file = getattr(args, "site_key_file", None)
    key: str | None = None
    if key_file:
        path = Path(key_file)
        if not path.is_file() or path.stat().st_size > 16384:
            raise UsageError(f"{key_file}: not a public key file")
        key = path.read_text(encoding="ascii", errors="replace")
    elif getattr(args, "key_stdin", False):
        key = sys.stdin.read(16384)
    interactive = sys.stdin.isatty() and not ctx.out.json_mode and not ctx.dry_run
    if interactive and not user:
        user = input("Site user name (SSH/SFTP login, e.g. john): ").strip() or None
    if interactive and user and not key:
        key = input("SSH public key for this user (paste one line, empty = later): ").strip()
        key = key or None
    if user:
        validate.site_user(user)
    if key and not user:
        raise UsageError("--key needs --user (the account the key logs in to)")
    return user, key


def create(ctx: Context, args: argparse.Namespace) -> CommandResult:
    domain = _domain(ctx)
    site_user, site_key = _site_login(ctx, args)
    req = CreateRequest(
        domain=domain,
        site_type=args.site_type or ctx.config.default_site_type,
        aliases=list(args.alias),
        php_version=args.php_version,
        tier=args.tier or ctx.config.default_tier,
        upstream=args.upstream,
        writable_code=args.writable_code,
        cloudflare=bool(getattr(args, "cloudflare_dns", False)),
        ssl=not getattr(args, "no_ssl", False),
        tenant_id=getattr(args, "tenant_id", None),
        site_user=site_user,
        site_key=site_key,
        node_version=getattr(args, "node_version", None),
        start=getattr(args, "start", None),
    )
    result = _manager(ctx).create(req)
    if result["dry_run"]:
        return CommandResult(result, [f"Dry run: nothing was changed for {domain}."])
    names = ", ".join([domain, *result["aliases"]])
    issued = result.get("ssl") == "issued"
    login = result.get("login")
    text = [
        f"Created {domain} ({result['type']}) with its own user {result['site_user']}.",
        f"Login (SSH key; SFTP + shell): {login}"
        if login
        else f"Login: add an SSH key: sudo site {domain} sftp create --key <file.pub> "
        "--name <label>",
        "Website files go in ~/app/public.",
        "HTTPS: " + ("Let's Encrypt certificate" if issued else str(result.get("ssl"))),
        "Next steps:",
        (
            f"  - Cloudflare DNS: {result['cloudflare']}"
            if result.get("cloudflare")
            else f"  - DNS (if not done yet): A/AAAA records for {names} -> this server "
            "(Cloudflare proxy on or off; with the proxy, use SSL/TLS mode Full)"
        ),
        f"  - database: sudo site {domain} db create" if result["type"] == "php" else "",
        *(
            [
                f"  - Laravel database {result['tenant']}_app is ready. In ~/app/.env set:",
                "      DB_CONNECTION=mariadb",
                "      DB_SOCKET=/run/mysqld/mysqld.sock",
                f"      DB_DATABASE={result['tenant']}_app",
                f"      DB_USERNAME={result['tenant']}",
                f"      DB_PASSWORD=<sudo site {domain} db credentials>",
                "    then, as the site user: php artisan migrate --force",
            ]
            if result["type"] == "laravel"
            else []
        ),
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
        raise PreconditionFailed(f"{ctx.domain} is not an ozenix site")
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
        raise PreconditionFailed(f"{ctx.domain} is not an ozenix site")
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


# --- Node.js / Python apps ------------------------------------------------------------


def app_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    st = _manager(ctx).app_status(_domain(ctx))
    runtime = f"Node.js {st['node_version']}" if st["runtime"] == "node" else "Python"
    return CommandResult(
        st,
        [
            f"App:      {runtime}, {st['state']} ({st['restarts']} restarts)",
            f"Start:    {st['start']}",
            f"Listens:  127.0.0.1:{st['port']} (nginx forwards {st['domain']} there)",
            f"Log:      {st['log']}",
        ],
    )


def app_restart(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).app_restart(_domain(ctx))
    return CommandResult(result, ["Dry run." if result["dry_run"] else "App restarted."])


def app_set(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if args.start is None and args.node_version is None:
        raise UsageError("nothing to change: give --start and/or --node")
    result = _manager(ctx).app_set(_domain(ctx), start=args.start, node_version=args.node_version)
    if not result["changed"]:
        return CommandResult(result, ["Nothing changed."])
    return CommandResult(result, [f"App now starts with: {result['start']} (restarted)"])


def laravel_queue(ctx: Context, args: argparse.Namespace) -> CommandResult:
    on = args.state == "on"
    result = _manager(ctx).laravel_queue(_domain(ctx), on)
    if result.get("dry_run"):
        return CommandResult(result, ["Dry run."])
    return CommandResult(
        result, [f"Laravel queue worker {'started' if on else 'stopped'} ({result['unit']})."]
    )


def env_protect(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).env_protect(_domain(ctx))
    if not result["fixed"] and not result["skipped"]:
        return CommandResult(result, ["No .env file in ~/app."])
    lines = [f"Protected (site user, mode 0640): {', '.join(result['fixed']) or 'none'}"]
    if result["skipped"]:
        lines.append(f"Skipped: {', '.join(result['skipped'])}")
    return CommandResult(result, lines)
