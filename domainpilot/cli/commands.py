"""Command table (docs/cli-spec.md §4).

Every documented command is listed, with the phase that implements it, so
help output is complete from day one and unimplemented commands fail clearly.
Kinds: R = read-only, M = mutating (supports --dry-run), D = destructive
(requires typed confirmation).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass

from domainpilot.cli import handlers, site_handlers, tenant_handlers
from domainpilot.cli.context import Handler

Configure = Callable[[argparse.ArgumentParser], None]


@dataclass(frozen=True)
class CommandSpec:
    scope: str  # "site" (needs a domain), "system", or "list"
    words: tuple[str, ...]
    kind: str  # R, M, D
    phase: int
    summary: str
    handler: Handler | None = None
    configure: Configure | None = None

    @property
    def usage_words(self) -> str:
        return " ".join(self.words)


def _create_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--type", choices=["php", "static", "proxy"], dest="site_type")
    p.add_argument("--php", dest="php_version")
    p.add_argument("--tier", choices=["s", "c"])
    p.add_argument("--alias", action="append", default=[])
    p.add_argument("--upstream")
    p.add_argument("--writable-code", action="store_true")
    p.add_argument("--no-ssl", action="store_true")


def _php_version_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("version", help="PHP version, e.g. 8.3")


def _username_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("username")


def _delete_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--purge", action="store_true", help="also erase data, database and backups")


def _restore_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--snapshot")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--files", action="store_true")
    group.add_argument("--db", action="store_true")
    group.add_argument("--all", action="store_true")
    p.add_argument("--to-staging", action="store_true")


def _optimize_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--analyze", action="store_true")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--profile", choices=["small", "medium", "large", "dedicated", "high-traffic"])
    p.add_argument("--rollback", metavar="ID")
    p.add_argument("--history", action="store_true")


def _update_args(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true")
    group.add_argument("--security", action="store_true")


def _logs_args(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group()
    group.add_argument("--access", dest="kind", action="store_const", const="access")
    group.add_argument("--error", dest="kind", action="store_const", const="error")
    group.add_argument("--php", dest="kind", action="store_const", const="php")
    p.add_argument("--lines", type=int, default=50)


def _db_create_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--name", default="app", help="database name suffix (default: app)")


def _db_credentials_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rotate", action="store_true", help="generate a new password")
    p.add_argument(
        "--show-secret",
        action="store_true",
        help="print the password even in --json mode or when not on a terminal",
    )


def _apply_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument("--apply", action="store_true", help="make changes (after diff + confirmation)")


S = "site"
SY = "system"

COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("list", (), "R", 3, "List all sites", handlers.site_list),
    # --- sites
    CommandSpec(
        S, ("create",), "M", 5, "Create a site", site_handlers.create, configure=_create_args
    ),
    CommandSpec(S, ("status",), "R", 3, "Show site status", handlers.site_status),
    CommandSpec(S, ("enable",), "M", 5, "Enable a disabled site", site_handlers.enable),
    CommandSpec(
        S,
        ("disable",),
        "M",
        5,
        "Disable a site (maintenance page; data kept)",
        site_handlers.disable,
    ),
    CommandSpec(
        S, ("delete",), "D", 5, "Delete a site", site_handlers.delete, configure=_delete_args
    ),
    CommandSpec(S, ("repair",), "M", 5, "Clean up an interrupted operation", site_handlers.repair),
    CommandSpec(S, ("logs",), "R", 5, "Show site logs", site_handlers.logs, configure=_logs_args),
    # --- SSL
    CommandSpec(S, ("ssl",), "M", 6, "Issue a certificate now"),
    CommandSpec(S, ("autossl",), "M", 6, "Turn automatic certificates on/off"),
    CommandSpec(S, ("ssl", "status"), "R", 6, "Show certificate status"),
    CommandSpec(S, ("ssl", "renew"), "M", 6, "Renew the certificate"),
    CommandSpec(S, ("ssl", "revoke"), "D", 6, "Revoke the certificate"),
    # --- PHP
    CommandSpec(
        S, ("php", "status"), "R", 4, "Show the PHP runtime status", tenant_handlers.php_status
    ),
    CommandSpec(
        S, ("php", "restart"), "M", 4, "Restart the site's PHP runtime", tenant_handlers.php_restart
    ),
    CommandSpec(S, ("php", "optimize"), "M", 7, "Tune the site's PHP-FPM pool"),
    CommandSpec(S, ("php",), "M", 7, "Switch PHP version", configure=_php_version_arg),
    CommandSpec(S, ("optimize",), "M", 7, "Analyze/optimize the site", configure=_optimize_args),
    # --- database
    CommandSpec(
        S,
        ("db", "create"),
        "M",
        5,
        "Create a site database",
        site_handlers.db_create,
        configure=_db_create_args,
    ),
    CommandSpec(S, ("db", "status"), "R", 4, "Show database status", tenant_handlers.db_status),
    CommandSpec(S, ("db", "backup"), "M", 8, "Back up the database"),
    CommandSpec(S, ("db", "restore"), "D", 8, "Restore the database", configure=_restore_args),
    CommandSpec(
        S,
        ("db", "credentials"),
        "M",
        5,
        "Show or rotate database credentials",
        site_handlers.db_credentials,
        configure=_db_credentials_args,
    ),
    # --- SFTP
    CommandSpec(S, ("sftp", "create"), "M", 8, "Create an SFTP account"),
    CommandSpec(S, ("sftp", "list"), "R", 8, "List SFTP accounts"),
    CommandSpec(S, ("sftp", "revoke"), "D", 8, "Revoke an SFTP account", configure=_username_arg),
    # --- security & isolation
    CommandSpec(S, ("security",), "R", 9, "Security report for the site"),
    CommandSpec(
        S,
        ("isolation", "status"),
        "R",
        4,
        "Show isolation controls",
        tenant_handlers.isolation_status,
    ),
    CommandSpec(S, ("isolation", "audit"), "R", 9, "Audit isolation configuration"),
    CommandSpec(S, ("isolation", "test"), "R", 9, "Actively test isolation from inside"),
    # --- backups
    CommandSpec(S, ("backup",), "M", 8, "Back up the site"),
    CommandSpec(S, ("backup", "list"), "R", 8, "List backups"),
    CommandSpec(S, ("restore",), "D", 8, "Restore the site", configure=_restore_args),
    # --- Cloudflare (read-only unless --apply)
    CommandSpec(S, ("cloudflare", "status"), "R", 6, "Cloudflare status", configure=_apply_flag),
    CommandSpec(S, ("cloudflare", "dns"), "R", 6, "Check DNS records", configure=_apply_flag),
    CommandSpec(S, ("cloudflare", "ssl"), "R", 6, "Check SSL/TLS settings", configure=_apply_flag),
    CommandSpec(S, ("cloudflare", "security"), "R", 6, "Check WAF/security", configure=_apply_flag),
    # --- system
    CommandSpec(SY, ("status",), "R", 3, "Server status", handlers.system_status),
    CommandSpec(SY, ("health",), "R", 7, "Health checks (incl. reboot-required)"),
    CommandSpec(SY, ("update",), "M", 7, "Apply updates", configure=_update_args),
    CommandSpec(SY, ("backup",), "M", 8, "Back up configuration and all sites"),
    CommandSpec(SY, ("logs",), "R", 8, "Show system and audit logs"),
    CommandSpec(SY, ("security",), "R", 9, "Security report for the server"),
    CommandSpec(SY, ("audit",), "R", 9, "Full configuration audit"),
    CommandSpec(SY, ("optimize",), "M", 7, "Analyze/optimize the server", configure=_optimize_args),
    CommandSpec(
        SY, ("firewall", "status"), "R", 4, "Firewall status", tenant_handlers.firewall_status
    ),
    CommandSpec(
        SY,
        ("firewall", "confirm"),
        "M",
        4,
        "Confirm a pending firewall change",
        tenant_handlers.firewall_confirm,
    ),
    CommandSpec(
        SY,
        ("firewall", "rollback"),
        "M",
        4,
        "Roll back a pending firewall change",
        tenant_handlers.firewall_rollback,
    ),
)


def for_scope(scope: str) -> list[CommandSpec]:
    return [c for c in COMMANDS if c.scope == scope]


def match(scope: str, tokens: list[str]) -> CommandSpec | None:
    """Longest fixed-word match of the leading non-flag tokens."""
    best: CommandSpec | None = None
    for spec in for_scope(scope):
        n = len(spec.words)
        if tokens[:n] == list(spec.words) and (best is None or n > len(best.words)):
            best = spec
    return best
