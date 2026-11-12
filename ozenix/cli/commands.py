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

from ozenix.cli import (
    backup_handlers,
    cf_handlers,
    handlers,
    monitor_handlers,
    ops_handlers,
    security_handlers,
    site_handlers,
    tenant_handlers,
    tls_handlers,
)
from ozenix.cli.context import Handler

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
    # False: long-running jobs (backups, monitoring) that must not block site
    # management; they take their own lock instead of the global one.
    lock: bool = True

    @property
    def usage_words(self) -> str:
        return " ".join(self.words)


def _create_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--type",
        choices=["php", "laravel", "static", "proxy", "nodejs", "python"],
        dest="site_type",
    )
    p.add_argument("--node", dest="node_version", help="Node.js major for --type nodejs (e.g. 24)")
    p.add_argument(
        "--start",
        help="start command of a nodejs/python app (default: npm start / python3 app.py); "
        "it must listen on 127.0.0.1:$PORT",
    )
    p.add_argument(
        "--user",
        dest="site_user",
        help="the site's own Linux user (SSH/SFTP login, owns the code); asked if omitted",
    )
    key = p.add_mutually_exclusive_group()
    key.add_argument("--key", dest="site_key_file", help="SSH public key file for --user")
    key.add_argument("--key-stdin", action="store_true", help="read the public key from stdin")
    p.add_argument("--php", dest="php_version")
    p.add_argument("--tier", choices=["s", "c"])
    p.add_argument("--alias", action="append", default=[])
    p.add_argument("--upstream")
    p.add_argument("--writable-code", action="store_true")
    p.add_argument(
        "--no-ssl",
        action="store_true",
        help="do not request a Let's Encrypt certificate (the self-signed one is still made)",
    )
    p.add_argument(
        "--cloudflare-dns",
        action="store_true",
        help="also create proxied DNS records in Cloudflare (needs a stored token); "
        "by default DNS is left to you",
    )
    # Accepted for old scripts; DNS is never touched unless --cloudflare-dns is given.
    p.add_argument("--no-cloudflare", action="store_true", help=argparse.SUPPRESS)
    p.add_argument(
        "--tenant-id",
        help="disaster recovery: reuse the id (tNNNN) the site had on the lost server",
    )


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
    group.add_argument("--check", action="store_true", help="only list pending updates")
    group.add_argument("--security", action="store_true", help="security updates only")
    group.add_argument("--history", action="store_true", help="show recent update runs")
    p.add_argument(
        "--include-major",
        action="store_true",
        help="also apply major branch changes (e.g. nginx 1.30 -> 1.32)",
    )


def _ssl_issue_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--staging", action="store_true", help="use the Let's Encrypt staging CA")
    p.add_argument("--challenge", choices=["http", "dns"], default="http")


def _autossl_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("state", nargs="?", choices=["on", "off"], default="on")


def _ssl_renew_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--force", action="store_true", help="renew even if not due (counts against CA rate limits)"
    )


def _token_label_opt(p: argparse.ArgumentParser) -> None:
    p.add_argument("--label", help="name for this token (default: its zone, or 'account')")


def _token_label_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("label")


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


def _report_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--verbose-report", action="store_true", help="list passing checks too, not just problems"
    )


def _show_secret_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--show-secret", action="store_true", help="print it even when not on a terminal"
    )


def _snapshot_opt(p: argparse.ArgumentParser) -> None:
    p.add_argument("--snapshot", help="server backup to read (default: the newest)")


def _rotate_key_args(p: argparse.ArgumentParser) -> None:
    _show_secret_flag(p)
    p.add_argument(
        "--finish",
        action="store_true",
        help="remove the old key (only after the new one is stored offline)",
    )


def _on_off_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("state", choices=["on", "off"])


def _app_set_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--start", help="new start command (must listen on 127.0.0.1:$PORT)")
    p.add_argument("--node", dest="node_version", help="switch the Node.js major (e.g. 26)")


def _sftp_create_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key", help="public key file (.pub)")
    p.add_argument("--key-stdin", action="store_true", help="read the public key from stdin")
    p.add_argument("--name", default="default", help="account name (default: default)")


def _system_backup_args(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group()
    group.add_argument("--verify", action="store_true", help="check repository integrity")
    group.add_argument("--test-restore", action="store_true", help="restore drill (all sites)")
    group.add_argument("--status", action="store_true", help="show the last results")


def _backup_setup_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--repository", required=True, help="s3:https://<endpoint>/<bucket>[/prefix] or /path"
    )
    p.add_argument("--credentials-stdin", action="store_true", help="S3 KEY=VALUE lines on stdin")
    p.add_argument("--keep-daily", type=int, default=7)
    p.add_argument("--keep-weekly", type=int, default=4)
    p.add_argument("--keep-monthly", type=int, default=6)
    _show_secret_flag(p)


def _monitor_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--notify", action="store_true", help="send alerts for changes")
    p.add_argument("--unit-failed", help=argparse.SUPPRESS)


def _alerts_setup_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--kind", required=True, choices=["ntfy", "slack", "discord", "telegram", "webhook"]
    )
    p.add_argument("--url-stdin", action="store_true", help="read the (secret) URL from stdin")
    p.add_argument("--min-severity", default="warn", choices=["info", "warn", "critical"])
    p.add_argument("--reminder-hours", type=int, default=6)


def _logs_system_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--audit", action="store_true", help="ozenix audit events")
    p.add_argument("--errors", action="store_true", help="warnings and errors only")
    p.add_argument("-n", "--lines", type=int, default=100)


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
    CommandSpec(
        S,
        ("ssl",),
        "M",
        6,
        "Issue a certificate now",
        tls_handlers.ssl_issue,
        configure=_ssl_issue_args,
    ),
    CommandSpec(
        S,
        ("autossl",),
        "M",
        6,
        "Turn automatic certificates on/off",
        tls_handlers.autossl,
        configure=_autossl_args,
    ),
    CommandSpec(S, ("ssl", "status"), "R", 6, "Show certificate status", tls_handlers.ssl_status),
    CommandSpec(
        S,
        ("ssl", "renew"),
        "M",
        6,
        "Renew the certificate",
        tls_handlers.ssl_renew,
        configure=_ssl_renew_args,
    ),
    CommandSpec(S, ("ssl", "revoke"), "D", 6, "Revoke the certificate", tls_handlers.ssl_revoke),
    # --- PHP
    CommandSpec(
        S, ("php", "status"), "R", 4, "Show the PHP runtime status", tenant_handlers.php_status
    ),
    CommandSpec(
        S, ("php", "restart"), "M", 4, "Restart the site's PHP runtime", tenant_handlers.php_restart
    ),
    CommandSpec(
        S,
        ("php", "optimize"),
        "M",
        7,
        "Tune the site's PHP-FPM pool",
        ops_handlers.site_optimize,
        configure=_optimize_args,
    ),
    CommandSpec(
        S,
        ("php",),
        "M",
        7,
        "Switch PHP version",
        ops_handlers.php_switch,
        configure=_php_version_arg,
    ),
    CommandSpec(
        S,
        ("optimize",),
        "M",
        7,
        "Analyze/optimize the site",
        ops_handlers.site_optimize,
        configure=_optimize_args,
    ),
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
    CommandSpec(
        S, ("db", "backup"), "M", 8, "Back up the database", backup_handlers.db_backup, lock=False
    ),
    CommandSpec(
        S,
        ("db", "restore"),
        "D",
        8,
        "Restore the database",
        backup_handlers.db_restore,
        configure=_restore_args,
    ),
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
    CommandSpec(
        S,
        ("sftp", "create"),
        "M",
        8,
        "Create an SFTP account (public key)",
        monitor_handlers.sftp_create,
        configure=_sftp_create_args,
    ),
    CommandSpec(
        S,
        ("env", "protect"),
        "M",
        11,
        "Lock down ~/app/.env (site user only, PHP read-only)",
        site_handlers.env_protect,
    ),
    CommandSpec(
        S,
        ("laravel", "queue"),
        "M",
        11,
        "Start/stop the Laravel queue worker",
        site_handlers.laravel_queue,
        configure=_on_off_arg,
    ),
    CommandSpec(
        S, ("app", "status"), "R", 11, "Node.js/Python app status", site_handlers.app_status
    ),
    CommandSpec(S, ("app", "restart"), "M", 11, "Restart the app", site_handlers.app_restart),
    CommandSpec(
        S,
        ("app", "set"),
        "M",
        11,
        "Change start command or Node.js version",
        site_handlers.app_set,
        configure=_app_set_args,
    ),
    CommandSpec(S, ("sftp", "list"), "R", 8, "List SFTP accounts", monitor_handlers.sftp_list),
    CommandSpec(
        S,
        ("sftp", "revoke"),
        "D",
        8,
        "Revoke an SFTP account",
        monitor_handlers.sftp_revoke,
        configure=_username_arg,
    ),
    # --- security & isolation
    CommandSpec(
        S,
        ("security",),
        "R",
        9,
        "Security report for the site",
        security_handlers.site_security,
        configure=_report_args,
    ),
    CommandSpec(
        S,
        ("isolation", "status"),
        "R",
        4,
        "Show isolation controls",
        tenant_handlers.isolation_status,
    ),
    CommandSpec(
        S,
        ("isolation", "audit"),
        "R",
        9,
        "Audit isolation configuration",
        security_handlers.isolation_audit,
        configure=_report_args,
    ),
    CommandSpec(
        S,
        ("isolation", "test"),
        "R",
        9,
        "Actively test isolation from inside",
        security_handlers.isolation_test,
        configure=_report_args,
    ),
    # --- backups
    CommandSpec(
        S, ("backup",), "M", 8, "Back up the site", backup_handlers.site_backup, lock=False
    ),
    CommandSpec(S, ("backup", "list"), "R", 8, "List backups", backup_handlers.backup_list),
    CommandSpec(
        S,
        ("restore",),
        "D",
        8,
        "Restore the site",
        backup_handlers.restore,
        configure=_restore_args,
    ),
    # --- Cloudflare (read-only unless --apply)
    CommandSpec(
        S,
        ("cloudflare", "status"),
        "R",
        6,
        "Cloudflare audit (DNS, SSL, security)",
        cf_handlers.status,
    ),
    CommandSpec(
        S,
        ("cloudflare", "dns"),
        "M",
        6,
        "Check DNS records (--apply: fix this site's)",
        cf_handlers.dns,
        configure=_apply_flag,
    ),
    CommandSpec(
        S,
        ("cloudflare", "ssl"),
        "R",
        6,
        "Check Cloudflare SSL/TLS settings",
        cf_handlers.ssl,
        configure=_apply_flag,
    ),
    CommandSpec(
        S,
        ("cloudflare", "security"),
        "R",
        6,
        "Check Cloudflare security settings",
        cf_handlers.security,
        configure=_apply_flag,
    ),
    # --- system
    CommandSpec(SY, ("status",), "R", 3, "Server status", handlers.system_status),
    CommandSpec(
        SY,
        ("refresh",),
        "M",
        11,
        "Re-apply every site's configuration (after an upgrade)",
        handlers.system_refresh,
    ),
    CommandSpec(
        SY, ("health",), "R", 7, "Health checks (incl. reboot-required)", ops_handlers.system_health
    ),
    CommandSpec(
        SY,
        ("update",),
        "M",
        7,
        "Check or apply updates",
        ops_handlers.system_update,
        configure=_update_args,
    ),
    CommandSpec(
        SY,
        ("backup",),
        "M",
        8,
        "Back up configuration and all sites",
        backup_handlers.system_backup,
        configure=_system_backup_args,
        lock=False,
    ),
    CommandSpec(
        SY,
        ("backup", "setup"),
        "M",
        8,
        "Configure the backup target",
        backup_handlers.setup,
        configure=_backup_setup_args,
    ),
    CommandSpec(
        SY,
        ("backup", "show-key"),
        "M",
        8,
        "Show the backup master key",
        backup_handlers.show_key,
        configure=_show_secret_flag,
    ),
    CommandSpec(
        SY,
        ("backup", "import-key"),
        "M",
        8,
        "Import a master key (disaster recovery)",
        backup_handlers.import_key,
    ),
    CommandSpec(
        SY,
        ("backup", "sites"),
        "R",
        10,
        "Sites recorded in a server backup (disaster recovery)",
        backup_handlers.recorded_sites,
        configure=_snapshot_opt,
    ),
    CommandSpec(
        SY,
        ("backup", "rotate-key"),
        "M",
        10,
        "Rotate the backup master key (then --finish)",
        backup_handlers.rotate_key,
        configure=_rotate_key_args,
    ),
    CommandSpec(
        SY,
        ("monitor",),
        "M",
        8,
        "Check everything and send alerts on changes",
        monitor_handlers.system_monitor,
        configure=_monitor_args,
        lock=False,
    ),
    CommandSpec(
        SY,
        ("alerts", "setup"),
        "M",
        8,
        "Configure where alerts go",
        monitor_handlers.alerts_setup,
        configure=_alerts_setup_args,
    ),
    CommandSpec(SY, ("alerts", "test"), "M", 8, "Send a test alert", monitor_handlers.alerts_test),
    CommandSpec(
        SY, ("alerts", "status"), "R", 8, "Show alert settings", monitor_handlers.alerts_status
    ),
    CommandSpec(
        SY,
        ("alerts", "remove"),
        "D",
        8,
        "Remove the alert destination",
        monitor_handlers.alerts_remove,
    ),
    CommandSpec(
        SY,
        ("logs",),
        "R",
        8,
        "Show system and audit logs",
        monitor_handlers.system_logs,
        configure=_logs_system_args,
    ),
    CommandSpec(
        SY,
        ("security",),
        "R",
        9,
        "Security report for the server",
        security_handlers.system_security,
    ),
    CommandSpec(SY, ("audit",), "R", 9, "Full configuration audit", security_handlers.system_audit),
    CommandSpec(
        SY,
        ("optimize",),
        "M",
        7,
        "Analyze/optimize the server",
        ops_handlers.system_optimize,
        configure=_optimize_args,
    ),
    CommandSpec(
        SY,
        ("cloudflare", "token", "add"),
        "M",
        6,
        "Store a Cloudflare API token",
        cf_handlers.token_add,
        configure=_token_label_opt,
    ),
    CommandSpec(
        SY,
        ("cloudflare", "token", "list"),
        "R",
        6,
        "List stored Cloudflare tokens",
        cf_handlers.token_list,
    ),
    CommandSpec(
        SY,
        ("cloudflare", "token", "remove"),
        "D",
        6,
        "Delete a stored Cloudflare token",
        cf_handlers.token_remove,
        configure=_token_label_arg,
    ),
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
