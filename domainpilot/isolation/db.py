"""Per-tenant MariaDB accounts.

The tenant's database user can authenticate with the OS identity of its PHP
process (unix_socket, no secret to steal) or with a generated password, and is
granted privileges only on databases named ``<tenant>_*``. MariaDB listens on
its Unix socket only (skip-networking).

All identifiers are validated before being placed into SQL; passwords come
from ``secrets.token_urlsafe`` ([A-Za-z0-9_-] only). SQL is passed on stdin,
never on the command line.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence

from domainpilot.core import proc, validate

MARIADB = "/usr/bin/mariadb"
MAX_USER_CONNECTIONS = 20

Runner = Callable[..., proc.Result]


def new_password() -> str:
    return secrets.token_urlsafe(24)


def _check_password(password: str) -> str:
    if not password or any(not (c.isalnum() or c in "-_") for c in password):
        raise ValueError("password must be URL-safe base64")
    return password


def create_user_sql(tenant: str, password: str) -> str:
    t = validate.tenant_id(tenant)
    pw = _check_password(password)
    return (
        f"CREATE USER IF NOT EXISTS '{t}'@'localhost' "
        f"IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('{pw}') "
        f"WITH MAX_USER_CONNECTIONS {MAX_USER_CONNECTIONS};\n"
        f"GRANT ALL PRIVILEGES ON `{t}\\_%`.* TO '{t}'@'localhost';\n"
    )


def drop_user_sql(tenant: str) -> str:
    return f"DROP USER IF EXISTS '{validate.tenant_id(tenant)}'@'localhost';\n"


def database_name(tenant: str, name: str) -> str:
    return f"{validate.tenant_id(tenant)}_{validate.db_name(name)}"


def create_database_sql(tenant: str, name: str) -> str:
    db = database_name(tenant, name)
    return (
        f"CREATE DATABASE IF NOT EXISTS `{db}` "
        "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
    )


def drop_databases_sql(tenant: str, databases: Sequence[str]) -> str:
    t = validate.tenant_id(tenant)
    out = []
    for db in databases:
        if not db.startswith(f"{t}_"):
            raise ValueError(f"database {db!r} does not belong to {t}")
        validate.db_name(db[len(t) + 1 :])
        out.append(f"DROP DATABASE IF EXISTS `{db}`;\n")
    return "".join(out)


def execute(sql: str, run: Runner = proc.run) -> proc.Result:
    return run([MARIADB, "--batch", "--skip-column-names"], stdin=sql, timeout=60)


def list_databases(tenant: str, run: Runner = proc.run) -> list[str]:
    t = validate.tenant_id(tenant)
    result = execute(
        "SELECT schema_name FROM information_schema.schemata "
        f"WHERE schema_name LIKE '{t}\\_%';\n",
        run,
    )
    return [line for line in result.stdout.splitlines() if line]


def user_exists(tenant: str, run: Runner = proc.run) -> bool:
    t = validate.tenant_id(tenant)
    result = execute(
        f"SELECT COUNT(*) FROM mysql.user WHERE User='{t}' AND Host='localhost';\n", run
    )
    return result.stdout.strip() == "1"
