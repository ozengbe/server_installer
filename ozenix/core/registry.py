"""Site registry: the source of truth for tenants, sites and operations.

SQLite (stdlib), root-only file (0600), WAL mode, foreign keys on, and
forward-only numbered migrations. Tenant IDs and UIDs are never reused, so a
deleted tenant's leftover files can never be inherited by a new tenant.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ozenix.core import validate
from ozenix.core.errors import OperationFailed, PreconditionFailed

UID_BASE = 20000
UID_MAX = 29999
SITE_TYPES = ("php", "static", "proxy", "nodejs", "python")
TENANT_STATUSES = ("provisioning", "active", "disabled", "deleting", "archived", "purged")
OPERATION_STATUSES = ("running", "succeeded", "failed", "rolled_back", "rollback_failed")

_MIGRATIONS: Sequence[str] = (
    # 1: initial schema
    f"""
    CREATE TABLE tenants (
        id          TEXT PRIMARY KEY,
        seq         INTEGER NOT NULL UNIQUE,
        uid         INTEGER NOT NULL UNIQUE CHECK (uid BETWEEN {UID_BASE} AND {UID_MAX}),
        status      TEXT NOT NULL CHECK (status IN {TENANT_STATUSES!r}),
        tier        TEXT NOT NULL DEFAULT 's' CHECK (tier IN ('s', 'c')),
        host        TEXT NOT NULL DEFAULT 'local',
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );
    CREATE TABLE sites (
        domain      TEXT PRIMARY KEY,
        tenant_id   TEXT NOT NULL REFERENCES tenants(id),
        is_primary  INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
        site_type   TEXT NOT NULL CHECK (site_type IN ('php', 'static', 'proxy')),
        php_version TEXT,
        enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at  TEXT NOT NULL
    );
    CREATE INDEX sites_tenant ON sites(tenant_id);
    CREATE TABLE operations (
        id          TEXT PRIMARY KEY,
        started_at  TEXT NOT NULL,
        finished_at TEXT,
        actor       TEXT NOT NULL,
        command     TEXT NOT NULL,
        target      TEXT,
        status      TEXT NOT NULL CHECK (status IN {OPERATION_STATUSES!r}),
        steps       TEXT NOT NULL DEFAULT '[]',
        error       TEXT
    );
    CREATE INDEX operations_target ON operations(target, status);
    """,
    # 2: per-tenant settings (PHP version, cache, resource limits) as JSON
    """
    ALTER TABLE tenants ADD COLUMN settings TEXT NOT NULL DEFAULT '{}';
    """,
    # 3: Node.js and Python sites (SQLite cannot alter a CHECK: rebuild the table).
    # Only the constant SITE_TYPES is interpolated.
    f"""
    CREATE TABLE sites_v3 (
        domain      TEXT PRIMARY KEY,
        tenant_id   TEXT NOT NULL REFERENCES tenants(id),
        is_primary  INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
        site_type   TEXT NOT NULL CHECK (site_type IN {SITE_TYPES!r}),
        php_version TEXT,
        enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at  TEXT NOT NULL
    );
    INSERT INTO sites_v3 (domain, tenant_id, is_primary, site_type, php_version, enabled,
                          created_at)
        SELECT domain, tenant_id, is_primary, site_type, php_version, enabled, created_at
        FROM sites;
    DROP TABLE sites;
    ALTER TABLE sites_v3 RENAME TO sites;
    CREATE INDEX sites_tenant ON sites(tenant_id);
    """,  # noqa: S608  # nosec B608  # constant SITE_TYPES only
)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


@dataclass(frozen=True)
class Tenant:
    id: str
    uid: int
    status: str
    tier: str
    host: str
    created_at: str


@dataclass(frozen=True)
class Site:
    domain: str
    tenant_id: str
    is_primary: bool
    site_type: str
    php_version: str | None
    enabled: bool
    created_at: str


@dataclass(frozen=True)
class Operation:
    id: str
    started_at: str
    finished_at: str | None
    actor: str
    command: list[str]
    target: str | None
    status: str
    steps: list[dict[str, Any]]
    error: str | None


class Registry:
    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        self._conn = conn
        self.path = path

    # --- lifecycle -----------------------------------------------------------

    @classmethod
    def open(cls, path: Path, *, create: bool = True) -> Registry | None:
        """Open (and migrate) the registry. Returns None if missing and not ``create``."""
        if not path.exists():
            if not create:
                return None
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        if path.is_symlink():
            raise OperationFailed(f"registry {path} is a symlink; refusing to open")
        conn = sqlite3.connect(path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        registry = cls(conn, path)
        registry._migrate()
        return registry

    def close(self) -> None:
        self._conn.close()

    def backup_to(self, target: Path) -> None:
        """Consistent copy of the live database (SQLite online backup), root 0600."""
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.unlink(missing_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        dest = sqlite3.connect(target)
        try:
            self._conn.backup(dest)
        finally:
            dest.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _migrate(self) -> None:
        current = self.schema_version()
        if current > len(_MIGRATIONS):
            raise OperationFailed(
                f"registry schema v{current} is newer than this ozenix "
                f"(supports v{len(_MIGRATIONS)}); upgrade ozenix first"
            )
        for number, script in enumerate(_MIGRATIONS[current:], start=current + 1):
            with self._tx() as conn:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {number:d}")

    def schema_version(self) -> int:
        row = self._conn.execute("PRAGMA user_version").fetchone()
        return int(row[0])

    # --- tenants & sites -----------------------------------------------------

    def allocate_tenant(self, *, tier: str = "s", tenant_id: str | None = None) -> Tenant:
        """Reserve the next tenant ID and UID (never reused).

        ``tenant_id`` is for disaster recovery on a new server: the site gets the
        id it had on the lost one, so its backup repository, file owners and
        database names match. It must never have existed in this registry.
        """
        if tier not in ("s", "c"):
            raise OperationFailed(f"unknown tier {tier!r}")
        now = _now()
        with self._tx() as conn:
            if tenant_id is not None:
                seq = int(validate.tenant_id(tenant_id)[1:])
                if seq < 1:
                    raise PreconditionFailed("tenant ids start at t0001")
                used = conn.execute("SELECT 1 FROM tenants WHERE seq = ?", (seq,)).fetchone()
                if used:
                    raise PreconditionFailed(
                        f"tenant {tenant_id} already exists on this server (ids are never reused)"
                    )
            else:
                row = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM tenants").fetchone()
                seq = int(row[0]) + 1
            uid = UID_BASE + seq
            if uid > UID_MAX:
                raise PreconditionFailed("tenant UID range exhausted")
            tid = validate.tenant_id(f"t{seq:04d}")
            conn.execute(
                "INSERT INTO tenants (id, seq, uid, status, tier, created_at, updated_at) "
                "VALUES (?, ?, ?, 'provisioning', ?, ?, ?)",
                (tid, seq, uid, tier, now, now),
            )
        return Tenant(tid, uid, "provisioning", tier, "local", now)

    def set_tenant_status(self, tenant_id: str, status: str) -> None:
        if status not in TENANT_STATUSES:
            raise OperationFailed(f"unknown tenant status {status!r}")
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE tenants SET status = ?, updated_at = ? WHERE id = ?",
                (status, _now(), tenant_id),
            )
            if cur.rowcount != 1:
                raise OperationFailed(f"tenant {tenant_id} not found")

    def get_tenant_settings(self, tenant_id: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT settings FROM tenants WHERE id = ?", (tenant_id,)
        ).fetchone()
        if row is None:
            raise OperationFailed(f"tenant {tenant_id} not found")
        data: dict[str, Any] = json.loads(row[0])
        return data

    def set_tenant_settings(self, tenant_id: str, settings: dict[str, Any]) -> None:
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE tenants SET settings = ?, updated_at = ? WHERE id = ?",
                (json.dumps(settings, sort_keys=True), _now(), tenant_id),
            )
            if cur.rowcount != 1:
                raise OperationFailed(f"tenant {tenant_id} not found")

    def list_tenants(self) -> list[Tenant]:
        rows = self._conn.execute(
            "SELECT id, uid, status, tier, host, created_at FROM tenants ORDER BY seq"
        ).fetchall()
        return [Tenant(*r) for r in rows]

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        row = self._conn.execute(
            "SELECT id, uid, status, tier, host, created_at FROM tenants WHERE id = ?",
            (tenant_id,),
        ).fetchone()
        return Tenant(*row) if row else None

    def add_site(
        self,
        domain: str,
        tenant_id: str,
        *,
        site_type: str,
        php_version: str | None,
        is_primary: bool = True,
    ) -> Site:
        domain = validate.domain(domain)
        if site_type not in SITE_TYPES:
            raise OperationFailed(f"unknown site type {site_type!r}")
        if php_version is not None:
            validate.php_version(php_version)
        now = _now()
        try:
            with self._tx() as conn:
                conn.execute(
                    "INSERT INTO sites (domain, tenant_id, is_primary, site_type, php_version,"
                    " enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (domain, tenant_id, int(is_primary), site_type, php_version, now),
                )
        except sqlite3.IntegrityError as exc:
            raise PreconditionFailed(f"cannot register {domain}: {exc}") from None
        return Site(domain, tenant_id, is_primary, site_type, php_version, True, now)

    def get_site(self, domain: str) -> Site | None:
        row = self._conn.execute(
            "SELECT domain, tenant_id, is_primary, site_type, php_version, enabled, created_at "
            "FROM sites WHERE domain = ?",
            (domain,),
        ).fetchone()
        if not row:
            return None
        return Site(
            row["domain"],
            row["tenant_id"],
            bool(row["is_primary"]),
            row["site_type"],
            row["php_version"],
            bool(row["enabled"]),
            row["created_at"],
        )

    def list_sites(self) -> list[Site]:
        rows = self._conn.execute(
            "SELECT domain FROM sites ORDER BY tenant_id, is_primary DESC, domain"
        ).fetchall()
        sites = [self.get_site(r["domain"]) for r in rows]
        return [s for s in sites if s is not None]

    def remove_site(self, domain: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM sites WHERE domain = ?", (domain,))

    def set_site_enabled(self, domain: str, enabled: bool) -> None:
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE sites SET enabled = ? WHERE domain = ?", (int(enabled), domain)
            )
            if cur.rowcount != 1:
                raise OperationFailed(f"site {domain} not found")

    def set_php_version(self, tenant_id: str, version: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE sites SET php_version = ? WHERE tenant_id = ?",
                (validate.php_version(version), tenant_id),
            )

    def sites_for_tenant(self, tenant_id: str) -> list[Site]:
        return [s for s in self.list_sites() if s.tenant_id == tenant_id]

    def tenants_for_domain(self, domain: str, *, statuses: tuple[str, ...]) -> list[Tenant]:
        """Tenants whose settings name this domain (used to find half-built sites)."""
        found = []
        for tenant in self.list_tenants():
            if (
                tenant.status in statuses
                and self.get_tenant_settings(tenant.id).get("domain") == domain
            ):
                found.append(tenant)
        return found

    def counts(self) -> dict[str, int]:
        tenants = self._conn.execute(
            "SELECT COUNT(*) FROM tenants WHERE status NOT IN ('archived', 'purged')"
        ).fetchone()[0]
        sites = self._conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
        enabled = self._conn.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1").fetchone()[0]
        running = self._conn.execute(
            "SELECT COUNT(*) FROM operations WHERE status IN ('running', 'rollback_failed')"
        ).fetchone()[0]
        return {
            "tenants": int(tenants),
            "sites": int(sites),
            "sites_enabled": int(enabled),
            "unfinished_operations": int(running),
        }

    # --- operation journal ---------------------------------------------------

    def begin_operation(self, *, actor: str, command: Sequence[str], target: str | None) -> str:
        op_id = uuid.uuid4().hex
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO operations (id, started_at, actor, command, target, status) "
                "VALUES (?, ?, ?, ?, ?, 'running')",
                (op_id, _now(), actor, json.dumps(list(command)), target),
            )
        return op_id

    def update_operation(
        self,
        op_id: str,
        *,
        steps: list[dict[str, Any]],
        status: str = "running",
        error: str | None = None,
    ) -> None:
        if status not in OPERATION_STATUSES:
            raise OperationFailed(f"unknown operation status {status!r}")
        finished = None if status == "running" else _now()
        with self._tx() as conn:
            conn.execute(
                "UPDATE operations SET steps = ?, status = ?, error = ?, finished_at = ? "
                "WHERE id = ?",
                (json.dumps(steps), status, error, finished, op_id),
            )

    def get_operation(self, op_id: str) -> Operation | None:
        row = self._conn.execute("SELECT * FROM operations WHERE id = ?", (op_id,)).fetchone()
        return self._operation(row) if row else None

    def unfinished_operations(self, target: str | None = None) -> list[Operation]:
        query = "SELECT * FROM operations WHERE status IN ('running', 'rollback_failed')"
        params: tuple[Any, ...] = ()
        if target is not None:
            query += " AND target = ?"
            params = (target,)
        rows = self._conn.execute(query + " ORDER BY started_at", params).fetchall()
        return [self._operation(r) for r in rows]

    @staticmethod
    def _operation(row: sqlite3.Row) -> Operation:
        return Operation(
            id=row["id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            actor=row["actor"],
            command=json.loads(row["command"]),
            target=row["target"],
            status=row["status"],
            steps=json.loads(row["steps"]),
            error=row["error"],
        )
