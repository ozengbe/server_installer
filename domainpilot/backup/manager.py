"""Site and system backups, restores and restore drills (architecture §6).

Per site, one backup run makes one *files* snapshot (app/ and data/; tmp/ is
never backed up) and one *db* snapshot per database, all tagged with the same
run id. Database dumps stream straight into restic (no temporary file).

Restores never write into a live tree directly: files are restored into a
root-only staging directory on the same filesystem, sanitised (no setuid,
no device files), verified by restic, and only then swapped in with a rename.
The replaced tree is kept next to the staging copy for manual rollback.
Databases get a safety snapshot of their current state first; if the import
fails, that safety snapshot is imported back.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from domainpilot.backup.config import BackupConfig, BackupSettings
from domainpilot.backup.restic import Piper, Restic, Runner, Snapshot
from domainpilot.core import fsutil, proc, validate
from domainpilot.core.audit import AuditLog
from domainpilot.core.errors import DPError, OperationFailed, PreconditionFailed
from domainpilot.core.paths import Paths
from domainpilot.core.registry import Registry, Tenant

MARIADB = "/usr/bin/mariadb"
MARIADB_DUMP = "/usr/bin/mariadb-dump"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEM_PATHS = [
    Path("/etc/domainpilot"),
    Path("/etc/nginx"),
    Path("/etc/letsencrypt"),
    Path("/etc/mysql"),
    Path("/etc/php"),
    Path("/etc/ssh"),
    Path("/etc/apparmor.d/domainpilot"),
    Path("/etc/nftables.conf"),
]
SUBTREES = ("app", "data")  # tmp/ is scratch space: never backed up or restored
DUMP_DONE = "-- Dump completed"
_DB_RE = re.compile(r"t[0-9]{4}_[a-z0-9_]{1,48}")
STAGING_KEEP_DAYS = 7

Reporter = Callable[[str, str], None]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class BackupManager:
    def __init__(
        self,
        *,
        paths: Paths,
        registry: Registry,
        settings: BackupSettings,
        audit: AuditLog,
        argv: list[str],
        run: Runner = proc.run,
        pipe: Piper = proc.pipeline,
        reporter: Reporter | None = None,
        hostname: str | None = None,
        system_paths: list[Path] | None = None,
    ) -> None:
        self.paths = paths
        self.registry = registry
        self.settings = settings
        self.audit = audit
        self.argv = argv
        self.run = run
        self.pipe = pipe
        self.reporter = reporter
        self.hostname = hostname or socket.gethostname()
        self.system_paths = SYSTEM_PATHS if system_paths is None else system_paths
        self.state_file = paths.var_lib / "backup" / "state.json"
        self.cache_dir = paths.var_lib / "backup" / "cache"
        self.staging_root = paths.tenants / ".dp-restore"
        self._config: BackupConfig | None = None

    # --- plumbing -------------------------------------------------------------

    def config(self) -> BackupConfig:
        if self._config is None:
            self._config = self.settings.load()
        return self._config

    def restic(self, name: str) -> Restic:
        self.cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        env = self.settings.restic_env(self.config(), name, self.cache_dir)
        return Restic(env, run=self.run, pipe=self.pipe, hostname=self.hostname)

    def _say(self, message: str, status: str = "done") -> None:
        if self.reporter:
            self.reporter(message, status)

    def load_state(self) -> dict[str, Any]:
        try:
            data = json.loads(fsutil.read_text_nofollow(self.state_file))
        except (OSError, ValueError):
            return {"sites": {}, "system": {}, "test_restore": {}, "verify": {}}
        return data if isinstance(data, dict) else {"sites": {}}

    def _save_state(self, state: dict[str, Any]) -> None:
        self.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        text = json.dumps(state, indent=2, sort_keys=True)
        fsutil.atomic_write(self.state_file, text, mode=0o600)

    def _record(self, section: str, key: str | None, ok: bool, **extra: Any) -> None:
        state = self.load_state()
        bucket = state.setdefault(section, {})
        entry = bucket.setdefault(key, {}) if key else bucket
        entry.update(last_attempt=_now(), ok=ok, **extra)
        if ok:
            entry["last_success"] = entry["last_attempt"]
            entry.pop("error", None)
        self._save_state(state)

    def tenant_for(self, domain: str) -> Tenant:
        site = self.registry.get_site(domain)
        if site is None:
            raise PreconditionFailed(f"{domain} is not an Ozenix site")
        tenant = self.registry.get_tenant(site.tenant_id)
        if tenant is None or tenant.status not in ("active", "archived"):
            raise PreconditionFailed(f"{domain} has no active tenant to back up")
        return tenant

    def databases(self, tenant: str) -> list[str]:
        tenant = validate.tenant_id(tenant)  # "t" + 4 digits: nothing to escape
        sql = (
            "SELECT schema_name FROM information_schema.schemata "  # noqa: S608
            f"WHERE schema_name LIKE '{tenant}\\_%' ORDER BY schema_name;\n"
        )
        out = self.run([MARIADB, "--batch", "--skip-column-names"], stdin=sql, timeout=60).stdout
        return [d for d in out.split() if _DB_RE.fullmatch(d) and d.startswith(tenant + "_")]

    @staticmethod
    def _dump_argv(db: str) -> list[str]:
        return [
            MARIADB_DUMP,
            "--single-transaction",
            "--quick",
            "--routines",
            "--triggers",
            "--events",
            "--hex-blob",
            "--default-character-set=utf8mb4",
            "--databases",
            db,
        ]

    # --- backup ---------------------------------------------------------------

    def backup_tenant(
        self, tenant: Tenant, *, files: bool = True, retention: bool = True
    ) -> dict[str, Any]:
        run_id = time.strftime("%Y%m%dT%H%M%S")
        tags = ["dp", f"tenant:{tenant.id}", f"run:{run_id.lower()}"]
        result: dict[str, Any] = {"tenant": tenant.id, "run": run_id.lower(), "databases": {}}
        try:
            restic = self.restic(tenant.id)
            if restic.ensure_repository():
                self._say(f"created backup repository for {tenant.id}")
            root = self.paths.tenant_root(tenant.id)
            present = [root / s for s in SUBTREES if (root / s).is_dir()]
            if present and files:
                result["files"] = restic.backup_paths(present, [*tags, "files"])
                self._say(f"backed up files of {tenant.id} ({result['files'][:8]})")
            for db in self.databases(tenant.id):
                snap = restic.backup_stream(
                    self._dump_argv(db), f"{db}.sql", [*tags, "db", f"db:{db}"]
                )
                result["databases"][db] = snap
                self._say(f"backed up database {db} ({snap[:8]})")
            if retention:
                restic.apply_retention(self.config().retention.args())
        except DPError as exc:
            self._record("sites", tenant.id, False, error=exc.message)
            self.audit.record(
                "backup.site",
                argv=self.argv,
                outcome="failure",
                details={"tenant": tenant.id, "error": exc.message},
            )
            raise
        self._record("sites", tenant.id, True, run=result["run"])
        self.audit.record("backup.site", argv=self.argv, outcome="success", details=result)
        return result

    def backup_system(self) -> dict[str, Any]:
        """The server's own configuration (+ a consistent copy of the registry)."""
        restic = self.restic("system")
        restic.ensure_repository()
        copy = self.paths.var_lib / "backup" / "registry-copy.sqlite3"
        self.registry.backup_to(copy)
        try:
            paths = [p for p in [*self.system_paths, copy] if p.exists()]
            snap = restic.backup_paths(
                paths, ["dp", "system", f"run:{time.strftime('%Y%m%dt%H%M%S')}"]
            )
            restic.apply_retention(self.config().retention.args())
        except DPError as exc:
            self._record("system", None, False, error=exc.message)
            raise
        finally:
            copy.unlink(missing_ok=True)
        self._record("system", None, True, snapshot=snap)
        self._say(f"backed up server configuration ({snap[:8]})")
        return {"snapshot": snap}

    def recorded_sites(self, snapshot: str | None = None) -> dict[str, Any]:
        """Disaster recovery: the sites (and their tenant ids) recorded in a
        server-configuration backup, read from its registry copy."""
        restic = self.restic("system")
        if snapshot:
            snap = restic.find(snapshot)
        else:
            snaps = restic.snapshots(["system"])
            if not snaps:
                raise PreconditionFailed(
                    "there is no server-configuration backup in the repository"
                )
            snap = snaps[0]
        copy = self.paths.var_lib / "backup" / "registry-copy.sqlite3"
        staging = self._staging("system")
        try:
            restic.restore(snap, staging, include=str(copy))
            restored = staging / copy.relative_to(copy.anchor)
            if not restored.is_file() or restored.is_symlink():
                raise OperationFailed(f"snapshot {snap.short_id} has no registry copy")
            conn = sqlite3.connect(f"file:{restored}?mode=ro", uri=True)
            try:
                rows = conn.execute(
                    "SELECT s.domain, s.tenant_id, s.site_type, s.php_version, s.is_primary, "
                    "t.status FROM sites s JOIN tenants t ON t.id = s.tenant_id "
                    "ORDER BY s.tenant_id, s.is_primary DESC, s.domain"
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise OperationFailed(f"cannot read the registry copy: {exc}") from None
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        sites = [
            {
                "domain": str(r[0]),
                "tenant": str(r[1]),
                "type": str(r[2]),
                "php": r[3],
                "primary": bool(r[4]),
                "status": str(r[5]),
            }
            for r in rows
        ]
        return {"snapshot": snap.short_id, "time": snap.time, "sites": sites}

    def backup_all(self) -> dict[str, Any]:
        results: dict[str, Any] = {"sites": {}, "failed": []}
        try:
            results["system"] = self.backup_system()
        except DPError as exc:
            results["failed"].append("system")
            results["system"] = {"error": exc.message}
            self._say(f"server configuration backup failed: {exc.message}", "failed")
        for tenant in self.registry.list_tenants():
            if tenant.status not in ("active", "archived"):
                continue
            try:
                results["sites"][tenant.id] = self.backup_tenant(tenant)
            except DPError as exc:
                results["failed"].append(tenant.id)
                results["sites"][tenant.id] = {"error": exc.message}
                self._say(f"backup of {tenant.id} failed: {exc.message}", "failed")
        self._prune_staging()
        return results

    # --- listing --------------------------------------------------------------

    def snapshots(self, tenant: Tenant) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self.restic(tenant.id).snapshots(["dp"])]

    def _select(
        self, restic: Restic, snapshot: str | None
    ) -> tuple[Snapshot | None, list[Snapshot]]:
        """The files snapshot and db snapshots that belong to one backup run."""
        snaps = restic.snapshots(["dp"])
        if snapshot:
            chosen = restic.find(snapshot)
            run = chosen.tag_value("run")
        else:
            latest = next((s for s in snaps if s.kind == "files"), None) or next(
                (s for s in snaps if s.kind == "db"), None
            )
            if latest is None:
                raise PreconditionFailed("there are no backups of this site yet")
            chosen, run = latest, latest.tag_value("run")
        group = [s for s in snaps if run and s.tag_value("run") == run] or [chosen]
        files = next((s for s in group if s.kind == "files"), None)
        dbs = [s for s in group if s.kind == "db" and "pre-restore" not in s.tags]
        if chosen.kind == "db" and snapshot:
            dbs = [chosen]  # an explicit db snapshot restores just that database
        return files, dbs

    # --- restore --------------------------------------------------------------

    def _staging(self, tenant: str) -> Path:
        fsutil.ensure_dir(self.staging_root, mode=0o700)
        self.staging_root.chmod(0o700)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = self.staging_root / f"{tenant}-{stamp}-{uuid.uuid4().hex[:6]}"
        target.mkdir(mode=0o700)
        return target

    @staticmethod
    def _sanitise(tree: Path) -> list[str]:
        """Strip setuid/setgid from files, drop device/fifo/socket nodes."""
        removed = []
        for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
            for name in [*filenames, *dirnames]:
                path = Path(dirpath) / name
                st = path.lstat()
                if stat.S_ISREG(st.st_mode) and st.st_mode & 0o6000:
                    path.chmod(stat.S_IMODE(st.st_mode) & ~0o6000)
                elif not (
                    stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
                ):
                    path.unlink()
                    removed.append(str(path.relative_to(tree)))
        return removed

    def restore(
        self, domain: str, *, snapshot: str | None, what: str, to_staging: bool
    ) -> dict[str, Any]:
        tenant = self.tenant_for(domain)
        restic = self.restic(tenant.id)
        files, dbs = self._select(restic, snapshot)
        result: dict[str, Any] = {"domain": domain, "tenant": tenant.id, "to_staging": to_staging}
        if what in ("files", "all") and files is None:
            raise PreconditionFailed("that backup run has no files snapshot")
        staging = self._staging(tenant.id)
        result["staging"] = str(staging)
        if what in ("files", "all") and files is not None:
            result["files"] = self._restore_files(tenant, restic, files, staging, to_staging)
        if what in ("db", "all"):
            result["databases"] = self._restore_dbs(tenant, restic, dbs, staging, to_staging)
        self.audit.record(
            "backup.restore",
            argv=self.argv,
            outcome="success",
            details={
                "domain": domain,
                "tenant": tenant.id,
                "what": what,
                "to_staging": to_staging,
                "files": files.short_id if files and what != "db" else None,
                "databases": sorted(result.get("databases", {})),
            },
        )
        return result

    def _restore_files(
        self, tenant: Tenant, restic: Restic, snap: Snapshot, staging: Path, to_staging: bool
    ) -> dict[str, Any]:
        restic.restore(snap, staging / "restore")
        root = self.paths.tenant_root(tenant.id)
        staged = staging / "restore" / root.relative_to(root.anchor)
        removed = self._sanitise(staging / "restore")
        self._say(f"restored files snapshot {snap.short_id} into staging (verified)")
        info: dict[str, Any] = {"snapshot": snap.short_id, "removed_special_files": removed}
        if to_staging:
            info["path"] = str(staged)
            return info
        previous = staging / "previous"
        previous.mkdir(mode=0o700)
        swapped = []
        for sub in SUBTREES:
            new = staged / sub
            if not new.is_dir():
                continue
            live = root / sub
            if live.exists() or live.is_symlink():
                live.rename(previous / sub)
            new.rename(live)
            swapped.append(sub)
        settings = self.registry.get_tenant_settings(tenant.id)
        if settings.get("php"):  # drop OPcache's view of the old code
            self.run([SYSTEMCTL, "try-restart", f"dp-php@{tenant.id}.service"], timeout=120)
        self._say(f"swapped in {', '.join(swapped)}; previous copy kept in {previous}")
        info.update(swapped=swapped, previous=str(previous))
        return info

    def _restore_dbs(
        self, tenant: Tenant, restic: Restic, dbs: list[Snapshot], staging: Path, to_staging: bool
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for snap in dbs:
            db = snap.tag_value("db") or ""
            if not (_DB_RE.fullmatch(db) and db.startswith(tenant.id + "_")):
                raise OperationFailed(f"snapshot {snap.short_id} is not a database of {tenant.id}")
            if to_staging:
                restic.restore(snap, staging / "db")
                out[db] = {"snapshot": snap.short_id, "path": str(staging / "db" / f"{db}.sql")}
                continue
            tail = restic.dump_tail(snap, f"{db}.sql")
            if not tail.startswith(DUMP_DONE):
                raise OperationFailed(f"snapshot {snap.short_id} of {db} is not a complete dump")
            safety = ""
            if db in self.databases(tenant.id):
                safety = restic.backup_stream(
                    self._dump_argv(db),
                    f"{db}.sql",
                    ["dp", f"tenant:{tenant.id}", "db", f"db:{db}", "pre-restore"],
                )
            self._import(db, restic, snap, safety)
            out[db] = {"snapshot": snap.short_id, "safety_snapshot": safety[:8] or None}
            self._say(f"restored database {db} from {snap.short_id}")
        return out

    def _import(self, db: str, restic: Restic, snap: Snapshot, safety: str) -> None:
        drop = f"DROP DATABASE IF EXISTS `{db}`;\n"
        self.run([MARIADB, "--batch"], stdin=drop, timeout=600)
        try:
            restic.dump_into(snap, f"{db}.sql", [MARIADB, "--batch"])
        except DPError:
            if safety:
                self.run([MARIADB, "--batch"], stdin=drop, timeout=600)
                restic.dump_into(restic.find(safety[:8]), f"{db}.sql", [MARIADB, "--batch"])
                self._say(f"import failed; {db} put back from safety snapshot", "failed")
            raise

    def _prune_staging(self) -> None:
        if not self.staging_root.is_dir():
            return
        cutoff = time.time() - STAGING_KEEP_DAYS * 86400
        for entry in self.staging_root.iterdir():
            if entry.is_dir() and not entry.is_symlink() and entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry)

    # --- verification ---------------------------------------------------------

    def _repos(self) -> list[str]:
        tenants = [t.id for t in self.registry.list_tenants() if t.status in ("active", "archived")]
        return ["system", *tenants]

    # --- master-key rotation ----------------------------------------------------

    def restic_with(self, name: str, key: str) -> Restic:
        self.cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        env = self.settings.restic_env(self.config(), name, self.cache_dir, key=key)
        return Restic(env, run=self.run, pipe=self.pipe, hostname=self.hostname)

    def _password_file(self, name: str) -> Path:
        """New repository password for `restic key add`, on tmpfs, root 0600."""
        self.paths.run.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.paths.run / f"rotate-{name}-{uuid.uuid4().hex}.pw"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, self.settings.repo_password(name, key="master-next").encode())
        finally:
            os.close(fd)
        return path

    def rotate_key(self) -> dict[str, Any]:
        """Step 1: add a key derived from a new master to every repository, then
        make the new master current. The old key keeps working until finish."""
        state = self.settings.rotation_state()
        if state == "promoted":
            raise PreconditionFailed(
                "a previous rotation is waiting to be finished",
                hint="store the current key offline, then: sudo site system backup "
                "rotate-key --finish",
            )
        self.settings.begin_rotation()
        results: dict[str, str] = {}
        for name in self._repos():
            if self.restic_with(name, "master-next").probe() == "ok":
                results[name] = "already rotated"
                continue
            status = self.restic_with(name, "master").probe()
            if status == "absent":
                results[name] = "no repository yet"
                continue
            if status != "ok":
                raise OperationFailed(
                    f"repository {name}: neither the current nor the new key opens it",
                    hint="nothing was removed; check `sudo site system backup --verify`",
                )
            pw = self._password_file(name)
            try:
                self.restic_with(name, "master").add_key(pw)
            finally:
                pw.unlink(missing_ok=True)
            if self.restic_with(name, "master-next").probe() != "ok":
                raise OperationFailed(
                    f"repository {name}: the new key was added but does not open it"
                )
            results[name] = "new key added"
            self._say(f"{name}: new key added")
        self.settings.promote_next()
        self.audit.record(
            "backup.rotate_key",
            argv=self.argv,
            outcome="success",
            details={"step": "promoted", "repositories": len(results)},
        )
        return {"step": "promoted", "repositories": results}

    def finish_rotation(self) -> dict[str, Any]:
        """Step 2: remove the old key from every repository."""
        if self.settings.rotation_state() != "promoted":
            raise PreconditionFailed(
                "no rotation is waiting to be finished",
                hint="start one with: sudo site system backup rotate-key",
            )
        results: dict[str, str] = {}
        for name in self._repos():
            old = self.restic_with(name, "master-prev")
            status = old.probe()
            if status != "ok":
                results[name] = "old key already gone" if status == "denied" else "no repository"
                continue
            old_id = old.current_key_id()
            new = self.restic_with(name, "master")
            if new.probe() != "ok":
                raise OperationFailed(
                    f"repository {name}: the new key does not open it; keeping the old key",
                    hint="run `sudo site system backup rotate-key` again first",
                )
            if new.current_key_id() == old_id:  # same password (should never happen)
                results[name] = "unchanged"
                continue
            new.remove_key(old_id)
            results[name] = "old key removed"
            self._say(f"{name}: old key removed")
        self.settings.drop_previous()
        self.audit.record(
            "backup.rotate_key",
            argv=self.argv,
            outcome="success",
            details={"step": "finished", "repositories": len(results)},
        )
        return {"step": "finished", "repositories": results}

    def verify(self, *, read_data_subset: str = "2%") -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name in self._repos():
            try:
                self.restic(name).check(read_data_subset)
                results[name] = "ok"
            except DPError as exc:
                results[name] = exc.message
        ok = all(v == "ok" for v in results.values())
        self._record("verify", None, ok, results=results)
        return {"repositories": results, "ok": ok}

    def test_restore(self) -> dict[str, Any]:
        """Restore drill: the newest backup of every site must restore and be complete."""
        results: dict[str, Any] = {}
        for tenant in self.registry.list_tenants():
            if tenant.status != "active":
                continue
            staging = self._staging(tenant.id)
            try:
                restic = self.restic(tenant.id)
                files, dbs = self._select(restic, None)
                checked: dict[str, Any] = {}
                if files is not None:
                    restic.restore(files, staging / "restore")  # --verify checks contents
                    count = sum(len(f) for _d, _s, f in os.walk(staging / "restore"))
                    checked["files"] = {"snapshot": files.short_id, "count": count}
                for snap in dbs:
                    db = snap.tag_value("db") or "?"
                    if not restic.dump_tail(snap, f"{db}.sql").startswith(DUMP_DONE):
                        raise OperationFailed(f"{db}: dump in {snap.short_id} is incomplete")
                    checked[db] = {"snapshot": snap.short_id, "complete": True}
                results[tenant.id] = {"ok": True, **checked}
            except DPError as exc:
                results[tenant.id] = {"ok": False, "error": exc.message}
            finally:
                shutil.rmtree(staging, ignore_errors=True)
        ok = all(r["ok"] for r in results.values())
        self._record("test_restore", None, ok, results=results)
        self.audit.record(
            "backup.test_restore",
            argv=self.argv,
            outcome="success" if ok else "failure",
            details=results,
        )
        return {"sites": results, "ok": ok}
