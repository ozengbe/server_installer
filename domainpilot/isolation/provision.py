"""Create and remove isolated tenants.

Creation is a list of transaction steps, each with an undo, so a failure at
any point rolls back everything done so far (core/txn.py). Removal (purge) is
best-effort and reports every problem instead of stopping at the first one.

Root never follows tenant-controlled paths: directories are created by us in
root-owned parents, and deletion uses ``shutil.rmtree``, which is
symlink-attack resistant on Linux (fd-based traversal).
"""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from domainpilot.core import fsutil, proc
from domainpilot.core.audit import AuditLog
from domainpilot.core.config import HostFacts
from domainpilot.core.errors import OperationFailed, PreconditionFailed
from domainpilot.core.paths import Paths
from domainpilot.core.registry import Registry, Tenant
from domainpilot.core.txn import Reporter, Step, Transaction
from domainpilot.isolation import db
from domainpilot.isolation.limits import TenantLimits
from domainpilot.isolation.render import TenantSpec, render

Runner = Callable[..., proc.Result]

SYSTEMCTL = "/usr/bin/systemctl"
APPARMOR_PARSER = "/usr/sbin/apparmor_parser"
NOLOGIN = "/usr/sbin/nologin"


@dataclass(frozen=True)
class DirSpec:
    path: Path
    mode: int
    owner: str  # "root", "tenant" or "deploy"


class Provisioner:
    def __init__(
        self,
        paths: Paths,
        host: HostFacts,
        *,
        run: Runner = proc.run,
        socket_timeout: float = 20.0,
    ) -> None:
        self.paths = paths
        self.host = host
        self.run = run
        self.socket_timeout = socket_timeout

    # --- helpers -------------------------------------------------------------

    def _cmd(self, *argv: str) -> Callable[[], None]:
        def action() -> None:
            self.run(list(argv))

        return action

    def _delete_group(self, name: str) -> Callable[[], None]:
        def action() -> None:
            try:
                grp.getgrnam(name)
            except KeyError:
                return
            self.run(["/usr/sbin/groupdel", name])

        return action

    def _sql(self, sql: str) -> Callable[[], None]:
        def action() -> None:
            db.execute(sql, self.run)

        return action

    def directories(self, spec: TenantSpec) -> list[DirSpec]:
        t = spec.tenant
        root = self.paths.tenant_root(t)
        etc = self.paths.tenant_etc(t)
        dirs = [
            DirSpec(root, 0o750, "root"),
            DirSpec(root / "app", 0o2750, "deploy"),
            DirSpec(root / "app" / "public", 0o2750, "deploy"),
            DirSpec(root / "data", 0o2770, "tenant"),
            DirSpec(root / "tmp", 0o700, "tenant"),
            DirSpec(etc, 0o750, "root"),
            DirSpec(etc / "secrets", 0o750, "root"),
            DirSpec(self.paths.tenant_log(t), 0o750, "tenant"),
        ]
        if spec.php:
            dirs.append(DirSpec(self.paths.systemd / f"dp-php@{t}.service.d", 0o755, "root"))
        if spec.cache:
            dirs += [
                DirSpec(self.paths.tenant_cache_data(t), 0o700, "tenant"),
                DirSpec(self.paths.systemd / f"dp-cache@{t}.service.d", 0o755, "root"),
            ]
        return dirs

    def _parents_ready(self, spec: TenantSpec) -> None:
        """Parents we do not create ourselves must have been made by the installer."""
        ours = {d.path for d in self.directories(spec)}
        for d in self.directories(spec):
            if d.path.parent not in ours and not d.path.parent.is_dir():
                raise PreconditionFailed(
                    f"{d.path.parent} is missing", hint="run the Ozenix installer first"
                )

    def _ids(self, spec: TenantSpec, owner: str) -> tuple[int, int]:
        gid = grp.getgrnam(spec.tenant).gr_gid
        if owner == "tenant":
            return spec.uid, gid
        if owner == "deploy":
            return spec.deploy_uid, gid
        return 0, gid

    # --- creation ------------------------------------------------------------

    def create_steps(self, spec: TenantSpec, *, db_password: str) -> list[Step]:
        t = spec.tenant
        units = ([f"dp-cache@{t}.service"] if spec.cache else []) + (
            [f"dp-php@{t}.service"] if spec.php else []
        )
        files = render(spec, self.paths, self.host)
        profile = self.paths.apparmor / f"tenant-{t}"
        created_dirs: list[Path] = []
        written: list[Path] = []

        def check_free() -> None:
            self._parents_ready(spec)
            for name in (t, spec.deploy_user):
                try:
                    pwd.getpwnam(name)
                except KeyError:
                    continue
                raise PreconditionFailed(f"user {name} already exists")
            for uid in (spec.uid, spec.deploy_uid):
                try:
                    pwd.getpwuid(uid)
                except KeyError:
                    continue
                raise PreconditionFailed(f"uid {uid} is already in use")
            try:
                grp.getgrgid(spec.uid)
            except KeyError:
                return
            raise PreconditionFailed(f"gid {spec.uid} is already in use")

        def make_dirs() -> None:
            # Pass 1: create the whole tree root-owned and private, so every
            # parent is root-owned while we write into it (fsutil refuses
            # otherwise). Pass 2: hand out ownership and modes. No tenant
            # process exists yet, so nothing can race us in between.
            specs = self.directories(spec)
            for d in specs:
                if fsutil.ensure_dir(d.path, mode=0o700):
                    created_dirs.append(d.path)
            for d in specs:
                if d.path in created_dirs:
                    uid, gid = self._ids(spec, d.owner)
                    os.chown(d.path, uid, gid, follow_symlinks=False)
                    d.path.chmod(d.mode)

        def remove_dirs() -> None:
            for path in reversed(created_dirs):
                if path.exists():
                    path.rmdir()  # only ever empty here: nothing has run yet

        def write_files() -> None:
            gid = grp.getgrnam(t).gr_gid
            for f in files:
                fsutil.atomic_write(
                    f.path, f.content, mode=f.mode, uid=0, gid=gid if f.group_is_tenant else 0
                )
                written.append(f.path)
            secret = self.paths.tenant_etc(t) / "secrets" / "db.env"
            fsutil.atomic_write(
                secret,
                f"DB_USER={t}\nDB_PASSWORD={db_password}\nDB_SOCKET=/run/mysqld/mysqld.sock\n",
                mode=0o640,
                uid=0,
                gid=gid,
            )
            written.append(secret)

        def remove_files() -> None:
            for path in reversed(written):
                path.unlink(missing_ok=True)
            self.run([SYSTEMCTL, "daemon-reload"])

        def wait_for_sockets() -> None:
            wanted = [self.paths.php_socket(t)] if spec.php else []
            if spec.cache:
                wanted.append(self.paths.cache_socket(t))
            deadline = time.monotonic() + self.socket_timeout
            while time.monotonic() < deadline:
                if all(p.is_socket() for p in wanted):
                    return
                time.sleep(0.25)
            missing = ", ".join(str(p) for p in wanted if not p.is_socket())
            raise OperationFailed(
                f"tenant {t} did not start (no socket at {missing})",
                hint=f"journalctl -u dp-php@{t} -u dp-cache@{t} -n 50",
            )

        steps = [
            Step("preflight", "check tenant identity and paths are free", check_free),
            Step(
                "group",
                f"create group {t} (gid {spec.uid})",
                self._cmd("/usr/sbin/groupadd", "--gid", str(spec.uid), t),
                # userdel already removes a same-named primary group; only
                # delete the group if it is still there.
                self._delete_group(t),
            ),
            Step(
                "runtime-user",
                f"create runtime user {t} (uid {spec.uid})",
                self._cmd(
                    "/usr/sbin/useradd",
                    "--uid",
                    str(spec.uid),
                    "--gid",
                    t,
                    "--no-create-home",
                    "--home-dir",
                    str(self.paths.tenant_root(t)),
                    "--shell",
                    NOLOGIN,
                    "--comment",
                    f"Ozenix tenant {t} runtime",
                    t,
                ),
                self._cmd("/usr/sbin/userdel", t),
            ),
            Step(
                "deploy-user",
                f"create deploy user {spec.deploy_user} (uid {spec.deploy_uid})",
                self._cmd(
                    "/usr/sbin/useradd",
                    "--uid",
                    str(spec.deploy_uid),
                    "--gid",
                    t,
                    "--no-create-home",
                    "--home-dir",
                    str(self.paths.tenant_root(t)),
                    "--shell",
                    NOLOGIN,
                    "--comment",
                    f"Ozenix tenant {t} deploy",
                    spec.deploy_user,
                ),
                self._cmd("/usr/sbin/userdel", spec.deploy_user),
            ),
            Step(
                "web-server-access",
                f"let {self.host.nginx_user} read {t}'s public files and socket",
                self._cmd("/usr/bin/gpasswd", "--add", self.host.nginx_user, t),
                self._cmd("/usr/bin/gpasswd", "--delete", self.host.nginx_user, t),
            ),
            Step("directories", f"create {t} directory tree", make_dirs, remove_dirs),
            Step("configuration", f"write {t} runtime configuration", write_files, remove_files),
            Step(
                "apparmor",
                f"load AppArmor profile {spec.apparmor_profile}",
                self._cmd(APPARMOR_PARSER, "--replace", str(profile)),
                self._cmd(APPARMOR_PARSER, "--remove", str(profile)),
            ),
            Step(
                "database-user",
                f"create database account {t} (own databases only)",
                self._sql(db.create_user_sql(t, db_password)),
                self._sql(db.drop_user_sql(t)),
            ),
            Step("systemd-reload", "reload systemd units", self._cmd(SYSTEMCTL, "daemon-reload")),
            Step(
                "start",
                f"start {', '.join(units)}" if units else "no runtime services to start",
                self._cmd(SYSTEMCTL, "enable", "--now", *units) if units else _noop,
                self._cmd(SYSTEMCTL, "disable", "--now", *units) if units else None,
            ),
            Step("verify", f"wait for {t}'s sockets", wait_for_sockets),
        ]
        return steps

    # --- removal -------------------------------------------------------------

    def purge(self, tenant: str) -> list[str]:
        """Remove everything belonging to a tenant. Returns problems (empty = clean)."""
        t = tenant
        problems: list[str] = []

        def attempt(what: str, action: Callable[[], object]) -> None:
            try:
                action()
            except (OSError, KeyError, ValueError, OperationFailed) as exc:
                problems.append(f"{what}: {exc}")

        units = [f"dp-php@{t}.service", f"dp-cache@{t}.service"]
        attempt(
            "stop services", lambda: self.run([SYSTEMCTL, "disable", "--now", *units], check=False)
        )
        # Leave no runtime trace: stop the (now empty) slice and clear failed states.
        attempt(
            "stop slice",
            lambda: self.run([SYSTEMCTL, "stop", f"dptenants-{t}.slice"], check=False),
        )
        attempt(
            "clear failed state",
            lambda: self.run([SYSTEMCTL, "reset-failed", *units], check=False),
        )
        profile = self.paths.apparmor / f"tenant-{t}"
        if profile.exists():
            attempt(
                "unload AppArmor profile",
                lambda: self.run([APPARMOR_PARSER, "--remove", str(profile)], check=False),
            )
            attempt("delete AppArmor profile", lambda: profile.unlink())
        for path in (
            self.paths.systemd / f"dp-php@{t}.service.d",
            self.paths.systemd / f"dp-cache@{t}.service.d",
        ):
            attempt(f"delete {path}", lambda p=path: shutil.rmtree(p) if p.exists() else None)  # type: ignore[misc]
        attempt(
            "delete slice",
            lambda: (self.paths.systemd / f"dptenants-{t}.slice").unlink(missing_ok=True),
        )
        attempt("reload systemd", lambda: self.run([SYSTEMCTL, "daemon-reload"]))
        attempt(
            "drop databases",
            lambda: db.execute(db.drop_databases_sql(t, db.list_databases(t, self.run)), self.run),
        )
        attempt("drop database user", lambda: db.execute(db.drop_user_sql(t), self.run))
        for path in (
            self.paths.tenant_root(t),
            self.paths.tenant_etc(t),
            self.paths.tenant_log(t),
            self.paths.tenant_cache_data(t),
            self.paths.tenant_run(t),
        ):
            attempt(f"delete {path}", lambda p=path: shutil.rmtree(p) if p.exists() else None)  # type: ignore[misc]
        attempt(
            "remove web server access",
            lambda: self.run(
                ["/usr/bin/gpasswd", "--delete", self.host.nginx_user, t], check=False
            ),
        )
        attempt(
            "delete deploy user",
            lambda: self.run(["/usr/sbin/userdel", f"{t}-deploy"], check=False),
        )
        attempt("delete runtime user", lambda: self.run(["/usr/sbin/userdel", t], check=False))
        attempt("delete group", lambda: self.run(["/usr/sbin/groupdel", t], check=False))
        return problems


def provision_tenant(
    *,
    paths: Paths,
    host: HostFacts,
    registry: Registry,
    audit: AuditLog,
    php_version: str | None = None,
    limits: TenantLimits | None = None,
    cache: bool = True,
    php_open_basedir: bool = True,
    run: Runner = proc.run,
    reporter: Reporter | None = None,
    dry_run: bool = False,
) -> Tenant:
    """Allocate a tenant and build its isolated runtime (rolled back on failure)."""
    limits = limits or TenantLimits()
    php = php_version or host.default_php_version
    if php not in host.php_versions:
        raise PreconditionFailed(f"PHP {php} is not installed on this host")
    tenant = registry.allocate_tenant()
    spec = TenantSpec(tenant.id, tenant.uid, php, limits, cache, php_open_basedir)
    registry.set_tenant_settings(
        tenant.id, {"php_version": php, "cache": cache, "limits": limits.to_dict()}
    )
    txn = Transaction(
        registry=registry,
        audit=audit,
        command=["isolation", "provision", tenant.id],
        target=tenant.id,
        dry_run=dry_run,
        reporter=reporter,
    )
    for step in Provisioner(paths, host, run=run).create_steps(spec, db_password=db.new_password()):
        txn.add(step)
    try:
        txn.execute()
    except BaseException:
        registry.set_tenant_status(tenant.id, "purged")  # ID and UID are never reused
        raise
    if not dry_run:
        registry.set_tenant_status(tenant.id, "active")
    return tenant


def _noop() -> None:
    """Placeholder action for steps that have nothing to do in this configuration."""
