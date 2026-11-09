"""Server-wide tuning: nginx, MariaDB, PHP OPcache.

The tuning values live in files owned by the optimizer (the installer only
creates them once), so the installer and the optimizer never fight over the
same lines. Apply = snapshot -> write -> validate -> activate; any failure
restores the snapshot. MariaDB is never restarted: dynamic variables are set
live and the file makes them permanent.
"""

from __future__ import annotations

import difflib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from domainpilot.core import fsutil, proc
from domainpilot.core.errors import DPError, OperationFailed
from domainpilot.optimize.profiles import Tuning
from domainpilot.optimize.snapshot import Snapshot, SnapshotStore

Runner = Callable[..., proc.Result]
NGINX = "/usr/sbin/nginx"
SYSTEMCTL = "/usr/bin/systemctl"
MARIADB = "/usr/bin/mariadb"

HEADER = (
    "# Managed by DomainPilot's optimizer (`site system optimize`). Rolled back with --rollback.\n"
)
# MariaDB variables that can be changed at runtime (value in the cnf -> SET GLOBAL).
DYNAMIC_DB: dict[str, Callable[[str], int]] = {
    "innodb_buffer_pool_size": lambda v: int(v.rstrip("M")) * 1024 * 1024,
    "max_connections": int,
    "table_open_cache": int,
    "tmp_table_size": lambda v: int(v.rstrip("M")) * 1024 * 1024,
    "max_heap_table_size": lambda v: int(v.rstrip("M")) * 1024 * 1024,
    "innodb_io_capacity": int,
}


@dataclass
class Layout:
    nginx_events: Path = Path("/etc/nginx/domainpilot/tuning-events.conf")
    nginx_http: Path = Path("/etc/nginx/domainpilot/tuning-http.conf")
    mariadb: Path = Path("/etc/mysql/mariadb.conf.d/98-domainpilot-tuning.cnf")
    php_conf_d: list[Path] = field(default_factory=list)  # /etc/php/<v>/fpm/conf.d

    def php_files(self) -> list[Path]:
        return [d / "98-domainpilot-tuning.ini" for d in self.php_conf_d]

    def all(self) -> list[Path]:
        return [self.nginx_events, self.nginx_http, self.mariadb, *self.php_files()]


def render(t: Tuning, layout: Layout) -> dict[Path, str]:
    files = {
        layout.nginx_events: HEADER + f"worker_connections {t.nginx_worker_connections};\n",
        layout.nginx_http: HEADER + f"open_file_cache max={t.nginx_open_file_cache} inactive=60s;\n"
        "open_file_cache_valid 120s;\n"
        "open_file_cache_min_uses 2;\n"
        "open_file_cache_errors on;\n",
        layout.mariadb: HEADER + "[mysqld]\n"
        f"innodb_buffer_pool_size = {t.mariadb_buffer_pool_mb}M\n"
        f"max_connections = {t.mariadb_max_connections}\n"
        f"table_open_cache = {t.mariadb_table_open_cache}\n"
        f"tmp_table_size = {t.mariadb_tmp_table_mb}M\n"
        f"max_heap_table_size = {t.mariadb_tmp_table_mb}M\n"
        f"innodb_io_capacity = {t.mariadb_io_capacity}\n",
    }
    for php in layout.php_files():
        files[php] = (
            HEADER.replace("#", ";") + f"opcache.memory_consumption = {t.opcache_memory_mb}\n"
            f"opcache.max_accelerated_files = {t.opcache_max_files}\n"
        )
    return files


def parse_db_values(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        m = re.fullmatch(r"\s*([a-z_]+)\s*=\s*([0-9]+M?)\s*", line)
        if m and m.group(1) in DYNAMIC_DB:
            values[m.group(1)] = m.group(2)
    return values


class ServerTuner:
    def __init__(
        self,
        layout: Layout,
        snapshots: SnapshotStore,
        *,
        run: Runner = proc.run,
        nginx_reload: Callable[[], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.layout = layout
        self.snapshots = snapshots
        self.run = run
        self.sleep = sleep
        self.nginx_reload = nginx_reload or (lambda: self.run([SYSTEMCTL, "reload", "nginx"]))

    def diff(self, tuning: Tuning) -> list[dict[str, Any]]:
        changes = []
        for path, new in render(tuning, self.layout).items():
            old = fsutil.read_text_nofollow(path) if path.exists() else ""
            if old != new:
                changes.append(
                    {
                        "path": str(path),
                        "diff": "".join(
                            difflib.unified_diff(
                                old.splitlines(keepends=True),
                                new.splitlines(keepends=True),
                                fromfile=f"{path} (current)",
                                tofile=f"{path} (recommended)",
                            )
                        ),
                    }
                )
        return changes

    def apply(self, tuning: Tuning, *, note: str = "") -> tuple[Snapshot, list[str]]:
        files = render(tuning, self.layout)
        snap = self.snapshots.take("server", list(files), note=note or tuning.profile)
        warnings: list[str] = []
        try:
            for path, content in files.items():
                fsutil.atomic_write(path, content, mode=0o644)
            self._activate(warnings)
        except DPError:
            self.snapshots.restore(snap)
            self._activate([])
            raise
        return snap, warnings

    def rollback(self, snap_id: str) -> tuple[Snapshot, list[str], list[str]]:
        snap = self.snapshots.get(snap_id)
        changed = self.snapshots.restore(snap)
        warnings: list[str] = []
        self._activate(warnings)
        return snap, changed, warnings

    def _activate(self, warnings: list[str]) -> None:
        test = self.run([NGINX, "-t", "-q"], check=False, timeout=60)
        if not test.ok:
            raise OperationFailed(
                "nginx rejected the tuned configuration: "
                + (test.stderr.strip().splitlines() or ["?"])[-1]
            )
        self.nginx_reload()
        if self.layout.mariadb.exists():
            values = parse_db_values(fsutil.read_text_nofollow(self.layout.mariadb))
            self._apply_db({k: DYNAMIC_DB[k](v) for k, v in values.items()}, warnings)
        if self.layout.php_files():
            # OPcache size is fixed when a master starts. The tenant sandbox may not
            # exec anything (AppArmor), so php-fpm's USR2 re-exec cannot work: restart
            # (Type=notify, so systemd waits until each new master is ready).
            self.run([SYSTEMCTL, "try-restart", "dp-php@*.service"], check=False, timeout=300)

    def _apply_db(self, wanted: dict[str, int], warnings: list[str]) -> None:
        """SET GLOBAL each value, then read the running values back.

        Statements run one by one (--force) so one refused value does not stop the
        others; whatever MariaDB did not take is reported, never claimed.
        """
        if not wanted:
            return
        sql = "".join(f"SET GLOBAL {k} = {v};\n" for k, v in wanted.items())
        try:
            self.run([MARIADB, "--batch", "--force"], stdin=sql, check=False, timeout=300)
            live = self._db_values(list(wanted))
            # InnoDB may resize the buffer pool in the background (MariaDB 10.11).
            for _ in range(30):
                pool = "innodb_buffer_pool_size"
                if not live or pool not in wanted or live.get(pool) == wanted[pool]:
                    break
                self.sleep(1)
                live = self._db_values(list(wanted))
        except DPError as exc:
            warnings.append(
                f"MariaDB values saved but not applied live ({exc}); "
                "they take effect at the next MariaDB restart"
            )
            return
        for key, value in wanted.items():
            if key in live and live[key] != value:
                warnings.append(
                    f"MariaDB is running with {key} = {live[key]} (saved: {value}); "
                    "the saved value takes effect at the next MariaDB restart"
                )

    def _db_values(self, keys: list[str]) -> dict[str, int]:
        result = self.run(
            [MARIADB, "--batch", "--skip-column-names"],
            stdin="SELECT " + ", ".join(f"@@GLOBAL.{k}" for k in keys) + ";\n",
            timeout=60,
        )
        fields = result.stdout.split()
        if len(fields) != len(keys) or not all(f.isdigit() for f in fields):
            return {}
        return dict(zip(keys, (int(f) for f in fields), strict=True))
