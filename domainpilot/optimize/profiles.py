"""Host facts -> profile -> recommended server tuning.

Recommendations depend only on hardware and on what tenants were promised
(their configured limits), never on short-term load, so applying twice gives
the same result and production configs are not rewritten on every spike.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
PROFILES = ("small", "medium", "large", "dedicated", "high-traffic")


@dataclass(frozen=True)
class HostFacts:
    cpu_count: int
    memory_bytes: int
    ssd: bool
    tenants: int
    tenant_memory_promised_mb: int
    # MariaDB 11.8+: the buffer pool cannot grow past innodb_buffer_pool_size_max
    # (fixed at startup) without a restart. None = no such limit (10.11).
    db_pool_max_mb: int | None = None

    @property
    def memory_mb(self) -> int:
        return self.memory_bytes // MIB


@dataclass(frozen=True)
class Tuning:
    profile: str
    # nginx
    nginx_worker_connections: int
    nginx_open_file_cache: int
    # MariaDB
    mariadb_buffer_pool_mb: int
    mariadb_max_connections: int
    mariadb_table_open_cache: int
    mariadb_tmp_table_mb: int
    mariadb_io_capacity: int
    # PHP OPcache (shared by every tenant master of a PHP version)
    opcache_memory_mb: int
    opcache_max_files: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_facts(
    *,
    tenants: int,
    tenant_memory_promised_mb: int,
    proc_root: Path = Path("/proc"),
    sys_block: Path = Path("/sys/block"),
    cpu_count: int | None = None,
    db_pool_max_mb: int | None = None,
) -> HostFacts:
    import os

    mem = 0
    try:
        for line in (proc_root / "meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                mem = int(line.split()[1]) * 1024
                break
    except OSError:
        pass
    ssd = True
    try:
        rotational = [
            (d / "queue" / "rotational").read_text(encoding="ascii").strip()
            for d in sys_block.iterdir()
            if not d.name.startswith(("loop", "ram", "zram", "sr"))
            and (d / "queue" / "rotational").exists()
        ]
        ssd = "1" not in rotational
    except OSError:
        pass
    return HostFacts(
        cpu_count=cpu_count or os.cpu_count() or 1,
        memory_bytes=mem,
        ssd=ssd,
        tenants=tenants,
        tenant_memory_promised_mb=tenant_memory_promised_mb,
        db_pool_max_mb=db_pool_max_mb,
    )


def choose_profile(facts: HostFacts) -> str:
    mb = facts.memory_mb
    if mb < 2048:
        return "small"
    if mb < 8192:
        return "medium"
    if mb < 32768:
        return "large"
    return "dedicated"


# Share of RAM given to MariaDB's buffer pool, per profile. The rest stays for
# the OS page cache, nginx and the tenants' own (cgroup-limited) memory.
_DB_SHARE = {"small": 0.12, "medium": 0.20, "large": 0.25, "dedicated": 0.30, "high-traffic": 0.25}
_NGINX_CONN = {
    "small": 1024,
    "medium": 4096,
    "large": 8192,
    "dedicated": 16384,
    "high-traffic": 32768,
}
_OPCACHE = {"small": 96, "medium": 128, "large": 256, "dedicated": 512, "high-traffic": 512}


def recommend(facts: HostFacts, profile: str | None = None) -> Tuning:
    p = profile or choose_profile(facts)
    if p not in PROFILES:
        raise ValueError(f"unknown profile {p!r}")
    mem = max(facts.memory_mb, 512)
    pool = int(mem * _DB_SHARE[p]) // 64 * 64  # whole 64 MiB chunks
    pool = max(128, pool)
    if facts.db_pool_max_mb:  # stay within what the running server can take live
        pool = min(pool, max(128, facts.db_pool_max_mb // 64 * 64))
    max_conn = {"small": 60, "medium": 150, "large": 300, "dedicated": 500, "high-traffic": 800}[p]
    # Every tenant may hold up to 20 connections (MAX_USER_CONNECTIONS); leave room.
    max_conn = max(max_conn, min(facts.tenants * 20 + 20, 2000))
    return Tuning(
        profile=p,
        nginx_worker_connections=_NGINX_CONN[p],
        nginx_open_file_cache={
            "small": 2000,
            "medium": 10000,
            "large": 20000,
            "dedicated": 50000,
            "high-traffic": 100000,
        }[p],
        mariadb_buffer_pool_mb=pool,
        mariadb_max_connections=max_conn,
        mariadb_table_open_cache={
            "small": 400,
            "medium": 2000,
            "large": 4000,
            "dedicated": 8000,
            "high-traffic": 8000,
        }[p],
        mariadb_tmp_table_mb={
            "small": 16,
            "medium": 32,
            "large": 64,
            "dedicated": 128,
            "high-traffic": 64,
        }[p],
        mariadb_io_capacity=2000 if facts.ssd else 200,
        opcache_memory_mb=_OPCACHE[p],
        opcache_max_files=20000 if p == "small" else 50000,
    )


def overcommit_warnings(facts: HostFacts, tuning: Tuning) -> list[str]:
    """Promised tenant memory vs what is actually left after MariaDB and the OS."""
    os_reserve = max(512, facts.memory_mb // 10)
    available = facts.memory_mb - os_reserve - tuning.mariadb_buffer_pool_mb
    warnings = []
    if facts.tenant_memory_promised_mb > available * 2:
        warnings.append(
            f"tenants are promised {facts.tenant_memory_promised_mb} MiB but only about "
            f"{available} MiB remain after MariaDB and the OS (more than 2x overcommit)"
        )
    elif facts.tenant_memory_promised_mb > available:
        warnings.append(
            f"tenant memory limits ({facts.tenant_memory_promised_mb} MiB) exceed the "
            f"{available} MiB left; fine while sites are not all busy at once"
        )
    return warnings
