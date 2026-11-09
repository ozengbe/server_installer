"""Per-site tuning: PHP-FPM workers sized to the tenant's memory limit.

pm.max_children = (memory_max - cache - headroom) / average worker RSS, where
the RSS is measured from the tenant's own cgroup when the site has been
running, and a conservative default otherwise. Never exceeds what the cgroup
allows, so the kernel's OOM killer is not the limiter.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from domainpilot.isolation.limits import TenantLimits

DEFAULT_WORKER_MB = 64
HEADROOM_MB = 64  # PHP-FPM master, shared libraries, short spikes
MIN_CHILDREN = 2
MAX_CHILDREN = 64


@dataclass(frozen=True)
class WorkerStats:
    workers: int
    average_rss_mb: int | None  # None = not measured (site idle or not running)


def measure_workers(
    tenant: str, *, cgroup_root: Path = Path("/sys/fs/cgroup"), proc_root: Path = Path("/proc")
) -> WorkerStats:
    procs = (
        cgroup_root
        / "dptenants.slice"
        / f"dptenants-{tenant}.slice"
        / f"dp-php@{tenant}.service"
        / "cgroup.procs"
    )
    try:
        pids = [int(p) for p in procs.read_text(encoding="ascii").split()]
    except (OSError, ValueError):
        return WorkerStats(0, None)
    rss: list[int] = []
    for pid in pids:
        try:
            status = (proc_root / str(pid) / "status").read_text(encoding="ascii")
        except OSError:
            continue
        name = next(
            (ln.split(None, 1)[1] for ln in status.splitlines() if ln.startswith("Name:")), ""
        )
        kb = next((int(ln.split()[1]) for ln in status.splitlines() if ln.startswith("VmRSS:")), 0)
        # Children are named "php-fpm8.x"; skip the master (first pid, lowest RSS)
        if name.startswith("php-fpm") and kb:
            rss.append(kb // 1024)
    if len(rss) > 1:
        rss = sorted(rss)[1:]  # drop the smallest: usually the idle master
    if not rss:
        return WorkerStats(0, None)
    return WorkerStats(len(rss), max(1, sum(rss) // len(rss)))


def recommend_limits(current: TenantLimits, stats: WorkerStats) -> tuple[TenantLimits, str]:
    per_worker = max(stats.average_rss_mb or DEFAULT_WORKER_MB, 24)
    budget = current.memory_max_mb - current.cache_maxmemory_mb - HEADROOM_MB
    children = max(MIN_CHILDREN, min(MAX_CHILDREN, budget // per_worker))
    basis = (
        f"measured {stats.average_rss_mb} MiB per worker ({stats.workers} sampled)"
        if stats.average_rss_mb
        else f"assumed {DEFAULT_WORKER_MB} MiB per worker (no " "running workers to measure)"
    )
    return replace(current, php_max_children=int(children)), basis
