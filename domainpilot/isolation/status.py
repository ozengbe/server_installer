"""Read-only inspection of a tenant's isolation controls."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from domainpilot.core import proc
from domainpilot.core.errors import DPError
from domainpilot.core.paths import Paths

Runner = Callable[..., proc.Result]

SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
APPARMOR_PROFILES = Path("/sys/kernel/security/apparmor/profiles")
EXPOSURE_TARGET = 2.0  # roadmap Phase 4 acceptance: systemd-analyze security <= 2.0

_SLICE_PROPS = ("CPUQuotaPerSecUSec", "MemoryHigh", "MemoryMax", "TasksMax", "MemoryCurrent")


def _show(run: Runner, unit: str, props: tuple[str, ...]) -> dict[str, str]:
    argv = [SYSTEMCTL, "show", unit]
    for p in props:
        argv += ["-p", p]
    try:
        result = run(argv, check=False, timeout=15)
    except DPError:
        return {}
    out: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        out[key] = value
    return out


def exposure_score(unit: str, run: Runner = proc.run) -> float | None:
    """systemd's own sandboxing score for a unit (0 = most locked down, 10 = none)."""
    try:
        result = run([SYSTEMD_ANALYZE, "security", "--no-pager", unit], check=False, timeout=30)
    except DPError:
        return None
    match = re.search(r"exposure level for \S+:\s*([0-9]+(?:\.[0-9]+)?)", result.stdout)
    return float(match.group(1)) if match else None


def apparmor_mode(profile: str, profiles_file: Path = APPARMOR_PROFILES) -> str:
    try:
        for line in profiles_file.read_text(encoding="utf-8").splitlines():
            name, _, mode = line.rpartition(" ")
            if name == profile:
                return mode.strip("()")
    except OSError:
        return "unknown"
    return "not loaded"


def tenant_status(
    paths: Paths, tenant: str, *, run: Runner = proc.run, with_score: bool = True
) -> dict[str, Any]:
    php_unit = f"dp-php@{tenant}.service"
    cache_unit = f"dp-cache@{tenant}.service"
    status: dict[str, Any] = {
        "tenant": tenant,
        "units": {
            php_unit: _show(run, php_unit, ("ActiveState", "SubState", "MainPID")),
            cache_unit: _show(run, cache_unit, ("ActiveState", "SubState")),
        },
        "slice": _show(run, f"dptenants-{tenant}.slice", _SLICE_PROPS),
        "apparmor": apparmor_mode(f"domainpilot-tenant-{tenant}"),
        "sockets": {
            "php": paths.php_socket(tenant).is_socket(),
            "cache": paths.cache_socket(tenant).is_socket(),
        },
    }
    if with_score:
        status["exposure"] = {
            php_unit: exposure_score(php_unit, run),
            cache_unit: exposure_score(cache_unit, run),
            "target": EXPOSURE_TARGET,
        }
    return status
