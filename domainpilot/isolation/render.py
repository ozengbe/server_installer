"""Render per-tenant configuration from strict templates.

``string.Template.substitute`` raises on any missing placeholder, and every
value comes from validated, typed data, so no user-controlled text can reach
a configuration file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from string import Template

from domainpilot.core import validate
from domainpilot.core.config import HostFacts
from domainpilot.core.paths import Paths
from domainpilot.isolation.limits import TenantLimits

TEMPLATE_DIR = Path(__file__).parent / "templates"

DISABLED_PHP_FUNCTIONS = (
    "exec",
    "passthru",
    "shell_exec",
    "system",
    "proc_open",
    "popen",
    "pcntl_exec",
    "pcntl_fork",
    "pcntl_signal",
    "posix_kill",
    "posix_setuid",
    "posix_setgid",
    "dl",
)


@dataclass(frozen=True)
class TenantSpec:
    tenant: str
    uid: int
    php_version: str
    limits: TenantLimits
    cache: bool = True
    # Tests switch this off so probes exercise the real sandbox, not PHP's check.
    php_open_basedir: bool = True
    # Static and proxy sites have no PHP runtime at all.
    php: bool = True

    def __post_init__(self) -> None:
        validate.tenant_id(self.tenant)
        validate.php_version(self.php_version)
        if not 20000 <= self.uid <= 29999:
            raise ValueError("tenant uid out of range")

    @property
    def deploy_user(self) -> str:
        return f"{self.tenant}-deploy"

    @property
    def deploy_uid(self) -> int:
        return self.uid + 10000

    @property
    def slice(self) -> str:
        return f"dptenants-{self.tenant}.slice"

    @property
    def apparmor_profile(self) -> str:
        return f"domainpilot-tenant-{self.tenant}"


def _load(name: str) -> Template:
    return Template((TEMPLATE_DIR / name).read_text(encoding="utf-8"))


def _values(spec: TenantSpec, paths: Paths, host: HostFacts) -> dict[str, str]:
    t = spec.tenant
    lim = spec.limits
    return {
        "tenant": t,
        "root": str(paths.tenant_root(t)),
        "etc_dir": str(paths.tenant_etc(t)),
        "log_dir": str(paths.tenant_log(t)),
        "run_dir": str(paths.tenant_run(t)),
        "cache_data": str(paths.tenant_cache_data(t)),
        "php_socket": str(paths.php_socket(t)),
        "cache_socket": str(paths.cache_socket(t)),
        "php_version": spec.php_version,
        "slice": spec.slice,
        "cache_server": host.cache_server,
        "max_children": str(lim.php_max_children),
        "php_memory_limit": str(lim.php_memory_limit_mb),
        "cache_maxmemory": str(lim.cache_maxmemory_mb),
        "cpu_quota": str(lim.cpu_quota_percent),
        "memory_high": str(lim.memory_high_mb),
        "memory_max": str(lim.memory_max_mb),
        "swap_max": str(lim.swap_max_mb),
        "tasks_max": str(lim.tasks_max),
        "disable_functions": ",".join(DISABLED_PHP_FUNCTIONS),
        "open_basedir_line": (
            f"php_admin_value[open_basedir] = {paths.tenant_root(t)}/:/tmp/"
            if spec.php_open_basedir
            else "; open_basedir disabled for this tenant (isolation test tenant)"
        ),
    }


@dataclass(frozen=True)
class RenderedFile:
    path: Path
    content: str
    mode: int
    group_is_tenant: bool  # root:<tenant> instead of root:root


def render(spec: TenantSpec, paths: Paths, host: HostFacts) -> list[RenderedFile]:
    """All configuration files for one tenant, with their target paths and modes."""
    v = _values(spec, paths, host)
    t = spec.tenant
    etc = paths.tenant_etc(t)
    files: list[RenderedFile] = []
    if spec.php:
        files += [
            RenderedFile(
                etc / "php-fpm.conf", _load("php-fpm.conf.tmpl").substitute(v), 0o640, True
            ),
            RenderedFile(
                paths.systemd / f"dp-php@{t}.service.d" / "10-tenant.conf",
                _load("php-dropin.conf.tmpl").substitute(v),
                0o644,
                False,
            ),
        ]
    files += [
        RenderedFile(
            paths.systemd / spec.slice, _load("tenant.slice.tmpl").substitute(v), 0o644, False
        ),
        RenderedFile(
            paths.apparmor / f"tenant-{t}", _load("apparmor.tmpl").substitute(v), 0o644, False
        ),
    ]
    if spec.cache:
        files += [
            RenderedFile(etc / "cache.conf", _load("cache.conf.tmpl").substitute(v), 0o640, True),
            RenderedFile(
                paths.systemd / f"dp-cache@{t}.service.d" / "10-tenant.conf",
                _load("cache-dropin.conf.tmpl").substitute(v),
                0o644,
                False,
            ),
        ]
    return files
