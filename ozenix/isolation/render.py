"""Render per-tenant configuration from strict templates.

``string.Template.substitute`` raises on any missing placeholder, and every
value comes from validated, typed data, so no user-controlled text can reach
a configuration file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from string import Template

from ozenix.core import validate
from ozenix.core.config import HostFacts
from ozenix.core.paths import Paths
from ozenix.isolation.limits import TenantLimits

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


APP_RUNTIMES = ("node", "python")
NODE_ROOT = "/opt/ozenix/node"
APP_PORT_BASE = 10000  # site app port = 10000 + site number (privileged range)


def app_port(tenant: str) -> int:
    return APP_PORT_BASE + int(validate.tenant_id(tenant)[1:])


@dataclass(frozen=True)
class AppSpec:
    """A site's Node.js or Python app, run by dp-app@<tenant> as the site's PHP-less
    runtime user, listening on 127.0.0.1:port."""

    runtime: str  # node | python
    start: str
    port: int
    node_version: str | None = None

    def __post_init__(self) -> None:
        if self.runtime not in APP_RUNTIMES:
            raise ValueError(f"unknown app runtime {self.runtime!r}")
        validate.app_command(self.start)
        if not APP_PORT_BASE < self.port < 20000:
            raise ValueError("app port out of range")
        if self.runtime == "node":
            validate.node_version(self.node_version or "")


def systemd_exec(command: str) -> str:
    """Quote a shell command for `ExecStart=/bin/sh -c <here>`: systemd must not
    expand anything ($ and % doubled), the shell gets it verbatim."""
    escaped = command.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped.replace("%", "%%").replace("$", "$$") + '"'


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
    # Node.js or Python app (site types nodejs/python); None for php/static/proxy.
    app: AppSpec | None = None
    # Laravel: writable paths (storage, bootstrap cache) live in data/, not app/.
    laravel: bool = False
    # The site's login user (SSH key, SFTP + shell), chosen at `site create --user`.
    # None: the automatic name "<tenant>-deploy".
    site_user: str | None = None

    def __post_init__(self) -> None:
        validate.tenant_id(self.tenant)
        if self.site_user is not None:
            validate.site_user(self.site_user)
        validate.php_version(self.php_version)
        if not 20000 <= self.uid <= 29999:
            raise ValueError("tenant uid out of range")

    @property
    def deploy_user(self) -> str:
        return self.site_user or f"{self.tenant}-deploy"

    @property
    def deploy_uid(self) -> int:
        return self.uid + 10000

    @property
    def slice(self) -> str:
        return f"dptenants-{self.tenant}.slice"

    @property
    def apparmor_profile(self) -> str:
        return f"ozenix-tenant-{self.tenant}"


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
        "laravel_lines": laravel_fpm_lines(paths.tenant_root(t)) if spec.laravel else "",
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
    if spec.laravel:
        env = {"PHP_BIN": f"/usr/bin/php{spec.php_version}", **laravel_env(paths.tenant_root(t))}
        files.append(
            RenderedFile(
                etc / "laravel.env",
                "# Managed by ozenix: environment of this site's Laravel scheduler and queue.\n"
                + "".join(f"{k}={v}\n" for k, v in env.items()),
                0o640,
                True,
            )
        )
    if spec.app is not None:
        app = spec.app
        root = paths.tenant_root(t)
        path = (
            f"{NODE_ROOT}/{app.node_version}/bin:/usr/local/bin:/usr/bin:/bin"
            if app.runtime == "node"
            else f"{root}/app/.venv/bin:/usr/local/bin:/usr/bin:/bin"
        )
        va = {
            **v,
            "app_runtime": "Node.js" if app.runtime == "node" else "Python",
            "app_port": str(app.port),
            "app_path": path,
            "app_exec": systemd_exec(app.start),
        }
        files.append(
            RenderedFile(
                paths.systemd / f"dp-app@{t}.service.d" / "10-tenant.conf",
                _load("app-dropin.conf.tmpl").substitute(va),
                0o644,
                False,
            )
        )
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


def deploy_user_of(tenant: str) -> str:
    """Name of a tenant's login (deploy) user, found by its fixed uid.

    The runtime user is ``<tenant>`` (uid U); the deploy user always has uid
    U + 10000, whatever name was chosen for it at creation.
    """
    import pwd

    tenant = validate.tenant_id(tenant)
    try:
        return pwd.getpwuid(pwd.getpwnam(tenant).pw_uid + 10000).pw_name
    except KeyError:
        return f"{tenant}-deploy"


def laravel_env(root: Path) -> dict[str, str]:
    """Where a Laravel app writes: data/ (writable), never app/ (read-only code).

    Laravel reads LARAVEL_STORAGE_PATH from $_ENV and the APP_*_CACHE paths from
    the environment, so the code tree needs no writable storage/ or
    bootstrap/cache/ directory.
    """
    data = root / "data"
    cache = data / "cache"
    return {
        "LARAVEL_STORAGE_PATH": str(data / "storage"),
        "APP_SERVICES_CACHE": str(cache / "services.php"),
        "APP_PACKAGES_CACHE": str(cache / "packages.php"),
        "APP_CONFIG_CACHE": str(cache / "config.php"),
        "APP_ROUTES_CACHE": str(cache / "routes-v7.php"),
        "APP_EVENTS_CACHE": str(cache / "events.php"),
    }


# Directories Laravel expects below LARAVEL_STORAGE_PATH (and the cache dir).
LARAVEL_DIRS = (
    "storage",
    "storage/app",
    "storage/app/public",
    "storage/framework",
    "storage/framework/cache",
    "storage/framework/cache/data",
    "storage/framework/sessions",
    "storage/framework/views",
    "storage/logs",
    "cache",
)


def laravel_fpm_lines(root: Path) -> str:
    lines = ["; Laravel: storage and caches in data/ (the code in app/ stays read-only)."]
    lines += [f"env[{k}] = {v}" for k, v in laravel_env(root).items()]
    # Laravel reads LARAVEL_STORAGE_PATH from $_ENV, which needs "E" here.
    lines.append('php_admin_value[variables_order] = "EGPCS"')
    return "\n".join(lines)
