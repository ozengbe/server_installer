"""Filesystem layout (architecture §4.2, §5).

Production code uses ``Paths.default()``. Tests construct ``Paths.under(tmp)``.
There is deliberately no environment variable to relocate these paths: a
root-run tool must not let its caller's environment redirect its state.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domainpilot.core import validate


@dataclass(frozen=True)
class Paths:
    etc: Path
    var_lib: Path
    run: Path
    log: Path
    tenants: Path
    systemd: Path = Path("/etc/systemd/system")
    apparmor: Path = Path("/etc/apparmor.d/domainpilot")

    @classmethod
    def default(cls) -> Paths:
        return cls(
            etc=Path("/etc/domainpilot"),
            var_lib=Path("/var/lib/domainpilot"),
            run=Path("/run/domainpilot"),
            log=Path("/var/log/domainpilot"),
            tenants=Path("/srv/tenants"),
        )

    @classmethod
    def under(cls, root: Path) -> Paths:
        return cls(
            etc=root / "etc",
            var_lib=root / "var_lib",
            run=root / "run",
            log=root / "log",
            tenants=root / "tenants",
            systemd=root / "systemd",
            apparmor=root / "apparmor",
        )

    @property
    def config_file(self) -> Path:
        return self.etc / "domainpilot.toml"

    @property
    def host_config_file(self) -> Path:
        """Written by the installer (Ansible): facts about this host."""
        return self.etc / "host.toml"

    @property
    def registry(self) -> Path:
        return self.var_lib / "registry.sqlite3"

    @property
    def audit_log(self) -> Path:
        return self.log / "audit.jsonl"

    @property
    def global_lock(self) -> Path:
        return self.run / "global.lock"

    def tenant_lock(self, tenant: str) -> Path:
        return self.run / f"tenant-{validate.tenant_id(tenant)}.lock"

    @property
    def firewall_pending(self) -> Path:
        return self.var_lib / "firewall" / "pending"

    # --- per-tenant locations (tenant id is validated before use) ------------

    def tenant_root(self, tenant: str) -> Path:
        return self.tenants / validate.tenant_id(tenant)

    def tenant_etc(self, tenant: str) -> Path:
        return self.etc / "tenants" / validate.tenant_id(tenant)

    def tenant_log(self, tenant: str) -> Path:
        return self.log / "tenants" / validate.tenant_id(tenant)

    def tenant_run(self, tenant: str) -> Path:
        return self.run / validate.tenant_id(tenant)

    def tenant_cache_data(self, tenant: str) -> Path:
        return self.var_lib / "cache" / validate.tenant_id(tenant)

    def php_socket(self, tenant: str) -> Path:
        return self.tenant_run(tenant) / "php" / "php.sock"

    def cache_socket(self, tenant: str) -> Path:
        return self.tenant_run(tenant) / "cache" / "cache.sock"

    def create_runtime_dirs(self) -> None:
        """Create state directories with restrictive modes (idempotent).

        /run/domainpilot is 0711: tenants and nginx must traverse it to reach
        their own socket directories (each 0750), but nobody can list it.
        """
        for directory, mode in (
            (self.var_lib, 0o700),
            (self.run, 0o711),
            (self.log, 0o750),
        ):
            directory.mkdir(mode=mode, parents=True, exist_ok=True)
            directory.chmod(mode)
