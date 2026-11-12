"""Read-only host probes used by status/health commands.

Kept behind a small class so tests can substitute a fake host.
"""

from __future__ import annotations

import os
import shutil
import socket
from pathlib import Path
from typing import Any

from ozenix.core import proc
from ozenix.core.errors import DPError

# Intrusion prevention: CrowdSec where its signed repository supports this Ubuntu
# release, fail2ban elsewhere (installer: dp_ids, recorded as "ids" in host.toml).
IDS_UNITS: dict[str, tuple[str, ...]] = {
    "fail2ban": ("fail2ban",),
    "crowdsec": ("crowdsec", "crowdsec-firewall-bouncer"),
}


def core_services(ids: str = "fail2ban") -> tuple[str, ...]:
    """The host services that must be running (critical in health checks)."""
    return ("nginx", "mariadb", *IDS_UNITS.get(ids, ()), "auditd", "apparmor")


CORE_SERVICES = core_services()


class SystemProbe:
    def __init__(self, root: Path = Path("/")) -> None:
        self.root = root

    def _read(self, relative: str) -> str | None:
        try:
            return (self.root / relative).read_text(encoding="utf-8")
        except OSError:
            return None

    def os_release(self) -> dict[str, str]:
        data: dict[str, str] = {}
        for line in (self._read("etc/os-release") or "").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                data[key] = value.strip().strip('"')
        return data

    def hostname(self) -> str:
        return socket.gethostname()

    def kernel(self) -> str:
        return os.uname().release

    def uptime_seconds(self) -> float | None:
        text = self._read("proc/uptime")
        return float(text.split()[0]) if text else None

    def load_average(self) -> tuple[float, float, float] | None:
        try:
            return os.getloadavg()
        except OSError:
            return None

    def cpu_count(self) -> int:
        return os.cpu_count() or 1

    def memory(self) -> dict[str, int]:
        info: dict[str, int] = {}
        for line in (self._read("proc/meminfo") or "").splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                info[key] = int(parts[0]) * 1024
        return {
            "total_bytes": info.get("MemTotal", 0),
            "available_bytes": info.get("MemAvailable", 0),
            "swap_total_bytes": info.get("SwapTotal", 0),
            "swap_free_bytes": info.get("SwapFree", 0),
        }

    def disk(self, path: str) -> dict[str, int] | None:
        target = self.root / path.lstrip("/")
        if not target.exists():
            return None
        usage = shutil.disk_usage(target)
        return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}

    def service_state(self, unit: str) -> str:
        try:
            result = proc.run(["/usr/bin/systemctl", "is-active", unit], check=False, timeout=15)
        except DPError:
            return "unknown"
        return result.stdout.strip() or "unknown"

    def ssh_state(self) -> str:
        socket_state = self.service_state("ssh.socket")
        return "active" if socket_state == "active" else self.service_state("ssh.service")

    def firewall_table_present(self) -> bool | None:
        try:
            result = proc.run(
                ["/usr/sbin/nft", "list", "table", "inet", "ozenix"], check=False, timeout=15
            )
        except DPError:
            return None
        return result.ok

    def reboot_required(self) -> bool:
        return (self.root / "run/reboot-required").exists()

    def summary(self) -> dict[str, Any]:
        release = self.os_release()
        return {
            "hostname": self.hostname(),
            "os": release.get("PRETTY_NAME", "unknown"),
            "os_version_id": release.get("VERSION_ID", ""),
            "kernel": self.kernel(),
            "uptime_seconds": self.uptime_seconds(),
            "load_average": self.load_average(),
            "cpu_count": self.cpu_count(),
            "memory": self.memory(),
        }
