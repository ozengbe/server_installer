"""`site system health`: one structured report of everything that needs attention."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from domainpilot.core import proc
from domainpilot.core.errors import DPError
from domainpilot.core.sysinfo import CORE_SERVICES, SystemProbe

Runner = Callable[..., proc.Result]
ORDER = ["ok", "info", "warn", "critical"]
CERT_WARN_DAYS = 14
CERT_CRITICAL_DAYS = 7


@dataclass
class Report:
    checks: list[dict[str, str]] = field(default_factory=list)

    def add(self, severity: str, check: str, message: str) -> None:
        self.checks.append({"severity": severity, "check": check, "message": message})

    @property
    def worst(self) -> str:
        return max((c["severity"] for c in self.checks), key=ORDER.index, default="ok")


def check(
    *,
    probe: SystemProbe,
    run: Runner = proc.run,
    certificates: Sequence[tuple[str, int | None]] = (),
    pending_security: int | None = None,
    firewall_pending: bool = False,
    disks: tuple[str, ...] = ("/", "/srv", "/var/lib/mysql"),
    meminfo: Path = Path("/proc/meminfo"),
) -> Report:
    r = Report()
    for svc in CORE_SERVICES:
        state = probe.service_state(svc)
        r.add("ok" if state == "active" else "critical", "service", f"{svc} is {state}")
    ssh = probe.ssh_state()
    r.add("ok" if ssh == "active" else "critical", "service", f"ssh is {ssh}")

    try:
        failed = run(
            ["/usr/bin/systemctl", "list-units", "--state=failed", "--plain", "--no-legend"],
            check=False,
            timeout=30,
        ).stdout.split("\n")
        units = [line.split()[0] for line in failed if line.strip()]
    except DPError:
        units = []
    tenant_units = [u for u in units if u.startswith(("dp-php@", "dp-cache@"))]
    other_units = [u for u in units if u not in tenant_units]
    if tenant_units:
        r.add("critical", "tenants", "failed tenant services: " + ", ".join(tenant_units))
    if other_units:
        r.add("warn", "units", "failed units: " + ", ".join(other_units))

    try:
        nginx = run(["/usr/sbin/nginx", "-t", "-q"], check=False, timeout=60)
        r.add(
            "ok" if nginx.ok else "critical",
            "nginx",
            "configuration valid"
            if nginx.ok
            else "configuration INVALID: " + nginx.stderr.strip()[-200:],
        )
    except DPError as exc:
        r.add("warn", "nginx", f"cannot test configuration: {exc}")

    table = probe.firewall_table_present()
    r.add(
        {True: "ok", False: "critical", None: "warn"}[table],
        "firewall",
        {True: "rules loaded", False: "DomainPilot rules NOT loaded", None: "state unknown"}[table],
    )
    if firewall_pending:
        r.add("warn", "firewall", "a firewall change is waiting for confirmation")

    if probe.reboot_required():
        r.add("warn", "reboot", "a reboot is required to finish applying updates")
    if pending_security:
        r.add("warn", "updates", f"{pending_security} security update(s) pending")

    for path in disks:
        target = Path(path)
        if not target.exists():
            continue
        usage = shutil.disk_usage(target)
        pct = usage.used * 100 // max(usage.total, 1)
        sev = "critical" if pct >= 95 else "warn" if pct >= 90 else "ok"
        r.add(sev, "disk", f"{path} {pct}% used")

    try:
        info = {
            ln.split(":")[0]: int(ln.split()[1])
            for ln in meminfo.read_text(encoding="ascii").splitlines()
            if ln.split()[1:2]
        }
        avail = info.get("MemAvailable", 0) * 100 // max(info.get("MemTotal", 1), 1)
        r.add(
            "critical" if avail < 5 else "warn" if avail < 10 else "ok",
            "memory",
            f"{avail}% memory available",
        )
    except (OSError, ValueError):
        pass

    for domain, days in certificates:
        if days is None:
            continue
        sev = "critical" if days < CERT_CRITICAL_DAYS else "warn" if days < CERT_WARN_DAYS else "ok"
        r.add(sev, "certificate", f"{domain}: {days} days left")
    return r


def as_dict(report: Report) -> dict[str, Any]:
    return {"worst": report.worst, "checks": report.checks}
