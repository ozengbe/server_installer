"""Command implementations available in Phase 3 (read-only foundation)."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from typing import Any

from domainpilot.cli.context import CommandResult, Context
from domainpilot.core.errors import PreconditionFailed
from domainpilot.core.output import table
from domainpilot.core.sysinfo import CORE_SERVICES

DISK_WARN_RATIO = 0.90


def _human_bytes(n: int | None) -> str:
    if n is None:
        return "-"
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{n} B"  # pragma: no cover


def _human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h {minutes}m"


def site_list(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    registry = ctx.registry(create=False)
    sites = registry.list_sites() if registry else []
    data = {"sites": [asdict(s) for s in sites], "count": len(sites)}
    if not sites:
        return CommandResult(data, ["No sites yet. Create one with: sudo site example.com create"])
    rows = [
        [
            s.domain,
            s.tenant_id,
            s.site_type,
            s.php_version or "-",
            "yes" if s.enabled else "no",
            "" if s.is_primary else "alias",
        ]
        for s in sites
    ]
    return CommandResult(data, table(rows, ["DOMAIN", "TENANT", "TYPE", "PHP", "ENABLED", ""]))


def site_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    if ctx.domain is None:  # pragma: no cover - dispatcher always sets it for site scope
        raise PreconditionFailed("no domain given")
    registry = ctx.registry(create=False)
    site = registry.get_site(ctx.domain) if registry else None
    if site is None or registry is None:
        raise PreconditionFailed(
            f"{ctx.domain} is not an Ozenix site",
            hint=f"create it with: sudo site {ctx.domain} create",
        )
    tenant = registry.get_tenant(site.tenant_id)
    pending = registry.unfinished_operations(ctx.domain)
    if pending:
        ctx.out.warn(f"{len(pending)} unfinished operation(s); run: sudo site {ctx.domain} repair")
    data: dict[str, Any] = {
        "site": asdict(site),
        "tenant": asdict(tenant) if tenant else None,
        "unfinished_operations": [op.id for op in pending],
    }
    text = [
        f"Site:     {site.domain}" + ("" if site.is_primary else " (alias)"),
        f"Tenant:   {site.tenant_id}" + (f" (uid {tenant.uid}, {tenant.status})" if tenant else ""),
        f"Type:     {site.site_type}" + (f", PHP {site.php_version}" if site.php_version else ""),
        f"Enabled:  {'yes' if site.enabled else 'no'}",
        f"Created:  {site.created_at}",
    ]
    return CommandResult(data, text)


def system_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    probe = ctx.probe
    summary = probe.summary()
    services = {name: probe.service_state(name) for name in CORE_SERVICES}
    services["ssh"] = probe.ssh_state()
    disks = {path: probe.disk(path) for path in ("/", "/srv", "/var/lib/mysql")}
    firewall = {
        "table_present": probe.firewall_table_present(),
        "change_pending": ctx.paths.firewall_pending.exists(),
    }
    reboot = probe.reboot_required()
    registry = ctx.registry(create=False)
    counts = (
        registry.counts()
        if registry
        else {
            "tenants": 0,
            "sites": 0,
            "sites_enabled": 0,
            "unfinished_operations": 0,
        }
    )

    for name, state in services.items():
        if state != "active":
            ctx.out.warn(f"service {name} is {state}")
    if firewall["table_present"] is False:
        ctx.out.warn("Ozenix firewall table is not loaded")
    if firewall["change_pending"]:
        ctx.out.warn("a firewall change is waiting for confirmation (sudo dp-firewall confirm)")
    if reboot:
        ctx.out.warn("a reboot is required to finish applying updates")
    for path, usage in disks.items():
        if (
            usage
            and usage["total_bytes"]
            and usage["used_bytes"] / usage["total_bytes"] > DISK_WARN_RATIO
        ):
            ctx.out.warn(f"disk {path} is more than {DISK_WARN_RATIO:.0%} full")
    if counts["unfinished_operations"]:
        ctx.out.warn(f"{counts['unfinished_operations']} unfinished operation(s) need repair")

    data = {
        "host": summary,
        "services": services,
        "disks": disks,
        "firewall": firewall,
        "reboot_required": reboot,
        "registry": counts,
    }
    mem = summary["memory"]
    load = summary["load_average"]
    text = [
        f"Host:      {summary['hostname']} ({summary['os']}, kernel {summary['kernel']})",
        f"Uptime:    {_human_duration(summary['uptime_seconds'])}",
        f"CPU:       {summary['cpu_count']} cores"
        + (f", load {load[0]:.2f} {load[1]:.2f} {load[2]:.2f}" if load else ""),
        f"Memory:    {_human_bytes(mem['available_bytes'])} available"
        f" of {_human_bytes(mem['total_bytes'])}",
    ]
    for path, usage in disks.items():
        if usage:
            text.append(
                f"Disk {path}: {_human_bytes(usage['free_bytes'])} free"
                f" of {_human_bytes(usage['total_bytes'])}"
            )
    text.append("Services:  " + ", ".join(f"{k}={v}" for k, v in services.items()))
    fw_state = {True: "loaded", False: "NOT LOADED", None: "unknown"}[firewall["table_present"]]
    text.append(
        f"Firewall:  {fw_state}" + (" (change pending)" if firewall["change_pending"] else "")
    )
    text.append(f"Reboot:    {'required' if reboot else 'not required'}")
    text.append(
        f"Sites:     {counts['sites']} ({counts['sites_enabled']} enabled), "
        f"{counts['tenants']} tenants"
    )
    return CommandResult(data, text)
