"""Phase 4 commands: isolation status, PHP runtime, database status, firewall."""

from __future__ import annotations

import argparse
from typing import Any

from domainpilot.cli.context import CommandResult, Context
from domainpilot.core import proc
from domainpilot.core.errors import OperationFailed, PreconditionFailed
from domainpilot.core.registry import Site, Tenant
from domainpilot.isolation import db
from domainpilot.isolation.status import tenant_status

DP_FIREWALL = "/usr/local/sbin/dp-firewall"


def _site_tenant(ctx: Context) -> tuple[Site, Tenant]:
    registry = ctx.registry(create=False)
    site = registry.get_site(ctx.domain) if (registry and ctx.domain) else None
    if site is None or registry is None:
        raise PreconditionFailed(
            f"{ctx.domain} is not a DomainPilot site",
            hint=f"create it with: sudo site {ctx.domain} create",
        )
    tenant = registry.get_tenant(site.tenant_id)
    if tenant is None:
        raise OperationFailed(f"registry inconsistency: tenant {site.tenant_id} missing")
    return site, tenant


def isolation_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    _site, tenant = _site_tenant(ctx)
    st = tenant_status(ctx.paths, tenant.id)
    text = [f"Tenant {tenant.id} (uid {tenant.uid}) for {ctx.domain}"]
    for unit, props in st["units"].items():
        text.append(f"  {unit:<28} {props.get('ActiveState', '?')}/{props.get('SubState', '?')}")
    sl = st["slice"]
    text.append(
        f"  limits: memory high {sl.get('MemoryHigh', '?')} max {sl.get('MemoryMax', '?')},"
        f" cpu {sl.get('CPUQuotaPerSecUSec', '?')}/s, tasks {sl.get('TasksMax', '?')}"
    )
    text.append(f"  AppArmor: {st['apparmor']}")
    text.append(f"  sockets: php={st['sockets']['php']} cache={st['sockets']['cache']}")
    exposure = st.get("exposure", {})
    for unit, score in exposure.items():
        if unit != "target" and score is not None:
            text.append(f"  systemd exposure {unit}: {score} (target <= {exposure['target']})")
            if score > exposure["target"]:
                ctx.out.warn(f"{unit} exposure {score} is above target {exposure['target']}")
    if st["apparmor"] != "enforce":
        ctx.out.warn(f"AppArmor profile is {st['apparmor']}, expected enforce")
    return CommandResult(st, text)


def php_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    _site, tenant = _site_tenant(ctx)
    settings = ctx.registry().get_tenant_settings(tenant.id)  # type: ignore[union-attr]
    st = tenant_status(ctx.paths, tenant.id, with_score=False)
    unit = f"dp-php@{tenant.id}.service"
    data: dict[str, Any] = {
        "php_version": settings.get("php_version"),
        "unit": st["units"][unit],
        "socket": st["sockets"]["php"],
        "limits": settings.get("limits", {}),
    }
    text = [
        f"PHP {data['php_version']} for {ctx.domain} ({unit}):"
        f" {data['unit'].get('ActiveState', '?')}, socket {'ok' if data['socket'] else 'missing'}",
    ]
    return CommandResult(data, text)


def php_restart(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    _site, tenant = _site_tenant(ctx)
    unit = f"dp-php@{tenant.id}.service"
    if ctx.dry_run:
        ctx.out.step(f"restart {unit}", "planned")
        return CommandResult({"unit": unit, "dry_run": True})
    proc.run(["/usr/bin/systemctl", "restart", unit], timeout=60)
    ctx.audit().record("php.restart", argv=ctx.argv, outcome="success", details={"unit": unit})
    ctx.out.step(f"restarted {unit}")
    return CommandResult({"unit": unit})


def db_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    _site, tenant = _site_tenant(ctx)
    databases = db.list_databases(tenant.id)
    data = {"user": tenant.id, "user_exists": db.user_exists(tenant.id), "databases": databases}
    text = [
        f"Database user {tenant.id}: {'present' if data['user_exists'] else 'MISSING'}",
        "Databases: " + (", ".join(databases) if databases else "(none yet)"),
    ]
    return CommandResult(data, text)


def _firewall(ctx: Context, action: str) -> CommandResult:
    if action != "status" and ctx.dry_run:
        ctx.out.step(f"dp-firewall {action}", "planned")
        return CommandResult({"action": action, "dry_run": True})
    result = proc.run([DP_FIREWALL, action], check=False, timeout=60)
    output = (result.stdout + result.stderr).strip()
    pending = action == "status" and result.returncode == 3
    if action != "status":
        if not result.ok:
            raise OperationFailed(f"dp-firewall {action} failed: {output}")
        ctx.audit().record(f"firewall.{action}", argv=ctx.argv, outcome="success")
    elif result.returncode not in (0, 3):
        raise OperationFailed(f"dp-firewall status failed: {output}")
    return CommandResult({"action": action, "pending": pending, "output": output}, [output])


def firewall_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    return _firewall(ctx, "status")


def firewall_confirm(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    return _firewall(ctx, "confirm")


def firewall_rollback(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    return _firewall(ctx, "rollback")
