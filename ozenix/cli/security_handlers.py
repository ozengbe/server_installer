"""Phase 9 commands: security reports, audits and the active isolation test."""

from __future__ import annotations

import argparse
import contextlib
import json
from dataclasses import asdict
from typing import Any

from ozenix.cli.context import CommandResult, Context
from ozenix.cli.ops_handlers import SEVERITY_EXIT, _health_report
from ozenix.cli.site_handlers import _domain, _manager
from ozenix.core import fsutil
from ozenix.core.errors import DPError, ExitCode, PreconditionFailed
from ozenix.isolation import db
from ozenix.security.host_audit import audit_host
from ozenix.security.ids import (
    Ids,
    as_dicts,
    parse_target,
    validate_duration,
    validate_reason,
)
from ozenix.security.isolation_test import IsolationTester, evaluate
from ozenix.security.report import Finding, SecurityReport
from ozenix.security.site_audit import SiteAuditor, SiteFacts
from ozenix.sftp import SftpManager
from ozenix.tls.acme import Certbot


def _result(rep: SecurityReport, *, verbose: bool) -> CommandResult:
    return CommandResult(
        rep.as_dict(),
        rep.lines(verbose=verbose),
        exit_code=int(SEVERITY_EXIT.get(rep.worst, ExitCode.OK)),
        disclaimer=True,
    )


def _facts(ctx: Context) -> SiteFacts:
    domain = _domain(ctx)
    site, tenant = _manager(ctx).primary_site(domain)
    if tenant.status != "active":
        raise PreconditionFailed(f"{domain} is not active")
    registry = ctx.registry(create=False)
    settings = registry.get_tenant_settings(tenant.id) if registry else {}
    days = None
    try:
        info = Certbot().info(domain) if Certbot().exists(domain) else None
        days = info.days_left if info else None
    except DPError:
        pass
    backup_state = None
    if (ctx.paths.etc / "backup.json").exists():
        try:
            state = json.loads(
                fsutil.read_text_nofollow(ctx.paths.var_lib / "backup" / "state.json")
            )
        except (OSError, ValueError):
            state = {}
        backup_state = state.get("sites", {}).get(tenant.id, {})
    accounts: list[dict[str, str]] = []
    with contextlib.suppress(DPError):
        accounts = SftpManager(audit=ctx.audit(), argv=ctx.argv, keys_dir=ctx.paths.ssh_keys).list(
            tenant.id
        )
    return SiteFacts(
        tenant=tenant.id,
        domain=domain,
        php=bool(settings.get("php", site.site_type == "php")),
        cert_days_left=days,
        sftp_accounts=accounts,
        backup_state=backup_state,
    )


def site_security(ctx: Context, args: argparse.Namespace) -> CommandResult:
    rep = SiteAuditor(ctx.paths).security(_facts(ctx))
    return _result(rep, verbose=getattr(args, "verbose_report", False))


def isolation_audit(ctx: Context, args: argparse.Namespace) -> CommandResult:
    rep = SiteAuditor(ctx.paths).isolation_audit(_facts(ctx))
    return _result(rep, verbose=getattr(args, "verbose_report", False))


def isolation_test(ctx: Context, args: argparse.Namespace) -> CommandResult:
    facts = _facts(ctx)
    if not facts.php:
        raise PreconditionFailed(f"{facts.domain} runs no PHP; there is no sandbox to probe")
    registry = ctx.registry(create=False)
    tenants = registry.list_tenants() if registry else []
    others = [t.id for t in tenants if t.status == "active" and t.id != facts.tenant]
    other_db = ""
    for other in others:
        try:
            names = db.list_databases(other)
        except DPError:
            names = []
        if names:
            other_db = names[0]
            break
    if not other_db and others:
        other_db = db.database_name(others[0], "app")
    tenant = registry.get_tenant(facts.tenant) if registry else None
    results = IsolationTester(ctx.paths).run_probe(facts.tenant, others=others, other_db=other_db)
    rep = evaluate(
        results,
        tenant=facts.tenant,
        uid=tenant.uid if tenant else -1,
        writable_code=False,
    )
    data_extra: dict[str, Any] = {"probe": results, "compared_with": others}
    out = _result(rep, verbose=getattr(args, "verbose_report", False))
    out.data.update(data_extra)
    return out


def system_audit(ctx: Context, args: argparse.Namespace) -> CommandResult:
    return _result(audit_host(), verbose=True)


def system_security(ctx: Context, args: argparse.Namespace) -> CommandResult:
    """Short server report: the audit's problems, health problems, and the residual risks."""
    rep = audit_host()
    for c in _health_report(ctx).checks:
        if c["severity"] in ("warn", "critical"):
            rep.findings.append(
                Finding(f"HEALTH-{c['check'].upper()}", c["severity"], c["message"])
            )
    out = _result(rep, verbose=False)
    out.text.append("Residual risks that no check can remove: see docs/security-report.md")
    return out


# --- intrusion prevention (CrowdSec or fail2ban) -------------------------------------------


def _ids(ctx: Context) -> Ids:
    return Ids(ctx.host().ids)


def ids_blocks(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    ids = _ids(ctx)
    blocks = ids.blocks()
    lines = [f"Intrusion prevention: {ids.engine}. Blocked: {len(blocks)}."]
    lines += [
        f"  {b.target:<40} {b.reason:<40} {b.origin:<10} {b.duration}".rstrip() for b in blocks
    ]
    return CommandResult({"engine": ids.engine, "blocks": as_dicts(blocks)}, lines)


def ids_block(ctx: Context, args: argparse.Namespace) -> CommandResult:
    target, _ = parse_target(args.target)
    duration = validate_duration(args.duration)
    reason = validate_reason(args.reason)
    if ctx.dry_run:
        return CommandResult(
            {"target": target, "duration": duration, "dry_run": True},
            [f"Would block {target} for {duration} ({reason})."],
        )
    block = _ids(ctx).block(target, duration=duration, reason=reason)
    ctx.audit().record("ids.block", argv=ctx.argv, outcome="success", details=asdict(block))
    return CommandResult(asdict(block), [f"Blocked {block.target} for {block.duration}."])


def ids_unblock(ctx: Context, args: argparse.Namespace) -> CommandResult:
    target, _ = parse_target(args.target)
    if ctx.dry_run:
        return CommandResult(
            {"target": target, "dry_run": True}, [f"Would lift every block on {target}."]
        )
    removed = _ids(ctx).unblock(target)
    ctx.audit().record(
        "ids.unblock",
        argv=ctx.argv,
        outcome="success",
        details={"target": target, "removed": removed},
    )
    text = (
        f"Unblocked {target} ({removed} block(s) removed)."
        if removed
        else f"{target} was not blocked."
    )
    return CommandResult({"target": target, "removed": removed}, [text])
