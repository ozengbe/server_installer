"""Phase 6b commands: Cloudflare tokens and per-site audits (read-only by default)."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Any

from domainpilot.cli.context import CommandResult, Context
from domainpilot.cli.site_handlers import _domain, _manager
from domainpilot.cloudflare.api import Client, CloudflareError
from domainpilot.cloudflare.creds import CredentialStore, validate_label
from domainpilot.core.errors import ExitCode, OperationFailed, PreconditionFailed, UsageError

SYMBOL = {"ok": "ok  ", "info": "info", "warn": "WARN", "critical": "CRIT"}


def _store() -> CredentialStore:
    return CredentialStore()


def _render_audit(ctx: Context, result: dict[str, Any]) -> CommandResult:
    lines = [
        f"Cloudflare zone {result['zone']}"
        + ("" if result.get("managed") else " (DNS not managed by DomainPilot)")
    ]
    for f in result["findings"]:
        lines.append(f"  {SYMBOL.get(f['severity'], f['severity'])}  {f['message']}")
    code = {"critical": ExitCode.AUDIT_CRITICAL, "warn": ExitCode.AUDIT_WARNINGS}.get(
        result["worst"], ExitCode.OK
    )
    return CommandResult(result, lines, exit_code=int(code), disclaimer=True)


def _audit(ctx: Context, sections: list[str]) -> CommandResult:
    return _render_audit(ctx, _manager(ctx).cloudflare_audit(_domain(ctx), sections))


def status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    return _audit(ctx, ["dns", "ssl", "security"])


def dns(ctx: Context, args: argparse.Namespace) -> CommandResult:
    if args.apply:
        result = _manager(ctx).cloudflare_sync(_domain(ctx))
        for action in result["actions"]:
            ctx.out.step(f"Cloudflare: {action}", "planned" if result["dry_run"] else "done")
        if not result["actions"]:
            return CommandResult(result, ["DNS records already correct; nothing to change."])
        return CommandResult(result, [])
    return _audit(ctx, ["dns"])


def ssl(ctx: Context, args: argparse.Namespace) -> CommandResult:
    _no_apply(args)
    return _audit(ctx, ["ssl"])


def security(ctx: Context, args: argparse.Namespace) -> CommandResult:
    _no_apply(args)
    return _audit(ctx, ["security"])


def _no_apply(args: argparse.Namespace) -> None:
    if getattr(args, "apply", False):
        raise UsageError(
            "DomainPilot does not change Cloudflare zone settings (read-only token by design)",
            hint="change it in the Cloudflare dashboard; this command shows what to change",
        )


# --- tokens -----------------------------------------------------------------------


def _read_token() -> str:
    if sys.stdin.isatty():
        token = getpass.getpass("Cloudflare API token (input hidden): ")
    else:
        token = sys.stdin.readline()
    return token.strip()


def token_add(ctx: Context, args: argparse.Namespace) -> CommandResult:
    token = _read_token()
    if not token:
        raise UsageError("no token given")
    client = Client(token)
    try:
        if client.verify() != "active":
            raise PreconditionFailed("Cloudflare says this token is not active")
        zones = client.zones()
    except CloudflareError as exc:
        raise PreconditionFailed(
            f"Cloudflare rejected the token: {exc.message}",
            hint="check its permissions and IP filter (IPv4 and IPv6)",
        ) from None
    if not zones:
        raise PreconditionFailed("the token cannot see any zone (needs Zone - DNS - Edit)")
    label = (
        validate_label(args.label)
        if args.label
        else (zones[0].name if len(zones) == 1 else "account")
    )
    if ctx.dry_run:
        return CommandResult({"label": label, "zones": [z.name for z in zones], "dry_run": True})
    _store().save(label, token)
    ctx.audit().record(
        "cloudflare.token.add",
        argv=ctx.argv,
        outcome="success",
        details={"label": label, "zones": [z.name for z in zones]},
    )
    return CommandResult(
        {"label": label, "zones": [z.name for z in zones]},
        [f"Stored token {label!r} (encrypted). Zones: {', '.join(z.name for z in zones)}"],
    )


def token_list(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    store = _store()
    rows: list[dict[str, Any]] = []
    for label in store.labels():
        row: dict[str, Any] = {"label": label}
        try:
            client = Client(store.load(label))
            row["status"] = client.verify()
            row["zones"] = [z.name for z in client.zones()]
        except (CloudflareError, OperationFailed) as exc:
            row["status"] = "error"
            row["error"] = getattr(exc, "message", str(exc))
            ctx.out.warn(f"token {label!r}: {row['error']}")
        rows.append(row)
    if not rows:
        return CommandResult(
            {"tokens": []},
            ["No Cloudflare tokens stored. " "Add one: sudo site system cloudflare token add"],
        )
    text = [
        f"{r['label']}: {r['status']}  zones: {', '.join(r.get('zones', [])) or '-'}" for r in rows
    ]
    return CommandResult({"tokens": rows}, text)


def token_remove(ctx: Context, args: argparse.Namespace) -> CommandResult:
    store = _store()
    label = validate_label(args.label)
    if label not in store.labels():
        raise PreconditionFailed(f"no stored token named {label!r}")
    if not ctx.dry_run:
        store.remove(label)
        ctx.audit().record(
            "cloudflare.token.remove", argv=ctx.argv, outcome="success", details={"label": label}
        )
    return CommandResult(
        {"label": label, "removed": not ctx.dry_run},
        [f"Removed token {label!r}. Revoke it in Cloudflare as well."],
    )
