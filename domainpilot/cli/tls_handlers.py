"""Phase 6 commands: certificates (AutoSSL)."""

from __future__ import annotations

import argparse

from domainpilot.cli.context import CommandResult, Context
from domainpilot.cli.site_handlers import _domain, _manager
from domainpilot.core.errors import NotImplementedYet

RENEW_WARN_DAYS = 14


def _check_challenge(args: argparse.Namespace) -> None:
    if getattr(args, "challenge", "http") == "dns":
        raise NotImplementedYet("DNS-01 (Cloudflare) arrives in Phase 6b; use --challenge http")


def ssl_issue(ctx: Context, args: argparse.Namespace) -> CommandResult:
    _check_challenge(args)
    staging = True if args.staging else None
    result = _manager(ctx).ssl_issue(_domain(ctx), staging=staging)
    if result.get("dry_run"):
        return CommandResult(result, ["Dry run: no certificate requested."])
    note = " (STAGING: not trusted by browsers)" if result["staging"] else ""
    return CommandResult(
        result,
        [
            f"HTTPS enabled for {', '.join(result['names'])}{note}.",
            f"Valid until {result['not_after']} ({result['days_left']} days);"
            " renews automatically.",
        ],
    )


def autossl(ctx: Context, args: argparse.Namespace) -> CommandResult:
    on = args.state != "off"
    result = _manager(ctx).set_autossl(_domain(ctx), on)
    lines = [f"AutoSSL {'on' if on else 'off'} for {result['domain']}."]
    for reason in result.get("waiting_for", []):
        ctx.out.warn(f"waiting for DNS: {reason}")
    if result.get("issued"):
        lines.append("Certificate issued and HTTPS enabled.")
    return CommandResult(result, lines)


def ssl_status(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    st = _manager(ctx).ssl_status(_domain(ctx))
    cert = st["certificate"]
    lines = [
        f"HTTPS:    {'on' if st['https'] else 'off'}   AutoSSL: {'on' if st['autossl'] else 'off'}"
        f"   HSTS max-age: {st['hsts_max_age']}s",
    ]
    if cert is None:
        lines.append("Certificate: none")
    else:
        lines += [
            f"Certificate: {', '.join(cert['names'])}",
            f"  issuer {cert['issuer']}",
            f"  valid until {cert['not_after']} ({cert['days_left']} days)",
        ]
        if cert["staging"]:
            ctx.out.warn("this is a STAGING certificate (not trusted by browsers)")
        if cert["days_left"] < RENEW_WARN_DAYS:
            ctx.out.warn(f"certificate expires in {cert['days_left']} days")
        if not cert["covers_all_names"]:
            ctx.out.warn(
                f"certificate does not cover every name; run: sudo site {st['domain']} ssl"
            )
    for reason in st["eligibility_problems"]:
        ctx.out.warn(reason)
    return CommandResult(st, lines)


def ssl_renew(ctx: Context, args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).ssl_renew(_domain(ctx), force=args.force)
    if result.get("dry_run"):
        return CommandResult(result, ["Dry run: nothing renewed."])
    return CommandResult(result, [f"Certificate valid for {result['days_left']} more days."])


def ssl_revoke(ctx: Context, _args: argparse.Namespace) -> CommandResult:
    result = _manager(ctx).ssl_revoke(_domain(ctx))
    if result.get("dry_run"):
        return CommandResult(result, ["Dry run: nothing revoked."])
    return CommandResult(
        result,
        [
            f"Certificate for {result['domain']} revoked and deleted; site is served over HTTP.",
            "AutoSSL was turned off so it is not re-issued automatically.",
        ],
    )
