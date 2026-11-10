"""Site lifecycle: create, enable/disable, delete (archive or purge), repair.

A site is a primary domain (plus optional aliases) served by one isolated
tenant. Creation is a single transaction: tenant runtime (Phase 4 steps),
starter page, nginx log directory, vhost and registry rows. Any failure
undoes everything; a crash leaves the tenant in "provisioning", which
`repair` removes completely.
"""

from __future__ import annotations

import contextlib
import grp
import json
import pwd
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from domainpilot.cloudflare.api import CloudflareError, Zone
from domainpilot.cloudflare.creds import CredentialStore
from domainpilot.cloudflare.manager import CloudflareManager, ZoneRef
from domainpilot.core import fsutil, proc, validate
from domainpilot.core.audit import AuditLog
from domainpilot.core.config import Config, HostFacts
from domainpilot.core.errors import (
    DPError,
    NotImplementedYet,
    OperationFailed,
    PreconditionFailed,
)
from domainpilot.core.paths import Paths
from domainpilot.core.registry import UID_BASE, Registry, Site, Tenant
from domainpilot.core.txn import Reporter, Step, Transaction
from domainpilot.isolation import db
from domainpilot.isolation.limits import TenantLimits
from domainpilot.isolation.provision import SYSTEMCTL, Provisioner
from domainpilot.isolation.render import TenantSpec
from domainpilot.isolation.render import render as render_tenant
from domainpilot.optimize.site import measure_workers, recommend_limits
from domainpilot.optimize.snapshot import SnapshotStore
from domainpilot.sftp import SftpManager
from domainpilot.tls import dns, selfsigned
from domainpilot.tls.acme import Certbot
from domainpilot.web.nginx import DEFAULT_HSTS, Nginx, TlsFiles, Upstream, parse_upstream

Runner = Callable[..., proc.Result]
UpstreamParser = Callable[[str], Upstream]

STARTER_PHP = """<?php
// Placeholder created by DomainPilot. Replace it by uploading your site over SFTP.
http_response_code(200);
header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><title>Site ready</title><h1>Site ready</h1>';
"""
STARTER_HTML = (
    "<!doctype html><title>Site ready</title><h1>Site ready</h1>\n"
    "<!-- Placeholder created by DomainPilot. Replace it by uploading your site. -->\n"
)
UNFINISHED = ("provisioning",)


@dataclass
class CreateRequest:
    domain: str
    site_type: str = "php"
    aliases: list[str] = field(default_factory=list)
    php_version: str | None = None
    tier: str = "s"
    upstream: str | None = None
    writable_code: bool = False
    limits: TenantLimits = field(default_factory=TenantLimits)
    # Opt-in (--cloudflare-dns): create proxied DNS records in Cloudflare. By default
    # DomainPilot never touches DNS: point the name at the server yourself (orange
    # cloud on or off), like CloudPanel.
    cloudflare: bool = False
    # Try Let's Encrypt right after creation (--no-ssl turns AutoSSL off for the site).
    ssl: bool = True
    # Disaster recovery: reuse the tenant id the site had on a lost server.
    tenant_id: str | None = None


class SiteManager:
    def __init__(
        self,
        *,
        paths: Paths,
        host: HostFacts,
        registry: Registry,
        audit: AuditLog,
        argv: list[str],
        run: Runner = proc.run,
        nginx: Nginx | None = None,
        reporter: Reporter | None = None,
        dry_run: bool = False,
        upstream_parser: UpstreamParser = parse_upstream,
        config: Config | None = None,
        certbot: Certbot | None = None,
        host_ips: Callable[[], set[str]] | None = None,
        resolver: dns.Resolver = dns.resolve,
        cloudflare: CloudflareManager | None = None,
        proxy_ranges: Callable[[], Sequence[dns.Network]] | None = None,
    ) -> None:
        self.paths = paths
        self.host = host
        self.registry = registry
        self.audit = audit
        self.argv = argv
        self.run = run
        self.nginx = nginx or Nginx(paths, run=run)
        self.reporter = reporter
        self.dry_run = dry_run
        self.parse_upstream = upstream_parser
        self.provisioner = Provisioner(paths, host, run=run)
        self.config = config or Config()
        self.certbot = certbot or Certbot(run=run)
        self.host_ips = host_ips or (lambda: dns.host_addresses(run))
        self.resolver = resolver
        self.proxy_ranges = proxy_ranges or dns.cloudflare_ranges
        self.selfsigned_dir = self.nginx.conf_dir.parent / "selfsigned"
        self.cloudflare = cloudflare or CloudflareManager(CredentialStore(run=run))
        self.sftp = SftpManager(audit=audit, argv=argv, run=run, keys_dir=paths.ssh_keys)

    # --- helpers -------------------------------------------------------------

    def _txn(self, target: str) -> Transaction:
        return Transaction(
            registry=self.registry,
            audit=self.audit,
            command=self.argv,
            target=target,
            dry_run=self.dry_run,
            reporter=self.reporter,
        )

    def primary_site(self, domain: str) -> tuple[Site, Tenant]:
        site = self.registry.get_site(domain)
        if site is None:
            raise PreconditionFailed(
                f"{domain} is not a DomainPilot site",
                hint=f"create it with: sudo site {domain} create",
            )
        if not site.is_primary:
            primary = next(
                s.domain for s in self.registry.sites_for_tenant(site.tenant_id) if s.is_primary
            )
            raise PreconditionFailed(f"{domain} is an alias of {primary}; use {primary}")
        tenant = self.registry.get_tenant(site.tenant_id)
        if tenant is None:
            raise OperationFailed(f"registry inconsistency: tenant {site.tenant_id} missing")
        return site, tenant

    def _render(self, site: Site, tenant: Tenant, *, enabled: bool) -> str:
        settings = self.registry.get_tenant_settings(tenant.id)
        aliases = [s.domain for s in self.registry.sites_for_tenant(tenant.id) if not s.is_primary]
        if not enabled:
            kind = "maintenance"
            upstream = None
        else:
            kind = site.site_type
            upstream = self.parse_upstream(settings["upstream"]) if kind == "proxy" else None
        tls = self._tls(site.domain, settings)
        placeholder = None if tls else selfsigned.files(self.selfsigned_dir, site.domain)
        return self.nginx.render(
            kind,
            domain=site.domain,
            aliases=aliases,
            tenant=tenant.id,
            upstream=upstream,
            tls=tls or placeholder,
            hsts_max_age=int(settings.get("hsts", DEFAULT_HSTS)),
            trusted=tls is not None,
        )

    def _tls(self, domain: str, settings: dict[str, Any]) -> TlsFiles | None:
        """Serve HTTPS only if TLS is enabled for the site AND the files exist."""
        if settings.get("tls", {}).get("enabled") and self.certbot.exists(domain):
            return self.certbot.files(domain)
        return None

    def _update_settings(self, tenant: str, **changes: Any) -> None:
        settings = self.registry.get_tenant_settings(tenant)
        settings.update(changes)
        self.registry.set_tenant_settings(tenant, settings)

    def _names(self, tenant: str) -> list[str]:
        sites = self.registry.sites_for_tenant(tenant)
        return [s.domain for s in sorted(sites, key=lambda s: (not s.is_primary, s.domain))]

    def _units(self, tenant: str) -> list[str]:
        settings = self.registry.get_tenant_settings(tenant)
        units = []
        if settings.get("cache"):
            units.append(f"dp-cache@{tenant}.service")
        if settings.get("php"):
            units.append(f"dp-php@{tenant}.service")
        return units

    def _systemctl(self, *args: str) -> Callable[[], None]:
        def action() -> None:
            self.run([SYSTEMCTL, *args], timeout=120)

        return action

    # --- create --------------------------------------------------------------

    def _check_free_identity(self, tenant_id: str) -> None:
        """--tenant-id must not collide with anything left on this host."""
        uid = UID_BASE + int(tenant_id[1:])
        clashes = []
        for name in (tenant_id, f"{tenant_id}-deploy"):
            with contextlib.suppress(KeyError):
                pwd.getpwnam(name)
                clashes.append(f"user {name}")
        with contextlib.suppress(KeyError):
            clashes.append(f"uid {uid} ({pwd.getpwuid(uid).pw_name})")
        root = self.paths.tenant_root(tenant_id)
        if root.exists() or root.is_symlink():
            clashes.append(str(root))
        if clashes:
            raise PreconditionFailed(
                f"tenant id {tenant_id} is still in use on this host: {', '.join(clashes)}",
                hint="--tenant-id is only for recreating a site on a new server",
            )

    def create(self, req: CreateRequest) -> dict[str, Any]:
        domain = validate.domain(req.domain)
        aliases = list(dict.fromkeys(validate.domain(a) for a in req.aliases if a != domain))
        if req.site_type not in ("php", "static", "proxy"):
            raise PreconditionFailed(f"unknown site type {req.site_type!r}")
        if req.tier != "s":
            raise NotImplementedYet("container tier (--tier c) is planned for a later phase")
        if req.writable_code:
            raise NotImplementedYet("--writable-code is planned for a later phase")
        # Unfinished creations first: a crash after registration leaves rows that
        # would otherwise look like an existing site.
        if self.registry.tenants_for_domain(domain, statuses=UNFINISHED):
            raise PreconditionFailed(
                f"an earlier attempt to create {domain} did not finish",
                hint=f"run: sudo site {domain} repair",
            )
        for name in (domain, *aliases):
            if self.registry.get_site(name) is not None:
                raise PreconditionFailed(f"{name} is already a DomainPilot site (or alias)")
        is_php = req.site_type == "php"
        php = req.php_version or self.host.default_php_version
        if is_php and php not in self.host.php_versions:
            raise PreconditionFailed(f"PHP {php} is not installed on this host")
        if req.site_type == "proxy" and not req.upstream:
            raise PreconditionFailed("proxy sites need --upstream https://host")
        upstream = (
            self.parse_upstream(req.upstream) if req.site_type == "proxy" and req.upstream else None
        )
        if req.site_type != "proxy" and req.upstream:
            raise PreconditionFailed("--upstream is only valid with --type proxy")

        if req.tenant_id is not None:
            self._check_free_identity(validate.tenant_id(req.tenant_id))
        if self.dry_run:
            tenant = Tenant(req.tenant_id or "t0000", 20000, "provisioning", "s", "local", "")
        else:
            tenant = self.registry.allocate_tenant(tenant_id=req.tenant_id)
            self.registry.set_tenant_settings(
                tenant.id,
                {
                    "domain": domain,
                    "site_type": req.site_type,
                    "php": is_php,
                    "php_version": php if is_php else None,
                    "cache": is_php,
                    "upstream": upstream.url if upstream else None,
                    "limits": req.limits.to_dict(),
                    "autossl": self.config.autossl and req.ssl,
                    "tls": {"enabled": False},
                    "hsts": DEFAULT_HSTS,
                },
            )
        spec = TenantSpec(
            tenant.id, max(tenant.uid, 20000), php, req.limits, cache=is_php, php=is_php
        )
        txn = self._txn(domain)
        for step in self.provisioner.create_steps(spec, db_password=db.new_password()):
            txn.add(step)
        self._add_site_steps(txn, spec, domain, aliases, req.site_type, upstream)
        try:
            result = txn.execute()
        except BaseException:
            if not self.dry_run:
                self.registry.set_tenant_status(tenant.id, "purged")
            raise
        ssl_note = cf_note = None
        if not self.dry_run:
            self.registry.set_tenant_status(tenant.id, "active")
            cf_note = self._cloudflare_after_create(domain, tenant.id) if req.cloudflare else None
            self._placeholder_after_create(domain)
            ssl_note = self._autossl_after_create(domain, enabled=req.ssl)
        return {
            "domain": domain,
            "aliases": aliases,
            "tenant": tenant.id,
            "type": req.site_type,
            "php_version": php if is_php else None,
            "dry_run": self.dry_run,
            "plan": result.plan if self.dry_run else None,
            "cloudflare": cf_note,
            "ssl": ssl_note,
        }

    # --- Cloudflare -------------------------------------------------------------------

    def _cf_ref(self, tenant: str) -> ZoneRef | None:
        """The Cloudflare zone this site's DNS is managed in (None = not managed)."""
        cf = self.registry.get_tenant_settings(tenant).get("cloudflare")
        if not cf:
            return None
        return ZoneRef(cf["label"], Zone(cf["zone_id"], cf["zone"], "active", ""))

    def _eligibility(self, tenant: str, names: list[str]) -> list[str]:
        """Why a certificate cannot be issued now (DNS-01 via Cloudflare or HTTP-01)."""
        ref = self._cf_ref(tenant)
        if ref is not None:
            try:
                return self.cloudflare.records_ok(ref, names, self.host_ips())
            except CloudflareError as exc:
                return [f"Cloudflare: {exc.message}"]
        return dns.problems(names, self.host_ips(), self.resolver, self.proxy_ranges())

    def _cloudflare_after_create(self, domain: str, tenant: str) -> str | None:
        """Point the new site's names at this server through Cloudflare (proxied).

        Never fails the creation: problems are reported and the site keeps
        working for DNS you manage yourself.
        """
        try:
            ref = self.cloudflare.zone_for(domain)
        except (CloudflareError, DPError) as exc:
            return f"skipped: {getattr(exc, 'message', exc)}"
        if ref is None:
            return None  # not on Cloudflare (or no token for its zone): nothing to do
        names = self._names(tenant)
        outside = [n for n in names if n != ref.zone.name and not n.endswith("." + ref.zone.name)]
        names = [n for n in names if n not in outside]
        try:
            actions = self.cloudflare.ensure_records(ref, names, self.host_ips(), tenant)
        except (CloudflareError, DPError) as exc:
            message = getattr(exc, "message", str(exc))
            if self.reporter:
                self.reporter(f"Cloudflare DNS not configured: {message}", "failed")
            return f"not configured: {message}"
        self._update_settings(
            tenant,
            cloudflare={
                "label": ref.label,
                "zone": ref.zone.name,
                "zone_id": ref.zone.id,
                "proxied": True,
            },
        )
        for action in actions:
            if self.reporter:
                self.reporter(f"Cloudflare: {action}", "done")
        note = f"proxied through Cloudflare zone {ref.zone.name}"
        if outside:
            note += f" (not in this zone, manage yourself: {', '.join(outside)})"
        return note

    def _cloudflare_cleanup(self, domain: str, tenant: str) -> list[str]:
        """Remove the records DomainPilot created for this site (tagged ones only)."""
        ref = self._cf_ref(tenant)
        if ref is None:
            return []
        try:
            return self.cloudflare.remove_records(ref, self._names(tenant) or [domain], tenant)
        except (CloudflareError, DPError) as exc:
            return [f"Cloudflare cleanup failed: {getattr(exc, 'message', exc)}"]

    def cloudflare_audit(self, domain: str, sections: list[str]) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        ref = self._cf_ref(tenant.id) or self.cloudflare.zone_for(domain)
        if ref is None:
            raise PreconditionFailed(
                f"{domain} is not in any Cloudflare zone reachable with a stored token",
                hint="add a token: sudo site system cloudflare token add",
            )
        # Use fresh zone data (status) for the audit.
        fresh = next((z for z in self.cloudflare.zones(ref.label) if z.id == ref.zone.id), ref.zone)
        audit = self.cloudflare.audit(
            ZoneRef(ref.label, fresh), self._names(tenant.id), self.host_ips(), sections=sections
        )
        result = audit.as_dict()
        result["managed"] = self._cf_ref(tenant.id) is not None
        return result

    def cloudflare_sync(self, domain: str) -> dict[str, Any]:
        """--apply for `cloudflare dns`: (re)create this site's proxied records."""
        _site, tenant = self.primary_site(domain)
        ref = self._cf_ref(tenant.id) or self.cloudflare.zone_for(domain)
        if ref is None:
            raise PreconditionFailed(f"{domain} is not in a Cloudflare zone with a stored token")
        actions = self.cloudflare.ensure_records(
            ref, self._names(tenant.id), self.host_ips(), tenant.id, dry_run=self.dry_run
        )
        if not self.dry_run:
            self._update_settings(
                tenant.id,
                cloudflare={
                    "label": ref.label,
                    "zone": ref.zone.name,
                    "zone_id": ref.zone.id,
                    "proxied": True,
                },
            )
            self.audit.record(
                "cloudflare.dns",
                argv=self.argv,
                outcome="success",
                details={"domain": domain, "actions": actions},
            )
        return {"domain": domain, "actions": actions, "dry_run": self.dry_run}

    def _placeholder_after_create(self, domain: str) -> None:
        """Self-signed certificate so HTTPS answers at once (Cloudflare "Full" mode
        works immediately). Never fails the creation."""
        site, tenant = self.primary_site(domain)
        try:
            selfsigned.ensure(self.selfsigned_dir, domain, self._names(tenant.id), self.run)
            self.nginx.apply(domain, self._render(site, tenant, enabled=site.enabled))
        except DPError as exc:
            if self.reporter:
                self.reporter(f"no placeholder certificate: {exc.message}", "failed")
            return
        if self.reporter and selfsigned.files(self.selfsigned_dir, domain):
            self.reporter("HTTPS enabled with a self-signed placeholder certificate", "done")

    def _autossl_after_create(self, domain: str, *, enabled: bool = True) -> str:
        """Try to get a certificate for a new site. Never fails the creation."""
        if not (self.config.autossl and enabled):
            return f"AutoSSL is off; when ready run: sudo site {domain} ssl"
        try:
            self.ssl_issue(domain)
        except DPError as exc:
            if self.reporter:
                self.reporter(f"no Let's Encrypt certificate yet: {exc.message}", "pending")
            return (
                f"not issued yet ({exc.message}). AutoSSL retries automatically; "
                "until then the site uses its self-signed certificate (fine behind "
                'Cloudflare with SSL/TLS mode "Full")'
            )
        return "issued"

    # --- TLS / AutoSSL --------------------------------------------------------------

    def ssl_issue(self, domain: str, *, staging: bool | None = None) -> dict[str, Any]:
        """Obtain a certificate, verify it, then switch the vhost to HTTPS."""
        site, tenant = self.primary_site(domain)
        if tenant.status != "active":
            raise PreconditionFailed(
                f"{domain} is {tenant.status}; certificates need an active site"
            )
        names = self._names(tenant.id)
        use_staging = self.config.ssl_staging if staging is None else staging
        reasons = self._eligibility(tenant.id, names)
        if reasons:
            raise PreconditionFailed(
                "not eligible for a certificate yet: " + "; ".join(reasons),
                hint="point DNS (A and AAAA records) at this server, then run: "
                f"sudo site {domain} ssl",
            )
        settings = self.registry.get_tenant_settings(tenant.id)
        previous_tls = dict(settings.get("tls", {}))
        previous_vhost: list[bytes | None] = []
        info: list[Any] = []

        def obtain() -> None:
            cf = self._cf_ref(tenant.id)
            ini = self.cloudflare.store.certbot_ini(cf.label) if cf else None
            try:
                self.certbot.issue(
                    domain,
                    names,
                    staging=use_staging,
                    email=self.config.ssl_email,
                    dns_credentials=ini,
                )
            finally:
                if cf:
                    self.cloudflare.store.discard_ini(cf.label)

        def check() -> None:
            info.append(self.certbot.verify(domain, names))

        def record() -> None:
            self._update_settings(tenant.id, tls={"enabled": True, "staging": use_staging})

        def unrecord() -> None:
            self._update_settings(tenant.id, tls=previous_tls)

        def vhost() -> None:
            previous_vhost.append(
                self.nginx.apply(domain, self._render(site, tenant, enabled=site.enabled))
            )

        txn = self._txn(domain)
        txn.add(
            Step(
                "certificate",
                f"request a certificate for {', '.join(names)}"
                + (" (staging CA)" if use_staging else ""),
                obtain,
            )
        )
        txn.add(Step("verify-certificate", "verify names, validity and key match", check))
        txn.add(Step("record-tls", "mark HTTPS as enabled", record, unrecord))
        txn.add(
            Step(
                "https-vhost",
                f"switch nginx for {domain} to HTTPS (validated)",
                vhost,
                lambda: self.nginx.restore(domain, previous_vhost[0] if previous_vhost else None),
            )
        )
        txn.execute()
        if self.dry_run:
            return {"domain": domain, "names": names, "staging": use_staging, "dry_run": True}
        cert = info[0]
        return {
            "domain": domain,
            "names": list(cert.names),
            "staging": cert.staging,
            "issuer": cert.issuer,
            "not_after": cert.not_after.isoformat(),
            "days_left": cert.days_left,
        }

    def ssl_status(self, domain: str) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        settings = self.registry.get_tenant_settings(tenant.id)
        cert = self.certbot.info(domain)
        names = self._names(tenant.id)
        return {
            "domain": domain,
            "autossl": bool(settings.get("autossl", False)),
            "https": bool(self._tls(domain, settings))
            or selfsigned.files(self.selfsigned_dir, domain) is not None,
            "certificate_kind": "lets-encrypt"
            if self._tls(domain, settings)
            else "self-signed placeholder"
            if selfsigned.files(self.selfsigned_dir, domain)
            else "none",
            "hsts_max_age": settings.get("hsts", DEFAULT_HSTS),
            "eligibility_problems": self._eligibility(tenant.id, names),
            "challenge": "dns-01 (Cloudflare)" if self._cf_ref(tenant.id) else "http-01",
            "certificate": None
            if cert is None
            else {
                "names": list(cert.names),
                "issuer": cert.issuer,
                "staging": cert.staging,
                "not_after": cert.not_after.isoformat(),
                "days_left": cert.days_left,
                "covers_all_names": set(names) <= set(cert.names),
            },
        }

    def ssl_renew(self, domain: str, *, force: bool) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        if not self.certbot.exists(domain):
            raise PreconditionFailed(f"{domain} has no certificate", hint=f"sudo site {domain} ssl")
        if self.dry_run:
            return {"domain": domain, "force": force, "dry_run": True}
        self.certbot.renew(domain, force=force)
        cert = self.certbot.verify(domain, self._names(tenant.id))
        self.audit.record(
            "ssl.renew",
            argv=self.argv,
            outcome="success",
            details={"domain": domain, "not_after": cert.not_after.isoformat()},
        )
        return {
            "domain": domain,
            "days_left": cert.days_left,
            "not_after": cert.not_after.isoformat(),
        }

    def ssl_revoke(self, domain: str) -> dict[str, Any]:
        """Back to HTTP first (so nginx never points at deleted files), then revoke."""
        site, tenant = self.primary_site(domain)
        if not self.certbot.exists(domain):
            raise PreconditionFailed(f"{domain} has no certificate")
        if self.dry_run:
            return {"domain": domain, "dry_run": True}
        settings = self.registry.get_tenant_settings(tenant.id)
        self._update_settings(tenant.id, tls={"enabled": False}, autossl=False)
        try:
            self.nginx.apply(domain, self._render(site, tenant, enabled=site.enabled))
        except DPError:
            self.registry.set_tenant_settings(tenant.id, settings)
            raise
        self.certbot.revoke(domain)
        self.audit.record(
            "ssl.revoke", argv=self.argv, outcome="success", details={"domain": domain}
        )
        return {"domain": domain, "revoked": True, "autossl": False}

    def autossl_pending(self, *, now: float, every: float = 3600) -> dict[str, str]:
        """AutoSSL retry (from the 5-minute self-check): sites with AutoSSL on and no
        Let's Encrypt certificate yet get one as soon as their DNS is ready. Each
        site is tried at most once per ``every`` seconds (Let's Encrypt limits
        failed validations), and only when the DNS pre-check passes."""
        results: dict[str, str] = {}
        for tenant in self.registry.list_tenants():
            if tenant.status != "active":
                continue
            settings = self.registry.get_tenant_settings(tenant.id)
            primary = next(
                (s for s in self.registry.sites_for_tenant(tenant.id) if s.is_primary), None
            )
            if primary is None or not settings.get("autossl") or not primary.enabled:
                continue
            if settings.get("tls", {}).get("enabled") and self.certbot.exists(primary.domain):
                continue
            tried = settings.get("autossl_tried")
            if tried is not None and now - float(tried) < every:
                continue
            if self._eligibility(tenant.id, self._names(tenant.id)):
                results[primary.domain] = "waiting for DNS"
                continue
            self._update_settings(tenant.id, autossl_tried=now)
            try:
                self.ssl_issue(primary.domain)
                results[primary.domain] = "issued"
            except DPError as exc:
                results[primary.domain] = f"failed: {exc.message}"
        return results

    def set_autossl(self, domain: str, on: bool) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        if self.dry_run:
            return {"domain": domain, "autossl": on, "dry_run": True}
        self._update_settings(tenant.id, autossl=on)
        result: dict[str, Any] = {"domain": domain, "autossl": on, "issued": False}
        if on and not self.certbot.exists(domain):
            reasons = self._eligibility(tenant.id, self._names(tenant.id))
            if reasons:
                result["waiting_for"] = reasons
            else:
                self.ssl_issue(domain)
                result["issued"] = True
        return result

    def _add_site_steps(
        self,
        txn: Transaction,
        spec: TenantSpec,
        domain: str,
        aliases: list[str],
        site_type: str,
        upstream: Upstream | None,
    ) -> None:
        t = spec.tenant
        public = self.paths.tenant_root(t) / "app" / "public"
        starter = public / ("index.php" if site_type == "php" else "index.html")
        log_created: list[bool] = []
        previous_vhost: list[bytes | None] = []

        def write_starter() -> None:
            deploy = pwd.getpwnam(spec.deploy_user).pw_uid
            gid = grp.getgrnam(t).gr_gid
            # public/ belongs to the deploy user: exclusive no-follow creation
            # cannot be redirected by anything planted there.
            content = STARTER_PHP if site_type == "php" else STARTER_HTML
            fsutil.create_exclusive(starter, content, mode=0o640, uid=deploy, gid=gid)

        def make_logs() -> None:
            log_created.append(self.nginx.ensure_log_dir(t))

        def remove_logs() -> None:
            if log_created and log_created[0]:
                shutil.rmtree(self.nginx.log_dir(t), ignore_errors=True)

        def vhost() -> None:
            content = self.nginx.render(
                site_type, domain=domain, aliases=aliases, tenant=t, upstream=upstream
            )
            previous_vhost.append(self.nginx.apply(domain, content))

        def undo_vhost() -> None:
            self.nginx.restore(domain, previous_vhost[0] if previous_vhost else None)

        def register() -> None:
            self.registry.add_site(
                domain,
                t,
                site_type=site_type,
                php_version=spec.php_version if spec.php else None,
                is_primary=True,
            )
            for alias in aliases:
                self.registry.add_site(
                    alias,
                    t,
                    site_type=site_type,
                    php_version=spec.php_version if spec.php else None,
                    is_primary=False,
                )

        def unregister() -> None:
            for name in (domain, *aliases):
                self.registry.remove_site(name)

        if site_type != "proxy":
            txn.add(
                Step(
                    "starter-page",
                    f"place a starter page in {public}",
                    write_starter,
                    lambda: starter.unlink(missing_ok=True),
                )
            )
        txn.add(Step("web-logs", f"create nginx log directory for {t}", make_logs, remove_logs))
        txn.add(
            Step(
                "vhost",
                f"configure nginx for {domain} (validated with nginx -t)",
                vhost,
                undo_vhost,
            )
        )
        txn.add(Step("register", f"register {domain} in the site registry", register, unregister))

    # --- enable / disable ---------------------------------------------------------

    def set_enabled(self, domain: str, enabled: bool) -> dict[str, Any]:
        site, tenant = self.primary_site(domain)
        if tenant.status == "archived":
            raise PreconditionFailed(f"{domain} was deleted (archived); it cannot be re-enabled")
        if site.enabled == enabled:
            return {"domain": domain, "enabled": enabled, "changed": False}
        units = self._units(tenant.id)
        previous: list[bytes | None] = []
        txn = self._txn(domain)
        target = "the site" if enabled else "a 503 maintenance page"

        def vhost() -> None:
            previous.append(self.nginx.apply(domain, self._render(site, tenant, enabled=enabled)))

        txn.add(
            Step(
                "vhost",
                f"switch nginx for {domain} to {target}",
                vhost,
                lambda: self.nginx.restore(domain, previous[0] if previous else None),
            )
        )
        if units:
            on, off = (
                self._systemctl("enable", "--now", *units),
                self._systemctl("disable", "--now", *units),
            )
            txn.add(
                Step(
                    "runtime",
                    f"{'start' if enabled else 'stop'} {', '.join(units)}",
                    on if enabled else off,
                    off if enabled else on,
                )
            )
        txn.add(
            Step(
                "register",
                f"mark {domain} {'enabled' if enabled else 'disabled'}",
                lambda: self.registry.set_site_enabled(domain, enabled),
                lambda: self.registry.set_site_enabled(domain, not enabled),
            )
        )
        txn.execute()
        return {"domain": domain, "enabled": enabled, "changed": True, "dry_run": self.dry_run}

    # --- delete -------------------------------------------------------------

    def delete(self, domain: str, *, purge: bool) -> dict[str, Any]:
        site, tenant = self.primary_site(domain)
        names = [s.domain for s in self.registry.sites_for_tenant(tenant.id)]
        if self.dry_run:
            plan = [
                f"remove nginx configuration for {domain}",
                f"stop {', '.join(self._units(tenant.id)) or 'nothing'}",
            ]
            plan += (
                [f"ERASE files, databases and accounts of {tenant.id}"]
                if purge
                else [f"keep files and databases of {tenant.id} (archived)"]
            )
            for line in plan:
                self.reporter and self.reporter(line, "planned")
            return {"domain": domain, "purge": purge, "dry_run": True, "plan": plan}

        if tenant.status != "archived":
            self.nginx.remove(domain)
            selfsigned.remove(self.selfsigned_dir, domain)
            if self.reporter:
                self.reporter(f"removed nginx configuration for {domain}", "done")
            for line in self._cloudflare_cleanup(domain, tenant.id):
                if self.reporter:
                    self.reporter(line, "failed" if "failed" in line else "done")
        if self.sftp.revoke_all(tenant.id) and self.reporter:
            self.reporter(f"revoked SFTP access of {tenant.id}", "done")
        if not purge:
            units = self._units(tenant.id)
            if units:
                self.run([SYSTEMCTL, "disable", "--now", *units], timeout=120)
            for name in names:
                self.registry.set_site_enabled(name, False)
            self.registry.set_tenant_status(tenant.id, "archived")
            self.audit.record(
                "site.delete",
                argv=self.argv,
                outcome="success",
                details={"tenant": tenant.id, "purge": False},
            )
            if self.reporter:
                self.reporter(f"archived {tenant.id}; files and databases kept", "done")
            return {"domain": domain, "tenant": tenant.id, "purge": False, "problems": []}

        problems = self.provisioner.purge(tenant.id)
        try:
            self.certbot.delete(domain)
        except DPError as exc:
            problems.append(f"certificate: {exc.message}")
        shutil.rmtree(self.nginx.log_dir(tenant.id), ignore_errors=True)
        for name in names:
            self.registry.remove_site(name)
        self.registry.set_tenant_status(tenant.id, "purged")
        self.audit.record(
            "site.delete",
            argv=self.argv,
            outcome="success" if not problems else "partial",
            details={"tenant": tenant.id, "purge": True, "problems": problems},
        )
        if self.reporter:
            self.reporter(f"erased {tenant.id} ({len(problems)} problem(s))", "done")
        return {"domain": domain, "tenant": tenant.id, "purge": True, "problems": problems}

    # --- repair -------------------------------------------------------------

    def repair(self, domain: str) -> dict[str, Any]:
        """Bring a site back to a consistent state after an interrupted operation.

        * An unfinished creation is removed completely (re-run `create`).
        * An existing site gets its vhost and runtime state re-applied from the registry.
        """
        domain = validate.domain(domain)
        actions: list[str] = []
        problems: list[str] = []
        for tenant in self.registry.tenants_for_domain(domain, statuses=UNFINISHED):
            if self.dry_run:
                actions.append(f"remove unfinished creation {tenant.id}")
                continue
            try:
                self.nginx.remove(domain)
            except OperationFailed as exc:
                problems.append(str(exc))
            selfsigned.remove(self.selfsigned_dir, domain)
            problems += self.provisioner.purge(tenant.id)
            shutil.rmtree(self.nginx.log_dir(tenant.id), ignore_errors=True)
            for site in self.registry.sites_for_tenant(tenant.id):
                self.registry.remove_site(site.domain)
            self.registry.set_tenant_status(tenant.id, "purged")
            actions.append(f"removed unfinished creation {tenant.id}")

        current = self.registry.get_site(domain)
        if current is not None and current.is_primary:
            owner = self.registry.get_tenant(current.tenant_id)
            if owner is not None and owner.status == "active":
                if self.dry_run:
                    actions.append(f"re-apply nginx and runtime state for {domain}")
                else:
                    self.nginx.apply(domain, self._render(current, owner, enabled=current.enabled))
                    units = self._units(owner.id)
                    if units:
                        verb = ("enable", "--now") if current.enabled else ("disable", "--now")
                        self.run([SYSTEMCTL, *verb, *units], timeout=120)
                    actions.append(f"re-applied nginx and runtime state for {domain}")

        if not self.dry_run:
            for op in self.registry.unfinished_operations(domain):
                self.registry.update_operation(
                    op.id, steps=op.steps, status="rolled_back", error="cleaned up by site repair"
                )
                actions.append(f"closed interrupted operation {op.id}")
            self.audit.record(
                "site.repair",
                argv=self.argv,
                outcome="success" if not problems else "partial",
                details={"actions": actions, "problems": problems},
            )
        if self.reporter:
            for a in actions:
                self.reporter(a, "planned" if self.dry_run else "done")
        return {"domain": domain, "actions": actions, "problems": problems, "dry_run": self.dry_run}

    # --- tuning & PHP version (Phase 7) -------------------------------------------------

    def _tenant_files(
        self, tenant: Tenant, limits: TenantLimits, php_version: str
    ) -> dict[Path, Any]:
        settings = self.registry.get_tenant_settings(tenant.id)
        spec = TenantSpec(
            tenant.id,
            tenant.uid,
            php_version,
            limits,
            cache=bool(settings.get("cache")),
            php=bool(settings.get("php")),
        )
        return {f.path: f for f in render_tenant(spec, self.paths, self.host)}

    def _write_tenant_files(self, tenant: Tenant, files: dict[Path, Any]) -> None:
        gid = grp.getgrnam(tenant.id).gr_gid
        for path, f in files.items():
            fsutil.atomic_write(
                path, f.content, mode=f.mode, uid=0, gid=gid if f.group_is_tenant else 0
            )

    def site_optimize(self, domain: str, *, apply: bool) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        settings = self.registry.get_tenant_settings(tenant.id)
        if not settings.get("php"):
            raise PreconditionFailed(f"{domain} has no PHP runtime to tune")
        current = TenantLimits.from_dict(settings.get("limits", {}))
        stats = measure_workers(tenant.id)
        recommended, basis = recommend_limits(current, stats)
        result: dict[str, Any] = {
            "domain": domain,
            "basis": basis,
            "current": {"php_max_children": current.php_max_children},
            "recommended": {"php_max_children": recommended.php_max_children},
            "changed": recommended != current,
            "applied": False,
        }
        if not apply or not result["changed"] or self.dry_run:
            return result
        php = str(settings.get("php_version") or self.host.default_php_version)
        files = self._tenant_files(tenant, recommended, php)
        snap = SnapshotStore(self.paths.var_lib / "optimize").take(
            f"site:{domain}", list(files), note=json.dumps({"limits": current.to_dict()})
        )
        self._write_tenant_files(tenant, files)
        self._update_settings(tenant.id, limits=recommended.to_dict())
        self.run([SYSTEMCTL, "daemon-reload"], timeout=60)
        self.run([SYSTEMCTL, "restart", f"dp-php@{tenant.id}.service"], timeout=120)
        self.audit.record(
            "site.optimize",
            argv=self.argv,
            outcome="success",
            details={
                "domain": domain,
                "snapshot": snap.id,
                "php_max_children": recommended.php_max_children,
            },
        )
        result.update(applied=True, snapshot=snap.id)
        return result

    def site_optimize_rollback(self, domain: str, snap_id: str) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        store = SnapshotStore(self.paths.var_lib / "optimize")
        snap = store.get(snap_id)
        if snap.kind != f"site:{domain}":
            raise PreconditionFailed(f"snapshot {snap_id} does not belong to {domain}")
        if self.dry_run:
            return {"domain": domain, "snapshot": snap_id, "dry_run": True}
        changed = store.restore(snap)
        previous = json.loads(snap.note or "{}").get("limits")
        if previous:
            self._update_settings(tenant.id, limits=previous)
        self.run([SYSTEMCTL, "daemon-reload"], timeout=60)
        self.run([SYSTEMCTL, "restart", f"dp-php@{tenant.id}.service"], timeout=120)
        self.audit.record(
            "site.optimize.rollback",
            argv=self.argv,
            outcome="success",
            details={"domain": domain, "snapshot": snap_id},
        )
        return {"domain": domain, "snapshot": snap_id, "restored": changed}

    def php_switch(self, domain: str, version: str) -> dict[str, Any]:
        _site, tenant = self.primary_site(domain)
        version = validate.php_version(version)
        settings = self.registry.get_tenant_settings(tenant.id)
        if not settings.get("php"):
            raise PreconditionFailed(f"{domain} has no PHP runtime")
        if version not in self.host.php_versions:
            raise PreconditionFailed(
                f"PHP {version} is not installed on this host "
                f"(installed: {', '.join(self.host.php_versions)})"
            )
        old = str(settings.get("php_version"))
        if version == old:
            return {"domain": domain, "php_version": version, "changed": False}
        if self.dry_run:
            return {"domain": domain, "from": old, "to": version, "dry_run": True}
        limits = TenantLimits.from_dict(settings.get("limits", {}))
        old_files = self._tenant_files(tenant, limits, old)
        new_files = self._tenant_files(tenant, limits, version)
        unit = f"dp-php@{tenant.id}.service"
        try:
            self._write_tenant_files(tenant, new_files)
            self.run([SYSTEMCTL, "daemon-reload"], timeout=60)
            self.run([SYSTEMCTL, "restart", unit], timeout=120)
        except DPError:
            self._write_tenant_files(tenant, old_files)
            self.run([SYSTEMCTL, "daemon-reload"], timeout=60)
            self.run([SYSTEMCTL, "restart", unit], timeout=120, check=False)
            raise
        self._update_settings(tenant.id, php_version=version)
        self.registry.set_php_version(tenant.id, version)
        self.audit.record(
            "php.switch",
            argv=self.argv,
            outcome="success",
            details={"domain": domain, "from": old, "to": version},
        )
        return {"domain": domain, "from": old, "to": version, "changed": True}
