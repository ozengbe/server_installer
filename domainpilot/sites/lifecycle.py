"""Site lifecycle: create, enable/disable, delete (archive or purge), repair.

A site is a primary domain (plus optional aliases) served by one isolated
tenant. Creation is a single transaction: tenant runtime (Phase 4 steps),
starter page, nginx log directory, vhost and registry rows. Any failure
undoes everything; a crash leaves the tenant in "provisioning", which
`repair` removes completely.
"""

from __future__ import annotations

import grp
import pwd
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from domainpilot.core import fsutil, proc, validate
from domainpilot.core.audit import AuditLog
from domainpilot.core.config import HostFacts
from domainpilot.core.errors import NotImplementedYet, OperationFailed, PreconditionFailed
from domainpilot.core.paths import Paths
from domainpilot.core.registry import Registry, Site, Tenant
from domainpilot.core.txn import Reporter, Step, Transaction
from domainpilot.isolation import db
from domainpilot.isolation.limits import TenantLimits
from domainpilot.isolation.provision import SYSTEMCTL, Provisioner
from domainpilot.isolation.render import TenantSpec
from domainpilot.web.nginx import Nginx, Upstream, parse_upstream

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
        return self.nginx.render(
            kind, domain=site.domain, aliases=aliases, tenant=tenant.id, upstream=upstream
        )

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

        if self.dry_run:
            tenant = Tenant("t0000", 20000, "provisioning", "s", "local", "")
        else:
            tenant = self.registry.allocate_tenant()
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
        if not self.dry_run:
            self.registry.set_tenant_status(tenant.id, "active")
        return {
            "domain": domain,
            "aliases": aliases,
            "tenant": tenant.id,
            "type": req.site_type,
            "php_version": php if is_php else None,
            "dry_run": self.dry_run,
            "plan": result.plan if self.dry_run else None,
        }

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
            if self.reporter:
                self.reporter(f"removed nginx configuration for {domain}", "done")
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
