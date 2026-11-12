"""Cloudflare for any domain: find its zone, manage its proxied records, audit.

Safety rules:
* Records are only created for the site's own names, and are tagged with a
  comment "ozenix:<tenant>". Only records carrying that exact tag are
  ever deleted, so ozenix never removes something it did not create.
* An existing A/AAAA/CNAME record for a name that ozenix did not create
  stops the operation instead of being overwritten.
* Zone settings are only read and reported: ozenix's token needs read
  access to settings, never write access.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ozenix.cloudflare.api import Client, CloudflareError, DnsRecord, Zone
from ozenix.cloudflare.creds import CredentialStore
from ozenix.core import validate
from ozenix.core.errors import OperationFailed, PreconditionFailed

ClientFactory = Callable[[str], Client]
TAG_PREFIX = "ozenix:"


def tag(tenant: str) -> str:
    return TAG_PREFIX + validate.tenant_id(tenant)


@dataclass(frozen=True)
class ZoneRef:
    label: str
    zone: Zone


@dataclass
class Finding:
    severity: str  # "ok", "warn", "critical", "info"
    check: str
    message: str


@dataclass
class Audit:
    zone: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: str, check: str, message: str) -> None:
        self.findings.append(Finding(severity, check, message))

    @property
    def worst(self) -> str:
        order = ["ok", "info", "warn", "critical"]
        return max((f.severity for f in self.findings), key=order.index, default="ok")

    def as_dict(self) -> dict[str, Any]:
        return {
            "zone": self.zone,
            "worst": self.worst,
            "findings": [f.__dict__ for f in self.findings],
        }


class CloudflareManager:
    def __init__(self, store: CredentialStore, *, client_factory: ClientFactory = Client) -> None:
        self.store = store
        self.client_factory = client_factory
        self._zones: dict[str, list[Zone]] = {}
        self._clients: dict[str, Client] = {}

    def client(self, label: str) -> Client:
        if label not in self._clients:
            self._clients[label] = self.client_factory(self.store.load(label))
        return self._clients[label]

    def zones(self, label: str) -> list[Zone]:
        if label not in self._zones:
            self._zones[label] = self.client(label).zones()
        return self._zones[label]

    def zone_for(self, domain: str) -> ZoneRef | None:
        """Longest-suffix zone match across every stored token (None = not on Cloudflare)."""
        domain = validate.domain(domain)
        best: ZoneRef | None = None
        for label in self.store.labels():
            try:
                zones = self.zones(label)
            except (CloudflareError, OperationFailed):
                continue  # a broken token must not block other zones
            for zone in zones:
                in_zone = domain == zone.name or domain.endswith("." + zone.name)
                if in_zone and (best is None or len(zone.name) > len(best.zone.name)):
                    best = ZoneRef(label, zone)
        return best

    # --- DNS records ------------------------------------------------------------------

    def ensure_records(
        self,
        ref: ZoneRef,
        names: Sequence[str],
        host_ips: set[str],
        tenant: str,
        *,
        proxied: bool = True,
        dry_run: bool = False,
    ) -> list[str]:
        """Point each name at this server (A, and AAAA when the host has IPv6)."""
        v4 = sorted(ip for ip in host_ips if ipaddress.ip_address(ip).version == 4)
        v6 = sorted(ip for ip in host_ips if ipaddress.ip_address(ip).version == 6)
        if not v4:
            raise PreconditionFailed("this server has no public IPv4 address for Cloudflare")
        wanted = [("A", v4[0])] + ([("AAAA", v6[0])] if v6 else [])
        client = self.client(ref.label)
        actions: list[str] = []
        for name in names:
            existing = [
                r for r in client.records(ref.zone.id, name) if r.type in ("A", "AAAA", "CNAME")
            ]
            foreign = [r for r in existing if r.comment != tag(tenant)]
            if foreign:
                raise PreconditionFailed(
                    f"{name} already has DNS records in Cloudflare that ozenix did not "
                    f"create ({', '.join(sorted({r.type for r in foreign}))})",
                    hint="remove them in Cloudflare, or create the site with --no-cloudflare",
                )
            for rtype, content in wanted:
                if any(
                    r.type == rtype and r.content == content and r.proxied == proxied
                    for r in existing
                ):
                    continue
                actions.append(
                    f"create {rtype} {name} -> {content}" + (" (proxied)" if proxied else "")
                )
                if not dry_run:
                    client.create_record(
                        ref.zone.id,
                        type=rtype,
                        name=name,
                        content=content,
                        proxied=proxied,
                        comment=tag(tenant),
                    )
        return actions

    def remove_records(self, ref: ZoneRef, names: Sequence[str], tenant: str) -> list[str]:
        client = self.client(ref.label)
        removed = []
        for name in names:
            for r in client.records(ref.zone.id, name):
                if r.comment == tag(tenant):  # exact tag: never someone else's record
                    client.delete_record(ref.zone.id, r.id)
                    removed.append(f"deleted {r.type} {r.name}")
        return removed

    def records_ok(self, ref: ZoneRef, names: Sequence[str], host_ips: set[str]) -> list[str]:
        """Problems that would stop DNS-01 / proxying; empty when every name points here."""
        client = self.client(ref.label)
        out = []
        for name in names:
            recs = [r for r in client.records(ref.zone.id, name) if r.type in ("A", "AAAA")]
            if not recs:
                out.append(f"{name} has no A/AAAA record in Cloudflare")
            elif any(r.content not in host_ips for r in recs):
                out.append(f"{name} has records in Cloudflare that point elsewhere")
        return out

    # --- audits -------------------------------------------------------------------------

    def audit(
        self, ref: ZoneRef, names: Sequence[str], host_ips: set[str], *, sections: Sequence[str]
    ) -> Audit:
        client = self.client(ref.label)
        audit = Audit(ref.zone.name)
        if ref.zone.status != "active":
            audit.add("critical", "zone", f"zone status is {ref.zone.status!r}, not active")
        if "dns" in sections:
            self._audit_dns(client, ref, names, host_ips, audit)
        settings = self._settings(client, ref, audit)
        if "ssl" in sections and settings is not None:
            self._audit_ssl(settings, audit)
        if "security" in sections and settings is not None:
            self._audit_security(settings, audit)
        return audit

    def _audit_dns(
        self, client: Client, ref: ZoneRef, names: Sequence[str], host_ips: set[str], audit: Audit
    ) -> None:
        for name in names:
            recs: list[DnsRecord] = [
                r for r in client.records(ref.zone.id, name) if r.type in ("A", "AAAA", "CNAME")
            ]
            if not recs:
                audit.add("critical", "dns", f"{name}: no record in Cloudflare")
                continue
            for r in recs:
                where = "this server" if r.content in host_ips else r.content
                if not r.proxied:
                    audit.add(
                        "warn",
                        "dns",
                        f"{name} {r.type} -> {where}: DNS only (not proxied); "
                        "visitors reach the server directly",
                    )
                elif r.content not in host_ips and r.type != "CNAME":
                    audit.add(
                        "critical",
                        "dns",
                        f"{name} {r.type} points to {r.content}, " "not to this server",
                    )
                else:
                    audit.add("ok", "dns", f"{name} {r.type} -> {where} (proxied)")

    def _settings(self, client: Client, ref: ZoneRef, audit: Audit) -> dict[str, Any] | None:
        wanted = (
            "ssl",
            "min_tls_version",
            "always_use_https",
            "tls_1_3",
            "automatic_https_rewrites",
            "security_level",
            "browser_check",
            "tls_client_auth",
        )
        values: dict[str, Any] = {}
        for name in wanted:
            try:
                values[name] = client.setting(ref.zone.id, name)
            except CloudflareError as exc:
                if 9109 in exc.codes or 10000 in exc.codes:
                    audit.add(
                        "warn",
                        "permissions",
                        "the token cannot read zone settings; add "
                        "'Zone - Zone Settings - Read' to audit SSL and security",
                    )
                    return None
                values[name] = None
        return values

    @staticmethod
    def _audit_ssl(s: dict[str, Any], audit: Audit) -> None:
        mode = s.get("ssl")
        if mode == "strict":
            audit.add("ok", "ssl", "SSL/TLS mode is Full (strict)")
        elif mode == "full":
            audit.add(
                "critical",
                "ssl",
                "SSL/TLS mode is Full (not strict): Cloudflare does "
                "not verify the origin certificate; set Full (strict)",
            )
        else:
            audit.add(
                "critical",
                "ssl",
                f"SSL/TLS mode is {mode!r}: traffic to the origin is "
                "not (properly) encrypted; set Full (strict)",
            )
        tls = s.get("min_tls_version")
        audit.add(
            "ok" if tls in ("1.2", "1.3") else "warn",
            "ssl",
            f"minimum TLS version is {tls}"
            + ("" if tls in ("1.2", "1.3") else "; set at least 1.2"),
        )
        audit.add(
            "ok" if s.get("always_use_https") == "on" else "warn",
            "ssl",
            f"Always Use HTTPS is {s.get('always_use_https')}",
        )
        audit.add(
            "ok" if s.get("tls_1_3") in ("on", "zrt") else "info",
            "ssl",
            f"TLS 1.3 is {s.get('tls_1_3')}",
        )
        audit.add("info", "ssl", f"Authenticated Origin Pulls is {s.get('tls_client_auth')}")

    @staticmethod
    def _audit_security(s: dict[str, Any], audit: Audit) -> None:
        level = s.get("security_level")
        audit.add(
            "warn" if level in ("off", "essentially_off") else "ok",
            "security",
            f"security level is {level}",
        )
        audit.add(
            "ok" if s.get("browser_check") == "on" else "info",
            "security",
            f"browser integrity check is {s.get('browser_check')}",
        )
