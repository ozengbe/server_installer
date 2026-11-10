"""Is a name ready for HTTP-01 validation? (avoid burning ACME rate limits)

Every A/AAAA record of every name must point at this server: Let's Encrypt
may validate over IPv6 when an AAAA record exists, so a stale AAAA record
elsewhere fails validation even if the A record is right.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Callable, Sequence
from pathlib import Path

from domainpilot.core import proc
from domainpilot.core.errors import DPError

IP = "/usr/sbin/ip"
REALIP_CONF = Path("/etc/nginx/domainpilot/snippets/cloudflare-realip.conf")

Runner = Callable[..., proc.Result]
Resolver = Callable[[str], set[str]]
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def resolve(name: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(name, 80, proto=socket.IPPROTO_TCP)
    except OSError:
        return set()
    return {str(info[4][0]).split("%")[0] for info in infos}


def host_addresses(run: Runner = proc.run) -> set[str]:
    """Public (global-scope) addresses configured on this host."""
    try:
        result = run([IP, "-j", "address", "show"], timeout=15)
        interfaces = json.loads(result.stdout or "[]")
    except (DPError, ValueError):
        return set()
    found: set[str] = set()
    for iface in interfaces:
        for addr in iface.get("addr_info", []):
            local = addr.get("local")
            if addr.get("scope") == "global" and local and ipaddress.ip_address(local).is_global:
                found.add(local)
    return found


def problems(
    names: Sequence[str],
    host_ips: set[str],
    resolver: Resolver = resolve,
    proxy_ranges: Sequence[Network] = (),
) -> list[str]:
    """Human-readable reasons why HTTP-01 would fail; empty means eligible.

    A name proxied through Cloudflare (all its addresses are Cloudflare edges)
    counts as eligible: Cloudflare forwards the challenge to this server. We
    cannot see which origin it forwards to; if it is not this one, Let's
    Encrypt's check fails and the site simply stays on its placeholder.
    """
    out: list[str] = []
    if not host_ips:
        return ["this server has no public IP address configured"]
    for name in names:
        addresses = resolver(name)
        if not addresses:
            out.append(f"{name} does not resolve")
            continue
        if behind(addresses, proxy_ranges):
            continue
        foreign = sorted(addresses - host_ips)
        if foreign:
            out.append(f"{name} points to {', '.join(foreign)}, not to this server")
    return out


def cloudflare_ranges(path: Path = REALIP_CONF) -> list[Network]:
    """Cloudflare's edge ranges, as installed for nginx's real-IP support."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    nets: list[Network] = []
    for line in text.splitlines():
        parts = line.strip().rstrip(";").split()
        if len(parts) == 2 and parts[0] == "set_real_ip_from":
            try:
                nets.append(ipaddress.ip_network(parts[1]))
            except ValueError:
                continue
    return nets


def behind(addresses: set[str], ranges: Sequence[Network]) -> bool:
    """True when every address is a proxy edge (e.g. Cloudflare's orange cloud)."""
    if not addresses or not ranges:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if not any(ip in net for net in ranges):
            return False
    return True
