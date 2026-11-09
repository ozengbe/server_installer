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

from domainpilot.core import proc
from domainpilot.core.errors import DPError

IP = "/usr/sbin/ip"

Runner = Callable[..., proc.Result]
Resolver = Callable[[str], set[str]]


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


def problems(names: Sequence[str], host_ips: set[str], resolver: Resolver = resolve) -> list[str]:
    """Human-readable reasons why HTTP-01 would fail; empty means eligible."""
    out: list[str] = []
    if not host_ips:
        return ["this server has no public IP address configured"]
    for name in names:
        addresses = resolver(name)
        if not addresses:
            out.append(f"{name} does not resolve")
            continue
        foreign = sorted(addresses - host_ips)
        if foreign:
            out.append(f"{name} points to {', '.join(foreign)}, not to this server")
    return out
