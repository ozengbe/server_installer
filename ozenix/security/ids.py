"""Intrusion prevention: who is blocked, and manual block / unblock.

One interface over the two engines the installer may set up (host.toml
``ids``): CrowdSec (``cscli``, decisions enforced by the nftables bouncer)
or fail2ban (``fail2ban-client``). Only validated IP addresses and ranges
reach either tool, always as separate argv items.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

from ozenix.core import proc
from ozenix.core.errors import OperationFailed, ValidationError

Runner = Callable[..., proc.Result]

CSCLI = "/usr/bin/cscli"
FAIL2BAN = "/usr/bin/fail2ban-client"
ENGINES = ("crowdsec", "fail2ban")
# fail2ban has no per-ban duration: manual bans go to the long-term jail.
FAIL2BAN_MANUAL_JAIL = "recidive"
_DURATION_RE = re.compile(r"[1-9][0-9]{0,3}[mhd]")
_REASON_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._,:/()-]{0,79}")  # never starts with "-"
_F2B_JAIL_RE = re.compile(r"\{'([A-Za-z0-9_.-]+)': \[([^\]]*)\]\}")


@dataclass(frozen=True)
class Block:
    target: str  # IP address or CIDR range
    reason: str  # scenario or jail
    origin: str  # crowdsec, cscli (manual), fail2ban
    duration: str  # time left, as the engine reports it ("" if unknown)


def parse_target(value: str) -> tuple[str, bool]:
    """An IP address or a CIDR range that is safe to block. Returns (text, is_range)."""
    value = value.strip()
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=True)
            addr = net.network_address
            is_range = net.num_addresses > 1
            text = str(net) if is_range else str(addr)
        else:
            addr = ipaddress.ip_address(value)
            is_range, text = False, str(addr)
    except ValueError:
        raise ValidationError(f"not an IP address or CIDR range: {value!r}") from None
    if addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast:
        raise ValidationError(f"refusing to block {text}: loopback/local/multicast address")
    if is_range and net.prefixlen < (16 if net.version == 4 else 32):
        raise ValidationError(f"refusing to block {text}: range too large")
    return text, is_range


def validate_duration(value: str) -> str:
    if not _DURATION_RE.fullmatch(value):
        raise ValidationError("duration must look like 30m, 12h or 7d")
    return value


def validate_reason(value: str) -> str:
    if not _REASON_RE.fullmatch(value):
        raise ValidationError(
            "reason: 1-80 letters, digits, spaces or . _ , : / ( ) -; no leading -"
        )
    return value


class Ids:
    def __init__(self, engine: str, *, run: Runner = proc.run) -> None:
        if engine not in ENGINES:
            raise ValidationError(f"unknown intrusion prevention engine {engine!r}")
        self.engine = engine
        self.run = run

    # --- read ---------------------------------------------------------------------

    def blocks(self) -> list[Block]:
        if self.engine == "crowdsec":
            out = self.run([CSCLI, "decisions", "list", "-o", "json"], timeout=60).stdout
            return parse_crowdsec(out)
        out = self.run([FAIL2BAN, "banned"], timeout=60).stdout
        return parse_fail2ban(out)

    # --- write --------------------------------------------------------------------

    def block(self, target: str, *, duration: str, reason: str) -> Block:
        text, is_range = parse_target(target)
        duration = validate_duration(duration)
        reason = validate_reason(reason)
        if self.engine == "crowdsec":
            self.run(
                [
                    CSCLI, "decisions", "add",
                    "--range" if is_range else "--ip", text,
                    "--duration", duration,
                    "--reason", reason,
                    "--type", "ban",
                ],
                timeout=60,
            )  # fmt: skip
            return Block(text, reason, "manual", duration)
        if is_range:
            raise ValidationError("fail2ban blocks single addresses only, not ranges")
        self.run([FAIL2BAN, "set", FAIL2BAN_MANUAL_JAIL, "banip", text], timeout=60)
        return Block(text, f"manual ({FAIL2BAN_MANUAL_JAIL} jail)", "manual", "1w")

    def unblock(self, target: str) -> int:
        """Lift every block on this address/range. Returns how many were removed."""
        text, is_range = parse_target(target)
        before = [b for b in self.blocks() if b.target == text]
        if not before:
            return 0
        if self.engine == "crowdsec":
            flag = "--range" if is_range else "--ip"
            self.run([CSCLI, "decisions", "delete", flag, text], timeout=60)
        else:
            self.run([FAIL2BAN, "unban", text], timeout=60)
        return len(before)


def parse_crowdsec(out: str) -> list[Block]:
    """`cscli decisions list -o json`: a list of alerts (or null when empty)."""
    out = out.strip()
    if out in ("", "null"):
        return []
    try:
        alerts = json.loads(out)
    except ValueError:
        raise OperationFailed("unexpected output from cscli decisions list") from None
    blocks: list[Block] = []
    for alert in alerts or []:
        for d in alert.get("decisions") or []:
            if d.get("type") != "ban":
                continue
            value = str(d.get("value", ""))
            try:
                target = str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
            if target.endswith(("/32", "/128")):
                target = target.rsplit("/", 1)[0]
            blocks.append(
                Block(
                    target,
                    str(d.get("scenario", "")),
                    str(d.get("origin", "")),
                    str(d.get("duration", "")),
                )
            )
    return blocks


def parse_fail2ban(out: str) -> list[Block]:
    """`fail2ban-client banned`: "[{'sshd': ['192.0.2.1']}, {'recidive': []}]"."""
    blocks: list[Block] = []
    for jail, ips in _F2B_JAIL_RE.findall(out):
        for raw in re.findall(r"'([^']+)'", ips):
            try:
                target = str(ipaddress.ip_address(raw))
            except ValueError:
                continue
            blocks.append(Block(target, jail, "fail2ban", ""))
    return blocks


def as_dicts(blocks: list[Block]) -> list[dict[str, str]]:
    return [asdict(b) for b in blocks]
