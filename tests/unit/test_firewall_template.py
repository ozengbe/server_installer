"""TH12 (direct-to-origin bypass of Cloudflare): render the real nftables template.

With the origin lock on, ports 80/443 must accept only Cloudflare's ranges and
there must be no unrestricted rule for them; with it off, they are public.
Jinja2 comes with ansible-core, which the checks and CI install.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

jinja2 = pytest.importorskip("jinja2")

TEMPLATE = Path(__file__).resolve().parents[2] / "ansible/roles/firewall/templates/ozenix.nft.j2"


def render(**overrides: Any) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["bool"] = lambda v: str(v).lower() in ("1", "true", "yes", "on")
    variables = {
        "dp_cloudflare_origin_lock": False,
        "dp_cloudflare_v4": ["173.245.48.0/20", "104.16.0.0/13"],
        "dp_cloudflare_v6": ["2400:cb00::/32"],
        "dp_firewall_public_tcp": [22, 80, 443],
        "dp_firewall_public_udp": [],
        "dp_ssh_allow_v4": [],
        "dp_ssh_allow_v6": [],
        "dp_wireguard_port": 0,
    } | overrides
    text: str = env.from_string(TEMPLATE.read_text(encoding="utf-8")).render(**variables)
    return text


def web_rules(text: str) -> list[str]:
    """Inbound rules for ports 80/443: the input chain only (tenant egress may use 443)."""
    chain = text.split("chain input {", 1)[1].split("chain forward {", 1)[0]
    return [ln.strip() for ln in chain.splitlines() if re.search(r"dport \{[^}]*\b(80|443)\b", ln)]


def test_origin_lock_allows_web_ports_from_cloudflare_only() -> None:
    text = render(dp_cloudflare_origin_lock=True)
    rules = web_rules(text)
    assert rules, text
    assert all(r.startswith(("ip saddr @cloudflare_v4", "ip6 saddr @cloudflare_v6")) for r in rules)
    assert "173.245.48.0/20" in text and "2400:cb00::/32" in text
    assert re.search(r"tcp dport \{ 22 \} accept", text)  # SSH stays reachable


def test_without_origin_lock_web_ports_are_public() -> None:
    text = render()
    assert any(r.startswith("tcp dport { 22, 80, 443 }") for r in web_rules(text))
    assert "@cloudflare_v4" not in text
    assert re.search(r"policy drop", text)  # default deny either way
