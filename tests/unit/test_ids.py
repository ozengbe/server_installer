"""Intrusion prevention (CrowdSec or fail2ban): parsing, validation, argv."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ozenix.core import proc
from ozenix.core.config import load_host
from ozenix.core.errors import ValidationError
from ozenix.core.sysinfo import core_services
from ozenix.monitor.monitor import watched_units
from ozenix.security import ids

CROWDSEC_LIST = json.dumps(
    [
        {
            "id": 1,
            "decisions": [
                {
                    "value": "192.0.2.10",
                    "type": "ban",
                    "scenario": "crowdsecurity/ssh-bf",
                    "origin": "crowdsec",
                    "duration": "3h59m",
                    "scope": "Ip",
                },
                {"value": "192.0.2.11", "type": "captcha", "scenario": "x", "origin": "crowdsec"},
            ],
        },
        {
            "id": 2,
            "decisions": [
                {
                    "value": "198.51.100.0/24",
                    "type": "ban",
                    "scenario": "manual block",
                    "origin": "cscli",
                    "duration": "23h",
                    "scope": "Range",
                },
                {"value": "not-an-ip", "type": "ban"},
            ],
        },
    ]
)
F2B_BANNED = (
    "[{'sshd': ['192.0.2.10', '2001:db8::5']}, {'nginx-limit-req': []}, "
    "{'recidive': ['203.0.113.7']}]"
)


class FakeRun:
    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kw: Any) -> proc.Result:
        self.calls.append(list(argv))
        key = " ".join(argv[1:3])
        return proc.Result(tuple(argv), 0, self.outputs.get(key, ""), "")


def test_parse_crowdsec_keeps_bans_only() -> None:
    blocks = ids.parse_crowdsec(CROWDSEC_LIST)
    assert [(b.target, b.reason, b.origin) for b in blocks] == [
        ("192.0.2.10", "crowdsecurity/ssh-bf", "crowdsec"),
        ("198.51.100.0/24", "manual block", "cscli"),
    ]


@pytest.mark.parametrize("out", ["", "null", "null\n"])
def test_parse_crowdsec_empty(out: str) -> None:
    assert ids.parse_crowdsec(out) == []


def test_parse_fail2ban() -> None:
    blocks = ids.parse_fail2ban(F2B_BANNED)
    assert [(b.target, b.reason) for b in blocks] == [
        ("192.0.2.10", "sshd"),
        ("2001:db8::5", "sshd"),
        ("203.0.113.7", "recidive"),
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.0.2.10", ("192.0.2.10", False)),
        (" 2001:db8::1 ", ("2001:db8::1", False)),
        ("198.51.100.0/24", ("198.51.100.0/24", True)),
        ("198.51.100.9/32", ("198.51.100.9", False)),
    ],
)
def test_parse_target_ok(value: str, expected: tuple[str, bool]) -> None:
    assert ids.parse_target(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "::1",
        "0.0.0.0",  # noqa: S104 - a value under test, nothing binds
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "10.0.0.0/8",  # far too large
        "198.51.100.1/24",  # host bits set
        "192.0.2.10; rm -rf /",
        "--help",
        "",
    ],
)
def test_parse_target_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        ids.parse_target(value)


@pytest.mark.parametrize("value", ["0h", "24", "1y", "10000d", "1h;x", ""])
def test_bad_duration(value: str) -> None:
    with pytest.raises(ValidationError):
        ids.validate_duration(value)


@pytest.mark.parametrize("value", ["", "x" * 81, "a\nb", "$(id)", "--reason"])
def test_bad_reason(value: str) -> None:
    with pytest.raises(ValidationError):
        ids.validate_reason(value)


def test_crowdsec_block_argv() -> None:
    run = FakeRun({})
    block = ids.Ids("crowdsec", run=run).block("198.51.100.0/24", duration="7d", reason="scanner")
    assert run.calls == [
        [
            ids.CSCLI, "decisions", "add", "--range", "198.51.100.0/24",
            "--duration", "7d", "--reason", "scanner", "--type", "ban",
        ]
    ]  # fmt: skip
    assert block.target == "198.51.100.0/24"


def test_fail2ban_block_uses_long_term_jail_and_refuses_ranges() -> None:
    run = FakeRun({})
    engine = ids.Ids("fail2ban", run=run)
    engine.block("192.0.2.50", duration="24h", reason="manual block")
    assert run.calls == [[ids.FAIL2BAN, "set", "recidive", "banip", "192.0.2.50"]]
    with pytest.raises(ValidationError):
        engine.block("198.51.100.0/24", duration="24h", reason="manual block")


def test_unblock_only_when_blocked() -> None:
    run = FakeRun({"decisions list": CROWDSEC_LIST})
    engine = ids.Ids("crowdsec", run=run)
    assert engine.unblock("203.0.113.99") == 0
    assert all(c[1:3] == ["decisions", "list"] for c in run.calls)
    assert engine.unblock("192.0.2.10") == 1
    assert run.calls[-1] == [ids.CSCLI, "decisions", "delete", "--ip", "192.0.2.10"]


def test_fail2ban_unblock() -> None:
    run = FakeRun({"banned": F2B_BANNED})
    assert ids.Ids("fail2ban", run=run).unblock("192.0.2.10") == 1
    assert run.calls[-1] == [ids.FAIL2BAN, "unban", "192.0.2.10"]


def test_unknown_engine() -> None:
    with pytest.raises(ValidationError):
        ids.Ids("snort")


def test_service_lists_follow_the_engine() -> None:
    assert "fail2ban" in core_services("fail2ban")
    cs = core_services("crowdsec")
    assert "crowdsec" in cs and "crowdsec-firewall-bouncer" in cs and "fail2ban" not in cs
    assert "crowdsec-firewall-bouncer.service" in watched_units("crowdsec")
    assert "fail2ban.service" in watched_units("fail2ban")


def test_host_toml_ids(tmp_path: Any) -> None:
    path = tmp_path / "host.toml"
    path.write_text('[host]\nids = "crowdsec"\n')
    assert load_host(path).ids == "crowdsec"
    path.write_text('[host]\nids = "snort"\n')
    with pytest.raises(ValidationError):
        load_host(path)
    path.write_text("[host]\n")
    assert load_host(path).ids == "fail2ban"
