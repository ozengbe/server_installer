from __future__ import annotations

import random
import re

import pytest

from domainpilot.core import validate
from domainpilot.core.errors import ValidationError

# Payloads that must never be accepted as a domain (injection, traversal,
# confusion with flags, templates, SQL, control characters).
HOSTILE = [
    "",
    ".",
    "..",
    "../etc/passwd",
    "example.com/../../etc",
    "example.com;id",
    "example.com && reboot",
    "example.com|sh",
    "$(id).example.com",
    "`id`.example.com",
    "example.com\nserver_name evil",
    "example.com\r\n",
    "exa mple.com",
    "example.com\x00.evil",
    "-rf.example.com",
    "example-.com",
    "-example.com",
    "a..b.com",
    "example.com.",
    "*.example.com",
    "ex_ample.com",
    "example.c0m",
    "example.com'",
    'example.com"',
    "example.com{}",
    "${HOME}.example.com",
    "{{7*7}}.example.com",
    "1.2.3.4",
    "::1",
    "[::1]",
    "localhost",
    "foo.localhost",
    "printer.local",
    "corp.internal",
    "x.test",
    "x.invalid",
    "x.onion",
    "example",
    "a" * 64 + ".com",
    ".".join(["a" * 63] * 4) + ".com",
    "example.com\t",
    "‮example.com",
]

VALID = {
    "example.com": "example.com",
    "Example.COM": "example.com",
    "sub.example.co.uk": "sub.example.co.uk",
    "a-b.example.com": "a-b.example.com",
    "xn--bcher-kva.example": None,  # special-use .example
    "bücher.de": "xn--bcher-kva.de",
    "123.example.org": "123.example.org",
    "a.io": "a.io",
}


@pytest.mark.parametrize("value", HOSTILE)
def test_domain_rejects_hostile(value: str) -> None:
    with pytest.raises(ValidationError):
        validate.domain(value)


@pytest.mark.parametrize(("value", "expected"), VALID.items())
def test_domain_valid(value: str, expected: str | None) -> None:
    if expected is None:
        with pytest.raises(ValidationError):
            validate.domain(value)
    else:
        assert validate.domain(value) == expected


def test_domain_special_use_override() -> None:
    assert validate.domain("x.test", allow_special_use=True) == "x.test"


def test_domain_fuzz_output_is_always_safe() -> None:
    """Whatever is accepted must be a plain lowercase hostname, nothing else."""
    rng = random.Random(1337)
    alphabet = "abcXYZ019-._/\\;|&$`'\" \t\n\x00*{}()<>%~é漢"
    safe = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
    accepted = 0
    for _ in range(20000):
        candidate = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 24)))
        try:
            result = validate.domain(candidate)
        except ValidationError:
            continue
        accepted += 1
        assert safe.match(result), (candidate, result)
        assert ".." not in result and len(result) <= 253
    assert accepted > 0  # the fuzzer exercised the success path too


@pytest.mark.parametrize("value", ["t0001", "t123456"])
def test_tenant_id_valid(value: str) -> None:
    assert validate.tenant_id(value) == value


@pytest.mark.parametrize("value", ["t1", "t0001a", "T0001", "t0001\n", "../t0001", "", "t1234567"])
def test_tenant_id_invalid(value: str) -> None:
    with pytest.raises(ValidationError):
        validate.tenant_id(value)


@pytest.mark.parametrize("value", ["t0001", "t0001-deploy", "t000123-sftp"])
def test_username_valid(value: str) -> None:
    assert validate.username(value) == value


@pytest.mark.parametrize(
    "value", ["root", "t0001-", "t0001-DEPLOY", "t0001-toolongname", "t0001 x"]
)
def test_username_invalid(value: str) -> None:
    with pytest.raises(ValidationError):
        validate.username(value)


def test_username_suffix() -> None:
    assert validate.username_suffix("deploy") == "deploy"
    with pytest.raises(ValidationError):
        validate.username_suffix("x1")


def test_php_version() -> None:
    assert validate.php_version("8.3") == "8.3"
    for bad in ("8", "8.3.1", "7.4", "8.3;id", ""):
        with pytest.raises(ValidationError):
            validate.php_version(bad)


def test_db_name() -> None:
    assert validate.db_name("app_1") == "app_1"
    for bad in ("1app", "App", "a-b", "a;drop", "a" * 32):
        with pytest.raises(ValidationError):
            validate.db_name(bad)


@pytest.mark.parametrize(("value", "expected"), [(80, 80), ("443", 443), ("65535", 65535)])
def test_port_valid(value: int | str, expected: int) -> None:
    assert validate.port(value) == expected


@pytest.mark.parametrize("value", [0, "0", 65536, "-1", "80a", "08", "1e3", None, "", " 80x"])
def test_port_invalid(value: object) -> None:
    with pytest.raises(ValidationError):
        validate.port(value)  # type: ignore[arg-type]


def test_looks_like_domain() -> None:
    assert validate.looks_like_domain("example.com")
    assert not validate.looks_like_domain("system")
    assert not validate.looks_like_domain("status")
