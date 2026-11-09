"""Strict validators for every externally supplied value.

Every value that reaches a file path, a template, a subprocess argument or SQL
must pass one of these first. Validators return the canonical form.
"""

from __future__ import annotations

import ipaddress
import re

from domainpilot.core.errors import ValidationError

# All patterns are applied with fullmatch(): "$" alone would accept a trailing newline.
# Reserved CLI words can never be domains (docs/cli-spec.md §1).
RESERVED_TARGETS = frozenset({"list", "system", "help", "version"})

_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_TENANT_RE = re.compile(r"^t\d{4,6}$")
_USERNAME_RE = re.compile(r"^t\d{4,6}(?:-[a-z]{1,8})?$")
_PHP_VERSIONS = frozenset({"8.1", "8.2", "8.3", "8.4", "8.5"})
_SUFFIX_RE = re.compile(r"^[a-z]{1,8}$")
_DB_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")

# Names that must never be hosted (local, test, documentation and special-use).
_SPECIAL_USE_SUFFIXES = (
    "localhost",
    "local",
    "localdomain",
    "internal",
    "invalid",
    "test",
    "example",
    "onion",
    "home.arpa",
    "arpa",
)

MAX_DOMAIN_LENGTH = 253


def domain(value: str, *, allow_special_use: bool = False) -> str:
    """Return the canonical (lowercase IDNA A-label) form of a hostname.

    Rejects IP literals, single-label names, wildcards, trailing dots, path
    separators, whitespace, control characters and special-use names.
    """
    if not isinstance(value, str) or not value:
        raise ValidationError("domain name is empty")
    if len(value) > 4 * MAX_DOMAIN_LENGTH:
        raise ValidationError("domain name is too long")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValidationError("domain name contains whitespace or control characters")
    if value.endswith("."):
        raise ValidationError("domain name must not end with a dot")
    if "*" in value:
        raise ValidationError("wildcard domains are not supported here")

    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValidationError("IP addresses are not domain names")

    try:
        ascii_name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError(f"invalid internationalised domain name: {exc}") from None

    if len(ascii_name) > MAX_DOMAIN_LENGTH:
        raise ValidationError("domain name exceeds 253 characters")
    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise ValidationError("domain name must contain at least one dot (e.g. example.com)")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise ValidationError(f"invalid domain label {label!r}")
    if not _TLD_RE.fullmatch(labels[-1]):
        raise ValidationError(f"invalid top-level domain {labels[-1]!r}")
    if not allow_special_use:
        for suffix in _SPECIAL_USE_SUFFIXES:
            if ascii_name == suffix or ascii_name.endswith("." + suffix):
                raise ValidationError(f"special-use domain .{suffix} cannot be hosted")
    if ascii_name in RESERVED_TARGETS:
        raise ValidationError("reserved word")
    return ascii_name


def tenant_id(value: str) -> str:
    if not isinstance(value, str) or not _TENANT_RE.fullmatch(value):
        raise ValidationError(f"invalid tenant id {value!r} (expected t0001 style)")
    return value


def username(value: str) -> str:
    if not isinstance(value, str) or not _USERNAME_RE.fullmatch(value):
        raise ValidationError(f"invalid DomainPilot username {value!r}")
    return value


def username_suffix(value: str) -> str:
    if not isinstance(value, str) or not _SUFFIX_RE.fullmatch(value):
        raise ValidationError("username suffix must be 1-8 lowercase letters")
    return value


def php_version(value: str) -> str:
    if value not in _PHP_VERSIONS:
        allowed = ", ".join(sorted(_PHP_VERSIONS))
        raise ValidationError(f"unsupported PHP version {value!r} (allowed: {allowed})")
    return value


def db_name(value: str) -> str:
    if not isinstance(value, str) or not _DB_NAME_RE.fullmatch(value):
        raise ValidationError("database name must match [a-z][a-z0-9_]{0,30}")
    return value


def port(value: int | str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"invalid port {value!r}") from None
    if not 1 <= number <= 65535 or str(number) != str(value).strip():
        raise ValidationError(f"invalid port {value!r}")
    return number


def looks_like_domain(value: str) -> bool:
    """Cheap syntactic check used by the CLI to tell domains from reserved words."""
    return "." in value and value not in RESERVED_TARGETS
