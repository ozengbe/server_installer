"""Host configuration from /etc/ozenix/ozenix.toml (optional file).

Unknown sections or keys are errors: a typo must never silently fall back to
a default on a security-relevant setting. Secrets never live in this file.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ozenix.core import validate
from ozenix.core.errors import ValidationError
from ozenix.core.fsutil import read_text_nofollow


@dataclass(frozen=True)
class Config:
    default_php_version: str = "8.3"
    default_site_type: str = "php"
    default_tier: str = "s"
    lock_timeout: float = 30.0
    # AutoSSL: request certificates automatically when a site is created.
    autossl: bool = True
    # Let's Encrypt staging CA (untrusted test certificates, generous limits).
    ssl_staging: bool = False
    ssl_email: str | None = None


_SCHEMA: dict[str, dict[str, type]] = {
    "sites": {"default_php_version": str, "default_type": str, "default_tier": str},
    "cli": {"lock_timeout": float},
    "ssl": {"autossl": bool, "staging": bool, "email": str},
}


def load(path: Path) -> Config:
    if not path.exists():
        return Config()
    try:
        raw: dict[str, Any] = tomllib.loads(read_text_nofollow(path, max_bytes=256 * 1024))
    except tomllib.TOMLDecodeError as exc:
        raise ValidationError(f"{path}: invalid TOML: {exc}") from None

    for section, values in raw.items():
        if section not in _SCHEMA or not isinstance(values, dict):
            raise ValidationError(f"{path}: unknown section [{section}]")
        for key, value in values.items():
            expected = _SCHEMA[section].get(key)
            if expected is None:
                raise ValidationError(f"{path}: unknown key {section}.{key}")
            if expected is float and isinstance(value, int) and not isinstance(value, bool):
                value = float(value)
            if not isinstance(value, expected):
                raise ValidationError(f"{path}: {section}.{key} must be {expected.__name__}")

    sites = raw.get("sites", {})
    cli = raw.get("cli", {})
    ssl = raw.get("ssl", {})
    site_type = sites.get("default_type", "php")
    if site_type not in ("php", "static", "proxy"):
        raise ValidationError(f"{path}: sites.default_type must be php, static or proxy")
    tier = sites.get("default_tier", "s")
    if tier not in ("s", "c"):
        raise ValidationError(f"{path}: sites.default_tier must be 's' or 'c'")
    timeout = float(cli.get("lock_timeout", 30.0))
    if not 1 <= timeout <= 3600:
        raise ValidationError(f"{path}: cli.lock_timeout must be between 1 and 3600")
    return Config(
        default_php_version=validate.php_version(sites.get("default_php_version", "8.3")),
        default_site_type=site_type,
        default_tier=tier,
        lock_timeout=timeout,
        autossl=ssl.get("autossl", True),
        ssl_staging=ssl.get("staging", False),
        ssl_email=_email(path, ssl.get("email")),
    )


# --- host facts written by the installer -------------------------------------

CACHE_ENGINES = {
    "valkey": "/usr/bin/valkey-server",
    "redis": "/usr/bin/redis-server",
}


@dataclass(frozen=True)
class HostFacts:
    """What the installer put on this host (/etc/ozenix/host.toml)."""

    release: str = "unknown"
    default_php_version: str = "8.3"
    php_versions: tuple[str, ...] = ("8.3",)
    cache_engine: str = "valkey"
    nginx_user: str = "nginx"
    # Node.js majors under /opt/ozenix/node (empty: no Node.js sites).
    node_versions: tuple[str, ...] = ()
    default_node_version: str = ""
    python_sites: bool = False
    # Intrusion prevention engine: "crowdsec" or "fail2ban".
    ids: str = "fail2ban"

    @property
    def cache_server(self) -> str:
        return CACHE_ENGINES[self.cache_engine]


_HOST_KEYS: dict[str, type] = {
    "release": str,
    "default_php_version": str,
    "php_versions": list,
    "cache_engine": str,
    "nginx_user": str,
    "node_versions": list,
    "default_node_version": str,
    "python_sites": bool,
    "ids": str,
}


def load_host(path: Path) -> HostFacts:
    """Read host facts. A missing file means the installer has not run yet."""
    if not path.exists():
        return HostFacts()
    try:
        raw: dict[str, Any] = tomllib.loads(read_text_nofollow(path, max_bytes=64 * 1024))
    except tomllib.TOMLDecodeError as exc:
        raise ValidationError(f"{path}: invalid TOML: {exc}") from None
    host = raw.get("host")
    if set(raw) != {"host"} or not isinstance(host, dict):
        raise ValidationError(f"{path}: expected a single [host] section")
    for key, value in host.items():
        expected = _HOST_KEYS.get(key)
        if expected is None:
            raise ValidationError(f"{path}: unknown key host.{key}")
        if not isinstance(value, expected):
            raise ValidationError(f"{path}: host.{key} must be {expected.__name__}")
    versions = tuple(validate.php_version(v) for v in host.get("php_versions", ["8.3"]))
    default = validate.php_version(host.get("default_php_version", versions[0]))
    if default not in versions:
        raise ValidationError(f"{path}: default PHP {default} is not installed")
    engine = host.get("cache_engine", "valkey")
    if engine not in CACHE_ENGINES:
        raise ValidationError(f"{path}: host.cache_engine must be valkey or redis")
    nginx_user = host.get("nginx_user", "nginx")
    if nginx_user not in ("nginx", "www-data"):
        raise ValidationError(f"{path}: host.nginx_user must be nginx or www-data")
    ids = host.get("ids", "fail2ban")
    if ids not in ("crowdsec", "fail2ban"):
        raise ValidationError(f"{path}: host.ids must be crowdsec or fail2ban")
    nodes = tuple(validate.node_version(v) for v in host.get("node_versions", []))
    default_node = host.get("default_node_version", nodes[0] if nodes else "")
    if nodes and default_node not in nodes:
        raise ValidationError(f"{path}: default Node.js {default_node} is not installed")
    return HostFacts(
        release=host.get("release", "unknown"),
        default_php_version=default,
        php_versions=versions,
        cache_engine=engine,
        nginx_user=nginx_user,
        node_versions=nodes,
        default_node_version=default_node if nodes else "",
        python_sites=bool(host.get("python_sites", False)),
        ids=ids,
    )


def _email(path: Path, value: str | None) -> str | None:
    if value is None:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}", value):
        raise ValidationError(f"{path}: ssl.email is not a valid address")
    return value
