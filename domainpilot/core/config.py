"""Host configuration from /etc/domainpilot/domainpilot.toml (optional file).

Unknown sections or keys are errors: a typo must never silently fall back to
a default on a security-relevant setting. Secrets never live in this file.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domainpilot.core import validate
from domainpilot.core.errors import ValidationError
from domainpilot.core.fsutil import read_text_nofollow


@dataclass(frozen=True)
class Config:
    default_php_version: str = "8.3"
    default_site_type: str = "php"
    default_tier: str = "s"
    lock_timeout: float = 30.0


_SCHEMA: dict[str, dict[str, type]] = {
    "sites": {"default_php_version": str, "default_type": str, "default_tier": str},
    "cli": {"lock_timeout": float},
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
    )
