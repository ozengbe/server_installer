"""Cloudflare API tokens, encrypted at rest with systemd-creds.

Each token lives in /etc/domainpilot/secrets/cloudflare/<label>.cred (root,
0600), encrypted with the host key (TPM2 when available) under the credential
name "cloudflare-<label>". Tokens travel only through stdin/stdout of
systemd-creds, never through argv or the environment.

For certbot's DNS-01 plugin the token must exist as a file while certbot
runs. It is written to /run (tmpfs, RAM only), 0600, and removed afterwards;
certbot's renewal pre/post hooks do the same for automatic renewals.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from domainpilot.core import fsutil, proc
from domainpilot.core.errors import OperationFailed, ValidationError

SYSTEMD_CREDS = "/usr/bin/systemd-creds"
STORE = Path("/etc/domainpilot/secrets/cloudflare")
RUNTIME = Path("/run/domainpilot/cloudflare")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?")

Runner = Callable[..., proc.Result]


def validate_label(label: str) -> str:
    if not _LABEL_RE.fullmatch(label):
        raise ValidationError("credential label must be lowercase letters, digits, dots, dashes")
    return label


class CredentialStore:
    def __init__(
        self, *, store: Path = STORE, runtime: Path = RUNTIME, run: Runner = proc.run
    ) -> None:
        self.store = store
        self.runtime = runtime
        self.run = run

    def path(self, label: str) -> Path:
        return self.store / f"{validate_label(label)}.cred"

    def labels(self) -> list[str]:
        if not self.store.is_dir():
            return []
        return sorted(p.stem for p in self.store.glob("*.cred") if _LABEL_RE.fullmatch(p.stem))

    def save(self, label: str, token: str) -> None:
        if not token or any(c.isspace() for c in token):
            raise ValidationError("the token is empty or contains whitespace")
        for directory in (self.store.parent, self.store):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        target = self.path(label)
        tmp = target.with_suffix(".cred.new")
        self.run(
            [SYSTEMD_CREDS, "encrypt", f"--name=cloudflare-{label}", "-", str(tmp)],
            stdin=token,
            timeout=30,
        )
        tmp.chmod(0o600)
        tmp.replace(target)

    def load(self, label: str) -> str:
        path = self.path(label)
        if not path.exists():
            raise OperationFailed(f"no Cloudflare credential named {label!r}")
        token = self.run(
            [SYSTEMD_CREDS, "decrypt", f"--name=cloudflare-{label}", str(path), "-"], timeout=30
        ).stdout
        if not token or any(c.isspace() for c in token):
            raise OperationFailed(f"Cloudflare credential {label!r} is empty or malformed")
        return token

    def remove(self, label: str) -> None:
        self.path(label).unlink(missing_ok=True)

    def certbot_ini(self, label: str) -> Path:
        """Write the RAM-only credentials file certbot's dns-cloudflare plugin reads."""
        self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime.chmod(0o700)
        ini = self.runtime / f"{validate_label(label)}.ini"
        ini.unlink(missing_ok=True)
        fsutil.create_exclusive(ini, f"dns_cloudflare_api_token = {self.load(label)}\n", mode=0o600)
        return ini

    def discard_ini(self, label: str) -> None:
        ini = self.runtime / f"{validate_label(label)}.ini"
        if ini.exists():
            # Overwrite before unlinking: tmpfs pages may otherwise linger.
            size = ini.stat().st_size
            with ini.open("r+b") as handle:
                handle.write(b"\0" * size)
                handle.flush()
                os.fsync(handle.fileno())
            ini.unlink()
