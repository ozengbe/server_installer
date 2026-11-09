"""Small secrets encrypted at rest with systemd-creds (host key, TPM2 when present).

Each secret is one file, root 0600, below /etc/domainpilot/secrets/<area>/.
Values travel only over stdin/stdout of systemd-creds, never argv or the
environment of other processes.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from domainpilot.core import proc
from domainpilot.core.errors import OperationFailed, ValidationError

SYSTEMD_CREDS = "/usr/bin/systemd-creds"
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")

Runner = Callable[..., proc.Result]


class SecretStore:
    def __init__(self, directory: Path, area: str, *, run: Runner = proc.run) -> None:
        if not _NAME_RE.fullmatch(area):
            raise ValidationError(f"invalid secret area {area!r}")
        self.directory = directory
        self.area = area
        self.run = run

    def _path(self, name: str) -> Path:
        if not _NAME_RE.fullmatch(name):
            raise ValidationError(f"invalid secret name {name!r}")
        return self.directory / f"{name}.cred"

    def exists(self, name: str) -> bool:
        return self._path(name).exists()

    def save(self, name: str, value: str) -> None:
        if not value:
            raise ValidationError("refusing to store an empty secret")
        for directory in (self.directory.parent, self.directory):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        target = self._path(name)
        tmp = target.with_suffix(".cred.new")
        self.run(
            [SYSTEMD_CREDS, "encrypt", f"--name={self.area}-{name}", "-", str(tmp)],
            stdin=value,
            timeout=30,
        )
        tmp.chmod(0o600)
        tmp.replace(target)

    def load(self, name: str) -> str:
        path = self._path(name)
        if not path.exists():
            raise OperationFailed(f"secret {self.area}/{name} is not configured")
        if path.stat().st_mode & 0o077:  # self-heal: only root may read even ciphertext
            path.chmod(0o600)
        value = self.run(
            [SYSTEMD_CREDS, "decrypt", f"--name={self.area}-{name}", str(path), "-"], timeout=30
        ).stdout
        if not value:
            raise OperationFailed(f"secret {self.area}/{name} is empty")
        return value

    def remove(self, name: str) -> bool:
        path = self._path(name)
        if path.exists():
            path.unlink()
            return True
        return False
