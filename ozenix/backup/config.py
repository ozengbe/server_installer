"""Backup target configuration and keys.

* /etc/ozenix/backup.json (root 0600): repository base and retention.
* secrets (systemd-creds, see core.secrets), area "backup":
  - "master": 256-bit key. Every repository password is derived from it
    (HMAC-SHA256), so the master key alone (plus the bucket credentials)
    recovers every backup after total loss of this server. It is shown once
    at setup and must be stored offline: the encrypted copy here is bound to
    this host's key and is useless if the server is lost.
  - "s3": KEY=VALUE lines for the bucket (AWS_ACCESS_KEY_ID, ...).

Repositories: <base>/<tenant> for each site and <base>/system for the
server's own configuration. One key per repository means one tenant's
password opens nothing else, and a repository can be handed over or erased
on its own.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ozenix.core import fsutil
from ozenix.core.errors import PreconditionFailed, ValidationError
from ozenix.core.secrets import SecretStore

_LOCAL_RE = re.compile(r"(?:/[A-Za-z0-9._-]+)+")
_S3_RE = re.compile(
    r"s3:https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:/[A-Za-z0-9._-]+)*"
)
_REPO_NAME_RE = re.compile(r"t[0-9]{4}|system")
S3_KEYS = frozenset(
    {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION", "AWS_SESSION_TOKEN"}
)
_DERIVE_CONTEXT = b"ozenix-backup-v1:"


def validate_repository(value: str, *, tenants_root: Path = Path("/srv/tenants")) -> str:
    value = value.strip().rstrip("/")
    if _S3_RE.fullmatch(value):
        return value
    if _LOCAL_RE.fullmatch(value):
        parts = Path(value).parts
        if ".." in parts or "." in parts:
            raise ValidationError("the backup path may not contain '.' or '..'")
        if Path(value).is_relative_to(tenants_root):
            raise ValidationError("backups may not live inside the tenants' tree")
        return value
    raise ValidationError(
        "repository must be s3:https://<endpoint>/<bucket>[/<prefix>] or an absolute local path",
        hint="e.g. s3:https://s3.us-west-004.backblazeb2.com/my-bucket/server1",
    )


def parse_s3_env(text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in S3_KEYS:
            raise ValidationError(
                "credentials must be KEY=VALUE lines with keys from: " + ", ".join(sorted(S3_KEYS))
            )
        if not value or any(c.isspace() for c in value):
            raise ValidationError(f"{key} is empty or contains whitespace")
        env[key] = value
    if not {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} <= set(env):
        raise ValidationError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are both required")
    return env


@dataclass
class Retention:
    daily: int = 7
    weekly: int = 4
    monthly: int = 6

    def args(self) -> list[str]:
        return [
            f"--keep-daily={self.daily}",
            f"--keep-weekly={self.weekly}",
            f"--keep-monthly={self.monthly}",
        ]


@dataclass
class BackupConfig:
    repository: str
    retention: Retention = field(default_factory=Retention)
    configured_at: str = ""

    @property
    def is_s3(self) -> bool:
        return self.repository.startswith("s3:")

    def repo_url(self, name: str) -> str:
        if not _REPO_NAME_RE.fullmatch(name):
            raise ValidationError(f"invalid repository name {name!r}")
        return f"{self.repository}/{name}"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupConfig:
        return cls(
            repository=validate_repository(str(data["repository"])),
            retention=Retention(**data.get("retention", {})),
            configured_at=str(data.get("configured_at", "")),
        )


class BackupSettings:
    """Reads/writes backup.json and the backup secrets."""

    def __init__(self, etc: Path, secrets_store: SecretStore | None = None) -> None:
        self.file = etc / "backup.json"
        self.secrets = secrets_store or SecretStore(etc / "secrets" / "backup", "backup")

    def load(self) -> BackupConfig:
        if not self.file.exists():
            raise PreconditionFailed(
                "backups are not configured",
                hint="sudo site system backup setup --repository <s3:https://...|/path>",
            )
        return BackupConfig.from_dict(json.loads(fsutil.read_text_nofollow(self.file)))

    def configured(self) -> bool:
        return self.file.exists()

    def save(self, config: BackupConfig) -> None:
        fsutil.atomic_write(self.file, config.to_json(), mode=0o600)

    def ensure_master(self) -> str | None:
        """Create the master key if missing. Returns it only when newly created."""
        if self.secrets.exists("master"):
            return None
        key = secrets.token_hex(32)
        self.secrets.save("master", key)
        return key

    def import_master(self, key: str) -> None:
        key = key.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValidationError("a master key is 64 lowercase hex characters")
        self.secrets.save("master", key)

    # --- master-key rotation (docs/runbooks/key-rotation.md) ------------------
    # Secrets during a rotation:  "master-next" = new key not yet in use;
    # "master-prev" = old key, still accepted by the repositories until
    # `rotate-key --finish` removes it. Every step is idempotent, so an
    # interrupted rotation is completed by running the same command again.

    def rotation_state(self) -> str:
        if self.secrets.exists("master-next"):
            return "adding"
        if self.secrets.exists("master-prev"):
            return "promoted"
        return "idle"

    def begin_rotation(self) -> None:
        if not self.secrets.exists("master"):
            raise PreconditionFailed("there is no master key to rotate")
        if not self.secrets.exists("master-next"):
            self.secrets.save("master-next", secrets.token_hex(32))

    def promote_next(self) -> None:
        """New key becomes the master; the old one is kept as master-prev."""
        if not self.secrets.exists("master-prev"):
            self.secrets.save("master-prev", self.secrets.load("master").strip())
        self.secrets.save("master", self.secrets.load("master-next").strip())
        self.secrets.remove("master-next")

    def drop_previous(self) -> None:
        self.secrets.remove("master-prev")

    def repo_password(self, name: str, *, key: str = "master") -> str:
        master = bytes.fromhex(self.secrets.load(key).strip())
        return hmac.new(master, _DERIVE_CONTEXT + name.encode(), hashlib.sha256).hexdigest()

    def restic_env(
        self, config: BackupConfig, name: str, cache_dir: Path, *, key: str = "master"
    ) -> dict[str, str]:
        env = {
            "RESTIC_REPOSITORY": config.repo_url(name),
            "RESTIC_PASSWORD": self.repo_password(name, key=key),
            "RESTIC_CACHE_DIR": str(cache_dir),
            "RESTIC_PROGRESS_FPS": "0.0167",
        }
        if config.is_s3:
            env |= parse_s3_env(self.secrets.load("s3"))
        return env
