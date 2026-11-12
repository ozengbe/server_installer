"""SSH/SFTP access for a site's user (architecture §4.3).

* Account: the site user chosen at `site <domain> create --user NAME` (older
  sites: `<tid>-deploy`). It owns app/ and logs in with SSH keys only: SFTP
  and a shell (git, composer, wp-cli) as itself, in its own site. Each key is
  labelled, so several people/machines can be added and revoked one by one.
* Keys live in /etc/ssh/authorized_keys.d/<user> (root-owned, 0644): the
  site user cannot add keys itself. Every line carries `restrict,pty` (a
  terminal, but no port/agent/X11 forwarding), on top of sshd's
  `Match Group dp-sftp` block (keys only, no forwarding).
* Membership of the dp-sftp group is granted with the first key and removed
  with the last.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ozenix.core import fsutil, proc
from ozenix.core.audit import AuditLog
from ozenix.core.errors import PreconditionFailed, ValidationError
from ozenix.isolation import logins
from ozenix.isolation.render import deploy_user_of

SSH_KEYGEN = "/usr/bin/ssh-keygen"
GPASSWD = "/usr/bin/gpasswd"
KEYS_DIR = Path("/etc/ssh/authorized_keys.d")
GROUP = "dp-sftp"
MIN_RSA_BITS = 3072

_KEY_RE = re.compile(
    r"(?P<type>ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) (?P<blob>[A-Za-z0-9+/]{16,8192}={0,3})"
    r"(?: [ -~]{0,200})?"
)
_LABEL_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_LINE_RE = re.compile(r"restrict(?:,pty)? (?P<type>\S+) (?P<blob>\S+) dp:(?P<label>[a-z0-9-]+)")

Runner = Callable[..., proc.Result]


def validate_label(label: str) -> str:
    if not _LABEL_RE.fullmatch(label):
        raise ValidationError("an SFTP account name is 1-32 lowercase letters, digits or dashes")
    return label


def parse_public_key(text: str) -> tuple[str, str]:
    """Exactly one OpenSSH public key line (no options). Returns (type, blob)."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    if len(lines) != 1:
        raise ValidationError("give exactly one public key (the contents of a .pub file)")
    m = _KEY_RE.fullmatch(lines[0])
    if not m:
        raise ValidationError(
            "not an accepted public key; use ssh-ed25519 (recommended), ECDSA or RSA >= 3072 bits",
            hint="create one with: ssh-keygen -t ed25519",
        )
    return m["type"], m["blob"]


class SftpManager:
    def __init__(
        self,
        *,
        audit: AuditLog,
        argv: list[str],
        run: Runner = proc.run,
        keys_dir: Path = KEYS_DIR,
        hostname: str = "this-server",
    ) -> None:
        self.audit = audit
        self.argv = argv
        self.run = run
        self.keys_dir = keys_dir
        self.hostname = hostname

    @staticmethod
    def user(tenant: str) -> str:
        return deploy_user_of(tenant)

    def _file(self, tenant: str) -> Path:
        return self.keys_dir / self.user(tenant)

    def _entries(self, tenant: str) -> list[dict[str, str]]:
        path = self._file(tenant)
        if not path.exists():
            return []
        entries = []
        for line in fsutil.read_text_nofollow(path).splitlines():
            m = _LINE_RE.fullmatch(line.strip())
            if m:
                entries.append({"label": m["label"], "type": m["type"], "blob": m["blob"]})
        return entries

    def _write(self, tenant: str, entries: list[dict[str, str]]) -> None:
        path = self._file(tenant)
        if not entries:
            path.unlink(missing_ok=True)
            return
        text = "".join(f"restrict,pty {e['type']} {e['blob']} dp:{e['label']}\n" for e in entries)
        fsutil.atomic_write(path, text, mode=0o644)

    def _fingerprint(self, key_type: str, blob: str) -> tuple[str, int]:
        out = self.run(
            [SSH_KEYGEN, "-l", "-E", "sha256", "-f", "/dev/stdin"],
            stdin=f"{key_type} {blob}\n",
            timeout=30,
        ).stdout.split()
        if len(out) < 2 or not out[0].isdigit() or not out[1].startswith("SHA256:"):
            raise ValidationError("ssh-keygen could not read this public key")
        return out[1], int(out[0])

    def create(self, tenant: str, key_text: str, label: str) -> dict[str, Any]:
        label = validate_label(label)
        key_type, blob = parse_public_key(key_text)
        fingerprint, bits = self._fingerprint(key_type, blob)
        if key_type == "ssh-rsa" and bits < MIN_RSA_BITS:
            raise ValidationError(f"RSA keys must have at least {MIN_RSA_BITS} bits (got {bits})")
        entries = self._entries(tenant)
        if any(e["label"] == label for e in entries):
            raise PreconditionFailed(f"an SFTP account named {label!r} already exists")
        if any(e["blob"] == blob for e in entries):
            raise PreconditionFailed("this key is already authorised for the site")
        self._write(tenant, [*entries, {"label": label, "type": key_type, "blob": blob}])
        self.run([GPASSWD, "-a", self.user(tenant), GROUP], timeout=30)
        self.audit.record(
            "sftp.create",
            argv=self.argv,
            outcome="success",
            details={"tenant": tenant, "label": label, "fingerprint": fingerprint},
        )
        return {
            "tenant": tenant,
            "account": label,
            "username": self.user(tenant),
            "fingerprint": fingerprint,
            "connect": f"ssh {self.user(tenant)}@{self.hostname}",
            "directory": "~/app/public is the web root; ~/data holds uploads",
        }

    def list(self, tenant: str) -> list[dict[str, str]]:
        out = []
        for entry in self._entries(tenant):
            fingerprint, _bits = self._fingerprint(entry["type"], entry["blob"])
            out.append(
                {
                    "account": entry["label"],
                    "username": self.user(tenant),
                    "type": entry["type"],
                    "fingerprint": fingerprint,
                }
            )
        return out

    def revoke(self, tenant: str, label: str) -> dict[str, Any]:
        label = validate_label(label)
        entries = self._entries(tenant)
        remaining = [e for e in entries if e["label"] != label]
        if len(remaining) == len(entries):
            raise PreconditionFailed(f"no SFTP account named {label!r}")
        self._write(tenant, remaining)
        if not remaining:
            self.run([GPASSWD, "-d", self.user(tenant), GROUP], timeout=30, check=False)
            logins.end_sessions(self.user(tenant), self.run)  # no key left: log out now
        self.audit.record(
            "sftp.revoke",
            argv=self.argv,
            outcome="success",
            details={"tenant": tenant, "label": label, "remaining": len(remaining)},
        )
        return {"tenant": tenant, "revoked": label, "remaining": len(remaining)}

    def revoke_all(self, tenant: str) -> bool:
        """Used when a site is archived or erased."""
        had = bool(self._entries(tenant)) or self._file(tenant).exists()
        self._file(tenant).unlink(missing_ok=True)
        if had:
            self.run([GPASSWD, "-d", self.user(tenant), GROUP], timeout=30, check=False)
            logins.end_sessions(self.user(tenant), self.run)
        return had
