"""Thin restic wrapper (works with restic 0.16 on 24.04 and 0.18 on 26.04).

Credentials reach restic only through its environment (RESTIC_PASSWORD,
AWS_*), which only root can read; never through argv.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domainpilot.core import proc
from domainpilot.core.errors import OperationFailed, ValidationError

RESTIC = "/usr/bin/restic"
_ID_RE = re.compile(r"[0-9a-f]{8}|[0-9a-f]{64}")
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9:._-]{0,62}")

Runner = Callable[..., proc.Result]
Piper = Callable[..., tuple[proc.Result, proc.Result]]


def validate_snapshot_id(value: str) -> str:
    if not _ID_RE.fullmatch(value):
        raise ValidationError("a snapshot id is 8 or 64 lowercase hex characters")
    return value


@dataclass(frozen=True)
class Snapshot:
    id: str
    short_id: str
    time: str
    paths: list[str]
    tags: list[str]

    @property
    def kind(self) -> str:
        return "db" if "db" in self.tags else "files" if "files" in self.tags else "other"

    def tag_value(self, prefix: str) -> str | None:
        return next((t.split(":", 1)[1] for t in self.tags if t.startswith(prefix + ":")), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.short_id,
            "time": self.time,
            "kind": self.kind,
            "run": self.tag_value("run"),
            "database": self.tag_value("db"),
            "paths": self.paths,
            "tags": self.tags,
        }


def _snapshot_id_from_json(stdout: str) -> str:
    for line in reversed(stdout.splitlines()):
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("message_type") == "summary":
            return str(msg.get("snapshot_id", ""))
    raise OperationFailed("restic did not report a snapshot id")


class Restic:
    def __init__(
        self,
        env: Mapping[str, str],
        *,
        run: Runner = proc.run,
        pipe: Piper = proc.pipeline,
        hostname: str = "domainpilot",
    ) -> None:
        self.env = dict(env)
        self.run = run
        self.pipe = pipe
        self.hostname = hostname

    def _restic(self, *args: str, timeout: float = 3600, check: bool = True) -> proc.Result:
        return self.run([RESTIC, *args], env=self.env, timeout=timeout, check=check)

    def ensure_repository(self) -> bool:
        """Create the repository if needed. Returns True when it was created."""
        if self._restic("cat", "config", "--no-lock", timeout=120, check=False).ok:
            return False
        self._restic("init", timeout=300)
        return True

    @staticmethod
    def _tags(tags: list[str]) -> list[str]:
        for tag in tags:
            if not _TAG_RE.fullmatch(tag):
                raise ValidationError(f"invalid backup tag {tag!r}")
        return [f"--tag={t}" for t in tags]

    def backup_paths(
        self, paths: list[Path], tags: list[str], *, excludes: list[Path] | None = None
    ) -> str:
        args = [
            "backup",
            "--json",
            "--quiet",
            "--one-file-system",
            "--retry-lock=5m",
            f"--host={self.hostname}",
            *self._tags(tags),
            *[f"--exclude={p}" for p in excludes or []],
            "--",
            *[str(p) for p in paths],
        ]
        return _snapshot_id_from_json(self._restic(*args, timeout=6 * 3600).stdout)

    def backup_stream(self, producer: list[str], filename: str, tags: list[str]) -> str:
        """Stream a command's stdout (e.g. a DB dump) into a snapshot.

        A producer that fails leaves a truncated snapshot behind; it is forgotten
        again so a broken dump can never be mistaken for a good backup.
        """
        consumer = [
            RESTIC,
            "backup",
            "--json",
            "--quiet",
            "--retry-lock=5m",
            f"--host={self.hostname}",
            "--stdin",
            f"--stdin-filename={filename}",
            *self._tags(tags),
        ]
        prod, cons = self.pipe(producer, consumer, env=self.env, timeout=6 * 3600, check=False)
        snap = ""
        if cons.ok:
            snap = _snapshot_id_from_json(cons.stdout)
        if not prod.ok:
            if snap:
                self.forget_ids([snap])
            detail = (prod.stderr.strip().splitlines() or ["no output"])[-1]
            raise OperationFailed(f"{Path(producer[0]).name} failed: {detail}")
        if not cons.ok:
            detail = (cons.stderr.strip().splitlines() or ["no output"])[-1]
            raise OperationFailed(f"restic backup failed: {detail}")
        return snap

    def snapshots(self, tags: list[str] | None = None) -> list[Snapshot]:
        args = ["snapshots", "--json", "--no-lock"]
        if tags:
            args.append("--tag=" + ",".join(t for t in tags if _TAG_RE.fullmatch(t)))
        data = json.loads(self._restic(*args, timeout=600).stdout or "[]")
        snaps = [
            Snapshot(
                id=str(s["id"]),
                short_id=str(s.get("short_id", str(s["id"])[:8])),
                time=str(s["time"]),
                paths=[str(p) for p in s.get("paths") or []],
                tags=[str(t) for t in s.get("tags") or []],
            )
            for s in data or []
        ]
        return sorted(snaps, key=lambda s: s.time, reverse=True)

    def find(self, snap_id: str) -> Snapshot:
        snap_id = validate_snapshot_id(snap_id)
        for snap in self.snapshots():
            if snap.id.startswith(snap_id):
                return snap
        raise OperationFailed(f"no snapshot {snap_id}")

    def restore(self, snap: Snapshot, target: Path, *, include: str | None = None) -> None:
        extra = [f"--include={include}"] if include else []
        self._restic("restore", snap.id, f"--target={target}", "--verify", *extra, timeout=6 * 3600)

    def dump_into(self, snap: Snapshot, filename: str, consumer: list[str]) -> None:
        """`restic dump <snap> /<file> | consumer` (e.g. into mariadb)."""
        self.pipe(
            [RESTIC, "dump", "--no-lock", snap.id, "/" + filename],
            consumer,
            producer_env=self.env,
            timeout=6 * 3600,
        )

    def dump_tail(self, snap: Snapshot, filename: str) -> str:
        """Last line of a streamed file, without keeping the whole file anywhere."""
        _prod, cons = self.pipe(
            [RESTIC, "dump", "--no-lock", snap.id, "/" + filename],
            ["/usr/bin/tail", "-n", "1"],
            producer_env=self.env,
            timeout=6 * 3600,
        )
        return cons.stdout.strip()

    def forget_ids(self, ids: list[str]) -> None:
        if ids:
            self._restic("forget", "--retry-lock=5m", *ids, timeout=600, check=False)

    def apply_retention(self, keep: list[str]) -> None:
        self._restic("forget", "--retry-lock=5m", "--prune", *keep, timeout=6 * 3600)

    def check(self, read_data_subset: str | None = None) -> None:
        args = ["check", "--retry-lock=5m"]
        if read_data_subset:
            args.append(f"--read-data-subset={read_data_subset}")
        self._restic(*args, timeout=6 * 3600)

    # --- keys (master-key rotation) -------------------------------------------

    def probe(self) -> str:
        """'ok' if this password opens the repository, 'absent' if there is no
        repository, 'denied' if the password is wrong. Other errors raise."""
        r = self._restic("cat", "config", "--no-lock", timeout=120, check=False)
        if r.ok:
            return "ok"
        err = r.stderr.lower()
        if "wrong password" in err or "no key found" in err or r.returncode == 12:
            return "denied"
        if r.returncode == 10 or "does not exist" in err or "unable to open config" in err:
            return "absent"
        raise OperationFailed(f"restic could not open the repository: {r.stderr.strip()[-300:]}")

    def current_key_id(self) -> str:
        """Id of the key that this environment's password opens."""
        out = self._restic("key", "list", "--json", "--no-lock", timeout=120).stdout
        try:
            keys = json.loads(out)
        except ValueError:
            raise OperationFailed("restic key list returned no JSON") from None
        for key in keys if isinstance(keys, list) else []:
            if isinstance(key, dict) and key.get("current"):
                key_id = str(key.get("id", ""))
                if re.fullmatch(r"[0-9a-f]{8,64}", key_id):
                    return key_id
        raise OperationFailed("restic did not report the current key")

    def add_key(self, new_password_file: Path) -> None:
        self._restic(
            "key",
            "add",
            "--retry-lock=5m",
            f"--new-password-file={new_password_file}",
            "--host=domainpilot",
            "--user=rotate",
            timeout=300,
        )

    def remove_key(self, key_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{8,64}", key_id):
            raise ValidationError(f"invalid restic key id {key_id!r}")
        self._restic("key", "remove", "--retry-lock=5m", key_id, timeout=300)
