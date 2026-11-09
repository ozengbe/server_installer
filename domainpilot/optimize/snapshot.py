"""Snapshots of configuration files for byte-exact rollback.

Before any tuning change the current bytes of every file that may change are
copied into /var/lib/domainpilot/optimize/<id>/ (root-only). Rollback writes
those bytes back with the same mode and owner (or removes files that did not exist before).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domainpilot.core import fsutil
from domainpilot.core.errors import PreconditionFailed

KEEP = 30  # newest snapshots kept


@dataclass(frozen=True)
class Snapshot:
    id: str
    created: str
    kind: str
    note: str
    files: list[dict[str, Any]]


class SnapshotStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def take(self, kind: str, paths: list[Path], note: str = "") -> Snapshot:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        snap_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        directory = self.root / snap_id
        directory.mkdir(mode=0o700)
        files = []
        for index, path in enumerate(paths):
            entry: dict[str, Any] = {"path": str(path), "existed": path.exists()}
            if path.exists():
                data = fsutil.read_bytes_nofollow(path)
                blob = directory / f"{index}.orig"
                fsutil.create_exclusive(blob, data, mode=0o600)
                st = path.lstat()
                entry.update(
                    blob=blob.name,
                    sha256=hashlib.sha256(data).hexdigest(),
                    mode=st.st_mode & 0o7777,
                    uid=st.st_uid,
                    gid=st.st_gid,
                )
            files.append(entry)
        snap = Snapshot(snap_id, time.strftime("%Y-%m-%dT%H:%M:%S%z"), kind, note, files)
        fsutil.create_exclusive(
            directory / "manifest.json", json.dumps(snap.__dict__, indent=2), mode=0o600
        )
        self._prune()
        return snap

    def entries(self) -> list[Snapshot]:
        if not self.root.is_dir():
            return []
        snaps = []
        for manifest in sorted(self.root.glob("*/manifest.json"), reverse=True):
            data = json.loads(fsutil.read_text_nofollow(manifest))
            snaps.append(Snapshot(**data))
        return snaps

    def get(self, snap_id: str) -> Snapshot:
        for snap in self.entries():
            if snap.id == snap_id:
                return snap
        raise PreconditionFailed(f"no snapshot {snap_id!r}", hint="see: --history")

    def restore(self, snap: Snapshot) -> list[str]:
        """Write every file back exactly as it was. Returns the paths changed."""
        changed = []
        for entry in snap.files:
            path = Path(entry["path"])
            if not entry["existed"]:
                if path.exists():
                    path.unlink()
                    changed.append(str(path))
                continue
            data = fsutil.read_bytes_nofollow(self.root / snap.id / entry["blob"])
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise PreconditionFailed(f"snapshot {snap.id} is damaged ({path})")
            owner = {"uid": entry.get("uid"), "gid": entry.get("gid")}  # older manifests: None
            if fsutil.atomic_write(path, data, mode=entry["mode"], **owner):
                changed.append(str(path))
        return changed

    def _prune(self) -> None:
        import shutil

        for old in sorted(p for p in self.root.iterdir() if p.is_dir())[:-KEEP]:
            shutil.rmtree(old)
