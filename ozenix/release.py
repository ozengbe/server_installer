"""Release identity and the upgrade policy (docs/upgrade.md).

The installer (installer/install.sh) calls this module *before* it changes
anything, with the release it is about to install:

    python3 -IB -c '...' plan <installed-file> [--allow-downgrade]
        -> prints one of: fresh | reinstall | upgrade | downgrade
           exit 3 when a downgrade is refused
    ... record <installed-file> <history-file> <commit>

The installed release is recorded in /var/lib/ozenix/release.json and
every install in release-history.jsonl next to it.

Versions are a strict subset of PEP 440 that sorts reliably without
third-party code: MAJOR.MINOR.PATCH with an optional rcN or .devN suffix.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ozenix import __version__
from ozenix.core import fsutil

_VERSION_RE = re.compile(
    r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})"
    r"(?:(rc)(0|[1-9][0-9]{0,3})|\.(dev)(0|[1-9][0-9]{0,3}))?"
)
_COMMIT_RE = re.compile(r"[0-9a-f]{7,40}|unknown")
RELEASE_FILE = Path("/var/lib/ozenix/release.json")
HISTORY_FILE = Path("/var/lib/ozenix/release-history.jsonl")
LEGACY_CLI = Path("/usr/local/bin/site")
EXIT_REFUSED = 3


class VersionError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Version:
    """Ordered as PEP 440: 1.0.0.dev1 < 1.0.0rc1 < 1.0.0."""

    major: int
    minor: int
    patch: int
    stage: int  # 0 = dev, 1 = rc, 2 = final
    serial: int

    @classmethod
    def parse(cls, text: str) -> Version:
        m = _VERSION_RE.fullmatch(text.strip())
        if not m:
            raise VersionError(f"not an ozenix version: {text!r}")
        major, minor, patch = (int(m.group(i)) for i in (1, 2, 3))
        if m.group(4):
            return cls(major, minor, patch, 1, int(m.group(5)))
        if m.group(6):
            return cls(major, minor, patch, 0, int(m.group(7)))
        return cls(major, minor, patch, 2, 0)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.stage == 0:
            return f"{base}.dev{self.serial}"
        if self.stage == 1:
            return f"{base}rc{self.serial}"
        return base


def plan(installed: str | None, new: str, *, allow_downgrade: bool = False) -> str:
    """What installing ``new`` over ``installed`` means."""
    target = Version.parse(new)
    if installed is None:
        return "fresh"
    current = Version.parse(installed)
    if target == current:
        return "reinstall"
    if target > current:
        return "upgrade"
    if not allow_downgrade:
        raise VersionError(
            f"refusing to downgrade {current} -> {target}: newer releases may have migrated "
            "the registry and configuration. Follow docs/runbooks/rollback.md "
            "(restore the pre-upgrade snapshot), then re-run with --allow-downgrade."
        )
    return "downgrade"


def installed_version(path: Path = RELEASE_FILE, *, legacy_cli: Path | None = None) -> str | None:
    """Version recorded by the last successful install, or None on a fresh host.

    Hosts installed before release tracking existed have the CLI but no record;
    they are treated as 0.0.0 so any release counts as an upgrade.
    """
    try:
        data = json.loads(fsutil.read_text_nofollow(path))
    except FileNotFoundError:
        return "0.0.0" if (legacy_cli or LEGACY_CLI).exists() else None
    except (OSError, ValueError) as exc:
        raise VersionError(f"cannot read {path}: {exc}") from None
    version = str(data.get("version", "")) if isinstance(data, dict) else ""
    Version.parse(version)
    return version


def record(path: Path, history: Path, *, commit: str, previous: str | None) -> dict[str, Any]:
    if not _COMMIT_RE.fullmatch(commit):
        raise VersionError(f"invalid commit id {commit!r}")
    entry = {
        "version": __version__,
        "commit": commit,
        "previous": previous,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fsutil.atomic_write(path, json.dumps(entry, indent=2, sort_keys=True) + "\n", mode=0o644)
    line = (json.dumps(entry, sort_keys=True) + "\n").encode()
    fd = os.open(history, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
    return entry


def describe_installed(path: Path = RELEASE_FILE) -> str:
    """One line for `site version`: what the installer last put on this host."""
    try:
        data = json.loads(fsutil.read_text_nofollow(path))
    except FileNotFoundError:
        return "installed release: not recorded (development install)"
    except PermissionError:
        return "installed release: run with sudo to see it"
    except (OSError, ValueError) as exc:
        return f"installed release: unreadable ({exc})"
    if not isinstance(data, dict):
        return "installed release: unreadable"
    return (
        f"installed release: {data.get('version', '?')} (commit {data.get('commit', '?')}, "
        f"{data.get('installed_at', '?')}; previous {data.get('previous') or 'none'})"
    )


def installer_main(argv: list[str]) -> int:
    """Entry point for installer/install.sh (not part of the `site` CLI)."""
    try:
        if argv[:1] == ["version"]:
            print(__version__)
            return 0
        if len(argv) >= 2 and argv[0] == "plan":
            current = installed_version(Path(argv[1]))
            action = plan(current, __version__, allow_downgrade="--allow-downgrade" in argv[2:])
            print(f"{action} {current or '-'} {__version__}")
            return 0
        if len(argv) == 4 and argv[0] == "record":
            path = Path(argv[1])
            previous = installed_version(path)
            record(path, Path(argv[2]), commit=argv[3], previous=previous)
            return 0
    except VersionError as exc:
        print(f"release: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    print(
        "usage: release (version | plan FILE [--allow-downgrade] | record FILE HISTORY COMMIT)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(installer_main(sys.argv[1:]))
