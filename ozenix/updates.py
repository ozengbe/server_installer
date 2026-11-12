"""Managed package updates (never reboots, never jumps major versions silently).

* --check: refresh package lists and classify pending upgrades.
* --security: run unattended-upgrades (security pocket only, same policy as
  the nightly run).
* default: `apt-get upgrade` (no new packages, no removals). A jump of the
  nginx.org stable *branch* (e.g. 1.30 -> 1.32) is held back unless
  --include-major is given. PHP and MariaDB majors cannot arrive through
  upgrade on Ubuntu (they are separate package names).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ozenix.core import proc

Runner = Callable[..., proc.Result]
APT_GET = "/usr/bin/apt-get"
APT = "/usr/bin/apt"
APT_MARK = "/usr/bin/apt-mark"
UNATTENDED = "/usr/bin/unattended-upgrade"
HISTORY = Path("/var/log/apt/history.log")
REBOOT = Path("/run/reboot-required")
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
MAJOR_GUARDED = ("nginx",)

_LINE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<suites>\S+)\s+(?P<new>\S+)\s+\S+\s+"
    r"\[upgradable from: (?P<old>[^\]]+)\]"
)


@dataclass(frozen=True)
class Pending:
    name: str
    old: str
    new: str
    security: bool
    major: bool


def _branch(version: str) -> str:
    """'1.30.6-1~noble' -> '1.30' (for packages that follow major.minor branches)."""
    core = version.split(":")[-1]
    return ".".join(core.split(".")[:2])


def parse_upgradable(text: str) -> list[Pending]:
    out = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        name = m["name"]
        major = name in MAJOR_GUARDED and _branch(m["old"]) != _branch(m["new"])
        out.append(Pending(name, m["old"], m["new"], "-security" in m["suites"], major))
    return out


def pending(run: Runner = proc.run, *, refresh: bool = True) -> list[Pending]:
    if refresh:
        run([APT_GET, "update", "-qq"], env=APT_ENV, timeout=600)
    result = run([APT, "list", "--upgradable"], env=APT_ENV, check=False, timeout=120)
    return parse_upgradable(result.stdout)


def apply(
    run: Runner = proc.run, *, security_only: bool, include_major: bool = False
) -> dict[str, Any]:
    before = pending(run)
    if security_only:
        run([UNATTENDED, "-v"], env=APT_ENV, timeout=3600)
        held: list[str] = []
    else:
        held = [] if include_major else sorted({p.name for p in before if p.major})
        if held:
            run([APT_MARK, "hold", *held], timeout=60)
        try:
            run(
                [
                    APT_GET,
                    "-y",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "upgrade",
                ],
                env=APT_ENV,
                timeout=3600,
            )
        finally:
            if held:
                run([APT_MARK, "unhold", *held], timeout=60, check=False)
    after = {p.name for p in pending(run, refresh=False)}
    return {
        "upgraded": sorted(p.name for p in before if p.name not in after),
        "held_major": held,
        "still_pending": sorted(after),
        "reboot_required": REBOOT.exists(),
    }


def history(path: Path = HISTORY, limit: int = 10) -> list[dict[str, Any]]:
    """Recent apt transactions from apt's own history log."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.strip().splitlines():
            key, sep, value = line.partition(": ")
            if sep:
                fields[key] = value
        if "Start-Date" not in fields:
            continue
        changed = fields.get("Upgrade", "") or fields.get("Install", "")
        entries.append(
            {
                "start": fields["Start-Date"],
                "end": fields.get("End-Date"),
                "command": fields.get("Commandline", fields.get("Requested-By", "")),
                "packages": sorted(
                    {m.group(1) for m in re.finditer(r"([^\s,:()]+):[a-z0-9]+ \(", changed)}
                ),
                "error": fields.get("Error"),
            }
        )
    return entries[-limit:][::-1]


def as_dicts(items: list[Pending]) -> list[dict[str, Any]]:
    return [asdict(p) for p in items]
