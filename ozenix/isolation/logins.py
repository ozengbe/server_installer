"""Limits for a site's login user (the SSH/SFTP user with a shell).

PHP and apps run inside the site's own sandboxed services; an SSH session
runs in systemd's user-<uid>.slice instead. So that a site user cannot use
more of the server than its site may, or leave work running behind:

* user-<uid>.slice gets the site's own CPU, memory and process limits;
* the user is listed in /etc/cron.deny and /etc/at.deny (no scheduled jobs:
  the site's scheduler/apps are the supported way, inside the sandbox);
* when its last key is revoked or the site is deleted, its sessions and
  processes are ended.

(The firewall applies the site egress policy to uids 30000-39999 as well.)
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ozenix.core import fsutil, proc, validate
from ozenix.core.paths import Paths
from ozenix.isolation.limits import TenantLimits

LOGINCTL = "/usr/bin/loginctl"
PKILL = "/usr/bin/pkill"
SYSTEMCTL = "/usr/bin/systemctl"
DENY_FILES = ("cron.deny", "at.deny")

Runner = Callable[..., proc.Result]


def slice_dropin(paths: Paths, uid: int) -> Path:
    return paths.systemd / f"user-{uid}.slice.d" / "50-ozenix.conf"


def apply(paths: Paths, user: str, uid: int, limits: TenantLimits, run: Runner) -> None:
    """Idempotent: deny scheduling and cap the user's sessions."""
    user = validate.site_user_or_legacy(user)
    for name in DENY_FILES:
        _edit_deny(paths, name, user, add=True)
    dropin = slice_dropin(paths, uid)
    fsutil.ensure_dir(dropin.parent, mode=0o755)
    fsutil.atomic_write(
        dropin,
        "# Managed by ozenix: limits of a site user's SSH/SFTP sessions (= the site's).\n"
        "[Slice]\n"
        f"CPUQuota={limits.cpu_quota_percent}%\n"
        f"MemoryHigh={limits.memory_high_mb}M\n"
        f"MemoryMax={limits.memory_max_mb}M\n"
        f"MemorySwapMax={limits.swap_max_mb}M\n"
        f"TasksMax={limits.tasks_max}\n",
        mode=0o644,
    )
    run([SYSTEMCTL, "daemon-reload"], timeout=60)


def remove(paths: Paths, user: str, uid: int, run: Runner) -> None:
    user = validate.site_user_or_legacy(user)
    for name in DENY_FILES:
        _edit_deny(paths, name, user, add=False)
    dropin = slice_dropin(paths, uid)
    dropin.unlink(missing_ok=True)
    if dropin.parent.is_dir() and not any(dropin.parent.iterdir()):
        dropin.parent.rmdir()
    run([SYSTEMCTL, "daemon-reload"], timeout=60, check=False)


def end_sessions(user: str, run: Runner) -> None:
    """Log the user out everywhere and stop everything it still runs."""
    user = validate.site_user_or_legacy(user)
    run([LOGINCTL, "terminate-user", user], check=False, timeout=30)
    run([PKILL, "-KILL", "-u", user], check=False, timeout=30)


def _edit_deny(paths: Paths, name: str, user: str, *, add: bool) -> None:
    path = paths.system_etc / name
    lines = fsutil.read_text_nofollow(path).splitlines() if path.exists() else []
    present = user in lines
    if add and not present:
        lines.append(user)
    elif not add and present:
        lines = [ln for ln in lines if ln != user]
    else:
        return
    fsutil.atomic_write(path, "".join(f"{ln}\n" for ln in lines), mode=0o640)
