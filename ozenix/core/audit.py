"""Structured audit log for every privileged operation (architecture §5 rule 6).

Events go to an append-only JSON-lines file (``chattr +a`` is applied by the
installer) and to syslog/journald with identifier ``ozenix-audit``.
Secret-looking fields are redacted before anything is written.
"""

from __future__ import annotations

import json
import os
import re
import syslog
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_SECRET_KEY_RE = re.compile(r"(pass(word|wd)?|secret|token|key|credential|auth)", re.IGNORECASE)
_SECRET_FLAGS = frozenset({"--password", "--token", "--secret", "--api-token", "--key-stdin"})
REDACTED = "***"


def redact(value: Any) -> Any:
    """Recursively replace values of secret-looking keys."""
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if _SECRET_KEY_RE.search(str(k)) else redact(v)) for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


def redact_argv(argv: Sequence[str]) -> list[str]:
    out: list[str] = []
    hide_next = False
    for arg in argv:
        if hide_next:
            out.append(REDACTED)
            hide_next = False
            continue
        flag, sep, _ = arg.partition("=")
        if flag in _SECRET_FLAGS:
            if sep:
                out.append(f"{flag}={REDACTED}")
            else:
                out.append(arg)
                hide_next = True
            continue
        out.append(arg)
    return out


def actor() -> str:
    """The human behind the privileged call (sudo sets SUDO_USER)."""
    sudo_user = os.environ.get("SUDO_USER", "")
    if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", sudo_user):
        return sudo_user
    return f"uid:{os.getuid()}"


class AuditLog:
    def __init__(self, path: Path, *, use_syslog: bool = True) -> None:
        self.path = path
        self.use_syslog = use_syslog

    def record(
        self,
        event: str,
        *,
        argv: Sequence[str] = (),
        outcome: str,
        details: Mapping[str, Any] | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "id": operation_id or uuid.uuid4().hex,
            "event": event,
            "actor": actor(),
            "pid": os.getpid(),
            "argv": redact_argv(argv),
            "outcome": outcome,
            "details": redact(dict(details or {})),
        }
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        fd = os.open(
            self.path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o640,
        )
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        if self.use_syslog:
            syslog.openlog("ozenix-audit", 0, syslog.LOG_AUTHPRIV)
            priority = syslog.LOG_NOTICE if outcome == "success" else syslog.LOG_WARNING
            syslog.syslog(priority, line)
            syslog.closelog()
        return entry
