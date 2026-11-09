"""The only module allowed to start processes (enforced by tests/security).

Rules: argv lists only (never a shell), absolute executable paths, a scrubbed
environment, mandatory timeouts, captured output, and secrets passed by stdin
rather than argv.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from domainpilot.core.errors import OperationFailed, ValidationError

SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_TIMEOUT = 120.0
_MAX_ARG_LEN = 64 * 1024


@dataclass(frozen=True)
class Result:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _check_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, str | bytes) or not argv:
        raise ValidationError("argv must be a non-empty list of strings")
    args = tuple(argv)
    for arg in args:
        if not isinstance(arg, str):
            raise ValidationError("every argv element must be a string")
        if "\x00" in arg:
            raise ValidationError("NUL byte in process argument")
        if len(arg) > _MAX_ARG_LEN:
            raise ValidationError("process argument too long")
    if not os.path.isabs(args[0]):
        raise ValidationError(f"executable must be an absolute path, got {args[0]!r}")
    return args


def safe_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": SAFE_PATH, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "HOME": "/root"}
    if extra:
        for key, value in extra.items():
            if not key.isidentifier() or "\x00" in value:
                raise ValidationError(f"invalid environment variable {key!r}")
            env[key] = value
    return env


def run(
    argv: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    stdin: str | None = None,
    check: bool = True,
    env: Mapping[str, str] | None = None,
    cwd: str = "/",
) -> Result:
    """Run a command safely. Raises OperationFailed on non-zero exit if ``check``."""
    args = _check_argv(argv)
    if timeout <= 0:
        raise ValidationError("timeout must be positive")
    try:
        completed = subprocess.run(  # noqa: S603 - argv validated above, never a shell
            args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=safe_env(env),
            cwd=cwd,
            shell=False,
            close_fds=True,
            check=False,
        )
    except FileNotFoundError:
        raise OperationFailed(f"command not found: {args[0]}") from None
    except subprocess.TimeoutExpired:
        raise OperationFailed(f"command timed out after {timeout:g}s: {args[0]}") from None

    result = Result(args, completed.returncode, completed.stdout, completed.stderr)
    if check and not result.ok:
        detail = (result.stderr or result.stdout).strip().splitlines()
        tail = detail[-1] if detail else "no output"
        raise OperationFailed(
            f"{os.path.basename(args[0])} exited with status {result.returncode}: {tail}"
        )
    return result
