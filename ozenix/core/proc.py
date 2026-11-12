"""The only module allowed to start processes (enforced by tests/security).

Rules: argv lists only (never a shell), absolute executable paths, a scrubbed
environment, mandatory timeouts, captured output, and secrets passed by stdin
rather than argv.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ozenix.core.errors import OperationFailed, ValidationError

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


def pipeline(
    producer: Sequence[str],
    consumer: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    env: Mapping[str, str] | None = None,
    producer_env: Mapping[str, str] | None = None,
    check: bool = True,
) -> tuple[Result, Result]:
    """``producer | consumer`` without a shell; both exit codes are checked.

    Used to stream a database dump into ``restic backup --stdin`` without a
    temporary file. A producer that fails half-way (truncated dump) raises even
    when the consumer was happy with what it got; the caller then discards the
    consumer's result (e.g. forgets the snapshot).
    """
    first, second = _check_argv(producer), _check_argv(consumer)
    if timeout <= 0:
        raise ValidationError("timeout must be positive")
    errfile = tempfile.TemporaryFile()  # noqa: SIM115 - closed in finally
    try:
        prod = subprocess.Popen(  # noqa: S603 - argv validated above, never a shell
            first,
            stdout=subprocess.PIPE,
            stderr=errfile,
            stdin=subprocess.DEVNULL,
            env=safe_env(producer_env),
            cwd="/",
            close_fds=True,
        )
    except FileNotFoundError:
        errfile.close()
        raise OperationFailed(f"command not found: {first[0]}") from None
    try:
        cons = subprocess.Popen(  # noqa: S603 - argv validated above, never a shell
            second,
            stdin=prod.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=safe_env(env),
            cwd="/",
            close_fds=True,
            text=True,
        )
    except FileNotFoundError:
        prod.kill()
        prod.wait()
        errfile.close()
        raise OperationFailed(f"command not found: {second[0]}") from None
    if prod.stdout is not None:
        prod.stdout.close()  # the consumer owns the read end now (SIGPIPE reaches prod)
    try:
        out, err = cons.communicate(timeout=timeout)
        prod.wait(timeout=30)
        errfile.seek(0)
        prod_err = errfile.read(64 * 1024).decode(errors="replace")
    except subprocess.TimeoutExpired:
        for p in (prod, cons):
            p.kill()
            p.wait()
        raise OperationFailed(f"pipeline timed out after {timeout:g}s: {first[0]}") from None
    finally:
        errfile.close()
    results = (
        Result(first, prod.returncode, "", prod_err),
        Result(second, cons.returncode, out, err),
    )
    for result in results if check else ():
        if not result.ok:
            detail = result.stderr.strip().splitlines()
            raise OperationFailed(
                f"{os.path.basename(result.argv[0])} exited with status {result.returncode}: "
                + (detail[-1] if detail else "no output")
            )
    return results
