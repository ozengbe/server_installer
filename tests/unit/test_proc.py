from __future__ import annotations

import pytest

from ozenix.core import proc
from ozenix.core.errors import OperationFailed, ValidationError


def test_runs_argv_literally_without_shell() -> None:
    payload = "$(id); `id` | rm -rf / && echo pwned"
    result = proc.run(["/bin/echo", payload])
    assert result.ok
    assert result.stdout == payload + "\n"


@pytest.mark.parametrize(
    "argv",
    [
        "echo hi",
        b"/bin/echo",
        [],
        ["echo", "hi"],
        ["./echo"],
        ["/bin/echo", "a\x00b"],
        ["/bin/echo", 5],
    ],
)
def test_rejects_unsafe_argv(argv: object) -> None:
    with pytest.raises(ValidationError):
        proc.run(argv)  # type: ignore[arg-type]


def test_rejects_huge_argument() -> None:
    with pytest.raises(ValidationError):
        proc.run(["/bin/echo", "x" * (64 * 1024 + 1)])


def test_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("SECRET_TOKEN", "hunter2")
    out = proc.run(["/usr/bin/env"], env={"DP_EXTRA": "1"}).stdout
    keys = {line.split("=", 1)[0] for line in out.splitlines()}
    assert keys == {"PATH", "LC_ALL", "LANG", "HOME", "DP_EXTRA"}
    assert "hunter2" not in out


def test_rejects_bad_env_names() -> None:
    with pytest.raises(ValidationError):
        proc.run(["/bin/true"], env={"BAD NAME": "x"})
    with pytest.raises(ValidationError):
        proc.run(["/bin/true"], env={"OK": "a\x00b"})


def test_stdin_is_passed() -> None:
    assert proc.run(["/bin/cat"], stdin="secret-via-stdin").stdout == "secret-via-stdin"


def test_nonzero_exit_raises_when_checked() -> None:
    with pytest.raises(OperationFailed, match="exited with status 1"):
        proc.run(["/bin/false"])
    assert proc.run(["/bin/false"], check=False).returncode == 1


def test_timeout() -> None:
    with pytest.raises(OperationFailed, match="timed out"):
        proc.run(["/bin/sleep", "5"], timeout=0.2)
    with pytest.raises(ValidationError):
        proc.run(["/bin/true"], timeout=0)


def test_missing_binary() -> None:
    with pytest.raises(OperationFailed, match="not found"):
        proc.run(["/nonexistent/binary"])
