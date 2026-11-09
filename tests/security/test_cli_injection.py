"""Negative tests: hostile input on the command line must be rejected early
and must never create files, directories or state."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import RunCli

from domainpilot.core.errors import ExitCode

HOSTILE_TARGETS = [
    "example.com;id",
    "example.com && touch /tmp/pwned",
    "$(touch /tmp/pwned).example.com",
    "`id`.example.com",
    "../../etc/passwd",
    "example.com/../../root",
    "example.com\nserver_name evil.com",
    "example.com\x00.evil",
    "{{7*7}}.example.com",
    "-rf.example.com",
    "localhost.localdomain",
    "127.0.0.1",
    "[::1]",
    "x" * 300 + ".com",
]


def _snapshot(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


@pytest.mark.parametrize("target", HOSTILE_TARGETS)
@pytest.mark.parametrize("verb", [["status"], ["create"], ["delete", "--purge"]])
def test_hostile_targets_rejected_without_side_effects(
    run_cli: RunCli, tmp_path: Path, target: str, verb: list[str]
) -> None:
    before = _snapshot(tmp_path)
    r = run_cli(target, *verb)
    assert r.code in (ExitCode.USAGE, ExitCode.VALIDATION), (target, r.code, r.err)
    assert _snapshot(tmp_path) == before
    assert not Path("/tmp/pwned").exists()


@pytest.mark.parametrize("value", ["8.3;id", "../8.3", "$(id)"])
def test_hostile_option_values_not_accepted_as_versions(run_cli: RunCli, value: str) -> None:
    # `php <version>` is not implemented yet, but must never succeed with junk.
    assert run_cli("example.com", "php", value).code != 0


def test_confirm_value_must_match_exactly(run_cli: RunCli) -> None:
    # A confirm value differing only in case/whitespace is not a confirmation.
    for value in ("EXAMPLE.COM", "example.com ", " example.com"):
        r = run_cli("example.com", "delete", "--confirm", value)
        assert r.code != 0
