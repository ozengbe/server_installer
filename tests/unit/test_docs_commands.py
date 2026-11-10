"""Every `site ...` command shown in the operator documentation must parse.

Release gate: an administrator who is not the author installs and runs the
platform from the docs alone, so a documented command that the CLI rejects
is a release bug. Commands are parsed with the real grammar (no execution).
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from domainpilot.cli import commands
from domainpilot.cli.main import _leading_words, _Parser, split_globals

ROOT = Path(__file__).resolve().parents[2]
DOCS = sorted(
    [
        ROOT / "docs" / "install.md",
        ROOT / "docs" / "upgrade.md",
        ROOT / "docs" / "admin-guide.md",
        ROOT / "docs" / "commands.md",
        *(ROOT / "docs" / "runbooks").glob("*.md"),
    ]
)
PLACEHOLDERS = {
    "<domain>": "example.com",
    "<tNNNN>": "t0001",
    "<type>": "php",
}
_FENCE = re.compile(r"```(?:bash|sh)?\n(.*?)```", re.S)


def _documented() -> list[tuple[str, str]]:
    found = []
    for doc in DOCS:
        for block in _FENCE.findall(doc.read_text(encoding="utf-8")):
            for line in block.replace("\\\n", " ").splitlines():
                code = line.split(" #", 1)[0].strip()
                m = re.search(r"(?:^|\|\s*)(?:sudo\s+)?site\s+(.*)$", code)
                if not m or code.startswith("#"):
                    continue
                args = re.split(r"\s+(?:\d?>|\|)\s*", m.group(1))[0]  # drop redirects/pipes
                for key, value in PLACEHOLDERS.items():
                    args = args.replace(key, value)
                args = re.sub(r"<[^>]+>", "abcdef12", args)
                found.append((f"{doc.relative_to(ROOT)}: {code}", args))
    return found


DOCUMENTED = _documented()


def test_docs_contain_commands() -> None:
    assert len(DOCUMENTED) > 40
    assert {d.name for d in DOCS} >= {"incident.md", "restore.md", "rollback.md", "key-rotation.md"}


@pytest.mark.parametrize(("where", "args"), DOCUMENTED, ids=[d[0] for d in DOCUMENTED])
def test_documented_command_parses(where: str, args: str) -> None:
    flags = split_globals(shlex.split(args))
    rest = flags.rest
    assert rest, where
    if rest[0] in ("version", "help"):
        return
    head = rest[0]
    scope = head if head in ("list", "system") else "site"
    remaining = rest[1:]
    spec = commands.match(scope, _leading_words(remaining))
    assert spec is not None, f"unknown command in {where}"
    assert spec.handler is not None, f"documented but not implemented: {where}"
    parser = _Parser(prog="site", add_help=False)
    if spec.configure:
        spec.configure(parser)
    parser.parse_args(remaining[len(spec.words) :])
    if spec.kind == "D" and not flags.dry_run:
        assert flags.confirm, f"destructive command documented without --confirm: {where}"
