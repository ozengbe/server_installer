"""Security gate #1: every threat in the threat model has at least one automated test.

Reads the threat list from docs/threat-model.md §4 and the traceability table
from docs/security-report.md §3, and fails if a threat has no test or a listed
test function does not exist (so the table cannot silently rot).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
THREATS = ROOT / "docs" / "threat-model.md"
REPORT = ROOT / "docs" / "security-report.md"


def threat_ids() -> list[str]:
    text = THREATS.read_text(encoding="utf-8")
    return re.findall(r"^\| (TH[0-9]+) \|", text, re.M)


def traceability() -> dict[str, list[str]]:
    text = REPORT.read_text(encoding="utf-8")
    table: dict[str, list[str]] = {}
    for th, tests in re.findall(r"^\| (TH[0-9]+) \| (.*?) \| [^|]+ \|$", text, re.M):
        table[th] = re.findall(r"`([^`]+::[a-z0-9_]+)`", tests)
    return table


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")
    }


def test_every_threat_has_an_existing_test() -> None:
    threats = threat_ids()
    assert len(threats) >= 24
    table = traceability()
    missing = [th for th in threats if not table.get(th)]
    assert not missing, f"threats without tests: {missing}"
    unknown = sorted(set(table) - set(threats))
    assert not unknown, f"report lists threats the model does not have: {unknown}"
    broken = []
    for th, refs in table.items():
        for ref in refs:
            file, _, name = ref.partition("::")
            path = ROOT / file
            if not path.is_file() or name not in _test_functions(path):
                broken.append(f"{th}: {ref}")
    assert not broken, f"traceability points at missing tests: {broken}"
