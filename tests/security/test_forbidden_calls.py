"""Static guard rails for the root-run code base (architecture §5).

These tests fail the build if code under ``ozenix/`` uses constructs that
are forbidden for a program that runs as root and handles untrusted input.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[2] / "ozenix"

# The single module allowed to import subprocess (added in Phase 3).
SUBPROCESS_ALLOWED = {PKG_ROOT / "core" / "proc.py"}

FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execl"),
    ("os", "execlp"),
    ("os", "execv"),
    ("os", "execvp"),
    ("os", "spawnl"),
    ("os", "spawnv"),
    ("pickle", "load"),
    ("pickle", "loads"),
    ("marshal", "loads"),
    ("tempfile", "mktemp"),
}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_IMPORTS = {"pickle", "marshal", "shelve", "telnetlib", "ftplib"}


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path.relative_to(PKG_ROOT.parent)}:{self.line}: {self.message}"


def _scan(path: Path) -> list[Violation]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[Violation] = []

    def add(node: ast.AST, msg: str) -> None:
        found.append(Violation(path, getattr(node, "lineno", 0), msg))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                root = name.split(".")[0]
                if root in FORBIDDEN_IMPORTS:
                    add(node, f"forbidden import {name!r}")
                if root == "subprocess" and path not in SUBPROCESS_ALLOWED:
                    add(node, "subprocess may only be used via ozenix.core.proc")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                add(node, f"forbidden builtin {func.id}()")
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and (func.value.id, func.attr) in FORBIDDEN_CALLS
            ):
                add(node, f"forbidden call {func.value.id}.{func.attr}()")
            for kw in node.keywords:
                if kw.arg == "shell" and not (
                    isinstance(kw.value, ast.Constant) and kw.value.value is False
                ):
                    add(node, "shell= must be literally False")
    return found


def scan_package() -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(PKG_ROOT.rglob("*.py")):
        violations.extend(_scan(path))
    return violations


def test_package_has_no_forbidden_constructs() -> None:
    violations = scan_package()
    assert not violations, "\n".join(map(str, violations))


def test_scanner_detects_violations(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(
        "import os, subprocess, pickle\n"
        "os.system('x')\n"
        "subprocess.run('x', shell=True)\n"
        "eval('1')\n",
        encoding="utf-8",
    )
    messages = {v.message for v in _scan(bad)}
    assert "forbidden call os.system()" in messages
    assert "shell= must be literally False" in messages
    assert "forbidden builtin eval()" in messages
    assert "forbidden import 'pickle'" in messages
    assert "subprocess may only be used via ozenix.core.proc" in messages
