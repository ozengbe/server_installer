"""Human and JSON output (docs/cli-spec.md §5).

Text mode: progress lines while working, a result block at the end, warnings
and errors on stderr. JSON mode: a single envelope on stdout, nothing else.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO

SCHEMA_VERSION = 1
AUDIT_DISCLAIMER = (
    "Automated checks passed for the listed controls only. This is not a guarantee of security."
)

_SYMBOLS = {
    "done": ("✔", "32"),
    "planned": ("•", "36"),
    "undone": ("↺", "33"),
    "undo_failed": ("✘", "31"),
    "failed": ("✘", "31"),
    "pending": ("…", "33"),
}


@dataclass
class Output:
    json_mode: bool = False
    quiet: bool = False
    verbose: bool = False
    color: bool = False
    stdout: TextIO = field(default_factory=lambda: sys.stdout)
    stderr: TextIO = field(default_factory=lambda: sys.stderr)
    _steps: list[dict[str, str]] = field(default_factory=list)
    _warnings: list[str] = field(default_factory=list)

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def step(self, description: str, status: str = "done") -> None:
        self._steps.append({"description": description, "status": status})
        if self.json_mode or self.quiet:
            return
        symbol, code = _SYMBOLS.get(status, ("-", "0"))
        suffix = "" if status in ("done", "planned") else f" ({status})"
        print(f"{self._paint(symbol, code)} {description}{suffix}", file=self.stdout)

    def warn(self, message: str) -> None:
        self._warnings.append(message)
        if not self.json_mode:
            print(self._paint(f"warning: {message}", "33"), file=self.stderr)

    def info(self, message: str) -> None:
        if not self.json_mode and not self.quiet:
            print(message, file=self.stdout)

    def result(
        self,
        command: Sequence[str],
        data: dict[str, Any],
        *,
        text: Sequence[str] = (),
        disclaimer: bool = False,
    ) -> None:
        if self.json_mode:
            envelope: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "ok": True,
                "command": list(command),
                "result": data,
                "warnings": self._warnings,
                "errors": [],
            }
            if self._steps:
                envelope["steps"] = self._steps
            if disclaimer:
                envelope["disclaimer"] = AUDIT_DISCLAIMER
            print(json.dumps(envelope, indent=2, sort_keys=True, default=str), file=self.stdout)
            return
        for line in text:
            print(line, file=self.stdout)
        if disclaimer:
            print(f"\nNote: {AUDIT_DISCLAIMER}", file=self.stdout)

    def error(
        self,
        command: Sequence[str],
        code: str,
        message: str,
        *,
        hint: str | None = None,
    ) -> None:
        if self.json_mode:
            err: dict[str, Any] = {"code": code, "message": message}
            if hint:
                err["hint"] = hint
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "ok": False,
                "command": list(command),
                "result": None,
                "warnings": self._warnings,
                "errors": [err],
            }
            if self._steps:
                envelope["steps"] = self._steps
            print(json.dumps(envelope, indent=2, sort_keys=True), file=self.stdout)
            return
        print(self._paint(f"error: {message}", "31"), file=self.stderr)
        if hint:
            print(f"hint: {hint}", file=self.stderr)


def table(rows: Sequence[Sequence[str]], headers: Sequence[str]) -> list[str]:
    """Plain aligned text table."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines.extend(fmt.format(*row) for row in rows)
    return [line.rstrip() for line in lines]
