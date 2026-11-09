"""Per-invocation state handed to command handlers."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from domainpilot.core.audit import AuditLog
from domainpilot.core.config import Config
from domainpilot.core.output import Output
from domainpilot.core.paths import Paths
from domainpilot.core.registry import Registry
from domainpilot.core.sysinfo import SystemProbe


@dataclass
class CommandResult:
    data: dict[str, Any]
    text: list[str] = field(default_factory=list)
    exit_code: int = 0
    disclaimer: bool = False


@dataclass
class Context:
    paths: Paths
    out: Output
    probe: SystemProbe
    config: Config
    argv: list[str]
    domain: str | None = None
    dry_run: bool = False
    use_syslog: bool = True
    _registry: Registry | None = None

    def registry(self, *, create: bool = False) -> Registry | None:
        """Open the registry. Read-only commands pass create=False and get None if absent."""
        if self._registry is None:
            if create:
                self.paths.create_runtime_dirs()
            self._registry = Registry.open(self.paths.registry, create=create)
        return self._registry

    def audit(self) -> AuditLog:
        self.paths.create_runtime_dirs()
        return AuditLog(self.paths.audit_log, use_syslog=self.use_syslog)

    def close(self) -> None:
        if self._registry is not None:
            self._registry.close()
            self._registry = None


Handler = Callable[[Context, argparse.Namespace], CommandResult]
