"""Transactions: ordered steps with compensating undo actions.

Every mutating command is expressed as steps. Progress is journaled in the
registry before and after each step, so an interrupted run (crash, power loss,
kill) leaves a record that `site <domain> repair` can roll back or finish.
On failure, completed steps are undone in reverse order.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from ozenix.core.audit import AuditLog, actor
from ozenix.core.errors import DPError, OperationFailed, UsageError
from ozenix.core.registry import Registry

Reporter = Callable[[str, str], None]  # (step description, status)


@dataclass(frozen=True)
class Step:
    name: str
    description: str
    apply: Callable[[], None]
    undo: Callable[[], None] | None = None


@dataclass
class TxnResult:
    operation_id: str | None
    dry_run: bool
    steps: list[dict[str, Any]] = field(default_factory=list)

    @property
    def plan(self) -> list[str]:
        return [s["description"] for s in self.steps]


class Transaction:
    def __init__(
        self,
        *,
        registry: Registry | None,
        audit: AuditLog | None,
        command: Sequence[str],
        target: str | None,
        dry_run: bool = False,
        reporter: Reporter | None = None,
    ) -> None:
        if not dry_run and (registry is None or audit is None):
            raise UsageError("a registry and audit log are required for real changes")
        self.registry = registry
        self.audit = audit
        self.command = list(command)
        self.target = target
        self.dry_run = dry_run
        self.reporter = reporter or (lambda _desc, _status: None)
        self._steps: list[Step] = []

    def add(self, step: Step) -> Transaction:
        if any(s.name == step.name for s in self._steps):
            raise UsageError(f"duplicate step name {step.name!r}")
        self._steps.append(step)
        return self

    def execute(self) -> TxnResult:
        if self.dry_run:
            planned = [
                {"name": s.name, "description": s.description, "status": "planned"}
                for s in self._steps
            ]
            for s in self._steps:
                self.reporter(s.description, "planned")
            return TxnResult(None, True, planned)

        if self.registry is None or self.audit is None:  # guarded in __init__
            raise UsageError("a registry and audit log are required for real changes")
        journal: list[dict[str, Any]] = [
            {"name": s.name, "description": s.description, "status": "pending"} for s in self._steps
        ]
        op_id = self.registry.begin_operation(
            actor=actor(), command=self.command, target=self.target
        )
        done: list[int] = []
        for index, step in enumerate(self._steps):
            journal[index]["status"] = "running"
            self.registry.update_operation(op_id, steps=journal)
            try:
                step.apply()
            except BaseException as exc:
                journal[index]["status"] = "failed"
                self._rollback(op_id, journal, done, exc)
            journal[index]["status"] = "done"
            done.append(index)
            self.registry.update_operation(op_id, steps=journal)
            self.reporter(step.description, "done")
            _crash_hook(step.name)

        self.registry.update_operation(op_id, steps=journal, status="succeeded")
        self.audit.record(
            "operation",
            argv=self.command,
            outcome="success",
            details={"target": self.target, "steps": [s["name"] for s in journal]},
            operation_id=op_id,
        )
        return TxnResult(op_id, False, journal)

    def _rollback(
        self,
        op_id: str,
        journal: list[dict[str, Any]],
        done: list[int],
        cause: BaseException,
    ) -> NoReturn:
        if self.registry is None or self.audit is None:  # guarded in __init__
            raise UsageError("a registry and audit log are required for real changes")
        message = (
            cause.message if isinstance(cause, DPError) else f"{type(cause).__name__}: {cause}"
        )
        undo_failures: list[str] = []
        for index in reversed(done):
            step = self._steps[index]
            if step.undo is None:
                journal[index]["status"] = "kept"
                continue
            try:
                step.undo()
            except Exception as exc:  # keep undoing the rest; report everything
                journal[index]["status"] = "undo_failed"
                undo_failures.append(f"{step.name}: {exc}")
                self.reporter(step.description, "undo_failed")
            else:
                journal[index]["status"] = "undone"
                self.reporter(step.description, "undone")

        status = "rollback_failed" if undo_failures else "rolled_back"
        self.registry.update_operation(op_id, steps=journal, status=status, error=message)
        self.audit.record(
            "operation",
            argv=self.command,
            outcome=status,
            details={"target": self.target, "error": message, "undo_failures": undo_failures},
            operation_id=op_id,
        )
        if undo_failures:
            raise OperationFailed(
                f"{message}; rollback incomplete ({'; '.join(undo_failures)})",
                hint=f"run: sudo site {self.target or 'system'} repair  (operation {op_id})",
            ) from cause
        if isinstance(cause, DPError):
            raise cause
        raise OperationFailed(f"{message}; all completed steps were rolled back") from cause


TEST_VM_MARKER = Path("/etc/ozenix-test-vm")


def _crash_hook(step_name: str) -> None:
    """Crash-injection for recovery tests: hard-exit right after a named step.

    Active only on disposable test hosts (marker file present) and only when
    DP_TEST_CRASH_AFTER_STEP names this step. Simulates power loss / kill -9:
    no rollback, no cleanup, journal left as "running".
    """
    if os.environ.get("DP_TEST_CRASH_AFTER_STEP") == step_name and TEST_VM_MARKER.exists():
        os._exit(137)
