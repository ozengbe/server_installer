"""Error types with stable exit codes (docs/cli-spec.md §3)."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    FAILED = 1
    USAGE = 2
    VALIDATION = 3
    LOCK_BUSY = 4
    PRECONDITION = 5
    CONFIRMATION = 6
    AUDIT_WARNINGS = 10
    AUDIT_CRITICAL = 11


class DPError(Exception):
    """Base class. ``code`` is a stable machine-readable identifier."""

    exit_code: ExitCode = ExitCode.FAILED
    code: str = "failed"

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class OperationFailed(DPError):
    exit_code = ExitCode.FAILED
    code = "operation_failed"


class UsageError(DPError):
    exit_code = ExitCode.USAGE
    code = "usage"


class ValidationError(DPError):
    exit_code = ExitCode.VALIDATION
    code = "validation"


class LockBusy(DPError):
    exit_code = ExitCode.LOCK_BUSY
    code = "lock_busy"


class PreconditionFailed(DPError):
    exit_code = ExitCode.PRECONDITION
    code = "precondition"


class ConfirmationRequired(DPError):
    exit_code = ExitCode.CONFIRMATION
    code = "confirmation_required"


class NotImplementedYet(DPError):
    exit_code = ExitCode.FAILED
    code = "not_implemented"
