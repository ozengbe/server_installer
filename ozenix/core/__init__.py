"""Core building blocks shared by every ozenix command.

Security rules (architecture §5) are enforced here so command modules cannot
bypass them: input validation, argv-only subprocesses, atomic no-follow file
writes, locking, transactions with rollback, and audit logging.
"""
