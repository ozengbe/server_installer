"""Advisory locks so concurrent `site` invocations cannot interleave changes.

Lock order (to avoid deadlocks): global lock first, then one tenant lock.
"""

from __future__ import annotations

import fcntl
import os
import time
from pathlib import Path
from types import TracebackType

from ozenix.core.errors import LockBusy


class FileLock:
    def __init__(self, path: Path, *, timeout: float = 30.0, poll: float = 0.1) -> None:
        self.path = path
        self.timeout = timeout
        self.poll = poll
        self._fd: int | None = None

    def acquire(self) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockBusy(
                        f"another ozenix operation holds {self.path.name}",
                        hint="wait for it to finish, then retry",
                    ) from None
                time.sleep(self.poll)
                continue
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
            self._fd = fd
            return

    def release(self) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
