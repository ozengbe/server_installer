"""Safe file operations for a root process.

* Writes are atomic (temp file in the same directory, fsync, rename, fsync dir).
* Symlinks are never followed at the final component, and directories
  traversed for writing must not be writable by group/other unless sticky-free
  root-owned (prevents symlink and swap attacks by local users).
* Paths built from user input must be checked with ``contained``.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import tempfile
from pathlib import Path

from domainpilot.core.errors import OperationFailed, ValidationError


def contained(base: Path, *parts: str) -> Path:
    """Join ``parts`` under ``base`` and guarantee the result stays inside it.

    Each part must be a single safe path component (no separators, no '..').
    """
    for part in parts:
        if (
            not part
            or part in {".", ".."}
            or "/" in part
            or "\\" in part
            or "\x00" in part
            or part.startswith("-")
        ):
            raise ValidationError(f"unsafe path component {part!r}")
    candidate = base.joinpath(*parts)
    base_resolved = os.path.normpath(base)
    cand_norm = os.path.normpath(candidate)
    if os.path.commonpath([base_resolved, cand_norm]) != base_resolved:
        raise ValidationError("path escapes its base directory")
    return Path(cand_norm)


def _check_parent_dir(directory: Path) -> None:
    st = os.lstat(directory)
    if stat.S_ISLNK(st.st_mode):
        raise OperationFailed(f"refusing to write through symlinked directory {directory}")
    if not stat.S_ISDIR(st.st_mode):
        raise OperationFailed(f"{directory} is not a directory")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OperationFailed(
            f"refusing to write in {directory}: writable by group/other (mode {st.st_mode:o})"
        )
    if os.geteuid() == 0 and st.st_uid != 0:
        raise OperationFailed(f"refusing to write in {directory}: not owned by root")


def atomic_write(
    path: Path,
    data: str | bytes,
    *,
    mode: int = 0o644,
    uid: int | None = None,
    gid: int | None = None,
) -> bool:
    """Atomically replace ``path`` with ``data``. Returns False if content was identical."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    directory = path.parent
    _check_parent_dir(directory)

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None:
        if stat.S_ISLNK(st.st_mode):
            raise OperationFailed(f"refusing to replace symlink {path}")
        if not stat.S_ISREG(st.st_mode):
            raise OperationFailed(f"refusing to replace non-regular file {path}")
        same_owner = (uid is None or st.st_uid == uid) and (gid is None or st.st_gid == gid)
        if same_owner and stat.S_IMODE(st.st_mode) == mode and read_bytes_nofollow(path) == payload:
            return False

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".dp-tmp", dir=directory)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            if uid is not None or gid is not None:
                os.fchown(handle.fileno(), -1 if uid is None else uid, -1 if gid is None else gid)
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return True


def read_bytes_nofollow(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    """Read a regular file without following a symlink at the final component."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:  # final component is a symlink
            raise OperationFailed(f"refusing to read symlink {path}") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OperationFailed(f"{path} is not a regular file")
        if st.st_size > max_bytes:
            raise OperationFailed(f"{path} is larger than {max_bytes} bytes")
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_text_nofollow(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> str:
    return read_bytes_nofollow(path, max_bytes=max_bytes).decode("utf-8")


def ensure_dir(
    path: Path, *, mode: int = 0o755, uid: int | None = None, gid: int | None = None
) -> bool:
    """Create a directory (parent must already be safe). Returns True if created."""
    _check_parent_dir(path.parent)
    try:
        os.mkdir(path, mode)
        created = True
    except FileExistsError:
        created = False
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OperationFailed(f"{path} exists and is not a real directory")
    if created:
        # chown first: a later chown may clear setgid bits set by chmod.
        if uid is not None or gid is not None:
            os.chown(
                path, -1 if uid is None else uid, -1 if gid is None else gid, follow_symlinks=False
            )
        os.chmod(path, mode)  # just created by us and verified not a symlink
    return created


def create_exclusive(
    path: Path,
    data: str | bytes,
    *,
    mode: int = 0o640,
    uid: int | None = None,
    gid: int | None = None,
) -> None:
    """Create a NEW file, safe even inside a directory someone else controls.

    O_CREAT|O_EXCL fails if anything (including a symlink) already exists at
    the path, and O_NOFOLLOW refuses symlinks, so a pre-planted link can never
    redirect the write. Ownership is changed on the open descriptor.
    """
    payload = data.encode("utf-8") if isinstance(data, str) else data
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, payload)
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
