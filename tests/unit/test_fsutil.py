from __future__ import annotations

import os
from pathlib import Path

import pytest

from domainpilot.core import fsutil
from domainpilot.core.errors import OperationFailed, ValidationError


@pytest.fixture
def safe_dir(tmp_path: Path) -> Path:
    d = tmp_path / "safe"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    return d


@pytest.mark.parametrize("part", ["", ".", "..", "a/b", "a\\b", "a\x00", "-rf"])
def test_contained_rejects_unsafe_components(tmp_path: Path, part: str) -> None:
    with pytest.raises(ValidationError):
        fsutil.contained(tmp_path, part)


def test_contained_ok(tmp_path: Path) -> None:
    assert fsutil.contained(tmp_path, "t0001", "app") == tmp_path / "t0001" / "app"


def test_atomic_write_creates_with_mode(safe_dir: Path) -> None:
    target = safe_dir / "f.conf"
    assert fsutil.atomic_write(target, "hello\n", mode=0o640) is True
    assert target.read_text() == "hello\n"
    assert target.stat().st_mode & 0o777 == 0o640
    assert not [p for p in safe_dir.iterdir() if p.name.endswith(".dp-tmp")]


def test_atomic_write_is_idempotent(safe_dir: Path) -> None:
    target = safe_dir / "f.conf"
    fsutil.atomic_write(target, b"x", mode=0o644)
    assert fsutil.atomic_write(target, b"x", mode=0o644) is False
    assert fsutil.atomic_write(target, b"x", mode=0o600) is True  # mode change counts
    assert fsutil.atomic_write(target, b"y", mode=0o600) is True
    assert target.read_bytes() == b"y"


def test_atomic_write_refuses_symlink_target(safe_dir: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    link = safe_dir / "link.conf"
    link.symlink_to(victim)
    with pytest.raises(OperationFailed, match="symlink"):
        fsutil.atomic_write(link, "pwned")
    assert victim.read_text() == "keep"


def test_atomic_write_refuses_non_regular(safe_dir: Path) -> None:
    (safe_dir / "dir").mkdir()
    with pytest.raises(OperationFailed, match="non-regular"):
        fsutil.atomic_write(safe_dir / "dir", "x")


def test_atomic_write_refuses_world_writable_dir(tmp_path: Path) -> None:
    d = tmp_path / "ww"
    d.mkdir()
    d.chmod(0o777)
    with pytest.raises(OperationFailed, match="writable by group/other"):
        fsutil.atomic_write(d / "f", "x")


def test_atomic_write_refuses_symlinked_directory(safe_dir: Path, tmp_path: Path) -> None:
    link_dir = tmp_path / "linkdir"
    link_dir.symlink_to(safe_dir, target_is_directory=True)
    with pytest.raises(OperationFailed, match="symlinked directory"):
        fsutil.atomic_write(link_dir / "f", "x")


def test_atomic_write_refuses_non_root_owned_dir_when_root(safe_dir: Path) -> None:
    if os.geteuid() != 0:
        pytest.skip("needs root to chown")
    os.chown(safe_dir, 12345, 12345)
    with pytest.raises(OperationFailed, match="not owned by root"):
        fsutil.atomic_write(safe_dir / "f", "x")


def test_atomic_write_sets_owner(safe_dir: Path) -> None:
    if os.geteuid() != 0:
        pytest.skip("needs root to chown")
    target = safe_dir / "owned"
    fsutil.atomic_write(target, "x", uid=1234, gid=4321)
    st = target.stat()
    assert (st.st_uid, st.st_gid) == (1234, 4321)


def test_atomic_write_cleans_temp_on_error(safe_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        fsutil.atomic_write(safe_dir / "f", "x")
    assert list(safe_dir.iterdir()) == []


def test_read_nofollow(safe_dir: Path, tmp_path: Path) -> None:
    real = safe_dir / "real"
    real.write_text("data")
    assert fsutil.read_text_nofollow(real) == "data"
    link = safe_dir / "link"
    link.symlink_to(real)
    with pytest.raises(OperationFailed, match="symlink"):
        fsutil.read_text_nofollow(link)
    with pytest.raises(OperationFailed, match="not a regular file"):
        fsutil.read_bytes_nofollow(safe_dir)
    with pytest.raises(OperationFailed, match="larger than"):
        fsutil.read_bytes_nofollow(real, max_bytes=2)
    with pytest.raises(FileNotFoundError):
        fsutil.read_bytes_nofollow(safe_dir / "missing")


def test_ensure_dir(safe_dir: Path, tmp_path: Path) -> None:
    d = safe_dir / "sub"
    assert fsutil.ensure_dir(d, mode=0o750) is True
    assert d.stat().st_mode & 0o777 == 0o750
    assert fsutil.ensure_dir(d, mode=0o750) is False
    (safe_dir / "file").write_text("x")
    with pytest.raises(OperationFailed, match="not a real directory"):
        fsutil.ensure_dir(safe_dir / "file")
    (safe_dir / "dlink").symlink_to(tmp_path)
    with pytest.raises(OperationFailed, match="not a real directory"):
        fsutil.ensure_dir(safe_dir / "dlink")
    if os.geteuid() == 0:
        owned = safe_dir / "owned"
        fsutil.ensure_dir(owned, uid=1234, gid=4321)
        assert owned.stat().st_uid == 1234
