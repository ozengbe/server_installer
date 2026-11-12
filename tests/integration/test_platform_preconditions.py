"""Runs only inside a disposable Ubuntu 24.04 or 26.04 test host (tools/vm.sh test).

Checks that the kernel/userspace features the isolation model depends on
(architecture §4) exist before any later phase relies on them.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            data[key] = value.strip('"')
    return data


def test_supported_ubuntu_release() -> None:
    rel = _os_release()
    assert rel.get("ID") == "ubuntu"
    assert rel.get("VERSION_ID") in ("24.04", "26.04")


def test_cgroup_v2_unified() -> None:
    assert Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    controllers = Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="utf-8").split()
    for needed in ("cpu", "memory", "pids", "io"):
        assert needed in controllers


def test_systemd_is_pid1() -> None:
    assert Path("/proc/1/comm").read_text(encoding="utf-8").strip() == "systemd"


def test_apparmor_enabled() -> None:
    enabled = Path("/sys/module/apparmor/parameters/enabled")
    assert enabled.read_text(encoding="utf-8").strip() == "Y"


def test_unprivileged_userns_restricted_by_apparmor() -> None:
    knob = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    assert knob.exists()
    assert knob.read_text(encoding="utf-8").strip() == "1"


def test_nftables_available() -> None:
    assert shutil.which("nft") is not None


def test_running_as_root_in_vm() -> None:
    # Integration tests mutate the system; refuse to run unless explicitly in a test VM.
    assert os.geteuid() == 0
    assert Path("/etc/ozenix-test-vm").is_file(), "not an ozenix test VM"
