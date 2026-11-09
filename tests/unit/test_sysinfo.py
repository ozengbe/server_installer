from __future__ import annotations

import os
from pathlib import Path

import pytest

from domainpilot.core import proc, sysinfo
from domainpilot.core.errors import OperationFailed


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    (tmp_path / "etc").mkdir()
    (tmp_path / "proc").mkdir()
    (tmp_path / "run").mkdir()
    (tmp_path / "srv").mkdir()
    (tmp_path / "etc/os-release").write_text(
        'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nVERSION_ID="24.04"\nID=ubuntu\n# comment\n'
    )
    (tmp_path / "proc/uptime").write_text("93784.12 1000.00\n")
    (tmp_path / "proc/meminfo").write_text(
        "MemTotal:        2048000 kB\nMemAvailable:    1024000 kB\nSwapTotal: 0 kB\n"
        "SwapFree: 0 kB\nHugePages_Total:       0\nWeird line\n"
    )
    return tmp_path


def test_probe_reads_host_files(fake_root: Path) -> None:
    probe = sysinfo.SystemProbe(fake_root)
    summary = probe.summary()
    assert summary["os"] == "Ubuntu 24.04.3 LTS"
    assert summary["os_version_id"] == "24.04"
    assert summary["uptime_seconds"] == pytest.approx(93784.12)
    assert summary["memory"]["total_bytes"] == 2048000 * 1024
    assert summary["cpu_count"] >= 1
    assert probe.disk("/srv") is not None
    assert probe.disk("/nonexistent") is None
    assert probe.reboot_required() is False
    (fake_root / "run/reboot-required").write_text("")
    assert probe.reboot_required() is True


def test_probe_missing_files(tmp_path: Path) -> None:
    probe = sysinfo.SystemProbe(tmp_path)
    assert probe.os_release() == {}
    assert probe.uptime_seconds() is None
    assert probe.memory()["total_bytes"] == 0


def test_probe_commands(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kw: object) -> proc.Result:
        calls.append(list(argv))
        if argv[-1] == "ssh.socket":
            return proc.Result(tuple(argv), 3, "inactive\n", "")
        if argv[0].endswith("nft"):
            return proc.Result(tuple(argv), 1, "", "No such table")
        return proc.Result(tuple(argv), 0, "active\n", "")

    monkeypatch.setattr(proc, "run", fake_run)
    probe = sysinfo.SystemProbe(tmp_path)
    assert probe.service_state("nginx") == "active"
    assert probe.ssh_state() == "active"  # falls back to ssh.service
    assert probe.firewall_table_present() is False
    assert ["/usr/bin/systemctl", "is-active", "ssh.service"] in calls


def test_probe_commands_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def broken(*_a: object, **_k: object) -> proc.Result:
        raise OperationFailed("command not found")

    monkeypatch.setattr(proc, "run", broken)
    probe = sysinfo.SystemProbe(tmp_path)
    assert probe.service_state("nginx") == "unknown"
    assert probe.firewall_table_present() is None


def test_probe_load_average_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def no_load() -> tuple[float, float, float]:
        raise OSError

    monkeypatch.setattr(os, "getloadavg", no_load)
    assert sysinfo.SystemProbe(tmp_path).load_average() is None
