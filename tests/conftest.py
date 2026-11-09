from __future__ import annotations

import io
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from domainpilot.cli.main import main
from domainpilot.core.paths import Paths
from domainpilot.core.sysinfo import SystemProbe


class FakeProbe(SystemProbe):
    """Deterministic host for CLI tests (no systemctl/nft in containers)."""

    def __init__(self, root: Path, services: dict[str, str] | None = None) -> None:
        super().__init__(root)
        self.services = services or {}
        self.table_present: bool | None = True
        self.reboot = False

    def hostname(self) -> str:
        return "test-host"

    def os_release(self) -> dict[str, str]:
        return {"PRETTY_NAME": "Ubuntu 24.04.3 LTS", "VERSION_ID": "24.04"}

    def service_state(self, unit: str) -> str:
        return self.services.get(unit, "active")

    def ssh_state(self) -> str:
        return self.services.get("ssh", "active")

    def firewall_table_present(self) -> bool | None:
        return self.table_present

    def reboot_required(self) -> bool:
        return self.reboot


@dataclass
class CliResult:
    code: int
    out: str
    err: str

    def json(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(self.out)
        return data


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    p = Paths.under(tmp_path / "dp")
    (tmp_path / "dp").mkdir(mode=0o755)
    p.etc.mkdir(mode=0o750)
    return p


@pytest.fixture
def probe(tmp_path: Path) -> FakeProbe:
    return FakeProbe(tmp_path)


RunCli = Callable[..., CliResult]


@pytest.fixture
def run_cli(paths: Paths, probe: FakeProbe) -> RunCli:
    def _run(*argv: str, euid: int = 0, stdin_text: str = "") -> CliResult:
        out, err = io.StringIO(), io.StringIO()
        code = main(
            list(argv),
            paths=paths,
            probe=probe,
            euid=euid,
            stdin=io.StringIO(stdin_text),
            stdout=out,
            stderr=err,
            use_syslog=False,
        )
        return CliResult(code, out.getvalue(), err.getvalue())

    return _run
