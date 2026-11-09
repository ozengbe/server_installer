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


# --- shared fake system for lifecycle tests (sites, TLS, Cloudflare, tuning) ------------

import grp  # noqa: E402
import os  # noqa: E402
import pwd  # noqa: E402
import socket  # noqa: E402

from domainpilot.core import proc  # noqa: E402
from domainpilot.core.audit import AuditLog  # noqa: E402
from domainpilot.core.config import HostFacts  # noqa: E402
from domainpilot.core.errors import OperationFailed  # noqa: E402
from domainpilot.core.registry import Registry  # noqa: E402
from domainpilot.sites.lifecycle import SiteManager  # noqa: E402
from domainpilot.web.nginx import Nginx, parse_upstream  # noqa: E402

SITE_HOST = HostFacts(release="26.04", default_php_version="8.5", php_versions=("8.5",))


def public_resolver(_host: str, _port: int) -> list[str]:
    return ["93.184.215.14"]


@pytest.fixture
def system(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    paths = Paths.under(tmp_path / "root")
    for d in (
        paths.tenants,
        paths.etc / "tenants",
        paths.log / "tenants",
        paths.var_lib / "cache",
        paths.systemd,
        paths.apparmor,
        paths.run,
    ):
        d.mkdir(parents=True, mode=0o755)
    calls: list[list[str]] = []
    users: set[str] = set()
    state = {"nginx_fail": False, "start_fail": False}

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(list(argv))
        if argv[0] == "/usr/sbin/useradd":
            users.add(argv[-1])
        if argv[0] == "/usr/sbin/userdel":
            users.discard(argv[-1])
        if argv[:2] == ["/usr/sbin/nginx", "-t"] and state["nginx_fail"]:
            return proc.Result(tuple(argv), 1, "", "nginx: [emerg] bad\n")
        if argv[:3] == ["/usr/bin/systemctl", "enable", "--now"]:
            if state["start_fail"]:
                raise OperationFailed("unit failed to start")
            for arg in argv[3:]:
                tenant = arg.split("@")[1].split(".")[0]
                kind = "php" if arg.startswith("dp-php@") else "cache"
                sock = paths.tenant_run(tenant) / kind / f"{kind}.sock"
                sock.parent.mkdir(parents=True, exist_ok=True)
                if not sock.exists():
                    s = socket.socket(socket.AF_UNIX)
                    s.bind(str(sock))
                    s.close()
        return proc.Result(tuple(argv), 0, "", "")

    def getpwnam(name: str) -> Any:
        if name in users:
            return pwd.struct_passwd((name, "x", os.getuid(), os.getgid(), "", "", ""))
        raise KeyError(name)

    monkeypatch.setattr(pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(KeyError(uid)))
    monkeypatch.setattr(grp, "getgrgid", lambda gid: (_ for _ in ()).throw(KeyError(gid)))
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: grp.struct_group((name, "x", os.getgid(), []))
    )
    if os.geteuid() != 0:
        monkeypatch.setattr(os, "chown", lambda *a, **k: None)
        monkeypatch.setattr(os, "fchown", lambda *a, **k: None)
    paths.create_runtime_dirs()
    registry = Registry.open(paths.registry)
    assert registry is not None
    conf = tmp_path / "sites"
    logs = tmp_path / "nginxlogs"
    conf.mkdir(mode=0o755)
    logs.mkdir(mode=0o750)
    reported: list[tuple[str, str]] = []

    def manager(dry_run: bool = False) -> SiteManager:
        return SiteManager(
            paths=paths,
            host=SITE_HOST,
            registry=registry,
            audit=AuditLog(paths.audit_log, use_syslog=False),
            argv=["site", "test"],
            run=run,
            nginx=Nginx(paths, conf_dir=conf, log_root=logs, run=run),
            reporter=lambda d, s: reported.append((d, s)),
            dry_run=dry_run,
            upstream_parser=lambda v: parse_upstream(v, resolve=public_resolver),
        )

    return {
        "paths": paths,
        "registry": registry,
        "calls": calls,
        "state": state,
        "manager": manager,
        "conf": conf,
        "users": users,
        "reported": reported,
    }
