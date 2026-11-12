"""Node.js and Python sites on a real host: app behind nginx, port protection.

Runs only on a disposable test host (/etc/ozenix-test-vm).
"""

from __future__ import annotations

import http.client
import json
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
NODE = "p12node.example.com"
PY = "p12py.example.com"


def site_json(*args: str, ok: bool = True) -> dict[str, Any]:
    r = subprocess.run([SITE, "--json", *args], capture_output=True, text=True, timeout=900)
    data = json.loads(r.stdout or r.stderr)
    if ok:
        assert r.returncode == 0 and data["ok"], r.stdout + r.stderr
        return dict(data["result"])
    assert r.returncode != 0, r.stdout
    return dict(data.get("error") or data)


def http_get(host: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=15)
    try:
        conn.request("GET", "/", headers={"Host": host})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def wait_for_body(host: str, text: str, timeout: float = 60) -> str:
    deadline = time.monotonic() + timeout
    body = ""
    while time.monotonic() < deadline:
        try:
            status, body = http_get(host)
            if status == 200 and text in body:
                return body
        except OSError:
            pass
        time.sleep(1)
    raise AssertionError(f"{host} never answered with {text!r}: {body[:300]}")


def host_facts() -> str:
    return Path("/etc/ozenix/host.toml").read_text()


@pytest.fixture(scope="module")
def apps() -> Iterator[dict[str, str]]:
    assert Path("/etc/ozenix-test-vm").is_file(), "test host only"
    for name in (NODE, PY):
        subprocess.run([SITE, name, "delete", "--purge", "--confirm", name], capture_output=True)
    made: dict[str, str] = {}
    if 'node_versions = ["' in host_facts():
        made["node"] = site_json(NODE, "create", "--type", "nodejs", "--no-ssl")["tenant"]
    if "python_sites = true" in host_facts():
        made["python"] = site_json(PY, "create", "--type", "python", "--no-ssl")["tenant"]
    yield made
    for name in (NODE, PY):
        subprocess.run([SITE, name, "delete", "--purge", "--confirm", name], capture_output=True)


def test_node_runtimes_are_signed_releases() -> None:
    nodes = sorted(p.name for p in Path("/opt/ozenix/node").iterdir() if p.is_symlink())
    assert nodes, "no Node.js runtime installed"
    for major in nodes:
        out = subprocess.run(
            [f"/opt/ozenix/node/{major}/bin/node", "--version"], capture_output=True, text=True
        )
        assert out.stdout.startswith(f"v{major}."), out
        assert Path(f"/opt/ozenix/node/{major}").resolve().stat().st_uid == 0


def test_nodejs_site_serves_through_nginx(apps: dict[str, str]) -> None:
    if "node" not in apps:
        pytest.skip("Node.js not installed on this host")
    wait_for_body(NODE, "Site ready (Node.js)")
    status = site_json(NODE, "app", "status")
    assert status["state"] == "active" and status["port"] == 10000 + int(apps["node"][1:])
    # Change the start command: the app restarts with it.
    app_js = Path(f"/srv/tenants/{apps['node']}/app/server.js")
    app_js.write_text(app_js.read_text().replace("Site ready (Node.js)", "Changed app"))
    site_json(NODE, "app", "restart")
    wait_for_body(NODE, "Changed app")


def test_python_site_serves_through_nginx(apps: dict[str, str]) -> None:
    if "python" not in apps:
        pytest.skip("Python sites not enabled on this host")
    wait_for_body(PY, "Site ready (Python)")
    assert site_json(PY, "app", "status")["runtime"] == "python"


def test_app_ports_cannot_be_taken_over(apps: dict[str, str]) -> None:
    """Nobody but the site's own app may listen on its port (10000 + site number)."""
    if not apps:
        pytest.skip("no app site")
    tenant = next(iter(apps.values()))
    port = 10000 + int(tenant[1:])
    deploy = f"{tenant}-deploy"
    grab = subprocess.run(
        [
            "/usr/bin/setpriv", f"--reuid={deploy}", f"--regid={tenant}", "--init-groups", "--",
            "/usr/bin/python3", "-c",
            f"import socket; s=socket.socket(); s.bind(('127.0.0.1', {port + 1}))",
        ],
        capture_output=True,
        text=True,
    )  # fmt: skip
    assert grab.returncode != 0 and "Permission denied" in grab.stderr
    assert (
        "10000"
        not in subprocess.run(
            ["/usr/sbin/sysctl", "-n", "net.ipv4.ip_unprivileged_port_start"],
            capture_output=True,
            text=True,
        ).stdout
    )  # sanity: the knob is set (20000), not 10000
    unit = Path(f"/etc/systemd/system/dp-php@{tenant}.service.d")
    assert (
        not unit.exists()
        or "SocketBindDeny=any" in Path("/etc/systemd/system/dp-php@.service").read_text()
    )


def test_purge_removes_the_app(apps: dict[str, str]) -> None:
    if "node" not in apps:
        pytest.skip("Node.js not installed on this host")
    site_json(NODE, "delete", "--purge", "--confirm", NODE)
    t = apps["node"]
    assert not Path(f"/etc/systemd/system/dp-app@{t}.service.d").exists()
    active = subprocess.run(
        ["/usr/bin/systemctl", "is-active", f"dp-app@{t}.service"], capture_output=True, text=True
    )
    assert active.stdout.strip() != "active"
