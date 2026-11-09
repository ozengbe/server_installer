"""Phase 2b acceptance tests. Run as root in a disposable VM AFTER the installer."""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

PUBLIC_TCP = {22, 80, 443}

# Release-specific defaults (ansible/group_vars/all.yml dp_release_defaults).
RELEASE = {
    "24.04": {"php": "8.3", "cache_service": "redis-server.service"},
    "26.04": {"php": "8.5", "cache_service": "valkey-server.service"},
}


def _release() -> dict[str, str]:
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION_ID="):
            return RELEASE[line.split("=", 1)[1].strip('"')]
    raise AssertionError("VERSION_ID missing from /etc/os-release")


REL = _release()
PHP = REL["php"]


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=120)


def listeners(proto: str) -> list[tuple[str, int, str]]:
    """(address, port, process) for every listening socket of proto 'tcp' or 'udp'."""
    flag = "-Hltnp" if proto == "tcp" else "-Hlunp"
    result = []
    for line in run("/usr/bin/ss", flag).stdout.splitlines():
        cols = line.split()
        local = cols[3]
        addr, _, port = local.rpartition(":")
        result.append((addr.strip("[]"), int(port), " ".join(cols[5:])))
    return result


def is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr in ("::1", "localhost")


# --- exposure ----------------------------------------------------------------


def test_no_unexpected_public_tcp_listeners() -> None:
    unexpected = [
        lst for lst in listeners("tcp") if not is_loopback(lst[0]) and lst[1] not in PUBLIC_TCP
    ]
    assert not unexpected, f"unexpected public TCP listeners: {unexpected}"


def test_database_and_cache_not_on_network() -> None:
    for proto in ("tcp", "udp"):
        for addr, port, proc in listeners(proto):
            assert port not in (3306, 6379), f"{proto} {addr}:{port} {proc}"
            for daemon in ("mariadbd", "redis", "valkey"):
                assert daemon not in proc, f"{proto} {addr}:{port} {proc}"


# --- nginx -------------------------------------------------------------------


def test_nginx_from_signed_nginx_org_repo() -> None:
    maintainer = run("/usr/bin/dpkg-query", "-W", "-f=${Maintainer}", "nginx").stdout.lower()
    assert "nginx" in maintainer and "ubuntu" not in maintainer
    sources = Path("/etc/apt/sources.list.d/nginx.sources").read_text(encoding="utf-8")
    assert "Signed-By: /usr/share/keyrings/nginx-archive-keyring.asc" in sources
    assert "URIs: https://nginx.org/packages/ubuntu" in sources


def test_nginx_effective_config() -> None:
    dump = run("/usr/sbin/nginx", "-T").stdout
    for needle in (
        "server_tokens off;",
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "ssl_session_tickets off;",
        "ssl_reject_handshake on;",
        "limit_req_zone",
        "client_max_body_size",
    ):
        assert needle in dump, needle
    assert not re.search(r"^\s*autoindex\s+on", dump, re.MULTILINE)


@pytest.mark.parametrize("host", ["127.0.0.1", "unknown.example"])
def test_default_server_closes_unknown_http(host: str) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
    conn.request("GET", "/", headers={"Host": host})
    with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError)):
        conn.getresponse()
    conn.close()


def test_default_server_rejects_unknown_tls() -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection(("127.0.0.1", 443), timeout=10) as raw,
        pytest.raises(ssl.SSLError),
        ctx.wrap_socket(raw, server_hostname="unknown.example"),
    ):
        pass


def test_nginx_sandboxed() -> None:
    props = run(
        "/usr/bin/systemctl", "show", "nginx", "-p", "NoNewPrivileges", "-p", "ProtectHome"
    ).stdout
    assert "NoNewPrivileges=yes" in props
    assert "ProtectHome=yes" in props


# --- PHP / Redis shared services are masked ----------------------------------


@pytest.mark.parametrize("unit", [f"php{PHP}-fpm.service", REL["cache_service"]])
def test_shared_services_masked(unit: str) -> None:
    state = run("/usr/bin/systemctl", "is-enabled", unit, check=False).stdout.strip()
    assert state == "masked"
    assert run("/usr/bin/systemctl", "is-active", unit, check=False).stdout.strip() != "active"


def test_php_hardening() -> None:
    ini = Path(f"/etc/php/{PHP}/fpm/conf.d/99-domainpilot.ini").read_text(encoding="utf-8")
    for needle in ("expose_php = Off", "allow_url_include = Off", "cgi.fix_pathinfo = 0"):
        assert needle in ini
    run(f"/usr/sbin/php-fpm{PHP}", "-t")


# --- MariaDB ----------------------------------------------------------------


def test_mariadb_hardening() -> None:
    out = run(
        "/usr/bin/mariadb",
        "-NBe",
        "SELECT @@skip_networking, @@local_infile, @@secure_file_priv",
    ).stdout.split()
    assert out[0] == "1"
    assert out[1] == "0"
    assert out[2].rstrip("/") == "/var/lib/mysql-files"


def test_mariadb_no_anonymous_or_remote_root() -> None:
    out = run(
        "/usr/bin/mariadb",
        "-NBe",
        "SELECT COUNT(*) FROM mysql.user WHERE User='' OR (User='root' AND Host<>'localhost')",
    ).stdout.strip()
    assert out == "0"
    assert run("/usr/bin/mariadb", "-NBe", "SHOW DATABASES LIKE 'test'").stdout.strip() == ""


# --- fail2ban ---------------------------------------------------------------


@pytest.mark.parametrize("jail", ["sshd", "nginx-limit-req", "recidive"])
def test_fail2ban_jail_running(jail: str) -> None:
    run("/usr/bin/fail2ban-client", "status", jail)


def test_fail2ban_uses_own_nft_table_not_ours() -> None:
    dump = run("/usr/sbin/nft", "list", "table", "inet", "domainpilot").stdout
    assert "f2b" not in dump


# --- updates ----------------------------------------------------------------


def test_unattended_upgrades_policy() -> None:
    dump = run("/usr/bin/apt-config", "dump").stdout
    assert 'Unattended-Upgrade::Automatic-Reboot "false";' in dump
    assert 'APT::Periodic::Unattended-Upgrade "1";' in dump
    origins = re.findall(r'Unattended-Upgrade::Allowed-Origins:: "([^"]+)";', dump)
    assert origins, "no allowed origins configured"
    for origin in origins:
        assert not re.search(r"-(updates|proposed|backports)$", origin), origin


def test_upgrade_timer_has_health_check() -> None:
    props = run("/usr/bin/systemctl", "cat", "apt-daily-upgrade.service").stdout
    assert "ExecStartPost=-/usr/local/sbin/dp-healthcheck --post-update" in props


def test_healthcheck_passes() -> None:
    result = run("/usr/local/sbin/dp-healthcheck", "--json", check=False)
    # 10 = warnings only (e.g. reboot-required on a freshly patched runner)
    assert result.returncode in (0, 10), result.stdout
    assert '"ok":true' in result.stdout
