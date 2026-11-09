"""Phase 2a acceptance tests. Run as root in a disposable VM AFTER the installer.

Covers: sshd hardening, sudoers, sysctls, nftables policy, and the
dp-firewall anti-lockout mechanism (auto-rollback, confirm, invalid input).
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

DPFW = "/usr/local/sbin/dp-firewall"
CANDIDATE = Path("/etc/domainpilot/firewall/domainpilot.nft")
PENDING = Path("/var/lib/domainpilot/firewall/pending")


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=120)


def live_table() -> str:
    return run("/usr/sbin/nft", "list", "table", "inet", "domainpilot").stdout


def _strip_counters(ruleset: str) -> str:
    # Counter values change continuously; compare structure only.
    return re.sub(r"counter packets \d+ bytes \d+", "counter", ruleset)


# --- SSH -------------------------------------------------------------------


@pytest.fixture(scope="module")
def sshd_effective() -> dict[str, str]:
    out = run("/usr/sbin/sshd", "-T").stdout
    # sshd -T prints list-valued keys (e.g. allowgroups) once per value.
    conf: dict[str, str] = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        value = value.strip()
        conf[key] = f"{conf[key]} {value}" if key in conf else value
    return conf


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("permitrootlogin", "no"),
        ("passwordauthentication", "no"),
        ("kbdinteractiveauthentication", "no"),
        ("authenticationmethods", "publickey"),
        ("authorizedkeysfile", "/etc/ssh/authorized_keys.d/%u"),
        ("allowgroups", "dp-admins dp-sftp"),
        ("x11forwarding", "no"),
        ("allowagentforwarding", "no"),
        ("allowtcpforwarding", "no"),
        ("permittunnel", "no"),
        ("permituserenvironment", "no"),
        ("subsystem", "sftp internal-sftp"),
        ("maxauthtries", "3"),
    ],
)
def test_sshd_effective_setting(sshd_effective: dict[str, str], key: str, expected: str) -> None:
    assert sshd_effective.get(key) == expected


def test_sshd_has_no_weak_algorithms(sshd_effective: dict[str, str]) -> None:
    for key in ("kexalgorithms", "ciphers", "macs"):
        value = sshd_effective[key]
        for weak in ("sha1", "cbc", "diffie-hellman-group14", "umac-64", "3des", "arcfour"):
            assert weak not in value, f"{key} contains {weak}"


def test_sshd_config_is_valid() -> None:
    run("/usr/sbin/sshd", "-t")


def test_sudoers_valid_and_scoped() -> None:
    run("/usr/sbin/visudo", "-c")
    text = Path("/etc/sudoers.d/90-domainpilot").read_text(encoding="utf-8")
    assert "%dp-admins ALL=(ALL:ALL)" in text
    assert Path("/etc/sudoers.d/90-domainpilot").stat().st_mode & 0o777 == 0o440


def test_authorized_keys_root_owned() -> None:
    d = Path("/etc/ssh/authorized_keys.d")
    for f in d.iterdir():
        st = f.stat()
        assert st.st_uid == 0
        assert st.st_mode & 0o022 == 0, f"{f} is group/other writable"


# --- sysctl ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("kernel.kptr_restrict", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.unprivileged_bpf_disabled", "1"),
        ("kernel.yama.ptrace_scope", "2"),
        ("kernel.apparmor_restrict_unprivileged_userns", "1"),
        ("fs.protected_symlinks", "1"),
        ("fs.protected_regular", "2"),
        ("fs.suid_dumpable", "0"),
        ("kernel.core_pattern", "|/bin/false"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
    ],
)
def test_sysctl(key: str, expected: str) -> None:
    assert run("/usr/sbin/sysctl", "-n", key).stdout.strip() == expected


# --- firewall --------------------------------------------------------------


def test_firewall_default_deny_both_families() -> None:
    table = live_table()
    assert "table inet domainpilot" in table  # inet = IPv4 and IPv6 in one policy
    assert "hook input priority filter; policy drop;" in table
    assert "hook forward priority filter; policy drop;" in table


def test_firewall_persisted_equals_candidate() -> None:
    assert Path("/etc/nftables.conf").read_bytes() == CANDIDATE.read_bytes()
    assert not PENDING.exists()


def test_firewall_rejects_invalid_candidate(tmp_path: Path) -> None:
    before = _strip_counters(live_table())
    bad = tmp_path / "bad.nft"
    bad.write_text("table inet domainpilot { chain input { this is not nft } }\n", encoding="utf-8")
    result = run(DPFW, "apply", str(bad), "--timeout", "5", check=False)
    assert result.returncode != 0
    assert not PENDING.exists()
    assert _strip_counters(live_table()) == before


def _modified_candidate(tmp_path: Path, marker: str) -> Path:
    text = CANDIDATE.read_text(encoding="utf-8")
    modified = text.replace(
        "chain forward {",
        f'set dp_test_marker {{ type ipv4_addr; comment "{marker}"; }}\n\n\tchain forward {{',
        1,
    )
    assert modified != text
    path = tmp_path / "candidate.nft"
    path.write_text(modified, encoding="utf-8")
    return path


def test_firewall_auto_rollback_when_not_confirmed(tmp_path: Path) -> None:
    before = _strip_counters(live_table())
    persisted = Path("/etc/nftables.conf").read_bytes()
    run(DPFW, "apply", str(_modified_candidate(tmp_path, "rollback-test")), "--timeout", "5")
    assert PENDING.exists()
    assert "dp_test_marker" in live_table()

    deadline = time.monotonic() + 30
    while PENDING.exists() and time.monotonic() < deadline:
        time.sleep(1)

    assert not PENDING.exists(), "rollback timer did not fire"
    assert "dp_test_marker" not in live_table()
    assert _strip_counters(live_table()) == before
    assert Path("/etc/nftables.conf").read_bytes() == persisted  # never persisted


def test_firewall_second_apply_refused_while_pending(tmp_path: Path) -> None:
    candidate = _modified_candidate(tmp_path, "pending-test")
    run(DPFW, "apply", str(candidate), "--timeout", "60")
    try:
        assert run(DPFW, "apply", str(candidate), check=False).returncode != 0
    finally:
        run(DPFW, "rollback")
    assert not PENDING.exists()
    assert "dp_test_marker" not in live_table()


def test_firewall_confirm_persists_then_restore(tmp_path: Path) -> None:
    original = CANDIDATE.read_bytes()
    run(DPFW, "apply", str(_modified_candidate(tmp_path, "confirm-test")), "--timeout", "60")
    run(DPFW, "confirm")
    assert not PENDING.exists()
    assert b"dp_test_marker" in Path("/etc/nftables.conf").read_bytes()
    time.sleep(7)  # make sure no rollback timer is still armed
    assert "dp_test_marker" in live_table()

    # Restore the managed ruleset through the same mechanism.
    run(DPFW, "apply", str(CANDIDATE), "--timeout", "60")
    run(DPFW, "confirm")
    assert Path("/etc/nftables.conf").read_bytes() == original
    assert "dp_test_marker" not in live_table()


def test_apport_cannot_reset_hardening() -> None:
    state = run("/usr/bin/systemctl", "is-enabled", "apport.service", check=False).stdout.strip()
    assert state in ("masked", "not-found", ""), state
