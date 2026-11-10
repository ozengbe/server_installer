"""Phase 10 acceptance: installed release record, upgrade layout, downgrade refusal,
backup master-key rotation against real restic, and the disaster-recovery commands.

Runs only on a disposable test host (/etc/domainpilot-test-vm). Backup settings and
keys that existed before are put back afterwards; the master key created here for
the test repository never replaces a pre-existing one.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
REPO_ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "p10.example.com"
REPO = Path("/var/backups/domainpilot-p10test")
ETC = Path("/etc/domainpilot")
BACKUP_JSON = ETC / "backup.json"
BACKUP_SECRETS = ETC / "secrets" / "backup"
CODE = Path("/usr/lib/domainpilot")


def site(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([SITE, *args], input=stdin, capture_output=True, text=True, timeout=1800)


def site_json(*args: str, ok: bool = True) -> dict[str, Any]:
    for _ in range(3):  # a background dp-monitor/dp-backup run may hold a lock briefly
        r = site("--json", *args)
        data = json.loads(r.stdout or r.stderr)
        if r.returncode == 0 or "holds" not in (r.stdout + r.stderr):
            break
        time.sleep(5)
    if ok:
        assert r.returncode == 0 and data["ok"], r.stdout + r.stderr
        return dict(data["result"])
    assert r.returncode != 0, r.stdout
    return dict(data.get("error") or data)


def restic_keys(name: str, master: str) -> int:
    """Number of keys in a repository, opened with a password derived from ``master``."""
    import hashlib
    import hmac

    pw = hmac.new(
        bytes.fromhex(master), b"domainpilot-backup-v1:" + name.encode(), hashlib.sha256
    ).hexdigest()
    r = subprocess.run(
        ["/usr/bin/restic", "key", "list", "--json", "--no-lock"],
        env={"RESTIC_REPOSITORY": str(REPO / name), "RESTIC_PASSWORD": pw, "PATH": "/usr/bin"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    return len(json.loads(r.stdout)) if r.returncode == 0 else -1


@pytest.fixture(scope="module")
def backups(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    assert Path("/etc/domainpilot-test-vm").is_file(), "test host only"
    keep = tmp_path_factory.mktemp("saved")
    if BACKUP_JSON.exists():
        shutil.copy2(BACKUP_JSON, keep / "backup.json")
    if BACKUP_SECRETS.exists():
        shutil.copytree(BACKUP_SECRETS, keep / "backup")
        shutil.rmtree(BACKUP_SECRETS)  # fresh master for the test repository only
    site(DOMAIN, "delete", "--purge", "--confirm", DOMAIN)
    shutil.rmtree(REPO, ignore_errors=True)
    tenant = site_json(DOMAIN, "create")["tenant"]
    site_json("system", "backup", "setup", "--repository", str(REPO), "--show-secret")
    try:
        yield {"tenant": tenant}
    finally:
        site(DOMAIN, "delete", "--purge", "--confirm", DOMAIN)
        shutil.rmtree(REPO, ignore_errors=True)
        BACKUP_JSON.unlink(missing_ok=True)
        shutil.rmtree(BACKUP_SECRETS, ignore_errors=True)
        if (keep / "backup.json").exists():
            shutil.copy2(keep / "backup.json", BACKUP_JSON)
        if (keep / "backup").exists():
            shutil.copytree(keep / "backup", BACKUP_SECRETS)
        Path("/var/lib/domainpilot/backup/state.json").unlink(missing_ok=True)


# --- release record and code layout -------------------------------------------------------


def test_release_is_recorded() -> None:
    from domainpilot import __version__

    record = json.loads(Path("/var/lib/domainpilot/release.json").read_text())
    assert record["version"] == __version__
    history = Path("/var/lib/domainpilot/release-history.jsonl").read_text().splitlines()
    assert json.loads(history[-1])["version"] == __version__
    out = site("version").stdout
    assert __version__ in out and "installed release" in out


def test_code_is_versioned_and_root_owned() -> None:
    from domainpilot import __version__

    current = CODE / "current"
    assert current.is_symlink() and os.readlink(current) == f"releases/{__version__}"
    assert not (CODE / "domainpilot").exists()  # pre-0.10 location removed
    for path in [CODE, CODE / "releases", *(CODE / "releases").iterdir()]:
        st = path.lstat()
        assert st.st_uid == 0 and not st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_IWGRP
    assert len(list((CODE / "releases").iterdir())) <= 3


def test_downgrade_is_refused(tmp_path: Path) -> None:
    fake = tmp_path / "release.json"
    fake.write_text(json.dumps({"version": "99.0.0"}))
    argv = [
        "/usr/bin/python3",
        "-IB",
        "-c",
        "import sys; sys.path.insert(0, sys.argv[1]); from domainpilot.release import "
        "installer_main; raise SystemExit(installer_main(sys.argv[2:]))",
        str(REPO_ROOT),
        "plan",
        str(fake),
    ]
    refused = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert refused.returncode == 3 and "refusing to downgrade" in refused.stderr
    allowed = subprocess.run([*argv, "--allow-downgrade"], capture_output=True, text=True)
    assert allowed.returncode == 0 and allowed.stdout.startswith("downgrade")


def test_pre_upgrade_snapshot_is_private() -> None:
    snaps = sorted(Path("/var/backups/domainpilot").glob("pre-upgrade-*.tar.gz"))
    if not snaps:
        pytest.skip("this host was never upgraded (fresh install)")
    assert stat.S_IMODE(Path("/var/backups/domainpilot").stat().st_mode) == 0o700
    newest = snaps[-1]
    assert stat.S_IMODE(newest.stat().st_mode) == 0o600
    names = subprocess.run(
        ["/usr/bin/tar", "-tzf", str(newest)], capture_output=True, text=True, check=True
    ).stdout.split()
    assert "./registry.sqlite3" in names and any(n.startswith("etc/domainpilot") for n in names)
    assert not any("backup/cache" in n for n in names)


# --- backup master-key rotation ---------------------------------------------------------


def test_master_key_rotation(backups: dict[str, Any]) -> None:
    tenant = backups["tenant"]
    site_json(DOMAIN, "backup")
    site_json("system", "backup")  # system repository too
    old = site_json("system", "backup", "show-key", "--show-secret")["master_key"]
    assert restic_keys(tenant, old) == 1

    plain = site("system", "backup", "rotate-key")  # not a terminal, no --show-secret
    assert plain.returncode != 0 and "--show-secret" in plain.stderr + plain.stdout

    started = site_json("system", "backup", "rotate-key", "--show-secret")
    new = started["master_key"]
    assert new != old and started["repositories"][tenant] == "new key added"
    assert restic_keys(tenant, new) == 2 and restic_keys(tenant, old) == 2  # both work
    again = site_json("system", "backup", "rotate-key", "--show-secret", ok=False)
    assert "waiting to be finished" in json.dumps(again)

    site_json(DOMAIN, "backup")  # backups run with the new key
    finished = site_json("system", "backup", "rotate-key", "--finish")
    assert finished["repositories"][tenant] == "old key removed"
    assert restic_keys(tenant, new) == 1 and restic_keys(tenant, old) == -1
    assert restic_keys("system", new) == 1 and restic_keys("system", old) == -1
    snaps = site_json(DOMAIN, "backup", "list")["snapshots"]
    assert len([s for s in snaps if s["kind"] == "files"]) == 2  # old snapshots still readable
    assert site_json("system", "backup", "--verify")["ok"]
    assert not list(Path("/run/domainpilot").glob("rotate-*.pw"))  # no password left behind


# --- disaster recovery ------------------------------------------------------------------


def test_backup_sites_lists_tenant_ids(backups: dict[str, Any]) -> None:
    site_json("system", "backup")
    listed = site_json("system", "backup", "sites")
    mine = [s for s in listed["sites"] if s["domain"] == DOMAIN]
    assert mine and mine[0]["tenant"] == backups["tenant"] and mine[0]["primary"]


def test_create_with_tenant_id_is_refused_for_used_ids(backups: dict[str, Any]) -> None:
    err = site_json("dr.example.com", "create", "--tenant-id", backups["tenant"], ok=False)
    assert "already exists" in json.dumps(err) or "still in use" in json.dumps(err)
    dry = site_json("dr.example.com", "--dry-run", "create", "--tenant-id", "t9876")
    assert dry["tenant"] == "t9876"
