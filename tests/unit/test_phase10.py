"""Phase 10: release identity, upgrade policy, backup key rotation, disaster recovery."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest
from test_phase8 import _ctx, creds_runner, settings

from domainpilot import __version__, release
from domainpilot.backup import config as bconf
from domainpilot.backup.manager import BackupManager
from domainpilot.backup.restic import Restic, Snapshot
from domainpilot.cli import backup_handlers
from domainpilot.core import fsutil, proc
from domainpilot.core.audit import AuditLog
from domainpilot.core.errors import OperationFailed, PreconditionFailed, UsageError
from domainpilot.core.secrets import SecretStore
from domainpilot.security import host_audit as ha
from domainpilot.security.report import SecurityReport
from domainpilot.sites.lifecycle import CreateRequest

# --- versions and the upgrade policy -------------------------------------------------------


def test_version_order_follows_pep440() -> None:
    order = ["0.9.0", "0.10.0.dev1", "0.10.0rc1", "0.10.0rc2", "0.10.0", "0.10.1", "1.0.0"]
    parsed = [release.Version.parse(v) for v in order]
    assert parsed == sorted(parsed)
    assert [str(v) for v in parsed] == order
    assert release.Version.parse(__version__)  # the package's own version is valid


@pytest.mark.parametrize("bad", ["", "1.0", "1.0.0.0", "01.0.0", "1.0.0-rc1", "v1.0.0", "1.0.0\n2"])
def test_invalid_versions(bad: str) -> None:
    with pytest.raises(release.VersionError):
        release.Version.parse(bad)


def test_upgrade_plan() -> None:
    assert release.plan(None, "0.10.0") == "fresh"
    assert release.plan("0.10.0", "0.10.0") == "reinstall"
    assert release.plan("0.0.0", "0.10.0") == "upgrade"
    assert release.plan("0.10.0rc1", "0.10.0") == "upgrade"
    with pytest.raises(release.VersionError, match="refusing to downgrade"):
        release.plan("0.11.0", "0.10.0")
    assert release.plan("0.11.0", "0.10.0", allow_downgrade=True) == "downgrade"


def test_installed_version_and_record(tmp_path: Path) -> None:
    rel, hist, cli = tmp_path / "state" / "release.json", tmp_path / "hist.jsonl", tmp_path / "site"
    assert release.installed_version(rel, legacy_cli=cli) is None  # fresh host
    cli.write_text("")
    assert release.installed_version(rel, legacy_cli=cli) == "0.0.0"  # pre-0.10 install
    entry = release.record(rel, hist, commit="abcdef1234", previous="0.0.0")
    assert entry["version"] == __version__ and entry["previous"] == "0.0.0"
    assert release.installed_version(rel, legacy_cli=cli) == __version__
    release.record(rel, hist, commit="unknown", previous=__version__)
    lines = hist.read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[1])["commit"] == "unknown"
    assert stat.S_IMODE(hist.stat().st_mode) == 0o640
    assert __version__ in release.describe_installed(rel)
    with pytest.raises(release.VersionError, match="commit"):
        release.record(rel, hist, commit="$(id)", previous=None)
    rel.write_text("{not json")
    with pytest.raises(release.VersionError, match="cannot read"):
        release.installed_version(rel, legacy_cli=cli)
    assert "unreadable" in release.describe_installed(rel)
    rel.write_text("[]")
    assert release.describe_installed(rel) == "installed release: unreadable"
    assert "not recorded" in release.describe_installed(tmp_path / "none.json")
    hist.unlink()
    hist.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):  # never appends through a planted symlink
        release.record(tmp_path / "r2.json", hist, commit="abcdef1", previous=None)


def test_describe_installed_without_permission(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(_path: Path) -> str:
        raise PermissionError("denied")

    monkeypatch.setattr(fsutil, "read_text_nofollow", denied)
    assert "sudo" in release.describe_installed(Path("/x"))


def test_installer_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(release, "LEGACY_CLI", tmp_path / "no-cli")
    rel, hist = tmp_path / "release.json", tmp_path / "hist.jsonl"
    assert release.installer_main(["version"]) == 0
    assert capsys.readouterr().out.strip() == __version__
    assert release.installer_main(["plan", str(rel)]) == 0
    assert capsys.readouterr().out.split() == ["fresh", "-", __version__]
    assert release.installer_main(["record", str(rel), str(hist), "0123456789ab"]) == 0
    assert release.installer_main(["plan", str(rel)]) == 0
    assert capsys.readouterr().out.split()[0] == "reinstall"
    rel.write_text(json.dumps({"version": "99.0.0"}))
    assert release.installer_main(["plan", str(rel)]) == release.EXIT_REFUSED
    assert "refusing to downgrade" in capsys.readouterr().err
    assert release.installer_main(["plan", str(rel), "--allow-downgrade"]) == 0
    assert capsys.readouterr().out.startswith("downgrade 99.0.0")
    assert release.installer_main(["bogus"]) == 2


# --- backup master-key rotation ----------------------------------------------------------


class KeyedRepos:
    """Repositories that accept a set of passwords, like restic key files."""

    def __init__(self) -> None:
        self.keys: dict[str, dict[str, str]] = {}  # repo -> key id -> password
        self.fail_add: set[str] = set()
        self.password_files: list[tuple[Path, int]] = []

    def create(self, name: str, password: str) -> None:
        self.keys[name] = {"k" + "0" * 7: password}

    def client(self, name: str, password: str) -> Any:
        repos = self

        class Client:
            def probe(self) -> str:
                if name not in repos.keys:
                    return "absent"
                return "ok" if password in repos.keys[name].values() else "denied"

            def current_key_id(self) -> str:
                return next(k for k, v in repos.keys[name].items() if v == password)

            def add_key(self, pw_file: Path) -> None:
                repos.password_files.append((pw_file, stat.S_IMODE(pw_file.stat().st_mode)))
                if name in repos.fail_add:
                    raise OperationFailed("network down")
                new_id = f"{len(repos.keys[name]):08x}"
                repos.keys[name][new_id] = pw_file.read_text()

            def remove_key(self, key_id: str) -> None:
                del repos.keys[name][key_id]

        return Client()


@pytest.fixture
def rotation(system: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    paths = system["paths"]
    system["manager"]().create(CreateRequest("example.com"))
    system["manager"]().create(CreateRequest("never-backed-up.com"))
    sets = settings(tmp_path)
    sets.save(bconf.BackupConfig(repository=str(tmp_path / "repo")))
    sets.ensure_master()
    manager = BackupManager(
        paths=paths,
        registry=system["registry"],
        settings=sets,
        audit=AuditLog(paths.audit_log, use_syslog=False),
        argv=["site", "system", "backup", "rotate-key"],
        run=lambda argv, **kw: proc.Result(tuple(argv), 0, "", ""),
        hostname="test",
    )
    repos = KeyedRepos()
    tenant = system["registry"].get_site("example.com").tenant_id
    for name in ("system", tenant):
        repos.create(name, sets.repo_password(name))
    monkeypatch.setattr(
        manager,
        "restic_with",
        lambda name, key: repos.client(name, sets.repo_password(name, key=key)),
    )
    return {"manager": manager, "repos": repos, "sets": sets, "tenant": tenant}


def test_rotation_adds_promotes_then_removes(rotation: dict[str, Any]) -> None:
    mgr, repos, sets, tenant = (rotation[k] for k in ("manager", "repos", "sets", "tenant"))
    old_master = sets.secrets.load("master")
    old_pw = sets.repo_password(tenant)
    result = mgr.rotate_key()
    assert result["repositories"]["system"] == "new key added"
    assert result["repositories"][tenant] == "new key added"
    assert "no repository yet" in result["repositories"].values()
    assert sets.rotation_state() == "promoted"
    assert sets.secrets.load("master") != old_master
    assert sets.secrets.load("master-prev") == old_master
    new_pw = sets.repo_password(tenant)
    assert set(repos.keys[tenant].values()) == {old_pw, new_pw}  # old key still works
    assert all(mode == 0o600 and not f.exists() for f, mode in repos.password_files)
    with pytest.raises(PreconditionFailed, match="waiting to be finished"):
        mgr.rotate_key()
    done = mgr.finish_rotation()
    assert done["repositories"][tenant] == "old key removed"
    assert set(repos.keys[tenant].values()) == {new_pw}
    assert sets.rotation_state() == "idle" and not sets.secrets.exists("master-prev")
    with pytest.raises(PreconditionFailed, match="no rotation"):
        mgr.finish_rotation()


def test_interrupted_rotation_resumes(rotation: dict[str, Any]) -> None:
    mgr, repos, sets, tenant = (rotation[k] for k in ("manager", "repos", "sets", "tenant"))
    old_master = sets.secrets.load("master")
    repos.fail_add.add(tenant)
    with pytest.raises(OperationFailed, match="network down"):
        mgr.rotate_key()
    # Nothing promoted, nothing removed: backups keep using the old key.
    assert sets.rotation_state() == "adding" and sets.secrets.load("master") == old_master
    repos.fail_add.clear()
    result = mgr.rotate_key()
    assert result["repositories"]["system"] == "already rotated"
    assert result["repositories"][tenant] == "new key added"
    # Crash between promotion and finish, then finish twice: idempotent.
    repos.keys["system"] = {"k" + "0" * 7: sets.repo_password("system")}  # old key gone already
    assert mgr.finish_rotation()["repositories"]["system"] == "old key already gone"


def test_rotation_refuses_unreadable_repository(rotation: dict[str, Any]) -> None:
    mgr, repos, sets, tenant = (rotation[k] for k in ("manager", "repos", "sets", "tenant"))
    repos.keys[tenant] = {"deadbeef": "somebody-elses-password"}
    with pytest.raises(OperationFailed, match="neither the current nor the new key"):
        mgr.rotate_key()
    assert sets.rotation_state() == "adding"


def test_finish_keeps_old_key_if_new_one_fails(rotation: dict[str, Any]) -> None:
    mgr, repos, sets, tenant = (rotation[k] for k in ("manager", "repos", "sets", "tenant"))
    mgr.rotate_key()
    new_pw = sets.repo_password(tenant)
    repos.keys[tenant] = {k: v for k, v in repos.keys[tenant].items() if v != new_pw}
    with pytest.raises(OperationFailed, match="keeping the old key"):
        mgr.finish_rotation()
    assert sets.rotation_state() == "promoted"


def test_rotation_needs_a_master(tmp_path: Path) -> None:
    with pytest.raises(PreconditionFailed, match="no master key"):
        settings(tmp_path).begin_rotation()


def test_rotate_key_handler(
    system: dict[str, Any], rotation: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backup_handlers, "_manager", lambda ctx: rotation["manager"])
    monkeypatch.setattr(backup_handlers, "_settings", lambda ctx: rotation["sets"])
    ns = argparse.Namespace
    with pytest.raises(UsageError, match="new master key"):
        backup_handlers.rotate_key(_ctx(system), ns(finish=False, show_secret=False))
    started = backup_handlers.rotate_key(_ctx(system), ns(finish=False, show_secret=True))
    assert started.data["master_key"] == rotation["sets"].secrets.load("master").strip()
    assert any("--finish" in line for line in started.text)
    finished = backup_handlers.rotate_key(_ctx(system), ns(finish=True, show_secret=False))
    assert finished.data["step"] == "finished"


def test_restic_key_commands() -> None:
    calls: list[list[str]] = []
    replies = {
        "config": proc.Result((), 1, "", "Fatal: wrong password or no key found\n"),
        "list": proc.Result(
            (),
            0,
            json.dumps([{"current": False, "id": "aaaa1111"}, {"current": True, "id": "bbbb2222"}]),
            "",
        ),
    }

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        calls.append(argv)
        key = "config" if "config" in argv else "list" if "list" in argv else "other"
        return replies.get(key, proc.Result((), 0, "", ""))

    r = Restic({"RESTIC_PASSWORD": "x"}, run=run)
    assert r.probe() == "denied"
    replies["config"] = proc.Result((), 10, "", "Fatal: repository does not exist\n")
    assert r.probe() == "absent"
    replies["config"] = proc.Result((), 1, "", "Fatal: unable to open config file: stat: no such\n")
    assert r.probe() == "absent"
    replies["config"] = proc.Result((), 1, "", "Fatal: connection refused\n")
    with pytest.raises(OperationFailed, match="connection refused"):
        r.probe()
    replies["config"] = proc.Result((), 0, "", "")
    assert r.probe() == "ok"
    assert r.current_key_id() == "bbbb2222"
    r.add_key(Path("/run/domainpilot/x.pw"))
    assert "--new-password-file=/run/domainpilot/x.pw" in calls[-1]
    r.remove_key("aaaa1111")
    assert calls[-1][-1] == "aaaa1111"
    with pytest.raises(Exception, match="invalid restic key id"):
        r.remove_key("--all")
    replies["list"] = proc.Result((), 0, "not json", "")
    with pytest.raises(OperationFailed, match="no JSON"):
        r.current_key_id()
    replies["list"] = proc.Result((), 0, "[]", "")
    with pytest.raises(OperationFailed, match="current key"):
        r.current_key_id()
    r.restore(Snapshot("a" * 64, "aaaaaaaa", "t", [], []), Path("/s"), include="/var/x")
    assert "--include=/var/x" in calls[-1]


# --- disaster recovery: recorded sites, fixed tenant ids ---------------------------------


def test_recorded_sites_from_server_backup(
    system: dict[str, Any],
    rotation: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mgr = rotation["manager"]
    snap = Snapshot("c" * 64, "cccccccc", "2026-11-09T02:30:00", ["/etc"], ["dp", "system"])
    source = tmp_path / "registry-source.sqlite3"
    system["registry"].backup_to(source)

    class SystemRepo:
        def snapshots(self, tags: list[str] | None = None) -> list[Snapshot]:
            return [snap]

        def find(self, snap_id: str) -> Snapshot:
            return snap

        def restore(self, s: Snapshot, target: Path, *, include: str | None = None) -> None:
            dest = target / str(include).lstrip("/")
            dest.parent.mkdir(parents=True)
            shutil.copy(source, dest)

    monkeypatch.setattr(mgr, "restic", lambda name: SystemRepo())
    data = mgr.recorded_sites()
    assert {s["domain"] for s in data["sites"]} == {"example.com", "never-backed-up.com"}
    assert all(s["tenant"].startswith("t") and s["primary"] for s in data["sites"])
    assert not list(mgr.staging_root.iterdir())  # staging cleaned up
    assert mgr.recorded_sites("cccccccc")["snapshot"] == "cccccccc"

    monkeypatch.setattr(backup_handlers, "_manager", lambda ctx: mgr)
    out = backup_handlers.recorded_sites(_ctx(system), argparse.Namespace(snapshot=None))
    assert any("--tenant-id" in line for line in out.text)

    class Empty(SystemRepo):
        def snapshots(self, tags: list[str] | None = None) -> list[Snapshot]:
            return []

        def restore(self, s: Snapshot, target: Path, *, include: str | None = None) -> None:
            pass

    monkeypatch.setattr(mgr, "restic", lambda name: Empty())
    with pytest.raises(PreconditionFailed, match="no server-configuration backup"):
        mgr.recorded_sites()
    with pytest.raises(OperationFailed, match="no registry copy"):
        mgr.recorded_sites("cccccccc")

    class Garbage(SystemRepo):
        def restore(self, s: Snapshot, target: Path, *, include: str | None = None) -> None:
            dest = target / str(include).lstrip("/")
            dest.parent.mkdir(parents=True)
            dest.write_text("not a database")

    monkeypatch.setattr(mgr, "restic", lambda name: Garbage())
    with pytest.raises(OperationFailed, match="cannot read the registry copy"):
        mgr.recorded_sites()


def test_allocate_fixed_tenant_id(system: dict[str, Any]) -> None:
    reg = system["registry"]
    t = reg.allocate_tenant(tenant_id="t0042")
    assert (t.id, t.uid) == ("t0042", 20042)
    with pytest.raises(PreconditionFailed, match="never reused"):
        reg.allocate_tenant(tenant_id="t0042")
    with pytest.raises(PreconditionFailed, match="start at t0001"):
        reg.allocate_tenant(tenant_id="t0000")
    assert reg.allocate_tenant().id == "t0043"  # automatic ids continue above it


def test_create_with_tenant_id(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    mgr = system["manager"]
    dry = mgr(dry_run=True).create(CreateRequest("restored.com", tenant_id="t0007"))
    assert dry["tenant"] == "t0007"
    created = mgr().create(CreateRequest("restored.com", tenant_id="t0007"))
    assert created["tenant"] == "t0007"
    # Leftovers of the id on this host: refused before anything is allocated.
    (system["paths"].tenants / "t0009").mkdir()
    with pytest.raises(PreconditionFailed, match="still in use"):
        mgr().create(CreateRequest("other.com", tenant_id="t0009"))
    import pwd

    monkeypatch.setattr(
        pwd, "getpwuid", lambda uid: pwd.struct_passwd(("someone", "x", uid, uid, "", "", ""))
    )
    with pytest.raises(PreconditionFailed, match="uid 20011"):
        mgr().create(CreateRequest("third.com", tenant_id="t0011"))
    assert system["registry"].get_site("other.com") is None


# --- audit: versioned code directory -----------------------------------------------------


def test_code_tree_symlink_rules(tmp_path: Path) -> None:
    view = ha.HostView(root=tmp_path)
    code = tmp_path / "usr/lib/domainpilot"
    (code / "releases" / "0.10.0").mkdir(parents=True)
    for d in (code, code / "releases", code / "releases" / "0.10.0"):
        d.chmod(0o755)
    (code / "current").symlink_to("releases/0.10.0")
    rule = ha.PathRule("/usr/lib/domainpilot", 0o755, os.getuid(), "C", recursive_files=0o755)
    rep = SecurityReport("x")
    ha.check_paths(view, rep, [rule])
    assert rep.worst == "ok", rep.findings[0].detail
    (code / "evil").symlink_to("/tmp")
    rep = SecurityReport("x")
    ha.check_paths(view, rep, [rule])
    assert rep.worst != "ok" and "evil: symlink leaving the tree" in rep.findings[0].detail


def test_secret_store_used_by_rotation_is_encrypted(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    store = SecretStore(tmp_path / "s" / "backup", "backup", run=creds_runner(calls))
    sets = bconf.BackupSettings(tmp_path, store)
    sets.ensure_master()
    sets.begin_rotation()
    sets.begin_rotation()  # idempotent: the pending key is not replaced
    assert sum("--name=backup-master-next" in c for c in calls if c[1] == "encrypt") == 1
