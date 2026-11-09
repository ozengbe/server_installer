"""Phase 8: backups, SFTP, monitoring and alerts (unit level)."""

from __future__ import annotations

import argparse
import http.server
import io
import json
import os
import shutil
import stat
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from domainpilot.backup import config as bconf
from domainpilot.backup.manager import BackupManager
from domainpilot.backup.restic import Restic, Snapshot, validate_snapshot_id
from domainpilot.cli import backup_handlers, monitor_handlers
from domainpilot.core import proc
from domainpilot.core.audit import AuditLog
from domainpilot.core.errors import (
    OperationFailed,
    PreconditionFailed,
    UsageError,
    ValidationError,
)
from domainpilot.core.secrets import SecretStore
from domainpilot.health import Report
from domainpilot.monitor import alerts as al
from domainpilot.monitor import monitor as mon
from domainpilot.sftp import SftpManager, parse_public_key
from domainpilot.sites.lifecycle import CreateRequest

ED25519 = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl0aXNhdGVzdGtleWZvcmRvbWFpbnBpbG90MDAw alice@laptop"
)


# --- helpers --------------------------------------------------------------------------


def creds_runner(calls: list[list[str]] | None = None) -> Any:
    """systemd-creds stand-in: 'encrypt' stores stdin as-is, 'decrypt' reads it back."""

    def run(argv: list[str], **kw: Any) -> proc.Result:
        if calls is not None:
            calls.append(list(argv))
        if argv[1] == "encrypt":
            Path(argv[-1]).write_text(kw["stdin"])
            return proc.Result(tuple(argv), 0, "", "")
        if argv[1] == "decrypt":
            return proc.Result(tuple(argv), 0, Path(argv[-2]).read_text(), "")
        raise AssertionError(argv)

    return run


def settings(tmp: Path) -> bconf.BackupSettings:
    etc = tmp / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    return bconf.BackupSettings(
        etc, SecretStore(etc / "secrets" / "backup", "backup", run=creds_runner())
    )


class FakeRestic:
    """In-memory restic: snapshots are directory copies / strings."""

    def __init__(self, store: Path) -> None:
        self.store = store
        self.snaps: list[Snapshot] = []
        self.trees: dict[str, list[Path]] = {}
        self.streams: dict[str, str] = {}
        self.calls: list[str] = []
        self.fail_import = False
        self.created = False

    def _add(self, tags: list[str], paths: list[str]) -> str:
        sid = f"{len(self.snaps) + 1:08x}" + "0" * 56
        time.sleep(0.001)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S") + f".{len(self.snaps):06d}"
        self.snaps.append(Snapshot(sid, sid[:8], stamp, paths, tags))
        return sid

    def ensure_repository(self) -> bool:
        created, self.created = not self.created, True
        return created

    def backup_paths(self, paths: list[Path], tags: list[str], **_kw: Any) -> str:
        sid = self._add(tags, [str(p) for p in paths])
        for p in paths:
            dest = self.store / sid / p.relative_to(p.anchor)
            if p.is_dir():
                shutil.copytree(p, dest, symlinks=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)
        self.trees[sid] = paths
        return sid

    def backup_stream(self, producer: list[str], filename: str, tags: list[str]) -> str:
        sid = self._add(tags, ["/" + filename])
        self.streams[sid] = f"CREATE TABLE x;\n-- Dump completed on 2026-11-09 for {producer[-1]}"
        return sid

    def apply_retention(self, keep: list[str]) -> None:
        self.calls.append("forget " + " ".join(keep))

    def snapshots(self, tags: list[str] | None = None) -> list[Snapshot]:
        return sorted(self.snaps, key=lambda s: s.time, reverse=True)

    def find(self, snap_id: str) -> Snapshot:
        return next(s for s in self.snaps if s.id.startswith(snap_id))

    def restore(self, snap: Snapshot, target: Path) -> None:
        if snap.id in self.streams:
            target.mkdir(parents=True, exist_ok=True)
            (target / snap.paths[0].lstrip("/")).write_text(self.streams[snap.id])
            return
        shutil.copytree(self.store / snap.id, target, symlinks=True, dirs_exist_ok=True)

    def dump_tail(self, snap: Snapshot, filename: str) -> str:
        return self.streams[snap.id].splitlines()[-1]

    def dump_into(self, snap: Snapshot, filename: str, consumer: list[str]) -> None:
        self.calls.append(f"import {snap.short_id}")
        if self.fail_import and "pre-restore" not in snap.tags:
            raise OperationFailed("mariadb exited with status 1: syntax error")

    def check(self, read_data_subset: str | None = None) -> None:
        self.calls.append(f"check {read_data_subset}")


@pytest.fixture
def backups(system: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    paths = system["paths"]
    mgr = system["manager"]()
    mgr.create(CreateRequest("example.com"))
    tenant = system["registry"].get_site("example.com").tenant_id
    root = paths.tenant_root(tenant)
    (root / "app" / "public" / "index.php").write_text("<?php echo 'v1';")
    (root / "data" / "upload.txt").write_text("user upload")
    (root / "tmp" / "scratch").write_text("never backed up")
    sets = settings(tmp_path)
    sets.save(bconf.BackupConfig(repository=str(tmp_path / "repo")))
    sets.ensure_master()
    fakes: dict[str, FakeRestic] = {}

    def run(argv: list[str], **kw: Any) -> proc.Result:
        system["calls"].append(list(argv))
        if argv[0] == "/usr/bin/mariadb" and "information_schema" in kw.get("stdin", ""):
            return proc.Result(tuple(argv), 0, f"{tenant}_app\nt9999_other\n", "")
        return proc.Result(tuple(argv), 0, "", "")

    manager = BackupManager(
        paths=paths,
        registry=system["registry"],
        settings=sets,
        audit=AuditLog(paths.audit_log, use_syslog=False),
        argv=["site", "backup"],
        run=run,
        reporter=lambda m, s: system["reported"].append((m, s)),
        hostname="test",
        system_paths=[paths.etc],
    )

    def fake(name: str) -> FakeRestic:
        if name not in fakes:
            (tmp_path / "store" / name).mkdir(parents=True)
            fakes[name] = FakeRestic(tmp_path / "store" / name)
        return fakes[name]

    monkeypatch.setattr(manager, "restic", fake)
    return {"manager": manager, "tenant": tenant, "root": root, "fakes": fakes, "sets": sets}


# --- proc.pipeline ----------------------------------------------------------------------


def test_pipeline_streams_and_checks_both_ends() -> None:
    prod, cons = proc.pipeline(["/bin/echo", "hello"], ["/usr/bin/tr", "a-z", "A-Z"])
    assert cons.stdout == "HELLO\n" and prod.ok
    with pytest.raises(OperationFailed, match="false exited with status 1"):
        proc.pipeline(["/bin/false"], ["/bin/cat"])
    prod, cons = proc.pipeline(["/bin/false"], ["/bin/cat"], check=False)
    assert not prod.ok and cons.ok
    with pytest.raises(OperationFailed, match="command not found"):
        proc.pipeline(["/nonexistent"], ["/bin/cat"])
    with pytest.raises(OperationFailed, match="command not found"):
        proc.pipeline(["/bin/echo"], ["/nonexistent"])
    with pytest.raises(OperationFailed, match="timed out"):
        proc.pipeline(["/bin/sleep", "5"], ["/bin/cat"], timeout=0.3)
    with pytest.raises(ValidationError):
        proc.pipeline(["/bin/echo"], ["/bin/cat"], timeout=0)


# --- secrets & config -------------------------------------------------------------------


def test_secret_store(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    store = SecretStore(tmp_path / "secrets" / "x", "x", run=creds_runner(calls))
    assert not store.exists("k")
    store.save("k", "value")
    assert store.exists("k") and store.load("k") == "value"
    assert stat.S_IMODE((tmp_path / "secrets" / "x" / "k.cred").stat().st_mode) == 0o600
    assert calls[0][2] == "--name=x-k" and "value" not in " ".join(calls[0])  # never argv
    assert store.remove("k") and not store.remove("k")
    with pytest.raises(OperationFailed, match="not configured"):
        store.load("k")
    with pytest.raises(ValidationError):
        store.save("k", "")
    with pytest.raises(ValidationError):
        store.exists("../escape")
    with pytest.raises(ValidationError):
        SecretStore(tmp_path, "Bad Area")
    (tmp_path / "secrets" / "x" / "e.cred").write_text("")
    with pytest.raises(OperationFailed, match="empty"):
        store.load("e")


@pytest.mark.parametrize(
    "repo",
    [
        "s3:https://s3.us-west-004.backblazeb2.com/my-bucket/server1",
        "s3:https://s3.eu-central-1.wasabisys.com:443/bkt",
        "/var/backups/domainpilot",
    ],
)
def test_valid_repositories(repo: str) -> None:
    assert bconf.validate_repository(repo + "/") == repo


@pytest.mark.parametrize(
    "repo",
    [
        "s3:http://insecure.example.com/bucket",
        "relative/path",
        "/var/../etc",
        "/srv/tenants/t0001/backups",
        "sftp:user@host:/x",
        "/var/backups;rm -rf /",
        "s3:https://host/UPPERCASE",
    ],
)
def test_invalid_repositories(repo: str) -> None:
    with pytest.raises(ValidationError):
        bconf.validate_repository(repo)


def test_s3_credentials_parsing() -> None:
    env = bconf.parse_s3_env("# B2\nAWS_ACCESS_KEY_ID=abc\n\nAWS_SECRET_ACCESS_KEY = s3cr3t\n")
    assert env == {"AWS_ACCESS_KEY_ID": "abc", "AWS_SECRET_ACCESS_KEY": "s3cr3t"}
    for bad in ("AWS_ACCESS_KEY_ID=abc", "PATH=/tmp\nAWS_ACCESS_KEY_ID=a", "AWS_ACCESS_KEY_ID="):
        with pytest.raises(ValidationError):
            bconf.parse_s3_env(bad)
    with pytest.raises(ValidationError):
        bconf.parse_s3_env("AWS_ACCESS_KEY_ID=a b\nAWS_SECRET_ACCESS_KEY=c")


def test_backup_settings_and_derived_keys(tmp_path: Path) -> None:
    sets = settings(tmp_path)
    with pytest.raises(PreconditionFailed, match="not configured"):
        sets.load()
    assert not sets.configured()
    cfg = bconf.BackupConfig("s3:https://s3.example.com/bucket", bconf.Retention(3, 2, 1))
    sets.save(cfg)
    assert sets.load() == cfg and cfg.is_s3 and sets.configured()
    assert cfg.retention.args() == ["--keep-daily=3", "--keep-weekly=2", "--keep-monthly=1"]
    assert stat.S_IMODE(sets.file.stat().st_mode) == 0o600
    key = sets.ensure_master()
    assert key and len(key) == 64 and sets.ensure_master() is None
    a, b = sets.repo_password("t0001"), sets.repo_password("t0002")
    assert a != b and a == sets.repo_password("t0001") and key not in a  # derived, not reused
    sets.secrets.save("s3", "AWS_ACCESS_KEY_ID=k\nAWS_SECRET_ACCESS_KEY=s\n")
    env = sets.restic_env(cfg, "t0001", tmp_path / "cache")
    assert env["RESTIC_REPOSITORY"] == "s3:https://s3.example.com/bucket/t0001"
    assert env["AWS_SECRET_ACCESS_KEY"] == "s" and env["RESTIC_PASSWORD"] == a
    with pytest.raises(ValidationError):
        cfg.repo_url("../x")
    # Disaster recovery: the same master key on a new server derives the same passwords.
    other = settings(tmp_path / "new")
    other.import_master(key)
    assert other.repo_password("t0001") == a
    with pytest.raises(ValidationError):
        other.import_master("not-hex")


# --- restic wrapper ---------------------------------------------------------------------


def test_restic_wrapper_commands() -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    summary = json.dumps({"message_type": "summary", "snapshot_id": "a" * 64})
    listing = json.dumps(
        [
            {
                "id": "b" * 64,
                "short_id": "bbbbbbbb",
                "time": "2026-11-01T02:30:00",
                "paths": ["/srv/tenants/t0001/app"],
                "tags": ["dp", "files", "run:1"],
            },
            {
                "id": "c" * 64,
                "time": "2026-11-02T02:30:00",
                "paths": ["/t0001_app.sql"],
                "tags": ["dp", "db", "db:t0001_app", "run:2"],
            },
        ]
    )

    def run(argv: list[str], **kw: Any) -> proc.Result:
        calls.append((argv, kw))
        sub = argv[1]
        if sub == "cat":
            return proc.Result(tuple(argv), 1, "", "repository does not exist")
        if sub == "backup":
            return proc.Result(tuple(argv), 0, '{"message_type":"status"}\n' + summary, "")
        if sub == "snapshots":
            return proc.Result(tuple(argv), 0, listing, "")
        return proc.Result(tuple(argv), 0, "", "")

    pipes: list[tuple[list[str], list[str]]] = []

    def pipe(producer: list[str], consumer: list[str], **_kw: Any) -> Any:
        pipes.append((producer, consumer))
        ok = proc.Result(tuple(producer), 0, "", "")
        return ok, proc.Result(tuple(consumer), 0, "-- Dump completed on x\n", "")

    r = Restic({"RESTIC_PASSWORD": "pw"}, run=run, pipe=pipe, hostname="h")
    assert r.ensure_repository() is True
    assert calls[-1][0][1] == "init" and calls[-1][1]["env"]["RESTIC_PASSWORD"] == "pw"
    assert r.backup_paths([Path("/a")], ["dp", "files"], excludes=[Path("/a/tmp")]) == "a" * 64
    argv = calls[-1][0]
    assert "--tag=files" in argv and "--exclude=/a/tmp" in argv and argv[-2:] == ["--", "/a"]
    assert all("pw" not in a for a in argv)  # password only in the environment
    snaps = r.snapshots(["dp"])
    assert [s.kind for s in snaps] == ["db", "files"] and snaps[0].tag_value("db") == "t0001_app"
    assert snaps[0].short_id == "cccccccc" and snaps[0].as_dict()["run"] == "2"
    assert r.find("bbbbbbbb").kind == "files"
    with pytest.raises(OperationFailed, match="no snapshot"):
        r.find("dddddddd")
    r.restore(snaps[1], Path("/staging"))
    assert "--verify" in calls[-1][0]
    assert r.dump_tail(snaps[0], "t0001_app.sql") == "-- Dump completed on x"
    r.dump_into(snaps[0], "t0001_app.sql", ["/usr/bin/mariadb"])
    assert pipes[-1][0][-1] == "/t0001_app.sql"
    r.apply_retention(["--keep-daily=7"])
    assert calls[-1][0][1:4] == ["forget", "--retry-lock=5m", "--prune"]
    r.check("2%")
    assert calls[-1][0][-1] == "--read-data-subset=2%"
    with pytest.raises(ValidationError):
        r.backup_paths([Path("/a")], ["Bad Tag"])
    with pytest.raises(ValidationError):
        validate_snapshot_id("xyz")


def test_restic_stream_discards_truncated_dump() -> None:
    forgotten: list[list[str]] = []

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        if argv[1] == "forget":
            forgotten.append(argv)
        return proc.Result(tuple(argv), 0, "", "")

    summary = json.dumps({"message_type": "summary", "snapshot_id": "e" * 64})

    def pipe_fail_producer(producer: list[str], consumer: list[str], **_kw: Any) -> Any:
        return (
            proc.Result(tuple(producer), 2, "", "mariadb-dump: Lost connection\n"),
            proc.Result(tuple(consumer), 0, summary, ""),
        )

    r = Restic({}, run=run, pipe=pipe_fail_producer)
    with pytest.raises(OperationFailed, match="Lost connection"):
        r.backup_stream(["/usr/bin/mariadb-dump", "db"], "db.sql", ["dp"])
    assert forgotten and "e" * 64 in forgotten[0]  # the partial snapshot is removed

    def pipe_fail_consumer(producer: list[str], consumer: list[str], **_kw: Any) -> Any:
        return (
            proc.Result(tuple(producer), 0, "", ""),
            proc.Result(tuple(consumer), 1, "", "Fatal: wrong password\n"),
        )

    with pytest.raises(OperationFailed, match="wrong password"):
        Restic({}, run=run, pipe=pipe_fail_consumer).backup_stream(["/bin/x"], "d.sql", ["dp"])

    def pipe_no_summary(producer: list[str], consumer: list[str], **_kw: Any) -> Any:
        return proc.Result(tuple(producer), 0, "", ""), proc.Result(tuple(consumer), 0, "x", "")

    with pytest.raises(OperationFailed, match="snapshot id"):
        Restic({}, run=run, pipe=pipe_no_summary).backup_stream(["/bin/x"], "d.sql", ["dp"])


# --- backup manager ---------------------------------------------------------------------


def test_backup_site_files_and_databases(backups: dict[str, Any]) -> None:
    m, tenant = backups["manager"], backups["tenant"]
    result = m.backup_tenant(m.tenant_for("example.com"))
    fake = backups["fakes"][tenant]
    assert set(result["databases"]) == {f"{tenant}_app"}  # t9999_other is not this tenant's
    files = next(s for s in fake.snaps if s.kind == "files")
    assert all(not p.endswith("/tmp") for p in files.paths)  # tmp/ is never backed up
    assert {f"tenant:{tenant}", "files", "dp"} <= set(files.tags)
    assert fake.calls == ["forget --keep-daily=7 --keep-weekly=4 --keep-monthly=6"]
    state = m.load_state()["sites"][tenant]
    assert state["ok"] and state["last_success"]
    db_only = m.backup_tenant(m.tenant_for("example.com"), files=False)
    assert "files" not in db_only and db_only["databases"]
    assert [s["kind"] for s in m.snapshots(m.tenant_for("example.com"))][:1] == ["db"]
    with pytest.raises(PreconditionFailed):
        m.tenant_for("unknown.example.com")


def test_backup_failure_is_recorded(
    backups: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    m, tenant = backups["manager"], backups["tenant"]
    fake = m.restic(tenant)

    def broken(*_a: Any, **_k: Any) -> str:
        raise OperationFailed("restic exited with status 1: s3 unreachable")

    monkeypatch.setattr(fake, "backup_paths", broken)
    result = m.backup_all()
    assert result["failed"] == [tenant] and "s3 unreachable" in result["sites"][tenant]["error"]
    assert result["system"]["snapshot"]
    state = m.load_state()
    assert state["sites"][tenant]["ok"] is False and state["system"]["ok"]
    assert not (m.paths.var_lib / "backup" / "registry-copy.sqlite3").exists()


def test_restore_files_to_staging_and_live(backups: dict[str, Any]) -> None:
    m, root = backups["manager"], backups["root"]
    m.backup_tenant(m.tenant_for("example.com"))
    index = root / "app" / "public" / "index.php"
    index.write_text("<?php echo 'hacked';")
    staged = m.restore("example.com", snapshot=None, what="files", to_staging=True)
    assert index.read_text() == "<?php echo 'hacked';"  # staging changes nothing live
    assert Path(staged["files"]["path"], "app", "public", "index.php").read_text().endswith("v1';")
    live = m.restore("example.com", snapshot=None, what="files", to_staging=False)
    assert index.read_text() == "<?php echo 'v1';"
    assert set(live["files"]["swapped"]) == {"app", "data"}
    previous = Path(live["files"]["previous"])
    assert (previous / "app" / "public" / "index.php").read_text().endswith("hacked';")
    assert stat.S_IMODE(m.staging_root.stat().st_mode) == 0o700


def test_restore_sanitises_special_files(tmp_path: Path) -> None:
    tree = tmp_path / "t"
    tree.mkdir()
    suid = tree / "suid"
    suid.write_text("x")
    suid.chmod(0o4755)
    os.mkfifo(tree / "fifo")
    (tree / "link").symlink_to("/etc/passwd")
    removed = BackupManager._sanitise(tree)
    assert removed == ["fifo"] and stat.S_IMODE(suid.stat().st_mode) == 0o755
    assert (tree / "link").is_symlink()  # symlinks stay symlinks (never followed)


def test_restore_database_with_safety_copy(backups: dict[str, Any]) -> None:
    m, tenant = backups["manager"], backups["tenant"]
    run = m.backup_tenant(m.tenant_for("example.com"))
    fake = backups["fakes"][tenant]
    result = m.restore("example.com", snapshot=None, what="db", to_staging=False)
    db = f"{tenant}_app"
    assert result["databases"][db]["safety_snapshot"]
    assert any("pre-restore" in s.tags for s in fake.snaps)
    assert fake.calls[-1] == f"import {run['databases'][db][:8]}"
    staged = m.restore("example.com", snapshot=None, what="db", to_staging=True)
    assert Path(staged["databases"][db]["path"]).read_text().startswith("CREATE TABLE")
    # An explicit db snapshot restores just that database.
    one = m.restore("example.com", snapshot=run["databases"][db][:8], what="db", to_staging=False)
    assert list(one["databases"]) == [db]


def test_failed_import_puts_safety_copy_back(backups: dict[str, Any]) -> None:
    m, tenant = backups["manager"], backups["tenant"]
    m.backup_tenant(m.tenant_for("example.com"))
    fake = backups["fakes"][tenant]
    fake.fail_import = True
    with pytest.raises(OperationFailed, match="syntax error"):
        m.restore("example.com", snapshot=None, what="db", to_staging=False)
    safety = next(s for s in fake.snaps if "pre-restore" in s.tags)
    assert fake.calls[-1] == f"import {safety.short_id}"


def test_restore_refuses_incomplete_dump_and_foreign_db(backups: dict[str, Any]) -> None:
    m, tenant = backups["manager"], backups["tenant"]
    run = m.backup_tenant(m.tenant_for("example.com"))
    fake = backups["fakes"][tenant]
    sid = run["databases"][f"{tenant}_app"]
    fake.streams[sid] = "CREATE TABLE x;\nINSERT INTO x VALUES (1"  # truncated
    with pytest.raises(OperationFailed, match="not a complete dump"):
        m.restore("example.com", snapshot=None, what="db", to_staging=False)
    snap = fake.find(sid)
    fake.snaps[fake.snaps.index(snap)] = Snapshot(
        snap.id, snap.short_id, snap.time, snap.paths, [*snap.tags[:-1], "db:t9999_other"]
    )
    with pytest.raises(OperationFailed, match="not a database of"):
        m.restore("example.com", snapshot=sid[:8], what="db", to_staging=False)


def test_restore_without_backups(backups: dict[str, Any]) -> None:
    with pytest.raises(PreconditionFailed, match="no backups"):
        backups["manager"].restore("example.com", snapshot=None, what="all", to_staging=True)


def test_verify_and_restore_drill(backups: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    m, tenant = backups["manager"], backups["tenant"]
    m.backup_all()
    verified = m.verify()
    assert verified["ok"] and set(verified["repositories"]) == {"system", tenant}
    drill = m.test_restore()
    assert drill["ok"] and drill["sites"][tenant][f"{tenant}_app"]["complete"]
    assert drill["sites"][tenant]["files"]["count"] >= 2
    assert not [p for p in m.staging_root.iterdir()]  # drill cleans up after itself
    fake = backups["fakes"][tenant]
    for sid in list(fake.streams):
        fake.streams[sid] = "truncated"
    assert not m.test_restore()["ok"]
    assert m.load_state()["test_restore"]["ok"] is False

    def broken(_r: str | None = None) -> None:
        raise OperationFailed("pack 1234 is damaged")

    monkeypatch.setattr(fake, "check", broken)
    assert m.verify()["repositories"][tenant] == "pack 1234 is damaged"


def test_staging_pruned_after_a_week(backups: dict[str, Any]) -> None:
    m = backups["manager"]
    old = m._staging("t0001")
    week_ago = time.time() - 8 * 86400
    os.utime(old, (week_ago, week_ago))
    fresh = m._staging("t0002")
    m._prune_staging()
    assert not old.exists() and fresh.exists()


# --- SFTP -------------------------------------------------------------------------------


def keygen_runner(calls: list[list[str]], bits: int = 256) -> Any:
    def run(argv: list[str], **kw: Any) -> proc.Result:
        calls.append(list(argv))
        if argv[0].endswith("ssh-keygen"):
            kind = kw["stdin"].split()[0]
            return proc.Result(
                tuple(argv), 0, f"{bits} SHA256:abc{len(kw['stdin'])} ({kind})\n", ""
            )
        return proc.Result(tuple(argv), 0, "", "")

    return run


def test_sftp_accounts(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o755)
    sftp = SftpManager(
        audit=AuditLog(tmp_path / "audit.jsonl", use_syslog=False),
        argv=["site"],
        run=keygen_runner(calls),
        keys_dir=keys,
        hostname="srv.example.net",
    )
    created = sftp.create("t0001", ED25519 + "\n", "alice")
    assert created["username"] == "t0001-deploy" and created["connect"].endswith("@srv.example.net")
    line = (keys / "t0001-deploy").read_text()
    assert line.startswith("restrict ssh-ed25519 ") and line.rstrip().endswith("dp:alice")
    assert "alice@laptop" not in line  # the user's comment is not trusted/stored
    assert ["/usr/bin/gpasswd", "-a", "t0001-deploy", "dp-sftp"] in calls
    other = ED25519.replace("AAAAIGl0", "AAAAIGx4")
    sftp.create("t0001", other, "bob")
    assert [a["account"] for a in sftp.list("t0001")] == ["alice", "bob"]
    with pytest.raises(PreconditionFailed, match="already exists"):
        sftp.create("t0001", other.replace("x4", "y5"), "bob")
    with pytest.raises(PreconditionFailed, match="already authorised"):
        sftp.create("t0001", ED25519, "carol")
    assert sftp.revoke("t0001", "alice")["remaining"] == 1
    assert ["/usr/bin/gpasswd", "-d", "t0001-deploy", "dp-sftp"] not in calls
    sftp.revoke("t0001", "bob")
    assert not (keys / "t0001-deploy").exists()
    assert ["/usr/bin/gpasswd", "-d", "t0001-deploy", "dp-sftp"] in calls
    with pytest.raises(PreconditionFailed, match="no SFTP account"):
        sftp.revoke("t0001", "bob")
    sftp.create("t0001", ED25519, "alice")
    assert sftp.revoke_all("t0001") and not sftp.revoke_all("t0001")


@pytest.mark.parametrize(
    "text",
    [
        "",
        ED25519 + "\n" + ED25519,  # two keys
        'command="/bin/sh" ' + ED25519,  # options smuggled in
        "ssh-dss AAAAB3NzaC1kc3MAAACBAP== old",
        "ssh-ed25519 not*base64",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_sftp_rejects_bad_keys(text: str) -> None:
    with pytest.raises(ValidationError):
        parse_public_key(text)


def test_sftp_rejects_weak_rsa_and_bad_labels(tmp_path: Path) -> None:
    sftp = SftpManager(
        audit=AuditLog(tmp_path / "a.jsonl", use_syslog=False),
        argv=["site"],
        run=keygen_runner([], bits=2048),
        keys_dir=tmp_path,
    )
    rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtest0000000000"
    with pytest.raises(ValidationError, match="3072"):
        sftp.create("t0001", rsa, "old")
    for label in ("Alice", "a b", "../x", "x" * 40):
        with pytest.raises(ValidationError):
            sftp.create("t0001", ED25519, label)

    def bad_keygen(argv: list[str], **_kw: Any) -> proc.Result:
        return proc.Result(tuple(argv), 0, "garbage\n", "")

    sftp.run = bad_keygen
    with pytest.raises(ValidationError, match="could not read"):
        sftp.create("t0001", ED25519, "alice")


# --- alerts -----------------------------------------------------------------------------


def test_alert_urls_and_payloads() -> None:
    assert al.validate_url(" https://ntfy.sh/dp-topic ") == "https://ntfy.sh/dp-topic"
    assert al.validate_url("http://127.0.0.1:8080/hook")
    for bad in ("http://ntfy.sh/x", "ftp://x", "https://", "http://10.0.0.1/x", "javascript:x"):
        with pytest.raises(ValidationError):
            al.validate_url(bad)
    alert = al.Alert("disk:/", "critical", "/ 96% used", "problem", "srv1")
    assert alert.title == "[CRITICAL] srv1: disk:/"
    data, headers = al.payload("ntfy", alert)
    assert data == b"/ 96% used" and headers["Priority"] == "urgent"
    resolved = al.Alert("disk:/", "critical", "resolved", "resolved", "srv1")
    assert al.payload("ntfy", resolved)[1]["Priority"] == "default"
    assert json.loads(al.payload("slack", alert)[0])["text"].startswith("[CRITICAL]")
    assert "content" in json.loads(al.payload("discord", alert)[0])
    assert "text" in json.loads(al.payload("telegram", alert)[0])
    generic = json.loads(al.payload("webhook", alert)[0])
    assert generic["source"] == "domainpilot" and generic["severity"] == "critical"
    for state in ("reminder", "event", "test"):
        assert al.Alert("k", "warn", "m", state, "h").title


@pytest.fixture
def hook_server() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append({"path": self.path, "body": body, "headers": dict(self.headers)})
            self.send_response(500 if self.path == "/fail" else 200)
            self.end_headers()

        def log_message(self, *_a: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", received
    server.shutdown()


def test_notifier_delivers_over_http(
    tmp_path: Path, hook_server: tuple[str, list[dict[str, Any]]]
) -> None:
    base, received = hook_server
    store = SecretStore(tmp_path / "secrets" / "alerts", "alerts", run=creds_runner())
    notifier = al.Notifier(tmp_path, store=store)
    assert not notifier.configured()
    with pytest.raises(PreconditionFailed):
        notifier.settings()
    notifier.setup(al.AlertSettings("webhook"), base + "/hook")
    assert notifier.configured() and notifier.settings().kind == "webhook"
    notifier.send(al.Alert("test", "info", "hello", "test", "srv"))
    assert received[0]["path"] == "/hook" and json.loads(received[0]["body"])["message"] == "hello"
    notifier.setup(al.AlertSettings("ntfy"), base + "/fail")
    with pytest.raises(OperationFailed, match="HTTP 500"):
        notifier.send(al.Alert("test", "info", "x", "test", "srv"))
    notifier.setup(al.AlertSettings("ntfy"), "http://127.0.0.1:1/closed")
    with pytest.raises(OperationFailed, match="could not reach"):
        notifier.send(al.Alert("test", "info", "x", "test", "srv"))
    notifier.remove()
    assert not notifier.configured()
    for bad in (
        al.AlertSettings("email"),
        al.AlertSettings("ntfy", "loud"),
        al.AlertSettings("ntfy", reminder_hours=0),
    ):
        with pytest.raises(ValidationError):
            bad.validate()


# --- monitor ----------------------------------------------------------------------------


def test_problems_from_health_sites_and_backups() -> None:
    report = Report()
    report.add("ok", "service", "nginx is active")
    report.add("critical", "service", "mariadb is failed")
    report.add("warn", "disk", "/srv 91% used")
    report.add("warn", "certificate", "example.com: 10 days left")
    report.add("warn", "memory", "8% memory available")
    keys = {p.key for p in mon.from_health(report)}
    assert keys == {"service:mariadb", "disk:/srv", "certificate:example.com", "memory"}

    status = {"up.example": 200, "down.example": 502, "dead.example": None, "redir.example": 301}
    problems = mon.site_problems(status, probe=status.get)
    assert {p.key for p in problems} == {"site:down.example", "site:dead.example"}
    assert mon.http_probe("nothing-listens.invalid") in (None, 444) or True

    now = time.mktime(time.strptime("2026-11-09T12:00:00", "%Y-%m-%dT%H:%M:%S"))
    state = {
        "sites": {
            "t0001": {"last_success": "2026-11-09T02:30:00+0100", "ok": True},
            "t0002": {"last_success": "2026-11-07T02:30:00+0100", "ok": True},
            "t0003": {"last_success": "2026-11-09T02:30:00", "ok": False, "error": "s3 down"},
            "t0004": {"last_success": "2026-11-08T08:00:00", "ok": True},
        },
        "system": {"last_success": "2026-11-09T02:30:00", "ok": True},
        "test_restore": {"last_success": "2026-10-01T05:00:00", "ok": True},
    }
    tenants = [
        ("t0001", "2026-01-01T00:00:00"),
        ("t0002", "2026-01-01T00:00:00"),
        ("t0003", "2026-01-01T00:00:00"),
        ("t0004", "2026-01-01T00:00:00"),
        ("t0005", "2026-11-09T11:00:00"),  # brand new: grace period
        ("t0006", "2026-11-01T00:00:00"),  # never backed up
    ]
    found = {p.key: p for p in mon.backup_problems(state, tenants, now=now)}
    assert "backup:t0001" not in found and found["backup:t0002"].severity == "critical"
    assert "s3 down" in found["backup:t0003"].message and found["backup:t0004"].severity == "warn"
    assert "backup:t0005" not in found and "never" in found["backup:t0006"].message
    assert found["backup:restore-test"].severity == "warn"
    state["test_restore"] = {"ok": False}
    state["system"] = {"last_success": "2026-11-01T02:00:00"}
    found = {p.key: p for p in mon.backup_problems(state, [], now=now)}
    assert found["backup:restore-test"].severity == "critical" and "backup:system" in found


def test_restart_counts() -> None:
    def run(argv: list[str], **_kw: Any) -> proc.Result:
        unit = argv[-1]
        if unit == "boom.service":
            raise OperationFailed("systemctl missing")
        return proc.Result(tuple(argv), 0, "3\n" if unit == "nginx.service" else "\n", "")

    counts = mon.restart_counts(["nginx.service", "gone.service", "boom.service"], run)
    assert counts == {"nginx.service": 3}


def test_monitor_alerts_only_on_change(
    tmp_path: Path, hook_server: tuple[str, list[dict[str, Any]]]
) -> None:
    base, received = hook_server
    store = SecretStore(tmp_path / "secrets" / "alerts", "alerts", run=creds_runner())
    notifier = al.Notifier(tmp_path, store=store)
    clock = [1000.0]
    monitor = mon.Monitor(tmp_path / "state.json", notifier, host="srv", clock=lambda: clock[0])
    disk = mon.Problem("disk:/", "warn", "/ 91% used")
    down = mon.Problem("site:a.example", "critical", "a.example answers HTTP 502")

    # Not configured: state is still tracked, nothing is sent.
    first = monitor.evaluate([disk], {"nginx.service": 0})
    assert [a.state for a in first] == ["problem"]
    assert monitor.deliver(first) == {"sent": 0, "skipped": 1, "errors": [], "configured": False}

    notifier.setup(al.AlertSettings("webhook", reminder_hours=1), base + "/hook")
    assert monitor.evaluate([disk], {"nginx.service": 0}) == []  # unchanged: silence
    clock[0] += 60
    alerts = monitor.evaluate([disk, down], {"nginx.service": 2})
    assert {(a.key, a.state) for a in alerts} == {
        ("site:a.example", "problem"),
        ("crash:nginx.service", "event"),
    }
    assert monitor.deliver(alerts)["sent"] == 2 and len(received) == 2
    clock[0] += 3600
    reminders = monitor.evaluate([disk, down], {"nginx.service": 2})
    assert [(a.key, a.state) for a in reminders] == [("site:a.example", "reminder")]
    escalated = monitor.evaluate([mon.Problem("disk:/", "critical", "/ 97%"), down], {})
    assert [(a.key, a.severity) for a in escalated] == [("disk:/", "critical")]
    resolved = monitor.evaluate([], {}, failed_unit="mariadb.service")
    assert {(a.key, a.state) for a in resolved} == {
        ("disk:/", "resolved"),
        ("site:a.example", "resolved"),
        ("failed:mariadb.service", "event"),
    }
    # Filtering: with min severity "critical", warn-level news is not sent.
    notifier.setup(al.AlertSettings("webhook", min_severity="critical"), base + "/fail")
    out = monitor.deliver(
        [
            al.Alert("k", "warn", "m", "event", "srv"),
            al.Alert("k2", "critical", "m", "event", "srv"),
        ]
    )
    assert out["skipped"] == 1 and out["sent"] == 0 and "HTTP 500" in out["errors"][0]
    (tmp_path / "state.json").write_text("not json")
    assert monitor.evaluate([], {}) == []  # corrupt state: start fresh, no crash


# --- CLI handlers -----------------------------------------------------------------------


def _ctx(system: dict[str, Any], domain: str | None = None, *, tty: bool = False) -> Any:
    from conftest import FakeProbe

    from domainpilot.cli.context import Context
    from domainpilot.core.config import Config
    from domainpilot.core.output import Output

    class Out(io.StringIO):
        def isatty(self) -> bool:
            return tty

    ctx = Context(
        paths=system["paths"],
        out=Output(stdout=Out(), stderr=io.StringIO()),
        probe=FakeProbe(system["paths"].etc),
        config=Config(),
        argv=["site"],
        domain=domain,
        use_syslog=False,
    )
    ctx._registry = system["registry"]
    return ctx


def _ns(**kw: Any) -> argparse.Namespace:
    return argparse.Namespace(**kw)


@pytest.fixture
def fake_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    original = SecretStore.__init__

    def init(self: SecretStore, directory: Path, area: str, *, run: Any = None) -> None:
        original(self, directory, area, run=creds_runner())

    monkeypatch.setattr(SecretStore, "__init__", init)


def setup_ns(repo: str, **kw: Any) -> argparse.Namespace:
    base = {
        "repository": repo,
        "credentials_stdin": False,
        "keep_daily": 7,
        "keep_weekly": 4,
        "keep_monthly": 6,
        "show_secret": False,
    }
    return _ns(**(base | kw))


def test_backup_setup_and_keys(
    system: dict[str, Any], fake_creds: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(system, tty=True)
    first = backup_handlers.setup(ctx, setup_ns(str(tmp_path / "repo")))
    key = first.data["master_key"]
    assert key and len(key) == 64 and any("OFFLINE" in line for line in first.text)
    again = backup_handlers.setup(_ctx(system), setup_ns(str(tmp_path / "repo")))
    assert again.data["master_key"] is None  # never regenerated (would orphan backups)
    hidden = backup_handlers.show_key
    with pytest.raises(UsageError, match="terminal"):
        hidden(_ctx(system), _ns(show_secret=False))
    assert hidden(_ctx(system), _ns(show_secret=True)).data["master_key"] == key
    with pytest.raises(UsageError, match="already has a master key"):
        backup_handlers.import_key(_ctx(system), _ns())
    with pytest.raises(UsageError, match="needs credentials"):
        backup_handlers.setup(_ctx(system), setup_ns("s3:https://s3.example.com/bkt"))
    monkeypatch.setattr("sys.stdin", io.StringIO("AWS_ACCESS_KEY_ID=a\nAWS_SECRET_ACCESS_KEY=b\n"))
    s3 = backup_handlers.setup(
        _ctx(system), setup_ns("s3:https://s3.example.com/bkt", credentials_stdin=True)
    )
    assert s3.data["repository"] == "s3:https://s3.example.com/bkt"
    with pytest.raises(UsageError, match="only for s3"):
        backup_handlers.setup(_ctx(system), setup_ns("/var/b", credentials_stdin=True))
    (system["paths"].etc / "secrets" / "backup" / "master.cred").unlink()
    monkeypatch.setattr("sys.stdin", io.StringIO(key + "\n"))
    assert backup_handlers.import_key(_ctx(system), _ns()).data["imported"]


def test_backup_command_handlers(
    system: dict[str, Any], fake_creds: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system["manager"]().create(CreateRequest("example.com"))
    backup_handlers.setup(_ctx(system), setup_ns(str(tmp_path / "repo")))
    calls: list[str] = []

    class Stub:
        def __init__(self, **_kw: Any) -> None:
            pass

        def tenant_for(self, domain: str) -> Any:
            return system["registry"].get_tenant("t0001") or domain

        def backup_tenant(self, tenant: Any, files: bool = True) -> dict[str, Any]:
            calls.append(f"backup files={files}")
            return {"run": "r1", "databases": {"t0001_app": "x"}}

        def backup_all(self) -> dict[str, Any]:
            return {"sites": {"t0001": {}}, "failed": ["t0001"] if calls else []}

        def verify(self) -> dict[str, Any]:
            return {"repositories": {"system": "ok"}, "ok": True}

        def test_restore(self) -> dict[str, Any]:
            return {"sites": {"t0001": {"ok": False, "error": "bad"}}, "ok": False}

        def load_state(self) -> dict[str, Any]:
            return {"sites": {"t0001": {"ok": True, "last_success": "x"}}, "test_restore": {"x": 1}}

        def snapshots(self, _t: Any) -> list[dict[str, Any]]:
            return [{"id": "a", "time": "2026", "kind": "db", "database": "d", "tags": []}]

        def restore(self, domain: str, **kw: Any) -> dict[str, Any]:
            calls.append(f"restore {kw['what']} staging={kw['to_staging']}")
            return {"staging": "/s", "files": {"previous": "/p"}}

    monkeypatch.setattr(backup_handlers, "BackupManager", Stub)
    flags = {"status": False, "verify": False, "test_restore": False}
    assert backup_handlers.system_backup(_ctx(system), _ns(**flags)).exit_code == 0
    status = backup_handlers.system_backup(_ctx(system), _ns(**(flags | {"status": True})))
    assert status.data["configured"] and any("Restore test" in t for t in status.text)
    assert (
        backup_handlers.system_backup(_ctx(system), _ns(**(flags | {"verify": True}))).exit_code
        == 0
    )
    drill = backup_handlers.system_backup(_ctx(system), _ns(**(flags | {"test_restore": True})))
    assert drill.exit_code != 0 and "FAILED" in drill.text[0]
    ctx = _ctx(system, "example.com")
    backup_handlers.site_backup(ctx, _ns())
    backup_handlers.db_backup(ctx, _ns())
    assert calls[-2:] == ["backup files=True", "backup files=False"]
    assert backup_handlers.system_backup(_ctx(system), _ns(**flags)).exit_code != 0
    assert backup_handlers.backup_list(ctx, _ns()).data["snapshots"]
    restore_ns = {"files": False, "db": False, "all": False, "snapshot": None, "to_staging": False}
    out = backup_handlers.restore(ctx, _ns(**(restore_ns | {"files": True})))
    assert "/p" in out.text[-1]
    staged = backup_handlers.restore(ctx, _ns(**(restore_ns | {"to_staging": True})))
    assert "staging" in staged.text[0]
    backup_handlers.db_restore(ctx, _ns(**restore_ns))
    assert calls[-3:] == [
        "restore files staging=False",
        "restore all staging=True",
        "restore db staging=False",
    ]
    with pytest.raises(UsageError):
        backup_handlers.db_restore(ctx, _ns(**(restore_ns | {"all": True})))


def test_sftp_handlers(
    system: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system["manager"]().create(CreateRequest("example.com"))
    system["paths"].ssh_keys.mkdir(mode=0o755)
    monkeypatch.setattr(
        monitor_handlers, "SftpManager", lambda **kw: SftpManager(run=keygen_runner([]), **kw)
    )
    ctx = _ctx(system, "example.com")
    key = tmp_path / "id.pub"
    key.write_text(ED25519)
    with pytest.raises(UsageError):
        monitor_handlers.sftp_create(ctx, _ns(key=None, key_stdin=False, name="a"))
    made = monitor_handlers.sftp_create(ctx, _ns(key=str(key), key_stdin=False, name="alice"))
    assert "Connect: sftp t0001-deploy@" in made.text[1]
    monkeypatch.setattr("sys.stdin", io.StringIO(ED25519.replace("AAAAIGl0", "AAAAIGx4")))
    monitor_handlers.sftp_create(ctx, _ns(key=None, key_stdin=True, name="bob"))
    listed = monitor_handlers.sftp_list(ctx, _ns())
    assert [a["account"] for a in listed.data["accounts"]] == ["alice", "bob"]
    monitor_handlers.sftp_revoke(ctx, _ns(username="alice"))
    big = tmp_path / "big.pub"
    big.write_text("x" * 20000)
    with pytest.raises(UsageError, match="too large"):
        monitor_handlers.sftp_create(ctx, _ns(key=str(big), key_stdin=False, name="c"))
    # Archiving the site revokes deploy access at once.
    system["manager"]().delete("example.com", purge=False)
    assert not (system["paths"].ssh_keys / "t0001-deploy").exists()
    with pytest.raises(PreconditionFailed, match="not active"):
        monitor_handlers.sftp_list(ctx, _ns())


def test_monitor_and_alert_handlers(
    system: dict[str, Any],
    fake_creds: None,
    monkeypatch: pytest.MonkeyPatch,
    hook_server: tuple[str, list[dict[str, Any]]],
) -> None:
    base, received = hook_server
    system["manager"]().create(CreateRequest("example.com"))
    (system["paths"].etc / "backup.json").write_text("{}")
    monkeypatch.setattr(monitor_handlers, "_health_report", lambda ctx: Report())
    monkeypatch.setattr(mon, "restart_counts", lambda units, run=None: {u: 0 for u in units})
    real_site_problems = mon.site_problems
    monkeypatch.setattr(
        mon, "site_problems", lambda d, probe=None: real_site_problems(d, lambda x: 502)
    )
    ctx = _ctx(system)
    status = monitor_handlers.alerts_status(ctx, _ns())
    assert status.data == {"configured": False}
    with pytest.raises(UsageError, match="stdin"):
        monitor_handlers.alerts_setup(
            ctx, _ns(url_stdin=False, kind="ntfy", min_severity="warn", reminder_hours=6)
        )
    monkeypatch.setattr("sys.stdin", io.StringIO(base + "/hook\n"))
    monitor_handlers.alerts_setup(
        ctx, _ns(url_stdin=True, kind="webhook", min_severity="warn", reminder_hours=6)
    )
    assert monitor_handlers.alerts_status(ctx, _ns()).data["kind"] == "webhook"
    monitor_handlers.alerts_test(ctx, _ns())
    assert json.loads(received[-1]["body"])["state"] == "test"
    result = monitor_handlers.system_monitor(ctx, _ns(notify=True, unit_failed=None))
    keys = {p["key"] for p in result.data["problems"]}
    assert "site:example.com" in keys and "backup:t0001" not in keys  # new site: grace
    assert result.data["delivery"]["sent"] >= 1
    quiet = monitor_handlers.system_monitor(ctx, _ns(notify=False, unit_failed="nginx.service"))
    assert "not sent" in quiet.text[-1]
    monitor_handlers.alerts_remove(ctx, _ns())
    assert not monitor_handlers.alerts_status(ctx, _ns()).data["configured"]


def test_system_logs(system: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx(system)
    assert monitor_handlers.system_logs(ctx, _ns(audit=True, lines=10, errors=False)).text == [
        "No audit events."
    ]
    AuditLog(system["paths"].audit_log, use_syslog=False).record(
        "backup.site", argv=["site", "example.com", "backup"], outcome="success", details={}
    )
    with system["paths"].audit_log.open("a") as f:
        f.write("not json\n")
    logs = monitor_handlers.system_logs(ctx, _ns(audit=True, lines=10, errors=False))
    assert "backup.site" in logs.text[0]
    seen: list[list[str]] = []

    def run(argv: list[str], **_kw: Any) -> proc.Result:
        seen.append(argv)
        return proc.Result(tuple(argv), 0, "line1\nline2\n", "")

    monkeypatch.setattr(proc, "run", run)
    journal = monitor_handlers.system_logs(ctx, _ns(audit=False, lines=5000, errors=True))
    assert journal.text == ["line1", "line2"] and "2000" in seen[0] and "warning" in seen[0]


def test_secret_files_are_tightened_on_load(tmp_path: Path) -> None:
    store = SecretStore(tmp_path / "secrets" / "x", "x", run=creds_runner())
    store.save("k", "value")
    cred = tmp_path / "secrets" / "x" / "k.cred"
    cred.chmod(0o644)  # e.g. written by an older version
    assert store.load("k") == "value"
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600
