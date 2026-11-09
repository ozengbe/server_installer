"""Locks, audit log, config and output."""

from __future__ import annotations

import io
import json
import syslog
from pathlib import Path

import pytest

from domainpilot.core import audit, config
from domainpilot.core.errors import LockBusy, ValidationError
from domainpilot.core.locks import FileLock
from domainpilot.core.output import AUDIT_DISCLAIMER, Output, table

# --- locks ------------------------------------------------------------------


def test_lock_excludes_second_holder(tmp_path: Path) -> None:
    path = tmp_path / "g.lock"
    with FileLock(path) as first:
        assert first.held
        with pytest.raises(LockBusy):
            FileLock(path, timeout=0.2, poll=0.05).acquire()
    assert not first.held
    with FileLock(path, timeout=0.2):
        pass  # free again after release


def test_lock_refuses_symlink(tmp_path: Path) -> None:
    (tmp_path / "real").write_text("")
    (tmp_path / "l.lock").symlink_to(tmp_path / "real")
    with pytest.raises(OSError):
        FileLock(tmp_path / "l.lock").acquire()


# --- audit ------------------------------------------------------------------


def test_redact_nested() -> None:
    data = {"user": "a", "password": "p", "nested": {"api_token": "t", "ok": [{"secret": 1}]}}
    assert audit.redact(data) == {
        "user": "a",
        "password": audit.REDACTED,
        "nested": {"api_token": audit.REDACTED, "ok": [{"secret": audit.REDACTED}]},
    }


def test_redact_argv() -> None:
    argv = ["site", "x.com", "--token", "abc", "--password=pw", "--type", "php", "--token"]
    assert audit.redact_argv(argv) == [
        "site",
        "x.com",
        "--token",
        audit.REDACTED,
        f"--password={audit.REDACTED}",
        "--type",
        "php",
        "--token",
    ]


def test_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUDO_USER", "alice")
    assert audit.actor() == "alice"
    monkeypatch.setenv("SUDO_USER", "evil\nINJECTED")
    assert audit.actor().startswith("uid:")
    monkeypatch.delenv("SUDO_USER")
    assert audit.actor().startswith("uid:")


def test_audit_appends_json_lines(tmp_path: Path) -> None:
    log = audit.AuditLog(tmp_path / "audit.jsonl", use_syslog=False)
    log.record("op", argv=["site", "--token", "x"], outcome="success", details={"key": "k"})
    log.record("op", outcome="failed", operation_id="abc")
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)
    assert first["argv"] == ["site", "--token", audit.REDACTED]
    assert first["details"] == {"key": audit.REDACTED}
    assert second["id"] == "abc" and second["outcome"] == "failed"
    assert (tmp_path / "audit.jsonl").stat().st_mode & 0o007 == 0


def test_audit_syslog_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[int, str]] = []
    monkeypatch.setattr(syslog, "openlog", lambda *a, **k: None)
    monkeypatch.setattr(syslog, "closelog", lambda: None)
    monkeypatch.setattr(syslog, "syslog", lambda prio, msg: sent.append((prio, msg)))
    audit.AuditLog(tmp_path / "a.jsonl").record("op", outcome="success")
    audit.AuditLog(tmp_path / "a.jsonl").record("op", outcome="failed")
    assert [p for p, _ in sent] == [syslog.LOG_NOTICE, syslog.LOG_WARNING]


def test_audit_refuses_symlinked_log(tmp_path: Path) -> None:
    (tmp_path / "target").write_text("")
    (tmp_path / "a.jsonl").symlink_to(tmp_path / "target")
    with pytest.raises(OSError):
        audit.AuditLog(tmp_path / "a.jsonl", use_syslog=False).record("op", outcome="success")


# --- config -----------------------------------------------------------------


def test_config_defaults_when_missing(tmp_path: Path) -> None:
    assert config.load(tmp_path / "none.toml") == config.Config()


def test_config_valid(tmp_path: Path) -> None:
    f = tmp_path / "c.toml"
    f.write_text(
        '[sites]\ndefault_php_version = "8.4"\ndefault_type = "static"\ndefault_tier = "c"\n'
        "[cli]\nlock_timeout = 5\n"
    )
    cfg = config.load(f)
    assert cfg == config.Config("8.4", "static", "c", 5.0)


@pytest.mark.parametrize(
    "content",
    [
        "[nope]\nx = 1\n",
        "[sites]\ntypo = 1\n",
        "[sites]\ndefault_type = 3\n",
        '[sites]\ndefault_type = "cgi"\n',
        '[sites]\ndefault_tier = "x"\n',
        '[sites]\ndefault_php_version = "5.6"\n',
        "[cli]\nlock_timeout = 0\n",
        "[cli]\nlock_timeout = true\n",
        "not toml ===",
        "x = 1\n",
    ],
)
def test_config_rejects(tmp_path: Path, content: str) -> None:
    f = tmp_path / "c.toml"
    f.write_text(content)
    with pytest.raises(ValidationError):
        config.load(f)


# --- output -----------------------------------------------------------------


def test_output_json_envelope() -> None:
    buf = io.StringIO()
    out = Output(json_mode=True, stdout=buf, stderr=io.StringIO())
    out.step("did a thing")
    out.warn("careful")
    out.info("hidden in json")
    out.result(["site", "list"], {"n": 1}, text=["ignored"], disclaimer=True)
    env = json.loads(buf.getvalue())
    assert env["ok"] is True and env["schema_version"] == 1
    assert env["result"] == {"n": 1}
    assert env["warnings"] == ["careful"]
    assert env["steps"] == [{"description": "did a thing", "status": "done"}]
    assert env["disclaimer"] == AUDIT_DISCLAIMER


def test_output_json_error() -> None:
    buf = io.StringIO()
    out = Output(json_mode=True, stdout=buf, stderr=io.StringIO())
    out.step("partial", "failed")
    out.error(["site"], "validation", "bad", hint="fix it")
    env = json.loads(buf.getvalue())
    assert env["ok"] is False
    assert env["errors"] == [{"code": "validation", "message": "bad", "hint": "fix it"}]
    assert env["steps"][0]["status"] == "failed"


def test_output_text_mode() -> None:
    o, e = io.StringIO(), io.StringIO()
    out = Output(stdout=o, stderr=e, color=True)
    out.step("created user")
    out.step("removed user", "undone")
    out.info("note")
    out.warn("w")
    out.result(["site"], {}, text=["line"], disclaimer=True)
    out.error(["site"], "x", "boom", hint="h")
    text = o.getvalue()
    assert "created user" in text and "(undone)" in text and "line" in text
    assert AUDIT_DISCLAIMER in text
    assert (
        "warning: w" in e.getvalue() and "error: boom" in e.getvalue() and "hint: h" in e.getvalue()
    )


def test_output_quiet_suppresses_progress() -> None:
    o = io.StringIO()
    out = Output(quiet=True, stdout=o, stderr=io.StringIO())
    out.step("x")
    out.info("y")
    assert o.getvalue() == ""


def test_table() -> None:
    lines = table([["a.com", "t0001"]], ["DOMAIN", "TENANT"])
    assert lines[0].startswith("DOMAIN") and "t0001" in lines[2]
