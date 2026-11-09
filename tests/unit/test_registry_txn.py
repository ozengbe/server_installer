from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from domainpilot.core.audit import AuditLog
from domainpilot.core.errors import OperationFailed, PreconditionFailed, UsageError, ValidationError
from domainpilot.core.registry import UID_BASE, Registry
from domainpilot.core.txn import Step, Transaction


@pytest.fixture
def registry(tmp_path: Path) -> Registry:
    reg = Registry.open(tmp_path / "registry.sqlite3")
    assert reg is not None
    return reg


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", use_syslog=False)


# --- registry ---------------------------------------------------------------


def test_registry_created_private_and_migrated(tmp_path: Path, registry: Registry) -> None:
    assert (tmp_path / "registry.sqlite3").stat().st_mode & 0o777 == 0o600
    assert registry.schema_version() == 2
    registry.close()
    again = Registry.open(tmp_path / "registry.sqlite3")
    assert again is not None and again.schema_version() == 2


def test_registry_open_without_create(tmp_path: Path) -> None:
    assert Registry.open(tmp_path / "missing.sqlite3", create=False) is None


def test_registry_refuses_symlink(tmp_path: Path, registry: Registry) -> None:
    (tmp_path / "link.sqlite3").symlink_to(tmp_path / "registry.sqlite3")
    with pytest.raises(OperationFailed, match="symlink"):
        Registry.open(tmp_path / "link.sqlite3")


def test_registry_refuses_newer_schema(tmp_path: Path, registry: Registry) -> None:
    registry.close()
    conn = sqlite3.connect(tmp_path / "registry.sqlite3")
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(OperationFailed, match="newer"):
        Registry.open(tmp_path / "registry.sqlite3")


def test_tenant_allocation_is_unique_and_never_reused(registry: Registry) -> None:
    a = registry.allocate_tenant()
    b = registry.allocate_tenant(tier="c")
    assert (a.id, a.uid) == ("t0001", UID_BASE + 1)
    assert (b.id, b.uid, b.tier) == ("t0002", UID_BASE + 2, "c")
    registry.set_tenant_status(a.id, "purged")
    assert registry.allocate_tenant().id == "t0003"
    tenant = registry.get_tenant("t0001")
    assert tenant is not None and tenant.status == "purged"
    assert registry.get_tenant("t9999") is None


def test_tenant_validation(registry: Registry) -> None:
    with pytest.raises(OperationFailed):
        registry.allocate_tenant(tier="x")
    with pytest.raises(OperationFailed):
        registry.set_tenant_status("t0001", "bogus")
    with pytest.raises(OperationFailed, match="not found"):
        registry.set_tenant_status("t0042", "active")


def test_sites(registry: Registry) -> None:
    t = registry.allocate_tenant()
    registry.set_tenant_status(t.id, "active")
    site = registry.add_site("Example.com", t.id, site_type="php", php_version="8.3")
    assert site.domain == "example.com"
    registry.add_site("www.example.com", t.id, site_type="php", php_version="8.3", is_primary=False)
    assert [s.domain for s in registry.list_sites()] == ["example.com", "www.example.com"]
    got = registry.get_site("example.com")
    assert got is not None and got.enabled and got.is_primary
    assert registry.get_site("nope.com") is None
    assert registry.counts() == {
        "tenants": 1,
        "sites": 2,
        "sites_enabled": 2,
        "unfinished_operations": 0,
    }
    with pytest.raises(PreconditionFailed):
        registry.add_site("example.com", t.id, site_type="php", php_version="8.3")
    with pytest.raises(PreconditionFailed):  # foreign key: unknown tenant
        registry.add_site("other.com", "t0999", site_type="static", php_version=None)
    with pytest.raises(OperationFailed):
        registry.add_site("x.com", t.id, site_type="cgi", php_version=None)
    with pytest.raises(ValidationError):
        registry.add_site("x.com", t.id, site_type="php", php_version="5.6")
    with pytest.raises(ValidationError):
        registry.add_site("bad;name", t.id, site_type="php", php_version=None)


def test_operation_journal(registry: Registry) -> None:
    op = registry.begin_operation(
        actor="alice", command=["site", "a.com", "create"], target="a.com"
    )
    assert [o.id for o in registry.unfinished_operations("a.com")] == [op]
    assert registry.unfinished_operations("b.com") == []
    registry.update_operation(op, steps=[{"name": "x", "status": "done"}], status="succeeded")
    stored = registry.get_operation(op)
    assert stored is not None and stored.status == "succeeded" and stored.finished_at
    assert stored.command == ["site", "a.com", "create"]
    assert registry.unfinished_operations() == []
    assert registry.get_operation("nope") is None
    with pytest.raises(OperationFailed):
        registry.update_operation(op, steps=[], status="weird")


# --- transactions -----------------------------------------------------------


def _steps(log: list[str], fail_at: str | None = None, undo_fail: str | None = None) -> list[Step]:
    def make(name: str) -> Step:
        def apply() -> None:
            if name == fail_at:
                raise RuntimeError(f"{name} broke")
            log.append(f"do:{name}")

        def undo() -> None:
            if name == undo_fail:
                raise RuntimeError(f"cannot undo {name}")
            log.append(f"undo:{name}")

        return Step(name, f"step {name}", apply, undo)

    return [make(n) for n in ("a", "b", "c")]


def _txn(registry: Registry, audit_log: AuditLog, **kw: object) -> Transaction:
    return Transaction(
        registry=registry,
        audit=audit_log,
        command=["site", "x.com", "create"],
        target="x.com",
        **kw,  # type: ignore[arg-type]
    )


def test_txn_success(registry: Registry, audit_log: AuditLog, tmp_path: Path) -> None:
    log: list[str] = []
    reported: list[tuple[str, str]] = []
    txn = _txn(registry, audit_log, reporter=lambda d, s: reported.append((d, s)))
    for s in _steps(log):
        txn.add(s)
    result = txn.execute()
    assert log == ["do:a", "do:b", "do:c"]
    assert [s["status"] for s in result.steps] == ["done"] * 3
    assert reported[-1] == ("step c", "done")
    op = registry.get_operation(result.operation_id or "")
    assert op is not None and op.status == "succeeded"
    entry = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert entry["outcome"] == "success" and entry["id"] == result.operation_id


def test_txn_dry_run_changes_nothing() -> None:
    log: list[str] = []
    txn = Transaction(registry=None, audit=None, command=["x"], target=None, dry_run=True)
    for s in _steps(log):
        txn.add(s)
    result = txn.execute()
    assert log == []
    assert result.dry_run and result.plan == ["step a", "step b", "step c"]


def test_txn_rolls_back_in_reverse(registry: Registry, audit_log: AuditLog) -> None:
    log: list[str] = []
    txn = _txn(registry, audit_log)
    for s in _steps(log, fail_at="c"):
        txn.add(s)
    with pytest.raises(OperationFailed, match="c broke; all completed steps were rolled back"):
        txn.execute()
    assert log == ["do:a", "do:b", "undo:b", "undo:a"]
    (op,) = [o for o in [registry.get_operation(i) for i in _op_ids(registry)] if o]
    assert op.status == "rolled_back"
    assert [s["status"] for s in op.steps] == ["undone", "undone", "failed"]


def test_txn_reraises_domain_errors(registry: Registry, audit_log: AuditLog) -> None:
    def fail() -> None:
        raise PreconditionFailed("DNS does not point here")

    txn = _txn(registry, audit_log).add(Step("x", "x", fail))
    with pytest.raises(PreconditionFailed, match="DNS"):
        txn.execute()


def test_txn_undo_failure_reports_repair(registry: Registry, audit_log: AuditLog) -> None:
    log: list[str] = []
    txn = _txn(registry, audit_log)
    for s in _steps(log, fail_at="c", undo_fail="a"):
        txn.add(s)
    txn.add(Step("keep", "no undo", lambda: None))  # never reached
    with pytest.raises(OperationFailed) as info:
        txn.execute()
    assert "rollback incomplete" in info.value.message
    assert info.value.hint is not None and "site x.com repair" in info.value.hint
    assert registry.unfinished_operations("x.com")[0].status == "rollback_failed"


def test_txn_step_without_undo_is_kept(registry: Registry, audit_log: AuditLog) -> None:
    def fail() -> None:
        raise RuntimeError("boom")

    txn = _txn(registry, audit_log)
    txn.add(Step("a", "a", lambda: None)).add(Step("b", "b", fail))
    with pytest.raises(OperationFailed):
        txn.execute()
    op = registry.get_operation(_op_ids(registry)[0])
    assert op is not None and op.steps[0]["status"] == "kept"


def test_txn_guards(registry: Registry, audit_log: AuditLog) -> None:
    with pytest.raises(UsageError):
        Transaction(registry=None, audit=None, command=[], target=None)
    txn = _txn(registry, audit_log).add(Step("a", "a", lambda: None))
    with pytest.raises(UsageError, match="duplicate"):
        txn.add(Step("a", "again", lambda: None))


def _op_ids(registry: Registry) -> list[str]:
    rows = registry._conn.execute("SELECT id FROM operations").fetchall()
    return [r[0] for r in rows]
