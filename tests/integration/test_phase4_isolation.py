"""Phase 4 acceptance: tenant isolation, tested from inside real sandboxes.

Creates three tenants on a disposable test host, runs ozenix/isolation/
probe.php through each tenant's own PHP-FPM (so it executes inside the real
sandbox), and asserts every escape attempt fails. Tenants are purged afterwards.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ozenix.core import proc
from ozenix.core.audit import AuditLog
from ozenix.core.config import load_host
from ozenix.core.errors import DPError
from ozenix.core.paths import Paths
from ozenix.core.registry import Registry, Tenant
from ozenix.isolation import db, fcgi
from ozenix.isolation.provision import Provisioner, provision_tenant
from ozenix.isolation.status import EXPOSURE_TARGET, exposure_score

pytestmark = pytest.mark.integration

PROBE_SRC = Path(__file__).resolve().parents[2] / "ozenix" / "isolation" / "probe.php"
PATHS = Paths.default()


def sh(*argv: str) -> str:
    return subprocess.run(list(argv), check=True, capture_output=True, text=True, timeout=60).stdout


@pytest.fixture(scope="module")
def env() -> Iterator[dict[str, Any]]:
    assert os.geteuid() == 0 and Path("/etc/ozenix-test-vm").is_file(), "test VM only"
    PATHS.create_runtime_dirs()
    host = load_host(PATHS.host_config_file)
    registry = Registry.open(PATHS.registry)
    assert registry is not None
    audit = AuditLog(PATHS.audit_log, use_syslog=False)
    tenants: list[Tenant] = []
    try:
        for _ in range(3):
            tenants.append(
                provision_tenant(
                    paths=PATHS, host=host, registry=registry, audit=audit, php_open_basedir=False
                )
            )
        for t in tenants:
            pub = PATHS.tenant_root(t.id) / "app" / "public"
            target = pub / "dp-probe.php"
            shutil.copyfile(PROBE_SRC, target)
            os.chown(target, pwd.getpwnam(f"{t.id}-deploy").pw_uid, pwd.getpwnam(t.id).pw_gid)
            target.chmod(0o640)
        db.execute(db.create_database_sql(tenants[1].id, "probe"))
        yield {"host": host, "registry": registry, "audit": audit, "tenants": tenants}
    finally:
        prov = Provisioner(PATHS, host)
        for t in tenants:
            problems = prov.purge(t.id)
            registry.set_tenant_status(t.id, "purged")
            assert not problems, problems
        registry.close()


def probe(env: dict[str, Any], index: int) -> dict[str, Any]:
    tenants: list[Tenant] = env["tenants"]
    me = tenants[index]
    others = [t.id for t in tenants if t.id != me.id]
    other_db = db.database_name(tenants[1].id if index != 1 else tenants[0].id, "probe")
    script = PATHS.tenant_root(me.id) / "app" / "public" / "dp-probe.php"
    params = fcgi.php_params(
        script,
        extra={"DP_SELF": me.id, "DP_OTHERS": ",".join(others), "DP_OTHER_DB": other_db},
    )
    resp = fcgi.request(PATHS.php_socket(me.id), params, timeout=90)
    assert resp.status == 200, (resp.status, resp.body[:500], resp.stderr[:500])
    data: dict[str, Any] = json.loads(resp.body)
    return data


@pytest.fixture(scope="module")
def results(env: dict[str, Any]) -> list[dict[str, Any]]:
    return [probe(env, i) for i in range(3)]


# --- identity & sandbox -------------------------------------------------------------


def test_runs_as_own_unprivileged_user(env: dict[str, Any], results: list[dict[str, Any]]) -> None:
    for t, r in zip(env["tenants"], results, strict=True):
        assert r["euid"] == t.uid
        assert r["no_new_privs"] and r["seccomp_filter"] and r["cap_eff_zero"]
        # systemd may attach the profile as a stack ("ours//&unconfined"): a stack is
        # the intersection of its members, and "unconfined" adds no permissions.
        label, _, mode = r["apparmor_label"].rpartition(" ")
        assert mode == "(enforce)", r["apparmor_label"]
        members = label.split("//&")
        assert members[0] == f"ozenix-tenant-{t.id}", r["apparmor_label"]
        assert set(members[1:]) <= {"unconfined"}, r["apparmor_label"]


def test_code_is_read_only_for_runtime(results: list[dict[str, Any]]) -> None:
    for r in results:
        assert r["own_read_code"] is True
        assert r["own_write_code"] is False  # FS-CODE: a compromised app cannot persist a webshell
        assert r["own_write_data"] is True and r["own_write_tmp"] is True
        assert r["own_config_readable"] is True


# --- cross-tenant -------------------------------------------------------------------


def test_other_tenants_do_not_exist_in_namespace(
    env: dict[str, Any], results: list[dict[str, Any]]
) -> None:
    for t, r in zip(env["tenants"], results, strict=True):
        others = {o.id for o in env["tenants"]} - {t.id}
        # FS-*: at most its own entry; AppArmor may deny listing /srv/tenants entirely.
        assert set(r["srv_tenants_listing"]) <= {t.id}, r["srv_tenants_listing"]
        assert not others & set(r["srv_tenants_listing"])
        assert r["other_paths_visible"] == []
        assert r["other_sockets_connectable"] == []  # SOCK-*


def test_host_secrets_unreachable(results: list[dict[str, Any]]) -> None:
    for r in results:
        assert r["host_secret_paths_readable"] == []


def test_no_foreign_processes_visible(results: list[dict[str, Any]]) -> None:
    for r in results:
        assert r["foreign_processes_visible"] == 0  # PROC-*


def test_exec_functions_disabled(results: list[dict[str, Any]]) -> None:
    for r in results:
        assert r["exec_functions_available"] == []


# --- network --------------------------------------------------------------------------


def test_network_egress_policy(results: list[dict[str, Any]]) -> None:
    for r in results:
        net = r["net"]
        for check in (
            "loopback_ssh_v4",
            "loopback_http_v4",
            "loopback_ssh_v6",
            "cloud_metadata",
            "private_10",
            "private_192_168",
            "public_dns_tcp",
        ):
            assert net[check] is False, check  # NET-LO / NET-META / IPv6
        assert r["dns_resolves"] is True  # positive control: local resolver allowed
        assert net["public_https"] is True  # positive control: public HTTPS allowed


# --- database & cache -------------------------------------------------------------------


def test_database_isolation(results: list[dict[str, Any]]) -> None:
    for r in results:
        assert r["db_own_login"] is True  # unix_socket auth as its own OS user
        assert r["db_other_access"] is False  # DB-*
        assert r["db_global_privs"] is False


def test_cache_isolation(results: list[dict[str, Any]]) -> None:
    for r in results:
        assert r["cache_own_ping"] is True
        assert r["cache_config_allowed"] is False


# --- limits & hardening scores --------------------------------------------------------------


def test_resource_limits_applied(env: dict[str, Any]) -> None:
    for t in env["tenants"]:
        out = sh(
            "/usr/bin/systemctl",
            "show",
            f"dptenants-{t.id}.slice",
            "-p",
            "MemoryMax",
            "-p",
            "TasksMax",
            "-p",
            "CPUQuotaPerSecUSec",
        )
        assert "MemoryMax=1073741824" in out
        assert "TasksMax=256" in out
        assert "CPUQuotaPerSecUSec=1s" in out
        unit = sh("/usr/bin/systemctl", "show", f"dp-php@{t.id}.service", "-p", "Slice")
        assert f"Slice=dptenants-{t.id}.slice" in unit


def test_systemd_exposure_score(env: dict[str, Any]) -> None:
    for t in env["tenants"]:
        for unit in (f"dp-php@{t.id}.service", f"dp-cache@{t.id}.service"):
            score = exposure_score(unit)
            assert score is not None and score <= EXPOSURE_TARGET, (unit, score)


# --- transactional rollback ------------------------------------------------------------------


def test_failed_provisioning_rolls_back_completely(env: dict[str, Any]) -> None:
    def failing_start(argv: list[str], **kw: Any) -> proc.Result:
        if argv[:3] == ["/usr/bin/systemctl", "enable", "--now"]:
            raise DPError("simulated failure while starting services")
        return proc.run(argv, **kw)

    with pytest.raises(DPError, match="simulated failure"):
        provision_tenant(
            paths=PATHS,
            host=env["host"],
            registry=env["registry"],
            audit=env["audit"],
            run=failing_start,
        )
    failed = env["registry"].list_tenants()[-1]
    assert failed.status == "purged"
    with pytest.raises(KeyError):
        pwd.getpwnam(failed.id)
    assert not PATHS.tenant_root(failed.id).exists()
    assert not PATHS.tenant_etc(failed.id).exists()
    assert not (PATHS.apparmor / f"tenant-{failed.id}").exists()
    assert (
        f"ozenix-tenant-{failed.id}"
        not in Path("/sys/kernel/security/apparmor/profiles").read_text()
    )
    assert not db.user_exists(failed.id)
