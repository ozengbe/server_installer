"""`site <domain> isolation test`: active escape attempts from inside the sandbox.

The Phase 4 probe (isolation/probe.php) runs through the site's own PHP-FPM, so
it executes with exactly the confinement a hacked web app would have: same
UID, systemd sandbox, AppArmor profile, seccomp filter, cgroup and nftables
rules, plus the site's open_basedir.

Safety on a live site:
* The probe is written *as the owner of app/public* (setpriv drop, never a root
  write into a tenant-controlled directory), under a random dot-name. nginx
  returns 404 for every dot-file, so it is never reachable from the web; we
  call it directly on the FastCGI socket. It is deleted afterwards.
* Towards other tenants it only tries to read, list or connect; it never
  writes anything outside its own tree.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from domainpilot.core import proc
from domainpilot.core.errors import OperationFailed, PreconditionFailed
from domainpilot.core.paths import Paths
from domainpilot.isolation import fcgi
from domainpilot.security.report import SecurityReport

SETPRIV = "/usr/bin/setpriv"
PROBE = Path(__file__).resolve().parents[1] / "isolation" / "probe.php"
NET_BLOCKED = {
    "loopback_ssh_v4": ("NET-LO", "TH5", "SSH on the host's loopback (IPv4)"),
    "loopback_http_v4": ("NET-LO", "TH5", "web server on the host's loopback"),
    "loopback_ssh_v6": ("NET-LO-V6", "TH5", "SSH on the host's loopback (IPv6)"),
    "cloud_metadata": ("NET-META", "TH4", "cloud metadata service 169.254.169.254"),
    "private_10": ("NET-PRIVATE", "TH5", "private network 10.0.0.0/8"),
    "private_192_168": ("NET-PRIVATE", "TH5", "private network 192.168.0.0/16"),
    "public_dns_tcp": ("NET-DNS", "TH5", "outside DNS servers (data exfiltration)"),
}

Runner = Callable[..., proc.Result]
Requester = Callable[..., fcgi.Response]


def evaluate(r: dict[str, Any], *, tenant: str, uid: int, writable_code: bool) -> SecurityReport:
    rep = SecurityReport(tenant)
    t1, t3 = ("TH1",), ("TH3",)
    rep.add(
        "SBX-UID",
        r.get("euid") == uid,
        "PHP runs as the site's own unprivileged user",
        detail=f"euid {r.get('euid')} (expected {uid})",
        threats=("TH1",),
    )
    rep.add(
        "SBX-NNP",
        bool(r.get("no_new_privs")),
        "no_new_privs is set (no setuid escalation)",
        threats=("TH1",),
    )
    rep.add(
        "SBX-SECCOMP",
        bool(r.get("seccomp_filter")),
        "seccomp system-call filter active",
        threats=("TH1",),
    )
    rep.add("SBX-CAPS", bool(r.get("cap_eff_zero")), "no Linux capabilities", threats=("TH1",))
    label = str(r.get("apparmor_label", ""))
    members = label.rpartition(" ")[0].split("//&")
    rep.add(
        "SBX-APPARMOR",
        label.endswith("(enforce)")
        and members[0] == f"domainpilot-tenant-{tenant}"
        and set(members[1:]) <= {"unconfined"},
        "the site's own AppArmor profile confines PHP (enforce mode)",
        detail=label or "no label",
        fix=f"sudo apparmor_parser -r /etc/apparmor.d/domainpilot/tenant-{tenant}",
        threats=("TH1",),
    )
    if writable_code:
        rep.add(
            "FS-CODE",
            False,
            "PHP can modify its own code (--writable-code was chosen)",
            detail="a hacked app can persist a webshell",
            severity="warn",
            fix="recreate the site without --writable-code if the app allows it",
            threats=t1,
        )
    else:
        rep.add(
            "FS-CODE",
            r.get("own_write_code") is False,
            "PHP cannot modify the site's code (no persistent webshell)",
            fix="code must be owned by the deploy user, group-read-only",
            threats=t1,
        )
    rep.add(
        "FS-OTHERS",
        not r.get("other_paths_visible"),
        "other sites' files are invisible",
        detail=str(r.get("other_paths_visible")),
        threats=t1,
    )
    listing = set(r.get("srv_tenants_listing") or [])
    rep.add(
        "FS-LISTING",
        listing <= {tenant},
        "other sites cannot even be listed",
        detail=", ".join(sorted(listing)),
        threats=t1,
    )
    rep.add(
        "FS-HOST-SECRETS",
        not r.get("host_secret_paths_readable"),
        "server secrets (keys, registry, shadow) are unreadable",
        detail=str(r.get("host_secret_paths_readable")),
        threats=("TH1", "TH22"),
    )
    rep.add(
        "SOCK-OTHERS",
        not r.get("other_sockets_connectable"),
        "other sites' PHP/cache sockets are unreachable",
        detail=str(r.get("other_sockets_connectable")),
        threats=("TH2",),
    )
    rep.add(
        "PROC-OTHERS",
        r.get("foreign_processes_visible") == 0,
        "no other processes are visible",
        detail=str(r.get("foreign_processes_visible")),
        threats=t3,
    )
    rep.add(
        "PHP-EXEC",
        not r.get("exec_functions_available"),
        "shell-execution functions are disabled",
        detail=", ".join(r.get("exec_functions_available") or []),
        threats=("TH1",),
    )
    net = r.get("net") or {}
    for key, (fid, threat, what) in NET_BLOCKED.items():
        rep.add(
            f"{fid}:{key}",
            net.get(key) is False,
            f"blocked: {what}",
            fix="sudo site system firewall status",
            threats=(threat,),
        )
    rep.add(
        "DB-OTHERS",
        r.get("db_other_access") is False,
        "other sites' databases are inaccessible",
        threats=("TH7",),
    )
    rep.add(
        "DB-GLOBAL",
        r.get("db_global_privs") is False,
        "the site's database user has no global privileges",
        threats=("TH7",),
    )
    rep.add(
        "CACHE-CONFIG",
        r.get("cache_config_allowed") is False,
        "the cache refuses CONFIG (cannot write files as the cache)",
        threats=("TH2",),
    )
    # Positive controls: the site must still work. open_basedir may hide some of
    # these from PHP on purpose, so a "no" is information, not a failure.
    for key, what in (
        ("own_read_code", "PHP reads its code"),
        ("own_write_data", "PHP writes data/"),
        ("own_write_tmp", "PHP writes tmp/"),
        ("db_own_login", "PHP logs in to its own database"),
        ("cache_own_ping", "PHP reaches its own cache"),
        ("dns_resolves", "DNS resolution works"),
    ):
        rep.info(f"WORKS:{key}", f"{what}: {'yes' if r.get(key) else 'no'}")
    if net.get("public_https") is not None:
        rep.info("WORKS:public_https", f"outbound HTTPS: {'yes' if net['public_https'] else 'no'}")
    return rep


class IsolationTester:
    def __init__(
        self,
        paths: Paths,
        *,
        run: Runner = proc.run,
        request: Requester = fcgi.request,
        probe_source: Path = PROBE,
    ) -> None:
        self.paths = paths
        self.run = run
        self.request = request
        self.probe_source = probe_source

    def _as_owner(self, owner: tuple[int, int], *argv: str, stdin: str | None = None) -> None:
        uid, gid = owner
        if uid == 0:
            raise PreconditionFailed("the site's public directory is owned by root; refusing")
        self.run(
            [
                SETPRIV,
                f"--reuid={uid}",
                f"--regid={gid}",
                "--clear-groups",
                "--no-new-privs",
                "--",
                *argv,
            ],
            stdin=stdin,
            timeout=30,
        )

    def run_probe(self, tenant: str, *, others: list[str], other_db: str = "") -> dict[str, Any]:
        public = self.paths.tenant_root(tenant) / "app" / "public"
        st = public.lstat()
        owner = (st.st_uid, st.st_gid)
        script = public / f".dp-probe-{secrets.token_hex(12)}.php"
        source = self.probe_source.read_text(encoding="utf-8")
        self._as_owner(owner, "/usr/bin/tee", str(script), stdin=source)
        try:
            params = fcgi.php_params(
                script,
                extra={"DP_SELF": tenant, "DP_OTHERS": ",".join(others), "DP_OTHER_DB": other_db},
            )
            resp = self.request(self.paths.php_socket(tenant), params, timeout=120)
        finally:
            self._as_owner(owner, "/usr/bin/rm", "-f", "--", str(script))
        if resp.status != 200:
            raise OperationFailed(f"the probe did not run (HTTP {resp.status})")
        try:
            data: dict[str, Any] = json.loads(resp.body)
        except ValueError:
            raise OperationFailed("the probe returned no usable result") from None
        return data
