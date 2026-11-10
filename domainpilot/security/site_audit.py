"""`site <domain> isolation audit` and `site <domain> security` (read-only).

isolation audit: is the site's confinement *configured* as designed (systemd
sandbox properties as systemd actually applies them, exposure score, AppArmor
mode, cgroup limits, directory ownership, database grants, account hygiene)?
`isolation test` (isolation_test.py) then proves it by trying to break out.

security: the isolation audit plus what the site owner controls (dangerous
files in the tree, PHP settings, certificate, SFTP keys, backups).
The tree scan never follows symlinks and only reads metadata (lstat).
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from domainpilot.core import proc
from domainpilot.core.errors import DPError
from domainpilot.core.paths import Paths
from domainpilot.isolation.render import DISABLED_PHP_FUNCTIONS
from domainpilot.isolation.status import EXPOSURE_TARGET, apparmor_mode, exposure_score
from domainpilot.security.report import SecurityReport

Runner = Callable[..., proc.Result]
SYSTEMCTL = "/usr/bin/systemctl"
MARIADB = "/usr/bin/mariadb"
# Owner of every tenant root (root; tests run unprivileged and override it).
ROOT_UID = 0
UNIT_EXPECT = {
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictNamespaces": "yes",
    "RestrictSUIDSGID": "yes",
    "MemoryDenyWriteExecute": "yes",
    "LockPersonality": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectControlGroups": "yes",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
}
PRIVILEGED_GROUPS = ("sudo", "adm", "root", "dp-admins", "shadow", "docker", "lxd", "disk")
SENSITIVE_PUBLIC = re.compile(
    r"(?:\.env|\.git|\.svn|\.htpasswd|id_rsa|id_ed25519|.*\.(?:sql|sql\.gz|bak|zip|tar|tar\.gz|tgz|7z|pem|key))",
    re.I,
)
SCAN_LIMIT = 200_000


@dataclass
class SiteFacts:
    tenant: str
    domain: str
    php: bool = True
    cert_days_left: int | None = None
    sftp_accounts: list[dict[str, str]] = field(default_factory=list)
    backup_state: dict[str, Any] | None = None  # None = backups not configured


class SiteAuditor:
    def __init__(
        self,
        paths: Paths,
        *,
        run: Runner = proc.run,
        getpwnam: Callable[[str], Any] = pwd.getpwnam,
        getgrnam: Callable[[str], Any] = grp.getgrnam,
        exposure: Callable[[str], float | None] | None = None,
        apparmor: Callable[[str], str] = apparmor_mode,
    ) -> None:
        self.paths = paths
        self.run = run
        self.getpwnam = getpwnam
        self.getgrnam = getgrnam
        self.exposure = exposure or (lambda unit: exposure_score(unit, run))
        self.apparmor = apparmor

    def _show(self, unit: str, props: list[str]) -> dict[str, str]:
        try:
            out = self.run(
                [SYSTEMCTL, "show", unit, *[f"--property={p}" for p in props]],
                check=False,
                timeout=30,
            ).stdout
        except DPError:
            return {}
        result = {}
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                result[key] = value.strip()
        return result

    # --- isolation audit ------------------------------------------------------

    def isolation_audit(self, facts: SiteFacts) -> SecurityReport:
        t = facts.tenant
        rep = SecurityReport(facts.domain)
        if facts.php:
            self._unit(rep, t)
        mode = self.apparmor(f"domainpilot-tenant-{t}")
        rep.add(
            "AA-PROFILE",
            mode == "enforce",
            "the site's AppArmor profile is enforced",
            detail=f"mode: {mode}",
            fix=f"sudo apparmor_parser -r /etc/apparmor.d/domainpilot/tenant-{t}",
            threats=("TH1", "TH2"),
        )
        self._limits(rep, t)
        self._tree(rep, t)
        self._grants(rep, t)
        self._accounts(rep, t)
        return rep

    def _unit(self, rep: SecurityReport, t: str) -> None:
        unit = f"dp-php@{t}.service"
        props = self._show(
            unit, ["User", "AppArmorProfile", "Slice", "IPAddressDeny", *UNIT_EXPECT]
        )
        if not props:
            rep.add("SBX-UNIT", False, "the PHP sandbox unit can be inspected", threats=("TH1",))
            return
        wrong = [f"{k}={props.get(k)!r}" for k, v in UNIT_EXPECT.items() if props.get(k) != v]
        rep.add(
            "SBX-PROPERTIES",
            not wrong,
            "systemd sandbox settings are in effect",
            detail=", ".join(wrong),
            fix="re-run the installer (role isolation)",
            threats=("TH1", "TH3"),
        )
        rep.add(
            "SBX-USER",
            props.get("User") == t,
            "PHP runs as the site's own user",
            detail=str(props.get("User")),
            threats=("TH1",),
        )
        rep.add(
            "SBX-SLICE",
            props.get("Slice") == f"dptenants-{t}.slice",
            "PHP runs in the site's own resource slice",
            detail=str(props.get("Slice")),
            threats=("TH6",),
        )
        deny = props.get("IPAddressDeny", "")
        rep.add(
            "NET-META-UNIT",
            "169.254.0.0/16" in deny,
            "cloud metadata is blocked at the unit (second layer)",
            detail=deny,
            threats=("TH4",),
        )
        score = self.exposure(unit)
        rep.add(
            "SBX-EXPOSURE",
            score is not None and score <= EXPOSURE_TARGET,
            f"systemd exposure score at most {EXPOSURE_TARGET}",
            detail=str(score),
            severity="warn",
            threats=("TH1",),
        )

    def _limits(self, rep: SecurityReport, t: str) -> None:
        props = self._show(f"dptenants-{t}.slice", ["MemoryMax", "TasksMax", "CPUQuotaPerSecUSec"])
        unlimited = [
            k
            for k in ("MemoryMax", "TasksMax", "CPUQuotaPerSecUSec")
            if props.get(k) in (None, "", "infinity")
        ]
        rep.add(
            "RES-LIMITS",
            not unlimited,
            "memory, process and CPU limits are set",
            detail=", ".join(unlimited),
            threats=("TH6",),
        )

    def _tree(self, rep: SecurityReport, t: str) -> None:
        root = self.paths.tenant_root(t)
        try:
            tid = self.getpwnam(t)
            deploy = self.getpwnam(f"{t}-deploy")
        except KeyError:
            rep.add("FS-ACCOUNTS", False, "the site's system users exist", threats=("TH1",))
            return
        # path, max mode, expected owner uid
        layout = [
            (root, 0o750, ROOT_UID),
            (root / "app", 0o2750, deploy.pw_uid),
            (root / "app" / "public", 0o2750, deploy.pw_uid),
            (root / "data", 0o2770, tid.pw_uid),
            (root / "tmp", 0o700, tid.pw_uid),
        ]
        problems = []
        for path, max_mode, owner in layout:
            try:
                st = path.lstat()
            except OSError:
                problems.append(f"{path.name or path}: missing")
                continue
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                problems.append(f"{path}: not a directory")
            if st.st_uid != owner:
                problems.append(f"{path}: owner uid {st.st_uid}")
            if mode & ~max_mode & 0o7777 or mode & 0o007:
                problems.append(f"{path}: mode {mode:04o}")
            if st.st_gid != tid.pw_gid:
                problems.append(f"{path}: group gid {st.st_gid}")
        rep.add(
            "FS-LAYOUT",
            not problems,
            "site directories have the designed owners and modes",
            detail="; ".join(problems),
            fix="sudo site <domain> repair",
            threats=("TH1",),
        )
        sock = self.paths.php_socket(t).parent
        try:
            sock_mode = stat.S_IMODE(sock.lstat().st_mode)
            rep.add(
                "SOCK-DIR",
                not sock_mode & 0o007,
                "the PHP socket is not reachable by others",
                detail=f"{sock}: {sock_mode:04o}",
                threats=("TH2",),
            )
        except OSError:
            pass

    def _grants(self, rep: SecurityReport, t: str) -> None:
        try:
            out = self.run(
                [MARIADB, "--batch", "--skip-column-names"],
                stdin=f"SHOW GRANTS FOR '{t}'@'localhost';\n",
                check=False,
                timeout=30,
            )
        except DPError:
            return
        if not out.ok:
            return  # no database user (static/proxy site)
        # `t0001\_%` (one backslash; --batch output may show it escaped as two).
        allowed = re.compile(
            rf"GRANT (?:USAGE ON \*\.\*|.+ ON `{t}\\{{1,2}}_%`\.\*) "
            rf"TO [`']{t}[`']@[`']localhost[`'].*"
        )
        extra = [ln for ln in out.stdout.splitlines() if ln.strip() and not allowed.fullmatch(ln)]
        rep.add(
            "DB-GRANTS",
            not extra,
            "database rights cover only the site's own databases",
            detail="; ".join(extra)[:300],
            threats=("TH7",),
        )

    def _accounts(self, rep: SecurityReport, t: str) -> None:
        members = []
        for group in PRIVILEGED_GROUPS:
            try:
                gr = self.getgrnam(group)
            except KeyError:
                continue
            members += [f"{m}@{group}" for m in gr.gr_mem if m in (t, f"{t}-deploy")]
        rep.add(
            "PRIV-GROUPS",
            not members,
            "site users are in no privileged group",
            detail=", ".join(members),
            threats=("TH1",),
        )
        shells = []
        for user in (t, f"{t}-deploy"):
            try:
                shell = self.getpwnam(user).pw_shell
            except KeyError:
                continue
            if shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                shells.append(f"{user}: {shell}")
        rep.add(
            "PRIV-SHELL",
            not shells,
            "site users have no login shell",
            detail=", ".join(shells),
            threats=("TH15",),
        )

    # --- site security --------------------------------------------------------

    def security(self, facts: SiteFacts) -> SecurityReport:
        rep = self.isolation_audit(facts)
        self._scan(rep, facts.tenant)
        if facts.php:
            self._php(rep, facts.tenant)
        days = facts.cert_days_left
        if days is None:
            rep.add(
                "TLS-CERT",
                False,
                "the site has a TLS certificate",
                severity="warn",
                detail="served over HTTP only",
                fix=f"point DNS here, then: sudo site {facts.domain} ssl",
                threats=("TH22",),
            )
        else:
            rep.add(
                "TLS-CERT",
                days >= 14,
                "the certificate is valid for 14+ days",
                detail=f"{days} days left",
                severity="warn" if days >= 3 else "critical",
                fix=f"sudo site {facts.domain} ssl renew",
                threats=("TH22",),
            )
        rsa = [a["account"] for a in facts.sftp_accounts if a.get("type") == "ssh-rsa"]
        rep.info(
            "SFTP-ACCOUNTS",
            f"{len(facts.sftp_accounts)} SFTP account(s)",
            detail=f"RSA keys (prefer ed25519): {', '.join(rsa)}" if rsa else "",
            threats=("TH15",),
        )
        if facts.backup_state is not None:
            ok = bool(facts.backup_state.get("ok")) and facts.backup_state.get("last_success")
            rep.add(
                "BKP-SITE",
                bool(ok),
                "the site has a recent successful backup",
                detail=str(
                    facts.backup_state.get("error")
                    or facts.backup_state.get("last_success")
                    or "never"
                ),
                severity="warn",
                fix=f"sudo site {facts.domain} backup",
                threats=("TH18",),
            )
        else:
            rep.add(
                "BKP-SITE",
                False,
                "backups are configured",
                severity="warn",
                fix="sudo site system backup setup ...",
                threats=("TH18",),
            )
        return rep

    def _scan(self, rep: SecurityReport, t: str) -> None:
        root = self.paths.tenant_root(t)
        public = root / "app" / "public"
        world_writable, setuid, exposed, outside = [], [], [], []
        seen = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            if here == root:
                dirnames[:] = [d for d in dirnames if d in ("app", "data")]  # tmp is scratch
            for name in [*dirnames, *filenames]:
                seen += 1
                path = here / name
                try:
                    st = path.lstat()
                except OSError:
                    continue
                mode = st.st_mode
                rel = str(path.relative_to(root))
                if stat.S_ISLNK(mode):
                    target = str(path.readlink())
                    resolved = os.path.normpath(here / target)
                    if not resolved.startswith(str(root) + os.sep):
                        outside.append(f"{rel} -> {target}")
                    continue
                if mode & 0o002:
                    world_writable.append(rel)
                if stat.S_ISREG(mode) and mode & 0o6000:
                    setuid.append(rel)
                if here.is_relative_to(public) and SENSITIVE_PUBLIC.fullmatch(name):
                    exposed.append(rel)
            if seen > SCAN_LIMIT:
                rep.info("SCAN-LIMIT", f"only the first {SCAN_LIMIT} entries were scanned")
                break
        rep.add(
            "FILES-WORLD-WRITABLE",
            not world_writable,
            "no world-writable files",
            detail=", ".join(world_writable[:10]),
            fix="chmod o-w on the listed paths",
            threats=("TH1",),
        )
        rep.add(
            "FILES-SETUID",
            not setuid,
            "no setuid/setgid files",
            detail=", ".join(setuid[:10]),
            fix="chmod ug-s on the listed files",
            threats=("TH1",),
        )
        rep.add(
            "FILES-PUBLIC-SECRETS",
            not exposed,
            "no secrets, dumps or archives inside the web root",
            detail=", ".join(exposed[:10]),
            fix="move them out of app/public (nginx blocks most, not all)",
            severity="warn",
            threats=("TH1",),
        )
        rep.add(
            "FILES-SYMLINKS-OUT",
            not outside,
            "no symlinks pointing outside the site",
            detail=", ".join(outside[:10]) + " (nginx and the sandbox refuse to follow them)",
            severity="warn",
            threats=("TH8",),
        )

    def _php(self, rep: SecurityReport, t: str) -> None:
        conf = self.paths.tenant_etc(t) / "php-fpm.conf"
        try:
            text = conf.read_text(encoding="utf-8")
        except OSError:
            rep.add(
                "PHP-CONFIG", False, "the site's PHP configuration is readable", threats=("TH1",)
            )
            return
        values = dict(
            re.findall(r"^php_admin_(?:value|flag)\[([a-z_.]+)\]\s*=\s*(.*?)\s*$", text, re.M)
        )
        disabled = set(values.get("disable_functions", "").split(","))
        missing = sorted(set(DISABLED_PHP_FUNCTIONS) - disabled)
        rep.add(
            "PHP-DISABLE-FUNCTIONS",
            not missing,
            "shell-execution functions are disabled",
            detail=", ".join(missing),
            threats=("TH1",),
        )
        rep.add(
            "PHP-OPEN-BASEDIR",
            "open_basedir" in values,
            "PHP file access is limited to the site (open_basedir)",
            severity="warn",
            threats=("TH1",),
        )
        rep.add(
            "PHP-DISPLAY-ERRORS",
            values.get("display_errors") == "off",
            "PHP errors are not shown to visitors",
            severity="warn",
            threats=("TH23",),
        )
