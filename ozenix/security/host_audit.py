"""`site system audit` / `site system security`: read-only checks of the host.

Every check compares the *running* state (sshd -T, nft, sysctl, MariaDB
variables, file modes) with the security baseline, so drift after install is
caught, not just the files the installer wrote. Nothing here changes anything.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ozenix.core import proc
from ozenix.core.errors import DPError
from ozenix.security.report import SecurityReport

Runner = Callable[..., proc.Result]
PUBLIC_PORTS = {22, 80, 443}
SSHD_EXPECT = {
    "permitemptypasswords": ("no",),
    "permituserenvironment": ("no",),
}
# Hardening tips for the server's own login (warnings: the owner decides).
SSHD_RECOMMEND: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("permitrootlogin", ("no", "prohibit-password", "without-password"),
     "root cannot log in with a password"),
    ("passwordauthentication", ("no",), "SSH passwords are off (keys only)"),
    ("x11forwarding", ("no",), "X11 forwarding is off"),
)  # fmt: skip


@dataclass
class HostView:
    """Where to look; tests point it at a fake tree and a fake runner."""

    run: Runner = proc.run
    root: Path = Path("/")

    def p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def out(self, *argv: str, timeout: float = 60) -> str | None:
        try:
            r = self.run(list(argv), check=False, timeout=timeout)
        except DPError:
            return None
        return r.stdout if r.ok else None


def _mode(path: Path) -> tuple[int, int, int] | None:
    try:
        st = path.lstat()
    except OSError:
        return None
    return stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid


def check_ssh(view: HostView, rep: SecurityReport) -> None:
    """The server's own login is the owner's choice (ozenix leaves it as it is):
    only real holes are critical; hardening tips are warnings."""
    text = view.out("/usr/sbin/sshd", "-T")
    if text is None:
        rep.add(
            "SSH-CONFIG",
            False,
            "sshd configuration readable",
            detail="sshd -T failed",
            fix="sudo sshd -t",
            threats=("TH14",),
        )
        return
    conf: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        conf.setdefault(key.lower(), value.strip())
    for key, allowed in SSHD_EXPECT.items():
        rep.add(
            f"SSH-{key.upper()}",
            conf.get(key) in allowed,
            f"sshd {key} {allowed[0]}",
            detail=f"running value: {conf.get(key)}",
            fix="re-run the installer (role ssh)",
            threats=("TH14", "TH15"),
        )
    for key, good, tip in SSHD_RECOMMEND:
        rep.add(
            f"SSH-{key.upper()}",
            conf.get(key) in good,
            tip,
            detail=f"running value: {conf.get(key)}",
            fix=f"set '{key} {good[0]}' in /etc/ssh/sshd_config.d/ (your choice)",
            severity="warn",
            threats=("TH14",),
        )
    rep.add(
        "SSH-KEYS-DIR",
        "/etc/ssh/authorized_keys.d/%u" in conf.get("authorizedkeysfile", "").split(),
        "site users' keys come from a root-owned location",
        detail=conf.get("authorizedkeysfile", ""),
        fix="re-run the installer (role ssh)",
        threats=("TH14", "TH15"),
    )


def check_firewall(view: HostView, rep: SecurityReport) -> None:
    chain = view.out("/usr/sbin/nft", "list", "chain", "inet", "ozenix", "input")
    rep.add(
        "FW-TABLE",
        chain is not None,
        "ozenix firewall rules are loaded",
        fix="sudo systemctl restart nftables",
        threats=("TH4", "TH5", "TH20"),
    )
    if chain is not None:
        rep.add(
            "FW-DEFAULT-DENY",
            "policy drop" in chain,
            "inbound default policy is drop",
            threats=("TH5",),
        )
    egress = view.out("/usr/sbin/nft", "list", "chain", "inet", "ozenix", "tenant_egress")
    rep.add(
        "FW-TENANT-EGRESS",
        egress is not None and "drop" in egress,
        "tenant egress is filtered (metadata, loopback, private ranges)",
        threats=("TH4", "TH5"),
    )
    if view.p("/var/lib/ozenix/firewall/pending").exists():
        rep.add(
            "FW-PENDING",
            False,
            "no unconfirmed firewall change",
            severity="warn",
            fix="sudo site system firewall confirm (or rollback)",
            threats=("TH20",),
        )


def public_listeners(text: str) -> list[str]:
    bad = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        local = cols[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if addr.startswith("127.") or addr in ("::1",):
            continue
        if port.isdigit() and int(port) not in PUBLIC_PORTS:
            bad.append(f"{cols[0]} {local}")
    return sorted(set(bad))


def check_listeners(view: HostView, rep: SecurityReport) -> None:
    text = view.out("/usr/bin/ss", "-H", "-l", "-n", "-t", "-u")
    if text is None:
        return
    bad = public_listeners(text)
    rep.add(
        "NET-LISTENERS",
        not bad,
        "nothing but SSH/HTTP/HTTPS listens publicly",
        detail=", ".join(bad),
        fix="stop or bind the service to 127.0.0.1",
        threats=("TH5",),
    )


def check_sysctl(view: HostView, rep: SecurityReport) -> None:
    conf = view.p("/etc/sysctl.d/99-zz-ozenix.conf")  # as written by role sysctl
    try:
        lines = conf.read_text(encoding="utf-8").splitlines()
    except OSError:
        rep.add(
            "KERN-SYSCTL",
            False,
            "kernel hardening settings installed",
            severity="warn",
            fix="re-run the installer (role sysctl)",
            threats=("TH1",),
        )
        return
    drift = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        key, sep, want = line.partition("=")
        if not sep:
            continue
        key, want = key.strip(), " ".join(want.split())
        if not re.fullmatch(r"[a-z0-9_.-]+", key):
            continue
        live_path = view.p("/proc/sys/" + key.replace(".", "/"))
        try:
            live = " ".join(live_path.read_text(encoding="ascii").split())
        except OSError:
            continue  # not present on this kernel
        if live != want:
            drift.append(f"{key}={live} (want {want})")
    rep.add(
        "KERN-SYSCTL",
        not drift,
        "kernel hardening settings are in effect",
        detail="; ".join(drift),
        fix="sudo sysctl --system",
        threats=("TH1", "TH3"),
    )


def check_mariadb(view: HostView, rep: SecurityReport) -> None:
    sql = (
        "SELECT @@skip_networking, @@local_infile;"
        "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='' OR host NOT IN "
        "('localhost','127.0.0.1','::1');"
    )
    text = view.out("/usr/bin/mariadb", "--batch", "--skip-column-names", "-e", sql)
    if text is None:
        rep.add(
            "DB-REACHABLE",
            False,
            "MariaDB can be audited",
            severity="warn",
            fix="sudo systemctl status mariadb",
            threats=("TH7",),
        )
        return
    rows = [r.split("\t") for r in text.strip().splitlines()]
    first = rows[0] if rows else []
    rep.add(
        "DB-NO-TCP",
        first[:1] == ["1"],
        "MariaDB does not listen on the network",
        threats=("TH5", "TH7"),
    )
    rep.add("DB-LOCAL-INFILE", first[1:2] == ["0"], "LOAD DATA LOCAL is disabled", threats=("TH7",))
    odd = [r[0] for r in rows[1:] if r and r[0]]
    rep.add(
        "DB-ACCOUNTS",
        not odd,
        "no anonymous or remote database accounts",
        detail=", ".join(odd),
        fix="DROP USER the listed accounts",
        threats=("TH7",),
    )
    privs = view.out(
        "/usr/bin/mariadb", "--batch", "--skip-column-names", "-e",
        "SELECT CONCAT(user,'@',host) FROM mysql.global_priv WHERE user REGEXP '^t[0-9]{4}$' "
        "AND JSON_VALUE(priv,'$.access') NOT IN ('0');",
    )  # fmt: skip
    tenants_global = (privs or "").split()
    rep.add(
        "DB-TENANT-GLOBAL",
        not tenants_global,
        "site database users have no global rights",
        detail=", ".join(tenants_global),
        threats=("TH7",),
    )


@dataclass(frozen=True)
class PathRule:
    path: str
    max_mode: int  # bits beyond these are a finding
    owner: int = 0
    fid: str = "PERM"
    threats: tuple[str, ...] = ("TH17",)
    recursive_files: int | None = None  # max mode for files below


PATH_RULES = (
    PathRule("/etc/ozenix", 0o750, fid="PERM-ETC", threats=("TH16", "TH17")),
    PathRule("/etc/ozenix/secrets", 0o700, fid="PERM-SECRETS", threats=("TH16",),
             recursive_files=0o600),
    PathRule("/var/lib/ozenix", 0o700, fid="PERM-STATE", threats=("TH17",)),
    PathRule("/var/lib/ozenix/registry.sqlite3", 0o600, fid="PERM-REGISTRY"),
    PathRule("/usr/lib/ozenix", 0o755, fid="PERM-CODE", threats=("TH17",),
             recursive_files=0o755),
    PathRule("/usr/local/bin/site", 0o755, fid="PERM-CLI", threats=("TH17",)),
    PathRule("/etc/letsencrypt/archive", 0o700, fid="PERM-TLS-KEYS", threats=("TH22",)),
    PathRule("/etc/ssh/authorized_keys.d", 0o755, fid="PERM-SSH-KEYS", threats=("TH14",),
             recursive_files=0o644),
)  # fmt: skip


def _too_open(mode: int, allowed: int) -> bool:
    return bool(mode & ~allowed & 0o7777)


def check_paths(
    view: HostView, rep: SecurityReport, rules: Iterable[PathRule] = PATH_RULES
) -> None:
    for rule in rules:
        path = view.p(rule.path)
        info = _mode(path)
        if info is None:
            continue
        mode, uid, _gid = info
        problems = []
        if stat.S_ISLNK(path.lstat().st_mode):
            problems.append("is a symlink")
        if uid != rule.owner:
            problems.append(f"owner uid {uid}")
        if _too_open(mode, rule.max_mode):
            problems.append(f"mode {mode:04o} (max {rule.max_mode:04o})")
        if rule.recursive_files is not None and path.is_dir():
            for dirpath, dirnames, filenames in os.walk(path):
                for name in [*filenames, *dirnames]:
                    sub = Path(dirpath) / name
                    sinfo = _mode(sub)
                    if sinfo is None:
                        continue
                    if sub.is_symlink():  # e.g. /usr/lib/ozenix/current
                        inside = sub.resolve().is_relative_to(path.resolve())
                        if sinfo[1] != rule.owner or not inside:
                            problems.append(f"{sub.relative_to(path)}: symlink leaving the tree")
                        continue
                    limit = rule.max_mode if name in dirnames else rule.recursive_files
                    if sinfo[1] != rule.owner or _too_open(sinfo[0], limit):
                        problems.append(f"{sub.relative_to(path)}: {sinfo[0]:04o} uid {sinfo[1]}")
                if len(problems) > 5:
                    break
        rep.add(
            rule.fid,
            not problems,
            f"{rule.path} is root-owned and not too open",
            detail="; ".join(problems[:6]),
            fix=f"chown -R root and chmod {rule.path}",
            threats=rule.threats,
        )


def check_audit_log(view: HostView, rep: SecurityReport) -> None:
    log = view.p("/var/log/ozenix/audit.jsonl")
    if not log.exists():
        return
    attrs = view.out("/usr/bin/lsattr", "-d", str(log))
    flags = (attrs or "").split(" ", 1)[0]
    rep.add(
        "AUDIT-APPEND-ONLY",
        "a" in flags,
        "the audit log is append-only (chattr +a)",
        detail=flags,
        severity="warn",
        fix=f"sudo chattr +a {log}",
        threats=("TH19",),
    )


def check_services(view: HostView, rep: SecurityReport) -> None:
    def active(unit: str) -> bool:
        return (view.out("/usr/bin/systemctl", "is-active", unit) or "").strip() == "active"

    try:
        aa = view.p("/sys/module/apparmor/parameters/enabled").read_text().strip()
    except OSError:
        aa = ""
    rep.add("AA-ENABLED", aa == "Y", "AppArmor is enabled", threats=("TH1",))
    if view.p("/usr/bin/cscli").exists():
        collections = view.out("/usr/bin/cscli", "collections", "list", "-o", "raw") or ""
        rep.add(
            "IDS-SSH",
            active("crowdsec")
            and active("crowdsec-firewall-bouncer")
            and "crowdsecurity/sshd" in collections,
            "CrowdSec protects SSH (sshd scenarios and the firewall bouncer are active)",
            severity="warn",
            threats=("TH14",),
        )
    else:
        rep.add(
            "IDS-SSH",
            view.out("/usr/bin/fail2ban-client", "status", "sshd") is not None,
            "fail2ban protects SSH",
            severity="warn",
            threats=("TH14",),
        )
    rep.add(
        "UPD-TIMER",
        active("apt-daily-upgrade.timer"),
        "automatic security updates are scheduled",
        severity="warn",
        threats=("TH17",),
    )
    rep.add(
        "MON-TIMER",
        active("dp-monitor.timer"),
        "self-monitoring runs",
        severity="warn",
        threats=("TH18", "TH19"),
    )
    rep.add(
        "AUDITD",
        active("auditd"),
        "the kernel audit daemon runs",
        severity="warn",
        threats=("TH19",),
    )


def check_nginx(view: HostView, rep: SecurityReport) -> None:
    dump = view.out("/usr/sbin/nginx", "-T", timeout=60)
    if dump is None:
        rep.add(
            "NGX-CONFIG",
            False,
            "nginx configuration is valid",
            fix="sudo nginx -t",
            threats=("TH23",),
        )
        return
    rep.add(
        "NGX-TOKENS",
        re.search(r"^\s*server_tokens\s+off;", dump, re.M) is not None,
        "nginx does not reveal its version",
        severity="warn",
        threats=("TH23",),
    )
    rep.add(
        "NGX-DEFAULT-444",
        "return 444" in dump and "ssl_reject_handshake on" in dump,
        "unknown host names get no site (444, TLS handshake refused)",
        threats=("TH11",),
    )
    sources = re.findall(r"^\s*set_real_ip_from\s+(\S+);", dump, re.M)
    wide = [s for s in sources if s in ("0.0.0.0/0", "::/0", "all")]
    rep.add(
        "NGX-REALIP",
        not wide,
        "client IPs are trusted only from Cloudflare's ranges",
        detail=", ".join(wide),
        threats=("TH13",),
    )
    rep.add(
        "NGX-LIMITS",
        "limit_req_zone" in dump and "limit_conn_zone" in dump,
        "request and connection rate limits are defined",
        severity="warn",
        threats=("TH24",),
    )
    # Token-exact: "TLSv1" must not match inside "TLSv1.2".
    protocols = " ".join(re.findall(r"^\s*ssl_protocols\s+([^;]*);", dump, re.M)).split()
    weak = sorted({p for p in protocols if p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")})
    rep.add(
        "NGX-TLS-PROTOCOLS", not weak, "only TLS 1.2/1.3", detail=", ".join(weak), threats=("TH23",)
    )


def check_backups_and_alerts(view: HostView, rep: SecurityReport) -> None:
    conf = view.p("/etc/ozenix/backup.json")
    if not conf.exists():
        rep.add(
            "BKP-CONFIGURED",
            False,
            "backups are configured",
            severity="warn",
            fix="sudo site system backup setup --repository s3:https://...",
            threats=("TH18",),
        )
    else:
        text = conf.read_text(encoding="utf-8", errors="replace")
        rep.add(
            "BKP-OFFSITE",
            '"s3:' in text,
            "backups are stored off this server",
            detail="local repository: lost together with the server",
            severity="warn",
            fix="use an S3 bucket with Object Lock (docs/install.md)",
            threats=("TH18",),
        )
    rep.add(
        "MON-ALERTS",
        view.p("/etc/ozenix/alerts.json").exists(),
        "alerts are delivered somewhere",
        severity="warn",
        fix="echo URL | sudo site system alerts setup --kind ntfy --url-stdin",
        threats=("TH18", "TH19"),
    )


ALL_CHECKS = (
    check_ssh,
    check_firewall,
    check_listeners,
    check_sysctl,
    check_mariadb,
    check_paths,
    check_audit_log,
    check_services,
    check_nginx,
    check_backups_and_alerts,
)


def audit_host(view: HostView | None = None) -> SecurityReport:
    view = view or HostView()
    rep = SecurityReport("system")
    for check in ALL_CHECKS:
        check(view, rep)
    return rep
