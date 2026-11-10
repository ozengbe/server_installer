"""nginx virtual hosts for Ozenix sites.

Every change is validated with ``nginx -t`` *before* nginx is reloaded; if
validation fails the previous file is restored (or the new one removed) and
nginx keeps running the old configuration untouched.

Logs live in a root-owned directory per tenant, never in a tenant-owned one:
nginx's master runs as root and opens log files, so a tenant able to replace
a log file with a symlink could make it append to any file on the system.
"""

from __future__ import annotations

import grp
import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from string import Template
from urllib.parse import urlsplit

from domainpilot.core import fsutil, proc, validate
from domainpilot.core.errors import OperationFailed, ValidationError
from domainpilot.core.paths import Paths

TEMPLATE_DIR = Path(__file__).parent / "templates"
SITE_KINDS = ("php", "static", "proxy", "maintenance")
NGINX = "/usr/sbin/nginx"
SYSTEMCTL = "/usr/bin/systemctl"

Runner = Callable[..., proc.Result]
Resolver = Callable[[str, int], list[str]]


DEFAULT_HSTS = 300  # 5 minutes: HSTS is rolled out in steps (raise once HTTPS is proven)
MAX_HSTS = 63072000  # 2 years
# Port 80 of a site with a trusted certificate: ACME challenges (snippet) + redirect.
REDIRECT = "    location / {\n        return 301 https://$host$request_uri;\n    }"


def _template(name: str) -> Template:
    return Template((TEMPLATE_DIR / name).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class TlsFiles:
    certificate: Path
    key: Path


def _resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True)
class Upstream:
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"https://{self.host}" + ("" if self.port == 443 else f":{self.port}")

    @property
    def host_header(self) -> str:
        return self.host if self.port == 443 else f"{self.host}:{self.port}"


def parse_upstream(value: str, *, resolve: Resolver = _resolve) -> Upstream:
    """Accept only https://<public hostname>[:port] (SSRF / lateral-movement guard)."""
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ValidationError("upstream must use https://")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValidationError("upstream must not contain credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise ValidationError("upstream must not contain a path")
    host = validate.domain(parts.hostname or "")  # rejects IP literals and special-use names
    try:
        port = parts.port or 443
    except ValueError:
        raise ValidationError("invalid upstream port") from None
    validate.port(port)
    try:
        addresses = resolve(host, port)
    except OSError as exc:
        raise ValidationError(f"upstream {host} does not resolve: {exc}") from None
    if not addresses:
        raise ValidationError(f"upstream {host} does not resolve")
    for addr in addresses:
        if not ipaddress.ip_address(addr.split("%")[0]).is_global:
            raise ValidationError(
                f"upstream {host} resolves to non-public address {addr}; refusing"
            )
    return Upstream(host, port)


class Nginx:
    def __init__(
        self,
        paths: Paths,
        *,
        conf_dir: Path = Path("/etc/nginx/domainpilot/sites"),
        log_root: Path = Path("/var/log/nginx/domainpilot"),
        run: Runner = proc.run,
        pid_file: Path = Path("/run/nginx.pid"),
        proc_root: Path = Path("/proc"),
        reload_timeout: float = 10.0,
    ) -> None:
        self.paths = paths
        self.conf_dir = conf_dir
        self.log_root = log_root
        self.run = run
        self.pid_file = pid_file
        self.proc_root = proc_root
        self.reload_timeout = reload_timeout

    def conf_path(self, domain: str) -> Path:
        return self.conf_dir / f"{validate.domain(domain)}.conf"

    def log_dir(self, tenant: str) -> Path:
        return self.log_root / validate.tenant_id(tenant)

    def render(
        self,
        kind: str,
        *,
        domain: str,
        aliases: list[str],
        tenant: str,
        upstream: Upstream | None = None,
        tls: TlsFiles | None = None,
        hsts_max_age: int = DEFAULT_HSTS,
        trusted: bool = True,
    ) -> str:
        """Compose the site body (php/static/proxy/maintenance) into the HTTP or
        HTTPS wrapper. HSTS is only ever sent over HTTPS.

        ``trusted=False`` is the self-signed placeholder certificate a new site gets
        until Let's Encrypt issues one: HTTPS works (e.g. behind Cloudflare in
        "Full" mode) but HTTP is served too, with no redirect and no HSTS, so direct
        visitors are never pushed onto a certificate their browser rejects."""
        if kind not in SITE_KINDS:
            raise ValidationError(f"unknown site kind {kind!r}")
        if kind == "proxy" and upstream is None:
            raise ValidationError("proxy sites need --upstream https://host")
        if not 0 <= hsts_max_age <= MAX_HSTS:
            raise ValidationError(f"HSTS max-age must be between 0 and {MAX_HSTS}")
        names = [validate.domain(domain), *(validate.domain(a) for a in aliases)]
        hsts = (
            f'    add_header Strict-Transport-Security "max-age={hsts_max_age}" always;'
            if tls and trusted and hsts_max_age
            else ""
        )
        values = {
            "domain": names[0],
            "server_names": " ".join(names),
            "tenant": validate.tenant_id(tenant),
            "docroot": str(self.paths.tenant_root(tenant) / "app" / "public"),
            "log_dir": str(self.log_dir(tenant)),
            "php_socket": str(self.paths.php_socket(tenant)),
            "upstream": upstream.url if upstream else "",
            "upstream_host": upstream.host_header if upstream else "",
            "hsts": hsts,
            "certificate": str(tls.certificate) if tls else "",
            "certificate_key": str(tls.key) if tls else "",
        }
        body = _template(f"{kind}.body.tmpl").substitute(values)
        wrapper = _template("https.tmpl" if tls else "http.tmpl")
        body = body.rstrip("\n")
        http_body = REDIRECT if trusted else body
        # The body is inserted as a value, so its nginx "$" variables are not re-read.
        return wrapper.substitute({**values, "body": body, "http_body": http_body})

    def ensure_log_dir(self, tenant: str) -> bool:
        """Root-owned, group adm (log readers), 0750."""
        try:
            gid = grp.getgrnam("adm").gr_gid
        except KeyError:
            gid = 0
        return fsutil.ensure_dir(self.log_dir(tenant), mode=0o750, uid=0, gid=gid)

    def _test(self) -> None:
        result = self.run([NGINX, "-t", "-q"], check=False, timeout=60)
        if not result.ok:
            lines = (result.stderr or result.stdout).strip().splitlines()
            raise OperationFailed(
                "nginx rejected the configuration: " + (lines[-1] if lines else "unknown error")
            )

    def _workers(self) -> set[int]:
        """PIDs of the nginx master's current worker processes."""
        try:
            master = int(self.pid_file.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return set()
        workers: set[int] = set()
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text(encoding="ascii", errors="replace")
            except OSError:
                continue
            # Field 4 (ppid) follows the ")" that closes the command name.
            fields = stat.rpartition(")")[2].split()
            if len(fields) > 1 and fields[1] == str(master):
                workers.add(int(entry.name))
        return workers

    def reload(self) -> None:
        """Reload nginx and wait until new workers (with the new config) are serving.

        `systemctl reload` only signals the master; until it has started new
        workers, old ones answer requests with the old configuration.
        """
        before = self._workers()
        self.run([SYSTEMCTL, "reload", "nginx"], timeout=60)
        if not before:
            return  # not running here (or not observable): nothing to wait for
        deadline = time.monotonic() + self.reload_timeout
        while not (self._workers() - before):
            if time.monotonic() >= deadline:
                raise OperationFailed(
                    "nginx did not start new workers after reload",
                    hint="check: journalctl -u nginx; tail /var/log/nginx/error.log",
                )
            time.sleep(0.05)
        # nginx forks the new workers before telling the old ones to quit; until
        # they have, a new connection can still reach an old-config worker. Wait
        # for them, best effort: one busy with a long download may linger.
        while self._workers() & before and time.monotonic() < deadline:
            time.sleep(0.05)

    def _restore(self, path: Path, previous: bytes | None) -> None:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            fsutil.atomic_write(path, previous, mode=0o644)

    def apply(self, domain: str, content: str) -> bytes | None:
        """Install a vhost, validate, reload. Returns the previous content (None = new)."""
        path = self.conf_path(domain)
        previous = fsutil.read_bytes_nofollow(path) if path.exists() else None
        fsutil.atomic_write(path, content, mode=0o644)
        try:
            self._test()
        except OperationFailed:
            self._restore(path, previous)
            raise
        self.reload()
        return previous

    def remove(self, domain: str) -> bytes | None:
        path = self.conf_path(domain)
        if not path.exists():
            return None
        previous = fsutil.read_bytes_nofollow(path)
        path.unlink()
        try:
            self._test()
        except OperationFailed:
            self._restore(path, previous)
            raise
        self.reload()
        return previous

    def restore(self, domain: str, previous: bytes | None) -> None:
        """Undo helper: put back what apply()/remove() replaced, then reload."""
        self._restore(self.conf_path(domain), previous)
        self._test()
        self.reload()
