"""Self-signed placeholder certificate for a new site (like CloudPanel).

Every site gets one at creation, so HTTPS answers immediately: behind
Cloudflare with SSL/TLS mode "Full" the site works before (or without) a
Let's Encrypt certificate. It is replaced as soon as Let's Encrypt issues one.
Browsers reject it when visited directly, so a site on the placeholder keeps
serving plain HTTP too (no redirect, no HSTS; see web/nginx.py).

Files: <dir>/<domain>/cert.pem and key.pem, root-only (nginx's master reads
them as root). <dir> is /etc/nginx/ozenix/selfsigned.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence
from pathlib import Path

from ozenix.core import proc, validate
from ozenix.core.errors import OperationFailed
from ozenix.web.nginx import TlsFiles

OPENSSL = "/usr/bin/openssl"
DAYS = 3650

Runner = Callable[..., proc.Result]


def files(directory: Path, domain: str) -> TlsFiles | None:
    base = directory / validate.domain(domain)
    cert, key = base / "cert.pem", base / "key.pem"
    if cert.is_file() and key.is_file() and not cert.is_symlink() and not key.is_symlink():
        return TlsFiles(cert, key)
    return None


def ensure(directory: Path, domain: str, names: Sequence[str], run: Runner = proc.run) -> TlsFiles:
    """Create the placeholder if it does not exist yet (P-256, 10 years)."""
    domain = validate.domain(domain)
    existing = files(directory, domain)
    if existing is not None:
        return existing
    sans = ",".join(f"DNS:{validate.domain(n)}" for n in dict.fromkeys([domain, *names]))
    for d in (directory, directory / domain):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        d.chmod(0o700)
    base = directory / domain
    cert_new, key_new = base / "cert.pem.new", base / "key.pem.new"
    run(
        [
            OPENSSL, "req", "-x509", "-nodes",
            "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-days", str(DAYS),
            "-subj", f"/CN={domain}",
            "-addext", f"subjectAltName={sans}",
            "-keyout", str(key_new), "-out", str(cert_new),
        ],
        timeout=60,
    )  # fmt: skip
    if not (key_new.is_file() and cert_new.is_file()):
        raise OperationFailed("openssl did not create the placeholder certificate")
    key_new.chmod(0o600)
    cert_new.chmod(0o644)
    key_new.replace(base / "key.pem")
    cert_new.replace(base / "cert.pem")
    return TlsFiles(base / "cert.pem", base / "key.pem")


def remove(directory: Path, domain: str) -> None:
    base = directory / validate.domain(domain)
    if base.is_dir() and not base.is_symlink():
        shutil.rmtree(base)
