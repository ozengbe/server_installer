"""ACME certificates through certbot (Ubuntu archive package).

certbot keeps its state in /etc/letsencrypt and renews from its own systemd
timer; a deploy hook installed by the installer validates and reloads nginx.
Before a certificate is put into service we verify it ourselves: it must
cover every requested name, be within its validity period, match its private
key, and the key must be readable by root only.
"""

from __future__ import annotations

import re
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from domainpilot.core import proc, validate
from domainpilot.core.errors import OperationFailed
from domainpilot.web.nginx import TlsFiles

CERTBOT = "/usr/bin/certbot"
OPENSSL = "/usr/bin/openssl"
LIVE = Path("/etc/letsencrypt/live")
WEBROOT = Path("/var/lib/domainpilot-acme")
CERTBOT_TIMEOUT = 300
# Required owner of private keys (root; tests run unprivileged and override it).
ROOT_UID = 0
DNS_PROPAGATION_SECONDS = 30

Runner = Callable[..., proc.Result]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class CertInfo:
    names: tuple[str, ...]
    not_after: datetime
    issuer: str
    days_left: int

    @property
    def staging(self) -> bool:
        return "(STAGING)" in self.issuer


def parse_x509_text(text: str, now: datetime) -> CertInfo:
    """Parse `openssl x509 -noout -enddate -issuer -ext subjectAltName` output."""
    end = re.search(r"^notAfter=(.+)$", text, re.MULTILINE)
    issuer = re.search(r"^issuer=(.+)$", text, re.MULTILINE)
    if not end or not issuer:
        raise OperationFailed("could not read the certificate's validity or issuer")
    not_after = datetime.strptime(" ".join(end.group(1).split()), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=UTC
    )
    names = tuple(sorted(set(re.findall(r"DNS:([A-Za-z0-9.*-]+)", text))))
    return CertInfo(names, not_after, issuer.group(1).strip(), (not_after - now).days)


class Certbot:
    def __init__(
        self,
        *,
        run: Runner = proc.run,
        live: Path = LIVE,
        webroot: Path = WEBROOT,
        now: Clock = lambda: datetime.now(UTC),
    ) -> None:
        self.run = run
        self.live = live
        self.webroot = webroot
        self.now = now

    def files(self, domain: str) -> TlsFiles:
        base = self.live / validate.domain(domain)
        return TlsFiles(base / "fullchain.pem", base / "privkey.pem")

    def exists(self, domain: str) -> bool:
        files = self.files(domain)
        return files.certificate.exists() and files.key.exists()

    def info(self, domain: str) -> CertInfo | None:
        cert = self.live / validate.domain(domain) / "cert.pem"
        if not cert.exists():
            return None
        result = self.run(
            [
                OPENSSL,
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-enddate",
                "-issuer",
                "-ext",
                "subjectAltName",
            ],
            timeout=30,
        )
        return parse_x509_text(result.stdout, self.now())

    def issue(
        self,
        domain: str,
        names: Sequence[str],
        *,
        staging: bool,
        email: str | None,
        dns_credentials: Path | None = None,
    ) -> None:
        """Obtain (or extend) the certificate named after the primary domain.

        HTTP-01 through the webroot by default; DNS-01 through Cloudflare when
        ``dns_credentials`` (a RAM-only credentials file) is given.
        """
        domain = validate.domain(domain)
        if dns_credentials is None:
            challenge = ["--webroot", "-w", str(self.webroot)]
        else:
            challenge = [
                "--dns-cloudflare",
                "--dns-cloudflare-credentials",
                str(dns_credentials),
                "--dns-cloudflare-propagation-seconds",
                str(DNS_PROPAGATION_SECONDS),
            ]
        argv = [
            CERTBOT,
            "certonly",
            "--non-interactive",
            "--agree-tos",
            *challenge,
            "--cert-name",
            domain,
            "--expand",
            "--key-type",
            "ecdsa",
            "--elliptic-curve",
            "secp256r1",
        ]
        for name in names:
            argv += ["-d", validate.domain(name)]
        if email:
            argv += ["--email", validate_email(email)]
        else:
            argv.append("--register-unsafely-without-email")
        if staging:
            argv.append("--staging")
        current = self.info(domain) if self.exists(domain) else None
        if current is not None and current.staging != staging:
            # Switching between staging and production CAs needs a fresh certificate.
            argv += ["--force-renewal", "--break-my-certs"]
        self.run(argv, timeout=CERTBOT_TIMEOUT)

    def renew(self, domain: str, *, force: bool) -> None:
        # Without a TTY certbot sleeps up to 8 min before renewing (meant for the
        # timer, to spread load on the CA). An admin's manual renew must not wait.
        argv = [
            CERTBOT,
            "renew",
            "--non-interactive",
            "--no-random-sleep-on-renew",
            "--cert-name",
            validate.domain(domain),
        ]
        if force:
            argv.append("--force-renewal")
        self.run(argv, timeout=CERTBOT_TIMEOUT)

    def revoke(self, domain: str) -> None:
        info = self.info(domain)
        argv = [
            CERTBOT,
            "revoke",
            "--non-interactive",
            "--cert-name",
            validate.domain(domain),
            "--delete-after-revoke",
            "--reason",
            "unspecified",
        ]
        if info is not None and info.staging:
            argv.append("--staging")  # revoke at the CA that issued it
        self.run(argv, timeout=CERTBOT_TIMEOUT)

    def delete(self, domain: str) -> None:
        if (self.live / validate.domain(domain)).exists():
            self.run([CERTBOT, "delete", "--non-interactive", "--cert-name", domain], timeout=120)

    def verify(self, domain: str, names: Sequence[str]) -> CertInfo:
        """Refuse to put a certificate into service unless it is exactly right."""
        info = self.info(domain)
        if info is None or not self.exists(domain):
            raise OperationFailed(f"no certificate files for {domain}")
        missing = sorted(set(names) - set(info.names))
        if missing:
            raise OperationFailed(f"certificate does not cover: {', '.join(missing)}")
        if info.not_after <= self.now():
            raise OperationFailed(f"certificate for {domain} has expired")
        files = self.files(domain)
        cert_key = self.run(
            [OPENSSL, "x509", "-in", str(files.certificate), "-noout", "-pubkey"], timeout=30
        ).stdout
        key_pub = self.run([OPENSSL, "pkey", "-in", str(files.key), "-pubout"], timeout=30).stdout
        if not cert_key.strip() or cert_key.strip() != key_pub.strip():
            raise OperationFailed(f"certificate and private key for {domain} do not match")
        st = files.key.stat()  # follows live/ -> archive/; both are root-only
        if st.st_uid != ROOT_UID or stat.S_IMODE(st.st_mode) & 0o077:
            raise OperationFailed(f"private key for {domain} is readable by non-root users")
        return info


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")


def validate_email(value: str) -> str:
    if not _EMAIL_RE.fullmatch(value):
        raise OperationFailed(f"invalid ACME account email {value!r}")
    return value
