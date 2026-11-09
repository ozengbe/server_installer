"""Alert delivery to a webhook / push service.

The destination URL usually *is* the secret (ntfy topic, Slack/Discord hook,
Telegram bot token), so it is stored encrypted (core.secrets, area "alerts")
and given to `site` on stdin only. Non-secret settings live in
/etc/domainpilot/alerts.json.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from domainpilot.core import fsutil
from domainpilot.core.errors import OperationFailed, PreconditionFailed, ValidationError
from domainpilot.core.secrets import SecretStore

KINDS = ("ntfy", "slack", "discord", "telegram", "webhook")
SEVERITIES = ("info", "warn", "critical")
_HTTPS_RE = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[!-~]*)?")
# Plain HTTP only to this machine (tests, a local relay); never across the network.
_LOCAL_HTTP_RE = re.compile(r"http://127\.0\.0\.1:[0-9]{1,5}(?:/[!-~]*)?")

Sender = Callable[[str, bytes, dict[str, str]], None]


def validate_url(url: str) -> str:
    url = url.strip()
    if not (_HTTPS_RE.fullmatch(url) or _LOCAL_HTTP_RE.fullmatch(url)):
        raise ValidationError(
            "the alert URL must be https://... (or http://127.0.0.1:<port>/... for a local relay)"
        )
    return url


@dataclass(frozen=True)
class Alert:
    key: str
    severity: str
    message: str
    state: str  # "problem" | "resolved" | "reminder" | "event" | "test"
    host: str

    @property
    def title(self) -> str:
        label = {
            "problem": self.severity.upper(),
            "reminder": f"STILL {self.severity.upper()}",
            "resolved": "RESOLVED",
            "event": self.severity.upper(),
            "test": "TEST",
        }[self.state]
        return f"[{label}] {self.host}: {self.key}"


def payload(kind: str, alert: Alert) -> tuple[bytes, dict[str, str]]:
    text = f"{alert.title}\n{alert.message}"
    if kind == "ntfy":
        priority = {"critical": "urgent", "warn": "high"}.get(alert.severity, "default")
        if alert.state == "resolved":
            priority = "default"
        return alert.message.encode(), {
            "Title": alert.title.encode("ascii", "replace").decode(),
            "Priority": priority,
            "Tags": "white_check_mark" if alert.state == "resolved" else "warning",
        }
    body: dict[str, Any]
    if kind == "slack":
        body = {"text": text}
    elif kind == "discord":
        body = {"content": text[:1900]}
    elif kind == "telegram":
        body = {"text": text[:4000]}
    else:
        body = {"source": "domainpilot", **asdict(alert), "title": alert.title}
    return json.dumps(body).encode(), {"Content-Type": "application/json"}


def http_send(url: str, data: bytes, headers: dict[str, str]) -> None:
    request = urllib.request.Request(  # noqa: S310 - scheme validated (https / loopback http)
        url, data=data, headers={"User-Agent": "domainpilot-alerts", **headers}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            if response.status >= 300:
                raise OperationFailed(f"alert endpoint answered HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise OperationFailed(f"alert endpoint answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise OperationFailed(f"could not reach the alert endpoint: {exc}") from None


@dataclass
class AlertSettings:
    kind: str
    min_severity: str = "warn"
    reminder_hours: int = 6

    def validate(self) -> AlertSettings:
        if self.kind not in KINDS:
            raise ValidationError(f"alert kind must be one of: {', '.join(KINDS)}")
        if self.min_severity not in SEVERITIES:
            raise ValidationError(f"severity must be one of: {', '.join(SEVERITIES)}")
        if not 1 <= self.reminder_hours <= 168:
            raise ValidationError("reminder interval must be 1-168 hours")
        return self


class Notifier:
    def __init__(
        self, etc: Path, *, store: SecretStore | None = None, sender: Sender = http_send
    ) -> None:
        self.file = etc / "alerts.json"
        self.store = store or SecretStore(etc / "secrets" / "alerts", "alerts")
        self.sender = sender
        self.host = socket.gethostname()

    def configured(self) -> bool:
        return self.file.exists() and self.store.exists("webhook")

    def settings(self) -> AlertSettings:
        if not self.file.exists():
            raise PreconditionFailed(
                "alerts are not configured",
                hint="echo '<url>' | sudo site system alerts setup --kind ntfy --url-stdin",
            )
        data = json.loads(fsutil.read_text_nofollow(self.file))
        return AlertSettings(**data).validate()

    def setup(self, settings: AlertSettings, url: str) -> None:
        settings.validate()
        self.store.save("webhook", validate_url(url))
        fsutil.atomic_write(self.file, json.dumps(asdict(settings), indent=2) + "\n", mode=0o600)

    def remove(self) -> None:
        self.store.remove("webhook")
        self.file.unlink(missing_ok=True)

    def wants(self, severity: str, settings: AlertSettings) -> bool:
        return SEVERITIES.index(severity) >= SEVERITIES.index(settings.min_severity)

    def send(self, alert: Alert, settings: AlertSettings | None = None) -> None:
        settings = settings or self.settings()
        url = validate_url(self.store.load("webhook"))
        data, headers = payload(settings.kind, alert)
        self.sender(url, data, headers)
