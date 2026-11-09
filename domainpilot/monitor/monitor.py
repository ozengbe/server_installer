"""Self-monitoring: problems -> state transitions -> alerts.

Runs from dp-monitor.timer every few minutes (and from dp-alert@.service when
a watched unit finally fails). Each run collects the current problems,
compares them with the previous run (state file), and alerts only on change:
a new problem, a resolved problem, or a reminder while a problem persists.
Crashes that systemd recovered from on its own (bounded Restart=) are
detected via NRestarts and reported once, so silent crash loops are visible.
"""

from __future__ import annotations

import http.client
import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domainpilot.core import fsutil, proc
from domainpilot.core.errors import DPError
from domainpilot.health import Report
from domainpilot.monitor.alerts import Alert, Notifier

Runner = Callable[..., proc.Result]
Prober = Callable[[str], int | None]
SYSTEMCTL = "/usr/bin/systemctl"
WATCHED_UNITS = ("nginx.service", "mariadb.service", "fail2ban.service")
BACKUP_WARN_HOURS = 26
BACKUP_CRITICAL_HOURS = 50
DRILL_WARN_DAYS = 8


@dataclass(frozen=True)
class Problem:
    key: str
    severity: str
    message: str


def _key(check: str, message: str) -> str:
    """Stable identity of a health finding (values such as percentages excluded)."""
    if check in ("service", "disk", "certificate"):
        return f"{check}:{message.split()[0].rstrip(':')}"
    return check


def from_health(report: Report) -> list[Problem]:
    return [
        Problem(_key(c["check"], c["message"]), c["severity"], c["message"])
        for c in report.checks
        if c["severity"] in ("warn", "critical")
    ]


def http_probe(domain: str) -> int | None:
    """Status of GET / on the local web server for this site (None = no answer)."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
        conn.request("GET", "/", headers={"Host": domain, "User-Agent": "domainpilot-monitor"})
        status = conn.getresponse().status
        conn.close()
        return status
    except (OSError, http.client.HTTPException):
        return None


def site_problems(domains: Iterable[str], probe: Prober = http_probe) -> list[Problem]:
    out = []
    for domain in domains:
        status = probe(domain)
        if status is None or status >= 500:
            what = "does not answer" if status is None else f"answers HTTP {status}"
            out.append(Problem(f"site:{domain}", "critical", f"{domain} {what}"))
    return out


def _age_hours(stamp: str | None, now: float) -> float | None:
    if not stamp:
        return None
    try:
        return (now - time.mktime(time.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S"))) / 3600
    except ValueError:
        return None


def backup_problems(
    state: dict[str, Any], tenants: Iterable[tuple[str, str]], *, now: float | None = None
) -> list[Problem]:
    """tenants: (tenant id, created_at). Fresh sites get a grace period."""
    now = now or time.time()
    out = []
    sites = state.get("sites", {})
    for tenant, created in tenants:
        entry = sites.get(tenant, {})
        age = _age_hours(entry.get("last_success"), now)
        if age is None:
            site_age = _age_hours(created, now)
            if site_age is not None and site_age < BACKUP_WARN_HOURS:
                continue
            out.append(Problem(f"backup:{tenant}", "warn", f"{tenant} has never been backed up"))
        elif age >= BACKUP_CRITICAL_HOURS:
            out.append(
                Problem(f"backup:{tenant}", "critical", f"last backup of {tenant} {age:.0f}h ago")
            )
        elif age >= BACKUP_WARN_HOURS or entry.get("ok") is False:
            detail = entry.get("error") or f"last success {age:.0f}h ago"
            out.append(Problem(f"backup:{tenant}", "warn", f"backup of {tenant}: {detail}"))
    system = state.get("system", {})
    sys_age = _age_hours(system.get("last_success"), now)
    if system and (sys_age is None or sys_age >= BACKUP_WARN_HOURS):
        out.append(Problem("backup:system", "warn", "server configuration backup is overdue"))
    drill = state.get("test_restore", {})
    if drill:
        drill_age = _age_hours(drill.get("last_success"), now)
        if drill.get("ok") is False:
            out.append(Problem("backup:restore-test", "critical", "the last restore test FAILED"))
        elif drill_age is None or drill_age >= DRILL_WARN_DAYS * 24:
            out.append(Problem("backup:restore-test", "warn", "no successful restore test lately"))
    return out


def restart_counts(units: Iterable[str], run: Runner = proc.run) -> dict[str, int]:
    counts = {}
    for unit in units:
        try:
            out = run(
                [SYSTEMCTL, "show", "--property=NRestarts", "--value", unit],
                check=False,
                timeout=15,
            ).stdout.strip()
        except DPError:
            continue
        if out.isdigit():
            counts[unit] = int(out)
    return counts


class Monitor:
    def __init__(
        self,
        state_file: Path,
        notifier: Notifier | None,
        *,
        host: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.state_file = state_file
        self.notifier = notifier
        self.host = host
        self.clock = clock

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(fsutil.read_text_nofollow(self.state_file))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, state: dict[str, Any]) -> None:
        self.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        text = json.dumps(state, indent=2, sort_keys=True)
        fsutil.atomic_write(self.state_file, text, mode=0o600)

    def evaluate(
        self,
        problems: list[Problem],
        restarts: dict[str, int],
        *,
        failed_unit: str | None = None,
    ) -> list[Alert]:
        """Update the state file; return the alerts this run should send."""
        now = self.clock()
        state = self._load()
        active: dict[str, Any] = state.get("active", {})
        configured = self.notifier is not None and self.notifier.configured()
        settings = self.notifier.settings() if self.notifier and configured else None
        remind = (settings.reminder_hours if settings else 6) * 3600
        alerts: list[Alert] = []
        current = {p.key: p for p in problems}

        for key, p in current.items():
            known = active.get(key)
            if known is None or known["severity"] != p.severity:
                alerts.append(Alert(key, p.severity, p.message, "problem", self.host))
                active[key] = {"severity": p.severity, "since": now, "last_sent": now}
            elif p.severity == "critical" and now - known.get("last_sent", 0) >= remind:
                alerts.append(Alert(key, p.severity, p.message, "reminder", self.host))
                known["last_sent"] = now
            active[key]["message"] = p.message
        for key in [k for k in active if k not in current]:
            gone = active.pop(key)
            message = f"resolved: {gone.get('message', key)}"
            alerts.append(Alert(key, gone["severity"], message, "resolved", self.host))

        previous: dict[str, int] = state.get("restarts", {})
        for unit, count in restarts.items():
            before = previous.get(unit)
            if before is not None and count > before:
                alerts.append(
                    Alert(
                        f"crash:{unit}",
                        "warn",
                        f"{unit} crashed and was restarted automatically "
                        f"({count - before} time(s) since the last check)",
                        "event",
                        self.host,
                    )
                )
        if failed_unit:
            alerts.append(
                Alert(
                    f"failed:{failed_unit}",
                    "critical",
                    f"{failed_unit} failed and systemd gave up restarting it",
                    "event",
                    self.host,
                )
            )
        state.update(active=active, restarts=previous | restarts, checked_at=now)
        self._save(state)
        return alerts

    def deliver(self, alerts: list[Alert]) -> dict[str, Any]:
        sent, skipped, errors = 0, 0, []
        if not self.notifier or not self.notifier.configured():
            return {"sent": 0, "skipped": len(alerts), "errors": [], "configured": False}
        settings = self.notifier.settings()
        for alert in alerts:
            if not self.notifier.wants(alert.severity, settings):
                skipped += 1
                continue
            try:
                self.notifier.send(alert, settings)
                sent += 1
            except DPError as exc:
                errors.append(exc.message)
        return {"sent": sent, "skipped": skipped, "errors": errors, "configured": True}
