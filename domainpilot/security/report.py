"""Findings and reports shared by every security command (Phase 9).

A finding names the control it checked, the threat(s) from docs/threat-model.md
it guards against, what was found, and how to fix it. Reports never claim more
than the listed checks: every report carries the disclaimer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("ok", "info", "warn", "critical")
DISCLAIMER = (
    "Automated checks passed for the listed controls only. This is not a guarantee of security."
)


@dataclass(frozen=True)
class Finding:
    id: str  # e.g. "SSH-PASSWORD"
    severity: str  # ok | info | warn | critical
    title: str
    detail: str = ""
    fix: str = ""
    threats: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")


@dataclass
class SecurityReport:
    scope: str  # "system" or a domain
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        fid: str,
        ok: bool,
        title: str,
        *,
        detail: str = "",
        fix: str = "",
        threats: tuple[str, ...] = (),
        severity: str = "critical",
    ) -> None:
        """Record a check: `ok` passes, otherwise it fails with `severity`."""
        self.findings.append(
            Finding(fid, "ok" if ok else severity, title, detail, "" if ok else fix, threats)
        )

    def info(self, fid: str, title: str, detail: str = "", threats: tuple[str, ...] = ()) -> None:
        self.findings.append(Finding(fid, "info", title, detail, "", threats))

    def extend(self, other: SecurityReport) -> None:
        self.findings.extend(other.findings)

    @property
    def worst(self) -> str:
        return max((f.severity for f in self.findings), key=SEVERITIES.index, default="ok")

    def counts(self) -> dict[str, int]:
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}

    def problems(self) -> list[Finding]:
        return sorted(
            (f for f in self.findings if f.severity in ("warn", "critical")),
            key=lambda f: -SEVERITIES.index(f.severity),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "worst": self.worst,
            "counts": self.counts(),
            "findings": [asdict(f) | {"threats": list(f.threats)} for f in self.findings],
            "disclaimer": DISCLAIMER,
        }

    def lines(self, *, verbose: bool) -> list[str]:
        mark = {"ok": "ok  ", "info": "info", "warn": "WARN", "critical": "CRIT"}
        shown = self.findings if verbose else self.problems()
        out = []
        for f in sorted(shown, key=lambda f: -SEVERITIES.index(f.severity)):
            out.append(f"{mark[f.severity]}  {f.id:<22} {f.title}")
            if f.severity in ("warn", "critical"):
                if f.detail:
                    out.append(f"      {f.detail}")
                if f.fix:
                    out.append(f"      fix: {f.fix}")
        c = self.counts()
        out.append(
            f"{len(self.findings)} checks: {c['ok']} ok, {c['info']} info, "
            f"{c['warn']} warning(s), {c['critical']} critical"
        )
        return out
