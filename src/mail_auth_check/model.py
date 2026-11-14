"""Result types shared by all checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["SEVERITIES", "CheckResult", "DomainReport", "Finding", "worst"]

# Ordered from best to worst.
SEVERITIES = ("ok", "info", "warning", "error")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def worst(severities: list[str] | tuple[str, ...], default: str = "ok") -> str:
    return max(severities, key=lambda s: _RANK[s], default=default)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    hint: str | None = None
    reference: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in _RANK:
            raise ValueError(f"unknown severity {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"severity": self.severity, "code": self.code, "message": self.message}
        if self.hint:
            out["hint"] = self.hint
        if self.reference:
            out["reference"] = self.reference
        return out


@dataclass
class CheckResult:
    """The outcome of one check (SPF, DKIM, ...). ``score`` is out of ``max_score`` points."""

    name: str
    title: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    max_score: float = 0.0
    dns_failure: bool = False

    def add(
        self, severity: str, code: str, message: str, hint: str | None = None, reference: str | None = None
    ) -> Finding:
        f = Finding(severity, code, message, hint, reference)
        self.findings.append(f)
        return f

    def ok(self, code: str, message: str) -> Finding:
        return self.add("ok", code, message)

    def info(self, code: str, message: str, hint: str | None = None, reference: str | None = None) -> Finding:
        return self.add("info", code, message, hint, reference)

    def warn(self, code: str, message: str, hint: str | None = None, reference: str | None = None) -> Finding:
        return self.add("warning", code, message, hint, reference)

    def error(self, code: str, message: str, hint: str | None = None, reference: str | None = None) -> Finding:
        return self.add("error", code, message, hint, reference)

    @property
    def status(self) -> str:
        return worst([f.severity for f in self.findings])

    def has(self, code: str) -> bool:
        return any(f.code == code for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status,
            "score": round(self.score, 1),
            "maxScore": self.max_score,
            "dnsFailure": self.dns_failure,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }


@dataclass
class DomainReport:
    domain: str
    checks: list[CheckResult] = field(default_factory=list)
    score: int = 0
    grade: str = "F"

    def get(self, name: str) -> CheckResult | None:
        return next((c for c in self.checks if c.name == name), None)

    @property
    def status(self) -> str:
        return worst([c.status for c in self.checks])

    @property
    def dns_failure(self) -> bool:
        return any(c.dns_failure for c in self.checks)

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(SEVERITIES, 0)
        for c in self.checks:
            for f in c.findings:
                out[f.severity] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "status": self.status,
            "counts": self.counts(),
            "checks": [c.to_dict() for c in self.checks],
        }
