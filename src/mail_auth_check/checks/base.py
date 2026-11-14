"""Check context and scoring helpers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ..model import CheckResult
from ..resolver import Resolver
from ..util import Fetcher

__all__ = ["RFC", "CheckContext", "score_by_severity"]

RFC = {
    "spf": "https://www.rfc-editor.org/rfc/rfc7208",
    "dkim": "https://www.rfc-editor.org/rfc/rfc6376",
    "dkim-ed25519": "https://www.rfc-editor.org/rfc/rfc8463",
    "dkim-rsa": "https://www.rfc-editor.org/rfc/rfc8301",
    "dmarc": "https://www.rfc-editor.org/rfc/rfc7489",
    "mta-sts": "https://www.rfc-editor.org/rfc/rfc8461",
    "tlsrpt": "https://www.rfc-editor.org/rfc/rfc8460",
    "null-mx": "https://www.rfc-editor.org/rfc/rfc7505",
    "smtp": "https://www.rfc-editor.org/rfc/rfc5321",
    "bimi": "https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/",
    "gmail": "https://support.google.com/a/answer/81126",
    "yahoo": "https://senders.yahooinc.com/best-practices/",
    "one-click": "https://www.rfc-editor.org/rfc/rfc8058",
}


@dataclass
class CheckContext:
    domain: str
    resolver: Resolver
    fetcher: Fetcher | None = None  # None disables HTTPS fetches (MTA-STS policy, BIMI logo)
    selectors: Sequence[str] = ()
    common_selectors: bool = True
    sending_ips: Sequence[str] = ()
    headers_text: str | None = None
    org_domain: str | None = None
    timeout: float = 10.0
    results: dict[str, CheckResult] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)


def score_by_severity(result: CheckResult, max_score: float) -> None:
    """Default scoring: full points without problems, partial points for warnings, none for an error."""
    result.max_score = max_score
    errors = sum(1 for f in result.findings if f.severity == "error")
    warnings = sum(1 for f in result.findings if f.severity == "warning")
    if errors:
        result.score = 0.0
    elif warnings:
        result.score = max_score * max(0.3, 0.75 - 0.15 * (warnings - 1))
    else:
        result.score = max_score
