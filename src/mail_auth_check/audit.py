"""Run every check for a domain and compute the score."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .checks import (
    CheckContext,
    check_bimi,
    check_dkim,
    check_dmarc,
    check_headers,
    check_mta_sts,
    check_mx,
    check_reverse_dns,
    check_senders,
    check_spf,
    check_tlsrpt,
)
from .model import CheckResult, DomainReport
from .resolver import Resolver
from .util import Fetcher, is_valid_hostname

__all__ = ["ALL_CHECKS", "audit_domain", "grade_for", "score_report"]

# Order matters: later checks read what earlier ones stored in the context.
ALL_CHECKS: dict[str, Callable[[CheckContext], CheckResult]] = {
    "mx": check_mx,
    "spf": check_spf,
    "dkim": check_dkim,
    "dmarc": check_dmarc,
    "mta_sts": check_mta_sts,
    "tlsrpt": check_tlsrpt,
    "bimi": check_bimi,
}


def grade_for(score: int) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            return grade
    return "F"


def score_report(report: DomainReport) -> None:
    total = sum(c.max_score for c in report.checks)
    got = sum(min(c.score, c.max_score) for c in report.checks)
    report.score = round(100 * got / total) if total else 0
    report.grade = grade_for(report.score)


def audit_domain(
    domain: str,
    resolver: Resolver,
    fetcher: Fetcher | None = None,
    selectors: Sequence[str] = (),
    common_selectors: bool = True,
    sending_ips: Sequence[str] = (),
    headers_text: str | None = None,
    only: Sequence[str] | None = None,
    org_domain: str | None = None,
    bulk_sender: bool = True,
    timeout: float = 10.0,
) -> DomainReport:
    domain = domain.strip().rstrip(".").lower()
    if domain.startswith(("http://", "https://")) or "@" in domain:
        domain = domain.split("@")[-1].split("://")[-1].split("/")[0]
    if not is_valid_hostname(domain):
        raise ValueError(f"'{domain}' is not a valid domain name")
    ctx = CheckContext(
        domain=domain,
        resolver=resolver,
        fetcher=fetcher,
        selectors=list(selectors),
        common_selectors=common_selectors,
        sending_ips=list(sending_ips),
        headers_text=headers_text,
        org_domain=org_domain,
        timeout=timeout,
    )
    ctx.shared["bulk_sender"] = bulk_sender
    report = DomainReport(domain)
    if headers_text:
        headers = check_headers(ctx)
        ctx.results["headers"] = headers
        # Selectors seen in real signatures are the most reliable way to find the DKIM key.
        for sel in headers.data.get("selectors", []) or []:
            if sel not in ctx.selectors:
                ctx.selectors = [*ctx.selectors, sel]
    names = list(ALL_CHECKS) if not only else [n for n in ALL_CHECKS if n in only]
    unknown = [n for n in (only or []) if n not in ALL_CHECKS and n not in ("senders", "rdns", "headers")]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)}")
    for name in names:
        result = ALL_CHECKS[name](ctx)
        ctx.results[name] = result
        report.checks.append(result)
    if sending_ips:
        rdns = check_reverse_dns(ctx)
        ctx.results["rdns"] = rdns
        report.checks.append(rdns)
    if "headers" in ctx.results:
        report.checks.append(ctx.results["headers"])
    if (not only or "senders" in only) and all(n in ctx.results for n in ("spf", "dkim", "dmarc")):
        report.checks.append(check_senders(ctx))
    score_report(report)
    return report
