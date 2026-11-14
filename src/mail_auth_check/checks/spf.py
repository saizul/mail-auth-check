"""SPF check."""

from __future__ import annotations

import ipaddress

from ..model import CheckResult
from ..spf import LOOKUP_LIMIT, VOID_LIMIT, analyze, check_host
from .base import RFC, CheckContext, score_by_severity

__all__ = ["check_spf"]

MAX_SCORE = 25.0
REF = RFC["spf"]


def check_spf(ctx: CheckContext) -> CheckResult:
    res = CheckResult("spf", "SPF")
    analysis = analyze(ctx.resolver, ctx.domain)
    ctx.shared["spf"] = analysis
    res.data = analysis.to_dict()
    root = analysis.root

    if root.status == "temperror" and root.record is None:
        res.dns_failure = True
        res.error(
            "spf.dns",
            f"The TXT lookup for {ctx.domain} failed: {root.notes[0] if root.notes else 'error'}",
            "Check that the domain's name servers answer; receivers treat this as temperror.",
        )
        res.max_score = MAX_SCORE
        return res
    if root.status == "none":
        res.error(
            "spf.missing",
            f"{ctx.domain} has no SPF record.",
            "Publish one TXT record, for example 'v=spf1 include:<your provider> -all', or 'v=spf1 -all' if the "
            "domain sends no mail.",
            REF,
        )
        res.max_score = MAX_SCORE
        return res
    if root.duplicates:
        res.error(
            "spf.multiple",
            f"{ctx.domain} publishes {len(root.duplicates)} SPF records; receivers return permerror.",
            "Merge them into a single 'v=spf1 ...' TXT record.",
            REF + "#section-4.5",
        )
        res.max_score = MAX_SCORE
        return res

    record = root.record
    assert record is not None
    res.ok("spf.present", f"SPF record found: {root.text}")
    for err in record.errors:
        res.error(
            "spf.syntax",
            f"Syntax error: {err}",
            "Fix the term; any syntax error makes the whole policy fail.",
            REF + "#section-12",
        )
    for warning in record.warnings:
        res.warn("spf.style", warning)

    # Lookup limits (4.6.4)
    n = analysis.total_lookups
    if n > LOOKUP_LIMIT:
        res.error(
            "spf.too_many_lookups",
            f"The policy needs {n} DNS lookups; the limit is {LOOKUP_LIMIT}, so receivers return permerror.",
            "Remove unused includes, replace 'a'/'mx'/'ptr' with ip4:/ip6: ranges, or flatten includes you control.",
            REF + "#section-4.6.4",
        )
    elif n >= LOOKUP_LIMIT - 1:
        res.warn(
            "spf.near_lookup_limit",
            f"The policy needs {n} of {LOOKUP_LIMIT} allowed DNS lookups.",
            "One more include from a provider will break SPF; trim the record now.",
            REF + "#section-4.6.4",
        )
    else:
        res.ok("spf.lookups", f"{n} of {LOOKUP_LIMIT} DNS lookups used.")
    if analysis.total_void > VOID_LIMIT:
        res.error(
            "spf.too_many_void",
            f"{analysis.total_void} lookups return no records (void lookups); more than {VOID_LIMIT} is a permerror.",
            "Remove mechanisms that point at names without records.",
            REF + "#section-4.6.4",
        )
    elif analysis.total_void:
        res.warn(
            "spf.void_lookup",
            f"{analysis.total_void} lookup(s) return no records (void lookups).",
            "Remove mechanisms that point at names without records; receivers allow at most two.",
            REF + "#section-4.6.4",
        )

    for node in root.walk():
        for note in node.notes:
            if "void lookup" in note or "'ptr'" in note:
                continue
            res.info("spf.note", f"{node.domain}: {note}")
        if node.record and any(t.name == "ptr" for t in node.record.mechanisms):
            res.warn(
                "spf.ptr",
                f"{node.domain} uses the 'ptr' mechanism.",
                "RFC 7208 says 'ptr' SHOULD NOT be published: it is slow and unreliable. Use ip4:/ip6: instead.",
                REF + "#section-5.5",
            )
        if node is not root and node.status in ("permerror", "loop"):
            res.error(
                "spf.include_error",
                f"{node.via}:{node.domain} cannot be evaluated ({node.status}).",
                "An include or redirect that fails makes the whole policy fail.",
                REF + "#section-5.2",
            )
        if node.status == "temperror":
            res.dns_failure = True
            res.warn("spf.include_dns", f"DNS error while reading the SPF record of {node.domain}.")
    for err in analysis.errors:
        if "MX hosts" in err:
            res.error("spf.tree", err, reference=REF + "#section-4.6.4")

    # The final "all"
    qualifier = analysis.effective_all()
    if qualifier == "+":
        res.error(
            "spf.plus_all",
            "The policy ends with '+all': every server on the internet passes SPF.",
            "Use '-all' (or '~all' while testing).",
            REF + "#section-5.1",
        )
    elif qualifier == "?":
        res.warn(
            "spf.neutral_all",
            "The policy ends with '?all' (neutral): it gives no protection.",
            "Use '-all', or '~all' while you confirm all senders are listed.",
            REF + "#section-5.1",
        )
    elif qualifier == "~":
        res.ok("spf.softfail_all", "The policy ends with '~all' (softfail).")
        res.info(
            "spf.consider_fail", "With DMARC enforcing, '~all' is common; '-all' rejects unlisted senders outright."
        )
    elif qualifier == "-":
        res.ok("spf.fail_all", "The policy ends with '-all' (fail).")
    elif not record.errors:
        res.warn(
            "spf.no_all",
            "The policy has no 'all' mechanism and no redirect, so unlisted senders get neutral.",
            "End the record with '-all' or '~all'.",
            REF + "#section-4.7",
        )

    # Overly broad ranges
    for net in analysis.ip4:
        prefix = int(net.split("/")[1]) if "/" in net else 32
        if prefix < 16:
            res.warn(
                "spf.broad_ip4",
                f"ip4:{net} authorizes {2 ** (32 - prefix):,} addresses.",
                "List only the addresses that send mail.",
            )
    for net in analysis.ip6:
        prefix = int(net.split("/")[1]) if "/" in net else 128
        if prefix < 32:
            res.warn("spf.broad_ip6", f"ip6:{net} is a very large range.", "List only the networks that send mail.")
    if root.text and len(root.text) > 450:
        res.info("spf.long", f"The record is {len(root.text)} characters long; very long TXT answers may need TCP.")

    # Evaluate the given sending IPs
    if ctx.sending_ips:
        evaluations = []
        for ip in ctx.sending_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                res.error("spf.bad_ip", f"'{ip}' is not an IP address.")
                continue
            ev = check_host(ctx.resolver, ip, ctx.domain)
            evaluations.append({"ip": ip, **ev.to_dict()})
            if ev.result == "pass":
                res.ok("spf.ip_pass", f"{ip}: pass ({ev.reason}).")
            elif ev.result in ("fail", "softfail", "neutral", "none"):
                res.error(
                    "spf.ip_not_authorized",
                    f"{ip}: {ev.result} ({ev.reason}).",
                    f"Add the sender to the SPF record, e.g. 'ip4:{ip}' or its provider's include.",
                )
            else:
                res.error("spf.ip_error", f"{ip}: {ev.result} ({ev.reason}).")
        res.data["evaluations"] = evaluations

    score_by_severity(res, MAX_SCORE)
    return res
