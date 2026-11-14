"""MX sanity checks (RFC 5321 5.1, RFC 7505 null MX, RFC 2181 10.3)."""

from __future__ import annotations

import ipaddress

from ..model import CheckResult
from .base import RFC, CheckContext, score_by_severity

__all__ = ["check_mx"]

MAX_SCORE = 6.0


_NON_PUBLIC = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "::/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _non_public(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return any(ip.version == n.version and ip in n for n in _NON_PUBLIC)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def check_mx(ctx: CheckContext) -> CheckResult:
    res = CheckResult("mx", "MX")
    ans = ctx.resolver.resolve(ctx.domain, "MX")
    ctx.shared["mx_hosts"] = []
    ctx.shared["null_mx"] = False
    if ans.failed:
        res.dns_failure = True
        res.error("mx.dns", f"The MX lookup for {ctx.domain} failed: {ans.error}.")
        res.max_score = MAX_SCORE
        return res
    if not ans.ok:
        a = ctx.resolver.resolve(ctx.domain, "A")
        aaaa = ctx.resolver.resolve(ctx.domain, "AAAA")
        if a.ok or aaaa.ok:
            res.warn(
                "mx.implicit",
                f"{ctx.domain} has no MX record; senders fall back to its A/AAAA address (implicit MX).",
                "Publish an MX record, or a null MX ('0 .') if the domain receives no mail.",
                RFC["smtp"] + "#section-5.1",
            )
        else:
            res.warn(
                "mx.none",
                f"{ctx.domain} has no MX record and no address: it cannot receive mail.",
                "Bounces and DMARC reports to this domain are lost. Publish an MX or a null MX ('0 .').",
            )
        score_by_severity(res, MAX_SCORE)
        return res

    records = sorted(ans.records)
    res.data = {"mx": [{"preference": p, "exchange": h} for p, h in records]}
    if any(h in ("", ".") for _, h in records):
        ctx.shared["null_mx"] = True
        if len(records) == 1 and records[0][0] == 0:
            res.ok("mx.null", "Null MX ('0 .'): the domain explicitly accepts no mail.")
            res.info(
                "mx.null_spf",
                "A domain that sends no mail should also publish 'v=spf1 -all' and p=reject.",
                reference=RFC["null-mx"],
            )
        else:
            res.error(
                "mx.null_mixed",
                "A null MX ('.') is mixed with other MX records.",
                "A null MX must be the only MX record, with preference 0.",
                RFC["null-mx"],
            )
        score_by_severity(res, MAX_SCORE)
        return res

    res.ok("mx.present", f"{len(records)} MX record(s): " + ", ".join(f"{p} {h}" for p, h in records))
    hosts: list[str] = []
    for pref, host in records:
        if _is_ip(host):
            res.error(
                "mx.ip_literal",
                f"MX {host} is an IP address; MX records must name a host.",
                "Point the MX at a host name with A/AAAA records.",
                RFC["smtp"] + "#section-5.1",
            )
            continue
        cname = ctx.resolver.resolve(host, "CNAME")
        if cname.ok:
            res.warn(
                "mx.cname",
                f"MX {host} is a CNAME (to {cname.records[0]}); MX targets must not be aliases.",
                "Use the canonical host name in the MX record.",
                "https://www.rfc-editor.org/rfc/rfc2181#section-10.3",
            )
        a = ctx.resolver.resolve(host, "A")
        aaaa = ctx.resolver.resolve(host, "AAAA")
        if a.failed and aaaa.failed:
            res.dns_failure = True
            res.warn("mx.dns_host", f"Could not resolve MX host {host} (DNS error).")
            continue
        if not a.ok and not aaaa.ok:
            res.error(
                "mx.unresolvable",
                f"MX {host} (preference {pref}) has no A or AAAA record.",
                "Fix or remove the MX record; senders cannot deliver to it.",
            )
            continue
        for addr in [*a.records, *aaaa.records]:
            if _non_public(addr):
                res.error("mx.private_ip", f"MX {host} resolves to the non-public address {addr}.")
        hosts.append(host)
    ctx.shared["mx_hosts"] = hosts
    prefs = [p for p, _ in records]
    if len(records) == 1:
        res.info("mx.single", "Only one MX host; consider a second one for redundancy (or rely on the provider's).")
    elif len(set(prefs)) == 1:
        res.info("mx.equal_pref", "All MX records have the same preference; mail is spread between them.")
    score_by_severity(res, MAX_SCORE)
    return res
