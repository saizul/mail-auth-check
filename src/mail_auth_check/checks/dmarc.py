"""DMARC check, including external report destination verification (RFC 7489 7.1)."""

from __future__ import annotations

from ..dmarc import DmarcRecord, is_dmarc_record, parse_dmarc
from ..model import CheckResult
from ..util import organizational_domain
from .base import RFC, CheckContext

__all__ = ["check_dmarc", "lookup_dmarc"]

MAX_SCORE = 30.0
REF = RFC["dmarc"]


def lookup_dmarc(ctx: CheckContext, res: CheckResult) -> tuple[str | None, DmarcRecord | None]:
    """Find the policy for the domain, falling back to the organizational domain (6.6.3)."""
    org = ctx.org_domain or organizational_domain(ctx.domain)
    candidates = [ctx.domain] if org == ctx.domain else [ctx.domain, org]
    for name in candidates:
        ans = ctx.resolver.resolve(f"_dmarc.{name}", "TXT")
        if ans.failed:
            res.dns_failure = True
            res.error("dmarc.dns", f"The TXT lookup for _dmarc.{name} failed: {ans.error}.")
            return None, None
        records = [t for t in ans.records if is_dmarc_record(t)] if ans.status == "ok" else []
        if len(records) > 1:
            res.error(
                "dmarc.multiple",
                f"_dmarc.{name} has {len(records)} DMARC records; receivers ignore them all.",
                "Keep exactly one v=DMARC1 record.",
                REF + "#section-6.6.3",
            )
            return name, None
        if records:
            return name, parse_dmarc(records[0])
        other = [t for t in ans.records if t.lower().replace(" ", "").startswith("v=dmarc")] if ans.ok else []
        if other:
            res.error("dmarc.bad_version", f"_dmarc.{name} has a record that does not start with v=DMARC1: {other[0]}")
            return name, None
    return None, None


def check_dmarc(ctx: CheckContext) -> CheckResult:
    res = CheckResult("dmarc", "DMARC")
    res.max_score = MAX_SCORE
    found_at, rec = lookup_dmarc(ctx, res)
    ctx.shared["dmarc"] = rec
    ctx.shared["dmarc_domain"] = found_at
    if rec is None:
        if not res.findings:
            res.error(
                "dmarc.missing",
                f"No DMARC record at _dmarc.{ctx.domain}.",
                "Start with 'v=DMARC1; p=none; rua=mailto:dmarc-reports@" + ctx.domain + "', read the reports, "
                "then move to p=quarantine and p=reject. Gmail and Yahoo require DMARC for bulk senders.",
                REF + "#section-6.1",
            )
        return res
    res.data = {
        "foundAt": f"_dmarc.{found_at}",
        "record": rec.text,
        "policy": rec.policy,
        "subdomainPolicy": rec.effective_subdomain_policy,
        "pct": rec.pct,
        "adkim": rec.adkim,
        "aspf": rec.aspf,
        "rua": [u.raw for u in rec.rua],
        "ruf": [u.raw for u in rec.ruf],
    }
    if found_at != ctx.domain:
        res.info("dmarc.inherited", f"No record at _dmarc.{ctx.domain}; the policy of {found_at} applies.")
    res.ok("dmarc.present", f"DMARC record found at _dmarc.{found_at}: {rec.text}")
    for err in rec.errors:
        res.error("dmarc.syntax", err, reference=REF + "#section-6.3")
    for w in rec.warnings:
        res.warn("dmarc.style", w, reference=REF + "#section-6.3")
    for tag in rec.unknown_tags:
        res.info("dmarc.unknown_tag", f"Unknown tag '{tag}=' (ignored by receivers).")

    inherited = found_at != ctx.domain
    policy = rec.effective_subdomain_policy if inherited else rec.policy
    score = 0.0
    if policy == "reject":
        res.ok("dmarc.reject", "Policy is reject: failing mail is refused.")
        score = 1.0
    elif policy == "quarantine":
        res.ok("dmarc.quarantine", "Policy is quarantine: failing mail goes to spam.")
        res.info("dmarc.consider_reject", "Move to p=reject once reports show all legitimate mail passes.")
        score = 0.9
    elif policy == "none":
        res.warn(
            "dmarc.none",
            "Policy is none: monitoring only, spoofed mail is still delivered.",
            "Enough for the Gmail/Yahoo bulk-sender rules, but move to quarantine or reject after reviewing "
            "aggregate reports.",
            REF + "#section-6.3",
        )
        score = 0.6
    if rec.policy and rec.pct < 100 and rec.enforcing:
        res.warn(
            "dmarc.pct",
            f"pct={rec.pct}: the policy applies to only {rec.pct}% of failing mail.",
            "Raise pct to 100 when you are confident.",
            REF + "#section-6.3",
        )
        score -= 0.1
    if not inherited and rec.enforcing and rec.subdomain_policy == "none":
        res.warn(
            "dmarc.sp_none",
            "sp=none leaves subdomains unprotected while the domain itself enforces.",
            "Remove sp= or set it to quarantine/reject.",
        )
        score -= 0.1
    if rec.adkim == "s" or rec.aspf == "s":
        res.info("dmarc.strict", f"Strict alignment (adkim={rec.adkim}, aspf={rec.aspf}): subdomain senders fail.")
    if not rec.rua:
        res.warn(
            "dmarc.no_rua",
            "No rua= address: you get no aggregate reports.",
            "Add rua=mailto:... to see who sends as your domain (Yahoo strongly recommends it).",
            RFC["yahoo"],
        )
        score -= 0.15
    if rec.ruf:
        res.info("dmarc.ruf", "ruf= is set; few receivers send failure reports, and they may contain personal data.")

    # 7.1 external destination verification
    org = ctx.org_domain or organizational_domain(found_at or ctx.domain)
    checked: set[str] = set()
    for tag, uris in (("rua", rec.rua), ("ruf", rec.ruf)):
        for uri in uris:
            if uri.error or not uri.host:
                continue
            if uri.scheme != "mailto":
                res.warn("dmarc.uri_scheme", f"{tag}: {uri.raw} is not a mailto: URI; most receivers only send mail.")
            if organizational_domain(uri.host) == org or uri.host in checked:
                continue
            checked.add(uri.host)
            name = f"{found_at}._report._dmarc.{uri.host}"
            ans = ctx.resolver.resolve(name, "TXT")
            if ans.failed:
                res.dns_failure = True
                res.warn("dmarc.external_dns", f"Could not verify {uri.host}: DNS error for {name}.")
                continue
            wildcard = f"*._report._dmarc.{uri.host}"
            authorized = ans.status == "ok" and any(is_dmarc_record(t) for t in ans.records)
            if authorized:
                res.ok("dmarc.external_ok", f"{uri.host} accepts {tag} reports for {found_at} ({name}).")
            else:
                res.error(
                    "dmarc.external_unverified",
                    f"{tag} goes to {uri.host}, which does not publish {name}; receivers will not send these reports.",
                    f"Ask the report provider to publish 'v=DMARC1' at {name} (or {wildcard}).",
                    REF + "#section-7.1",
                )
                score -= 0.1
    if rec.errors:
        score = min(score, 0.2)
    res.score = max(0.0, MAX_SCORE * score)
    return res
