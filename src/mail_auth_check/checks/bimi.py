"""BIMI check (draft-brand-indicators-for-message-identification)."""

from __future__ import annotations

import re

from ..model import CheckResult
from ..util import parse_tag_list
from .base import RFC, CheckContext, score_by_severity

__all__ = ["check_bimi", "parse_bimi"]

MAX_SCORE = 4.0
LOGO_MAX_BYTES = 32 * 1024


def parse_bimi(text: str) -> tuple[dict[str, str], list[str]]:
    tags = parse_tag_list(text)
    errors = list(tags.errors)
    if not tags.order or tags.order[0] != "v" or tags.get("v") != "BIMI1":
        errors.append("the record must start with v=BIMI1")
    if "l" not in tags:
        errors.append("the l= tag (logo URI) is required")
    for name in ("l", "a"):
        value = tags.get(name)
        if value:
            for uri in value.split(","):
                if not uri.strip().lower().startswith("https://"):
                    errors.append(f"{name}={uri.strip()} must be an https:// URI")
    return dict(tags.tags), errors


def check_bimi(ctx: CheckContext, selector: str = "default") -> CheckResult:
    res = CheckResult("bimi", "BIMI")
    res.max_score = MAX_SCORE
    ref = RFC["bimi"]
    name = f"{selector}._bimi.{ctx.domain}"
    ans = ctx.resolver.resolve(name, "TXT")
    if ans.failed:
        res.dns_failure = True
        res.warn("bimi.dns", f"The TXT lookup for {name} failed: {ans.error}.")
        score_by_severity(res, MAX_SCORE)
        return res
    records = [t for t in ans.records if re.match(r"^\s*v\s*=\s*BIMI1", t, re.IGNORECASE)] if ans.ok else []
    dmarc = ctx.shared.get("dmarc")
    if not records:
        res.info(
            "bimi.missing",
            f"No BIMI record at {name} (optional; shows your logo in supporting inboxes).",
            "BIMI needs DMARC at quarantine (pct=100) or reject, an SVG Tiny PS logo and, for Gmail and Apple, "
            "a mark certificate (VMC or CMC).",
            ref,
        )
        res.score = MAX_SCORE * 0.5
        return res
    if len(records) > 1:
        res.error("bimi.multiple", f"{name} has {len(records)} BIMI records.", "Keep exactly one.")
        score_by_severity(res, MAX_SCORE)
        return res
    tags, errors = parse_bimi(records[0])
    res.data = {"record": records[0], "logo": tags.get("l"), "evidence": tags.get("a")}
    if tags.get("l") == "" and not tags.get("a"):
        res.info("bimi.declined", "The record declines BIMI participation (empty l= and a=).")
        res.score = MAX_SCORE * 0.5
        return res
    for err in errors:
        res.error("bimi.syntax", err, reference=ref)
    if not errors:
        res.ok("bimi.present", f"BIMI record found: {records[0]}")
    # DMARC prerequisites
    if dmarc is None:
        res.error("bimi.no_dmarc", "BIMI requires a DMARC policy, and none was found.")
    else:
        strong = dmarc.policy == "reject" or (dmarc.policy == "quarantine" and dmarc.pct == 100)
        if not strong:
            res.error(
                "bimi.weak_dmarc",
                f"DMARC is p={dmarc.policy} pct={dmarc.pct}; BIMI needs quarantine at pct=100 or reject.",
                "Raise the DMARC policy before expecting logos to show.",
                ref,
            )
        if dmarc.subdomain_policy == "none":
            res.error("bimi.sp_none", "DMARC sp=none: receivers skip BIMI when the subdomain policy is none.")
    if not tags.get("a"):
        res.info("bimi.no_vmc", "No a= evidence document (VMC/CMC); Gmail and Apple Mail show logos only with one.")
    logo = (tags.get("l") or "").split(",")[0].strip()
    if logo and ctx.fetcher is not None and logo.lower().startswith("https://"):
        got = ctx.fetcher(logo, ctx.timeout, LOGO_MAX_BYTES)
        if got.error or got.status != 200:
            res.error("bimi.logo_fetch", f"The logo {logo} could not be fetched ({got.error or got.status}).")
        else:
            body = got.body.decode("utf-8", errors="replace")
            ctype = got.content_type.split(";")[0].strip().lower()
            if "<svg" not in body:
                res.error("bimi.logo_not_svg", "The logo is not an SVG document.")
            elif not re.search(r"baseProfile\s*=\s*[\"']tiny-ps[\"']", body):
                res.warn(
                    "bimi.logo_profile",
                    'The SVG does not declare baseProfile="tiny-ps" (SVG Tiny PS).',
                    "Export the logo as SVG Tiny Portable/Secure.",
                )
            else:
                res.ok("bimi.logo", "The logo is an SVG Tiny PS document.")
            if ctype and ctype != "image/svg+xml":
                res.warn("bimi.logo_type", f"The logo is served as {ctype}, not image/svg+xml.")
            if got.truncated:
                res.warn("bimi.logo_size", f"The logo is larger than {LOGO_MAX_BYTES // 1024} KB.")
    score_by_severity(res, MAX_SCORE)
    return res
