"""MTA-STS and TLS-RPT checks."""

from __future__ import annotations

import re

from ..model import CheckResult
from ..mta_sts import MAX_POLICY_BYTES, mx_matches, parse_policy, parse_sts_record, policy_url
from ..util import parse_tag_list
from .base import RFC, CheckContext, score_by_severity

__all__ = ["check_mta_sts", "check_tlsrpt", "parse_tlsrpt"]

MTA_STS_SCORE = 6.0
TLSRPT_SCORE = 4.0


def check_mta_sts(ctx: CheckContext) -> CheckResult:
    res = CheckResult("mta_sts", "MTA-STS")
    ref = RFC["mta-sts"]
    if ctx.shared.get("null_mx"):
        res.info("mta_sts.null_mx", "The domain has a null MX; MTA-STS is not needed.")
        res.max_score = 0.0
        return res
    ans = ctx.resolver.resolve(f"_mta-sts.{ctx.domain}", "TXT")
    if ans.failed:
        res.dns_failure = True
        res.error("mta_sts.dns", f"The TXT lookup for _mta-sts.{ctx.domain} failed: {ans.error}.")
        res.max_score = MTA_STS_SCORE
        return res
    # 3.1: records that do not begin with v=STSv1; are discarded; exactly one must remain.
    records = [t for t in ans.records if re.match(r"^v=STSv1\s*;", t)] if ans.status == "ok" else []
    if not records:
        res.warn(
            "mta_sts.missing",
            f"No MTA-STS record at _mta-sts.{ctx.domain}.",
            "MTA-STS makes senders require TLS with a valid certificate when delivering to you. Publish "
            "'v=STSv1; id=<timestamp>' and a policy file at " + policy_url(ctx.domain) + ".",
            ref,
        )
        res.max_score = MTA_STS_SCORE
        res.score = MTA_STS_SCORE * 0.4
        return res
    if len(records) > 1:
        res.error(
            "mta_sts.multiple",
            f"{len(records)} MTA-STS records; senders then ignore MTA-STS.",
            "Publish exactly one v=STSv1 record.",
            ref + "#section-3.1",
        )
        score_by_severity(res, MTA_STS_SCORE)
        return res
    rec = parse_sts_record(records[0])
    res.data = {"record": rec.text, "id": rec.id, "policyUrl": policy_url(ctx.domain)}
    if rec.errors:
        for err in rec.errors:
            res.error("mta_sts.record_syntax", f"_mta-sts record: {err}", reference=ref + "#section-3.1")
    else:
        res.ok("mta_sts.record", f"MTA-STS record found: {rec.text}")

    if ctx.fetcher is None:
        res.info("mta_sts.not_fetched", "The policy file was not fetched (HTTP checks disabled).")
        score_by_severity(res, MTA_STS_SCORE)
        return res
    url = policy_url(ctx.domain)
    got = ctx.fetcher(url, ctx.timeout, MAX_POLICY_BYTES)
    if got.error:
        res.error(
            "mta_sts.fetch",
            f"Fetching {url} failed: {got.error}.",
            "The policy host needs a valid certificate for mta-sts." + ctx.domain + " and must answer over HTTPS.",
            ref + "#section-3.3",
        )
        score_by_severity(res, MTA_STS_SCORE)
        return res
    if 300 <= got.status < 400:
        res.error(
            "mta_sts.redirect",
            f"{url} answers with a redirect ({got.status}); senders must not follow it.",
            "Serve the policy directly with status 200.",
            ref + "#section-3.3",
        )
        score_by_severity(res, MTA_STS_SCORE)
        return res
    if got.status != 200:
        res.error(
            "mta_sts.status",
            f"{url} answers with HTTP {got.status}; only 200 is valid.",
            reference=ref + "#section-3.3",
        )
        score_by_severity(res, MTA_STS_SCORE)
        return res
    if got.truncated:
        res.error("mta_sts.too_large", f"The policy is larger than {MAX_POLICY_BYTES} bytes.")
    ctype = got.content_type.split(";")[0].strip().lower()
    if ctype != "text/plain":
        res.warn(
            "mta_sts.content_type",
            f"The policy is served as '{got.content_type or 'no type'}'; senders should check for text/plain.",
            "Serve it as text/plain.",
            ref + "#section-3.3",
        )
    policy = parse_policy(got.body.decode("utf-8", errors="replace"))
    res.data["policy"] = {"mode": policy.mode, "maxAge": policy.max_age, "mx": policy.mx}
    for err in policy.errors:
        res.error("mta_sts.policy_syntax", f"Policy: {err}", reference=ref + "#section-3.2")
    for w in policy.warnings:
        res.warn("mta_sts.policy_style", f"Policy: {w}")
    if not policy.errors:
        res.ok(
            "mta_sts.policy",
            f"Policy file valid: mode {policy.mode}, max_age {policy.max_age}, mx {', '.join(policy.mx) or '-'}.",
        )
    if policy.mode == "testing":
        res.warn(
            "mta_sts.testing",
            "mode is testing: failures are only reported, not enforced.",
            "Switch to mode: enforce after TLS-RPT reports look clean.",
        )
    elif policy.mode == "none":
        res.warn("mta_sts.mode_none", "mode is none: the policy is switched off.")
    if policy.max_age is not None and policy.max_age < 86400 and policy.mode == "enforce":
        res.warn(
            "mta_sts.short_max_age",
            f"max_age {policy.max_age} is under a day; senders refetch often and "
            "a short cache gives little protection.",
            "Use at least 604800 (one week).",
        )
    mx_hosts = ctx.shared.get("mx_hosts") or []
    if policy.mode in ("enforce", "testing") and policy.mx:
        for host in mx_hosts:
            if not any(mx_matches(host, p) for p in policy.mx):
                res.error(
                    "mta_sts.mx_mismatch",
                    f"MX {host} does not match any mx: pattern in the policy; "
                    "senders enforcing the policy will not deliver to it.",
                    "Add the host (or a *. pattern) to the policy and change the id= in DNS.",
                    ref + "#section-4.1",
                )
    score_by_severity(res, MTA_STS_SCORE)
    return res


def parse_tlsrpt(text: str) -> tuple[list[str], list[str]]:
    """Return (rua URIs, errors) for a v=TLSRPTv1 record (RFC 8460 3)."""
    errors: list[str] = []
    tags = parse_tag_list(text, lower_names=False)
    if not tags.order or tags.order[0] != "v" or tags.get("v") != "TLSRPTv1":
        errors.append("the record must start with v=TLSRPTv1")
    rua = tags.get("rua")
    if not rua:
        errors.append("the required rua= field is missing")
        return [], errors
    uris = [u.strip() for u in rua.split(",") if u.strip()]
    for uri in uris:
        scheme = uri.split(":", 1)[0].lower() if ":" in uri else ""
        if scheme not in ("mailto", "https"):
            errors.append(f"rua URI '{uri}' must use mailto: or https:")
        elif scheme == "mailto" and "@" not in uri:
            errors.append(f"rua URI '{uri}' is not a valid mailto: address")
    return uris, errors


def check_tlsrpt(ctx: CheckContext) -> CheckResult:
    res = CheckResult("tlsrpt", "TLS-RPT")
    ref = RFC["tlsrpt"]
    if ctx.shared.get("null_mx"):
        res.info("tlsrpt.null_mx", "The domain has a null MX; TLS reporting is not needed.")
        return res
    ans = ctx.resolver.resolve(f"_smtp._tls.{ctx.domain}", "TXT")
    res.max_score = TLSRPT_SCORE
    if ans.failed:
        res.dns_failure = True
        res.error("tlsrpt.dns", f"The TXT lookup for _smtp._tls.{ctx.domain} failed: {ans.error}.")
        return res
    records = [t for t in ans.records if re.match(r"^v=TLSRPTv1\s*;", t)] if ans.status == "ok" else []
    has_sts = bool(ctx.results.get("mta_sts") and ctx.results["mta_sts"].has("mta_sts.record"))
    if not records:
        msg = f"No TLS-RPT record at _smtp._tls.{ctx.domain}."
        hint = "Publish 'v=TLSRPTv1; rua=mailto:tls-reports@" + ctx.domain + "' to get reports about TLS failures."
        if has_sts:
            res.warn(
                "tlsrpt.missing", msg + " Without it you will not hear about MTA-STS delivery failures.", hint, ref
            )
        else:
            res.warn("tlsrpt.missing", msg, hint, ref)
        res.score = TLSRPT_SCORE * 0.4
        return res
    if len(records) > 1:
        res.error(
            "tlsrpt.multiple",
            f"{len(records)} TLS-RPT records; senders then assume there is none.",
            "Publish exactly one v=TLSRPTv1 record.",
            ref + "#section-3",
        )
        res.score = 0.0
        return res
    uris, errors = parse_tlsrpt(records[0])
    res.data = {"record": records[0], "rua": uris}
    for err in errors:
        res.error("tlsrpt.syntax", err, reference=ref + "#section-3")
    if not errors:
        res.ok("tlsrpt.present", f"TLS-RPT record found: {records[0]}")
    score_by_severity(res, TLSRPT_SCORE)
    return res
