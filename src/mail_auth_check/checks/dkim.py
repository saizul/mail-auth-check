"""DKIM check: selector discovery, key type and key length."""

from __future__ import annotations

from ..dkim import COMMON_SELECTORS, DkimKey, looks_like_dkim, parse_dkim_record
from ..model import CheckResult
from .base import RFC, CheckContext

__all__ = ["check_dkim", "selectors_to_try"]

MAX_SCORE = 25.0
WILDCARD_PROBE = "mac-probe-7f3a9c"


def selectors_to_try(ctx: CheckContext) -> list[str]:
    seen: list[str] = []
    for sel in [*ctx.selectors, *(COMMON_SELECTORS if ctx.common_selectors else ())]:
        sel = sel.strip().lower()
        if sel and sel not in seen:
            seen.append(sel)
    return seen


def check_dkim(ctx: CheckContext) -> CheckResult:
    res = CheckResult("dkim", "DKIM")
    res.max_score = MAX_SCORE
    selectors = selectors_to_try(ctx)
    keys: list[DkimKey] = []
    failures: list[str] = []
    for sel in selectors:
        name = f"{sel}._domainkey.{ctx.domain}"
        ans = ctx.resolver.resolve(name, "TXT")
        if ans.failed:
            failures.append(sel)
            continue
        if ans.status != "ok":
            continue
        candidates = [t for t in ans.records if looks_like_dkim(t)]
        if not candidates:
            continue
        if len(candidates) > 1:
            res.warn(
                "dkim.multiple",
                f"{name} has {len(candidates)} DKIM records; verifiers may pick either.",
                "Publish exactly one key record per selector.",
            )
        keys.append(parse_dkim_record(sel, name, candidates[0]))
    ctx.shared["dkim_keys"] = keys
    res.data = {"selectorsTried": len(selectors), "keys": [k.to_dict() for k in keys]}

    probe = ctx.resolver.resolve(f"{WILDCARD_PROBE}._domainkey.{ctx.domain}", "TXT")
    if probe.status == "ok" and any(looks_like_dkim(t) for t in probe.records):
        res.warn(
            "dkim.wildcard",
            "A random selector also returns a DKIM key, so the zone has a wildcard record.",
            "Discovery results are not meaningful; check the selector from a real DKIM-Signature header.",
        )

    if failures:
        res.dns_failure = True
        res.warn("dkim.dns", f"DNS errors for {len(failures)} selector(s): {', '.join(failures[:5])}.")

    if not keys:
        if ctx.selectors:
            res.error(
                "dkim.not_found",
                f"No DKIM key found for the given selector(s): {', '.join(ctx.selectors)}.",
                f"Publish the TXT record your mail provider gives you at <selector>._domainkey.{ctx.domain}.",
                RFC["dkim"] + "#section-3.6.2.1",
            )
        else:
            res.warn(
                "dkim.not_found",
                f"No DKIM key found among {len(selectors)} common selectors.",
                "DKIM keys can only be found by selector. Pass --selector with the s= value of a DKIM-Signature "
                "header from a real message.",
                RFC["dkim"],
            )
        res.score = MAX_SCORE * 0.3 if not ctx.selectors else 0.0
        return res

    usable = 0
    for key in keys:
        label = f"selector '{key.selector}'"
        for err in key.errors:
            res.error("dkim.syntax", f"{label}: {err}", reference=RFC["dkim"] + "#section-3.6.1")
        for w in key.warnings:
            res.warn(
                "dkim.weak_hash", f"{label}: {w}", "Remove sha1 from h= (or drop h= to allow sha256).", RFC["dkim-rsa"]
            )
        if key.revoked:
            res.info("dkim.revoked", f"{label}: the key is revoked (empty p=).")
            continue
        if key.errors:
            continue
        if key.testing:
            res.warn(
                "dkim.testing",
                f"{label}: t=y marks the key as testing; verifiers may ignore failures.",
                "Remove t=y once signing works.",
                RFC["dkim"] + "#section-3.6.1",
            )
        if key.key_type == "ed25519":
            usable += 1
            res.ok("dkim.ed25519", f"{label}: Ed25519 key.")
            res.info(
                "dkim.ed25519_support",
                f"{label}: many receivers do not verify Ed25519 yet; also sign with RSA.",
                reference=RFC["dkim-ed25519"],
            )
            continue
        bits = key.bits or 0
        if bits < 1024:
            res.error(
                "dkim.short_key",
                f"{label}: {bits}-bit RSA key.",
                "RSA keys must be at least 1024 bits (RFC 8301) and Gmail requires 1024+; use 2048.",
                RFC["dkim-rsa"],
            )
        elif bits < 2048:
            usable += 1
            res.warn(
                "dkim.1024",
                f"{label}: {bits}-bit RSA key.",
                "Rotate to a 2048-bit key; Gmail recommends 2048 bits where the DNS host supports it.",
                RFC["gmail"],
            )
        else:
            usable += 1
            res.ok("dkim.key", f"{label}: {bits}-bit RSA key.")

    ctx.shared["dkim_usable"] = usable
    if usable == 0:
        res.error("dkim.no_usable_key", "None of the DKIM keys found can verify signatures.")
        res.score = 0.0
        return res
    errors = sum(1 for f in res.findings if f.severity == "error")
    warnings = sum(1 for f in res.findings if f.severity == "warning")
    res.score = MAX_SCORE * (1.0 if not errors and not warnings else (0.5 if errors else 0.8))
    return res
