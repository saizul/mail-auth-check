"""Gmail and Yahoo sender requirements, forward-confirmed reverse DNS and message header checks.

Sources: Gmail "Email sender guidelines" (support.google.com/a/answer/81126) and Yahoo "Sender Best Practices"
(senders.yahooinc.com/best-practices). Both apply to all senders, with extra rules for bulk senders (Gmail: more than
5,000 messages a day to personal accounts). DNS shows only part of the picture: spam rate, TLS for outgoing mail and
message formatting cannot be checked from records, so they are listed as manual items.
"""

from __future__ import annotations

import email
import email.policy
import ipaddress
import re
from dataclasses import dataclass
from email.utils import getaddresses

from ..model import CheckResult
from ..util import organizational_domain
from .base import RFC, CheckContext

__all__ = ["Requirement", "check_headers", "check_reverse_dns", "check_senders", "parse_message_headers"]


@dataclass
class Requirement:
    key: str
    text: str
    scope: str  # "all" or "bulk"
    status: str  # pass, fail, warn, unknown, manual
    detail: str = ""


def check_reverse_dns(ctx: CheckContext) -> CheckResult:
    """Forward-confirmed reverse DNS for the sending IPs given with --ip (Gmail and Yahoo: all senders)."""
    res = CheckResult("rdns", "Sending IP reverse DNS")
    rows = []
    for ip in ctx.sending_ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            res.error("rdns.bad_ip", f"'{ip}' is not an IP address.")
            continue
        ptr = ctx.resolver.resolve(addr.reverse_pointer, "PTR")
        if ptr.failed:
            res.dns_failure = True
            res.warn("rdns.dns", f"{ip}: PTR lookup failed ({ptr.error}).")
            rows.append({"ip": ip, "ptr": None, "confirmed": False})
            continue
        if not ptr.ok:
            res.error(
                "rdns.no_ptr",
                f"{ip} has no PTR (reverse DNS) record.",
                "Ask the owner of the IP range (your hosting provider) to set a PTR record that points to a "
                "host name which resolves back to this IP.",
                RFC["gmail"],
            )
            rows.append({"ip": ip, "ptr": None, "confirmed": False})
            continue
        confirmed_name = None
        for name in ptr.records:
            fwd = ctx.resolver.resolve(name, "A" if addr.version == 4 else "AAAA")
            if fwd.ok and any(ipaddress.ip_address(a) == addr for a in fwd.records):
                confirmed_name = name
                break
        rows.append({"ip": ip, "ptr": list(ptr.records), "confirmed": bool(confirmed_name)})
        if confirmed_name:
            res.ok("rdns.fcrdns", f"{ip} -> {confirmed_name} -> {ip} (forward-confirmed).")
            if re.search(r"(\d{1,3}[.-]){3}\d{1,3}|dynamic|dhcp|pool|dsl|cable", confirmed_name, re.IGNORECASE):
                res.warn(
                    "rdns.generic",
                    f"{confirmed_name} looks like a generic or dynamic host name.",
                    "Use a host name under your own domain, such as mail.example.com.",
                )
        else:
            res.error(
                "rdns.not_confirmed",
                f"{ip} -> {', '.join(ptr.records)}, but that name does not resolve back to {ip}.",
                "Add an A/AAAA record for the PTR name that points to the sending IP.",
                RFC["gmail"],
            )
    res.data = {"ips": rows}
    return res


def parse_message_headers(text: str) -> email.message.Message:
    head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0] + "\n\n"
    return email.message_from_string(head, policy=email.policy.compat32)


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().strip(">").lower().rstrip(".") if "@" in address else ""


def _aligned(a: str, b: str) -> bool:
    return bool(a and b) and organizational_domain(a) == organizational_domain(b)


def check_headers(ctx: CheckContext) -> CheckResult:
    """Inspect the headers of a real message (``--headers``): alignment, one-click unsubscribe, results."""
    res = CheckResult("headers", "Message headers")
    msg = parse_message_headers(ctx.headers_text or "")
    from_addrs = [a for _, a in getaddresses(msg.get_all("From", []))]
    from_domain = _domain_of(from_addrs[0]) if from_addrs else ""
    data: dict[str, object] = {"fromDomain": from_domain}
    if not from_domain:
        res.error("headers.no_from", "The message has no parsable From: address.", reference="RFC 5322")
        res.data = data
        return res
    if len(from_addrs) > 1:
        res.warn("headers.multiple_from", "The From: header has more than one address; DMARC receivers may reject it.")
    if from_domain != ctx.domain and organizational_domain(from_domain) != organizational_domain(ctx.domain):
        res.warn("headers.other_domain", f"The message is from {from_domain}, not {ctx.domain}.")

    # DKIM-Signature d= / s=
    sigs = []
    for raw in msg.get_all("DKIM-Signature", []):
        tags = {
            k.strip().lower(): re.sub(r"\s+", "", v)
            for k, _, v in (p.partition("=") for p in str(raw).split(";"))
            if k.strip()
        }
        sigs.append({"d": tags.get("d", "").lower(), "s": tags.get("s", ""), "a": tags.get("a", "")})
    data["dkimSignatures"] = sigs
    if not sigs:
        res.error(
            "headers.no_dkim",
            "The message has no DKIM-Signature header.",
            "Turn on DKIM signing at your mail provider.",
            RFC["gmail"],
        )
    else:
        aligned = [s for s in sigs if _aligned(s["d"], from_domain)]
        if aligned:
            res.ok("headers.dkim_aligned", f"DKIM d={aligned[0]['d']} aligns with From: {from_domain} (relaxed).")
        else:
            res.warn(
                "headers.dkim_unaligned",
                f"No DKIM signature aligns with {from_domain} (d={', '.join(s['d'] for s in sigs)}).",
                "Sign with your own domain so DKIM can satisfy DMARC.",
            )
        for s in sigs:
            if s["a"].lower() == "rsa-sha1":
                res.error("headers.dkim_sha1", f"The signature from {s['d']} uses rsa-sha1.", reference=RFC["dkim-rsa"])
        selectors = sorted({s["s"].lower() for s in sigs if s["s"] and _aligned(s["d"], ctx.domain)})
        data["selectors"] = selectors

    # Return-Path (SPF identity)
    rp = msg.get("Return-Path", "")
    rp_domain = _domain_of(str(rp))
    data["returnPathDomain"] = rp_domain
    if rp_domain:
        if _aligned(rp_domain, from_domain):
            res.ok("headers.spf_aligned", f"Return-Path {rp_domain} aligns with From: {from_domain} (relaxed).")
        else:
            res.info(
                "headers.spf_unaligned",
                f"Return-Path {rp_domain} does not align with {from_domain}; DMARC will rely on DKIM.",
            )

    # Authentication-Results from the receiving side
    results = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    if results:
        found = {m.group(1).lower(): m.group(2).lower() for m in re.finditer(r"\b(spf|dkim|dmarc)=(\w+)", results)}
        data["authenticationResults"] = found
        for method in ("spf", "dkim", "dmarc"):
            value = found.get(method)
            if value is None:
                continue
            if value == "pass":
                res.ok(f"headers.{method}_pass", f"The receiver reported {method}=pass.")
            else:
                res.error(f"headers.{method}_{value}", f"The receiver reported {method}={value}.")

    # One-click unsubscribe (RFC 8058)
    lu = str(msg.get("List-Unsubscribe", "") or "")
    lup = str(msg.get("List-Unsubscribe-Post", "") or "")
    data["listUnsubscribe"] = bool(lu)
    if not lu:
        res.warn(
            "headers.no_unsubscribe",
            "No List-Unsubscribe header.",
            "Gmail and Yahoo require one-click unsubscribe for marketing and subscribed mail from bulk senders: "
            "add List-Unsubscribe with an https URL and List-Unsubscribe-Post: List-Unsubscribe=One-Click.",
            RFC["one-click"],
        )
    else:
        has_https = bool(re.search(r"<https://[^>]+>", lu, re.IGNORECASE))
        if lup.strip().replace(" ", "") == "List-Unsubscribe=One-Click" and has_https:
            res.ok("headers.one_click", "One-click unsubscribe (RFC 8058) headers are present.")
        elif not has_https:
            res.warn(
                "headers.unsubscribe_mailto",
                "List-Unsubscribe has no https URL; one-click needs one.",
                reference=RFC["one-click"],
            )
        else:
            res.warn(
                "headers.no_one_click",
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click is missing.",
                reference=RFC["one-click"],
            )
    for name in ("Date", "Message-ID"):
        if not msg.get(name):
            res.warn(f"headers.no_{name.lower().replace('-', '_')}", f"The message has no {name}: header (RFC 5322).")
    res.data = data
    return res


def check_senders(ctx: CheckContext) -> CheckResult:
    """Roll the other results up into the Gmail/Yahoo requirement list."""
    res = CheckResult("senders", "Gmail / Yahoo sender requirements")
    spf = ctx.results.get("spf")
    dkim_res = ctx.results.get("dkim")
    analysis = ctx.shared.get("spf")
    dmarc = ctx.shared.get("dmarc")
    keys = ctx.shared.get("dkim_keys") or []
    headers = ctx.results.get("headers")
    rdns = ctx.results.get("rdns")
    reqs: list[Requirement] = []

    spf_ok = bool(
        analysis
        and analysis.status == "ok"
        and spf
        and not spf.has("spf.too_many_lookups")
        and not spf.has("spf.plus_all")
        and not spf.has("spf.syntax")
    )
    usable_keys = [k for k in keys if not k.errors and not k.revoked and (k.bits or 0) >= 1024]
    dkim_ok = bool(usable_keys) or bool(headers and headers.has("headers.dkim_aligned"))
    dkim_status = (
        "pass"
        if dkim_ok
        else ("unknown" if dkim_res and dkim_res.has("dkim.not_found") and not ctx.selectors else "fail")
    )

    reqs.append(
        Requirement(
            "auth_any",
            "SPF or DKIM set up for the sending domain",
            "all",
            "pass" if spf_ok or dkim_ok else ("unknown" if dkim_status == "unknown" else "fail"),
        )
    )
    reqs.append(Requirement("spf", "Valid SPF record", "bulk", "pass" if spf_ok else "fail"))
    reqs.append(
        Requirement(
            "dkim",
            "DKIM key published (found by selector)",
            "bulk",
            dkim_status,
            "" if dkim_ok else "pass --selector to check your provider's key",
        )
    )
    weak = [k for k in usable_keys if k.key_type == "rsa" and (k.bits or 0) < 2048]
    if usable_keys:
        reqs.append(
            Requirement(
                "dkim_1024", "DKIM RSA keys of 1024 bits or more (2048 recommended)", "all", "warn" if weak else "pass"
            )
        )
    dmarc_valid = bool(dmarc and dmarc.policy and not dmarc.errors)
    reqs.append(
        Requirement(
            "dmarc", "DMARC record published (p=none is the minimum)", "bulk", "pass" if dmarc_valid else "fail"
        )
    )
    if dmarc_valid and not dmarc.rua:
        reqs.append(
            Requirement(
                "dmarc_rua", "DMARC aggregate reports (rua) configured (Yahoo: strongly recommended)", "bulk", "warn"
            )
        )
    if headers is not None:
        aligned = headers.has("headers.dkim_aligned") or headers.has("headers.spf_aligned")
        reqs.append(
            Requirement(
                "alignment", "From: domain aligned with SPF or DKIM domain", "bulk", "pass" if aligned else "fail"
            )
        )
        reqs.append(
            Requirement(
                "one_click",
                "One-click unsubscribe (RFC 8058) for marketing mail",
                "bulk",
                "pass" if headers.has("headers.one_click") else "warn",
            )
        )
    else:
        reqs.append(
            Requirement(
                "alignment",
                "From: domain aligned with SPF or DKIM domain",
                "bulk",
                "manual",
                "check a real message with --headers",
            )
        )
        reqs.append(
            Requirement(
                "one_click",
                "One-click unsubscribe (RFC 8058) for marketing mail",
                "bulk",
                "manual",
                "check a real message with --headers",
            )
        )
    if rdns is not None and ctx.sending_ips:
        reqs.append(
            Requirement(
                "rdns",
                "Sending IPs have forward-confirmed reverse DNS",
                "all",
                "pass" if rdns.status in ("ok", "info") else "fail",
            )
        )
    else:
        reqs.append(
            Requirement(
                "rdns",
                "Sending IPs have valid forward and reverse DNS",
                "all",
                "manual",
                "pass --ip with your sending IPs",
            )
        )
    reqs.append(Requirement("tls", "Mail is sent over TLS", "all", "manual", "check your provider or MTA config"))
    reqs.append(
        Requirement(
            "spam_rate",
            "Spam rate below 0.3% (Gmail recommends staying under 0.1%)",
            "all",
            "manual",
            "Google Postmaster Tools / Yahoo Sender Hub",
        )
    )
    reqs.append(Requirement("rfc5322", "Messages formatted per RFC 5322", "all", "manual"))

    for r in reqs:
        label = f"[{'bulk' if r.scope == 'bulk' else 'all senders'}] {r.text}"
        extra = f" ({r.detail})" if r.detail else ""
        if r.status == "pass":
            res.ok(f"senders.{r.key}", label)
        elif r.status == "fail":
            sev = "error" if r.scope == "all" or ctx.shared.get("bulk_sender", True) else "warning"
            res.add(sev, f"senders.{r.key}", label + extra, reference=RFC["gmail"])
        elif r.status == "warn":
            res.warn(f"senders.{r.key}", label + extra, reference=RFC["gmail"])
        elif r.status == "unknown":
            res.warn(f"senders.{r.key}", label + " - not verified" + extra)
        else:
            res.info(f"senders.{r.key}", label + " - manual check" + extra)
    res.data = {"requirements": [r.__dict__ for r in reqs]}
    return res
