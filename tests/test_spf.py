from __future__ import annotations

import pytest

from mail_auth_check.resolver import StaticResolver
from mail_auth_check.spf import (
    MacroContext,
    MacroError,
    analyze,
    check_host,
    expand,
    is_spf_record,
    parse_record,
    select_records,
    validate_macro_string,
)

# -- selection and parsing -------------------------------------------------------------------------------------------


def test_select_records():
    txt = ["v=spf1 -all", "v=spf10 x", "V=SPF1 a -all", "google-site-verification=x", "v=spf1"]
    assert select_records(txt) == ["v=spf1 -all", "V=SPF1 a -all", "v=spf1"]
    assert is_spf_record("v=spf1 ") and not is_spf_record("spf1 -all")


def test_parse_all_mechanisms():
    rec = parse_record(
        "v=spf1 +a -mx:mail.example.com/24 ~a:example.org//64 ?ptr:example.net ip4:192.0.2.1 "
        "ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.example.com exists:%{i}.bl.example.org "
        "redirect=_spf.example.net exp=explain.example.com"
    )
    assert rec.valid, rec.errors
    names = [(t.qualifier, t.name) for t in rec.mechanisms]
    assert names == [
        ("+", "a"),
        ("-", "mx"),
        ("~", "a"),
        ("?", "ptr"),
        ("+", "ip4"),
        ("+", "ip4"),
        ("+", "ip6"),
        ("+", "include"),
        ("+", "exists"),
    ]
    mx = rec.mechanisms[1]
    assert (mx.value, mx.cidr4, mx.cidr6, mx.result) == ("mail.example.com", 24, None, "fail")
    assert rec.mechanisms[2].cidr6 == 64
    assert rec.mechanisms[5].cidr4 == 24
    assert rec.redirect.value == "_spf.example.net"
    assert rec.modifier("exp").value == "explain.example.com"
    # include, a, mx, a, ptr, exists, redirect (no "all", so redirect counts)
    assert len(rec.lookup_terms) == 7


@pytest.mark.parametrize(
    ("record", "fragment"),
    [
        ("v=spf1 foo -all", "unknown mechanism"),
        ("v=spf1 ip4:999.1.1.1 -all", "invalid IPv4"),
        ("v=spf1 ip4:192.0.2.0/33 -all", "prefix length"),
        ("v=spf1 ip6:zz::1 -all", "invalid IPv6"),
        ("v=spf1 include -all", "needs ':domain'"),
        ("v=spf1 include:localhost-only -all", "fully qualified"),
        ("v=spf1 a:example.com/40 -all", "IPv4 prefix length"),
        ("v=spf1 all:x", "takes no argument"),
        ("v=spf1 redirect=a.example redirect=b.example", "more than once"),
        ("v=spf1 exists:%{z}.example.com -all", "invalid macro"),
        ("v=spf1 exists:%{c}.example.com -all", "only allowed in 'exp'"),
        ("v=spf1 ip4 -all", "needs ':address'"),
        ("spf1 -all", "does not start"),
    ],
)
def test_syntax_errors(record, fragment):
    rec = parse_record(record)
    assert not rec.valid
    assert any(fragment in e for e in rec.errors), rec.errors


def test_style_warnings():
    rec = parse_record("v=spf1  a -all mx foo=bar redirect=x.example.com")
    w = " | ".join(rec.warnings)
    assert "single spaces" in w
    assert "'mx' comes after 'all'" in w
    assert "redirect' modifier is ignored" in w
    assert "unknown modifier 'foo'" in w
    assert rec.lookup_terms[-1].name == "mx"  # redirect ignored next to all


# -- macros ------------------------------------------------------------------------------------------------------------

CTX = MacroContext(
    ip="192.0.2.3", domain="email.example.com", sender="strong-bad@email.example.com", helo="mx.example.org"
)


@pytest.mark.parametrize(
    ("macro", "expected"),
    [
        # Examples from RFC 7208 section 7.4
        ("%{s}", "strong-bad@email.example.com"),
        ("%{o}", "email.example.com"),
        ("%{d}", "email.example.com"),
        ("%{d4}", "email.example.com"),
        ("%{d3}", "email.example.com"),
        ("%{d2}", "example.com"),
        ("%{d1}", "com"),
        ("%{dr}", "com.example.email"),
        ("%{d2r}", "example.email"),
        ("%{l}", "strong-bad"),
        ("%{l-}", "strong.bad"),
        ("%{lr}", "strong-bad"),
        ("%{lr-}", "bad.strong"),
        ("%{l1r-}", "strong"),
        ("%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"),
        ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
        ("%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"),
    ],
)
def test_macro_expansion_rfc_examples(macro, expected):
    assert expand(macro, CTX) == expected


def test_macro_ipv6_and_escapes():
    ctx6 = MacroContext(ip="2001:db8::cb01", domain="email.example.com", sender="x@email.example.com")
    assert expand("%{ir}.%{v}._spf.%{d2}", ctx6) == (
        "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
    )
    assert expand("%%-%_-%-", CTX, is_domain=False) == "%- -%20"
    assert (
        expand("%{S}", MacroContext("192.0.2.3", "d.example", "a b@d.example"), is_domain=False) == "a%20b%40d.example"
    )


def test_macro_validation():
    validate_macro_string("plain.example.com")
    validate_macro_string("%{ir}.%{l1r+-}.x")
    with pytest.raises(MacroError):
        validate_macro_string("%{d0}")
    with pytest.raises(MacroError):
        validate_macro_string("50%")


def test_long_expansion_is_truncated():
    ctx = MacroContext(ip="192.0.2.3", domain="example.com", sender=("a" * 60 + ".") * 5 + "x@example.com")
    out = expand("%{l}.example.com", ctx)
    assert len(out) <= 253 and out.endswith("example.com")


# -- analysis ----------------------------------------------------------------------------------------------------------


def chain_zone(n_includes: int) -> dict:
    zones = {
        "example.com": {
            "TXT": [" ".join(["v=spf1", *[f"include:i{i}.example.com" for i in range(n_includes)], "-all"])]
        }
    }
    for i in range(n_includes):
        zones[f"i{i}.example.com"] = {"TXT": [f"v=spf1 ip4:192.0.2.{i} ~all"]}
    return zones


def test_lookup_count_includes_nested_terms():
    zones = {
        "example.com": {
            "TXT": ["v=spf1 a mx include:a.example.net redirect=ignored.example.net -all"],
            "A": ["192.0.2.1"],
            "MX": [[10, "mx.example.com"]],
        },
        "a.example.net": {"TXT": ["v=spf1 include:b.example.net exists:x.example.net ~all"]},
        "b.example.net": {"TXT": ["v=spf1 a:host.example.net ip4:198.51.100.0/24 ~all"]},
        "host.example.net": {"A": ["198.51.100.5"]},
        "x.example.net": {"A": ["127.0.0.2"]},
    }
    a = analyze(StaticResolver(zones), "example.com")
    assert a.status == "ok"
    assert a.total_lookups == 6  # a, mx, include, include, exists, a
    assert a.total_void == 0
    assert a.ip4 == ["198.51.100.0/24"]
    assert a.effective_all() == "-"
    assert [c.domain for c in a.root.children] == ["a.example.net"]


def test_lookup_limit_exceeded():
    a = analyze(StaticResolver(chain_zone(11)), "example.com")
    assert a.total_lookups == 11 and a.over_lookup_limit


def test_void_lookups_counted():
    zones = {"example.com": {"TXT": ["v=spf1 a:gone1.example.com mx:gone2.example.com exists:gone3.example.com -all"]}}
    a = analyze(StaticResolver(zones), "example.com")
    assert a.total_void == 3 and a.over_void_limit


def test_include_without_spf_and_loops_and_duplicates():
    zones = {
        "example.com": {"TXT": ["v=spf1 include:nospf.example.com include:loop.example.com -all"]},
        "nospf.example.com": {"TXT": ["hello"]},
        "loop.example.com": {"TXT": ["v=spf1 include:example.com -all"]},
        "dup.example.com": {"TXT": ["v=spf1 -all", "v=spf1 ~all"]},
    }
    a = analyze(StaticResolver(zones), "example.com")
    assert a.status == "permerror"
    assert any("has no SPF record" in e for e in a.errors)
    assert any("loop" in e for e in a.errors)
    d = analyze(StaticResolver(zones), "dup.example.com")
    assert d.status == "permerror" and len(d.root.duplicates) == 2
    n = analyze(StaticResolver(zones), "nospf.example.com")
    assert n.status == "none"


def test_redirect_followed_for_effective_all():
    zones = {
        "example.com": {"TXT": ["v=spf1 redirect=_spf.example.net"]},
        "_spf.example.net": {"TXT": ["v=spf1 ip4:192.0.2.0/24 ?all"]},
    }
    a = analyze(StaticResolver(zones), "example.com")
    assert a.total_lookups == 1
    assert a.effective_all() == "?"


def test_too_many_mx_names_and_dns_error():
    zones = {
        "example.com": {
            "TXT": ["v=spf1 mx include:broken.example.com -all"],
            "MX": [[i, f"mx{i}.example.com"] for i in range(11)],
        },
        "broken.example.com": {"error": "SERVFAIL"},
    }
    a = analyze(StaticResolver(zones), "example.com")
    assert any("11 MX hosts" in e for e in a.errors)
    assert any("failed" in e for e in a.errors)


def test_macro_terms_are_not_resolved():
    zones = {"example.com": {"TXT": ["v=spf1 exists:%{i}._spf.example.com -all"]}}
    a = analyze(StaticResolver(zones), "example.com")
    assert a.total_lookups == 1
    assert any("macros" in n for n in a.root.notes)


# -- check_host --------------------------------------------------------------------------------------------------------

EVAL_ZONE = {
    "example.com": {
        "TXT": ["v=spf1 ip4:192.0.2.0/25 a:web.example.com/30 mx include:_spf.example.net ptr -all"],
        "MX": [[10, "mx.example.com"]],
    },
    "web.example.com": {"A": ["198.51.100.8"]},
    "mx.example.com": {"A": ["203.0.113.10"], "AAAA": ["2001:db8::10"]},
    "_spf.example.net": {"TXT": ["v=spf1 ip6:2001:db8:aa::/48 ~all"]},
    "5.113.0.203.in-addr.arpa": {"PTR": ["out.example.com"]},
    "out.example.com": {"A": ["203.0.113.5"]},
    "soft.example.com": {"TXT": ["v=spf1 redirect=_spf.example.net"]},
    "norecord.example.com": {"TXT": ["nothing here"]},
    "redir-none.example.com": {"TXT": ["v=spf1 redirect=norecord.example.com"]},
    "neutral.example.com": {"TXT": ["v=spf1 ip4:192.0.2.1"]},
    "macro.example.com": {"TXT": ["v=spf1 exists:%{ir}.list.example.com -all"]},
    "4.3.2.1.list.example.com": {"A": ["127.0.0.2"]},
    "temp.example.com": {"TXT": ["v=spf1 include:down.example.com -all"]},
    "down.example.com": {"error": "timeout"},
}


@pytest.mark.parametrize(
    ("ip", "domain", "result", "mechanism"),
    [
        ("192.0.2.77", "example.com", "pass", "ip4:192.0.2.0/25"),
        ("192.0.2.200", "example.com", "fail", "-all"),
        ("198.51.100.9", "example.com", "pass", "a:web.example.com/30"),
        ("203.0.113.10", "example.com", "pass", "mx"),
        ("2001:db8::10", "example.com", "pass", "mx"),
        ("2001:db8:aa::1", "example.com", "pass", "include:_spf.example.net"),
        ("203.0.113.5", "example.com", "pass", "ptr"),
        ("::ffff:192.0.2.5", "example.com", "pass", "ip4:192.0.2.0/25"),
        ("2001:db8:ff::1", "soft.example.com", "softfail", "~all"),
        ("192.0.2.9", "neutral.example.com", "neutral", None),
        ("192.0.2.1", "norecord.example.com", "none", None),
        ("1.2.3.4", "macro.example.com", "pass", "exists:%{ir}.list.example.com"),
        ("1.2.3.5", "macro.example.com", "fail", "-all"),
    ],
)
def test_check_host(ip, domain, result, mechanism):
    ev = check_host(StaticResolver(EVAL_ZONE), ip, domain)
    assert ev.result == result, ev.reason
    assert ev.mechanism == mechanism


def test_check_host_errors():
    r = StaticResolver(EVAL_ZONE)
    assert check_host(r, "192.0.2.1", "redir-none.example.com").result == "permerror"
    assert check_host(r, "192.0.2.1", "temp.example.com").result == "temperror"
    assert check_host(r, "not-an-ip", "example.com").result == "permerror"
    over = check_host(StaticResolver(chain_zone(12)), "203.0.113.1", "example.com")
    assert over.result == "permerror" and "more than 10" in over.reason
    voids = {"example.com": {"TXT": ["v=spf1 a:v1.example.com a:v2.example.com a:v3.example.com -all"]}}
    assert "void" in check_host(StaticResolver(voids), "192.0.2.1", "example.com").reason


def test_check_host_stops_at_first_match():
    ev = check_host(StaticResolver(chain_zone(12)), "192.0.2.0", "example.com")
    assert ev.lookups == 1  # the first include matched (ip4:192.0.2.0) before the limit
    assert ev.result == "pass"
