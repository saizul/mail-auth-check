from __future__ import annotations

import copy

from conftest import GOOD_POLICY, dkim_txt, good_fetcher, make_ctx
from mail_auth_check.checks import (
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
from mail_auth_check.util import StaticFetcher

POLICY_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"


def codes(result):
    return {f.code for f in result.findings}


# -- SPF -------------------------------------------------------------------------------------------------------------


def test_spf_good(zone):
    res = check_spf(make_ctx(zone))
    assert res.status == "ok" and res.score == res.max_score == 25
    assert {"spf.present", "spf.lookups", "spf.fail_all"} <= codes(res)
    assert res.data["lookups"] == 1


def test_spf_missing_multiple_dns():
    assert "spf.missing" in codes(check_spf(make_ctx({"example.com": {"TXT": ["x"]}})))
    dup = check_spf(make_ctx({"example.com": {"TXT": ["v=spf1 -all", "v=spf1 a -all"]}}))
    assert "spf.multiple" in codes(dup) and dup.score == 0
    down = check_spf(make_ctx({"example.com": {"error": "SERVFAIL"}}))
    assert down.dns_failure and "spf.dns" in codes(down)


def test_spf_all_qualifiers():
    def spf(record):
        return codes(check_spf(make_ctx({"example.com": {"TXT": [record]}})))

    assert "spf.plus_all" in spf("v=spf1 +all")
    assert "spf.plus_all" in spf("v=spf1 all")
    assert "spf.neutral_all" in spf("v=spf1 ip4:192.0.2.1 ?all")
    assert "spf.softfail_all" in spf("v=spf1 ip4:192.0.2.1 ~all")
    assert "spf.no_all" in spf("v=spf1 ip4:192.0.2.1")
    assert "spf.broad_ip4" in spf("v=spf1 ip4:10.0.0.0/8 -all")
    assert "spf.broad_ip6" in spf("v=spf1 ip6:2001::/16 -all")
    assert "spf.ptr" in spf("v=spf1 ptr -all")
    assert "spf.syntax" in spf("v=spf1 ip4:300.1.1.1 -all")


def test_spf_lookup_and_void_limits():
    many = " ".join(f"include:i{i}.example.com" for i in range(11))
    zones = {"example.com": {"TXT": [f"v=spf1 {many} -all"]}}
    for i in range(11):
        zones[f"i{i}.example.com"] = {"TXT": ["v=spf1 -all"]}
    assert "spf.too_many_lookups" in codes(check_spf(make_ctx(zones)))
    nine = {"example.com": {"TXT": ["v=spf1 " + " ".join(f"a:h{i}.example.com" for i in range(9)) + " -all"]}}
    for i in range(9):
        nine[f"h{i}.example.com"] = {"A": ["192.0.2.1"]}
    assert "spf.near_lookup_limit" in codes(check_spf(make_ctx(nine)))
    voids = {"example.com": {"TXT": ["v=spf1 a:x1.example.com -all"]}}
    assert "spf.void_lookup" in codes(check_spf(make_ctx(voids)))
    voids3 = {"example.com": {"TXT": ["v=spf1 a:x1.example.com a:x2.example.com a:x3.example.com -all"]}}
    assert "spf.too_many_void" in codes(check_spf(make_ctx(voids3)))


def test_spf_include_problems():
    zones = {
        "example.com": {"TXT": ["v=spf1 include:gone.example.com include:loop.example.com -all"]},
        "loop.example.com": {"TXT": ["v=spf1 include:example.com -all"]},
    }
    res = check_spf(make_ctx(zones))
    assert "spf.include_error" in codes(res) and res.score == 0


def test_spf_sending_ip_evaluation(zone):
    res = check_spf(make_ctx(zone, sending_ips=["192.0.2.10", "203.0.113.1", "nope"]))
    assert {"spf.ip_pass", "spf.ip_not_authorized", "spf.bad_ip"} <= codes(res)
    assert [e["result"] for e in res.data["evaluations"]] == ["pass", "fail"]


# -- DKIM ------------------------------------------------------------------------------------------------------------


def test_dkim_found_by_common_selector(zone):
    ctx = make_ctx(zone)
    res = check_dkim(ctx)
    assert res.status == "ok" and res.score == 25
    assert res.data["keys"][0]["selector"] == "selector1"


def test_dkim_given_selector_only_and_missing():
    zones = {"s9._domainkey.example.com": {"TXT": [dkim_txt(2048)]}}
    res = check_dkim(make_ctx(zones, selectors=["S9"], common_selectors=False))
    assert res.data["selectorsTried"] == 1 and res.status == "ok"
    miss = check_dkim(make_ctx({}, selectors=["nope"], common_selectors=False))
    assert miss.status == "error" and miss.score == 0
    guess = check_dkim(make_ctx({}))
    assert guess.status == "warning" and 0 < guess.score < 25


def test_dkim_key_sizes_and_flags():
    zones = {
        "a._domainkey.example.com": {"TXT": [dkim_txt(512)]},
        "b._domainkey.example.com": {"TXT": [dkim_txt(1024, "t=y; ")]},
        "c._domainkey.example.com": {"TXT": [dkim_txt(key_type="ed25519")]},
        "d._domainkey.example.com": {"TXT": ["v=DKIM1; p="]},
        "e._domainkey.example.com": {"TXT": [dkim_txt(2048), dkim_txt(2048)]},
    }
    res = check_dkim(make_ctx(zones, selectors=list("abcde"), common_selectors=False))
    c = codes(res)
    assert {"dkim.short_key", "dkim.1024", "dkim.testing", "dkim.ed25519", "dkim.revoked", "dkim.multiple"} <= c
    assert 0 < res.score < 25


def test_dkim_wildcard_and_dns_error():
    zones = {"*._domainkey.example.com": {"TXT": [dkim_txt(2048)]}, "x._domainkey.example.com": {"error": "SERVFAIL"}}
    res = check_dkim(make_ctx(zones, selectors=["x"]))
    assert {"dkim.wildcard", "dkim.dns"} <= codes(res) and res.dns_failure


def test_dkim_only_unusable_keys():
    zones = {"a._domainkey.example.com": {"TXT": ["v=DKIM1; p=***"]}}
    res = check_dkim(make_ctx(zones, selectors=["a"], common_selectors=False))
    assert "dkim.no_usable_key" in codes(res) and res.score == 0


# -- DMARC -----------------------------------------------------------------------------------------------------------


def dmarc(record, extra=None, domain="example.com"):
    zones = {f"_dmarc.{domain}": {"TXT": [record]}} if record else {}
    zones.update(extra or {})
    return check_dmarc(make_ctx(zones, domain=domain))


def test_dmarc_policies_and_scores():
    rej = dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com")
    assert rej.status == "ok" and rej.score == 30
    q = dmarc("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com")
    assert "dmarc.pct" in codes(q) and q.score < 30
    n = dmarc("v=DMARC1; p=none")
    assert {"dmarc.none", "dmarc.no_rua"} <= codes(n) and n.score < 20
    sp = dmarc("v=DMARC1; p=reject; sp=none; adkim=s; ruf=mailto:f@example.com; rua=mailto:d@example.com")
    assert {"dmarc.sp_none", "dmarc.strict", "dmarc.ruf"} <= codes(sp)
    assert "dmarc.missing" in codes(dmarc(None))
    bad = dmarc("v=DMARC1; p=whatever")
    assert "dmarc.syntax" in codes(bad) and bad.score <= 6


def test_dmarcbis_np_testing_and_psd():
    good = dmarc("v=DMARC1; p=reject; np=reject; t=n; psd=n; rua=mailto:d@example.com")
    assert not {"dmarc.np_none", "dmarc.testing", "dmarc.psd"} & codes(good)
    assert good.score == 30
    assert good.data["nonexistentPolicy"] == "reject" and good.data["testing"] is False
    np_none = dmarc("v=DMARC1; p=reject; np=none; rua=mailto:d@example.com")
    assert "dmarc.np_none" in codes(np_none) and np_none.score < 30
    assert "dmarc.np_none" not in codes(dmarc("v=DMARC1; p=none; np=none; rua=mailto:d@example.com"))
    testing = dmarc("v=DMARC1; p=reject; t=y; rua=mailto:d@example.com")
    finding = next(f for f in testing.findings if f.code == "dmarc.testing")
    assert "apply quarantine" in finding.message and testing.score < 30
    quarantine_testing = dmarc("v=DMARC1; p=quarantine; t=y; rua=mailto:d@example.com")
    assert "apply none" in next(f for f in quarantine_testing.findings if f.code == "dmarc.testing").message
    psd = dmarc("v=DMARC1; p=reject; psd=y; rua=mailto:d@example.com")
    assert "dmarc.psd" in codes(psd) and psd.data["psd"] == "y"
    bad = dmarc("v=DMARC1; p=reject; np=maybe; rua=mailto:d@example.com")
    assert "dmarc.syntax" in codes(bad) and bad.score <= 6


def test_dmarc_inherited_from_org_domain():
    res = check_dmarc(
        make_ctx(
            {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"]}},
            domain="news.example.com",
        )
    )
    assert "dmarc.inherited" in codes(res)
    assert "dmarc.quarantine" in codes(res)  # sp applies to the subdomain


def test_dmarc_multiple_and_dns_and_bad_version():
    assert "dmarc.multiple" in codes(
        dmarc(None, {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}})
    )
    down = dmarc(None, {"_dmarc.example.com": {"error": "timeout"}})
    assert down.dns_failure
    assert "dmarc.bad_version" in codes(dmarc("v=DMARC2; p=none"))


def test_dmarc_external_destination_verification():
    record = "v=DMARC1; p=reject; rua=mailto:a@reports.example.net,mailto:b@other.example.org,mailto:c@mail.example.com"
    res = dmarc(
        record,
        {
            "example.com._report._dmarc.reports.example.net": {"TXT": ["v=DMARC1"]},
        },
    )
    c = codes(res)
    assert "dmarc.external_ok" in c and "dmarc.external_unverified" in c
    unverified = [f for f in res.findings if f.code == "dmarc.external_unverified"]
    assert len(unverified) == 1 and "other.example.org" in unverified[0].message  # same org domain not checked
    wild = dmarc(
        "v=DMARC1; p=reject; rua=mailto:a@agg.example.net", {"*._report._dmarc.agg.example.net": {"TXT": ["v=DMARC1;"]}}
    )
    assert "dmarc.external_ok" in codes(wild)
    http = dmarc("v=DMARC1; p=reject; rua=https://agg.example.com/r")
    assert "dmarc.uri_scheme" in codes(http)


# -- MX --------------------------------------------------------------------------------------------------------------


def test_mx_good_and_problems(zone):
    ctx = make_ctx(zone)
    res = check_mx(ctx)
    assert res.status == "ok" and ctx.shared["mx_hosts"] == ["mx1.example.com", "b.mail.example.com"]
    bad = check_mx(
        make_ctx(
            {
                "example.com": {
                    "MX": [
                        [10, "192.0.2.1"],
                        [10, "alias.example.com"],
                        [10, "nohost.example.com"],
                        [10, "lan.example.com"],
                    ]
                },
                "alias.example.com": {"CNAME": ["real.example.com"]},
                "real.example.com": {"A": ["192.0.2.30"]},
                "lan.example.com": {"A": ["192.168.1.10"]},
            }
        )
    )
    assert {"mx.ip_literal", "mx.cname", "mx.unresolvable", "mx.private_ip", "mx.equal_pref"} <= codes(bad)


def test_mx_null_implicit_none_dns():
    ctx = make_ctx({"example.com": {"MX": [[0, "."]]}})
    assert "mx.null" in codes(check_mx(ctx)) and ctx.shared["null_mx"]
    assert "mx.null_mixed" in codes(check_mx(make_ctx({"example.com": {"MX": [[0, "."], [10, "mx.example.com"]]}})))
    assert "mx.implicit" in codes(check_mx(make_ctx({"example.com": {"A": ["192.0.2.1"]}})))
    assert "mx.none" in codes(check_mx(make_ctx({})))
    assert check_mx(make_ctx({"example.com": {"MX": {"error": "SERVFAIL"}}})).dns_failure
    single = check_mx(
        make_ctx({"example.com": {"MX": [[5, "mx.example.com"]]}, "mx.example.com": {"A": ["192.0.2.2"]}})
    )
    assert "mx.single" in codes(single)


# -- MTA-STS / TLS-RPT ----------------------------------------------------------------------------------------------


def sts_ctx(zone, fetcher):
    ctx = make_ctx(zone, fetcher=fetcher)
    check_mx(ctx)
    return ctx


def test_mta_sts_good(zone):
    res = check_mta_sts(sts_ctx(zone, good_fetcher()))
    assert res.status == "ok", res.findings
    assert res.data["policy"]["mode"] == "enforce"


def test_mta_sts_policy_problems(zone):
    def run(spec, z=None):
        return codes(check_mta_sts(sts_ctx(z or zone, StaticFetcher({POLICY_URL: spec}))))

    assert "mta_sts.redirect" in run({"status": 301, "location": "https://elsewhere.example/"})
    assert "mta_sts.status" in run({"status": 404})
    assert "mta_sts.fetch" in run({"error": "TLS certificate verification failed: hostname mismatch"})
    assert "mta_sts.content_type" in run({"body": GOOD_POLICY, "content_type": "text/html"})
    testing = GOOD_POLICY.replace("enforce", "testing")
    assert "mta_sts.testing" in run({"body": testing})
    assert "mta_sts.mode_none" in run({"body": "version: STSv1\nmode: none\nmax_age: 86400\n"})
    short = GOOD_POLICY.replace("604800", "300")
    assert "mta_sts.short_max_age" in run({"body": short})
    mismatch = GOOD_POLICY.replace("mx: *.mail.example.com\r\n", "")
    assert "mta_sts.mx_mismatch" in run({"body": mismatch})
    assert "mta_sts.policy_syntax" in run({"body": "version: STSv1\n"})
    assert "mta_sts.too_large" in run({"body": GOOD_POLICY + "#" * 70000})


def test_mta_sts_record_problems(zone):
    z = copy.deepcopy(zone)
    del z["_mta-sts.example.com"]
    res = check_mta_sts(sts_ctx(z, good_fetcher()))
    assert "mta_sts.missing" in codes(res) and 0 < res.score < res.max_score
    z["_mta-sts.example.com"] = {"TXT": ["v=STSv1; id=1", "v=STSv1; id=2"]}
    assert "mta_sts.multiple" in codes(check_mta_sts(sts_ctx(z, good_fetcher())))
    z["_mta-sts.example.com"] = {"TXT": ["v=STSv1; id=not valid!"]}
    assert "mta_sts.record_syntax" in codes(check_mta_sts(sts_ctx(z, good_fetcher())))
    z["_mta-sts.example.com"] = {"TXT": ["v=STSv1; id=1"]}
    assert "mta_sts.not_fetched" in codes(check_mta_sts(sts_ctx(z, None)))
    z["_mta-sts.example.com"] = {"error": "SERVFAIL"}
    assert check_mta_sts(sts_ctx(z, None)).dns_failure
    null = make_ctx({"example.com": {"MX": [[0, "."]]}})
    check_mx(null)
    assert "mta_sts.null_mx" in codes(check_mta_sts(null))
    assert "tlsrpt.null_mx" in codes(check_tlsrpt(null))


def test_tlsrpt(zone):
    assert check_tlsrpt(make_ctx(zone)).status == "ok"

    def run(records):
        z = {"_smtp._tls.example.com": {"TXT": records}} if records is not None else {}
        return codes(check_tlsrpt(make_ctx(z)))

    assert "tlsrpt.missing" in run(None)
    assert "tlsrpt.missing" in run(["v=TLSRPTv2; rua=mailto:a@example.com"])
    assert "tlsrpt.multiple" in run(["v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"])
    assert "tlsrpt.syntax" in run(["v=TLSRPTv1; rua=ftp://x.example.com"])
    assert "tlsrpt.syntax" in run(["v=TLSRPTv1;"])
    assert "tlsrpt.syntax" in run(["v=TLSRPTv1; rua=mailto:nobody"])
    assert "tlsrpt.present" in run(["v=TLSRPTv1; rua=mailto:a@example.com,https://r.example.com/tls"])


# -- BIMI ------------------------------------------------------------------------------------------------------------

LOGO = "https://www.example.com/logo.svg"
SVG = '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>x</title></svg>'


def bimi(record, dmarc_record="v=DMARC1; p=reject; rua=mailto:d@example.com", logo=None):
    zones = {"_dmarc.example.com": {"TXT": [dmarc_record]}}
    if record:
        zones["default._bimi.example.com"] = {"TXT": [record]}
    ctx = make_ctx(zones, fetcher=StaticFetcher({LOGO: logo}) if logo else None)
    check_dmarc(ctx)
    return check_bimi(ctx)


def test_bimi_cases():
    good = bimi(
        f"v=BIMI1; l={LOGO}; a=https://www.example.com/vmc.pem", logo={"body": SVG, "content_type": "image/svg+xml"}
    )
    assert good.status == "ok", good.findings
    assert "bimi.missing" in codes(bimi(None))
    assert "bimi.declined" in codes(bimi("v=BIMI1; l=; a=;"))
    assert "bimi.syntax" in codes(bimi("v=BIMI1; l=http://www.example.com/logo.svg"))
    assert "bimi.syntax" in codes(bimi("v=BIMI1; a=https://x.example.com/v.pem"))
    weak = codes(bimi(f"v=BIMI1; l={LOGO}", "v=DMARC1; p=quarantine; pct=50; sp=none"))
    assert {"bimi.weak_dmarc", "bimi.sp_none", "bimi.no_vmc"} <= weak
    assert "bimi.logo_profile" in codes(
        bimi(f"v=BIMI1; l={LOGO}", logo={"body": "<svg></svg>", "content_type": "image/svg+xml"})
    )
    assert "bimi.logo_not_svg" in codes(bimi(f"v=BIMI1; l={LOGO}", logo={"body": "<html/>"}))
    assert "bimi.logo_type" in codes(bimi(f"v=BIMI1; l={LOGO}", logo={"body": SVG, "content_type": "text/plain"}))
    assert "bimi.logo_fetch" in codes(bimi(f"v=BIMI1; l={LOGO}", logo={"status": 404}))
    nodmarc = make_ctx({"default._bimi.example.com": {"TXT": [f"v=BIMI1; l={LOGO}"]}})
    check_dmarc(nodmarc)
    assert "bimi.no_dmarc" in codes(check_bimi(nodmarc))


# -- reverse DNS, headers, sender requirements ----------------------------------------------------------------------


def test_reverse_dns():
    zones = {
        "10.2.0.192.in-addr.arpa": {"PTR": ["mail.example.com"]},
        "mail.example.com": {"A": ["192.0.2.10"]},
        "11.2.0.192.in-addr.arpa": {"PTR": ["other.example.com"]},
        "other.example.com": {"A": ["192.0.2.99"]},
        "12.2.0.192.in-addr.arpa": {"PTR": ["192-0-2-12.dynamic.example.net"]},
        "192-0-2-12.dynamic.example.net": {"A": ["192.0.2.12"]},
        "13.2.0.192.in-addr.arpa": {"error": "SERVFAIL"},
    }
    res = check_reverse_dns(
        make_ctx(zones, sending_ips=["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14", "bogus"])
    )
    assert {"rdns.fcrdns", "rdns.not_confirmed", "rdns.generic", "rdns.dns", "rdns.no_ptr", "rdns.bad_ip"} <= codes(res)
    assert res.data["ips"][0]["confirmed"] is True


HEADERS = """Return-Path: <bounce+abc@mail.example.com>
Authentication-Results: mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=mail.example.com;
 dmarc=pass (p=REJECT) header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to;
 bh=abc=; b=def=
DKIM-Signature: v=1; a=rsa-sha1; d=esp.example.net; s=k1; bh=x; b=y
From: News <news@example.com>
To: someone@example.org
Subject: Hello
Date: Fri, 13 Nov 2026 10:00:00 +0000
Message-ID: <1@example.com>
List-Unsubscribe: <https://example.com/u/1>, <mailto:u@example.com>
List-Unsubscribe-Post: List-Unsubscribe=One-Click

Body text.
"""


def test_headers_good():
    res = check_headers(make_ctx({}, headers_text=HEADERS))
    c = codes(res)
    assert {
        "headers.dkim_aligned",
        "headers.spf_aligned",
        "headers.one_click",
        "headers.dkim_pass",
        "headers.spf_pass",
        "headers.dmarc_pass",
        "headers.dkim_sha1",
    } <= c
    assert res.data["selectors"] == ["selector1"]


def test_headers_problems():
    text = (
        "From: a@other.example\nFrom2: x\nList-Unsubscribe: <mailto:u@other.example>\n"
        "Authentication-Results: mx; dmarc=fail\nReturn-Path: <b@bounces.esp.example>\n\n"
    )
    c = codes(check_headers(make_ctx({}, headers_text=text)))
    assert {
        "headers.other_domain",
        "headers.no_dkim",
        "headers.spf_unaligned",
        "headers.unsubscribe_mailto",
        "headers.dmarc_fail",
        "headers.no_date",
        "headers.no_message_id",
    } <= c
    c2 = codes(
        check_headers(
            make_ctx(
                {},
                headers_text="From: a@example.com\nList-Unsubscribe: <https://e.example/u>\n"
                "DKIM-Signature: d=esp.example.net; s=x\n\n",
            )
        )
    )
    assert {"headers.no_one_click", "headers.dkim_unaligned"} <= c2
    assert "headers.no_unsubscribe" in codes(check_headers(make_ctx({}, headers_text="From: a@example.com\n\n")))
    assert "headers.no_from" in codes(check_headers(make_ctx({}, headers_text="Subject: x\n\n")))


def test_sender_requirements_rollup(zone):
    ctx = make_ctx(zone, fetcher=good_fetcher(), headers_text=HEADERS)
    ctx.results["headers"] = check_headers(ctx)
    for fn in (check_mx, check_spf, check_dkim, check_dmarc):
        r = fn(ctx)
        ctx.results[r.name] = r
    res = check_senders(ctx)
    status = {r["key"]: r["status"] for r in res.data["requirements"]}
    assert status["auth_any"] == status["spf"] == status["dkim"] == status["dmarc"] == "pass"
    assert status["alignment"] == "pass" and status["one_click"] == "pass"
    assert status["spam_rate"] == "manual" and status["rdns"] == "manual"
    assert res.status != "error"


def test_sender_requirements_failures():
    ctx = make_ctx({"example.com": {"TXT": ["v=spf1 +all"]}}, selectors=["s"], common_selectors=False)
    for fn in (check_spf, check_dkim, check_dmarc):
        r = fn(ctx)
        ctx.results[r.name] = r
    res = check_senders(ctx)
    status = {r["key"]: r["status"] for r in res.data["requirements"]}
    assert status["spf"] == "fail" and status["dkim"] == "fail" and status["dmarc"] == "fail"
    assert status["auth_any"] == "fail"
    assert res.status == "error"
    ctx.shared["bulk_sender"] = False
    soft = check_senders(ctx)
    bulk_findings = [f for f in soft.findings if f.message.startswith("[bulk] Valid SPF")]
    assert bulk_findings[0].severity == "warning"
