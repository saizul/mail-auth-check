from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from mail_auth_check import flatten_spf
from mail_auth_check.cli import EXIT_DNS, EXIT_FAIL, EXIT_OK, EXIT_USAGE, main
from mail_auth_check.resolver import StaticResolver
from mail_auth_check.spf import OverlayResolver, analyze, check_host
from mail_auth_check.spf.flatten import split_txt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def over_limit_zone() -> dict:
    """example.com needs 12 lookups: eleven provider includes, one of them nested."""
    zones: dict = {
        "example.com": {
            "TXT": [
                "v=spf1 a mx " + " ".join(f"include:_spf{i}.provider.test" for i in range(1, 9)) + " ~all",
                "google-site-verification=abc",
            ],
            "A": ["192.0.2.10"],
            "MX": [[10, "mx1.example.com"], [20, "mx2.example.com"]],
        },
        "mx1.example.com": {"A": ["192.0.2.25"]},
        "mx2.example.com": {"A": ["192.0.2.26"], "AAAA": ["2001:db8::26"]},
    }
    for i in range(1, 9):
        zones[f"_spf{i}.provider.test"] = {"TXT": [f"v=spf1 ip4:198.51.{100 + i}.0/24 -all"]}
    zones["_spf1.provider.test"]["TXT"] = ["v=spf1 include:_nested.provider.test ip4:198.51.101.0/24 ~all"]
    zones["_nested.provider.test"] = {"TXT": ["v=spf1 ip6:2001:db8:aa::/48 ip4:198.51.101.128/25 -all"]}
    return zones


def run(argv, zones):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, resolver=StaticResolver(zones), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_flatten_brings_policy_under_the_limit():
    zones = over_limit_zone()
    resolver = StaticResolver(zones)
    assert analyze(resolver, "example.com").total_lookups == 11
    result = flatten_spf(resolver, "example.com")
    assert result.status == "ok", result.errors
    assert result.original_lookups == 11 and result.lookups == 0
    record = result.records["example.com"]
    assert record.startswith("v=spf1 ip4:192.0.2.10 ip4:192.0.2.25 ip4:192.0.2.26 ")
    assert record.endswith(" ip6:2001:db8::26 ip6:2001:db8:aa::/48 ~all")
    # 198.51.101.128/25 is inside 198.51.101.0/24 and is merged away; adjacent /24s are collapsed.
    assert "198.51.101.128" not in record
    assert "ip4:198.51.102.0/23" in record and "ip4:198.51.104.0/22" in record
    assert result.verification and not result.mismatches
    # Addresses matched late in the original need more than 10 lookups there (permerror), so they are not compared.
    assert {v["match"] for v in result.verification} == {"yes", "n/a"}
    assert "example.com: include:_spf1.provider.test" in result.flattened


def test_overlay_keeps_other_txt_records():
    zones = over_limit_zone()
    overlay = OverlayResolver(StaticResolver(zones), {"example.com": "v=spf1 -all", "_spf9.example.com": "v=spf1 ~all"})
    assert overlay.resolve("example.com", "TXT").records == ("v=spf1 -all", "google-site-verification=abc")
    assert overlay.resolve("_spf9.example.com", "TXT").records == ("v=spf1 ~all",)
    assert overlay.resolve("example.com", "A").records == ("192.0.2.10",)


def test_flatten_splits_long_records_into_a_chain():
    zones = {"example.com": {"TXT": ["v=spf1 include:big.provider.test -all"]}}
    nets = " ".join(f"ip4:10.{i}.0.1" for i in range(0, 120, 2))
    zones["big.provider.test"] = {"TXT": [f"v=spf1 {nets} -all"]}
    result = flatten_spf(StaticResolver(zones), "example.com", max_length=200, label="_s")
    assert result.status == "ok", result.errors
    root = result.records["example.com"]
    chained = [n for n in result.records if n != "example.com"]
    assert chained[0] == "_s1.example.com" and len(chained) >= 4
    assert root == "v=spf1 " + " ".join(f"include:{n}" for n in chained) + " -all"
    assert all(len(v) <= 200 for v in result.records.values())
    assert all(result.records[n].endswith(" -all") for n in chained)
    assert result.lookups == len(chained)
    assert not result.mismatches and len(result.verification) > 60


def test_flatten_keeps_requested_and_unflattenable_includes():
    zones = over_limit_zone()
    zones["example.com"]["TXT"][0] = (
        "v=spf1 include:_spf2.provider.test include:macro.provider.test include:keep.provider.test "
        "exists:%{i}._spf.example.com -all"
    )
    zones["macro.provider.test"] = {"TXT": ["v=spf1 ip4:203.0.113.0/24 exists:%{i}.allow.provider.test -all"]}
    zones["keep.provider.test"] = {"TXT": ["v=spf1 ip4:198.18.0.0/24 -all"]}
    result = flatten_spf(StaticResolver(zones), "example.com", keep=["KEEP.provider.test."])
    assert result.status == "ok", result.errors
    assert result.records["example.com"] == (
        "v=spf1 ip4:198.51.102.0/24 include:macro.provider.test include:keep.provider.test "
        "exists:%{i}._spf.example.com -all"
    )
    assert result.kept == ["include:macro.provider.test", "include:keep.provider.test", "exists:%{i}._spf.example.com"]
    assert any("cannot be replaced" in w for w in result.warnings)
    assert result.lookups == 4


def test_flatten_follows_redirect_and_keeps_exp():
    zones = {
        "example.com": {"TXT": ["v=spf1 ip4:192.0.2.1 redirect=_spf.example.net exp=explain.example.com"]},
        "_spf.example.net": {"TXT": ["v=spf1 a:mail.example.net ?all"]},
        "mail.example.net": {"A": ["198.51.100.7"]},
    }
    result = flatten_spf(StaticResolver(zones), "example.com")
    assert result.records["example.com"] == "v=spf1 ip4:192.0.2.1 ip4:198.51.100.7 ?all exp=explain.example.com"
    assert any("?all" in w for w in result.warnings)
    kept = flatten_spf(StaticResolver(zones), "example.com", keep=["_spf.example.net"])
    assert kept.records["example.com"] == "v=spf1 ip4:192.0.2.1 redirect=_spf.example.net exp=explain.example.com"


def test_flatten_cidr_lengths_and_host_bits():
    zones = {
        "example.com": {"TXT": ["v=spf1 a/24//64 mx:mail.example.com/30 ip4:192.0.2.77/28 -all"]},
        "mail.example.com": {"MX": [[5, "mx.example.com"]]},
        "mx.example.com": {"A": ["198.51.100.9"]},
    }
    zones["example.com"]["A"] = ["203.0.113.50"]
    zones["example.com"]["AAAA"] = ["2001:db8:1:2::5"]
    result = flatten_spf(StaticResolver(zones), "example.com")
    assert result.ip4 == ["192.0.2.64/28", "198.51.100.8/30", "203.0.113.0/24"]
    assert result.ip6 == ["2001:db8:1:2::/64"]
    assert any("host bits" in n for n in result.notes)
    assert not result.mismatches


def test_flatten_detects_order_change():
    zones = {
        "example.com": {"TXT": ["v=spf1 a -ip4:192.0.2.5 include:p.example.net -all"], "A": ["198.51.100.1"]},
        "p.example.net": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
    }
    result = flatten_spf(StaticResolver(zones), "example.com", sample_ips=["192.0.2.5"])
    assert any("non-pass term" in w for w in result.warnings)
    assert result.status == "error"
    assert result.mismatches[0] == {"ip": "192.0.2.5", "original": "fail", "flattened": "pass", "match": "no"}


def test_flatten_include_internals():
    zones = {
        "example.com": {"TXT": ["v=spf1 include:p.example.net include:open.example.net -all"]},
        "p.example.net": {"TXT": ["v=spf1 -ip4:192.0.2.9 ip4:192.0.2.0/24 ~all"]},
        "open.example.net": {"TXT": ["v=spf1 ip4:198.51.100.0/24 +all"]},
    }
    result = flatten_spf(StaticResolver(zones), "example.com", verify=False)
    assert any("does not authorize" in n for n in result.notes)
    assert "include:open.example.net" in result.kept
    assert result.verification == []


@pytest.mark.parametrize(
    ("zones", "message", "dns"),
    [
        ({}, "has no SPF record", False),
        ({"example.com": {"TXT": ["v=spf1 -all", "v=spf1 ~all"]}}, "publishes 2 SPF records", False),
        ({"example.com": {"TXT": ["v=spf1 foo:bar -all"]}}, "unknown mechanism", False),
        ({"example.com": {"TXT": {"error": "SERVFAIL"}}}, "failed", True),
        (
            {
                "example.com": {"TXT": ["v=spf1 include:a.example.net -all"]},
                "a.example.net": {"TXT": ["v=spf1 include:example.com -all"]},
            },
            "include loop",
            False,
        ),
        (
            {"example.com": {"TXT": ["v=spf1 include:x.example.net -all"]}, "x.example.net": {"error": "timeout"}},
            "timeout",
            True,
        ),
        (
            {
                "example.com": {"TXT": ["v=spf1 mx -all"], "MX": [[i, f"mx{i}.example.com"] for i in range(11)]},
            },
            "11 MX hosts",
            False,
        ),
    ],
)
def test_flatten_errors(zones, message, dns):
    result = flatten_spf(StaticResolver(zones), "example.com")
    assert result.status == "error" and not result.records
    assert message in result.errors[0]
    assert result.dns_failure is dns


def test_flatten_still_over_limit_with_kept_includes():
    zones = over_limit_zone()
    keep = [f"_spf{i}.provider.test" for i in range(1, 9)]
    result = flatten_spf(StaticResolver(zones), "example.com", keep=keep)
    assert result.status == "ok" and result.lookups == 9
    zones["_spf2.provider.test"]["TXT"] = ["v=spf1 " + " ".join(f"a:h{i}.provider.test" for i in range(4)) + " -all"]
    result = flatten_spf(StaticResolver(zones), "example.com", keep=keep)
    assert result.status == "error" and result.lookups == 13
    assert "still needs 13 DNS lookups" in result.errors[0]


def test_flatten_unchanged_and_bad_arguments():
    zones = {"example.com": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]}}
    assert flatten_spf(StaticResolver(zones), "example.com").status == "unchanged"
    with pytest.raises(ValueError, match="max_length"):
        flatten_spf(StaticResolver(zones), "example.com", max_length=10)
    with pytest.raises(ValueError, match="invalid label"):
        flatten_spf(StaticResolver(zones), "example.com", label="a..b")


def test_split_txt():
    assert split_txt("") == [""]
    parts = split_txt("x" * 600)
    assert [len(p) for p in parts] == [255, 255, 90]


def test_cli_flatten_text_json_and_zone():
    zones = over_limit_zone()
    code, out, _ = run(["flatten-spf", "example.com"], zones)
    assert code == EXIT_OK
    assert "SPF flattening for example.com: ok" in out and "original (11 lookups)" in out
    assert 'example.com. 3600 IN TXT "v=spf1 ip4:192.0.2.10' in out
    assert "give the same result" in out

    code, out, _ = run(
        ["flatten-spf", "example.com", "-f", "json", "--keep", "_spf1.provider.test,_spf2.provider.test"], zones
    )
    data = json.loads(out)
    assert code == EXIT_OK and data["lookups"] == 3 and data["lookupLimit"] == 10
    assert data["records"][0]["name"] == "example.com"
    assert data["kept"] == ["include:_spf1.provider.test", "include:_spf2.provider.test"]

    code, out, _ = run(["flatten-spf", "example.com", "-f", "zone", "--max-length", "100", "--ttl", "300"], zones)
    lines = out.splitlines()
    assert code == EXIT_OK and len(lines) > 2
    assert lines[0].startswith('example.com. 300 IN TXT "v=spf1 include:_spf1.example.com ')
    assert lines[1].startswith("_spf1.example.com. 300 IN TXT")


def test_cli_flatten_exit_codes(tmp_path):
    zones = {
        "example.com": {"TXT": ["v=spf1 a -ip4:192.0.2.5 include:p.example.net -all"], "A": ["198.51.100.1"]},
        "p.example.net": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
        "down.example.com": {"error": "SERVFAIL"},
    }
    assert run(["flatten-spf", "example.com", "--ip", "192.0.2.5"], zones)[0] == EXIT_FAIL
    assert run(["flatten-spf", "example.com", "--no-verify"], zones)[0] == EXIT_OK
    assert run(["flatten-spf", "down.example.com"], zones)[0] == EXIT_DNS
    code, _, err = run(["flatten-spf", "example.com", "--ip", "nope"], zones)
    assert code == EXIT_USAGE and "nope" in err
    assert run(["flatten-spf", "not a domain"], zones)[0] == EXIT_USAGE
    assert run(["flatten-spf"], zones)[0] == EXIT_USAGE
    target = tmp_path / "out.txt"
    assert run(["flatten-spf", "example.com", "--no-verify", "-o", str(target)], zones) == (EXIT_OK, "", "")
    assert "SPF flattening" in target.read_text(encoding="utf-8")


def test_cli_flatten_example_data(capsys):
    code = main(["flatten-spf", "example.com", "--dns-data", str(EXAMPLES / "dns-example.json"), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == EXIT_OK
    assert data["records"][0]["value"] == "v=spf1 ip4:192.0.2.0/27 ip4:198.51.100.0/24 ip6:2001:db8:100::/48 -all"
    resolver = OverlayResolver(
        StaticResolver.from_file(EXAMPLES / "dns-example.json"), {"example.com": data["records"][0]["value"]}
    )
    assert check_host(resolver, "198.51.100.20", "example.com").result == "pass"
