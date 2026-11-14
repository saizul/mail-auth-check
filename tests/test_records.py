from __future__ import annotations

import base64

import pytest

from conftest import dkim_txt, rsa_pkcs1, rsa_spki
from mail_auth_check.dkim import DkimKeyError, looks_like_dkim, parse_dkim_record, rsa_modulus_bits
from mail_auth_check.dmarc import is_dmarc_record, parse_dmarc, parse_report_uri
from mail_auth_check.mta_sts import MAX_AGE_LIMIT, mx_matches, parse_policy, parse_sts_record, policy_url
from mail_auth_check.util import is_valid_hostname, organizational_domain, parse_tag_list

# -- tag lists, names ----------------------------------------------------------------------------------------------


def test_tag_list():
    t = parse_tag_list(" v=DKIM1 ; K=rsa;; p=abc; bad; 1x=2; v=again ")
    assert t.order == ["v", "k", "p"]
    assert t.get("k") == "rsa"
    assert t.duplicates == ["v"]
    assert len(t.errors) == 2
    assert "p" in t and "x" not in t
    assert parse_tag_list("V=STSv1", lower_names=False).order == ["V"]


@pytest.mark.parametrize(
    ("domain", "org"),
    [
        ("example.com", "example.com"),
        ("mail.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("shop.example.com.bd", "example.com.bd"),
        ("example.com.au", "example.com.au"),
        ("com", "com"),
    ],
)
def test_organizational_domain(domain, org):
    assert organizational_domain(domain) == org


def test_hostname_validation():
    assert is_valid_hostname("mail.example.com")
    assert is_valid_hostname("_dmarc.example.com.")
    assert not is_valid_hostname("localhost")
    assert not is_valid_hostname("-bad.example.com")
    assert not is_valid_hostname("a" * 64 + ".com")


# -- DKIM ----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("bits", [512, 1024, 2048, 3072, 4096])
def test_rsa_modulus_bits(bits):
    assert rsa_modulus_bits(rsa_spki(bits)) == bits
    assert rsa_modulus_bits(rsa_pkcs1(bits)) == bits


@pytest.mark.parametrize("blob", [b"", b"\x30", b"\x02\x01\x00", b"\x30\x03\x06\x01\x00", b"\x30\x84\xff\xff\xff\xff"])
def test_rsa_modulus_bits_rejects_garbage(blob):
    with pytest.raises(DkimKeyError):
        rsa_modulus_bits(blob)


def test_rsa_rejects_other_algorithm():
    from conftest import tlv

    spki = tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("2b6570")) + b"") + tlv(0x03, b"\x00" + b"\x01" * 32))
    with pytest.raises(DkimKeyError, match="not an RSA key"):
        rsa_modulus_bits(spki)


def test_parse_dkim_rsa_and_ed25519():
    key = parse_dkim_record("s1", "s1._domainkey.example.com", dkim_txt(2048, "h=sha256; t=y:s; "))
    assert (key.key_type, key.bits, key.testing, key.hash_algs, key.errors) == ("rsa", 2048, True, ["sha256"], [])
    ed = parse_dkim_record("e", "e._domainkey.example.com", dkim_txt(key_type="ed25519"))
    assert ed.key_type == "ed25519" and ed.bits == 256 and not ed.errors
    assert key.to_dict()["bits"] == 2048


def test_parse_dkim_problems():
    p = base64.b64encode(rsa_spki(1024)).decode()
    assert parse_dkim_record("s", "n", "v=DKIM1; p=").revoked
    assert "missing" in parse_dkim_record("s", "n", "v=DKIM1; k=rsa").errors[0]
    assert "first tag" in parse_dkim_record("s", "n", f"k=rsa; v=DKIM1; p={p}").errors[0]
    assert "DKIM1" in parse_dkim_record("s", "n", f"v=DKIM2; p={p}").errors[0]
    assert "base64" in parse_dkim_record("s", "n", "v=DKIM1; p=***").errors[0]
    assert "SHA-1" in parse_dkim_record("s", "n", f"v=DKIM1; h=sha1; p={p}").errors[0]
    assert parse_dkim_record("s", "n", f"v=DKIM1; h=sha1:sha256; p={p}").warnings
    assert "unknown key type" in parse_dkim_record("s", "n", f"v=DKIM1; k=dsa; p={p}").errors[0]
    assert "not valid for email" in parse_dkim_record("s", "n", f"v=DKIM1; s=other; p={p}").errors[0]
    assert "32 bytes" in parse_dkim_record("s", "n", "v=DKIM1; k=ed25519; p=AAAA").errors[0]
    # whitespace inside p= (long keys split across strings) is fine
    spaced = f"v=DKIM1; p={p[:50]} {p[50:]}"
    assert parse_dkim_record("s", "n", spaced).bits == 1024


def test_looks_like_dkim():
    assert looks_like_dkim("v=DKIM1; p=x")
    assert looks_like_dkim("k=rsa; p=abc")
    assert not looks_like_dkim("v=spf1 -all")


# -- DMARC ---------------------------------------------------------------------------------------------------------


def test_parse_dmarc_full():
    rec = parse_dmarc(
        "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; fo=1:d; rf=afrf; ri=3600; "
        "rua=mailto:agg@example.com!10m,mailto:other@example.net; ruf=mailto:f@example.com"
    )
    assert not rec.errors, rec.errors
    assert (rec.policy, rec.subdomain_policy, rec.pct, rec.adkim, rec.aspf) == ("quarantine", "reject", 50, "s", "r")
    assert rec.fo == ["1", "d"] and rec.ri == 3600
    assert rec.rua[0].max_size == 10 * 2**20 and rec.rua[1].host == "example.net"
    assert rec.enforcing and rec.effective_subdomain_policy == "reject"


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("p=none; v=DMARC1", "must start with v=DMARC1"),
        ("v=DMARC1", "required p= tag"),
        ("v=DMARC1; rua=mailto:a@example.com", "receivers may treat"),
        ("v=DMARC1; p=block", "not none, quarantine or reject"),
        ("v=DMARC1; p=none; sp=maybe", "sp=maybe"),
        ("v=DMARC1; p=none; pct=150", "pct=150"),
        ("v=DMARC1; p=none; adkim=x", "adkim=x"),
        ("v=DMARC1; p=none; fo=2; ruf=mailto:a@example.com", "unknown option"),
        ("v=DMARC1; p=none; rf=iodef", "only afrf"),
        ("v=DMARC1; p=none; ri=abc", "32-bit"),
        ("v=DMARC1; p=none; rua=reports@example.com", "no URI scheme"),
        ("v=DMARC1; p=none; rua=mailto:nobody", "not a valid mailto"),
        ("v=DMARC1; p=none; rua=mailto:a@example.com!10x", "size limit"),
        ("v=DMARC1; p=none; rua=ftp://x.example.com", "unsupported URI scheme"),
        ("v=DMARC1; p=none; p=reject", "more than once"),
    ],
)
def test_parse_dmarc_errors(text, fragment):
    rec = parse_dmarc(text)
    assert any(fragment in e for e in rec.errors), rec.errors


def test_dmarc_warnings_and_unknown_tags():
    rec = parse_dmarc("v=DMARC1; pct=100; p=none; fo=1; foo=bar")
    assert any("directly follow" in w for w in rec.warnings)
    assert any("no effect without ruf" in w for w in rec.warnings)
    assert rec.unknown_tags == ["foo"]
    assert is_dmarc_record("v=DMARC1; p=none") and is_dmarc_record("v = DMARC1")
    assert not is_dmarc_record("v=DMARC2; p=none")


def test_report_uri_units():
    assert parse_report_uri("mailto:a@example.com!1k").max_size == 1024
    assert parse_report_uri("mailto:a@example.com!7").max_size == 7
    assert parse_report_uri("https://r.example.com/dmarc").host == "r.example.com"


# -- MTA-STS -------------------------------------------------------------------------------------------------------


def test_sts_record():
    assert parse_sts_record("v=STSv1; id=20160831085700Z;").errors == []
    assert parse_sts_record("v=STSv1; id=abc").id == "abc"
    assert "id=" in parse_sts_record("v=STSv1;").errors[0]
    assert "1 to 32" in parse_sts_record("v=STSv1; id=" + "a" * 33).errors[0]
    assert "1 to 32" in parse_sts_record("v=STSv1; id=has-dash").errors[0]
    assert "start with" in parse_sts_record("id=1; v=STSv1").errors[0]


def test_policy_parsing():
    pol = parse_policy("version: STSv1\nmode: enforce\nmx: MX1.example.com.\nmx: *.example.net\nmax_age: 86400\n")
    assert (pol.version, pol.mode, pol.max_age, pol.mx, pol.errors) == (
        "STSv1",
        "enforce",
        86400,
        ["mx1.example.com", "*.example.net"],
        [],
    )
    assert policy_url("example.com") == "https://mta-sts.example.com/.well-known/mta-sts.txt"


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 1", "version must be STSv1"),
        ("version: STSv1\nmode: strict\nmx: a.example.com\nmax_age: 1", "mode 'strict'"),
        ("version: STSv1\nmode: enforce\nmx: a.example.com", "max_age is missing"),
        ("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: -5", "non-negative"),
        (f"version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: {MAX_AGE_LIMIT + 1}", "above the maximum"),
        ("version: STSv1\nmode: testing\nmax_age: 10", "at least one mx"),
        ("version: STSv1\nmode: enforce\nmx: a*.example.com\nmax_age: 10", "whole left-most label"),
        ("version: STSv1\nmode: enforce\nmx: *.a.*.example.com\nmax_age: 10", "only the left-most"),
        ("version: STSv1\ngarbage line\nmode: none\nmax_age: 10", "not 'key: value'"),
    ],
)
def test_policy_errors(text, fragment):
    assert any(fragment in e for e in parse_policy(text).errors), parse_policy(text).errors


def test_policy_mode_none_needs_no_mx_and_duplicate_keys_warn():
    pol = parse_policy("version: STSv1\nmode: none\nmode: enforce\nmax_age: 10\n")
    assert pol.errors == [] and pol.mode == "none" and pol.warnings


@pytest.mark.parametrize(
    ("host", "pattern", "ok"),
    [
        ("mx1.example.com", "mx1.example.com", True),
        ("MX1.Example.com.", "mx1.example.com", True),
        ("a.mail.example.com", "*.mail.example.com", True),
        ("mail.example.com", "*.mail.example.com", False),
        ("a.b.mail.example.com", "*.mail.example.com", False),
        ("evilmail.example.com", "*.mail.example.com", False),
    ],
)
def test_mx_matches(host, pattern, ok):
    assert mx_matches(host, pattern) is ok
