from __future__ import annotations

import json

import dns.exception
import dns.resolver
import pytest

from mail_auth_check.resolver import DnspythonResolver, StaticResolver
from mail_auth_check.util import FetchResult, StaticFetcher, urllib_fetcher


def test_static_resolver_statuses():
    r = StaticResolver(
        {
            "Example.COM.": {"TXT": [["v=spf1 ", "-all"], "plain"], "MX": [[10, "MX.example.com."]], "A": []},
            "alias.example.com": {"CNAME": "example.com"},
            "loop1.example.com": {"CNAME": ["loop2.example.com"]},
            "loop2.example.com": {"CNAME": ["loop1.example.com"]},
            "down.example.com": {"error": "SERVFAIL"},
            "slow.example.com": {"TXT": {"error": "timeout"}},
            "*.wild.example.com": {"TXT": ["wildcard"]},
        }
    )
    txt = r.resolve("example.com", "txt")
    assert txt.ok and txt.records == ("v=spf1 -all", "plain")
    assert r.resolve("example.com", "MX").records == ((10, "mx.example.com"),)
    assert r.resolve("example.com", "A").status == "nodata"
    assert r.resolve("example.com", "AAAA").status == "nodata" and r.resolve("example.com", "AAAA").is_void
    assert r.resolve("missing.example.com", "A").status == "nxdomain"
    assert r.resolve("alias.example.com", "MX").records == ((10, "mx.example.com"),)
    assert r.resolve("alias.example.com", "CNAME").records == ("example.com",)
    assert r.resolve("loop1.example.com", "A").failed
    assert r.resolve("down.example.com", "TXT").error == "SERVFAIL"
    assert r.resolve("slow.example.com", "TXT").failed
    assert r.resolve("anything.wild.example.com", "TXT").records == ("wildcard",)
    assert r.resolve("a.b.wild.example.com", "TXT").records == ("wildcard",)
    assert r.resolve("wild.example.com", "TXT").status == "nxdomain"
    assert ("example.com", "TXT") in r.queries


def test_static_resolver_from_file(tmp_path):
    p = tmp_path / "z.json"
    p.write_text(json.dumps({"example.com": {"A": ["192.0.2.1"]}}))
    assert StaticResolver.from_file(p).resolve("example.com", "A").ok
    p.write_text("[]")
    with pytest.raises(ValueError):
        StaticResolver.from_file(p)


class _RR:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def to_text(self):
        return self.text


class _Name:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


def test_dnspython_resolver_mapping(monkeypatch):
    r = DnspythonResolver(nameservers=["192.0.2.53"], timeout=1, lifetime=2)
    assert r._resolver.nameservers == ["192.0.2.53"]
    answers = {
        ("example.com.", "TXT"): [_RR(strings=[b"v=spf1 ", b"-all"]), _RR(strings=[b"\xff\xfe"])],
        ("example.com.", "MX"): [_RR(preference=10, exchange=_Name("mx.example.com."))],
        ("example.com.", "A"): [_RR(text="192.0.2.1")],
        ("www.example.com.", "CNAME"): [_RR(target=_Name("example.com."))],
    }

    def fake_resolve(qname, rdtype, raise_on_no_answer=True, search=False):
        if qname == "nx.example.com.":
            raise dns.resolver.NXDOMAIN()
        if qname == "empty.example.com.":
            raise dns.resolver.NoAnswer()
        if qname == "slow.example.com.":
            raise dns.exception.Timeout()
        if qname == "refused.example.com.":
            raise dns.resolver.NoNameservers()
        if qname == "odd.example.com.":
            raise dns.exception.DNSException("weird")
        return answers[(qname, rdtype)]

    monkeypatch.setattr(r._resolver, "resolve", fake_resolve)
    txt = r.resolve("Example.com.", "TXT")
    assert txt.records == ("v=spf1 -all", "\xff\xfe".encode("latin-1").decode("latin-1"))
    assert r.resolve("example.com", "MX").records == ((10, "mx.example.com"),)
    assert r.resolve("example.com", "A").records == ("192.0.2.1",)
    assert r.resolve("www.example.com", "CNAME").records == ("example.com",)
    assert r.resolve("nx.example.com", "A").status == "nxdomain"
    assert r.resolve("empty.example.com", "A").status == "nodata"
    assert r.resolve("slow.example.com", "A").error == "timeout"
    assert r.resolve("refused.example.com", "A").failed
    assert r.resolve("odd.example.com", "A").error == "weird"
    before = r.queries
    r.resolve("example.com", "TXT")  # cached
    assert r.queries == before


def test_static_fetcher():
    f = StaticFetcher(
        {
            "https://a.example/x": {"status": 301, "location": "https://b.example/"},
            "https://a.example/big": {"body": "x" * 20},
            "https://a.example/err": {"error": "certificate expired"},
        }
    )
    assert f("https://a.example/x").redirect_location == "https://b.example/"
    big = f("https://a.example/big", 1, 10)
    assert big.truncated and len(big.body) == 10 and big.ok
    assert f("https://a.example/err").error == "certificate expired"
    assert f("https://unknown.example/").error
    assert f.requests[0] == "https://a.example/x"


def test_urllib_fetcher_refuses_plain_http():
    got = urllib_fetcher("http://example.com/")
    assert isinstance(got, FetchResult) and got.error and not got.ok
