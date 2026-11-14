from __future__ import annotations

import base64
from typing import Any

import pytest

from mail_auth_check.checks import CheckContext
from mail_auth_check.resolver import StaticResolver
from mail_auth_check.util import StaticFetcher

RSA_OID = bytes.fromhex("2a864886f70d010101")


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def der_int(value: int) -> bytes:
    return tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def rsa_spki(bits: int) -> bytes:
    """A syntactically valid RSA SubjectPublicKeyInfo with a modulus of exactly ``bits`` bits."""
    modulus = (1 << (bits - 1)) | 1
    pkcs1 = tlv(0x30, der_int(modulus) + der_int(65537))
    algo = tlv(0x30, tlv(0x06, RSA_OID) + b"\x05\x00")
    return tlv(0x30, algo + tlv(0x03, b"\x00" + pkcs1))


def rsa_pkcs1(bits: int) -> bytes:
    return tlv(0x30, der_int((1 << (bits - 1)) | 1) + der_int(65537))


def dkim_txt(bits: int = 2048, extra: str = "", key_type: str = "rsa") -> str:
    if key_type == "ed25519":
        p = base64.b64encode(b"\x01" * 32).decode()
        return f"v=DKIM1; k=ed25519; {extra}p={p}"
    p = base64.b64encode(rsa_spki(bits)).decode()
    return f"v=DKIM1; k=rsa; {extra}p={p}"


GOOD_POLICY = "version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.mail.example.com\r\nmax_age: 604800\r\n"


def good_zone(domain: str = "example.com") -> dict[str, Any]:
    return {
        domain: {
            "MX": [[10, f"mx1.{domain}"], [20, f"b.mail.{domain}"]],
            "TXT": [f"v=spf1 ip4:192.0.2.0/24 include:_spf.{domain} -all"],
        },
        f"mx1.{domain}": {"A": ["192.0.2.25"]},
        f"b.mail.{domain}": {"AAAA": ["2001:db8::25"]},
        f"_spf.{domain}": {"TXT": ["v=spf1 ip6:2001:db8::/32 ~all"]},
        f"selector1._domainkey.{domain}": {"TXT": [dkim_txt(2048)]},
        f"_dmarc.{domain}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"]},
        f"_mta-sts.{domain}": {"TXT": ["v=STSv1; id=2026111401"]},
        f"_smtp._tls.{domain}": {"TXT": [f"v=TLSRPTv1; rua=mailto:tls@{domain}"]},
    }


def good_fetcher(domain: str = "example.com") -> StaticFetcher:
    return StaticFetcher({f"https://mta-sts.{domain}/.well-known/mta-sts.txt": {"status": 200, "body": GOOD_POLICY}})


def make_ctx(zones: dict[str, Any], domain: str = "example.com", **kw: Any) -> CheckContext:
    return CheckContext(domain=domain, resolver=StaticResolver(zones), **kw)


@pytest.fixture
def zone() -> dict[str, Any]:
    return good_zone()
