"""DKIM key records (RFC 6376 3.6.1, RFC 8301, RFC 8463) and public key size from DER, without dependencies."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from .util import parse_tag_list

__all__ = [
    "COMMON_SELECTORS",
    "DkimKey",
    "DkimKeyError",
    "parse_dkim_record",
    "rsa_modulus_bits",
]

# Selectors used by common providers and control panels. Discovery can only find keys whose selector is guessed;
# pass the real selector (the s= tag of a DKIM-Signature header) to be sure.
COMMON_SELECTORS = (
    "default",
    "dkim",
    "mail",
    "email",
    "smtp",
    "selector",
    "selector1",
    "selector2",  # generic, Microsoft 365
    "google",
    "google2048",  # Google Workspace
    "k1",
    "k2",
    "k3",  # Mailchimp / Mandrill
    "s1",
    "s2",  # SendGrid
    "mx",
    "pic",
    "krs",
    "mailo",  # Mailgun
    "zoho",
    "zmail",  # Zoho
    "fm1",
    "fm2",
    "fm3",  # Fastmail
    "protonmail",
    "protonmail2",
    "protonmail3",  # Proton
    "sig1",  # iCloud
    "everlytickey1",
    "everlytickey2",
    "eversrv",  # Everlytic
    "mandrill",
    "mte1",
    "mte2",
    "cm",
    "ctct1",
    "ctct2",  # Campaign Monitor, Constant Contact
    "hs1",
    "hs2",  # HubSpot
    "key1",
    "key2",
    "dkim1",
    "dkim2",
    "s1024",
    "s2048",
    "x",  # misc
    "mailjet",
    "sendinblue",
    "brevo",
    "mesmtp",
    "smtpapi",
    "turbo-smtp",
    "pm",
    "postmark",
)

RSA_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1


class DkimKeyError(ValueError):
    pass


def _der_read(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the TLV at ``pos``."""
    if pos + 2 > len(data):
        raise DkimKeyError("truncated DER")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DkimKeyError("bad DER length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise DkimKeyError("DER length beyond the data")
    return tag, pos, end


def _rsa_from_pkcs1(data: bytes, start: int, end: int) -> int:
    tag, s, e = _der_read(data, start)
    if tag != 0x02:
        raise DkimKeyError("RSA key: expected the modulus INTEGER")
    modulus = int.from_bytes(data[s:e], "big")
    tag2, _, _ = _der_read(data, e)
    if tag2 != 0x02:
        raise DkimKeyError("RSA key: expected the exponent INTEGER")
    return modulus.bit_length()


def rsa_modulus_bits(der: bytes) -> int:
    """Modulus size of an RSA public key in SubjectPublicKeyInfo (the normal DKIM form) or PKCS#1 form."""
    tag, start, end = _der_read(der, 0)
    if tag != 0x30:
        raise DkimKeyError("not a DER SEQUENCE")
    inner_tag, s, e = _der_read(der, start)
    if inner_tag == 0x02:  # PKCS#1 RSAPublicKey
        return _rsa_from_pkcs1(der, start, end)
    if inner_tag != 0x30:
        raise DkimKeyError("unexpected DER structure")
    oid_tag, os_, oe = _der_read(der, s)
    if oid_tag != 0x06:
        raise DkimKeyError("missing algorithm OID")
    if der[os_:oe] != RSA_OID:
        raise DkimKeyError("the key is not an RSA key")
    bit_tag, bs, be = _der_read(der, e)
    if bit_tag != 0x03 or bs >= be:
        raise DkimKeyError("missing BIT STRING")
    # skip the "unused bits" byte
    seq_tag, ss, se = _der_read(der, bs + 1)
    if seq_tag != 0x30:
        raise DkimKeyError("bad RSAPublicKey")
    return _rsa_from_pkcs1(der, ss, se)


@dataclass
class DkimKey:
    selector: str
    name: str
    text: str
    version: str | None = None
    key_type: str = "rsa"
    bits: int | None = None
    hash_algs: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    service: str | None = None
    revoked: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def testing(self) -> bool:
        return "y" in self.flags

    def to_dict(self) -> dict[str, object]:
        return {
            "selector": self.selector,
            "name": self.name,
            "keyType": self.key_type,
            "bits": self.bits,
            "revoked": self.revoked,
            "testing": self.testing,
            "hashAlgorithms": self.hash_algs,
            "flags": self.flags,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def looks_like_dkim(text: str) -> bool:
    return bool(re.search(r"(^|;)\s*(v\s*=\s*DKIM1|p\s*=)", text, re.IGNORECASE))


def parse_dkim_record(selector: str, name: str, text: str) -> DkimKey:
    key = DkimKey(selector, name, text)
    tags = parse_tag_list(text)
    key.errors.extend(tags.errors)
    for dup in tags.duplicates:
        key.errors.append(f"tag '{dup}' appears more than once")
    if "v" in tags:
        key.version = tags.get("v")
        if key.version != "DKIM1":
            key.errors.append(f"v={key.version}: the version must be DKIM1")
        elif tags.order[0] != "v":
            key.errors.append("the v= tag must be the first tag")
    key.key_type = (tags.get("k") or "rsa").lower()
    if key.key_type not in ("rsa", "ed25519"):
        key.errors.append(f"unknown key type k={key.key_type}")
    if tags.get("h"):
        key.hash_algs = [h.strip().lower() for h in (tags.get("h") or "").split(":") if h.strip()]
        if key.hash_algs == ["sha1"]:
            key.errors.append("h=sha1 only: RFC 8301 forbids signing with SHA-1")
        elif "sha1" in key.hash_algs:
            key.warnings.append("h= still allows sha1")
    if tags.get("t"):
        key.flags = [f.strip().lower() for f in (tags.get("t") or "").split(":") if f.strip()]
    key.service = tags.get("s")
    if key.service and not any(s.strip() in ("*", "email") for s in key.service.split(":")):
        key.errors.append(f"s={key.service}: the key is not valid for email")
    if "p" not in tags:
        key.errors.append("the required p= tag (public key) is missing")
        return key
    p = re.sub(r"\s+", "", tags.get("p") or "")
    if not p:
        key.revoked = True
        return key
    try:
        raw = base64.b64decode(p, validate=True)
    except (binascii.Error, ValueError):
        key.errors.append("p= is not valid base64")
        return key
    if key.key_type == "ed25519":
        if len(raw) != 32:
            key.errors.append(f"an Ed25519 key must be 32 bytes, got {len(raw)}")
        else:
            key.bits = 256
        return key
    try:
        key.bits = rsa_modulus_bits(raw)
    except DkimKeyError as exc:
        key.errors.append(f"cannot read the RSA public key: {exc}")
    return key
