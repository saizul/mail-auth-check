"""DMARC record parsing (RFC 7489 section 6)."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from .util import parse_tag_list

__all__ = ["KNOWN_TAGS", "DmarcRecord", "ReportUri", "is_dmarc_record", "parse_dmarc", "parse_report_uri"]

KNOWN_TAGS = ("v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri", "np", "psd", "t")
POLICIES = ("none", "quarantine", "reject")
_SIZE_RE = re.compile(r"^(\d+)([kmgt]?)$", re.IGNORECASE)
_UNITS = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30, "t": 2**40}


def is_dmarc_record(text: str) -> bool:
    return bool(re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", text))


@dataclass
class ReportUri:
    raw: str
    scheme: str = ""
    address: str = ""
    host: str = ""
    max_size: int | None = None
    error: str | None = None


def parse_report_uri(raw: str) -> ReportUri:
    """``mailto:reports@example.com!10m`` (6.2: a DMARC URI with an optional '!' size limit)."""
    uri = ReportUri(raw.strip())
    text = uri.raw
    if "!" in text:
        text, size = text.rsplit("!", 1)
        m = _SIZE_RE.match(size)
        if not m:
            uri.error = f"invalid size limit '!{size}'"
            return uri
        uri.max_size = int(m.group(1)) * _UNITS[m.group(2).lower()]
    parts = urllib.parse.urlsplit(text)
    uri.scheme = parts.scheme.lower()
    if uri.scheme == "mailto":
        address = urllib.parse.unquote(parts.path)
        if address.count("@") != 1 or not address.split("@")[1]:
            uri.error = f"'{text}' is not a valid mailto: address"
            return uri
        uri.address = address
        uri.host = address.split("@")[1].lower().rstrip(".")
    elif uri.scheme in ("http", "https"):
        uri.address = text
        uri.host = (parts.hostname or "").lower()
        uri.error = None
    elif not uri.scheme:
        uri.error = f"'{text}' has no URI scheme (use mailto:)"
    else:
        uri.error = f"unsupported URI scheme '{uri.scheme}:'"
    return uri


@dataclass
class DmarcRecord:
    text: str
    tags: dict[str, str] = field(default_factory=dict)
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    fo: list[str] = field(default_factory=lambda: ["0"])
    ri: int = 86400
    nonexistent_policy: str | None = None
    psd: str = "u"
    testing: bool = False
    rua: list[ReportUri] = field(default_factory=list)
    ruf: list[ReportUri] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unknown_tags: list[str] = field(default_factory=list)

    @property
    def effective_subdomain_policy(self) -> str | None:
        return self.subdomain_policy or self.policy

    @property
    def effective_nonexistent_policy(self) -> str | None:
        """DMARCbis np=: the policy for subdomains that do not exist, falling back to sp= and then p=."""
        return self.nonexistent_policy or self.effective_subdomain_policy

    @property
    def enforcing(self) -> bool:
        return self.policy in ("quarantine", "reject")


def parse_dmarc(text: str) -> DmarcRecord:
    rec = DmarcRecord(text)
    tags = parse_tag_list(text)
    rec.tags = dict(tags.tags)
    rec.errors.extend(tags.errors)
    for dup in tags.duplicates:
        rec.errors.append(f"tag '{dup}' appears more than once")
    if not tags.order or tags.order[0] != "v" or tags.get("v") != "DMARC1":
        rec.errors.append("the record must start with v=DMARC1")
    p = tags.get("p")
    if p is None:
        if tags.get("rua"):
            rec.errors.append("the p= tag is missing (receivers may treat the record as p=none)")
            rec.policy = "none"
        else:
            rec.errors.append("the required p= tag is missing")
    else:
        if len(tags.order) > 1 and tags.order[1] != "p":
            rec.warnings.append("p= should directly follow v=DMARC1")
        if p.lower() not in POLICIES:
            rec.errors.append(f"p={p} is not none, quarantine or reject")
        else:
            rec.policy = p.lower()
    sp = tags.get("sp")
    if sp is not None:
        if sp.lower() not in POLICIES:
            rec.errors.append(f"sp={sp} is not none, quarantine or reject")
        else:
            rec.subdomain_policy = sp.lower()
    np = tags.get("np")
    if np is not None:
        if np.lower() not in POLICIES:
            rec.errors.append(f"np={np} is not none, quarantine or reject")
        else:
            rec.nonexistent_policy = np.lower()
    psd = tags.get("psd")
    if psd is not None:
        if psd.lower() not in ("y", "n", "u"):
            rec.errors.append(f"psd={psd} must be y, n or u")
        else:
            rec.psd = psd.lower()
    t = tags.get("t")
    if t is not None:
        if t.lower() not in ("y", "n"):
            rec.errors.append(f"t={t} must be y or n")
        else:
            rec.testing = t.lower() == "y"
    pct = tags.get("pct")
    if pct is not None:
        if not pct.isdigit() or not 0 <= int(pct) <= 100:
            rec.errors.append(f"pct={pct} must be an integer from 0 to 100")
        else:
            rec.pct = int(pct)
    for name in ("adkim", "aspf"):
        value = tags.get(name)
        if value is not None:
            if value.lower() not in ("r", "s"):
                rec.errors.append(f"{name}={value} must be r or s")
            else:
                setattr(rec, name, value.lower())
    fo = tags.get("fo")
    if fo is not None:
        options = [o.strip() for o in fo.split(":")]
        bad = [o for o in options if o not in ("0", "1", "d", "s")]
        if bad:
            rec.errors.append(f"fo={fo}: unknown option(s) {', '.join(bad)}")
        rec.fo = options
        if not tags.get("ruf"):
            rec.warnings.append("fo= has no effect without ruf=")
    rf = tags.get("rf")
    if rf is not None and any(r.strip().lower() != "afrf" for r in rf.split(":")):
        rec.errors.append(f"rf={rf}: only afrf is defined")
    ri = tags.get("ri")
    if ri is not None:
        if not ri.isdigit() or int(ri) > 2**32 - 1:
            rec.errors.append(f"ri={ri} must be a 32-bit unsigned integer")
        else:
            rec.ri = int(ri)
    for name in ("rua", "ruf"):
        value = tags.get(name)
        if value is None:
            continue
        uris = [parse_report_uri(u) for u in value.split(",") if u.strip()]
        if not uris:
            rec.errors.append(f"{name}= is empty")
        for uri in uris:
            if uri.error:
                rec.errors.append(f"{name}: {uri.error}")
        setattr(rec, name, uris)
    rec.unknown_tags = [t for t in tags.order if t not in KNOWN_TAGS]
    return rec
