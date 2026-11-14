"""SPF record selection and parsing (RFC 7208 sections 4.5, 4.6, 5, 6 and 12)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .macros import MacroError, validate_macro_string

__all__ = [
    "DNS_MECHANISMS",
    "MECHANISMS",
    "QUALIFIERS",
    "SpfRecord",
    "SpfSyntaxError",
    "Term",
    "is_spf_record",
    "parse_record",
    "select_records",
]

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
# Terms that cause DNS queries and count toward the limit of 10 (4.6.4). "redirect" counts too.
DNS_MECHANISMS = ("include", "a", "mx", "ptr", "exists")

_VERSION_RE = re.compile(r"^v=spf1(?: |$)", re.IGNORECASE)


class SpfSyntaxError(ValueError):
    pass


@dataclass(frozen=True)
class Term:
    kind: str  # "mechanism" or "modifier"
    name: str  # lower case
    raw: str
    qualifier: str = "+"
    value: str | None = None  # domain-spec, network or modifier value
    cidr4: int | None = None
    cidr6: int | None = None

    @property
    def result(self) -> str:
        return QUALIFIERS[self.qualifier]

    @property
    def counts_lookup(self) -> bool:
        return (self.kind == "mechanism" and self.name in DNS_MECHANISMS) or (
            self.kind == "modifier" and self.name == "redirect"
        )

    @property
    def has_macro(self) -> bool:
        return bool(self.value and "%" in self.value)


@dataclass
class SpfRecord:
    text: str
    terms: list[Term] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def mechanisms(self) -> list[Term]:
        return [t for t in self.terms if t.kind == "mechanism"]

    def modifier(self, name: str) -> Term | None:
        return next((t for t in self.terms if t.kind == "modifier" and t.name == name), None)

    @property
    def redirect(self) -> Term | None:
        return self.modifier("redirect")

    @property
    def all_term(self) -> Term | None:
        return next((t for t in self.mechanisms if t.name == "all"), None)

    @property
    def lookup_terms(self) -> list[Term]:
        """Terms that cost a DNS lookup. A redirect next to an ``all`` is ignored (5.1), so it does not count."""
        terms = [t for t in self.terms if t.counts_lookup]
        if self.all_term is not None:
            terms = [t for t in terms if not (t.kind == "modifier" and t.name == "redirect")]
        return terms


def is_spf_record(txt: str) -> bool:
    return bool(_VERSION_RE.match(txt.strip()))


def select_records(txt_records: Iterable[str]) -> list[str]:
    """4.5: keep the TXT records that begin with ``v=spf1`` followed by a space or the end of the record."""
    return [t for t in txt_records if _VERSION_RE.match(t)]


def _parse_cidr(spec: str, allow_v4: bool, allow_v6: bool) -> tuple[str, int | None, int | None]:
    """Split ``domain/24//64`` (dual-cidr-length) into the domain part and the two lengths."""
    cidr4 = cidr6 = None
    rest = spec
    m = re.search(r"(?:/(\d+))?(?://(\d+))?$", spec)
    if m and m.group(0):
        rest = spec[: m.start()]
        if m.group(1) is not None:
            if not allow_v4:
                raise SpfSyntaxError("an IPv4 prefix length is not allowed here")
            cidr4 = int(m.group(1))
            if not 0 <= cidr4 <= 32 or (len(m.group(1)) > 1 and m.group(1).startswith("0")):
                raise SpfSyntaxError(f"invalid IPv4 prefix length /{m.group(1)}")
        if m.group(2) is not None:
            if not allow_v6:
                raise SpfSyntaxError("an IPv6 prefix length is not allowed here")
            cidr6 = int(m.group(2))
            if not 0 <= cidr6 <= 128 or (len(m.group(2)) > 1 and m.group(2).startswith("0")):
                raise SpfSyntaxError(f"invalid IPv6 prefix length //{m.group(2)}")
    return rest, cidr4, cidr6


def _check_domain_spec(spec: str, term: str) -> None:
    if not spec:
        raise SpfSyntaxError(f"'{term}' needs a domain")
    try:
        validate_macro_string(spec)
    except MacroError as exc:
        raise SpfSyntaxError(f"'{term}': {exc}") from exc
    if "%" not in spec:
        labels = spec.rstrip(".").split(".")
        if len(labels) < 2 and spec not in ("localhost",):
            raise SpfSyntaxError(f"'{term}': '{spec}' is not a fully qualified domain")
        for label in labels:
            if not label or len(label) > 63:
                raise SpfSyntaxError(f"'{term}': invalid domain '{spec}'")
            if not re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9\-_]*[A-Za-z0-9_])?", label):
                raise SpfSyntaxError(f"'{term}': invalid domain '{spec}'")


def _parse_term(raw: str) -> Term:
    qualifier = "+"
    body = raw
    if body[0] in QUALIFIERS:
        qualifier, body = body[0], body[1:]
    # Modifiers are name=value; mechanisms use ':' or '/' (or nothing).
    m = re.match(r"^([A-Za-z][A-Za-z0-9\-_.]*)=(.*)$", body)
    if m and raw[0] not in QUALIFIERS:
        name, value = m.group(1).lower(), m.group(2)
        if name in ("redirect", "exp"):
            _check_domain_spec(value, name)
        else:
            try:
                validate_macro_string(value)
            except MacroError as exc:
                raise SpfSyntaxError(f"modifier '{name}': {exc}") from exc
        return Term("modifier", name, raw, value=value)
    m = re.match(r"^([A-Za-z][A-Za-z0-9\-_.]*)(.*)$", body)
    if not m:
        raise SpfSyntaxError(f"unparsable term '{raw}'")
    name, rest = m.group(1).lower(), m.group(2)
    if name not in MECHANISMS:
        raise SpfSyntaxError(f"unknown mechanism '{m.group(1)}'")
    if name == "all":
        if rest:
            raise SpfSyntaxError(f"'all' takes no argument: '{raw}'")
        return Term("mechanism", "all", raw, qualifier)
    if name in ("include", "exists"):
        if not rest.startswith(":"):
            raise SpfSyntaxError(f"'{name}' needs ':domain'")
        _check_domain_spec(rest[1:], name)
        return Term("mechanism", name, raw, qualifier, rest[1:])
    if name in ("a", "mx"):
        spec, c4, c6 = _parse_cidr(rest, True, True)
        domain = None
        if spec:
            if not spec.startswith(":"):
                raise SpfSyntaxError(f"invalid '{name}' mechanism '{raw}'")
            domain = spec[1:]
            _check_domain_spec(domain, name)
        return Term("mechanism", name, raw, qualifier, domain, c4, c6)
    if name == "ptr":
        domain = None
        if rest:
            if not rest.startswith(":"):
                raise SpfSyntaxError(f"invalid 'ptr' mechanism '{raw}'")
            domain = rest[1:]
            _check_domain_spec(domain, name)
        return Term("mechanism", "ptr", raw, qualifier, domain)
    # ip4 / ip6
    if not rest.startswith(":"):
        raise SpfSyntaxError(f"'{name}' needs ':address'")
    addr = rest[1:]
    if name == "ip4":
        net, _, length = addr.partition("/")
        try:
            ip = ipaddress.IPv4Address(net)
        except ValueError as exc:
            raise SpfSyntaxError(f"invalid IPv4 address in '{raw}'") from exc
        c4 = None
        if length:
            if not length.isdigit() or not 0 <= int(length) <= 32:
                raise SpfSyntaxError(f"invalid IPv4 prefix length in '{raw}'")
            c4 = int(length)
        return Term("mechanism", "ip4", raw, qualifier, str(ip), cidr4=c4)
    net, _, length = addr.partition("/")
    try:
        ip6 = ipaddress.IPv6Address(net)
    except ValueError as exc:
        raise SpfSyntaxError(f"invalid IPv6 address in '{raw}'") from exc
    c6 = None
    if length:
        if not length.isdigit() or not 0 <= int(length) <= 128:
            raise SpfSyntaxError(f"invalid IPv6 prefix length in '{raw}'")
        c6 = int(length)
    return Term("mechanism", "ip6", raw, qualifier, str(ip6), cidr6=c6)


def parse_record(text: str) -> SpfRecord:
    """Parse one SPF record. Syntax problems are collected in ``errors`` (each means permerror)."""
    record = SpfRecord(text)
    stripped = text.strip()
    if not _VERSION_RE.match(stripped):
        record.errors.append("the record does not start with 'v=spf1'")
        return record
    if "\t" in text or "  " in stripped:
        record.warnings.append("terms should be separated by single spaces")
    seen_modifiers: dict[str, int] = {}
    for raw in stripped.split()[1:]:
        try:
            term = _parse_term(raw)
        except SpfSyntaxError as exc:
            record.errors.append(str(exc))
            continue
        if term.kind == "modifier":
            seen_modifiers[term.name] = seen_modifiers.get(term.name, 0) + 1
        record.terms.append(term)
    for name in ("redirect", "exp"):
        if seen_modifiers.get(name, 0) > 1:
            record.errors.append(f"the '{name}' modifier appears more than once")
    # Ordering advice (section 6: modifiers SHOULD be at the end; 5.1: terms after "all" are never evaluated).
    seen_all = False
    for term in record.terms:
        if seen_all and term.kind == "mechanism":
            record.warnings.append(f"'{term.raw}' comes after 'all' and is never evaluated")
        if term.kind == "mechanism" and term.name == "all":
            seen_all = True
    if record.redirect and record.all_term:
        record.warnings.append("the 'redirect' modifier is ignored because the record has an 'all' mechanism")
    unknown = sorted({t.name for t in record.terms if t.kind == "modifier" and t.name not in ("redirect", "exp")})
    for name in unknown:
        record.warnings.append(f"unknown modifier '{name}' (ignored by receivers)")
    return record
