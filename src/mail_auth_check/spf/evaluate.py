"""SPF analysis and evaluation.

``analyze()`` walks the whole include/redirect tree without an IP address and counts every DNS-querying term, which
is the worst case a receiver can hit: the 10-lookup limit (RFC 7208 4.6.4) applies to the whole evaluation, includes
and redirects included. It also counts void lookups (limit 2) and the MX names of each ``mx`` term (limit 10).

``check_host()`` evaluates the policy for one client IP the way a receiver does (section 4), stopping at the first
matching mechanism, and returns pass, fail, softfail, neutral, none, permerror or temperror.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ..resolver import DnsAnswer, Resolver
from .macros import MacroContext, MacroError, expand
from .parser import SpfRecord, Term, parse_record, select_records

__all__ = [
    "LOOKUP_LIMIT",
    "MX_LIMIT",
    "PTR_LIMIT",
    "VOID_LIMIT",
    "EvalResult",
    "SpfAnalysis",
    "SpfNode",
    "analyze",
    "check_host",
    "fetch_spf",
]

LOOKUP_LIMIT = 10
VOID_LIMIT = 2
MX_LIMIT = 10
PTR_LIMIT = 10


def fetch_spf(resolver: Resolver, domain: str) -> tuple[str, str | None, list[str], DnsAnswer]:
    """Return ``(status, record_text, all_spf_records, answer)``; status is ok, none, permerror or temperror."""
    answer = resolver.resolve(domain, "TXT")
    if answer.failed:
        return "temperror", None, [], answer
    records = select_records(answer.records if answer.status == "ok" else ())
    if not records:
        return "none", None, [], answer
    if len(records) > 1:
        return "permerror", None, records, answer
    return "ok", records[0], records, answer


# -- static analysis -----------------------------------------------------------------------------------------------


@dataclass
class SpfNode:
    domain: str
    via: str = "root"  # root, include or redirect
    status: str = "ok"  # ok, none, permerror, temperror, loop, skipped
    text: str | None = None
    record: SpfRecord | None = None
    duplicates: list[str] = field(default_factory=list)
    children: list[SpfNode] = field(default_factory=list)
    lookups: int = 0  # DNS-querying terms in this record
    void_lookups: int = 0
    notes: list[str] = field(default_factory=list)
    mx_names: dict[str, int] = field(default_factory=dict)

    def walk(self):  # type: ignore[no-untyped-def]
        yield self
        for child in self.children:
            yield from child.walk()

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "via": self.via,
            "status": self.status,
            "record": self.text,
            "lookups": self.lookups,
            "voidLookups": self.void_lookups,
            "notes": self.notes,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class SpfAnalysis:
    domain: str
    root: SpfNode
    total_lookups: int = 0
    total_void: int = 0
    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return self.root.status

    @property
    def record(self) -> SpfRecord | None:
        return self.root.record

    @property
    def over_lookup_limit(self) -> bool:
        return self.total_lookups > LOOKUP_LIMIT

    @property
    def over_void_limit(self) -> bool:
        return self.total_void > VOID_LIMIT

    def effective_all(self) -> str | None:
        """Qualifier of the ``all`` that ends evaluation, following a redirect chain when there is no ``all``."""
        node = self.root
        seen = 0
        while node and node.record and seen < 20:
            seen += 1
            term = node.record.all_term
            if term is not None:
                return term.qualifier
            nxt = next((c for c in node.children if c.via == "redirect"), None)
            if nxt is None:
                return None
            node = nxt
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status,
            "record": self.root.text,
            "lookups": self.total_lookups,
            "lookupLimit": LOOKUP_LIMIT,
            "voidLookups": self.total_void,
            "voidLimit": VOID_LIMIT,
            "ip4": self.ip4,
            "ip6": self.ip6,
            "errors": self.errors,
            "tree": self.root.to_dict(),
        }


def _void_a(resolver: Resolver, name: str) -> tuple[bool, bool]:
    """Return (void, failed) for an a-style lookup when the client address family is unknown."""
    a = resolver.resolve(name, "A")
    aaaa = resolver.resolve(name, "AAAA")
    return (a.is_void and aaaa.is_void), (a.failed or aaaa.failed)


def analyze(resolver: Resolver, domain: str, max_depth: int = 12) -> SpfAnalysis:
    root = SpfNode(domain)
    analysis = SpfAnalysis(domain, root)
    _analyze_node(resolver, root, analysis, (domain.lower(),), max_depth)
    for node in root.walk():
        analysis.total_lookups += node.lookups
        analysis.total_void += node.void_lookups
    return analysis


def _analyze_node(resolver: Resolver, node: SpfNode, analysis: SpfAnalysis, chain: tuple[str, ...], depth: int) -> None:
    status, text, records, answer = fetch_spf(resolver, node.domain)
    if status == "temperror":
        node.status = "temperror"
        node.notes.append(f"DNS error for {node.domain}: {answer.error}")
        analysis.errors.append(f"TXT lookup for {node.domain} failed ({answer.error})")
        return
    if status == "none":
        node.status = "none"
        if answer.is_void and node.via != "root":
            node.void_lookups += 1
        return
    if status == "permerror":
        node.status = "permerror"
        node.duplicates = records
        analysis.errors.append(f"{node.domain} publishes {len(records)} SPF records; exactly one is allowed")
        return
    node.text = text
    record = parse_record(text or "")
    node.record = record
    if record.errors:
        node.status = "permerror"
        analysis.errors.extend(f"{node.domain}: {e}" for e in record.errors)
    node.lookups = len(record.lookup_terms)
    for term in record.terms:
        if term.kind == "mechanism" and term.name == "ip4":
            analysis.ip4.append(term.value + (f"/{term.cidr4}" if term.cidr4 is not None else ""))
        elif term.kind == "mechanism" and term.name == "ip6":
            analysis.ip6.append(term.value + (f"/{term.cidr6}" if term.cidr6 is not None else ""))
    for term in record.lookup_terms:
        target = term.value or node.domain
        if term.has_macro:
            node.notes.append(f"'{term.raw}' uses macros; its target depends on the message and was not resolved")
            continue
        if term.name in ("include", "redirect"):
            via = "include" if term.name == "include" else "redirect"
            if target.lower() in chain:
                child = SpfNode(target, via, status="loop")
                node.children.append(child)
                analysis.errors.append(f"{via} loop: {' -> '.join((*chain, target.lower()))}")
                node.status = "permerror"
                continue
            if depth <= 0:
                node.children.append(SpfNode(target, via, status="skipped", notes=["nesting too deep"]))
                continue
            child = SpfNode(target, via)
            node.children.append(child)
            _analyze_node(resolver, child, analysis, (*chain, target.lower()), depth - 1)
            if child.status == "none":
                # 5.2 / 6.1: an include or redirect to a domain without SPF is a permerror.
                analysis.errors.append(f"{via}:{target} has no SPF record (permerror)")
                child.status = "permerror"
            if child.status in ("permerror", "loop"):
                node.status = "permerror"
            elif child.status == "temperror" and node.status == "ok":
                node.status = "temperror"
        elif term.name == "a":
            void, failed = _void_a(resolver, target)
            if failed:
                node.notes.append(f"'{term.raw}': DNS error")
            elif void:
                node.void_lookups += 1
                node.notes.append(f"'{term.raw}': {target} has no A/AAAA records (void lookup)")
        elif term.name == "mx":
            mx = resolver.resolve(target, "MX")
            if mx.failed:
                node.notes.append(f"'{term.raw}': DNS error")
                continue
            if mx.is_void:
                node.void_lookups += 1
                node.notes.append(f"'{term.raw}': {target} has no MX records (void lookup)")
                continue
            names = [host for _, host in mx.records if host]
            node.mx_names[term.raw] = len(names)
            if len(names) > MX_LIMIT:
                node.status = "permerror"
                analysis.errors.append(f"'{term.raw}' at {node.domain} has {len(names)} MX hosts; the limit is 10")
        elif term.name == "exists":
            ans = resolver.resolve(target, "A")
            if ans.is_void:
                node.void_lookups += 1
        elif term.name == "ptr":
            node.notes.append("'ptr' is slow and unreliable; RFC 7208 says it SHOULD NOT be published")


# -- check_host ------------------------------------------------------------------------------------------------------


@dataclass
class EvalResult:
    result: str  # pass fail softfail neutral none permerror temperror
    domain: str
    mechanism: str | None = None
    reason: str = ""
    lookups: int = 0
    void_lookups: int = 0
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "domain": self.domain,
            "mechanism": self.mechanism,
            "reason": self.reason,
            "lookups": self.lookups,
            "voidLookups": self.void_lookups,
            "trace": self.trace,
        }


class _Abort(Exception):
    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


class _Evaluator:
    def __init__(self, resolver: Resolver, ip: str, sender: str, helo: str) -> None:
        self.resolver = resolver
        self.ip = ipaddress.ip_address(ip)
        if isinstance(self.ip, ipaddress.IPv6Address) and self.ip.ipv4_mapped:
            self.ip = self.ip.ipv4_mapped
        self.sender = sender
        self.helo = helo
        self.lookups = 0
        self.voids = 0
        self.trace: list[str] = []

    # bookkeeping
    def count_lookup(self, term: Term) -> None:
        self.lookups += 1
        if self.lookups > LOOKUP_LIMIT:
            raise _Abort("permerror", f"more than {LOOKUP_LIMIT} DNS lookups (at '{term.raw}')")

    def query(self, name: str, rdtype: str) -> DnsAnswer:
        ans = self.resolver.resolve(name, rdtype)
        if ans.failed:
            raise _Abort("temperror", f"DNS error for {rdtype} {name}: {ans.error}")
        if ans.is_void:
            self.voids += 1
            if self.voids > VOID_LIMIT:
                raise _Abort("permerror", f"more than {VOID_LIMIT} void lookups")
        return ans

    def target(self, term: Term, domain: str) -> str:
        if not term.value:
            return domain
        try:
            return expand(term.value, MacroContext(str(self.ip), domain, self.sender, self.helo))
        except MacroError as exc:
            raise _Abort("permerror", str(exc)) from exc

    def addresses(self, name: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        rdtype = "A" if self.ip.version == 4 else "AAAA"
        ans = self.query(name, rdtype)
        return [ipaddress.ip_address(r) for r in ans.records] if ans.status == "ok" else []

    def in_net(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, term: Term) -> bool:
        if addr.version != self.ip.version:
            return False
        length = term.cidr4 if self.ip.version == 4 else term.cidr6
        if length is None:
            return addr == self.ip
        return self.ip in ipaddress.ip_network(f"{addr}/{length}", strict=False)

    # evaluation
    def check_host(self, domain: str, depth: int = 0) -> tuple[str, Term | None]:
        if depth > 20:
            raise _Abort("permerror", "include/redirect nesting too deep")
        status, text, _, answer = fetch_spf(self.resolver, domain)
        if status == "temperror":
            raise _Abort("temperror", f"TXT lookup for {domain} failed: {answer.error}")
        if status == "none":
            return "none", None
        if status == "permerror":
            raise _Abort("permerror", f"{domain} has more than one SPF record")
        record = parse_record(text or "")
        if record.errors:
            raise _Abort("permerror", f"{domain}: {record.errors[0]}")
        self.trace.append(f"{domain}: {text}")
        for term in record.mechanisms:
            if self.matches(term, domain, depth):
                self.trace.append(f"{domain}: matched '{term.raw}' -> {term.result}")
                return term.result, term
        redirect = record.redirect
        if redirect is not None and record.all_term is None:
            self.count_lookup(redirect)
            target = self.target(redirect, domain)
            result, term = self.check_host(target, depth + 1)
            if result == "none":
                raise _Abort("permerror", f"redirect={target} has no SPF record")
            return result, term
        return "neutral", None

    def matches(self, term: Term, domain: str, depth: int) -> bool:
        name = term.name
        if name == "all":
            return True
        if name == "ip4":
            if self.ip.version != 4:
                return False
            return self.ip in ipaddress.ip_network(
                f"{term.value}/{term.cidr4 if term.cidr4 is not None else 32}", strict=False
            )
        if name == "ip6":
            if self.ip.version != 6:
                return False
            return self.ip in ipaddress.ip_network(
                f"{term.value}/{term.cidr6 if term.cidr6 is not None else 128}", strict=False
            )
        self.count_lookup(term)
        target = self.target(term, domain)
        if name == "include":
            result, _ = self.check_host(target, depth + 1)
            if result == "pass":
                return True
            if result in ("fail", "softfail", "neutral"):
                return False
            raise _Abort("permerror", f"include:{target} returned {result}")
        if name == "a":
            return any(self.in_net(a, term) for a in self.addresses(target))
        if name == "mx":
            ans = self.query(target, "MX")
            hosts = [h for _, h in sorted(ans.records)] if ans.status == "ok" else []
            if len(hosts) > MX_LIMIT:
                raise _Abort("permerror", f"{target} has more than {MX_LIMIT} MX records")
            return any(self.in_net(a, term) for host in hosts for a in self.addresses(host))
        if name == "exists":
            ans = self.query(target, "A")
            return ans.status == "ok" and bool(ans.records)
        if name == "ptr":
            return self.ptr_matches(target)
        return False  # pragma: no cover - parser rejects other names

    def ptr_matches(self, target: str) -> bool:
        rev = self.ip.reverse_pointer
        ans = self.resolver.resolve(rev, "PTR")
        if ans.failed or ans.status != "ok":
            return False
        target = target.lower()
        for name in list(ans.records)[:PTR_LIMIT]:
            try:
                confirmed = self.ip in self.addresses(name)
            except _Abort:
                continue
            if confirmed and (name == target or name.endswith("." + target)):
                return True
        return False


def check_host(resolver: Resolver, ip: str, domain: str, sender: str = "", helo: str = "") -> EvalResult:
    """Evaluate the SPF policy of ``domain`` for a message from ``ip``."""
    try:
        ev = _Evaluator(resolver, ip, sender or f"postmaster@{domain}", helo)
    except ValueError as exc:
        return EvalResult("permerror", domain, reason=f"invalid IP address: {exc}")
    try:
        result, term = ev.check_host(domain)
    except _Abort as exc:
        return EvalResult(exc.result, domain, None, exc.reason, ev.lookups, ev.voids, ev.trace)
    reason = f"matched '{term.raw}'" if term else ("no SPF record" if result == "none" else "no mechanism matched")
    return EvalResult(result, domain, term.raw if term else None, reason, ev.lookups, ev.voids, ev.trace)
