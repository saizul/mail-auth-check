"""SPF flattening: replace includes, ``a`` and ``mx`` terms with the ip4:/ip6: ranges they resolve to.

A policy that needs more than 10 DNS lookups is a permerror (RFC 7208 4.6.4). ``flatten_spf()`` walks the policy of a
domain, resolves every term it can safely replace, merges the resulting networks and builds a new record (split into
a chain of ``include:_spfN.<domain>`` records when it would be too long for one TXT answer). Terms that depend on the
message (macros, ``exists``, ``ptr``) and includes listed in ``keep`` are left as they are.

The proposed records are then checked: the lookup count is computed by ``analyze()`` against the original DNS data
with the new records laid over it, and ``check_host()`` is run for a sample of addresses against the old and the new
policy to confirm that both give the same result.

Flattened ranges are a snapshot. Providers change their sending addresses, so a flattened record must be rebuilt
regularly (for example from a scheduled job); ``keep`` lets you flatten only the includes you control.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..resolver import DnsAnswer, Resolver, normalize_name
from .evaluate import LOOKUP_LIMIT, MX_LIMIT, analyze, check_host, fetch_spf
from .parser import SpfRecord, Term, parse_record

__all__ = [
    "DEFAULT_MAX_LENGTH",
    "FlattenResult",
    "OverlayResolver",
    "flatten_spf",
    "split_txt",
]

# Keeps the whole answer comfortably inside a 512-byte UDP response together with the other TXT records.
DEFAULT_MAX_LENGTH = 450
MIN_MAX_LENGTH = 64
MAX_SAMPLES = 256

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class _Unflattenable(Exception):
    """Raised inside an include whose content cannot be replaced by address ranges."""


class _Fatal(Exception):
    def __init__(self, reason: str, dns_failure: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.dns_failure = dns_failure


@dataclass
class FlattenResult:
    domain: str
    status: str = "ok"  # ok, unchanged or error
    original: str | None = None
    original_lookups: int = 0
    records: dict[str, str] = field(default_factory=dict)  # name -> SPF record, the domain itself first
    lookups: int = 0
    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)  # terms copied unchanged
    flattened: list[str] = field(default_factory=list)  # terms replaced by ranges
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    verification: list[dict[str, str]] = field(default_factory=list)
    dns_failure: bool = False

    @property
    def ok(self) -> bool:
        return self.status != "error"

    @property
    def mismatches(self) -> list[dict[str, str]]:
        return [v for v in self.verification if v.get("match") == "no"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status,
            "original": self.original,
            "originalLookups": self.original_lookups,
            "lookups": self.lookups,
            "lookupLimit": LOOKUP_LIMIT,
            "records": [{"name": n, "value": v, "length": len(v)} for n, v in self.records.items()],
            "ip4": self.ip4,
            "ip6": self.ip6,
            "flattened": self.flattened,
            "kept": self.kept,
            "notes": self.notes,
            "warnings": self.warnings,
            "errors": self.errors,
            "verification": self.verification,
        }


class OverlayResolver:
    """Answer SPF TXT queries for some names from a mapping and everything else from another resolver.

    For a name in ``spf`` the SPF records of the real answer are replaced and its other TXT records are kept, which is
    what publishing the new record would do.
    """

    def __init__(self, base: Resolver, spf: Mapping[str, str]) -> None:
        self.base = base
        self.spf = {normalize_name(k): v for k, v in spf.items()}

    def resolve(self, name: str, rdtype: str) -> DnsAnswer:
        qname, qtype = normalize_name(name), rdtype.upper()
        if qtype != "TXT" or qname not in self.spf:
            return self.base.resolve(name, rdtype)
        real = self.base.resolve(name, rdtype)
        others = [] if real.status != "ok" else [r for r in real.records if not str(r).lower().startswith("v=spf1")]
        return DnsAnswer(qname, "TXT", "ok", (self.spf[qname], *others))


def split_txt(value: str, size: int = 255) -> list[str]:
    """Split a TXT value into character-strings of at most ``size`` bytes (RFC 1035 3.3.14)."""
    raw = value.encode("utf-8")
    return [raw[i : i + size].decode("utf-8", "replace") for i in range(0, len(raw), size)] or [""]


def _net_term(net: Network) -> str:
    if net.version == 4:
        return f"ip4:{net.network_address}" if net.prefixlen == 32 else f"ip4:{net}"
    return f"ip6:{net.network_address}" if net.prefixlen == 128 else f"ip6:{net}"


class _Collector:
    def __init__(self, resolver: Resolver, keep: set[str]) -> None:
        self.resolver = resolver
        self.keep = keep
        self.nets: list[Network] = []
        self.before: list[str] = []  # kept terms that come before the first flattened term
        self.after: list[str] = []  # kept terms that come after it
        self.flattened: list[str] = []
        self.notes: list[str] = []
        self.warnings: list[str] = []
        self.all_term: str | None = None
        self.redirect: str | None = None
        self.exp: str | None = None
        self.negative_after_flat = False

    # -- helpers ---------------------------------------------------------------------------------------------------

    def _query(self, name: str, rdtype: str) -> DnsAnswer:
        ans = self.resolver.resolve(name, rdtype)
        if ans.failed:
            raise _Fatal(f"DNS error for {rdtype} {name}: {ans.error}", dns_failure=True)
        return ans

    def _addresses(self, name: str, term: Term, raw: str) -> list[Network]:
        nets: list[Network] = []
        for rdtype, length, bits in (("A", term.cidr4, 32), ("AAAA", term.cidr6, 128)):
            ans = self._query(name, rdtype)
            if ans.status != "ok":
                continue
            for rec in ans.records:
                prefix = bits if length is None else length
                nets.append(ipaddress.ip_network(f"{rec}/{prefix}", strict=False))
        if not nets:
            self.notes.append(f"'{raw}': {name} has no A/AAAA records, nothing to add")
        return nets

    def _keep(self, raw: str, top: bool) -> None:
        if not top:
            raise _Unflattenable(raw)
        (self.after if self.flattened else self.before).append(raw)
        if self.flattened and raw[0] in "-~?":
            self.negative_after_flat = True

    # -- walk ------------------------------------------------------------------------------------------------------

    def load(self, domain: str, via: str) -> SpfRecord:
        status, text, records, answer = fetch_spf(self.resolver, domain)
        if status == "temperror":
            raise _Fatal(f"TXT lookup for {domain} failed: {answer.error}", dns_failure=True)
        if status == "none":
            raise _Fatal(f"{via}{domain} has no SPF record")
        if status == "permerror":
            raise _Fatal(f"{domain} publishes {len(records)} SPF records; exactly one is allowed")
        record = parse_record(text or "")
        if record.errors:
            raise _Fatal(f"{domain}: {record.errors[0]}")
        return record

    def walk(self, domain: str, record: SpfRecord, top: bool, chain: tuple[str, ...]) -> None:
        """Collect ``record``. ``top`` is true for the domain itself and its redirect chain."""
        for term in record.mechanisms:
            if term.name == "all":
                if top:
                    self.all_term = term.raw
                elif term.qualifier == "+":
                    # An include ending in +all matches every address: it cannot become a list of ranges.
                    raise _Unflattenable(term.raw)
                return
            self.term(domain, term, top, chain)
        exp = record.modifier("exp")
        if top and exp is not None and self.exp is None:
            self.exp = exp.raw
        for t in record.terms:
            if t.kind == "modifier" and t.name not in ("redirect", "exp"):
                self.notes.append(f"{domain}: unknown modifier '{t.raw}' dropped")
        redirect = record.redirect
        if redirect is None:
            return
        target = redirect.value or ""
        if redirect.has_macro or normalize_name(target) in self.keep:
            if not top:
                raise _Unflattenable(redirect.raw)
            self.redirect = redirect.raw
            return
        if normalize_name(target) in chain:
            raise _Fatal(f"redirect loop: {' -> '.join((*chain, normalize_name(target)))}")
        child = self.load(target, "redirect=")
        self.flattened.append(f"{domain}: {redirect.raw}")
        self.walk(target, child, top, (*chain, normalize_name(target)))

    def term(self, domain: str, term: Term, top: bool, chain: tuple[str, ...]) -> None:
        raw = term.raw
        if term.qualifier != "+":
            if top:
                self._keep(raw, top)
            else:
                # An include only passes for its "+" mechanisms; other results fall through to the parent. The
                # addresses such a term excludes are simply not added.
                self.notes.append(f"{domain}: '{raw}' does not authorize anything and was left out")
            return
        if term.name in ("ip4", "ip6"):
            length = term.cidr4 if term.name == "ip4" else term.cidr6
            bits = 32 if term.name == "ip4" else 128
            net = ipaddress.ip_network(f"{term.value}/{bits if length is None else length}", strict=False)
            if str(net.network_address) != term.value and length is not None:
                self.notes.append(f"{domain}: '{raw}' has host bits set; written as {_net_term(net)}")
            self.nets.append(net)
            if top:
                self.flattened.append(f"{domain}: {raw}")
            return
        if term.has_macro or term.name in ("exists", "ptr"):
            if top:
                self.notes.append(f"'{raw}' depends on the message and is kept as it is")
            self._keep(raw, top)
            return
        target = term.value or domain
        if term.name == "include":
            name = normalize_name(target)
            if name in self.keep:
                self._keep(raw, top)
                return
            if name in chain:
                raise _Fatal(f"include loop: {' -> '.join((*chain, name))}")
            child_record = self.load(target, "include:")
            sub = _Collector(self.resolver, self.keep)
            try:
                sub.walk(target, child_record, False, (*chain, name))
            except _Unflattenable as exc:
                if not top:
                    raise
                self.warnings.append(
                    f"include:{target} contains '{exc}', which cannot be replaced by address ranges; it is kept"
                )
                self._keep(raw, top)
                return
            self.nets.extend(sub.nets)
            self.notes.extend(sub.notes)
            self.flattened.append(f"{domain}: {raw}")
            return
        if term.name == "a":
            self.nets.extend(self._addresses(target, term, raw))
        elif term.name == "mx":
            ans = self._query(target, "MX")
            hosts = [h for _, h in sorted(ans.records) if h] if ans.status == "ok" else []
            if len(hosts) > MX_LIMIT:
                raise _Fatal(f"'{raw}' at {domain}: {target} has {len(hosts)} MX hosts; the limit is {MX_LIMIT}")
            if not hosts:
                self.notes.append(f"'{raw}': {target} has no MX records, nothing to add")
            for host in hosts:
                self.nets.extend(self._addresses(host, term, raw))
        if top:
            self.flattened.append(f"{domain}: {raw}")


def _pack(terms: Sequence[str], max_length: int, prefix: str = "v=spf1", suffix: str = "") -> list[list[str]]:
    """Group terms so that ``prefix + terms + suffix`` stays within ``max_length`` characters."""
    chunks: list[list[str]] = []
    current: list[str] = []
    size = len(prefix) + (len(suffix) + 1 if suffix else 0)
    for term in terms:
        if current and size + 1 + len(term) > max_length:
            chunks.append(current)
            current, size = [], len(prefix) + (len(suffix) + 1 if suffix else 0)
        current.append(term)
        size += 1 + len(term)
    if current:
        chunks.append(current)
    return chunks


def _join(*parts: Iterable[str]) -> str:
    return " ".join(["v=spf1", *(p for group in parts for p in group)])


def _samples(nets: Sequence[Network], extra: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for ip in extra:
        seen.setdefault(ip, None)
    for net in nets:
        seen.setdefault(str(net.network_address), None)
        if net.num_addresses > 1:
            seen.setdefault(str(net.broadcast_address), None)
    # Addresses next to the authorized ranges should not start passing.
    for net in nets:
        if net.version == 4 and int(net.broadcast_address) < 2**32 - 1:
            seen.setdefault(str(net.broadcast_address + 1), None)
    return list(seen)[:MAX_SAMPLES]


def flatten_spf(
    resolver: Resolver,
    domain: str,
    *,
    keep: Iterable[str] = (),
    max_length: int = DEFAULT_MAX_LENGTH,
    label: str = "_spf",
    verify: bool = True,
    sample_ips: Iterable[str] = (),
) -> FlattenResult:
    """Build a flattened SPF policy for ``domain``.

    ``keep`` lists include (or redirect) domains to leave unchanged, ``max_length`` is the longest record to propose
    before splitting into ``<label>1.<domain>``, ``<label>2.<domain>``, ... and ``sample_ips`` adds addresses to the
    old/new comparison.
    """
    domain = normalize_name(domain)
    result = FlattenResult(domain)
    if max_length < MIN_MAX_LENGTH:
        raise ValueError(f"max_length must be at least {MIN_MAX_LENGTH}")
    if not label or not all(part and len(part) <= 60 for part in label.split(".")):
        raise ValueError(f"invalid label '{label}'")
    keep_set = {normalize_name(k) for k in keep if k.strip()}

    before = analyze(resolver, domain)
    result.original = before.root.text
    result.original_lookups = before.total_lookups
    collector = _Collector(resolver, keep_set)
    try:
        record = collector.load(domain, "")
        collector.walk(domain, record, True, (domain,))
    except _Fatal as exc:
        result.status = "error"
        result.errors.append(exc.reason)
        result.dns_failure = exc.dns_failure
        return result

    nets4 = list(ipaddress.collapse_addresses(n for n in collector.nets if n.version == 4))
    nets6 = list(ipaddress.collapse_addresses(n for n in collector.nets if n.version == 6))
    nets: list[Network] = [*nets4, *nets6]
    result.ip4 = [str(n) for n in nets4]
    result.ip6 = [str(n) for n in nets6]
    result.kept = [*collector.before, *collector.after]
    result.flattened = collector.flattened
    result.notes = collector.notes
    result.warnings = collector.warnings
    if collector.negative_after_flat:
        result.warnings.append(
            "a non-pass term comes after terms that were flattened; the ranges are placed before it, so check that "
            "the order still gives the result you want"
        )
    if collector.all_term in ("+all", "all", "?all"):
        result.warnings.append(f"the policy ends with '{collector.all_term}', which does not reject other senders")
    for net in nets:
        if (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 32):
            result.warnings.append(f"{_net_term(net)} is a very large range")

    tail: list[str] = []
    if collector.redirect:
        tail.append(collector.redirect)
    elif collector.all_term:
        tail.append(collector.all_term)
    if collector.exp:
        tail.append(collector.exp)
    terms = [_net_term(n) for n in nets]
    single = _join(collector.before, terms, collector.after, tail)
    records: dict[str, str] = {}
    if len(single) <= max_length:
        records[domain] = single
    else:
        fixed = len(_join(collector.before, collector.after, tail))
        chunks = _pack(terms, max_length, suffix="-all")
        includes = [f"include:{label}{i}.{domain}" for i in range(1, len(chunks) + 1)]
        root = _join(collector.before, includes, collector.after, tail)
        if len(root) > max_length:
            result.warnings.append(
                f"the record for {domain} is {len(root)} characters even with every range moved out "
                f"({fixed} without the includes)"
            )
        records[domain] = root
        for i, chunk in enumerate(chunks, 1):
            name = f"{label}{i}.{domain}"
            if resolver.resolve(name, "TXT").status == "ok":
                result.notes.append(f"{name} already has TXT records; its SPF record will be replaced")
            records[name] = _join(chunk, ["-all"])
    result.records = records

    overlay = OverlayResolver(resolver, records)
    after = analyze(overlay, domain)
    result.lookups = after.total_lookups
    if after.over_lookup_limit:
        result.status = "error"
        result.errors.append(
            f"the flattened policy still needs {after.total_lookups} DNS lookups (limit {LOOKUP_LIMIT}); "
            "flatten some of the kept includes or remove senders"
        )
    if after.errors:
        result.status = "error"
        result.errors.extend(after.errors)
    if result.status != "error" and records.get(domain) == (result.original or "").strip() and len(records) == 1:
        result.status = "unchanged"
        result.notes.append("nothing to flatten: the record already lists only ranges and kept terms")

    if verify:
        for ip in _samples(nets, sample_ips):
            old = check_host(resolver, ip, domain)
            new = check_host(overlay, ip, domain)
            row = {"ip": ip, "original": old.result, "flattened": new.result}
            if old.result in ("permerror", "temperror"):
                row["match"] = "n/a"
            else:
                row["match"] = "yes" if old.result == new.result else "no"
            result.verification.append(row)
        for row in result.mismatches:
            result.status = "error"
            result.errors.append(
                f"{row['ip']}: the original policy gives {row['original']}, the flattened one {row['flattened']}"
            )
    return result
