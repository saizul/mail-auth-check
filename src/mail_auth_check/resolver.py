"""DNS access behind a small interface.

Every check asks a ``Resolver`` for records and gets a ``DnsAnswer`` back, never an exception. The default
implementation uses dnspython; ``StaticResolver`` answers from a dictionary (or a JSON file) and is what the tests and
the ``--dns-data`` option use.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

__all__ = [
    "SUPPORTED_TYPES",
    "DnsAnswer",
    "DnspythonResolver",
    "Resolver",
    "StaticResolver",
    "normalize_name",
]

SUPPORTED_TYPES = ("TXT", "MX", "A", "AAAA", "CNAME", "PTR")

# status values
OK = "ok"
NXDOMAIN = "nxdomain"
NODATA = "nodata"
ERROR = "error"


def normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


@dataclass(frozen=True)
class DnsAnswer:
    """``status`` is ``ok``, ``nxdomain``, ``nodata`` or ``error``.

    ``records`` holds strings for TXT (the character-strings of one record joined), A, AAAA, CNAME and PTR, and
    ``(preference, exchange)`` tuples for MX. Names never have a trailing dot.
    """

    name: str
    rdtype: str
    status: str
    records: tuple[Any, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == OK and bool(self.records)

    @property
    def is_void(self) -> bool:
        """RFC 7208 4.6.4: a lookup that returns no records (NXDOMAIN or an empty answer)."""
        return self.status in (NXDOMAIN, NODATA) or (self.status == OK and not self.records)

    @property
    def failed(self) -> bool:
        return self.status == ERROR


class Resolver(Protocol):
    def resolve(self, name: str, rdtype: str) -> DnsAnswer: ...


def _decode_txt(strings: Sequence[bytes]) -> str:
    raw = b"".join(strings)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


class DnspythonResolver:
    """Resolver built on ``dns.resolver``. Answers are cached for the life of the object."""

    def __init__(self, nameservers: Sequence[str] | None = None, timeout: float = 5.0, lifetime: float = 10.0) -> None:
        import dns.resolver

        self._dns = dns
        self._resolver = dns.resolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self.queries = 0

    def resolve(self, name: str, rdtype: str) -> DnsAnswer:
        import dns.exception
        import dns.resolver

        key = (normalize_name(name), rdtype.upper())
        if key in self._cache:
            return self._cache[key]
        self.queries += 1
        qname, qtype = key
        try:
            answer = self._resolver.resolve(qname + ".", qtype, raise_on_no_answer=True, search=False)
        except dns.resolver.NXDOMAIN:
            result = DnsAnswer(qname, qtype, NXDOMAIN)
        except dns.resolver.NoAnswer:
            result = DnsAnswer(qname, qtype, NODATA)
        except dns.resolver.NoNameservers as exc:
            result = DnsAnswer(qname, qtype, ERROR, error=f"SERVFAIL or refused: {exc}")
        except dns.exception.Timeout:
            result = DnsAnswer(qname, qtype, ERROR, error="timeout")
        except (dns.exception.DNSException, ValueError) as exc:
            result = DnsAnswer(qname, qtype, ERROR, error=str(exc) or type(exc).__name__)
        else:
            records: list[Any] = []
            for rr in answer:
                if qtype == "TXT":
                    records.append(_decode_txt(rr.strings))
                elif qtype == "MX":
                    records.append((int(rr.preference), normalize_name(rr.exchange.to_text())))
                elif qtype in ("CNAME", "PTR"):
                    records.append(normalize_name(rr.target.to_text()))
                else:
                    records.append(rr.to_text())
            result = DnsAnswer(qname, qtype, OK, tuple(records))
        self._cache[key] = result
        return result


@dataclass
class StaticResolver:
    """Answer from a mapping ``{name: {TYPE: [records]}}``.

    * a name that is missing is NXDOMAIN; a name without the asked type is NODATA
    * ``*.example.com`` entries act as wildcards for missing names below example.com
    * ``{"CNAME": ["target"]}`` is followed for other types, like a recursive resolver would
    * ``{"error": "SERVFAIL"}`` (for the whole name) or ``{"TXT": {"error": "timeout"}}`` simulates a failure
    * MX records are ``[preference, "exchange"]`` pairs; TXT records may be a list of strings (they are joined)
    """

    zones: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    queries: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.zones = {normalize_name(k): dict(v) for k, v in self.zones.items()}

    @classmethod
    def from_file(cls, path: str | Path) -> StaticResolver:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a JSON object of names")
        return cls(data)

    def resolve(self, name: str, rdtype: str, _depth: int = 0) -> DnsAnswer:
        qname, qtype = normalize_name(name), rdtype.upper()
        if _depth == 0:
            self.queries.append((qname, qtype))
        node = self.zones.get(qname)
        if node is None:
            # Wildcards (RFC 4592, simplified): the closest "*.<ancestor>" answers for a missing name.
            labels = qname.split(".")
            for i in range(1, len(labels)):
                node = self.zones.get("*." + ".".join(labels[i:]))
                if node is not None:
                    break
        if node is None:
            return DnsAnswer(qname, qtype, NXDOMAIN)
        if "error" in node:
            return DnsAnswer(qname, qtype, ERROR, error=str(node["error"]))
        if qtype != "CNAME" and "CNAME" in node and qtype not in node:
            if _depth > 8:
                return DnsAnswer(qname, qtype, ERROR, error="CNAME loop")
            target = node["CNAME"][0] if isinstance(node["CNAME"], list) else node["CNAME"]
            followed = self.resolve(str(target), qtype, _depth + 1)
            return DnsAnswer(qname, qtype, followed.status, followed.records, followed.error)
        value = node.get(qtype)
        if value is None:
            return DnsAnswer(qname, qtype, NODATA)
        if isinstance(value, dict) and "error" in value:
            return DnsAnswer(qname, qtype, ERROR, error=str(value["error"]))
        if isinstance(value, str):
            value = [value]
        records: list[Any] = []
        for item in value:
            if qtype == "TXT":
                records.append("".join(item) if isinstance(item, list) else str(item))
            elif qtype == "MX":
                records.append((int(item[0]), normalize_name(str(item[1]))))
            elif qtype in ("CNAME", "PTR"):
                records.append(normalize_name(str(item)))
            else:
                records.append(str(item))
        if not records:
            return DnsAnswer(qname, qtype, NODATA)
        return DnsAnswer(qname, qtype, OK, tuple(records))
