"""Check the email authentication setup of a domain: SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT and MX."""

from ._version import __version__
from .audit import ALL_CHECKS, audit_domain, grade_for
from .dkim import COMMON_SELECTORS, parse_dkim_record
from .dmarc import parse_dmarc
from .model import CheckResult, DomainReport, Finding
from .mta_sts import parse_policy, parse_sts_record
from .report import render
from .resolver import DnsAnswer, DnspythonResolver, Resolver, StaticResolver
from .spf import FlattenResult, check_host, flatten_spf, parse_record
from .spf import analyze as analyze_spf
from .util import FetchResult, organizational_domain, urllib_fetcher

__all__ = [
    "ALL_CHECKS",
    "COMMON_SELECTORS",
    "CheckResult",
    "DnsAnswer",
    "DnspythonResolver",
    "DomainReport",
    "FetchResult",
    "FlattenResult",
    "Finding",
    "Resolver",
    "StaticResolver",
    "__version__",
    "analyze_spf",
    "audit_domain",
    "check_host",
    "flatten_spf",
    "grade_for",
    "organizational_domain",
    "parse_dkim_record",
    "parse_dmarc",
    "parse_policy",
    "parse_record",
    "parse_sts_record",
    "render",
    "urllib_fetcher",
]
