"""SPF (RFC 7208): parsing, macro expansion, lookup counting and check_host() evaluation."""

from .evaluate import (
    LOOKUP_LIMIT,
    MX_LIMIT,
    VOID_LIMIT,
    EvalResult,
    SpfAnalysis,
    SpfNode,
    analyze,
    check_host,
    fetch_spf,
)
from .flatten import FlattenResult, OverlayResolver, flatten_spf
from .macros import MacroContext, MacroError, expand, validate_macro_string
from .parser import DNS_MECHANISMS, MECHANISMS, QUALIFIERS, SpfRecord, Term, is_spf_record, parse_record, select_records

__all__ = [
    "DNS_MECHANISMS",
    "LOOKUP_LIMIT",
    "MECHANISMS",
    "MX_LIMIT",
    "QUALIFIERS",
    "VOID_LIMIT",
    "EvalResult",
    "FlattenResult",
    "MacroContext",
    "MacroError",
    "OverlayResolver",
    "SpfAnalysis",
    "SpfNode",
    "SpfRecord",
    "Term",
    "analyze",
    "check_host",
    "expand",
    "fetch_spf",
    "flatten_spf",
    "is_spf_record",
    "parse_record",
    "select_records",
    "validate_macro_string",
]
