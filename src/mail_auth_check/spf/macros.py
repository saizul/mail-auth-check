"""SPF macro syntax and expansion (RFC 7208 section 7)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

__all__ = ["MacroContext", "MacroError", "expand", "validate_macro_string"]

_MACRO_RE = re.compile(r"%(?:\{([slodiphcrtvSLODIPHCRTV])(\d*)(r?)([.\-+,/_=]*)\}|%|_|-)")
_EXP_ONLY = set("crt")
MAX_DOMAIN_LENGTH = 253


class MacroError(ValueError):
    pass


def validate_macro_string(value: str, explanation: bool = False) -> None:
    """Raise ``MacroError`` for a '%' that does not start a valid macro."""
    pos = 0
    while True:
        idx = value.find("%", pos)
        if idx < 0:
            return
        m = _MACRO_RE.match(value, idx)
        if not m:
            raise MacroError(f"invalid macro at '{value[idx : idx + 12]}'")
        letter = m.group(1)
        if letter and letter.lower() in _EXP_ONLY and not explanation:
            raise MacroError(f"macro letter '{letter}' is only allowed in 'exp' explanations")
        if m.group(2) == "0":
            raise MacroError("a macro transformer of 0 is not allowed")
        pos = m.end()


@dataclass(frozen=True)
class MacroContext:
    ip: str
    domain: str
    sender: str = ""
    helo: str = ""
    validated_ptr: str = "unknown"
    receiver: str = "unknown"
    timestamp: int = 0

    def value(self, letter: str) -> str:
        letter = letter.lower()
        sender = self.sender or f"postmaster@{self.helo or self.domain}"
        local, _, sender_domain = sender.rpartition("@")
        if letter == "s":
            return sender
        if letter == "l":
            return local or "postmaster"
        if letter == "o":
            return sender_domain
        if letter == "d":
            return self.domain
        if letter == "i":
            addr = ipaddress.ip_address(self.ip)
            if addr.version == 6:
                return ".".join(addr.exploded.replace(":", ""))
            return str(addr)
        if letter == "c":
            return str(ipaddress.ip_address(self.ip))
        if letter == "p":
            return self.validated_ptr
        if letter == "v":
            return "ip6" if ipaddress.ip_address(self.ip).version == 6 else "in-addr"
        if letter == "h":
            return self.helo or self.domain
        if letter == "r":
            return self.receiver
        if letter == "t":
            return str(self.timestamp)
        raise MacroError(f"unknown macro letter {letter!r}")  # pragma: no cover - regex limits letters


def _transform(value: str, digits: str, reverse: str, delimiters: str) -> str:
    delims = delimiters or "."
    parts = re.split("[" + re.escape(delims) + "]", value)
    if reverse:
        parts.reverse()
    if digits:
        n = int(digits)
        parts = parts[-n:] if n < len(parts) else parts
    return ".".join(parts)


def expand(value: str, ctx: MacroContext, is_domain: bool = True) -> str:
    """Expand a macro-string. Upper-case letters are URL-escaped (7.3). Domains longer than 253 characters lose
    labels from the left (7.3)."""
    validate_macro_string(value, explanation=not is_domain)

    def repl(m: re.Match[str]) -> str:
        token = m.group(0)
        if token == "%%":
            return "%"
        if token == "%_":
            return " "
        if token == "%-":
            return "%20"
        letter = m.group(1)
        out = _transform(ctx.value(letter), m.group(2), m.group(3), m.group(4))
        if letter.isupper():
            from urllib.parse import quote

            out = quote(out, safe="-._~")
        return out

    result = _MACRO_RE.sub(repl, value)
    if is_domain:
        result = result.rstrip(".")
        while len(result) > MAX_DOMAIN_LENGTH and "." in result:
            result = result.split(".", 1)[1]
    return result
