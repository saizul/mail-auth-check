"""MTA-STS (RFC 8461): the _mta-sts TXT record and the HTTPS policy file."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .util import parse_tag_list

__all__ = [
    "MAX_AGE_LIMIT",
    "MAX_POLICY_BYTES",
    "MtaStsPolicy",
    "MtaStsRecord",
    "mx_matches",
    "parse_policy",
    "parse_sts_record",
    "policy_url",
]

MAX_AGE_LIMIT = 31_557_600  # 3.2: maximum value of max_age
MAX_POLICY_BYTES = 64 * 1024  # 3.3: suggested maximum policy size
_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")


def policy_url(domain: str) -> str:
    return f"https://mta-sts.{domain}/.well-known/mta-sts.txt"


@dataclass
class MtaStsRecord:
    text: str
    id: str | None = None
    errors: list[str] = field(default_factory=list)


def parse_sts_record(text: str) -> MtaStsRecord:
    rec = MtaStsRecord(text)
    tags = parse_tag_list(text, lower_names=False)
    if not tags.order or tags.order[0] != "v" or tags.get("v") != "STSv1":
        rec.errors.append("the record must start with v=STSv1")
    rec.id = tags.get("id")
    if rec.id is None:
        rec.errors.append("the required id= field is missing")
    elif not _ID_RE.match(rec.id):
        rec.errors.append(f"id={rec.id} must be 1 to 32 letters and digits")
    rec.errors.extend(tags.errors)
    return rec


@dataclass
class MtaStsPolicy:
    text: str
    version: str | None = None
    mode: str | None = None
    max_age: int | None = None
    mx: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_policy(text: str) -> MtaStsPolicy:
    """Parse the key: value lines of a policy file (3.2). Lines may end in CRLF or LF."""
    pol = MtaStsPolicy(text)
    seen: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        if ":" not in line:
            pol.errors.append(f"line {lineno}: '{line}' is not 'key: value'")
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if key == "mx":
            if value:
                pol.mx.append(value.lower().rstrip("."))
            continue
        if key in seen:
            pol.warnings.append(f"'{key}' appears more than once; only the first is used")
            continue
        seen.add(key)
        if key == "version":
            pol.version = value
        elif key == "mode":
            pol.mode = value
        elif key == "max_age":
            if value.isdigit():
                pol.max_age = int(value)
            else:
                pol.errors.append(f"max_age '{value}' is not a non-negative integer")
    if pol.version != "STSv1":
        pol.errors.append("version must be STSv1")
    if pol.mode not in ("enforce", "testing", "none"):
        pol.errors.append(f"mode '{pol.mode}' must be enforce, testing or none")
    if pol.max_age is None:
        if not any("max_age" in e for e in pol.errors):
            pol.errors.append("max_age is missing")
    elif pol.max_age > MAX_AGE_LIMIT:
        pol.errors.append(f"max_age {pol.max_age} is above the maximum of {MAX_AGE_LIMIT}")
    if pol.mode in ("enforce", "testing") and not pol.mx:
        pol.errors.append("at least one mx: line is required unless mode is none")
    for pattern in pol.mx:
        labels = pattern.split(".")
        if any("*" in label for label in labels[1:]):
            pol.errors.append(f"mx pattern '{pattern}': only the left-most label may be a wildcard")
        elif "*" in labels[0] and labels[0] != "*":
            pol.errors.append(f"mx pattern '{pattern}': a wildcard must be a whole left-most label")
    return pol


def mx_matches(host: str, pattern: str) -> bool:
    """4.1: a ``*.`` pattern matches exactly one extra left-most label."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and "." not in host[: -len(suffix)] and len(host) > len(suffix)
    return host == pattern
