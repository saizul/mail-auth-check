"""Command-line interface."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from ._version import __version__
from .audit import ALL_CHECKS, audit_domain
from .model import DomainReport
from .report import FORMATS, _clean, render
from .resolver import DnspythonResolver, Resolver, StaticResolver
from .spf.flatten import DEFAULT_MAX_LENGTH, FlattenResult, flatten_spf, split_txt
from .util import Fetcher, StaticFetcher, urllib_fetcher

__all__ = [
    "EXIT_DNS",
    "EXIT_FAIL",
    "EXIT_OK",
    "EXIT_USAGE",
    "build_flatten_parser",
    "build_parser",
    "exit_code",
    "flatten_main",
    "main",
    "render_flatten",
]

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_DNS = 3


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mail-auth-check",
        description="Check SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, MX and the Gmail/Yahoo sender requirements "
        "of a domain.",
        epilog="Run 'mail-auth-check flatten-spf --help' to build a flattened SPF record.",
    )
    p.add_argument("domains", nargs="*", help="domain(s) to check")
    p.add_argument("--domains-file", help="file with one domain per line")
    p.add_argument("--selector", "-s", action="append", default=[], help="DKIM selector to check (repeatable)")
    p.add_argument("--no-common-selectors", action="store_true", help="only try the selectors given with -s")
    p.add_argument("--ip", action="append", default=[], help="sending IP: evaluate SPF and reverse DNS for it")
    p.add_argument("--headers", help="file with the headers (or full source) of a message sent from the domain")
    p.add_argument("--checks", type=_csv, help=f"comma-separated subset: {', '.join([*ALL_CHECKS, 'senders'])}")
    p.add_argument("--org-domain", help="override the organizational domain guess (for DMARC)")
    p.add_argument("--not-bulk", action="store_true", help="report bulk-sender-only requirements as warnings")
    p.add_argument("--format", "-f", choices=sorted(FORMATS), default="text")
    p.add_argument("--output", "-o", help="write the report to this file")
    p.add_argument("--verbose", "-v", action="store_true", help="show passing findings and notes in text output")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.add_argument("--no-http", action="store_true", help="do not fetch the MTA-STS policy or the BIMI logo")
    p.add_argument("--nameserver", action="append", default=[], help="DNS server to query (repeatable)")
    p.add_argument("--dns-data", help="answer DNS from this JSON file instead of the network (offline mode)")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS and HTTP timeout in seconds")
    p.add_argument("--fail-under", type=int, help="exit 1 if a domain scores below this")
    p.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def exit_code(reports: Sequence[DomainReport], fail_under: int | None = None, strict: bool = False) -> int:
    if any(r.dns_failure for r in reports):
        return EXIT_DNS
    for r in reports:
        if r.status == "error" or (strict and r.status == "warning"):
            return EXIT_FAIL
        if fail_under is not None and r.score < fail_under:
            return EXIT_FAIL
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    resolver: Resolver | None = None,
    fetcher: Fetcher | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "flatten-spf":
        return flatten_main(argv[1:], resolver=resolver, stdout=stdout, stderr=stderr)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    domains = list(args.domains)
    try:
        if args.domains_file:
            for line in Path(args.domains_file).read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    domains.append(line)
        if not domains:
            print("error: give at least one domain", file=stderr)
            return EXIT_USAGE
        headers_text = Path(args.headers).read_text(encoding="utf-8", errors="replace") if args.headers else None
        if resolver is None:
            if args.dns_data:
                resolver = StaticResolver.from_file(args.dns_data)
                if fetcher is None:
                    http = getattr(resolver, "zones", {}).get("_http")
                    fetcher = StaticFetcher(http.get("responses", http) if isinstance(http, dict) else {})
            else:
                resolver = DnspythonResolver(args.nameserver or None, timeout=args.timeout, lifetime=args.timeout * 2)
        if args.no_http:
            fetcher = None
        elif fetcher is None:
            fetcher = urllib_fetcher
        reports = [
            audit_domain(
                d,
                resolver,
                fetcher=fetcher,
                selectors=args.selector,
                common_selectors=not args.no_common_selectors,
                sending_ips=args.ip,
                headers_text=headers_text,
                only=args.checks,
                org_domain=args.org_domain,
                bulk_sender=not args.not_bulk,
                timeout=args.timeout,
            )
            for d in domains
        ]
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=stderr)
        return EXIT_USAGE
    if args.format == "text":
        use_color = args.color == "always" or (
            args.color == "auto" and not args.output and stdout.isatty() and not os.environ.get("NO_COLOR")
        )
        text = render("text", reports, verbose=args.verbose, color=use_color)
    else:
        text = render(args.format, reports)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        stdout.write(text)
    return exit_code(reports, args.fail_under, args.strict)


# -- flatten-spf -------------------------------------------------------------------------------------------------------


def build_flatten_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mail-auth-check flatten-spf",
        description="Replace the include, a and mx terms of an SPF record with the ip4:/ip6: ranges they resolve to, "
        "so that the policy fits in the limit of 10 DNS lookups. Prints the records to publish; nothing is changed.",
    )
    p.add_argument("domain", help="domain whose SPF record to flatten")
    p.add_argument(
        "--keep",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="leave include:DOMAIN (or redirect=DOMAIN) as it is (repeatable, comma-separated)",
    )
    p.add_argument(
        "--max-length",
        type=int,
        default=DEFAULT_MAX_LENGTH,
        help=f"longest record before splitting into chained includes (default {DEFAULT_MAX_LENGTH})",
    )
    p.add_argument("--label", default="_spf", help="name prefix of the chained records: <label>1.<domain>, ...")
    p.add_argument("--ttl", type=int, default=3600, help="TTL in the zone-file lines (default 3600)")
    p.add_argument("--ip", action="append", default=[], help="also compare the old and new policy for this IP")
    p.add_argument("--no-verify", action="store_true", help="skip the old/new check_host() comparison")
    p.add_argument("--format", "-f", choices=("text", "json", "zone"), default="text")
    p.add_argument("--output", "-o", help="write the result to this file")
    p.add_argument("--nameserver", action="append", default=[], help="DNS server to query (repeatable)")
    p.add_argument("--dns-data", help="answer DNS from this JSON file instead of the network (offline mode)")
    p.add_argument("--timeout", type=float, default=5.0, help="DNS timeout in seconds")
    return p


def _zone_lines(result: FlattenResult, ttl: int) -> list[str]:
    lines = []
    for name, value in result.records.items():
        strings = " ".join('"' + part.replace("\\", "\\\\").replace('"', '\\"') + '"' for part in split_txt(value))
        lines.append(f"{name}. {ttl} IN TXT {strings}")
    return lines


def render_flatten(result: FlattenResult, fmt: str = "text", ttl: int = 3600) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2) + "\n"
    if fmt == "zone":
        return "\n".join(_zone_lines(result, ttl)) + ("\n" if result.records else "")
    out = [f"SPF flattening for {result.domain}: {result.status}"]
    if result.original is not None:
        out.append(f"  original ({result.original_lookups} lookups): {_clean(result.original)}")
    if result.records:
        out.append(f"  proposed ({result.lookups} lookups, {len(result.ip4)} ip4 and {len(result.ip6)} ip6 ranges):")
        out.extend("    " + _clean(line) for line in _zone_lines(result, ttl))
    if result.flattened:
        out.append("  flattened:")
        out.extend(f"    {_clean(t)}" for t in result.flattened)
    if result.kept:
        out.append("  kept: " + _clean(" ".join(result.kept)))
    for label, items in (("error", result.errors), ("warning", result.warnings), ("note", result.notes)):
        out.extend(f"  {label}: {_clean(item)}" for item in items)
    if result.verification:
        checked = [v for v in result.verification if v["match"] != "n/a"]
        same = sum(1 for v in checked if v["match"] == "yes")
        out.append(f"  verified: {same} of {len(checked)} sample addresses give the same result")
        skipped = len(result.verification) - len(checked)
        if skipped:
            out.append(f"  {skipped} sample(s) not compared: the original policy returns permerror or temperror")
    if result.records and result.status != "error":
        out.append("  Ranges are a snapshot: rebuild the record when your providers change their addresses.")
    return "\n".join(out) + "\n"


def flatten_main(
    argv: Sequence[str],
    resolver: Resolver | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        args = build_flatten_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    keep = [k for value in args.keep for k in _csv(value)]
    try:
        if resolver is None:
            if args.dns_data:
                resolver = StaticResolver.from_file(args.dns_data)
            else:
                resolver = DnspythonResolver(args.nameserver or None, timeout=args.timeout, lifetime=args.timeout * 2)
        domain = args.domain.strip().rstrip(".").lower()
        if "." not in domain or any(c in domain for c in " /@:"):
            raise ValueError(f"'{args.domain}' is not a valid domain")
        for ip in args.ip:
            ipaddress.ip_address(ip)
        result = flatten_spf(
            resolver,
            domain,
            keep=keep,
            max_length=args.max_length,
            label=args.label,
            verify=not args.no_verify,
            sample_ips=args.ip,
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=stderr)
        return EXIT_USAGE
    text = render_flatten(result, args.format, args.ttl)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        stdout.write(text)
    if result.dns_failure:
        return EXIT_DNS
    return EXIT_FAIL if result.status == "error" else EXIT_OK
