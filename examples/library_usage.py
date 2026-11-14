"""Use mail-auth-check as a library.

Runs offline against examples/dns-example.json. Replace StaticResolver with DnspythonResolver() (and pass
fetcher=urllib_fetcher) to check real domains.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mail_auth_check import StaticResolver, analyze_spf, audit_domain, check_host, render
from mail_auth_check.util import StaticFetcher

HERE = Path(__file__).resolve().parent


def main() -> int:
    resolver = StaticResolver.from_file(HERE / "dns-example.json")
    fetcher = StaticFetcher(resolver.zones["_http"])  # the fake HTTPS responses in the same file

    # Full audit
    report = audit_domain("example.com", resolver, fetcher=fetcher, selectors=["selector1"])
    print(f"{report.domain}: {report.score}/100 ({report.grade})")

    # SPF details: lookup count across includes, and evaluation for one sending IP
    spf = analyze_spf(resolver, "broken.example")
    print(f"broken.example SPF needs {spf.total_lookups} lookups ({spf.total_void} void)")
    result = check_host(resolver, "198.51.100.20", "example.com")
    print(f"198.51.100.20 for example.com: {result.result} ({result.reason})")

    sys.stdout.write(render("markdown", [report]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
