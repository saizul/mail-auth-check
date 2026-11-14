"""Small shared helpers: tag=value lists, domain names, organizational domains and an HTTPS fetcher."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from ._version import __version__

__all__ = [
    "USER_AGENT",
    "FetchResult",
    "Fetcher",
    "StaticFetcher",
    "TagList",
    "is_valid_hostname",
    "organizational_domain",
    "parse_tag_list",
    "urllib_fetcher",
]

USER_AGENT = f"mail-auth-check/{__version__} (+https://github.com/saizul/mail-auth-check)"

# Public suffixes with more than one label that are common enough to matter for the organizational-domain
# heuristic. This is not the full Public Suffix List; pass --org-domain when it guesses wrong.
# fmt: off
_MULTI_LABEL_SUFFIXES = frozenset((
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk", "nhs.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ed.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd", "ac.bd", "co.bd", "info.bd",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "co.id", "or.id", "ac.id", "go.id", "web.id",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "co.th", "in.th", "ac.th", "go.th", "or.th",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "co.ke", "or.ke", "ac.ke", "go.ke",
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
    "co.at", "or.at", "ac.at", "gv.at",
    "com.pl", "net.pl", "org.pl",
    "com.es", "org.es", "nom.es", "edu.es", "gob.es",
    "com.co", "net.co", "org.co", "edu.co", "gov.co",
    "com.pe", "net.pe", "org.pe", "gob.pe",
))
# fmt: on

_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


def is_valid_hostname(name: str) -> bool:
    name = name.rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def organizational_domain(domain: str) -> str:
    """Approximate the RFC 7489 organizational domain: the registrable domain under a public suffix."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass
class TagList:
    tags: dict[str, str] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.tags.get(name, default)

    def __contains__(self, name: str) -> bool:
        return name in self.tags


def parse_tag_list(text: str, lower_names: bool = True) -> TagList:
    """Parse ``tag=value; tag=value`` (RFC 6376 3.2 tag-list, also used by DMARC, BIMI, MTA-STS and TLS-RPT)."""
    out = TagList()
    for raw in text.split(";"):
        part = raw.strip()
        if not part:
            continue
        if "=" not in part:
            out.errors.append(f"'{part}' is not a tag=value pair")
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if lower_names:
            name = name.lower()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            out.errors.append(f"invalid tag name '{name}'")
            continue
        if name in out.tags:
            out.duplicates.append(name)
            continue
        out.tags[name] = value.strip()
        out.order.append(name)
    return out


@dataclass
class FetchResult:
    url: str
    status: int = 0
    content_type: str = ""
    body: bytes = b""
    error: str | None = None
    redirect_location: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status == 200


# A fetcher takes (url, timeout, max_bytes) and never raises: failures are reported in FetchResult.error.
Fetcher = Callable[[str, float, int], FetchResult]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def urllib_fetcher(url: str, timeout: float = 10.0, max_bytes: int = 64 * 1024) -> FetchResult:
    """HTTPS GET with certificate and host name verification and no redirects (RFC 8461 3.3 forbids following
    them for MTA-STS policies)."""
    if not url.lower().startswith("https://"):
        return FetchResult(url, error="only https:// URLs are fetched")
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes + 1)
            return FetchResult(
                url,
                resp.status,
                resp.headers.get("Content-Type", ""),
                body[:max_bytes],
                truncated=len(body) > max_bytes,
            )
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location") if exc.headers else None
        return FetchResult(url, exc.code, (exc.headers or {}).get("Content-Type", ""), b"", redirect_location=location)
    except ssl.SSLCertVerificationError as exc:
        return FetchResult(url, error=f"TLS certificate verification failed: {exc.verify_message or exc}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return FetchResult(url, error=f"TLS certificate verification failed: {reason.verify_message or reason}")
        return FetchResult(url, error=str(reason))


class StaticFetcher:
    """Answer HTTPS fetches from a mapping ``{url: {"status": 200, "content_type": "...", "body": "..."}}``.

    Used by tests and by ``--dns-data`` files that carry an ``"_http"`` section. Unknown URLs fail like an
    unreachable host.
    """

    def __init__(self, responses: dict[str, dict[str, object]] | None = None) -> None:
        self.responses = dict(responses or {})
        self.requests: list[str] = []

    def __call__(self, url: str, timeout: float = 10.0, max_bytes: int = 64 * 1024) -> FetchResult:
        self.requests.append(url)
        spec = self.responses.get(url)
        if spec is None:
            return FetchResult(url, error="connection refused")
        if spec.get("error"):
            return FetchResult(url, error=str(spec["error"]))
        body = spec.get("body", "")
        raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)  # type: ignore[arg-type]
        return FetchResult(
            url,
            int(spec.get("status", 200)),  # type: ignore[arg-type]
            str(spec.get("content_type", "text/plain")),
            raw[:max_bytes],
            redirect_location=spec.get("location"),  # type: ignore[arg-type]
            truncated=len(raw) > max_bytes,
        )
