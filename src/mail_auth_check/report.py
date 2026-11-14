"""Text, JSON and Markdown output."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone

from ._version import __version__
from .model import DomainReport

__all__ = ["FORMATS", "render", "render_json", "render_markdown", "render_text"]

_MARK = {"ok": "PASS", "info": "INFO", "warning": "WARN", "error": "FAIL"}
_MD_MARK = {"ok": "pass", "info": "info", "warning": "**warn**", "error": "**FAIL**"}


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(text: str) -> str:
    """Drop control characters (for example ANSI escapes inside a hostile TXT record)."""
    return _CONTROL.sub("?", text)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def render_text(reports: Sequence[DomainReport], verbose: bool = False, color: bool = False) -> str:
    colors = {"ok": "\033[32m", "info": "\033[36m", "warning": "\033[33m", "error": "\033[31m"}
    reset = "\033[0m"

    def tag(sev: str) -> str:
        label = _MARK[sev]
        return f"{colors[sev]}{label}{reset}" if color else label

    out: list[str] = []
    for rep in reports:
        c = rep.counts()
        out.append(
            f"{rep.domain}: score {rep.score}/100 (grade {rep.grade}), {c['error']} error(s), {c['warning']} warning(s)"
        )
        for check in rep.checks:
            out.append("")
            score = f" {check.score:.0f}/{check.max_score:.0f}" if check.max_score else ""
            out.append(f"  {check.title} [{tag(check.status)}]{score}")
            for f in check.findings:
                if (
                    f.severity == "ok"
                    and not verbose
                    and check.status in ("warning", "error")
                    and check.name != "senders"
                ):
                    continue
                if f.severity == "info" and not verbose and f.code.endswith(".note"):
                    continue
                out.append(f"    {tag(f.severity)}  {_clean(f.message)}")
                if f.hint and f.severity in ("warning", "error"):
                    out.append(f"          fix: {_clean(f.hint)}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_json(reports: Sequence[DomainReport], generated_at: str | None = None, **_: object) -> str:
    doc = {
        "tool": "mail-auth-check",
        "version": __version__,
        "generatedAt": generated_at or _now(),
        "domains": [r.to_dict() for r in reports],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _md(text: str) -> str:
    return _clean(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(reports: Sequence[DomainReport], generated_at: str | None = None, **_: object) -> str:
    out = [
        "# Email authentication report",
        "",
        f"Generated {generated_at or _now()} by mail-auth-check {__version__}.",
        "",
    ]
    if len(reports) > 1:
        out += ["| Domain | Score | Grade | Errors | Warnings |", "| --- | ---: | :---: | ---: | ---: |"]
        for rep in reports:
            c = rep.counts()
            out.append(f"| {rep.domain} | {rep.score} | {rep.grade} | {c['error']} | {c['warning']} |")
        out.append("")
    for rep in reports:
        out += [f"## {rep.domain}: {rep.score}/100 (grade {rep.grade})", ""]
        out += ["| Check | Result | Points |", "| --- | --- | ---: |"]
        for check in rep.checks:
            pts = f"{check.score:.0f} / {check.max_score:.0f}" if check.max_score else "-"
            out.append(f"| {check.title} | {_MD_MARK[check.status]} | {pts} |")
        out.append("")
        fixes = [(c.title, f) for c in rep.checks for f in c.findings if f.severity in ("error", "warning")]
        if fixes:
            out += ["### What to fix", ""]
            for title, f in sorted(fixes, key=lambda x: x[1].severity != "error"):
                line = f"- {_MD_MARK[f.severity]} **{_md(title)}**: {_md(f.message)}"
                if f.hint:
                    line += f" *Fix:* {_md(f.hint)}"
                if f.reference:
                    line += f" ([ref]({f.reference}))"
                out.append(line)
            out.append("")
        out += ["### Details", ""]
        for check in rep.checks:
            out += [f"#### {check.title}", ""]
            for f in check.findings:
                out.append(f"- {_MD_MARK[f.severity]}: {_md(f.message)}")
            if not check.findings:
                out.append("- nothing to report")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


FORMATS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render(fmt: str, reports: Sequence[DomainReport], **kwargs: object) -> str:
    try:
        fn = FORMATS[fmt]
    except KeyError:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from None
    return fn(reports, **kwargs)  # type: ignore[operator]
