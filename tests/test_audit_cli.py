from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import good_fetcher, good_zone
from mail_auth_check import __version__, audit_domain, grade_for, render
from mail_auth_check.cli import EXIT_DNS, EXIT_FAIL, EXIT_OK, EXIT_USAGE, main
from mail_auth_check.resolver import StaticResolver

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run(argv, zones=None, fetcher=None):
    out, err = io.StringIO(), io.StringIO()
    resolver = StaticResolver(zones) if zones is not None else None
    code = main(argv, resolver=resolver, fetcher=fetcher, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_audit_good_domain_scores_high():
    rep = audit_domain("Example.COM.", StaticResolver(good_zone()), fetcher=good_fetcher())
    assert rep.domain == "example.com"
    assert [c.name for c in rep.checks] == ["mx", "spf", "dkim", "dmarc", "mta_sts", "tlsrpt", "bimi", "senders"]
    assert rep.score >= 95 and rep.grade == "A"
    assert rep.status != "error"


def test_audit_input_normalization_and_errors():
    rep = audit_domain("https://example.com/path", StaticResolver(good_zone()), only=["spf"])
    assert rep.domain == "example.com" and [c.name for c in rep.checks] == ["spf"]
    assert audit_domain("postmaster@example.com", StaticResolver(good_zone()), only=["mx"]).domain == "example.com"
    with pytest.raises(ValueError, match="not a valid domain"):
        audit_domain("not a domain", StaticResolver({}))
    with pytest.raises(ValueError, match="unknown check"):
        audit_domain("example.com", StaticResolver({}), only=["nope"])


def test_audit_with_headers_adds_selector_and_ip():
    zones = good_zone()
    zones["custom._domainkey.example.com"] = zones.pop("selector1._domainkey.example.com")
    zones["10.2.0.192.in-addr.arpa"] = {"PTR": ["mx1.example.com"]}
    zones["mx1.example.com"]["A"].append("192.0.2.10")
    headers = "From: a@example.com\nDKIM-Signature: v=1; d=example.com; s=custom; a=rsa-sha256\n\n"
    rep = audit_domain(
        "example.com",
        StaticResolver(zones),
        fetcher=good_fetcher(),
        headers_text=headers,
        sending_ips=["192.0.2.10"],
        common_selectors=False,
    )
    dkim = rep.get("dkim")
    assert dkim.data["keys"][0]["selector"] == "custom"
    assert rep.get("rdns").status == "ok" and rep.get("headers") is not None
    assert rep.get("spf").has("spf.ip_pass")


def test_grades():
    assert [grade_for(s) for s in (100, 90, 85, 70, 55, 10)] == ["A", "A", "B", "C", "D", "F"]


def test_renderers():
    reps = [
        audit_domain("example.com", StaticResolver(good_zone()), fetcher=good_fetcher()),
        audit_domain("example.org", StaticResolver({})),
    ]
    text = render("text", reps)
    assert "example.com: score" in text and "fix:" in text
    assert "\033[" in render("text", reps, color=True)
    doc = json.loads(render("json", reps))
    assert doc["tool"] == "mail-auth-check" and doc["version"] == __version__
    assert doc["domains"][0]["checks"][0]["name"] == "mx"
    md = render("markdown", reps)
    assert "| Domain | Score | Grade |" in md and "### What to fix" in md and "## example.org" in md
    with pytest.raises(ValueError):
        render("pdf", reps)


def test_cli_exit_codes():
    code, out, _ = run(["example.com", "--no-http"], good_zone())
    assert code == EXIT_OK, out
    code, _, _ = run(["example.org"], {})
    assert code == EXIT_FAIL
    code, _, _ = run(["example.com", "--fail-under", "101"], good_zone(), good_fetcher())
    assert code == EXIT_FAIL
    monitoring = good_zone()
    monitoring["_dmarc.example.com"] = {"TXT": ["v=DMARC1; p=none; rua=mailto:d@example.com"]}
    assert run(["example.com", "--no-http"], monitoring)[0] == EXIT_OK
    assert run(["example.com", "--strict", "--no-http"], monitoring)[0] == EXIT_FAIL
    zones = good_zone()
    zones["_dmarc.example.com"] = {"error": "SERVFAIL"}
    assert run(["example.com"], zones, good_fetcher())[0] == EXIT_DNS
    assert run([], {})[0] == EXIT_USAGE
    assert run(["bad domain!"], {})[0] == EXIT_USAGE
    assert run(["example.com", "--checks", "spf,bogus"], {})[0] == EXIT_USAGE
    assert run(["--version"])[0] == 0


def test_cli_formats_and_files(tmp_path):
    out_file = tmp_path / "r.md"
    domains = tmp_path / "domains.txt"
    domains.write_text("# list\nexample.com\n\n")
    code, _, _ = run(
        ["--domains-file", str(domains), "-f", "markdown", "-o", str(out_file)], good_zone(), good_fetcher()
    )
    assert code == EXIT_OK and out_file.read_text().startswith("# Email authentication report")
    code, out, _ = run(["example.com", "-f", "json", "--checks", "spf,dmarc,senders"], good_zone())
    assert [c["name"] for c in json.loads(out)["domains"][0]["checks"]] == ["spf", "dmarc"]
    code, out, _ = run(["example.com", "-v", "--color", "never", "--ip", "192.0.2.5"], good_zone(), good_fetcher())
    assert "PASS" in out and "Sending IP reverse DNS" in out
    hdr = tmp_path / "msg.eml"
    hdr.write_text("From: a@example.com\nDKIM-Signature: d=example.com; s=selector1\n\nbody")
    code, out, _ = run(["example.com", "--headers", str(hdr)], good_zone(), good_fetcher())
    assert "Message headers" in out
    assert run(["example.com", "--headers", str(tmp_path / "missing")], good_zone())[0] == EXIT_USAGE


def test_cli_offline_example_file():
    code, out, _ = run(
        ["example.com", "broken.example", "--dns-data", str(EXAMPLES / "dns-example.json"), "-f", "json"]
    )
    doc = json.loads(out)
    good, broken = doc["domains"]
    assert good["grade"] == "A" and broken["grade"] == "F"
    spf = next(c for c in broken["checks"] if c["name"] == "spf")
    assert spf["data"]["lookups"] > 10
    assert code == EXIT_FAIL


def test_module_entry_point():
    res = subprocess.run([sys.executable, "-m", "mail_auth_check", "--version"], capture_output=True, text=True)
    assert res.returncode == 0 and __version__ in res.stdout


def test_text_output_strips_control_characters():
    zones = {"example.com": {"TXT": ["v=spf1 ip4:192.0.2.1 \x1b[31m-all"]}}
    rep = audit_domain("example.com", StaticResolver(zones), only=["spf"])
    assert "\x1b" not in render("text", [rep]) and "\x1b" not in render("markdown", [rep])
