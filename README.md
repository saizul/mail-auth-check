# mail-auth-check

[![CI](https://github.com/saizul/mail-auth-check/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/mail-auth-check/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

Check the email authentication setup of a domain from the command line: SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT
and MX, plus the Gmail and Yahoo sender requirements. Every problem comes with a fix hint and a reference, every
domain gets a score out of 100, and the exit code tells CI whether something is broken.

Most "check my SPF" tools look at one record. Real problems hide one level down: the include of an include that
pushes SPF past 10 DNS lookups, the `rua=` address at an agency that never published its authorization record, the
1024-bit DKIM key from 2016, the MTA-STS policy that lists an MX host you retired. `mail-auth-check` follows those
chains the way receivers do.

```console
$ mail-auth-check broken.example
broken.example: score 41/100 (grade F), 7 error(s), 8 warning(s)

  SPF [FAIL] 0/25
    FAIL  The policy needs 15 DNS lookups; the limit is 10, so receivers return permerror.
          fix: Remove unused includes, replace 'a'/'mx'/'ptr' with ip4:/ip6: ranges, or flatten includes you control.
    FAIL  4 lookups return no records (void lookups); more than 2 is a permerror.
          fix: Remove mechanisms that point at names without records.
    WARN  broken.example uses the 'ptr' mechanism.
          fix: RFC 7208 says 'ptr' SHOULD NOT be published: it is slow and unreliable. Use ip4:/ip6: instead.
    FAIL  The policy ends with '+all': every server on the internet passes SPF.
          fix: Use '-all' (or '~all' while testing).

  DMARC [FAIL] 15/30
    WARN  Policy is none: monitoring only, spoofed mail is still delivered.
    FAIL  rua goes to thirdparty.example.net, which does not publish
          broken.example._report._dmarc.thirdparty.example.net; receivers will not send these reports.
  ...
```

(Output shortened; `broken.example` is the sample domain in `examples/dns-example.json`, run it yourself with
`--dns-data examples/dns-example.json`.)

## Contents

- [Features](#features)
- [Installation](#installation)
- [Docker image](#docker-image)
- [Usage](#usage)
- [What is checked](#what-is-checked)
- [Flattening an SPF record](#flattening-an-spf-record)
- [Score and exit codes](#score-and-exit-codes)
- [Configuration](#configuration)
- [Offline mode and fake DNS data](#offline-mode-and-fake-dns-data)
- [Library use](#library-use)
- [Examples](#examples)
- [Testing](#testing)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Features

- **SPF (RFC 7208)**: syntax of every term and modifier, macro syntax, the 10 DNS-lookup limit counted over the whole
  include/redirect tree, void lookups (more than 2 is a permerror), the 10-name limit of `mx`, include and redirect
  loops, includes without an SPF record, multiple records, `+all` / `?all` / no `all`, `redirect` ignored next to
  `all`, terms after `all`, `ptr`, very broad `ip4`/`ip6` ranges, and a real `check_host()` evaluation (with macro
  expansion) for the sending IPs you pass with `--ip`.
- **SPF flattening** (`flatten-spf`): proposes records that replace includes, `a` and `mx` with merged `ip4`/`ip6`
  ranges (split into chained includes when too long), and checks them with `check_host()` against the current policy
  before printing them.
- **DKIM (RFC 6376, 8301, 8463)**: selector discovery from about 50 selectors used by common providers plus your own
  (`--selector`), wildcard detection, key type, RSA key length read from the DER public key, revoked keys, `t=y`
  testing mode, `h=sha1`, `s=` service type, multiple records per selector.
- **DMARC (RFC 7489)**: tag syntax and values, `v`/`p` order, fallback to the organizational domain, policy strength,
  `pct`, `sp`, alignment modes, missing `rua`, and **external report destination verification**: for a `rua`/`ruf`
  address in another organizational domain it looks up `<domain>._report._dmarc.<host>` (section 7.1).
- **BIMI** (draft-brand-indicators-for-message-identification): `default._bimi` record, `l=`/`a=` as HTTPS URIs,
  declination records, the DMARC prerequisites (quarantine at `pct=100` or reject, `sp` not `none`), and an optional
  check that the logo is SVG Tiny PS.
- **MTA-STS (RFC 8461)**: the `_mta-sts` record (`v=STSv1`, `id` of 1 to 32 letters and digits, exactly one record)
  and the policy file over HTTPS: status 200, no redirects, certificate validity, `text/plain`, 64 KB limit,
  `version`/`mode`/`max_age`/`mx` fields, wildcard rules, and that every MX host matches a policy `mx:` pattern.
- **TLS-RPT (RFC 8460)**: `v=TLSRPTv1`, `rua` with `mailto:`/`https:` URIs, exactly one record.
- **MX**: null MX (RFC 7505), implicit MX, IP literals, CNAME targets, hosts without addresses, private addresses.
- **Gmail / Yahoo sender requirements**: a checklist built from the other results (SPF or DKIM for all senders, SPF
  and DKIM plus DMARC `p=none` or stronger for bulk senders, DKIM keys of 1024 bits or more), plus:
  - `--ip`: forward-confirmed reverse DNS for your sending IPs (PTR and back) and SPF evaluation for them
  - `--headers`: a real message's headers: DKIM `d=` and Return-Path alignment with `From:`, one-click unsubscribe
    (`List-Unsubscribe` with an https URL and `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, RFC 8058),
    `Authentication-Results`, `rsa-sha1` signatures; the DKIM selectors found there are checked automatically
  - items that DNS cannot show (spam rate, TLS for outgoing mail, RFC 5322 formatting) are listed as manual checks
- **Output**: text (with optional colour), JSON and Markdown, with a 0-100 score, a grade, a "what to fix" list and
  references to the RFC section or guideline page.
- **Testable by design**: all DNS goes through a small `Resolver` interface (dnspython by default), all HTTPS through
  a `Fetcher` callable. `--dns-data` answers from a JSON file, for offline runs and reproducible bug reports.

## Installation

Python 3.10 or newer. The only dependency is [dnspython](https://www.dnspython.org/).

```bash
pip install "mail-auth-check @ git+https://github.com/saizul/mail-auth-check"
# or from a checkout
pip install .
```

This installs the `mail-auth-check` command (also available as `python -m mail_auth_check`).

## Docker image

A multi-arch image (linux/amd64, linux/arm64) is published to GitHub Packages:

```bash
docker pull ghcr.io/saizul/mail-auth-check:latest

docker run --rm ghcr.io/saizul/mail-auth-check:latest example.com --selector google

# Files (headers, domain lists, DNS data) are read from /work, the working directory of the image.
docker run --rm -v "$PWD:/work:ro" ghcr.io/saizul/mail-auth-check:latest \
  --domains-file domains.txt --headers message.eml --format markdown
```

Release images are also tagged with the version (`ghcr.io/saizul/mail-auth-check:0.1.0`) and every build with its
commit SHA. The container runs as an unprivileged user (uid 10001) and uses the DNS resolver Docker gives it; pass
`--nameserver` to pick another one.

## Usage

```bash
# Everything, with the common DKIM selectors
mail-auth-check example.com

# Your real DKIM selector(s) (the s= value of a DKIM-Signature header) and only those
mail-auth-check example.com -s selector1 -s s2 --no-common-selectors

# Evaluate SPF and reverse DNS for your sending IPs
mail-auth-check example.com --ip 192.0.2.25 --ip 2001:db8::25

# Check a real message against the Gmail/Yahoo rules (save "Show original" / "View source" to a file)
mail-auth-check example.com --headers newsletter.eml

# Several domains, Markdown report to a file, fail CI under 80 points
mail-auth-check example.com example.org --format markdown -o report.md --fail-under 80
mail-auth-check --domains-file domains.txt --format json

# Only some checks
mail-auth-check example.com --checks spf,dmarc

# A specific resolver, no HTTPS fetches
mail-auth-check example.com --nameserver 1.1.1.1 --no-http
```

| Option | Meaning |
| --- | --- |
| `-s`, `--selector` | DKIM selector to check (repeatable) |
| `--no-common-selectors` | do not try the built-in selector list |
| `--ip` | sending IP: SPF `check_host()` and forward-confirmed reverse DNS (repeatable) |
| `--headers FILE` | headers or full source of a message sent from the domain |
| `--checks LIST` | subset of `mx,spf,dkim,dmarc,mta_sts,tlsrpt,bimi,senders` |
| `--org-domain` | organizational domain for DMARC, when the built-in guess is wrong |
| `--not-bulk` | report bulk-sender-only requirements as warnings instead of errors |
| `-f`, `--format` | `text` (default), `json` or `markdown` |
| `-o`, `--output` | write the report to a file |
| `-v`, `--verbose` | also show passing findings and notes in text output |
| `--color` | `auto` (default; honours `NO_COLOR`), `always` or `never` |
| `--no-http` | do not fetch the MTA-STS policy or the BIMI logo |
| `--nameserver` | DNS server to use (repeatable) |
| `--dns-data FILE` | answer DNS (and HTTPS) from a JSON file |
| `--timeout` | DNS and HTTP timeout in seconds (default 5) |
| `--fail-under N` | exit 1 when a domain scores below N |
| `--strict` | exit 1 on warnings too |

## What is checked

### SPF

| Finding | Severity | Rule |
| --- | --- | --- |
| no SPF record, or more than one | error | RFC 7208 4.5 |
| syntax error in any term (unknown mechanism, bad IP or prefix, bad macro, duplicate `redirect`/`exp`) | error | 12 |
| more than 10 DNS-querying terms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) in the whole tree | error | 4.6.4 |
| 9 or 10 lookups | warning | |
| more than 2 void lookups (NXDOMAIN or empty answer) / 1 or 2 | error / warning | 4.6.4 |
| an `mx` term with more than 10 MX names | error | 4.6.4 |
| include or redirect to a domain without SPF, or a loop | error | 5.2, 6.1 |
| ends with `+all` (or a bare `all`) | error | 5.1 |
| ends with `?all`, or has no `all` and no `redirect` | warning | |
| `ptr` mechanism | warning | 5.5 |
| `ip4` wider than /16, `ip6` wider than /32 | warning | |
| terms after `all`, `redirect` next to `all`, unknown modifiers | warning | 5.1, 6 |
| `--ip` evaluates to anything but `pass` | error | 4 |

The lookup count is the worst case: every term is counted, as if no earlier mechanism matched. That is the number a
receiver hits for mail from a server you forgot to list. Terms whose target uses macros (`exists:%{i}._spf...`) are
counted but not resolved, because their target depends on the message.

### DKIM

Keys are found only by selector, so the tool tries a list of selectors used by common providers (Microsoft 365,
Google Workspace, Mailchimp, SendGrid, Mailgun, Zoho, Fastmail, Proton, iCloud and more) plus yours. When none is
found without `--selector`, the result is a warning, not an error: the key may simply use another selector. RSA keys
under 1024 bits are errors (RFC 8301, and Gmail requires 1024+), 1024-bit keys are warnings (Gmail recommends 2048),
Ed25519 keys are accepted with a note that you should also sign with RSA.

### DMARC

Records are looked up at `_dmarc.<domain>` and then at the organizational domain (where `sp=` applies). `p=none` is
a warning (it satisfies the Gmail/Yahoo bulk-sender minimum but stops nothing), `pct` under 100 and `sp=none` next to
an enforcing policy are warnings, a missing `rua=` is a warning. For report addresses outside your organizational
domain, the authorization record `<your domain>._report._dmarc.<report host>` must exist and start with `v=DMARC1`,
otherwise receivers drop those reports: that is an error.

The DMARCbis tags are validated too: `np=` (policy for subdomains that do not exist) must be none, quarantine or
reject, `psd=` must be y, n or u, and `t=` must be y or n. `np=none` next to an enforcing policy is a warning
(`dmarc.np_none`), `t=y` is a warning because receivers apply the policy one level lower (`dmarc.testing`: reject
becomes quarantine, quarantine becomes none), and `psd=y` on an ordinary domain is a warning (`dmarc.psd`). The JSON
output includes `nonexistentPolicy`, `psd` and `testing`.

### MTA-STS, TLS-RPT, BIMI and MX

See [Features](#features). A domain with a null MX skips MTA-STS and TLS-RPT. BIMI is optional, so a missing record is
informational; a BIMI record with a weak DMARC policy is an error because logos will not show.

### Gmail and Yahoo requirements

Based on Google's [Email sender guidelines](https://support.google.com/a/answer/81126) and Yahoo's
[Sender Best Practices](https://senders.yahooinc.com/best-practices/):

| Requirement | Applies to | How it is checked |
| --- | --- | --- |
| SPF or DKIM | all senders | SPF and DKIM checks |
| SPF and DKIM | bulk senders | SPF and DKIM checks (DKIM needs the right selector) |
| DKIM key of 1024 bits or more | all senders | DKIM check (2048 recommended) |
| DMARC with at least `p=none` | bulk senders | DMARC check |
| `From:` aligned with SPF or DKIM domain | bulk senders | `--headers` |
| one-click unsubscribe (RFC 8058) for marketing mail | bulk senders | `--headers` |
| valid forward and reverse DNS for sending IPs | all senders | `--ip` |
| TLS, spam rate under 0.3%, RFC 5322 format | all senders | listed as manual checks |

Gmail counts a bulk sender as one that sends more than 5,000 messages a day to personal Gmail accounts. If you are
not one, `--not-bulk` turns the bulk-only failures into warnings.

## Flattening an SPF record

When a policy needs more than 10 DNS lookups, `flatten-spf` proposes records that replace includes and `a`/`mx`
terms with the address ranges they resolve to. Nothing is published; the records are printed for you to review.

```bash
# Proposed records, what was flattened or kept, and the old/new comparison
mail-auth-check flatten-spf example.com

# Keep the includes of providers that change their addresses often, write zone-file lines
mail-auth-check flatten-spf example.com --keep _spf.google.com,spf.protection.outlook.com --format zone --ttl 300

# Offline, against fake DNS data
mail-auth-check flatten-spf example.com --dns-data examples/dns-example.json --format json
```

| Option | Meaning |
| --- | --- |
| `--keep DOMAIN` | leave `include:DOMAIN` / `redirect=DOMAIN` unchanged (repeatable, comma-separated) |
| `--max-length N` | longest record before the ranges move to `<label>1.<domain>`, `<label>2.<domain>`, ... (default 450) |
| `--label PREFIX` | name prefix of the chained records (default `_spf`) |
| `--ip IP` | add an address to the old/new comparison (repeatable) |
| `--no-verify` | skip the comparison |
| `--format` | `text`, `json` or `zone`; `--ttl` sets the TTL of zone-file lines (default 3600) |
| `--dns-data`, `--nameserver`, `--timeout`, `--output` | as for the audit |

How it works:

- `ip4`/`ip6` ranges are collected from the whole tree, host bits are cleared, and overlapping or adjacent ranges are
  merged. `a` and `mx` terms are resolved with their prefix lengths (`a/24//64`).
- Inside an include only the `+` mechanisms authorize anything, so `-ip4:` and similar terms there are left out. At
  the top level non-pass terms are kept in place; if one comes after a flattened term you get a warning, because the
  ranges are written before it.
- Terms that depend on the message (macros, `exists`, `ptr`) cannot become ranges. At the top level they are kept; an
  include that contains one (or ends in `+all`) is kept as a whole. `exp=` is kept, unknown modifiers are dropped.
- The chained records end in `-all`, which inside an include only means "no match here".
- The proposal is checked against the real DNS data with the new records laid over it: the lookup count must be 10 or
  less, and `check_host()` must give the same result for each sample address as the current policy. Samples where the
  current policy already returns permerror (usually because it is over the limit) are not compared.

| Exit code | Meaning |
| ---: | --- |
| 0 | records proposed (or nothing to flatten) |
| 1 | the proposal still needs more than 10 lookups, or gives a different result for a sample address |
| 2 | usage error |
| 3 | DNS lookups failed |

Flattened ranges are a snapshot. When a provider adds sending addresses, mail from them fails SPF until you rebuild
the record, so run `flatten-spf` from a scheduled job and compare its `--format zone` output, or `--keep` the
includes you do not control.

## Score and exit codes

Points per check: DMARC 30, SPF 25, DKIM 25, MX 6, MTA-STS 6, TLS-RPT 4, BIMI 4. A check without problems gets full
points, warnings cost part of them, an error usually costs all of them. The score is the percentage of the points of
the checks that ran; grades are A (90+), B (80+), C (65+), D (50+) and F.

| Exit code | Meaning |
| ---: | --- |
| 0 | no errors (and every score at or above `--fail-under`) |
| 1 | at least one error, a score below `--fail-under`, or a warning with `--strict` |
| 2 | usage error (bad arguments, invalid domain, unreadable file) |
| 3 | DNS lookups failed (timeouts, SERVFAIL), so the result is not reliable |

## Configuration

There is no configuration file; everything is a command-line option. `NO_COLOR` disables colour in `--color auto`
mode. The DNS resolver comes from the system configuration (`/etc/resolv.conf`) unless `--nameserver` is given.

## Offline mode and fake DNS data

`--dns-data FILE` answers every query from a JSON file instead of the network:

```json
{
  "example.com": {
    "MX": [[10, "mx1.example.com"]],
    "TXT": ["v=spf1 include:_spf.example.net -all"]
  },
  "mx1.example.com": {"A": ["192.0.2.25"]},
  "selector1._domainkey.example.com": {"TXT": [["v=DKIM1; k=rsa; p=MIIBIjAN...", "...IDAQAB"]]},
  "www.example.com": {"CNAME": ["example.com"]},
  "*._report._dmarc.reports.example.net": {"TXT": ["v=DMARC1"]},
  "down.example.com": {"error": "SERVFAIL"},
  "_http": {
    "https://mta-sts.example.com/.well-known/mta-sts.txt": {
      "status": 200, "content_type": "text/plain", "body": "version: STSv1\r\nmode: enforce\r\n..."
    }
  }
}
```

A missing name is NXDOMAIN, a name without the asked type is an empty answer (NODATA), CNAMEs are followed, `*.`
names act as wildcards, `"error"` simulates a failed lookup, and TXT records given as a list of strings are joined
like multi-string TXT records. The `_http` section answers HTTPS fetches. This is how the test suite works, and it is
a convenient way to try a DNS change before publishing it.

## Library use

```python
from mail_auth_check import (
    DnspythonResolver,
    analyze_spf,
    audit_domain,
    check_host,
    flatten_spf,
    render,
    urllib_fetcher,
)

resolver = DnspythonResolver(timeout=5)
report = audit_domain("example.com", resolver, fetcher=urllib_fetcher, selectors=["selector1"])
print(report.score, report.grade)
for check in report.checks:
    for finding in check.findings:
        if finding.severity == "error":
            print(check.name, finding.code, finding.message, finding.hint)

spf = analyze_spf(resolver, "example.com")
print(spf.total_lookups, spf.total_void, spf.ip4)
flat = flatten_spf(resolver, "example.com", keep=["_spf.google.com"])
print(flat.status, flat.lookups, flat.records, flat.mismatches)
print(check_host(resolver, "192.0.2.25", "example.com", sender="news@example.com").result)
print(render("markdown", [report]))
```

Any object with `resolve(name, rdtype) -> DnsAnswer` can replace the resolver; `StaticResolver` takes the same
mapping as `--dns-data`. Finding codes (`spf.too_many_lookups`, `dmarc.external_unverified`, ...) are stable and are
part of the JSON output.

## Examples

`examples/` contains:

- `dns-example.json`: a well-configured `example.com` and a deliberately broken `broken.example`, for offline runs
- `message-headers.txt`: headers of a bulk message that meets the Gmail/Yahoo rules
- `domains.txt`: input for `--domains-file`
- `library_usage.py`: library use, runs offline
- `github-actions-mail-auth-check.yml`: a scheduled workflow that puts the Markdown report in the job summary

```bash
mail-auth-check example.com broken.example --dns-data examples/dns-example.json
mail-auth-check example.com --dns-data examples/dns-example.json --headers examples/message-headers.txt --ip 192.0.2.25
```

## Testing

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest
$ ruff check . && ruff format --check .
```

The tests use `StaticResolver` with fake DNS data and `StaticFetcher` for HTTPS, build DKIM keys of any length in
DER form, check the macro examples from RFC 7208 section 7.4, and exercise the dnspython wrapper with a patched
resolver. They never use the network. CI runs them on Python 3.10 to 3.13, plus a smoke test of the CLI and a Docker
build.

## Limitations

- DKIM keys can only be found by selector. Without `--selector` (or `--headers`), a missing key is a warning.
- The organizational domain for DMARC is guessed from the last two labels plus a built-in list of common
  multi-label suffixes (`co.uk`, `com.bd`, `com.au`, ...), not the full Public Suffix List. Use `--org-domain` when it
  matters.
- DNSSEC is not validated; use a validating resolver with `--nameserver` if you need it.
- `check_host()` implements every mechanism and macro, but `exp=` explanations are not fetched, and the `p` macro
  expands to `unknown`.
- The SPF lookup count for terms with macros is counted but not followed.
- The MTA-STS check uses the system's certificate store and does not check the certificates of your MX hosts (that
  needs an SMTP STARTTLS connection).
- BIMI: the mark certificate (VMC/CMC) in `a=` is not downloaded or validated. The 32 KB logo size warning is a
  common recommendation, not a protocol limit.
- DMARCbis `psd=` is validated, but the DMARCbis tree walk for the organizational domain is not implemented; the
  built-in suffix list is used instead.
- Spam rate, TLS for outgoing mail and message formatting cannot be seen in DNS; they are listed as manual checks.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Gmail is a trademark of Google LLC and Yahoo is a trademark of Yahoo Inc.; this project
is not affiliated with either.
