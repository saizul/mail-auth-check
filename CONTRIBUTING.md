# Contributing

Thanks for taking the time to improve mail-auth-check. Bug reports, new checks,
fixes to RFC interpretation and documentation corrections are all welcome.

## Reporting a bug

Open an issue with:

- the command you ran and the output (`--format json` helps)
- your Python version (`python --version`), dnspython version and operating system
- the DNS records involved (`dig +short TXT _dmarc.example.com` and so on), with
  private names replaced by `example.com` and documentation IP ranges
- for a disagreement with an RFC: the section number and what you expected

## Development setup

You need Python 3.10 or newer.

```console
$ git clone https://github.com/saizul/mail-auth-check.git
$ cd mail-auth-check
$ python -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e ".[dev]"
```

Before every commit:

```console
$ ruff check .
$ ruff format --check .
$ pytest
```

All three must pass; CI runs them on Python 3.10 to 3.13.

## Guidelines

- **Tests never touch the network.** Use `StaticResolver` (fake DNS data) and
  `StaticFetcher` (fake HTTPS answers). `tests/conftest.py` has `good_zone()`,
  `make_ctx()` and helpers that build DKIM keys of any size.
- **Cite the source.** A rule taken from an RFC, the BIMI draft or a mailbox
  provider's sender guidelines needs the section or page in a comment or in the
  finding's `reference`.
- **Findings are stable.** Codes like `spf.too_many_lookups` are part of the JSON
  output; do not rename them without a changelog entry.
- **Every finding that is not "ok" should say how to fix it** (the `hint`).
- **Every change comes with a test** that fails without it.
- Add a line to the `Unreleased` section of `CHANGELOG.md` for anything a user
  would notice.

## Project layout

```text
src/mail_auth_check/
    resolver.py    Resolver interface, dnspython and static implementations
    spf/           SPF parser, macros, lookup counting and check_host()
    dkim.py        DKIM key records and DER key size
    dmarc.py       DMARC record parsing
    mta_sts.py     MTA-STS record and policy parsing
    util.py        tag lists, organizational domain, HTTPS fetcher
    checks/        the checks: mx, spf, dkim, dmarc, transport (MTA-STS, TLS-RPT),
                   bimi, senders (reverse DNS, headers, Gmail/Yahoo summary)
    audit.py       runs the checks and scores a domain
    report.py      text, JSON and Markdown output
    cli.py         command-line interface
tests/             pytest suite with fake DNS data
examples/          offline DNS data, sample headers, CI example, library use
```

## Pull requests

- Keep each pull request focused on one change.
- Describe what changed and why, and how you tested it.
- Do not bump the version number; that happens at release time.

By contributing you agree that your work is released under the MIT License.
