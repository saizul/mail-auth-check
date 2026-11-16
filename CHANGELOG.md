# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `mail-auth-check flatten-spf <domain>`: builds an SPF record that replaces `include`, `a`, `mx` and `redirect`
  terms with the `ip4:`/`ip6:` ranges they resolve to (merged and collapsed), to get a policy back under the
  10-lookup limit. Long results are split into chained `include:_spfN.<domain>` records under `--max-length`
  (default 450 characters). Macros, `exists`, `ptr`, non-pass terms and includes that end in `+all` are kept, and
  `--keep` leaves chosen includes alone.
- Every proposal is checked before it is printed: the new lookup count comes from the same analysis as the SPF check
  with the new records laid over the real DNS answers, and `check_host()` runs for a sample of addresses (range edges,
  the address after each range and `--ip`) against the old and the new policy. A different result is an error.
- Text, JSON and zone-file (`--format zone`, `--ttl`) output; exit codes 0, 1 (still over the limit or a different
  result), 2 (usage) and 3 (DNS failure).
- Library API: `flatten_spf()`, `FlattenResult` and `OverlayResolver` (try new SPF records on top of any resolver).

## [0.1.0] - 2026-11-14

### Added

- SPF: record selection and full syntax check (RFC 7208), macro validation and expansion, the 10 DNS lookup limit
  counted across includes and redirects, void lookups (limit 2), the 10-name limit for `mx`, include/redirect loops,
  `+all` / `?all` / missing `all`, `ptr`, overly broad ranges, and `check_host()` evaluation for sending IPs (`--ip`).
- DKIM: selector discovery from a list of common provider selectors plus `--selector`, wildcard detection, key type
  (RSA, Ed25519), RSA key length read from the DER key, revoked keys, `t=y`, `h=sha1`, `s=` service type.
- DMARC: tag validation (RFC 7489 6.3), organizational-domain fallback, policy strength, `pct`, `sp`, alignment
  modes, and external report destination verification (`<domain>._report._dmarc.<host>`, 7.1).
- BIMI record and DMARC prerequisites, optional SVG Tiny PS logo check.
- MTA-STS TXT record and HTTPS policy file (no redirects, status, content type, size, fields, MX pattern match).
- TLS-RPT record, MX sanity (null MX, implicit MX, IP literals, CNAME targets, unresolvable and private addresses).
- Forward-confirmed reverse DNS for sending IPs, message header checks (`--headers`: alignment, one-click
  unsubscribe, Authentication-Results) and a Gmail/Yahoo sender requirements summary.
- Text, JSON and Markdown reports with a 0-100 score, grade, fix hints and references; exit codes for CI.
- Injectable resolver (dnspython by default) and `--dns-data` offline mode with a JSON zone file.
- Docker image published to `ghcr.io/saizul/mail-auth-check`.

[Unreleased]: https://github.com/saizul/mail-auth-check/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/mail-auth-check/releases/tag/v0.1.0
