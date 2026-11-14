# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
