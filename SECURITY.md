# Security policy

## Supported versions

Security fixes are made for the latest release. Please upgrade before reporting.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting instead: open the **Security** tab of
https://github.com/saizul/mail-auth-check and choose **Report a
vulnerability**.

Include what you found, how to reproduce it and what an attacker could do with
it. You should get an answer within a week. Once a fix is released you will be
credited in the changelog unless you prefer otherwise.

Replace real domain names, IP addresses and message headers with `example.com`
and documentation addresses (192.0.2.0/24, 2001:db8::/32) where you can.

## Scope

In scope:

- parsing of untrusted DNS answers, policy files, SVG logos and message headers
  (crashes, hangs, excessive memory or DNS queries)
- the HTTPS fetcher (certificate checks, redirects, size limits)
- output that could inject content into reports (Markdown, terminal escapes)

Out of scope: the security of the DNS data itself (use a validating resolver if
you need DNSSEC), and wrong results caused by a resolver you configured.
