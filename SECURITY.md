# Security Policy

## Supported Versions

Security fixes will be backported only to the webpki versions for which the
original semver-compatible release was published less than 2 years ago.

For example, as of 2026-03-24 the latest release is 0.104.0-alpha.5.

* 0.104.0 is yet to be released.
* 0.103.0 was released in Febrary 2025
* 0.102.0 was released in November 2023
* 0.101.0 was released in July 2023
* 0.100.0 was released in March 2023
* 0.17.0 was released in August 2017

Therefore 0.103.x will receive security fixes, but others will not.

## Reporting a Vulnerability

Before reporting a security bug, make sure to:

- Consider the threat model. Misconfiguration that is unlikely to happen accidentally is
  unlikely to be a security bug.
- If applicable, compare the behavior to other TLS implementations. If the behavior is consistent
  with other implementations, it is less likely to be a security bug.

Please report security bugs [via github](https://github.com/rustls/webpki/security/advisories/new).
Make sure to disclose any use of AI assistance upfront.

We'll then:

- Prepare a fix and regression tests.
- Backport the fix and make a patch release for most recent release.
- Submit an advisory to [rustsec/advisory-db](https://github.com/RustSec/advisory-db).
- Refer to the advisory on the main README.md and release notes.
