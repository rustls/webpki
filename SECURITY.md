# Security Policy

## Supported Versions

Security fixes will be backported only to the webpki versions for which the
original semver-compatible release was published less than 2 years ago.

For example, as of 2023-06-13 the latest release is 0.100.1

* 0.100.0 was released in March of 2023
* 0.17.0 was released in August of 2017

Therefore 0.100.x ill be updated, while 0.17.x will not be.

## Reporting a Vulnerability

Please report security bugs by email to rustls-security@googlegroups.com.
We'll then:

- Prepare a fix and regression tests.
- Backport the fix and make a patch release for most recent release.
- Submit an advisory to [rustsec/advisory-db](https://github.com/RustSec/advisory-db).
- Refer to the advisory on the main README.md and release notes.
