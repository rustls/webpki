// Copyright 2025 webpki Authors.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/// Returns the fully qualified domain name authority component of `uri`.
///
/// RFC 5280 § 4.2.1.10 defines `uniformResourceIdentifier` name constraints in terms of the host
/// part of the URI, matched using the same rules as `dNSName` constraints.
///
/// Parsing follows the generic RFC 3986 authority syntax and is intentionally minimal: anything
/// ambiguous fails closed (returns `None`).
pub(super) fn host_of(uri: untrusted::Input<'_>) -> Option<untrusted::Input<'_>> {
    let uri = uri.as_slice_less_safe();

    // RFC 3986: URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ].
    let (_, rest) = split_once(uri, |&b| b == b':')?;

    // An authority component is only present after a "//" following the scheme delimiter.
    let rest = rest.strip_prefix(b"//")?;

    // authority ends at the first "/", "?", or "#".
    let authority = match split_once(rest, |&b| matches!(b, b'/' | b'?' | b'#')) {
        Some((authority, _)) => authority,
        None => rest,
    };

    // Drop any userinfo ("user:pass@"); it ends at the last "@".
    let host_port = match split_once(authority, |&b| b == b'@') {
        Some((_, host_port)) => host_port,
        None => authority,
    };

    // An IPv6 (or IP-future) literal is bracketed; per RFC 5280 IP hosts are not allowed.
    if host_port.first() == Some(&b'[') {
        return None;
    }

    // Strip a trailing ":port". Since we've excluded bracketed literals above, the only
    // remaining colon is the port separator.
    let host = match split_once(host_port, |&b| b == b':') {
        Some((host, _)) => host,
        None => host_port,
    };
    if host.is_empty() {
        return None;
    }

    let mut octets = 0;
    for label in host.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 3 || !label.iter().all(u8::is_ascii_digit) {
            octets = 0; // Not an IPv4 literal
            break;
        }
        octets += 1;
    }

    match octets {
        4 => None, // IPv4 literal
        _ => Some(untrusted::Input::from(host)),
    }
}

/// `slice::split_once()` is not stable yet
fn split_once(bytes: &[u8], pred: impl FnMut(&u8) -> bool) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(pred)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::{format, str};

    use proptest::prelude::*;
    use url::{Host, Url};

    use super::*;

    #[test]
    fn simple() {
        assert_eq!(host(b"https://example.com"), Some(&b"example.com"[..]));
        assert_eq!(
            host(b"https://host.example.com/path"),
            Some(&b"host.example.com"[..])
        );
    }

    #[test]
    fn port_userinfo_path_query_fragment() {
        assert_eq!(host(b"https://example.com:8443"), Some(&b"example.com"[..]));
        assert_eq!(
            host(b"https://user@example.com/p"),
            Some(&b"example.com"[..])
        );
        assert_eq!(
            host(b"https://user:pass@example.com:8443/p?q#f"),
            Some(&b"example.com"[..])
        );
        assert_eq!(host(b"https://example.com?q"), Some(&b"example.com"[..]));
        assert_eq!(host(b"https://example.com#f"), Some(&b"example.com"[..]));
    }

    #[test]
    fn no_authority() {
        assert_eq!(host(b"urn:example:animal"), None);
        assert_eq!(host(b"mailto:user@example.com"), None);
        assert_eq!(host(b"example.com"), None);
    }

    #[test]
    fn empty_host() {
        assert_eq!(host(b"file:///path"), None);
        assert_eq!(host(b"https://:8443/p"), None);
        assert_eq!(host(b"https://user@/p"), None);
    }

    #[test]
    fn ip_literal_host() {
        assert_eq!(host(b"https://127.0.0.1/p"), None);
        assert_eq!(host(b"https://127.0.0.1:8443"), None);
        assert_eq!(host(b"https://[2001:db8::1]/p"), None);
        assert_eq!(host(b"https://[2001:db8::1]:8443"), None);
    }

    #[test]
    fn not_ip_literal() {
        // Trailing/short label counts that aren't four octets are hostnames.
        assert_eq!(host(b"https://1.2.3"), Some(&b"1.2.3"[..]));
        assert_eq!(host(b"https://1.2.3.4.5"), Some(&b"1.2.3.4.5"[..]));
        assert_eq!(host(b"https://1234.2.3.4"), Some(&b"1234.2.3.4"[..]));
    }

    fn host(uri: &[u8]) -> Option<&[u8]> {
        host_of(untrusted::Input::from(uri)).map(|h| h.as_slice_less_safe())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        // Cross-check against the `url` crate on URIs where RFC 3986 and the WHATWG URL
        // standard agree. The generator avoids inputs the two standards parse differently:
        // hosts with a numeric or "xn--" last label, percent-encoding, IPv4 literals with
        // non-special schemes, out-of-range ports, and raw "@" or "\" in the authority.
        #[test]
        fn consistent_with_url_crate(uri in uri_strategy()) {
            let expected = match Url::parse(&uri) {
                Ok(url) => match url.host() {
                    Some(Host::Domain(host)) if !host.is_empty() => {
                        Some(host.to_ascii_lowercase())
                    }
                    Some(Host::Domain(_)) | Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) | None => {
                        None
                    }
                },
                Err(_) => None,
            };

            let actual = host(uri.as_bytes())
                .map(|host| str::from_utf8(host).unwrap().to_ascii_lowercase());
            prop_assert_eq!(actual, expected, "uri = {:?}", uri);
        }
    }

    fn uri_strategy() -> impl Strategy<Value = String> {
        let special = prop::sample::select(&["http", "https", "ws", "wss", "ftp"][..]);
        let non_special = prop::sample::select(&["coap", "git", "spiffe", "ldap"][..]);
        let scheme_and_host = prop_oneof![
            (special, prop_oneof![domain(), ipv4_quad(), ipv6_literal()]),
            (non_special, prop_oneof![domain(), ipv6_literal()]),
        ];

        (scheme_and_host, userinfo(), port(), tail()).prop_map(
            |((scheme, host), userinfo, port, tail)| {
                format!("{scheme}://{userinfo}{host}{port}{tail}")
            },
        )
    }

    fn domain() -> impl Strategy<Value = String> {
        let label = proptest::string::string_regex("[A-Za-z0-9_-]{1,8}").unwrap();
        let last = proptest::string::string_regex("[A-Za-z][A-Za-z0-9_-]{0,7}").unwrap();
        (prop::collection::vec(label, 0..=3), last)
            .prop_map(|(mut labels, last)| {
                labels.push(last);
                labels.join(".")
            })
            .prop_filter("xn-- labels trigger punycode decoding", |host| {
                !host
                    .to_ascii_lowercase()
                    .split('.')
                    .any(|label| label.starts_with("xn--"))
            })
    }

    fn ipv4_quad() -> impl Strategy<Value = String> {
        let octet = proptest::string::string_regex("[0-9]{1,3}").unwrap();
        prop::collection::vec(octet, 4).prop_map(|octets| octets.join("."))
    }

    fn ipv6_literal() -> impl Strategy<Value = String> {
        proptest::string::string_regex("\\[(2001:db8::1|::1|::|fe80::a:b)\\]").unwrap()
    }

    fn userinfo() -> impl Strategy<Value = String> {
        let userinfo = proptest::string::string_regex("[a-z0-9:]{0,8}@").unwrap();
        prop_oneof![Just(String::new()), userinfo]
    }

    fn port() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            Just(String::from(":")),
            (0..=0xffffu32).prop_map(|port| format!(":{port}")),
        ]
    }

    fn tail() -> impl Strategy<Value = String> {
        let path = proptest::string::string_regex("(/[A-Za-z0-9._~-]{0,6}){0,3}").unwrap();
        let query = proptest::string::string_regex("(\\?[a-z0-9=&._-]{0,8})?").unwrap();
        let fragment = proptest::string::string_regex("(#[a-z0-9._-]{0,8})?").unwrap();
        (path, query, fragment)
            .prop_map(|(path, query, fragment)| format!("{path}{query}{fragment}"))
    }
}
