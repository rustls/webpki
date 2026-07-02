// Copyright 2022 Joseph Birr-Pixton.
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
#![cfg(feature = "alloc")]

use core::time::Duration;

use pki_types::{CertificateDer, ServerName, UnixTime};
use rcgen::{
    Certificate, CertificateParams, CertifiedIssuer, CidrSubnet, CustomExtension,
    DistinguishedName, DnType, GeneralSubtree, IsCa, KeyPair, NameConstraints, SanType,
    date_time_ymd,
};
use webpki::{ExtendedKeyUsage, InvalidNameContext, PathBuilder, anchor_from_trusted_cert};

mod common;
use common::issuer_params;

#[track_caller]
fn check_cert(
    ee: &[u8],
    ca: &[u8],
    valid_names: &[&str],
    invalid_names: &[&str],
    presented_names: &[&str],
) -> Result<(), webpki::Error> {
    let ca_cert_der = CertificateDer::from(ca);
    let anchors = [anchor_from_trusted_cert(&ca_cert_der).unwrap()];
    let builder = PathBuilder::new(
        &[],
        None,
        &ExtendedKeyUsage::SERVER_AUTH,
        rustls_aws_lc_rs::ALL_VERIFICATION_ALGS,
        &anchors,
    );

    let ee_der = CertificateDer::from(ee);
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let cert = webpki::EndEntityCert::try_from(&ee_der).unwrap();
    builder.build(&cert, time)?;

    for valid in valid_names {
        let name = ServerName::try_from(*valid).unwrap();
        assert_eq!(cert.verify_is_valid_for_subject_name(&name), Ok(()));
    }

    for invalid in invalid_names {
        let name = ServerName::try_from(*invalid).unwrap();
        assert_eq!(
            cert.verify_is_valid_for_subject_name(&name),
            Err(webpki::Error::CertNotValidForName(InvalidNameContext {
                expected: name.to_owned(),
                presented: presented_names.iter().map(|n| n.to_string()).collect(),
            }))
        );
    }

    Ok(())
}

#[test]
fn no_name_constraints() {
    let issuer = make_issuer(None);
    let ee = generate_cert_with_names(
        Some("subject.example.com"),
        None,
        vec![SanType::DnsName("dns.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["dns.example.com"],
            &["subject.example.com"],
            &["DnsName(\"dns.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn additional_dns_labels() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(".example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert_with_names(
        Some("subject.example.com"),
        None,
        vec![
            SanType::DnsName("host1.example.com".try_into().unwrap()),
            SanType::DnsName("host2.example.com".try_into().unwrap()),
        ],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["host1.example.com", "host2.example.com"],
            &["subject.example.com"],
            &[
                "DnsName(\"host1.example.com\")",
                "DnsName(\"host2.example.com\")"
            ]
        ),
        Ok(())
    );
}

#[test]
fn disallow_dns_san() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DnsName(
            "disallowed.example.com".to_string(),
        )],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName(
            "disallowed.example.com".try_into().unwrap(),
        )],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["DnsName(\"disallowed.example.com\")"]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn allow_subject_common_name() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("allowed.example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert_with_names(Some("allowed.example.com"), None, vec![], &issuer);
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &["allowed.example.com"], &[]),
        Ok(())
    );
}

#[test]
fn allow_dns_san() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("allowed.example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName("allowed.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["allowed.example.com"],
            &[],
            &["DnsName(\"allowed.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn allow_dns_san_and_subject_common_name() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("allowed-san.example.com".to_string()),
            GeneralSubtree::DnsName("allowed-cn.example.com".to_string()),
        ],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert_with_names(
        Some("allowed-cn.example.com"),
        None,
        vec![SanType::DnsName(
            "allowed-san.example.com".try_into().unwrap(),
        )],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["allowed-san.example.com"],
            &["allowed-cn.example.com"],
            &["DnsName(\"allowed-san.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn disallow_dns_san_and_allow_subject_common_name() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("allowed-san.example.com".to_string()),
            GeneralSubtree::DnsName("allowed-cn.example.com".to_string()),
        ],
        excluded_subtrees: vec![GeneralSubtree::DnsName(
            "disallowed-san.example.com".to_string(),
        )],
    }));
    let ee = generate_cert_with_names(
        Some("allowed-cn.example.com"),
        None,
        vec![
            SanType::DnsName("allowed-san.example.com".try_into().unwrap()),
            SanType::DnsName("disallowed-san.example.com".try_into().unwrap()),
        ],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &[
                "DnsName(\"allowed-san.example.com\")",
                "DnsName(\"disallowed-san.example.com\")"
            ]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn we_incorrectly_ignore_name_constraints_on_name_in_subject() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::Rfc822Name("example.com".to_string())],
    }));
    let ee = generate_cert_with_names(None, Some("test@example.com"), vec![], &issuer);
    // webpki incorrectly ignores name constraints on email addresses in the subject DN
    // The email in subject should be checked against constraints, but it isn't
    assert_eq!(check_cert(ee.der(), issuer.der(), &[], &[], &[]), Ok(()));
}

#[test]
fn reject_constraints_on_unimplemented_names() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::Rfc822Name("example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::Rfc822Name("joe@example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn we_ignore_constraints_on_names_that_do_not_appear_in_cert() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::Rfc822Name("example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName("notexample.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["notexample.com"],
            &["example.com"],
            &["DnsName(\"notexample.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn wildcard_san_accepted_if_in_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName("*.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["bob.example.com", "jane.example.com"],
            &["example.com", "uh.oh.example.com"],
            &["DnsName(\"*.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn wildcard_san_rejected_if_in_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DnsName("example.com".to_string())],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName("*.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["DnsName(\"*.example.com\")"]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

/// CVE-2025-61727: a wildcard SAN like `*.example.com` can expand to a name (like
/// `evil.example.com`) that falls inside an excluded subtree such as `evil.example.com`. Such
/// certificates must be rejected even though the excluded subtree is narrower than the wildcard's
/// parent label.
#[test]
fn wildcard_san_rejected_if_could_match_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DnsName("evil.example.com".to_string())],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName("*.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["DnsName(\"*.example.com\")"]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

/// When a CA name constraint permits `www.example.com`, leaf certificates with a wildcard SAN of
/// `*.example.com` should be rejected, because it could match names outside the permitted subtree.
///
/// <https://github.com/rustls/webpki/security/advisories/GHSA-xgp8-3hg3-c2mh>
#[test]
fn wildcard_san_rejected_if_could_match_name_outside_permitted_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("foo.example.com".to_string())],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::DnsName("*.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["DnsName(\"*.example.com\")"]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn ip4_address_san_rejected_if_in_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 0],
            [255, 255, 255, 0],
        ))],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("12.34.56.78".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["IpAddress(12.34.56.78)"]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn ip4_address_san_allowed_if_outside_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 252],
            [255, 255, 255, 252],
        ))],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("12.34.56.78".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["12.34.56.78"],
            &[],
            &["IpAddress(12.34.56.78)"]
        ),
        Ok(())
    );
}

#[test]
fn ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 0],
            [255, 0, 255, 0],
        ))],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("12.34.56.79".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["IpAddress(12.34.56.79)"]
        ),
        Err(webpki::Error::InvalidNetworkMaskConstraint)
    );
}

#[test]
fn ip4_address_san_allowed() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V4(
            [12, 34, 56, 0],
            [255, 255, 255, 0],
        ))],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("12.34.56.78".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["12.34.56.78"],
            &[
                "12.34.56.77",
                "12.34.56.79",
                "0000:0000:0000:0000:0000:ffff:0c22:384e"
            ],
            &["IpAddress(12.34.56.78)"]
        ),
        Ok(())
    );
}

#[test]
fn ip6_address_san_rejected_if_in_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ))],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("2001:db8::1".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &[],
            &["IpAddress(2001:db8::1)"]
        ),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn ip6_address_san_allowed_if_outside_excluded_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ))],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("2001:db9::1".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["2001:0db9:0000:0000:0000:0000:0000:0001"],
            &[],
            &["IpAddress(2001:db9::1)"]
        ),
        Ok(())
    );
}

#[test]
fn ip6_address_san_allowed() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::IpAddress(CidrSubnet::V6(
            [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ))],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![SanType::IpAddress("2001:db9::1".parse().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["2001:0db9:0000:0000:0000:0000:0000:0001"],
            &["12.34.56.78"],
            &["IpAddress(2001:db9::1)"]
        ),
        Ok(())
    );
}

#[test]
fn ip46_mixed_address_san_allowed() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([12, 34, 56, 0], [255, 255, 255, 0])),
            GeneralSubtree::IpAddress(CidrSubnet::V6(
                [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            )),
        ],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(
        vec![
            SanType::IpAddress("12.34.56.78".parse().unwrap()),
            SanType::IpAddress("2001:db9::1".parse().unwrap()),
        ],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["12.34.56.78", "2001:0db9:0000:0000:0000:0000:0000:0001"],
            &[
                "12.34.56.77",
                "12.34.56.79",
                "0000:0000:0000:0000:0000:ffff:0c22:384e"
            ],
            &["IpAddress(12.34.56.78)", "IpAddress(2001:db9::1)"]
        ),
        Ok(())
    );
}

// RFC 5280 § 4.2.1.10: URI constraints apply to the host part of the name,
// matched using the same rules as dNSName constraints. The constraint is a
// bare host/domain (`allowed.example.com` or `.example.com`), not a full URI.
#[test]
fn uri_san_matches_uri_permitted_subtree() {
    // As with dNSName constraints (and Go's matchDomainConstraint, which backs
    // both), a bare constraint matches the exact host and any subdomain of it.
    assert_eq!(
        check_uri_constraint(
            b"allowed.example.com",
            PERMITTED,
            "https://allowed.example.com"
        ),
        Ok(()),
    );
    assert_eq!(
        check_uri_constraint(
            b"allowed.example.com",
            PERMITTED,
            "https://sub.allowed.example.com",
        ),
        Ok(()),
    );
    // A URI that is not below the permitted subtree is rejected.
    assert_eq!(
        check_uri_constraint(
            b"allowed.example.com",
            PERMITTED,
            "https://evil.example.com"
        ),
        Err(webpki::Error::NameConstraintViolation),
    );
}

#[test]
fn uri_san_matches_leading_dot_permitted_subtree() {
    // A leading dot matches subdomains, but not the bare domain itself.
    assert_eq!(
        check_uri_constraint(
            b".allowed.example.com",
            PERMITTED,
            "https://host.allowed.example.com",
        ),
        Ok(()),
    );
    assert_eq!(
        check_uri_constraint(
            b".allowed.example.com",
            PERMITTED,
            "https://allowed.example.com",
        ),
        Err(webpki::Error::NameConstraintViolation),
    );
}

#[test]
fn uri_san_matches_nested_hostname() {
    // A leading dot matches subdomains, but not the bare domain itself.
    assert_eq!(
        check_uri_constraint(
            b"allowed.example.com",
            PERMITTED,
            "https://allowed.example.com",
        ),
        Ok(()),
    );
    assert_eq!(
        check_uri_constraint(
            b"allowed.example.com",
            EXCLUDED,
            "https://host.allowed.example.com",
        ),
        Err(webpki::Error::NameConstraintViolation),
    );
}

#[test]
fn uri_san_ignores_userinfo_and_port() {
    // The host is extracted from the authority, ignoring userinfo and port.
    assert_eq!(
        check_uri_constraint(
            b".allowed.example.com",
            PERMITTED,
            "https://user@host.allowed.example.com:8443/path?q#frag",
        ),
        Ok(()),
    );
}

#[test]
fn uri_san_matches_uri_excluded_subtree() {
    // A URI whose host falls in the excluded subtree is rejected.
    assert_eq!(
        check_uri_constraint(b"evil.example.com", EXCLUDED, "https://evil.example.com"),
        Err(webpki::Error::NameConstraintViolation),
    );
    // A URI outside the excluded subtree is allowed.
    assert_eq!(
        check_uri_constraint(b"evil.example.com", EXCLUDED, "https://good.example.com"),
        Ok(()),
    );
}

#[test]
fn uri_san_without_fqdn_host_rejected() {
    // RFC 5280 requires rejecting a URI SAN that has no authority component, or
    // whose host is an IP address, when a URI constraint applies to it.
    for san in [
        "urn:example:animal",      // no authority component
        "https://127.0.0.1/p",     // IPv4 host
        "https://[2001:db8::1]/p", // IPv6 host
    ] {
        assert_eq!(
            check_uri_constraint(b"allowed.example.com", PERMITTED, san),
            Err(webpki::Error::NameConstraintViolation),
            "expected {san} to be rejected against a permitted subtree",
        );
        assert_eq!(
            check_uri_constraint(b"allowed.example.com", EXCLUDED, san),
            Err(webpki::Error::NameConstraintViolation),
            "expected {san} to be rejected against an excluded subtree",
        );
    }
}

// permittedSubtrees [0] IMPLICIT / excludedSubtrees [1] IMPLICIT
const PERMITTED: u8 = 0xa0;
const EXCLUDED: u8 = 0xa1;

// Build an issuer carrying a single URI name constraint over `constraint`, issue
// an EE cert whose only SAN is `san_uri`, and return the path-building result.
fn check_uri_constraint(
    constraint: &[u8],
    subtrees_tag: u8,
    san_uri: &str,
) -> Result<(), webpki::Error> {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = issuer_params("issuer.example.com").unwrap();
    ca_params
        .custom_extensions
        .push(uri_name_constraints(constraint, subtrees_tag));
    let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).expect("failed to generate CA");

    let ee = generate_cert(vec![SanType::URI(san_uri.try_into().unwrap())], &issuer);
    check_cert(ee.der(), issuer.der(), &[], &[], &[])
}

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// permitted or excluded subtree containing a URI GeneralName. rcgen's
// GeneralSubtree enum doesn't expose a URI variant, so we emit the DER directly.
fn uri_name_constraints(uri: &[u8], subtrees_tag: u8) -> CustomExtension {
    assert!(uri.len() < 128);
    // URI GeneralName: [6] IMPLICIT IA5String
    let mut uri_gn = vec![0x86, uri.len() as u8];
    uri_gn.extend_from_slice(uri);
    // GeneralSubtree SEQUENCE { base GeneralName, ... }
    let mut subtree = vec![0x30, uri_gn.len() as u8];
    subtree.extend_from_slice(&uri_gn);
    // permittedSubtrees [0] or excludedSubtrees [1] IMPLICIT GeneralSubtrees
    let mut subtrees = vec![subtrees_tag, subtree.len() as u8];
    subtrees.extend_from_slice(&subtree);
    // NameConstraints SEQUENCE
    let mut nc = vec![0x30, subtrees.len() as u8];
    nc.extend_from_slice(&subtrees);

    let mut ext = CustomExtension::from_oid_content(&[2, 5, 29, 30], nc);
    ext.set_criticality(true);
    ext
}

#[test]
fn permit_directory_name_not_implemented() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "CN");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert(vec![], &issuer);
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn exclude_directory_name_not_implemented() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "CN");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
    }));
    let ee = generate_cert(vec![], &issuer);
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn invalid_dns_name_matching() {
    let issuer = make_issuer(None);
    let ee = generate_cert(
        vec![
            SanType::DnsName("{invalid}.example.com".try_into().unwrap()),
            SanType::DnsName("dns.example.com".try_into().unwrap()),
        ],
        &issuer,
    );
    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &["dns.example.com"],
            &[],
            &[
                "DnsName(\"{invalid}.example.com\")",
                "DnsName(\"dns.example.com\")"
            ]
        ),
        Ok(())
    );
}

fn generate_cert(sans: Vec<SanType>, issuer: &CertifiedIssuer<'_, KeyPair>) -> Certificate {
    generate_cert_with_names(None, None, sans, issuer)
}

fn generate_cert_with_names(
    subject_cn: Option<&str>,
    subject_email: Option<&str>,
    sans: Vec<SanType>,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> Certificate {
    let (not_before, not_after) = (date_time_ymd(1970, 1, 1), date_time_ymd(2050, 1, 1));

    // Generate end entity certificate
    let ee_key = KeyPair::generate().unwrap();
    let mut ee_params = CertificateParams::new([]).expect("failed to create EE params");
    ee_params.subject_alt_names = sans;
    if let Some(cn) = subject_cn {
        ee_params.distinguished_name.push(DnType::CommonName, cn);
    }
    if let Some(email) = subject_email {
        ee_params
            .distinguished_name
            .push(DnType::from_oid(OID_EMAIL_ADDRESS), email);
    }
    ee_params
        .distinguished_name
        .push(DnType::OrganizationName, "test");
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.not_before = not_before;
    ee_params.not_after = not_after;

    ee_params
        .signed_by(&ee_key, issuer)
        .expect("failed to generate EE cert")
}

fn make_issuer(name_constraints: Option<NameConstraints>) -> CertifiedIssuer<'static, KeyPair> {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = issuer_params("issuer.example.com").unwrap();
    ca_params.name_constraints = name_constraints;
    CertifiedIssuer::self_signed(ca_params, ca_key).expect("failed to generate CA cert")
}

// OID for emailAddress in subject DN (pkcs9-emailAddress)
const OID_EMAIL_ADDRESS: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];
