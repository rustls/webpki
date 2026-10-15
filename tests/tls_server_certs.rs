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

/// Since we don't have real constraint matching implemented for URI names, fail closed.
#[test]
fn uri_san_rejected_against_uri_permitted_subtree() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = issuer_params("issuer.example.com").unwrap();
    ca_params
        .custom_extensions
        .push(uri_permitted_name_constraints(
            b"https://allowed.example.com",
        ));
    let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).expect("failed to generate CA");

    let ee = generate_cert(
        vec![SanType::URI("https://evil.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation),
    );
}

/// Since we don't have real constraint matching implemented for URI names, fail closed.
#[test]
fn uri_san_rejected_against_uri_excluded_subtree() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = issuer_params("issuer.example.com").unwrap();
    ca_params
        .custom_extensions
        .push(uri_excluded_name_constraints(b"https://evil.example.com"));
    let issuer = CertifiedIssuer::self_signed(ca_params, ca_key).expect("failed to generate CA");

    let ee = generate_cert(
        vec![SanType::URI("https://evil.example.com".try_into().unwrap())],
        &issuer,
    );
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation),
    );
}

#[test]
fn empty_name_constraint_sequences_rejected() {
    let permitted = name_constraint_subtrees(b"example.com", DNS_NAME_TAG, PERMITTED_SUBTREES_TAG);
    let excluded = name_constraint_subtrees(b"example.com", DNS_NAME_TAG, EXCLUDED_SUBTREES_TAG);
    let empty_permitted = der_tlv(PERMITTED_SUBTREES_TAG, &[]);
    let empty_excluded = der_tlv(EXCLUDED_SUBTREES_TAG, &[]);

    let cases = [
        ("neither subtree field present", vec![]),
        (
            "empty permittedSubtrees",
            [empty_permitted.as_slice(), excluded.as_slice()].concat(),
        ),
        (
            "empty excludedSubtrees",
            [permitted.as_slice(), empty_excluded.as_slice()].concat(),
        ),
        (
            "both subtree fields empty",
            [empty_permitted.as_slice(), empty_excluded.as_slice()].concat(),
        ),
    ];

    for (description, subtrees) in cases {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = issuer_params("issuer.example.com").unwrap();
        ca_params
            .custom_extensions
            .push(name_constraints_extension(&subtrees));
        let issuer =
            CertifiedIssuer::self_signed(ca_params, ca_key).expect("failed to generate CA");
        let ee = generate_cert(vec![], &issuer);

        assert_eq!(
            check_cert(ee.der(), issuer.der(), &[], &[], &[]),
            Err(webpki::Error::MalformedNameConstraint),
            "{description}",
        );
    }
}

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// permittedSubtree containing a URI GeneralName. rcgen's GeneralSubtree enum
// doesn't expose a URI variant, so we emit the DER directly.
fn uri_permitted_name_constraints(uri: &[u8]) -> CustomExtension {
    uri_name_constraints(uri, PERMITTED_SUBTREES_TAG)
}

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// excludedSubtree containing a URI GeneralName.
fn uri_excluded_name_constraints(uri: &[u8]) -> CustomExtension {
    uri_name_constraints(uri, EXCLUDED_SUBTREES_TAG)
}

fn uri_name_constraints(uri: &[u8], subtrees_tag: u8) -> CustomExtension {
    let subtrees = name_constraint_subtrees(uri, UNIFORM_RESOURCE_IDENTIFIER_TAG, subtrees_tag);
    name_constraints_extension(&subtrees)
}

fn name_constraint_subtrees(name: &[u8], name_tag: u8, subtrees_tag: u8) -> Vec<u8> {
    let general_name = der_tlv(name_tag, name);
    let subtree = der_tlv(SEQUENCE_TAG, &general_name);
    der_tlv(subtrees_tag, &subtree)
}

fn name_constraints_extension(subtrees: &[u8]) -> CustomExtension {
    let nc = der_tlv(SEQUENCE_TAG, subtrees);
    let mut ext = CustomExtension::from_oid_content(&[2, 5, 29, 30], nc);
    ext.set_criticality(true);
    ext
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut encoded = vec![tag, value.len() as u8];
    encoded.extend_from_slice(value);
    encoded
}

const SEQUENCE_TAG: u8 = 0x30;
const DNS_NAME_TAG: u8 = 0x82; // [2] IMPLICIT IA5String
const UNIFORM_RESOURCE_IDENTIFIER_TAG: u8 = 0x86; // [6] IMPLICIT IA5String
const PERMITTED_SUBTREES_TAG: u8 = 0xa0; // [0] IMPLICIT GeneralSubtrees
const EXCLUDED_SUBTREES_TAG: u8 = 0xa1; // [1] IMPLICIT GeneralSubtrees

#[test]
fn permit_directory_name_match() {
    // Constraint = [CN] is a prefix of EE = [CN, O=test].
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "subject.example.com");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert_with_names(Some("subject.example.com"), None, vec![], &issuer);
    assert_eq!(check_cert(ee.der(), issuer.der(), &[], &[], &[]), Ok(()));
}

#[test]
fn permit_directory_name_no_match() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "different value");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert_with_names(Some("subject.example.com"), None, vec![], &issuer);
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn exclude_directory_name_match() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "subject.example.com");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
    }));
    let ee = generate_cert_with_names(Some("subject.example.com"), None, vec![], &issuer);
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn exclude_directory_name_no_match_is_still_rejected() {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "different value");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
    }));
    let ee = generate_cert_with_names(Some("subject.example.com"), None, vec![], &issuer);
    assert_eq!(
        check_cert(ee.der(), issuer.der(), &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn permit_directory_name_exact_match() {
    // Constraint matches the entire EE DN, not just a prefix.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "subject.example.com");
    dn.push(DnType::OrganizationName, "test");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
        excluded_subtrees: vec![],
    }));
    let ee = generate_cert_with_names(Some("subject.example.com"), None, vec![], &issuer);
    assert_eq!(check_cert(ee.der(), issuer.der(), &[], &[], &[]), Ok(()));
}

#[test]
fn permit_directory_name_deeper_subtree() {
    // Constraint is shorter than EE DN; EE has extra RDN(s) at the tail.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "subject.example.com");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(dn)],
        excluded_subtrees: vec![],
    }));
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
            &[],
            &["DnsName(\"dns.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn permitted_directory_name_skips_empty_subject_but_checks_dns_sans() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DirectoryName(country_name("US")),
            GeneralSubtree::DnsName("example.com".into()),
        ],
        excluded_subtrees: vec![],
    }));
    for (dns, expected) in [
        ("www.example.com", Ok(())),
        (
            "elsewhere.test",
            Err(webpki::Error::NameConstraintViolation),
        ),
    ] {
        assert_eq!(
            check_directory_name_cert(
                &issuer,
                DistinguishedName::new(),
                vec![SanType::DnsName(dns.try_into().unwrap())],
                None,
            ),
            expected,
        );
    }
}

#[test]
fn permitted_directory_name_checks_every_san_and_subject() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(country_name("US"))],
        excluded_subtrees: vec![],
    }));
    // A matching subject cannot hide a mismatching SAN, and a matching SAN
    // cannot hide a mismatching subject. Empty subjects still constrain SANs.
    for (subject, countries, expected) in [
        (DistinguishedName::new(), vec![b"US"], Ok(())),
        (
            DistinguishedName::new(),
            vec![b"GB"],
            Err(webpki::Error::NameConstraintViolation),
        ),
        (
            DistinguishedName::new(),
            vec![b"US", b"GB"],
            Err(webpki::Error::NameConstraintViolation),
        ),
        (
            country_name("US"),
            vec![b"GB"],
            Err(webpki::Error::NameConstraintViolation),
        ),
        (
            country_name("GB"),
            vec![b"US"],
            Err(webpki::Error::NameConstraintViolation),
        ),
        (country_name("US"), vec![b"US"], Ok(())),
    ] {
        assert_eq!(
            check_directory_name_cert(
                &issuer,
                subject,
                vec![],
                Some(directory_name_sans(&countries))
            ),
            expected,
        );
    }
}

#[test]
fn permitted_directory_name_accepts_any_matching_subtree() {
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DirectoryName(country_name("GB")),
            GeneralSubtree::DirectoryName(country_name("US")),
        ],
        excluded_subtrees: vec![],
    }));
    assert_eq!(
        check_directory_name_cert(&issuer, country_name("US"), vec![], None),
        Ok(())
    );
}

#[test]
fn excluded_directory_name_rejects_even_without_presented_directory_names() {
    for constraint in [DistinguishedName::new(), country_name("US")] {
        let issuer = make_issuer(Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName("example.com".into())],
            excluded_subtrees: vec![GeneralSubtree::DirectoryName(constraint)],
        }));
        for subject in [
            DistinguishedName::new(),
            country_name("GB"),
            country_name("US"),
        ] {
            assert_eq!(
                check_directory_name_cert(
                    &issuer,
                    subject,
                    vec![SanType::DnsName("www.example.com".try_into().unwrap())],
                    None,
                ),
                Err(webpki::Error::NameConstraintViolation),
            );
        }
    }
}

#[test]
fn excluded_directory_name_cannot_be_bypassed_by_missing_normalization() {
    let mut excluded = DistinguishedName::new();
    excluded.push(DnType::OrganizationName, "Straße");
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![],
        excluded_subtrees: vec![GeneralSubtree::DirectoryName(excluded)],
    }));
    let mut subject = DistinguishedName::new();
    subject.push(DnType::OrganizationName, "Strasse");
    assert_eq!(
        check_directory_name_cert(&issuer, subject, vec![], None),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn unsupported_directory_name_encoding_is_only_rejected_when_constrained() {
    let mut subject = DistinguishedName::new();
    subject.push(
        DnType::CountryName,
        rcgen::DnValue::BmpString("US".try_into().unwrap()),
    );
    let unconstrained = make_issuer(None);
    assert_eq!(
        check_directory_name_cert(&unconstrained, subject.clone(), vec![], None),
        Ok(())
    );
    let constrained = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(country_name("US"))],
        excluded_subtrees: vec![],
    }));
    assert_eq!(
        check_directory_name_cert(&constrained, subject, vec![], None),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn tuntrust_style_directory_dns_and_ip_constraints() {
    // The combination reported in rustls/webpki#19: permitted C=TN and DNS:tn,
    // with every IPv4 and IPv6 address excluded.
    let issuer = make_issuer(Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DirectoryName(country_name("TN")),
            GeneralSubtree::DnsName("tn".into()),
        ],
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress("0.0.0.0/0".parse().unwrap()),
            GeneralSubtree::IpAddress("::/0".parse().unwrap()),
        ],
    }));
    for (country, san, expected) in [
        (
            "TN",
            SanType::DnsName("validovssl.tuntrust.tn".try_into().unwrap()),
            Ok(()),
        ),
        (
            "GB",
            SanType::DnsName("validovssl.tuntrust.tn".try_into().unwrap()),
            Err(webpki::Error::NameConstraintViolation),
        ),
        (
            "TN",
            SanType::DnsName("example.com".try_into().unwrap()),
            Err(webpki::Error::NameConstraintViolation),
        ),
        (
            "TN",
            SanType::IpAddress("192.0.2.1".parse().unwrap()),
            Err(webpki::Error::NameConstraintViolation),
        ),
        (
            "TN",
            SanType::IpAddress("2001:db8::1".parse().unwrap()),
            Err(webpki::Error::NameConstraintViolation),
        ),
    ] {
        assert_eq!(
            check_directory_name_cert(&issuer, country_name(country), vec![san], None),
            expected
        );
    }
}

fn country_name(country: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, country);
    dn
}

fn check_directory_name_cert(
    issuer: &CertifiedIssuer<'_, KeyPair>,
    subject: DistinguishedName,
    sans: Vec<SanType>,
    custom_san: Option<CustomExtension>,
) -> Result<(), webpki::Error> {
    let mut params = CertificateParams::new([]).unwrap();
    params.distinguished_name = subject;
    params.subject_alt_names = sans;
    params.custom_extensions.extend(custom_san);
    params.not_before = date_time_ymd(1970, 1, 1);
    params.not_after = date_time_ymd(2050, 1, 1);
    let ee = params
        .signed_by(&KeyPair::generate().unwrap(), issuer)
        .unwrap();
    check_cert(ee.der(), issuer.der(), &[], &[], &[])
}

fn directory_name_sans(countries: &[&[u8; 2]]) -> CustomExtension {
    // rcgen has no directoryName SAN variant. Each entry is an explicitly
    // tagged Name containing a single PrintableString countryName attribute.
    let mut names = Vec::new();
    for country in countries {
        names.extend_from_slice(&[
            0xa4, 0x0f, 0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
            0x02,
        ]);
        names.extend_from_slice(*country);
    }
    assert!(names.len() < 128);
    let mut value = vec![0x30, u8::try_from(names.len()).unwrap()];
    value.extend(names);
    let mut extension = CustomExtension::from_oid_content(&[2, 5, 29, 17], value);
    extension.set_criticality(true);
    extension
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

#[test]
fn presented_names_escape_control_characters() {
    // `InvalidNameContext::presented` is public API built by formatting the SAN
    // entries, and a certificate can carry anything there. Whatever a caller
    // does with those strings, they should not contain raw control characters.
    let issuer = make_issuer(None);
    let ee = generate_cert_with_names(
        None,
        None,
        vec![SanType::DnsName(
            "a\r\nInjected: header\u{1b}[31m".try_into().unwrap(),
        )],
        &issuer,
    );

    assert_eq!(
        check_cert(
            ee.der(),
            issuer.der(),
            &[],
            &["real.example.com"],
            &[r#"DnsName("a\r\nInjected: header\u{1b}[31m")"#],
        ),
        Ok(())
    );
}
