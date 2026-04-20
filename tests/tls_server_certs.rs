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
#![cfg(all(feature = "alloc", any(feature = "ring", feature = "aws-lc-rs")))]

use core::time::Duration;

use pki_types::{CertificateDer, ServerName, UnixTime};
use rcgen::{
    Certificate, CertificateParams, CertifiedIssuer, CustomExtension, DnType, GeneralSubtree, IsCa,
    KeyPair, NameConstraints, SanType, date_time_ymd,
};
use webpki::{InvalidNameContext, KeyUsage, anchor_from_trusted_cert};

mod common;
use common::issuer_params;

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

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// permittedSubtree containing a URI GeneralName. rcgen's GeneralSubtree enum
// doesn't expose a URI variant, so we emit the DER directly.
fn uri_permitted_name_constraints(uri: &[u8]) -> CustomExtension {
    uri_name_constraints(uri, 0xa0) // permittedSubtrees [0] IMPLICIT
}

// Hand-encode a NameConstraints extension (OID 2.5.29.30) with a single
// excludedSubtree containing a URI GeneralName.
fn uri_excluded_name_constraints(uri: &[u8]) -> CustomExtension {
    uri_name_constraints(uri, 0xa1) // excludedSubtrees [1] IMPLICIT
}

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

    let ee_der = CertificateDer::from(ee);
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let cert = webpki::EndEntityCert::try_from(&ee_der).unwrap();
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &[],
        time,
        KeyUsage::server_auth(),
        None,
        None,
    )?;

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

fn make_issuer(name_constraints: Option<NameConstraints>) -> CertifiedIssuer<'static, KeyPair> {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = issuer_params("issuer.example.com").unwrap();
    ca_params.name_constraints = name_constraints;
    CertifiedIssuer::self_signed(ca_params, ca_key).expect("failed to generate CA cert")
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

// OID for emailAddress in subject DN (pkcs9-emailAddress)
const OID_EMAIL_ADDRESS: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];

// DO NOT EDIT BELOW: generated by tests/generate.py

#[test]
fn no_name_constraints() {
    let ee = include_bytes!("tls_server_certs/no_name_constraints.ee.der");
    let ca = include_bytes!("tls_server_certs/no_name_constraints.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["dns.example.com"],
            &["subject.example.com"],
            &["DnsName(\"dns.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn additional_dns_labels() {
    let ee = include_bytes!("tls_server_certs/additional_dns_labels.ee.der");
    let ca = include_bytes!("tls_server_certs/additional_dns_labels.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
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
    let ee = include_bytes!("tls_server_certs/disallow_dns_san.ee.der");
    let ca = include_bytes!("tls_server_certs/disallow_dns_san.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &["DnsName(\"disallowed.example.com\")"]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn allow_subject_common_name() {
    let ee = include_bytes!("tls_server_certs/allow_subject_common_name.ee.der");
    let ca = include_bytes!("tls_server_certs/allow_subject_common_name.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &["allowed.example.com"], &[]),
        Ok(())
    );
}

#[test]
fn allow_dns_san() {
    let ee = include_bytes!("tls_server_certs/allow_dns_san.ee.der");
    let ca = include_bytes!("tls_server_certs/allow_dns_san.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["allowed.example.com"],
            &[],
            &["DnsName(\"allowed.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn allow_dns_san_and_subject_common_name() {
    let ee = include_bytes!("tls_server_certs/allow_dns_san_and_subject_common_name.ee.der");
    let ca = include_bytes!("tls_server_certs/allow_dns_san_and_subject_common_name.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["allowed-san.example.com"],
            &["allowed-cn.example.com"],
            &["DnsName(\"allowed-san.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn disallow_dns_san_and_allow_subject_common_name() {
    let ee =
        include_bytes!("tls_server_certs/disallow_dns_san_and_allow_subject_common_name.ee.der");
    let ca =
        include_bytes!("tls_server_certs/disallow_dns_san_and_allow_subject_common_name.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
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
    let ee = include_bytes!(
        "tls_server_certs/we_incorrectly_ignore_name_constraints_on_name_in_subject.ee.der"
    );
    let ca = include_bytes!(
        "tls_server_certs/we_incorrectly_ignore_name_constraints_on_name_in_subject.ca.der"
    );
    assert_eq!(check_cert(ee, ca, &[], &[], &[]), Ok(()));
}

#[test]
fn reject_constraints_on_unimplemented_names() {
    let ee = include_bytes!("tls_server_certs/reject_constraints_on_unimplemented_names.ee.der");
    let ca = include_bytes!("tls_server_certs/reject_constraints_on_unimplemented_names.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn we_ignore_constraints_on_names_that_do_not_appear_in_cert() {
    let ee = include_bytes!(
        "tls_server_certs/we_ignore_constraints_on_names_that_do_not_appear_in_cert.ee.der"
    );
    let ca = include_bytes!(
        "tls_server_certs/we_ignore_constraints_on_names_that_do_not_appear_in_cert.ca.der"
    );
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["notexample.com"],
            &["example.com"],
            &["DnsName(\"notexample.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn wildcard_san_accepted_if_in_subtree() {
    let ee = include_bytes!("tls_server_certs/wildcard_san_accepted_if_in_subtree.ee.der");
    let ca = include_bytes!("tls_server_certs/wildcard_san_accepted_if_in_subtree.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["bob.example.com", "jane.example.com"],
            &["example.com", "uh.oh.example.com"],
            &["DnsName(\"*.example.com\")"]
        ),
        Ok(())
    );
}

#[test]
fn wildcard_san_rejected_if_in_excluded_subtree() {
    let ee = include_bytes!("tls_server_certs/wildcard_san_rejected_if_in_excluded_subtree.ee.der");
    let ca = include_bytes!("tls_server_certs/wildcard_san_rejected_if_in_excluded_subtree.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &["DnsName(\"*.example.com\")"]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn ip4_address_san_rejected_if_in_excluded_subtree() {
    let ee =
        include_bytes!("tls_server_certs/ip4_address_san_rejected_if_in_excluded_subtree.ee.der");
    let ca =
        include_bytes!("tls_server_certs/ip4_address_san_rejected_if_in_excluded_subtree.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &["IpAddress(12.34.56.78)"]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn ip4_address_san_allowed_if_outside_excluded_subtree() {
    let ee = include_bytes!(
        "tls_server_certs/ip4_address_san_allowed_if_outside_excluded_subtree.ee.der"
    );
    let ca = include_bytes!(
        "tls_server_certs/ip4_address_san_allowed_if_outside_excluded_subtree.ca.der"
    );
    assert_eq!(
        check_cert(ee, ca, &["12.34.56.78"], &[], &["IpAddress(12.34.56.78)"]),
        Ok(())
    );
}

#[test]
fn ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask() {
    let ee = include_bytes!(
        "tls_server_certs/ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask.ee.der"
    );
    let ca = include_bytes!(
        "tls_server_certs/ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask.ca.der"
    );
    assert_eq!(
        check_cert(ee, ca, &[], &[], &["IpAddress(12.34.56.79)"]),
        Err(webpki::Error::InvalidNetworkMaskConstraint)
    );
}

#[test]
fn ip4_address_san_allowed() {
    let ee = include_bytes!("tls_server_certs/ip4_address_san_allowed.ee.der");
    let ca = include_bytes!("tls_server_certs/ip4_address_san_allowed.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
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
    let ee =
        include_bytes!("tls_server_certs/ip6_address_san_rejected_if_in_excluded_subtree.ee.der");
    let ca =
        include_bytes!("tls_server_certs/ip6_address_san_rejected_if_in_excluded_subtree.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &["IpAddress(2001:db8::1)"]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn ip6_address_san_allowed_if_outside_excluded_subtree() {
    let ee = include_bytes!(
        "tls_server_certs/ip6_address_san_allowed_if_outside_excluded_subtree.ee.der"
    );
    let ca = include_bytes!(
        "tls_server_certs/ip6_address_san_allowed_if_outside_excluded_subtree.ca.der"
    );
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["2001:0db9:0000:0000:0000:0000:0000:0001"],
            &[],
            &["IpAddress(2001:db9::1)"]
        ),
        Ok(())
    );
}

#[test]
fn ip6_address_san_allowed() {
    let ee = include_bytes!("tls_server_certs/ip6_address_san_allowed.ee.der");
    let ca = include_bytes!("tls_server_certs/ip6_address_san_allowed.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
            &["2001:0db9:0000:0000:0000:0000:0000:0001"],
            &["12.34.56.78"],
            &["IpAddress(2001:db9::1)"]
        ),
        Ok(())
    );
}

#[test]
fn ip46_mixed_address_san_allowed() {
    let ee = include_bytes!("tls_server_certs/ip46_mixed_address_san_allowed.ee.der");
    let ca = include_bytes!("tls_server_certs/ip46_mixed_address_san_allowed.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
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

#[test]
fn permit_directory_name_not_implemented() {
    let ee = include_bytes!("tls_server_certs/permit_directory_name_not_implemented.ee.der");
    let ca = include_bytes!("tls_server_certs/permit_directory_name_not_implemented.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn exclude_directory_name_not_implemented() {
    let ee = include_bytes!("tls_server_certs/exclude_directory_name_not_implemented.ee.der");
    let ca = include_bytes!("tls_server_certs/exclude_directory_name_not_implemented.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[], &[], &[]),
        Err(webpki::Error::NameConstraintViolation)
    );
}

#[test]
fn invalid_dns_name_matching() {
    let ee = include_bytes!("tls_server_certs/invalid_dns_name_matching.ee.der");
    let ca = include_bytes!("tls_server_certs/invalid_dns_name_matching.ca.der");
    assert_eq!(
        check_cert(
            ee,
            ca,
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
