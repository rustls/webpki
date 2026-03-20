// Copyright 2023 Daniel McCarney.
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

use core::time::Duration;

use pki_types::{
    CertificateDer, CertificateRevocationListDer, SignatureVerificationAlgorithm, UnixTime,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CertifiedIssuer, CrlDistributionPoint, CrlIssuingDistributionPoint, CustomExtension, DnType,
    IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams,
    SerialNumber, SignatureAlgorithm, date_time_ymd,
};
#[cfg(feature = "alloc")]
use webpki::OwnedCertRevocationList;
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, ExtendedKeyUsage, RevocationCheckDepth,
    RevocationOptions, RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};
use x509_parser::oid_registry;

static ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    rustls_ring::ECDSA_P256_SHA256,
    rustls_aws_lc_rs::ECDSA_P256_SHA256,
];

fn check_cert(
    ee: &[u8],
    intermediates: &[&[u8]],
    ca: &[u8],
    revocation: Option<RevocationOptions<'_>>,
) -> Result<(), webpki::Error> {
    let ca = CertificateDer::from(ca);
    let anchors = &[anchor_from_trusted_cert(&ca).unwrap()];
    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let intermediates = intermediates
        .iter()
        .map(|cert| CertificateDer::from(*cert))
        .collect::<Vec<_>>();

    cert.verify_for_usage(
        ALGS,
        anchors,
        &intermediates,
        time,
        &ExtendedKeyUsage::client_auth(),
        revocation,
        None,
    )
    .map(|_| ())
}

#[test]
fn no_crls_test() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            None,
        ),
        Ok(())
    );
}

#[test]
fn no_relevant_crl_ee_depth_allow_unknown() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&no_match_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

#[test]
fn no_relevant_crl_ee_depth_forbid_unknown() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&no_match_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

#[test]
fn ee_not_revoked_ee_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_not_revoked_crl = chain
        .int_a
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_not_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

#[test]
fn ee_not_revoked_chain_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_not_revoked_crl = chain
        .int_a
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_not_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

#[test]
fn ee_revoked_badsig_ee_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_badsig = chain.int_a.generate_crl_bad_sig(chain.ee_serial.clone());

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_badsig).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::InvalidCrlSignatureForPublicKey)
    );
}

#[test]
fn ee_revoked_wrong_ku_ee_depth() {
    let chain = CertChain::no_crl_key_usage("no_crl_ku_chain");

    let ee_revoked_crl = chain
        .int_a
        .generate_crl_with_crl_sign(chain.ee_serial.clone());

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::IssuerNotCrlSigner)
    );
}

#[test]
fn ee_not_revoked_wrong_ku_ee_depth() {
    let chain = CertChain::no_crl_key_usage("no_crl_ku_chain");

    let ee_not_revoked_crl = chain
        .int_a
        .generate_crl_with_crl_sign(SerialNumber::from(12345));

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_not_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::IssuerNotCrlSigner)
    );
}

#[test]
fn ee_revoked_no_ku_ee_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

#[test]
fn ee_revoked_crl_ku_ee_depth() {
    let chain = CertChain::with_crl_key_usage("ku_chain");

    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

#[test]
fn no_crls_test_chain_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            None,
        ),
        Ok(())
    );
}

#[test]
fn no_relevant_crl_chain_depth_allow_unknown() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&no_match_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

#[test]
fn no_relevant_crl_chain_depth_forbid_unknown() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&no_match_crl).unwrap(),
    )];
    let revocation = RevocationOptionsBuilder::new(crls).unwrap().build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

#[test]
fn int_not_revoked_chain_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_not_revoked_crl = chain
        .int_b
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&int_not_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

#[test]
fn int_not_revoked_chain_depth_forbid_unknown() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_not_revoked_crl = chain
        .int_b
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&int_not_revoked_crl).unwrap(),
    )];
    let revocation = RevocationOptionsBuilder::new(crls).unwrap().build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

#[test]
fn int_revoked_badsig_chain_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_revoked_badsig = chain.int_b.generate_crl_bad_sig(chain.int_a.serial.clone());

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&int_revoked_badsig).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::InvalidCrlSignatureForPublicKey)
    );
}

#[test]
fn int_revoked_wrong_ku_chain_depth() {
    let chain = CertChain::no_crl_key_usage("no_crl_ku_chain");

    let int_revoked_crl = chain
        .int_b
        .generate_crl_with_crl_sign(chain.int_a.serial.clone());

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&int_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::IssuerNotCrlSigner)
    );
}

#[test]
fn ee_revoked_chain_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_chain_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

#[test]
fn int_revoked_no_ku_chain_depth() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_revoked_crl = chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&int_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

#[test]
fn int_revoked_crl_ku_chain_depth() {
    let chain = CertChain::with_crl_key_usage("ku_chain");

    let int_revoked_crl = chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&int_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

#[test]
fn ee_revoked_topbit_serial() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_topbit_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert_topbit.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

// Chain with no CRL distribution points in certs, but CRL has an IDP.
// CRL should still be considered relevant because certs have no DP.
#[test]
fn ee_no_dp_crl_idp() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_crl = chain.int_a.generate_crl(
        SerialNumber::from(0xFFFF),
        Some(CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: VALID_CRL_DP_URIS.iter().map(|s| s.to_string()).collect(),
            },
            scope: None,
        }),
        None,
    );

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

// Chain with CRL distribution points in certs, CRL has no IDP.
// CRL should be considered relevant because CRL without IDP covers "everything".
#[test]
fn ee_not_revoked_crl_no_idp() {
    let chain = CertChain::with_crl_dps(
        "dp_chain",
        VALID_CERT_CRL_DP_URIS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    );
    let ee_crl = chain
        .int_a
        .generate_crl(SerialNumber::from(0xFFFF), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

// Chain with CRL distribution points in certs, CRL has no IDP.
// EE is revoked, so should return CertRevoked.
#[test]
fn ee_revoked_crl_no_idp() {
    let chain = CertChain::with_crl_dps(
        "dp_chain",
        VALID_CERT_CRL_DP_URIS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    );
    let ee_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

// Chain with CRL distribution points in certs, CRL has non-matching IDP.
// CRL should not be considered relevant, so UnknownRevocationStatus.
#[test]
fn ee_crl_mismatched_idp_unknown_status() {
    let chain = CertChain::with_crl_dps(
        "dp_chain",
        VALID_CERT_CRL_DP_URIS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    );
    let ee_crl = chain.int_a.generate_crl(
        SerialNumber::from(0xFFFF),
        Some(CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: vec!["http://does.not.match.example.com".to_string()],
            },
            scope: None,
        }),
        None,
    );

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

// Chain with CRL distribution points in certs, CRL has matching IDP.
// CRL should be considered relevant, EE is not revoked, so OK.
#[test]
fn ee_dp_idp_match() {
    let dp_uris = vec!["http://example.com/valid.crl".to_string()];
    let chain = CertChain::with_crl_dps("dp_chain", dp_uris.clone());
    let ee_crl = chain.int_a.generate_crl(
        SerialNumber::from(0xFFFF),
        Some(CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint { uris: dp_uris },
            scope: None,
        }),
        None,
    );

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

// Chain with indirect CRL distribution point in certs.
// CRL is not indirect, so should not be considered relevant.
#[test]
fn ee_indirect_dp_unknown_status() {
    let ee = include_bytes!("client_auth_revocation/indirect_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/indirect_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/indirect_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/indirect_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(
            include_bytes!("client_auth_revocation/ee_indirect_dp_unknown_status.crl.der")
                .as_slice(),
        )
        .unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(ee, intermediates, ca, Some(revocation)),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

// Chain with reason-sharded CRL distribution point in certs.
// CRL is not reason-sharded, so should not be considered relevant.
#[test]
fn ee_reasons_dp_unknown_status() {
    let ee = include_bytes!("client_auth_revocation/reasons_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/reasons_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/reasons_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/reasons_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(
            include_bytes!("client_auth_revocation/ee_reasons_dp_unknown_status.crl.der")
                .as_slice(),
        )
        .unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(ee, intermediates, ca, Some(revocation)),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

// Chain with relative-name CRL distribution point in certs (no full_name).
// CRL has full_name IDP, so should not be considered relevant.
#[test]
fn ee_nofullname_dp_unknown_status() {
    let ee = include_bytes!("client_auth_revocation/nofullname_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/nofullname_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/nofullname_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/nofullname_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(
            include_bytes!("client_auth_revocation/ee_nofullname_dp_unknown_status.crl.der")
                .as_slice(),
        )
        .unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(ee, intermediates, ca, Some(revocation)),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

// Chain with invalid CRL distribution point in certs (no full_name, no crl_issuer).
// Cannot match any CRL, so should result in unknown revocation status.
#[test]
fn ee_dp_invalid() {
    let ee = include_bytes!("client_auth_revocation/invalid_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/invalid_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/invalid_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/invalid_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(
            include_bytes!("client_auth_revocation/ee_dp_invalid.crl.der").as_slice(),
        )
        .unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();

    assert_eq!(
        check_cert(ee, intermediates, ca, Some(revocation)),
        Err(webpki::Error::UnknownRevocationStatus)
    );
}

// Use an expired CRL but don't enforce expiration policy (default is to ignore).
// Should be OK because we don't enforce expiration.
#[test]
fn expired_crl_ignore_expiration() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let expired_next_update = 0x1FED_F00D - 1;
    let ee_crl =
        chain
            .int_a
            .generate_crl(SerialNumber::from(0xFFFF), None, Some(expired_next_update));

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Ok(())
    );
}

#[test]
fn ee_revoked_expired_crl() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    // Use a next_update that's after this_update but before verification time
    // to create an expired CRL. Verification time is 0x1FED_F00D.
    let expired_next_update = 0x1FED_F00D - 1;
    let ee_revoked_crl =
        chain
            .int_a
            .generate_crl(chain.ee_serial.clone(), None, Some(expired_next_update));

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
        .build();

    assert!(matches!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CrlExpired { .. })
    ));
}

// Cert has two normal DPs; first doesn't match IDP, second does.
// Proves the outer cert_dp loop continues to the next DP when URIs don't match.
#[test]
fn ee_revoked_multi_dp_second_matches() {
    let chain = CertChain::with_cert_dps(
        "multi_dp_chain",
        vec![
            CrlDistributionPoint {
                uris: vec![NON_MATCHING_URI.to_string()],
            },
            CrlDistributionPoint {
                uris: vec![MATCHING_URI.to_string()],
            },
        ],
    );

    assert_eq!(
        check_custom_ee_revoked(
            &chain,
            &chain.ee_cert,
            chain.ee_serial.clone(),
            matching_idp()
        ),
        Err(webpki::Error::CertRevoked)
    );
}

// First DP has reasons (should be skipped), second is a valid match.
// Proves that a reason-partitioned DP is skipped via continue, not return false.
#[test]
fn ee_revoked_reasons_dp_then_valid_dp() {
    let chain = CertChain::no_key_usages("reasons_then_valid");
    let dp_der = build_crl_dps_extension(&[
        build_reasons_dp(NON_MATCHING_URI),
        build_uri_dp(MATCHING_URI),
    ]);
    let (ee_cert, ee_serial) = chain.generate_ee_with_custom_crl_dps(dp_der);

    assert_eq!(
        check_custom_ee_revoked(&chain, &ee_cert, ee_serial, matching_idp()),
        Err(webpki::Error::CertRevoked)
    );
}

// First DP is indirect (cRLIssuer, should be skipped), second is a valid match.
// Proves that an indirect CRL DP is skipped via continue, not return false.
#[test]
fn ee_revoked_indirect_dp_then_valid_dp() {
    let chain = CertChain::no_key_usages("indirect_then_valid");
    let dp_der = build_crl_dps_extension(&[build_indirect_dp(), build_uri_dp(MATCHING_URI)]);
    let (ee_cert, ee_serial) = chain.generate_ee_with_custom_crl_dps(dp_der);

    assert_eq!(
        check_custom_ee_revoked(&chain, &ee_cert, ee_serial, matching_idp()),
        Err(webpki::Error::CertRevoked)
    );
}

// First DP has a relative name (no fullName, should be skipped), second is a valid match.
// Proves that a DP without fullName is skipped via continue, not return false.
#[test]
fn ee_revoked_nofullname_dp_then_valid_dp() {
    let chain = CertChain::no_key_usages("nofullname_then_valid");
    let dp_der = build_crl_dps_extension(&[build_relative_name_dp(), build_uri_dp(MATCHING_URI)]);
    let (ee_cert, ee_serial) = chain.generate_ee_with_custom_crl_dps(dp_der);

    assert_eq!(
        check_custom_ee_revoked(&chain, &ee_cert, ee_serial, matching_idp()),
        Err(webpki::Error::CertRevoked)
    );
}

struct CertChain {
    root: CertifiedIssuer<'static, KeyPair>,
    int_b: Intermediate,
    int_a: Intermediate,
    ee_cert: Certificate,
    ee_serial: SerialNumber,
    ee_cert_topbit: Certificate,
    ee_topbit_serial: SerialNumber,
}

impl CertChain {
    fn no_key_usages(chain_name: &str) -> Self {
        Self::generate(chain_name, vec![], vec![])
    }

    fn no_crl_key_usage(chain_name: &str) -> Self {
        Self::generate(
            chain_name,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ],
            vec![],
        )
    }

    fn with_crl_key_usage(chain_name: &str) -> Self {
        Self::generate(
            chain_name,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ],
            vec![],
        )
    }

    fn with_crl_dps(chain_name: &str, crl_dp_uris: Vec<String>) -> Self {
        Self::generate(
            chain_name,
            vec![],
            vec![CrlDistributionPoint { uris: crl_dp_uris }],
        )
    }

    fn with_cert_dps(chain_name: &str, crl_dps: Vec<CrlDistributionPoint>) -> Self {
        Self::generate(chain_name, vec![], crl_dps)
    }

    fn generate(
        chain_name: &str,
        key_usage: Vec<KeyUsagePurpose>,
        crl_dps: Vec<CrlDistributionPoint>,
    ) -> Self {
        let root_key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap();
        let mut root_params = CertificateParams::new(vec![format!("ca.{chain_name}")]).unwrap();
        root_params
            .distinguished_name
            .push(DnType::OrganizationName, chain_name);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "issuer.example.com");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = key_usage.clone();
        root_params.crl_distribution_points = crl_dps.clone();
        let root = CertifiedIssuer::self_signed(root_params, root_key).unwrap();

        let int_b = Intermediate::generate(
            &format!("int.b.{chain_name}"),
            &[
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
            ],
            key_usage.clone(),
            crl_dps.clone(),
            &root,
        );

        let int_a = Intermediate::generate(
            &format!("int.a.{chain_name}"),
            &[
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
            ],
            key_usage,
            crl_dps.clone(),
            &int_b.issuer,
        );

        let mut ee_params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        ee_params
            .distinguished_name
            .push(DnType::OrganizationName, chain_name);
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "test.example.com");
        let ee_serial = SerialNumber::from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        ]);
        ee_params.serial_number = Some(ee_serial.clone());
        ee_params.crl_distribution_points = crl_dps;
        let ee_cert = ee_params
            .signed_by(
                &KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap(),
                &int_a.issuer,
            )
            .unwrap();

        let mut ee_params_topbit = ee_params.clone();
        let ee_topbit_serial =
            SerialNumber::from_slice(&[0x80, 0xDE, 0xAD, 0xBE, 0xEF, 0xF0, 0x0D]);
        ee_params_topbit.serial_number = Some(ee_topbit_serial.clone());
        let ee_cert_topbit = ee_params_topbit
            .signed_by(
                &KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap(),
                &int_a.issuer,
            )
            .unwrap();

        Self {
            root,
            int_b,
            int_a,
            ee_cert,
            ee_serial,
            ee_cert_topbit,
            ee_topbit_serial,
        }
    }

    fn intermediates(&self) -> [&[u8]; 2] {
        [
            self.int_a.issuer.der().as_ref(),
            self.int_b.issuer.der().as_ref(),
        ]
    }

    fn generate_ee_with_custom_crl_dps(
        &self,
        custom_dp_der: Vec<u8>,
    ) -> (Certificate, SerialNumber) {
        let mut ee_params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "test.example.com");
        let serial = SerialNumber::from(0xDEAD_BEEF_u64);
        ee_params.serial_number = Some(serial.clone());
        ee_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS
                    .iter()
                    .unwrap()
                    .collect::<Vec<_>>(),
                custom_dp_der,
            ));
        let cert = ee_params
            .signed_by(
                &KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap(),
                &self.int_a.issuer,
            )
            .unwrap();
        (cert, serial)
    }
}

struct Intermediate {
    params: CertificateParams,
    serial: SerialNumber,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Intermediate {
    fn generate(
        name: &str,
        serial_bytes: &[u8],
        key_usage: Vec<KeyUsagePurpose>,
        crl_dps: Vec<CrlDistributionPoint>,
        parent: &CertifiedIssuer<'_, impl rcgen::SigningKey>,
    ) -> Self {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(DnType::OrganizationName, name);
        params
            .distinguished_name
            .push(DnType::CommonName, "issuer.example.com");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = key_usage;
        let serial = SerialNumber::from_slice(serial_bytes);
        params.serial_number = Some(serial.clone());
        params.crl_distribution_points = crl_dps;

        let key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap();
        let issuer = CertifiedIssuer::signed_by(params.clone(), key, parent).unwrap();

        Self {
            params,
            serial,
            issuer,
        }
    }

    fn generate_crl_bad_sig(&self, serial: SerialNumber) -> CertificateRevocationListDer<'static> {
        let bad_key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap();
        let mut params_with_crl_sign = self.params.clone();
        if !params_with_crl_sign
            .key_usages
            .contains(&KeyUsagePurpose::CrlSign)
        {
            params_with_crl_sign
                .key_usages
                .push(KeyUsagePurpose::CrlSign);
        }

        let issuer = CertifiedIssuer::self_signed(params_with_crl_sign, bad_key).unwrap();
        crl_params(serial, None, None)
            .signed_by(&issuer)
            .unwrap()
            .into()
    }

    fn generate_crl(
        &self,
        serial: SerialNumber,
        issuing_dp: Option<CrlIssuingDistributionPoint>,
        not_after_secs: Option<u64>,
    ) -> CertificateRevocationListDer<'static> {
        crl_params(serial, issuing_dp, not_after_secs)
            .signed_by(&self.issuer)
            .unwrap()
            .into()
    }

    fn generate_crl_with_crl_sign(
        &self,
        serial: SerialNumber,
    ) -> CertificateRevocationListDer<'static> {
        let signer = self.crl_signer();
        crl_params(serial, None, None)
            .signed_by(&signer)
            .unwrap()
            .into()
    }

    fn crl_signer(&self) -> Issuer<'_, &KeyPair> {
        let mut params = self.params.clone();
        if !params.key_usages.contains(&KeyUsagePurpose::CrlSign) {
            params.key_usages.push(KeyUsagePurpose::CrlSign);
        }
        Issuer::new(params, self.issuer.key())
    }
}

fn crl_params(
    serial_number: SerialNumber,
    issuing_distribution_point: Option<CrlIssuingDistributionPoint>,
    not_after_secs: Option<u64>,
) -> CertificateRevocationListParams {
    CertificateRevocationListParams {
        this_update: date_time_ymd(1970, 1, 1) + Duration::from_secs(NOT_BEFORE_SECS),
        next_update: date_time_ymd(1970, 1, 1)
            + Duration::from_secs(not_after_secs.unwrap_or(NOT_AFTER_SECS)),
        crl_number: SerialNumber::from(1234),
        issuing_distribution_point,
        key_identifier_method: KeyIdMethod::Sha256,
        revoked_certs: vec![RevokedCertParams {
            serial_number,
            revocation_time: date_time_ymd(2024, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
    }
}

// A revoked EE cert must be rejected when the matching DP/IDP URI is not
// the first URI in either sequence. Exercises the iterator exhaustion bug
// in uri_name_in_common(): after checking the first IDP URI against all DP
// URIs, the DP iterator is exhausted and later IDP URIs are never compared
// against the DP names, causing the CRL to be treated as non-authoritative.
#[test]
fn ee_revoked_dp_idp_match_later_uri() {
    let cert_dp_uris = vec![
        "http://example.com/other.crl".to_string(),
        "http://example.com/valid.crl".to_string(),
    ];
    let chain = CertChain::with_crl_dps("dp_later_uri_chain", cert_dp_uris);

    let crl_idp_uris = vec![
        "http://example.com/another.crl".to_string(),
        "http://example.com/valid.crl".to_string(),
    ];
    let ee_crl = chain.int_a.generate_crl(
        chain.ee_serial.clone(),
        Some(CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint { uris: crl_idp_uris },
            scope: None,
        }),
        None,
    );

    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];

    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
        .build();

    assert_eq!(
        check_cert(
            chain.ee_cert.der(),
            &chain.intermediates(),
            chain.root.der(),
            Some(revocation),
        ),
        Err(webpki::Error::CertRevoked)
    );
}

/// Helper to run a revocation check with a custom EE cert and CRL IDP.
fn check_custom_ee_revoked(
    chain: &CertChain,
    ee_cert: &Certificate,
    ee_serial: SerialNumber,
    idp: CrlIssuingDistributionPoint,
) -> Result<(), webpki::Error> {
    let ee_crl = chain.int_a.generate_crl(ee_serial, Some(idp), None);
    let crls = &[&CertRevocationList::Borrowed(
        BorrowedCertRevocationList::from_der(&ee_crl).unwrap(),
    )];
    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .build();
    check_cert(
        ee_cert.der(),
        &chain.intermediates(),
        chain.root.der(),
        Some(revocation),
    )
}

/// Build a DistributionPoint with a fullName containing a single URI general name.
fn build_uri_dp(uri: &str) -> Vec<u8> {
    // uniformResourceIdentifier [6] IMPLICIT IA5String
    let mut uri_name = Vec::new();
    write_der_tlv(Tag::ContextPrimitive6, uri.as_bytes(), &mut uri_name);
    // fullName [0] IMPLICIT GeneralNames
    let mut full_name = Vec::new();
    write_der_tlv(Tag::ContextConstructed0, &uri_name, &mut full_name);
    // distributionPoint [0] CONSTRUCTED
    let mut dist_point = Vec::new();
    write_der_tlv(Tag::ContextConstructed0, &full_name, &mut dist_point);
    let mut result = Vec::new();
    write_der_tlv(Tag::Sequence, &dist_point, &mut result);
    result
}

/// Build a DistributionPoint with a fullName URI and a reasons bit flag.
fn build_reasons_dp(uri: &str) -> Vec<u8> {
    let mut uri_name = Vec::new();
    write_der_tlv(Tag::ContextPrimitive6, uri.as_bytes(), &mut uri_name);
    let mut full_name = Vec::new();
    write_der_tlv(Tag::ContextConstructed0, &uri_name, &mut full_name);
    let mut dp_content = Vec::new();
    // distributionPoint [0] CONSTRUCTED
    write_der_tlv(Tag::ContextConstructed0, &full_name, &mut dp_content);
    // reasons [1] IMPLICIT BIT STRING: keyCompromise (bit 1)
    // BIT STRING content: unused_bits=6, value=0x40
    write_der_tlv(Tag::ContextPrimitive1, &[0x06, 0x40], &mut dp_content);
    let mut result = Vec::new();
    write_der_tlv(Tag::Sequence, &dp_content, &mut result);
    result
}

/// Build a DistributionPoint with only a cRLIssuer (indirect CRL, no distributionPoint name).
fn build_indirect_dp() -> Vec<u8> {
    // directoryName [4] CONSTRUCTED { Name }
    let mut attr = Vec::new();
    write_der_tlv(
        Tag::ObjectId,
        oid_registry::OID_X509_COMMON_NAME.as_bytes(),
        &mut attr,
    ); // OID 2.5.4.3 (commonName)
    write_der_tlv(Tag::Utf8String, b"indirect.example.com", &mut attr); // UTF8String
    let mut attr_seq = Vec::new();
    write_der_tlv(Tag::Sequence, &attr, &mut attr_seq); // SEQUENCE (AttributeTypeAndValue)
    let mut attr_set = Vec::new();
    write_der_tlv(Tag::Set, &attr_seq, &mut attr_set); // SET
    let mut name = Vec::new();
    write_der_tlv(Tag::Sequence, &attr_set, &mut name); // SEQUENCE (Name)
    let mut dir_name = Vec::new();
    write_der_tlv(Tag::ContextConstructed4, &name, &mut dir_name); // directoryName [4] CONSTRUCTED
    // cRLIssuer [2] IMPLICIT GeneralNames (replaces SEQUENCE tag)
    let mut crl_issuer = Vec::new();
    write_der_tlv(Tag::ContextConstructed2, &dir_name, &mut crl_issuer);
    let mut result = Vec::new();
    write_der_tlv(Tag::Sequence, &crl_issuer, &mut result);
    result
}

/// Build a DistributionPoint with nameRelativeToCRLIssuer (no fullName).
fn build_relative_name_dp() -> Vec<u8> {
    let mut attr = Vec::new();
    write_der_tlv(
        Tag::ObjectId,
        oid_registry::OID_X509_COMMON_NAME.as_bytes(),
        &mut attr,
    );
    write_der_tlv(Tag::Utf8String, b"example.com", &mut attr);
    let mut attr_seq = Vec::new();
    write_der_tlv(Tag::Sequence, &attr, &mut attr_seq);
    // nameRelativeToCRLIssuer [1] IMPLICIT SET (replaces SET tag 0x31 with 0xA1)
    let mut relative_name = Vec::new();
    write_der_tlv(Tag::ContextConstructed1, &attr_seq, &mut relative_name);
    // distributionPoint [0] CONSTRUCTED
    let mut dist_point = Vec::new();
    write_der_tlv(Tag::ContextConstructed0, &relative_name, &mut dist_point);
    let mut result = Vec::new();
    write_der_tlv(Tag::Sequence, &dist_point, &mut result);
    result
}

/// Build a CRLDistributionPoints extension value (SEQUENCE OF DistributionPoint).
fn build_crl_dps_extension(dps: &[Vec<u8>]) -> Vec<u8> {
    let mut content = Vec::new();
    for dp in dps {
        content.extend_from_slice(dp);
    }
    let mut result = Vec::new();
    write_der_tlv(Tag::Sequence, &content, &mut result);
    result
}

fn matching_idp() -> CrlIssuingDistributionPoint {
    CrlIssuingDistributionPoint {
        distribution_point: CrlDistributionPoint {
            uris: vec![MATCHING_URI.to_string()],
        },
        scope: None,
    }
}

/// Encode a DER tag-length-value triple into `buf`.
fn write_der_tlv(tag: Tag, value: &[u8], buf: &mut Vec<u8>) {
    buf.push(tag as u8);
    let len = value.len();
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
    buf.extend_from_slice(value);
}

#[repr(u8)]
enum Tag {
    ObjectId = 0x06,
    Utf8String = 0x0c,
    Sequence = 0x30,
    Set = 0x31,
    ContextPrimitive1 = 0x80 | 1,
    ContextPrimitive6 = 0x80 | 6,
    ContextConstructed0 = 0x80 | 0x20,
    ContextConstructed1 = 0x80 | 0x20 | 1,
    ContextConstructed2 = 0x80 | 0x20 | 2,
    ContextConstructed4 = 0x80 | 0x20 | 4,
}

static RCGEN_SIGNATURE_ALG: &SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

const NOT_BEFORE_SECS: u64 = 0x1FED_F00D - 30;
const NOT_AFTER_SECS: u64 = 0x1FED_F00D + 30;

// CRL Distribution Point URIs for certificates (must have at least one URI matching VALID_CRL_DP_URIS)
const VALID_CERT_CRL_DP_URIS: &[&str] = &[
    "http://example.com/another.crl",
    "http://example.com/valid.crl",
];

// CRL Issuing Distribution Point URIs (must have at least one URI matching VALID_CERT_CRL_DP_URIS)
const VALID_CRL_DP_URIS: &[&str] = &[
    "http://example.com/yet.another.crl",
    "http://example.com/valid.crl",
];

const MATCHING_URI: &str = "http://example.com/valid.crl";
const NON_MATCHING_URI: &str = "http://example.com/other.crl";
