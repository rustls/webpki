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

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

use core::time::Duration;

use pki_types::{
    CertificateDer, CertificateRevocationListDer, SignatureVerificationAlgorithm, UnixTime,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    CertifiedIssuer, CrlDistributionPoint, CrlIssuingDistributionPoint, DnType, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    SignatureAlgorithm, date_time_ymd,
};
#[cfg(feature = "alloc")]
use webpki::OwnedCertRevocationList;
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, ExtendedKeyUsage, RevocationCheckDepth,
    RevocationOptions, RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};

static ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    #[cfg(feature = "ring")]
    webpki::ring::ECDSA_P256_SHA256,
    #[cfg(feature = "aws-lc-rs")]
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
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

#[cfg(feature = "alloc")]
#[test]
fn no_crls_test_owned() {
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

#[cfg(feature = "alloc")]
#[test]
fn no_relevant_crl_ee_depth_allow_unknown_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&no_match_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn no_relevant_crl_ee_depth_forbid_unknown_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&no_match_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_not_revoked_ee_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_not_revoked_crl = chain
        .int_a
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_not_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_not_revoked_chain_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_not_revoked_crl = chain
        .int_a
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_not_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_badsig_ee_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_badsig = chain.int_a.generate_crl_bad_sig(chain.ee_serial.clone());

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_badsig).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_wrong_ku_ee_depth_owned() {
    let chain = CertChain::no_crl_key_usage("no_crl_ku_chain");

    let ee_revoked_crl = chain
        .int_a
        .generate_crl_with_crl_sign(chain.ee_serial.clone());

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_not_revoked_wrong_ku_ee_depth_owned() {
    let chain = CertChain::no_crl_key_usage("no_crl_ku_chain");

    let ee_not_revoked_crl = chain
        .int_a
        .generate_crl_with_crl_sign(SerialNumber::from(12345));

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_not_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_no_ku_ee_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_crl_ku_ee_depth_owned() {
    let chain = CertChain::with_crl_key_usage("ku_chain");

    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn no_crls_test_chain_depth_owned() {
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

#[cfg(feature = "alloc")]
#[test]
fn no_relevant_crl_chain_depth_allow_unknown_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&no_match_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn no_relevant_crl_chain_depth_forbid_unknown_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let other_chain = CertChain::no_key_usages("other_chain");
    let no_match_crl = other_chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&no_match_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn int_not_revoked_chain_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_not_revoked_crl = chain
        .int_b
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&int_not_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn int_not_revoked_chain_depth_forbid_unknown_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_not_revoked_crl = chain
        .int_b
        .generate_crl(SerialNumber::from(12345), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&int_not_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn int_revoked_badsig_chain_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_revoked_badsig = chain.int_b.generate_crl_bad_sig(chain.int_a.serial.clone());

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&int_revoked_badsig).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn int_revoked_wrong_ku_chain_depth_owned() {
    let chain = CertChain::no_crl_key_usage("no_crl_ku_chain");

    let int_revoked_crl = chain
        .int_b
        .generate_crl_with_crl_sign(chain.int_a.serial.clone());

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&int_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn int_revoked_no_ku_chain_depth_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let int_revoked_crl = chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&int_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn int_revoked_crl_ku_chain_depth_owned() {
    let chain = CertChain::with_crl_key_usage("ku_chain");

    let int_revoked_crl = chain
        .int_b
        .generate_crl(chain.int_a.serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&int_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_topbit_serial_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let ee_revoked_crl = chain
        .int_a
        .generate_crl(chain.ee_topbit_serial.clone(), None, None);

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_no_dp_crl_idp_owned() {
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

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_not_revoked_crl_no_idp_owned() {
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

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_crl_no_idp_owned() {
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

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_crl_mismatched_idp_unknown_status_owned() {
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

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_dp_idp_match_owned() {
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

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_indirect_dp_unknown_status_owned() {
    let ee = include_bytes!("client_auth_revocation/indirect_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/indirect_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/indirect_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/indirect_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(
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

#[cfg(feature = "alloc")]
#[test]
fn ee_reasons_dp_unknown_status_owned() {
    let ee = include_bytes!("client_auth_revocation/reasons_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/reasons_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/reasons_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/reasons_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(
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

#[cfg(feature = "alloc")]
#[test]
fn ee_nofullname_dp_unknown_status_owned() {
    let ee = include_bytes!("client_auth_revocation/nofullname_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/nofullname_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/nofullname_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/nofullname_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(
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

#[cfg(feature = "alloc")]
#[test]
fn ee_dp_invalid_owned() {
    let ee = include_bytes!("client_auth_revocation/invalid_dp_chain.ee.der");
    let intermediates = &[
        include_bytes!("client_auth_revocation/invalid_dp_chain.int.a.ca.der").as_slice(),
        include_bytes!("client_auth_revocation/invalid_dp_chain.int.b.ca.der").as_slice(),
    ];
    let ca = include_bytes!("client_auth_revocation/invalid_dp_chain.root.ca.der");

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(
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

#[cfg(feature = "alloc")]
#[test]
fn expired_crl_ignore_expiration_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    let expired_next_update = 0x1FED_F00D - 1;
    let ee_crl =
        chain
            .int_a
            .generate_crl(SerialNumber::from(0xFFFF), None, Some(expired_next_update));

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_crl).unwrap(),
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

#[cfg(feature = "alloc")]
#[test]
fn ee_revoked_expired_crl_owned() {
    let chain = CertChain::no_key_usages("no_ku_chain");
    // Use a next_update that's after this_update but before verification time
    // to create an expired CRL. Verification time is 0x1FED_F00D.
    let expired_next_update = 0x1FED_F00D - 1;
    let ee_revoked_crl =
        chain
            .int_a
            .generate_crl(chain.ee_serial.clone(), None, Some(expired_next_update));

    let crls = &[&CertRevocationList::Owned(
        OwnedCertRevocationList::from_der(&ee_revoked_crl).unwrap(),
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
        Self::generate(chain_name, vec![], None)
    }

    fn no_crl_key_usage(chain_name: &str) -> Self {
        Self::generate(
            chain_name,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
            ],
            None,
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
            None,
        )
    }

    fn with_crl_dps(chain_name: &str, crl_dps: Vec<String>) -> Self {
        Self::generate(chain_name, vec![], Some(crl_dps))
    }

    fn generate(
        chain_name: &str,
        key_usage: Vec<KeyUsagePurpose>,
        crl_dps: Option<Vec<String>>,
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
        if let Some(uris) = crl_dps.clone() {
            root_params.crl_distribution_points = vec![CrlDistributionPoint { uris }];
        }
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
        if let Some(uris) = crl_dps {
            ee_params.crl_distribution_points = vec![CrlDistributionPoint { uris }];
        }
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
        crl_dps: Option<Vec<String>>,
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
        if let Some(uris) = crl_dps {
            params.crl_distribution_points = vec![CrlDistributionPoint { uris }];
        }

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
