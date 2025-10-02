// Copyright 2023 Joseph Birr-Pixton.
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

use std::error::Error as StdError;

use core::time::Duration;
use pki_types::{CertificateDer, UnixTime};
use rcgen::{Certificate, ExtendedKeyUsagePurpose};
use webpki::{ExtendedKeyUsage, RequiredEkuNotFoundContext, anchor_from_trusted_cert};

mod common;
use common::{make_end_entity, make_issuer};

#[test]
fn cert_with_no_eku_accepted_for_client_auth() {
    let (ee, ca) = test_certs(vec![], "cert_with_no_eku_accepted_for_client_auth").unwrap();
    assert_eq!(check_cert(ee.der(), ca), Ok(()));
}

#[test]
fn cert_with_clientauth_eku_accepted_for_client_auth() {
    let (ee, ca) = test_certs(
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        "cert_with_clientauth_eku_accepted_for_client_auth",
    )
    .unwrap();
    assert_eq!(check_cert(ee.der(), ca), Ok(()));
}

#[test]
fn cert_with_both_ekus_accepted_for_client_auth() {
    let (ee, ca) = test_certs(
        vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ],
        "cert_with_both_ekus_accepted_for_client_auth",
    )
    .unwrap();
    assert_eq!(check_cert(ee.der(), ca), Ok(()));
}

#[test]
fn cert_with_serverauth_eku_rejected_for_client_auth() {
    let (ee, ca) = test_certs(
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        "cert_with_serverauth_eku_rejected_for_client_auth",
    )
    .unwrap();

    let err = check_cert(ee.der(), ca).unwrap_err();
    assert_eq!(
        err,
        webpki::Error::RequiredEkuNotFound(RequiredEkuNotFoundContext {
            required: ExtendedKeyUsage::client_auth(),
            present: vec![vec![1, 3, 6, 1, 5, 5, 7, 3, 1]],
        })
    );

    assert_eq!(
        format!("{err}"),
        "RequiredEkuNotFound(RequiredEkuNotFoundContext { required: KeyPurposeId(1.3.6.1.5.5.7.3.2), present: [KeyPurposeId(1.3.6.1.5.5.7.3.1)] })"
    )
}

fn check_cert(ee: &[u8], ca: CertificateDer<'static>) -> Result<(), webpki::Error> {
    let anchors = &[anchor_from_trusted_cert(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        anchors,
        &[],
        time,
        &ExtendedKeyUsage::client_auth(),
        None,
        None,
    )
    .map(|_| ())
}

fn test_certs(
    ekus: Vec<ExtendedKeyUsagePurpose>,
    name: &str,
) -> Result<(Certificate, CertificateDer<'static>), Box<dyn StdError>> {
    let issuer = make_issuer(name)?;
    let end_entity = make_end_entity(ekus, name, &issuer)?;
    Ok((end_entity.cert, issuer.as_ref().der().clone()))
}
