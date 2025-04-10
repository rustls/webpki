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
use webpki::{KeyUsage, anchor_from_trusted_cert};

mod common;
use common::{make_end_entity, make_issuer};

#[test]
fn cert_with_no_eku_accepted_for_client_auth() {
    let (ee, ca) = test_certs(vec![], "cert_with_no_eku_accepted_for_client_auth").unwrap();
    assert_eq!(check_cert(ee.der(), ca.der()), Ok(()));
}

#[test]
fn cert_with_clientauth_eku_accepted_for_client_auth() {
    let (ee, ca) = test_certs(
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        "cert_with_clientauth_eku_accepted_for_client_auth",
    )
    .unwrap();
    assert_eq!(check_cert(ee.der(), ca.der()), Ok(()));
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
    assert_eq!(check_cert(ee.der(), ca.der()), Ok(()));
}

#[test]
fn cert_with_serverauth_eku_rejected_for_client_auth() {
    let (ee, ca) = test_certs(
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        "cert_with_serverauth_eku_rejected_for_client_auth",
    )
    .unwrap();
    assert_eq!(
        check_cert(ee.der(), ca.der()),
        Err(webpki::Error::RequiredEkuNotFound)
    );
}

fn check_cert(ee: &[u8], ca: &[u8]) -> Result<(), webpki::Error> {
    let ca = CertificateDer::from(ca);
    let anchors = &[anchor_from_trusted_cert(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        anchors,
        &[],
        time,
        KeyUsage::client_auth(),
        None,
        None,
    )
    .map(|_| ())
}

fn test_certs(
    ekus: Vec<ExtendedKeyUsagePurpose>,
    name: &str,
) -> Result<(Certificate, Certificate), Box<dyn StdError>> {
    let issuer = make_issuer(name)?;
    let end_entity = make_end_entity(ekus, name, &issuer.cert, &issuer.key_pair)?;
    Ok((end_entity.cert, issuer.cert))
}
