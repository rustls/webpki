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

#![cfg(all(feature = "alloc", any(feature = "ring", feature = "aws_lc_rs")))]

use core::time::Duration;
use pki_types::{CertificateDer, UnixTime};
use webpki::{extract_trust_anchor, ChainOptions, KeyUsage};

fn check_cert(ee: &[u8], ca: &[u8]) -> Result<(), webpki::Error> {
    let ca = CertificateDer::from(ca);
    let anchors = &[extract_trust_anchor(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();

    let options = ChainOptions {
        eku: KeyUsage::client_auth(),
        trust_anchors: anchors,
        intermediate_certs: &[],
        revocation: None,
        supported_sig_algs: webpki::ALL_VERIFICATION_ALGS,
    };

    options.verify_trusted(&cert, time)
}

// DO NOT EDIT BELOW: generated by tests/generate.py

#[test]
fn cert_with_no_eku_accepted_for_client_auth() {
    let ee = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ca.der");
    assert_eq!(check_cert(ee, ca), Ok(()));
}

#[test]
fn cert_with_clientauth_eku_accepted_for_client_auth() {
    let ee = include_bytes!("client_auth/cert_with_clientauth_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_clientauth_eku_accepted_for_client_auth.ca.der");
    assert_eq!(check_cert(ee, ca), Ok(()));
}

#[test]
fn cert_with_both_ekus_accepted_for_client_auth() {
    let ee = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    assert_eq!(check_cert(ee, ca), Ok(()));
}

#[test]
fn cert_with_serverauth_eku_rejected_for_client_auth() {
    let ee = include_bytes!("client_auth/cert_with_serverauth_eku_rejected_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_serverauth_eku_rejected_for_client_auth.ca.der");
    assert_eq!(check_cert(ee, ca), Err(webpki::Error::RequiredEkuNotFound));
}
