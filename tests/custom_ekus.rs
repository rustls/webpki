#![cfg(all(feature = "alloc", any(feature = "ring", feature = "aws_lc_rs")))]

use core::time::Duration;

use pki_types::{CertificateDer, UnixTime};
use webpki::{extract_trust_anchor, ChainOptions, KeyUsage};

fn check_cert(
    ee: &[u8],
    ca: &[u8],
    eku: KeyUsage,
    time: UnixTime,
    result: Result<(), webpki::Error>,
) {
    let ca = CertificateDer::from(ca);
    let anchors = [extract_trust_anchor(&ca).unwrap()];

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();

    let options = ChainOptions {
        eku,
        trust_anchors: &anchors,
        intermediate_certs: &[],
        revocation: None,
        supported_sig_algs: webpki::ALL_VERIFICATION_ALGS,
    };

    assert_eq!(options.verify_trusted(&cert, time), result);
}

#[test]
pub fn verify_custom_eku_mdoc() {
    let err = Err(webpki::Error::RequiredEkuNotFound);
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_609_459_200)); //  Jan 1 01:00:00 CET 2021

    let ee = include_bytes!("misc/mdoc_eku.ee.der");
    let ca = include_bytes!("misc/mdoc_eku.ca.der");

    let eku_mdoc = KeyUsage::required(&[40, 129, 140, 93, 5, 1, 2]);
    check_cert(ee, ca, eku_mdoc, time, Ok(()));
    check_cert(ee, ca, KeyUsage::server_auth(), time, err);
    check_cert(ee, ca, eku_mdoc, time, Ok(()));
    check_cert(ee, ca, KeyUsage::server_auth(), time, err);
}

#[test]
pub fn verify_custom_eku_client() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let ee = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, KeyUsage::client_auth(), time, Ok(()));

    let ee = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, KeyUsage::client_auth(), time, Ok(()));
    check_cert(ee, ca, KeyUsage::server_auth(), time, Ok(()));
}
