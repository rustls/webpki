#![cfg(feature = "alloc")]

use core::time::Duration;

use pki_types::{CertificateDer, UnixTime};
use webpki::{ExtendedKeyUsage, RequiredEkuNotFoundContext, anchor_from_trusted_cert};

fn check_cert(
    ee: &[u8],
    ca: &[u8],
    eku: &ExtendedKeyUsage,
    time: UnixTime,
    result: Result<(), webpki::Error>,
) {
    let ca = CertificateDer::from(ca);
    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();

    assert_eq!(
        cert.verify_for_usage(
            rustls_aws_lc_rs::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            time,
            eku,
            None,
            None,
        )
        .map(|_| ()),
        result
    );
}

#[test]
pub fn verify_custom_eku_mdoc() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_609_459_200)); //  Jan 1 01:00:00 CET 2021

    let ee = include_bytes!("misc/mdoc_eku.ee.der");
    let ca = include_bytes!("misc/mdoc_eku.ca.der");

    let eku_mdoc = ExtendedKeyUsage::required(&[40, 129, 140, 93, 5, 1, 2]);
    check_cert(ee, ca, &eku_mdoc, time, Ok(()));
    check_cert(
        ee,
        ca,
        &ExtendedKeyUsage::server_auth(),
        time,
        Err(webpki::Error::RequiredEkuNotFound(
            RequiredEkuNotFoundContext {
                required: ExtendedKeyUsage::server_auth(),
                present: vec![vec![1, 0, 18013, 5, 1, 2]],
            },
        )),
    );
    check_cert(ee, ca, &eku_mdoc, time, Ok(()));
    check_cert(
        ee,
        ca,
        &ExtendedKeyUsage::server_auth(),
        time,
        Err(webpki::Error::RequiredEkuNotFound(
            RequiredEkuNotFoundContext {
                required: ExtendedKeyUsage::server_auth(),
                present: vec![vec![1, 0, 18013, 5, 1, 2]],
            },
        )),
    );
}

#[test]
pub fn verify_custom_eku_client() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &ExtendedKeyUsage::client_auth(), time, Ok(()));

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &ExtendedKeyUsage::client_auth(), time, Ok(()));
    check_cert(ee, ca, &ExtendedKeyUsage::server_auth(), time, Ok(()));
}

#[test]
pub fn verify_custom_eku_required_if_present() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let eku = ExtendedKeyUsage::required_if_present(&[43, 6, 1, 5, 5, 7, 3, 2]);

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &eku, time, Ok(()));

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &eku, time, Ok(()));
}
