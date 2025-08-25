#![cfg(all(feature = "alloc", any(feature = "ring", feature = "aws-lc-rs")))]

use core::time::Duration;

use pki_types::{CertificateDer, UnixTime};
use webpki::{KeyUsage, RequiredEkuNotFoundContext, anchor_from_trusted_cert};

fn check_cert(
    ee: &[u8],
    ca: &[u8],
    eku: KeyUsage,
    time: UnixTime,
    result: Result<(), webpki::Error>,
) {
    let ca = CertificateDer::from(ca);
    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();

    assert_eq!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
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

    let eku_mdoc = KeyUsage::required(&[40, 129, 140, 93, 5, 1, 2]);
    check_cert(ee, ca, eku_mdoc, time, Ok(()));
    check_cert(
        ee,
        ca,
        KeyUsage::server_auth(),
        time,
        Err(webpki::Error::RequiredEkuNotFoundContext(
            RequiredEkuNotFoundContext {
                required: KeyUsage::server_auth(),
                present: vec![vec![1, 0, 68701, 5, 1, 2]],
            },
        )),
    );
    check_cert(ee, ca, eku_mdoc, time, Ok(()));
    check_cert(
        ee,
        ca,
        KeyUsage::server_auth(),
        time,
        Err(webpki::Error::RequiredEkuNotFoundContext(
            RequiredEkuNotFoundContext {
                required: KeyUsage::server_auth(),
                present: vec![vec![1, 0, 68701, 5, 1, 2]],
            },
        )),
    );
}

#[test]
pub fn verify_custom_eku_client() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, KeyUsage::client_auth(), time, Ok(()));

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, KeyUsage::client_auth(), time, Ok(()));
    check_cert(ee, ca, KeyUsage::server_auth(), time, Ok(()));
}

#[test]
pub fn verify_custom_eku_required_if_present() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let eku = KeyUsage::required_if_present(&[43, 6, 1, 5, 5, 7, 3, 2]);

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, eku, time, Ok(()));

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, eku, time, Ok(()));
}

#[test]
pub fn verify_x_required_if_y_present_without_y() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let server_auth_oid = &[43, 6, 1, 5, 5, 7, 3, 1]; // id-kp-serverAuth
    let client_auth_oid = &[43, 6, 1, 5, 5, 7, 3, 2]; // id-kp-clientAuth

    let eku = KeyUsage::x_required_if_y_present(server_auth_oid, client_auth_oid);

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, eku, time, Ok(()));
}

#[test]
pub fn verify_x_required_if_y_present_with_other_ekus() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let server_auth_oid = &[43, 6, 1, 5, 5, 7, 3, 1]; // id-kp-serverAuth
    let client_auth_oid = &[43, 6, 1, 5, 5, 7, 3, 2]; // id-kp-clientAuth

    let eku = KeyUsage::x_required_if_y_present(server_auth_oid, client_auth_oid);

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, eku, time, Ok(()));
}

#[test]
pub fn verify_x_required_if_y_present_negative_case() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    // Negative test: require a non-existent EKU when client-auth is present
    // Using a made-up OID that definitely won't be in any certificate
    let non_existent_oid = &[99, 99, 99, 99, 99, 99, 99, 99]; // mock non-existent OID
    let client_auth_oid = &[43, 6, 1, 5, 5, 7, 3, 2]; // id-kp-clientAuth

    let eku = KeyUsage::x_required_if_y_present(non_existent_oid, client_auth_oid);

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");

    check_cert(
        ee,
        ca,
        eku,
        time,
        Err(webpki::Error::RequiredEkuNotFoundContext(
            RequiredEkuNotFoundContext {
                required: eku,
                present: vec![
                    vec![1, 3, 6, 1, 5, 5, 7, 3, 2], // id-kp-clientAuth (decoded)
                    vec![1, 3, 6, 1, 5, 5, 7, 3, 1], // id-kp-serverAuth (decoded)
                ],
            },
        )),
    );
}
