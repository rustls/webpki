#[cfg(feature = "alloc")]
use webpki::ExtendedKeyUsage::{Required, RequiredIfPresent};

#[cfg(feature = "alloc")]
fn check_cert(
    ee: &[u8],
    ca: &[u8],
    eku: webpki::ExtendedKeyUsage,
    time: webpki::Time,
    result: Result<(), webpki::Error>,
) {
    let anchors = vec![webpki::TrustAnchor::try_from_cert_der(ca).unwrap()];
    let anchors = webpki::NonTlsTrustAnchors(&anchors);
    let algs = &[
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        &webpki::ECDSA_P256_SHA256,
    ];

    let cert = webpki::EndEntityCert::try_from(ee).unwrap();

    assert_eq!(
        cert.verify_is_valid_cert_with_eku(algs, &anchors, &[], time, eku, &[]),
        result
    );
}

#[cfg(feature = "alloc")]
#[allow(clippy::identity_op)]
static EKU_CLIENT_AUTH: webpki::KeyPurposeId =
    webpki::KeyPurposeId::new(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 2]);

#[cfg(feature = "alloc")]
#[allow(clippy::identity_op)]
static EKU_SERVER_AUTH: webpki::KeyPurposeId =
    webpki::KeyPurposeId::new(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 1]);

#[cfg(feature = "alloc")]
#[allow(clippy::identity_op)]
static EKU_MDOC_ISSUER_AUTH: webpki::KeyPurposeId =
    webpki::KeyPurposeId::new(&[(40 * 1) + 0, 129, 140, 93, 5, 1, 2]);

#[cfg(feature = "alloc")]
#[test]
pub fn verify_custom_eku_mdoc() {
    let err = Err(webpki::Error::RequiredEkuNotFound);
    let time = webpki::Time::from_seconds_since_unix_epoch(1609459200); //  Jan 1 01:00:00 CET 2021

    let ee = include_bytes!("misc/mdoc_eku.ee.der");
    let ca = include_bytes!("misc/mdoc_eku.ca.der");
    check_cert(ee, ca, Required(EKU_MDOC_ISSUER_AUTH), time, Ok(()));
    check_cert(ee, ca, Required(EKU_SERVER_AUTH), time, err);
    check_cert(
        ee,
        ca,
        RequiredIfPresent(EKU_MDOC_ISSUER_AUTH),
        time,
        Ok(()),
    );
    check_cert(ee, ca, RequiredIfPresent(EKU_SERVER_AUTH), time, err);
}

#[cfg(feature = "alloc")]
#[test]
pub fn verify_custom_eku_client() {
    let err = Err(webpki::Error::RequiredEkuNotFound);
    let time = webpki::Time::from_seconds_since_unix_epoch(0x1fed_f00d);

    let ee = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, Required(EKU_CLIENT_AUTH), time, err);
    check_cert(ee, ca, RequiredIfPresent(EKU_CLIENT_AUTH), time, Ok(()));

    let ee = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, Required(EKU_CLIENT_AUTH), time, Ok(()));
    check_cert(ee, ca, Required(EKU_SERVER_AUTH), time, Ok(()));
    check_cert(ee, ca, RequiredIfPresent(EKU_CLIENT_AUTH), time, Ok(()));
    check_cert(ee, ca, RequiredIfPresent(EKU_SERVER_AUTH), time, Ok(()));
}

#[test]
fn key_purpose_id() {
    webpki::KeyPurposeId::new(&[1, 2, 3]);
}
