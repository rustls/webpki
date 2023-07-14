#[cfg(feature = "alloc")]
fn check_cert(
    ee: &[u8],
    ca: &[u8],
    eku: webpki::ExtendedKeyUsage,
    result: Result<(), webpki::Error>,
) {
    let anchors = vec![webpki::TrustAnchor::try_from_cert_der(ca).unwrap()];
    let anchors = webpki::NonTlsTrustAnchors(&anchors);

    let time = webpki::Time::from_seconds_since_unix_epoch(0x1fed_f00d);
    let cert = webpki::EndEntityCert::try_from(ee).unwrap();

    assert_eq!(
        cert.verify_is_valid_cert_with_eku(
            eku,
            &[&webpki::RSA_PKCS1_2048_8192_SHA256],
            &anchors,
            &[],
            time,
            &[],
        ),
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
#[test]
pub fn verify_custom_eku() {
    use webpki::ExtendedKeyUsage::Required;
    use webpki::ExtendedKeyUsage::RequiredIfPresent;

    let err = Err(webpki::Error::RequiredEkuNotFound);

    let ee = include_bytes!("client_auth/cert_with_clientauth_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_clientauth_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, Required(EKU_CLIENT_AUTH), Ok(()));
    check_cert(ee, ca, Required(EKU_SERVER_AUTH), err);
    check_cert(ee, ca, RequiredIfPresent(EKU_CLIENT_AUTH), Ok(()));
    check_cert(ee, ca, RequiredIfPresent(EKU_SERVER_AUTH), err);

    let ee = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, Required(EKU_CLIENT_AUTH), err);
    check_cert(ee, ca, RequiredIfPresent(EKU_CLIENT_AUTH), Ok(()));

    let ee = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("client_auth/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, Required(EKU_CLIENT_AUTH), Ok(()));
    check_cert(ee, ca, Required(EKU_SERVER_AUTH), Ok(()));
    check_cert(ee, ca, RequiredIfPresent(EKU_CLIENT_AUTH), Ok(()));
    check_cert(ee, ca, RequiredIfPresent(EKU_SERVER_AUTH), Ok(()));
}

#[test]
fn key_purpose_id() {
    webpki::KeyPurposeId::new(&[1, 2, 3]);
}
