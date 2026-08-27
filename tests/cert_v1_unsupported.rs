use pki_types::CertificateDer;

#[test]
fn test_cert_v1_unsupported() {
    // Check with `openssl x509 -text -noout -in cert_v1.der -inform DER`
    // to verify this is a correct version 1 certificate.
    let ca = CertificateDer::from(&include_bytes!("cert_v1.der")[..]);

    assert_eq!(
        Some(webpki::Error::UnsupportedCertVersion),
        webpki::EndEntityCert::try_from(&ca).err()
    );
}
