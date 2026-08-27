use pki_types::CertificateDer;

#[test]
fn cert_without_extensions_test() {
    // Check the certificate is valid with
    // `openssl x509 -in cert_without_extensions.der -inform DER -text -noout`
    let ca = CertificateDer::from(&include_bytes!("cert_without_extensions.der")[..]);
    assert!(webpki::EndEntityCert::try_from(&ca).is_ok());
}

#[test]
fn cert_with_empty_extensions_test() {
    // Check the certificate is valid with
    // `openssl x509 -in cert_with_empty_extensions.der -inform DER -text -noout`
    let ca = CertificateDer::from(&include_bytes!("cert_with_empty_extensions.der")[..]);
    assert!(webpki::EndEntityCert::try_from(&ca).is_ok());
}
