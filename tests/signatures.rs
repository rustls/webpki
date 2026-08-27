#![cfg(feature = "alloc")]

use pki_types::{CertificateDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer};
use rcgen::{
    Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SignatureAlgorithm,
    SigningKey,
};
use rustls_aws_lc_rs::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA256,
    ECDSA_P521_SHA384, ECDSA_P521_SHA512, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
};
use x509_parser::prelude::*;

mod common;

fn check_sig(
    ee: &[u8],
    alg: &dyn SignatureVerificationAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), webpki::Error> {
    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    cert.verify_signature(alg, message, signature)
}

fn check_sig_rpk(
    spki: &[u8],
    alg: &dyn SignatureVerificationAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), webpki::Error> {
    let spki = SubjectPublicKeyInfoDer::from(spki);
    let rpk = webpki::RawPublicKeyEntity::try_from(&spki).unwrap();
    rpk.verify_signature(alg, message, signature)
}

#[test]
fn ed25519() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(test_cert.cert.der(), ED25519, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ED25519, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(test_cert.cert.der(), ED25519, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ED25519, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );

    for algorithm in &[
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_3072_8192_SHA384,
        RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ] {
        assert!(matches!(
            check_sig(test_cert.cert.der(), *algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_))
        ));
    }
}

/// P256 with SHA384 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p256_sha384() {
    let ee = include_bytes!("signatures/ecdsa_p256.ee.der");
    let rpk = include_bytes!("signatures/ecdsa_p256.spki.der");
    let message = include_bytes!("signatures/message.bin");
    let good_sig =
        include_bytes!("signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature.sig.bin");
    let bad_sig = include_bytes!(
        "signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature.sig.bin"
    );

    assert_eq!(check_sig(ee, ECDSA_P256_SHA384, message, good_sig), Ok(()));
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P256_SHA384, message, good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(ee, ECDSA_P256_SHA384, message, bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P256_SHA384, message, bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p256_sha256() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P256_SHA256, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );

    for algorithm in &[
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_3072_8192_SHA384,
        RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ] {
        assert!(matches!(
            check_sig(test_cert.cert.der(), *algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_))
        ));
    }
}

#[test]
fn ecdsa_p384_sha384() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P384_SHA384, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P384_SHA384, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P384_SHA384, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P384_SHA384, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

/// P384 with SHA256 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p384_sha256() {
    let ee = include_bytes!("signatures/ecdsa_p384.ee.der");
    let rpk = include_bytes!("signatures/ecdsa_p384.spki.der");
    let message = include_bytes!("signatures/message.bin");
    let good_sig =
        include_bytes!("signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature.sig.bin");
    let bad_sig = include_bytes!(
        "signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature.sig.bin"
    );

    assert_eq!(check_sig(ee, ECDSA_P384_SHA256, message, good_sig), Ok(()));
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P384_SHA256, message, good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(ee, ECDSA_P384_SHA256, message, bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P384_SHA256, message, bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p384_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    for algorithm in &[
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ED25519,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_3072_8192_SHA384,
        RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ] {
        assert!(matches!(
            check_sig(test_cert.cert.der(), *algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_))
        ));
    }
}

#[test]
fn ecdsa_p521_sha512() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA512, "ecdsa_p521 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P521_SHA512, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA512, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P521_SHA512, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA512, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p521_sha256() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA256, "ecdsa_p521 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P521_SHA256, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA256, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P521_SHA256, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA256, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p521_sha384() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA384, "ecdsa_p521 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P521_SHA384, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA384, MESSAGE, &good_sig),
        Ok(())
    );
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P521_SHA384, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA384, MESSAGE, &bad_sig),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p521_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA512, "ecdsa_p521 test");

    for algorithm in &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_3072_8192_SHA384,
        RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ] {
        assert!(matches!(
            check_sig(test_cert.cert.der(), *algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_))
        ));
    }
}

#[test]
fn rsa_pkcs1_2048_8192_sha256() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &good_sig
        ),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &good_sig
        ),
        Ok(())
    );
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &bad_sig
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &bad_sig
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_pkcs1_2048_8192_sha384() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &good_sig
        ),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &good_sig
        ),
        Ok(())
    );
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &bad_sig
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &bad_sig
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_pkcs1_2048_8192_sha512() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA512, "rsa_2048 test");
    let good_sig = test_cert.sign(MESSAGE);
    let bad_sig = test_cert.sign_bad(MESSAGE);

    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &good_sig
        ),
        Ok(())
    );
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &good_sig
        ),
        Ok(())
    );
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &bad_sig
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &bad_sig
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    for algorithm in &[
        ECDSA_P521_SHA256,
        ECDSA_P521_SHA384,
        ECDSA_P521_SHA512,
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
    ] {
        assert!(matches!(
            check_sig(test_cert.cert.der(), *algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_))
        ));
    }
}

#[test]
fn rsa_2048_key_rejected_by_rsa_pkcs1_3072_8192_sha384() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_3072_8192_SHA384,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_rejected_by_rsa_pkcs1_3072_8192_sha384_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_3072_8192_SHA384,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn key_usage_digital_signature_accepted() {
    // An end-entity certificate that asserts the digitalSignature bit in its KeyUsage extension
    // may be used to verify a signature.
    let test_cert = TestCertificate::generate_with_key_usages(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        "key usage test",
        vec![KeyUsagePurpose::DigitalSignature],
    );
    let good_sig = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Ok(())
    );
}

#[test]
fn key_usage_without_digital_signature_rejected() {
    // An end-entity certificate that carries a KeyUsage extension which does not assert the
    // digitalSignature bit must not be usable to verify a signature, even when the signature
    // itself is valid.
    let test_cert = TestCertificate::generate_with_key_usages(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        "key usage test",
        vec![KeyUsagePurpose::KeyAgreement],
    );
    let good_sig = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Err(webpki::Error::KeyUsageMissingDigitalSignature)
    );
    // The raw public key API does not see the certificate's KeyUsage extension, so it remains
    // usable to verify the same signature.
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &good_sig),
        Ok(())
    );
}

struct TestCertificate {
    key_pair: KeyPair,
    cert: Certificate,
    spki_der: Vec<u8>,
}

impl TestCertificate {
    fn generate(alg: &'static SignatureAlgorithm, org: &str) -> Self {
        Self::generate_with_key_usages(alg, org, vec![])
    }

    fn generate_with_key_usages(
        alg: &'static SignatureAlgorithm,
        org: &str,
        key_usages: Vec<KeyUsagePurpose>,
    ) -> Self {
        let key_pair = KeyPair::generate_for(alg).unwrap();

        let mut ee_params = CertificateParams::new(vec![]).unwrap();
        ee_params
            .distinguished_name
            .push(DnType::OrganizationName, org);

        // rcgen only emits the extensions block (including KeyUsage) when this is set.
        ee_params.is_ca = IsCa::ExplicitNoCa;
        ee_params.key_usages = key_usages;

        let issuer = common::make_issuer("issuer.example.com").unwrap();
        let cert = ee_params.signed_by(&key_pair, &issuer).unwrap();

        let (_, parsed_cert) = X509Certificate::from_der(cert.der()).unwrap();
        let spki_der = parsed_cert.public_key().raw.to_vec();

        Self {
            key_pair,
            cert,
            spki_der,
        }
    }

    fn sign_bad(&self, message: &[u8]) -> Vec<u8> {
        // Sign a different message to create a bad signature
        let mut bad_message = message.to_vec();
        bad_message.push(b'X');
        self.sign(&bad_message)
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).unwrap()
    }
}

const MESSAGE: &[u8] = b"hello world!";
