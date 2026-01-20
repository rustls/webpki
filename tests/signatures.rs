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

use pki_types::{CertificateDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SignatureAlgorithm, SigningKey};
use x509_parser::prelude::*;

#[cfg(feature = "ring")]
use webpki::ring::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384, ED25519,
};
#[cfg(all(feature = "ring", feature = "alloc"))]
use webpki::ring::{
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384, RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY, RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
};

#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
use webpki::aws_lc_rs::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA256,
    ECDSA_P521_SHA384, ECDSA_P521_SHA512, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
};

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
fn ed25519_key_and_ed25519_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ED25519, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn ed25519_key_and_ed25519_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ED25519, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn ed25519_key_and_ed25519_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ED25519, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ed25519_key_and_ed25519_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ED25519, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ed25519_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ED25519, "ed25519 test");
    for algorithm in &[
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA256,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA384,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
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
fn ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature() {
    let ee = include_bytes!("signatures/ecdsa_p256.ee.der");
    let message = include_bytes!("signatures/message.bin");
    let signature =
        include_bytes!("signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature.sig.bin");
    assert_eq!(check_sig(ee, ECDSA_P256_SHA384, message, signature), Ok(()));
}

/// P256 with SHA384 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature_rpk() {
    let rpk = include_bytes!("signatures/ecdsa_p256.spki.der");
    let message = include_bytes!("signatures/message.bin");
    let signature =
        include_bytes!("signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_good_signature.sig.bin");
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P256_SHA384, message, signature),
        Ok(())
    );
}

/// P256 with SHA384 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature() {
    let ee = include_bytes!("signatures/ecdsa_p256.ee.der");
    let message = include_bytes!("signatures/message.bin");
    let signature = include_bytes!(
        "signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature.sig.bin"
    );
    assert_eq!(
        check_sig(ee, ECDSA_P256_SHA384, message, signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

/// P256 with SHA384 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature_rpk() {
    let rpk = include_bytes!("signatures/ecdsa_p256.spki.der");
    let message = include_bytes!("signatures/message.bin");
    let signature = include_bytes!(
        "signatures/ecdsa_p256_key_and_ecdsa_p256_sha384_detects_bad_signature.sig.bin"
    );
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P256_SHA384, message, signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha256_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P256_SHA256, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha256_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha256_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P256_SHA256, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p256_key_and_ecdsa_p256_sha256_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P256_SHA256, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p256_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa_p256 test");
    for algorithm in &[
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA256,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA384,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
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
fn ecdsa_p384_key_and_ecdsa_p384_sha384_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P384_SHA384, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha384_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P384_SHA384, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha384_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(test_cert.cert.der(), ECDSA_P384_SHA384, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha384_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P384_SHA384, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

/// P384 with SHA256 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature() {
    let ee = include_bytes!("signatures/ecdsa_p384.ee.der");
    let message = include_bytes!("signatures/message.bin");
    let signature =
        include_bytes!("signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature.sig.bin");
    assert_eq!(check_sig(ee, ECDSA_P384_SHA256, message, signature), Ok(()));
}

/// P384 with SHA256 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature_rpk() {
    let rpk = include_bytes!("signatures/ecdsa_p384.spki.der");
    let message = include_bytes!("signatures/message.bin");
    let signature =
        include_bytes!("signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_good_signature.sig.bin");
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P384_SHA256, message, signature),
        Ok(())
    );
}

/// P384 with SHA256 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature() {
    let ee = include_bytes!("signatures/ecdsa_p384.ee.der");
    let message = include_bytes!("signatures/message.bin");
    let signature = include_bytes!(
        "signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature.sig.bin"
    );
    assert_eq!(
        check_sig(ee, ECDSA_P384_SHA256, message, signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

/// P384 with SHA256 signing is not supported by aws-lc-rs, so these tests use pre-generated keys.
#[test]
fn ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature_rpk() {
    let rpk = include_bytes!("signatures/ecdsa_p384.spki.der");
    let message = include_bytes!("signatures/message.bin");
    let signature = include_bytes!(
        "signatures/ecdsa_p384_key_and_ecdsa_p384_sha256_detects_bad_signature.sig.bin"
    );
    assert_eq!(
        check_sig_rpk(rpk, ECDSA_P384_SHA256, message, signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn ecdsa_p384_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa_p384 test");
    for algorithm in &[
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA256,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA384,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
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
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha512_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA512, "ecdsa_p521 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            &test_cert.cert.der(),
            ECDSA_P521_SHA512,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha512_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA512, "ecdsa_p521 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA512, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha512_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA512, "ecdsa_p521 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(
            &test_cert.cert.der(),
            ECDSA_P521_SHA512,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha512_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA512, "ecdsa_p521 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA512, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha256_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA256, "ecdsa_p521 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            &test_cert.cert.der(),
            ECDSA_P521_SHA256,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha256_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA256, "ecdsa_p521 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA256, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha256_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA256, "ecdsa_p521 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(
            &test_cert.cert.der(),
            ECDSA_P521_SHA256,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha256_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA256, "ecdsa_p521 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA256, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha384_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA384, "ecdsa_p521 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            &test_cert.cert.der(),
            ECDSA_P521_SHA384,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha384_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA384, "ecdsa_p521 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA384, MESSAGE, &signature),
        Ok(())
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha384_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA384, "ecdsa_p521 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(
            &test_cert.cert.der(),
            ECDSA_P521_SHA384,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
fn ecdsa_p521_key_and_ecdsa_p521_sha384_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_ECDSA_P521_SHA384, "ecdsa_p521 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(&test_cert.spki_der, ECDSA_P521_SHA384, MESSAGE, &signature),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
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
            check_sig(&test_cert.cert.der(), *algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey(_))
        ));
    }
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha256_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha256_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha256_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha256_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA256,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha384_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha384_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha384_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha384_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA384, "rsa_2048 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA384,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha512_good_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA512, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha512_good_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA512, "rsa_2048 test");
    let signature = test_cert.sign(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha512_detects_bad_signature() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA512, "rsa_2048 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig(
            test_cert.cert.der(),
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_and_rsa_pkcs1_2048_8192_sha512_detects_bad_signature_rpk() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA512, "rsa_2048 test");
    let signature = test_cert.sign_bad(MESSAGE);
    assert_eq!(
        check_sig_rpk(
            &test_cert.spki_der,
            RSA_PKCS1_2048_8192_SHA512,
            MESSAGE,
            &signature
        ),
        Err(webpki::Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn rsa_2048_key_rejected_by_other_algorithms() {
    let test_cert = TestCertificate::generate(&rcgen::PKCS_RSA_SHA256, "rsa_2048 test");
    for algorithm in &[
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA256,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        ECDSA_P521_SHA384,
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
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

struct TestCertificate {
    key_pair: KeyPair,
    cert: Certificate,
    spki_der: Vec<u8>,
}

impl TestCertificate {
    fn generate(alg: &'static SignatureAlgorithm, org: &str) -> Self {
        let key_pair = KeyPair::generate_for(alg).unwrap();

        let mut ee_params = CertificateParams::new(vec![]).unwrap();
        ee_params
            .distinguished_name
            .push(DnType::OrganizationName, org);

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
