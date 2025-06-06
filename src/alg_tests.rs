// Copyright 2015 Brian Smith.
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

#![allow(clippy::duplicate_mod)]

use std::prelude::v1::*;

use base64::{Engine as _, engine::general_purpose};

use crate::error::{DerTypeId, Error};
use crate::verify_cert::Budget;
use crate::{der, signed_data};

use super::{
    INVALID_SIGNATURE_FOR_RSA_KEY, OK_IF_POINT_COMPRESSION_SUPPORTED, OK_IF_RSA_AVAILABLE,
    SUPPORTED_ALGORITHMS_IN_TESTS, UNSUPPORTED_ECDSA_SHA512_SIGNATURE,
    UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_RSA_KEY,
};

macro_rules! test_file_bytes {
    ( $file_name:expr ) => {
        include_bytes!(concat!(
            "../third-party/chromium/data/verify_signed_data/",
            $file_name
        ))
    };
}

// TODO: The expected results need to be modified for SHA-1 deprecation.

fn test_verify_signed_data(file_contents: &[u8]) -> Result<(), Error> {
    let tsd = parse_test_signed_data(file_contents);
    let spki_value = untrusted::Input::from(&tsd.spki);
    let spki_value = spki_value
        .read_all(Error::BadDer, |input| {
            der::expect_tag(input, der::Tag::Sequence)
        })
        .unwrap();

    // we can't use `parse_signed_data` because it requires `data`
    // to be an ASN.1 SEQUENCE, and that isn't the case with
    // Chromium's test data. TODO: The test data set should be
    // expanded with SEQUENCE-wrapped data so that we can actually
    // test `parse_signed_data`.

    let algorithm = untrusted::Input::from(&tsd.algorithm);
    let algorithm = algorithm
        .read_all(
            Error::TrailingData(DerTypeId::SignatureAlgorithm),
            |input| der::expect_tag(input, der::Tag::Sequence),
        )
        .unwrap();

    let signature = untrusted::Input::from(&tsd.signature);
    let signature = signature
        .read_all(Error::TrailingData(DerTypeId::Signature), |input| {
            der::bit_string_with_no_unused_bits(input)
        })
        .unwrap();

    let signed_data = signed_data::SignedData {
        data: untrusted::Input::from(&tsd.data),
        algorithm,
        signature,
    };

    signed_data::verify_signed_data(
        SUPPORTED_ALGORITHMS_IN_TESTS,
        spki_value,
        &signed_data,
        &mut Budget::default(),
    )
}

fn test_verify_signed_data_signature_outer(file_contents: &[u8]) -> Result<(), Error> {
    let tsd = parse_test_signed_data(file_contents);
    let signature = untrusted::Input::from(&tsd.signature);
    signature.read_all(Error::TrailingData(DerTypeId::Signature), |input| {
        der::bit_string_with_no_unused_bits(input)
    })?;

    Ok(())
}

fn test_parse_spki_bad_outer(file_contents: &[u8]) -> Result<(), Error> {
    let tsd = parse_test_signed_data(file_contents);
    let spki = untrusted::Input::from(&tsd.spki);
    spki.read_all(Error::BadDer, |input| {
        der::expect_tag(input, der::Tag::Sequence)
    })?;

    Ok(())
}

// XXX: Some of the BadDer tests should have better error codes, maybe?

// XXX: We should have a variant of this test with a SHA-256 digest that gives
// `Error::UnsupportedSignatureAlgorithmForPublicKey`.
#[test]
fn test_ecdsa_prime256v1_sha512_spki_params_null() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ecdsa-prime256v1-sha512-spki-params-null.pem"
        )),
        Err(UNSUPPORTED_ECDSA_SHA512_SIGNATURE)
    );
}

#[test]
fn test_ecdsa_prime256v1_sha512_unused_bits_signature() {
    assert_eq!(
        test_verify_signed_data_signature_outer(test_file_bytes!(
            "ecdsa-prime256v1-sha512-unused-bits-signature.pem"
        )),
        Err(Error::BadDer)
    );
}

// XXX: We should have a variant of this test with a SHA-256 digest that gives
// `Error::UnsupportedSignatureAlgorithmForPublicKey`.
#[test]
fn test_ecdsa_prime256v1_sha512_using_ecdh_key() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ecdsa-prime256v1-sha512-using-ecdh-key.pem"
        )),
        Err(UNSUPPORTED_ECDSA_SHA512_SIGNATURE)
    );
}

// XXX: We should have a variant of this test with a SHA-256 digest that gives
// `Error::UnsupportedSignatureAlgorithmForPublicKey`.
#[test]
fn test_ecdsa_prime256v1_sha512_using_ecmqv_key() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ecdsa-prime256v1-sha512-using-ecmqv-key.pem"
        )),
        Err(UNSUPPORTED_ECDSA_SHA512_SIGNATURE)
    );
}

#[test]
fn test_ecdsa_prime256v1_sha512_using_rsa_algorithm() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ecdsa-prime256v1-sha512-using-rsa-algorithm.pem"
        )),
        Err(UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_RSA_KEY)
    );
}

// XXX: We should have a variant of this test with a SHA-256 digest that gives
// `Error::InvalidSignatureForPublicKey`.
#[test]
fn test_ecdsa_prime256v1_sha512_wrong_signature_format() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ecdsa-prime256v1-sha512-wrong-signature-format.pem"
        )),
        Err(UNSUPPORTED_ECDSA_SHA512_SIGNATURE)
    );
}

// Differs from Chromium because we don't support P-256 with SHA-512.
#[test]
fn test_ecdsa_prime256v1_sha512() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ecdsa-prime256v1-sha512.pem")),
        Err(UNSUPPORTED_ECDSA_SHA512_SIGNATURE)
    );
}

#[test]
fn test_ecdsa_secp384r1_sha256_corrupted_data() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ecdsa-secp384r1-sha256-corrupted-data.pem"
        )),
        Err(Error::InvalidSignatureForPublicKey)
    );
}

#[test]
fn test_ecdsa_secp384r1_sha256() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ecdsa-secp384r1-sha256.pem")),
        Ok(())
    );
}

#[test]
fn test_ecdsa_using_rsa_key() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ecdsa-using-rsa-key.pem")),
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    );
}

#[test]
fn test_rsa_pkcs1_sha1_bad_key_der_length() {
    assert_eq!(
        test_parse_spki_bad_outer(test_file_bytes!("rsa-pkcs1-sha1-bad-key-der-length.pem")),
        Err(Error::BadDer)
    );
}

#[test]
fn test_rsa_pkcs1_sha1_bad_key_der_null() {
    assert_eq!(
        test_parse_spki_bad_outer(test_file_bytes!("rsa-pkcs1-sha1-bad-key-der-null.pem")),
        Err(Error::BadDer)
    );
}

#[test]
fn test_rsa_pkcs1_sha1_key_params_absent() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pkcs1-sha1-key-params-absent.pem")),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pkcs1_sha1_using_pss_key_no_params() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pkcs1-sha1-using-pss-key-no-params.pem"
        )),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pkcs1_sha1_wrong_algorithm() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pkcs1-sha1-wrong-algorithm.pem")),
        Err(INVALID_SIGNATURE_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa_pkcs1_sha1() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pkcs1-sha1.pem")),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

// XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
// 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
// our results differ from Chromium's. TODO: this means we need a 2048+ bit
// version of this test.

#[test]
fn test_rsa_pkcs1_sha256() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pkcs1-sha256.pem")),
        Err(INVALID_SIGNATURE_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa_pkcs1_sha256_key_encoded_ber() {
    assert_eq!(
        test_parse_spki_bad_outer(test_file_bytes!("rsa-pkcs1-sha256-key-encoded-ber.pem")),
        Err(Error::BadDer)
    );
}

#[test]
fn test_rsa_pkcs1_sha256_spki_non_null_params() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pkcs1-sha256-spki-non-null-params.pem"
        )),
        Err(UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa_pkcs1_sha256_using_ecdsa_algorithm() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pkcs1-sha256-using-ecdsa-algorithm.pem"
        )),
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    );
}

#[test]
fn test_rsa_pkcs1_sha256_using_id_ea_rsa() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pkcs1-sha256-using-id-ea-rsa.pem")),
        Err(UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_RSA_KEY)
    );
}

// Chromium's PSS test are for parameter combinations we don't support.

#[test]
fn test_rsa_pss_sha1_salt20_using_pss_key_no_params() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pss-sha1-salt20-using-pss-key-no-params.pem"
        )),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pss_sha1_salt20_using_pss_key_with_null_params() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pss-sha1-salt20-using-pss-key-with-null-params.pem"
        )),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}
#[test]
fn test_rsa_pss_sha1_salt20() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pss-sha1-salt20.pem")),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pss_sha1_wrong_salt() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pss-sha1-wrong-salt.pem")),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pss_sha256_mgf1_sha512_salt33() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pss-sha256-mgf1-sha512-salt33.pem")),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pss_sha256_salt10_using_pss_key_with_params() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pss-sha256-salt10-using-pss-key-with-params.pem"
        )),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}
#[test]
fn test_rsa_pss_sha256_salt10_using_pss_key_with_wrong_params() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "rsa-pss-sha256-salt10-using-pss-key-with-wrong-params.pem"
        )),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

#[test]
fn test_rsa_pss_sha256_salt10() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-pss-sha256-salt10.pem")),
        Err(Error::UnsupportedSignatureAlgorithm)
    );
}

// Our PSS tests that should work.

#[test]
fn test_rsa_pss_sha256_salt32() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ours/rsa-pss-sha256-salt32.pem")),
        OK_IF_RSA_AVAILABLE
    );
}

#[test]
fn test_rsa_pss_sha384_salt48() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ours/rsa-pss-sha384-salt48.pem")),
        OK_IF_RSA_AVAILABLE
    );
}

#[test]
fn test_rsa_pss_sha512_salt64() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ours/rsa-pss-sha512-salt64.pem")),
        OK_IF_RSA_AVAILABLE
    );
}

#[test]
fn test_rsa_pss_sha256_salt32_corrupted_data() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ours/rsa-pss-sha256-salt32-corrupted-data.pem"
        )),
        Err(INVALID_SIGNATURE_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa_pss_sha384_salt48_corrupted_data() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ours/rsa-pss-sha384-salt48-corrupted-data.pem"
        )),
        Err(INVALID_SIGNATURE_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa_pss_sha512_salt64_corrupted_data() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ours/rsa-pss-sha512-salt64-corrupted-data.pem"
        )),
        Err(INVALID_SIGNATURE_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa_using_ec_key() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa-using-ec-key.pem")),
        Err(UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_RSA_KEY)
    );
}

#[test]
fn test_rsa2048_pkcs1_sha512() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("rsa2048-pkcs1-sha512.pem")),
        OK_IF_RSA_AVAILABLE
    );
}

#[test]
fn test_ecdsa_prime256v1_sha256() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!("ours/ecdsa-prime256v1-sha256.pem")),
        (Ok(()))
    );
}

#[test]
fn test_ecdsa_prime256v1_sha256_compressed() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ours/ecdsa-prime256v1-sha256-compressed.pem"
        )),
        OK_IF_POINT_COMPRESSION_SUPPORTED
    );
}

#[test]
fn test_ecdsa_prime256v1_sha256_spki_inside_spki() {
    assert_eq!(
        test_verify_signed_data(test_file_bytes!(
            "ours/ecdsa-prime256v1-sha256-spki-inside-spki.pem"
        )),
        Err(Error::InvalidSignatureForPublicKey)
    );
}

struct TestSignedData {
    spki: Vec<u8>,
    data: Vec<u8>,
    algorithm: Vec<u8>,
    signature: Vec<u8>,
}

fn parse_test_signed_data(file_contents: &[u8]) -> TestSignedData {
    let mut lines = core::str::from_utf8(file_contents).unwrap().lines();
    let spki = read_pem_section(&mut lines, "PUBLIC KEY");
    let algorithm = read_pem_section(&mut lines, "ALGORITHM");
    let data = read_pem_section(&mut lines, "DATA");
    let signature = read_pem_section(&mut lines, "SIGNATURE");

    TestSignedData {
        spki,
        data,
        algorithm,
        signature,
    }
}

use alloc::str::Lines;

fn read_pem_section(lines: &mut Lines<'_>, section_name: &str) -> Vec<u8> {
    // Skip comments and header
    let begin_section = format!("-----BEGIN {}-----", section_name);
    loop {
        let line = lines.next().unwrap();
        if line == begin_section {
            break;
        }
    }

    let mut base64 = String::new();

    let end_section = format!("-----END {}-----", section_name);
    loop {
        let line = lines.next().unwrap();
        if line == end_section {
            break;
        }
        base64.push_str(line);
    }

    general_purpose::STANDARD.decode(&base64).unwrap()
}
