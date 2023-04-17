use std::convert::TryFrom;
use webpki::{CertRevocationList, Error};

#[test]
fn parse_valid_crl() {
    // We should be able to parse a valid CRL without error.
    let crl = include_bytes!("crls/crl.valid.der");
    let crl = CertRevocationList::try_from(&crl[..]).expect("failed to parse valid crl");

    // The CRL should have the expected number.
    let expected_crl_number: &[u8] = &[0x17, 0x1C, 0xCE, 0x3D, 0xE4, 0x82, 0xBA, 0x61];
    assert_eq!(crl.crl_number, Some(expected_crl_number));

    // The encoded AKI should match expected.
    let expected_aki: &[u8] = &[
        0x30, 0x16, 0x80, 0x14, 0x01, 0xDA, 0xBB, 0x7A, 0xCB, 0x25, 0x20, 0x8E, 0x5E, 0x79, 0xD6,
        0xF9, 0x96, 0x42, 0x2F, 0x02, 0x41, 0x29, 0x07, 0xBE,
    ];
    let aki = crl.authority_key_identifier.expect("missing AKI");
    assert_eq!(aki.as_slice_less_safe(), expected_aki);
}

#[test]
fn parse_empty_crl() {
    // We should be able to parse an empty CRL without error.
    let crl = include_bytes!("crls/crl.empty.der");
    let _ = CertRevocationList::try_from(&crl[..]).expect("failed to parse empty crl");
}

#[test]
fn parse_mismatched_sigalg_crl() {
    // Parsing a CRL with a mismatched outer/inner signature algorithm should fail.
    let crl = include_bytes!("crls/crl.mismatched.sigalg.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::SignatureAlgorithmMismatch)));
}

#[test]
fn parse_bad_this_update_crl() {
    // Parsing a CRL with an invalid this update time should error.
    let crl = include_bytes!("crls/crl.invalid.this.update.time.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::BadDerTime)));
}

#[test]
fn parse_missing_next_update_crl() {
    // Parsing a CRL with a missing next update time should error.
    let crl = include_bytes!("crls/crl.missing.next.update.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::BadDer)));
}

#[test]
fn parse_wrong_version_crl() {
    // Parsing a CRL with an unsupported version should error.
    let crl = include_bytes!("crls/crl.wrong.version.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::UnsupportedCrlVersion)));
}

#[test]
fn parse_missing_exts_crl() {
    // Parsing a CRL with no list extensions should error.
    let crl = include_bytes!("crls/crl.missing.exts.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::MalformedExtensions)));
}

#[test]
fn parse_delta_crl() {
    // Parsing a CRL with an extension indicating its a delta CRL should error.
    let crl = include_bytes!("crls/crl.delta.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::UnsupportedDeltaCrl)));
}

#[test]
fn parse_unknown_crit_ext_crl() {
    // Parsing a CRL with an unknown critical list extension should error.
    let crl = include_bytes!("crls/crl.unknown.crit.ext.der");
    let res = CertRevocationList::try_from(&crl[..]);
    assert!(matches!(res, Err(Error::UnsupportedCriticalExtension)));
}
