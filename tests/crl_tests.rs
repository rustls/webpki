use std::convert::TryFrom;
use webpki::{CertRevocationList, Error};

#[test]
fn parse_valid_crl() {
    // We should be able to parse a valid CRL without error.
    let crl = include_bytes!("crls/crl.valid.der");
    let _ = CertRevocationList::try_from(&crl[..]).expect("failed to parse valid crl");
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
