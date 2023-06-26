use webpki::{BorrowedCertRevocationList, Error};

const REVOKED_SERIAL: &[u8] = &[0x03, 0xAE, 0x51, 0xDB, 0x51, 0x15, 0x5A, 0x3C];

#[test]
fn parse_valid_crl() {
    // We should be able to parse a valid CRL without error.
    let crl = include_bytes!("crls/crl.valid.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).expect("failed to parse valid crl");

    // The CRL should have the expected number.
    let expected_crl_number: &[u8] = &[0x17, 0x1C, 0xCE, 0x3D, 0xE4, 0x82, 0xBA, 0x61];
    assert_eq!(crl.crl_number, Some(expected_crl_number));

    // The encoded AKI should match expected.
    let expected_aki: &[u8] = &[
        0x30, 0x16, 0x80, 0x14, 0x01, 0xDA, 0xBB, 0x7A, 0xCB, 0x25, 0x20, 0x8E, 0x5E, 0x79, 0xD6,
        0xF9, 0x96, 0x42, 0x2F, 0x02, 0x41, 0x29, 0x07, 0xBE,
    ];
    let aki = crl.authority_key_identifier().expect("missing AKI");
    assert_eq!(aki, expected_aki);

    // We should find the expected revoked certificate with the expected serial number.
    assert!(crl.find_serial(REVOKED_SERIAL).unwrap().is_some())
}

#[test]
fn parse_empty_crl() {
    // We should be able to parse an empty CRL without error.
    let crl = include_bytes!("crls/crl.empty.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).expect("failed to parse empty crl");

    // We should find no revoked certificates.
    assert!(crl.into_iter().next().is_none());
}

#[test]
fn parse_mismatched_sigalg_crl() {
    // Parsing a CRL with a mismatched outer/inner signature algorithm should fail.
    let crl = include_bytes!("crls/crl.mismatched.sigalg.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::SignatureAlgorithmMismatch)));
}

#[test]
fn parse_bad_this_update_crl() {
    // Parsing a CRL with an invalid this update time should error.
    let crl = include_bytes!("crls/crl.invalid.this.update.time.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::BadDerTime)));
}

#[test]
fn parse_missing_next_update_crl() {
    // Parsing a CRL with a missing next update time should error.
    let crl = include_bytes!("crls/crl.missing.next.update.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::BadDer)));
}

#[test]
fn parse_wrong_version_crl() {
    // Parsing a CRL with an unsupported version should error.
    let crl = include_bytes!("crls/crl.wrong.version.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::UnsupportedCrlVersion)));
}

#[test]
fn parse_missing_exts_crl() {
    // Parsing a CRL with no list extensions should error.
    let crl = include_bytes!("crls/crl.missing.exts.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::MalformedExtensions)));
}

#[test]
fn parse_delta_crl() {
    // Parsing a CRL with an extension indicating its a delta CRL should error.
    let crl = include_bytes!("crls/crl.delta.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::UnsupportedDeltaCrl)));
}

#[test]
fn parse_unknown_crit_ext_crl() {
    // Parsing a CRL with an unknown critical list extension should error.
    let crl = include_bytes!("crls/crl.unknown.crit.ext.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::UnsupportedCriticalExtension)));
}

#[test]
fn parse_negative_crl_number_crl() {
    // Parsing a CRL with a negative CRL number should error.
    let crl = include_bytes!("crls/crl.negative.crl.number.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);
    assert!(matches!(res, Err(Error::InvalidCrlNumber)));
}

#[test]
fn parse_entry_negative_serial_crl() {
    // Parsing a CRL that includes a revoked entry with a negative serial number shouldn't error
    // up-front since the error is with a revoked entry.
    let crl = include_bytes!("crls/crl.negative.serial.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

    // but searching for a revoked cert should error due to the entry with the negative serial number.
    let res = crl.find_serial(REVOKED_SERIAL);
    assert!(matches!(res, Err(Error::InvalidSerialNumber)));
}

#[test]
fn parse_entry_without_exts_crl() {
    // Parsing a CRL that includes a revoked entry that has no extensions shouldn't error.
    let crl = include_bytes!("crls/crl.no.entry.exts.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).expect("unexpected error parsing crl");
    // We should find the expected revoked certificate with the expected serial number.
    assert!(crl.find_serial(REVOKED_SERIAL).unwrap().is_some());
}

#[test]
fn parse_entry_with_empty_exts_seq() {
    let crl = include_bytes!("crls/crl.entry.empty.ext.seq.der");
    let res = BorrowedCertRevocationList::from_der(&crl[..]);

    assert!(res.is_ok());
}

#[test]
fn parse_entry_unknown_crit_ext_crl() {
    // Parsing a CRL that includes a revoked entry that has an unknown critical extension shouldn't
    // error up-front because the problem is with a revoked cert entry.
    let crl = include_bytes!("crls/crl.entry.unknown.crit.ext.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

    // but should error when we try to find a revoked serial due to the entry with the unsupported
    // critical ext.
    let res = crl.find_serial(REVOKED_SERIAL);
    assert!(matches!(res, Err(Error::UnsupportedCriticalExtension)));
}

#[test]
fn parse_entry_invalid_reason_crl() {
    // Parsing a CRL that includes a revoked entry that has an unknown revocation reason shouldn't
    // error up-front since the problem is with a revoked entry.
    let crl = include_bytes!("crls/crl.entry.invalid.reason.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

    // But searching for a serial should error due to the revoked cert with the unknown reason.
    let res = crl.find_serial(REVOKED_SERIAL);
    assert!(matches!(res, Err(Error::UnsupportedRevocationReason)));
}

#[test]
fn parse_entry_invalidity_date_crl() {
    // Parsing a CRL that includes a revoked entry that has an invalidity date ext shouldn't error.
    let crl = include_bytes!("crls/crl.entry.invalidity.date.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).expect("unexpected err parsing CRL");

    // We should find the expected revoked cert, and it should have a parsed invalidity date.
    assert!(crl
        .find_serial(REVOKED_SERIAL)
        .unwrap()
        .unwrap()
        .invalidity_date
        .is_some());
}

#[test]
fn parse_entry_indirect_issuer_crl() {
    // Parsing a CRL that includes a revoked entry that has a issuer certificate extension
    // shouldn't error up-front - we expect the error to be surfaced when we iterate the revoked
    // certs.
    let crl = include_bytes!("crls/crl.entry.issuer.ext.der");
    let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

    // But searching for a serial should error because the CRL contains a revoked cert with an
    // issuer certificate extension indicating this is an "indirect" CRL that we do not support.
    let res = crl.find_serial(REVOKED_SERIAL);
    assert!(matches!(res, Err(Error::UnsupportedIndirectCrl)));
}
