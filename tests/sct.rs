//! Verification of real-world SCTs embedded in certificates.
//!
//! The fixtures in `tests/sct/` are real certificates collected in November 2026:
//!
//! - `<host>/ee.der`: the end-entity certificate served by `<host>`, carrying two embedded SCTs.
//! - `<host>/inter.der`: the certificate that issued it. We use this as the trust anchor, as
//!   only the immediate issuer matters for SCT verification.
//! - `logs/*.der`: the `SubjectPublicKeyInfo` of each log, from Chrome's log list (v97.3).
//!
//! Between them, these cover SCTs from RFC 6962 logs (Cloudflare Nimbus2027, DigiCert
//! Sphinx2027h1), which have empty SCT extensions, and from a static-ct-api log (Let's
//! Encrypt Willow2027h1), whose SCTs carry a `leaf_index` extension.

#![cfg(feature = "alloc")]

use core::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use pki_types::{
    CertificateDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls_aws_lc_rs::{ALL_VERIFICATION_ALGS, ECDSA_P256_SHA256};
use webpki::sct::{self, LogIdAndTimestamp, LogLookup};
use webpki::{
    EndEntityCert, Error, ExtendedKeyUsage, PathBuilder, VerifiedPath, anchor_from_trusted_cert,
};

#[test]
fn letsencrypt_org() {
    check(
        include_bytes!("sct/letsencrypt.org/ee.der"),
        include_bytes!("sct/letsencrypt.org/inter.der"),
        &[
            (CLOUDFLARE_NIMBUS2027, 1_793_716_984_256), // 2026-11-03T14:43:04.256Z
            (DIGICERT_SPHINX2027H1, 1_793_716_986_252), // 2026-11-03T14:43:06.252Z
        ],
    );
}

#[test]
fn www_cloudflare_com() {
    check(
        include_bytes!("sct/www.cloudflare.com/ee.der"),
        include_bytes!("sct/www.cloudflare.com/inter.der"),
        &[
            (CLOUDFLARE_NIMBUS2027, 1_794_852_368_336), // 2026-11-16T18:06:08.336Z
            (LETSENCRYPT_WILLOW2027H1, 1_794_852_368_533), // 2026-11-16T18:06:08.533Z
        ],
    );
}

#[test]
fn github_com() {
    check(
        include_bytes!("sct/github.com/ee.der"),
        include_bytes!("sct/github.com/inter.der"),
        &[
            (DIGICERT_SPHINX2027H1, 1_793_319_667_488), // 2026-10-30T00:21:07.488Z
            (LETSENCRYPT_WILLOW2027H1, 1_793_319_667_750), // 2026-10-30T00:21:07.750Z
        ],
    );
}

/// Check that every SCT in `ee` verifies, and yields `expected`; then check the ways
/// verification can fail or be skipped.
fn check(ee: &[u8], inter: &[u8], expected: &[(&[u8], u64)]) {
    let ee = CertificateDer::from(ee);
    let inter = CertificateDer::from(inter);
    let anchors = [anchor_from_trusted_cert(&inter).unwrap()];
    let ee = EndEntityCert::try_from(&ee).unwrap();
    let path = PathBuilder::new(
        &[],
        None,
        &ExtendedKeyUsage::SERVER_AUTH,
        ALL_VERIFICATION_ALGS,
        &anchors,
    )
    .build(&ee, TIME)
    .unwrap();

    let issuer_spki_sha256 = sha256(&path.issuer_spki());

    // All SCTs are authentic.
    let expected = expected
        .iter()
        .map(|(log, timestamp_ms)| {
            Ok(LogIdAndTimestamp {
                log_id: sha256(log),
                timestamp_ms: *timestamp_ms,
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        verify(&path, issuer_spki_sha256, &KnownLogs, &[ECDSA_P256_SHA256]),
        expected
    );

    // The issuer's key is part of the signed data.
    let mut wrong_issuer = issuer_spki_sha256;
    wrong_issuer[0] ^= 1;
    assert_eq!(
        verify(&path, wrong_issuer, &KnownLogs, &[ECDSA_P256_SHA256]),
        [INVALID, INVALID]
    );

    // Each SCT is only valid with its own log's key.
    assert_eq!(
        verify(&path, issuer_spki_sha256, &WrongLogs, &[ECDSA_P256_SHA256]),
        [INVALID, INVALID]
    );

    // SCTs from unknown logs are skipped.
    assert_eq!(
        verify(&path, issuer_spki_sha256, &NoLogs, &[ECDSA_P256_SHA256]),
        []
    );

    // SCTs with unsupported signature algorithms are skipped.
    assert_eq!(verify(&path, issuer_spki_sha256, &KnownLogs, &[]), []);
}

fn verify(
    path: &VerifiedPath<'_>,
    issuer_spki_sha256: [u8; 32],
    logs: &dyn LogLookup,
    signature_algorithms: &[&'static dyn SignatureVerificationAlgorithm],
) -> Vec<Result<LogIdAndTimestamp, Error>> {
    path.verify_scts(issuer_spki_sha256, logs, signature_algorithms)
        .unwrap()
        .map(|sct| sct.map(|sct| sct.inclusion))
        .collect()
}

/// Knows every log in `LOGS`.
struct KnownLogs;

impl LogLookup for KnownLogs {
    fn lookup(&self, id: &[u8; 32]) -> Option<SubjectPublicKeyInfoDer<'_>> {
        LOGS.iter()
            .find(|log| sha256(log) == *id)
            .map(|log| SubjectPublicKeyInfoDer::from(*log))
    }
}

/// Returns some other log's key for every log ID.
struct WrongLogs;

impl LogLookup for WrongLogs {
    fn lookup(&self, id: &[u8; 32]) -> Option<SubjectPublicKeyInfoDer<'_>> {
        LOGS.iter()
            .find(|log| sha256(log) != *id)
            .map(|log| SubjectPublicKeyInfoDer::from(*log))
    }
}

/// Knows no logs.
struct NoLogs;

impl LogLookup for NoLogs {
    fn lookup(&self, _id: &[u8; 32]) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    digest(&SHA256, data).as_ref().try_into().unwrap()
}

const INVALID: Result<LogIdAndTimestamp, Error> = Err(Error::SignedCertificateTimestampError(
    sct::Error::InvalidSctSignature,
));

const LOGS: &[&[u8]] = &[
    CLOUDFLARE_NIMBUS2027,
    DIGICERT_SPHINX2027H1,
    LETSENCRYPT_WILLOW2027H1,
];

const CLOUDFLARE_NIMBUS2027: &[u8] = include_bytes!("sct/logs/cloudflare-nimbus2027.der");
const DIGICERT_SPHINX2027H1: &[u8] = include_bytes!("sct/logs/digicert-sphinx2027h1.der");
const LETSENCRYPT_WILLOW2027H1: &[u8] = include_bytes!("sct/logs/letsencrypt-willow2027h1.der");

/// 2026-11-20T00:00:00Z, when all fixture certificates are valid.
const TIME: UnixTime = UnixTime::since_unix_epoch(Duration::from_secs(1_795_132_800));
