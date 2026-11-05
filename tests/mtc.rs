#![cfg(feature = "alloc")]

//! Merkle Tree Certificate verification, against the fixtures that
//! `tests/mtc/make_mtc_testcerts.py` generates.

use core::time::Duration;

use pki_types::{
    CertificateDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, TrustAnchor, UnixTime,
};
use serde::Deserialize;
use webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, Error, ExtendedKeyUsage, MtcCa,
    MtcCosigner, MtcHash, MtcSubtree, PathBuilder, RevocationOptions, RevocationOptionsBuilder,
    anchor_from_trusted_cert,
};

#[test]
fn standalone_accepted() {
    for quorum in 0..=2 {
        assert_eq!(verify(STANDALONE, &[ca(quorum)]), Ok(()));
    }
}

#[test]
fn landmark_accepted() {
    assert_eq!(verify(LANDMARK, &[landmark_ca()]), Ok(()));
}

#[test]
fn landmark_rejected_without_trusted_subtrees() {
    assert_eq!(verify(LANDMARK, &[ca(0)]), Err(Error::InvalidMtcProof));
}

#[test]
fn rejected_without_mtc_ca() {
    // Neither as an MTC CA, nor as a classic trust anchor.
    let ca = CertificateDer::from(CA);
    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];
    for anchors in [&[][..], &anchors[..]] {
        assert_eq!(
            build(STANDALONE, &[], anchors, None, None),
            Err(Error::UnknownIssuer)
        );
    }

    // Another issuer.
    assert_eq!(verify(STANDALONE, &[]), Err(Error::UnknownIssuer));
}

#[test]
fn trusted_subtree_with_wrong_hash() {
    // A trusted subtree decides alone, even though the cosignatures are valid.
    let mut ca = ca(0);
    ca.set_trusted_subtrees(vec![MtcSubtree {
        log_number: 1,
        start: 8,
        end: 13,
        hash: [0; 32],
    }]);
    assert_eq!(verify(STANDALONE, &[ca]), Err(Error::InvalidMtcProof));

    let mut ca = landmark_ca();
    let mut subtrees = trusted_subtrees();
    subtrees[1].hash[0] ^= 1;
    ca.set_trusted_subtrees(subtrees);
    assert_eq!(verify(LANDMARK, &[ca]), Err(Error::InvalidMtcProof));
}

#[test]
fn trusted_subtree_of_another_log() {
    let mut ca = ca(0);
    let mut subtrees = trusted_subtrees();
    subtrees[1].log_number = 2;
    ca.set_trusted_subtrees(subtrees);
    assert_eq!(verify(LANDMARK, &[ca]), Err(Error::InvalidMtcProof));
}

#[test]
fn ca_cosignature_required() {
    let ee = include_bytes!("mtc/no-ca-cosignature.der");
    for quorum in 0..=2 {
        assert_eq!(verify(ee, &[ca(quorum)]), Err(Error::InvalidMtcProof));
    }
}

#[test]
fn witness_quorum() {
    assert_eq!(verify(STANDALONE, &[ca(3)]), Err(Error::InvalidMtcProof));

    // Cosignatures from cosigners that aren't configured don't count.
    let ca = MtcCa::from_ca_cert(&CertificateDer::from(CA), Vec::new(), 1).unwrap();
    assert_eq!(verify(STANDALONE, &[ca]), Err(Error::InvalidMtcProof));
}

#[test]
fn malformed_cosignatures() {
    for ee in [
        &include_bytes!("mtc/duplicate-cosignature.der")[..],
        include_bytes!("mtc/misordered-cosignatures.der"),
    ] {
        assert_eq!(verify(ee, &[ca(0)]), Err(Error::MalformedMtcProof));
    }
}

#[test]
fn revoked_serials() {
    // Outside the CA certificate's serial number range.
    for ee in [
        &include_bytes!("mtc/below-min-serial.der")[..],
        include_bytes!("mtc/above-max-serial.der"),
    ] {
        assert_eq!(verify(ee, &[ca(0)]), Err(Error::CertRevoked));
    }

    // In an added range.
    let serial = manifest().standalone_serial;
    let mut ca = ca(0);
    ca.add_revoked_range(serial + 1..=u64::MAX);
    ca.add_revoked_range(0..=serial - 1);
    assert_eq!(verify(STANDALONE, &[ca.clone()]), Ok(()));
    ca.add_revoked_range(serial..=serial);
    assert_eq!(verify(STANDALONE, &[ca]), Err(Error::CertRevoked));
}

#[test]
fn serial_selects_index() {
    // The serial number is not in the leaf hash, but picks the index the proof is for.
    let serial = STANDALONE.windows(9).position(|w| w == SERIAL_TLV).unwrap() + 2;
    let with_serial = |value: [u8; 7]| {
        let mut ee = STANDALONE.to_vec();
        ee[serial..serial + 7].copy_from_slice(&value);
        verify(&ee, &[ca(0)])
    };

    // Another index in the subtree, and one outside it.
    assert_eq!(
        with_serial([1, 0, 0, 0, 0, 0, 10]),
        Err(Error::InvalidMtcProof)
    );
    assert_eq!(
        with_serial([1, 0, 0, 0, 0, 0, 7]),
        Err(Error::InvalidMtcProof)
    );
    // Log 0 is always revoked, because the minimum serial number is at least 2^48.
    assert_eq!(
        with_serial([0, 0xff, 0, 0, 0, 0, 9]),
        Err(Error::CertRevoked)
    );
    // Negative.
    assert_eq!(
        with_serial([0x81, 0, 0, 0, 0, 0, 9]),
        Err(Error::MalformedMtcProof)
    );
}

#[test]
fn cosigned_message_must_match() {
    for ee in [
        &include_bytes!("mtc/wrong-log-origin.der")[..],
        include_bytes!("mtc/wrong-cosigner-name.der"),
        include_bytes!("mtc/wrong-start.der"),
        include_bytes!("mtc/wrong-end.der"),
        include_bytes!("mtc/nonzero-timestamp.der"),
    ] {
        assert_eq!(verify(ee, &[ca(0)]), Err(Error::InvalidMtcProof));
    }
}

#[test]
fn rejected_under_intermediate() {
    let intermediates = [CertificateDer::from(
        &include_bytes!("mtc/intermediate.der")[..],
    )];
    assert_eq!(
        build(
            include_bytes!("mtc/ee-under-intermediate.der"),
            &intermediates,
            &[],
            Some(&[ca(0)]),
            None,
        ),
        Err(Error::InvalidMtcProof)
    );
}

#[test]
fn cosigner_key_never_signs_certificates() {
    let ee = include_bytes!("mtc/cosigner-signed.der");
    assert_eq!(verify(ee, &[ca(0)]), Err(Error::UnknownIssuer));

    // Not even with the CA certificate as a classic trust anchor.
    let ca_der = CertificateDer::from(CA);
    let anchors = [anchor_from_trusted_cert(&ca_der).unwrap()];
    assert_eq!(
        build(ee, &[], &anchors, Some(&[ca(0)]), None),
        Err(Error::UnknownIssuer)
    );
    assert_eq!(
        build(ee, &[], &anchors, None, None),
        Err(Error::UnknownIssuer)
    );
}

#[test]
fn tbs_certificate_bit_flips() {
    let (tbs_start, tbs_end) = (4, 4 + der_len(&STANDALONE[4..]));
    let serial = STANDALONE.windows(9).position(|w| w == SERIAL_TLV).unwrap();
    let cas = [ca(0)];
    for i in (tbs_start..tbs_end).filter(|i| !(serial..serial + 9).contains(i)) {
        for bit in 0..8 {
            let mut ee = STANDALONE.to_vec();
            ee[i] ^= 1 << bit;
            assert!(verify(&ee, &cas).is_err(), "byte {i} bit {bit}");
        }
    }
}

#[test]
fn crl_signed_by_ca_cosigner() {
    let crl = CertRevocationList::from(
        BorrowedCertRevocationList::from_der(include_bytes!("mtc/ca.crl.der")).unwrap(),
    );
    let crls = [&crl];
    let revocation = || Some(RevocationOptionsBuilder::new(&crls).unwrap().build());

    let cas = [landmark_ca()];
    assert_eq!(
        build(STANDALONE, &[], &[], Some(&cas), revocation()),
        Err(Error::CertRevoked)
    );
    assert_eq!(build(LANDMARK, &[], &[], Some(&cas), revocation()), Ok(()));
}

#[test]
fn path_verification_callback() {
    let cas = [ca(0)];
    let ee_der = CertificateDer::from(STANDALONE);
    let ee = EndEntityCert::try_from(&ee_der).unwrap();
    let reject = |_: &webpki::VerifiedPath<'_>| Err(Error::NameConstraintViolation);
    let result = PathBuilder::new(&[], None, &ExtendedKeyUsage::SERVER_AUTH, ALGS, &[])
        .with_mtc(&cas, &Sha256)
        .with_path_verification(&reject)
        .build(&ee, time());
    assert_eq!(result.err(), Some(Error::NameConstraintViolation));

    let path = PathBuilder::new(&[], None, &ExtendedKeyUsage::SERVER_AUTH, ALGS, &[])
        .with_mtc(&cas, &Sha256)
        .build(&ee, time())
        .unwrap();
    assert_eq!(path.intermediate_certificates().count(), 0);
    assert_eq!(path.anchor().subject.as_ref(), &CA_NAME);
}

#[test]
fn ca_certificate_rejections() {
    for (der, err) in [
        (
            &include_bytes!("mtc/ca-no-extension.der")[..],
            Error::ExtensionValueInvalid,
        ),
        (
            include_bytes!("mtc/ca-not-critical.der"),
            Error::ExtensionValueInvalid,
        ),
        (
            include_bytes!("mtc/ca-min-serial-too-small.der"),
            Error::ExtensionValueInvalid,
        ),
        (
            include_bytes!("mtc/ca-min-serial-above-max.der"),
            Error::ExtensionValueInvalid,
        ),
        (include_bytes!("mtc/ca-not-ca-id-name.der"), Error::BadDer),
    ] {
        let result = MtcCa::from_ca_cert(&CertificateDer::from(der), Vec::new(), 0);
        assert_eq!(result.err(), Some(err));
    }
}

#[test]
fn cosigner_rejections() {
    let alg = rustls_aws_lc_rs::ED25519.signature_alg_id();
    let spki = SubjectPublicKeyInfoDer::from(&[0x30, 0x00][..]);
    assert!(MtcCosigner::new(&[1], &spki, alg).is_ok());
    for id in [&[][..], &[0x81], &[1; 33]] {
        assert_eq!(MtcCosigner::new(id, &spki, alg).err(), Some(Error::BadDer));
    }

    let spki = SubjectPublicKeyInfoDer::from(&[0x31, 0x00][..]);
    assert_eq!(
        MtcCosigner::new(&[1], &spki, alg).err(),
        Some(Error::BadDer)
    );
}

#[test]
fn requested_trust_anchor_id() {
    let m = manifest();
    let ca_id = unhex(&m.ca_id);
    let mut ca = ca(0);
    assert_eq!(ca.requested_trust_anchor_id(), ca_id);

    // caID.2.N.L (MTC section 8.2.1).
    ca.set_latest_landmark(Some((m.log_number, m.latest_landmark)))
        .unwrap();
    assert_eq!(
        ca.requested_trust_anchor_id(),
        [&ca_id[..], &[2, 1, 1]].concat()
    );

    ca.set_latest_landmark(None).unwrap();
    assert_eq!(ca.requested_trust_anchor_id(), ca_id);
}

fn verify(ee: &[u8], cas: &[MtcCa]) -> Result<(), Error> {
    build(ee, &[], &[], Some(cas), None)
}

fn build(
    ee: &[u8],
    intermediates: &[CertificateDer<'_>],
    anchors: &[TrustAnchor<'_>],
    cas: Option<&[MtcCa]>,
    revocation: Option<RevocationOptions<'_>>,
) -> Result<(), Error> {
    let ee_der = CertificateDer::from(ee);
    let ee = EndEntityCert::try_from(&ee_der)?;
    let builder = PathBuilder::new(
        intermediates,
        revocation,
        &ExtendedKeyUsage::SERVER_AUTH,
        ALGS,
        anchors,
    );
    let builder = match cas {
        Some(cas) => builder.with_mtc(cas, &Sha256),
        None => builder,
    };
    builder.build(&ee, time()).map(|_| ())
}

fn ca(witness_quorum: usize) -> MtcCa {
    let witnesses = manifest()
        .witnesses
        .iter()
        .map(|w| {
            let alg = match w.alg.as_str() {
                "ECDSA_P256_SHA256" => rustls_aws_lc_rs::ECDSA_P256_SHA256,
                "ML_DSA_44" => rustls_post_quantum::ML_DSA_44,
                alg => panic!("unknown algorithm {alg}"),
            };
            let spki = SubjectPublicKeyInfoDer::from(unhex(&w.spki));
            MtcCosigner::new(&unhex(&w.id), &spki, alg.signature_alg_id()).unwrap()
        })
        .collect();
    MtcCa::from_ca_cert(&CertificateDer::from(CA), witnesses, witness_quorum).unwrap()
}

fn landmark_ca() -> MtcCa {
    let mut ca = ca(2);
    ca.set_trusted_subtrees(trusted_subtrees());
    ca
}

fn trusted_subtrees() -> Vec<MtcSubtree> {
    manifest()
        .trusted_subtrees
        .iter()
        .map(|t| MtcSubtree {
            log_number: t.log_number,
            start: t.start,
            end: t.end,
            hash: unhex(&t.hash).try_into().unwrap(),
        })
        .collect()
}

fn time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(manifest().validation_time))
}

fn manifest() -> Manifest {
    serde_json::from_str(include_str!("mtc/manifest.json")).unwrap()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The total length of the DER element at the start of `der`.
fn der_len(der: &[u8]) -> usize {
    match der[1] {
        len if len < 0x80 => 2 + usize::from(len),
        0x81 => 3 + usize::from(der[2]),
        0x82 => 4 + ((usize::from(der[2]) << 8) | usize::from(der[3])),
        _ => unreachable!(),
    }
}

#[derive(Deserialize)]
struct Manifest {
    validation_time: u64,
    ca_id: String,
    log_number: u16,
    standalone_serial: u64,
    witnesses: Vec<Witness>,
    latest_landmark: u64,
    trusted_subtrees: Vec<TrustedSubtree>,
}

#[derive(Deserialize)]
struct Witness {
    id: String,
    spki: String,
    alg: String,
}

#[derive(Deserialize)]
struct TrustedSubtree {
    log_number: u16,
    start: u64,
    end: u64,
    hash: String,
}

struct Sha256;

impl MtcHash for Sha256 {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        let hash = rustls_aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
            .common
            .hash_provider;
        let mut ctx = hash.start();
        for part in parts {
            ctx.update(part);
        }
        ctx.finish().as_ref().try_into().unwrap()
    }
}

static ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    rustls_aws_lc_rs::ED25519,
    rustls_aws_lc_rs::ECDSA_P256_SHA256,
    rustls_post_quantum::ML_DSA_44,
];

const CA: &[u8] = include_bytes!("mtc/ca.der");
const STANDALONE: &[u8] = include_bytes!("mtc/standalone.der");
const LANDMARK: &[u8] = include_bytes!("mtc/landmark.der");

/// The standalone certificate's serial number: log 1, index 9.
const SERIAL_TLV: [u8; 9] = [0x02, 0x07, 1, 0, 0, 0, 0, 0, 9];

/// The CA ID 32473.1 as a distinguished name, without the outer SEQUENCE.
const CA_NAME: [u8; 20] = [
    0x31, 0x12, 0x30, 0x10, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x19, 0x03, 0x0d, 0x04,
    0x81, 0xfd, 0x59, 0x01,
];
