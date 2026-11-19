#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate webpki;

use core::time::Duration;

use pki_types::{CertificateDer, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsage, MtcCa, MtcHash, PathBuilder, mtc};

fuzz_target!(|data: &[u8]| {
    // Inclusion proof evaluation, with the index, start and end in the first 24 bytes.
    if let Some((head, proof)) = data.split_first_chunk::<24>() {
        let field = |i: usize| u64::from_be_bytes(head[i..i + 8].try_into().unwrap());
        let _ = mtc::evaluate_inclusion_proof(
            &XorHash,
            field(0),
            &[0; 32],
            field(8),
            field(16),
            proof,
        );
    }

    // MTCProof decoding and the rest of verification, for a certificate naming the test CA.
    let ca = CertificateDer::from(&include_bytes!("../../tests/mtc/ca.der")[..]);
    let cas = [MtcCa::from_ca_cert(&ca, Vec::new(), 0).unwrap()];
    let ee = CertificateDer::from(data);
    let Ok(ee) = EndEntityCert::try_from(&ee) else {
        return;
    };

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_780_272_000));
    let _ = PathBuilder::new(&[], None, &ExtendedKeyUsage::SERVER_AUTH, &[], &[])
        .with_mtc(&cas, &XorHash)
        .build(&ee, time);
});

/// Not SHA-256: fuzzing only needs a cheap hash that depends on its input.
struct XorHash;

impl MtcHash for XorHash {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut out = [0; 32];
        for (i, byte) in parts.iter().flat_map(|part| part.iter()).enumerate() {
            out[i % 32] ^= byte;
        }
        out
    }
}
