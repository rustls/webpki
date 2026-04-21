#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate webpki;

use pki_types::CertificateDer;
use webpki::anchor_from_trusted_cert;

fuzz_target!(|data: &[u8]| {
    let _ = anchor_from_trusted_cert(&CertificateDer::from(data));
});
