#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate webpki;

use pki_types::CertificateDer;
use webpki::EndEntityCert;

fuzz_target!(|data: &[u8]| {
    let _ = EndEntityCert::try_from(&CertificateDer::from(data));
});
