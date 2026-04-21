#![no_main]

#[macro_use]
extern crate libfuzzer_sys;
extern crate webpki;

use webpki::BorrowedCertRevocationList;

fuzz_target!(|data: &[u8]| {
    let _ = BorrowedCertRevocationList::from_der(data);
});
