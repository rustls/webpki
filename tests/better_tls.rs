#![cfg(feature = "ring")]

use std::collections::HashMap;
use std::fs::File;

use base64::{engine::general_purpose, Engine as _};
use bzip2::read::BzDecoder;
use serde::Deserialize;

use webpki::{KeyUsage, SubjectNameRef, TrustAnchor};

#[test]
fn better_tls() {
    let better_tls = testdata();
    let root_der = &better_tls.root_der();
    let roots = &[TrustAnchor::try_from_cert_der(root_der).expect("invalid trust anchor")];

    let suite = "pathbuilding";
    run_testsuite(
        suite,
        better_tls
            .suites
            .get(suite)
            .unwrap_or_else(|| panic!("missing {suite} suite")),
        roots,
    );
}

#[test]
fn name_constraints() {
    let better_tls = testdata();
    let root_der = &better_tls.root_der();
    let roots = &[TrustAnchor::try_from_cert_der(root_der).expect("invalid trust anchor")];

    let suite = "nameconstraints";
    run_testsuite(
        suite,
        better_tls
            .suites
            .get(suite)
            .unwrap_or_else(|| panic!("missing {suite} suite")),
        roots,
    );
}

fn run_testsuite(suite_name: &str, suite: &BetterTlsSuite, roots: &[TrustAnchor]) {
    for testcase in &suite.test_cases {
        println!("Testing {suite_name} test case {}", testcase.id);

        let certs_der = testcase.certs_der();
        let ee_der = &certs_der[0];
        let intermediates = &certs_der[1..]
            .iter()
            .map(|cert| cert.as_slice())
            .collect::<Vec<_>>();

        let ee_cert =
            webpki::EndEntityCert::try_from(ee_der.as_slice()).expect("invalid end entity cert");

        // Set the time to the time of test case generation. This ensures that the test case
        // certificates won't expire.
        let now = webpki::Time::from_seconds_since_unix_epoch(1_691_788_832);

        let result = ee_cert
            .verify_for_usage(
                &[webpki::ECDSA_P256_SHA256], // All of the BetterTLS testcases use P256 keys.
                roots,
                intermediates,
                now,
                KeyUsage::server_auth(),
                None,
            )
            .and_then(|_| {
                ee_cert.verify_is_valid_for_subject_name(
                    SubjectNameRef::try_from_ascii_str(&testcase.hostname)
                        .expect("invalid testcase hostname"),
                )
            });

        match testcase.expected {
            ExpectedResult::Accept => assert!(result.is_ok(), "expected success, got {:?}", result),
            ExpectedResult::Reject => {
                assert!(result.is_err(), "expected failure, got {:?}", result)
            }
        }
    }
}

fn testdata() -> BetterTls {
    let mut data_file = File::open("third-party/bettertls/bettertls.tests.json.bz2")
        .expect("failed to open data file");
    let decompressor = BzDecoder::new(&mut data_file);

    let better_tls: BetterTls = serde_json::from_reader(decompressor).expect("invalid test JSON");
    println!("Testing BetterTLS revision {:?}", better_tls.revision);

    better_tls
}

#[derive(Deserialize, Debug)]
struct BetterTls {
    #[serde(rename(deserialize = "betterTlsRevision"))]
    revision: String,
    #[serde(rename(deserialize = "trustRoot"))]
    root: String,
    suites: HashMap<String, BetterTlsSuite>,
}

impl BetterTls {
    fn root_der(&self) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(&self.root)
            .expect("invalid trust anchor base64")
    }
}

#[derive(Deserialize, Debug)]
struct BetterTlsSuite {
    #[serde(rename(deserialize = "testCases"))]
    test_cases: Vec<BetterTlsTest>,
}

#[derive(Deserialize, Debug)]
struct BetterTlsTest {
    id: u32,
    certificates: Vec<String>,
    hostname: String,
    expected: ExpectedResult,
}

impl BetterTlsTest {
    fn certs_der(&self) -> Vec<Vec<u8>> {
        self.certificates
            .iter()
            .map(|cert| {
                general_purpose::STANDARD
                    .decode(cert)
                    .expect("invalid cert base64")
            })
            .collect()
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
enum ExpectedResult {
    Accept,
    Reject,
}
