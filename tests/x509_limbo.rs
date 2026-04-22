#![cfg(feature = "alloc")]

use std::collections::HashMap;
use std::fs::File;

use chrono::{DateTime, Utc};
use limbo_harness_support::LIMBO_JSON;
use limbo_harness_support::models::{ExpectedResult, Feature, Limbo, Testcase, ValidationKind};
use serde::{Deserialize, Serialize};

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use webpki::{
    EndEntityCert, ExpirationPolicy, ExtendedKeyUsage, OwnedCertRevocationList,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};

#[ignore] // Runs slower than other unit tests - opt-in with `cargo test -- --include-ignored`
#[test]
fn x509_limbo() {
    let limbo = serde_json::from_slice::<Limbo>(LIMBO_JSON).expect("invalid test JSON");

    let exceptions = serde_json::from_reader(
        File::open("third-party/x509-limbo/exceptions.json")
            .expect("failed to open exceptions file"),
    )
    .expect("invalid exceptions JSON");

    let mut summary = Summary::default();
    for testcase in &limbo.testcases {
        let id = testcase.id.to_string();

        match evaluate_testcase(testcase, &exceptions) {
            Outcome::Pass => summary.passed.push(id),
            Outcome::Skip(reason) => summary.skipped.push((id, reason)),
            Outcome::KnownDivergence => summary.known_divergences.push(id),
            Outcome::UnexpectedFailure(err) => summary.unexpected_failures.push((id, err)),
            Outcome::UnexpectedSuccess => summary.unexpected_successes.push(id),
        }
    }

    summary.print();

    if summary.has_failures() {
        panic!(
            "x509-limbo: {} unexpected failures, {} unexpected successes",
            summary.unexpected_failures.len(),
            summary.unexpected_successes.len()
        );
    }
}

fn evaluate_testcase(tc: &Testcase, exceptions: &HashMap<String, Exception>) -> Outcome {
    // Check for skipped features first
    if tc.features.contains(&Feature::MaxChainDepth) {
        return Outcome::Skip("max-chain-depth testcases are not supported by this API".into());
    }

    if !matches!(tc.validation_kind, ValidationKind::Server) {
        return Outcome::Skip("non-SERVER testcases not supported yet".into());
    }

    if !tc.signature_algorithms.is_empty() {
        return Outcome::Skip("signature_algorithms not supported yet".into());
    }

    if !tc.key_usage.is_empty() {
        return Outcome::Skip("key_usage not supported yet".into());
    }

    let validation_result = run_validation(tc);
    let actual_success = validation_result.is_ok();
    let expected_success = matches!(tc.expected_result, ExpectedResult::Success);

    if let Some(exception) = exceptions.get(tc.id.as_str()) {
        if actual_success == (exception.actual == "SUCCESS") {
            return Outcome::KnownDivergence;
        }
        // If the exception no longer applies (behavior changed), fall through to normal comparison
    }

    // Compare actual vs expected
    match (expected_success, validation_result) {
        (true, Ok(())) | (false, Err(_)) => Outcome::Pass,
        (true, Err(err)) => Outcome::UnexpectedFailure(err),
        (false, Ok(())) => Outcome::UnexpectedSuccess,
    }
}

/// Run validation and return Ok(()) on success, or an error message on failure
fn run_validation(tc: &Testcase) -> Result<(), String> {
    let leaf_der = cert_der_from_pem(&tc.peer_certificate);
    let leaf =
        EndEntityCert::try_from(&leaf_der).map_err(|e| format!("leaf cert parse failed: {e}"))?;

    let intermediates = tc
        .untrusted_intermediates
        .iter()
        .map(|ic| cert_der_from_pem(ic))
        .collect::<Vec<_>>();

    let trust_anchor_ders = tc
        .trusted_certs
        .iter()
        .map(|ta| cert_der_from_pem(ta))
        .collect::<Vec<_>>();

    let trust_anchors = trust_anchor_ders
        .iter()
        .filter_map(|der| anchor_from_trusted_cert(der).ok())
        .collect::<Vec<_>>();

    if trust_anchors.is_empty() && !trust_anchor_ders.is_empty() {
        return Err("trust anchor extraction failed".into());
    }

    let validation_time = UnixTime::since_unix_epoch(
        (tc.validation_time.unwrap_or_else(Utc::now) - DateTime::UNIX_EPOCH)
            .to_std()
            .expect("invalid validation time!"),
    );

    let sig_algs = rustls_aws_lc_rs::ALL_VERIFICATION_ALGS;

    let crls = tc
        .crls
        .iter()
        .map(|pem| {
            OwnedCertRevocationList::from_der(
                CertificateRevocationListDer::from_pem_slice(pem.as_bytes())
                    .expect("CRL PEM parse failed")
                    .as_ref(),
            )
            .expect("CRL DER parse failed")
            .into()
        })
        .collect::<Vec<_>>();
    let crls = crls.iter().collect::<Vec<_>>();

    let revocation_options = if !crls.is_empty() {
        let opts = RevocationOptionsBuilder::new(crls.as_slice()).unwrap();
        opts.with_depth(RevocationCheckDepth::Chain);
        opts.with_status_policy(UnknownStatusPolicy::Deny);
        opts.with_expiration_policy(ExpirationPolicy::Enforce);
        Some(opts.build())
    } else {
        None
    };

    leaf.verify_for_usage(
        sig_algs,
        &trust_anchors,
        &intermediates[..],
        validation_time,
        &ExtendedKeyUsage::server_auth(),
        revocation_options,
        None,
    )
    .map_err(|e| e.to_string())?;

    // Verify subject name if expected
    if let Some(peer_name) = tc.expected_peer_name.as_ref() {
        let subject_name = ServerName::try_from(peer_name.value.as_str())
            .map_err(|_| format!("invalid expected peer name: {:?}", peer_name))?;

        leaf.verify_is_valid_for_subject_name(&subject_name)
            .map_err(|_| "subject name validation failed")?;
    }

    Ok(())
}

fn cert_der_from_pem<B: AsRef<[u8]>>(bytes: B) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(bytes.as_ref())
        .expect("cert PEM parse failed")
        .into_owned()
}

/// An exception entry for a testcase where webpki intentionally/knowingly diverges from the expected result.
#[derive(Debug, Deserialize, Serialize)]
struct Exception {
    /// The expected result according to x509-limbo
    expected: String,
    /// What webpki actually produces
    actual: String,
    /// Why webpki diverges from the expected result
    reason: String,
}

/// Outcome of evaluating a single testcase
#[derive(Debug)]
enum Outcome {
    /// Test passed - actual result matches expected
    Pass,
    /// Test was skipped (unsupported feature)
    Skip(String),
    /// Known divergence - in exceptions file
    KnownDivergence,
    /// Unexpected failure - expected SUCCESS but got FAILURE
    UnexpectedFailure(String),
    /// Unexpected success - expected FAILURE but got SUCCESS
    UnexpectedSuccess,
}

/// Summary of test run
#[derive(Debug, Default)]
struct Summary {
    passed: Vec<String>,
    skipped: Vec<(String, String)>,
    known_divergences: Vec<String>,
    unexpected_failures: Vec<(String, String)>,
    unexpected_successes: Vec<String>,
}

impl Summary {
    fn print(&self) {
        println!("\nx509-limbo: {} tests", self.total());
        println!("  {} passed (match expected)", self.passed.len());
        println!("  {} skipped (unsupported features)", self.skipped.len());
        println!(
            "  {} known divergences (see exceptions.json)",
            self.known_divergences.len()
        );

        if !self.unexpected_failures.is_empty() {
            println!(
                "\nUNEXPECTED FAILURES ({}):",
                self.unexpected_failures.len()
            );
            for (id, err) in &self.unexpected_failures {
                println!("  - {id}: {err}");
            }
        }

        if !self.unexpected_successes.is_empty() {
            println!(
                "\nUNEXPECTED SUCCESSES ({}):",
                self.unexpected_successes.len()
            );
            println!("  (expected FAILURE but got SUCCESS - may indicate a bug in webpki)");
            for id in &self.unexpected_successes {
                println!("  - {id}");
            }
        }
    }

    fn total(&self) -> usize {
        self.passed.len()
            + self.skipped.len()
            + self.known_divergences.len()
            + self.unexpected_failures.len()
            + self.unexpected_successes.len()
    }

    fn has_failures(&self) -> bool {
        !self.unexpected_failures.is_empty() || !self.unexpected_successes.is_empty()
    }
}
