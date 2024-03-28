use bencher::{benchmark_group, benchmark_main, Bencher};
use once_cell::sync::Lazy;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertifiedKey, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams,
    SerialNumber, PKCS_ECDSA_P256_SHA256,
};

use std::fs::File;
use std::hint::black_box;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::sync::Mutex;

use webpki::{BorrowedCertRevocationList, CertRevocationList, OwnedCertRevocationList};

/// Lazy initialized CRL issuer to be used when generating CRL data. Includes
/// `KeyUsagePurpose::CrlSign` key usage bit.
static CRL_ISSUER: Lazy<Mutex<CertifiedKey>> = Lazy::new(|| {
    let mut issuer_params =
        CertificateParams::new(vec!["crl.issuer.example.com".to_string()]).unwrap();
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = issuer_params.self_signed(&key_pair).unwrap();
    Mutex::new(CertifiedKey { cert, key_pair })
});

/// Number of revoked certificates to include in the small benchmark CRL. Produces a CRL roughly
/// ~72kb in size when serialized to disk.
const SMALL_CRL_CERT_COUNT: usize = 2_000;
/// Number of revoked certificates to include in the medium benchmark CRL. Produces a CRL roughly
/// ~22mb in size when serialized to disk.
const MEDIUM_CRL_CERT_COUNT: usize = 600_000;
/// Number of revoked certificates to include in the large benchmark CRL. Produces a CRL roughly
/// ~50mb in size when serialized to disk.
const LARGE_CRL_CERT_COUNT: usize = 1_500_000;

/// A fake serial number to use in the search tests. In order to provoke a full scan of the CRL
/// contents this serial should **not** appear in the revoked certificates.
const FAKE_SERIAL: &[u8] = &[0xC0, 0xFF, 0xEE];

/// Try to load a DER bytes from `crl_path`. If that file path does not exist, generate a CRL
/// with `revoked_count` revoked certificates, write the DER encoding to `crl_path` and return the
/// newly created DER bytes.
fn load_or_generate(crl_path: impl AsRef<Path> + Copy, revoked_count: usize) -> Vec<u8> {
    match File::open(crl_path) {
        Ok(mut crl_file) => {
            let mut crl_der = Vec::new();
            crl_file.read_to_end(&mut crl_der).unwrap();
            crl_der
        }
        Err(e) => match e.kind() {
            ErrorKind::NotFound => match File::create(crl_path) {
                Err(e) => panic!("unexpected err creating CRL file: {:?}", e),
                Ok(mut crl_file) => {
                    let new_crl = generate_crl(revoked_count);
                    crl_file.write_all(&new_crl).unwrap();
                    new_crl
                }
            },
            e => {
                panic!("unexpected err opening CRL file: {:?}", e);
            }
        },
    }
}

/// Create a new benchmark CRL with `revoked_count` revoked certificates.
fn generate_crl(revoked_count: usize) -> Vec<u8> {
    let mut revoked_certs = Vec::with_capacity(revoked_count);
    (0..revoked_count).for_each(|i| {
        revoked_certs.push(RevokedCertParams {
            serial_number: SerialNumber::from((i + 1) as u64),
            revocation_time: date_time_ymd(2024, 6, 17),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        });
    });

    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2023, 6, 17),
        next_update: date_time_ymd(2024, 6, 17),
        crl_number: SerialNumber::from(1234),
        key_identifier_method: KeyIdMethod::Sha256,
        issuing_distribution_point: None,
        revoked_certs,
    };
    let issuer = CRL_ISSUER.lock().unwrap();
    crl.signed_by(&issuer.cert, &issuer.key_pair)
        .unwrap()
        .der()
        .to_vec()
}

/// Benchmark parsing a small CRL file into a borrowed representation.
fn bench_parse_borrowed_crl_small(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/small.crl.der", SMALL_CRL_CERT_COUNT);

    c.iter(|| BorrowedCertRevocationList::from_der(&crl_bytes).unwrap());
}

/// Benchmark parsing a small CRL file into an owned representation.
fn bench_parse_owned_crl_small(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/small.crl.der", SMALL_CRL_CERT_COUNT);

    c.iter(|| OwnedCertRevocationList::from_der(&crl_bytes).unwrap());
}

/// Benchmark parsing a medium CRL file into a borrowed representation..
fn bench_parse_borrowed_crl_medium(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/medium.crl.der", MEDIUM_CRL_CERT_COUNT);

    c.iter(|| BorrowedCertRevocationList::from_der(&crl_bytes).unwrap());
}

/// Benchmark parsing a medium CRL file into an owned representation..
fn bench_parse_owned_crl_medium(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/medium.crl.der", MEDIUM_CRL_CERT_COUNT);

    c.iter(|| OwnedCertRevocationList::from_der(&crl_bytes).unwrap());
}

/// Benchmark parsing a large CRL file into a borrowed representation..
fn bench_parse_borrowed_crl_large(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/large.crl.der", LARGE_CRL_CERT_COUNT);

    c.iter(|| BorrowedCertRevocationList::from_der(&crl_bytes).unwrap());
}

/// Benchmark parsing a large CRL file into an owned representation..
fn bench_parse_owned_crl_large(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/large.crl.der", LARGE_CRL_CERT_COUNT);

    c.iter(|| BorrowedCertRevocationList::from_der(&crl_bytes).unwrap());
}

/// Benchmark searching a small CRL file in borrowed representation for a serial that does not
/// appear. Doesn't include the time it takes to parse the CRL in the benchmark task.
fn bench_search_borrowed_crl_small(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/small.crl.der", SMALL_CRL_CERT_COUNT);
    let crl: CertRevocationList = BorrowedCertRevocationList::from_der(&crl_bytes)
        .unwrap()
        .into();

    c.iter(|| black_box(assert!(matches!(crl.find_serial(FAKE_SERIAL), Ok(None)))));
}

/// Benchmark searching a small CRL file in owned representation for a serial that does not
/// appear. Doesn't include the time it takes to parse the CRL in the benchmark task.
fn bench_search_owned_crl_small(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/small.crl.der", SMALL_CRL_CERT_COUNT);
    let crl: CertRevocationList = OwnedCertRevocationList::from_der(&crl_bytes)
        .unwrap()
        .into();

    c.iter(|| black_box(assert!(matches!(crl.find_serial(FAKE_SERIAL), Ok(None)))));
}

/// Benchmark searching a medium CRL file in borrowed representation for a serial that does not
/// appear. Doesn't include the time it takes to parse the CRL in the benchmark task.
fn bench_search_borrowed_crl_medium(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/medium.crl.der", MEDIUM_CRL_CERT_COUNT);
    let crl: CertRevocationList = BorrowedCertRevocationList::from_der(&crl_bytes)
        .unwrap()
        .into();

    c.iter(|| black_box(assert!(matches!(crl.find_serial(FAKE_SERIAL), Ok(None)))));
}

/// Benchmark searching a medium CRL file in owned representation for a serial that does not
/// appear. Doesn't include the time it takes to parse the CRL in the benchmark task.
fn bench_search_owned_crl_medium(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/medium.crl.der", MEDIUM_CRL_CERT_COUNT);
    let crl: CertRevocationList = OwnedCertRevocationList::from_der(&crl_bytes)
        .unwrap()
        .into();

    c.iter(|| black_box(assert!(matches!(crl.find_serial(FAKE_SERIAL), Ok(None)))));
}

/// Benchmark searching a large CRL file in borrowed representation for a serial that does not
/// appear. Doesn't include the time it takes to parse the CRL in the benchmark task.
fn bench_search_borrowed_crl_large(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/large.crl.der", LARGE_CRL_CERT_COUNT);
    let crl: CertRevocationList = BorrowedCertRevocationList::from_der(&crl_bytes)
        .unwrap()
        .into();

    c.iter(|| black_box(assert!(matches!(crl.find_serial(FAKE_SERIAL), Ok(None)))));
}

/// Benchmark searching a large CRL file in owned representation for a serial that does not
/// appear. Doesn't include the time it takes to parse the CRL in the benchmark task.
fn bench_search_owned_crl_large(c: &mut Bencher) {
    let crl_bytes = load_or_generate("./benches/large.crl.der", LARGE_CRL_CERT_COUNT);
    let crl: CertRevocationList = OwnedCertRevocationList::from_der(&crl_bytes)
        .unwrap()
        .into();

    c.iter(|| black_box(assert!(matches!(crl.find_serial(FAKE_SERIAL), Ok(None)))));
}

benchmark_group!(
    crl_benches,
    bench_parse_borrowed_crl_small,
    bench_parse_owned_crl_small,
    bench_parse_borrowed_crl_medium,
    bench_parse_owned_crl_medium,
    bench_parse_borrowed_crl_large,
    bench_parse_owned_crl_large,
    bench_search_borrowed_crl_small,
    bench_search_owned_crl_small,
    bench_search_borrowed_crl_medium,
    bench_search_owned_crl_medium,
    bench_search_borrowed_crl_large,
    bench_search_owned_crl_large,
);

benchmark_main!(crl_benches);
