#![cfg(feature = "alloc")]
use std::prelude::v1::*;

#[cfg_attr(not(feature = "ring"), allow(dead_code))]
pub(crate) fn make_end_entity(
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
) -> rcgen::CertifiedKey {
    let key_pair = make_keypair();
    rcgen::CertifiedKey {
        cert: end_entity_params(vec!["example.com".into()])
            .signed_by(&key_pair, issuer, issuer_key)
            .unwrap(),
        key_pair,
    }
}

pub(crate) fn make_issuer(org_name: impl Into<String>) -> rcgen::CertifiedKey {
    let key_pair = make_keypair();
    rcgen::CertifiedKey {
        cert: issuer_params(org_name).self_signed(&key_pair).unwrap(),
        key_pair,
    }
}

/// Populate a [CertificateParams] that describes an unconstrained issuer certificate capable
/// of signing other certificates and CRLs, with the given `org_name` as an organization distinguished
/// subject name.
pub(crate) fn issuer_params(org_name: impl Into<String>) -> rcgen::CertificateParams {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, org_name);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params
}

pub(crate) fn end_entity_params(subject_alt_names: Vec<String>) -> rcgen::CertificateParams {
    let mut ee_params = rcgen::CertificateParams::new(subject_alt_names).unwrap();
    ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
    ee_params
}

pub(crate) fn make_keypair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap()
}

/// Signature algorithm used by certificates and parameters generated using the test utils helpers.
static RCGEN_SIGNATURE_ALG: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
