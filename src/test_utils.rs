#![cfg(feature = "alloc")]
use std::prelude::v1::*;

use rcgen::{CertifiedIssuer, CertifiedKey, Issuer, KeyPair, SigningKey};

#[cfg_attr(not(feature = "ring"), allow(dead_code))]
pub(crate) fn make_end_entity(issuer: &Issuer<'_, impl SigningKey>) -> CertifiedKey<KeyPair> {
    let signing_key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap();
    CertifiedKey {
        cert: end_entity_params(vec!["example.com".into()])
            .signed_by(&signing_key, issuer)
            .unwrap(),
        signing_key,
    }
}

pub(crate) fn make_issuer(org_name: impl Into<String>) -> CertifiedIssuer<'static, KeyPair> {
    let params = issuer_params(org_name);
    let key_pair = KeyPair::generate_for(RCGEN_SIGNATURE_ALG).unwrap();
    CertifiedIssuer::self_signed(params, key_pair).unwrap()
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

/// Signature algorithm used by certificates and parameters generated using the test utils helpers.
pub(crate) static RCGEN_SIGNATURE_ALG: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
