#![cfg(feature = "alloc")]
use std::prelude::v1::*;

use crate::types::CertificateDer;

#[cfg_attr(not(feature = "ring"), allow(dead_code))]
pub(crate) fn make_end_entity(issuer: &rcgen::Certificate) -> CertificateDer<'static> {
    CertificateDer::from(
        rcgen::Certificate::from_params(end_entity_params(vec!["example.com".into()]))
            .unwrap()
            .serialize_der_with_signer(issuer)
            .unwrap(),
    )
}

pub(crate) fn make_issuer(org_name: impl Into<String>) -> rcgen::Certificate {
    rcgen::Certificate::from_params(issuer_params(org_name)).unwrap()
}

/// Populate a [CertificateParams] that describes an unconstrained issuer certificate capable
/// of signing other certificates and CRLs, with the given `org_name` as an organization distinguished
/// subject name.
pub(crate) fn issuer_params(org_name: impl Into<String>) -> rcgen::CertificateParams {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new());
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, org_name);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params.alg = RCGEN_SIGNATURE_ALG;
    ca_params
}

pub(crate) fn end_entity_params(subject_alt_names: Vec<String>) -> rcgen::CertificateParams {
    let mut ee_params = rcgen::CertificateParams::new(subject_alt_names);
    ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
    ee_params.alg = RCGEN_SIGNATURE_ALG;
    ee_params
}

/// Signature algorithm used by certificates and parameters generated using the test utils helpers.
static RCGEN_SIGNATURE_ALG: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
