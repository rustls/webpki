#![cfg(feature = "alloc")]

use crate::types::CertificateDer;

/// Signature algorithm used by certificates generated using `make_issuer` and
/// `make_end_entity`. This is exported as a constant so that tests can use the
/// same algorithm when generating certificates using `rcgen`.
pub(crate) static RCGEN_SIGNATURE_ALG: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

pub(crate) fn make_issuer(
    org_name: impl Into<String>,
    name_constraints: Option<rcgen::NameConstraints>,
) -> rcgen::Certificate {
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
    ca_params.name_constraints = name_constraints;
    rcgen::Certificate::from_params(ca_params).unwrap()
}

pub(crate) fn make_end_entity(issuer: &rcgen::Certificate) -> CertificateDer<'static> {
    let mut ee_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
    ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
    ee_params.alg = RCGEN_SIGNATURE_ALG;
    CertificateDer::from(
        rcgen::Certificate::from_params(ee_params)
            .unwrap()
            .serialize_der_with_signer(issuer)
            .unwrap(),
    )
}
