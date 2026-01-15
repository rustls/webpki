#![allow(dead_code, unreachable_pub)]

use std::error::Error as StdError;

use rcgen::{
    CertificateParams, CertifiedIssuer, CertifiedKey, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SignatureAlgorithm, SigningKey,
};

pub fn make_end_entity(
    ekus: Vec<ExtendedKeyUsagePurpose>,
    org_name: impl Into<DnValue>,
    issuer: &Issuer<'_, impl SigningKey>,
) -> Result<CertifiedKey<KeyPair>, Box<dyn StdError>> {
    let signing_key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG)?;
    Ok(CertifiedKey {
        cert: end_entity_params(vec!["example.com".into()], org_name, ekus)?
            .signed_by(&signing_key, issuer)?,
        signing_key,
    })
}

pub fn make_issuer(
    org_name: impl Into<String>,
) -> Result<CertifiedIssuer<'static, KeyPair>, Box<dyn StdError>> {
    let params = issuer_params(org_name)?;
    let signing_key = KeyPair::generate_for(RCGEN_SIGNATURE_ALG)?;
    Ok(CertifiedIssuer::self_signed(params, signing_key)?)
}

/// Populate a [CertificateParams] that describes an unconstrained issuer certificate.
///
/// The given `org_name` is used as the organization distinguished subject name.
pub fn issuer_params(org_name: impl Into<DnValue>) -> Result<CertificateParams, Box<dyn StdError>> {
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, org_name);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    Ok(ca_params)
}

pub fn end_entity_params(
    subject_alt_names: Vec<String>,
    org_name: impl Into<DnValue>,
    ekus: Vec<ExtendedKeyUsagePurpose>,
) -> Result<CertificateParams, Box<dyn StdError>> {
    let mut ee_params = CertificateParams::new(subject_alt_names)?;
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.extended_key_usages = ekus;
    ee_params
        .distinguished_name
        .push(DnType::OrganizationName, org_name);
    Ok(ee_params)
}

/// Signature algorithm used by certificates and parameters generated using the test utils helpers.
static RCGEN_SIGNATURE_ALG: &SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
