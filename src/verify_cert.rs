// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use core::default::Default;

use pki_types::{CertificateDer, TrustAnchor};

use crate::cert::{Cert, EndEntityOrCa};
use crate::crl::IssuingDistributionPoint;
use crate::der::{self, FromDer};
use crate::{
    signed_data, subject_name, time, CertRevocationList, Error, SignatureVerificationAlgorithm,
};

/// Builds a RevocationOptions instance to control how revocation checking is performed.
#[derive(Debug, Copy, Clone)]
pub struct RevocationOptionsBuilder<'a> {
    crls: &'a [&'a dyn CertRevocationList],

    depth: RevocationCheckDepth,

    status_requirement: UnknownStatusPolicy,
}

impl<'a> RevocationOptionsBuilder<'a> {
    /// Create a builder that will perform revocation checking using the provided certificate
    /// revocation lists (CRLs). At least one CRL must be provided.
    ///
    /// Use [RevocationOptionsBuilder::build] to create a [RevocationOptions] instance.
    ///
    /// By default revocation checking will be performed on both the end-entity (leaf) certificate
    /// and intermediate certificates. This can be customized using the
    /// [RevocationOptionsBuilder::with_depth] method.
    ///
    /// By default revocation checking will fail if the revocation status of a certificate cannot
    /// be determined. This can be customized using the
    /// [RevocationOptionsBuilder::allow_unknown_status] method.
    pub fn new(crls: &'a [&'a dyn CertRevocationList]) -> Result<Self, CrlsRequired> {
        if crls.is_empty() {
            return Err(CrlsRequired(()));
        }

        Ok(Self {
            crls,
            depth: RevocationCheckDepth::Chain,
            status_requirement: UnknownStatusPolicy::Deny,
        })
    }

    /// Customize the depth at which revocation checking will be performed, controlling
    /// whether only the end-entity (leaf) certificate in the chain to a trust anchor will
    /// have its revocation status checked, or whether the intermediate certificates will as well.
    pub fn with_depth(mut self, depth: RevocationCheckDepth) -> Self {
        self.depth = depth;
        self
    }

    /// Treat unknown revocation status permissively, acting as if the certificate were not
    /// revoked.
    pub fn allow_unknown_status(mut self) -> Self {
        self.status_requirement = UnknownStatusPolicy::Allow;
        self
    }

    /// Treat unknown revocation status strictly, considering it an error condition.
    pub fn forbid_unknown_status(mut self) -> Self {
        self.status_requirement = UnknownStatusPolicy::Deny;
        self
    }

    /// Construct a [RevocationOptions] instance based on the builder's configuration.
    pub fn build(self) -> RevocationOptions<'a> {
        RevocationOptions {
            crls: self.crls,
            depth: self.depth,
            status_requirement: self.status_requirement,
        }
    }
}

/// Describes how revocation checking is performed, if at all. Can be constructed with a
/// [RevocationOptionsBuilder] instance.
#[derive(Debug, Copy, Clone)]
pub struct RevocationOptions<'a> {
    crls: &'a [&'a dyn CertRevocationList],
    depth: RevocationCheckDepth,
    status_requirement: UnknownStatusPolicy,
}

/// Describes how much of a certificate chain is checked for revocation status.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RevocationCheckDepth {
    /// Only check the end entity (leaf) certificate's revocation status.
    EndEntity,
    /// Check the revocation status of the end entity (leaf) and all intermediates.
    Chain,
}

/// Describes how to handle the case where a certificate's revocation status is unknown.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UnknownStatusPolicy {
    /// Treat unknown revocation status permissively, acting as if the certificate were
    /// not revoked.
    Allow,
    /// Treat unknown revocation status as an error condition, yielding
    /// [Error::UnknownRevocationStatus].
    Deny,
}

#[derive(Debug, Copy, Clone)]
/// An opaque error indicating the caller must provide at least one CRL when building a
/// [RevocationOptions] instance.
pub struct CrlsRequired(());

pub(crate) struct ChainOptions<'a> {
    pub(crate) eku: KeyUsage,
    pub(crate) supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    pub(crate) trust_anchors: &'a [TrustAnchor<'a>],
    pub(crate) intermediate_certs: &'a [CertificateDer<'a>],
    pub(crate) revocation: Option<RevocationOptions<'a>>,
}

pub(crate) fn build_chain(opts: &ChainOptions, cert: &Cert, time: time::Time) -> Result<(), Error> {
    build_chain_inner(opts, cert, time, 0, &mut Budget::default())
}

fn build_chain_inner(
    opts: &ChainOptions,
    cert: &Cert,
    time: time::Time,
    sub_ca_count: usize,
    budget: &mut Budget,
) -> Result<(), Error> {
    let used_as_ca = used_as_ca(&cert.ee_or_ca);

    check_issuer_independent_properties(cert, time, used_as_ca, sub_ca_count, opts.eku.inner)?;

    // TODO: HPKP checks.

    match used_as_ca {
        UsedAsCa::Yes => {
            const MAX_SUB_CA_COUNT: usize = 6;

            if sub_ca_count >= MAX_SUB_CA_COUNT {
                return Err(Error::MaximumPathDepthExceeded);
            }
        }
        UsedAsCa::No => {
            assert_eq!(0, sub_ca_count);
        }
    }

    // for the purpose of name constraints checking, only end-entity server certificates
    // could plausibly have a DNS name as a subject commonName that could contribute to
    // path validity
    let subject_common_name_contents = if opts
        .eku
        .inner
        .key_purpose_id_equals(EKU_SERVER_AUTH.oid_value)
        && used_as_ca == UsedAsCa::No
    {
        subject_name::SubjectCommonNameContents::DnsName
    } else {
        subject_name::SubjectCommonNameContents::Ignore
    };

    let result = loop_while_non_fatal_error(
        Error::UnknownIssuer,
        opts.trust_anchors,
        |trust_anchor: &TrustAnchor| {
            let trust_anchor_subject = untrusted::Input::from(trust_anchor.subject.as_ref());
            if cert.issuer != trust_anchor_subject {
                return Err(Error::UnknownIssuer);
            }

            let name_constraints = trust_anchor
                .name_constraints
                .as_ref()
                .map(|der| untrusted::Input::from(der.as_ref()));

            untrusted::read_all_optional(name_constraints, Error::BadDer, |value| {
                subject_name::check_name_constraints(value, cert, subject_common_name_contents)
            })?;

            // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;

            check_signatures(
                opts.supported_sig_algs,
                cert,
                trust_anchor,
                opts.revocation,
                budget,
            )?;

            Ok(())
        },
    );

    let err = match result {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };

    loop_while_non_fatal_error(err, opts.intermediate_certs, |cert_der| {
        let potential_issuer =
            Cert::from_der(untrusted::Input::from(cert_der), EndEntityOrCa::Ca(cert))?;

        if potential_issuer.subject != cert.issuer {
            return Err(Error::UnknownIssuer);
        }

        // Prevent loops; see RFC 4158 section 5.2.
        let mut prev = cert;
        loop {
            if potential_issuer.spki == prev.spki && potential_issuer.subject == prev.subject {
                return Err(Error::UnknownIssuer);
            }
            match &prev.ee_or_ca {
                EndEntityOrCa::EndEntity => {
                    break;
                }
                EndEntityOrCa::Ca(child_cert) => {
                    prev = child_cert;
                }
            }
        }

        untrusted::read_all_optional(potential_issuer.name_constraints, Error::BadDer, |value| {
            subject_name::check_name_constraints(value, cert, subject_common_name_contents)
        })?;

        let next_sub_ca_count = match used_as_ca {
            UsedAsCa::No => sub_ca_count,
            UsedAsCa::Yes => sub_ca_count + 1,
        };

        budget.consume_build_chain_call()?;
        build_chain_inner(opts, &potential_issuer, time, next_sub_ca_count, budget)
    })
}

fn check_signatures(
    supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
    cert_chain: &Cert,
    trust_anchor: &TrustAnchor,
    revocation: Option<RevocationOptions>,
    budget: &mut Budget,
) -> Result<(), Error> {
    let mut spki_value = untrusted::Input::from(trust_anchor.subject_public_key_info.as_ref());
    let mut issuer_subject = untrusted::Input::from(trust_anchor.subject.as_ref());
    let mut issuer_key_usage = None; // TODO(XXX): Consider whether to track TrustAnchor KU.
    let mut cert = cert_chain;
    loop {
        signed_data::verify_signed_data(supported_sig_algs, spki_value, &cert.signed_data, budget)?;

        if let Some(revocation_opts) = &revocation {
            check_crls(
                supported_sig_algs,
                cert,
                issuer_subject,
                spki_value,
                issuer_key_usage,
                revocation_opts,
                budget,
            )?;
        }

        match &cert.ee_or_ca {
            EndEntityOrCa::Ca(child_cert) => {
                spki_value = cert.spki;
                issuer_subject = cert.subject;
                issuer_key_usage = cert.key_usage;
                cert = child_cert;
            }
            EndEntityOrCa::EndEntity => {
                break;
            }
        }
    }

    Ok(())
}

pub struct Budget {
    signatures: usize,
    build_chain_calls: usize,
}

impl Budget {
    #[inline]
    pub(crate) fn consume_signature(&mut self) -> Result<(), Error> {
        self.signatures = self
            .signatures
            .checked_sub(1)
            .ok_or(Error::MaximumSignatureChecksExceeded)?;
        Ok(())
    }

    #[inline]
    fn consume_build_chain_call(&mut self) -> Result<(), Error> {
        self.build_chain_calls = self
            .build_chain_calls
            .checked_sub(1)
            .ok_or(Error::MaximumPathBuildCallsExceeded)?;
        Ok(())
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            // This limit is taken from the remediation for golang CVE-2018-16875.  However,
            // note that golang subsequently implemented AKID matching due to this limit
            // being hit in real applications (see <https://github.com/spiffe/spire/issues/1004>).
            // So this may actually be too aggressive.
            signatures: 100,

            // This limit is taken from NSS libmozpkix, see:
            // <https://github.com/nss-dev/nss/blob/bb4a1d38dd9e92923525ac6b5ed0288479f3f3fc/lib/mozpkix/lib/pkixbuild.cpp#L381-L393>
            build_chain_calls: 200_000,
        }
    }
}

// Zero-sized marker type representing positive assertion that revocation status was checked
// for a certificate and the result was that the certificate is not revoked.
struct CertNotRevoked(());

impl CertNotRevoked {
    // Construct a CertNotRevoked marker.
    fn assertion() -> Self {
        Self(())
    }
}

fn check_crls(
    supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
    cert: &Cert,
    issuer_subject: untrusted::Input,
    issuer_spki: untrusted::Input,
    issuer_ku: Option<untrusted::Input>,
    revocation: &RevocationOptions,
    budget: &mut Budget,
) -> Result<Option<CertNotRevoked>, Error> {
    assert_eq!(cert.issuer, issuer_subject);

    // If the policy only specifies checking EndEntity revocation state and we're looking at an
    // issuer certificate, return early without considering the certificate's revocation state.
    if let (RevocationCheckDepth::EndEntity, EndEntityOrCa::Ca(_)) =
        (revocation.depth, &cert.ee_or_ca)
    {
        return Ok(None);
    }

    let crl = revocation
        .crls
        .iter()
        .find(|candidate_crl| crl_authoritative(**candidate_crl, cert));

    use UnknownStatusPolicy::*;
    let crl = match (crl, revocation.status_requirement) {
        (Some(crl), _) => crl,
        // If the policy allows unknown, return Ok(None) to indicate that the certificate
        // was not confirmed as CertNotRevoked, but that this isn't an error condition.
        (None, Allow) => return Ok(None),
        // Otherwise, this is an error condition based on the provided policy.
        (None, _) => return Err(Error::UnknownRevocationStatus),
    };

    // Verify the CRL signature with the issuer SPKI.
    // TODO(XXX): consider whether we can refactor so this happens once up-front, instead
    //            of per-lookup.
    //            https://github.com/rustls/webpki/issues/81
    crl.verify_signature(supported_sig_algs, issuer_spki.as_slice_less_safe(), budget)
        .map_err(crl_signature_err)?;

    // Verify that if the issuer has a KeyUsage bitstring it asserts cRLSign.
    KeyUsageMode::CrlSign.check(issuer_ku)?;

    // Try to find the cert serial in the verified CRL contents.
    let cert_serial = cert.serial.as_slice_less_safe();
    match crl.find_serial(cert_serial)? {
        None => Ok(Some(CertNotRevoked::assertion())),
        Some(_) => Err(Error::CertRevoked),
    }
}

/// Returns true if the CRL can be considered authoritative for the given certificate.
///
/// A CRL is considered authoritative for a certificate when:
///   * The certificate issuer matches the CRL issuer and,
///     * The certificate has no CRL distribution points, and the CRL has no issuing distribution
///       point extension.
///     * Or, the certificate has no CRL distribution points, but the the CRL has an issuing
///       distribution point extension with a scope that includes the certificate.
///     * Or, the certificate has CRL distribution points, and the CRL has an issuing
///       distribution point extension with a scope that includes the certificate, and at least
///       one distribution point full name is a URI type general name that can also be found in
///       the CRL issuing distribution point full name general name sequence.
///
/// In all other circumstances the CRL is not considered authoritative.
fn crl_authoritative(crl: &dyn CertRevocationList, cert: &Cert<'_>) -> bool {
    // In all cases we require that the authoritative CRL have the same issuer
    // as the certificate. Recall we do not support indirect CRLs.
    if crl.issuer() != cert.issuer() {
        return false;
    }

    let crl_idp = match (
        cert.crl_distribution_points(),
        crl.issuing_distribution_point(),
    ) {
        // If the certificate has no CRL distribution points, and the CRL has no issuing distribution point,
        // then we can consider this CRL authoritative based on the issuer matching.
        (cert_dps, None) => return cert_dps.is_none(),

        // If the CRL has an issuing distribution point, parse it so we can consider its scope
        // and compare against the cert CRL distribution points, if present.
        (_, Some(crl_idp)) => {
            match IssuingDistributionPoint::from_der(untrusted::Input::from(crl_idp)) {
                Ok(crl_idp) => crl_idp,
                Err(_) => return false, // Note: shouldn't happen - we verify IDP at CRL-load.
            }
        }
    };

    crl_idp.authoritative_for(cert)
}

// When verifying CRL signed data we want to disambiguate the context of possible errors by mapping
// them to CRL specific variants that a consumer can use to tell the issue was with the CRL's
// signature, not a certificate.
fn crl_signature_err(err: Error) -> Error {
    match err {
        Error::UnsupportedSignatureAlgorithm => Error::UnsupportedCrlSignatureAlgorithm,
        Error::UnsupportedSignatureAlgorithmForPublicKey => {
            Error::UnsupportedCrlSignatureAlgorithmForPublicKey
        }
        Error::InvalidSignatureForPublicKey => Error::InvalidCrlSignatureForPublicKey,
        _ => err,
    }
}

fn check_issuer_independent_properties(
    cert: &Cert,
    time: time::Time,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
    eku: ExtendedKeyUsage,
) -> Result<(), Error> {
    // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;
    // TODO: Check signature algorithm like mozilla::pkix.
    // TODO: Check SPKI like mozilla::pkix.
    // TODO: check for active distrust like mozilla::pkix.

    // For cert validation, we ignore the KeyUsage extension. For CA
    // certificates, BasicConstraints.cA makes KeyUsage redundant. Firefox
    // and other common browsers do not check KeyUsage for end-entities,
    // though it would be kind of nice to ensure that a KeyUsage without
    // the keyEncipherment bit could not be used for RSA key exchange.

    cert.validity
        .read_all(Error::BadDer, |value| check_validity(value, time))?;
    untrusted::read_all_optional(cert.basic_constraints, Error::BadDer, |value| {
        check_basic_constraints(value, used_as_ca, sub_ca_count)
    })?;
    untrusted::read_all_optional(cert.eku, Error::BadDer, |value| eku.check(value))?;

    Ok(())
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
fn check_validity(input: &mut untrusted::Reader, time: time::Time) -> Result<(), Error> {
    let not_before = time::Time::from_der(input)?;
    let not_after = time::Time::from_der(input)?;

    if not_before > not_after {
        return Err(Error::InvalidCertValidity);
    }
    if time < not_before {
        return Err(Error::CertNotValidYet);
    }
    if time > not_after {
        return Err(Error::CertExpired);
    }

    // TODO: mozilla::pkix allows the TrustDomain to check not_before and
    // not_after, to enforce things like a maximum validity period. We should
    // do something similar.

    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum UsedAsCa {
    Yes,
    No,
}

fn used_as_ca(ee_or_ca: &EndEntityOrCa) -> UsedAsCa {
    match ee_or_ca {
        EndEntityOrCa::EndEntity => UsedAsCa::No,
        EndEntityOrCa::Ca(..) => UsedAsCa::Yes,
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
fn check_basic_constraints(
    input: Option<&mut untrusted::Reader>,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
) -> Result<(), Error> {
    let (is_ca, path_len_constraint) = match input {
        Some(input) => {
            let is_ca = bool::from_der(input)?;

            // https://bugzilla.mozilla.org/show_bug.cgi?id=985025: RFC 5280
            // says that a certificate must not have pathLenConstraint unless
            // it is a CA certificate, but some real-world end-entity
            // certificates have pathLenConstraint.
            let path_len_constraint = if !input.at_end() {
                Some(usize::from(u8::from_der(input)?))
            } else {
                None
            };

            (is_ca, path_len_constraint)
        }
        None => (false, None),
    };

    match (used_as_ca, is_ca, path_len_constraint) {
        (UsedAsCa::No, true, _) => Err(Error::CaUsedAsEndEntity),
        (UsedAsCa::Yes, false, _) => Err(Error::EndEntityUsedAsCa),
        (UsedAsCa::Yes, true, Some(len)) if sub_ca_count > len => {
            Err(Error::PathLenConstraintViolated)
        }
        _ => Ok(()),
    }
}

/// The expected key usage of a certificate.
///
/// This type represents the expected key usage of an end entity certificate. Although for most
/// kinds of certificates the extended key usage extension is optional (and so certificates
/// not carrying a particular value in the EKU extension are acceptable). If the extension
/// is present, the certificate MUST only be used for one of the purposes indicated.
///
/// <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12>
#[derive(Clone, Copy)]
pub struct KeyUsage {
    inner: ExtendedKeyUsage,
}

impl KeyUsage {
    /// Construct a new [`KeyUsage`] as appropriate for server certificate authentication.
    ///
    /// As specified in <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12>, this does not require the certificate to specify the eKU extension.
    pub const fn server_auth() -> Self {
        Self {
            inner: ExtendedKeyUsage::RequiredIfPresent(EKU_SERVER_AUTH),
        }
    }

    /// Construct a new [`KeyUsage`] as appropriate for client certificate authentication.
    ///
    /// As specified in <>, this does not require the certificate to specify the eKU extension.
    pub const fn client_auth() -> Self {
        Self {
            inner: ExtendedKeyUsage::RequiredIfPresent(EKU_CLIENT_AUTH),
        }
    }

    /// Construct a new [`KeyUsage`] requiring a certificate to support the specified OID.
    pub const fn required(oid: &'static [u8]) -> Self {
        Self {
            inner: ExtendedKeyUsage::Required(KeyPurposeId::new(oid)),
        }
    }
}

/// Extended Key Usage (EKU) of a certificate.
#[derive(Clone, Copy)]
enum ExtendedKeyUsage {
    /// The certificate must contain the specified [`KeyPurposeId`] as EKU.
    Required(KeyPurposeId),

    /// If the certificate has EKUs, then the specified [`KeyPurposeId`] must be included.
    RequiredIfPresent(KeyPurposeId),
}

impl ExtendedKeyUsage {
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.12
    fn check(&self, input: Option<&mut untrusted::Reader>) -> Result<(), Error> {
        let input = match (input, self) {
            (Some(input), _) => input,
            (None, Self::RequiredIfPresent(_)) => return Ok(()),
            (None, Self::Required(_)) => return Err(Error::RequiredEkuNotFound),
        };

        loop {
            let value = der::expect_tag(input, der::Tag::OID)?;
            if self.key_purpose_id_equals(value) {
                input.skip_to_end();
                break;
            }

            if input.at_end() {
                return Err(Error::RequiredEkuNotFound);
            }
        }

        Ok(())
    }

    fn key_purpose_id_equals(&self, value: untrusted::Input<'_>) -> bool {
        match self {
            ExtendedKeyUsage::Required(eku) => *eku,
            ExtendedKeyUsage::RequiredIfPresent(eku) => *eku,
        }
        .oid_value
            == value
    }
}

/// An OID value indicating an Extended Key Usage (EKU) key purpose.
#[derive(Clone, Copy, PartialEq, Eq)]
struct KeyPurposeId {
    oid_value: untrusted::Input<'static>,
}

impl KeyPurposeId {
    /// Construct a new [`KeyPurposeId`].
    ///
    /// `oid` is the OBJECT IDENTIFIER in bytes.
    const fn new(oid: &'static [u8]) -> Self {
        Self {
            oid_value: untrusted::Input::from(oid),
        }
    }
}

// id-pkix            OBJECT IDENTIFIER ::= { 1 3 6 1 5 5 7 }
// id-kp              OBJECT IDENTIFIER ::= { id-pkix 3 }

// id-kp-serverAuth   OBJECT IDENTIFIER ::= { id-kp 1 }
const EKU_SERVER_AUTH: KeyPurposeId = KeyPurposeId::new(&oid!(1, 3, 6, 1, 5, 5, 7, 3, 1));

// id-kp-clientAuth   OBJECT IDENTIFIER ::= { id-kp 2 }
const EKU_CLIENT_AUTH: KeyPurposeId = KeyPurposeId::new(&oid!(1, 3, 6, 1, 5, 5, 7, 3, 2));

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
#[repr(u8)]
#[derive(Clone, Copy)]
enum KeyUsageMode {
    // DigitalSignature = 0,
    // ContentCommitment = 1,
    // KeyEncipherment = 2,
    // DataEncipherment = 3,
    // KeyAgreement = 4,
    // CertSign = 5,
    CrlSign = 6,
    // EncipherOnly = 7,
    // DecipherOnly = 8,
}

impl KeyUsageMode {
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
    fn check(self, input: Option<untrusted::Input>) -> Result<(), Error> {
        let bit_string = match input {
            Some(input) => {
                der::expect_tag(&mut untrusted::Reader::new(input), der::Tag::BitString)?
            }
            // While RFC 5280 requires KeyUsage be present, historically the absence of a KeyUsage
            // has been treated as "Any Usage". We follow that convention here and assume the absence
            // of KeyUsage implies the required_ku_bit_if_present we're checking for.
            None => return Ok(()),
        };

        let flags = der::bit_string_flags(bit_string)?;
        #[allow(clippy::as_conversions)] // u8 always fits in usize.
        match flags.bit_set(self as usize) {
            true => Ok(()),
            false => Err(Error::IssuerNotCrlSigner),
        }
    }
}

fn loop_while_non_fatal_error<V>(
    default_error: Error,
    values: V,
    mut f: impl FnMut(V::Item) -> Result<(), Error>,
) -> Result<(), Error>
where
    V: IntoIterator,
{
    let mut error = default_error;
    for v in values {
        match f(v) {
            Ok(()) => return Ok(()),
            err @ Err(Error::MaximumSignatureChecksExceeded)
            | err @ Err(Error::MaximumPathBuildCallsExceeded) => return err,
            Err(new_error) => error = error.most_specific(new_error),
        }
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BorrowedCertRevocationList;

    #[test]
    fn eku_key_purpose_id() {
        assert!(ExtendedKeyUsage::RequiredIfPresent(EKU_SERVER_AUTH)
            .key_purpose_id_equals(EKU_SERVER_AUTH.oid_value))
    }

    #[test]
    // safe to convert BorrowedCertRevocationList to CertRevocationList.
    // redundant clone, clone_on_copy allowed to verify derived traits.
    #[allow(clippy::as_conversions, clippy::redundant_clone, clippy::clone_on_copy)]
    fn test_revocation_opts_builder() {
        // Trying to build a RevocationOptionsBuilder w/o CRLs should err.
        let result = RevocationOptionsBuilder::new(&[]);
        assert!(matches!(result, Err(CrlsRequired(_))));

        // The CrlsRequired error should be debug and clone when alloc is enabled.
        #[cfg(feature = "alloc")]
        {
            let err = result.unwrap_err();
            println!("{:?}", err.clone());
        }

        // It should be possible to build a revocation options builder with defaults.
        let crl = include_bytes!("../tests/crls/crl.valid.der");
        let crl =
            &BorrowedCertRevocationList::from_der(&crl[..]).unwrap() as &dyn CertRevocationList;
        let crls = [crl];
        let builder = RevocationOptionsBuilder::new(&crls[..]).unwrap();
        #[cfg(feature = "alloc")]
        {
            // The builder should be debug, and clone when alloc is enabled
            println!("{:?}", builder);
            _ = builder.clone();
        }
        let opts = builder.build();
        assert_eq!(opts.depth, RevocationCheckDepth::Chain);
        assert_eq!(opts.status_requirement, UnknownStatusPolicy::Deny);
        assert_eq!(opts.crls.len(), 1);

        // It should be possible to build a revocation options builder with custom depth.
        let opts = RevocationOptionsBuilder::new(&crls[..])
            .unwrap()
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        assert_eq!(opts.depth, RevocationCheckDepth::EndEntity);
        assert_eq!(opts.status_requirement, UnknownStatusPolicy::Deny);
        assert_eq!(opts.crls.len(), 1);

        // It should be possible to build a revocation options builder that allows unknown
        // revocation status.
        let opts = RevocationOptionsBuilder::new(&crls[..])
            .unwrap()
            .allow_unknown_status()
            .build();
        assert_eq!(opts.depth, RevocationCheckDepth::Chain);
        assert_eq!(opts.status_requirement, UnknownStatusPolicy::Allow);
        assert_eq!(opts.crls.len(), 1);

        // It should be possible to specify both depth and unknown status requirements together.
        let opts = RevocationOptionsBuilder::new(&crls[..])
            .unwrap()
            .allow_unknown_status()
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        assert_eq!(opts.depth, RevocationCheckDepth::EndEntity);
        assert_eq!(opts.status_requirement, UnknownStatusPolicy::Allow);
        assert_eq!(opts.crls.len(), 1);

        // The same should be true for explicitly forbidding unknown status.
        let opts = RevocationOptionsBuilder::new(&crls[..])
            .unwrap()
            .forbid_unknown_status()
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        assert_eq!(opts.depth, RevocationCheckDepth::EndEntity);
        assert_eq!(opts.status_requirement, UnknownStatusPolicy::Deny);
        assert_eq!(opts.crls.len(), 1);

        // Built revocation options should be debug and clone when alloc is enabled.
        #[cfg(feature = "alloc")]
        {
            println!("{:?}", opts.clone());
        }
    }

    #[test]
    fn test_crl_authoritative_issuer_mismatch() {
        let crl = include_bytes!("../tests/crls/crl.valid.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        let ee = include_bytes!("../tests/client_auth_revocation/no_ku_chain.ee.der");
        let ee = Cert::from_der(untrusted::Input::from(&ee[..]), EndEntityOrCa::EndEntity).unwrap();

        // The CRL should not be authoritative for an EE issued by a different issuer.
        assert!(!crl_authoritative(&crl, &ee));
    }

    #[test]
    fn test_crl_authoritative_no_idp_no_cert_dp() {
        let crl =
            include_bytes!("../tests/client_auth_revocation/ee_revoked_crl_ku_ee_depth.crl.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        let ee = include_bytes!("../tests/client_auth_revocation/ku_chain.ee.der");
        let ee = Cert::from_der(untrusted::Input::from(&ee[..]), EndEntityOrCa::EndEntity).unwrap();

        // The CRL should be considered authoritative, the issuers match, the CRL has no IDP and the
        // cert has no CRL DPs.
        assert!(crl_authoritative(&crl, &ee));
    }

    #[cfg(feature = "alloc")]
    enum TrustAnchorIsActualIssuer {
        Yes,
        No,
    }

    #[cfg(feature = "alloc")]
    fn build_degenerate_chain(
        intermediate_count: usize,
        trust_anchor_is_actual_issuer: TrustAnchorIsActualIssuer,
    ) -> Error {
        use crate::{extract_trust_anchor, ECDSA_P256_SHA256};
        use crate::{EndEntityCert, Time};

        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        let make_issuer = || {
            let mut ca_params = rcgen::CertificateParams::new(Vec::new());
            ca_params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "Bogus Subject");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            ca_params.alg = alg;
            rcgen::Certificate::from_params(ca_params).unwrap()
        };

        let ca_cert = make_issuer();
        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());

        let mut intermediates = Vec::with_capacity(intermediate_count);
        let mut issuer = ca_cert;
        for _ in 0..intermediate_count {
            let intermediate = make_issuer();
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        let mut ee_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
        ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        ee_params.alg = alg;
        let ee_cert = rcgen::Certificate::from_params(ee_params).unwrap();
        let ee_cert_der = CertificateDer::from(ee_cert.serialize_der_with_signer(&issuer).unwrap());

        let anchors = &[extract_trust_anchor(&ca_cert_der).unwrap()];
        let time = Time::from_seconds_since_unix_epoch(0x1fed_f00d);
        let cert = EndEntityCert::try_from(&ee_cert_der).unwrap();
        let mut intermediates_der = intermediates
            .iter()
            .map(|x| CertificateDer::from(x.as_ref()))
            .collect::<Vec<_>>();

        if let TrustAnchorIsActualIssuer::No = trust_anchor_is_actual_issuer {
            intermediates_der.pop();
        }

        build_chain(
            &ChainOptions {
                eku: KeyUsage::server_auth(),
                supported_sig_algs: &[ECDSA_P256_SHA256],
                trust_anchors: anchors,
                intermediate_certs: &intermediates_der,
                revocation: None,
            },
            cert.inner(),
            time,
        )
        .unwrap_err()
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_signatures() {
        assert_eq!(
            build_degenerate_chain(5, TrustAnchorIsActualIssuer::Yes),
            Error::MaximumSignatureChecksExceeded
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_path_calls() {
        assert_eq!(
            build_degenerate_chain(10, TrustAnchorIsActualIssuer::No),
            Error::MaximumPathBuildCallsExceeded
        );
    }

    #[cfg(feature = "alloc")]
    fn build_linear_chain(chain_length: usize) -> Result<(), Error> {
        use crate::{extract_trust_anchor, ECDSA_P256_SHA256};
        use crate::{EndEntityCert, Time};

        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        let make_issuer = |index: usize| {
            let mut ca_params = rcgen::CertificateParams::new(Vec::new());
            ca_params.distinguished_name.push(
                rcgen::DnType::OrganizationName,
                format!("Bogus Subject {index}"),
            );
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            ca_params.alg = alg;
            rcgen::Certificate::from_params(ca_params).unwrap()
        };

        let ca_cert = make_issuer(chain_length);
        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());

        let mut intermediates = Vec::with_capacity(chain_length);
        let mut issuer = ca_cert;
        for i in 0..chain_length {
            let intermediate = make_issuer(i);
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        let mut ee_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
        ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        ee_params.alg = alg;
        let ee_cert = rcgen::Certificate::from_params(ee_params).unwrap();
        let ee_cert_der = CertificateDer::from(ee_cert.serialize_der_with_signer(&issuer).unwrap());

        let anchors = &[extract_trust_anchor(&ca_cert_der).unwrap()];
        let time = Time::from_seconds_since_unix_epoch(0x1fed_f00d);
        let cert = EndEntityCert::try_from(&ee_cert_der).unwrap();
        let intermediates_der = intermediates
            .iter()
            .map(|x| CertificateDer::from(x.as_ref()))
            .collect::<Vec<_>>();

        build_chain(
            &ChainOptions {
                eku: KeyUsage::server_auth(),
                supported_sig_algs: &[ECDSA_P256_SHA256],
                trust_anchors: anchors,
                intermediate_certs: &intermediates_der,
                revocation: None,
            },
            cert.inner(),
            time,
        )
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn longest_allowed_path() {
        assert_eq!(build_linear_chain(1), Ok(()));
        assert_eq!(build_linear_chain(2), Ok(()));
        assert_eq!(build_linear_chain(3), Ok(()));
        assert_eq!(build_linear_chain(4), Ok(()));
        assert_eq!(build_linear_chain(5), Ok(()));
        assert_eq!(build_linear_chain(6), Ok(()));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn path_too_long() {
        assert_eq!(build_linear_chain(7), Err(Error::MaximumPathDepthExceeded));
    }
}
