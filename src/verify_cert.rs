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
use core::ops::ControlFlow;

use pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};

use crate::cert::Cert;
use crate::crl::RevocationOptions;
use crate::der::{self, FromDer};
use crate::{signed_data, subject_name, Error};

pub(crate) struct ChainOptions<'a> {
    pub(crate) eku: KeyUsage,
    pub(crate) supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
    pub(crate) trust_anchors: &'a [TrustAnchor<'a>],
    pub(crate) intermediate_certs: &'a [CertificateDer<'a>],
    pub(crate) revocation: Option<RevocationOptions<'a>>,
}

impl<'a> ChainOptions<'a> {
    pub(crate) fn build_chain(&self, cert: &Cert<'_>, time: UnixTime) -> Result<(), Error> {
        let path = PathNode { cert, issued: None };
        self.build_chain_inner(&path, time, 0, &mut Budget::default())
            .map_err(|e| match e {
                ControlFlow::Break(err) => err,
                ControlFlow::Continue(err) => err,
            })
    }

    fn build_chain_inner(
        &self,
        path: &PathNode<'_>,
        time: UnixTime,
        sub_ca_count: usize,
        budget: &mut Budget,
    ) -> Result<(), ControlFlow<Error, Error>> {
        let role = path.role();

        check_issuer_independent_properties(path.cert, time, role, sub_ca_count, self.eku.inner)?;

        // TODO: HPKP checks.

        match role {
            Role::Issuer => {
                const MAX_SUB_CA_COUNT: usize = 6;

                if sub_ca_count >= MAX_SUB_CA_COUNT {
                    return Err(Error::MaximumPathDepthExceeded.into());
                }
            }
            Role::EndEntity => {
                assert_eq!(0, sub_ca_count);
            }
        }

        let result = loop_while_non_fatal_error(
            Error::UnknownIssuer,
            self.trust_anchors,
            |trust_anchor: &TrustAnchor| {
                let trust_anchor_subject = untrusted::Input::from(trust_anchor.subject.as_ref());
                if path.cert.issuer != trust_anchor_subject {
                    return Err(Error::UnknownIssuer.into());
                }

                // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;

                self.check_signed_chain(path, trust_anchor, budget)?;

                check_signed_chain_name_constraints(path, trust_anchor, budget)?;

                Ok(())
            },
        );

        let err = match result {
            Ok(()) => return Ok(()),
            // Fatal errors should halt further path building.
            res @ Err(ControlFlow::Break(_)) => return res,
            // Non-fatal errors should be carried forward as the default_error for subsequent
            // loop_while_non_fatal_error processing and only returned once all other path-building
            // options have been exhausted.
            Err(ControlFlow::Continue(err)) => err,
        };

        loop_while_non_fatal_error(err, self.intermediate_certs, |cert_der| {
            let potential_issuer = Cert::from_der(untrusted::Input::from(cert_der))?;
            if potential_issuer.subject != path.cert.issuer {
                return Err(Error::UnknownIssuer.into());
            }

            // Prevent loops; see RFC 4158 section 5.2.
            if path.iter().any(|prev| {
                potential_issuer.spki == prev.cert.spki
                    && potential_issuer.subject == prev.cert.subject
            }) {
                return Err(Error::UnknownIssuer.into());
            }

            let next_sub_ca_count = match role {
                Role::EndEntity => sub_ca_count,
                Role::Issuer => sub_ca_count + 1,
            };

            budget.consume_build_chain_call()?;
            let potential_path = PathNode {
                cert: &potential_issuer,
                issued: Some(path),
            };
            self.build_chain_inner(&potential_path, time, next_sub_ca_count, budget)
        })
    }

    fn check_signed_chain(
        &self,
        path: &PathNode<'_>,
        trust_anchor: &TrustAnchor,
        budget: &mut Budget,
    ) -> Result<(), ControlFlow<Error, Error>> {
        let mut spki_value = untrusted::Input::from(trust_anchor.subject_public_key_info.as_ref());
        let mut issuer_subject = untrusted::Input::from(trust_anchor.subject.as_ref());
        let mut issuer_key_usage = None; // TODO(XXX): Consider whether to track TrustAnchor KU.
        for path in path.iter() {
            signed_data::verify_signed_data(
                self.supported_sig_algs,
                spki_value,
                &path.cert.signed_data,
                budget,
            )?;

            if let Some(revocation_opts) = &self.revocation {
                revocation_opts.check(
                    path,
                    issuer_subject,
                    spki_value,
                    issuer_key_usage,
                    self.supported_sig_algs,
                    budget,
                )?;
            }

            spki_value = path.cert.spki;
            issuer_subject = path.cert.subject;
            issuer_key_usage = path.cert.key_usage;
        }

        Ok(())
    }
}

fn check_signed_chain_name_constraints(
    path: &PathNode<'_>,
    trust_anchor: &TrustAnchor,
    budget: &mut Budget,
) -> Result<(), ControlFlow<Error, Error>> {
    let mut name_constraints = trust_anchor
        .name_constraints
        .as_ref()
        .map(|der| untrusted::Input::from(der.as_ref()));

    for path in path.iter() {
        untrusted::read_all_optional(name_constraints, Error::BadDer, |value| {
            subject_name::check_name_constraints(value, path, budget)
        })?;

        name_constraints = path.cert.name_constraints;
    }

    Ok(())
}

pub struct Budget {
    signatures: usize,
    build_chain_calls: usize,
    name_constraint_comparisons: usize,
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

    #[inline]
    pub(crate) fn consume_name_constraint_comparison(&mut self) -> Result<(), Error> {
        self.name_constraint_comparisons = self
            .name_constraint_comparisons
            .checked_sub(1)
            .ok_or(Error::MaximumNameConstraintComparisonsExceeded)?;
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

            // This limit is taken from golang crypto/x509's default, see:
            // <https://github.com/golang/go/blob/ac17bb6f13979f2ab9fcd45f0758b43ed72d0973/src/crypto/x509/verify.go#L588-L592>
            name_constraint_comparisons: 250_000,
        }
    }
}

fn check_issuer_independent_properties(
    cert: &Cert,
    time: UnixTime,
    role: Role,
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
        check_basic_constraints(value, role, sub_ca_count)
    })?;
    untrusted::read_all_optional(cert.eku, Error::BadDer, |value| eku.check(value))?;

    Ok(())
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
fn check_validity(input: &mut untrusted::Reader, time: UnixTime) -> Result<(), Error> {
    let not_before = UnixTime::from_der(input)?;
    let not_after = UnixTime::from_der(input)?;

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

// https://tools.ietf.org/html/rfc5280#section-4.2.1.9
fn check_basic_constraints(
    input: Option<&mut untrusted::Reader>,
    role: Role,
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

    match (role, is_ca, path_len_constraint) {
        (Role::EndEntity, true, _) => Err(Error::CaUsedAsEndEntity),
        (Role::Issuer, false, _) => Err(Error::EndEntityUsedAsCa),
        (Role::Issuer, true, Some(len)) if sub_ca_count > len => {
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

fn loop_while_non_fatal_error<V>(
    default_error: Error,
    values: V,
    mut f: impl FnMut(V::Item) -> Result<(), ControlFlow<Error, Error>>,
) -> Result<(), ControlFlow<Error, Error>>
where
    V: IntoIterator,
{
    let mut error = default_error;
    for v in values {
        match f(v) {
            Ok(()) => return Ok(()),
            // Fatal errors should halt further looping.
            res @ Err(ControlFlow::Break(_)) => return res,
            // Non-fatal errors should be ranked by specificity and only returned
            // once all other path-building options have been exhausted.
            Err(ControlFlow::Continue(new_error)) => error = error.most_specific(new_error),
        }
    }
    Err(error.into())
}

/// A node in a [`Cert`] path, represented as a linked list from trust anchor to end-entity.
pub(crate) struct PathNode<'a> {
    pub(crate) cert: &'a Cert<'a>,
    /// Links to the next node in the path; this list is in trust anchor to end-entity order.
    /// As such, the next node, `issued`, was issued by this node; and `issued` is `None` for the
    /// last node, which thus represents the end-entity certificate.
    pub(crate) issued: Option<&'a PathNode<'a>>,
}

impl<'a> PathNode<'a> {
    pub(crate) fn iter(&'a self) -> PathNodeIter<'a> {
        PathNodeIter { next: Some(self) }
    }

    fn role(&self) -> Role {
        match self.issued {
            Some(_) => Role::Issuer,
            None => Role::EndEntity,
        }
    }
}

pub(crate) struct PathNodeIter<'a> {
    next: Option<&'a PathNode<'a>>,
}

impl<'a> Iterator for PathNodeIter<'a> {
    type Item = &'a PathNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next?;
        self.next = next.issued;
        Some(next)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Issuer,
    EndEntity,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::test_utils::{issuer_params, make_end_entity, make_issuer};

    #[test]
    fn eku_key_purpose_id() {
        assert!(ExtendedKeyUsage::RequiredIfPresent(EKU_SERVER_AUTH)
            .key_purpose_id_equals(EKU_SERVER_AUTH.oid_value))
    }

    #[cfg(feature = "alloc")]
    enum ChainTrustAnchor {
        NotInChain,
        InChain,
    }

    #[cfg(feature = "alloc")]
    fn build_degenerate_chain(
        intermediate_count: usize,
        trust_anchor: ChainTrustAnchor,
    ) -> ControlFlow<Error, Error> {
        let ca_cert = make_issuer("Bogus Subject");
        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());

        let mut intermediates = Vec::with_capacity(intermediate_count + 1);
        if let ChainTrustAnchor::InChain = trust_anchor {
            intermediates.push(ca_cert_der.to_vec());
        }

        let mut issuer = ca_cert;
        for _ in 0..intermediate_count {
            let intermediate = make_issuer("Bogus Subject");
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        let trust_anchor = match trust_anchor {
            ChainTrustAnchor::InChain => {
                let unused_anchor = make_issuer("Bogus Trust Anchor");
                CertificateDer::from(unused_anchor.serialize_der().unwrap())
            }
            ChainTrustAnchor::NotInChain => ca_cert_der,
        };

        verify_chain(
            &trust_anchor,
            &intermediates,
            &make_end_entity(&issuer),
            None,
        )
        .unwrap_err()
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_signatures() {
        assert!(matches!(
            build_degenerate_chain(5, ChainTrustAnchor::NotInChain),
            ControlFlow::Break(Error::MaximumSignatureChecksExceeded)
        ));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_path_calls() {
        assert!(matches!(
            dbg!(build_degenerate_chain(10, ChainTrustAnchor::InChain)),
            ControlFlow::Break(Error::MaximumPathBuildCallsExceeded)
        ));
    }

    #[cfg(feature = "alloc")]
    fn build_linear_chain(chain_length: usize) -> Result<(), ControlFlow<Error, Error>> {
        let ca_cert = make_issuer(format!("Bogus Subject {chain_length}"));
        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());

        let mut intermediates = Vec::with_capacity(chain_length);
        let mut issuer = ca_cert;
        for i in 0..chain_length {
            let intermediate = make_issuer(format!("Bogus Subject {i}"));
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        verify_chain(
            &ca_cert_der,
            &intermediates,
            &make_end_entity(&issuer),
            None,
        )
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn longest_allowed_path() {
        assert!(build_linear_chain(1).is_ok());
        assert!(build_linear_chain(2).is_ok());
        assert!(build_linear_chain(3).is_ok());
        assert!(build_linear_chain(4).is_ok());
        assert!(build_linear_chain(5).is_ok());
        assert!(build_linear_chain(6).is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn path_too_long() {
        assert!(matches!(
            build_linear_chain(7),
            Err(ControlFlow::Continue(Error::MaximumPathDepthExceeded))
        ));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn name_constraint_budget() {
        // Issue a trust anchor that imposes name constraints. The constraint should match
        // the end entity certificate SAN.
        let mut ca_cert_params = issuer_params("Constrained Root");
        ca_cert_params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName(".com".into())],
            excluded_subtrees: vec![],
        });
        let ca_cert = rcgen::Certificate::from_params(ca_cert_params).unwrap();
        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der().unwrap());

        // Create a series of intermediate issuers. We'll only use one in the actual built path,
        // helping demonstrate that the name constraint budget is not expended checking certificates
        // that are not part of the path we compute.
        const NUM_INTERMEDIATES: usize = 5;
        let mut intermediates = Vec::with_capacity(NUM_INTERMEDIATES);
        for i in 0..NUM_INTERMEDIATES {
            intermediates.push(make_issuer(format!("Intermediate {i}")));
        }

        // Each intermediate should be issued by the trust anchor.
        let mut intermediates_der = Vec::with_capacity(NUM_INTERMEDIATES);
        for intermediate in &intermediates {
            intermediates_der.push(intermediate.serialize_der_with_signer(&ca_cert).unwrap());
        }

        // Create an end-entity cert that is issued by the last of the intermediates.
        let ee_cert = make_end_entity(intermediates.last().unwrap());

        // We use a custom budget to make it easier to write a test, otherwise it is tricky to
        // stuff enough names/constraints into the potential chains while staying within the path
        // depth limit and the build chain call limit.
        let passing_budget = Budget {
            // One comparison against the intermediate's distinguished name.
            // One comparison against the EE's distinguished name.
            // One comparison against the EE's SAN.
            //  = 3 total comparisons.
            name_constraint_comparisons: 3,
            ..Budget::default()
        };

        // Validation should succeed with the name constraint comparison budget allocated above.
        // This shows that we're not consuming budget on unused intermediates: we didn't budget
        // enough comparisons for that to pass the overall chain building.
        assert!(verify_chain(
            &ca_cert_der,
            &intermediates_der,
            &ee_cert,
            Some(passing_budget),
        )
        .is_ok());

        let failing_budget = Budget {
            // See passing_budget: 2 comparisons is not sufficient.
            name_constraint_comparisons: 2,
            ..Budget::default()
        };
        // Validation should fail when the budget is smaller than the number of comparisons performed
        // on the validated path. This demonstrates we properly fail path building when too many
        // name constraint comparisons occur.
        let result = verify_chain(
            &ca_cert_der,
            &intermediates_der,
            &ee_cert,
            Some(failing_budget),
        );

        assert!(matches!(
            result,
            Err(ControlFlow::Break(
                Error::MaximumNameConstraintComparisonsExceeded
            ))
        ));
    }

    #[cfg(feature = "alloc")]
    fn verify_chain(
        trust_anchor: &CertificateDer<'_>,
        intermediates_der: &[Vec<u8>],
        ee_cert: &CertificateDer<'_>,
        budget: Option<Budget>,
    ) -> Result<(), ControlFlow<Error, Error>> {
        use crate::end_entity::EndEntityCert;
        use crate::ring_algs::ECDSA_P256_SHA256;
        use crate::trust_anchor::extract_trust_anchor;
        use core::time::Duration;

        let anchors = &[extract_trust_anchor(trust_anchor).unwrap()];
        let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
        let cert = EndEntityCert::try_from(ee_cert).unwrap();
        let intermediates_der = intermediates_der
            .iter()
            .map(|x| CertificateDer::from(x.as_ref()))
            .collect::<Vec<_>>();

        ChainOptions {
            eku: KeyUsage::server_auth(),
            supported_sig_algs: &[ECDSA_P256_SHA256],
            trust_anchors: anchors,
            intermediate_certs: &intermediates_der,
            revocation: None,
        }
        .build_chain_inner(
            &PathNode {
                cert: cert.inner(),
                issued: None,
            },
            time,
            0,
            &mut budget.unwrap_or_default(),
        )
    }
}
