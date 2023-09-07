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

use crate::{
    cert::{self, Cert, EndEntityOrCa},
    der, signed_data, subject_name, time, Error, SignatureAlgorithm, TrustAnchor,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_chain(
    required_eku_if_present: KeyPurposeId,
    supported_sig_algs: &[&SignatureAlgorithm],
    trust_anchors: &[TrustAnchor],
    intermediate_certs: &[&[u8]],
    cert: &Cert,
    time: time::Time,
) -> Result<(), Error> {
    build_chain_inner(
        required_eku_if_present,
        supported_sig_algs,
        trust_anchors,
        intermediate_certs,
        cert,
        time,
        0,
        &mut Budget::default(),
    )
    .map_err(|e| match e {
        ControlFlow::Break(err) => err,
        ControlFlow::Continue(err) => err,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_chain_inner(
    required_eku_if_present: KeyPurposeId,
    supported_sig_algs: &[&SignatureAlgorithm],
    trust_anchors: &[TrustAnchor],
    intermediate_certs: &[&[u8]],
    cert: &Cert,
    time: time::Time,
    sub_ca_count: usize,
    budget: &mut Budget,
) -> Result<(), ControlFlow<Error, Error>> {
    let used_as_ca = used_as_ca(&cert.ee_or_ca);

    check_issuer_independent_properties(
        cert,
        time,
        used_as_ca,
        sub_ca_count,
        required_eku_if_present,
    )?;

    // TODO: HPKP checks.

    match used_as_ca {
        UsedAsCa::Yes => {
            const MAX_SUB_CA_COUNT: usize = 6;

            if sub_ca_count >= MAX_SUB_CA_COUNT {
                return Err(Error::MaximumPathDepthExceeded.into());
            }
        }
        UsedAsCa::No => {
            assert_eq!(0, sub_ca_count);
        }
    }

    // for the purpose of name constraints checking, only end-entity server certificates
    // could plausibly have a DNS name as a subject commonName that could contribute to
    // path validity
    let subject_common_name_contents =
        if required_eku_if_present == EKU_SERVER_AUTH && used_as_ca == UsedAsCa::No {
            subject_name::SubjectCommonNameContents::DnsName
        } else {
            subject_name::SubjectCommonNameContents::Ignore
        };

    // TODO: revocation.

    let result = loop_while_non_fatal_error(trust_anchors, |trust_anchor: &TrustAnchor| {
        let trust_anchor_subject = untrusted::Input::from(trust_anchor.subject);
        if cert.issuer != trust_anchor_subject {
            return Err(Error::UnknownIssuer.into());
        }

        // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;

        let trust_anchor_spki = untrusted::Input::from(trust_anchor.spki);
        check_signed_chain(supported_sig_algs, cert, trust_anchor_spki, budget)?;

        check_signed_chain_name_constraints(
            cert,
            trust_anchor,
            subject_common_name_contents,
            budget,
        )?;

        Ok(())
    });

    // If the error is not fatal, then keep going.
    match result {
        Ok(()) => return Ok(()),
        // Fatal errors should halt further path building.
        res @ Err(ControlFlow::Break(_)) => return res,
        // Non-fatal errors should allow path building to continue.
        Err(ControlFlow::Continue(_)) => {}
    };

    loop_while_non_fatal_error(intermediate_certs, |cert_der| {
        let potential_issuer =
            cert::parse_cert(untrusted::Input::from(cert_der), EndEntityOrCa::Ca(cert))?;

        if potential_issuer.subject != cert.issuer {
            return Err(Error::UnknownIssuer.into());
        }

        // Prevent loops; see RFC 4158 section 5.2.
        let mut prev = cert;
        loop {
            if potential_issuer.spki.value() == prev.spki.value()
                && potential_issuer.subject == prev.subject
            {
                return Err(Error::UnknownIssuer.into());
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

        let next_sub_ca_count = match used_as_ca {
            UsedAsCa::No => sub_ca_count,
            UsedAsCa::Yes => sub_ca_count + 1,
        };

        budget.consume_build_chain_call()?;
        build_chain_inner(
            required_eku_if_present,
            supported_sig_algs,
            trust_anchors,
            intermediate_certs,
            &potential_issuer,
            time,
            next_sub_ca_count,
            budget,
        )
    })
}

fn check_signed_chain(
    supported_sig_algs: &[&SignatureAlgorithm],
    cert_chain: &Cert,
    trust_anchor_key: untrusted::Input,
    budget: &mut Budget,
) -> Result<(), ControlFlow<Error, Error>> {
    let mut spki_value = trust_anchor_key;
    let mut cert = cert_chain;
    loop {
        signed_data::verify_signed_data(supported_sig_algs, spki_value, &cert.signed_data, budget)?;

        // TODO: check revocation

        match &cert.ee_or_ca {
            EndEntityOrCa::Ca(child_cert) => {
                spki_value = cert.spki.value();
                cert = child_cert;
            }
            EndEntityOrCa::EndEntity => {
                break;
            }
        }
    }

    Ok(())
}

fn check_signed_chain_name_constraints(
    cert_chain: &Cert,
    trust_anchor: &TrustAnchor,
    subject_common_name_contents: subject_name::SubjectCommonNameContents,
    budget: &mut Budget,
) -> Result<(), ControlFlow<Error, Error>> {
    let mut cert = cert_chain;
    let mut name_constraints = trust_anchor
        .name_constraints
        .as_ref()
        .map(|der| untrusted::Input::from(der));

    loop {
        untrusted::read_all_optional(name_constraints, Error::BadDer, |value| {
            subject_name::check_name_constraints(value, cert, subject_common_name_contents, budget)
        })?;

        match &cert.ee_or_ca {
            EndEntityOrCa::Ca(child_cert) => {
                name_constraints = cert.name_constraints;
                cert = child_cert;
            }
            EndEntityOrCa::EndEntity => {
                break;
            }
        }
    }

    Ok(())
}

pub(crate) struct Budget {
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
    time: time::Time,
    used_as_ca: UsedAsCa,
    sub_ca_count: usize,
    required_eku_if_present: KeyPurposeId,
) -> Result<(), Error> {
    // TODO: check_distrust(trust_anchor_subject, trust_anchor_spki)?;
    // TODO: Check signature algorithm like mozilla::pkix.
    // TODO: Check SPKI like mozilla::pkix.
    // TODO: check for active distrust like mozilla::pkix.

    // See the comment in `remember_extension` for why we don't check the
    // KeyUsage extension.

    cert.validity
        .read_all(Error::BadDer, |value| check_validity(value, time))?;
    untrusted::read_all_optional(cert.basic_constraints, Error::BadDer, |value| {
        check_basic_constraints(value, used_as_ca, sub_ca_count)
    })?;
    untrusted::read_all_optional(cert.eku, Error::BadDer, |value| {
        check_eku(value, required_eku_if_present)
    })?;

    Ok(())
}

// https://tools.ietf.org/html/rfc5280#section-4.1.2.5
fn check_validity(input: &mut untrusted::Reader, time: time::Time) -> Result<(), Error> {
    let not_before = der::time_choice(input)?;
    let not_after = der::time_choice(input)?;

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
            let is_ca = der::optional_boolean(input)?;

            // https://bugzilla.mozilla.org/show_bug.cgi?id=985025: RFC 5280
            // says that a certificate must not have pathLenConstraint unless
            // it is a CA certificate, but some real-world end-entity
            // certificates have pathLenConstraint.
            let path_len_constraint = if !input.at_end() {
                let value = der::small_nonnegative_integer(input)?;
                Some(usize::from(value))
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyPurposeId {
    oid_value: untrusted::Input<'static>,
}

// id-pkix            OBJECT IDENTIFIER ::= { 1 3 6 1 5 5 7 }
// id-kp              OBJECT IDENTIFIER ::= { id-pkix 3 }

// id-kp-serverAuth   OBJECT IDENTIFIER ::= { id-kp 1 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub(crate) static EKU_SERVER_AUTH: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 1]),
};

// id-kp-clientAuth   OBJECT IDENTIFIER ::= { id-kp 2 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub(crate) static EKU_CLIENT_AUTH: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 2]),
};

// id-kp-OCSPSigning  OBJECT IDENTIFIER ::= { id-kp 9 }
#[allow(clippy::identity_op)] // TODO: Make this clearer
pub(crate) static EKU_OCSP_SIGNING: KeyPurposeId = KeyPurposeId {
    oid_value: untrusted::Input::from(&[(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 9]),
};

// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// Notable Differences from RFC 5280:
//
// * We follow the convention established by Microsoft's implementation and
//   mozilla::pkix of treating the EKU extension in a CA certificate as a
//   restriction on the allowable EKUs for certificates issued by that CA. RFC
//   5280 doesn't prescribe any meaning to the EKU extension when a certificate
//   is being used as a CA certificate.
//
// * We do not recognize anyExtendedKeyUsage. NSS and mozilla::pkix do not
//   recognize it either.
//
// * We treat id-Netscape-stepUp as being equivalent to id-kp-serverAuth in CA
//   certificates (only). Comodo has issued certificates that require this
//   behavior that don't expire until June 2020. See https://bugzilla.mozilla.org/show_bug.cgi?id=982292.
fn check_eku(
    input: Option<&mut untrusted::Reader>,
    required_eku_if_present: KeyPurposeId,
) -> Result<(), Error> {
    match input {
        Some(input) => {
            loop {
                let value = der::expect_tag_and_get_value(input, der::Tag::OID)?;
                if value == required_eku_if_present.oid_value {
                    input.skip_to_end();
                    break;
                }
                if input.at_end() {
                    return Err(Error::RequiredEkuNotFound);
                }
            }
            Ok(())
        }
        None => {
            // http://tools.ietf.org/html/rfc6960#section-4.2.2.2:
            // "OCSP signing delegation SHALL be designated by the inclusion of
            // id-kp-OCSPSigning in an extended key usage certificate extension
            // included in the OCSP response signer's certificate."
            //
            // A missing EKU extension generally means "any EKU", but it is
            // important that id-kp-OCSPSigning is explicit so that a normal
            // end-entity certificate isn't able to sign trusted OCSP responses
            // for itself or for other certificates issued by its issuing CA.
            if required_eku_if_present.oid_value == EKU_OCSP_SIGNING.oid_value {
                return Err(Error::RequiredEkuNotFound);
            }

            Ok(())
        }
    }
}

fn loop_while_non_fatal_error<V>(
    values: V,
    mut f: impl FnMut(V::Item) -> Result<(), ControlFlow<Error, Error>>,
) -> Result<(), ControlFlow<Error, Error>>
where
    V: IntoIterator,
{
    for v in values {
        // If the error is not fatal, then keep going.
        match f(v) {
            Ok(()) => return Ok(()),
            // Fatal errors should halt further looping.
            res @ Err(ControlFlow::Break(_)) => return res,
            // Non-fatal errors should allow looping to continue.
            Err(ControlFlow::Continue(_)) => {}
        }
    }
    Err(Error::UnknownIssuer.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryFrom;

    #[cfg(feature = "alloc")]
    enum TrustAnchorIsActualIssuer {
        Yes,
        No,
    }

    #[cfg(feature = "alloc")]
    fn build_degenerate_chain(
        intermediate_count: usize,
        trust_anchor_is_actual_issuer: TrustAnchorIsActualIssuer,
        budget: Option<Budget>,
    ) -> ControlFlow<Error, Error> {
        let ca_cert = make_issuer("Bogus Subject", None);
        let ca_cert_der = ca_cert.serialize_der().unwrap();

        let mut intermediates = Vec::with_capacity(intermediate_count);
        let mut issuer = ca_cert;
        for _ in 0..intermediate_count {
            let intermediate = make_issuer("Bogus Subject", None);
            let intermediate_der = intermediate.serialize_der_with_signer(&issuer).unwrap();
            intermediates.push(intermediate_der);
            issuer = intermediate;
        }

        if let TrustAnchorIsActualIssuer::No = trust_anchor_is_actual_issuer {
            intermediates.pop();
        }

        verify_chain(
            &ca_cert_der,
            &intermediates,
            &make_end_entity(&issuer),
            budget,
        )
        .unwrap_err()
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_signatures() {
        assert!(matches!(
            build_degenerate_chain(5, TrustAnchorIsActualIssuer::Yes, None),
            ControlFlow::Break(Error::MaximumSignatureChecksExceeded)
        ));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_too_many_path_calls() {
        assert!(matches!(
            build_degenerate_chain(
                10,
                TrustAnchorIsActualIssuer::No,
                Some(Budget {
                    // Crafting a chain that will expend the build chain calls budget without
                    // first expending the signature checks budget is tricky, so we artificially
                    // inflate the signature limit to make this test easier to write.
                    signatures: usize::MAX,
                    ..Budget::default()
                })
            ),
            ControlFlow::Break(Error::MaximumPathBuildCallsExceeded)
        ));
    }

    #[cfg(feature = "alloc")]
    fn build_linear_chain(chain_length: usize) -> Result<(), ControlFlow<Error, Error>> {
        let ca_cert = make_issuer(format!("Bogus Subject {chain_length}"), None);
        let ca_cert_der = ca_cert.serialize_der().unwrap();

        let mut intermediates = Vec::with_capacity(chain_length);
        let mut issuer = ca_cert;
        for i in 0..chain_length {
            let intermediate = make_issuer(format!("Bogus Subject {i}"), None);
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
        // Note: webpki 0.101.x and earlier surface all non-fatal errors as UnknownIssuer,
        //       eating the more specific MaximumPathDepthExceeded error.
        assert!(matches!(
            build_linear_chain(7),
            Err(ControlFlow::Continue(Error::UnknownIssuer))
        ));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn name_constraint_budget() {
        // Issue a trust anchor that imposes name constraints. The constraint should match
        // the end entity certificate SAN.
        let ca_cert = make_issuer(
            "Constrained Root",
            Some(rcgen::NameConstraints {
                permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName(".com".into())],
                excluded_subtrees: vec![],
            }),
        );
        let ca_cert_der = ca_cert.serialize_der().unwrap();

        // Create a series of intermediate issuers. We'll only use one in the actual built path,
        // helping demonstrate that the name constraint budget is not expended checking certificates
        // that are not part of the path we compute.
        const NUM_INTERMEDIATES: usize = 5;
        let mut intermediates = Vec::with_capacity(NUM_INTERMEDIATES);
        for i in 0..NUM_INTERMEDIATES {
            intermediates.push(make_issuer(format!("Intermediate {i}"), None));
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
        trust_anchor_der: &[u8],
        intermediates_der: &[Vec<u8>],
        ee_cert_der: &[u8],
        budget: Option<Budget>,
    ) -> Result<(), ControlFlow<Error, Error>> {
        use crate::ECDSA_P256_SHA256;
        use crate::{EndEntityCert, Time};

        let anchors = &[TrustAnchor::try_from_cert_der(trust_anchor_der).unwrap()];
        let time = Time::from_seconds_since_unix_epoch(0x1fed_f00d);
        let cert = EndEntityCert::try_from(ee_cert_der).unwrap();
        let intermediates_der = intermediates_der
            .iter()
            .map(|x| x.as_ref())
            .collect::<Vec<_>>();

        build_chain_inner(
            EKU_SERVER_AUTH,
            &[&ECDSA_P256_SHA256],
            anchors,
            &intermediates_der,
            cert.inner(),
            time,
            0,
            &mut budget.unwrap_or_default(),
        )
    }

    #[cfg(feature = "alloc")]
    fn make_issuer(
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
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        ca_params.name_constraints = name_constraints;
        rcgen::Certificate::from_params(ca_params).unwrap()
    }

    #[cfg(feature = "alloc")]
    fn make_end_entity(issuer: &rcgen::Certificate) -> Vec<u8> {
        let mut ee_params = rcgen::CertificateParams::new(vec!["example.com".to_string()]);
        ee_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        ee_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        rcgen::Certificate::from_params(ee_params)
            .unwrap()
            .serialize_der_with_signer(issuer)
            .unwrap()
    }
}
