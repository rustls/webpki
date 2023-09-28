// Copyright 2023 Daniel McCarney.
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

use pki_types::SignatureVerificationAlgorithm;

use crate::der;
use crate::error::Error;
use crate::verify_cert::{Budget, PathNode};

use core::fmt::Debug;

mod types;
use types::IssuingDistributionPoint;
pub use types::{
    BorrowedCertRevocationList, BorrowedRevokedCert, CertRevocationList, RevocationReason,
};
#[cfg(feature = "alloc")]
pub use types::{OwnedCertRevocationList, OwnedRevokedCert};

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
    pub(crate) crls: &'a [&'a dyn CertRevocationList],
    pub(crate) depth: RevocationCheckDepth,
    pub(crate) status_requirement: UnknownStatusPolicy,
}

impl<'a> RevocationOptions<'a> {
    pub(crate) fn check(
        &self,
        path: &PathNode<'_>,
        issuer_subject: untrusted::Input,
        issuer_spki: untrusted::Input,
        issuer_ku: Option<untrusted::Input>,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        budget: &mut Budget,
    ) -> Result<Option<CertNotRevoked>, Error> {
        assert_eq!(path.cert.issuer, issuer_subject);

        // If the policy only specifies checking EndEntity revocation state and we're looking at an
        // issuer certificate, return early without considering the certificate's revocation state.
        if let (RevocationCheckDepth::EndEntity, Some(_)) = (self.depth, &path.issued) {
            return Ok(None);
        }

        let crl = self
            .crls
            .iter()
            .find(|candidate_crl| crl_authoritative(**candidate_crl, path));

        use UnknownStatusPolicy::*;
        let crl = match (crl, self.status_requirement) {
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
        // Note: The `verify_signature` method is part of a public trait in the exported API.
        //       We can't add a budget argument to that fn in a semver compatible way and so must
        //       consume signature budget here before calling verify_signature.
        budget.consume_signature()?;
        crl.verify_signature(supported_sig_algs, issuer_spki.as_slice_less_safe())
            .map_err(crl_signature_err)?;

        // Verify that if the issuer has a KeyUsage bitstring it asserts cRLSign.
        KeyUsageMode::CrlSign.check(issuer_ku)?;

        // Try to find the cert serial in the verified CRL contents.
        let cert_serial = path.cert.serial.as_slice_less_safe();
        match crl.find_serial(cert_serial)? {
            None => Ok(Some(CertNotRevoked::assertion())),
            Some(_) => Err(Error::CertRevoked),
        }
    }
}

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
fn crl_authoritative(crl: &dyn CertRevocationList, path: &PathNode<'_>) -> bool {
    // In all cases we require that the authoritative CRL have the same issuer
    // as the certificate. Recall we do not support indirect CRLs.
    if crl.issuer() != path.cert.issuer() {
        return false;
    }

    let crl_idp = match (
        path.cert.crl_distribution_points(),
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

    crl_idp.authoritative_for(path)
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

// Zero-sized marker type representing positive assertion that revocation status was checked
// for a certificate and the result was that the certificate is not revoked.
pub(crate) struct CertNotRevoked(());

impl CertNotRevoked {
    // Construct a CertNotRevoked marker.
    fn assertion() -> Self {
        Self(())
    }
}

#[derive(Debug, Copy, Clone)]
/// An opaque error indicating the caller must provide at least one CRL when building a
/// [RevocationOptions] instance.
pub struct CrlsRequired(pub(crate) ());

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Cert;
    use crate::verify_cert::PathNode;

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
        let crl = include_bytes!("../../tests/crls/crl.valid.der");
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
        let crl = include_bytes!("../../tests/crls/crl.valid.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        let ee = include_bytes!("../../tests/client_auth_revocation/no_ku_chain.ee.der");
        let ee = Cert::from_der(untrusted::Input::from(&ee[..])).unwrap();

        // The CRL should not be authoritative for an EE issued by a different issuer.
        assert!(!crl_authoritative(
            &crl,
            &PathNode {
                cert: &ee,
                issued: None
            }
        ));
    }

    #[test]
    fn test_crl_authoritative_no_idp_no_cert_dp() {
        let crl =
            include_bytes!("../../tests/client_auth_revocation/ee_revoked_crl_ku_ee_depth.crl.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        let ee = include_bytes!("../../tests/client_auth_revocation/ku_chain.ee.der");
        let ee = Cert::from_der(untrusted::Input::from(&ee[..])).unwrap();

        // The CRL should be considered authoritative, the issuers match, the CRL has no IDP and the
        // cert has no CRL DPs.
        assert!(crl_authoritative(
            &crl,
            &PathNode {
                cert: &ee,
                issued: None
            }
        ));
    }
}
