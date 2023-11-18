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

use crate::error::Error;
use crate::verify_cert::{Budget, PathNode, Role};
use crate::{der, public_values_eq};

use core::fmt::Debug;

mod crl;
pub use crl::{
    BorrowedCertRevocationList, BorrowedRevokedCert, CertRevocationList, RevocationReason,
};
#[cfg(feature = "alloc")]
pub use crl::{OwnedCertRevocationList, OwnedRevokedCert};

pub struct RevocationParameters<'a> {
    status_policy: &'a UnknownStatusPolicy,
    path: &'a PathNode<'a>,
    issuer_spki: untrusted::Input<'a>,
    issuer_ku: Option<untrusted::Input<'a>>,
    supported_sig_algs: &'a [&'a dyn SignatureVerificationAlgorithm],
}

pub trait RevocationStrategy: Debug {
    fn verify_adequacy(&self) -> Result<AdequateStrategy, InadequateStrategy>;
    fn check_revoced(
        &self,
        revocation_parameters: &RevocationParameters,
        budget: &mut Budget,
    ) -> Result<RevocationStatus, Error>;
}

/// Builds a RevocationOptions instance to control how revocation checking is performed.
#[derive(Debug, Copy, Clone)]
pub struct RevocationOptionsBuilder<'a> {
    strategy: &'a dyn RevocationStrategy,

    depth: RevocationCheckDepth,

    status_policy: UnknownStatusPolicy,
}

impl<'a> RevocationOptionsBuilder<'a> {
    /// Create a builder that will perform revocation checking using the provided stategy.
    ///
    /// The constructor checks whether or not the provided strategy is adequate for revocation checking.
    /// E.g. making sure that a passed slice of CRLs is not empty.
    ///
    /// Use [RevocationOptionsBuilder::build] to create a [RevocationOptions] instance.
    ///
    /// By default revocation checking will be performed on both the end-entity (leaf) certificate
    /// and intermediate certificates. This can be customized using the
    /// [RevocationOptionsBuilder::with_depth] method.
    ///
    /// By default revocation checking will fail if the revocation status of a certificate cannot
    /// be determined. This can be customized using the
    /// [RevocationOptionsBuilder::with_status_policy] method.
    pub fn new(strategy: &'a impl RevocationStrategy) -> Result<Self, InadequateStrategy> {
        strategy.verify_adequacy()?;

        Ok(Self {
            strategy,
            depth: RevocationCheckDepth::Chain,
            status_policy: UnknownStatusPolicy::Deny,
        })
    }

    /// Customize the depth at which revocation checking will be performed, controlling
    /// whether only the end-entity (leaf) certificate in the chain to a trust anchor will
    /// have its revocation status checked, or whether the intermediate certificates will as well.
    pub fn with_depth(mut self, depth: RevocationCheckDepth) -> Self {
        self.depth = depth;
        self
    }

    /// Customize whether unknown revocation status is an error, or permitted.
    pub fn with_status_policy(mut self, policy: UnknownStatusPolicy) -> Self {
        self.status_policy = policy;
        self
    }

    /// Construct a [RevocationOptions] instance based on the builder's configuration.
    pub fn build(self) -> RevocationOptions<'a> {
        RevocationOptions {
            strategy: self.strategy,
            check_depth: self.depth,
            status_policy: self.status_policy,
        }
    }
}

/// Describes how revocation checking is performed, if at all. Can be constructed with a
/// [RevocationOptionsBuilder] instance.
#[derive(Debug, Copy, Clone)]
pub struct RevocationOptions<'a> {
    pub(crate) strategy: &'a dyn RevocationStrategy,
    pub(crate) check_depth: RevocationCheckDepth,
    pub(crate) status_policy: UnknownStatusPolicy,
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
    ) -> Result<RevocationStatus, Error> {
        assert!(public_values_eq(path.cert.issuer, issuer_subject));

        let revocation_parameters = RevocationParameters {
            status_policy: &self.status_policy,
            path,
            issuer_spki,
            issuer_ku,
            supported_sig_algs,
        };

        // If the policy only specifies checking EndEntity revocation state and we're looking at an
        // issuer certificate, return early without considering the certificate's revocation state.
        if let (RevocationCheckDepth::EndEntity, Role::Issuer) = (self.check_depth, path.role()) {
            return Ok(RevocationStatus::Skipped(()));
        }

        self.strategy.check_revoced(&revocation_parameters, budget)
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

/*
    Ok markers
*/

pub enum RevocationStatus {
    Skipped(()),
    NotRevoked(()),
}

pub struct AdequateStrategy(());

/*
    Error markers
*/

#[derive(Debug, Clone)]
pub struct InadequateStrategy(&'static str);

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct MockRevocationStrategy {
        inadequate_strategy: bool,
    }

    impl RevocationStrategy for MockRevocationStrategy {
        fn verify_adequacy(&self) -> Result<AdequateStrategy, InadequateStrategy> {
            match self.inadequate_strategy {
                true => Err(InadequateStrategy("")),
                false => Ok(AdequateStrategy(())),
            }
        }

        fn check_revoced(
            &self,
            _revocation_parameters: &RevocationParameters,
            _budget: &mut Budget,
        ) -> Result<RevocationStatus, Error> {
            Ok(RevocationStatus::NotRevoked(()))
        }
    }

    #[test]
    // redundant clone, clone_on_copy allowed to verify derived traits.
    #[allow(clippy::redundant_clone, clippy::clone_on_copy)]
    fn test_revocation_opts_builder() {
        // Failed check should error initialization.
        let result = RevocationOptionsBuilder::new(&MockRevocationStrategy {
            inadequate_strategy: true,
        });
        assert!(matches!(result, Err(InadequateStrategy(_))));

        // The InadequateStrategy error should be debug and clone when alloc is enabled.
        #[cfg(feature = "alloc")]
        {
            let err = result.unwrap_err();
            println!("{:?}", err.clone());
        }

        let mock_strategy = MockRevocationStrategy::default();

        // It should be possible to build a revocation options builder with defaults.
        let builder = RevocationOptionsBuilder::new(&mock_strategy).unwrap();
        #[cfg(feature = "alloc")]
        {
            // The builder should be debug, and clone when alloc is enabled.
            println!("{:?}", builder);
            _ = builder.clone();
        }
        let opts = builder.build();
        assert_eq!(opts.check_depth, RevocationCheckDepth::Chain);
        assert_eq!(opts.status_policy, UnknownStatusPolicy::Deny);

        // It should be possible to build a revocation options builder with custom depth.
        let opts = RevocationOptionsBuilder::new(&mock_strategy)
            .unwrap()
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        assert_eq!(opts.check_depth, RevocationCheckDepth::EndEntity);
        assert_eq!(opts.status_policy, UnknownStatusPolicy::Deny);

        // It should be possible to build a revocation options builder that allows unknown
        // revocation status.
        let opts = RevocationOptionsBuilder::new(&mock_strategy)
            .unwrap()
            .with_status_policy(UnknownStatusPolicy::Allow)
            .build();
        assert_eq!(opts.check_depth, RevocationCheckDepth::Chain);
        assert_eq!(opts.status_policy, UnknownStatusPolicy::Allow);

        // It should be possible to specify both depth and unknown status policy together.
        let opts = RevocationOptionsBuilder::new(&mock_strategy)
            .unwrap()
            .with_status_policy(UnknownStatusPolicy::Allow)
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        assert_eq!(opts.check_depth, RevocationCheckDepth::EndEntity);
        assert_eq!(opts.status_policy, UnknownStatusPolicy::Allow);

        // The same should be true for explicitly forbidding unknown status.
        let opts = RevocationOptionsBuilder::new(&mock_strategy)
            .unwrap()
            .with_status_policy(UnknownStatusPolicy::Deny)
            .with_depth(RevocationCheckDepth::EndEntity)
            .build();
        assert_eq!(opts.check_depth, RevocationCheckDepth::EndEntity);
        assert_eq!(opts.status_policy, UnknownStatusPolicy::Deny);

        // Built revocation options should be debug and clone when alloc is enabled.
        #[cfg(feature = "alloc")]
        {
            println!("{:?}", opts.clone());
        }
    }
}
