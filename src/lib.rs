//! webpki: Web PKI X.509 Certificate Validation.
//!
//! See `EndEntityCert`'s documentation for a description of the certificate
//! processing steps necessary for a TLS connection.
//!
//! # Features
//!
//! | Feature | Description |
//! | ------- | ----------- |
//! | `alloc` | Enable features that require use of the heap. Currently all RSA signature algorithms require this feature. |
//! | `std` | Enable features that require libstd. Implies `alloc`. |

#![no_std]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::use_self,
    clippy::std_instead_of_core
)]
#![deny(missing_docs, clippy::as_conversions)]
// Enable documentation for all features on docs.rs
#![cfg_attr(webpki_docsrs, feature(doc_cfg))]

#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(any(test, feature = "alloc"))]
#[cfg_attr(test, macro_use)]
extern crate alloc;

#[macro_use]
mod der;

#[cfg(test)]
mod aws_lc_rs_algs;
mod cert;
mod end_entity;
mod error;
#[cfg(test)]
mod ring_algs;
mod rpk_entity;
/// Processing of certificate transparency SCTs.
pub mod sct;
mod signed_data;
mod subject_name;
mod time;
mod trust_anchor;

mod crl;
mod verify_cert;
mod x509;

#[cfg(test)]
pub(crate) mod test_utils;

pub use cert::Cert;
pub use crl::{
    BorrowedCertRevocationList, BorrowedRevokedCert, CertRevocationList, CrlsRequired,
    ExpirationPolicy, RevocationCheckDepth, RevocationOptions, RevocationOptionsBuilder,
    RevocationReason, UnknownStatusPolicy,
};
#[cfg(feature = "alloc")]
pub use crl::{OwnedCertRevocationList, OwnedRevokedCert};
pub use der::DerIterator;
pub use end_entity::EndEntityCert;
pub use error::{
    DerTypeId, DnsNameError, Error, InvalidNameContext, UnsupportedSignatureAlgorithmContext,
    UnsupportedSignatureAlgorithmForPublicKeyContext,
};
pub use rpk_entity::RawPublicKeyEntity;
pub use trust_anchor::anchor_from_trusted_cert;
#[cfg(feature = "alloc")]
pub use trust_anchor::spki_for_anchor;
pub use verify_cert::{
    ExtendedKeyUsage, ExtendedKeyUsageValidator, IntermediateIterator, KeyPurposeId,
    KeyPurposeIdIter, PathBuilder, RequiredEkuNotFoundContext, VerifiedPath,
};

fn public_values_eq(a: untrusted::Input<'_>, b: untrusted::Input<'_>) -> bool {
    a.as_slice_less_safe() == b.as_slice_less_safe()
}
