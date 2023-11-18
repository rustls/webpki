mod strategy;

mod cert_list;
pub use cert_list::CertRevocationList;

#[cfg(feature = "alloc")]
mod owned_list;
#[cfg(feature = "alloc")]
pub use owned_list::OwnedCertRevocationList;

mod borrowed_list;
pub use borrowed_list::BorrowedCertRevocationList;

mod issuing_distribution_point;
pub(crate) use issuing_distribution_point::IssuingDistributionPoint;

mod owned_revoked_cert;
pub use owned_revoked_cert::OwnedRevokedCert;

mod borrowed_revoked_cert;
pub use borrowed_revoked_cert::BorrowedRevokedCert;

mod revocation_reason;
pub use revocation_reason::RevocationReason;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::{SignatureVerificationAlgorithm, UnixTime};

use crate::der::{self, DerIterator, FromDer, Tag};
use crate::error::{DerTypeId, Error};
use crate::signed_data::{self, SignedData};
use crate::verify_cert::{Budget, PathNode, Role};
use crate::x509::{remember_extension, set_extension_once, Extension};
