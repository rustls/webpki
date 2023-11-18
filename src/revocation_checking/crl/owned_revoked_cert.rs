use super::*;

/// Owned representation of a RFC 5280[^1] profile Certificate Revocation List (CRL) revoked
/// certificate entry.
///
/// Only available when the "alloc" feature is enabled.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct OwnedRevokedCert {
    /// Serial number of the revoked certificate.
    pub serial_number: Vec<u8>,

    /// The date at which the CA processed the revocation.
    pub revocation_date: UnixTime,

    /// Identifies the reason for the certificate revocation. When absent, the revocation reason
    /// is assumed to be RevocationReason::Unspecified. For consistency with other extensions
    /// and to ensure only one revocation reason extension may be present we maintain this field
    /// as optional instead of defaulting to unspecified.
    pub reason_code: Option<RevocationReason>,

    /// Provides the date on which it is known or suspected that the private key was compromised or
    /// that the certificate otherwise became invalid. This date may be earlier than the revocation
    /// date which is the date at which the CA processed the revocation.
    pub invalidity_date: Option<UnixTime>,
}

#[cfg(feature = "alloc")]
impl OwnedRevokedCert {
    /// Convert the owned representation of this revoked cert to a borrowed version.
    pub fn borrow(&self) -> BorrowedRevokedCert {
        BorrowedRevokedCert {
            serial_number: &self.serial_number,
            revocation_date: self.revocation_date,
            reason_code: self.reason_code,
            invalidity_date: self.invalidity_date,
        }
    }
}
