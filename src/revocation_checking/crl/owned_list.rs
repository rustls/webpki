use super::*;

/// Owned representation of a RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[derive(Debug, Clone)]
pub struct OwnedCertRevocationList {
    /// A map of the revoked certificates contained in then CRL, keyed by the DER encoding
    /// of the revoked cert's serial number.
    pub(super) revoked_certs: BTreeMap<Vec<u8>, OwnedRevokedCert>,
    pub(super) issuer: Vec<u8>,
    pub(super) issuing_distribution_point: Option<Vec<u8>>,
    pub(super) signed_data: signed_data::OwnedSignedData,
}

impl OwnedCertRevocationList {
    /// Try to parse the given bytes as a RFC 5280[^1] profile Certificate Revocation List (CRL).
    ///
    /// Webpki does not support:
    ///   * CRL versions other than version 2.
    ///   * CRLs missing the next update field.
    ///   * CRLs missing certificate revocation list extensions.
    ///   * Delta CRLs.
    ///   * CRLs larger than (2^32)-1 bytes in size.
    ///
    /// See [BorrowedCertRevocationList::from_der] for more details.
    ///
    /// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
    pub fn from_der(crl_der: &[u8]) -> Result<Self, Error> {
        BorrowedCertRevocationList::from_der(crl_der)?.to_owned()
    }

    pub(super) fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert>, Error> {
        // note: this is infallible for the owned representation because we process all
        // revoked certificates at the time of construction to build the `revoked_certs` map,
        // returning any encountered errors at that time.
        Ok(self
            .revoked_certs
            .get(serial)
            .map(|owned_revoked_cert| owned_revoked_cert.borrow()))
    }
}
