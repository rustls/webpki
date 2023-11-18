use super::*;

/// A RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// May be either an owned, or a borrowed representation.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[derive(Debug)]
pub enum CertRevocationList<'a> {
    /// An owned representation of a CRL.
    #[cfg(feature = "alloc")]
    Owned(OwnedCertRevocationList),
    /// A borrowed representation of a CRL.
    Borrowed(BorrowedCertRevocationList<'a>),
}

#[cfg(feature = "alloc")]
impl From<OwnedCertRevocationList> for CertRevocationList<'_> {
    fn from(crl: OwnedCertRevocationList) -> Self {
        Self::Owned(crl)
    }
}

impl<'a> From<BorrowedCertRevocationList<'a>> for CertRevocationList<'a> {
    fn from(crl: BorrowedCertRevocationList<'a>) -> Self {
        Self::Borrowed(crl)
    }
}

impl<'a> CertRevocationList<'a> {
    /// Return the DER encoded issuer of the CRL.
    pub fn issuer(&self) -> &[u8] {
        match self {
            #[cfg(feature = "alloc")]
            CertRevocationList::Owned(crl) => crl.issuer.as_ref(),
            CertRevocationList::Borrowed(crl) => crl.issuer.as_slice_less_safe(),
        }
    }

    /// Return the DER encoded issuing distribution point of the CRL, if any.
    pub fn issuing_distribution_point(&self) -> Option<&[u8]> {
        match self {
            #[cfg(feature = "alloc")]
            CertRevocationList::Owned(crl) => crl.issuing_distribution_point.as_deref(),
            CertRevocationList::Borrowed(crl) => crl
                .issuing_distribution_point
                .map(|idp| idp.as_slice_less_safe()),
        }
    }

    /// Try to find a revoked certificate in the CRL by DER encoded serial number. This
    /// may yield an error if the CRL has malformed revoked certificates.
    pub fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert>, Error> {
        match self {
            #[cfg(feature = "alloc")]
            CertRevocationList::Owned(crl) => crl.find_serial(serial),
            CertRevocationList::Borrowed(crl) => crl.find_serial(serial),
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
    pub(crate) fn authoritative(&self, path: &PathNode<'_>) -> bool {
        // In all cases we require that the authoritative CRL have the same issuer
        // as the certificate. Recall we do not support indirect CRLs.
        if self.issuer() != path.cert.issuer() {
            return false;
        }

        let crl_idp = match (
            path.cert.crl_distribution_points(),
            self.issuing_distribution_point(),
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

    /// Verify the CRL signature using the issuer certificate and a list of supported signature
    /// verification algorithms, consuming signature operations from the [`Budget`].
    pub(crate) fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: untrusted::Input,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        signed_data::verify_signed_data(
            supported_sig_algs,
            issuer_spki,
            &match self {
                #[cfg(feature = "alloc")]
                CertRevocationList::Owned(crl) => crl.signed_data.borrow(),
                CertRevocationList::Borrowed(crl) => SignedData {
                    data: crl.signed_data.data,
                    algorithm: crl.signed_data.algorithm,
                    signature: crl.signed_data.signature,
                },
            },
            budget,
        )
        .map_err(crl_signature_err)
    }
}
