use crate::revocation_checking::*;

impl<'a> RevocationVerifier for &'a CertRevocationList<'a> {
    fn verify(
        &self,
        revocation_parameters: &RevocationParameters,
        budget: &mut Budget,
    ) -> Result<RevocationStatus, Error> {
        let RevocationParameters {
            path,
            issuer_spki,
            issuer_ku,
            supported_sig_algs,
        } = revocation_parameters;

        // Verify the CRL signature with the issuer SPKI.
        // TODO(XXX): consider whether we can refactor so this happens once up-front, instead
        //            of per-lookup.
        //            https://github.com/rustls/webpki/issues/81
        self.verify_signature(supported_sig_algs, *issuer_spki, budget)
            .map_err(crl_signature_err)?;

        // Verify that if the issuer has a KeyUsage bitstring it asserts cRLSign.
        KeyUsageMode::CrlSign.check(*issuer_ku)?;

        // Try to find the cert serial in the verified CRL contents.
        let cert_serial = path.cert.serial.as_slice_less_safe();
        return match self.find_serial(cert_serial)? {
            None => Ok(RevocationStatus::NotRevoked(())),
            Some(_) => Err(Error::CertRevoked),
        };

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
    }
}

impl<'a> RevocationStrategy for &'a [&'a CertRevocationList<'a>] {
    fn verify_adequacy(&self) -> Result<AdequateStrategy, InadequateStrategy> {
        match self.is_empty() {
            true => Err(InadequateStrategy("at least one crl is required")),
            false => Ok(AdequateStrategy(())),
        }
    }

    fn find_verifier(
        &self,
        revocation_parameters: &RevocationParameters,
    ) -> Result<Option<&dyn RevocationVerifier>, Error> {
        #[allow(clippy::as_conversions)]
        Ok(self
            .iter()
            .find(|candidate_crl| candidate_crl.authoritative(revocation_parameters.path))
            .map(|crl| crl as &dyn RevocationVerifier))
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dissallows_empty_crls_revocation_strategy() {
        // Trying to build a RevocationOptionsBuilder w/o CRLs should err.
        let empty_crl: &[&CertRevocationList] = &[];
        let result = RevocationOptionsBuilder::new(&empty_crl);
        assert!(matches!(result, Err(InadequateStrategy(_))));
    }
}
