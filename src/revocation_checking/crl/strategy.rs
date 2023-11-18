use crate::revocation_checking::*;

impl<'a, T: AsRef<[&'a CertRevocationList<'a>]> + Debug> RevocationStrategy for T {
    fn verify_adequacy(&self) -> Result<AdequateStrategy, InadequateStrategy> {
        match self.as_ref().is_empty() {
            true => Err(InadequateStrategy("at least one crl is required")),
            false => Ok(AdequateStrategy(())),
        }
    }

    fn check_revoced(
        &self,
        revocation_parameters: &RevocationParameters,
        budget: &mut Budget,
    ) -> Result<RevocationStatus, Error> {
        let RevocationParameters {
            status_policy,
            path,
            issuer_spki,
            issuer_ku,
            supported_sig_algs,
        } = revocation_parameters;

        let crl = self
            .as_ref()
            .iter()
            .find(|candidate_crl| candidate_crl.authoritative(path));

        use UnknownStatusPolicy::*;
        let crl = match (crl, status_policy) {
            (Some(crl), _) => crl,
            // If the policy allows unknown, return Ok(None) to indicate that the certificate
            // was not confirmed as CertNotRevoked, but that this isn't an error condition.
            (None, Allow) => return Ok(RevocationStatus::Skipped(())),
            // Otherwise, this is an error condition based on the provided policy.
            (None, _) => return Err(Error::UnknownRevocationStatus),
        };

        // Verify the CRL signature with the issuer SPKI.
        // TODO(XXX): consider whether we can refactor so this happens once up-front, instead
        //            of per-lookup.
        //            https://github.com/rustls/webpki/issues/81
        crl.verify_signature(supported_sig_algs, *issuer_spki, budget)
            .map_err(crl_signature_err)?;

        // Verify that if the issuer has a KeyUsage bitstring it asserts cRLSign.
        KeyUsageMode::CrlSign.check(*issuer_ku)?;

        // Try to find the cert serial in the verified CRL contents.
        let cert_serial = path.cert.serial.as_slice_less_safe();
        return match crl.find_serial(cert_serial)? {
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
