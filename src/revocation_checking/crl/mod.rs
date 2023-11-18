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

impl<'a, T: AsRef<[&'a CertRevocationList<'a>]> + Debug> RevocationStrategy for T {
    fn can_check(&self) -> Result<AdequateStrategy, InadequateStrategy> {
        match self.as_ref().is_empty() {
            true => Err(InadequateStrategy("at least one crl is required")),
            false => Ok(AdequateStrategy(())),
        }
    }

    fn check_revoced(
        &self,
        revocation_parameters: &RevocationParameters,
        budget: &mut Budget,
    ) -> Result<Option<CertNotRevoked>, Error> {
        let RevocationParameters {
            depth,
            status_policy,
            path,
            issuer_spki,
            issuer_ku,
            supported_sig_algs,
        } = revocation_parameters;

        // If the policy only specifies checking EndEntity revocation state and we're looking at an
        // issuer certificate, return early without considering the certificate's revocation state.
        if let (RevocationCheckDepth::EndEntity, Role::Issuer) = (depth, path.role()) {
            return Ok(None);
        }

        let crl = self
            .as_ref()
            .iter()
            .find(|candidate_crl| candidate_crl.authoritative(path));

        use UnknownStatusPolicy::*;
        let crl = match (crl, status_policy) {
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
        crl.verify_signature(supported_sig_algs, *issuer_spki, budget)
            .map_err(crl_signature_err)?;

        // Verify that if the issuer has a KeyUsage bitstring it asserts cRLSign.
        KeyUsageMode::CrlSign.check(*issuer_ku)?;

        // Try to find the cert serial in the verified CRL contents.
        let cert_serial = path.cert.serial.as_slice_less_safe();
        match crl.find_serial(cert_serial)? {
            None => Ok(Some(CertNotRevoked(()))),
            Some(_) => Err(Error::CertRevoked),
        }
    }
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

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use pki_types::CertificateDer;

    use super::*;
    use crate::cert::Cert;
    use crate::end_entity::EndEntityCert;
    use crate::subject_name::GeneralName;
    use crate::verify_cert::PartialPath;
    use crate::x509::DistributionPointName;

    #[test]
    fn parse_issuing_distribution_point_ext() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.valid.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point
            .expect("missing crl distribution point DER");

        #[cfg(feature = "alloc")]
        {
            // We should also be able to find the distribution point extensions bytes from
            // an owned representation of the CRL.
            let owned_crl = crl.to_owned().unwrap();
            assert!(owned_crl.issuing_distribution_point.is_some());
        }

        let crl_issuing_dp = IssuingDistributionPoint::from_der(untrusted::Input::from(
            crl_issuing_dp.as_slice_less_safe(),
        ))
        .expect("failed to parse issuing distribution point DER");

        // We don't expect any of the bool fields to have been set true.
        assert!(!crl_issuing_dp.only_contains_user_certs);
        assert!(!crl_issuing_dp.only_contains_ca_certs);
        assert!(!crl_issuing_dp.indirect_crl);

        // Since the issuing distribution point doesn't specify the optional onlySomeReasons field,
        // we shouldn't find that it was parsed.
        assert!(crl_issuing_dp.only_some_reasons.is_none());

        // We should find the expected URI distribution point name.
        let dp_name = crl_issuing_dp
            .names()
            .expect("failed to parse distribution point names")
            .expect("missing distribution point name");
        let uri = match dp_name {
            DistributionPointName::NameRelativeToCrlIssuer(_) => {
                panic!("unexpected relative dp name")
            }
            DistributionPointName::FullName(general_names) => {
                general_names.map(|general_name| match general_name {
                    Ok(GeneralName::UniformResourceIdentifier(uri)) => uri.as_slice_less_safe(),
                    _ => panic!("unexpected general name type"),
                })
            }
        }
        .collect::<Vec<_>>();
        let expected = &["http://crl.trustcor.ca/sub/dv-ssl-rsa-s-0.crl".as_bytes()];
        assert_eq!(uri, expected);
    }

    #[test]
    fn test_issuing_distribution_point_only_user_certs() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.only_user_certs.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point
            .expect("missing crl distribution point DER");
        let crl_issuing_dp = IssuingDistributionPoint::from_der(crl_issuing_dp)
            .expect("failed to parse issuing distribution point DER");

        // We should find the expected bool state.
        assert!(crl_issuing_dp.only_contains_user_certs);

        // The IDP shouldn't be considered authoritative for a CA Cert.
        let ee = CertificateDer::from(
            &include_bytes!("../../../tests/client_auth_revocation/no_crl_ku_chain.ee.der")[..],
        );
        let ee = EndEntityCert::try_from(&ee).unwrap();
        let ca =
            include_bytes!("../../../tests/client_auth_revocation/no_crl_ku_chain.int.a.ca.der");
        let ca = Cert::from_der(untrusted::Input::from(&ca[..])).unwrap();

        let mut path = PartialPath::new(&ee);
        path.push(ca).unwrap();

        assert!(!crl_issuing_dp.authoritative_for(&path.node()));
    }

    #[test]
    fn test_issuing_distribution_point_only_ca_certs() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.only_ca_certs.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point
            .expect("missing crl distribution point DER");
        let crl_issuing_dp = IssuingDistributionPoint::from_der(crl_issuing_dp)
            .expect("failed to parse issuing distribution point DER");

        // We should find the expected bool state.
        assert!(crl_issuing_dp.only_contains_ca_certs);

        // The IDP shouldn't be considered authoritative for an EE Cert.
        let ee = CertificateDer::from(
            &include_bytes!("../../../tests/client_auth_revocation/no_crl_ku_chain.ee.der")[..],
        );
        let ee = EndEntityCert::try_from(&ee).unwrap();
        let path = PartialPath::new(&ee);

        assert!(!crl_issuing_dp.authoritative_for(&path.node()));
    }

    #[test]
    fn test_issuing_distribution_point_indirect() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.indirect_crl.der");
        // We should encounter an error parsing a CRL with an IDP extension that indicates it's an
        // indirect CRL.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::UnsupportedIndirectCrl)));
    }

    #[test]
    fn test_issuing_distribution_only_attribute_certs() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.only_attribute_certs.der");
        // We should find an error when we parse a CRL with an IDP extension that indicates it only
        // contains attribute certs.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::MalformedExtensions)));
    }

    #[test]
    fn test_issuing_distribution_only_some_reasons() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.only_some_reasons.der");
        // We should encounter an error parsing a CRL with an IDP extension that indicates it's
        // partitioned by revocation reason.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(
            result,
            Err(Error::UnsupportedRevocationReasonsPartitioning)
        ));
    }

    #[test]
    fn test_issuing_distribution_invalid_bool() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.invalid.bool.der.txt -o tests/crls/crl.idp.invalid.bool.der
        let crl = include_bytes!("../../../tests/crls/crl.idp.invalid.bool.der");
        // We should encounter an error parsing a CRL with an IDP extension with an invalid encoded boolean.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::BadDer)))
    }

    #[test]
    fn test_issuing_distribution_explicit_false_bool() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.explicit.false.bool.der.txt -o tests/crls/crl.idp.explicit.false.bool.der
        let crl = include_bytes!("../../../tests/crls/crl.idp.explicit.false.bool.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point
            .expect("missing crl distribution point DER");
        assert!(IssuingDistributionPoint::from_der(crl_issuing_dp).is_ok());
    }

    #[test]
    fn test_issuing_distribution_unknown_tag() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.unknown.tag.der.txt -o tests/crls/crl.idp.unknown.tag.der
        let crl = include_bytes!("../../../tests/crls/crl.idp.unknown.tag.der");
        // We should encounter an error parsing a CRL with an invalid IDP extension.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::BadDer)));
    }

    #[test]
    fn test_issuing_distribution_invalid_name() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.invalid.name.der.txt -o tests/crls/crl.idp.invalid.name.der
        let crl = include_bytes!("../../../tests/crls/crl.idp.invalid.name.der");

        // We should encounter an error parsing a CRL with an invalid issuing distribution point name.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::MalformedExtensions)))
    }

    #[test]
    fn test_issuing_distribution_relative_name() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.name_relative_to_issuer.der");
        // We should encounter an error parsing a CRL with an issuing distribution point extension
        // that has a distribution point name relative to an issuer.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(
            result,
            Err(Error::UnsupportedCrlIssuingDistributionPoint)
        ))
    }

    #[test]
    fn test_issuing_distribution_no_name() {
        let crl = include_bytes!("../../../tests/crls/crl.idp.no_distribution_point_name.der");
        // We should encounter an error parsing a CRL with an issuing distribution point extension
        // that has no distribution point name.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(
            result,
            Err(Error::UnsupportedCrlIssuingDistributionPoint)
        ))
    }

    #[test]
    fn revocation_reasons() {
        // Test that we can convert the allowed u8 revocation reason code values into the expected
        // revocation reason variant.
        let testcases: Vec<(u8, RevocationReason)> = vec![
            (0, RevocationReason::Unspecified),
            (1, RevocationReason::KeyCompromise),
            (2, RevocationReason::CaCompromise),
            (3, RevocationReason::AffiliationChanged),
            (4, RevocationReason::Superseded),
            (5, RevocationReason::CessationOfOperation),
            (6, RevocationReason::CertificateHold),
            // Note: 7 is unused.
            (8, RevocationReason::RemoveFromCrl),
            (9, RevocationReason::PrivilegeWithdrawn),
            (10, RevocationReason::AaCompromise),
        ];
        for tc in testcases.iter() {
            let (id, expected) = tc;
            let actual = <u8 as TryInto<RevocationReason>>::try_into(*id)
                .expect("unexpected reason code conversion error");
            assert_eq!(actual, *expected);
            #[cfg(feature = "alloc")]
            {
                // revocation reasons should be Debug.
                println!("{:?}", actual);
            }
        }

        // Unsupported/unknown revocation reason codes should produce an error.
        let res = <u8 as TryInto<RevocationReason>>::try_into(7);
        assert!(matches!(res, Err(Error::UnsupportedRevocationReason)));

        // The iterator should produce all possible revocation reason variants.
        let expected = testcases
            .iter()
            .map(|(_, reason)| *reason)
            .collect::<Vec<_>>();
        let actual = RevocationReason::iter().collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    // redundant clone, clone_on_copy allowed to verify derived traits.
    #[allow(clippy::redundant_clone, clippy::clone_on_copy)]
    fn test_derived_traits() {
        let crl = BorrowedCertRevocationList::from_der(include_bytes!(
            "../../../tests/crls/crl.valid.der"
        ))
        .unwrap();
        println!("{:?}", crl); // BorrowedCertRevocationList should be debug.

        let owned_crl = crl.to_owned().unwrap();
        println!("{:?}", owned_crl); // OwnedCertRevocationList should be debug.
        let _ = owned_crl.clone(); // OwnedCertRevocationList should be clone.

        let mut revoked_certs = crl.into_iter();
        println!("{:?}", revoked_certs); // RevokedCert should be debug.

        let revoked_cert = revoked_certs.next().unwrap().unwrap();
        println!("{:?}", revoked_cert); // BorrowedRevokedCert should be debug.

        let owned_revoked_cert = revoked_cert.to_owned();
        println!("{:?}", owned_revoked_cert); // OwnedRevokedCert should be debug.
        let _ = owned_revoked_cert.clone(); // OwnedRevokedCert should be clone.
    }

    #[test]
    fn test_enum_conversions() {
        let crl = include_bytes!(
            "../../../tests/client_auth_revocation/ee_revoked_crl_ku_ee_depth.crl.der"
        );
        let borrowed_crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();
        let owned_crl = borrowed_crl.to_owned().unwrap();

        // It should be possible to convert a BorrowedCertRevocationList to a CertRevocationList.
        let _crl: CertRevocationList = borrowed_crl.into();
        // And similar for an OwnedCertRevocationList.
        let _crl: CertRevocationList = owned_crl.into();
    }

    #[test]
    fn test_crl_authoritative_issuer_mismatch() {
        let crl = include_bytes!("../../../tests/crls/crl.valid.der");
        let crl: CertRevocationList = BorrowedCertRevocationList::from_der(&crl[..])
            .unwrap()
            .into();

        let ee = CertificateDer::from(
            &include_bytes!("../../../tests/client_auth_revocation/no_ku_chain.ee.der")[..],
        );
        let ee = EndEntityCert::try_from(&ee).unwrap();
        let path = PartialPath::new(&ee);

        // The CRL should not be authoritative for an EE issued by a different issuer.
        assert!(!crl.authoritative(&path.node()));
    }

    #[test]
    fn test_crl_authoritative_no_idp_no_cert_dp() {
        let crl = include_bytes!(
            "../../../tests/client_auth_revocation/ee_revoked_crl_ku_ee_depth.crl.der"
        );
        let crl: CertRevocationList = BorrowedCertRevocationList::from_der(&crl[..])
            .unwrap()
            .into();

        let ee = CertificateDer::from(
            &include_bytes!("../../../tests/client_auth_revocation/ku_chain.ee.der")[..],
        );
        let ee = EndEntityCert::try_from(&ee).unwrap();
        let path = PartialPath::new(&ee);

        // The CRL should be considered authoritative, the issuers match, the CRL has no IDP and the
        // cert has no CRL DPs.
        assert!(crl.authoritative(&path.node()));
    }

    #[test]
    fn test_construct_owned_crl() {
        // It should be possible to construct an owned CRL directly from DER without needing
        // to build a borrowed representation first.
        let crl = include_bytes!(
            "../../../tests/client_auth_revocation/ee_revoked_crl_ku_ee_depth.crl.der"
        );
        assert!(OwnedCertRevocationList::from_der(crl).is_ok())
    }

    #[test]
    fn dissallows_empty_crls_revocation_strategy() {
        // Trying to build a RevocationOptionsBuilder w/o CRLs should err.
        let empty_crl: &[&CertRevocationList] = &[];
        let result = RevocationOptionsBuilder::new(&empty_crl);
        assert!(matches!(result, Err(InadequateStrategy(_))));
    }
}
