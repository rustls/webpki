use crate::der::{CONSTRUCTED, CONTEXT_SPECIFIC};
use crate::subject_name::GeneralName;
use crate::x509::DistributionPointName;

use super::*;

pub(crate) struct IssuingDistributionPoint<'a> {
    distribution_point: Option<untrusted::Input<'a>>,
    pub(crate) only_contains_user_certs: bool,
    pub(crate) only_contains_ca_certs: bool,
    pub(crate) only_some_reasons: Option<der::BitStringFlags<'a>>,
    pub(crate) indirect_crl: bool,
    pub(crate) only_contains_attribute_certs: bool,
}

impl<'a> IssuingDistributionPoint<'a> {
    pub(crate) fn from_der(der: untrusted::Input<'a>) -> Result<IssuingDistributionPoint, Error> {
        const DISTRIBUTION_POINT_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED;
        const ONLY_CONTAINS_USER_CERTS_TAG: u8 = CONTEXT_SPECIFIC | 1;
        const ONLY_CONTAINS_CA_CERTS_TAG: u8 = CONTEXT_SPECIFIC | 2;
        const ONLY_CONTAINS_SOME_REASONS_TAG: u8 = CONTEXT_SPECIFIC | 3;
        const INDIRECT_CRL_TAG: u8 = CONTEXT_SPECIFIC | 4;
        const ONLY_CONTAINS_ATTRIBUTE_CERTS_TAG: u8 = CONTEXT_SPECIFIC | 5;

        let mut result = IssuingDistributionPoint {
            distribution_point: None,
            only_contains_user_certs: false,
            only_contains_ca_certs: false,
            only_some_reasons: None,
            indirect_crl: false,
            only_contains_attribute_certs: false,
        };

        // Note: we can't use der::optional_boolean here because the distribution point
        //       booleans are context specific primitives and der::optional_boolean expects
        //       to unwrap a Tag::Boolean constructed value.
        fn decode_bool(value: untrusted::Input) -> Result<bool, Error> {
            let mut reader = untrusted::Reader::new(value);
            let value = reader.read_byte().map_err(der::end_of_input_err)?;
            if !reader.at_end() {
                return Err(Error::BadDer);
            }
            match value {
                0xFF => Ok(true),
                0x00 => Ok(false), // non-conformant explicit encoding allowed for compat.
                _ => Err(Error::BadDer),
            }
        }

        // RFC 5280 section §4.2.1.13:
        der::nested(
            &mut untrusted::Reader::new(der),
            Tag::Sequence,
            Error::TrailingData(DerTypeId::IssuingDistributionPoint),
            |der| {
                while !der.at_end() {
                    let (tag, value) = der::read_tag_and_get_value(der)?;
                    match tag {
                        DISTRIBUTION_POINT_TAG => {
                            set_extension_once(&mut result.distribution_point, || Ok(value))?
                        }
                        ONLY_CONTAINS_USER_CERTS_TAG => {
                            result.only_contains_user_certs = decode_bool(value)?
                        }
                        ONLY_CONTAINS_CA_CERTS_TAG => {
                            result.only_contains_ca_certs = decode_bool(value)?
                        }
                        ONLY_CONTAINS_SOME_REASONS_TAG => {
                            set_extension_once(&mut result.only_some_reasons, || {
                                der::bit_string_flags(value)
                            })?
                        }
                        INDIRECT_CRL_TAG => result.indirect_crl = decode_bool(value)?,
                        ONLY_CONTAINS_ATTRIBUTE_CERTS_TAG => {
                            result.only_contains_attribute_certs = decode_bool(value)?
                        }
                        _ => return Err(Error::BadDer),
                    }
                }

                Ok(())
            },
        )?;

        // RFC 5280 4.2.1.10:
        //   Conforming CRLs issuers MUST set the onlyContainsAttributeCerts boolean to FALSE.
        if result.only_contains_attribute_certs {
            return Err(Error::MalformedExtensions);
        }

        // We don't support indirect CRLs.
        if result.indirect_crl {
            return Err(Error::UnsupportedIndirectCrl);
        }

        // We don't support CRLs partitioned by revocation reason.
        if result.only_some_reasons.is_some() {
            return Err(Error::UnsupportedRevocationReasonsPartitioning);
        }

        // We require a distribution point, and it must be a full name.
        use DistributionPointName::*;
        match result.names() {
            Ok(Some(FullName(_))) => Ok(result),
            Ok(Some(NameRelativeToCrlIssuer(_))) | Ok(None) => {
                Err(Error::UnsupportedCrlIssuingDistributionPoint)
            }
            Err(_) => Err(Error::MalformedExtensions),
        }
    }

    /// Return the distribution point names (if any).
    pub(crate) fn names(&self) -> Result<Option<DistributionPointName<'a>>, Error> {
        self.distribution_point
            .map(|input| DistributionPointName::from_der(&mut untrusted::Reader::new(input)))
            .transpose()
    }

    /// Returns true if the CRL can be considered authoritative for the given certificate. We make
    /// this determination using the certificate and CRL issuers, and the distribution point names
    /// that may be present in extensions found on both.
    ///
    /// We consider the CRL authoritative for the certificate if the CRL issuing distribution point
    /// has a scope that could include the cert and if the cert has CRL distribution points, that
    /// at least one CRL DP has a valid distribution point full name where one of the general names
    /// is a Uniform Resource Identifier (URI) general name that can also be found in the CRL
    /// issuing distribution point.
    ///
    /// We do not consider:
    /// * Distribution point names relative to an issuer.
    /// * General names of a type other than URI.
    /// * Malformed names or invalid IDP or CRL DP extensions.
    pub(crate) fn authoritative_for(&self, node: &PathNode<'a>) -> bool {
        assert!(!self.only_contains_attribute_certs); // We check this at time of parse.

        // Check that the scope of the CRL issuing distribution point could include the cert.
        if self.only_contains_ca_certs && node.role() != Role::Issuer
            || self.only_contains_user_certs && node.role() != Role::EndEntity
        {
            return false;
        }

        let cert_dps = match node.cert.crl_distribution_points() {
            // If the certificate has no distribution points, then the CRL can be authoritative
            // based on the issuer matching and the scope including the cert.
            None => return true,
            Some(cert_dps) => cert_dps,
        };

        let mut idp_general_names = match self.names() {
            Ok(Some(DistributionPointName::FullName(general_names))) => general_names,
            _ => return false, // Note: Either no full names, or malformed. Shouldn't occur, we check at CRL parse time.
        };

        for cert_dp in cert_dps {
            let cert_dp = match cert_dp {
                Ok(cert_dp) => cert_dp,
                // certificate CRL DP was invalid, can't match.
                Err(_) => return false,
            };

            // If the certificate CRL DP was for an indirect CRL, or a CRL
            // sharded by revocation reason, it can't match.
            if cert_dp.crl_issuer.is_some() || cert_dp.reasons.is_some() {
                return false;
            }

            let mut dp_general_names = match cert_dp.names() {
                Ok(Some(DistributionPointName::FullName(general_names))) => general_names,
                _ => return false, // Either no full names, or malformed.
            };

            // At least one URI type name in the IDP full names must match a URI type name in the
            // DP full names.
            if Self::uri_name_in_common(&mut idp_general_names, &mut dp_general_names) {
                return true;
            }
        }

        false
    }

    fn uri_name_in_common(
        idp_general_names: &mut DerIterator<'a, GeneralName<'a>>,
        dp_general_names: &mut DerIterator<'a, GeneralName<'a>>,
    ) -> bool {
        use GeneralName::UniformResourceIdentifier;
        for name in idp_general_names.flatten() {
            let uri = match name {
                UniformResourceIdentifier(uri) => uri,
                _ => continue,
            };

            for other_name in (&mut *dp_general_names).flatten() {
                match other_name {
                    UniformResourceIdentifier(other_uri)
                        if uri.as_slice_less_safe() == other_uri.as_slice_less_safe() =>
                    {
                        return true
                    }
                    _ => continue,
                }
            }
        }
        false
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use pki_types::CertificateDer;

    use crate::cert::Cert;
    use crate::end_entity::EndEntityCert;
    use crate::subject_name::GeneralName;
    use crate::verify_cert::PartialPath;
    use crate::x509::DistributionPointName;

    use super::*;

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
}
