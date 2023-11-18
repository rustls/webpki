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
