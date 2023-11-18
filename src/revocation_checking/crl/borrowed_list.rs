use crate::public_values_eq;

use super::*;

/// Borrowed representation of a RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[derive(Debug)]
pub struct BorrowedCertRevocationList<'a> {
    /// A `SignedData` structure that can be passed to `verify_signed_data`.
    pub(super) signed_data: SignedData<'a>,
    /// Identifies the entity that has signed and issued this
    /// CRL.
    pub(super) issuer: untrusted::Input<'a>,
    /// An optional CRL extension that identifies the CRL distribution point and scope for the CRL.
    pub(super) issuing_distribution_point: Option<untrusted::Input<'a>>,
    /// List of certificates revoked by the issuer in this CRL.
    pub(super) revoked_certs: untrusted::Input<'a>,
}

impl<'a> BorrowedCertRevocationList<'a> {
    /// Try to parse the given bytes as a RFC 5280[^1] profile Certificate Revocation List (CRL).
    ///
    /// Webpki does not support:
    ///   * CRL versions other than version 2.
    ///   * CRLs missing the next update field.
    ///   * CRLs missing certificate revocation list extensions.
    ///   * Delta CRLs.
    ///   * CRLs larger than (2^32)-1 bytes in size.
    ///
    /// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
    pub fn from_der(crl_der: &'a [u8]) -> Result<Self, Error> {
        der::read_all(untrusted::Input::from(crl_der))
    }

    /// Convert the CRL to an [`OwnedCertRevocationList`]. This may error if any of the revoked
    /// certificates in the CRL are malformed or contain unsupported features.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> Result<OwnedCertRevocationList, Error> {
        // Parse and collect the CRL's revoked cert entries, ensuring there are no errors. With
        // the full set in-hand, create a lookup map by serial number for fast revocation checking.
        let revoked_certs = self
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .map(|revoked_cert| (revoked_cert.serial_number.to_vec(), revoked_cert.to_owned()))
            .collect::<BTreeMap<_, _>>();

        Ok(OwnedCertRevocationList {
            signed_data: self.signed_data.to_owned(),
            issuer: self.issuer.as_slice_less_safe().to_vec(),
            issuing_distribution_point: self
                .issuing_distribution_point
                .map(|idp| idp.as_slice_less_safe().to_vec()),
            revoked_certs,
        })
    }

    fn remember_extension(&mut self, extension: &Extension<'a>) -> Result<(), Error> {
        remember_extension(extension, |id| {
            match id {
                // id-ce-cRLNumber 2.5.29.20 - RFC 5280 §5.2.3
                20 => {
                    // RFC 5280 §5.2.3:
                    //   CRL verifiers MUST be able to handle CRLNumber values
                    //   up to 20 octets.  Conforming CRL issuers MUST NOT use CRLNumber
                    //   values longer than 20 octets.
                    //
                    extension.value.read_all(Error::InvalidCrlNumber, |der| {
                        let crl_number = der::nonnegative_integer(der)
                            .map_err(|_| Error::InvalidCrlNumber)?
                            .as_slice_less_safe();
                        if crl_number.len() <= 20 {
                            Ok(crl_number)
                        } else {
                            Err(Error::InvalidCrlNumber)
                        }
                    })?;
                    // We enforce the cRLNumber is sensible, but don't retain the value for use.
                    Ok(())
                }

                // id-ce-deltaCRLIndicator 2.5.29.27 - RFC 5280 §5.2.4
                // We explicitly do not support delta CRLs.
                27 => Err(Error::UnsupportedDeltaCrl),

                // id-ce-issuingDistributionPoint 2.5.29.28 - RFC 5280 §5.2.4
                // We recognize the extension and retain its value for use.
                28 => {
                    set_extension_once(&mut self.issuing_distribution_point, || Ok(extension.value))
                }

                // id-ce-authorityKeyIdentifier 2.5.29.35 - RFC 5280 §5.2.1, §4.2.1.1
                // We recognize the extension but don't retain its value for use.
                35 => Ok(()),

                // Unsupported extension
                _ => extension.unsupported(),
            }
        })
    }

    pub(super) fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert>, Error> {
        for revoked_cert_result in self {
            match revoked_cert_result {
                Err(e) => return Err(e),
                Ok(revoked_cert) => {
                    if revoked_cert.serial_number.eq(serial) {
                        return Ok(Some(revoked_cert));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl<'a> FromDer<'a> for BorrowedCertRevocationList<'a> {
    /// Try to parse the given bytes as a RFC 5280[^1] profile Certificate Revocation List (CRL).
    ///
    /// Webpki does not support:
    ///   * CRL versions other than version 2.
    ///   * CRLs missing the next update field.
    ///   * CRLs missing certificate revocation list extensions.
    ///   * Delta CRLs.
    ///   * CRLs larger than (2^32)-1 bytes in size.
    ///
    /// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let (tbs_cert_list, signed_data) = der::nested_limited(
            reader,
            Tag::Sequence,
            Error::TrailingData(Self::TYPE_ID),
            |signed_der| SignedData::from_der(signed_der, der::MAX_DER_SIZE),
            der::MAX_DER_SIZE,
        )?;

        let crl = tbs_cert_list.read_all(Error::BadDer, |tbs_cert_list| {
            // RFC 5280 §5.1.2.1:
            //   This optional field describes the version of the encoded CRL.  When
            //   extensions are used, as required by this profile, this field MUST be
            //   present and MUST specify version 2 (the integer value is 1).
            // RFC 5280 §5.2:
            //   Conforming CRL issuers are REQUIRED to include the authority key
            //   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
            //   extensions in all CRLs issued.
            // As a result of the above we parse this as a required section, not OPTIONAL.
            // NOTE: Encoded value of version 2 is 1.
            if u8::from_der(tbs_cert_list)? != 1 {
                return Err(Error::UnsupportedCrlVersion);
            }

            // RFC 5280 §5.1.2.2:
            //   This field MUST contain the same algorithm identifier as the
            //   signatureAlgorithm field in the sequence CertificateList
            let signature = der::expect_tag(tbs_cert_list, Tag::Sequence)?;
            if !public_values_eq(signature, signed_data.algorithm) {
                return Err(Error::SignatureAlgorithmMismatch);
            }

            // RFC 5280 §5.1.2.3:
            //   The issuer field MUST contain a non-empty X.500 distinguished name (DN).
            let issuer = der::expect_tag(tbs_cert_list, Tag::Sequence)?;

            // RFC 5280 §5.1.2.4:
            //    This field indicates the issue date of this CRL.  thisUpdate may be
            //    encoded as UTCTime or GeneralizedTime.
            // We do not presently enforce the correct choice of UTCTime or GeneralizedTime based on
            // whether the date is post 2050.
            UnixTime::from_der(tbs_cert_list)?;

            // While OPTIONAL in the ASN.1 module, RFC 5280 §5.1.2.5 says:
            //   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
            // We do not presently enforce the correct choice of UTCTime or GeneralizedTime based on
            // whether the date is post 2050.
            UnixTime::from_der(tbs_cert_list)?;

            // RFC 5280 §5.1.2.6:
            //   When there are no revoked certificates, the revoked certificates list
            //   MUST be absent
            // TODO(@cpu): Do we care to support empty CRLs if we don't support delta CRLs?
            let revoked_certs = if tbs_cert_list.peek(Tag::Sequence.into()) {
                der::expect_tag_and_get_value_limited(
                    tbs_cert_list,
                    Tag::Sequence,
                    der::MAX_DER_SIZE,
                )?
            } else {
                untrusted::Input::from(&[])
            };

            let mut crl = BorrowedCertRevocationList {
                signed_data,
                issuer,
                revoked_certs,
                issuing_distribution_point: None,
            };

            // RFC 5280 §5.1.2.7:
            //   This field may only appear if the version is 2 (Section 5.1.2.1).  If
            //   present, this field is a sequence of one or more CRL extensions.
            // RFC 5280 §5.2:
            //   Conforming CRL issuers are REQUIRED to include the authority key
            //   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
            //   extensions in all CRLs issued.
            // As a result of the above we parse this as a required section, not OPTIONAL.
            der::nested(
                tbs_cert_list,
                Tag::ContextSpecificConstructed0,
                Error::MalformedExtensions,
                |tagged| {
                    der::nested_of_mut(
                        tagged,
                        Tag::Sequence,
                        Tag::Sequence,
                        Error::TrailingData(DerTypeId::CertRevocationListExtension),
                        |extension| {
                            // RFC 5280 §5.2:
                            //   If a CRL contains a critical extension
                            //   that the application cannot process, then the application MUST NOT
                            //   use that CRL to determine the status of certificates.  However,
                            //   applications may ignore unrecognized non-critical extensions.
                            crl.remember_extension(&Extension::from_der(extension)?)
                        },
                    )
                },
            )?;

            Ok(crl)
        })?;

        // If an issuing distribution point extension is present, parse it up-front to validate
        // that it only uses well-formed and supported features.
        if let Some(der) = crl.issuing_distribution_point {
            IssuingDistributionPoint::from_der(der)?;
        }

        Ok(crl)
    }

    const TYPE_ID: DerTypeId = DerTypeId::CertRevocationList;
}

impl<'a> IntoIterator for &'a BorrowedCertRevocationList<'a> {
    type Item = Result<BorrowedRevokedCert<'a>, Error>;
    type IntoIter = DerIterator<'a, BorrowedRevokedCert<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        DerIterator::new(self.revoked_certs)
    }
}
