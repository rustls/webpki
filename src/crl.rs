// Copyright 2023 Daniel McCarney.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::cert::lenient_certificate_serial_number;
use crate::der::{self, DerIterator, FromDer, Tag, CONSTRUCTED, CONTEXT_SPECIFIC};
use crate::error::{DerTypeId, Error};
use crate::signed_data::{self, SignedData};
use crate::x509::{remember_extension, set_extension_once, DistributionPointName, Extension};
use crate::{SignatureVerificationAlgorithm, Time};
use core::fmt::Debug;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use private::Sealed;

/// Operations over a RFC 5280[^1] profile Certificate Revocation List (CRL) required
/// for revocation checking. Implemented by [`OwnedCertRevocationList`] and
/// [`BorrowedCertRevocationList`].
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
pub trait CertRevocationList: Sealed + Debug {
    /// Return the DER encoded issuer of the CRL.
    fn issuer(&self) -> &[u8];

    /// Return the DER encoded issuing distribution point of the CRL, if any.
    fn issuing_distribution_point(&self) -> Option<&[u8]>;

    /// Try to find a revoked certificate in the CRL by DER encoded serial number. This
    /// may yield an error if the CRL has malformed revoked certificates.
    fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert>, Error>;

    /// Verify the CRL signature using the issuer's subject public key information (SPKI)
    /// and a list of supported signature verification algorithms.
    fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: &[u8],
    ) -> Result<(), Error>;
}

/// Owned representation of a RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Debug, Clone)]
pub struct OwnedCertRevocationList {
    /// A map of the revoked certificates contained in then CRL, keyed by the DER encoding
    /// of the revoked cert's serial number.
    revoked_certs: BTreeMap<Vec<u8>, OwnedRevokedCert>,

    issuer: Vec<u8>,

    issuing_distribution_point: Option<Vec<u8>>,

    signed_data: signed_data::OwnedSignedData,
}

#[cfg(feature = "alloc")]
impl Sealed for OwnedCertRevocationList {}

#[cfg(feature = "alloc")]
impl CertRevocationList for OwnedCertRevocationList {
    fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    fn issuing_distribution_point(&self) -> Option<&[u8]> {
        self.issuing_distribution_point.as_deref()
    }

    fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert>, Error> {
        // note: this is infallible for the owned representation because we process all
        // revoked certificates at the time of construction to build the `revoked_certs` map,
        // returning any encountered errors at that time.
        Ok(self
            .revoked_certs
            .get(serial)
            .map(|owned_revoked_cert| owned_revoked_cert.borrow()))
    }

    fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: &[u8],
    ) -> Result<(), Error> {
        signed_data::verify_signed_data(
            supported_sig_algs,
            untrusted::Input::from(issuer_spki),
            &self.signed_data.borrow(),
        )
    }
}

/// Borrowed representation of a RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[derive(Debug)]
pub struct BorrowedCertRevocationList<'a> {
    /// A `SignedData` structure that can be passed to `verify_signed_data`.
    signed_data: SignedData<'a>,

    /// Identifies the entity that has signed and issued this
    /// CRL.
    issuer: untrusted::Input<'a>,

    /// An optional CRL extension that identifies the CRL distribution point and scope for the CRL.
    issuing_distribution_point: Option<untrusted::Input<'a>>,

    /// List of certificates revoked by the issuer in this CRL.
    revoked_certs: untrusted::Input<'a>,
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
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
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
}

impl Sealed for BorrowedCertRevocationList<'_> {}

impl CertRevocationList for BorrowedCertRevocationList<'_> {
    fn issuer(&self) -> &[u8] {
        self.issuer.as_slice_less_safe()
    }

    fn issuing_distribution_point(&self) -> Option<&[u8]> {
        self.issuing_distribution_point
            .map(|der| der.as_slice_less_safe())
    }

    fn find_serial(&self, serial: &[u8]) -> Result<Option<BorrowedRevokedCert>, Error> {
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

    fn verify_signature(
        &self,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        issuer_spki: &[u8],
    ) -> Result<(), Error> {
        signed_data::verify_signed_data(
            supported_sig_algs,
            untrusted::Input::from(issuer_spki),
            &self.signed_data,
        )
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
            if signature != signed_data.algorithm {
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
            Time::from_der(tbs_cert_list)?;

            // While OPTIONAL in the ASN.1 module, RFC 5280 §5.1.2.5 says:
            //   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
            // We do not presently enforce the correct choice of UTCTime or GeneralizedTime based on
            // whether the date is post 2050.
            Time::from_der(tbs_cert_list)?;

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
    pub revocation_date: Time,

    /// Identifies the reason for the certificate revocation. When absent, the revocation reason
    /// is assumed to be RevocationReason::Unspecified. For consistency with other extensions
    /// and to ensure only one revocation reason extension may be present we maintain this field
    /// as optional instead of defaulting to unspecified.
    pub reason_code: Option<RevocationReason>,

    /// Provides the date on which it is known or suspected that the private key was compromised or
    /// that the certificate otherwise became invalid. This date may be earlier than the revocation
    /// date which is the date at which the CA processed the revocation.
    pub invalidity_date: Option<Time>,
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

/// Borrowed representation of a RFC 5280[^1] profile Certificate Revocation List (CRL) revoked
/// certificate entry.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[derive(Debug)]
pub struct BorrowedRevokedCert<'a> {
    /// Serial number of the revoked certificate.
    pub serial_number: &'a [u8],

    /// The date at which the CA processed the revocation.
    pub revocation_date: Time,

    /// Identifies the reason for the certificate revocation. When absent, the revocation reason
    /// is assumed to be RevocationReason::Unspecified. For consistency with other extensions
    /// and to ensure only one revocation reason extension may be present we maintain this field
    /// as optional instead of defaulting to unspecified.
    pub reason_code: Option<RevocationReason>,

    /// Provides the date on which it is known or suspected that the private key was compromised or
    /// that the certificate otherwise became invalid. This date may be earlier than the revocation
    /// date which is the date at which the CA processed the revocation.
    pub invalidity_date: Option<Time>,
}

impl<'a> BorrowedRevokedCert<'a> {
    /// Construct an owned representation of the revoked certificate.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_owned(&self) -> OwnedRevokedCert {
        OwnedRevokedCert {
            serial_number: self.serial_number.to_vec(),
            revocation_date: self.revocation_date,
            reason_code: self.reason_code,
            invalidity_date: self.invalidity_date,
        }
    }

    fn remember_extension(&mut self, extension: &Extension<'a>) -> Result<(), Error> {
        remember_extension(extension, |id| {
            match id {
                // id-ce-cRLReasons 2.5.29.21 - RFC 5280 §5.3.1.
                21 => set_extension_once(&mut self.reason_code, || der::read_all(extension.value)),

                // id-ce-invalidityDate 2.5.29.24 - RFC 5280 §5.3.2.
                24 => set_extension_once(&mut self.invalidity_date, || {
                    extension.value.read_all(Error::BadDer, Time::from_der)
                }),

                // id-ce-certificateIssuer 2.5.29.29 - RFC 5280 §5.3.3.
                //   This CRL entry extension identifies the certificate issuer associated
                //   with an entry in an indirect CRL, that is, a CRL that has the
                //   indirectCRL indicator set in its issuing distribution point
                //   extension.
                // We choose not to support indirect CRLs and so turn this into a more specific
                // error rather than simply letting it fail as an unsupported critical extension.
                29 => Err(Error::UnsupportedIndirectCrl),

                // Unsupported extension
                _ => extension.unsupported(),
            }
        })
    }
}

impl<'a> FromDer<'a> for BorrowedRevokedCert<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        der::nested(
            reader,
            Tag::Sequence,
            Error::TrailingData(DerTypeId::RevokedCertEntry),
            |der| {
                // RFC 5280 §4.1.2.2:
                //    Certificate users MUST be able to handle serialNumber values up to 20 octets.
                //    Conforming CAs MUST NOT use serialNumber values longer than 20 octets.
                //
                //    Note: Non-conforming CAs may issue certificates with serial numbers
                //    that are negative or zero.  Certificate users SHOULD be prepared to
                //    gracefully handle such certificates.
                // Like the handling in cert.rs we choose to be lenient here, not enforcing the length
                // of a CRL revoked certificate's serial number is less than 20 octets in encoded form.
                let serial_number = lenient_certificate_serial_number(der)
                    .map_err(|_| Error::InvalidSerialNumber)?
                    .as_slice_less_safe();

                let revocation_date = Time::from_der(der)?;

                let mut revoked_cert = BorrowedRevokedCert {
                    serial_number,
                    revocation_date,
                    reason_code: None,
                    invalidity_date: None,
                };

                // RFC 5280 §5.3:
                //   Support for the CRL entry extensions defined in this specification is
                //   optional for conforming CRL issuers and applications.  However, CRL
                //   issuers SHOULD include reason codes (Section 5.3.1) and invalidity
                //   dates (Section 5.3.2) whenever this information is available.
                if der.at_end() {
                    return Ok(revoked_cert);
                }

                // It would be convenient to use der::nested_of_mut here to unpack a SEQUENCE of one or
                // more SEQUENCEs, however CAs have been mis-encoding the absence of extensions as an
                // empty SEQUENCE so we must be tolerant of that.
                let ext_seq = der::expect_tag(der, Tag::Sequence)?;
                if ext_seq.is_empty() {
                    return Ok(revoked_cert);
                }

                let mut reader = untrusted::Reader::new(ext_seq);
                loop {
                    der::nested(
                        &mut reader,
                        Tag::Sequence,
                        Error::TrailingData(DerTypeId::RevokedCertificateExtension),
                        |ext_der| {
                            // RFC 5280 §5.3:
                            //   If a CRL contains a critical CRL entry extension that the application cannot
                            //   process, then the application MUST NOT use that CRL to determine the
                            //   status of any certificates.  However, applications may ignore
                            //   unrecognized non-critical CRL entry extensions.
                            revoked_cert.remember_extension(&Extension::from_der(ext_der)?)
                        },
                    )?;
                    if reader.at_end() {
                        break;
                    }
                }

                Ok(revoked_cert)
            },
        )
    }

    const TYPE_ID: DerTypeId = DerTypeId::RevokedCertificate;
}

/// Identifies the reason a certificate was revoked.
/// See RFC 5280 §5.3.1[^1]
///
/// [^1] <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(missing_docs)] // Not much to add above the code name.
pub enum RevocationReason {
    /// Unspecified should not be used, and is instead assumed by the absence of a RevocationReason
    /// extension.
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is not used.
    /// RemoveFromCrl only appears in delta CRLs that are unsupported.
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Return an iterator over all possible [RevocationReason] variants.
    pub fn iter() -> impl Iterator<Item = RevocationReason> {
        use RevocationReason::*;
        [
            Unspecified,
            KeyCompromise,
            CaCompromise,
            AffiliationChanged,
            Superseded,
            CessationOfOperation,
            CertificateHold,
            RemoveFromCrl,
            PrivilegeWithdrawn,
            AaCompromise,
        ]
        .into_iter()
    }
}

impl<'a> FromDer<'a> for RevocationReason {
    // RFC 5280 §5.3.1.
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let input = der::expect_tag(reader, Tag::Enum)?;
        Self::try_from(input.read_all(Error::BadDer, |reason| {
            reason.read_byte().map_err(|_| Error::BadDer)
        })?)
    }

    const TYPE_ID: DerTypeId = DerTypeId::RevocationReason;
}

impl TryFrom<u8> for RevocationReason {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // See https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
        match value {
            0 => Ok(RevocationReason::Unspecified),
            1 => Ok(RevocationReason::KeyCompromise),
            2 => Ok(RevocationReason::CaCompromise),
            3 => Ok(RevocationReason::AffiliationChanged),
            4 => Ok(RevocationReason::Superseded),
            5 => Ok(RevocationReason::CessationOfOperation),
            6 => Ok(RevocationReason::CertificateHold),
            // 7 is not used.
            8 => Ok(RevocationReason::RemoveFromCrl),
            9 => Ok(RevocationReason::PrivilegeWithdrawn),
            10 => Ok(RevocationReason::AaCompromise),
            _ => Err(Error::UnsupportedRevocationReason),
        }
    }
}

#[allow(dead_code)] // TODO(@cpu): remove this once used in CRL validation.
pub(crate) struct IssuingDistributionPoint<'a> {
    distribution_point: Option<untrusted::Input<'a>>,
    pub(crate) only_contains_user_certs: bool,
    pub(crate) only_contains_ca_certs: bool,
    pub(crate) only_some_reasons: Option<der::BitStringFlags<'a>>,
    pub(crate) indirect_crl: bool,
    pub(crate) only_contains_attribute_certs: bool,
}

impl<'a> IssuingDistributionPoint<'a> {
    #[allow(dead_code)] // TODO(@cpu): remove this once used in CRL validation.
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
            let value = reader.read_byte()?;
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
    #[allow(dead_code)] // TODO(@cpu): remove this once used in CRL validation.
    pub(crate) fn names(&self) -> Result<Option<DistributionPointName<'a>>, Error> {
        self.distribution_point
            .map(|input| DistributionPointName::from_der(&mut untrusted::Reader::new(input)))
            .transpose()
    }
}

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        crl::IssuingDistributionPoint, subject_name::GeneralName, x509::DistributionPointName,
        BorrowedCertRevocationList, CertRevocationList, Error, RevocationReason,
    };

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
    #[cfg(feature = "alloc")]
    fn test_derived_traits() {
        let crl = crate::crl::BorrowedCertRevocationList::from_der(include_bytes!(
            "../tests/crls/crl.valid.der"
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
    fn parse_issuing_distribution_point_ext() {
        let crl = include_bytes!("../tests/crls/crl.idp.valid.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point()
            .expect("missing crl distribution point DER");

        #[cfg(feature = "alloc")]
        {
            // We should also be able to find the distribution point extensions bytes from
            // an owned representation of the CRL.
            let owned_crl = crl.to_owned().unwrap();
            assert!(owned_crl.issuing_distribution_point().is_some());
        }

        let crl_issuing_dp =
            IssuingDistributionPoint::from_der(untrusted::Input::from(crl_issuing_dp))
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
        let crl = include_bytes!("../tests/crls/crl.idp.only_user_certs.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point()
            .expect("missing crl distribution point DER");
        let crl_issuing_dp =
            IssuingDistributionPoint::from_der(untrusted::Input::from(crl_issuing_dp))
                .expect("failed to parse issuing distribution point DER");

        // We should find the expected bool state.
        assert!(crl_issuing_dp.only_contains_user_certs);
    }

    #[test]
    fn test_issuing_distribution_point_only_ca_certs() {
        let crl = include_bytes!("../tests/crls/crl.idp.only_ca_certs.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point()
            .expect("missing crl distribution point DER");
        let crl_issuing_dp =
            IssuingDistributionPoint::from_der(untrusted::Input::from(crl_issuing_dp))
                .expect("failed to parse issuing distribution point DER");

        // We should find the expected bool state.
        assert!(crl_issuing_dp.only_contains_ca_certs);
    }

    #[test]
    fn test_issuing_distribution_point_indirect() {
        let crl = include_bytes!("../tests/crls/crl.idp.indirect_crl.der");
        // We should encounter an error parsing a CRL with an IDP extension that indicates it's an
        // indirect CRL.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::UnsupportedIndirectCrl)));
    }

    #[test]
    fn test_issuing_distribution_only_attribute_certs() {
        let crl = include_bytes!("../tests/crls/crl.idp.only_attribute_certs.der");
        // We should find an error when we parse a CRL with an IDP extension that indicates it only
        // contains attribute certs.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::MalformedExtensions)));
    }

    #[test]
    fn test_issuing_distribution_only_some_reasons() {
        let crl = include_bytes!("../tests/crls/crl.idp.only_some_reasons.der");
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
        let crl = include_bytes!("../tests/crls/crl.idp.invalid.bool.der");
        // We should encounter an error parsing a CRL with an IDP extension with an invalid encoded boolean.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::BadDer)))
    }

    #[test]
    fn test_issuing_distribution_explicit_false_bool() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.explicit.false.bool.der.txt -o tests/crls/crl.idp.explicit.false.bool.der
        let crl = include_bytes!("../tests/crls/crl.idp.explicit.false.bool.der");
        let crl = BorrowedCertRevocationList::from_der(&crl[..]).unwrap();

        // We should be able to parse the issuing distribution point extension.
        let crl_issuing_dp = crl
            .issuing_distribution_point()
            .expect("missing crl distribution point DER");
        assert!(IssuingDistributionPoint::from_der(untrusted::Input::from(crl_issuing_dp)).is_ok());
    }

    #[test]
    fn test_issuing_distribution_unknown_tag() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.unknown.tag.der.txt -o tests/crls/crl.idp.unknown.tag.der
        let crl = include_bytes!("../tests/crls/crl.idp.unknown.tag.der");
        // We should encounter an error parsing a CRL with an invalid IDP extension.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::BadDer)));
    }

    #[test]
    fn test_issuing_distribution_invalid_name() {
        // Created w/
        //   ascii2der -i tests/crls/crl.idp.invalid.name.der.txt -o tests/crls/crl.idp.invalid.name.der
        let crl = include_bytes!("../tests/crls/crl.idp.invalid.name.der");

        // We should encounter an error parsing a CRL with an invalid issuing distribution point name.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(result, Err(Error::MalformedExtensions)))
    }

    #[test]
    fn test_issuing_distribution_relative_name() {
        let crl = include_bytes!("../tests/crls/crl.idp.name_relative_to_issuer.der");
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
        let crl = include_bytes!("../tests/crls/crl.idp.no_distribution_point_name.der");
        // We should encounter an error parsing a CRL with an issuing distribution point extension
        // that has no distribution point name.
        let result = BorrowedCertRevocationList::from_der(&crl[..]);
        assert!(matches!(
            result,
            Err(Error::UnsupportedCrlIssuingDistributionPoint)
        ))
    }
}
