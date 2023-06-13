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

use core::convert::{TryFrom, TryInto};

use crate::der::Tag;
use crate::x509::{remember_extension, set_extension_once, Extension};
use crate::{der, signed_data, Error, Time};

/// Representation of a RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
pub struct CertRevocationList<'a> {
    /// A `SignedData` structure that can be passed to `verify_signed_data`.
    #[allow(unused)] // TODO(@cpu): Remove when support for revocation checking is added.
    pub(crate) signed_data: signed_data::SignedData<'a>,

    /// Identifies the entity that has signed and issued this
    /// CRL.
    pub(crate) issuer: untrusted::Input<'a>,

    /// Indicates the issue date of this CRL.
    pub this_update: Time,

    /// Indicates the date by which the next CRL will be issued.
    pub next_update: Time,

    /// List of certificates revoked by the issuer in this CRL.
    pub(crate) revoked_certs: untrusted::Input<'a>,

    /// Provides a means of identifying the public key corresponding to the private key used to
    /// sign this CRL.
    pub(crate) authority_key_identifier: Option<untrusted::Input<'a>>,

    /// A monotonically increasing sequence number for a given CRL scope and CRL issuer.
    pub crl_number: Option<&'a [u8]>,
}

impl<'a> CertRevocationList<'a> {
    /// Raw DER encoding of the issuer of the CRL.
    pub fn issuer(&self) -> &[u8] {
        self.issuer.as_slice_less_safe()
    }

    /// DER encoding of the authority key identifier (AKI) of the CRL.
    pub fn authority_key_identifier(&self) -> Option<&[u8]> {
        self.authority_key_identifier
            .map(|input| input.as_slice_less_safe())
    }
}

/// Representation of a RFC 5280[^1] profile Certificate Revocation List (CRL) revoked certificate
/// entry.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
pub struct RevokedCert<'a> {
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

/// Identifies the reason a certificate was revoked.
/// See RFC 5280 §5.3.1[^1]
///
/// [^1] <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)] // Not much to add above the code name.
pub enum RevocationReason {
    /// Unspecified should not be used, and is instead assumed by the absence of a RevocationReason
    /// extension.
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    /// RemoveFromCrl only appears in delta CRLs that are unsupported.
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

pub struct RevokedCerts<'a> {
    reader: untrusted::Reader<'a>,
}

impl<'a> Iterator for RevokedCerts<'a> {
    type Item = Result<RevokedCert<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.reader.at_end()).then(|| parse_revoked_cert(&mut self.reader))
    }
}

impl<'a> IntoIterator for &'a CertRevocationList<'a> {
    type Item = Result<RevokedCert<'a>, Error>;
    type IntoIter = RevokedCerts<'a>;

    fn into_iter(self) -> Self::IntoIter {
        RevokedCerts {
            reader: untrusted::Reader::new(self.revoked_certs),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for CertRevocationList<'a> {
    type Error = Error;

    /// Try to parse the given bytes as a RFC 5280[^1] profile Certificate Revocation List (CRL).
    ///
    /// Webpki does not support:
    ///   * CRL versions other than version 2.
    ///   * CRLs missing the next update field.
    ///   * CRLs missing certificate revocation list extensions.
    ///   * Delta CRLs.
    ///
    /// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
    fn try_from(crl_der: &'a [u8]) -> Result<Self, Self::Error> {
        // Try to parse the CRL.
        let crl = parse_crl(untrusted::Input::from(crl_der))?;

        // Iterate through the revoked certificate entries to ensure they are valid so we can
        // yield an error up-front instead of on first iteration by the caller.
        for cert_result in crl.into_iter() {
            cert_result?;
        }

        Ok(crl)
    }
}

impl<'a> CertRevocationList<'a> {
    /// Try to find a [`RevokedCert`] in the CRL that has a serial number matching `serial`. This
    /// method will ignore any [`RevokedCert`] entries that do not parse successfully. To handle
    /// parse errors use [`CertRevocationList`]'s [`IntoIterator`] trait.
    pub fn find_serial(&self, serial: &[u8]) -> Option<RevokedCert> {
        self.into_iter()
            .filter_map(|parse_res| parse_res.ok())
            .find(|revoked_cert| revoked_cert.serial_number.eq(serial))
    }
}

fn parse_crl(crl_der: untrusted::Input) -> Result<CertRevocationList, Error> {
    let (tbs_cert_list, signed_data) = crl_der.read_all(Error::BadDer, |crl_der| {
        der::nested(
            crl_der,
            Tag::Sequence,
            Error::BadDer,
            signed_data::parse_signed_data,
        )
    })?;

    tbs_cert_list.read_all(Error::BadDer, |tbs_cert_list| {
        version2(tbs_cert_list)?;

        // RFC 5280 §5.1.2.2:
        //   This field MUST contain the same algorithm identifier as the
        //   signatureAlgorithm field in the sequence CertificateList
        let signature = der::expect_tag_and_get_value(tbs_cert_list, Tag::Sequence)?;
        if signature != signed_data.algorithm {
            return Err(Error::SignatureAlgorithmMismatch);
        }

        // RFC 5280 §5.1.2.3:
        //   The issuer field MUST contain a non-empty X.500 distinguished name (DN).
        let issuer = der::expect_tag_and_get_value(tbs_cert_list, Tag::Sequence)?;

        // RFC 5280 §5.1.2.4:
        //    This field indicates the issue date of this CRL.  thisUpdate may be
        //    encoded as UTCTime or GeneralizedTime.
        // We do not presently enforce the correct choice of UTCTime or GeneralizedTime based on
        // whether the date is post 2050.
        let this_update = der::time_choice(tbs_cert_list)?;

        // While OPTIONAL in the ASN.1 module, RFC 5280 §5.1.2.5 says:
        //   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
        // We do not presently enforce the correct choice of UTCTime or GeneralizedTime based on
        // whether the date is post 2050.
        let next_update = der::time_choice(tbs_cert_list)?;

        // RFC 5280 §5.1.2.6:
        //   When there are no revoked certificates, the revoked certificates list
        //   MUST be absent
        // TODO(@cpu): Do we care to support empty CRLs if we don't support delta CRLs?
        let revoked_certs = if tbs_cert_list.peek(Tag::Sequence.into()) {
            der::expect_tag_and_get_value(tbs_cert_list, Tag::Sequence)?
        } else {
            untrusted::Input::from(&[])
        };

        let mut crl = CertRevocationList {
            signed_data,
            issuer,
            this_update,
            next_update,
            revoked_certs,
            authority_key_identifier: None,
            crl_number: None,
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
                    Error::BadDer,
                    |extension| {
                        // RFC 5280 §5.2:
                        //   If a CRL contains a critical extension
                        //   that the application cannot process, then the application MUST NOT
                        //   use that CRL to determine the status of certificates.  However,
                        //   applications may ignore unrecognized non-critical extensions.
                        remember_crl_extension(&mut crl, &Extension::parse(extension)?)
                    },
                )
            },
        )?;

        Ok(crl)
    })
}

// RFC 5280 §5.1.2.1:
//   This optional field describes the version of the encoded CRL.  When
//   extensions are used, as required by this profile, this field MUST be
//   present and MUST specify version 2 (the integer value is 1).
// RFC 5280 §5.2:
//   Conforming CRL issuers are REQUIRED to include the authority key
//   identifier (Section 5.2.1) and the CRL number (Section 5.2.3)
//   extensions in all CRLs issued.
// As a result of the above we parse this as a required section, not OPTIONAL.
fn version2(input: &mut untrusted::Reader) -> Result<(), Error> {
    // NOTE: Encoded value of version 2 is 1.
    if der::small_nonnegative_integer(input)? != 1 {
        return Err(Error::UnsupportedCrlVersion);
    }
    Ok(())
}

fn remember_crl_extension<'a>(
    crl: &mut CertRevocationList<'a>,
    extension: &Extension<'a>,
) -> Result<(), Error> {
    remember_extension(extension, |id| {
        match id {
            // id-ce-cRLNumber 2.5.29.20 - RFC 5280 §5.2.3
            20 => {
                // RFC 5280 §5.2.3:
                //   CRL verifiers MUST be able to handle CRLNumber values
                //   up to 20 octets.  Conforming CRL issuers MUST NOT use CRLNumber
                //   values longer than 20 octets.
                //
                let crl_number = extension.value.read_all(Error::InvalidCrlNumber, |der| {
                    let crl_number = ring::io::der::positive_integer(der)
                        .map_err(|_| Error::InvalidCrlNumber)?
                        .big_endian_without_leading_zero();
                    if crl_number.len() <= 20 {
                        Ok(crl_number)
                    } else {
                        Err(Error::InvalidCrlNumber)
                    }
                });
                set_extension_once(&mut crl.crl_number, || crl_number)
            }

            // id-ce-deltaCRLIndicator 2.5.29.27 - RFC 5280 §5.2.4
            // We explicitly do not support delta CRLs.
            27 => Err(Error::UnsupportedDeltaCrl),

            // id-ce-issuingDistributionPoint 2.5.29.28 - RFC 5280 §5.2.4
            //    Although the extension is critical, conforming implementations are not
            //    required to support this extension.  However, implementations that do not
            //    support this extension MUST either treat the status of any certificate not listed
            //    on this CRL as unknown or locate another CRL that does not contain any
            //    unrecognized critical extensions.
            // TODO(@cpu): We may want to parse this enough to be able to error on indirectCRL
            //  bool == true, or to enforce validation based on onlyContainsUserCerts,
            //  onlyContainsCACerts, and onlySomeReasons. For now we use the carve-out where
            //  we'll treat it as understood without parsing and consider certificates not found
            //  in the list as unknown.
            28 => Ok(()),

            // id-ce-authorityKeyIdentifier 2.5.29.35 - RFC 5280 §5.2.1, §4.2.1.1
            35 => set_extension_once(&mut crl.authority_key_identifier, || Ok(extension.value)),

            // Unsupported extension
            _ => extension.unsupported(),
        }
    })
}

fn parse_revoked_cert<'a>(der: &mut untrusted::Reader<'a>) -> Result<RevokedCert<'a>, Error> {
    der::nested(der, Tag::Sequence, Error::BadDer, |der| {
        // RFC 5280 §4.1.2.2:
        //    Certificate users MUST be able to handle serialNumber values up to 20 octets.
        //    Conforming CAs MUST NOT use serialNumber values longer than 20 octets.
        //
        //    Note: Non-conforming CAs may issue certificates with serial numbers
        //    that are negative or zero.  Certificate users SHOULD be prepared to
        //    gracefully handle such certificates.
        // Like the handling in cert.rs we choose to be lenient here, not enforcing the length
        // of a CRL revoked certificate's serial number is less than 20 octets in encoded form.
        let serial_number = ring::io::der::positive_integer(der)
            .map_err(|_| Error::InvalidSerialNumber)?
            .big_endian_without_leading_zero();

        let revocation_date = der::time_choice(der)?;

        let mut revoked_cert = RevokedCert {
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
        let ext_seq = der::expect_tag_and_get_value(der, Tag::Sequence)?;
        if ext_seq.is_empty() {
            return Ok(revoked_cert);
        }

        let mut reader = untrusted::Reader::new(ext_seq);
        loop {
            der::nested(&mut reader, Tag::Sequence, Error::BadDer, |ext_der| {
                // RFC 5280 §5.3:
                //   If a CRL contains a critical CRL entry extension that the application cannot
                //   process, then the application MUST NOT use that CRL to determine the
                //   status of any certificates.  However, applications may ignore
                //   unrecognized non-critical CRL entry extensions.
                remember_revoked_cert_extension(&mut revoked_cert, &Extension::parse(ext_der)?)
            })?;
            if reader.at_end() {
                break;
            }
        }

        Ok(revoked_cert)
    })
}

fn remember_revoked_cert_extension<'a>(
    revoked_cert: &mut RevokedCert<'a>,
    extension: &Extension<'a>,
) -> Result<(), Error> {
    remember_extension(extension, |id| {
        match id {
            // id-ce-cRLReasons 2.5.29.21 - RFC 5280 §5.3.1.
            21 => set_extension_once(&mut revoked_cert.reason_code, || {
                revocation_reason(extension.value)?.try_into()
            }),

            // id-ce-invalidityDate 2.5.29.24 - RFC 5280 §5.3.2.
            24 => set_extension_once(&mut revoked_cert.invalidity_date, || {
                extension.value.read_all(Error::BadDer, der::time_choice)
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

// RFC 5280 §5.3.1.
fn revocation_reason(value: untrusted::Input) -> Result<u8, Error> {
    value.read_all(Error::BadDer, |enumerated_reason| {
        let value = der::expect_tag(enumerated_reason, Tag::Enum)?;
        value.value().read_all(Error::BadDer, |reason| {
            reason.read_byte().map_err(|_| Error::BadDer)
        })
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::convert::TryInto;

    use crate::{Error, RevocationReason};

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
        }

        // Unsupported/unknown revocation reason codes should produce an error.
        let res = <u8 as TryInto<RevocationReason>>::try_into(7);
        assert!(matches!(res, Err(Error::UnsupportedRevocationReason)));
    }
}
