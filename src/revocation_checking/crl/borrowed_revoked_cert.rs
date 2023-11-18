use crate::cert::lenient_certificate_serial_number;

use super::*;

/// Borrowed representation of a RFC 5280[^1] profile Certificate Revocation List (CRL) revoked
/// certificate entry.
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
#[derive(Debug)]
pub struct BorrowedRevokedCert<'a> {
    /// Serial number of the revoked certificate.
    pub serial_number: &'a [u8],

    /// The date at which the CA processed the revocation.
    pub revocation_date: UnixTime,

    /// Identifies the reason for the certificate revocation. When absent, the revocation reason
    /// is assumed to be RevocationReason::Unspecified. For consistency with other extensions
    /// and to ensure only one revocation reason extension may be present we maintain this field
    /// as optional instead of defaulting to unspecified.
    pub reason_code: Option<RevocationReason>,

    /// Provides the date on which it is known or suspected that the private key was compromised or
    /// that the certificate otherwise became invalid. This date may be earlier than the revocation
    /// date which is the date at which the CA processed the revocation.
    pub invalidity_date: Option<UnixTime>,
}

impl<'a> BorrowedRevokedCert<'a> {
    /// Construct an owned representation of the revoked certificate.
    #[cfg(feature = "alloc")]
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
                    extension.value.read_all(Error::BadDer, UnixTime::from_der)
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

                let revocation_date = UnixTime::from_der(der)?;

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
