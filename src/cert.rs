// Copyright 2015 Brian Smith.
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

use crate::der::Tag;
use crate::der::{self, CONSTRUCTED, CONTEXT_SPECIFIC};
use crate::signed_data::SignedData;
use crate::subject_name::GeneralName;
use crate::x509::{remember_extension, set_extension_once, Extension};
use crate::Error;

/// An enumeration indicating whether a [`Cert`] is a leaf end-entity cert, or a linked
/// list node from the CA `Cert` to a child `Cert` it issued.
pub enum EndEntityOrCa<'a> {
    /// The [`Cert`] is a leaf end-entity certificate.
    EndEntity,

    /// The [`Cert`] is an issuer certificate, and issued the referenced child `Cert`.
    Ca(&'a Cert<'a>),
}

/// A parsed X509 certificate.
pub struct Cert<'a> {
    pub(crate) ee_or_ca: EndEntityOrCa<'a>,

    pub(crate) serial: untrusted::Input<'a>,
    pub(crate) signed_data: SignedData<'a>,
    pub(crate) issuer: untrusted::Input<'a>,
    pub(crate) validity: untrusted::Input<'a>,
    pub(crate) subject: untrusted::Input<'a>,
    pub(crate) spki: der::Value<'a>,

    pub(crate) basic_constraints: Option<untrusted::Input<'a>>,
    // key usage (KU) extension (if any). When validating certificate revocation lists (CRLs) this
    // field will be consulted to determine if the cert is allowed to sign CRLs. For cert validation
    // this field is ignored (for more detail see in `verify_cert.rs` and
    // `check_issuer_independent_properties`).
    pub(crate) key_usage: Option<untrusted::Input<'a>>,
    pub(crate) eku: Option<untrusted::Input<'a>>,
    pub(crate) name_constraints: Option<untrusted::Input<'a>>,
    pub(crate) subject_alt_name: Option<untrusted::Input<'a>>,
    pub(crate) crl_distribution_points: Option<untrusted::Input<'a>>,
}

impl<'a> Cert<'a> {
    pub(crate) fn from_der(
        cert_der: untrusted::Input<'a>,
        ee_or_ca: EndEntityOrCa<'a>,
    ) -> Result<Self, Error> {
        let (tbs, signed_data) = cert_der.read_all(Error::BadDer, |cert_der| {
            der::nested(cert_der, der::Tag::Sequence, Error::BadDer, |der| {
                // limited to SEQUENCEs of size 2^16 or less.
                SignedData::from_der(der, der::TWO_BYTE_DER_SIZE)
            })
        })?;

        tbs.read_all(Error::BadDer, |tbs| {
            version3(tbs)?;

            let serial = lenient_certificate_serial_number(tbs)?;

            let signature = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
            // TODO: In mozilla::pkix, the comparison is done based on the
            // normalized value (ignoring whether or not there is an optional NULL
            // parameter for RSA-based algorithms), so this may be too strict.
            if signature != signed_data.algorithm {
                return Err(Error::SignatureAlgorithmMismatch);
            }

            let issuer = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
            let validity = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
            let subject = der::expect_tag_and_get_value(tbs, der::Tag::Sequence)?;
            let spki = der::expect_tag(tbs, der::Tag::Sequence)?;

            // In theory there could be fields [1] issuerUniqueID and [2]
            // subjectUniqueID, but in practice there never are, and to keep the
            // code small and simple we don't accept any certificates that do
            // contain them.

            let mut cert = Cert {
                ee_or_ca,

                signed_data,
                serial,
                issuer,
                validity,
                subject,
                spki,

                basic_constraints: None,
                key_usage: None,
                eku: None,
                name_constraints: None,
                subject_alt_name: None,
                crl_distribution_points: None,
            };

            if !tbs.at_end() {
                der::nested(
                    tbs,
                    der::Tag::ContextSpecificConstructed3,
                    Error::MalformedExtensions,
                    |tagged| {
                        der::nested_of_mut(
                            tagged,
                            der::Tag::Sequence,
                            der::Tag::Sequence,
                            Error::BadDer,
                            |extension| {
                                remember_cert_extension(&mut cert, &Extension::parse(extension)?)
                            },
                        )
                    },
                )?;
            }

            Ok(cert)
        })
    }

    /// Raw DER encoded certificate serial number.
    pub fn serial(&self) -> &[u8] {
        self.serial.as_slice_less_safe()
    }

    /// Raw DER encoded certificate issuer.
    pub fn issuer(&self) -> &[u8] {
        self.issuer.as_slice_less_safe()
    }

    /// Raw DER encoded certificate subject.
    pub fn subject(&self) -> &[u8] {
        self.subject.as_slice_less_safe()
    }

    /// Returns an indication of whether the certificate is an end-entity (leaf) certificate,
    /// or a certificate authority.
    pub fn end_entity_or_ca(&self) -> &EndEntityOrCa {
        &self.ee_or_ca
    }

    /// Returns an iterator over the certificate's cRLDistributionPoints extension values, if any.
    #[allow(dead_code)] // TODO(@cpu): remove once used in CRL validation.
    pub(crate) fn crl_distribution_points(&self) -> Option<CrlDistributionPoints> {
        self.crl_distribution_points
            .map(|crl_distribution_points| CrlDistributionPoints {
                reader: untrusted::Reader::new(crl_distribution_points),
            })
    }
}

// mozilla::pkix supports v1, v2, v3, and v4, including both the implicit
// (correct) and explicit (incorrect) encoding of v1. We allow only v3.
fn version3(input: &mut untrusted::Reader) -> Result<(), Error> {
    der::nested(
        input,
        der::Tag::ContextSpecificConstructed0,
        Error::UnsupportedCertVersion,
        |input| {
            let version = der::small_nonnegative_integer(input)?;
            if version != 2 {
                // v3
                return Err(Error::UnsupportedCertVersion);
            }
            Ok(())
        },
    )
}

pub(crate) fn lenient_certificate_serial_number<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>, Error> {
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.2:
    // * Conforming CAs MUST NOT use serialNumber values longer than 20 octets."
    // * "The serial number MUST be a positive integer [...]"
    //
    // However, we don't enforce these constraints, as there are widely-deployed trust anchors
    // and many X.509 implementations in common use that violate these constraints. This is called
    // out by the same section of RFC 5280 as cited above:
    //   Note: Non-conforming CAs may issue certificates with serial numbers
    //   that are negative or zero.  Certificate users SHOULD be prepared to
    //   gracefully handle such certificates.
    der::expect_tag_and_get_value(input, Tag::Integer)
}

fn remember_cert_extension<'a>(
    cert: &mut Cert<'a>,
    extension: &Extension<'a>,
) -> Result<(), Error> {
    // We don't do anything with certificate policies so we can safely ignore
    // all policy-related stuff. We assume that the policy-related extensions
    // are not marked critical.

    remember_extension(extension, |id| {
        let out = match id {
            // id-ce-keyUsage 2.5.29.15.
            15 => &mut cert.key_usage,

            // id-ce-subjectAltName 2.5.29.17
            17 => &mut cert.subject_alt_name,

            // id-ce-basicConstraints 2.5.29.19
            19 => &mut cert.basic_constraints,

            // id-ce-nameConstraints 2.5.29.30
            30 => &mut cert.name_constraints,

            // id-ce-cRLDistributionPoints 2.5.29.31
            31 => &mut cert.crl_distribution_points,

            // id-ce-extKeyUsage 2.5.29.37
            37 => &mut cert.eku,

            // Unsupported extension
            _ => return extension.unsupported(),
        };

        set_extension_once(out, || {
            extension.value.read_all(Error::BadDer, |value| match id {
                // Unlike the other extensions we remember KU is a BitString and not a Sequence. We
                // read the raw bytes here and parse at the time of use.
                15 => Ok(value.read_bytes_to_end()),
                // All other remembered certificate extensions are wrapped in a Sequence.
                _ => der::expect_tag_and_get_value(value, Tag::Sequence),
            })
        })
    })
}

/// Iterator over a certificate's certificate revocation list (CRL) distribution
/// points as described in RFC 5280 section 4.2.3.13[^1].
///
/// The CRL distribution point extensions describes how CRL information can be obtained for
/// a given certificate.
///
/// [^1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13>
pub(crate) struct CrlDistributionPoints<'a> {
    reader: untrusted::Reader<'a>,
}

impl<'a> Iterator for CrlDistributionPoints<'a> {
    type Item = Result<CrlDistributionPoint<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.reader.at_end()).then(|| CrlDistributionPoint::from_der(&mut self.reader))
    }
}

/// A certificate revocation list (CRL) distribution point, describing a source of
/// CRL information for a given certificate as described in RFC 5280 section 4.2.3.13[^1].
///
/// [^1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13>
pub(crate) struct CrlDistributionPoint<'a> {
    /// distributionPoint describes the location of CRL information.
    distribution_point: Option<untrusted::Input<'a>>,

    /// reasons holds a bit flag set of certificate revocation reasons associated with the
    /// CRL distribution point.
    pub(crate) reasons: Option<der::BitStringFlags<'a>>,

    /// when the CRL issuer is not the certificate issuer, crl_issuer identifies the issuer of the
    /// CRL.
    pub(crate) crl_issuer: Option<untrusted::Input<'a>>,
}

impl<'a> CrlDistributionPoint<'a> {
    fn from_der(der: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        // RFC 5280 section §4.2.1.13:
        //   A DistributionPoint consists of three fields, each of which is optional:
        //   distributionPoint, reasons, and cRLIssuer.
        let mut result = CrlDistributionPoint {
            distribution_point: None,
            reasons: None,
            crl_issuer: None,
        };

        der::nested(der, Tag::Sequence, Error::BadDer, |der| {
            const DISTRIBUTION_POINT_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED;
            const REASONS_TAG: u8 = CONTEXT_SPECIFIC | 1;
            const CRL_ISSUER_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 2;

            while !der.at_end() {
                let (tag, value) = der::read_tag_and_get_value(der)?;
                match tag {
                    DISTRIBUTION_POINT_TAG => {
                        set_extension_once(&mut result.distribution_point, || Ok(value))?
                    }
                    REASONS_TAG => {
                        set_extension_once(&mut result.reasons, || der::bit_string_flags(value))?
                    }
                    CRL_ISSUER_TAG => set_extension_once(&mut result.crl_issuer, || Ok(value))?,
                    _ => return Err(Error::BadDer),
                }
            }

            // RFC 5280 section §4.2.1.13:
            //   a DistributionPoint MUST NOT consist of only the reasons field; either distributionPoint or
            //   cRLIssuer MUST be present.
            match (result.distribution_point, result.crl_issuer) {
                (None, None) => return Err(Error::MalformedExtensions),
                _ => {}
            }

            Ok(result)
        })
    }

    /// Return the distribution point names (if any).
    #[allow(dead_code)] // TODO(@cpu): remove this once used in CRL validation.
    pub(crate) fn names(&self) -> Result<Option<DistributionPointName<'a>>, Error> {
        Ok(match self.distribution_point {
            None => None,
            Some(der) => Some(DistributionPointName::from_der(der)?),
        })
    }
}

/// A certificate revocation list (CRL) distribution point name, describing a source of
/// CRL information for a given certificate as described in RFC 5280 section 4.2.3.13[^1].
///
/// [^1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13>
#[allow(dead_code)] // TODO(@cpu): remove this once used in CRL validation.
pub(crate) enum DistributionPointName<'a> {
    /// The distribution point name is a relative distinguished name, relative to the CRL issuer.
    NameRelativeToCrlIssuer(untrusted::Input<'a>),
    /// The distribution point name is a sequence of [GeneralNames].
    FullName(GeneralNames<'a>),
}

impl<'a> DistributionPointName<'a> {
    fn from_der(der: untrusted::Input<'_>) -> Result<DistributionPointName, Error> {
        const FULL_NAME_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED;
        const NAME_RELATIVE_TO_CRL_ISSUER_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 1;

        let (tag, value) = der::read_tag_and_get_value(&mut untrusted::Reader::new(der))?;
        match tag {
            FULL_NAME_TAG => Ok(DistributionPointName::FullName(GeneralNames {
                reader: untrusted::Reader::new(value),
            })),
            NAME_RELATIVE_TO_CRL_ISSUER_TAG => {
                Ok(DistributionPointName::NameRelativeToCrlIssuer(value))
            }
            _ => Err(Error::BadDer),
        }
    }
}

/// An iterator over a series of X.509 [GeneralName] instances describing locations that can be used
/// to fetch a certificate revocation list for a certificate.
pub(crate) struct GeneralNames<'a> {
    reader: untrusted::Reader<'a>,
}

impl<'a> Iterator for GeneralNames<'a> {
    type Item = Result<GeneralName<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.reader.at_end()).then(|| GeneralName::from_der(&mut self.reader))
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::{Cert, EndEntityOrCa};

    #[test]
    // Note: cert::parse_cert is crate-local visibility, and EndEntityCert doesn't expose the
    //       inner Cert, or the serial number. As a result we test that the raw serial value
    //       is read correctly here instead of in tests/integration.rs.
    fn test_serial_read() {
        let ee = include_bytes!("../tests/misc/serial_neg_ee.der");
        let cert = Cert::from_der(untrusted::Input::from(ee), EndEntityOrCa::EndEntity)
            .expect("failed to parse certificate");
        assert_eq!(cert.serial.as_slice_less_safe(), &[255, 33, 82, 65, 17]);

        let ee = include_bytes!("../tests/misc/serial_large_positive.der");
        let cert = Cert::from_der(untrusted::Input::from(ee), EndEntityOrCa::EndEntity)
            .expect("failed to parse certificate");
        assert_eq!(
            cert.serial.as_slice_less_safe(),
            &[
                0, 230, 9, 254, 122, 234, 0, 104, 140, 224, 36, 180, 237, 32, 27, 31, 239, 82, 180,
                68, 209
            ]
        )
    }
}
