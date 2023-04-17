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

use core::convert::TryFrom;

use crate::der::Tag;
use crate::{der, signed_data, Error, Time};

/// A collection of Certificate Revocation Lists (CRLs) which may be used to check client                                                         
/// certificates for revocation status.
// TODO(@cpu): Remove allows once used.
// TODO(@cpu): I suspect at this stage we mostly want to index this by issuer name. Is there
//             a better way to express that while still being no-std/no-alloc?
#[allow(unused, unreachable_pub)]
pub struct CertificateRevocationLists<'a>(pub &'a [CertRevocationList<'a>]);

/// Representation of a RFC 5280[^1] profile Certificate Revocation List (CRL).
///
/// [^1]: <https://www.rfc-editor.org/rfc/rfc5280#section-5>
pub struct CertRevocationList<'a> {
    /// A `SignedData` structure that can be passed to `verify_signed_data`.
    pub signed_data: signed_data::SignedData<'a>,

    /// Identifies the entity that has signed and issued this
    /// CRL.
    pub issuer: untrusted::Input<'a>,

    /// Indicates the issue date of this CRL.
    pub this_update: Time,

    /// Indicates the date by which the next CRL will be issued.
    pub next_update: Time,

    /// List of certificates revoked by the issuer in this CRL.
    pub revoked_certs: untrusted::Input<'a>,

    /// Provides a means of identifying the public key corresponding to the private key used to
    /// sign this CRL.
    pub authority_key_identifier: Option<untrusted::Input<'a>>,

    /// A monotonically increasing sequence number for a given CRL scope and CRL issuer.
    pub crl_number: Option<&'a [u8]>,
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
        parse_crl(untrusted::Input::from(crl_der))
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

        // Consume extensions (if present) without parsing.
        // TODO(@cpu): parse these.
        _ = tbs_cert_list.read_bytes_to_end();

        Ok(CertRevocationList {
            signed_data,
            issuer,
            this_update,
            next_update,
            revoked_certs,
            authority_key_identifier: None,
            crl_number: None,
        })
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
