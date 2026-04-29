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

use core::fmt;

use crate::der::{self, CONSTRUCTED, CONTEXT_SPECIFIC, DerIterator, FromDer};
use crate::error::{DerTypeId, Error};
use crate::public_values_eq;
use crate::subject_name::GeneralName;
use crate::verify_cert::OidDecoder;

/// DER OBJECT IDENTIFIER value bytes identifying an X.509 extension.
#[derive(Clone, Copy)]
pub struct ExtensionId<'a> {
    oid_value: untrusted::Input<'a>,
}

impl<'a> ExtensionId<'a> {
    /// Construct a new [`ExtensionId`].
    ///
    /// `oid` is the DER OBJECT IDENTIFIER value bytes, without the OBJECT IDENTIFIER tag or
    /// length.
    pub const fn new(oid: &'a [u8]) -> Self {
        Self {
            oid_value: untrusted::Input::from(oid),
        }
    }

    fn matches(&self, oid: untrusted::Input<'_>) -> bool {
        public_values_eq(self.oid_value, oid)
    }
}

impl fmt::Debug for ExtensionId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtensionId(")?;
        let decoder = OidDecoder::new(self.oid_value.as_slice_less_safe());
        for (i, part) in decoder.enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{part}")?;
        }
        write!(f, ")")
    }
}

pub(crate) struct Extension<'a> {
    pub(crate) critical: bool,
    pub(crate) id: untrusted::Input<'a>,
    pub(crate) value: untrusted::Input<'a>,
}

impl Extension<'_> {
    pub(crate) fn unsupported(&self, policy: UnknownExtensionPolicy<'_>) -> Result<(), Error> {
        match policy {
            UnknownExtensionPolicy::Strict if self.critical => {
                Err(Error::UnsupportedCriticalExtension)
            }
            UnknownExtensionPolicy::AllowUnsupportedCritical(ids)
                if self.critical && !ids.iter().any(|id| id.matches(self.id)) =>
            {
                Err(Error::UnsupportedCriticalExtension)
            }
            _ => Ok(()),
        }
    }
}

impl<'a> FromDer<'a> for Extension<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let id = der::expect_tag(reader, der::Tag::OID)?;
        let critical = bool::from_der(reader)?;
        let value = der::expect_tag(reader, der::Tag::OctetString)?;
        Ok(Extension {
            id,
            critical,
            value,
        })
    }

    const TYPE_ID: DerTypeId = DerTypeId::Extension;
}

pub(crate) fn set_extension_once<T>(
    destination: &mut Option<T>,
    parser: impl Fn() -> Result<T, Error>,
) -> Result<(), Error> {
    match destination {
        // The extension value has already been set, indicating that we encountered it
        // more than once in our serialized data. That's invalid!
        Some(..) => Err(Error::ExtensionValueInvalid),
        None => {
            *destination = Some(parser()?);
            Ok(())
        }
    }
}

pub(crate) fn remember_extension(
    extension: &Extension<'_>,
    ext_policy: UnknownExtensionPolicy<'_>,
    mut handler: impl FnMut(ExtensionOid) -> Result<(), Error>,
) -> Result<(), Error> {
    match ExtensionOid::lookup(extension.id) {
        Some(oid) => handler(oid),
        None => extension.unsupported(ext_policy),
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum UnknownExtensionPolicy<'a> {
    #[default]
    Strict,
    IgnoreCritical,
    AllowUnsupportedCritical(&'a [ExtensionId<'a>]),
}

/// A certificate revocation list (CRL) distribution point name, describing a source of
/// CRL information for a given certificate as described in RFC 5280 section 4.2.3.13[^1].
///
/// [^1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13>
pub(crate) enum DistributionPointName<'a> {
    /// The distribution point name is a relative distinguished name, relative to the CRL issuer.
    NameRelativeToCrlIssuer,
    /// The distribution point name is a sequence of [GeneralName] items.
    FullName(DerIterator<'a, GeneralName<'a>>),
}

impl<'a> FromDer<'a> for DistributionPointName<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        // RFC 5280 section §4.2.1.13:
        //   When the distributionPoint field is present, it contains either a
        //   SEQUENCE of general names or a single value, nameRelativeToCRLIssuer
        const FULL_NAME_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED;
        const NAME_RELATIVE_TO_CRL_ISSUER_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 1;

        let (tag, value) = der::read_tag_and_get_value(reader)?;
        match tag {
            FULL_NAME_TAG => Ok(DistributionPointName::FullName(DerIterator::new(value))),
            NAME_RELATIVE_TO_CRL_ISSUER_TAG => Ok(DistributionPointName::NameRelativeToCrlIssuer),
            _ => Err(Error::BadDer),
        }
    }

    const TYPE_ID: DerTypeId = DerTypeId::DistributionPointName;
}

/// Simplified representation of supported extension OIDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExtensionOid {
    /// Extensions whose OID is under `id-ce` arc.
    Standard(u8),
    /// The OID given by `SCT_LIST_OID`.
    SignedCertificateTimestampList,
}

impl ExtensionOid {
    fn lookup(id: untrusted::Input<'_>) -> Option<Self> {
        match id.as_slice_less_safe() {
            v if v == SCT_LIST_OID => Some(Self::SignedCertificateTimestampList),
            [first, second, x] if [*first, *second] == ID_CE => Some(Self::Standard(*x)),
            _ => None,
        }
    }
}

/// This is 1.3.6.1.4.1.11129.2.4.2, as defined in RFC6962
///
/// In full this is:
///
/// ```text
/// {iso(1) identified-organization(3) dod(6) internet(1)
///  private(4) enterprise(1) google(11129) 2 4 2}
/// ```
///
/// Note that the `oid!` macro doesn't work for OIDs with any
/// limb greater than 7 bits, so this is a manual expansion.
///
/// <https://datatracker.ietf.org/doc/html/rfc6962#section-3.3>
const SCT_LIST_OID: [u8; 10] = [40 + 3, 6, 1, 4, 1, 214, 121, 2, 4, 2];

/// ISO arc for standard certificate and CRL extensions.
///
/// ```text
/// id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
/// ```
///
/// <https://www.rfc-editor.org/rfc/rfc5280#appendix-A.2>
const ID_CE: [u8; 2] = oid!(2, 5, 29);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_extension_policy_debug() {
        let ignored = [ExtensionId::new(&[43, 6, 1, 4, 1, 42, 1])];

        assert_eq!(
            format!(
                "{:?}",
                UnknownExtensionPolicy::AllowUnsupportedCritical(&ignored)
            ),
            "AllowUnsupportedCritical([ExtensionId(1.3.6.1.4.1.42.1)])"
        );
    }
}
