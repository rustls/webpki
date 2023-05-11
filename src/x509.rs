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

use crate::{der, Error};

pub(crate) struct Extension<'a> {
    pub(crate) critical: bool,
    pub(crate) id: untrusted::Input<'a>,
    pub(crate) value: untrusted::Input<'a>,
}

impl<'a> Extension<'a> {
    pub(crate) fn parse(der: &mut untrusted::Reader<'a>) -> Result<Extension<'a>, Error> {
        let id = der::expect_tag_and_get_value(der, der::Tag::OID)?;
        let critical = der::optional_boolean(der)?;
        let value = der::expect_tag_and_get_value(der, der::Tag::OctetString)?;
        Ok(Extension {
            id,
            critical,
            value,
        })
    }

    pub(crate) fn unsupported(&self) -> Result<(), Error> {
        match self.critical {
            true => Err(Error::UnsupportedCriticalExtension),
            false => Ok(()),
        }
    }
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
