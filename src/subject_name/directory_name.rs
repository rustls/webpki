use crate::der::{self, Tag};
use crate::error::Error;

/// RDNSequence contents, without the outer SEQUENCE tag and length.
#[derive(Clone, Copy)]
pub(crate) struct DirectoryName<'a>(untrusted::Input<'a>);

impl<'a> DirectoryName<'a> {
    pub(super) fn from_rdn_sequence(value: untrusted::Input<'a>) -> Self {
        Self(value)
    }

    pub(super) fn from_explicit(value: untrusted::Input<'a>) -> Result<Self, Error> {
        // directoryName is an explicitly tagged CHOICE (X.680 section 31.2.7).
        value.read_all(Error::BadDer, |reader| {
            der::expect_tag(reader, Tag::Sequence).map(Self)
        })
    }

    /// Match a permitted subtree at complete RDN boundaries (RFC 5280 section 7.1).
    ///
    /// Like mozilla::pkix, compare attributes in encoded order, with identical
    /// OIDs and value bytes. PrintableString and UTF8String may encode the same
    /// value. We intentionally omit case folding, whitespace normalization and
    /// other stringprep processing, and reject other value encodings.
    ///
    /// This can reject otherwise equivalent names. It is only safe for permitted
    /// subtrees: excluded directoryName constraints must be rejected separately.
    pub(super) fn matches_permitted(self, constraint: Self) -> Result<bool, Error> {
        let mut presented = untrusted::Reader::new(self.0);
        let mut constraint = untrusted::Reader::new(constraint.0);
        let mut matches = true;
        while !constraint.at_end() {
            let base = RelativeDistinguishedName::from_der(&mut constraint)?;
            if presented.at_end() {
                base.validate()?;
                matches = false;
            } else {
                let name = RelativeDistinguishedName::from_der(&mut presented)?;
                matches &= name.matches(base)?;
            }
        }
        // Validate the entire name, including RDNs beyond the constraint prefix.
        while !presented.at_end() {
            RelativeDistinguishedName::from_der(&mut presented)?.validate()?;
        }
        Ok(matches)
    }
}

struct RelativeDistinguishedName<'a> {
    attributes: untrusted::Reader<'a>,
    previous: Option<untrusted::Input<'a>>,
}

impl<'a> RelativeDistinguishedName<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let contents = der::expect_tag(reader, Tag::Set)?;
        if contents.is_empty() {
            return Err(Error::BadDer);
        }
        Ok(Self {
            attributes: untrusted::Reader::new(contents),
            previous: None,
        })
    }

    fn matches(mut self, mut other: Self) -> Result<bool, Error> {
        let mut matches = true;
        // Keep validating both RDNs after a mismatch or unequal attribute counts.
        loop {
            match (self.read_attribute()?, other.read_attribute()?) {
                (Some(a), Some(b)) => {
                    matches &= a.oid.as_slice_less_safe() == b.oid.as_slice_less_safe()
                        && a.value.as_slice_less_safe() == b.value.as_slice_less_safe();
                }
                (None, None) => return Ok(matches),
                _ => matches = false,
            }
        }
    }

    fn validate(mut self) -> Result<(), Error> {
        while self.read_attribute()?.is_some() {}
        Ok(())
    }

    fn read_attribute(&mut self) -> Result<Option<AttributeTypeAndValue<'a>>, Error> {
        if self.attributes.at_end() {
            return Ok(None);
        }
        let (encoded, attribute) = self
            .attributes
            .read_partial(AttributeTypeAndValue::from_der)?;
        // DER SET OF ordering is lexicographic over the complete encodings,
        // including their tags and lengths (X.690 section 11.6).
        if self
            .previous
            .is_some_and(|prev| prev.as_slice_less_safe() > encoded.as_slice_less_safe())
        {
            return Err(Error::BadDer);
        }
        self.previous = Some(encoded);
        Ok(Some(attribute))
    }
}

struct AttributeTypeAndValue<'a> {
    oid: untrusted::Input<'a>,
    value: untrusted::Input<'a>,
}

impl<'a> AttributeTypeAndValue<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let contents = der::expect_tag(reader, Tag::Sequence)?;
        contents.read_all(Error::BadDer, |reader| {
            let oid = der::expect_tag(reader, Tag::OID)?;
            // Each OID subidentifier must have a minimal, complete base-128 encoding.
            let mut start = true;
            for byte in oid.as_slice_less_safe() {
                if start && *byte == 0x80 {
                    return Err(Error::BadDer);
                }
                start = byte & 0x80 == 0;
            }
            if oid.is_empty() || !start {
                return Err(Error::BadDer);
            }

            let (tag, value) = der::read_tag_and_get_value(reader)?;
            let bytes = value.as_slice_less_safe();
            if tag == u8::from(Tag::UTF8String) {
                core::str::from_utf8(bytes).map_err(|_| Error::BadDer)?;
            } else if tag == u8::from(Tag::PrintableString) {
                if !bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b))
                {
                    return Err(Error::BadDer);
                }
            } else {
                // Unsupported encodings can be valid DER; this is a policy restriction.
                return Err(Error::NameConstraintViolation);
            }
            Ok(Self { oid, value })
        })
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    const OID_C: &[u8] = &[0x55, 0x04, 0x06];
    const OID_O: &[u8] = &[0x55, 0x04, 0x0a];
    const UTF8: u8 = 0x0c;
    const PRINTABLE: u8 = 0x13;

    fn attribute(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        let mut contents = der::asn1_wrap(Tag::OID, oid);
        let mut value = der::asn1_wrap(Tag::UTF8String, value);
        value[0] = tag;
        contents.extend(value);
        der::asn1_wrap(Tag::Sequence, &contents)
    }

    fn rdn(attributes: &[Vec<u8>]) -> Vec<u8> {
        der::asn1_wrap(Tag::Set, &attributes.concat())
    }

    fn country(value: &[u8]) -> Vec<u8> {
        rdn(&[attribute(OID_C, PRINTABLE, value)])
    }

    fn organization(tag: u8, value: &[u8]) -> Vec<u8> {
        rdn(&[attribute(OID_O, tag, value)])
    }

    fn matches(presented: &[u8], constraint: &[u8]) -> Result<bool, Error> {
        DirectoryName::from_rdn_sequence(untrusted::Input::from(presented)).matches_permitted(
            DirectoryName::from_rdn_sequence(untrusted::Input::from(constraint)),
        )
    }

    #[test]
    fn matches_complete_rdn_prefixes() {
        let c = country(b"US");
        let o = organization(UTF8, b"Example");
        let name = [c.clone(), o.clone()].concat();
        assert_eq!(matches(&name, &name), Ok(true));
        assert_eq!(matches(&name, &c), Ok(true));
        assert_eq!(matches(&c, &name), Ok(false));
        assert_eq!(matches(&name, &o), Ok(false));
        assert_eq!(matches(&[o, c].concat(), &name), Ok(false));
        assert_eq!(matches(&name, &country(b"GB")), Ok(false));
    }

    #[test]
    fn empty_names() {
        let name = country(b"US");
        assert_eq!(matches(&[], &[]), Ok(true));
        assert_eq!(matches(&name, &[]), Ok(true));
        assert_eq!(matches(&[], &name), Ok(false));
    }

    #[test]
    fn printable_and_utf8_with_identical_values_match() {
        let a = organization(UTF8, b"Example");
        let b = organization(PRINTABLE, b"Example");
        assert_eq!(matches(&a, &b), Ok(true));
        assert_eq!(matches(&b, &a), Ok(true));
        let unicode = organization(UTF8, "Société".as_bytes());
        assert_eq!(matches(&unicode, &unicode), Ok(true));
    }

    #[test]
    fn values_are_not_normalized() {
        for (a, b) in [
            ("Example", "EXAMPLE"),
            ("Example", " Example "),
            ("Example Co", "Example  Co"),
            ("Example Co", "Example\tCo"),
            ("Straße", "Strasse"),
            ("é", "e\u{301}"),
        ] {
            assert_eq!(
                matches(
                    &organization(UTF8, a.as_bytes()),
                    &organization(UTF8, b.as_bytes())
                ),
                Ok(false)
            );
        }
    }

    #[test]
    fn attribute_types_must_match() {
        assert_eq!(
            matches(&country(b"US"), &organization(PRINTABLE, b"US")),
            Ok(false)
        );
    }

    #[test]
    fn multivalued_rdns_must_match_completely() {
        let mut attributes = vec![
            attribute(OID_C, PRINTABLE, b"US"),
            attribute(OID_O, UTF8, b"Example"),
        ];
        attributes.sort();
        let name = rdn(&attributes);
        assert_eq!(matches(&name, &name), Ok(true));
        assert_eq!(matches(&name, &country(b"US")), Ok(false));
        assert_eq!(matches(&country(b"US"), &name), Ok(false));
        // Repeating an attribute cannot stand in for a different attribute.
        let duplicates = rdn(&[attributes[0].clone(), attributes[0].clone()]);
        assert_eq!(matches(&duplicates, &name), Ok(false));
    }

    #[test]
    fn noncanonical_set_order_is_rejected() {
        // The encodings have different lengths, so comparing only OIDs would
        // give the wrong DER ordering here.
        let mut attributes = vec![
            attribute(OID_O, UTF8, b"A"),
            attribute(OID_C, PRINTABLE, b"US"),
        ];
        attributes.sort();
        let canonical = rdn(&attributes);
        assert_eq!(matches(&canonical, &canonical), Ok(true));
        attributes.reverse();
        let noncanonical = rdn(&attributes);
        assert_eq!(matches(&noncanonical, &canonical), Err(Error::BadDer));
        assert_eq!(matches(&canonical, &noncanonical), Err(Error::BadDer));
        assert_eq!(matches(&noncanonical, &noncanonical), Err(Error::BadDer));
        for other in [country(b"US"), country(b"GB"), vec![]] {
            assert_eq!(matches(&noncanonical, &other), Err(Error::BadDer));
            assert_eq!(matches(&other, &noncanonical), Err(Error::BadDer));
        }
    }

    #[test]
    fn more_than_sixteen_attributes() {
        let mut attributes = (0..32)
            .map(|i| attribute(&[0x55, 0x04, i], UTF8, b"Example"))
            .collect::<Vec<_>>();
        attributes.sort();
        let name = rdn(&attributes);
        assert_eq!(matches(&name, &name), Ok(true));
    }

    #[test]
    fn unsupported_encodings_are_rejected() {
        for (tag, value) in [
            (0x14, b"Example".as_slice()), // TeletexString
            (0x16, b"Example".as_slice()), // IA5String
            (0x1c, b"\0\0\0E".as_slice()), // UniversalString
            (0x1e, b"\0E".as_slice()),     // BMPString
            (0x04, b"Example".as_slice()), // OCTET STRING
        ] {
            let name = organization(tag, value);
            assert_eq!(matches(&name, &name), Err(Error::NameConstraintViolation));
            assert_eq!(
                matches(&name, &organization(UTF8, b"Example")),
                Err(Error::NameConstraintViolation)
            );
            assert_eq!(
                matches(&organization(UTF8, b"Example"), &name),
                Err(Error::NameConstraintViolation)
            );
            assert_eq!(
                matches(&[country(b"US"), name].concat(), &country(b"US")),
                Err(Error::NameConstraintViolation)
            );
        }
    }

    #[test]
    fn malformed_values_are_rejected() {
        for (tag, value) in [
            (PRINTABLE, b"invalid!".as_slice()),
            (PRINTABLE, b"invalid\t".as_slice()),
            (PRINTABLE, b"\xc3\xa9".as_slice()),
            (UTF8, b"\xc3\x28".as_slice()),
            (UTF8, b"\xed\xa0\x80".as_slice()),
        ] {
            let name = organization(tag, value);
            assert_eq!(matches(&name, &name), Err(Error::BadDer));

            // The first attribute can match or differ; the invalid second
            // attribute must still be rejected, even with no counterpart.
            let name = rdn(&[
                attribute(OID_C, PRINTABLE, b"US"),
                attribute(OID_O, tag, value),
            ]);
            for other in [country(b"US"), country(b"GB"), vec![]] {
                assert_eq!(matches(&name, &other), Err(Error::BadDer));
                assert_eq!(matches(&other, &name), Err(Error::BadDer));
            }
        }
    }

    #[test]
    fn malformed_oids_are_rejected() {
        for oid in [&[][..], &[0x80, 0x2a], &[0x2a, 0x80, 0x01], &[0x2a, 0x81]] {
            let name = rdn(&[attribute(oid, UTF8, b"Example")]);
            assert_eq!(matches(&name, &name), Err(Error::BadDer));
        }
    }

    #[test]
    fn malformed_structure_and_trailing_data_are_rejected() {
        let mut extra_field = der::asn1_wrap(Tag::OID, OID_C);
        extra_field.extend(der::asn1_wrap(Tag::PrintableString, b"US"));
        extra_field.extend([0x05, 0x00]);
        for malformed in [
            vec![0x31, 0x00],                         // empty RDN
            vec![0x31, 0x05, 0x30, 0x0a, 0x00, 0x00], // truncated RDN
            vec![0x31, 0x81, 0x00],                   // nonminimal length
            rdn(&[der::asn1_wrap(Tag::Sequence, &extra_field)]),
            rdn(&[der::asn1_wrap(Tag::OID, OID_C)]), // missing attribute SEQUENCE
        ] {
            assert_eq!(matches(&malformed, &malformed), Err(Error::BadDer));
            let trailing = [country(b"US"), malformed].concat();
            assert_eq!(matches(&trailing, &country(b"US")), Err(Error::BadDer));
            assert_eq!(matches(&trailing, &country(b"GB")), Err(Error::BadDer));
            assert_eq!(matches(&country(b"GB"), &trailing), Err(Error::BadDer));
        }
    }

    #[test]
    fn explicit_wrapper_is_required_and_fully_consumed() {
        let name = country(b"US");
        let explicit = der::asn1_wrap(Tag::Sequence, &name);
        let parsed = DirectoryName::from_explicit(untrusted::Input::from(&explicit)).unwrap();
        assert_eq!(
            parsed.matches_permitted(DirectoryName::from_rdn_sequence(untrusted::Input::from(
                &name
            ))),
            Ok(true)
        );
        for malformed in [&name[..], &[0x30, 0x01], &[0x30, 0x00, 0x00]] {
            assert_eq!(
                DirectoryName::from_explicit(untrusted::Input::from(malformed)).err(),
                Some(Error::BadDer)
            );
        }
    }
}
