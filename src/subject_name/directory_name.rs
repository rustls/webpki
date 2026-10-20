use crate::der::{self, Tag};
use crate::error::Error;

/// A subject RDNSequence or an explicitly tagged directoryName GeneralName.
#[derive(Clone, Copy)]
pub(crate) enum DirectoryName<'a> {
    RdnSequence(untrusted::Input<'a>),
    Explicit(untrusted::Input<'a>),
}

impl<'a> DirectoryName<'a> {
    fn rdn_sequence(self) -> Result<untrusted::Input<'a>, Error> {
        match self {
            Self::RdnSequence(value) => Ok(value),
            // Only unwrap directoryName when matching constraints, so an unused
            // SAN does not affect DNS/IP verification or name iteration.
            // directoryName is an explicitly tagged CHOICE (X.680 section 31.2.7).
            Self::Explicit(value) => value.read_all(Error::BadDer, |reader| {
                der::expect_tag(reader, Tag::Sequence)
            }),
        }
    }

    /// Match a permitted subtree at complete RDN boundaries (RFC 5280 section 7.1).
    ///
    /// Like mozilla::pkix, compare attributes in encoded order, with identical
    /// OIDs and value bytes. PrintableString and UTF8String may encode the same
    /// value. IA5String requires the same tag and bytes on both sides. We omit
    /// case folding, whitespace normalization and other stringprep processing,
    /// and reject other value encodings in compared attributes.
    ///
    /// This can reject otherwise equivalent names. It is only safe for permitted
    /// subtrees: excluded directoryName constraints must be rejected separately.
    /// Stop at the end of the prefix or the first mismatch: validating unused
    /// suffixes would multiply their cost by the number of constraints.
    pub(super) fn matches_permitted(self, constraint: Self) -> Result<bool, Error> {
        let mut presented = untrusted::Reader::new(self.rdn_sequence()?);
        let mut constraint = untrusted::Reader::new(constraint.rdn_sequence()?);
        while !constraint.at_end() {
            if presented.at_end() {
                return Ok(false);
            }
            let base = RelativeDistinguishedName::from_der(&mut constraint)?;
            let name = RelativeDistinguishedName::from_der(&mut presented)?;
            if !name.matches(base)? {
                return Ok(false);
            }
        }
        Ok(true)
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
        while !self.attributes.at_end() && !other.attributes.at_end() {
            if !self.read_attribute()?.matches(other.read_attribute()?)? {
                return Ok(false);
            }
        }
        Ok(self.attributes.at_end() && other.attributes.at_end())
    }

    fn read_attribute(&mut self) -> Result<AttributeTypeAndValue<'a>, Error> {
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
        Ok(attribute)
    }
}

struct AttributeTypeAndValue<'a> {
    oid: untrusted::Input<'a>,
    tag: u8,
    value: untrusted::Input<'a>,
}

impl<'a> AttributeTypeAndValue<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let contents = der::expect_tag(reader, Tag::Sequence)?;
        contents.read_all(Error::BadDer, |reader| {
            let oid = der::expect_tag(reader, Tag::OID)?;
            let (tag, value) = der::read_tag_and_get_value(reader)?;
            if tag != u8::from(Tag::UTF8String)
                && tag != u8::from(Tag::PrintableString)
                && tag != u8::from(Tag::IA5String)
            {
                // Unsupported encodings can be valid DER; this is a policy restriction.
                return Err(Error::NameConstraintViolation);
            }
            Ok(Self { oid, tag, value })
        })
    }

    fn matches(self, other: Self) -> Result<bool, Error> {
        let tags_match = self.tag == other.tag
            || (self.tag == u8::from(Tag::UTF8String)
                && other.tag == u8::from(Tag::PrintableString))
            || (self.tag == u8::from(Tag::PrintableString)
                && other.tag == u8::from(Tag::UTF8String));
        if !tags_match
            || self.oid.as_slice_less_safe() != other.oid.as_slice_less_safe()
            || self.value.as_slice_less_safe() != other.value.as_slice_less_safe()
        {
            return Ok(false);
        }

        // Validate only after comparing lengths and bytes. Otherwise many short
        // constraints could repeatedly scan a large, mismatching OID or value.
        self.validate()?;
        other.validate()?;
        Ok(true)
    }

    fn validate(&self) -> Result<(), Error> {
        // Each OID subidentifier must have a minimal, complete base-128 encoding.
        let mut start = true;
        for byte in self.oid.as_slice_less_safe() {
            if start && *byte == 0x80 {
                return Err(Error::BadDer);
            }
            start = byte & 0x80 == 0;
        }
        if self.oid.is_empty() || !start {
            return Err(Error::BadDer);
        }

        let bytes = self.value.as_slice_less_safe();
        if self.tag == u8::from(Tag::UTF8String) {
            core::str::from_utf8(bytes).map_err(|_| Error::BadDer)?;
        } else if self.tag == u8::from(Tag::PrintableString) {
            if !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b))
            {
                return Err(Error::BadDer);
            }
        } else if !bytes.is_ascii() {
            return Err(Error::BadDer);
        }
        Ok(())
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
    const IA5: u8 = 0x16;

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
        DirectoryName::RdnSequence(untrusted::Input::from(presented)).matches_permitted(
            DirectoryName::RdnSequence(untrusted::Input::from(constraint)),
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
    fn ia5_requires_identical_tags_and_bytes() {
        let oid_dc = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
        let name = rdn(&[attribute(oid_dc, IA5, b"example")]);
        assert_eq!(matches(&name, &name), Ok(true));
        let different = rdn(&[attribute(oid_dc, IA5, b"EXAMPLE")]);
        assert_eq!(matches(&name, &different), Ok(false));
        for tag in [UTF8, PRINTABLE] {
            let other = rdn(&[attribute(oid_dc, tag, b"example")]);
            assert_eq!(matches(&name, &other), Ok(false));
            assert_eq!(matches(&other, &name), Ok(false));
        }
    }

    #[test]
    fn matching_stops_at_prefix_end_or_first_mismatch() {
        // Invalid trailing DER makes any attempt to parse the suffix observable
        // without relying on timing measurements.
        let name = [country(b"US"), vec![0xff]].concat();
        assert_eq!(matches(&name, &country(b"US")), Ok(true));
        assert_eq!(matches(&name, &country(b"GB")), Ok(false));
        assert_eq!(matches(&country(b"US"), &name), Ok(false));
        assert_eq!(matches(&country(b"GB"), &name), Ok(false));
        assert_eq!(matches(&name, &[]), Ok(true));
        assert_eq!(matches(&[], &name), Ok(false));

        // The same early exits apply inside a multi-valued RDN, but every
        // attribute must match for the RDN as a whole to match.
        let name = rdn(&[attribute(OID_C, PRINTABLE, b"US"), vec![0xff]]);
        for other in [country(b"US"), country(b"GB")] {
            assert_eq!(matches(&name, &other), Ok(false));
            assert_eq!(matches(&other, &name), Ok(false));
        }
    }

    #[test]
    fn large_mismatching_attributes_are_not_validated() {
        let other = organization(UTF8, b"Example");
        // A long invalid value or OID would fail validation if scanned. Length
        // comparison is enough to reject it, even against many short constraints.
        for name in [
            organization(UTF8, &vec![0xff; 60_000]),
            rdn(&[attribute(&vec![0x80; 60_000], UTF8, b"Example")]),
        ] {
            assert_eq!(matches(&name, &other), Ok(false));
            assert_eq!(matches(&other, &name), Ok(false));
        }
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
        assert_eq!(matches(&noncanonical, &canonical), Ok(false));
        assert_eq!(matches(&canonical, &noncanonical), Ok(false));
        assert_eq!(matches(&noncanonical, &noncanonical), Err(Error::BadDer));
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
                Ok(true)
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
            (IA5, b"\x80".as_slice()),
        ] {
            let name = organization(tag, value);
            assert_eq!(matches(&name, &name), Err(Error::BadDer));
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
    fn malformed_compared_structure_is_rejected() {
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
        }
    }

    #[test]
    fn explicit_wrapper_is_required_and_fully_consumed() {
        let name = country(b"US");
        let explicit = der::asn1_wrap(Tag::Sequence, &name);
        let parsed = DirectoryName::Explicit(untrusted::Input::from(&explicit));
        let subject = DirectoryName::RdnSequence(untrusted::Input::from(&name));
        assert_eq!(parsed.matches_permitted(subject), Ok(true));
        assert_eq!(subject.matches_permitted(parsed), Ok(true));
        for malformed in [&name[..], &[0x30, 0x01], &[0x30, 0x00, 0x00]] {
            let malformed = DirectoryName::Explicit(untrusted::Input::from(malformed));
            assert_eq!(malformed.matches_permitted(subject), Err(Error::BadDer));
            assert_eq!(subject.matches_permitted(malformed), Err(Error::BadDer));
        }
    }
}
