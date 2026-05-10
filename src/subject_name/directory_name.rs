// Copyright 2026 webpki Authors.
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

use crate::der::{self, Tag};
use crate::error::Error;

// Real DNs hold one AVA per RDN, occasionally a few. 16 is well above any sane
// observed value while still fitting a `u32` matched-bitmap.
const MAX_AVAS: usize = 16;

const UTF8_STRING_TAG: u8 = Tag::UTF8String.as_u8();
const PRINTABLE_STRING_TAG: u8 = Tag::PrintableString.as_u8();
const IA5_STRING_TAG: u8 = Tag::IA5String.as_u8();
const UNIVERSAL_STRING_TAG: u8 = Tag::UniversalString.as_u8();
const BMP_STRING_TAG: u8 = Tag::BMPString.as_u8();

// X.680 §31.2.7 promotes tags on untagged CHOICE types to EXPLICIT, so the
// `[4]` content of a directoryName GeneralName is a SEQUENCE wrapping the
// RDNSequence. Strip the wrapper to expose the RDNSequence content.
pub(super) fn strip_explicit_sequence(
    value: untrusted::Input<'_>,
) -> Result<untrusted::Input<'_>, Error> {
    let mut reader = untrusted::Reader::new(value);
    let rdn_sequence = der::expect_tag(&mut reader, Tag::Sequence)?;
    if !reader.at_end() {
        return Err(Error::BadDer);
    }
    Ok(rdn_sequence)
}

// https://tools.ietf.org/html/rfc5280#section-7.1 says:
//   A distinguished name DN1 is within the subtree defined by the
//   distinguished name DN2 if DN1 contains at least as many RDNs as DN2,
//   and DN1 and DN2 are a match when trailing RDNs in DN1 are ignored.
//
// Both inputs are RDNSequence content (no outer SEQUENCE tag). Callers
// holding `[4]` directoryName GeneralName bytes should run them through
// `strip_explicit_sequence` first; `Cert::subject` is already RDNSequence
// content.
pub(super) fn presented_directory_name_matches_constraint(
    presented: untrusted::Input<'_>,
    constraint: untrusted::Input<'_>,
) -> Result<bool, Error> {
    if constraint.is_empty() {
        return Ok(true);
    }
    if presented.is_empty() {
        return Ok(false);
    }
    let mut presented = untrusted::Reader::new(presented);
    let mut constraint = untrusted::Reader::new(constraint);
    while !constraint.at_end() {
        if presented.at_end() {
            return Ok(false);
        }
        let p_rdn = der::expect_tag(&mut presented, Tag::Set)?;
        let c_rdn = der::expect_tag(&mut constraint, Tag::Set)?;
        if !rdn_eq(p_rdn, c_rdn)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// https://tools.ietf.org/html/rfc5280#section-7.1 says:
//   Two relative distinguished names RDN1 and RDN2 match if they have the
//   same number of naming attributes and for each naming attribute in RDN1
//   there is a matching naming attribute in RDN2.
//
// The bitmap tracks which `b` AVAs have already been claimed so that
// duplicate AVAs in `a` cannot match the same `b` AVA twice.
fn rdn_eq(a: untrusted::Input<'_>, b: untrusted::Input<'_>) -> Result<bool, Error> {
    let mut a_avas: [Option<untrusted::Input<'_>>; MAX_AVAS] = [None; MAX_AVAS];
    let mut b_avas: [Option<untrusted::Input<'_>>; MAX_AVAS] = [None; MAX_AVAS];
    let a_n = collect_avas(a, &mut a_avas)?;
    let b_n = collect_avas(b, &mut b_avas)?;
    if a_n != b_n {
        return Ok(false);
    }

    let mut matched: u32 = 0;
    for a_ava in a_avas.iter().take(a_n).map(|opt| opt.unwrap()) {
        let mut found = false;
        for (j, b_ava) in b_avas.iter().take(b_n).map(|opt| opt.unwrap()).enumerate() {
            if matched & (1 << j) != 0 {
                continue;
            }
            if ava_eq(a_ava, b_ava)? {
                matched |= 1 << j;
                found = true;
                break;
            }
        }
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}

fn collect_avas<'a>(
    rdn: untrusted::Input<'a>,
    out: &mut [Option<untrusted::Input<'a>>; MAX_AVAS],
) -> Result<usize, Error> {
    let mut reader = untrusted::Reader::new(rdn);
    let mut count = 0;
    while !reader.at_end() {
        if count >= MAX_AVAS {
            return Err(Error::BadDer);
        }
        out[count] = Some(der::expect_tag(&mut reader, Tag::Sequence)?);
        count += 1;
    }
    Ok(count)
}

// And https://tools.ietf.org/html/rfc5280#section-7.1 says:
//   Two naming attributes match if the attribute types are the same and
//   the values of the attributes are an exact match after processing with
//   the string preparation algorithm.
fn ava_eq(a: untrusted::Input<'_>, b: untrusted::Input<'_>) -> Result<bool, Error> {
    let mut a = untrusted::Reader::new(a);
    let mut b = untrusted::Reader::new(b);
    let a_oid = der::expect_tag(&mut a, Tag::OID)?;
    let b_oid = der::expect_tag(&mut b, Tag::OID)?;
    if a_oid.as_slice_less_safe() != b_oid.as_slice_less_safe() {
        return Ok(false);
    }
    let (a_tag, a_value) = der::read_tag_and_get_value(&mut a)?;
    let (b_tag, b_value) = der::read_tag_and_get_value(&mut b)?;
    if !a.at_end() || !b.at_end() {
        return Err(Error::BadDer);
    }
    Ok(ava_value_eq(
        a_tag,
        a_value.as_slice_less_safe(),
        b_tag,
        b_value.as_slice_less_safe(),
    ))
}

fn ava_value_eq(a_tag: u8, a: &[u8], b_tag: u8, b: &[u8]) -> bool {
    if is_normalizable_string(a_tag) && is_normalizable_string(b_tag) {
        return normalized_string_eq(a_tag, a, b_tag, b);
    }
    a_tag == b_tag && a == b
}

fn is_normalizable_string(tag: u8) -> bool {
    matches!(
        tag,
        UTF8_STRING_TAG
            | PRINTABLE_STRING_TAG
            | IA5_STRING_TAG
            | UNIVERSAL_STRING_TAG
            | BMP_STRING_TAG
    )
}

// https://tools.ietf.org/html/rfc5280#section-7.1 says:
//   Conforming implementations MUST use the LDAP StringPrep profile
//   (including insignificant space handling), as specified in [RFC4518],
//   as the basis for comparison of distinguished name attributes encoded
//   in either PrintableString or UTF8String.
//
// We do not implement RFC 4518 in full — Unicode case folding (RFC 3454
// Appendix B.2), NFKC normalization, the full RFC 3454 prohibit list, and
// a BiDi check would each pull in substantial Unicode tables. The inputs
// that exercise those steps don't appear in WebPKI in practice:
// directoryName name constraints are rare, and non-ASCII DN values inside
// them are rarer still. Mirroring BoringSSL pki, we write just enough to
// handle the inputs that exist in the wild and stop there: ASCII-only
// case folding and insignificant-space handling, plus a small subset of
// step 1 (Transcode) and step 4 (Prohibit) checks (see `CodePoints` and
// `decode_unicode_scalar`). Where we report a match for a given pair of
// valid Unicode strings, RFC 4518 applied to the same content would too.
fn normalized_string_eq(a_tag: u8, a: &[u8], b_tag: u8, b: &[u8]) -> bool {
    let (Some(a_iter), Some(b_iter)) = (CodePoints::new(a_tag, a), CodePoints::new(b_tag, b))
    else {
        return false;
    };
    let mut a = Normalizer::new(a_iter);
    let mut b = Normalizer::new(b_iter);
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(Ok(x)), Some(Ok(y))) if x == y => continue,
            _ => return false,
        }
    }
}

// Streaming code-point iterator over a string-typed AVA value. `new`
// validates the encoding (https://tools.ietf.org/html/rfc4518#section-2.1
// "Transcode"); `next` rejects surrogates (via `char::from_u32`) and the
// Unicode noncharacters listed in RFC 3454 Table C.4 — the slice of RFC
// 4518 step 4 ("Prohibit") we implement.
enum CodePoints<'a> {
    /// PrintableString or IA5String: each byte is one code point.
    Latin1(&'a [u8]),
    /// UTF8String: pre-validated; iterate decoded chars.
    Utf8(core::str::Chars<'a>),
    /// BMPString: 2-byte big-endian units.
    Bmp(&'a [u8]),
    /// UniversalString: 4-byte big-endian units.
    Universal(&'a [u8]),
}

impl<'a> CodePoints<'a> {
    fn new(tag: u8, bytes: &'a [u8]) -> Option<Self> {
        match tag {
            PRINTABLE_STRING_TAG => bytes
                .iter()
                .all(|&b| is_printable_string_byte(b))
                .then_some(Self::Latin1(bytes)),
            IA5_STRING_TAG => bytes.is_ascii().then_some(Self::Latin1(bytes)),
            UTF8_STRING_TAG => Some(Self::Utf8(core::str::from_utf8(bytes).ok()?.chars())),
            BMP_STRING_TAG => (bytes.len() % 2 == 0).then_some(Self::Bmp(bytes)),
            UNIVERSAL_STRING_TAG => (bytes.len() % 4 == 0).then_some(Self::Universal(bytes)),
            _ => None,
        }
    }
}

impl Iterator for CodePoints<'_> {
    type Item = Result<char, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Latin1(bytes) => {
                let (head, rest) = bytes.split_first()?;
                *bytes = rest;
                Some(Ok(char::from(*head)))
            }
            Self::Utf8(chars) => chars.next().map(Ok),
            Self::Bmp(bytes) => {
                let (head, rest) = bytes.split_first_chunk::<2>()?;
                *bytes = rest;
                Some(decode_unicode_scalar(u32::from(u16::from_be_bytes(*head))).ok_or(()))
            }
            Self::Universal(bytes) => {
                let (head, rest) = bytes.split_first_chunk::<4>()?;
                *bytes = rest;
                Some(decode_unicode_scalar(u32::from_be_bytes(*head)).ok_or(()))
            }
        }
    }
}

// X.680 PrintableString charset: alphanumerics, space, and the symbols
// below. `*` is *not* in the set.
fn is_printable_string_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
}

// Decode a raw scalar from BMPString/UniversalString. Rejects surrogates
// and out-of-range values (via `char::from_u32`) plus the Unicode
// noncharacters listed in RFC 3454 Table C.4.
fn decode_unicode_scalar(cp: u32) -> Option<char> {
    let c = char::from_u32(cp)?;
    let v = u32::from(c);
    if (v & 0xFFFE) == 0xFFFE || (0xFDD0..=0xFDEF).contains(&v) {
        return None;
    }
    Some(c)
}

// https://tools.ietf.org/html/rfc4518#section-2.6.1 ("Insignificant Space
// Handling") describes prep as: leading/trailing space collapsed to one
// SPACE and inner runs of spaces collapsed to two SPACEs. We implement an
// equivalent matching rule — trim leading/trailing whitespace and collapse
// internal runs to one SPACE — which yields the same answer when both
// sides go through the same normalization.
//
// Combined with ASCII A–Z to a–z folding, this is the ASCII-only
// approximation of caseIgnoreMatch + insignificant-space handling.
struct Normalizer<'a> {
    inner: CodePoints<'a>,
    state: NormState,
    buffered: Option<char>,
}

#[derive(PartialEq)]
enum NormState {
    Leading,
    Content,
    PendingWs,
    Done,
}

impl<'a> Normalizer<'a> {
    fn new(inner: CodePoints<'a>) -> Self {
        Self {
            inner,
            state: NormState::Leading,
            buffered: None,
        }
    }
}

impl Iterator for Normalizer<'_> {
    type Item = Result<char, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.buffered.take() {
            self.state = NormState::Content;
            return Some(Ok(c));
        }
        loop {
            if self.state == NormState::Done {
                return None;
            }
            let c = match self.inner.next() {
                None => {
                    self.state = NormState::Done;
                    return None;
                }
                Some(Err(e)) => {
                    self.state = NormState::Done;
                    return Some(Err(e));
                }
                Some(Ok(c)) => c,
            };
            let is_ws = is_ascii_ws(c);
            match (&self.state, is_ws) {
                (NormState::Leading, true) => continue,
                (NormState::Leading, false) => {
                    self.state = NormState::Content;
                    return Some(Ok(c.to_ascii_lowercase()));
                }
                (NormState::Content, true) => {
                    self.state = NormState::PendingWs;
                    continue;
                }
                (NormState::Content, false) => return Some(Ok(c.to_ascii_lowercase())),
                (NormState::PendingWs, true) => continue,
                (NormState::PendingWs, false) => {
                    // Emit a single space now; defer the just-read code point
                    // until the next call.
                    self.buffered = Some(c.to_ascii_lowercase());
                    return Some(Ok(' '));
                }
                (NormState::Done, _) => return None,
            }
        }
    }
}

// Wider than `char::is_ascii_whitespace` (which excludes U+000B); covers
// the C0 whitespace family that RFC 4518 §2.2 ("Map") folds to SPACE
// before the insignificant-space step.
fn is_ascii_ws(c: char) -> bool {
    matches!(c, '\t'..='\r' | ' ')
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    // countryName = 2.5.4.6
    const OID_C: &[u8] = &[0x55, 0x04, 0x06];
    // organizationName = 2.5.4.10
    const OID_O: &[u8] = &[0x55, 0x04, 0x0A];

    fn ava(oid: &[u8], val_tag: u8, val: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(u8::try_from(oid.len()).unwrap());
        inner.extend_from_slice(oid);
        inner.push(val_tag);
        inner.push(u8::try_from(val.len()).unwrap());
        inner.extend_from_slice(val);
        let mut out = vec![0x30, u8::try_from(inner.len()).unwrap()];
        out.extend(inner);
        out
    }

    fn rdn(avas: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        for ava in avas {
            content.extend_from_slice(ava);
        }
        let mut out = vec![0x31, u8::try_from(content.len()).unwrap()];
        out.extend(content);
        out
    }

    fn dn(rdns: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in rdns {
            out.extend_from_slice(r);
        }
        out
    }

    fn matches(presented: &[u8], constraint: &[u8]) -> Result<bool, Error> {
        presented_directory_name_matches_constraint(
            untrusted::Input::from(presented),
            untrusted::Input::from(constraint),
        )
    }

    #[test]
    fn empty_constraint_matches_anything() {
        assert_eq!(matches(&[], &[]), Ok(true));
        let dn = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        assert_eq!(matches(&dn, &[]), Ok(true));
    }

    #[test]
    fn empty_presented_does_not_match_non_empty_constraint() {
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        assert_eq!(matches(&[], &constraint), Ok(false));
    }

    #[test]
    fn exact_match() {
        let d = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        assert_eq!(matches(&d, &d), Ok(true));
    }

    #[test]
    fn proper_prefix_match() {
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        let presented = dn(&[
            rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")]),
            rdn(&[ava(OID_O, UTF8_STRING_TAG, b"Foo")]),
        ]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn presented_shorter_than_constraint_does_not_match() {
        let constraint = dn(&[
            rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")]),
            rdn(&[ava(OID_O, UTF8_STRING_TAG, b"Foo")]),
        ]);
        let presented = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn different_value_does_not_match() {
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        let presented = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"DE")])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn cross_type_string_match() {
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        let presented = dn(&[rdn(&[ava(OID_C, UTF8_STRING_TAG, b"US")])]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn case_fold_match() {
        let constraint = dn(&[rdn(&[ava(OID_O, UTF8_STRING_TAG, b"Foo")])]);
        let presented = dn(&[rdn(&[ava(OID_O, PRINTABLE_STRING_TAG, b"FOO")])]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn whitespace_normalization_match() {
        let constraint = dn(&[rdn(&[ava(OID_O, UTF8_STRING_TAG, b"foo bar")])]);
        let presented = dn(&[rdn(&[ava(OID_O, UTF8_STRING_TAG, b"  Foo   Bar  ")])]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn multivalued_rdn_reordered_match() {
        let a = ava(OID_C, PRINTABLE_STRING_TAG, b"US");
        let b = ava(OID_O, UTF8_STRING_TAG, b"Foo");
        let constraint = dn(&[rdn(&[a.clone(), b.clone()])]);
        let presented = dn(&[rdn(&[b, a])]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn multivalued_rdn_count_mismatch_does_not_match() {
        let a = ava(OID_C, PRINTABLE_STRING_TAG, b"US");
        let b = ava(OID_O, UTF8_STRING_TAG, b"Foo");
        let constraint = dn(&[rdn(core::slice::from_ref(&a))]);
        let presented = dn(&[rdn(&[a, b])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn bmp_string_matches_printable_string() {
        // BMPString "US" = 00 55 00 53
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        let presented = dn(&[rdn(&[ava(
            OID_C,
            BMP_STRING_TAG,
            &[0x00, 0x55, 0x00, 0x53],
        )])]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn bmp_string_surrogate_does_not_match() {
        // 0xD800 is a high surrogate — illegal in BMPString.
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        let presented = dn(&[rdn(&[ava(OID_C, BMP_STRING_TAG, &[0xD8, 0x00])])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn universal_string_match() {
        // UniversalString "US" = 00 00 00 55 00 00 00 53
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"US")])]);
        let presented = dn(&[rdn(&[ava(
            OID_C,
            UNIVERSAL_STRING_TAG,
            &[0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x53],
        )])]);
        assert_eq!(matches(&presented, &constraint), Ok(true));
    }

    #[test]
    fn teletex_string_binary_only() {
        // TeletexString matches only against TeletexString with identical bytes.
        let teletex_us = ava(OID_C, 0x14, b"US");
        let printable_us = ava(OID_C, PRINTABLE_STRING_TAG, b"US");
        assert_eq!(
            matches(
                &dn(&[rdn(core::slice::from_ref(&teletex_us))]),
                &dn(&[rdn(core::slice::from_ref(&teletex_us))]),
            ),
            Ok(true)
        );
        assert_eq!(
            matches(&dn(&[rdn(&[teletex_us])]), &dn(&[rdn(&[printable_us])])),
            Ok(false)
        );
    }

    #[test]
    fn different_oid_does_not_match() {
        let constraint = dn(&[rdn(&[ava(OID_C, PRINTABLE_STRING_TAG, b"Foo")])]);
        let presented = dn(&[rdn(&[ava(OID_O, PRINTABLE_STRING_TAG, b"Foo")])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn malformed_rdn_is_bad_der() {
        // SET tag with truncated content.
        let bad = vec![0x31, 0x05, 0x30, 0x0A, 0x00, 0x00];
        assert_eq!(matches(&bad, &bad), Err(Error::BadDer));
    }

    #[test]
    fn malformed_printable_string_does_not_match() {
        // `!` is not in the X.680 PrintableString charset.
        let bad = ava(OID_O, PRINTABLE_STRING_TAG, b"foo!");
        let good = ava(OID_O, UTF8_STRING_TAG, b"foo!");
        let constraint = dn(&[rdn(core::slice::from_ref(&bad))]);
        let presented = dn(&[rdn(core::slice::from_ref(&good))]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
        // And it's not equal to itself either: validation rejects the value
        // before normalization runs.
        assert_eq!(matches(&dn(&[rdn(&[bad])]), &constraint), Ok(false));
    }

    #[test]
    fn ia5_string_with_high_byte_does_not_match() {
        let bad = ava(OID_O, IA5_STRING_TAG, b"foo\xC3\x9F"); // 'ß' as UTF-8
        let other = ava(OID_O, UTF8_STRING_TAG, b"foo\xC3\x9F");
        let constraint = dn(&[rdn(core::slice::from_ref(&bad))]);
        let presented = dn(&[rdn(core::slice::from_ref(&other))]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn invalid_utf8_string_does_not_match() {
        // 0xC3 0x28 is an invalid UTF-8 sequence (lone lead byte).
        let bad = ava(OID_O, UTF8_STRING_TAG, b"\xC3\x28");
        let constraint = dn(&[rdn(core::slice::from_ref(&bad))]);
        let presented = dn(&[rdn(core::slice::from_ref(&bad))]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn bmp_string_odd_length_does_not_match() {
        // BMPString must be a multiple of 2 bytes.
        let bad = ava(OID_O, BMP_STRING_TAG, &[0x00, 0x55, 0x00]);
        let constraint = dn(&[rdn(core::slice::from_ref(&bad))]);
        let presented = dn(&[rdn(core::slice::from_ref(&bad))]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn bmp_string_noncharacter_does_not_match() {
        // U+FFFE is a Unicode noncharacter (RFC 3454 Table C.4).
        let constraint = dn(&[rdn(&[ava(OID_O, UTF8_STRING_TAG, b"foo")])]);
        let presented = dn(&[rdn(&[ava(OID_O, BMP_STRING_TAG, &[0xFF, 0xFE])])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn universal_string_noncharacter_does_not_match() {
        // U+FDD0 is a Unicode noncharacter (RFC 3454 Table C.4).
        let constraint = dn(&[rdn(&[ava(OID_O, UTF8_STRING_TAG, b"foo")])]);
        let presented = dn(&[rdn(&[ava(
            OID_O,
            UNIVERSAL_STRING_TAG,
            &[0x00, 0x00, 0xFD, 0xD0],
        )])]);
        assert_eq!(matches(&presented, &constraint), Ok(false));
    }

    #[test]
    fn normalizer_drops_leading_trailing_collapses_internal() {
        let inner = CodePoints::new(UTF8_STRING_TAG, b"  hello   World  ").unwrap();
        let out: alloc::string::String = Normalizer::new(inner).map(|r| r.unwrap()).collect();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn normalizer_only_whitespace_yields_empty() {
        let inner = CodePoints::new(UTF8_STRING_TAG, b"   \t\n   ").unwrap();
        assert_eq!(Normalizer::new(inner).count(), 0);
    }
}
