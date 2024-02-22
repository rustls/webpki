//! Certificate policies extension.
//!
//! The `cert_policy` feature is required.

#![cfg(feature = "cert_policy")]

use core::ops::ControlFlow;

use crate::cert::Cert;
use crate::der::{self, FromDer, Tag};
use crate::error::{DerTypeId, Error};
use crate::verify_cert::PathNode;

// Checks if the individual certificate policies extensions conform to the
// specification described in RFC 5280, Section 4.2.1.4.
//
// Checks:
// - policy OID duplication
//
//   RFC 5280, Section 4.2.1.4:
//   > A certificate policy OID MUST NOT appear more than once in a
//   > certificate policies extension.
//
// - format of optional policy qualifiers:
//
//   - only CPS Pointer (URI) and User Notice are allowed
//
//     RFC 5280, Section 4.2.1.4:
//     > To promote interoperability, this profile RECOMMENDS that policy
//     > information terms consist of only an OID. Where an OID alone is
//     > insufficient, this profile strongly recommends that the use of
//     > qualifiers be limited to those identified in this section.
//     >
//     > This specification defines two policy qualifier types for use by
//     > certificate policy writers and certificate issuers.  The qualifier
//     > types are the CPS Pointer and User Notice qualifiers.
//
//     All the other qualifiers fall into "unknown" category and are rejected.
pub(crate) fn check_certificate_policies(
    path: &PathNode<'_>,
) -> Result<(), ControlFlow<Error, Error>> {
    for path in path.iter() {
        check_certificate_policies_in_cert(path.cert)?;
    }
    Ok(())
}

fn check_certificate_policies_in_cert(cert: &Cert) -> Result<(), ControlFlow<Error, Error>> {
    if let Some(policies) = cert.certificate_policies {
        if policies.is_empty() {
            return Err(ControlFlow::Continue(Error::EmptyCertificatePolicies));
        }
        check_certificate_policy_oid_duplication(policies)?;
        check_certificate_policy_qualifiers(policies)?;
    }
    Ok(())
}

fn check_certificate_policy_oid_duplication(policies: untrusted::Input<'_>) -> Result<(), Error> {
    let mut policy_iter = PolicyIterator::new(policies);
    loop {
        let policy = policy_iter.next();
        if let Some(policy) = policy {
            let policy = policy?;
            // compares `policy` and remaining ones
            for other_policy in policy_iter.duplicate() {
                let other_policy = other_policy?;
                if policy.id.as_slice_less_safe() == other_policy.id.as_slice_less_safe() {
                    return Err(Error::DuplicateCertificatePolicyOid);
                }
            }
        } else {
            break;
        }
    }
    Ok(())
}

fn check_certificate_policy_qualifiers(policies: untrusted::Input<'_>) -> Result<(), Error> {
    for policy in PolicyIterator::new(policies) {
        let policy = policy?;
        for qualifier in policy.qualifiers() {
            let qualifier = qualifier?;
            if qualifier.unknown() {
                return Err(Error::UnknownPolicyQualifier);
            }
        }
    }
    Ok(())
}

pub(crate) struct PolicyIterator<'a> {
    // `None` means that the end of the input has been reached.
    policies: Option<untrusted::Reader<'a>>,
}

// Represents a sequence of certificate policies defined in
// RFC 5280, Section 4.2.1.4:
//
// ```
// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
// ```
//
// Note that SEQUENCE tag has already been consumed.
impl<'a> PolicyIterator<'a> {
    pub(crate) fn new(policies: untrusted::Input<'a>) -> Self {
        PolicyIterator {
            policies: Some(untrusted::Reader::new(policies)),
        }
    }

    // Works around the limitation that
    // [`untrusted::Reader`] does not implement [`Clone`].
    // There is some overhead for boundary check.
    fn duplicate(&mut self) -> Self {
        if let Some(policies) = self.policies.as_mut() {
            let underlying = policies.read_bytes_to_end();
            // restores the original Reader and creates a new one
            self.policies = Some(untrusted::Reader::new(underlying));
            PolicyIterator {
                policies: Some(untrusted::Reader::new(underlying)),
            }
        } else {
            PolicyIterator { policies: None }
        }
    }
}

impl<'a> Iterator for PolicyIterator<'a> {
    type Item = Result<CertificatePolicy<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(policies) = self.policies.as_mut() {
            if !policies.at_end() {
                let err = match CertificatePolicy::from_der(policies) {
                    Ok(policy) => return Some(Ok(policy)),
                    Err(err) => err,
                };

                // Make sure we don't yield any items after this error.
                self.policies = None;
                return Some(Err(err));
            } else {
                self.policies = None;
            }
        }
        None
    }
}

/// Represents a single policy information defined in
/// RFC 5280, Section 4.2.1.4.
///
/// ```text
/// PolicyInformation ::= SEQUENCE {
///      policyIdentifier   CertPolicyId,
///      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
///                              PolicyQualifierInfo OPTIONAL }
/// ```
#[derive(Clone)]
pub struct CertificatePolicy<'a> {
    id: untrusted::Input<'a>,
    qualifiers: Option<untrusted::Input<'a>>,
}

impl<'a> CertificatePolicy<'a> {
    /// Returns the policy OID.
    pub fn policy_oid(&self) -> PolicyOid<'a> {
        PolicyOid::from(self.id)
    }

    /// Iterates over policy qualifiers.
    pub fn qualifiers(&self) -> impl Iterator<Item = Result<PolicyQualifierInfo<'a>, Error>> {
        PolicyQualifierInfoIterator::new(self.qualifiers)
    }
}

impl<'a> FromDer<'a> for CertificatePolicy<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        der::nested(
            reader,
            Tag::Sequence,
            Error::TrailingData(DerTypeId::CertificatePolicy),
            |reader| {
                let id = der::expect_tag(reader, Tag::OID)?;
                let qualifiers = if !reader.at_end() {
                    let qualifiers = der::expect_tag(reader, Tag::Sequence)?;
                    if qualifiers.is_empty() {
                        return Err(Error::BadDer);
                    }
                    Some(qualifiers)
                } else {
                    None
                };
                Ok(Self { id, qualifiers })
            },
        )
    }

    const TYPE_ID: DerTypeId = DerTypeId::CertificatePolicy;
}

// Represents a sequence of policy qualifier information defined in
// RFC 5280, Section 4.2.1.4:
//
// ```
// policyQualifiers   SEQUENCE SIZE (1..MAX) OF
//                              PolicyQualifierInfo OPTIONAL }
// ```
//
// Note that SEQUENCE tag has already been consumed.
struct PolicyQualifierInfoIterator<'a> {
    // `None` means that the end of the input has been reached or
    // qualifiers are omitted
    qualifiers: Option<untrusted::Reader<'a>>,
}

impl<'a> PolicyQualifierInfoIterator<'a> {
    fn new(qualifiers: Option<untrusted::Input<'a>>) -> Self {
        Self {
            qualifiers: qualifiers.map(untrusted::Reader::new),
        }
    }
}

impl<'a> Iterator for PolicyQualifierInfoIterator<'a> {
    type Item = Result<PolicyQualifierInfo<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(qualifiers) = self.qualifiers.as_mut() {
            if !qualifiers.at_end() {
                let err = match PolicyQualifierInfo::from_der(qualifiers) {
                    Ok(qualifier) => return Some(Ok(qualifier)),
                    Err(err) => err,
                };

                // Make sure we don't yield any items after this error.
                self.qualifiers = None;
                return Some(Err(err));
            } else {
                self.qualifiers = None;
            }
        }
        None
    }
}

/// Represents a single policy qualifier information defined in
/// RFC 5280, Section 4.2.1.4.
///
/// ```text
/// PolicyQualifierInfo ::= SEQUENCE {
///      policyQualifierId  PolicyQualifierId,
///      qualifier          ANY DEFINED BY policyQualifierId }
///
/// -- policyQualifierIds for Internet policy qualifiers
///
/// id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
/// id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
/// id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
///
/// PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
/// ```
pub struct PolicyQualifierInfo<'a> {
    /// Policy qualifier ID.
    ///
    /// The OID tag and length are not included.
    pub id: untrusted::Input<'a>,
    /// Optional fields of the policy qualifier.
    pub qualifier: PolicyQualifier<'a>,
}

impl<'a> PolicyQualifierInfo<'a> {
    fn unknown(&self) -> bool {
        matches!(&self.qualifier, PolicyQualifier::Unknown(_))
    }
}

impl<'a> FromDer<'a> for PolicyQualifierInfo<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        der::nested(
            reader,
            Tag::Sequence,
            Error::TrailingData(DerTypeId::PolicyQualifierInfo),
            |reader| {
                let id = der::expect_tag(reader, Tag::OID)?;
                let qualifier = match id.as_slice_less_safe() {
                    POLICY_QUALIFIER_ID_CPS => PolicyQualifier::cps_uri_from_der(reader)?,
                    POLICY_QUALIFIER_ID_USER_NOTICE => {
                        PolicyQualifier::user_notice_from_der(reader)?
                    }
                    _ => PolicyQualifier::Unknown(reader.read_bytes_to_end()),
                };
                Ok(Self { id, qualifier })
            },
        )
    }

    const TYPE_ID: DerTypeId = DerTypeId::PolicyQualifierInfo;
}

// Forms a policy qualifier ID by appending a given number to the
// `id-qt` defined in RFC 5280, Section 4.2.1.4:
// ```
// id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
// ```
macro_rules! policy_qualifier_id {
    ($i:literal) => {
        oid!(1, 3, 6, 1, 5, 5, 7, 2, $i)
    };
}

// Policy quaifier ID for CPS Pointer (CPSuri) defined in
// RFC 5280, Section 4.2.1.4:
// ```
// id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
// ```
const POLICY_QUALIFIER_ID_CPS: &[u8] = &policy_qualifier_id!(1);

// Policy qualifier ID for User Notice defined in
// RFC 5280, Section 4.2.1.4:
// ```
// id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
// ```
const POLICY_QUALIFIER_ID_USER_NOTICE: &[u8] = &policy_qualifier_id!(2);

/// Represents additional fields of policy qualifiers.
pub enum PolicyQualifier<'a> {
    /// CPS Pointer (URI) in RFC 5280, Section 4.2.1.4:
    /// ```text
    /// CPSuri ::= IA5String
    /// ```
    /// Note that the value does not contain the IA5String tag and length.
    CPSuri(untrusted::Input<'a>),
    /// User notice in RFC 5280, Section 4.2.1.4:
    /// ```text
    /// UserNotice ::= SEQUENCE {
    ///      noticeRef        NoticeReference OPTIONAL,
    ///      explicitText     DisplayText OPTIONAL }
    /// ```
    /// We accept the case where neither of `noticeRef` and `explicitText` is
    /// present.
    UserNotice {
        /// Notice reference.
        notice_ref: Option<NoticeReference<'a>>,
        /// Explicit text.
        explicit_text: Option<DisplayText<'a>>,
    },
    /// Other qualifier IDs fall into this variant.
    Unknown(untrusted::Input<'a>),
}

impl<'a> PolicyQualifier<'a> {
    fn cps_uri_from_der(reader: &mut untrusted::Reader<'a>) -> Result<PolicyQualifier<'a>, Error> {
        let uri = der::expect_tag(reader, Tag::IA5String)?;
        Ok(Self::CPSuri(uri))
    }

    fn user_notice_from_der(
        reader: &mut untrusted::Reader<'a>,
    ) -> Result<PolicyQualifier<'a>, Error> {
        der::nested(
            reader,
            Tag::Sequence,
            Error::TrailingData(DerTypeId::UserNotice),
            |reader| {
                // noticeRef starts with SEQUENCE, otherwise omitted
                let notice_ref = if reader.peek(Tag::Sequence.into()) {
                    Some(NoticeReference::from_der(reader)?)
                } else {
                    None
                };
                // expects explicitText if there are remaining data,
                // otherwise omitted
                let explicit_text = if !reader.at_end() {
                    Some(DisplayText::from_der(reader)?)
                } else {
                    None
                };
                Ok(Self::UserNotice {
                    notice_ref,
                    explicit_text,
                })
            },
        )
    }
}

/// Represents a notice reference defined in RFC 5280, Section 4.2.1.4:
///
/// ```text
/// NoticeReference ::= SEQUENCE {
///      organization     DisplayText,
///      noticeNumbers    SEQUENCE OF INTEGER }
/// ```
pub struct NoticeReference<'a> {
    /// Organization.
    pub organization: DisplayText<'a>,
    /// Policy numbers.
    ///
    /// The SEQUENCE tag and length are not included.
    pub notice_numbers: untrusted::Input<'a>,
}

impl<'a> FromDer<'a> for NoticeReference<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        der::nested(
            reader,
            Tag::Sequence,
            Error::TrailingData(DerTypeId::NoticeReference),
            |reader| {
                let organization = DisplayText::from_der(reader)?;
                let notice_numbers = der::expect_tag(reader, Tag::Sequence)?;
                // checks if notice_numbers only contains INTEGER
                let number_reader = &mut untrusted::Reader::new(notice_numbers);
                while !number_reader.at_end() {
                    der::expect_tag(number_reader, Tag::Integer)?;
                }
                Ok(Self {
                    organization,
                    notice_numbers,
                })
            },
        )
    }

    const TYPE_ID: DerTypeId = DerTypeId::NoticeReference;
}

/// Represents a display text defined in RFC 5280, Section 4.2.1.4:
///
/// ```text
/// DisplayText ::= CHOICE {
///      ia5String        IA5String      (SIZE (1..200)),
///      visibleString    VisibleString  (SIZE (1..200)),
///      bmpString        BMPString      (SIZE (1..200)),
///      utf8String       UTF8String     (SIZE (1..200)) }
/// ```
///
/// Despite said in RFC 5280, Section 4.2.1.4:
///
/// > Conforming CAs MUST NOT encode explicitText as VisibleString or BMPString.
///
/// We faced both VisibleString and BMPString in the following test fixtures:
/// - tests/netflix
/// - tests/win_hello_attest_tpm
///
/// We do not impose the cap on the length as said in RFC 5280, Section 4.2.1.4:
///
/// > Note: While the explicitText has a maximum size of 200 characters, some
/// > non-conforming CAs exceed this limit.  Therefore, certificate users SHOULD
/// > gracefully handle explicitText with more than 200 characters.
///
/// The value of each variant does not include the tag and length.
// The variants all end with "String" and `clippy` does not like it.
// But I leave it as is to keep coherent with the terms in the RFC.
#[allow(clippy::enum_variant_names)]
pub enum DisplayText<'a> {
    /// IA5String.
    IA5String(untrusted::Input<'a>),
    /// VisibleString.
    VisibleString(untrusted::Input<'a>),
    /// BMPString.
    BMPString(untrusted::Input<'a>),
    /// UTF8String.
    UTF8String(untrusted::Input<'a>),
}

impl<'a> FromDer<'a> for DisplayText<'a> {
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        const TAG_IA5STRING: u8 = 0x16;
        const TAG_UTF8STRING: u8 = 0x0C;
        const TAG_VISIBLESTRING: u8 = 0x1A;
        const TAG_BMPSTRING: u8 = 0x1E;
        let (tag, value) = der::read_tag_and_get_value(reader)?;
        match tag {
            TAG_IA5STRING => Ok(Self::IA5String(value)),
            TAG_UTF8STRING => Ok(Self::UTF8String(value)),
            TAG_VISIBLESTRING => Ok(Self::VisibleString(value)),
            TAG_BMPSTRING => Ok(Self::BMPString(value)),
            _ => Err(Error::BadDer),
        }
    }

    const TYPE_ID: DerTypeId = DerTypeId::DisplayText;
}

// RFC 5280, Section 4.2.1.4
const ANY_POLICY_OID: &[u8] = &oid!(2, 5, 29, 32, 0);

/// Policy OID.
pub enum PolicyOid<'a> {
    /// `anyPolicy`
    AnyPolicy,
    /// Specific policy OID.
    ///
    /// The OID tag and length are not included.
    SpecificPolicy(untrusted::Input<'a>),
}

impl<'a> PolicyOid<'a> {
    fn from(oid: untrusted::Input<'a>) -> Self {
        if oid.as_slice_less_safe() == ANY_POLICY_OID {
            Self::AnyPolicy
        } else {
            Self::SpecificPolicy(oid)
        }
    }

    /// Returns if this policy OID is `anyPolicy`.
    pub const fn is_any_policy(&self) -> bool {
        matches!(self, Self::AnyPolicy)
    }

    /// Returns if this policy OID matches another policy OID.
    ///
    /// `anyPolicy` matches any policy OID.
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AnyPolicy, _) | (_, Self::AnyPolicy) => true,
            (Self::SpecificPolicy(a), Self::SpecificPolicy(b)) => {
                a.as_slice_less_safe() == b.as_slice_less_safe()
            }
        }
    }
}

impl<'a, T> From<T> for PolicyOid<'a>
where
    T: Into<untrusted::Input<'a>>,
{
    fn from(oid: T) -> Self {
        Self::from(oid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_empty_certificate_policies_extension() {
        // forges a certificate with an empty certificate policies extension
        let ee = include_bytes!("../tests/netflix/ee.der");
        let mut ee_cert =
            Cert::from_der(untrusted::Input::from(ee)).expect("failed to parse EE cert");
        ee_cert.certificate_policies = Some(untrusted::Input::from(&[]));
        assert!(matches!(
            check_certificate_policies_in_cert(&ee_cert),
            Err(ControlFlow::Continue(Error::EmptyCertificatePolicies)),
        ));
    }

    #[test]
    fn accept_multiple_unique_certificate_policy_oids() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x0B,
            // policyIdentifier = OID
            0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x1F,
            // PolicyInformation = SEQUENCE
            0x30, 0x08,
            // policyIdentifier = OID (2.23.140.1.2.2)
            0x06, 0x06, 0x82, 0x81, 0x0C, 0x01, 0x02, 0x02,
        ];
        assert!(check_certificate_policy_oid_duplication(INPUT.into()).is_ok());
    }

    #[test]
    fn reject_duplicate_certificate_policy_oid() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x0B,
            // policyIdentifier = OID
            0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x1F,
            // PolicyInformation = SEQUENCE
            0x30, 0x0B,
            // policyIdentifier = OID
            0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x1F,
        ];
        assert_eq!(
            check_certificate_policy_oid_duplication(INPUT.into()),
            Err(Error::DuplicateCertificatePolicyOid),
        )
    }

    #[test]
    fn reject_unknown_policy_qualifier() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x19,
            // policyIdentifier = OID
            0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x1F,
            // policyQualifiers = SEQUENCE
            0x30, 0x0C,
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x0A,
            // policyQualifierId = OID
            0x06, 0x08, 0x43, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x7F,
        ];
        assert_eq!(
            check_certificate_policy_qualifiers(INPUT.into()),
            Err(Error::UnknownPolicyQualifier),
        );
    }

    #[test]
    fn accept_certificate_policy_without_qualifier() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x06,
            // policyIdentifier = OBJECT IDENTIFIER
            0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
        ];
        assert!(CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())).is_ok());
    }

    #[test]
    fn accept_certificate_policy_with_qualifiers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x2C,
            // policyIdentifier = OBJECT IDENTIFIER
            0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
            // policyQualifiers = SEQUENCE
            0x30, 0x24,
            // policyQualifierInfo = SEQUENCE
            0x30, 0x22,
            // policyQualifierId = OBJECT IDENTIFIER (id-qt-cps)
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
            // qualifier = CPSuri (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // policyQualifierId = OBJECT IDENTIFIER (id-qt-unotice)
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02,
            // qualifier = UserNotice (SEQUENCE)
            0x30, 0x05,
            // explicitText = DisplayText (UTF8String)
            0x06, 0x03, 0x48, 0x45, 0x59,
        ];
        assert!(CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())).is_ok());
    }

    #[test]
    fn reject_certificate_policy_with_empty_qualifiers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x08,
            // policyIdentifier = OBJECT IDENTIFIER
            0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
            // policyQualifiers = SEQUENCE (empty)
            0x30, 0x00,
        ];
        assert!(matches!(
            CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_certificate_policy_without_qualifier_but_with_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x09,
            // policyIdentifier = OBJECT IDENTIFIER
            0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_certificate_policy_with_qualifiers_and_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x2F,
            // policyIdentifier = OBJECT IDENTIFIER
            0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
            // policyQualifiers = SEQUENCE
            0x30, 0x24,
            // policyQualifierInfo = SEQUENCE
            0x30, 0x22,
            // policyQualifierId = OBJECT IDENTIFIER (id-qt-cps)
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
            // qualifier = CPSuri (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // policyQualifierId = OBJECT IDENTIFIER (id-qt-unotice)
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02,
            // qualifier = UserNotice (SEQUENCE)
            0x30, 0x05,
            // explicitText = DisplayText (UTF8String)
            0x06, 0x03, 0x48, 0x45, 0x59,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::CertificatePolicy)),
        ));
    }

    #[test]
    fn reject_certificate_policy_missing_policy_identifier() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyInformation = SEQUENCE
            0x30, 0x00,
        ];
        assert!(matches!(
            CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_non_sequence_certificate_policy() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // policyIdentifier = OBJECT IDENTIFIER
            0x06, 0x04, 0x55, 0x1D, 0x20, 0x00,
        ];
        assert!(matches!(
            CertificatePolicy::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::CertificatePolicy)),
        ));
    }

    #[test]
    fn accept_policy_qualifier_info_with_cps_uri() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x11,
            // policyQualifierId = OBJECT IDENTIFIER
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
            // qualifier = CPSuri (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        let qualifier_info =
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert_eq!(
            qualifier_info.id.as_slice_less_safe(),
            POLICY_QUALIFIER_ID_CPS
        );
        assert!(matches!(
            qualifier_info.qualifier,
            PolicyQualifier::CPSuri(_)
        ));
    }

    #[test]
    fn accept_policy_qualifier_info_with_user_notice() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x13,
            // policyQualifierId = OBJECT IDENTIFIER
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02,
            // qualifier = UserNotice (SEQUENCE)
            0x30, 0x07,
            // explicitText = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        let qualifier_info =
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert_eq!(
            qualifier_info.id.as_slice_less_safe(),
            POLICY_QUALIFIER_ID_USER_NOTICE
        );
        assert!(matches!(
            qualifier_info.qualifier,
            PolicyQualifier::UserNotice { .. },
        ));
    }

    #[test]
    fn accept_policy_qualifier_info_with_unknown_id() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x0D,
            // policyQualifierId = OBJECT IDENTIFIER
            0x06, 0x06, 0x52, 0x17, 0x81, 0x05, 0x08, 0x03,
            // qualifier = ANY DEFINED BY policyQualifierId
            0x30, 0x05, 0x0C, 0x03, 0x48, 0x45, 0x59,
        ];
        let qualifier_info =
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert!(matches!(
            qualifier_info.qualifier,
            PolicyQualifier::Unknown(_),
        ));
    }

    #[test]
    fn reject_policy_qualifier_info_cps_with_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x14,
            // policyQualifierId = OBJECT IDENTIFIER
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
            // qualifier = CPSuri (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::PolicyQualifierInfo)),
        ));
    }

    #[test]
    fn reject_policy_qualifier_info_unotice_with_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x16,
            // policyQualifierId = OBJECT IDENTIFIER
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02,
            // qualifier = UserNotice (SEQUENCE)
            0x30, 0x07,
            // explicitText = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::PolicyQualifierInfo)),
        ));
    }

    #[test]
    fn reject_policy_qualifier_missing_policy_qualifier_id() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // PolicyQualifierInfo = SEQUENCE
            0x30, 0x07,
            // qualifier = CPSuri (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        assert!(matches!(
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_non_sequence_policy_qualifier_info() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // policyQualifierId = OBJECT IDENTIFIER
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
        ];
        assert!(matches!(
            PolicyQualifierInfo::from_der(&mut untrusted::Reader::new(INPUT.into()),),
            Err(Error::TrailingData(DerTypeId::PolicyQualifierInfo)),
        ));
    }

    #[test]
    fn accept_cps_uri_in_ia5string() {
        const INPUT: &[u8] = &[0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        assert!(matches!(
            PolicyQualifier::cps_uri_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(PolicyQualifier::CPSuri(uri)) if uri.as_slice_less_safe() == b"hello",
        ));
    }

    #[test]
    fn reject_cps_uri_in_utf8string() {
        const INPUT: &[u8] = &[0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        assert!(matches!(
            PolicyQualifier::cps_uri_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn accept_user_notice_with_notice_ref_only() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // UserNotice = SEQUENCE
            0x30, 0x0E,
            // NoticeReference = SEQUENCE
            0x30, 0x0C,
            // organization = DisplayText (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x03, 0x02, 0x01, 0x01,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(PolicyQualifier::UserNotice {
                notice_ref: Some(NoticeReference {
                    organization: DisplayText::IA5String(organization),
                    notice_numbers,
                }),
                explicit_text: None,
            }) if organization.as_slice_less_safe() == b"hello"
                && notice_numbers.as_slice_less_safe() == [0x02, 0x01, 0x01],
        ));
    }

    #[test]
    fn accept_user_notice_with_explicit_text_only() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // UserNotice = SEQUENCE
            0x30, 0x07,
            // explicitText = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(PolicyQualifier::UserNotice {
                notice_ref: None,
                explicit_text: Some(DisplayText::UTF8String(text)),
            }) if text.as_slice_less_safe() == b"hello",
        ));
    }

    #[test]
    fn accept_user_notice_with_both_notice_ref_and_explicit_text() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // UserNotice = SEQUENCE
            0x30, 0x15,
            // NoticeReference = SEQUENCE
            0x30, 0x0C,
            // organization = DisplayText (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x03, 0x02, 0x01, 0x01,
            // explicitText = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(PolicyQualifier::UserNotice {
                notice_ref: Some(NoticeReference {
                    organization: DisplayText::IA5String(organization),
                    notice_numbers,
                }),
                explicit_text: Some(DisplayText::UTF8String(text)),
            }) if organization.as_slice_less_safe() == b"hello"
                && notice_numbers.as_slice_less_safe() == [0x02, 0x01, 0x01]
                && text.as_slice_less_safe() == b"hello",
        ));
    }

    #[test]
    fn accept_empty_user_notice() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // UserNotice = SEQUENCE
            0x30, 0x00,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(PolicyQualifier::UserNotice {
                notice_ref: None,
                explicit_text: None,
            }),
        ));
    }

    #[test]
    fn reject_user_notice_with_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // UserNotice = SEQUENCE
            0x30, 0x0A,
            // explicitText = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::UserNotice)),
        ));
    }

    #[test]
    fn reject_empty_user_notice_with_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // UserNotice = SEQUENCE
            0x30, 0x03,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_non_sequence_user_notice() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // explicitText = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        assert!(matches!(
            PolicyQualifier::user_notice_from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::UserNotice)),
        ));
    }

    #[test]
    fn accept_notice_reference_with_three_notice_numbers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x12,
            // organization = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(NoticeReference {
                organization: DisplayText::UTF8String(organization),
                notice_numbers,
            }) if organization.as_slice_less_safe() == b"hello"
                && notice_numbers.as_slice_less_safe() == [0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03],
        ));
    }

    #[test]
    fn accept_notice_reference_with_empty_notice_numbers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x09,
            // organization = DisplayText (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x00,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Ok(NoticeReference {
                organization: DisplayText::IA5String(organization),
                notice_numbers,
            }) if organization.as_slice_less_safe() == b"hello"
                && notice_numbers.is_empty(),
        ));
    }

    #[test]
    fn reject_notice_reference_with_non_integer_notice_numbers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x12,
            // organization = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x09, 0x02, 0x01, 0x01, 0x0C, 0x04, 0x6F, 0x6F, 0x70, 0x73,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_notice_reference_with_trailing_data() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x0F,
            // organization = DisplayText (UTF8String)
            0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x03, 0x02, 0x01, 0x01,
            // extra data
            0x02, 0x01, 0x00,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::NoticeReference)),
        ));
    }

    #[test]
    fn reject_notice_reference_missing_organization() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x02,
            // noticeNumbers = SEQUENCE OF INTEGER
            0x30, 0x00,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_notice_reference_missing_notice_numbers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x07,
            // organization = DisplayText (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_notice_reference_with_non_sequence_notice_numbers() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // NoticeReference = SEQUENCE
            0x30, 0x0A,
            // organization = DisplayText (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
            // single INTEGER
            0x02, 0x01, 0x01,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn reject_non_sequence_notice_reference() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // organization = DisplayText (IA5String)
            0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
        ];
        assert!(matches!(
            NoticeReference::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::TrailingData(DerTypeId::NoticeReference)),
        ));
    }

    #[test]
    fn accept_ia5string_display_text() {
        const INPUT: &[u8] = &[0x16, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        let display_text =
            DisplayText::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert!(matches!(
            display_text,
            DisplayText::IA5String(text) if text.as_slice_less_safe() == b"hello",
        ));
    }

    #[test]
    fn accept_utf8_string_display_text() {
        const INPUT: &[u8] = &[0x0C, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        let display_text =
            DisplayText::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert!(matches!(
            display_text,
            DisplayText::UTF8String(text) if text.as_slice_less_safe() == b"hello",
        ));
    }

    #[test]
    fn accept_visible_string_display_text() {
        const INPUT: &[u8] = &[0x1A, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        let display_text =
            DisplayText::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert!(matches!(
            display_text,
            DisplayText::VisibleString(text) if text.as_slice_less_safe() == b"hello",
        ));
    }

    #[test]
    fn accept_bmp_string_display_text() {
        // BMPString is consisting of two-byte characters
        const INPUT: &[u8] = &[
            0x1E, 0x0A, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F,
        ];
        let display_text =
            DisplayText::from_der(&mut untrusted::Reader::new(INPUT.into())).unwrap();
        assert!(matches!(
            display_text,
            DisplayText::BMPString(text) if text.as_slice_less_safe() == [0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F],
        ));
    }

    #[test]
    fn reject_printable_string_display_text() {
        const INPUT: &[u8] = &[0x13, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
        assert!(matches!(
            DisplayText::from_der(&mut untrusted::Reader::new(INPUT.into())),
            Err(Error::BadDer),
        ));
    }

    #[test]
    fn any_policy_oid() {
        const OID: &[u8] = &oid!(2, 5, 29, 32, 0);
        let policy: PolicyOid = OID.into();
        assert!(policy.is_any_policy());
    }

    #[test]
    fn specific_policy_oid() {
        const OID: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 2);
        let policy: PolicyOid = OID.into();
        assert!(!policy.is_any_policy());
    }

    #[test]
    fn any_policy_matches_any_policy() {
        assert!(PolicyOid::AnyPolicy.matches(&PolicyOid::AnyPolicy));
    }

    #[test]
    fn any_policy_matches_specific_policy() {
        const OID: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 2);
        let policy: PolicyOid = OID.into();
        assert!(PolicyOid::AnyPolicy.matches(&policy));
        assert!(policy.matches(&PolicyOid::AnyPolicy));
    }

    #[test]
    fn specific_policy_matches_same_specific_policy() {
        const OID_1: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 2, 1);
        const OID_2: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 2, 1);
        let policy_1: PolicyOid = OID_1.into();
        let policy_2: PolicyOid = OID_2.into();
        assert!(policy_1.matches(&policy_2));
    }

    #[test]
    fn specific_policy_does_not_match_different_specific_policy() {
        const OID_1: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 2, 1);
        const OID_2: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 2, 2);
        let policy_1: PolicyOid = OID_1.into();
        let policy_2: PolicyOid = OID_2.into();
        assert!(!policy_1.matches(&policy_2));
    }
}
