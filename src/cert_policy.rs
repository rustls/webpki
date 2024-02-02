use core::ops::ControlFlow;

use crate::cert::Cert;
use crate::der::{self, FromDer, Tag};
use crate::error::{DerTypeId, Error};
use crate::verify_cert::{IntermediateIterator, PathNode, VerifiedPath};

/// Validates the certificate policy tree formed by a given certificate path.
///
/// ### Remarks
///
/// This function does not build the entire policy tree as described in RFC
/// 5280, Section 6.1, but checks if there is any policy tree path that accepts
/// at least one policy in `user_initial_policy_set` in a depth-first search
/// manner.
///
/// This function assumes:
/// - *valid_policy_tree* must include at least one policy in
///   `user_initial_policy_set`
/// - *anyPolicy* is allowed
/// - Policy mappings extension is not supported
/// - Policy constraints extension is not supported
/// - Inhibit anyPolicy extension is not supported
///
/// `user_initial_policy_set` is a slice of acceptable policy OIDs.
/// Each OID must be DER-encoded but without the first two bytes (the tag and
/// length).
/// You may include *anyPolicy* in `user_initial_policy_set`.
/// This function fails if `user_initial_policy_set` is empty.
///
/// ### Conformity to RFC 5280, Section 6.1.
///
/// Excerpts from RFC 5280 are blockquoted.
///
/// #### 6.1.1. Inputs
///
/// > (a) a prospective certification path of length n.
///
/// Given by `path`.
///
/// > (b) the current date/time.
///
/// Does not apply.
///
/// > (c) user-initial-policy-set
///
/// Given by `user_initial_policy_set`.
///
/// > (d) trust anchor information
///
/// Does not apply.
///
/// > (e) initial-policy-mapping-inhibit
///
/// Policy mapping is not supported.
///
/// > (f) initial-explicit-policy
///
/// Always set; i.e., this function fails if `path` is valid for none of
/// policies in `user_initial_policy_set`.
///
/// > (g) initial-any-policy-inhibit
///
/// Always unset; i.e., any policy is allowed.
///
/// > (h) initial-permitted-subtrees
///
/// Does not apply.
///
/// > (i) initial-excluded-subtrees
///
/// Does not apply.
///
/// #### 6.1.2. Initialization
///
/// > (a) valid_policy_tree:
/// > ...
/// > The initial value of the valid_policy_tree is a single node with
/// > valid_policy anyPolicy, an empty qualifier set, and an expected_policy_set
/// > with the single value anyPolicy. This node is considered to be at depth
/// > zero.
///
/// This function works in a depth-first search manner.
/// The initial value of *valid_policy* is the first policy in
/// `user_initial_policy_set`.
/// This function goes through `path` checking if *valid_policy* is valid.
/// If the inital *valid_policy* is not valid, this function picks the next
/// policy in `user_initial_policy_set` as the next initial *valid_policy* and
/// repeats the above check.
/// This function repeats the above process until it finds a valid policy or
/// processes all the policies in `user_initial_policy_set`.
///
/// *qualifier_set* is not used; i.e., this function is **not suitable for
/// applications that require policy qualifiers**.
///
/// *expected_policy_set* is always equal to *valid_policy*.
///
/// > (b) permitted_subtrees:
///
/// Does not apply.
///
/// > (c) excluded_subtrees:
///
/// Does not apply.
///
/// > (d) explicit_policy:
///
/// 0 because *initial-explict-policy* is set.
///
/// > (e) inhibit_anyPolicy:
///
/// n+1 because *initial-any-policy-inhibit* is unset.
///
/// > (f) policy_mapping:
///
/// Policy mappings extension is not supported.
///
/// > (g) working_public_key_algorithm:
///
/// Does not apply.
///
/// > (h) working_public_key:
///
/// Does not apply.
///
/// > (i) working_public_key_parameters:
///
/// Does not apply.
///
/// > (j) working_issuer_name:
///
/// Does not apply.
///
/// > (k) max_path_length:
///
/// Does not apply.
///
/// #### 6.1.3. Basic Certificate Processing
///
/// > (a) Verify the basic certificate information.
///
/// Does not apply.
///
/// > (b) If certificate i is self-issued ...
/// > within one of the permitted_subtrees ...
///
/// Does not apply.
///
/// > (c) If certificate i is self-issued ...
/// > not within one of the excluded_subtrees ...
///
/// Does not apply.
///
/// > (d) If the certificate policies extension is present in the certificate
/// > and the valid_policy_tree is not NULL, process the policy information by
/// > performing the following steps in order:
///
/// > (1) For each policy P not equal to anyPolicy in the certificate policies
/// > extension, let P-OID denote the OID for policy P and P-Q denote the
/// > qualifier set for policy P.
///
/// Policy qualifier *P-Q* is not handled.
///
/// > (i) For each node of depth i-1 in the valid_policy_tree where P-OID is
/// > in the expected_policy_set, create a child node as follows: set the
/// > valid_policy to P-OID, set the qualifier_set to P-Q, and set the
/// > expected_policy_set to {P-OID}.
///
/// Since *expected_policy_set* is equivalent to *valid_policy* in our
/// procedure, this step checks if non-any *valid_policy* matches *P-OID*.
/// If it matches, this function recursively applies Step (d) to the remaining
/// certificates in `path`.
/// Otherwise, proceeds to Step (ii).
/// If *valid_policy* is valid for all the remaining certificates in `path`,
/// this function finishes with success.
/// Otherwise, proceeds to Step (ii).
///
/// > (ii) If there was no match in step (i) and the valid_policy_tree includes
/// > a node of depth i-1 with the valid_policy anyPolicy, generate a child node
/// > with the following values: set the valid_policy to P-OID, set the
/// > qualifier_set to P-Q, and set the expected_policy_set to {P-OID}.
///
/// This step is applied if *valid_policy* is *anyPolicy* since we are
/// performing a depth-first search.
/// If *valid_policy* is *anyPolicy*, this function replaces *valid_policy* with
/// *P-OID* and recursively applies Step (d) to the remaining certificates in
/// `path`.
/// Otherwise, proceeds to Step (2).
/// If *valid_policy* is valid for all the remaining certificates in `path`,
/// this function finishes with success.
/// Otherwise, proceeds to Step (2).
///
/// > (2) If the certificate policies extension includes the policy anyPolicy
/// > with the qualifier set AP-Q and either (a) inhibit_anyPolicy is greater
/// > than 0 or (b) i<n and the certificate is self-issued, then
/// >
/// > For each node in the valid_policy_tree of depth i-1, for each value in the
/// > expected_policy_set (including anyPolicy) that does not appear in a child
/// > node, create a child node with the following values: set the valid_policy
/// > to the value from the expected_policy_set in the parent node, set the
/// > qualifier_set to AP-Q, and set the expected_policy_set to the value in the
/// > valid_policy from this node.
///
/// If the certificate policies extension includes the policy *anyPolicy*,
/// this function recursively applies Step (d) to the remaining certificates in
/// `path`.
/// Otherwise, proceeds to Step (3).
/// If *valid_policy* is valid for all the remaining certificates in `path`,
/// this function finishes with success.
/// Otherwise, proceeds to Step (3).
///
/// Policy qualifier *AP-Q* is not handled.
///
/// *inhibit_anyPolicy* does not matter because it is virtually greater than 0.
///
/// > (3) If there is a node in the valid_policy_tree of depth i-1 or less
/// > without any child nodes, delete that node. Repeat this step until there
/// > are no nodes of depth i-1 or less without children.
///
/// This function stops the recursion with failure as soon as it reaches this
/// step.
/// Our procedure does not need "pruning" described in RFC 5280 because it
/// performs a depth-first search.
///
/// > (e) If the certificate policies extension is not present, set the
/// > valid_policy_tree to NULL.
/// >
/// > (f) Verify that either explicit_policy is greater than 0 or the
/// > valid_policy_tree is not equal to NULL.
///
/// This function immediately fails if any certificate in `path` does not have
/// the certificate policies extension, because *explicit_policy* is vritually
/// 0.
///
/// This function fails if all the recursions at Step (d) fail for all the
/// policies in `user_initial_policy_set`.
/// It is equivalent to the situation where *valid_policy_tree* is *NULL*.
///
/// #### 6.1.4. Preparation for Certificate i+1
///
/// As detailed below, the steps described in this section do not apply.
///
/// > To prepare for processing of certificate i+1, perform the following steps
/// > for certificate i:
///
/// > (a) If a policy mappings extension is present, ...
///
/// Policy mappings is not supported.
///
/// > (b) If a policy mappings extension is present, ...
///
/// Policy mappings is not supported.
///
/// > (c) Assign the certificate subject name to working_issuer_name.
///
/// Does not apply.
///
/// > (d) Assign the certificate subjectPublicKey to working_public_key.
///
/// Does not apply.
///
/// > (e) If the subjectPublicKeyInfo field of ...
///
/// Does not apply.
///
/// > (f) Assign the certificate subjectPublicKey algorithm to ...
///
/// Does not apply.
///
/// > (g) If a name constraints extension is included in the certificate, ...
///
/// Does not apply.
///
/// > (h) If certificate i is not self-issued:
///
/// > (1) If explicit_policy is not 0, decrement explicit_policy by 1.
///
/// *explicit_policy* is virtually 0.
///
/// > (2) If policy_mapping is not 0, decrement policy_mapping by 1.
///
/// Policy mappings extension is not supported.
///
/// > (3) If inhibit_anyPolicy is not 0, decrement inhibit_anyPolicy by 1.
///
/// *inhibit_anyPolicy* is virtually always greater than 0, because
/// *initial-any-policy-inhibit* is unset and inhibit anyPolicy extension is
/// not supported.
///
/// > (i) If a policy constraints extension is included in the certificate, ...
///
/// Policy constraints extension is not supported.
///
/// > (j) If the inhibitAnyPolicy extension is included in the certificate, ...
///
/// Inhibit anyPolicy exxtension is not supported.
///
/// > (k) If certificate i is a version 3 certificate, ...
///
/// Does not apply.
///
/// > (l) If the certificate was not self-issued, verify that max_path_length ...
///
/// Does not apply.
///
/// > (m) If pathLenConstraint is present in the certificate ...
///
/// Does not apply.
///
/// > (n) If a key usage extension is present, ...
///
/// Does not apply.
///
/// > (o) Recognize and process any other critical extension ...
///
/// Does not apply.
///
/// #### 6.1.5. Wrap-Up Procedure
///
/// As detailed below, the steps described in this section do not apply.
///
/// > To complete the processing of the target certificate, perform the
/// > following steps for certificate n:
///
/// > (a) If explicit_policy is not 0, decrement explicit_policy by 1.
///
/// *explicit_policy* is virtualy 0.
///
/// > (b) If a policy constraints extension is included in the certificate ...
///
/// Policy constraints extension is not supported.
///
/// > (c) Assign the certificate subjectPublicKey to working_public_key.
///
/// Does not apply.
///
/// > (d) If the subjectPublicKeyInfo field of the certificate ...
///
/// Does not apply.
///
/// > (e) Assign the certificate subjectPublicKey algorithm to ...
///
/// Does not apply.
///
/// > (f) Recognize and process any other critical extension ...
///
/// Does not apply.
///
/// > (g) Calculate the intersection of the valid_policy_tree and the
/// > user-initial-policy-set, as follows:
///
/// Does not apply because we do not build the entire policy tree.
/// Because we start from a specific policy OID in `user_initial_policy_set`,
/// the valid policy tree path that our procedure finds is vitually included in
/// the intersection of the *valid_policy_tree* and the
/// *user-initial-policy-set*.
pub fn validate_policy_tree_paths(
    path: &crate::VerifiedPath<'_>,
    user_initial_policy_set: &[&[u8]],
) -> Result<(), Error> {
    for &valid_policy in user_initial_policy_set {
        let cert_chain = CertificateIterator::new(path);
        match validate_policy_tree_paths_inner(cert_chain, &valid_policy.into()) {
            Ok(()) => return Ok(()),
            Err(ControlFlow::Break(err)) => return Err(err),
            Err(ControlFlow::Continue(_)) => (),
        }
    }
    Err(Error::InvalidPolicyTree)
}

fn validate_policy_tree_paths_inner<'a>(
    mut cert_chain: impl Iterator<Item = &'a Cert<'a>> + Clone,
    valid_policy: &PolicyOid<'_>,
) -> Result<(), ControlFlow<Error, Error>> {
    if let Some(cert) = cert_chain.next() {
        if let Some(policies) = cert.certificate_policies {
            let mut policy_iter = PolicyIterator::new(policies);
            let mut has_any_policy = false;
            for policy in &mut policy_iter {
                let policy = policy?.policy_oid(); // should not fail
                if !policy.is_any_policy() {
                    // RFC 5280, Section 6.1.3. (d)
                    // (1) For each policy P not equal to anyPolicy in the
                    // certificate policies extension
                    if valid_policy.matches(&policy) {
                        // covers both (i) and (ii)
                        //
                        // (i) For each node of depth i-1 in the
                        // valid_policy_tree where P-OID is in the
                        // expected_policy_set ...
                        // ← valid_policy is not anyPolicy
                        //
                        // (ii) If there was no match in step (i) and the
                        // valid_policy_tree includes a node of depth i-1 with
                        // the valid_policy anyPolicy ...
                        // ← valid_policy is anyPolicy
                        match validate_policy_tree_paths_inner(cert_chain.clone(), valid_policy) {
                            Ok(()) => return Ok(()),
                            res @ Err(ControlFlow::Break(_)) => return res,
                            Err(ControlFlow::Continue(_)) => (),
                        }
                    }
                } else {
                    has_any_policy = true;
                }
            }
            if has_any_policy {
                // (2) If the certificate policies extension includes the policy
                // anyPolicy
                validate_policy_tree_paths_inner(cert_chain, valid_policy)
            } else {
                Err(ControlFlow::Continue(Error::InvalidPolicyTree))
            }
        } else {
            // if any cert in the chain lacks the certificate policies extension
            // there is no chance to succeed
            Err(ControlFlow::Break(Error::InvalidPolicyTree))
        }
    } else {
        Ok(())
    }
}

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

struct PolicyIterator<'a> {
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
    fn new(policies: untrusted::Input<'a>) -> Self {
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

// Represents a single policy information defined in
// RFC 5280, Section 4.2.1.4:
//
// ```
// PolicyInformation ::= SEQUENCE {
//      policyIdentifier   CertPolicyId,
//      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
//                              PolicyQualifierInfo OPTIONAL }
// ```
#[derive(Clone)]
struct CertificatePolicy<'a> {
    pub(crate) id: untrusted::Input<'a>,
    qualifiers: Option<untrusted::Input<'a>>,
}

impl<'a> CertificatePolicy<'a> {
    fn policy_oid(&self) -> PolicyOid<'a> {
        PolicyOid::from(self.id)
    }

    pub(crate) fn qualifiers(&self) -> PolicyQualifierInfoIterator<'a> {
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

// Represents a single policy qualifier information defined in
// RFC 5280, Section 4.2.1.4:
//
// ```
// PolicyQualifierInfo ::= SEQUENCE {
//      policyQualifierId  PolicyQualifierId,
//      qualifier          ANY DEFINED BY policyQualifierId }
// ```
#[cfg_attr(not(test), allow(dead_code))]
struct PolicyQualifierInfo<'a> {
    id: untrusted::Input<'a>,
    qualifier: PolicyQualifier<'a>,
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

// Represents variants of policy qualifiers.
enum PolicyQualifier<'a> {
    // RFC 5280, Section 4.2.1.4:
    // ```
    // CPSuri ::= IA5String
    // ```
    // Note that the value does not contain the IA5String tag and length.
    CPSuri(untrusted::Input<'a>),
    // RFC 5280, Section 4.2.1.4:
    // ```
    // UserNotice ::= SEQUENCE {
    //      noticeRef        NoticeReference OPTIONAL,
    //      explicitText     DisplayText OPTIONAL }
    // ```
    // We accept the case where neither of `noticeRef` and `explicitText` is
    // present.
    #[cfg_attr(not(test), allow(dead_code))]
    UserNotice {
        notice_ref: Option<NoticeReference<'a>>,
        explicit_text: Option<DisplayText<'a>>,
    },
    // Other qualifier IDs fall into this variant.
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

// Represents a notice reference defined in RFC 5280, Section 4.2.1.4:
//
// ```
// NoticeReference ::= SEQUENCE {
//      organization     DisplayText,
//      noticeNumbers    SEQUENCE OF INTEGER }
// ```
#[cfg_attr(not(test), allow(dead_code))]
struct NoticeReference<'a> {
    organization: DisplayText<'a>,
    notice_numbers: untrusted::Input<'a>,
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

// Represents a display text defined in RFC 5280, Section 4.2.1.4:
//
// ```
// DisplayText ::= CHOICE {
//      ia5String        IA5String      (SIZE (1..200)),
//      visibleString    VisibleString  (SIZE (1..200)),
//      bmpString        BMPString      (SIZE (1..200)),
//      utf8String       UTF8String     (SIZE (1..200)) }
// ```
//
// Despite said in RFC 5280, Section 4.2.1.4:
//
// > Conforming CAs MUST NOT encode explicitText as VisibleString or BMPString.
//
// We faced both VisibleString and BMPString in the following test fixtures:
// - tests/netflix
// - tests/win_hello_attest_tpm
//
// We do not impose the cap on the length as said in RFC 5280, Section 4.2.1.4:
//
// > Note: While the explicitText has a maximum size of 200 characters, some
// > non-conforming CAs exceed this limit.  Therefore, certificate users SHOULD
// > gracefully handle explicitText with more than 200 characters.
//
// The variants all end with "String" and `clippy` does not like it.
// But I leave it as is to keep coherent with the terms in the RFC.
#[allow(clippy::enum_variant_names)]
enum DisplayText<'a> {
    IA5String(untrusted::Input<'a>),
    VisibleString(untrusted::Input<'a>),
    BMPString(untrusted::Input<'a>),
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

#[derive(Clone)]
struct CertificateIterator<'a> {
    // `None` means all the intermediate certificates have been porcessed.
    intermediate_certs: Option<IntermediateIterator<'a>>,
    // `None` means the end-entity certificate has been processed.
    end_entity_cert: Option<&'a Cert<'a>>,
}

impl<'a> CertificateIterator<'a> {
    fn new(path: &'a VerifiedPath<'a>) -> Self {
        Self {
            intermediate_certs: Some(path.intermediate_certificates()),
            end_entity_cert: Some(path.end_entity()),
        }
    }
}

impl<'a> Iterator for CertificateIterator<'a> {
    type Item = &'a Cert<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(intermediate_certs) = self.intermediate_certs.as_mut() {
            if let Some(cert) = intermediate_certs.next_back() {
                return Some(cert);
            } else {
                self.intermediate_certs = None;
                // returns the end-entity certificate below
            }
        }
        if let Some(end_entity_cert) = self.end_entity_cert.take() {
            return Some(end_entity_cert);
        }
        None
    }
}

// RFC 5280, Section 4.2.1.4
const ANY_POLICY_OID: &[u8] = &oid!(2, 5, 29, 32, 0);

enum PolicyOid<'a> {
    // anyPolicy
    AnyPolicy,
    // specific policy OID
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

    const fn is_any_policy(&self) -> bool {
        matches!(self, Self::AnyPolicy)
    }

    fn matches(&self, other: &Self) -> bool {
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
