//! Merkle Tree Certificates (MTC).
//!
//! This tracks [draft-ietf-plants-merkle-tree-certs-07], and trust anchor IDs as defined by
//! [draft-ietf-tls-trust-anchor-ids-06]. Both are drafts, so this API may change with them.
//!
//! [draft-ietf-plants-merkle-tree-certs-07]: https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07
//! [draft-ietf-tls-trust-anchor-ids-06]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-06

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use alloc::{format, vec};
#[cfg(feature = "alloc")]
use core::fmt::Write;
#[cfg(feature = "alloc")]
use core::ops::RangeInclusive;

#[cfg(feature = "alloc")]
use pki_types::{
    AlgorithmIdentifier, CertificateDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
    TrustAnchor,
};
use untrusted::{Input, Reader};

#[cfg(feature = "alloc")]
use crate::cert::Cert;
#[cfg(feature = "alloc")]
use crate::der::FromDer;
use crate::der::{self, Tag};
use crate::error::Error;
#[cfg(feature = "alloc")]
use crate::signed_data::SignedData;
#[cfg(feature = "alloc")]
use crate::verify_cert::Budget;
#[cfg(feature = "alloc")]
use crate::x509::{Extension, set_extension_once};

/// A SHA-256 implementation, supplied by the caller.
///
/// webpki does no hashing of its own. SHA-256 is the only hash MTC defines.
pub trait MtcHash {
    /// Returns the SHA-256 hash of the concatenation of `parts`.
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32];
}

/// Returns whether `[start, end)` is a valid subtree (MTC section 4.1).
pub fn is_valid_subtree(start: u64, end: u64) -> bool {
    let Some(size) = end.checked_sub(start) else {
        return false;
    };

    match size > 1 << 63 {
        // `next_power_of_two()` would overflow.
        true => start == 0,
        false => start & (size.next_power_of_two() - 1) == 0,
    }
}

/// Evaluates a subtree inclusion proof (MTC section 4.3.2).
///
/// Returns the hash of the subtree `[start, end)` implied by `proof`, the concatenated proof
/// hashes for the entry at `index` with hash `entry_hash`.
pub fn evaluate_inclusion_proof(
    hash: &dyn MtcHash,
    index: u64,
    entry_hash: &[u8; 32],
    start: u64,
    end: u64,
    proof: &[u8],
) -> Result<[u8; 32], Error> {
    if !is_valid_subtree(start, end) || !(start..end).contains(&index) {
        return Err(Error::InvalidMtcProof);
    }

    if proof.len() % HASH_SIZE != 0 {
        return Err(Error::InvalidMtcProof);
    }

    let (mut fn_, mut sn) = (index - start, end - start - 1);
    let mut r = *entry_hash;
    for p in proof.chunks_exact(HASH_SIZE) {
        if sn == 0 {
            return Err(Error::InvalidMtcProof);
        }

        if fn_ & 1 == 1 || fn_ == sn {
            r = hash.sha256(&[&[NODE_PREFIX], p, &r]);
            // The draft omits `fn_ != 0`; it can't be reached, but bounds the loop regardless.
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = hash.sha256(&[&[NODE_PREFIX], &r, p]);
        }

        fn_ >>= 1;
        sn >>= 1;
    }

    match sn {
        0 => Ok(r),
        _ => Err(Error::InvalidMtcProof),
    }
}

/// Verifies a subtree consistency proof (MTC section 4.4.3).
///
/// Checks that `proof` shows the subtree `[start, end)` with hash `node_hash` is consistent
/// with the tree of size `n` with hash `root_hash`.
pub fn verify_consistency_proof(
    hash: &dyn MtcHash,
    n: u64,
    start: u64,
    end: u64,
    proof: &[u8],
    node_hash: &[u8; 32],
    root_hash: &[u8; 32],
) -> Result<(), Error> {
    if !is_valid_subtree(start, end) || end > n || proof.len() % HASH_SIZE != 0 {
        return Err(Error::InvalidMtcProof);
    }

    if start == end {
        return match proof.is_empty() && *node_hash == hash.sha256(&[]) {
            true => Ok(()),
            false => Err(Error::InvalidMtcProof),
        };
    }

    let (mut fn_, mut sn, mut tn) = (start, end - 1, n - 1);
    let shift = |fn_: &mut u64, sn: &mut u64, tn: &mut u64| {
        *fn_ >>= 1;
        *sn >>= 1;
        *tn >>= 1;
    };

    if sn == tn {
        while fn_ != sn {
            shift(&mut fn_, &mut sn, &mut tn);
        }
    } else {
        while fn_ != sn && sn & 1 == 1 {
            shift(&mut fn_, &mut sn, &mut tn);
        }
    }

    let mut proof = proof.chunks_exact(HASH_SIZE);
    let (mut fr, mut sr) = match fn_ == sn {
        true => (*node_hash, *node_hash),
        false => {
            let first = proof.next().ok_or(Error::InvalidMtcProof)?;
            let first = <[u8; HASH_SIZE]>::try_from(first).map_err(|_| Error::InvalidMtcProof)?;
            (first, first)
        }
    };

    for c in proof {
        if tn == 0 {
            return Err(Error::InvalidMtcProof);
        }

        if sn & 1 == 1 || sn == tn {
            if fn_ < sn {
                fr = hash.sha256(&[&[NODE_PREFIX], c, &fr]);
            }
            sr = hash.sha256(&[&[NODE_PREFIX], c, &sr]);
            // Terminates: here `sn` is odd, or equal to `tn` which is non-zero.
            while sn & 1 == 0 {
                shift(&mut fn_, &mut sn, &mut tn);
            }
        } else {
            sr = hash.sha256(&[&[NODE_PREFIX], &sr, c]);
        }

        shift(&mut fn_, &mut sn, &mut tn);
    }

    match tn == 0 && fr == *node_hash && sr == *root_hash {
        true => Ok(()),
        false => Err(Error::InvalidMtcProof),
    }
}

/// Returns the two subtrees that efficiently cover `[start, end)` (MTC section 4.5.1).
///
/// Each subtree is returned as `(start, end)`. Returns `None` if `start > end`.
pub fn find_subtrees(start: u64, end: u64) -> Option<[(u64, u64); 2]> {
    if end.checked_sub(start)? <= 1 {
        return Some([(start, end), (end, end)]);
    }

    let last = end - 1;
    // Where the tree paths of `start` and `last` diverge.
    let split = bit_length(start ^ last) - 1;
    let mask = (1 << split) - 1;
    let mid = last & !mask;
    let left_split = bit_length(!start & mask);
    let left_start = start & !((1 << left_split) - 1);
    Some([(left_start, mid), (mid, end)])
}

fn bit_length(n: u64) -> u32 {
    u64::BITS - n.leading_zeros()
}

/// A trusted Merkle Tree Certificate CA, with the relying party's state for it (MTC section 7.1).
///
/// Use with [`PathBuilder::with_mtc()`](crate::PathBuilder::with_mtc).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct MtcCa {
    pub(crate) anchor: TrustAnchor<'static>,
    ca_id: Vec<u8>,
    /// The text form of this CA's log IDs, up to the log number.
    log_origin_prefix: String,
    /// The CA cosigner, then the other cosigners.
    cosigners: Vec<MtcCosigner>,
    witness_quorum: usize,
    trusted_subtrees: Vec<MtcSubtree>,
    requested_trust_anchor_id: Vec<u8>,
    revoked: Vec<RangeInclusive<u64>>,
}

#[cfg(feature = "alloc")]
impl MtcCa {
    /// Builds an `MtcCa` from its CA certificate (MTC section 5.5).
    ///
    /// The certificate's subject is the CA ID, its key is the CA cosigner's key, and it must
    /// carry the critical `id-pe-mtcCertificationAuthority-SHA256` extension. Serial numbers
    /// outside the extension's range are revoked.
    ///
    /// `witnesses` are the cosigners other than the CA cosigner, and `witness_quorum` is how
    /// many of them must also have signed a subtree. The CA cosigner's signature is always
    /// required. A quorum of 0 trusts the CA without transparency (MTC section 7.3).
    pub fn from_ca_cert(
        cert: &CertificateDer<'_>,
        witnesses: Vec<MtcCosigner>,
        witness_quorum: usize,
    ) -> Result<Self, Error> {
        let cert = Cert::for_trust_anchor(Input::from(cert.as_ref()))?;
        let ca_id = ca_id_from_name(cert.subject).ok_or(Error::BadDer)?;
        let (sig_alg, min_serial, max_serial) = mtc_ca_extension(cert.signed_data.data)?;
        let ca = MtcCosigner::from_parts(ca_id, cert.spki.as_slice_less_safe(), sig_alg)?;

        let log_origin_prefix = format!("{}.0.", ca.name);
        let mut revoked = Vec::with_capacity(2);
        // `min_serial` is at least 2^48.
        revoked.push(0..=min_serial - 1);
        if let Some(above) = max_serial.checked_add(1) {
            revoked.push(above..=u64::MAX);
        }

        let mut cosigners = vec![ca];
        cosigners.extend(witnesses);
        Ok(Self {
            ca_id: ca_id.to_vec(),
            requested_trust_anchor_id: ca_id.to_vec(),
            anchor: TrustAnchor::from(cert).to_owned(),
            log_origin_prefix,
            cosigners,
            witness_quorum,
            trusted_subtrees: Vec::new(),
            revoked,
        })
    }

    /// Sets the trusted subtrees, replacing any set before (MTC section 7.4).
    ///
    /// A trusted subtree is as powerful as the CA: a certificate with an inclusion proof into
    /// it needs no cosignatures. Only pass subtrees checked to be consistent with checkpoints
    /// cosigned by this CA's cosigners.
    pub fn set_trusted_subtrees(&mut self, subtrees: Vec<MtcSubtree>) {
        self.trusted_subtrees = subtrees;
    }

    /// Sets the latest trusted landmark of this CA, as `(log_number, landmark)`.
    ///
    /// This only affects [`Self::requested_trust_anchor_id()`]. Pass `None` when no landmark
    /// data is current.
    pub fn set_latest_landmark(&mut self, latest: Option<(u16, u64)>) -> Result<(), Error> {
        self.requested_trust_anchor_id = match latest {
            Some((log_number, landmark)) => {
                derive_trust_anchor_id(&self.ca_id, LANDMARK_GROUPS, log_number, landmark)?
            }
            None => self.ca_id.clone(),
        };
        Ok(())
    }

    /// Revokes every certificate whose serial number is in `serials` (MTC section 7.5).
    pub fn add_revoked_range(&mut self, serials: RangeInclusive<u64>) {
        self.revoked.push(serials);
    }

    /// The trust anchor ID a relying party requests this CA's certificates with.
    ///
    /// This is the landmark group ID of the latest landmark if one is set, otherwise the
    /// CA ID (MTC section 8.2.1). It is in binary form.
    pub fn requested_trust_anchor_id(&self) -> &[u8] {
        &self.requested_trust_anchor_id
    }

    /// Verifies the `id-alg-mtcProof` signature of `cert`, which names this CA as its issuer
    /// (MTC section 7.2).
    pub(crate) fn verify(
        &self,
        cert: &Cert<'_>,
        supported_sig_algs: &[&dyn SignatureVerificationAlgorithm],
        hash: &dyn MtcHash,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        let proof = MtcProof::from_bytes(cert.signed_data.signature.as_slice_less_safe())?;
        let serial = der_u64(cert.serial.as_slice_less_safe()).ok_or(Error::MalformedMtcProof)?;
        if self.revoked.iter().any(|range| range.contains(&serial)) {
            return Err(Error::CertRevoked);
        }

        let index = serial & ((1 << 48) - 1);
        let log_number = match u16::try_from(serial >> 48) {
            Ok(0) | Err(_) => return Err(Error::MalformedMtcProof),
            Ok(log_number) => log_number,
        };

        let entry_hash = leaf_hash(hash, cert.signed_data.data, proof.extensions)?;
        let subtree_hash = evaluate_inclusion_proof(
            hash,
            index,
            &entry_hash,
            proof.start,
            proof.end,
            proof.inclusion_proof,
        )?;

        // A trusted subtree decides alone, without falling back to cosignatures.
        let subtree = (log_number, proof.start, proof.end);
        if let Some(trusted) = self
            .trusted_subtrees
            .iter()
            .find(|t| (t.log_number, t.start, t.end) == subtree)
        {
            return match trusted.hash == subtree_hash {
                true => Ok(()),
                false => Err(Error::InvalidMtcProof),
            };
        }

        let log_origin = format!("{}{log_number}", self.log_origin_prefix);
        let mut buf = [0; MAX_COSIGNED_SUBTREE_LEN];
        let (mut ca_signed, mut witnesses) = (false, 0);
        for (id, signature) in proof.cosignatures() {
            if ca_signed && witnesses >= self.witness_quorum {
                break;
            }

            // Unknown cosigners, including GREASE, are ignored.
            let Some(position) = self.cosigners.iter().position(|c| c.id == id) else {
                continue;
            };

            let cosigner = &self.cosigners[position];
            let message = cosigned_subtree(
                &mut buf,
                cosigner.name.as_bytes(),
                0,
                log_origin.as_bytes(),
                proof.start,
                proof.end,
                &subtree_hash,
            )?;
            let signed_data = SignedData {
                data: Input::from(message),
                algorithm: Input::from(&cosigner.sig_alg),
                signature,
            };
            match signed_data.verify(supported_sig_algs, Input::from(&cosigner.spki), budget) {
                Ok(()) if position == 0 => ca_signed = true,
                Ok(()) => witnesses += 1,
                Err(err) if err.is_fatal() => return Err(err),
                Err(_) => {}
            }
        }

        match ca_signed && witnesses >= self.witness_quorum {
            true => Ok(()),
            false => Err(Error::InvalidMtcProof),
        }
    }
}

/// Reads the `MTCCertificationAuthority` extension of a CA certificate (MTC section 5.5).
///
/// `tbs` is the DER `TBSCertificate`. Returns the CA cosigner's signature algorithm and the
/// minimum and maximum serial numbers.
#[cfg(feature = "alloc")]
fn mtc_ca_extension(tbs: Input<'_>) -> Result<(&[u8], u64, u64), Error> {
    tbs.read_all(Error::BadDer, |rd| {
        der::nested(rd, Tag::Sequence, Error::BadDer, |tbs| {
            // version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
            for _ in 0..7 {
                der::read_tag_and_get_value(tbs)?;
            }

            let mut found = None;
            while !tbs.at_end() {
                // Skip issuerUniqueID and subjectUniqueID.
                let (tag, extensions) = der::read_tag_and_get_value(tbs)?;
                if tag != u8::from(Tag::ContextSpecificConstructed3) {
                    continue;
                }

                extensions.read_all(Error::BadDer, |rd| {
                    der::nested_of_mut(
                        rd,
                        Tag::Sequence,
                        Tag::Sequence,
                        Error::BadDer,
                        true,
                        |rd| {
                            let extension = Extension::from_der(rd)?;
                            if extension.id.as_slice_less_safe() != MTC_CA_EXTENSION {
                                return Ok(());
                            }

                            set_extension_once(&mut found, || match extension.critical {
                                true => mtc_ca_extension_value(extension.value),
                                false => Err(Error::ExtensionValueInvalid),
                            })
                        },
                    )
                })?;
            }

            found.ok_or(Error::ExtensionValueInvalid)
        })
    })
}

#[cfg(feature = "alloc")]
fn mtc_ca_extension_value(value: Input<'_>) -> Result<(&[u8], u64, u64), Error> {
    value.read_all(Error::ExtensionValueInvalid, |rd| {
        der::nested(rd, Tag::Sequence, Error::ExtensionValueInvalid, |rd| {
            let sig_alg = der::expect_tag(rd, Tag::Sequence)?.as_slice_less_safe();
            let mut serial = || {
                let serial = der::expect_tag(rd, Tag::Integer)?.as_slice_less_safe();
                match der_u64(serial) {
                    Some(serial) if serial >= MIN_SERIAL => Ok(serial),
                    _ => Err(Error::ExtensionValueInvalid),
                }
            };

            match (serial()?, serial()?) {
                (min, max) if min <= max => Ok((sig_alg, min, max)),
                _ => Err(Error::ExtensionValueInvalid),
            }
        })
    })
}

/// A cosigner of an [`MtcCa`]'s subtrees (MTC section 5.3).
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub struct MtcCosigner {
    id: Vec<u8>,
    /// The `SubjectPublicKeyInfo` contents, without the outer SEQUENCE.
    spki: Vec<u8>,
    /// The `AlgorithmIdentifier` contents.
    sig_alg: Vec<u8>,
    /// The `cosigner_name` of a `CosignedSubtree`.
    name: String,
}

#[cfg(feature = "alloc")]
impl MtcCosigner {
    /// Builds a cosigner from its cosigner ID, a trust anchor ID in binary form, its key
    /// and its signature algorithm.
    ///
    /// A cosignature is verified with the supported algorithm whose `signature_alg_id()` is
    /// `sig_alg`.
    pub fn new(
        id: &[u8],
        spki: &SubjectPublicKeyInfoDer<'_>,
        sig_alg: AlgorithmIdentifier,
    ) -> Result<Self, Error> {
        let spki = Input::from(spki.as_ref())
            .read_all(Error::BadDer, |rd| der::expect_tag(rd, Tag::Sequence))?;
        Self::from_parts(id, spki.as_slice_less_safe(), sig_alg.as_ref())
    }

    fn from_parts(id: &[u8], spki: &[u8], sig_alg: &[u8]) -> Result<Self, Error> {
        let mut name = String::from(TEXT_OID_PREFIX);
        write_trust_anchor_id(&mut name, id)?;
        Ok(Self {
            id: id.to_vec(),
            spki: spki.to_vec(),
            sig_alg: sig_alg.to_vec(),
            name,
        })
    }
}

/// A subtree the relying party already trusts, normally a landmark subtree (MTC section 7.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtcSubtree {
    /// The issuance log number.
    pub log_number: u16,
    /// The index of the subtree's first entry.
    pub start: u64,
    /// One past the index of the subtree's last entry.
    pub end: u64,
    /// The subtree hash.
    pub hash: [u8; 32],
}

/// A decoded `MTCProof` (MTC section 6.2).
pub(crate) struct MtcProof<'a> {
    /// The `extensions` field, including its length prefix.
    pub(crate) extensions: &'a [u8],
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) inclusion_proof: &'a [u8],
    signatures: Input<'a>,
}

impl<'a> MtcProof<'a> {
    pub(crate) fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        Input::from(bytes).read_all(Error::MalformedMtcProof, |rd| {
            let (extensions, ()) = rd.read_partial(|rd| {
                read_vec(rd, 2)?.read_all(Error::MalformedMtcProof, |rd| {
                    let mut prev = None;
                    while !rd.at_end() {
                        // Strictly ascending `extension_type`.
                        let extension_type = read_uint(rd, 2)?;
                        if prev.is_some_and(|prev| prev >= extension_type) {
                            return Err(Error::MalformedMtcProof);
                        }
                        prev = Some(extension_type);
                        read_vec(rd, 2)?;
                    }
                    Ok(())
                })
            })?;

            let start = read_uint(rd, 6)?;
            let end = read_uint(rd, 6)?;
            let inclusion_proof = read_vec(rd, 2)?.as_slice_less_safe();

            let signatures = read_vec(rd, 3)?;
            signatures.read_all(Error::MalformedMtcProof, |rd| {
                let mut prev: &[u8] = &[];
                while !rd.at_end() {
                    // Strictly increasing `cosigner_id`: shorter first, then bytewise.
                    let (id, _) = read_cosignature(rd)?;
                    if (prev.len(), prev) >= (id.len(), id) {
                        return Err(Error::MalformedMtcProof);
                    }
                    prev = id;
                }
                Ok(())
            })?;

            Ok(Self {
                extensions: extensions.as_slice_less_safe(),
                start,
                end,
                inclusion_proof,
                signatures,
            })
        })
    }

    /// Yields each `(cosigner_id, signature)`, in order.
    pub(crate) fn cosignatures(&self) -> impl Iterator<Item = (&'a [u8], Input<'a>)> {
        let mut rd = Reader::new(self.signatures);
        // `from_bytes()` already checked these decode.
        core::iter::from_fn(move || match rd.at_end() {
            true => None,
            false => read_cosignature(&mut rd).ok(),
        })
    }
}

fn read_cosignature<'a>(rd: &mut Reader<'a>) -> Result<(&'a [u8], Input<'a>), Error> {
    let id = read_vec(rd, 1)?.as_slice_less_safe();
    if id.is_empty() || id.len() > MAX_TRUST_ANCHOR_ID_LEN {
        return Err(Error::MalformedMtcProof);
    }

    Ok((id, read_vec(rd, 2)?))
}

/// Read a field with a big-endian length prefix of `len_bytes` bytes.
fn read_vec<'a>(rd: &mut Reader<'a>, len_bytes: usize) -> Result<Input<'a>, Error> {
    let len = usize::try_from(read_uint(rd, len_bytes)?).map_err(|_| Error::MalformedMtcProof)?;
    rd.read_bytes(len).map_err(|_| Error::MalformedMtcProof)
}

/// Read a big-endian unsigned integer of `len` bytes, at most 8.
fn read_uint(rd: &mut Reader<'_>, len: usize) -> Result<u64, Error> {
    let bytes = rd.read_bytes(len).map_err(|_| Error::MalformedMtcProof)?;
    Ok(bytes
        .as_slice_less_safe()
        .iter()
        .fold(0, |acc, &b| (acc << 8) | u64::from(b)))
}

/// Decodes the contents of a DER INTEGER that must be non-negative and fit in a `u64`.
pub(crate) fn der_u64(integer: &[u8]) -> Option<u64> {
    let bytes = match integer {
        // A leading zero is only allowed before a byte with its high bit set.
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => rest,
        [0, _, ..] => return None,
        [first, ..] if first & 0x80 == 0 => integer,
        // Empty or negative.
        _ => return None,
    };

    let mut buf = [0; 8];
    buf.get_mut(8usize.checked_sub(bytes.len())?..)?
        .copy_from_slice(bytes);
    Some(u64::from_be_bytes(buf))
}

/// Computes the hash of the `MTCLogEntry` for a certificate in a single pass (MTC section 7.2).
///
/// `tbs` is the DER `TBSCertificate`, including its tag and length. `extensions` is the
/// `MTCProof.extensions` field, including its length prefix.
pub(crate) fn leaf_hash(
    hash: &dyn MtcHash,
    tbs: Input<'_>,
    extensions: &[u8],
) -> Result<[u8; 32], Error> {
    tbs.read_all(Error::BadDer, |rd| {
        der::nested(rd, Tag::Sequence, Error::BadDer, |tbs| {
            let version = match tbs.peek(Tag::ContextSpecificConstructed0.into()) {
                true => read_tlv(tbs, Tag::ContextSpecificConstructed0)?,
                false => &[],
            };
            read_tlv(tbs, Tag::Integer)?; // serialNumber
            read_tlv(tbs, Tag::Sequence)?; // signature
            let issuer = read_tlv(tbs, Tag::Sequence)?;
            let validity = read_tlv(tbs, Tag::Sequence)?;
            let subject = read_tlv(tbs, Tag::Sequence)?;
            let (spki, spki_algorithm) = tbs.read_partial(|tbs| {
                der::nested(tbs, Tag::Sequence, Error::BadDer, |spki| {
                    let algorithm = read_tlv(spki, Tag::Sequence)?;
                    spki.skip_to_end();
                    Ok(algorithm)
                })
            })?;
            let rest = tbs.read_bytes_to_end();

            Ok(hash.sha256(&[
                &[LEAF_PREFIX],
                extensions,
                &TBS_CERT_ENTRY,
                version,
                issuer,
                validity,
                subject,
                spki_algorithm,
                // subjectPublicKeyInfoHash: an OCTET STRING of HASH_SIZE bytes.
                &[0x04, 0x20],
                &hash.sha256(&[spki.as_slice_less_safe()]),
                rest.as_slice_less_safe(),
            ]))
        })
    })
}

/// Read one DER element with the given tag, returning it with its tag and length.
fn read_tlv<'a>(rd: &mut Reader<'a>, tag: Tag) -> Result<&'a [u8], Error> {
    let (tlv, _) = rd.read_partial(|rd| der::expect_tag(rd, tag))?;
    Ok(tlv.as_slice_less_safe())
}

/// Builds the `CosignedSubtree` message a cosigner signs (MTC section 5.3.1).
pub(crate) fn cosigned_subtree<'b>(
    out: &'b mut [u8; MAX_COSIGNED_SUBTREE_LEN],
    cosigner_name: &[u8],
    timestamp: u64,
    log_origin: &[u8],
    start: u64,
    end: u64,
    subtree_hash: &[u8; 32],
) -> Result<&'b [u8], Error> {
    let short_len = |field: &[u8]| match u8::try_from(field.len()) {
        Ok(0) | Err(_) => Err(Error::InvalidMtcProof),
        Ok(len) => Ok(len),
    };

    let parts: [&[u8]; 9] = [
        COSIGNED_SUBTREE_LABEL,
        &[short_len(cosigner_name)?],
        cosigner_name,
        &timestamp.to_be_bytes(),
        &[short_len(log_origin)?],
        log_origin,
        &start.to_be_bytes(),
        &end.to_be_bytes(),
        subtree_hash,
    ];

    let mut len = 0;
    for part in parts {
        // Cannot overflow: `MAX_COSIGNED_SUBTREE_LEN` is the sum of the maximum field sizes.
        out[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }

    Ok(&out[..len])
}

/// Returns the CA ID of a distinguished name that is a CA ID (MTC section 5.1).
///
/// `name` is the contents of the `Name` SEQUENCE. Such a name has exactly one relative
/// distinguished name, holding exactly one `id-rdna-trustAnchorID` attribute.
pub(crate) fn ca_id_from_name(name: Input<'_>) -> Option<&[u8]> {
    name.read_all(Error::BadDer, |rd| {
        let (SET_TAG, rdn) = der::read_tag_and_get_value(rd)? else {
            return Err(Error::BadDer);
        };

        rdn.read_all(Error::BadDer, |rd| {
            der::nested(rd, Tag::Sequence, Error::BadDer, |attribute| {
                if der::expect_tag(attribute, Tag::OID)?.as_slice_less_safe() != TRUST_ANCHOR_ID {
                    return Err(Error::BadDer);
                }

                match der::read_tag_and_get_value(attribute)? {
                    (RELATIVE_OID_TAG, id) => Ok(id.as_slice_less_safe()),
                    _ => Err(Error::BadDer),
                }
            })
        })
    })
    .ok()
}

/// Appends the dotted decimal form of the trust anchor ID `id` to `out`.
///
/// Arcs above `u64::MAX` are rejected, as MTC section 5.3.1 permits.
#[cfg(feature = "alloc")]
pub(crate) fn write_trust_anchor_id(out: &mut String, id: &[u8]) -> Result<(), Error> {
    if id.is_empty() || id.len() > MAX_TRUST_ANCHOR_ID_LEN {
        return Err(Error::BadDer);
    }

    let (mut arc, mut arc_start, mut sep) = (0u64, true, "");
    for &byte in id {
        // Reject non-minimal encodings and overflow.
        if (arc_start && byte == 0x80) || arc > u64::MAX >> 7 {
            return Err(Error::BadDer);
        }

        arc = (arc << 7) | u64::from(byte & 0x7f);
        arc_start = byte & 0x80 == 0;
        if arc_start {
            write!(out, "{sep}{arc}").map_err(|_| Error::BadDer)?;
            (arc, sep) = (0, ".");
        }
    }

    match arc_start {
        true => Ok(()),
        // Truncated final arc.
        false => Err(Error::BadDer),
    }
}

/// Derives the trust anchor ID `ca_id.kind.log_number.landmark` (MTC section 8.2).
///
/// `kind` is 1 for a landmark, 2 for a landmark group.
#[cfg(feature = "alloc")]
pub(crate) fn derive_trust_anchor_id(
    ca_id: &[u8],
    kind: u64,
    log_number: u16,
    landmark: u64,
) -> Result<Vec<u8>, Error> {
    let mut id = ca_id.to_vec();
    for arc in [kind, u64::from(log_number), landmark] {
        let groups = bit_length(arc).div_ceil(7).max(1);
        for i in (0..groups).rev() {
            let continuation = if i > 0 { 0x80 } else { 0 };
            id.push(((arc >> (7 * i)) & 0x7f).to_le_bytes()[0] | continuation);
        }
    }

    // Never truncated.
    match id.len() > MAX_TRUST_ANCHOR_ID_LEN {
        true => Err(Error::BadDer),
        false => Ok(id),
    }
}

/// `id-alg-mtcProof` as an `AlgorithmIdentifier` value, with absent parameters.
///
/// 1.3.6.1.5.5.7.6.67, MTC section 6.2.
#[cfg(feature = "alloc")]
pub(crate) const MTC_PROOF_ALG_ID: &[u8] =
    &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43];

/// `id-pe-mtcCertificationAuthority-SHA256`, MTC section 5.5.
#[cfg(feature = "alloc")]
const MTC_CA_EXTENSION: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 1, 38);

/// `mtcMinSerial`, MTC section 5.5.
#[cfg(feature = "alloc")]
const MIN_SERIAL: u64 = 1 << 48;

/// The `landmarkGroups(2)` arc under a CA ID, MTC section 5.1.
#[cfg(feature = "alloc")]
const LANDMARK_GROUPS: u64 = 2;

/// Prefix of the text form of a trust anchor ID, MTC section 5.3.1.
#[cfg(feature = "alloc")]
const TEXT_OID_PREFIX: &str = "oid/1.3.6.1.4.1.";

/// `id-rdna-trustAnchorID`, MTC section 5.1.
const TRUST_ANCHOR_ID: &[u8] = &oid!(1, 3, 6, 1, 5, 5, 7, 25, 3);

const COSIGNED_SUBTREE_LABEL: &[u8] = b"subtree/v1\n\0";

pub(crate) const MAX_COSIGNED_SUBTREE_LEN: usize = 12 + 1 + 255 + 8 + 1 + 255 + 8 + 8 + HASH_SIZE;

/// `MTCLogEntryType::tbs_cert_entry`, big-endian.
const TBS_CERT_ENTRY: [u8; 2] = [0x00, 0x01];

/// The binary form of a trust anchor ID is at most this long (TAI section 4).
const MAX_TRUST_ANCHOR_ID_LEN: usize = 32;

const HASH_SIZE: usize = 32;
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const SET_TAG: u8 = 0x31;
const RELATIVE_OID_TAG: u8 = 0x0d;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn subtree_hashes() {
        // MTC appendix C.1.1.
        let mut tree = Tree::default();
        let mut out = Vec::new();
        for end in 0..=130 {
            for start in 0..=end {
                if is_valid_subtree(start, end) {
                    let hash = tree.mth(start, end);
                    out.extend(format!("[{start}, {end}) {}\n", hex(&hash)).bytes());
                }
            }
        }

        assert_eq!(
            hex(&Sha256.sha256(&[&out])),
            "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
        );
    }

    #[test]
    fn inclusion_proofs() {
        // MTC appendix C.1.2.
        let mut tree = Tree::default();
        let mut out = Vec::new();
        for end in 0..=130 {
            for start in 0..=end {
                if !is_valid_subtree(start, end) {
                    continue;
                }

                let subtree_hash = tree.mth(start, end);
                for index in start..end {
                    let proof = tree.inclusion_proof(index - start, start, end);
                    let mut line = format!("{index} [{start}, {end})");
                    for p in proof.chunks(HASH_SIZE) {
                        line.push_str(&format!(" {}", hex(p)));
                    }
                    out.extend(format!("{line}\n").bytes());

                    let leaf = tree.leaf(index);
                    let eval = |proof: &[u8]| {
                        evaluate_inclusion_proof(&Sha256, index, &leaf, start, end, proof)
                    };
                    assert_eq!(eval(&proof), Ok(subtree_hash));
                    if !proof.is_empty() {
                        assert!(eval(&proof[..proof.len() - 1]).is_err());
                        assert!(eval(&proof[..proof.len() - HASH_SIZE]).is_err());
                    }
                    assert!(eval(&[&proof[..], &[0]].concat()).is_err());
                    assert!(eval(&[&proof[..], &[0xaa; HASH_SIZE]].concat()).is_err());
                }
            }
        }

        assert_eq!(
            hex(&Sha256.sha256(&[&out])),
            "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
        );
    }

    #[test]
    fn consistency_proofs() {
        // MTC appendix C.1.3.
        let mut tree = Tree::default();
        let mut out = Vec::new();
        for n in 0..=130 {
            let root = tree.mth(0, n);
            for end in 0..=n {
                for start in 0..=end {
                    if !is_valid_subtree(start, end) {
                        continue;
                    }

                    let proof = tree.consistency_proof(start, end, n);
                    let mut line = format!("[{start}, {end}) {n}");
                    for p in proof.chunks(HASH_SIZE) {
                        line.push_str(&format!(" {}", hex(p)));
                    }
                    out.extend(format!("{line}\n").bytes());

                    let node = tree.mth(start, end);
                    let verify = |proof: &[u8], node: &[u8; 32], root: &[u8; 32]| {
                        verify_consistency_proof(&Sha256, n, start, end, proof, node, root)
                    };
                    assert_eq!(verify(&proof, &node, &root), Ok(()));
                    if !proof.is_empty() {
                        assert!(verify(&proof[..proof.len() - 1], &node, &root).is_err());
                        assert!(verify(&proof[..proof.len() - HASH_SIZE], &node, &root).is_err());
                    }
                    assert!(verify(&[&proof[..], &[0]].concat(), &node, &root).is_err());
                    let extended = [&proof[..], &[0xaa; HASH_SIZE]].concat();
                    assert!(verify(&extended, &node, &root).is_err());
                    assert!(verify(&proof, &flip(node), &root).is_err());
                    if start != end {
                        assert!(verify(&proof, &node, &flip(root)).is_err());
                    }
                }
            }
        }

        assert_eq!(
            hex(&Sha256.sha256(&[&out])),
            "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
        );
    }

    #[test]
    fn covering_subtrees() {
        // MTC appendix C.1.4.
        let mut out = Vec::new();
        for end in 0..=130 {
            for start in 0..=end {
                let [(ls, le), (rs, re)] = find_subtrees(start, end).unwrap();
                out.extend(format!("[{ls}, {le}) [{rs}, {re})\n").bytes());
            }
        }

        assert_eq!(
            hex(&Sha256.sha256(&[&out])),
            "7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0"
        );
        assert_eq!(find_subtrees(5, 13), Some([(4, 8), (8, 13)]));
        assert_eq!(find_subtrees(1, 0), None);
    }

    #[test]
    fn large_subtree_validity() {
        // MTC appendix C.2.1.
        for (start, end) in [
            (0, (1 << 47) + 1),
            (0, (1 << 48) - 1),
            (0, (1 << 62) + 1),
            (0, (1 << 63) - 1),
            (0, (1 << 63) + 1),
            (0, u64::MAX),
        ] {
            assert!(is_valid_subtree(start, end));
        }

        for (start, end) in [
            (1 << 46, (1 << 47) + 1),
            (1 << 46, (1 << 48) - 1),
            (1 << 61, (1 << 62) + 1),
            (1 << 61, (1 << 63) - 1),
            (1 << 62, (1 << 63) + 1),
            (1 << 62, u64::MAX),
        ] {
            assert!(!is_valid_subtree(start, end));
        }

        assert!(!is_valid_subtree(1, 0));
        assert!(is_valid_subtree(u64::MAX, u64::MAX));
    }

    #[test]
    fn large_covering_subtrees() {
        // MTC appendix C.2.4.
        for (range, expected) in [
            (
                (0x0, 0x800000000000),
                [(0x0, 0x400000000000), (0x400000000000, 0x800000000000)],
            ),
            (
                (0x500000000000, 0xd00000000000),
                [
                    (0x400000000000, 0x800000000000),
                    (0x800000000000, 0xd00000000000),
                ],
            ),
            (
                (0x7fffffffffff, 0x800000000001),
                [
                    (0x7fffffffffff, 0x800000000000),
                    (0x800000000000, 0x800000000001),
                ],
            ),
            (
                (0xfffffffffffe, 0xffffffffffff),
                [
                    (0xfffffffffffe, 0xffffffffffff),
                    (0xffffffffffff, 0xffffffffffff),
                ],
            ),
            (
                (0xffffffffffff, 0xffffffffffff),
                [
                    (0xffffffffffff, 0xffffffffffff),
                    (0xffffffffffff, 0xffffffffffff),
                ],
            ),
            (
                (0x0, 0x4000000000000000),
                [
                    (0x0, 0x2000000000000000),
                    (0x2000000000000000, 0x4000000000000000),
                ],
            ),
            (
                (0x2800000000000000, 0x6800000000000000),
                [
                    (0x2000000000000000, 0x4000000000000000),
                    (0x4000000000000000, 0x6800000000000000),
                ],
            ),
            (
                (0x3fffffffffffffff, 0x4000000000000001),
                [
                    (0x3fffffffffffffff, 0x4000000000000000),
                    (0x4000000000000000, 0x4000000000000001),
                ],
            ),
            (
                (0x7ffffffffffffffe, 0x7fffffffffffffff),
                [
                    (0x7ffffffffffffffe, 0x7fffffffffffffff),
                    (0x7fffffffffffffff, 0x7fffffffffffffff),
                ],
            ),
            (
                (0x7fffffffffffffff, 0x7fffffffffffffff),
                [
                    (0x7fffffffffffffff, 0x7fffffffffffffff),
                    (0x7fffffffffffffff, 0x7fffffffffffffff),
                ],
            ),
            (
                (0x0, 0x8000000000000000),
                [
                    (0x0, 0x4000000000000000),
                    (0x4000000000000000, 0x8000000000000000),
                ],
            ),
            (
                (0x5000000000000000, 0xd000000000000000),
                [
                    (0x4000000000000000, 0x8000000000000000),
                    (0x8000000000000000, 0xd000000000000000),
                ],
            ),
            (
                (0x7fffffffffffffff, 0x8000000000000001),
                [
                    (0x7fffffffffffffff, 0x8000000000000000),
                    (0x8000000000000000, 0x8000000000000001),
                ],
            ),
            (
                (0xfffffffffffffffe, 0xffffffffffffffff),
                [
                    (0xfffffffffffffffe, 0xffffffffffffffff),
                    (0xffffffffffffffff, 0xffffffffffffffff),
                ],
            ),
            (
                (0xffffffffffffffff, 0xffffffffffffffff),
                [
                    (0xffffffffffffffff, 0xffffffffffffffff),
                    (0xffffffffffffffff, 0xffffffffffffffff),
                ],
            ),
        ] {
            assert_eq!(find_subtrees(range.0, range.1), Some(expected));
        }
    }

    #[test]
    fn inclusion_proof_rejections() {
        let leaf = [0; 32];
        let eval = |index, start, end, proof: &[u8]| {
            evaluate_inclusion_proof(&Sha256, index, &leaf, start, end, proof)
        };

        // Single-entry subtree: the proof is empty and the hash is the entry hash.
        assert_eq!(eval(4, 4, 5, &[]), Ok(leaf));
        // Index outside the subtree.
        assert_eq!(eval(5, 4, 5, &[]), Err(Error::InvalidMtcProof));
        assert_eq!(eval(3, 4, 5, &[]), Err(Error::InvalidMtcProof));
        // Empty and invalid subtrees.
        assert_eq!(eval(4, 4, 4, &[]), Err(Error::InvalidMtcProof));
        assert_eq!(eval(5, 5, 7, &[0; 32]), Err(Error::InvalidMtcProof));
        // Not a multiple of the hash size.
        assert_eq!(eval(4, 4, 6, &[0; 33]), Err(Error::InvalidMtcProof));
        // Too short and too long.
        assert_eq!(eval(4, 4, 6, &[]), Err(Error::InvalidMtcProof));
        assert!(eval(4, 4, 6, &[0; 32]).is_ok());
        assert_eq!(eval(4, 4, 6, &[0; 64]), Err(Error::InvalidMtcProof));
        // Bounded however long the proof is.
        assert_eq!(
            eval(0, 0, u64::MAX, &[0; 65_504]),
            Err(Error::InvalidMtcProof)
        );
    }

    #[test]
    fn mtc_proof_minimal() {
        let bytes = [
            0, 0, // extensions
            0, 0, 0, 0, 0, 4, // start
            0, 0, 0, 0, 0, 8, // end
            0, 0, // inclusion_proof
            0, 0, 0, // signatures
        ];
        let proof = MtcProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof.extensions, &[0, 0]);
        assert_eq!((proof.start, proof.end), (4, 8));
        assert!(proof.inclusion_proof.is_empty());
        assert_eq!(proof.cosignatures().count(), 0);
    }

    #[test]
    fn mtc_proof_fields() {
        let bytes = [
            0, 9, 0, 1, 0, 1, b'x', 0, 2, 0, 0, // extensions: types 1 and 2
            0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, // start
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // end
            0, 2, 1, 2, // inclusion_proof
            0, 0, 15, // signatures
            1, 7, 0, 0, // id 07, empty signature
            1, 8, 0, 1, b's', // id 08
            2, 1, 0, 0, 1, b't', // id 01 00
        ];
        let proof = MtcProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof.extensions, &bytes[..11]);
        assert_eq!((proof.start, proof.end), ((1 << 48) - 2, (1 << 48) - 1));
        assert_eq!(proof.inclusion_proof, &[1, 2]);
        let cosignatures = proof
            .cosignatures()
            .map(|(id, sig)| (id, sig.as_slice_less_safe()))
            .collect::<Vec<_>>();
        assert_eq!(
            cosignatures,
            [(&[7][..], &[][..]), (&[8], b"s"), (&[1, 0], b"t")]
        );
    }

    #[test]
    fn mtc_proof_rejections() {
        let proof = |extensions: &[u8], signatures: &[u8]| {
            let mut bytes = extensions.to_vec();
            bytes.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
            bytes.extend(signatures);
            MtcProof::from_bytes(&bytes).map(|_| ())
        };
        let malformed = Err(Error::MalformedMtcProof);

        assert_eq!(proof(&[0, 0], &[0, 0, 0]), Ok(()));
        // Truncated and trailing data.
        assert_eq!(proof(&[0, 0], &[0, 0]), malformed);
        assert_eq!(proof(&[0, 0], &[0, 0, 0, 0]), malformed);
        // Extensions: truncated, duplicated or out of order.
        assert_eq!(proof(&[0, 3, 0, 1, 0], &[0, 0, 0]), malformed);
        assert_eq!(
            proof(&[0, 8, 0, 1, 0, 0, 0, 1, 0, 0], &[0, 0, 0]),
            malformed
        );
        assert_eq!(
            proof(&[0, 8, 0, 2, 0, 0, 0, 1, 0, 0], &[0, 0, 0]),
            malformed
        );
        // Cosigner IDs: empty, too long, duplicated, or out of order.
        assert_eq!(proof(&[0, 0], &[0, 0, 3, 0, 0, 0]), malformed);
        let mut long_id = vec![0, 0, 36, 33];
        long_id.extend([1; 33]);
        long_id.extend([0, 0]);
        assert_eq!(proof(&[0, 0], &long_id), malformed);
        assert_eq!(
            proof(&[0, 0], &[0, 0, 8, 1, 7, 0, 0, 1, 7, 0, 0]),
            malformed
        );
        assert_eq!(
            proof(&[0, 0], &[0, 0, 8, 1, 8, 0, 0, 1, 7, 0, 0]),
            malformed
        );
        assert_eq!(
            proof(&[0, 0], &[0, 0, 9, 2, 1, 0, 0, 0, 1, 7, 0, 0]),
            malformed
        );
        // Signature overruns its cosignature.
        assert_eq!(proof(&[0, 0], &[0, 0, 4, 1, 7, 0, 1]), malformed);
    }

    #[test]
    fn serial_numbers() {
        assert_eq!(der_u64(&[0]), Some(0));
        assert_eq!(der_u64(&[0x7f]), Some(0x7f));
        assert_eq!(der_u64(&[0, 0x80]), Some(0x80));
        assert_eq!(
            der_u64(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Some(u64::MAX)
        );
        assert_eq!(der_u64(&[1, 0, 0, 0, 0, 0, 9]), Some((1 << 48) | 9));
        // Empty, negative, non-minimal or too large.
        assert_eq!(der_u64(&[]), None);
        assert_eq!(der_u64(&[0x80]), None);
        assert_eq!(der_u64(&[0, 1]), None);
        assert_eq!(der_u64(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn leaf_hash_skips_serial_and_signature() {
        let version = [0xa0, 0x03, 0x02, 0x01, 0x02];
        let serial = [0x02, 0x01, 0x05];
        let signature = [
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43,
        ];
        let issuer = [0x30, 0x01, 0xaa];
        let validity = [0x30, 0x01, 0xbb];
        let subject = [0x30, 0x01, 0xcc];
        let spki_algorithm = [0x30, 0x01, 0xdd];
        let spki = [&[0x30, 0x06][..], &spki_algorithm, &[0x03, 0x01, 0x00]].concat();
        let rest = [0xa3, 0x02, 0x30, 0x00];
        let tbs = [
            &version[..],
            &serial,
            &signature,
            &issuer,
            &validity,
            &subject,
            &spki,
            &rest,
        ]
        .concat();
        let tbs = [&[0x30, u8::try_from(tbs.len()).unwrap()][..], &tbs].concat();
        let extensions = [0, 4, 0, 1, 0, 0];

        let expected = Sha256.sha256(&[
            &[0],
            &extensions,
            &[0, 1],
            &version,
            &issuer,
            &validity,
            &subject,
            &spki_algorithm,
            &[0x04, 0x20],
            &Sha256.sha256(&[&spki]),
            &rest,
        ]);
        assert_eq!(
            leaf_hash(&Sha256, Input::from(&tbs), &extensions),
            Ok(expected)
        );
    }

    #[test]
    fn cosigned_subtree_layout() {
        let mut buf = [0; MAX_COSIGNED_SUBTREE_LEN];
        let msg = cosigned_subtree(&mut buf, b"name", 7, b"origin", 8, 13, &[0xab; 32]).unwrap();
        let expected = [
            &b"subtree/v1\n\0"[..],
            &[4],
            b"name",
            &7u64.to_be_bytes(),
            &[6],
            b"origin",
            &8u64.to_be_bytes(),
            &13u64.to_be_bytes(),
            &[0xab; 32],
        ]
        .concat();
        assert_eq!(msg, expected);

        // The largest message fits.
        let long = [b'x'; 255];
        let msg = cosigned_subtree(&mut buf, &long, 0, &long, 0, 0, &[0; 32]).unwrap();
        assert_eq!(msg.len(), MAX_COSIGNED_SUBTREE_LEN);

        let too_long = [b'x'; 256];
        let err = Err(Error::InvalidMtcProof);
        assert_eq!(
            cosigned_subtree(&mut buf, &too_long, 0, b"o", 0, 0, &[0; 32]),
            err
        );
        assert_eq!(
            cosigned_subtree(&mut buf, b"", 0, b"o", 0, 0, &[0; 32]),
            err
        );
    }

    #[test]
    fn ca_id_names() {
        // 1.3.6.1.5.5.7.25.3=#0d0481fd5901, MTC section 5.1.
        let name = [
            0x31, 0x12, 0x30, 0x10, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x19, 0x03,
            0x0d, 0x04, 0x81, 0xfd, 0x59, 0x01,
        ];
        assert_eq!(
            ca_id_from_name(Input::from(&name)),
            Some(&[0x81, 0xfd, 0x59, 0x01][..])
        );

        // Two relative distinguished names.
        let twice = [&name[..], &name].concat();
        assert_eq!(ca_id_from_name(Input::from(&twice)), None);
        // Wrong value type: UTF8String.
        let mut utf8 = name;
        utf8[14] = 0x0c;
        assert_eq!(ca_id_from_name(Input::from(&utf8)), None);
        // Wrong attribute type: commonName.
        let cn = [
            0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, b'c', b'a',
        ];
        assert_eq!(ca_id_from_name(Input::from(&cn)), None);
        assert_eq!(ca_id_from_name(Input::from(&[])), None);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn trust_anchor_id_text() {
        let text = |id: &[u8]| {
            let mut out = String::new();
            write_trust_anchor_id(&mut out, id).map(|()| out)
        };

        assert_eq!(text(&[0x81, 0xfd, 0x59, 0x01]).unwrap(), "32473.1");
        assert_eq!(text(&[0]).unwrap(), "0");
        assert_eq!(
            text(&[0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).unwrap(),
            "18446744073709551615"
        );
        // Empty, too long, truncated, non-minimal, or an arc above `u64::MAX`.
        assert_eq!(text(&[]), Err(Error::BadDer));
        assert_eq!(text(&[1; 33]), Err(Error::BadDer));
        assert!(text(&[1; 32]).is_ok());
        assert_eq!(text(&[0x81, 0xfd]), Err(Error::BadDer));
        assert_eq!(text(&[0x80, 0x01]), Err(Error::BadDer));
        assert_eq!(
            text(&[0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            Err(Error::BadDer)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn trust_anchor_id_derivation() {
        // CA 32473.100, log 8, landmark 42, MTC section 8.2.1.
        let ca_id = [0x81, 0xfd, 0x59, 0x64];
        let group = derive_trust_anchor_id(&ca_id, 2, 8, 42).unwrap();
        assert_eq!(group, [0x81, 0xfd, 0x59, 0x64, 0x02, 0x08, 0x2a]);
        let mut out = String::new();
        write_trust_anchor_id(&mut out, &group).unwrap();
        assert_eq!(out, "32473.100.2.8.42");

        assert_eq!(
            derive_trust_anchor_id(&ca_id, 1, 0xffff, 128).unwrap(),
            [0x81, 0xfd, 0x59, 0x64, 0x01, 0x83, 0xff, 0x7f, 0x81, 0x00]
        );

        // Never truncated.
        assert_eq!(
            derive_trust_anchor_id(&[1; 21], 2, 1, u64::MAX),
            Err(Error::BadDer)
        );
        assert!(derive_trust_anchor_id(&[1; 20], 2, 1, u64::MAX).is_ok());
    }

    fn flip(mut hash: [u8; 32]) -> [u8; 32] {
        hash[0] ^= 1;
        hash
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A Merkle tree over `d[i] = i`, as in MTC appendix C.1.
    #[derive(Default)]
    struct Tree {
        cache: HashMap<(u64, u64), [u8; 32]>,
    }

    impl Tree {
        fn leaf(&self, index: u64) -> [u8; 32] {
            Sha256.sha256(&[&[LEAF_PREFIX], &[u8::try_from(index).unwrap()]])
        }

        /// MTH(D[start:end]), RFC 9162 section 2.1.1.
        fn mth(&mut self, start: u64, end: u64) -> [u8; 32] {
            if let Some(hash) = self.cache.get(&(start, end)) {
                return *hash;
            }

            let hash = match end - start {
                0 => Sha256.sha256(&[]),
                1 => self.leaf(start),
                n => {
                    let k = split(n);
                    let (left, right) = (self.mth(start, start + k), self.mth(start + k, end));
                    Sha256.sha256(&[&[NODE_PREFIX], &left, &right])
                }
            };
            self.cache.insert((start, end), hash);
            hash
        }

        /// PATH(m, D[start:end]), RFC 9162 section 2.1.3.1.
        fn inclusion_proof(&mut self, m: u64, start: u64, end: u64) -> Vec<u8> {
            let n = end - start;
            if n <= 1 {
                return Vec::new();
            }

            let k = split(n);
            let (mut proof, sibling) = match m < k {
                true => (
                    self.inclusion_proof(m, start, start + k),
                    self.mth(start + k, end),
                ),
                false => (
                    self.inclusion_proof(m - k, start + k, end),
                    self.mth(start, start + k),
                ),
            };
            proof.extend(sibling);
            proof
        }

        /// SUBTREE_PROOF(start, end, D_n), MTC section 4.4.1.
        fn consistency_proof(&mut self, start: u64, end: u64, n: u64) -> Vec<u8> {
            match start == end {
                true => Vec::new(),
                false => self.subproof(start, end, 0, n, true),
            }
        }

        /// SUBTREE_SUBPROOF(start, end, D[lo:hi], b), with `start` and `end` relative to `lo`.
        fn subproof(&mut self, start: u64, end: u64, lo: u64, hi: u64, b: bool) -> Vec<u8> {
            let n = hi - lo;
            if start == 0 && end == n {
                return match b {
                    true => Vec::new(),
                    false => self.mth(lo, hi).to_vec(),
                };
            }

            let k = split(n);
            let (mut proof, sibling) = if end <= k {
                (
                    self.subproof(start, end, lo, lo + k, b),
                    self.mth(lo + k, hi),
                )
            } else if k <= start {
                let proof = self.subproof(start - k, end - k, lo + k, hi, b);
                (proof, self.mth(lo, lo + k))
            } else {
                let proof = self.subproof(0, end - k, lo + k, hi, false);
                (proof, self.mth(lo, lo + k))
            };
            proof.extend(sibling);
            proof
        }
    }

    /// The largest power of two smaller than `n`.
    fn split(n: u64) -> u64 {
        1 << (bit_length(n - 1) - 1)
    }

    struct Sha256;

    impl MtcHash for Sha256 {
        fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
            let hash = rustls_aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
                .common
                .hash_provider;
            let mut ctx = hash.start();
            for part in parts {
                ctx.update(part);
            }
            ctx.finish().as_ref().try_into().unwrap()
        }
    }
}
