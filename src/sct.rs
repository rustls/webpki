#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::error::Error as StdError;
use core::fmt;

#[cfg(feature = "alloc")]
use pki_types::{SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, alg_id};
use untrusted::{Input, Reader};

#[cfg(feature = "alloc")]
use crate::{der, signed_data};

pub(crate) struct SctParser<'a> {
    reader: Reader<'a>,
    done: bool,
}

impl<'a> SctParser<'a> {
    pub(crate) fn new(input: Option<Input<'a>>) -> Result<Self, Error> {
        Ok(SctParser {
            reader: match input {
                Some(input) => Reader::new(
                    input.read_all(Error::MalformedSct, |rd| read_field(rd, non_zero_u16_len))?,
                ),
                None => Reader::new(Input::from(&[])),
            },
            done: false,
        })
    }
}

impl<'a> Iterator for SctParser<'a> {
    type Item = Result<SignedCertificateTimestamp<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.reader.at_end() {
            return None;
        }

        let result = read_field(&mut self.reader, non_zero_u16_len)
            .and_then(|item| SignedCertificateTimestamp::try_from(item.as_slice_less_safe()));
        match result {
            Err(Error::UnsupportedSctVersion) | Ok(_) => {}
            Err(_) => self.done = true,
        }
        Some(result)
    }
}

/// This is `SignedCertificateTimestamp` defined in [RFC6962][].
///
/// [RFC6962]: https://www.rfc-editor.org/rfc/rfc6962.html#section-3.2
#[derive(Debug, PartialEq)]
pub(crate) struct SignedCertificateTimestamp<'a> {
    log_id: [u8; 32],
    timestamp_ms: u64,
    extensions: &'a [u8],
    signature_algorithm: u16,
    signature: &'a [u8],
}

impl SignedCertificateTimestamp<'_> {
    /// Verify this SCT's signature, as issued by a log for a precertificate.
    ///
    /// `log_spki` is the log's DER-encoded `SubjectPublicKeyInfo`, as published in log lists.
    #[cfg_attr(not(test), expect(dead_code))]
    #[cfg(feature = "alloc")]
    pub(crate) fn verify_precert_signature(
        &self,
        log_spki: &SubjectPublicKeyInfoDer<'_>,
        tbs_precert: &[u8],
        issuer_key_hash: &[u8; 32],
        signature_algorithm: &dyn SignatureVerificationAlgorithm,
    ) -> Result<(), Error> {
        // opaque TBSCertificate<1..2^24-1>;
        //
        // struct {
        //   opaque issuer_key_hash[32];
        //   TBSCertificate tbs_certificate;
        // } PreCert;
        //
        // digitally-signed struct {
        //     Version sct_version = v1;
        //     SignatureType signature_type = certificate_timestamp;
        //     uint64 timestamp;
        //     LogEntryType entry_type = precert_entry;
        //     precert_entry PreCert;
        //     CtExtensions extensions;
        // };

        // A `TBSCertificate` outside `<1..2^24-1>` cannot be encoded, so
        // cannot have been signed by the log.
        let Ok(tbs_len @ 1..0x100_0000) = u32::try_from(tbs_precert.len()) else {
            return Err(Error::InvalidSctSignature);
        };

        let Ok(extensions_len) = u16::try_from(self.extensions.len()) else {
            // `extensions` was read from a field with a u16 length prefix.
            unreachable!();
        };

        let mut signed = Vec::with_capacity(
            1 + 1 + 8 + 2 + 32 + 3 + tbs_precert.len() + 2 + self.extensions.len(),
        );
        signed.extend_from_slice(&[0x0, 0x0]);
        signed.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        signed.extend_from_slice(&[0x0, 0x1]);
        signed.extend_from_slice(issuer_key_hash);
        signed.extend_from_slice(&tbs_len.to_be_bytes()[1..]);
        signed.extend_from_slice(tbs_precert);
        signed.extend_from_slice(&extensions_len.to_be_bytes());
        signed.extend_from_slice(self.extensions);

        // `signed_data::verify_signature` takes the contents of the SPKI `SEQUENCE`.
        let log_spki = Input::from(log_spki)
            .read_all(crate::Error::BadDer, |rd| {
                der::expect_tag(rd, der::Tag::Sequence)
            })
            .map_err(|_| Error::InvalidSctSignature)?;

        signed_data::verify_signature(
            signature_algorithm,
            log_spki,
            Input::from(&signed),
            Input::from(self.signature),
        )
        .map_err(|_| Error::InvalidSctSignature)
    }

    #[cfg_attr(not(test), expect(dead_code))]
    #[cfg(feature = "alloc")]
    pub(crate) fn choose_signature_algorithm<'a>(
        &self,
        supported_algorithms: &[&'a dyn SignatureVerificationAlgorithm],
    ) -> Option<&'a dyn SignatureVerificationAlgorithm> {
        let (signature_alg_id, public_key_alg_id) = match self.signature_algorithm {
            0x0403 => (alg_id::ECDSA_SHA256, alg_id::ECDSA_P256),
            _ => return None,
        };

        supported_algorithms
            .iter()
            .find(|a| {
                a.signature_alg_id() == signature_alg_id
                    && a.public_key_alg_id() == public_key_alg_id
            })
            .copied()
    }

    pub(crate) fn log_id_and_timestamp(&self) -> LogIdAndTimestamp {
        LogIdAndTimestamp {
            log_id: self.log_id,
            timestamp_ms: self.timestamp_ms,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for SignedCertificateTimestamp<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let input = Input::from(bytes);
        input.read_all(Error::MalformedSct, |rd| {
            match read_array(rd)? {
                [0] => {}
                _ => return Err(Error::UnsupportedSctVersion),
            };

            let log_id = read_array(rd)?;
            let timestamp_ms = u64::from_be_bytes(read_array(rd)?);
            let extensions = read_field(rd, any_u16_len)?.as_slice_less_safe();
            let signature_algorithm = u16::from_be_bytes(read_array(rd)?);
            let signature = read_field(rd, non_zero_u16_len)?.as_slice_less_safe();

            Ok(SignedCertificateTimestamp {
                log_id,
                timestamp_ms,
                extensions,
                signature_algorithm,
                signature,
            })
        })
    }
}

/// The certificate transparency log ID and associated inclusion timestamp.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LogIdAndTimestamp {
    /// Log ID
    pub log_id: [u8; 32],
    /// Inclusion timestamp in milliseconds.
    pub timestamp_ms: u64,
}

/// Read a length-prefixed field from `rd`.
///
/// The length is encoded in `N` bytes and those bytes are decoded by `into_size`.
fn read_field<'a, const N: usize>(
    rd: &mut Reader<'a>,
    into_size: fn([u8; N]) -> Result<usize, Error>,
) -> Result<Input<'a>, Error> {
    let len = into_size(read_array::<N>(rd)?)?;
    rd.read_bytes(len).map_err(|_| Error::MalformedSct)
}

/// Read `N` bytes from `rd` as an array.
fn read_array<const N: usize>(rd: &mut Reader<'_>) -> Result<[u8; N], Error> {
    rd.read_bytes(N)
        .map_err(|_| Error::MalformedSct)?
        .as_slice_less_safe()
        .try_into()
        .map_err(|_| Error::MalformedSct)
}

/// Converts two bytes into a usize.
///
/// Does not fail.
fn any_u16_len(bytes: [u8; 2]) -> Result<usize, Error> {
    Ok(usize::from(u16::from_be_bytes(bytes)))
}

/// Converts two bytes into a usize, erroring if the result is zero.
fn non_zero_u16_len(bytes: [u8; 2]) -> Result<usize, Error> {
    match any_u16_len(bytes)? {
        0 => Err(Error::MalformedSct),
        len => Ok(len),
    }
}

/// Possible errors from SCT parsing and processing
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The SCT was somehow misencoded, truncated or otherwise corrupt.
    MalformedSct,

    /// An unsupported SCT version was encountered.
    ///
    /// This library only supports `v1(0)`.
    UnsupportedSctVersion,

    /// A signature on an SCT was invalid.
    InvalidSctSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSct => write!(f, "malformed SCT"),
            Self::UnsupportedSctVersion => write!(f, "unsupported SCT version"),
            Self::InvalidSctSignature => write!(f, "invalid SCT signature"),
        }
    }
}

impl StdError for Error {}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::vec;

    #[test]
    fn absent_sct_sequence() {
        assert!(SctParser::new(None).unwrap().next().is_none());
    }

    #[test]
    fn empty_sct_sequence() {
        assert_eq!(
            Some(Error::MalformedSct),
            SctParser::new(Some(Input::from(&[]))).err()
        );
    }

    #[test]
    fn truncated_sct_length_in_sequence() {
        assert_eq!(
            Some(Error::MalformedSct),
            SctParser::new(Some(Input::from(&[0]))).err()
        );
    }

    #[test]
    fn empty_sct_in_sequence() {
        assert_eq!(
            Some(Error::MalformedSct),
            SctParser::new(Some(Input::from(&[0, 0]))).err()
        );
    }

    #[test]
    fn truncated_sct_in_sequence() {
        assert_eq!(
            Some(Error::MalformedSct),
            SctParser::new(Some(Input::from(&[0, 1]))).err()
        );
    }

    #[test]
    fn sample_sct() {
        let bytes = encode_sct_list([TestSct::default().encode()]);

        SignedCertificateTimestamp::try_from(&bytes[4..]).unwrap();

        assert_eq!(
            SignedCertificateTimestamp {
                log_id: [b'l'; 32],
                timestamp_ms: 0x74747474_74747474,
                extensions: b"",
                signature_algorithm: 0x7361,
                signature: b"s",
            },
            SctParser::new(Some(Input::from(&bytes)))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn terminate_iterator_after_error_within_sct() {
        let bytes = encode_sct_list([TestSct {
            signature: Vec::new(),
            ..Default::default()
        }
        .encode()]);

        SignedCertificateTimestamp::try_from(&bytes[4..]).unwrap_err();

        let mut iter = SctParser::new(Some(Input::from(&bytes))).unwrap();
        assert_eq!(iter.next(), Some(Err(Error::MalformedSct)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn continue_iterator_after_unsupported_version() {
        let bytes = encode_sct_list([
            TestSct::default().encode(),
            vec![
                0x1, // unsupported SCT version
                0x7, 0x0, 0x0, 0x1, b'?', // version-specific contents
            ],
            TestSct {
                log_id: [b'm'; 32],
                timestamp_ms: u64::from_be_bytes([b'u'; 8]),
                ..Default::default()
            }
            .encode(),
        ]);

        let mut iter = SctParser::new(Some(Input::from(&bytes))).unwrap();
        assert_eq!(
            iter.next().unwrap().unwrap().log_id_and_timestamp(),
            LogIdAndTimestamp {
                log_id: [b'l'; 32],
                timestamp_ms: 0x74747474_74747474,
            }
        );
        assert_eq!(iter.next(), Some(Err(Error::UnsupportedSctVersion)));
        assert_eq!(
            iter.next().unwrap().unwrap().log_id_and_timestamp(),
            LogIdAndTimestamp {
                log_id: [b'm'; 32],
                timestamp_ms: 0x75757575_75757575,
            }
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn illegal_empty_signature() {
        let bytes = TestSct {
            signature: Vec::new(),
            ..Default::default()
        }
        .encode();

        assert_eq!(
            Some(Error::MalformedSct),
            SignedCertificateTimestamp::try_from(&bytes[..]).err()
        );
    }

    #[test]
    fn illegal_unknown_version() {
        let bytes = TestSct {
            version: 1,
            ..Default::default()
        }
        .encode();

        assert_eq!(
            Some(Error::UnsupportedSctVersion),
            SignedCertificateTimestamp::try_from(&bytes[..]).err()
        );
    }

    #[test]
    fn illegal_trailing_extension_data() {
        let bytes = [
            0x0, 0x1,  // extension outer length
            b'?', // doesn't matter
            b'x', // unexpected trailing data
        ];

        assert_eq!(
            Some(Error::MalformedSct),
            SctParser::new(Some(Input::from(&bytes))).err()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn precert_signed_data_layout() {
        let sct = test_sct(b"\x11\x22\x33\x44");
        let issuer_key_hash = [b'h'; 32];

        let mut expected = vec![
            0x0, // sct_version
            0x0, // signature_type
        ];
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // timestamp
        expected.extend_from_slice(&[0x0, 0x1]); // entry_type
        expected.extend_from_slice(&issuer_key_hash);
        expected.extend_from_slice(&[0x0, 0x0, 0x3]); // tbs length
        expected.extend_from_slice(b"tbs");
        expected.extend_from_slice(&[0x0, 0x4]); // extensions length
        expected.extend_from_slice(b"\x11\x22\x33\x44");

        assert_eq!(
            sct.verify_precert_signature(
                &test_spki(),
                b"tbs",
                &issuer_key_hash,
                &ExpectMessage(expected)
            ),
            Ok(())
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn precert_tbs_length_bounds() {
        let sct = test_sct(b"");

        assert_eq!(
            sct.verify_precert_signature(&test_spki(), b"", &[0; 32], &AcceptAll),
            Err(Error::InvalidSctSignature)
        );
        assert_eq!(
            sct.verify_precert_signature(&test_spki(), &vec![0; 0xff_ffff], &[0; 32], &AcceptAll),
            Ok(())
        );
        assert_eq!(
            sct.verify_precert_signature(&test_spki(), &vec![0; 0x100_0000], &[0; 32], &AcceptAll),
            Err(Error::InvalidSctSignature)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn precert_log_key_must_be_spki() {
        let sct = test_sct(b"");
        let spki = test_spki();

        // The `SEQUENCE` contents, or the bare key, are not accepted.
        for key in [&spki[2..], b"key"] {
            assert_eq!(
                sct.verify_precert_signature(
                    &SubjectPublicKeyInfoDer::from(key),
                    b"tbs",
                    &[0; 32],
                    &AcceptAll
                ),
                Err(Error::InvalidSctSignature)
            );
        }

        // Nor is an SPKI for the wrong key type.
        let rsa_spki = SubjectPublicKeyInfoDer::from(der::asn1_wrap(
            der::Tag::Sequence,
            &[
                der::asn1_wrap(der::Tag::Sequence, alg_id::RSA_ENCRYPTION.as_ref()),
                vec![0x03, 0x04, 0x00, b'k', b'e', b'y'],
            ]
            .concat(),
        ));
        assert_eq!(
            sct.verify_precert_signature(&rsa_spki, b"tbs", &[0; 32], &AcceptAll),
            Err(Error::InvalidSctSignature)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn choose_signature_algorithm() {
        let mut sct = test_sct(b"");
        assert!(sct.choose_signature_algorithm(&[&AcceptAll]).is_some());
        assert!(sct.choose_signature_algorithm(&[]).is_none());

        // RSA-PKCS1-SHA256 is allowed by RFC 6962 but not supported.
        sct.signature_algorithm = 0x0401;
        assert!(sct.choose_signature_algorithm(&[&AcceptAll]).is_none());
    }

    /// A P-256 `SubjectPublicKeyInfo` whose key is `b"key"`.
    #[cfg(feature = "alloc")]
    fn test_spki() -> SubjectPublicKeyInfoDer<'static> {
        SubjectPublicKeyInfoDer::from(der::asn1_wrap(
            der::Tag::Sequence,
            &[
                der::asn1_wrap(der::Tag::Sequence, alg_id::ECDSA_P256.as_ref()),
                vec![0x03, 0x04, 0x00, b'k', b'e', b'y'], // BIT STRING
            ]
            .concat(),
        ))
    }

    #[cfg(feature = "alloc")]
    fn test_sct(extensions: &[u8]) -> SignedCertificateTimestamp<'_> {
        SignedCertificateTimestamp {
            log_id: [b'l'; 32],
            timestamp_ms: 0x01020304_05060708,
            extensions,
            signature_algorithm: 0x0403,
            signature: b"sig",
        }
    }

    /// An ECDSA-P256-SHA256 stand-in that accepts only `self.0` as the message.
    #[cfg(feature = "alloc")]
    #[derive(Debug)]
    struct ExpectMessage(Vec<u8>);

    #[cfg(feature = "alloc")]
    impl SignatureVerificationAlgorithm for ExpectMessage {
        fn verify_signature(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), pki_types::InvalidSignature> {
            assert_eq!(public_key, b"key");
            assert_eq!(signature, b"sig");
            assert_eq!(message, self.0);
            Ok(())
        }

        fn public_key_alg_id(&self) -> pki_types::AlgorithmIdentifier {
            alg_id::ECDSA_P256
        }

        fn signature_alg_id(&self) -> pki_types::AlgorithmIdentifier {
            alg_id::ECDSA_SHA256
        }
    }

    /// An ECDSA-P256-SHA256 stand-in that accepts any message.
    #[cfg(feature = "alloc")]
    #[derive(Debug)]
    struct AcceptAll;

    #[cfg(feature = "alloc")]
    impl SignatureVerificationAlgorithm for AcceptAll {
        fn verify_signature(
            &self,
            _public_key: &[u8],
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<(), pki_types::InvalidSignature> {
            Ok(())
        }

        fn public_key_alg_id(&self) -> pki_types::AlgorithmIdentifier {
            alg_id::ECDSA_P256
        }

        fn signature_alg_id(&self) -> pki_types::AlgorithmIdentifier {
            alg_id::ECDSA_SHA256
        }
    }

    struct TestSct {
        version: u8,
        log_id: [u8; 32],
        timestamp_ms: u64,
        extensions: Vec<u8>,
        signature_algorithm: [u8; 2],
        signature: Vec<u8>,
    }

    impl TestSct {
        fn encode(self) -> Vec<u8> {
            let mut encoded = vec![self.version];
            encoded.extend_from_slice(&self.log_id);
            encoded.extend_from_slice(&self.timestamp_ms.to_be_bytes());
            encoded.extend(u16_length_prefixed(self.extensions));
            encoded.extend_from_slice(&self.signature_algorithm);
            encoded.extend(u16_length_prefixed(self.signature));
            encoded
        }
    }

    impl Default for TestSct {
        fn default() -> Self {
            Self {
                version: 0,
                log_id: [b'l'; 32],
                timestamp_ms: u64::from_be_bytes([b't'; 8]),
                extensions: Vec::new(),
                signature_algorithm: *b"sa",
                signature: vec![b's'],
            }
        }
    }

    fn encode_sct_list(scts: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        let mut encoded = Vec::new();
        for sct in scts {
            encoded.extend(u16_length_prefixed(sct));
        }
        u16_length_prefixed(encoded)
    }

    fn u16_length_prefixed(body: Vec<u8>) -> Vec<u8> {
        let length = u16::try_from(body.len()).unwrap();
        let mut encoded = Vec::with_capacity(2 + body.len());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend(body);
        encoded
    }
}
