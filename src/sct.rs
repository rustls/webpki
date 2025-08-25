use core::marker::PhantomData;

use untrusted::{Input, Reader};

pub(crate) struct SctParser<'a> {
    reader: Reader<'a>,
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
        })
    }
}

impl<'a> Iterator for SctParser<'a> {
    type Item = Result<SignedCertificateTimestamp<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.at_end() {
            return None;
        }

        Some(
            read_field(&mut self.reader, non_zero_u16_len)
                .and_then(|item| SignedCertificateTimestamp::try_from(item.as_slice_less_safe())),
        )
    }
}

/// This is `SignedCertificateTimestamp` defined in [RFC6962][].
///
/// [RFC6962]: https://www.rfc-editor.org/rfc/rfc6962.html#section-3.2
#[derive(Debug, PartialEq)]
pub(crate) struct SignedCertificateTimestamp<'a> {
    log_id: [u8; 32],
    timestamp_ms: u64,
    _future_lifetime_for_signature: PhantomData<&'a ()>,
}

impl SignedCertificateTimestamp<'_> {
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
            let _extensions = read_field(rd, any_u16_len)?;
            let _signature_algorithm = u16::from_be_bytes(read_array(rd)?);
            let _signature = read_field(rd, non_zero_u16_len)?;

            Ok(SignedCertificateTimestamp {
                log_id,
                timestamp_ms,
                _future_lifetime_for_signature: PhantomData,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let bytes = [
            0x0, 0x32, // outer len
            0x0, 0x30, // item len
            0x0,  // version
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', // log id
            b't', b't', b't', b't', b't', b't', b't', b't', // timestamp
            0x0, 0x0, // extensions
            b's', b'a', // sig alg
            0x0, 0x1, b's', // sig
        ];

        SignedCertificateTimestamp::try_from(&bytes[4..]).unwrap();

        assert_eq!(
            SignedCertificateTimestamp {
                log_id: [b'l'; 32],
                timestamp_ms: 0x74747474_74747474,
                _future_lifetime_for_signature: PhantomData
            },
            SctParser::new(Some(Input::from(&bytes)))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn illegal_empty_signature() {
        let bytes = [
            0x0, // version
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', // log id
            b't', b't', b't', b't', b't', b't', b't', b't', // timestamp
            0x0, 0x0, // extensions
            b's', b'a', // sig alg
            0x0, 0x0, // sig
        ];

        assert_eq!(
            Some(Error::MalformedSct),
            SignedCertificateTimestamp::try_from(&bytes[..]).err()
        );
    }

    #[test]
    fn illegal_unknown_version() {
        let bytes = [
            0x1, // version
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l', b'l',
            b'l', b'l', b'l', b'l', // log id
            b't', b't', b't', b't', b't', b't', b't', b't', // timestamp
            0x0, 0x0, // extensions
            b's', b'a', // sig alg
            0x0, 0x1, b's', // sig
        ];

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
}
