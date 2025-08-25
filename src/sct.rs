/// Reads a `SignedCertificateTimestampList` encoding, yielding each `SignedCertificateTimestamp`.
pub(crate) fn iter_scts<'a>(
    bytes: untrusted::Input<'a>,
) -> Result<impl Iterator<Item = Result<SignedCertificateTimestamp<'a>, Error>> + 'a, Error> {
    let items_body = bytes.read_all(Error::MalformedSct, |rd| read_field(rd, u16_field_len, 1))?;

    let mut reader = untrusted::Reader::new(items_body);

    Ok(core::iter::from_fn(move || {
        let item = read_field(&mut reader, u16_field_len, 1).ok()?;
        Some(SignedCertificateTimestamp::try_from(
            item.as_slice_less_safe(),
        ))
    }))
}

/// This is `SignedCertificateTimestamp` defined in [RFC6962][].
///
/// [RFC6962]: https://www.rfc-editor.org/rfc/rfc6962.html#section-3.2
#[derive(Debug)]
pub(crate) struct SignedCertificateTimestamp<'a> {
    pub(crate) log_id: LogId,
    pub(crate) timestamp: Timestamp,
    #[allow(dead_code)] // pending sct verification
    extensions: untrusted::Input<'a>,
    #[allow(dead_code)] // pending sct verification
    signature_algorithm: u16,
    #[allow(dead_code)] // pending sct verification
    signature: untrusted::Input<'a>,
}

impl<'a> TryFrom<&'a [u8]> for SignedCertificateTimestamp<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let input = untrusted::Input::from(bytes);
        input.read_all(Error::MalformedSct, |rd| {
            match read_array(rd)? {
                [0] => {}
                _ => return Err(Error::UnsupportedSctVersion),
            };

            let log_id = LogId(read_array(rd)?);
            let timestamp = Timestamp(u64::from_be_bytes(read_array(rd)?));
            let extensions = read_field(rd, u16_field_len, 0)?;
            let signature_algorithm = u16::from_be_bytes(read_array(rd)?);
            let signature = read_field(rd, u16_field_len, 1)?;

            Ok(SignedCertificateTimestamp {
                log_id,
                timestamp,
                extensions,
                signature_algorithm,
                signature,
            })
        })
    }
}

#[derive(Debug)]
pub struct LogId(pub [u8; 32]);

#[derive(Debug)]
pub struct Timestamp(pub u64);

/// Read `N` bytes from `rd` as an array.
fn read_array<const N: usize>(rd: &mut untrusted::Reader<'_>) -> Result<[u8; N], Error> {
    rd.read_bytes(N)
        .map_err(|_| Error::MalformedSct)?
        .as_slice_less_safe()
        .try_into()
        .map_err(|_| Error::MalformedSct)
}

/// Read a length-prefixed field from `rd`.
///
/// The length is encoded in `N` bytes and those bytes are decoded by `into_size`,
/// and must be at least `min_size` bytes.
fn read_field<'a, const N: usize>(
    rd: &mut untrusted::Reader<'a>,
    into_size: fn([u8; N]) -> usize,
    min_size: usize,
) -> Result<untrusted::Input<'a>, Error> {
    let len = into_size(read_array::<N>(rd)?);
    if len < min_size {
        return Err(Error::MalformedSct);
    }
    rd.read_bytes(len).map_err(|_| Error::MalformedSct)
}

fn u16_field_len(bytes: [u8; 2]) -> usize {
    usize::from(u16::from_be_bytes(bytes))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The SCT was somehow misencoded, truncated or otherwise corrupt.
    MalformedSct,

    /// An unsupported SCT version was encountered.
    ///
    /// This library only supports `v1(0)`.
    UnsupportedSctVersion,
}
