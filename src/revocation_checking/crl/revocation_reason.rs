use super::*;

/// Identifies the reason a certificate was revoked.
/// See RFC 5280 §5.3.1[^1]
///
/// [^1] <https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(missing_docs)] // Not much to add above the code name.
pub enum RevocationReason {
    /// Unspecified should not be used, and is instead assumed by the absence of a RevocationReason
    /// extension.
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is not used.
    /// RemoveFromCrl only appears in delta CRLs that are unsupported.
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Return an iterator over all possible [RevocationReason] variants.
    pub fn iter() -> impl Iterator<Item = RevocationReason> {
        use RevocationReason::*;
        [
            Unspecified,
            KeyCompromise,
            CaCompromise,
            AffiliationChanged,
            Superseded,
            CessationOfOperation,
            CertificateHold,
            RemoveFromCrl,
            PrivilegeWithdrawn,
            AaCompromise,
        ]
        .into_iter()
    }
}

impl<'a> FromDer<'a> for RevocationReason {
    // RFC 5280 §5.3.1.
    fn from_der(reader: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let input = der::expect_tag(reader, Tag::Enum)?;
        Self::try_from(input.read_all(Error::BadDer, |reason| {
            reason.read_byte().map_err(|_| Error::BadDer)
        })?)
    }

    const TYPE_ID: DerTypeId = DerTypeId::RevocationReason;
}

impl TryFrom<u8> for RevocationReason {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // See https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
        match value {
            0 => Ok(RevocationReason::Unspecified),
            1 => Ok(RevocationReason::KeyCompromise),
            2 => Ok(RevocationReason::CaCompromise),
            3 => Ok(RevocationReason::AffiliationChanged),
            4 => Ok(RevocationReason::Superseded),
            5 => Ok(RevocationReason::CessationOfOperation),
            6 => Ok(RevocationReason::CertificateHold),
            // 7 is not used.
            8 => Ok(RevocationReason::RemoveFromCrl),
            9 => Ok(RevocationReason::PrivilegeWithdrawn),
            10 => Ok(RevocationReason::AaCompromise),
            _ => Err(Error::UnsupportedRevocationReason),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_reasons() {
        // Test that we can convert the allowed u8 revocation reason code values into the expected
        // revocation reason variant.
        let testcases: Vec<(u8, RevocationReason)> = vec![
            (0, RevocationReason::Unspecified),
            (1, RevocationReason::KeyCompromise),
            (2, RevocationReason::CaCompromise),
            (3, RevocationReason::AffiliationChanged),
            (4, RevocationReason::Superseded),
            (5, RevocationReason::CessationOfOperation),
            (6, RevocationReason::CertificateHold),
            // Note: 7 is unused.
            (8, RevocationReason::RemoveFromCrl),
            (9, RevocationReason::PrivilegeWithdrawn),
            (10, RevocationReason::AaCompromise),
        ];
        for tc in testcases.iter() {
            let (id, expected) = tc;
            let actual = <u8 as TryInto<RevocationReason>>::try_into(*id)
                .expect("unexpected reason code conversion error");
            assert_eq!(actual, *expected);
            #[cfg(feature = "alloc")]
            {
                // revocation reasons should be Debug.
                println!("{:?}", actual);
            }
        }

        // Unsupported/unknown revocation reason codes should produce an error.
        let res = <u8 as TryInto<RevocationReason>>::try_into(7);
        assert!(matches!(res, Err(Error::UnsupportedRevocationReason)));

        // The iterator should produce all possible revocation reason variants.
        let expected = testcases
            .iter()
            .map(|(_, reason)| *reason)
            .collect::<Vec<_>>();
        let actual = RevocationReason::iter().collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}
