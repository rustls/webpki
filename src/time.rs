// Copyright 2015-2016 Brian Smith.
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

//! Conversions into the library's time type.

use crate::calendar;
use crate::der::{self, FromDer, Tag};
use crate::error::Error;

/// The time type.
///
/// Internally this is merely a UNIX timestamp: a count of non-leap
/// seconds since the start of 1970.  This type exists to assist
/// unit-of-measure correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct Time(u64);

impl Time {
    /// Create a `webpki::Time` from a unix timestamp.
    ///
    /// It is usually better to use the less error-prone
    /// `webpki::Time::try_from(time: std::time::SystemTime)` instead when
    /// `std::time::SystemTime` is available (when `#![no_std]` isn't being
    /// used).
    #[allow(clippy::must_use_candidate)]
    pub fn from_seconds_since_unix_epoch(secs: u64) -> Self {
        Self(secs)
    }
}

impl<'a> FromDer<'a> for Time {
    fn from_der(input: &mut untrusted::Reader<'a>) -> Result<Self, Error> {
        let is_utc_time = input.peek(Tag::UTCTime.into());
        let expected_tag = if is_utc_time {
            Tag::UTCTime
        } else {
            Tag::GeneralizedTime
        };

        fn read_digit(inner: &mut untrusted::Reader) -> Result<u64, Error> {
            const DIGIT: core::ops::RangeInclusive<u8> = b'0'..=b'9';
            let b = inner.read_byte().map_err(|_| Error::BadDerTime)?;
            if DIGIT.contains(&b) {
                return Ok(u64::from(b - DIGIT.start()));
            }
            Err(Error::BadDerTime)
        }

        fn read_two_digits(
            inner: &mut untrusted::Reader,
            min: u64,
            max: u64,
        ) -> Result<u64, Error> {
            let hi = read_digit(inner)?;
            let lo = read_digit(inner)?;
            let value = (hi * 10) + lo;
            if value < min || value > max {
                return Err(Error::BadDerTime);
            }
            Ok(value)
        }

        der::nested(input, expected_tag, Error::BadDer, |value| {
            let (year_hi, year_lo) = if is_utc_time {
                let lo = read_two_digits(value, 0, 99)?;
                let hi = if lo >= 50 { 19 } else { 20 };
                (hi, lo)
            } else {
                let hi = read_two_digits(value, 0, 99)?;
                let lo = read_two_digits(value, 0, 99)?;
                (hi, lo)
            };

            let year = (year_hi * 100) + year_lo;
            let month = read_two_digits(value, 1, 12)?;
            let days_in_month = calendar::days_in_month(year, month);
            let day_of_month = read_two_digits(value, 1, days_in_month)?;
            let hours = read_two_digits(value, 0, 23)?;
            let minutes = read_two_digits(value, 0, 59)?;
            let seconds = read_two_digits(value, 0, 59)?;

            let time_zone = value.read_byte().map_err(|_| Error::BadDerTime)?;
            if time_zone != b'Z' {
                return Err(Error::BadDerTime);
            }

            calendar::time_from_ymdhms_utc(year, month, day_of_month, hours, minutes, seconds)
        })
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<std::time::SystemTime> for Time {
    type Error = std::time::SystemTimeError;

    /// Create a `webpki::Time` from a `std::time::SystemTime`.
    ///
    /// # Example:
    ///
    /// Construct a `webpki::Time` from the current system time:
    ///
    /// ```
    /// # extern crate ring;
    /// # extern crate webpki;
    /// #
    /// #![cfg(feature = "std")]
    /// use std::time::SystemTime;
    ///
    /// # fn foo() -> Result<(), std::time::SystemTimeError> {
    /// let time = webpki::Time::try_from(SystemTime::now())?;
    /// # Ok(())
    /// # }
    /// ```
    fn try_from(value: std::time::SystemTime) -> Result<Self, Self::Error> {
        value
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| Self::from_seconds_since_unix_epoch(d.as_secs()))
    }
}
