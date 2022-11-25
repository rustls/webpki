// Copyright 2015-2020 Brian Smith.
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

use crate::Error;

#[cfg(feature = "alloc")]
use alloc::string::String;

const VALID_IP_BY_CONSTRUCTION: &str = "IP address is a valid string by construction";

/// Either a IPv4 or IPv6 address, plus its owned string representation
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum IpAddress {
    /// An ipv4 address and its owned string representation
    IpV4Address(String, [u8; 4]),
    /// An ipv6 address and its owned string representation
    IpV6Address(String, [u8; 16]),
}

#[cfg(feature = "alloc")]
impl AsRef<str> for IpAddress {
    fn as_ref(&self) -> &str {
        match self {
            IpAddress::IpV4Address(ip_address, _) | IpAddress::IpV6Address(ip_address, _) => {
                ip_address.as_str()
            }
        }
    }
}

/// Either a IPv4 or IPv6 address, plus its borrowed string representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddressRef<'a> {
    /// An IPv4 address and its borrowed string representation
    IpV4AddressRef(&'a [u8], [u8; 4]),
    /// An IPv6 address and its borrowed string representation
    IpV6AddressRef(&'a [u8], [u8; 16]),
}

#[cfg(feature = "alloc")]
impl<'a> From<IpAddressRef<'a>> for IpAddress {
    fn from(ip_address: IpAddressRef<'a>) -> IpAddress {
        match ip_address {
            IpAddressRef::IpV4AddressRef(ip_address, ip_address_octets) => IpAddress::IpV4Address(
                String::from_utf8(ip_address.to_vec()).expect(VALID_IP_BY_CONSTRUCTION),
                ip_address_octets,
            ),
            IpAddressRef::IpV6AddressRef(ip_address, ip_address_octets) => IpAddress::IpV6Address(
                String::from_utf8(ip_address.to_vec()).expect(VALID_IP_BY_CONSTRUCTION),
                ip_address_octets,
            ),
        }
    }
}

// Returns the octets that correspond to the provided IPv4 address.
//
// This function can only be called on IPv4 addresses that have
// already been validated with `is_valid_ipv4_address`.
pub(crate) fn ipv4_octets(ip_address: &[u8]) -> Result<[u8; 4], InvalidIpAddressError> {
    let mut result: [u8; 4] = [0, 0, 0, 0];
    for (i, textual_octet) in ip_address
        .split(|textual_octet| *textual_octet == b'.')
        .enumerate()
    {
        result[i] = str::parse::<u8>(
            core::str::from_utf8(textual_octet).map_err(|_| InvalidIpAddressError)?,
        )
        .map_err(|_| InvalidIpAddressError)?;
    }
    Ok(result)
}

// Returns the octets that correspond to the provided IPv6 address.
//
// This function can only be called on uncompressed IPv6 addresses
// that have already been validated with `is_valid_ipv6_address`.
pub(crate) fn ipv6_octets(ip_address: &[u8]) -> Result<[u8; 16], InvalidIpAddressError> {
    let mut result: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (i, textual_block) in ip_address
        .split(|textual_block| *textual_block == b':')
        .enumerate()
    {
        let octets = u16::from_str_radix(
            core::str::from_utf8(textual_block).map_err(|_| InvalidIpAddressError)?,
            16,
        )
        .map_err(|_| InvalidIpAddressError)?
        .to_be_bytes();

        result[2 * i] = octets[0];
        result[(2 * i) + 1] = octets[1];
    }
    Ok(result)
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a IpAddress> for IpAddressRef<'a> {
    fn from(ip_address: &'a IpAddress) -> IpAddressRef<'a> {
        match ip_address {
            IpAddress::IpV4Address(ip_address, ip_address_octets) => {
                IpAddressRef::IpV4AddressRef(ip_address.as_bytes(), *ip_address_octets)
            }
            IpAddress::IpV6Address(ip_address, ip_address_octets) => {
                IpAddressRef::IpV6AddressRef(ip_address.as_bytes(), *ip_address_octets)
            }
        }
    }
}

/// An error indicating that an `IpAddressRef` could not built because the input
/// is not a valid IP address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIpAddressError;

impl core::fmt::Display for InvalidIpAddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Requires the `std` feature.
#[cfg(feature = "std")]
impl ::std::error::Error for InvalidIpAddressError {}

impl<'a> IpAddressRef<'a> {
    /// Constructs an `IpAddressRef` from the given input if the input is a
    /// valid IPv4 or IPv6 address.
    pub fn try_from_ascii(ip_address: &'a [u8]) -> Result<Self, InvalidIpAddressError> {
        if is_valid_ipv4_address(untrusted::Input::from(ip_address)) {
            Ok(IpAddressRef::IpV4AddressRef(
                ip_address,
                ipv4_octets(ip_address)?,
            ))
        } else if is_valid_ipv6_address(untrusted::Input::from(ip_address)) {
            Ok(IpAddressRef::IpV6AddressRef(
                ip_address,
                ipv6_octets(ip_address)?,
            ))
        } else {
            Err(InvalidIpAddressError)
        }
    }

    /// Constructs an `IpAddressRef` from the given input if the input is a
    /// valid IP address.
    pub fn try_from_ascii_str(ip_address: &'a str) -> Result<Self, InvalidIpAddressError> {
        Self::try_from_ascii(ip_address.as_bytes())
    }

    /// Constructs an `IpAddress` from this `IpAddressRef`
    ///
    /// Requires the `alloc` feature.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> IpAddress {
        match self {
            IpAddressRef::IpV4AddressRef(ip_address, ip_address_octets) => IpAddress::IpV4Address(
                String::from_utf8(ip_address.to_vec()).expect(VALID_IP_BY_CONSTRUCTION),
                *ip_address_octets,
            ),
            IpAddressRef::IpV6AddressRef(ip_address, ip_address_octets) => IpAddress::IpV6Address(
                String::from_utf8(ip_address.to_vec()).expect(VALID_IP_BY_CONSTRUCTION),
                *ip_address_octets,
            ),
        }
    }
}

#[cfg(feature = "std")]
fn ipv6_to_uncompressed_string(octets: [u8; 16]) -> String {
    octets
        .chunks(2)
        .map(|octet| format!("{:02x?}{:02x?}", octet[0], octet[1]))
        .collect::<Vec<String>>()
        .join(":")
}

#[cfg(feature = "std")]
impl From<std::net::IpAddr> for IpAddress {
    fn from(ip_address: std::net::IpAddr) -> IpAddress {
        match ip_address {
            std::net::IpAddr::V4(ip_address) => {
                IpAddress::IpV4Address(ip_address.to_string(), ip_address.octets())
            }
            std::net::IpAddr::V6(ip_address) => IpAddress::IpV6Address(
                // We cannot rely on the Display implementation of
                // std::net::Ipv6Addr given that it might return
                // compressed IPv6 addresses if the address can be
                // expressed in such form. However, given we don't
                // support the IPv6 compressed form, we should not
                // generate such format either when converting from a
                // type that supports it.
                ipv6_to_uncompressed_string(ip_address.octets()),
                ip_address.octets(),
            ),
        }
    }
}

impl<'a> From<IpAddressRef<'a>> for &'a str {
    fn from(ip_address: IpAddressRef<'a>) -> &'a str {
        match ip_address {
            IpAddressRef::IpV4AddressRef(ip_address, _)
            | IpAddressRef::IpV6AddressRef(ip_address, _) => {
                core::str::from_utf8(ip_address).expect(VALID_IP_BY_CONSTRUCTION)
            }
        }
    }
}

impl<'a> From<IpAddressRef<'a>> for &'a [u8] {
    fn from(ip_address: IpAddressRef<'a>) -> &'a [u8] {
        match ip_address {
            IpAddressRef::IpV4AddressRef(ip_address, _)
            | IpAddressRef::IpV6AddressRef(ip_address, _) => ip_address,
        }
    }
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.6 says:
//   When the subjectAltName extension contains an iPAddress, the address
//   MUST be stored in the octet string in "network byte order", as
//   specified in [RFC791].  The least significant bit (LSB) of each octet
//   is the LSB of the corresponding byte in the network address.  For IP
//   version 4, as specified in [RFC791], the octet string MUST contain
//   exactly four octets.  For IP version 6, as specified in
//   [RFC2460], the octet string MUST contain exactly sixteen octets.
pub(super) fn presented_id_matches_reference_id(
    presented_id: untrusted::Input,
    reference_id: untrusted::Input,
) -> Result<bool, Error> {
    if presented_id.len() != reference_id.len() {
        return Ok(false);
    }

    let mut presented_ip_address = untrusted::Reader::new(presented_id);
    let mut reference_ip_address = untrusted::Reader::new(reference_id);
    loop {
        let presented_ip_address_byte = presented_ip_address.read_byte().unwrap();
        let reference_ip_address_byte = reference_ip_address.read_byte().unwrap();
        if presented_ip_address_byte != reference_ip_address_byte {
            return Ok(false);
        }
        if presented_ip_address.at_end() {
            break;
        }
    }

    Ok(true)
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.10 says:
//
//     For IPv4 addresses, the iPAddress field of GeneralName MUST contain
//     eight (8) octets, encoded in the style of RFC 4632 (CIDR) to represent
//     an address range [RFC4632].  For IPv6 addresses, the iPAddress field
//     MUST contain 32 octets similarly encoded.  For example, a name
//     constraint for "class C" subnet 192.0.2.0 is represented as the
//     octets C0 00 02 00 FF FF FF 00, representing the CIDR notation
//     192.0.2.0/24 (mask 255.255.255.0).
pub(super) fn presented_id_matches_constraint(
    name: untrusted::Input,
    constraint: untrusted::Input,
) -> Result<bool, Error> {
    if name.len() != 4 && name.len() != 16 {
        return Err(Error::BadDER);
    }
    if constraint.len() != 8 && constraint.len() != 32 {
        return Err(Error::BadDER);
    }

    // an IPv4 address never matches an IPv6 constraint, and vice versa.
    if name.len() * 2 != constraint.len() {
        return Ok(false);
    }

    let (constraint_address, constraint_mask) = constraint.read_all(Error::BadDER, |value| {
        let address = value.read_bytes(constraint.len() / 2).unwrap();
        let mask = value.read_bytes(constraint.len() / 2).unwrap();
        Ok((address, mask))
    })?;

    let mut name = untrusted::Reader::new(name);
    let mut constraint_address = untrusted::Reader::new(constraint_address);
    let mut constraint_mask = untrusted::Reader::new(constraint_mask);
    loop {
        let name_byte = name.read_byte().unwrap();
        let constraint_address_byte = constraint_address.read_byte().unwrap();
        let constraint_mask_byte = constraint_mask.read_byte().unwrap();
        if ((name_byte ^ constraint_address_byte) & constraint_mask_byte) != 0 {
            return Ok(false);
        }
        if name.at_end() {
            break;
        }
    }

    Ok(true)
}

pub(crate) fn is_valid_ipv4_address(ip_address: untrusted::Input) -> bool {
    let mut ip_address = untrusted::Reader::new(ip_address);
    let mut is_first_byte = true;
    let mut current: [u8; 3] = [0, 0, 0];
    let mut current_size = 0;
    let mut dot_count = 0;

    // Returns a u32 so it's possible to identify (and error) when
    // provided textual octets > 255, not representable by u8.
    fn radix10_to_octet(textual_octets: &[u8]) -> u32 {
        let mut result: u32 = 0;
        for digit in textual_octets.iter() {
            result *= 10;
            result += u32::from(*digit);
        }
        result
    }

    loop {
        match ip_address.read_byte() {
            Ok(b'.') => {
                if is_first_byte {
                    // IPv4 address cannot start with a dot.
                    return false;
                }
                if ip_address.at_end() {
                    // IPv4 address cannot end with a dot.
                    return false;
                }
                if dot_count == 3 {
                    // IPv4 address cannot have more than three dots.
                    return false;
                }
                dot_count += 1;
                if current_size == 0 {
                    // IPv4 address cannot contain two dots in a row.
                    return false;
                }
                if radix10_to_octet(&current[..current_size]) > 255 {
                    // No octet can be greater than 255.
                    return false;
                }
                // We move on to the next textual octet.
                current = [0, 0, 0];
                current_size = 0;
            }
            Ok(number @ b'0'..=b'9') => {
                if number == b'0'
                    && current_size == 0
                    && !ip_address.peek(b'.')
                    && !ip_address.at_end()
                {
                    // No octet can start with 0 if a dot does not follow and if we are not at the end.
                    return false;
                }
                if current_size >= current.len() {
                    // More than 3 octets in a triple
                    return false;
                }
                current[current_size] = number - b'0';
                current_size += 1;
            }
            _ => {
                return false;
            }
        }
        is_first_byte = false;

        if ip_address.at_end() {
            if current_size > 0 && radix10_to_octet(&current[..current_size]) > 255 {
                // No octet can be greater than 255.
                return false;
            }
            break;
        }
    }
    dot_count == 3
}

pub(crate) fn is_valid_ipv6_address(ip_address: untrusted::Input) -> bool {
    // Compressed addresses are not supported. Also, IPv4-mapped IPv6
    // addresses are not supported. This makes 8 groups of 4
    // hexadecimal characters + 7 colons.
    if ip_address.len() != 39 {
        return false;
    }

    let mut ip_address = untrusted::Reader::new(ip_address);
    let mut is_first_byte = true;
    let mut current_textual_block_size = 0;
    let mut colon_count = 0;
    loop {
        match ip_address.read_byte() {
            Ok(b':') => {
                if is_first_byte {
                    // Uncompressed IPv6 address cannot start with a colon.
                    return false;
                }
                if ip_address.at_end() {
                    // Uncompressed IPv6 address cannot end with a colon.
                    return false;
                }
                if colon_count == 7 {
                    // IPv6 address cannot have more than seven colons.
                    return false;
                }
                colon_count += 1;
                if current_textual_block_size == 0 {
                    // Uncompressed IPv6 address cannot contain two colons in a row.
                    return false;
                }
                if current_textual_block_size != 4 {
                    // Compressed IPv6 addresses are not supported.
                    return false;
                }
                // We move on to the next textual block.
                current_textual_block_size = 0;
            }
            Ok(b'0'..=b'9') | Ok(b'a'..=b'f') | Ok(b'A'..=b'F') => {
                if current_textual_block_size == 4 {
                    // Blocks cannot contain more than 4 hexadecimal characters.
                    return false;
                }
                current_textual_block_size += 1;
            }
            _ => {
                return false;
            }
        }
        is_first_byte = false;

        if ip_address.at_end() {
            break;
        }
    }
    colon_count == 7
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_ADDRESSES_VALIDITY: &[(&[u8], bool)] = &[
        // Valid IPv4 addresses
        (b"0.0.0.0", true),
        (b"127.0.0.1", true),
        (b"1.1.1.1", true),
        (b"255.255.255.255", true),
        (b"205.0.0.0", true),
        (b"0.205.0.0", true),
        (b"0.0.205.0", true),
        (b"0.0.0.205", true),
        (b"0.0.0.20", true),
        // Invalid IPv4 addresses
        (b"", false),
        (b"...", false),
        (b".0.0.0.0", false),
        (b"0.0.0.0.", false),
        (b"256.0.0.0", false),
        (b"0.256.0.0", false),
        (b"0.0.256.0", false),
        (b"0.0.0.256", false),
        (b"1..1.1.1", false),
        (b"1.1..1.1", false),
        (b"1.1.1..1", false),
        (b"025.0.0.0", false),
        (b"0.025.0.0", false),
        (b"0.0.025.0", false),
        (b"0.0.0.025", false),
        (b"1234.0.0.0", false),
        (b"0.1234.0.0", false),
        (b"0.0.1234.0", false),
        (b"0.0.0.1234", false),
    ];

    #[test]
    fn is_valid_ipv4_address_test() {
        for &(ip_address, expected_result) in IPV4_ADDRESSES_VALIDITY {
            assert_eq!(
                is_valid_ipv4_address(untrusted::Input::from(ip_address)),
                expected_result
            );
        }
    }

    #[test]
    fn ipv4_octets_test() {
        assert_eq!(ipv4_octets(b"0.0.0.0"), Ok([0, 0, 0, 0]));
        assert_eq!(ipv4_octets(b"54.155.246.232"), Ok([54, 155, 246, 232]));
        // Invalid UTF-8 encoding
        assert_eq!(ipv4_octets(b"0.\xc3\x28.0.0"), Err(InvalidIpAddressError));
        // Invalid number for a u8
        assert_eq!(ipv4_octets(b"0.0.0.256"), Err(InvalidIpAddressError));
    }

    const IPV6_ADDRESSES_VALIDITY: &[(&[u8], bool)] = &[
        // Valid IPv6 addresses
        (b"2a05:d018:076c:b685:e8ab:afd3:af51:3aed", true),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
        (b"FFFF:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true), // both case hex allowed
        // Invalid IPv6 addresses

        // Missing octets on uncompressed addresses. The unmatching letter has the violation
        (b"aaa:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:aaa:ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:aaa:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:aaa:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:aaa:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:aaa:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:aaa:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:aaa", false),
        // Wrong hexadecimal characters on different positions
        (b"ffgf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:gfff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:fffg:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffgf:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:gfff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:fgff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffgf:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffgf:fffg", false),
        // Wrong colons on uncompressed addresses
        (b":ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff::ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff::ffff:ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff::ffff:ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff::ffff:ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff::ffff:ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff::ffff:ffff", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffff::ffff", false),
        // More colons than allowed
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:", false),
        (b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        // v Invalid UTF-8 encoding
        (b"\xc3\x28a05:d018:076c:b685:e8ab:afd3:af51:3aed", false),
        // v Invalid hexadecimal
        (b"ga05:d018:076c:b685:e8ab:afd3:af51:3aed", false),
        // Cannot start with colon
        (b":a05:d018:076c:b685:e8ab:afd3:af51:3aed", false),
        // Cannot end with colon
        (b"2a05:d018:076c:b685:e8ab:afd3:af51:3ae:", false),
        // Cannot have more than seven colons
        (b"2a05:d018:076c:b685:e8ab:afd3:af51:3a::", false),
        // Cannot contain two colons in a row
        (b"2a05::018:076c:b685:e8ab:afd3:af51:3aed", false),
        // v Textual block size is longer
        (b"2a056:d018:076c:b685:e8ab:afd3:af51:3ae", false),
        // v Textual block size is shorter
        (b"2a0:d018:076c:b685:e8ab:afd3:af51:3aed ", false),
        // Shorter IPv6 address
        (b"d018:076c:b685:e8ab:afd3:af51:3aed", false),
        // Longer IPv6 address
        (b"2a05:d018:076c:b685:e8ab:afd3:af51:3aed3aed", false),
        // These are valid IPv6 addresses, but we don't support compressed addresses
        (b"0:0:0:0:0:0:0:1", false),
        (b"2a05:d018:76c:b685:e8ab:afd3:af51:3aed", false),
    ];

    #[test]
    fn is_valid_ipv6_address_test() {
        for &(ip_address, expected_result) in IPV6_ADDRESSES_VALIDITY {
            assert_eq!(
                is_valid_ipv6_address(untrusted::Input::from(ip_address)),
                expected_result
            );
        }
    }

    #[test]
    fn ipv6_octets_test() {
        // Invalid UTF-8 encoding
        assert_eq!(
            ipv6_octets(b"\xc3\x28a05:d018:076c:b684:8e48:47c9:84aa:b34d"),
            Err(InvalidIpAddressError),
        );
        // Invalid hexadecimal
        assert_eq!(
            ipv6_octets(b"ga05:d018:076c:b684:8e48:47c9:84aa:b34d"),
            Err(InvalidIpAddressError),
        );
    }

    #[test]
    fn try_from_ascii_ip_address_test() {
        const IP_ADDRESSES: &[(&[u8], Result<IpAddressRef, InvalidIpAddressError>)] = &[
            // Valid IPv4 addresses
            (
                b"127.0.0.1",
                Ok(IpAddressRef::IpV4AddressRef(b"127.0.0.1", [127, 0, 0, 1])),
            ),
            // Invalid IPv4 addresses
            (
                // Ends with a dot; misses one octet
                b"127.0.0.",
                Err(InvalidIpAddressError),
            ),
            // Valid IPv6 addresses
            (
                b"0000:0000:0000:0000:0000:0000:0000:0001",
                Ok(IpAddressRef::IpV6AddressRef(
                    b"0000:0000:0000:0000:0000:0000:0000:0001",
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                )),
            ),
            // Invalid IPv6 addresses
            (
                // IPv6 addresses in compressed form are not supported
                b"0:0:0:0:0:0:0:1",
                Err(InvalidIpAddressError),
            ),
            // Something else
            (
                // A hostname
                b"example.com",
                Err(InvalidIpAddressError),
            ),
        ];
        for &(ip_address, expected_result) in IP_ADDRESSES {
            assert_eq!(IpAddressRef::try_from_ascii(ip_address), expected_result)
        }
    }

    #[test]
    fn try_from_ascii_str_ip_address_test() {
        const IP_ADDRESSES: &[(&str, Result<IpAddressRef, InvalidIpAddressError>)] = &[
            // Valid IPv4 addresses
            (
                "127.0.0.1",
                Ok(IpAddressRef::IpV4AddressRef(b"127.0.0.1", [127, 0, 0, 1])),
            ),
            // Invalid IPv4 addresses
            (
                // Ends with a dot; misses one octet
                "127.0.0.",
                Err(InvalidIpAddressError),
            ),
            // Valid IPv6 addresses
            (
                "0000:0000:0000:0000:0000:0000:0000:0001",
                Ok(IpAddressRef::IpV6AddressRef(
                    b"0000:0000:0000:0000:0000:0000:0000:0001",
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                )),
            ),
            // Invalid IPv6 addresses
            (
                // IPv6 addresses in compressed form are not supported
                "0:0:0:0:0:0:0:1",
                Err(InvalidIpAddressError),
            ),
            // Something else
            (
                // A hostname
                "example.com",
                Err(InvalidIpAddressError),
            ),
        ];
        for &(ip_address, expected_result) in IP_ADDRESSES {
            assert_eq!(
                IpAddressRef::try_from_ascii_str(ip_address),
                expected_result
            )
        }
    }

    #[test]
    fn str_from_ip_address_ref_test() {
        let ip_addresses = vec![
            // IPv4 addresses
            (
                IpAddressRef::IpV4AddressRef(b"127.0.0.1", [127, 0, 0, 1]),
                "127.0.0.1",
            ),
            // IPv6 addresses
            (
                IpAddressRef::IpV6AddressRef(
                    b"0000:0000:0000:0000:0000:0000:0000:0001",
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                "0000:0000:0000:0000:0000:0000:0000:0001",
            ),
        ];
        for (ip_address, expected_ip_address) in ip_addresses {
            assert_eq!(Into::<&str>::into(ip_address), expected_ip_address,)
        }
    }

    #[test]
    fn u8_array_from_ip_address_ref_test() {
        let ip_addresses = vec![
            // IPv4 addresses
            (
                IpAddressRef::IpV4AddressRef(b"127.0.0.1", [127, 0, 0, 1]),
                "127.0.0.1",
            ),
            // IPv6 addresses
            (
                IpAddressRef::IpV6AddressRef(
                    b"0000:0000:0000:0000:0000:0000:0000:0001",
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                "0000:0000:0000:0000:0000:0000:0000:0001",
            ),
        ];
        for (ip_address, expected_ip_address) in ip_addresses {
            assert_eq!(
                Into::<&[u8]>::into(ip_address),
                expected_ip_address.as_bytes()
            )
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod alloc_tests {
    use super::*;

    #[test]
    fn as_ref_ip_address_test() {
        assert_eq!(
            IpAddress::IpV4Address(String::from("127.0.0.1"), [127, 0, 0, 1]).as_ref(),
            "127.0.0.1",
        );
        assert_eq!(
            IpAddress::IpV6Address(
                String::from("0000:0000:0000:0000:0000:0000:0000:0001"),
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            )
            .as_ref(),
            "0000:0000:0000:0000:0000:0000:0000:0001",
        );
    }

    #[test]
    fn from_ip_address_ref_for_ip_address_test() {
        {
            let (ip_address, ip_address_octets) = ("127.0.0.1", [127, 0, 0, 1]);
            assert_eq!(
                IpAddress::from(IpAddressRef::IpV4AddressRef(
                    ip_address.as_bytes(),
                    ip_address_octets
                )),
                IpAddress::IpV4Address(String::from(ip_address), ip_address_octets),
            )
        }
        {
            let (ip_address, ip_address_octets) = (
                "0000:0000:0000:0000:0000:0000:0000:0001",
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            );
            assert_eq!(
                IpAddress::from(IpAddressRef::IpV6AddressRef(
                    ip_address.as_bytes(),
                    ip_address_octets
                )),
                IpAddress::IpV6Address(String::from(ip_address), ip_address_octets),
            )
        }
    }

    #[test]
    fn from_ip_address_for_ip_address_ref_test() {
        {
            let ip_address = IpAddress::IpV4Address(String::from("127.0.0.1"), [127, 0, 0, 1]);
            assert_eq!(
                IpAddressRef::from(&ip_address),
                IpAddressRef::IpV4AddressRef(b"127.0.0.1", [127, 0, 0, 1]),
            )
        }
        {
            let ip_address = IpAddress::IpV6Address(
                String::from("0000:0000:0000:0000:0000:0000:0000:0001"),
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            );
            assert_eq!(
                IpAddressRef::from(&ip_address),
                IpAddressRef::IpV6AddressRef(
                    b"0000:0000:0000:0000:0000:0000:0000:0001",
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                ),
            )
        }
    }

    #[test]
    fn display_invalid_ip_address_error_test() {
        assert_eq!(
            InvalidIpAddressError.to_string(),
            String::from("InvalidIpAddressError"),
        )
    }

    #[test]
    fn ip_address_ref_to_owned_test() {
        {
            assert_eq!(
                IpAddressRef::IpV4AddressRef(b"127.0.0.1", [127, 0, 0, 1]).to_owned(),
                IpAddress::IpV4Address(String::from("127.0.0.1"), [127, 0, 0, 1]),
            )
        }
        {
            assert_eq!(
                IpAddressRef::IpV6AddressRef(
                    b"0000:0000:0000:0000:0000:0000:0000:0001",
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                )
                .to_owned(),
                IpAddress::IpV6Address(
                    String::from("0000:0000:0000:0000:0000:0000:0000:0001"),
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
            )
        }
    }

    #[test]
    fn ip_address_from_std_net_ipaddr_test() {
        let ip_addresses = vec![
            (
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                IpAddress::IpV4Address(String::from("127.0.0.1"), [127, 0, 0, 1]),
            ),
            (
                std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                IpAddress::IpV6Address(
                    String::from("0000:0000:0000:0000:0000:0000:0000:0001"),
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
            ),
        ];
        for (ip_address, expected_ip_address) in ip_addresses {
            assert_eq!(IpAddress::from(ip_address), expected_ip_address,)
        }
    }

    #[test]
    fn ipv6_to_uncompressed_string_test() {
        let ip_addresses = vec![
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                String::from("0000:0000:0000:0000:0000:0000:0000:0001"),
            ),
            (
                [
                    0x2a, 0x05, 0xd0, 0x18, 0x07, 0x6c, 0xb6, 0x84, 0x8e, 0x48, 0x47, 0xc9, 0x84,
                    0xaa, 0xb3, 0x4d,
                ],
                String::from("2a05:d018:076c:b684:8e48:47c9:84aa:b34d"),
            ),
        ];
        for (ip_address_octets, expected_result) in ip_addresses {
            assert_eq!(
                ipv6_to_uncompressed_string(ip_address_octets),
                expected_result,
            )
        }
    }
}
