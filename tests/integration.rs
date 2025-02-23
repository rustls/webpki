// Copyright 2016 Joseph Birr-Pixton.
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

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

use core::time::Duration;

use pki_types::{CertificateDer, UnixTime};
use webpki::{KeyUsage, anchor_from_trusted_cert};

fn revocation_options_for_test<'a>(
    crls: &'a [&'a webpki::CertRevocationList<'a>],
) -> webpki::RevocationOptions<'a> {
    webpki::RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(webpki::RevocationCheckDepth::EndEntity)
        .with_status_policy(webpki::UnknownStatusPolicy::Allow)
        .build()
}

#[cfg(feature = "alloc")]
#[test]
pub fn amazon() {
    // The 4 Amazon roots
    let roots: &[&[u8]] = &[
        // https://www.amazontrust.com/repository/AmazonRootCA1.cer
        // https://crt.sh/?id=12745009
        include_bytes!("amazon/AmazonRootCA1.cer"),
        // https://www.amazontrust.com/repository/AmazonRootCA2.cer
        // https://crt.sh/?id=12744983
        include_bytes!("amazon/AmazonRootCA2.cer"),
        // https://www.amazontrust.com/repository/AmazonRootCA3.cer
        // https://crt.sh/?id=12744938
        include_bytes!("amazon/AmazonRootCA3.cer"),
        // https://www.amazontrust.com/repository/AmazonRootCA4.cer
        // https://crt.sh/?id=12745024
        include_bytes!("amazon/AmazonRootCA4.cer"),
    ];

    let roots = roots
        .iter()
        .map(|&der| CertificateDer::from(der))
        .collect::<Vec<_>>();
    let anchors = roots
        .iter()
        .map(|cert_der| anchor_from_trusted_cert(cert_der).unwrap())
        .collect::<Vec<_>>();

    // https://aws.amazon.com/blogs/security/acm-will-no-longer-cross-sign-certificates-with-starfield-class-2-starting-august-2024/
    // https://crt.sh/?id=793888
    // https://crt.sh/?id=10739077
    let legacy_root: &[u8] = include_bytes!("amazon/SFSRootCAG2.cer");
    let legacy_root = CertificateDer::from(legacy_root);
    let legacy_anchors = vec![anchor_from_trusted_cert(&legacy_root).unwrap()];

    let all_anchors = [&anchors[..], &legacy_anchors[..]].concat();

    let roots_as_intermediates: &[&[u8]] = &[
        include_bytes!("amazon/rootca1.cer"),
        include_bytes!("amazon/rootca2.cer"),
        include_bytes!("amazon/rootca3.cer"),
        include_bytes!("amazon/rootca4.cer"),
    ];

    let roots_as_intermediates = roots_as_intermediates
        .iter()
        .map(|&cert_der| CertificateDer::from(cert_der))
        .collect::<Vec<_>>();

    let roots_crls: &[&[u8]] = &[
        include_bytes!("amazon/rootca1.crl"),
        include_bytes!("amazon/rootca2.crl"),
        include_bytes!("amazon/rootca3.crl"),
        include_bytes!("amazon/rootca4.crl"),
    ];

    let roots_crls = roots_crls
        .iter()
        .map(|bytes| {
            webpki::CertRevocationList::from(
                webpki::OwnedCertRevocationList::from_der(bytes).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let roots_crls = roots_crls.iter().collect::<Vec<_>>();

    let intermediates: &[&[u8]] = &[
        include_bytes!("amazon/r2m01.cer"),
        include_bytes!("amazon/r2m02.cer"),
        include_bytes!("amazon/r2m03.cer"),
        include_bytes!("amazon/r2m04.cer"),
        include_bytes!("amazon/r4m01.cer"),
        include_bytes!("amazon/r4m02.cer"),
        include_bytes!("amazon/r4m03.cer"),
        include_bytes!("amazon/r4m04.cer"),
        include_bytes!("amazon/e2m01.cer"),
        include_bytes!("amazon/e2m02.cer"),
        include_bytes!("amazon/e2m03.cer"),
        include_bytes!("amazon/e2m04.cer"),
        include_bytes!("amazon/e3m01.cer"),
        include_bytes!("amazon/e3m02.cer"),
        include_bytes!("amazon/e3m03.cer"),
        include_bytes!("amazon/e3m04.cer"),
    ];

    let intermediates = intermediates
        .iter()
        .map(|&cert_der| CertificateDer::from(cert_der))
        .collect::<Vec<_>>();

    let intermediates_legacy = [&intermediates[..], &roots_as_intermediates[..]].concat();

    let intermediates_crls: &[&[u8]] = &[
        include_bytes!("amazon/r2m01.crl"),
        include_bytes!("amazon/r2m02.crl"),
        include_bytes!("amazon/r2m03.crl"),
        include_bytes!("amazon/r2m04.crl"),
        include_bytes!("amazon/r4m01.crl"),
        include_bytes!("amazon/r4m02.crl"),
        include_bytes!("amazon/r4m03.crl"),
        include_bytes!("amazon/r4m04.crl"),
        include_bytes!("amazon/e2m01.crl"),
        include_bytes!("amazon/e2m02.crl"),
        include_bytes!("amazon/e2m03.crl"),
        include_bytes!("amazon/e2m04.crl"),
        include_bytes!("amazon/e3m01.crl"),
        include_bytes!("amazon/e3m02.crl"),
        include_bytes!("amazon/e3m03.crl"),
        include_bytes!("amazon/e3m04.crl"),
    ];

    let intermediates_crls = intermediates_crls
        .iter()
        .map(|bytes| {
            webpki::CertRevocationList::from(
                webpki::OwnedCertRevocationList::from_der(bytes).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let intermediates_crls = intermediates_crls.iter().collect::<Vec<_>>();

    let all_crls = [&roots_crls[..], &intermediates_crls[..]].concat();

    let valid_demo_root_1: (&[u8], &str) = (
        include_bytes!("amazon/valid.rootca1.demo.amazontrust.com.cer"),
        "valid.rootca1.demo.amazontrust.com",
    );
    let valid_demo_root_2: (&[u8], &str) = (
        include_bytes!("amazon/valid.rootca2.demo.amazontrust.com.cer"),
        "valid.rootca2.demo.amazontrust.com",
    );
    let valid_demo_root_3: (&[u8], &str) = (
        include_bytes!("amazon/valid.rootca3.demo.amazontrust.com.cer"),
        "valid.rootca3.demo.amazontrust.com",
    );
    let valid_demo_root_4: (&[u8], &str) = (
        include_bytes!("amazon/valid.rootca4.demo.amazontrust.com.cer"),
        "valid.rootca4.demo.amazontrust.com",
    );

    let revoked_demo_root_1: (&[u8], &str) = (
        include_bytes!("amazon/revoked.rootca1.demo.amazontrust.com.cer"),
        "revoked.rootca1.demo.amazontrust.com",
    );
    let revoked_demo_root_2: (&[u8], &str) = (
        include_bytes!("amazon/revoked.rootca2.demo.amazontrust.com.cer"),
        "revoked.rootca2.demo.amazontrust.com",
    );
    let revoked_demo_root_3: (&[u8], &str) = (
        include_bytes!("amazon/revoked.rootca3.demo.amazontrust.com.cer"),
        "revoked.rootca3.demo.amazontrust.com",
    );
    let revoked_demo_root_4: (&[u8], &str) = (
        include_bytes!("amazon/revoked.rootca4.demo.amazontrust.com.cer"),
        "revoked.rootca4.demo.amazontrust.com",
    );

    let expired_demo_root_1: (&[u8], &str) = (
        include_bytes!("amazon/expired.rootca1.demo.amazontrust.com.cer"),
        "expired.rootca1.demo.amazontrust.com",
    );
    let expired_demo_root_2: (&[u8], &str) = (
        include_bytes!("amazon/expired.rootca2.demo.amazontrust.com.cer"),
        "expired.rootca2.demo.amazontrust.com",
    );
    let expired_demo_root_3: (&[u8], &str) = (
        include_bytes!("amazon/expired.rootca3.demo.amazontrust.com.cer"),
        "expired.rootca3.demo.amazontrust.com",
    );
    let expired_demo_root_4: (&[u8], &str) = (
        include_bytes!("amazon/expired.rootca4.demo.amazontrust.com.cer"),
        "expired.rootca4.demo.amazontrust.com",
    );

    for &(cert, dns_name) in &[
        valid_demo_root_1,
        valid_demo_root_2,
        valid_demo_root_3,
        valid_demo_root_4,
        revoked_demo_root_1,
        revoked_demo_root_2,
        revoked_demo_root_3,
        revoked_demo_root_4,
        expired_demo_root_1,
        expired_demo_root_2,
        expired_demo_root_3,
        expired_demo_root_4,
    ] {
        let cert = CertificateDer::from(cert);
        let cert = webpki::EndEntityCert::try_from(&cert).unwrap();

        assert_eq!(
            Ok(()),
            cert.verify_is_valid_for_subject_name(
                &pki_types::ServerName::try_from(dns_name).unwrap()
            ),
        );
    }

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_740_304_936)); // Sun Feb 23 02:02:16 PST 2025

    for &(cert, _dns_name) in &[
        valid_demo_root_1,
        valid_demo_root_2,
        valid_demo_root_3,
        valid_demo_root_4,
    ] {
        let cert = CertificateDer::from(cert);
        let cert = webpki::EndEntityCert::try_from(&cert).unwrap();

        for &crls in &[
            None,
            Some(&roots_crls),
            Some(&intermediates_crls),
            Some(&all_crls),
        ] {
            assert!(
                cert.verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &anchors,
                    &intermediates,
                    time,
                    KeyUsage::server_auth(),
                    crls.map(|l| revocation_options_for_test(l)),
                    None,
                )
                .is_ok()
            );

            assert!(
                cert.verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &legacy_anchors,
                    &intermediates_legacy,
                    time,
                    KeyUsage::server_auth(),
                    crls.map(|l| revocation_options_for_test(l)),
                    None,
                )
                .is_ok()
            );

            let path = cert
                .verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &all_anchors,
                    &intermediates_legacy,
                    time,
                    KeyUsage::server_auth(),
                    crls.map(|l| revocation_options_for_test(l)),
                    None,
                )
                .unwrap();

            // verify should find shortest path
            assert!(anchors.contains(path.anchor()));
        }
    }

    for &(cert, _dns_name) in &[
        revoked_demo_root_1,
        revoked_demo_root_2,
        revoked_demo_root_3,
        revoked_demo_root_4,
    ] {
        let cert = CertificateDer::from(cert);
        let cert = webpki::EndEntityCert::try_from(&cert).unwrap();

        for &crls in &[None, Some(&roots_crls)] {
            assert!(
                cert.verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &anchors,
                    &intermediates,
                    time,
                    KeyUsage::server_auth(),
                    crls.map(|l| revocation_options_for_test(l)),
                    None,
                )
                .is_ok()
            );
        }

        for &crls in &[&intermediates_crls, &all_crls] {
            assert!(
                cert.verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &anchors,
                    &intermediates,
                    time,
                    KeyUsage::server_auth(),
                    Some(revocation_options_for_test(crls)),
                    None,
                )
                .is_err_and(|e| matches!(e, webpki::Error::CertRevoked))
            );
        }
    }

    for &(cert, _dns_name) in &[
        expired_demo_root_1,
        expired_demo_root_2,
        expired_demo_root_3,
        expired_demo_root_4,
    ] {
        let cert = CertificateDer::from(cert);
        let cert = webpki::EndEntityCert::try_from(&cert).unwrap();

        assert!(
            cert.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                time,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .is_err_and(|e| matches!(e, webpki::Error::CertExpired { .. }))
        );
    }
}

/* Checks we can verify netflix's cert chain.  This is notable
 * because they're rooted at a Verisign v1 root. */
#[cfg(feature = "alloc")]
#[test]
fn netflix() {
    let ee: &[u8] = include_bytes!("netflix/ee.der");
    let inter = CertificateDer::from(&include_bytes!("netflix/inter.der")[..]);
    let ca = CertificateDer::from(&include_bytes!("netflix/ca.der")[..]);

    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_492_441_716)); // 2017-04-17T15:08:36Z

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    assert!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[inter],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
    );
}

/* This is notable because it is a popular use of IP address subjectAltNames. */
#[cfg(feature = "alloc")]
#[test]
fn cloudflare_dns() {
    use pki_types::ServerName;

    let ee: &[u8] = include_bytes!("cloudflare_dns/ee.der");
    let inter = CertificateDer::from(&include_bytes!("cloudflare_dns/inter.der")[..]);
    let ca = CertificateDer::from(&include_bytes!("cloudflare_dns/ca.der")[..]);

    let ca_cert = CertificateDer::from(&ca[..]);
    let anchors = [anchor_from_trusted_cert(&ca_cert).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_663_495_771));

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    assert!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[inter],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
    );

    let check_name = |name: &str| {
        let subject_name_ref = ServerName::try_from(name).unwrap();
        assert_eq!(
            Ok(()),
            cert.verify_is_valid_for_subject_name(&subject_name_ref)
        );
        println!("{:?} ok as name", name);
    };

    let check_addr = |addr: &str| {
        let subject_name_ref = ServerName::try_from(addr.as_bytes()).unwrap();
        assert_eq!(
            Ok(()),
            cert.verify_is_valid_for_subject_name(&subject_name_ref)
        );
        println!("{:?} ok as address", addr);
    };

    check_name("cloudflare-dns.com");
    check_name("wildcard.cloudflare-dns.com");
    check_name("one.one.one.one");
    check_addr("1.1.1.1");
    check_addr("1.0.0.1");
    check_addr("162.159.36.1");
    check_addr("162.159.46.1");
    check_addr("2606:4700:4700:0000:0000:0000:0000:1111");
    check_addr("2606:4700:4700:0000:0000:0000:0000:1001");
    check_addr("2606:4700:4700:0000:0000:0000:0000:0064");
    check_addr("2606:4700:4700:0000:0000:0000:0000:6400");
}

#[cfg(feature = "alloc")]
#[test]
fn wpt() {
    let ee = CertificateDer::from(&include_bytes!("wpt/ee.der")[..]);
    let ca = CertificateDer::from(&include_bytes!("wpt/ca.der")[..]);

    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_619_256_684)); // 2021-04-24T09:31:24Z
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    assert!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
    );
}

#[test]
fn ed25519() {
    let ee = CertificateDer::from(&include_bytes!("ed25519/ee.der")[..]);
    let ca = CertificateDer::from(&include_bytes!("ed25519/ca.der")[..]);

    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_547_363_522)); // 2019-01-13T07:12:02Z

    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    assert!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
    );
}

#[test]
#[cfg(feature = "alloc")]
fn critical_extensions() {
    let root = CertificateDer::from(&include_bytes!("critical_extensions/root-cert.der")[..]);
    let ca = CertificateDer::from(&include_bytes!("critical_extensions/ca-cert.der")[..]);

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_670_779_098));
    let anchors = [anchor_from_trusted_cert(&root).unwrap()];
    let intermediates = [ca];

    let ee = CertificateDer::from(
        &include_bytes!("critical_extensions/ee-cert-noncrit-unknown-ext.der")[..],
    );
    let ee_cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    assert!(
        ee_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                time,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .is_ok(),
        "accept non-critical unknown extension"
    );

    let ee = CertificateDer::from(
        &include_bytes!("critical_extensions/ee-cert-crit-unknown-ext.der")[..],
    );
    assert!(
        matches!(
            webpki::EndEntityCert::try_from(&ee),
            Err(webpki::Error::UnsupportedCriticalExtension)
        ),
        "reject critical unknown extension"
    );
}

#[test]
fn read_root_with_zero_serial() {
    let ca = CertificateDer::from(&include_bytes!("misc/serial_zero.der")[..]);
    anchor_from_trusted_cert(&ca).expect("godaddy cert should parse as anchor");
}

#[test]
fn read_root_with_neg_serial() {
    let ca = CertificateDer::from(&include_bytes!("misc/serial_neg.der")[..]);
    anchor_from_trusted_cert(&ca).expect("idcat cert should parse as anchor");
}

#[test]
#[cfg(feature = "alloc")]
fn read_ee_with_neg_serial() {
    let ca = CertificateDer::from(&include_bytes!("misc/serial_neg_ca.der")[..]);
    let ee = CertificateDer::from(&include_bytes!("misc/serial_neg_ee.der")[..]);

    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_667_401_500)); // 2022-11-02T15:05:00Z

    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();
    assert!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
    );
}

#[test]
#[cfg(feature = "alloc")]
fn read_ee_with_large_pos_serial() {
    let ee = CertificateDer::from(&include_bytes!("misc/serial_large_positive.der")[..]);

    webpki::EndEntityCert::try_from(&ee).expect("should parse 20-octet positive serial number");
}

#[test]
fn list_netflix_names() {
    expect_cert_dns_names(
        include_bytes!("netflix/ee.der"),
        [
            "account.netflix.com",
            "ca.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            "www.netflix.com",
        ],
    );
}

#[test]
fn invalid_subject_alt_names() {
    expect_cert_dns_names(
        // same as netflix ee certificate, but with the last name in the list
        // changed to 'www.netflix:com'
        include_bytes!("misc/invalid_subject_alternative_name.der"),
        [
            "account.netflix.com",
            "ca.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            // NOT 'www.netflix:com'
        ],
    );
}

#[test]
fn wildcard_subject_alternative_names() {
    expect_cert_dns_names(
        // same as netflix ee certificate, but with the last name in the list
        // changed to 'ww*.netflix:com'
        include_bytes!("misc/dns_names_and_wildcards.der"),
        [
            "account.netflix.com",
            "*.netflix.com",
            "netflix.ca",
            "netflix.com",
            "signup.netflix.com",
            "www.netflix.ca",
            "www1.netflix.com",
            "www2.netflix.com",
            "www3.netflix.com",
            "develop-stage.netflix.com",
            "release-stage.netflix.com",
            "www.netflix.com",
        ],
    );
}

#[test]
fn no_subject_alt_names() {
    expect_cert_dns_names(include_bytes!("misc/no_subject_alternative_name.der"), [])
}

fn expect_cert_dns_names<'name>(
    cert_der: &[u8],
    expected_names: impl IntoIterator<Item = &'name str>,
) {
    let der = CertificateDer::from(cert_der);
    let cert = webpki::EndEntityCert::try_from(&der)
        .expect("should parse end entity certificate correctly");

    assert!(cert.valid_dns_names().eq(expected_names))
}

#[cfg(feature = "alloc")]
#[test]
fn cert_time_validity() {
    let ee: &[u8] = include_bytes!("netflix/ee.der");
    let inter = CertificateDer::from(&include_bytes!("netflix/inter.der")[..]);
    let ca = CertificateDer::from(&include_bytes!("netflix/ca.der")[..]);

    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let not_before = UnixTime::since_unix_epoch(Duration::from_secs(1_478_563_200));
    let not_after = UnixTime::since_unix_epoch(Duration::from_secs(1_541_203_199));

    let just_before = UnixTime::since_unix_epoch(Duration::from_secs(not_before.as_secs() - 1));
    let just_after = UnixTime::since_unix_epoch(Duration::from_secs(not_after.as_secs() + 1));

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();

    assert_eq!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[inter.clone()],
            just_before,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .err(),
        Some(webpki::Error::CertNotValidYet {
            time: just_before,
            not_before
        })
    );

    assert_eq!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[inter],
            just_after,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .err(),
        Some(webpki::Error::CertExpired {
            time: just_after,
            not_after
        })
    );
}
