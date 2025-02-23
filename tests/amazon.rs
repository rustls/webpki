// SPDX-License-Identifier: ISC
#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

use core::time::Duration;

use pki_types::{CertificateDer, ServerName, UnixTime};
use webpki::{
    CertRevocationList, EndEntityCert, KeyUsage, OwnedCertRevocationList, RevocationCheckDepth,
    RevocationOptions, RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};

fn revocation_options_for_test<'a>(
    crls: &'a [&'a CertRevocationList<'a>],
) -> RevocationOptions<'a> {
    RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Allow)
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
        .copied()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let anchors = roots
        .iter()
        .map(anchor_from_trusted_cert)
        .map(Result::unwrap)
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
        .copied()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();

    let roots_crls: &[&[u8]] = &[
        include_bytes!("amazon/rootca1.crl"),
        include_bytes!("amazon/rootca2.crl"),
        include_bytes!("amazon/rootca3.crl"),
        include_bytes!("amazon/rootca4.crl"),
    ];

    let roots_crls = roots_crls
        .iter()
        .copied()
        .map(OwnedCertRevocationList::from_der)
        .map(Result::unwrap)
        .map(CertRevocationList::from)
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
        .copied()
        .map(CertificateDer::from)
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
        .copied()
        .map(OwnedCertRevocationList::from_der)
        .map(Result::unwrap)
        .map(CertRevocationList::from)
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
    let valid_certs = &[
        valid_demo_root_1,
        valid_demo_root_2,
        valid_demo_root_3,
        valid_demo_root_4,
    ];

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
    let revoked_certs = &[
        revoked_demo_root_1,
        revoked_demo_root_2,
        revoked_demo_root_3,
        revoked_demo_root_4,
    ];

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
    let expired_certs = &[
        expired_demo_root_1,
        expired_demo_root_2,
        expired_demo_root_3,
        expired_demo_root_4,
    ];

    for &(cert, dns_name) in &[&valid_certs[..], &revoked_certs[..], &expired_certs[..]].concat() {
        let cert = CertificateDer::from(cert);
        let cert = EndEntityCert::try_from(&cert).unwrap();

        assert_eq!(
            Ok(()),
            cert.verify_is_valid_for_subject_name(&ServerName::try_from(dns_name).unwrap()),
        );
    }

    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_740_304_936)); // Sun Feb 23 02:02:16 PST 2025

    for &(cert, _dns_name) in valid_certs {
        let cert = CertificateDer::from(cert);
        let cert = EndEntityCert::try_from(&cert).unwrap();

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

    for &(cert, _dns_name) in revoked_certs {
        let cert = CertificateDer::from(cert);
        let cert = EndEntityCert::try_from(&cert).unwrap();

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

    for &(cert, _dns_name) in expired_certs {
        let cert = CertificateDer::from(cert);
        let cert = EndEntityCert::try_from(&cert).unwrap();

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
