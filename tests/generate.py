#!/usr/bin/env python3

"""
Generates test cases that aim to validate name constraints and other
name-related parts of webpki.

Run this script from tests/.  It edits the bottom part of tests/name_constraints.rs
and drops files into tests/name_constraints.
"""
import argparse
import os
from typing import TextIO, Optional, Union, Any, Callable, Iterable, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import ipaddress
import datetime
import subprocess

ISSUER_PRIVATE_KEY: rsa.RSAPrivateKey = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
ISSUER_PUBLIC_KEY: rsa.RSAPublicKey = ISSUER_PRIVATE_KEY.public_key()

NOT_BEFORE: datetime.datetime = datetime.datetime.utcfromtimestamp(0x1FEDF00D - 30)
NOT_AFTER: datetime.datetime = datetime.datetime.utcfromtimestamp(0x1FEDF00D + 30)

ANY_PRIV_KEY = Union[
    ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
]
ANY_PUB_KEY = Union[
    ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey | rsa.RSAPublicKey
]
SIGNER = Callable[
    [Any, bytes], Any
]  # Note: a bit loosey-goosey here but good enough for tests.


def trim_top(file_name: str) -> TextIO:
    """
    Reads `file_name`, then writes lines up to a particular comment (the "top"
    of the file) back to it and returns the file object for further writing.
    """

    with open(file_name, "r") as f:
        top = f.readlines()
    top = top[: top.index("// DO NOT EDIT BELOW: generated by tests/generate.py\n") + 1]
    output = open(file_name, "w")
    for line in top:
        output.write(line)
    return output


def key_or_generate(key: Optional[ANY_PRIV_KEY] = None) -> ANY_PRIV_KEY:
    return (
        key
        if key is not None
        else rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
    )


def end_entity_cert(
    *,
    subject_name: x509.Name,
    issuer_name: x509.Name,
    issuer_key: Optional[ANY_PRIV_KEY] = None,
    subject_key: Optional[ANY_PRIV_KEY] = None,
    sans: Optional[Iterable[x509.GeneralName]] = None,
    ekus: Optional[Iterable[x509.ObjectIdentifier]] = None,
) -> x509.Certificate:
    subject_priv_key = key_or_generate(subject_key)
    subject_key_pub: ANY_PUB_KEY = subject_priv_key.public_key()

    ee_builder: x509.CertificateBuilder = x509.CertificateBuilder()
    ee_builder = ee_builder.subject_name(subject_name)
    ee_builder = ee_builder.issuer_name(issuer_name)
    ee_builder = ee_builder.not_valid_before(NOT_BEFORE)
    ee_builder = ee_builder.not_valid_after(NOT_AFTER)
    ee_builder = ee_builder.serial_number(x509.random_serial_number())
    ee_builder = ee_builder.public_key(subject_key_pub)
    if sans:
        ee_builder = ee_builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    if ekus:
        ee_builder = ee_builder.add_extension(
            x509.ExtendedKeyUsage(ekus), critical=False
        )
    ee_builder = ee_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    return ee_builder.sign(
        private_key=issuer_key if issuer_key is not None else ISSUER_PRIVATE_KEY,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )


def issuer_name_for_test(test_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "issuer.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, test_name),
        ]
    )


def ca_cert(
    *,
    subject_name: x509.Name,
    subject_key: Optional[ANY_PRIV_KEY] = None,
    permitted_subtrees: Optional[Iterable[x509.GeneralName]] = None,
    excluded_subtrees: Optional[Iterable[x509.GeneralName]] = None,
) -> x509.Certificate:
    subject_priv_key = key_or_generate(subject_key)
    subject_key_pub: ANY_PUB_KEY = subject_priv_key.public_key()

    ca_builder: x509.CertificateBuilder = x509.CertificateBuilder()
    ca_builder = ca_builder.subject_name(subject_name)
    ca_builder = ca_builder.issuer_name(subject_name)
    ca_builder = ca_builder.not_valid_before(NOT_BEFORE)
    ca_builder = ca_builder.not_valid_after(NOT_AFTER)
    ca_builder = ca_builder.serial_number(x509.random_serial_number())
    ca_builder = ca_builder.public_key(subject_key_pub)
    ca_builder = ca_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    if permitted_subtrees is not None or excluded_subtrees is not None:
        ca_builder = ca_builder.add_extension(
            x509.NameConstraints(permitted_subtrees, excluded_subtrees), critical=True
        )

    return ca_builder.sign(
        private_key=subject_priv_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )


def generate_name_constraints_test(
    output: TextIO,
    test_name: str,
    expected_error: Optional[str] = None,
    subject_common_name: Optional[str] = None,
    extra_subject_names: Optional[List[x509.NameAttribute]] = None,
    valid_names: Optional[List[str]] = None,
    invalid_names: Optional[List[str]] = None,
    sans: Optional[Iterable[x509.GeneralName]] = None,
    permitted_subtrees: Optional[Iterable[x509.GeneralName]] = None,
    excluded_subtrees: Optional[Iterable[x509.GeneralName]] = None,
) -> None:
    """
    Generate a test case, writing a rust '#[test]' function into
    name_constraints.rs, and writing supporting files into the current
    directory.

    - `test_name`: name of the test, must be a rust identifier.
    - `expected_error`: item in `webpki::Error` enum, expected error from
      webpki `verify_is_valid_tls_server_cert` function.  Leave absent to
      expect success.
    - `subject_common_name`: optional string to put in end-entity certificate
      subject common name.
    - `extra_subject_names`: optional sequence of `x509.NameAttributes` to add
      to end-entity certificate subject.
    - `valid_names`: optional sequence of valid names that the end-entity
      certificate is expected to pass `verify_is_valid_for_subject_name` for.
    - `invalid_names`: optional sequence of invalid names that the end-entity
      certificate is expected to fail `verify_is_valid_for_subject_name` with
      `CertNotValidForName`.
    - `sans`: optional sequence of `x509.GeneralName`s that are the contents of
      the subjectAltNames extension.  If empty or not provided the end-entity
      certificate does not have a subjectAltName extension.
    - `permitted_subtrees`: optional sequence of `x509.GeneralName`s that are
      the `permittedSubtrees` contents of the `nameConstraints` extension.
      If this and `excluded_subtrees` are empty/absent then the end-entity
      certificate does not have a `nameConstraints` extension.
    - `excluded_subtrees`: optional sequence of `x509.GeneralName`s that are
      the `excludedSubtrees` contents of the `nameConstraints` extension.
      If this and `permitted_subtrees` are both empty/absent then the
      end-entity  certificate does not have a `nameConstraints` extension.
    """

    if invalid_names is None:
        invalid_names = []
    if valid_names is None:
        valid_names = []
    if extra_subject_names is None:
        extra_subject_names = []

    issuer_name: x509.Name = issuer_name_for_test(test_name)

    # end-entity
    ee_subject = x509.Name(
        (
            [x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)]
            if subject_common_name
            else []
        )
        + [x509.NameAttribute(NameOID.ORGANIZATION_NAME, test_name)]
        + extra_subject_names
    )
    ee_certificate: x509.Certificate = end_entity_cert(
        subject_name=ee_subject,
        issuer_name=issuer_name,
        sans=sans,
    )

    output_dir: str = "name_constraints"
    ee_cert_path: str = os.path.join(output_dir, f"{test_name}.ee.der")
    ca_cert_path: str = os.path.join(output_dir, f"{test_name}.ca.der")

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    with open(ee_cert_path, "wb") as f:
        f.write(ee_certificate.public_bytes(Encoding.DER))

    # issuer
    ca: x509.Certificate = ca_cert(
        subject_name=issuer_name,
        subject_key=ISSUER_PRIVATE_KEY,
        permitted_subtrees=permitted_subtrees,
        excluded_subtrees=excluded_subtrees,
    )

    with open(ca_cert_path, "wb") as f:
        f.write(ca.public_bytes(Encoding.DER))

    expected: str = ""
    if expected_error is None:
        expected = "Ok(())"
    else:
        expected = "Err(webpki::Error::" + expected_error + ")"

    valid_names_str: str = ", ".join('"' + name + '"' for name in valid_names)
    invalid_names_str: str = ", ".join('"' + name + '"' for name in invalid_names)

    print(
        """
#[test]
fn %(test_name)s() {
    let ee = include_bytes!("%(ee_cert_path)s");
    let ca = include_bytes!("%(ca_cert_path)s");
    assert_eq!(
        check_cert(ee, ca, &[%(valid_names_str)s], &[%(invalid_names_str)s]),
        %(expected)s
    );
}"""
        % locals(),
        file=output,
    )


def name_constraints() -> None:
    with trim_top("name_constraints.rs") as output:
        generate_name_constraints_test(
            output,
            "no_name_constraints",
            subject_common_name="subject.example.com",
            valid_names=["dns.example.com"],
            invalid_names=["subject.example.com"],
            sans=[x509.DNSName("dns.example.com")],
        )

        generate_name_constraints_test(
            output,
            "additional_dns_labels",
            subject_common_name="subject.example.com",
            valid_names=["host1.example.com", "host2.example.com"],
            invalid_names=["subject.example.com"],
            sans=[x509.DNSName("host1.example.com"), x509.DNSName("host2.example.com")],
            permitted_subtrees=[x509.DNSName(".example.com")],
        )

        generate_name_constraints_test(
            output,
            "disallow_subject_common_name",
            expected_error="UnknownIssuer",
            subject_common_name="disallowed.example.com",
            excluded_subtrees=[x509.DNSName("disallowed.example.com")],
        )
        generate_name_constraints_test(
            output,
            "disallow_dns_san",
            expected_error="UnknownIssuer",
            sans=[x509.DNSName("disallowed.example.com")],
            excluded_subtrees=[x509.DNSName("disallowed.example.com")],
        )

        generate_name_constraints_test(
            output,
            "allow_subject_common_name",
            subject_common_name="allowed.example.com",
            invalid_names=["allowed.example.com"],
            permitted_subtrees=[x509.DNSName("allowed.example.com")],
        )
        generate_name_constraints_test(
            output,
            "allow_dns_san",
            valid_names=["allowed.example.com"],
            sans=[x509.DNSName("allowed.example.com")],
            permitted_subtrees=[x509.DNSName("allowed.example.com")],
        )
        generate_name_constraints_test(
            output,
            "allow_dns_san_and_subject_common_name",
            valid_names=["allowed-san.example.com"],
            invalid_names=["allowed-cn.example.com"],
            sans=[x509.DNSName("allowed-san.example.com")],
            subject_common_name="allowed-cn.example.com",
            permitted_subtrees=[
                x509.DNSName("allowed-san.example.com"),
                x509.DNSName("allowed-cn.example.com"),
            ],
        )
        generate_name_constraints_test(
            output,
            "allow_dns_san_and_disallow_subject_common_name",
            expected_error="UnknownIssuer",
            sans=[x509.DNSName("allowed-san.example.com")],
            subject_common_name="disallowed-cn.example.com",
            permitted_subtrees=[x509.DNSName("allowed-san.example.com")],
            excluded_subtrees=[x509.DNSName("disallowed-cn.example.com")],
        )
        generate_name_constraints_test(
            output,
            "disallow_dns_san_and_allow_subject_common_name",
            expected_error="UnknownIssuer",
            sans=[
                x509.DNSName("allowed-san.example.com"),
                x509.DNSName("disallowed-san.example.com"),
            ],
            subject_common_name="allowed-cn.example.com",
            permitted_subtrees=[
                x509.DNSName("allowed-san.example.com"),
                x509.DNSName("allowed-cn.example.com"),
            ],
            excluded_subtrees=[x509.DNSName("disallowed-san.example.com")],
        )

        # XXX: ideally this test case would be a negative one, because the name constraints
        # should apply to the subject name.
        # however, because we don't look at email addresses in subjects, it is accepted.
        generate_name_constraints_test(
            output,
            "we_incorrectly_ignore_name_constraints_on_name_in_subject",
            extra_subject_names=[
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "joe@notexample.com")
            ],
            permitted_subtrees=[x509.RFC822Name("example.com")],
        )

        # this does work, however, because we process all SANs
        generate_name_constraints_test(
            output,
            "reject_constraints_on_unimplemented_names",
            expected_error="UnknownIssuer",
            sans=[x509.RFC822Name("joe@example.com")],
            permitted_subtrees=[x509.RFC822Name("example.com")],
        )

        # RFC5280 4.2.1.10:
        #   "If no name of the type is in the certificate,
        #    the certificate is acceptable."
        generate_name_constraints_test(
            output,
            "we_ignore_constraints_on_names_that_do_not_appear_in_cert",
            sans=[x509.DNSName("notexample.com")],
            valid_names=["notexample.com"],
            invalid_names=["example.com"],
            permitted_subtrees=[x509.RFC822Name("example.com")],
        )

        generate_name_constraints_test(
            output,
            "wildcard_san_accepted_if_in_subtree",
            sans=[x509.DNSName("*.example.com")],
            valid_names=["bob.example.com", "jane.example.com"],
            invalid_names=["example.com", "uh.oh.example.com"],
            permitted_subtrees=[x509.DNSName("example.com")],
        )

        generate_name_constraints_test(
            output,
            "wildcard_san_rejected_if_in_excluded_subtree",
            expected_error="UnknownIssuer",
            sans=[x509.DNSName("*.example.com")],
            excluded_subtrees=[x509.DNSName("example.com")],
        )

        generate_name_constraints_test(
            output,
            "ip4_address_san_rejected_if_in_excluded_subtree",
            expected_error="UnknownIssuer",
            sans=[x509.IPAddress(ipaddress.ip_address("12.34.56.78"))],
            excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("12.34.56.0/24"))],
        )

        generate_name_constraints_test(
            output,
            "ip4_address_san_allowed_if_outside_excluded_subtree",
            valid_names=["12.34.56.78"],
            sans=[x509.IPAddress(ipaddress.ip_address("12.34.56.78"))],
            excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("12.34.56.252/30"))],
        )

        sparse_net_addr = ipaddress.ip_network("12.34.56.78/24", strict=False)
        sparse_net_addr.netmask = ipaddress.ip_address("255.255.255.1")
        generate_name_constraints_test(
            output,
            "ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask",
            expected_error="UnknownIssuer",
            sans=[
                # inside excluded network, if netmask is allowed to be sparse
                x509.IPAddress(ipaddress.ip_address("12.34.56.79")),
            ],
            excluded_subtrees=[x509.IPAddress(sparse_net_addr)],
        )

        generate_name_constraints_test(
            output,
            "ip4_address_san_allowed",
            valid_names=["12.34.56.78"],
            invalid_names=[
                "12.34.56.77",
                "12.34.56.79",
                "0000:0000:0000:0000:0000:ffff:0c22:384e",
            ],
            sans=[x509.IPAddress(ipaddress.ip_address("12.34.56.78"))],
            permitted_subtrees=[x509.IPAddress(ipaddress.ip_network("12.34.56.0/24"))],
        )

        generate_name_constraints_test(
            output,
            "ip6_address_san_rejected_if_in_excluded_subtree",
            expected_error="UnknownIssuer",
            sans=[x509.IPAddress(ipaddress.ip_address("2001:db8::1"))],
            excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("2001:db8::/48"))],
        )

        generate_name_constraints_test(
            output,
            "ip6_address_san_allowed_if_outside_excluded_subtree",
            valid_names=["2001:0db9:0000:0000:0000:0000:0000:0001"],
            sans=[x509.IPAddress(ipaddress.ip_address("2001:db9::1"))],
            excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("2001:db8::/48"))],
        )

        generate_name_constraints_test(
            output,
            "ip6_address_san_allowed",
            valid_names=["2001:0db9:0000:0000:0000:0000:0000:0001"],
            invalid_names=["12.34.56.78"],
            sans=[x509.IPAddress(ipaddress.ip_address("2001:db9::1"))],
            permitted_subtrees=[x509.IPAddress(ipaddress.ip_network("2001:db9::/48"))],
        )

        generate_name_constraints_test(
            output,
            "ip46_mixed_address_san_allowed",
            valid_names=["12.34.56.78", "2001:0db9:0000:0000:0000:0000:0000:0001"],
            invalid_names=[
                "12.34.56.77",
                "12.34.56.79",
                "0000:0000:0000:0000:0000:ffff:0c22:384e",
            ],
            sans=[
                x509.IPAddress(ipaddress.ip_address("12.34.56.78")),
                x509.IPAddress(ipaddress.ip_address("2001:db9::1")),
            ],
            permitted_subtrees=[
                x509.IPAddress(ipaddress.ip_network("12.34.56.0/24")),
                x509.IPAddress(ipaddress.ip_network("2001:db9::/48")),
            ],
        )

        generate_name_constraints_test(
            output,
            "permit_directory_name_not_implemented",
            expected_error="UnknownIssuer",
            permitted_subtrees=[
                x509.DirectoryName(
                    x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "CN")])
                )
            ],
        )

        generate_name_constraints_test(
            output,
            "exclude_directory_name_not_implemented",
            expected_error="UnknownIssuer",
            excluded_subtrees=[
                x509.DirectoryName(
                    x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "CN")])
                )
            ],
        )


def signatures() -> None:
    rsa_pub_exponent: int = 0x10001
    backend: Any = default_backend()
    all_key_types: dict[str, ANY_PRIV_KEY] = {
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
        "ecdsa_p256": ec.generate_private_key(ec.SECP256R1(), backend),
        "ecdsa_p384": ec.generate_private_key(ec.SECP384R1(), backend),
        "ecdsa_p521_not_supported": ec.generate_private_key(ec.SECP521R1(), backend),
        "rsa_1024_not_supported": rsa.generate_private_key(
            rsa_pub_exponent, 1024, backend
        ),
        "rsa_2048": rsa.generate_private_key(rsa_pub_exponent, 2048, backend),
        "rsa_3072": rsa.generate_private_key(rsa_pub_exponent, 3072, backend),
        "rsa_4096": rsa.generate_private_key(rsa_pub_exponent, 4096, backend),
    }

    rsa_types: list[str] = [
        "RSA_PKCS1_2048_8192_SHA256",
        "RSA_PKCS1_2048_8192_SHA384",
        "RSA_PKCS1_2048_8192_SHA512",
        "RSA_PSS_2048_8192_SHA256_LEGACY_KEY",
        "RSA_PSS_2048_8192_SHA384_LEGACY_KEY",
        "RSA_PSS_2048_8192_SHA512_LEGACY_KEY",
    ]

    webpki_algs: dict[str, Iterable[str]] = {
        "ed25519": ["ED25519"],
        "ecdsa_p256": ["ECDSA_P256_SHA384", "ECDSA_P256_SHA256"],
        "ecdsa_p384": ["ECDSA_P384_SHA384", "ECDSA_P384_SHA256"],
        "rsa_2048": rsa_types,
        "rsa_3072": rsa_types + ["RSA_PKCS1_3072_8192_SHA384"],
        "rsa_4096": rsa_types + ["RSA_PKCS1_3072_8192_SHA384"],
    }

    pss_sha256: padding.PSS = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()), salt_length=32
    )
    pss_sha384: padding.PSS = padding.PSS(
        mgf=padding.MGF1(hashes.SHA384()), salt_length=48
    )
    pss_sha512: padding.PSS = padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()), salt_length=64
    )

    how_to_sign: dict[str, SIGNER] = {
        "ED25519": lambda key, message: key.sign(message),
        "ECDSA_P256_SHA256": lambda key, message: key.sign(
            message, ec.ECDSA(hashes.SHA256())
        ),
        "ECDSA_P256_SHA384": lambda key, message: key.sign(
            message, ec.ECDSA(hashes.SHA384())
        ),
        "ECDSA_P384_SHA256": lambda key, message: key.sign(
            message, ec.ECDSA(hashes.SHA256())
        ),
        "ECDSA_P384_SHA384": lambda key, message: key.sign(
            message, ec.ECDSA(hashes.SHA384())
        ),
        "RSA_PKCS1_2048_8192_SHA256": lambda key, message: key.sign(
            message, padding.PKCS1v15(), hashes.SHA256()
        ),
        "RSA_PKCS1_2048_8192_SHA384": lambda key, message: key.sign(
            message, padding.PKCS1v15(), hashes.SHA384()
        ),
        "RSA_PKCS1_2048_8192_SHA512": lambda key, message: key.sign(
            message, padding.PKCS1v15(), hashes.SHA512()
        ),
        "RSA_PKCS1_3072_8192_SHA384": lambda key, message: key.sign(
            message, padding.PKCS1v15(), hashes.SHA384()
        ),
        "RSA_PSS_2048_8192_SHA256_LEGACY_KEY": lambda key, message: key.sign(
            message, pss_sha256, hashes.SHA256()
        ),
        "RSA_PSS_2048_8192_SHA384_LEGACY_KEY": lambda key, message: key.sign(
            message, pss_sha384, hashes.SHA384()
        ),
        "RSA_PSS_2048_8192_SHA512_LEGACY_KEY": lambda key, message: key.sign(
            message, pss_sha512, hashes.SHA512()
        ),
    }

    output_dir: str = "signatures"
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    message = b"hello world!"
    message_path: str = os.path.join(output_dir, "message.bin")
    with open(message_path, "wb") as f:
        f.write(message)

    def _cert_path(cert_type: str) -> str:
        return os.path.join(output_dir, f"{cert_type}.ee.der")

    for name, private_key in all_key_types.items():
        ee_subject = x509.Name(
            [x509.NameAttribute(NameOID.ORGANIZATION_NAME, name + " test")]
        )
        issuer_subject = x509.Name(
            [x509.NameAttribute(NameOID.ORGANIZATION_NAME, name + " issuer")]
        )
        certificate: x509.Certificate = end_entity_cert(
            subject_name=ee_subject,
            subject_key=private_key,
            issuer_name=issuer_subject,
        )

        with open(_cert_path(name), "wb") as f:
            f.write(certificate.public_bytes(Encoding.DER))

    def _test(
        test_name: str, cert_type: str, algorithm: str, signature: bytes, expected: str
    ) -> None:
        nonlocal message_path
        cert_path: str = _cert_path(cert_type)
        lower_test_name: str = test_name.lower()

        sig_path: str = os.path.join(output_dir, f"{lower_test_name}.sig.bin")
        with open(sig_path, "wb") as f:
            f.write(signature)

        print(
            """
#[test]
#[cfg(feature = "alloc")]
fn %(lower_test_name)s() {
    let ee = include_bytes!("%(cert_path)s");
    let message = include_bytes!("%(message_path)s");
    let signature = include_bytes!("%(sig_path)s");
    assert_eq!(
        check_sig(ee, &webpki::%(algorithm)s, message, signature),
        %(expected)s
    );
}"""
            % locals(),
            file=output,
        )

    def good_signature(
        test_name: str, cert_type: str, algorithm: str, signer: SIGNER
    ) -> None:
        signature: bytes = signer(all_key_types[cert_type], message)
        _test(test_name, cert_type, algorithm, signature, expected="Ok(())")

    def good_signature_but_rejected(
        test_name: str, cert_type: str, algorithm: str, signer: SIGNER
    ) -> None:
        signature: bytes = signer(all_key_types[cert_type], message)
        _test(
            test_name,
            cert_type,
            algorithm,
            signature,
            expected="Err(webpki::Error::InvalidSignatureForPublicKey)",
        )

    def bad_signature(
        test_name: str, cert_type: str, algorithm: str, signer: SIGNER
    ) -> None:
        signature: bytes = signer(all_key_types[cert_type], message + b"?")
        _test(
            test_name,
            cert_type,
            algorithm,
            signature,
            expected="Err(webpki::Error::InvalidSignatureForPublicKey)",
        )

    def bad_algorithms_for_key(
        test_name: str, cert_type: str, unusable_algs: set[str]
    ) -> None:
        cert_path: str = _cert_path(cert_type)
        test_name_lower: str = test_name.lower()
        unusable_algs_str: str = ", ".join(
            "&webpki::" + alg for alg in sorted(unusable_algs)
        )
        print(
            """
#[test]
#[cfg(feature = "alloc")]
fn %(test_name_lower)s() {
    let ee = include_bytes!("%(cert_path)s");
    for algorithm in &[ %(unusable_algs_str)s ] {
        assert_eq!(
            check_sig(ee, algorithm, b"", b""),
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
        );
    }
}"""
            % locals(),
            file=output,
        )

    with trim_top("signatures.rs") as output:
        # compute all webpki algorithms covered by these tests
        all_webpki_algs: set[str] = set(
            [item for algs in webpki_algs.values() for item in algs]
        )

        for type, algs in webpki_algs.items():
            for alg in algs:
                signer: SIGNER = how_to_sign[alg]
                good_signature(
                    type + "_key_and_" + alg + "_good_signature",
                    cert_type=type,
                    algorithm=alg,
                    signer=signer,
                )
                bad_signature(
                    type + "_key_and_" + alg + "_detects_bad_signature",
                    cert_type=type,
                    algorithm=alg,
                    signer=signer,
                )

            unusable_algs = set(all_webpki_algs)
            for alg in algs:
                unusable_algs.remove(alg)

            # special case: tested separately below
            if type == "rsa_2048":
                unusable_algs.remove("RSA_PKCS1_3072_8192_SHA384")

            bad_algorithms_for_key(
                type + "_key_rejected_by_other_algorithms",
                cert_type=type,
                unusable_algs=unusable_algs,
            )

        good_signature_but_rejected(
            "rsa_2048_key_rejected_by_RSA_PKCS1_3072_8192_SHA384",
            cert_type="rsa_2048",
            algorithm="RSA_PKCS1_3072_8192_SHA384",
            signer=signer,
        )


def generate_client_auth_test(
    output: TextIO,
    test_name: str,
    ekus: Optional[Iterable[x509.ObjectIdentifier]],
    expected_error: Optional[str] = None,
) -> None:
    issuer_name: x509.Name = issuer_name_for_test(test_name)

    # end-entity
    ee_subject: x509.Name = x509.Name(
        [x509.NameAttribute(NameOID.ORGANIZATION_NAME, test_name)]
    )
    ee_certificate: x509.Certificate = end_entity_cert(
        subject_name=ee_subject,
        ekus=ekus,
        issuer_name=issuer_name,
    )

    output_dir: str = "client_auth"
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    ee_cert_path: str = os.path.join(output_dir, f"{test_name}.ee.der")
    with open(ee_cert_path, "wb") as f:
        f.write(ee_certificate.public_bytes(Encoding.DER))

    # issuer
    ca: x509.Certificate = ca_cert(
        subject_name=issuer_name, subject_key=ISSUER_PRIVATE_KEY
    )

    ca_cert_path: str = os.path.join(output_dir, f"{test_name}.ca.der")
    with open(ca_cert_path, "wb") as f:
        f.write(ca.public_bytes(Encoding.DER))

    expected: str = ""
    if expected_error is None:
        expected = "Ok(())"
    else:
        expected = "Err(webpki::Error::" + expected_error + ")"

    print(
        """
#[test]
#[cfg(feature = "alloc")]
fn %(test_name)s() {
    let ee = include_bytes!("%(ee_cert_path)s");
    let ca = include_bytes!("%(ca_cert_path)s");
    assert_eq!(
        check_cert(ee, ca),
        %(expected)s
    );
}"""
        % locals(),
        file=output,
    )


def client_auth() -> None:
    with trim_top("client_auth.rs") as output:
        generate_client_auth_test(
            output, "cert_with_no_eku_accepted_for_client_auth", ekus=None
        )
        generate_client_auth_test(
            output,
            "cert_with_clientauth_eku_accepted_for_client_auth",
            ekus=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        generate_client_auth_test(
            output,
            "cert_with_both_ekus_accepted_for_client_auth",
            ekus=[ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
        )
        generate_client_auth_test(
            output,
            "cert_with_serverauth_eku_rejected_for_client_auth",
            ekus=[ExtendedKeyUsageOID.SERVER_AUTH],
            expected_error="RequiredEkuNotFound",
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--name-constraints",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Generate name constraint testcases",
    )
    parser.add_argument(
        "--signatures",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Generate signature testcases",
    )
    parser.add_argument(
        "--clientauth",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Generate client auth testcases",
    )
    parser.add_argument(
        "--format",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run cargo fmt post-generation",
    )
    parser.add_argument(
        "--test",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run cargo test post-generation",
    )
    args = parser.parse_args()

    if args.name_constraints:
        name_constraints()
    if args.signatures:
        signatures()
    if args.clientauth:
        client_auth()

    if args.format:
        subprocess.run("cargo fmt", shell=True, check=True)
    if args.test:
        subprocess.run("cargo test", shell=True, check=True)
