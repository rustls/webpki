"""
Generates test cases that aim to validate name constraints and other
name-related parts of webpki.

Run this script from tests/.  It edits the bottom part of tests/name_constraints.rs
and drops files into tests/name_constraints.
"""


from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import ipaddress
import datetime

ISSUER_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
ISSUER_PUBLIC_KEY = ISSUER_PRIVATE_KEY.public_key()

NOT_BEFORE = datetime.datetime.utcfromtimestamp(0x1FEDF00D - 30)
NOT_AFTER = datetime.datetime.utcfromtimestamp(0x1FEDF00D + 30)


def name_constraints_test(
    test_name,
    expected_error=None,
    subject_common_name=None,
    extra_subject_names=[],
    valid_names=[],
    invalid_names=[],
    sans=None,
    permitted_subtrees=None,
    excluded_subtrees=None,
):
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

    # keys must be valid but are otherwise unimportant for these tests
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    issuer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "issuer.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, test_name),
        ]
    )

    # end-entity
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            (
                [x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)]
                if subject_common_name
                else []
            )
            + [x509.NameAttribute(NameOID.ORGANIZATION_NAME, test_name)]
            + extra_subject_names
        )
    )
    builder = builder.issuer_name(issuer_name)

    builder = builder.not_valid_before(NOT_BEFORE)
    builder = builder.not_valid_after(NOT_AFTER)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    certificate = builder.sign(
        private_key=ISSUER_PRIVATE_KEY,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    with open(f"name_constraints/{test_name}.ee.der", "wb") as f:
        f.write(certificate.public_bytes(Encoding.DER))

    # issuer
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(issuer_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(NOT_BEFORE)
    builder = builder.not_valid_after(NOT_AFTER)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ISSUER_PUBLIC_KEY)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    if permitted_subtrees or excluded_subtrees:
        builder = builder.add_extension(
            x509.NameConstraints(permitted_subtrees, excluded_subtrees), critical=True
        )

    certificate = builder.sign(
        private_key=ISSUER_PRIVATE_KEY,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    with open(f"name_constraints/{test_name}.ca.der", "wb") as f:
        f.write(certificate.public_bytes(Encoding.DER))

    if expected_error is None:
        expected = "Ok(())"
    else:
        expected = "Err(webpki::Error::" + expected_error + ")"

    valid_names = ", ".join('"' + name + '"' for name in valid_names)
    invalid_names = ", ".join('"' + name + '"' for name in invalid_names)

    print(
        """
#[test]
fn %(test_name)s() {
    let ee = include_bytes!("name_constraints/%(test_name)s.ee.der");
    let ca = include_bytes!("name_constraints/%(test_name)s.ca.der");
    assert_eq!(
        check_cert(ee, ca, &[%(valid_names)s], &[%(invalid_names)s]),
        %(expected)s
    );
}"""
        % locals(),
        file=output,
    )


top = open("name_constraints.rs", "r").readlines()
top = top[: top.index("// DO NOT EDIT BELOW: generated by tests/generate.py\n") + 1]
output = open("name_constraints.rs", "w")
for line in top:
    output.write(line)

name_constraints_test(
    "no_name_constraints",
    subject_common_name="subject.example.com",
    valid_names=["dns.example.com"],
    invalid_names=["subject.example.com"],
    sans=[x509.DNSName("dns.example.com")],
)

name_constraints_test(
    "additional_dns_labels",
    subject_common_name="subject.example.com",
    valid_names=["host1.example.com", "host2.example.com"],
    invalid_names=["subject.example.com"],
    sans=[x509.DNSName("host1.example.com"), x509.DNSName("host2.example.com")],
    permitted_subtrees=[x509.DNSName(".example.com")],
)


name_constraints_test(
    "disallow_subject_common_name",
    expected_error="UnknownIssuer",
    subject_common_name="disallowed.example.com",
    excluded_subtrees=[x509.DNSName("disallowed.example.com")],
)
name_constraints_test(
    "disallow_dns_san",
    expected_error="UnknownIssuer",
    sans=[x509.DNSName("disallowed.example.com")],
    excluded_subtrees=[x509.DNSName("disallowed.example.com")],
)

name_constraints_test(
    "allow_subject_common_name",
    subject_common_name="allowed.example.com",
    invalid_names=["allowed.example.com"],
    permitted_subtrees=[x509.DNSName("allowed.example.com")],
)
name_constraints_test(
    "allow_dns_san",
    valid_names=["allowed.example.com"],
    sans=[x509.DNSName("allowed.example.com")],
    permitted_subtrees=[x509.DNSName("allowed.example.com")],
)
name_constraints_test(
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
name_constraints_test(
    "allow_dns_san_and_disallow_subject_common_name",
    expected_error="UnknownIssuer",
    sans=[x509.DNSName("allowed-san.example.com")],
    subject_common_name="disallowed-cn.example.com",
    permitted_subtrees=[x509.DNSName("allowed-san.example.com")],
    excluded_subtrees=[x509.DNSName("disallowed-cn.example.com")],
)
name_constraints_test(
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
name_constraints_test(
    "we_incorrectly_ignore_name_constraints_on_name_in_subject",
    extra_subject_names=[
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "joe@notexample.com")
    ],
    permitted_subtrees=[x509.RFC822Name("example.com")],
)

# this does work, however, because we process all SANs
name_constraints_test(
    "reject_constraints_on_unimplemented_names",
    expected_error="UnknownIssuer",
    sans=[x509.RFC822Name("joe@example.com")],
    permitted_subtrees=[x509.RFC822Name("example.com")],
)

# RFC5280 4.2.1.10:
#   "If no name of the type is in the certificate,
#    the certificate is acceptable."
name_constraints_test(
    "we_ignore_constraints_on_names_that_do_not_appear_in_cert",
    sans=[x509.DNSName("notexample.com")],
    valid_names=["notexample.com"],
    invalid_names=["example.com"],
    permitted_subtrees=[x509.RFC822Name("example.com")],
)

name_constraints_test(
    "wildcard_san_accepted_if_in_subtree",
    sans=[x509.DNSName("*.example.com")],
    valid_names=["bob.example.com", "jane.example.com"],
    invalid_names=["example.com", "uh.oh.example.com"],
    permitted_subtrees=[x509.DNSName("example.com")],
)

name_constraints_test(
    "wildcard_san_rejected_if_in_excluded_subtree",
    expected_error="UnknownIssuer",
    sans=[x509.DNSName("*.example.com")],
    excluded_subtrees=[x509.DNSName("example.com")],
)

name_constraints_test(
    "ip4_address_san_rejected_if_in_excluded_subtree",
    expected_error="UnknownIssuer",
    sans=[x509.IPAddress(ipaddress.ip_address("12.34.56.78"))],
    excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("12.34.56.0/24"))],
)

name_constraints_test(
    "ip4_address_san_allowed_if_outside_excluded_subtree",
    valid_names=["12.34.56.78"],
    sans=[x509.IPAddress(ipaddress.ip_address("12.34.56.78"))],
    excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("12.34.56.252/30"))],
)

sparse_net_addr = ipaddress.ip_network("12.34.56.78/24", strict=False)
sparse_net_addr.netmask = ipaddress.ip_address("255.255.255.1")
name_constraints_test(
    "ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask",
    expected_error="UnknownIssuer",
    sans=[
        # inside excluded network, if netmask is allowed to be sparse
        x509.IPAddress(ipaddress.ip_address("12.34.56.79")),
    ],
    excluded_subtrees=[x509.IPAddress(sparse_net_addr)],
)


name_constraints_test(
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

name_constraints_test(
    "ip6_address_san_rejected_if_in_excluded_subtree",
    expected_error="UnknownIssuer",
    sans=[x509.IPAddress(ipaddress.ip_address("2001:db8::1"))],
    excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("2001:db8::/48"))],
)

name_constraints_test(
    "ip6_address_san_allowed_if_outside_excluded_subtree",
    valid_names=["2001:0db9:0000:0000:0000:0000:0000:0001"],
    sans=[x509.IPAddress(ipaddress.ip_address("2001:db9::1"))],
    excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("2001:db8::/48"))],
)

name_constraints_test(
    "ip6_address_san_allowed",
    valid_names=["2001:0db9:0000:0000:0000:0000:0000:0001"],
    invalid_names=["12.34.56.78"],
    sans=[x509.IPAddress(ipaddress.ip_address("2001:db9::1"))],
    permitted_subtrees=[x509.IPAddress(ipaddress.ip_network("2001:db9::/48"))],
)

name_constraints_test(
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

name_constraints_test(
    "permit_directory_name_not_implemented",
    expected_error="UnknownIssuer",
    permitted_subtrees=[
        x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "CN")]))
    ],
)

name_constraints_test(
    "exclude_directory_name_not_implemented",
    expected_error="UnknownIssuer",
    excluded_subtrees=[
        x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "CN")]))
    ],
)
