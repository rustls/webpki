from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import CertificatePoliciesOID
import datetime

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

builder = x509.CertificateBuilder()
builder = builder.subject_name(x509.Name([]))
builder = builder.issuer_name(x509.Name([]))
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(datetime.datetime.fromtimestamp(0x1FEDF00D - 30))
builder = builder.not_valid_after(datetime.datetime.fromtimestamp(0x1FEDF00D + 30))
builder = builder.public_key(private_key.public_key())
builder = builder.add_extension(
    x509.CertificatePolicies(
        [x509.PolicyInformation(CertificatePoliciesOID.ANY_POLICY, ["Example CPS"])]
    ),
    critical=True,
)

certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
)

with open("any-policy.der", "wb") as f:
    f.write(certificate.public_bytes(Encoding.DER))
