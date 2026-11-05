"""
Generates Merkle Tree Certificate test fixtures, following
draft-ietf-plants-merkle-tree-certs-07 ("MTC").

The certificates are DER-encoded by hand, because MTC certificates are not
signed in the usual way. All keys are fixed, so only the ML-DSA-44 signatures
differ between runs.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Object identifiers.
ID_ALG_MTC_PROOF = "1.3.6.1.5.5.7.6.67"
ID_RDNA_TRUST_ANCHOR_ID = "1.3.6.1.5.5.7.25.3"
ID_PE_MTC_CA = "1.3.6.1.5.5.7.1.38"
ID_ALG_UNSIGNED = "1.3.6.1.5.5.7.6.36"
ID_ED25519 = "1.3.101.112"
ID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
ID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17"
ID_COMMON_NAME = "2.5.4.3"
ID_BASIC_CONSTRAINTS = "2.5.29.19"
ID_KEY_USAGE = "2.5.29.15"
ID_SUBJECT_ALT_NAME = "2.5.29.17"
ID_CRL_NUMBER = "2.5.29.20"

# Trust anchor IDs, as relative OIDs under 1.3.6.1.4.1.
CA_ID = "32473.1"
ECDSA_WITNESS_ID = "32473.2.1"
ML_DSA_WITNESS_ID = "32473.2.2"
GREASE_ID = "32473.9"

LOG_NUMBER = 1
LOG_SIZE = 13
# The CA revokes the first and last entries of the log.
MIN_SERIAL = (LOG_NUMBER << 48) | 1
MAX_SERIAL = (LOG_NUMBER << 48) | (LOG_SIZE - 2)

NOT_BEFORE = b"260101000000Z"
NOT_AFTER = b"270101000000Z"
# 2026-06-01T00:00:00Z, within the validity period.
VALIDATION_TIME = 1780272000

# Entries of interest. The others are ordinary end-entity certificates.
STANDALONE_INDEX = 9
LANDMARK_INDEX = 5
INTERMEDIATE_INDEX = 3

CA_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ECDSA_WITNESS_KEY = ec.derive_private_key(0x1F2E3D4C, ec.SECP256R1())
ML_DSA_WITNESS_KEY = mldsa.MLDSA44PrivateKey.from_seed_bytes(bytes(range(32, 64)))
EE_KEY = ec.derive_private_key(0x5A6B7C8D, ec.SECP256R1())
ECDSA = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)

Subtree = Tuple[int, int]


def der(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def seq(*items: bytes) -> bytes:
    return der(0x30, b"".join(items))


def base128(arcs: List[int]) -> bytes:
    out = b""
    for arc in arcs:
        groups = [arc & 0x7F]
        arc >>= 7
        while arc:
            groups.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(groups))
    return out


def oid(dotted: str) -> bytes:
    arcs = [int(arc) for arc in dotted.split(".")]
    return der(0x06, base128([40 * arcs[0] + arcs[1]] + arcs[2:]))


def trust_anchor_id(dotted: str) -> bytes:
    return base128([int(arc) for arc in dotted.split(".")])


def integer(value: int) -> bytes:
    return der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def bit_string(content: bytes) -> bytes:
    return der(0x03, b"\x00" + content)


def alg_id(dotted: str) -> bytes:
    return seq(oid(dotted))


def extension(dotted: str, critical: bool, value: bytes) -> bytes:
    flag = der(0x01, b"\xff") if critical else b""
    return seq(oid(dotted), flag, der(0x04, value))


def ca_id_name(dotted: str) -> bytes:
    attribute = seq(oid(ID_RDNA_TRUST_ANCHOR_ID), der(0x0D, trust_anchor_id(dotted)))
    return seq(der(0x31, attribute))


def common_name(name: str) -> bytes:
    return seq(der(0x31, seq(oid(ID_COMMON_NAME), der(0x0C, name.encode()))))


PrivateKey = Union[
    ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey, mldsa.MLDSA44PrivateKey
]


def spki(key: PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def first_element(encoded: bytes) -> bytes:
    """The first element of the DER SEQUENCE `encoded`, which must use short-form lengths."""
    assert encoded[1] < 0x80 and encoded[3] < 0x80
    end = 4 + encoded[3]
    return encoded[2:end]


def sha256(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


VALIDITY = seq(der(0x17, NOT_BEFORE), der(0x17, NOT_AFTER))
VERSION_3 = der(0xA0, integer(2))
CA_NAME = ca_id_name(CA_ID)
CA_CERT_KEY_USAGE = extension(ID_KEY_USAGE, True, der(0x03, b"\x01\x06"))
CA_BASIC_CONSTRAINTS = extension(ID_BASIC_CONSTRAINTS, True, seq(der(0x01, b"\xff")))


def mtc_ca_cert(
    name: bytes = CA_NAME,
    critical: Optional[bool] = True,
    min_serial: int = MIN_SERIAL,
    max_serial: int = MAX_SERIAL,
) -> bytes:
    """An MTC CA certificate (MTC section 5.5). `critical=None` omits the MTC extension."""
    body = seq(alg_id(ID_ED25519), integer(min_serial), integer(max_serial))
    extensions = [CA_BASIC_CONSTRAINTS, CA_CERT_KEY_USAGE]
    if critical is not None:
        extensions.append(extension(ID_PE_MTC_CA, critical, body))
    tbs = seq(
        VERSION_3,
        integer(1),
        alg_id(ID_ALG_UNSIGNED),
        name,
        VALIDITY,
        name,
        spki(CA_KEY),
        der(0xA3, seq(*extensions)),
    )
    # An unsigned certificate (RFC 9925).
    return seq(tbs, alg_id(ID_ALG_UNSIGNED), bit_string(b""))


class Entry:
    """A TBSCertificate, split into the fields MTC section 7.2 names."""

    def __init__(self, index: int, subject: bytes, extensions: List[bytes]) -> None:
        self.serial = (LOG_NUMBER << 48) | index
        self.subject = subject
        self.spki = spki(EE_KEY)
        self.extensions = der(0xA3, seq(*extensions))

    def tbs(self, signature_alg: str = ID_ALG_MTC_PROOF) -> bytes:
        return seq(
            VERSION_3,
            integer(self.serial),
            alg_id(signature_alg),
            CA_NAME,
            VALIDITY,
            self.subject,
            self.spki,
            self.extensions,
        )

    def leaf_hash(self) -> bytes:
        entry_data = b"".join(
            [
                VERSION_3,
                CA_NAME,
                VALIDITY,
                self.subject,
                first_element(self.spki),
                der(0x04, sha256(self.spki)),
                self.extensions,
            ]
        )
        # MTCLogEntry: no extensions, tbs_cert_entry(1).
        return sha256(b"\x00", b"\x00\x00", b"\x00\x01", entry_data)


def end_entity(index: int) -> Entry:
    san = seq(der(0x82, f"mtc-{index}.example.com".encode()))
    return Entry(
        index, common_name(f"mtc-{index}"), [extension(ID_SUBJECT_ALT_NAME, False, san)]
    )


def intermediate() -> Entry:
    return Entry(
        INTERMEDIATE_INDEX,
        common_name("mtc-intermediate"),
        [CA_BASIC_CONSTRAINTS, CA_CERT_KEY_USAGE],
    )


ENTRIES = [
    intermediate() if i == INTERMEDIATE_INDEX else end_entity(i)
    for i in range(LOG_SIZE)
]
LEAVES = [entry.leaf_hash() for entry in ENTRIES]


def mth(start: int, end: int) -> bytes:
    """MTH(D[start:end]), RFC 9162 section 2.1.1."""
    n = end - start
    if n == 0:
        return sha256()
    if n == 1:
        return LEAVES[start]
    k = 1 << ((n - 1).bit_length() - 1)
    return sha256(b"\x01", mth(start, start + k), mth(start + k, end))


def inclusion_proof(index: int, start: int, end: int) -> bytes:
    """PATH(index - start, D[start:end]), RFC 9162 section 2.1.3.1."""
    n = end - start
    if n <= 1:
        return b""
    k = 1 << ((n - 1).bit_length() - 1)
    if index - start < k:
        return inclusion_proof(index, start, start + k) + mth(start + k, end)
    return inclusion_proof(index, start + k, end) + mth(start, start + k)


def find_subtrees(start: int, end: int) -> Tuple[Subtree, Subtree]:
    """MTC section 4.5.1."""
    if end - start <= 1:
        return (start, end), (end, end)
    last = end - 1
    split = (start ^ last).bit_length() - 1
    mask = (1 << split) - 1
    mid = last & ~mask
    left_split = (~start & mask).bit_length()
    left_start = start & ~((1 << left_split) - 1)
    return (left_start, mid), (mid, end)


def text(dotted: str) -> bytes:
    return f"oid/1.3.6.1.4.1.{dotted}".encode()


def cosigned_subtree(
    cosigner_id: str,
    subtree: Subtree,
    subtree_hash: bytes,
    timestamp: int = 0,
    log_number: int = LOG_NUMBER,
) -> bytes:
    """The message a cosigner signs, MTC section 5.3.1."""
    name = text(cosigner_id)
    origin = text(f"{CA_ID}.0.{log_number}")
    return b"".join(
        [
            b"subtree/v1\n\0",
            bytes([len(name)]),
            name,
            timestamp.to_bytes(8, "big"),
            bytes([len(origin)]),
            origin,
            subtree[0].to_bytes(8, "big"),
            subtree[1].to_bytes(8, "big"),
            subtree_hash,
        ]
    )


def sign(cosigner_id: str, message: bytes) -> bytes:
    if cosigner_id == CA_ID:
        return CA_KEY.sign(message)
    if cosigner_id == ECDSA_WITNESS_ID:
        return ECDSA_WITNESS_KEY.sign(message, ECDSA)
    if cosigner_id == ML_DSA_WITNESS_ID:
        return ML_DSA_WITNESS_KEY.sign(message)
    # GREASE: an unknown cosigner with arbitrary bytes, as long as an Ed25519 signature.
    return bytes(64)


def cosignature(cosigner_id: str, signature: bytes) -> bytes:
    binary = trust_anchor_id(cosigner_id)
    return bytes([len(binary)]) + binary + len(signature).to_bytes(2, "big") + signature


def sort_key(cosigner_id: str) -> Tuple[int, bytes]:
    binary = trust_anchor_id(cosigner_id)
    return len(binary), binary


def mtc_proof(subtree: Subtree, proof: bytes, cosignatures: List[bytes]) -> bytes:
    """MTCProof, MTC section 6.2."""
    signatures = b"".join(cosignatures)
    return b"".join(
        [
            b"\x00\x00",
            subtree[0].to_bytes(6, "big"),
            subtree[1].to_bytes(6, "big"),
            len(proof).to_bytes(2, "big"),
            proof,
            len(signatures).to_bytes(3, "big"),
            signatures,
        ]
    )


def mtc_cert(
    index: int,
    subtree: Subtree,
    cosigners: List[str],
    message_args: Optional[Dict[str, int]] = None,
    message_subtree: Optional[Subtree] = None,
    message_cosigner: Optional[str] = None,
    sort: bool = True,
) -> bytes:
    """An MTC certificate for log entry `index`, proven into `subtree`.

    The `message_*` arguments sign something other than the correct
    CosignedSubtree, and `sort=False` keeps `cosigners` in the given order.
    """
    subtree_hash = mth(*subtree)
    signed = message_subtree or subtree
    cosignatures = [
        cosignature(
            cosigner_id,
            sign(
                cosigner_id,
                cosigned_subtree(
                    message_cosigner or cosigner_id,
                    signed,
                    subtree_hash,
                    **(message_args or {}),
                ),
            ),
        )
        for cosigner_id in (sorted(cosigners, key=sort_key) if sort else cosigners)
    ]
    proof = mtc_proof(subtree, inclusion_proof(index, *subtree), cosignatures)
    return seq(ENTRIES[index].tbs(), alg_id(ID_ALG_MTC_PROOF), bit_string(proof))


def classic_cert(tbs: bytes, alg: str, signature: bytes) -> bytes:
    return seq(tbs, alg_id(alg), bit_string(signature))


def crl(revoked_serial: int) -> bytes:
    """A CRL issued by the MTC CA, signed by the CA cosigner key (MTC section 5.4)."""
    revoked = seq(seq(integer(revoked_serial), der(0x17, NOT_BEFORE)))
    crl_number = der(0xA0, seq(extension(ID_CRL_NUMBER, False, integer(1))))
    tbs = seq(
        integer(1),
        alg_id(ID_ED25519),
        CA_NAME,
        der(0x17, NOT_BEFORE),
        der(0x17, NOT_AFTER),
        revoked,
        crl_number,
    )
    return seq(tbs, alg_id(ID_ED25519), bit_string(CA_KEY.sign(tbs)))


def write(path: Path, content: bytes, force: bool) -> None:
    # Avoid churn from regenerating existing on-disk resources unless force is enabled.
    if path.exists() and not force:
        return
    path.write_bytes(content)


def main(force: bool) -> None:
    out = Path(__file__).parent
    all_cosigners = [CA_ID, ECDSA_WITNESS_ID, ML_DSA_WITNESS_ID, GREASE_ID]
    checkpoint_subtrees = find_subtrees(0, LOG_SIZE)
    landmark_subtrees = find_subtrees(0, 8)
    standalone_subtree = checkpoint_subtrees[1]
    assert standalone_subtree == (8, 13)
    landmark_subtree = landmark_subtrees[1]
    assert landmark_subtree == (4, 8)

    standalone = (STANDALONE_INDEX, standalone_subtree)
    fixtures = {
        "ca.der": mtc_ca_cert(),
        "ca-not-critical.der": mtc_ca_cert(critical=False),
        "ca-no-extension.der": mtc_ca_cert(critical=None),
        "ca-min-serial-too-small.der": mtc_ca_cert(min_serial=(1 << 48) - 1),
        "ca-min-serial-above-max.der": mtc_ca_cert(min_serial=MAX_SERIAL + 1),
        "ca-not-ca-id-name.der": mtc_ca_cert(name=common_name("mtc-ca")),
        "standalone.der": mtc_cert(*standalone, all_cosigners),
        "landmark.der": mtc_cert(LANDMARK_INDEX, landmark_subtree, []),
        "no-ca-cosignature.der": mtc_cert(
            *standalone, [ECDSA_WITNESS_ID, ML_DSA_WITNESS_ID]
        ),
        "duplicate-cosignature.der": mtc_cert(*standalone, [CA_ID, CA_ID], sort=False),
        "misordered-cosignatures.der": mtc_cert(
            *standalone, [ECDSA_WITNESS_ID, CA_ID], sort=False
        ),
        "wrong-log-origin.der": mtc_cert(
            *standalone, [CA_ID], message_args={"log_number": 2}
        ),
        "wrong-cosigner-name.der": mtc_cert(
            *standalone, [CA_ID], message_cosigner=ECDSA_WITNESS_ID
        ),
        "wrong-start.der": mtc_cert(*standalone, [CA_ID], message_subtree=(0, 13)),
        "wrong-end.der": mtc_cert(*standalone, [CA_ID], message_subtree=(8, 16)),
        "nonzero-timestamp.der": mtc_cert(
            *standalone, [CA_ID], message_args={"timestamp": 1}
        ),
        "below-min-serial.der": mtc_cert(0, checkpoint_subtrees[0], [CA_ID]),
        "above-max-serial.der": mtc_cert(LOG_SIZE - 1, standalone_subtree, [CA_ID]),
        "intermediate.der": mtc_cert(
            INTERMEDIATE_INDEX, checkpoint_subtrees[0], [CA_ID]
        ),
        "ca.crl.der": crl(ENTRIES[STANDALONE_INDEX].serial),
    }

    # A TBSCertificate signed directly by the CA cosigner key, which MTC section 5.4 forbids.
    classic_tbs = ENTRIES[STANDALONE_INDEX].tbs(ID_ED25519)
    fixtures["cosigner-signed.der"] = classic_cert(
        classic_tbs, ID_ED25519, CA_KEY.sign(classic_tbs)
    )

    # An end-entity certificate issued by the MTC-issued intermediate.
    ee_tbs = seq(
        VERSION_3,
        integer(2),
        alg_id(ID_ECDSA_SHA256),
        common_name("mtc-intermediate"),
        VALIDITY,
        common_name("mtc-leaf"),
        spki(EE_KEY),
    )
    fixtures["ee-under-intermediate.der"] = classic_cert(
        ee_tbs, ID_ECDSA_SHA256, EE_KEY.sign(ee_tbs, ECDSA)
    )

    for name, content in fixtures.items():
        write(out / name, content, force)

    manifest = {
        "validation_time": VALIDATION_TIME,
        "ca_id": trust_anchor_id(CA_ID).hex(),
        "log_number": LOG_NUMBER,
        "standalone_serial": ENTRIES[STANDALONE_INDEX].serial,
        "witnesses": [
            {
                "id": trust_anchor_id(ECDSA_WITNESS_ID).hex(),
                "spki": spki(ECDSA_WITNESS_KEY).hex(),
                "alg": "ECDSA_P256_SHA256",
            },
            {
                "id": trust_anchor_id(ML_DSA_WITNESS_ID).hex(),
                "spki": spki(ML_DSA_WITNESS_KEY).hex(),
                "alg": "ML_DSA_44",
            },
        ],
        "latest_landmark": 1,
        "trusted_subtrees": [
            {
                "log_number": LOG_NUMBER,
                "start": start,
                "end": end,
                "hash": mth(start, end).hex(),
            }
            for start, end in landmark_subtrees
        ],
    }
    write(
        out / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode(), force
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Overwrite existing test files",
    )
    args = parser.parse_args()
    main(args.force)
