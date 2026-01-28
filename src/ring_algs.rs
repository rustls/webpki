// Copyright 2015 Brian Smith.
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

use pki_types::SignatureVerificationAlgorithm;

use rustls_ring::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384, ED25519,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    RSA_PKCS1_3072_8192_SHA384, RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY, RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
};

#[cfg(test)]
#[path = "."]
mod tests {
    #[cfg(feature = "alloc")]
    use crate::error::UnsupportedSignatureAlgorithmForPublicKeyContext;
    use crate::error::{Error, UnsupportedSignatureAlgorithmContext};

    static SUPPORTED_ALGORITHMS_IN_TESTS: &[&dyn super::SignatureVerificationAlgorithm] = &[
        // Reasonable algorithms.
        super::ECDSA_P256_SHA256,
        super::ECDSA_P384_SHA384,
        super::ED25519,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_2048_8192_SHA256,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_2048_8192_SHA384,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_2048_8192_SHA512,
        #[cfg(feature = "alloc")]
        super::RSA_PKCS1_3072_8192_SHA384,
        #[cfg(feature = "alloc")]
        super::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        #[cfg(feature = "alloc")]
        super::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        #[cfg(feature = "alloc")]
        super::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        // Algorithms deprecated because they are nonsensical combinations.
        super::ECDSA_P256_SHA384, // Truncates digest.
        super::ECDSA_P384_SHA256, // Digest is unnecessarily short.
    ];

    const OK_IF_POINT_COMPRESSION_SUPPORTED: Result<(), Error> =
        Err(Error::InvalidSignatureForPublicKey);

    #[path = "alg_tests.rs"]
    mod alg_tests;

    fn maybe_rsa() -> Result<(), Error> {
        #[cfg(feature = "alloc")]
        {
            Ok(())
        }
        #[cfg(not(feature = "alloc"))]
        {
            Err(unsupported(&[]))
        }
    }

    fn unsupported_for_rsa(sig_alg_id: &[u8], _public_key_alg_id: &[u8]) -> Error {
        #[cfg(feature = "alloc")]
        {
            Error::UnsupportedSignatureAlgorithmForPublicKey(
                UnsupportedSignatureAlgorithmForPublicKeyContext {
                    signature_algorithm_id: sig_alg_id.to_vec(),
                    public_key_algorithm_id: _public_key_alg_id.to_vec(),
                },
            )
        }
        #[cfg(not(feature = "alloc"))]
        {
            unsupported(sig_alg_id)
        }
    }

    fn invalid_rsa_signature() -> Error {
        #[cfg(feature = "alloc")]
        {
            Error::InvalidSignatureForPublicKey
        }
        #[cfg(not(feature = "alloc"))]
        {
            unsupported(&[])
        }
    }

    fn unsupported_for_ecdsa(sig_alg_id: &[u8], _public_key_alg_id: &[u8]) -> Error {
        unsupported(sig_alg_id)
    }

    fn unsupported(_sig_alg_id: &[u8]) -> Error {
        Error::UnsupportedSignatureAlgorithm(UnsupportedSignatureAlgorithmContext {
            #[cfg(feature = "alloc")]
            signature_algorithm_id: _sig_alg_id.to_vec(),
            #[cfg(feature = "alloc")]
            supported_algorithms: SUPPORTED_ALGORITHMS_IN_TESTS
                .iter()
                .map(|&alg| alg.signature_alg_id())
                .collect(),
        })
    }
}
