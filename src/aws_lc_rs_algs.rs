use pki_types::SignatureVerificationAlgorithm;
use rustls_aws_lc_rs::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384, ECDSA_P521_SHA256,
    ECDSA_P521_SHA384, ECDSA_P521_SHA512, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS, RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS, RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
};

#[cfg(test)]
#[path = "."]
mod tests {
    use crate::error::{
        Error, UnsupportedSignatureAlgorithmContext,
        UnsupportedSignatureAlgorithmForPublicKeyContext,
    };

    static SUPPORTED_ALGORITHMS_IN_TESTS: &[&dyn super::SignatureVerificationAlgorithm] = &[
        // Reasonable algorithms.
        super::ECDSA_P256_SHA256,
        super::ECDSA_P384_SHA384,
        super::ECDSA_P521_SHA256,
        super::ECDSA_P521_SHA384,
        super::ECDSA_P521_SHA512,
        super::ED25519,
        super::RSA_PKCS1_2048_8192_SHA256,
        super::RSA_PKCS1_2048_8192_SHA384,
        super::RSA_PKCS1_2048_8192_SHA512,
        super::RSA_PKCS1_3072_8192_SHA384,
        super::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        super::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        super::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        // Algorithms deprecated because they are nonsensical combinations.
        super::ECDSA_P256_SHA384, // Truncates digest.
        super::ECDSA_P384_SHA256, // Digest is unnecessarily short.
    ];

    const OK_IF_POINT_COMPRESSION_SUPPORTED: Result<(), Error> = Ok(());

    #[path = "alg_tests.rs"]
    mod alg_tests;

    fn maybe_rsa() -> Result<(), Error> {
        Ok(())
    }

    fn unsupported_for_rsa(_sig_alg_id: &[u8], _public_key_alg_id: &[u8]) -> Error {
        Error::UnsupportedSignatureAlgorithmForPublicKey(
            UnsupportedSignatureAlgorithmForPublicKeyContext {
                #[cfg(feature = "alloc")]
                signature_algorithm_id: _sig_alg_id.to_vec(),
                #[cfg(feature = "alloc")]
                public_key_algorithm_id: _public_key_alg_id.to_vec(),
            },
        )
    }

    fn invalid_rsa_signature() -> Error {
        Error::InvalidSignatureForPublicKey
    }

    fn unsupported_for_ecdsa(_sig_alg_id: &[u8], _public_key_alg_id: &[u8]) -> Error {
        Error::UnsupportedSignatureAlgorithmForPublicKey(
            UnsupportedSignatureAlgorithmForPublicKeyContext {
                #[cfg(feature = "alloc")]
                signature_algorithm_id: _sig_alg_id.to_vec(),
                #[cfg(feature = "alloc")]
                public_key_algorithm_id: _public_key_alg_id.to_vec(),
            },
        )
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
