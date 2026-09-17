// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Detached public-signature verification for Xenia consumers.
//!
//! This module deliberately owns only cryptographic verification. It does not
//! decide who is authorized, which key is trusted, what a signature means, or
//! whether an application action may proceed. Callers must supply already-
//! selected public key bytes, a signature, and the exact message to verify.
//!
//! Hybrid verification is strict AND-composition: both Ed25519 and ML-DSA-87
//! must verify over the identical message. There is no classical-only or
//! post-quantum-only fallback.

use ed25519_dalek::{
    Signature as Ed25519Signature, Verifier as Ed25519VerifierTrait,
    VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature,
    EncodedVerifyingKey as MlDsaEncodedVerifyingKey, MlDsa87,
    Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    signature::Verifier as MlDsaVerifierTrait,
};

/// Ed25519 public-key size in bytes.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature size in bytes.
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// FIPS 204 ML-DSA-87 public verification-key size in bytes.
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;
/// FIPS 204 ML-DSA-87 signature size in bytes.
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;
/// Concatenated Ed25519 || ML-DSA-87 public-key size in bytes.
pub const HYBRID_PUBLIC_KEY_BYTES: usize = ED25519_PUBLIC_KEY_BYTES + ML_DSA_87_PUBLIC_KEY_BYTES;
/// Concatenated Ed25519 || ML-DSA-87 signature size in bytes.
pub const HYBRID_SIGNATURE_BYTES: usize = ED25519_SIGNATURE_BYTES + ML_DSA_87_SIGNATURE_BYTES;

/// Detached signature suite selected by the caller's already-authenticated
/// policy layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachedSignatureScheme {
    /// RFC 8032 Ed25519.
    Ed25519,
    /// FIPS 204 ML-DSA-87.
    MlDsa87,
    /// Strict Ed25519 AND ML-DSA-87 verification over the same message.
    HybridEd25519MlDsa87,
}

/// Failure returned by detached verification.
///
/// The taxonomy intentionally stays coarse. Applications should normally map
/// any failure to one authorization failure rather than expose parsing details
/// to an untrusted peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DetachedSignatureError {
    /// Public key length does not match the selected suite exactly.
    #[error("detached signature public-key length mismatch: expected {expected}, got {actual}")]
    PublicKeyLength {
        /// Exact size required by the selected suite.
        expected: usize,
        /// Size supplied by the caller.
        actual: usize,
    },
    /// Signature length does not match the selected suite exactly.
    #[error("detached signature length mismatch: expected {expected}, got {actual}")]
    SignatureLength {
        /// Exact size required by the selected suite.
        expected: usize,
        /// Size supplied by the caller.
        actual: usize,
    },
    /// Public verification-key bytes are not a valid encoding.
    #[error("detached signature public key is invalid")]
    InvalidPublicKey,
    /// Signature bytes are not a valid encoding.
    #[error("detached signature encoding is invalid")]
    InvalidSignatureEncoding,
    /// Cryptographic verification failed.
    #[error("detached signature verification failed")]
    VerificationFailed,
}

/// Verify one detached signature with exact-length, fail-closed parsing.
///
/// For [`DetachedSignatureScheme::HybridEd25519MlDsa87`], `public_key` must be
/// `Ed25519 public key || ML-DSA-87 public key` and `signature` must be
/// `Ed25519 signature || ML-DSA-87 signature`. Both signatures must verify over
/// `message`; success from only one component is a failure.
pub fn verify_detached_signature(
    scheme: DetachedSignatureScheme,
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), DetachedSignatureError> {
    match scheme {
        DetachedSignatureScheme::Ed25519 => verify_ed25519(public_key, signature, message),
        DetachedSignatureScheme::MlDsa87 => verify_ml_dsa_87(public_key, signature, message),
        DetachedSignatureScheme::HybridEd25519MlDsa87 => {
            require_len(public_key, HYBRID_PUBLIC_KEY_BYTES, true)?;
            require_len(signature, HYBRID_SIGNATURE_BYTES, false)?;

            let (ed_pk, ml_pk) = public_key.split_at(ED25519_PUBLIC_KEY_BYTES);
            let (ed_sig, ml_sig) = signature.split_at(ED25519_SIGNATURE_BYTES);

            verify_ed25519(ed_pk, ed_sig, message)?;
            verify_ml_dsa_87(ml_pk, ml_sig, message)
        }
    }
}

fn require_len(
    bytes: &[u8],
    expected: usize,
    public_key: bool,
) -> Result<(), DetachedSignatureError> {
    if bytes.len() == expected {
        return Ok(());
    }
    if public_key {
        Err(DetachedSignatureError::PublicKeyLength {
            expected,
            actual: bytes.len(),
        })
    } else {
        Err(DetachedSignatureError::SignatureLength {
            expected,
            actual: bytes.len(),
        })
    }
}

fn verify_ed25519(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), DetachedSignatureError> {
    require_len(public_key, ED25519_PUBLIC_KEY_BYTES, true)?;
    require_len(signature, ED25519_SIGNATURE_BYTES, false)?;

    let pk: &[u8; ED25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| DetachedSignatureError::InvalidPublicKey)?;
    let sig_bytes: &[u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| DetachedSignatureError::InvalidSignatureEncoding)?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(pk)
        .map_err(|_| DetachedSignatureError::InvalidPublicKey)?;
    let signature = Ed25519Signature::from_bytes(sig_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| DetachedSignatureError::VerificationFailed)
}

fn verify_ml_dsa_87(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), DetachedSignatureError> {
    require_len(public_key, ML_DSA_87_PUBLIC_KEY_BYTES, true)?;
    require_len(signature, ML_DSA_87_SIGNATURE_BYTES, false)?;

    let encoded_key = MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|_| DetachedSignatureError::InvalidPublicKey)?;
    let verifying_key = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded_key);
    let encoded_signature = MlDsaEncodedSignature::<MlDsa87>::try_from(signature)
        .map_err(|_| DetachedSignatureError::InvalidSignatureEncoding)?;
    let signature = MlDsaSignature::<MlDsa87>::decode(&encoded_signature)
        .ok_or(DetachedSignatureError::InvalidSignatureEncoding)?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| DetachedSignatureError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as Ed25519SignerTrait, SigningKey as Ed25519SigningKey};
    use ml_dsa::{
        Generate as MlDsaGenerate, Signature as MlDsaSignature,
        SigningKey as MlDsaSigningKey,
        signature::{Keypair as MlDsaKeypair, Signer as MlDsaSignerTrait},
    };
    use rand::rngs::OsRng;

    const MESSAGE: &[u8] = b"xenia detached signature conformance v1";

    fn ed25519_fixture() -> (Vec<u8>, Vec<u8>) {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let signature = signing_key.sign(MESSAGE).to_bytes().to_vec();
        (public_key, signature)
    }

    fn ml_dsa_87_fixture() -> (Vec<u8>, Vec<u8>) {
        let signing_key = MlDsaSigningKey::<MlDsa87>::generate();
        let public_key = signing_key.verifying_key().encode().as_slice().to_vec();
        let signature: MlDsaSignature<MlDsa87> = signing_key.sign(MESSAGE);
        let signature = signature.encode().as_slice().to_vec();
        (public_key, signature)
    }

    #[test]
    fn ed25519_exact_signature_verifies() {
        let (public_key, signature) = ed25519_fixture();
        assert_eq!(
            verify_detached_signature(
                DetachedSignatureScheme::Ed25519,
                &public_key,
                &signature,
                MESSAGE,
            ),
            Ok(())
        );
    }

    #[test]
    fn ml_dsa_87_exact_signature_verifies() {
        let (public_key, signature) = ml_dsa_87_fixture();
        assert_eq!(
            verify_detached_signature(
                DetachedSignatureScheme::MlDsa87,
                &public_key,
                &signature,
                MESSAGE,
            ),
            Ok(())
        );
    }

    #[test]
    fn hybrid_requires_both_components() {
        let (ed_pk, ed_sig) = ed25519_fixture();
        let (ml_pk, ml_sig) = ml_dsa_87_fixture();
        let mut public_key = ed_pk;
        public_key.extend_from_slice(&ml_pk);
        let mut signature = ed_sig;
        signature.extend_from_slice(&ml_sig);

        assert_eq!(
            verify_detached_signature(
                DetachedSignatureScheme::HybridEd25519MlDsa87,
                &public_key,
                &signature,
                MESSAGE,
            ),
            Ok(())
        );

        signature[ED25519_SIGNATURE_BYTES] ^= 0x01;
        assert_eq!(
            verify_detached_signature(
                DetachedSignatureScheme::HybridEd25519MlDsa87,
                &public_key,
                &signature,
                MESSAGE,
            ),
            Err(DetachedSignatureError::VerificationFailed)
        );
    }

    #[test]
    fn hybrid_rejects_truncated_material_without_fallback() {
        let (ed_pk, ed_sig) = ed25519_fixture();
        assert_eq!(
            verify_detached_signature(
                DetachedSignatureScheme::HybridEd25519MlDsa87,
                &ed_pk,
                &ed_sig,
                MESSAGE,
            ),
            Err(DetachedSignatureError::PublicKeyLength {
                expected: HYBRID_PUBLIC_KEY_BYTES,
                actual: ED25519_PUBLIC_KEY_BYTES,
            })
        );
    }

    #[test]
    fn message_mutation_fails() {
        let (public_key, signature) = ml_dsa_87_fixture();
        assert_eq!(
            verify_detached_signature(
                DetachedSignatureScheme::MlDsa87,
                &public_key,
                &signature,
                b"different message",
            ),
            Err(DetachedSignatureError::VerificationFailed)
        );
    }
}