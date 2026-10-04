// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Generic exact-evidence attestations.
//!
//! This module authenticates one exact 32-byte subject digest under one exact
//! 32-byte context digest and replay nonce. It deliberately does not decide
//! whether the signer is trusted, whether a key or credential is revoked, or
//! whether the attested claim is scientifically or legally valid.
//!
//! Signatures cover a manual canonical byte protocol rather than a Serde or
//! bincode representation. Schema version, signature profile, validity window,
//! signer key identity, replay nonce and optional causal binding are all signed.
//! Restoring an attestation from bytes recovers data, not verification authority:
//! consumers must call [`Ed25519EvidenceAttestation::verify_signature`],
//! [`Ed25519EvidenceAttestation::verify_binding`] and, when relevant,
//! [`EvidenceAttestationCore::check_time`] against their own explicit policy.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Schema version of the canonical evidence-attestation core.
pub const EVIDENCE_ATTESTATION_SCHEMA_VERSION: u16 = 1;

/// Signature profile identifier for Ed25519 attestations.
pub const SIGNATURE_PROFILE_ED25519: u16 = 1;

/// Byte length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Byte length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

const ATTESTATION_DOMAIN: &[u8] = b"xenia.evidence-attestation.v1\0";
const KEY_ID_DOMAIN: &[u8] = b"xenia.evidence-attestation.key-id.v1\0";

/// Exact signed semantic core shared by evidence-attestation signature profiles.
///
/// `subject_digest` and `context_digest` are deliberately opaque 32-byte values.
/// The calling protocol owns their hash algorithm and semantic preimage. Xenia
/// signs them exactly; it does not reinterpret their domain meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceAttestationCore {
    schema_version: u16,
    subject_digest: [u8; 32],
    context_digest: [u8; 32],
    signature_profile: u16,
    signer_key_id: [u8; 32],
    issued_at: u64,
    valid_until: u64,
    nonce: [u8; 32],
    causal_binding: Option<[u8; 32]>,
}

impl EvidenceAttestationCore {
    /// Construct an exact attestation core.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_digest: [u8; 32],
        context_digest: [u8; 32],
        signature_profile: u16,
        signer_key_id: [u8; 32],
        issued_at: u64,
        valid_until: u64,
        nonce: [u8; 32],
        causal_binding: Option<[u8; 32]>,
    ) -> Result<Self, AttestationError> {
        let core = Self {
            schema_version: EVIDENCE_ATTESTATION_SCHEMA_VERSION,
            subject_digest,
            context_digest,
            signature_profile,
            signer_key_id,
            issued_at,
            valid_until,
            nonce,
            causal_binding,
        };
        core.validate()?;
        Ok(core)
    }

    /// Return the exact subject digest signed by this attestation.
    pub const fn subject_digest(&self) -> &[u8; 32] {
        &self.subject_digest
    }

    /// Return the exact context/domain digest signed by this attestation.
    pub const fn context_digest(&self) -> &[u8; 32] {
        &self.context_digest
    }

    /// Return the signed signature-profile identifier.
    pub const fn signature_profile(&self) -> u16 {
        self.signature_profile
    }

    /// Return the signed signer-key identity.
    pub const fn signer_key_id(&self) -> &[u8; 32] {
        &self.signer_key_id
    }

    /// Return the explicit signed issuance time as Unix epoch seconds.
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Return the explicit signed expiry time as Unix epoch seconds.
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Return the exact replay/ceremony nonce signed by this attestation.
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Return the optional exact causal binding digest.
    pub const fn causal_binding(&self) -> Option<&[u8; 32]> {
        self.causal_binding.as_ref()
    }

    /// Validate schema-level invariants without claiming signature authority.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema_version != EVIDENCE_ATTESTATION_SCHEMA_VERSION {
            return Err(AttestationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.signature_profile == 0 {
            return Err(AttestationError::InvalidSignatureProfile(0));
        }
        if self.valid_until <= self.issued_at {
            return Err(AttestationError::InvalidValidityWindow {
                issued_at: self.issued_at,
                valid_until: self.valid_until,
            });
        }
        if self.nonce == [0; 32] {
            return Err(AttestationError::ZeroNonce);
        }
        Ok(())
    }

    /// Return the normative bytes covered by the signature.
    ///
    /// The encoding is independent of Serde/bincode implementation details:
    /// domain tag, little-endian fixed-width integers, fixed-size byte fields,
    /// and a one-byte optional-field tag.
    pub fn canonical_preimage(&self) -> Result<Vec<u8>, AttestationError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(211);
        bytes.extend_from_slice(ATTESTATION_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        bytes.extend_from_slice(&self.subject_digest);
        bytes.extend_from_slice(&self.context_digest);
        bytes.extend_from_slice(&self.signature_profile.to_le_bytes());
        bytes.extend_from_slice(&self.signer_key_id);
        bytes.extend_from_slice(&self.issued_at.to_le_bytes());
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        match self.causal_binding {
            None => bytes.push(0),
            Some(binding) => {
                bytes.push(1);
                bytes.extend_from_slice(&binding);
            }
        }
        Ok(bytes)
    }

    /// Return SHA-256 of the canonical signed preimage.
    ///
    /// This is an identity/debugging helper. The Ed25519 signature is over the
    /// canonical preimage itself, not over this digest.
    pub fn canonical_preimage_sha256(&self) -> Result<[u8; 32], AttestationError> {
        Ok(Sha256::digest(self.canonical_preimage()?).into())
    }

    /// Check explicit time validity with caller-selected clock skew.
    ///
    /// This function never reads the system clock. Trust policy must supply the
    /// evaluation time and acceptable skew explicitly.
    pub fn check_time(&self, now: u64, allowed_clock_skew_secs: u64) -> Result<(), AttestationError> {
        self.validate()?;
        let earliest = self.issued_at.saturating_sub(allowed_clock_skew_secs);
        let latest = self.valid_until.saturating_add(allowed_clock_skew_secs);
        if now < earliest {
            return Err(AttestationError::NotYetValid {
                issued_at: self.issued_at,
                now,
            });
        }
        if now > latest {
            return Err(AttestationError::Expired {
                valid_until: self.valid_until,
                now,
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct EvidenceAttestationCoreWire {
    schema_version: u16,
    subject_digest: [u8; 32],
    context_digest: [u8; 32],
    signature_profile: u16,
    signer_key_id: [u8; 32],
    issued_at: u64,
    valid_until: u64,
    nonce: [u8; 32],
    causal_binding: Option<[u8; 32]>,
}

impl<'de> Deserialize<'de> for EvidenceAttestationCore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EvidenceAttestationCoreWire::deserialize(deserializer)?;
        let core = Self {
            schema_version: wire.schema_version,
            subject_digest: wire.subject_digest,
            context_digest: wire.context_digest,
            signature_profile: wire.signature_profile,
            signer_key_id: wire.signer_key_id,
            issued_at: wire.issued_at,
            valid_until: wire.valid_until,
            nonce: wire.nonce,
            causal_binding: wire.causal_binding,
        };
        core.validate().map_err(serde::de::Error::custom)?;
        Ok(core)
    }
}

/// Ed25519-signed exact evidence attestation.
///
/// Deserialization validates only structural invariants. It does not authenticate
/// the signature. Call [`Self::verify_signature`] after restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519EvidenceAttestation {
    core: EvidenceAttestationCore,
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    #[serde(with = "BigArray")]
    signature: [u8; ED25519_SIGNATURE_LEN],
}

impl Ed25519EvidenceAttestation {
    /// Construct and sign a new Ed25519 evidence attestation.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        subject_digest: [u8; 32],
        context_digest: [u8; 32],
        issued_at: u64,
        valid_until: u64,
        nonce: [u8; 32],
        causal_binding: Option<[u8; 32]>,
        signing_key: &SigningKey,
    ) -> Result<Self, AttestationError> {
        let public_key = signing_key.verifying_key().to_bytes();
        let signer_key_id = derive_signer_key_id(SIGNATURE_PROFILE_ED25519, &public_key);
        let core = EvidenceAttestationCore::new(
            subject_digest,
            context_digest,
            SIGNATURE_PROFILE_ED25519,
            signer_key_id,
            issued_at,
            valid_until,
            nonce,
            causal_binding,
        )?;
        let signature = signing_key.sign(&core.canonical_preimage()?).to_bytes();
        Ok(Self {
            core,
            public_key,
            signature,
        })
    }

    /// Return the exact signed semantic core.
    pub const fn core(&self) -> &EvidenceAttestationCore {
        &self.core
    }

    /// Return the embedded raw Ed25519 public key.
    pub const fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Return the raw Ed25519 signature bytes.
    pub const fn signature(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.signature
    }

    /// Verify the Ed25519 signature and key identity.
    ///
    /// If `expected_key_id` is supplied, the signed key identity must also match
    /// it exactly. This method deliberately does not check time, revocation,
    /// delegation or trust roots.
    pub fn verify_signature(
        &self,
        expected_key_id: Option<&[u8; 32]>,
    ) -> Result<(), AttestationError> {
        self.core.validate()?;
        if self.core.signature_profile != SIGNATURE_PROFILE_ED25519 {
            return Err(AttestationError::InvalidSignatureProfile(
                self.core.signature_profile,
            ));
        }
        let actual_key_id = derive_signer_key_id(SIGNATURE_PROFILE_ED25519, &self.public_key);
        if actual_key_id != self.core.signer_key_id {
            return Err(AttestationError::SignerKeyIdMismatch);
        }
        if expected_key_id.is_some_and(|expected| expected != &actual_key_id) {
            return Err(AttestationError::UnexpectedSignerKey);
        }
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| AttestationError::InvalidPublicKey)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| AttestationError::InvalidSignatureEncoding)?;
        verifying_key
            .verify(&self.core.canonical_preimage()?, &signature)
            .map_err(|_| AttestationError::InvalidSignature)
    }

    /// Verify exact subject, context, nonce and optional causal binding.
    ///
    /// This is separate from signature verification so consumers cannot confuse
    /// “cryptographically signed” with “signed for the subject I intended.”
    pub fn verify_binding(
        &self,
        expected_subject_digest: &[u8; 32],
        expected_context_digest: &[u8; 32],
        expected_nonce: &[u8; 32],
        expected_causal_binding: Option<&[u8; 32]>,
    ) -> Result<(), AttestationError> {
        if self.core.subject_digest != *expected_subject_digest {
            return Err(AttestationError::SubjectMismatch);
        }
        if self.core.context_digest != *expected_context_digest {
            return Err(AttestationError::ContextMismatch);
        }
        if self.core.nonce != *expected_nonce {
            return Err(AttestationError::NonceMismatch);
        }
        if self.core.causal_binding.as_ref() != expected_causal_binding {
            return Err(AttestationError::CausalBindingMismatch);
        }
        Ok(())
    }
}

/// Derive a stable 32-byte signer-key identity from a signature profile and key.
pub fn derive_signer_key_id(signature_profile: u16, public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(signature_profile.to_le_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

/// Failure while constructing or explicitly verifying an evidence attestation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The serialized core used an unsupported schema version.
    #[error("unsupported evidence-attestation schema version {0}")]
    UnsupportedSchemaVersion(u16),
    /// The signature profile is invalid or unsupported by this verifier.
    #[error("invalid or unsupported signature profile {0}")]
    InvalidSignatureProfile(u16),
    /// The signed validity window is empty or reversed.
    #[error("invalid validity window: issued_at={issued_at}, valid_until={valid_until}")]
    InvalidValidityWindow {
        /// Signed issuance time.
        issued_at: u64,
        /// Signed expiry time.
        valid_until: u64,
    },
    /// The replay/ceremony nonce was all zeros.
    #[error("evidence-attestation nonce must be non-zero")]
    ZeroNonce,
    /// The evaluation time is earlier than the allowed issuance boundary.
    #[error("attestation is not yet valid: issued_at={issued_at}, now={now}")]
    NotYetValid {
        /// Signed issuance time.
        issued_at: u64,
        /// Caller-supplied evaluation time.
        now: u64,
    },
    /// The evaluation time is later than the allowed expiry boundary.
    #[error("attestation expired: valid_until={valid_until}, now={now}")]
    Expired {
        /// Signed expiry time.
        valid_until: u64,
        /// Caller-supplied evaluation time.
        now: u64,
    },
    /// The embedded public key does not derive the signed signer key identity.
    #[error("embedded public key does not match signed signer-key identity")]
    SignerKeyIdMismatch,
    /// The caller required a different signer key identity.
    #[error("attestation signer key does not match expected key identity")]
    UnexpectedSignerKey,
    /// The embedded Ed25519 public key is malformed.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// The Ed25519 signature bytes have an invalid encoding.
    #[error("invalid Ed25519 signature encoding")]
    InvalidSignatureEncoding,
    /// Ed25519 signature verification failed.
    #[error("invalid Ed25519 evidence-attestation signature")]
    InvalidSignature,
    /// The signed subject does not match the caller's expected subject.
    #[error("attestation subject digest mismatch")]
    SubjectMismatch,
    /// The signed context does not match the caller's expected context.
    #[error("attestation context digest mismatch")]
    ContextMismatch,
    /// The signed replay nonce does not match the caller's expected nonce.
    #[error("attestation nonce mismatch")]
    NonceMismatch,
    /// The optional signed causal binding differs from the caller's expectation.
    #[error("attestation causal binding mismatch")]
    CausalBindingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn attestation() -> Ed25519EvidenceAttestation {
        Ed25519EvidenceAttestation::sign(
            [0x11; 32],
            [0x22; 32],
            1_700_000_000,
            1_700_003_600,
            [0x33; 32],
            Some([0x44; 32]),
            &signing_key(),
        )
        .unwrap()
    }

    #[test]
    fn deterministic_profile_has_frozen_key_and_preimage_vectors() {
        let signed = attestation();
        assert_eq!(
            signed.public_key(),
            &hex32("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
        );
        assert_eq!(
            signed.core().signer_key_id(),
            &hex32("07dd40bed193b1146a3b0ae78d12efcda79542e6c5625cb12420ba3954a8b03e")
        );
        assert_eq!(
            signed.core().canonical_preimage_sha256().unwrap(),
            hex32("b435e9b459020a9689fa60743bbc665cf8ba153887eb33e5bb8cd18750dc0be3")
        );
        assert_eq!(
            signed.signature(),
            &hex64("34ceba6cd1dab8376350e095fbdeb9a2cb385483ea8593d1e2d1fa7a2d3c2569945ecc9910bdac55d697cb7366fa7c08a03364900b4f06a2e011a5b5cfc5090e")
        );
    }

    #[test]
    fn signed_attestation_verifies_exact_binding_and_time() {
        let signed = attestation();
        signed
            .verify_signature(Some(signed.core().signer_key_id()))
            .unwrap();
        signed
            .verify_binding(
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 32],
                Some(&[0x44; 32]),
            )
            .unwrap();
        signed.core().check_time(1_700_001_800, 0).unwrap();
    }

    #[test]
    fn serde_round_trip_does_not_change_signed_identity() {
        let signed = attestation();
        let bytes = serde_json::to_vec(&signed).unwrap();
        let restored: Ed25519EvidenceAttestation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored, signed);
        restored.verify_signature(None).unwrap();
    }

    #[test]
    fn changed_subject_context_nonce_or_causal_binding_is_rejected() {
        let signed = attestation();
        assert_eq!(
            signed.verify_binding(&[9; 32], &[0x22; 32], &[0x33; 32], Some(&[0x44; 32])),
            Err(AttestationError::SubjectMismatch)
        );
        assert_eq!(
            signed.verify_binding(&[0x11; 32], &[9; 32], &[0x33; 32], Some(&[0x44; 32])),
            Err(AttestationError::ContextMismatch)
        );
        assert_eq!(
            signed.verify_binding(&[0x11; 32], &[0x22; 32], &[9; 32], Some(&[0x44; 32])),
            Err(AttestationError::NonceMismatch)
        );
        assert_eq!(
            signed.verify_binding(&[0x11; 32], &[0x22; 32], &[0x33; 32], None),
            Err(AttestationError::CausalBindingMismatch)
        );
    }

    #[test]
    fn another_expected_key_is_rejected_even_when_signature_is_valid() {
        let signed = attestation();
        let other = derive_signer_key_id(SIGNATURE_PROFILE_ED25519, &[8; 32]);
        assert_eq!(
            signed.verify_signature(Some(&other)),
            Err(AttestationError::UnexpectedSignerKey)
        );
    }

    #[test]
    fn modified_signature_or_public_key_fails_closed() {
        let mut changed_signature = attestation();
        changed_signature.signature[0] ^= 1;
        assert_eq!(
            changed_signature.verify_signature(None),
            Err(AttestationError::InvalidSignature)
        );

        let mut changed_key = attestation();
        changed_key.public_key[0] ^= 1;
        assert_eq!(
            changed_key.verify_signature(None),
            Err(AttestationError::SignerKeyIdMismatch)
        );
    }

    #[test]
    fn explicit_time_policy_rejects_early_and_expired_attestations() {
        let signed = attestation();
        assert!(matches!(
            signed.core().check_time(1_699_999_999, 0),
            Err(AttestationError::NotYetValid { .. })
        ));
        assert!(matches!(
            signed.core().check_time(1_700_003_601, 0),
            Err(AttestationError::Expired { .. })
        ));
        signed.core().check_time(1_699_999_999, 1).unwrap();
        signed.core().check_time(1_700_003_601, 1).unwrap();
    }

    #[test]
    fn invalid_window_and_zero_nonce_fail_at_construction() {
        let key_id = derive_signer_key_id(SIGNATURE_PROFILE_ED25519, &[7; 32]);
        assert!(matches!(
            EvidenceAttestationCore::new(
                [1; 32], [2; 32], SIGNATURE_PROFILE_ED25519, key_id, 5, 5, [3; 32], None,
            ),
            Err(AttestationError::InvalidValidityWindow { .. })
        ));
        assert_eq!(
            EvidenceAttestationCore::new(
                [1; 32], [2; 32], SIGNATURE_PROFILE_ED25519, key_id, 5, 6, [0; 32], None,
            ),
            Err(AttestationError::ZeroNonce)
        );
    }

    fn hex32(value: &str) -> [u8; 32] {
        let bytes = decode_hex(value);
        bytes.try_into().unwrap()
    }

    fn hex64(value: &str) -> [u8; 64] {
        let bytes = decode_hex(value);
        bytes.try_into().unwrap()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }
}
