// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error taxonomy for the Xenia wire.
//!
//! All fallible operations return [`WireError`]. The variants are coarse on
//! purpose: a deployed receiver should react the same way to any failure
//! (drop the envelope, keep the session alive) without leaking the specific
//! reason to an attacker. Finer-grained diagnosis is available in debug
//! builds via the inner error strings.

use thiserror::Error;

/// Errors returned by the wire codec.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WireError {
    /// Bincode encode or decode failure. Wraps the inner reason for logs.
    #[error("xenia wire codec: {0}")]
    Codec(String),

    /// Session has no current or previous key. The caller must install a key
    /// via [`crate::Session::install_key`] before sealing or opening.
    #[error("xenia wire: session key not established")]
    NoSessionKey,

    /// AEAD seal failed. In practice this means the key material was
    /// rejected by the underlying ChaCha20-Poly1305 implementation — should
    /// not happen with a valid 32-byte key and under-capacity plaintext.
    #[error("xenia wire: AEAD seal failed")]
    SealFailed,

    /// AEAD open failed. Either:
    /// - the envelope is under the minimum length (12 nonce + 16 tag),
    /// - the ciphertext fails Poly1305 verification (wrong key, corruption,
    ///   or tampering), or
    /// - the replay window rejected a valid-ciphertext envelope as a
    ///   duplicate or too-old sequence.
    ///
    /// Callers SHOULD NOT distinguish these sub-cases in production — doing
    /// so leaks timing or structure to an attacker. Drop the envelope and
    /// keep the session alive.
    #[error("xenia wire: AEAD open failed")]
    OpenFailed,

    /// The 32-bit nonce sequence space is exhausted. The caller must
    /// rekey before sealing more envelopes; continuing would wrap the
    /// sequence counter and cause nonce reuse, which catastrophically
    /// breaks ChaCha20-Poly1305 confidentiality and integrity.
    ///
    /// Reached after `2^32` seals on a single installed key — approximately
    /// 4.5 years at 30 fps, or ~40 hours at 30 kHz. Any production deployment
    /// should rekey on a much shorter cadence (the reference default is 30
    /// minutes), so this variant surfaces a programming error: the caller
    /// disabled or failed to trigger rekey.
    #[error("xenia wire: sequence space exhausted — rekey required")]
    SequenceExhausted,

    /// Seal or open of an application `FRAME` (or `FRAME_LZ4`) payload
    /// was attempted on a session whose consent state is not `Approved`.
    /// The peer must complete the consent ceremony — seal a
    /// `ConsentRequest`, receive an approving `ConsentResponse` — before
    /// application data can flow.
    ///
    /// Only surfaced when the `consent` feature is enabled. Sessions
    /// compiled without the feature behave as draft-01 (no enforcement).
    #[cfg(feature = "consent")]
    #[error("xenia wire: consent ceremony not completed — FRAME refused")]
    NoConsent,

    /// Seal or open of an application `FRAME` (or `FRAME_LZ4`) payload
    /// was attempted on a session that entered the `Revoked` terminal
    /// state. The session is finished; the caller must tear it down
    /// and — if appropriate — start a new one with a new consent
    /// ceremony.
    #[cfg(feature = "consent")]
    #[error("xenia wire: consent revoked — session terminated")]
    ConsentRevoked,
}

impl WireError {
    /// Construct a `Codec(...)` from any `Display` encode error. Primarily
    /// used by `Sealable::to_bin` implementations.
    pub fn encode<E: core::fmt::Display>(e: E) -> Self {
        Self::Codec(format!("encode: {e}"))
    }

    /// Construct a `Codec(...)` from any `Display` decode error. Primarily
    /// used by `Sealable::from_bin` implementations.
    pub fn decode<E: core::fmt::Display>(e: E) -> Self {
        Self::Codec(format!("decode: {e}"))
    }
}
