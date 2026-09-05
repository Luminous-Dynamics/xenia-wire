// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Additive strict receive helpers for binding an envelope to its expected
//! cleartext nonce domain before AEAD open mutates replay state.
//!
//! Draft-03 places the sender source prefix, payload type, and session epoch in
//! cleartext nonce bytes 0..8. Those bytes are subsequently authenticated by
//! ChaCha20-Poly1305, but the base [`crate::Session::open`] API intentionally
//! accepts any authenticated nonce domain held by a peer with the traffic key.
//!
//! Higher-level profiles that already know which sender/stream/epoch is legal
//! can use [`open_from_nonce_domain`] to reject a domain mismatch *before*
//! replay-window state is touched. This is an additive policy helper; it changes
//! no wire bytes and does not make the cleartext precheck itself cryptographic.

use crate::{Sealable, Session, WireError};

/// Number of `source_id` bytes carried in the draft-03 AEAD nonce.
pub const NONCE_SOURCE_PREFIX_LEN: usize = 6;

const NONCE_LEN: usize = 12;

/// Authenticated sender/stream domain carried in cleartext nonce bytes 0..8.
///
/// The remaining four nonce bytes are the per-key sequence number and therefore
/// are intentionally not part of this expected-domain identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceDomain {
    /// First six bytes of the sender's `source_id`.
    pub source_prefix: [u8; NONCE_SOURCE_PREFIX_LEN],
    /// Exact payload/stream type expected on this receive path.
    pub payload_type: u8,
    /// Sender's session epoch byte.
    pub epoch: u8,
}

impl NonceDomain {
    /// Construct an expected nonce domain from an already-extracted six-byte
    /// sender prefix.
    pub const fn new(
        source_prefix: [u8; NONCE_SOURCE_PREFIX_LEN],
        payload_type: u8,
        epoch: u8,
    ) -> Self {
        Self {
            source_prefix,
            payload_type,
            epoch,
        }
    }

    /// Construct a nonce domain from Xenia's full eight-byte `source_id`.
    ///
    /// Only the first six bytes are authenticated in the draft-03 nonce. The
    /// trailing two routing bytes are therefore deliberately discarded here
    /// rather than accidentally implying they are part of this security check.
    pub const fn from_source_id(source_id: [u8; 8], payload_type: u8, epoch: u8) -> Self {
        Self {
            source_prefix: [
                source_id[0],
                source_id[1],
                source_id[2],
                source_id[3],
                source_id[4],
                source_id[5],
            ],
            payload_type,
            epoch,
        }
    }
}

/// Read the draft-03 sender/stream nonce domain without decrypting the envelope.
///
/// Returns `None` unless the envelope contains the complete 12-byte nonce. A
/// partial nonce is not exposed as a usable domain identity even if bytes 0..8
/// happen to be present.
pub fn envelope_nonce_domain(envelope: &[u8]) -> Option<NonceDomain> {
    if envelope.len() < NONCE_LEN {
        return None;
    }
    let prefix = envelope.get(..NONCE_SOURCE_PREFIX_LEN)?;
    let mut source_prefix = [0u8; NONCE_SOURCE_PREFIX_LEN];
    source_prefix.copy_from_slice(prefix);
    Some(NonceDomain {
        source_prefix,
        payload_type: *envelope.get(6)?,
        epoch: *envelope.get(7)?,
    })
}

/// Open and deserialize only if the envelope belongs to `expected`.
///
/// Domain comparison happens before [`Session::open`], so a mismatched sender,
/// payload type, or epoch cannot consume or advance receive replay-window state.
/// A successful precheck is **not** authentication: `Session::open` still AEAD
/// verifies the complete nonce and ciphertext before plaintext is returned.
///
/// Domain mismatch and malformed-short envelopes return [`WireError::OpenFailed`]
/// to preserve the crate's deliberately coarse receive-side error taxonomy.
pub fn open_from_nonce_domain<T: Sealable>(
    bytes: &[u8],
    session: &mut Session,
    expected: NonceDomain,
) -> Result<T, WireError> {
    if envelope_nonce_domain(bytes) != Some(expected) {
        return Err(WireError::OpenFailed);
    }
    let plaintext = session.open(bytes)?;
    T::from_bin(&plaintext)
}
