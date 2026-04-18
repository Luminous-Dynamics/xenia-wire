// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Payload serialization contract and reference types.
//!
//! Xenia's wire is payload-agnostic: [`crate::seal`] and [`crate::open`]
//! work on any type that implements [`Sealable`]. The default
//! implementation uses `bincode` for its compact binary encoding, but any
//! `to_bin` / `from_bin` pair is acceptable as long as both peers agree.
//!
//! The reference types [`Frame`] and [`Input`] are provided behind the
//! default `reference-frame` feature so the quick-start example works
//! without flag wrangling. For real applications you will almost certainly
//! want to define your own payload structures that carry your domain's
//! semantics, and implement [`Sealable`] for them.

use crate::WireError;

/// Serialization contract for any payload that can travel over the Xenia
/// wire.
///
/// Implementations should use a compact binary encoding. The default
/// reference types use `bincode::serialize` / `bincode::deserialize`.
pub trait Sealable: Sized {
    /// Serialize `self` to a compact binary payload.
    fn to_bin(&self) -> Result<Vec<u8>, WireError>;
    /// Deserialize from a binary payload.
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError>;
}

/// Reference forward-path payload: a primary stream carrying an
/// application-defined byte blob.
///
/// This is intentionally minimal — just enough to make the quick-start
/// example work and to demonstrate the [`Sealable`] contract. Real
/// applications should define their own payload structure with domain
/// semantics and implement [`Sealable`] directly.
#[cfg(feature = "reference-frame")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Frame {
    /// Monotonically increasing identifier. Convention only — the wire
    /// does not enforce monotonicity on this field.
    pub frame_id: u64,
    /// Timestamp in milliseconds since the Unix epoch. Convention only —
    /// the wire does not validate this field.
    pub timestamp_ms: u64,
    /// Opaque application payload.
    pub payload: Vec<u8>,
}

#[cfg(feature = "reference-frame")]
impl Sealable for Frame {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

/// Reference reverse-path payload: an input event batch carrying an
/// application-defined byte blob.
///
/// Paired with [`Frame`] for bidirectional remote-control use. The
/// sequence field is a convention for caller-side ordering; the wire's
/// own replay window operates on the AEAD nonce sequence, not on this
/// field.
#[cfg(feature = "reference-frame")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Input {
    /// Caller-side sequence number for ordering events.
    pub sequence: u64,
    /// Timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Opaque application payload.
    pub payload: Vec<u8>,
}

#[cfg(feature = "reference-frame")]
impl Sealable for Input {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        bincode::serialize(self).map_err(WireError::encode)
    }
    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        bincode::deserialize(bytes).map_err(WireError::decode)
    }
}

#[cfg(all(test, feature = "reference-frame"))]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = Frame {
            frame_id: 42,
            timestamp_ms: 1_700_000_000_000,
            payload: b"hello".to_vec(),
        };
        let bytes = f.to_bin().unwrap();
        let decoded = Frame::from_bin(&bytes).unwrap();
        assert_eq!(f, decoded);
    }

    #[test]
    fn input_roundtrip() {
        let i = Input {
            sequence: 7,
            timestamp_ms: 1_700_000_000_050,
            payload: b"click".to_vec(),
        };
        let bytes = i.to_bin().unwrap();
        let decoded = Input::from_bin(&bytes).unwrap();
        assert_eq!(i, decoded);
    }

    #[test]
    fn from_bin_rejects_garbage() {
        assert!(Frame::from_bin(&[0xFFu8; 4]).is_err());
    }
}
