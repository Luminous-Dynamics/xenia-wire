// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Payload-type registry.
//!
//! The 7th nonce byte (`nonce[6]`) is a `payload_type` that separates
//! independent streams on the same session key. Two streams with different
//! payload_type values can run concurrently without colliding on replay
//! state or risking nonce reuse — the replay window is keyed by
//! `(source_id, payload_type)`.
//!
//! This module reserves specific byte values for well-known stream types.
//! Callers of generic [`crate::seal`] / [`crate::open`] MAY use any byte
//! not in the reserved ranges below, preferring the application range
//! `0x30..=0xFF`.
//!
//! ## Reserved ranges
//!
//! | Range          | Owner            | Status                          |
//! |----------------|------------------|---------------------------------|
//! | `0x00..=0x0F`  | mesh (upstream)  | Wisdom / heartbeat / affective. |
//! | `0x10..=0x1F`  | xenia core       | Frames, inputs, future core.    |
//! | `0x20..=0x2F`  | xenia extensions | Consent, replay, attestation.   |
//! | `0x30..=0xFF`  | applications     | Free for custom payload types.  |
//!
//! The `0x00..=0x0F` range is reserved for upstream compatibility with the
//! Symthaea mesh-layer AEAD primitives from which this wire descends.
//! Do NOT use those values — the packet_crypto::build_nonce layout in
//! Symthaea may dispatch based on this byte, and Xenia preserves the
//! boundary for future cross-wire interop.

/// Payload type for the primary frame stream (server → client direction).
///
/// Used by [`crate::seal_frame`] and [`crate::open_frame`]. Independent
/// replay window from inputs and LZ4 frames.
pub const PAYLOAD_TYPE_FRAME: u8 = 0x10;

/// Payload type for the reverse-path input stream (client → server).
///
/// Used by [`crate::seal_input`] and [`crate::open_input`]. Independent
/// replay window from frames — a captured input event cannot replay as a
/// frame or vice versa.
pub const PAYLOAD_TYPE_INPUT: u8 = 0x11;

/// Payload type for LZ4-compressed frames.
///
/// Used by [`crate::seal_frame_lz4`] and [`crate::open_frame_lz4`] when the
/// `lz4` feature is enabled. A distinct payload type from [`PAYLOAD_TYPE_FRAME`]
/// so a session can interleave raw and compressed frames without replay-window
/// collision.
///
/// LZ4 MUST precede AEAD — ChaCha20-Poly1305 ciphertext is pseudorandom and
/// does not compress. See `SPEC.md` §LZ4-before-AEAD for the full rationale.
pub const PAYLOAD_TYPE_FRAME_LZ4: u8 = 0x12;

/// Reserved — Week-5 spec differentiator: consent ceremony request.
///
/// Implemented in a later release. Reserved now so the wire format is
/// forward-compatible.
pub const PAYLOAD_TYPE_CONSENT_REQUEST: u8 = 0x20;

/// Reserved — Week-5 spec differentiator: consent ceremony response.
pub const PAYLOAD_TYPE_CONSENT_RESPONSE: u8 = 0x21;

/// Reserved — Week-5 spec differentiator: consent revocation (mid-session).
pub const PAYLOAD_TYPE_CONSENT_REVOCATION: u8 = 0x22;

/// Reserved — Week-5 spec differentiator: attestation-chained action log entry.
pub const PAYLOAD_TYPE_ATTESTED_ACTION: u8 = 0x23;

/// Lowest byte available for application-defined payload types.
///
/// Use any value in `0x30..=0xFF` for custom streams. The Xenia core will
/// not assign values in this range in future releases.
pub const PAYLOAD_TYPE_APPLICATION_MIN: u8 = 0x30;
