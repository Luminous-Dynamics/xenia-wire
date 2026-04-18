// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Seal / open functions over the [`crate::Session`] and [`crate::Sealable`]
//! primitives.
//!
//! Two API surfaces:
//!
//! - Generic [`seal`] / [`open`] take any `T: Sealable` and a caller-chosen
//!   payload type byte. Use these for custom payload structures.
//! - Convenience wrappers [`seal_frame`] / [`open_frame`] / [`seal_input`] /
//!   [`open_input`] pin the payload type to the reference constants
//!   ([`crate::PAYLOAD_TYPE_FRAME`], [`crate::PAYLOAD_TYPE_INPUT`]) and the
//!   reference types ([`crate::Frame`], [`crate::Input`]). Available under
//!   the default `reference-frame` feature.
//! - LZ4-before-AEAD variants [`seal_frame_lz4`] / [`open_frame_lz4`] are
//!   gated behind the `lz4` feature.

#[cfg(any(feature = "reference-frame", feature = "lz4"))]
use crate::payload_types;
use crate::{Sealable, Session, WireError};

/// Seal any [`Sealable`] payload under the session key with the caller-chosen
/// payload type byte.
///
/// The payload type separates concurrent streams on the same session:
/// independent replay windows, and domain-separated AEAD nonces. See
/// [`crate::payload_types`] for reserved values and the
/// application-reserved range `0x30..=0xFF`.
pub fn seal<T: Sealable>(
    payload: &T,
    session: &mut Session,
    payload_type: u8,
) -> Result<Vec<u8>, WireError> {
    let plaintext = payload.to_bin()?;
    session.seal(&plaintext, payload_type)
}

/// Open a sealed envelope and deserialize it into a [`Sealable`] payload.
///
/// Uses the payload type byte embedded in the envelope's nonce for
/// replay-window keying only — the caller is responsible for knowing
/// which type `T` to expect. Mismatched types surface as a codec error
/// from [`Sealable::from_bin`].
pub fn open<T: Sealable>(bytes: &[u8], session: &mut Session) -> Result<T, WireError> {
    let plaintext = session.open(bytes)?;
    T::from_bin(&plaintext)
}

/// Seal a reference [`crate::Frame`] on the forward path
/// ([`crate::PAYLOAD_TYPE_FRAME`]).
#[cfg(feature = "reference-frame")]
pub fn seal_frame(frame: &crate::Frame, session: &mut Session) -> Result<Vec<u8>, WireError> {
    seal(frame, session, payload_types::PAYLOAD_TYPE_FRAME)
}

/// Open a sealed envelope produced by [`seal_frame`].
#[cfg(feature = "reference-frame")]
pub fn open_frame(bytes: &[u8], session: &mut Session) -> Result<crate::Frame, WireError> {
    open(bytes, session)
}

/// Seal a reference [`crate::Input`] on the reverse path
/// ([`crate::PAYLOAD_TYPE_INPUT`]).
#[cfg(feature = "reference-frame")]
pub fn seal_input(input: &crate::Input, session: &mut Session) -> Result<Vec<u8>, WireError> {
    seal(input, session, payload_types::PAYLOAD_TYPE_INPUT)
}

/// Open a sealed envelope produced by [`seal_input`].
#[cfg(feature = "reference-frame")]
pub fn open_input(bytes: &[u8], session: &mut Session) -> Result<crate::Input, WireError> {
    open(bytes, session)
}

/// Seal a reference [`crate::Frame`] with LZ4-before-AEAD compression
/// ([`crate::PAYLOAD_TYPE_FRAME_LZ4`]).
///
/// # Why LZ4 must precede AEAD
///
/// ChaCha20-Poly1305 ciphertext is pseudorandom and does not compress.
/// Applying LZ4 after seal wastes CPU for zero byte reduction. Applying
/// LZ4 before seal — on the bincode-encoded plaintext — achieves the
/// measured 2.12× reduction on live traffic (Pixel 8 Pro, 2026-04-17).
///
/// # Compatibility
///
/// Envelopes sealed by this function MUST be opened by [`open_frame_lz4`].
/// The distinct payload type ([`crate::PAYLOAD_TYPE_FRAME_LZ4`] vs
/// [`crate::PAYLOAD_TYPE_FRAME`]) separates the two streams on the wire —
/// a caller can interleave raw and LZ4 frames on the same session key
/// without replay-window collision.
#[cfg(feature = "lz4")]
pub fn seal_frame_lz4(frame: &crate::Frame, session: &mut Session) -> Result<Vec<u8>, WireError> {
    let plaintext = frame.to_bin()?;
    let compressed = lz4_flex::block::compress_prepend_size(&plaintext);
    session.seal(&compressed, payload_types::PAYLOAD_TYPE_FRAME_LZ4)
}

/// Open a sealed envelope produced by [`seal_frame_lz4`].
///
/// Reverses the pipeline: AEAD verify → LZ4 decompress → bincode deserialize.
/// Returns [`WireError::OpenFailed`] on AEAD failure, decompression
/// failure, or any length-prefix corruption; [`WireError::Codec`] on
/// bincode deserialization failure of the decompressed plaintext.
#[cfg(feature = "lz4")]
pub fn open_frame_lz4(bytes: &[u8], session: &mut Session) -> Result<crate::Frame, WireError> {
    let compressed = session.open(bytes)?;
    let plaintext = lz4_flex::block::decompress_size_prepended(&compressed)
        .map_err(|_| WireError::OpenFailed)?;
    <crate::Frame as Sealable>::from_bin(&plaintext)
}

#[cfg(all(test, feature = "reference-frame"))]
mod tests {
    use super::*;
    use crate::Frame;

    fn paired_sessions(key: [u8; 32]) -> (Session, Session) {
        let mut sender = Session::with_source_id([0x11; 8], 0x42);
        let mut receiver = Session::with_source_id([0x11; 8], 0x42);
        sender.install_key(key);
        receiver.install_key(key);
        (sender, receiver)
    }

    fn sample_frame() -> Frame {
        Frame {
            frame_id: 1,
            timestamp_ms: 1_700_000_000_000,
            payload: (0..256u16).map(|i| (i & 0xFF) as u8).collect(),
        }
    }

    #[test]
    fn seal_open_frame_roundtrip() {
        let (mut sender, mut receiver) = paired_sessions([0xAB; 32]);
        let frame = sample_frame();
        let sealed = seal_frame(&frame, &mut sender).unwrap();
        let opened = open_frame(&sealed, &mut receiver).unwrap();
        assert_eq!(opened, frame);
    }

    #[test]
    fn seal_open_input_roundtrip() {
        let (mut sender, mut receiver) = paired_sessions([0xCD; 32]);
        let input = crate::Input {
            sequence: 3,
            timestamp_ms: 1_700_000_000_050,
            payload: b"tap".to_vec(),
        };
        let sealed = seal_input(&input, &mut sender).unwrap();
        let opened = open_input(&sealed, &mut receiver).unwrap();
        assert_eq!(opened, input);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn lz4_roundtrip_and_smaller_than_raw() {
        let (mut raw_sender, _) = paired_sessions([0x01; 32]);
        let (mut lz4_sender, mut lz4_receiver) = paired_sessions([0x02; 32]);

        // A frame with a highly compressible payload.
        let frame = Frame {
            frame_id: 9,
            timestamp_ms: 1_700_000_000_123,
            payload: vec![0x5A; 4096],
        };

        let raw_sealed = seal_frame(&frame, &mut raw_sender).unwrap();
        let lz4_sealed = seal_frame_lz4(&frame, &mut lz4_sender).unwrap();
        let opened = open_frame_lz4(&lz4_sealed, &mut lz4_receiver).unwrap();

        assert_eq!(opened, frame);
        assert!(
            lz4_sealed.len() < raw_sealed.len(),
            "LZ4 sealed ({}) must be smaller than raw sealed ({}) for compressible payloads",
            lz4_sealed.len(),
            raw_sealed.len(),
        );
    }

    #[test]
    fn generic_seal_open_for_custom_payload_type() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct MyPayload {
            marker: u32,
            bytes: Vec<u8>,
        }
        impl Sealable for MyPayload {
            fn to_bin(&self) -> Result<Vec<u8>, WireError> {
                bincode::serialize(self).map_err(WireError::encode)
            }
            fn from_bin(b: &[u8]) -> Result<Self, WireError> {
                bincode::deserialize(b).map_err(WireError::decode)
            }
        }

        let (mut sender, mut receiver) = paired_sessions([0xEF; 32]);
        let payload = MyPayload {
            marker: 0xDEAD_BEEF,
            bytes: vec![1, 2, 3, 4, 5],
        };
        let sealed = seal(&payload, &mut sender, 0x30).unwrap();
        let opened: MyPayload = open(&sealed, &mut receiver).unwrap();
        assert_eq!(opened, payload);
    }
}
