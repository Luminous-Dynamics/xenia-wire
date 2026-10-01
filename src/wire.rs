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

use crate::payload_types;
use crate::{Sealable, Session, WireError};

/// Read the `payload_type` byte out of a sealed envelope's cleartext
/// nonce prefix, without decrypting anything.
///
/// Per [`Session::seal`]'s doc comment, the wire format is
/// `[nonce (12 bytes) | ciphertext | tag (16 bytes)]` with the nonce
/// laid out as `source_id[0..6] | payload_type | epoch | sequence[0..4]`
/// — so `payload_type` is always cleartext byte index 6. This lets a
/// receiver expecting more than one possible payload type on the same
/// (unwrapped) stream dispatch by type before committing to a specific
/// `open`/`open_input`-style call, instead of guessing and discarding a
/// failed attempt (which would also incorrectly consume replay-window
/// state for the wrong stream).
///
/// Returns `None` if `envelope` is too short to contain a full nonce.
pub fn envelope_payload_type(envelope: &[u8]) -> Option<u8> {
    envelope.get(6).copied()
}

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

/// Upper bound on the uncompressed size an [`open_frame_lz4`] caller will
/// allocate for, read from the LZ4 size prefix before decompression.
///
/// `lz4_flex::block::decompress_size_prepended` trusts its 4-byte
/// little-endian size prefix and allocates that many bytes up front. That
/// prefix is authenticated (it's inside the AEAD-sealed envelope by the
/// time we read it), so this isn't a spoofable-by-outsiders vector — but a
/// valid-session-key sender who is buggy or compromised could still make an
/// honest peer allocate an enormous single buffer. 64 MiB comfortably
/// covers any realistic single frame/input payload for this protocol.
#[cfg(feature = "lz4")]
const MAX_LZ4_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// Open a sealed envelope produced by [`seal_frame_lz4`].
///
/// Reverses the pipeline: AEAD verify → LZ4 decompress → bincode deserialize.
/// Returns [`WireError::OpenFailed`] on AEAD failure, decompression
/// failure, a size prefix over `MAX_LZ4_DECOMPRESSED_SIZE`, or any
/// length-prefix corruption; [`WireError::Codec`] on bincode deserialization
/// failure of the decompressed plaintext.
#[cfg(feature = "lz4")]
pub fn open_frame_lz4(bytes: &[u8], session: &mut Session) -> Result<crate::Frame, WireError> {
    let compressed = session.open(bytes)?;
    let (uncompressed_size, _) =
        lz4_flex::block::uncompressed_size(&compressed).map_err(|_| WireError::OpenFailed)?;
    if uncompressed_size > MAX_LZ4_DECOMPRESSED_SIZE {
        return Err(WireError::OpenFailed);
    }
    let plaintext = lz4_flex::block::decompress_size_prepended(&compressed)
        .map_err(|_| WireError::OpenFailed)?;
    <crate::Frame as Sealable>::from_bin(&plaintext)
}

// ─── Consent ceremony wrappers (SPEC draft-02 §12) ───────────────────
//
// These mirror the seal_frame / seal_input surface for the consent
// ceremony messages: callers never need to remember payload-type bytes
// or pass them by hand to the generic `seal` / `open`. Feature-gated
// on `consent` (which also brings the underlying types into scope via
// `crate::consent`).

/// Seal a [`crate::consent::ConsentRequest`] under
/// [`crate::PAYLOAD_TYPE_CONSENT_REQUEST`] (0x20).
///
/// The consent state machine treats this as an outbound `Request`
/// event — after a successful seal, the caller SHOULD drive the local
/// `Session` via [`Session::observe_consent`][crate::Session::observe_consent]`(ConsentEvent::Request)`
/// so subsequent FRAME seals are correctly gated.
#[cfg(feature = "consent")]
pub fn seal_consent_request(
    request: &crate::consent::ConsentRequest,
    session: &mut Session,
) -> Result<Vec<u8>, WireError> {
    seal(
        request,
        session,
        payload_types::PAYLOAD_TYPE_CONSENT_REQUEST,
    )
}

/// Open an envelope sealed by [`seal_consent_request`].
#[cfg(feature = "consent")]
pub fn open_consent_request(
    bytes: &[u8],
    session: &mut Session,
) -> Result<crate::consent::ConsentRequest, WireError> {
    open(bytes, session)
}

/// Seal a [`crate::consent::ConsentResponse`] under
/// [`crate::PAYLOAD_TYPE_CONSENT_RESPONSE`] (0x21).
#[cfg(feature = "consent")]
pub fn seal_consent_response(
    response: &crate::consent::ConsentResponse,
    session: &mut Session,
) -> Result<Vec<u8>, WireError> {
    seal(
        response,
        session,
        payload_types::PAYLOAD_TYPE_CONSENT_RESPONSE,
    )
}

/// Open an envelope sealed by [`seal_consent_response`].
#[cfg(feature = "consent")]
pub fn open_consent_response(
    bytes: &[u8],
    session: &mut Session,
) -> Result<crate::consent::ConsentResponse, WireError> {
    open(bytes, session)
}

/// Seal a [`crate::consent::ConsentRevocation`] under
/// [`crate::PAYLOAD_TYPE_CONSENT_REVOCATION`] (0x22).
#[cfg(feature = "consent")]
pub fn seal_consent_revocation(
    revocation: &crate::consent::ConsentRevocation,
    session: &mut Session,
) -> Result<Vec<u8>, WireError> {
    seal(
        revocation,
        session,
        payload_types::PAYLOAD_TYPE_CONSENT_REVOCATION,
    )
}

/// Open an envelope sealed by [`seal_consent_revocation`].
#[cfg(feature = "consent")]
pub fn open_consent_revocation(
    bytes: &[u8],
    session: &mut Session,
) -> Result<crate::consent::ConsentRevocation, WireError> {
    open(bytes, session)
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

    #[test]
    fn envelope_payload_type_matches_sealed_type_without_decrypting() {
        let (mut sender, _) = paired_sessions([0xEF; 32]);
        let frame_envelope = seal_frame(&sample_frame(), &mut sender).unwrap();
        assert_eq!(
            envelope_payload_type(&frame_envelope),
            Some(payload_types::PAYLOAD_TYPE_FRAME)
        );

        let input = crate::Input {
            sequence: 1,
            timestamp_ms: 0,
            payload: vec![],
        };
        let input_envelope = seal_input(&input, &mut sender).unwrap();
        assert_eq!(
            envelope_payload_type(&input_envelope),
            Some(payload_types::PAYLOAD_TYPE_INPUT)
        );
    }

    #[test]
    fn envelope_payload_type_none_for_short_envelope() {
        assert_eq!(envelope_payload_type(&[1, 2, 3]), None);
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
