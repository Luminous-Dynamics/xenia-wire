// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # xenia-wire
//!
//! PQC-sealed binary wire protocol for remote-control streams.
//!
//! **Pre-alpha.** The wire format is not yet frozen and breaking changes
//! will land between `0.1.x` releases. Do not deploy in production.
//!
//! ## What this crate provides
//!
//! - **[`Session`]** — minimal AEAD session state: a current key, an
//!   optional previous key with grace period for rekey, per-session
//!   random `source_id` + `epoch`, monotonic nonce counter, and a
//!   64-slot sliding replay window.
//! - **[`ReplayWindow`]** — sliding-window replay protection keyed by
//!   `(source_id, payload_type)`. IPsec/DTLS semantics.
//! - **[`Sealable`]** — generic bincode-based serialization contract.
//!   Bring your own payload type.
//! - **[`seal`] / [`open`]** — generic functions for any `Sealable` payload.
//! - **[`seal_frame`] / [`open_frame`] / [`seal_input`] / [`open_input`]** —
//!   convenience wrappers for the reference [`Frame`] + [`Input`] types.
//!   Available under the default `reference-frame` feature.
//! - **[`seal_frame_lz4`] / [`open_frame_lz4`]** — LZ4-before-AEAD
//!   compression variants. Available under the `lz4` feature.
//!
//! ## What this crate deliberately does NOT do
//!
//! - **No transport.** Sealed bytes are returned to the caller; the
//!   caller ships them over TCP / WebSocket / QUIC / whatever.
//! - **No handshake.** Session keys arrive from somewhere else
//!   (ML-KEM-768 in real deployments). Call [`Session::install_key`]
//!   directly in tests or early prototypes.
//! - **No state machine.** `Session` has no lifecycle — no connecting,
//!   authenticating, closing. Those are application concerns.
//! - **No domain semantics.** The reference [`Frame`] / [`Input`] types
//!   carry opaque byte payloads. Implement [`Sealable`] on your own
//!   types for anything real.
//!
//! ## Quick start
//!
//! ```
//! use xenia_wire::{Session, seal_frame, open_frame, Frame};
//!
//! let key = [0xAB; 32];
//! let mut sender = Session::new();
//! let mut receiver = Session::new();
//! sender.install_key(key);
//! receiver.install_key(key);
//!
//! let frame = Frame {
//!     frame_id: 1,
//!     timestamp_ms: 1_700_000_000_000,
//!     payload: b"hello, xenia".to_vec(),
//! };
//! let sealed = seal_frame(&frame, &mut sender).unwrap();
//! let opened = open_frame(&sealed, &mut receiver).unwrap();
//! assert_eq!(opened.payload, b"hello, xenia");
//!
//! // Replaying the same bytes fails — the sliding window catches it.
//! assert!(open_frame(&sealed, &mut receiver).is_err());
//! ```
//!
//! ## Wire format
//!
//! ```text
//! envelope = nonce || ciphertext || tag
//!   nonce       : 12 bytes — source_id[0..6] || payload_type || epoch || seq[0..4]
//!   ciphertext  : len(plaintext) bytes — ChaCha20-Poly1305 encrypt(plaintext)
//!   tag         : 16 bytes — Poly1305 authentication tag
//! ```
//!
//! The plaintext is typically `bincode::serialize(payload)`. Under the
//! `lz4` feature the plaintext is `lz4_flex::compress_prepend_size(bincode_bytes)`.
//!
//! ## Feature flags
//!
//! | Feature           | Default | Description                                          |
//! |-------------------|---------|------------------------------------------------------|
//! | `reference-frame` | yes     | Ships [`Frame`] + [`Input`] reference types.         |
//! | `lz4`             | no      | Adds LZ4-before-AEAD variants for frame sealing.     |
//!
//! ## License
//!
//! Dual-licensed under Apache-2.0 OR MIT.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

mod error;
pub mod payload_types;
mod replay_window;
mod session;
mod wire;

mod frame;

#[cfg(feature = "consent")]
pub mod consent;

pub use error::WireError;
pub use payload_types::{
    PAYLOAD_TYPE_APPLICATION_MIN, PAYLOAD_TYPE_ATTESTED_ACTION, PAYLOAD_TYPE_CONSENT_REQUEST,
    PAYLOAD_TYPE_CONSENT_RESPONSE, PAYLOAD_TYPE_CONSENT_REVOCATION, PAYLOAD_TYPE_FRAME,
    PAYLOAD_TYPE_FRAME_LZ4, PAYLOAD_TYPE_INPUT,
};
pub use replay_window::{ReplayWindow, WINDOW_BITS};
pub use session::{Session, DEFAULT_REKEY_GRACE};

pub use frame::Sealable;
pub use wire::{open, seal};

#[cfg(feature = "reference-frame")]
pub use frame::{Frame, Input};

#[cfg(feature = "reference-frame")]
pub use wire::{open_frame, open_input, seal_frame, seal_input};

#[cfg(feature = "lz4")]
pub use wire::{open_frame_lz4, seal_frame_lz4};
