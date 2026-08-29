// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # xenia-wire
//!
//! AEAD-sealed binary wire protocol for remote-control streams.
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
//! - **[`consent`]** — signed draft-03 request/response/revocation ceremony.
//! - **[`authority`]** — experimental exact external-action authority. Unlike
//!   ordinary consent responses, its responder statement commits to the digest
//!   of the complete signed request. Available only with `causal-authority`.
//! - **[`authority_session`]** — negotiated authority type-state and live-session
//!   binding. The owned authority session hides unrestricted key replacement.
//! - **[`authority_live_use`]** — session-borrowed online verification so a
//!   verified action cannot silently outlive a rekey or authority teardown.
//! - **[`negotiated_context`]** — canonical capability offers, deterministic
//!   selected contexts, and negotiation binding primitives.
//! - **[`negotiated_context_codec`]** — bounded canonical decoding for untrusted
//!   capability offers and selected contexts; alternate encodings fail closed.
//! - **[`negotiation_policy`]** — local minimum/allow-list policy over an
//!   authenticated selected context, with a separate audit hash.
//! - **[`handshake_v2_contract`]** — non-production independent reproduction of
//!   candidate dynamic-negotiation V2 message bytes and signature transcripts.
//! - **[`authority_activation_evidence`]** — durable policy-bound evidence that
//!   separates authenticated session lineage from local authority activation.
//! - **[`authority_lineage_epoch_evidence`]** — durable continuity evidence for
//!   the existing verified Xenia rekey epoch chain.
//! - **[`authority_rekey_transition_evidence`]** — self-describing public rekey
//!   context evidence that recomputes the exact existing lane/operator epoch hash.
//! - **[`authority_rekey_profile_binding`]** — pins one rekey protocol domain to
//!   an activation so a contiguous lineage cannot silently switch semantics.
//! - **[`authority_negotiation`]** — exact causal-authority draft-04 capability
//!   identity and selected-context checks when `causal-authority` + `handshake`
//!   are enabled together.
//!
//! ## What this crate deliberately does NOT do
//!
//! - **No transport.** Sealed bytes are returned to the caller; the
//!   caller ships them over TCP / WebSocket / QUIC / whatever.
//! - **No handshake by default.** Session keys may arrive from somewhere else;
//!   the optional `handshake` feature provides the viewer-side PQC handshake.
//! - **No application lifecycle.** Session creation/teardown and durable
//!   authority consumption remain application concerns.
//! - **No domain semantics.** Xenia binds canonical application bytes and
//!   digests; consuming applications define what those bytes mean.
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
//! | Feature            | Default | Description |
//! |--------------------|---------|-------------|
//! | `reference-frame`  | yes     | Ships [`Frame`] + [`Input`] reference types. |
//! | `lz4`              | no      | Adds LZ4-before-AEAD variants for frames. |
//! | `consent`          | no      | Adds signed consent ceremony + session gating. |
//! | `causal-authority` | no      | Experimental exact request-bound authority; implies `consent`. |
//! | `handshake`        | no      | Viewer-side hybrid-PQ handshake + negotiated-context primitives. |
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

#[cfg(feature = "causal-authority")]
pub mod authority;

#[cfg(feature = "causal-authority")]
pub mod authority_session;

#[cfg(all(feature = "causal-authority", feature = "handshake"))]
pub mod authority_live_use;

#[cfg(feature = "handshake")]
pub mod handshake;

#[cfg(feature = "handshake")]
pub mod negotiated_context;

#[cfg(feature = "handshake")]
pub mod negotiated_context_codec;

#[cfg(feature = "handshake")]
pub mod negotiation_policy;

#[cfg(feature = "handshake")]
pub mod handshake_v2_contract;

#[cfg(all(feature = "causal-authority", feature = "handshake"))]
pub mod authority_activation_evidence;

#[cfg(all(feature = "causal-authority", feature = "handshake"))]
pub mod authority_lineage_epoch_evidence;

#[cfg(all(feature = "causal-authority", feature = "handshake"))]
pub mod authority_rekey_transition_evidence;

#[cfg(all(feature = "causal-authority", feature = "handshake"))]
pub mod authority_rekey_profile_binding;

#[cfg(all(feature = "causal-authority", feature = "handshake"))]
pub mod authority_negotiation;

#[cfg(feature = "handshake")]
pub mod handshake_highsec;

#[cfg(feature = "operator-rekey")]
pub mod operator_rekey;

pub use error::WireError;
pub use payload_types::{
    PAYLOAD_TYPE_APPLICATION_MIN, PAYLOAD_TYPE_ATTESTED_ACTION,
    PAYLOAD_TYPE_CAUSAL_AUTHORITY_RESPONSE, PAYLOAD_TYPE_CONSENT_REQUEST,
    PAYLOAD_TYPE_CONSENT_RESPONSE, PAYLOAD_TYPE_CONSENT_REVOCATION, PAYLOAD_TYPE_FRAME,
    PAYLOAD_TYPE_FRAME_LZ4, PAYLOAD_TYPE_INPUT,
};
pub use replay_window::{DEFAULT_WINDOW_BITS, MAX_WINDOW_BITS, ReplayWindow, WINDOW_BITS};
#[cfg(all(feature = "consent", feature = "bench-internals"))]
pub use session::ct_eq_32_for_bench;
pub use session::{DEFAULT_REKEY_GRACE, Session, SessionBuilder};

pub use frame::Sealable;
pub use wire::{envelope_payload_type, open, seal};

#[cfg(feature = "reference-frame")]
pub use frame::{Frame, Input};

#[cfg(feature = "reference-frame")]
pub use wire::{open_frame, open_input, seal_frame, seal_input};

#[cfg(feature = "lz4")]
pub use wire::{open_frame_lz4, seal_frame_lz4};

#[cfg(feature = "consent")]
pub use wire::{
    open_consent_request, open_consent_response, open_consent_revocation, seal_consent_request,
    seal_consent_response, seal_consent_revocation,
};
