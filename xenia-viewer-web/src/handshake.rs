// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Thin `#[wasm_bindgen]` wrapper over the viewer-side PQC handshake, which now
//! lives in the `xenia-wire` crate (`xenia_wire::handshake`, behind its
//! `handshake` feature) so non-browser clients — notably the operator console —
//! can reuse the exact same wire-compatible implementation without pulling this
//! WASM app crate. This module only adds the JS boundary: `Uint8Array`
//! marshalling and `JsError` conversion.
//!
//! The wire protocol, key schedule, and native cross-compatibility are defined
//! and documented in `xenia_wire::handshake`; the byte-identical parity with the
//! native host is proven by `tests/handshake_cross_compat.rs` (which drives the
//! real native host against the [`WasmHandshake`] wrapper below).

use wasm_bindgen::prelude::*;

use xenia_wire::handshake::{HandshakeError, SessionKeySchedule, ViewerHandshake};

// `session.rs` reuses this for rekey-epoch key derivation; re-exported here so
// its `use crate::handshake::derive_labeled_session_key` keeps working after the
// core moved into xenia-wire.
pub use xenia_wire::handshake::derive_labeled_session_key;

/// The transcript-bound lane key schedule returned by [`WasmHandshake::finish`].
/// Re-exported from `xenia_wire::handshake` so downstream code (and the
/// cross-compat test) keeps its historical `WasmSessionKeySchedule` name.
pub use xenia_wire::handshake::SessionKeySchedule as WasmSessionKeySchedule;

/// Drives the viewer side of a real PQC handshake against a native `xenia-peer`
/// host, from the browser. Wraps [`xenia_wire::handshake::ViewerHandshake`].
#[wasm_bindgen]
pub struct WasmHandshake {
    inner: ViewerHandshake,
}

#[wasm_bindgen]
impl WasmHandshake {
    /// Generate a fresh viewer Ed25519 + ML-DSA-65 identity for this session.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: ViewerHandshake::new(),
        }
    }

    /// Reconstruct a viewer identity from *persisted* seeds — a 32-byte Ed25519
    /// secret and a 32-byte ML-DSA-65 seed — instead of generating fresh keys,
    /// so the browser drives the handshake with the *enrolled* operator
    /// identity. See `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`.
    #[wasm_bindgen(js_name = fromIdentity)]
    pub fn from_identity(
        ed25519_secret: &[u8],
        ml_dsa_seed: &[u8],
    ) -> Result<WasmHandshake, JsError> {
        let inner =
            ViewerHandshake::from_identity(ed25519_secret, ml_dsa_seed).map_err(js_error)?;
        Ok(Self { inner })
    }

    /// Process the host's `HostHello` envelope; returns the `ViewerResponse`
    /// envelope bytes to send back over the transport.
    #[wasm_bindgen(js_name = begin)]
    pub fn begin(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        self.begin_inner(hello_bytes).map_err(js_error)
    }

    /// Process the host's `HostFinalize` envelope; returns the full
    /// transcript-bound lane key schedule (`{ aead, control, video, audio,
    /// telemetry, rekey, context, transcript_hash, host_identity_fingerprint }`,
    /// each a 32-byte `Uint8Array`) on success.
    #[wasm_bindgen(js_name = finish)]
    pub fn finish(&mut self, finalize_bytes: &[u8]) -> Result<JsValue, JsError> {
        let schedule = self.finish_inner(finalize_bytes).map_err(js_error)?;
        schedule_to_js(&schedule)
    }
}

impl Default for WasmHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmHandshake {
    /// Pure-Rust, JS-boundary-free [`WasmHandshake::begin`] — used directly by
    /// native tests (`JsError` construction needs a real JS host and panics on
    /// native targets).
    pub fn begin_inner(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        self.inner.begin(hello_bytes)
    }

    /// Pure-Rust, JS-boundary-free [`WasmHandshake::finish`] — used directly by
    /// native tests.
    pub fn finish_inner(
        &mut self,
        finalize_bytes: &[u8],
    ) -> Result<SessionKeySchedule, HandshakeError> {
        self.inner.finish(finalize_bytes)
    }
}

/// Build the JS-facing object: `{ aead, control, video, audio, telemetry,
/// rekey, context, transcript_hash, host_identity_fingerprint }`, each a
/// `Uint8Array`.
fn schedule_to_js(schedule: &SessionKeySchedule) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();
    let field = |obj: &js_sys::Object, name: &str, bytes: &[u8; 32]| -> Result<(), JsError> {
        js_sys::Reflect::set(
            obj,
            &JsValue::from_str(name),
            &js_sys::Uint8Array::from(bytes.as_slice()).into(),
        )
        .map(|_| ())
        .map_err(|_| JsError::new("Reflect::set failed on session key schedule"))
    };
    field(&obj, "aead", &schedule.aead)?;
    field(&obj, "control", &schedule.control)?;
    field(&obj, "video", &schedule.video)?;
    field(&obj, "audio", &schedule.audio)?;
    field(&obj, "telemetry", &schedule.telemetry)?;
    field(&obj, "rekey", &schedule.rekey)?;
    field(&obj, "context", &schedule.context)?;
    field(&obj, "transcript_hash", &schedule.transcript_hash)?;
    field(
        &obj,
        "host_identity_fingerprint",
        &schedule.host_identity_fingerprint,
    )?;
    Ok(obj.into())
}

fn js_error(e: HandshakeError) -> JsError {
    JsError::new(&format!("xenia handshake: {e}"))
}
