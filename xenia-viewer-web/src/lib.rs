// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! WebAssembly demo of the Xenia wire protocol.
//!
//! Exposes a minimal JS API (via `wasm-bindgen`) that exercises
//! `seal_frame` / `open_frame` round-trip entirely in the browser.
//! The demo is a reference — a reader of the paper can click a URL,
//! load the JS glue, and see that Xenia's wire works in a WASM
//! environment. It does NOT include a live-server deployment or
//! WebSocket transport; those are deployment concerns left to the
//! application.

use wasm_bindgen::prelude::*;
use xenia_wire::{open_frame, seal_frame, Frame, Session};

/// Install the panic hook so Rust panics surface in the browser console
/// with readable stack traces. Call once at startup from JS.
#[wasm_bindgen(start)]
pub fn on_load() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

/// Wrapper around [`Session`] exposed to JS.
///
/// Hides the Rust type behind a `#[wasm_bindgen]`-friendly surface so
/// the browser-side code can construct sessions and install keys without
/// caring about Rust idioms.
#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
}

#[wasm_bindgen]
impl WasmSession {
    /// Create a new session. The `source_id` and `epoch` are randomized
    /// per-session via the JS `crypto.getRandomValues` path (see
    /// `getrandom`'s `"js"` feature in the `xenia-wire` Cargo.toml).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Session::new(),
        }
    }

    /// Install a 32-byte session key from a `Uint8Array`. Throws if the
    /// slice is not exactly 32 bytes.
    #[wasm_bindgen(js_name = installKey)]
    pub fn install_key(&mut self, key: &[u8]) -> Result<(), JsError> {
        let arr: [u8; 32] = key
            .try_into()
            .map_err(|_| JsError::new("xenia: key must be exactly 32 bytes"))?;
        self.inner.install_key(arr);
        Ok(())
    }

    /// Return `true` once `installKey` has been called.
    #[wasm_bindgen(js_name = hasKey)]
    pub fn has_key(&self) -> bool {
        self.inner.has_key()
    }

    /// Observability: current nonce counter.
    #[wasm_bindgen(js_name = nonceCounter)]
    pub fn nonce_counter(&self) -> u64 {
        self.inner.nonce_counter()
    }

    /// Hex-encoded `source_id` (for display in the demo page).
    #[wasm_bindgen(js_name = sourceIdHex)]
    pub fn source_id_hex(&self) -> String {
        hex::encode(self.inner.source_id())
    }
}

impl Default for WasmSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Seal an application payload as a `Frame` under `session`. Returns the
/// sealed envelope as a `Uint8Array`.
#[wasm_bindgen(js_name = sealFrame)]
pub fn seal_frame_js(
    session: &mut WasmSession,
    frame_id: u64,
    timestamp_ms: u64,
    payload: &[u8],
) -> Result<Vec<u8>, JsError> {
    let frame = Frame {
        frame_id,
        timestamp_ms,
        payload: payload.to_vec(),
    };
    seal_frame(&frame, &mut session.inner).map_err(|e| JsError::new(&e.to_string()))
}

/// Open a sealed envelope and return the JSON-ish shape
/// `{frame_id, timestamp_ms, payload}` as a JS object. Rejects on any
/// AEAD / replay / codec failure.
#[wasm_bindgen(js_name = openFrame)]
pub fn open_frame_js(session: &mut WasmSession, envelope: &[u8]) -> Result<JsValue, JsError> {
    let frame = open_frame(envelope, &mut session.inner).map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("frame_id"),
        &JsValue::from(frame.frame_id as f64),
    )
    .map_err(|_| JsError::new("Reflect::set frame_id failed"))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("timestamp_ms"),
        &JsValue::from(frame.timestamp_ms as f64),
    )
    .map_err(|_| JsError::new("Reflect::set timestamp_ms failed"))?;
    let payload_arr = js_sys::Uint8Array::from(&frame.payload[..]);
    js_sys::Reflect::set(&obj, &JsValue::from_str("payload"), &payload_arr)
        .map_err(|_| JsError::new("Reflect::set payload failed"))?;
    Ok(obj.into())
}

/// Version of the underlying `xenia-wire` crate baked into this build.
#[wasm_bindgen(js_name = wireVersion)]
pub fn wire_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
