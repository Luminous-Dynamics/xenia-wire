// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! WebAssembly demo of the Xenia wire protocol.
//!
//! Exposes several JS-facing APIs via `wasm-bindgen`:
//!
//! - [`WasmSession`] — minimal wrapper around [`xenia_wire::Session`]
//!   for the smallest roundtrip demo (see `www/demo.html`).
//! - [`WasmConsentCeremony`] — a two-sided fixture that drives a full
//!   consent ceremony entirely in-browser for the walk-through on
//!   `www/consent.html`.
//! - [`WasmViewer`] — a loopback pair of sessions + helpers for
//!   synthesizing "remote screen" FRAME payloads and sealing captured
//!   keyboard/mouse as INPUT envelopes on `www/viewer.html`.
//!
//! Nothing here is production-relevant. The demos show that the wire
//! works on the web platform; they do NOT establish a real session
//! with a remote peer.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;
use xenia_wire::consent::{
    ConsentEvent, ConsentRequestCore, ConsentResponseCore, ConsentRevocationCore, ConsentScope,
    ConsentState,
};
use xenia_wire::{
    open_consent_request, open_consent_response, open_consent_revocation, open_frame,
    open_input, seal_consent_request, seal_consent_response, seal_consent_revocation,
    seal_frame, seal_input, Frame, Input, Session,
};

/// Install the panic hook so Rust panics surface in the browser console
/// with readable stack traces. Call once at startup from JS.
#[wasm_bindgen(start)]
pub fn on_load() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

// ─── WasmSession (unchanged minimal demo surface) ─────────────────────

/// Wrapper around [`Session`] exposed to JS.
#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
}

#[wasm_bindgen]
impl WasmSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Session::new(),
        }
    }

    /// Install a 32-byte session key.
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

    #[wasm_bindgen(js_name = nonceCounter)]
    pub fn nonce_counter(&self) -> u64 {
        self.inner.nonce_counter()
    }

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

/// Seal an application payload as a `Frame` under `session`.
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

/// Open a sealed envelope.
#[wasm_bindgen(js_name = openFrame)]
pub fn open_frame_js(session: &mut WasmSession, envelope: &[u8]) -> Result<JsValue, JsError> {
    let frame = open_frame(envelope, &mut session.inner).map_err(|e| JsError::new(&e.to_string()))?;
    let obj = js_sys::Object::new();
    set_field(&obj, "frame_id", JsValue::from(frame.frame_id as f64))?;
    set_field(&obj, "timestamp_ms", JsValue::from(frame.timestamp_ms as f64))?;
    let arr = js_sys::Uint8Array::from(&frame.payload[..]);
    set_field(&obj, "payload", arr.into())?;
    Ok(obj.into())
}

/// Version of the underlying `xenia-wire` crate baked into this build.
#[wasm_bindgen(js_name = wireVersion)]
pub fn wire_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ─── Daemon-protocol browser viewer ───────────────────────────────────
//
// Shadow structs mirroring `xenia-peer-core`'s `RawFrame` +
// `PixelFormat`. The peer-core crate lives in a different repository
// (`Luminous-Dynamics/xenia-peer`), so we don't take a cross-repo path
// dependency here — the wire format is the normative contract and the
// shadow definitions track it via bincode v1's deterministic layout.
// Field order MUST match the upstream crate byte-for-byte.

/// Shadow of `xenia_peer_core::frame::PixelFormat`. `#[repr(u8)]` +
/// bincode v1 encodes this as a single byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[repr(u8)]
#[allow(dead_code)]
enum RawPixelFormat {
    Rgba8 = 0,
    Bgra8 = 1,
    H264 = 16,
    Vp9 = 17,
    Passthrough = 32,
}

/// Shadow of `xenia_peer_core::frame::RawFrame`. Field order matches
/// the upstream; any divergence will produce a bincode-deserialize
/// error on the first frame.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // fields are populated by bincode + read by open_daemon_frame_js
struct RawFrameShadow {
    frame_id: u64,
    timestamp_ms: u64,
    width: u32,
    height: u32,
    pixel_format: RawPixelFormat,
    pixels: Vec<u8>,
}

/// Open a sealed envelope that the xenia-peer daemon emitted, and
/// decode it as a passthrough-codec RGBA frame.
///
/// Returns a JS object `{ width, height, rgba, frame_id,
/// timestamp_ms }`. The `rgba` field is a `Uint8Array` of length
/// `width * height * 4`; caller wraps it in an `ImageData` and
/// paints to a canvas.
///
/// Only `PixelFormat::Passthrough` frames are accepted in this
/// release. H.264 frames would need WebCodecs integration, which
/// is M4.1b.
#[wasm_bindgen(js_name = openDaemonFrame)]
pub fn open_daemon_frame_js(
    session: &mut WasmSession,
    envelope: &[u8],
) -> Result<JsValue, JsError> {
    // 1. AEAD-open the envelope to recover the inner wire-Frame
    //    (whose payload is the bincode-encoded RawFrame).
    let wire_frame = open_frame(envelope, &mut session.inner)
        .map_err(|e| JsError::new(&format!("xenia-wire open_frame: {e}")))?;

    // 2. Bincode-deserialize the RawFrame out of wire_frame.payload.
    let raw: RawFrameShadow = bincode::deserialize(&wire_frame.payload)
        .map_err(|e| JsError::new(&format!("RawFrame bincode decode: {e}")))?;

    // 3. Dispatch on codec. Passthrough is the only path the browser
    //    can handle today; H.264 would need WebCodecs.
    if raw.pixel_format != RawPixelFormat::Passthrough {
        return Err(JsError::new(&format!(
            "xenia-viewer-web currently only supports --codec passthrough; daemon sent {:?}",
            raw.pixel_format
        )));
    }

    // 4. Parse the passthrough header (12 bytes: magic 'X', version 1,
    //    pix_fmt, reserved, width LE u32, height LE u32), then take
    //    the raw pixel bytes.
    if raw.pixels.len() < 12 {
        return Err(JsError::new("passthrough payload shorter than 12-byte header"));
    }
    if raw.pixels[0] != 0x58 {
        return Err(JsError::new("passthrough bad magic"));
    }
    if raw.pixels[1] != 0x01 {
        return Err(JsError::new("passthrough unsupported version"));
    }
    // Only RGBA (0) is wired in the browser path; BGRA would need a swizzle
    // in JS which we skip for MVP.
    if raw.pixels[2] != 0 {
        return Err(JsError::new("passthrough: only RGBA pixel-format supported in browser"));
    }
    let width = u32::from_le_bytes([raw.pixels[4], raw.pixels[5], raw.pixels[6], raw.pixels[7]]);
    let height = u32::from_le_bytes([raw.pixels[8], raw.pixels[9], raw.pixels[10], raw.pixels[11]]);
    let body = &raw.pixels[12..];
    let expected = (width as usize) * (height as usize) * 4;
    if body.len() != expected {
        return Err(JsError::new(&format!(
            "passthrough body {} bytes, expected {} for {}x{}",
            body.len(),
            expected,
            width,
            height
        )));
    }

    // 5. Build the JS return object.
    let obj = js_sys::Object::new();
    set_field(&obj, "frame_id", JsValue::from(raw.frame_id as f64))?;
    set_field(&obj, "timestamp_ms", JsValue::from(raw.timestamp_ms as f64))?;
    set_field(&obj, "width", JsValue::from(width as f64))?;
    set_field(&obj, "height", JsValue::from(height as f64))?;
    let rgba_arr = js_sys::Uint8Array::from(body);
    set_field(&obj, "rgba", rgba_arr.into())?;
    Ok(obj.into())
}

fn set_field(obj: &js_sys::Object, key: &str, value: JsValue) -> Result<(), JsError> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| JsError::new(&format!("Reflect::set {key} failed")))
}

// ─── Consent ceremony walk-through (for www/consent.html) ─────────────

/// Two-sided fixture that drives a full consent ceremony entirely in
/// the browser. Owns both the technician and end-user sides: two
/// [`Session`]s (with the same fixture AEAD key) + two Ed25519
/// [`SigningKey`]s.
#[wasm_bindgen]
pub struct WasmConsentCeremony {
    tech: Session,
    user: Session,
    tech_sk: SigningKey,
    user_sk: SigningKey,
    next_request_id: u64,
}

#[wasm_bindgen]
impl WasmConsentCeremony {
    /// Construct with fresh random AEAD key + two random Ed25519
    /// keypairs.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let key: [u8; 32] = rand::random();
        // Opt into ceremony mode on both sides so the walkthrough
        // actually exercises the AwaitingRequest → Requested → Approved
        // transitions. `Session::new` defaults to `LegacyBypass`
        // (sticky), which would make every `observe_consent` a no-op.
        let mut tech = Session::builder().require_consent(true).build();
        let mut user = Session::builder().require_consent(true).build();
        tech.install_key(key);
        user.install_key(key);
        Self {
            tech,
            user,
            tech_sk: SigningKey::generate(&mut OsRng),
            user_sk: SigningKey::generate(&mut OsRng),
            next_request_id: 1,
        }
    }

    /// Hex-encoded public keys for display.
    #[wasm_bindgen(js_name = technicianPubkeyHex)]
    pub fn technician_pubkey_hex(&self) -> String {
        hex::encode(self.tech_sk.verifying_key().to_bytes())
    }

    #[wasm_bindgen(js_name = endUserPubkeyHex)]
    pub fn end_user_pubkey_hex(&self) -> String {
        hex::encode(self.user_sk.verifying_key().to_bytes())
    }

    #[wasm_bindgen(js_name = technicianConsentState)]
    pub fn technician_consent_state(&self) -> String {
        consent_state_string(self.tech.consent_state())
    }

    #[wasm_bindgen(js_name = endUserConsentState)]
    pub fn end_user_consent_state(&self) -> String {
        consent_state_string(self.user.consent_state())
    }

    /// Technician signs + seals a `ConsentRequest`. Returns the
    /// sealed envelope bytes. After this call the technician's state
    /// advances to `Requested`.
    #[wasm_bindgen(js_name = technicianSignRequest)]
    pub fn technician_sign_request(
        &mut self,
        scope: u8,
        reason: String,
        valid_seconds: u64,
    ) -> Result<Vec<u8>, JsError> {
        let scope = scope_from_u8(scope)
            .ok_or_else(|| JsError::new("invalid ConsentScope value (0..=3)"))?;
        let now = js_sys::Date::now() as u64 / 1000;
        let request_id = self.next_request_id;
        let core = ConsentRequestCore {
            request_id,
            requester_pubkey: self.tech_sk.verifying_key().to_bytes(),
            session_fingerprint: [0; 32], // overwritten by sign_consent_request
            valid_until: now + valid_seconds,
            scope,
            reason,
            causal_binding: None,
        };
        let req = self
            .tech
            .sign_consent_request(core, &self.tech_sk)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let envelope = seal_consent_request(&req, &mut self.tech)
            .map_err(|e| JsError::new(&e.to_string()))?;
        self.tech
            .observe_consent(ConsentEvent::Request { request_id })
            .map_err(|v| JsError::new(&v.to_string()))?;
        self.next_request_id += 1;
        Ok(envelope)
    }

    /// End-user opens a consent request, verifies the signature, and
    /// returns a JS object with `{ request_id, requester_pubkey_hex,
    /// valid_until, scope, reason, verified }`. Also advances the
    /// end-user's consent state to `Requested`.
    #[wasm_bindgen(js_name = endUserOpenRequest)]
    pub fn end_user_open_request(&mut self, envelope: &[u8]) -> Result<JsValue, JsError> {
        let req = open_consent_request(envelope, &mut self.user)
            .map_err(|e| JsError::new(&e.to_string()))?;
        // Session-bound verify: checks signature AND HKDF fingerprint.
        let verified = self.user.verify_consent_request(&req, None);
        self.user
            .observe_consent(ConsentEvent::Request {
                request_id: req.core.request_id,
            })
            .map_err(|v| JsError::new(&v.to_string()))?;

        let obj = js_sys::Object::new();
        set_field(&obj, "request_id", JsValue::from(req.core.request_id as f64))?;
        set_field(
            &obj,
            "requester_pubkey_hex",
            JsValue::from_str(&hex::encode(req.core.requester_pubkey)),
        )?;
        set_field(
            &obj,
            "valid_until",
            JsValue::from(req.core.valid_until as f64),
        )?;
        set_field(
            &obj,
            "scope",
            JsValue::from_str(scope_string(&req.core.scope)),
        )?;
        set_field(&obj, "reason", JsValue::from_str(&req.core.reason))?;
        set_field(&obj, "verified", JsValue::from_bool(verified))?;
        Ok(obj.into())
    }

    /// End-user signs + seals a `ConsentResponse` and advances local
    /// state accordingly. Returns the sealed envelope bytes.
    #[wasm_bindgen(js_name = endUserSignResponse)]
    pub fn end_user_sign_response(
        &mut self,
        request_id: u64,
        approved: bool,
        reason: String,
    ) -> Result<Vec<u8>, JsError> {
        let core = ConsentResponseCore {
            request_id,
            responder_pubkey: self.user_sk.verifying_key().to_bytes(),
            session_fingerprint: [0; 32], // overwritten
            approved,
            reason,
        };
        let resp = self
            .user
            .sign_consent_response(core, &self.user_sk)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let envelope = seal_consent_response(&resp, &mut self.user)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let event = if approved {
            ConsentEvent::ResponseApproved { request_id }
        } else {
            ConsentEvent::ResponseDenied { request_id }
        };
        self.user
            .observe_consent(event)
            .map_err(|v| JsError::new(&v.to_string()))?;
        Ok(envelope)
    }

    /// Technician opens the response, verifies, advances state.
    /// Returns `{ request_id, responder_pubkey_hex, approved, reason,
    /// verified }`.
    #[wasm_bindgen(js_name = technicianOpenResponse)]
    pub fn technician_open_response(&mut self, envelope: &[u8]) -> Result<JsValue, JsError> {
        let resp = open_consent_response(envelope, &mut self.tech)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let verified = self.tech.verify_consent_response(&resp, None);
        let event = if resp.core.approved {
            ConsentEvent::ResponseApproved {
                request_id: resp.core.request_id,
            }
        } else {
            ConsentEvent::ResponseDenied {
                request_id: resp.core.request_id,
            }
        };
        self.tech
            .observe_consent(event)
            .map_err(|v| JsError::new(&v.to_string()))?;

        let obj = js_sys::Object::new();
        set_field(&obj, "request_id", JsValue::from(resp.core.request_id as f64))?;
        set_field(
            &obj,
            "responder_pubkey_hex",
            JsValue::from_str(&hex::encode(resp.core.responder_pubkey)),
        )?;
        set_field(&obj, "approved", JsValue::from_bool(resp.core.approved))?;
        set_field(&obj, "reason", JsValue::from_str(&resp.core.reason))?;
        set_field(&obj, "verified", JsValue::from_bool(verified))?;
        Ok(obj.into())
    }

    /// Technician seals an application frame (only succeeds once the
    /// ceremony is `Approved`).
    #[wasm_bindgen(js_name = technicianSealFrame)]
    pub fn technician_seal_frame(
        &mut self,
        frame_id: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let now = js_sys::Date::now() as u64;
        let frame = Frame {
            frame_id,
            timestamp_ms: now,
            payload: payload.to_vec(),
        };
        seal_frame(&frame, &mut self.tech).map_err(|e| JsError::new(&e.to_string()))
    }

    /// End-user signs + seals a `ConsentRevocation` and advances local
    /// state to `Revoked`. Returns the sealed envelope.
    #[wasm_bindgen(js_name = endUserRevoke)]
    pub fn end_user_revoke(&mut self, request_id: u64, reason: String) -> Result<Vec<u8>, JsError> {
        let now = js_sys::Date::now() as u64 / 1000;
        let core = ConsentRevocationCore {
            request_id,
            revoker_pubkey: self.user_sk.verifying_key().to_bytes(),
            session_fingerprint: [0; 32], // overwritten
            issued_at: now,
            reason,
        };
        let rev = self
            .user
            .sign_consent_revocation(core, &self.user_sk)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let envelope = seal_consent_revocation(&rev, &mut self.user)
            .map_err(|e| JsError::new(&e.to_string()))?;
        self.user
            .observe_consent(ConsentEvent::Revocation { request_id })
            .map_err(|v| JsError::new(&v.to_string()))?;
        Ok(envelope)
    }

    /// Technician opens a revocation and advances state to `Revoked`.
    #[wasm_bindgen(js_name = technicianOpenRevocation)]
    pub fn technician_open_revocation(&mut self, envelope: &[u8]) -> Result<JsValue, JsError> {
        let rev = open_consent_revocation(envelope, &mut self.tech)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let verified = self.tech.verify_consent_revocation(&rev, None);
        self.tech
            .observe_consent(ConsentEvent::Revocation {
                request_id: rev.core.request_id,
            })
            .map_err(|v| JsError::new(&v.to_string()))?;

        let obj = js_sys::Object::new();
        set_field(&obj, "request_id", JsValue::from(rev.core.request_id as f64))?;
        set_field(&obj, "issued_at", JsValue::from(rev.core.issued_at as f64))?;
        set_field(&obj, "reason", JsValue::from_str(&rev.core.reason))?;
        set_field(&obj, "verified", JsValue::from_bool(verified))?;
        Ok(obj.into())
    }
}

impl Default for WasmConsentCeremony {
    fn default() -> Self {
        Self::new()
    }
}

fn scope_from_u8(v: u8) -> Option<ConsentScope> {
    match v {
        0 => Some(ConsentScope::ScreenOnly),
        1 => Some(ConsentScope::ScreenAndInput),
        2 => Some(ConsentScope::ScreenInputFiles),
        3 => Some(ConsentScope::Interactive),
        _ => None,
    }
}

fn scope_string(s: &ConsentScope) -> &'static str {
    match s {
        ConsentScope::ScreenOnly => "Screen only",
        ConsentScope::ScreenAndInput => "Screen + input",
        ConsentScope::ScreenInputFiles => "Screen + input + files",
        ConsentScope::Interactive => "Full interactive",
    }
}

fn consent_state_string(s: ConsentState) -> String {
    match s {
        ConsentState::LegacyBypass => "LegacyBypass",
        ConsentState::AwaitingRequest => "AwaitingRequest",
        ConsentState::Requested => "Requested",
        ConsentState::Approved => "Approved",
        ConsentState::Denied => "Denied",
        ConsentState::Revoked => "Revoked",
    }
    .to_string()
}

// ─── Viewer MVP loopback (for www/viewer.html) ────────────────────────

/// Paired sender+receiver sessions + consent already-approved, so the
/// viewer page can focus on frame/input traffic rather than ceremony.
#[wasm_bindgen]
pub struct WasmViewer {
    sender: Session,
    receiver: Session,
    input_seq: u64,
}

#[wasm_bindgen]
impl WasmViewer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let key: [u8; 32] = rand::random();
        // Session::new → LegacyBypass. FRAME/INPUT flow out-of-band
        // (no ceremony needed) — that's what we want for this
        // demo-focused MVP viewer.
        let mut sender = Session::new();
        let mut receiver = Session::new();
        sender.install_key(key);
        receiver.install_key(key);
        Self {
            sender,
            receiver,
            input_seq: 0,
        }
    }

    /// Seal a raw RGBA pixel buffer as a `Frame` on the forward path,
    /// then open on the loopback side. Returns the decoded payload so
    /// JS can render it to a canvas.
    #[wasm_bindgen(js_name = roundTripFrame)]
    pub fn round_trip_frame(
        &mut self,
        frame_id: u64,
        rgba: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let now = js_sys::Date::now() as u64;
        let frame = Frame {
            frame_id,
            timestamp_ms: now,
            payload: rgba.to_vec(),
        };
        let sealed =
            seal_frame(&frame, &mut self.sender).map_err(|e| JsError::new(&e.to_string()))?;
        let opened =
            open_frame(&sealed, &mut self.receiver).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(opened.payload)
    }

    /// Seal a captured input event as an `Input` on the reverse path.
    /// JS passes a UTF-8 JSON-encoded event (e.g., `{"ev":"mousedown",...}`);
    /// we don't interpret it, just seal it.
    #[wasm_bindgen(js_name = roundTripInput)]
    pub fn round_trip_input(&mut self, event_json: &str) -> Result<String, JsError> {
        let now = js_sys::Date::now() as u64;
        let seq = self.input_seq;
        self.input_seq += 1;
        let input = Input {
            sequence: seq,
            timestamp_ms: now,
            payload: event_json.as_bytes().to_vec(),
        };
        let sealed =
            seal_input(&input, &mut self.sender).map_err(|e| JsError::new(&e.to_string()))?;
        let opened =
            open_input(&sealed, &mut self.receiver).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(String::from_utf8(opened.payload).unwrap_or_default())
    }

    /// Total envelopes sealed on each stream (frame / input).
    #[wasm_bindgen(js_name = counters)]
    pub fn counters(&self) -> JsValue {
        let obj = js_sys::Object::new();
        let _ = set_field(
            &obj,
            "nonce_counter",
            JsValue::from(self.sender.nonce_counter() as f64),
        );
        let _ = set_field(&obj, "input_seq", JsValue::from(self.input_seq as f64));
        obj.into()
    }
}

impl Default for WasmViewer {
    fn default() -> Self {
        Self::new()
    }
}
