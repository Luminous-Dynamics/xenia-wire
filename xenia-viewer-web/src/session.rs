// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Lane-separated session (post-handshake video/audio/telemetry/control
//! traffic) and continuous rekey state machine for the browser viewer.
//!
//! Mirrors `xenia_peer_core::session::LaneSession` and
//! `xenia_peer_core::handshake::SessionEpochState` from scratch -- same
//! constraint as `handshake.rs`: this crate ships standalone and can't
//! depend on the `xenia-peer` repo at runtime. Verified byte-identical
//! against the real native types by `tests/handshake_cross_compat.rs`
//! (dev-dependency only).
//!
//! ## Lane envelope format
//!
//! `XLN1` magic (4 bytes) + lane tag (1 byte: 0=control, 1=video,
//! 2=audio, 3=telemetry) + the raw AEAD-sealed `xenia_wire` envelope.
//! Each lane is an independent `xenia_wire::Session` keyed from a
//! distinct label of the transcript-bound key schedule. Input events
//! and rekey acks are the only things the browser ever seals; both use
//! the control lane's key directly, matching
//! `LaneSession::seal_input_event`/`open_input` on the native side --
//! see that type's doc comment for why input isn't lane-wrapped.

use wasm_bindgen::prelude::*;
use xenia_wire::{Frame, Session as WireSession};

use crate::handshake::derive_labeled_session_key;
use crate::hdc::HdcDecoderState;
use crate::{decode_passthrough, h264, set_field, RawFrameShadow, RawPixelFormat};

const LANE_ENVELOPE_MAGIC: [u8; 4] = *b"XLN1";
const LANE_ENVELOPE_HEADER_LEN: usize = 5;

const LANE_TAG_CONTROL: u8 = 0;
const LANE_TAG_VIDEO: u8 = 1;
const LANE_TAG_AUDIO: u8 = 2;
const LANE_TAG_TELEMETRY: u8 = 3;

const REKEY_CONTEXT_SCHEMA: &str = "xenia-rekey-epoch-context-v1";
const REKEY_CONTROL_KEY_LABEL: &[u8] = b"xenia/rekey/control";
const REKEY_VIDEO_KEY_LABEL: &[u8] = b"xenia/rekey/video";
const REKEY_AUDIO_KEY_LABEL: &[u8] = b"xenia/rekey/audio";
const REKEY_TELEMETRY_KEY_LABEL: &[u8] = b"xenia/rekey/telemetry";

fn to_key(bytes: &[u8]) -> Result<[u8; 32], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new("session key must be exactly 32 bytes"))
}

fn wrap_lane_envelope(tag: u8, sealed: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(LANE_ENVELOPE_HEADER_LEN + sealed.len());
    out.extend_from_slice(&LANE_ENVELOPE_MAGIC);
    out.push(tag);
    out.extend_from_slice(&sealed);
    out
}

fn unwrap_lane_envelope(envelope: &[u8]) -> Result<(u8, &[u8]), JsError> {
    if envelope.len() < LANE_ENVELOPE_HEADER_LEN || envelope[..4] != LANE_ENVELOPE_MAGIC {
        return Err(JsError::new(
            "envelope missing XLN1 lane-envelope prefix (expected a lane-tagged frame)",
        ));
    }
    Ok((envelope[4], &envelope[LANE_ENVELOPE_HEADER_LEN..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Control,
    Video,
    Audio,
    Telemetry,
}

fn lane_from_tag(tag: u8) -> Result<Lane, JsError> {
    match tag {
        LANE_TAG_CONTROL => Ok(Lane::Control),
        LANE_TAG_VIDEO => Ok(Lane::Video),
        LANE_TAG_AUDIO => Ok(Lane::Audio),
        LANE_TAG_TELEMETRY => Ok(Lane::Telemetry),
        other => Err(JsError::new(&format!("unknown lane envelope tag {other}"))),
    }
}

fn lane_name(lane: Lane) -> &'static str {
    match lane {
        Lane::Control => "control",
        Lane::Video => "video",
        Lane::Audio => "audio",
        Lane::Telemetry => "telemetry",
    }
}

// ─── Shadow types for control-lane payloads (Capabilities / Rekey) ────
//
// Same convention as lib.rs's RawFrameShadow/RawPixelFormat: field
// order and variant declaration order must match the upstream
// xenia-peer-core types byte-for-byte under bincode v1.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
enum AdvertisedAudioCodecShadow {
    RawPcm,
    Opus,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
struct AudioAdvertisementShadow {
    codecs: Vec<AdvertisedAudioCodecShadow>,
    selected_codec: AdvertisedAudioCodecShadow,
    sample_rate_hz: u32,
    max_channels: u16,
    frame_duration_ms: Vec<u16>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
struct RawCapabilitiesShadow {
    frame_id: u64,
    timestamp_ms: u64,
    audio: Option<AudioAdvertisementShadow>,
    video_format: RawPixelFormat,
    telemetry_enabled: bool,
    input_control_enabled: bool,
    clipboard_enabled: bool,
    lane_envelope_version: u16,
    lane_envelope_magic: [u8; 4],
}

/// Shadow of `xenia_handshake::RekeyReason`. Declaration order must
/// match the upstream enum exactly (see `RawPixelFormat`'s doc comment
/// for why bincode enum decoding depends on this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
enum RekeyReasonShadow {
    Manual,
    FrameCount,
    ByteCount,
    Time,
    TransportChange,
}

fn reason_name(r: RekeyReasonShadow) -> &'static str {
    match r {
        RekeyReasonShadow::Manual => "manual",
        RekeyReasonShadow::FrameCount => "frame_count",
        RekeyReasonShadow::ByteCount => "byte_count",
        RekeyReasonShadow::Time => "time",
        RekeyReasonShadow::TransportChange => "transport_change",
    }
}

fn reason_from_name(s: &str) -> Result<RekeyReasonShadow, JsError> {
    Ok(match s {
        "manual" => RekeyReasonShadow::Manual,
        "frame_count" => RekeyReasonShadow::FrameCount,
        "byte_count" => RekeyReasonShadow::ByteCount,
        "time" => RekeyReasonShadow::Time,
        "transport_change" => RekeyReasonShadow::TransportChange,
        other => return Err(JsError::new(&format!("unknown rekey reason {other:?}"))),
    })
}

/// Shadow of `xenia_peer_core::frame::RawRekey`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
enum RawRekeyShadow {
    Proposal {
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: RekeyReasonShadow,
        epoch_hash: [u8; 32],
    },
    Ack {
        key_epoch: u64,
        epoch_hash: [u8; 32],
    },
}

/// Shadow of `xenia_peer_core::frame::ClipboardContent`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[allow(dead_code)]
enum ClipboardContentShadow {
    Text(String),
    Cleared,
}

/// Shadow of `xenia_peer_core::frame::RawClipboard` (forward path only --
/// host-to-viewer clipboard updates ride the lane-envelope system as a
/// `PixelFormat::Clipboard` frame; the browser never seals one of these
/// itself, only decodes what the daemon sends).
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)]
struct RawClipboardShadow {
    sequence: u64,
    timestamp_ms: u64,
    content: ClipboardContentShadow,
}

/// Shadow of `xenia_handshake::RekeyEpochContextV1` -- used only to
/// recompute `epoch_hash()` (BLAKE3-256 of the canonical bincode
/// bytes) for validating an inbound proposal.
#[derive(Debug, Clone, serde::Serialize)]
struct RekeyEpochContextV1Shadow {
    schema: String,
    key_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
    reason: RekeyReasonShadow,
}

impl RekeyEpochContextV1Shadow {
    fn epoch_hash(&self) -> Result<[u8; 32], JsError> {
        let bytes = bincode::serialize(self)
            .map_err(|e| JsError::new(&format!("rekey context encode: {e}")))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

/// Lane-separated session: four independent `xenia_wire::Session`s, one
/// per traffic lane, each keyed from a distinct label of the
/// transcript-bound key schedule (`WasmHandshake::finish`'s return
/// value). Mirrors `xenia_peer_core::session::LaneSession`, viewer/
/// open-only side -- this type only ever *seals* input events and
/// rekey acks (both control-lane), never video/audio/telemetry.
#[wasm_bindgen]
pub struct WasmLaneSession {
    control: WireSession,
    video: WireSession,
    audio: WireSession,
    telemetry: WireSession,
    /// HDC delta-decode state for the video lane. Lazily primed by the
    /// first keyframe; a fresh session (or one that never sees an HDC
    /// frame, e.g. passthrough/H.264 codec) just never touches this.
    hdc: HdcDecoderState,
}

#[wasm_bindgen]
impl WasmLaneSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            control: WireSession::new(),
            video: WireSession::new(),
            audio: WireSession::new(),
            telemetry: WireSession::new(),
            hdc: HdcDecoderState::default(),
        }
    }

    /// Install the initial transcript-derived lane keys from
    /// `WasmHandshake::finish`'s returned schedule object (pass its
    /// `control`/`video`/`audio`/`telemetry` fields).
    #[wasm_bindgen(js_name = installSchedule)]
    pub fn install_schedule(
        &mut self,
        control: &[u8],
        video: &[u8],
        audio: &[u8],
        telemetry: &[u8],
    ) -> Result<(), JsError> {
        self.control.install_key(to_key(control)?);
        self.video.install_key(to_key(video)?);
        self.audio.install_key(to_key(audio)?);
        self.telemetry.install_key(to_key(telemetry)?);
        Ok(())
    }
}

impl Default for WasmLaneSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoded clipboard content, mirroring `xenia_peer_core::frame::ClipboardContent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardContent {
    Text(String),
    Cleared,
}

/// Plain-Rust decode result for a lane-enveloped frame -- no `JsValue`
/// touched, so this can run on native test targets (constructing a
/// `JsValue`/`JsError` panics outside a real JS host; see
/// `handshake.rs`'s `begin_inner`/`finish_inner` doc comments for the
/// same constraint). `open_lane_frame_js` is the thin wasm-bindgen
/// wrapper that converts this into the JS object shape.
#[derive(Debug, Clone, PartialEq)]
pub enum OpenedLaneFrame {
    Passthrough {
        frame_id: u64,
        timestamp_ms: u64,
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    },
    Capabilities {
        frame_id: u64,
        timestamp_ms: u64,
        telemetry_enabled: bool,
        input_control_enabled: bool,
        clipboard_enabled: bool,
    },
    /// Host-to-viewer clipboard update (control lane). The reverse
    /// direction (viewer-to-host) isn't wired here -- the browser
    /// Clipboard API's read side needs focus + a permission prompt and
    /// has no change event to poll against, unlike the native viewer's
    /// OS-level clipboard watcher.
    Clipboard {
        frame_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        content: ClipboardContent,
    },
    RekeyProposal {
        frame_id: u64,
        timestamp_ms: u64,
        key_epoch: u64,
        base_transcript_hash: [u8; 32],
        previous_epoch_hash: [u8; 32],
        reason: &'static str,
        epoch_hash: [u8; 32],
    },
    /// H.264 Annex-B access unit (video lane) -- undecoded. Actual
    /// decode happens in the browser's native `VideoDecoder` (WebCodecs),
    /// not here; this just recovers the two things the wire format
    /// doesn't carry that `EncodedVideoChunk`/`configure()` need: a
    /// keyframe flag (scanned for an IDR NAL) and, when this chunk
    /// contains a SPS, a codec string derived from its actual
    /// profile/constraint-flags/level bytes (see `h264.rs`).
    H264 {
        frame_id: u64,
        timestamp_ms: u64,
        is_keyframe: bool,
        /// `Some` only for chunks that contain a SPS NAL (typically
        /// the first keyframe, and any keyframe after a dimension
        /// change) -- present once is enough to configure the decoder.
        codec_string: Option<String>,
        bytes: Vec<u8>,
    },
    /// HDC hybrid tile-delta codec frame (video lane), patched into
    /// this session's persistent HDC canvas and returned fully
    /// decoded as RGBA -- same shape as `Passthrough`. `pts_ms` here
    /// is the codec's own source-time timestamp (from `HdcPacket`),
    /// which may differ slightly from the outer `RawFrame.timestamp_ms`.
    Hdc {
        frame_id: u64,
        timestamp_ms: u64,
        pts_ms: u64,
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    },
    /// Telemetry / audio / anything else this MVP viewer doesn't
    /// decode further (no telemetry panel / WebAudio playback wired
    /// here yet).
    Other {
        lane: &'static str,
        pixel_format: String,
        frame_id: u64,
        timestamp_ms: u64,
    },
}

/// Open a lane-enveloped sealed frame from the daemon and decode it.
/// Native-callable, `JsValue`-free -- see [`OpenedLaneFrame`].
///
/// Reuses `unwrap_lane_envelope`/`lane_from_tag` (which return
/// `Result<_, JsError>`) purely for their `Ok` path; their `Err` path
/// constructs a `JsError`, which -- like the rest of the wasm-bindgen
/// surface -- panics outside a real JS host. That's fine here: this
/// function is only ever called by native tests with well-formed
/// envelopes (the whole point is proving successful decode), never to
/// exercise the malformed-input path.
pub fn open_lane_frame_inner(
    session: &mut WasmLaneSession,
    envelope: &[u8],
) -> Result<OpenedLaneFrame, String> {
    let (tag, sealed) = unwrap_lane_envelope(envelope).map_err(|e| format!("{e:?}"))?;
    let lane = lane_from_tag(tag).map_err(|e| format!("{e:?}"))?;
    let wire = match lane {
        Lane::Control => &mut session.control,
        Lane::Video => &mut session.video,
        Lane::Audio => &mut session.audio,
        Lane::Telemetry => &mut session.telemetry,
    };
    let wire_frame = xenia_wire::open_frame(sealed, wire)
        .map_err(|e| format!("xenia-wire open_frame ({}): {e}", lane_name(lane)))?;
    let raw: RawFrameShadow = bincode::deserialize(&wire_frame.payload)
        .map_err(|e| format!("RawFrame bincode decode: {e}"))?;

    Ok(match raw.pixel_format {
        RawPixelFormat::Passthrough => {
            let (width, height, body) =
                decode_passthrough(&raw.pixels).map_err(|e| format!("{e:?}"))?;
            OpenedLaneFrame::Passthrough {
                frame_id: raw.frame_id,
                timestamp_ms: raw.timestamp_ms,
                width,
                height,
                rgba: body.to_vec(),
            }
        }
        RawPixelFormat::H264 => OpenedLaneFrame::H264 {
            frame_id: raw.frame_id,
            timestamp_ms: raw.timestamp_ms,
            is_keyframe: h264::is_keyframe_chunk(&raw.pixels),
            codec_string: h264::sps_codec_string(&raw.pixels),
            bytes: raw.pixels,
        },
        RawPixelFormat::Hdc => {
            let decoded = session
                .hdc
                .decode(&raw.pixels)
                .map_err(|e| format!("HDC decode: {e}"))?;
            OpenedLaneFrame::Hdc {
                frame_id: raw.frame_id,
                timestamp_ms: raw.timestamp_ms,
                pts_ms: decoded.pts_ms,
                width: decoded.width,
                height: decoded.height,
                rgba: decoded.rgba,
            }
        }
        RawPixelFormat::Capabilities => {
            let caps: RawCapabilitiesShadow = bincode::deserialize(&raw.pixels)
                .map_err(|e| format!("RawCapabilities bincode decode: {e}"))?;
            OpenedLaneFrame::Capabilities {
                frame_id: raw.frame_id,
                timestamp_ms: raw.timestamp_ms,
                telemetry_enabled: caps.telemetry_enabled,
                input_control_enabled: caps.input_control_enabled,
                clipboard_enabled: caps.clipboard_enabled,
            }
        }
        RawPixelFormat::Clipboard => {
            let clip: RawClipboardShadow = bincode::deserialize(&raw.pixels)
                .map_err(|e| format!("RawClipboard bincode decode: {e}"))?;
            OpenedLaneFrame::Clipboard {
                frame_id: raw.frame_id,
                timestamp_ms: raw.timestamp_ms,
                sequence: clip.sequence,
                content: match clip.content {
                    ClipboardContentShadow::Text(s) => ClipboardContent::Text(s),
                    ClipboardContentShadow::Cleared => ClipboardContent::Cleared,
                },
            }
        }
        RawPixelFormat::Rekey => {
            let rekey: RawRekeyShadow = bincode::deserialize(&raw.pixels)
                .map_err(|e| format!("RawRekey bincode decode: {e}"))?;
            match rekey {
                RawRekeyShadow::Proposal {
                    key_epoch,
                    base_transcript_hash,
                    previous_epoch_hash,
                    reason,
                    epoch_hash,
                } => OpenedLaneFrame::RekeyProposal {
                    frame_id: raw.frame_id,
                    timestamp_ms: raw.timestamp_ms,
                    key_epoch,
                    base_transcript_hash,
                    previous_epoch_hash,
                    reason: reason_name(reason),
                    epoch_hash,
                },
                RawRekeyShadow::Ack { .. } => {
                    return Err(
                        "viewer received a rekey Ack (browser only ever sends Acks, never receives them)"
                            .to_string(),
                    );
                }
            }
        }
        other => OpenedLaneFrame::Other {
            lane: lane_name(lane),
            pixel_format: format!("{other:?}"),
            frame_id: raw.frame_id,
            timestamp_ms: raw.timestamp_ms,
        },
    })
}

/// Open a lane-enveloped sealed frame from the daemon and decode it.
/// Returns a JS object; shape depends on `pixel_format`:
///
/// - `"passthrough"` (video lane): `{ lane, pixel_format, frame_id,
///   timestamp_ms, width, height, rgba }`
/// - `"h264"` (video lane): `{ lane, pixel_format, frame_id,
///   timestamp_ms, is_keyframe, codec_string, bytes }` -- undecoded
///   Annex-B bytes; feed `bytes` to a WebCodecs `VideoDecoder` as an
///   `EncodedVideoChunk` (`type: is_keyframe ? "key" : "delta"`).
///   `codec_string` is `null` unless this chunk contains a SPS (use it
///   to `configure()` the decoder the first time it's non-null).
/// - `"hdc"` (video lane): `{ lane, pixel_format, frame_id,
///   timestamp_ms, pts_ms, width, height, rgba }` -- same shape as
///   `"passthrough"` plus `pts_ms` (the HDC codec's own source-time
///   timestamp). The tile-delta patching happens internally against
///   this session's persistent HDC canvas; callers just get back a
///   fully-decoded RGBA frame each time, keyframe or delta alike.
/// - `"capabilities"` (control lane): `{ lane, pixel_format, frame_id,
///   timestamp_ms, telemetry_enabled, input_control_enabled,
///   clipboard_enabled }`
/// - `"rekey"` (control lane, proposal only -- the browser only ever
///   *receives* proposals, never acks): `{ lane, pixel_format,
///   frame_id, timestamp_ms, rekey_kind: "proposal", key_epoch,
///   base_transcript_hash, previous_epoch_hash, reason, epoch_hash }`.
///   Pass these fields straight to `WasmRekeyState.handleProposal`.
/// - anything else (telemetry / audio / …): `{ lane, pixel_format,
///   frame_id, timestamp_ms }` only -- payload decode isn't wired for
///   these lanes in this MVP viewer (no telemetry panel / WebAudio
///   playback here); extend this function if that's needed later.
#[wasm_bindgen(js_name = openLaneFrame)]
pub fn open_lane_frame_js(
    session: &mut WasmLaneSession,
    envelope: &[u8],
) -> Result<JsValue, JsError> {
    let opened = open_lane_frame_inner(session, envelope).map_err(|e| JsError::new(&e))?;

    let obj = js_sys::Object::new();
    match opened {
        OpenedLaneFrame::Passthrough {
            frame_id,
            timestamp_ms,
            width,
            height,
            rgba,
        } => {
            set_field(&obj, "lane", JsValue::from_str("video"))?;
            set_field(&obj, "pixel_format", JsValue::from_str("passthrough"))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
            set_field(&obj, "width", JsValue::from(width as f64))?;
            set_field(&obj, "height", JsValue::from(height as f64))?;
            set_field(
                &obj,
                "rgba",
                js_sys::Uint8Array::from(rgba.as_slice()).into(),
            )?;
        }
        OpenedLaneFrame::H264 {
            frame_id,
            timestamp_ms,
            is_keyframe,
            codec_string,
            bytes,
        } => {
            set_field(&obj, "lane", JsValue::from_str("video"))?;
            set_field(&obj, "pixel_format", JsValue::from_str("h264"))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
            set_field(&obj, "is_keyframe", JsValue::from_bool(is_keyframe))?;
            set_field(
                &obj,
                "codec_string",
                match codec_string {
                    Some(s) => JsValue::from_str(&s),
                    None => JsValue::NULL,
                },
            )?;
            set_field(
                &obj,
                "bytes",
                js_sys::Uint8Array::from(bytes.as_slice()).into(),
            )?;
        }
        OpenedLaneFrame::Hdc {
            frame_id,
            timestamp_ms,
            pts_ms,
            width,
            height,
            rgba,
        } => {
            set_field(&obj, "lane", JsValue::from_str("video"))?;
            set_field(&obj, "pixel_format", JsValue::from_str("hdc"))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
            set_field(&obj, "pts_ms", JsValue::from(pts_ms as f64))?;
            set_field(&obj, "width", JsValue::from(width as f64))?;
            set_field(&obj, "height", JsValue::from(height as f64))?;
            set_field(
                &obj,
                "rgba",
                js_sys::Uint8Array::from(rgba.as_slice()).into(),
            )?;
        }
        OpenedLaneFrame::Capabilities {
            frame_id,
            timestamp_ms,
            telemetry_enabled,
            input_control_enabled,
            clipboard_enabled,
        } => {
            set_field(&obj, "lane", JsValue::from_str("control"))?;
            set_field(&obj, "pixel_format", JsValue::from_str("capabilities"))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
            set_field(
                &obj,
                "telemetry_enabled",
                JsValue::from_bool(telemetry_enabled),
            )?;
            set_field(
                &obj,
                "input_control_enabled",
                JsValue::from_bool(input_control_enabled),
            )?;
            set_field(
                &obj,
                "clipboard_enabled",
                JsValue::from_bool(clipboard_enabled),
            )?;
        }
        OpenedLaneFrame::Clipboard {
            frame_id,
            timestamp_ms,
            sequence,
            content,
        } => {
            set_field(&obj, "lane", JsValue::from_str("control"))?;
            set_field(&obj, "pixel_format", JsValue::from_str("clipboard"))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
            set_field(&obj, "sequence", JsValue::from(sequence as f64))?;
            match content {
                ClipboardContent::Text(text) => {
                    set_field(&obj, "content_kind", JsValue::from_str("text"))?;
                    set_field(&obj, "content_text", JsValue::from_str(&text))?;
                }
                ClipboardContent::Cleared => {
                    set_field(&obj, "content_kind", JsValue::from_str("cleared"))?;
                }
            }
        }
        OpenedLaneFrame::RekeyProposal {
            frame_id,
            timestamp_ms,
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
            epoch_hash,
        } => {
            set_field(&obj, "lane", JsValue::from_str("control"))?;
            set_field(&obj, "pixel_format", JsValue::from_str("rekey"))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
            set_field(&obj, "rekey_kind", JsValue::from_str("proposal"))?;
            // BigInt, not Number -- must match handleProposal's u64
            // (bigint) parameter type, or JS throws on the call.
            set_field(&obj, "key_epoch", JsValue::from(key_epoch))?;
            set_field(
                &obj,
                "base_transcript_hash",
                js_sys::Uint8Array::from(&base_transcript_hash[..]).into(),
            )?;
            set_field(
                &obj,
                "previous_epoch_hash",
                js_sys::Uint8Array::from(&previous_epoch_hash[..]).into(),
            )?;
            set_field(&obj, "reason", JsValue::from_str(reason))?;
            set_field(
                &obj,
                "epoch_hash",
                js_sys::Uint8Array::from(&epoch_hash[..]).into(),
            )?;
        }
        OpenedLaneFrame::Other {
            lane,
            pixel_format,
            frame_id,
            timestamp_ms,
        } => {
            set_field(&obj, "lane", JsValue::from_str(lane))?;
            set_field(&obj, "pixel_format", JsValue::from_str(&pixel_format))?;
            set_field(&obj, "frame_id", JsValue::from(frame_id as f64))?;
            set_field(&obj, "timestamp_ms", JsValue::from(timestamp_ms as f64))?;
        }
    }
    Ok(obj.into())
}

/// Continuous rekey state machine: validates each inbound `RawRekey::
/// Proposal`, derives + installs the new epoch's lane keys, and builds
/// the Ack to send back. Call `handleProposal` again for every
/// subsequent proposal for the life of the session -- rekeys are
/// periodic (every few video frames by default on the daemon), not a
/// one-off post-handshake exchange.
#[wasm_bindgen]
pub struct WasmRekeyState {
    rekey_root_key: [u8; 32],
    current_epoch: u64,
    base_transcript_hash: [u8; 32],
    previous_epoch_hash: [u8; 32],
}

#[wasm_bindgen]
impl WasmRekeyState {
    /// `rekey_root_key` and `transcript_hash` come from
    /// `WasmHandshake::finish`'s returned schedule object (its
    /// `rekey` and `transcript_hash` fields respectively).
    #[wasm_bindgen(constructor)]
    pub fn new(rekey_root_key: &[u8], transcript_hash: &[u8]) -> Result<WasmRekeyState, JsError> {
        let transcript_hash = to_key(transcript_hash)?;
        Ok(Self {
            rekey_root_key: to_key(rekey_root_key)?,
            current_epoch: 0,
            base_transcript_hash: transcript_hash,
            previous_epoch_hash: transcript_hash,
        })
    }

    #[wasm_bindgen(js_name = currentEpoch)]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Validate an inbound Rekey Proposal (pass the matching fields
    /// from `openLaneFrame`'s `rekey_kind === "proposal"` result),
    /// derive and install the new epoch's lane keys into
    /// `lane_session`, advance local epoch state, and return the
    /// sealed + lane-wrapped Ack envelope ready to send back.
    #[wasm_bindgen(js_name = handleProposal)]
    #[allow(clippy::too_many_arguments)]
    pub fn handle_proposal(
        &mut self,
        lane_session: &mut WasmLaneSession,
        key_epoch: u64,
        base_transcript_hash: &[u8],
        previous_epoch_hash: &[u8],
        reason: &str,
        epoch_hash: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let base_transcript_hash = to_key(base_transcript_hash)?;
        let previous_epoch_hash = to_key(previous_epoch_hash)?;
        let epoch_hash = to_key(epoch_hash)?;
        let reason = reason_from_name(reason)?;

        let context = RekeyEpochContextV1Shadow {
            schema: REKEY_CONTEXT_SCHEMA.to_string(),
            key_epoch,
            base_transcript_hash,
            previous_epoch_hash,
            reason,
        };
        if key_epoch != self.current_epoch + 1
            || base_transcript_hash != self.base_transcript_hash
            || previous_epoch_hash != self.previous_epoch_hash
            || context.epoch_hash()? != epoch_hash
        {
            return Err(JsError::new(
                "rekey proposal failed validation (epoch/transcript/hash mismatch) -- possible forged or replayed proposal",
            ));
        }

        let new_control =
            derive_labeled_session_key(&self.rekey_root_key, &epoch_hash, REKEY_CONTROL_KEY_LABEL);
        let new_video =
            derive_labeled_session_key(&self.rekey_root_key, &epoch_hash, REKEY_VIDEO_KEY_LABEL);
        let new_audio =
            derive_labeled_session_key(&self.rekey_root_key, &epoch_hash, REKEY_AUDIO_KEY_LABEL);
        let new_telemetry = derive_labeled_session_key(
            &self.rekey_root_key,
            &epoch_hash,
            REKEY_TELEMETRY_KEY_LABEL,
        );

        // Install the new epoch's keys FIRST, then seal the Ack --
        // the daemon installs its new keys locally right after sending
        // the proposal and waits for the Ack sealed under the NEW
        // control key (matches xenia-viewer's native rekey handling:
        // `session.install_rekey_keys(&keys)` runs before
        // `session.seal_control_frame(&ack)` in both `main.rs`'s
        // CLI-mode and GUI-mode receive loops).
        lane_session.control.install_key(new_control);
        lane_session.video.install_key(new_video);
        lane_session.audio.install_key(new_audio);
        lane_session.telemetry.install_key(new_telemetry);

        // Every sealed frame's wire-level payload is bincode(RawFrame),
        // and RawFrame.pixels is in turn bincode(the specific payload
        // type) -- so the Ack itself must be wrapped in an outer
        // RawFrameShadow before it becomes the wire Frame's payload
        // (see RawFrameShadow's doc comment).
        let ack = RawRekeyShadow::Ack {
            key_epoch,
            epoch_hash,
        };
        let ack_bytes = bincode::serialize(&ack)
            .map_err(|e| JsError::new(&format!("rekey ack encode: {e}")))?;
        let raw_frame = RawFrameShadow {
            frame_id: 0,
            timestamp_ms: 0,
            width: 0,
            height: 0,
            pixel_format: RawPixelFormat::Rekey,
            pixels: ack_bytes,
        };
        let wire_payload = bincode::serialize(&raw_frame)
            .map_err(|e| JsError::new(&format!("rekey ack RawFrame encode: {e}")))?;
        let frame = Frame {
            frame_id: 0,
            timestamp_ms: 0,
            payload: wire_payload,
        };
        let sealed = xenia_wire::seal_frame(&frame, &mut lane_session.control)
            .map_err(|e| JsError::new(&format!("seal rekey ack: {e}")))?;

        self.current_epoch = key_epoch;
        self.previous_epoch_hash = epoch_hash;

        Ok(wrap_lane_envelope(LANE_TAG_CONTROL, sealed))
    }
}
