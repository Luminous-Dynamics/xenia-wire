// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Suppresses Rust's own auto-generated `main` entry symbol, which
// otherwise collides with the one #[wasm_bindgen(start)] generates
// below (confirmed live 2026-07-04: "entry symbol `main` declared
// multiple times" without this).
#![no_main]

//! Leptos CSR viewer for the xenia-peer daemon.
//!
//! Replaces `www/daemon.js`'s hand-written DOM/WebSocket glue. Calls
//! `xenia-viewer-web`'s handshake/session/decode logic directly as
//! plain Rust function calls -- no JS round-trip needed at all, since
//! `open_lane_frame_inner` in particular already returns a plain Rust
//! `OpenedLaneFrame` enum (the `JsValue`-returning `open_lane_frame_js`
//! is a separate wrapper specifically for JS callers; see its own doc
//! comment).
//!
//! Reproduces daemon.js's passthrough/HDC/H.264 rendering path, plus
//! host-to-viewer clipboard sync (write-only -- see the module doc
//! comment on `apply_clipboard_content` for why the reverse direction
//! isn't wired here).

mod h264;

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::Uint8Array;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    BinaryType, CanvasRenderingContext2d, HtmlCanvasElement, ImageData, MessageEvent, WebSocket,
};
use xenia_viewer_web::{ClipboardContent, OpenedLaneFrame, WasmHandshake, WasmLaneSession, WasmRekeyState};

use h264::H264Player;

/// Apply a daemon-originated clipboard update to the browser's clipboard.
/// Write-only: `navigator.clipboard.writeText` needs no special
/// permission in most browsers when called from a user-gesture-adjacent
/// context, unlike `readText` (permission prompt + requires document
/// focus) -- and there's no clipboard "change" event to poll against
/// even if read access were granted. The native viewer's bidirectional
/// OS-level clipboard watching has no real browser equivalent, so the
/// reverse (viewer-to-host) direction isn't wired here.
fn apply_clipboard_content(content: ClipboardContent, ui: UiState) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let text = match content {
        ClipboardContent::Text(text) => text,
        ClipboardContent::Cleared => String::new(),
    };
    let clipboard = window.navigator().clipboard();
    let promise = clipboard.write_text(&text);
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = wasm_bindgen_futures::JsFuture::from(promise).await {
            ui.err.set(format!("clipboard write failed: {e:?}"));
        }
    });
}

const DEFAULT_URL: &str = "ws://127.0.0.1:4747";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnState {
    Idle,
    Handshaking,
    Connected,
    Closed,
}

impl ConnState {
    fn label(self) -> &'static str {
        match self {
            ConnState::Idle => "idle",
            ConnState::Handshaking => "handshaking…",
            ConnState::Connected => "connected",
            ConnState::Closed => "closed",
        }
    }
}

/// Handshake stage, mirroring daemon.js's `handshakeStage`.
enum HandshakeStage {
    AwaitingHello,
    AwaitingFinalize(WasmHandshake),
    Done,
}

/// Mutable connection state captured by the WebSocket's `onmessage`
/// closure. `Rc<RefCell<_>>` rather than Leptos signals for the parts
/// that aren't directly rendered -- these are wasm-bindgen objects
/// with real cryptographic state, not UI state.
struct Connection {
    socket: WebSocket,
    stage: HandshakeStage,
    lane_session: Option<WasmLaneSession>,
    rekey_state: Option<WasmRekeyState>,
    h264_player: Option<H264Player>,
}

#[derive(Clone, Copy)]
struct UiState {
    conn_state: RwSignal<ConnState>,
    frame_count: RwSignal<u64>,
    last_frame: RwSignal<String>,
    err: RwSignal<String>,
    wire_version: RwSignal<String>,
}

fn draw_rgba(
    ctx: &CanvasRenderingContext2d,
    canvas: &HtmlCanvasElement,
    width: u32,
    height: u32,
    rgba: &[u8],
) {
    if canvas.width() != width {
        canvas.set_width(width);
    }
    if canvas.height() != height {
        canvas.set_height(height);
    }
    // ImageData::new_with_u8_clamped_array copies the slice, unlike
    // daemon.js's zero-copy Uint8ClampedArray::view -- acceptable here
    // since correctness-first is the goal for this first Leptos pass,
    // not matching the JS version's micro-optimization.
    let mut rgba = rgba.to_vec();
    if let Ok(image_data) =
        ImageData::new_with_u8_clamped_array_and_sh(wasm_bindgen::Clamped(&mut rgba), width, height)
    {
        // With `web_sys_unstable_apis` enabled (needed for WebCodecs
        // below), web-sys swaps in the newer i32-arg put_image_data
        // overload in place of the stable f64-arg one.
        let _ = ctx.put_image_data(&image_data, 0, 0);
    }
}

fn handle_message(
    conn: &Rc<RefCell<Option<Connection>>>,
    ui: UiState,
    ctx: &CanvasRenderingContext2d,
    canvas: &HtmlCanvasElement,
    bytes: Vec<u8>,
) {
    let mut conn_borrow = conn.borrow_mut();
    let Some(conn_mut) = conn_borrow.as_mut() else {
        return;
    };
    match &mut conn_mut.stage {
        HandshakeStage::AwaitingHello => {
            let mut handshake = WasmHandshake::new();
            match handshake.begin_inner(&bytes) {
                Ok(response) => {
                    let _ = conn_mut.socket.send_with_u8_array(&response);
                    conn_mut.stage = HandshakeStage::AwaitingFinalize(handshake);
                }
                Err(e) => ui.err.set(format!("handshake (HostHello): {e:?}")),
            }
        }
        HandshakeStage::AwaitingFinalize(handshake) => match handshake.finish_inner(&bytes) {
            Ok(schedule) => {
                let mut lane_session = WasmLaneSession::new();
                if let Err(e) = lane_session.install_schedule(
                    &schedule.control,
                    &schedule.video,
                    &schedule.audio,
                    &schedule.telemetry,
                ) {
                    ui.err.set(format!("installSchedule: {e:?}"));
                    return;
                }
                let rekey_state =
                    match WasmRekeyState::new(&schedule.rekey, &schedule.transcript_hash) {
                        Ok(state) => state,
                        Err(e) => {
                            ui.err.set(format!("WasmRekeyState::new: {e:?}"));
                            return;
                        }
                    };
                conn_mut.lane_session = Some(lane_session);
                conn_mut.rekey_state = Some(rekey_state);
                conn_mut.stage = HandshakeStage::Done;
                ui.conn_state.set(ConnState::Connected);
            }
            Err(e) => ui.err.set(format!("handshake (HostFinalize): {e:?}")),
        },
        HandshakeStage::Done => {
            let (Some(lane_session), Some(rekey_state)) = (
                conn_mut.lane_session.as_mut(),
                conn_mut.rekey_state.as_mut(),
            ) else {
                return;
            };
            match xenia_viewer_web::open_lane_frame_inner(lane_session, &bytes) {
                Ok(OpenedLaneFrame::Passthrough {
                    frame_id,
                    width,
                    height,
                    rgba,
                    ..
                }) => {
                    draw_rgba(ctx, canvas, width, height, &rgba);
                    ui.frame_count.update(|n| *n += 1);
                    ui.last_frame
                        .set(format!("{width}×{height} (id {frame_id})"));
                }
                Ok(OpenedLaneFrame::Hdc {
                    frame_id,
                    width,
                    height,
                    rgba,
                    ..
                }) => {
                    draw_rgba(ctx, canvas, width, height, &rgba);
                    ui.frame_count.update(|n| *n += 1);
                    ui.last_frame
                        .set(format!("{width}×{height} (id {frame_id}, hdc)"));
                }
                Ok(OpenedLaneFrame::RekeyProposal {
                    key_epoch,
                    base_transcript_hash,
                    previous_epoch_hash,
                    reason,
                    epoch_hash,
                    ..
                }) => {
                    match rekey_state.handle_proposal(
                        lane_session,
                        key_epoch,
                        &base_transcript_hash,
                        &previous_epoch_hash,
                        reason,
                        &epoch_hash,
                    ) {
                        Ok(ack) => {
                            let _ = conn_mut.socket.send_with_u8_array(&ack);
                        }
                        Err(e) => ui.err.set(format!("rekey: {e:?}")),
                    }
                }
                Ok(OpenedLaneFrame::H264 {
                    is_keyframe,
                    codec_string,
                    bytes,
                    timestamp_ms,
                    ..
                }) => {
                    if conn_mut.h264_player.is_none() {
                        match H264Player::new(ctx.clone(), canvas.clone(), ui) {
                            Ok(player) => conn_mut.h264_player = Some(player),
                            Err(e) => {
                                ui.err.set(format!("VideoDecoder construction: {e:?}"));
                                return;
                            }
                        }
                    }
                    if let Some(player) = conn_mut.h264_player.as_mut()
                        && let Err(e) =
                            player.handle_frame(is_keyframe, codec_string, timestamp_ms, &bytes)
                    {
                        ui.err.set(format!("H264 decode: {e:?}"));
                    }
                }
                Ok(OpenedLaneFrame::Clipboard { content, .. }) => {
                    apply_clipboard_content(content, ui);
                }
                Ok(OpenedLaneFrame::Capabilities { .. } | OpenedLaneFrame::Other { .. }) => {}
                Err(e) => ui.err.set(e),
            }
        }
    }
}

#[component]
fn App() -> impl IntoView {
    let url = RwSignal::new(DEFAULT_URL.to_string());
    let ui = UiState {
        conn_state: RwSignal::new(ConnState::Idle),
        frame_count: RwSignal::new(0u64),
        last_frame: RwSignal::new("–".to_string()),
        err: RwSignal::new("–".to_string()),
        wire_version: RwSignal::new(xenia_viewer_web::wire_version()),
    };
    // Plain Rc<RefCell<_>>, not a Leptos signal: Connection holds
    // wasm-bindgen objects with real cryptographic/socket state, not
    // UI state, and it isn't Send -- Leptos 0.8's default RwSignal
    // storage requires Send+Sync even in single-threaded WASM.
    let connection: Rc<RefCell<Option<Connection>>> = Rc::new(RefCell::new(None));
    let canvas_ref = NodeRef::<leptos::html::Canvas>::new();

    let connect = {
        let connection = connection.clone();
        move |_| {
            let Some(canvas) = canvas_ref.get() else {
                return;
            };
            let canvas: HtmlCanvasElement = canvas.unchecked_into();
            let ctx: CanvasRenderingContext2d = canvas
                .get_context("2d")
                .ok()
                .flatten()
                .unwrap()
                .unchecked_into();

            let Ok(socket) = WebSocket::new(&url.get_untracked()) else {
                ui.err.set("failed to construct WebSocket".to_string());
                return;
            };
            socket.set_binary_type(BinaryType::Arraybuffer);

            *connection.borrow_mut() = Some(Connection {
                socket: socket.clone(),
                stage: HandshakeStage::AwaitingHello,
                lane_session: None,
                rekey_state: None,
                h264_player: None,
            });
            ui.conn_state.set(ConnState::Handshaking);
            ui.err.set("–".to_string());

            let onmessage_conn = connection.clone();
            let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let Ok(buf) = event.data().dyn_into::<js_sys::ArrayBuffer>() else {
                    ui.err.set("message data is not an ArrayBuffer".to_string());
                    return;
                };
                let bytes = Uint8Array::new(&buf).to_vec();
                handle_message(&onmessage_conn, ui, &ctx, &canvas, bytes);
            });
            socket.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            onmessage.forget();

            let onclose = Closure::<dyn FnMut()>::new(move || {
                ui.conn_state.set(ConnState::Closed);
            });
            socket.set_onclose(Some(onclose.as_ref().unchecked_ref()));
            onclose.forget();

            let onerror = Closure::<dyn FnMut()>::new(move || {
                ui.err
                    .set("WebSocket error (see browser console)".to_string());
            });
            socket.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onerror.forget();
        }
    };

    let disconnect = move |_| {
        if let Some(conn) = connection.borrow_mut().take() {
            let _ = conn.socket.close();
        }
        ui.conn_state.set(ConnState::Idle);
        ui.frame_count.set(0);
        ui.last_frame.set("–".to_string());
    };

    view! {
        <header>
            <h1>"Xenia daemon viewer"</h1>
            <small>"Connect to an "<code>"xenia-peer"</code>" daemon's WebSocket endpoint and render its frames in this tab. Pre-alpha (Leptos)."</small>
        </header>
        <div class="controls">
            <label>"ws://"</label>
            <input
                type="text"
                prop:value=move || url.get()
                on:input=move |ev| url.set(event_target_value(&ev))
            />
            <button on:click=connect disabled=move || ui.conn_state.get() == ConnState::Connected>"Connect"</button>
            <button class="danger" on:click=disconnect disabled=move || ui.conn_state.get() != ConnState::Connected>"Disconnect"</button>
        </div>
        <div class="status">
            <span class="kv">"wire: "<b>{move || ui.wire_version.get()}</b></span>
            <span class="kv">"state: "<b>{move || ui.conn_state.get().label()}</b></span>
            <span class="kv">"frames: "<b>{move || ui.frame_count.get()}</b></span>
            <span class="kv">"last: "<b>{move || ui.last_frame.get()}</b></span>
            <span class="kv">"err: "<b class="err">{move || ui.err.get()}</b></span>
        </div>
        <main>
            <canvas node_ref=canvas_ref width="320" height="200"></canvas>
        </main>
        <footer>
            <b>"Xenia"</b>" — sealed RDP wire · pre-alpha · Leptos viewer"
        </footer>
    }
}

// Explicit start marker: verified live 2026-07-04 that a plain `fn
// main()` in this bin-target wasm32-unknown-unknown crate never
// actually ran (the WASM module instantiated cleanly -- no console
// errors, `window.wasmBindings` was populated -- but `document.body`
// stayed exactly as trunk's static template left it, meaning
// mount_to_body never executed). #[wasm_bindgen(start)] makes the JS
// glue call this explicitly on module init instead of relying on
// wasm32-unknown-unknown's implicit (and here, apparently absent)
// bin-target auto-invoke behavior.
#[wasm_bindgen(start)]
fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
