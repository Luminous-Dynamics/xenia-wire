// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Minimal Annex-B NAL-unit parsing to support WebCodecs `VideoDecoder`
//! playback of the daemon's H.264 stream (M4.1b).
//!
//! `xenia_video::h264::H264Encoder` emits Annex-B (start-code-prefixed)
//! packets -- "what a standard H.264 decoder or WebCodecs expects" per
//! that module's own doc comment. The actual video decode itself runs
//! in the browser's `VideoDecoder` (a native browser API, not
//! something to reimplement in Rust/WASM), but two things the wire
//! format doesn't carry need real parsing on this side:
//!
//! 1. **Keyframe detection.** `EncodedPacket::is_keyframe` never makes
//!    it onto the wire (`RawFrame::encoded` only carries frame_id/
//!    timestamp/dimensions/pixel_format/bytes) -- so `EncodedVideoChunk`'s
//!    required `type: "key" | "delta"` has to be recovered by scanning
//!    NAL unit types for an IDR slice (type 5).
//! 2. **Codec string for `VideoDecoder.configure()`.** WebCodecs needs
//!    an exact `avc1.PPCCLL` (profile/constraint-flags/level, each one
//!    hex byte) string up front, matching the *actual* stream --
//!    guessing wrong makes `configure()` throw or decode garbage. The
//!    real values are the first three bytes of a Sequence Parameter
//!    Set NAL's payload (RFC 6184 / ITU-T H.264 §7.3.2.1.1), so this
//!    module extracts them directly from the first SPS the daemon
//!    actually sends instead of hardcoding a profile.

/// One parsed NAL unit: its type (low 5 bits of the header byte, per
/// H.264 §7.4.1) and its payload (everything after that single header
/// byte, still Annex-B framed -- callers needing RBSP would have to
/// further remove emulation-prevention bytes, but neither consumer
/// below needs that).
struct Nal<'a> {
    nal_type: u8,
    payload: &'a [u8],
}

/// Split an Annex-B byte stream into NAL units by scanning start codes
/// (`00 00 01` or `00 00 00 01`). Best-effort: a malformed/truncated
/// stream just yields fewer NALs, never panics or errors -- this is
/// only used for keyframe detection and opportunistic SPS parsing,
/// both of which degrade gracefully to "unknown" rather than needing
/// to be authoritative.
///
/// Single forward pass: for each `00 00 01` match, the start code
/// itself begins either right there (3-byte form) or one byte earlier
/// if that byte is also `0x00` (4-byte form) -- recording each NAL's
/// *content*-start position (right after the header byte) alongside
/// its *start-code*-begin position lets every NAL's end be derived
/// exactly as "the next NAL's start-code-begin position" (or
/// `bytes.len()` for the last one), with no ambiguity from a stray
/// zero byte inside a payload.
fn iter_annexb_nals(bytes: &[u8]) -> impl Iterator<Item = Nal<'_>> {
    let mut marks = Vec::new(); // (start_code_begin, nal_type, content_start)
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 1 {
            let start_code_begin = if i > 0 && bytes[i - 1] == 0 { i - 1 } else { i };
            let content_start = i + 3;
            if content_start < bytes.len() {
                marks.push((
                    start_code_begin,
                    bytes[content_start] & 0x1F,
                    content_start + 1,
                ));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let len = bytes.len();
    (0..marks.len()).filter_map(move |idx| {
        let (_, nal_type, content_start) = marks[idx];
        let end = marks.get(idx + 1).map(|(sc, ..)| *sc).unwrap_or(len);
        if content_start > end {
            return None;
        }
        Some(Nal {
            nal_type,
            payload: &bytes[content_start..end],
        })
    })
}

/// `true` if any NAL in this Annex-B chunk is an IDR slice (type 5).
/// SPS/PPS (types 7/8), which typically precede an IDR in the same
/// keyframe access unit, are not treated as sufficient on their own --
/// only an actual IDR slice makes the access unit decodable standalone.
pub(crate) fn is_keyframe_chunk(bytes: &[u8]) -> bool {
    iter_annexb_nals(bytes).any(|nal| nal.nal_type == 5)
}

/// Extract a WebCodecs `avc1.PPCCLL` codec string from the first SPS
/// (NAL type 7) found in this chunk, or `None` if there isn't one.
/// `PP`/`CC`/`LL` are `profile_idc`, the constraint-flags/reserved
/// byte, and `level_idc` -- the first three bytes of the SPS RBSP,
/// per H.264 §7.3.2.1.1. Assumes no emulation-prevention byte
/// (`00 00 03`) falls within these first three bytes, which holds for
/// every profile/level combination in practice (that escape sequence
/// only exists to avoid accidental start-code-like patterns, which
/// can't occur in these particular byte positions for valid profile/
/// level values).
pub(crate) fn sps_codec_string(bytes: &[u8]) -> Option<String> {
    let sps = iter_annexb_nals(bytes).find(|nal| nal.nal_type == 7)?;
    if sps.payload.len() < 3 {
        return None;
    }
    Some(format!(
        "avc1.{:02x}{:02x}{:02x}",
        sps.payload[0], sps.payload[1], sps.payload[2]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annexb(nals: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (nal_type, payload) in nals {
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.push(*nal_type); // forbidden_zero_bit=0, nal_ref_idc=0
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn detects_idr_keyframe() {
        let bytes = annexb(&[(7, &[0x64, 0x00, 0x28]), (5, &[0xAB, 0xCD])]);
        assert!(is_keyframe_chunk(&bytes));
    }

    #[test]
    fn non_idr_delta_is_not_a_keyframe() {
        let bytes = annexb(&[(1, &[0xAB, 0xCD, 0xEF])]);
        assert!(!is_keyframe_chunk(&bytes));
    }

    #[test]
    fn extracts_codec_string_from_sps() {
        // profile_idc=0x64 (High), constraint flags=0x00, level_idc=0x28 (4.0)
        let bytes = annexb(&[(7, &[0x64, 0x00, 0x28, 0xAC]), (5, &[0x11])]);
        assert_eq!(sps_codec_string(&bytes), Some("avc1.640028".to_string()));
    }

    #[test]
    fn no_sps_yields_no_codec_string() {
        let bytes = annexb(&[(1, &[0xAB])]);
        assert_eq!(sps_codec_string(&bytes), None);
    }

    #[test]
    fn multiple_nals_are_all_found() {
        let bytes = annexb(&[(7, &[1, 2, 3]), (8, &[4, 5]), (5, &[6, 7, 8])]);
        let nals: Vec<u8> = iter_annexb_nals(&bytes).map(|n| n.nal_type).collect();
        assert_eq!(nals, vec![7, 8, 5]);
    }
}
