// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Browser-side shadow decoder for Xenia session capabilities V2.
//!
//! The production WASM viewer cannot depend on the separate `xenia-peer`
//! repository, so this module mirrors the capability structs byte-for-byte.
//! It intentionally does not implement native execution; it only recognizes the
//! authenticated advertisement that a later integration tranche can surface to
//! the browser UI/session typestate.

use serde::Deserialize;
use thiserror::Error;

use crate::RawPixelFormat;

/// Must match `xenia_peer_core::capabilities_v2::CAPABILITIES_V2_SCHEMA`.
pub(crate) const CAPABILITIES_V2_SCHEMA: &str = "xenia-session-capabilities-v2";
/// Must match `xenia_peer_core::capabilities_v2::CAPABILITIES_V2_PREFIX`.
pub(crate) const CAPABILITIES_V2_PREFIX: [u8; 17] = [
    b'X', b'C', b'A', b'P', b'V', b'2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];
const INPUT_EVENT_SCHEMA_VERSION: u16 = 2;
const LANE_ENVELOPE_SCHEMA_VERSION: u16 = 1;
const LANE_ENVELOPE_MAGIC: [u8; 4] = *b"XLN1";
const EXEC_PROTOCOL_VERSION: u16 = 1;
const MAX_CONCURRENT_PROCESSES_V1: u16 = 64;

/// Shadow of `xenia_peer_core::advertisement::AdvertisedAudioCodec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[allow(dead_code)]
enum AdvertisedAudioCodecShadow {
    RawPcm,
    Opus,
}

/// Shadow of `xenia_peer_core::advertisement::AudioAdvertisement`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[allow(dead_code)]
struct AudioAdvertisementShadow {
    codecs: Vec<AdvertisedAudioCodecShadow>,
    selected_codec: AdvertisedAudioCodecShadow,
    sample_rate_hz: u32,
    max_channels: u16,
    frame_duration_ms: Vec<u16>,
}

/// Correct V1 shadow, including `input_event_schema_version`.
///
/// The older inline browser shadow accidentally omitted that field and then
/// interpreted the following lane fields at the wrong offsets. The fields were
/// not consumed by UI code, so that drift remained latent. V2 starts from this
/// corrected shape rather than perpetuating it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[allow(dead_code)]
struct RawCapabilitiesV1Shadow {
    frame_id: u64,
    timestamp_ms: u64,
    audio: Option<AudioAdvertisementShadow>,
    video_format: RawPixelFormat,
    telemetry_enabled: bool,
    input_control_enabled: bool,
    clipboard_enabled: bool,
    input_event_schema_version: u16,
    lane_envelope_version: u16,
    lane_envelope_magic: [u8; 4],
}

/// Shadow of `xenia_exec_proto::ExecAdvertisementV1`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ExecAdvertisementV1Shadow {
    pub(crate) protocol_version: u16,
    pub(crate) policy_digest: [u8; 32],
    pub(crate) one_shot_enabled: bool,
    pub(crate) interactive_pty_enabled: bool,
    pub(crate) max_concurrent_processes: u16,
}

impl ExecAdvertisementV1Shadow {
    fn validate(&self) -> Result<(), CapabilitiesV2DecodeError> {
        if self.protocol_version != EXEC_PROTOCOL_VERSION {
            return Err(CapabilitiesV2DecodeError::UnsupportedExecProtocol(
                self.protocol_version,
            ));
        }
        if self.interactive_pty_enabled {
            return Err(CapabilitiesV2DecodeError::UnsupportedInteractivePty);
        }
        if self.max_concurrent_processes > MAX_CONCURRENT_PROCESSES_V1 {
            return Err(CapabilitiesV2DecodeError::ExecConcurrencyTooLarge);
        }
        if self.one_shot_enabled != (self.max_concurrent_processes != 0) {
            return Err(CapabilitiesV2DecodeError::InvalidExecAdvertisement);
        }
        Ok(())
    }
}

/// Shadow of `xenia_peer_core::capabilities_v2::RawCapabilitiesV2`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawCapabilitiesV2Shadow {
    schema: String,
    base: RawCapabilitiesV1Shadow,
    exec: Option<ExecAdvertisementV1Shadow>,
}

/// Small browser-facing result from decoding V2 capabilities.
///
/// Only fields needed for capability authentication/UI gating are surfaced.
/// The browser does not receive an API here to originate execution requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedCapabilitiesV2 {
    pub(crate) frame_id: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) telemetry_enabled: bool,
    pub(crate) input_control_enabled: bool,
    pub(crate) clipboard_enabled: bool,
    pub(crate) exec: Option<ExecAdvertisementV1Shadow>,
}

/// Decode and validate the exact V2 capability payload bytes.
pub(crate) fn decode_capabilities_v2_payload(
    payload: &[u8],
) -> Result<DecodedCapabilitiesV2, CapabilitiesV2DecodeError> {
    if !payload.starts_with(&CAPABILITIES_V2_PREFIX) {
        return Err(CapabilitiesV2DecodeError::MissingPrefix);
    }
    let decoded: RawCapabilitiesV2Shadow =
        bincode::deserialize(&payload[CAPABILITIES_V2_PREFIX.len()..])?;
    if decoded.schema != CAPABILITIES_V2_SCHEMA {
        return Err(CapabilitiesV2DecodeError::UnsupportedSchema);
    }
    if decoded.base.input_event_schema_version != INPUT_EVENT_SCHEMA_VERSION {
        return Err(CapabilitiesV2DecodeError::UnsupportedInputEventSchema(
            decoded.base.input_event_schema_version,
        ));
    }
    if decoded.base.lane_envelope_version != LANE_ENVELOPE_SCHEMA_VERSION
        || decoded.base.lane_envelope_magic != LANE_ENVELOPE_MAGIC
    {
        return Err(CapabilitiesV2DecodeError::UnsupportedLaneEnvelope);
    }
    if let Some(exec) = &decoded.exec {
        exec.validate()?;
    }

    Ok(DecodedCapabilitiesV2 {
        frame_id: decoded.base.frame_id,
        timestamp_ms: decoded.base.timestamp_ms,
        telemetry_enabled: decoded.base.telemetry_enabled,
        input_control_enabled: decoded.base.input_control_enabled,
        clipboard_enabled: decoded.base.clipboard_enabled,
        exec: decoded.exec,
    })
}

/// Browser capability V2 decode/validation failure.
#[derive(Debug, Error)]
pub(crate) enum CapabilitiesV2DecodeError {
    #[error("capabilities payload is not V2")]
    MissingPrefix,
    #[error("unsupported capabilities-v2 schema")]
    UnsupportedSchema,
    #[error("unsupported input-event schema version {0}")]
    UnsupportedInputEventSchema(u16),
    #[error("unsupported lane-envelope contract")]
    UnsupportedLaneEnvelope,
    #[error("unsupported exec protocol version {0}")]
    UnsupportedExecProtocol(u16),
    #[error("interactive PTY is not supported by exec protocol V1")]
    UnsupportedInteractivePty,
    #[error("exec concurrency exceeds protocol V1 ceiling")]
    ExecConcurrencyTooLarge,
    #[error("contradictory exec advertisement")]
    InvalidExecAdvertisement,
    #[error("capabilities-v2 bincode decode failed: {0}")]
    Codec(#[from] bincode::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    enum AdvertisedAudioCodecFixture {
        RawPcm,
    }

    #[derive(Serialize)]
    struct AudioAdvertisementFixture {
        codecs: Vec<AdvertisedAudioCodecFixture>,
        selected_codec: AdvertisedAudioCodecFixture,
        sample_rate_hz: u32,
        max_channels: u16,
        frame_duration_ms: Vec<u16>,
    }

    #[derive(Serialize)]
    struct RawCapabilitiesV1Fixture {
        frame_id: u64,
        timestamp_ms: u64,
        audio: Option<AudioAdvertisementFixture>,
        video_format: RawPixelFormat,
        telemetry_enabled: bool,
        input_control_enabled: bool,
        clipboard_enabled: bool,
        input_event_schema_version: u16,
        lane_envelope_version: u16,
        lane_envelope_magic: [u8; 4],
    }

    #[derive(Serialize)]
    struct ExecAdvertisementFixture {
        protocol_version: u16,
        policy_digest: [u8; 32],
        one_shot_enabled: bool,
        interactive_pty_enabled: bool,
        max_concurrent_processes: u16,
    }

    #[derive(Serialize)]
    struct RawCapabilitiesV2Fixture {
        schema: String,
        base: RawCapabilitiesV1Fixture,
        exec: Option<ExecAdvertisementFixture>,
    }

    fn fixture(exec: Option<ExecAdvertisementFixture>) -> Vec<u8> {
        let typed = RawCapabilitiesV2Fixture {
            schema: CAPABILITIES_V2_SCHEMA.to_string(),
            base: RawCapabilitiesV1Fixture {
                frame_id: 7,
                timestamp_ms: 11,
                audio: Some(AudioAdvertisementFixture {
                    codecs: vec![AdvertisedAudioCodecFixture::RawPcm],
                    selected_codec: AdvertisedAudioCodecFixture::RawPcm,
                    sample_rate_hz: 48_000,
                    max_channels: 2,
                    frame_duration_ms: vec![20],
                }),
                video_format: RawPixelFormat::Passthrough,
                telemetry_enabled: true,
                input_control_enabled: false,
                clipboard_enabled: true,
                input_event_schema_version: INPUT_EVENT_SCHEMA_VERSION,
                lane_envelope_version: LANE_ENVELOPE_SCHEMA_VERSION,
                lane_envelope_magic: LANE_ENVELOPE_MAGIC,
            },
            exec,
        };
        let mut bytes = CAPABILITIES_V2_PREFIX.to_vec();
        bytes.extend_from_slice(&bincode::serialize(&typed).unwrap());
        bytes
    }

    #[test]
    fn decodes_disabled_execution() {
        let decoded = decode_capabilities_v2_payload(&fixture(None)).unwrap();
        assert_eq!(decoded.frame_id, 7);
        assert_eq!(decoded.timestamp_ms, 11);
        assert!(decoded.telemetry_enabled);
        assert!(decoded.clipboard_enabled);
        assert!(decoded.exec.is_none());
    }

    #[test]
    fn decodes_policy_digest_without_enabling_terminal() {
        let decoded = decode_capabilities_v2_payload(&fixture(Some(ExecAdvertisementFixture {
            protocol_version: 1,
            policy_digest: [0xA5; 32],
            one_shot_enabled: true,
            interactive_pty_enabled: false,
            max_concurrent_processes: 1,
        })))
        .unwrap();
        let exec = decoded.exec.unwrap();
        assert_eq!(exec.policy_digest, [0xA5; 32]);
        assert!(exec.one_shot_enabled);
        assert!(!exec.interactive_pty_enabled);
    }

    #[test]
    fn rejects_v1_payload_without_v2_prefix() {
        assert!(matches!(
            decode_capabilities_v2_payload(&[0u8; 64]),
            Err(CapabilitiesV2DecodeError::MissingPrefix)
        ));
    }

    #[test]
    fn rejects_interactive_pty_in_exec_v1() {
        let result = decode_capabilities_v2_payload(&fixture(Some(ExecAdvertisementFixture {
            protocol_version: 1,
            policy_digest: [0u8; 32],
            one_shot_enabled: true,
            interactive_pty_enabled: true,
            max_concurrent_processes: 1,
        })));
        assert!(matches!(
            result,
            Err(CapabilitiesV2DecodeError::UnsupportedInteractivePty)
        ));
    }
}
