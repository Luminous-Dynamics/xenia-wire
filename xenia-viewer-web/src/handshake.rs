// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Viewer-side PQC handshake (ML-KEM-768 + Ed25519 + ML-DSA-65 +
//! HKDF-SHA-256) for the browser, matching xenia-peer's native
//! `xenia-peer-core::handshake` + `xenia-handshake` byte-for-byte. This
//! crate cannot depend on those crates at runtime (they live in the
//! sibling `xenia-peer` repo, and this crate ships standalone to
//! npm/crates.io as a WASM demo) — instead this module is a from-scratch
//! reimplementation using the exact same algorithm and wire types,
//! verified against the real native implementation by
//! `tests/handshake_cross_compat.rs` (a dev-dependency on
//! `xenia-peer-core`/`xenia-handshake`, never compiled into the shipped
//! wasm artifact).
//!
//! ## Protocol (viewer side only — the browser never hosts)
//!
//! 1. Host sends `HostHello { ed25519_pk, ml_dsa_pk, kem_pk, nonce,
//!    negotiated_context_hash }`.
//! 2. Viewer (`begin`): stores host's identity, generates a fresh nonce,
//!    ML-KEM-768-encapsulates to the host's `kem_pk`, signs a
//!    domain-separated transcript with *both* Ed25519 and ML-DSA-65,
//!    sends back `ViewerResponse`.
//! 3. Host verifies both signatures, decapsulates, derives the root key,
//!    and replies with `HostFinalize { signature, ml_dsa_signature }` over
//!    the finalized transcript.
//! 4. Viewer (`finish`): verifies both of the host's signatures, rebuilds
//!    the canonical transcript, and derives the same 32-byte AEAD session
//!    key the host derived — installed via
//!    [`crate::WasmSession::install_key`].
//!
//! Every signature-bearing message carries both an Ed25519 and an
//! ML-DSA-65 signature over the identical transcript bytes — both must
//! verify (AND composition, no classical-only fallback), matching
//! `xenia-peer-core::handshake`'s native driver. See
//! `docs/crypto/FULL_PQC_MIGRATION_PLAN.md` Stage 2 in the `xenia-peer`
//! repo.
//!
//! The viewer never generates or holds a KEM keypair — only the host does;
//! the viewer only encapsulates to the host's public key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_dsa::{
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    Generate as MlDsaGenerate, MlDsa65, Signature as MlDsaSignatureT,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, B32,
};
use ml_kem::{kem::Encapsulate, ml_kem_768::EncapsulationKey as MlKemEk, TryKeyInit};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

// ─── Wire-compatible constants (must match xenia-handshake exactly) ───

const ML_KEM_768_PK_LEN: usize = 1184;
const ML_KEM_768_CT_LEN: usize = 1088;
/// ML-DSA-65 verifying-key size in bytes (FIPS 204).
const ML_DSA_65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature size in bytes (FIPS 204).
const ML_DSA_65_SIG_LEN: usize = 3309;

const HKDF_SALT: &[u8] = b"xenia-handshake-v1";
const HKDF_INFO: &[u8] = b"xenia-session-key";

const KEM_SUITE_LABEL: &str = "ml-kem-768-fips203";
// Stage 2 (hybrid PQ transcript authentication) labels -- must match
// xenia-handshake's TRANSCRIPT_SIGNATURE_SUITE_LABEL/HANDSHAKE_POLICY_PROFILE
// exactly, since both are bound into the signed transcript bytes.
const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &str = "ed25519-rfc8032+ml-dsa-65-fips204";
const KDF_SUITE_LABEL: &str = "hkdf-sha256";
const HANDSHAKE_POLICY_PROFILE: &str = "hybrid-pq-transcript-v1";
const HANDSHAKE_TRANSCRIPT_SCHEMA: &str = "xenia-handshake-transcript-v1";
const HANDSHAKE_SIGNATURE_CONTEXT_V1: &str = "xenia-handshake-signature-v1";

const SESSION_KEY_SCHEDULE_SCHEMA: &str = "xenia-session-key-schedule-v1";
const SESSION_AEAD_KEY_LABEL: &[u8] = b"xenia/session/aead";
const SESSION_CONTROL_KEY_LABEL: &[u8] = b"xenia/session/control";
const SESSION_VIDEO_KEY_LABEL: &[u8] = b"xenia/session/video";
const SESSION_AUDIO_KEY_LABEL: &[u8] = b"xenia/session/audio";
const SESSION_TELEMETRY_KEY_LABEL: &[u8] = b"xenia/session/telemetry";
const SESSION_REKEY_KEY_LABEL: &[u8] = b"xenia/session/rekey";
const SESSION_CONTEXT_KEY_LABEL: &[u8] = b"xenia/session/context";

// ─── Wire-compatible message shape (must match xenia-peer-core's
//     HandshakeMessage byte-for-byte under bincode v1) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
enum HandshakeMessage {
    HostHello {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        #[serde(with = "BigArray")]
        kem_pk: [u8; ML_KEM_768_PK_LEN],
        nonce: [u8; 32],
        negotiated_context_hash: Option<[u8; 32]>,
    },
    ViewerResponse {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
        #[serde(with = "BigArray")]
        kem_ct: [u8; ML_KEM_768_CT_LEN],
        nonce: [u8; 32],
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
    HostFinalize {
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    },
}

// ─── Wire-compatible transcript (must match xenia-handshake's
//     HandshakeTranscriptV1 field-for-field under bincode v1) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeTranscriptV1 {
    schema: String,
    kem: String,
    transcript_signature: String,
    kdf: String,
    negotiated_context_hash: Option<[u8; 32]>,
    host_ed25519_pk: [u8; 32],
    viewer_ed25519_pk: [u8; 32],
    host_ml_dsa_pk: Vec<u8>,
    viewer_ml_dsa_pk: Vec<u8>,
    host_kem_pk: Vec<u8>,
    kem_ciphertext: Vec<u8>,
    host_nonce: [u8; 32],
    viewer_nonce: [u8; 32],
    viewer_signature: Vec<u8>,
    host_signature: Vec<u8>,
    viewer_ml_dsa_signature: Vec<u8>,
    host_ml_dsa_signature: Vec<u8>,
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("handshake transcript component exceeds u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn signature_context_prefix() -> Vec<u8> {
    let mut out = Vec::new();
    append_len_prefixed(&mut out, HANDSHAKE_SIGNATURE_CONTEXT_V1.as_bytes());
    append_len_prefixed(&mut out, HANDSHAKE_TRANSCRIPT_SCHEMA.as_bytes());
    append_len_prefixed(&mut out, HANDSHAKE_POLICY_PROFILE.as_bytes());
    append_len_prefixed(&mut out, KEM_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut out, TRANSCRIPT_SIGNATURE_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut out, KDF_SUITE_LABEL.as_bytes());
    out
}

fn viewer_signature_transcript(
    hello_bytes: &[u8],
    viewer_ed25519_pk: &[u8; 32],
    viewer_ml_dsa_pk: &[u8; ML_DSA_65_PK_LEN],
    kem_ct: &[u8],
    viewer_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = signature_context_prefix();
    append_len_prefixed(&mut transcript, b"viewer-response");
    append_len_prefixed(&mut transcript, hello_bytes);
    append_len_prefixed(&mut transcript, viewer_ed25519_pk);
    append_len_prefixed(&mut transcript, viewer_ml_dsa_pk);
    append_len_prefixed(&mut transcript, kem_ct);
    append_len_prefixed(&mut transcript, viewer_nonce);
    transcript
}

fn host_signature_transcript(
    hello_bytes: &[u8],
    viewer_ed25519_pk: &[u8; 32],
    viewer_ml_dsa_pk: &[u8; ML_DSA_65_PK_LEN],
    kem_ct: &[u8],
    viewer_nonce: &[u8; 32],
    viewer_signature: &[u8; 64],
    viewer_ml_dsa_signature: &[u8; ML_DSA_65_SIG_LEN],
) -> Vec<u8> {
    let mut transcript = viewer_signature_transcript(
        hello_bytes,
        viewer_ed25519_pk,
        viewer_ml_dsa_pk,
        kem_ct,
        viewer_nonce,
    );
    append_len_prefixed(&mut transcript, b"host-finalize");
    append_len_prefixed(&mut transcript, viewer_signature);
    append_len_prefixed(&mut transcript, viewer_ml_dsa_signature);
    transcript
}

fn hkdf_derive(classical_nonce: &[u8], kem_shared_secret: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(classical_nonce.len() + kem_shared_secret.len());
    ikm.extend_from_slice(classical_nonce);
    ikm.extend_from_slice(kem_shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF-SHA256 32-byte expand cannot fail for 32-byte output");
    okm
}

/// `pub(crate)` so `session.rs` can reuse it for rekey-epoch key
/// derivation (`schedule.rekey` as root, epoch hash as transcript hash,
/// `xenia/rekey/*` labels) -- same HKDF construction, different labels.
pub(crate) fn derive_labeled_session_key(
    root_key: &[u8; 32],
    transcript_hash: &[u8; 32],
    label: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SESSION_KEY_SCHEDULE_SCHEMA.as_bytes()), root_key);
    let mut info = Vec::with_capacity(label.len() + 1 + transcript_hash.len());
    info.extend_from_slice(label);
    info.extend_from_slice(b":");
    info.extend_from_slice(transcript_hash);

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 32-byte expand cannot fail for labeled session key");
    okm
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("expected HostHello message")]
    ExpectedHostHello,
    #[error("expected HostFinalize message")]
    ExpectedHostFinalize,
    #[error("bincode decode/encode failed: {0}")]
    Codec(#[from] bincode::Error),
    #[error("invalid host Ed25519 verifying key")]
    InvalidVerifyingKey,
    #[error("invalid host ML-KEM-768 public key")]
    InvalidKemPublicKey,
    #[error("host signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid host ML-DSA-65 verifying key")]
    InvalidMlDsaVerifyingKey,
    #[error("invalid ML-DSA-65 signature encoding")]
    InvalidMlDsaSignatureEncoding,
    #[error("host ML-DSA-65 signature verification failed")]
    MlDsaSignatureVerificationFailed,
    #[error("called finish() before begin()")]
    NotStarted,
}

/// Parse a raw ML-DSA-65 verifying-key byte array (mirrors
/// `xenia_handshake::HandshakeManager::parse_peer_ml_dsa_public_key`).
fn parse_peer_ml_dsa_public_key(
    bytes: &[u8; ML_DSA_65_PK_LEN],
) -> Result<MlDsaVerifyingKey<MlDsa65>, HandshakeError> {
    let encoded = MlDsaEncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice())
        .map_err(|_| HandshakeError::InvalidMlDsaVerifyingKey)?;
    Ok(MlDsaVerifyingKey::<MlDsa65>::decode(&encoded))
}

/// Verify an ML-DSA-65 signature from a peer's verifying-key bytes
/// (mirrors `xenia_handshake::HandshakeManager::verify_ml_dsa`).
fn verify_ml_dsa(
    peer_pk: &[u8; ML_DSA_65_PK_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA_65_SIG_LEN],
) -> Result<(), HandshakeError> {
    let verifying_key = parse_peer_ml_dsa_public_key(peer_pk)?;
    let encoded_sig = MlDsaEncodedSignature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|_| HandshakeError::InvalidMlDsaSignatureEncoding)?;
    let sig = MlDsaSignatureT::<MlDsa65>::decode(&encoded_sig)
        .ok_or(HandshakeError::InvalidMlDsaSignatureEncoding)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| HandshakeError::MlDsaSignatureVerificationFailed)
}

/// Pending state carried between [`WasmHandshake::begin`] and
/// [`WasmHandshake::finish`].
struct PendingState {
    hello_bytes: Vec<u8>,
    host_ed25519_pk: [u8; 32],
    host_verifying_key: VerifyingKey,
    host_ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
    host_kem_pk: [u8; ML_KEM_768_PK_LEN],
    host_nonce: [u8; 32],
    negotiated_context_hash: Option<[u8; 32]>,
    viewer_nonce: [u8; 32],
    kem_ct: [u8; ML_KEM_768_CT_LEN],
    viewer_ed25519_pk: [u8; 32],
    viewer_ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
    viewer_signature: [u8; 64],
    viewer_ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN],
    root_key: [u8; 32],
}

/// Transcript-bound lane keys, mirroring `xenia_handshake::SessionKeySchedule`
/// field-for-field. `aead` is unused by the lane-based session (each lane has
/// its own key) but kept for parity/potential single-key fallback use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmSessionKeySchedule {
    pub aead: [u8; 32],
    pub control: [u8; 32],
    pub video: [u8; 32],
    pub audio: [u8; 32],
    pub telemetry: [u8; 32],
    pub rekey: [u8; 32],
    pub context: [u8; 32],
    /// Canonical handshake transcript hash. Not part of the native
    /// `SessionKeySchedule` type, but bundled here so the browser can
    /// construct a `WasmRekeyState` (which needs it to validate future
    /// rekey proposals) from this one return value.
    pub transcript_hash: [u8; 32],
    /// BLAKE3 fingerprint of the host's signing identity (Ed25519 ||
    /// ML-DSA-65), byte-identical to native `xenia_handshake`'s
    /// `host_identity_fingerprint`. The browser pins this (localStorage
    /// known-hosts) to detect an active MITM that substituted its own keys
    /// in HostHello -- the browser's counterpart to the native viewer's
    /// `--known-hosts` / `--host-fingerprint`.
    pub host_identity_fingerprint: [u8; 32],
}

impl WasmSessionKeySchedule {
    fn derive(
        root_key: &[u8; 32],
        transcript_hash: [u8; 32],
        host_identity_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            host_identity_fingerprint,
            aead: derive_labeled_session_key(root_key, &transcript_hash, SESSION_AEAD_KEY_LABEL),
            control: derive_labeled_session_key(
                root_key,
                &transcript_hash,
                SESSION_CONTROL_KEY_LABEL,
            ),
            video: derive_labeled_session_key(root_key, &transcript_hash, SESSION_VIDEO_KEY_LABEL),
            audio: derive_labeled_session_key(root_key, &transcript_hash, SESSION_AUDIO_KEY_LABEL),
            telemetry: derive_labeled_session_key(
                root_key,
                &transcript_hash,
                SESSION_TELEMETRY_KEY_LABEL,
            ),
            rekey: derive_labeled_session_key(root_key, &transcript_hash, SESSION_REKEY_KEY_LABEL),
            context: derive_labeled_session_key(
                root_key,
                &transcript_hash,
                SESSION_CONTEXT_KEY_LABEL,
            ),
            transcript_hash,
        }
    }

    /// Build the JS-facing object: `{ aead, control, video, audio,
    /// telemetry, rekey, context, transcript_hash }`, each a `Uint8Array`.
    fn to_js(self) -> Result<JsValue, JsError> {
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
        field(&obj, "aead", &self.aead)?;
        field(&obj, "control", &self.control)?;
        field(&obj, "video", &self.video)?;
        field(&obj, "audio", &self.audio)?;
        field(&obj, "telemetry", &self.telemetry)?;
        field(&obj, "rekey", &self.rekey)?;
        field(&obj, "context", &self.context)?;
        field(&obj, "transcript_hash", &self.transcript_hash)?;
        field(
            &obj,
            "host_identity_fingerprint",
            &self.host_identity_fingerprint,
        )?;
        Ok(obj.into())
    }
}

/// Drives the viewer side of a real PQC handshake against a native
/// `xenia-peer` host. See the module doc comment for the protocol.
#[wasm_bindgen]
pub struct WasmHandshake {
    signing_key: SigningKey,
    ml_dsa_signing_key: MlDsaSigningKey<MlDsa65>,
    pending: Option<PendingState>,
}

#[wasm_bindgen]
impl WasmHandshake {
    /// Generate a fresh viewer Ed25519 + ML-DSA-65 identity for this
    /// session.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            ml_dsa_signing_key: MlDsaSigningKey::<MlDsa65>::generate(),
            pending: None,
        }
    }

    /// Reconstruct a viewer identity from *persisted* seeds — a 32-byte Ed25519
    /// secret and a 32-byte ML-DSA-65 seed — instead of generating fresh keys.
    /// Derivation mirrors the native `HandshakeManager::from_identity_seeds`
    /// exactly, so the same two seeds yield the same public identity on both
    /// sides. This lets the operator console drive the handshake with its
    /// *enrolled* operator key (the console already persists these seeds), so
    /// the handshake authenticates the operator — see xenia-peer
    /// `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`.
    #[wasm_bindgen(js_name = fromIdentity)]
    pub fn from_identity(
        ed25519_secret: &[u8],
        ml_dsa_seed: &[u8],
    ) -> Result<WasmHandshake, JsError> {
        let ed: [u8; 32] = ed25519_secret
            .try_into()
            .map_err(|_| JsError::new("ed25519_secret must be exactly 32 bytes"))?;
        let ml: [u8; 32] = ml_dsa_seed
            .try_into()
            .map_err(|_| JsError::new("ml_dsa_seed must be exactly 32 bytes"))?;
        let seed: B32 = ml.into();
        Ok(Self {
            signing_key: SigningKey::from_bytes(&ed),
            ml_dsa_signing_key: MlDsaSigningKey::<MlDsa65>::from_seed(&seed),
            pending: None,
        })
    }

    /// Process the host's `HostHello` envelope; returns the `ViewerResponse`
    /// envelope bytes to send back over the transport.
    #[wasm_bindgen(js_name = begin)]
    pub fn begin(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        self.begin_inner(hello_bytes).map_err(js_error)
    }

    /// Process the host's `HostFinalize` envelope; returns the full
    /// transcript-bound lane key schedule (`{ aead, control, video, audio,
    /// telemetry, rekey, context }`, each a 32-byte `Uint8Array`) on
    /// success. Install the per-lane keys into a `WasmLaneSession` via
    /// `installSchedule`.
    #[wasm_bindgen(js_name = finish)]
    pub fn finish(&mut self, finalize_bytes: &[u8]) -> Result<JsValue, JsError> {
        self.finish_inner(finalize_bytes).map_err(js_error)?.to_js()
    }
}

impl Default for WasmHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmHandshake {
    /// Pure-Rust, JS-boundary-free version of [`WasmHandshake::begin`] —
    /// used directly by native tests (`JsError` construction needs a real
    /// JS host and panics on native targets).
    pub fn begin_inner(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let hello: HandshakeMessage = bincode::deserialize(hello_bytes)?;
        let HandshakeMessage::HostHello {
            ed25519_pk,
            ml_dsa_pk: host_ml_dsa_pk,
            kem_pk,
            nonce: host_nonce,
            negotiated_context_hash,
        } = hello
        else {
            return Err(HandshakeError::ExpectedHostHello);
        };

        let host_verifying_key = VerifyingKey::from_bytes(&ed25519_pk)
            .map_err(|_| HandshakeError::InvalidVerifyingKey)?;
        // Validate eagerly so a malformed host key fails at begin() rather
        // than surfacing later as a signature-verification failure.
        parse_peer_ml_dsa_public_key(&host_ml_dsa_pk)?;

        let viewer_nonce = rand::random::<[u8; 32]>();

        let ek: MlKemEk = <MlKemEk as TryKeyInit>::new_from_slice(&kem_pk)
            .map_err(|_| HandshakeError::InvalidKemPublicKey)?;
        let (kem_ct, shared) = <MlKemEk as Encapsulate>::encapsulate(&ek);
        let kem_ct: [u8; ML_KEM_768_CT_LEN] = kem_ct
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::InvalidKemPublicKey)?;

        let viewer_ed25519_pk = self.signing_key.verifying_key().to_bytes();
        let viewer_ml_dsa_pk: [u8; ML_DSA_65_PK_LEN] = self
            .ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-65 encoded verifying key is always ML_DSA_65_PK_LEN bytes");

        let transcript = viewer_signature_transcript(
            hello_bytes,
            &viewer_ed25519_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );
        let viewer_signature = self.signing_key.sign(&transcript).to_bytes();
        let viewer_ml_dsa_signature: [u8; ML_DSA_65_SIG_LEN] = {
            let sig: MlDsaSignatureT<MlDsa65> = self.ml_dsa_signing_key.sign(&transcript);
            sig.encode()
                .as_slice()
                .try_into()
                .expect("ml-dsa-65 encoded signature is always ML_DSA_65_SIG_LEN bytes")
        };

        let mut combined_nonce = [0u8; 64];
        combined_nonce[..32].copy_from_slice(&host_nonce);
        combined_nonce[32..].copy_from_slice(&viewer_nonce);
        let root_key = hkdf_derive(&combined_nonce, shared.as_slice());

        self.pending = Some(PendingState {
            hello_bytes: hello_bytes.to_vec(),
            host_ed25519_pk: ed25519_pk,
            host_verifying_key,
            host_ml_dsa_pk,
            host_kem_pk: kem_pk,
            host_nonce,
            negotiated_context_hash,
            viewer_nonce,
            kem_ct,
            viewer_ed25519_pk,
            viewer_ml_dsa_pk,
            viewer_signature,
            viewer_ml_dsa_signature,
            root_key,
        });

        let response = HandshakeMessage::ViewerResponse {
            ed25519_pk: viewer_ed25519_pk,
            ml_dsa_pk: viewer_ml_dsa_pk,
            kem_ct,
            nonce: viewer_nonce,
            signature: viewer_signature,
            ml_dsa_signature: viewer_ml_dsa_signature,
        };
        Ok(bincode::serialize(&response)?)
    }

    /// Pure-Rust, JS-boundary-free version of [`WasmHandshake::finish`] —
    /// used directly by native tests (`JsError` construction needs a real
    /// JS host and panics on native targets).
    pub fn finish_inner(
        &mut self,
        finalize_bytes: &[u8],
    ) -> Result<WasmSessionKeySchedule, HandshakeError> {
        let state = self.pending.take().ok_or(HandshakeError::NotStarted)?;

        let finalize: HandshakeMessage = bincode::deserialize(finalize_bytes)?;
        let HandshakeMessage::HostFinalize {
            signature: host_sig_bytes,
            ml_dsa_signature: host_ml_dsa_sig_bytes,
        } = finalize
        else {
            return Err(HandshakeError::ExpectedHostFinalize);
        };

        let final_transcript = host_signature_transcript(
            &state.hello_bytes,
            &state.viewer_ed25519_pk,
            &state.viewer_ml_dsa_pk,
            &state.kem_ct,
            &state.viewer_nonce,
            &state.viewer_signature,
            &state.viewer_ml_dsa_signature,
        );
        let host_sig = Signature::from_bytes(&host_sig_bytes);
        state
            .host_verifying_key
            .verify(&final_transcript, &host_sig)
            .map_err(|_| HandshakeError::SignatureVerificationFailed)?;
        // Both Ed25519 and ML-DSA-65 must verify -- no classical-only
        // fallback, matching the native handshake driver.
        verify_ml_dsa(
            &state.host_ml_dsa_pk,
            &final_transcript,
            &host_ml_dsa_sig_bytes,
        )?;

        let transcript = HandshakeTranscriptV1 {
            schema: HANDSHAKE_TRANSCRIPT_SCHEMA.to_string(),
            kem: KEM_SUITE_LABEL.to_string(),
            transcript_signature: TRANSCRIPT_SIGNATURE_SUITE_LABEL.to_string(),
            kdf: KDF_SUITE_LABEL.to_string(),
            negotiated_context_hash: state.negotiated_context_hash,
            host_ed25519_pk: state.host_ed25519_pk,
            viewer_ed25519_pk: state.viewer_ed25519_pk,
            host_ml_dsa_pk: state.host_ml_dsa_pk.to_vec(),
            viewer_ml_dsa_pk: state.viewer_ml_dsa_pk.to_vec(),
            host_kem_pk: state.host_kem_pk.to_vec(),
            kem_ciphertext: state.kem_ct.to_vec(),
            host_nonce: state.host_nonce,
            viewer_nonce: state.viewer_nonce,
            viewer_signature: state.viewer_signature.to_vec(),
            host_signature: host_sig_bytes.to_vec(),
            viewer_ml_dsa_signature: state.viewer_ml_dsa_signature.to_vec(),
            host_ml_dsa_signature: host_ml_dsa_sig_bytes.to_vec(),
        };
        let transcript_bytes = bincode::serialize(&transcript)?;
        let transcript_hash = *blake3::hash(&transcript_bytes).as_bytes();

        let host_fingerprint =
            host_identity_fingerprint(&state.host_ed25519_pk, &state.host_ml_dsa_pk);

        Ok(WasmSessionKeySchedule::derive(
            &state.root_key,
            transcript_hash,
            host_fingerprint,
        ))
    }
}

/// BLAKE3-256 fingerprint binding a peer's full signing identity: its Ed25519
/// and ML-DSA-65 public keys together. Byte-identical to native
/// `xenia_handshake::host_identity_fingerprint` -- the same domain tag and
/// input order -- so a value pinned by a native viewer and one pinned by the
/// browser refer to the same host.
fn host_identity_fingerprint(ed25519_pk: &[u8; 32], ml_dsa_pk: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia-host-identity-fingerprint-v1");
    hasher.update(ed25519_pk);
    hasher.update(ml_dsa_pk);
    *hasher.finalize().as_bytes()
}

fn js_error(e: HandshakeError) -> JsError {
    JsError::new(&format!("xenia handshake: {e}"))
}
