// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `ViewerHandshake::finish()` on a corrupted, but
//! previously-real, `HostFinalize` envelope.
//!
//! `fuzz_handshake_begin` already covers `begin()` on fully arbitrary bytes
//! -- the network-facing entry point for `HostHello`, reached with zero
//! prior state. `finish()` is different: it only runs meaningfully *after*
//! a successful `begin()` populated `ViewerHandshake`'s internal pending
//! state, so pure-random bytes handed to a freshly-constructed
//! `ViewerHandshake` reject at `NotStarted` before touching any real
//! parsing or signature-verification logic at all.
//!
//! To actually exercise that logic, this harness plays "fake host": it
//! builds a real Ed25519 + ML-DSA-65 + ML-KEM-768 host identity (generated
//! once and cached in a `OnceLock` -- keygen for all three is the expensive
//! part of this harness, and nothing about corruption-fuzzing `finish()`
//! needs a fresh host identity every iteration), encodes a genuinely valid
//! `HostHello`, drives a real `begin()` to get a real `ViewerResponse` and
//! a populated pending state, then assembles a genuinely valid signed
//! `HostFinalize` for that exact exchange -- before finally corrupting it
//! (several different ways, fuzzer-selected) and handing it to `finish()`.
//! Goal: no panic on any corruption of an otherwise-valid final message
//! (transcript rebuild, signature verification, key derivation).
//!
//! `HandshakeMessage` is private to `xenia_wire::handshake`, so this file
//! defines a structurally-identical shadow enum. bincode's derived enum
//! encoding is purely positional (u32 variant index + fields in
//! declaration order), so a field-for-field mirror serializes and
//! deserializes byte-identically to the real type -- the same "shadow
//! type" pattern already used for the WASM viewer's decode-only mirrors of
//! this crate's wire types (see xenia-viewer-web). Likewise, the
//! transcript-construction helpers below are copies of `handshake.rs`'s
//! private `signature_context_prefix`/`host_signature_transcript` -- kept
//! in sync by hand since fuzz targets in this crate don't share code with
//! `src/`.

#![no_main]

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use ml_dsa::{
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner},
    Generate as MlDsaGenerate, MlDsa65, Signature as MlDsaSignatureT,
    SigningKey as MlDsaSigningKey,
};
use ml_kem::{kem::Kem, KeyExport, MlKem768};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use xenia_wire::handshake::ViewerHandshake;

const ML_KEM_768_PK_LEN: usize = 1184;
const ML_KEM_768_CT_LEN: usize = 1088;
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

const HANDSHAKE_SIGNATURE_CONTEXT_V1: &str = "xenia-handshake-signature-v1";
const HANDSHAKE_TRANSCRIPT_SCHEMA: &str = "xenia-handshake-transcript-v1";
const HANDSHAKE_POLICY_PROFILE: &str = "hybrid-pq-transcript-v1";
const KEM_SUITE_LABEL: &str = "ml-kem-768-fips203";
const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &str = "ed25519-rfc8032+ml-dsa-65-fips204";
const KDF_SUITE_LABEL: &str = "hkdf-sha256";

#[derive(Serialize, Deserialize)]
enum ShadowHandshakeMessage {
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

struct HostIdentity {
    signing_key: SigningKey,
    ml_dsa_signing_key: MlDsaSigningKey<MlDsa65>,
    kem_pk: [u8; ML_KEM_768_PK_LEN],
    ed25519_pk: [u8; 32],
    ml_dsa_pk: [u8; ML_DSA_65_PK_LEN],
}

/// Host keygen (Ed25519 + ML-DSA-65 + ML-KEM-768) is the expensive part of
/// this harness. Fixed across the whole fuzzing run rather than
/// regenerated per-iteration: nothing about corruption-fuzzing `finish()`
/// requires a fresh host identity each time, and reusing one gives
/// libFuzzer's coverage-guided mutation a stable target instead of
/// re-randomizing the "valid" backing state on every call.
fn host_identity() -> &'static HostIdentity {
    static HOST: OnceLock<HostIdentity> = OnceLock::new();
    HOST.get_or_init(|| {
        let signing_key = SigningKey::generate(&mut OsRng);
        let ml_dsa_signing_key = MlDsaSigningKey::<MlDsa65>::generate();
        let (_dk, ek) = MlKem768::generate_keypair();
        let kem_pk: [u8; ML_KEM_768_PK_LEN] = ek
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("ml-kem-768 encoded encapsulation key is always ML_KEM_768_PK_LEN bytes");
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk: [u8; ML_DSA_65_PK_LEN] = ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-65 encoded verifying key is always ML_DSA_65_PK_LEN bytes");
        HostIdentity {
            signing_key,
            ml_dsa_signing_key,
            kem_pk,
            ed25519_pk,
            ml_dsa_pk,
        }
    })
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
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
    let mut transcript = Vec::new();
    append_len_prefixed(&mut transcript, HANDSHAKE_SIGNATURE_CONTEXT_V1.as_bytes());
    append_len_prefixed(&mut transcript, HANDSHAKE_TRANSCRIPT_SCHEMA.as_bytes());
    append_len_prefixed(&mut transcript, HANDSHAKE_POLICY_PROFILE.as_bytes());
    append_len_prefixed(&mut transcript, KEM_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut transcript, TRANSCRIPT_SIGNATURE_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut transcript, KDF_SUITE_LABEL.as_bytes());
    append_len_prefixed(&mut transcript, b"viewer-response");
    append_len_prefixed(&mut transcript, hello_bytes);
    append_len_prefixed(&mut transcript, viewer_ed25519_pk);
    append_len_prefixed(&mut transcript, viewer_ml_dsa_pk);
    append_len_prefixed(&mut transcript, kem_ct);
    append_len_prefixed(&mut transcript, viewer_nonce);
    append_len_prefixed(&mut transcript, b"host-finalize");
    append_len_prefixed(&mut transcript, viewer_signature);
    append_len_prefixed(&mut transcript, viewer_ml_dsa_signature);
    transcript
}

/// Corrupt an otherwise-valid `HostFinalize` blob several different ways,
/// fuzzer-selected via `data[0]`, instead of only ever XORing bytes at the
/// front: truncation, trailing-byte append (oversized/trailing-garbage
/// probing), a mid-buffer XOR splice, and wholesale replacement with raw
/// fuzzer bytes (still meaningful here, unlike `fuzz_handshake_begin`,
/// because `finish()` has already consumed real pending state via
/// `pending.take()` by the time it reaches `bincode::deserialize`).
fn corrupt(valid: &[u8], data: &[u8]) -> Vec<u8> {
    let Some((&mode, rest)) = data.split_first() else {
        return valid.to_vec();
    };
    match mode % 5 {
        0 => {
            // Mid-buffer XOR splice at a fuzzer-chosen offset.
            let mut out = valid.to_vec();
            if !out.is_empty() {
                let offset = rest.first().map_or(0, |&b| b as usize % out.len());
                for (i, &b) in rest.iter().enumerate() {
                    let idx = (offset + i) % out.len();
                    out[idx] ^= b;
                }
            }
            out
        }
        1 => {
            // Truncate to a fuzzer-chosen length.
            let len = rest.first().map_or(0, |&b| b as usize % (valid.len() + 1));
            valid[..len.min(valid.len())].to_vec()
        }
        2 => {
            // Append trailing garbage after an otherwise-valid message.
            let mut out = valid.to_vec();
            out.extend_from_slice(rest);
            out
        }
        3 => {
            // Wholesale replace with raw fuzzer bytes -- still reaches
            // finish()'s post-NotStarted logic, unlike fuzzing an
            // unpopulated ViewerHandshake from scratch would.
            rest.to_vec()
        }
        _ => {
            // Prepend a length-prefixed garbage field ahead of the valid
            // bytes, probing bincode's handling of misaligned structure.
            let mut out = Vec::with_capacity(rest.len() + valid.len());
            out.extend_from_slice(rest);
            out.extend_from_slice(valid);
            out
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let host = host_identity();

    let hello = ShadowHandshakeMessage::HostHello {
        ed25519_pk: host.ed25519_pk,
        ml_dsa_pk: host.ml_dsa_pk,
        kem_pk: host.kem_pk,
        nonce: rand::random(),
        negotiated_context_hash: None,
    };
    let Ok(hello_bytes) = bincode::serialize(&hello) else {
        return;
    };

    // --- Real begin(): populates `viewer`'s pending state for real. ---
    let mut viewer = ViewerHandshake::new();
    let Ok(response_bytes) = viewer.begin(&hello_bytes) else {
        return;
    };
    let Ok(ShadowHandshakeMessage::ViewerResponse {
        ed25519_pk: viewer_ed25519_pk,
        ml_dsa_pk: viewer_ml_dsa_pk,
        kem_ct,
        nonce: viewer_nonce,
        signature: viewer_signature,
        ml_dsa_signature: viewer_ml_dsa_signature,
    }) = bincode::deserialize::<ShadowHandshakeMessage>(&response_bytes)
    else {
        return;
    };

    // --- Fake host: a genuinely valid HostFinalize for this exchange. ---
    let final_transcript = host_signature_transcript(
        &hello_bytes,
        &viewer_ed25519_pk,
        &viewer_ml_dsa_pk,
        &kem_ct,
        &viewer_nonce,
        &viewer_signature,
        &viewer_ml_dsa_signature,
    );
    let host_signature = host.signing_key.sign(&final_transcript).to_bytes();
    let host_ml_dsa_sig: MlDsaSignatureT<MlDsa65> = host.ml_dsa_signing_key.sign(&final_transcript);
    let Ok(host_ml_dsa_signature) =
        <[u8; ML_DSA_65_SIG_LEN]>::try_from(host_ml_dsa_sig.encode().as_slice())
    else {
        return;
    };
    let valid_finalize = ShadowHandshakeMessage::HostFinalize {
        signature: host_signature,
        ml_dsa_signature: host_ml_dsa_signature,
    };
    let Ok(valid_finalize_bytes) = bincode::serialize(&valid_finalize) else {
        return;
    };

    let corrupted = corrupt(&valid_finalize_bytes, data);
    let _ = viewer.finish(&corrupted);
});
