// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Fuzz target: `ViewerHandshakeHighSec::finish()` on a corrupted, but
//! previously-real, `HostFinalize` envelope.
//!
//! Same rationale and structure as `fuzz_handshake_finish`, for the
//! ML-KEM-1024 + ML-DSA-87 high-security suite -- see that file's module
//! doc comment for the full explanation. The host identity (Ed25519 +
//! ML-DSA-87 + ML-KEM-1024, all more expensive to generate than the
//! standard suite's) is cached in a `OnceLock` for the same reason.
//!
//! `HandshakeMessageHighSec` is private to
//! `xenia_wire::handshake_highsec`; this file defines a
//! structurally-identical shadow enum for the same reason
//! `fuzz_handshake_finish.rs` does.

#![no_main]

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use ml_dsa::{
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner},
    Generate as MlDsaGenerate, MlDsa87, Signature as MlDsaSignatureT,
    SigningKey as MlDsaSigningKey,
};
use ml_kem::{kem::Kem, KeyExport, MlKem1024};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use xenia_wire::handshake_highsec::ViewerHandshakeHighSec;

const ML_KEM_1024_PK_LEN: usize = 1568;
const ML_KEM_1024_CT_LEN: usize = 1568;
const ML_DSA_87_PK_LEN: usize = 2592;
const ML_DSA_87_SIG_LEN: usize = 4627;

const HANDSHAKE_SIGNATURE_CONTEXT_V1: &str = "xenia-handshake-signature-highsec-v1";
const HANDSHAKE_TRANSCRIPT_SCHEMA: &str = "xenia-handshake-transcript-highsec-v1";
const HANDSHAKE_POLICY_PROFILE: &str = "hybrid-pq-transcript-highsec-v1";
const KEM_SUITE_LABEL: &str = "ml-kem-1024-fips203";
const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &str = "ed25519-rfc8032+ml-dsa-87-fips204";
const KDF_SUITE_LABEL: &str = "hkdf-sha256";

#[derive(Serialize, Deserialize)]
enum ShadowHandshakeMessageHighSec {
    HostHello {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_87_PK_LEN],
        #[serde(with = "BigArray")]
        kem_pk: [u8; ML_KEM_1024_PK_LEN],
        nonce: [u8; 32],
        negotiated_context_hash: Option<[u8; 32]>,
    },
    ViewerResponse {
        ed25519_pk: [u8; 32],
        #[serde(with = "BigArray")]
        ml_dsa_pk: [u8; ML_DSA_87_PK_LEN],
        #[serde(with = "BigArray")]
        kem_ct: [u8; ML_KEM_1024_CT_LEN],
        nonce: [u8; 32],
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_87_SIG_LEN],
    },
    HostFinalize {
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        #[serde(with = "BigArray")]
        ml_dsa_signature: [u8; ML_DSA_87_SIG_LEN],
    },
}

struct HostIdentity {
    signing_key: SigningKey,
    ml_dsa_signing_key: MlDsaSigningKey<MlDsa87>,
    kem_pk: [u8; ML_KEM_1024_PK_LEN],
    ed25519_pk: [u8; 32],
    ml_dsa_pk: [u8; ML_DSA_87_PK_LEN],
}

/// See `fuzz_handshake_finish.rs::host_identity` for why this is cached
/// rather than regenerated per-iteration -- doubly worthwhile here since
/// ML-DSA-87/ML-KEM-1024 keygen is more expensive than the standard suite.
fn host_identity() -> &'static HostIdentity {
    static HOST: OnceLock<HostIdentity> = OnceLock::new();
    HOST.get_or_init(|| {
        let signing_key = SigningKey::generate(&mut OsRng);
        let ml_dsa_signing_key = MlDsaSigningKey::<MlDsa87>::generate();
        let (_dk, ek) = MlKem1024::generate_keypair();
        let kem_pk: [u8; ML_KEM_1024_PK_LEN] = ek
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("ml-kem-1024 encoded encapsulation key is always ML_KEM_1024_PK_LEN bytes");
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk: [u8; ML_DSA_87_PK_LEN] = ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-87 encoded verifying key is always ML_DSA_87_PK_LEN bytes");
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
    viewer_ml_dsa_pk: &[u8; ML_DSA_87_PK_LEN],
    kem_ct: &[u8],
    viewer_nonce: &[u8; 32],
    viewer_signature: &[u8; 64],
    viewer_ml_dsa_signature: &[u8; ML_DSA_87_SIG_LEN],
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

/// See `fuzz_handshake_finish.rs::corrupt` -- identical strategy.
fn corrupt(valid: &[u8], data: &[u8]) -> Vec<u8> {
    let Some((&mode, rest)) = data.split_first() else {
        return valid.to_vec();
    };
    match mode % 5 {
        0 => {
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
            let len = rest.first().map_or(0, |&b| b as usize % (valid.len() + 1));
            valid[..len.min(valid.len())].to_vec()
        }
        2 => {
            let mut out = valid.to_vec();
            out.extend_from_slice(rest);
            out
        }
        3 => rest.to_vec(),
        _ => {
            let mut out = Vec::with_capacity(rest.len() + valid.len());
            out.extend_from_slice(rest);
            out.extend_from_slice(valid);
            out
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let host = host_identity();

    let hello = ShadowHandshakeMessageHighSec::HostHello {
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
    let mut viewer = ViewerHandshakeHighSec::new();
    let Ok(response_bytes) = viewer.begin(&hello_bytes) else {
        return;
    };
    let Ok(ShadowHandshakeMessageHighSec::ViewerResponse {
        ed25519_pk: viewer_ed25519_pk,
        ml_dsa_pk: viewer_ml_dsa_pk,
        kem_ct,
        nonce: viewer_nonce,
        signature: viewer_signature,
        ml_dsa_signature: viewer_ml_dsa_signature,
    }) = bincode::deserialize::<ShadowHandshakeMessageHighSec>(&response_bytes)
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
    let host_ml_dsa_sig: MlDsaSignatureT<MlDsa87> = host.ml_dsa_signing_key.sign(&final_transcript);
    let Ok(host_ml_dsa_signature) =
        <[u8; ML_DSA_87_SIG_LEN]>::try_from(host_ml_dsa_sig.encode().as_slice())
    else {
        return;
    };
    let valid_finalize = ShadowHandshakeMessageHighSec::HostFinalize {
        signature: host_signature,
        ml_dsa_signature: host_ml_dsa_signature,
    };
    let Ok(valid_finalize_bytes) = bincode::serialize(&valid_finalize) else {
        return;
    };

    let corrupted = corrupt(&valid_finalize_bytes, data);
    let _ = viewer.finish(&corrupted);
});
