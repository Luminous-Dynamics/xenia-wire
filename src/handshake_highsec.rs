// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A high-security parameter-set variant of [`crate::handshake`]'s PQC
//! handshake: **ML-KEM-1024 + Ed25519 + ML-DSA-87** (NIST security category
//! 5), versus [`crate::handshake`]'s ML-KEM-768 + ML-DSA-65 (category 3).
//! Xenia's own `ml-dsa`/`ml-kem` crates already support these larger
//! parameter sets natively -- this module wires them into the identical
//! protocol shape ([`HostHandshakeHighSec`] mirrors the native
//! `xenia_peer_core::handshake::perform_host_handshake_authenticating_peer`
//! host-role driver; [`ViewerHandshakeHighSec`] mirrors
//! [`crate::handshake::ViewerHandshake`]).
//!
//! Unlike [`crate::handshake`] (which implements only the *viewer* role --
//! the *host* role's standard-suite counterpart lives natively in
//! xenia-peer's `xenia_handshake`/`xenia_peer_core::handshake` crates,
//! independently reimplemented and cross-compat tested against this one),
//! this module implements **both** roles in one place. There is no
//! pre-existing native high-security implementation to stay wire-compatible
//! with, so putting both roles here -- this crate already compiles natively
//! *and* to wasm32 -- means the daemon and the console run the literal same
//! code. No duplication, no cross-compat test needed: the byte-identity is
//! structural, not asserted.
//!
//! Suite selection is out-of-band (e.g. a daemon CLI flag with a matching
//! console setting), not negotiated on the wire: [`crate::handshake`] and
//! this module speak different, non-interoperable message shapes (different
//! fixed array sizes), so a mismatched pairing fails to deserialize rather
//! than silently downgrading. That's a deliberate simplicity choice for a
//! first cut -- see `docs/security/SEALED_OPERATOR_CHANNEL_DESIGN.md`.
//!
//! Both suites reuse the exact same downstream machinery -- this module
//! produces the identical [`crate::handshake::SessionKeySchedule`] type the
//! standard suite does, via the same `SessionKeySchedule::derive` HKDF
//! construction -- only the key-establishment step (the handshake itself)
//! differs.
//!
//! ## Protocol
//!
//! Identical in shape to [`crate::handshake`]'s (see that module's doc
//! comment), just with ML-KEM-1024 + ML-DSA-87 in place of ML-KEM-768 +
//! ML-DSA-65: `HostHello` → `ViewerResponse` (signed, KEM-encapsulated) →
//! `HostFinalize` (signed) → both sides derive the identical
//! [`crate::handshake::SessionKeySchedule`].

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_dsa::{
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    Generate as MlDsaGenerate, MlDsa87, Signature as MlDsaSignatureT,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, B32,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_1024::{
        Ciphertext as MlKem1024Ciphertext, DecapsulationKey as MlKemDk1024,
        EncapsulationKey as MlKemEk1024,
    },
    MlKem1024, TryKeyInit,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::Sha256;

use crate::handshake::{HandshakeError, SessionKeySchedule};

// ─── Suite-specific sizes (FIPS 203 / FIPS 204, category-5 parameter sets) ───

const ML_KEM_1024_PK_LEN: usize = 1568;
const ML_KEM_1024_CT_LEN: usize = 1568;
/// ML-DSA-87 verifying-key size in bytes (FIPS 204).
const ML_DSA_87_PK_LEN: usize = 2592;
/// ML-DSA-87 signature size in bytes (FIPS 204).
const ML_DSA_87_SIG_LEN: usize = 4627;

const HKDF_SALT: &[u8] = b"xenia-handshake-highsec-v1";
const HKDF_INFO: &[u8] = b"xenia-session-key";

const KEM_SUITE_LABEL: &str = "ml-kem-1024-fips203";
const TRANSCRIPT_SIGNATURE_SUITE_LABEL: &str = "ed25519-rfc8032+ml-dsa-87-fips204";
const KDF_SUITE_LABEL: &str = "hkdf-sha256";
const HANDSHAKE_POLICY_PROFILE: &str = "hybrid-pq-transcript-highsec-v1";
const HANDSHAKE_TRANSCRIPT_SCHEMA: &str = "xenia-handshake-transcript-highsec-v1";
const HANDSHAKE_SIGNATURE_CONTEXT_V1: &str = "xenia-handshake-signature-highsec-v1";

// ─── Wire message shape (own fixed-size layout; not interoperable with the
//     standard suite's `HandshakeMessage`) ───

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum HandshakeMessageHighSec {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeTranscriptHighSec {
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
    viewer_ml_dsa_pk: &[u8; ML_DSA_87_PK_LEN],
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
    viewer_ml_dsa_pk: &[u8; ML_DSA_87_PK_LEN],
    kem_ct: &[u8],
    viewer_nonce: &[u8; 32],
    viewer_signature: &[u8; 64],
    viewer_ml_dsa_signature: &[u8; ML_DSA_87_SIG_LEN],
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

fn parse_peer_ml_dsa_public_key(
    bytes: &[u8; ML_DSA_87_PK_LEN],
) -> Result<MlDsaVerifyingKey<MlDsa87>, HandshakeError> {
    let encoded = MlDsaEncodedVerifyingKey::<MlDsa87>::try_from(bytes.as_slice())
        .map_err(|_| HandshakeError::InvalidMlDsaVerifyingKey)?;
    Ok(MlDsaVerifyingKey::<MlDsa87>::decode(&encoded))
}

fn verify_ml_dsa(
    peer_pk: &[u8; ML_DSA_87_PK_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA_87_SIG_LEN],
) -> Result<(), HandshakeError> {
    let verifying_key = parse_peer_ml_dsa_public_key(peer_pk)?;
    let encoded_sig = MlDsaEncodedSignature::<MlDsa87>::try_from(signature.as_slice())
        .map_err(|_| HandshakeError::InvalidMlDsaSignatureEncoding)?;
    let sig = MlDsaSignatureT::<MlDsa87>::decode(&encoded_sig)
        .ok_or(HandshakeError::InvalidMlDsaSignatureEncoding)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| HandshakeError::MlDsaSignatureVerificationFailed)
}

// One argument per `HandshakeTranscriptHighSec` field this assembles --
// bundling them into a builder struct would just move the same field count
// somewhere else, not reduce it.
#[allow(clippy::too_many_arguments)]
fn build_transcript_hash(
    negotiated_context_hash: Option<[u8; 32]>,
    host_ed25519_pk: [u8; 32],
    viewer_ed25519_pk: [u8; 32],
    host_ml_dsa_pk: &[u8; ML_DSA_87_PK_LEN],
    viewer_ml_dsa_pk: &[u8; ML_DSA_87_PK_LEN],
    host_kem_pk: &[u8; ML_KEM_1024_PK_LEN],
    kem_ct: &[u8; ML_KEM_1024_CT_LEN],
    host_nonce: [u8; 32],
    viewer_nonce: [u8; 32],
    viewer_signature: &[u8; 64],
    host_signature: &[u8; 64],
    viewer_ml_dsa_signature: &[u8; ML_DSA_87_SIG_LEN],
    host_ml_dsa_signature: &[u8; ML_DSA_87_SIG_LEN],
) -> Result<[u8; 32], HandshakeError> {
    let transcript = HandshakeTranscriptHighSec {
        schema: HANDSHAKE_TRANSCRIPT_SCHEMA.to_string(),
        kem: KEM_SUITE_LABEL.to_string(),
        transcript_signature: TRANSCRIPT_SIGNATURE_SUITE_LABEL.to_string(),
        kdf: KDF_SUITE_LABEL.to_string(),
        negotiated_context_hash,
        host_ed25519_pk,
        viewer_ed25519_pk,
        host_ml_dsa_pk: host_ml_dsa_pk.to_vec(),
        viewer_ml_dsa_pk: viewer_ml_dsa_pk.to_vec(),
        host_kem_pk: host_kem_pk.to_vec(),
        kem_ciphertext: kem_ct.to_vec(),
        host_nonce,
        viewer_nonce,
        viewer_signature: viewer_signature.to_vec(),
        host_signature: host_signature.to_vec(),
        viewer_ml_dsa_signature: viewer_ml_dsa_signature.to_vec(),
        host_ml_dsa_signature: host_ml_dsa_signature.to_vec(),
    };
    let bytes = bincode::serialize(&transcript).map_err(HandshakeError::Codec)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// BLAKE3-256 fingerprint binding a peer's full high-security signing
/// identity: its Ed25519 and ML-DSA-87 public keys together. Deliberately a
/// *different* domain tag from [`crate::handshake`]'s
/// `host_identity_fingerprint` (`xenia-host-identity-fingerprint-v1`) so a
/// standard-suite fingerprint and a high-security one can never collide even
/// if (implausibly) the same Ed25519 key were reused across both suites.
fn host_identity_fingerprint_highsec(ed25519_pk: &[u8; 32], ml_dsa_pk: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xenia-host-identity-fingerprint-highsec-v1");
    hasher.update(ed25519_pk);
    hasher.update(ml_dsa_pk);
    *hasher.finalize().as_bytes()
}

// ─── Viewer role ───

struct ViewerPendingState {
    hello_bytes: Vec<u8>,
    host_ed25519_pk: [u8; 32],
    host_verifying_key: VerifyingKey,
    host_ml_dsa_pk: [u8; ML_DSA_87_PK_LEN],
    host_kem_pk: [u8; ML_KEM_1024_PK_LEN],
    host_nonce: [u8; 32],
    negotiated_context_hash: Option<[u8; 32]>,
    viewer_nonce: [u8; 32],
    kem_ct: [u8; ML_KEM_1024_CT_LEN],
    viewer_ed25519_pk: [u8; 32],
    viewer_ml_dsa_pk: [u8; ML_DSA_87_PK_LEN],
    viewer_signature: [u8; 64],
    viewer_ml_dsa_signature: [u8; ML_DSA_87_SIG_LEN],
    root_key: [u8; 32],
}

/// Drives the viewer side of the high-security handshake. Mirrors
/// [`crate::handshake::ViewerHandshake`] field-for-field; see the module doc
/// comment for why this suite gets its own type rather than a generic
/// parameter on the existing one (the wire message shapes differ in fixed
/// array size, which bincode's `BigArray` encoding bakes in at the type
/// level).
pub struct ViewerHandshakeHighSec {
    signing_key: SigningKey,
    ml_dsa_signing_key: MlDsaSigningKey<MlDsa87>,
    pending: Option<ViewerPendingState>,
}

impl Default for ViewerHandshakeHighSec {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewerHandshakeHighSec {
    /// Generate a fresh viewer Ed25519 + ML-DSA-87 identity for this session.
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            ml_dsa_signing_key: MlDsaSigningKey::<MlDsa87>::generate(),
            pending: None,
        }
    }

    /// Reconstruct a viewer identity from *persisted* seeds, mirroring
    /// [`crate::handshake::ViewerHandshake::from_identity`].
    pub fn from_identity(
        ed25519_secret: &[u8],
        ml_dsa_seed: &[u8],
    ) -> Result<Self, HandshakeError> {
        let ed: [u8; 32] = ed25519_secret
            .try_into()
            .map_err(|_| HandshakeError::InvalidSeedLength)?;
        let ml: [u8; 32] = ml_dsa_seed
            .try_into()
            .map_err(|_| HandshakeError::InvalidSeedLength)?;
        let seed: B32 = ml.into();
        Ok(Self {
            signing_key: SigningKey::from_bytes(&ed),
            ml_dsa_signing_key: MlDsaSigningKey::<MlDsa87>::from_seed(&seed),
            pending: None,
        })
    }

    /// The viewer's Ed25519 public key.
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The viewer's ML-DSA-87 public key bytes -- what an operator enrolls
    /// (alongside [`Self::ed25519_public_key`]) in a host's `OperatorPolicy`
    /// for the high-security suite. Without this there is no way to derive
    /// the value to enroll from a `ViewerHandshakeHighSec` identity at all.
    pub fn ml_dsa_public_key_bytes(&self) -> [u8; ML_DSA_87_PK_LEN] {
        self.ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-87 encoded verifying key is always ML_DSA_87_PK_LEN bytes")
    }

    /// Process the host's `HostHello`; returns the `ViewerResponse` bytes.
    pub fn begin(&mut self, hello_bytes: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let hello: HandshakeMessageHighSec = bincode::deserialize(hello_bytes)?;
        let HandshakeMessageHighSec::HostHello {
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
        parse_peer_ml_dsa_public_key(&host_ml_dsa_pk)?;

        let viewer_nonce = rand::random::<[u8; 32]>();

        let ek: MlKemEk1024 = <MlKemEk1024 as TryKeyInit>::new_from_slice(&kem_pk)
            .map_err(|_| HandshakeError::InvalidKemPublicKey)?;
        let (kem_ct, shared) = <MlKemEk1024 as Encapsulate>::encapsulate(&ek);
        let kem_ct: [u8; ML_KEM_1024_CT_LEN] = kem_ct
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::InvalidKemPublicKey)?;

        let viewer_ed25519_pk = self.signing_key.verifying_key().to_bytes();
        let viewer_ml_dsa_pk: [u8; ML_DSA_87_PK_LEN] = self
            .ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-87 encoded verifying key is always ML_DSA_87_PK_LEN bytes");

        let transcript = viewer_signature_transcript(
            hello_bytes,
            &viewer_ed25519_pk,
            &viewer_ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );
        let viewer_signature = self.signing_key.sign(&transcript).to_bytes();
        let viewer_ml_dsa_signature: [u8; ML_DSA_87_SIG_LEN] = {
            let sig: MlDsaSignatureT<MlDsa87> = self.ml_dsa_signing_key.sign(&transcript);
            sig.encode()
                .as_slice()
                .try_into()
                .expect("ml-dsa-87 encoded signature is always ML_DSA_87_SIG_LEN bytes")
        };

        let mut combined_nonce = [0u8; 64];
        combined_nonce[..32].copy_from_slice(&host_nonce);
        combined_nonce[32..].copy_from_slice(&viewer_nonce);
        let root_key = hkdf_derive(&combined_nonce, shared.as_slice());

        self.pending = Some(ViewerPendingState {
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

        let response = HandshakeMessageHighSec::ViewerResponse {
            ed25519_pk: viewer_ed25519_pk,
            ml_dsa_pk: viewer_ml_dsa_pk,
            kem_ct,
            nonce: viewer_nonce,
            signature: viewer_signature,
            ml_dsa_signature: viewer_ml_dsa_signature,
        };
        Ok(bincode::serialize(&response)?)
    }

    /// Process the host's `HostFinalize`; returns the derived key schedule.
    pub fn finish(&mut self, finalize_bytes: &[u8]) -> Result<SessionKeySchedule, HandshakeError> {
        let state = self.pending.take().ok_or(HandshakeError::NotStarted)?;

        let finalize: HandshakeMessageHighSec = bincode::deserialize(finalize_bytes)?;
        let HandshakeMessageHighSec::HostFinalize {
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
        verify_ml_dsa(
            &state.host_ml_dsa_pk,
            &final_transcript,
            &host_ml_dsa_sig_bytes,
        )?;

        let transcript_hash = build_transcript_hash(
            state.negotiated_context_hash,
            state.host_ed25519_pk,
            state.viewer_ed25519_pk,
            &state.host_ml_dsa_pk,
            &state.viewer_ml_dsa_pk,
            &state.host_kem_pk,
            &state.kem_ct,
            state.host_nonce,
            state.viewer_nonce,
            &state.viewer_signature,
            &host_sig_bytes,
            &state.viewer_ml_dsa_signature,
            &host_ml_dsa_sig_bytes,
        )?;

        let host_fingerprint =
            host_identity_fingerprint_highsec(&state.host_ed25519_pk, &state.host_ml_dsa_pk);

        Ok(SessionKeySchedule::derive(
            &state.root_key,
            transcript_hash,
            host_fingerprint,
        ))
    }
}

// ─── Host role ───

struct HostPendingState {
    hello_bytes: Vec<u8>,
    host_nonce: [u8; 32],
    host_ed25519_pk: [u8; 32],
    host_ml_dsa_pk: [u8; ML_DSA_87_PK_LEN],
    host_kem_pk: [u8; ML_KEM_1024_PK_LEN],
    negotiated_context_hash: Option<[u8; 32]>,
}

/// A peer identity verified by [`HostHandshakeHighSec::finish`] -- both
/// Ed25519 and ML-DSA-87 signatures checked, no classical-only fallback.
#[derive(Debug, Clone)]
pub struct VerifiedPeerIdentityHighSec {
    /// The peer's Ed25519 public key (what an operator enrolls in a policy).
    pub ed25519_pk: [u8; 32],
    /// The peer's ML-DSA-87 public key bytes.
    pub ml_dsa_pk: Vec<u8>,
}

/// Drives the host side of the high-security handshake. Transport-agnostic
/// like every type in this crate (see the crate doc comment's "What this
/// crate deliberately does NOT do") -- the caller ships `hello()`'s and
/// `finish()`'s returned bytes over whatever transport it has, and feeds the
/// peer's response bytes back in.
///
/// The KEM keypair is generated once at construction and reused across every
/// handshake this instance drives (the normal, intended usage pattern for a
/// KEM public key -- unlike a nonce, which must be fresh per handshake and
/// is), mirroring native `xenia_handshake::HandshakeManager`'s design.
pub struct HostHandshakeHighSec {
    signing_key: SigningKey,
    ml_dsa_signing_key: MlDsaSigningKey<MlDsa87>,
    kem_dk: MlKemDk1024,
    kem_ek_bytes: [u8; ML_KEM_1024_PK_LEN],
    pending: Option<HostPendingState>,
}

impl HostHandshakeHighSec {
    /// Generate a fresh host Ed25519 + ML-DSA-87 + ML-KEM-1024 identity.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let ml_dsa_seed: [u8; 32] = rand::random();
        Self::from_identity_unchecked(signing_key, ml_dsa_seed)
    }

    /// Reconstruct a host identity from *persisted* seeds -- a 32-byte
    /// Ed25519 secret and a 32-byte ML-DSA-87 seed. Mirrors
    /// `xenia_handshake::HandshakeManager::from_identity_seeds`: the KEM
    /// keypair stays freshly generated per construction (only the signing
    /// identity is pinned by a peer).
    pub fn from_identity(ed25519_secret: &[u8; 32], ml_dsa_seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(ed25519_secret);
        Self::from_identity_unchecked(signing_key, *ml_dsa_seed)
    }

    fn from_identity_unchecked(signing_key: SigningKey, ml_dsa_seed: [u8; 32]) -> Self {
        let seed: B32 = ml_dsa_seed.into();
        let ml_dsa_signing_key = MlDsaSigningKey::<MlDsa87>::from_seed(&seed);
        let (kem_dk, kem_ek) = MlKem1024::generate_keypair();
        let ek_encoded = kem_ek.to_bytes();
        let mut kem_ek_bytes = [0u8; ML_KEM_1024_PK_LEN];
        kem_ek_bytes.copy_from_slice(ek_encoded.as_slice());
        Self {
            signing_key,
            ml_dsa_signing_key,
            kem_dk,
            kem_ek_bytes,
            pending: None,
        }
    }

    /// The host's Ed25519 public key.
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The host's ML-DSA-87 public key bytes.
    pub fn ml_dsa_public_key_bytes(&self) -> [u8; ML_DSA_87_PK_LEN] {
        self.ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-87 encoded verifying key is always ML_DSA_87_PK_LEN bytes")
    }

    /// BLAKE3-256 fingerprint of this host's high-security signing identity
    /// (Ed25519 || ML-DSA-87). A viewer pins this for trust-on-first-use.
    pub fn identity_fingerprint(&self) -> [u8; 32] {
        host_identity_fingerprint_highsec(
            &self.ed25519_public_key(),
            &self.ml_dsa_public_key_bytes(),
        )
    }

    /// Build and store `HostHello`; returns the bytes to send first.
    pub fn hello(&mut self, negotiated_context_hash: Option<[u8; 32]>) -> Vec<u8> {
        let host_nonce = rand::random::<[u8; 32]>();
        let host_ed25519_pk = self.ed25519_public_key();
        let host_ml_dsa_pk: [u8; ML_DSA_87_PK_LEN] = self
            .ml_dsa_signing_key
            .verifying_key()
            .encode()
            .as_slice()
            .try_into()
            .expect("ml-dsa-87 encoded verifying key is always ML_DSA_87_PK_LEN bytes");

        let hello = HandshakeMessageHighSec::HostHello {
            ed25519_pk: host_ed25519_pk,
            ml_dsa_pk: host_ml_dsa_pk,
            kem_pk: self.kem_ek_bytes,
            nonce: host_nonce,
            negotiated_context_hash,
        };
        let hello_bytes =
            bincode::serialize(&hello).expect("HandshakeMessageHighSec::HostHello always encodes");

        self.pending = Some(HostPendingState {
            hello_bytes: hello_bytes.clone(),
            host_nonce,
            host_ed25519_pk,
            host_ml_dsa_pk,
            host_kem_pk: self.kem_ek_bytes,
            negotiated_context_hash,
        });

        hello_bytes
    }

    /// Process the viewer's `ViewerResponse`: verify both signatures,
    /// decapsulate, derive the key schedule, and return `(finalize_bytes,
    /// schedule, verified_peer)` -- send `finalize_bytes` to complete the
    /// handshake on the viewer's side.
    pub fn finish(
        &mut self,
        response_bytes: &[u8],
    ) -> Result<(Vec<u8>, SessionKeySchedule, VerifiedPeerIdentityHighSec), HandshakeError> {
        let state = self.pending.take().ok_or(HandshakeError::NotStarted)?;

        let response: HandshakeMessageHighSec = bincode::deserialize(response_bytes)?;
        let HandshakeMessageHighSec::ViewerResponse {
            ed25519_pk,
            ml_dsa_pk,
            kem_ct,
            nonce: viewer_nonce,
            signature,
            ml_dsa_signature,
        } = response
        else {
            return Err(HandshakeError::ExpectedHostHello);
        };

        let viewer_verifying_key = VerifyingKey::from_bytes(&ed25519_pk)
            .map_err(|_| HandshakeError::InvalidVerifyingKey)?;
        parse_peer_ml_dsa_public_key(&ml_dsa_pk)?;

        let transcript = viewer_signature_transcript(
            &state.hello_bytes,
            &ed25519_pk,
            &ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
        );
        let sig = Signature::from_bytes(&signature);
        viewer_verifying_key
            .verify(&transcript, &sig)
            .map_err(|_| HandshakeError::SignatureVerificationFailed)?;
        verify_ml_dsa(&ml_dsa_pk, &transcript, &ml_dsa_signature)?;

        let mut combined_nonce = [0u8; 64];
        combined_nonce[..32].copy_from_slice(&state.host_nonce);
        combined_nonce[32..].copy_from_slice(&viewer_nonce);

        let ct = MlKem1024Ciphertext::try_from(kem_ct.as_slice())
            .map_err(|_| HandshakeError::InvalidKemPublicKey)?;
        // ML-KEM decapsulate is infallible per FIPS 203 (implicit rejection:
        // an invalid ciphertext yields a pseudorandom shared secret rather
        // than an error). Authentication happens at the Ed25519/ML-DSA-87
        // layer, same as the standard suite.
        let shared = self.kem_dk.decapsulate(&ct);
        let root_key = hkdf_derive(&combined_nonce, shared.as_slice());

        let final_transcript = host_signature_transcript(
            &state.hello_bytes,
            &ed25519_pk,
            &ml_dsa_pk,
            &kem_ct,
            &viewer_nonce,
            &signature,
            &ml_dsa_signature,
        );
        let host_sig = self.signing_key.sign(&final_transcript).to_bytes();
        let host_ml_dsa_sig: [u8; ML_DSA_87_SIG_LEN] = {
            let sig: MlDsaSignatureT<MlDsa87> = self.ml_dsa_signing_key.sign(&final_transcript);
            sig.encode()
                .as_slice()
                .try_into()
                .expect("ml-dsa-87 encoded signature is always ML_DSA_87_SIG_LEN bytes")
        };

        let finalize = HandshakeMessageHighSec::HostFinalize {
            signature: host_sig,
            ml_dsa_signature: host_ml_dsa_sig,
        };
        let finalize_bytes = bincode::serialize(&finalize)?;

        let transcript_hash = build_transcript_hash(
            state.negotiated_context_hash,
            state.host_ed25519_pk,
            ed25519_pk,
            &state.host_ml_dsa_pk,
            &ml_dsa_pk,
            &state.host_kem_pk,
            &kem_ct,
            state.host_nonce,
            viewer_nonce,
            &signature,
            &host_sig,
            &ml_dsa_signature,
            &host_ml_dsa_sig,
        )?;

        let host_fingerprint =
            host_identity_fingerprint_highsec(&state.host_ed25519_pk, &state.host_ml_dsa_pk);

        let schedule = SessionKeySchedule::derive(&root_key, transcript_hash, host_fingerprint);
        let peer = VerifiedPeerIdentityHighSec {
            ed25519_pk,
            ml_dsa_pk: ml_dsa_pk.to_vec(),
        };
        Ok((finalize_bytes, schedule, peer))
    }
}

impl Default for HostHandshakeHighSec {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a stable ML-DSA-87 identity seed from an already-persisted Ed25519
/// secret, so a host that already persists a standard-suite identity (e.g.
/// xenia-peer's `--host-identity-key-path`, an Ed25519-secret ||
/// ML-DSA-65-seed blob) can offer the high-security suite too without a
/// second key file: the Ed25519 keypair itself is suite-independent (reused
/// as-is), and this HKDF derivation gives a deterministic, stable ML-DSA-87
/// seed tied to that same persisted secret -- stable across restarts, and
/// distinct from the standard suite's ML-DSA-65 seed (a different value
/// entirely, stored in the same file) by construction.
pub fn derive_ml_dsa_87_seed_from_ed25519_secret(ed25519_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(
        Some(b"xenia-highsec-identity-derivation-v1".as_slice()),
        ed25519_secret,
    );
    let mut seed = [0u8; 32];
    hk.expand(b"xenia/highsec/ml-dsa-87-seed", &mut seed)
        .expect("HKDF-SHA256 32-byte expand cannot fail for 32-byte output");
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_viewer_derive_the_same_session_key_schedule() {
        let mut host = HostHandshakeHighSec::new();
        let mut viewer = ViewerHandshakeHighSec::new();

        let hello = host.hello(None);
        let response = viewer.begin(&hello).unwrap();
        let (finalize, host_schedule, peer) = host.finish(&response).unwrap();
        let viewer_schedule = viewer.finish(&finalize).unwrap();

        assert_eq!(host_schedule, viewer_schedule);
        assert_ne!(host_schedule.aead, [0u8; 32]);
        assert_eq!(peer.ed25519_pk, viewer.ed25519_public_key());
        assert_eq!(
            host_schedule.host_identity_fingerprint,
            host.identity_fingerprint()
        );
    }

    #[test]
    fn persisted_identity_seeds_reproduce_the_same_public_identity() {
        let ed = [7u8; 32];
        let ml = [9u8; 32];
        let host1 = HostHandshakeHighSec::from_identity(&ed, &ml);
        let host2 = HostHandshakeHighSec::from_identity(&ed, &ml);
        assert_eq!(host1.ed25519_public_key(), host2.ed25519_public_key());
        assert_eq!(host1.identity_fingerprint(), host2.identity_fingerprint());

        let viewer1 = ViewerHandshakeHighSec::from_identity(&ed, &ml).unwrap();
        let viewer2 = ViewerHandshakeHighSec::from_identity(&ed, &ml).unwrap();
        assert_eq!(viewer1.ed25519_public_key(), viewer2.ed25519_public_key());
    }

    #[test]
    fn tampered_viewer_response_is_rejected() {
        let mut host = HostHandshakeHighSec::new();
        let mut viewer = ViewerHandshakeHighSec::new();

        let hello = host.hello(None);
        let mut response = viewer.begin(&hello).unwrap();
        let last = response.len() - 1;
        response[last] ^= 0xFF;

        // Either a decode error (corrupted the length-prefixed tail) or a
        // signature-verification failure -- either way, must not succeed.
        assert!(host.finish(&response).is_err());
    }

    #[test]
    fn wrong_role_message_is_rejected() {
        let mut host = HostHandshakeHighSec::new();
        let hello = host.hello(None);
        // A HostHello fed back into finish() (expects ViewerResponse) must
        // be rejected, not silently misinterpreted.
        assert!(host.finish(&hello).is_err());
    }

    #[test]
    fn does_not_collide_with_the_standard_suite_transcript_schema() {
        assert_ne!(HANDSHAKE_TRANSCRIPT_SCHEMA, "xenia-handshake-transcript-v1");
        assert_ne!(KEM_SUITE_LABEL, "ml-kem-768-fips203");
        assert_ne!(
            TRANSCRIPT_SIGNATURE_SUITE_LABEL,
            "ed25519-rfc8032+ml-dsa-65-fips204"
        );
    }

    #[test]
    fn derived_highsec_seed_is_deterministic_and_distinct_from_input() {
        let secret = [3u8; 32];
        let seed1 = derive_ml_dsa_87_seed_from_ed25519_secret(&secret);
        let seed2 = derive_ml_dsa_87_seed_from_ed25519_secret(&secret);
        assert_eq!(seed1, seed2);
        assert_ne!(seed1, secret);

        let other_secret = [4u8; 32];
        let seed3 = derive_ml_dsa_87_seed_from_ed25519_secret(&other_secret);
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn host_identity_derived_from_shared_ed25519_secret_round_trips() {
        // The pattern xenia-peer's daemon actually uses: reuse the persisted
        // Ed25519 secret, derive the ML-DSA-87 seed from it.
        let ed25519_secret = [5u8; 32];
        let ml_dsa_seed = derive_ml_dsa_87_seed_from_ed25519_secret(&ed25519_secret);

        let mut host = HostHandshakeHighSec::from_identity(&ed25519_secret, &ml_dsa_seed);
        let mut viewer =
            ViewerHandshakeHighSec::from_identity(&ed25519_secret, &ml_dsa_seed).unwrap();

        let hello = host.hello(None);
        let response = viewer.begin(&hello).unwrap();
        let (finalize, host_schedule, _peer) = host.finish(&response).unwrap();
        let viewer_schedule = viewer.finish(&finalize).unwrap();
        assert_eq!(host_schedule, viewer_schedule);
    }
}
